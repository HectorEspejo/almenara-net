//! DAO de servicios detectados por dispositivo (tabla DEVICE_SERVICES).
//!
//! Cada fila representa un (dispositivo, puerto, protocolo). El estado se deriva
//! de dos columnas: CERRADO si `closed_at` no es NULL (§7.12, F6); si no,
//! OBSOLETO si `last_seen` pasa del umbral de F2; si no, ABIERTO. Desde la v6,
//! `last_seen` es siempre la última vez que el puerto se vio abierto:
//! `Repo::mark_service_closed` no lo toca (hasta F5 lo movía y el estado CERRADO
//! dependía de él).
//!
//! Los puertos cerrados se purgan a los `events_retention_days` de su
//! `closed_at`; los abiertos u obsoletos, a los de su `last_seen`.

use std::time::SystemTime;

use rusqlite::{params, Connection, Row};

use super::{ahora_rfc3339, instante_a_rfc3339, Repo};
use crate::error::Result;

/// Protocolo de transporte de un servicio.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Protocol {
    /// TCP.
    #[default]
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// Todos los protocolos soportados.
    pub const ALL: [Self; 2] = [Self::Tcp, Self::Udp];

    /// Representación persistida.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Reconstruye el protocolo desde su representación persistida.
    pub fn from_str(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|proto| proto.as_str() == value)
    }
}

/// Servicio detectado y persistido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceService {
    /// Identificador interno.
    pub id: i64,
    /// FK a DEVICES.
    pub device_id: i64,
    /// Puerto.
    pub port: u16,
    /// Protocolo.
    pub protocol: Protocol,
    /// Servicio identificado (http, ssh...), si se conoce.
    pub service: Option<String>,
    /// Banner saneado y truncado, si se obtuvo.
    pub banner: Option<String>,
    /// Primera detección (RFC 3339 UTC).
    pub first_seen: String,
    /// Última vez visto abierto (RFC 3339 UTC).
    pub last_seen: String,
    /// Cuándo un escaneo lo vio cerrado (§7.12); NULL = no está cerrado.
    pub closed_at: Option<String>,
}

impl DeviceService {
    /// Etiqueta visible del servicio (o "?" si no se identificó).
    pub fn display_service(&self) -> &str {
        self.service.as_deref().unwrap_or("?")
    }

    /// Indica si el puerto está CERRADO (F6, §7.12).
    pub fn is_closed(&self) -> bool {
        self.closed_at.is_some()
    }
}

/// Datos para hacer upsert de un servicio detectado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUpsert {
    /// FK a DEVICES.
    pub device_id: i64,
    /// Puerto.
    pub port: u16,
    /// Protocolo.
    pub protocol: Protocol,
    /// Servicio identificado, si se conoce.
    pub service: Option<String>,
    /// Banner saneado, si se obtuvo.
    pub banner: Option<String>,
}

/// Columnas de DEVICE_SERVICES en el orden que espera fila_a_servicio.
const SQL_SELECCION: &str = "SELECT id, device_id, port, protocol, service, banner, first_seen, last_seen, closed_at FROM DEVICE_SERVICES";

/// Inserta o actualiza un servicio por (device_id, port, protocol).
///
/// Verlo abierto borra `closed_at` y actualiza `last_seen` (§7.12): el puerto
/// vuelve a ABIERTO y la reconciliación emitirá `service_new` con
/// `reopened = true`.
pub(crate) fn upsert(conn: &Connection, servicio: &ServiceUpsert) -> Result<i64> {
    let ahora = ahora_rfc3339();
    let id = conn.query_row(
        "INSERT INTO DEVICE_SERVICES (device_id, port, protocol, service, banner, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(device_id, port, protocol) DO UPDATE SET
             service = COALESCE(excluded.service, DEVICE_SERVICES.service),
             banner = COALESCE(excluded.banner, DEVICE_SERVICES.banner),
             last_seen = excluded.last_seen,
             closed_at = NULL
         RETURNING id",
        params![
            servicio.device_id,
            servicio.port,
            servicio.protocol.as_str(),
            servicio.service,
            servicio.banner,
            ahora
        ],
        |fila| fila.get(0),
    )?;
    Ok(id)
}

/// Lista los servicios de un dispositivo, ordenados por puerto y protocolo.
pub(crate) fn list(conn: &Connection, device_id: i64) -> Result<Vec<DeviceService>> {
    let sql = format!("{SQL_SELECCION} WHERE device_id = ?1 ORDER BY port, protocol");
    let mut sentencia = conn.prepare(&sql)?;
    let filas = sentencia.query_map(params![device_id], fila_a_servicio)?;
    let mut servicios = Vec::new();
    for fila in filas {
        servicios.push(fila?);
    }
    Ok(servicios)
}

/// Cuenta los servicios ABIERTOS de un dispositivo con last_seen anterior al corte.
///
/// En Fase 2 el estado STALE es derivado; desde la F6 los puertos CERRADOS no
/// cuentan como obsoletos (`closed_at` manda, §7.12).
pub(crate) fn mark_stale(conn: &Connection, device_id: i64, older_than: &str) -> Result<usize> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM DEVICE_SERVICES
          WHERE device_id = ?1 AND closed_at IS NULL AND last_seen < ?2",
        params![device_id, older_than],
        |fila| fila.get(0),
    )?;
    Ok(total.max(0) as usize)
}

/// Elimina los servicios vencidos según su estado (§7.12).
///
/// Los CERRADOS se purgan por `closed_at`; los abiertos u obsoletos, por
/// `last_seen`, ambos con el corte de retención de eventos.
pub(crate) fn prune(conn: &Connection, older_than: &str) -> Result<usize> {
    let borrados = conn.execute(
        "DELETE FROM DEVICE_SERVICES
          WHERE (closed_at IS NOT NULL AND closed_at < ?1)
             OR (closed_at IS NULL AND last_seen < ?1)",
        params![older_than],
    )?;
    Ok(borrados)
}

/// Marca un servicio como CERRADO fijando `closed_at` (§7.12).
///
/// No toca `last_seen`: sigue siendo la última vez que el puerto se vio abierto.
/// Devuelve cuántas filas ha actualizado (0 si el servicio no estaba persistido
/// o ya estaba cerrado).
pub(crate) fn mark_closed(
    conn: &Connection,
    device_id: i64,
    port: u16,
    protocol: Protocol,
    at: SystemTime,
) -> Result<usize> {
    let cambiados = conn.execute(
        "UPDATE DEVICE_SERVICES SET closed_at = ?1
          WHERE device_id = ?2 AND port = ?3 AND protocol = ?4 AND closed_at IS NULL",
        params![instante_a_rfc3339(at), device_id, port, protocol.as_str()],
    )?;
    Ok(cambiados)
}

/// Relleno de `closed_at` desde el último evento de servicio (migración v6, §7.12).
///
/// Para cada puerto cuyo último evento de servicio es `service_gone` fija
/// `closed_at` a la fecha de ese evento. No toca `last_seen`. Devuelve cuántas
/// filas ha rellenado.
pub(crate) fn backfill_closed_at(conn: &Connection) -> Result<usize> {
    let pendientes: Vec<(i64, i64, String, String)> = {
        let mut sentencia = conn.prepare(
            "WITH ultimo AS (
                 SELECT device_id,
                        json_extract(details, '$.port')     AS port,
                        json_extract(details, '$.protocol') AS protocol,
                        event_type,
                        created_at,
                        ROW_NUMBER() OVER (
                            PARTITION BY device_id,
                                         json_extract(details, '$.port'),
                                         json_extract(details, '$.protocol')
                            ORDER BY created_at DESC, id DESC
                        ) AS n
                   FROM DEVICE_EVENTS
                  WHERE event_type IN ('service_new', 'service_gone')
             )
             SELECT device_id, port, protocol, created_at
               FROM ultimo
              WHERE n = 1 AND event_type = 'service_gone'",
        )?;
        let filas = sentencia.query_map([], |fila| {
            Ok((
                fila.get::<_, i64>(0)?,
                fila.get::<_, i64>(1)?,
                fila.get::<_, String>(2)?,
                fila.get::<_, String>(3)?,
            ))
        })?;
        let mut pendientes = Vec::new();
        for fila in filas {
            pendientes.push(fila?);
        }
        pendientes
    };

    let mut cerrados = 0usize;
    for (device_id, port, protocol, created_at) in pendientes {
        let Ok(port) = u16::try_from(port) else {
            continue;
        };
        cerrados += conn.execute(
            "UPDATE DEVICE_SERVICES SET closed_at = ?1
              WHERE device_id = ?2 AND port = ?3 AND protocol = ?4 AND closed_at IS NULL",
            params![created_at, device_id, port, protocol],
        )?;
    }
    Ok(cerrados)
}

impl Repo {
    /// Relleno de `closed_at` tras la migración v6 (§7.12).
    pub fn backfill_closed_at(&mut self) -> Result<usize> {
        backfill_closed_at(&self.conn)
    }

    /// Marca un servicio como cerrado fijando `closed_at` sin tocar `last_seen`
    /// (§7.12). Lo llama la reconciliación tras emitir `service_gone`.
    pub fn mark_service_closed(
        &mut self,
        device_id: i64,
        port: u16,
        protocol: Protocol,
        at: SystemTime,
    ) -> Result<usize> {
        mark_closed(&self.conn, device_id, port, protocol, at)
    }
}

/// Reconstruye un servicio a partir de una fila de SQL_SELECCION.
fn fila_a_servicio(fila: &Row<'_>) -> rusqlite::Result<DeviceService> {
    let protocolo: String = fila.get(3)?;
    Ok(DeviceService {
        id: fila.get(0)?,
        device_id: fila.get(1)?,
        port: fila.get(2)?,
        protocol: Protocol::from_str(&protocolo).unwrap_or(Protocol::Tcp),
        service: fila.get(4)?,
        banner: fila.get(5)?,
        first_seen: fila.get(6)?,
        last_seen: fila.get(7)?,
        closed_at: fila.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{DeviceUpsert, Interface, Repo};

    /// Repositorio con una interfaz y un equipo, y el id del equipo.
    fn repo_con_equipo() -> (tempfile::TempDir, Repo, i64) {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let interface_id = repo
            .upsert_interface(&Interface::without_id(
                "eth0".to_string(),
                Some("02:00:00:00:00:ff".to_string()),
                Some("192.168.1.10".to_string()),
                Some("255.255.255.0".to_string()),
                None,
                true,
                "2026-01-01T00:00:00Z".to_string(),
            ))
            .unwrap();
        let (device_id, _) = repo
            .upsert_device(&DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.20".to_string(),
                hostname: None,
                vendor: None,
                interface_id,
                device_type: "unknown".to_string(),
            })
            .unwrap();
        (dir, repo, device_id)
    }

    fn servicio(device_id: i64, port: u16) -> ServiceUpsert {
        ServiceUpsert {
            device_id,
            port,
            protocol: Protocol::Tcp,
            service: Some("ssh".to_string()),
            banner: None,
        }
    }

    /// Instante fijo de las pruebas: 2026-11-04T11:00:00Z.
    fn instante() -> SystemTime {
        crate::repo::rfc3339_a_instante("2026-11-04T11:00:00Z").expect("fecha de prueba")
    }

    #[test]
    fn marcar_cierre_fija_closed_at_y_no_toca_last_seen() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        repo.upsert_service(&servicio(device_id, 445)).unwrap();
        let antes = repo.list_services(device_id).unwrap().remove(0);
        assert_eq!(antes.closed_at, None);
        assert!(!antes.is_closed());

        assert_eq!(
            repo.mark_service_closed(device_id, 445, Protocol::Tcp, instante())
                .unwrap(),
            1
        );
        let cerrado = repo.list_services(device_id).unwrap().remove(0);
        assert_eq!(cerrado.closed_at.as_deref(), Some("2026-11-04T11:00:00Z"));
        assert_eq!(
            cerrado.last_seen, antes.last_seen,
            "last_seen sigue siendo la última vez que se vio abierto"
        );
        assert!(cerrado.is_closed());

        // Ya cerrado: el cierre no se vuelve a fechar.
        assert_eq!(
            repo.mark_service_closed(device_id, 445, Protocol::Tcp, instante())
                .unwrap(),
            0
        );
        // Un puerto no persistido no se toca.
        assert_eq!(
            repo.mark_service_closed(device_id, 22, Protocol::Tcp, instante())
                .unwrap(),
            0
        );
        // Los cerrados no cuentan como obsoletos (CERRADO manda sobre STALE).
        assert_eq!(
            repo.mark_stale_services(device_id, "2999-01-01T00:00:00Z")
                .unwrap(),
            0
        );
    }

    #[test]
    fn ver_abierto_de_nuevo_borra_closed_at_y_actualiza_last_seen() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        repo.upsert_service(&servicio(device_id, 22)).unwrap();
        repo.mark_service_closed(device_id, 22, Protocol::Tcp, instante())
            .unwrap();
        assert!(repo.list_services(device_id).unwrap()[0].is_closed());

        repo.upsert_service(&servicio(device_id, 22)).unwrap();
        let abierto = repo.list_services(device_id).unwrap().remove(0);
        assert_eq!(abierto.closed_at, None, "un puerto abierto no está cerrado");
        assert!(!abierto.is_closed());
    }

    #[test]
    fn la_purga_usa_closed_at_en_los_cerrados_y_last_seen_en_los_abiertos() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        repo.upsert_service(&servicio(device_id, 22)).unwrap();
        repo.upsert_service(&servicio(device_id, 80)).unwrap();
        repo.mark_service_closed(device_id, 80, Protocol::Tcp, instante())
            .unwrap();
        // El abierto se hace viejo por last_seen.
        repo.connection()
            .execute(
                "UPDATE DEVICE_SERVICES SET last_seen = '2026-01-01T00:00:00Z' WHERE port = 22",
                [],
            )
            .unwrap();

        // Corte entre el viejo y el cierre: se lleva el abierto y el cerrado.
        let borrados = repo.prune_services("2026-06-01T00:00:00Z").unwrap();
        assert_eq!(borrados, 1, "el abierto viejo se purga por last_seen");
        let quedan = repo.list_services(device_id).unwrap();
        assert_eq!(quedan.len(), 1);
        assert_eq!(quedan[0].port, 80, "el cerrado aún no ha vencido");

        // Con un corte por delante del cierre, el cerrado se va por closed_at.
        let borrados = repo.prune_services("2026-12-01T00:00:00Z").unwrap();
        assert_eq!(borrados, 1, "el cerrado se purga por closed_at");
        assert!(repo.list_services(device_id).unwrap().is_empty());
    }

    #[test]
    fn backfill_closed_at_rellena_desde_el_ultimo_evento_de_servicio() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        repo.upsert_service(&servicio(device_id, 22)).unwrap();
        let last_seen = repo.list_services(device_id).unwrap()[0].last_seen.clone();
        for (tipo, created_at) in [
            ("service_new", "2026-11-04T10:00:00Z"),
            ("service_gone", "2026-11-04T11:00:00Z"),
        ] {
            repo.connection()
                .execute(
                    "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
                     VALUES (?1, ?2, '{\"port\":22,\"protocol\":\"tcp\"}', ?3)",
                    params![device_id, tipo, created_at],
                )
                .unwrap();
        }

        assert_eq!(repo.backfill_closed_at().unwrap(), 1);
        let servicio = repo.list_services(device_id).unwrap().remove(0);
        assert_eq!(
            servicio.closed_at.as_deref(),
            Some("2026-11-04T11:00:00Z"),
            "closed_at es la fecha del último service_gone"
        );
        assert_eq!(servicio.last_seen, last_seen, "last_seen no cambia");
        assert_eq!(repo.backfill_closed_at().unwrap(), 0, "idempotente");
    }

    #[test]
    fn el_ultimo_evento_service_new_no_cierra_el_puerto() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        repo.upsert_service(&servicio(device_id, 22)).unwrap();
        for (tipo, created_at) in [
            ("service_gone", "2026-11-04T10:00:00Z"),
            ("service_new", "2026-11-04T11:00:00Z"),
        ] {
            repo.connection()
                .execute(
                    "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
                     VALUES (?1, ?2, '{\"port\":22,\"protocol\":\"tcp\"}', ?3)",
                    params![device_id, tipo, created_at],
                )
                .unwrap();
        }
        assert_eq!(repo.backfill_closed_at().unwrap(), 0);
        assert!(!repo.list_services(device_id).unwrap()[0].is_closed());
    }

    #[test]
    fn protocolo_ida_y_vuelta() {
        for protocolo in Protocol::ALL {
            assert_eq!(Protocol::from_str(protocolo.as_str()), Some(protocolo));
        }
        assert_eq!(Protocol::from_str("sctp"), None);
        assert_eq!(Protocol::default(), Protocol::Tcp);
    }

    #[test]
    fn etiqueta_de_servicio() {
        let servicio = DeviceService {
            id: 1,
            device_id: 2,
            port: 22,
            protocol: Protocol::Tcp,
            service: None,
            banner: None,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
            closed_at: None,
        };
        assert_eq!(servicio.display_service(), "?");
        assert!(!servicio.is_closed());
    }
}
