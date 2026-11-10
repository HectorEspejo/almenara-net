//! DAO de servicios detectados por dispositivo (tabla DEVICE_SERVICES).
//!
//! Cada fila representa un (dispositivo, puerto, protocolo) abierto. El ciclo de
//! vida ACTIVE/STALE se deriva de last_seen: no hay columna de estado porque la
//! especificación de Fase 2 no la define, así que "marcar STALE" significa
//! consultar cuántos servicios llevan sin verse más de un corte temporal.

use rusqlite::{params, Connection, Row};

use super::ahora_rfc3339;
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
    /// Última detección (RFC 3339 UTC).
    pub last_seen: String,
}

impl DeviceService {
    /// Etiqueta visible del servicio (o "?" si no se identificó).
    pub fn display_service(&self) -> &str {
        self.service.as_deref().unwrap_or("?")
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
const SQL_SELECCION: &str =
    "SELECT id, device_id, port, protocol, service, banner, first_seen, last_seen FROM DEVICE_SERVICES";

/// Inserta o actualiza un servicio por (device_id, port, protocol).
pub(crate) fn upsert(conn: &Connection, servicio: &ServiceUpsert) -> Result<i64> {
    let ahora = ahora_rfc3339();
    let id = conn.query_row(
        "INSERT INTO DEVICE_SERVICES (device_id, port, protocol, service, banner, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(device_id, port, protocol) DO UPDATE SET
             service = COALESCE(excluded.service, DEVICE_SERVICES.service),
             banner = COALESCE(excluded.banner, DEVICE_SERVICES.banner),
             last_seen = excluded.last_seen
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

/// Cuenta los servicios de un dispositivo con last_seen anterior al corte.
///
/// En Fase 2 el estado STALE es derivado (no hay columna de estado): este método
/// materializa la marca devolviendo cuántos servicios llevan sin verse desde el
/// corte indicado.
pub(crate) fn mark_stale(conn: &Connection, device_id: i64, older_than: &str) -> Result<usize> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM DEVICE_SERVICES WHERE device_id = ?1 AND last_seen < ?2",
        params![device_id, older_than],
        |fila| fila.get(0),
    )?;
    Ok(total.max(0) as usize)
}

/// Elimina definitivamente los servicios con last_seen anterior al corte.
pub(crate) fn prune(conn: &Connection, older_than: &str) -> Result<usize> {
    let borrados = conn.execute(
        "DELETE FROM DEVICE_SERVICES WHERE last_seen < ?1",
        params![older_than],
    )?;
    Ok(borrados)
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        assert_eq!(servicio.display_service(), "?");
    }
}
