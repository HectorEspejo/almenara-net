//! DAO del inventario por equipo (DEVICE_SEEN) y del propio equipo (HOST_SEEN).
//!
//! Una fila por sujeto, tipo y clave con la primera y la última vez que se vio.
//! Nunca guarda destinos (privacidad) ni claves especiales: el agregador ya los
//! filtra antes de enviar el lote. El propio equipo no está en DEVICES, así que
//! su inventario vive en HOST_SEEN (§7.11).
//!
//! `upsert_seen` devuelve las entradas que se han visto por primera vez: son la
//! señal de las reglas de lo nuevo (§7.1).

use std::time::SystemTime;

use rusqlite::{params, Connection, Row};

use crate::error::Result;
use crate::history::{SeenItem, SeenKind};
use crate::repo::instante_a_rfc3339;

/// Entrada persistida del inventario de un equipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenEntry {
    /// FK a DEVICES.
    pub device_id: i64,
    /// Tipo de clave.
    pub kind: SeenKind,
    /// Clave vista.
    pub key: String,
    /// Primera vez vista (RFC 3339 UTC).
    pub first_seen: String,
    /// Última vez vista (RFC 3339 UTC).
    pub last_seen: String,
}

/// Entrada persistida del inventario del propio equipo (HOST_SEEN, §7.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSeenEntry {
    /// Tipo de clave.
    pub kind: SeenKind,
    /// Clave vista.
    pub key: String,
    /// Primera vez vista (RFC 3339 UTC).
    pub first_seen: String,
    /// Última vez vista (RFC 3339 UTC).
    pub last_seen: String,
}

/// Entradas nuevas de un lote del inventario (§7.11).
///
/// Trae juntas las de los equipos (`Device(id)`) y las del propio equipo
/// (`Host`): el hilo de la TUI construye con ellas las señales del motor y las
/// separa por sujeto.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeenChange {
    /// Entradas que se han visto por primera vez en este lote.
    pub new_items: Vec<SeenItem>,
}

impl SeenChange {
    /// Indica si no hay nada nuevo.
    pub fn is_empty(&self) -> bool {
        self.new_items.is_empty()
    }
}

const SQL_SELECCION: &str = "SELECT device_id, kind, key, first_seen, last_seen FROM DEVICE_SEEN";

/// Lista el inventario de un equipo ordenado por tipo y primera vez.
pub(crate) fn list(conn: &Connection, device_id: i64) -> Result<Vec<SeenEntry>> {
    let sql = format!("{SQL_SELECCION} WHERE device_id = ?1 ORDER BY kind, first_seen, key");
    let mut sentencia = conn.prepare(&sql)?;
    let filas = sentencia.query_map(params![device_id], fila_a_entrada)?;
    let mut entradas = Vec::new();
    for fila in filas {
        entradas.push(fila?);
    }
    Ok(entradas)
}

/// Fecha de la primera vez que se vio algo de un equipo (inicio del inventario).
pub(crate) fn first_seen(conn: &Connection, device_id: i64) -> Result<Option<String>> {
    let fecha: Option<String> = conn.query_row(
        "SELECT MIN(first_seen) FROM DEVICE_SEEN WHERE device_id = ?1",
        params![device_id],
        |fila| fila.get(0),
    )?;
    Ok(fecha)
}

/// Lista el inventario del propio equipo ordenado por tipo y primera vez.
pub(crate) fn list_host(conn: &Connection) -> Result<Vec<HostSeenEntry>> {
    let mut sentencia = conn.prepare(
        "SELECT kind, key, first_seen, last_seen FROM HOST_SEEN ORDER BY kind, first_seen, key",
    )?;
    let filas = sentencia.query_map([], fila_a_entrada_host)?;
    let mut entradas = Vec::new();
    for fila in filas {
        entradas.push(fila?);
    }
    Ok(entradas)
}

/// Inserta o actualiza las entradas de inventario en la conexión indicada.
///
/// Separa las del propio equipo (HOST_SEEN) de las de DEVICES y devuelve las que
/// son nuevas. Debe llamarse dentro de una transacción junto con el lote del
/// minuto (§7.11).
pub(crate) fn upsert_seen_en(
    conn: &Connection,
    items: &[SeenItem],
    at: &str,
) -> Result<SeenChange> {
    let mut sentencia_equipo = conn.prepare_cached(
        "INSERT OR IGNORE INTO DEVICE_SEEN (device_id, kind, key, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?4)",
    )?;
    let mut sentencia_ultimo_equipo = conn.prepare_cached(
        "UPDATE DEVICE_SEEN SET last_seen = ?1
          WHERE device_id = ?2 AND kind = ?3 AND key = ?4",
    )?;
    let mut sentencia_host = conn.prepare_cached(
        "INSERT OR IGNORE INTO HOST_SEEN (kind, key, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?3)",
    )?;
    let mut sentencia_ultimo_host =
        conn.prepare_cached("UPDATE HOST_SEEN SET last_seen = ?1 WHERE kind = ?2 AND key = ?3")?;

    let mut cambio = SeenChange::default();
    for item in items {
        let nuevas = if let Some(device_id) = item.device_id() {
            let insertada =
                sentencia_equipo.execute(params![device_id, item.kind.as_str(), item.key, at])?;
            if insertada == 0 {
                sentencia_ultimo_equipo.execute(params![
                    at,
                    device_id,
                    item.kind.as_str(),
                    item.key
                ])?;
            }
            insertada
        } else if item.es_host() {
            let insertada = sentencia_host.execute(params![item.kind.as_str(), item.key, at])?;
            if insertada == 0 {
                sentencia_ultimo_host.execute(params![at, item.kind.as_str(), item.key])?;
            }
            insertada
        } else {
            // Ni equipo ni propio equipo: el agregador no debería mandarlo.
            tracing::debug!(
                subject = item.subject.as_str(),
                "entrada de inventario con sujeto no persistible; se omite"
            );
            0
        };
        if nuevas > 0 {
            cambio.new_items.push(item.clone());
        }
    }
    Ok(cambio)
}

/// Inserta o actualiza el inventario en una transacción propia.
pub(crate) fn upsert_seen(
    conn: &mut Connection,
    items: &[SeenItem],
    at: &str,
) -> Result<SeenChange> {
    let transaccion = conn.transaction()?;
    let cambio = upsert_seen_en(&transaccion, items, at)?;
    transaccion.commit()?;
    Ok(cambio)
}

/// Purga las entradas de HOST_SEEN sin verse desde el instante indicado (§7.15).
pub(crate) fn prune_host_seen(conn: &Connection, before: SystemTime) -> Result<usize> {
    let borradas = conn.execute(
        "DELETE FROM HOST_SEEN WHERE last_seen < ?1",
        params![instante_a_rfc3339(before)],
    )?;
    Ok(borradas)
}

fn fila_a_entrada(fila: &Row<'_>) -> rusqlite::Result<SeenEntry> {
    let kind: String = fila.get(1)?;
    Ok(SeenEntry {
        device_id: fila.get(0)?,
        kind: SeenKind::from_str(&kind).unwrap_or(SeenKind::App),
        key: fila.get(2)?,
        first_seen: fila.get(3)?,
        last_seen: fila.get(4)?,
    })
}

fn fila_a_entrada_host(fila: &Row<'_>) -> rusqlite::Result<HostSeenEntry> {
    let kind: String = fila.get(0)?;
    Ok(HostSeenEntry {
        kind: SeenKind::from_str(&kind).unwrap_or(SeenKind::App),
        key: fila.get(1)?,
        first_seen: fila.get(2)?,
        last_seen: fila.get(3)?,
    })
}

// API de la Fase 5/6 sobre el repositorio para el inventario.
impl crate::repo::Repo {
    /// Lista el inventario de un equipo.
    pub fn list_seen(&self, device_id: i64) -> crate::error::Result<Vec<SeenEntry>> {
        list(&self.conn, device_id)
    }

    /// Lista el inventario del propio equipo (§7.11).
    pub fn list_host_seen(&self) -> crate::error::Result<Vec<HostSeenEntry>> {
        list_host(&self.conn)
    }

    /// Inserta o actualiza el inventario de un lote y devuelve lo nuevo (§7.11).
    pub fn upsert_seen(
        &mut self,
        items: &[SeenItem],
        at: SystemTime,
    ) -> crate::error::Result<SeenChange> {
        upsert_seen(&mut self.conn, items, &instante_a_rfc3339(at))
    }

    /// Purga el inventario del propio equipo a los `day_days` de su last_seen.
    pub fn prune_host_seen(&mut self, before: SystemTime) -> crate::error::Result<usize> {
        prune_host_seen(&self.conn, before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;
    use std::time::Duration;
    use tempfile::tempdir;

    /// Instante fijo de las pruebas: 2026-01-01T10:00:00Z.
    fn instante(horas: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_261_600 + horas * 3600)
    }

    fn repo_con_equipo() -> (tempfile::TempDir, Repo, i64) {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let id = repo
            .upsert_interface(&crate::repo::Interface::without_id(
                "eth0",
                None,
                Some("192.168.1.10".to_string()),
                None,
                None,
                true,
                "2026-01-01T00:00:00Z",
            ))
            .expect("interfaz");
        let (device_id, _) = repo
            .upsert_device(&crate::repo::DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.50".to_string(),
                hostname: None,
                vendor: None,
                interface_id: id,
                device_type: "unknown".to_string(),
            })
            .expect("equipo");
        (dir, repo, device_id)
    }

    #[test]
    fn el_inventario_se_lista_por_equipo_y_tipo() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let items = vec![
            SeenItem::de_equipo(device_id, SeenKind::App, "youtube"),
            SeenItem::de_equipo(device_id, SeenKind::Country, "US"),
        ];
        let cambio = repo.upsert_seen(&items, instante(0)).expect("upsert");
        assert_eq!(cambio.new_items.len(), 2);
        let entradas = list(repo.connection(), device_id).expect("listar");
        assert_eq!(entradas.len(), 2);
        assert_eq!(entradas[0].kind, SeenKind::App);
        assert_eq!(entradas[1].kind, SeenKind::Country);
        assert_eq!(
            first_seen(repo.connection(), device_id)
                .expect("primera")
                .as_deref(),
            Some("2026-01-01T10:00:00Z")
        );
    }

    #[test]
    fn el_inventario_del_propio_equipo_vive_en_host_seen() {
        let (_dir, mut repo, _device_id) = repo_con_equipo();
        let items = vec![
            SeenItem::del_host(SeenKind::App, "steam"),
            SeenItem::del_host(SeenKind::Org, "Valve Corporation"),
        ];
        let cambio = repo.upsert_seen(&items, instante(0)).expect("primera vez");
        assert_eq!(cambio.new_items.len(), 2);
        assert!(cambio.new_items.iter().all(SeenItem::es_host));
        assert!(list(repo.connection(), 1)
            .expect("listar equipos")
            .is_empty());

        // Repetir solo actualiza last_seen y no devuelve novedades.
        let cambio = repo.upsert_seen(&items, instante(1)).expect("segunda vez");
        assert!(cambio.is_empty());
        let entradas = list_host(repo.connection()).expect("listar host");
        assert_eq!(entradas.len(), 2);
        assert_eq!(entradas[0].kind, SeenKind::App);
        assert_eq!(entradas[0].first_seen, "2026-01-01T10:00:00Z");
        assert_eq!(entradas[0].last_seen, "2026-01-01T11:00:00Z");
    }

    #[test]
    fn un_lote_mezcla_equipos_y_propio_equipo_y_devuelve_solo_lo_nuevo() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let items = vec![
            SeenItem::de_equipo(device_id, SeenKind::App, "youtube"),
            SeenItem::del_host(SeenKind::App, "steam"),
        ];
        let cambio = repo.upsert_seen(&items, instante(0)).expect("lote");
        assert_eq!(cambio.new_items.len(), 2);

        let items = vec![
            SeenItem::de_equipo(device_id, SeenKind::App, "youtube"),
            SeenItem::del_host(SeenKind::App, "steam"),
            SeenItem::de_equipo(device_id, SeenKind::Ja4, "t13d1516h2"),
            SeenItem::del_host(SeenKind::Country, "IE"),
        ];
        let cambio = repo.upsert_seen(&items, instante(1)).expect("lote");
        assert_eq!(cambio.new_items.len(), 2, "solo las dos claves nuevas");
        assert_eq!(
            repo.list_host_seen().expect("host").len(),
            2,
            "el propio equipo tiene sus dos claves"
        );
        assert_eq!(
            repo.list_seen(device_id).expect("equipo").len(),
            2,
            "el equipo tiene las suyas"
        );
    }

    #[test]
    fn purgar_el_inventario_del_propio_equipo_respeta_el_corte() {
        let (_dir, mut repo, _device_id) = repo_con_equipo();
        let corte = instante(0) + std::time::Duration::from_secs(30 * 60);
        let items = vec![SeenItem::del_host(SeenKind::App, "steam")];
        repo.upsert_seen(&items, instante(0)).expect("inventario");
        assert_eq!(repo.prune_host_seen(corte).expect("purgar"), 1);
        assert_eq!(repo.prune_host_seen(corte).expect("segunda purga"), 0);
        assert!(repo.list_host_seen().expect("listar").is_empty());
    }
}
