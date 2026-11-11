//! DAO del inventario por equipo (DEVICE_SEEN, §7.9).
//!
//! Una fila por equipo, tipo y clave con la primera y la última vez que se vio.
//! Nunca guarda destinos (privacidad) ni claves especiales: el agregador ya los
//! filtra antes de enviar el lote.

use rusqlite::{params, Connection, Row};

use crate::error::Result;
use crate::history::SeenKind;

/// Entrada persistida del inventario.
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

// API de la Fase 5 sobre el repositorio para el inventario por equipo.
#[allow(dead_code)]
impl crate::repo::Repo {
    /// Lista el inventario de un equipo.
    pub fn list_seen(&self, device_id: i64) -> crate::error::Result<Vec<SeenEntry>> {
        list(&self.conn, device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;
    use tempfile::tempdir;

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
            crate::history::SeenItem {
                device_id,
                kind: SeenKind::App,
                key: "youtube".to_string(),
            },
            crate::history::SeenItem {
                device_id,
                kind: SeenKind::Country,
                key: "US".to_string(),
            },
        ];
        crate::repo::rollups::upsert_seen(repo.connection_mut(), &items, "2026-01-01T10:00:00Z")
            .expect("upsert");
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
}
