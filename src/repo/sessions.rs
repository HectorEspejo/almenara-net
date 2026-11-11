//! DAO de las sesiones de Almenara (APP_SESSIONS, §7.6).
//!
//! Cada ejecución de Almenara abre una sesión con su modo, captura, modo pasivo
//! y versión, y da un latido cada minuto. Si el proceso muere sin salir, la
//! sesión queda abierta y el arranque siguiente la cierra como interrumpida con
//! ended_at = last_beat (pérdida máxima: un minuto).

use rusqlite::{params, Connection, Row};

use crate::error::Result;
use crate::history::SessionInfo;
use crate::repo::ahora_rfc3339;

/// Sesión de Almenara persistida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// Identificador interno.
    pub id: i64,
    /// Arranque (RFC 3339 UTC).
    pub started_at: String,
    /// Cierre; None mientras está abierta.
    pub ended_at: Option<String>,
    /// Último latido (RFC 3339 UTC).
    pub last_beat: String,
    /// Motivo de cierre: quit o interrupted.
    pub end_reason: Option<String>,
    /// Modo de ejecución: privileged o degraded.
    pub mode: String,
    /// Había captura al arrancar.
    pub capture: bool,
    /// Modo pasivo de escaneo.
    pub passive_only: bool,
    /// Versión de Almenara.
    pub version: String,
}

const SQL_SELECCION: &str = "\
SELECT id, started_at, ended_at, last_beat, end_reason, mode, capture, passive_only, version
  FROM APP_SESSIONS";

/// Abre una sesión nueva y devuelve su id.
pub(crate) fn open(conn: &Connection, info: &SessionInfo) -> Result<i64> {
    let ahora = ahora_rfc3339();
    let id = conn.query_row(
        "INSERT INTO APP_SESSIONS
             (started_at, ended_at, last_beat, end_reason, mode, capture, passive_only, version)
         VALUES (?1, NULL, ?1, NULL, ?2, ?3, ?4, ?5)
         RETURNING id",
        params![
            ahora,
            info.mode,
            info.capture,
            info.passive_only,
            info.version
        ],
        |fila| fila.get(0),
    )?;
    Ok(id)
}

/// Actualiza el latido de una sesión abierta.
pub(crate) fn beat(conn: &Connection, id: i64, at: &str) -> Result<()> {
    conn.execute(
        "UPDATE APP_SESSIONS SET last_beat = ?1 WHERE id = ?2 AND ended_at IS NULL",
        params![at, id],
    )?;
    Ok(())
}

/// Cierra una sesión con end_reason = quit.
pub(crate) fn close(conn: &Connection, id: i64, at: &str) -> Result<()> {
    conn.execute(
        "UPDATE APP_SESSIONS
            SET ended_at = ?1, last_beat = MAX(last_beat, ?1), end_reason = 'quit'
          WHERE id = ?2 AND ended_at IS NULL",
        params![at, id],
    )?;
    Ok(())
}

/// Cierra las sesiones sin cierre como interrumpidas (ended_at = last_beat).
///
/// Además cierra los huecos de `COVERAGE_GAPS` que quedaron abiertos en esas
/// sesiones con el `ended_at` de su sesión (§7.10): tras una caída, un hueco de
/// captura parada no puede quedarse abierto para siempre.
pub(crate) fn close_open(conn: &mut Connection) -> Result<usize> {
    let transaccion = conn.transaction()?;
    let cerradas = transaccion.execute(
        "UPDATE APP_SESSIONS
            SET ended_at = last_beat, end_reason = 'interrupted'
          WHERE ended_at IS NULL",
        [],
    )?;
    let huecos = crate::repo::gaps::close_of_closed_sessions(&transaccion)?;
    transaccion.commit()?;
    if huecos > 0 {
        tracing::debug!(
            huecos,
            "huecos abiertos cerrados con su sesión interrumpida"
        );
    }
    Ok(cerradas)
}

/// Lista todas las sesiones ordenadas por arranque.
pub(crate) fn list(conn: &Connection) -> Result<Vec<SessionRow>> {
    let mut sentencia = conn.prepare(&format!("{SQL_SELECCION} ORDER BY started_at, id"))?;
    let filas = sentencia.query_map([], fila_a_sesion)?;
    let mut sesiones = Vec::new();
    for fila in filas {
        sesiones.push(fila?);
    }
    Ok(sesiones)
}

fn fila_a_sesion(fila: &Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        id: fila.get(0)?,
        started_at: fila.get(1)?,
        ended_at: fila.get(2)?,
        last_beat: fila.get(3)?,
        end_reason: fila.get(4)?,
        mode: fila.get(5)?,
        capture: fila.get(6)?,
        passive_only: fila.get(7)?,
        version: fila.get(8)?,
    })
}

// API de la Fase 5 sobre el repositorio para las sesiones de Almenara.
#[allow(dead_code)]
impl crate::repo::Repo {
    /// Abre la sesión de Almenara del arranque (§7.6).
    pub fn open_session(&mut self, info: &SessionInfo) -> crate::error::Result<i64> {
        open(&self.conn, info)
    }

    /// Da el latido de la sesión cada minuto.
    pub fn beat_session(&mut self, id: i64, at: std::time::SystemTime) -> crate::error::Result<()> {
        beat(&self.conn, id, &crate::repo::instante_a_rfc3339(at))
    }

    /// Cierra la sesión con end_reason = quit.
    pub fn close_session(
        &mut self,
        id: i64,
        at: std::time::SystemTime,
    ) -> crate::error::Result<()> {
        close(&self.conn, id, &crate::repo::instante_a_rfc3339(at))
    }

    /// Cierra como interrumpidas las sesiones que quedaron abiertas.
    pub fn close_open_sessions(&mut self) -> crate::error::Result<usize> {
        close_open(&mut self.conn)
    }

    /// Lista las sesiones de Almenara ordenadas por arranque.
    pub fn list_sessions(&self) -> crate::error::Result<Vec<SessionRow>> {
        list(&self.conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;
    use tempfile::tempdir;

    fn info() -> SessionInfo {
        SessionInfo {
            mode: "privileged".to_string(),
            capture: true,
            passive_only: false,
            version: "0.5.0".to_string(),
        }
    }

    #[test]
    fn abrir_latir_cerrar_y_listar() {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let conn = repo.connection_mut();
        let id = open(conn, &info()).expect("abrir sesión");
        beat(conn, id, "2026-01-01T10:01:00Z").expect("latido");
        close(conn, id, "2026-01-01T10:02:00Z").expect("cerrar");
        let sesiones = list(conn).expect("listar");
        assert_eq!(sesiones.len(), 1);
        assert_eq!(sesiones[0].id, id);
        assert_eq!(sesiones[0].mode, "privileged");
        assert!(sesiones[0].capture);
        assert_eq!(sesiones[0].end_reason.as_deref(), Some("quit"));
        assert_eq!(
            sesiones[0].ended_at.as_deref(),
            Some("2026-01-01T10:02:00Z")
        );
    }

    #[test]
    fn las_sesiones_sin_cierre_se_cierran_como_interrumpidas() {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let conn = repo.connection_mut();
        let id = open(conn, &info()).expect("abrir sesión");
        beat(conn, id, "2026-01-01T10:41:00Z").expect("latido");
        assert_eq!(close_open(conn).expect("cerrar abiertas"), 1);
        assert_eq!(close_open(conn).expect("segunda vez"), 0);
        let sesiones = list(conn).expect("listar");
        assert_eq!(
            sesiones[0].ended_at.as_deref(),
            Some("2026-01-01T10:41:00Z"),
            "la interrumpida se cierra en su último latido"
        );
        assert_eq!(sesiones[0].end_reason.as_deref(), Some("interrupted"));
    }

    #[test]
    fn cerrar_una_sesion_ya_cerrada_no_la_pisa() {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let conn = repo.connection_mut();
        let id = open(conn, &info()).expect("abrir sesión");
        close(conn, id, "2026-01-01T10:02:00Z").expect("cerrar");
        close(conn, id, "2026-01-01T11:00:00Z").expect("cerrar otra vez");
        beat(conn, id, "2026-01-01T11:00:00Z").expect("latir cerrada");
        let sesiones = list(conn).expect("listar");
        assert_eq!(
            sesiones[0].ended_at.as_deref(),
            Some("2026-01-01T10:02:00Z")
        );
        // last_beat parte del instante real de apertura (open usa ahora) y el
        // cierre no lo retrasa: el latido de después no lo pisa.
        assert_ne!(
            sesiones[0].last_beat.as_str(),
            "2026-01-01T11:00:00Z",
            "una sesión cerrada no admite latidos"
        );
    }

    #[test]
    fn cerrar_las_sesiones_interrumpidas_cierra_sus_huecos_abiertos() {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let conn = repo.connection_mut();
        let id = open(conn, &info()).expect("abrir sesión");
        let inicio = crate::repo::rfc3339_a_instante("2026-01-01T10:30:00Z").expect("inicio");
        let abierto =
            crate::repo::gaps::open(conn, id, crate::repo::GapKind::Capture, inicio, None)
                .expect("abrir hueco");
        crate::repo::gaps::open(
            conn,
            id,
            crate::repo::GapKind::Suspend,
            inicio,
            Some(inicio + std::time::Duration::from_secs(600)),
        )
        .expect("guardar suspensión");
        beat(conn, id, "2026-01-01T10:41:00Z").expect("latido");

        assert_eq!(close_open(conn).expect("cerrar interrumpidas"), 1);
        let (ended_at, kind): (Option<String>, String) = conn
            .query_row(
                "SELECT ended_at, kind FROM COVERAGE_GAPS WHERE id = ?1",
                params![abierto],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer hueco cerrado");
        assert_eq!(kind, "capture");
        assert_eq!(
            ended_at.as_deref(),
            Some("2026-01-01T10:41:00Z"),
            "el hueco abierto se cierra con el ended_at de su sesión"
        );
    }
}
