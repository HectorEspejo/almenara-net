//! DAO de los huecos dentro de una sesión de Almenara (COVERAGE_GAPS, §7.10).
//!
//! Un hueco es un intervalo sin datos dentro de una sesión: `suspend` (el equipo
//! estuvo suspendido: no hay tráfico ni escaneo) o `capture` (la captura estaba
//! parada: no hay tráfico). La suspensión se guarda ya cerrada con el reloj de
//! pared de los dos ticks que la detectan; el hueco de captura se abre al
//! pararse la captura y se cierra cuando vuelve, al salir con `q` o, tras una
//! caída, en el arranque siguiente con el `ended_at` de su sesión.
//!
//! Toda cobertura de tráfico (histórico, aprendizaje y «más tráfico de lo
//! habitual») resta estos huecos; la presencia solo resta los de suspensión.

use std::time::SystemTime;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::history::localtime;
use crate::repo::{instante_a_rfc3339, rfc3339_a_instante};

/// Tipo de hueco dentro de una sesión (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapKind {
    /// El equipo estuvo suspendido (sin tráfico ni escaneo).
    Suspend,
    /// La captura estuvo parada (sin tráfico).
    Capture,
}

impl GapKind {
    /// Todos los tipos de hueco.
    pub const ALL: [Self; 2] = [Self::Suspend, Self::Capture];

    /// Representación persistida en COVERAGE_GAPS.kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Capture => "capture",
        }
    }

    /// Reconstruye el tipo desde su representación persistida.
    pub fn from_str(valor: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == valor)
    }
}

/// Abre un hueco (o guarda una suspensión ya cerrada) y devuelve su id.
pub(crate) fn open(
    conn: &Connection,
    session_id: i64,
    kind: GapKind,
    from: SystemTime,
    to: Option<SystemTime>,
) -> Result<i64> {
    let id = conn.query_row(
        "INSERT INTO COVERAGE_GAPS (session_id, kind, started_at, ended_at)
         VALUES (?1, ?2, ?3, ?4)
         RETURNING id",
        params![
            session_id,
            kind.as_str(),
            instante_a_rfc3339(from),
            to.map(instante_a_rfc3339)
        ],
        |fila| fila.get(0),
    )?;
    Ok(id)
}

/// Cierra un hueco abierto. Si ya estaba cerrado no cambia nada.
pub(crate) fn close(conn: &Connection, id: i64, at: SystemTime) -> Result<usize> {
    let cerrados = conn.execute(
        "UPDATE COVERAGE_GAPS SET ended_at = ?1 WHERE id = ?2 AND ended_at IS NULL",
        params![instante_a_rfc3339(at), id],
    )?;
    Ok(cerrados)
}

/// Cierra todos los huecos abiertos de una sesión (salida con `q`).
pub(crate) fn close_open(conn: &Connection, session_id: i64, at: SystemTime) -> Result<usize> {
    let cerrados = conn.execute(
        "UPDATE COVERAGE_GAPS SET ended_at = ?1
          WHERE session_id = ?2 AND ended_at IS NULL",
        params![instante_a_rfc3339(at), session_id],
    )?;
    Ok(cerrados)
}

/// Id del último hueco abierto de un tipo en una sesión, si lo hay.
pub(crate) fn last_open(conn: &Connection, session_id: i64, kind: GapKind) -> Result<Option<i64>> {
    let id = conn
        .query_row(
            "SELECT id FROM COVERAGE_GAPS
              WHERE session_id = ?1 AND kind = ?2 AND ended_at IS NULL
              ORDER BY id DESC LIMIT 1",
            params![session_id, kind.as_str()],
            |fila| fila.get(0),
        )
        .optional()?;
    Ok(id)
}

/// Cierra los huecos abiertos de sesiones ya cerradas con el `ended_at` de su
/// sesión (arranque tras una caída, §7.10).
///
/// Lo llama `Repo::close_open_sessions` después de cerrar las sesiones
/// interrumpidas: en ese momento toda sesión abierta acaba de recibir su
/// `ended_at = last_beat`, así que ningún hueco puede quedar abierto.
pub(crate) fn close_of_closed_sessions(conn: &Connection) -> Result<usize> {
    let cerrados = conn.execute(
        "UPDATE COVERAGE_GAPS
            SET ended_at = (SELECT s.ended_at FROM APP_SESSIONS s
                             WHERE s.id = COVERAGE_GAPS.session_id)
          WHERE ended_at IS NULL
            AND session_id IN (SELECT id FROM APP_SESSIONS WHERE ended_at IS NOT NULL)",
        [],
    )?;
    Ok(cerrados)
}

/// Segundos de cobertura de tráfico entre dos instantes Unix (ambos incluidos en
/// el redondeo, el fin excluido).
///
/// La cobertura la forman las sesiones con captura activa, unidas y sin solapar,
/// menos los huecos de `COVERAGE_GAPS` (suspensión y captura parada). Los
/// instantes abiertos (sesión o hueco sin `ended_at`) se cierran con `ahora`.
pub(crate) fn cobertura_trafico(
    conn: &Connection,
    desde: i64,
    hasta: i64,
    ahora: i64,
) -> Result<i64> {
    if hasta <= desde {
        return Ok(0);
    }
    let sesiones = unir(intervalos(
        conn,
        "SELECT started_at, ended_at FROM APP_SESSIONS
          WHERE capture = 1 AND started_at < ?1 AND (ended_at IS NULL OR ended_at > ?2)",
        desde,
        hasta,
        ahora,
    )?);
    let huecos = unir(intervalos(
        conn,
        "SELECT started_at, ended_at FROM COVERAGE_GAPS
          WHERE started_at < ?1 AND (ended_at IS NULL OR ended_at > ?2)",
        desde,
        hasta,
        ahora,
    )?);
    Ok(longitud(&sesiones) - longitud_interseccion(&sesiones, &huecos))
}

/// Indica si una hora UTC tiene cobertura de tráfico completa (§7.4).
///
/// Los huecos de menos de un minuto no cuentan (granularidad del latido): se
/// ignoran al restar. La hora debe estar cubierta entera por sesiones con
/// captura.
pub(crate) fn hora_con_cobertura(conn: &Connection, hora: i64, ahora: i64) -> Result<bool> {
    let hasta = hora.saturating_add(3600);
    if hasta <= hora {
        return Ok(false);
    }
    let sesiones = unir(intervalos(
        conn,
        "SELECT started_at, ended_at FROM APP_SESSIONS
          WHERE capture = 1 AND started_at < ?1 AND (ended_at IS NULL OR ended_at > ?2)",
        hora,
        hasta,
        ahora,
    )?);
    let mut huecos = intervalos(
        conn,
        "SELECT started_at, ended_at FROM COVERAGE_GAPS
          WHERE started_at < ?1 AND (ended_at IS NULL OR ended_at > ?2)",
        hora,
        hasta,
        ahora,
    )?;
    // Un hueco de menos de un minuto es ruido del latido y no invalida la hora.
    huecos.retain(|(inicio, fin)| fin - inicio >= 60);
    let huecos = unir(huecos);
    let cubierto = longitud(&sesiones) - longitud_interseccion(&sesiones, &huecos);
    Ok(cubierto >= hasta - hora)
}

/// Lee intervalos de una consulta con fechas RFC 3339 y los recorta a la ventana.
///
/// Los textos corruptos se omiten (base de datos dañada): nunca entran en pánico.
fn intervalos(
    conn: &Connection,
    sql: &str,
    desde: i64,
    hasta: i64,
    ahora: i64,
) -> Result<Vec<(i64, i64)>> {
    let mut sentencia = conn.prepare(sql)?;
    let filas = sentencia.query_map(
        params![localtime::rfc3339(hasta), localtime::rfc3339(desde)],
        |fila| Ok((fila.get::<_, String>(0)?, fila.get::<_, Option<String>>(1)?)),
    )?;
    let mut intervalos = Vec::new();
    for fila in filas {
        let (inicio_texto, fin_texto) = fila?;
        let Some(inicio) = rfc3339_a_instante(&inicio_texto).and_then(unix_de_instante) else {
            tracing::debug!(fecha = %inicio_texto, "fecha corrupta en la cobertura; se omite");
            continue;
        };
        let fin = match fin_texto {
            Some(texto) => match rfc3339_a_instante(&texto).and_then(unix_de_instante) {
                Some(fin) => fin,
                None => {
                    tracing::debug!(fecha = %texto, "fecha de fin corrupta; se omite el intervalo");
                    continue;
                }
            },
            None => ahora,
        };
        let inicio = inicio.max(desde);
        let fin = fin.min(hasta);
        if fin > inicio {
            intervalos.push((inicio, fin));
        }
    }
    Ok(intervalos)
}

/// Convierte un instante a segundos Unix (None si es anterior a la época).
pub(crate) fn unix_de_instante(instante: SystemTime) -> Option<i64> {
    instante
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duracion| i64::try_from(duracion.as_secs()).ok())
}

/// Une una lista de intervalos solapados o contiguos.
fn unir(mut intervalos: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    intervalos.sort_unstable();
    let mut unidos: Vec<(i64, i64)> = Vec::new();
    for (inicio, fin) in intervalos {
        match unidos.last_mut() {
            Some(ultimo) if inicio <= ultimo.1 => ultimo.1 = ultimo.1.max(fin),
            _ => unidos.push((inicio, fin)),
        }
    }
    unidos
}

/// Longitud total de una lista de intervalos ya unidos y ordenados.
fn longitud(intervalos: &[(i64, i64)]) -> i64 {
    intervalos.iter().map(|(inicio, fin)| fin - inicio).sum()
}

/// Longitud de la intersección de dos listas de intervalos ya unidas.
fn longitud_interseccion(a: &[(i64, i64)], b: &[(i64, i64)]) -> i64 {
    let (mut i, mut j) = (0usize, 0usize);
    let mut total = 0i64;
    while i < a.len() && j < b.len() {
        let inicio = a[i].0.max(b[j].0);
        let fin = a[i].1.min(b[j].1);
        if fin > inicio {
            total += fin - inicio;
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    total
}

impl crate::repo::Repo {
    /// Abre un hueco de captura o guarda una suspensión ya cerrada (§7.10).
    pub fn open_gap(
        &mut self,
        session_id: i64,
        kind: GapKind,
        from: SystemTime,
        to: Option<SystemTime>,
    ) -> crate::error::Result<i64> {
        open(&self.conn, session_id, kind, from, to)
    }

    /// Cierra un hueco de captura.
    pub fn close_gap(&mut self, id: i64, at: SystemTime) -> crate::error::Result<()> {
        close(&self.conn, id, at)?;
        Ok(())
    }

    /// Cierra todos los huecos abiertos de una sesión (salida con `q`).
    pub fn close_open_gaps(
        &mut self,
        session_id: i64,
        at: SystemTime,
    ) -> crate::error::Result<usize> {
        close_open(&self.conn, session_id, at)
    }

    /// Id del último hueco abierto de un tipo en una sesión.
    pub fn last_open_gap(
        &self,
        session_id: i64,
        kind: GapKind,
    ) -> crate::error::Result<Option<i64>> {
        last_open(&self.conn, session_id, kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Repo;
    use tempfile::tempdir;

    /// Repositorio con una sesión abierta; devuelve su id.
    fn repo_con_sesion() -> (tempfile::TempDir, Repo, i64) {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let id = repo
            .open_session(&crate::history::SessionInfo {
                mode: "privileged".to_string(),
                capture: true,
                passive_only: false,
                version: "0.6.0".to_string(),
            })
            .expect("sesión");
        (dir, repo, id)
    }

    fn instante(texto: &str) -> SystemTime {
        rfc3339_a_instante(texto).expect("fecha de prueba")
    }

    #[test]
    fn abrir_cerrar_y_localizar_huecos() {
        let (_dir, mut repo, session_id) = repo_con_sesion();
        let desde = instante("2026-11-04T10:00:00Z");
        let id = repo
            .open_gap(session_id, GapKind::Capture, desde, None)
            .expect("abrir hueco");
        assert_eq!(
            repo.last_open_gap(session_id, GapKind::Capture)
                .expect("último abierto"),
            Some(id)
        );
        assert_eq!(
            repo.last_open_gap(session_id, GapKind::Suspend)
                .expect("sin suspensión"),
            None
        );
        repo.close_gap(id, instante("2026-11-04T10:05:00Z"))
            .expect("cerrar");
        assert_eq!(
            repo.last_open_gap(session_id, GapKind::Capture)
                .expect("ya cerrado"),
            None
        );
        // Cerrar dos veces no falla ni pisa el cierre.
        repo.close_gap(id, instante("2026-11-04T11:00:00Z"))
            .expect("cerrar otra vez");
        let terminado: String = repo
            .connection()
            .query_row(
                "SELECT ended_at FROM COVERAGE_GAPS WHERE id = ?1",
                params![id],
                |fila| fila.get(0),
            )
            .expect("leer cierre");
        assert_eq!(terminado, "2026-11-04T10:05:00Z");
    }

    #[test]
    fn una_suspension_se_guarda_ya_cerrada_y_no_es_un_hueco_abierto() {
        let (_dir, mut repo, session_id) = repo_con_sesion();
        let desde = instante("2026-11-04T10:00:00Z");
        let hasta = instante("2026-11-04T18:00:00Z");
        repo.open_gap(session_id, GapKind::Suspend, desde, Some(hasta))
            .expect("guardar suspensión");
        assert_eq!(
            repo.last_open_gap(session_id, GapKind::Suspend)
                .expect("no queda abierto"),
            None
        );
        let (inicio, fin): (String, String) = repo
            .connection()
            .query_row(
                "SELECT started_at, ended_at FROM COVERAGE_GAPS",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer suspensión");
        assert_eq!(inicio, "2026-11-04T10:00:00Z");
        assert_eq!(fin, "2026-11-04T18:00:00Z");
    }

    #[test]
    fn la_cobertura_de_trafico_resta_suspensiones_y_capturas_paradas() {
        let (_dir, mut repo, _session_id) = repo_con_sesion();
        let conn = repo.connection_mut();
        conn.execute(
            "INSERT INTO APP_SESSIONS
                 (started_at, ended_at, last_beat, end_reason, mode, capture, passive_only,
                  version)
             VALUES ('2026-11-04T10:00:00Z', '2026-11-04T12:00:00Z',
                     '2026-11-04T12:00:00Z', 'quit', 'privileged', 1, 0, '0.6.0')",
            [],
        )
        .expect("sesión con captura");
        // Suspensión de 15 min y captura parada de 10 min.
        conn.execute(
            "INSERT INTO COVERAGE_GAPS (session_id, kind, started_at, ended_at)
             VALUES (1, 'suspend', '2026-11-04T10:30:00Z', '2026-11-04T10:45:00Z')",
            [],
        )
        .expect("suspensión");
        conn.execute(
            "INSERT INTO COVERAGE_GAPS (session_id, kind, started_at, ended_at)
             VALUES (1, 'capture', '2026-11-04T11:00:00Z', '2026-11-04T11:10:00Z')",
            [],
        )
        .expect("captura parada");

        let ahora = localtime::now_unix();
        let desde = unix_de_instante(instante("2026-11-04T09:00:00Z")).unwrap();
        let hasta = unix_de_instante(instante("2026-11-04T13:00:00Z")).unwrap();
        let cobertura = cobertura_trafico(conn, desde, hasta, ahora).expect("cobertura");
        assert_eq!(
            cobertura,
            2 * 3600 - 15 * 60 - 10 * 60,
            "120 min de sesión menos 15 de suspensión y 10 de captura parada"
        );
    }

    #[test]
    fn una_sesion_sin_captura_no_cubre_trafico() {
        let (_dir, mut repo, _session_id) = repo_con_sesion();
        let conn = repo.connection_mut();
        conn.execute(
            "INSERT INTO APP_SESSIONS
                 (started_at, ended_at, last_beat, end_reason, mode, capture, passive_only,
                  version)
             VALUES ('2026-11-04T10:00:00Z', '2026-11-04T12:00:00Z',
                     '2026-11-04T12:00:00Z', 'quit', 'degraded', 0, 0, '0.6.0')",
            [],
        )
        .expect("sesión sin captura");
        let ahora = localtime::now_unix();
        let desde = unix_de_instante(instante("2026-11-04T10:00:00Z")).unwrap();
        let hasta = unix_de_instante(instante("2026-11-04T12:00:00Z")).unwrap();
        assert_eq!(
            cobertura_trafico(conn, desde, hasta, ahora).expect("cobertura"),
            0
        );
    }

    #[test]
    fn una_hora_tiene_cobertura_si_los_huecos_son_de_menos_de_un_minuto() {
        let (_dir, mut repo, _session_id) = repo_con_sesion();
        let conn = repo.connection_mut();
        let hora = unix_de_instante(instante("2026-11-04T10:00:00Z")).unwrap();
        conn.execute(
            "INSERT INTO APP_SESSIONS
                 (started_at, ended_at, last_beat, end_reason, mode, capture, passive_only,
                  version)
             VALUES ('2026-11-04T10:00:00Z', '2026-11-04T12:00:00Z',
                     '2026-11-04T12:00:00Z', 'quit', 'privileged', 1, 0, '0.6.0')",
            [],
        )
        .expect("sesión");
        let ahora = localtime::now_unix();

        // Sin huecos: cobertura completa.
        assert!(hora_con_cobertura(conn, hora, ahora).expect("primera"));
        // Un hueco de 30 s es ruido del latido: no invalida la hora.
        conn.execute(
            "INSERT INTO COVERAGE_GAPS (session_id, kind, started_at, ended_at)
             VALUES (1, 'capture', '2026-11-04T10:20:00Z', '2026-11-04T10:20:30Z')",
            [],
        )
        .expect("hueco corto");
        assert!(hora_con_cobertura(conn, hora, ahora).expect("hueco corto"));
        // Un hueco de dos minutos sí la invalida.
        conn.execute(
            "INSERT INTO COVERAGE_GAPS (session_id, kind, started_at, ended_at)
             VALUES (1, 'suspend', '2026-11-04T10:30:00Z', '2026-11-04T10:32:00Z')",
            [],
        )
        .expect("hueco largo");
        assert!(!hora_con_cobertura(conn, hora, ahora).expect("hueco largo"));
    }

    #[test]
    fn cerrar_los_huecos_de_una_sesion_ya_cerrada_los_deja_con_su_cierre() {
        let (_dir, mut repo, session_id) = repo_con_sesion();
        let desde = instante("2026-11-04T10:00:00Z");
        repo.open_gap(session_id, GapKind::Capture, desde, None)
            .expect("hueco abierto");
        repo.connection()
            .execute(
                "UPDATE APP_SESSIONS
                    SET ended_at = '2026-11-04T10:41:00Z',
                        last_beat = '2026-11-04T10:41:00Z'
                  WHERE id = ?1",
                params![session_id],
            )
            .expect("cerrar sesión a mano");
        assert_eq!(
            close_of_closed_sessions(repo.connection()).expect("cerrar huecos"),
            1
        );
        let terminado: String = repo
            .connection()
            .query_row(
                "SELECT ended_at FROM COVERAGE_GAPS WHERE session_id = ?1",
                params![session_id],
                |fila| fila.get(0),
            )
            .expect("leer cierre");
        assert_eq!(terminado, "2026-11-04T10:41:00Z");
        assert_eq!(
            close_of_closed_sessions(repo.connection()).expect("idempotente"),
            0
        );
    }
}
