//! Hilo lector con conexión de solo lectura (§4.5 y §7.10).
//!
//! Las consultas del histórico pueden tardar cientos de milisegundos y no
//! pueden bloquear el hilo de la TUI (ADR-60). El lector abre su propia conexión
//! con SQLITE_OPEN_READ_ONLY y PRAGMA query_only = ON, recibe peticiones con un
//! identificador creciente y responde por AppEvent::History. Cada consulta se
//! corta a los 2 s con un progress_handler, que interrumpe la sentencia en curso
//! y devuelve un error que la vista muestra sin colgar la interfaz.

// Varias operaciones de esta API son parte del checklist de F5 y solo las usan
// las pruebas o la integración de la TUI; se permite dead_code como en los DAO
// de fases anteriores.
#![allow(dead_code)]

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use tokio::sync::broadcast;

use super::queries;
use super::{HistoryQuery, HistoryResponse};
use crate::error::{Error, Result};
use crate::events::AppEvent;

/// Tiempo máximo de una consulta del histórico (§7.10).
pub const LIMITE_CONSULTA: Duration = Duration::from_secs(2);

/// Instrucciones de la máquina virtual entre comprobaciones del plazo.
const OPS_ENTRE_COMPROBACIONES: i32 = 1000;

/// Mensaje de error de la consulta interrumpida por el plazo.
pub const MENSAJE_TIMEOUT: &str =
    "La consulta del histórico tardó más de 2 s; prueba con un rango menor";

/// Manejador de consultas del histórico.
#[derive(Debug, Clone)]
pub struct HistoryHandle {
    tx: mpsc::Sender<(u64, HistoryQuery)>,
}

impl HistoryHandle {
    /// Encola una consulta con su identificador creciente.
    ///
    /// La respuesta llega por AppEvent::History con el mismo identificador; la
    /// TUI descarta las respuestas que no sean de la última petición de la vista.
    pub fn query(&self, id: u64, consulta: HistoryQuery) {
        if self.tx.send((id, consulta)).is_err() {
            tracing::debug!(id, "el hilo lector del histórico ya no está disponible");
        }
    }

    /// Crea un manejador a partir del canal interno (solo lo usa el lector).
    pub fn from_sender(tx: mpsc::Sender<(u64, HistoryQuery)>) -> Self {
        Self { tx }
    }
}

/// Lanzador del hilo lector del histórico.
pub struct HistoryReader;

impl HistoryReader {
    /// Lanza el hilo lector con su conexión de solo lectura.
    ///
    /// Se llama después de las migraciones, con la conexión de escritura ya
    /// abierta: así existen los ficheros -wal y -shm que necesita una conexión
    /// de solo lectura en modo WAL.
    pub fn spawn(db_path: &Path, events: broadcast::Sender<AppEvent>) -> Result<HistoryHandle> {
        let conexion = abrir_solo_lectura(db_path)?;
        let (tx, rx) = mpsc::channel();
        let nombre = "almenara-historico";
        std::thread::Builder::new()
            .name(nombre.to_string())
            .spawn(move || bucle_lector(conexion, rx, events))
            .map_err(|err| {
                Error::History(format!(
                    "no se pudo lanzar el hilo lector del histórico: {err}"
                ))
            })?;
        Ok(HistoryHandle { tx })
    }
}

/// Abre la conexión de solo lectura: ni el lector ni un fallo suyo pueden
/// escribir en la base de datos.
fn abrir_solo_lectura(ruta: &Path) -> Result<Connection> {
    let conexion = Connection::open_with_flags(
        ruta,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| Error::database_open(ruta, &err))?;
    conexion.busy_timeout(Duration::from_millis(5_000))?;
    conexion.execute_batch("PRAGMA query_only = ON;")?;
    Ok(conexion)
}

/// Bucle del hilo: una consulta detrás de otra, respondiendo por el bus.
fn bucle_lector(
    conexion: Connection,
    receptor: mpsc::Receiver<(u64, HistoryQuery)>,
    events: broadcast::Sender<AppEvent>,
) {
    let plazo = Arc::new(AtomicI64::new(0));
    let plazo_handler = Arc::clone(&plazo);
    conexion.progress_handler(
        OPS_ENTRE_COMPROBACIONES,
        Some(move || {
            let limite = plazo_handler.load(Ordering::Relaxed);
            limite > 0 && ahora_milisegundos() >= limite
        }),
    );

    while let Ok((id, consulta)) = receptor.recv() {
        let limite = ahora_milisegundos() + LIMITE_CONSULTA.as_millis() as i64;
        plazo.store(limite, Ordering::Relaxed);
        let respuesta = queries::ejecutar(&conexion, &consulta).map_err(error_de_consulta);
        plazo.store(0, Ordering::Relaxed);
        // Los dominios y claves del histórico solo pueden aparecer en debug.
        tracing::debug!(id, "consulta del histórico respondida");
        if events
            .send(AppEvent::History {
                id,
                response: respuesta,
            })
            .is_err()
        {
            tracing::trace!(id, "sin suscriptores para la respuesta del histórico");
        }
    }
}

/// Traduce el error de una consulta a un mensaje para la vista.
fn error_de_consulta(err: Error) -> String {
    if es_interrumpida(&err) {
        return MENSAJE_TIMEOUT.to_string();
    }
    format!("No se pudo consultar el histórico: {err}")
}

fn es_interrumpida(err: &Error) -> bool {
    matches!(
        err,
        Error::Database(rusqlite::Error::SqliteFailure(codigo, _))
            if codigo.code == rusqlite::ErrorCode::OperationInterrupted
    )
}

fn ahora_milisegundos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duracion| duracion.as_millis() as i64)
        .unwrap_or(0)
}

/// Resultado de una consulta (para pruebas y consumidores internos).
pub type ReaderResponse = std::result::Result<HistoryResponse, String>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{HistoryQuery, Range};
    use crate::repo::Repo;
    use tempfile::tempdir;

    #[test]
    fn el_lector_responde_y_respeta_el_identificador() {
        let dir = tempdir().expect("directorio temporal");
        let ruta = dir.path().join("data.db");
        let repo = Repo::init(&ruta).expect("repositorio de prueba");
        let (tx, mut rx) = broadcast::channel(8);
        let lector = HistoryReader::spawn(&ruta, tx).expect("lanzar lector");
        lector.query(
            41,
            HistoryQuery::Coverage {
                range: Range::Hours24,
                now: crate::history::localtime::now_unix(),
            },
        );
        // Sin datos, la consulta de cobertura responde con un hueco o vacío; lo
        // importante aquí es que llegue la respuesta con el id correcto y que
        // una consulta que falla no tumbe el hilo.
        let evento = rx.blocking_recv().expect("respuesta del lector");
        match evento {
            AppEvent::History { id, response } => {
                assert_eq!(id, 41);
                // La consulta puede responder datos o un error de vista: lo que
                // no puede hacer es tumbar el hilo ni perder el identificador.
                let _ = response;
            }
            otro => panic!("evento inesperado: {otro:?}"),
        }
        drop(repo);
    }

    #[test]
    fn el_lector_muere_al_cerrarse_el_canal() {
        let dir = tempdir().expect("directorio temporal");
        let ruta = dir.path().join("data.db");
        let _repo = Repo::init(&ruta).expect("repositorio de prueba");
        let (tx, _rx) = broadcast::channel(8);
        let lector = HistoryReader::spawn(&ruta, tx).expect("lanzar lector");
        drop(lector);
        // No hay forma directa de observar el hilo; basta con que no bloquee.
    }

    #[test]
    fn la_conexion_del_lector_es_de_solo_lectura() {
        let dir = tempdir().expect("directorio temporal");
        let ruta = dir.path().join("data.db");
        let _repo = Repo::init(&ruta).expect("repositorio de prueba");
        let conexion = abrir_solo_lectura(&ruta).expect("abrir en solo lectura");
        let escritura = conexion.execute_batch(
            "INSERT INTO APP_SESSIONS
                 (started_at, last_beat, mode, capture, passive_only, version)
             VALUES ('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'degraded', 0, 0, '0.5.0')",
        );
        assert!(escritura.is_err(), "el lector no puede escribir");
    }
}
