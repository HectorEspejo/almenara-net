//! Inicialización del logging a fichero con rotación por tamaño.
//!
//! La TUI ocupa la terminal, así que los logs nunca se escriben en stdout/stderr:
//! van a `~/.local/state/almenara/log/almenara.log`. `tracing-appender` aporta el
//! escritor no bloqueante (la TUI no espera al disco) y este módulo añade la
//! rotación por tamaño sobre el fichero base.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use crate::error::{Error, Result};

/// Tamaño máximo por defecto de un fichero de log (10 MiB).
pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
/// Número de ficheros rotados que se conservan.
pub const MAX_LOG_FILES: usize = 3;
/// Nombre del fichero de log.
pub const LOG_FILE_NAME: &str = "almenara.log";

/// Mantiene vivo el hilo de escritura de logs mientras la aplicación corre.
#[derive(Debug)]
pub struct LogGuard {
    _worker: WorkerGuard,
}

/// Inicializa el logging global escribiendo en `log_dir`.
///
/// Devuelve un guard que debe vivir hasta el final del programa. En caso de error
/// el arranque continúa sin logging (la persona que ejecuta verá un aviso).
pub fn init(verbose: u8, log_dir: &Path) -> Result<LogGuard> {
    fs::create_dir_all(log_dir).map_err(|err| {
        Error::Logging(format!(
            "no se pudo crear el directorio de logs {}: {err}",
            log_dir.display()
        ))
    })?;

    let writer = SizeRotatingWriter::new(log_dir.join(LOG_FILE_NAME), MAX_LOG_BYTES, MAX_LOG_FILES)
        .map_err(|err| Error::Logging(format!("no se pudo abrir el fichero de log: {err}")))?;

    let (non_blocking, guard) = tracing_appender::non_blocking(writer);

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter_directive(verbose)))
        .map_err(|err| Error::Logging(format!("filtro de logs no válido: {err}")))?;

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(false),
        )
        .try_init()
        .map_err(|err| Error::Logging(format!("no se pudo inicializar tracing: {err}")))?;

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Almenara iniciado");
    Ok(LogGuard { _worker: guard })
}

/// Directiva de filtro para `-v` / `-vv`.
pub fn filter_directive(verbose: u8) -> String {
    match verbose {
        0 => "almenara=info,warn".to_string(),
        1 => "almenara=debug,warn".to_string(),
        _ => "almenara=trace,warn".to_string(),
    }
}

/// Escritor de fichero con rotación por tamaño.
///
/// Antes de cada escritura comprueba si se superaría `max_bytes`; en tal caso
/// renombra el fichero actual a `.1` y desplaza los anteriores (conservando
/// `max_files` copias rotadas).
#[derive(Debug)]
pub struct SizeRotatingWriter {
    path: PathBuf,
    max_bytes: u64,
    max_files: usize,
    file: Option<BufWriter<File>>,
    size: u64,
}

impl SizeRotatingWriter {
    /// Crea el escritor sobre `path` en modo append.
    pub fn new(path: PathBuf, max_bytes: u64, max_files: usize) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        Ok(Self {
            path,
            max_bytes,
            max_files: max_files.max(1),
            file: Some(BufWriter::new(file)),
            size,
        })
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        PathBuf::from(format!("{}.{index}", self.path.display()))
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        // Desplaza .N-1 -> .N, ... y el fichero base -> .1, descartando el más antiguo.
        for index in (1..self.max_files).rev() {
            let desde = self.rotated_path(index);
            let hasta = self.rotated_path(index + 1);
            if desde.exists() {
                let _ = fs::rename(desde, hasta);
            }
        }
        if self.max_files >= 1 && self.path.exists() {
            let _ = fs::rename(&self.path, self.rotated_path(1));
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.file = Some(BufWriter::new(file));
        self.size = 0;
        Ok(())
    }
}

impl Write for SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "log cerrado"))?;
        let written = file.write(buf)?;
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
        }
        Ok(())
    }
}

impl Drop for SizeRotatingWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directivas_segun_verbosidad() {
        assert_eq!(filter_directive(0), "almenara=info,warn");
        assert_eq!(filter_directive(1), "almenara=debug,warn");
        assert_eq!(filter_directive(2), "almenara=trace,warn");
        assert_eq!(filter_directive(5), "almenara=trace,warn");
    }

    #[test]
    fn rota_por_tamano_y_conserva_copias() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("almenara.log");
        {
            let mut writer = SizeRotatingWriter::new(path.clone(), 10, 2).unwrap();
            for _ in 0..6 {
                writer.write_all(b"0123456789").unwrap();
            }
            writer.flush().unwrap();
        }
        assert!(path.exists(), "debe existir el fichero activo");
        assert!(path.with_extension("log.1").exists(), "debe existir .1");
        let tamano = fs::metadata(&path).unwrap().len();
        assert!(tamano <= 10, "el fichero activo no debe superar el máximo");
    }

    #[test]
    fn sin_rotacion_si_cabe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("almenara.log");
        {
            let mut writer = SizeRotatingWriter::new(path.clone(), 1024, 3).unwrap();
            writer.write_all(b"linea corta").unwrap();
            writer.flush().unwrap();
        }
        assert!(path.exists());
        assert!(!path.with_extension("log.1").exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), "linea corta");
    }

    #[test]
    fn append_conserva_lo_anterior() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("almenara.log");
        fs::write(&path, "previo\n").unwrap();
        {
            let mut writer = SizeRotatingWriter::new(path.clone(), 1024, 3).unwrap();
            writer.write_all(b"nuevo\n").unwrap();
            writer.flush().unwrap();
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), "previo\nnuevo\n");
    }
}
