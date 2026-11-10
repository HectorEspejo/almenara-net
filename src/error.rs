//! Error central de Almenara.
//!
//! Todo el código interno usa este tipo de error (via el alias [`Result`]) y lo
//! convierte a mensajes en castellano para la interfaz cuando es necesario.

use std::path::PathBuf;

use thiserror::Error;

/// Alias de resultado usado en toda la aplicación.
pub type Result<T> = std::result::Result<T, Error>;

/// Error unificado de Almenara.
#[derive(Debug, Error)]
pub enum Error {
    /// La configuración TOML es sintácticamente inválida o no pasa la validación.
    #[error("error de configuración: {0}")]
    Config(String),

    /// Error de entrada/salida genérico.
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),

    /// Error de SQLite.
    #[error("error de base de datos: {0}")]
    Database(#[from] rusqlite::Error),

    /// La base de datos no se pudo abrir ni inicializar.
    #[error("base de datos inaccesible en {path}: {reason}")]
    DatabaseOpen {
        /// Ruta de la base de datos.
        path: PathBuf,
        /// Motivo legible del fallo.
        reason: String,
    },

    /// Error al inicializar el registro de logs.
    #[error("error de logging: {0}")]
    Logging(String),

    /// Error durante el escaneo de la red.
    #[error("error de escaneo: {0}")]
    Scan(String),

    /// Error del subsistema de captura de tráfico (AF_PACKET/TPACKET_V3).
    #[error("error de captura: {0}")]
    Capture(String),

    /// Error de terminal (ratatui/crossterm).
    #[error("error de terminal: {0}")]
    Terminal(String),

    /// Ruta no válida o no expandible.
    #[error("ruta inválida: {0}")]
    InvalidPath(String),
}

impl Error {
    /// Construye un error de base de datos inaccesible a partir de un error de SQLite.
    pub fn database_open(path: impl Into<PathBuf>, source: &rusqlite::Error) -> Self {
        Self::DatabaseOpen {
            path: path.into(),
            reason: source.to_string(),
        }
    }

    /// Construye un error de configuración con contexto de fichero.
    pub fn config_at(path: &std::path::Path, reason: impl std::fmt::Display) -> Self {
        Self::Config(format!("{}: {reason}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn los_mensajes_estan_en_castellano() {
        let err = Error::Config("intervalo demasiado bajo".to_string());
        assert_eq!(
            err.to_string(),
            "error de configuración: intervalo demasiado bajo"
        );

        let err = Error::InvalidPath("~".to_string());
        assert!(err.to_string().starts_with("ruta inválida:"));
    }

    #[test]
    fn database_open_incluye_la_ruta() {
        let err = Error::database_open(
            std::path::PathBuf::from("/tmp/data.db"),
            &rusqlite::Error::QueryReturnedNoRows,
        );
        let texto = err.to_string();
        assert!(texto.contains("/tmp/data.db"));
    }
}
