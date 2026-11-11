//! Bloqueo de instancia única por base de datos (ADR-65).
//!
//! Dos Almenara sobre la misma base de datos contarían dos veces el tráfico y
//! duplicarían eventos y rollups. Se toma un flock exclusivo y no bloqueante
//! sobre el fichero <db>.lock; el kernel libera el bloqueo si el proceso muere,
//! así que no quedan bloqueos huérfanos que limpiar.

// Varias operaciones de esta API son parte del checklist de F5 y solo las usan
// las pruebas o la integración de la TUI; se permite dead_code como en los DAO
// de fases anteriores.
#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// Bloqueo de instancia única; se libera al soltar el valor.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
    pid: u32,
}

impl InstanceLock {
    /// Ruta del fichero de bloqueo que acompaña a la base de datos.
    pub fn lock_path(db_path: &Path) -> PathBuf {
        let mut nombre = db_path.as_os_str().to_owned();
        nombre.push(".lock");
        PathBuf::from(nombre)
    }

    /// Intenta tomar el bloqueo de la base de datos indicada.
    ///
    /// Devuelve el error AlreadyRunning con el PID de la otra instancia (si se
    /// pudo leer) cuando ya hay una Almenara en marcha.
    pub fn acquire(db_path: &Path) -> std::result::Result<Self, AlreadyRunning> {
        let path = Self::lock_path(db_path);
        if let Some(padre) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(padre).map_err(|err| AlreadyRunning {
                pid: None,
                detail: format!("no se pudo crear el directorio del bloqueo: {err}"),
            })?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|err| AlreadyRunning {
                pid: None,
                detail: format!("no se pudo abrir {}: {err}", path.display()),
            })?;

        // SAFETY: flock sobre el descriptor abierto; LOCK_EX | LOCK_NB no bloquea.
        let codigo = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if codigo != 0 {
            let pid = leer_pid(&mut file);
            return Err(AlreadyRunning {
                pid,
                detail: String::new(),
            });
        }

        let pid = std::process::id();
        file.set_len(0).map_err(|err| AlreadyRunning {
            pid: None,
            detail: format!("no se pudo truncar el fichero de bloqueo: {err}"),
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|err| AlreadyRunning {
                pid: None,
                detail: format!("no se pudo posicionar el fichero de bloqueo: {err}"),
            })?;
        file.write_all(pid.to_string().as_bytes())
            .map_err(|err| AlreadyRunning {
                pid: None,
                detail: format!("no se pudo escribir el PID: {err}"),
            })?;

        Ok(Self {
            _file: file,
            path,
            pid,
        })
    }

    /// PID de esta instancia.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Ruta del fichero de bloqueo.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Otra instancia de Almenara tiene la base de datos bloqueada.
#[derive(Debug, Clone)]
pub struct AlreadyRunning {
    /// PID de la otra instancia, si se pudo leer.
    pub pid: Option<u32>,
    /// Detalle del fallo (vacío si es simplemente que ya está en marcha).
    pub detail: String,
}

impl std::fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(
                f,
                "Almenara ya está en marcha (PID {pid}). Usa esa sesión (p. ej. tmux attach)."
            ),
            None => write!(
                f,
                "Almenara ya está en marcha sobre esta base de datos. Usa esa sesión (p. ej. tmux attach)."
            ),
        }
    }
}

impl std::error::Error for AlreadyRunning {}

/// Toma el bloqueo y traduce el error al tipo central de errores.
pub fn acquire(db_path: &Path) -> Result<InstanceLock> {
    InstanceLock::acquire(db_path).map_err(|err| crate::error::Error::Config(err.to_string()))
}

fn leer_pid(file: &mut File) -> Option<u32> {
    let _ = file.seek(SeekFrom::Start(0));
    let mut texto = String::new();
    file.read_to_string(&mut texto).ok()?;
    texto.trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_bloqueo_es_exclusivo_y_se_libera_al_soltarlo() {
        let dir = tempfile::tempdir().expect("directorio temporal");
        let db = dir.path().join("data.db");

        let primero = InstanceLock::acquire(&db).expect("primer bloqueo");
        assert_eq!(primero.path(), InstanceLock::lock_path(&db));
        assert!(InstanceLock::acquire(&db).is_err());

        drop(primero);
        let segundo = InstanceLock::acquire(&db).expect("bloqueo tras soltar");
        assert_eq!(segundo.pid(), std::process::id());
    }

    #[test]
    fn el_mensaje_de_ya_en_marcha_lleva_el_pid_si_se_conoce() {
        let error = AlreadyRunning {
            pid: Some(4242),
            detail: String::new(),
        };
        assert!(error.to_string().contains("PID 4242"));
        assert!(error.to_string().contains("ya está en marcha"));
    }
}
