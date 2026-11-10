//! Atribución de sockets locales a procesos mediante `/proc/[pid]/fd`.
//!
//! Cada socket abierto por un proceso aparece en `/proc/[pid]/fd` como un enlace
//! simbólico cuyo destino es `socket:[<inodo>]`. Cruzando ese inodo con la columna
//! `inode` de `/proc/net/{tcp,udp}{,6}` (ver el módulo [`super::conntrack`]) se
//! obtiene el PID y el nombre corto (`comm`) del proceso dueño de cada conexión.
//!
//! La lectura es **best-effort**: como usuario normal solo se ven los procesos
//! propios, y sin permisos sobre `/proc/[pid]/fd` el proceso se omite en silencio.
//! Ningún fallo de lectura (proceso que termina, permisos, enlaces raros) debe
//! abortar la atribución del resto de sockets.

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Directorio raíz del pseudo-fichero sistema de procesos.
const RUTA_PROC: &str = "/proc";

/// Proceso dueño de un socket: PID y nombre corto del ejecutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Identificador del proceso.
    pub pid: u32,
    /// Nombre corto del proceso (`/proc/[pid]/comm`), sin salto de línea.
    pub comm: String,
}

/// Buscador de procesos dueños de sockets por inodo.
#[derive(Debug, Clone, Copy)]
pub struct Process;

impl Process {
    /// Devuelve el proceso dueño del socket con el inodo indicado.
    ///
    /// Degradación silenciosa: si no hay ningún proceso accesible con ese socket
    /// (permisos, carrera con la salida del proceso...) devuelve `None`.
    // La API del contrato de Fase 3 la exige; el flujo periódico usa attribute_many.
    #[allow(dead_code)]
    pub fn attribute(inode: u64) -> Option<ProcessInfo> {
        Self::attribute_many(&HashSet::from([inode])).remove(&inode)
    }

    /// Igual que [`Process::attribute`] pero para varios inodos en una sola pasada.
    ///
    /// Recorre `/proc` una única vez, lo que evita repetir la lectura completa de la
    /// tabla de procesos por cada conexión.
    pub fn attribute_many(inodes: &HashSet<u64>) -> HashMap<u64, ProcessInfo> {
        Self::attribute_many_in(Path::new(RUTA_PROC), inodes)
    }

    /// Versión testeable de [`Process::attribute`] sobre un `/proc` simulado.
    ///
    /// `root` es el directorio que hace de `/proc` (en los tests, un directorio
    /// temporal con `<pid>/comm` y `<pid>/fd/<n> -> socket:[<inodo>]`).
    // Variante del contrato pensada para tests sobre un /proc simulado.
    #[allow(dead_code)]
    pub fn attribute_in(root: &Path, inode: u64) -> Option<ProcessInfo> {
        Self::attribute_many_in(root, &HashSet::from([inode])).remove(&inode)
    }

    /// Recorre `root` una sola vez y atribuye todos los inodos pedidos.
    ///
    /// Los PID se procesan en orden numérico para que el resultado sea determinista
    /// si dos procesos comparten el mismo inodo (caso artificial): gana el menor.
    fn attribute_many_in(root: &Path, inodes: &HashSet<u64>) -> HashMap<u64, ProcessInfo> {
        let mut encontrados: HashMap<u64, ProcessInfo> = HashMap::new();
        if inodes.is_empty() {
            return encontrados;
        }
        for pid in pids_en(root) {
            let pid_dir = root.join(pid.to_string());
            let inodos = inodos_de_socket(&pid_dir, inodes);
            if inodos.is_empty() {
                continue;
            }
            let info = ProcessInfo {
                pid,
                comm: leer_comm(&pid_dir),
            };
            for inodo in inodos {
                encontrados.entry(inodo).or_insert_with(|| info.clone());
            }
        }
        encontrados
    }
}

/// Lista los PID del `/proc` indicado, ordenados de menor a mayor.
///
/// Cualquier entrada que no sea un número (self, sys, net...) se ignora.
fn pids_en(root: &Path) -> Vec<u32> {
    let Ok(directorio) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = directorio
        .flatten()
        .filter_map(|entrada| entrada.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids
}

/// Devuelve los inodos pedidos que aparecen como `socket:[N]` en `<pid>/fd`.
///
/// Si el directorio `fd` no puede leerse (permisos, proceso terminado...) se
/// devuelve una lista vacía: la atribución continúa con el resto de procesos.
fn inodos_de_socket(pid_dir: &Path, buscados: &HashSet<u64>) -> Vec<u64> {
    let Ok(fd_dir) = std::fs::read_dir(pid_dir.join("fd")) else {
        return Vec::new();
    };
    let mut encontrados: Vec<u64> = Vec::new();
    for entrada in fd_dir.flatten() {
        let Ok(destino) = std::fs::read_link(entrada.path()) else {
            continue;
        };
        let Some(inodo) = inodo_de_socket(&destino) else {
            continue;
        };
        if buscados.contains(&inodo) && !encontrados.contains(&inodo) {
            encontrados.push(inodo);
        }
    }
    encontrados
}

/// Extrae el inodo de un destino de enlace con formato `socket:[<inodo>]`.
fn inodo_de_socket(destino: &Path) -> Option<u64> {
    destino
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Lee el nombre corto del proceso (`/proc/[pid]/comm`) sin el salto de línea.
///
/// Si no se puede leer devuelve una cadena vacía: el PID sigue siendo útil.
fn leer_comm(pid_dir: &Path) -> String {
    std::fs::read_to_string(pid_dir.join("comm"))
        .map(|texto| texto.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crea un `/proc/[pid]` simulado con su `comm` y sus sockets.
    fn crear_proceso(root: &Path, pid: u32, comm: &str, sockets: &[u64]) {
        let pid_dir = root.join(pid.to_string());
        let fd_dir = pid_dir.join("fd");
        std::fs::create_dir_all(&fd_dir).expect("crear /proc/[pid]/fd simulado");
        std::fs::write(pid_dir.join("comm"), format!("{comm}\n")).expect("escribir comm");
        for (indice, inodo) in sockets.iter().enumerate() {
            std::os::unix::fs::symlink(
                format!("socket:[{inodo}]"),
                fd_dir.join((indice + 3).to_string()),
            )
            .expect("crear enlace de socket");
        }
    }

    #[test]
    fn atribuye_un_socket_a_pid_y_comm() {
        let proc = tempfile::tempdir().expect("directorio temporal");
        crear_proceso(proc.path(), 4242, "firefox", &[42]);

        let info = Process::attribute_in(proc.path(), 42).expect("socket atribuido");
        assert_eq!(info.pid, 4242);
        assert_eq!(info.comm, "firefox");
    }

    #[test]
    fn inodo_sin_proceso_devuelve_none() {
        let proc = tempfile::tempdir().expect("directorio temporal");
        crear_proceso(proc.path(), 4242, "firefox", &[42]);

        assert!(Process::attribute_in(proc.path(), 99).is_none());
        assert!(Process::attribute_in(Path::new("/ruta/que/no/existe"), 42).is_none());
    }

    #[test]
    fn atribuye_varios_inodos_en_una_sola_pasada() {
        let proc = tempfile::tempdir().expect("directorio temporal");
        crear_proceso(proc.path(), 100, "curl", &[7]);
        crear_proceso(proc.path(), 200, "sshd", &[8]);

        let inodos: HashSet<u64> = [7u64, 8, 99].into_iter().collect();
        let mapa = Process::attribute_many_in(proc.path(), &inodos);
        assert_eq!(mapa.len(), 2, "el inodo 99 no pertenece a nadie");
        assert_eq!(mapa[&7].pid, 100);
        assert_eq!(mapa[&7].comm, "curl");
        assert_eq!(mapa[&8].pid, 200);
        assert_eq!(mapa[&8].comm, "sshd");
        assert!(!mapa.contains_key(&99));
    }

    #[test]
    fn el_pid_menor_gana_si_comparten_inodo() {
        let proc = tempfile::tempdir().expect("directorio temporal");
        crear_proceso(proc.path(), 500, "duplicado", &[5]);
        crear_proceso(proc.path(), 100, "duplicado", &[5]);

        let info = Process::attribute_in(proc.path(), 5).expect("socket atribuido");
        assert_eq!(info.pid, 100, "el recorrido es determinista");
    }

    #[test]
    fn degrada_sin_directorio_fd_o_sin_permisos() {
        let proc = tempfile::tempdir().expect("directorio temporal");

        // Proceso sin /proc/[pid]/fd (simula falta de permisos o proceso del núcleo).
        let sin_fd = proc.path().join("777");
        std::fs::create_dir_all(&sin_fd).expect("crear pid sin fd");
        std::fs::write(sin_fd.join("comm"), "protegido\n").expect("escribir comm");

        // Proceso con descriptores que no son sockets (se ignoran).
        let otros = proc.path().join("888");
        let fd_dir = otros.join("fd");
        std::fs::create_dir_all(&fd_dir).expect("crear pid con fds");
        std::fs::write(otros.join("comm"), "otros\n").expect("escribir comm");
        std::os::unix::fs::symlink("/dev/null", fd_dir.join("0")).expect("enlace a /dev/null");
        std::os::unix::fs::symlink("pipe:[1234]", fd_dir.join("1")).expect("enlace a pipe");

        assert!(Process::attribute_in(proc.path(), 42).is_none());
        assert!(Process::attribute_many_in(proc.path(), &HashSet::from([42])).is_empty());
    }

    #[test]
    fn comm_con_espacios_conserva_el_nombre_corto() {
        let proc = tempfile::tempdir().expect("directorio temporal");
        crear_proceso(proc.path(), 31337, "Web Content", &[9]);

        let info = Process::attribute_in(proc.path(), 9).expect("socket atribuido");
        assert_eq!(info.comm, "Web Content");
    }

    #[test]
    fn proc_real_es_tolerante() {
        // Escanear el /proc real con un inodo imposible no atribuye nada ni falla.
        assert!(Process::attribute(u64::MAX).is_none());
        assert!(Process::attribute_many(&HashSet::new()).is_empty());
        assert!(Process::attribute_many(&HashSet::from([u64::MAX])).is_empty());
    }
}
