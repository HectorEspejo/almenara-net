//! Listener pasivo SSDP en 239.255.255.250:1900.
//!
//! Crea un socket UDP ligado a 0.0.0.0:1900 con SO_REUSEADDR y SO_REUSEPORT
//! (std no permite fijarlas antes del bind, así que se usa libc), se une al grupo
//! multicast 239.255.255.250 y lanza un hilo lector que acumula los mensajes
//! NOTIFY en un buzón acotado. El orquestador lo drena en cada ciclo.
//!
//! Decisiones:
//! - La lectura usa un timeout para que el hilo compruebe la bandera de parada y
//!   [Drop] no se quede bloqueado.
//! - El buzón está acotado a [MAX_PENDIENTES]; si nadie drena se descartan los
//!   mensajes más antiguos.
//! - El listener es solo pasivo (anuncios NOTIFY); las respuestas a M-SEARCH
//!   llegan únicamente a la consulta activa de [crate::discovery::ssdp::query].
//! - Si el bind o la unión al grupo fallan, [SsdpListener::start] devuelve error
//!   y el orquestador continúa sin SSDP pasivo.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::{Error, Result};

use super::parser::{self, SsdpRecord};

/// Grupo multicast estándar de SSDP.
const GRUPO_SSDP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// Puerto estándar de SSDP.
const PUERTO_SSDP: u16 = 1900;
/// Tamaño máximo de un datagrama SSDP (muy por encima de lo real).
const MAX_DATAGRAMA: usize = 8192;
/// Mensajes pendientes máximos antes de descartar los más antiguos.
const MAX_PENDIENTES: usize = 256;
/// Cada cuánto despierta el hilo para comprobar si debe parar.
const TIMEOUT_LECTURA: Duration = Duration::from_millis(500);

/// Listener pasivo de mensajes SSDP.
#[derive(Debug)]
pub struct SsdpListener {
    activo: Arc<AtomicBool>,
    buzon: Arc<Mutex<Buzon<SsdpRecord>>>,
    hilo: Option<JoinHandle<()>>,
}

impl SsdpListener {
    /// Suscribe el socket al grupo multicast 239.255.255.250:1900.
    ///
    /// API del contrato; la orquestación usa [SsdpListener::start_on] para unir
    /// el grupo en las interfaces concretas del equipo.
    #[allow(dead_code)]
    pub fn start() -> Result<Self> {
        Self::start_on(&[])
    }

    /// Suscribe el socket al grupo SSDP uniéndose en cada interfaz indicada.
    ///
    /// Igual que en mDNS, unir con INADDR_ANY puede no seleccionar la interfaz
    /// correcta en algunos sistemas; con interfaces explícitas se une en todas.
    pub fn start_on(interfaces: &[Ipv4Addr]) -> Result<Self> {
        let socket = crear_socket_multicast(GRUPO_SSDP, PUERTO_SSDP, interfaces)?;
        socket.set_read_timeout(Some(TIMEOUT_LECTURA))?;

        let activo = Arc::new(AtomicBool::new(true));
        let buzon = Arc::new(Mutex::new(Buzon::nuevo(MAX_PENDIENTES)));
        let activo_hilo = Arc::clone(&activo);
        let buzon_hilo = Arc::clone(&buzon);

        let hilo = std::thread::Builder::new()
            .name("almenara-ssdp".to_string())
            .spawn(move || bucle_lectura(socket, buzon_hilo, activo_hilo))
            .map_err(|err| {
                Error::Scan(format!(
                    "no se pudo lanzar el hilo del listener SSDP: {err}"
                ))
            })?;

        Ok(Self {
            activo,
            buzon,
            hilo: Some(hilo),
        })
    }

    /// Vacía el buffer de mensajes recibidos desde la última llamada.
    pub fn drain(&mut self) -> Vec<SsdpRecord> {
        let mut guardia = self
            .buzon
            .lock()
            .unwrap_or_else(|envenenado| envenenado.into_inner());
        guardia.drenar()
    }
}

impl Drop for SsdpListener {
    fn drop(&mut self) {
        // El hilo comprueba la bandera cada TIMEOUT_LECTURA; el join es corto.
        self.activo.store(false, Ordering::Relaxed);
        if let Some(hilo) = self.hilo.take() {
            let _ = hilo.join();
        }
    }
}

/// Buzón compartido entre el hilo lector y el consumidor.
#[derive(Debug)]
struct Buzon<T> {
    datos: VecDeque<T>,
    maximo: usize,
}

impl<T> Buzon<T> {
    /// Crea un buzón acotado (el máximo siempre es al menos 1).
    fn nuevo(maximo: usize) -> Self {
        Self {
            datos: VecDeque::new(),
            maximo: maximo.max(1),
        }
    }

    /// Encola un mensaje; si está lleno, descarta el más antiguo.
    fn empujar(&mut self, valor: T) {
        if self.datos.len() >= self.maximo {
            self.datos.pop_front();
        }
        self.datos.push_back(valor);
    }

    /// Extrae todos los mensajes pendientes.
    fn drenar(&mut self) -> Vec<T> {
        self.datos.drain(..).collect()
    }
}

/// Crea y configura el socket multicast que se une al grupo indicado.
fn crear_socket_multicast(
    grupo: Ipv4Addr,
    puerto: u16,
    interfaces: &[Ipv4Addr],
) -> Result<UdpSocket> {
    // SAFETY: socket(2) solo devuelve un descriptor nuevo (o -1, que se valida
    // justo después). No se comparte con nadie hasta envolverlo.
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(Error::Scan(format!(
            "no se pudo crear el socket UDP de SSDP: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: el descriptor es válido y la envoltura toma su propiedad, así que
    // se cierra también en los caminos de error posteriores.
    let socket = unsafe { UdpSocket::from_raw_fd(descriptor) };
    activar_reuso(&socket)?;
    enlazar(&socket, puerto)?;
    unir_grupo(&socket, grupo, interfaces)?;
    Ok(socket)
}

/// Se une al grupo multicast SSDP en cada interfaz indicada.
fn unir_grupo(socket: &UdpSocket, grupo: Ipv4Addr, interfaces: &[Ipv4Addr]) -> Result<()> {
    if interfaces.is_empty() {
        return socket
            .join_multicast_v4(&grupo, &Ipv4Addr::UNSPECIFIED)
            .map_err(|err| {
                Error::Scan(format!(
                    "no se pudo unir al grupo multicast SSDP {grupo}: {err}"
                ))
            });
    }
    let mut unidas = 0usize;
    let mut ultimo_error = None;
    for interfaz in interfaces.iter().filter(|ip| !ip.is_unspecified()) {
        match socket.join_multicast_v4(&grupo, interfaz) {
            Ok(()) => unidas += 1,
            Err(err) => {
                tracing::warn!(%interfaz, %err, "no se pudo unir al grupo SSDP en la interfaz");
                ultimo_error = Some(err);
            }
        }
    }
    if unidas == 0 {
        return Err(Error::Scan(format!(
            "no se pudo unir al grupo multicast SSDP {grupo} en ninguna interfaz: {}",
            ultimo_error
                .map(|err| err.to_string())
                .unwrap_or_else(|| "sin interfaces válidas".to_string())
        )));
    }
    Ok(())
}

/// Activa SO_REUSEADDR y SO_REUSEPORT para convivir con otros clientes SSDP.
fn activar_reuso(socket: &UdpSocket) -> Result<()> {
    let uno: libc::c_int = 1;
    for opcion in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        // SAFETY: se pasa un puntero a un c_int válido con su tamaño correcto.
        let resultado = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                opcion,
                (&uno as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if resultado != 0 {
            return Err(Error::Scan(format!(
                "no se pudo activar la opción de socket {opcion}: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Liga el socket a 0.0.0.0:puerto.
fn enlazar(socket: &UdpSocket, puerto: u16) -> Result<()> {
    // SAFETY: sockaddr_in es POD y se rellena por completo; el puntero solo se
    // usa durante la llamada.
    let direccion = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: puerto.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    // SAFETY: el descriptor es válido y la dirección tiene el tamaño declarado.
    let resultado = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&direccion as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if resultado != 0 {
        return Err(Error::Scan(format!(
            "no se pudo ligar el socket UDP de SSDP al puerto {puerto}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Bucle del hilo lector: recibe, parsea y encola hasta que se pide parar.
fn bucle_lectura(socket: UdpSocket, buzon: Arc<Mutex<Buzon<SsdpRecord>>>, activo: Arc<AtomicBool>) {
    let mut datos = [0u8; MAX_DATAGRAMA];
    while activo.load(Ordering::Relaxed) {
        match socket.recv_from(&mut datos) {
            Ok((leidos, origen)) => {
                if leidos == 0 {
                    continue;
                }
                let ip_origen = match origen {
                    SocketAddr::V4(direccion) => *direccion.ip(),
                    SocketAddr::V6(_) => continue,
                };
                match parser::parse_from(&datos[..leidos], ip_origen) {
                    Ok(registro) => {
                        let mut guardia = buzon
                            .lock()
                            .unwrap_or_else(|envenenado| envenenado.into_inner());
                        guardia.empujar(registro);
                    }
                    Err(err) => tracing::debug!(%err, "mensaje SSDP descartado"),
                }
            }
            Err(err) => match err.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {}
                _ => {
                    tracing::warn!(%err, "error leyendo el socket SSDP; se detiene el listener");
                    break;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_buzon_descarta_los_mas_antiguos_al_llenarse() {
        let mut buzon = Buzon::nuevo(2);
        buzon.empujar("a");
        buzon.empujar("b");
        buzon.empujar("c");
        assert_eq!(buzon.drenar(), vec!["b", "c"]);
        assert!(buzon.drenar().is_empty());
    }

    #[test]
    fn start_tolera_que_el_socket_no_este_disponible() {
        // Sin red, sin permisos o con otro proceso ocupando el puerto, start
        // puede fallar: es un resultado válido y no debe romper el test.
        if let Ok(mut listener) = SsdpListener::start() {
            let _ = listener.drain();
            drop(listener);
        }
    }
}
