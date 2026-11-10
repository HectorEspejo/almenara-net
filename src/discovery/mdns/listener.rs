//! Listener pasivo mDNS en 224.0.0.251:5353.
//!
//! Abre un socket UDP ligado a 0.0.0.0:5353 con SO_REUSEADDR y SO_REUSEPORT
//! (std no permite fijar esas opciones antes del bind, así que el socket se crea
//! con libc), se une al grupo multicast 224.0.0.251 y lanza un hilo lector. El
//! hilo acumula los registros parseados en un buzón acotado que el orquestador
//! drena en cada ciclo con [MdnsListener::drain].
//!
//! Decisiones:
//! - La lectura usa un timeout: así el hilo revisa periódicamente la bandera de
//!   parada y [Drop] no se queda bloqueado esperando un paquete.
//! - El buzón está acotado a [MAX_PENDIENTES]: si nadie drena, se descartan los
//!   registros más antiguos para no crecer sin límite.
//! - La unión al grupo se hace por la interfaz multicast por defecto
//!   (INADDR_ANY); el contrato no recibe el nombre de la interfaz.
//! - Si el bind o la unión fallan, [MdnsListener::start] devuelve error; el
//!   orquestador lo registra y continúa sin mDNS, nunca aborta el ciclo.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::{Error, Result};

use super::parser::{self, MdnsRecord};

/// Grupo multicast estándar de mDNS.
const GRUPO_MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// Puerto estándar de mDNS.
const PUERTO_MDNS: u16 = 5353;
/// Tamaño máximo de un datagrama mDNS (RFC 6762 permite hasta 9000 bytes).
const MAX_DATAGRAMA: usize = 9000;
/// Registros pendientes máximos antes de descartar los más antiguos.
const MAX_PENDIENTES: usize = 512;
/// Cada cuánto despierta el hilo para comprobar si debe parar.
const TIMEOUT_LECTURA: Duration = Duration::from_millis(500);

/// Listener pasivo de anuncios mDNS.
#[derive(Debug)]
pub struct MdnsListener {
    activo: Arc<AtomicBool>,
    buzon: Arc<Mutex<Buzon<MdnsRecord>>>,
    hilo: Option<JoinHandle<()>>,
}

impl MdnsListener {
    /// Suscribe el socket al grupo multicast 224.0.0.251:5353.
    ///
    /// API del contrato; la orquestación usa [MdnsListener::start_on] para unir
    /// el grupo en las interfaces concretas del equipo.
    #[allow(dead_code)]
    pub fn start() -> Result<Self> {
        Self::start_on(&[])
    }

    /// Suscribe el socket al grupo mDNS uniéndose en cada interfaz indicada.
    ///
    /// Es necesario unir el grupo explícitamente por interfaz: en algunos
    /// sistemas unir con INADDR_ANY no selecciona la interfaz correcta y no se
    /// recibe el multicast que llega de la red (solo el generado en local).
    pub fn start_on(interfaces: &[Ipv4Addr]) -> Result<Self> {
        let socket = crear_socket_multicast(GRUPO_MDNS, PUERTO_MDNS, interfaces)?;
        socket.set_read_timeout(Some(TIMEOUT_LECTURA))?;

        let activo = Arc::new(AtomicBool::new(true));
        let buzon = Arc::new(Mutex::new(Buzon::nuevo(MAX_PENDIENTES)));
        let activo_hilo = Arc::clone(&activo);
        let buzon_hilo = Arc::clone(&buzon);

        let hilo = std::thread::Builder::new()
            .name("almenara-mdns".to_string())
            .spawn(move || bucle_lectura(socket, buzon_hilo, activo_hilo))
            .map_err(|err| {
                Error::Scan(format!(
                    "no se pudo lanzar el hilo del listener mDNS: {err}"
                ))
            })?;

        Ok(Self {
            activo,
            buzon,
            hilo: Some(hilo),
        })
    }

    /// Vacía el buffer de paquetes recibidos desde la última llamada.
    pub fn drain(&mut self) -> Vec<MdnsRecord> {
        let mut guardia = self
            .buzon
            .lock()
            .unwrap_or_else(|envenenado| envenenado.into_inner());
        guardia.drenar()
    }
}

impl Drop for MdnsListener {
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

    /// Encola un registro; si está lleno, descarta el más antiguo.
    fn empujar(&mut self, valor: T) {
        if self.datos.len() >= self.maximo {
            self.datos.pop_front();
        }
        self.datos.push_back(valor);
    }

    /// Extrae todos los registros pendientes.
    fn drenar(&mut self) -> Vec<T> {
        self.datos.drain(..).collect()
    }
}

/// Crea y configura el socket multicast que se une al grupo indicado.
///
/// std no permite aplicar SO_REUSEADDR/SO_REUSEPORT antes de bind, de modo que
/// el descriptor se crea con libc y solo después se envuelve en un UdpSocket.
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
            "no se pudo crear el socket UDP de mDNS: {}",
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

/// Se une al grupo multicast en cada interfaz indicada.
///
/// Sin interfaces explícitas se usa INADDR_ANY (comportamiento heredado); con
/// interfaces se une en todas y se devuelve error solo si no se pudo unir en
/// ninguna.
fn unir_grupo(socket: &UdpSocket, grupo: Ipv4Addr, interfaces: &[Ipv4Addr]) -> Result<()> {
    if interfaces.is_empty() {
        return socket
            .join_multicast_v4(&grupo, &Ipv4Addr::UNSPECIFIED)
            .map_err(|err| {
                Error::Scan(format!(
                    "no se pudo unir al grupo multicast mDNS {grupo}: {err}"
                ))
            });
    }
    let mut unidas = 0usize;
    let mut ultimo_error = None;
    for interfaz in interfaces.iter().filter(|ip| !ip.is_unspecified()) {
        match socket.join_multicast_v4(&grupo, interfaz) {
            Ok(()) => unidas += 1,
            Err(err) => {
                tracing::warn!(%interfaz, %err, "no se pudo unir al grupo mDNS en la interfaz");
                ultimo_error = Some(err);
            }
        }
    }
    tracing::debug!(?interfaces, unidas, "unión al grupo mDNS");
    if unidas == 0 {
        return Err(Error::Scan(format!(
            "no se pudo unir al grupo multicast mDNS {grupo} en ninguna interfaz: {}",
            ultimo_error
                .map(|err| err.to_string())
                .unwrap_or_else(|| "sin interfaces válidas".to_string())
        )));
    }
    Ok(())
}

/// Activa SO_REUSEADDR y SO_REUSEPORT para convivir con otros clientes mDNS.
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
            "no se pudo ligar el socket UDP de mDNS al puerto {puerto}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Bucle del hilo lector: recibe, parsea y encola hasta que se pide parar.
fn bucle_lectura(socket: UdpSocket, buzon: Arc<Mutex<Buzon<MdnsRecord>>>, activo: Arc<AtomicBool>) {
    let mut datos = [0u8; MAX_DATAGRAMA];
    while activo.load(Ordering::Relaxed) {
        match socket.recv_from(&mut datos) {
            Ok((leidos, origen)) => {
                if leidos == 0 {
                    continue;
                }
                tracing::trace!(bytes = leidos, %origen, "datagrama mDNS recibido");
                match parser::parse(&datos[..leidos]) {
                    Ok(registros) => {
                        tracing::trace!(registros = registros.len(), "paquete mDNS parseado");
                        let mut guardia = buzon
                            .lock()
                            .unwrap_or_else(|envenenado| envenenado.into_inner());
                        for registro in registros {
                            guardia.empujar(registro);
                        }
                    }
                    Err(err) => tracing::debug!(%err, "paquete mDNS descartado"),
                }
            }
            Err(err) => match err.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {}
                _ => {
                    tracing::warn!(%err, "error leyendo el socket mDNS; se detiene el listener");
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
        buzon.empujar(1);
        buzon.empujar(2);
        buzon.empujar(3);
        assert_eq!(buzon.drenar(), vec![2, 3]);
        assert!(buzon.drenar().is_empty());
    }

    #[test]
    fn el_buzon_acepta_un_maximo_de_al_menos_uno() {
        let mut buzon = Buzon::nuevo(0);
        buzon.empujar("a");
        buzon.empujar("b");
        assert_eq!(buzon.drenar(), vec!["b"]);
    }

    #[test]
    fn start_tolera_que_el_socket_no_este_disponible() {
        // Sin red, sin permisos o con otro proceso ocupando el puerto, start
        // puede fallar: es un resultado válido y no debe romper el test.
        if let Ok(mut listener) = MdnsListener::start() {
            let _ = listener.drain();
            drop(listener);
        }
    }
}
