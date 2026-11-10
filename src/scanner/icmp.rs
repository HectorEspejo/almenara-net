//! Ping sweep ICMP sobre una lista de IPv4 usando un socket raw de libc.
//!
//! Requiere CAP_NET_RAW; si no está disponible devuelve error y el escaneo sigue
//! con la lectura pasiva de /proc/net/arp. Se usa libc directamente (socket raw +
//! poll/recvfrom) en lugar del canal de transporte de pnet: el envío de pnet
//! devuelve EINVAL en algunos núcleos/entornos. La construcción y el parseo de
//! paquetes son funciones puras para poder probarlas sin privilegios.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::Packet;

use crate::error::{Error, Result};

/// Datos que se envían en cada eco para reconocer nuestras respuestas.
const RELLENO: &[u8] = b"almenara";

/// Cabecera ICMP (tipo, código, checksum) más identificador y secuencia.
const TAMANO_CABECERA_ICMP: usize = 8;

/// Tamaño del búfer de recepción (suficiente para una cabecera IP + ICMP).
const TAMANO_BUFFER: usize = 1500;

/// Realiza un ping sweep concurrente y devuelve las IPs que respondieron.
///
/// Envía un eco ICMP a cada objetivo y espera las respuestas hasta agotar
/// `timeout` (sin superar en total ~2 × `timeout`). Solo se aceptan respuestas
/// cuyo identificador coincide con el del proceso. El resultado se devuelve
/// ordenado y sin duplicados. `concurrency` se usa para espaciar los envíos en
/// lotes y no saturar la cola de la interfaz.
pub fn sweep(targets: &[Ipv4Addr], timeout: Duration, concurrency: usize) -> Result<Vec<Ipv4Addr>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut objetivos = targets.to_vec();
    objetivos.sort_unstable();
    objetivos.dedup();

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(Error::Scan(format!(
            "no se pudo abrir el socket ICMP raw (¿falta CAP_NET_RAW?): {}",
            std::io::Error::last_os_error()
        )));
    }
    let _guard = SocketGuard(fd);

    let identificador = std::process::id() as u16;
    let conjunto_objetivos: HashSet<Ipv4Addr> = objetivos.iter().copied().collect();
    let mut respondidos = HashSet::new();
    let mut enviados: usize = 0;
    let tamano_lote = concurrency.max(1);
    let limite_global = Instant::now() + timeout.saturating_mul(2);
    let mut secuencia: u16 = 0;

    'lotes: for lote in objetivos.chunks(tamano_lote) {
        for objetivo in lote {
            let paquete_bytes = construir_eco_peticion(identificador, secuencia);
            secuencia = secuencia.wrapping_add(1);
            let mut direccion: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            direccion.sin_family = libc::AF_INET as libc::sa_family_t;
            direccion.sin_port = 0;
            direccion.sin_addr.s_addr = u32::from_ne_bytes(objetivo.octets());
            let resultado = unsafe {
                libc::sendto(
                    fd,
                    paquete_bytes.as_ptr() as *const libc::c_void,
                    paquete_bytes.len(),
                    0,
                    &direccion as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if resultado >= 0 {
                enviados += 1;
            } else {
                tracing::debug!(
                    %objetivo,
                    error = %std::io::Error::last_os_error(),
                    "no se pudo enviar el eco ICMP"
                );
            }
        }

        // Ventana corta de recepción entre lotes para no acumular respuestas.
        let limite_lote =
            (Instant::now() + timeout.min(Duration::from_millis(50))).min(limite_global);
        recibir_respuestas(
            fd,
            limite_lote,
            identificador,
            &conjunto_objetivos,
            &mut respondidos,
        );
        if Instant::now() >= limite_global || respondidos.len() >= conjunto_objetivos.len() {
            break 'lotes;
        }
    }

    // Ventana final de recepción con el tiempo restante del timeout.
    let limite_final = (Instant::now() + timeout).min(limite_global);
    recibir_respuestas(
        fd,
        limite_final,
        identificador,
        &conjunto_objetivos,
        &mut respondidos,
    );

    if enviados == 0 && !objetivos.is_empty() {
        return Err(Error::Scan(
            "no se pudo enviar ningún eco ICMP del ping sweep (¿falta CAP_NET_RAW?)".to_string(),
        ));
    }

    let mut resultado: Vec<Ipv4Addr> = respondidos.into_iter().collect();
    resultado.sort_unstable();
    Ok(resultado)
}

/// Recibe y acumula respuestas de eco hasta el instante límite.
fn recibir_respuestas(
    fd: libc::c_int,
    limite: Instant,
    identificador: u16,
    objetivos: &HashSet<Ipv4Addr>,
    respondidos: &mut HashSet<Ipv4Addr>,
) {
    loop {
        let ahora = Instant::now();
        if ahora >= limite || respondidos.len() >= objetivos.len() {
            return;
        }
        let restante_ms = (limite - ahora).as_millis().max(1) as libc::c_int;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let listo = unsafe { libc::poll(&mut pollfd, 1, restante_ms) };
        if listo <= 0 {
            return;
        }
        let mut buffer = [0u8; TAMANO_BUFFER];
        let mut origen: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut longitud = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let leidos = unsafe {
            libc::recvfrom(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
                &mut origen as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut longitud,
            )
        };
        if leidos <= 0 {
            continue;
        }
        if let Some((ip, _ttl)) = parse_eco_respuesta(&buffer[..leidos as usize], identificador) {
            if objetivos.contains(&ip) {
                respondidos.insert(ip);
            }
        }
    }
}

/// Cierra el socket raw al salir de `sweep`.
struct SocketGuard(libc::c_int);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Construye un paquete ICMP echo request con su checksum ya calculado.
///
/// El identificador y la secuencia ocupan los cuatro bytes de datos que el tipo
/// genérico `Icmp` deja dentro del payload, justo detrás de la cabecera de 4 bytes.
fn construir_eco_peticion(identificador: u16, secuencia: u16) -> Vec<u8> {
    let mut buffer = vec![0u8; TAMANO_CABECERA_ICMP + RELLENO.len()];
    let mut paquete = MutableIcmpPacket::new(&mut buffer[..])
        .expect("el búfer tiene el tamaño de una cabecera ICMP");
    paquete.set_icmp_type(IcmpTypes::EchoRequest);
    paquete.set_icmp_code(echo_request::IcmpCodes::NoCode);

    let mut datos = Vec::with_capacity(4 + RELLENO.len());
    datos.extend_from_slice(&identificador.to_be_bytes());
    datos.extend_from_slice(&secuencia.to_be_bytes());
    datos.extend_from_slice(RELLENO);
    paquete.set_payload(&datos);

    let suma = pnet::packet::icmp::checksum(&paquete.to_immutable());
    paquete.set_checksum(suma);
    buffer
}

/// Extrae la IP de origen y el TTL de una respuesta de eco propia.
///
/// El búfer que devuelve un socket raw de IP incluye la cabecera IPv4. Se
/// descartan paquetes que no sean IPv4/ICMP, que no sean Echo Reply o cuyo
/// identificador no coincida con el del proceso.
pub fn parse_eco_respuesta(bytes: &[u8], identificador: u16) -> Option<(Ipv4Addr, u8)> {
    if bytes.len() < 20 {
        return None;
    }
    let version = bytes[0] >> 4;
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if version != 4 || ihl < 20 || bytes.len() < ihl + TAMANO_CABECERA_ICMP {
        return None;
    }
    if bytes[9] != pnet::packet::ip::IpNextHeaderProtocols::Icmp.0 {
        return None;
    }
    let ttl = bytes[8];
    let origen = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let icmp = IcmpPacket::new(&bytes[ihl..])?;
    if icmp.get_icmp_type() != IcmpTypes::EchoReply {
        return None;
    }
    let respuesta = echo_reply::EchoReplyPacket::new(icmp.packet())?;
    if respuesta.get_identifier() != identificador {
        return None;
    }
    Some((origen, ttl))
}

/// Indica si un error de lectura significa fin del tiempo de espera (reservado).
#[allow(dead_code)]
fn es_fin_de_espera(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_sin_objetivos_no_abre_socket() {
        let respuesta = sweep(&[], Duration::from_millis(50), 8).expect("sin objetivos no falla");
        assert!(respuesta.is_empty());
    }

    #[test]
    fn construye_eco_peticion_valido() {
        let bytes = construir_eco_peticion(0x1234, 7);
        assert_eq!(bytes.len(), TAMANO_CABECERA_ICMP + RELLENO.len());

        let paquete = IcmpPacket::new(&bytes).expect("paquete ICMP válido");
        assert_eq!(paquete.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(paquete.get_icmp_code(), echo_request::IcmpCodes::NoCode);
        assert_ne!(paquete.get_checksum(), 0);

        let datos = paquete.payload();
        assert_eq!(u16::from_be_bytes([datos[0], datos[1]]), 0x1234);
        assert_eq!(u16::from_be_bytes([datos[2], datos[3]]), 7);
        assert_eq!(&datos[4..], RELLENO);
    }

    #[test]
    fn checksum_del_eco_es_correcto() {
        let bytes = construir_eco_peticion(42, 3);
        let paquete = IcmpPacket::new(&bytes).expect("paquete ICMP válido");
        assert_eq!(
            pnet::packet::icmp::checksum(&paquete),
            paquete.get_checksum()
        );

        let mut copia = bytes.clone();
        {
            let mut mutable = MutableIcmpPacket::new(&mut copia[..]).expect("paquete mutable");
            mutable.set_checksum(0);
        }
        let sin_checksum = IcmpPacket::new(&copia).expect("paquete ICMP válido");
        let calculado = pnet::packet::icmp::checksum(&sin_checksum);
        assert_eq!(calculado, paquete.get_checksum());
    }

    #[test]
    fn parsea_respuesta_eco_propia_con_ttl() {
        let identificador = 0x1234;
        let paquete = construir_eco_respuesta(identificador, 9);
        let ip = cabecera_ipv4(&paquete, 64);
        let (origen, ttl) = parse_eco_respuesta(&ip, identificador).expect("respuesta válida");
        assert_eq!(origen, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ttl, 64);
    }

    #[test]
    fn rechaza_peticion_y_respuestas_ajenas() {
        let peticion = construir_eco_peticion(0x1234, 1);
        let mut ip = cabecera_ipv4(&peticion, 64);
        assert!(parse_eco_respuesta(&ip, 0x1234).is_none());

        let otra = construir_eco_respuesta(0x4321, 1);
        ip = cabecera_ipv4(&otra, 64);
        assert!(parse_eco_respuesta(&ip, 0x1234).is_none());
    }

    #[test]
    fn rechaza_paquetes_truncados_y_no_icmp() {
        assert!(parse_eco_respuesta(&[0u8; 8], 1).is_none());

        let mut ip = cabecera_ipv4(&construir_eco_respuesta(1, 1), 64);
        ip[9] = 6; // TCP
        assert!(parse_eco_respuesta(&ip, 1).is_none());
    }

    /// Construye una respuesta de eco con la misma disposición que las peticiones.
    fn construir_eco_respuesta(identificador: u16, secuencia: u16) -> Vec<u8> {
        let mut buffer = vec![0u8; TAMANO_CABECERA_ICMP + RELLENO.len()];
        let mut paquete = MutableIcmpPacket::new(&mut buffer[..]).expect("búfer suficiente");
        paquete.set_icmp_type(IcmpTypes::EchoReply);
        paquete.set_icmp_code(echo_reply::IcmpCodes::NoCode);

        let mut datos = Vec::with_capacity(4 + RELLENO.len());
        datos.extend_from_slice(&identificador.to_be_bytes());
        datos.extend_from_slice(&secuencia.to_be_bytes());
        datos.extend_from_slice(RELLENO);
        paquete.set_payload(&datos);

        let suma = pnet::packet::icmp::checksum(&paquete.to_immutable());
        paquete.set_checksum(suma);
        buffer
    }

    /// Antepone una cabecera IPv4 a un paquete ICMP para las pruebas de parseo.
    fn cabecera_ipv4(icmp: &[u8], ttl: u8) -> Vec<u8> {
        let mut paquete = vec![0u8; 20 + icmp.len()];
        paquete[0] = 0x45;
        paquete[8] = ttl;
        paquete[9] = pnet::packet::ip::IpNextHeaderProtocols::Icmp.0;
        paquete[12..16].copy_from_slice(&[192, 168, 1, 1]);
        paquete[20..].copy_from_slice(icmp);
        paquete
    }
}
