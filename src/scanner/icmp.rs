//! Ping sweep ICMP sobre una lista de IPv4 usando sockets raw (pnet).
//!
//! Requiere CAP_NET_RAW; si no está disponible devuelve error y el escaneo sigue
//! con la lectura pasiva de /proc/net/arp. La construcción y el parseo de paquetes
//! son funciones puras para poder probarlas sin privilegios.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType};

use crate::error::{Error, Result};

/// Datos que se envían en cada eco para reconocer nuestras respuestas.
const RELLENO: &[u8] = b"almenara";

/// Cabecera ICMP (tipo, código, checksum) más identificador y secuencia.
const TAMANO_CABECERA_ICMP: usize = 8;

/// Tamaño del búfer del socket de transporte.
const TAMANO_BUFFER: usize = 4096;

/// Realiza un ping sweep concurrente y devuelve las IPs que respondieron.
///
/// Envía los ecos por lotes de `concurrency` destinos y espera las respuestas hasta
/// agotar `timeout` por lote (sin superar en total ~2 × `timeout`). Solo se aceptan
/// respuestas cuyo identificador coincide con el del proceso. El resultado se
/// devuelve ordenado y sin duplicados.
pub fn sweep(targets: &[Ipv4Addr], timeout: Duration, concurrency: usize) -> Result<Vec<Ipv4Addr>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut objetivos = targets.to_vec();
    objetivos.sort_unstable();
    objetivos.dedup();

    let (mut emisor, mut receptor) = transport_channel(
        TAMANO_BUFFER,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
    )
    .map_err(|err| {
        Error::Scan(format!(
            "no se pudo abrir el socket ICMP raw (¿falta CAP_NET_RAW?): {err}"
        ))
    })?;

    let identificador = std::process::id() as u16;
    let tamano_lote = concurrency.max(1);
    let limite_global = Instant::now() + timeout.saturating_mul(2);
    let conjunto_objetivos: HashSet<Ipv4Addr> = objetivos.iter().copied().collect();
    let mut respondidos = HashSet::new();
    let mut iterador = icmp_packet_iter(&mut receptor);
    let mut secuencia: u16 = 0;

    for lote in objetivos.chunks(tamano_lote) {
        if respondidos.len() >= conjunto_objetivos.len() {
            break;
        }

        for objetivo in lote {
            let paquete_bytes = construir_eco_peticion(identificador, secuencia);
            secuencia = secuencia.wrapping_add(1);
            let paquete = IcmpPacket::new(&paquete_bytes).ok_or_else(|| {
                Error::Scan("no se pudo construir el paquete ICMP del ping sweep".to_string())
            })?;
            emisor
                .send_to(paquete, IpAddr::V4(*objetivo))
                .map_err(|err| {
                    Error::Scan(format!(
                        "no se pudo enviar el ICMP a {objetivo} (¿falta CAP_NET_RAW?): {err}"
                    ))
                })?;
        }

        let limite_lote = (Instant::now() + timeout).min(limite_global);
        loop {
            let ahora = Instant::now();
            if ahora >= limite_lote || respondidos.len() >= conjunto_objetivos.len() {
                break;
            }
            let restante = limite_lote.saturating_duration_since(ahora);

            match iterador.next_with_timeout(restante) {
                Ok(Some((paquete, IpAddr::V4(origen)))) => {
                    if es_respuesta_eco(&paquete, identificador)
                        && conjunto_objetivos.contains(&origen)
                    {
                        respondidos.insert(origen);
                    }
                }
                Ok(Some((_, IpAddr::V6(_)))) => continue,
                Ok(None) => break,
                Err(err) if es_fin_de_espera(&err) => break,
                Err(err) => {
                    return Err(Error::Scan(format!(
                        "error leyendo respuestas ICMP del ping sweep: {err}"
                    )))
                }
            }
        }
    }

    let mut resultado: Vec<Ipv4Addr> = respondidos.into_iter().collect();
    resultado.sort_unstable();
    Ok(resultado)
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

/// Indica si un paquete ICMP es una respuesta de eco nuestra.
fn es_respuesta_eco(paquete: &IcmpPacket, identificador: u16) -> bool {
    if paquete.get_icmp_type() != IcmpTypes::EchoReply {
        return false;
    }
    match echo_reply::EchoReplyPacket::new(paquete.packet()) {
        Some(respuesta) => respuesta.get_identifier() == identificador,
        None => false,
    }
}

/// Indica si un error de lectura significa fin del tiempo de espera.
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

        // Un checksum correcto hace que la suma de todo el paquete sea cero.
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
    fn reconoce_respuesta_eco_propia() {
        let identificador = 0x1234;
        let reply = construir_eco_respuesta(identificador, 9);

        let paquete = IcmpPacket::new(&reply).expect("paquete ICMP válido");
        assert!(es_respuesta_eco(&paquete, identificador));
        assert!(!es_respuesta_eco(&paquete, identificador.wrapping_add(1)));
    }

    #[test]
    fn rechaza_peticion_y_respuestas_ajenas() {
        let peticion = construir_eco_peticion(0x1234, 1);
        let paquete = IcmpPacket::new(&peticion).expect("paquete ICMP válido");
        assert!(!es_respuesta_eco(&paquete, 0x1234));

        let otra = construir_eco_respuesta(0x4321, 1);
        let paquete = IcmpPacket::new(&otra).expect("paquete ICMP válido");
        assert!(!es_respuesta_eco(&paquete, 0x1234));
    }

    #[test]
    fn rechaza_paquetes_truncados() {
        let minúsculo = [8u8, 0, 0, 0];
        let paquete = IcmpPacket::new(&minúsculo).expect("cabecera mínima");
        assert!(!es_respuesta_eco(&paquete, 1));
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
}
