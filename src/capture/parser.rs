//! Parser de tramas Ethernet del subsistema de captura.
//!
//! Descompone una trama capturada con AF_PACKET en los metadatos que consume la
//! agregación: direcciones IP, puertos, protocolo, longitud, flags TCP y una
//! copia acotada de las cabeceras IP y de transporte (para el panel de la tecla
//! v). El payload **nunca** se conserva: solo se examina dentro de [Parser::parse]
//! para extraer el QNAME de DNS o el SNI de TLS cuando la atribución está activa.
//!
//! Se soportan: Ethernet con o sin un tag VLAN 802.1Q, IPv4 (fragmento inicial
//! únicamente), IPv6 con cadena de cabeceras de extensión 0/43/44/60 y transporte
//! TCP, UDP, ICMP e ICMPv6.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use super::{
    ArpInfo, HeaderSnapshot, PacketMeta, ParsedArpFrame, ParsedFrame, ParsedIpFrame, Protocol,
    TcpFlags,
};

/// Longitud de la cabecera Ethernet (sin VLAN).
const ETHERNET_HEADER_LEN: usize = 14;
/// Longitud de una etiqueta VLAN 802.1Q.
const VLAN_TAG_LEN: usize = 4;
/// EtherType de IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType de IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// EtherType de VLAN 802.1Q.
const ETHERTYPE_VLAN: u16 = 0x8100;
/// EtherType de ARP.
const ETHERTYPE_ARP: u16 = 0x0806;
/// Longitud mínima de una trama ARP para Ethernet/IPv4.
const ARP_MIN_LEN: usize = 28;

/// Número de protocolo IP de ICMP.
const IPPROTO_ICMP: u8 = 1;
/// Número de protocolo IP de TCP.
const IPPROTO_TCP: u8 = 6;
/// Número de protocolo IP de UDP.
const IPPROTO_UDP: u8 = 17;
/// Número de protocolo IP de ICMPv6.
const IPPROTO_ICMPV6: u8 = 58;

/// Longitud mínima de una cabecera IPv4.
const IPV4_MIN_HEADER_LEN: usize = 20;
/// Longitud de la cabecera fija de IPv6.
const IPV6_HEADER_LEN: usize = 40;
/// Longitud mínima de una cabecera TCP.
const TCP_MIN_HEADER_LEN: usize = 20;
/// Longitud de la cabecera UDP.
const UDP_HEADER_LEN: usize = 8;
/// Longitud mínima de un mensaje ICMP/ICMPv6 (tipo, código, checksum y resto).
const ICMP_MIN_HEADER_LEN: usize = 8;
/// Número máximo de cabeceras de extensión IPv6 que se siguen.
const MAX_EXTENSIONES_IPV6: usize = 16;
/// Número máximo de bytes de cabecera IP que se copian.
const IP_RAW_LEN: usize = 40;
/// Número máximo de bytes de cabecera de transporte que se copian.
const TRANSPORT_RAW_LEN: usize = 20;
/// Máscara de los 9 bits de flags TCP (NS + los ocho clásicos).
const MASCARA_FLAGS_TCP: u16 = 0x01FF;

/// Parser de tramas Ethernet (sin estado propio).
#[derive(Debug, Clone, Copy, Default)]
pub struct Parser;

impl Parser {
    /// Crea un parser de tramas.
    pub fn new() -> Self {
        Self
    }

    /// Constructor por defecto (equivalente a [Parser::new]).
    pub fn with_defaults() -> Self {
        Self
    }

    /// Parsea una trama Ethernet completa y devuelve solo los metadatos.
    ///
    /// Devuelve [ParseError] con `ignorable = true` para las tramas que se
    /// descartan en silencio (EtherType no soportado, IP no IPv4/IPv6, fragmento
    /// no inicial, ARP) y con `ignorable = false` para las mal formadas o truncadas.
    pub fn parse(&self, frame: &[u8]) -> Result<PacketMeta, ParseError> {
        match self.parse_frame(frame)? {
            ParsedFrame::Ip(ip) => Ok(ip.meta),
            ParsedFrame::Arp(_) => Err(ParseError::ignorable(
                "trama ARP: se procesa como equipo observado, no como conexión".to_string(),
            )),
            ParsedFrame::Ignorada(mensaje) => Err(ParseError::ignorable(mensaje)),
        }
    }

    /// Parsea una trama Ethernet completa y localiza su payload.
    ///
    /// A diferencia de [Parser::parse], distingue las tramas ARP y devuelve el
    /// rango del payload dentro de la trama original para que el FlowInspector
    /// lo inspeccione en el hilo de captura. Ninguna copia del payload sale del
    /// hilo: el rango caduca con la trama.
    pub fn parse_frame(&self, frame: &[u8]) -> Result<ParsedFrame, ParseError> {
        let (src_mac, dst_mac, ethertype, offset) = leer_cabecera_ethernet(frame)?;
        match ethertype {
            ETHERTYPE_IPV4 => self
                .parse_ipv4(frame, offset, src_mac, dst_mac)
                .map(ParsedFrame::Ip),
            ETHERTYPE_IPV6 => self
                .parse_ipv6(frame, offset, src_mac, dst_mac)
                .map(ParsedFrame::Ip),
            ETHERTYPE_ARP => parse_arp(frame, offset).map(|arp| {
                ParsedFrame::Arp(ParsedArpFrame {
                    arp,
                    src_mac,
                    dst_mac,
                })
            }),
            otro => Ok(ParsedFrame::Ignorada(format!(
                "EtherType 0x{otro:04X} no soportado: se descarta"
            ))),
        }
    }

    /// Parsea un paquete IPv4 que empieza en `offset`.
    fn parse_ipv4(
        &self,
        frame: &[u8],
        offset: usize,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
    ) -> Result<ParsedIpFrame, ParseError> {
        if frame.len() < offset + IPV4_MIN_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "paquete IPv4 truncado: cabecera incompleta ({} bytes)",
                frame.len().saturating_sub(offset)
            )));
        }
        let version = frame[offset] >> 4;
        if version != 4 {
            return Err(ParseError::ignorable(format!(
                "IP no soportada: versión {version} en una trama de EtherType IPv4"
            )));
        }
        let ip_header_len = usize::from(frame[offset] & 0x0F) * 4;
        if ip_header_len < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "longitud de cabecera IPv4 inválida: {ip_header_len} bytes"
            )));
        }
        if frame.len() < offset + ip_header_len {
            return Err(ParseError::malformada(format!(
                "paquete IPv4 truncado: cabecera de {ip_header_len} bytes"
            )));
        }
        let total_len = usize::from(leer_u16(frame, offset + 2));
        if total_len < ip_header_len {
            return Err(ParseError::malformada(format!(
                "longitud total IPv4 ({total_len} bytes) menor que la cabecera ({ip_header_len} bytes)"
            )));
        }
        if frame.len() < offset + total_len {
            return Err(ParseError::malformada(format!(
                "paquete IPv4 truncado: {} bytes disponibles de {total_len} anunciados",
                frame.len().saturating_sub(offset)
            )));
        }
        let fragmentacion = leer_u16(frame, offset + 6);
        if fragmentacion & 0x1FFF != 0 {
            // Solo el fragmento inicial contiene la cabecera de transporte.
            return Err(ParseError::ignorable(
                "fragmento IPv4 no inicial: se descarta".to_string(),
            ));
        }
        let ttl = frame[offset + 8];
        let tos = frame[offset + 1];
        let ip_protocol = frame[offset + 9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(
            frame[offset + 12],
            frame[offset + 13],
            frame[offset + 14],
            frame[offset + 15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            frame[offset + 16],
            frame[offset + 17],
            frame[offset + 18],
            frame[offset + 19],
        ));
        let transport_start = offset + ip_header_len;
        let transport_len = total_len - ip_header_len;
        let transporte =
            self.parse_transport(frame, transport_start, transport_len, ip_protocol, false)?;
        let mut headers = HeaderSnapshot {
            ip_version: 4,
            ip_header_len: ip_header_len as u8,
            ip_total_len: total_len as u16,
            ttl,
            tos,
            ip_protocol,
            ..HeaderSnapshot::default()
        };
        let copia = ip_header_len.min(IP_RAW_LEN);
        headers.ip_raw[..copia].copy_from_slice(&frame[offset..offset + copia]);
        headers.ip_raw_len = copia as u8;
        transporte.volcar(&mut headers);
        let payload = transporte.payload_start..transporte.payload_end;
        Ok(ParsedIpFrame {
            meta: PacketMeta {
                timestamp: Instant::now(),
                src_ip,
                dst_ip,
                src_port: transporte.src_port,
                dst_port: transporte.dst_port,
                protocol: transporte.protocol,
                len: total_len as u32,
                tcp_flags: transporte.tcp_flags,
                headers: Some(headers),
            },
            payload,
            src_mac,
            dst_mac,
        })
    }

    /// Parsea un paquete IPv6 que empieza en `offset`.
    fn parse_ipv6(
        &self,
        frame: &[u8],
        offset: usize,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
    ) -> Result<ParsedIpFrame, ParseError> {
        if frame.len() < offset + IPV6_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "paquete IPv6 truncado: cabecera incompleta ({} bytes)",
                frame.len().saturating_sub(offset)
            )));
        }
        let version = frame[offset] >> 4;
        if version != 6 {
            return Err(ParseError::ignorable(format!(
                "IP no soportada: versión {version} en una trama de EtherType IPv6"
            )));
        }
        let payload_len = usize::from(leer_u16(frame, offset + 4));
        let total_len = IPV6_HEADER_LEN + payload_len;
        if frame.len() < offset + total_len {
            return Err(ParseError::malformada(format!(
                "paquete IPv6 truncado: {} bytes disponibles de {total_len} anunciados",
                frame.len().saturating_sub(offset)
            )));
        }
        let tos = ((frame[offset] & 0x0F) << 4) | (frame[offset + 1] >> 4);
        let ttl = frame[offset + 7];
        let mut bytes_origen = [0u8; 16];
        bytes_origen.copy_from_slice(&frame[offset + 8..offset + 24]);
        let mut bytes_destino = [0u8; 16];
        bytes_destino.copy_from_slice(&frame[offset + 24..offset + 40]);
        let src_ip = IpAddr::V6(Ipv6Addr::from(bytes_origen));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(bytes_destino));

        let (ip_protocol, transport_start, transport_len) =
            Self::saltar_extensiones(frame, offset, total_len)?;
        let transporte =
            self.parse_transport(frame, transport_start, transport_len, ip_protocol, true)?;
        let mut headers = HeaderSnapshot {
            ip_version: 6,
            ip_header_len: IPV6_HEADER_LEN as u8,
            ip_total_len: total_len.min(usize::from(u16::MAX)) as u16,
            ttl,
            tos,
            ip_protocol,
            ..HeaderSnapshot::default()
        };
        headers
            .ip_raw
            .copy_from_slice(&frame[offset..offset + IPV6_HEADER_LEN]);
        headers.ip_raw_len = IPV6_HEADER_LEN as u8;
        transporte.volcar(&mut headers);
        let payload = transporte.payload_start..transporte.payload_end;
        Ok(ParsedIpFrame {
            meta: PacketMeta {
                timestamp: Instant::now(),
                src_ip,
                dst_ip,
                src_port: transporte.src_port,
                dst_port: transporte.dst_port,
                protocol: transporte.protocol,
                len: total_len as u32,
                tcp_flags: transporte.tcp_flags,
                headers: Some(headers),
            },
            payload,
            src_mac,
            dst_mac,
        })
    }

    /// Recorre la cadena de cabeceras de extensión IPv6 (0/43/44/60).
    ///
    /// Devuelve el protocolo de la capa superior, el desplazamiento donde empieza
    /// su cabecera y los bytes que le quedan.
    fn saltar_extensiones(
        frame: &[u8],
        offset: usize,
        total_len: usize,
    ) -> Result<(u8, usize, usize), ParseError> {
        let mut siguiente = frame[offset + 6];
        let mut cursor = offset + IPV6_HEADER_LEN;
        let mut restantes = total_len - IPV6_HEADER_LEN;
        for _ in 0..MAX_EXTENSIONES_IPV6 {
            match siguiente {
                0 | 43 | 60 => {
                    if restantes < 8 {
                        return Err(ParseError::malformada(
                            "cabecera de extensión IPv6 truncada".to_string(),
                        ));
                    }
                    let longitud = (usize::from(frame[cursor + 1]) + 1) * 8;
                    if longitud > restantes {
                        return Err(ParseError::malformada(format!(
                            "cabecera de extensión IPv6 de {longitud} bytes excede los {restantes} restantes"
                        )));
                    }
                    siguiente = frame[cursor];
                    cursor += longitud;
                    restantes -= longitud;
                }
                44 => {
                    if restantes < 8 {
                        return Err(ParseError::malformada(
                            "cabecera de fragmento IPv6 truncada".to_string(),
                        ));
                    }
                    let campo = leer_u16(frame, cursor + 2);
                    if campo & 0xFFF8 != 0 {
                        return Err(ParseError::ignorable(
                            "fragmento IPv6 no inicial: se descarta".to_string(),
                        ));
                    }
                    siguiente = frame[cursor];
                    cursor += 8;
                    restantes -= 8;
                }
                _ => return Ok((siguiente, cursor, restantes)),
            }
        }
        Err(ParseError::malformada(
            "cadena de cabeceras de extensión IPv6 demasiado larga".to_string(),
        ))
    }

    /// Parsea la cabecera de transporte y localiza el payload.
    fn parse_transport(
        &self,
        frame: &[u8],
        start: usize,
        len: usize,
        ip_protocol: u8,
        ipv6: bool,
    ) -> Result<TransportInfo, ParseError> {
        let protocol = protocolo_de_ip(ip_protocol, ipv6);
        match protocol {
            Protocol::Tcp => Self::transporte_tcp(frame, start, len),
            Protocol::Udp => Self::transporte_udp(frame, start, len),
            icmp @ (Protocol::Icmp | Protocol::Icmpv6) => {
                Self::transporte_icmp(frame, start, len, icmp)
            }
            Protocol::Other => Ok(Self::transporte_otro(start, len)),
        }
    }

    /// Cabecera TCP: puertos, seq/ack, flags 9 bits y payload.
    fn transporte_tcp(frame: &[u8], start: usize, len: usize) -> Result<TransportInfo, ParseError> {
        if len < TCP_MIN_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "cabecera TCP truncada: {len} bytes de {TCP_MIN_HEADER_LEN} mínimos"
            )));
        }
        let data_offset = usize::from(frame[start + 12] >> 4) * 4;
        if data_offset < TCP_MIN_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "longitud de cabecera TCP inválida: {data_offset} bytes"
            )));
        }
        if data_offset > len {
            return Err(ParseError::malformada(format!(
                "cabecera TCP de {data_offset} bytes excede el payload IP de {len} bytes"
            )));
        }
        let mut raw = [0u8; TRANSPORT_RAW_LEN];
        raw.copy_from_slice(&frame[start..start + TCP_MIN_HEADER_LEN]);
        let bits = leer_u16(frame, start + 12) & MASCARA_FLAGS_TCP;
        Ok(TransportInfo {
            protocol: Protocol::Tcp,
            src_port: Some(leer_u16(frame, start)),
            dst_port: Some(leer_u16(frame, start + 2)),
            tcp_flags: Some(TcpFlags::from_bits(bits)),
            tcp_seq: leer_u32(frame, start + 4),
            tcp_ack: leer_u32(frame, start + 8),
            tcp_window: leer_u16(frame, start + 14),
            tcp_bits: bits,
            raw,
            raw_len: TRANSPORT_RAW_LEN as u8,
            payload_start: start + data_offset,
            payload_end: start + len,
        })
    }

    /// Cabecera UDP: puertos y longitud.
    fn transporte_udp(frame: &[u8], start: usize, len: usize) -> Result<TransportInfo, ParseError> {
        if len < UDP_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "cabecera UDP truncada: {len} bytes de {UDP_HEADER_LEN} mínimos"
            )));
        }
        let udp_len = usize::from(leer_u16(frame, start + 4));
        if udp_len < UDP_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "longitud UDP inválida: {udp_len} bytes"
            )));
        }
        if udp_len > len {
            return Err(ParseError::malformada(format!(
                "datagrama UDP truncado: {udp_len} bytes anunciados y {len} disponibles"
            )));
        }
        let mut raw = [0u8; TRANSPORT_RAW_LEN];
        raw[..UDP_HEADER_LEN].copy_from_slice(&frame[start..start + UDP_HEADER_LEN]);
        Ok(TransportInfo {
            protocol: Protocol::Udp,
            src_port: Some(leer_u16(frame, start)),
            dst_port: Some(leer_u16(frame, start + 2)),
            tcp_flags: None,
            tcp_seq: 0,
            tcp_ack: 0,
            tcp_window: 0,
            tcp_bits: 0,
            raw,
            raw_len: UDP_HEADER_LEN as u8,
            payload_start: start + UDP_HEADER_LEN,
            payload_end: start + udp_len,
        })
    }

    /// Cabecera ICMP/ICMPv6: tipo y código (sin puertos).
    fn transporte_icmp(
        frame: &[u8],
        start: usize,
        len: usize,
        protocol: Protocol,
    ) -> Result<TransportInfo, ParseError> {
        if len < ICMP_MIN_HEADER_LEN {
            return Err(ParseError::malformada(format!(
                "cabecera ICMP truncada: {len} bytes de {ICMP_MIN_HEADER_LEN} mínimos"
            )));
        }
        let mut raw = [0u8; TRANSPORT_RAW_LEN];
        raw[..ICMP_MIN_HEADER_LEN].copy_from_slice(&frame[start..start + ICMP_MIN_HEADER_LEN]);
        Ok(TransportInfo {
            protocol,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            tcp_seq: 0,
            tcp_ack: 0,
            tcp_window: 0,
            tcp_bits: 0,
            raw,
            raw_len: ICMP_MIN_HEADER_LEN as u8,
            payload_start: start + ICMP_MIN_HEADER_LEN,
            payload_end: start + len,
        })
    }

    /// Protocolo IP no TCP/UDP/ICMP: no se conoce su cabecera de transporte.
    ///
    /// Por privacidad no se copia ningún byte: los primeros bytes de un
    /// protocolo desconocido podrían ser ya payload.
    fn transporte_otro(start: usize, len: usize) -> TransportInfo {
        TransportInfo {
            protocol: Protocol::Other,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            tcp_seq: 0,
            tcp_ack: 0,
            tcp_window: 0,
            tcp_bits: 0,
            raw: [0u8; TRANSPORT_RAW_LEN],
            raw_len: 0,
            payload_start: start,
            payload_end: start + len,
        }
    }
}

/// Atajo que parsea con las opciones por defecto.
///
/// Forma parte de la API del contrato; la captura crea su propio [Parser] para
/// reutilizar las opciones configuradas y por eso este atajo aún no se usa.
#[allow(dead_code)]
pub fn parse(frame: &[u8]) -> Result<PacketMeta, ParseError> {
    Parser::with_defaults().parse(frame)
}

/// Error de parseo de una trama.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Mensaje legible en castellano.
    pub message: String,
    /// Si es verdadero, la trama se descarta en silencio y no cuenta como error.
    pub ignorable: bool,
}

impl ParseError {
    /// Error no ignorable: trama mal formada o truncada.
    fn malformada(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ignorable: false,
        }
    }

    /// Error ignorable: trama válida de un tipo que no se procesa.
    fn ignorable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ignorable: true,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

/// Cabecera de transporte decodificada y localización del payload.
struct TransportInfo {
    protocol: Protocol,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    tcp_flags: Option<TcpFlags>,
    tcp_seq: u32,
    tcp_ack: u32,
    tcp_window: u16,
    tcp_bits: u16,
    raw: [u8; TRANSPORT_RAW_LEN],
    raw_len: u8,
    payload_start: usize,
    payload_end: usize,
}

impl TransportInfo {
    /// Copia los campos de transporte en la instantánea de cabeceras.
    fn volcar(&self, headers: &mut HeaderSnapshot) {
        headers.transport_raw = self.raw;
        headers.transport_raw_len = self.raw_len;
        headers.tcp_seq = self.tcp_seq;
        headers.tcp_ack = self.tcp_ack;
        headers.tcp_window = self.tcp_window;
        headers.tcp_flags = self.tcp_bits;
    }
}

/// Protocolo de capa superior a partir del número de protocolo IP.
fn protocolo_de_ip(ip_protocol: u8, ipv6: bool) -> Protocol {
    match ip_protocol {
        IPPROTO_TCP => Protocol::Tcp,
        IPPROTO_UDP => Protocol::Udp,
        IPPROTO_ICMP if !ipv6 => Protocol::Icmp,
        IPPROTO_ICMPV6 if ipv6 => Protocol::Icmpv6,
        _ => Protocol::Other,
    }
}

/// Lee un entero de 16 bits en orden de red.
fn leer_u16(frame: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes([frame[pos], frame[pos + 1]])
}

/// Lee un entero de 32 bits en orden de red.
fn leer_u32(frame: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes([frame[pos], frame[pos + 1], frame[pos + 2], frame[pos + 3]])
}

/// Lee la cabecera Ethernet (con VLAN opcional): MACs, EtherType y offset.
fn leer_cabecera_ethernet(frame: &[u8]) -> Result<([u8; 6], [u8; 6], u16, usize), ParseError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::malformada(format!(
            "trama truncada: cabecera Ethernet incompleta ({} bytes)",
            frame.len()
        )));
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    src_mac.copy_from_slice(&frame[6..12]);
    let mut ethertype = leer_u16(frame, 12);
    let mut offset = ETHERNET_HEADER_LEN;
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < offset + VLAN_TAG_LEN {
            return Err(ParseError::malformada(format!(
                "trama truncada: etiqueta VLAN incompleta ({} bytes)",
                frame.len()
            )));
        }
        ethertype = leer_u16(frame, offset + 2);
        offset += VLAN_TAG_LEN;
    }
    Ok((src_mac, dst_mac, ethertype, offset))
}

/// Parsea una trama ARP para Ethernet/IPv4 (petición o respuesta).
fn parse_arp(frame: &[u8], offset: usize) -> Result<ArpInfo, ParseError> {
    if frame.len() < offset + ARP_MIN_LEN {
        return Err(ParseError::malformada(format!(
            "trama ARP truncada: {} bytes disponibles de {ARP_MIN_LEN} mínimos",
            frame.len().saturating_sub(offset)
        )));
    }
    let hardware = leer_u16(frame, offset);
    let protocolo = leer_u16(frame, offset + 2);
    let hlen = frame[offset + 4];
    let plen = frame[offset + 5];
    if hardware != 1 || protocolo != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
        return Err(ParseError::ignorable(format!(
            "trama ARP de hardware/protocolo no soportado (htype={hardware}, ptype=0x{protocolo:04X})"
        )));
    }
    let opcode = leer_u16(frame, offset + 6);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[offset + 8..offset + 14]);
    let sender_ip = Ipv4Addr::new(
        frame[offset + 14],
        frame[offset + 15],
        frame[offset + 16],
        frame[offset + 17],
    );
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&frame[offset + 18..offset + 24]);
    let target_ip = Ipv4Addr::new(
        frame[offset + 24],
        frame[offset + 25],
        frame[offset + 26],
        frame[offset + 27],
    );
    Ok(ArpInfo {
        opcode,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Direcciones y constructores de tramas sintéticas (deterministas) ----

    const IP_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const IP_B: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

    fn ipv6_a() -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
    }

    fn ipv6_b() -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)
    }

    fn cabecera_ethernet(ethertype: u16) -> Vec<u8> {
        let mut trama = Vec::with_capacity(64);
        trama.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // MAC destino
        trama.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // MAC origen
        trama.extend_from_slice(&ethertype.to_be_bytes());
        trama
    }

    fn trama_ipv4(datos_ip: &[u8]) -> Vec<u8> {
        let mut trama = cabecera_ethernet(ETHERTYPE_IPV4);
        trama.extend_from_slice(datos_ip);
        trama
    }

    fn cabecera_ipv4(
        protocolo: u8,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        carga_len: usize,
        opciones: &[u8],
    ) -> Vec<u8> {
        let ihl = 5 + opciones.len() / 4;
        let total = ihl * 4 + carga_len;
        let mut ip = Vec::with_capacity(ihl * 4);
        ip.push(0x40 | ihl as u8);
        ip.push(0); // DSCP/ECN
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // identificación
        ip.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
        ip.push(64); // TTL
        ip.push(protocolo);
        ip.extend_from_slice(&0u16.to_be_bytes()); // checksum
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&dst.octets());
        ip.extend_from_slice(opciones);
        ip
    }

    fn paquete_ipv4(protocolo: u8, src: Ipv4Addr, dst: Ipv4Addr, transporte: &[u8]) -> Vec<u8> {
        let mut ip = cabecera_ipv4(protocolo, src, dst, transporte.len(), &[]);
        ip.extend_from_slice(transporte);
        trama_ipv4(&ip)
    }

    fn cabecera_tcp(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u16,
        ventana: u16,
    ) -> Vec<u8> {
        let mut tcp = vec![0u8; TCP_MIN_HEADER_LEN];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = (5 << 4) | ((flags >> 8) & 0x01) as u8;
        tcp[13] = (flags & 0xFF) as u8;
        tcp[14..16].copy_from_slice(&ventana.to_be_bytes());
        tcp
    }

    fn trama_tcp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u16,
        carga: &[u8],
    ) -> Vec<u8> {
        let mut tcp = cabecera_tcp(src_port, dst_port, 1_000, 2_000, flags, 64_240);
        tcp.extend_from_slice(carga);
        paquete_ipv4(IPPROTO_TCP, src, dst, &tcp)
    }

    fn udp(src_port: u16, dst_port: u16, carga: &[u8]) -> Vec<u8> {
        let longitud = UDP_HEADER_LEN + carga.len();
        let mut udp = Vec::with_capacity(longitud);
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&(longitud as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum
        udp.extend_from_slice(carga);
        udp
    }

    fn icmp(tipo: u8, codigo: u8, resto: &[u8]) -> Vec<u8> {
        let mut mensaje = vec![tipo, codigo, 0x00, 0x00];
        mensaje.extend_from_slice(resto);
        mensaje
    }

    fn cabecera_ipv6(siguiente: u8, carga_len: usize) -> Vec<u8> {
        let mut ip = vec![0u8; IPV6_HEADER_LEN];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(carga_len as u16).to_be_bytes());
        ip[6] = siguiente;
        ip[7] = 64; // hop limit
        ip[8..24].copy_from_slice(&ipv6_a().octets());
        ip[24..40].copy_from_slice(&ipv6_b().octets());
        ip
    }

    fn trama_ipv6(siguiente: u8, transporte: &[u8]) -> Vec<u8> {
        let mut ip = cabecera_ipv6(siguiente, transporte.len());
        ip.extend_from_slice(transporte);
        let mut trama = cabecera_ethernet(ETHERTYPE_IPV6);
        trama.extend_from_slice(&ip);
        trama
    }

    fn extension_ipv6(siguiente: u8) -> Vec<u8> {
        let mut extension = vec![0u8; 8];
        extension[0] = siguiente;
        extension[1] = 0; // longitud: (0 + 1) * 8 bytes
        extension
    }

    fn fragmento_ipv6(siguiente: u8, offset: u16, mas_fragmentos: bool) -> Vec<u8> {
        let mut fragmento = vec![0u8; 8];
        fragmento[0] = siguiente;
        let mut campo = (offset / 8) << 3;
        if mas_fragmentos {
            campo |= 0x0001;
        }
        fragmento[2..4].copy_from_slice(&campo.to_be_bytes());
        fragmento
    }

    fn trama_con_vlan(ethertype: u16, datos: &[u8]) -> Vec<u8> {
        let mut trama = cabecera_ethernet(ETHERTYPE_VLAN);
        trama.extend_from_slice(&[0x00, 0x64]); // TCI: prioridad 0, VLAN 100
        trama.extend_from_slice(&ethertype.to_be_bytes());
        trama.extend_from_slice(datos);
        trama
    }

    // ---- Ethernet / IPv4 / IPv6 / transporte ----

    #[test]
    fn parsea_ethernet_ipv4_tcp_con_flags() {
        let trama = trama_tcp(IP_A, IP_B, 51_000, 443, 0x12, b"");
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("trama TCP válida");
        assert_eq!(meta.src_ip, IpAddr::V4(IP_A));
        assert_eq!(meta.dst_ip, IpAddr::V4(IP_B));
        assert_eq!(meta.src_port, Some(51_000));
        assert_eq!(meta.dst_port, Some(443));
        assert_eq!(meta.protocol, Protocol::Tcp);
        assert_eq!(meta.len, 40);
        let flags = meta.tcp_flags.expect("flags TCP presentes");
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.fin);
        let cabeceras = meta.headers.expect("siempre hay copia de cabeceras");
        assert_eq!(cabeceras.ip_version, 4);
        assert_eq!(cabeceras.ip_header_len, 20);
        assert_eq!(cabeceras.ip_total_len, 40);
        assert_eq!(cabeceras.ip_protocol, IPPROTO_TCP);
        assert_eq!(cabeceras.ip_raw_len, 20);
        assert_eq!(cabeceras.transport_raw_len, 20);
        assert_eq!(cabeceras.tcp_flags, 0x12);
        assert_eq!(cabeceras.tcp_seq, 1_000);
        assert_eq!(cabeceras.tcp_ack, 2_000);
        assert_eq!(cabeceras.tcp_window, 64_240);
        assert_eq!(&cabeceras.transport_bytes()[0..2], &[0xC7, 0x38]);
    }

    #[test]
    fn parsea_ipv4_udp() {
        let trama = paquete_ipv4(IPPROTO_UDP, IP_A, IP_B, &udp(50_000, 123, b"ntp"));
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("trama UDP válida");
        assert_eq!(meta.protocol, Protocol::Udp);
        assert_eq!(meta.src_port, Some(50_000));
        assert_eq!(meta.dst_port, Some(123));
        assert_eq!(meta.len, 31);
        assert!(meta.tcp_flags.is_none());
        let cabeceras = meta.headers.expect("cabeceras");
        assert_eq!(cabeceras.transport_raw_len, 8);
        assert_eq!(cabeceras.tcp_flags, 0);
    }

    #[test]
    fn parsea_ipv4_icmp() {
        let trama = paquete_ipv4(
            IPPROTO_ICMP,
            IP_A,
            IP_B,
            &icmp(8, 0, &[0x12, 0x34, 0x00, 0x01]),
        );
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("trama ICMP válida");
        assert_eq!(meta.protocol, Protocol::Icmp);
        assert_eq!(meta.src_port, None);
        assert_eq!(meta.dst_port, None);
        assert_eq!(meta.len, 28);
        assert!(meta.tcp_flags.is_none());
        let cabeceras = meta.headers.expect("cabeceras");
        assert_eq!(cabeceras.ip_protocol, IPPROTO_ICMP);
        assert_eq!(cabeceras.transport_raw[0], 8); // tipo echo request
        assert_eq!(cabeceras.transport_raw[1], 0); // código
    }

    #[test]
    fn parsea_ipv4_con_opciones() {
        let mut ip = cabecera_ipv4(IPPROTO_TCP, IP_A, IP_B, TCP_MIN_HEADER_LEN, &[1, 1, 1, 0]);
        ip.extend_from_slice(&cabecera_tcp(1_234, 80, 1, 2, 0x02, 1_000));
        let trama = trama_ipv4(&ip);
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("trama con opciones IP");
        assert_eq!(meta.src_port, Some(1_234));
        assert_eq!(meta.dst_port, Some(80));
        let cabeceras = meta.headers.expect("cabeceras");
        assert_eq!(cabeceras.ip_header_len, 24);
        assert_eq!(cabeceras.ip_raw_len, 24);
    }

    #[test]
    fn parsea_ipv6_udp() {
        let trama = trama_ipv6(IPPROTO_UDP, &udp(50_000, 5_000, b"hola"));
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("trama IPv6 UDP válida");
        assert_eq!(meta.src_ip, IpAddr::V6(ipv6_a()));
        assert_eq!(meta.dst_ip, IpAddr::V6(ipv6_b()));
        assert_eq!(meta.protocol, Protocol::Udp);
        assert_eq!(meta.src_port, Some(50_000));
        assert_eq!(meta.dst_port, Some(5_000));
        assert_eq!(meta.len, 52);
        let cabeceras = meta.headers.expect("cabeceras");
        assert_eq!(cabeceras.ip_version, 6);
        assert_eq!(cabeceras.ip_header_len, 40);
        assert_eq!(cabeceras.ip_raw_len, 40);
        assert_eq!(cabeceras.ip_protocol, IPPROTO_UDP);
        assert_eq!(cabeceras.ttl, 64);
    }

    #[test]
    fn parsea_ipv6_con_cadena_de_extensiones() {
        let udp_bytes = udp(50_000, 5_000, b"x");
        let mut carga = extension_ipv6(60); // hop-by-hop -> destination options
        carga.extend_from_slice(&extension_ipv6(IPPROTO_UDP));
        carga.extend_from_slice(&udp_bytes);
        let trama = trama_ipv6(0, &carga);
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("IPv6 con extensiones");
        assert_eq!(meta.protocol, Protocol::Udp);
        assert_eq!(meta.src_port, Some(50_000));
        let cabeceras = meta.headers.expect("cabeceras");
        assert_eq!(cabeceras.ip_protocol, IPPROTO_UDP);
        assert_eq!(meta.len, 40 + carga.len() as u32);
    }

    #[test]
    fn parsea_ipv6_con_fragmento_inicial() {
        let udp_bytes = udp(50_000, 5_000, b"x");
        let mut carga = fragmento_ipv6(IPPROTO_UDP, 0, true);
        carga.extend_from_slice(&udp_bytes);
        let trama = trama_ipv6(44, &carga);
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("fragmento inicial IPv6");
        assert_eq!(meta.protocol, Protocol::Udp);
        assert_eq!(meta.dst_port, Some(5_000));
    }

    #[test]
    fn parsea_ipv6_icmpv6() {
        let trama = trama_ipv6(IPPROTO_ICMPV6, &icmp(128, 0, &[0x00, 0x01, 0x00, 0x01]));
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("ICMPv6 válido");
        assert_eq!(meta.protocol, Protocol::Icmpv6);
        assert_eq!(meta.src_port, None);
        assert_eq!(meta.dst_port, None);
        let cabeceras = meta.headers.expect("cabeceras");
        assert_eq!(cabeceras.ip_protocol, IPPROTO_ICMPV6);
        assert_eq!(cabeceras.transport_raw[0], 128); // echo request
    }

    #[test]
    fn parsea_vlan_8021q() {
        let mut ip = cabecera_ipv4(IPPROTO_TCP, IP_A, IP_B, TCP_MIN_HEADER_LEN, &[]);
        ip.extend_from_slice(&cabecera_tcp(1_000, 80, 1, 2, 0x02, 1_000));
        let trama = trama_con_vlan(ETHERTYPE_IPV4, &ip);
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("trama con VLAN");
        assert_eq!(meta.protocol, Protocol::Tcp);
        assert_eq!(meta.src_port, Some(1_000));
        assert_eq!(meta.dst_port, Some(80));
    }

    #[test]
    fn el_protocolo_desconocido_se_marca_como_otros_sin_puertos() {
        let trama = paquete_ipv4(47, IP_A, IP_B, &[0x00, 0x00, 0x08, 0x00, 0x45, 0x00]);
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("GRE es un protocolo válido");
        assert_eq!(meta.protocol, Protocol::Other);
        assert_eq!(meta.src_port, None);
        assert_eq!(meta.dst_port, None);
        let cabeceras = meta.headers.expect("cabeceras");
        assert_eq!(cabeceras.ip_protocol, 47);
        // Por privacidad, de un protocolo desconocido no se copia la cabecera.
        assert_eq!(cabeceras.transport_raw_len, 0);
    }

    #[test]
    fn el_protocolo_desconocido_ipv6_tambien_es_otros() {
        let trama = trama_ipv6(50, &[0u8; 8]); // ESP
        let meta = Parser::with_defaults().parse(&trama).expect("ESP válido");
        assert_eq!(meta.protocol, Protocol::Other);
        assert_eq!(meta.len, 48);
    }

    // ---- Errores: ignorables y no ignorables ----

    #[test]
    fn el_ether_type_no_soportado_es_ignorable() {
        let mut trama = cabecera_ethernet(0x0806); // ARP
        trama.extend_from_slice(&[0u8; 28]);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("ARP no se procesa");
        assert!(error.ignorable);
        assert!(error.to_string().contains("no soportado"));
    }

    #[test]
    fn la_trama_ethernet_truncada_no_es_ignorable() {
        let error = Parser::with_defaults()
            .parse(&[0u8; 10])
            .expect_err("trama corta");
        assert!(!error.ignorable);
    }

    #[test]
    fn la_trama_vlan_truncada_no_es_ignorable() {
        let mut trama = cabecera_ethernet(ETHERTYPE_VLAN);
        trama.push(0x00);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("VLAN corta");
        assert!(!error.ignorable);
    }

    #[test]
    fn la_ipv4_truncada_no_es_ignorable() {
        let mut trama = trama_tcp(IP_A, IP_B, 1_000, 80, 0x02, b"carga");
        trama.truncate(trama.len() - 4);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("paquete cortado");
        assert!(!error.ignorable);
    }

    #[test]
    fn la_cabecera_ipv4_incompleta_no_es_ignorable() {
        let trama = trama_ipv4(&[0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00]);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("cabecera IP incompleta");
        assert!(!error.ignorable);
    }

    #[test]
    fn una_version_ip_distinta_es_ignorable() {
        let mut ip = cabecera_ipv4(IPPROTO_TCP, IP_A, IP_B, 20, &[]);
        ip[0] = 0x65; // versión 6 dentro de EtherType IPv4
        ip.extend_from_slice(&[0u8; 20]);
        let trama = trama_ipv4(&ip);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("versión rara");
        assert!(error.ignorable);
    }

    #[test]
    fn la_cabecera_tcp_truncada_no_es_ignorable() {
        let trama = paquete_ipv4(IPPROTO_TCP, IP_A, IP_B, &[0u8; 10]);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("TCP corto");
        assert!(!error.ignorable);
        assert!(error.to_string().contains("TCP"));
    }

    #[test]
    fn una_longitud_udp_invalida_no_es_ignorable() {
        let mut udp_bytes = vec![0u8; UDP_HEADER_LEN];
        udp_bytes[4..6].copy_from_slice(&4u16.to_be_bytes()); // longitud < 8
        let trama = paquete_ipv4(IPPROTO_UDP, IP_A, IP_B, &udp_bytes);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("longitud UDP inválida");
        assert!(!error.ignorable);
    }

    #[test]
    fn un_datagrama_udp_truncado_no_es_ignorable() {
        let mut udp_bytes = vec![0u8; UDP_HEADER_LEN];
        udp_bytes[4..6].copy_from_slice(&100u16.to_be_bytes()); // anuncia 100, hay 8
        let trama = paquete_ipv4(IPPROTO_UDP, IP_A, IP_B, &udp_bytes);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("UDP truncado");
        assert!(!error.ignorable);
    }

    #[test]
    fn la_ipv6_truncada_no_es_ignorable() {
        let mut trama = trama_ipv6(IPPROTO_UDP, &udp(1, 2, b"x"));
        trama.truncate(trama.len() - 3);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("IPv6 cortado");
        assert!(!error.ignorable);
    }

    #[test]
    fn la_extension_ipv6_truncada_no_es_ignorable() {
        let mut carga = extension_ipv6(IPPROTO_UDP);
        carga[1] = 5; // declara 48 bytes de extensión
        let trama = trama_ipv6(0, &carga);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("extensión corta");
        assert!(!error.ignorable);
    }

    #[test]
    fn el_fragmento_ipv4_no_inicial_es_ignorable() {
        let mut trama = paquete_ipv4(IPPROTO_UDP, IP_A, IP_B, &udp(1_000, 2_000, b"x"));
        let inicio = ETHERNET_HEADER_LEN + 6;
        trama[inicio..inicio + 2].copy_from_slice(&0x0001u16.to_be_bytes());
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("fragmento no inicial");
        assert!(error.ignorable);
    }

    #[test]
    fn el_fragmento_ipv6_no_inicial_es_ignorable() {
        let mut carga = fragmento_ipv6(IPPROTO_UDP, 8, false);
        carga.extend_from_slice(&udp(1_000, 2_000, b"x"));
        let trama = trama_ipv6(44, &carga);
        let error = Parser::with_defaults()
            .parse(&trama)
            .expect_err("fragmento no inicial IPv6");
        assert!(error.ignorable);
    }

    #[test]
    fn el_payload_no_aparece_en_los_metadatos() {
        let mut consulta = vec![0u8; 12];
        consulta.extend_from_slice(b"MARCADOR_SECRETO_DEL_PAYLOAD");
        let trama = paquete_ipv4(IPPROTO_UDP, IP_A, IP_B, &udp(50_000, 53, &consulta));
        let meta = Parser::with_defaults()
            .parse(&trama)
            .expect("trama UDP válida");
        let volcado = format!("{meta:?}");
        assert!(!volcado.contains("MARCADOR"));
        // PacketMeta está pensado para no almacenar payload: su tamaño es fijo y pequeño.
        assert!(std::mem::size_of::<PacketMeta>() < 512);
    }

    // ---- Comportamiento general ----

    #[test]
    fn el_atajo_parse_usa_las_opciones_por_defecto() {
        let trama = trama_tcp(IP_A, IP_B, 1_234, 8_080, 0x02, b"");
        let meta = parse(&trama).expect("trama válida con el atajo");
        assert_eq!(meta.protocol, Protocol::Tcp);
        assert_eq!(meta.dst_port, Some(8_080));
    }

    #[test]
    fn la_longitud_es_la_del_paquete_ip_y_no_la_de_la_trama_con_relleno() {
        let mut trama = trama_tcp(IP_A, IP_B, 1_234, 80, 0x02, b"");
        trama.extend_from_slice(&[0u8; 10]); // relleno Ethernet
        let meta = Parser::with_defaults().parse(&trama).expect("trama válida");
        assert_eq!(meta.len, 40);
    }

    #[test]
    fn no_hace_panic_con_tramas_arbitrarias() {
        for semilla in 0u32..16 {
            for longitud in [0usize, 1, 13, 14, 20, 34, 42, 60, 120] {
                let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(1);
                let mut datos = Vec::with_capacity(longitud);
                for _ in 0..longitud {
                    estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                    datos.push((estado >> 24) as u8);
                }
                let _ = Parser::with_defaults().parse(&datos);
            }
        }
    }

    #[test]
    fn los_errores_son_std_error() {
        let error: Box<dyn std::error::Error> = Box::new(ParseError::malformada("trama rota"));
        assert!(error.to_string().contains("trama rota"));
    }
}
