//! Firmas de protocolos de aplicación y reglas por puerto (§7.3).
//!
//! Primero manda la firma de los primeros bytes reensamblados; solo si no hay
//! firma se usa el puerto típico como protocolo provisional. Una firma gana
//! siempre al puerto: un SSH en el puerto 443 se identifica como SSH.
//!
//! Las firmas débiles (un solo byte, puertos típicos conocidos) exigen además el
//! puerto de la tabla para no confundir tráfico arbitrario: así se comportan
//! DHCPv6, CoAP, OpenVPN, IPsec y NetBIOS.

use crate::inference::{AppProtocol, L4};

/// Longitud de la cabecera fija de un mensaje DNS.
const CABECERA_DNS: usize = 12;
/// Longitud máxima de la parte inicial que se examina para MQTT.
const LIMITE_MQTT: usize = 20;

/// Certeza de la identificación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certainty {
    /// Firma de los primeros bytes.
    Signature,
    /// Puerto típico (provisional).
    Port,
}

/// Identifica el protocolo de aplicación por firma o, si no hay, por puerto.
///
/// `ports` es `(origen, destino)`; `c2s` y `s2c` son los primeros bytes
/// reensamblados de cada sentido (vacíos si aún no hay datos).
pub fn identify(
    l4: L4,
    ports: (u16, u16),
    c2s: &[u8],
    s2c: &[u8],
) -> Option<(AppProtocol, Certainty)> {
    if let Some(protocolo) = por_firma(l4, ports, c2s, s2c) {
        return Some((protocolo, Certainty::Signature));
    }
    por_puerto(l4, ports).map(|protocolo| (protocolo, Certainty::Port))
}

/// Indica si un puerto es de servicio conocido (< 1024 o tabla §7.3).
pub fn is_service_port(port: u16) -> bool {
    port < 1024
        || matches!(
            port,
            1194 | 1883 | 1900 | 3389 | 4500 | 5060 | 5353 | 5355 | 5683 | 5900..=5909
        )
}

/// Indica si un puerto es efímero (>= 32768).
pub fn is_ephemeral(port: u16) -> bool {
    port >= 32768
}

/// Protocolo provisional asignado a un puerto típico de servicio.
pub fn protocol_for_port(l4: L4, port: u16) -> Option<AppProtocol> {
    Some(match l4 {
        L4::Tcp => match port {
            21 => AppProtocol::Ftp,
            22 => AppProtocol::Ssh,
            25 | 587 => AppProtocol::Smtp,
            53 => AppProtocol::Dns,
            80 => AppProtocol::Http,
            110 => AppProtocol::Pop3,
            139 => AppProtocol::Netbios,
            143 => AppProtocol::Imap,
            443 => AppProtocol::Tls,
            445 => AppProtocol::Smb,
            554 => AppProtocol::Rtsp,
            1194 => AppProtocol::Openvpn,
            1883 => AppProtocol::Mqtt,
            3389 => AppProtocol::Rdp,
            5060 => AppProtocol::Sip,
            5900..=5909 => AppProtocol::Vnc,
            _ => return None,
        },
        L4::Udp => match port {
            53 => AppProtocol::Dns,
            67 | 68 => AppProtocol::Dhcp,
            123 => AppProtocol::Ntp,
            137 | 138 => AppProtocol::Netbios,
            161 | 162 => AppProtocol::Snmp,
            500 | 4500 => AppProtocol::Ipsec,
            546 | 547 => AppProtocol::Dhcpv6,
            1194 => AppProtocol::Openvpn,
            1900 => AppProtocol::Ssdp,
            5060 => AppProtocol::Sip,
            5353 => AppProtocol::Mdns,
            5355 => AppProtocol::Llmnr,
            5683 => AppProtocol::Coap,
            _ => return None,
        },
    })
}

/// Busca una firma en los primeros bytes de cada sentido.
fn por_firma(l4: L4, ports: (u16, u16), c2s: &[u8], s2c: &[u8]) -> Option<AppProtocol> {
    match l4 {
        L4::Tcp => {
            if es_tls(c2s) || es_tls(s2c) {
                return Some(AppProtocol::Tls);
            }
            if es_ssh(c2s) || es_ssh(s2c) {
                return Some(AppProtocol::Ssh);
            }
            if es_http2(c2s) {
                return Some(AppProtocol::Http2);
            }
            if es_rtsp(c2s) || es_rtsp(s2c) {
                return Some(AppProtocol::Rtsp);
            }
            if es_sip(c2s) || es_sip(s2c) {
                return Some(AppProtocol::Sip);
            }
            if es_http(c2s, s2c) {
                return Some(AppProtocol::Http);
            }
            if es_rdp(c2s) || es_rdp(s2c) {
                return Some(AppProtocol::Rdp);
            }
            if es_vnc(s2c) {
                return Some(AppProtocol::Vnc);
            }
            if es_smb(c2s) || es_smb(s2c) {
                return Some(AppProtocol::Smb);
            }
            if es_mqtt(c2s) {
                return Some(AppProtocol::Mqtt);
            }
            if es_bittorrent(c2s) || es_bittorrent(s2c) {
                return Some(AppProtocol::Bittorrent);
            }
            if es_ftp(c2s, s2c) {
                return Some(AppProtocol::Ftp);
            }
            if es_smtp(c2s, s2c) {
                return Some(AppProtocol::Smtp);
            }
            if es_imap(s2c) {
                return Some(AppProtocol::Imap);
            }
            if es_pop3(s2c) {
                return Some(AppProtocol::Pop3);
            }
            if es_netbios(ports, c2s, s2c) {
                return Some(AppProtocol::Netbios);
            }
            if let Some(protocolo) = firma_dns(L4::Tcp, ports, c2s, s2c) {
                return Some(protocolo);
            }
            None
        }
        L4::Udp => {
            if es_quic(c2s) || es_quic(s2c) {
                return Some(AppProtocol::Quic);
            }
            if es_dhcp(c2s) || es_dhcp(s2c) {
                return Some(AppProtocol::Dhcp);
            }
            if es_dhcpv6(ports, c2s) || es_dhcpv6(ports, s2c) {
                return Some(AppProtocol::Dhcpv6);
            }
            if es_stun(c2s) || es_stun(s2c) {
                return Some(AppProtocol::Stun);
            }
            if es_wireguard(c2s) || es_wireguard(s2c) {
                return Some(AppProtocol::Wireguard);
            }
            if es_ipsec(ports, c2s) || es_ipsec(ports, s2c) {
                return Some(AppProtocol::Ipsec);
            }
            if es_openvpn(ports, c2s) || es_openvpn(ports, s2c) {
                return Some(AppProtocol::Openvpn);
            }
            if es_coap(ports, c2s) || es_coap(ports, s2c) {
                return Some(AppProtocol::Coap);
            }
            if es_snmp(c2s) || es_snmp(s2c) {
                return Some(AppProtocol::Snmp);
            }
            if es_ntp(c2s) || es_ntp(s2c) {
                return Some(AppProtocol::Ntp);
            }
            if es_ssdp(c2s) || es_ssdp(s2c) {
                return Some(AppProtocol::Ssdp);
            }
            if es_bittorrent(c2s) || es_bittorrent(s2c) {
                return Some(AppProtocol::Bittorrent);
            }
            if es_netbios(ports, c2s, s2c) {
                return Some(AppProtocol::Netbios);
            }
            if let Some(protocolo) = firma_dns(L4::Udp, ports, c2s, s2c) {
                return Some(protocolo);
            }
            None
        }
    }
}

/// Protocolo provisional según los puertos, prefiriendo el de destino.
fn por_puerto(l4: L4, ports: (u16, u16)) -> Option<AppProtocol> {
    let (origen, destino) = ports;
    protocol_for_port(l4, destino).or_else(|| protocol_for_port(l4, origen))
}

/// Indica si el puerto aparece en cualquiera de los dos extremos.
fn puerto_en(ports: (u16, u16), puerto: u16) -> bool {
    ports.0 == puerto || ports.1 == puerto
}

/// Indica si `datos` empieza por el prefijo indicado.
fn empieza_con(datos: &[u8], prefijo: &[u8]) -> bool {
    datos.len() >= prefijo.len() && &datos[..prefijo.len()] == prefijo
}

/// Indica si `datos` empieza por alguno de los prefijos indicados.
fn empieza_con_alguna(datos: &[u8], prefijos: &[&[u8]]) -> bool {
    prefijos.iter().any(|prefijo| empieza_con(datos, prefijo))
}

/// Busca una aguja en los primeros `limite` bytes.
fn contiene_en(datos: &[u8], aguja: &[u8], limite: usize) -> bool {
    let fin = datos.len().min(limite);
    datos[..fin]
        .windows(aguja.len())
        .any(|ventana| ventana == aguja)
}

fn es_tls(datos: &[u8]) -> bool {
    datos.len() >= 3 && datos[0] == 0x16 && datos[1] == 0x03 && datos[2] <= 0x04
}

fn es_ssh(datos: &[u8]) -> bool {
    empieza_con_alguna(datos, &[b"SSH-2.0-", b"SSH-1.99-"])
}

fn es_http2(datos: &[u8]) -> bool {
    empieza_con(datos, b"PRI * HTTP/2.0")
}

fn es_http(c2s: &[u8], s2c: &[u8]) -> bool {
    const METODOS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    empieza_con_alguna(c2s, &METODOS) || empieza_con(s2c, b"HTTP/1.")
}

fn es_rtsp(datos: &[u8]) -> bool {
    empieza_con_alguna(
        datos,
        &[b"OPTIONS rtsp://", b"DESCRIBE rtsp://", b"RTSP/1.0"],
    )
}

fn es_sip(datos: &[u8]) -> bool {
    empieza_con_alguna(datos, &[b"INVITE sip:", b"REGISTER sip:", b"SIP/2.0"])
}

fn es_ssdp(datos: &[u8]) -> bool {
    empieza_con_alguna(
        datos,
        &[
            b"M-SEARCH * HTTP/1.1",
            b"NOTIFY * HTTP/1.1",
            b"HTTP/1.1 200",
        ],
    )
}

fn es_rdp(datos: &[u8]) -> bool {
    datos.len() >= 6 && datos[0] == 0x03 && datos[1] == 0x00 && datos[5] == 0xE0
}

fn es_vnc(datos: &[u8]) -> bool {
    empieza_con(datos, b"RFB 003.")
}

fn es_smb(datos: &[u8]) -> bool {
    const FIRMAS: [&[u8]; 2] = [b"\xffSMB", b"\xfeSMB"];
    if empieza_con_alguna(datos, &FIRMAS) {
        return true;
    }
    // Sobre NetBIOS: 4 bytes de cabecera de sesión antes del mensaje SMB.
    if datos.len() >= 8 && datos[0] == 0x00 {
        return empieza_con_alguna(&datos[4..], &FIRMAS);
    }
    false
}

fn es_mqtt(datos: &[u8]) -> bool {
    datos.first() == Some(&0x10)
        && (contiene_en(datos, b"MQTT", LIMITE_MQTT) || contiene_en(datos, b"MQIsdp", LIMITE_MQTT))
}

fn es_bittorrent(datos: &[u8]) -> bool {
    empieza_con_alguna(datos, &[b"\x13BitTorrent protocol", b"d1:ad2:id20:"])
}

fn es_ftp(c2s: &[u8], s2c: &[u8]) -> bool {
    empieza_con(s2c, b"220") && empieza_con_alguna(c2s, &[b"USER ", b"AUTH "])
}

fn es_smtp(c2s: &[u8], s2c: &[u8]) -> bool {
    empieza_con(s2c, b"220") && empieza_con_alguna(c2s, &[b"EHLO ", b"HELO "])
}

fn es_imap(datos: &[u8]) -> bool {
    empieza_con(datos, b"* OK")
}

fn es_pop3(datos: &[u8]) -> bool {
    empieza_con(datos, b"+OK")
}

fn es_quic(datos: &[u8]) -> bool {
    if datos.len() < 5 || datos[0] & 0x80 == 0 || datos[0] & 0x40 == 0 {
        return false;
    }
    let version = u32::from_be_bytes([datos[1], datos[2], datos[3], datos[4]]);
    version == 1 || version == 0x6b33_43cf
}

fn es_dhcp(datos: &[u8]) -> bool {
    datos.len() >= 240 && matches!(&datos[236..240], [0x63, 0x82, 0x53, 0x63])
}

fn es_dhcpv6(ports: (u16, u16), datos: &[u8]) -> bool {
    (puerto_en(ports, 546) || puerto_en(ports, 547))
        && datos.first().is_some_and(|tipo| (1..=13).contains(tipo))
}

fn es_ntp(datos: &[u8]) -> bool {
    if datos.len() < 48 {
        return false;
    }
    let version = (datos[0] >> 3) & 0x07;
    let mode = datos[0] & 0x07;
    matches!(version, 3 | 4) && (1..=5).contains(&mode)
}

fn es_stun(datos: &[u8]) -> bool {
    datos.len() >= 20 && matches!(&datos[4..8], [0x21, 0x12, 0xA4, 0x42])
}

fn es_wireguard(datos: &[u8]) -> bool {
    if datos.len() < 4 || !matches!(&datos[1..4], [0, 0, 0]) {
        return false;
    }
    match datos[0] {
        1 => datos.len() == 148,
        2 => datos.len() == 92,
        3 => datos.len() == 64,
        4 => datos.len() >= 32,
        _ => false,
    }
}

fn es_openvpn(ports: (u16, u16), datos: &[u8]) -> bool {
    if datos.len() < 14 || !puerto_en(ports, 1194) {
        return false;
    }
    let opcode = (datos[0] >> 3) & 0x1f;
    opcode == 7 || opcode == 10
}

fn es_ipsec(ports: (u16, u16), datos: &[u8]) -> bool {
    datos.len() >= 28 && (puerto_en(ports, 500) || puerto_en(ports, 4500)) && datos[17] == 0x20
}

fn es_coap(ports: (u16, u16), datos: &[u8]) -> bool {
    if datos.len() < 4 || !puerto_en(ports, 5683) {
        return false;
    }
    let version = (datos[0] >> 6) & 0x03;
    let token_length = datos[0] & 0x0f;
    let codigo = datos[1];
    if version != 1 || token_length > 8 {
        return false;
    }
    let clase = codigo >> 5;
    codigo == 0 || (1..=4).contains(&codigo) || matches!(clase, 2 | 4 | 5)
}

fn es_snmp(datos: &[u8]) -> bool {
    datos.len() >= 6
        && datos[0] == 0x30
        && datos[2] == 0x02
        && datos[3] == 0x01
        && matches!(datos[4], 0 | 1 | 3)
}

fn es_netbios(ports: (u16, u16), c2s: &[u8], s2c: &[u8]) -> bool {
    if puerto_en(ports, 138) && (es_cabecera_nbds(c2s) || es_cabecera_nbds(s2c)) {
        return true;
    }
    if puerto_en(ports, 139) && (es_cabecera_sesion_netbios(c2s) || es_cabecera_sesion_netbios(s2c))
    {
        return true;
    }
    false
}

fn es_cabecera_nbds(datos: &[u8]) -> bool {
    datos.len() >= 14 && (0x10..=0x16).contains(&datos[0])
}

fn es_cabecera_sesion_netbios(datos: &[u8]) -> bool {
    datos.len() >= 4 && matches!(datos[0], 0x00 | 0x81..=0x85)
}

/// Firma de la familia DNS (dns, mdns, llmnr y NBNS).
fn firma_dns(l4: L4, ports: (u16, u16), c2s: &[u8], s2c: &[u8]) -> Option<AppProtocol> {
    let tcp = l4 == L4::Tcp;
    if !cabecera_dns_valida(c2s, tcp) && !cabecera_dns_valida(s2c, tcp) {
        return None;
    }
    if !tcp {
        if puerto_en(ports, 5353) {
            return Some(AppProtocol::Mdns);
        }
        if puerto_en(ports, 5355) {
            return Some(AppProtocol::Llmnr);
        }
        if puerto_en(ports, 137) {
            return Some(AppProtocol::Netbios);
        }
    }
    Some(AppProtocol::Dns)
}

/// Comprueba una cabecera DNS válida (opcode 0 y QDCOUNT >= 1).
fn cabecera_dns_valida(datos: &[u8], tcp: bool) -> bool {
    let inicio = if tcp {
        // DNS sobre TCP: prefijo de longitud de 2 bytes (RFC 1035 §4.2.2).
        if datos.len() < 2 + CABECERA_DNS {
            return false;
        }
        let longitud = usize::from(u16::from_be_bytes([datos[0], datos[1]]));
        if longitud < CABECERA_DNS {
            return false;
        }
        2
    } else {
        0
    };
    let cabecera = match datos.get(inicio..inicio + CABECERA_DNS) {
        Some(cabecera) => cabecera,
        None => return false,
    };
    let flags = u16::from_be_bytes([cabecera[2], cabecera[3]]);
    let opcode = (flags >> 11) & 0x0f;
    let preguntas = u16::from_be_bytes([cabecera[4], cabecera[5]]);
    opcode == 0 && preguntas >= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Protocolo identificado, sin la certeza.
    fn protocolo(l4: L4, ports: (u16, u16), c2s: &[u8], s2c: &[u8]) -> Option<AppProtocol> {
        identify(l4, ports, c2s, s2c).map(|(protocolo, _)| protocolo)
    }

    /// Cabecera de consulta DNS seguida de un QNAME sin compresión.
    fn consulta_dns(qname: &str) -> Vec<u8> {
        let mut mensaje = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for etiqueta in qname.split('.') {
            mensaje.push(etiqueta.len() as u8);
            mensaje.extend_from_slice(etiqueta.as_bytes());
        }
        mensaje.push(0);
        mensaje.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        mensaje
    }

    #[test]
    fn identifica_todas_las_filas_de_la_tabla() {
        // dns, mdns y llmnr comparten formato y se distinguen por el puerto.
        let consulta = consulta_dns("example.com");
        assert_eq!(
            protocolo(L4::Udp, (50000, 53), &consulta, &[]),
            Some(AppProtocol::Dns)
        );
        assert_eq!(
            protocolo(L4::Udp, (5353, 5353), &consulta, &[]),
            Some(AppProtocol::Mdns)
        );
        assert_eq!(
            protocolo(L4::Udp, (50000, 5355), &consulta, &[]),
            Some(AppProtocol::Llmnr)
        );
        // DNS sobre TCP con prefijo de longitud.
        let mut dns_tcp = (consulta.len() as u16).to_be_bytes().to_vec();
        dns_tcp.extend_from_slice(&consulta);
        assert_eq!(
            protocolo(L4::Tcp, (50000, 53), &dns_tcp, &[]),
            Some(AppProtocol::Dns)
        );

        // netbios: NBNS (137) con formato DNS, NBDS (138) y sesión (139).
        assert_eq!(
            protocolo(L4::Udp, (50000, 137), &consulta, &[]),
            Some(AppProtocol::Netbios)
        );
        let mut nbds = vec![0x10u8; 20];
        nbds[1] = 0x01;
        assert_eq!(
            protocolo(L4::Udp, (50000, 138), &nbds, &[]),
            Some(AppProtocol::Netbios)
        );
        assert_eq!(
            protocolo(
                L4::Tcp,
                (50000, 139),
                &[0x00, 0x00, 0x00, 0x08, 0, 0, 0, 0],
                &[]
            ),
            Some(AppProtocol::Netbios)
        );

        // dhcp: cookie mágica en el byte 236.
        let mut dhcp = vec![0u8; 240];
        dhcp[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        assert_eq!(
            protocolo(L4::Udp, (68, 67), &dhcp, &[]),
            Some(AppProtocol::Dhcp)
        );

        // dhcpv6: tipo de mensaje 1-13 y puerto 546/547.
        assert_eq!(
            protocolo(L4::Udp, (546, 547), &[1, 0, 0, 0], &[]),
            Some(AppProtocol::Dhcpv6)
        );

        // ntp: 48 bytes, versión 4 y modo cliente.
        let mut ntp = vec![0u8; 48];
        ntp[0] = 0x23;
        assert_eq!(
            protocolo(L4::Udp, (50000, 123), &ntp, &[]),
            Some(AppProtocol::Ntp)
        );

        // ssdp.
        assert_eq!(
            protocolo(
                L4::Udp,
                (50000, 1900),
                b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250\r\n\r\n",
                &[]
            ),
            Some(AppProtocol::Ssdp)
        );
        assert_eq!(
            protocolo(L4::Udp, (1900, 50000), b"NOTIFY * HTTP/1.1\r\n\r\n", &[]),
            Some(AppProtocol::Ssdp)
        );

        // tls.
        assert_eq!(
            protocolo(L4::Tcp, (50000, 443), &[0x16, 0x03, 0x01, 0x00, 0x00], &[]),
            Some(AppProtocol::Tls)
        );

        // quic: cabecera larga con bit fijo y versión 1.
        assert_eq!(
            protocolo(
                L4::Udp,
                (50000, 443),
                &[0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0, 0],
                &[]
            ),
            Some(AppProtocol::Quic)
        );

        // http: método y respuesta.
        assert_eq!(
            protocolo(L4::Tcp, (50000, 80), b"GET / HTTP/1.1\r\n\r\n", &[]),
            Some(AppProtocol::Http)
        );
        assert_eq!(
            protocolo(L4::Tcp, (80, 50000), &[], b"HTTP/1.1 200 OK\r\n\r\n"),
            Some(AppProtocol::Http)
        );

        // http2 (h2c).
        assert_eq!(
            protocolo(
                L4::Tcp,
                (50000, 80),
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                &[]
            ),
            Some(AppProtocol::Http2)
        );

        // rdp: TPKT + X.224 Connection Request.
        assert_eq!(
            protocolo(
                L4::Tcp,
                (50000, 3389),
                &[0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0],
                &[]
            ),
            Some(AppProtocol::Rdp)
        );

        // vnc: saludo del servidor.
        assert_eq!(
            protocolo(L4::Tcp, (5900, 50000), &[], b"RFB 003.008\n"),
            Some(AppProtocol::Vnc)
        );

        // smb directo y tras la cabecera NetBIOS de sesión.
        assert_eq!(
            protocolo(L4::Tcp, (50000, 445), b"\xffSMB\x72\x00\x00\x00", &[]),
            Some(AppProtocol::Smb)
        );
        assert_eq!(
            protocolo(
                L4::Tcp,
                (50000, 139),
                b"\x00\x00\x00\x08\xffSMB\x72\x00",
                &[]
            ),
            Some(AppProtocol::Smb)
        );

        // ftp y smtp comparten el 220 y se distinguen por la orden del cliente.
        assert_eq!(
            protocolo(
                L4::Tcp,
                (50000, 21),
                b"USER anonymous\r\n",
                b"220 (vsFTPd 3.0.5)\r\n"
            ),
            Some(AppProtocol::Ftp)
        );
        assert_eq!(
            protocolo(
                L4::Tcp,
                (50000, 25),
                b"EHLO cliente\r\n",
                b"220 mail.example.com ESMTP\r\n"
            ),
            Some(AppProtocol::Smtp)
        );

        // imap y pop3: saludo del servidor.
        assert_eq!(
            protocolo(L4::Tcp, (143, 50000), &[], b"* OK IMAP4rev1 listo\r\n"),
            Some(AppProtocol::Imap)
        );
        assert_eq!(
            protocolo(L4::Tcp, (110, 50000), &[], b"+OK POP3 listo\r\n"),
            Some(AppProtocol::Pop3)
        );

        // mqtt: CONNECT con el protocolo en el nombre.
        let mut mqtt = vec![0x10, 0x0e, 0x00, 0x04];
        mqtt.extend_from_slice(b"MQTT");
        mqtt.extend_from_slice(&[0x04, 0x02, 0x00, 0x3c]);
        assert_eq!(
            protocolo(L4::Tcp, (50000, 1883), &mqtt, &[]),
            Some(AppProtocol::Mqtt)
        );

        // coap: versión 1 y código GET.
        assert_eq!(
            protocolo(L4::Udp, (50000, 5683), &[0x40, 0x01, 0x00, 0x01], &[]),
            Some(AppProtocol::Coap)
        );

        // rtsp.
        assert_eq!(
            protocolo(
                L4::Tcp,
                (50000, 554),
                b"OPTIONS rtsp://cam/ RTSP/1.0\r\n\r\n",
                &[]
            ),
            Some(AppProtocol::Rtsp)
        );

        // sip.
        assert_eq!(
            protocolo(
                L4::Udp,
                (50000, 5060),
                b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n",
                &[]
            ),
            Some(AppProtocol::Sip)
        );

        // stun: cookie mágica en los bytes 4-7.
        let mut stun = vec![0u8; 20];
        stun[0] = 0x00;
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(
            protocolo(L4::Udp, (50000, 3478), &stun, &[]),
            Some(AppProtocol::Stun)
        );

        // wireguard: tipo 1 con 3 bytes reservados a cero y 148 bytes.
        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        assert_eq!(
            protocolo(L4::Udp, (50000, 51820), &wg, &[]),
            Some(AppProtocol::Wireguard)
        );

        // openvpn: P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7).
        let ovpn = vec![7 << 3; 20];
        assert_eq!(
            protocolo(L4::Udp, (50000, 1194), &ovpn, &[]),
            Some(AppProtocol::Openvpn)
        );

        // ipsec: cabecera IKEv2 con versión 0x20.
        let mut ike = vec![0u8; 28];
        ike[17] = 0x20;
        assert_eq!(
            protocolo(L4::Udp, (50000, 500), &ike, &[]),
            Some(AppProtocol::Ipsec)
        );

        // bittorrent: handshake y DHT.
        assert_eq!(
            protocolo(L4::Tcp, (50000, 6881), b"\x13BitTorrent protocol", &[]),
            Some(AppProtocol::Bittorrent)
        );
        assert_eq!(
            protocolo(L4::Udp, (50000, 6881), b"d1:ad2:id20:", &[]),
            Some(AppProtocol::Bittorrent)
        );

        // snmp: BER SEQUENCE con versión 0.
        assert_eq!(
            protocolo(
                L4::Udp,
                (50000, 161),
                &[0x30, 0x05, 0x02, 0x01, 0x00, 0x04, 0x00],
                &[]
            ),
            Some(AppProtocol::Snmp)
        );
    }

    #[test]
    fn una_firma_gana_al_puerto() {
        let ssh = b"SSH-2.0-OpenSSH_9.6\r\n";
        assert_eq!(
            identify(L4::Tcp, (50000, 443), ssh, &[]),
            Some((AppProtocol::Ssh, Certainty::Signature))
        );
        assert_eq!(
            identify(L4::Tcp, (50000, 21), b"GET / HTTP/1.1\r\n\r\n", &[]),
            Some((AppProtocol::Http, Certainty::Signature))
        );
    }

    #[test]
    fn sin_firma_usa_el_puerto_provisional() {
        assert_eq!(
            identify(L4::Tcp, (50000, 21), &[], &[]),
            Some((AppProtocol::Ftp, Certainty::Port))
        );
        assert_eq!(
            identify(L4::Tcp, (50000, 443), &[], &[]),
            Some((AppProtocol::Tls, Certainty::Port))
        );
        assert_eq!(
            identify(L4::Udp, (50000, 53), &[], &[]),
            Some((AppProtocol::Dns, Certainty::Port))
        );
        assert_eq!(identify(L4::Tcp, (50000, 50001), &[], &[]), None);
        assert_eq!(identify(L4::Udp, (50000, 50001), &[], &[]), None);
    }

    #[test]
    fn los_puertos_de_servicio_y_efimeros_se_clasifican_bien() {
        for puerto in [21, 22, 53, 80, 443, 1023, 3389, 5353, 5683, 5900, 5909] {
            assert!(is_service_port(puerto), "{puerto}");
        }
        for puerto in [1024, 5000, 5910, 32767, 50000] {
            assert!(!is_service_port(puerto), "{puerto}");
        }
        assert!(!is_ephemeral(32767));
        assert!(is_ephemeral(32768));
        assert!(is_ephemeral(65535));
    }

    #[test]
    fn asigna_protocolos_provisionales_por_puerto() {
        assert_eq!(protocol_for_port(L4::Tcp, 22), Some(AppProtocol::Ssh));
        assert_eq!(protocol_for_port(L4::Tcp, 443), Some(AppProtocol::Tls));
        assert_eq!(protocol_for_port(L4::Tcp, 80), Some(AppProtocol::Http));
        assert_eq!(protocol_for_port(L4::Tcp, 3389), Some(AppProtocol::Rdp));
        assert_eq!(protocol_for_port(L4::Tcp, 5901), Some(AppProtocol::Vnc));
        assert_eq!(protocol_for_port(L4::Udp, 53), Some(AppProtocol::Dns));
        assert_eq!(protocol_for_port(L4::Udp, 5353), Some(AppProtocol::Mdns));
        assert_eq!(protocol_for_port(L4::Udp, 123), Some(AppProtocol::Ntp));
        assert_eq!(protocol_for_port(L4::Tcp, 5353), None);
        assert_eq!(protocol_for_port(L4::Udp, 443), None);
        assert_eq!(protocol_for_port(L4::Tcp, 50000), None);
    }

    #[test]
    fn no_hace_panic_con_datos_aleatorios() {
        for semilla in 0u32..256 {
            let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(13);
            let longitud = (semilla % 80) as usize;
            let mut c2s = Vec::with_capacity(longitud);
            for _ in 0..longitud {
                estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                c2s.push((estado >> 24) as u8);
            }
            let s2c = c2s.clone();
            let puerto_origen = (semilla % 65536) as u16;
            let puerto_destino = ((semilla * 7) % 65536) as u16;
            let _ = identify(L4::Tcp, (puerto_origen, puerto_destino), &c2s, &s2c);
            let _ = identify(L4::Udp, (puerto_origen, puerto_destino), &c2s, &s2c);
        }
    }
}
