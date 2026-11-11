//! Consultas y respuestas DNS (§7.7). Sustituye a capture/dns.rs de la Fase 3.
//!
//! El parseo se delega en hickory-proto, que ya resuelve la compresión de nombres
//! y tolera mensajes mal formados sin pánicos. De todo el mensaje solo salen de
//! este módulo el QNAME consultado y las observaciones IP → nombre consultado.

use std::net::IpAddr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};

use crate::inference::{NameObservation, NameSource};

/// Longitud de la cabecera fija de un mensaje DNS.
const CABECERA_DNS: usize = 12;

/// Consulta DNS observada.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsQuery {
    /// Nombre consultado, normalizado.
    pub qname: String,
    /// Tipo de registro (1 = A, 28 = AAAA, 5 = CNAME…).
    pub qtype: u16,
}

/// Extrae la primera pregunta de una consulta DNS.
pub fn extract_query(data: &[u8]) -> Option<DnsQuery> {
    let mensaje = parsear(data)?;
    if mensaje.metadata.message_type != MessageType::Query
        || mensaje.metadata.op_code != OpCode::Query
    {
        return None;
    }
    let pregunta = mensaje.queries.first()?;
    let qname = normalize_name(&pregunta.name().to_utf8())?;
    Some(DnsQuery {
        qname,
        qtype: u16::from(pregunta.query_type()),
    })
}

/// Convierte una respuesta DNS en observaciones IP → nombre consultado.
///
/// Solo respuestas QR=1, rcode=0 y no truncadas; asocia cada registro A o AAAA
/// al nombre de la primera pregunta (aunque llegue tras una cadena CNAME).
pub fn extract_answers(data: &[u8], client: IpAddr) -> Vec<NameObservation> {
    let Some(mensaje) = parsear(data) else {
        return Vec::new();
    };
    if mensaje.metadata.message_type != MessageType::Response
        || mensaje.metadata.response_code != ResponseCode::NoError
        || mensaje.metadata.truncation
    {
        return Vec::new();
    }
    let Some(pregunta) = mensaje.queries.first() else {
        return Vec::new();
    };
    let Some(nombre) = normalize_name(&pregunta.name().to_utf8()) else {
        return Vec::new();
    };
    let mut observaciones = Vec::new();
    for registro in &mensaje.answers {
        if let Some(ip) = registro.data.ip_addr() {
            observaciones.push(observacion(
                ip,
                nombre.clone(),
                client,
                Some(u64::from(registro.ttl)),
            ));
        }
    }
    observaciones
}

/// Parsea un mensaje DNS admitiendo el prefijo de longitud de DNS sobre TCP.
fn parsear(data: &[u8]) -> Option<Message> {
    if data.len() < CABECERA_DNS {
        return None;
    }
    // DNS sobre TCP: dos bytes de longitud al principio (RFC 1035 §4.2.2).
    if let Some(longitud) = longitud_tcp(data) {
        if longitud == data.len().saturating_sub(2) {
            if let Ok(mensaje) = Message::from_vec(&data[2..]) {
                return Some(mensaje);
            }
        }
    }
    if let Ok(mensaje) = Message::from_vec(data) {
        return Some(mensaje);
    }
    if let Some(longitud) = longitud_tcp(data) {
        let fin = 2usize.checked_add(longitud)?;
        if let Ok(mensaje) = Message::from_vec(data.get(2..fin)?) {
            return Some(mensaje);
        }
    }
    None
}

/// Longitud declarada por el prefijo de DNS sobre TCP, si es plausible.
fn longitud_tcp(data: &[u8]) -> Option<usize> {
    let cabecera = data.get(0..2)?;
    let longitud = usize::from(u16::from_be_bytes([cabecera[0], cabecera[1]]));
    if longitud == 0 || data.len() < 2 + longitud {
        return None;
    }
    Some(longitud)
}

/// Normaliza un nombre DNS (minúsculas, sin punto final, máx. 255).
pub fn normalize_name(name: &str) -> Option<String> {
    let limpio = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if limpio.is_empty() || limpio.len() > 255 {
        return None;
    }
    Some(limpio)
}

/// Observaciones de una respuesta sin equipo cliente conocido.
pub fn answers_for(data: &[u8]) -> Vec<NameObservation> {
    extract_answers(data, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

/// Nombre de la primera pregunta de una respuesta (para server_name por caché).
pub fn first_question(data: &[u8]) -> Option<String> {
    let mensaje = parsear(data)?;
    let pregunta = mensaje.queries.first()?;
    normalize_name(&pregunta.name().to_utf8())
}

/// Construye la observación IP → nombre de una respuesta.
fn observacion(ip: IpAddr, name: String, client: IpAddr, ttl: Option<u64>) -> NameObservation {
    NameObservation {
        ip,
        name,
        source: NameSource::Dns,
        requester: if client.is_unspecified() {
            None
        } else {
            Some(client)
        },
        ttl_seconds: ttl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::domain::Name;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use hickory_proto::rr::{RData, Record, RecordType};
    use std::net::Ipv4Addr;

    fn nombre(valor: &str) -> Name {
        Name::from_ascii(valor).expect("nombre DNS válido")
    }

    fn consulta(qname: &str, qtype: RecordType) -> Vec<u8> {
        let mut mensaje = Message::query();
        mensaje.metadata.id = 0x1234;
        mensaje.add_query(Query::query(nombre(qname), qtype));
        mensaje.to_vec().expect("serializar consulta")
    }

    fn mensaje_respuesta(qname: &str, qtype: RecordType, respuestas: Vec<Record>) -> Message {
        let mut mensaje = Message::query();
        mensaje.metadata.id = 0x5678;
        mensaje.metadata.message_type = MessageType::Response;
        mensaje.add_query(Query::query(nombre(qname), qtype));
        for registro in respuestas {
            mensaje.add_answer(registro);
        }
        mensaje
    }

    fn respuesta(qname: &str, qtype: RecordType, respuestas: Vec<Record>) -> Vec<u8> {
        mensaje_respuesta(qname, qtype, respuestas)
            .to_vec()
            .expect("serializar respuesta")
    }

    fn registro_a(propietario: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(nombre(propietario), ttl, RData::A(A(ip)))
    }

    fn registro_aaaa(propietario: &str, ip: std::net::Ipv6Addr, ttl: u32) -> Record {
        Record::from_rdata(nombre(propietario), ttl, RData::AAAA(AAAA(ip)))
    }

    fn registro_cname(propietario: &str, destino: &str, ttl: u32) -> Record {
        Record::from_rdata(
            nombre(propietario),
            ttl,
            RData::CNAME(CNAME(nombre(destino))),
        )
    }

    fn con_prefijo_tcp(mensaje: &[u8]) -> Vec<u8> {
        let mut datos = (mensaje.len() as u16).to_be_bytes().to_vec();
        datos.extend_from_slice(mensaje);
        datos
    }

    #[test]
    fn extrae_la_primera_pregunta_normalizada() {
        let consulta = consulta("WWW.Example.COM.", RecordType::A);
        let extraida = extract_query(&consulta).expect("consulta DNS A");
        assert_eq!(extraida.qname, "www.example.com");
        assert_eq!(extraida.qtype, 1);
    }

    #[test]
    fn extrae_el_tipo_de_pregunta_aaaa() {
        let consulta = consulta("ipv6.example.com.", RecordType::AAAA);
        let extraida = extract_query(&consulta).expect("consulta DNS AAAA");
        assert_eq!(extraida.qname, "ipv6.example.com");
        assert_eq!(extraida.qtype, 28);
    }

    #[test]
    fn descarta_las_respuestas_como_consulta() {
        let respuesta = respuesta(
            "example.com.",
            RecordType::A,
            vec![registro_a(
                "example.com.",
                Ipv4Addr::new(93, 184, 216, 34),
                60,
            )],
        );
        assert_eq!(extract_query(&respuesta), None);
    }

    #[test]
    fn descarta_las_consultas_sin_preguntas() {
        let dos_mensajes = Message::query().to_vec().expect("serializar mensaje vacío");
        assert_eq!(extract_query(&dos_mensajes), None);
    }

    #[test]
    fn respuesta_con_cname_asocia_las_ips_al_nombre_consultado() {
        let cliente: IpAddr = "192.168.1.10".parse().expect("IP válida");
        let respuesta = respuesta(
            "www.example.com.",
            RecordType::A,
            vec![
                registro_cname("www.example.com.", "cdn.example.net.", 300),
                registro_a("cdn.example.net.", Ipv4Addr::new(93, 184, 216, 34), 300),
                registro_aaaa(
                    "cdn.example.net.",
                    "2606:2800:220:1:248:1893:25c8:1946"
                        .parse()
                        .expect("IPv6 válida"),
                    300,
                ),
            ],
        );
        let observaciones = extract_answers(&respuesta, cliente);
        assert_eq!(observaciones.len(), 2);
        for observacion in &observaciones {
            assert_eq!(observacion.name, "www.example.com");
            assert_eq!(observacion.source, NameSource::Dns);
            assert_eq!(observacion.requester, Some(cliente));
            assert_eq!(observacion.ttl_seconds, Some(300));
        }
        assert_eq!(
            observaciones[0].ip,
            "93.184.216.34".parse::<IpAddr>().expect("IP válida")
        );
        assert!(matches!(observaciones[1].ip, IpAddr::V6(_)));
    }

    #[test]
    fn descarta_respuestas_con_codigo_de_error() {
        let mut mensaje = mensaje_respuesta(
            "noexiste.example.com.",
            RecordType::A,
            vec![registro_a(
                "noexiste.example.com.",
                Ipv4Addr::new(1, 2, 3, 4),
                60,
            )],
        );
        mensaje.metadata.response_code = ResponseCode::NXDomain;
        let datos = mensaje.to_vec().expect("serializar respuesta");
        assert!(extract_answers(&datos, IpAddr::V4(Ipv4Addr::UNSPECIFIED)).is_empty());
    }

    #[test]
    fn descarta_respuestas_truncadas() {
        let mut mensaje = mensaje_respuesta(
            "example.com.",
            RecordType::A,
            vec![registro_a("example.com.", Ipv4Addr::new(1, 2, 3, 4), 60)],
        );
        mensaje.metadata.truncation = true;
        let datos = mensaje.to_vec().expect("serializar respuesta");
        assert!(extract_answers(&datos, IpAddr::V4(Ipv4Addr::UNSPECIFIED)).is_empty());
    }

    #[test]
    fn descarta_las_consultas_en_extract_answers() {
        let consulta = consulta("example.com.", RecordType::A);
        assert!(extract_answers(&consulta, IpAddr::V4(Ipv4Addr::UNSPECIFIED)).is_empty());
    }

    #[test]
    fn una_respuesta_solo_con_cname_no_da_observaciones() {
        let respuesta = respuesta(
            "alias.example.com.",
            RecordType::CNAME,
            vec![registro_cname(
                "alias.example.com.",
                "real.example.com.",
                60,
            )],
        );
        assert!(extract_answers(&respuesta, IpAddr::V4(Ipv4Addr::UNSPECIFIED)).is_empty());
    }

    #[test]
    fn extrae_el_nombre_de_la_primera_pregunta() {
        let respuesta = respuesta(
            "www.example.com.",
            RecordType::A,
            vec![registro_a(
                "www.example.com.",
                Ipv4Addr::new(93, 184, 216, 34),
                60,
            )],
        );
        assert_eq!(
            first_question(&respuesta).as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn acepta_dns_sobre_tcp_con_prefijo_de_longitud() {
        let consulta = con_prefijo_tcp(&consulta("tcp.example.com.", RecordType::A));
        assert_eq!(
            extract_query(&consulta).map(|extraida| extraida.qname),
            Some("tcp.example.com".to_string())
        );

        let respuesta = con_prefijo_tcp(&respuesta(
            "tcp.example.com.",
            RecordType::A,
            vec![registro_a(
                "tcp.example.com.",
                Ipv4Addr::new(203, 0, 113, 7),
                120,
            )],
        ));
        let observaciones = extract_answers(&respuesta, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(observaciones.len(), 1);
        assert_eq!(
            observaciones[0].ip,
            "203.0.113.7".parse::<IpAddr>().expect("IP válida")
        );
    }

    #[test]
    fn sin_cliente_conocido_la_observacion_no_tiene_requester() {
        let datos = respuesta(
            "example.com.",
            RecordType::A,
            vec![registro_a("example.com.", Ipv4Addr::new(1, 2, 3, 4), 60)],
        );
        let observaciones = answers_for(&datos);
        assert_eq!(observaciones.len(), 1);
        assert_eq!(observaciones[0].requester, None);
    }

    #[test]
    fn no_hace_panic_con_entradas_truncadas_o_aleatorias() {
        let consulta = consulta("example.com.", RecordType::A);
        let respuesta = respuesta(
            "www.example.com.",
            RecordType::A,
            vec![
                registro_cname("www.example.com.", "cdn.example.net.", 60),
                registro_a("cdn.example.net.", Ipv4Addr::new(93, 184, 216, 34), 60),
            ],
        );
        for datos in [consulta, respuesta] {
            for longitud in 0..datos.len() {
                let trozo = &datos[..longitud];
                let _ = extract_query(trozo);
                let _ = extract_answers(trozo, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let _ = first_question(trozo);
            }
        }
        for semilla in 0u32..128 {
            let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(3);
            let longitud = (semilla % 64) as usize;
            let mut datos = Vec::with_capacity(longitud);
            for _ in 0..longitud {
                estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                datos.push((estado >> 24) as u8);
            }
            let _ = extract_query(&datos);
            let _ = extract_answers(&datos, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let _ = first_question(&datos);
        }
    }

    #[test]
    fn normaliza_los_nombres_dns() {
        assert_eq!(
            normalize_name("WWW.Example.COM.").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            normalize_name("  example.com  ").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_name("."), None);
        assert_eq!(normalize_name(""), None);
        assert_eq!(normalize_name(&"a".repeat(256)), None);
    }
}
