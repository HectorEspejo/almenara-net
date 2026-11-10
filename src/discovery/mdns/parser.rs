//! Parser de respuestas mDNS/DNS-SD.
//!
//! Convierte un datagrama DNS completo (normalmente una respuesta multicast de
//! mDNS) en una lista de [MdnsRecord]: una vista normalizada por equipo con su
//! IP, hostname, servicios anunciados y sistema operativo declarado.
//!
//! Solo se tienen en cuenta los registros A, AAAA, PTR, SRV, TXT y HINFO; el
//! resto se ignora sin error.
//!
//! Decisiones:
//! - De los AAAA solo se aprovecha el nombre del propietario: la Fase 2 asocia
//!   equipos por IPv4, así que no se guarda la dirección IPv6.
//! - Un paquete mDNS puede anunciar varios equipos; los registros se agrupan por
//!   hostname (A/AAAA/HINFO) y por instancia de servicio (PTR/SRV/TXT).
//! - Los tipos de servicio se normalizan a minúsculas (p. ej. "_HTTP._tcp" pasa
//!   a "_http._tcp") para que la clasificación sea estable.
//! - Los nombres DNS se leen etiqueta a etiqueta (sin la representación escapada
//!   de `Display`), de modo que los nombres de instancia con espacios se
//!   conservan tal cual.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData};

use crate::error::{Error, Result};

/// Servicio anunciado por mDNS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsService {
    /// Tipo de servicio, p. ej. "_http._tcp" (sin el sufijo .local.).
    pub service_type: String,
    /// Nombre de la instancia anunciada.
    pub name: Option<String>,
    /// Puerto del registro SRV.
    pub port: Option<u16>,
    /// Pares clave/valor del registro TXT.
    pub txt: Vec<(String, String)>,
}

/// Registro mDNS normalizado y asociado a un equipo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsRecord {
    /// IPv4 del registro A (los AAAA se ignoran en Fase 2).
    pub ip: Option<Ipv4Addr>,
    /// Hostname .local sin sufijo.
    pub hostname: Option<String>,
    /// Servicios anunciados.
    pub services: Vec<MdnsService>,
    /// Sistema operativo declarado por HINFO, si lo hay.
    pub hinfo_os: Option<String>,
}

/// Acumulador de los datos de un equipo dentro del paquete.
#[derive(Debug, Default)]
struct AcumuladorHost {
    ip: Option<Ipv4Addr>,
    hinfo_os: Option<String>,
}

/// Acumulador de una instancia de servicio dentro del paquete.
#[derive(Debug, Default)]
struct AcumuladorServicio {
    service_type: String,
    name: Option<String>,
    port: Option<u16>,
    txt: Vec<(String, String)>,
    target: Option<String>,
}

/// Parsea un paquete mDNS y extrae los registros A, AAAA, PTR, SRV, TXT y HINFO.
pub fn parse(packet: &[u8]) -> Result<Vec<MdnsRecord>> {
    let mensaje = Message::from_vec(packet)
        .map_err(|err| Error::Scan(format!("paquete mDNS inválido: {err}")))?;

    let mut orden_hosts: Vec<String> = Vec::new();
    let mut hosts: HashMap<String, AcumuladorHost> = HashMap::new();
    let mut orden_servicios: Vec<String> = Vec::new();
    let mut servicios: HashMap<String, AcumuladorServicio> = HashMap::new();
    let mut tipos_servicio: Vec<String> = Vec::new();

    let registros = mensaje
        .answers
        .iter()
        .chain(mensaje.authorities.iter())
        .chain(mensaje.additionals.iter());

    for registro in registros {
        let etiquetas_dueno = etiquetas_de(&registro.name);
        match &registro.data {
            RData::A(direccion) => {
                let Some(host) = normalize_hostname(&etiquetas_dueno.join(".")) else {
                    continue;
                };
                let acumulador = acumular_host(&mut hosts, &mut orden_hosts, &host);
                if acumulador.ip.is_none() {
                    acumulador.ip = Some(direccion.0);
                }
            }
            RData::AAAA(_) => {
                // Solo interesa el hostname: la Fase 2 no persiste IPv6.
                if let Some(host) = normalize_hostname(&etiquetas_dueno.join(".")) {
                    let _ = acumular_host(&mut hosts, &mut orden_hosts, &host);
                }
            }
            RData::HINFO(info) => {
                let Some(host) = normalize_hostname(&etiquetas_dueno.join(".")) else {
                    continue;
                };
                let sistema = texto_utf8(&info.os);
                let acumulador = acumular_host(&mut hosts, &mut orden_hosts, &host);
                if acumulador.hinfo_os.is_none() {
                    acumulador.hinfo_os = sistema;
                }
            }
            RData::PTR(destino) => {
                let etiquetas_destino = etiquetas_de(&destino.0);
                if es_consulta_de_servicios(&etiquetas_dueno) {
                    // Los PTR de _services._dns-sd._udp enumeran tipos de servicio.
                    if let Some(tipo) = tipo_servicio(&etiquetas_destino) {
                        if !tipos_servicio.contains(&tipo) {
                            tipos_servicio.push(tipo);
                        }
                    }
                    continue;
                }
                if !es_nombre_de_tipo_de_servicio(&etiquetas_dueno) {
                    // PTR de alias de host: no aporta servicios ni hostname.
                    continue;
                }
                let Some((tipo, Some(instancia))) = descomponer_servicio(&etiquetas_destino) else {
                    continue;
                };
                let clave = clave_instancia(&etiquetas_destino);
                let acumulador = acumular_servicio(&mut servicios, &mut orden_servicios, &clave);
                if acumulador.service_type.is_empty() {
                    acumulador.service_type = tipo;
                }
                if acumulador.name.is_none() {
                    acumulador.name = Some(instancia);
                }
            }
            RData::SRV(srv) => {
                let Some((tipo, instancia)) = descomponer_servicio(&etiquetas_dueno) else {
                    continue;
                };
                let target = normalize_hostname(&etiquetas_de(&srv.target).join("."));
                let clave = clave_instancia(&etiquetas_dueno);
                let acumulador = acumular_servicio(&mut servicios, &mut orden_servicios, &clave);
                if acumulador.service_type.is_empty() {
                    acumulador.service_type = tipo;
                }
                if acumulador.name.is_none() {
                    acumulador.name = instancia;
                }
                acumulador.port = Some(srv.port);
                acumulador.target = target;
            }
            RData::TXT(txt) => {
                let Some((tipo, instancia)) = descomponer_servicio(&etiquetas_dueno) else {
                    continue;
                };
                let pares: Vec<(String, String)> = txt
                    .txt_data
                    .iter()
                    .filter_map(|trozo| parse_txt(trozo))
                    .collect();
                let clave = clave_instancia(&etiquetas_dueno);
                let acumulador = acumular_servicio(&mut servicios, &mut orden_servicios, &clave);
                if acumulador.service_type.is_empty() {
                    acumulador.service_type = tipo;
                }
                if acumulador.name.is_none() {
                    acumulador.name = instancia;
                }
                acumulador.txt = pares;
            }
            // Cualquier otro tipo de registro (CNAME, NSEC, OPT...) se ignora.
            _ => {}
        }
    }

    Ok(construir_registros(
        &orden_hosts,
        &hosts,
        &orden_servicios,
        &servicios,
        &tipos_servicio,
    ))
}

/// Normaliza un nombre mDNS: quita el punto final y el sufijo .local.
pub fn normalize_hostname(name: &str) -> Option<String> {
    let sin_puntos = name.trim().trim_end_matches('.');
    if sin_puntos.is_empty() {
        return None;
    }
    let host = match sin_puntos.get(sin_puntos.len().saturating_sub(6)..) {
        Some(sufijo) if sufijo.eq_ignore_ascii_case(".local") => {
            sin_puntos[..sin_puntos.len() - 6].trim_end_matches('.')
        }
        _ => sin_puntos,
    };
    if host.is_empty() || host.contains('\0') {
        None
    } else {
        Some(host.to_string())
    }
}

/// Construye la salida final agrupada por equipo e instancia.
fn construir_registros(
    orden_hosts: &[String],
    hosts: &HashMap<String, AcumuladorHost>,
    orden_servicios: &[String],
    servicios: &HashMap<String, AcumuladorServicio>,
    tipos_servicio: &[String],
) -> Vec<MdnsRecord> {
    let mut salida = Vec::new();

    // Un registro por hostname descubierto (A/AAAA/HINFO), con sus servicios.
    for host in orden_hosts {
        let Some(acumulador) = hosts.get(host) else {
            continue;
        };
        let anunciados = orden_servicios
            .iter()
            .filter_map(|clave| servicios.get(clave))
            .filter(|servicio| {
                servicio
                    .target
                    .as_deref()
                    .is_some_and(|target| target.eq_ignore_ascii_case(host))
            })
            .map(servicio_publico)
            .collect();
        salida.push(MdnsRecord {
            ip: acumulador.ip,
            hostname: Some(host.clone()),
            services: anunciados,
            hinfo_os: acumulador.hinfo_os.clone(),
        });
    }

    // Instancias cuyo host no viene en este paquete: se mantiene el hostname
    // declarado por el SRV para poder asociarlas después por otra fuente.
    for clave in orden_servicios {
        let Some(servicio) = servicios.get(clave) else {
            continue;
        };
        match &servicio.target {
            // Los nombres DNS no distinguen mayúsculas: se compara sin ellas.
            Some(target)
                if hosts
                    .keys()
                    .any(|existente| existente.eq_ignore_ascii_case(target)) => {}
            Some(target) => salida.push(MdnsRecord {
                ip: None,
                hostname: Some(target.clone()),
                services: vec![servicio_publico(servicio)],
                hinfo_os: None,
            }),
            None => salida.push(MdnsRecord {
                ip: None,
                hostname: None,
                services: vec![servicio_publico(servicio)],
                hinfo_os: None,
            }),
        }
    }

    // Enumeración de tipos de servicio anunciados.
    if !tipos_servicio.is_empty() {
        salida.push(MdnsRecord {
            ip: None,
            hostname: None,
            services: tipos_servicio
                .iter()
                .map(|tipo| MdnsService {
                    service_type: tipo.clone(),
                    ..MdnsService::default()
                })
                .collect(),
            hinfo_os: None,
        });
    }

    salida
}

/// Convierte el acumulador interno en el servicio público.
fn servicio_publico(acumulador: &AcumuladorServicio) -> MdnsService {
    MdnsService {
        service_type: acumulador.service_type.clone(),
        name: acumulador.name.clone(),
        port: acumulador.port,
        txt: acumulador.txt.clone(),
    }
}

/// Obtiene (o crea) el acumulador de un hostname, respetando el orden de llegada.
fn acumular_host<'a>(
    hosts: &'a mut HashMap<String, AcumuladorHost>,
    orden: &mut Vec<String>,
    host: &str,
) -> &'a mut AcumuladorHost {
    if !hosts.contains_key(host) {
        orden.push(host.to_string());
    }
    hosts.entry(host.to_string()).or_default()
}

/// Obtiene (o crea) el acumulador de una instancia de servicio.
fn acumular_servicio<'a>(
    servicios: &'a mut HashMap<String, AcumuladorServicio>,
    orden: &mut Vec<String>,
    clave: &str,
) -> &'a mut AcumuladorServicio {
    if !servicios.contains_key(clave) {
        orden.push(clave.to_string());
    }
    servicios.entry(clave.to_string()).or_default()
}

/// Convierte el nombre de un registro en sus etiquetas ya decodificadas.
fn etiquetas_de(nombre: &Name) -> Vec<String> {
    nombre
        .iter()
        .map(|etiqueta| String::from_utf8_lossy(etiqueta).into_owned())
        .collect()
}

/// Clave de una instancia: su nombre completo sin el sufijo .local.
fn clave_instancia(etiquetas: &[String]) -> String {
    match etiquetas.last() {
        Some(ultima) if ultima.eq_ignore_ascii_case("local") => {
            etiquetas[..etiquetas.len() - 1].join(".")
        }
        _ => etiquetas.join("."),
    }
}

/// Índice de la etiqueta de protocolo (_tcp/_udp) más a la derecha.
fn indice_protocolo(etiquetas: &[String]) -> Option<usize> {
    etiquetas
        .iter()
        .rposition(|etiqueta| es_protocolo(etiqueta))
}

/// Indica si una etiqueta es un protocolo DNS-SD.
fn es_protocolo(etiqueta: &str) -> bool {
    etiqueta.eq_ignore_ascii_case("_tcp") || etiqueta.eq_ignore_ascii_case("_udp")
}

/// Tipo de servicio canónico de un nombre DNS-SD (p. ej. "_ipp._tcp").
fn tipo_servicio(etiquetas: &[String]) -> Option<String> {
    let indice = indice_protocolo(etiquetas)?;
    if indice == 0 || !etiquetas[indice - 1].starts_with('_') {
        return None;
    }
    Some(format!(
        "{}.{}",
        etiquetas[indice - 1].to_ascii_lowercase(),
        etiquetas[indice].to_ascii_lowercase()
    ))
}

/// Descompone "Instancia._ipp._tcp.local." en tipo de servicio e instancia.
fn descomponer_servicio(etiquetas: &[String]) -> Option<(String, Option<String>)> {
    let indice = indice_protocolo(etiquetas)?;
    let tipo = tipo_servicio(etiquetas)?;
    let instancia = if indice > 1 {
        Some(etiquetas[..indice - 1].join("."))
    } else {
        None
    };
    Some((tipo, instancia))
}

/// Indica si un nombre es un tipo de servicio (posiblemente con subtipos).
fn es_nombre_de_tipo_de_servicio(etiquetas: &[String]) -> bool {
    let Some(indice) = indice_protocolo(etiquetas) else {
        return false;
    };
    if indice == 0 || !etiquetas[indice - 1].starts_with('_') {
        return false;
    }
    // Si hay etiquetas antes del servicio solo pueden ser subtipos (_printer._sub).
    etiquetas[..indice - 1]
        .iter()
        .all(|etiqueta| etiqueta.starts_with('_'))
}

/// Indica si el nombre es el de la consulta de enumeración de servicios.
fn es_consulta_de_servicios(etiquetas: &[String]) -> bool {
    let nombre = etiquetas.join(".");
    nombre.eq_ignore_ascii_case("_services._dns-sd._udp")
        || nombre.eq_ignore_ascii_case("_services._dns-sd._udp.local")
}

/// Decodifica un trozo de TXT como par clave/valor.
fn parse_txt(trozo: &[u8]) -> Option<(String, String)> {
    let texto = String::from_utf8_lossy(trozo);
    let texto = texto.trim_matches('\0').trim();
    if texto.is_empty() {
        return None;
    }
    match texto.split_once('=') {
        Some((clave, valor)) => Some((clave.trim().to_string(), valor.trim().to_string())),
        None => Some((texto.to_string(), String::new())),
    }
}

/// Convierte bytes de un HINFO en texto UTF-8 recortado.
fn texto_utf8(bytes: &[u8]) -> Option<String> {
    let texto = String::from_utf8_lossy(bytes);
    let texto = texto.trim();
    if texto.is_empty() {
        None
    } else {
        Some(texto.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, HINFO, PTR, SRV, TXT};
    use hickory_proto::rr::Record;

    fn nombre(texto: &str) -> Name {
        Name::from_ascii(texto).expect("nombre DNS de prueba válido")
    }

    fn registro(propietario: &str, datos: RData) -> Record {
        Record::from_rdata(nombre(propietario), 120, datos)
    }

    fn respuesta() -> Message {
        Message::new(0, MessageType::Response, OpCode::Query)
    }

    fn serializar(mensaje: &Message) -> Vec<u8> {
        mensaje.to_vec().expect("paquete mDNS serializable")
    }

    #[test]
    fn agrupa_host_con_su_servicio() {
        let mut mensaje = respuesta();
        mensaje.add_answer(registro(
            "_ipp._tcp.local.",
            RData::PTR(PTR(nombre("Impresora._ipp._tcp.local."))),
        ));
        mensaje.add_answer(registro(
            "Impresora._ipp._tcp.local.",
            RData::SRV(SRV::new(0, 0, 631, nombre("Impresora.local."))),
        ));
        mensaje.add_answer(registro(
            "Impresora._ipp._tcp.local.",
            RData::TXT(TXT::new(vec![
                "rp=print".to_string(),
                "ty=HP LaserJet".to_string(),
                "sinvalor".to_string(),
            ])),
        ));
        mensaje.add_additional(registro(
            "Impresora.local.",
            RData::A(A::new(192, 168, 1, 20)),
        ));
        mensaje.add_additional(registro(
            "Impresora.local.",
            RData::HINFO(HINFO::new("x86".to_string(), "Linux".to_string())),
        ));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        let equipo = &salida[0];
        assert_eq!(equipo.ip, Some(Ipv4Addr::new(192, 168, 1, 20)));
        assert_eq!(equipo.hostname.as_deref(), Some("Impresora"));
        assert_eq!(equipo.hinfo_os.as_deref(), Some("Linux"));
        assert_eq!(equipo.services.len(), 1);
        let servicio = &equipo.services[0];
        assert_eq!(servicio.service_type, "_ipp._tcp");
        assert_eq!(servicio.name.as_deref(), Some("Impresora"));
        assert_eq!(servicio.port, Some(631));
        assert_eq!(
            servicio.txt,
            vec![
                ("rp".to_string(), "print".to_string()),
                ("ty".to_string(), "HP LaserJet".to_string()),
                ("sinvalor".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn agrupa_varios_equipos_en_el_mismo_paquete() {
        let mut mensaje = respuesta();
        // El A llega en la sección adicional y el SRV antes: el orden no importa.
        mensaje.add_answer(registro(
            "Sala._airplay._tcp.local.",
            RData::SRV(SRV::new(0, 0, 7000, nombre("salon.local."))),
        ));
        mensaje.add_answer(registro(
            "Sala._airplay._tcp.local.",
            RData::TXT(TXT::new(vec!["model=AppleTV6,2".to_string()])),
        ));
        mensaje.add_additional(registro("salon.local.", RData::A(A::new(192, 168, 1, 30))));
        mensaje.add_additional(registro(
            "_googlecast._tcp.local.",
            RData::PTR(PTR(nombre("TV._googlecast._tcp.local."))),
        ));
        mensaje.add_additional(registro(
            "TV._googlecast._tcp.local.",
            RData::SRV(SRV::new(0, 0, 8009, nombre("tv.local."))),
        ));
        mensaje.add_additional(registro("tv.local.", RData::A(A::new(192, 168, 1, 31))));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 2);
        let salon = salida
            .iter()
            .find(|registro| registro.ip == Some(Ipv4Addr::new(192, 168, 1, 30)))
            .expect("equipo del salón");
        assert_eq!(salon.hostname.as_deref(), Some("salon"));
        assert_eq!(salon.services[0].service_type, "_airplay._tcp");
        assert_eq!(salon.services[0].port, Some(7000));
        let tele = salida
            .iter()
            .find(|registro| registro.ip == Some(Ipv4Addr::new(192, 168, 1, 31)))
            .expect("televisor");
        assert_eq!(tele.hostname.as_deref(), Some("tv"));
        assert_eq!(tele.services[0].service_type, "_googlecast._tcp");
    }

    #[test]
    fn extrae_los_tipos_de_servicio_de_la_especificacion() {
        let mut mensaje = respuesta();
        let tipos = [
            "_http._tcp",
            "_ipp._tcp",
            "_airplay._tcp",
            "_googlecast._tcp",
            "_raop._tcp",
            "_device-info._tcp",
        ];
        for tipo in tipos {
            mensaje.add_answer(registro(
                "_services._dns-sd._udp.local.",
                RData::PTR(PTR(nombre(&format!("{tipo}.local.")))),
            ));
        }

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        let vistas: Vec<&str> = salida[0]
            .services
            .iter()
            .map(|servicio| servicio.service_type.as_str())
            .collect();
        assert_eq!(vistas, tipos);
    }

    #[test]
    fn enumera_tipos_de_servicio() {
        let mut mensaje = respuesta();
        mensaje.add_answer(registro(
            "_services._dns-sd._udp.local.",
            RData::PTR(PTR(nombre("_http._tcp.local."))),
        ));
        mensaje.add_answer(registro(
            "_services._dns-sd._udp.local.",
            RData::PTR(PTR(nombre("_airplay._tcp.local."))),
        ));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        let tipos: Vec<&str> = salida[0]
            .services
            .iter()
            .map(|servicio| servicio.service_type.as_str())
            .collect();
        assert_eq!(tipos, vec!["_http._tcp", "_airplay._tcp"]);
        assert!(salida[0]
            .services
            .iter()
            .all(|servicio| servicio.name.is_none()));
        assert!(salida[0].hostname.is_none());
        assert!(salida[0].ip.is_none());
    }

    #[test]
    fn normaliza_mayusculas_del_tipo_de_servicio() {
        let mut mensaje = respuesta();
        mensaje.add_answer(registro(
            "_HTTP._TCP.local.",
            RData::PTR(PTR(nombre("Web._HTTP._TCP.local."))),
        ));
        mensaje.add_answer(registro(
            "Web._HTTP._TCP.local.",
            RData::SRV(SRV::new(0, 0, 80, nombre("web.local."))),
        ));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        assert_eq!(salida[0].services[0].service_type, "_http._tcp");
    }

    #[test]
    fn instancia_sin_host_conocido_conserva_el_hostname_del_srv() {
        let mut mensaje = respuesta();
        mensaje.add_answer(registro(
            "Camara._rtsp._tcp.local.",
            RData::SRV(SRV::new(0, 0, 554, nombre("camara.local."))),
        ));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        assert_eq!(salida[0].hostname.as_deref(), Some("camara"));
        assert_eq!(salida[0].ip, None);
        assert_eq!(salida[0].services[0].port, Some(554));
    }

    #[test]
    fn asocia_servicios_aunque_el_hostname_cambie_de_mayusculas() {
        let mut mensaje = respuesta();
        mensaje.add_answer(registro(
            "NAS._smb._tcp.local.",
            RData::SRV(SRV::new(0, 0, 445, nombre("NAS.local."))),
        ));
        mensaje.add_additional(registro("nas.local.", RData::A(A::new(192, 168, 1, 90))));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        assert_eq!(salida[0].hostname.as_deref(), Some("nas"));
        assert_eq!(salida[0].services.len(), 1);
        assert_eq!(salida[0].services[0].service_type, "_smb._tcp");
    }

    #[test]
    fn registros_aaaa_descubren_hostname_sin_ip() {
        let mut mensaje = respuesta();
        mensaje.add_answer(registro(
            "v6.local.",
            RData::AAAA(AAAA::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        ));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        assert_eq!(salida[0].hostname.as_deref(), Some("v6"));
        assert_eq!(salida[0].ip, None);
    }

    #[test]
    fn ignora_registros_no_soportados() {
        let mut mensaje = respuesta();
        mensaje.add_answer(registro(
            "alias.local.",
            RData::CNAME(CNAME(nombre("real.local."))),
        ));
        mensaje.add_additional(registro("real.local.", RData::A(A::new(10, 0, 0, 7))));

        let salida = parse(&serializar(&mensaje)).expect("paquete válido");

        assert_eq!(salida.len(), 1);
        assert_eq!(salida[0].ip, Some(Ipv4Addr::new(10, 0, 0, 7)));
    }

    #[test]
    fn una_consulta_sin_respuestas_devuelve_vacio() {
        let mensaje = Message::new(0, MessageType::Query, OpCode::Query);
        assert!(parse(&serializar(&mensaje))
            .expect("paquete válido")
            .is_empty());
    }

    #[test]
    fn un_paquete_invalido_devuelve_error() {
        assert!(parse(b"esto no es dns").is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn normalize_hostname_recorta_punto_y_local() {
        assert_eq!(
            normalize_hostname("Impresora.local.").as_deref(),
            Some("Impresora")
        );
        assert_eq!(
            normalize_hostname("Impresora.local").as_deref(),
            Some("Impresora")
        );
        assert_eq!(
            normalize_hostname("impresora.").as_deref(),
            Some("impresora")
        );
        assert_eq!(
            normalize_hostname("  impresora  ").as_deref(),
            Some("impresora")
        );
        assert_eq!(normalize_hostname("").as_deref(), None);
        assert_eq!(normalize_hostname(".").as_deref(), None);
        assert_eq!(normalize_hostname("..").as_deref(), None);
        assert_eq!(normalize_hostname(".local").as_deref(), None);
    }
}
