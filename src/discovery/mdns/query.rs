//! Browse activo mDNS de _services._dns-sd._udp.local.
//!
//! El browse es en dos etapas: primero se enumeran los tipos de servicio
//! anunciados (PTR de _services._dns-sd._udp.local) y después se consulta cada
//! tipo para obtener las instancias (PTR de _<tipo>._tcp/_udp) con sus registros
//! SRV/TXT y, en los adicionales, las direcciones A. Es la forma de obtener
//! hostname, IP y servicios de los equipos que anuncian DNS-SD: una única
//! consulta de tipos solo devuelve los nombres de los servicios.
//!
//! Decisiones:
//! - Cada consulta usa un socket efímero y marca la pregunta con el bit QU
//!   (respuesta unicast), así las respuestas llegan a ese puerto sin compartir el
//!   5353 con el listener pasivo.
//! - Se aplica TTL multicast 255 (recomendado por RFC 6762) sin considerarlo
//!   fatal si el sistema no lo permite.
//! - El número de tipos consultados y de registros devueltos está acotado para
//!   que un fallo de red no haga crecer la memoria sin límite ni alargue el ciclo.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket as UdpSocketEstandar};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

use crate::error::{Error, Result};

use super::parser::{self, MdnsRecord};

/// Grupo multicast estándar de mDNS.
const GRUPO_MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// Puerto estándar de mDNS.
const PUERTO_MDNS: u16 = 5353;
/// Nombre fijo de la consulta de enumeración de servicios.
const NOMBRE_SERVICIOS: &str = "_services._dns-sd._udp.local.";
/// Tamaño máximo de un datagrama mDNS.
const MAX_DATAGRAMA: usize = 9000;
/// Registros máximos que se recopilan en una consulta.
const MAX_REGISTROS: usize = 2048;
/// Tipos de servicio máximos que se consultan en la segunda etapa.
const MAX_TIPOS: usize = 12;
/// Duración de la consulta de enumeración de tipos.
const DURACION_TIPOS: Duration = Duration::from_millis(900);
/// Duración máxima de cada consulta de instancias.
const DURACION_INSTANCIAS: Duration = Duration::from_millis(400);
/// Tipos habituales que se consultan si la enumeración no devuelve ninguno.
const TIPOS_COMUNES: &[&str] = &[
    "_http._tcp",
    "_ipp._tcp",
    "_printer._tcp",
    "_airplay._tcp",
    "_googlecast._tcp",
    "_raop._tcp",
    "_device-info._tcp",
    "_ssh._tcp",
    "_smb._tcp",
    "_workstation._tcp",
];

/// Consulta activa mDNS.
#[derive(Debug, Clone, Copy)]
pub struct MdnsQuery;

impl MdnsQuery {
    /// Enumera los servicios anunciados y resuelve sus instancias hasta agotar el timeout.
    ///
    /// API del contrato; la orquestación usa [MdnsQuery::discover_services_on]
    /// para enviar el multicast por la interfaz concreta del equipo.
    #[allow(dead_code)]
    pub async fn discover_services(timeout: Duration) -> Result<Vec<MdnsRecord>> {
        Self::discover_services_on(Ipv4Addr::UNSPECIFIED, timeout).await
    }

    /// Igual que [MdnsQuery::discover_services], enviando el multicast por la
    /// interfaz indicada.
    ///
    /// Es necesario fijar la interfaz de salida: sin IP_MULTICAST_IF el núcleo
    /// puede elegir una interfaz incorrecta y las consultas no llegan a la red.
    pub async fn discover_services_on(
        interface: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Vec<MdnsRecord>> {
        let inicio = tokio::time::Instant::now();
        let socket = abrir_socket(interface)?;
        let mut registros = consultar(
            &socket,
            construir_consulta_ptr(NOMBRE_SERVICIOS)?,
            timeout.min(DURACION_TIPOS),
        )
        .await?;

        let mut tipos = extraer_tipos(&registros);
        if tipos.is_empty() {
            tipos = TIPOS_COMUNES.iter().map(|tipo| tipo.to_string()).collect();
        }

        let mut restante = timeout.saturating_sub(inicio.elapsed());
        for tipo in tipos.into_iter().take(MAX_TIPOS) {
            if restante < Duration::from_millis(100) {
                break;
            }
            let porcion = restante.min(DURACION_INSTANCIAS);
            let nombre = format!("{tipo}.local.");
            match construir_consulta_ptr(&nombre) {
                Ok(consulta) => match consultar(&socket, consulta, porcion).await {
                    Ok(nuevos) => registros.extend(nuevos),
                    Err(err) => tracing::debug!(%tipo, %err, "consulta mDNS de instancias fallida"),
                },
                Err(err) => tracing::debug!(%tipo, %err, "nombre mDNS de servicio no válido"),
            }
            restante = restante.saturating_sub(porcion);
        }

        Ok(registros)
    }
}

/// Envía una consulta al grupo mDNS y recoge las respuestas hasta el timeout.
async fn consultar(
    socket: &tokio::net::UdpSocket,
    peticion: Vec<u8>,
    timeout: Duration,
) -> Result<Vec<MdnsRecord>> {
    socket
        .send_to(&peticion, SocketAddrV4::new(GRUPO_MDNS, PUERTO_MDNS))
        .await
        .map_err(|err| Error::Scan(format!("no se pudo enviar la consulta mDNS: {err}")))?;

    let limite = tokio::time::Instant::now() + timeout;
    let mut datos = [0u8; MAX_DATAGRAMA];
    let mut registros: Vec<MdnsRecord> = Vec::new();
    loop {
        let restante = limite.saturating_duration_since(tokio::time::Instant::now());
        if restante.is_zero() || registros.len() >= MAX_REGISTROS {
            break;
        }
        match tokio::time::timeout(restante, socket.recv_from(&mut datos)).await {
            Err(_) => break,
            Ok(Err(err)) => {
                tracing::debug!(%err, "error recibiendo respuestas mDNS");
                break;
            }
            Ok(Ok((leidos, _origen))) => {
                if leidos == 0 {
                    continue;
                }
                if let Ok(nuevos) = parser::parse(&datos[..leidos]) {
                    for registro in nuevos {
                        if registros.len() >= MAX_REGISTROS {
                            break;
                        }
                        registros.push(registro);
                    }
                }
            }
        }
    }
    Ok(registros)
}

/// Abre el socket de consulta mDNS ligado al puerto 5353.
///
/// RFC 6762 exige que las consultas mDNS se envíen desde el puerto 5353; los
/// respondedores ignoran las consultas con puerto de origen efímero. El socket
/// se une al grupo en la interfaz indicada para recibir las respuestas multicast
/// (las respuestas unicast QU podrían repartirse entre sockets con SO_REUSEPORT).
fn abrir_socket(interface: Ipv4Addr) -> Result<tokio::net::UdpSocket> {
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(Error::Scan(format!(
            "no se pudo crear el socket UDP de la consulta mDNS: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: el descriptor es válido y la envoltura toma su propiedad.
    let socket = unsafe { UdpSocketEstandar::from_raw_fd(descriptor) };

    let uno: libc::c_int = 1;
    for opcion in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
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
                "no se pudo activar la opción de socket {opcion} para mDNS: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    let direccion = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: PUERTO_MDNS.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let resultado = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&direccion as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if resultado != 0 {
        return Err(Error::Scan(format!(
            "no se pudo ligar el socket de consulta mDNS al puerto {PUERTO_MDNS}: {}",
            std::io::Error::last_os_error()
        )));
    }

    let interfaz = if interface.is_unspecified() {
        Ipv4Addr::UNSPECIFIED
    } else {
        interface
    };
    socket
        .join_multicast_v4(&GRUPO_MDNS, &interfaz)
        .map_err(|err| {
            Error::Scan(format!(
                "no se pudo unir al grupo multicast mDNS {GRUPO_MDNS}: {err}"
            ))
        })?;
    if let Err(err) = socket.set_multicast_ttl_v4(255) {
        tracing::debug!(%err, "no se pudo fijar el TTL multicast de la consulta mDNS");
    }
    fijar_interfaz_multicast_estandar(&socket, interfaz);

    socket
        .set_nonblocking(true)
        .map_err(|err| Error::Scan(format!("no se pudo configurar el socket mDNS: {err}")))?;
    tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| Error::Scan(format!("no se pudo adaptar el socket mDNS: {err}")))
}

/// Fija la interfaz de salida del multicast sobre un socket estándar.
fn fijar_interfaz_multicast_estandar(socket: &UdpSocketEstandar, interface: Ipv4Addr) {
    if interface.is_unspecified() {
        return;
    }
    let direccion = libc::in_addr {
        s_addr: u32::from_ne_bytes(interface.octets()),
    };
    let resultado = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            (&direccion as *const libc::in_addr).cast(),
            std::mem::size_of::<libc::in_addr>() as libc::socklen_t,
        )
    };
    if resultado != 0 {
        tracing::debug!(
            %interface,
            error = %std::io::Error::last_os_error(),
            "no se pudo fijar la interfaz multicast de la consulta mDNS"
        );
    }
}

/// Extrae los tipos de servicio distintos de los registros de enumeración.
fn extraer_tipos(registros: &[MdnsRecord]) -> Vec<String> {
    let mut vistos = HashSet::new();
    let mut tipos = Vec::new();
    for registro in registros {
        for servicio in &registro.services {
            let tipo = servicio.service_type.trim();
            if tipo.starts_with('_') && vistos.insert(tipo.to_ascii_lowercase()) {
                tipos.push(tipo.to_string());
            }
        }
    }
    tipos
}

/// Serializa una consulta PTR mDNS con el bit QU activado.
fn construir_consulta_ptr(nombre: &str) -> Result<Vec<u8>> {
    let nombre = Name::from_ascii(nombre)
        .map_err(|err| Error::Scan(format!("nombre mDNS interno inválido: {err}")))?;
    let mut pregunta = Query::query(nombre, RecordType::PTR);
    // Sin QU: la respuesta llega por multicast al socket de consulta y al
    // listener pasivo (las respuestas unicast a 5353 podrían repartirse entre
    // varios sockets con SO_REUSEPORT).
    pregunta.set_mdns_unicast_response(false);
    let mut mensaje = Message::new(0, MessageType::Query, OpCode::Query);
    mensaje.add_query(pregunta);
    mensaje
        .to_vec()
        .map_err(|err| Error::Scan(format!("no se pudo serializar la consulta mDNS: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_consulta_pide_los_tipos_de_servicio() {
        let bytes = construir_consulta_ptr(NOMBRE_SERVICIOS).expect("consulta serializable");
        let mensaje = Message::from_vec(&bytes).expect("consulta parseable");

        assert_eq!(mensaje.queries.len(), 1);
        let pregunta = &mensaje.queries[0];
        assert_eq!(pregunta.name().to_string(), "_services._dns-sd._udp.local.");
        assert_eq!(pregunta.query_type(), RecordType::PTR);
        assert!(!pregunta.mdns_unicast_response());
    }

    #[test]
    fn la_consulta_de_instancias_usa_el_tipo_indicado() {
        let bytes = construir_consulta_ptr("_ipp._tcp.local.").expect("consulta serializable");
        let mensaje = Message::from_vec(&bytes).expect("consulta parseable");
        assert_eq!(mensaje.queries[0].name().to_string(), "_ipp._tcp.local.");
    }

    #[test]
    fn extrae_tipos_distintos_y_descarta_no_servicios() {
        let registros = vec![
            MdnsRecord {
                services: vec![super::super::parser::MdnsService {
                    service_type: "_http._tcp".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            MdnsRecord {
                services: vec![
                    super::super::parser::MdnsService {
                        service_type: "_HTTP._TCP".to_string(),
                        ..Default::default()
                    },
                    super::super::parser::MdnsService {
                        service_type: "no-es-servicio".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        ];
        let tipos = extraer_tipos(&registros);
        assert_eq!(tipos, vec!["_http._tcp".to_string()]);
    }

    #[tokio::test]
    #[ignore = "requiere red local con mDNS; se ejecuta manualmente"]
    async fn browse_real_encuentra_servicios() {
        let interface = crate::scanner::interfaces::detect()
            .iter()
            .find_map(|iface| iface.ipv4)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let registros = MdnsQuery::discover_services_on(interface, Duration::from_secs(4))
            .await
            .expect("browse mDNS");
        let con_ip: Vec<&MdnsRecord> = registros.iter().filter(|r| r.ip.is_some()).collect();
        eprintln!(
            "browse mDNS: {} registros, {} con IP",
            registros.len(),
            con_ip.len()
        );
        for registro in con_ip.iter().take(20) {
            eprintln!(
                "  ip={:?} hostname={:?} servicios={:?}",
                registro.ip,
                registro.hostname,
                registro
                    .services
                    .iter()
                    .map(|servicio| servicio.service_type.as_str())
                    .collect::<Vec<_>>()
            );
        }
        assert!(
            !registros.is_empty(),
            "la red local debería anunciar algún servicio mDNS"
        );
    }
}
