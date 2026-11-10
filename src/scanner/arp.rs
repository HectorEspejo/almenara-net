//! Escaneo ARP activo sobre una interfaz usando sockets raw (pnet).
//!
//! Requiere CAP_NET_RAW; si el canal de enlace no se puede abrir devuelve error y
//! el escaneo continúa en modo degradado. La construcción y el parseo de tramas
//! están separados en funciones puras para poder probarlas sin privilegios.

use std::collections::{BTreeMap, HashSet};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, Config};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use crate::error::{Error, Result};
use crate::oui;
use crate::scanner::interfaces::DetectedInterface;

/// Tamaño de una trama ARP sobre Ethernet: 14 (Ethernet) + 28 (ARP).
const TAMANO_TRAMA_ARP: usize = 14 + 28;

/// Host descubierto por ARP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpHost {
    /// Dirección IPv4 que respondió.
    pub ip: Ipv4Addr,
    /// MAC normalizada del respondedor.
    pub mac: String,
}

/// Realiza un barrido ARP sobre los objetivos indicados.
///
/// Envía una petición ARP por cada objetivo y espera las respuestas hasta agotar
/// `timeout`. Devuelve los hosts que respondieron, deduplicados por MAC y en orden
/// determinista (por MAC).
pub fn scan(
    iface: &DetectedInterface,
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Result<Vec<ArpHost>> {
    let mac_origen = mac_de_interfaz(iface)?;
    let ip_origen = iface.ipv4.ok_or_else(|| {
        Error::Scan(format!(
            "la interfaz {} no tiene dirección IPv4: no se puede hacer el barrido ARP",
            iface.name
        ))
    })?;

    if targets.is_empty() || timeout.is_zero() {
        return Ok(Vec::new());
    }

    let mut objetivos = targets.to_vec();
    objetivos.sort_unstable();
    objetivos.dedup();

    let interfaz = datalink::interfaces()
        .into_iter()
        .find(|candidata| candidata.name == iface.name)
        .ok_or_else(|| {
            Error::Scan(format!(
                "la interfaz {} no existe en el sistema: no se puede hacer el barrido ARP",
                iface.name
            ))
        })?;

    let configuracion = Config {
        read_timeout: Some(timeout),
        write_timeout: Some(timeout),
        ..Config::default()
    };

    let (mut emisor, mut receptor) = match datalink::channel(&interfaz, configuracion) {
        Ok(Channel::Ethernet(emisor, receptor)) => (emisor, receptor),
        Ok(_) => {
            return Err(Error::Scan(format!(
                "el canal de enlace de {} no es Ethernet: no se puede hacer el barrido ARP",
                iface.name
            )))
        }
        Err(err) => {
            return Err(Error::Scan(format!(
            "no se pudo abrir el canal raw en {} para el barrido ARP (¿falta CAP_NET_RAW?): {err}",
            iface.name
        )))
        }
    };

    for objetivo in &objetivos {
        let trama = construir_trama_arp(
            mac_origen,
            ip_origen,
            MacAddr::broadcast(),
            MacAddr::zero(),
            *objetivo,
            ArpOperations::Request,
        );
        match emisor.send_to(&trama, None) {
            Some(Ok(_)) => {}
            Some(Err(err)) => {
                return Err(Error::Scan(format!(
                    "no se pudo enviar la petición ARP a {objetivo} por {}: {err}",
                    iface.name
                )))
            }
            None => {
                return Err(Error::Scan(format!(
                    "no se pudo enviar la petición ARP a {objetivo} por {}: búfer de envío lleno",
                    iface.name
                )))
            }
        }
    }

    let limite = Instant::now() + timeout;
    let conjunto_objetivos: HashSet<Ipv4Addr> = objetivos.iter().copied().collect();
    let mut respondidos: HashSet<Ipv4Addr> = HashSet::new();
    let mut por_mac: BTreeMap<String, ArpHost> = BTreeMap::new();

    while Instant::now() < limite && respondidos.len() < conjunto_objetivos.len() {
        match receptor.next() {
            Ok(trama) => {
                if let Some(host) = parse_arp_reply(trama, &objetivos) {
                    respondidos.insert(host.ip);
                    por_mac.entry(host.mac.clone()).or_insert(host);
                }
            }
            Err(err) if es_fin_de_espera(&err) => break,
            Err(err) => {
                return Err(Error::Scan(format!(
                    "error leyendo respuestas ARP por {}: {err}",
                    iface.name
                )))
            }
        }
    }

    Ok(por_mac.into_values().collect())
}

/// Calienta la tabla ARP del núcleo enviando datagramas UDP a los objetivos.
///
/// Se usa como respaldo cuando el barrido ARP raw no devuelve hosts: algunas
/// interfaces Wi-Fi descartan las tramas inyectadas con AF_PACKET. Al enviar un
/// datagrama UDP a cada IP, el núcleo resuelve la MAC con su propio ARP y deja la
/// entrada en /proc/net/arp, de donde el escáner la vuelve a leer. Solo abre un
/// socket UDP (sin privilegios) y es tráfico activo: el llamador debe respetar
/// passive_only.
pub fn calentar_tabla_arp(iface: &DetectedInterface, targets: &[Ipv4Addr]) -> Result<()> {
    let ip_local = iface.ipv4.ok_or_else(|| {
        Error::Scan(format!(
            "la interfaz {} no tiene dirección IPv4: no se puede calentar la tabla ARP",
            iface.name
        ))
    })?;
    let socket = std::net::UdpSocket::bind((ip_local, 0)).map_err(|err| {
        Error::Scan(format!(
            "no se pudo abrir el socket UDP para calentar la tabla ARP en {}: {err}",
            iface.name
        ))
    })?;
    // Dos rondas: la primera provoca la resolución y la segunda cubre pérdidas.
    for _ in 0..2 {
        for objetivo in targets {
            // Puerto 9 (discard): el contenido y el resultado no importan, solo
            // que el núcleo necesite resolver la MAC de destino.
            let _ = socket.send_to(&[0u8], (*objetivo, 9));
        }
    }
    Ok(())
}

/// Devuelve la MAC de la interfaz ya parseada.
fn mac_de_interfaz(iface: &DetectedInterface) -> Result<MacAddr> {
    let mac = iface.mac.as_deref().ok_or_else(|| {
        Error::Scan(format!(
            "la interfaz {} no tiene MAC: no se puede hacer el barrido ARP",
            iface.name
        ))
    })?;
    MacAddr::from_str(mac).map_err(|err| {
        Error::Scan(format!(
            "la MAC de la interfaz {} no es válida ({mac}): {err}",
            iface.name
        ))
    })
}

/// Construye una trama Ethernet + ARP.
///
/// `destino_mac` es la MAC de destino a nivel Ethernet y `destino_ip` la dirección
/// que se consulta en el campo de destino del ARP.
fn construir_trama_arp(
    origen_mac: MacAddr,
    origen_ip: Ipv4Addr,
    destino_mac: MacAddr,
    destino_hw: MacAddr,
    destino_ip: Ipv4Addr,
    operacion: pnet::packet::arp::ArpOperation,
) -> Vec<u8> {
    let mut buffer = vec![0u8; TAMANO_TRAMA_ARP];
    {
        let mut ethernet = MutableEthernetPacket::new(&mut buffer[..])
            .expect("el búfer tiene el tamaño de una trama Ethernet");
        ethernet.set_destination(destino_mac);
        ethernet.set_source(origen_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(ethernet.payload_mut())
            .expect("el búfer tiene el tamaño de un ARP sobre Ethernet");
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(operacion);
        arp.set_sender_hw_addr(origen_mac);
        arp.set_sender_proto_addr(origen_ip);
        arp.set_target_hw_addr(destino_hw);
        arp.set_target_proto_addr(destino_ip);
    }
    buffer
}

/// Extrae un host de una respuesta ARP si corresponde a alguno de los objetivos.
///
/// Devuelve `None` para tramas truncadas, que no son ARP, que no son respuestas o
/// cuyo emisor no estaba en la lista de objetivos.
fn parse_arp_reply(frame: &[u8], targets: &[Ipv4Addr]) -> Option<ArpHost> {
    let ethernet = EthernetPacket::new(frame)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    let ip = arp.get_sender_proto_addr();
    if !targets.contains(&ip) {
        return None;
    }

    let mac = oui::normalize_mac(&arp.get_sender_hw_addr().to_string())?;
    Some(ArpHost { ip, mac })
}

/// Indica si un error de lectura del canal significa fin del tiempo de espera.
fn es_fin_de_espera(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::arp::ArpHardwareType;
    use pnet::packet::ethernet::EtherType;

    fn mac(texto: &str) -> MacAddr {
        MacAddr::from_str(texto).expect("MAC de prueba válida")
    }

    fn interfaz(mac: Option<&str>, ipv4: Option<&str>) -> DetectedInterface {
        DetectedInterface {
            name: "eth0".to_string(),
            mac: mac.map(str::to_string),
            ipv4: ipv4.map(|ip| ip.parse().expect("IP de prueba válida")),
            netmask: Some("255.255.255.0".parse().expect("máscara de prueba válida")),
            gateway: Some("192.168.1.1".parse().expect("gateway de prueba válido")),
            is_up: true,
        }
    }

    #[test]
    fn construye_peticion_arp_valida() {
        let trama = construir_trama_arp(
            mac("aa:bb:cc:dd:ee:ff"),
            "192.168.1.10".parse().unwrap(),
            MacAddr::broadcast(),
            MacAddr::zero(),
            "192.168.1.1".parse().unwrap(),
            ArpOperations::Request,
        );
        assert_eq!(trama.len(), TAMANO_TRAMA_ARP);

        let ethernet = EthernetPacket::new(&trama).expect("trama Ethernet");
        assert_eq!(ethernet.get_destination(), MacAddr::broadcast());
        assert_eq!(ethernet.get_source(), mac("aa:bb:cc:dd:ee:ff"));
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Arp);

        let arp = ArpPacket::new(ethernet.payload()).expect("paquete ARP");
        assert_eq!(arp.get_hardware_type(), ArpHardwareTypes::Ethernet);
        assert_eq!(arp.get_protocol_type(), EtherTypes::Ipv4);
        assert_eq!(arp.get_hw_addr_len(), 6);
        assert_eq!(arp.get_proto_addr_len(), 4);
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_hw_addr(), mac("aa:bb:cc:dd:ee:ff"));
        assert_eq!(arp.get_sender_proto_addr(), Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(arp.get_target_hw_addr(), MacAddr::zero());
        assert_eq!(arp.get_target_proto_addr(), Ipv4Addr::new(192, 168, 1, 1));
    }

    fn trama_respuesta(respondedor_mac: &str, respondedor_ip: &str) -> Vec<u8> {
        construir_trama_arp(
            mac(respondedor_mac),
            respondedor_ip.parse().unwrap(),
            mac("aa:bb:cc:dd:ee:ff"),
            mac("aa:bb:cc:dd:ee:ff"),
            "192.168.1.10".parse().unwrap(),
            ArpOperations::Reply,
        )
    }

    #[test]
    fn parsea_respuesta_de_un_objetivo() {
        let objetivos = [
            "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
            "192.168.1.20".parse::<Ipv4Addr>().unwrap(),
        ];
        let trama = trama_respuesta("11:22:33:44:55:66", "192.168.1.20");
        let host = parse_arp_reply(&trama, &objetivos).expect("respuesta válida");
        assert_eq!(host.ip, Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(host.mac, "11:22:33:44:55:66");
    }

    #[test]
    fn descarta_respuestas_de_ips_no_objetivo() {
        let objetivos = ["192.168.1.1".parse::<Ipv4Addr>().unwrap()];
        let trama = trama_respuesta("11:22:33:44:55:66", "192.168.1.250");
        assert!(parse_arp_reply(&trama, &objetivos).is_none());
    }

    #[test]
    fn descarta_peticiones_y_tramas_no_arp() {
        let objetivos = ["192.168.1.20".parse::<Ipv4Addr>().unwrap()];
        let peticion = construir_trama_arp(
            mac("aa:bb:cc:dd:ee:ff"),
            "192.168.1.10".parse().unwrap(),
            MacAddr::broadcast(),
            MacAddr::zero(),
            objetivos[0],
            ArpOperations::Request,
        );
        assert!(parse_arp_reply(&peticion, &objetivos).is_none());

        let mut ipv4 = peticion.clone();
        ipv4[12] = 0x08;
        ipv4[13] = 0x00;
        assert!(parse_arp_reply(&ipv4, &objetivos).is_none());
    }

    #[test]
    fn descarta_tramas_truncadas_o_invalidas() {
        let objetivos = ["192.168.1.20".parse::<Ipv4Addr>().unwrap()];
        assert!(parse_arp_reply(&[], &objetivos).is_none());
        assert!(parse_arp_reply(&[0u8; 13], &objetivos).is_none());
        let trama = trama_respuesta("11:22:33:44:55:66", "192.168.1.20");
        assert!(parse_arp_reply(&trama[..20], &objetivos).is_none());
    }

    #[test]
    fn tipos_del_arp_son_los_esperados() {
        assert_eq!(ArpHardwareTypes::Ethernet, ArpHardwareType::new(1));
        assert_eq!(EtherTypes::Arp, EtherType(0x0806));
    }

    #[test]
    fn scan_sin_mac_devuelve_error_de_escaneo() {
        let err = scan(
            &interfaz(None, Some("192.168.1.10")),
            &[],
            Duration::from_millis(50),
        )
        .expect_err("sin MAC no se puede escanear");
        assert!(matches!(err, Error::Scan(_)));
        assert!(err.to_string().contains("no tiene MAC"));
    }

    #[test]
    fn scan_sin_ipv4_devuelve_error_de_escaneo() {
        let err = scan(
            &interfaz(Some("aa:bb:cc:dd:ee:ff"), None),
            &[],
            Duration::from_millis(50),
        )
        .expect_err("sin IPv4 no se puede escanear");
        assert!(matches!(err, Error::Scan(_)));
        assert!(err.to_string().contains("no tiene dirección IPv4"));
    }

    #[test]
    fn scan_sin_objetivos_no_abre_socket() {
        let detectada = interfaz(Some("aa:bb:cc:dd:ee:ff"), Some("192.168.1.10"));
        let hosts =
            scan(&detectada, &[], Duration::from_millis(50)).expect("sin objetivos no falla");
        assert!(hosts.is_empty());
    }

    #[test]
    fn scan_con_timeout_cero_no_abre_socket() {
        let detectada = interfaz(Some("aa:bb:cc:dd:ee:ff"), Some("192.168.1.10"));
        let objetivos = ["192.168.1.1".parse::<Ipv4Addr>().unwrap()];
        let hosts = scan(&detectada, &objetivos, Duration::ZERO).expect("timeout cero no falla");
        assert!(hosts.is_empty());
    }

    #[test]
    fn calentar_tabla_arp_con_objetivos_locales_no_falla() {
        let detectada = interfaz(Some("aa:bb:cc:dd:ee:ff"), Some("127.0.0.1"));
        calentar_tabla_arp(&detectada, &["127.0.0.1".parse().unwrap()])
            .expect("calentar la tabla ARP local no debe fallar");
    }

    #[test]
    fn calentar_tabla_arp_sin_ipv4_devuelve_error() {
        let detectada = interfaz(Some("aa:bb:cc:dd:ee:ff"), None);
        assert!(calentar_tabla_arp(&detectada, &[]).is_err());
    }
}
