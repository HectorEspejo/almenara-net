//! Rol cliente/servidor de un flujo (§7.1).
//!
//! La 5-tupla canónica ordena los extremos por valor, no por quién inició la
//! conexión. El rol se guarda aparte: [infer] devuelve `Some(true)` si el
//! origen canónico es el cliente, `Some(false)` si es el servidor y `None` cuando
//! no hay ninguna señal que lo permita deducir. Nunca se inventa.

use std::collections::HashSet;

use crate::capture::{PacketMeta, Protocol};
use crate::inference::FlowState;

use super::protocols::{is_ephemeral, is_service_port};

/// Conjunto de puertos en escucha del host y puertos de servicio de F2.
///
/// Se actualiza desde el ciclo de 5 s de la tarea de tráfico con los sockets en
/// LISTEN de /proc/net/tcp* y se comparte con los hilos de captura.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenSet {
    /// Pares (transporte, puerto) en LISTEN.
    listening: HashSet<(Protocol, u16)>,
    /// Puertos de servicio de F2.
    services: HashSet<u16>,
}

impl ListenSet {
    /// Crea un conjunto vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sustituye los sockets en escucha.
    pub fn set_listening(&mut self, ports: impl IntoIterator<Item = (Protocol, u16)>) {
        self.listening = ports.into_iter().collect();
    }

    /// Sustituye los puertos de servicio de F2.
    pub fn set_services(&mut self, ports: impl IntoIterator<Item = u16>) {
        self.services = ports.into_iter().collect();
    }

    /// Indica si el host tiene un socket en escucha en ese puerto.
    pub fn contains(&self, protocol: Protocol, port: u16) -> bool {
        self.listening.contains(&(protocol, port))
    }

    /// Indica si el puerto es un servicio de F2.
    pub fn is_service(&self, port: u16) -> bool {
        self.services.contains(&port)
    }

    /// Indica si el conjunto está vacío.
    pub fn is_empty(&self) -> bool {
        self.listening.is_empty() && self.services.is_empty()
    }
}

/// Infiere si el extremo origen canónico del flujo es el cliente (§7.1).
///
/// Reglas en orden: SYN sin ACK; socket local en LISTEN; puerto de servicio
/// frente a puerto efímero; primer datagrama UDP del flujo.
pub fn infer(flow: &FlowState, meta: &PacketMeta, listening: &ListenSet) -> Option<bool> {
    // 1) TCP: quien envía el SYN sin ACK es el cliente (regla más fuerte).
    if meta.protocol == Protocol::Tcp {
        if let Some(flags) = meta.tcp_flags {
            if flags.syn && !flags.ack {
                return Some(meta.src() == flow.key.origin);
            }
        }
    }

    // 2) Socket local en LISTEN: el host es el servidor.
    if let Some(cliente) = rol_por_escucha(flow, listening) {
        return Some(cliente);
    }

    // 3) Puerto de servicio en un extremo y puerto efímero en el otro.
    let puerto_origen = flow.key.origin.port;
    let puerto_destino = flow.key.destination.port;
    if let (Some(origen), Some(destino)) = (puerto_origen, puerto_destino) {
        let origen_servicio = puerto_de_servicio(origen, listening);
        let destino_servicio = puerto_de_servicio(destino, listening);
        if origen_servicio && is_ephemeral(destino) {
            return Some(false);
        }
        if destino_servicio && is_ephemeral(origen) {
            return Some(true);
        }
    }

    // 4) UDP: quien envía el primer datagrama del flujo observado.
    if meta.protocol == Protocol::Udp && flow.is_new {
        return Some(meta.src() == flow.key.origin);
    }

    None
}

/// Aplica la regla del socket local en LISTEN.
fn rol_por_escucha(flow: &FlowState, listening: &ListenSet) -> Option<bool> {
    let protocolo = flow.key.protocol;
    let origen_escucha = flow
        .key
        .origin
        .port
        .is_some_and(|puerto| listening.contains(protocolo, puerto));
    let destino_escucha = flow
        .key
        .destination
        .port
        .is_some_and(|puerto| listening.contains(protocolo, puerto));
    match (origen_escucha, destino_escucha) {
        // El host es el origen canónico: el cliente es el destino.
        (true, false) => Some(false),
        // El host es el destino canónico: el cliente es el origen.
        (false, true) => Some(true),
        _ => None,
    }
}

/// Indica si el puerto es de servicio por la tabla §7.3 o por un servicio de F2.
fn puerto_de_servicio(puerto: u16, listening: &ListenSet) -> bool {
    is_service_port(puerto) || listening.is_service(puerto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{ConnectionKey, Endpoint, TcpFlags};
    use crate::inference::L4;
    use std::net::IpAddr;
    use std::time::Instant;

    fn endpoint(ip: &str, puerto: u16) -> Endpoint {
        Endpoint::new(ip.parse::<IpAddr>().expect("IP válida"), Some(puerto))
    }

    fn crear_flujo(a: (&str, u16), b: (&str, u16), protocolo: Protocol, is_new: bool) -> FlowState {
        FlowState {
            key: ConnectionKey::from_endpoints(protocolo, endpoint(a.0, a.1), endpoint(b.0, b.1)),
            first_seen: Instant::now(),
            is_new,
            l4: L4::from_protocol(protocolo),
            app_protocol: None,
            client_is_src: None,
            quic: false,
        }
    }

    fn crear_paquete(
        origen: (&str, u16),
        destino: (&str, u16),
        protocolo: Protocol,
        flags: Option<TcpFlags>,
    ) -> PacketMeta {
        PacketMeta {
            timestamp: Instant::now(),
            src_ip: origen.0.parse().expect("IP válida"),
            dst_ip: destino.0.parse().expect("IP válida"),
            src_port: Some(origen.1),
            dst_port: Some(destino.1),
            protocol: protocolo,
            len: 60,
            tcp_flags: flags,
            headers: None,
        }
    }

    fn syn(ack: bool) -> TcpFlags {
        TcpFlags {
            syn: true,
            ack,
            ..TcpFlags::default()
        }
    }

    fn vacio() -> ListenSet {
        ListenSet::new()
    }

    #[test]
    fn el_syn_sin_ack_marca_como_cliente_al_emisor() {
        let flujo = crear_flujo(("10.0.0.1", 1234), ("10.0.0.2", 80), Protocol::Tcp, true);
        let paquete = crear_paquete(
            ("10.0.0.1", 1234),
            ("10.0.0.2", 80),
            Protocol::Tcp,
            Some(syn(false)),
        );
        assert_eq!(infer(&flujo, &paquete, &vacio()), Some(true));

        // El otro extremo canónico manda el SYN: el cliente es el destino.
        let paquete = crear_paquete(
            ("10.0.0.2", 80),
            ("10.0.0.1", 1234),
            Protocol::Tcp,
            Some(syn(false)),
        );
        assert_eq!(infer(&flujo, &paquete, &vacio()), Some(false));
    }

    #[test]
    fn el_syn_ack_no_decide_por_si_solo() {
        let flujo = crear_flujo(
            ("10.0.0.1", 12345),
            ("10.0.0.2", 54321),
            Protocol::Tcp,
            false,
        );
        let paquete = crear_paquete(
            ("10.0.0.2", 54321),
            ("10.0.0.1", 12345),
            Protocol::Tcp,
            Some(syn(true)),
        );
        assert_eq!(infer(&flujo, &paquete, &vacio()), None);
    }

    #[test]
    fn un_socket_en_escucha_marca_como_servidor_al_host() {
        let mut escucha = vacio();
        escucha.set_listening([(Protocol::Tcp, 8080)]);

        // El host (192.168.1.10:8080) es el origen canónico: servidor.
        let flujo_servidor = crear_flujo(
            ("192.168.1.10", 8080),
            ("192.168.1.200", 50000),
            Protocol::Tcp,
            false,
        );
        let paquete = crear_paquete(
            ("192.168.1.200", 50000),
            ("192.168.1.10", 8080),
            Protocol::Tcp,
            None,
        );
        assert_eq!(infer(&flujo_servidor, &paquete, &escucha), Some(false));

        // El host es el destino canónico: el cliente es el origen.
        let flujo_cliente = crear_flujo(
            ("192.168.1.10", 50000),
            ("192.168.1.200", 8080),
            Protocol::Tcp,
            false,
        );
        let paquete = crear_paquete(
            ("192.168.1.10", 50000),
            ("192.168.1.200", 8080),
            Protocol::Tcp,
            None,
        );
        assert_eq!(infer(&flujo_cliente, &paquete, &escucha), Some(true));
    }

    #[test]
    fn el_puerto_de_servicio_frente_al_efimero_decide_el_rol() {
        // Servidor en el origen canónico.
        let flujo = crear_flujo(("10.0.0.1", 22), ("10.0.0.2", 50000), Protocol::Tcp, false);
        let paquete = crear_paquete(("10.0.0.2", 50000), ("10.0.0.1", 22), Protocol::Tcp, None);
        assert_eq!(infer(&flujo, &paquete, &vacio()), Some(false));

        // Servidor en el destino canónico.
        let flujo = crear_flujo(("10.0.0.1", 50000), ("10.0.0.2", 443), Protocol::Tcp, false);
        let paquete = crear_paquete(("10.0.0.1", 50000), ("10.0.0.2", 443), Protocol::Tcp, None);
        assert_eq!(infer(&flujo, &paquete, &vacio()), Some(true));
    }

    #[test]
    fn los_servicios_de_f2_cuentan_como_puerto_de_servicio() {
        let mut escucha = vacio();
        escucha.set_services([8080]);
        let flujo = crear_flujo(
            ("10.0.0.1", 8080),
            ("10.0.0.2", 50000),
            Protocol::Tcp,
            false,
        );
        let paquete = crear_paquete(("10.0.0.2", 50000), ("10.0.0.1", 8080), Protocol::Tcp, None);
        assert_eq!(infer(&flujo, &paquete, &escucha), Some(false));
    }

    #[test]
    fn sin_puerto_efimero_ni_escucha_no_hay_rol() {
        let flujo = crear_flujo(("10.0.0.1", 22), ("10.0.0.2", 1234), Protocol::Tcp, false);
        let paquete = crear_paquete(("10.0.0.2", 1234), ("10.0.0.1", 22), Protocol::Tcp, None);
        assert_eq!(infer(&flujo, &paquete, &vacio()), None);
    }

    #[test]
    fn el_primer_datagrama_udp_marca_el_cliente() {
        let flujo = crear_flujo(
            ("10.0.0.1", 12345),
            ("10.0.0.2", 54321),
            Protocol::Udp,
            true,
        );
        let paquete = crear_paquete(
            ("10.0.0.1", 12345),
            ("10.0.0.2", 54321),
            Protocol::Udp,
            None,
        );
        assert_eq!(infer(&flujo, &paquete, &vacio()), Some(true));

        let paquete = crear_paquete(
            ("10.0.0.2", 54321),
            ("10.0.0.1", 12345),
            Protocol::Udp,
            None,
        );
        assert_eq!(infer(&flujo, &paquete, &vacio()), Some(false));
    }

    #[test]
    fn un_flujo_udp_ya_visto_no_decide_por_el_primer_datagrama() {
        let flujo = crear_flujo(
            ("10.0.0.1", 12345),
            ("10.0.0.2", 54321),
            Protocol::Udp,
            false,
        );
        let paquete = crear_paquete(
            ("10.0.0.1", 12345),
            ("10.0.0.2", 54321),
            Protocol::Udp,
            None,
        );
        assert_eq!(infer(&flujo, &paquete, &vacio()), None);
    }

    #[test]
    fn sin_senales_el_rol_queda_en_none() {
        let flujo = crear_flujo(
            ("10.0.0.1", 12345),
            ("10.0.0.2", 54321),
            Protocol::Tcp,
            false,
        );
        let paquete = crear_paquete(
            ("10.0.0.1", 12345),
            ("10.0.0.2", 54321),
            Protocol::Tcp,
            Some(TcpFlags::default()),
        );
        assert_eq!(infer(&flujo, &paquete, &vacio()), None);
    }

    #[test]
    fn un_flujo_sin_puertos_ni_flags_no_tiene_rol() {
        let ip_a: IpAddr = "10.0.0.1".parse().expect("IP válida");
        let ip_b: IpAddr = "10.0.0.2".parse().expect("IP válida");
        let flujo = FlowState {
            key: ConnectionKey::from_endpoints(
                Protocol::Icmp,
                Endpoint::new(ip_a, None),
                Endpoint::new(ip_b, None),
            ),
            first_seen: Instant::now(),
            is_new: true,
            l4: L4::from_protocol(Protocol::Icmp),
            app_protocol: None,
            client_is_src: None,
            quic: false,
        };
        let paquete = PacketMeta {
            timestamp: Instant::now(),
            src_ip: ip_a,
            dst_ip: ip_b,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Icmp,
            len: 84,
            tcp_flags: None,
            headers: None,
        };
        assert_eq!(infer(&flujo, &paquete, &vacio()), None);
    }

    #[test]
    fn el_conjunto_de_escucha_se_sustituye_entero() {
        let mut escucha = vacio();
        assert!(escucha.is_empty());
        escucha.set_listening([(Protocol::Tcp, 22), (Protocol::Udp, 5353)]);
        escucha.set_services([8080]);
        assert!(!escucha.is_empty());
        assert!(escucha.contains(Protocol::Tcp, 22));
        assert!(!escucha.contains(Protocol::Tcp, 5353));
        assert!(escucha.contains(Protocol::Udp, 5353));
        assert!(escucha.is_service(8080));
        assert!(!escucha.is_service(22));

        escucha.set_listening([(Protocol::Tcp, 443)]);
        assert!(!escucha.contains(Protocol::Tcp, 22));
        assert!(escucha.contains(Protocol::Tcp, 443));
    }
}
