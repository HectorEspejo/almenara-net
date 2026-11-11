//! Captura de tráfico en vivo con AF_PACKET + TPACKET_V3.
//!
//! Este módulo es la fachada del subsistema de captura: define los tipos de
//! metadatos que comparten todos los submódulos y el ciclo de vida de
//! [Capture] (apertura de los anillos TPACKET_V3, un hilo dedicado por interfaz,
//! drenaje de paquetes, contadores y parada limpia).
//!
//! Privacidad: el payload nunca se conserva. El parser solo copia las cabeceras
//! IP y de transporte (necesarias para el panel de cabeceras de la tecla v) y,
//! opcionalmente, extrae el QNAME de DNS o el SNI de TLS; el resto del contenido
//! del paquete se descarta inmediatamente.
//!
//! Fase 3 no usa libpcap: los filtros son BPF clásico adjunto al socket con
//! SO_ATTACH_FILTER y el anillo se gestiona directamente con libc.

// La fachada de captura expone la API completa del checklist de Fase 3, incluidas
// operaciones que la integración actual aún no consume (y que usarán F4/F5/F7).
// Se permite código muerto en este módulo para no marcar como muerta esa
// superficie pública; los submódulos mantienen su propio control.
#![allow(dead_code)]

pub mod afpacket;
pub mod aggregate;
pub mod bpf;
pub mod conntrack;
pub mod parser;
pub mod process;
pub mod windows;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::config::{CaptureConfig, InferenceConfig};
use crate::error::{Error, Result};
use crate::identify::observed::{ObservedFilter, ObservedHosts};
use crate::identify::CaptureIdentityStore;
use crate::inference::role::ListenSet;
use crate::inference::{Evidence, FlowInspector, InferenceCounters, ObservedHost, ObservedSource};

/// Tamaño total del anillo TPACKET_V3 por interfaz: 64 MB.
pub const RING_BYTES: usize = 64 * 1024 * 1024;
/// Tamaño de bloque del anillo: 1 MB.
pub const RING_BLOCK_SIZE: u32 = 1024 * 1024;
/// Número de bloques del anillo (64 MB / 1 MB).
pub const RING_BLOCK_NR: u32 = (RING_BYTES / RING_BLOCK_SIZE as usize) as u32;
/// Tamaño de frame del anillo: 4 KB.
pub const RING_FRAME_SIZE: u32 = 4096;
/// Capacidad de la cola entre el hilo de captura y el consumidor (en lotes).
pub const BATCH_CAPACITY: usize = 32;
/// Número máximo de paquetes por lote.
pub const BATCH_SIZE: usize = 256;
/// Tiempo máximo de espera de cada poll sobre el socket de captura.
pub const POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// Protocolo de transporte observado en un paquete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP (IPv4).
    Icmp,
    /// ICMPv6.
    Icmpv6,
    /// Otro protocolo IP (IPIP, GRE, etc.).
    Other,
}

impl Protocol {
    /// Protocolos de transporte soportados por la agregación y la TUI.
    pub const ALL: [Self; 4] = [Self::Tcp, Self::Udp, Self::Icmp, Self::Icmpv6];

    /// Representación persistida y de filtros.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmp6",
            Self::Other => "other",
        }
    }

    /// Reconstruye el protocolo desde su representación persistida.
    pub fn from_str(valor: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protocolo| protocolo.as_str() == valor)
            .or_else(|| (valor == "other").then_some(Self::Other))
    }

    /// Etiqueta visible en castellano.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Other => "otros",
        }
    }
}

/// Flags de la cabecera TCP (9 bits: NS y los 8 clásicos).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    /// Congestion Window Reduced.
    pub cwr: bool,
    /// ECN-Echo.
    pub ece: bool,
    /// Urgent pointer válido.
    pub urg: bool,
    /// Acknowledgement válido.
    pub ack: bool,
    /// Push.
    pub psh: bool,
    /// Reset.
    pub rst: bool,
    /// Synchronize.
    pub syn: bool,
    /// Fin.
    pub fin: bool,
}

impl TcpFlags {
    /// Reconstruye los flags desde los 9 bits del campo TCP.
    pub fn from_bits(bits: u16) -> Self {
        let bit = |mascara: u16| bits & mascara != 0;
        Self {
            cwr: bit(0x0080),
            ece: bit(0x0040),
            urg: bit(0x0020),
            ack: bit(0x0010),
            psh: bit(0x0008),
            rst: bit(0x0004),
            syn: bit(0x0002),
            fin: bit(0x0001),
        }
    }

    /// Devuelve los 9 bits del campo TCP.
    pub fn to_bits(self) -> u16 {
        let mut bits = 0u16;
        for (activo, mascara) in [
            (self.cwr, 0x0080),
            (self.ece, 0x0040),
            (self.urg, 0x0020),
            (self.ack, 0x0010),
            (self.psh, 0x0008),
            (self.rst, 0x0004),
            (self.syn, 0x0002),
            (self.fin, 0x0001),
        ] {
            if activo {
                bits |= mascara;
            }
        }
        bits
    }

    /// Etiqueta legible de los flags activos (por ejemplo "SYN,ACK").
    pub fn label(self) -> String {
        let mut activos: Vec<&str> = Vec::new();
        for (activo, nombre) in [
            (self.cwr, "CWR"),
            (self.ece, "ECE"),
            (self.urg, "URG"),
            (self.ack, "ACK"),
            (self.psh, "PSH"),
            (self.rst, "RST"),
            (self.syn, "SYN"),
            (self.fin, "FIN"),
        ] {
            if activo {
                activos.push(nombre);
            }
        }
        activos.join(",")
    }
}

/// Copia de las cabeceras IP y de transporte de un paquete, en tamaño fijo.
///
/// Se guarda para que el panel de cabeceras de la tecla v pueda mostrar
/// exactamente los bytes observados sin conservar el payload. Nunca contiene
/// datos del payload: solo la cabecera IP (hasta 40 bytes) y la cabecera de
/// transporte (hasta 20 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderSnapshot {
    /// Versión de IP (4 o 6).
    pub ip_version: u8,
    /// Longitud de la cabecera IP en bytes.
    pub ip_header_len: u8,
    /// Longitud total del paquete IP en bytes.
    pub ip_total_len: u16,
    /// TTL (IPv4) o hop limit (IPv6).
    pub ttl: u8,
    /// Traffic Class / TOS.
    pub tos: u8,
    /// Protocolo IP (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6).
    pub ip_protocol: u8,
    /// Bytes crudos de la cabecera IP.
    pub ip_raw: [u8; 40],
    /// Bytes válidos dentro de ip_raw.
    pub ip_raw_len: u8,
    /// Bytes crudos de la cabecera de transporte.
    pub transport_raw: [u8; 20],
    /// Bytes válidos dentro de transport_raw.
    pub transport_raw_len: u8,
    /// Número de secuencia TCP.
    pub tcp_seq: u32,
    /// Número de acknowledgement TCP.
    pub tcp_ack: u32,
    /// Ventana TCP.
    pub tcp_window: u16,
    /// Bits de flags TCP (9 bits).
    pub tcp_flags: u16,
}

impl Default for HeaderSnapshot {
    fn default() -> Self {
        Self {
            ip_version: 0,
            ip_header_len: 0,
            ip_total_len: 0,
            ttl: 0,
            tos: 0,
            ip_protocol: 0,
            ip_raw: [0; 40],
            ip_raw_len: 0,
            transport_raw: [0; 20],
            transport_raw_len: 0,
            tcp_seq: 0,
            tcp_ack: 0,
            tcp_window: 0,
            tcp_flags: 0,
        }
    }
}

impl HeaderSnapshot {
    /// Devuelve los bytes válidos de la cabecera IP.
    pub fn ip_bytes(&self) -> &[u8] {
        &self.ip_raw[..usize::from(self.ip_raw_len.min(40))]
    }

    /// Devuelve los bytes válidos de la cabecera de transporte.
    pub fn transport_bytes(&self) -> &[u8] {
        &self.transport_raw[..usize::from(self.transport_raw_len.min(20))]
    }
}

/// Extremo de una conexión (dirección + puerto opcional).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    /// Dirección IP.
    pub ip: IpAddr,
    /// Puerto de transporte (None en ICMP).
    pub port: Option<u16>,
}

impl Endpoint {
    /// Construye un extremo.
    pub fn new(ip: IpAddr, port: Option<u16>) -> Self {
        Self { ip, port }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.ip, self.port) {
            (IpAddr::V6(ip), Some(puerto)) => write!(f, "[{ip}]:{puerto}"),
            (ip, Some(puerto)) => write!(f, "{ip}:{puerto}"),
            (ip, None) => write!(f, "{ip}"),
        }
    }
}

/// Metadatos de un paquete capturado (sin payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMeta {
    /// Instante de captura en el reloj monótono (bucketiza las ventanas).
    pub timestamp: Instant,
    /// IP de origen.
    pub src_ip: IpAddr,
    /// IP de destino.
    pub dst_ip: IpAddr,
    /// Puerto de origen (None en ICMP).
    pub src_port: Option<u16>,
    /// Puerto de destino (None en ICMP).
    pub dst_port: Option<u16>,
    /// Protocolo de transporte.
    pub protocol: Protocol,
    /// Longitud en cable (longitud total IP).
    pub len: u32,
    /// Flags TCP, si aplica.
    pub tcp_flags: Option<TcpFlags>,
    /// Copia de cabeceras (IP + transporte) para el panel de la tecla v.
    pub headers: Option<HeaderSnapshot>,
}

impl PacketMeta {
    /// Extremo de origen.
    pub fn src(&self) -> Endpoint {
        Endpoint::new(self.src_ip, self.src_port)
    }

    /// Extremo de destino.
    pub fn dst(&self) -> Endpoint {
        Endpoint::new(self.dst_ip, self.dst_port)
    }

    /// Indica si el destino es difusión o multidifusión.
    pub fn is_broadcast(&self) -> bool {
        es_direccion_broadcast(self.dst_ip)
    }

    /// Indica si el paquete es IPv6.
    pub fn is_ipv6(&self) -> bool {
        matches!(self.dst_ip, IpAddr::V6(_))
    }
}

/// Información de una trama ARP (EtherType 0x0806).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpInfo {
    /// Código de operación (1 = petición, 2 = respuesta).
    pub opcode: u16,
    /// MAC del emisor.
    pub sender_mac: [u8; 6],
    /// IP del emisor.
    pub sender_ip: Ipv4Addr,
    /// MAC del destinatario (cero en una petición).
    pub target_mac: [u8; 6],
    /// IP del destinatario.
    pub target_ip: Ipv4Addr,
}

impl ArpInfo {
    /// Trama ARP de petición o respuesta (se ignoran RARP y otras).
    pub fn es_peticion_o_respuesta(&self) -> bool {
        self.opcode == 1 || self.opcode == 2
    }
}

/// Trama IPv4/IPv6 parseada, con la localización del payload en la trama.
///
/// El rango `payload` apunta dentro de la trama original: el hilo de captura lo
/// pasa al FlowInspector y lo descarta inmediatamente después.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIpFrame {
    /// Metadatos del paquete (sin payload).
    pub meta: PacketMeta,
    /// Rango del payload de transporte dentro de la trama.
    pub payload: std::ops::Range<usize>,
    /// MAC de origen Ethernet.
    pub src_mac: [u8; 6],
    /// MAC de destino Ethernet.
    pub dst_mac: [u8; 6],
}

impl ParsedIpFrame {
    /// Devuelve el payload de transporte dentro de la trama capturada.
    pub fn payload<'a>(&self, frame: &'a [u8]) -> &'a [u8] {
        let inicio = self.payload.start.min(frame.len());
        let fin = self.payload.end.min(frame.len());
        &frame[inicio..fin]
    }
}

/// Trama ARP parseada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedArpFrame {
    /// Información ARP.
    pub arp: ArpInfo,
    /// MAC de origen Ethernet.
    pub src_mac: [u8; 6],
    /// MAC de destino Ethernet.
    pub dst_mac: [u8; 6],
}

/// Resultado de parsear una trama Ethernet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedFrame {
    /// Trama IPv4 o IPv6.
    Ip(ParsedIpFrame),
    /// Trama ARP.
    Arp(ParsedArpFrame),
    /// Trama de un EtherType no soportado: se descarta en silencio.
    Ignorada(String),
}

/// Indica si una IP es de difusión o multidifusión.
///
/// Cubre 255.255.255.255, el rango 224.0.0.0/4 (IPv4) y ff00::/8 (IPv6).
pub fn es_direccion_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::BROADCAST || (u32::from(v4) & 0xF000_0000) == 0xE000_0000,
        IpAddr::V6(v6) => v6.segments()[0] & 0xFF00 == 0xFF00,
    }
}

/// Clave canónica de una conexión por 5-tuple.
///
/// Los dos extremos se ordenan por (IP, puerto): el menor es origin y el mayor
/// destination. Así las tramas de ida y de vuelta comparten una única entrada y
/// bytes_out / bytes_in son relativos al extremo origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionKey {
    /// Protocolo de transporte.
    pub protocol: Protocol,
    /// Extremo canónico de origen.
    pub origin: Endpoint,
    /// Extremo canónico de destino.
    pub destination: Endpoint,
}

impl ConnectionKey {
    /// Canonicaliza los dos extremos de un paquete.
    pub fn from_packet(meta: &PacketMeta) -> Self {
        Self::from_endpoints(meta.protocol, meta.src(), meta.dst())
    }

    /// Canonicaliza dos extremos arbitrarios.
    pub fn from_endpoints(protocol: Protocol, a: Endpoint, b: Endpoint) -> Self {
        if a <= b {
            Self {
                protocol,
                origin: a,
                destination: b,
            }
        } else {
            Self {
                protocol,
                origin: b,
                destination: a,
            }
        }
    }

    /// Devuelve la clave con los extremos intercambiados.
    pub fn inverted(&self) -> Self {
        Self {
            protocol: self.protocol,
            origin: self.destination,
            destination: self.origin,
        }
    }
}

/// Contadores de la captura expuestos a la TUI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Paquetes por segundo en la última ventana de un segundo.
    pub pps: u64,
    /// Paquetes capturados desde el arranque.
    pub total: u64,
    /// Paquetes descartados (anillo, cola llena o límite max_pps).
    pub drops: u64,
    /// Paquetes con cabecera mal formada o truncada.
    pub parse_errors: u64,
    /// Contadores del motor de inferencia (Fase 4).
    pub inference: InferenceCounters,
}

/// Configuración del anillo TPACKET_V3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingConfig {
    /// Tamaño de cada bloque (1 MB por defecto).
    pub block_size: u32,
    /// Número de bloques (64 por defecto, 64 MB en total).
    pub block_nr: u32,
    /// Tamaño de frame (4 KB por defecto).
    pub frame_size: u32,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            block_size: RING_BLOCK_SIZE,
            block_nr: RING_BLOCK_NR,
            frame_size: RING_FRAME_SIZE,
        }
    }
}

impl RingConfig {
    /// Tamaño total del anillo en bytes.
    pub fn bytes(self) -> usize {
        self.block_size as usize * self.block_nr as usize
    }
}

/// Interfaz sobre la que capturar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureInterface {
    /// Nombre de la interfaz (eth0, wlan0, ...).
    pub name: String,
    /// IPv4 principal de la interfaz, si tiene.
    pub ipv4: Option<Ipv4Addr>,
    /// MAC de la interfaz, si tiene.
    pub mac: Option<String>,
    /// Máscara de red IPv4, si tiene.
    pub netmask: Option<Ipv4Addr>,
    /// Puerto de enlace por defecto asociado, si lo hay.
    pub gateway: Option<Ipv4Addr>,
}

impl CaptureInterface {
    /// Construye la interfaz de captura con su IPv4.
    pub fn new(name: impl Into<String>, ipv4: Option<Ipv4Addr>) -> Self {
        Self {
            name: name.into(),
            ipv4,
            mac: None,
            netmask: None,
            gateway: None,
        }
    }

    /// Construye la interfaz de captura con todos sus datos de red.
    pub fn with_details(
        name: impl Into<String>,
        ipv4: Option<Ipv4Addr>,
        mac: Option<String>,
        netmask: Option<Ipv4Addr>,
        gateway: Option<Ipv4Addr>,
    ) -> Self {
        Self {
            name: name.into(),
            ipv4,
            mac,
            netmask,
            gateway,
        }
    }

    /// IP local de la interfaz como IpAddr, si existe.
    pub fn ip(&self) -> Option<IpAddr> {
        self.ipv4.map(IpAddr::V4)
    }

    /// Subred local como (red, máscara), si se conocen IP y máscara.
    pub fn red_local(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        let ip = self.ipv4?;
        let mascara = self.netmask?;
        Some((Ipv4Addr::from(u32::from(ip) & u32::from(mascara)), mascara))
    }
}

/// Contadores compartidos entre los hilos de captura.
#[derive(Debug)]
struct SharedStats {
    total: AtomicU64,
    drops: AtomicU64,
    parse_errors: AtomicU64,
    limit_drops: AtomicU64,
    inference_errors: AtomicU64,
    reassembly_drops: AtomicU64,
    quic_errors: AtomicU64,
    labelled_flows: AtomicU64,
    pps: Vec<Arc<AtomicU64>>,
}

impl SharedStats {
    fn new(interfaces: usize) -> Arc<Self> {
        Arc::new(Self {
            total: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            limit_drops: AtomicU64::new(0),
            inference_errors: AtomicU64::new(0),
            reassembly_drops: AtomicU64::new(0),
            quic_errors: AtomicU64::new(0),
            labelled_flows: AtomicU64::new(0),
            pps: (0..interfaces)
                .map(|_| Arc::new(AtomicU64::new(0)))
                .collect(),
        })
    }

    /// Suma los contadores de inferencia de un hilo.
    fn acumular_inferencia(&self, total: &InferenceCounters) {
        self.inference_errors
            .fetch_add(total.inference_errors, Ordering::Relaxed);
        self.reassembly_drops
            .fetch_add(total.reassembly_drops, Ordering::Relaxed);
        self.quic_errors
            .fetch_add(total.quic_errors, Ordering::Relaxed);
        self.labelled_flows
            .fetch_add(total.labelled_flows, Ordering::Relaxed);
    }

    fn pps_total(&self) -> u64 {
        self.pps
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .sum()
    }
}

/// Limitador global de paquetes por segundo ([capture].max_pps).
#[derive(Debug)]
struct PpsLimiter {
    max_pps: u64,
    ventana: Mutex<(Instant, u64)>,
}

impl PpsLimiter {
    fn new(max_pps: u64) -> Self {
        Self {
            max_pps,
            ventana: Mutex::new((Instant::now(), 0)),
        }
    }

    /// Indica si el paquete puede procesarse en este instante.
    fn permitir(&self, ahora: Instant) -> bool {
        if self.max_pps == 0 {
            return true;
        }
        let mut estado = match self.ventana.lock() {
            Ok(guardia) => guardia,
            Err(envenenado) => envenenado.into_inner(),
        };
        if ahora.duration_since(estado.0) >= Duration::from_secs(1) {
            estado.0 = ahora;
            estado.1 = 0;
        }
        if estado.1 >= self.max_pps {
            false
        } else {
            estado.1 += 1;
            true
        }
    }
}

/// Configuración de la inspección de la Fase 4 para los hilos de captura.
///
/// Los hilos comparten el conjunto de puertos en escucha (rol cliente/servidor),
/// el almacén de identidad DHCP y el buffer de equipos observados con la tarea
/// de tráfico y con el ciclo de escaneo.
pub struct CaptureInference {
    /// Configuración de `[inference]`.
    pub config: InferenceConfig,
    /// IPs propias del host (para el rol y la atribución de proceso).
    pub local_ips: HashSet<IpAddr>,
    /// Sockets en LISTEN del host, actualizados por la tarea de tráfico.
    pub listening: Arc<RwLock<ListenSet>>,
    /// Identidad capturada (DHCP y User-Agent) para el ciclo de escaneo.
    pub identity: Arc<Mutex<CaptureIdentityStore>>,
    /// Equipos observados en la captura (fuente L2 de F4).
    pub observed: Arc<Mutex<ObservedHosts>>,
    /// Filtro de equipos observados.
    pub observed_filter: ObservedFilter,
}

impl CaptureInference {
    /// Crea la configuración de inspección con los almacenes compartidos.
    pub fn new(
        config: InferenceConfig,
        local_ips: HashSet<IpAddr>,
        listening: Arc<RwLock<ListenSet>>,
        identity: Arc<Mutex<CaptureIdentityStore>>,
        observed: Arc<Mutex<ObservedHosts>>,
        observed_filter: ObservedFilter,
    ) -> Self {
        Self {
            config,
            local_ips,
            listening,
            identity,
            observed,
            observed_filter,
        }
    }
}

/// Lote de paquetes y evidencias que viaja del hilo de captura al agregador.
#[derive(Debug, Default)]
pub struct CaptureBatch {
    /// Paquetes capturados (sin payload).
    pub packets: Vec<PacketMeta>,
    /// Evidencias extraídas por el FlowInspector de la interfaz.
    pub evidence: Vec<Evidence>,
}

/// Resultado de drenar los hilos de captura.
#[derive(Debug, Default)]
pub struct CaptureDrain {
    /// Paquetes capturados desde la última llamada.
    pub packets: Vec<PacketMeta>,
    /// Evidencias extraídas desde la última llamada.
    pub evidence: Vec<Evidence>,
}

/// Formatea una MAC de 6 bytes como `aa:bb:cc:dd:ee:ff`.
pub fn formatear_mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Estado de un hilo de captura (un socket por interfaz).
struct HiloCaptura {
    socket: afpacket::AfPacketSocket,
    parser: parser::Parser,
    tx: SyncSender<CaptureBatch>,
    shared: Arc<SharedStats>,
    limitador: Arc<PpsLimiter>,
    parar: Arc<AtomicBool>,
    pps: Arc<AtomicU64>,
    inspector: FlowInspector,
    identity: Arc<Mutex<CaptureIdentityStore>>,
    observed: Arc<Mutex<ObservedHosts>>,
    observed_filter: ObservedFilter,
    observados_vistos: HashSet<(String, Ipv4Addr)>,
    contadores_previos: InferenceCounters,
}

/// Envía un lote al consumidor; si la cola está llena se descartan los paquetes.
fn enviar_lote(tx: &SyncSender<CaptureBatch>, lote: CaptureBatch, shared: &SharedStats) {
    let cantidad = lote.packets.len() as u64;
    match tx.try_send(lote) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            shared.drops.fetch_add(cantidad, Ordering::Relaxed);
        }
    }
}

impl HiloCaptura {
    /// Bucle del hilo: poll del anillo, parseo, inspección, límite de pps y lotes.
    ///
    /// El payload solo vive dentro de `parse_frame`/`inspect`: al hilo del
    /// agregador solo viajan los metadatos y las evidencias derivadas.
    fn ejecutar(mut self) {
        let mut lote = CaptureBatch {
            packets: Vec::with_capacity(BATCH_SIZE),
            evidence: Vec::new(),
        };
        let mut inicio_segundo = Instant::now();
        let mut paquetes_segundo = 0u64;
        let Self {
            socket,
            parser,
            tx,
            shared,
            limitador,
            parar,
            pps,
            inspector,
            identity,
            observed,
            observed_filter,
            observados_vistos,
            contadores_previos,
        } = &mut self;

        while !parar.load(Ordering::Relaxed) {
            let resultado = socket.poll_frames(POLL_TIMEOUT, &mut |trama: &[u8]| {
                shared.total.fetch_add(1, Ordering::Relaxed);
                paquetes_segundo += 1;
                if !limitador.permitir(Instant::now()) {
                    shared.limit_drops.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let ahora = Instant::now();
                match parser.parse_frame(trama) {
                    Ok(ParsedFrame::Ip(paquete)) => {
                        let payload = paquete.payload(trama);
                        let evidencias = inspector.inspect(&paquete.meta, payload, ahora);
                        procesar_evidencias(
                            evidencias,
                            identity,
                            observed,
                            observed_filter,
                            observados_vistos,
                            &mut lote.evidence,
                        );
                        // Equipo observado por una trama IPv4 de la subred local.
                        if let IpAddr::V4(ip) = paquete.meta.src_ip {
                            observar_equipo(
                                paquete.src_mac,
                                ip,
                                ObservedSource::Frame,
                                None,
                                observed,
                                observed_filter,
                                observados_vistos,
                            );
                        }
                        lote.packets.push(paquete.meta);
                    }
                    Ok(ParsedFrame::Arp(marco)) => {
                        if marco.arp.es_peticion_o_respuesta() {
                            observar_equipo(
                                marco.arp.sender_mac,
                                marco.arp.sender_ip,
                                ObservedSource::Arp,
                                None,
                                observed,
                                observed_filter,
                                observados_vistos,
                            );
                        }
                    }
                    Ok(ParsedFrame::Ignorada(_)) => {}
                    Err(error) => {
                        if !error.ignorable {
                            shared.parse_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if lote.packets.len() >= BATCH_SIZE {
                    let datos = std::mem::replace(
                        &mut lote,
                        CaptureBatch {
                            packets: Vec::with_capacity(BATCH_SIZE),
                            evidence: Vec::new(),
                        },
                    );
                    enviar_lote(tx, datos, shared);
                }
            });

            if !lote.packets.is_empty() || !lote.evidence.is_empty() {
                let datos = std::mem::replace(
                    &mut lote,
                    CaptureBatch {
                        packets: Vec::with_capacity(BATCH_SIZE),
                        evidence: Vec::new(),
                    },
                );
                enviar_lote(tx, datos, shared);
            }

            // Temporizadores de los reensamblados y contadores de inferencia.
            inspector.tick(Instant::now());
            let totales = inspector.counters();
            let incremento = InferenceCounters {
                reassembly_drops: totales
                    .reassembly_drops
                    .saturating_sub(contadores_previos.reassembly_drops),
                inference_errors: totales
                    .inference_errors
                    .saturating_sub(contadores_previos.inference_errors),
                quic_errors: totales
                    .quic_errors
                    .saturating_sub(contadores_previos.quic_errors),
                labelled_flows: totales
                    .labelled_flows
                    .saturating_sub(contadores_previos.labelled_flows),
            };
            *contadores_previos = totales;
            shared.acumular_inferencia(&incremento);

            match resultado {
                Ok(salida) => {
                    shared.drops.fetch_add(salida.drops, Ordering::Relaxed);
                }
                Err(error) => {
                    tracing::warn!(interfaz = socket.ifname(), %error, "la captura se ha detenido por un error");
                    break;
                }
            }

            let ahora = Instant::now();
            if ahora.duration_since(inicio_segundo) >= Duration::from_secs(1) {
                pps.store(paquetes_segundo, Ordering::Relaxed);
                paquetes_segundo = 0;
                inicio_segundo = ahora;
            }
        }

        if !lote.packets.is_empty() || !lote.evidence.is_empty() {
            enviar_lote(tx, lote, shared);
        }
        pps.store(0, Ordering::Relaxed);
    }
}

/// Enruta las evidencias: las de equipo/identidad van a los almacenes
/// compartidos y el resto al agregador.
fn procesar_evidencias(
    evidencias: Vec<Evidence>,
    identity: &Arc<Mutex<CaptureIdentityStore>>,
    observed: &Arc<Mutex<ObservedHosts>>,
    observed_filter: &ObservedFilter,
    observados_vistos: &mut HashSet<(String, Ipv4Addr)>,
    destino: &mut Vec<Evidence>,
) {
    for evidencia in evidencias {
        match evidencia {
            Evidence::Host(equipo) => {
                if observados_vistos.insert((equipo.mac.clone(), equipo.ip)) {
                    if let Ok(mut almacen) = observed.lock() {
                        almacen.push(equipo);
                    }
                } else if let Ok(mut almacen) = observed.lock() {
                    // Deduplicación por MAC + IP en el propio buffer.
                    almacen.push(equipo);
                }
            }
            Evidence::Dhcp(identidad) => {
                if let Ok(mut almacen) = identity.lock() {
                    almacen.record_dhcp(identidad);
                }
            }
            Evidence::Flow(flujo) => {
                // El User-Agent de HTTP en claro identifica al equipo cliente.
                if let (Some(ua), Some(ip)) = (flujo.user_agent.clone(), flujo.client_ip) {
                    if let Ok(mut almacen) = identity.lock() {
                        almacen.record_user_agent(ip, ua);
                    }
                }
                destino.push(Evidence::Flow(flujo));
            }
            otra => destino.push(otra),
        }
    }
    let _ = observed_filter;
}

/// Registra un equipo observado si el filtro lo acepta (con dedup local barata).
fn observar_equipo(
    mac: [u8; 6],
    ip: Ipv4Addr,
    origen: ObservedSource,
    dhcp: Option<crate::inference::DhcpObservation>,
    observed: &Arc<Mutex<ObservedHosts>>,
    filtro: &ObservedFilter,
    vistos: &mut HashSet<(String, Ipv4Addr)>,
) {
    if ip.is_unspecified() || ip.is_broadcast() {
        return;
    }
    let equipo = ObservedHost {
        mac: formatear_mac(mac),
        ip,
        source: origen,
        dhcp,
    };
    if !filtro.accepts(&equipo) {
        return;
    }
    if !vistos.insert((equipo.mac.clone(), equipo.ip)) && origen != ObservedSource::Arp {
        return;
    }
    if vistos.len() > 8192 {
        vistos.clear();
    }
    if let Ok(mut almacen) = observed.lock() {
        almacen.push(equipo);
    }
}

/// Captura de tráfico en vivo sobre una o varias interfaces.
#[derive(Debug)]
pub struct Capture {
    receivers: Vec<Receiver<CaptureBatch>>,
    shared: Arc<SharedStats>,
    parar: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
    interfaces: Vec<CaptureInterface>,
    filter: String,
    bpf_error: Option<String>,
}

impl Capture {
    /// Abre un anillo TPACKET_V3 por interfaz y lanza un hilo de captura por cada una.
    ///
    /// Si el filtro BPF no compila se registra un aviso y se captura sin filtro
    /// (el error queda disponible en [Capture::bpf_error]). Si no hay permisos
    /// suficientes (CAP_NET_RAW) devuelve un error claro.
    pub fn start(
        config: &CaptureConfig,
        interfaces: Vec<CaptureInterface>,
        inferencia: CaptureInference,
    ) -> Result<Self> {
        if !config.enabled {
            return Err(Error::Capture(
                "la captura está deshabilitada en la configuración".to_string(),
            ));
        }
        if interfaces.is_empty() {
            return Err(Error::Capture(
                "no hay interfaces disponibles para capturar".to_string(),
            ));
        }

        let (programa, bpf_error) = match config.filter.trim() {
            "" => (None, None),
            expresion => match bpf::compile(expresion) {
                Ok(programa) => (Some(programa), None),
                Err(error) => {
                    tracing::warn!(
                        filtro = expresion,
                        %error,
                        "no se pudo compilar el filtro BPF; se captura sin filtro"
                    );
                    (
                        None,
                        Some(format!(
                            "filtro BPF inválido ({expresion}): {error}; se captura sin filtro"
                        )),
                    )
                }
            },
        };

        // Fase 4: toda la extracción la hace el FlowInspector del hilo de
        // captura; el parser solo decodifica cabeceras y localiza el payload.
        let parser = parser::Parser::new();
        let anillo = RingConfig::default();
        let shared = SharedStats::new(interfaces.len());
        let limitador = Arc::new(PpsLimiter::new(config.max_pps));
        let parar = Arc::new(AtomicBool::new(false));
        let mut receivers = Vec::with_capacity(interfaces.len());
        let mut handles = Vec::with_capacity(interfaces.len());

        for (indice, interfaz) in interfaces.iter().enumerate() {
            let socket = afpacket::AfPacketSocket::open(&interfaz.name, anillo, programa.as_ref())
                .map_err(|error| {
                    Error::Capture(format!(
                        "no se pudo abrir la captura en {}: {error}",
                        interfaz.name
                    ))
                })?;
            let (tx, rx) = sync_channel::<CaptureBatch>(BATCH_CAPACITY);
            let hilo = HiloCaptura {
                socket,
                parser,
                tx,
                shared: Arc::clone(&shared),
                limitador: Arc::clone(&limitador),
                parar: Arc::clone(&parar),
                pps: Arc::clone(&shared.pps[indice]),
                inspector: FlowInspector::new(
                    &inferencia.config,
                    inferencia.local_ips.clone(),
                    Arc::clone(&inferencia.listening),
                ),
                identity: Arc::clone(&inferencia.identity),
                observed: Arc::clone(&inferencia.observed),
                observed_filter: inferencia.observed_filter.clone(),
                observados_vistos: HashSet::new(),
                contadores_previos: InferenceCounters::default(),
            };
            let nombre = format!("almenara-captura-{}", interfaz.name);
            let handle = std::thread::Builder::new()
                .name(nombre)
                .spawn(move || hilo.ejecutar())
                .map_err(|error| {
                    Error::Capture(format!("no se pudo lanzar el hilo de captura: {error}"))
                })?;
            receivers.push(rx);
            handles.push(handle);
        }

        Ok(Self {
            receivers,
            shared,
            parar,
            handles,
            interfaces,
            filter: config.filter.clone(),
            bpf_error,
        })
    }

    /// Paquetes y evidencias capturados desde la última llamada.
    pub fn drain(&self) -> CaptureDrain {
        let mut drenado = CaptureDrain::default();
        for receptor in &self.receivers {
            while let Ok(lote) = receptor.try_recv() {
                drenado.packets.extend(lote.packets);
                drenado.evidence.extend(lote.evidence);
            }
        }
        drenado
    }

    /// Contadores actuales de la captura.
    pub fn stats(&self) -> CaptureStats {
        CaptureStats {
            pps: self.shared.pps_total(),
            total: self.shared.total.load(Ordering::Relaxed),
            drops: self.shared.drops.load(Ordering::Relaxed),
            parse_errors: self.shared.parse_errors.load(Ordering::Relaxed),
            inference: InferenceCounters {
                reassembly_drops: self.shared.reassembly_drops.load(Ordering::Relaxed),
                inference_errors: self.shared.inference_errors.load(Ordering::Relaxed),
                quic_errors: self.shared.quic_errors.load(Ordering::Relaxed),
                labelled_flows: self.shared.labelled_flows.load(Ordering::Relaxed),
            },
        }
    }

    /// Paquetes descartados por el límite max_pps (para el aviso periódico).
    pub fn limit_drops(&self) -> u64 {
        self.shared.limit_drops.load(Ordering::Relaxed)
    }

    /// Interfaces sobre las que se está capturando.
    pub fn interfaces(&self) -> &[CaptureInterface] {
        &self.interfaces
    }

    /// Expresión del filtro configurado (vacía si no hay filtro).
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Error de compilación del filtro BPF, si lo hubo (se captura sin filtro).
    pub fn bpf_error(&self) -> Option<&str> {
        self.bpf_error.as_deref()
    }

    /// Para los hilos de captura y libera los anillos.
    pub fn stop(mut self) -> Result<()> {
        self.parar_ahora();
        Ok(())
    }

    fn parar_ahora(&mut self) {
        self.parar.store(true, Ordering::SeqCst);
        for handle in self.handles.drain(..) {
            if handle.join().is_err() {
                tracing::warn!("un hilo de captura terminó de forma anómala");
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.parar_ahora();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn meta(origen: &str, destino: &str, protocolo: Protocol) -> PacketMeta {
        PacketMeta {
            timestamp: Instant::now(),
            src_ip: origen.parse().expect("IP de origen"),
            dst_ip: destino.parse().expect("IP de destino"),
            src_port: Some(40000),
            dst_port: Some(443),
            protocol: protocolo,
            len: 60,
            tcp_flags: None,
            headers: None,
        }
    }

    #[test]
    fn protocolo_ida_y_vuelta() {
        for protocolo in Protocol::ALL {
            assert_eq!(Protocol::from_str(protocolo.as_str()), Some(protocolo));
        }
        assert_eq!(Protocol::from_str("other"), Some(Protocol::Other));
        assert_eq!(Protocol::from_str("sctp"), None);
        assert_eq!(Protocol::Tcp.label(), "TCP");
    }

    #[test]
    fn flags_tcp_ida_y_vuelta_y_etiqueta() {
        let flags = TcpFlags::from_bits(0x0012);
        assert!(flags.syn && flags.ack);
        assert!(!flags.fin && !flags.rst);
        assert_eq!(flags.to_bits(), 0x0012);
        assert!(flags.label().contains("SYN"));
        assert!(flags.label().contains("ACK"));
        assert_eq!(TcpFlags::default().label(), "");
    }

    #[test]
    fn endpoint_se_formatea_con_corchetes_en_ipv6() {
        let v4 = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)), Some(443));
        assert_eq!(v4.to_string(), "192.168.1.42:443");
        let v6 = Endpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(53));
        assert_eq!(v6.to_string(), "[::1]:53");
        assert_eq!(
            Endpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), None).to_string(),
            "127.0.0.1"
        );
    }

    #[test]
    fn detecta_direcciones_de_broadcast_y_multicast() {
        assert!(es_direccion_broadcast("255.255.255.255".parse().unwrap()));
        assert!(es_direccion_broadcast("224.0.0.251".parse().unwrap()));
        assert!(!es_direccion_broadcast("192.168.1.42".parse().unwrap()));
        assert!(es_direccion_broadcast("ff02::fb".parse().unwrap()));
        assert!(!es_direccion_broadcast("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn packet_meta_usa_el_destino_para_broadcast() {
        let mut paquete = meta("192.168.1.42", "255.255.255.255", Protocol::Udp);
        assert!(paquete.is_broadcast());
        assert!(!paquete.is_ipv6());
        paquete.dst_ip = "ff02::fb".parse().unwrap();
        assert!(paquete.is_broadcast());
        assert!(paquete.is_ipv6());
        assert_eq!(paquete.src().port, Some(40000));
    }

    #[test]
    fn clave_canonica_ordena_los_extremos() {
        let ida = meta("192.168.1.42", "1.1.1.1", Protocol::Tcp);
        let mut vuelta = ida.clone();
        std::mem::swap(&mut vuelta.src_ip, &mut vuelta.dst_ip);
        std::mem::swap(&mut vuelta.src_port, &mut vuelta.dst_port);
        let clave_ida = ConnectionKey::from_packet(&ida);
        let clave_vuelta = ConnectionKey::from_packet(&vuelta);
        assert_eq!(clave_ida, clave_vuelta, "la 5-tuple canónica es única");
        let invertida = clave_ida.inverted();
        assert_eq!(invertida.origin, clave_ida.destination);
        assert_eq!(invertida.destination, clave_ida.origin);
    }

    #[test]
    fn snapshot_de_cabeceras_expone_solo_los_bytes_validos() {
        let mut snapshot = HeaderSnapshot {
            ip_raw_len: 20,
            transport_raw_len: 8,
            ..HeaderSnapshot::default()
        };
        assert_eq!(snapshot.ip_bytes().len(), 20);
        assert_eq!(snapshot.transport_bytes().len(), 8);
        snapshot.ip_raw_len = 200;
        assert_eq!(snapshot.ip_bytes().len(), 40, "se recorta al tamaño fijo");
    }

    #[test]
    fn configuracion_de_anillo_por_defecto_son_64_mb() {
        let anillo = RingConfig::default();
        assert_eq!(anillo.block_size, 1024 * 1024);
        assert_eq!(anillo.block_nr, 64);
        assert_eq!(anillo.frame_size, 4096);
        assert_eq!(anillo.bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn interfaz_de_captura_expone_su_ip() {
        let interfaz = CaptureInterface::new("eth0", Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(
            interfaz.ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
        let sin_ip = CaptureInterface::new("wlan0", None);
        assert_eq!(sin_ip.ip(), None);
    }

    #[test]
    fn parse_frame_localiza_el_payload_y_las_macs() {
        // Ethernet + IPv4 + TCP sin payload: 14 + 20 + 20.
        let mut trama = Vec::new();
        trama.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        trama.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        trama.extend_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[192, 168, 1, 10]);
        ip[16..20].copy_from_slice(&[192, 168, 1, 20]);
        trama.extend_from_slice(&ip);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 5 << 4;
        trama.extend_from_slice(&tcp);
        trama.extend_from_slice(b"HOLA");
        // Ajustamos la longitud total IP a 20 + 20 + 4.
        let total = 44u16.to_be_bytes();
        trama[16..18].copy_from_slice(&total);

        let parser = parser::Parser::with_defaults();
        match parser.parse_frame(&trama).expect("trama parseable") {
            ParsedFrame::Ip(paquete) => {
                assert_eq!(paquete.meta.dst_port, Some(443));
                assert_eq!(formatear_mac(paquete.src_mac), "02:00:00:00:00:01");
                assert_eq!(paquete.payload(&trama), b"HOLA");
            }
            otro => panic!("esperaba una trama IP: {otro:?}"),
        }
    }

    #[test]
    fn parse_frame_reconoce_arp() {
        let mut trama = Vec::new();
        trama.extend_from_slice(&[0xff; 6]); // destino broadcast
        trama.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        trama.extend_from_slice(&0x0806u16.to_be_bytes());
        trama.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
        trama.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        trama.push(6); // hlen
        trama.push(4); // plen
        trama.extend_from_slice(&1u16.to_be_bytes()); // petición
        trama.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        trama.extend_from_slice(&[192, 168, 1, 50]);
        trama.extend_from_slice(&[0x00; 6]);
        trama.extend_from_slice(&[192, 168, 1, 1]);

        let parser = parser::Parser::with_defaults();
        match parser.parse_frame(&trama).expect("ARP parseable") {
            ParsedFrame::Arp(marco) => {
                assert_eq!(marco.arp.opcode, 1);
                assert_eq!(marco.arp.sender_ip, Ipv4Addr::new(192, 168, 1, 50));
                assert_eq!(marco.arp.target_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert!(marco.arp.es_peticion_o_respuesta());
            }
            otro => panic!("esperaba una trama ARP: {otro:?}"),
        }
        // El parser clásico sigue ignorando el ARP sin contarlo como error.
        let error = parser.parse(&trama).expect_err("el ARP no es una conexión");
        assert!(error.ignorable);
    }

    #[test]
    fn red_local_se_deriva_de_ip_y_mascara() {
        let interfaz = CaptureInterface::with_details(
            "eth0",
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            Some("02:00:00:00:00:01".to_string()),
            Some(Ipv4Addr::new(255, 255, 255, 0)),
            Some(Ipv4Addr::new(192, 168, 1, 1)),
        );
        assert_eq!(
            interfaz.red_local(),
            Some((
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(255, 255, 255, 0)
            ))
        );
        assert_eq!(
            formatear_mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
    }
}

/// Replay condicional de un fichero pcap capturado como fixture.
///
/// Solo se compila con la feature no default "pcap" (preparada para F7). Sirve
/// de integración entre el parser, el filtro BPF y la agregación sin necesidad
/// de CAP_NET_RAW ni de red.
#[cfg(all(test, feature = "pcap"))]
mod replay_pcap {
    use super::aggregate::Aggregator;
    use super::{bpf, parser};
    use std::collections::HashMap;
    use std::time::Instant;

    /// Lee las tramas Ethernet de un fichero pcap (little endian, EN10MB).
    fn leer_pcap(contenido: &[u8]) -> Vec<Vec<u8>> {
        assert!(contenido.len() >= 24, "cabecera pcap incompleta");
        let mut tramas = Vec::new();
        let mut posicion = 24;
        while posicion + 16 <= contenido.len() {
            let incl_len = u32::from_le_bytes([
                contenido[posicion + 8],
                contenido[posicion + 9],
                contenido[posicion + 10],
                contenido[posicion + 11],
            ]) as usize;
            posicion += 16;
            if posicion + incl_len > contenido.len() {
                break;
            }
            tramas.push(contenido[posicion..posicion + incl_len].to_vec());
            posicion += incl_len;
        }
        tramas
    }

    #[test]
    fn replay_del_fixture_parsea_filtra_y_agrega() {
        let ruta = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fase3-replay.pcap");
        let contenido = std::fs::read(&ruta).expect("fixture pcap de Fase 3");
        let tramas = leer_pcap(&contenido);
        assert_eq!(tramas.len(), 5, "el fixture tiene cinco tramas");

        let parser = parser::Parser::with_defaults();
        let metas: Vec<_> = tramas
            .iter()
            .map(|trama| parser.parse(trama).expect("trama parseable"))
            .collect();
        assert_eq!(metas[0].protocol, super::Protocol::Tcp);
        assert_eq!(metas[0].dst_port, Some(443));
        assert_eq!(metas[3].protocol, super::Protocol::Udp);
        assert!(metas[4].is_ipv6());

        // El filtro BPF clásico discrimina el tráfico TCP del puerto 443.
        let filtro = bpf::compile("tcp and port 443").expect("filtro válido");
        assert!(filtro.matches(&tramas[0]));
        assert!(!filtro.matches(&tramas[3]));

        // Agregación por dispositivo: .42 envía, 1.1.1.1 recibe.
        let mut aggregator = Aggregator::new(Instant::now());
        let mut mapa = HashMap::new();
        mapa.insert("192.168.1.42".parse().unwrap(), 1_i64);
        mapa.insert("1.1.1.1".parse().unwrap(), 2_i64);
        aggregator.set_devices(&mapa);
        for meta in &metas {
            aggregator.update(meta);
        }
        let snapshot = aggregator.snapshot();
        let dispositivo_1 = snapshot
            .devices
            .iter()
            .find(|device| device.device_id == 1)
            .expect("dispositivo 1 en la agregación");
        let dispositivo_2 = snapshot
            .devices
            .iter()
            .find(|device| device.device_id == 2)
            .expect("dispositivo 2 en la agregación");
        assert!(dispositivo_1.bytes_out > 0);
        assert!(dispositivo_2.bytes_in > 0);
    }
}
