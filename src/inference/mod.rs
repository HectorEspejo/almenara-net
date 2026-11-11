//! Motor de inferencia de la Fase 4: protocolos, nombres, apps y top talkers.
//!
//! El módulo se divide en dos mitades con dueños distintos:
//!
//! - [FlowInspector]: vive en el hilo de captura (uno por interfaz). Recibe los
//!   metadatos y el payload de cada trama, reensambla el inicio de los flujos,
//!   identifica el protocolo de aplicación, extrae SNI, Host, User-Agent, JA4,
//!   respuestas DNS, DHCP y tramas observadas, y devuelve [Evidence].
//!   **Ningún byte de payload sale de este hilo.**
//! - [LabelResolver]: vive en el agregador (tarea de tráfico). Mantiene la caché
//!   de nombres, el catálogo, la base IP y la fuerza de cada etiqueta, y produce
//!   [FlowLabel] para los rankings y para CONNECTIONS.
//!
//! Los extractores puros (protocolos, TLS, HTTP, DNS, JA4, QUIC) y los datos
//! embebidos (catálogo, PSL, DB-IP) viven en los submódulos.

// La fase expone la API completa del checklist (incluidas operaciones que la TUI
// aún no consume); se permite código muerto para no marcar como muerta esa
// superficie pública, igual que en las fases anteriores.
#![allow(dead_code)]

pub mod catalog;
pub mod dns;
pub mod domain;
pub mod http;
pub mod ipdb;
pub mod ja4;
pub mod names;
pub mod protocols;
pub mod quic;
pub mod reassembly;
pub mod role;
pub mod tls;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::capture::{ConnectionKey, PacketMeta, Protocol};
use crate::config::InferenceConfig;

/// Bytes máximos reensamblados en sentido cliente → servidor.
pub const CLIENT_ASSEMBLY_BYTES: usize = 4096;
/// Bytes máximos reensamblados en sentido servidor → cliente.
pub const SERVER_ASSEMBLY_BYTES: usize = 64;
/// Paquetes con datos máximos por reensamblado del inicio de flujo.
pub const MAX_ASSEMBLY_PACKETS: u8 = 8;
/// Tiempo máximo de vida de un reensamblado.
pub const ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(3);
/// Reensamblados simultáneos máximos por interfaz.
pub const MAX_REASSEMBLIES: usize = 1024;
/// Tiempo máximo para recomponer el ClientHello de QUIC (4 Initial o 3 s).
pub const QUIC_MAX_INITIALS: u8 = 4;
/// Longitud máxima de un nombre de servidor (SNI, Host o caché).
pub const MAX_SERVER_NAME: usize = 255;
/// Longitud máxima del User-Agent saneado.
pub const MAX_USER_AGENT: usize = 256;
/// Tiempo que se conserva un flujo ya inspeccionado antes de desalojarlo.
pub const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Transporte de una firma o regla de puerto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum L4 {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl L4 {
    /// Transporte de un paquete capturado, si es TCP o UDP.
    pub fn from_protocol(protocol: Protocol) -> Option<Self> {
        match protocol {
            Protocol::Tcp => Some(Self::Tcp),
            Protocol::Udp => Some(Self::Udp),
            _ => None,
        }
    }

    /// Representación persistida y de reglas del catálogo ("tcp"/"udp").
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Reconstruye el transporte desde "tcp"/"udp".
    pub fn from_str(valor: &str) -> Option<Self> {
        match valor.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// Protocolo de aplicación identificado por firma o por puerto (§7.3).
///
/// Los valores se persisten tal cual en `CONNECTIONS.app_protocol`. Si no hay
/// firma ni puerto conocido se usa el valor del transporte (`tcp`, `udp`,
/// `icmp`, `icmp6`, `other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AppProtocol {
    Dns,
    Mdns,
    Llmnr,
    Netbios,
    Dhcp,
    Dhcpv6,
    Ntp,
    Ssdp,
    Tls,
    Quic,
    Http,
    Http2,
    Ssh,
    Rdp,
    Vnc,
    Smb,
    Ftp,
    Smtp,
    Imap,
    Pop3,
    Mqtt,
    Coap,
    Rtsp,
    Sip,
    Stun,
    Wireguard,
    Openvpn,
    Ipsec,
    Bittorrent,
    Snmp,
    /// Sin firma ni puerto conocido: TCP.
    Tcp,
    /// Sin firma ni puerto conocido: UDP.
    Udp,
    /// ICMP.
    Icmp,
    /// ICMPv6.
    Icmpv6,
    /// Otro protocolo IP.
    Other,
}

impl AppProtocol {
    /// Valor persistido en `CONNECTIONS.app_protocol`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Llmnr => "llmnr",
            Self::Netbios => "netbios",
            Self::Dhcp => "dhcp",
            Self::Dhcpv6 => "dhcpv6",
            Self::Ntp => "ntp",
            Self::Ssdp => "ssdp",
            Self::Tls => "tls",
            Self::Quic => "quic",
            Self::Http => "http",
            Self::Http2 => "http2",
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Smb => "smb",
            Self::Ftp => "ftp",
            Self::Smtp => "smtp",
            Self::Imap => "imap",
            Self::Pop3 => "pop3",
            Self::Mqtt => "mqtt",
            Self::Coap => "coap",
            Self::Rtsp => "rtsp",
            Self::Sip => "sip",
            Self::Stun => "stun",
            Self::Wireguard => "wireguard",
            Self::Openvpn => "openvpn",
            Self::Ipsec => "ipsec",
            Self::Bittorrent => "bittorrent",
            Self::Snmp => "snmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmp6",
            Self::Other => "other",
        }
    }

    /// Reconstruye el protocolo desde su valor persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        Some(match valor {
            "dns" => Self::Dns,
            "mdns" => Self::Mdns,
            "llmnr" => Self::Llmnr,
            "netbios" => Self::Netbios,
            "dhcp" => Self::Dhcp,
            "dhcpv6" => Self::Dhcpv6,
            "ntp" => Self::Ntp,
            "ssdp" => Self::Ssdp,
            "tls" => Self::Tls,
            "quic" => Self::Quic,
            "http" => Self::Http,
            "http2" => Self::Http2,
            "ssh" => Self::Ssh,
            "rdp" => Self::Rdp,
            "vnc" => Self::Vnc,
            "smb" => Self::Smb,
            "ftp" => Self::Ftp,
            "smtp" => Self::Smtp,
            "imap" => Self::Imap,
            "pop3" => Self::Pop3,
            "mqtt" => Self::Mqtt,
            "coap" => Self::Coap,
            "rtsp" => Self::Rtsp,
            "sip" => Self::Sip,
            "stun" => Self::Stun,
            "wireguard" => Self::Wireguard,
            "openvpn" => Self::Openvpn,
            "ipsec" => Self::Ipsec,
            "bittorrent" => Self::Bittorrent,
            "snmp" => Self::Snmp,
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            "icmp6" => Self::Icmpv6,
            "other" => Self::Other,
            _ => return None,
        })
    }

    /// Etiqueta corta para la TUI.
    pub fn label(self) -> &'static str {
        match self {
            Self::Dns | Self::Mdns | Self::Llmnr => "DNS",
            Self::Netbios => "NetBIOS",
            Self::Dhcp | Self::Dhcpv6 => "DHCP",
            Self::Ntp => "NTP",
            Self::Ssdp => "SSDP",
            Self::Tls => "TLS",
            Self::Quic => "QUIC",
            Self::Http | Self::Http2 => "HTTP",
            Self::Ssh => "SSH",
            Self::Rdp => "RDP",
            Self::Vnc => "VNC",
            Self::Smb => "SMB",
            Self::Ftp => "FTP",
            Self::Smtp => "SMTP",
            Self::Imap => "IMAP",
            Self::Pop3 => "POP3",
            Self::Mqtt => "MQTT",
            Self::Coap => "CoAP",
            Self::Rtsp => "RTSP",
            Self::Sip => "SIP",
            Self::Stun => "STUN",
            Self::Wireguard => "WireGuard",
            Self::Openvpn => "OpenVPN",
            Self::Ipsec => "IPsec",
            Self::Bittorrent => "BitTorrent",
            Self::Snmp => "SNMP",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Other => "otros",
        }
    }

    /// Protocolo genérico del transporte, sin firma conocida.
    pub fn transport_fallback(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Tcp => Self::Tcp,
            Protocol::Udp => Self::Udp,
            Protocol::Icmp => Self::Icmp,
            Protocol::Icmpv6 => Self::Icmpv6,
            Protocol::Other => Self::Other,
        }
    }

    /// Todos los valores, para pruebas de ida y vuelta.
    pub const ALL: [Self; 35] = [
        Self::Dns,
        Self::Mdns,
        Self::Llmnr,
        Self::Netbios,
        Self::Dhcp,
        Self::Dhcpv6,
        Self::Ntp,
        Self::Ssdp,
        Self::Tls,
        Self::Quic,
        Self::Http,
        Self::Http2,
        Self::Ssh,
        Self::Rdp,
        Self::Vnc,
        Self::Smb,
        Self::Ftp,
        Self::Smtp,
        Self::Imap,
        Self::Pop3,
        Self::Mqtt,
        Self::Coap,
        Self::Rtsp,
        Self::Sip,
        Self::Stun,
        Self::Wireguard,
        Self::Openvpn,
        Self::Ipsec,
        Self::Bittorrent,
        Self::Snmp,
        Self::Tcp,
        Self::Udp,
        Self::Icmp,
        Self::Icmpv6,
        Self::Other,
    ];
}

/// Fuente del nombre de un servidor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameSource {
    /// Respuesta DNS (A/AAAA/CNAME).
    Dns,
    /// SNI de un ClientHello TLS o QUIC.
    Sni,
    /// Cabecera Host de una petición HTTP/1.x en claro.
    Http,
    /// Nombre procedente de la caché IP → nombre (solo para `CONNECTIONS.name_source`).
    Cache,
}

impl NameSource {
    /// Valor persistido en `CONNECTIONS.name_source` y en `NAME_CACHE.source`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Sni => "sni",
            Self::Http => "http",
            Self::Cache => "cache",
        }
    }

    /// Reconstruye la fuente desde su valor persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        match valor {
            "dns" => Some(Self::Dns),
            "sni" => Some(Self::Sni),
            "http" => Some(Self::Http),
            "cache" => Some(Self::Cache),
            _ => None,
        }
    }

    /// Etiqueta visible en el panel de detalle.
    pub fn label(self) -> &'static str {
        match self {
            Self::Dns => "DNS",
            Self::Sni => "SNI",
            Self::Http => "HTTP",
            Self::Cache => "caché",
        }
    }
}

/// Fuente de la app de una conexión (§7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AppSource {
    /// Regla por dominio del catálogo (nombre SNI/Host o caché).
    Domain,
    /// Servicio de F2 en un flujo dentro de la LAN.
    LanService,
    /// Regla por ASN del catálogo.
    Asn,
    /// Regla por puerto/protocolo del catálogo.
    Port,
}

impl AppSource {
    /// Valor persistido en `CONNECTIONS.app_source`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::LanService => "lan_service",
            Self::Asn => "asn",
            Self::Port => "port",
        }
    }

    /// Reconstruye la fuente desde su valor persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        match valor {
            "domain" => Some(Self::Domain),
            "lan_service" => Some(Self::LanService),
            "asn" => Some(Self::Asn),
            "port" => Some(Self::Port),
            _ => None,
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Domain => "dominio",
            Self::LanService => "servicio LAN",
            Self::Asn => "ASN",
            Self::Port => "puerto",
        }
    }

    /// Fuerza de la etiqueta según la tabla de §7.8.
    pub fn strength(self, name_source: Option<NameSource>) -> u8 {
        match self {
            Self::Domain => match name_source {
                Some(NameSource::Sni) | Some(NameSource::Http) => 5,
                Some(NameSource::Cache) => 4,
                _ => 4,
            },
            Self::LanService => 3,
            Self::Asn => 2,
            Self::Port => 1,
        }
    }
}

/// Tipo de clave de destino de los rankings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestinationKind {
    /// Dominio registrable obtenido del nombre del servidor.
    Domain,
    /// Dirección IP remota sin nombre.
    Ip,
    /// Equipo de la LAN (clave `lan:<device_id>`).
    Lan,
}

/// Destino resuelto de un flujo (§7.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationInfo {
    /// Clave del ranking de destinos.
    pub key: String,
    /// Texto visible (dominio, IP o nombre del equipo de la LAN).
    pub label: String,
    /// Organización (ASN) si la IP es de Internet.
    pub org: Option<String>,
    /// País (ISO 3166-1 alfa-2) si la IP es de Internet.
    pub country: Option<String>,
    /// Cómo se construyó la clave.
    pub kind: DestinationKind,
}

impl DestinationInfo {
    /// Destino vacío para un flujo sin resolver.
    pub fn unknown(ip: IpAddr) -> Self {
        Self {
            key: ip.to_string(),
            label: ip.to_string(),
            org: None,
            country: None,
            kind: DestinationKind::Ip,
        }
    }

    /// Texto "Organización · país" o "red local" para la TUI.
    pub fn subtitle(&self) -> String {
        match (&self.org, &self.country) {
            (Some(org), Some(pais)) => format!("{org} · {pais}"),
            (Some(org), None) => org.clone(),
            (None, Some(pais)) => pais.clone(),
            (None, None) => {
                if self.kind == DestinationKind::Lan {
                    "red local".to_string()
                } else {
                    String::new()
                }
            }
        }
    }
}

/// Etiqueta resuelta de un flujo, tal y como se persiste y se pinta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowLabel {
    /// Protocolo de aplicación (firma o puerto).
    pub app_protocol: Option<AppProtocol>,
    /// Nombre del servidor normalizado.
    pub server_name: Option<String>,
    /// Fuente del nombre (SNI > Host > caché).
    pub name_source: Option<NameSource>,
    /// Clave de app del catálogo; `None` = sin identificar.
    pub app: Option<String>,
    /// Clave de categoría del catálogo.
    pub category: Option<String>,
    /// Fuente de la app.
    pub app_source: Option<AppSource>,
    /// Huella JA4 del cliente (t… o q…).
    pub ja4: Option<String>,
    /// `Some(true)` = el extremo origen canónico es el cliente.
    pub client_is_src: Option<bool>,
    /// Fuerza de la etiqueta (0 = sin identificar).
    pub strength: u8,
    /// Destino resuelto (clave y metadatos del ranking).
    pub destination: DestinationInfo,
}

impl FlowLabel {
    /// Etiqueta vacía para un flujo nuevo: solo el destino por IP.
    pub fn empty(ip: IpAddr) -> Self {
        Self {
            app_protocol: None,
            server_name: None,
            name_source: None,
            app: None,
            category: None,
            app_source: None,
            ja4: None,
            client_is_src: None,
            strength: 0,
            destination: DestinationInfo::unknown(ip),
        }
    }

    /// Nombre a mostrar en Conexiones: nombre del servidor o IP del destino.
    pub fn server_display(&self) -> &str {
        self.server_name
            .as_deref()
            .unwrap_or(self.destination.label.as_str())
    }

    /// Indica si la etiqueta tiene app.
    pub fn identified(&self) -> bool {
        self.app.is_some() || self.app_protocol.is_some()
    }
}

/// Observación IP → nombre que alimenta la caché (§7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameObservation {
    /// IP del servidor.
    pub ip: IpAddr,
    /// Nombre observado o consultado.
    pub name: String,
    /// Fuente de la observación.
    pub source: NameSource,
    /// IP del equipo que hizo la consulta, si se conoce.
    pub requester: Option<IpAddr>,
    /// TTL sugerido en segundos (la caché lo acota a 1 h–24 h para DNS).
    pub ttl_seconds: Option<u64>,
}

/// Identidad DHCP capturada de un equipo (§7.12).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpObservation {
    /// MAC del cliente (chaddr).
    pub mac: Option<String>,
    /// IP del cliente (ciaddr o yiaddr).
    pub ip: Option<IpAddr>,
    /// Tipo de mensaje DHCP (1-13).
    pub message_type: Option<u8>,
    /// Opción 55: lista de parámetros en decimal separada por comas, en su orden.
    pub fingerprint: Option<String>,
    /// Opción 60 saneada.
    pub vendor: Option<String>,
    /// Opción 12 saneada.
    pub hostname: Option<String>,
    /// Opción 61 (client identifier), saneada.
    pub client_id: Option<String>,
}

/// Origen de un equipo observado en la captura (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservedSource {
    /// Trama ARP.
    Arp,
    /// Paquete DHCP.
    Dhcp,
    /// Trama IPv4 con MAC e IP de la subred local.
    Frame,
}

impl ObservedSource {
    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Arp => "ARP",
            Self::Dhcp => "DHCP",
            Self::Frame => "trama",
        }
    }
}

/// Equipo observado en la captura (fuente L2 de F4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHost {
    /// MAC normalizada del equipo.
    pub mac: String,
    /// IPv4 observada.
    pub ip: std::net::Ipv4Addr,
    /// Origen de la observación.
    pub source: ObservedSource,
    /// Identidad DHCP si la observación viene de un paquete DHCP.
    pub dhcp: Option<DhcpObservation>,
}

/// Evidencia extraída por el inspector de un flujo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEvidence {
    /// Clave canónica del flujo.
    pub key: ConnectionKey,
    /// Protocolo de aplicación (firma o puerto).
    pub app_protocol: Option<AppProtocol>,
    /// SNI (normalizado) del ClientHello TLS.
    pub sni: Option<String>,
    /// Host de una petición HTTP/1.x en claro.
    pub http_host: Option<String>,
    /// User-Agent de una petición HTTP/1.x en claro (saneado y truncado).
    pub user_agent: Option<String>,
    /// Huella JA4 del cliente.
    pub ja4: Option<String>,
    /// Rol inferido: `Some(true)` si el origen canónico es el cliente.
    pub client_is_src: Option<bool>,
    /// IP del cliente, si se dedujo.
    pub client_ip: Option<IpAddr>,
    /// IP del servidor, si se dedujo.
    pub server_ip: Option<IpAddr>,
    /// El flujo es QUIC (para marcar los paquetes siguientes).
    pub quic: bool,
}

impl FlowEvidence {
    /// Evidencia mínima para un flujo: solo su clave.
    pub fn empty(key: ConnectionKey) -> Self {
        Self {
            key,
            app_protocol: None,
            sni: None,
            http_host: None,
            user_agent: None,
            ja4: None,
            client_is_src: None,
            client_ip: None,
            server_ip: None,
            quic: false,
        }
    }
}

/// Evidencia que el hilo de captura manda al agregador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// Datos de un flujo (protocolo, nombre, JA4, rol).
    Flow(FlowEvidence),
    /// Observación IP → nombre para la caché.
    Name(NameObservation),
    /// Equipo observado en la captura (ARP, DHCP o trama).
    Host(ObservedHost),
    /// Identidad DHCP de un equipo.
    Dhcp(DhcpObservation),
}

/// Contadores del motor de inferencia.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InferenceCounters {
    /// Reensamblados descartados por el tope de flujos simultáneos.
    pub reassembly_drops: u64,
    /// Entradas mal formadas descartadas sin detener la captura.
    pub inference_errors: u64,
    /// Paquetes QUIC Initial descartados (versión desconocida o descifrado fallido).
    pub quic_errors: u64,
    /// Flujos en los que se extrajo alguna etiqueta.
    pub labelled_flows: u64,
}

impl InferenceCounters {
    /// Suma los contadores de otra instancia.
    pub fn add(&mut self, other: &Self) {
        self.reassembly_drops = self.reassembly_drops.saturating_add(other.reassembly_drops);
        self.inference_errors = self.inference_errors.saturating_add(other.inference_errors);
        self.quic_errors = self.quic_errors.saturating_add(other.quic_errors);
        self.labelled_flows = self.labelled_flows.saturating_add(other.labelled_flows);
    }
}

/// Estado de un flujo durante su inspección (hilo de captura).
#[derive(Debug, Clone)]
pub struct FlowState {
    /// Clave canónica del flujo.
    pub key: ConnectionKey,
    /// Primer paquete visto.
    pub first_seen: Instant,
    /// El flujo acaba de crearse.
    pub is_new: bool,
    /// Transporte de la firma.
    pub l4: Option<L4>,
    /// Protocolo de aplicación ya identificado.
    pub app_protocol: Option<AppProtocol>,
    /// Rol inferido.
    pub client_is_src: Option<bool>,
    /// Flujo marcado como QUIC.
    pub quic: bool,
}

/// Estado de inspección por interfaz (hilo de captura).
///
/// Mantiene los reensamblados del inicio de cada flujo TCP y las tramas CRYPTO
/// de QUIC. Los buffers viven y mueren aquí: nunca salen del hilo.
#[derive(Debug)]
pub struct FlowInspector {
    config: InferenceConfig,
    local_ips: HashSet<IpAddr>,
    listening: Arc<RwLock<role::ListenSet>>,
    flows: HashMap<ConnectionKey, InspectedFlow>,
    counters: InferenceCounters,
}

/// Estado interno de un flujo en inspección.
#[derive(Debug)]
struct InspectedFlow {
    state: Option<FlowState>,
    c2s: reassembly::StreamStart,
    s2c: reassembly::StreamStart,
    quic: reassembly::CryptoStream,
    last_seen: Instant,
    first_data: Option<Instant>,
    packets_with_data: u8,
    /// Dirección del primer paquete con datos: `true` si el origen canónico era
    /// el cliente. Solo es una suposición hasta que se conoce el rol.
    client_guess: Option<bool>,
    labelled: bool,
    protocol_done: bool,
    tls_done: bool,
    http_done: bool,
    dns_done: bool,
    quic_done: bool,
    role_done: bool,
}

impl Default for InspectedFlow {
    fn default() -> Self {
        Self {
            state: None,
            c2s: reassembly::StreamStart::client(),
            s2c: reassembly::StreamStart::server(),
            quic: reassembly::CryptoStream::default(),
            last_seen: Instant::now(),
            first_data: None,
            packets_with_data: 0,
            client_guess: None,
            labelled: false,
            protocol_done: false,
            tls_done: false,
            http_done: false,
            dns_done: false,
            quic_done: false,
            role_done: false,
        }
    }
}

impl FlowInspector {
    /// Crea el inspector de una interfaz.
    pub fn new(
        config: &InferenceConfig,
        local_ips: HashSet<IpAddr>,
        listening: Arc<RwLock<role::ListenSet>>,
    ) -> Self {
        Self {
            config: config.clone(),
            local_ips,
            listening,
            flows: HashMap::new(),
            counters: InferenceCounters::default(),
        }
    }

    /// Indica si la inferencia está activa.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Inspecciona un paquete capturado y devuelve las evidencias extraídas.
    pub fn inspect(&mut self, meta: &PacketMeta, payload: &[u8], now: Instant) -> Vec<Evidence> {
        self.inspect_impl(meta, payload, now)
    }

    /// Avanza los temporizadores y libera reensamblados caducados.
    pub fn tick(&mut self, now: Instant) {
        self.tick_impl(now)
    }

    /// Contadores de la interfaz.
    pub fn counters(&self) -> InferenceCounters {
        self.counters
    }

    /// Acceso mutable a los contadores (módulo interno).
    fn counters_mut(&mut self) -> &mut InferenceCounters {
        &mut self.counters
    }
}

/// Resuelve etiquetas y alimenta la caché de nombres (agregador).
#[derive(Debug)]
pub struct LabelResolver {
    config: InferenceConfig,
    names: names::NameCache,
    catalog: catalog::Catalog,
    ipdb: Option<ipdb::IpDb>,
    local_ips: HashSet<IpAddr>,
    devices: HashMap<IpAddr, (i64, String)>,
    services: HashMap<(IpAddr, u16), Vec<String>>,
    labels: HashMap<ConnectionKey, FlowLabel>,
    ip_info: HashMap<IpAddr, Option<ipdb::IpInfo>>,
}

impl LabelResolver {
    /// Crea el resolutor con el catálogo, la base IP y la caché de nombres.
    pub fn new(
        config: &InferenceConfig,
        catalog: catalog::Catalog,
        ipdb: Option<ipdb::IpDb>,
        local_ips: HashSet<IpAddr>,
    ) -> Self {
        Self {
            config: config.clone(),
            names: names::NameCache::new(names::MAX_NAMES),
            catalog,
            ipdb,
            local_ips,
            devices: HashMap::new(),
            services: HashMap::new(),
            labels: HashMap::new(),
            ip_info: HashMap::new(),
        }
    }

    /// Resuelve la etiqueta de un flujo a partir de una evidencia (§7.8).
    pub fn resolve(&mut self, key: &ConnectionKey, ev: &FlowEvidence) -> FlowLabel {
        crate::inference::resolver::resolve(self, key, ev)
    }

    /// Alimenta la caché de nombres con una observación.
    pub fn observe_name(&mut self, obs: NameObservation) {
        crate::inference::resolver::observe_name(self, obs)
    }

    /// Etiqueta vigente de un flujo; si aún no se conoce, devuelve una vacía.
    pub fn label(&self, key: &ConnectionKey) -> Option<&FlowLabel> {
        self.labels.get(key)
    }

    /// Etiqueta de un flujo para sumar sus bytes a los rankings.
    ///
    /// La primera vez resuelve la etiqueta débil (nombre en caché, ASN, servicio
    /// de F2 o puerto) y la guarda; las siguientes es una búsqueda directa.
    pub fn label_for(&mut self, key: &ConnectionKey) -> &FlowLabel {
        crate::inference::resolver::label_for(self, key)
    }

    /// Entradas nuevas o refrescadas de la caché de nombres (para persistir).
    pub fn take_dirty_names(&mut self) -> Vec<names::NameEntry> {
        self.names.take_dirty()
    }

    /// Purga las entradas caducadas de la caché de nombres.
    pub fn prune_names(&mut self, now: std::time::SystemTime) -> usize {
        self.names.prune(now)
    }

    /// Indica si la inferencia está activa.
    pub fn inference_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Catálogo cargado.
    pub fn catalog(&self) -> &catalog::Catalog {
        &self.catalog
    }

    /// Base IP embebida, si se pudo abrir.
    pub fn ipdb(&self) -> Option<&ipdb::IpDb> {
        self.ipdb.as_ref()
    }

    /// Caché de nombres.
    pub fn names(&self) -> &names::NameCache {
        &self.names
    }

    /// Caché de nombres mutable.
    pub fn names_mut(&mut self) -> &mut names::NameCache {
        &mut self.names
    }

    /// Actualiza el mapa IP → equipo de la LAN.
    pub fn set_devices(&mut self, devices: &[(IpAddr, i64, String)]) {
        self.devices = devices
            .iter()
            .map(|(ip, id, nombre)| (*ip, (*id, nombre.clone())))
            .collect();
        self.labels.clear();
    }

    /// Actualiza los servicios de F2 por IP y puerto.
    pub fn set_services(&mut self, services: HashMap<(IpAddr, u16), Vec<String>>) {
        self.services = services;
        self.labels.clear();
    }

    /// Consulta (con caché) la organización y país de una IP.
    pub fn ip_info(&mut self, ip: IpAddr) -> Option<ipdb::IpInfo> {
        crate::inference::resolver::ip_info(self, ip)
    }
}

mod inspector;
mod resolver;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocolos_ida_y_vuelta() {
        for protocolo in AppProtocol::ALL {
            assert_eq!(
                AppProtocol::from_str(protocolo.as_str()),
                Some(protocolo),
                "{}",
                protocolo.as_str()
            );
        }
        assert_eq!(AppProtocol::from_str("otro"), None);
    }

    #[test]
    fn fuentes_y_fuerzas() {
        assert_eq!(NameSource::from_str("sni"), Some(NameSource::Sni));
        assert_eq!(
            AppSource::from_str("lan_service"),
            Some(AppSource::LanService)
        );
        assert_eq!(AppSource::Domain.strength(Some(NameSource::Sni)), 5);
        assert_eq!(AppSource::Domain.strength(Some(NameSource::Dns)), 4);
        assert_eq!(AppSource::LanService.strength(None), 3);
        assert_eq!(AppSource::Asn.strength(None), 2);
        assert_eq!(AppSource::Port.strength(None), 1);
    }

    #[test]
    fn etiqueta_vacia_y_destino() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let etiqueta = FlowLabel::empty(ip);
        assert!(!etiqueta.identified());
        assert_eq!(etiqueta.server_display(), "1.2.3.4");
        assert_eq!(etiqueta.destination.kind, DestinationKind::Ip);
    }

    #[test]
    fn carga_de_catalogo_y_bases_ip_es_rapida() {
        // NFR §8: catálogo y MMDB abiertos en menos de 200 ms al arrancar.
        let inicio = Instant::now();
        let (catalogo, avisos) = catalog::Catalog::load(catalog::EMBEDDED, None);
        let base = ipdb::IpDb::embedded().expect("bases DB-IP embebidas");
        let transcurrido = inicio.elapsed();
        assert!(
            catalogo.counts().embedded_apps >= 150,
            "apps embebidas: {}",
            catalogo.counts().embedded_apps
        );
        assert!(avisos.is_empty(), "avisos del catálogo: {avisos:?}");
        assert!(base.lookup("8.8.8.8".parse().unwrap()).is_some());
        eprintln!("carga catálogo + MMDB: {transcurrido:?}");
        assert!(
            transcurrido < Duration::from_millis(200),
            "carga demasiado lenta: {transcurrido:?}"
        );
    }

    #[test]
    fn los_datos_embebidos_caben_en_el_presupuesto() {
        // NFR §8: como mucho 25 MB más de binario por los datos embebidos.
        let total = catalog::EMBEDDED.len() as u64 + ipdb::BYTES_EMBEBIDOS;
        eprintln!("datos embebidos: {} bytes", total);
        assert!(
            total <= 25 * 1024 * 1024,
            "los datos embebidos ocupan {total} bytes"
        );
    }

    #[test]
    fn transporte_desde_protocolo() {
        assert_eq!(L4::from_protocol(Protocol::Tcp), Some(L4::Tcp));
        assert_eq!(L4::from_protocol(Protocol::Udp), Some(L4::Udp));
        assert_eq!(L4::from_protocol(Protocol::Icmp), None);
        assert_eq!(L4::from_str("udp"), Some(L4::Udp));
    }
}
