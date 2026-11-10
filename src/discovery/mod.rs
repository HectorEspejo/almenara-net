//! Orquestación del descubrimiento avanzado de la Fase 2.
//!
//! Este módulo agrupa las fuentes de descubrimiento y los listeners de larga
//! vida. El ciclo completo lo compone crate::scanner:
//!
//! 1. Fase pasiva (siempre): se drenan los listeners mDNS y SSDP, se leen los
//!    leases DHCP y se consulta NetBIOS a los equipos ya vistos por L2.
//! 2. Fase activa (solo si !passive_only && CAP_NET_RAW): browse mDNS,
//!    M-SEARCH SSDP, descarga del XML de descripción, port scan TCP CONNECT,
//!    banner grabbing y fingerprint de SO, únicamente para los equipos que
//!    toca reescanear en este ciclo.
//!
//! Los listeners se arrancan una sola vez (DiscoveryState) y se drenan en cada
//! ciclo; los errores de arranque no abortan la aplicación (modo degradado).

pub mod banner;
pub mod dhcp;
pub mod fingerprint;
pub mod mdns;
pub mod netbios;
pub mod portscan;
pub mod ssdp;

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;

use crate::classify::{self, OsFamily, ServiceKind};
use crate::error::Result;
use crate::repo::Protocol;

use banner::BannerGrab;
use dhcp::{DhcpLeases, Lease};
use fingerprint::{Fingerprint, TcpFingerprint};
use mdns::{MdnsListener, MdnsQuery, MdnsRecord};
use netbios::{Netbios, NetbiosInfo};
use portscan::PortScan;
use ssdp::{SsdpListener, SsdpQuery, SsdpRecord, UpnpDescription};

/// Timeout del browse activo mDNS (en dos etapas: tipos e instancias).
pub const MDNS_BROWSE_TIMEOUT: Duration = Duration::from_secs(4);
/// Timeout del M-SEARCH activo SSDP.
pub const SSDP_SEARCH_TIMEOUT: Duration = Duration::from_secs(2);
/// Timeout de la descarga del XML de descripción UPnP.
pub const SSDP_FETCH_TIMEOUT: Duration =
    Duration::from_millis(crate::config::DEFAULT_SSDP_FETCH_TIMEOUT_MS);
/// Timeout de la consulta NetBIOS.
pub const NETBIOS_TIMEOUT: Duration =
    Duration::from_millis(crate::config::DEFAULT_NETBIOS_TIMEOUT_MS);
/// Timeout por puerto del port scan.
pub const PORTSCAN_TIMEOUT: Duration =
    Duration::from_millis(crate::config::DEFAULT_PORTSCAN_TIMEOUT_MS);
/// Timeout del banner grabbing.
pub const BANNER_TIMEOUT: Duration =
    Duration::from_millis(crate::config::DEFAULT_BANNER_TIMEOUT_MS);
/// Concurrencia del port scan dentro de un equipo.
pub const PORTSCAN_CONCURRENCY: usize = 64;
/// Máximo de equipos escaneados por ciclo.
pub const MAX_PORTSCAN_HOSTS: usize = 1024;
/// Máximo de XML de descripción UPnP descargados por ciclo.
pub const MAX_SSDP_DESCRIPTIONS: usize = 16;
/// Concurrencia de las descargas UPnP.
pub const SSDP_FETCH_CONCURRENCY: usize = 4;
/// Concurrencia de los banners por equipo.
pub const BANNER_CONCURRENCY: usize = 8;
/// Concurrencia de equipos escaneados a la vez.
pub const HOST_SCAN_CONCURRENCY: usize = 4;
/// Concurrencia de consultas NetBIOS.
pub const NETBIOS_CONCURRENCY: usize = 16;

/// Servicio detectado por una fuente de Fase 2, antes de persistirse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedService {
    /// Puerto.
    pub port: u16,
    /// Protocolo de transporte.
    pub protocol: Protocol,
    /// Servicio identificado, si se conoce.
    pub service: Option<ServiceKind>,
    /// Banner saneado, si se obtuvo.
    pub banner: Option<String>,
}

/// Resultado del escaneo activo de un equipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostActiveScan {
    /// MAC del equipo.
    pub mac: String,
    /// IPv4 del equipo.
    pub ip: Ipv4Addr,
    /// Servicios detectados.
    pub services: Vec<DetectedService>,
    /// Familia de SO estimada (None si no supera el umbral).
    pub os_family: Option<OsFamily>,
    /// JSON del último fingerprint observado.
    pub last_fingerprint: Option<String>,
    /// Indica si se intentó fingerprint (para poder limpiar os_family si falla).
    pub fingerprint_attempted: bool,
    /// Errores no fatales.
    pub errors: Vec<String>,
}

/// Descripción UPnP asociada a la IP que la anunció.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpnpDevice {
    /// IP del dispositivo que respondió al M-SEARCH.
    pub ip: Ipv4Addr,
    /// Descripción descargada del LOCATION.
    pub description: UpnpDescription,
}

/// Datos pasivos recogidos en un ciclo.
#[derive(Debug, Clone, Default)]
pub struct PassiveData {
    /// Registros mDNS drenados del listener.
    pub mdns: Vec<MdnsRecord>,
    /// Mensajes SSDP drenados del listener.
    pub ssdp: Vec<SsdpRecord>,
    /// Leases DHCP leídos.
    pub leases: Vec<Lease>,
    /// Errores no fatales.
    pub errors: Vec<String>,
}

/// Resultado de las consultas activas del ciclo (mDNS browse, M-SEARCH y UPnP).
#[derive(Debug, Clone, Default)]
pub struct ActiveQueries {
    /// Registros mDNS del browse activo.
    pub mdns: Vec<MdnsRecord>,
    /// Respuestas del M-SEARCH activo.
    pub ssdp: Vec<SsdpRecord>,
    /// Descripciones UPnP descargadas.
    pub upnp: Vec<UpnpDevice>,
    /// Errores no fatales.
    pub errors: Vec<String>,
}

/// Estado de los listeners pasivos de larga vida.
#[derive(Debug, Default)]
pub struct DiscoveryState {
    mdns: Option<MdnsListener>,
    ssdp: Option<SsdpListener>,
}

impl DiscoveryState {
    /// Arranca los listeners pasivos uniéndose al grupo en las interfaces dadas.
    ///
    /// Se unen explícitamente por interfaz: unir con INADDR_ANY puede no recibir
    /// el multicast de la red en algunos sistemas (verificado en Wi-Fi).
    pub fn start_on(interfaces: &[Ipv4Addr]) -> Self {
        let mdns = match MdnsListener::start_on(interfaces) {
            Ok(listener) => Some(listener),
            Err(err) => {
                tracing::warn!(%err, "no se pudo arrancar el listener mDNS; se continúa sin él");
                None
            }
        };
        let ssdp = match SsdpListener::start_on(interfaces) {
            Ok(listener) => Some(listener),
            Err(err) => {
                tracing::warn!(%err, "no se pudo arrancar el listener SSDP; se continúa sin él");
                None
            }
        };
        Self { mdns, ssdp }
    }

    /// Arranca los listeners sin interfaz explícita (INADDR_ANY).
    ///
    /// API de compatibilidad; la orquestación usa [DiscoveryState::start_on]
    /// para unir el multicast en las interfaces concretas del equipo.
    #[allow(dead_code)]
    pub fn start() -> Self {
        Self::start_on(&[])
    }

    /// Estado sin listeners (pruebas de integración sin red).
    #[cfg(test)]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Drena los buffers de los listeners y devuelve los registros nuevos.
    pub fn drain(&mut self) -> (Vec<MdnsRecord>, Vec<SsdpRecord>) {
        let mdns = self
            .mdns
            .as_mut()
            .map(|listener| listener.drain())
            .unwrap_or_default();
        let ssdp = self
            .ssdp
            .as_mut()
            .map(|listener| listener.drain())
            .unwrap_or_default();
        (mdns, ssdp)
    }
}

impl PassiveData {
    /// Recoge los datos pasivos del ciclo: listeners + leases DHCP.
    pub fn collect(state: &mut DiscoveryState, lease_paths: &[PathBuf]) -> Self {
        let (mdns, ssdp) = state.drain();
        let mut errors = Vec::new();
        let leases = match DhcpLeases::read_all(lease_paths) {
            Ok(leases) => leases,
            Err(err) => {
                errors.push(format!("No se pudieron leer los leases DHCP: {err}"));
                Vec::new()
            }
        };
        Self {
            mdns,
            ssdp,
            leases,
            errors,
        }
    }
}

/// Consulta NetBIOS a los equipos dados, con concurrencia limitada.
///
/// El fallo es silencioso (solo se registra en debug): un equipo que no responde
/// a NBNS es lo normal y no debe generar avisos visibles.
pub async fn query_netbios(
    hosts: &[(String, Ipv4Addr)],
    timeout: Duration,
    concurrency: usize,
) -> HashMap<String, NetbiosInfo> {
    if hosts.is_empty() {
        return HashMap::new();
    }
    let limite = concurrency.max(1);
    let resultados: Vec<(String, NetbiosInfo)> = futures::stream::iter(hosts.iter().cloned())
        .map(|(mac, ip)| async move {
            match Netbios::query_name(ip, timeout).await {
                Ok(info) => Some((mac, info)),
                Err(err) => {
                    tracing::debug!(%ip, %err, "consulta NetBIOS sin respuesta");
                    None
                }
            }
        })
        .buffer_unordered(limite)
        .filter_map(|resultado| async move { resultado })
        .collect()
        .await;
    resultados.into_iter().collect()
}

/// Ejecuta las consultas activas del ciclo: browse mDNS, M-SEARCH y XML UPnP.
///
/// Las consultas se envían por cada interfaz indicada (normalmente una): fijar
/// la interfaz de salida del multicast es necesario para que lleguen a la red.
pub async fn run_active_queries(interfaces: &[Ipv4Addr]) -> ActiveQueries {
    let mut errors = Vec::new();
    let interfaces: Vec<Ipv4Addr> = if interfaces.is_empty() {
        vec![Ipv4Addr::UNSPECIFIED]
    } else {
        interfaces.to_vec()
    };
    let porcion = MDNS_BROWSE_TIMEOUT / interfaces.len().max(1) as u32;
    let mut mdns_resultado: Result<Vec<MdnsRecord>> = Ok(Vec::new());
    let mut ssdp_resultado: Result<Vec<SsdpRecord>> = Ok(Vec::new());
    for interface in &interfaces {
        let mdns = MdnsQuery::discover_services_on(*interface, porcion).await;
        let ssdp = SsdpQuery::m_search_on(*interface, "ssdp:all", SSDP_SEARCH_TIMEOUT).await;
        match (mdns_resultado, mdns) {
            (Ok(mut acumulado), Ok(nuevos)) => {
                acumulado.extend(nuevos);
                mdns_resultado = Ok(acumulado);
            }
            (Ok(_), Err(err)) => mdns_resultado = Err(err),
            (Err(err), _) => mdns_resultado = Err(err),
        }
        match (ssdp_resultado, ssdp) {
            (Ok(mut acumulado), Ok(nuevos)) => {
                acumulado.extend(nuevos);
                ssdp_resultado = Ok(acumulado);
            }
            (Ok(_), Err(err)) => ssdp_resultado = Err(err),
            (Err(err), _) => ssdp_resultado = Err(err),
        }
    }

    let mdns = match mdns_resultado {
        Ok(registros) => registros,
        Err(err) => {
            errors.push(format!("El browse mDNS activo falló: {err}"));
            Vec::new()
        }
    };
    let ssdp = match ssdp_resultado {
        Ok(registros) => registros,
        Err(err) => {
            errors.push(format!("El M-SEARCH SSDP activo falló: {err}"));
            Vec::new()
        }
    };

    // Descarga del XML de descripción: solo http/https, sin redirecciones y con
    // timeout; un LOCATION inaccesible solo genera un aviso en el log.
    let mut localizaciones: Vec<(Ipv4Addr, reqwest::Url)> = Vec::new();
    let mut vistas: HashSet<String> = HashSet::new();
    for registro in &ssdp {
        let (Some(ip), Some(location)) = (registro.source_ip, registro.location.as_deref()) else {
            continue;
        };
        if localizaciones.len() >= MAX_SSDP_DESCRIPTIONS {
            break;
        }
        let Ok(url) = reqwest::Url::parse(location.trim()) else {
            tracing::debug!(%location, "LOCATION SSDP no es una URL válida");
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") {
            tracing::debug!(%location, "LOCATION SSDP con esquema no permitido");
            continue;
        }
        if !vistas.insert(url.to_string()) {
            continue;
        }
        localizaciones.push((ip, url));
    }

    let upnp: Vec<UpnpDevice> = futures::stream::iter(localizaciones)
        .map(|(ip, url)| async move {
            match ssdp::parser::fetch_description(url.clone(), SSDP_FETCH_TIMEOUT).await {
                Ok(description) => Some(UpnpDevice { ip, description }),
                Err(err) => {
                    tracing::warn!(%url, %err, "no se pudo descargar el XML de descripción SSDP");
                    None
                }
            }
        })
        .buffer_unordered(SSDP_FETCH_CONCURRENCY)
        .filter_map(|resultado| async move { resultado })
        .collect()
        .await;

    ActiveQueries {
        mdns,
        ssdp,
        upnp,
        errors,
    }
}

/// Escanea un equipo en la fase activa: puertos, banners y fingerprint de SO.
pub async fn scan_host_active(mac: &str, ip: Ipv4Addr, top_ports: &[u16]) -> HostActiveScan {
    let mut errors = Vec::new();

    let abiertos = match PortScan::scan(ip, top_ports, PORTSCAN_TIMEOUT, PORTSCAN_CONCURRENCY).await
    {
        Ok(abiertos) => abiertos,
        Err(err) => {
            errors.push(format!("El port scan de {ip} falló: {err}"));
            Vec::new()
        }
    };

    let banners: Vec<(u16, Option<String>)> = futures::stream::iter(abiertos.iter().copied())
        .map(|abierto| async move {
            let banner = BannerGrab::grab(ip, abierto.port, BANNER_TIMEOUT).await;
            (abierto.port, banner)
        })
        .buffer_unordered(BANNER_CONCURRENCY)
        .collect()
        .await;

    let mut servicios = Vec::with_capacity(banners.len());
    for (puerto, banner) in banners {
        let servicio = classify::service(puerto, banner.as_deref());
        servicios.push(DetectedService {
            port: puerto,
            protocol: Protocol::Tcp,
            service: servicio,
            banner,
        });
    }
    servicios.sort_by_key(|servicio| servicio.port);

    // TTL por ICMP raw (spawn_blocking porque usa sockets bloqueantes).
    let ttl = tokio::task::spawn_blocking(move || Fingerprint::probe_ttl(ip, PORTSCAN_TIMEOUT))
        .await
        .ok()
        .flatten();

    let opciones = abiertos
        .first()
        .map(|abierto| abierto.tcp_options)
        .unwrap_or_default();
    let banner_hint = servicios
        .iter()
        .find_map(|servicio| servicio.banner.clone());
    let huella = TcpFingerprint {
        observed_ttl: ttl,
        window: None,
        options: opciones,
        banner: banner_hint,
    };
    let (_, score) = Fingerprint::detect_with_score(&huella);
    let os_family = Fingerprint::detect(&huella);
    let fingerprint_attempted = ttl.is_some() || !abiertos.is_empty();
    let last_fingerprint = if fingerprint_attempted {
        Some(
            serde_json::json!({
                "ttl_observado": ttl,
                "ttl_inicial": ttl.map(Fingerprint::estimate_initial_ttl),
                "ventana": serde_json::Value::Null,
                "opciones": {
                    "timestamps": opciones.timestamps,
                    "sack_ok": opciones.sack_ok,
                    "window_scale": opciones.window_scale,
                    "mss": opciones.mss,
                },
                "banner": huella.banner.is_some(),
                "score": score,
                "os_family": os_family.map(OsFamily::as_str),
            })
            .to_string(),
        )
    } else {
        None
    };

    HostActiveScan {
        mac: mac.to_string(),
        ip,
        services: servicios,
        os_family,
        last_fingerprint,
        fingerprint_attempted,
        errors,
    }
}

/// Escanea en la fase activa todos los equipos indicados, con concurrencia limitada.
pub async fn scan_hosts_active(
    objetivos: &[(String, Ipv4Addr)],
    top_ports: &[u16],
) -> Vec<HostActiveScan> {
    let limite = HOST_SCAN_CONCURRENCY.max(1);
    futures::stream::iter(objetivos.iter().cloned())
        .map(|(mac, ip)| async move { scan_host_active(&mac, ip, top_ports).await })
        .buffer_unordered(limite)
        .collect()
        .await
}
