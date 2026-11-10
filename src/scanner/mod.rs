//! Orquestación del descubrimiento de equipos.
//!
//! Flujo de un ciclo de escaneo:
//! 1. Lectura pasiva de /proc/net/arp.
//! 2. Escaneo ARP activo e ICMP sweep si hay CAP_NET_RAW (si no, modo degradado).
//! 3. Merge determinista por MAC y lookup de fabricante (OUI).
//! 4. Reverse DNS con timeout y concurrencia limitada.
//! 5. Reconciliación con la base de datos: altas, cambios y marcado offline.

pub mod arp;
pub mod dns;
pub mod icmp;
pub mod interfaces;
pub mod proc_arp;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use pnet::ipnetwork::Ipv4Network;

use crate::classify::{self, DeviceCtx, DeviceType, OsFamily, ServiceKind};
use crate::config::{ScanConfig, DEFAULT_SWEEP_CONCURRENCY};
use crate::discovery::{
    self, DetectedService, DiscoveryState, HostActiveScan, PassiveData, UpnpDevice,
};
use crate::error::Result;
use crate::notifier::{Level, Notification};
use crate::oui;
use crate::repo::devices::DeviceUpsert;
use crate::repo::events::EventType;
use crate::repo::{Device, DiscoverySource, Interface, Protocol, Repo, ServiceUpsert};

use interfaces::DetectedInterface;

/// Origen de un dato de descubrimiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostSource {
    /// Barrido ARP activo.
    Arp,
    /// Ping sweep ICMP.
    Icmp,
    /// Lectura pasiva de /proc/net/arp.
    ProcArp,
}

/// Equipo descubierto en la red, fruto del merge de fuentes de F1 y F2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// MAC normalizada.
    pub mac: String,
    /// IPv4 vista (se prefiere la confirmada por ARP).
    pub ip: Ipv4Addr,
    /// Hostname final, tras aplicar la precedencia de Fase 2.
    pub hostname: Option<String>,
    /// Fabricante por OUI, si se conoce.
    pub vendor: Option<String>,
    /// Interfaz por la que se ha visto, si se pudo asignar.
    pub interface: Option<String>,
    /// Fuentes de Fase 1 que han confirmado al equipo.
    pub sources: Vec<HostSource>,
    /// Hostname por reverse DNS (heredado de F1).
    pub reverse_dns_name: Option<String>,
    /// Hostname anunciado por mDNS.
    pub mdns_name: Option<String>,
    /// Hostname devuelto por NetBIOS.
    pub netbios_name: Option<String>,
    /// Hostname del lease DHCP.
    pub dhcp_name: Option<String>,
    /// Familia de SO estimada por fingerprint.
    pub os_family: Option<OsFamily>,
    /// JSON del último fingerprint observado.
    pub last_fingerprint: Option<String>,
    /// Se intentó el fingerprint en este ciclo (permite limpiar os_family).
    pub fingerprint_attempted: bool,
    /// Servicios detectados (mDNS, SSDP y port scan).
    pub services: Vec<DetectedService>,
    /// Fuentes de descubrimiento de Fase 2 que han visto al equipo.
    pub discovery_sources: Vec<DiscoverySource>,
    /// Tipos de servicio mDNS anunciados.
    pub mdns_services: Vec<String>,
    /// Tipos de dispositivo UPnP anunciados.
    pub upnp_types: Vec<String>,
}

impl Host {
    /// Crea un host con los datos mínimos del merge de F1.
    pub fn new(mac: impl Into<String>, ip: Ipv4Addr) -> Self {
        Self {
            mac: mac.into(),
            ip,
            hostname: None,
            vendor: None,
            interface: None,
            sources: Vec::new(),
            reverse_dns_name: None,
            mdns_name: None,
            netbios_name: None,
            dhcp_name: None,
            os_family: None,
            last_fingerprint: None,
            fingerprint_attempted: false,
            services: Vec::new(),
            discovery_sources: Vec::new(),
            mdns_services: Vec::new(),
            upnp_types: Vec::new(),
        }
    }
}

/// Resultado de un ciclo de escaneo, antes de tocar la base de datos.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Equipos descubiertos, ordenados por MAC.
    pub hosts: Vec<Host>,
    /// Interfaces detectadas en el equipo.
    pub interfaces: Vec<DetectedInterface>,
    /// IPs que respondieron al ping sweep.
    pub icmp_responders: Vec<Ipv4Addr>,
    /// Errores no fatales ocurridos durante el escaneo.
    pub errors: Vec<String>,
    /// Indica si se ha escaneado con capacidades raw.
    pub privileged: bool,
    /// Indica si el ciclo se ha ejecutado en modo pasivo.
    pub passive_only: bool,
    /// Duración del ciclo.
    pub duration: Duration,
    /// Leases DHCP leídos en este ciclo.
    pub leases: Vec<discovery::dhcp::Lease>,
    /// Registros mDNS vistos en este ciclo (pasivos y activos).
    pub mdns_records: Vec<discovery::mdns::MdnsRecord>,
    /// Mensajes SSDP vistos en este ciclo (pasivos y activos).
    pub ssdp_records: Vec<discovery::ssdp::SsdpRecord>,
}

/// Opciones de un ciclo de escaneo.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Hay CAP_NET_RAW disponible.
    pub privileged: bool,
    /// Modo pasivo consciente: deshabilita todo el tráfico activo.
    pub passive_only: bool,
    /// Nombres de interfaz permitidos (vacío = todas las candidatas).
    pub interfaces: Vec<String>,
    /// Rangos configurados (vacío = derivar de cada interfaz).
    pub ranges: Vec<Ipv4Network>,
    /// Timeout de ICMP y reverse DNS.
    pub timeout: Duration,
    /// Concurrencia del ping sweep.
    pub concurrency: usize,
    /// Puertos del port scan TCP CONNECT.
    pub top_ports: Vec<u16>,
    /// Rutas adicionales de leases DHCP.
    pub dhcp_lease_paths: Vec<PathBuf>,
    /// Permite desactivar las consultas NetBIOS (pruebas de integración sin red).
    pub netbios_enabled: bool,
}

impl ScanOptions {
    /// Construye las opciones a partir de la sección [scan] de la configuración.
    pub fn from_config(scan: &ScanConfig, privileged: bool) -> Result<Self> {
        let interfaces = match &scan.interfaces {
            crate::config::InterfacesSetting::Auto => Vec::new(),
            crate::config::InterfacesSetting::Names(names) => names.clone(),
        };
        let mut dhcp_lease_paths = Vec::new();
        for ruta in &scan.dhcp_lease_paths {
            match crate::config::expand_tilde(ruta) {
                Ok(expandida) => dhcp_lease_paths.push(expandida),
                Err(err) => tracing::warn!(
                    %err,
                    ruta = %ruta,
                    "ruta de leases DHCP no válida; se descarta"
                ),
            }
        }
        Ok(Self {
            privileged,
            passive_only: scan.passive_only,
            interfaces,
            ranges: scan.parse_ranges()?,
            timeout: Duration::from_millis(scan.icmp_timeout_ms),
            concurrency: DEFAULT_SWEEP_CONCURRENCY,
            top_ports: scan.top_ports.clone(),
            dhcp_lease_paths,
            netbios_enabled: true,
        })
    }

    /// Indica si en este ciclo se permite tráfico activo.
    pub fn active_allowed(&self) -> bool {
        !self.passive_only && self.privileged
    }
}

/// Estado en memoria del escaneo activo entre ciclos.
///
/// El port scan y el fingerprint solo se ejecutan al descubrir un equipo nuevo,
/// cuando cambia su IP/MAC o cuando el usuario pulsa `r`. Este estado guarda los
/// equipos conocidos y evita reescanear en cada ciclo periódico.
#[derive(Debug, Clone, Default)]
pub struct ScanState {
    conocidos: HashMap<String, String>,
    escaneados: HashSet<String>,
}

impl ScanState {
    /// Crea el estado con los equipos ya persistidos al arrancar.
    pub fn new(inicial: &[(String, String)]) -> Self {
        Self {
            conocidos: inicial.iter().cloned().collect(),
            escaneados: HashSet::new(),
        }
    }

    /// Equipos a los que toca hacer port scan y fingerprint en este ciclo.
    pub fn select_for_active_scan(
        &mut self,
        hosts: &[Host],
        manual: bool,
    ) -> Vec<(String, Ipv4Addr)> {
        let mut objetivos = Vec::new();
        for host in hosts {
            let nuevo = !self.conocidos.contains_key(&host.mac);
            let ip_actual = host.ip.to_string();
            let cambio_ip = self
                .conocidos
                .get(&host.mac)
                .map(|ip| ip != &ip_actual)
                .unwrap_or(false);
            if manual || nuevo || cambio_ip {
                objetivos.push((host.mac.clone(), host.ip));
            }
        }
        objetivos.truncate(discovery::MAX_PORTSCAN_HOSTS);
        objetivos
    }

    /// Actualiza el estado con los equipos vistos en el ciclo.
    pub fn update_known(&mut self, hosts: &[Host]) {
        for host in hosts {
            self.conocidos.insert(host.mac.clone(), host.ip.to_string());
            self.escaneados.insert(host.mac.clone());
        }
    }

    /// Indica cuántos equipos se han escaneado en la sesión (diagnóstico).
    pub fn scanned_count(&self) -> usize {
        self.escaneados.len()
    }
}

/// Aplica la precedencia de hostname de la especificación:
/// mDNS > NetBIOS > DHCP > reverse DNS (el alias manual se aplica en la TUI).
pub fn hostname_precedence(
    mdns: Option<&str>,
    netbios: Option<&str>,
    dhcp: Option<&str>,
    reverse_dns: Option<&str>,
) -> Option<String> {
    [mdns, netbios, dhcp, reverse_dns]
        .into_iter()
        .filter_map(nombre_valido)
        .next()
}

/// Valida y normaliza un hostname candidato.
fn nombre_valido(valor: Option<&str>) -> Option<String> {
    let texto = valor?.trim().trim_end_matches('.').to_string();
    if texto.is_empty() || texto.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    if texto.to_ascii_uppercase().contains("*SMBSERVER*") {
        return None;
    }
    Some(texto)
}

/// Persiste en la base de datos las interfaces detectadas al arrancar.
///
/// Se ejecuta antes de abrir la TUI para que la tabla INTERFACES refleje el
/// estado del equipo desde el primer momento (el escaneo periódico volverá a
/// hacer upsert de las interfaces en cada ciclo).
pub fn persistir_interfaces_iniciales(repo: &mut Repo) -> Result<usize> {
    let ahora = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let detectadas = interfaces::detect();
    let mut guardadas = 0usize;
    for iface in &detectadas {
        let persistida = Interface::without_id(
            iface.name.clone(),
            iface.mac.clone(),
            iface.ipv4.map(|ip| ip.to_string()),
            iface.netmask.map(|mascara| mascara.to_string()),
            iface.gateway.map(|gw| gw.to_string()),
            iface.is_up,
            ahora.clone(),
        );
        repo.upsert_interface(&persistida)?;
        guardadas += 1;
    }
    Ok(guardadas)
}

/// Ejecuta un ciclo de descubrimiento completo (F1 + F2).
pub async fn run_scan(
    options: &ScanOptions,
    state: &mut ScanState,
    discovery_state: &mut DiscoveryState,
    manual: bool,
) -> ScanReport {
    let started = Instant::now();
    let mut errors = Vec::new();

    let detectados = match tokio::task::spawn_blocking(interfaces::detect).await {
        Ok(interfaces) => interfaces,
        Err(err) => {
            errors.push(format!("No se pudieron enumerar las interfaces: {err}"));
            Vec::new()
        }
    };

    let mut selected: Vec<DetectedInterface> = if options.interfaces.is_empty() {
        detectados
            .iter()
            .filter(|iface| iface.is_scan_candidate())
            .cloned()
            .collect()
    } else {
        let mut encontradas = Vec::new();
        for nombre in &options.interfaces {
            match detectados.iter().find(|iface| &iface.name == nombre) {
                Some(iface) => encontradas.push(iface.clone()),
                None => errors.push(format!("La interfaz configurada {nombre} no existe")),
            }
        }
        encontradas
    };
    selected.sort_by_key(|iface| iface.name.clone());
    selected.dedup_by(|a, b| a.name == b.name);

    let mut arp_hosts = Vec::new();
    let mut icmp_responders = Vec::new();
    let mut proc_entries = tokio::task::spawn_blocking(proc_arp::read)
        .await
        .unwrap_or_default();

    // El modo pasivo deshabilita ARP scan e ICMP sweep con independencia de las
    // capacidades; /proc/net/arp se sigue leyendo siempre.
    if options.privileged && !options.passive_only {
        for iface in &selected {
            if !iface.is_scan_candidate() {
                continue;
            }
            let targets = targets_for_interface(iface, &options.ranges);
            if targets.is_empty() {
                continue;
            }

            let iface_arp = iface.clone();
            let targets_arp = targets.clone();
            let timeout = options.timeout;
            let objetivos_arp = targets.len();
            match tokio::task::spawn_blocking(move || arp::scan(&iface_arp, &targets_arp, timeout))
                .await
            {
                Ok(Ok(mut hosts)) => {
                    tracing::debug!(
                        interfaz = %iface.name,
                        objetivos = objetivos_arp,
                        encontrados = hosts.len(),
                        "barrido ARP completado"
                    );
                    arp_hosts.append(&mut hosts)
                }
                Ok(Err(err)) => {
                    errors.push(format!("El barrido ARP por {} falló: {err}", iface.name))
                }
                Err(err) => errors.push(format!(
                    "El barrido ARP por {} se canceló: {err}",
                    iface.name
                )),
            }

            let targets_icmp = targets.clone();
            let objetivos_icmp = targets_icmp.len();
            let concurrency = options.concurrency.max(1);
            match tokio::task::spawn_blocking(move || {
                icmp::sweep(&targets_icmp, timeout, concurrency)
            })
            .await
            {
                Ok(Ok(mut ips)) => {
                    tracing::debug!(
                        interfaz = %iface.name,
                        objetivos = objetivos_icmp,
                        respondedores = ips.len(),
                        "ping sweep completado"
                    );
                    icmp_responders.append(&mut ips)
                }
                Ok(Err(err)) => {
                    errors.push(format!("El ping sweep por {} falló: {err}", iface.name))
                }
                Err(err) => errors.push(format!(
                    "El ping sweep por {} se canceló: {err}",
                    iface.name
                )),
            }
        }

        // Tras el ping sweep la tabla ARP del núcleo suele estar poblada: se relee.
        proc_entries = tokio::task::spawn_blocking(proc_arp::read)
            .await
            .unwrap_or(proc_entries);

        // Respaldo: si el barrido ARP raw no ha encontrado nada (algunas
        // interfaces Wi-Fi descartan las tramas inyectadas), se calienta la tabla
        // ARP del núcleo con datagramas UDP y se vuelve a leer /proc/net/arp.
        if arp_hosts.len() < 2 {
            tracing::debug!(
                encontrados = arp_hosts.len(),
                "el barrido ARP raw apenas encontró hosts; se calienta la tabla ARP del núcleo"
            );
            for iface in &selected {
                if !iface.is_scan_candidate() {
                    continue;
                }
                let targets = targets_for_interface(iface, &options.ranges);
                if targets.is_empty() {
                    continue;
                }
                let iface_calentar = iface.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    arp::calentar_tabla_arp(&iface_calentar, &targets)
                })
                .await;
            }
            tokio::time::sleep(Duration::from_millis(1200)).await;
            proc_entries = tokio::task::spawn_blocking(proc_arp::read)
                .await
                .unwrap_or(proc_entries);
        }
    } else if !options.passive_only {
        errors.push(
            "Sin CAP_NET_RAW: escaneo activo desactivado; solo lectura pasiva de /proc/net/arp"
                .to_string(),
        );
    }

    arp_hosts.sort_by_key(|host| host.ip);
    arp_hosts.dedup_by(|a, b| a.mac == b.mac && a.ip == b.ip);
    icmp_responders.sort_unstable();
    icmp_responders.dedup();

    let mut hosts = merge_hosts(&arp_hosts, &proc_entries, &icmp_responders);

    // Se descartan las MAC de nuestras propias interfaces.
    let macs_locales: HashSet<String> = selected
        .iter()
        .filter_map(|iface| iface.mac.clone())
        .collect();
    hosts.retain(|host| !macs_locales.contains(&host.mac));

    // Reverse DNS con timeout corto y concurrencia limitada (pasivo permitido).
    let ips: Vec<Ipv4Addr> = hosts.iter().map(|host| host.ip).collect();
    let resueltos = dns::resolve_many(&ips, options.timeout, options.concurrency.max(1)).await;
    let por_ip: HashMap<Ipv4Addr, String> = resueltos.into_iter().collect();
    for host in &mut hosts {
        if let Some(nombre) = por_ip.get(&host.ip) {
            host.hostname = Some(nombre.clone());
            host.reverse_dns_name = Some(nombre.clone());
        }
    }

    for host in &mut hosts {
        host.vendor = oui::lookup(&host.mac);
        if host.interface.is_none() {
            host.interface = selected
                .iter()
                .find(|iface| {
                    iface
                        .network()
                        .map(|red| red.contains(host.ip))
                        .unwrap_or(false)
                })
                .map(|iface| iface.name.clone());
        }
    }

    // --- Fase pasiva de F2 (siempre): listeners mDNS/SSDP + DHCP + NetBIOS ---
    let pasivo = PassiveData::collect(discovery_state, &options.dhcp_lease_paths);
    tracing::debug!(
        mdns = pasivo.mdns.len(),
        ssdp = pasivo.ssdp.len(),
        leases = pasivo.leases.len(),
        "fuentes pasivas del ciclo"
    );
    errors.extend(pasivo.errors.clone());
    let pares: Vec<(String, Ipv4Addr)> = hosts
        .iter()
        .map(|host| (host.mac.clone(), host.ip))
        .collect();
    let netbios = if options.netbios_enabled {
        discovery::query_netbios(
            &pares,
            discovery::NETBIOS_TIMEOUT,
            discovery::NETBIOS_CONCURRENCY,
        )
        .await
    } else {
        HashMap::new()
    };
    aplicar_fuentes_pasivas(&mut hosts, &pasivo, &[], &netbios);

    let mut mdns_records = pasivo.mdns.clone();
    let mut ssdp_records = pasivo.ssdp.clone();

    // --- Fase activa de F2 (solo !passive_only && CAP_NET_RAW) ---
    if options.active_allowed() {
        let interfaces_multicast: Vec<Ipv4Addr> =
            selected.iter().filter_map(|iface| iface.ipv4).collect();
        let activas = discovery::run_active_queries(&interfaces_multicast).await;
        errors.extend(activas.errors.clone());
        mdns_records.extend(activas.mdns.clone());
        ssdp_records.extend(activas.ssdp.clone());
        let upnp_devices = activas.upnp.clone();

        let fuentes_activas = PassiveData {
            mdns: activas.mdns,
            ssdp: activas.ssdp,
            leases: Vec::new(),
            errors: Vec::new(),
        };
        aplicar_fuentes_pasivas(&mut hosts, &fuentes_activas, &upnp_devices, &HashMap::new());

        let objetivos = state.select_for_active_scan(&hosts, manual);
        let escaneos = discovery::scan_hosts_active(&objetivos, &options.top_ports).await;
        for escaneo in escaneos {
            errors.extend(escaneo.errors.clone());
            aplicar_escaneo_activo(&mut hosts, &escaneo);
        }
    }

    state.update_known(&hosts);
    tracing::debug!(
        equipos_escaneados = state.scanned_count(),
        "estado del escaneo activo actualizado"
    );

    ScanReport {
        hosts,
        interfaces: selected,
        icmp_responders,
        errors,
        privileged: options.privileged,
        passive_only: options.passive_only,
        duration: started.elapsed(),
        leases: pasivo.leases,
        mdns_records,
        ssdp_records,
    }
}

/// Acumulado de registros mDNS para una IP.
#[derive(Debug, Default)]
struct MdnsAgg {
    hostname: Option<String>,
    services: Vec<DetectedService>,
    mdns_services: Vec<String>,
}

/// Agrupa los registros mDNS por IP, asociando hostname y servicios.
fn agregar_mdns(registros: &[crate::discovery::mdns::MdnsRecord]) -> HashMap<Ipv4Addr, MdnsAgg> {
    let mut por_ip: HashMap<Ipv4Addr, MdnsAgg> = HashMap::new();
    let con_ip = registros
        .iter()
        .filter(|registro| registro.ip.is_some())
        .count();
    tracing::trace!(
        total = registros.len(),
        con_ip,
        "registros mDNS a asociar por IP"
    );
    for registro in registros {
        tracing::trace!(
            ip = ?registro.ip,
            hostname = ?registro.hostname,
            servicios = registro.services.len(),
            "registro mDNS"
        );
        let Some(ip) = registro.ip else {
            continue;
        };
        let acumulado = por_ip.entry(ip).or_default();
        if acumulado.hostname.is_none() {
            acumulado.hostname = registro.hostname.clone();
        }
        for servicio in &registro.services {
            if !acumulado.mdns_services.contains(&servicio.service_type) {
                acumulado.mdns_services.push(servicio.service_type.clone());
            }
            let Some(puerto) = servicio.port else {
                continue;
            };
            let protocolo = if servicio.service_type.to_ascii_lowercase().contains("_udp") {
                Protocol::Udp
            } else {
                Protocol::Tcp
            };
            let detectado = DetectedService {
                port: puerto,
                protocol: protocolo,
                service: classify::service(puerto, None),
                banner: None,
            };
            if !acumulado
                .services
                .iter()
                .any(|existente| existente.port == puerto && existente.protocol == protocolo)
            {
                acumulado.services.push(detectado);
            }
        }
    }
    por_ip
}

/// Aplica a los hosts las fuentes pasivas de F2 (mDNS, SSDP, DHCP, NetBIOS y UPnP).
fn aplicar_fuentes_pasivas(
    hosts: &mut [Host],
    pasivo: &PassiveData,
    upnp: &[UpnpDevice],
    netbios: &HashMap<String, crate::discovery::netbios::NetbiosInfo>,
) {
    let mdns = agregar_mdns(&pasivo.mdns);
    let upnp_por_ip: HashMap<Ipv4Addr, &crate::discovery::ssdp::UpnpDescription> = upnp
        .iter()
        .map(|dispositivo| (dispositivo.ip, &dispositivo.description))
        .collect();
    let ssdp_ips: HashSet<Ipv4Addr> = pasivo
        .ssdp
        .iter()
        .filter_map(|registro| registro.source_ip)
        .collect();

    for host in hosts.iter_mut() {
        if let Some(acumulado) = mdns.get(&host.ip) {
            if host.mdns_name.is_none() {
                host.mdns_name = acumulado.hostname.clone();
            }
            for servicio in &acumulado.mdns_services {
                if !host.mdns_services.contains(servicio) {
                    host.mdns_services.push(servicio.clone());
                }
            }
            for servicio in &acumulado.services {
                fusionar_servicio(&mut host.services, servicio.clone());
            }
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Mdns);
        }

        if let Some(info) = netbios.get(&host.mac) {
            if host.netbios_name.is_none() {
                host.netbios_name = info.hostname.clone();
            }
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Netbios);
        }

        if let Some(lease) = pasivo
            .leases
            .iter()
            .find(|lease| lease.mac.as_deref() == Some(host.mac.as_str()) || lease.ip == host.ip)
        {
            if host.dhcp_name.is_none() {
                host.dhcp_name = lease.hostname.clone();
            }
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Dhcp);
        }

        if let Some(descripcion) = upnp_por_ip.get(&host.ip) {
            if let Some(tipo) = &descripcion.device_type {
                if !host.upnp_types.contains(tipo) {
                    host.upnp_types.push(tipo.clone());
                }
            }
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Ssdp);
        } else if ssdp_ips.contains(&host.ip) {
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Ssdp);
        }

        host.hostname = hostname_precedence(
            host.mdns_name.as_deref(),
            host.netbios_name.as_deref(),
            host.dhcp_name.as_deref(),
            host.reverse_dns_name.as_deref(),
        );
    }
}

/// Fusiona un servicio detectado sin duplicar (device_id, port, protocol).
fn fusionar_servicio(servicios: &mut Vec<DetectedService>, nuevo: DetectedService) {
    if let Some(existente) = servicios
        .iter_mut()
        .find(|servicio| servicio.port == nuevo.port && servicio.protocol == nuevo.protocol)
    {
        if existente.service.is_none() {
            existente.service = nuevo.service;
        }
        if existente.banner.is_none() {
            existente.banner = nuevo.banner;
        }
    } else {
        servicios.push(nuevo);
    }
}

/// Añade una fuente de descubrimiento sin duplicados.
fn anyadir_fuente(fuentes: &mut Vec<DiscoverySource>, fuente: DiscoverySource) {
    if !fuentes.contains(&fuente) {
        fuentes.push(fuente);
    }
}

/// Aplica el resultado del escaneo activo de un equipo.
fn aplicar_escaneo_activo(hosts: &mut [Host], escaneo: &HostActiveScan) {
    let Some(host) = hosts.iter_mut().find(|host| host.mac == escaneo.mac) else {
        return;
    };
    for servicio in &escaneo.services {
        fusionar_servicio(&mut host.services, servicio.clone());
    }
    if escaneo.fingerprint_attempted {
        host.fingerprint_attempted = true;
        host.os_family = escaneo.os_family;
        host.last_fingerprint = escaneo.last_fingerprint.clone();
    }
    anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Portscan);
}

/// Heurística para distinguir un televisor de un dispositivo de streaming.
fn parece_televisor(host: &Host) -> bool {
    let nombre = host.hostname.as_deref().unwrap_or("").to_lowercase();
    const INDICIOS_STREAMING: &[&str] = &[
        "chromecast",
        "firetv",
        "fire-tv",
        "appletv",
        "apple-tv",
        "shield",
        "roku",
        "googletv",
        "google-tv",
        "mi-box",
        "mibox",
    ];
    if INDICIOS_STREAMING
        .iter()
        .any(|indicio| nombre.contains(indicio))
    {
        return false;
    }
    const INDICIOS_TV: &[&str] = &[
        "tv", "bravia", "webos", "smart-tv", "smarttv", "vizio", "hisense",
    ];
    if INDICIOS_TV.iter().any(|indicio| nombre.contains(indicio)) {
        return true;
    }
    let vendor = host.vendor.as_deref().unwrap_or("").to_lowercase();
    let vendor_tv = [
        "samsung",
        "lg electronics",
        "sony",
        "philips",
        "panasonic",
        "sharp",
        "vizio",
        "hisense",
        "tcl",
    ]
    .iter()
    .any(|marca| vendor.contains(marca));
    vendor_tv
        && (host
            .upnp_types
            .iter()
            .any(|tipo| tipo.to_lowercase().contains("mediarenderer"))
            || host
                .mdns_services
                .iter()
                .any(|servicio| servicio.contains("_airplay")))
}

/// Merge determinista de los resultados ARP y de /proc/net/arp.
///
/// Las respuestas ARP activas mandan sobre la tabla del núcleo; las IPs del ping
/// sweep solo confirman liveness (el MAC no viaja en ICMP) y se usan para saber
/// qué equipos están vivos. El resultado se ordena por MAC.
pub fn merge_hosts(
    arp_hosts: &[arp::ArpHost],
    proc_entries: &[proc_arp::ArpEntry],
    icmp_responders: &[Ipv4Addr],
) -> Vec<Host> {
    let mut por_mac: BTreeMap<String, Host> = BTreeMap::new();

    for host in arp_hosts {
        let mac = match oui::normalize_mac(&host.mac) {
            Some(mac) if es_mac_utilizable(&mac) => mac,
            _ => continue,
        };
        por_mac
            .entry(mac.clone())
            .and_modify(|existente| {
                if !existente.sources.contains(&HostSource::Arp) {
                    existente.sources.push(HostSource::Arp);
                }
            })
            .or_insert_with(|| {
                let mut nuevo = Host::new(mac, host.ip);
                nuevo.sources.push(HostSource::Arp);
                nuevo
            });
    }

    for entry in proc_entries {
        if !entry.is_complete() {
            continue;
        }
        let mac = match oui::normalize_mac(&entry.mac) {
            Some(mac) if es_mac_utilizable(&mac) => mac,
            _ => continue,
        };
        por_mac
            .entry(mac.clone())
            .and_modify(|existente| {
                if !existente.sources.contains(&HostSource::ProcArp) {
                    existente.sources.push(HostSource::ProcArp);
                }
                if !existente.sources.contains(&HostSource::Arp) {
                    existente.ip = entry.ip;
                }
                if existente.interface.is_none() && !entry.iface.is_empty() {
                    existente.interface = Some(entry.iface.clone());
                }
            })
            .or_insert_with(|| {
                let mut nuevo = Host::new(mac, entry.ip);
                nuevo.interface = Some(entry.iface.clone());
                nuevo.sources.push(HostSource::ProcArp);
                nuevo
            });
    }

    let vivos: HashSet<Ipv4Addr> = icmp_responders.iter().copied().collect();
    let mut hosts: Vec<Host> = por_mac.into_values().collect();
    for host in &mut hosts {
        if vivos.contains(&host.ip) && !host.sources.contains(&HostSource::Icmp) {
            host.sources.push(HostSource::Icmp);
        }
    }
    hosts
}

fn es_mac_utilizable(mac: &str) -> bool {
    mac != "00:00:00:00:00:00" && mac != "ff:ff:ff:ff:ff:ff"
}

/// Calcula los objetivos de escaneo de una interfaz.
pub fn targets_for_interface(
    iface: &DetectedInterface,
    configured: &[Ipv4Network],
) -> Vec<Ipv4Addr> {
    let mut rangos: Vec<Ipv4Network> = if configured.is_empty() {
        iface
            .network()
            .map(|red| vec![acotar_rango(red, iface.ipv4)])
            .unwrap_or_default()
    } else {
        configured
            .iter()
            .filter(|red| {
                iface
                    .network()
                    .map(|local| red.contains(local.ip()) || local.contains(red.ip()))
                    .unwrap_or(true)
            })
            .map(|red| acotar_rango(*red, iface.ipv4))
            .collect()
    };

    if rangos.is_empty() {
        if let Some(red) = iface.network() {
            rangos.push(acotar_rango(red, iface.ipv4));
        }
    }

    let mut objetivos = Vec::new();
    for red in rangos {
        if red.size() <= 2 {
            continue;
        }
        for ip in red.iter() {
            if ip == red.network() || ip == red.broadcast() {
                continue;
            }
            // La propia IP de la interfaz no se escanea: enviar un eco ICMP a
            // una dirección local del propio equipo puede fallar (EINVAL) y
            // abortaba el barrido completo.
            if Some(ip) == iface.ipv4 {
                continue;
            }
            objetivos.push(ip);
        }
    }
    objetivos.sort_unstable();
    objetivos.dedup();
    objetivos
}

fn acotar_rango(red: Ipv4Network, local: Option<Ipv4Addr>) -> Ipv4Network {
    if red.size() <= crate::config::MAX_RANGE_HOSTS {
        return red;
    }
    let ip = local.unwrap_or_else(|| red.ip());
    // /22 = 1024 direcciones: límite de la Fase 1 para rangos automáticos.
    Ipv4Network::new(ip, 22).unwrap_or(red)
}

/// Contador en memoria de ciclos consecutivos sin ver un equipo.
#[derive(Debug, Clone)]
pub struct OnlineTracker {
    misses: HashMap<String, u32>,
    offline_after: u32,
}

impl OnlineTracker {
    /// Crea el contador con el umbral indicado (mínimo 1).
    pub fn new(offline_after: u32) -> Self {
        Self {
            misses: HashMap::new(),
            offline_after: offline_after.max(1),
        }
    }

    /// Fallos consecutivos acumulados por MAC (usado en tests).
    #[cfg(test)]
    pub fn misses_for(&self, mac: &str) -> u32 {
        self.misses.get(mac).copied().unwrap_or(0)
    }

    /// Actualiza contadores con los equipos vistos en este ciclo.
    ///
    /// `known_online` son las MAC que la base de datos tiene como online. Devuelve
    /// las MAC que acaban de alcanzar el umbral y deben marcarse offline.
    pub fn observe(&mut self, seen: &HashSet<String>, known_online: &[String]) -> Vec<String> {
        for mac in seen {
            self.misses.remove(mac);
        }

        let mut recien_offline = Vec::new();
        for mac in known_online {
            if seen.contains(mac) {
                continue;
            }
            let contador = self.misses.entry(mac.clone()).or_insert(0);
            *contador += 1;
            if *contador == self.offline_after {
                recien_offline.push(mac.clone());
            }
        }
        recien_offline.sort();
        recien_offline
    }
}

/// Evento de dispositivo emitido durante la reconciliación y ya persistido.
#[derive(Debug, Clone)]
pub struct ReconciledEvent {
    /// Tipo de evento.
    pub event_type: EventType,
    /// IP del dispositivo en el momento del evento.
    pub ip: String,
    /// Etiqueta visible (alias/hostname o IP).
    pub label: String,
}

/// Resultado de reconciliar un escaneo con la base de datos.
#[derive(Debug, Clone)]
pub struct Reconciliation {
    /// Dispositivos actualizados, tal como quedan en la base de datos.
    pub devices: Vec<Device>,
    /// Interfaces persistidas.
    pub interfaces: Vec<Interface>,
    /// Eventos emitidos y persistidos.
    pub events: Vec<ReconciledEvent>,
    /// Equipos nuevos en este ciclo.
    pub new_devices: usize,
    /// Equipos marcados offline en este ciclo.
    pub marked_offline: usize,
    /// Eventos purgados por retención.
    pub pruned_events: usize,
    /// Servicios detectados y persistidos en este ciclo.
    pub services_detected: usize,
    /// Servicios obsoletos según last_seen (STALE derivado, sin columna de estado).
    pub stale_services: usize,
    /// Servicios purgados por retención.
    pub pruned_services: usize,
    /// Errores no fatales.
    pub errors: Vec<String>,
}

fn etiqueta_corta(label: &str, ip: &str) -> String {
    if label == ip {
        ip.to_string()
    } else {
        label.to_string()
    }
}

fn mensaje_con_etiqueta(prefijo: &str, label: &str, ip: &str) -> String {
    if label == ip {
        format!("{prefijo} {ip}")
    } else {
        format!("{prefijo} {label} ({ip})")
    }
}

impl Reconciliation {
    /// Genera las notificaciones no bloqueantes que corresponden a este ciclo.
    pub fn notifications(&self) -> Vec<Notification> {
        let mut out = Vec::new();
        if self.new_devices > 5 {
            out.push(Notification::new(
                Level::Info,
                format!("{} equipos nuevos detectados", self.new_devices),
            ));
        }
        for evento in &self.events {
            let mensaje = match evento.event_type {
                EventType::New => mensaje_con_etiqueta("Nuevo equipo:", &evento.label, &evento.ip),
                EventType::Disappeared => {
                    mensaje_con_etiqueta("Equipo desconectado:", &evento.label, &evento.ip)
                }
                EventType::IpChanged => format!(
                    "Cambio de IP en {}: {}",
                    etiqueta_corta(&evento.label, &evento.ip),
                    evento.ip
                ),
                EventType::MacChanged => {
                    mensaje_con_etiqueta("Cambio de MAC en", &evento.label, &evento.ip)
                }
                EventType::HostnameChanged => {
                    mensaje_con_etiqueta("Cambio de nombre en", &evento.label, &evento.ip)
                }
            };
            let nivel = match evento.event_type {
                EventType::New | EventType::Disappeared | EventType::MacChanged => Level::Warn,
                _ => Level::Info,
            };
            let es_nuevo_resumido = evento.event_type == EventType::New && self.new_devices > 5;
            if !es_nuevo_resumido {
                out.push(Notification::new(nivel, mensaje));
            }
        }
        out
    }
}

/// Reconoce el resultado de un escaneo contra la base de datos.
///
/// Persiste interfaces, altas/cambios de dispositivos, clasificación automática
/// de device_type, servicios detectados, fuentes de descubrimiento, fingerprint de
/// SO, marca offline tras N ciclos, poda de servicios obsoletos y retención del
/// histórico de eventos.
pub fn reconcile(
    repo: &mut Repo,
    report: &ScanReport,
    tracker: &mut OnlineTracker,
    retention_days: u32,
    stale_before: &str,
) -> Result<Reconciliation> {
    let ahora = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut errors = Vec::new();
    let mut events = Vec::new();

    // 1) Interfaces detectadas.
    let mut ids_interfaz: HashMap<String, i64> = HashMap::new();
    for iface in &report.interfaces {
        let persistida = Interface::without_id(
            iface.name.clone(),
            iface.mac.clone(),
            iface.ipv4.map(|ip| ip.to_string()),
            iface.netmask.map(|mascara| mascara.to_string()),
            iface.gateway.map(|gw| gw.to_string()),
            iface.is_up,
            ahora.clone(),
        );
        match repo.upsert_interface(&persistida) {
            Ok(id) => {
                ids_interfaz.insert(iface.name.clone(), id);
            }
            Err(err) => errors.push(format!(
                "No se pudo guardar la interfaz {}: {err}",
                iface.name
            )),
        }
    }
    let interfaces = repo.list_interfaces().unwrap_or_default();
    let id_por_defecto = interfaces.first().map(|iface| iface.id);

    // 2) Estado previo de dispositivos.
    let previos = repo.list_devices()?;
    let mut previos_por_mac: HashMap<String, Device> = previos
        .iter()
        .map(|device| (device.mac.clone(), device.clone()))
        .collect();
    let macs_actuales: HashSet<String> = report.hosts.iter().map(|host| host.mac.clone()).collect();

    // 3) Altas y cambios.
    let mut vistos: HashSet<String> = HashSet::new();
    let mut nuevos = 0usize;
    let mut servicios_detectados = 0usize;
    for host in &report.hosts {
        let interface_id = match host
            .interface
            .as_ref()
            .and_then(|nombre| ids_interfaz.get(nombre))
            .copied()
            .or(id_por_defecto)
        {
            Some(id) => id,
            None => {
                errors.push(format!(
                    "No hay interfaz persistida para el equipo {}; se omite",
                    host.ip
                ));
                continue;
            }
        };

        // Cambio de identidad: misma IP, MAC nueva y MAC antigua desaparecida.
        if !previos_por_mac.contains_key(&host.mac) {
            let candidato = previos
                .iter()
                .find(|device| {
                    device.ip == host.ip.to_string()
                        && device.mac != host.mac
                        && !macs_actuales.contains(&device.mac)
                        && device.is_online
                })
                .cloned();
            if let Some(anterior) = candidato {
                if let Err(err) = repo.update_device_mac(anterior.id, &host.mac) {
                    errors.push(format!(
                        "No se pudo actualizar la MAC de {}: {err}",
                        anterior.ip
                    ));
                } else {
                    let details = serde_json::json!({
                        "before": anterior.mac,
                        "after": host.mac,
                    })
                    .to_string();
                    if let Err(err) =
                        repo.append_event(anterior.id, EventType::MacChanged, &details)
                    {
                        errors.push(format!("No se pudo registrar mac_changed: {err}"));
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::MacChanged,
                        ip: host.ip.to_string(),
                        label: anterior.display_name().to_string(),
                    });
                    previos_por_mac.remove(&anterior.mac);
                    previos_por_mac.insert(
                        host.mac.clone(),
                        Device {
                            mac: host.mac.clone(),
                            ..anterior
                        },
                    );
                }
            }
        }

        // Clasificación automática de F2 (el override manual se aplica en la TUI).
        let es_gateway = report
            .interfaces
            .iter()
            .find(|iface| host.interface.as_deref() == Some(iface.name.as_str()))
            .and_then(|iface| iface.gateway)
            .map(|gateway| gateway == host.ip)
            .unwrap_or(false);
        // La clasificación usa los servicios vistos en este ciclo y también los
        // ya persistidos: el port scan solo se ejecuta al descubrir un equipo o
        // con r, así que sin esto el tipo podría regresar a "unknown" en los
        // ciclos siguientes.
        let mut servicios_clasificacion: Vec<ServiceKind> = host
            .services
            .iter()
            .filter_map(|servicio| servicio.service)
            .collect();
        if let Some(previo) = previos_por_mac.get(&host.mac) {
            if let Ok(guardados) = repo.list_services(previo.id) {
                for guardado in guardados {
                    if let Some(clase) = guardado.service.as_deref().and_then(ServiceKind::from_str)
                    {
                        if !servicios_clasificacion.contains(&clase) {
                            servicios_clasificacion.push(clase);
                        }
                    }
                }
            }
        }
        let contexto = DeviceCtx {
            is_gateway: es_gateway,
            vendor: host.vendor.clone(),
            hostname: host.hostname.clone(),
            os_family: host.os_family,
            services: servicios_clasificacion,
            mdns_services: host.mdns_services.clone(),
            upnp_types: host.upnp_types.clone(),
            is_tv: parece_televisor(host),
        };
        let mut tipo = classify::device_type(&contexto);
        // Evitar que un tipo ya conocido vuelva a "unknown" en un ciclo sin
        // evidencia nueva (p. ej. sin port scan): se conserva el anterior.
        if tipo == DeviceType::Unknown {
            if let Some(previo) = previos_por_mac.get(&host.mac) {
                if let Some(anterior) = DeviceType::from_str(&previo.device_type) {
                    if anterior != DeviceType::Unknown {
                        tipo = anterior;
                    }
                }
            }
        }

        let upsert = DeviceUpsert {
            mac: host.mac.clone(),
            ip: host.ip.to_string(),
            hostname: host.hostname.clone(),
            vendor: host.vendor.clone(),
            interface_id,
            device_type: tipo.as_str().to_string(),
        };

        match repo.upsert_device(&upsert) {
            Ok((device_id, cambios)) => {
                vistos.insert(host.mac.clone());
                let etiqueta = host
                    .hostname
                    .clone()
                    .or_else(|| {
                        previos_por_mac
                            .get(&host.mac)
                            .and_then(|device| device.alias.clone())
                    })
                    .unwrap_or_else(|| host.ip.to_string());

                if cambios.is_new {
                    nuevos += 1;
                    let details = serde_json::json!({
                        "before": serde_json::Value::Null,
                        "after": {
                            "ip": host.ip.to_string(),
                            "hostname": host.hostname,
                            "vendor": host.vendor,
                        },
                    })
                    .to_string();
                    if let Err(err) = repo.append_event(device_id, EventType::New, &details) {
                        errors.push(format!("No se pudo registrar new: {err}"));
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::New,
                        ip: host.ip.to_string(),
                        label: etiqueta.clone(),
                    });
                }
                if let Some((antes, despues)) = &cambios.ip_changed {
                    let details =
                        serde_json::json!({"before": antes, "after": despues}).to_string();
                    if let Err(err) = repo.append_event(device_id, EventType::IpChanged, &details) {
                        errors.push(format!("No se pudo registrar ip_changed: {err}"));
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::IpChanged,
                        ip: despues.clone(),
                        label: etiqueta.clone(),
                    });
                }
                if let Some((antes, despues)) = &cambios.hostname_changed {
                    let details =
                        serde_json::json!({"before": antes, "after": despues}).to_string();
                    if let Err(err) =
                        repo.append_event(device_id, EventType::HostnameChanged, &details)
                    {
                        errors.push(format!("No se pudo registrar hostname_changed: {err}"));
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::HostnameChanged,
                        ip: host.ip.to_string(),
                        label: etiqueta,
                    });
                }

                // Fingerprint de SO: si se intentó y no superó el umbral, se deja NULL.
                if host.fingerprint_attempted {
                    if let Err(err) = repo.set_os_family(device_id, host.os_family) {
                        errors.push(format!("No se pudo guardar os_family: {err}"));
                    }
                }
                if let Some(fingerprint) = &host.last_fingerprint {
                    if let Err(err) = repo.set_last_fingerprint(device_id, Some(fingerprint)) {
                        errors.push(format!("No se pudo guardar last_fingerprint: {err}"));
                    }
                }

                // Servicios detectados.
                for servicio in &host.services {
                    let upsert_servicio = ServiceUpsert {
                        device_id,
                        port: servicio.port,
                        protocol: servicio.protocol,
                        service: servicio.service.map(|clase| clase.as_str().to_string()),
                        banner: servicio.banner.clone(),
                    };
                    match repo.upsert_service(&upsert_servicio) {
                        Ok(_) => servicios_detectados += 1,
                        Err(err) => errors.push(format!(
                            "No se pudo guardar el servicio {} de {}: {err}",
                            servicio.port, host.ip
                        )),
                    }
                }

                // Fuentes de descubrimiento.
                for fuente in fuentes_de_host(host) {
                    if let Err(err) = repo.upsert_source(device_id, fuente) {
                        errors.push(format!("No se pudo guardar la fuente {fuente:?}: {err}"));
                    }
                }
            }
            Err(err) => errors.push(format!(
                "No se pudo guardar el equipo {} ({}): {err}",
                host.ip, host.mac
            )),
        }
    }

    // 4) Fuentes pasivas de dispositivos que no están en la foto actual (offline).
    // Se aplican en orden de precedencia (mDNS antes que DHCP) y solo se
    // rellena el hostname si está vacío: no se pisa un nombre ya conocido
    // porque no se guarda la procedencia del hostname actual.
    for registro in &report.mdns_records {
        let Some(ip) = registro.ip else {
            continue;
        };
        let Some(dispositivo) = repo.get_device_by_ip(&ip.to_string()).ok().flatten() else {
            continue;
        };
        if dispositivo.hostname.is_none() {
            if let Some(nombre) = &registro.hostname {
                if let Err(err) = repo.set_hostname(dispositivo.id, Some(nombre)) {
                    errors.push(format!("No se pudo guardar el hostname mDNS: {err}"));
                }
            }
        }
        if let Err(err) = repo.upsert_source(dispositivo.id, DiscoverySource::Mdns) {
            errors.push(format!("No se pudo guardar la fuente mDNS: {err}"));
        }
        for servicio in &registro.services {
            let Some(puerto) = servicio.port else {
                continue;
            };
            let protocolo = if servicio.service_type.to_ascii_lowercase().contains("_udp") {
                Protocol::Udp
            } else {
                Protocol::Tcp
            };
            let upsert_servicio = ServiceUpsert {
                device_id: dispositivo.id,
                port: puerto,
                protocol: protocolo,
                service: classify::service(puerto, None).map(|clase| clase.as_str().to_string()),
                banner: None,
            };
            match repo.upsert_service(&upsert_servicio) {
                Ok(_) => servicios_detectados += 1,
                Err(err) => errors.push(format!("No se pudo guardar el servicio mDNS: {err}")),
            }
        }
    }

    for lease in &report.leases {
        let dispositivo = lease
            .mac
            .as_deref()
            .and_then(|mac| repo.get_device_by_mac(mac).ok().flatten())
            .or_else(|| repo.get_device_by_ip(&lease.ip.to_string()).ok().flatten());
        let Some(dispositivo) = dispositivo else {
            continue;
        };
        if dispositivo.hostname.is_none() {
            if let Some(hostname) = &lease.hostname {
                if let Err(err) = repo.set_hostname(dispositivo.id, Some(hostname)) {
                    errors.push(format!("No se pudo guardar el hostname DHCP: {err}"));
                }
            }
        }
        if let Err(err) = repo.upsert_source(dispositivo.id, DiscoverySource::Dhcp) {
            errors.push(format!("No se pudo guardar la fuente DHCP: {err}"));
        }
    }

    for registro in &report.ssdp_records {
        let Some(ip) = registro.source_ip else {
            continue;
        };
        if let Some(dispositivo) = repo.get_device_by_ip(&ip.to_string()).ok().flatten() {
            if let Err(err) = repo.upsert_source(dispositivo.id, DiscoverySource::Ssdp) {
                errors.push(format!("No se pudo guardar la fuente SSDP: {err}"));
            }
        }
    }

    // 5) Marcado offline tras N ciclos sin respuesta.
    let conocidos_online: Vec<String> = previos
        .iter()
        .filter(|device| device.is_online)
        .map(|device| device.mac.clone())
        .collect();
    let recien_offline = tracker.observe(&vistos, &conocidos_online);
    let mut marcados_offline = 0usize;
    for mac in &recien_offline {
        let Some(device) = previos_por_mac.get(mac) else {
            continue;
        };
        match repo.set_device_online(device.id, false) {
            Ok(()) => {
                marcados_offline += 1;
                let details = serde_json::json!({
                    "before": {"ip": device.ip, "is_online": true},
                    "after": {"is_online": false},
                })
                .to_string();
                if let Err(err) = repo.append_event(device.id, EventType::Disappeared, &details) {
                    errors.push(format!("No se pudo registrar disappeared: {err}"));
                }
                events.push(ReconciledEvent {
                    event_type: EventType::Disappeared,
                    ip: device.ip.clone(),
                    label: device.display_name().to_string(),
                });
            }
            Err(err) => errors.push(format!(
                "No se pudo marcar offline el equipo {}: {err}",
                device.ip
            )),
        }
    }

    // 6) Servicios obsoletos (STALE derivado de last_seen) y purga por retención.
    let mut stale_services = 0usize;
    let dispositivos = repo.list_devices().unwrap_or_default();
    for dispositivo in &dispositivos {
        match repo.mark_stale_services(dispositivo.id, stale_before) {
            Ok(total) => stale_services += total,
            Err(err) => errors.push(format!("No se pudieron marcar servicios obsoletos: {err}")),
        }
    }
    let corte_retencion = (Utc::now() - chrono::Duration::days(i64::from(retention_days)))
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let pruned_services = match repo.prune_services(&corte_retencion) {
        Ok(borrados) => borrados,
        Err(err) => {
            errors.push(format!("No se pudieron podar los servicios: {err}"));
            0
        }
    };

    // 7) Retención del histórico.
    let pruned_events = match repo.prune_events(retention_days) {
        Ok(borrados) => borrados,
        Err(err) => {
            errors.push(format!("No se pudo podar el histórico: {err}"));
            0
        }
    };

    Ok(Reconciliation {
        devices: repo.list_devices()?,
        interfaces,
        events,
        new_devices: nuevos,
        marked_offline: marcados_offline,
        pruned_events,
        services_detected: servicios_detectados,
        stale_services,
        pruned_services,
        errors,
    })
}

/// Fuentes de descubrimiento de F1 y F2 de un equipo, sin duplicados.
fn fuentes_de_host(host: &Host) -> Vec<DiscoverySource> {
    let mut fuentes = Vec::new();
    for fuente in &host.sources {
        let mapeada = match fuente {
            HostSource::Arp | HostSource::ProcArp => DiscoverySource::Arp,
            HostSource::Icmp => DiscoverySource::Icmp,
        };
        if !fuentes.contains(&mapeada) {
            fuentes.push(mapeada);
        }
    }
    for fuente in &host.discovery_sources {
        if !fuentes.contains(fuente) {
            fuentes.push(*fuente);
        }
    }
    fuentes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::events::EventType;

    #[test]
    fn merge_prefiere_arp_y_ordena_por_mac() {
        let arp_hosts = vec![
            arp::ArpHost {
                ip: "192.168.1.10".parse().unwrap(),
                mac: "aa:bb:cc:dd:ee:01".to_string(),
            },
            arp::ArpHost {
                ip: "192.168.1.11".parse().unwrap(),
                mac: "aa:bb:cc:dd:ee:02".to_string(),
            },
        ];
        let proc_entries = vec![proc_arp::ArpEntry {
            ip: "192.168.1.99".parse().unwrap(),
            mac: "aa:bb:cc:dd:ee:01".to_string(),
            flags: 0x2,
            iface: "eth0".to_string(),
        }];
        let merged = merge_hosts(&arp_hosts, &proc_entries, &[]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(merged[0].ip, "192.168.1.10".parse::<Ipv4Addr>().unwrap());
        assert!(merged[0].sources.contains(&HostSource::Arp));
        assert!(merged[0].sources.contains(&HostSource::ProcArp));
        assert_eq!(merged[1].mac, "aa:bb:cc:dd:ee:02");
    }

    #[test]
    fn merge_ignora_entradas_incompletas_y_macs_invalidas() {
        let proc_entries = vec![
            proc_arp::ArpEntry {
                ip: "192.168.1.20".parse().unwrap(),
                mac: "aa:bb:cc:dd:ee:20".to_string(),
                flags: 0,
                iface: "eth0".to_string(),
            },
            proc_arp::ArpEntry {
                ip: "192.168.1.21".parse().unwrap(),
                mac: "no-es-mac".to_string(),
                flags: 0x2,
                iface: "eth0".to_string(),
            },
        ];
        assert!(merge_hosts(&[], &proc_entries, &[]).is_empty());
    }

    #[test]
    fn merge_marca_respondedores_icmp() {
        let arp_hosts = vec![arp::ArpHost {
            ip: "10.0.0.2".parse().unwrap(),
            mac: "aa:bb:cc:00:00:01".to_string(),
        }];
        let merged = merge_hosts(&arp_hosts, &[], &["10.0.0.2".parse().unwrap()]);
        assert!(merged[0].sources.contains(&HostSource::Icmp));
    }

    #[test]
    fn tracker_marca_offline_tras_n_ciclos() {
        let mut tracker = OnlineTracker::new(3);
        let known = vec!["aa:bb:cc:dd:ee:01".to_string()];
        let mut seen = HashSet::new();
        assert!(tracker.observe(&seen, &known).is_empty());
        assert!(tracker.observe(&seen, &known).is_empty());
        assert_eq!(tracker.observe(&seen, &known), known);
        assert!(
            tracker.observe(&seen, &known).is_empty(),
            "solo emite una vez"
        );
        seen.insert("aa:bb:cc:dd:ee:01".to_string());
        assert!(tracker.observe(&seen, &known).is_empty());
        assert_eq!(tracker.misses_for("aa:bb:cc:dd:ee:01"), 0);
    }

    #[test]
    fn tracker_ignora_equipos_que_no_estan_online() {
        let mut tracker = OnlineTracker::new(1);
        let mut seen = HashSet::new();
        assert!(tracker.observe(&seen, &[]).is_empty());
        seen.insert("aa:bb:cc:dd:ee:01".to_string());
        assert!(tracker.observe(&seen, &[]).is_empty());
    }

    #[test]
    fn tipos_de_evento_cubiertos() {
        assert_eq!(EventType::ALL.len(), 5);
        assert_eq!(EventType::New.as_str(), "new");
        assert_eq!(
            EventType::from_str("mac_changed"),
            Some(EventType::MacChanged)
        );
        assert_eq!(EventType::from_str("otro"), None);
    }

    #[test]
    fn rango_automatico_se_acota_a_1024_direcciones() {
        let iface = DetectedInterface {
            name: "eth0".to_string(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            ipv4: Some("10.1.2.3".parse().unwrap()),
            netmask: Some("255.0.0.0".parse().unwrap()),
            gateway: None,
            is_up: true,
        };
        let red = iface.network().unwrap();
        assert!(red.size() > crate::config::MAX_RANGE_HOSTS);
        let objetivos = targets_for_interface(&iface, &[]);
        assert!(!objetivos.is_empty());
        assert!(objetivos.len() <= crate::config::MAX_RANGE_HOSTS as usize);
    }

    #[test]
    fn objetivos_configurados_respetan_la_red() {
        let iface = DetectedInterface {
            name: "eth0".to_string(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            ipv4: Some("192.168.1.10".parse().unwrap()),
            netmask: Some("255.255.255.0".parse().unwrap()),
            gateway: Some("192.168.1.1".parse().unwrap()),
            is_up: true,
        };
        let red: Ipv4Network = "192.168.1.0/24".parse().unwrap();
        let objetivos = targets_for_interface(&iface, &[red]);
        assert_eq!(objetivos.len(), 253);
        assert!(objetivos.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!objetivos.contains(&"192.168.1.0".parse().unwrap()));
        assert!(!objetivos.contains(&"192.168.1.255".parse().unwrap()));
        assert!(
            !objetivos.contains(&"192.168.1.10".parse().unwrap()),
            "la propia IP de la interfaz no debe escanearse"
        );
    }

    fn interfaz_de_prueba() -> DetectedInterface {
        DetectedInterface {
            name: "eth0".to_string(),
            mac: Some("02:00:00:00:00:ff".to_string()),
            ipv4: Some("192.168.1.10".parse().unwrap()),
            netmask: Some("255.255.255.0".parse().unwrap()),
            gateway: Some("192.168.1.1".parse().unwrap()),
            is_up: true,
        }
    }

    /// Corte de obsolescencia usado en los tests (marca todo como obsoleto).
    const STALE_FUTURO: &str = "2999-01-01T00:00:00Z";

    fn host_de_prueba(mac: &str, ip: &str, hostname: Option<&str>) -> Host {
        let mut host = Host::new(mac, ip.parse().unwrap());
        host.hostname = hostname.map(str::to_string);
        host.vendor = Some("Apple".to_string());
        host.interface = Some("eth0".to_string());
        host.sources.push(HostSource::Arp);
        host
    }

    fn informe_de_prueba(hosts: Vec<Host>) -> ScanReport {
        ScanReport {
            hosts,
            interfaces: vec![interfaz_de_prueba()],
            icmp_responders: Vec::new(),
            errors: Vec::new(),
            privileged: true,
            passive_only: false,
            duration: Duration::from_millis(1),
            leases: Vec::new(),
            mdns_records: Vec::new(),
            ssdp_records: Vec::new(),
        }
    }

    #[test]
    fn reconcilia_altas_cambios_y_offline_contra_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(2);

        let primero = informe_de_prueba(vec![
            host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop")),
            host_de_prueba("aa:bb:cc:dd:ee:02", "192.168.1.1", Some("router")),
        ]);
        let primera = reconcile(&mut repo, &primero, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(primera.new_devices, 2);
        assert_eq!(primera.devices.len(), 2);
        assert_eq!(primera.interfaces.len(), 1);
        assert_eq!(primera.events.len(), 2);
        assert!(primera
            .events
            .iter()
            .all(|evento| evento.event_type == EventType::New));
        let router = primera
            .devices
            .iter()
            .find(|device| device.ip == "192.168.1.1")
            .unwrap();
        assert_eq!(router.device_type, "gateway");
        let portatil = primera
            .devices
            .iter()
            .find(|device| device.ip == "192.168.1.10")
            .unwrap();
        assert_eq!(portatil.device_type, "unknown");

        // Misma foto: no debe haber eventos nuevos.
        let segunda = reconcile(&mut repo, &primero, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(segunda.new_devices, 0);
        assert!(segunda.events.is_empty());

        // Cambios de IP y hostname para la misma MAC.
        let cambiado = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.11",
            Some("laptop-nueva"),
        )]);
        let tercera = reconcile(&mut repo, &cambiado, &mut tracker, 90, STALE_FUTURO).unwrap();
        let tipos: Vec<EventType> = tercera.events.iter().map(|e| e.event_type).collect();
        assert!(tipos.contains(&EventType::IpChanged));
        assert!(tipos.contains(&EventType::HostnameChanged));
        let actualizado = tercera
            .devices
            .iter()
            .find(|device| device.mac == "aa:bb:cc:dd:ee:01")
            .unwrap();
        assert_eq!(actualizado.ip, "192.168.1.11");
        assert_eq!(actualizado.hostname.as_deref(), Some("laptop-nueva"));

        // Cambio de identidad: misma IP, MAC nueva y MAC anterior desaparecida.
        let identidad = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:03",
            "192.168.1.11",
            None,
        )]);
        let cuarta = reconcile(&mut repo, &identidad, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert!(cuarta
            .events
            .iter()
            .any(|evento| evento.event_type == EventType::MacChanged));
        let renombrado = cuarta
            .devices
            .iter()
            .find(|device| device.ip == "192.168.1.11")
            .unwrap();
        assert_eq!(renombrado.mac, "aa:bb:cc:dd:ee:03");
        assert_eq!(cuarta.devices.len(), 2, "no debe crear un duplicado");

        // Dos ciclos sin ver a la MAC original del router: offline + disappeared.
        let vacio = informe_de_prueba(vec![]);
        let quinta = reconcile(&mut repo, &vacio, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(quinta.marked_offline, 0);
        let sexta = reconcile(&mut repo, &vacio, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert!(sexta.marked_offline >= 1);
        assert!(sexta
            .events
            .iter()
            .any(|evento| evento.event_type == EventType::Disappeared));
        assert!(sexta.devices.iter().all(|device| !device.is_online));

        // Reaparece (con la MAC de identidad actual): online sin evento new.
        let reaparece = informe_de_prueba(vec![
            host_de_prueba("aa:bb:cc:dd:ee:03", "192.168.1.11", Some("laptop-nueva")),
            host_de_prueba("aa:bb:cc:dd:ee:02", "192.168.1.1", Some("router")),
        ]);
        let septima = reconcile(&mut repo, &reaparece, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(septima.new_devices, 0);
        assert!(septima
            .events
            .iter()
            .all(|evento| evento.event_type != EventType::New));
        assert!(septima.devices.iter().any(|device| device.is_online));
    }

    #[test]
    fn reconcilia_poda_eventos_segun_retencion() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);
        let informe = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.20",
            Some("viejo"),
        )]);
        let reconciliacion =
            reconcile(&mut repo, &informe, &mut tracker, 90, STALE_FUTURO).unwrap();
        let device_id = reconciliacion.devices[0].id;
        repo.connection()
            .execute(
                "UPDATE DEVICE_EVENTS SET created_at = '2000-01-01T00:00:00Z'",
                [],
            )
            .unwrap();
        let limpieza = reconcile(&mut repo, &informe, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert!(limpieza.pruned_events >= 1);
        assert!(repo.list_events(device_id).unwrap().is_empty());
    }

    #[test]
    fn notificaciones_resumen_equipos_nuevos() {
        let mut hosts = Vec::new();
        for indice in 1..=6 {
            hosts.push(host_de_prueba(
                &format!("aa:bb:cc:dd:ee:0{indice}"),
                &format!("192.168.1.{}", 10 + indice),
                None,
            ));
        }
        let reconciliacion = Reconciliation {
            devices: Vec::new(),
            interfaces: Vec::new(),
            events: Vec::new(),
            new_devices: 6,
            marked_offline: 0,
            pruned_events: 0,
            services_detected: 0,
            stale_services: 0,
            pruned_services: 0,
            errors: Vec::new(),
        };
        let notificaciones = reconciliacion.notifications();
        assert!(notificaciones
            .iter()
            .any(|notificacion| notificacion.message.contains("6 equipos nuevos")));
        let _ = hosts;
    }

    #[test]
    fn precedencia_de_hostname_segun_la_especificacion() {
        // mDNS > NetBIOS > DHCP > reverse DNS.
        assert_eq!(
            hostname_precedence(Some("mdns.local"), Some("nb"), Some("dhcp"), Some("rdns")),
            Some("mdns.local".to_string())
        );
        assert_eq!(
            hostname_precedence(None, Some("nb"), Some("dhcp"), Some("rdns")),
            Some("nb".to_string())
        );
        assert_eq!(
            hostname_precedence(None, None, Some("dhcp"), Some("rdns")),
            Some("dhcp".to_string())
        );
        assert_eq!(
            hostname_precedence(None, None, None, Some("rdns")),
            Some("rdns".to_string())
        );
        assert_eq!(hostname_precedence(None, None, None, None), None);

        // Se ignoran nombres vacíos, IPs y el *SMBSERVER* de NetBIOS.
        assert_eq!(
            hostname_precedence(Some("   "), Some("*SMBSERVER*"), None, Some("192.168.1.5")),
            None
        );
        // Se recorta el punto final de los FQDN.
        assert_eq!(
            hostname_precedence(Some("impresora.local."), None, None, None),
            Some("impresora.local".to_string())
        );
    }

    #[test]
    fn port_scan_solo_para_equipos_nuevos_cambiados_o_manual() {
        let mut state =
            ScanState::new(&[("aa:bb:cc:dd:ee:01".to_string(), "192.168.1.10".to_string())]);
        let conocido = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", None);
        let nuevo = host_de_prueba("aa:bb:cc:dd:ee:02", "192.168.1.11", None);
        let hosts = vec![conocido.clone(), nuevo.clone()];

        // Primer ciclo: solo el equipo nuevo (el persistido no se reescanea).
        let objetivos = state.select_for_active_scan(&hosts, false);
        assert_eq!(objetivos.len(), 1);
        assert_eq!(objetivos[0].0, "aa:bb:cc:dd:ee:02");
        state.update_known(&hosts);
        assert_eq!(state.scanned_count(), 2);

        // Sin cambios no hay nada que escanear.
        assert!(state.select_for_active_scan(&hosts, false).is_empty());

        // Cambio de IP de un equipo conocido: se vuelve a escanear.
        let mut cambiado = conocido;
        cambiado.ip = "192.168.1.20".parse().unwrap();
        let objetivos = state.select_for_active_scan(&[cambiado], false);
        assert_eq!(objetivos.len(), 1);

        // r manual fuerza el escaneo de todos.
        let objetivos = state.select_for_active_scan(&hosts, true);
        assert_eq!(objetivos.len(), 2);
    }

    #[test]
    fn reconcilia_servicios_fuentes_y_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        host.services.push(DetectedService {
            port: 22,
            protocol: Protocol::Tcp,
            service: Some(crate::classify::ServiceKind::Ssh),
            banner: Some("SSH-2.0-OpenSSH_9.6".to_string()),
        });
        host.discovery_sources
            .extend([DiscoverySource::Mdns, DiscoverySource::Portscan]);
        host.os_family = Some(OsFamily::Linux);
        host.last_fingerprint = Some("{\"ttl\":64}".to_string());
        host.fingerprint_attempted = true;

        let informe = informe_de_prueba(vec![host]);
        let reconciliacion =
            reconcile(&mut repo, &informe, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(reconciliacion.services_detected, 1);
        let device_id = reconciliacion.devices[0].id;
        let servicios = repo.list_services(device_id).unwrap();
        assert_eq!(servicios.len(), 1);
        assert_eq!(servicios[0].port, 22);
        assert_eq!(servicios[0].service.as_deref(), Some("ssh"));
        assert_eq!(servicios[0].banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));

        let dispositivo = &reconciliacion.devices[0];
        assert_eq!(dispositivo.os_family.as_deref(), Some("linux"));
        assert_eq!(
            dispositivo.last_fingerprint.as_deref(),
            Some("{\"ttl\":64}")
        );
        let fuentes = repo.list_sources(device_id).unwrap();
        let nombres: Vec<&str> = fuentes.iter().map(|fila| fila.source.as_str()).collect();
        assert!(nombres.contains(&"arp"));
        assert!(nombres.contains(&"mdns"));
        assert!(nombres.contains(&"portscan"));
        assert!(!nombres.contains(&"ssdp"));
    }

    #[test]
    fn override_manual_manda_sobre_el_tipo_automatico() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);
        let informe = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.10",
            Some("laptop"),
        )]);
        let reconciliacion =
            reconcile(&mut repo, &informe, &mut tracker, 90, STALE_FUTURO).unwrap();
        let device_id = reconciliacion.devices[0].id;
        repo.set_device_type_manual(device_id, Some(crate::classify::DeviceType::Pc))
            .unwrap();
        let dispositivo = repo
            .get_device_by_mac("aa:bb:cc:dd:ee:01")
            .unwrap()
            .unwrap();
        assert_eq!(dispositivo.effective_device_type(), "pc");
        assert_eq!(dispositivo.device_type, "unknown");
    }

    #[test]
    fn fuentes_pasivas_actualizan_dispositivos_offline() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        // Alta inicial del equipo.
        let inicial = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.10",
            None,
        )]);
        let reconciliacion =
            reconcile(&mut repo, &inicial, &mut tracker, 90, STALE_FUTURO).unwrap();
        let device_id = reconciliacion.devices[0].id;

        // Ciclo vacío con un anuncio mDNS y un lease DHCP del mismo equipo.
        let mut vacio = informe_de_prueba(vec![]);
        vacio.mdns_records.push(crate::discovery::mdns::MdnsRecord {
            ip: Some("192.168.1.10".parse().unwrap()),
            hostname: Some("impresora.local".to_string()),
            services: vec![crate::discovery::mdns::MdnsService {
                service_type: "_ipp._tcp".to_string(),
                name: Some("HP".to_string()),
                port: Some(631),
                txt: Vec::new(),
            }],
            hinfo_os: None,
        });
        vacio.leases.push(crate::discovery::dhcp::Lease {
            mac: Some("aa:bb:cc:dd:ee:01".to_string()),
            ip: "192.168.1.10".parse().unwrap(),
            hostname: Some("impresora-dhcp".to_string()),
            expiry: None,
            source: crate::discovery::dhcp::LeaseSource::Dnsmasq,
            path: None,
        });
        let ciclo = reconcile(&mut repo, &vacio, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(ciclo.new_devices, 0);
        let dispositivo = repo
            .get_device_by_mac("aa:bb:cc:dd:ee:01")
            .unwrap()
            .unwrap();
        assert_eq!(dispositivo.hostname.as_deref(), Some("impresora.local"));
        let fuentes = repo.list_sources(device_id).unwrap();
        let nombres: Vec<&str> = fuentes.iter().map(|fila| fila.source.as_str()).collect();
        assert!(nombres.contains(&"mdns"));
        assert!(nombres.contains(&"dhcp"));
        assert_eq!(repo.list_services(device_id).unwrap().len(), 1);
    }

    #[test]
    fn el_merge_pasivo_respeta_la_precedencia_y_conserva_reverse_dns() {
        // Sin fuentes de F2, el hostname de reverse DNS se conserva.
        let mut host = Host::new("aa:bb:cc:dd:ee:01", "192.168.1.10".parse().unwrap());
        host.reverse_dns_name = Some("equipo.lan".to_string());
        host.hostname = Some("equipo.lan".to_string());
        aplicar_fuentes_pasivas(
            std::slice::from_mut(&mut host),
            &PassiveData::default(),
            &[],
            &HashMap::new(),
        );
        assert_eq!(host.hostname.as_deref(), Some("equipo.lan"));

        // mDNS manda sobre reverse DNS y añade servicios y fuente.
        let mut host = Host::new("aa:bb:cc:dd:ee:02", "192.168.1.11".parse().unwrap());
        host.reverse_dns_name = Some("equipo.lan".to_string());
        host.hostname = Some("equipo.lan".to_string());
        let pasivo = PassiveData {
            mdns: vec![crate::discovery::mdns::MdnsRecord {
                ip: Some("192.168.1.11".parse().unwrap()),
                hostname: Some("impresora.local".to_string()),
                services: vec![crate::discovery::mdns::MdnsService {
                    service_type: "_ipp._tcp".to_string(),
                    name: Some("HP".to_string()),
                    port: Some(631),
                    txt: Vec::new(),
                }],
                hinfo_os: None,
            }],
            ..PassiveData::default()
        };
        aplicar_fuentes_pasivas(
            std::slice::from_mut(&mut host),
            &pasivo,
            &[],
            &HashMap::new(),
        );
        assert_eq!(host.hostname.as_deref(), Some("impresora.local"));
        assert_eq!(host.mdns_services, vec!["_ipp._tcp".to_string()]);
        assert!(host.discovery_sources.contains(&DiscoverySource::Mdns));
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.services[0].port, 631);
    }

    #[test]
    fn el_tipo_no_regresa_si_los_servicios_ya_estan_persistidos() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("hoguera"));
        host.services.push(DetectedService {
            port: 22,
            protocol: Protocol::Tcp,
            service: Some(crate::classify::ServiceKind::Ssh),
            banner: Some("SSH-2.0-OpenSSH_10.0".to_string()),
        });
        let primero = informe_de_prueba(vec![host.clone()]);
        let reconciliacion =
            reconcile(&mut repo, &primero, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(reconciliacion.devices[0].device_type, "pc");

        // Ciclo siguiente sin port scan: el servicio sigue en DEVICE_SERVICES y
        // el tipo no debe volver a unknown.
        let mut sin_servicios = host;
        sin_servicios.services.clear();
        let segundo = informe_de_prueba(vec![sin_servicios]);
        let reconciliacion =
            reconcile(&mut repo, &segundo, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(reconciliacion.devices[0].device_type, "pc");
        assert_eq!(
            repo.list_services(reconciliacion.devices[0].id)
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn ciclo_con_passive_only_no_emite_trafico_activo() {
        // Sin listeners, sin NetBIOS y con reverse DNS desactivado (timeout 0):
        // el ciclo no toca la red y no debe intentar ninguna fase activa.
        let options = ScanOptions {
            privileged: false,
            passive_only: true,
            interfaces: vec!["almenara-interfaz-inexistente".to_string()],
            ranges: Vec::new(),
            timeout: Duration::ZERO,
            concurrency: 4,
            top_ports: vec![22, 80],
            dhcp_lease_paths: Vec::new(),
            netbios_enabled: false,
        };
        assert!(!options.active_allowed());

        let mut state = ScanState::new(&[]);
        let mut discovery_state = DiscoveryState::disabled();
        let informe = run_scan(&options, &mut state, &mut discovery_state, false).await;

        assert!(informe.passive_only);
        assert!(!informe.privileged);
        assert!(
            !informe
                .errors
                .iter()
                .any(|error| error.contains("Sin CAP_NET_RAW")),
            "en modo pasivo no debe avisarse de falta de privilegios: {:?}",
            informe.errors
        );
        assert!(
            !informe
                .errors
                .iter()
                .any(|error| error.contains("ARP") || error.contains("ping")),
            "no debe intentarse ARP ni ICMP en pasivo: {:?}",
            informe.errors
        );
        // Ningún equipo debe seleccionarse para port scan en un ciclo pasivo.
        assert!(state
            .select_for_active_scan(&informe.hosts, false)
            .is_empty());
    }
}
