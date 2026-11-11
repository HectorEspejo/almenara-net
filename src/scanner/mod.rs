//! Orquestación del descubrimiento de equipos.
//!
//! Flujo de un ciclo de escaneo:
//! 1. Drenaje de los equipos observados y de la identidad de la captura (F4).
//! 2. Lectura pasiva de /proc/net/arp.
//! 3. Escaneo ARP activo e ICMP sweep si hay CAP_NET_RAW (si no, modo degradado).
//! 4. Merge determinista por MAC y lookup de fabricante (OUI), con los equipos
//!    observados en la captura como una fuente L2 más.
//! 5. Reverse DNS con timeout y concurrencia limitada (solo IPs de la LAN y
//!    nunca en modo pasivo).
//! 6. Reconciliación con la base de datos: altas, cambios, identidad y marcado
//!    offline.

pub mod arp;
pub mod dns;
pub mod icmp;
pub mod interfaces;
pub mod proc_arp;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use pnet::ipnetwork::Ipv4Network;

use crate::classify::{self, DeviceCtx, DeviceType, OsFamily, ServiceKind};
use crate::config::{ScanConfig, DEFAULT_SWEEP_CONCURRENCY};
use crate::discovery::{
    self, DetectedService, DiscoveryState, HostActiveScan, PassiveData, UpnpDevice,
};
use crate::error::Result;
use crate::history::changes::{Changes, NewEvent};
use crate::identify::dhcp as dhcp_ident;
use crate::identify::mac as mac_ident;
use crate::identify::models as models_ident;
use crate::identify::observed::ObservedHosts;
use crate::identify::useragent;
use crate::identify::{self, CaptureIdentityStore, DeviceIdentitySignals, OsSignals, OsSource};
use crate::inference::{DhcpObservation, ObservedHost};
use crate::notifier::{Level, Notification};
use crate::oui;
use crate::repo::devices::{DeviceUpsert, IdentityUpdate};
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
    /// Se ha ejecutado un escaneo de puertos TCP real de este equipo en el ciclo.
    ///
    /// El escaneo de puertos de F2 solo corre al descubrir el equipo, al cambiar
    /// su IP/MAC o con `r` manual; si falla, este campo queda a false para no
    /// interpretar como cerrados puertos que no se han llegado a escanear.
    pub port_scan_attempted: bool,
    /// Puertos TCP que ha intentado el escaneo de puertos en este ciclo.
    ///
    /// La reconciliación lo usa para distinguir un puerto CERRADO (escaneado y
    /// sin respuesta) de un puerto STALE por tiempo (no escaneado, §7.7).
    pub port_scan_ports: Vec<u16>,
    /// Servicios abiertos que ha visto el escaneo de puertos en este ciclo.
    pub port_scan_services: Vec<DetectedService>,
    /// Fuentes de descubrimiento de Fase 2 que han visto al equipo.
    pub discovery_sources: Vec<DiscoverySource>,
    /// Tipos de servicio mDNS anunciados.
    pub mdns_services: Vec<String>,
    /// Tipos de dispositivo UPnP anunciados.
    pub upnp_types: Vec<String>,
    /// Modelo anunciado por mDNS (TXT) o UPnP, si se conoce.
    pub model: Option<String>,
    /// Huella DHCP capturada: opción 55 en decimal separada por comas.
    pub dhcp_fingerprint: Option<String>,
    /// Vendor class DHCP capturado: opción 60 saneada.
    pub dhcp_vendor: Option<String>,
    /// Hostname DHCP capturado: opción 12 saneada.
    pub dhcp_hostname: Option<String>,
    /// Último User-Agent HTTP en claro observado en la captura.
    pub user_agent: Option<String>,
    /// Señal que fijó `os_family` al combinar las señales de F2 y F4 (§7.12).
    pub os_source: Option<OsSource>,
    /// MAC administrada localmente (bit U/L): puede ser aleatoria por privacidad.
    pub mac_random: bool,
    /// Puntuación de la huella TCP de F2 (0 si no se intentó el fingerprint).
    pub fingerprint_score: u8,
    /// Pistas de SO del modelo anunciado (se combinan al final del ciclo).
    model_os: Vec<(OsFamily, u8)>,
    /// Tipo de equipo sugerido por el modelo anunciado.
    model_device_type: Option<DeviceType>,
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
            port_scan_attempted: false,
            port_scan_ports: Vec::new(),
            port_scan_services: Vec::new(),
            discovery_sources: Vec::new(),
            mdns_services: Vec::new(),
            upnp_types: Vec::new(),
            model: None,
            dhcp_fingerprint: None,
            dhcp_vendor: None,
            dhcp_hostname: None,
            user_agent: None,
            os_source: None,
            mac_random: false,
            fingerprint_score: 0,
            model_os: Vec::new(),
            model_device_type: None,
        }
    }

    /// Aplica las señales de identidad de F4 a la clasificación de SO.
    ///
    /// Se ejecuta al cerrar el ciclo, cuando ya han llegado la huella DHCP, el
    /// modelo y el User-Agent: suma sus puntos a los de la huella TCP de F2 y
    /// guarda el SO ganador y la señal que más aportó (§7.12).
    fn combinar_os(&mut self) {
        let (familia, fuente) = identify::os_family(&senales_os(self));
        self.os_family = familia;
        self.os_source = fuente;
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
            // En modo pasivo no se consulta a nadie (§7.15): NetBIOS desactivado.
            netbios_enabled: !scan.passive_only,
        })
    }

    /// Indica si en este ciclo se permite tráfico activo.
    pub fn active_allowed(&self) -> bool {
        !self.passive_only && self.privileged
    }
}

/// Indica si el ciclo consulta NetBIOS (§7.15: nunca en modo pasivo).
fn netbios_habilitado(options: &ScanOptions) -> bool {
    options.netbios_enabled && !options.passive_only
}

/// Indica si el ciclo hace reverse DNS (§7.15: nunca en modo pasivo).
fn dns_inverso_habilitado(options: &ScanOptions) -> bool {
    !options.passive_only
}

/// Indica si una IPv4 pertenece a alguna de las subredes locales indicadas.
///
/// Es el guard explícito de §7.15: nunca se hace DNS inverso de IPs de Internet.
fn es_ip_de_subred_local(ip: Ipv4Addr, redes: &[Ipv4Network]) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && redes.iter().any(|red| red.contains(ip))
}

/// Subredes locales del ciclo: las de las interfaces y los rangos configurados.
fn redes_locales(interfaces: &[DetectedInterface], rangos: &[Ipv4Network]) -> Vec<Ipv4Network> {
    let mut redes: Vec<Ipv4Network> = interfaces
        .iter()
        .filter_map(|iface| iface.network())
        .collect();
    redes.extend(rangos.iter().copied());
    redes
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
/// alias > mDNS/fn > NetBIOS > DHCP (lease o capturado) > reverse DNS.
///
/// El alias manual se aplica en la TUI (manda sobre el hostname persistido). El
/// nombre amigable de Google Cast (TXT `fn`, nivel mDNS) y el hostname DHCP
/// capturado (opción 12, nivel de lease) llegan ya fundidos en `mdns` y `dhcp`
/// respectivamente (§7.12).
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

/// Precedencia de hostname en modo pasivo (§7.15):
/// alias > mDNS/fn > DHCP (lease o capturado) > último conocido.
///
/// En pasivo no hay consultas NetBIOS ni DNS inverso; el «último conocido» lo
/// conserva la persistencia, porque el upsert no pisa un hostname con NULL.
pub fn hostname_precedence_pasivo(mdns: Option<&str>, dhcp: Option<&str>) -> Option<String> {
    hostname_precedence(mdns, None, dhcp, None)
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

/// Ejecuta un ciclo de descubrimiento completo (F1 + F2 + F4).
///
/// `observado` e `identidad` son los almacenes compartidos con el hilo de
/// captura de F4: al inicio del ciclo se vacían y sus observaciones se fusionan
/// como una fuente L2 más (§7.14).
pub async fn run_scan(
    options: &ScanOptions,
    state: &mut ScanState,
    discovery_state: &mut DiscoveryState,
    manual: bool,
    observado: &Arc<Mutex<ObservedHosts>>,
    identidad: &Arc<Mutex<CaptureIdentityStore>>,
) -> ScanReport {
    let started = Instant::now();
    let mut errors = Vec::new();

    // Al inicio del ciclo se drenan los almacenes de la captura para no
    // retener los locks durante el escaneo.
    let (observados_captura, identidades_captura) = drenar_captura(observado, identidad);

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
    let macs_locales_normalizadas: HashSet<String> = macs_locales
        .iter()
        .filter_map(|mac| oui::normalize_mac(mac))
        .collect();

    // --- F4: equipos observados en la captura como fuente L2 (§7.14) ---
    //
    // Un equipo ya visto por ARP/ICMP no se duplica ni cambia de IP: solo gana
    // la fuente `capture` y la identidad DHCP capturada. Los equipos que solo
    // ha visto la captura se incorporan al ciclo y pueden provocar `new`.
    fusionar_observados(&mut hosts, observados_captura, &macs_locales_normalizadas);
    fusionar_identidad(&mut hosts, &identidades_captura);
    hosts.retain(|host| !macs_locales_normalizadas.contains(&host.mac));

    // Reverse DNS con timeout corto y concurrencia limitada. En modo pasivo no
    // se hace (§7.15) y en ningún modo se resuelve una IP de Internet: solo las
    // de las subredes locales del equipo.
    if dns_inverso_habilitado(options) {
        let redes = redes_locales(&selected, &options.ranges);
        let ips: Vec<Ipv4Addr> = hosts
            .iter()
            .map(|host| host.ip)
            .filter(|ip| es_ip_de_subred_local(*ip, &redes))
            .collect();
        let resueltos = dns::resolve_many(&ips, options.timeout, options.concurrency.max(1)).await;
        let por_ip: HashMap<Ipv4Addr, String> = resueltos.into_iter().collect();
        for host in &mut hosts {
            if let Some(nombre) = por_ip.get(&host.ip) {
                host.hostname = Some(nombre.clone());
                host.reverse_dns_name = Some(nombre.clone());
            }
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
    let netbios = if netbios_habilitado(options) {
        discovery::query_netbios(
            &pares,
            discovery::NETBIOS_TIMEOUT,
            discovery::NETBIOS_CONCURRENCY,
        )
        .await
    } else {
        HashMap::new()
    };
    aplicar_fuentes_pasivas(&mut hosts, &pasivo, &[], &netbios, options.passive_only);

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
        aplicar_fuentes_pasivas(
            &mut hosts,
            &fuentes_activas,
            &upnp_devices,
            &HashMap::new(),
            options.passive_only,
        );

        let objetivos = state.select_for_active_scan(&hosts, manual);
        let inicio_escaneo_activo = Instant::now();
        let escaneos = discovery::scan_hosts_active(&objetivos, &options.top_ports).await;
        // Medición del §8 de F2 (port scan de TOP-20 sobre los hosts del ciclo).
        tracing::debug!(
            hosts = objetivos.len(),
            duracion_ms = inicio_escaneo_activo.elapsed().as_millis(),
            "port scan activo completado"
        );
        for escaneo in escaneos {
            // Sin un port scan real no se pueden deducir cierres de servicios:
            // los puertos no escaneados no deben interpretarse como cerrados.
            let port_scan_ok = !escaneo
                .errors
                .iter()
                .any(|error| error.starts_with(PREFIJO_ERROR_PORT_SCAN));
            errors.extend(escaneo.errors.clone());
            aplicar_escaneo_activo(&mut hosts, &escaneo, &options.top_ports, port_scan_ok);
        }
    }

    // Cierre de identidad: MAC privada y SO combinado (F2 + DHCP + modelo + UA).
    for host in &mut hosts {
        host.mac_random = mac_ident::is_private(&host.mac);
        host.combinar_os();
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

/// Drena los equipos observados y la identidad acumulada por la captura (F4).
///
/// Identidad capturada de un equipo: puede venir por MAC o por IP y trae las
/// señales DHCP y el User-Agent observados (§7.12).
type IdentidadCapturada = (Option<String>, Option<IpAddr>, DeviceIdentitySignals);

/// Se vacían al inicio del ciclo para no retener los locks mientras se hace el
/// escaneo. Un lock envenenado por un pánico de la captura no aborta el ciclo:
/// se continúa sin las observaciones de ese almacén.
fn drenar_captura(
    observado: &Arc<Mutex<ObservedHosts>>,
    identidad: &Arc<Mutex<CaptureIdentityStore>>,
) -> (Vec<ObservedHost>, Vec<IdentidadCapturada>) {
    let equipos = match observado.lock() {
        Ok(mut buffer) => buffer.drain(),
        Err(_) => Vec::new(),
    };
    let identidades = match identidad.lock() {
        Ok(mut almacen) => almacen.drain(),
        Err(_) => Vec::new(),
    };
    (equipos, identidades)
}

/// Fusiona los equipos observados por la captura como una fuente L2 más.
///
/// Un equipo ya conocido por su MAC no se duplica ni se le cambia la IP que
/// confirmó el ARP: solo se le añade la fuente [`DiscoverySource::Capture`] y la
/// identidad DHCP que traiga la observación. Los equipos nuevos se incorporan al
/// ciclo (podrán provocar el evento `new`).
fn fusionar_observados(
    hosts: &mut Vec<Host>,
    observados: Vec<ObservedHost>,
    macs_locales: &HashSet<String>,
) {
    for observado in observados {
        let Some(mac) = oui::normalize_mac(&observado.mac) else {
            continue;
        };
        if !es_mac_utilizable(&mac) || macs_locales.contains(&mac) {
            continue;
        }
        if let Some(host) = hosts.iter_mut().find(|host| host.mac == mac) {
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Capture);
            aplicar_dhcp_observado(host, observado.dhcp.as_ref());
            continue;
        }
        let mut host = Host::new(mac, observado.ip);
        host.discovery_sources.push(DiscoverySource::Capture);
        aplicar_dhcp_observado(&mut host, observado.dhcp.as_ref());
        hosts.push(host);
    }
}

/// Aplica la identidad capturada (DHCP y User-Agent) a los equipos ya conocidos.
///
/// Las entradas llegan por MAC (identidad DHCP) y por IP (User-Agent y DHCP con
/// IP): se busca primero la MAC y, si no hay, la IP. La identidad DHCP solo se
/// atribuye cuando la MAC coincide, para no pasarle la huella de un equipo a
/// otro en un cambio de IP.
fn fusionar_identidad(hosts: &mut [Host], identidades: &[IdentidadCapturada]) {
    for (mac, ip, senales) in identidades {
        let por_mac = mac
            .as_deref()
            .and_then(oui::normalize_mac)
            .and_then(|mac| hosts.iter().position(|host| host.mac == mac));
        let indice = match por_mac {
            Some(indice) => Some(indice),
            None => match ip {
                Some(ip) => hosts.iter().position(|host| IpAddr::V4(host.ip) == *ip),
                None => None,
            },
        };
        let Some(indice) = indice else {
            continue;
        };
        let host = &mut hosts[indice];
        if let Some(dhcp) = &senales.dhcp {
            let mac_coincide = dhcp
                .mac
                .as_deref()
                .and_then(oui::normalize_mac)
                .map(|mac| mac == host.mac)
                .unwrap_or(true);
            if mac_coincide {
                aplicar_dhcp_observado(host, Some(dhcp));
            }
        }
        if let Some(user_agent) = &senales.user_agent {
            host.user_agent = Some(user_agent.clone());
        }
    }
}

/// Vuelca la identidad DHCP de una observación capturada en el equipo.
fn aplicar_dhcp_observado(host: &mut Host, dhcp: Option<&DhcpObservation>) {
    let Some(dhcp) = dhcp else {
        return;
    };
    if let Some(fingerprint) = dhcp.fingerprint.as_deref() {
        host.dhcp_fingerprint = Some(fingerprint.to_string());
    }
    if let Some(vendor) = dhcp.vendor.as_deref() {
        host.dhcp_vendor = Some(vendor.to_string());
    }
    if let Some(hostname) = dhcp.hostname.as_deref() {
        host.dhcp_hostname = Some(hostname.to_string());
        // El nombre DHCP capturado entra en la precedencia al nivel de lease.
        host.dhcp_name = Some(hostname.to_string());
    }
}

/// Señales de identidad de un equipo para la puntuación combinada de SO.
fn senales_os(host: &Host) -> OsSignals {
    let mut senales = OsSignals::default();
    // La familia de F2 solo existe si superó el umbral; sus puntos son la
    // puntuación obtenida (mínimo el umbral, 4).
    if let Some(familia) = host.os_family {
        senales.push(OsSource::Tcp, familia, host.fingerprint_score.max(4));
    }
    for (familia, puntos) in dhcp_ident::os_hints(
        host.dhcp_vendor.as_deref(),
        host.dhcp_fingerprint.as_deref(),
    ) {
        senales.push(OsSource::Dhcp, familia, puntos);
    }
    for (familia, puntos) in &host.model_os {
        senales.push(OsSource::Model, *familia, *puntos);
    }
    if let Some(ua) = host.user_agent.as_deref() {
        for (familia, puntos) in useragent::hints(ua).os {
            senales.push(OsSource::UserAgent, familia, puntos);
        }
    }
    senales
}

/// Acumulado de registros mDNS para una IP.
#[derive(Debug, Default)]
struct MdnsAgg {
    hostname: Option<String>,
    cast_name: Option<String>,
    model: Option<models_ident::ModelHint>,
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
            // Los TXT del servicio pueden anunciar el modelo (§7.12) y el
            // nombre amigable de Google Cast (`fn`, nivel mDNS de la
            // precedencia de hostname).
            if !servicio.txt.is_empty() {
                if acumulado.model.is_none() {
                    acumulado.model =
                        models_ident::from_mdns_txt(&servicio.service_type, &servicio.txt);
                }
                if acumulado.cast_name.is_none() {
                    acumulado.cast_name = models_ident::cast_friendly_name(&servicio.txt);
                }
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
///
/// `passive_only` selecciona la precedencia de hostname del modo pasivo (§7.15).
fn aplicar_fuentes_pasivas(
    hosts: &mut [Host],
    pasivo: &PassiveData,
    upnp: &[UpnpDevice],
    netbios: &HashMap<String, crate::discovery::netbios::NetbiosInfo>,
    passive_only: bool,
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
            // El nombre amigable de Cast (`fn`) vive al nivel de mDNS: manda
            // sobre el hostname .local si ambos están anunciados.
            if host.mdns_name.is_none() {
                host.mdns_name = acumulado
                    .cast_name
                    .clone()
                    .or_else(|| acumulado.hostname.clone());
            }
            for servicio in &acumulado.mdns_services {
                if !host.mdns_services.contains(servicio) {
                    host.mdns_services.push(servicio.clone());
                }
            }
            for servicio in &acumulado.services {
                fusionar_servicio(&mut host.services, servicio.clone());
            }
            if let Some(pista) = &acumulado.model {
                fusionar_modelo(host, pista);
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
            if let Some(pista) = models_ident::from_upnp(descripcion) {
                fusionar_modelo(host, &pista);
            }
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Ssdp);
        } else if ssdp_ips.contains(&host.ip) {
            anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Ssdp);
        }

        let dhcp = host.dhcp_name.as_deref().or(host.dhcp_hostname.as_deref());
        host.hostname = if passive_only {
            hostname_precedence_pasivo(host.mdns_name.as_deref(), dhcp)
        } else {
            hostname_precedence(
                host.mdns_name.as_deref(),
                host.netbios_name.as_deref(),
                dhcp,
                host.reverse_dns_name.as_deref(),
            )
        };
    }
}

/// Fusiona una pista de modelo (mDNS o UPnP) sin duplicar señales.
fn fusionar_modelo(host: &mut Host, pista: &models_ident::ModelHint) {
    if host.model.is_none() {
        host.model = pista.model.clone();
    }
    for (familia, puntos) in &pista.os {
        if !host.model_os.contains(&(*familia, *puntos)) {
            host.model_os.push((*familia, *puntos));
        }
    }
    if host.model_device_type.is_none() {
        host.model_device_type = pista.device_type;
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

/// Prefijo del error con el que `discovery::scan_host_active` avisa de que el
/// escaneo de puertos no se pudo ejecutar (mismo texto en `src/discovery/mod.rs`).
const PREFIJO_ERROR_PORT_SCAN: &str = "El port scan de ";

/// Aplica el resultado del escaneo activo de un equipo.
///
/// `top_ports` y `port_scan_ok` describen el escaneo de puertos del ciclo: solo
/// con un escaneo real (y no fallido) se guardan los puertos intentados, los
/// abiertos y la fuente `portscan`, que es la línea base de `service_new` y
/// `service_gone` (§7.7). El fingerprint se aplica aunque falle el port scan:
/// son pruebas independientes.
fn aplicar_escaneo_activo(
    hosts: &mut [Host],
    escaneo: &HostActiveScan,
    top_ports: &[u16],
    port_scan_ok: bool,
) {
    let Some(host) = hosts.iter_mut().find(|host| host.mac == escaneo.mac) else {
        return;
    };
    for servicio in &escaneo.services {
        fusionar_servicio(&mut host.services, servicio.clone());
    }
    if port_scan_ok && !top_ports.is_empty() {
        host.port_scan_attempted = true;
        host.port_scan_ports = top_ports.to_vec();
        host.port_scan_services = escaneo.services.clone();
        anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Portscan);
    }
    if escaneo.fingerprint_attempted {
        host.fingerprint_attempted = true;
        host.os_family = escaneo.os_family;
        host.fingerprint_score = escaneo.os_score;
        host.last_fingerprint = escaneo.last_fingerprint.clone();
    }
}

/// Heurística para distinguir un televisor de un dispositivo de streaming.
fn parece_televisor(host: &Host) -> bool {
    // Un User-Agent de TV (Tizen, Web0S o SMART-TV) lo dice explícitamente y
    // manda sobre el nombre del equipo (§7.12).
    if host
        .user_agent
        .as_deref()
        .map(|ua| useragent::hints(ua).is_tv)
        .unwrap_or(false)
    {
        return true;
    }
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

/// Clasifica el tipo automático de F4: las reglas de modelo y User-Agent van
/// antes que las de hostname de F2 (§7.12).
///
/// Las señales que la especificación coloca antes del nombre (gateway,
/// impresora, cámara, TV/streaming y NAS) siguen mandando sobre la pista; si no
/// hay ninguna, la pista de F4 sustituye a la clasificación por hostname.
fn clasificar_tipo(host: &Host, contexto: DeviceCtx) -> DeviceType {
    let Some(pista) = tipo_por_modelo_o_user_agent(host) else {
        return classify::device_type(&contexto);
    };
    let mut sin_hostname = contexto;
    sin_hostname.hostname = None;
    let base = classify::device_type(&sin_hostname);
    if base == DeviceType::Unknown {
        pista
    } else {
        base
    }
}

/// Tipo de equipo sugerido por el modelo anunciado o por el User-Agent.
fn tipo_por_modelo_o_user_agent(host: &Host) -> Option<DeviceType> {
    if let Some(tipo) = host.model_device_type {
        return Some(tipo);
    }
    host.user_agent
        .as_deref()
        .and_then(|ua| useragent::hints(ua).device_type)
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
    /// FK al equipo del evento (F6: señal para el motor de alertas).
    pub device_id: i64,
    /// Detalles JSON del evento, tal como se persistieron (F6).
    pub details: String,
    /// DEVICE_EVENTS.id del evento creado (referencia lógica de la alerta, F6).
    pub event_id: Option<i64>,
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
                EventType::Reappeared => {
                    mensaje_con_etiqueta("Vuelve a estar en línea:", &evento.label, &evento.ip)
                }
                EventType::ServiceNew => {
                    mensaje_con_etiqueta("Nuevo servicio en", &evento.label, &evento.ip)
                }
                EventType::ServiceGone => {
                    mensaje_con_etiqueta("Servicio cerrado en", &evento.label, &evento.ip)
                }
                EventType::OsChanged => {
                    mensaje_con_etiqueta("Cambio de SO en", &evento.label, &evento.ip)
                }
                EventType::TypeChanged => {
                    mensaje_con_etiqueta("Cambio de tipo en", &evento.label, &evento.ip)
                }
            };
            let nivel = match evento.event_type {
                EventType::New | EventType::Disappeared | EventType::MacChanged => Level::Warn,
                EventType::Reappeared | EventType::ServiceNew | EventType::ServiceGone => {
                    Level::Info
                }
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

/// Persiste un evento nuevo y lo añade al resumen del ciclo.
fn registrar_evento(
    repo: &mut Repo,
    device_id: i64,
    evento: &NewEvent,
    host: &Host,
    etiqueta: &str,
    events: &mut Vec<ReconciledEvent>,
    errors: &mut Vec<String>,
) {
    let details = evento.details.to_string();
    match repo.append_event_id(device_id, evento.tipo, &details) {
        Ok(event_id) => events.push(ReconciledEvent {
            event_type: evento.tipo,
            ip: host.ip.to_string(),
            label: etiqueta.to_string(),
            device_id,
            details,
            event_id: Some(event_id),
        }),
        Err(err) => errors.push(format!(
            "No se pudo registrar {} de {}: {err}",
            evento.tipo.as_str(),
            host.ip
        )),
    }
}

/// Calcula los eventos de servicios de un escaneo de puertos real (§7.7).
///
/// Se llama antes de escribir los servicios y las fuentes del ciclo: la fuente
/// `portscan` de DISCOVERY_SOURCES distingue el primer escaneo (línea base, sin
/// eventos) y los servicios conocidos son los persistidos antes del upsert. El
/// puerto y el protocolo de cada cierre viajan en el detalle del `service_gone`;
/// el llamador los usa después para materializar el STALE de F2.
fn eventos_de_servicios(
    repo: &Repo,
    device_id: i64,
    host: &Host,
    passive_only: bool,
    errores: &mut Vec<String>,
) -> Vec<NewEvent> {
    if !host.port_scan_attempted || passive_only {
        return Vec::new();
    }

    let ya_escaneado = match repo.list_sources(device_id) {
        Ok(fuentes) => fuentes
            .iter()
            .any(|fila| fila.source == DiscoverySource::Portscan),
        Err(err) => {
            errores.push(format!(
                "No se pudieron leer las fuentes de {}: {err}",
                host.ip
            ));
            return Vec::new();
        }
    };

    let conocidos = match repo.list_services(device_id) {
        Ok(servicios) => servicios,
        Err(err) => {
            errores.push(format!(
                "No se pudieron leer los servicios de {}: {err}",
                host.ip
            ));
            return Vec::new();
        }
    };

    Changes::services(
        ya_escaneado,
        passive_only,
        &host.port_scan_ports,
        &host.port_scan_services,
        &conocidos,
    )
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
    let ahora_sistema = SystemTime::now();
    let ahora = DateTime::<Utc>::from(ahora_sistema).to_rfc3339_opts(SecondsFormat::Secs, true);
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

    // Identidad persistida de los equipos conocidos, para la regla de rotación
    // de MAC privada de mac_changed v2 (§7.13).
    let identidades_conocidas: Vec<mac_ident::DeviceIdentity> = previos
        .iter()
        .map(|device| mac_ident::DeviceIdentity {
            id: device.id,
            mac: device.mac.clone(),
            dhcp_fingerprint: device.dhcp_fingerprint.clone(),
            dhcp_hostname: device.dhcp_hostname.clone(),
            seen_this_cycle: macs_actuales.contains(&device.mac),
        })
        .collect();
    // Equipos cuya MAC ya se ha fusionado en este ciclo: no pueden ser
    // candidatos de otra fusión (nunca se fusiona dos veces el mismo equipo).
    let mut fusionados: HashSet<i64> = HashSet::new();

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

        // Cambio de identidad de mac_changed v2 (§7.13): primero la rotación
        // de MAC privada con la misma identidad DHCP y después la toma de IP de
        // F1, que no se aplica si las huellas DHCP se contradicen.
        if !previos_por_mac.contains_key(&host.mac) {
            let candidato = candidato_cambio_identidad(
                host,
                &previos,
                &previos_por_mac,
                &identidades_conocidas,
                &macs_actuales,
                &fusionados,
            );
            if let Some((anterior, motivo)) = candidato {
                if let Err(err) = repo.update_device_mac(anterior.id, &host.mac) {
                    errors.push(format!(
                        "No se pudo actualizar la MAC de {}: {err}",
                        anterior.ip
                    ));
                } else {
                    let details = serde_json::json!({
                        "before": anterior.mac,
                        "after": host.mac,
                        "reason": motivo,
                    })
                    .to_string();
                    let mut event_id = None;
                    match repo.append_event_id(anterior.id, EventType::MacChanged, &details) {
                        Ok(id) => event_id = Some(id),
                        Err(err) => errors.push(format!("No se pudo registrar mac_changed: {err}")),
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::MacChanged,
                        ip: host.ip.to_string(),
                        label: anterior.display_name().to_string(),
                        device_id: anterior.id,
                        details,
                        event_id,
                    });
                    fusionados.insert(anterior.id);
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
        let mut tipo = clasificar_tipo(host, contexto);
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

                // Presencia: un equipo OFFLINE que vuelve a verse (§7.7 y §7.8).
                if cambios.became_online {
                    if let Some(previo) = previos_por_mac.get(&host.mac) {
                        if let Some(evento) = Changes::presence(previo, true, ahora_sistema) {
                            registrar_evento(
                                repo,
                                device_id,
                                &evento,
                                host,
                                &etiqueta,
                                &mut events,
                                &mut errors,
                            );
                        }
                    }
                }

                if cambios.is_new {
                    nuevos += 1;
                    // `mac_random` permite a F6 bajar la severidad de un equipo
                    // nuevo detectado en la captura detrás de una MAC privada.
                    let mac_random = host.mac_random || mac_ident::is_private(&host.mac);
                    let details = serde_json::json!({
                        "before": serde_json::Value::Null,
                        "after": {
                            "ip": host.ip.to_string(),
                            "hostname": host.hostname,
                            "vendor": host.vendor,
                        },
                        "mac_random": mac_random,
                    })
                    .to_string();
                    let mut event_id = None;
                    match repo.append_event_id(device_id, EventType::New, &details) {
                        Ok(id) => event_id = Some(id),
                        Err(err) => errors.push(format!("No se pudo registrar new: {err}")),
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::New,
                        ip: host.ip.to_string(),
                        label: etiqueta.clone(),
                        device_id,
                        details,
                        event_id,
                    });
                }
                if let Some((antes, despues)) = &cambios.ip_changed {
                    let details =
                        serde_json::json!({"before": antes, "after": despues}).to_string();
                    let mut event_id = None;
                    match repo.append_event_id(device_id, EventType::IpChanged, &details) {
                        Ok(id) => event_id = Some(id),
                        Err(err) => errors.push(format!("No se pudo registrar ip_changed: {err}")),
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::IpChanged,
                        ip: despues.clone(),
                        label: etiqueta.clone(),
                        device_id,
                        details,
                        event_id,
                    });
                }
                if let Some((antes, despues)) = &cambios.hostname_changed {
                    let details =
                        serde_json::json!({"before": antes, "after": despues}).to_string();
                    let mut event_id = None;
                    match repo.append_event_id(device_id, EventType::HostnameChanged, &details) {
                        Ok(id) => event_id = Some(id),
                        Err(err) => {
                            errors.push(format!("No se pudo registrar hostname_changed: {err}"));
                        }
                    }
                    events.push(ReconciledEvent {
                        event_type: EventType::HostnameChanged,
                        ip: host.ip.to_string(),
                        label: etiqueta.clone(),
                        device_id,
                        details,
                        event_id,
                    });
                }

                // Identidad de F4: modelo, señales DHCP, User-Agent y SO
                // combinado con su fuente. Los campos a None conservan el valor
                // persistido (las señales llegan en ciclos distintos).
                let identidad = IdentityUpdate {
                    model: host.model.clone(),
                    dhcp_fingerprint: host.dhcp_fingerprint.clone(),
                    dhcp_vendor: host.dhcp_vendor.clone(),
                    dhcp_hostname: host.dhcp_hostname.clone(),
                    user_agent: host.user_agent.clone(),
                    os_family: host.os_family,
                    os_source: host.os_source,
                };
                if identidad != IdentityUpdate::default() {
                    if let Err(err) = repo.set_device_identity(device_id, &identidad) {
                        errors.push(format!(
                            "No se pudo guardar la identidad de {}: {err}",
                            host.ip
                        ));
                    }
                }
                // Fingerprint de SO: si se intentó y la puntuación combinada no
                // supera el umbral, se deja NULL (regla de F2, §7.12).
                if host.fingerprint_attempted && host.os_family.is_none() {
                    if let Err(err) = repo.set_os_family(device_id, None) {
                        errors.push(format!("No se pudo limpiar os_family: {err}"));
                    }
                }
                if let Some(fingerprint) = &host.last_fingerprint {
                    if let Err(err) = repo.set_last_fingerprint(device_id, Some(fingerprint)) {
                        errors.push(format!("No se pudo guardar last_fingerprint: {err}"));
                    }
                }

                // Servicios: se comparan con lo persistido ANTES de escribir
                // los servicios y las fuentes de este ciclo (§7.7). La fuente
                // `portscan` de DISCOVERY_SOURCES marca la línea base: en el
                // primer escaneo del equipo no hay eventos.
                let eventos_servicio =
                    eventos_de_servicios(repo, device_id, host, report.passive_only, &mut errors);
                let mut puertos_cerrados: Vec<(u16, Protocol)> = Vec::new();
                for evento in &eventos_servicio {
                    if evento.tipo == EventType::ServiceGone {
                        if let (Some(port), Some(protocol)) = (
                            evento.details.get("port").and_then(|valor| valor.as_u64()),
                            evento
                                .details
                                .get("protocol")
                                .and_then(|valor| valor.as_str())
                                .and_then(Protocol::from_str),
                        ) {
                            puertos_cerrados.push((port as u16, protocol));
                        }
                    }
                    registrar_evento(
                        repo,
                        device_id,
                        evento,
                        host,
                        &etiqueta,
                        &mut events,
                        &mut errors,
                    );
                }

                // Identidad: `os_changed` y `type_changed` comparando el equipo
                // previo con el ya persistido después de aplicar tipo e
                // identidad (§7.7).
                if let Some(previo) = previos_por_mac.get(&host.mac) {
                    match repo.get_device_by_mac(&host.mac) {
                        Ok(Some(actual)) => {
                            for evento in Changes::identity(previo, &actual) {
                                registrar_evento(
                                    repo,
                                    device_id,
                                    &evento,
                                    host,
                                    &etiqueta,
                                    &mut events,
                                    &mut errors,
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(err) => errors.push(format!(
                            "No se pudo releer el equipo {} para comparar su identidad: {err}",
                            host.ip
                        )),
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

                // Cierres del escaneo: el servicio queda STALE de forma
                // determinista para F2, sin cambiar el esquema (§7.7). Va
                // después del upsert para que el cierre visto por el escaneo
                // mande sobre un anuncio mDNS del mismo ciclo y el aviso no se
                // repita en el siguiente escaneo.
                for (port, protocol) in puertos_cerrados {
                    if let Err(err) =
                        repo.mark_service_closed(device_id, port, protocol, ahora_sistema)
                    {
                        errors.push(format!(
                            "No se pudo marcar cerrado el servicio {port}/{}: {err}",
                            protocol.as_str()
                        ));
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
                    // F5: la presencia (§7.8) usa last_seen para marcar el
                    // inicio de la ausencia, también tras un arranque.
                    "last_seen": &device.last_seen,
                })
                .to_string();
                let mut event_id = None;
                match repo.append_event_id(device.id, EventType::Disappeared, &details) {
                    Ok(id) => event_id = Some(id),
                    Err(err) => errors.push(format!("No se pudo registrar disappeared: {err}")),
                }
                events.push(ReconciledEvent {
                    event_type: EventType::Disappeared,
                    ip: device.ip.clone(),
                    label: device.display_name().to_string(),
                    device_id: device.id,
                    details,
                    event_id,
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

/// Elige el equipo conocido al que pertenece una MAC nueva de mac_changed v2.
///
/// Primero la regla A de rotación de MAC privada (misma huella y mismo nombre
/// DHCP, un único candidato no visto en el ciclo); después la heurística de
/// toma de IP de F1, que no se aplica si las huellas DHCP de los dos equipos se
/// contradicen. Con varios candidatos no se fusiona identidad: el equipo sale
/// como nuevo (§7.13).
fn candidato_cambio_identidad(
    host: &Host,
    previos: &[Device],
    previos_por_mac: &HashMap<String, Device>,
    identidades_conocidas: &[mac_ident::DeviceIdentity],
    macs_actuales: &HashSet<String>,
    fusionados: &HashSet<i64>,
) -> Option<(Device, &'static str)> {
    // Regla A: rotación de la MAC privada de un mismo equipo.
    let identidad = mac_ident::DhcpIdentity {
        mac: host.mac.clone(),
        dhcp_fingerprint: host.dhcp_fingerprint.clone(),
        dhcp_hostname: host.dhcp_hostname.clone(),
    };
    if let Some(id) = mac_ident::rotation_match(&identidad, identidades_conocidas) {
        if !fusionados.contains(&id) {
            if let Some(equipo) = previos_por_mac.values().find(|device| device.id == id) {
                return Some((equipo.clone(), "rotation"));
            }
        }
    }

    // Regla B: la MAC nueva ocupa la IP de un equipo online que ha desaparecido.
    let mut candidatos: Vec<&Device> = previos
        .iter()
        .filter(|device| {
            device.ip == host.ip.to_string()
                && device.mac != host.mac
                && !macs_actuales.contains(&device.mac)
                && device.is_online
                && !fusionados.contains(&device.id)
                && previos_por_mac.contains_key(&device.mac)
        })
        .collect();
    if candidatos.len() != 1 {
        return None;
    }
    let anterior = candidatos.remove(0);
    if huellas_dhcp_compatibles(anterior, host) {
        Some((anterior.clone(), "ip_takeover"))
    } else {
        None
    }
}

/// Indica si las huellas DHCP del equipo anterior y del nuevo no se contradicen.
///
/// Solo se contradicen si los dos equipos tienen huella y es distinta (§7.13);
/// sin evidencia DHCP suficiente se mantiene la toma de IP de F1.
fn huellas_dhcp_compatibles(anterior: &Device, host: &Host) -> bool {
    let anterior_huella = anterior
        .dhcp_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|huella| !huella.is_empty());
    let nueva_huella = host
        .dhcp_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|huella| !huella.is_empty());
    match (anterior_huella, nueva_huella) {
        (Some(anterior), Some(nueva)) => anterior == nueva,
        _ => true,
    }
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
        assert_eq!(EventType::ALL.len(), 10);
        assert_eq!(EventType::New.as_str(), "new");
        assert_eq!(
            EventType::from_str("mac_changed"),
            Some(EventType::MacChanged)
        );
        assert_eq!(EventType::from_str("otro"), None);
        // F5: los cinco tipos nuevos van y vuelven sin cambio de esquema.
        for tipo in [
            EventType::Reappeared,
            EventType::ServiceNew,
            EventType::ServiceGone,
            EventType::OsChanged,
            EventType::TypeChanged,
        ] {
            assert_eq!(EventType::from_str(tipo.as_str()), Some(tipo));
        }
        assert_eq!(EventType::Reappeared.as_str(), "reappeared");
        assert_eq!(EventType::ServiceGone.as_str(), "service_gone");
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

    /// Informe de un ciclo en modo pasivo (sin tráfico activo, §7.7).
    fn informe_pasivo(hosts: Vec<Host>) -> ScanReport {
        ScanReport {
            passive_only: true,
            ..informe_de_prueba(hosts)
        }
    }

    /// Servicio TCP detectado por puerto, como lo dejaría el escaneo activo.
    fn servicio_tcp(puerto: u16) -> DetectedService {
        DetectedService {
            port: puerto,
            protocol: Protocol::Tcp,
            service: classify::service(puerto, None),
            banner: None,
        }
    }

    /// Marca en el host un escaneo de puertos real con sus puertos abiertos.
    fn aplicar_portscan_de_prueba(host: &mut Host, escaneados: &[u16], abiertos: &[u16]) {
        host.port_scan_attempted = true;
        host.port_scan_ports = escaneados.to_vec();
        host.port_scan_services = abiertos
            .iter()
            .map(|puerto| servicio_tcp(*puerto))
            .collect();
        for servicio in &host.port_scan_services {
            fusionar_servicio(&mut host.services, servicio.clone());
        }
        anyadir_fuente(&mut host.discovery_sources, DiscoverySource::Portscan);
    }

    /// Tipos de evento de una reconciliación.
    fn tipos_de_evento(reconciliacion: &Reconciliation) -> Vec<EventType> {
        reconciliacion
            .events
            .iter()
            .map(|evento| evento.event_type)
            .collect()
    }

    /// Eventos persistidos de un tipo, con los detalles JSON ya parseados.
    fn eventos_persistidos(repo: &Repo, device_id: i64, tipo: EventType) -> Vec<serde_json::Value> {
        repo.list_events(device_id)
            .unwrap()
            .into_iter()
            .filter(|evento| evento.event_type == tipo)
            .map(|evento| serde_json::from_str(&evento.details).unwrap())
            .collect()
    }

    /// Indica si una reconciliación ha emitido algún evento de servicios.
    fn hay_eventos_de_servicio(reconciliacion: &Reconciliation) -> bool {
        tipos_de_evento(reconciliacion)
            .iter()
            .any(|tipo| matches!(tipo, EventType::ServiceNew | EventType::ServiceGone))
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
    fn el_escaneo_activo_solo_marca_puertos_y_fuente_si_es_real() {
        let mut hosts = vec![host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", None)];
        let escaneo = HostActiveScan {
            mac: "aa:bb:cc:dd:ee:01".to_string(),
            ip: "192.168.1.10".parse().unwrap(),
            services: vec![servicio_tcp(22)],
            os_family: None,
            os_score: 0,
            last_fingerprint: None,
            fingerprint_attempted: false,
            errors: Vec::new(),
        };
        aplicar_escaneo_activo(&mut hosts, &escaneo, &[22, 80], true);
        assert!(hosts[0].port_scan_attempted);
        assert_eq!(hosts[0].port_scan_ports, vec![22, 80]);
        assert_eq!(hosts[0].port_scan_services.len(), 1);
        assert!(hosts[0]
            .discovery_sources
            .contains(&DiscoverySource::Portscan));

        // Un port scan fallido no marca la línea base ni los puertos: sin
        // escaneo real no se pueden deducir cierres de servicios.
        let mut hosts = vec![host_de_prueba("aa:bb:cc:dd:ee:02", "192.168.1.11", None)];
        let mut escaneo_fallido = escaneo.clone();
        escaneo_fallido.mac = "aa:bb:cc:dd:ee:02".to_string();
        escaneo_fallido.ip = "192.168.1.11".parse().unwrap();
        escaneo_fallido.errors.push(format!(
            "{PREFIJO_ERROR_PORT_SCAN}192.168.1.11 falló: sin ruta al equipo"
        ));
        aplicar_escaneo_activo(&mut hosts, &escaneo_fallido, &[22, 80], false);
        assert!(!hosts[0].port_scan_attempted);
        assert!(hosts[0].port_scan_ports.is_empty());
        assert!(!hosts[0]
            .discovery_sources
            .contains(&DiscoverySource::Portscan));
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
    fn reconcilia_reappeared_con_ausencia_y_disappeared_con_last_seen() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(1);

        let inicial = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.10",
            Some("laptop"),
        )]);
        let primera = reconcile(&mut repo, &inicial, &mut tracker, 90, STALE_FUTURO).unwrap();
        let device_id = primera.devices[0].id;
        let last_seen_inicial = primera.devices[0].last_seen.clone();

        // Un ciclo sin verlo: OFFLINE y evento disappeared con last_seen (§7.7).
        let vacio = informe_de_prueba(vec![]);
        let segunda = reconcile(&mut repo, &vacio, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert!(tipos_de_evento(&segunda).contains(&EventType::Disappeared));
        let desaparecido = eventos_persistidos(&repo, device_id, EventType::Disappeared);
        assert_eq!(desaparecido.len(), 1);
        assert_eq!(desaparecido[0]["last_seen"], last_seen_inicial);

        // Se fuerza un last_seen antiguo para comprobar la ausencia calculada.
        repo.connection()
            .execute(
                "UPDATE DEVICES SET last_seen = ?1 WHERE id = ?2",
                rusqlite::params!["2000-01-01T00:00:00Z", device_id],
            )
            .unwrap();

        let reaparece = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.10",
            Some("laptop"),
        )]);
        let tercera = reconcile(&mut repo, &reaparece, &mut tracker, 90, STALE_FUTURO).unwrap();
        let tipos = tipos_de_evento(&tercera);
        assert!(tipos.contains(&EventType::Reappeared));
        assert!(!tipos.contains(&EventType::New));
        let reaparecido = eventos_persistidos(&repo, device_id, EventType::Reappeared);
        assert_eq!(reaparecido.len(), 1);
        assert_eq!(reaparecido[0]["away_since"], "2000-01-01T00:00:00Z");
        assert!(reaparecido[0]["away_s"].as_u64().unwrap_or(0) > 0);
        assert!(tercera
            .notifications()
            .iter()
            .any(|notificacion| notificacion.message.contains("Vuelve a estar en línea")));

        // Un ciclo más con el equipo presente no repite el aviso.
        let cuarta = reconcile(&mut repo, &reaparece, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert!(!tipos_de_evento(&cuarta).contains(&EventType::Reappeared));
        assert_eq!(
            eventos_persistidos(&repo, device_id, EventType::Reappeared).len(),
            1
        );
    }

    #[test]
    fn reconcilia_os_changed_y_type_changed_automaticos() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        // Ciclo 1: SSH → PC y SO Linux por huella TCP.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        host.services.push(servicio_tcp(22));
        host.os_family = Some(OsFamily::Linux);
        host.os_source = Some(OsSource::Tcp);
        let primera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        let device_id = primera.devices[0].id;
        assert_eq!(primera.devices[0].device_type, "pc");
        assert_eq!(primera.devices[0].os_family.as_deref(), Some("linux"));

        // Ciclo 2: SSH + HTTP → servidor y SO Windows por DHCP.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        host.services.push(servicio_tcp(22));
        host.services.push(servicio_tcp(80));
        host.os_family = Some(OsFamily::Windows);
        host.os_source = Some(OsSource::Dhcp);
        let segunda = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        let tipos = tipos_de_evento(&segunda);
        assert!(tipos.contains(&EventType::OsChanged));
        assert!(tipos.contains(&EventType::TypeChanged));

        let os = eventos_persistidos(&repo, device_id, EventType::OsChanged);
        assert_eq!(os.len(), 1);
        assert_eq!(os[0]["before"], "linux");
        assert_eq!(os[0]["after"], "windows");
        assert_eq!(os[0]["os_source"], "dhcp");
        let tipo = eventos_persistidos(&repo, device_id, EventType::TypeChanged);
        assert_eq!(tipo.len(), 1);
        assert_eq!(tipo[0]["before"], "pc");
        assert_eq!(tipo[0]["after"], "server");

        // El mismo escaneo repetido no duplica los eventos de identidad.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        host.services.push(servicio_tcp(22));
        host.services.push(servicio_tcp(80));
        host.os_family = Some(OsFamily::Windows);
        host.os_source = Some(OsSource::Dhcp);
        let tercera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert!(!tipos_de_evento(&tercera).contains(&EventType::OsChanged));
        assert!(!tipos_de_evento(&tercera).contains(&EventType::TypeChanged));
    }

    #[test]
    fn identidad_no_emite_con_unknown_ni_con_override_manual() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        // Unknown → PC: el tipo desconocido no genera type_changed.
        let inicial = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.10",
            None,
        )]);
        let primera = reconcile(&mut repo, &inicial, &mut tracker, 90, STALE_FUTURO).unwrap();
        let device_id = primera.devices[0].id;
        assert_eq!(primera.devices[0].device_type, "unknown");

        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", None);
        host.services.push(servicio_tcp(22));
        host.os_family = Some(OsFamily::Linux);
        host.os_source = Some(OsSource::Tcp);
        let segunda = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(segunda.devices[0].device_type, "pc");
        let tipos = tipos_de_evento(&segunda);
        assert!(!tipos.contains(&EventType::TypeChanged));
        // os_family NULL → linux tampoco es un cambio entre valores no nulos.
        assert!(!tipos.contains(&EventType::OsChanged));

        // Override manual: el automático pasa de pc a server y no hay evento.
        repo.set_device_type_manual(device_id, Some(crate::classify::DeviceType::Mobile))
            .unwrap();
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", None);
        host.services.push(servicio_tcp(22));
        host.services.push(servicio_tcp(80));
        host.os_family = Some(OsFamily::Linux);
        host.os_source = Some(OsSource::Tcp);
        let tercera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        let tipos = tipos_de_evento(&tercera);
        assert!(!tipos.contains(&EventType::TypeChanged));
        assert!(!tipos.contains(&EventType::OsChanged));
        let dispositivo = tercera
            .devices
            .iter()
            .find(|dispositivo| dispositivo.id == device_id)
            .unwrap();
        assert_eq!(
            dispositivo.device_type, "server",
            "el automático cambia por debajo"
        );
        assert_eq!(dispositivo.effective_device_type(), "mobile");
    }

    #[test]
    fn reconcilia_eventos_de_servicios_con_escaneo_real() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);
        let puertos = [22u16, 80, 443];

        // Primer escaneo: es la línea base y no genera eventos de servicios.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[22]);
        let primera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        let device_id = primera.devices[0].id;
        assert!(!hay_eventos_de_servicio(&primera));
        assert_eq!(repo.list_services(device_id).unwrap().len(), 1);
        assert!(repo
            .list_sources(device_id)
            .unwrap()
            .iter()
            .any(|fila| fila.source == DiscoverySource::Portscan));

        // Segundo escaneo: el 80 aparece y el 22 sigue abierto.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[22, 80]);
        let segunda = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        let nuevos = eventos_persistidos(&repo, device_id, EventType::ServiceNew);
        assert_eq!(nuevos.len(), 1);
        assert_eq!(nuevos[0]["port"], 80);
        assert_eq!(nuevos[0]["protocol"], "tcp");
        assert_eq!(nuevos[0]["service"], "http");
        assert_eq!(nuevos[0]["reopened"], false);
        assert!(segunda
            .notifications()
            .iter()
            .any(|notificacion| notificacion.message.contains("Nuevo servicio en")));

        // Repetir el mismo escaneo no duplica el aviso (idempotencia).
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[22, 80]);
        let repetida = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert!(!hay_eventos_de_servicio(&repetida));

        // Tercer escaneo: el 22 se ve cerrado → service_gone y STALE determinista.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[80]);
        let tercera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        let cerrados = eventos_persistidos(&repo, device_id, EventType::ServiceGone);
        assert_eq!(cerrados.len(), 1);
        assert_eq!(cerrados[0]["port"], 22);
        assert_eq!(cerrados[0]["protocol"], "tcp");
        assert_eq!(cerrados[0]["service"], "ssh");
        assert!(tercera
            .notifications()
            .iter()
            .any(|notificacion| notificacion.message.contains("Servicio cerrado en")));
        let servicio_cerrado = repo
            .list_services(device_id)
            .unwrap()
            .into_iter()
            .find(|servicio| servicio.port == 22)
            .expect("el puerto cerrado sigue persistido");
        assert!(
            servicio_cerrado.is_closed(),
            "el cierre se marca con closed_at (§7.12)"
        );
        assert_ne!(
            servicio_cerrado.last_seen, "2998-12-31T23:59:59Z",
            "last_seen ya no se mueve al cerrar: sigue siendo la última vez abierto"
        );

        // Repetir el escaneo con el 22 cerrado no repite service_gone.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[80]);
        let repetida = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert!(!hay_eventos_de_servicio(&repetida));
        assert_eq!(
            eventos_persistidos(&repo, device_id, EventType::ServiceGone).len(),
            1
        );

        // Cuarto escaneo: el 22 vuelve a abrirse → service_new con reopened.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[22, 80]);
        let cuarta = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert!(cuarta
            .notifications()
            .iter()
            .any(|notificacion| notificacion.message.contains("Nuevo servicio en")));
        let reabierto = eventos_persistidos(&repo, device_id, EventType::ServiceNew)
            .into_iter()
            .find(|detalles| detalles["port"] == 22)
            .expect("el puerto 22 debe tener un service_new de reapertura");
        assert_eq!(reabierto["reopened"], true);
    }

    #[test]
    fn sin_eventos_de_servicios_en_pasivo_y_el_stale_por_tiempo_no_avisa() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);
        let puertos = [22u16, 80];

        // Primer escaneo real: línea base.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[22]);
        let primera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert!(!hay_eventos_de_servicio(&primera));

        // Ciclo sin escaneo de puertos: el 22 solo pasa a STALE por tiempo y no
        // hay service_gone (§7.7).
        let host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        let ciclo = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert!(!hay_eventos_de_servicio(&ciclo));
        assert!(
            ciclo.stale_services >= 1,
            "el servicio no visto queda STALE por tiempo"
        );

        // Modo pasivo: aunque el host traiga datos de un escaneo, no se emiten
        // eventos de servicios.
        let mut host = host_de_prueba("aa:bb:cc:dd:ee:01", "192.168.1.10", Some("laptop"));
        aplicar_portscan_de_prueba(&mut host, &puertos, &[80]);
        let pasivo = reconcile(
            &mut repo,
            &informe_pasivo(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert!(!hay_eventos_de_servicio(&pasivo));
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
            false,
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
            false,
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
        let observado = std::sync::Arc::new(std::sync::Mutex::new(
            crate::identify::observed::ObservedHosts::default(),
        ));
        let identidad = std::sync::Arc::new(std::sync::Mutex::new(
            crate::identify::CaptureIdentityStore::new(),
        ));
        let informe = run_scan(
            &options,
            &mut state,
            &mut discovery_state,
            false,
            &observado,
            &identidad,
        )
        .await;

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

    // --- F4: captura como fuente de equipos, identidad y modo pasivo ---

    /// Observación DHCP de prueba con identidad completa.
    fn observacion_dhcp(
        mac: &str,
        ip: &str,
        vendor: &str,
        fingerprint: &str,
        hostname: &str,
    ) -> DhcpObservation {
        DhcpObservation {
            mac: Some(mac.to_string()),
            ip: Some(ip.parse::<IpAddr>().unwrap()),
            message_type: Some(1),
            fingerprint: Some(fingerprint.to_string()),
            vendor: Some(vendor.to_string()),
            hostname: Some(hostname.to_string()),
            client_id: None,
        }
    }

    /// Servicio mDNS de prueba con su TXT.
    fn servicio_mdns(
        service_type: &str,
        port: Option<u16>,
        txt: &[(&str, &str)],
    ) -> crate::discovery::mdns::MdnsService {
        crate::discovery::mdns::MdnsService {
            service_type: service_type.to_string(),
            name: None,
            port,
            txt: txt
                .iter()
                .map(|(clave, valor)| ((*clave).to_string(), (*valor).to_string()))
                .collect(),
        }
    }

    /// Registro mDNS de prueba asociado a una IP.
    fn registro_mdns(
        ip: &str,
        hostname: Option<&str>,
        servicios: Vec<crate::discovery::mdns::MdnsService>,
    ) -> crate::discovery::mdns::MdnsRecord {
        crate::discovery::mdns::MdnsRecord {
            ip: Some(ip.parse().unwrap()),
            hostname: hostname.map(str::to_string),
            services: servicios,
            hinfo_os: None,
        }
    }

    /// Equipo de prueba con la identidad DHCP de un móvil de MAC privada.
    fn host_privado_con_dhcp(mac: &str, ip: &str) -> Host {
        let mut host = host_de_prueba(mac, ip, None);
        host.dhcp_fingerprint = Some("1,121,3,6,15,119".to_string());
        host.dhcp_hostname = Some("iPhone-de-Marta".to_string());
        host.dhcp_vendor = Some("Apple".to_string());
        host.mac_random = true;
        host
    }

    #[test]
    fn los_equipos_observados_crean_y_completan_equipos_con_fuente_capture() {
        let mut hosts = vec![host_de_prueba(
            "3c:22:fb:11:22:33",
            "192.168.1.50",
            Some("impresora"),
        )];
        let ip_arp = hosts[0].ip;
        let observados = vec![
            ObservedHost {
                mac: "3C-22-FB-11-22-33".to_string(),
                ip: "192.168.1.51".parse().unwrap(),
                source: crate::inference::ObservedSource::Frame,
                dhcp: None,
            },
            ObservedHost {
                mac: "da:a1:19:00:00:01".to_string(),
                ip: "192.168.1.60".parse().unwrap(),
                source: crate::inference::ObservedSource::Dhcp,
                dhcp: Some(observacion_dhcp(
                    "da:a1:19:00:00:01",
                    "192.168.1.60",
                    "android-dhcp-13",
                    "1,3,6",
                    "movil-De-Marta",
                )),
            },
        ];
        fusionar_observados(&mut hosts, observados, &HashSet::new());

        assert_eq!(hosts.len(), 2, "el equipo ya conocido no se duplica");
        let conocido = hosts
            .iter()
            .find(|host| host.mac == "3c:22:fb:11:22:33")
            .expect("equipo del ARP");
        assert_eq!(conocido.ip, ip_arp, "no se pisa la IP confirmada por ARP");
        assert!(conocido
            .discovery_sources
            .contains(&DiscoverySource::Capture));
        assert_eq!(conocido.hostname.as_deref(), Some("impresora"));

        let nuevo = hosts
            .iter()
            .find(|host| host.mac == "da:a1:19:00:00:01")
            .expect("equipo de la captura");
        assert_eq!(nuevo.discovery_sources, vec![DiscoverySource::Capture]);
        assert_eq!(nuevo.dhcp_fingerprint.as_deref(), Some("1,3,6"));
        assert_eq!(nuevo.dhcp_vendor.as_deref(), Some("android-dhcp-13"));
        assert_eq!(nuevo.dhcp_hostname.as_deref(), Some("movil-De-Marta"));
        assert_eq!(nuevo.dhcp_name.as_deref(), Some("movil-De-Marta"));
        assert!(mac_ident::is_private(&nuevo.mac));
    }

    #[test]
    fn la_identidad_capturada_se_aplica_por_mac_y_por_ip_sin_mezclar_equipos() {
        let mut hosts = vec![host_de_prueba("da:a1:19:00:00:02", "192.168.1.70", None)];
        let ip: IpAddr = "192.168.1.70".parse().unwrap();
        let identidades = vec![
            (
                Some("da:a1:19:00:00:02".to_string()),
                None,
                DeviceIdentitySignals {
                    dhcp: Some(observacion_dhcp(
                        "da:a1:19:00:00:02",
                        "192.168.1.70",
                        "MSFT 5.0",
                        "1,3,6,15",
                        "portatil",
                    )),
                    user_agent: None,
                },
            ),
            (
                None,
                Some(ip),
                DeviceIdentitySignals {
                    dhcp: None,
                    user_agent: Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0".to_string()),
                },
            ),
        ];
        fusionar_identidad(&mut hosts, &identidades);
        assert_eq!(hosts[0].dhcp_fingerprint.as_deref(), Some("1,3,6,15"));
        assert_eq!(hosts[0].dhcp_vendor.as_deref(), Some("MSFT 5.0"));
        assert_eq!(hosts[0].dhcp_name.as_deref(), Some("portatil"));
        assert_eq!(
            hosts[0].user_agent.as_deref(),
            Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0")
        );

        // Una identidad DHCP de otra MAC no se atribuye por IP.
        let identidades = vec![(
            None,
            Some(ip),
            DeviceIdentitySignals {
                dhcp: Some(observacion_dhcp(
                    "3c:22:fb:ff:ff:ff",
                    "192.168.1.70",
                    "udhcp 1.36",
                    "1,3,6",
                    "router",
                )),
                user_agent: None,
            },
        )];
        fusionar_identidad(&mut hosts, &identidades);
        assert_eq!(
            hosts[0].dhcp_vendor.as_deref(),
            Some("MSFT 5.0"),
            "no se le pasa la huella de otro equipo"
        );
    }

    #[tokio::test]
    async fn el_ciclo_fusiona_los_equipos_observados_por_la_captura() {
        let mut filtro = crate::identify::observed::ObservedFilter::default();
        filtro.networks.push((
            "10.99.99.0".parse::<Ipv4Addr>().unwrap(),
            "255.255.255.0".parse::<Ipv4Addr>().unwrap(),
        ));
        let observado = Arc::new(Mutex::new(ObservedHosts::new(filtro)));
        let identidad = Arc::new(Mutex::new(CaptureIdentityStore::new()));
        {
            let mut buffer = observado.lock().expect("lock de observados");
            assert!(buffer.push(ObservedHost {
                mac: "da:a1:19:00:00:03".to_string(),
                ip: "10.99.99.50".parse().unwrap(),
                source: crate::inference::ObservedSource::Arp,
                dhcp: None,
            }));
        }
        {
            let mut almacen = identidad.lock().expect("lock de identidad");
            almacen.record_dhcp(observacion_dhcp(
                "da:a1:19:00:00:03",
                "10.99.99.50",
                "MSFT 5.0",
                "1,3,6,15",
                "portatil",
            ));
        }

        let options = ScanOptions {
            privileged: false,
            passive_only: true,
            interfaces: vec!["almenara-interfaz-inexistente".to_string()],
            ranges: Vec::new(),
            timeout: Duration::ZERO,
            concurrency: 4,
            top_ports: vec![22],
            dhcp_lease_paths: Vec::new(),
            netbios_enabled: false,
        };
        let mut state = ScanState::new(&[]);
        let mut discovery_state = DiscoveryState::disabled();
        let informe = run_scan(
            &options,
            &mut state,
            &mut discovery_state,
            false,
            &observado,
            &identidad,
        )
        .await;

        let host = informe
            .hosts
            .iter()
            .find(|host| host.mac == "da:a1:19:00:00:03")
            .expect("equipo creado desde la captura");
        assert!(host.discovery_sources.contains(&DiscoverySource::Capture));
        assert_eq!(host.dhcp_fingerprint.as_deref(), Some("1,3,6,15"));
        assert_eq!(host.dhcp_vendor.as_deref(), Some("MSFT 5.0"));
        assert_eq!(host.hostname.as_deref(), Some("portatil"));
        assert!(host.mac_random);
        assert!(observado.lock().expect("lock").is_empty());
        assert!(identidad.lock().expect("lock").is_empty());
    }

    #[test]
    fn las_senales_dhcp_modelo_y_user_agent_puntuan_el_so_y_su_fuente() {
        // Criterio de aceptación: model=MacBookPro… → macOS y os_source = model.
        let ip: Ipv4Addr = "192.168.1.30".parse().unwrap();
        let mut host = Host::new("3c:22:fb:11:22:33", ip);
        let pasivo = PassiveData {
            mdns: vec![registro_mdns(
                "192.168.1.30",
                Some("mac-de-casa.local"),
                vec![servicio_mdns(
                    "_device-info._tcp",
                    None,
                    &[("model", "MacBookPro18,3")],
                )],
            )],
            ..PassiveData::default()
        };
        aplicar_fuentes_pasivas(
            std::slice::from_mut(&mut host),
            &pasivo,
            &[],
            &HashMap::new(),
            false,
        );
        host.combinar_os();
        assert_eq!(host.model.as_deref(), Some("MacBookPro18,3"));
        assert_eq!(host.os_family, Some(OsFamily::MacOs));
        assert_eq!(host.os_source, Some(OsSource::Model));

        // Huella DHCP de Windows + User-Agent de Windows: la huella DHCP aporta
        // más puntos y queda como fuente.
        let mut host = Host::new("3c:22:fb:11:22:44", ip);
        host.dhcp_vendor = Some("MSFT 5.0".to_string());
        host.dhcp_fingerprint = Some("1,3,6,15,119,252".to_string());
        host.user_agent = Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120".to_string());
        host.combinar_os();
        assert_eq!(host.os_family, Some(OsFamily::Windows));
        assert_eq!(host.os_source, Some(OsSource::Dhcp));

        // La huella TCP de F2 se suma a la pista del User-Agent.
        let mut host = Host::new("3c:22:fb:11:22:55", ip);
        host.os_family = Some(OsFamily::MacOs);
        host.fingerprint_score = 4;
        host.user_agent =
            Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15".to_string());
        host.combinar_os();
        assert_eq!(host.os_family, Some(OsFamily::MacOs));
        assert_eq!(
            host.os_source,
            Some(OsSource::Tcp),
            "la huella TCP aporta más puntos"
        );
    }

    #[test]
    fn el_nombre_fn_de_cast_y_el_dhcp_capturado_entran_en_la_precedencia() {
        // `fn` de Google Cast (nivel mDNS) manda sobre DHCP y reverse DNS.
        let mut host = Host::new("3c:22:fb:11:22:66", "192.168.1.40".parse().unwrap());
        host.reverse_dns_name = Some("chromecast.lan".to_string());
        host.hostname = Some("chromecast.lan".to_string());
        host.dhcp_name = Some("dhcp-chromecast".to_string());
        let pasivo = PassiveData {
            mdns: vec![registro_mdns(
                "192.168.1.40",
                None,
                vec![servicio_mdns(
                    "_googlecast._tcp",
                    None,
                    &[("fn", "Salón TV"), ("md", "Chromecast Ultra")],
                )],
            )],
            ..PassiveData::default()
        };
        aplicar_fuentes_pasivas(
            std::slice::from_mut(&mut host),
            &pasivo,
            &[],
            &HashMap::new(),
            false,
        );
        assert_eq!(host.mdns_name.as_deref(), Some("Salón TV"));
        assert_eq!(host.hostname.as_deref(), Some("Salón TV"));

        // El nombre DHCP capturado (nivel de lease) manda sobre el reverse DNS.
        assert_eq!(
            hostname_precedence(None, None, Some("movil-dhcp"), Some("movil.lan")),
            Some("movil-dhcp".to_string())
        );

        // En pasivo: mDNS/fn > DHCP > último conocido, sin NetBIOS ni reverse DNS.
        assert_eq!(
            hostname_precedence_pasivo(Some("Salón TV"), Some("tv-dhcp")),
            Some("Salón TV".to_string())
        );
        assert_eq!(
            hostname_precedence_pasivo(None, Some("tv-dhcp")),
            Some("tv-dhcp".to_string())
        );
        assert_eq!(hostname_precedence_pasivo(None, None), None);
    }

    #[test]
    fn el_modo_pasivo_desactiva_netbios_y_el_dns_inverso() {
        let config = ScanConfig {
            passive_only: true,
            ..ScanConfig::default()
        };
        let options = ScanOptions::from_config(&config, true).expect("opciones válidas");
        assert!(!options.netbios_enabled, "en pasivo no se consulta NetBIOS");
        assert!(!netbios_habilitado(&options));
        assert!(!dns_inverso_habilitado(&options));

        let normal =
            ScanOptions::from_config(&ScanConfig::default(), true).expect("opciones válidas");
        assert!(normal.netbios_enabled);
        assert!(netbios_habilitado(&normal));
        assert!(dns_inverso_habilitado(&normal));

        // La condición de run_scan vuelve a exigir el modo pasivo.
        let forzado = ScanOptions {
            passive_only: true,
            netbios_enabled: true,
            ..normal
        };
        assert!(!netbios_habilitado(&forzado));
    }

    #[test]
    fn solo_se_resuelven_ips_de_subredes_locales() {
        let redes = vec!["192.168.1.0/24".parse::<Ipv4Network>().unwrap()];
        assert!(es_ip_de_subred_local(
            "192.168.1.50".parse().unwrap(),
            &redes
        ));
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.9",
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.251",
            "255.255.255.255",
        ] {
            assert!(
                !es_ip_de_subred_local(ip.parse().unwrap(), &redes),
                "{ip} no es una IP de la LAN"
            );
        }
        assert!(
            !es_ip_de_subred_local("192.168.1.50".parse().unwrap(), &[]),
            "sin subredes no se resuelve nada"
        );
    }

    #[test]
    fn las_reglas_de_modelo_y_user_agent_van_antes_que_las_de_hostname() {
        // El hostname sugiere iPhone, pero el modelo anuncia un MacBook: pc.
        let mut host = Host::new("3c:22:fb:11:22:77", "192.168.1.45".parse().unwrap());
        host.hostname = Some("iPhone-de-Marta".to_string());
        host.model_device_type = Some(DeviceType::Pc);
        let contexto = DeviceCtx {
            hostname: host.hostname.clone(),
            ..DeviceCtx::default()
        };
        assert_eq!(clasificar_tipo(&host, contexto), DeviceType::Pc);

        // UA de TV: tv aunque el hostname no lo diga.
        let mut host = Host::new("3c:22:fb:11:22:78", "192.168.1.46".parse().unwrap());
        host.hostname = Some("tele-del-salon".to_string());
        host.user_agent =
            Some("Mozilla/5.0 (SMART-TV; Linux; Tizen 6.0) AppleWebKit/537.36".to_string());
        let contexto = DeviceCtx {
            hostname: host.hostname.clone(),
            is_tv: parece_televisor(&host),
            ..DeviceCtx::default()
        };
        assert_eq!(clasificar_tipo(&host, contexto), DeviceType::Tv);

        // Sin pistas de F4, la clasificación por hostname de F2 sigue igual.
        let mut host = Host::new("3c:22:fb:11:22:79", "192.168.1.47".parse().unwrap());
        host.hostname = Some("iPhone-de-Marta".to_string());
        let contexto = DeviceCtx {
            hostname: host.hostname.clone(),
            ..DeviceCtx::default()
        };
        assert_eq!(clasificar_tipo(&host, contexto), DeviceType::Mobile);
    }

    #[test]
    fn el_modelo_anunciado_por_mdns_tambien_fija_el_tipo() {
        let pasivo = PassiveData {
            mdns: vec![
                registro_mdns(
                    "192.168.1.81",
                    None,
                    vec![servicio_mdns(
                        "_googlecast._tcp",
                        None,
                        &[("md", "Chromecast Ultra")],
                    )],
                ),
                registro_mdns(
                    "192.168.1.82",
                    None,
                    vec![servicio_mdns(
                        "_ipp._tcp",
                        Some(631),
                        &[("ty", "HP LaserJet 400")],
                    )],
                ),
                registro_mdns(
                    "192.168.1.83",
                    None,
                    vec![servicio_mdns(
                        "_airplay._tcp",
                        None,
                        &[("model", "AppleTV6,2")],
                    )],
                ),
            ],
            ..PassiveData::default()
        };
        let mut hosts = vec![
            Host::new("3c:22:fb:11:22:81", "192.168.1.81".parse().unwrap()),
            Host::new("3c:22:fb:11:22:82", "192.168.1.82".parse().unwrap()),
            Host::new("3c:22:fb:11:22:83", "192.168.1.83".parse().unwrap()),
        ];
        aplicar_fuentes_pasivas(&mut hosts, &pasivo, &[], &HashMap::new(), false);

        let chromecast = &hosts[0];
        assert_eq!(chromecast.model.as_deref(), Some("Chromecast Ultra"));
        let contexto = DeviceCtx {
            mdns_services: chromecast.mdns_services.clone(),
            ..DeviceCtx::default()
        };
        assert_eq!(clasificar_tipo(chromecast, contexto), DeviceType::Streaming);

        let impresora = &hosts[1];
        assert_eq!(impresora.model.as_deref(), Some("HP LaserJet 400"));
        let contexto = DeviceCtx {
            mdns_services: impresora.mdns_services.clone(),
            services: impresora
                .services
                .iter()
                .filter_map(|servicio| servicio.service)
                .collect(),
            ..DeviceCtx::default()
        };
        assert_eq!(clasificar_tipo(impresora, contexto), DeviceType::Printer);

        let appletv = &hosts[2];
        let contexto = DeviceCtx {
            mdns_services: appletv.mdns_services.clone(),
            ..DeviceCtx::default()
        };
        assert_eq!(clasificar_tipo(appletv, contexto), DeviceType::Streaming);
    }

    #[test]
    fn un_equipo_observado_por_la_captura_crea_equipo_con_fuente_capture() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        // Solo lo ha visto la captura: sin fuentes de F1.
        let mut host = Host::new("3c:22:fb:11:22:93", "192.168.1.98".parse().unwrap());
        host.interface = Some("eth0".to_string());
        host.discovery_sources.push(DiscoverySource::Capture);
        let informe = informe_de_prueba(vec![host]);
        let reconciliacion =
            reconcile(&mut repo, &informe, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(reconciliacion.new_devices, 1);
        let dispositivo = &reconciliacion.devices[0];
        assert!(reconciliacion
            .events
            .iter()
            .any(|evento| evento.event_type == EventType::New));
        let fuentes = repo.list_sources(dispositivo.id).unwrap();
        let nombres: Vec<&str> = fuentes.iter().map(|fila| fila.source.as_str()).collect();
        assert!(
            nombres.contains(&"capture"),
            "la fuente capture debe persistirse: {nombres:?}"
        );
    }

    #[test]
    fn las_observaciones_de_la_captura_cuentan_como_visto_para_el_offline() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(1);

        let primera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host_de_prueba(
                "3c:22:fb:11:22:94",
                "192.168.1.99",
                None,
            )]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(primera.new_devices, 1);

        // El único dato del ciclo es una observación de la captura: cuenta como
        // visto y no se marca offline (el umbral es de un solo ciclo).
        let mut capturado = Host::new("3c:22:fb:11:22:94", "192.168.1.99".parse().unwrap());
        capturado.interface = Some("eth0".to_string());
        capturado.discovery_sources.push(DiscoverySource::Capture);
        let segunda = reconcile(
            &mut repo,
            &informe_de_prueba(vec![capturado]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(segunda.marked_offline, 0);
        assert!(segunda.devices.iter().all(|device| device.is_online));

        // Sin observaciones, el siguiente ciclo sí lo marca offline.
        let tercera = reconcile(
            &mut repo,
            &informe_de_prueba(Vec::new()),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(tercera.marked_offline, 1);
    }

    #[test]
    fn la_identidad_de_f4_se_persiste_en_devices() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        let mut host = host_de_prueba("3c:22:fb:11:22:95", "192.168.1.100", None);
        host.model = Some("MacBookPro18,3".to_string());
        host.dhcp_fingerprint = Some("1,121,3,6".to_string());
        host.dhcp_vendor = Some("Apple".to_string());
        host.dhcp_hostname = Some("mac-de-casa".to_string());
        host.user_agent = Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)".to_string());
        host.os_family = Some(OsFamily::MacOs);
        host.os_source = Some(OsSource::Model);
        let reconciliacion = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        let device_id = reconciliacion.devices[0].id;
        let dispositivo = repo
            .get_device_by_mac("3c:22:fb:11:22:95")
            .unwrap()
            .expect("equipo persistido");
        assert_eq!(dispositivo.model.as_deref(), Some("MacBookPro18,3"));
        assert_eq!(dispositivo.dhcp_fingerprint.as_deref(), Some("1,121,3,6"));
        assert_eq!(dispositivo.dhcp_vendor.as_deref(), Some("Apple"));
        assert_eq!(dispositivo.dhcp_hostname.as_deref(), Some("mac-de-casa"));
        assert_eq!(
            dispositivo.user_agent.as_deref(),
            Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
        );
        assert_eq!(dispositivo.os_family.as_deref(), Some("macos"));
        assert_eq!(dispositivo.os_source.as_deref(), Some("model"));
        assert_eq!(device_id, dispositivo.id);
    }

    #[test]
    fn la_rotacion_de_mac_privada_conserva_el_equipo_y_marca_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        let primero = informe_de_prueba(vec![host_privado_con_dhcp(
            "da:a1:19:00:00:01",
            "192.168.1.90",
        )]);
        let primera = reconcile(&mut repo, &primero, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(primera.new_devices, 1);
        let device_id = primera.devices[0].id;

        // Otra MAC privada con la misma huella y nombre DHCP, con la anterior
        // sin verse en el ciclo: se conserva el equipo.
        let segundo = informe_de_prueba(vec![host_privado_con_dhcp(
            "da:a1:19:00:00:02",
            "192.168.1.90",
        )]);
        let segunda = reconcile(&mut repo, &segundo, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(segunda.devices.len(), 1, "se conserva el equipo");
        assert_eq!(segunda.devices[0].id, device_id);
        assert_eq!(segunda.devices[0].mac, "da:a1:19:00:00:02");
        assert!(segunda
            .events
            .iter()
            .any(|evento| evento.event_type == EventType::MacChanged));
        let guardados = repo.list_events(device_id).unwrap();
        let mac_changed = guardados
            .iter()
            .find(|evento| evento.event_type == EventType::MacChanged)
            .expect("mac_changed persistido");
        assert!(
            mac_changed.details.contains("\"reason\":\"rotation\""),
            "{}",
            mac_changed.details
        );
    }

    #[test]
    fn con_varios_candidatos_de_rotacion_no_se_fusiona_y_sale_new_con_mac_random() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        let inicial = informe_de_prueba(vec![
            host_privado_con_dhcp("da:a1:19:00:00:11", "192.168.1.91"),
            host_privado_con_dhcp("da:a1:19:00:00:12", "192.168.1.92"),
        ]);
        let primera = reconcile(&mut repo, &inicial, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(primera.devices.len(), 2);

        let otra = informe_de_prueba(vec![host_privado_con_dhcp(
            "da:a1:19:00:00:13",
            "192.168.1.93",
        )]);
        let segunda = reconcile(&mut repo, &otra, &mut tracker, 90, STALE_FUTURO).unwrap();
        assert_eq!(
            segunda.devices.len(),
            3,
            "con varios candidatos no se fusiona identidad"
        );
        assert!(!segunda
            .events
            .iter()
            .any(|evento| evento.event_type == EventType::MacChanged));
        let nuevo = segunda
            .devices
            .iter()
            .find(|device| device.mac == "da:a1:19:00:00:13")
            .expect("equipo nuevo");
        let eventos = repo.list_events(nuevo.id).unwrap();
        let new = eventos
            .iter()
            .find(|evento| evento.event_type == EventType::New)
            .expect("evento new persistido");
        assert!(
            new.details.contains("\"mac_random\":true"),
            "{}",
            new.details
        );
    }

    #[test]
    fn la_toma_de_ip_no_se_aplica_si_las_huellas_dhcp_se_contradicen() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        let mut antiguo = host_de_prueba("3c:22:fb:11:22:90", "192.168.1.95", None);
        antiguo.dhcp_fingerprint = Some("1,3,6,15,119,252".to_string());
        let primera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![antiguo]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(primera.devices.len(), 1);

        let mut nuevo = host_de_prueba("3c:22:fb:44:55:66", "192.168.1.95", None);
        nuevo.dhcp_fingerprint = Some("1,121,3,6".to_string());
        let segunda = reconcile(
            &mut repo,
            &informe_de_prueba(vec![nuevo]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(
            segunda.devices.len(),
            2,
            "con huellas DHCP contradictorias no se fusiona"
        );
        assert!(!segunda
            .events
            .iter()
            .any(|evento| evento.event_type == EventType::MacChanged));
        assert!(segunda
            .events
            .iter()
            .any(|evento| evento.event_type == EventType::New));
    }

    #[test]
    fn la_toma_de_ip_compatible_marca_ip_takeover() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let mut tracker = OnlineTracker::new(3);

        let primera = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host_de_prueba(
                "3c:22:fb:11:22:91",
                "192.168.1.96",
                None,
            )]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(primera.devices.len(), 1);
        let device_id = primera.devices[0].id;

        let segunda = reconcile(
            &mut repo,
            &informe_de_prueba(vec![host_de_prueba(
                "3c:22:fb:44:55:67",
                "192.168.1.96",
                None,
            )]),
            &mut tracker,
            90,
            STALE_FUTURO,
        )
        .unwrap();
        assert_eq!(segunda.devices.len(), 1, "se conserva el equipo");
        assert_eq!(segunda.devices[0].mac, "3c:22:fb:44:55:67");
        let guardados = repo.list_events(device_id).unwrap();
        let mac_changed = guardados
            .iter()
            .find(|evento| evento.event_type == EventType::MacChanged)
            .expect("mac_changed persistido");
        assert!(
            mac_changed.details.contains("\"reason\":\"ip_takeover\""),
            "{}",
            mac_changed.details
        );
    }
}
