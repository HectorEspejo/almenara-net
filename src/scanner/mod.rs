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
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use pnet::ipnetwork::Ipv4Network;

use crate::config::{ScanConfig, DEFAULT_SWEEP_CONCURRENCY};
use crate::error::Result;
use crate::notifier::{Level, Notification};
use crate::oui;
use crate::repo::devices::DeviceUpsert;
use crate::repo::events::EventType;
use crate::repo::{Device, Interface, Repo};

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

/// Equipo descubierto en la red, fruto del merge de fuentes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// MAC normalizada.
    pub mac: String,
    /// IPv4 vista (se prefiere la confirmada por ARP).
    pub ip: Ipv4Addr,
    /// Hostname por reverse DNS, si se resolvió.
    pub hostname: Option<String>,
    /// Fabricante por OUI, si se conoce.
    pub vendor: Option<String>,
    /// Interfaz por la que se ha visto, si se pudo asignar.
    pub interface: Option<String>,
    /// Fuentes que han confirmado al equipo.
    pub sources: Vec<HostSource>,
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
    /// Duración del ciclo.
    pub duration: Duration,
}

/// Opciones de un ciclo de escaneo.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Hay CAP_NET_RAW disponible.
    pub privileged: bool,
    /// Nombres de interfaz permitidos (vacío = todas las candidatas).
    pub interfaces: Vec<String>,
    /// Rangos configurados (vacío = derivar de cada interfaz).
    pub ranges: Vec<Ipv4Network>,
    /// Timeout de ICMP y reverse DNS.
    pub timeout: Duration,
    /// Concurrencia del ping sweep.
    pub concurrency: usize,
}

impl ScanOptions {
    /// Construye las opciones a partir de la sección [scan] de la configuración.
    pub fn from_config(scan: &ScanConfig, privileged: bool) -> Result<Self> {
        let interfaces = match &scan.interfaces {
            crate::config::InterfacesSetting::Auto => Vec::new(),
            crate::config::InterfacesSetting::Names(names) => names.clone(),
        };
        Ok(Self {
            privileged,
            interfaces,
            ranges: scan.parse_ranges()?,
            timeout: Duration::from_millis(scan.icmp_timeout_ms),
            concurrency: DEFAULT_SWEEP_CONCURRENCY,
        })
    }
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

/// Ejecuta un ciclo de descubrimiento completo.
pub async fn run_scan(options: ScanOptions) -> ScanReport {
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

    if options.privileged {
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
            match tokio::task::spawn_blocking(move || arp::scan(&iface_arp, &targets_arp, timeout))
                .await
            {
                Ok(Ok(mut hosts)) => arp_hosts.append(&mut hosts),
                Ok(Err(err)) => {
                    errors.push(format!("El barrido ARP por {} falló: {err}", iface.name))
                }
                Err(err) => errors.push(format!(
                    "El barrido ARP por {} se canceló: {err}",
                    iface.name
                )),
            }

            let targets_icmp = targets.clone();
            let concurrency = options.concurrency.max(1);
            match tokio::task::spawn_blocking(move || {
                icmp::sweep(&targets_icmp, timeout, concurrency)
            })
            .await
            {
                Ok(Ok(mut ips)) => icmp_responders.append(&mut ips),
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
    } else {
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

    // Reverse DNS con timeout corto y concurrencia limitada.
    let ips: Vec<Ipv4Addr> = hosts.iter().map(|host| host.ip).collect();
    let resueltos = dns::resolve_many(&ips, options.timeout, options.concurrency.max(1)).await;
    let por_ip: HashMap<Ipv4Addr, String> = resueltos.into_iter().collect();
    for host in &mut hosts {
        if let Some(nombre) = por_ip.get(&host.ip) {
            host.hostname = Some(nombre.clone());
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

    ScanReport {
        hosts,
        interfaces: selected,
        icmp_responders,
        errors,
        privileged: options.privileged,
        duration: started.elapsed(),
    }
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
            .or_insert_with(|| Host {
                mac,
                ip: host.ip,
                hostname: None,
                vendor: None,
                interface: None,
                sources: vec![HostSource::Arp],
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
            .or_insert_with(|| Host {
                mac,
                ip: entry.ip,
                hostname: None,
                vendor: None,
                interface: Some(entry.iface.clone()),
                sources: vec![HostSource::ProcArp],
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
/// Persiste interfaces, altas/cambios de dispositivos, marca offline los equipos
/// que llevan `offline_after_cycles` ciclos sin aparecer, emite eventos y poda el
/// histórico según la retención configurada.
pub fn reconcile(
    repo: &mut Repo,
    report: &ScanReport,
    tracker: &mut OnlineTracker,
    retention_days: u32,
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

        let gateway_de_interfaz = report
            .interfaces
            .iter()
            .find(|iface| iface.name.as_str() == host.interface.as_deref().unwrap_or_default())
            .and_then(|iface| iface.gateway);
        let device_type = if gateway_de_interfaz == Some(host.ip) {
            "gateway"
        } else {
            "unknown"
        };

        let upsert = DeviceUpsert {
            mac: host.mac.clone(),
            ip: host.ip.to_string(),
            hostname: host.hostname.clone(),
            vendor: host.vendor.clone(),
            interface_id,
            device_type: device_type.to_string(),
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
            }
            Err(err) => errors.push(format!(
                "No se pudo guardar el equipo {} ({}): {err}",
                host.ip, host.mac
            )),
        }
    }

    // 4) Marcado offline tras N ciclos sin respuesta.
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

    // 5) Retención del histórico.
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
        errors,
    })
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
        assert_eq!(objetivos.len(), 254);
        assert!(objetivos.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!objetivos.contains(&"192.168.1.0".parse().unwrap()));
        assert!(!objetivos.contains(&"192.168.1.255".parse().unwrap()));
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

    fn host_de_prueba(mac: &str, ip: &str, hostname: Option<&str>) -> Host {
        Host {
            mac: mac.to_string(),
            ip: ip.parse().unwrap(),
            hostname: hostname.map(str::to_string),
            vendor: Some("Apple".to_string()),
            interface: Some("eth0".to_string()),
            sources: vec![HostSource::Arp],
        }
    }

    fn informe_de_prueba(hosts: Vec<Host>) -> ScanReport {
        ScanReport {
            hosts,
            interfaces: vec![interfaz_de_prueba()],
            icmp_responders: Vec::new(),
            errors: Vec::new(),
            privileged: true,
            duration: Duration::from_millis(1),
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
        let primera = reconcile(&mut repo, &primero, &mut tracker, 90).unwrap();
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
        let segunda = reconcile(&mut repo, &primero, &mut tracker, 90).unwrap();
        assert_eq!(segunda.new_devices, 0);
        assert!(segunda.events.is_empty());

        // Cambios de IP y hostname para la misma MAC.
        let cambiado = informe_de_prueba(vec![host_de_prueba(
            "aa:bb:cc:dd:ee:01",
            "192.168.1.11",
            Some("laptop-nueva"),
        )]);
        let tercera = reconcile(&mut repo, &cambiado, &mut tracker, 90).unwrap();
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
        let cuarta = reconcile(&mut repo, &identidad, &mut tracker, 90).unwrap();
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
        let quinta = reconcile(&mut repo, &vacio, &mut tracker, 90).unwrap();
        assert_eq!(quinta.marked_offline, 0);
        let sexta = reconcile(&mut repo, &vacio, &mut tracker, 90).unwrap();
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
        let septima = reconcile(&mut repo, &reaparece, &mut tracker, 90).unwrap();
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
        let reconciliacion = reconcile(&mut repo, &informe, &mut tracker, 90).unwrap();
        let device_id = reconciliacion.devices[0].id;
        repo.connection()
            .execute(
                "UPDATE DEVICE_EVENTS SET created_at = '2000-01-01T00:00:00Z'",
                [],
            )
            .unwrap();
        let limpieza = reconcile(&mut repo, &informe, &mut tracker, 90).unwrap();
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
            errors: Vec::new(),
        };
        let notificaciones = reconciliacion.notifications();
        assert!(notificaciones
            .iter()
            .any(|notificacion| notificacion.message.contains("6 equipos nuevos")));
        let _ = hosts;
    }
}
