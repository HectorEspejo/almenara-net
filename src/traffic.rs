//! Monitor de tráfico en vivo (Fase 3).
//!
//! Tarea asíncrona que integra la captura AF_PACKET, la agregación por
//! dispositivo, las conexiones del kernel (/proc/net/* y conntrack) y las
//! conexiones observadas por captura. Publica una actualización cada segundo por
//! el bus de eventos; el hilo de la TUI es el único que escribe en SQLite
//! (snapshot cada 5 s y persistencia de conexiones), respetando la regla de una
//! única conexión de escritura en el hilo de la TUI.
//!
//! Este módulo no persiste nada: solo calcula el estado en memoria y lo emite.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc};

use crate::capture::aggregate::{Aggregator, DeviceTraffic, GlobalTraffic};
use crate::capture::conntrack::{Conntrack, ConntrackEntry, ProcNet, ProcNetEntry};
use crate::capture::process::{Process, ProcessInfo};
use crate::capture::windows::Windows;
use crate::capture::{
    es_direccion_broadcast, Capture, CaptureInterface, CaptureStats, ConnectionKey, Endpoint,
    HeaderSnapshot, PacketMeta, Protocol,
};
use crate::config::Config;
use crate::events::{AppEvent, TrafficCommand};
use crate::notifier::Level;

/// Id centinela del tráfico propio del host en la vista de tráfico.
///
/// No es un dispositivo de SQLite: se usa para mostrar en el ranking de la
/// pestaña Tráfico el tráfico del propio host (que en red conmutada es la mayor
/// parte de lo visible y no se atribuye a ningún equipo del inventario).
pub const DEVICE_ID_HOST: i64 = -1;

/// Cada cuánto se drena la captura (paquetes capturados → agregación).
pub const CAPTURE_DRAIN: Duration = Duration::from_millis(100);
/// Cada cuánto se publica una actualización de tráfico.
pub const UPDATE_INTERVAL: Duration = Duration::from_secs(1);
/// Cada cuánto se leen las conexiones del kernel y se purga la caché.
pub const KERNEL_INTERVAL: Duration = Duration::from_secs(5);
/// Ventana mínima entre avisos de max_pps y de captura.
pub const NOTICE_INTERVAL: Duration = Duration::from_secs(60);
/// Número máximo de conexiones mantenidas en memoria.
pub const MAX_CONEXIONES: usize = 2048;
/// Timeout de purga de una conexión TCP sin estado especial.
pub const TIMEOUT_TCP: Duration = Duration::from_secs(300);
/// Timeout de purga de TIME_WAIT / CLOSE_WAIT.
pub const TIMEOUT_TCP_CERRADA: Duration = Duration::from_secs(60);
/// Timeout de purga de una conexión UDP.
pub const TIMEOUT_UDP: Duration = Duration::from_secs(60);
/// Timeout de purga de una conexión ICMP.
pub const TIMEOUT_ICMP: Duration = Duration::from_secs(30);

/// Referencia mínima a un dispositivo para atribuir tráfico por IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRef {
    /// Id del dispositivo en SQLite.
    pub id: i64,
    /// Última IP conocida del dispositivo.
    pub ip: String,
}

impl DeviceRef {
    /// Construye la referencia a partir de la IP en texto.
    pub fn new(id: i64, ip: impl Into<String>) -> Self {
        Self { id, ip: ip.into() }
    }

    /// IP parseada, si el texto es válido.
    pub fn parsed_ip(&self) -> Option<IpAddr> {
        self.ip.parse().ok()
    }
}

/// Estado de la captura visible en la barra de estado y en la pestaña Tráfico.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureStatus {
    /// La captura está funcionando.
    pub active: bool,
    /// Interfaces sobre las que se captura.
    pub interfaces: Vec<String>,
    /// Filtro BPF configurado (vacío = sin filtro).
    pub filter: String,
    /// Paquetes por segundo de la última ventana.
    pub pps: u64,
    /// Paquetes capturados desde el arranque.
    pub total: u64,
    /// Paquetes descartados.
    pub drops: u64,
    /// Paquetes con cabecera inválida.
    pub parse_errors: u64,
    /// Límite configurado (0 = sin límite).
    pub max_pps: u64,
    /// CAP_NET_RAW disponible.
    pub available: bool,
    /// Motivo por el que la captura está desactivada, si aplica.
    pub disabled_reason: Option<String>,
}

impl CaptureStatus {
    /// Texto de una línea con el estado de la captura.
    pub fn summary(&self) -> String {
        if !self.active {
            let motivo = self
                .disabled_reason
                .clone()
                .unwrap_or_else(|| "captura desactivada".to_string());
            return format!("captura deshabilitada: {motivo}");
        }
        let mut texto = format!(
            "capturando · {} pps · filtro: {}",
            formatear_pps(self.pps),
            if self.filter.trim().is_empty() {
                "(ninguno)"
            } else {
                self.filter.trim()
            }
        );
        if self.max_pps > 0 {
            texto.push_str(&format!(" · límite {} pps", formatear_pps(self.max_pps)));
        }
        if !self.interfaces.is_empty() {
            texto.push_str(&format!(" · {}", self.interfaces.join(", ")));
        }
        texto
    }

    /// Prefijo textual para NO_COLOR: [CAP] capturando, [CAP:off] desactivada.
    pub fn no_color_prefix(&self) -> &'static str {
        if self.active {
            "[CAP]"
        } else {
            "[CAP:off]"
        }
    }

    /// Texto de visibilidad honesta de la red conmutada.
    pub fn visibility_label() -> &'static str {
        "visibilidad: propia + broadcast"
    }
}

/// Extremo de una conexión tal y como se pinta en la TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointView {
    /// IP del extremo.
    pub ip: IpAddr,
    /// Puerto del extremo.
    pub port: Option<u16>,
    /// Dispositivo atribuido, si está inventariado.
    pub device_id: Option<i64>,
    /// Etiqueta cuando no hay dispositivo: host, broadcast o ?.
    pub tag: Option<&'static str>,
}

impl EndpointView {
    /// Texto "ip:puerto" (IPv6 entre corchetes).
    pub fn display(&self) -> String {
        Endpoint::new(self.ip, self.port).to_string()
    }
}

/// Conexión activa tal y como la consume la TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionView {
    /// Clave canónica de 5-tuple.
    pub key: ConnectionKey,
    /// Estado del kernel o heurístico (None = desconocido).
    pub state: Option<String>,
    /// Bytes recibidos por el extremo origen.
    pub bytes_in: u64,
    /// Bytes enviados por el extremo origen.
    pub bytes_out: u64,
    /// Antigüedad de la conexión.
    pub age: Duration,
    /// Tiempo sin tráfico.
    pub idle: Duration,
    /// PID del socket local, si se pudo atribuir.
    pub pid: Option<u32>,
    /// Nombre del proceso local, si se pudo atribuir.
    pub comm: Option<String>,
    /// Dispositivo atribuido a la conexión, si aplica.
    pub device_id: Option<i64>,
    /// Extremo origen (canónico).
    pub origin: EndpointView,
    /// Extremo destino (canónico).
    pub destination: EndpointView,
    /// Copia de cabeceras del primer paquete visto (tecla v).
    pub headers: Option<HeaderSnapshot>,
    /// La conexión se ha visto por captura de paquetes.
    pub seen_capture: bool,
    /// La conexión se ha visto en /proc/net/* o conntrack.
    pub seen_kernel: bool,
}

impl ConnectionView {
    /// Protocolo de transporte.
    pub fn protocol(&self) -> Protocol {
        self.key.protocol
    }

    /// Etiqueta de edad compacta ("2m", "45s", "3h").
    pub fn age_label(&self) -> String {
        formatear_duracion(self.age)
    }

    /// Etiqueta de inactividad compacta.
    pub fn idle_label(&self) -> String {
        formatear_duracion(self.idle)
    }

    /// Estado visible ("—" si se desconoce).
    pub fn state_label(&self) -> &str {
        self.state.as_deref().unwrap_or("—")
    }

    /// Proceso local visible ("pid comm" o vacío).
    pub fn process_label(&self) -> Option<String> {
        match (self.pid, &self.comm) {
            (Some(pid), Some(comm)) => Some(format!("{pid} {comm}")),
            (Some(pid), None) => Some(pid.to_string()),
            _ => None,
        }
    }
}

/// Actualización periódica de tráfico publicada en el bus de eventos.
#[derive(Debug, Clone)]
pub struct TrafficUpdate {
    /// Estado de la captura.
    pub capture: CaptureStatus,
    /// Tráfico agregado por dispositivo en el último segundo.
    pub devices: Vec<DeviceTraffic>,
    /// Tráfico propio del host (device_id = DEVICE_ID_HOST).
    pub host: DeviceTraffic,
    /// Agregado global (incluye el tráfico propio y el de los dispositivos).
    pub global: GlobalTraffic,
    /// Conexiones activas (vista ya resuelta).
    pub connections: Vec<ConnectionView>,
    /// Número total de conexiones en la caché.
    pub connections_total: usize,
}

/// Handle de la tarea de tráfico.
#[derive(Debug)]
pub struct TrafficHandle {
    /// Canal de órdenes hacia la tarea.
    pub command_tx: mpsc::Sender<TrafficCommand>,
    /// Handle de la tarea tokio (se aborta al cerrar si sigue viva).
    pub join: tokio::task::JoinHandle<()>,
}

/// Arranca la tarea de monitorización de tráfico.
///
/// Devuelve el handle de control, el estado inicial de la captura y una lista de
/// notificaciones para mostrar una única vez al arrancar (aviso de captura,
/// CAP_NET_RAW ausente, filtro BPF inválido...).
pub fn spawn(
    config: &Config,
    interfaces: Vec<CaptureInterface>,
    host_ips: HashSet<IpAddr>,
    devices: Vec<DeviceRef>,
    capabilities_raw: bool,
    event_tx: broadcast::Sender<AppEvent>,
) -> (TrafficHandle, CaptureStatus, Vec<(Level, String)>) {
    let mut notificaciones: Vec<(Level, String)> = Vec::new();
    let mut estado = CaptureStatus {
        max_pps: config.capture.max_pps,
        filter: config.capture.filter.clone(),
        interfaces: interfaces
            .iter()
            .map(|interfaz| interfaz.name.clone())
            .collect(),
        available: capabilities_raw,
        ..CaptureStatus::default()
    };

    let mut captura = None;
    if !config.capture.enabled {
        estado.disabled_reason = Some("captura desactivada en [capture].enabled".to_string());
        tracing::info!("captura desactivada por configuración");
    } else if !capabilities_raw {
        estado.disabled_reason = Some("requiere CAP_NET_RAW".to_string());
        tracing::warn!("captura de tráfico deshabilitada: sin CAP_NET_RAW");
        notificaciones.push((
            Level::Warn,
            "Captura deshabilitada: requiere CAP_NET_RAW. Consulta la pestaña Ayuda (setcap cap_net_raw+ep)"
                .to_string(),
        ));
    } else if interfaces.is_empty() {
        estado.disabled_reason = Some("no hay interfaces activas".to_string());
        tracing::warn!("captura de tráfico deshabilitada: no hay interfaces activas");
        notificaciones.push((
            Level::Warn,
            "Captura deshabilitada: no se ha detectado ninguna interfaz activa".to_string(),
        ));
    } else {
        match Capture::start(&config.capture, interfaces.clone()) {
            Ok(activa) => {
                estado.active = true;
                estado.interfaces = activa
                    .interfaces()
                    .iter()
                    .map(|interfaz| interfaz.name.clone())
                    .collect();
                estado.filter = activa.filter().to_string();
                let nombres = interfaces
                    .iter()
                    .map(|interfaz| interfaz.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                notificaciones.push((Level::Info, format!("capturando en {nombres}")));
                if let Some(error) = activa.bpf_error() {
                    notificaciones.push((Level::Warn, error.to_string()));
                }
                tracing::info!(interfaces = %nombres, filtro = %config.capture.filter, "captura de tráfico iniciada");
                captura = Some(activa);
            }
            Err(error) => {
                estado.disabled_reason = Some(error.to_string());
                notificaciones.push((
                    Level::Warn,
                    format!("No se pudo iniciar la captura de tráfico: {error}"),
                ));
                tracing::warn!(%error, "no se pudo iniciar la captura de tráfico");
            }
        }
    }

    let (command_tx, command_rx) = crate::events::traffic_command_channel();
    let mapa = mapa_de_dispositivos(&devices);
    let config_clonada = config.clone();
    let estado_inicial = estado.clone();
    let join = tokio::spawn(async move {
        ejecutar(
            captura,
            config_clonada,
            estado_inicial,
            mapa,
            host_ips,
            event_tx,
            command_rx,
        )
        .await;
    });

    (TrafficHandle { command_tx, join }, estado, notificaciones)
}

fn mapa_de_dispositivos(devices: &[DeviceRef]) -> HashMap<IpAddr, i64> {
    let mut mapa = HashMap::new();
    for device in devices {
        if let Some(ip) = device.parsed_ip() {
            mapa.insert(ip, device.id);
        }
    }
    mapa
}

/// Agregado en memoria del tráfico propio del host ([host]).
///
/// En red conmutada la mayor parte de lo observable es tráfico del propio host
/// y de difusión; el primero no pertenece a ningún equipo del inventario, así
/// que se mantiene aparte para que la pestaña Tráfico muestre datos reales en
/// lugar de una tabla de ceros.
#[derive(Debug)]
struct HostTraffic {
    bytes_in_60: Windows,
    bytes_out_60: Windows,
    bytes_in_5min: Windows,
    bytes_out_5min: Windows,
    packets_in_60: Windows,
    packets_out_60: Windows,
}

impl HostTraffic {
    fn new(origin: Instant) -> Self {
        Self {
            bytes_in_60: Windows::new_60s(origin),
            bytes_out_60: Windows::new_60s(origin),
            bytes_in_5min: Windows::new_5min(origin),
            bytes_out_5min: Windows::new_5min(origin),
            packets_in_60: Windows::new_60s(origin),
            packets_out_60: Windows::new_60s(origin),
        }
    }

    /// Contabiliza el paquete si alguno de sus extremos es una IP propia.
    fn update(&mut self, meta: &PacketMeta, host_ips: &HashSet<IpAddr>) {
        let bytes = u64::from(meta.len);
        if host_ips.contains(&meta.src_ip) {
            self.bytes_out_60.push(meta.timestamp, bytes);
            self.bytes_out_5min.push(meta.timestamp, bytes);
            self.packets_out_60.push(meta.timestamp, 1);
        }
        if host_ips.contains(&meta.dst_ip) {
            self.bytes_in_60.push(meta.timestamp, bytes);
            self.bytes_in_5min.push(meta.timestamp, bytes);
            self.packets_in_60.push(meta.timestamp, 1);
        }
    }

    fn tick(&mut self, now: Instant) {
        self.bytes_in_60.advance(now);
        self.bytes_out_60.advance(now);
        self.bytes_in_5min.advance(now);
        self.bytes_out_5min.advance(now);
        self.packets_in_60.advance(now);
        self.packets_out_60.advance(now);
    }

    /// Instantánea con el mismo formato que la agregación por dispositivo.
    fn snapshot(&self) -> DeviceTraffic {
        let serie_60_in = self.bytes_in_60.series_60s();
        let serie_60_out = self.bytes_out_60.series_60s();
        let peak_bps = serie_60_in
            .iter()
            .zip(serie_60_out.iter())
            .map(|(entrada, salida)| entrada.saturating_add(*salida))
            .max()
            .unwrap_or(0);
        DeviceTraffic {
            device_id: DEVICE_ID_HOST,
            bytes_in: self.bytes_in_60.total(),
            bytes_out: self.bytes_out_60.total(),
            packets_in: self.packets_in_60.total(),
            packets_out: self.packets_out_60.total(),
            rate_in: self.bytes_in_60.last(),
            rate_out: self.bytes_out_60.last(),
            peak_bps,
            series_60s_in: serie_60_in,
            series_60s_out: serie_60_out,
            series_5min_in: self.bytes_in_5min.series_5min(),
            series_5min_out: self.bytes_out_5min.series_5min(),
            top_ports: Vec::new(),
        }
    }
}

async fn ejecutar(
    captura: Option<Capture>,
    config: Config,
    estado_inicial: CaptureStatus,
    mapa_inicial: HashMap<IpAddr, i64>,
    host_ips: HashSet<IpAddr>,
    event_tx: broadcast::Sender<AppEvent>,
    mut command_rx: mpsc::Receiver<TrafficCommand>,
) {
    let ahora = Instant::now();
    let mut aggregator = Aggregator::new(ahora);
    aggregator.set_devices(&mapa_inicial);
    let mut cache = ConnCache::new(ahora, mapa_inicial, host_ips.clone());
    let mut host = HostTraffic::new(ahora);

    let mut tick_captura = tokio::time::interval(CAPTURE_DRAIN);
    tick_captura.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tick_segundo = tokio::time::interval(UPDATE_INTERVAL);
    tick_segundo.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tick_kernel = tokio::time::interval(KERNEL_INTERVAL);
    tick_kernel.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut ultimo_aviso_limite: Option<Instant> = None;
    let mut drops_limite_previos = 0u64;
    let mut stats_previas = CaptureStats::default();
    let mut aviso_drops_hecho = false;

    loop {
        tokio::select! {
            _ = tick_captura.tick() => {
                if let Some(activa) = captura.as_ref() {
                    let paquetes = activa.drain();
                    if !paquetes.is_empty() {
                        cache.ingerir_paquetes(&paquetes);
                        for meta in &paquetes {
                            aggregator.update(meta);
                            host.update(meta, &host_ips);
                        }
                    }
                }
                let ahora_tick = Instant::now();
                aggregator.tick(ahora_tick);
                host.tick(ahora_tick);
                cache.purgar(ahora_tick);
            }
            _ = tick_segundo.tick() => {
                let ahora = Instant::now();
                let stats = captura.as_ref().map(Capture::stats).unwrap_or(stats_previas);
                let drops_previos = stats_previas.drops;
                let mut estado = estado_inicial.clone();
                estado.active = captura.is_some() && estado.active;
                estado.pps = stats.pps;
                estado.total = stats.total;
                estado.drops = stats.drops;
                estado.parse_errors = stats.parse_errors;
                stats_previas = stats;

                // Aviso de max_pps: como mucho una vez por minuto.
                if let Some(activa) = captura.as_ref() {
                    let limite = activa.limit_drops();
                    if limite > drops_limite_previos && config.capture.max_pps > 0 {
                        drops_limite_previos = limite;
                        let avisar = ultimo_aviso_limite
                            .map(|ultimo| ahora.duration_since(ultimo) >= NOTICE_INTERVAL)
                            .unwrap_or(true);
                        if avisar {
                            ultimo_aviso_limite = Some(ahora);
                            let _ = event_tx.send(AppEvent::CaptureNotice {
                                level: Level::Warn,
                                message: format!(
                                    "captura limitada a {} pps ([capture].max_pps)",
                                    formatear_pps(config.capture.max_pps)
                                ),
                            });
                        }
                    }
                }
                // Aviso de paquetes descartados por el anillo o la cola (una vez).
                if estado.drops > drops_previos && !aviso_drops_hecho && estado.active
                    && estado.drops >= 1000
                {
                    aviso_drops_hecho = true;
                    let _ = event_tx.send(AppEvent::CaptureNotice {
                        level: Level::Warn,
                        message: format!(
                            "la captura está descartando paquetes ({})",
                            estado.drops
                        ),
                    });
                }

                let agregado = aggregator.snapshot();
                let host_actual = host.snapshot();
                let global = GlobalTraffic {
                    bytes_in: agregado
                        .global
                        .bytes_in
                        .saturating_add(host_actual.bytes_in),
                    bytes_out: agregado
                        .global
                        .bytes_out
                        .saturating_add(host_actual.bytes_out),
                    broadcast_bytes: agregado.global.broadcast_bytes,
                    packets_total: agregado.global.packets_total,
                };
                let update = TrafficUpdate {
                    capture: estado,
                    devices: agregado.devices,
                    host: host_actual,
                    global,
                    connections: cache.views(Instant::now()),
                    connections_total: cache.len(),
                };
                let _ = event_tx.send(AppEvent::Traffic(Box::new(update)));
            }
            _ = tick_kernel.tick() => {
                let kernel = tokio::task::spawn_blocking(leer_conexiones_kernel).await;
                if let Ok((entradas, conntrack)) = kernel {
                    cache.merge_kernel(&entradas, &conntrack, Instant::now());
                }
                cache.purgar(Instant::now());
            }
            comando = command_rx.recv() => {
                match comando {
                    Some(TrafficCommand::UpdateDevices(devices)) => {
                        let mapa = mapa_de_dispositivos(&devices);
                        aggregator.set_devices(&mapa);
                        cache.set_dispositivos(mapa);
                    }
                    Some(TrafficCommand::Stop) | None => break,
                }
            }
        }
    }

    if let Some(activa) = captura {
        let _ = activa.stop();
    }
}

/// Lee /proc/net/{tcp,udp}{,6} y conntrack y atribuye sockets a procesos.
fn leer_conexiones_kernel() -> (
    Vec<(ProcNetEntry, Option<ProcessInfo>)>,
    Vec<ConntrackEntry>,
) {
    let mut entradas = Vec::new();
    if let Ok(tcp) = ProcNet::read_tcp() {
        entradas.extend(tcp);
    }
    if let Ok(udp) = ProcNet::read_udp() {
        entradas.extend(udp);
    }
    let inodos: HashSet<u64> = entradas
        .iter()
        .map(|entrada| entrada.inode)
        .filter(|inodo| *inodo != 0)
        .collect();
    let procesos = Process::attribute_many(&inodos);
    let con_pid = entradas
        .into_iter()
        .map(|entrada| {
            let proceso = procesos.get(&entrada.inode).map(|info| ProcessInfo {
                pid: info.pid,
                comm: info.comm.clone(),
            });
            (entrada, proceso)
        })
        .collect();
    let conntrack = Conntrack::read().unwrap_or_default();
    (con_pid, conntrack)
}

/// Entrada de la caché de conexiones en memoria.
#[derive(Debug, Clone)]
struct Entrada {
    key: ConnectionKey,
    state: Option<String>,
    bytes_in: u64,
    bytes_out: u64,
    first_seen: Instant,
    last_seen: Instant,
    headers: Option<HeaderSnapshot>,
    pid: Option<u32>,
    comm: Option<String>,
    seen_capture: bool,
    seen_kernel: bool,
}

impl Entrada {
    fn nueva(key: ConnectionKey, ahora: Instant) -> Self {
        Self {
            key,
            state: None,
            bytes_in: 0,
            bytes_out: 0,
            first_seen: ahora,
            last_seen: ahora,
            headers: None,
            pid: None,
            comm: None,
            seen_capture: false,
            seen_kernel: false,
        }
    }

    /// Timeout de purga según protocolo y estado.
    fn timeout(&self) -> Duration {
        match self.key.protocol {
            Protocol::Icmp | Protocol::Icmpv6 => TIMEOUT_ICMP,
            Protocol::Udp => TIMEOUT_UDP,
            Protocol::Tcp => match self.state.as_deref() {
                Some("TIME_WAIT") | Some("CLOSE_WAIT") => TIMEOUT_TCP_CERRADA,
                _ => TIMEOUT_TCP,
            },
            Protocol::Other => TIMEOUT_TCP,
        }
    }
}

/// Caché de conexiones activas (memoria, purgada por timeout).
#[derive(Debug)]
struct ConnCache {
    entradas: HashMap<ConnectionKey, Entrada>,
    ip_device: HashMap<IpAddr, i64>,
    host_ips: HashSet<IpAddr>,
}

impl ConnCache {
    fn new(_ahora: Instant, ip_device: HashMap<IpAddr, i64>, host_ips: HashSet<IpAddr>) -> Self {
        Self {
            entradas: HashMap::new(),
            ip_device,
            host_ips,
        }
    }

    fn set_dispositivos(&mut self, ip_device: HashMap<IpAddr, i64>) {
        self.ip_device = ip_device;
    }

    fn len(&self) -> usize {
        self.entradas.len()
    }

    /// Incorpora los paquetes capturados a la caché de conexiones.
    fn ingerir_paquetes(&mut self, paquetes: &[PacketMeta]) {
        for meta in paquetes {
            let key = ConnectionKey::from_packet(meta);
            let salida = meta.src() == key.origin;
            let entrada = self
                .entradas
                .entry(key)
                .or_insert_with(|| Entrada::nueva(key, meta.timestamp));
            entrada.last_seen = meta.timestamp;
            entrada.seen_capture = true;
            if salida {
                entrada.bytes_out = entrada.bytes_out.saturating_add(u64::from(meta.len));
            } else {
                entrada.bytes_in = entrada.bytes_in.saturating_add(u64::from(meta.len));
            }
            if entrada.headers.is_none() {
                entrada.headers = meta.headers;
            }
        }
    }

    /// Mezcla por 5-tuple las conexiones del kernel y de conntrack.
    fn merge_kernel(
        &mut self,
        proc: &[(ProcNetEntry, Option<ProcessInfo>)],
        conntrack: &[ConntrackEntry],
        ahora: Instant,
    ) {
        for (entrada, proceso) in proc {
            if entrada.remote_port == 0 || entrada.state.as_deref() == Some("LISTEN") {
                continue;
            }
            let key = ConnectionKey::from_endpoints(
                entrada.protocol,
                Endpoint::new(entrada.local_ip, Some(entrada.local_port)),
                Endpoint::new(entrada.remote_ip, Some(entrada.remote_port)),
            );
            let conexion = self
                .entradas
                .entry(key)
                .or_insert_with(|| Entrada::nueva(key, ahora));
            conexion.last_seen = ahora;
            conexion.seen_kernel = true;
            if let Some(estado) = &entrada.state {
                conexion.state = Some(estado.clone());
            }
            if let Some(proceso) = proceso {
                conexion.pid = Some(proceso.pid);
                conexion.comm = Some(proceso.comm.clone());
            }
        }
        for entrada in conntrack {
            if entrada.src_port == 0 || entrada.dst_port == 0 {
                continue;
            }
            let key = ConnectionKey::from_endpoints(
                entrada.protocol,
                Endpoint::new(entrada.src_ip, Some(entrada.src_port)),
                Endpoint::new(entrada.dst_ip, Some(entrada.dst_port)),
            );
            let conexion = self
                .entradas
                .entry(key)
                .or_insert_with(|| Entrada::nueva(key, ahora));
            conexion.last_seen = ahora;
            conexion.seen_kernel = true;
            if conexion.state.is_none() {
                conexion.state = entrada.state.clone();
            }
        }
        self.limitar_tamano(ahora);
    }

    /// Poda por timeout y por tamaño máximo.
    fn purgar(&mut self, ahora: Instant) {
        self.entradas.retain(|_, entrada| {
            let inactiva = ahora.saturating_duration_since(entrada.last_seen);
            inactiva < entrada.timeout()
        });
        self.limitar_tamano(ahora);
    }

    fn limitar_tamano(&mut self, ahora: Instant) {
        if self.entradas.len() <= MAX_CONEXIONES {
            return;
        }
        let exceso = self.entradas.len() - MAX_CONEXIONES;
        let mut candidatos: Vec<(ConnectionKey, Duration)> = self
            .entradas
            .iter()
            .map(|(key, entrada)| (*key, ahora.saturating_duration_since(entrada.last_seen)))
            .collect();
        candidatos.sort_by_key(|(_, inactiva)| std::cmp::Reverse(*inactiva));
        for (key, _) in candidatos.into_iter().take(exceso) {
            self.entradas.remove(&key);
        }
    }

    /// Construye la vista de conexiones que consume la TUI.
    fn views(&self, ahora: Instant) -> Vec<ConnectionView> {
        let mut vistas: Vec<ConnectionView> = self
            .entradas
            .values()
            .map(|entrada| {
                let origin = self.endpoint_view(entrada.key.origin);
                let destination = self.endpoint_view(entrada.key.destination);
                ConnectionView {
                    key: entrada.key,
                    state: entrada.state.clone(),
                    bytes_in: entrada.bytes_in,
                    bytes_out: entrada.bytes_out,
                    age: ahora.saturating_duration_since(entrada.first_seen),
                    idle: ahora.saturating_duration_since(entrada.last_seen),
                    pid: entrada.pid,
                    comm: entrada.comm.clone(),
                    device_id: origin.device_id.or(destination.device_id),
                    origin,
                    destination,
                    headers: entrada.headers,
                    seen_capture: entrada.seen_capture,
                    seen_kernel: entrada.seen_kernel,
                }
            })
            .collect();
        vistas.sort_by_key(|vista| vista.idle);
        vistas
    }

    fn endpoint_view(&self, extremo: Endpoint) -> EndpointView {
        let device_id = self.ip_device.get(&extremo.ip).copied();
        let tag = if device_id.is_some() {
            None
        } else if self.host_ips.contains(&extremo.ip) {
            Some("host")
        } else if es_direccion_broadcast(extremo.ip) {
            Some("broadcast")
        } else {
            Some("?")
        };
        EndpointView {
            ip: extremo.ip,
            port: extremo.port,
            device_id,
            tag,
        }
    }
}

/// Formatea una cantidad de bytes por segundo de forma compacta ("12.4 M/s").
pub fn formatear_bytes_por_segundo(bytes: u64) -> String {
    let valor = bytes as f64;
    if bytes >= 1_000_000_000 {
        format!("{:.1} G/s", valor / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} M/s", valor / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} K/s", valor / 1_000.0)
    } else {
        format!("{bytes} B/s")
    }
}

/// Formatea una cantidad de bytes de forma compacta ("14.5 M", "320 K").
pub fn formatear_bytes(bytes: u64) -> String {
    let valor = bytes as f64;
    if bytes >= 1_000_000_000 {
        format!("{:.1} G", valor / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} M", valor / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} K", valor / 1_000.0)
    } else {
        bytes.to_string()
    }
}

/// Formatea una tasa de paquetes ("2.4 K pps").
pub fn formatear_pps(pps: u64) -> String {
    if pps >= 1_000_000 {
        format!("{:.1} M", pps as f64 / 1_000_000.0)
    } else if pps >= 1_000 {
        format!("{:.1} K", pps as f64 / 1_000.0)
    } else {
        pps.to_string()
    }
}

/// Formatea una duración compacta ("3s", "45s", "2m", "3h").
pub fn formatear_duracion(duracion: Duration) -> String {
    let segundos = duracion.as_secs();
    if segundos >= 3600 {
        format!("{}h", segundos / 3600)
    } else if segundos >= 60 {
        format!("{}m", segundos / 60)
    } else {
        format!("{segundos}s")
    }
}

/// Genera una sparkline Unicode de 8 niveles a partir de una serie.
///
/// Los valores se escalan respecto al máximo de la serie; una serie toda a cero
/// se dibuja como una línea de guiones bajos (arranca a cero).
pub fn sparkline(serie: &[u64]) -> String {
    const BLOQUES: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let maximo = serie.iter().copied().max().unwrap_or(0);
    if maximo == 0 {
        return "─".repeat(serie.len());
    }
    serie
        .iter()
        .map(|valor| {
            let nivel = ((*valor as f64 / maximo as f64) * 7.0).round() as usize;
            BLOQUES[nivel.min(7)]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba")
    }

    fn meta(origen: &str, destino: &str, protocolo: Protocol, len: u32) -> PacketMeta {
        let (src_port, dst_port) = match protocolo {
            Protocol::Tcp => (Some(40000), Some(443)),
            Protocol::Udp => (Some(5353), Some(53)),
            _ => (None, None),
        };
        PacketMeta {
            timestamp: Instant::now(),
            src_ip: ip(origen),
            dst_ip: ip(destino),
            src_port,
            dst_port,
            protocol: protocolo,
            len,
            tcp_flags: None,
            headers: None,
            dns_qname: None,
            sni: None,
        }
    }

    fn cache_prueba() -> ConnCache {
        let mut mapa = HashMap::new();
        mapa.insert(ip("192.168.1.42"), 1);
        let mut host = HashSet::new();
        host.insert(ip("192.168.1.10"));
        ConnCache::new(Instant::now(), mapa, host)
    }

    #[test]
    fn status_activo_y_desactivado() {
        let mut status = CaptureStatus {
            active: true,
            filter: "not port 22".to_string(),
            pps: 2400,
            interfaces: vec!["eth0".to_string()],
            ..CaptureStatus::default()
        };
        let texto = status.summary();
        assert!(texto.contains("capturando"));
        assert!(texto.contains("filtro: not port 22"));
        assert!(texto.contains("eth0"));
        assert_eq!(status.no_color_prefix(), "[CAP]");
        status.active = false;
        status.disabled_reason = Some("requiere CAP_NET_RAW".to_string());
        assert!(status.summary().contains("CAP_NET_RAW"));
        assert_eq!(status.no_color_prefix(), "[CAP:off]");
        assert!(CaptureStatus::visibility_label().contains("propia + broadcast"));
    }

    #[test]
    fn status_muestra_limite_pps() {
        let status = CaptureStatus {
            active: true,
            max_pps: 5000,
            ..CaptureStatus::default()
        };
        assert!(status.summary().contains("límite 5.0 K pps"));
    }

    #[test]
    fn captura_agrega_por_conexion_y_direccion() {
        let mut cache = cache_prueba();
        let ida = meta("192.168.1.42", "1.1.1.1", Protocol::Tcp, 100);
        let vuelta = {
            let mut meta = ida.clone();
            std::mem::swap(&mut meta.src_ip, &mut meta.dst_ip);
            std::mem::swap(&mut meta.src_port, &mut meta.dst_port);
            meta.len = 40;
            meta
        };
        cache.ingerir_paquetes(&[ida, vuelta]);
        assert_eq!(cache.len(), 1, "ida y vuelta comparten 5-tuple canónica");
        let vistas = cache.views(Instant::now());
        let vista = &vistas[0];
        assert_eq!(vista.protocol(), Protocol::Tcp);
        let (out, in_) = if vista.origin.ip == ip("192.168.1.42") {
            (vista.bytes_out, vista.bytes_in)
        } else {
            (vista.bytes_in, vista.bytes_out)
        };
        assert_eq!(out, 100);
        assert_eq!(in_, 40);
    }

    #[test]
    fn el_trafico_propio_se_agrega_como_host() {
        let ahora = Instant::now();
        let mut host = HostTraffic::new(ahora);
        let mut propias: HashSet<IpAddr> = HashSet::new();
        propias.insert(ip("192.168.1.49"));
        host.update(
            &meta("192.168.1.49", "1.1.1.1", Protocol::Tcp, 100),
            &propias,
        );
        host.update(
            &meta("1.1.1.1", "192.168.1.49", Protocol::Tcp, 40),
            &propias,
        );
        // Un paquete ajeno no cuenta como tráfico propio.
        host.update(
            &meta("192.168.1.20", "8.8.8.8", Protocol::Udp, 60),
            &propias,
        );

        let instantanea = host.snapshot();
        assert_eq!(instantanea.device_id, DEVICE_ID_HOST);
        assert_eq!(instantanea.bytes_out, 100);
        assert_eq!(instantanea.bytes_in, 40);
        assert_eq!(instantanea.packets_out, 1);
        assert_eq!(instantanea.packets_in, 1);
        assert_eq!(instantanea.rate_out, 100);
        assert_eq!(instantanea.rate_in, 40);
        assert_eq!(instantanea.series_60s_out.iter().sum::<u64>(), 100);
        assert_eq!(instantanea.series_5min_in.iter().sum::<u64>(), 40);
        assert_eq!(
            instantanea.peak_bps, 140,
            "pico = entrada + salida del segundo"
        );
    }

    #[test]
    fn detecta_trafico_de_terceros_y_atribuye_tags() {
        let mut cache = cache_prueba();
        cache.ingerir_paquetes(&[
            meta("192.168.1.20", "8.8.8.8", Protocol::Udp, 60),
            meta("192.168.1.10", "192.168.1.42", Protocol::Tcp, 80),
            meta("0.0.0.0", "255.255.255.255", Protocol::Udp, 300),
        ]);
        let vistas = cache.views(Instant::now());
        assert_eq!(vistas.len(), 3);
        let de_host = vistas
            .iter()
            .find(|vista| {
                vista.origin.ip == ip("192.168.1.10") || vista.destination.ip == ip("192.168.1.10")
            })
            .expect("conexión del host");
        let tag_host = de_host
            .origin
            .tag
            .or(de_host.destination.tag)
            .expect("tag de host");
        assert_eq!(tag_host, "host");
        let bcast = vistas
            .iter()
            .find(|vista| vista.destination.ip == ip("255.255.255.255"))
            .expect("conexión de broadcast");
        assert_eq!(bcast.destination.tag, Some("broadcast"));
        let dispositivo = vistas
            .iter()
            .find(|vista| {
                vista.origin.ip == ip("192.168.1.20") || vista.destination.ip == ip("192.168.1.20")
            })
            .expect("conexión de terceros");
        assert_eq!(dispositivo.device_id, None);
        assert_eq!(
            dispositivo.origin.tag.or(dispositivo.destination.tag),
            Some("?")
        );
    }

    #[test]
    fn merge_kernel_respeta_estado_y_pid() {
        let mut cache = cache_prueba();
        let entrada = ProcNetEntry {
            local_ip: ip("192.168.1.10"),
            local_port: 40000,
            remote_ip: ip("1.1.1.1"),
            remote_port: 443,
            state: Some("ESTABLISHED".to_string()),
            inode: 4242,
            protocol: Protocol::Tcp,
        };
        let proceso = ProcessInfo {
            pid: 1234,
            comm: "firefox".to_string(),
        };
        let conntrack = vec![ConntrackEntry {
            protocol: Protocol::Udp,
            src_ip: ip("192.168.1.10"),
            src_port: 5353,
            dst_ip: ip("224.0.0.251"),
            dst_port: 5353,
            state: Some("UNREPLIED".to_string()),
        }];
        cache.merge_kernel(&[(entrada, Some(proceso))], &conntrack, Instant::now());
        let vistas = cache.views(Instant::now());
        assert_eq!(vistas.len(), 2);
        let tcp = vistas
            .iter()
            .find(|vista| vista.protocol() == Protocol::Tcp)
            .expect("conexión TCP del kernel");
        assert_eq!(tcp.state_label(), "ESTABLISHED");
        assert_eq!(tcp.pid, Some(1234));
        assert_eq!(tcp.comm.as_deref(), Some("firefox"));
    }

    #[test]
    fn purga_por_timeout_y_por_protocolo() {
        let mut cache = cache_prueba();
        let ahora = Instant::now();
        cache.ingerir_paquetes(&[meta("192.168.1.20", "8.8.8.8", Protocol::Udp, 60)]);
        // Simula 61 s de inactividad: UDP caduca a los 60 s.
        cache.purgar(ahora + TIMEOUT_UDP + Duration::from_secs(1));
        assert_eq!(cache.len(), 0);

        let mut cache = cache_prueba();
        cache.ingerir_paquetes(&[meta("192.168.1.20", "8.8.8.8", Protocol::Tcp, 60)]);
        cache.purgar(ahora + TIMEOUT_TCP - Duration::from_secs(1));
        assert_eq!(cache.len(), 1, "TCP sigue viva antes de 300 s");
    }

    #[test]
    fn purga_time_wait_antes_que_tcp_normal() {
        let mut cache = cache_prueba();
        let ahora = Instant::now();
        let entrada = ProcNetEntry {
            local_ip: ip("192.168.1.10"),
            local_port: 40000,
            remote_ip: ip("1.1.1.1"),
            remote_port: 443,
            state: Some("TIME_WAIT".to_string()),
            inode: 1,
            protocol: Protocol::Tcp,
        };
        cache.merge_kernel(&[(entrada, None)], &[], ahora);
        cache.purgar(ahora + TIMEOUT_TCP_CERRADA + Duration::from_secs(1));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn formateos_compactos() {
        assert_eq!(formatear_bytes_por_segundo(0), "0 B/s");
        assert_eq!(formatear_bytes_por_segundo(1200), "1.2 K/s");
        assert_eq!(formatear_bytes_por_segundo(1_500_000), "1.5 M/s");
        assert_eq!(formatear_bytes(0), "0");
        assert_eq!(formatear_bytes(14_500_000), "14.5 M");
        assert_eq!(formatear_bytes(320_000), "320.0 K");
        assert_eq!(formatear_pps(2400), "2.4 K");
        assert_eq!(formatear_pps(12), "12");
        assert_eq!(formatear_duracion(Duration::from_secs(45)), "45s");
        assert_eq!(formatear_duracion(Duration::from_secs(125)), "2m");
        assert_eq!(formatear_duracion(Duration::from_secs(7200)), "2h");
    }

    #[test]
    fn sparkline_escala_y_arranca_a_cero() {
        assert_eq!(sparkline(&[0, 0, 0]), "───");
        let serie = [0, 1, 2, 4, 8];
        let dibujo = sparkline(&serie);
        assert_eq!(dibujo.chars().count(), serie.len());
        assert!(dibujo.starts_with('▁'));
        assert!(dibujo.ends_with('█'));
    }

    #[test]
    fn localiza_y_formatea_endpoints() {
        let v4 = EndpointView {
            ip: ip("192.168.1.42"),
            port: Some(443),
            device_id: Some(1),
            tag: None,
        };
        assert_eq!(v4.display(), "192.168.1.42:443");
        let v6 = EndpointView {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: Some(53),
            device_id: None,
            tag: Some("host"),
        };
        assert_eq!(v6.display(), "[::1]:53");
        assert_eq!(Ipv4Addr::new(192, 168, 1, 42).to_string(), "192.168.1.42");
        assert!(es_direccion_broadcast(ip("224.0.0.251")));
        assert!(es_direccion_broadcast(ip("ff02::fb")));
    }
}
