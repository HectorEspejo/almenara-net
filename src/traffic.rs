//! Monitor de tráfico en vivo (Fases 3 y 4).
//!
//! Tarea asíncrona que integra la captura AF_PACKET, la agregación por
//! dispositivo, las conexiones del kernel (/proc/net/* y conntrack), las
//! conexiones observadas por captura y el motor de inferencia de F4: caché de
//! nombres, catálogo de apps, base IP, rankings y panel «¿Quién lo usa?».
//!
//! Publica una actualización cada segundo por el bus de eventos; el hilo de la
//! TUI es el único que escribe en SQLite (snapshot, conexiones y caché de
//! nombres cada 5 s), respetando la regla de una única conexión de escritura en
//! el hilo de la TUI.
//!
//! Este módulo no persiste nada: solo calcula el estado en memoria y lo emite.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc};

use crate::capture::aggregate::{Aggregator, DeviceTraffic, GlobalTraffic};
use crate::capture::conntrack::{Conntrack, ConntrackEntry, ProcNet, ProcNetEntry};
use crate::capture::process::{Process, ProcessInfo};
use crate::capture::windows::Windows;
use crate::capture::{
    es_direccion_broadcast, Capture, CaptureInference, CaptureInterface, CaptureStats,
    ConnectionKey, Endpoint, HeaderSnapshot, PacketMeta, Protocol,
};
use crate::config::Config;
use crate::events::{AppEvent, TrafficCommand};
use crate::identify::observed::{ObservedFilter, ObservedHosts};
use crate::identify::CaptureIdentityStore;
use crate::inference::catalog::{self, Catalog, CatalogCounts};
use crate::inference::ipdb::IpDb;
use crate::inference::names::NameEntry;
use crate::inference::role::ListenSet;
use crate::inference::{AppProtocol, FlowLabel, InferenceCounters, LabelResolver, L4};
use crate::notifier::Level;
use crate::rankings::{Dimension, Dir, FlowCtx, Rankings, SortKey, Window};

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
/// Filas publicadas por dimensión y ventana en cada actualización.
pub const TOP_RANKING: usize = 50;

/// Servicio de F2 de un equipo, tal y como lo consume el catálogo de red local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRef {
    /// Puerto.
    pub port: u16,
    /// Transporte.
    pub protocol: Protocol,
    /// Servicio identificado ("smb", "ssh", "rtsp"…).
    pub service: Option<String>,
}

/// Referencia mínima a un dispositivo para atribuir tráfico por IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRef {
    /// Id del dispositivo en SQLite.
    pub id: i64,
    /// Última IP conocida del dispositivo.
    pub ip: String,
    /// MAC normalizada del dispositivo.
    pub mac: String,
    /// Nombre visible (alias, hostname o MAC).
    pub name: Option<String>,
    /// Servicios de F2 detectados.
    pub services: Vec<ServiceRef>,
}

impl DeviceRef {
    /// Construye la referencia a partir de la IP en texto.
    ///
    /// La usa el canal de órdenes y los tests; la integración principal usa
    /// [DeviceRef::with_details] para llevar también identidad y servicios.
    #[allow(dead_code)]
    pub fn new(id: i64, ip: impl Into<String>) -> Self {
        Self {
            id,
            ip: ip.into(),
            mac: String::new(),
            name: None,
            services: Vec::new(),
        }
    }

    /// Construye la referencia con identidad y servicios de F2.
    pub fn with_details(
        id: i64,
        ip: impl Into<String>,
        mac: impl Into<String>,
        name: Option<String>,
        services: Vec<ServiceRef>,
    ) -> Self {
        Self {
            id,
            ip: ip.into(),
            mac: mac.into(),
            name,
            services,
        }
    }

    /// IP parseada, si el texto es válido.
    pub fn parsed_ip(&self) -> Option<IpAddr> {
        self.ip.parse().ok()
    }

    /// Nombre visible (nombre, MAC o IP).
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .filter(|nombre| !nombre.trim().is_empty())
            .or_else(|| {
                if self.mac.trim().is_empty() {
                    None
                } else {
                    Some(self.mac.clone())
                }
            })
            .unwrap_or_else(|| self.ip.clone())
    }
}

/// Estado de la captura visible en la barra de estado y en la pestaña Tráfico.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// La inferencia está activa ([inference].enabled).
    pub inference_enabled: bool,
    /// Contadores del motor de inferencia de la fase.
    pub inference: InferenceCounters,
    /// Entradas vigentes en la caché de nombres.
    pub names_cached: usize,
}

impl Default for CaptureStatus {
    fn default() -> Self {
        Self {
            active: false,
            interfaces: Vec::new(),
            filter: String::new(),
            pps: 0,
            total: 0,
            drops: 0,
            parse_errors: 0,
            max_pps: 0,
            available: false,
            disabled_reason: None,
            inference_enabled: true,
            inference: InferenceCounters::default(),
            names_cached: 0,
        }
    }
}

impl CaptureStatus {
    /// Texto de una línea con el estado de la captura.
    pub fn summary(&self) -> String {
        if !self.active {
            let motivo = self
                .disabled_reason
                .clone()
                .unwrap_or_else(|| "captura desactivada".to_string());
            return format!(
                "captura deshabilitada: {motivo} · {}",
                self.inference_label()
            );
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
        texto.push_str(" · ");
        texto.push_str(self.inference_label());
        texto
    }

    /// Texto «inferencia: activa / desactivada» de la barra de estado.
    pub fn inference_label(&self) -> &'static str {
        if self.inference_enabled {
            "inferencia: activa"
        } else {
            "inferencia: desactivada"
        }
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
    /// Etiqueta de F4 resuelta (protocolo de app, nombre, app, rol, JA4…).
    pub label: Option<FlowLabel>,
    /// Nombre visible de la app (catálogo).
    pub app_name: Option<String>,
    /// Nombre corto de la categoría.
    pub category_name: Option<String>,
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

    /// Protocolo de aplicación visible ("tcp"/"udp" si no se identificó).
    pub fn app_protocol_label(&self) -> &str {
        self.label
            .as_ref()
            .and_then(|etiqueta| etiqueta.app_protocol)
            .map(AppProtocol::as_str)
            .unwrap_or_else(|| self.protocol().as_str())
    }

    /// Nombre del servidor o IP del destino.
    pub fn server_label(&self) -> String {
        self.label
            .as_ref()
            .and_then(|etiqueta| etiqueta.server_name.clone())
            .unwrap_or_else(|| self.destination.ip.to_string())
    }

    /// App visible (nombre del catálogo o "Sin identificar").
    pub fn app_label(&self) -> String {
        self.app_name
            .clone()
            .or_else(|| {
                self.label
                    .as_ref()
                    .and_then(|etiqueta| etiqueta.app.clone())
            })
            .unwrap_or_else(|| "Sin identificar".to_string())
    }

    /// Nombre de la categoría visible ("—" si no hay).
    pub fn category_label(&self) -> &str {
        self.category_name.as_deref().unwrap_or("—")
    }
}

/// Filas de un ranking de una dimensión y ventana.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankingView {
    /// Dimensión del ranking.
    pub dimension: Dimension,
    /// Ventana.
    pub window: Window,
    /// Top 50 filas ordenadas por total de bytes.
    pub rows: Vec<crate::rankings::RankRow>,
}

/// Top apps y destinos de un equipo (detalle de equipo, ventana de 5 min).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRankingView {
    /// Equipo (o [host] con -1).
    pub device_id: i64,
    /// Ventana consultada.
    pub window: Window,
    /// Top 5 apps del equipo.
    pub apps: Vec<crate::rankings::RankRow>,
    /// Top 5 destinos del equipo.
    pub destinations: Vec<crate::rankings::RankRow>,
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
    /// Conexiones activas (vista ya resuelta con su etiqueta de F4).
    pub connections: Vec<ConnectionView>,
    /// Número total de conexiones en la caché.
    pub connections_total: usize,
    /// Top 50 por dimensión y ventana (6 × 3 entradas).
    pub rankings: Vec<RankingView>,
    /// Porcentaje de bytes sin identificar por ventana [60 s, 5 min, sesión].
    pub unidentified: [f32; 3],
    /// Top 5 de apps y destinos por equipo (detalle de equipo, 5 min).
    pub device_rankings: Vec<DeviceRankingView>,
    /// Entradas nuevas o refrescadas de NAME_CACHE (para persistir cada 5 s).
    pub names: Vec<NameEntry>,
    /// La inferencia está activa.
    #[allow(dead_code)]
    pub inference_enabled: bool,
    /// Cifras del catálogo para la pestaña Config.
    pub catalog: CatalogCounts,
    /// Fecha de las bases IP embebidas.
    pub ipdb_date: Option<String>,
}

/// Handle de la tarea de tráfico.
#[derive(Debug)]
pub struct TrafficHandle {
    /// Canal de órdenes hacia la tarea.
    pub command_tx: mpsc::Sender<TrafficCommand>,
    /// Handle de la tarea tokio (se aborta al cerrar si sigue viva).
    pub join: tokio::task::JoinHandle<()>,
}

/// Estado devuelto al arrancar la tarea de tráfico.
pub struct TrafficStart {
    /// Handle de control de la tarea.
    pub handle: TrafficHandle,
    /// Estado inicial de la captura.
    pub status: CaptureStatus,
    /// Notificaciones que se muestran una única vez al arrancar.
    pub notices: Vec<(Level, String)>,
    /// Equipos observados en la captura (los vacía el ciclo de escaneo).
    pub observed: Arc<Mutex<ObservedHosts>>,
    /// Identidad capturada (DHCP y User-Agent) para el ciclo de escaneo.
    pub identity: Arc<Mutex<CaptureIdentityStore>>,
    /// Cifras del catálogo.
    pub catalog: CatalogCounts,
    /// Fecha de las bases IP embebidas.
    pub ipdb_date: Option<String>,
}

/// Arranca la tarea de monitorización de tráfico.
///
/// `names` son las entradas vigentes de NAME_CACHE cargadas al arrancar en
/// caliente; `devices` incluye sus servicios de F2 para el catálogo de red local.
pub fn spawn(
    config: &Config,
    interfaces: Vec<CaptureInterface>,
    host_ips: HashSet<IpAddr>,
    devices: Vec<DeviceRef>,
    names: Vec<NameEntry>,
    capabilities_raw: bool,
    event_tx: broadcast::Sender<AppEvent>,
) -> TrafficStart {
    let mut notificaciones: Vec<(Level, String)> = Vec::new();

    // Catálogo de apps embebido + apps.toml del usuario.
    let (catalogo, avisos_catalogo) = Catalog::load(
        catalog::EMBEDDED,
        config.inference.apps_file_path().as_deref(),
    );
    for aviso in avisos_catalogo {
        notificaciones.push((Level::Warn, aviso.message));
    }
    let catalog_counts = catalogo.counts();

    // Bases IP embebidas (ASN y país).
    let (ipdb, ipdb_date) = match IpDb::embedded() {
        Ok(base) => {
            let fecha = base.build_date();
            (Some(base), fecha)
        }
        Err(error) => {
            notificaciones.push((
                Level::Warn,
                format!("No se pudieron abrir las bases IP embebidas: {error}"),
            ));
            (None, None)
        }
    };

    // Resolutor de etiquetas: catálogo, base IP, caché de nombres y equipos.
    let mut resolver = LabelResolver::new(&config.inference, catalogo, ipdb, host_ips.clone());
    resolver.names_mut().load(names);
    resolver.set_devices(&nombres_para_resolver(&devices));
    resolver.set_services(servicios_para_resolver(&devices));

    // Rankings con los nombres del catálogo y de los equipos.
    let mut rankings = Rankings::new();
    rankings.set_devices(mapa_nombres_equipos(&devices));
    rankings.set_app_names(
        resolver
            .catalog()
            .apps()
            .iter()
            .map(|app| (app.key.clone(), app.name.clone()))
            .collect(),
    );
    rankings.set_category_names(
        resolver
            .catalog()
            .categories()
            .iter()
            .map(|categoria| (categoria.key.clone(), categoria.short.clone()))
            .collect(),
    );
    rankings.set_app_categories(
        resolver
            .catalog()
            .apps()
            .iter()
            .filter_map(|app| {
                resolver
                    .catalog()
                    .category_short(&app.category)
                    .map(|corta| (app.key.clone(), corta.to_string()))
            })
            .collect(),
    );

    // Estado compartido con los hilos de captura y con el ciclo de escaneo.
    let listening = Arc::new(RwLock::new(ListenSet::new()));
    let observed = Arc::new(Mutex::new(ObservedHosts::new(filtro_observados(
        &interfaces,
        &host_ips,
    ))));
    let identity = Arc::new(Mutex::new(CaptureIdentityStore::new()));
    let filtro = filtro_observados(&interfaces, &host_ips);

    let mut estado = CaptureStatus {
        max_pps: config.capture.max_pps,
        filter: config.capture.filter.clone(),
        interfaces: interfaces
            .iter()
            .map(|interfaz| interfaz.name.clone())
            .collect(),
        available: capabilities_raw,
        inference_enabled: config.inference.enabled,
        ..CaptureStatus::default()
    };

    if !config.inference.enabled {
        notificaciones.push((
            Level::Info,
            "Inferencia desactivada ([inference].enabled = false): solo se etiqueta por servicio de F2, ASN, puerto y proceso".to_string(),
        ));
    }

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
        let inferencia = CaptureInference::new(
            config.inference.clone(),
            host_ips.clone(),
            Arc::clone(&listening),
            Arc::clone(&identity),
            Arc::clone(&observed),
            filtro,
        );
        match Capture::start(&config.capture, interfaces.clone(), inferencia) {
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
            resolver,
            rankings,
            listening,
            event_tx,
            command_rx,
        )
        .await;
    });

    TrafficStart {
        handle: TrafficHandle { command_tx, join },
        status: estado,
        notices: notificaciones,
        observed,
        identity,
        catalog: catalog_counts,
        ipdb_date,
    }
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

fn nombres_para_resolver(devices: &[DeviceRef]) -> Vec<(IpAddr, i64, String)> {
    devices
        .iter()
        .filter_map(|device| {
            device
                .parsed_ip()
                .map(|ip| (ip, device.id, device.display_name()))
        })
        .collect()
}

fn servicios_para_resolver(devices: &[DeviceRef]) -> HashMap<(IpAddr, u16), Vec<String>> {
    let mut servicios: HashMap<(IpAddr, u16), Vec<String>> = HashMap::new();
    for device in devices {
        let Some(ip) = device.parsed_ip() else {
            continue;
        };
        for servicio in &device.services {
            if let Some(nombre) = &servicio.service {
                servicios
                    .entry((ip, servicio.port))
                    .or_default()
                    .push(nombre.clone());
            }
        }
    }
    servicios
}

fn puertos_de_servicio(devices: &[DeviceRef]) -> Vec<u16> {
    devices
        .iter()
        .flat_map(|device| device.services.iter().map(|servicio| servicio.port))
        .collect()
}

fn mapa_nombres_equipos(devices: &[DeviceRef]) -> HashMap<i64, String> {
    let mut mapa: HashMap<i64, String> = HashMap::new();
    mapa.insert(DEVICE_ID_HOST, "[host]".to_string());
    for device in devices {
        mapa.insert(device.id, device.display_name());
    }
    mapa
}

fn filtro_observados(
    interfaces: &[CaptureInterface],
    host_ips: &HashSet<IpAddr>,
) -> ObservedFilter {
    use std::net::Ipv4Addr;
    let mut filtro = ObservedFilter::default();
    for interfaz in interfaces {
        if let Some(mac) = &interfaz.mac {
            filtro.local_macs.insert(mac.to_ascii_lowercase());
        }
        if let Some(ip) = interfaz.ipv4 {
            filtro.local_ips.insert(ip);
            if let Some(red) = interfaz.red_local() {
                filtro.networks.push(red);
            }
        }
        if let Some(gateway) = interfaz.gateway {
            filtro.gateway_ip = Some(gateway);
        }
    }
    for ip in host_ips {
        if let IpAddr::V4(ipv4) = ip {
            filtro.local_ips.insert(*ipv4);
        }
    }
    if filtro.local_ips.is_empty() {
        filtro.local_ips.insert(Ipv4Addr::LOCALHOST);
    }
    // MAC del gateway desde la tabla ARP del núcleo (solo si hay gateway).
    if let Some(gateway) = filtro.gateway_ip {
        let entradas = crate::scanner::proc_arp::read();
        if let Some(entrada) = entradas.iter().find(|entrada| entrada.ip == gateway) {
            filtro.gateway_mac = Some(entrada.mac.to_ascii_lowercase());
        }
    }
    filtro
}

/// Agregado en memoria del tráfico propio del host ([host]).
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

/// Bytes acumulados de un flujo entre dos volcados a los rankings.
#[derive(Debug, Default, Clone, Copy)]
struct FlujoPendiente {
    desde_origen: u64,
    desde_destino: u64,
}

#[allow(clippy::too_many_arguments)]
async fn ejecutar(
    captura: Option<Capture>,
    config: Config,
    estado_inicial: CaptureStatus,
    mapa_inicial: HashMap<IpAddr, i64>,
    host_ips: HashSet<IpAddr>,
    mut resolver: LabelResolver,
    mut rankings: Rankings,
    listening: Arc<RwLock<ListenSet>>,
    event_tx: broadcast::Sender<AppEvent>,
    mut command_rx: mpsc::Receiver<TrafficCommand>,
) {
    let ahora = Instant::now();
    let mut ids_dispositivos: Vec<i64> = mapa_inicial.values().copied().collect();
    ids_dispositivos.push(DEVICE_ID_HOST);
    ids_dispositivos.sort_unstable();
    ids_dispositivos.dedup();
    let mut aggregator = Aggregator::new(ahora);
    aggregator.set_devices(&mapa_inicial);
    let mut cache = ConnCache::new(ahora, mapa_inicial, host_ips.clone());
    let mut host = HostTraffic::new(ahora);
    let mut pendientes: HashMap<ConnectionKey, FlujoPendiente> = HashMap::new();
    let mut puertos_servicio: Vec<u16> = Vec::new();

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
                    let drenado = activa.drain();
                    if !drenado.packets.is_empty() || !drenado.evidence.is_empty() {
                        // Evidencias primero: el nombre y la app de un flujo se
                        // resuelven antes de volcar sus bytes a los rankings.
                        for evidencia in drenado.evidence {
                            match evidencia {
                                crate::inference::Evidence::Name(observacion) => {
                                    resolver.observe_name(observacion);
                                }
                                crate::inference::Evidence::Flow(flujo) => {
                                    resolver.resolve(&flujo.key, &flujo);
                                }
                                _ => {}
                            }
                        }
                        cache.ingerir_paquetes(&drenado.packets);
                        for meta in &drenado.packets {
                            aggregator.update(meta);
                            host.update(meta, &host_ips);
                            acumular_pendiente(&mut pendientes, meta);
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
                estado.inference = stats.inference;
                estado.inference_enabled = config.inference.enabled;
                estado.names_cached = resolver.names().len();
                stats_previas = stats;

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

                // Volcado de los bytes del último segundo a los rankings.
                rankings.tick(ahora);
                volcar_pendientes(&mut pendientes, &mut resolver, &mut rankings, &cache, &host_ips, ahora);

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

                // Conexiones con su etiqueta y nombres visibles.
                let mut conexiones = cache.views(ahora);
                for vista in &mut conexiones {
                    let etiqueta = resolver.label_for(&vista.key).clone();
                    vista.app_name = etiqueta
                        .app
                        .as_deref()
                        .and_then(|clave| resolver.catalog().app_name(clave))
                        .map(str::to_string);
                    vista.category_name = etiqueta
                        .category
                        .as_deref()
                        .and_then(|clave| resolver.catalog().category_short(clave))
                        .map(str::to_string);
                    vista.label = Some(etiqueta);
                }

                // Rankings publicados: top 50 por dimensión y ventana.
                let mut vistas_rankings = Vec::with_capacity(18);
                for dimension in Dimension::ALL {
                    for window in Window::ALL {
                        vistas_rankings.push(RankingView {
                            dimension,
                            window,
                            rows: rankings.top(dimension, window, SortKey::Total, TOP_RANKING),
                        });
                    }
                }
                let sin_identificar = [
                    rankings.unidentified_share(Window::Sixty),
                    rankings.unidentified_share(Window::FiveMin),
                    rankings.unidentified_share(Window::Session),
                ];

                // Conexiones activas por clave (columna de los rankings).
                rankings.begin_connections();
                for vista in &conexiones {
                    let Some(etiqueta) = &vista.label else {
                        continue;
                    };
                    let proceso = if vista.pid.is_some()
                        && (vista.device_id == Some(DEVICE_ID_HOST)
                            || vista.origin.tag == Some("host")
                            || vista.destination.tag == Some("host"))
                    {
                        Some((vista.pid.unwrap_or(0), vista.comm.clone().unwrap_or_default()))
                    } else {
                        None
                    };
                    let ctx = FlowCtx {
                        device_id: vista.device_id,
                        process: proceso,
                        l4: L4::from_protocol(vista.key.protocol),
                    };
                    rankings.record_connection(etiqueta, &ctx);
                }

                // Top 5 de apps y destinos por equipo para el detalle.
                let detalle_equipos: Vec<DeviceRankingView> = ids_dispositivos
                    .iter()
                    .map(|device_id| DeviceRankingView {
                        device_id: *device_id,
                        window: Window::FiveMin,
                        apps: rankings.top_for_device(
                            Dimension::App,
                            *device_id,
                            Window::FiveMin,
                            5,
                        ),
                        destinations: rankings.top_for_device(
                            Dimension::Destination,
                            *device_id,
                            Window::FiveMin,
                            5,
                        ),
                    })
                    .collect();

                let update = TrafficUpdate {
                    capture: estado,
                    devices: agregado.devices,
                    host: host_actual,
                    global,
                    connections: conexiones,
                    connections_total: cache.len(),
                    rankings: vistas_rankings,
                    unidentified: sin_identificar,
                    device_rankings: detalle_equipos,
                    names: resolver.take_dirty_names(),
                    inference_enabled: config.inference.enabled,
                    catalog: resolver.catalog().counts(),
                    ipdb_date: resolver.ipdb().and_then(|base| base.build_date()),
                };
                let _ = event_tx.send(AppEvent::Traffic(Box::new(update)));
            }
            _ = tick_kernel.tick() => {
                let kernel = tokio::task::spawn_blocking(leer_conexiones_kernel).await;
                if let Ok((entradas, conntrack, escuchas)) = kernel {
                    cache.merge_kernel(&entradas, &conntrack, Instant::now());
                    actualizar_escuchas(&listening, &escuchas, &puertos_servicio);
                }
                cache.purgar(Instant::now());
                resolver.prune_names(std::time::SystemTime::now());
            }
            comando = command_rx.recv() => {
                match comando {
                    Some(TrafficCommand::UpdateDevices(devices)) => {
                        let mapa = mapa_de_dispositivos(&devices);
                        aggregator.set_devices(&mapa);
                        cache.set_dispositivos(mapa);
                        resolver.set_devices(&nombres_para_resolver(&devices));
                        resolver.set_services(servicios_para_resolver(&devices));
                        puertos_servicio = puertos_de_servicio(&devices);
                        rankings.set_devices(mapa_nombres_equipos(&devices));
                        ids_dispositivos = devices.iter().map(|device| device.id).collect();
                        ids_dispositivos.push(DEVICE_ID_HOST);
                        ids_dispositivos.sort_unstable();
                        ids_dispositivos.dedup();
                    }
                    Some(TrafficCommand::WhoUses { dimension, key, window, reply }) => {
                        let cuota = rankings.who_uses(dimension, &key, window);
                        let _ = reply.send(cuota);
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

/// Suma los bytes de un paquete a su flujo pendiente de volcar a los rankings.
fn acumular_pendiente(pendientes: &mut HashMap<ConnectionKey, FlujoPendiente>, meta: &PacketMeta) {
    let key = ConnectionKey::from_packet(meta);
    let entrada = pendientes.entry(key).or_default();
    let bytes = u64::from(meta.len);
    if meta.src() == key.origin {
        entrada.desde_origen = entrada.desde_origen.saturating_add(bytes);
    } else {
        entrada.desde_destino = entrada.desde_destino.saturating_add(bytes);
    }
}

/// Vuelca los bytes acumulados del último segundo a los rankings.
fn volcar_pendientes(
    pendientes: &mut HashMap<ConnectionKey, FlujoPendiente>,
    resolver: &mut LabelResolver,
    rankings: &mut Rankings,
    cache: &ConnCache,
    host_ips: &HashSet<IpAddr>,
    ahora: Instant,
) {
    for (key, acumulado) in pendientes.drain() {
        let etiqueta = resolver.label_for(&key).clone();
        let cliente_origen = etiqueta.client_is_src.unwrap_or_else(|| {
            if host_ips.contains(&key.origin.ip) {
                true
            } else {
                !host_ips.contains(&key.destination.ip)
            }
        });
        let (bajada, subida) = if cliente_origen {
            (acumulado.desde_destino, acumulado.desde_origen)
        } else {
            (acumulado.desde_origen, acumulado.desde_destino)
        };
        let (device_id, proceso) = contexto_para(&key, cliente_origen, cache, host_ips);
        let ctx = FlowCtx {
            device_id,
            process: proceso,
            l4: L4::from_protocol(key.protocol),
        };
        if subida > 0 {
            rankings.record(&etiqueta, &ctx, subida, Dir::Up, ahora);
        }
        if bajada > 0 {
            rankings.record(&etiqueta, &ctx, bajada, Dir::Down, ahora);
        }
    }
}

/// Equipo y proceso local atribuidos a un flujo para los rankings.
fn contexto_para(
    key: &ConnectionKey,
    cliente_origen: bool,
    cache: &ConnCache,
    host_ips: &HashSet<IpAddr>,
) -> (Option<i64>, Option<(u32, String)>) {
    let (cliente, servidor) = if cliente_origen {
        (key.origin, key.destination)
    } else {
        (key.destination, key.origin)
    };
    let device = if host_ips.contains(&cliente.ip) {
        Some(DEVICE_ID_HOST)
    } else {
        cache.dispositivo_de(&cliente.ip).or_else(|| {
            if host_ips.contains(&servidor.ip) {
                Some(DEVICE_ID_HOST)
            } else {
                cache.dispositivo_de(&servidor.ip)
            }
        })
    };
    let proceso = if host_ips.contains(&cliente.ip) || host_ips.contains(&servidor.ip) {
        cache.proceso_de(key)
    } else {
        None
    };
    (device, proceso)
}

/// Actualiza el conjunto de puertos en escucha y de servicio.
fn actualizar_escuchas(
    listening: &Arc<RwLock<ListenSet>>,
    escuchas: &[(Protocol, u16)],
    servicios: &[u16],
) {
    if let Ok(mut conjunto) = listening.write() {
        conjunto.set_listening(escuchas.iter().copied());
        conjunto.set_services(servicios.iter().copied());
    }
}

/// Conexiones del kernel leídas para mezclar en la caché.
type ConexionesKernel = (
    Vec<(ProcNetEntry, Option<ProcessInfo>)>,
    Vec<ConntrackEntry>,
    Vec<(Protocol, u16)>,
);

/// Lee /proc/net/{tcp,udp}{,6} y conntrack, atribuye sockets a procesos y
/// devuelve los puertos en LISTEN.
fn leer_conexiones_kernel() -> ConexionesKernel {
    let mut entradas = Vec::new();
    if let Ok(tcp) = ProcNet::read_tcp() {
        entradas.extend(tcp);
    }
    if let Ok(udp) = ProcNet::read_udp() {
        entradas.extend(udp);
    }
    let escuchas: Vec<(Protocol, u16)> = entradas
        .iter()
        .filter(|entrada| entrada.state.as_deref() == Some("LISTEN") || entrada.remote_port == 0)
        .filter(|entrada| entrada.local_port != 0)
        .map(|entrada| (entrada.protocol, entrada.local_port))
        .collect();
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
    (con_pid, conntrack, escuchas)
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

    /// Equipo inventariado de una IP, si lo hay.
    fn dispositivo_de(&self, ip: &IpAddr) -> Option<i64> {
        self.ip_device.get(ip).copied()
    }

    /// Proceso local de una conexión, si se atribuyó por /proc.
    fn proceso_de(&self, key: &ConnectionKey) -> Option<(u32, String)> {
        let entrada = self.entradas.get(key)?;
        let pid = entrada.pid?;
        Some((pid, entrada.comm.clone().unwrap_or_default()))
    }

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
                    label: None,
                    app_name: None,
                    category_name: None,
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
