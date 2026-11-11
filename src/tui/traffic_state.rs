//! Estado de tráfico, conexiones y detalle de equipo en la TUI (Fase 3).
//!
//! Este módulo amplía [App] con el estado que consume la interfaz en las
//! pestañas Tráfico y Conexiones, el panel master-detail de equipo y el panel de
//! cabeceras de la tecla v. La lógica de captura y de red vive en
//! [crate::traffic] y [crate::capture]; aquí solo hay estado de presentación.

use std::time::{Duration, Instant};

use crate::capture::aggregate::{DeviceTraffic, GlobalTraffic};
use crate::capture::Protocol;
use crate::config::TrafficGroup;
use crate::rankings::{DeviceShare, Dimension, RankRow, SortKey, Window};
use crate::repo::{DeviceService, TrafficSnapshot};
use crate::traffic::{
    CaptureStatus, ConnectionView, DeviceRankingView, EndpointView, TrafficUpdate,
};
use crate::tui::app::App;

/// A partir de este ancho el panel de detalle ocupa la mitad derecha; por
/// debajo se muestra a pantalla completa.
pub const DETAIL_MIN_WIDTH: u16 = 100;

/// Panel que tiene el foco en la vista master-detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FocusPanel {
    /// Lista de equipos (panel izquierdo).
    #[default]
    Lista,
    /// Detalle del equipo (panel derecho o pantalla completa).
    Detalle,
}

impl FocusPanel {
    /// Devuelve el foco contrario.
    pub fn toggled(self) -> Self {
        match self {
            Self::Lista => Self::Detalle,
            Self::Detalle => Self::Lista,
        }
    }
}

/// Columna por la que se ordena la tabla de conexiones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSortKey {
    /// Protocolo de transporte.
    Protocolo,
    /// Origen (IP y puerto).
    Origen,
    /// Destino (IP y puerto).
    Destino,
    /// Estado TCP.
    Estado,
    /// Bytes enviados por el origen.
    Enviado,
    /// Bytes recibidos por el origen.
    Recibido,
    /// Edad de la conexión.
    Edad,
}

impl ConnectionSortKey {
    /// Columnas en orden de ciclado.
    pub const ALL: [Self; 7] = [
        Self::Protocolo,
        Self::Origen,
        Self::Destino,
        Self::Estado,
        Self::Enviado,
        Self::Recibido,
        Self::Edad,
    ];

    /// Siguiente columna.
    pub fn next(self) -> Self {
        let posicion = Self::ALL
            .iter()
            .position(|clave| *clave == self)
            .unwrap_or(0);
        Self::ALL[(posicion + 1) % Self::ALL.len()]
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Protocolo => "protocolo",
            Self::Origen => "origen",
            Self::Destino => "destino",
            Self::Estado => "estado",
            Self::Enviado => "enviado",
            Self::Recibido => "recibido",
            Self::Edad => "edad",
        }
    }
}

/// Estado de ordenación de la tabla de conexiones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionSort {
    /// Columna activa.
    pub key: ConnectionSortKey,
    /// Orden ascendente.
    pub ascending: bool,
}

impl Default for ConnectionSort {
    fn default() -> Self {
        Self {
            key: ConnectionSortKey::Enviado,
            ascending: false,
        }
    }
}

impl ConnectionSort {
    /// Cicla a la siguiente columna o invierte la dirección.
    pub fn cycle(&mut self) {
        if self.ascending {
            self.ascending = false;
        } else {
            self.key = self.key.next();
            self.ascending = true;
        }
    }

    /// Etiqueta visible con la dirección.
    pub fn label(&self) -> String {
        format!(
            "{} {}",
            self.key.label(),
            if self.ascending { "↑" } else { "↓" }
        )
    }
}

/// Filtro activo de la tabla de conexiones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionFilter {
    /// Todas las conexiones.
    Todas,
    /// Solo un protocolo de transporte.
    Protocolo(Protocol),
    /// Solo un estado TCP concreto.
    Estado(&'static str),
    /// Solo las conexiones del dispositivo indicado.
    Dispositivo(i64),
    /// Solo las conexiones del proceso local indicado (pid y nombre).
    Proceso {
        /// PID del socket local, si se conoce.
        pid: Option<u32>,
        /// Nombre del proceso local (vacío si solo se conoce el pid).
        comm: String,
    },
}

impl ConnectionFilter {
    /// Etiqueta visible del filtro (resuelve el nombre del dispositivo).
    pub fn label(&self, app: &App) -> String {
        match self {
            Self::Todas => "todas".to_string(),
            Self::Protocolo(protocolo) => protocolo.label().to_lowercase(),
            Self::Estado(estado) => estado.to_lowercase(),
            Self::Dispositivo(id) => app
                .devices
                .iter()
                .find(|device| device.id == *id)
                .map(|device| device.display_name().to_string())
                .unwrap_or_else(|| format!("equipo {id}")),
            Self::Proceso { pid, comm } => {
                let nombre = if comm.trim().is_empty() {
                    "desconocido".to_string()
                } else {
                    comm.clone()
                };
                match pid {
                    Some(pid) => format!("proceso {nombre} ({pid})"),
                    None => format!("proceso {nombre}"),
                }
            }
        }
    }
}

/// Estado del panel de detalle de un equipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailState {
    /// Id del equipo en SQLite.
    pub device_id: i64,
    /// Servicios de F2 del equipo (DEVICE_SERVICES).
    pub services: Vec<DeviceService>,
}

/// Panel inferior no modal con las cabeceras IP/TCP de una conexión.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersView {
    /// Conexión de la que se muestran las cabeceras.
    pub connection: ConnectionView,
}

/// Estado del panel «¿Quién lo usa?» de la pestaña Tráfico.
#[derive(Debug, Clone, PartialEq)]
pub struct WhoUsesState {
    /// Dimensión del ranking consultado.
    pub dimension: Dimension,
    /// Clave de la fila del ranking (destino, app, categoría o protocolo).
    pub key: String,
    /// Texto visible de la fila.
    pub label: String,
    /// Ventana consultada.
    pub window: Window,
    /// Equipos que usan la clave, con bytes y porcentaje.
    pub rows: Vec<DeviceShare>,
    /// Fila seleccionada dentro del panel.
    pub selected: usize,
    /// La petición está en curso («Consultando…»).
    pub pending: bool,
}

/// Lado cliente/servidor deducido del rol de una conexión (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSides {
    /// El extremo origen canónico es el cliente.
    ClienteOrigen,
    /// El extremo destino canónico es el cliente.
    ClienteDestino,
    /// No se pudo deducir el rol: se usa el orden canónico y se marca «?».
    Desconocido,
}

impl ConnectionSides {
    /// Indica si la fila se pinta sin rol deducido.
    pub fn sin_rol(self) -> bool {
        matches!(self, Self::Desconocido)
    }
}

/// Deduce los lados cliente/servidor de una conexión a partir de su etiqueta.
///
/// Devuelve el rol y los extremos (cliente, servidor). Sin rol se mantiene el
/// orden canónico (origen → destino) y se marca [ConnectionSides::Desconocido]
/// para que la vista ponga «?» delante del destino.
pub fn lados_conexion(conexion: &ConnectionView) -> (ConnectionSides, EndpointView, EndpointView) {
    match conexion
        .label
        .as_ref()
        .and_then(|etiqueta| etiqueta.client_is_src)
    {
        Some(true) => (
            ConnectionSides::ClienteOrigen,
            conexion.origin.clone(),
            conexion.destination.clone(),
        ),
        Some(false) => (
            ConnectionSides::ClienteDestino,
            conexion.destination.clone(),
            conexion.origin.clone(),
        ),
        None => (
            ConnectionSides::Desconocido,
            conexion.origin.clone(),
            conexion.destination.clone(),
        ),
    }
}

/// Bytes de subida (cliente → servidor) y de bajada (servidor → cliente).
///
/// F3 orientaba las columnas al extremo origen canónico; con el rol de F4 la
/// subida es siempre el sentido cliente → servidor.
pub fn bytes_orientados(conexion: &ConnectionView) -> (u64, u64) {
    match lados_conexion(conexion).0 {
        ConnectionSides::ClienteOrigen | ConnectionSides::Desconocido => {
            (conexion.bytes_out, conexion.bytes_in)
        }
        ConnectionSides::ClienteDestino => (conexion.bytes_in, conexion.bytes_out),
    }
}

/// Convierte la agrupación persistida de [ui].traffic_group en una dimensión.
pub fn dimension_de_grupo(grupo: TrafficGroup) -> Dimension {
    match grupo {
        TrafficGroup::Device => Dimension::Device,
        TrafficGroup::Destination => Dimension::Destination,
        TrafficGroup::App => Dimension::App,
        TrafficGroup::Category => Dimension::Category,
        TrafficGroup::Protocol => Dimension::Protocol,
        TrafficGroup::Process => Dimension::Process,
    }
}

/// Convierte una dimensión del ranking en la agrupación persistida.
pub fn grupo_de_dimension(dimension: Dimension) -> TrafficGroup {
    match dimension {
        Dimension::Device => TrafficGroup::Device,
        Dimension::Destination => TrafficGroup::Destination,
        Dimension::App => TrafficGroup::App,
        Dimension::Category => TrafficGroup::Category,
        Dimension::Protocol => TrafficGroup::Protocol,
        Dimension::Process => TrafficGroup::Process,
    }
}

/// Reordena las filas de un ranking según el criterio de «s».
///
/// Las filas llegan del agregador ordenadas por total; la TUI reordena la copia
/// recibida sin pedir otro cálculo. Los empates se resuelven por etiqueta para
/// que el orden sea estable entre refrescos.
pub fn ordenar_ranking(filas: &mut [RankRow], clave: SortKey) {
    filas.sort_by(|a, b| {
        let orden = match clave {
            SortKey::Down => b.bytes_down.cmp(&a.bytes_down),
            SortKey::Up => b.bytes_up.cmp(&a.bytes_up),
            SortKey::Total => b.total().cmp(&a.total()),
            SortKey::Devices => b.devices.cmp(&a.devices),
        };
        orden.then_with(|| a.label.cmp(&b.label))
    });
}

/// Estado en memoria del tráfico en vivo y las conexiones.
#[derive(Debug, Clone)]
pub struct TrafficState {
    /// Estado de la captura.
    pub capture: CaptureStatus,
    /// Agregado por dispositivo actualizado cada segundo.
    pub devices: Vec<DeviceTraffic>,
    /// Tráfico propio del host (device_id = crate::traffic::DEVICE_ID_HOST).
    pub host: DeviceTraffic,
    /// Agregado global actualizado cada segundo.
    pub global: GlobalTraffic,
    /// Conexiones activas.
    pub connections: Vec<ConnectionView>,
    /// Número total de conexiones en la caché antes de filtrar.
    pub connections_total: usize,
    /// Momento de la última actualización recibida.
    pub updated_at: Option<Instant>,
    /// Semilla inicial leída de TRAFFIC_SNAPSHOT al arrancar.
    pub seed: Vec<TrafficSnapshot>,
    /// Top 50 por dimensión y ventana publicados por el agregador (6 × 3).
    pub rankings: Vec<crate::traffic::RankingView>,
    /// Porcentaje de bytes sin identificar por ventana [60 s, 5 min, sesión].
    pub unidentified: [f32; 3],
    /// Top apps y destinos por equipo (ventana de 5 min) para el detalle.
    pub device_rankings: Vec<DeviceRankingView>,
    /// Panel «¿Quién lo usa?» abierto.
    pub who_uses: Option<WhoUsesState>,
    /// Entradas de NAME_CACHE pendientes de persistir en el ciclo de 5 s.
    pub pending_names: Vec<crate::inference::names::NameEntry>,
}

impl Default for TrafficState {
    fn default() -> Self {
        Self {
            capture: CaptureStatus::default(),
            devices: Vec::new(),
            host: dispositivo_vacio(crate::traffic::DEVICE_ID_HOST),
            global: GlobalTraffic {
                bytes_in: 0,
                bytes_out: 0,
                broadcast_bytes: 0,
                packets_total: 0,
            },
            connections: Vec::new(),
            connections_total: 0,
            updated_at: None,
            seed: Vec::new(),
            rankings: Vec::new(),
            unidentified: [0.0; 3],
            device_rankings: Vec::new(),
            who_uses: None,
            pending_names: Vec::new(),
        }
    }
}

/// DeviceTraffic a cero (host y valores por defecto).
fn dispositivo_vacio(device_id: i64) -> DeviceTraffic {
    DeviceTraffic {
        device_id,
        bytes_in: 0,
        bytes_out: 0,
        packets_in: 0,
        packets_out: 0,
        rate_in: 0,
        rate_out: 0,
        peak_bps: 0,
        series_60s_in: [0; 60],
        series_60s_out: [0; 60],
        series_5min_in: [0; 60],
        series_5min_out: [0; 60],
        top_ports: Vec::new(),
    }
}

/// Indica si un dispositivo tiene actividad observable.
fn tiene_actividad(estadisticas: &DeviceTraffic) -> bool {
    estadisticas.bytes_in > 0
        || estadisticas.bytes_out > 0
        || estadisticas.packets_in > 0
        || estadisticas.packets_out > 0
        || estadisticas.series_60s_in.iter().any(|valor| *valor > 0)
        || estadisticas.series_60s_out.iter().any(|valor| *valor > 0)
}

impl TrafficState {
    /// Indica si ya ha llegado al menos una actualización en vivo.
    pub fn has_live_data(&self) -> bool {
        self.updated_at.is_some()
    }

    /// Indica si hay semilla persistida de una ejecución anterior.
    pub fn has_seed(&self) -> bool {
        !self.seed.is_empty()
    }

    /// Etiqueta del momento de la semilla (updated_at más reciente).
    pub fn seed_label(&self) -> Option<String> {
        let mut ultima: Option<&str> = None;
        for snapshot in &self.seed {
            if ultima
                .map(|actual| snapshot.updated_at.as_str() > actual)
                .unwrap_or(true)
            {
                ultima = Some(snapshot.updated_at.as_str());
            }
        }
        ultima.map(str::to_string)
    }

    /// Estadísticas de un dispositivo: en vivo o semilla a cero.
    pub fn device_stats(&self, device_id: i64) -> Option<DeviceTraffic> {
        if let Some(estadisticas) = self
            .devices
            .iter()
            .find(|estadisticas| estadisticas.device_id == device_id)
        {
            return Some(estadisticas.clone());
        }
        let semilla = self
            .seed
            .iter()
            .find(|snapshot| snapshot.device_id == device_id)?;
        Some(DeviceTraffic {
            device_id,
            bytes_in: semilla.bytes_in.max(0) as u64,
            bytes_out: semilla.bytes_out.max(0) as u64,
            packets_in: semilla.packets_in.max(0) as u64,
            packets_out: semilla.packets_out.max(0) as u64,
            rate_in: 0,
            rate_out: 0,
            peak_bps: semilla.peak_bps.max(0) as u64,
            series_60s_in: [0; 60],
            series_60s_out: [0; 60],
            series_5min_in: [0; 60],
            series_5min_out: [0; 60],
            top_ports: Vec::new(),
        })
    }

    /// Ranking de dispositivos ordenado por consumo total en la ventana de 60 s.
    ///
    /// Solo incluye filas con actividad (no una tabla de ceros) y añade el
    /// tráfico propio del host como fila [host] cuando lo hay: en red conmutada
    /// es la mayor parte de lo observable y no pertenece a ningún equipo del
    /// inventario.
    pub fn ranked_devices(&self) -> Vec<DeviceTraffic> {
        let mut filas: Vec<DeviceTraffic> = if self.devices.is_empty() {
            let mut semilla = Vec::new();
            for snapshot in &self.seed {
                if let Some(estadisticas) = self.device_stats(snapshot.device_id) {
                    if tiene_actividad(&estadisticas) {
                        semilla.push(estadisticas);
                    }
                }
            }
            semilla
        } else {
            self.devices
                .iter()
                .filter(|estadisticas| tiene_actividad(estadisticas))
                .cloned()
                .collect()
        };
        if tiene_actividad(&self.host) {
            filas.push(self.host.clone());
        }
        filas.sort_by(|a, b| {
            let total_a = a.bytes_in.saturating_add(a.bytes_out);
            let total_b = b.bytes_in.saturating_add(b.bytes_out);
            total_b.cmp(&total_a)
        });
        filas
    }

    /// Ritmos globales (bytes/s) del último segundo, sumando dispositivos y host.
    pub fn global_rates(&self) -> (u64, u64) {
        let mut entrada = self.host.rate_in;
        let mut salida = self.host.rate_out;
        for estadisticas in &self.devices {
            entrada = entrada.saturating_add(estadisticas.rate_in);
            salida = salida.saturating_add(estadisticas.rate_out);
        }
        (entrada, salida)
    }

    /// Bytes de difusión/multidifusión observados desde el arranque.
    pub fn broadcast_bytes(&self) -> u64 {
        self.global.broadcast_bytes
    }

    /// Conexiones activas en las que participa la IP de un equipo.
    pub fn connections_of_ip(&self, ip: &str) -> Vec<&ConnectionView> {
        let Ok(direccion) = ip.parse::<std::net::IpAddr>() else {
            return Vec::new();
        };
        let mut conexiones: Vec<&ConnectionView> = self
            .connections
            .iter()
            .filter(|conexion| {
                conexion.origin.ip == direccion || conexion.destination.ip == direccion
            })
            .collect();
        conexiones.sort_by_key(|conexion| {
            std::cmp::Reverse(conexion.bytes_in.saturating_add(conexion.bytes_out))
        });
        conexiones
    }

    /// Filas publicadas de una dimensión y ventana (copia, sin reordenar).
    pub fn rank_rows(&self, dimension: Dimension, window: Window) -> Vec<RankRow> {
        self.rankings
            .iter()
            .find(|vista| vista.dimension == dimension && vista.window == window)
            .map(|vista| vista.rows.clone())
            .unwrap_or_default()
    }

    /// Porcentaje de bytes sin identificar de una ventana (0-100).
    pub fn unidentified_pct(&self, window: Window) -> f32 {
        self.unidentified
            .get(window.index())
            .copied()
            .unwrap_or(0.0)
    }

    /// Top apps y destinos de un equipo (ventana de 5 min) para el detalle.
    pub fn device_ranking(&self, device_id: i64) -> Option<&DeviceRankingView> {
        self.device_rankings
            .iter()
            .find(|ranking| ranking.device_id == device_id)
    }
}

impl App {
    /// Indica si el panel de detalle de equipo está abierto.
    pub fn detail_open(&self) -> bool {
        self.detail.is_some()
    }

    /// Abre el detalle de un equipo con sus servicios de F2.
    pub fn open_detail(
        &mut self,
        device_id: i64,
        services: Vec<DeviceService>,
        focus_detail: bool,
    ) {
        self.detail = Some(DetailState {
            device_id,
            services,
        });
        self.detail_focus = if focus_detail {
            FocusPanel::Detalle
        } else {
            FocusPanel::Lista
        };
        self.detail_scroll = 0;
        self.detail_max_scroll = 0;
    }

    /// Cierra el panel de detalle.
    pub fn close_detail(&mut self) {
        self.detail = None;
        self.detail_focus = FocusPanel::Lista;
        self.detail_scroll = 0;
        self.detail_max_scroll = 0;
    }

    /// Alterna el foco entre la lista y el detalle.
    pub fn toggle_detail_focus(&mut self) {
        if self.detail.is_some() {
            self.detail_focus = self.detail_focus.toggled();
        }
    }

    /// Equipo del panel de detalle.
    pub fn detail_device(&self) -> Option<&crate::repo::devices::Device> {
        let detalle = self.detail.as_ref()?;
        self.devices
            .iter()
            .find(|device| device.id == detalle.device_id)
    }

    /// Servicios de F2 del equipo abierto en el detalle.
    pub fn detail_services(&self) -> &[DeviceService] {
        self.detail
            .as_ref()
            .map(|detalle| detalle.services.as_slice())
            .unwrap_or(&[])
    }

    /// Aplica una actualización de tráfico recibida por el bus de eventos.
    pub fn apply_traffic(&mut self, update: TrafficUpdate) {
        self.traffic.capture = update.capture;
        self.traffic.devices = update.devices;
        self.traffic.host = update.host;
        self.traffic.global = update.global;
        self.traffic.connections = update.connections;
        self.traffic.connections_total = update.connections_total;
        self.traffic.rankings = update.rankings;
        self.traffic.unidentified = update.unidentified;
        self.traffic.device_rankings = update.device_rankings;
        self.traffic.pending_names.extend(update.names);
        self.traffic.updated_at = Some(Instant::now());
        // Las cifras del catálogo y de las bases IP se actualizan cada segundo;
        // main.rs las siembra al arrancar.
        self.catalog_counts = update.catalog;
        self.ipdb_date = update.ipdb_date;
        self.clamp_connection_selection();
        self.clamp_traffic_selection();
    }

    /// Guarda la semilla de TRAFFIC_SNAPSHOT leída al arrancar.
    pub fn set_traffic_seed(&mut self, snapshots: Vec<TrafficSnapshot>) {
        self.traffic.seed = snapshots;
    }

    /// Ranking de la pestaña Tráfico con la agrupación, ventana y orden activos.
    ///
    /// Usa las filas publicadas por el agregador. Para la agrupación por equipo,
    /// si el ranking aún no ha publicado filas se sintetiza con el agregado de
    /// F3 (comportamiento de la Fase 3 y arranque en frío).
    pub fn ranking_rows(&self) -> Vec<RankRow> {
        let mut filas = self
            .traffic
            .rank_rows(self.traffic_group, self.traffic_window);
        if filas.is_empty() && self.traffic_group == Dimension::Device {
            filas = self.filas_equipo_fase3();
        }
        ordenar_ranking(&mut filas, self.rank_sort);
        filas
    }

    /// Filas de equipo sintetizadas desde el agregado de F3 (respaldo).
    fn filas_equipo_fase3(&self) -> Vec<RankRow> {
        self.traffic
            .ranked_devices()
            .into_iter()
            .map(|estadisticas| {
                let device_id = estadisticas.device_id;
                let label = if device_id == crate::traffic::DEVICE_ID_HOST {
                    "[host]".to_string()
                } else {
                    self.devices
                        .iter()
                        .find(|device| device.id == device_id)
                        .map(|device| device.display_name().to_string())
                        .unwrap_or_else(|| format!("equipo {device_id}"))
                };
                let serie = std::array::from_fn(|punto| {
                    estadisticas.series_60s_in[punto]
                        .saturating_add(estadisticas.series_60s_out[punto])
                });
                RankRow {
                    key: device_id.to_string(),
                    label,
                    subtitle: None,
                    device_id: Some(device_id),
                    bytes_down: estadisticas.bytes_in,
                    bytes_up: estadisticas.bytes_out,
                    devices: 1,
                    connections: 0,
                    series_60s: serie,
                }
            })
            .collect()
    }

    /// Mueve la selección del ranking de tráfico.
    pub fn move_traffic_selection(&mut self, delta: isize) {
        let total = self.ranking_rows().len();
        if total == 0 {
            self.traffic_selected = 0;
        } else {
            let actual = self.traffic_selected.min(total - 1) as isize;
            self.traffic_selected = (actual + delta).clamp(0, total as isize - 1) as usize;
        }
        *self.traffic_table_state.selected_mut() = Some(self.traffic_selected);
    }

    /// Fila seleccionada del ranking de tráfico.
    pub fn selected_ranking_row(&self) -> Option<RankRow> {
        self.ranking_rows().get(self.traffic_selected).cloned()
    }

    /// Ajusta la selección del ranking al número de filas visibles.
    pub fn clamp_traffic_selection(&mut self) {
        let total = self.ranking_rows().len();
        if total == 0 {
            self.traffic_selected = 0;
        } else if self.traffic_selected >= total {
            self.traffic_selected = total - 1;
        }
    }

    /// Cicla la agrupación del ranking (g) y devuelve la preferencia a persistir.
    pub fn cycle_traffic_group(&mut self) -> Option<TrafficGroup> {
        let siguiente = self.traffic_group.index() + 1;
        self.traffic_group = Dimension::ALL[siguiente % Dimension::ALL.len()];
        self.traffic_selected = 0;
        self.traffic.who_uses = None;
        self.clamp_traffic_selection();
        let grupo = grupo_de_dimension(self.traffic_group);
        self.config.ui.traffic_group = grupo;
        self.push_notification(
            crate::notifier::Level::Info,
            format!(
                "Ranking por {} ([g] para cambiar)",
                self.traffic_group.label()
            ),
        );
        Some(grupo)
    }

    /// Cicla la ventana del ranking (w): 60 s → 5 min → sesión. No se persiste.
    pub fn cycle_traffic_window(&mut self) {
        let siguiente = self.traffic_window.index() + 1;
        self.traffic_window = Window::ALL[siguiente % Window::ALL.len()];
        self.traffic_selected = 0;
        self.traffic.who_uses = None;
        self.clamp_traffic_selection();
        self.push_notification(
            crate::notifier::Level::Info,
            format!("Ventana: {}", self.traffic_window.label()),
        );
    }

    /// Cicla el criterio de orden del ranking (s).
    pub fn cycle_ranking_sort(&mut self) {
        self.rank_sort = self.rank_sort.next();
        self.traffic_selected = 0;
        self.clamp_traffic_selection();
        self.push_notification(
            crate::notifier::Level::Info,
            format!("Orden del ranking: {}", self.rank_sort.label()),
        );
    }

    /// Abre el panel «¿Quién lo usa?» de la fila seleccionada.
    ///
    /// Devuelve la petición que el bucle debe enviar con
    /// [crate::events::TrafficCommand::WhoUses]; el panel queda en «Consultando…»
    /// hasta que llegue la respuesta.
    pub fn open_who_uses(&mut self) -> Option<(Dimension, String, String, Window)> {
        let Some(fila) = self.selected_ranking_row() else {
            self.push_notification(
                crate::notifier::Level::Info,
                "No hay ninguna fila seleccionada en el ranking",
            );
            return None;
        };
        if !matches!(
            self.traffic_group,
            Dimension::Destination | Dimension::App | Dimension::Category | Dimension::Protocol
        ) {
            return None;
        }
        let dimension = self.traffic_group;
        let window = self.traffic_window;
        self.traffic.who_uses = Some(WhoUsesState {
            dimension,
            key: fila.key.clone(),
            label: fila.label.clone(),
            window,
            rows: Vec::new(),
            selected: 0,
            pending: true,
        });
        Some((dimension, fila.key, fila.label, window))
    }

    /// Rellena el panel «¿Quién lo usa?» con la respuesta del agregador.
    pub fn set_who_uses(&mut self, rows: Vec<DeviceShare>) {
        if let Some(panel) = self.traffic.who_uses.as_mut() {
            panel.rows = rows;
            panel.selected = 0;
            panel.pending = false;
        }
    }

    /// Cierra el panel «¿Quién lo usa?»; devuelve true si estaba abierto.
    pub fn close_who_uses(&mut self) -> bool {
        self.traffic.who_uses.take().is_some()
    }

    /// Indica si el panel «¿Quién lo usa?» está abierto.
    pub fn who_uses_open(&self) -> bool {
        self.traffic.who_uses.is_some()
    }

    /// Fila seleccionada del panel «¿Quién lo usa?».
    pub fn selected_who_uses(&self) -> Option<DeviceShare> {
        let panel = self.traffic.who_uses.as_ref()?;
        panel.rows.get(panel.selected).cloned()
    }

    /// Mueve la selección del panel «¿Quién lo usa?».
    pub fn move_who_uses_selection(&mut self, delta: isize) {
        let Some(panel) = self.traffic.who_uses.as_mut() else {
            return;
        };
        let total = panel.rows.len();
        if total == 0 {
            panel.selected = 0;
        } else {
            let actual = panel.selected.min(total - 1) as isize;
            panel.selected = (actual + delta).clamp(0, total as isize - 1) as usize;
        }
    }

    /// Duración de la sesión (para la ventana «sesión» del ranking).
    pub fn session_elapsed(&self) -> Duration {
        self.session_started.elapsed()
    }

    /// Media de bytes por segundo de un total en una ventana.
    ///
    /// Las columnas ↓/↑ de los rankings muestran la media de la ventana (la
    /// ventana de sesión se divide entre el tiempo transcurrido desde el
    /// arranque); nunca divide entre cero.
    pub fn bytes_por_segundo_en_ventana(&self, bytes: u64, window: Window) -> u64 {
        let segundos = match window {
            Window::Sixty => 60,
            Window::FiveMin => 300,
            Window::Session => self.session_elapsed().as_secs().max(1),
        };
        bytes / segundos.max(1)
    }

    /// Abre las Conexiones filtradas por el proceso de la fila seleccionada.
    ///
    /// El ranking de proceso usa el pid como clave; si la clave no es numérica se
    /// intenta con el nombre visible. Devuelve false si no se puede identificar.
    pub fn filtrar_conexiones_por_proceso(&mut self) -> bool {
        let Some(fila) = self.selected_ranking_row() else {
            self.push_notification(
                crate::notifier::Level::Info,
                "No hay ningún proceso seleccionado",
            );
            return false;
        };
        let pid = fila.key.trim().parse::<u32>().ok();
        let comm = fila
            .label
            .split(['(', ' ', ')'])
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if pid.is_none() && comm.is_empty() {
            self.push_notification(
                crate::notifier::Level::Info,
                "No se pudo identificar el proceso de la fila",
            );
            return false;
        }
        self.conn_filter = ConnectionFilter::Proceso { pid, comm };
        self.conn_selected = 0;
        self.clamp_connection_selection();
        self.tab = crate::tui::app::Tab::Conexiones;
        true
    }

    /// Conexiones visibles según el filtro activo, ya ordenadas.
    pub fn filtered_connections(&self) -> Vec<&ConnectionView> {
        let mut visibles: Vec<&ConnectionView> = self
            .traffic
            .connections
            .iter()
            .filter(|conexion| self.connection_matches(conexion))
            .collect();
        let clave = self.conn_sort.key;
        let ascendente = self.conn_sort.ascending;
        visibles.sort_by(|a, b| {
            let orden = comparar_conexiones(a, b, clave);
            if ascendente {
                orden
            } else {
                orden.reverse()
            }
        });
        visibles
    }

    fn connection_matches(&self, conexion: &ConnectionView) -> bool {
        let pasa_filtro = match &self.conn_filter {
            ConnectionFilter::Todas => true,
            ConnectionFilter::Protocolo(protocolo) => {
                conexion.protocol() == *protocolo
                    || (*protocolo == Protocol::Icmp && conexion.protocol() == Protocol::Icmpv6)
            }
            ConnectionFilter::Estado(estado) => conexion
                .state
                .as_deref()
                .map(|actual| actual.eq_ignore_ascii_case(estado))
                .unwrap_or(false),
            ConnectionFilter::Dispositivo(id) => {
                conexion.device_id == Some(*id)
                    || conexion.origin.device_id == Some(*id)
                    || conexion.destination.device_id == Some(*id)
            }
            ConnectionFilter::Proceso { pid, comm } => match pid {
                Some(pid) => conexion.pid == Some(*pid),
                None => conexion
                    .comm
                    .as_deref()
                    .map(|actual| actual.eq_ignore_ascii_case(comm))
                    .unwrap_or(false),
            },
        };
        if !pasa_filtro {
            return false;
        }
        let consulta = self.effective_conn_search().trim().to_lowercase();
        if consulta.is_empty() {
            return true;
        }
        self.conexion_coincide_busqueda(conexion, &consulta)
    }

    /// Campos de una conexión que participan en la búsqueda de la pestaña
    /// Conexiones: extremos, protocolo, estado, servidor, app, categoría,
    /// proceso local y nombre de los equipos atribuidos.
    fn conexion_coincide_busqueda(&self, conexion: &ConnectionView, consulta: &str) -> bool {
        let mut campos: Vec<String> = vec![
            conexion.protocol().as_str().to_lowercase(),
            conexion.app_protocol_label().to_lowercase(),
            conexion.state_label().to_lowercase(),
            conexion.origin.ip.to_string().to_lowercase(),
            conexion.destination.ip.to_string().to_lowercase(),
            conexion.app_label().to_lowercase(),
            conexion.category_label().to_lowercase(),
        ];
        if let Some(etiqueta) = &conexion.label {
            if let Some(nombre) = &etiqueta.server_name {
                campos.push(nombre.to_lowercase());
            }
            campos.push(etiqueta.destination.label.to_lowercase());
            campos.push(etiqueta.destination.subtitle().to_lowercase());
        }
        if let Some(proceso) = conexion.process_label() {
            campos.push(proceso.to_lowercase());
        }
        if let Some(comm) = &conexion.comm {
            campos.push(comm.to_lowercase());
        }
        for id in [conexion.origin.device_id, conexion.destination.device_id]
            .into_iter()
            .flatten()
        {
            if let Some(device) = self.devices.iter().find(|device| device.id == id) {
                campos.push(device.display_name().to_lowercase());
            }
        }
        campos.iter().any(|campo| campo.contains(consulta))
    }

    /// Mueve la selección de la tabla de conexiones.
    pub fn move_connection_selection(&mut self, delta: isize) {
        let total = self.filtered_connections().len();
        if total == 0 {
            self.conn_selected = 0;
        } else {
            let actual = self.conn_selected.min(total - 1) as isize;
            self.conn_selected = (actual + delta).clamp(0, total as isize - 1) as usize;
        }
        *self.conn_table_state.selected_mut() = Some(self.conn_selected);
    }

    /// Ajusta la selección de conexiones al número de filas visibles.
    pub fn clamp_connection_selection(&mut self) {
        let total = self.filtered_connections().len();
        if total == 0 {
            self.conn_selected = 0;
        } else if self.conn_selected >= total {
            self.conn_selected = total - 1;
        }
        *self.conn_table_state.selected_mut() = Some(self.conn_selected);
    }

    /// Conexión seleccionada en la pestaña Conexiones.
    pub fn selected_connection(&self) -> Option<&ConnectionView> {
        self.filtered_connections().get(self.conn_selected).copied()
    }

    /// Cicla la ordenación de la tabla de conexiones.
    pub fn cycle_connection_sort(&mut self) {
        self.conn_sort.cycle();
        self.conn_selected = 0;
        self.clamp_connection_selection();
    }

    /// Cicla el filtro de la tabla de conexiones.
    pub fn cycle_connection_filter(&mut self) {
        let mut opciones: Vec<ConnectionFilter> = vec![
            ConnectionFilter::Todas,
            ConnectionFilter::Protocolo(Protocol::Tcp),
            ConnectionFilter::Protocolo(Protocol::Udp),
            ConnectionFilter::Protocolo(Protocol::Icmp),
            ConnectionFilter::Estado("ESTABLISHED"),
            ConnectionFilter::Estado("TIME_WAIT"),
            ConnectionFilter::Estado("CLOSE_WAIT"),
        ];
        let mut dispositivos: Vec<i64> = self
            .traffic
            .connections
            .iter()
            .filter_map(|conexion| conexion.device_id)
            .collect();
        dispositivos.sort_unstable();
        dispositivos.dedup();
        for id in dispositivos {
            opciones.push(ConnectionFilter::Dispositivo(id));
        }
        // Un filtro por proceso (puesto desde Tráfico) no está en el ciclo:
        // la primera pulsación de f lo quita y vuelve a «todas».
        match opciones
            .iter()
            .position(|opcion| *opcion == self.conn_filter)
        {
            Some(actual) => self.conn_filter = opciones[(actual + 1) % opciones.len()].clone(),
            None => self.conn_filter = ConnectionFilter::Todas,
        }
        self.conn_selected = 0;
        self.clamp_connection_selection();
    }

    /// Etiqueta visible del filtro de conexiones.
    pub fn connection_filter_label(&self) -> String {
        self.conn_filter.label(self)
    }

    /// Texto de la búsqueda efectiva de conexiones (incluye la edición en curso).
    pub fn effective_conn_search(&self) -> &str {
        match &self.input {
            Some(input) if input.mode == crate::tui::app::InputMode::ConnectionSearch => {
                &input.buffer
            }
            _ => &self.conn_search,
        }
    }

    /// Limpia la búsqueda confirmada de conexiones.
    pub fn clear_connection_search(&mut self) {
        self.conn_search.clear();
        self.conn_selected = 0;
        self.clamp_connection_selection();
    }

    /// Alterna la vista de nombres ⇄ IPs de la pestaña Conexiones (tecla i).
    ///
    /// No se persiste: cada arranque empieza mostrando nombres.
    pub fn toggle_connection_names(&mut self) {
        self.show_names = !self.show_names;
        let vista = if self.show_names { "nombres" } else { "IPs" };
        self.push_notification(
            crate::notifier::Level::Info,
            format!("Vista de Conexiones: {vista} ([i] para alternar)"),
        );
    }

    /// Abre el panel de cabeceras de la conexión seleccionada.
    pub fn open_headers(&mut self) -> bool {
        let Some(conexion) = self.selected_connection().cloned() else {
            self.push_notification(
                crate::notifier::Level::Info,
                "No hay ninguna conexión seleccionada",
            );
            return false;
        };
        self.headers = Some(HeadersView {
            connection: conexion,
        });
        true
    }

    /// Cierra el panel de cabeceras; devuelve true si estaba abierto.
    pub fn close_headers(&mut self) -> bool {
        self.headers.take().is_some()
    }

    /// Indica si el panel de cabeceras está abierto.
    pub fn headers_open(&self) -> bool {
        self.headers.is_some()
    }

    /// Indica si procede persistir el tráfico (cada 5 s).
    pub fn should_persist_traffic(&mut self) -> bool {
        let debe = self
            .last_traffic_persist
            .map(|ultimo| ultimo.elapsed() >= std::time::Duration::from_secs(5))
            .unwrap_or(true);
        if debe {
            self.last_traffic_persist = Some(Instant::now());
        }
        debe
    }

    /// Texto de la línea de captura para la barra de estado.
    pub fn capture_status_line(&self) -> String {
        self.traffic.capture.summary()
    }

    /// Texto de la visibilidad honesta de la red conmutada.
    pub fn visibility_line(&self) -> &'static str {
        CaptureStatus::visibility_label()
    }
}

/// Compara dos conexiones por la columna indicada (orden ascendente base).
pub fn comparar_conexiones(
    a: &ConnectionView,
    b: &ConnectionView,
    clave: ConnectionSortKey,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match clave {
        ConnectionSortKey::Protocolo => a.protocol().as_str().cmp(b.protocol().as_str()),
        ConnectionSortKey::Origen => {
            (a.origin.ip, a.origin.port).cmp(&(b.origin.ip, b.origin.port))
        }
        ConnectionSortKey::Destino => {
            (a.destination.ip, a.destination.port).cmp(&(b.destination.ip, b.destination.port))
        }
        ConnectionSortKey::Estado => a.state_label().cmp(b.state_label()),
        ConnectionSortKey::Enviado => a.bytes_out.cmp(&b.bytes_out),
        ConnectionSortKey::Recibido => a.bytes_in.cmp(&b.bytes_in),
        ConnectionSortKey::Edad => {
            let orden = a.age.cmp(&b.age);
            match orden {
                Ordering::Equal => Ordering::Equal,
                otro => otro,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::aggregate::DeviceTraffic;
    use crate::capture::{ConnectionKey, Endpoint, Protocol as CaptureProtocol};
    use crate::config::{Config, TrafficGroup};
    use crate::inference::{FlowLabel, NameSource};
    use crate::rankings::{DeviceShare, Dimension, RankRow, SortKey, Window};
    use crate::repo::devices::Device;
    use crate::traffic::{DeviceRankingView, EndpointView, RankingView, TrafficUpdate};
    use crate::tui::app::{Action, App, InputMode, Tab};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba")
    }

    fn dispositivo(id: i64, ip_texto: &str) -> Device {
        Device {
            id,
            mac: format!("aa:bb:cc:dd:ee:0{id}"),
            ip: ip_texto.to_string(),
            hostname: Some(format!("equipo-{id}")),
            vendor: None,
            interface_id: 1,
            device_type: "pc".to_string(),
            is_online: true,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
            alias: None,
            notes: None,
            os_family: None,
            device_type_manual: None,
            last_fingerprint: None,
            model: None,
            dhcp_fingerprint: None,
            dhcp_vendor: None,
            dhcp_hostname: None,
            user_agent: None,
            os_source: None,
        }
    }

    fn estadisticas(device_id: i64, bytes_in: u64) -> DeviceTraffic {
        DeviceTraffic {
            device_id,
            bytes_in,
            bytes_out: bytes_in / 2,
            packets_in: 1,
            packets_out: 1,
            rate_in: 1,
            rate_out: 1,
            peak_bps: bytes_in,
            series_60s_in: [0; 60],
            series_60s_out: [0; 60],
            series_5min_in: [0; 60],
            series_5min_out: [0; 60],
            top_ports: Vec::new(),
        }
    }

    fn conexion(device_id: Option<i64>, estado: &str) -> ConnectionView {
        ConnectionView {
            key: ConnectionKey::from_endpoints(
                CaptureProtocol::Tcp,
                Endpoint::new(ip("192.168.1.42"), Some(40000)),
                Endpoint::new(ip("1.1.1.1"), Some(443)),
            ),
            state: Some(estado.to_string()),
            bytes_in: 100,
            bytes_out: 50,
            age: Duration::from_secs(10),
            idle: Duration::from_secs(1),
            pid: None,
            comm: None,
            device_id,
            origin: EndpointView {
                ip: ip("192.168.1.42"),
                port: Some(40000),
                device_id,
                tag: None,
            },
            destination: EndpointView {
                ip: ip("1.1.1.1"),
                port: Some(443),
                device_id: None,
                tag: Some("?"),
            },
            headers: None,
            seen_capture: true,
            seen_kernel: false,
            label: None,
            app_name: None,
            category_name: None,
        }
    }

    fn app_prueba() -> App {
        let mut app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        );
        app.set_data(
            vec![
                dispositivo(1, "192.168.1.42"),
                dispositivo(2, "192.168.1.1"),
            ],
            Vec::new(),
        );
        app
    }

    fn tecla(codigo: KeyCode) -> KeyEvent {
        KeyEvent::new(codigo, KeyModifiers::NONE)
    }

    #[test]
    fn enter_en_trafico_hace_drill_down_al_detalle() {
        let mut app = app_prueba();
        app.traffic.devices = vec![estadisticas(2, 500_000), estadisticas(1, 1_000_000)];
        app.apply_traffic(TrafficUpdate {
            capture: CaptureStatus::default(),
            devices: app.traffic.devices.clone(),
            host: app.traffic.host.clone(),
            global: app.traffic.global,
            connections: Vec::new(),
            connections_total: 0,
            rankings: Vec::new(),
            unidentified: [0.0; 3],
            device_rankings: Vec::new(),
            names: Vec::new(),
            inference_enabled: true,
            catalog: Default::default(),
            ipdb_date: None,
        });
        app.tab = Tab::Trafico;
        // El ranking ordena por consumo: el primero es el equipo 1.
        assert_eq!(
            app.handle_key(tecla(KeyCode::Enter)),
            Action::OpenDetail { device_id: 1 }
        );
    }

    #[test]
    fn filtro_de_conexiones_por_dispositivo() {
        let mut app = app_prueba();
        app.traffic.connections = vec![
            conexion(Some(1), "ESTABLISHED"),
            conexion(None, "TIME_WAIT"),
        ];
        app.traffic.connections_total = 2;
        app.tab = Tab::Conexiones;
        assert_eq!(app.filtered_connections().len(), 2);
        // Cicla hasta llegar al filtro por dispositivo (tras los de protocolo y estado).
        for _ in 0..20 {
            app.cycle_connection_filter();
            if matches!(app.conn_filter, ConnectionFilter::Dispositivo(_)) {
                break;
            }
        }
        assert!(matches!(app.conn_filter, ConnectionFilter::Dispositivo(1)));
        assert_eq!(app.filtered_connections().len(), 1, "solo la del equipo 1");
        assert!(app.connection_filter_label().contains("equipo-1"));
    }

    #[test]
    fn seleccion_de_conexiones_respeta_limites() {
        let mut app = app_prueba();
        app.traffic.connections = vec![
            conexion(Some(1), "ESTABLISHED"),
            conexion(None, "TIME_WAIT"),
        ];
        app.traffic.connections_total = 2;
        app.tab = Tab::Conexiones;
        app.move_connection_selection(10);
        assert_eq!(app.conn_selected, 1);
        app.move_connection_selection(-10);
        assert_eq!(app.conn_selected, 0);
    }

    #[test]
    fn el_ranking_incluye_host_y_oculta_dispositivos_sin_trafico() {
        let mut app = app_prueba();
        let mut sin_trafico = estadisticas(2, 0);
        sin_trafico.packets_in = 0;
        sin_trafico.packets_out = 0;
        sin_trafico.rate_in = 0;
        sin_trafico.rate_out = 0;
        sin_trafico.peak_bps = 0;
        let mut host = estadisticas(crate::traffic::DEVICE_ID_HOST, 800);
        host.rate_in = 120;
        host.rate_out = 60;
        app.traffic.devices = vec![estadisticas(1, 400), sin_trafico];
        app.traffic.host = host;
        app.traffic.updated_at = Some(Instant::now());

        let ranking = app.traffic.ranked_devices();
        assert_eq!(ranking.len(), 2, "el equipo sin tráfico no aparece");
        assert_eq!(ranking[0].device_id, crate::traffic::DEVICE_ID_HOST);
        assert_eq!(ranking[1].device_id, 1);
        assert_eq!(app.traffic.global_rates(), (121, 61));
        assert!(app.traffic.broadcast_bytes() == 0);
    }

    #[test]
    fn enter_sobre_host_avisa_y_no_abre_detalle() {
        let mut app = app_prueba();
        let mut host = estadisticas(crate::traffic::DEVICE_ID_HOST, 800);
        host.rate_in = 120;
        host.rate_out = 60;
        app.traffic.host = host;
        app.traffic.updated_at = Some(Instant::now());
        app.tab = Tab::Trafico;
        assert_eq!(app.handle_key(tecla(KeyCode::Enter)), Action::None);
        assert!(!app.detail_open());
        assert!(app
            .notifier
            .current()
            .expect("aviso de host")
            .message
            .contains("host"));
    }

    #[test]
    fn apply_traffic_actualiza_estado_y_clampea() {
        let mut app = app_prueba();
        app.traffic_selected = 99;
        app.conn_selected = 99;
        app.apply_traffic(TrafficUpdate {
            capture: CaptureStatus {
                active: true,
                pps: 10,
                ..CaptureStatus::default()
            },
            devices: vec![estadisticas(1, 100)],
            host: app.traffic.host.clone(),
            global: app.traffic.global,
            connections: vec![conexion(Some(1), "ESTABLISHED")],
            connections_total: 1,
            rankings: Vec::new(),
            unidentified: [0.0; 3],
            device_rankings: Vec::new(),
            names: Vec::new(),
            inference_enabled: true,
            catalog: Default::default(),
            ipdb_date: None,
        });
        assert!(app.traffic.has_live_data());
        assert!(app.traffic.updated_at.is_some());
        assert_eq!(app.traffic_selected, 0);
        assert_eq!(app.conn_selected, 0);
    }

    fn fila_ranking(
        clave: &str,
        etiqueta: &str,
        bajada: u64,
        subida: u64,
        equipos: u32,
    ) -> RankRow {
        RankRow {
            key: clave.to_string(),
            label: etiqueta.to_string(),
            subtitle: None,
            device_id: None,
            bytes_down: bajada,
            bytes_up: subida,
            devices: equipos,
            connections: 1,
            series_60s: [0; 60],
        }
    }

    fn vista_ranking(dimension: Dimension, window: Window, rows: Vec<RankRow>) -> RankingView {
        RankingView {
            dimension,
            window,
            rows,
        }
    }

    fn etiqueta_con_rol(client_is_src: Option<bool>) -> FlowLabel {
        let mut etiqueta = FlowLabel::empty(ip("1.1.1.1"));
        etiqueta.client_is_src = client_is_src;
        etiqueta
    }

    #[test]
    fn el_ciclo_de_g_recorre_las_seis_agrupaciones_y_guarda_la_preferencia() {
        let mut app = app_prueba();
        assert_eq!(app.traffic_group, Dimension::Device);
        let mut vistos = Vec::new();
        for _ in 0..6 {
            vistos.push(app.cycle_traffic_group().expect("grupo persistido"));
        }
        assert_eq!(
            vistos,
            vec![
                TrafficGroup::Destination,
                TrafficGroup::App,
                TrafficGroup::Category,
                TrafficGroup::Protocol,
                TrafficGroup::Process,
                TrafficGroup::Device,
            ]
        );
        assert_eq!(app.traffic_group, Dimension::Device);
        assert_eq!(app.config.ui.traffic_group, TrafficGroup::Device);
        assert!(app.notifier.current().is_some(), "se avisa del cambio");
    }

    #[test]
    fn el_ciclo_de_w_no_se_persiste_y_arranca_en_sesenta_segundos() {
        let mut app = app_prueba();
        assert_eq!(app.traffic_window, Window::Sixty);
        app.cycle_traffic_window();
        assert_eq!(app.traffic_window, Window::FiveMin);
        app.cycle_traffic_window();
        assert_eq!(app.traffic_window, Window::Session);
        app.cycle_traffic_window();
        assert_eq!(app.traffic_window, Window::Sixty);
        // La agrupación persistida no cambia al cambiar la ventana.
        assert_eq!(app.config.ui.traffic_group, TrafficGroup::Device);
    }

    #[test]
    fn el_orden_del_ranking_reordena_las_filas_recibidas() {
        let mut app = app_prueba();
        app.traffic_group = Dimension::App;
        app.traffic.rankings = vec![vista_ranking(
            Dimension::App,
            Window::Sixty,
            vec![
                fila_ranking("youtube", "YouTube", 900, 10, 2),
                fila_ranking("netflix", "Netflix", 100, 500, 1),
            ],
        )];
        assert_eq!(app.ranking_rows()[0].key, "youtube");
        app.cycle_ranking_sort();
        assert_eq!(app.rank_sort, SortKey::Down);
        assert_eq!(app.ranking_rows()[0].key, "youtube");
        app.cycle_ranking_sort();
        assert_eq!(app.rank_sort, SortKey::Up);
        assert_eq!(app.ranking_rows()[0].key, "netflix");
        app.cycle_ranking_sort();
        assert_eq!(app.rank_sort, SortKey::Devices);
        assert_eq!(app.ranking_rows()[0].key, "youtube");
    }

    #[test]
    fn el_ranking_publicado_prevalece_sobre_el_respaldo_de_fase3() {
        let mut app = app_prueba();
        app.traffic.devices = vec![estadisticas(1, 1_000)];
        app.traffic.rankings = vec![vista_ranking(
            Dimension::Device,
            Window::Sixty,
            vec![RankRow {
                device_id: Some(2),
                key: "2".to_string(),
                label: "equipo-2".to_string(),
                subtitle: None,
                bytes_down: 2_000,
                bytes_up: 0,
                devices: 1,
                connections: 2,
                series_60s: [0; 60],
            }],
        )];
        let filas = app.ranking_rows();
        assert_eq!(filas.len(), 1);
        assert_eq!(filas[0].device_id, Some(2));
    }

    #[test]
    fn enter_en_app_devuelve_peticion_de_quien_lo_usa_y_esc_cierra_el_panel() {
        let mut app = app_prueba();
        app.tab = Tab::Trafico;
        app.traffic_group = Dimension::App;
        app.traffic.rankings = vec![vista_ranking(
            Dimension::App,
            Window::Sixty,
            vec![fila_ranking("youtube", "YouTube", 900, 10, 2)],
        )];
        assert_eq!(
            app.handle_key(tecla(KeyCode::Enter)),
            Action::WhoUses {
                dimension: Dimension::App,
                key: "youtube".to_string(),
                label: "YouTube".to_string(),
                window: Window::Sixty,
            }
        );
        assert!(app.traffic.who_uses.as_ref().expect("panel").pending);
        assert_eq!(app.handle_key(tecla(KeyCode::Esc)), Action::None);
        assert!(!app.who_uses_open());
        assert_eq!(app.tab, Tab::Trafico);
    }

    #[test]
    fn el_panel_quien_lo_usa_mueve_seleccion_y_enter_abre_detalle() {
        let mut app = app_prueba();
        app.tab = Tab::Trafico;
        app.traffic_group = Dimension::Destination;
        app.traffic_window = Window::FiveMin;
        app.traffic.rankings = vec![vista_ranking(
            Dimension::Destination,
            Window::FiveMin,
            vec![fila_ranking(
                "googlevideo.com",
                "googlevideo.com",
                900,
                10,
                2,
            )],
        )];
        let peticion = app.open_who_uses().expect("petición");
        assert_eq!(peticion.0, Dimension::Destination);
        assert_eq!(peticion.3, Window::FiveMin);
        app.set_who_uses(vec![
            DeviceShare {
                device_id: 1,
                label: "equipo-1".to_string(),
                bytes: 800,
                pct: 80.0,
            },
            DeviceShare {
                device_id: 2,
                label: "equipo-2".to_string(),
                bytes: 200,
                pct: 20.0,
            },
        ]);
        assert!(!app.traffic.who_uses.as_ref().unwrap().pending);
        assert_eq!(
            app.selected_who_uses().map(|cuota| cuota.device_id),
            Some(1)
        );
        app.handle_key(tecla(KeyCode::Char('j')));
        assert_eq!(
            app.selected_who_uses().map(|cuota| cuota.device_id),
            Some(2)
        );
        app.handle_key(tecla(KeyCode::Char('j')));
        assert_eq!(
            app.selected_who_uses().map(|cuota| cuota.device_id),
            Some(2)
        );
        assert_eq!(
            app.handle_key(tecla(KeyCode::Enter)),
            Action::OpenDetail { device_id: 2 }
        );
    }

    #[test]
    fn enter_en_proceso_abre_conexiones_filtradas_por_pid() {
        let mut app = app_prueba();
        app.tab = Tab::Trafico;
        app.traffic_group = Dimension::Process;
        app.traffic.rankings = vec![vista_ranking(
            Dimension::Process,
            Window::Sixty,
            vec![fila_ranking("1234", "firefox (1234)", 900, 10, 0)],
        )];
        let mut firefox = conexion(Some(1), "ESTABLISHED");
        firefox.pid = Some(1234);
        firefox.comm = Some("firefox".to_string());
        let mut bash = conexion(None, "TIME_WAIT");
        bash.pid = Some(555);
        bash.comm = Some("bash".to_string());
        bash.idle = Duration::from_secs(5);
        app.traffic.connections = vec![firefox, bash];
        app.traffic.connections_total = 2;

        assert_eq!(app.handle_key(tecla(KeyCode::Enter)), Action::None);
        assert_eq!(app.tab, Tab::Conexiones);
        assert_eq!(
            app.conn_filter,
            ConnectionFilter::Proceso {
                pid: Some(1234),
                comm: "firefox".to_string()
            }
        );
        assert_eq!(app.filtered_connections().len(), 1);
        // Una pulsación de f quita el filtro por proceso (no está en el ciclo).
        app.cycle_connection_filter();
        assert_eq!(app.conn_filter, ConnectionFilter::Todas);
    }

    #[test]
    fn una_clave_de_proceso_no_numerica_filtra_por_nombre() {
        let mut app = app_prueba();
        app.traffic_group = Dimension::Process;
        app.traffic.rankings = vec![vista_ranking(
            Dimension::Process,
            Window::Sixty,
            vec![fila_ranking("firefox", "firefox", 900, 10, 0)],
        )];
        let mut firefox = conexion(Some(1), "ESTABLISHED");
        firefox.pid = Some(1234);
        firefox.comm = Some("firefox".to_string());
        let mut bash = conexion(None, "TIME_WAIT");
        bash.pid = Some(999);
        bash.comm = Some("bash".to_string());
        app.traffic.connections = vec![firefox, bash];
        assert!(app.filtrar_conexiones_por_proceso());
        assert_eq!(
            app.conn_filter,
            ConnectionFilter::Proceso {
                pid: None,
                comm: "firefox".to_string()
            }
        );
        assert_eq!(app.filtered_connections().len(), 1);
    }

    #[test]
    fn la_tecla_i_alterna_nombres_e_ips() {
        let mut app = app_prueba();
        app.tab = Tab::Conexiones;
        assert!(app.show_names);
        app.handle_key(tecla(KeyCode::Char('i')));
        assert!(!app.show_names);
        app.handle_key(tecla(KeyCode::Char('i')));
        assert!(app.show_names);
    }

    #[test]
    fn la_busqueda_de_conexiones_usa_servidor_app_y_proceso() {
        let mut app = app_prueba();
        app.tab = Tab::Conexiones;
        let mut github = conexion(Some(1), "ESTABLISHED");
        let mut etiqueta = etiqueta_con_rol(Some(true));
        etiqueta.server_name = Some("github.com".to_string());
        etiqueta.name_source = Some(NameSource::Sni);
        etiqueta.app = Some("github".to_string());
        github.label = Some(etiqueta);
        github.app_name = Some("GitHub".to_string());
        github.pid = Some(1234);
        github.comm = Some("firefox".to_string());
        let mut curl = conexion(None, "TIME_WAIT");
        curl.pid = Some(555);
        curl.comm = Some("curl".to_string());
        curl.idle = Duration::from_secs(5);
        app.traffic.connections = vec![github, curl];
        app.traffic.connections_total = 2;

        app.conn_search = "github".to_string();
        assert_eq!(app.filtered_connections().len(), 1);
        app.conn_search = "firefox".to_string();
        assert_eq!(app.filtered_connections().len(), 1);
        app.conn_search = "curl".to_string();
        assert_eq!(app.filtered_connections().len(), 1);
        app.conn_search = "no-existe".to_string();
        assert!(app.filtered_connections().is_empty());

        // La búsqueda incremental de Conexiones no cambia de pestaña.
        app.conn_search.clear();
        app.handle_key(tecla(KeyCode::Char('/')));
        assert_eq!(
            app.input.as_ref().map(|input| input.mode),
            Some(InputMode::ConnectionSearch)
        );
        assert_eq!(app.tab, Tab::Conexiones);
        for letra in "firefox".chars() {
            app.handle_key(tecla(KeyCode::Char(letra)));
        }
        assert_eq!(app.effective_conn_search(), "firefox");
        app.handle_key(tecla(KeyCode::Enter));
        assert_eq!(app.conn_search, "firefox");
        assert_eq!(app.filtered_connections().len(), 1);
    }

    #[test]
    fn los_roles_orientan_cliente_servidor_y_bytes() {
        let mut conexion = conexion(Some(1), "ESTABLISHED");
        conexion.bytes_in = 900;
        conexion.bytes_out = 100;

        conexion.label = Some(etiqueta_con_rol(Some(true)));
        let (rol, cliente, servidor) = lados_conexion(&conexion);
        assert_eq!(rol, ConnectionSides::ClienteOrigen);
        assert_eq!(cliente.ip, ip("192.168.1.42"));
        assert_eq!(servidor.ip, ip("1.1.1.1"));
        assert_eq!(bytes_orientados(&conexion), (100, 900));

        conexion.label = Some(etiqueta_con_rol(Some(false)));
        let (rol, cliente, servidor) = lados_conexion(&conexion);
        assert_eq!(rol, ConnectionSides::ClienteDestino);
        assert_eq!(cliente.ip, ip("1.1.1.1"));
        assert_eq!(servidor.ip, ip("192.168.1.42"));
        assert_eq!(bytes_orientados(&conexion), (900, 100));

        conexion.label = None;
        let (rol, cliente, servidor) = lados_conexion(&conexion);
        assert_eq!(rol, ConnectionSides::Desconocido);
        assert!(rol.sin_rol());
        assert_eq!(cliente.ip, ip("192.168.1.42"));
        assert_eq!(servidor.ip, ip("1.1.1.1"));
        assert_eq!(bytes_orientados(&conexion), (100, 900));
    }

    #[test]
    fn las_medias_de_ventana_dividen_entre_sus_segundos() {
        let app = app_prueba();
        assert_eq!(app.bytes_por_segundo_en_ventana(600, Window::Sixty), 10);
        assert_eq!(app.bytes_por_segundo_en_ventana(1500, Window::FiveMin), 5);
        assert_eq!(
            app.bytes_por_segundo_en_ventana(0, Window::Session),
            0,
            "nunca divide entre cero"
        );
    }

    #[test]
    fn el_detalle_de_equipo_expone_el_ranking_de_cinco_minutos() {
        let mut app = app_prueba();
        app.traffic.device_rankings = vec![DeviceRankingView {
            device_id: 1,
            window: Window::FiveMin,
            apps: vec![fila_ranking("instagram", "Instagram", 2_000, 100, 1)],
            destinations: vec![fila_ranking(
                "cdninstagram.com",
                "cdninstagram.com",
                1_900,
                50,
                1,
            )],
        }];
        let ranking = app.traffic.device_ranking(1).expect("ranking del equipo");
        assert_eq!(ranking.apps[0].label, "Instagram");
        assert_eq!(ranking.destinations[0].label, "cdninstagram.com");
        assert_eq!(ranking.window, Window::FiveMin);
        assert!(app.traffic.device_ranking(2).is_none());
    }

    #[test]
    fn las_dimensiones_y_las_agrupaciones_se_mapean_en_ambos_sentidos() {
        for dimension in Dimension::ALL {
            let grupo = grupo_de_dimension(dimension);
            assert_eq!(dimension_de_grupo(grupo), dimension);
        }
        assert_eq!(dimension_de_grupo(TrafficGroup::App), Dimension::App);
        assert_eq!(
            grupo_de_dimension(Dimension::Process),
            TrafficGroup::Process
        );
    }

    #[test]
    fn ordenar_ranking_por_equipos_y_empates_por_etiqueta() {
        let mut filas = vec![
            fila_ranking("b", "Beta", 10, 1, 2),
            fila_ranking("a", "Alfa", 10, 1, 2),
            fila_ranking("c", "Gamma", 10, 1, 5),
        ];
        ordenar_ranking(&mut filas, SortKey::Devices);
        assert_eq!(filas[0].label, "Gamma");
        assert_eq!(filas[1].label, "Alfa");
        assert_eq!(filas[2].label, "Beta");
    }
}
