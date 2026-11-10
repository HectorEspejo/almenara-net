//! Estado de tráfico, conexiones y detalle de equipo en la TUI (Fase 3).
//!
//! Este módulo amplía [App] con el estado que consume la interfaz en las
//! pestañas Tráfico y Conexiones, el panel master-detail de equipo y el panel de
//! cabeceras de la tecla v. La lógica de captura y de red vive en
//! [crate::traffic] y [crate::capture]; aquí solo hay estado de presentación.

use std::time::Instant;

use crate::capture::aggregate::{DeviceTraffic, GlobalTraffic};
use crate::capture::Protocol;
use crate::repo::{DeviceService, TrafficSnapshot};
use crate::traffic::{CaptureStatus, ConnectionView, TrafficUpdate};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFilter {
    /// Todas las conexiones.
    Todas,
    /// Solo un protocolo de transporte.
    Protocolo(Protocol),
    /// Solo un estado TCP concreto.
    Estado(&'static str),
    /// Solo las conexiones del dispositivo indicado.
    Dispositivo(i64),
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
    }

    /// Cierra el panel de detalle.
    pub fn close_detail(&mut self) {
        self.detail = None;
        self.detail_focus = FocusPanel::Lista;
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
        self.traffic.updated_at = Some(Instant::now());
        self.clamp_connection_selection();
        self.clamp_traffic_selection();
    }

    /// Guarda la semilla de TRAFFIC_SNAPSHOT leída al arrancar.
    pub fn set_traffic_seed(&mut self, snapshots: Vec<TrafficSnapshot>) {
        self.traffic.seed = snapshots;
    }

    /// Ranking actual de la pestaña Tráfico.
    pub fn traffic_rows(&self) -> Vec<DeviceTraffic> {
        self.traffic.ranked_devices()
    }

    /// Mueve la selección del ranking de tráfico.
    pub fn move_traffic_selection(&mut self, delta: isize) {
        let total = self.traffic_rows().len();
        if total == 0 {
            self.traffic_selected = 0;
        } else {
            let actual = self.traffic_selected.min(total - 1) as isize;
            self.traffic_selected = (actual + delta).clamp(0, total as isize - 1) as usize;
        }
        *self.traffic_table_state.selected_mut() = Some(self.traffic_selected);
    }

    /// Equipo seleccionado en el ranking de tráfico.
    pub fn selected_traffic_device(&self) -> Option<DeviceTraffic> {
        self.traffic_rows().get(self.traffic_selected).cloned()
    }

    fn clamp_traffic_selection(&mut self) {
        let total = self.traffic_rows().len();
        if total == 0 {
            self.traffic_selected = 0;
        } else if self.traffic_selected >= total {
            self.traffic_selected = total - 1;
        }
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
        match self.conn_filter {
            ConnectionFilter::Todas => true,
            ConnectionFilter::Protocolo(protocolo) => {
                conexion.protocol() == protocolo
                    || (protocolo == Protocol::Icmp && conexion.protocol() == Protocol::Icmpv6)
            }
            ConnectionFilter::Estado(estado) => conexion
                .state
                .as_deref()
                .map(|actual| actual.eq_ignore_ascii_case(estado))
                .unwrap_or(false),
            ConnectionFilter::Dispositivo(id) => {
                conexion.device_id == Some(id)
                    || conexion.origin.device_id == Some(id)
                    || conexion.destination.device_id == Some(id)
            }
        }
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
        let actual = opciones
            .iter()
            .position(|opcion| *opcion == self.conn_filter)
            .unwrap_or(0);
        self.conn_filter = opciones[(actual + 1) % opciones.len()];
        self.conn_selected = 0;
        self.clamp_connection_selection();
    }

    /// Etiqueta visible del filtro de conexiones.
    pub fn connection_filter_label(&self) -> String {
        self.conn_filter.label(self)
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
    use crate::config::Config;
    use crate::repo::devices::Device;
    use crate::traffic::{EndpointView, TrafficUpdate};
    use crate::tui::app::{Action, App, Tab};
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
        });
        assert!(app.traffic.has_live_data());
        assert!(app.traffic.updated_at.is_some());
        assert_eq!(app.traffic_selected, 0);
        assert_eq!(app.conn_selected, 0);
    }
}
