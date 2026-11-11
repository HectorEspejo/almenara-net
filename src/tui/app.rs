//! Estado de la aplicación TUI y lógica de interacción.
//!
//! El estado es independiente de la base de datos: las acciones que requieren
//! persistencia se devuelven como [Action] y el bucle de la TUI las ejecuta.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::TableState;
use tokio::sync::mpsc;

use crate::capabilities::Capabilities;
use crate::classify::{group_for, DeviceGroup, DeviceType};
use crate::config::{Config, ListView, TrafficGroup};
use crate::events::{ScanCommand, TrafficCommand};
use crate::inference::catalog::CatalogCounts;
use crate::notifier::{Level, Notification, Notifier};
use crate::rankings::{Dimension, SortKey as RankingSortKey, Window};
use crate::repo::devices::Device;
use crate::repo::interfaces::Interface;
use crate::scanner::Reconciliation;
use crate::tui::theme::Theme;
use crate::tui::traffic_state::{
    dimension_de_grupo, ConnectionFilter, ConnectionSort, DetailState, FocusPanel, HeadersView,
    TrafficState,
};

/// Tiempo que se muestra el aviso de una línea de una alerta importante.
pub const ALERT_NOTICE_TTL: Duration = Duration::from_secs(10);

/// Ancho mínimo de terminal soportado.
pub const MIN_WIDTH: u16 = 80;
/// Alto mínimo de terminal soportado.
pub const MIN_HEIGHT: u16 = 24;

/// Pestañas de la aplicación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Vista principal de equipos.
    Equipos,
    /// Tráfico (placeholder en Fase 1).
    Trafico,
    /// Conexiones (placeholder en Fase 1).
    Conexiones,
    /// Histórico (placeholder en Fase 1).
    Historico,
    /// Alertas (placeholder en Fase 1).
    Alertas,
    /// Configuración activa (solo lectura).
    Config,
    /// Ayuda y keybindings.
    Ayuda,
}

impl Tab {
    /// Todas las pestañas en orden.
    pub const ALL: [Tab; 7] = [
        Tab::Equipos,
        Tab::Trafico,
        Tab::Conexiones,
        Tab::Historico,
        Tab::Alertas,
        Tab::Config,
        Tab::Ayuda,
    ];

    /// Índice de la pestaña.
    pub fn index(self) -> usize {
        match self {
            Tab::Equipos => 0,
            Tab::Trafico => 1,
            Tab::Conexiones => 2,
            Tab::Historico => 3,
            Tab::Alertas => 4,
            Tab::Config => 5,
            Tab::Ayuda => 6,
        }
    }

    /// Título visible en la barra de pestañas.
    pub fn title(self) -> &'static str {
        match self {
            Tab::Equipos => "Equipos",
            Tab::Trafico => "Tráfico",
            Tab::Conexiones => "Conexiones",
            Tab::Historico => "Histórico",
            Tab::Alertas => "Alertas",
            Tab::Config => "Config",
            Tab::Ayuda => "Ayuda",
        }
    }

    /// Pestaña a partir de un número 1-7.
    pub fn from_number(numero: u8) -> Option<Tab> {
        match numero {
            1 => Some(Tab::Equipos),
            2 => Some(Tab::Trafico),
            3 => Some(Tab::Conexiones),
            4 => Some(Tab::Historico),
            5 => Some(Tab::Alertas),
            6 => Some(Tab::Config),
            7 => Some(Tab::Ayuda),
            _ => None,
        }
    }

    /// Pestaña siguiente (con vuelta).
    pub fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    /// Pestaña anterior (con vuelta).
    pub fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}

/// Columna por la que se ordena la lista.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    /// Dirección IP.
    Ip,
    /// Hostname o alias.
    Hostname,
    /// MAC.
    Mac,
    /// Fabricante.
    Vendor,
    /// Estado online/offline.
    Estado,
}

impl SortKey {
    /// Siguiente columna ordenable.
    pub fn next(self) -> SortKey {
        match self {
            SortKey::Ip => SortKey::Hostname,
            SortKey::Hostname => SortKey::Mac,
            SortKey::Mac => SortKey::Vendor,
            SortKey::Vendor => SortKey::Estado,
            SortKey::Estado => SortKey::Ip,
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            SortKey::Ip => "IP",
            SortKey::Hostname => "hostname",
            SortKey::Mac => "MAC",
            SortKey::Vendor => "fabricante",
            SortKey::Estado => "estado",
        }
    }
}

/// Estado de ordenación actual.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortState {
    /// Columna activa.
    pub key: SortKey,
    /// Orden ascendente.
    pub ascending: bool,
}

impl Default for SortState {
    fn default() -> Self {
        Self {
            key: SortKey::Ip,
            ascending: true,
        }
    }
}

impl SortState {
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

/// Filtro activo de la lista de equipos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// Todos los equipos.
    All,
    /// Solo online.
    Online,
    /// Solo offline.
    Offline,
    /// Solo detectados en esta sesión.
    New,
    /// Alertas (no disponible en Fase 1).
    Alert,
}

impl Filter {
    /// Siguiente filtro.
    pub fn cycle(self) -> Filter {
        match self {
            Filter::All => Filter::Online,
            Filter::Online => Filter::Offline,
            Filter::Offline => Filter::New,
            Filter::New => Filter::Alert,
            Filter::Alert => Filter::All,
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "todos",
            Filter::Online => "online",
            Filter::Offline => "offline",
            Filter::New => "nuevos",
            Filter::Alert => "alertas",
        }
    }
}

/// Modo del campo de entrada activo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Búsqueda incremental de equipos.
    Search,
    /// Búsqueda incremental de conexiones (servidor, app o proceso).
    ConnectionSearch,
    /// Edición del alias.
    Alias,
    /// Edición de las notas.
    Notes,
}

/// Estado del campo de entrada activo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputState {
    /// Modo del campo.
    pub mode: InputMode,
    /// Texto en edición.
    pub buffer: String,
    /// Dispositivo afectado (solo alias/notas).
    pub device_id: Option<i64>,
}

/// Acciones que la capa TUI devuelve al bucle principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Sin acción.
    None,
    /// Cerrar la aplicación.
    Quit,
    /// Solicitar un rescaneo manual.
    Rescan,
    /// Guardar el alias de un dispositivo.
    SaveAlias {
        /// Id del dispositivo.
        id: i64,
        /// Alias nuevo (None para borrar).
        value: Option<String>,
    },
    /// Guardar las notas de un dispositivo.
    SaveNotes {
        /// Id del dispositivo.
        id: i64,
        /// Notas nuevas (None para borrar).
        value: Option<String>,
    },
    /// Cambiar la vista de la lista de equipos (plana o agrupada).
    SetListView(ListView),
    /// Guardar el tipo de dispositivo manual de un equipo (None = automático).
    SetDeviceTypeManual {
        /// Id del dispositivo.
        id: i64,
        /// Tipo forzado por el usuario; None deja la clasificación automática.
        value: Option<DeviceType>,
    },
    /// Abrir el panel de detalle (master-detail) de un equipo.
    OpenDetail {
        /// Id del dispositivo.
        device_id: i64,
    },
    /// Cambiar la agrupación del ranking de Tráfico (se persiste en [ui].traffic_group).
    SetTrafficGroup(TrafficGroup),
    /// Petición «¿Quién lo usa?» que el bucle resuelve con oneshot y timeout.
    WhoUses {
        /// Dimensión del ranking.
        dimension: Dimension,
        /// Clave de la fila.
        key: String,
        /// Texto visible de la fila.
        label: String,
        /// Ventana consultada.
        window: Window,
    },
    /// Marcar como vistas una alerta (y lo que agrupa, si es un resumen).
    MarkAlertSeen(crate::repo::SeenSel),
    /// Marcar como vistas todas las alertas del filtro de la pestaña Alertas.
    MarkAlertsSeen(crate::repo::AlertScope),
    /// Silenciar una regla para el sujeto y el equipo de una alerta.
    MuteAlert {
        /// Regla silenciada.
        rule: crate::alerts::RuleId,
        /// Sujeto.
        subject: crate::alerts::Subject,
        /// Fin del silencio (None = siempre).
        until: Option<std::time::SystemTime>,
    },
    /// Quitar un silencio.
    DeleteMute(i64),
    /// Guardar si una regla está activa y su nivel desde la vista Reglas.
    SaveRuleSetting {
        /// Regla.
        rule: crate::alerts::RuleId,
        /// Ajuste nuevo.
        setting: crate::alerts::RuleSetting,
    },
    /// Marcar o desmarcar un equipo como vigilado (tecla p).
    SetWatched {
        /// Equipo.
        device_id: i64,
        /// Vigilado.
        watched: bool,
    },
}

/// Estado completo de la aplicación.
#[derive(Debug)]
pub struct App {
    /// Equipos cargados.
    pub devices: Vec<Device>,
    /// Interfaces persistidas.
    pub interfaces: Vec<Interface>,
    /// Configuración activa.
    pub config: Config,
    /// Ruta del fichero de configuración.
    pub config_path: PathBuf,
    /// Ruta de la base de datos.
    pub db_path: PathBuf,
    /// Capacidades detectadas.
    pub capabilities: Capabilities,
    /// Pestaña activa.
    pub tab: Tab,
    /// Índice de la fila seleccionada dentro de la vista filtrada.
    pub selected: usize,
    /// Ordenación activa.
    pub sort: SortState,
    /// Filtro activo.
    pub filter: Filter,
    /// Vista de la lista de equipos (plana o agrupada por categoría).
    pub list_view: ListView,
    /// Búsqueda confirmada.
    pub search: String,
    /// Campo de entrada activo.
    pub input: Option<InputState>,
    /// Buffer de notificaciones.
    pub notifier: Notifier,
    /// Hay un escaneo en curso.
    pub scanning: bool,
    /// Momento del último escaneo completado.
    pub last_scan: Option<Instant>,
    /// Número de equipos del último escaneo.
    pub last_scan_devices: usize,
    /// La aplicación debe cerrarse.
    pub should_quit: bool,
    /// Estado de la tabla (scroll de ratatui).
    pub table_state: TableState,
    /// Inicio de la sesión en RFC 3339 (para el filtro "nuevos").
    pub session_start: String,
    /// Ya se ha avisado del modo degradado.
    pub degraded_warned: bool,
    /// Canal de órdenes hacia el escáner (None en tests).
    pub command_tx: Option<mpsc::Sender<ScanCommand>>,
    /// Paleta de colores activa.
    pub theme: Theme,
    /// Estado del tráfico en vivo (Fase 3).
    pub traffic: TrafficState,
    /// Panel de detalle de equipo abierto (master-detail).
    pub detail: Option<DetailState>,
    /// Foco del panel master-detail.
    pub detail_focus: FocusPanel,
    /// Ordenación de la tabla de conexiones.
    pub conn_sort: ConnectionSort,
    /// Filtro de la tabla de conexiones.
    pub conn_filter: ConnectionFilter,
    /// Selección de la tabla de conexiones.
    pub conn_selected: usize,
    /// Estado de tabla de la pestaña Conexiones.
    pub conn_table_state: TableState,
    /// Selección del ranking de la pestaña Tráfico.
    pub traffic_selected: usize,
    /// Estado de tabla del ranking de Tráfico.
    pub traffic_table_state: TableState,
    /// Panel de cabeceras IP/TCP abierto (tecla v).
    pub headers: Option<HeadersView>,
    /// Canal de órdenes hacia la tarea de tráfico (None en tests).
    pub traffic_command_tx: Option<mpsc::Sender<TrafficCommand>>,
    /// Marca temporal de la última persistencia de tráfico.
    pub last_traffic_persist: Option<Instant>,
    /// Agrupación del ranking de Tráfico (F4, persistida en [ui].traffic_group).
    pub traffic_group: Dimension,
    /// Ventana del ranking de Tráfico (F4, no se persiste: arranca en 60 s).
    pub traffic_window: Window,
    /// Criterio de orden del ranking de Tráfico (tecla s).
    pub rank_sort: RankingSortKey,
    /// Mostrar nombres (true) o IPs (false) en la pestaña Conexiones.
    pub show_names: bool,
    /// Búsqueda confirmada de la pestaña Conexiones.
    pub conn_search: String,
    /// Desplazamiento vertical del panel de detalle de equipo.
    pub detail_scroll: usize,
    /// Desplazamiento máximo del panel de detalle (lo fija la vista al dibujar).
    pub detail_max_scroll: usize,
    /// Cifras del catálogo de apps para la pestaña Config.
    pub catalog_counts: CatalogCounts,
    /// Fecha de las bases IP embebidas para la pestaña Config.
    pub ipdb_date: Option<String>,
    /// Inicio de la sesión, para las medias de la ventana «sesión».
    pub session_started: Instant,
    /// Estado del histórico de F5 (datos del lector y consultas en vuelo).
    pub history: crate::tui::history_state::HistoryState,
    /// Lector del histórico de solo lectura (None en pruebas).
    pub history_reader: Option<crate::history::reader::HistoryHandle>,
    /// Contadores de lotes del agregador (diagnóstico del histórico).
    pub rollup_counters: crate::history::RollupCounters,
    /// Lotes del minuto pendientes de escribir (hasta 10, §4.1).
    pub pending_rollups: Vec<crate::history::RollupBatch>,
    /// Id de la sesión abierta en APP_SESSIONS.
    pub session_id: Option<i64>,
    /// Último latido de la sesión.
    pub last_beat: Option<Instant>,
    /// La tarea de tráfico ha cerrado el minuto parcial al pararse.
    pub traffic_stopped: bool,
    /// Última purga del histórico.
    pub last_purge: Option<Instant>,
    /// Última consolidación de horas y días.
    pub last_consolidation: Option<Instant>,
    /// Ya se ha avisado de que la BD supera [history].max_db_mb.
    pub db_size_warned: bool,
    /// Ya se ha avisado del descarte de lotes del histórico.
    pub rollup_dropped_warned: bool,
    /// Estado de la pestaña Alertas (F6).
    pub alerts: crate::tui::alerts_state::AlertsState,
    /// Motor de alertas (None en pruebas: lo crea el bucle con el snapshot de la BD).
    pub alert_engine: Option<crate::alerts::AlertEngine>,
    /// Notificador de escritorio (None en pruebas).
    pub alert_notifier: Option<crate::notify::NotifierHandle>,
    /// Acciones del motor que no se pudieron escribir y se reintentan por minuto.
    pub pending_alert_actions: Vec<crate::alerts::AlertAction>,
    /// Ya se avisó de que no se podían escribir las alertas (§7.5).
    pub alert_write_warned: bool,
    /// Detector de suspensión por CLOCK_BOOTTIME frente a CLOCK_MONOTONIC (§7.10).
    pub suspend: crate::alerts::Suspend,
    /// Hueco `capture` abierto de la sesión, si lo hay.
    pub capture_gap: Option<i64>,
    /// La captura estaba activa en el tick anterior (para abrir el hueco).
    pub capture_was_active: bool,
    /// Última muestra de salud de la captura y de la BD (cada minuto).
    pub last_health: Option<Instant>,
    /// Paquetes capturados en la muestra de salud anterior.
    pub health_prev_total: u64,
    /// Paquetes perdidos por el anillo en la muestra de salud anterior.
    pub health_prev_drops: u64,
    /// Paquetes descartados por `max_pps` en la muestra de salud anterior.
    pub health_prev_limit_drops: u64,
    /// Ya se avisó de que no se pudo guardar una regla en config.toml (§7.14).
    pub alert_rule_save_warned: bool,
    /// Último reintento de las acciones del motor que no se pudieron escribir.
    pub last_alert_retry: Option<Instant>,
    /// La pestaña Alertas estaba visible en el tick anterior (refresco al entrar).
    pub alert_tab_active: bool,
    /// Última actualización de los contadores de alertas no vistas.
    pub last_alert_counts: Option<Instant>,
    /// Último tick de las tareas de alertas (suspensión, huecos, motor): 1 s.
    pub last_alert_tick: Option<Instant>,
    /// Aviso de una línea de una alerta importante (texto y momento), 10 s (§6).
    pub alert_notice: Option<(String, Instant)>,
}

impl App {
    /// Crea el estado inicial de la aplicación.
    pub fn new(
        config: Config,
        config_path: PathBuf,
        db_path: PathBuf,
        capabilities: Capabilities,
        command_tx: Option<mpsc::Sender<ScanCommand>>,
    ) -> Self {
        let theme = Theme::from_flags(config.ui.no_color, false);
        let list_view = config.ui.list_view;
        let traffic_group = dimension_de_grupo(config.ui.traffic_group);
        Self {
            devices: Vec::new(),
            interfaces: Vec::new(),
            config,
            config_path,
            db_path,
            capabilities,
            tab: Tab::Equipos,
            selected: 0,
            sort: SortState::default(),
            filter: Filter::All,
            list_view,
            search: String::new(),
            input: None,
            notifier: Notifier::new(),
            scanning: false,
            last_scan: None,
            last_scan_devices: 0,
            should_quit: false,
            table_state: TableState::default(),
            session_start: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            degraded_warned: false,
            command_tx,
            theme,
            traffic: TrafficState::default(),
            detail: None,
            detail_focus: FocusPanel::Lista,
            conn_sort: ConnectionSort::default(),
            conn_filter: ConnectionFilter::Todas,
            conn_selected: 0,
            conn_table_state: TableState::default(),
            traffic_selected: 0,
            traffic_table_state: TableState::default(),
            headers: None,
            traffic_command_tx: None,
            last_traffic_persist: None,
            traffic_group,
            traffic_window: Window::Sixty,
            rank_sort: RankingSortKey::Total,
            show_names: true,
            conn_search: String::new(),
            detail_scroll: 0,
            detail_max_scroll: 0,
            catalog_counts: CatalogCounts::default(),
            ipdb_date: None,
            session_started: Instant::now(),
            history: crate::tui::history_state::HistoryState::new(),
            history_reader: None,
            rollup_counters: crate::history::RollupCounters::default(),
            pending_rollups: Vec::new(),
            session_id: None,
            last_beat: None,
            traffic_stopped: false,
            last_purge: None,
            last_consolidation: None,
            db_size_warned: false,
            rollup_dropped_warned: false,
            alerts: crate::tui::alerts_state::AlertsState::new(),
            alert_engine: None,
            alert_notifier: None,
            pending_alert_actions: Vec::new(),
            alert_write_warned: false,
            suspend: crate::alerts::Suspend::new(),
            capture_gap: None,
            capture_was_active: false,
            last_health: None,
            health_prev_total: 0,
            health_prev_drops: 0,
            health_prev_limit_drops: 0,
            alert_rule_save_warned: false,
            last_alert_retry: None,
            alert_tab_active: false,
            last_alert_counts: None,
            last_alert_tick: None,
            alert_notice: None,
        }
    }

    /// Sustituye los datos de equipos e interfaces y ajusta la selección.
    pub fn set_data(&mut self, devices: Vec<Device>, interfaces: Vec<Interface>) {
        self.history.set_devices(&devices);
        self.devices = devices;
        self.interfaces = interfaces;
        self.clamp_selection();
    }

    /// Aplica el resultado de reconciliar un escaneo.
    pub fn apply_reconciliation(&mut self, reconciliacion: Reconciliation) {
        self.history.set_devices(&reconciliacion.devices);
        self.devices = reconciliacion.devices;
        self.interfaces = reconciliacion.interfaces;
        self.scanning = false;
        self.last_scan = Some(Instant::now());
        self.last_scan_devices = self.devices.len();
        self.clamp_selection();
    }

    /// Inserta una notificación en el buffer.
    pub fn push_notification(&mut self, level: Level, message: impl Into<String>) {
        self.notifier.push(level, message);
    }

    /// Inserta una notificación ya construida.
    pub fn push_notification_obj(&mut self, notification: Notification) {
        self.notifier.push(notification.level, notification.message);
    }

    /// Avanza el reloj de las notificaciones y del aviso de alerta importante.
    pub fn tick(&mut self) {
        self.notifier.tick();
        if let Some((_, mostrado)) = &self.alert_notice {
            if mostrado.elapsed() >= ALERT_NOTICE_TTL {
                self.alert_notice = None;
            }
        }
    }

    /// Muestra durante 10 s el aviso de una línea de una alerta importante (§6).
    pub fn push_alert_notice(&mut self, message: impl Into<String>) {
        self.alert_notice = Some((message.into(), Instant::now()));
    }

    /// Indica si la aplicación está en modo degradado.
    pub fn is_degraded(&self) -> bool {
        self.capabilities.degraded()
    }

    /// Texto de la consulta de búsqueda efectiva (incluye la edición en curso).
    pub fn effective_search(&self) -> &str {
        match &self.input {
            Some(input) if input.mode == InputMode::Search => &input.buffer,
            _ => &self.search,
        }
    }

    /// Índices de los dispositivos visibles según filtro, búsqueda y orden.
    ///
    /// En la vista agrupada se ordena primero por categoría ([DeviceGroup::ALL])
    /// y, dentro de cada grupo, por la ordenación activa. En ambos modos el
    /// índice devuelto es la posición en la lista visible (sin contar cabeceras).
    pub fn visible_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..self.devices.len())
            .filter(|indice| self.matches(&self.devices[*indice]))
            .collect();
        let ascending = self.sort.ascending;
        let key = self.sort.key;
        let ordenar = |a: &usize, b: &usize| {
            let izquierda = &self.devices[*a];
            let derecha = &self.devices[*b];
            let orden =
                comparar(izquierda, derecha, key).then_with(|| izquierda.mac.cmp(&derecha.mac));
            if ascending {
                orden
            } else {
                orden.reverse()
            }
        };
        if self.list_view == ListView::Grouped {
            indices.sort_by(|a, b| {
                grupo_de(&self.devices[*a])
                    .cmp(&grupo_de(&self.devices[*b]))
                    .then_with(|| ordenar(a, b))
            });
        } else {
            indices.sort_by(ordenar);
        }
        indices
    }

    /// Dispositivo seleccionado actualmente, si lo hay.
    pub fn selected_device(&self) -> Option<&Device> {
        let indices = self.visible_indices();
        indices
            .get(self.selected)
            .and_then(|indice| self.devices.get(*indice))
    }

    /// Número de filas visibles.
    pub fn visible_len(&self) -> usize {
        self.visible_indices().len()
    }

    /// Mueve la selección.
    pub fn move_selection(&mut self, delta: isize) {
        let total = self.visible_len();
        if total == 0 {
            self.selected = 0;
            return;
        }
        let actual = self.selected.min(total - 1) as isize;
        let nuevo = (actual + delta).clamp(0, total as isize - 1);
        self.selected = nuevo as usize;
    }

    /// Selecciona la primera fila.
    pub fn select_first(&mut self) {
        self.selected = 0;
    }

    /// Selecciona la última fila.
    pub fn select_last(&mut self) {
        let total = self.visible_len();
        self.selected = total.saturating_sub(1);
    }

    /// Cambia a la pestaña siguiente.
    pub fn next_tab(&mut self) {
        self.tab = self.tab.next();
    }

    /// Cambia a la pestaña anterior.
    pub fn previous_tab(&mut self) {
        self.tab = self.tab.prev();
    }

    /// Inicia una búsqueda: equipos o, en la pestaña Conexiones, conexiones.
    pub fn begin_search(&mut self) {
        if self.tab == Tab::Conexiones {
            self.input = Some(InputState {
                mode: InputMode::ConnectionSearch,
                buffer: self.conn_search.clone(),
                device_id: None,
            });
            self.conn_selected = 0;
            return;
        }
        self.tab = Tab::Equipos;
        self.input = Some(InputState {
            mode: InputMode::Search,
            buffer: self.search.clone(),
            device_id: None,
        });
        self.selected = 0;
    }

    /// Inicia la edición de alias o notas del dispositivo seleccionado.
    pub fn begin_device_input(&mut self, mode: InputMode) {
        if self.tab != Tab::Equipos {
            return;
        }
        let Some(device) = self.selected_device().cloned() else {
            self.push_notification(Level::Info, "No hay ningún equipo seleccionado");
            return;
        };
        let (buffer, device_id) = match mode {
            InputMode::Alias => (device.alias.unwrap_or_default(), device.id),
            InputMode::Notes => (device.notes.unwrap_or_default(), device.id),
            InputMode::Search | InputMode::ConnectionSearch => return,
        };
        self.input = Some(InputState {
            mode,
            buffer,
            device_id: Some(device_id),
        });
    }

    /// Cancela el campo de entrada activo.
    pub fn cancel_input(&mut self) {
        if let Some(input) = self.input.take() {
            match input.mode {
                InputMode::Search => self.search.clear(),
                InputMode::ConnectionSearch => self.conn_search.clear(),
                InputMode::Alias | InputMode::Notes => {}
            }
        }
        self.clamp_selection();
        self.clamp_connection_selection();
    }

    /// Confirma el campo de entrada y devuelve la acción a ejecutar.
    pub fn commit_input(&mut self) -> Action {
        match self.input.take() {
            Some(InputState {
                mode: InputMode::Search,
                buffer,
                ..
            }) => {
                self.search = buffer.trim().to_string();
                self.selected = 0;
                self.clamp_selection();
                Action::None
            }
            Some(InputState {
                mode: InputMode::ConnectionSearch,
                buffer,
                ..
            }) => {
                self.conn_search = buffer.trim().to_string();
                self.conn_selected = 0;
                self.clamp_connection_selection();
                Action::None
            }
            Some(InputState {
                mode: InputMode::Alias,
                buffer,
                device_id: Some(id),
            }) => Action::SaveAlias {
                id,
                value: valor_opcional(&buffer),
            },
            Some(InputState {
                mode: InputMode::Notes,
                buffer,
                device_id: Some(id),
            }) => Action::SaveNotes {
                id,
                value: valor_opcional(&buffer),
            },
            _ => Action::None,
        }
    }

    /// Añade un carácter al campo de entrada.
    pub fn push_input_char(&mut self, caracter: char) {
        if let Some(input) = self.input.as_mut() {
            input.buffer.push(caracter);
        }
        match self.input.as_ref().map(|i| i.mode) {
            Some(InputMode::Search) => {
                self.selected = 0;
                self.clamp_selection();
            }
            Some(InputMode::ConnectionSearch) => {
                self.conn_selected = 0;
                self.clamp_connection_selection();
            }
            _ => {}
        }
    }

    /// Borra el último carácter del campo de entrada.
    pub fn pop_input_char(&mut self) {
        if let Some(input) = self.input.as_mut() {
            input.buffer.pop();
        }
        match self.input.as_ref().map(|i| i.mode) {
            Some(InputMode::Search) => {
                self.selected = 0;
                self.clamp_selection();
            }
            Some(InputMode::ConnectionSearch) => {
                self.conn_selected = 0;
                self.clamp_connection_selection();
            }
            _ => {}
        }
    }

    /// Cicla la ordenación.
    pub fn cycle_sort(&mut self) {
        if self.tab != Tab::Equipos {
            return;
        }
        self.sort.cycle();
        self.selected = 0;
    }

    /// Cicla el filtro.
    pub fn cycle_filter(&mut self) {
        if self.tab != Tab::Equipos {
            return;
        }
        self.filter = self.filter.cycle();
        if self.filter == Filter::Alert {
            self.push_notification(
                Level::Info,
                "El filtro de alertas no está disponible en Fase 1",
            );
        }
        self.selected = 0;
        self.clamp_selection();
    }

    /// Alterna la vista de la lista de equipos (plana ↔ agrupada).
    ///
    /// Solo tiene efecto en la pestaña Equipos. Devuelve la vista nueva para que
    /// el bucle principal persista la preferencia `[ui].list_view`.
    pub fn toggle_list_view(&mut self) -> Option<ListView> {
        if self.tab != Tab::Equipos {
            return None;
        }
        let seleccionado = self.selected_device().map(|device| device.id);
        self.list_view = self.list_view.toggle();
        if let Some(id) = seleccionado {
            if let Some(posicion) = self
                .visible_indices()
                .iter()
                .position(|indice| self.devices[*indice].id == id)
            {
                self.selected = posicion;
            }
        }
        self.clamp_selection();
        Some(self.list_view)
    }

    /// Indica si el usuario ha activado el modo pasivo consciente.
    pub fn is_passive(&self) -> bool {
        self.config.scan.passive_only
    }

    /// Cicla el tipo de dispositivo manual del equipo seleccionado.
    ///
    /// El ciclo completo es None(auto) → gateway → printer → camera → tv →
    /// streaming → nas → mobile → tablet → server → pc → iot → unknown → None.
    /// Cuando el equipo no tiene override se parte de su tipo automático (no de
    /// None) para que la primera pulsación produzca un cambio visible; por la
    /// misma razón, si el automático es desconocido y el siguiente valor sería
    /// volver a automático, se salta a gateway.
    pub fn cycle_device_type_manual(&mut self) -> Action {
        if self.tab != Tab::Equipos {
            return Action::None;
        }
        let Some((id, manual, automatico)) = self.selected_device().map(|device| {
            (
                device.id,
                device.device_type_manual.clone(),
                device.device_type.clone(),
            )
        }) else {
            self.push_notification(Level::Info, "No hay ningún equipo seleccionado");
            return Action::None;
        };
        let manual = manual.as_deref().and_then(DeviceType::from_str);
        let base = manual
            .or_else(|| DeviceType::from_str(&automatico))
            .unwrap_or(DeviceType::Unknown);
        let mut siguiente = match DeviceType::ALL.iter().position(|tipo| *tipo == base) {
            Some(posicion) if posicion + 1 < DeviceType::ALL.len() => {
                Some(DeviceType::ALL[posicion + 1])
            }
            _ => None,
        };
        // Sin override, volver al automático no cambiaría el icono: se salta a
        // gateway para que la pulsación siempre tenga un efecto visible.
        if manual.is_none() && siguiente.is_none() {
            siguiente = Some(DeviceType::ALL[0]);
        }
        let mensaje = match siguiente {
            Some(tipo) => format!("Tipo manual: {}", tipo.label()),
            None => "Tipo automático".to_string(),
        };
        self.push_notification(Level::Info, mensaje);
        Action::SetDeviceTypeManual {
            id,
            value: siguiente,
        }
    }

    /// Limpia la búsqueda confirmada.
    pub fn clear_search(&mut self) {
        self.search.clear();
        self.selected = 0;
        self.clamp_selection();
    }

    /// Encola una petición de rescaneo. Devuelve false si ya hay uno en curso.
    pub fn request_rescan(&mut self) -> bool {
        if self.scanning {
            self.push_notification(Level::Info, "Ya hay un escaneo en curso");
            return false;
        }
        let enviado = match &self.command_tx {
            Some(tx) => tx.try_send(ScanCommand::Rescan).is_ok(),
            None => false,
        };
        if enviado {
            self.scanning = true;
        } else if self.command_tx.is_some() {
            self.push_notification(Level::Info, "Ya hay un escaneo en curso");
        }
        enviado
    }

    /// Resumen para la barra de estado.
    pub fn status_summary(&self) -> String {
        let total = self.devices.len();
        let online = self.devices.iter().filter(|d| d.is_online).count();
        let offline = total.saturating_sub(online);
        let mut texto = format!("{total} equipos · {online} online · {offline} offline");
        if self.filter != Filter::All {
            texto.push_str(&format!(" · filtro: {}", self.filter.label()));
        }
        let busqueda = self.effective_search();
        if !busqueda.is_empty() {
            texto.push_str(&format!(" · búsqueda: {busqueda:?}"));
        }
        if self.tab == Tab::Equipos {
            texto.push_str(&format!(" · orden: {}", self.sort.label()));
        }
        if self.scanning {
            texto.push_str(" · escaneando…");
        }
        texto
    }

    /// Etiqueta del modo de descubrimiento para la barra de estado.
    ///
    /// El modo pasivo consciente ([scan].passive_only) tiene prioridad sobre la
    /// detección de capacidades porque el usuario ha desactivado el tráfico activo;
    /// si no, se distingue entre privilegiado y degradado según CAP_NET_RAW.
    pub fn mode_label(&self) -> String {
        if self.config.scan.passive_only {
            "modo: pasivo".to_string()
        } else if !self.capabilities.raw_sockets {
            "modo: degradado (sin CAP_NET_RAW)".to_string()
        } else {
            "modo: privilegiado".to_string()
        }
    }

    /// Fuentes de descubrimiento activas según el modo actual.
    ///
    /// En modo pasivo o degradado solo se usan fuentes pasivas; además, con
    /// CAP_NET_RAW y sin `passive_only`, se añaden las activas (ARP, ICMP y
    /// port scan).
    pub fn active_sources(&self) -> Vec<&'static str> {
        let mut fuentes = vec!["/proc", "mDNS", "SSDP", "DHCP", "NetBIOS", "DNS inverso"];
        if !self.config.scan.passive_only && self.capabilities.raw_sockets {
            fuentes.extend(["ARP", "ICMP", "puertos"]);
        }
        fuentes
    }

    /// Procesa una tecla y devuelve la acción a ejecutar.
    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }
        // Pestaña Histórico (F5): consume sus propias teclas (e, w, Tab, <, >,
        // f, /, Enter) antes del manejo general.
        if self.tab == Tab::Historico {
            if let Some(accion) = self.history.history_handle_key(key) {
                return accion;
            }
        }
        // Pestaña Alertas (F6): Tab, Enter, espacio, T, f, u, /, m, e, n, x, 1-3.
        if self.tab == Tab::Alertas {
            if let Some(accion) = self.alerts.handle_key(key) {
                return accion;
            }
        }
        if self.input.is_some() {
            return self.handle_input_key(key);
        }

        // Esc cierra, en orden, los paneles no modales abiertos.
        if key.code == KeyCode::Esc {
            if self.history.close_history_who_uses() {
                return Action::None;
            }
            if self.close_who_uses() {
                return Action::None;
            }
            if self.headers.is_some() {
                self.close_headers();
                return Action::None;
            }
        }

        // En el detalle master-detail, Tab alterna el foco y Esc lo cierra.
        if self.detail.is_some() {
            match key.code {
                KeyCode::Esc => {
                    self.close_detail();
                    return Action::None;
                }
                KeyCode::Tab => {
                    self.toggle_detail_focus();
                    return Action::None;
                }
                _ => {
                    if self.detail_focus == FocusPanel::Detalle {
                        return self.handle_detail_panel_key(key);
                    }
                }
            }
        }

        // Panel «¿Quién lo usa?» del histórico (F5): j/k/Enter/Esc propios.
        if self.history.history_who_uses_open() {
            if let Some(accion) = self.history.handle_history_who_uses_key(key) {
                return accion;
            }
        }

        // Con el panel «¿Quién lo usa?» abierto, j/k mueven su selección.
        if self.who_uses_open() {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_who_uses_selection(1);
                    return Action::None;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_who_uses_selection(-1);
                    return Action::None;
                }
                KeyCode::Home => {
                    if let Some(panel) = self.traffic.who_uses.as_mut() {
                        panel.selected = 0;
                    }
                    return Action::None;
                }
                KeyCode::End => {
                    let total = self
                        .traffic
                        .who_uses
                        .as_ref()
                        .map(|panel| panel.rows.len())
                        .unwrap_or(0);
                    if let Some(panel) = self.traffic.who_uses.as_mut() {
                        panel.selected = total.saturating_sub(1);
                    }
                    return Action::None;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Char('q') => Action::Quit,
            KeyCode::Char('?') => {
                self.tab = Tab::Ayuda;
                Action::None
            }
            KeyCode::Char(c @ '1'..='7') => {
                if let Some(tab) = Tab::from_number(c as u8 - b'0') {
                    self.tab = tab;
                }
                Action::None
            }
            KeyCode::Tab => {
                self.next_tab();
                Action::None
            }
            KeyCode::BackTab => {
                self.previous_tab();
                Action::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection_in_tab(1);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection_in_tab(-1);
                Action::None
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.next_tab();
                Action::None
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.previous_tab();
                Action::None
            }
            KeyCode::Home => {
                self.select_first_in_tab();
                Action::None
            }
            KeyCode::End => {
                self.select_last_in_tab();
                Action::None
            }
            KeyCode::Enter => match self.tab {
                Tab::Equipos => self.open_selected_detail(),
                Tab::Trafico => self.enter_ranking(),
                _ => Action::None,
            },
            KeyCode::Char('/') => {
                self.begin_search();
                Action::None
            }
            KeyCode::Char('s') => {
                match self.tab {
                    Tab::Conexiones => self.cycle_connection_sort(),
                    Tab::Trafico => self.cycle_ranking_sort(),
                    _ => self.cycle_sort(),
                }
                Action::None
            }
            KeyCode::Char('f') => {
                match self.tab {
                    Tab::Conexiones => self.cycle_connection_filter(),
                    _ => self.cycle_filter(),
                }
                Action::None
            }
            KeyCode::Char('v') => {
                if self.tab == Tab::Conexiones {
                    self.open_headers();
                }
                Action::None
            }
            KeyCode::Char('i') => {
                if self.tab == Tab::Conexiones {
                    self.toggle_connection_names();
                }
                Action::None
            }
            KeyCode::Char('g') => match self.tab {
                Tab::Equipos => match self.toggle_list_view() {
                    Some(vista) => Action::SetListView(vista),
                    None => Action::None,
                },
                Tab::Trafico => match self.cycle_traffic_group() {
                    Some(grupo) => Action::SetTrafficGroup(grupo),
                    None => Action::None,
                },
                _ => Action::None,
            },
            KeyCode::Char('w') => {
                if self.tab == Tab::Trafico {
                    self.cycle_traffic_window();
                }
                Action::None
            }
            KeyCode::Char('t') => self.cycle_device_type_manual(),
            // F6: `p` marca o desmarca el equipo seleccionado como vigilado (§7.7).
            KeyCode::Char('p') if self.tab == Tab::Equipos => match self.selected_device() {
                Some(device) => Action::SetWatched {
                    device_id: device.id,
                    watched: !device.watched,
                },
                None => Action::None,
            },
            KeyCode::Char('r') => Action::Rescan,
            KeyCode::Char('a') => {
                self.begin_device_input(InputMode::Alias);
                Action::None
            }
            KeyCode::Char('n') => {
                self.begin_device_input(InputMode::Notes);
                Action::None
            }
            KeyCode::Esc => {
                self.clear_search();
                self.clear_connection_search();
                if self.tab != Tab::Equipos {
                    self.tab = Tab::Equipos;
                }
                Action::None
            }
            _ => Action::None,
        }
    }

    /// Enter en la pestaña Tráfico: detalle, «¿quién lo usa?» o proceso.
    ///
    /// En equipo abre el detalle (drill-down de F3); en proceso abre Conexiones
    /// filtrada; en destino, app, categoría o protocolo abre el panel.
    fn enter_ranking(&mut self) -> Action {
        // Ventanas de 1 h y 24 h (F5): el detalle de equipo y «¿Quién lo usa?»
        // salen del histórico, no de los rankings en memoria.
        if self.traffic_window.history().is_some() {
            if self.traffic_group == Dimension::Device {
                return match self.selected_ranking_row().and_then(|fila| fila.device_id) {
                    Some(device_id) if device_id == crate::traffic::DEVICE_ID_HOST => {
                        self.push_notification(
                            Level::Info,
                            "El tráfico del host no tiene detalle de equipo; consulta la pestaña Conexiones",
                        );
                        Action::None
                    }
                    Some(device_id) => Action::OpenDetail { device_id },
                    None => Action::None,
                };
            }
            if let Some(fila) = self.selected_ranking_row() {
                self.history.ask_who_uses(
                    self.traffic_group,
                    fila.key,
                    fila.label,
                    self.traffic_window,
                );
            }
            return Action::None;
        }
        if self.who_uses_open() {
            return match self.selected_who_uses() {
                Some(cuota) if cuota.device_id == crate::traffic::DEVICE_ID_HOST => {
                    self.push_notification(
                        Level::Info,
                        "El tráfico del host no tiene detalle de equipo; consulta la pestaña Conexiones",
                    );
                    Action::None
                }
                Some(cuota) => Action::OpenDetail {
                    device_id: cuota.device_id,
                },
                None => Action::None,
            };
        }
        match self.traffic_group {
            Dimension::Device => {
                let Some(fila) = self.selected_ranking_row() else {
                    return Action::None;
                };
                match fila.device_id {
                    Some(device_id) if device_id == crate::traffic::DEVICE_ID_HOST => {
                        self.push_notification(
                            Level::Info,
                            "El tráfico del host no tiene detalle de equipo; consulta la pestaña Conexiones",
                        );
                        Action::None
                    }
                    Some(device_id) => Action::OpenDetail { device_id },
                    None => Action::None,
                }
            }
            Dimension::Process => {
                self.filtrar_conexiones_por_proceso();
                Action::None
            }
            _ => match self.open_who_uses() {
                Some((dimension, key, label, window)) => Action::WhoUses {
                    dimension,
                    key,
                    label,
                    window,
                },
                None => Action::None,
            },
        }
    }

    /// Teclas dentro del panel de detalle cuando tiene el foco.
    fn handle_detail_panel_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('q') => Action::Quit,
            KeyCode::Char('?') => {
                self.tab = Tab::Ayuda;
                Action::None
            }
            KeyCode::Char(c @ '1'..='7') => {
                if let Some(tab) = Tab::from_number(c as u8 - b'0') {
                    self.tab = tab;
                }
                Action::None
            }
            KeyCode::Tab => {
                self.toggle_detail_focus();
                Action::None
            }
            KeyCode::Esc => {
                self.close_detail();
                Action::None
            }
            // Histórico del detalle: w alterna 24 h ⇄ 7 días (F5).
            KeyCode::Char('w') => {
                self.history.toggle_detail_history_range();
                self.history.history_refresh();
                Action::None
            }
            // F6: vigilar el equipo desde su detalle (§7.7).
            KeyCode::Char('p') => match self.detail.as_ref().map(|detalle| detalle.device_id) {
                Some(device_id) => Action::SetWatched {
                    device_id,
                    watched: !self
                        .devices
                        .iter()
                        .find(|device| device.id == device_id)
                        .map(|device| device.watched)
                        .unwrap_or(false),
                },
                None => Action::None,
            },
            // Desplazamiento del panel derecho cuando no cabe (F4).
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll_detail(1);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_detail(-1);
                Action::None
            }
            KeyCode::PageDown => {
                self.scroll_detail(10);
                Action::None
            }
            KeyCode::PageUp => {
                self.scroll_detail(-10);
                Action::None
            }
            KeyCode::Home => {
                self.detail_scroll = 0;
                Action::None
            }
            KeyCode::End => {
                self.detail_scroll = self.detail_max_scroll;
                Action::None
            }
            _ => Action::None,
        }
    }

    /// Desplaza el panel de detalle de equipo (j/k cuando tiene el foco).
    pub fn scroll_detail(&mut self, delta: isize) {
        let maximo = self.detail_max_scroll;
        let actual = self.detail_scroll.min(maximo) as isize;
        self.detail_scroll = (actual + delta).clamp(0, maximo as isize) as usize;
    }

    /// Mueve la selección de la pestaña activa.
    fn move_selection_in_tab(&mut self, delta: isize) {
        match self.tab {
            Tab::Equipos => self.move_selection(delta),
            Tab::Trafico => self.move_traffic_selection(delta),
            Tab::Conexiones => self.move_connection_selection(delta),
            _ => {}
        }
    }

    fn select_first_in_tab(&mut self) {
        match self.tab {
            Tab::Equipos => self.select_first(),
            Tab::Trafico => {
                self.traffic_selected = 0;
                *self.traffic_table_state.selected_mut() = Some(0);
            }
            Tab::Conexiones => {
                self.conn_selected = 0;
                *self.conn_table_state.selected_mut() = Some(0);
            }
            _ => {}
        }
    }

    fn select_last_in_tab(&mut self) {
        match self.tab {
            Tab::Equipos => self.select_last(),
            Tab::Trafico => {
                let total = self.ranking_rows().len();
                self.traffic_selected = total.saturating_sub(1);
                *self.traffic_table_state.selected_mut() = Some(self.traffic_selected);
            }
            Tab::Conexiones => {
                let total = self.filtered_connections().len();
                self.conn_selected = total.saturating_sub(1);
                *self.conn_table_state.selected_mut() = Some(self.conn_selected);
            }
            _ => {}
        }
    }

    /// Abre el detalle del equipo seleccionado en la pestaña Equipos.
    fn open_selected_detail(&mut self) -> Action {
        match self.selected_device().map(|device| device.id) {
            Some(device_id) => Action::OpenDetail { device_id },
            None => Action::None,
        }
    }

    fn handle_input_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => {
                self.cancel_input();
                Action::None
            }
            KeyCode::Enter => self.commit_input(),
            KeyCode::Backspace => {
                self.pop_input_char();
                Action::None
            }
            KeyCode::Char(caracter) => {
                if !caracter.is_control() {
                    self.push_input_char(caracter);
                }
                Action::None
            }
            _ => Action::None,
        }
    }

    fn matches(&self, device: &Device) -> bool {
        let estado_ok = match self.filter {
            Filter::All => true,
            Filter::Online => device.is_online,
            Filter::Offline => !device.is_online,
            Filter::New => device.first_seen.as_str() >= self.session_start.as_str(),
            Filter::Alert => false,
        };
        if !estado_ok {
            return false;
        }
        let consulta = self.effective_search().trim().to_lowercase();
        if consulta.is_empty() {
            return true;
        }
        let mut campos = vec![device.ip.to_lowercase(), device.mac.to_lowercase()];
        for valor in [&device.hostname, &device.vendor, &device.alias]
            .into_iter()
            .flatten()
        {
            campos.push(valor.to_lowercase());
        }
        campos.iter().any(|campo| campo.contains(&consulta))
    }

    /// Ajusta la selección al número de filas visibles.
    pub fn clamp_selection(&mut self) {
        let total = self.visible_len();
        if total == 0 {
            self.selected = 0;
        } else if self.selected >= total {
            self.selected = total - 1;
        }
        *self.table_state.selected_mut() = Some(self.selected);
    }
}

/// Compara dos dispositivos por la columna indicada (orden ascendente base).
pub fn comparar(a: &Device, b: &Device, key: SortKey) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match key {
        SortKey::Ip => {
            let ia = clave_ip(&a.ip);
            let ib = clave_ip(&b.ip);
            ia.cmp(&ib)
        }
        SortKey::Hostname => a
            .display_name()
            .to_lowercase()
            .cmp(&b.display_name().to_lowercase()),
        SortKey::Mac => a.mac.cmp(&b.mac),
        SortKey::Vendor => {
            let va = a.vendor.clone().unwrap_or_else(|| "~".to_string());
            let vb = b.vendor.clone().unwrap_or_else(|| "~".to_string());
            va.to_lowercase().cmp(&vb.to_lowercase())
        }
        SortKey::Estado => {
            let ea = if a.is_online {
                Ordering::Less
            } else {
                Ordering::Greater
            };
            let eb = if b.is_online {
                Ordering::Less
            } else {
                Ordering::Greater
            };
            ea.cmp(&eb)
        }
    }
}

fn clave_ip(ip: &str) -> u32 {
    ip.parse::<std::net::Ipv4Addr>()
        .map(u32::from)
        .unwrap_or(u32::MAX)
}

/// Grupo de la vista agrupada al que pertenece un dispositivo.
///
/// Se basa en el tipo efectivo: el override manual manda sobre el automático.
pub(crate) fn grupo_de(device: &Device) -> DeviceGroup {
    DeviceType::from_str(device.effective_device_type())
        .map(group_for)
        .unwrap_or(DeviceGroup::Unknown)
}

fn valor_opcional(buffer: &str) -> Option<String> {
    let recortado = buffer.trim();
    if recortado.is_empty() {
        None
    } else {
        Some(recortado.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn dispositivo(
        id: i64,
        mac: &str,
        ip: &str,
        hostname: Option<&str>,
        vendor: Option<&str>,
        online: bool,
    ) -> Device {
        Device {
            id,
            mac: mac.to_string(),
            ip: ip.to_string(),
            hostname: hostname.map(str::to_string),
            vendor: vendor.map(str::to_string),
            interface_id: 1,
            device_type: "unknown".to_string(),
            is_online: online,
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
            watched: false,
        }
    }

    fn app_con(devices: Vec<Device>) -> App {
        let mut app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: false,
                detail: "sin CAP_NET_RAW".to_string(),
            },
            None,
        );
        app.set_data(devices, Vec::new());
        app
    }

    fn app_con_config(config: Config, raw_sockets: bool) -> App {
        App::new(
            config,
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets,
                detail: if raw_sockets {
                    "CAP_NET_RAW detectada".to_string()
                } else {
                    "sin CAP_NET_RAW".to_string()
                },
            },
            None,
        )
    }

    fn dispositivo_de_tipo(id: i64, ip: &str, device_type: &str, online: bool) -> Device {
        let mut device = dispositivo(id, &format!("aa:bb:cc:dd:ee:0{id}"), ip, None, None, online);
        device.device_type = device_type.to_string();
        device
    }

    fn tecla(codigo: KeyCode) -> KeyEvent {
        KeyEvent::new(codigo, KeyModifiers::NONE)
    }

    #[test]
    fn pestanas_navegan_en_ciclo() {
        assert_eq!(Tab::Equipos.next(), Tab::Trafico);
        assert_eq!(Tab::Ayuda.next(), Tab::Equipos);
        assert_eq!(Tab::Equipos.prev(), Tab::Ayuda);
        assert_eq!(Tab::from_number(1), Some(Tab::Equipos));
        assert_eq!(Tab::from_number(7), Some(Tab::Ayuda));
        assert_eq!(Tab::from_number(8), None);
        assert_eq!(Tab::ALL.len(), 7);
    }

    #[test]
    fn orden_cicla_columnas_y_direccion() {
        let mut sort = SortState::default();
        assert_eq!(sort.key, SortKey::Ip);
        sort.cycle();
        assert_eq!((sort.key, sort.ascending), (SortKey::Ip, false));
        sort.cycle();
        assert_eq!((sort.key, sort.ascending), (SortKey::Hostname, true));
        for _ in 0..8 {
            sort.cycle();
        }
        assert_eq!(sort.key, SortKey::Ip);
        assert!(sort.label().contains('↑') || sort.label().contains('↓'));
    }

    #[test]
    fn filtro_cicla_y_avisa_de_alertas() {
        let mut app = app_con(vec![dispositivo(
            1,
            "aa:bb:cc:dd:ee:01",
            "10.0.0.2",
            None,
            None,
            true,
        )]);
        assert_eq!(app.filter, Filter::All);
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Online);
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Offline);
        app.cycle_filter();
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Alert);
        assert!(app.notifier.current().is_some());
        app.cycle_filter();
        assert_eq!(app.filter, Filter::All);
    }

    #[test]
    fn busca_por_varios_campos() {
        let mut app = app_con(vec![
            dispositivo(
                1,
                "aa:bb:cc:dd:ee:01",
                "10.0.0.2",
                Some("laptop"),
                Some("Apple"),
                true,
            ),
            dispositivo(
                2,
                "aa:bb:cc:dd:ee:02",
                "10.0.0.3",
                Some("nas"),
                Some("Synology"),
                false,
            ),
        ]);
        app.search = "apple".to_string();
        assert_eq!(app.visible_len(), 1);
        app.search = "10.0.0.3".to_string();
        assert_eq!(app.visible_len(), 1);
        app.search = "bb:cc:dd:ee:02".to_string();
        assert_eq!(app.visible_len(), 1);
        app.search = "zzz".to_string();
        assert_eq!(app.visible_len(), 0);
    }

    #[test]
    fn filtro_online_y_offline() {
        let mut app = app_con(vec![
            dispositivo(1, "aa:bb:cc:dd:ee:01", "10.0.0.2", None, None, true),
            dispositivo(2, "aa:bb:cc:dd:ee:02", "10.0.0.3", None, None, false),
        ]);
        app.filter = Filter::Online;
        assert_eq!(app.visible_len(), 1);
        app.filter = Filter::Offline;
        assert_eq!(app.visible_len(), 1);
        app.filter = Filter::New;
        assert_eq!(app.visible_len(), 0, "no hay equipos nuevos en la sesión");
    }

    #[test]
    fn seleccion_respeta_limites() {
        let mut app = app_con(vec![
            dispositivo(1, "aa:bb:cc:dd:ee:01", "10.0.0.2", None, None, true),
            dispositivo(2, "aa:bb:cc:dd:ee:02", "10.0.0.3", None, None, true),
        ]);
        app.move_selection(5);
        assert_eq!(app.selected, 1);
        app.move_selection(-5);
        assert_eq!(app.selected, 0);
        app.select_last();
        assert_eq!(app.selected, 1);
        app.select_first();
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn ordena_por_ip_y_hostname() {
        let mut app = app_con(vec![
            dispositivo(
                1,
                "aa:bb:cc:dd:ee:03",
                "10.0.0.10",
                Some("zeta"),
                None,
                true,
            ),
            dispositivo(2, "aa:bb:cc:dd:ee:01", "10.0.0.2", Some("alfa"), None, true),
        ]);
        let indices = app.visible_indices();
        assert_eq!(app.devices[indices[0]].ip, "10.0.0.2");
        app.sort.key = SortKey::Hostname;
        let indices = app.visible_indices();
        assert_eq!(app.devices[indices[0]].hostname.as_deref(), Some("alfa"));
    }

    #[test]
    fn teclas_de_navegacion_y_pestanas() {
        let mut app = app_con(vec![dispositivo(
            1,
            "aa:bb:cc:dd:ee:01",
            "10.0.0.2",
            None,
            None,
            true,
        )]);
        app.handle_key(tecla(KeyCode::Char('2')));
        assert_eq!(app.tab, Tab::Trafico);
        app.handle_key(tecla(KeyCode::Tab));
        assert_eq!(app.tab, Tab::Conexiones);
        app.handle_key(tecla(KeyCode::BackTab));
        assert_eq!(app.tab, Tab::Trafico);
        app.handle_key(tecla(KeyCode::Char('1')));
        assert_eq!(app.tab, Tab::Equipos);
        app.handle_key(tecla(KeyCode::Char('j')));
        assert_eq!(app.selected, 0);
        app.handle_key(tecla(KeyCode::Char('?')));
        assert_eq!(app.tab, Tab::Ayuda);
    }

    #[test]
    fn busqueda_incremental_se_commitea() {
        let mut app = app_con(vec![
            dispositivo(
                1,
                "aa:bb:cc:dd:ee:01",
                "10.0.0.2",
                Some("laptop"),
                None,
                true,
            ),
            dispositivo(2, "aa:bb:cc:dd:ee:02", "10.0.0.3", Some("nas"), None, true),
        ]);
        app.handle_key(tecla(KeyCode::Char('/')));
        assert!(app.input.is_some());
        for caracter in "laptop".chars() {
            app.handle_key(tecla(KeyCode::Char(caracter)));
        }
        assert_eq!(app.visible_len(), 1);
        app.handle_key(tecla(KeyCode::Enter));
        assert!(app.input.is_none());
        assert_eq!(app.search, "laptop");
        assert_eq!(app.visible_len(), 1);
        app.handle_key(tecla(KeyCode::Char('/')));
        app.handle_key(tecla(KeyCode::Esc));
        assert!(app.search.is_empty());
        app.handle_key(tecla(KeyCode::Char('/')));
        for caracter in "xxx".chars() {
            app.handle_key(tecla(KeyCode::Char(caracter)));
        }
        assert_eq!(app.visible_len(), 0);
        app.handle_key(tecla(KeyCode::Backspace));
        assert_eq!(app.effective_search(), "xx");
    }

    #[test]
    fn alias_y_notas_devuelven_accion() {
        let mut app = app_con(vec![dispositivo(
            7,
            "aa:bb:cc:dd:ee:01",
            "10.0.0.2",
            Some("laptop"),
            None,
            true,
        )]);
        app.handle_key(tecla(KeyCode::Char('a')));
        assert_eq!(app.input.as_ref().map(|i| i.mode), Some(InputMode::Alias));
        for caracter in "portatil".chars() {
            app.push_input_char(caracter);
        }
        assert_eq!(
            app.commit_input(),
            Action::SaveAlias {
                id: 7,
                value: Some("portatil".to_string())
            }
        );
        app.handle_key(tecla(KeyCode::Char('n')));
        assert_eq!(app.input.as_ref().map(|i| i.mode), Some(InputMode::Notes));
        app.push_input_char(' ');
        assert_eq!(app.commit_input(), Action::SaveNotes { id: 7, value: None });
    }

    #[test]
    fn rescan_respeta_estado_de_escaneo() {
        let mut app = app_con(vec![]);
        assert!(!app.request_rescan());
        app.scanning = true;
        assert!(!app.request_rescan());
    }

    #[test]
    fn resumen_y_modo() {
        let app = app_con(vec![
            dispositivo(1, "aa:bb:cc:dd:ee:01", "10.0.0.2", None, None, true),
            dispositivo(2, "aa:bb:cc:dd:ee:02", "10.0.0.3", None, None, false),
        ]);
        let resumen = app.status_summary();
        assert!(resumen.contains("2 equipos"));
        assert!(resumen.contains("1 online"));
        assert!(resumen.contains("1 offline"));
        assert_eq!(app.mode_label(), "modo: degradado (sin CAP_NET_RAW)");
        assert!(app.is_degraded());
    }

    #[test]
    fn enter_devuelve_accion_de_detalle() {
        let mut app = app_con(vec![dispositivo(
            7,
            "aa:bb:cc:dd:ee:01",
            "10.0.0.2",
            None,
            None,
            true,
        )]);
        assert_eq!(
            app.handle_key(tecla(KeyCode::Enter)),
            Action::OpenDetail { device_id: 7 }
        );
    }

    #[test]
    fn enter_sin_equipo_no_devuelve_accion() {
        let mut app = app_con(vec![]);
        assert_eq!(app.handle_key(tecla(KeyCode::Enter)), Action::None);
    }

    #[test]
    fn detalle_tab_alterna_foco_y_esc_cierra() {
        let mut app = app_con(vec![dispositivo(
            3,
            "aa:bb:cc:dd:ee:01",
            "10.0.0.2",
            None,
            None,
            true,
        )]);
        app.open_detail(3, Vec::new(), true);
        assert!(app.detail_open());
        assert_eq!(app.detail_focus, FocusPanel::Detalle);
        app.handle_key(tecla(KeyCode::Tab));
        assert_eq!(app.detail_focus, FocusPanel::Lista);
        app.handle_key(tecla(KeyCode::Tab));
        assert_eq!(app.detail_focus, FocusPanel::Detalle);
        app.handle_key(tecla(KeyCode::Esc));
        assert!(!app.detail_open(), "Esc cierra el detalle");
        assert_eq!(app.tab, Tab::Equipos);
    }

    #[test]
    fn tab_en_detalle_no_cambia_de_pestana() {
        let mut app = app_con(vec![]);
        app.open_detail(1, Vec::new(), false);
        app.handle_key(tecla(KeyCode::Tab));
        assert_eq!(app.tab, Tab::Equipos);
        assert_eq!(app.detail_focus, FocusPanel::Detalle);
    }

    #[test]
    fn escaleras_de_detalle_se_cierran_sin_panico_en_tests() {
        let mut app = app_con(vec![]);
        app.detail = Some(DetailState {
            device_id: 1,
            services: Vec::new(),
        });
        app.handle_key(tecla(KeyCode::Esc));
        assert!(app.detail.is_none());
        app.detail = Some(DetailState {
            device_id: 1,
            services: Vec::new(),
        });
        app.close_detail();
        assert!(app.detail.is_none());
    }

    #[test]
    fn q_y_esc_se_comportan() {
        let mut app = app_con(vec![]);
        assert_eq!(app.handle_key(tecla(KeyCode::Char('q'))), Action::Quit);
        app.tab = Tab::Ayuda;
        app.handle_key(tecla(KeyCode::Esc));
        assert_eq!(app.tab, Tab::Equipos);
    }

    #[test]
    fn comparar_estado_online_primero() {
        let online = dispositivo(1, "aa:bb:cc:dd:ee:01", "10.0.0.2", None, None, true);
        let offline = dispositivo(2, "aa:bb:cc:dd:ee:02", "10.0.0.3", None, None, false);
        assert_eq!(
            comparar(&online, &offline, SortKey::Estado),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            comparar(&offline, &online, SortKey::Estado),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn vista_se_inicializa_desde_config_y_alterna_con_g() {
        let mut config = Config::default();
        config.ui.list_view = ListView::Grouped;
        let mut app = app_con_config(config, false);
        app.set_data(
            vec![dispositivo_de_tipo(1, "10.0.0.1", "gateway", true)],
            Vec::new(),
        );
        assert_eq!(app.list_view, ListView::Grouped);
        assert_eq!(
            app.handle_key(tecla(KeyCode::Char('g'))),
            Action::SetListView(ListView::Flat)
        );
        assert_eq!(app.list_view, ListView::Flat);
        assert_eq!(
            app.handle_key(tecla(KeyCode::Char('g'))),
            Action::SetListView(ListView::Grouped)
        );
        app.tab = Tab::Ayuda;
        assert_eq!(app.handle_key(tecla(KeyCode::Char('g'))), Action::None);
        assert_eq!(app.list_view, ListView::Grouped, "g solo actúa en Equipos");
    }

    #[test]
    fn orden_agrupado_respeta_grupos_y_orden_interno() {
        let mut app = app_con(vec![
            dispositivo_de_tipo(1, "10.0.0.201", "unknown", true),
            dispositivo_de_tipo(2, "10.0.0.20", "printer", true),
            dispositivo_de_tipo(3, "10.0.0.1", "gateway", true),
            dispositivo_de_tipo(4, "10.0.0.42", "pc", true),
            dispositivo_de_tipo(5, "10.0.0.57", "mobile", true),
            dispositivo_de_tipo(6, "10.0.0.10", "nas", true),
        ]);
        app.list_view = ListView::Grouped;
        let ips: Vec<&str> = app
            .visible_indices()
            .iter()
            .map(|indice| app.devices[*indice].ip.as_str())
            .collect();
        assert_eq!(
            ips,
            vec![
                "10.0.0.1",
                "10.0.0.10",
                "10.0.0.42",
                "10.0.0.57",
                "10.0.0.20",
                "10.0.0.201"
            ]
        );
    }

    #[test]
    fn override_manual_manda_en_grupo_y_tipo_efectivo() {
        let mut desconocido = dispositivo_de_tipo(1, "10.0.0.201", "unknown", true);
        desconocido.device_type_manual = Some("printer".to_string());
        let pc = dispositivo_de_tipo(2, "10.0.0.42", "pc", true);
        let mut app = app_con(vec![desconocido, pc]);
        app.list_view = ListView::Grouped;
        let ids: Vec<i64> = app
            .visible_indices()
            .iter()
            .map(|indice| app.devices[*indice].id)
            .collect();
        assert_eq!(ids, vec![2, 1], "el override lo mueve a Impresoras");
        assert_eq!(app.devices[0].effective_device_type(), "printer");
    }

    #[test]
    fn alternar_vista_conserva_el_equipo_seleccionado() {
        let mut app = app_con(vec![
            dispositivo_de_tipo(1, "10.0.0.10", "printer", true),
            dispositivo_de_tipo(2, "10.0.0.20", "pc", true),
        ]);
        assert_eq!(app.selected_device().map(|device| device.id), Some(1));
        app.handle_key(tecla(KeyCode::Char('g')));
        assert_eq!(
            app.selected_device().map(|device| device.id),
            Some(1),
            "la selección sigue al equipo al cambiar de vista"
        );
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn tecla_t_cicla_tipo_manual_y_avisa() {
        let mut app = app_con(vec![dispositivo_de_tipo(7, "10.0.0.7", "gateway", true)]);
        // Sin override parte del tipo automático: gateway -> printer.
        assert_eq!(
            app.handle_key(tecla(KeyCode::Char('t'))),
            Action::SetDeviceTypeManual {
                id: 7,
                value: Some(DeviceType::Printer)
            }
        );
        assert!(app
            .notifier
            .current()
            .expect("notificación del tipo")
            .message
            .contains("Tipo manual: Impresora"));

        app.devices[0].device_type_manual = Some("printer".to_string());
        assert_eq!(
            app.handle_key(tecla(KeyCode::Char('t'))),
            Action::SetDeviceTypeManual {
                id: 7,
                value: Some(DeviceType::Camera)
            }
        );
        app.devices[0].device_type_manual = Some("iot".to_string());
        assert_eq!(
            app.handle_key(tecla(KeyCode::Char('t'))),
            Action::SetDeviceTypeManual {
                id: 7,
                value: Some(DeviceType::Unknown)
            }
        );
        app.devices[0].device_type_manual = Some("unknown".to_string());
        assert_eq!(
            app.handle_key(tecla(KeyCode::Char('t'))),
            Action::SetDeviceTypeManual { id: 7, value: None }
        );
        assert!(app
            .notifier
            .current()
            .expect("notificación del tipo")
            .message
            .contains("Tipo automático"));

        app.tab = Tab::Ayuda;
        assert_eq!(app.handle_key(tecla(KeyCode::Char('t'))), Action::None);
    }

    #[test]
    fn tecla_t_parte_del_automatico_y_salta_el_automatico_sin_override() {
        // Automático desconocido: volver a automático no cambiaría el icono, así
        // que la primera pulsación salta a gateway.
        let mut app = app_con(vec![dispositivo_de_tipo(1, "10.0.0.1", "unknown", true)]);
        assert_eq!(
            app.handle_key(tecla(KeyCode::Char('t'))),
            Action::SetDeviceTypeManual {
                id: 1,
                value: Some(DeviceType::Gateway)
            }
        );

        // Sin equipos seleccionables avisa y no devuelve acción.
        let mut vacia = app_con(vec![]);
        assert_eq!(vacia.handle_key(tecla(KeyCode::Char('t'))), Action::None);
        assert!(vacia
            .notifier
            .current()
            .expect("notificación sin equipo")
            .message
            .contains("No hay ningún equipo"));
    }

    #[test]
    fn modo_pasivo_es_prioritario_y_solo_lista_fuentes_pasivas() {
        let mut config = Config::default();
        config.scan.passive_only = true;
        let app = app_con_config(config, true);
        assert!(app.is_passive());
        assert_eq!(app.mode_label(), "modo: pasivo");
        assert_eq!(
            app.active_sources(),
            vec!["/proc", "mDNS", "SSDP", "DHCP", "NetBIOS", "DNS inverso"]
        );

        // El modo pasivo manda también sin CAP_NET_RAW.
        let mut config = Config::default();
        config.scan.passive_only = true;
        let app = app_con_config(config, false);
        assert_eq!(app.mode_label(), "modo: pasivo");
    }

    #[test]
    fn modo_degradado_y_privilegiado_listan_sus_fuentes() {
        let degradado = app_con_config(Config::default(), false);
        assert_eq!(degradado.mode_label(), "modo: degradado (sin CAP_NET_RAW)");
        assert_eq!(degradado.active_sources().len(), 6);

        let privilegiado = app_con_config(Config::default(), true);
        assert_eq!(privilegiado.mode_label(), "modo: privilegiado");
        let fuentes = privilegiado.active_sources();
        assert_eq!(fuentes.len(), 9);
        assert!(fuentes.contains(&"ARP"));
        assert!(fuentes.contains(&"ICMP"));
        assert!(fuentes.contains(&"puertos"));
    }

    #[test]
    fn el_aviso_de_alerta_importante_dura_diez_segundos() {
        let mut app = app_con(Vec::new());
        app.push_alert_notice("▲ Alerta importante: Equipo nuevo · [5] para verla");
        assert!(app.alert_notice.is_some());
        app.tick();
        assert!(
            app.alert_notice.is_some(),
            "el aviso debe seguir visible antes de 10 s"
        );
        app.alert_notice = Some((
            "viejo".to_string(),
            Instant::now() - ALERT_NOTICE_TTL - Duration::from_secs(1),
        ));
        app.tick();
        assert!(app.alert_notice.is_none(), "el aviso caduca a los 10 s");
    }
}
