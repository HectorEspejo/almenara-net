//! Estado de la pestaña Histórico y de los datos del histórico de la TUI (F5).
//!
//! Este módulo guarda lo último que ha respondido el lector de solo lectura y
//! decide qué consultas hay que pedir. El render nunca toca la base de datos:
//! pinta el último resultado recibido (§4.5 y ADR-60).
//!
//! Cada consulta viaja con un identificador creciente; solo se acepta la
//! respuesta de la última petición en vuelo de cada vista y las obsoletas se
//! descartan (§4.5). Las peticiones se deduplican: mientras hay una en vuelo no
//! se repite y, si cambian los parámetros, la anterior se da por perdida.
//!
//! La vista no conoce [App]: el bucle de la TUI sincroniza el contexto visible
//! con [HistoryState::sync_context] (pestaña, detalle, agrupación y ventana) y
//! le pasa los equipos con [HistoryState::set_devices] para el selector de
//! sujeto y la búsqueda de eventos.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::history::{
    DbStats, Dimension as HistoryDimension, EventFilter, Gap, HistWindow, HistoryQuery,
    HistoryResponse, Inventory, Page, PresenceSpan, PurgeStats, Range, RankingResult, Series,
    SubjectSel, TimelineItem, TopRow,
};
use crate::rankings::{DeviceShare, Dimension, RankRow, Window};
use crate::repo::devices::Device;
use crate::tui::app::{Action, Tab};

/// Filas máximas de cada bloque de «Más tráfico».
pub const MAX_FILAS_TOP: usize = 10;
/// Eventos y sesiones que se piden a la línea de tiempo.
pub const LIMITE_EVENTOS: usize = 200;

/// Panel que tiene el foco en la pestaña Histórico.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoryFocus {
    /// Gráfica de tráfico del rango.
    #[default]
    Grafica,
    /// Panel «Más tráfico».
    MasTrafico,
    /// Panel «Eventos».
    Eventos,
}

impl HistoryFocus {
    /// Siguiente panel del ciclo de Tab.
    pub fn next(self) -> Self {
        match self {
            Self::Grafica => Self::MasTrafico,
            Self::MasTrafico => Self::Eventos,
            Self::Eventos => Self::Grafica,
        }
    }

    /// Etiqueta visible del panel.
    pub fn label(self) -> &'static str {
        match self {
            Self::Grafica => "gráfica",
            Self::MasTrafico => "más tráfico",
            Self::Eventos => "eventos",
        }
    }
}

/// Vistas que pueden tener una consulta en vuelo.
///
/// Es el grano fino de [HistoryView]: «Más tráfico» necesita varios «topes» a la
/// vez (equipos, apps, destinos, organizaciones y países) y cada uno lleva su
/// propio identificador para no mezclar respuestas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Slot {
    /// Serie de la gráfica.
    Series,
    /// Equipos de «Más tráfico» (dimensión total por sujeto).
    TopEquipos,
    /// Apps de «Más tráfico».
    TopApps,
    /// Destinos de «Más tráfico».
    TopDestinos,
    /// Organizaciones de «Más tráfico».
    TopOrganizaciones,
    /// Países de «Más tráfico».
    TopPaises,
    /// Línea de tiempo de eventos y sesiones.
    Timeline,
    /// Cobertura del rango (huecos de la pestaña Histórico).
    Coverage,
    /// Serie de tráfico del detalle de equipo.
    DetailSeries,
    /// Presencia del detalle de equipo.
    Presence,
    /// Inventario del detalle de equipo.
    Inventory,
    /// Ranking de la ventana histórica de Tráfico.
    TrafficRanking,
    /// Cobertura de la ventana histórica de Tráfico.
    TrafficCoverage,
    /// Último evento de la base de datos (línea de Equipos).
    LastEvent,
    /// Estadísticas de la base de datos (pestaña Config).
    DbStats,
    /// «¿Quién lo usa?» de una ventana histórica.
    WhoUses,
}

impl Slot {
    /// Todos los slots, para invalidarlos de golpe.
    const ALL: [Self; 16] = [
        Self::Series,
        Self::TopEquipos,
        Self::TopApps,
        Self::TopDestinos,
        Self::TopOrganizaciones,
        Self::TopPaises,
        Self::Timeline,
        Self::Coverage,
        Self::DetailSeries,
        Self::Presence,
        Self::Inventory,
        Self::TrafficRanking,
        Self::TrafficCoverage,
        Self::LastEvent,
        Self::DbStats,
        Self::WhoUses,
    ];
}

/// Estado de una consulta: en vuelo, obsoleta y último error.
#[derive(Debug, Clone, Default)]
struct SlotState {
    /// Identificador de la consulta en vuelo (None si no hay ninguna).
    in_flight: Option<u64>,
    /// La consulta ha respondido al menos una vez (aunque sea sin filas).
    loaded: bool,
    /// Los datos guardados son de una versión anterior de los parámetros.
    stale: bool,
    /// Último error recibido.
    error: Option<String>,
    /// Instante (segundos Unix) a partir del cual se puede reintentar.
    retry_at: i64,
}

/// Selector de sujeto de la pestaña Histórico (tecla e).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectorState {
    /// Fila seleccionada de la lista filtrada.
    selected: usize,
    /// Texto de búsqueda de equipos (con /).
    query: String,
    /// Se está editando la búsqueda.
    editing: bool,
}

/// Edición de la búsqueda de eventos (tecla /).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BusquedaState {
    /// Texto en edición.
    buffer: String,
}

/// Panel «¿Quién lo usa?» de una ventana del histórico.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryWhoUses {
    /// Dimensión del ranking (la agrupación activa de Tráfico).
    pub dimension: Dimension,
    /// Clave de la fila del ranking.
    pub key: String,
    /// Texto visible de la fila.
    pub label: String,
    /// Ventana consultada (1 h o 24 h).
    pub window: Window,
    /// Equipos que usan la clave, con bytes y porcentaje.
    pub rows: Vec<DeviceShare>,
    /// Fila seleccionada dentro del panel.
    pub selected: usize,
    /// La petición está en curso («Consultando…»).
    pub pending: bool,
}

/// Estado del histórico en la TUI.
#[derive(Debug, Default)]
pub struct HistoryState {
    // --- Contexto sincronizado por el bucle de la TUI ---
    /// Equipos conocidos (id y nombre visible) para el selector y la búsqueda.
    devices: Vec<(i64, String)>,
    /// [history].enabled: sin histórico no se piden rollups.
    enabled: bool,
    /// La pestaña Histórico está visible.
    historico_visible: bool,
    /// La pestaña Config está visible.
    config_visible: bool,
    /// Equipo abierto en el detalle, si lo hay.
    detail_visible: Option<i64>,
    /// La pestaña Tráfico está visible con una ventana histórica.
    traffic_visible: bool,
    /// Agrupación activa de Tráfico.
    traffic_dimension: Dimension,
    /// Ventana histórica activa de Tráfico (None si la ventana es en memoria).
    traffic_window: Option<HistWindow>,

    // --- Estado de la pestaña Histórico ---
    /// Sujeto seleccionado (None = toda la red).
    pub subject: Option<SubjectSel>,
    /// Rango seleccionado con w.
    pub range: Range,
    /// Panel que tiene el foco (Tab).
    pub focus: HistoryFocus,
    /// Punto de la gráfica que muestra el cursor (< y >).
    pub cursor: Option<usize>,
    /// Filtro de la línea de tiempo (f).
    pub filter: EventFilter,
    /// Búsqueda confirmada de eventos (/).
    pub event_search: String,
    /// Selector de sujeto abierto.
    selector: Option<SelectorState>,
    /// Edición de la búsqueda de eventos.
    busqueda: Option<BusquedaState>,
    /// Fila seleccionada de «Más tráfico».
    pub top_selected: usize,
    /// Fila seleccionada de la línea de tiempo.
    pub timeline_selected: usize,

    // --- Datos recibidos ---
    /// Serie de la gráfica.
    pub series: Option<Series>,
    /// Filas de equipos de «Más tráfico».
    top_equipos: Vec<TopRow>,
    /// Filas de apps de «Más tráfico».
    top_apps: Vec<TopRow>,
    /// Filas de destinos de «Más tráfico».
    top_destinos: Vec<TopRow>,
    /// Filas de organizaciones de «Más tráfico».
    top_organizaciones: Vec<TopRow>,
    /// Filas de países de «Más tráfico».
    top_paises: Vec<TopRow>,
    /// Línea de tiempo de eventos y sesiones.
    timeline: Vec<TimelineItem>,
    /// Huecos de cobertura del rango.
    coverage: Option<Vec<Gap>>,
    /// Serie de tráfico del detalle (24 h o 7 días).
    pub detail_series: Option<Series>,
    /// Presencia del detalle.
    pub detail_presence: Option<Vec<PresenceSpan>>,
    /// Inventario del detalle.
    pub detail_inventory: Option<Inventory>,
    /// Rango del bloque de histórico del detalle.
    pub detail_range: Range,
    /// Ranking de la ventana histórica de Tráfico.
    pub traffic_ranking: Option<RankingResult>,
    /// Huecos de cobertura de la ventana histórica de Tráfico.
    traffic_coverage: Option<Vec<Gap>>,
    /// Último evento de dispositivo (línea «Último evento» de Equipos).
    pub last_event: Option<TimelineItem>,
    /// Estadísticas de la base de datos para Config.
    pub db_stats: Option<DbStats>,
    /// Última purga para Config.
    pub last_purge: Option<PurgeStats>,
    /// La base de datos supera [history].max_db_mb.
    pub db_over_limit: bool,
    /// Panel «¿Quién lo usa?» de una ventana histórica.
    pub who_uses: Option<HistoryWhoUses>,
    /// Instante del último [HistoryState::history_pending_requests].
    last_now: i64,

    // --- Control de peticiones ---
    /// Estado por vista consultada.
    slots: HashMap<Slot, SlotState>,
    /// Identificador en vuelo → vista (para descartar respuestas viejas).
    pending: HashMap<u64, Slot>,
    /// Contador de peticiones.
    next_id: u64,
}

impl HistoryState {
    /// Crea el estado vacío (equivale a Default).
    pub fn new() -> Self {
        Self {
            detail_range: Range::Hours24,
            ..Self::default()
        }
    }

    // ------------------------------------------------------------------
    // Contexto y configuración
    // ------------------------------------------------------------------

    /// Sincroniza el contexto de la TUI (pestaña, detalle, agrupación, ventana).
    ///
    /// Al entrar en una vista se marcan sus datos como obsoletos para pedirlos
    /// frescos; no hace falta que el bucle avise de cada cambio de pestaña.
    pub fn sync_context(
        &mut self,
        tab: Tab,
        detail_device: Option<i64>,
        traffic_group: Dimension,
        traffic_window: Window,
    ) {
        let historico = tab == Tab::Historico;
        if historico && !self.historico_visible {
            self.invalidate_historico();
        }
        self.historico_visible = historico;

        let config = tab == Tab::Config;
        if config && !self.config_visible {
            self.mark_stale(Slot::DbStats);
        }
        self.config_visible = config;

        if detail_device != self.detail_visible {
            self.detail_visible = detail_device;
            if detail_device.is_some() {
                self.invalidate_detail();
            }
        }

        let ventana = traffic_window.history();
        if ventana != self.traffic_window || traffic_group != self.traffic_dimension {
            self.traffic_window = ventana;
            self.traffic_dimension = traffic_group;
            self.who_uses = None;
            self.invalidate_traffic();
        }
        let visible = tab == Tab::Trafico && ventana.is_some();
        if visible && !self.traffic_visible {
            self.invalidate_traffic();
        }
        self.traffic_visible = visible;
    }

    /// Actualiza los equipos para el selector de sujeto y la búsqueda.
    pub fn set_devices(&mut self, devices: &[Device]) {
        self.devices = devices
            .iter()
            .map(|device| (device.id, device.display_name().to_string()))
            .collect();
    }

    /// Indica si el histórico está activo en la configuración.
    pub fn set_history_enabled(&mut self, enabled: bool) {
        if enabled != self.enabled {
            self.enabled = enabled;
            if enabled {
                // Al activarlo, todo lo guardado puede ser de una sesión anterior.
                self.history_refresh();
            }
        }
    }

    /// Actualiza las estadísticas de la base de datos y de la última purga.
    #[allow(dead_code)]
    pub fn set_runtime_stats(
        &mut self,
        db_stats: DbStats,
        last_purge: Option<PurgeStats>,
        over_limit: bool,
    ) {
        self.db_stats = Some(db_stats);
        self.last_purge = last_purge;
        self.db_over_limit = over_limit;
    }

    /// Ventana histórica activa en Tráfico, si la hay.
    pub fn current_window(&self) -> Option<HistWindow> {
        self.traffic_window
    }

    // ------------------------------------------------------------------
    // Invalidación y peticiones
    // ------------------------------------------------------------------

    /// Marca los datos como obsoletos tras un lote o al cambiar de contexto.
    pub fn history_refresh(&mut self) {
        for slot in Slot::ALL {
            self.mark_stale(slot);
        }
    }

    /// Marca los datos de la pestaña Histórico como obsoletos.
    fn invalidate_historico(&mut self) {
        for slot in [
            Slot::Series,
            Slot::TopEquipos,
            Slot::TopApps,
            Slot::TopDestinos,
            Slot::TopOrganizaciones,
            Slot::TopPaises,
            Slot::Timeline,
            Slot::Coverage,
        ] {
            self.mark_stale(slot);
        }
    }

    /// Marca los datos del detalle como obsoletos.
    fn invalidate_detail(&mut self) {
        for slot in [Slot::DetailSeries, Slot::Presence, Slot::Inventory] {
            self.mark_stale(slot);
        }
    }

    /// Marca los datos de la ventana histórica de Tráfico como obsoletos.
    fn invalidate_traffic(&mut self) {
        for slot in [Slot::TrafficRanking, Slot::TrafficCoverage] {
            self.mark_stale(slot);
        }
    }

    /// Marca un slot como obsoleto y descarta la respuesta que estuviera en vuelo.
    fn mark_stale(&mut self, slot: Slot) {
        let state = self.slots.entry(slot).or_default();
        state.in_flight = None;
        state.stale = true;
        state.error = None;
        state.retry_at = 0;
        self.pending.retain(|_, pendiente| *pendiente != slot);
    }

    /// Indica si un slot ya ha respondido alguna vez (aunque sea sin filas).
    fn has_data(&self, slot: Slot) -> bool {
        self.slots
            .get(&slot)
            .map(|state| state.loaded)
            .unwrap_or(false)
    }

    /// Indica si un slot espera su primera respuesta (y no ha fallado).
    fn cargando(&self, slot: Slot) -> bool {
        let state = self.slots.get(&slot).cloned().unwrap_or_default();
        !state.loaded && state.error.is_none()
    }

    /// Indica si alguno de los slots de «Más tráfico» está cargando.
    pub fn top_cargando(&self) -> bool {
        [
            Slot::TopEquipos,
            Slot::TopApps,
            Slot::TopDestinos,
            Slot::TopOrganizaciones,
            Slot::TopPaises,
        ]
        .into_iter()
        .any(|slot| self.cargando(slot))
    }

    /// Indica si la línea de tiempo está cargando.
    pub fn timeline_cargando(&self) -> bool {
        self.cargando(Slot::Timeline)
    }

    /// Indica si la serie de la gráfica está cargando.
    pub fn serie_cargando(&self) -> bool {
        self.cargando(Slot::Series)
    }

    /// Indica si un slot ya tiene datos válidos y no necesita otra consulta.
    fn necesita(&self, slot: Slot, now: i64) -> bool {
        let state = self.slots.get(&slot).cloned().unwrap_or_default();
        if state.in_flight.is_some() || now < state.retry_at {
            return false;
        }
        !self.has_data(slot) || state.stale
    }

    /// Encola una consulta y anota su identificador como el último en vuelo.
    fn pedir(&mut self, slot: Slot, consulta: HistoryQuery, out: &mut Vec<(u64, HistoryQuery)>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let state = self.slots.entry(slot).or_default();
        state.in_flight = Some(id);
        state.stale = false;
        state.error = None;
        state.retry_at = 0;
        self.pending.insert(id, slot);
        out.push((id, consulta));
    }

    /// Consultas que hay que lanzar al lector para lo que esté visible (§4.5).
    pub fn history_pending_requests(&mut self, now: i64) -> Vec<(u64, HistoryQuery)> {
        self.last_now = now;
        let mut out = Vec::new();

        // El último evento es de F1 y se muestra también con el histórico
        // desactivado: alimenta la línea de Equipos.
        if self.necesita(Slot::LastEvent, now) {
            self.pedir(Slot::LastEvent, HistoryQuery::LastEvent, &mut out);
        }

        if !self.enabled {
            // Sin rollups ni inventario siguen existiendo los eventos y las
            // sesiones: la línea de tiempo y la presencia se pueden consultar.
            if self.historico_visible && self.necesita(Slot::Timeline, now) {
                self.pedir_timeline(now, &mut out);
            }
            if let Some(device_id) = self.detail_visible {
                if self.necesita(Slot::Presence, now) {
                    self.pedir(
                        Slot::Presence,
                        HistoryQuery::Presence {
                            device_id,
                            range: self.detail_range,
                            now,
                        },
                        &mut out,
                    );
                }
            }
            if self.config_visible && self.necesita(Slot::DbStats, now) {
                self.pedir(Slot::DbStats, HistoryQuery::DbStats, &mut out);
            }
            return out;
        }

        if self.historico_visible {
            self.pedir_historico(now, &mut out);
        }
        if let Some(device_id) = self.detail_visible {
            self.pedir_detalle(device_id, now, &mut out);
        }
        if self.traffic_visible {
            self.pedir_trafico(now, &mut out);
        }
        if self.config_visible && self.necesita(Slot::DbStats, now) {
            self.pedir(Slot::DbStats, HistoryQuery::DbStats, &mut out);
        }
        let panel = self
            .who_uses
            .as_ref()
            .filter(|panel| panel.pending)
            .map(|panel| (panel.dimension, panel.key.clone(), panel.window));
        if let Some((dimension, key, window)) = panel {
            if self.necesita(Slot::WhoUses, now) {
                let consulta = HistoryQuery::WhoUses {
                    dimension: dimension_historica(dimension),
                    key,
                    window: self
                        .traffic_window
                        .or_else(|| window.history())
                        .unwrap_or(HistWindow::OneHour),
                    now_minute: crate::history::localtime::minute_start(now),
                };
                self.pedir(Slot::WhoUses, consulta, &mut out);
            }
        }
        out
    }

    /// Peticiones de la pestaña Histórico para su sujeto y rango.
    fn pedir_historico(&mut self, now: i64, out: &mut Vec<(u64, HistoryQuery)>) {
        let subject = self.subject_actual();
        let range = self.range;
        if self.necesita(Slot::Series, now) {
            self.pedir(
                Slot::Series,
                HistoryQuery::Series {
                    subject,
                    range,
                    now,
                },
                out,
            );
        }
        match subject {
            SubjectSel::Network => {
                if self.necesita(Slot::TopEquipos, now) {
                    self.pedir(
                        Slot::TopEquipos,
                        HistoryQuery::Top {
                            subject,
                            dimension: HistoryDimension::Total,
                            range,
                            n: MAX_FILAS_TOP,
                            now,
                        },
                        out,
                    );
                }
                if self.necesita(Slot::TopApps, now) {
                    self.pedir(
                        Slot::TopApps,
                        HistoryQuery::Top {
                            subject,
                            dimension: HistoryDimension::App,
                            range,
                            n: MAX_FILAS_TOP,
                            now,
                        },
                        out,
                    );
                }
            }
            SubjectSel::Host | SubjectSel::Device(_) => {
                if self.necesita(Slot::TopApps, now) {
                    self.pedir(
                        Slot::TopApps,
                        HistoryQuery::Top {
                            subject,
                            dimension: HistoryDimension::App,
                            range,
                            n: MAX_FILAS_TOP,
                            now,
                        },
                        out,
                    );
                }
                if range.admite_destinos() && self.necesita(Slot::TopDestinos, now) {
                    self.pedir(
                        Slot::TopDestinos,
                        HistoryQuery::Top {
                            subject,
                            dimension: HistoryDimension::Destination,
                            range,
                            n: MAX_FILAS_TOP,
                            now,
                        },
                        out,
                    );
                }
                if self.necesita(Slot::TopOrganizaciones, now) {
                    self.pedir(
                        Slot::TopOrganizaciones,
                        HistoryQuery::Top {
                            subject,
                            dimension: HistoryDimension::Org,
                            range,
                            n: MAX_FILAS_TOP,
                            now,
                        },
                        out,
                    );
                }
                if self.necesita(Slot::TopPaises, now) {
                    self.pedir(
                        Slot::TopPaises,
                        HistoryQuery::Top {
                            subject,
                            dimension: HistoryDimension::Country,
                            range,
                            n: MAX_FILAS_TOP,
                            now,
                        },
                        out,
                    );
                }
            }
        }
        if self.necesita(Slot::Timeline, now) {
            self.pedir_timeline(now, out);
        }
        if self.necesita(Slot::Coverage, now) {
            self.pedir(Slot::Coverage, HistoryQuery::Coverage { range, now }, out);
        }
    }

    /// Petición de la línea de tiempo con el filtro y el rango activos.
    fn pedir_timeline(&mut self, now: i64, out: &mut Vec<(u64, HistoryQuery)>) {
        self.pedir(
            Slot::Timeline,
            HistoryQuery::Timeline {
                filter: self.filter,
                range: self.range,
                page: Page {
                    limit: LIMITE_EVENTOS,
                    offset: 0,
                },
                now,
            },
            out,
        );
    }

    /// Peticiones del detalle de equipo: serie, presencia e inventario.
    fn pedir_detalle(&mut self, device_id: i64, now: i64, out: &mut Vec<(u64, HistoryQuery)>) {
        let range = self.detail_range;
        if self.necesita(Slot::DetailSeries, now) {
            self.pedir(
                Slot::DetailSeries,
                HistoryQuery::Series {
                    subject: SubjectSel::Device(device_id),
                    range,
                    now,
                },
                out,
            );
        }
        if self.necesita(Slot::Presence, now) {
            self.pedir(
                Slot::Presence,
                HistoryQuery::Presence {
                    device_id,
                    range,
                    now,
                },
                out,
            );
        }
        if self.necesita(Slot::Inventory, now) {
            self.pedir(Slot::Inventory, HistoryQuery::Inventory { device_id }, out);
        }
    }

    /// Peticiones de la ventana histórica de Tráfico.
    fn pedir_trafico(&mut self, now: i64, out: &mut Vec<(u64, HistoryQuery)>) {
        let Some(window) = self.traffic_window else {
            return;
        };
        let dimension = dimension_historica(self.traffic_dimension);
        if self.necesita(Slot::TrafficRanking, now) {
            self.pedir(
                Slot::TrafficRanking,
                HistoryQuery::WindowRanking {
                    dimension,
                    window,
                    now_minute: crate::history::localtime::minute_start(now),
                },
                out,
            );
        }
        if self.necesita(Slot::TrafficCoverage, now) {
            self.pedir(
                Slot::TrafficCoverage,
                HistoryQuery::Coverage {
                    range: Range::Hours24,
                    now,
                },
                out,
            );
        }
    }

    /// Guarda el resultado de una consulta si no es obsoleto (§4.5).
    pub fn apply_history_response(
        &mut self,
        id: u64,
        response: &std::result::Result<HistoryResponse, String>,
    ) {
        let Some(slot) = self.pending.remove(&id) else {
            return;
        };
        let Some(state) = self.slots.get(&slot).cloned() else {
            return;
        };
        if state.in_flight != Some(id) {
            // Llegó tarde: ya hay otra petición más nueva para esta vista.
            return;
        }
        if let Some(entry) = self.slots.get_mut(&slot) {
            entry.in_flight = None;
        }
        match response {
            Ok(respuesta) => {
                let guardado = self.guardar(slot, respuesta);
                if let Some(entry) = self.slots.get_mut(&slot) {
                    if guardado {
                        entry.loaded = true;
                        entry.stale = false;
                        entry.error = None;
                        entry.retry_at = 0;
                    } else {
                        // Respuesta de otra vista: se descarta y se reintenta.
                        entry.stale = true;
                    }
                }
            }
            Err(mensaje) => {
                if let Some(entry) = self.slots.get_mut(&slot) {
                    entry.stale = false;
                    // No se reintenta hasta el próximo refresco (lote del minuto o
                    // cambio de vista): un error del lector no puede martillear.
                    entry.retry_at = i64::MAX;
                    entry.error = Some(mensaje.clone());
                }
            }
        }
    }

    /// Guarda una respuesta en el campo que le corresponde.
    ///
    /// Devuelve false si la respuesta no encaja con la vista del slot (no debería
    /// pasar: el lector responde al tipo de la consulta).
    fn guardar(&mut self, slot: Slot, response: &HistoryResponse) -> bool {
        match (slot, response) {
            (Slot::Series, HistoryResponse::Series(series)) => {
                self.cursor = cursor_por_defecto(series);
                self.series = Some(series.clone());
            }
            (Slot::TopEquipos, HistoryResponse::Top(filas)) => self.top_equipos = filas.clone(),
            (Slot::TopApps, HistoryResponse::Top(filas)) => self.top_apps = filas.clone(),
            (Slot::TopDestinos, HistoryResponse::Top(filas)) => self.top_destinos = filas.clone(),
            (Slot::TopOrganizaciones, HistoryResponse::Top(filas)) => {
                self.top_organizaciones = filas.clone()
            }
            (Slot::TopPaises, HistoryResponse::Top(filas)) => self.top_paises = filas.clone(),
            (Slot::Timeline, HistoryResponse::Timeline(items)) => {
                self.timeline = items.clone();
                self.clamp_selecciones();
            }
            (Slot::Coverage, HistoryResponse::Coverage(huecos)) => {
                self.coverage = Some(huecos.clone())
            }
            (Slot::DetailSeries, HistoryResponse::Series(series)) => {
                self.detail_series = Some(series.clone())
            }
            (Slot::Presence, HistoryResponse::Presence(tramos)) => {
                self.detail_presence = Some(tramos.clone())
            }
            (Slot::Inventory, HistoryResponse::Inventory(inventario)) => {
                self.detail_inventory = Some((**inventario).clone());
            }
            (Slot::TrafficRanking, HistoryResponse::WindowRanking(ranking)) => {
                self.traffic_ranking = Some(ranking.clone())
            }
            (Slot::TrafficCoverage, HistoryResponse::Coverage(huecos)) => {
                self.traffic_coverage = Some(huecos.clone())
            }
            (Slot::LastEvent, HistoryResponse::LastEvent(evento)) => {
                self.last_event = evento.clone()
            }
            (Slot::DbStats, HistoryResponse::DbStats(stats)) => self.db_stats = Some(stats.clone()),
            (Slot::WhoUses, HistoryResponse::WhoUses(cuotas)) => {
                if let Some(panel) = self.who_uses.as_mut() {
                    panel.rows = cuotas.clone();
                    panel.selected = 0;
                    panel.pending = false;
                }
            }
            _ => return false,
        }
        true
    }

    /// Indica si el slot pertenece a una vista visible ahora mismo.
    fn slot_visible(&self, slot: Slot) -> bool {
        match slot {
            Slot::Series
            | Slot::TopEquipos
            | Slot::TopApps
            | Slot::TopDestinos
            | Slot::TopOrganizaciones
            | Slot::TopPaises
            | Slot::Timeline
            | Slot::Coverage => self.historico_visible,
            Slot::DetailSeries | Slot::Presence | Slot::Inventory => self.detail_visible.is_some(),
            Slot::TrafficRanking | Slot::TrafficCoverage => self.traffic_visible,
            Slot::DbStats => self.config_visible,
            Slot::WhoUses => self.who_uses.is_some(),
            Slot::LastEvent => false,
        }
    }

    /// Error visible de la vista o del detalle, si lo hay.
    ///
    /// Solo cuenta el error de las vistas visibles: el fallo de una consulta de
    /// otra pestaña no debe ensuciar la que se está mirando.
    pub fn error_actual(&self) -> Option<&str> {
        for slot in Slot::ALL {
            if !self.slot_visible(slot) {
                continue;
            }
            if let Some(state) = self.slots.get(&slot) {
                if let Some(error) = &state.error {
                    return Some(error);
                }
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Acciones del usuario en la pestaña Histórico
    // ------------------------------------------------------------------

    /// Procesa una tecla de la pestaña Histórico.
    ///
    /// Devuelve None si la tecla no es de esta vista (el bucle sigue con el
    /// manejo general) y Some(acción) si la consume.
    pub fn history_handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        if self.selector.is_some() {
            return Some(self.handle_selector_key(key));
        }
        if self.busqueda.is_some() {
            return Some(self.handle_busqueda_key(key));
        }
        match key.code {
            KeyCode::Char('e') => {
                let opciones = self.opciones_sujeto();
                let actual = self.subject_actual();
                let selected = opciones
                    .iter()
                    .position(|(sujeto, _)| *sujeto == actual)
                    .unwrap_or(0);
                self.selector = Some(SelectorState {
                    selected,
                    query: String::new(),
                    editing: false,
                });
                Some(Action::None)
            }
            KeyCode::Char('w') => {
                self.range = self.range.next();
                self.cursor = None;
                self.top_selected = 0;
                self.invalidate_historico();
                Some(Action::None)
            }
            KeyCode::Tab => {
                self.focus = self.focus.next();
                Some(Action::None)
            }
            KeyCode::Char('<') => {
                self.mover_cursor(-1);
                Some(Action::None)
            }
            KeyCode::Char('>') => {
                self.mover_cursor(1);
                Some(Action::None)
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.timeline_selected = 0;
                self.mark_stale(Slot::Timeline);
                Some(Action::None)
            }
            KeyCode::Char('/') => {
                self.busqueda = Some(BusquedaState {
                    buffer: self.event_search.clone(),
                });
                self.focus = HistoryFocus::Eventos;
                Some(Action::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.mover_seleccion(1);
                Some(Action::None)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.mover_seleccion(-1);
                Some(Action::None)
            }
            KeyCode::Home => {
                self.seleccionar_primera();
                Some(Action::None)
            }
            KeyCode::End => {
                self.seleccionar_ultima();
                Some(Action::None)
            }
            KeyCode::Enter => Some(self.abrir_detalle_seleccion().unwrap_or(Action::None)),
            _ => None,
        }
    }

    /// Teclas del selector de sujeto (e).
    fn handle_selector_key(&mut self, key: KeyEvent) -> Action {
        let editing = self
            .selector
            .as_ref()
            .map(|selector| selector.editing)
            .unwrap_or(false);
        match key.code {
            KeyCode::Esc => {
                let editing = self
                    .selector
                    .as_ref()
                    .map(|selector| selector.editing)
                    .unwrap_or(false);
                if editing {
                    if let Some(selector) = self.selector.as_mut() {
                        selector.editing = false;
                        selector.query.clear();
                        selector.selected = 0;
                    }
                } else {
                    self.selector = None;
                }
            }
            KeyCode::Char('/')
                if self
                    .selector
                    .as_ref()
                    .map(|selector| !selector.editing)
                    .unwrap_or(false) =>
            {
                if let Some(selector) = self.selector.as_mut() {
                    selector.editing = true;
                    selector.selected = 0;
                }
            }
            KeyCode::Char('j') if !editing => {
                let total = self.opciones_filtradas().len();
                if total > 0 {
                    if let Some(selector) = self.selector.as_mut() {
                        selector.selected = (selector.selected + 1) % total;
                    }
                }
            }
            KeyCode::Char('k') if !editing => {
                let total = self.opciones_filtradas().len();
                if total > 0 {
                    if let Some(selector) = self.selector.as_mut() {
                        selector.selected = (selector.selected + total - 1) % total;
                    }
                }
            }
            KeyCode::Char(caracter) => {
                if editing && !caracter.is_control() {
                    if let Some(selector) = self.selector.as_mut() {
                        selector.query.push(caracter);
                        selector.selected = 0;
                    }
                    self.clamp_selector();
                }
            }
            KeyCode::Backspace => {
                if editing {
                    if let Some(selector) = self.selector.as_mut() {
                        selector.query.pop();
                        selector.selected = 0;
                    }
                    self.clamp_selector();
                }
            }
            KeyCode::Down => {
                let total = self.opciones_filtradas().len();
                if total > 0 {
                    if let Some(selector) = self.selector.as_mut() {
                        selector.selected = (selector.selected + 1) % total;
                    }
                }
            }
            KeyCode::Up => {
                let total = self.opciones_filtradas().len();
                if total > 0 {
                    if let Some(selector) = self.selector.as_mut() {
                        selector.selected = (selector.selected + total - 1) % total;
                    }
                }
            }
            KeyCode::Enter => {
                let posicion = self
                    .selector
                    .as_ref()
                    .map(|selector| selector.selected)
                    .unwrap_or(0);
                let elegido = self
                    .opciones_filtradas()
                    .get(posicion)
                    .map(|(sujeto, _)| *sujeto);
                if let Some(sujeto) = elegido {
                    self.subject = Some(sujeto);
                    self.selector = None;
                    self.cursor = None;
                    self.top_selected = 0;
                    self.timeline_selected = 0;
                    self.invalidate_historico();
                }
            }
            _ => {}
        }
        Action::None
    }

    /// Teclas de la búsqueda de eventos (/).
    fn handle_busqueda_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => self.busqueda = None,
            KeyCode::Enter => {
                let texto = self
                    .busqueda
                    .as_ref()
                    .map(|busqueda| busqueda.buffer.trim().to_string())
                    .unwrap_or_default();
                self.event_search = texto;
                self.busqueda = None;
                self.timeline_selected = 0;
                self.clamp_selecciones();
            }
            KeyCode::Backspace => {
                if let Some(busqueda) = self.busqueda.as_mut() {
                    busqueda.buffer.pop();
                }
                self.timeline_selected = 0;
            }
            KeyCode::Char(caracter) if !caracter.is_control() => {
                if let Some(busqueda) = self.busqueda.as_mut() {
                    busqueda.buffer.push(caracter);
                }
                self.timeline_selected = 0;
            }
            _ => {}
        }
        Action::None
    }

    /// Mueve el cursor de la gráfica.
    fn mover_cursor(&mut self, delta: isize) {
        if self.focus != HistoryFocus::Grafica {
            return;
        }
        let total = self
            .series
            .as_ref()
            .map(|series| series.points.len())
            .unwrap_or(0);
        if total == 0 {
            self.cursor = None;
            return;
        }
        let actual = self.cursor.unwrap_or(0).min(total - 1) as isize;
        self.cursor = Some((actual + delta).clamp(0, total as isize - 1) as usize);
    }

    /// Mueve la selección del panel con foco.
    fn mover_seleccion(&mut self, delta: isize) {
        match self.focus {
            HistoryFocus::Grafica => {}
            HistoryFocus::MasTrafico => self.mover_top_seleccion(delta),
            HistoryFocus::Eventos => self.mover_timeline_seleccion(delta),
        }
    }

    /// Primer elemento del panel con foco.
    fn seleccionar_primera(&mut self) {
        match self.focus {
            HistoryFocus::Grafica => self.cursor = Some(0),
            HistoryFocus::MasTrafico => self.top_selected = 0,
            HistoryFocus::Eventos => self.timeline_selected = 0,
        }
    }

    /// Último elemento del panel con foco.
    fn seleccionar_ultima(&mut self) {
        match self.focus {
            HistoryFocus::Grafica => {
                self.cursor = self
                    .series
                    .as_ref()
                    .map(|series| series.points.len().saturating_sub(1));
            }
            HistoryFocus::MasTrafico => {
                self.top_selected = self.top_total_filas().saturating_sub(1);
            }
            HistoryFocus::Eventos => {
                self.timeline_selected = self.timeline_visible().len().saturating_sub(1);
            }
        }
    }

    /// Abre el detalle del equipo seleccionado o del evento seleccionado.
    fn abrir_detalle_seleccion(&self) -> Option<Action> {
        let device_id = match self.focus {
            HistoryFocus::Grafica => return None,
            HistoryFocus::MasTrafico => self.selected_top_row().and_then(|fila| fila.device_id),
            HistoryFocus::Eventos => self
                .selected_timeline_item()
                .and_then(|item| item.device_id),
        }?;
        Some(Action::OpenDetail { device_id })
    }

    // ------------------------------------------------------------------
    // Acceso a los datos para las vistas
    // ------------------------------------------------------------------

    /// Sujeto activo (la red entera si no se ha elegido otro).
    pub fn subject_actual(&self) -> SubjectSel {
        self.subject.unwrap_or(SubjectSel::Network)
    }

    /// Etiqueta del sujeto activo.
    pub fn subject_label(&self) -> String {
        self.label_de_sujeto(self.subject_actual())
    }

    /// Etiqueta visible de un sujeto.
    pub fn label_de_sujeto(&self, sujeto: SubjectSel) -> String {
        match sujeto {
            SubjectSel::Network => "Toda la red".to_string(),
            SubjectSel::Host => "Este equipo".to_string(),
            SubjectSel::Device(id) => self
                .devices
                .iter()
                .find(|(device_id, _)| *device_id == id)
                .map(|(_, nombre)| nombre.clone())
                .unwrap_or_else(|| format!("Equipo #{id}")),
        }
    }

    /// Opciones del selector de sujeto: toda la red, este equipo y los equipos.
    fn opciones_sujeto(&self) -> Vec<(SubjectSel, String)> {
        let mut opciones = vec![
            (SubjectSel::Network, "Toda la red".to_string()),
            (SubjectSel::Host, "Este equipo".to_string()),
        ];
        for (id, nombre) in &self.devices {
            opciones.push((SubjectSel::Device(*id), nombre.clone()));
        }
        opciones
    }

    /// Opciones del selector filtradas por la búsqueda.
    fn opciones_filtradas(&self) -> Vec<(SubjectSel, String)> {
        let Some(selector) = &self.selector else {
            return Vec::new();
        };
        let consulta = selector.query.trim().to_lowercase();
        self.opciones_sujeto()
            .into_iter()
            .filter(|(_, nombre)| consulta.is_empty() || nombre.to_lowercase().contains(&consulta))
            .collect()
    }

    /// Ajusta la selección del selector a las opciones filtradas.
    fn clamp_selector(&mut self) {
        let total = self.opciones_filtradas().len();
        if let Some(selector) = self.selector.as_mut() {
            if total == 0 {
                selector.selected = 0;
            } else if selector.selected >= total {
                selector.selected = total - 1;
            }
        }
    }

    /// Indica si el selector de sujeto está abierto.
    pub fn selector_abierto(&self) -> bool {
        self.selector.is_some()
    }

    /// Indica si se está editando la búsqueda del selector.
    pub fn selector_editando(&self) -> bool {
        self.selector
            .as_ref()
            .map(|selector| selector.editing)
            .unwrap_or(false)
    }

    /// Texto de búsqueda del selector.
    pub fn selector_consulta(&self) -> &str {
        self.selector
            .as_ref()
            .map(|selector| selector.query.as_str())
            .unwrap_or("")
    }

    /// Filas del selector: etiqueta visible y si está seleccionada.
    pub fn selector_filas(&self) -> Vec<(String, bool)> {
        let selected = self.selector.as_ref().map(|s| s.selected).unwrap_or(0);
        self.opciones_filtradas()
            .into_iter()
            .enumerate()
            .map(|(posicion, (_, nombre))| (nombre, posicion == selected))
            .collect()
    }

    /// Indica si se está editando la búsqueda de eventos.
    pub fn busqueda_activa(&self) -> bool {
        self.busqueda.is_some()
    }

    /// Texto en edición de la búsqueda de eventos (vacío si no se edita).
    pub fn busqueda_texto(&self) -> &str {
        self.busqueda
            .as_ref()
            .map(|busqueda| busqueda.buffer.as_str())
            .unwrap_or("")
    }

    /// Secciones visibles de «Más tráfico» con su título y sus filas.
    pub fn top_sections(&self) -> Vec<(&'static str, &[TopRow])> {
        match self.subject_actual() {
            SubjectSel::Network => vec![
                ("Equipos", self.top_equipos.as_slice()),
                ("Apps", self.top_apps.as_slice()),
            ],
            SubjectSel::Host | SubjectSel::Device(_) => {
                let mut secciones: Vec<(&'static str, &[TopRow])> =
                    vec![("Apps", self.top_apps.as_slice())];
                if self.range.admite_destinos() {
                    secciones.push(("Destinos", self.top_destinos.as_slice()));
                }
                secciones.push(("Organizaciones", self.top_organizaciones.as_slice()));
                secciones.push(("Países", self.top_paises.as_slice()));
                secciones
            }
        }
    }

    /// Número total de filas de «Más tráfico».
    pub fn top_total_filas(&self) -> usize {
        self.top_sections()
            .iter()
            .map(|(_, filas)| filas.len())
            .sum()
    }

    /// Fila seleccionada de «Más tráfico» (en el orden de las secciones).
    pub fn selected_top_row(&self) -> Option<&TopRow> {
        let mut restante = self.top_selected;
        for (_, filas) in self.top_sections() {
            if restante < filas.len() {
                return filas.get(restante);
            }
            restante -= filas.len();
        }
        None
    }

    /// Mueve la selección de «Más tráfico».
    pub fn mover_top_seleccion(&mut self, delta: isize) {
        let total = self.top_total_filas();
        if total == 0 {
            self.top_selected = 0;
            return;
        }
        let actual = self.top_selected.min(total - 1) as isize;
        self.top_selected = (actual + delta).clamp(0, total as isize - 1) as usize;
    }

    /// Eventos visibles de la línea de tiempo (filtro de búsqueda aplicado).
    pub fn timeline_visible(&self) -> Vec<&TimelineItem> {
        let consulta = self.event_search.trim().to_lowercase();
        self.timeline
            .iter()
            .filter(|item| {
                if consulta.is_empty() {
                    return true;
                }
                let coincide_equipo = item
                    .device_label
                    .as_deref()
                    .map(|nombre| nombre.to_lowercase().contains(&consulta))
                    .unwrap_or(false);
                coincide_equipo || item.summary.to_lowercase().contains(&consulta)
            })
            .collect()
    }

    /// Evento seleccionado de la línea de tiempo.
    pub fn selected_timeline_item(&self) -> Option<&TimelineItem> {
        self.timeline_visible().get(self.timeline_selected).copied()
    }

    /// Mueve la selección de la línea de tiempo.
    pub fn mover_timeline_seleccion(&mut self, delta: isize) {
        let total = self.timeline_visible().len();
        if total == 0 {
            self.timeline_selected = 0;
            return;
        }
        let actual = self.timeline_selected.min(total - 1) as isize;
        self.timeline_selected = (actual + delta).clamp(0, total as isize - 1) as usize;
    }

    /// Ajusta las selecciones de los paneles a los datos recibidos.
    fn clamp_selecciones(&mut self) {
        let total_top = self.top_total_filas();
        if total_top == 0 {
            self.top_selected = 0;
        } else if self.top_selected >= total_top {
            self.top_selected = total_top - 1;
        }
        let total_timeline = self.timeline_visible().len();
        if total_timeline == 0 {
            self.timeline_selected = 0;
        } else if self.timeline_selected >= total_timeline {
            self.timeline_selected = total_timeline - 1;
        }
    }

    /// Punto de la gráfica bajo el cursor.
    pub fn cursor_point(&self) -> Option<&crate::history::SeriesPoint> {
        let series = self.series.as_ref()?;
        series.points.get(self.cursor.unwrap_or(0))
    }

    /// Indica si el bloque de histórico del detalle está cargando.
    pub fn detalle_cargando(&self) -> bool {
        self.cargando(Slot::DetailSeries) || self.cargando(Slot::Presence)
    }

    /// Indica si el ranking de la ventana histórica está cargando.
    pub fn ranking_trafico_cargando(&self) -> bool {
        self.cargando(Slot::TrafficRanking)
    }

    /// Cobertura del rango activo (0-100), si ya se conoce.
    pub fn cobertura_pct(&self) -> Option<f32> {
        let huecos = self.coverage.as_ref()?;
        let total = self.range.dur_s().max(1);
        let cubierto_gap: i64 = huecos.iter().map(|hueco| hueco.dur()).sum();
        let cubierto = (total - cubierto_gap).clamp(0, total);
        Some(cubierto as f32 * 100.0 / total as f32)
    }

    /// Huecos de la ventana histórica de Tráfico en segundos.
    pub fn huecos_trafico(&self) -> Option<i64> {
        let huecos = self.traffic_coverage.as_deref()?;
        let ventana = match self.current_window()? {
            HistWindow::OneHour => 3600,
            HistWindow::Day24 => 86_400,
        };
        let ahora = if self.last_now > 0 {
            self.last_now
        } else {
            crate::history::localtime::now_unix()
        };
        let desde = ahora - ventana;
        let total: i64 = huecos
            .iter()
            .map(|hueco| {
                let inicio = hueco.start.max(desde);
                let fin = hueco.end.min(ahora);
                (fin - inicio).max(0)
            })
            .sum();
        Some(total)
    }

    /// Filas del ranking histórico de Tráfico en el formato de los rankings.
    pub fn ranking_rows_trafico(&self, window: Window) -> Option<Vec<RankRow>> {
        let ranking = self.traffic_ranking.as_ref()?;
        if ranking.window != window.history()? {
            return None;
        }
        if ranking.dimension != dimension_historica(self.traffic_dimension) {
            return None;
        }
        Some(
            ranking
                .rows
                .iter()
                .map(|fila| RankRow {
                    key: fila.key.clone(),
                    label: fila.label.clone(),
                    subtitle: fila.subtitle.clone(),
                    device_id: fila.device_id,
                    bytes_down: fila.bytes_down,
                    bytes_up: fila.bytes_up,
                    devices: fila.devices,
                    connections: fila.connections.min(u64::from(u32::MAX)) as u32,
                    series_60s: [0; 60],
                })
                .collect(),
        )
    }

    /// Porcentaje sin identificar de la ventana histórica.
    pub fn unidentified_pct_trafico(&self) -> f32 {
        self.traffic_ranking
            .as_ref()
            .map(|ranking| ranking.unidentified_pct)
            .unwrap_or(0.0)
    }

    /// Último minuto cerrado incluido en la ventana histórica.
    pub fn cerrado_hasta(&self) -> Option<i64> {
        self.traffic_ranking
            .as_ref()
            .map(|ranking| ranking.closed_until)
    }

    // ------------------------------------------------------------------
    // «¿Quién lo usa?» en ventanas históricas
    // ------------------------------------------------------------------

    /// Pide «¿Quién lo usa?» para una ventana del histórico (1 h o 24 h).
    pub fn ask_who_uses(
        &mut self,
        dimension: Dimension,
        key: String,
        label: String,
        window: Window,
    ) {
        self.who_uses = Some(HistoryWhoUses {
            dimension,
            key,
            label,
            window,
            rows: Vec::new(),
            selected: 0,
            pending: true,
        });
        self.mark_stale(Slot::WhoUses);
    }

    /// Indica si el panel «¿Quién lo usa?» del histórico está abierto.
    pub fn history_who_uses_open(&self) -> bool {
        self.who_uses.is_some()
    }

    /// Procesa una tecla del panel «¿Quién lo usa?» del histórico.
    pub fn handle_history_who_uses_key(&mut self, key: KeyEvent) -> Option<Action> {
        self.who_uses.as_ref()?;
        match key.code {
            KeyCode::Esc => {
                self.who_uses = None;
                Some(Action::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.mover_who_uses(1);
                Some(Action::None)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.mover_who_uses(-1);
                Some(Action::None)
            }
            KeyCode::Home => {
                if let Some(panel) = self.who_uses.as_mut() {
                    panel.selected = 0;
                }
                Some(Action::None)
            }
            KeyCode::End => {
                let total = self
                    .who_uses
                    .as_ref()
                    .map(|panel| panel.rows.len())
                    .unwrap_or(0);
                if let Some(panel) = self.who_uses.as_mut() {
                    panel.selected = total.saturating_sub(1);
                }
                Some(Action::None)
            }
            KeyCode::Enter => match self.selected_history_who_uses() {
                Some(cuota) if cuota.device_id == crate::traffic::DEVICE_ID_HOST => {
                    Some(Action::None)
                }
                Some(cuota) => Some(Action::OpenDetail {
                    device_id: cuota.device_id,
                }),
                None => Some(Action::None),
            },
            _ => None,
        }
    }

    /// Cierra el panel «¿Quién lo usa?» del histórico.
    pub fn close_history_who_uses(&mut self) -> bool {
        self.who_uses.take().is_some()
    }

    /// Fila seleccionada del panel «¿Quién lo usa?» del histórico.
    pub fn selected_history_who_uses(&self) -> Option<DeviceShare> {
        let panel = self.who_uses.as_ref()?;
        panel.rows.get(panel.selected).cloned()
    }

    /// Mueve la selección del panel «¿Quién lo usa?» del histórico.
    fn mover_who_uses(&mut self, delta: isize) {
        let Some(panel) = self.who_uses.as_mut() else {
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

    // ------------------------------------------------------------------
    // Detalle de equipo
    // ------------------------------------------------------------------

    /// Alterna 24 h ⇄ 7 días en el bloque de histórico del detalle.
    pub fn toggle_detail_history_range(&mut self) {
        self.detail_range = match self.detail_range {
            Range::Days7 => Range::Hours24,
            _ => Range::Days7,
        };
        self.mark_stale(Slot::DetailSeries);
        self.mark_stale(Slot::Presence);
    }
}

/// Punto del cursor por defecto: el último con datos del rango.
fn cursor_por_defecto(series: &Series) -> Option<usize> {
    if series.points.is_empty() {
        return None;
    }
    Some(series.first_future().saturating_sub(1))
}

/// Dimensión del histórico equivalente a una agrupación de Tráfico (§7.5).
fn dimension_historica(dimension: Dimension) -> HistoryDimension {
    match dimension {
        Dimension::Device => HistoryDimension::Total,
        Dimension::Destination => HistoryDimension::Destination,
        Dimension::App => HistoryDimension::App,
        Dimension::Category => HistoryDimension::Category,
        Dimension::Protocol => HistoryDimension::Protocol,
        Dimension::Process => HistoryDimension::Process,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{
        HistRankRow, PresenceSpan, PresenceState, RankingResult, SeriesPoint, TimelineKind,
    };
    use crate::repo::devices::Device;
    use crossterm::event::{KeyEvent, KeyModifiers};

    fn tecla(codigo: KeyCode) -> KeyEvent {
        KeyEvent::new(codigo, KeyModifiers::NONE)
    }

    fn dispositivo(id: i64, nombre: &str) -> Device {
        Device {
            id,
            mac: format!("aa:bb:cc:dd:ee:0{id}"),
            ip: format!("192.168.1.{id}"),
            hostname: Some(nombre.to_string()),
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
            watched: false,
        }
    }

    fn serie(minutos: i64, puntos: usize) -> Series {
        let points: Vec<SeriesPoint> = (0..puntos)
            .map(|indice| SeriesPoint {
                at: minutos + indice as i64 * 1800,
                bytes_down: 1000,
                bytes_up: 200,
                gap: indice == 2,
                future: indice == puntos - 1,
            })
            .collect();
        Series {
            range: Range::Hours24,
            points,
            total_down: 1000 * puntos as u64,
            total_up: 200 * puntos as u64,
            max: Some((0, 1200)),
        }
    }

    fn estado_con_historico() -> HistoryState {
        let mut estado = HistoryState::new();
        estado.set_devices(&[dispositivo(1, "iPhone-Marta"), dispositivo(2, "tv-sala")]);
        estado.set_history_enabled(true);
        estado.sync_context(Tab::Historico, None, Dimension::Device, Window::Sixty);
        estado
    }

    fn top_row(clave: &str, device_id: Option<i64>) -> TopRow {
        TopRow {
            key: clave.to_string(),
            label: clave.to_string(),
            subtitle: None,
            device_id,
            bytes_down: 10,
            bytes_up: 2,
            pct: 50.0,
            devices: 1,
        }
    }

    /// Busca el identificador de la consulta que cumple el predicado.
    fn id_de(
        peticiones: &[(u64, HistoryQuery)],
        mut predicado: impl FnMut(&HistoryQuery) -> bool,
    ) -> u64 {
        peticiones
            .iter()
            .find(|(_, consulta)| predicado(consulta))
            .map(|(id, _)| *id)
            .expect("la consulta esperada está en la lista")
    }

    #[test]
    fn el_ciclo_de_rango_recorre_los_cuatro_rangos() {
        let mut estado = estado_con_historico();
        assert_eq!(estado.range, Range::Hours24);
        for esperado in [Range::Days7, Range::Days30, Range::Year1, Range::Hours24] {
            estado.history_handle_key(tecla(KeyCode::Char('w')));
            assert_eq!(estado.range, esperado);
        }
    }

    #[test]
    fn el_ciclo_de_foco_recorre_grafica_mas_trafico_y_eventos() {
        let mut estado = estado_con_historico();
        assert_eq!(estado.focus, HistoryFocus::Grafica);
        estado.history_handle_key(tecla(KeyCode::Tab));
        assert_eq!(estado.focus, HistoryFocus::MasTrafico);
        estado.history_handle_key(tecla(KeyCode::Tab));
        assert_eq!(estado.focus, HistoryFocus::Eventos);
        estado.history_handle_key(tecla(KeyCode::Tab));
        assert_eq!(estado.focus, HistoryFocus::Grafica);
        assert_eq!(HistoryFocus::Eventos.label(), "eventos");
    }

    #[test]
    fn el_filtro_de_eventos_cicla_y_pide_la_linea_de_tiempo() {
        let mut estado = estado_con_historico();
        assert_eq!(estado.filter, EventFilter::All);
        for esperado in [
            EventFilter::Presence,
            EventFilter::Identity,
            EventFilter::Services,
            EventFilter::Almanara,
            EventFilter::All,
        ] {
            estado.history_handle_key(tecla(KeyCode::Char('f')));
            assert_eq!(estado.filter, esperado);
        }
    }

    #[test]
    fn el_cursor_se_mueve_con_menor_y_mayor_solo_en_la_grafica() {
        let mut estado = estado_con_historico();
        estado.series = Some(serie(1_760_000_000, 4));
        estado.cursor = Some(1);
        estado.history_handle_key(tecla(KeyCode::Char('>')));
        assert_eq!(estado.cursor, Some(2));
        estado.history_handle_key(tecla(KeyCode::Char('<')));
        assert_eq!(estado.cursor, Some(1));
        estado.focus = HistoryFocus::Eventos;
        estado.history_handle_key(tecla(KeyCode::Char('>')));
        assert_eq!(estado.cursor, Some(1), "con el foco fuera no se mueve");
    }

    #[test]
    fn el_selector_de_sujeto_filtra_por_equipo_y_selecciona() {
        let mut estado = estado_con_historico();
        estado.history_handle_key(tecla(KeyCode::Char('e')));
        assert!(estado.selector_abierto());
        assert_eq!(estado.selector_filas().len(), 4);
        estado.history_handle_key(tecla(KeyCode::Char('/')));
        for letra in "tv".chars() {
            estado.history_handle_key(tecla(KeyCode::Char(letra)));
        }
        assert!(estado.selector_editando());
        assert_eq!(estado.selector_consulta(), "tv");
        assert_eq!(estado.selector_filas().len(), 1);
        estado.history_handle_key(tecla(KeyCode::Enter));
        assert!(!estado.selector_abierto());
        assert_eq!(estado.subject_actual(), SubjectSel::Device(2));
        assert_eq!(estado.subject_label(), "tv-sala");
    }

    #[test]
    fn el_selector_se_cierra_con_esc() {
        let mut estado = estado_con_historico();
        estado.history_handle_key(tecla(KeyCode::Char('e')));
        estado.history_handle_key(tecla(KeyCode::Esc));
        assert!(!estado.selector_abierto());
        assert_eq!(estado.subject_actual(), SubjectSel::Network);
    }

    #[test]
    fn las_peticiones_solo_salen_para_lo_visible_y_se_deduplican() {
        let mut estado = estado_con_historico();
        let peticiones = estado.history_pending_requests(1_760_000_000);
        // El último evento (siempre), serie, dos topes, línea de tiempo y cobertura.
        assert_eq!(peticiones.len(), 6);
        let ids: Vec<u64> = peticiones.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3, 4, 5]);
        assert!(estado.history_pending_requests(1_760_000_001).is_empty());
        estado.history_refresh();
        let de_nuevo = estado.history_pending_requests(1_760_000_002);
        assert_eq!(de_nuevo.len(), 6);
        assert_eq!(de_nuevo[0].0, 6);
    }

    #[test]
    fn sin_historico_solo_se_pide_el_ultimo_evento_y_las_estadisticas() {
        let mut estado = HistoryState::new();
        estado.set_history_enabled(false);
        estado.sync_context(Tab::Historico, None, Dimension::Device, Window::Sixty);
        let consultas: Vec<HistoryQuery> = estado
            .history_pending_requests(100)
            .into_iter()
            .map(|(_, consulta)| consulta)
            .collect();
        // Sin rollups siguen la línea de tiempo y el último evento.
        assert_eq!(consultas.len(), 2);
        assert!(consultas.contains(&HistoryQuery::LastEvent));
        assert!(consultas
            .iter()
            .any(|consulta| matches!(consulta, HistoryQuery::Timeline { .. })));
        assert!(
            !consultas
                .iter()
                .any(|consulta| matches!(consulta, HistoryQuery::Series { .. })),
            "sin histórico no se piden series"
        );

        let mut config = HistoryState::new();
        config.set_history_enabled(false);
        config.sync_context(Tab::Config, None, Dimension::Device, Window::Sixty);
        let consultas: Vec<HistoryQuery> = config
            .history_pending_requests(100)
            .into_iter()
            .map(|(_, consulta)| consulta)
            .collect();
        assert!(consultas.contains(&HistoryQuery::DbStats));
        assert!(consultas.contains(&HistoryQuery::LastEvent));
    }

    #[test]
    fn el_detalle_pide_serie_presencia_e_inventario() {
        let mut estado = HistoryState::new();
        estado.set_history_enabled(true);
        estado.sync_context(Tab::Equipos, Some(7), Dimension::Device, Window::Sixty);
        let peticiones = estado.history_pending_requests(1_760_000_000);
        let consultas: Vec<HistoryQuery> = peticiones
            .iter()
            .map(|(_, consulta)| consulta.clone())
            .collect();
        assert!(consultas.contains(&HistoryQuery::Presence {
            device_id: 7,
            range: Range::Hours24,
            now: 1_760_000_000,
        }));
        assert!(consultas.contains(&HistoryQuery::Inventory { device_id: 7 }));
        assert!(consultas.iter().any(|consulta| matches!(
            consulta,
            HistoryQuery::Series {
                subject: SubjectSel::Device(7),
                ..
            }
        )));
        // w alterna 24 h ⇄ 7 días y vuelve a pedir presencia y serie.
        let _ = estado.history_pending_requests(1_760_000_001);
        estado.toggle_detail_history_range();
        assert_eq!(estado.detail_range, Range::Days7);
        let consultas: Vec<HistoryQuery> = estado
            .history_pending_requests(1_760_000_002)
            .into_iter()
            .map(|(_, consulta)| consulta)
            .collect();
        assert!(consultas.iter().any(|consulta| matches!(
            consulta,
            HistoryQuery::Presence {
                range: Range::Days7,
                ..
            }
        )));
    }

    #[test]
    fn las_respuestas_obsoletas_se_descartan() {
        let mut estado = estado_con_historico();
        let peticiones = estado.history_pending_requests(1_760_000_000);
        let serie_vieja = id_de(&peticiones, |consulta| {
            matches!(consulta, HistoryQuery::Series { .. })
        });
        // Cambia el rango: la respuesta anterior queda obsoleta.
        estado.history_handle_key(tecla(KeyCode::Char('w')));
        let nuevas = estado.history_pending_requests(1_760_000_001);
        let serie_nueva = id_de(&nuevas, |consulta| {
            matches!(consulta, HistoryQuery::Series { .. })
        });
        assert_ne!(serie_vieja, serie_nueva);

        estado.apply_history_response(
            serie_vieja,
            &Ok(HistoryResponse::Series(serie(1_760_000_000, 3))),
        );
        assert!(estado.series.is_none(), "la respuesta vieja se descarta");

        estado.apply_history_response(
            serie_nueva,
            &Ok(HistoryResponse::Series(serie(1_760_000_000, 5))),
        );
        assert!(estado.series.is_some());
        assert_eq!(estado.series.as_ref().unwrap().points.len(), 5);
    }

    #[test]
    fn el_error_se_muestra_y_no_se_reintenta_hasta_el_refresco() {
        let mut estado = estado_con_historico();
        let peticiones = estado.history_pending_requests(100);
        for (id, _) in &peticiones {
            estado.apply_history_response(*id, &Err("consulta cortada a los 2 s".to_string()));
        }
        assert_eq!(estado.error_actual(), Some("consulta cortada a los 2 s"));
        assert!(estado.history_pending_requests(101).is_empty());
        estado.history_refresh();
        assert!(!estado.history_pending_requests(102).is_empty());
    }

    #[test]
    fn los_topes_de_red_llegan_a_sus_secciones() {
        let mut estado = estado_con_historico();
        let peticiones = estado.history_pending_requests(10);
        let id_equipos = id_de(&peticiones, |consulta| {
            matches!(
                consulta,
                HistoryQuery::Top {
                    dimension: HistoryDimension::Total,
                    ..
                }
            )
        });
        let id_apps = id_de(&peticiones, |consulta| {
            matches!(
                consulta,
                HistoryQuery::Top {
                    dimension: HistoryDimension::App,
                    ..
                }
            )
        });
        estado.apply_history_response(
            id_equipos,
            &Ok(HistoryResponse::Top(vec![top_row("1", Some(1))])),
        );
        estado.apply_history_response(
            id_apps,
            &Ok(HistoryResponse::Top(vec![top_row("youtube", None)])),
        );
        let secciones = estado.top_sections();
        assert_eq!(secciones.len(), 2);
        assert_eq!(secciones[0].0, "Equipos");
        assert_eq!(secciones[1].0, "Apps");
        assert_eq!(estado.top_total_filas(), 2);
        estado.focus = HistoryFocus::MasTrafico;
        estado.top_selected = 0;
        assert_eq!(
            estado.history_handle_key(tecla(KeyCode::Enter)),
            Some(Action::OpenDetail { device_id: 1 })
        );
    }

    #[test]
    fn enter_sobre_un_evento_abre_el_detalle_del_equipo() {
        let mut estado = estado_con_historico();
        estado.timeline = vec![TimelineItem {
            at: "2026-11-11T10:00:00Z".to_string(),
            at_unix: 1_760_000_000,
            kind: TimelineKind::Event,
            device_id: Some(2),
            device_label: Some("tv-sala".to_string()),
            event_type: "reappeared".to_string(),
            summary: "tv-sala vuelve a estar en línea".to_string(),
            session_reason: None,
        }];
        estado.focus = HistoryFocus::Eventos;
        assert_eq!(
            estado.history_handle_key(tecla(KeyCode::Enter)),
            Some(Action::OpenDetail { device_id: 2 })
        );
    }

    #[test]
    fn la_busqueda_de_eventos_filtra_por_equipo() {
        let mut estado = estado_con_historico();
        estado.timeline = vec![
            TimelineItem {
                at: "2026-11-11T10:00:00Z".to_string(),
                at_unix: 1_760_000_000,
                kind: TimelineKind::Event,
                device_id: Some(1),
                device_label: Some("iPhone-Marta".to_string()),
                event_type: "new".to_string(),
                summary: "iPhone-Marta: nuevo".to_string(),
                session_reason: None,
            },
            TimelineItem {
                at: "2026-11-11T09:00:00Z".to_string(),
                at_unix: 1_759_996_400,
                kind: TimelineKind::Session,
                device_id: None,
                device_label: None,
                event_type: "session".to_string(),
                summary: "Almenara arrancada".to_string(),
                session_reason: None,
            },
        ];
        assert_eq!(estado.timeline_visible().len(), 2);
        estado.history_handle_key(tecla(KeyCode::Char('/')));
        for letra in "iphone".chars() {
            estado.history_handle_key(tecla(KeyCode::Char(letra)));
        }
        assert!(estado.busqueda_activa());
        estado.history_handle_key(tecla(KeyCode::Enter));
        assert!(!estado.busqueda_activa());
        assert_eq!(estado.event_search, "iphone");
        assert_eq!(estado.timeline_visible().len(), 1);
    }

    #[test]
    fn quien_lo_usa_pide_responde_y_abre_detalle() {
        let mut estado = HistoryState::new();
        estado.set_history_enabled(true);
        estado.sync_context(Tab::Trafico, None, Dimension::App, Window::Day24);
        estado.ask_who_uses(
            Dimension::App,
            "youtube".to_string(),
            "YouTube".to_string(),
            Window::Day24,
        );
        let peticiones = estado.history_pending_requests(1_760_000_000);
        let id = id_de(&peticiones, |consulta| {
            matches!(consulta, HistoryQuery::WhoUses { .. })
        });
        estado.apply_history_response(
            id,
            &Ok(HistoryResponse::WhoUses(vec![
                DeviceShare {
                    device_id: 1,
                    label: "iPhone-Marta".to_string(),
                    bytes: 800,
                    pct: 80.0,
                },
                DeviceShare {
                    device_id: 2,
                    label: "tv-sala".to_string(),
                    bytes: 200,
                    pct: 20.0,
                },
            ])),
        );
        assert!(!estado.who_uses.as_ref().unwrap().pending);
        assert_eq!(
            estado
                .selected_history_who_uses()
                .map(|cuota| cuota.device_id),
            Some(1)
        );
        estado.handle_history_who_uses_key(tecla(KeyCode::Char('j')));
        assert_eq!(
            estado.handle_history_who_uses_key(tecla(KeyCode::Enter)),
            Some(Action::OpenDetail { device_id: 2 })
        );
        assert!(estado.close_history_who_uses());
        assert!(!estado.history_who_uses_open());
    }

    #[test]
    fn el_ranking_historico_se_convierte_a_filas_del_ranking() {
        let mut estado = HistoryState::new();
        estado.set_history_enabled(true);
        estado.sync_context(Tab::Trafico, None, Dimension::Destination, Window::OneHour);
        estado.traffic_ranking = Some(RankingResult {
            window: HistWindow::OneHour,
            dimension: HistoryDimension::Destination,
            rows: vec![HistRankRow {
                key: "youtube.com".to_string(),
                label: "youtube.com".to_string(),
                subtitle: Some("Google LLC · US".to_string()),
                device_id: None,
                bytes_down: 10,
                bytes_up: 2,
                devices: 2,
                connections: 4,
            }],
            total_down: 10,
            total_up: 2,
            unidentified_pct: 3.0,
            closed_until: 1_760_000_040,
            gap_seconds: 60,
        });
        let filas = estado
            .ranking_rows_trafico(Window::OneHour)
            .expect("filas convertidas");
        assert_eq!(filas[0].label, "youtube.com");
        assert_eq!(filas[0].connections, 4);
        assert!(estado.ranking_rows_trafico(Window::Day24).is_none());
        assert_eq!(estado.unidentified_pct_trafico(), 3.0);
        assert_eq!(estado.cerrado_hasta(), Some(1_760_000_040));
    }

    #[test]
    fn la_cobertura_del_rango_se_calcula_con_los_huecos() {
        let mut estado = estado_con_historico();
        estado.coverage = Some(vec![Gap {
            start: 0,
            end: 3600,
        }]);
        let pct = estado.cobertura_pct().expect("cobertura");
        assert!((pct - 95.83).abs() < 0.5, "cobertura inesperada: {pct}");
    }

    #[test]
    fn la_presencia_se_guarda_para_el_detalle() {
        let mut estado = HistoryState::new();
        estado.set_history_enabled(true);
        estado.sync_context(Tab::Equipos, Some(1), Dimension::Device, Window::Sixty);
        let peticiones = estado.history_pending_requests(100);
        let id = id_de(&peticiones, |consulta| {
            matches!(consulta, HistoryQuery::Presence { .. })
        });
        estado.apply_history_response(
            id,
            &Ok(HistoryResponse::Presence(vec![PresenceSpan {
                start: 0,
                end: 60,
                state: PresenceState::Present,
            }])),
        );
        assert_eq!(estado.detail_presence.as_ref().unwrap().len(), 1);
        assert!(
            !estado.cargando(Slot::Presence),
            "la presencia ya ha respondido"
        );
    }

    #[test]
    fn los_slots_son_unicos() {
        let mut slots = Slot::ALL.to_vec();
        slots.sort();
        slots.dedup();
        assert_eq!(slots.len(), Slot::ALL.len());
    }
}
