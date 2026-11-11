//! Estado de la pestaña Alertas (F6): lista, Reglas y Silencios.
//!
//! La vista pinta lo último que ha devuelto el lector del histórico: el render
//! nunca consulta la base de datos. Este módulo decide qué consultas pedir
//! (`pending_requests`), guarda las respuestas y consume las teclas de la
//! pestaña devolviendo las acciones que escribe el hilo de la TUI.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::widgets::TableState;

use crate::alerts::{AlertCounts, Level, RuleId, RuleSetting};
use crate::history::{
    AlertDetail, AlertFilter, AlertRow, AlertSummary, HistoryQuery, HistoryResponse, HistoryView,
    MuteRow, Page, RuleStat, SubjectSel,
};
use crate::tui::app::Action;

/// Cada cuánto se refresca la lista aunque no haya cambios.
const REFRESCO_LISTA: Duration = Duration::from_secs(30);
/// Tiempo mínimo entre peticiones de la lista (evita ráfagas).
const ESPERA_LISTA: Duration = Duration::from_secs(1);
/// Cada cuánto se refrescan las estadísticas de reglas.
const REFRESCO_REGLAS: Duration = Duration::from_secs(30);
/// Cada cuánto se refrescan los silencios.
const REFRESCO_SILENCIOS: Duration = Duration::from_secs(10);
/// Cada cuánto se refresca el resumen de un sujeto.
const REFRESCO_RESUMEN: Duration = Duration::from_secs(30);
/// Filas máximas de la lista de alertas.
pub const LIMITE_ALERTAS: usize = 200;

/// Vista activa de la pestaña Alertas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AlertsView {
    /// Lista de alertas.
    #[default]
    Lista,
    /// Catálogo de reglas.
    Reglas,
    /// Silencios vigentes.
    Silencios,
}

impl AlertsView {
    /// Las tres vistas en el orden de `Tab`.
    pub const ALL: [Self; 3] = [Self::Lista, Self::Reglas, Self::Silencios];

    /// Título de la vista.
    pub fn title(self) -> &'static str {
        match self {
            Self::Lista => "Alertas",
            Self::Reglas => "Reglas",
            Self::Silencios => "Silencios",
        }
    }

    /// Vista siguiente.
    pub fn next(self) -> Self {
        match self {
            Self::Lista => Self::Reglas,
            Self::Reglas => Self::Silencios,
            Self::Silencios => Self::Lista,
        }
    }

    /// Vista anterior.
    pub fn prev(self) -> Self {
        match self {
            Self::Lista => Self::Silencios,
            Self::Reglas => Self::Lista,
            Self::Silencios => Self::Reglas,
        }
    }
}

/// Filtro de nivel de la lista (`f`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LevelFilter {
    /// Todas.
    #[default]
    Todas,
    /// Solo importantes.
    Importantes,
    /// Solo avisos.
    Avisos,
    /// Solo info.
    Info,
}

impl LevelFilter {
    /// Ciclo de `f`: todas → importantes → avisos → info → todas.
    pub fn next(self) -> Self {
        match self {
            Self::Todas => Self::Importantes,
            Self::Importantes => Self::Avisos,
            Self::Avisos => Self::Info,
            Self::Info => Self::Todas,
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Todas => "todas",
            Self::Importantes => "importantes",
            Self::Avisos => "avisos",
            Self::Info => "info",
        }
    }

    /// Nivel filtrado, si hay uno.
    pub fn level(self) -> Option<Level> {
        match self {
            Self::Todas => None,
            Self::Importantes => Some(Level::Important),
            Self::Avisos => Some(Level::Warning),
            Self::Info => Some(Level::Info),
        }
    }
}

/// Fila de la vista Reglas: una regla o su nivel de MAC privada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleRow {
    /// Una regla del catálogo.
    Rule(RuleId),
    /// El nivel de `device_new` con MAC privada (`level_private_mac`).
    PrivateMac,
}

/// Filas de la vista Reglas en orden: las 16 reglas y, tras «Equipo nuevo», su
/// fila «con MAC privada» (mockup 2).
pub fn rule_rows() -> Vec<RuleRow> {
    let mut filas = Vec::with_capacity(17);
    for regla in RuleId::ALL {
        filas.push(RuleRow::Rule(regla));
        if regla == RuleId::DeviceNew {
            filas.push(RuleRow::PrivateMac);
        }
    }
    filas
}

/// Estado de la pestaña Alertas.
#[derive(Debug, Default)]
pub struct AlertsState {
    /// Vista activa (lista, reglas o silencios).
    pub view: AlertsView,
    /// Alertas del filtro actual.
    pub rows: Vec<AlertRow>,
    /// Silencios vigentes.
    pub mutes: Vec<MuteRow>,
    /// Estadísticas por regla (7 días).
    pub stats: Vec<RuleStat>,
    /// No vistas por nivel (contador de la barra).
    pub counts: AlertCounts,
    /// Fila seleccionada de la lista.
    pub selected: usize,
    /// Fila seleccionada de la vista Reglas.
    pub selected_rule: usize,
    /// Fila seleccionada de la vista Silencios.
    pub selected_mute: usize,
    /// Detalle abierto de una alerta.
    pub detail: Option<AlertDetail>,
    /// El detalle está abierto (panel inferior).
    pub detail_open: bool,
    /// Filtro de nivel activo.
    pub level_filter: LevelFilter,
    /// Solo alertas sin ver (`u`).
    pub unseen_only: bool,
    /// Búsqueda por nombre de equipo (`/`).
    pub search: String,
    /// Se está editando la búsqueda.
    pub search_editing: bool,
    /// Pide confirmación para marcar más de 20 alertas como vistas (`T`).
    pub confirm_seen_all: bool,
    /// Menú de silencio abierto (`m`).
    pub mute_menu: bool,
    /// Error de la última consulta.
    pub error: Option<String>,
    /// La lista está esperando al lector.
    pub loading: bool,
    /// Tabla de la lista (scroll de ratatui).
    pub table_state: TableState,
    /// Tabla de reglas.
    pub rules_table_state: TableState,
    /// Tabla de silencios.
    pub mutes_table_state: TableState,
    /// Resumen de alertas del equipo abierto en el detalle (F6).
    pub device_summary: Option<AlertSummary>,
    /// Resumen de alertas del propio equipo (Config).
    pub host_summary: Option<AlertSummary>,
    /// Ajuste actual de las 16 reglas (lo inyecta la integración desde la config).
    pub rule_settings: BTreeMap<RuleId, RuleSetting>,
    /// Equipos con alguna alerta importante o de aviso sin ver (marca ! en Equipos).
    pub device_unseen: Vec<i64>,
    /// Equipo del resumen de detalle.
    pub device_summary_for: Option<i64>,
    /// Hay que volver a pedir la lista.
    list_dirty: bool,
    /// Hay que volver a pedir las reglas.
    rules_dirty: bool,
    /// Hay que volver a pedir los silencios.
    mutes_dirty: bool,
    /// Hay que volver a pedir el resumen del equipo.
    device_summary_dirty: bool,
    /// Hay que volver a pedir el resumen del propio equipo.
    host_summary_dirty: bool,
    /// Peticiones en vuelo por vista.
    inflight: HashMap<HistoryView, u64>,
    /// Siguiente identificador de petición.
    next_id: u64,
    /// Última petición por vista.
    last_request: HashMap<HistoryView, Instant>,
}

impl AlertsState {
    /// Crea el estado vacío.
    pub fn new() -> Self {
        Self {
            next_id: 1,
            list_dirty: true,
            rules_dirty: true,
            mutes_dirty: true,
            device_summary_dirty: true,
            host_summary_dirty: true,
            ..Self::default()
        }
    }

    /// Filtro actual de la lista.
    pub fn filter(&self) -> AlertFilter {
        AlertFilter {
            level: self.level_filter.level(),
            unseen_only: self.unseen_only,
            device_id: None,
            search: if self.search.trim().is_empty() {
                None
            } else {
                Some(self.search.trim().to_string())
            },
        }
    }

    /// Ámbito del filtro para marcar todas como vistas.
    pub fn scope(&self) -> crate::repo::AlertScope {
        crate::repo::AlertScope {
            level: self.level_filter.level(),
            unseen_only: self.unseen_only,
            device_id: None,
            search: if self.search.trim().is_empty() {
                None
            } else {
                Some(self.search.trim().to_string())
            },
        }
    }

    /// Alerta seleccionada.
    pub fn selected_alert(&self) -> Option<&AlertRow> {
        self.rows.get(self.selected)
    }

    /// Regla seleccionada en la vista Reglas (None en la fila de MAC privada).
    pub fn selected_rule(&self) -> Option<RuleId> {
        match rule_rows().get(self.selected_rule).copied() {
            Some(RuleRow::Rule(regla)) => Some(regla),
            _ => None,
        }
    }

    /// Fila seleccionada de la vista Reglas.
    pub fn selected_rule_row(&self) -> Option<RuleRow> {
        rule_rows().get(self.selected_rule).copied()
    }

    /// Silencio seleccionado.
    pub fn selected_mute(&self) -> Option<&MuteRow> {
        self.mutes.get(self.selected_mute)
    }

    /// Marca la lista para refrescarse (tras una alerta nueva, una vista o un filtro).
    pub fn mark_dirty(&mut self) {
        self.list_dirty = true;
        self.rules_dirty = true;
        self.mutes_dirty = true;
        self.device_summary_dirty = true;
        self.host_summary_dirty = true;
    }

    /// Fija los contadores de no vistas.
    pub fn set_counts(&mut self, counts: AlertCounts) {
        self.counts = counts;
    }

    /// Indica si un equipo tiene alertas importantes o de aviso sin ver (§6).
    pub fn has_unseen(&self, device_id: i64) -> bool {
        self.device_unseen.contains(&device_id)
    }

    /// Fija los equipos con alertas sin ver.
    pub fn set_device_unseen(&mut self, ids: Vec<i64>) {
        self.device_unseen = ids;
    }

    /// Copia los ajustes de las reglas desde la configuración activa.
    pub fn set_rule_settings(&mut self, params: &crate::alerts::AlertsParams) {
        self.rule_settings = params.rules.clone();
    }

    /// Ajuste actual de una regla.
    pub fn setting_actual(&self, rule: RuleId) -> RuleSetting {
        self.rule_settings
            .get(&rule)
            .copied()
            .unwrap_or_else(|| RuleSetting::default_for(rule))
    }

    /// Ajusta la selección a las filas disponibles.
    fn clamps(&mut self) {
        if self.rows.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.rows.len() {
            self.selected = self.rows.len() - 1;
        }
        let filas_reglas = rule_rows().len();
        if self.selected_rule >= filas_reglas {
            self.selected_rule = filas_reglas.saturating_sub(1);
        }
        if self.mutes.is_empty() {
            self.selected_mute = 0;
        } else if self.selected_mute >= self.mutes.len() {
            self.selected_mute = self.mutes.len() - 1;
        }
        self.table_state.select(if self.rows.is_empty() {
            None
        } else {
            Some(self.selected)
        });
        self.rules_table_state.select(Some(self.selected_rule));
        self.mutes_table_state.select(if self.mutes.is_empty() {
            None
        } else {
            Some(self.selected_mute)
        });
    }

    /// Consultas que la pestaña necesita ahora mismo.
    ///
    /// `ctx` dice qué está visible: la pestaña Alertas, la pestaña Config y el
    /// detalle de equipo abierto (esos paneles piden el resumen de su sujeto).
    pub fn pending_requests(&mut self, ctx: &AlertsRequestCtx) -> Vec<(u64, HistoryQuery)> {
        let mut out = Vec::new();
        let ahora = ctx.now;

        if ctx.active {
            let toca_lista = self.list_dirty
                || self
                    .last_request
                    .get(&HistoryView::Alerts)
                    .map(|ultimo| ultimo.elapsed() >= REFRESCO_LISTA)
                    .unwrap_or(true);
            if toca_lista && self.puede_pedir(HistoryView::Alerts, ESPERA_LISTA) {
                let id = self.nuevo_id();
                self.inflight.insert(HistoryView::Alerts, id);
                self.list_dirty = false;
                self.loading = true;
                out.push((
                    id,
                    HistoryQuery::Alerts {
                        filter: self.filter(),
                        page: Page {
                            limit: LIMITE_ALERTAS,
                            offset: 0,
                        },
                        now: ahora,
                    },
                ));
            }

            // Detalle: se pide cuando cambia la alerta seleccionada.
            if self.detail_open {
                if let Some(alerta) = self.selected_alert() {
                    let id_alerta = alerta.id;
                    let ya_esta = self
                        .detail
                        .as_ref()
                        .map(|detalle| detalle.row.id == id_alerta)
                        .unwrap_or(false);
                    if !ya_esta && self.puede_pedir(HistoryView::AlertDetail, Duration::ZERO) {
                        let id = self.nuevo_id();
                        self.inflight.insert(HistoryView::AlertDetail, id);
                        out.push((id, HistoryQuery::AlertDetail { id: id_alerta }));
                    }
                }
            }

            if self.view == AlertsView::Reglas
                && (self.rules_dirty || self.toca_refresco(HistoryView::RuleStats, REFRESCO_REGLAS))
                && self.puede_pedir(HistoryView::RuleStats, Duration::ZERO)
            {
                let id = self.nuevo_id();
                self.inflight.insert(HistoryView::RuleStats, id);
                self.rules_dirty = false;
                out.push((
                    id,
                    HistoryQuery::RuleStats {
                        since: ahora - 7 * 86_400,
                    },
                ));
            }

            if self.view == AlertsView::Silencios
                && (self.mutes_dirty || self.toca_refresco(HistoryView::Mutes, REFRESCO_SILENCIOS))
                && self.puede_pedir(HistoryView::Mutes, Duration::ZERO)
            {
                let id = self.nuevo_id();
                self.inflight.insert(HistoryView::Mutes, id);
                self.mutes_dirty = false;
                out.push((id, HistoryQuery::Mutes { now: ahora }));
            }
        }

        // Resumen del equipo abierto en el detalle (bloque Alertas).
        if let Some(device_id) = ctx.detail_device {
            let cambio = self.device_summary_for != Some(device_id);
            if cambio {
                self.device_summary_for = Some(device_id);
                self.device_summary = None;
                self.device_summary_dirty = true;
            }
            if self.device_summary_dirty
                && (cambio || self.toca_refresco(HistoryView::AlertSummary, REFRESCO_RESUMEN))
                && self.puede_pedir(HistoryView::AlertSummary, Duration::ZERO)
            {
                let id = self.nuevo_id();
                self.inflight.insert(HistoryView::AlertSummary, id);
                self.device_summary_dirty = false;
                out.push((
                    id,
                    HistoryQuery::AlertSummary {
                        subject: SubjectSel::Device(device_id),
                        now: ahora,
                    },
                ));
            }
        }

        // Aprendizaje e inventario del propio equipo (Config).
        if ctx.config_active
            && self.host_summary_dirty
            && self.toca_refresco(HistoryView::AlertSummary, REFRESCO_RESUMEN)
            && self.puede_pedir(HistoryView::AlertSummary, Duration::ZERO)
        {
            let id = self.nuevo_id();
            self.inflight.insert(HistoryView::AlertSummary, id);
            self.host_summary_dirty = false;
            out.push((
                id,
                HistoryQuery::AlertSummary {
                    subject: SubjectSel::Host,
                    now: ahora,
                },
            ));
        }

        out
    }

    fn nuevo_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn puede_pedir(&mut self, vista: HistoryView, espera: Duration) -> bool {
        if self.inflight.contains_key(&vista) {
            return false;
        }
        let toca = self
            .last_request
            .get(&vista)
            .map(|ultimo| ultimo.elapsed() >= espera)
            .unwrap_or(true);
        if toca {
            self.last_request.insert(vista, Instant::now());
        }
        toca
    }

    fn toca_refresco(&self, vista: HistoryView, intervalo: Duration) -> bool {
        self.last_request
            .get(&vista)
            .map(|ultimo| ultimo.elapsed() >= intervalo)
            .unwrap_or(true)
    }

    /// Aplica una respuesta del lector; devuelve true si era de esta pestaña.
    pub fn apply_response(
        &mut self,
        id: u64,
        response: &std::result::Result<HistoryResponse, String>,
    ) -> bool {
        let vista = match response {
            Ok(respuesta) => respuesta.vista(),
            Err(_) => match self
                .inflight
                .iter()
                .find(|(_, pendiente)| **pendiente == id)
            {
                Some((vista, _)) => *vista,
                None => return false,
            },
        };
        let esperada = match self.inflight.get(&vista) {
            Some(pendiente) => *pendiente,
            None => return false,
        };
        if esperada != id {
            return false;
        }
        self.inflight.remove(&vista);

        match response {
            Err(error) => {
                if vista == HistoryView::Alerts {
                    self.loading = false;
                }
                self.error = Some(error.clone());
            }
            Ok(respuesta) => {
                self.error = None;
                match respuesta {
                    HistoryResponse::Alerts(alertas) => {
                        self.rows = alertas.clone();
                        self.loading = false;
                        self.clamps();
                    }
                    HistoryResponse::AlertDetail(detalle) => {
                        self.detail = Some((**detalle).clone());
                    }
                    HistoryResponse::Mutes(silencios) => {
                        self.mutes = silencios.clone();
                        self.clamps();
                    }
                    HistoryResponse::RuleStats(stats) => {
                        self.stats = stats.clone();
                    }
                    HistoryResponse::AlertSummary(resumen) => {
                        if resumen.subject == SubjectSel::Host {
                            self.host_summary = Some((**resumen).clone());
                        } else {
                            self.device_summary = Some((**resumen).clone());
                        }
                    }
                    _ => {}
                }
            }
        }
        true
    }

    /// Consume las teclas de la pestaña Alertas.
    ///
    /// Devuelve `Some(Action::None)` cuando la tecla es de la pestaña pero no
    /// necesita escribir en la base de datos, y `None` cuando no la consume.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if self.search_editing {
            return Some(self.handle_search_key(key));
        }
        if self.mute_menu {
            return Some(self.handle_mute_menu_key(key));
        }
        match key.code {
            KeyCode::Tab => {
                self.view = self.view.next();
                self.detail_open = false;
                self.mark_dirty();
                Some(Action::None)
            }
            KeyCode::BackTab => {
                self.view = self.view.prev();
                self.detail_open = false;
                self.mark_dirty();
                Some(Action::None)
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.mover_seleccion(1);
                Some(Action::None)
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.mover_seleccion(-1);
                Some(Action::None)
            }
            KeyCode::Esc => {
                if self.detail_open {
                    self.detail_open = false;
                } else if !self.search.is_empty() {
                    self.search.clear();
                    self.list_dirty = true;
                }
                Some(Action::None)
            }
            _ if self.view == AlertsView::Lista => self.handle_lista_key(key),
            _ if self.view == AlertsView::Reglas => self.handle_reglas_key(key),
            _ => self.handle_silencios_key(key),
        }
    }

    fn mover_seleccion(&mut self, delta: isize) {
        match self.view {
            AlertsView::Lista => {
                let len = self.rows.len();
                if len == 0 {
                    return;
                }
                let actual = self.selected as isize + delta;
                self.selected = actual.clamp(0, len as isize - 1) as usize;
            }
            AlertsView::Reglas => {
                let len = rule_rows().len();
                let actual = self.selected_rule as isize + delta;
                self.selected_rule = actual.clamp(0, len as isize - 1) as usize;
            }
            AlertsView::Silencios => {
                let len = self.mutes.len();
                if len == 0 {
                    return;
                }
                let actual = self.selected_mute as isize + delta;
                self.selected_mute = actual.clamp(0, len as isize - 1) as usize;
            }
        }
        self.clamps();
    }

    fn handle_lista_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Enter => {
                let id = self.selected_alert().map(|alerta| alerta.id);
                match id {
                    Some(id) => {
                        self.detail_open = true;
                        Some(Action::MarkAlertSeen(crate::repo::SeenSel::Alert(id)))
                    }
                    None => Some(Action::None),
                }
            }
            KeyCode::Char(' ') => {
                let accion = self
                    .selected_alert()
                    .map(|alerta| Action::MarkAlertSeen(crate::repo::SeenSel::Alert(alerta.id)))
                    .unwrap_or(Action::None);
                Some(accion)
            }
            KeyCode::Char('T') => {
                if self.rows.len() > 20 && !self.confirm_seen_all {
                    self.confirm_seen_all = true;
                    return Some(Action::None);
                }
                self.confirm_seen_all = false;
                Some(Action::MarkAlertsSeen(self.scope()))
            }
            KeyCode::Char('f') => {
                self.level_filter = self.level_filter.next();
                self.list_dirty = true;
                Some(Action::None)
            }
            KeyCode::Char('u') => {
                self.unseen_only = !self.unseen_only;
                self.list_dirty = true;
                Some(Action::None)
            }
            KeyCode::Char('/') => {
                self.search_editing = true;
                Some(Action::None)
            }
            KeyCode::Char('m') => {
                if self.selected_alert().is_some() {
                    self.mute_menu = true;
                }
                Some(Action::None)
            }
            KeyCode::Char('e') => {
                let device_id = self.selected_alert().and_then(|alerta| alerta.device_id);
                match device_id {
                    Some(id) => Some(Action::OpenDetail { device_id: id }),
                    None => Some(Action::None),
                }
            }
            _ => None,
        }
    }

    fn handle_reglas_key(&mut self, key: KeyEvent) -> Option<Action> {
        let fila = self.selected_rule_row()?;
        match key.code {
            KeyCode::Char(' ') => {
                let Some(regla) = self.selected_rule() else {
                    // La fila «con MAC privada» no se activa ni apaga.
                    return Some(Action::None);
                };
                let mut ajuste = self.setting_actual(regla);
                ajuste.enabled = !ajuste.enabled;
                Some(Action::SaveRuleSetting {
                    rule: regla,
                    setting: ajuste,
                })
            }
            KeyCode::Char('n') => match fila {
                RuleRow::Rule(regla) => {
                    let mut ajuste = self.setting_actual(regla);
                    ajuste.level = ajuste.level.next();
                    Some(Action::SaveRuleSetting {
                        rule: regla,
                        setting: ajuste,
                    })
                }
                RuleRow::PrivateMac => {
                    let mut ajuste = self.setting_actual(RuleId::DeviceNew);
                    let actual = ajuste.level_private_mac.unwrap_or(Level::Warning);
                    ajuste.level_private_mac = Some(actual.next());
                    Some(Action::SaveRuleSetting {
                        rule: RuleId::DeviceNew,
                        setting: ajuste,
                    })
                }
            },
            _ => None,
        }
    }

    fn handle_silencios_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('x') => {
                let id = self.selected_mute().map(|silencio| silencio.id);
                id.map(Action::DeleteMute).or(Some(Action::None))
            }
            _ => None,
        }
    }

    fn handle_mute_menu_key(&mut self, key: KeyEvent) -> Action {
        let Some(alerta) = self.selected_alert().cloned() else {
            self.mute_menu = false;
            return Action::None;
        };
        let duracion = match key.code {
            KeyCode::Char('1') => Some(Duration::from_secs(86_400)),
            KeyCode::Char('2') => Some(Duration::from_secs(7 * 86_400)),
            KeyCode::Char('3') => None,
            KeyCode::Esc => {
                self.mute_menu = false;
                return Action::None;
            }
            _ => return Action::None,
        };
        self.mute_menu = false;
        let hasta = duracion.map(|d| SystemTime::now() + d);
        let Some(regla) = alerta.rule.rule_id() else {
            return Action::None;
        };
        Action::MuteAlert {
            rule: regla,
            subject: alerta.subject,
            until: hasta,
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Enter => {
                self.search_editing = false;
                self.list_dirty = true;
            }
            KeyCode::Esc => {
                self.search_editing = false;
                self.search.clear();
                self.list_dirty = true;
            }
            KeyCode::Backspace => {
                self.search.pop();
                self.list_dirty = true;
            }
            KeyCode::Char(c) => {
                self.search.push(c);
                self.list_dirty = true;
            }
            _ => {}
        }
        Action::None
    }
}

/// Contexto de peticiones de la pestaña.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlertsRequestCtx {
    /// La pestaña Alertas está visible.
    pub active: bool,
    /// La pestaña Config está visible.
    pub config_active: bool,
    /// Equipo abierto en el detalle master-detail.
    pub detail_device: Option<i64>,
    /// Instante actual en segundos Unix UTC.
    pub now: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{AlertRule, RuleId, Subject};
    use crate::history::AlertRow;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn tecla(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn alerta(id: i64, nivel: Level, rule: RuleId) -> AlertRow {
        AlertRow {
            id,
            rule: AlertRule::Rule(rule),
            level: nivel,
            subject: Subject::Device(1),
            device_id: Some(1),
            title: "Título".to_string(),
            subject_label: "nas".to_string(),
            created_at: 1_760_000_000,
            last_at: 1_760_000_100,
            count: 1,
            seen: false,
            resolved: false,
            notified: false,
            summary_id: None,
        }
    }

    fn estado_con_alertas(cuantas: usize) -> AlertsState {
        let mut estado = AlertsState::new();
        estado.rows = (0..cuantas)
            .map(|indice| alerta(indice as i64 + 1, Level::Warning, RuleId::DeviceNew))
            .collect();
        estado.clamps();
        estado
    }

    #[test]
    fn el_filtro_de_nivel_se_proyecta_a_alert_filter() {
        let mut estado = AlertsState::new();
        assert_eq!(estado.filter().level, None);
        estado.handle_key(tecla(KeyCode::Char('f')));
        assert_eq!(estado.filter().level, Some(Level::Important));
        assert_eq!(estado.level_filter.label(), "importantes");
        estado.handle_key(tecla(KeyCode::Char('f')));
        estado.handle_key(tecla(KeyCode::Char('f')));
        assert_eq!(estado.filter().level, Some(Level::Info));
        estado.handle_key(tecla(KeyCode::Char('f')));
        assert_eq!(estado.filter().level, None);
    }

    #[test]
    fn u_alterna_solo_sin_ver_y_barra_se_filtra() {
        let mut estado = estado_con_alertas(3);
        assert!(!estado.filter().unseen_only);
        estado.handle_key(tecla(KeyCode::Char('u')));
        assert!(estado.filter().unseen_only);
        assert!(estado.list_dirty);
    }

    #[test]
    fn tab_cicla_las_tres_vistas() {
        let mut estado = AlertsState::new();
        assert_eq!(estado.view, AlertsView::Lista);
        estado.handle_key(tecla(KeyCode::Tab));
        assert_eq!(estado.view, AlertsView::Reglas);
        estado.handle_key(tecla(KeyCode::Tab));
        assert_eq!(estado.view, AlertsView::Silencios);
        estado.handle_key(tecla(KeyCode::Tab));
        assert_eq!(estado.view, AlertsView::Lista);
    }

    #[test]
    fn t_pide_confirmacion_si_hay_mas_de_veinte() {
        let mut estado = estado_con_alertas(21);
        let primera = estado.handle_key(tecla(KeyCode::Char('T')));
        assert_eq!(primera, Some(Action::None));
        assert!(estado.confirm_seen_all);
        let segunda = estado.handle_key(tecla(KeyCode::Char('T')));
        assert!(matches!(segunda, Some(Action::MarkAlertsSeen(_))));
        assert!(!estado.confirm_seen_all);
    }

    #[test]
    fn t_marca_directamente_con_pocas_alertas() {
        let mut estado = estado_con_alertas(5);
        let accion = estado.handle_key(tecla(KeyCode::Char('T')));
        assert!(matches!(accion, Some(Action::MarkAlertsSeen(_))));
    }

    #[test]
    fn m_abre_el_menu_y_uno_crea_el_silencio_de_un_dia() {
        let mut estado = estado_con_alertas(1);
        assert_eq!(
            estado.handle_key(tecla(KeyCode::Char('m'))),
            Some(Action::None)
        );
        assert!(estado.mute_menu);
        let accion = estado.handle_key(tecla(KeyCode::Char('1')));
        match accion {
            Some(Action::MuteAlert {
                rule,
                subject,
                until,
            }) => {
                assert_eq!(rule, RuleId::DeviceNew);
                assert_eq!(subject, Subject::Device(1));
                assert!(until.is_some());
            }
            otro => panic!("acción inesperada: {otro:?}"),
        }
        assert!(!estado.mute_menu);
    }

    #[test]
    fn enter_abre_detalle_y_marca_vista() {
        let mut estado = estado_con_alertas(1);
        let accion = estado.handle_key(tecla(KeyCode::Enter));
        assert!(estado.detail_open);
        assert!(matches!(
            accion,
            Some(Action::MarkAlertSeen(crate::repo::SeenSel::Alert(1)))
        ));
    }

    #[test]
    fn espacio_marca_vista_sin_abrir_detalle() {
        let mut estado = estado_con_alertas(1);
        let accion = estado.handle_key(tecla(KeyCode::Char(' ')));
        assert!(!estado.detail_open);
        assert!(matches!(accion, Some(Action::MarkAlertSeen(_))));
    }

    #[test]
    fn e_abre_el_equipo_de_la_alerta() {
        let mut estado = estado_con_alertas(1);
        let accion = estado.handle_key(tecla(KeyCode::Char('e')));
        assert_eq!(accion, Some(Action::OpenDetail { device_id: 1 }));
    }

    #[test]
    fn reglas_espacio_alterna_el_ajuste_y_n_cicla_el_nivel() {
        let mut estado = AlertsState::new();
        estado.view = AlertsView::Reglas;
        estado.selected_rule = 2; // PortNew (el 1 es la fila «con MAC privada»)
        let accion = estado.handle_key(tecla(KeyCode::Char(' ')));
        match accion {
            Some(Action::SaveRuleSetting { rule, setting }) => {
                assert_eq!(rule, RuleId::PortNew);
                assert!(!setting.enabled);
                assert_eq!(setting.level, Level::Important);
            }
            otro => panic!("acción inesperada: {otro:?}"),
        }
        let accion = estado.handle_key(tecla(KeyCode::Char('n')));
        match accion {
            Some(Action::SaveRuleSetting { rule, setting }) => {
                assert_eq!(rule, RuleId::PortNew);
                assert_eq!(setting.level, Level::Warning);
            }
            otro => panic!("acción inesperada: {otro:?}"),
        }
    }

    #[test]
    fn reglas_la_fila_de_mac_privada_cambia_ese_nivel() {
        let mut estado = AlertsState::new();
        estado.view = AlertsView::Reglas;
        let fila = rule_rows()
            .iter()
            .position(|fila| *fila == RuleRow::PrivateMac)
            .expect("fila de MAC privada");
        estado.selected_rule = fila;
        let accion = estado.handle_key(tecla(KeyCode::Char('n')));
        match accion {
            Some(Action::SaveRuleSetting { rule, setting }) => {
                assert_eq!(rule, RuleId::DeviceNew);
                assert_eq!(setting.level_private_mac, Some(Level::Info));
            }
            otro => panic!("acción inesperada: {otro:?}"),
        }
    }

    #[test]
    fn silencios_x_quita_el_silencio_seleccionado() {
        let mut estado = AlertsState::new();
        estado.view = AlertsView::Silencios;
        estado.mutes = vec![MuteRow {
            id: 7,
            rule: RuleId::TrafficHigh,
            subject: Subject::Device(1),
            device_id: 1,
            device_label: Some("nas".to_string()),
            until: None,
            created_at: 1_760_000_000,
        }];
        estado.selected_mute = 0;
        assert_eq!(
            estado.handle_key(tecla(KeyCode::Char('x'))),
            Some(Action::DeleteMute(7))
        );
    }

    #[test]
    fn el_buscador_se_edita_con_slash() {
        let mut estado = estado_con_alertas(1);
        estado.handle_key(tecla(KeyCode::Char('/')));
        assert!(estado.search_editing);
        estado.handle_key(tecla(KeyCode::Char('n')));
        estado.handle_key(tecla(KeyCode::Char('a')));
        estado.handle_key(tecla(KeyCode::Char('s')));
        assert_eq!(estado.search, "nas");
        estado.handle_key(tecla(KeyCode::Enter));
        assert!(!estado.search_editing);
        assert_eq!(estado.filter().search.as_deref(), Some("nas"));
        estado.handle_key(tecla(KeyCode::Esc));
        assert_eq!(estado.filter().search, None);
    }

    #[test]
    fn pending_requests_pide_la_lista_solo_en_la_pestana_activa() {
        let mut estado = AlertsState::new();
        let ctx_inactivo = AlertsRequestCtx {
            active: false,
            now: 1_760_000_000,
            ..Default::default()
        };
        assert!(estado.pending_requests(&ctx_inactivo).is_empty());

        let ctx = AlertsRequestCtx {
            active: true,
            now: 1_760_000_000,
            ..Default::default()
        };
        let peticiones = estado.pending_requests(&ctx);
        assert_eq!(peticiones.len(), 1);
        assert!(matches!(peticiones[0].1, HistoryQuery::Alerts { .. }));
        assert!(estado.loading);
    }

    #[test]
    fn apply_response_descarta_respuestas_no_pedidas() {
        let mut estado = AlertsState::new();
        let respuesta = Ok(HistoryResponse::Alerts(Vec::new()));
        assert!(!estado.apply_response(99, &respuesta));
    }

    #[test]
    fn los_contadores_y_las_marcas_de_equipo_se_guardan() {
        let mut estado = AlertsState::new();
        estado.set_counts(AlertCounts {
            important: 2,
            warning: 0,
            info: 5,
        });
        estado.set_device_unseen(vec![3, 7]);
        assert_eq!(estado.counts.badge(), 2);
        assert!(estado.has_unseen(3));
        assert!(!estado.has_unseen(4));
        assert_eq!(
            crate::tui::views::alerts::contador_barra(estado.counts),
            "Alertas 2"
        );
    }
}
