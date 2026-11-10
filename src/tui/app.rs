//! Estado de la aplicación TUI y lógica de interacción.
//!
//! El estado es independiente de la base de datos: las acciones que requieren
//! persistencia se devuelven como [Action] y el bucle de la TUI las ejecuta.

use std::path::PathBuf;
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::TableState;
use tokio::sync::mpsc;

use crate::capabilities::Capabilities;
use crate::config::Config;
use crate::events::ScanCommand;
use crate::notifier::{Level, Notification, Notifier};
use crate::repo::devices::Device;
use crate::repo::interfaces::Interface;
use crate::scanner::Reconciliation;
use crate::tui::theme::Theme;

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

    /// Las cuatro pestañas centrales son placeholders en Fase 1.
    pub fn is_placeholder(self) -> bool {
        matches!(
            self,
            Tab::Trafico | Tab::Conexiones | Tab::Historico | Tab::Alertas
        )
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
    /// Búsqueda incremental.
    Search,
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
        }
    }

    /// Sustituye los datos de equipos e interfaces y ajusta la selección.
    pub fn set_data(&mut self, devices: Vec<Device>, interfaces: Vec<Interface>) {
        self.devices = devices;
        self.interfaces = interfaces;
        self.clamp_selection();
    }

    /// Aplica el resultado de reconciliar un escaneo.
    pub fn apply_reconciliation(&mut self, reconciliacion: Reconciliation) {
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

    /// Avanza el reloj de las notificaciones.
    pub fn tick(&mut self) {
        self.notifier.tick();
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
    pub fn visible_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..self.devices.len())
            .filter(|indice| self.matches(&self.devices[*indice]))
            .collect();
        let ascending = self.sort.ascending;
        let key = self.sort.key;
        indices.sort_by(|a, b| {
            let izquierda = &self.devices[*a];
            let derecha = &self.devices[*b];
            let orden =
                comparar(izquierda, derecha, key).then_with(|| izquierda.mac.cmp(&derecha.mac));
            if ascending {
                orden
            } else {
                orden.reverse()
            }
        });
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

    /// Inicia una búsqueda.
    pub fn begin_search(&mut self) {
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
            InputMode::Search => return,
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
            if input.mode == InputMode::Search {
                self.search.clear();
            }
        }
        self.clamp_selection();
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
        if self.input.as_ref().map(|i| i.mode) == Some(InputMode::Search) {
            self.selected = 0;
            self.clamp_selection();
        }
    }

    /// Borra el último carácter del campo de entrada.
    pub fn pop_input_char(&mut self) {
        if let Some(input) = self.input.as_mut() {
            input.buffer.pop();
        }
        if self.input.as_ref().map(|i| i.mode) == Some(InputMode::Search) {
            self.selected = 0;
            self.clamp_selection();
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

    /// Etiqueta del modo (privilegiado o degradado).
    pub fn mode_label(&self) -> String {
        if self.capabilities.raw_sockets {
            "modo: privilegiado".to_string()
        } else {
            "modo: degradado (sin CAP_NET_RAW)".to_string()
        }
    }

    /// Procesa una tecla y devuelve la acción a ejecutar.
    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }
        if self.input.is_some() {
            return self.handle_input_key(key);
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
                self.move_selection(1);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
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
                self.select_first();
                Action::None
            }
            KeyCode::End => {
                self.select_last();
                Action::None
            }
            KeyCode::Enter => {
                if let Some(device) = self.selected_device() {
                    let mensaje = format!(
                        "Detalle de {} no disponible hasta Fase 3",
                        device.display_name()
                    );
                    self.push_notification(Level::Info, mensaje);
                }
                Action::None
            }
            KeyCode::Char('/') => {
                self.begin_search();
                Action::None
            }
            KeyCode::Char('s') => {
                self.cycle_sort();
                Action::None
            }
            KeyCode::Char('f') => {
                self.cycle_filter();
                Action::None
            }
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
                if self.tab != Tab::Equipos {
                    self.tab = Tab::Equipos;
                }
                Action::None
            }
            _ => Action::None,
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
        assert!(Tab::Trafico.is_placeholder());
        assert!(!Tab::Config.is_placeholder());
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
    fn enter_avisa_de_detalle_no_disponible() {
        let mut app = app_con(vec![dispositivo(
            1,
            "aa:bb:cc:dd:ee:01",
            "10.0.0.2",
            None,
            None,
            true,
        )]);
        app.handle_key(tecla(KeyCode::Enter));
        assert!(app
            .notifier
            .current()
            .unwrap()
            .message
            .contains("no disponible"));
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
}
