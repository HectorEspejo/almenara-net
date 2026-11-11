//! Rankings por dimensión y ventana de la Fase 4 (§7.11).
//!
//! Mantiene, para cada dimensión (equipo, destino, app, categoría, protocolo y
//! proceso), los bytes ↓ y ↑ de las ventanas de 60 s y 5 min (reutilizando las
//! ventanas de F3) y el acumulado de sesión, con topes de 2048 claves.
//!
//! Cada clave guarda además los equipos que la usan con sus bytes por ventana
//! (para el panel «¿Quién lo usa?»), el instante de su último byte y el número
//! de conexiones activas que la tarea de tráfico refresca cada segundo con
//! [Rankings::begin_connections] y [Rankings::record_connection].
//!
//! Decisiones de integración:
//!
//! - La dirección la decide el llamante: [Dir::Down] = servidor → cliente y
//!   [Dir::Up] = cliente → servidor. [Rankings::record] puede llamarse varias
//!   veces por flujo y segundo (una por dirección) y las sumas se acumulan.
//! - El pico de 60 s no es un campo aparte: se calcula como el máximo de
//!   series_60s. La serie solo se rellena en la dimensión App (down + up por
//!   segundo) y vale cero en el resto, para no engordar las filas que no la
//!   necesitan.
//! - [Rankings::top_for_device] devuelve el ranking de un único equipo (top de
//!   apps y destinos del detalle de equipo): los bytes son los de ese equipo en
//!   la ventana y solo salen claves con bytes suyos.
//! - El porcentaje sin identificar son los bytes con app NULL entre los bytes
//!   totales de la ventana (0.0 si no hay bytes).
//! - El tope de 2048 claves por dimensión se aplica desalojando primero las
//!   claves con last_seen más antiguo sin bytes en 5 min. Si aun así se supera
//!   el tope (todas activas) se desaloja también la más antigua, como
//!   protección de memoria frente a destinos hostiles.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use crate::capture::windows::{Windows, LEN_60S};
use crate::history::rollup::{sujetos_y_dims, MinuteRollup};
use crate::history::RollupBatch;
use crate::inference::{AppProtocol, DestinationKind, FlowLabel, L4};
use crate::traffic::DEVICE_ID_HOST;

/// Tope de claves por dimensión (§7.11).
const MAX_CLAVES_POR_DIMENSION: usize = 2048;
/// Tiempo sin bytes a partir del cual una clave es desalojable.
const INACTIVIDAD_DESALOJO: Duration = Duration::from_secs(300);

/// Dimensiones de los rankings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dimension {
    /// Equipos (incluye la fila [host]).
    #[default]
    Device,
    /// Destinos: dominio registrable, IP remota o equipo de la LAN.
    Destination,
    /// Apps del catálogo.
    App,
    /// Categorías del catálogo.
    Category,
    /// Protocolos de aplicación.
    Protocol,
    /// Procesos locales (solo tráfico del propio equipo).
    Process,
}

impl Dimension {
    /// Las seis dimensiones, en el orden de g.
    pub const ALL: [Self; 6] = [
        Self::Device,
        Self::Destination,
        Self::App,
        Self::Category,
        Self::Protocol,
        Self::Process,
    ];

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Device => "equipo",
            Self::Destination => "destino",
            Self::App => "app",
            Self::Category => "categoría",
            Self::Protocol => "protocolo",
            Self::Process => "proceso",
        }
    }

    /// Posición en el ciclo de g.
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|dim| *dim == self).unwrap_or(0)
    }
}

/// Ventanas de los rankings.
///
/// Las tres primeras viven en memoria (F3/F4). Las ventanas de 1 h y 24 h
/// (F5) no se acumulan en memoria: se consultan al histórico con
/// [Window::history] y las responde el lector de solo lectura (ADR-63).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Window {
    /// 60 s (1 punto/s).
    Sixty,
    /// 5 min (1 punto/5 s).
    FiveMin,
    /// Última hora (minutos cerrados, desde el histórico).
    OneHour,
    /// Últimas 24 h (horas y minutos de la hora en curso, desde el histórico).
    Day24,
    /// Acumulado desde el arranque.
    Session,
}

impl Window {
    /// Las ventanas en memoria, en el orden de w de F3/F4.
    pub const ALL: [Self; 3] = [Self::Sixty, Self::FiveMin, Self::Session];

    /// Las cinco ventanas del ciclo de w, en orden (F5 añade 1 h y 24 h).
    pub const UI_ALL: [Self; 5] = [
        Self::Sixty,
        Self::FiveMin,
        Self::OneHour,
        Self::Day24,
        Self::Session,
    ];

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sixty => "60 s",
            Self::FiveMin => "5 min",
            Self::OneHour => "1 h",
            Self::Day24 => "24 h",
            Self::Session => "sesión",
        }
    }

    /// Índice de la ventana en el ciclo de w (0-4).
    pub fn index(self) -> usize {
        Self::UI_ALL
            .iter()
            .position(|window| *window == self)
            .unwrap_or(0)
    }

    /// Siguiente ventana del ciclo de w.
    pub fn next_ui(self) -> Self {
        Self::UI_ALL[(self.index() + 1) % Self::UI_ALL.len()]
    }

    /// Indica si la ventana se acumula en memoria.
    #[allow(dead_code)]
    pub fn in_memory(self) -> bool {
        matches!(self, Self::Sixty | Self::FiveMin | Self::Session)
    }

    /// Ventana equivalente del histórico, si la hay.
    pub fn history(self) -> Option<crate::history::HistWindow> {
        match self {
            Self::OneHour => Some(crate::history::HistWindow::OneHour),
            Self::Day24 => Some(crate::history::HistWindow::Day24),
            _ => None,
        }
    }
}

/// Criterio de ordenación del ranking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortKey {
    /// Bytes de bajada.
    Down,
    /// Bytes de subida.
    Up,
    /// Total de bytes (orden por defecto).
    #[default]
    Total,
    /// Número de equipos distintos.
    Devices,
}

impl SortKey {
    /// Ciclo de ordenación de s.
    pub fn next(self) -> Self {
        match self {
            Self::Total => Self::Down,
            Self::Down => Self::Up,
            Self::Up => Self::Devices,
            Self::Devices => Self::Total,
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Down => "↓",
            Self::Up => "↑",
            Self::Total => "total",
            Self::Devices => "equipos",
        }
    }
}

/// Dirección de un paquete respecto al cliente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Servidor → cliente (bajada).
    Down,
    /// Cliente → servidor (subida).
    Up,
}

/// Contexto de un paquete para los rankings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowCtx {
    /// Equipo atribuido (incluye [host] con -1).
    pub device_id: Option<i64>,
    /// Proceso local (solo tráfico del propio equipo).
    pub process: Option<(u32, String)>,
    /// Transporte.
    pub l4: Option<L4>,
    /// Protocolo de aplicación o de transporte ya resuelto (F5).
    ///
    /// La captura lo rellena con el protocolo real del flujo (incluido ICMP)
    /// para que el histórico no tenga que adivinarlo a partir de l4.
    pub protocol: Option<AppProtocol>,
    /// La columna Equipo del flujo es el cliente (para el inventario JA4, §7.9).
    pub es_cliente: bool,
}

/// Fila de un ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankRow {
    /// Clave de la fila (device_id, destino, app, categoría, protocolo o pid).
    pub key: String,
    /// Texto visible de la clave.
    pub label: String,
    /// Subtítulo (categoría corta, organización · país…).
    pub subtitle: Option<String>,
    /// Equipo asociado cuando la fila es un equipo.
    pub device_id: Option<i64>,
    /// Bytes de bajada en la ventana.
    pub bytes_down: u64,
    /// Bytes de subida en la ventana.
    pub bytes_up: u64,
    /// Equipos distintos en la ventana.
    pub devices: u32,
    /// Conexiones activas asociadas.
    pub connections: u32,
    /// Serie de 60 s para la sparkline (solo la necesita la agrupación por app).
    pub series_60s: [u64; 60],
}

impl RankRow {
    /// Total de bytes en la ventana.
    pub fn total(&self) -> u64 {
        self.bytes_down.saturating_add(self.bytes_up)
    }
}

/// Cuota de un equipo en el panel «¿Quién lo usa?».
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceShare {
    /// Equipo (o [host]).
    pub device_id: i64,
    /// Nombre visible.
    pub label: String,
    /// Bytes del equipo en la ventana.
    pub bytes: u64,
    /// Porcentaje sobre el total de la clave.
    pub pct: f32,
}

/// Clave concreta de una dimensión, tomada de la etiqueta y del contexto.
#[derive(Debug, Clone, Copy)]
enum Clave<'a> {
    /// Identificador del equipo (incluye -1 = [host]).
    Equipo(i64),
    /// Clave de destino resuelta.
    Destino(&'a str),
    /// Clave de app del catálogo.
    App(&'a str),
    /// Clave de categoría del catálogo.
    Categoria(&'a str),
    /// Protocolo de aplicación (firma, puerto o transporte).
    Protocolo(AppProtocol),
    /// Proceso local del propio equipo.
    Proceso { pid: u32, nombre: &'a str },
}

/// Datos de un apunte que se suma a una clave.
#[derive(Debug, Clone, Copy)]
struct Apunte {
    /// Bytes del paquete o del flujo.
    bytes: u64,
    /// Dirección respecto al cliente.
    dir: Dir,
    /// Instante del dato.
    now: Instant,
    /// Equipo que originó el tráfico, si se conoce.
    device_id: Option<i64>,
}

/// Bytes de un equipo dentro de una clave (panel «¿Quién lo usa?» y top de
/// apps/destinos del detalle de equipo).
#[derive(Debug)]
struct UsoEquipo {
    /// Bytes de bajada en los últimos 60 s.
    bytes_bajada_60: Windows,
    /// Bytes de subida en los últimos 60 s.
    bytes_subida_60: Windows,
    /// Bytes de bajada en los últimos 5 min.
    bytes_bajada_5min: Windows,
    /// Bytes de subida en los últimos 5 min.
    bytes_subida_5min: Windows,
    /// Bytes de bajada desde el arranque.
    sesion_bajada: u64,
    /// Bytes de subida desde el arranque.
    sesion_subida: u64,
}

impl UsoEquipo {
    fn nuevo(origin: Instant) -> Self {
        Self {
            bytes_bajada_60: Windows::new_60s(origin),
            bytes_subida_60: Windows::new_60s(origin),
            bytes_bajada_5min: Windows::new_5min(origin),
            bytes_subida_5min: Windows::new_5min(origin),
            sesion_bajada: 0,
            sesion_subida: 0,
        }
    }

    fn sumar(&mut self, now: Instant, bytes: u64, dir: Dir) {
        match dir {
            Dir::Down => {
                self.bytes_bajada_60.push(now, bytes);
                self.bytes_bajada_5min.push(now, bytes);
                self.sesion_bajada = self.sesion_bajada.saturating_add(bytes);
            }
            Dir::Up => {
                self.bytes_subida_60.push(now, bytes);
                self.bytes_subida_5min.push(now, bytes);
                self.sesion_subida = self.sesion_subida.saturating_add(bytes);
            }
        }
    }

    fn avanzar(&mut self, now: Instant) {
        self.bytes_bajada_60.advance(now);
        self.bytes_subida_60.advance(now);
        self.bytes_bajada_5min.advance(now);
        self.bytes_subida_5min.advance(now);
    }

    fn bajada(&self, window: Window) -> u64 {
        match window {
            Window::Sixty => self.bytes_bajada_60.total(),
            Window::FiveMin => self.bytes_bajada_5min.total(),
            Window::Session => self.sesion_bajada,
            // Las ventanas de 1 h y 24 h salen del histórico (lector).
            Window::OneHour | Window::Day24 => 0,
        }
    }

    fn subida(&self, window: Window) -> u64 {
        match window {
            Window::Sixty => self.bytes_subida_60.total(),
            Window::FiveMin => self.bytes_subida_5min.total(),
            Window::Session => self.sesion_subida,
            // Las ventanas de 1 h y 24 h salen del histórico (lector).
            Window::OneHour | Window::Day24 => 0,
        }
    }

    fn total(&self, window: Window) -> u64 {
        self.bajada(window).saturating_add(self.subida(window))
    }

    /// Serie de 60 s combinada (↓ + ↑ por segundo).
    fn serie_60s(&self) -> [u64; LEN_60S] {
        let bajada = self.bytes_bajada_60.series_60s();
        let subida = self.bytes_subida_60.series_60s();
        std::array::from_fn(|indice| {
            let abajo = bajada.get(indice).copied().unwrap_or(0);
            let arriba = subida.get(indice).copied().unwrap_or(0);
            abajo.saturating_add(arriba)
        })
    }
}

/// Una clave de un ranking con sus contadores.
#[derive(Debug)]
struct Entrada {
    /// Texto visible de la clave (salvo equipos, que se resuelven al pintar).
    label: String,
    /// Subtítulo (organización · país, pid…).
    subtitle: Option<String>,
    /// Clave de categoría de una app (para resolver el subtítulo corto).
    category: Option<String>,
    /// Equipo asociado a la fila (dimensión equipo o destino de la LAN).
    device_id: Option<i64>,
    /// Bytes de bajada en los últimos 60 s.
    bytes_bajada_60: Windows,
    /// Bytes de subida en los últimos 60 s.
    bytes_subida_60: Windows,
    /// Bytes de bajada en los últimos 5 min.
    bytes_bajada_5min: Windows,
    /// Bytes de subida en los últimos 5 min.
    bytes_subida_5min: Windows,
    /// Bytes de bajada desde el arranque.
    sesion_bajada: u64,
    /// Bytes de subida desde el arranque.
    sesion_subida: u64,
    /// Bytes por equipo dentro de la clave.
    equipos: HashMap<i64, UsoEquipo>,
    /// Último instante con bytes en la clave.
    last_seen: Instant,
}

impl Entrada {
    fn nueva(
        origin: Instant,
        now: Instant,
        label: String,
        subtitle: Option<String>,
        category: Option<String>,
        device_id: Option<i64>,
    ) -> Self {
        Self {
            label,
            subtitle,
            category,
            device_id,
            bytes_bajada_60: Windows::new_60s(origin),
            bytes_subida_60: Windows::new_60s(origin),
            bytes_bajada_5min: Windows::new_5min(origin),
            bytes_subida_5min: Windows::new_5min(origin),
            sesion_bajada: 0,
            sesion_subida: 0,
            equipos: HashMap::new(),
            last_seen: now,
        }
    }

    fn sumar(&mut self, origin: Instant, apunte: &Apunte) {
        match apunte.dir {
            Dir::Down => {
                self.bytes_bajada_60.push(apunte.now, apunte.bytes);
                self.bytes_bajada_5min.push(apunte.now, apunte.bytes);
                self.sesion_bajada = self.sesion_bajada.saturating_add(apunte.bytes);
            }
            Dir::Up => {
                self.bytes_subida_60.push(apunte.now, apunte.bytes);
                self.bytes_subida_5min.push(apunte.now, apunte.bytes);
                self.sesion_subida = self.sesion_subida.saturating_add(apunte.bytes);
            }
        }
        if apunte.now > self.last_seen {
            self.last_seen = apunte.now;
        }
        if let Some(id) = apunte.device_id {
            if let Some(uso) = self.equipos.get_mut(&id) {
                uso.sumar(apunte.now, apunte.bytes, apunte.dir);
            } else {
                let mut uso = UsoEquipo::nuevo(origin);
                uso.sumar(apunte.now, apunte.bytes, apunte.dir);
                self.equipos.insert(id, uso);
            }
        }
    }

    fn avanzar(&mut self, now: Instant) {
        self.bytes_bajada_60.advance(now);
        self.bytes_subida_60.advance(now);
        self.bytes_bajada_5min.advance(now);
        self.bytes_subida_5min.advance(now);
        for uso in self.equipos.values_mut() {
            uso.avanzar(now);
        }
    }

    fn bajada(&self, window: Window) -> u64 {
        match window {
            Window::Sixty => self.bytes_bajada_60.total(),
            Window::FiveMin => self.bytes_bajada_5min.total(),
            Window::Session => self.sesion_bajada,
            // Las ventanas de 1 h y 24 h salen del histórico (lector).
            Window::OneHour | Window::Day24 => 0,
        }
    }

    fn subida(&self, window: Window) -> u64 {
        match window {
            Window::Sixty => self.bytes_subida_60.total(),
            Window::FiveMin => self.bytes_subida_5min.total(),
            Window::Session => self.sesion_subida,
            // Las ventanas de 1 h y 24 h salen del histórico (lector).
            Window::OneHour | Window::Day24 => 0,
        }
    }

    fn total(&self, window: Window) -> u64 {
        self.bajada(window).saturating_add(self.subida(window))
    }

    fn equipos_en(&self, window: Window) -> u32 {
        let cantidad = self
            .equipos
            .values()
            .filter(|uso| uso.total(window) > 0)
            .count();
        u32::try_from(cantidad).unwrap_or(u32::MAX)
    }

    /// Serie de 60 s combinada (↓ + ↑ por segundo) para la sparkline.
    fn serie_60s(&self) -> [u64; LEN_60S] {
        let bajada = self.bytes_bajada_60.series_60s();
        let subida = self.bytes_subida_60.series_60s();
        std::array::from_fn(|indice| {
            let abajo = bajada.get(indice).copied().unwrap_or(0);
            let arriba = subida.get(indice).copied().unwrap_or(0);
            abajo.saturating_add(arriba)
        })
    }
}

/// Rankings en memoria.
#[derive(Debug)]
pub struct Rankings {
    /// Origen temporal común de todas las ventanas.
    origin: Instant,
    /// Nombres de equipo por id (los pasa la tarea de tráfico).
    devices: HashMap<i64, String>,
    /// Nombre visible de app por clave del catálogo.
    app_names: HashMap<String, String>,
    /// Nombre corto de categoría por clave del catálogo.
    category_names: HashMap<String, String>,
    /// Categoría corta de cada app del catálogo.
    app_categories: HashMap<String, String>,
    /// Claves de cada dimensión.
    dimensions: [HashMap<String, Entrada>; 6],
    /// Bytes totales (↓ + ↑) por ventana para el porcentaje sin identificar.
    total_60: Windows,
    /// Bytes totales (↓ + ↑) de la ventana de 5 min.
    total_5min: Windows,
    /// Bytes sin app de la ventana de 60 s.
    sin_identificar_60: Windows,
    /// Bytes sin app de la ventana de 5 min.
    sin_identificar_5min: Windows,
    /// Bytes totales desde el arranque.
    total_sesion: u64,
    /// Bytes sin app desde el arranque.
    sin_identificar_sesion: u64,
    /// Conexiones activas por clave y dimensión.
    connections: [HashMap<String, u32>; 6],
    /// Acumuladores del minuto del histórico (F5).
    rollup: MinuteRollup,
}

impl Default for Rankings {
    fn default() -> Self {
        let origin = Instant::now();
        Self {
            origin,
            devices: HashMap::new(),
            app_names: HashMap::new(),
            category_names: HashMap::new(),
            app_categories: HashMap::new(),
            dimensions: std::array::from_fn(|_| HashMap::new()),
            total_60: Windows::new_60s(origin),
            total_5min: Windows::new_5min(origin),
            sin_identificar_60: Windows::new_60s(origin),
            sin_identificar_5min: Windows::new_5min(origin),
            total_sesion: 0,
            sin_identificar_sesion: 0,
            connections: std::array::from_fn(|_| HashMap::new()),
            rollup: MinuteRollup::new(false),
        }
    }
}

impl Rankings {
    /// Crea los rankings vacíos.
    pub fn new() -> Self {
        Self::default()
    }

    /// Actualiza los nombres de equipo que se usan en las etiquetas.
    ///
    /// El mapa debería incluir el centinela -1 con el texto "[host]"; si falta,
    /// se usa ese texto por defecto.
    pub fn set_devices(&mut self, devices: HashMap<i64, String>) {
        self.devices = devices;
    }

    /// Actualiza los nombres visibles de app del catálogo (clave → nombre).
    pub fn set_app_names(&mut self, nombres: HashMap<String, String>) {
        self.app_names = nombres;
    }

    /// Actualiza los nombres cortos de categoría del catálogo (clave → corto).
    pub fn set_category_names(&mut self, nombres: HashMap<String, String>) {
        self.category_names = nombres;
    }

    /// Actualiza la categoría corta de cada app (clave de app → corto).
    pub fn set_app_categories(&mut self, categorias: HashMap<String, String>) {
        self.app_categories = categorias;
    }

    /// Activa o desactiva los acumuladores del histórico ([history].enabled).
    pub fn set_history_enabled(&mut self, enabled: bool) {
        self.rollup.set_enabled(enabled);
    }

    /// Fija el tope de claves de los rollups ([history].top_keys).
    pub fn set_history_top_keys(&mut self, top_keys: usize) {
        self.rollup.set_top_keys(top_keys);
    }

    /// Registra un flujo nuevo del minuto para contar sus conexiones.
    ///
    /// Si el flujo ya se contó en el minuto se refresca su etiqueta (la que
    /// tenga al cerrarse el minuto, §7.2) sin contar otra conexión.
    pub fn record_flow(&mut self, flujo: u64, label: &FlowLabel, ctx: &FlowCtx) {
        if !self.rollup.enabled() {
            return;
        }
        let (subjects, dims) = sujetos_y_dims(label, ctx);
        if self.rollup.conoce_flujo(flujo) {
            self.rollup.actualizar_flujo(flujo, &subjects, &dims);
        } else {
            self.rollup.add_flow(flujo, &subjects, &dims);
        }
    }

    /// Refresca la etiqueta de un flujo ya contado en el minuto, sin contar otra
    /// conexión. Si el flujo no se contó en este minuto, no hace nada.
    pub fn refresh_flow(&mut self, flujo: u64, label: &FlowLabel, ctx: &FlowCtx) {
        if !self.rollup.enabled() || !self.rollup.conoce_flujo(flujo) {
            return;
        }
        let (subjects, dims) = sujetos_y_dims(label, ctx);
        self.rollup.actualizar_flujo(flujo, &subjects, &dims);
    }

    /// Cierra el minuto en curso (parcial) al parar el agregador.
    pub fn flush_rollup(&mut self, wall: SystemTime) -> Option<RollupBatch> {
        if !self.rollup.enabled() {
            return None;
        }
        let minuto = minuto_utc(wall);
        let actual = self.rollup.minute();
        let lote = self.rollup.flush(if actual == 0 { minuto } else { actual });
        if lote.is_empty() {
            None
        } else {
            Some(lote)
        }
    }

    /// Vacía las conexiones activas de todas las dimensiones.
    ///
    /// La tarea de tráfico lo llama una vez por segundo, antes de registrar con
    /// [Rankings::record_connection] las conexiones vivas de su caché.
    pub fn begin_connections(&mut self) {
        for contadores in &mut self.connections {
            contadores.clear();
        }
    }

    /// Anota una conexión activa en las claves que ya existen en los rankings.
    ///
    /// No crea filas nuevas: una conexión sin bytes todavía no aparece en el
    /// ranking. El que muestra la TUI es el número de conexiones vivas de la
    /// caché de tráfico que comparten clave.
    pub fn record_connection(&mut self, label: &FlowLabel, ctx: &FlowCtx) {
        for (dim, clave) in Dimension::ALL.iter().copied().zip(claves(label, ctx)) {
            let Some(clave) = clave else { continue };
            match clave {
                Clave::Equipo(id) => {
                    let key = id.to_string();
                    self.contar_conexion(dim, &key);
                }
                Clave::Destino(key) | Clave::App(key) | Clave::Categoria(key) => {
                    self.contar_conexion(dim, key);
                }
                Clave::Protocolo(protocolo) => self.contar_conexion(dim, protocolo.as_str()),
                Clave::Proceso { pid, .. } => {
                    let key = pid.to_string();
                    self.contar_conexion(dim, &key);
                }
            }
        }
    }

    /// Suma los bytes de un paquete a cada dimensión.
    pub fn record(&mut self, label: &FlowLabel, ctx: &FlowCtx, bytes: u64, dir: Dir, now: Instant) {
        // Totales para el porcentaje sin identificar de la ventana.
        self.total_60.push(now, bytes);
        self.total_5min.push(now, bytes);
        self.total_sesion = self.total_sesion.saturating_add(bytes);
        let con_app = label
            .app
            .as_deref()
            .map(|app| !app.is_empty())
            .unwrap_or(false);
        if !con_app {
            self.sin_identificar_60.push(now, bytes);
            self.sin_identificar_5min.push(now, bytes);
            self.sin_identificar_sesion = self.sin_identificar_sesion.saturating_add(bytes);
        }

        let apunte = Apunte {
            bytes,
            dir,
            now,
            device_id: ctx.device_id,
        };
        for (dim, clave) in Dimension::ALL.iter().copied().zip(claves(label, ctx)) {
            let Some(clave) = clave else { continue };
            match clave {
                Clave::Equipo(id) => {
                    let key = id.to_string();
                    self.acumular(dim, &key, apunte, |origin, now| {
                        Entrada::nueva(origin, now, String::new(), None, None, Some(id))
                    });
                }
                Clave::Destino(key) => {
                    let destino = &label.destination;
                    let equipo_lan = match destino.kind {
                        DestinationKind::Lan => destino
                            .key
                            .strip_prefix("lan:")
                            .and_then(|id| id.parse::<i64>().ok()),
                        _ => None,
                    };
                    self.acumular(dim, key, apunte, |origin, now| {
                        let subtitulo = destino.subtitle();
                        let subtitulo = if subtitulo.is_empty() {
                            None
                        } else {
                            Some(subtitulo)
                        };
                        Entrada::nueva(
                            origin,
                            now,
                            destino.label.clone(),
                            subtitulo,
                            None,
                            equipo_lan,
                        )
                    });
                }
                Clave::App(key) => {
                    let categoria = label.category.as_deref();
                    self.acumular(dim, key, apunte, |origin, now| {
                        Entrada::nueva(
                            origin,
                            now,
                            key.to_string(),
                            None,
                            categoria.map(str::to_string),
                            None,
                        )
                    });
                }
                Clave::Categoria(key) => {
                    self.acumular(dim, key, apunte, |origin, now| {
                        Entrada::nueva(origin, now, key.to_string(), None, None, None)
                    });
                }
                Clave::Protocolo(protocolo) => {
                    self.acumular(dim, protocolo.as_str(), apunte, |origin, now| {
                        Entrada::nueva(origin, now, protocolo.label().to_string(), None, None, None)
                    });
                }
                Clave::Proceso { pid, nombre } => {
                    let key = pid.to_string();
                    self.acumular(dim, &key, apunte, |origin, now| {
                        let etiqueta = if nombre.is_empty() {
                            key.clone()
                        } else {
                            nombre.to_string()
                        };
                        Entrada::nueva(
                            origin,
                            now,
                            etiqueta,
                            Some(format!("pid {pid}")),
                            None,
                            None,
                        )
                    });
                }
            }
        }

        // Mismo volcado por flujo y segundo que los rankings: acumuladores del
        // histórico del minuto en curso (§7.2).
        if self.rollup.enabled() {
            let (subjects, dims) = sujetos_y_dims(label, ctx);
            self.rollup.add(&subjects, &dims, bytes, dir);
        }
    }

    /// Avanza las ventanas, desaloja claves inactivas y cierra el minuto.
    ///
    /// Cuando el reloj UTC cambia de minuto devuelve el lote del histórico del
    /// minuto cerrado (con topes e inventario) para que la tarea de tráfico lo
    /// publique como AppEvent::Rollup. Sin histórico activo devuelve None.
    pub fn tick(&mut self, now: Instant, wall: SystemTime) -> Option<RollupBatch> {
        self.total_60.advance(now);
        self.total_5min.advance(now);
        self.sin_identificar_60.advance(now);
        self.sin_identificar_5min.advance(now);
        for dim in Dimension::ALL {
            if let Some(mapa) = self.dimensions.get_mut(dim.index()) {
                for entrada in mapa.values_mut() {
                    entrada.avanzar(now);
                }
            }
        }
        for dim in Dimension::ALL {
            self.desalojar(dim, now);
        }
        self.cerrar_minuto(wall)
    }

    /// Cierra el minuto del histórico si el reloj UTC ha cambiado de minuto.
    fn cerrar_minuto(&mut self, wall: SystemTime) -> Option<RollupBatch> {
        if !self.rollup.enabled() {
            return None;
        }
        let minuto = minuto_utc(wall);
        let actual = self.rollup.minute();
        if actual == 0 {
            self.rollup.set_minute(minuto);
            return None;
        }
        if minuto <= actual {
            // Salto atrás del reloj: el minuto sigue acumulando en su cubo.
            return None;
        }
        let lote = self.rollup.flush(actual);
        self.rollup.set_minute(minuto);
        if lote.is_empty() {
            None
        } else {
            Some(lote)
        }
    }

    /// Filas de un ranking ordenadas.
    ///
    /// Solo devuelve claves con bytes en la ventana pedida; el resto de filas se
    /// consideran sin datos. El pico de 60 s es el máximo de series_60s.
    pub fn top(&self, dim: Dimension, window: Window, sort: SortKey, n: usize) -> Vec<RankRow> {
        if n == 0 {
            return Vec::new();
        }
        let Some(mapa) = self.dimensions.get(dim.index()) else {
            return Vec::new();
        };
        let mut filas: Vec<(&String, &Entrada)> = mapa
            .iter()
            .filter(|(_, entrada)| entrada.total(window) > 0)
            .collect();
        match sort {
            SortKey::Total => filas.sort_by(|a, b| {
                b.1.total(window)
                    .cmp(&a.1.total(window))
                    .then_with(|| a.0.as_str().cmp(b.0.as_str()))
            }),
            SortKey::Down => filas.sort_by(|a, b| {
                b.1.bajada(window)
                    .cmp(&a.1.bajada(window))
                    .then_with(|| b.1.total(window).cmp(&a.1.total(window)))
                    .then_with(|| a.0.as_str().cmp(b.0.as_str()))
            }),
            SortKey::Up => filas.sort_by(|a, b| {
                b.1.subida(window)
                    .cmp(&a.1.subida(window))
                    .then_with(|| b.1.total(window).cmp(&a.1.total(window)))
                    .then_with(|| a.0.as_str().cmp(b.0.as_str()))
            }),
            SortKey::Devices => filas.sort_by(|a, b| {
                b.1.equipos_en(window)
                    .cmp(&a.1.equipos_en(window))
                    .then_with(|| b.1.total(window).cmp(&a.1.total(window)))
                    .then_with(|| a.0.as_str().cmp(b.0.as_str()))
            }),
        }
        filas
            .into_iter()
            .take(n)
            .map(|(clave, entrada)| self.fila(dim, window, clave, entrada))
            .collect()
    }

    /// Ranking de un único equipo (top de apps y destinos del detalle de equipo).
    ///
    /// Devuelve las claves en las que ese equipo tiene bytes en la ventana, con
    /// los bytes del equipo (no el total de la clave) y ordenadas por total de
    /// bytes descendente. La serie de 60 s solo se rellena en la dimensión App.
    pub fn top_for_device(
        &self,
        dim: Dimension,
        device_id: i64,
        window: Window,
        n: usize,
    ) -> Vec<RankRow> {
        if n == 0 {
            return Vec::new();
        }
        let Some(mapa) = self.dimensions.get(dim.index()) else {
            return Vec::new();
        };
        let mut filas: Vec<(&String, &Entrada, &UsoEquipo)> = mapa
            .iter()
            .filter_map(|(clave, entrada)| {
                let uso = entrada.equipos.get(&device_id)?;
                if uso.total(window) == 0 {
                    return None;
                }
                Some((clave, entrada, uso))
            })
            .collect();
        filas.sort_by(|a, b| {
            b.2.total(window)
                .cmp(&a.2.total(window))
                .then_with(|| a.0.as_str().cmp(b.0.as_str()))
        });
        filas
            .into_iter()
            .take(n)
            .map(|(clave, entrada, uso)| {
                let mut fila = self.fila(dim, window, clave, entrada);
                fila.bytes_down = uso.bajada(window);
                fila.bytes_up = uso.subida(window);
                fila.devices = 1;
                fila.device_id = Some(device_id);
                if dim == Dimension::App {
                    fila.series_60s = uso.serie_60s();
                }
                fila
            })
            .collect()
    }

    /// Equipos que usan una clave, con sus bytes y porcentaje.
    ///
    /// Solo incluye equipos con bytes en la ventana; los porcentajes son sobre
    /// el total de la clave en esa misma ventana (sin redondear).
    pub fn who_uses(&self, dim: Dimension, key: &str, window: Window) -> Vec<DeviceShare> {
        let Some(mapa) = self.dimensions.get(dim.index()) else {
            return Vec::new();
        };
        let Some(entrada) = mapa.get(key) else {
            return Vec::new();
        };
        let total = entrada.total(window);
        let mut cuotas: Vec<DeviceShare> = entrada
            .equipos
            .iter()
            .filter_map(|(id, uso)| {
                let bytes = uso.total(window);
                if bytes == 0 {
                    return None;
                }
                let pct = if total == 0 {
                    0.0
                } else {
                    (bytes as f64 / total as f64 * 100.0) as f32
                };
                Some(DeviceShare {
                    device_id: *id,
                    label: etiqueta_equipo(&self.devices, *id),
                    bytes,
                    pct,
                })
            })
            .collect();
        cuotas.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.device_id.cmp(&b.device_id))
        });
        cuotas
    }

    /// Porcentaje de bytes sin identificar en la ventana (0-100).
    pub fn unidentified_share(&self, window: Window) -> f32 {
        let (sin_identificar, total) = match window {
            Window::Sixty => (self.sin_identificar_60.total(), self.total_60.total()),
            Window::FiveMin => (self.sin_identificar_5min.total(), self.total_5min.total()),
            Window::Session => (self.sin_identificar_sesion, self.total_sesion),
            // Las ventanas de 1 h y 24 h salen del histórico (lector).
            Window::OneHour | Window::Day24 => (0, 0),
        };
        if total == 0 {
            return 0.0;
        }
        let pct = (sin_identificar as f64 / total as f64 * 100.0) as f32;
        pct.clamp(0.0, 100.0)
    }

    /// Suma un apunte a la clave de una dimensión, creándola si hace falta.
    fn acumular(
        &mut self,
        dim: Dimension,
        key: &str,
        apunte: Apunte,
        crear: impl FnOnce(Instant, Instant) -> Entrada,
    ) {
        let origin = self.origin;
        let excedido;
        {
            let Some(mapa) = self.dimensions.get_mut(dim.index()) else {
                return;
            };
            if let Some(entrada) = mapa.get_mut(key) {
                entrada.sumar(origin, &apunte);
                return;
            }
            // La clave se crea ya con el apunte actual: si no, el primer paquete
            // de una clave nueva se perdería.
            let mut entrada = crear(origin, apunte.now);
            entrada.sumar(origin, &apunte);
            mapa.insert(key.to_string(), entrada);
            excedido = mapa.len() > MAX_CLAVES_POR_DIMENSION;
        }
        if excedido {
            self.desalojar(dim, apunte.now);
        }
    }

    /// Anota una conexión activa si la clave ya existe.
    fn contar_conexion(&mut self, dim: Dimension, clave: &str) {
        let Some(mapa_claves) = self.dimensions.get(dim.index()) else {
            return;
        };
        if !mapa_claves.contains_key(clave) {
            return;
        }
        let Some(contadores) = self.connections.get_mut(dim.index()) else {
            return;
        };
        if let Some(contador) = contadores.get_mut(clave) {
            *contador = contador.saturating_add(1);
            return;
        }
        contadores.insert(clave.to_string(), 1);
    }

    /// Desaloja claves hasta respetar el tope de la dimensión.
    fn desalojar(&mut self, dim: Dimension, ahora: Instant) {
        let Some(mapa) = self.dimensions.get_mut(dim.index()) else {
            return;
        };
        let exceso = mapa.len().saturating_sub(MAX_CLAVES_POR_DIMENSION);
        if exceso == 0 {
            return;
        }
        // 1) Claves sin bytes en 5 min, de la más antigua a la más reciente.
        let mut inactivas: Vec<(Instant, String)> = mapa
            .iter()
            .filter(|(_, entrada)| {
                ahora.saturating_duration_since(entrada.last_seen) >= INACTIVIDAD_DESALOJO
            })
            .map(|(clave, entrada)| (entrada.last_seen, clave.clone()))
            .collect();
        inactivas.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut faltan = exceso;
        for (_, clave) in inactivas {
            if faltan == 0 {
                break;
            }
            mapa.remove(&clave);
            faltan -= 1;
        }
        // 2) Protección de memoria: si todas siguen activas, fuera la más
        //    antigua para no crecer sin límite con destinos hostiles.
        if faltan > 0 {
            let mut activas: Vec<(Instant, String)> = mapa
                .iter()
                .map(|(clave, entrada)| (entrada.last_seen, clave.clone()))
                .collect();
            activas.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            for (_, clave) in activas.into_iter().take(faltan) {
                mapa.remove(&clave);
            }
        }
    }

    /// Construye la fila visible de una clave.
    fn fila(&self, dim: Dimension, window: Window, key: &str, entrada: &Entrada) -> RankRow {
        RankRow {
            key: key.to_string(),
            label: self.etiqueta(dim, key, entrada),
            subtitle: self.subtitulo(dim, key, entrada),
            device_id: entrada.device_id,
            bytes_down: entrada.bajada(window),
            bytes_up: entrada.subida(window),
            devices: entrada.equipos_en(window),
            connections: self
                .connections
                .get(dim.index())
                .and_then(|contadores| contadores.get(key))
                .copied()
                .unwrap_or(0),
            series_60s: if dim == Dimension::App {
                entrada.serie_60s()
            } else {
                [0u64; LEN_60S]
            },
        }
    }

    /// Texto visible de una clave.
    fn etiqueta(&self, dim: Dimension, key: &str, entrada: &Entrada) -> String {
        match dim {
            Dimension::Device => match entrada.device_id {
                Some(id) => etiqueta_equipo(&self.devices, id),
                None => entrada.label.clone(),
            },
            Dimension::App => self
                .app_names
                .get(key)
                .cloned()
                .unwrap_or_else(|| entrada.label.clone()),
            Dimension::Category => self
                .category_names
                .get(key)
                .cloned()
                .unwrap_or_else(|| entrada.label.clone()),
            _ => entrada.label.clone(),
        }
    }

    /// Subtítulo visible de una clave.
    fn subtitulo(&self, dim: Dimension, key: &str, entrada: &Entrada) -> Option<String> {
        match dim {
            Dimension::App => {
                if let Some(corto) = self.app_categories.get(key) {
                    return Some(corto.clone());
                }
                entrada
                    .category
                    .as_deref()
                    .and_then(|categoria| self.category_names.get(categoria))
                    .cloned()
            }
            Dimension::Destination | Dimension::Process => entrada.subtitle.clone(),
            _ => None,
        }
    }
}

/// Claves de las seis dimensiones para un flujo.
fn claves<'a>(label: &'a FlowLabel, ctx: &'a FlowCtx) -> [Option<Clave<'a>>; 6] {
    let equipo = ctx.device_id.map(Clave::Equipo);
    let destino = if label.destination.key.is_empty() {
        None
    } else {
        Some(Clave::Destino(&label.destination.key))
    };
    let app = label
        .app
        .as_deref()
        .filter(|clave| !clave.is_empty())
        .map(Clave::App);
    let categoria = label
        .category
        .as_deref()
        .filter(|clave| !clave.is_empty())
        .map(Clave::Categoria);
    let protocolo = label
        .app_protocol
        .or(ctx.protocol)
        .or_else(|| ctx.l4.map(protocolo_de_transporte))
        .map(Clave::Protocolo);
    let proceso = match &ctx.process {
        Some((pid, nombre)) if matches!(ctx.device_id, None | Some(DEVICE_ID_HOST)) => {
            Some(Clave::Proceso {
                pid: *pid,
                nombre: nombre.as_str(),
            })
        }
        _ => None,
    };
    [equipo, destino, app, categoria, protocolo, proceso]
}

/// Protocolo genérico de transporte para el ranking de protocolos.
fn protocolo_de_transporte(l4: L4) -> AppProtocol {
    match l4 {
        L4::Tcp => AppProtocol::Tcp,
        L4::Udp => AppProtocol::Udp,
    }
}

/// Inicio del minuto UTC de un instante del reloj de pared.
fn minuto_utc(wall: SystemTime) -> i64 {
    let segundos = wall
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    segundos - segundos.rem_euclid(60)
}

/// Nombre visible de un equipo; -1 es siempre la fila [host].
fn etiqueta_equipo(devices: &HashMap<i64, String>, id: i64) -> String {
    if let Some(nombre) = devices.get(&id) {
        return nombre.clone();
    }
    if id == DEVICE_ID_HOST {
        "[host]".to_string()
    } else {
        format!("#{id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::DestinationInfo;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba")
    }

    fn destino_ip(texto: &str) -> DestinationInfo {
        DestinationInfo::unknown(ip(texto))
    }

    fn destino_dominio(clave: &str, org: Option<&str>, pais: Option<&str>) -> DestinationInfo {
        DestinationInfo {
            key: clave.to_string(),
            label: clave.to_string(),
            org: org.map(str::to_string),
            country: pais.map(str::to_string),
            kind: DestinationKind::Domain,
        }
    }

    fn destino_lan(id: i64, nombre: &str) -> DestinationInfo {
        DestinationInfo {
            key: format!("lan:{id}"),
            label: nombre.to_string(),
            org: None,
            country: None,
            kind: DestinationKind::Lan,
        }
    }

    fn etiqueta(
        app: Option<&str>,
        categoria: Option<&str>,
        protocolo: Option<AppProtocol>,
        destino: DestinationInfo,
    ) -> FlowLabel {
        FlowLabel {
            app_protocol: protocolo,
            server_name: None,
            name_source: None,
            app: app.map(str::to_string),
            category: categoria.map(str::to_string),
            app_source: None,
            ja4: None,
            client_is_src: Some(true),
            strength: 5,
            destination: destino,
        }
    }

    fn contexto(device_id: Option<i64>, process: Option<(u32, &str)>) -> FlowCtx {
        FlowCtx {
            device_id,
            process: process.map(|(pid, nombre)| (pid, nombre.to_string())),
            l4: Some(L4::Tcp),
            protocol: None,
            es_cliente: false,
        }
    }

    fn mapa_equipos() -> HashMap<i64, String> {
        HashMap::from([
            (1, "laptop".to_string()),
            (2, "movil".to_string()),
            (5, "nas".to_string()),
            (7, "tv".to_string()),
            (DEVICE_ID_HOST, "[host]".to_string()),
        ])
    }

    fn claves_de(filas: &[RankRow]) -> Vec<&str> {
        filas.iter().map(|fila| fila.key.as_str()).collect()
    }

    fn fila_de(
        rankings: &Rankings,
        dim: Dimension,
        window: Window,
        clave: &str,
    ) -> Option<RankRow> {
        rankings
            .top(dim, window, SortKey::Total, MAX_CLAVES_POR_DIMENSION)
            .into_iter()
            .find(|fila| fila.key == clave)
    }

    #[test]
    fn suma_bytes_por_dimension_y_ventana() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let destino = destino_dominio("youtube.com", Some("Google LLC"), Some("US"));
        let flujo = etiqueta(
            Some("youtube"),
            Some("streaming"),
            Some(AppProtocol::Tls),
            destino,
        );
        let ctx = contexto(Some(1), None);
        rankings.record(&flujo, &ctx, 1_000, Dir::Down, t0);
        rankings.record(&flujo, &ctx, 200, Dir::Up, t0 + Duration::from_secs(1));
        let _ = rankings.tick(t0 + Duration::from_secs(2), std::time::SystemTime::now());

        for window in Window::ALL {
            let apps = rankings.top(Dimension::App, window, SortKey::Total, 10);
            assert_eq!(apps.len(), 1, "{window:?}");
            assert_eq!(apps[0].key, "youtube");
            assert_eq!(apps[0].label, "youtube", "sin catálogo se muestra la clave");
            assert_eq!(apps[0].subtitle, None);
            assert_eq!(apps[0].bytes_down, 1_000);
            assert_eq!(apps[0].bytes_up, 200);
            assert_eq!(apps[0].total(), 1_200);
            assert_eq!(apps[0].devices, 1);
            assert_eq!(apps[0].connections, 0);
            assert_eq!(apps[0].series_60s.iter().sum::<u64>(), 1_200);

            let destinos = rankings.top(Dimension::Destination, window, SortKey::Total, 10);
            assert_eq!(destinos.len(), 1, "{window:?}");
            assert_eq!(destinos[0].key, "youtube.com");
            assert_eq!(destinos[0].label, "youtube.com");
            assert_eq!(destinos[0].subtitle.as_deref(), Some("Google LLC · US"));
            assert_eq!(destinos[0].bytes_down, 1_000);
            assert_eq!(destinos[0].bytes_up, 200);
            assert_eq!(destinos[0].device_id, None);
            assert_eq!(
                destinos[0].series_60s, [0u64; LEN_60S],
                "la serie solo se rellena en la agrupación por app"
            );

            let equipos = rankings.top(Dimension::Device, window, SortKey::Total, 10);
            assert_eq!(equipos.len(), 1, "{window:?}");
            assert_eq!(equipos[0].key, "1");
            assert_eq!(equipos[0].label, "laptop");
            assert_eq!(equipos[0].device_id, Some(1));
            assert_eq!(equipos[0].total(), 1_200);

            let categorias = rankings.top(Dimension::Category, window, SortKey::Total, 10);
            assert_eq!(categorias.len(), 1, "{window:?}");
            assert_eq!(categorias[0].key, "streaming");
            assert_eq!(categorias[0].label, "streaming");

            let protocolos = rankings.top(Dimension::Protocol, window, SortKey::Total, 10);
            assert_eq!(protocolos.len(), 1, "{window:?}");
            assert_eq!(protocolos[0].key, "tls");
            assert_eq!(protocolos[0].label, "TLS");
            assert_eq!(protocolos[0].total(), 1_200);

            assert!(
                rankings
                    .top(Dimension::Process, window, SortKey::Total, 10)
                    .is_empty(),
                "{window:?}"
            );
        }
    }

    #[test]
    fn el_historico_cierra_el_minuto_con_el_reloj_utc() {
        let mut rankings = Rankings::new();
        rankings.set_history_enabled(true);
        rankings.set_history_top_keys(20);
        let t0 = Instant::now();
        let base = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let flujo = etiqueta(
            Some("youtube"),
            Some("streaming"),
            Some(AppProtocol::Tls),
            destino_dominio("youtube.com", Some("Google LLC"), Some("US")),
        );
        let ctx = FlowCtx {
            device_id: Some(1),
            protocol: Some(AppProtocol::Tls),
            ..FlowCtx::default()
        };
        rankings.record(&flujo, &ctx, 100, Dir::Down, t0);
        rankings.record_flow(7, &flujo, &ctx);
        // El primer tick solo fija el minuto en curso.
        assert!(rankings.tick(t0, base).is_none());
        // Al cambiar de minuto devuelve el lote del minuto cerrado.
        let lote = rankings
            .tick(t0 + Duration::from_secs(60), base + Duration::from_secs(60))
            .expect("lote del minuto");
        assert_eq!(lote.minute, 1_800_000_000);
        assert!(lote
            .rows
            .iter()
            .any(|fila| fila.dimension == crate::history::Dimension::Total));
        assert!(lote
            .rows
            .iter()
            .any(|fila| fila.dimension == crate::history::Dimension::App));
        assert!(lote
            .seen
            .iter()
            .any(|item| item.kind == crate::history::SeenKind::App));
        // Un tick en el mismo minuto no vuelve a emitir lote.
        assert!(rankings
            .tick(t0 + Duration::from_secs(61), base + Duration::from_secs(61))
            .is_none());
    }

    #[test]
    fn el_minuto_parcial_se_cierra_al_parar() {
        let mut rankings = Rankings::new();
        rankings.set_history_enabled(true);
        let t0 = Instant::now();
        let base = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let flujo = etiqueta(Some("youtube"), None, None, destino_ip("1.1.1.1"));
        let ctx = FlowCtx {
            device_id: Some(1),
            ..FlowCtx::default()
        };
        rankings.record(&flujo, &ctx, 50, Dir::Down, t0);
        // Primer tick: fija el minuto en curso sin emitir lote.
        assert!(rankings.tick(t0, base).is_none());
        // Al parar, el minuto parcial sale con su bucket.
        let lote = rankings
            .flush_rollup(base + Duration::from_secs(10))
            .expect("minuto parcial");
        assert_eq!(lote.minute, 1_800_000_000);
        assert!(!lote.rows.is_empty());
        // Después de cerrarlo, otro flush no inventa un lote vacío.
        assert!(rankings
            .flush_rollup(base + Duration::from_secs(11))
            .is_none());
    }

    #[test]
    fn el_avance_de_ventana_descarta_lo_caducado() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let flujo = etiqueta(
            Some("youtube"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("1.1.1.1"),
        );
        let ctx = contexto(Some(1), None);
        rankings.record(&flujo, &ctx, 500, Dir::Down, t0);

        let _ = rankings.tick(t0 + Duration::from_secs(30), std::time::SystemTime::now());
        assert_eq!(
            fila_de(&rankings, Dimension::App, Window::Sixty, "youtube").map(|fila| fila.total()),
            Some(500),
            "a los 30 s el dato sigue en la ventana de 60 s"
        );

        let _ = rankings.tick(t0 + Duration::from_secs(61), std::time::SystemTime::now());
        assert!(
            rankings
                .top(Dimension::App, Window::Sixty, SortKey::Total, 10)
                .is_empty(),
            "el dato de la ventana de 60 s caduca"
        );
        assert_eq!(
            fila_de(&rankings, Dimension::App, Window::FiveMin, "youtube").map(|fila| fila.total()),
            Some(500),
            "la ventana de 5 min conserva el dato"
        );
        assert_eq!(
            fila_de(&rankings, Dimension::App, Window::Session, "youtube").map(|fila| fila.total()),
            Some(500),
            "el acumulado de sesión conserva el dato"
        );

        let _ = rankings.tick(t0 + Duration::from_secs(301), std::time::SystemTime::now());
        assert!(
            rankings
                .top(Dimension::App, Window::FiveMin, SortKey::Total, 10)
                .is_empty(),
            "el dato de la ventana de 5 min caduca"
        );
        assert_eq!(
            fila_de(&rankings, Dimension::App, Window::Session, "youtube").map(|fila| fila.total()),
            Some(500),
            "la sesión no caduca hasta cerrar la app"
        );
    }

    #[test]
    fn ordena_por_total_bajada_subida_y_equipos() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let uno = contexto(Some(1), None);
        let dos = contexto(Some(2), None);
        let a = etiqueta(
            Some("a"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("1.0.0.1"),
        );
        let b = etiqueta(
            Some("b"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("1.0.0.2"),
        );
        let c = etiqueta(
            Some("c"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("1.0.0.3"),
        );
        rankings.record(&a, &uno, 100, Dir::Down, t0);
        rankings.record(&b, &uno, 10, Dir::Down, t0);
        rankings.record(&b, &dos, 10, Dir::Down, t0);
        rankings.record(&b, &uno, 50, Dir::Up, t0);
        rankings.record(&c, &uno, 200, Dir::Down, t0);
        let _ = rankings.tick(t0 + Duration::from_secs(1), std::time::SystemTime::now());

        assert_eq!(
            claves_de(&rankings.top(Dimension::App, Window::Sixty, SortKey::Total, 10)),
            vec!["c", "a", "b"]
        );
        assert_eq!(
            claves_de(&rankings.top(Dimension::App, Window::Sixty, SortKey::Down, 10)),
            vec!["c", "a", "b"]
        );
        assert_eq!(
            claves_de(&rankings.top(Dimension::App, Window::Sixty, SortKey::Up, 10)),
            vec!["b", "c", "a"]
        );
        assert_eq!(
            claves_de(&rankings.top(Dimension::App, Window::Sixty, SortKey::Devices, 10)),
            vec!["b", "c", "a"]
        );
        assert!(rankings
            .top(Dimension::App, Window::Sixty, SortKey::Total, 0)
            .is_empty());
        assert!(Rankings::new()
            .top(Dimension::App, Window::Sixty, SortKey::Total, 10)
            .is_empty());
    }

    #[test]
    fn who_uses_reparte_por_equipo_y_porcentaje() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let flujo = etiqueta(
            Some("youtube"),
            Some("streaming"),
            Some(AppProtocol::Tls),
            destino_ip("1.1.1.1"),
        );
        rankings.record(&flujo, &contexto(Some(1), None), 300, Dir::Down, t0);
        rankings.record(&flujo, &contexto(Some(2), None), 100, Dir::Up, t0);
        rankings.record(
            &flujo,
            &contexto(Some(DEVICE_ID_HOST), None),
            100,
            Dir::Down,
            t0,
        );
        let _ = rankings.tick(t0 + Duration::from_secs(1), std::time::SystemTime::now());

        let cuotas = rankings.who_uses(Dimension::App, "youtube", Window::Sixty);
        assert_eq!(cuotas.len(), 3);
        assert_eq!(cuotas[0].device_id, 1);
        assert_eq!(cuotas[0].label, "laptop");
        assert_eq!(cuotas[0].bytes, 300);
        assert!((cuotas[0].pct - 60.0).abs() < 0.01);
        // Empate a 100 bytes: desempata el id (-1 = [host] va primero).
        assert_eq!(cuotas[1].device_id, DEVICE_ID_HOST);
        assert_eq!(cuotas[1].label, "[host]");
        assert!((cuotas[1].pct - 20.0).abs() < 0.01);
        assert_eq!(cuotas[2].device_id, 2);
        assert!((cuotas[2].pct - 20.0).abs() < 0.01);
        assert_eq!(cuotas.iter().map(|cuota| cuota.bytes).sum::<u64>(), 500);

        // La ventana de sesión sigue repartiendo los mismos bytes.
        let _ = rankings.tick(t0 + Duration::from_secs(400), std::time::SystemTime::now());
        assert!(
            rankings
                .top(Dimension::App, Window::FiveMin, SortKey::Total, 10)
                .is_empty(),
            "la ventana de 5 min ya no tiene bytes"
        );
        let sesion = rankings.who_uses(Dimension::App, "youtube", Window::Session);
        assert_eq!(sesion.iter().map(|cuota| cuota.bytes).sum::<u64>(), 500);
        assert_eq!(
            fila_de(&rankings, Dimension::App, Window::Session, "youtube").map(|fila| fila.devices),
            Some(3)
        );

        assert!(rankings
            .who_uses(Dimension::App, "inexistente", Window::Sixty)
            .is_empty());
        assert!(rankings
            .who_uses(Dimension::Destination, "inexistente", Window::Sixty)
            .is_empty());
    }

    #[test]
    fn porcentaje_sin_identificar_por_ventana() {
        let mut rankings = Rankings::new();
        let t0 = Instant::now();
        let sin_app = etiqueta(None, None, Some(AppProtocol::Tls), destino_ip("1.1.1.1"));
        let con_app = etiqueta(
            Some("dns"),
            Some("infra"),
            Some(AppProtocol::Dns),
            destino_ip("8.8.8.8"),
        );
        rankings.record(&sin_app, &contexto(Some(1), None), 900, Dir::Down, t0);
        rankings.record(&con_app, &contexto(Some(1), None), 100, Dir::Down, t0);
        let _ = rankings.tick(t0 + Duration::from_secs(1), std::time::SystemTime::now());

        assert!((rankings.unidentified_share(Window::Sixty) - 90.0).abs() < 0.01);
        assert!((rankings.unidentified_share(Window::FiveMin) - 90.0).abs() < 0.01);
        assert!((rankings.unidentified_share(Window::Session) - 90.0).abs() < 0.01);

        let mut limpio = Rankings::new();
        limpio.record(&con_app, &contexto(Some(1), None), 100, Dir::Down, t0);
        let _ = limpio.tick(t0 + Duration::from_secs(1), std::time::SystemTime::now());
        assert_eq!(limpio.unidentified_share(Window::Sixty), 0.0);
        assert_eq!(Rankings::new().unidentified_share(Window::Session), 0.0);

        let _ = rankings.tick(t0 + Duration::from_secs(61), std::time::SystemTime::now());
        assert_eq!(
            rankings.unidentified_share(Window::Sixty),
            0.0,
            "sin bytes en la ventana el porcentaje vuelve a cero"
        );
        assert!((rankings.unidentified_share(Window::FiveMin) - 90.0).abs() < 0.01);
    }

    #[test]
    fn claves_de_destino_de_la_lan() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let flujo = etiqueta(
            Some("smb"),
            Some("lan"),
            Some(AppProtocol::Smb),
            destino_lan(5, "nas-synology"),
        );
        rankings.record(&flujo, &contexto(Some(1), None), 800, Dir::Down, t0);
        let _ = rankings.tick(t0 + Duration::from_secs(1), std::time::SystemTime::now());

        let destinos = rankings.top(Dimension::Destination, Window::Sixty, SortKey::Total, 10);
        assert_eq!(destinos.len(), 1);
        assert_eq!(destinos[0].key, "lan:5");
        assert_eq!(destinos[0].label, "nas-synology");
        assert_eq!(destinos[0].subtitle.as_deref(), Some("red local"));
        assert_eq!(destinos[0].device_id, Some(5));

        let cuotas = rankings.who_uses(Dimension::Destination, "lan:5", Window::Sixty);
        assert_eq!(cuotas.len(), 1);
        assert_eq!(cuotas[0].device_id, 1);
        assert_eq!(cuotas[0].label, "laptop");
        assert!((cuotas[0].pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn el_ranking_de_procesos_solo_cuenta_el_trafico_del_host() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let flujo = etiqueta(
            Some("web"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("1.1.1.1"),
        );
        rankings.record(
            &flujo,
            &contexto(Some(DEVICE_ID_HOST), Some((1234, "firefox"))),
            100,
            Dir::Down,
            t0,
        );
        // Proceso de un equipo de la LAN: no entra en el ranking de procesos.
        rankings.record(
            &flujo,
            &contexto(Some(7), Some((99, "dnsmasq"))),
            100,
            Dir::Down,
            t0,
        );
        // Sin atribución de equipo pero con proceso: también es tráfico del host.
        rankings.record(
            &flujo,
            &contexto(None, Some((55, "curl"))),
            100,
            Dir::Down,
            t0,
        );
        rankings.record(
            &flujo,
            &contexto(Some(DEVICE_ID_HOST), None),
            100,
            Dir::Down,
            t0,
        );
        let _ = rankings.tick(t0 + Duration::from_secs(1), std::time::SystemTime::now());

        let filas = rankings.top(Dimension::Process, Window::Sixty, SortKey::Total, 10);
        assert_eq!(claves_de(&filas), vec!["1234", "55"]);
        assert_eq!(filas[0].key, "1234");
        assert_eq!(filas[0].label, "firefox");
        assert_eq!(filas[0].subtitle.as_deref(), Some("pid 1234"));
        assert_eq!(filas[0].total(), 100);
        assert!(!claves_de(&filas).contains(&"99"));
    }

    #[test]
    fn conexiones_activas_por_clave() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let youtube = etiqueta(
            Some("youtube"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("1.1.1.1"),
        );
        let dns = etiqueta(
            Some("dns"),
            None,
            Some(AppProtocol::Dns),
            destino_ip("8.8.8.8"),
        );
        rankings.record(&youtube, &contexto(Some(1), None), 100, Dir::Down, t0);
        rankings.record(&dns, &contexto(Some(1), None), 50, Dir::Down, t0);
        let _ = rankings.tick(t0, std::time::SystemTime::now());

        rankings.begin_connections();
        rankings.record_connection(&youtube, &contexto(Some(1), None));
        rankings.record_connection(&youtube, &contexto(Some(2), None));
        rankings.record_connection(&dns, &contexto(Some(1), None));
        // Una conexión sin fila todavía no inventa claves nuevas.
        let desconocida = etiqueta(
            Some("desconocida"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("9.9.9.9"),
        );
        rankings.record_connection(&desconocida, &contexto(Some(1), None));

        let apps = rankings.top(Dimension::App, Window::Sixty, SortKey::Total, 10);
        assert_eq!(apps.len(), 2, "record_connection no crea filas");
        let youtube_fila = apps
            .iter()
            .find(|fila| fila.key == "youtube")
            .expect("youtube");
        assert_eq!(youtube_fila.connections, 2);
        let dns_fila = apps.iter().find(|fila| fila.key == "dns").expect("dns");
        assert_eq!(dns_fila.connections, 1);

        rankings.begin_connections();
        let apps_vacias = rankings.top(Dimension::App, Window::Sixty, SortKey::Total, 10);
        assert!(apps_vacias.iter().all(|fila| fila.connections == 0));
    }

    #[test]
    fn nombres_visibles_del_catalogo() {
        let mut rankings = Rankings::new();
        rankings.set_app_names(HashMap::from([(
            "youtube".to_string(),
            "YouTube".to_string(),
        )]));
        rankings.set_category_names(HashMap::from([
            ("streaming".to_string(), "Vídeo".to_string()),
            ("web".to_string(), "Web".to_string()),
        ]));
        rankings.set_app_categories(HashMap::from([(
            "youtube".to_string(),
            "Vídeo".to_string(),
        )]));
        let t0 = Instant::now();
        let youtube = etiqueta(
            Some("youtube"),
            Some("streaming"),
            Some(AppProtocol::Tls),
            destino_ip("1.1.1.1"),
        );
        let sin_catalogo = etiqueta(
            Some("rara"),
            Some("web"),
            Some(AppProtocol::Tls),
            destino_ip("2.2.2.2"),
        );
        rankings.record(&youtube, &contexto(Some(1), None), 200, Dir::Down, t0);
        rankings.record(&sin_catalogo, &contexto(Some(1), None), 100, Dir::Down, t0);
        let _ = rankings.tick(t0, std::time::SystemTime::now());

        let apps = rankings.top(Dimension::App, Window::Sixty, SortKey::Total, 10);
        let youtube_fila = apps
            .iter()
            .find(|fila| fila.key == "youtube")
            .expect("youtube");
        assert_eq!(youtube_fila.label, "YouTube");
        assert_eq!(youtube_fila.subtitle.as_deref(), Some("Vídeo"));
        let rara = apps.iter().find(|fila| fila.key == "rara").expect("rara");
        assert_eq!(rara.label, "rara", "sin nombre se muestra la clave");
        assert_eq!(
            rara.subtitle.as_deref(),
            Some("Web"),
            "el subtítulo sale de la categoría si no hay app_categories"
        );

        let categorias = rankings.top(Dimension::Category, Window::Sixty, SortKey::Total, 10);
        let streaming = categorias
            .iter()
            .find(|fila| fila.key == "streaming")
            .expect("streaming");
        assert_eq!(streaming.label, "Vídeo");
        let web = categorias
            .iter()
            .find(|fila| fila.key == "web")
            .expect("web");
        assert_eq!(web.label, "Web");
    }

    #[test]
    fn protocolo_de_respaldo_por_transporte() {
        let mut rankings = Rankings::new();
        let t0 = Instant::now();
        let flujo = etiqueta(Some("x"), None, None, destino_ip("1.1.1.1"));
        let tcp = FlowCtx {
            l4: Some(L4::Tcp),
            ..FlowCtx::default()
        };
        rankings.record(&flujo, &tcp, 10, Dir::Down, t0);
        let udp = FlowCtx {
            l4: Some(L4::Udp),
            ..FlowCtx::default()
        };
        rankings.record(&flujo, &udp, 20, Dir::Down, t0);
        let sin_l4 = FlowCtx::default();
        rankings.record(&flujo, &sin_l4, 30, Dir::Down, t0);
        let _ = rankings.tick(t0, std::time::SystemTime::now());

        let filas = rankings.top(Dimension::Protocol, Window::Sixty, SortKey::Total, 10);
        assert_eq!(claves_de(&filas), vec!["udp", "tcp"]);
        assert_eq!(filas[0].label, "UDP");
        assert_eq!(filas[0].total(), 20);
        assert_eq!(filas[1].label, "TCP");
        assert_eq!(filas[1].total(), 10);
    }

    #[test]
    fn top_para_el_detalle_de_equipo_filtra_por_equipo() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        rankings.set_app_names(HashMap::from([(
            "youtube".to_string(),
            "YouTube".to_string(),
        )]));
        rankings.set_app_categories(HashMap::from([(
            "youtube".to_string(),
            "Vídeo".to_string(),
        )]));
        let t0 = Instant::now();
        let youtube = etiqueta(
            Some("youtube"),
            Some("streaming"),
            Some(AppProtocol::Tls),
            destino_ip("1.1.1.1"),
        );
        let dns = etiqueta(
            Some("dns"),
            Some("infra"),
            Some(AppProtocol::Dns),
            destino_ip("8.8.8.8"),
        );
        rankings.record(&youtube, &contexto(Some(1), None), 300, Dir::Down, t0);
        rankings.record(&youtube, &contexto(Some(1), None), 100, Dir::Up, t0);
        rankings.record(&dns, &contexto(Some(1), None), 50, Dir::Down, t0);
        rankings.record(&youtube, &contexto(Some(2), None), 1_000, Dir::Down, t0);
        let _ = rankings.tick(t0 + Duration::from_secs(1), std::time::SystemTime::now());

        let apps = rankings.top_for_device(Dimension::App, 1, Window::FiveMin, 10);
        assert_eq!(claves_de(&apps), vec!["youtube", "dns"]);
        assert_eq!(apps[0].label, "YouTube");
        assert_eq!(apps[0].subtitle.as_deref(), Some("Vídeo"));
        assert_eq!(apps[0].bytes_down, 300);
        assert_eq!(apps[0].bytes_up, 100);
        assert_eq!(apps[0].total(), 400);
        assert_eq!(apps[0].devices, 1);
        assert_eq!(apps[0].device_id, Some(1));
        assert_eq!(apps[0].series_60s.iter().sum::<u64>(), 400);
        assert_eq!(apps[1].key, "dns");
        assert_eq!(apps[1].total(), 50);

        let apps_dos = rankings.top_for_device(Dimension::App, 2, Window::FiveMin, 10);
        assert_eq!(apps_dos.len(), 1);
        assert_eq!(apps_dos[0].total(), 1_000, "solo los bytes del equipo 2");

        assert_eq!(
            rankings
                .top_for_device(Dimension::App, 1, Window::FiveMin, 1)
                .len(),
            1
        );
        assert!(rankings
            .top_for_device(Dimension::App, 99, Window::FiveMin, 10)
            .is_empty());

        let destinos = rankings.top_for_device(Dimension::Destination, 1, Window::FiveMin, 10);
        assert_eq!(claves_de(&destinos), vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(destinos[0].total(), 400);
        assert_eq!(destinos[1].total(), 50);
    }

    #[test]
    fn etiquetas_incompletas_no_crean_filas_vacias() {
        let mut rankings = Rankings::new();
        let t0 = Instant::now();
        let vacia = FlowLabel::empty(ip("10.0.0.1"));
        rankings.record(&vacia, &FlowCtx::default(), 10, Dir::Down, t0);
        let _ = rankings.tick(t0, std::time::SystemTime::now());

        let destinos = rankings.top(Dimension::Destination, Window::Sixty, SortKey::Total, 10);
        assert_eq!(destinos.len(), 1);
        assert_eq!(destinos[0].key, "10.0.0.1");
        for dim in [
            Dimension::Device,
            Dimension::App,
            Dimension::Category,
            Dimension::Protocol,
            Dimension::Process,
        ] {
            assert!(
                rankings
                    .top(dim, Window::Sixty, SortKey::Total, 10)
                    .is_empty(),
                "{dim:?}"
            );
        }
        assert!((rankings.unidentified_share(Window::Sixty) - 100.0).abs() < 0.01);
    }

    #[test]
    fn desaloja_las_claves_inactivas_al_superar_el_tope() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let ctx = contexto(Some(1), None);
        for indice in 0..MAX_CLAVES_POR_DIMENSION {
            let flujo = etiqueta(
                None,
                None,
                Some(AppProtocol::Tls),
                destino_dominio(&format!("d{indice}.example"), None, None),
            );
            rankings.record(
                &flujo,
                &ctx,
                10,
                Dir::Down,
                t0 + Duration::from_millis(indice as u64),
            );
        }
        assert_eq!(
            rankings
                .top(
                    Dimension::Destination,
                    Window::Session,
                    SortKey::Total,
                    MAX_CLAVES_POR_DIMENSION + 10,
                )
                .len(),
            MAX_CLAVES_POR_DIMENSION,
            "se han llenado exactamente las 2048 claves"
        );

        // Cinco minutos después todas las claves llevan tiempo inactivas: al
        // entrar una nueva se desaloja la más antigua sin bytes en 5 min.
        let despues = t0 + Duration::from_secs(301);
        let _ = rankings.tick(despues, std::time::SystemTime::now());
        let flujo = etiqueta(
            None,
            None,
            Some(AppProtocol::Tls),
            destino_dominio("nuevo.example", None, None),
        );
        rankings.record(&flujo, &ctx, 10, Dir::Down, despues);

        let filas = rankings.top(
            Dimension::Destination,
            Window::Session,
            SortKey::Total,
            MAX_CLAVES_POR_DIMENSION + 10,
        );
        assert_eq!(filas.len(), MAX_CLAVES_POR_DIMENSION);
        let claves = claves_de(&filas);
        assert!(
            !claves.contains(&"d0.example"),
            "se desaloja la más antigua"
        );
        assert!(claves.contains(&"d1.example"));
        assert!(claves.contains(&"nuevo.example"));

        let sesenta = rankings.top(Dimension::Destination, Window::Sixty, SortKey::Total, 10);
        assert_eq!(claves_de(&sesenta), vec!["nuevo.example"]);
    }

    #[test]
    fn el_tope_protege_la_memoria_aunque_todas_las_claves_esten_activas() {
        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let t0 = Instant::now();
        let ctx = contexto(Some(1), None);
        let total = MAX_CLAVES_POR_DIMENSION + 16;
        for indice in 0..total {
            let flujo = etiqueta(
                None,
                None,
                Some(AppProtocol::Tls),
                destino_dominio(&format!("d{indice}.example"), None, None),
            );
            rankings.record(
                &flujo,
                &ctx,
                10,
                Dir::Down,
                t0 + Duration::from_millis(indice as u64),
            );
        }
        let filas = rankings.top(
            Dimension::Destination,
            Window::Session,
            SortKey::Total,
            total + 10,
        );
        assert_eq!(filas.len(), MAX_CLAVES_POR_DIMENSION, "el tope se mantiene");
        let claves = claves_de(&filas);
        assert!(!claves.contains(&"d0.example"));
        assert!(claves.contains(&format!("d{}.example", total - 1).as_str()));
    }

    #[test]
    fn entradas_aleatorias_y_limites_no_producen_panicos() {
        struct Azar(u64);
        impl Azar {
            fn siguiente(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                self.0 >> 11
            }
        }

        let mut rankings = Rankings::new();
        rankings.set_devices(mapa_equipos());
        let base = Instant::now();
        let mut azar = Azar(0x5eed_1234);

        for paso in 0..2600u64 {
            let app = match azar.siguiente() % 6 {
                0 => None,
                1 => Some(String::new()),
                2 => Some("youtube".to_string()),
                resto => Some(format!("app{resto}")),
            };
            let categoria = match azar.siguiente() % 4 {
                0 => None,
                1 => Some("streaming".to_string()),
                2 => Some("web".to_string()),
                _ => Some(String::new()),
            };
            let protocolo = match azar.siguiente() % 5 {
                0 => None,
                1 => Some(AppProtocol::Tls),
                2 => Some(AppProtocol::Dns),
                3 => Some(AppProtocol::Quic),
                _ => Some(AppProtocol::Other),
            };
            let destino = match azar.siguiente() % 4 {
                0 => DestinationInfo::unknown(IpAddr::V4(Ipv4Addr::from(azar.siguiente() as u32))),
                1 => destino_dominio(
                    &format!("sitio{}.example", azar.siguiente() % 4_000),
                    None,
                    None,
                ),
                2 => destino_lan((azar.siguiente() % 8) as i64, "equipo lan"),
                _ => DestinationInfo {
                    key: String::new(),
                    label: String::new(),
                    org: None,
                    country: None,
                    kind: DestinationKind::Ip,
                },
            };
            let device_id = match azar.siguiente() % 5 {
                0 => None,
                1 => Some(DEVICE_ID_HOST),
                2 => Some(1),
                3 => Some(2),
                _ => Some(7),
            };
            let process = match azar.siguiente() % 4 {
                0 => None,
                _ => Some(((azar.siguiente() % 400 + 1) as u32, "proceso")),
            };
            let l4 = match azar.siguiente() % 3 {
                0 => None,
                1 => Some(L4::Tcp),
                _ => Some(L4::Udp),
            };
            let bytes = match azar.siguiente() % 8 {
                0 => 0,
                1 => u64::MAX,
                2 => u64::MAX - 1,
                _ => azar.siguiente() % 1_000_000,
            };
            let dir = if azar.siguiente() & 1 == 0 {
                Dir::Down
            } else {
                Dir::Up
            };
            let flujo = etiqueta(app.as_deref(), categoria.as_deref(), protocolo, destino);
            let ctx = FlowCtx {
                device_id,
                process: process.map(|(pid, nombre)| (pid, nombre.to_string())),
                l4,
                protocol: None,
                es_cliente: false,
            };
            rankings.record(&flujo, &ctx, bytes, dir, base + Duration::from_millis(paso));
            if paso % 97 == 0 {
                rankings.begin_connections();
            }
            rankings.record_connection(&flujo, &ctx);
            if paso % 61 == 0 {
                let salto = azar.siguiente() % 400;
                let _ = rankings.tick(
                    base + Duration::from_millis(paso) + Duration::from_secs(salto),
                    std::time::SystemTime::now(),
                );
            }
        }
        let _ = rankings.tick(
            base + Duration::from_secs(500),
            std::time::SystemTime::now(),
        );

        for window in Window::ALL {
            let pct = rankings.unidentified_share(window);
            assert!(pct.is_finite(), "{window:?}");
            assert!((0.0..=100.0).contains(&pct), "{window:?}: {pct}");
        }

        for dim in Dimension::ALL {
            for window in Window::ALL {
                for sort in [SortKey::Total, SortKey::Down, SortKey::Up, SortKey::Devices] {
                    let filas = rankings.top(dim, window, sort, 50);
                    assert!(filas.len() <= 50);
                    let mut anterior: Option<u64> = None;
                    for fila in &filas {
                        let metrica = match sort {
                            SortKey::Total => fila.total(),
                            SortKey::Down => fila.bytes_down,
                            SortKey::Up => fila.bytes_up,
                            SortKey::Devices => u64::from(fila.devices),
                        };
                        if let Some(previo) = anterior {
                            assert!(metrica <= previo, "{dim:?} {window:?} {sort:?} orden roto");
                        }
                        anterior = Some(metrica);
                        assert!(fila.total() > 0, "solo filas con bytes en la ventana");
                    }
                }
                assert!(
                    rankings.top(dim, window, SortKey::Total, 0).is_empty(),
                    "{dim:?} {window:?}"
                );
            }
        }

        for clave in ["youtube", "app2", "app3"] {
            for cuota in rankings.who_uses(Dimension::App, clave, Window::Session) {
                assert!(cuota.pct.is_finite());
                assert!((0.0..=100.0).contains(&cuota.pct), "{}", cuota.pct);
            }
        }
        for dim in [Dimension::App, Dimension::Destination, Dimension::Protocol] {
            for fila in rankings.top(dim, Window::Session, SortKey::Total, 5) {
                for cuota in rankings.who_uses(dim, &fila.key, Window::Session) {
                    assert!(cuota.pct.is_finite());
                    assert!((0.0..=100.0).contains(&cuota.pct), "{}", cuota.pct);
                }
            }
        }
        let detalle = rankings.top_for_device(Dimension::App, 1, Window::FiveMin, 5);
        assert!(detalle.len() <= 5);
        let detalle =
            rankings.top_for_device(Dimension::Destination, DEVICE_ID_HOST, Window::Session, 5);
        assert!(detalle.len() <= 5);
    }

    #[test]
    fn desbordamiento_de_bytes_satura_sin_panicos() {
        let mut rankings = Rankings::new();
        let t0 = Instant::now();
        let flujo = etiqueta(
            Some("youtube"),
            None,
            Some(AppProtocol::Tls),
            destino_ip("1.1.1.1"),
        );
        let ctx = contexto(Some(1), None);
        rankings.record(&flujo, &ctx, u64::MAX, Dir::Down, t0);
        rankings.record(&flujo, &ctx, u64::MAX, Dir::Up, t0);
        rankings.record(&flujo, &ctx, u64::MAX, Dir::Down, t0);
        let _ = rankings.tick(t0, std::time::SystemTime::now());

        let filas = rankings.top(Dimension::App, Window::Session, SortKey::Total, 10);
        assert_eq!(filas.len(), 1);
        assert_eq!(filas[0].bytes_down, u64::MAX);
        assert_eq!(filas[0].bytes_up, u64::MAX);
        assert_eq!(filas[0].total(), u64::MAX);
        let serie: u64 = filas[0]
            .series_60s
            .iter()
            .fold(0u64, |acumulado, valor| acumulado.saturating_add(*valor));
        assert_eq!(serie, u64::MAX);
        assert!((rankings.unidentified_share(Window::Session) - 0.0).abs() < 0.01);
    }
}
