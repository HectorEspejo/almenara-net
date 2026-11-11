//! Histórico de Almenara (Fase 5): rollups, sesiones, presencia, inventario y
//! consultas del lector de solo lectura.
//!
//! Este módulo raíz reúne los tipos comunes que comparten el agregador
//! ([rollup]), la consolidación ([build]), la retención, los eventos nuevos
//! ([changes]), el hilo lector ([reader]) y sus consultas ([queries]).
//!
//! Reglas transversales (ADR-56):
//!
//! - Los cubos de TRAFFIC_ROLLUP_* son enteros: segundos Unix UTC para los
//!   minutos y las horas, y fecha local AAAAMMDD para los días.
//! - Las horas pertenecen al día local que contiene su inicio; nunca se mezclan
//!   horas UTC con días locales.
//! - Solo se guardan agregados: sin contenido, sin nombres completos y sin
//!   registro de conexiones.

// Varias operaciones de esta API son parte del checklist de F5 y solo las usan
// las pruebas o la integración de la TUI; se permite dead_code como en los DAO
// de fases anteriores.
#![allow(dead_code)]

pub mod build;
pub mod changes;
pub mod localtime;
pub mod queries;
pub mod reader;
pub mod retention;
pub mod rollup;
pub mod synthetic;

pub use localtime::LocalDay;

use crate::alerts::{AlertCounts, AlertRule, LearningState, Level, RuleId};
use crate::rankings::Dir;

/// Sujeto de un cubo del histórico (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subject {
    /// Un equipo de la LAN, con su identificador de DEVICES.
    Device(i64),
    /// El propio equipo (la fila [host] de F3).
    Host,
    /// Tráfico sin equipo local atribuible ([?], [broadcast]).
    Other,
    /// La red entera; solo existe en la dimensión total.
    Network,
}

impl Subject {
    /// Valor persistido en TRAFFIC_ROLLUP_*.subject.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device(_) => "device",
            Self::Host => "host",
            Self::Other => "other",
            Self::Network => "network",
        }
    }

    /// Identificador de DEVICES que acompaña al sujeto (0 si no es un equipo).
    pub fn device_id(self) -> i64 {
        match self {
            Self::Device(id) => id,
            _ => 0,
        }
    }

    /// Reconstruye un sujeto desde sus dos columnas persistidas.
    pub fn from_parts(subject: &str, device_id: i64) -> Option<Self> {
        Some(match subject {
            "device" => Self::Device(device_id),
            "host" => Self::Host,
            "other" => Self::Other,
            "network" => Self::Network,
            _ => return None,
        })
    }

    /// Indica si el sujeto es el propio equipo.
    pub fn is_host(self) -> bool {
        matches!(self, Self::Host)
    }
}

/// Dimensiones del histórico (§7.1). La dimensión device de los rankings no
/// existe aquí: el sujeto ya identifica al equipo.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dimension {
    /// Total del sujeto (clave vacía).
    #[default]
    Total,
    /// App del catálogo.
    App,
    /// Categoría del catálogo.
    Category,
    /// Destino: dominio registrable, IP remota o lan:<device_id>.
    Destination,
    /// Protocolo de aplicación o de transporte.
    Protocol,
    /// Proceso local (solo para el sujeto host).
    Process,
    /// Organización de DB-IP.
    Org,
    /// País ISO 3166-1 alfa-2 de DB-IP.
    Country,
}

impl Dimension {
    /// Las ocho dimensiones, en el orden del informe.
    pub const ALL: [Self; 8] = [
        Self::Total,
        Self::App,
        Self::Category,
        Self::Destination,
        Self::Protocol,
        Self::Process,
        Self::Org,
        Self::Country,
    ];

    /// Las dimensiones que alimentan el inventario por equipo (§7.9).
    pub const INVENTORY: [Self; 4] = [Self::App, Self::Category, Self::Org, Self::Country];

    /// Valor persistido en TRAFFIC_ROLLUP_*.dimension.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Total => "total",
            Self::App => "app",
            Self::Category => "category",
            Self::Destination => "destination",
            Self::Protocol => "protocol",
            Self::Process => "process",
            Self::Org => "org",
            Self::Country => "country",
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Total => "total",
            Self::App => "apps",
            Self::Category => "categorías",
            Self::Destination => "destinos",
            Self::Protocol => "protocolos",
            Self::Process => "procesos",
            Self::Org => "organizaciones",
            Self::Country => "países",
        }
    }

    /// Reconstruye la dimensión desde su valor persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|dim| dim.as_str() == valor)
    }

    /// Índice de la dimensión.
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|dim| *dim == self).unwrap_or(0)
    }

    /// Indica si la dimensión alimenta el inventario.
    pub fn is_inventory(self) -> bool {
        Self::INVENTORY.contains(&self)
    }
}

/// Clave especial de la dimensión app/categoría cuando el flujo no se identificó.
pub const KEY_UNIDENTIFIED: &str = "~sin_identificar";
/// Clave especial de organización y país para destinos de la LAN.
pub const KEY_LAN: &str = "~lan";
/// Clave especial de proceso/organización/país cuando no hay dato.
pub const KEY_UNKNOWN: &str = "~desconocido";
/// Clave que acumula lo que pasa del tope top_keys.
pub const KEY_OTHERS: &str = "~otros";

/// Indica si una clave es especial (empieza por ~).
pub fn clave_especial(clave: &str) -> bool {
    clave.starts_with('~')
}

/// Dimensiones válidas en cada sujeto: network solo lleva total; process solo
/// existe para el propio equipo.
pub fn dimension_valida(subject: Subject, dimension: Dimension) -> bool {
    match subject {
        // La red entera solo tiene el total (ADR-55).
        Subject::Network => dimension == Dimension::Total,
        // El proceso solo existe para el tráfico del propio equipo.
        Subject::Device(_) | Subject::Other => dimension != Dimension::Process,
        Subject::Host => true,
    }
}

/// Dimensiones que alimentan el inventario, con su clave persistida en
/// DEVICE_SEEN.kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SeenKind {
    /// App del catálogo.
    App,
    /// Categoría del catálogo.
    Category,
    /// Organización de DB-IP.
    Org,
    /// País de DB-IP.
    Country,
    /// Huella JA4 del cliente TLS/QUIC.
    Ja4,
}

impl SeenKind {
    /// Valor persistido en DEVICE_SEEN.kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Category => "category",
            Self::Org => "org",
            Self::Country => "country",
            Self::Ja4 => "ja4",
        }
    }

    /// Reconstruye el tipo desde su valor persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        Some(match valor {
            "app" => Self::App,
            "category" => Self::Category,
            "org" => Self::Org,
            "country" => Self::Country,
            "ja4" => Self::Ja4,
            _ => return None,
        })
    }

    /// Tipo de inventario de una dimensión (None si no alimenta el inventario).
    pub fn from_dimension(dimension: Dimension) -> Option<Self> {
        Some(match dimension {
            Dimension::App => Self::App,
            Dimension::Category => Self::Category,
            Dimension::Org => Self::Org,
            Dimension::Country => Self::Country,
            _ => return None,
        })
    }
}

/// Entrada del inventario que viaja en el lote del minuto (§7.11).
///
/// El sujeto es el equipo al que se atribuye la clave (`Device(id)`) o el propio
/// equipo (`Host`); `Other` y `Network` nunca entran en el inventario. Las claves
/// especiales (`~…`) y los destinos tampoco.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenItem {
    /// Sujeto al que se le ha visto la clave (equipo o propio equipo).
    pub subject: Subject,
    /// Tipo de clave.
    pub kind: SeenKind,
    /// Clave vista (app, categoría, organización, país o JA4).
    pub key: String,
}

impl SeenItem {
    /// Entrada del inventario de un equipo de DEVICES.
    pub fn de_equipo(device_id: i64, kind: SeenKind, key: impl Into<String>) -> Self {
        Self {
            subject: Subject::Device(device_id),
            kind,
            key: key.into(),
        }
    }

    /// Entrada del inventario del propio equipo (HOST_SEEN).
    pub fn del_host(kind: SeenKind, key: impl Into<String>) -> Self {
        Self {
            subject: Subject::Host,
            kind,
            key: key.into(),
        }
    }

    /// Identificador del equipo, si la entrada es de un equipo de DEVICES.
    pub fn device_id(&self) -> Option<i64> {
        match self.subject {
            Subject::Device(id) => Some(id),
            _ => None,
        }
    }

    /// Indica si la entrada es del propio equipo.
    pub fn es_host(&self) -> bool {
        self.subject.is_host()
    }
}

/// Dimensiones resueltas de un flujo para el agregador del histórico.
///
/// subject es la columna «Equipo» de F4: el sujeto al que se atribuyen las
/// dimensiones distintas de total (equipo de la LAN o host; None = otros).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowDims {
    /// Sujeto atribuido del flujo (la columna «Equipo» de F4).
    pub subject: Option<Subject>,
    /// Clave de app del catálogo; None = sin identificar.
    pub app: Option<String>,
    /// Clave de categoría del catálogo; None = sin identificar.
    pub category: Option<String>,
    /// Destino resuelto (dominio registrable, IP o lan:<device_id>).
    pub destination: Option<String>,
    /// Protocolo de app o de transporte (tcp, udp, icmp, other).
    pub protocol: Option<String>,
    /// Nombre del proceso local (solo tráfico del propio equipo).
    pub process: Option<String>,
    /// Organización de DB-IP.
    pub org: Option<String>,
    /// País de DB-IP.
    pub country: Option<String>,
    /// El destino es un equipo de la LAN (~lan en organización y país).
    pub destination_lan: bool,
    /// Sujeto del otro extremo de un flujo LAN↔LAN.
    ///
    /// Sus bytes entran en espejo en la dimensión total: lo que el cliente
    /// recibe es la subida del otro equipo y viceversa.
    pub peer: Option<Subject>,
    /// Huella JA4 del cliente del flujo, si se conoce.
    pub ja4: Option<String>,
}

impl FlowDims {
    /// Clave de una dimensión con su valor especial cuando falta el dato.
    ///
    /// Devuelve una vista prestada para no asignar memoria en el camino caliente
    /// del agregador (se llama por flujo y segundo; §8).
    pub fn clave(&self, dimension: Dimension) -> Option<std::borrow::Cow<'_, str>> {
        use std::borrow::Cow;
        fn opcional<'a>(valor: &'a Option<String>, especial: &'static str) -> Cow<'a, str> {
            match valor {
                Some(texto) if !texto.is_empty() => Cow::Borrowed(texto.as_str()),
                _ => Cow::Borrowed(especial),
            }
        }
        Some(match dimension {
            Dimension::Total => Cow::Borrowed(""),
            Dimension::App => opcional(&self.app, KEY_UNIDENTIFIED),
            Dimension::Category => opcional(&self.category, KEY_UNIDENTIFIED),
            Dimension::Destination => match &self.destination {
                Some(destino) if !destino.is_empty() => Cow::Borrowed(destino.as_str()),
                _ => return None,
            },
            Dimension::Protocol => match &self.protocol {
                Some(protocolo) if !protocolo.is_empty() => Cow::Borrowed(protocolo.as_str()),
                _ => Cow::Borrowed("other"),
            },
            Dimension::Process => {
                if self.subject.is_some_and(Subject::is_host) {
                    opcional(&self.process, KEY_UNKNOWN)
                } else {
                    return None;
                }
            }
            Dimension::Org => {
                if self.destination_lan {
                    Cow::Borrowed(KEY_LAN)
                } else {
                    opcional(&self.org, KEY_UNKNOWN)
                }
            }
            Dimension::Country => {
                if self.destination_lan {
                    Cow::Borrowed(KEY_LAN)
                } else {
                    opcional(&self.country, KEY_UNKNOWN)
                }
            }
        })
    }
}

/// Contadores de una clave del acumulador del minuto.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counter {
    /// Bytes de bajada.
    pub down: u64,
    /// Bytes de subida.
    pub up: u64,
    /// Flujos nuevos contados en el cubo.
    pub connections: u64,
}

impl Counter {
    /// Total de bytes.
    pub fn total(&self) -> u64 {
        self.down.saturating_add(self.up)
    }

    /// Suma otro contador.
    pub fn suma(&mut self, otro: Counter) {
        self.down = self.down.saturating_add(otro.down);
        self.up = self.up.saturating_add(otro.up);
        self.connections = self.connections.saturating_add(otro.connections);
    }

    /// Suma bytes en una dirección.
    pub fn suma_bytes(&mut self, bytes: u64, dir: Dir) {
        match dir {
            Dir::Down => self.down = self.down.saturating_add(bytes),
            Dir::Up => self.up = self.up.saturating_add(bytes),
        }
    }
}

/// Fila de un rollup (una clave de un cubo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollupRow {
    /// Sujeto del cubo.
    pub subject: Subject,
    /// Dimensión.
    pub dimension: Dimension,
    /// Clave (vacía en total).
    pub key: String,
    /// Contadores.
    pub counter: Counter,
}

/// Lote del minuto cerrado por el agregador, listo para escribir.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollupBatch {
    /// Inicio del minuto en segundos Unix UTC.
    pub minute: i64,
    /// Filas ya con los topes aplicados y las claves especiales.
    pub rows: Vec<RollupRow>,
    /// Inventario visto antes de los topes.
    pub seen: Vec<SeenItem>,
    /// Entradas que no cabían en los acumuladores (contador de diagnóstico).
    pub overflow: u64,
}

impl RollupBatch {
    /// Indica si el lote no tiene nada que escribir.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.seen.is_empty()
    }
}

/// Retención por resolución (§7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Retención de minutos en días (por defecto 2 = 48 h).
    pub minute_days: u32,
    /// Retención de horas en días (90).
    pub hour_days: u32,
    /// Retención de días, inventario y sesiones en días (730).
    pub day_days: u32,
    /// Retención de destinos por hora en días (30; 0 = no guardarlos).
    pub destination_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            minute_days: 2,
            hour_days: 90,
            day_days: 730,
            destination_days: 30,
        }
    }
}

/// Resultado de una purga del histórico.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeStats {
    /// Filas borradas de las tres resoluciones.
    pub rollup_rows: u64,
    /// Entradas de inventario borradas.
    pub seen_rows: u64,
    /// Sesiones borradas.
    pub session_rows: u64,
    /// Filas de eventos borradas.
    pub event_rows: u64,
    /// Páginas liberadas por incremental_vacuum.
    pub vacuum_pages: u64,
    /// Instante de la purga en segundos Unix UTC.
    pub at: i64,
}

impl PurgeStats {
    /// Total de filas borradas.
    pub fn total_filas(&self) -> u64 {
        self.rollup_rows
            .saturating_add(self.seen_rows)
            .saturating_add(self.session_rows)
            .saturating_add(self.event_rows)
    }
}

/// Información de una sesión de Almenara al abrirla (§7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Modo de ejecución: privileged o degraded.
    pub mode: String,
    /// Había captura al arrancar.
    pub capture: bool,
    /// Modo pasivo de escaneo.
    pub passive_only: bool,
    /// Versión de Almenara.
    pub version: String,
}

/// Selección de sujeto de la pestaña Histórico y del detalle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectSel {
    /// Toda la red.
    Network,
    /// El propio equipo (host).
    Host,
    /// Un equipo concreto.
    Device(i64),
}

impl SubjectSel {
    /// Etiqueta corta del sujeto.
    pub fn label(self) -> String {
        match self {
            Self::Network => "Toda la red".to_string(),
            Self::Host => "Este equipo".to_string(),
            Self::Device(id) => format!("Equipo #{id}"),
        }
    }
}

/// Rangos de la pestaña Histórico (§7.11).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Range {
    /// Últimas 24 h, puntos de 30 min.
    #[default]
    Hours24,
    /// Últimos 7 días, puntos de 3 h.
    Days7,
    /// Últimos 30 días, puntos de 1 día.
    Days30,
    /// Último año, puntos de una semana.
    Year1,
}

impl Range {
    /// Los cuatro rangos, en el orden de w.
    pub const ALL: [Self; 4] = [Self::Hours24, Self::Days7, Self::Days30, Self::Year1];

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Hours24 => "24 h",
            Self::Days7 => "7 días",
            Self::Days30 => "30 días",
            Self::Year1 => "1 año",
        }
    }

    /// Ciclo de w.
    pub fn next(self) -> Self {
        match self {
            Self::Hours24 => Self::Days7,
            Self::Days7 => Self::Days30,
            Self::Days30 => Self::Year1,
            Self::Year1 => Self::Hours24,
        }
    }

    /// Índice del rango.
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|r| *r == self).unwrap_or(0)
    }

    /// Duración del rango en segundos.
    pub fn dur_s(self) -> i64 {
        match self {
            Self::Hours24 => 24 * 3600,
            Self::Days7 => 7 * 86_400,
            Self::Days30 => 30 * 86_400,
            Self::Year1 => 366 * 86_400,
        }
    }

    /// Resolución de cada punto en segundos.
    pub fn resolution_s(self) -> i64 {
        match self {
            Self::Hours24 => 30 * 60,
            Self::Days7 => 3 * 3600,
            Self::Days30 => 86_400,
            Self::Year1 => 7 * 86_400,
        }
    }

    /// Número de puntos del rango.
    pub fn points(self) -> usize {
        match self {
            Self::Hours24 => 48,
            Self::Days7 => 56,
            Self::Days30 => 30,
            Self::Year1 => 53,
        }
    }

    /// Indica si el rango admite destinos (hasta 30 días).
    pub fn admite_destinos(self) -> bool {
        self != Self::Year1
    }

    /// Fuente de datos del rango.
    pub fn source(self) -> RangeSource {
        match self {
            Self::Hours24 => RangeSource::Minutes,
            Self::Days7 => RangeSource::HoursAndCurrentMinutes,
            Self::Days30 => RangeSource::DaysAndCurrentHours,
            Self::Year1 => RangeSource::Days,
        }
    }
}

/// Tabla de la que salen los puntos de un rango (§7.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeSource {
    /// Minutos.
    Minutes,
    /// Horas más los minutos de la hora en curso.
    HoursAndCurrentMinutes,
    /// Días más las horas del día en curso.
    DaysAndCurrentHours,
    /// Días.
    Days,
}

/// Ventanas de 1 h y 24 h de la pestaña Tráfico (desde el histórico).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum HistWindow {
    /// Última hora (minutos cerrados).
    #[default]
    OneHour,
    /// Últimas 24 h (horas + minutos de la hora en curso).
    Day24,
}

impl HistWindow {
    /// Las dos ventanas.
    pub const ALL: [Self; 2] = [Self::OneHour, Self::Day24];

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::OneHour => "1 h",
            Self::Day24 => "24 h",
        }
    }
}

/// Punto de la serie de tráfico de la gráfica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesPoint {
    /// Inicio del punto en segundos Unix UTC.
    pub at: i64,
    /// Bytes de bajada del punto.
    pub bytes_down: u64,
    /// Bytes de subida del punto.
    pub bytes_up: u64,
    /// El punto no tiene cobertura de tráfico (hueco): nunca se interpola.
    pub gap: bool,
    /// El punto cae en el futuro (se dibuja en blanco).
    pub future: bool,
}

impl SeriesPoint {
    /// Total de bytes del punto.
    pub fn total(&self) -> u64 {
        self.bytes_down.saturating_add(self.bytes_up)
    }
}

/// Serie de tráfico de un rango con sus huecos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Series {
    /// Rango consultado.
    pub range: Range,
    /// Puntos en orden cronológico.
    pub points: Vec<SeriesPoint>,
    /// Bajada total del rango.
    pub total_down: u64,
    /// Subida total del rango.
    pub total_up: u64,
    /// Índice y total del punto máximo (si hay algún byte).
    pub max: Option<(usize, u64)>,
}

impl Series {
    /// Total de bytes del rango.
    pub fn total(&self) -> u64 {
        self.total_down.saturating_add(self.total_up)
    }

    /// Índice del primer punto futuro (o el número de puntos si no hay).
    pub fn first_future(&self) -> usize {
        self.points
            .iter()
            .position(|punto| punto.future)
            .unwrap_or(self.points.len())
    }
}

/// Fila de «Más tráfico» del rango.
#[derive(Debug, Clone, PartialEq)]
pub struct TopRow {
    /// Clave de la fila (id de equipo, app, destino…).
    pub key: String,
    /// Texto visible.
    pub label: String,
    /// Subtítulo (organización · país, categoría…).
    pub subtitle: Option<String>,
    /// Equipo asociado cuando la fila es un equipo.
    pub device_id: Option<i64>,
    /// Bytes de bajada.
    pub bytes_down: u64,
    /// Bytes de subida.
    pub bytes_up: u64,
    /// Porcentaje sobre el total del rango.
    pub pct: f32,
    /// Equipos distintos que usan la clave.
    pub devices: u32,
}

impl TopRow {
    /// Total de bytes de la fila.
    pub fn total(&self) -> u64 {
        self.bytes_down.saturating_add(self.bytes_up)
    }
}

/// Tipo de elemento de la línea de tiempo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineKind {
    /// Evento de dispositivo.
    Event,
    /// Sesión de Almenara.
    Session,
}

/// Elemento de la línea de tiempo (evento o sesión).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineItem {
    /// Instante en RFC 3339 UTC.
    pub at: String,
    /// Instante en segundos Unix UTC.
    pub at_unix: i64,
    /// Tipo del elemento.
    pub kind: TimelineKind,
    /// Equipo asociado, si es un evento de dispositivo.
    pub device_id: Option<i64>,
    /// Nombre visible del equipo al pintar.
    pub device_label: Option<String>,
    /// Tipo de evento persistido (new, service_gone…) o session.
    pub event_type: String,
    /// Texto ya compuesto en castellano.
    pub summary: String,
    /// Motivo de cierre, en las sesiones.
    pub session_reason: Option<String>,
}

/// Estado de un tramo de presencia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceState {
    /// El equipo estaba conectado.
    Present,
    /// El equipo estaba desconectado.
    Absent,
    /// Almenara estaba cerrada: no hay datos.
    NoData,
}

impl PresenceState {
    /// Carácter de la rejilla de presencia.
    pub fn symbol(self) -> char {
        match self {
            Self::Present => '█',
            Self::Absent => '·',
            Self::NoData => '░',
        }
    }

    /// Etiqueta larga del estado.
    pub fn label(self) -> &'static str {
        match self {
            Self::Present => "presente",
            Self::Absent => "ausente",
            Self::NoData => "sin datos",
        }
    }
}

/// Tramo continuo de presencia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceSpan {
    /// Inicio del tramo en segundos Unix UTC.
    pub start: i64,
    /// Fin del tramo en segundos Unix UTC.
    pub end: i64,
    /// Estado del tramo.
    pub state: PresenceState,
}

/// Hueco de cobertura de un rango.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// Inicio del hueco.
    pub start: i64,
    /// Fin del hueco.
    pub end: i64,
}

impl Gap {
    /// Duración del hueco en segundos.
    pub fn dur(self) -> i64 {
        (self.end - self.start).max(0)
    }
}

/// Entrada del inventario de un equipo (§7.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRow {
    /// Clave vista.
    pub key: String,
    /// Texto visible de la clave (se resuelve al pintar con el catálogo).
    pub label: String,
    /// Primera vez vista (RFC 3339 UTC).
    pub first_seen: String,
    /// Última vez vista (RFC 3339 UTC).
    pub last_seen: String,
}

/// Puerto del inventario, leído de DEVICE_SERVICES (§7.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryPort {
    /// Puerto.
    pub port: u16,
    /// Protocolo (tcp/udp).
    pub protocol: String,
    /// Servicio identificado, si se conoce.
    pub service: Option<String>,
    /// Primera detección (RFC 3339 UTC).
    pub first_seen: String,
    /// Cuándo un escaneo lo vio cerrado (RFC 3339 UTC); None = abierto.
    pub closed_at: Option<String>,
}

/// Inventario de un equipo o del propio equipo (§7.9 y §7.11).
///
/// Para el propio equipo, `device_id` es 0 (centinela de HOST_SEEN; los
/// identificadores de DEVICES empiezan en 1) y no hay puertos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Equipo consultado (0 = el propio equipo).
    pub device_id: i64,
    /// Fecha de inicio del inventario (primer first_seen del equipo).
    pub since: Option<String>,
    /// Apps vistas.
    pub apps: Vec<SeenRow>,
    /// Categorías vistas.
    pub categories: Vec<SeenRow>,
    /// Organizaciones vistas.
    pub orgs: Vec<SeenRow>,
    /// Países vistos.
    pub countries: Vec<SeenRow>,
    /// Huellas JA4 vistas.
    pub ja4: Vec<SeenRow>,
    /// Puertos abiertos de DEVICE_SERVICES.
    pub ports: Vec<InventoryPort>,
}

impl Inventory {
    /// Número de claves de un tipo.
    pub fn count(&self, kind: SeenKind) -> usize {
        match kind {
            SeenKind::App => self.apps.len(),
            SeenKind::Category => self.categories.len(),
            SeenKind::Org => self.orgs.len(),
            SeenKind::Country => self.countries.len(),
            SeenKind::Ja4 => self.ja4.len(),
        }
    }

    /// Indica si el inventario no tiene nada.
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
            && self.categories.is_empty()
            && self.orgs.is_empty()
            && self.countries.is_empty()
            && self.ja4.is_empty()
            && self.ports.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Alertas (F6)
// ---------------------------------------------------------------------------

/// Filtro de la lista de la pestaña Alertas (§6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertFilter {
    /// Nivel exacto pedido con `f`; None = todos.
    pub level: Option<Level>,
    /// Solo las que no se han visto (`u`).
    pub unseen_only: bool,
    /// Solo las de un equipo concreto (detalle de equipo o `/`).
    pub device_id: Option<i64>,
    /// Texto libre del filtro `/` sobre el nombre del equipo.
    pub search: Option<String>,
}

/// Fila de la lista de alertas (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRow {
    /// ALERTS.id.
    pub id: i64,
    /// Regla que la creó, o el resumen de la puesta al día (`catch_up`).
    pub rule: AlertRule,
    /// Nivel efectivo.
    pub level: Level,
    /// Sujeto (equipo, propio equipo, red o Almenara).
    pub subject: crate::alerts::Subject,
    /// DEVICES.id si el sujeto es un equipo; NULL si el equipo se borró.
    pub device_id: Option<i64>,
    /// Texto corto ya compuesto y saneado.
    pub title: String,
    /// Etiqueta visible: nombre actual del equipo o la guardada al crearla.
    pub subject_label: String,
    /// Creación, en segundos Unix UTC.
    pub created_at: i64,
    /// Última repetición, en segundos Unix UTC (ordena la lista).
    pub last_at: i64,
    /// Veces que ha saltado dentro del plazo de deduplicación.
    pub count: i64,
    /// Ya vista (`seen_at` no NULL).
    pub seen: bool,
    /// Condición resuelta (`resolved_at` no NULL).
    pub resolved: bool,
    /// Se notificó en el escritorio.
    pub notified: bool,
    /// Resumen de la puesta al día que la agrupa, si lo hay.
    pub summary_id: Option<i64>,
}

impl AlertRow {
    /// Indica si la fila es el resumen de la puesta al día.
    pub fn es_resumen(&self) -> bool {
        matches!(self.rule, AlertRule::CatchUp)
    }

    /// Indica si la alerta sigue sin ver.
    pub fn es_nueva(&self) -> bool {
        !self.seen
    }
}

/// Silencio de una regla para un sujeto (§7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuteRow {
    /// ALERT_MUTES.id.
    pub id: i64,
    /// Regla silenciada.
    pub rule: RuleId,
    /// Sujeto del silencio.
    pub subject: crate::alerts::Subject,
    /// DEVICES.id si el sujeto es un equipo; 0 en otro caso.
    pub device_id: i64,
    /// Etiqueta del sujeto (`[host]`, el nombre del equipo…).
    pub device_label: Option<String>,
    /// Fin del silencio (None = siempre), en segundos Unix UTC.
    pub until: Option<i64>,
    /// Creación, en segundos Unix UTC.
    pub created_at: i64,
}

/// Contadores de una regla para la vista Reglas (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleStat {
    /// Regla del catálogo.
    pub rule: RuleId,
    /// Alertas de la regla en los últimos 7 días.
    pub count_7d: u32,
    /// Silencios de la regla.
    pub mutes: u32,
}

/// Resumen de un sujeto para el detalle de equipo y la pestaña Config (§6).
#[derive(Debug, Clone, PartialEq)]
pub struct AlertSummary {
    /// Sujeto del resumen (la TUI distingue Host de Device con este campo).
    pub subject: SubjectSel,
    /// Últimas alertas del sujeto (5 como mucho).
    pub recent: Vec<AlertRow>,
    /// Alertas sin ver del sujeto por nivel.
    pub unseen: AlertCounts,
    /// Silencios vigentes del sujeto.
    pub mutes: Vec<MuteRow>,
    /// Aprendizaje del sujeto, si tiene fila (None en la red entera).
    pub learning: Option<LearningState>,
    /// Inventario del propio equipo (solo con `SubjectSel::Host`; la pestaña
    /// Config lo pinta en el bloque «Propio equipo»). None en los equipos: su
    /// detalle ya pide `Queries::inventory` aparte.
    pub inventory: Option<Inventory>,
}

/// Detalle de una alerta (§6).
#[derive(Debug, Clone, PartialEq)]
pub struct AlertDetail {
    /// La fila de la lista.
    pub row: AlertRow,
    /// El porqué guardado en `details` (JSON).
    pub details: serde_json::Value,
    /// Alertas que agrupa, si es el resumen de la puesta al día.
    pub grouped: Vec<AlertRow>,
    /// Fin del aprendizaje del sujeto (segundos Unix UTC), si ya aprendió.
    pub learned_at: Option<i64>,
    /// Silencios del sujeto.
    pub mutes: Vec<MuteRow>,
}

/// Fila de un ranking de 1 h o 24 h (§7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistRankRow {
    /// Clave de la fila.
    pub key: String,
    /// Texto visible.
    pub label: String,
    /// Subtítulo.
    pub subtitle: Option<String>,
    /// Equipo asociado si la fila es un equipo.
    pub device_id: Option<i64>,
    /// Bytes de bajada.
    pub bytes_down: u64,
    /// Bytes de subida.
    pub bytes_up: u64,
    /// Equipos distintos en la ventana.
    pub devices: u32,
    /// Conexiones contadas en la ventana.
    pub connections: u64,
}

impl HistRankRow {
    /// Total de bytes.
    pub fn total(&self) -> u64 {
        self.bytes_down.saturating_add(self.bytes_up)
    }
}

/// Resultado del ranking de 1 h o 24 h.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RankingResult {
    /// Ventana consultada.
    pub window: HistWindow,
    /// Dimensión consultada.
    pub dimension: Dimension,
    /// Filas ordenadas por total descendente.
    pub rows: Vec<HistRankRow>,
    /// Bajada total de la ventana.
    pub total_down: u64,
    /// Subida total de la ventana.
    pub total_up: u64,
    /// Porcentaje de bytes sin identificar (solo en dimensiones de app).
    pub unidentified_pct: f32,
    /// Último minuto cerrado incluido (segundos Unix UTC).
    pub closed_until: i64,
    /// Huecos de tráfico dentro de la ventana, en segundos.
    pub gap_seconds: i64,
}

/// Estadísticas de la base de datos para la pestaña Config.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DbStats {
    /// Tamaño del fichero principal de la base de datos.
    pub db_bytes: u64,
    /// Tamaño del fichero -wal.
    pub wal_bytes: u64,
    /// Fecha del dato más antiguo del histórico (RFC 3339 UTC).
    pub data_since: Option<String>,
    /// Cobertura de tráfico de los últimos 30 días (0-100).
    pub coverage_30d_pct: f32,
}

/// Filtro de la línea de tiempo de eventos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EventFilter {
    /// Todos los eventos y sesiones.
    #[default]
    All,
    /// Altas y presencia: new, disappeared y reappeared.
    Presence,
    /// Identidad: ip_changed, hostname_changed, mac_changed, os_changed y
    /// type_changed.
    Identity,
    /// Servicios: service_new y service_gone.
    Services,
    /// Sesiones de Almenara.
    Almanara,
}

impl EventFilter {
    /// Los cinco filtros, en el orden de f.
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::Presence,
        Self::Identity,
        Self::Services,
        Self::Almanara,
    ];

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "todos",
            Self::Presence => "altas y presencia",
            Self::Identity => "identidad",
            Self::Services => "servicios",
            Self::Almanara => "Almenara",
        }
    }

    /// Ciclo de f.
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Presence,
            Self::Presence => Self::Identity,
            Self::Identity => Self::Services,
            Self::Services => Self::Almanara,
            Self::Almanara => Self::All,
        }
    }

    /// Tipos de evento incluidos en el filtro (vacío = sesiones no).
    pub fn tipos(self) -> &'static [&'static str] {
        match self {
            Self::All => &[
                "new",
                "disappeared",
                "reappeared",
                "ip_changed",
                "hostname_changed",
                "mac_changed",
                "os_changed",
                "type_changed",
                "service_new",
                "service_gone",
            ],
            Self::Presence => &["new", "disappeared", "reappeared"],
            Self::Identity => &[
                "ip_changed",
                "hostname_changed",
                "mac_changed",
                "os_changed",
                "type_changed",
            ],
            Self::Services => &["service_new", "service_gone"],
            Self::Almanara => &[],
        }
    }

    /// Indica si el filtro incluye las sesiones de Almenara.
    pub fn incluye_sesiones(self) -> bool {
        matches!(self, Self::All | Self::Almanara)
    }
}

/// Paginación de la línea de tiempo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Page {
    /// Número máximo de elementos.
    pub limit: usize,
    /// Desplazamiento.
    pub offset: usize,
}

/// Consulta que la TUI envía al lector del histórico (§4.5).
#[derive(Debug, Clone, PartialEq)]
pub enum HistoryQuery {
    /// Serie de tráfico con huecos.
    Series {
        /// Sujeto consultado.
        subject: SubjectSel,
        /// Rango.
        range: Range,
        /// Instante actual en segundos Unix UTC.
        now: i64,
    },
    /// «Más tráfico» del rango.
    Top {
        /// Sujeto consultado.
        subject: SubjectSel,
        /// Dimensión pedida.
        dimension: Dimension,
        /// Rango.
        range: Range,
        /// Número máximo de filas.
        n: usize,
        /// Instante actual en segundos Unix UTC.
        now: i64,
    },
    /// Línea de tiempo de eventos y sesiones.
    Timeline {
        /// Filtro.
        filter: EventFilter,
        /// Rango.
        range: Range,
        /// Paginación.
        page: Page,
        /// Instante actual en segundos Unix UTC.
        now: i64,
    },
    /// Presencia de un equipo.
    Presence {
        /// Equipo.
        device_id: i64,
        /// Rango.
        range: Range,
        /// Instante actual en segundos Unix UTC.
        now: i64,
    },
    /// Inventario de un equipo.
    Inventory {
        /// Equipo.
        device_id: i64,
    },
    /// Cobertura de tráfico del rango.
    Coverage {
        /// Rango.
        range: Range,
        /// Instante actual en segundos Unix UTC.
        now: i64,
    },
    /// Último evento de la base de datos (para la línea «Último evento»).
    LastEvent,
    /// Estadísticas de la base de datos.
    DbStats,
    /// Ranking de 1 h o 24 h de la pestaña Tráfico.
    WindowRanking {
        /// Dimensión.
        dimension: Dimension,
        /// Ventana.
        window: HistWindow,
        /// Inicio del minuto en curso (segundos Unix UTC).
        now_minute: i64,
    },
    /// «¿Quién lo usa?» en 1 h o 24 h.
    WhoUses {
        /// Dimensión.
        dimension: Dimension,
        /// Clave pedida.
        key: String,
        /// Ventana.
        window: HistWindow,
        /// Inicio del minuto en curso (segundos Unix UTC).
        now_minute: i64,
    },
    /// Lista de la pestaña Alertas (F6).
    Alerts {
        /// Filtro de la lista.
        filter: AlertFilter,
        /// Paginación.
        page: Page,
        /// Instante actual en segundos Unix UTC (reservado: la lista ordena por
        /// `last_at` y no filtra por tiempo).
        now: i64,
    },
    /// Detalle de una alerta (F6).
    AlertDetail {
        /// ALERTS.id.
        id: i64,
    },
    /// Silencios vigentes de la vista Silencios (F6).
    Mutes {
        /// Instante actual en segundos Unix UTC (para descartar caducados).
        now: i64,
    },
    /// Alertas y silencios por regla de la vista Reglas (F6).
    RuleStats {
        /// Inicio de la ventana de 7 días, en segundos Unix UTC.
        since: i64,
    },
    /// Resumen de alertas, silencios y aprendizaje de un sujeto (F6).
    AlertSummary {
        /// Sujeto consultado (equipo, propio equipo o red).
        subject: SubjectSel,
        /// Instante actual en segundos Unix UTC.
        now: i64,
    },
}

/// Respuesta del lector del histórico.
#[derive(Debug, Clone, PartialEq)]
pub enum HistoryResponse {
    /// Serie de tráfico.
    Series(Series),
    /// «Más tráfico».
    Top(Vec<TopRow>),
    /// Línea de tiempo.
    Timeline(Vec<TimelineItem>),
    /// Presencia.
    Presence(Vec<PresenceSpan>),
    /// Inventario.
    Inventory(Box<Inventory>),
    /// Cobertura.
    Coverage(Vec<Gap>),
    /// Último evento.
    LastEvent(Option<TimelineItem>),
    /// Estadísticas.
    DbStats(DbStats),
    /// Ranking de ventana.
    WindowRanking(RankingResult),
    /// «¿Quién lo usa?» en una ventana del histórico.
    WhoUses(Vec<crate::rankings::DeviceShare>),
    /// Lista de alertas.
    Alerts(Vec<AlertRow>),
    /// Detalle de una alerta.
    AlertDetail(Box<AlertDetail>),
    /// Silencios vigentes.
    Mutes(Vec<MuteRow>),
    /// Alertas y silencios por regla.
    RuleStats(Vec<RuleStat>),
    /// Resumen de un sujeto.
    AlertSummary(Box<AlertSummary>),
}

impl HistoryResponse {
    /// Vista a la que responde (para descartar respuestas obsoletas).
    pub fn vista(&self) -> HistoryView {
        match self {
            Self::Series(_) => HistoryView::Series,
            Self::Top(_) => HistoryView::Top,
            Self::Timeline(_) => HistoryView::Timeline,
            Self::Presence(_) => HistoryView::Presence,
            Self::Inventory(_) => HistoryView::Inventory,
            Self::Coverage(_) => HistoryView::Coverage,
            Self::LastEvent(_) => HistoryView::LastEvent,
            Self::DbStats(_) => HistoryView::DbStats,
            Self::WindowRanking(_) => HistoryView::WindowRanking,
            Self::WhoUses(_) => HistoryView::WhoUses,
            Self::Alerts(_) => HistoryView::Alerts,
            Self::AlertDetail(_) => HistoryView::AlertDetail,
            Self::Mutes(_) => HistoryView::Mutes,
            Self::RuleStats(_) => HistoryView::RuleStats,
            Self::AlertSummary(_) => HistoryView::AlertSummary,
        }
    }
}

/// Vistas que pueden tener una consulta en vuelo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HistoryView {
    /// Histórico: serie.
    Series,
    /// Histórico: «Más tráfico».
    Top,
    /// Histórico: línea de tiempo.
    Timeline,
    /// Detalle: presencia.
    Presence,
    /// Detalle: inventario.
    Inventory,
    /// Tráfico: cobertura de la ventana.
    Coverage,
    /// Equipos: último evento.
    LastEvent,
    /// Config: estadísticas.
    DbStats,
    /// Tráfico: ranking de 1 h/24 h.
    WindowRanking,
    /// Tráfico: «¿Quién lo usa?».
    WhoUses,
    /// Alertas: lista.
    Alerts,
    /// Alertas: detalle.
    AlertDetail,
    /// Alertas: vista Silencios.
    Mutes,
    /// Alertas: vista Reglas.
    RuleStats,
    /// Detalle de equipo o Config: resumen de alertas.
    AlertSummary,
}

/// Estadísticas de los lotes del agregador para diagnóstico e informe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollupCounters {
    /// Entradas que no cabían en los acumuladores.
    pub overflow: u64,
    /// Lotes descartados tras 10 reintentos.
    pub drops: u64,
    /// Lotes escritos con éxito.
    pub batches: u64,
}

/// Crea el esquema mínimo de la migración v6 para las pruebas de `history`.
///
/// Mientras el equipo de datos termina la migración v6, las consultas del lector
/// se prueban contra este esquema, idéntico al §3 del informe. Con la migración
/// ya aplicada las sentencias `IF NOT EXISTS` no hacen nada.
#[cfg(test)]
pub(crate) fn esquema_v6_de_pruebas(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ALERTS (
             id            INTEGER PRIMARY KEY AUTOINCREMENT,
             rule          TEXT NOT NULL,
             level         TEXT NOT NULL,
             subject       TEXT NOT NULL,
             device_id     INTEGER NULL REFERENCES DEVICES(id) ON DELETE SET NULL,
             key           TEXT NOT NULL DEFAULT '',
             title         TEXT NOT NULL,
             subject_label TEXT NOT NULL,
             details       TEXT NOT NULL DEFAULT '{}',
             event_id      INTEGER NULL,
             summary_id    INTEGER NULL,
             created_at    TIMESTAMP NOT NULL,
             last_at       TIMESTAMP NOT NULL,
             count         INTEGER NOT NULL DEFAULT 1,
             seen_at       TIMESTAMP NULL,
             resolved_at   TIMESTAMP NULL,
             notified      BOOLEAN NOT NULL DEFAULT 0
         );
         CREATE INDEX IF NOT EXISTS IDX_ALERTS_LAST_AT ON ALERTS(last_at);
         CREATE INDEX IF NOT EXISTS IDX_ALERTS_DEVICE ON ALERTS(device_id, last_at);
         CREATE INDEX IF NOT EXISTS IDX_ALERTS_UNSEEN ON ALERTS(level)
             WHERE seen_at IS NULL;
         CREATE TABLE IF NOT EXISTS ALERT_MUTES (
             id         INTEGER PRIMARY KEY AUTOINCREMENT,
             rule       TEXT NOT NULL,
             subject    TEXT NOT NULL,
             device_id  INTEGER NOT NULL DEFAULT 0,
             until      TIMESTAMP NULL,
             created_at TIMESTAMP NOT NULL,
             UNIQUE (rule, subject, device_id)
         );
         CREATE TABLE IF NOT EXISTS ALERT_LEARNING (
             subject       TEXT NOT NULL,
             device_id     INTEGER NOT NULL DEFAULT 0,
             learning_from TIMESTAMP NOT NULL,
             data_days     INTEGER NOT NULL DEFAULT 0,
             learned_at    TIMESTAMP NULL,
             updated_day   INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY (subject, device_id)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS HOST_SEEN (
             kind       TEXT NOT NULL,
             key        TEXT NOT NULL,
             first_seen TIMESTAMP NOT NULL,
             last_seen  TIMESTAMP NOT NULL,
             PRIMARY KEY (kind, key)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS IDX_HOST_SEEN_LAST_SEEN ON HOST_SEEN(last_seen);
         CREATE TABLE IF NOT EXISTS COVERAGE_GAPS (
             id         INTEGER PRIMARY KEY AUTOINCREMENT,
             session_id INTEGER NOT NULL REFERENCES APP_SESSIONS(id) ON DELETE CASCADE,
             kind       TEXT NOT NULL,
             started_at TIMESTAMP NOT NULL,
             ended_at   TIMESTAMP NULL
         );
         CREATE INDEX IF NOT EXISTS IDX_GAPS_SESSION ON COVERAGE_GAPS(session_id);
         CREATE INDEX IF NOT EXISTS IDX_GAPS_STARTED ON COVERAGE_GAPS(started_at);",
    )?;
    let tiene_closed_at: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('DEVICE_SERVICES') WHERE name = 'closed_at'",
        [],
        |fila| fila.get(0),
    )?;
    if tiene_closed_at == 0 {
        conn.execute_batch("ALTER TABLE DEVICE_SERVICES ADD COLUMN closed_at TIMESTAMP NULL;")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sujetos_ida_y_vuelta() {
        for sujeto in [
            Subject::Device(7),
            Subject::Host,
            Subject::Other,
            Subject::Network,
        ] {
            assert_eq!(
                Subject::from_parts(sujeto.as_str(), sujeto.device_id()),
                Some(sujeto)
            );
        }
        assert_eq!(Subject::Network.device_id(), 0);
        assert_eq!(Subject::from_parts("desconocido", 0), None);
    }

    #[test]
    fn dimensiones_ida_y_vuelta() {
        for dimension in Dimension::ALL {
            assert_eq!(Dimension::from_str(dimension.as_str()), Some(dimension));
        }
        assert_eq!(Dimension::ALL.len(), 8);
        assert_eq!(SeenKind::from_dimension(Dimension::Destination), None);
        assert_eq!(
            SeenKind::from_dimension(Dimension::App),
            Some(SeenKind::App)
        );
    }

    #[test]
    fn claves_especiales_y_dims() {
        let dims = FlowDims {
            subject: Some(Subject::Device(3)),
            destination: Some("youtube.com".to_string()),
            protocol: Some("tls".to_string()),
            ..FlowDims::default()
        };
        assert_eq!(dims.clave(Dimension::Total).as_deref(), Some(""));
        assert_eq!(
            dims.clave(Dimension::App).as_deref(),
            Some(KEY_UNIDENTIFIED)
        );
        assert_eq!(dims.clave(Dimension::Org).as_deref(), Some(KEY_UNKNOWN));
        assert_eq!(
            dims.clave(Dimension::Destination).as_deref(),
            Some("youtube.com")
        );
        assert_eq!(dims.clave(Dimension::Process), None);
        assert!(clave_especial(KEY_OTHERS));
        assert!(!clave_especial("youtube"));
    }

    #[test]
    fn rangos_en_ciclo_y_puntos() {
        assert_eq!(Range::Hours24.next(), Range::Days7);
        assert_eq!(Range::Year1.next(), Range::Hours24);
        assert_eq!(Range::ALL.len(), 4);
        assert_eq!(Range::Hours24.points(), 48);
        assert_eq!(Range::Days7.points(), 56);
        assert_eq!(Range::Year1.points(), 53);
        assert!(!Range::Year1.admite_destinos());
        assert_eq!(Range::Days30.source(), RangeSource::DaysAndCurrentHours);
    }

    #[test]
    fn filtros_de_eventos() {
        assert_eq!(EventFilter::ALL.len(), 5);
        assert_eq!(EventFilter::All.next(), EventFilter::Presence);
        assert!(EventFilter::All.incluye_sesiones());
        assert!(!EventFilter::Presence.incluye_sesiones());
        assert_eq!(EventFilter::Identity.tipos().len(), 5);
    }

    #[test]
    fn contadores_saturan() {
        let mut contador = Counter {
            down: u64::MAX,
            up: 0,
            connections: 0,
        };
        contador.suma_bytes(10, Dir::Down);
        assert_eq!(contador.down, u64::MAX);
        contador.suma(Counter {
            down: 1,
            up: 2,
            connections: 3,
        });
        assert_eq!(contador.up, 2);
        assert_eq!(contador.connections, 3);
    }

    #[test]
    fn entradas_de_inventario_de_equipo_y_de_host() {
        let equipo = SeenItem::de_equipo(7, SeenKind::App, "steam");
        assert_eq!(equipo.subject, Subject::Device(7));
        assert_eq!(equipo.device_id(), Some(7));
        assert!(!equipo.es_host());
        let host = SeenItem::del_host(SeenKind::Ja4, "t13d1516h2");
        assert_eq!(host.subject, Subject::Host);
        assert_eq!(host.device_id(), None);
        assert!(host.es_host());
    }

    #[test]
    fn filtros_y_resumenes_de_alertas_por_defecto() {
        let filtro = AlertFilter::default();
        assert!(filtro.level.is_none());
        assert!(!filtro.unseen_only);
        assert!(filtro.search.is_none());
        let resumen = AlertSummary {
            subject: SubjectSel::Host,
            recent: Vec::new(),
            unseen: AlertCounts::default(),
            mutes: Vec::new(),
            learning: None,
            inventory: None,
        };
        assert_eq!(resumen.subject, SubjectSel::Host);
        assert!(resumen.recent.is_empty());
        assert!(resumen.mutes.is_empty());
        assert!(resumen.learning.is_none());
    }
}
