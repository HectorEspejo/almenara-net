//! Motor de alertas de la Fase 6 (ADR-68).
//!
//! Este módulo es **puro**: recibe señales y devuelve acciones, sin abrir la base
//! de datos ni conocer la TUI. El hilo de la TUI es quien aplica las acciones
//! (único escritor, ADR-35) y quien entrega las notificaciones al notificador de
//! escritorio. Así el motor se prueba sin BD y lo reutilizará el modo servicio
//! de la sub-fase 6.5.
//!
//! Contrato de tipos del motor (compartido con `repo`, `history::queries` y la TUI).

pub mod baseline;
pub mod engine;
pub mod health;
pub mod learning;
pub mod policy;
pub mod rules;
pub mod suspend;
pub mod text;

#[allow(unused_imports)]
pub use baseline::{Baseline, HighInfo};
pub use engine::{
    AlertAction, AlertEngine, DedupKey, EngineSnapshot, LearningState, MuteState, NewAlert, Notice,
    RecentState,
};
pub use health::{CaptureHealth, CaptureStats, DbSize, Health, HealthSample};
pub use learning::{Learning, LearningParams};
#[allow(unused_imports)]
pub use policy::{NotifyDecision, NotifyPolicy, QuietHours};
#[allow(unused_imports)]
pub use rules::{RuleDef, RuleId, RuleSetting, Rules};
#[allow(unused_imports)]
pub use suspend::{Suspend, Suspension};
#[allow(unused_imports)]
pub use text::{AlertText, AlertTexts, SubjectInfo};

use std::collections::BTreeMap;
use std::time::SystemTime;

/// Identificador de la alerta resumen de la puesta al día (§7.9).
pub const CATCH_UP_RULE: &str = "catch_up";
/// Longitud máxima del título de una alerta (§7.13).
pub const TITLE_MAX: usize = 120;
/// Longitud máxima de la etiqueta del sujeto (§7.13).
pub const LABEL_MAX: usize = 64;
/// Longitud máxima del cuerpo de una notificación (§7.13).
pub const BODY_MAX: usize = 200;
/// Capacidad del canal acotado del notificador (ADR-76).
pub const NOTIFY_CHANNEL_CAPACITY: usize = 32;

/// Nivel de una alerta (§7.2). Solo `Important` notifica.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Se queda en la pestaña Alertas.
    #[default]
    Info,
    /// Pestaña y contador de la barra.
    Warning,
    /// Pestaña, contador y notificación de escritorio.
    Important,
}

#[allow(clippy::should_implement_trait)] // `from_str` inherente como en el resto del crate
impl Level {
    /// Todos los niveles, de menor a mayor gravedad.
    pub const ALL: [Level; 3] = [Level::Info, Level::Warning, Level::Important];

    /// Representación persistida en ALERTS.level.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Important => "important",
        }
    }

    /// Reconstruye el nivel desde su representación persistida.
    pub fn from_str(valor: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|nivel| nivel.as_str() == valor)
    }

    /// Etiqueta en castellano para la TUI.
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "aviso",
            Self::Important => "importante",
        }
    }

    /// Símbolo y texto que no dependen solo del color (§6, accesibilidad).
    pub fn badge(self) -> &'static str {
        match self {
            Self::Important => "!! IMP",
            Self::Warning => "!  AVI",
            Self::Info => "   INF",
        }
    }

    /// Indica si la alerta suma al contador «Alertas N» de la barra (§7.2).
    #[allow(dead_code)] // contrato del dominio; el contador usa AlertCounts::badge
    pub fn counts_in_badge(self) -> bool {
        matches!(self, Self::Important | Self::Warning)
    }

    /// Nivel siguiente en el ciclo de la vista Reglas (`n`).
    pub fn next(self) -> Self {
        match self {
            Self::Important => Self::Warning,
            Self::Warning => Self::Info,
            Self::Info => Self::Important,
        }
    }
}

/// Sujeto de una alerta: equipo, propio equipo, red entera o Almenara.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subject {
    /// Un equipo de DEVICES.
    Device(i64),
    /// El propio equipo (sujeto `host` del histórico).
    Host,
    /// La red entera (sujeto `network` del histórico).
    Network,
    /// Almenara (salud y resumen de la puesta al día).
    Almenara,
}

impl Subject {
    /// Valor persistido en ALERTS.subject.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device(_) => "device",
            Self::Host => "host",
            Self::Network => "network",
            Self::Almenara => "almenara",
        }
    }

    /// DEVICES.id asociado (0 en los sujetos que no son equipos, como los rollups).
    pub fn device_id(self) -> i64 {
        match self {
            Self::Device(id) => id,
            Self::Host | Self::Network | Self::Almenara => 0,
        }
    }

    /// Reconstruye el sujeto desde sus dos columnas persistidas.
    pub fn from_parts(subject: &str, device_id: i64) -> Option<Self> {
        match subject {
            "device" => Some(Self::Device(device_id)),
            "host" => Some(Self::Host),
            "network" => Some(Self::Network),
            "almenara" => Some(Self::Almenara),
            _ => None,
        }
    }

    /// Etiqueta para la TUI cuando no hay nombre propio.
    pub fn label(self) -> &'static str {
        match self {
            Self::Device(_) => "equipo",
            Self::Host => "[host]",
            Self::Network => "Toda la red",
            Self::Almenara => "Almenara",
        }
    }
}

/// Regla de una alerta: una de las 16 configurables o el resumen de la puesta
/// al día (`catch_up`), que no es configurable (§7.1 y §7.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertRule {
    /// Regla del catálogo fijo.
    Rule(RuleId),
    /// Resumen de la puesta al día.
    CatchUp,
}

#[allow(clippy::should_implement_trait)] // `from_str` inherente como en el resto del crate
impl AlertRule {
    /// Valor persistido en ALERTS.rule.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule(regla) => regla.as_str(),
            Self::CatchUp => CATCH_UP_RULE,
        }
    }

    /// Reconstruye la regla desde su valor persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        if valor == CATCH_UP_RULE {
            return Some(Self::CatchUp);
        }
        RuleId::from_str(valor).map(Self::Rule)
    }

    /// Nombre visible en la lista de alertas.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rule(regla) => regla.name(),
            Self::CatchUp => "Resumen al arrancar",
        }
    }

    /// Identificador del catálogo, si la alerta es de una regla configurable.
    pub fn rule_id(self) -> Option<RuleId> {
        match self {
            Self::Rule(regla) => Some(regla),
            Self::CatchUp => None,
        }
    }
}

/// Entrada nueva del inventario de un sujeto, con su etiqueta visible.
///
/// La señal `Seen` lleva solo las entradas que el DAO ha visto por primera vez.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenNew {
    /// Tipo de clave (`app`, `category`, `org`, `country` o `ja4`).
    pub kind: crate::history::SeenKind,
    /// Clave vista.
    pub key: String,
    /// Etiqueta legible para el título (`Steam`, `Irlanda (IE)`, …).
    pub label: String,
    /// Primera vez vista.
    pub first_seen: SystemTime,
}

/// Cómo llegó un equipo nuevo (para el porqué de `device_new`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeviceSource {
    /// Descubierto por el escaneo (ARP/ICMP/pasivo).
    #[default]
    Scan,
    /// Descubierto por la captura de tráfico (F4).
    Capture,
}

impl DeviceSource {
    /// Texto para `details.source`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Capture => "capture",
        }
    }
}

/// Datos del equipo que viajan en una señal de evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSignal {
    /// DEVICES.id.
    pub device_id: i64,
    /// Nombre visible actual (alias, hostname, IP o MAC).
    pub label: String,
    /// MAC actual.
    pub mac: String,
    /// MAC administrada localmente (posible rotación por privacidad, F4).
    pub mac_random: bool,
    /// Fabricante por OUI, si se conoce.
    pub vendor: Option<String>,
    /// IPv4 actual.
    pub ip: String,
    /// Hostname actual, si se conoce.
    pub hostname: Option<String>,
    /// Equipo vigilado (`DEVICES.watched`, §7.7).
    pub watched: bool,
    /// Familia de SO actual, si se conoce.
    pub os_family: Option<String>,
    /// Tipo de equipo efectivo (automático o manual).
    pub device_type: String,
    /// Primera vez visto.
    pub first_seen: SystemTime,
    /// Última vez visto.
    pub last_seen: SystemTime,
    /// Origen del descubrimiento en una alta (`scan` o `capture`).
    pub source: DeviceSource,
}

/// Tipo de evento de una señal de evento (subconjunto de DEVICE_EVENTS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Equipo nuevo (`new`).
    New,
    /// Equipo ausente (`disappeared`).
    Disappeared,
    /// Equipo de vuelta (`reappeared`).
    Reappeared,
    /// Cambio de MAC (`mac_changed`).
    MacChanged,
    /// Cambio de nombre (`hostname_changed`).
    HostnameChanged,
    /// Puerto nuevo o reabierto (`service_new`).
    ServiceNew,
    /// Cambio de SO (`os_changed`).
    OsChanged,
    /// Cambio de tipo (`type_changed`).
    TypeChanged,
}

/// Señal de un evento en vivo ya persistido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSignal {
    /// Equipo y sus datos actuales.
    pub device: DeviceSignal,
    /// Tipo de evento.
    pub kind: EventKind,
    /// Detalles JSON del evento (ya vienen saneados por el escaneo).
    pub details: serde_json::Value,
    /// DEVICE_EVENTS.id de origen, si se conoce (referencia lógica).
    pub event_id: Option<i64>,
}

/// Señal de inventario nuevo de un sujeto (equipo o propio equipo, §7.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenSignal {
    /// Sujeto al que se atribuye lo nuevo.
    pub subject: Subject,
    /// Etiqueta visible del sujeto.
    pub subject_label: String,
    /// El sujeto ya ha terminado el aprendizaje (§7.3): lo nuevo avisa.
    pub learned: bool,
    /// Fecha en que terminó el aprendizaje, si ya aprendió.
    pub learned_at: Option<SystemTime>,
    /// Entradas nuevas del inventario.
    pub items: Vec<SeenNew>,
}

/// Valor de un sujeto para una hora cerrada con sus muestras de 14 días.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HourSubject {
    /// Sujeto de la hora (equipo, propio equipo o red).
    pub subject: Subject,
    /// Etiqueta visible del sujeto (nombre actual del equipo, «Este equipo»…).
    pub label: String,
    /// Bytes de bajada de la hora.
    pub down: u64,
    /// Bytes de subida de la hora.
    pub up: u64,
    /// Muestras de la misma hora local de los días anteriores con cobertura.
    pub samples: Vec<(u64, u64)>,
}

/// Señal de una hora cerrada y consolidada en vivo (§7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HourClosedSignal {
    /// Inicio de la hora local en segundos Unix UTC.
    pub hour_start: i64,
    /// Valores y muestras por sujeto.
    pub subjects: Vec<HourSubject>,
}

/// Señal que recibe el motor.
#[derive(Debug, Clone, PartialEq)]
pub enum Signal {
    /// Un evento del escaneo (alta, ausencia, servicios, identidad).
    Event(EventSignal),
    /// Entradas nuevas del inventario de un sujeto.
    Seen(SeenSignal),
    /// Una hora recién consolidada en vivo.
    HourClosed(HourClosedSignal),
    /// Una muestra de salud de la captura o de la BD.
    Health(HealthSample),
}

/// Contadores de alertas no vistas por nivel (`Repo::unseen_counts`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AlertCounts {
    /// No vistas importantes.
    pub important: u32,
    /// No vistas de aviso.
    pub warning: u32,
    /// No vistas de info.
    pub info: u32,
}

impl AlertCounts {
    /// Suma de importantes y avisos (lo que muestra «Alertas N», §6).
    pub fn badge(self) -> u32 {
        self.important.saturating_add(self.warning)
    }

    /// Indica si el contador debe ocultarse.
    pub fn is_empty(self) -> bool {
        self.badge() == 0
    }
}

/// Parámetros de «más tráfico de lo habitual» (§7.4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrafficHighParams {
    /// Veces la mediana que debe superar el valor.
    pub factor: f64,
    /// Días de muestras (14).
    pub baseline_days: u32,
    /// Muestras mínimas para evaluar (5).
    pub min_days: u32,
    /// Mínimo de bajada por hora en MB de 1 000 000 bytes.
    pub min_mb_down: u64,
    /// Mínimo de subida por hora en MB de 1 000 000 bytes.
    pub min_mb_up: u64,
}

impl Default for TrafficHighParams {
    fn default() -> Self {
        Self {
            factor: 3.0,
            baseline_days: 14,
            min_days: 5,
            min_mb_down: 200,
            min_mb_up: 50,
        }
    }
}

/// Parámetros de «pérdidas de captura» (§7.8).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CaptureDropsParams {
    /// Porcentaje de pérdida por minuto que cuenta como malo (1,0).
    pub percent: f64,
    /// Minutos seguidos por encima del umbral (5).
    pub minutes: u32,
}

impl Default for CaptureDropsParams {
    fn default() -> Self {
        Self {
            percent: 1.0,
            minutes: 5,
        }
    }
}

/// Parámetros en tiempo de ejecución del motor de alertas.
///
/// Es la proyección validada de `[alerts]` de la configuración; el motor no
/// conoce `config::AlertsConfig` para poder probarse sin TOML.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertsParams {
    /// Motor de alertas encendido (`[alerts].enabled`).
    pub enabled: bool,
    /// Días de retención de alertas (90).
    pub retention_days: u32,
    /// Días con datos antes de avisar de lo nuevo (7).
    pub learning_days: u32,
    /// Minutos de puesta al día tras arrancar (10; 0 = sin ella).
    pub catch_up_minutes: u32,
    /// Horas de deduplicación (24).
    pub dedup_hours: u32,
    /// Notificaciones de escritorio encendidas.
    pub desktop_notifications: bool,
    /// Horario silencioso, si está configurado.
    pub quiet_hours: Option<QuietHours>,
    /// Tope de notificaciones por minuto (3).
    pub max_notifications_per_minute: u32,
    /// Parámetros de la regla `traffic_high`.
    pub traffic_high: TrafficHighParams,
    /// Parámetros de la regla `capture_drops`.
    pub capture_drops: CaptureDropsParams,
    /// Ajuste de cada una de las 16 reglas.
    pub rules: BTreeMap<RuleId, RuleSetting>,
}

impl Default for AlertsParams {
    fn default() -> Self {
        let mut rules = BTreeMap::new();
        for def in RuleId::ALL {
            rules.insert(def, RuleSetting::default_for(def));
        }
        Self {
            enabled: true,
            retention_days: 90,
            learning_days: 7,
            catch_up_minutes: 10,
            dedup_hours: 24,
            desktop_notifications: true,
            quiet_hours: None,
            max_notifications_per_minute: 3,
            traffic_high: TrafficHighParams::default(),
            capture_drops: CaptureDropsParams::default(),
            rules,
        }
    }
}

impl AlertsParams {
    /// Ajuste efectivo de una regla (sus valores por defecto si falta).
    pub fn rule(&self, rule: RuleId) -> RuleSetting {
        self.rules
            .get(&rule)
            .copied()
            .unwrap_or_else(|| RuleSetting::default_for(rule))
    }

    /// Nivel efectivo de una regla.
    pub fn level(&self, rule: RuleId) -> Level {
        self.rule(rule).level
    }
}
