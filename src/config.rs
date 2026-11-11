//! Carga y validación de la configuración TOML de Almenara.
//!
//! La configuración vive por defecto en `~/.config/almenara/config.toml`. Si el
//! fichero no existe se usan los valores por defecto y, en el arranque, se escribe
//! una plantilla comentada. Cualquier error de sintaxis o validación hace que se
//! usen los valores por defecto con un aviso (nunca impide arrancar).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// Nombre de la aplicación, usado para rutas y logs.
pub const APP_NAME: &str = "almenara";

/// Intervalo de escaneo por defecto, en segundos.
pub const DEFAULT_INTERVAL_S: u64 = 60;
/// Timeout por defecto de ICMP y reverse DNS, en milisegundos.
pub const DEFAULT_ICMP_TIMEOUT_MS: u64 = 500;
/// Ciclos sin respuesta antes de marcar un equipo como offline.
pub const DEFAULT_OFFLINE_CYCLES: u32 = 3;
/// Retención por defecto de eventos, en días.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;
/// Intervalo de escaneo mínimo aceptado, en segundos.
pub const MIN_INTERVAL_S: u64 = 10;
/// Timeout ICMP/DNS mínimo aceptado, en milisegundos.
pub const MIN_ICMP_TIMEOUT_MS: u64 = 100;
/// Timeout ICMP/DNS máximo aceptado, en milisegundos.
pub const MAX_ICMP_TIMEOUT_MS: u64 = 5000;
/// Máximo de direcciones por rango en Fase 1.
pub const MAX_RANGE_HOSTS: u32 = 1024;
/// Concurrencia usada por el ping sweep y por el port scan.
pub const DEFAULT_SWEEP_CONCURRENCY: usize = 64;

/// Puertos del port scan por defecto (TOP-20 de la especificación).
///
/// La lista del checklist repite el puerto 1883 (MQTT); como la validación exige
/// puertos únicos, aquí se deduplica y quedan 19 puertos. Es una desviación
/// documentada en el informe de implementación.
pub const DEFAULT_TOP_PORTS: [u16; 19] = [
    22, 23, 53, 80, 139, 443, 445, 515, 631, 1883, 3389, 5000, 5353, 5555, 8008, 8080, 8443, 9100,
    32400,
];
/// Número máximo de puertos configurable en [scan].top_ports.
pub const MAX_TOP_PORTS: usize = 64;
/// Timeout del port scan por defecto, en milisegundos.
pub const DEFAULT_PORTSCAN_TIMEOUT_MS: u64 = 500;
/// Timeout del banner grabbing por defecto, en milisegundos.
pub const DEFAULT_BANNER_TIMEOUT_MS: u64 = 1000;
/// Timeout del fetch del XML de descripción SSDP, en milisegundos.
pub const DEFAULT_SSDP_FETCH_TIMEOUT_MS: u64 = 2000;
/// Timeout de la consulta NetBIOS, en milisegundos.
pub const DEFAULT_NETBIOS_TIMEOUT_MS: u64 = 500;

/// Configuración completa de Almenara.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Parámetros del escaneo periódico.
    pub scan: ScanConfig,
    /// Parámetros de captura de tráfico en vivo (Fase 3).
    pub capture: CaptureConfig,
    /// Parámetros de persistencia.
    pub storage: StorageConfig,
    /// Parámetros del histórico (Fase 5).
    pub history: HistoryConfig,
    /// Parámetros de interfaz.
    pub ui: UiConfig,
    /// Parámetros del motor de inferencia (Fase 4).
    pub inference: InferenceConfig,
    /// Parámetros del motor de alertas (Fase 6).
    pub alerts: AlertsConfig,
}

/// Sección [scan] de la configuración.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Interfaces a escanear: "auto" o lista de nombres.
    pub interfaces: InterfacesSetting,
    /// Rangos IPv4 en notación CIDR. Vacío significa derivarlos de la interfaz.
    pub ranges: Vec<String>,
    /// Intervalo entre escaneos, en segundos (mínimo 10).
    pub interval_s: u64,
    /// Timeout de ICMP y reverse DNS, en milisegundos (100-5000).
    pub icmp_timeout_ms: u64,
    /// Ciclos consecutivos sin respuesta antes de marcar offline.
    pub offline_after_cycles: u32,
    /// Deshabilita todo el tráfico activo (modo pasivo consciente).
    pub passive_only: bool,
    /// Puertos del port scan TCP CONNECT (máximo 64, únicos).
    pub top_ports: Vec<u16>,
    /// Rutas manuales adicionales de ficheros de leases DHCP.
    pub dhcp_lease_paths: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            interfaces: InterfacesSetting::Auto,
            ranges: Vec::new(),
            interval_s: DEFAULT_INTERVAL_S,
            icmp_timeout_ms: DEFAULT_ICMP_TIMEOUT_MS,
            offline_after_cycles: DEFAULT_OFFLINE_CYCLES,
            passive_only: false,
            top_ports: DEFAULT_TOP_PORTS.to_vec(),
            dhcp_lease_paths: Vec::new(),
        }
    }
}

/// Sección [storage] de la configuración.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Ruta del fichero SQLite (admite ~).
    pub db_path: String,
    /// Días que se conservan los eventos antes de purgarlos.
    pub events_retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: "~/.local/share/almenara/data.db".to_string(),
            events_retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

/// Valores por defecto de [history] (§7.12).
pub const DEFAULT_MINUTE_DAYS: u32 = 2;
/// Días de retención de las horas.
pub const DEFAULT_HOUR_DAYS: u32 = 90;
/// Días de retención de días, inventario y sesiones.
pub const DEFAULT_DAY_DAYS: u32 = 730;
/// Días de retención de destinos por hora.
pub const DEFAULT_DESTINATION_DAYS: u32 = 30;
/// Claves normales por sujeto, dimensión y cubo.
pub const DEFAULT_TOP_KEYS: usize = 20;
/// Tamaño de la base de datos a partir del cual se avisa (MB).
pub const DEFAULT_MAX_DB_MB: u64 = 1024;
/// Mínimo aceptado de max_db_mb.
pub const MIN_MAX_DB_MB: u64 = 64;

/// Sección [history]: retención y límites del histórico de F5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryConfig {
    /// Guardar histórico (rollups e inventario).
    pub enabled: bool,
    /// Retención de minutos en días (48 h con el valor por defecto).
    pub minute_days: u32,
    /// Retención de horas en días.
    pub hour_days: u32,
    /// Retención de días, inventario y sesiones en días.
    pub day_days: u32,
    /// Retención de destinos por hora en días (0 = no guardarlos).
    pub destination_days: u32,
    /// Claves normales por sujeto, dimensión y cubo; el resto, «otros».
    pub top_keys: usize,
    /// Aviso cuando la base de datos supera este tamaño en MB.
    pub max_db_mb: u64,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            minute_days: DEFAULT_MINUTE_DAYS,
            hour_days: DEFAULT_HOUR_DAYS,
            day_days: DEFAULT_DAY_DAYS,
            destination_days: DEFAULT_DESTINATION_DAYS,
            top_keys: DEFAULT_TOP_KEYS,
            max_db_mb: DEFAULT_MAX_DB_MB,
        }
    }
}

impl HistoryConfig {
    /// Retención equivalente para el DAO del histórico.
    pub fn retention(&self) -> crate::history::Retention {
        crate::history::Retention {
            minute_days: self.minute_days,
            hour_days: self.hour_days,
            day_days: self.day_days,
            destination_days: self.destination_days,
        }
    }

    /// Corrige los valores fuera de rango con el valor por defecto y avisa.
    ///
    /// La configuración nunca aborta el arranque: un valor inválido se avisa una
    /// vez y se sustituye por el valor por defecto (§7.12).
    pub fn validar(&mut self) -> Vec<String> {
        let mut avisos = Vec::new();
        if !(1..=7).contains(&self.minute_days) {
            avisos.push(format!(
                "[history].minute_days = {} no es válido (1-7); se usa {DEFAULT_MINUTE_DAYS}",
                self.minute_days
            ));
            self.minute_days = DEFAULT_MINUTE_DAYS;
        }
        if !(7..=365).contains(&self.hour_days) {
            avisos.push(format!(
                "[history].hour_days = {} no es válido (7-365); se usa {DEFAULT_HOUR_DAYS}",
                self.hour_days
            ));
            self.hour_days = DEFAULT_HOUR_DAYS;
        }
        if !(30..=3650).contains(&self.day_days) {
            avisos.push(format!(
                "[history].day_days = {} no es válido (30-3650); se usa {DEFAULT_DAY_DAYS}",
                self.day_days
            ));
            self.day_days = DEFAULT_DAY_DAYS;
        }
        if self.destination_days > self.hour_days {
            avisos.push(format!(
                "[history].destination_days = {} no puede superar hour_days = {}; se usa {}",
                self.destination_days,
                self.hour_days,
                DEFAULT_DESTINATION_DAYS.min(self.hour_days)
            ));
            self.destination_days = DEFAULT_DESTINATION_DAYS.min(self.hour_days);
        }
        if !(5..=100).contains(&self.top_keys) {
            avisos.push(format!(
                "[history].top_keys = {} no es válido (5-100); se usa {DEFAULT_TOP_KEYS}",
                self.top_keys
            ));
            self.top_keys = DEFAULT_TOP_KEYS;
        }
        if self.max_db_mb < MIN_MAX_DB_MB {
            avisos.push(format!(
                "[history].max_db_mb = {} no es válido (mínimo {MIN_MAX_DB_MB}); se usa {DEFAULT_MAX_DB_MB}",
                self.max_db_mb
            ));
            self.max_db_mb = DEFAULT_MAX_DB_MB;
        }
        avisos
    }
}

/// Sección [capture] de la configuración: captura de tráfico en vivo (Fase 3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    /// Activa la captura de paquetes al arrancar.
    pub enabled: bool,
    /// Expresión de filtro BPF clásico; vacía = sin filtro.
    pub filter: String,
    /// Límite de paquetes por segundo (0 = sin límite).
    pub max_pps: u64,
    /// Clave obsoleta de F3: se ignora con un aviso único (la inferencia se
    /// controla con `[inference].enabled`). `None` si no aparece en el fichero.
    #[serde(default, skip_serializing)]
    pub inspect_payload: Option<bool>,
    /// Clave obsoleta de F3: se ignora con un aviso único.
    #[serde(default, skip_serializing)]
    pub dns_attribution: Option<bool>,
    /// Clave obsoleta de F3: se ignora con un aviso único.
    #[serde(default, skip_serializing)]
    pub sni_attribution: Option<bool>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            filter: String::new(),
            max_pps: 0,
            inspect_payload: None,
            dns_attribution: None,
            sni_attribution: None,
        }
    }
}

// Helpers de presentación de la sección [capture] (los usan la barra de estado,
// los tests y la pestaña Config de fases posteriores).
#[allow(dead_code)]
impl CaptureConfig {
    /// Indica si hay un filtro BPF configurado.
    pub fn has_filter(&self) -> bool {
        !self.filter.trim().is_empty()
    }

    /// Texto del filtro para la barra de estado ("(ninguno)" si está vacío).
    pub fn filter_label(&self) -> String {
        if self.has_filter() {
            self.filter.trim().to_string()
        } else {
            "(ninguno)".to_string()
        }
    }
}

/// Sección [ui] de la configuración.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    /// Nombre del tema (solo "default" en Fase 1).
    pub theme: String,
    /// Desactiva el color aunque el terminal lo soporte.
    pub no_color: bool,
    /// Vista de la lista de equipos: plana o agrupada por categoría.
    pub list_view: ListView,
    /// Agrupación del ranking de la pestaña Tráfico (Fase 4).
    pub traffic_group: TrafficGroup,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "default".to_string(),
            no_color: false,
            list_view: ListView::Flat,
            traffic_group: TrafficGroup::Device,
        }
    }
}

/// Vista de la lista de equipos.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListView {
    /// Lista plana (comportamiento de Fase 1).
    #[default]
    Flat,
    /// Lista agrupada por categoría de dispositivo.
    Grouped,
}

impl fmt::Display for ListView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flat => f.write_str("flat"),
            Self::Grouped => f.write_str("grouped"),
        }
    }
}

impl ListView {
    /// Alterna entre vista plana y agrupada.
    pub fn toggle(self) -> Self {
        match self {
            Self::Flat => Self::Grouped,
            Self::Grouped => Self::Flat,
        }
    }

    /// Etiqueta visible de la vista actual.
    pub fn label(self) -> &'static str {
        match self {
            Self::Flat => "plana",
            Self::Grouped => "agrupada",
        }
    }
}

/// Sección [inference] de la configuración (Fase 4).
///
/// La inferencia lee cabeceras DNS/TLS/HTTP/QUIC y los primeros bytes de cada
/// flujo para poner nombre al tráfico. El payload nunca se persiste. Con
/// `enabled = false` solo quedan etiquetas por servicio de F2, ASN, puerto y
/// proceso.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct InferenceConfig {
    /// Activa el motor de inferencia por defecto (ADR-37).
    pub enabled: bool,
    /// Ruta del fichero `apps.toml` del usuario (admite ~). `None` usa la ruta
    /// por defecto `~/.config/almenara/apps.toml`.
    pub apps_file: Option<String>,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            apps_file: None,
        }
    }
}

impl InferenceConfig {
    /// Ruta efectiva del `apps.toml` del usuario, expandiendo la virgulilla.
    ///
    /// Devuelve `None` si la ruta configurada no es válida (se avisa en la carga).
    pub fn apps_file_path(&self) -> Option<PathBuf> {
        match &self.apps_file {
            Some(ruta) => expand_tilde(ruta).ok(),
            None => Some(config_dir().join(APP_NAME).join("apps.toml")),
        }
    }

    /// Avisos de validación de la sección `[inference]`.
    pub fn warnings(&self) -> Vec<String> {
        let mut avisos = Vec::new();
        if let Some(ruta) = &self.apps_file {
            if expand_tilde(ruta).is_err() {
                avisos.push(format!(
                    "inference.apps_file no es una ruta válida (\"{ruta}\"); se ignora el fichero de apps propias"
                ));
            }
        }
        avisos
    }
}

/// Valores por defecto de [alerts] (§7.14).
pub const DEFAULT_ALERT_RETENTION_DAYS: u32 = 90;
/// Días con datos antes de avisar de lo nuevo (aprendizaje).
pub const DEFAULT_LEARNING_DAYS: u32 = 7;
/// Minutos de puesta al día tras arrancar.
pub const DEFAULT_CATCH_UP_MINUTES: u32 = 10;
/// Horas de deduplicación de una misma alerta.
pub const DEFAULT_DEDUP_HOURS: u32 = 24;
/// Tope de notificaciones de escritorio por minuto.
pub const DEFAULT_MAX_NOTIFICATIONS_PER_MINUTE: u32 = 3;
/// Veces la mediana que dispara «más tráfico de lo habitual».
pub const DEFAULT_TRAFFIC_FACTOR: f64 = 3.0;
/// Días de muestras de la línea base de tráfico.
pub const DEFAULT_BASELINE_DAYS: u32 = 14;
/// Muestras mínimas para evaluar la línea base.
pub const DEFAULT_MIN_DAYS: u32 = 5;
/// Mínimo de bajada por hora (MB de 1 000 000 bytes).
pub const DEFAULT_MIN_MB_DOWN: u64 = 200;
/// Mínimo de subida por hora (MB de 1 000 000 bytes).
pub const DEFAULT_MIN_MB_UP: u64 = 50;
/// Porcentaje de pérdida por minuto que cuenta como malo.
pub const DEFAULT_CAPTURE_DROPS_PERCENT: f64 = 1.0;
/// Minutos seguidos por encima del umbral de pérdidas.
pub const DEFAULT_CAPTURE_DROPS_MINUTES: u32 = 5;

/// Sección [alerts]: motor de alertas de F6 (§7.14).
///
/// La validación es tolerante (nunca aborta el arranque): cada valor fuera de
/// rango se avisa una vez y usa el valor por defecto; las reglas desconocidas se
/// avisan una vez y se descartan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertsConfig {
    /// Motor de alertas encendido. Apagado: no se crean alertas, el contador se
    /// oculta y las guardadas se siguen viendo.
    pub enabled: bool,
    /// Retención de alertas en días (7-730).
    pub retention_days: u32,
    /// Días con datos antes de avisar de lo nuevo (0-30).
    pub learning_days: u32,
    /// Puesta al día al arrancar en minutos (0-60; 0 = sin ella).
    pub catch_up_minutes: u32,
    /// Horas de deduplicación (1-168).
    pub dedup_hours: u32,
    /// Notificaciones de escritorio (solo importantes).
    pub desktop_notifications: bool,
    /// Horario silencioso «HH:MM-HH:MM» en hora local; vacío = sin horario.
    pub quiet_hours: String,
    /// Tope de notificaciones de escritorio por minuto (1-20).
    pub max_notifications_per_minute: u32,
    /// Parámetros de «más tráfico de lo habitual».
    pub traffic_high: TrafficHighConfig,
    /// Parámetros de «pérdidas de captura».
    pub capture_drops: CaptureDropsConfig,
    /// Ajuste de las 16 reglas del catálogo.
    pub rules: RulesConfig,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: DEFAULT_ALERT_RETENTION_DAYS,
            learning_days: DEFAULT_LEARNING_DAYS,
            catch_up_minutes: DEFAULT_CATCH_UP_MINUTES,
            dedup_hours: DEFAULT_DEDUP_HOURS,
            desktop_notifications: true,
            quiet_hours: String::new(),
            max_notifications_per_minute: DEFAULT_MAX_NOTIFICATIONS_PER_MINUTE,
            traffic_high: TrafficHighConfig::default(),
            capture_drops: CaptureDropsConfig::default(),
            rules: RulesConfig::default(),
        }
    }
}

impl AlertsConfig {
    /// Corrige los valores fuera de rango con el valor por defecto y avisa.
    ///
    /// La configuración nunca aborta el arranque (§7.14). También descarta las
    /// reglas desconocidas (con un aviso) y rellena las que faltan.
    pub fn validar(&mut self) -> Vec<String> {
        let mut avisos = Vec::new();
        if !(7..=730).contains(&self.retention_days) {
            avisos.push(format!(
                "[alerts].retention_days = {} no es válido (7-730); se usa {DEFAULT_ALERT_RETENTION_DAYS}",
                self.retention_days
            ));
            self.retention_days = DEFAULT_ALERT_RETENTION_DAYS;
        }
        if self.learning_days > 30 {
            avisos.push(format!(
                "[alerts].learning_days = {} no es válido (0-30); se usa {DEFAULT_LEARNING_DAYS}",
                self.learning_days
            ));
            self.learning_days = DEFAULT_LEARNING_DAYS;
        }
        if self.catch_up_minutes > 60 {
            avisos.push(format!(
                "[alerts].catch_up_minutes = {} no es válido (0-60); se usa {DEFAULT_CATCH_UP_MINUTES}",
                self.catch_up_minutes
            ));
            self.catch_up_minutes = DEFAULT_CATCH_UP_MINUTES;
        }
        if !(1..=168).contains(&self.dedup_hours) {
            avisos.push(format!(
                "[alerts].dedup_hours = {} no es válido (1-168); se usa {DEFAULT_DEDUP_HOURS}",
                self.dedup_hours
            ));
            self.dedup_hours = DEFAULT_DEDUP_HOURS;
        }
        if !(1..=20).contains(&self.max_notifications_per_minute) {
            avisos.push(format!(
                "[alerts].max_notifications_per_minute = {} no es válido (1-20); se usa {DEFAULT_MAX_NOTIFICATIONS_PER_MINUTE}",
                self.max_notifications_per_minute
            ));
            self.max_notifications_per_minute = DEFAULT_MAX_NOTIFICATIONS_PER_MINUTE;
        }
        match crate::alerts::QuietHours::parse(&self.quiet_hours) {
            Ok(_) => {}
            Err(motivo) => {
                avisos.push(format!(
                    "[alerts].quiet_hours = \"{}\" no es válido ({motivo}); se usa sin horario silencioso",
                    self.quiet_hours
                ));
                self.quiet_hours.clear();
            }
        }
        avisos.extend(self.traffic_high.validar(self.max_baseline_days()));
        avisos.extend(self.capture_drops.validar());
        avisos.extend(self.rules.validar());
        avisos
    }

    /// Días máximos de muestras: los de horas del histórico.
    fn max_baseline_days(&self) -> u32 {
        DEFAULT_HOUR_DAYS
    }

    /// Proyección validada al motor de alertas.
    ///
    /// Si la configuración no se ha validado antes, se valida aquí una copia;
    /// así el motor siempre recibe valores en rango.
    pub fn params(&self) -> crate::alerts::AlertsParams {
        let mut copia = self.clone();
        copia.validar();
        let mut rules = BTreeMap::new();
        for regla in crate::alerts::RuleId::ALL {
            rules.insert(regla, copia.rules.setting(regla));
        }
        crate::alerts::AlertsParams {
            enabled: copia.enabled,
            retention_days: copia.retention_days,
            learning_days: copia.learning_days,
            catch_up_minutes: copia.catch_up_minutes,
            dedup_hours: copia.dedup_hours,
            desktop_notifications: copia.desktop_notifications,
            quiet_hours: crate::alerts::QuietHours::parse(&copia.quiet_hours)
                .ok()
                .flatten(),
            max_notifications_per_minute: copia.max_notifications_per_minute,
            traffic_high: crate::alerts::TrafficHighParams {
                factor: copia.traffic_high.factor,
                baseline_days: copia.traffic_high.baseline_days,
                min_days: copia.traffic_high.min_days,
                min_mb_down: copia.traffic_high.min_mb_down,
                min_mb_up: copia.traffic_high.min_mb_up,
            },
            capture_drops: crate::alerts::CaptureDropsParams {
                percent: copia.capture_drops.percent,
                minutes: copia.capture_drops.minutes,
            },
            rules,
        }
    }

    /// Ajuste efectivo de una regla.
    pub fn rule(&self, rule: crate::alerts::RuleId) -> crate::alerts::RuleSetting {
        self.rules.setting(rule)
    }

    /// Guarda en memoria el ajuste de una regla.
    pub fn set_rule(&mut self, rule: crate::alerts::RuleId, setting: &crate::alerts::RuleSetting) {
        self.rules.set(rule, setting);
    }
}

/// Sección [alerts.traffic_high] (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrafficHighConfig {
    /// Veces la mediana que dispara la alerta (1,5-20).
    pub factor: f64,
    /// Días de muestras (7 hasta hour_days del histórico).
    pub baseline_days: u32,
    /// Muestras mínimas para evaluar (3 hasta baseline_days).
    pub min_days: u32,
    /// Mínimo de bajada por hora (MB de 1 000 000 bytes, ≥ 1).
    pub min_mb_down: u64,
    /// Mínimo de subida por hora (MB de 1 000 000 bytes, ≥ 1).
    pub min_mb_up: u64,
}

impl Default for TrafficHighConfig {
    fn default() -> Self {
        Self {
            factor: DEFAULT_TRAFFIC_FACTOR,
            baseline_days: DEFAULT_BASELINE_DAYS,
            min_days: DEFAULT_MIN_DAYS,
            min_mb_down: DEFAULT_MIN_MB_DOWN,
            min_mb_up: DEFAULT_MIN_MB_UP,
        }
    }
}

impl TrafficHighConfig {
    /// Valida los rangos de la sección y avisa de los valores corregidos.
    fn validar(&mut self, max_baseline_days: u32) -> Vec<String> {
        let mut avisos = Vec::new();
        if !(1.5..=20.0).contains(&self.factor) || !self.factor.is_finite() {
            avisos.push(format!(
                "[alerts.traffic_high].factor = {} no es válido (1,5-20); se usa {DEFAULT_TRAFFIC_FACTOR}",
                self.factor
            ));
            self.factor = DEFAULT_TRAFFIC_FACTOR;
        }
        if !(7..=max_baseline_days).contains(&self.baseline_days) {
            avisos.push(format!(
                "[alerts.traffic_high].baseline_days = {} no es válido (7-{max_baseline_days}); se usa {DEFAULT_BASELINE_DAYS}",
                self.baseline_days
            ));
            self.baseline_days = DEFAULT_BASELINE_DAYS.min(max_baseline_days);
        }
        if !(3..=self.baseline_days).contains(&self.min_days) {
            avisos.push(format!(
                "[alerts.traffic_high].min_days = {} no es válido (3-{}); se usa {DEFAULT_MIN_DAYS}",
                self.min_days, self.baseline_days
            ));
            self.min_days = DEFAULT_MIN_DAYS.min(self.baseline_days);
        }
        if self.min_mb_down < 1 {
            avisos.push(format!(
                "[alerts.traffic_high].min_mb_down = {} no es válido (mínimo 1); se usa {DEFAULT_MIN_MB_DOWN}",
                self.min_mb_down
            ));
            self.min_mb_down = DEFAULT_MIN_MB_DOWN;
        }
        if self.min_mb_up < 1 {
            avisos.push(format!(
                "[alerts.traffic_high].min_mb_up = {} no es válido (mínimo 1); se usa {DEFAULT_MIN_MB_UP}",
                self.min_mb_up
            ));
            self.min_mb_up = DEFAULT_MIN_MB_UP;
        }
        avisos
    }
}

/// Sección [alerts.capture_drops] (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureDropsConfig {
    /// Porcentaje perdido en un minuto (0,1-50).
    pub percent: f64,
    /// Minutos seguidos por encima del umbral (1-60).
    pub minutes: u32,
}

impl Default for CaptureDropsConfig {
    fn default() -> Self {
        Self {
            percent: DEFAULT_CAPTURE_DROPS_PERCENT,
            minutes: DEFAULT_CAPTURE_DROPS_MINUTES,
        }
    }
}

impl CaptureDropsConfig {
    /// Valida los rangos de la sección y avisa de los valores corregidos.
    fn validar(&mut self) -> Vec<String> {
        let mut avisos = Vec::new();
        if !(0.1..=50.0).contains(&self.percent) || !self.percent.is_finite() {
            avisos.push(format!(
                "[alerts.capture_drops].percent = {} no es válido (0,1-50); se usa {DEFAULT_CAPTURE_DROPS_PERCENT}",
                self.percent
            ));
            self.percent = DEFAULT_CAPTURE_DROPS_PERCENT;
        }
        if !(1..=60).contains(&self.minutes) {
            avisos.push(format!(
                "[alerts.capture_drops].minutes = {} no es válido (1-60); se usa {DEFAULT_CAPTURE_DROPS_MINUTES}",
                self.minutes
            ));
            self.minutes = DEFAULT_CAPTURE_DROPS_MINUTES;
        }
        avisos
    }
}

/// Ajuste de una regla en [alerts.rules].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    /// Regla activa.
    pub enabled: bool,
    /// Nivel: `important`, `warning` o `info`.
    pub level: String,
    /// Nivel de `device_new` con MAC privada (solo `device_new`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_private_mac: Option<String>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: String::new(),
            level_private_mac: None,
        }
    }
}

impl RuleConfig {
    /// Crea el ajuste por defecto de una regla del catálogo.
    pub fn default_for(rule: crate::alerts::RuleId) -> Self {
        let def = crate::alerts::RuleSetting::default_for(rule);
        Self {
            enabled: def.enabled,
            level: def.level.as_str().to_string(),
            level_private_mac: def
                .level_private_mac
                .map(|nivel| nivel.as_str().to_string()),
        }
    }

    /// Nivel efectivo, usando el de la regla si el campo falta o no es válido.
    fn nivel(&self, por_defecto: crate::alerts::Level) -> crate::alerts::Level {
        if self.level.trim().is_empty() {
            return por_defecto;
        }
        crate::alerts::Level::from_str(self.level.trim()).unwrap_or(por_defecto)
    }
}

/// Sección [alerts.rules]: las 16 reglas del catálogo (ADR-67).
///
/// Las claves desconocidas se capturan en `desconocidas` para avisarlas una vez y
/// descartarlas sin romper la carga (configuración tolerante de F4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    /// Equipo nuevo.
    pub device_new: RuleConfig,
    /// Puerto nuevo.
    pub port_new: RuleConfig,
    /// Cambio de MAC.
    pub mac_changed: RuleConfig,
    /// Cambio de nombre.
    pub name_changed: RuleConfig,
    /// Cambio de SO.
    pub os_changed: RuleConfig,
    /// Cambio de tipo.
    pub type_changed: RuleConfig,
    /// App nueva.
    pub new_app: RuleConfig,
    /// Categoría nueva.
    pub new_category: RuleConfig,
    /// País nuevo.
    pub new_country: RuleConfig,
    /// Organización nueva.
    pub new_org: RuleConfig,
    /// Huella TLS nueva (JA4).
    pub new_ja4: RuleConfig,
    /// Más tráfico de lo habitual.
    pub traffic_high: RuleConfig,
    /// Vigilado ausente o de vuelta.
    pub watched_presence: RuleConfig,
    /// Captura parada.
    pub capture_stopped: RuleConfig,
    /// Pérdidas de captura.
    pub capture_drops: RuleConfig,
    /// Base de datos grande.
    pub db_size: RuleConfig,
    /// Reglas desconocidas: se avisan una vez y se descartan.
    #[serde(flatten)]
    pub desconocidas: BTreeMap<String, toml::Value>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            device_new: RuleConfig::default_for(crate::alerts::RuleId::DeviceNew),
            port_new: RuleConfig::default_for(crate::alerts::RuleId::PortNew),
            mac_changed: RuleConfig::default_for(crate::alerts::RuleId::MacChanged),
            name_changed: RuleConfig::default_for(crate::alerts::RuleId::NameChanged),
            os_changed: RuleConfig::default_for(crate::alerts::RuleId::OsChanged),
            type_changed: RuleConfig::default_for(crate::alerts::RuleId::TypeChanged),
            new_app: RuleConfig::default_for(crate::alerts::RuleId::NewApp),
            new_category: RuleConfig::default_for(crate::alerts::RuleId::NewCategory),
            new_country: RuleConfig::default_for(crate::alerts::RuleId::NewCountry),
            new_org: RuleConfig::default_for(crate::alerts::RuleId::NewOrg),
            new_ja4: RuleConfig::default_for(crate::alerts::RuleId::NewJa4),
            traffic_high: RuleConfig::default_for(crate::alerts::RuleId::TrafficHigh),
            watched_presence: RuleConfig::default_for(crate::alerts::RuleId::WatchedPresence),
            capture_stopped: RuleConfig::default_for(crate::alerts::RuleId::CaptureStopped),
            capture_drops: RuleConfig::default_for(crate::alerts::RuleId::CaptureDrops),
            db_size: RuleConfig::default_for(crate::alerts::RuleId::DbSize),
            desconocidas: BTreeMap::new(),
        }
    }
}

impl RulesConfig {
    /// Referencia al ajuste de una regla del catálogo.
    pub fn config(&self, rule: crate::alerts::RuleId) -> &RuleConfig {
        use crate::alerts::RuleId::*;
        match rule {
            DeviceNew => &self.device_new,
            PortNew => &self.port_new,
            MacChanged => &self.mac_changed,
            NameChanged => &self.name_changed,
            OsChanged => &self.os_changed,
            TypeChanged => &self.type_changed,
            NewApp => &self.new_app,
            NewCategory => &self.new_category,
            NewCountry => &self.new_country,
            NewOrg => &self.new_org,
            NewJa4 => &self.new_ja4,
            TrafficHigh => &self.traffic_high,
            WatchedPresence => &self.watched_presence,
            CaptureStopped => &self.capture_stopped,
            CaptureDrops => &self.capture_drops,
            DbSize => &self.db_size,
        }
    }

    /// Referencia mutable al ajuste de una regla del catálogo.
    fn config_mut(&mut self, rule: crate::alerts::RuleId) -> &mut RuleConfig {
        use crate::alerts::RuleId::*;
        match rule {
            DeviceNew => &mut self.device_new,
            PortNew => &mut self.port_new,
            MacChanged => &mut self.mac_changed,
            NameChanged => &mut self.name_changed,
            OsChanged => &mut self.os_changed,
            TypeChanged => &mut self.type_changed,
            NewApp => &mut self.new_app,
            NewCategory => &mut self.new_category,
            NewCountry => &mut self.new_country,
            NewOrg => &mut self.new_org,
            NewJa4 => &mut self.new_ja4,
            TrafficHigh => &mut self.traffic_high,
            WatchedPresence => &mut self.watched_presence,
            CaptureStopped => &mut self.capture_stopped,
            CaptureDrops => &mut self.capture_drops,
            DbSize => &mut self.db_size,
        }
    }

    /// Ajuste efectivo de una regla (nivel por defecto si falta).
    pub fn setting(&self, rule: crate::alerts::RuleId) -> crate::alerts::RuleSetting {
        let cfg = self.config(rule);
        let por_defecto = crate::alerts::RuleSetting::default_for(rule);
        crate::alerts::RuleSetting {
            enabled: cfg.enabled,
            level: cfg.nivel(por_defecto.level),
            level_private_mac: cfg
                .level_private_mac
                .as_deref()
                .and_then(crate::alerts::Level::from_str),
        }
    }

    /// Guarda el ajuste de una regla.
    pub fn set(&mut self, rule: crate::alerts::RuleId, setting: &crate::alerts::RuleSetting) {
        let cfg = self.config_mut(rule);
        cfg.enabled = setting.enabled;
        cfg.level = setting.level.as_str().to_string();
        cfg.level_private_mac = setting
            .level_private_mac
            .map(|nivel| nivel.as_str().to_string());
    }

    /// Valida niveles y descarta las reglas desconocidas con aviso.
    fn validar(&mut self) -> Vec<String> {
        let mut avisos = Vec::new();
        for nombre in self.desconocidas.keys() {
            avisos.push(format!(
                "[alerts.rules] contiene la regla desconocida \"{nombre}\"; se ignora"
            ));
        }
        self.desconocidas.clear();

        for regla in crate::alerts::RuleId::ALL {
            let por_defecto = crate::alerts::RuleSetting::default_for(regla);
            let cfg = self.config_mut(regla);
            if !cfg.level.trim().is_empty()
                && crate::alerts::Level::from_str(cfg.level.trim()).is_none()
            {
                avisos.push(format!(
                    "[alerts.rules].{} tiene level = \"{}\" no válido; se usa \"{}\"",
                    regla.as_str(),
                    cfg.level,
                    por_defecto.level.as_str()
                ));
                cfg.level = por_defecto.level.as_str().to_string();
            } else if cfg.level.trim().is_empty() {
                cfg.level = por_defecto.level.as_str().to_string();
            }
            if let Some(nivel) = &cfg.level_private_mac {
                if crate::alerts::Level::from_str(nivel.trim()).is_none() {
                    let defecto = por_defecto
                        .level_private_mac
                        .unwrap_or(crate::alerts::Level::Warning);
                    avisos.push(format!(
                        "[alerts.rules].{} tiene level_private_mac = \"{nivel}\" no válido; se usa \"{}\"",
                        regla.as_str(),
                        defecto.as_str()
                    ));
                    cfg.level_private_mac = Some(defecto.as_str().to_string());
                }
            }
            if regla != crate::alerts::RuleId::DeviceNew && cfg.level_private_mac.is_some() {
                avisos.push(format!(
                    "[alerts.rules].{} no admite level_private_mac; se ignora",
                    regla.as_str()
                ));
                cfg.level_private_mac = None;
            }
        }
        avisos
    }
}

/// Guarda si una regla está activa y su nivel desde la vista Reglas de la TUI
/// (§7.14): reescribe `config.toml` completo, como `[ui]` en F2.
///
/// Si el fichero no existe o no se puede leer, parte de los valores por defecto.
pub fn save_rule(
    path: &Path,
    rule: crate::alerts::RuleId,
    setting: &crate::alerts::RuleSetting,
) -> Result<()> {
    let mut config = Config::load_or_default(Some(path)).0;
    config.alerts.set_rule(rule, setting);
    config.save(path)
}

/// Agrupación del ranking de la pestaña Tráfico (Fase 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficGroup {
    /// Rankin por equipo (comportamiento de Fase 3).
    #[default]
    Device,
    /// Ranking por destino (dominio registrable, IP o equipo de la LAN).
    Destination,
    /// Ranking por app del catálogo.
    App,
    /// Ranking por categoría.
    Category,
    /// Ranking por protocolo de aplicación.
    Protocol,
    /// Ranking por proceso local del propio equipo.
    Process,
}

#[allow(dead_code)]
impl TrafficGroup {
    /// Ciclo de agrupaciones de `g` en la pestaña Tráfico.
    pub fn cycle(self) -> Self {
        match self {
            Self::Device => Self::Destination,
            Self::Destination => Self::App,
            Self::App => Self::Category,
            Self::Category => Self::Protocol,
            Self::Protocol => Self::Process,
            Self::Process => Self::Device,
        }
    }

    /// Etiqueta visible de la agrupación.
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

    /// Representación persistida en `[ui].traffic_group`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Destination => "destination",
            Self::App => "app",
            Self::Category => "category",
            Self::Protocol => "protocol",
            Self::Process => "process",
        }
    }

    /// Reconstruye la agrupación desde su representación persistida.
    pub fn from_str(valor: &str) -> Option<Self> {
        match valor.trim().to_ascii_lowercase().as_str() {
            "device" | "equipo" => Some(Self::Device),
            "destination" | "destino" => Some(Self::Destination),
            "app" => Some(Self::App),
            "category" | "categoria" | "categoría" => Some(Self::Category),
            "protocol" | "protocolo" => Some(Self::Protocol),
            "process" | "proceso" => Some(Self::Process),
            _ => None,
        }
    }
}

impl fmt::Display for TrafficGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Ajuste de interfaces: automático o lista explícita de nombres.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InterfacesSetting {
    /// Detectar automáticamente las interfaces activas.
    #[default]
    Auto,
    /// Usar solo las interfaces indicadas.
    Names(Vec<String>),
}

impl fmt::Display for InterfacesSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Names(names) => f.write_str(&names.join(", ")),
        }
    }
}

impl Serialize for InterfacesSetting {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::Names(names) => names.serialize(serializer),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum InterfacesRepr {
    Auto(String),
    Names(Vec<String>),
}

impl<'de> Deserialize<'de> for InterfacesSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        match InterfacesRepr::deserialize(deserializer)? {
            InterfacesRepr::Auto(value) if value == "auto" => Ok(Self::Auto),
            InterfacesRepr::Auto(value) => Err(D::Error::custom(format!(
                "interfaces debe ser \"auto\" o una lista de nombres, no \"{value}\""
            ))),
            InterfacesRepr::Names(names) => {
                if names.is_empty() {
                    Err(D::Error::custom(
                        "interfaces no puede ser una lista vacía; usa \"auto\"",
                    ))
                } else {
                    Ok(Self::Names(names))
                }
            }
        }
    }
}

impl ScanConfig {
    /// Convierte los rangos de esta sección en redes IPv4 validadas.
    pub fn parse_ranges(&self) -> Result<Vec<pnet::ipnetwork::Ipv4Network>> {
        parse_ranges_list(&self.ranges)
    }
}

impl Config {
    /// Ruta por defecto del fichero de configuración.
    pub fn default_path() -> PathBuf {
        config_dir().join(APP_NAME).join("config.toml")
    }

    /// Carga la configuración desde `path` (o la ruta por defecto si es None).
    ///
    /// Si el fichero no existe devuelve los valores por defecto sin error.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => Self::default_path(),
        };

        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(&path)
            .map_err(|err| Error::config_at(&path, format!("no se pudo leer el fichero: {err}")))?;
        let config: Self = toml::from_str(&raw)
            .map_err(|err| Error::config_at(&path, format!("TOML inválido: {err}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Carga la configuración y devuelve avisos en lugar de fallar.
    ///
    /// Devuelve siempre una configuración utilizable junto a la lista de avisos
    /// que debe mostrarse al usuario (por ejemplo en una notificación).
    pub fn load_or_default(path: Option<&Path>) -> (Self, Vec<String>) {
        match Self::load(path) {
            Ok(config) => {
                let (mut config, mut avisos) = config.descartar_lease_paths_inexistentes();
                // [history] se valida campo a campo: un valor inválido se avisa
                // una vez y usa el valor por defecto, sin abortar el arranque.
                avisos.extend(config.history.validar());
                // [alerts] también se valida campo a campo: un valor inválido se
                // avisa una vez y usa el valor por defecto (§7.14).
                avisos.extend(config.alerts.validar());
                avisos.extend(config.warnings());
                // Las claves obsoletas de F3 se avisan una sola vez y se
                // descartan: la inferencia se rige por [inference].enabled.
                config.limpiar_claves_obsoletas();
                (config, avisos)
            }
            Err(err) => (
                Self::default(),
                vec![format!(
                    "Configuración no válida, se usan valores por defecto: {err}"
                )],
            ),
        }
    }

    /// Descarta las claves obsoletas de F3 ya avisadas.
    fn limpiar_claves_obsoletas(&mut self) {
        self.capture.inspect_payload = None;
        self.capture.dns_attribution = None;
        self.capture.sni_attribution = None;
    }

    /// Avisos de claves obsoletas y de secciones nuevas que no impiden arrancar.
    pub fn warnings(&self) -> Vec<String> {
        let mut avisos = Vec::new();
        let obsoletas: &[(&str, &Option<bool>)] = &[
            ("inspect_payload", &self.capture.inspect_payload),
            ("dns_attribution", &self.capture.dns_attribution),
            ("sni_attribution", &self.capture.sni_attribution),
        ];
        let presentes: Vec<&str> = obsoletas
            .iter()
            .filter(|(_, valor)| valor.is_some())
            .map(|(nombre, _)| *nombre)
            .collect();
        if !presentes.is_empty() {
            avisos.push(format!(
                "Las claves [capture] {} ya no se usan: la inferencia se controla con [inference].enabled",
                presentes.join(", ")
            ));
        }
        avisos.extend(self.inference.warnings());
        avisos
    }

    /// Descarta las rutas manuales de leases que no existen y devuelve avisos.
    fn descartar_lease_paths_inexistentes(mut self) -> (Self, Vec<String>) {
        let mut avisos = Vec::new();
        let rutas = std::mem::take(&mut self.scan.dhcp_lease_paths);
        self.scan.dhcp_lease_paths = rutas
            .into_iter()
            .filter(|ruta| {
                let existe = expand_tilde(ruta)
                    .map(|expandida| expandida.exists())
                    .unwrap_or(false);
                if !existe {
                    avisos.push(format!(
                        "scan.dhcp_lease_paths: se descarta la ruta inexistente {ruta}"
                    ));
                }
                existe
            })
            .collect();
        (self, avisos)
    }

    /// Valida los valores de configuración.
    pub fn validate(&self) -> Result<()> {
        if self.scan.interval_s < MIN_INTERVAL_S {
            return Err(Error::Config(format!(
                "scan.interval_s debe ser mayor o igual que {MIN_INTERVAL_S} (valor actual: {})",
                self.scan.interval_s
            )));
        }
        if !(MIN_ICMP_TIMEOUT_MS..=MAX_ICMP_TIMEOUT_MS).contains(&self.scan.icmp_timeout_ms) {
            return Err(Error::Config(format!(
                "scan.icmp_timeout_ms debe estar entre {MIN_ICMP_TIMEOUT_MS} y {MAX_ICMP_TIMEOUT_MS} ms (valor actual: {})",
                self.scan.icmp_timeout_ms
            )));
        }
        if self.scan.offline_after_cycles == 0 {
            return Err(Error::Config(
                "scan.offline_after_cycles debe ser mayor que 0".to_string(),
            ));
        }
        if self.storage.events_retention_days == 0 {
            return Err(Error::Config(
                "storage.events_retention_days debe ser mayor que 0".to_string(),
            ));
        }

        self.parse_ranges()?;

        if self.scan.top_ports.len() > MAX_TOP_PORTS {
            return Err(Error::Config(format!(
                "scan.top_ports admite como máximo {MAX_TOP_PORTS} puertos (valor actual: {})",
                self.scan.top_ports.len()
            )));
        }
        let mut vistos = std::collections::HashSet::new();
        for puerto in &self.scan.top_ports {
            if *puerto == 0 {
                return Err(Error::Config(
                    "scan.top_ports no admite el puerto 0; los puertos válidos van de 1 a 65535"
                        .to_string(),
                ));
            }
            if !vistos.insert(*puerto) {
                return Err(Error::Config(format!(
                    "scan.top_ports contiene el puerto duplicado {puerto}"
                )));
            }
        }

        if let InterfacesSetting::Names(names) = &self.scan.interfaces {
            if names.iter().any(|name| name.trim().is_empty()) {
                return Err(Error::Config(
                    "scan.interfaces contiene un nombre de interfaz vacío".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Convierte los rangos configurados en redes IPv4 validadas.
    pub fn parse_ranges(&self) -> Result<Vec<pnet::ipnetwork::Ipv4Network>> {
        parse_ranges_list(&self.scan.ranges)
    }

    /// Ruta absoluta de la base de datos, expandiendo la virgulilla.
    pub fn database_path(&self) -> Result<PathBuf> {
        expand_tilde(&self.storage.db_path)
    }

    /// Directorio de logs (estado del usuario), expandible.
    pub fn log_dir() -> Result<PathBuf> {
        let base = state_dir()?;
        Ok(base.join(APP_NAME).join("log"))
    }

    /// Escribe una plantilla de configuración si el fichero no existe.
    ///
    /// Devuelve la ruta final y un aviso cuando no se pudo escribir (por ejemplo
    /// por permisos), sin impedir el arranque.
    pub fn ensure_default_file(path: Option<&Path>) -> (PathBuf, Option<String>) {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => Self::default_path(),
        };
        if path.exists() {
            return (path, None);
        }
        let aviso = match write_default_file(&path) {
            Ok(()) => None,
            Err(err) => Some(format!(
                "No se pudo escribir la configuración por defecto en {}: {err}",
                path.display()
            )),
        };
        (path, aviso)
    }

    /// Serializa la configuración activa a TOML (para la pestaña Config).
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self)
            .unwrap_or_else(|err| format!("# No se pudo serializar la configuración: {err}"))
    }

    /// Guarda la configuración completa en path (la usa el toggle de vista).
    ///
    /// El fichero se reescribe completo porque es pequeño; los comentarios
    /// manuales del usuario se pierden, igual que en la plantilla inicial.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent().filter(|padre| !padre.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|err| {
                Error::config_at(path, format!("no se pudo crear el directorio: {err}"))
            })?;
        }
        let contenido = format!(
            "# Configuración de Almenara (Fase 4)\n# Los comentarios se pierden si la aplicación reescribe el fichero.\n\n{}",
            self.to_toml()
        );
        std::fs::write(path, contenido)
            .map_err(|err| Error::config_at(path, format!("no se pudo escribir: {err}")))
    }
}

fn parse_ranges_list(rangos: &[String]) -> Result<Vec<pnet::ipnetwork::Ipv4Network>> {
    let mut networks = Vec::with_capacity(rangos.len());
    for raw in rangos {
        let network: pnet::ipnetwork::Ipv4Network = raw.trim().parse().map_err(|_| {
            Error::Config(format!(
                "scan.ranges contiene un CIDR IPv4 no válido: \"{raw}\""
            ))
        })?;
        let hosts = 1u64 << (32 - u32::from(network.prefix()));
        if hosts > u64::from(MAX_RANGE_HOSTS) {
            return Err(Error::Config(format!(
                "el rango \"{raw}\" tiene {hosts} direcciones; el máximo en Fase 1 es {MAX_RANGE_HOSTS}"
            )));
        }
        networks.push(network);
    }
    Ok(networks)
}

fn write_default_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            Error::config_at(path, format!("no se pudo crear el directorio: {err}"))
        })?;
    }
    let mut content = String::from(
        "# Configuración de Almenara (Fase 4)\n# Los comentarios se pierden si la aplicación reescribe el fichero.\n\n",
    );
    content.push_str(&Config::default().to_toml());
    std::fs::write(path, content)
        .map_err(|err| Error::config_at(path, format!("no se pudo escribir: {err}")))
}

/// Directorio de configuración del usuario (`~/.config` en Linux).
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Directorio de estado del usuario (`~/.local/state` en Linux).
pub fn state_dir() -> Result<PathBuf> {
    dirs::state_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".local/state")))
        .ok_or_else(|| {
            Error::InvalidPath(
                "no se pudo determinar el directorio de estado del usuario".to_string(),
            )
        })
}

/// Expande una ruta que empieza por `~` usando el HOME del usuario.
pub fn expand_tilde(raw: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        Error::InvalidPath(format!(
            "no se pudo determinar el directorio personal para \"{raw}\""
        ))
    })?;
    expand_tilde_with_home(raw, &home)
}

fn expand_tilde_with_home(raw: &str, home: &Path) -> Result<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::InvalidPath(
            "la ruta configurada está vacía".to_string(),
        ));
    }
    if raw == "~" {
        return Ok(home.to_path_buf());
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return Ok(home.join(rest));
    }
    if raw.starts_with('~') {
        return Err(Error::InvalidPath(format!(
            "solo se admite ~ o ~/ al inicio de la ruta: \"{raw}\""
        )));
    }
    Ok(PathBuf::from(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn defaults_coherentes_con_la_especificacion() {
        let config = Config::default();
        assert_eq!(config.scan.interfaces, InterfacesSetting::Auto);
        assert_eq!(config.scan.interval_s, 60);
        assert_eq!(config.scan.icmp_timeout_ms, 500);
        assert_eq!(config.scan.offline_after_cycles, 3);
        assert_eq!(config.storage.db_path, "~/.local/share/almenara/data.db");
        assert_eq!(config.storage.events_retention_days, 90);
        assert!(!config.ui.no_color);
        assert!(!config.scan.passive_only);
        assert_eq!(config.scan.top_ports, DEFAULT_TOP_PORTS.to_vec());
        assert_eq!(config.scan.top_ports.len(), 19);
        assert!(config.scan.dhcp_lease_paths.is_empty());
        assert_eq!(config.ui.list_view, ListView::Flat);
        assert!(config.capture.enabled);
        assert_eq!(config.capture.filter, "");
        assert_eq!(config.capture.inspect_payload, None);
        assert_eq!(config.capture.max_pps, 0);
        assert_eq!(config.capture.dns_attribution, None);
        assert_eq!(config.capture.sni_attribution, None);
        assert!(!config.capture.has_filter());
        assert_eq!(config.capture.filter_label(), "(ninguno)");
        // [history] con los valores por defecto de §7.12.
        assert!(config.history.enabled);
        assert_eq!(config.history.minute_days, 2);
        assert_eq!(config.history.hour_days, 90);
        assert_eq!(config.history.day_days, 730);
        assert_eq!(config.history.destination_days, 30);
        assert_eq!(config.history.top_keys, 20);
        assert_eq!(config.history.max_db_mb, 1024);
        assert_eq!(
            config.history.retention(),
            crate::history::Retention {
                minute_days: 2,
                hour_days: 90,
                day_days: 730,
                destination_days: 30,
            }
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn la_plantilla_incluye_la_seccion_history() {
        let plantilla = Config::default().to_toml();
        assert!(
            plantilla.contains("[history]"),
            "falta [history]: {plantilla}"
        );
        assert!(plantilla.contains("minute_days = 2"));
        assert!(plantilla.contains("hour_days = 90"));
        assert!(plantilla.contains("day_days = 730"));
        assert!(plantilla.contains("destination_days = 30"));
        assert!(plantilla.contains("top_keys = 20"));
        assert!(plantilla.contains("max_db_mb = 1024"));
    }

    #[test]
    fn los_valores_invalidos_de_history_avisan_y_usan_el_valor_por_defecto() {
        let mut config = Config::default();
        config.history.hour_days = 2;
        config.history.minute_days = 0;
        config.history.day_days = 10;
        config.history.top_keys = 1000;
        config.history.max_db_mb = 1;
        config.history.destination_days = 500;
        let avisos = config.history.validar();
        assert_eq!(avisos.len(), 6, "un aviso por valor inválido: {avisos:?}");
        assert_eq!(config.history.hour_days, DEFAULT_HOUR_DAYS);
        assert_eq!(config.history.minute_days, DEFAULT_MINUTE_DAYS);
        assert_eq!(config.history.day_days, DEFAULT_DAY_DAYS);
        assert_eq!(config.history.top_keys, DEFAULT_TOP_KEYS);
        assert_eq!(config.history.max_db_mb, DEFAULT_MAX_DB_MB);
        assert_eq!(config.history.destination_days, DEFAULT_DESTINATION_DAYS);
        // La configuración nunca aborta: validate() no falla por [history].
        assert!(config.validate().is_ok());
    }

    #[test]
    fn destination_days_no_puede_superar_las_horas_validas() {
        let mut config = Config::default();
        config.history.hour_days = 7;
        config.history.destination_days = 30;
        let avisos = config.history.validar();
        assert_eq!(avisos.len(), 1);
        assert_eq!(config.history.destination_days, 7);
    }

    #[test]
    fn load_or_default_avisa_de_history_invalido() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[history]\nhour_days = 2\n").unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(config.history.hour_days, DEFAULT_HOUR_DAYS);
        assert!(
            avisos.iter().any(|aviso| aviso.contains("hour_days")),
            "debe avisar una vez: {avisos:?}"
        );
    }

    #[test]
    fn parsea_toml_completo() {
        let raw = r#"
[scan]
interfaces = ["eth0"]
ranges = ["192.168.1.0/24"]
interval_s = 30
icmp_timeout_ms = 200
offline_after_cycles = 2

[storage]
db_path = "~/data.db"
events_retention_days = 30

[ui]
theme = "default"
no_color = true
"#;
        let config: Config = toml::from_str(raw).expect("TOML válido");
        config.validate().expect("configuración válida");
        assert_eq!(
            config.scan.interfaces,
            InterfacesSetting::Names(vec!["eth0".to_string()])
        );
        assert_eq!(config.scan.ranges, vec!["192.168.1.0/24".to_string()]);
        assert!(config.ui.no_color);
    }

    #[test]
    fn interfaces_auto_como_cadena() {
        let config: Config = toml::from_str("[scan]\ninterfaces = \"auto\"\n").unwrap();
        assert_eq!(config.scan.interfaces, InterfacesSetting::Auto);
    }

    #[test]
    fn interfaces_cadena_desconocida_falla() {
        let err = toml::from_str::<Config>("[scan]\ninterfaces = \"eth0\"\n").unwrap_err();
        assert!(err.to_string().contains("auto"));
    }

    #[test]
    fn valida_intervalo_minimo() {
        let mut config = Config::default();
        config.scan.interval_s = 5;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("interval_s"));
    }

    #[test]
    fn valida_timeout_icmp() {
        let mut config = Config::default();
        config.scan.icmp_timeout_ms = 50;
        assert!(config.validate().is_err());
        config.scan.icmp_timeout_ms = 6000;
        assert!(config.validate().is_err());
        config.scan.icmp_timeout_ms = 100;
        assert!(config.validate().is_ok());
        config.scan.icmp_timeout_ms = 5000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn valida_ciclos_offline() {
        let mut config = Config::default();
        config.scan.offline_after_cycles = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn valida_rangos_cidr_y_tamano() {
        let mut config = Config::default();
        config.scan.ranges = vec!["192.168.1.0/24".to_string()];
        assert_eq!(config.parse_ranges().unwrap().len(), 1);

        config.scan.ranges = vec!["192.168.1.0/16".to_string()];
        let err = config.parse_ranges().unwrap_err().to_string();
        assert!(err.contains("máximo"));

        config.scan.ranges = vec!["192.168.1.0/33".to_string()];
        assert!(config.parse_ranges().is_err());
        config.scan.ranges = vec!["no-es-una-red".to_string()];
        assert!(config.parse_ranges().is_err());
        config.scan.ranges = vec!["2001:db8::/64".to_string()];
        assert!(config.parse_ranges().is_err());
    }

    #[test]
    fn expande_virgulilla() {
        let home = Path::new("/home/prueba");
        assert_eq!(
            expand_tilde_with_home("~/x.db", home).unwrap(),
            home.join("x.db")
        );
        assert_eq!(expand_tilde_with_home("~", home).unwrap(), home);
        assert_eq!(
            expand_tilde_with_home("/tmp/abs.db", home).unwrap(),
            PathBuf::from("/tmp/abs.db")
        );
        assert!(expand_tilde_with_home("~otro/x", home).is_err());
        assert!(expand_tilde_with_home("", home).is_err());
    }

    #[test]
    fn load_inexistente_devuelve_defaults() {
        let path = Path::new("/ruta/que/no/existe/almenara.toml");
        let config = Config::load(Some(path)).expect("no debe fallar");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn load_toml_invalido_devuelve_aviso() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "[scan]").unwrap();
        writeln!(file, "interval_s = 1").unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(config, Config::default());
        assert_eq!(avisos.len(), 1);
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(config.scan.interval_s, DEFAULT_INTERVAL_S);
        assert!(!avisos[0].is_empty());
    }

    #[test]
    fn ensure_default_file_escribe_plantilla() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config.toml");
        let (ruta, aviso) = Config::ensure_default_file(Some(&path));
        assert_eq!(ruta, path);
        assert!(aviso.is_none());
        assert!(path.exists());
        let config = Config::load(Some(&path)).expect("plantilla válida");
        assert_eq!(config, Config::default());
        // La segunda vez no reescribe ni falla.
        let (_, aviso) = Config::ensure_default_file(Some(&path));
        assert!(aviso.is_none());
    }

    #[test]
    fn to_toml_contiene_secciones() {
        let toml = Config::default().to_toml();
        assert!(toml.contains("[scan]"));
        assert!(toml.contains("[capture]"));
        assert!(toml.contains("[storage]"));
        assert!(toml.contains("[ui]"));
        assert!(
            !toml.contains("inspect_payload"),
            "clave obsoleta fuera de la plantilla"
        );
        assert!(toml.contains("max_pps = 0"));
        assert!(!toml.contains("dns_attribution"));
        assert!(!toml.contains("sni_attribution"));
        assert!(toml.contains("[inference]"));
        assert!(toml.contains("traffic_group = \"device\""));
        assert!(toml.contains("passive_only = false"));
        assert!(toml.contains("top_ports"));
        assert!(toml.contains("dhcp_lease_paths"));
        assert!(toml.contains("list_view = \"flat\""));
    }

    #[test]
    fn valida_top_ports_unicos_y_limite() {
        let mut config = Config::default();
        config.scan.top_ports = vec![22, 22];
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("duplicado"), "{err}");

        config.scan.top_ports = vec![0];
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("puerto 0"));

        config.scan.top_ports = (1..=65).collect();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("máximo"));

        config.scan.top_ports = (1..=64).collect();
        assert!(config.validate().is_ok());

        config.scan.top_ports = Vec::new();
        assert!(config.validate().is_ok(), "una lista vacía es válida");
    }

    #[test]
    fn parsea_toml_con_claves_de_fase_2() {
        let raw = r#"
[scan]
passive_only = true
top_ports = [22, 80, 443]
dhcp_lease_paths = ["/tmp/leases"]

[ui]
list_view = "grouped"
"#;
        let config: Config = toml::from_str(raw).expect("TOML válido");
        config.validate().expect("configuración válida");
        assert!(config.scan.passive_only);
        assert_eq!(config.scan.top_ports, vec![22, 80, 443]);
        assert_eq!(
            config.scan.dhcp_lease_paths,
            vec!["/tmp/leases".to_string()]
        );
        assert_eq!(config.ui.list_view, ListView::Grouped);
    }

    #[test]
    fn list_view_invalido_usa_defaults_con_aviso() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[ui]\nlist_view = \"cuadricula\"\n").unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(config.ui.list_view, ListView::Flat);
        assert_eq!(avisos.len(), 1);
    }

    #[test]
    fn rutas_de_leases_inexistentes_se_descartan_con_aviso() {
        let dir = tempfile::tempdir().unwrap();
        let existente = dir.path().join("leases.txt");
        std::fs::write(&existente, "1.2.3.4").unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            format!(
                "[scan]\ndhcp_lease_paths = [\"{}\", \"/ruta/que/no/existe\"]\n",
                existente.display()
            ),
        )
        .unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(
            config.scan.dhcp_lease_paths,
            vec![existente.display().to_string()]
        );
        assert_eq!(avisos.len(), 1);
        assert!(avisos[0].contains("/ruta/que/no/existe"));
    }

    #[test]
    fn save_escribe_y_recarga_la_configuracion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config.toml");
        let mut config = Config::default();
        config.scan.passive_only = true;
        config.ui.list_view = ListView::Grouped;
        config.save(&path).expect("guardar configuración");
        let recargada = Config::load(Some(&path)).expect("recargar configuración");
        assert_eq!(recargada, config);
        assert_eq!(recargada.ui.list_view, ListView::Grouped);
        assert!(recargada.scan.passive_only);
    }

    #[test]
    fn list_view_alterna_y_tiene_etiqueta() {
        assert_eq!(ListView::Flat.toggle(), ListView::Grouped);
        assert_eq!(ListView::Grouped.toggle(), ListView::Flat);
        assert_eq!(ListView::Flat.label(), "plana");
        assert_eq!(ListView::Grouped.to_string(), "grouped");
    }

    #[test]
    fn parsea_toml_con_claves_de_fase_3() {
        let raw = r#"
[capture]
enabled = false
filter = "not port 22"
inspect_payload = true
max_pps = 5000
dns_attribution = false
sni_attribution = false
"#;
        let config: Config = toml::from_str(raw).expect("TOML válido");
        config.validate().expect("configuración válida");
        assert!(!config.capture.enabled);
        assert_eq!(config.capture.filter, "not port 22");
        assert_eq!(config.capture.inspect_payload, Some(true));
        assert_eq!(config.capture.max_pps, 5000);
        assert_eq!(config.capture.dns_attribution, Some(false));
        assert_eq!(config.capture.sni_attribution, Some(false));
        assert!(config.capture.has_filter());
        assert_eq!(config.capture.filter_label(), "not port 22");
    }

    #[test]
    fn capture_max_pps_negativo_usa_defaults_con_aviso() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[capture]\nmax_pps = -1\n").unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(config, Config::default());
        assert_eq!(avisos.len(), 1);
        assert!(avisos[0].contains("Configuración no válida"));
    }

    #[test]
    fn capture_se_guarda_y_recarga() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        config.capture.enabled = false;
        config.capture.filter = "tcp and port 443".to_string();
        config.capture.max_pps = 1000;
        config.save(&path).expect("guardar configuración");
        let recargada = Config::load(Some(&path)).expect("recargar configuración");
        assert_eq!(recargada, config);
        assert_eq!(recargada.capture.filter_label(), "tcp and port 443");
    }

    #[test]
    fn claves_obsoletas_de_fase_3_avisan_una_vez_y_se_ignoran() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[capture]\ninspect_payload = true\ndns_attribution = false\nsni_attribution = true\n\n[inference]\nenabled = false\n",
        )
        .unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert!(!config.inference.enabled, "manda [inference].enabled");
        assert_eq!(config.capture.inspect_payload, None);
        assert_eq!(config.capture.dns_attribution, None);
        assert_eq!(config.capture.sni_attribution, None);
        let obsoletas: Vec<&String> = avisos
            .iter()
            .filter(|aviso| aviso.contains("[inference].enabled"))
            .collect();
        assert_eq!(obsoletas.len(), 1, "un único aviso: {avisos:?}");
        assert!(obsoletas[0].contains("inspect_payload"));
        assert!(obsoletas[0].contains("dns_attribution"));
        assert!(obsoletas[0].contains("sni_attribution"));
    }

    #[test]
    fn traffic_group_invalido_usa_device_con_aviso() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[ui]\ntraffic_group = \"cuadricula\"\n").unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(config.ui.traffic_group, TrafficGroup::Device);
        assert_eq!(avisos.len(), 1);
        assert!(avisos[0].contains("Configuración no válida"));
    }

    #[test]
    fn inference_invalida_usa_defaults_con_aviso() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[inference]\nenabled = \"sí\"\n").unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert!(config.inference.enabled);
        assert_eq!(avisos.len(), 1);
        assert!(avisos[0].contains("Configuración no válida"));
    }

    #[test]
    fn defaults_de_inference_y_traffic_group() {
        let config = Config::default();
        assert!(config.inference.enabled);
        assert_eq!(config.inference.apps_file, None);
        assert_eq!(config.ui.traffic_group, TrafficGroup::Device);
        assert_eq!(TrafficGroup::Device.cycle(), TrafficGroup::Destination);
        assert_eq!(TrafficGroup::from_str("app"), Some(TrafficGroup::App));
        let ruta = config
            .inference
            .apps_file_path()
            .expect("ruta de apps por defecto");
        assert!(ruta.ends_with("apps.toml"));
    }

    #[test]
    fn apps_file_invalido_avisa() {
        let mut config = Config::default();
        config.inference.apps_file = Some("~otro/apps.toml".to_string());
        let avisos = config.warnings();
        assert_eq!(avisos.len(), 1);
        assert!(avisos[0].contains("apps_file"));
    }

    #[test]
    fn la_configuracion_por_defecto_incluye_alerts_completa() {
        let config = Config::default();
        assert!(config.alerts.enabled);
        assert_eq!(config.alerts.retention_days, 90);
        assert_eq!(config.alerts.learning_days, 7);
        assert_eq!(config.alerts.catch_up_minutes, 10);
        assert_eq!(config.alerts.dedup_hours, 24);
        assert!(config.alerts.desktop_notifications);
        assert_eq!(config.alerts.quiet_hours, "");
        assert_eq!(config.alerts.max_notifications_per_minute, 3);
        assert_eq!(config.alerts.traffic_high.factor, 3.0);
        assert_eq!(config.alerts.traffic_high.baseline_days, 14);
        assert_eq!(config.alerts.traffic_high.min_days, 5);
        assert_eq!(config.alerts.capture_drops.percent, 1.0);
        assert_eq!(config.alerts.capture_drops.minutes, 5);
        assert!(
            config
                .alerts
                .rules
                .setting(crate::alerts::RuleId::ALL[0])
                .enabled
        );
        let toml = config.to_toml();
        assert!(toml.contains("[alerts]"), "{toml}");
        // El serializador TOML escribe cada regla como tabla propia; es
        // semánticamente equivalente a la tabla en línea del §7.14 y se recarga igual.
        assert!(
            toml.contains("[alerts.rules.device_new]") || toml.contains("device_new"),
            "{toml}"
        );
        assert!(toml.contains("device_new"), "{toml}");
        assert!(toml.contains("[alerts.traffic_high]"), "{toml}");
        assert!(toml.contains("[alerts.capture_drops]"), "{toml}");
    }

    #[test]
    fn alerts_validacion_tolerante_usa_el_valor_por_defecto() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[alerts]\nretention_days = 3\nlearning_days = 99\ndedup_hours = 0\nmax_notifications_per_minute = 500\nquiet_hours = \"25:00-08:00\"\n\n[alerts.traffic_high]\nfactor = 0.0\nmin_days = 99\n",
        )
        .unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert_eq!(config.alerts.retention_days, 90);
        assert_eq!(config.alerts.learning_days, 7);
        assert_eq!(config.alerts.dedup_hours, 24);
        assert_eq!(config.alerts.max_notifications_per_minute, 3);
        assert_eq!(config.alerts.quiet_hours, "");
        assert_eq!(config.alerts.traffic_high.factor, 3.0);
        assert_eq!(config.alerts.traffic_high.min_days, 5);
        assert!(avisos.iter().any(|aviso| aviso.contains("retention_days")));
        assert!(avisos.iter().any(|aviso| aviso.contains("factor")));
        assert!(avisos.iter().any(|aviso| aviso.contains("quiet_hours")));
    }

    #[test]
    fn alerts_reglas_desconocidas_se_avisan_y_se_ignoran() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[alerts.rules]\nregla_inventada = { enabled = false }\nport_new = { enabled = false, level = \"warning\" }\n",
        )
        .unwrap();
        let (config, avisos) = Config::load_or_default(Some(&path));
        assert!(!config.alerts.rules.port_new.enabled);
        assert_eq!(config.alerts.rules.port_new.level, "warning");
        assert_eq!(
            config.alerts.rule(crate::alerts::RuleId::PortNew).level,
            crate::alerts::Level::Warning
        );
        // Las reglas que faltan usan sus valores por defecto.
        assert_eq!(
            config.alerts.rule(crate::alerts::RuleId::DeviceNew).level,
            crate::alerts::Level::Important
        );
        assert!(avisos.iter().any(|aviso| aviso.contains("regla_inventada")));
    }

    #[test]
    fn alerts_params_proyecta_la_configuracion() {
        let mut config = Config::default();
        config.alerts.enabled = false;
        config.alerts.quiet_hours = "23:00-08:00".to_string();
        config.alerts.rules.new_app.enabled = false;
        let params = config.alerts.params();
        assert!(!params.enabled);
        assert_eq!(params.retention_days, 90);
        assert_eq!(params.learning_days, 7);
        assert!(!params.rule(crate::alerts::RuleId::NewApp).enabled);
        assert_eq!(
            params
                .rule(crate::alerts::RuleId::DeviceNew)
                .level_private_mac,
            Some(crate::alerts::Level::Warning)
        );
        assert_eq!(params.rules.len(), 16);
    }

    #[test]
    fn save_rule_reescribe_config_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut ajuste = crate::alerts::RuleSetting::default_for(crate::alerts::RuleId::NewOrg);
        ajuste.enabled = false;
        ajuste.level = crate::alerts::Level::Warning;
        super::save_rule(&path, crate::alerts::RuleId::NewOrg, &ajuste).expect("guardar regla");
        let recargada = Config::load(Some(&path)).expect("recargar");
        assert!(!recargada.alerts.rules.new_org.enabled);
        assert_eq!(recargada.alerts.rules.new_org.level, "warning");
        assert_eq!(recargada.alerts.rule(crate::alerts::RuleId::NewOrg), ajuste);
    }

    #[test]
    fn save_rule_conserva_el_resto_de_la_configuracion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::default();
        config.scan.passive_only = true;
        config.alerts.quiet_hours = "23:00-08:00".to_string();
        config.save(&path).expect("guardar configuración");
        let mut ajuste = crate::alerts::RuleSetting::default_for(crate::alerts::RuleId::DbSize);
        ajuste.level = crate::alerts::Level::Important;
        super::save_rule(&path, crate::alerts::RuleId::DbSize, &ajuste).expect("guardar regla");
        let recargada = Config::load(Some(&path)).expect("recargar");
        assert!(recargada.scan.passive_only);
        assert_eq!(recargada.alerts.quiet_hours, "23:00-08:00");
        assert_eq!(
            recargada.alerts.rule(crate::alerts::RuleId::DbSize).level,
            crate::alerts::Level::Important
        );
    }
}
