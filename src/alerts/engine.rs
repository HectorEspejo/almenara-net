//! Motor de alertas: señales → acciones (ADR-68).
//!
//! Implementación a cargo del equipo del motor; este archivo define el contrato
//! público (tipos y firmas) que consumen el repositorio y el hilo de la TUI.
//!
//! El motor es **puro**: no abre la base de datos, no conoce la TUI y no escribe
//! nada. Recibe señales en vivo (eventos, inventario, horas cerradas y salud) y
//! devuelve las acciones que el hilo de la TUI aplica (§4.1, §7.5–§7.9). El
//! único acceso al exterior son los relojes del kernel de la detección de
//! suspensión, que vive en `suspend`.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};

use super::policy::{texto_retenidas, NotifyDecision, NotifyPolicy};
use super::{
    AlertRule, AlertText, AlertsParams, Baseline, CaptureHealth, DbSize, EventKind, EventSignal,
    HealthSample, HourClosedSignal, Level, RuleId, RuleSetting, SeenSignal, Signal, Subject,
    SubjectInfo, BODY_MAX, TITLE_MAX,
};
use crate::history::{clave_especial, SeenKind};

/// Tiempo máximo que una inserción pendiente bloquea su clave de deduplicación.
///
/// La TUI reintenta la acción cada minuto; si nunca lo consigue (la acción se
/// descarta), la clave se libera para no perder alertas futuras. El margen
/// cubre de sobra la puesta al día (10 min) para que un fallo transitorio no
/// impida que su id acabe en el resumen.
const PENDIENTE_MAX: Duration = Duration::from_secs(15 * 60);

/// Clave de deduplicación de una alerta (§7.5): regla, sujeto, equipo y clave.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DedupKey {
    /// Regla que la produce.
    pub rule: RuleId,
    /// Sujeto (equipo, propio equipo, red o Almenara).
    pub subject: Subject,
    /// Clave de la regla (app, país, `22/tcp`, `down`, `gone`…); vacía si no aplica.
    pub key: String,
}

impl DedupKey {
    /// Construye la clave de deduplicación.
    pub fn new(rule: RuleId, subject: Subject, key: impl Into<String>) -> Self {
        Self {
            rule,
            subject,
            key: key.into(),
        }
    }
}

/// Alerta lista para insertar (`Repo::insert_alert`) o para el resumen.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAlert {
    /// Regla que la crea (o `catch_up` en el resumen de la puesta al día).
    pub rule: AlertRule,
    /// Nivel efectivo.
    pub level: Level,
    /// Sujeto.
    pub subject: Subject,
    /// DEVICES.id si el sujeto es un equipo.
    pub device_id: Option<i64>,
    /// Clave de la regla.
    pub key: String,
    /// Título corto ya compuesto y saneado.
    pub title: String,
    /// Nombre del sujeto al crear la alerta.
    pub subject_label: String,
    /// El porqué (§7.1), JSON saneado.
    pub details: Value,
    /// DEVICE_EVENTS.id de origen, si lo hay.
    pub event_id: Option<i64>,
}

impl NewAlert {
    /// Clave de deduplicación de esta alerta (None para el resumen `catch_up`).
    pub fn dedup_key(&self) -> Option<DedupKey> {
        self.rule
            .rule_id()
            .map(|regla| DedupKey::new(regla, self.subject, self.key.clone()))
    }
}

/// Notificación de escritorio ya compuesta (§7.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// Título: «Almenara · <regla>».
    pub summary: String,
    /// Cuerpo saneado y escapado (≤ 200 caracteres).
    pub body: String,
}

/// Acción que el hilo de la TUI debe aplicar (ADR-68).
#[derive(Debug, Clone, PartialEq)]
pub enum AlertAction {
    /// Crear una alerta; `notify` si la política decide notificarla.
    Insert {
        /// Alerta a crear.
        alert: NewAlert,
        /// Notificación de escritorio, si toca.
        notify: Option<Notice>,
    },
    /// Crear el resumen de la puesta al día y agrupar las alertas indicadas.
    InsertSummary {
        /// Alerta resumen.
        alert: NewAlert,
        /// Ids de las alertas agrupadas.
        grouped: Vec<i64>,
        /// Notificación de escritorio del resumen, si toca.
        notify: Option<Notice>,
    },
    /// Repetir una alerta existente dentro del plazo de deduplicación.
    Repeat {
        /// Id de la alerta.
        id: i64,
        /// Momento de la repetición.
        at: SystemTime,
        /// Detalles nuevos (para el caso de `traffic_high`, el valor mayor).
        details: Value,
        /// Reactivar una alerta de condición resuelta.
        reactivate: bool,
    },
    /// Resolver una alerta de condición.
    Resolve {
        /// Id de la alerta.
        id: i64,
        /// Momento de la resolución.
        at: SystemTime,
    },
    /// Notificación suelta (retenidas por el tope, §7.2).
    Notify(Notice),
}

/// Silencio vigente de una regla para un sujeto (§7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuteState {
    /// Regla silenciada.
    pub rule: RuleId,
    /// Sujeto.
    pub subject: Subject,
    /// Fin del silencio (None = siempre).
    pub until: Option<SystemTime>,
}

/// Estado de aprendizaje de un sujeto (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningState {
    /// Sujeto (`Device(id)` o `Host`).
    pub subject: Subject,
    /// Desde cuándo cuentan los días.
    pub learning_from: SystemTime,
    /// Días con datos contados.
    pub data_days: u32,
    /// Fin del día en que terminó el aprendizaje (None mientras aprende).
    pub learned_at: Option<SystemTime>,
}

/// Estado al arrancar: silencios vigentes, aprendizaje, claves de 24 h y
/// condiciones activas (`Repo::engine_snapshot`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EngineSnapshot {
    /// Silencios vigentes.
    pub mutes: Vec<MuteState>,
    /// Aprendizaje por sujeto.
    pub learning: Vec<LearningState>,
    /// Alertas de las últimas 24 h y condiciones activas.
    pub recent: Vec<RecentState>,
    /// `DEVICES` está vacía al arrancar: línea base hasta el primer escaneo (§7.9).
    pub devices_empty: bool,
}

/// Alerta reciente cargada desde la BD (deduplicación y condiciones).
#[derive(Debug, Clone, PartialEq)]
pub struct RecentState {
    /// Clave de deduplicación.
    pub key: DedupKey,
    /// Id de la alerta.
    pub id: i64,
    /// Momento de creación.
    pub created_at: SystemTime,
    /// Última repetición.
    pub last_at: SystemTime,
    /// Condición activa (`resolved_at` NULL).
    pub active: bool,
    /// Detalles actuales.
    pub details: Value,
}

/// Motor de alertas puro (sin BD ni TUI).
#[derive(Debug, Clone)]
pub struct AlertEngine {
    params: AlertsParams,
    snapshot: EngineSnapshot,
    estado: Estado,
}

/// Inserción emitida y pendiente de que la TUI apunte su id (`inserted`).
#[derive(Debug, Clone)]
struct Pendiente {
    /// Estado que pasará a `recientes` en cuanto se conozca el id.
    estado: RecentState,
    /// La alerta se creó durante la puesta al día: su id va al resumen.
    en_puesta_al_dia: bool,
}

/// Acumulado de la puesta al día para el resumen final (§7.9).
#[derive(Debug, Clone, Default)]
struct PuestaAlDia {
    /// El resumen ya se ha emitido (o no había nada que resumir).
    resumen_hecho: bool,
    /// Ids de las alertas creadas durante la puesta al día.
    agrupadas: Vec<i64>,
    /// Recuento por regla.
    por_regla: BTreeMap<RuleId, u32>,
    /// Recuento por nivel.
    por_nivel: BTreeMap<Level, u32>,
    /// Nivel mayor de lo agrupado.
    max_nivel: Option<Level>,
    /// Total de alertas agrupadas.
    total: u32,
}

/// Racha de minutos con pérdidas por encima y por debajo del umbral (§7.8).
#[derive(Debug, Clone, Default)]
struct RachaPerdidas {
    /// Minutos seguidos por encima del umbral.
    por_encima: u32,
    /// Minutos seguidos por debajo del umbral.
    por_debajo: u32,
}

/// Estado interno del motor.
#[derive(Debug, Clone, Default)]
struct Estado {
    /// Claves de las últimas 24 h y condiciones activas, por clave.
    recientes: HashMap<DedupKey, RecentState>,
    /// Inserciones emitidas a la espera de que la TUI llame a `inserted`.
    pendientes: HashMap<DedupKey, Pendiente>,
    /// Silencios vigentes.
    silencios: Vec<MuteState>,
    /// Aprendizaje conocido por sujeto.
    aprendizaje: HashMap<Subject, LearningState>,
    /// Política de notificación.
    politica: NotifyPolicy,
    /// Línea base de una base de datos nueva (§7.9).
    linea_base: bool,
    /// Primer instante visto (arranque aproximado de la sesión).
    arranque: Option<SystemTime>,
    /// Último instante recibido en `handle` o `tick`.
    ultimo: Option<SystemTime>,
    /// Acumulado de la puesta al día.
    puesta_al_dia: PuestaAlDia,
    /// Racha de pérdidas de captura.
    perdidas: RachaPerdidas,
}

impl Estado {
    /// Construye el estado inicial a partir del snapshot de la BD.
    fn desde_snapshot(params: &AlertsParams, snapshot: &EngineSnapshot) -> Self {
        let mut politica = NotifyPolicy::default();
        politica.reload(params);
        Self {
            recientes: snapshot
                .recent
                .iter()
                .cloned()
                .map(|reciente| (reciente.key.clone(), reciente))
                .collect(),
            silencios: snapshot.mutes.clone(),
            aprendizaje: snapshot
                .learning
                .iter()
                .cloned()
                .map(|aprendizaje| (aprendizaje.subject, aprendizaje))
                .collect(),
            politica,
            linea_base: snapshot.devices_empty,
            ..Self::default()
        }
    }

    /// Sustituye el aprendizaje por el que llega de la BD.
    fn aplicar_aprendizaje(&mut self, aprendizaje: &[LearningState]) {
        self.aprendizaje = aprendizaje
            .iter()
            .cloned()
            .map(|estado| (estado.subject, estado))
            .collect();
    }

    /// Sustituye los silencios por los que llegan de la BD.
    fn aplicar_silencios(&mut self, silencios: &[MuteState]) {
        self.silencios = silencios.to_vec();
    }
}

/// Candidata a alerta antes de la deduplicación, los silencios y la política.
#[derive(Debug, Clone)]
struct Candidato {
    /// Regla que la produce.
    rule: RuleId,
    /// Sujeto.
    subject: Subject,
    /// Clave de la regla.
    key: String,
    /// Nivel efectivo (el de `device_new` con MAC privada puede bajar).
    level: Level,
    /// El porqué (§7.1).
    details: Value,
    /// Evento de origen, si lo hay.
    event_id: Option<i64>,
    /// Etiqueta visible del sujeto al crear la alerta.
    subject_label: String,
}

impl AlertEngine {
    /// Estado inicial del motor con la configuración y el snapshot de la BD.
    pub fn new(params: AlertsParams, snapshot: EngineSnapshot) -> Self {
        let estado = Estado::desde_snapshot(&params, &snapshot);
        Self {
            params,
            snapshot,
            estado,
        }
    }

    /// Evalúa una señal y devuelve las acciones a aplicar.
    pub fn handle(&mut self, signal: Signal, now: SystemTime) -> Vec<AlertAction> {
        self.arrancar(now);
        if !self.params.enabled {
            return Vec::new();
        }
        match signal {
            Signal::Event(evento) => self.evento(evento, now),
            Signal::Seen(visto) => self.visto(visto, now),
            Signal::HourClosed(hora) => self.hora(hora, now),
            Signal::Health(salud) => self.salud(salud, now),
        }
    }

    /// Tareas periódicas (fin de la puesta al día, tope de notificaciones).
    pub fn tick(&mut self, now: SystemTime) -> Vec<AlertAction> {
        self.arrancar(now);
        let mut acciones = Vec::new();
        // Fin de la puesta al día: resumen y una sola notificación (§7.9).
        if let Some(fin) = self.estado.politica.catch_up_ends() {
            if now >= fin {
                self.estado.politica.mark_catch_up_done();
                acciones.extend(self.cerrar_puesta_al_dia(now));
            }
        }
        // Una inserción pendiente que no llega a apuntarse no puede bloquear
        // la clave para siempre: si la TUI descartó la acción, caduca.
        self.estado
            .pendientes
            .retain(|_, pendiente| diferencia(pendiente.estado.created_at, now) <= PENDIENTE_MAX);
        // Las claves fuera del plazo de deduplicación ya no hacen falta y se
        // descartan para que el motor no crezca sin límite (las condiciones
        // activas se conservan).
        let plazo = self.plazo();
        self.estado
            .recientes
            .retain(|_, reciente| reciente.active || diferencia(reciente.created_at, now) < plazo);
        // Notificaciones retenidas por el tope del minuto (§7.2).
        if let Some(retenidas) = self.estado.politica.tomar_retenidas(now) {
            let texto = texto_retenidas(retenidas);
            acciones.push(AlertAction::Notify(Notice {
                summary: format!("Almenara · {texto}"),
                body: AlertText::escape_markup(&AlertText::sanitize(&texto, BODY_MAX)),
            }));
        }
        acciones
    }

    /// Apunta el id de una alerta recién creada.
    ///
    /// El resumen de la puesta al día no tiene clave de deduplicación, así que
    /// la TUI no llama a este método para él. Si la inserción de una alerta
    /// falló y la TUI descartó la acción, su pendiente caduca en `tick` y aquí
    /// se tolera que la clave ya no exista: se registra igualmente para que la
    /// deduplicación de esa fila no se pierda.
    pub fn inserted(&mut self, key: &DedupKey, id: i64) {
        if let Some(mut pendiente) = self.estado.pendientes.remove(key) {
            pendiente.estado.id = id;
            if pendiente.en_puesta_al_dia {
                self.estado.puesta_al_dia.agrupadas.push(id);
            }
            self.estado.recientes.insert(key.clone(), pendiente.estado);
            return;
        }
        match self.estado.recientes.get_mut(key) {
            Some(reciente) if reciente.id == 0 => reciente.id = id,
            Some(_) => {}
            None => {
                let instante = self.estado.ultimo.unwrap_or(std::time::UNIX_EPOCH);
                self.estado.recientes.insert(
                    key.clone(),
                    RecentState {
                        key: key.clone(),
                        id,
                        created_at: instante,
                        last_at: instante,
                        active: false,
                        details: Value::Null,
                    },
                );
            }
        }
    }

    /// Recarga configuración y estado tras cambiar reglas, silencios o aprendizaje.
    ///
    /// API del contrato (checklist F6); la TUI la usará al recargar el motor.
    #[allow(dead_code)]
    pub fn reload(&mut self, params: AlertsParams, snapshot: EngineSnapshot) {
        self.params = params;
        self.estado.politica.reload(&self.params);
        self.snapshot = snapshot;
        self.estado.aplicar_silencios(&self.snapshot.mutes);
        self.estado.aplicar_aprendizaje(&self.snapshot.learning);
        // Las claves del snapshot mandan, pero no se pierde lo creado en esta
        // sesión si el snapshot se tomó un momento antes.
        for reciente in &self.snapshot.recent {
            self.estado
                .recientes
                .insert(reciente.key.clone(), reciente.clone());
        }
        if !self.snapshot.devices_empty {
            self.estado.linea_base = false;
        }
    }

    /// Termina la línea base tras el primer ciclo de escaneo completo (§7.9).
    pub fn end_baseline(&mut self) {
        self.estado.linea_base = false;
    }

    /// Enciende o apaga el motor (`[alerts].enabled`).
    #[allow(dead_code)] // API del contrato: la TUI y el modo servicio la usarán.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.params.enabled = enabled;
        self.estado.politica.reload(&self.params);
    }

    /// Cambia el ajuste de una regla; apagar una regla resuelve sus condiciones.
    pub fn set_rule(
        &mut self,
        rule: RuleId,
        setting: RuleSetting,
        now: SystemTime,
    ) -> Vec<AlertAction> {
        self.params.rules.insert(rule, setting);
        self.estado.politica.reload(&self.params);
        if setting.enabled {
            return Vec::new();
        }
        self.resolver_condiciones_de(rule, now)
    }

    /// Marca o desmarca un equipo como vigilado; desmarcarlo resuelve su
    /// alerta de ausencia activa (§7.7).
    pub fn set_watched(
        &mut self,
        device_id: i64,
        watched: bool,
        now: SystemTime,
    ) -> Vec<AlertAction> {
        if watched {
            return Vec::new();
        }
        self.resolver_clave(
            DedupKey::new(RuleId::WatchedPresence, Subject::Device(device_id), "gone"),
            now,
        )
    }

    /// Sustituye el aprendizaje conocido.
    pub fn set_learning(&mut self, learning: Vec<LearningState>) {
        self.snapshot.learning = learning;
        self.estado.aplicar_aprendizaje(&self.snapshot.learning);
    }

    /// Sustituye los silencios vigentes.
    pub fn set_mutes(&mut self, mutes: Vec<MuteState>) {
        self.snapshot.mutes = mutes;
        self.estado.aplicar_silencios(&self.snapshot.mutes);
    }

    /// Indica si la línea base sigue activa.
    #[allow(dead_code)] // API del contrato: la barra y el modo servicio la usarán.
    pub fn baseline_active(&self) -> bool {
        self.estado.linea_base
    }

    /// Indica si sigue la puesta al día (§7.9).
    ///
    /// Antes del primer tick o señal, la puesta al día está configurada pero
    /// aún no ha tomado su instante de arranque: se informa como activa para
    /// que la TUI no tenga que esperar al primer latido.
    #[allow(dead_code)] // API del contrato: la TUI y el modo servicio la usarán.
    pub fn in_catch_up(&self, now: SystemTime) -> bool {
        if !self.estado.politica.started() {
            return self.params.catch_up_minutes > 0;
        }
        self.estado.politica.in_catch_up(now)
    }

    /// Parámetros activos.
    #[allow(dead_code)] // API del contrato: la TUI la usará al abrir Config.
    pub fn params(&self) -> &AlertsParams {
        &self.params
    }

    /// Snapshot del arranque.
    #[allow(dead_code)] // API del contrato: la TUI la usará al abrir Config.
    pub fn snapshot(&self) -> &EngineSnapshot {
        &self.snapshot
    }

    /// Toma el instante de arranque y arranca la puesta al día la primera vez.
    fn arrancar(&mut self, now: SystemTime) {
        if self.estado.arranque.is_none() {
            self.estado.arranque = Some(now);
        }
        self.estado.ultimo = Some(now);
        if !self.estado.politica.started() {
            self.estado.politica.start(now);
        }
    }

    /// Evalúa un evento del escaneo (§7.1 y §7.7).
    fn evento(&mut self, evento: EventSignal, now: SystemTime) -> Vec<AlertAction> {
        let EventSignal {
            device,
            kind,
            details,
            event_id,
        } = evento;
        let subject = Subject::Device(device.device_id);
        match kind {
            EventKind::New => {
                // Línea base: la red de partida no avisa (§7.9).
                if self.estado.linea_base {
                    return Vec::new();
                }
                let ajuste = self.params.rule(RuleId::DeviceNew);
                let level = if device.mac_random {
                    ajuste.level_private_mac.unwrap_or(ajuste.level)
                } else {
                    ajuste.level
                };
                let por_que = json!({
                    "mac": sanear(&device.mac),
                    "mac_random": device.mac_random,
                    "vendor": opcion_texto(device.vendor.as_deref()),
                    "ip": sanear(&device.ip),
                    "source": device.source.as_str(),
                    "hostname": opcion_texto(device.hostname.as_deref()),
                });
                self.admitir(
                    Candidato {
                        rule: RuleId::DeviceNew,
                        subject,
                        key: String::new(),
                        level,
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                )
            }
            EventKind::ServiceNew => {
                let port = details.get("port").and_then(Value::as_u64).unwrap_or(0);
                let protocol = texto_de(&details, "protocol").unwrap_or_else(|| "tcp".to_string());
                let service = opcion_texto(details.get("service").and_then(Value::as_str));
                let reopened = details
                    .get("reopened")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let key = format!("{port}/{protocol}");
                let por_que = json!({
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "reopened": reopened,
                });
                self.admitir(
                    Candidato {
                        rule: RuleId::PortNew,
                        subject,
                        key,
                        level: self.params.level(RuleId::PortNew),
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                )
            }
            EventKind::MacChanged => {
                let before = valor_saneado(details.get("before"));
                let after = valor_saneado(details.get("after"));
                let key = texto_de(&details, "after")
                    .or_else(|| (!device.mac.trim().is_empty()).then(|| sanear(&device.mac)))
                    .unwrap_or_default();
                let por_que = json!({
                    "before": before,
                    "after": after,
                    "reason": opcion_texto(details.get("reason").and_then(Value::as_str)),
                });
                self.admitir(
                    Candidato {
                        rule: RuleId::MacChanged,
                        subject,
                        key,
                        level: self.params.level(RuleId::MacChanged),
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                )
            }
            EventKind::HostnameChanged => {
                let before = valor_saneado(details.get("before"));
                let after = valor_saneado(details.get("after"));
                let key = texto_de(&details, "after")
                    .or_else(|| device.hostname.as_deref().map(sanear))
                    .unwrap_or_default();
                let por_que = json!({"before": before, "after": after});
                self.admitir(
                    Candidato {
                        rule: RuleId::NameChanged,
                        subject,
                        key,
                        level: self.params.level(RuleId::NameChanged),
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                )
            }
            EventKind::OsChanged => {
                let before = valor_saneado(details.get("before"));
                let after = valor_saneado(details.get("after"));
                let key = texto_de(&details, "after").unwrap_or_default();
                let por_que = json!({
                    "before": before,
                    "after": after,
                    "os_source": opcion_texto(details.get("os_source").and_then(Value::as_str)),
                });
                self.admitir(
                    Candidato {
                        rule: RuleId::OsChanged,
                        subject,
                        key,
                        level: self.params.level(RuleId::OsChanged),
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                )
            }
            EventKind::TypeChanged => {
                let before = valor_saneado(details.get("before"));
                let after = valor_saneado(details.get("after"));
                let key = texto_de(&details, "after").unwrap_or_default();
                let por_que = json!({"before": before, "after": after});
                self.admitir(
                    Candidato {
                        rule: RuleId::TypeChanged,
                        subject,
                        key,
                        level: self.params.level(RuleId::TypeChanged),
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                )
            }
            EventKind::Disappeared => {
                if !device.watched {
                    return self.resolver_clave(
                        DedupKey::new(RuleId::WatchedPresence, subject, "gone"),
                        now,
                    );
                }
                let last_seen = device.last_seen;
                let while_closed = self
                    .estado
                    .arranque
                    .map(|arranque| last_seen < arranque)
                    .unwrap_or(false);
                let away_s = details
                    .get("away_s")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let por_que = json!({
                    "state": "gone",
                    "last_seen": fecha(last_seen),
                    "away_s": away_s,
                    "while_closed": while_closed,
                });
                self.admitir(
                    Candidato {
                        rule: RuleId::WatchedPresence,
                        subject,
                        key: "gone".to_string(),
                        level: self.params.level(RuleId::WatchedPresence),
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                )
            }
            EventKind::Reappeared => {
                if !device.watched {
                    return Vec::new();
                }
                // Resuelve la ausencia y avisa de la vuelta (§7.7).
                let mut acciones = self
                    .resolver_clave(DedupKey::new(RuleId::WatchedPresence, subject, "gone"), now);
                let away_s = details
                    .get("away_s")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let por_que = json!({
                    "state": "back",
                    "last_seen": fecha(device.last_seen),
                    "away_s": away_s,
                    "while_closed": false,
                });
                acciones.extend(self.admitir(
                    Candidato {
                        rule: RuleId::WatchedPresence,
                        subject,
                        key: "back".to_string(),
                        level: self.params.level(RuleId::WatchedPresence),
                        details: por_que,
                        event_id,
                        subject_label: device.label,
                    },
                    now,
                ));
                acciones
            }
        }
    }

    /// Evalúa las entradas nuevas del inventario de un sujeto (§7.11).
    fn visto(&mut self, visto: SeenSignal, now: SystemTime) -> Vec<AlertAction> {
        // Mientras el sujeto aprende, lo nuevo se apunta sin avisar (§7.3).
        if !visto.learned {
            return Vec::new();
        }
        let aprendido = visto.learned_at.or_else(|| {
            self.estado
                .aprendizaje
                .get(&visto.subject)
                .and_then(|estado| estado.learned_at)
        });
        let mut acciones = Vec::new();
        for item in &visto.items {
            let Some(rule) = regla_de_inventario(item.kind) else {
                continue;
            };
            // Las claves especiales (`~…`) nunca son la clave de una alerta (§7.1).
            if item.key.trim().is_empty() || clave_especial(&item.key) {
                continue;
            }
            let key = sanear(&item.key);
            let por_que = json!({
                "kind": item.kind.as_str(),
                "key": key,
                "label": sanear(&item.label),
                "first_seen": fecha(item.first_seen),
                "learned_at": match aprendido {
                    Some(instante) => Value::String(fecha(instante)),
                    None => Value::Null,
                },
            });
            acciones.extend(self.admitir(
                Candidato {
                    rule,
                    subject: visto.subject,
                    key,
                    level: self.params.level(rule),
                    details: por_que,
                    event_id: None,
                    subject_label: visto.subject_label.clone(),
                },
                now,
            ));
        }
        acciones
    }

    /// Evalúa una hora cerrada y consolidada con sus muestras (§7.4).
    fn hora(&mut self, hora: HourClosedSignal, now: SystemTime) -> Vec<AlertAction> {
        let p = self.params.traffic_high;
        let minimo_bajada = p.min_mb_down.saturating_mul(1_000_000);
        let minimo_subida = p.min_mb_up.saturating_mul(1_000_000);
        let level = self.params.level(RuleId::TrafficHigh);
        let mut acciones = Vec::new();
        for sujeto in &hora.subjects {
            let muestras_bajada: Vec<u64> =
                sujeto.samples.iter().map(|(bajada, _)| *bajada).collect();
            let muestras_subida: Vec<u64> =
                sujeto.samples.iter().map(|(_, subida)| *subida).collect();
            for (direccion, valor, minimo, muestras) in [
                ("down", sujeto.down, minimo_bajada, &muestras_bajada),
                ("up", sujeto.up, minimo_subida, &muestras_subida),
            ] {
                let Some(info) = Baseline::evaluate(valor, muestras, minimo, &p) else {
                    continue;
                };
                let por_que = json!({
                    "direction": direccion,
                    "hour": hora.hour_start,
                    "value": valor,
                    "median": info.median,
                    "factor": if info.factor.is_finite() {
                        Value::from(info.factor)
                    } else {
                        Value::Null
                    },
                    "samples": info.samples,
                });
                // La señal trae el nombre visible del sujeto; si no, se usa
                // la etiqueta genérica del tipo de sujeto.
                let subject_label = if sujeto.label.trim().is_empty() {
                    sujeto.subject.label().to_string()
                } else {
                    sanear(&sujeto.label)
                };
                acciones.extend(self.admitir(
                    Candidato {
                        rule: RuleId::TrafficHigh,
                        subject: sujeto.subject,
                        key: direccion.to_string(),
                        level,
                        details: por_que,
                        event_id: None,
                        subject_label,
                    },
                    now,
                ));
            }
        }
        acciones
    }

    /// Evalúa una muestra de salud de la captura o de la BD (§7.8).
    fn salud(&mut self, salud: HealthSample, now: SystemTime) -> Vec<AlertAction> {
        let mut acciones = Vec::new();
        acciones.extend(self.salud_captura_parada(&salud.capture, now));
        acciones.extend(self.salud_perdidas(&salud.capture, now));
        acciones.extend(self.salud_base_de_datos(&salud.db, now));
        acciones
    }

    /// Regla `capture_stopped` (§7.8).
    fn salud_captura_parada(
        &mut self,
        captura: &CaptureHealth,
        now: SystemTime,
    ) -> Vec<AlertAction> {
        let clave = DedupKey::new(RuleId::CaptureStopped, Subject::Almenara, "capture");
        if !captura.stopped {
            return self.resolver_clave(clave, now);
        }
        let por_que = json!({
            "interface": sanear(&captura.interface),
            "reason": opcion_texto(captura.reason.as_deref()),
        });
        self.admitir(
            Candidato {
                rule: RuleId::CaptureStopped,
                subject: Subject::Almenara,
                key: "capture".to_string(),
                level: self.params.level(RuleId::CaptureStopped),
                details: por_que,
                event_id: None,
                subject_label: Subject::Almenara.label().to_string(),
            },
            now,
        )
    }

    /// Regla `capture_drops`: > `percent` durante `minutes` minutos seguidos y
    /// resuelta tras `minutes` minutos seguidos por debajo (§7.8).
    fn salud_perdidas(&mut self, captura: &CaptureHealth, now: SystemTime) -> Vec<AlertAction> {
        let Some(porcentaje) = captura.drops_pct else {
            return Vec::new();
        };
        let p = self.params.capture_drops;
        let clave = DedupKey::new(RuleId::CaptureDrops, Subject::Almenara, "drops");
        if f64::from(porcentaje) > p.percent {
            self.estado.perdidas.por_encima = self.estado.perdidas.por_encima.saturating_add(1);
            self.estado.perdidas.por_debajo = 0;
            if self.estado.perdidas.por_encima < p.minutes {
                return Vec::new();
            }
            let por_que = json!({
                "percent": f64::from(porcentaje),
                "minutes": p.minutes,
                "kernel_drops": captura.kernel_drops,
                "limit_drops": captura.limit_drops,
            });
            self.admitir(
                Candidato {
                    rule: RuleId::CaptureDrops,
                    subject: Subject::Almenara,
                    key: "drops".to_string(),
                    level: self.params.level(RuleId::CaptureDrops),
                    details: por_que,
                    event_id: None,
                    subject_label: Subject::Almenara.label().to_string(),
                },
                now,
            )
        } else {
            self.estado.perdidas.por_debajo = self.estado.perdidas.por_debajo.saturating_add(1);
            self.estado.perdidas.por_encima = 0;
            if self.estado.perdidas.por_debajo < p.minutes {
                return Vec::new();
            }
            // Racha de calma suficiente: se resuelve (si estaba activa).
            self.estado.perdidas.por_debajo = 0;
            self.resolver_clave(clave, now)
        }
    }

    /// Regla `db_size`: la BD y su WAL pasan de `max_db_mb` (§7.8).
    fn salud_base_de_datos(&mut self, db: &DbSize, now: SystemTime) -> Vec<AlertAction> {
        let clave = DedupKey::new(RuleId::DbSize, Subject::Almenara, "db");
        if !db.over_limit() {
            return self.resolver_clave(clave, now);
        }
        let por_que = json!({
            "db_bytes": db.db_bytes,
            "wal_bytes": db.wal_bytes,
            "max_db_mb": db.max_db_mb,
        });
        self.admitir(
            Candidato {
                rule: RuleId::DbSize,
                subject: Subject::Almenara,
                key: "db".to_string(),
                level: self.params.level(RuleId::DbSize),
                details: por_que,
                event_id: None,
                subject_label: Subject::Almenara.label().to_string(),
            },
            now,
        )
    }

    /// Puerta única de las alertas: regla, silencio, deduplicación, condiciones
    /// y política de notificación (§4.1, §7.5 y §7.6).
    fn admitir(&mut self, candidato: Candidato, now: SystemTime) -> Vec<AlertAction> {
        // 0) El porqué en una o dos líneas para el panel de detalle (§7.1).
        let mut candidato = candidato;
        let info_sujeto = SubjectInfo {
            subject: candidato.subject,
            label: candidato.subject_label.clone(),
        };
        let porque = AlertText::porque(
            candidato.rule,
            &info_sujeto,
            &candidato.key,
            &candidato.details,
            now,
        );
        if let Value::Object(mapa) = &mut candidato.details {
            mapa.insert("porque".to_string(), Value::String(porque));
        }
        // 1) Regla apagada.
        if !self.params.rule(candidato.rule).enabled {
            return Vec::new();
        }
        // 2) Silencio vigente para la regla y el sujeto.
        if self.silenciado(candidato.rule, candidato.subject, now) {
            return Vec::new();
        }
        let clave = DedupKey::new(candidato.rule, candidato.subject, candidato.key.clone());
        // 3) Inserción ya emitida y pendiente de aplicar: no se duplica.
        if self.estado.pendientes.contains_key(&clave) {
            return Vec::new();
        }
        let condicion = es_condicion(candidato.rule, &candidato.key);
        // 4) Deduplicación dentro del plazo (§7.5).
        if let Some(previa) = self.estado.recientes.get(&clave).cloned() {
            // Una condición que sigue activa no genera nada nuevo, aunque su
            // fila sea más vieja que el plazo: la ausencia de un vigilado o la
            // captura parada siguen siéndolo hasta que desaparecen.
            if condicion && previa.active {
                return Vec::new();
            }
            if diferencia(previa.created_at, now) < self.plazo() {
                if condicion {
                    let details = candidato.details.clone();
                    if let Some(reciente) = self.estado.recientes.get_mut(&clave) {
                        reciente.active = true;
                        reciente.last_at = now;
                        reciente.details = details.clone();
                    }
                    return vec![AlertAction::Repeat {
                        id: previa.id,
                        at: now,
                        details,
                        reactivate: true,
                    }];
                }
                let details =
                    self.detalles_de_repeticion(candidato.rule, &previa.details, candidato.details);
                if let Some(reciente) = self.estado.recientes.get_mut(&clave) {
                    reciente.last_at = now;
                    reciente.details = details.clone();
                }
                return vec![AlertAction::Repeat {
                    id: previa.id,
                    at: now,
                    details,
                    reactivate: false,
                }];
            }
        }
        // 5) Alerta nueva.
        let info = SubjectInfo {
            subject: candidato.subject,
            label: candidato.subject_label.clone(),
        };
        let textos = AlertText::compose(candidato.rule, &info, &candidato.key, &candidato.details);
        let alerta = NewAlert {
            rule: AlertRule::Rule(candidato.rule),
            level: candidato.level,
            subject: candidato.subject,
            device_id: match candidato.subject {
                Subject::Device(id) => Some(id),
                _ => None,
            },
            key: candidato.key.clone(),
            title: textos.title,
            subject_label: textos.subject_label,
            details: candidato.details.clone(),
            event_id: candidato.event_id,
        };
        let aviso = self.aviso(&alerta, &textos.body, now);
        let en_puesta_al_dia = self.estado.politica.in_catch_up(now);
        if en_puesta_al_dia {
            self.anotar_puesta_al_dia(candidato.rule, candidato.level);
        }
        self.estado.pendientes.insert(
            clave,
            Pendiente {
                estado: RecentState {
                    key: DedupKey::new(candidato.rule, candidato.subject, candidato.key),
                    id: 0,
                    created_at: now,
                    last_at: now,
                    active: condicion,
                    details: candidato.details,
                },
                en_puesta_al_dia,
            },
        );
        vec![AlertAction::Insert {
            alert: alerta,
            notify: aviso,
        }]
    }

    /// Compone la notificación de una alerta nueva según la política (§7.2).
    fn aviso(&mut self, alerta: &NewAlert, cuerpo: &str, now: SystemTime) -> Option<Notice> {
        match self.estado.politica.decide(alerta.level, now) {
            NotifyDecision::Notify => Some(Notice {
                summary: format!("Almenara · {}", alerta.rule.name()),
                body: AlertText::escape_markup(&AlertText::sanitize(cuerpo, BODY_MAX)),
            }),
            _ => None,
        }
    }

    /// Apunta una alerta al resumen de la puesta al día (§7.9).
    fn anotar_puesta_al_dia(&mut self, rule: RuleId, level: Level) {
        let puesta = &mut self.estado.puesta_al_dia;
        puesta.total = puesta.total.saturating_add(1);
        *puesta.por_regla.entry(rule).or_insert(0) += 1;
        *puesta.por_nivel.entry(level).or_insert(0) += 1;
        puesta.max_nivel = Some(match puesta.max_nivel {
            Some(maximo) => maximo.max(level),
            None => level,
        });
    }

    /// Emite el resumen de la puesta al día al terminar los minutos configurados.
    fn cerrar_puesta_al_dia(&mut self, now: SystemTime) -> Vec<AlertAction> {
        if self.estado.puesta_al_dia.resumen_hecho {
            return Vec::new();
        }
        self.estado.puesta_al_dia.resumen_hecho = true;
        let total = self.estado.puesta_al_dia.total;
        if total == 0 {
            return Vec::new();
        }
        let por_regla = self.estado.puesta_al_dia.por_regla.clone();
        let por_nivel = self.estado.puesta_al_dia.por_nivel.clone();
        let agrupadas = self.estado.puesta_al_dia.agrupadas.clone();
        let level = self.estado.puesta_al_dia.max_nivel.unwrap_or(Level::Info);
        let importantes = por_nivel.get(&Level::Important).copied().unwrap_or(0);
        let mut reglas = Map::new();
        for (rule, cuenta) in &por_regla {
            reglas.insert(rule.as_str().to_string(), json!(cuenta));
        }
        let importantes_totales = por_nivel.get(&Level::Important).copied().unwrap_or(0);
        let avisos = por_nivel.get(&Level::Warning).copied().unwrap_or(0);
        let infos = por_nivel.get(&Level::Info).copied().unwrap_or(0);
        let agrupadas_txt = if total == 1 {
            "1 alerta agrupada".to_string()
        } else {
            format!("{total} alertas agrupadas")
        };
        let porque = AlertText::sanitize(
            &format!(
                "{agrupadas_txt}: {importantes_totales} importantes, {avisos} avisos, {infos} info"
            ),
            super::text::PORQUE_MAX,
        );
        let details = json!({
            "total": total,
            "by_rule": Value::Object(reglas),
            "by_level": {
                "important": importantes_totales,
                "warning": avisos,
                "info": infos,
            },
            "porque": porque,
        });
        let title = format!("Resumen al arrancar ({})", texto_alertas(total));
        let cuerpo = cuerpo_resumen(total, importantes);
        let aviso = if importantes > 0
            && matches!(
                self.estado.politica.decide_resumen(now),
                NotifyDecision::Notify
            ) {
            Some(Notice {
                summary: format!("Almenara · {}", AlertRule::CatchUp.name()),
                body: AlertText::escape_markup(&AlertText::sanitize(&cuerpo, BODY_MAX)),
            })
        } else {
            None
        };
        let alerta = NewAlert {
            rule: AlertRule::CatchUp,
            level,
            subject: Subject::Almenara,
            device_id: None,
            key: String::new(),
            title,
            subject_label: Subject::Almenara.label().to_string(),
            details,
            event_id: None,
        };
        vec![AlertAction::InsertSummary {
            alert: alerta,
            grouped: agrupadas,
            notify: aviso,
        }]
    }

    /// Resuelve una condición activa concreta (§7.5).
    fn resolver_clave(&mut self, clave: DedupKey, now: SystemTime) -> Vec<AlertAction> {
        if let Some(reciente) = self.estado.recientes.get_mut(&clave) {
            if reciente.active && reciente.id != 0 {
                reciente.active = false;
                return vec![AlertAction::Resolve {
                    id: reciente.id,
                    at: now,
                }];
            }
        }
        Vec::new()
    }

    /// Resuelve las condiciones activas de una regla apagada (§7.17).
    fn resolver_condiciones_de(&mut self, rule: RuleId, now: SystemTime) -> Vec<AlertAction> {
        let claves: Vec<DedupKey> = self
            .estado
            .recientes
            .iter()
            .filter(|(clave, reciente)| {
                clave.rule == rule
                    && reciente.active
                    && reciente.id != 0
                    && es_condicion(rule, &clave.key)
            })
            .map(|(clave, _)| clave.clone())
            .collect();
        let mut acciones = Vec::new();
        for clave in claves {
            if let Some(reciente) = self.estado.recientes.get_mut(&clave) {
                reciente.active = false;
                acciones.push(AlertAction::Resolve {
                    id: reciente.id,
                    at: now,
                });
            }
        }
        acciones
    }

    /// Indica si hay un silencio vigente para la regla y el sujeto (§7.6).
    fn silenciado(&self, rule: RuleId, subject: Subject, now: SystemTime) -> bool {
        self.estado.silencios.iter().any(|silencio| {
            silencio.rule == rule
                && silencio.subject == subject
                && match silencio.until {
                    None => true,
                    Some(hasta) => hasta > now,
                }
        })
    }

    /// Plazo de deduplicación (§7.5).
    fn plazo(&self) -> Duration {
        Duration::from_secs(u64::from(self.params.dedup_hours.max(1)) * 3_600)
    }

    /// Detalles de una repetición: para `traffic_high` se guarda el valor mayor
    /// (§7.4). Para el resto se quedan los nuevos.
    fn detalles_de_repeticion(&self, rule: RuleId, previos: &Value, nuevos: Value) -> Value {
        if rule != RuleId::TrafficHigh {
            return nuevos;
        }
        let anterior = previos.get("value").and_then(Value::as_u64).unwrap_or(0);
        let nuevo = nuevos.get("value").and_then(Value::as_u64).unwrap_or(0);
        if nuevo >= anterior {
            nuevos
        } else {
            previos.clone()
        }
    }
}

/// Indica si una alerta de la regla y clave dadas es de condición (§7.5).
fn es_condicion(rule: RuleId, key: &str) -> bool {
    match rule {
        // `watched_presence` solo es condición en la ausencia; la vuelta es un
        // aviso puntual que se queda resuelto en su fila.
        RuleId::WatchedPresence => key == "gone",
        otra => otra.def().condition,
    }
}

/// Regla de inventario que corresponde a un tipo de clave visto (§7.1).
fn regla_de_inventario(kind: SeenKind) -> Option<RuleId> {
    Some(match kind {
        SeenKind::App => RuleId::NewApp,
        SeenKind::Category => RuleId::NewCategory,
        SeenKind::Country => RuleId::NewCountry,
        SeenKind::Org => RuleId::NewOrg,
        SeenKind::Ja4 => RuleId::NewJa4,
    })
}

/// Diferencia absoluta entre dos instantes (§7.17: el reloj puede ir hacia atrás).
fn diferencia(a: SystemTime, b: SystemTime) -> Duration {
    a.duration_since(b)
        .or_else(|_| b.duration_since(a))
        .unwrap_or_default()
}

/// Fecha RFC 3339 UTC, como las guarda el histórico (ADR-34).
fn fecha(instante: SystemTime) -> String {
    let utc: DateTime<Utc> = instante.into();
    utc.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Sanea un texto que viene de la red para los detalles (§7.13).
fn sanear(texto: &str) -> String {
    AlertText::sanitize(texto, TITLE_MAX)
}

/// Cadena de `details` ya saneada, si existe y no está vacía.
fn texto_de(details: &Value, clave: &str) -> Option<String> {
    details
        .get(clave)
        .and_then(Value::as_str)
        .map(sanear)
        .filter(|texto| !texto.is_empty())
}

/// Texto opcional de `details` como valor JSON (saneado o `null`).
fn opcion_texto(texto: Option<&str>) -> Value {
    match texto {
        Some(texto) => Value::String(sanear(texto)),
        None => Value::Null,
    }
}

/// Valor de `details` saneado si es cadena; el resto se copia tal cual.
fn valor_saneado(valor: Option<&Value>) -> Value {
    match valor {
        Some(Value::String(texto)) => Value::String(sanear(texto)),
        Some(otro) => otro.clone(),
        None => Value::Null,
    }
}

/// «1 alerta» o «N alertas».
fn texto_alertas(total: u32) -> String {
    if total == 1 {
        "1 alerta".to_string()
    } else {
        format!("{total} alertas")
    }
}

/// Cuerpo de la notificación del resumen de la puesta al día.
fn cuerpo_resumen(total: u32, importantes: u32) -> String {
    let base = texto_alertas(total);
    let otros = total.saturating_sub(importantes);
    if importantes == 0 {
        format!("{base}: ninguna importante")
    } else if otros == 0 {
        format!("{base}: todas importantes")
    } else {
        format!("{base}: {importantes} importante(s), {otros} de otros niveles")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{
        CaptureHealth, CaptureStats, DeviceSignal, DeviceSource, EventSignal, Health, HealthSample,
        HourClosedSignal, HourSubject, SeenNew, SeenSignal,
    };
    use crate::history::SeenKind;
    use chrono::TimeZone;
    use std::time::{Instant, UNIX_EPOCH};

    /// Instante de prueba fijo (todas las pruebas usan la misma base).
    fn t(segundos: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000 + segundos)
    }

    /// Parámetros por defecto, sin puesta al día para que las notificaciones
    /// salgan enseguida (la puesta al día se prueba aparte).
    fn params() -> AlertsParams {
        AlertsParams {
            catch_up_minutes: 0,
            ..AlertsParams::default()
        }
    }

    fn motor(params: AlertsParams) -> AlertEngine {
        AlertEngine::new(params, EngineSnapshot::default())
    }

    fn equipo(id: i64, mac_random: bool, watched: bool) -> DeviceSignal {
        DeviceSignal {
            device_id: id,
            label: format!("equipo-{id}"),
            mac: format!("aa:bb:cc:dd:ee:{id:02x}"),
            mac_random,
            vendor: Some("ACME".to_string()),
            ip: format!("192.168.1.{id}"),
            hostname: None,
            watched,
            os_family: Some("linux".to_string()),
            device_type: "pc".to_string(),
            first_seen: t(0),
            last_seen: t(0),
            source: DeviceSource::Scan,
        }
    }

    fn evento(kind: EventKind, device: DeviceSignal, details: Value) -> Signal {
        Signal::Event(EventSignal {
            device,
            kind,
            details,
            event_id: Some(7),
        })
    }

    fn captura(stopped: bool, drops: Option<f32>) -> CaptureHealth {
        CaptureHealth {
            stopped,
            running: !stopped,
            reason: None,
            interface: "eth0".to_string(),
            drops_pct: drops,
            kernel_drops: 0,
            limit_drops: 0,
        }
    }

    fn salud(captura: CaptureHealth, db: DbSize) -> Signal {
        Signal::Health(HealthSample {
            capture: captura,
            db,
        })
    }

    fn salud_perdidas(porcentaje: f32) -> Signal {
        salud(captura(false, Some(porcentaje)), DbSize::default())
    }

    fn salud_parada(parada: bool) -> Signal {
        salud(captura(parada, None), DbSize::default())
    }

    fn salud_bd(bytes: u64, wal: u64, max_mb: u64) -> Signal {
        salud(
            captura(false, None),
            DbSize {
                db_bytes: bytes,
                wal_bytes: wal,
                max_db_mb: max_mb,
            },
        )
    }

    fn extraer_insert(acciones: &[AlertAction]) -> (&NewAlert, &Option<Notice>) {
        match acciones {
            [AlertAction::Insert { alert, notify }] => (alert, notify),
            otra => panic!("se esperaba un único Insert, llegó {otra:?}"),
        }
    }

    #[test]
    fn ac_motor_puro_sin_bd_equipo_nuevo_crea_y_notifica() {
        let mut motor = motor(params());
        let acciones = motor.handle(
            evento(EventKind::New, equipo(7, false, false), json!({})),
            t(10),
        );
        let (alerta, aviso) = extraer_insert(&acciones);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::DeviceNew));
        assert_eq!(alerta.level, Level::Important);
        assert_eq!(alerta.subject, Subject::Device(7));
        assert_eq!(alerta.device_id, Some(7));
        assert_eq!(alerta.title, "Equipo nuevo · MAC fija");
        assert_eq!(alerta.event_id, Some(7));
        assert!(alerta.details.get("porque").is_some());
        let aviso = aviso.as_ref().expect("debe haber notificación");
        assert_eq!(aviso.summary, "Almenara · Equipo nuevo");
        assert!(aviso.body.contains("MAC fija"));
    }

    #[test]
    fn ac_equipo_nuevo_con_mac_privada_baja_a_aviso_y_no_notifica() {
        let mut motor = motor(params());
        let acciones = motor.handle(
            evento(EventKind::New, equipo(8, true, false), json!({})),
            t(10),
        );
        let (alerta, aviso) = extraer_insert(&acciones);
        assert_eq!(alerta.level, Level::Warning);
        assert_eq!(alerta.title, "Equipo nuevo · MAC privada");
        assert!(aviso.is_none());
    }

    #[test]
    fn los_detalles_del_equipo_nuevo_son_los_del_catalogo() {
        let mut motor = motor(params());
        let mut device = equipo(9, false, false);
        device.hostname = Some("tv-sala".to_string());
        let acciones = motor.handle(evento(EventKind::New, device, json!({})), t(10));
        let (alerta, _) = extraer_insert(&acciones);
        assert_eq!(alerta.details["mac"], "aa:bb:cc:dd:ee:09");
        assert_eq!(alerta.details["mac_random"], false);
        assert_eq!(alerta.details["vendor"], "ACME");
        assert_eq!(alerta.details["ip"], "192.168.1.9");
        assert_eq!(alerta.details["source"], "scan");
        assert_eq!(alerta.details["hostname"], "tv-sala");
    }

    #[test]
    fn ac_linea_base_suprime_los_equipos_del_primer_ciclo() {
        let snapshot = EngineSnapshot {
            devices_empty: true,
            ..EngineSnapshot::default()
        };
        let mut motor = AlertEngine::new(params(), snapshot);
        assert!(motor.baseline_active());
        let acciones = motor.handle(
            evento(EventKind::New, equipo(1, false, false), json!({})),
            t(0),
        );
        assert!(acciones.is_empty());
        motor.end_baseline();
        assert!(!motor.baseline_active());
        let acciones = motor.handle(
            evento(EventKind::New, equipo(1, false, false), json!({})),
            t(10),
        );
        assert_eq!(acciones.len(), 1);
    }

    #[test]
    fn ac_dedup_una_fila_con_count_dos_dentro_de_veinticuatro_horas() {
        let mut motor = motor(params());
        let primera = motor.handle(
            evento(EventKind::New, equipo(3, false, false), json!({})),
            t(0),
        );
        let (alerta, _) = extraer_insert(&primera);
        let clave = alerta.dedup_key().expect("regla configurable");
        motor.inserted(&clave, 42);
        // Una hora después: repetición de la misma fila.
        let segunda = motor.handle(
            evento(EventKind::New, equipo(3, false, false), json!({})),
            t(3_600),
        );
        match &segunda[..] {
            [AlertAction::Repeat {
                id, at, reactivate, ..
            }] => {
                assert_eq!(*id, 42);
                assert_eq!(*at, t(3_600));
                assert!(!reactivate);
            }
            otra => panic!("se esperaba Repeat, llegó {otra:?}"),
        }
    }

    #[test]
    fn ac_el_plazo_de_veinticuatro_horas_se_cuenta_desde_created_at() {
        let mut motor = motor(params());
        let primera = motor.handle(
            evento(EventKind::New, equipo(4, false, false), json!({})),
            t(0),
        );
        let (alerta, _) = extraer_insert(&primera);
        motor.inserted(&alerta.dedup_key().expect("regla"), 5);
        // A las 25 h del alta ya es una alerta nueva.
        let acciones = motor.handle(
            evento(EventKind::New, equipo(4, false, false), json!({})),
            t(25 * 3_600),
        );
        assert!(matches!(acciones[..], [AlertAction::Insert { .. }]));
    }

    #[test]
    fn ac_condicion_de_captura_parada_se_resuelve_y_reactiva() {
        let mut motor = motor(params());
        let alta = motor.handle(salud_parada(true), t(0));
        let (alerta, aviso) = extraer_insert(&alta);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::CaptureStopped));
        assert_eq!(alerta.title, "Captura parada");
        assert!(aviso.is_some(), "captura parada es importante");
        motor.inserted(&alerta.dedup_key().expect("regla"), 11);
        // Sigue parada: ninguna acción nueva.
        assert!(motor.handle(salud_parada(true), t(60)).is_empty());
        // Vuelve a capturar: se resuelve.
        assert_eq!(
            motor.handle(salud_parada(false), t(120)),
            vec![AlertAction::Resolve { id: 11, at: t(120) }]
        );
        // Se vuelve a parar dentro de 24 h: se reactiva la misma fila.
        match &motor.handle(salud_parada(true), t(180))[..] {
            [AlertAction::Repeat { id, reactivate, .. }] => {
                assert_eq!(*id, 11);
                assert!(reactivate);
            }
            otra => panic!("se esperaba Repeat reactivado, llegó {otra:?}"),
        }
    }

    #[test]
    fn ac_apagar_una_regla_resuelve_sus_condiciones_activas() {
        let mut motor = motor(params());
        let alta = motor.handle(salud_parada(true), t(0));
        let (alerta, _) = extraer_insert(&alta);
        motor.inserted(&alerta.dedup_key().expect("regla"), 12);
        let mut ajuste = RuleSetting::default_for(RuleId::CaptureStopped);
        ajuste.enabled = false;
        let acciones = motor.set_rule(RuleId::CaptureStopped, ajuste, t(30));
        assert_eq!(acciones, vec![AlertAction::Resolve { id: 12, at: t(30) }]);
        // Con la regla apagada no vuelve a saltar.
        assert!(motor.handle(salud_parada(true), t(60)).is_empty());
    }

    #[test]
    fn ac_en_modo_degradado_la_captura_no_avisa_de_parada() {
        let mut motor = motor(params());
        let degradado = CaptureStats {
            enabled: true,
            privileged: false,
            running: false,
            interface: "eth0".to_string(),
            ..CaptureStats::default()
        };
        let muestra = Health::sample(&degradado, &DbSize::default(), t(0));
        assert!(motor.handle(Signal::Health(muestra), t(0)).is_empty());
        // Con CAP_NET_RAW y sin capturar sí avisa.
        let privilegiado = CaptureStats {
            privileged: true,
            ..degradado
        };
        let muestra = Health::sample(&privilegiado, &DbSize::default(), t(60));
        assert_eq!(motor.handle(Signal::Health(muestra), t(60)).len(), 1);
    }

    #[test]
    fn ac_perdidas_de_captura_cinco_minutos_seguidos() {
        let mut motor = motor(params());
        for minuto in 0..4 {
            assert!(
                motor.handle(salud_perdidas(2.0), t(minuto * 60)).is_empty(),
                "aún no son 5 minutos"
            );
        }
        let alta = motor.handle(salud_perdidas(2.0), t(4 * 60));
        let (alerta, aviso) = extraer_insert(&alta);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::CaptureDrops));
        assert_eq!(alerta.level, Level::Warning);
        assert!(aviso.is_none(), "un aviso no notifica");
        assert_eq!(alerta.details["percent"], 2.0);
        assert_eq!(alerta.details["minutes"], 5);
        motor.inserted(&alerta.dedup_key().expect("regla"), 21);
        // Cuatro minutos por debajo: todavía no se resuelve.
        for minuto in 5..9 {
            assert!(motor.handle(salud_perdidas(0.2), t(minuto * 60)).is_empty());
        }
        // Quinto minuto seguido por debajo: resuelta.
        assert_eq!(
            motor.handle(salud_perdidas(0.2), t(9 * 60)),
            vec![AlertAction::Resolve {
                id: 21,
                at: t(9 * 60)
            }]
        );
    }

    #[test]
    fn ac_base_de_datos_grande_salta_y_se_resuelve_al_bajar() {
        let mut motor = motor(params());
        let alta = motor.handle(salud_bd(900_000_000, 200_000_000, 1024), t(0));
        let (alerta, aviso) = extraer_insert(&alta);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::DbSize));
        assert_eq!(alerta.level, Level::Warning);
        assert!(aviso.is_none());
        assert_eq!(alerta.details["db_bytes"], 900_000_000_u64);
        assert_eq!(alerta.details["wal_bytes"], 200_000_000_u64);
        assert_eq!(alerta.details["max_db_mb"], 1024_u64);
        motor.inserted(&alerta.dedup_key().expect("regla"), 31);
        // Sigue por encima: nada.
        assert!(motor
            .handle(salud_bd(900_000_000, 200_000_000, 1024), t(3_600))
            .is_empty());
        // Baja del límite: resuelta.
        assert_eq!(
            motor.handle(salud_bd(500_000_000, 10_000_000, 1024), t(7_200)),
            vec![AlertAction::Resolve {
                id: 31,
                at: t(7_200)
            }]
        );
    }

    #[test]
    fn ac_vigilado_ausente_y_vuelta() {
        let mut motor = motor(params());
        // Sincroniza el arranque de la sesión.
        assert!(motor.tick(t(0)).is_empty());
        let mut caida = equipo(20, false, true);
        caida.last_seen = t(500);
        let alta = motor.handle(
            evento(
                EventKind::Disappeared,
                caida,
                json!({"last_seen": "2020-01-01T00:00:00Z"}),
            ),
            t(1_000),
        );
        let (alerta, aviso) = extraer_insert(&alta);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::WatchedPresence));
        assert_eq!(alerta.title, "Vigilado ausente");
        assert_eq!(alerta.details["state"], "gone");
        assert_eq!(alerta.details["while_closed"], false);
        assert!(aviso.is_none());
        motor.inserted(&alerta.dedup_key().expect("regla"), 41);
        // Vuelve tras 41 minutos.
        let mut vuelta = equipo(20, false, true);
        vuelta.last_seen = t(3_460);
        let acciones = motor.handle(
            evento(
                EventKind::Reappeared,
                vuelta,
                json!({"away_s": 2_460, "away_since": "2020-01-01T00:00:00Z"}),
            ),
            t(3_460),
        );
        assert_eq!(acciones.len(), 2, "resolver y avisar de la vuelta");
        assert_eq!(
            acciones[0],
            AlertAction::Resolve {
                id: 41,
                at: t(3_460)
            }
        );
        match &acciones[1] {
            AlertAction::Insert { alert, .. } => {
                assert_eq!(alert.key, "back");
                assert_eq!(alert.title, "Vigilado de vuelta tras 41 min");
                assert_eq!(alert.details["away_s"], 2_460_u64);
            }
            otra => panic!("se esperaba Insert de vuelta, llegó {otra:?}"),
        }
    }

    #[test]
    fn vigilado_ausente_mientras_almenara_estaba_cerrada() {
        let mut motor = motor(params());
        // La sesión arranca en t(100).
        assert!(motor.tick(t(100)).is_empty());
        let mut nas = equipo(21, false, true);
        nas.last_seen = t(50); // antes del arranque
        let acciones = motor.handle(evento(EventKind::Disappeared, nas, json!({})), t(200));
        let (alerta, _) = extraer_insert(&acciones);
        assert_eq!(alerta.details["while_closed"], true);
        assert!(alerta.details["porque"]
            .as_str()
            .unwrap_or("")
            .contains("mientras Almenara estaba cerrada"));
    }

    #[test]
    fn desmarcar_un_vigilado_resuelve_su_ausencia() {
        let mut motor = motor(params());
        assert!(motor.tick(t(0)).is_empty());
        let nas = equipo(22, false, true);
        let alta = motor.handle(evento(EventKind::Disappeared, nas, json!({})), t(100));
        let (alerta, _) = extraer_insert(&alta);
        motor.inserted(&alerta.dedup_key().expect("regla"), 51);
        assert_eq!(
            motor.set_watched(22, false, t(200)),
            vec![AlertAction::Resolve { id: 51, at: t(200) }]
        );
        // Y una nueva ausencia de un equipo no vigilado no avisa.
        let mut otro = equipo(23, false, false);
        otro.last_seen = t(150);
        assert!(motor
            .handle(evento(EventKind::Disappeared, otro, json!({})), t(300))
            .is_empty());
    }

    #[test]
    fn un_equipo_no_vigilado_no_genera_alertas_de_presencia() {
        let mut motor = motor(params());
        assert!(motor
            .handle(
                evento(EventKind::Reappeared, equipo(24, false, false), json!({})),
                t(0)
            )
            .is_empty());
    }

    #[test]
    fn ac_puerto_nuevo_y_reabierto() {
        let mut motor = motor(params());
        let acciones = motor.handle(
            evento(
                EventKind::ServiceNew,
                equipo(25, false, false),
                json!({"port": 22, "protocol": "tcp", "service": "ssh", "reopened": false}),
            ),
            t(0),
        );
        let (alerta, aviso) = extraer_insert(&acciones);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::PortNew));
        assert_eq!(alerta.level, Level::Important);
        assert_eq!(alerta.key, "22/tcp");
        assert_eq!(alerta.title, "Puerto nuevo: 22/tcp (ssh)");
        assert_eq!(alerta.details["port"], 22_u64);
        assert_eq!(alerta.details["protocol"], "tcp");
        assert_eq!(alerta.details["service"], "ssh");
        assert_eq!(alerta.details["reopened"], false);
        assert!(aviso.is_some());
        motor.inserted(&alerta.dedup_key().expect("regla"), 26);
        // El 22 se reabre más tarde: nueva fila (clave distinta de la anterior
        // solo si ya pasó el plazo).
        let acciones = motor.handle(
            evento(
                EventKind::ServiceNew,
                equipo(25, false, false),
                json!({"port": 22, "protocol": "tcp", "service": "ssh", "reopened": true}),
            ),
            t(25 * 3_600),
        );
        let (alerta, _) = extraer_insert(&acciones);
        assert_eq!(alerta.title, "Puerto reabierto: 22/tcp (ssh)");
        assert_eq!(alerta.details["reopened"], true);
    }

    #[test]
    fn ac_cambios_de_nombre_so_y_tipo_llevan_su_porque() {
        let mut motor = motor(params());
        for (kind, details, titulo) in [
            (
                EventKind::HostnameChanged,
                json!({"before": "diskstation", "after": "nas"}),
                "Cambio de nombre: diskstation → nas",
            ),
            (
                EventKind::OsChanged,
                json!({"before": "linux", "after": "windows", "os_source": "dhcp"}),
                "Cambio de SO: linux → windows",
            ),
            (
                EventKind::TypeChanged,
                json!({"before": "iot", "after": "tv"}),
                "Cambio de tipo: iot → tv",
            ),
            (
                EventKind::MacChanged,
                json!({"before": "aa:bb:cc:dd:ee:01", "after": "aa:bb:cc:dd:ee:02", "reason": "rotation"}),
                "Cambio de MAC: aa:bb:cc:dd:ee:01 → aa:bb:cc:dd:ee:02",
            ),
        ] {
            let acciones = motor.handle(evento(kind, equipo(26, false, false), details), t(0));
            let (alerta, _) = extraer_insert(&acciones);
            assert_eq!(alerta.title, titulo);
            assert!(!alerta
                .details
                .get("porque")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty());
        }
    }

    #[test]
    fn ac_app_nueva_solo_cuando_el_sujeto_ha_aprendido() {
        let mut motor = motor(params());
        let aprendiz = SeenSignal {
            subject: Subject::Host,
            subject_label: "[host]".to_string(),
            learned: false,
            learned_at: None,
            items: vec![SeenNew {
                kind: SeenKind::App,
                key: "steam".to_string(),
                label: "Steam".to_string(),
                first_seen: t(0),
            }],
        };
        assert!(motor
            .handle(Signal::Seen(aprendiz.clone()), t(0))
            .is_empty());
        let mut aprendido = aprendiz;
        aprendido.learned = true;
        aprendido.learned_at = Some(t(0));
        let acciones = motor.handle(Signal::Seen(aprendido), t(100));
        let (alerta, aviso) = extraer_insert(&acciones);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::NewApp));
        assert_eq!(alerta.level, Level::Info);
        assert_eq!(alerta.subject, Subject::Host);
        assert_eq!(alerta.title, "App nueva: Steam");
        assert_eq!(alerta.key, "steam");
        assert_eq!(alerta.details["kind"], "app");
        assert!(aviso.is_none());
        assert!(alerta.details["porque"].as_str().is_some());
    }

    #[test]
    fn las_claves_especiales_y_vacias_nunca_son_alerta() {
        let mut motor = motor(params());
        let visto = SeenSignal {
            subject: Subject::Host,
            subject_label: "[host]".to_string(),
            learned: true,
            learned_at: Some(t(0)),
            items: vec![
                SeenNew {
                    kind: SeenKind::App,
                    key: "~otros".to_string(),
                    label: "Otros".to_string(),
                    first_seen: t(0),
                },
                SeenNew {
                    kind: SeenKind::Org,
                    key: String::new(),
                    label: String::new(),
                    first_seen: t(0),
                },
            ],
        };
        assert!(motor.handle(Signal::Seen(visto), t(0)).is_empty());
    }

    #[test]
    fn las_reglas_de_lo_nuevo_cubren_todos_los_tipos() {
        let mut motor = motor(params());
        let visto = SeenSignal {
            subject: Subject::Host,
            subject_label: "[host]".to_string(),
            learned: true,
            learned_at: Some(t(0)),
            items: vec![
                SeenNew {
                    kind: SeenKind::Category,
                    key: "video".to_string(),
                    label: "Vídeo".to_string(),
                    first_seen: t(0),
                },
                SeenNew {
                    kind: SeenKind::Country,
                    key: "IE".to_string(),
                    label: "Irlanda (IE)".to_string(),
                    first_seen: t(0),
                },
                SeenNew {
                    kind: SeenKind::Org,
                    key: "cloudflare".to_string(),
                    label: "Cloudflare".to_string(),
                    first_seen: t(0),
                },
                SeenNew {
                    kind: SeenKind::Ja4,
                    key: "t13d1516h2_8daaf6152771_02713d6af863".to_string(),
                    label: String::new(),
                    first_seen: t(0),
                },
            ],
        };
        let acciones = motor.handle(Signal::Seen(visto), t(0));
        let reglas: Vec<RuleId> = acciones
            .iter()
            .filter_map(|accion| match accion {
                AlertAction::Insert { alert, .. } => alert.rule.rule_id(),
                _ => None,
            })
            .collect();
        assert_eq!(
            reglas,
            vec![
                RuleId::NewCategory,
                RuleId::NewCountry,
                RuleId::NewOrg,
                RuleId::NewJa4
            ]
        );
    }

    fn hora_cerrada(down: u64, up: u64, muestras: &[(u64, u64)]) -> Signal {
        Signal::HourClosed(HourClosedSignal {
            hour_start: 1_790_000_000,
            subjects: vec![HourSubject {
                subject: Subject::Host,
                label: "este-equipo".to_string(),
                down,
                up,
                samples: muestras.to_vec(),
            }],
        })
    }

    #[test]
    fn ac_mas_trafico_de_lo_habitual_con_la_mediana() {
        let mb = 1_000_000_u64;
        let muestras: Vec<(u64, u64)> = (0..5).map(|_| (400 * mb, 10 * mb)).collect();
        let mut motor = motor(params());
        let acciones = motor.handle(hora_cerrada(2_400 * mb, 10 * mb, &muestras), t(0));
        let (alerta, aviso) = extraer_insert(&acciones);
        assert_eq!(alerta.rule, AlertRule::Rule(RuleId::TrafficHigh));
        assert_eq!(alerta.level, Level::Warning);
        assert_eq!(alerta.key, "down");
        assert_eq!(alerta.title, "Más tráfico de lo habitual ↓ ×6");
        assert_eq!(alerta.subject_label, "este-equipo");
        assert_eq!(alerta.details["direction"], "down");
        assert_eq!(alerta.details["value"], 2_400 * mb);
        assert_eq!(alerta.details["median"], 400 * mb);
        assert_eq!(alerta.details["samples"], 5_u64);
        assert_eq!(alerta.details["factor"], 6.0);
        assert!(alerta.details["porque"]
            .as_str()
            .unwrap_or("")
            .contains("Bajada de 2,4 GB"));
        assert!(aviso.is_none());
    }

    #[test]
    fn ac_trafico_alto_de_un_equipo_y_de_la_red() {
        let mb = 1_000_000_u64;
        let muestras: Vec<(u64, u64)> = (0..5).map(|_| (400 * mb, 10 * mb)).collect();
        let mut motor = motor(params());
        let signal = Signal::HourClosed(HourClosedSignal {
            hour_start: 1_790_000_000,
            subjects: vec![
                HourSubject {
                    subject: Subject::Device(200),
                    label: "nas".to_string(),
                    down: 2_400 * mb,
                    up: 10 * mb,
                    samples: muestras.clone(),
                },
                HourSubject {
                    subject: Subject::Network,
                    label: "Toda la red".to_string(),
                    down: 5_000 * mb,
                    up: 10 * mb,
                    samples: muestras,
                },
            ],
        });
        let acciones = motor.handle(signal, t(0));
        let sujetos: Vec<(Subject, String)> = acciones
            .iter()
            .filter_map(|accion| match accion {
                AlertAction::Insert { alert, .. } => {
                    Some((alert.subject, alert.subject_label.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            sujetos,
            vec![
                (Subject::Device(200), "nas".to_string()),
                (Subject::Network, "Toda la red".to_string()),
            ]
        );
    }

    #[test]
    fn ac_sin_cinco_muestras_no_hay_aviso() {
        let mb = 1_000_000_u64;
        let muestras: Vec<(u64, u64)> = (0..4).map(|_| (400 * mb, 10 * mb)).collect();
        let mut motor = motor(params());
        assert!(motor
            .handle(hora_cerrada(4_000 * mb, 10 * mb, &muestras), t(0))
            .is_empty());
    }

    #[test]
    fn la_subida_tiene_su_propio_minimo() {
        let mb = 1_000_000_u64;
        let muestras: Vec<(u64, u64)> = (0..5).map(|_| (400 * mb, 10 * mb)).collect();
        let mut motor = motor(params());
        // 40 MB de subida: no llega al mínimo de 50 MB.
        assert!(motor
            .handle(hora_cerrada(400 * mb, 40 * mb, &muestras), t(0))
            .is_empty());
        // 60 MB: 6 veces la mediana de 10 MB y por encima del mínimo.
        let acciones = motor.handle(hora_cerrada(400 * mb, 60 * mb, &muestras), t(60));
        let (alerta, _) = extraer_insert(&acciones);
        assert_eq!(alerta.key, "up");
        assert_eq!(alerta.title, "Más tráfico de lo habitual ↑ ×6");
    }

    #[test]
    fn ac_la_repeticion_guarda_el_valor_mayor() {
        let mb = 1_000_000_u64;
        let muestras: Vec<(u64, u64)> = (0..5).map(|_| (400 * mb, 10 * mb)).collect();
        let mut motor = motor(params());
        let primera = motor.handle(hora_cerrada(2_400 * mb, 10 * mb, &muestras), t(0));
        let (alerta, _) = extraer_insert(&primera);
        motor.inserted(&alerta.dedup_key().expect("regla"), 61);
        // 3 GB: mayor, se guarda.
        match &motor.handle(hora_cerrada(3_000 * mb, 10 * mb, &muestras), t(3_600))[..] {
            [AlertAction::Repeat { details, .. }] => {
                assert_eq!(details["value"], 3_000 * mb);
            }
            otra => panic!("se esperaba Repeat, llegó {otra:?}"),
        }
        // 1,5 GB: menor, se conserva el valor mayor.
        match &motor.handle(hora_cerrada(1_500 * mb, 10 * mb, &muestras), t(7_200))[..] {
            [AlertAction::Repeat { details, .. }] => {
                assert_eq!(details["value"], 3_000 * mb);
            }
            otra => panic!("se esperaba Repeat, llegó {otra:?}"),
        }
    }

    #[test]
    fn ac_puesta_al_dia_resume_al_terminar() {
        let mut params = params();
        params.catch_up_minutes = 10;
        let mut motor = motor(params);
        assert!(motor.tick(t(0)).is_empty());
        assert!(motor.in_catch_up(t(1)), "arranque");
        let primera = motor.handle(
            evento(EventKind::New, equipo(30, false, false), json!({})),
            t(10),
        );
        let (alerta, aviso) = extraer_insert(&primera);
        assert!(aviso.is_none(), "durante la puesta al día no se notifica");
        motor.inserted(&alerta.dedup_key().expect("regla"), 71);
        // Otra alerta de aviso (puerto nuevo) para el recuento.
        let segunda = motor.handle(
            evento(
                EventKind::ServiceNew,
                equipo(30, false, false),
                json!({"port": 22, "protocol": "tcp", "service": "ssh", "reopened": false}),
            ),
            t(20),
        );
        let (alerta, _) = extraer_insert(&segunda);
        motor.inserted(&alerta.dedup_key().expect("regla"), 72);
        // Antes del fin no hay resumen.
        assert!(motor.tick(t(300)).is_empty());
        let acciones = motor.tick(t(10 * 60 + 1));
        assert_eq!(acciones.len(), 1);
        match &acciones[0] {
            AlertAction::InsertSummary {
                alert,
                grouped,
                notify,
            } => {
                assert_eq!(alert.rule, AlertRule::CatchUp);
                assert_eq!(alert.level, Level::Important);
                assert_eq!(alert.subject, Subject::Almenara);
                assert_eq!(alert.title, "Resumen al arrancar (2 alertas)");
                assert_eq!(grouped, &vec![71, 72]);
                assert_eq!(alert.details["total"], 2_u64);
                // Equipo nuevo y puerto nuevo son importantes por defecto.
                assert_eq!(alert.details["by_level"]["important"], 2_u64);
                assert_eq!(alert.details["by_level"]["warning"], 0_u64);
                assert!(alert.details["porque"]
                    .as_str()
                    .unwrap_or("")
                    .contains("2 alertas agrupadas: 2 importantes"));
                let aviso = notify
                    .as_ref()
                    .expect("hay una importante: notifica el resumen");
                assert_eq!(aviso.summary, "Almenara · Resumen al arrancar");
            }
            otra => panic!("se esperaba InsertSummary, llegó {otra:?}"),
        }
        // Un solo resumen por sesión.
        assert!(motor.tick(t(10 * 60 + 2)).is_empty());
        assert!(!motor.in_catch_up(t(10 * 60 + 2)));
    }

    #[test]
    fn la_puesta_al_dia_esta_activa_desde_el_arranque() {
        let mut con_puesta = params();
        con_puesta.catch_up_minutes = 10;
        let motor = AlertEngine::new(con_puesta, EngineSnapshot::default());
        assert!(motor.in_catch_up(t(0)));
        let motor = AlertEngine::new(params(), EngineSnapshot::default());
        assert!(!motor.in_catch_up(t(0)));
    }

    #[test]
    fn sin_puesta_al_dia_no_hay_resumen() {
        let mut motor = motor(params());
        motor.handle(
            evento(EventKind::New, equipo(31, false, false), json!({})),
            t(0),
        );
        assert!(motor.tick(t(3_600)).is_empty());
    }

    #[test]
    fn ac_tope_de_tres_notificaciones_y_liberacion_al_minuto() {
        let mut motor = motor(params());
        let mut notificadas = 0;
        for id in 40..44 {
            let acciones = motor.handle(
                evento(EventKind::New, equipo(id, false, false), json!({})),
                t(id as u64),
            );
            let (_, aviso) = extraer_insert(&acciones);
            if aviso.is_some() {
                notificadas += 1;
            }
        }
        assert_eq!(notificadas, 3, "solo salen 3 notificaciones por minuto");
        // Al cumplirse el minuto, la retenida sale agrupada.
        match &motor.tick(t(61))[..] {
            [AlertAction::Notify(aviso)] => {
                assert_eq!(aviso.summary, "Almenara · 1 alerta importante más");
            }
            otra => panic!("se esperaba Notify, llegó {otra:?}"),
        }
    }

    #[test]
    fn ac_horario_silencioso_no_notifica_pero_guarda_la_alerta() {
        let mut params = params();
        params.quiet_hours = super::super::QuietHours::parse("23:00-08:00").unwrap();
        let mut motor = motor(params);
        // A mediodía local sí notifica.
        let mediodia: SystemTime = chrono::Local
            .with_ymd_and_hms(2026, 11, 11, 12, 0, 0)
            .single()
            .expect("fecha válida")
            .into();
        let acciones = motor.handle(
            evento(EventKind::New, equipo(50, false, false), json!({})),
            mediodia,
        );
        let (_, aviso) = extraer_insert(&acciones);
        assert!(aviso.is_some());
        // De madrugada se guarda, pero no se notifica.
        let madrugada: SystemTime = chrono::Local
            .with_ymd_and_hms(2026, 11, 12, 2, 10, 0)
            .single()
            .expect("fecha válida")
            .into();
        let acciones = motor.handle(
            evento(EventKind::New, equipo(51, false, false), json!({})),
            madrugada,
        );
        let (_, aviso) = extraer_insert(&acciones);
        assert!(aviso.is_none());
    }

    #[test]
    fn ac_silencios_por_regla_y_sujeto() {
        let mut motor = motor(params());
        motor.set_mutes(vec![MuteState {
            rule: RuleId::DeviceNew,
            subject: Subject::Device(60),
            until: None,
        }]);
        assert!(motor
            .handle(
                evento(EventKind::New, equipo(60, false, false), json!({})),
                t(0)
            )
            .is_empty());
        // Otro equipo del mismo tipo sí avisa.
        assert_eq!(
            motor
                .handle(
                    evento(EventKind::New, equipo(61, false, false), json!({})),
                    t(10)
                )
                .len(),
            1
        );
        // Un silencio caducado se ignora.
        motor.set_mutes(vec![MuteState {
            rule: RuleId::DeviceNew,
            subject: Subject::Device(62),
            until: Some(t(100)),
        }]);
        assert!(!motor
            .handle(
                evento(EventKind::New, equipo(62, false, false), json!({})),
                t(200)
            )
            .is_empty());
    }

    #[test]
    fn ac_el_motor_apagado_no_crea_alertas() {
        let mut params = params();
        params.enabled = false;
        let mut motor = motor(params);
        assert!(motor
            .handle(
                evento(EventKind::New, equipo(70, false, false), json!({})),
                t(0)
            )
            .is_empty());
        motor.set_enabled(true);
        assert_eq!(
            motor
                .handle(
                    evento(EventKind::New, equipo(70, false, false), json!({})),
                    t(10)
                )
                .len(),
            1
        );
    }

    #[test]
    fn ac_el_snapshot_del_arranque_no_repite_alertas() {
        let clave = DedupKey::new(RuleId::DeviceNew, Subject::Device(80), "");
        let snapshot = EngineSnapshot {
            recent: vec![RecentState {
                key: clave.clone(),
                id: 88,
                created_at: t(0),
                last_at: t(0),
                active: true,
                details: json!({}),
            }],
            ..EngineSnapshot::default()
        };
        let mut motor = AlertEngine::new(params(), snapshot);
        match &motor.handle(
            evento(EventKind::New, equipo(80, false, false), json!({})),
            t(3_600),
        )[..]
        {
            [AlertAction::Repeat { id, .. }] => assert_eq!(*id, 88),
            otra => panic!("se esperaba Repeat del snapshot, llegó {otra:?}"),
        }
    }

    #[test]
    fn la_notificacion_escapa_el_marcado_y_quita_ansi() {
        let mut motor = motor(params());
        let mut device = equipo(90, false, false);
        device.label = "\u{1b}[1m<b>x</b>\u{1b}[0m".to_string();
        let acciones = motor.handle(evento(EventKind::New, device, json!({})), t(0));
        let (alerta, aviso) = extraer_insert(&acciones);
        assert_eq!(alerta.subject_label, "<b>x</b>");
        let aviso = aviso.as_ref().expect("notifica");
        assert!(aviso.body.contains("&lt;b&gt;x&lt;/b&gt;"));
        assert!(!aviso.body.contains('\u{1b}'));
    }

    #[test]
    fn las_claves_viejas_se_podan_sin_perder_las_condiciones_activas() {
        let mut motor = motor(params());
        let primera = motor.handle(
            evento(EventKind::New, equipo(105, false, false), json!({})),
            t(0),
        );
        let (alerta, _) = extraer_insert(&primera);
        motor.inserted(&alerta.dedup_key().expect("regla"), 1);
        // La condición de captura parada sigue activa aunque pase el plazo.
        let condicion = motor.handle(salud_parada(true), t(0));
        let (alerta, _) = extraer_insert(&condicion);
        motor.inserted(&alerta.dedup_key().expect("regla"), 2);
        // Pasadas 30 h, la clave de equipo nuevo ya no deduplica.
        assert!(motor.tick(t(30 * 3_600)).is_empty());
        match &motor.handle(
            evento(EventKind::New, equipo(105, false, false), json!({})),
            t(30 * 3_600),
        )[..]
        {
            [AlertAction::Insert { .. }] => {}
            otra => panic!("se esperaba Insert, llegó {otra:?}"),
        }
        // La condición activa no se ha podado: sigue sin generar nada nuevo.
        assert!(motor
            .handle(salud_parada(true), t(30 * 3_600 + 60))
            .is_empty());
    }

    #[test]
    fn inserted_del_resumen_no_rompe_nada() {
        // El resumen catch_up no tiene dedup_key: la TUI no llama inserted.
        // Aunque lo hiciera con una clave cualquiera, el motor no se rompe.
        let mut motor = motor(params());
        let clave = DedupKey::new(RuleId::DeviceNew, Subject::Almenara, "inventada");
        motor.inserted(&clave, 1);
        assert!(motor.tick(t(60)).is_empty());
    }

    #[test]
    fn una_insercion_que_nunca_se_apunta_caduca_y_vuelve_a_avisar() {
        let mut motor = motor(params());
        let primera = motor.handle(
            evento(EventKind::New, equipo(110, false, false), json!({})),
            t(0),
        );
        let (alerta, _) = extraer_insert(&primera);
        let _clave = alerta.dedup_key().expect("regla");
        // La TUI no consigue escribir la alerta ni llama inserted.
        assert!(motor.tick(t(16 * 60)).is_empty());
        // La clave se libera: una señal nueva vuelve a crear la alerta.
        let segunda = motor.handle(
            evento(EventKind::New, equipo(110, false, false), json!({})),
            t(16 * 60 + 60),
        );
        assert!(matches!(segunda[..], [AlertAction::Insert { .. }]));
    }

    #[test]
    fn un_inserted_tardio_registra_la_fila_para_deduplicar() {
        let mut motor = motor(params());
        assert!(motor.tick(t(0)).is_empty());
        // Llega el id de una alerta que la TUI escribió tarde.
        let clave = DedupKey::new(RuleId::DeviceNew, Subject::Device(111), "");
        motor.inserted(&clave, 123);
        match &motor.handle(
            evento(EventKind::New, equipo(111, false, false), json!({})),
            t(30),
        )[..]
        {
            [AlertAction::Repeat { id, .. }] => assert_eq!(*id, 123),
            otra => panic!("se esperaba Repeat, llegó {otra:?}"),
        }
    }

    /// Medición (checklist F6): `AlertEngine::handle` ≤ 1 ms por señal.
    ///
    /// `cargo test --release --bin almenara medir_ -- --ignored --nocapture --test-threads=1`
    #[test]
    #[ignore = "medición de rendimiento: requiere --release"]
    fn medir_alertas_motor() {
        const SENALES: u64 = 10_000;
        let mut motor = motor(params());
        let inicio = Instant::now();
        for indice in 0..SENALES {
            let _ = motor.handle(
                evento(
                    EventKind::New,
                    equipo(10_000 + indice as i64, false, false),
                    json!({}),
                ),
                t(indice),
            );
        }
        let total = inicio.elapsed();
        let por_senal = total / SENALES as u32;
        println!("medir_alertas_motor: {SENALES} señales en {total:?} ({por_senal:?} por señal)");
        assert!(
            por_senal <= Duration::from_millis(1),
            "handle debe tardar ≤ 1 ms por señal, tardó {por_senal:?}"
        );
    }

    /// Medición (checklist F6): evaluar una hora con 50 equipos y 14 días de
    /// muestras ≤ 20 ms.
    #[test]
    #[ignore = "medición de rendimiento: requiere --release"]
    fn medir_alertas_hora() {
        let mb = 1_000_000_u64;
        let muestras: Vec<(u64, u64)> = (0..14).map(|_| (400 * mb, 10 * mb)).collect();
        let subjects: Vec<HourSubject> = (1..=50)
            .map(|id| HourSubject {
                subject: Subject::Device(id),
                label: format!("equipo-{id}"),
                down: 2_400 * mb,
                up: 10 * mb,
                samples: muestras.clone(),
            })
            .collect();
        let mut motor = motor(params());
        let inicio = Instant::now();
        const REPETICIONES: u32 = 20;
        for _ in 0..REPETICIONES {
            let _ = motor.handle(
                Signal::HourClosed(HourClosedSignal {
                    hour_start: 1_790_000_000,
                    subjects: subjects.clone(),
                }),
                t(0),
            );
        }
        let total = inicio.elapsed();
        let por_hora = total / REPETICIONES;
        println!(
            "medir_alertas_hora: {REPETICIONES} horas de 50 equipos en {total:?} ({por_hora:?} por hora)"
        );
        assert!(
            por_hora <= Duration::from_millis(20),
            "evaluar una hora debe tardar ≤ 20 ms, tardó {por_hora:?}"
        );
    }

    /// Tamaño aproximado en bytes de un JSON, contando cadenas y contenedores.
    fn tamanio_json(valor: &Value) -> usize {
        use std::mem::size_of;
        match valor {
            Value::String(texto) => size_of::<Value>() + texto.capacity(),
            Value::Array(valores) => {
                size_of::<Value>()
                    + valores.capacity() * size_of::<Value>()
                    + valores.iter().map(tamanio_json).sum::<usize>()
            }
            Value::Object(mapa) => {
                size_of::<Value>()
                    + mapa.len() * (size_of::<String>() + size_of::<Value>())
                    + mapa
                        .iter()
                        .map(|(clave, valor)| clave.capacity() + tamanio_json(valor))
                        .sum::<usize>()
            }
            _ => size_of::<Value>(),
        }
    }

    /// Medición (checklist F6): memoria añadida por el motor ≤ 4 MB.
    ///
    /// Snapshot realista: 2 000 claves de deduplicación de 24 h, 30 silencios y
    /// 50 sujetos de aprendizaje, más el canal acotado del notificador (32
    /// avisos, estimado). La cifra es aproximada (size_of + capacity), no
    /// exacta al byte.
    #[test]
    #[ignore = "medición de memoria: requiere --release"]
    fn medir_alertas_memoria() {
        use std::mem::size_of;

        const CLAVES: u64 = 2_000;
        let mut recientes = Vec::with_capacity(CLAVES as usize);
        for id in 0..CLAVES {
            let rule = RuleId::ALL[(id as usize) % RuleId::ALL.len()];
            let subject = match id % 10 {
                0 => Subject::Host,
                1 => Subject::Network,
                _ => Subject::Device((id / 10) as i64 + 1),
            };
            let key = format!("clave-{id}-abcdefghijklmnop");
            let details = json!({
                "direction": "down",
                "hour": 1_790_000_000_i64,
                "value": 2_400_000_000_u64,
                "median": 400_000_000_u64,
                "factor": 6.0,
                "samples": 8,
                "mac": "aa:bb:cc:dd:ee:ff",
                "mac_random": false,
                "vendor": "ACME",
                "ip": "192.168.1.10",
                "source": "scan",
                "hostname": "equipo-de-prueba",
                "porque": "Bajada de 2,4 GB a las 21:00 · mediana de 400 MB en 8 días con datos (×6)",
            });
            recientes.push(RecentState {
                key: DedupKey::new(rule, subject, key),
                id: id as i64 + 1,
                created_at: t(0),
                last_at: t(0),
                active: false,
                details,
            });
        }
        let snapshot = EngineSnapshot {
            mutes: (0..30)
                .map(|id| MuteState {
                    rule: RuleId::ALL[id as usize % RuleId::ALL.len()],
                    subject: Subject::Device(id as i64 + 1),
                    until: None,
                })
                .collect(),
            learning: (0..50)
                .map(|id| LearningState {
                    subject: Subject::Device(id as i64 + 1),
                    learning_from: t(0),
                    data_days: 7,
                    learned_at: Some(t(0)),
                })
                .collect(),
            recent: recientes,
            devices_empty: false,
        };
        let motor = AlertEngine::new(params(), snapshot);
        let estado = &motor.estado;
        let mut bytes = 0usize;
        // Mapa y claves de deduplicación de 24 h: buckets + datos en el heap.
        bytes += size_of::<HashMap<DedupKey, RecentState>>();
        bytes += estado
            .recientes
            .capacity()
            .saturating_mul(size_of::<DedupKey>() + size_of::<RecentState>());
        for (clave, reciente) in &estado.recientes {
            bytes += clave.key.capacity()
                + reciente.key.key.capacity()
                + tamanio_json(&reciente.details);
        }
        // Inserciones pendientes (normalmente vacío).
        bytes += size_of::<HashMap<DedupKey, Pendiente>>();
        bytes += estado
            .pendientes
            .capacity()
            .saturating_mul(size_of::<DedupKey>() + size_of::<Pendiente>());
        for (clave, pendiente) in &estado.pendientes {
            bytes += clave.key.capacity()
                + pendiente.estado.key.key.capacity()
                + tamanio_json(&pendiente.estado.details);
        }
        // Silencios vigentes.
        bytes += estado.silencios.capacity() * size_of::<MuteState>();
        // Aprendizaje por sujeto.
        bytes += size_of::<HashMap<Subject, LearningState>>();
        bytes += estado
            .aprendizaje
            .capacity()
            .saturating_mul(size_of::<Subject>() + size_of::<LearningState>());
        // Política de notificación (ventana de un minuto) y puesta al día.
        bytes += size_of::<NotifyPolicy>() + 20 * size_of::<SystemTime>();
        bytes += size_of::<PuestaAlDia>();
        bytes += estado.puesta_al_dia.agrupadas.capacity() * size_of::<i64>();
        bytes += estado.puesta_al_dia.por_regla.len() * (size_of::<RuleId>() + size_of::<u32>());
        bytes += estado.puesta_al_dia.por_nivel.len() * (size_of::<Level>() + size_of::<u32>());
        // Canal acotado del notificador (32 avisos): resumen + cuerpo pequeños.
        bytes += 32 * (size_of::<Notice>() + 2 * 128);

        let mb = bytes as f64 / (1024.0 * 1024.0);
        println!(
            "medir_alertas_memoria: {mb:.2} MB (límite 4 MB; {} claves de 24 h, {} silencios, {} sujetos de aprendizaje; estimación con size_of + capacity, canal del notificador de 32 avisos incluido)",
            estado.recientes.len(),
            estado.silencios.len(),
            estado.aprendizaje.len()
        );
        assert!(
            mb <= 4.0,
            "memoria añadida {mb:.2} MB supera el límite de 4 MB"
        );
    }

    #[test]
    fn todos_los_detalles_llevan_el_porque() {
        let mut motor = motor(params());
        let mut total = 0;
        for signal in [
            evento(EventKind::New, equipo(100, false, false), json!({})),
            evento(
                EventKind::ServiceNew,
                equipo(100, false, false),
                json!({"port": 443, "protocol": "tcp", "service": "https", "reopened": false}),
            ),
            evento(
                EventKind::MacChanged,
                equipo(100, false, false),
                json!({"before": "aa:bb:cc:dd:ee:01", "after": "aa:bb:cc:dd:ee:02", "reason": "rotation"}),
            ),
            evento(
                EventKind::HostnameChanged,
                equipo(100, false, false),
                json!({"before": null, "after": "nas"}),
            ),
            evento(
                EventKind::OsChanged,
                equipo(100, false, false),
                json!({"before": "linux", "after": "windows", "os_source": "dhcp"}),
            ),
            evento(
                EventKind::TypeChanged,
                equipo(100, false, false),
                json!({"before": "iot", "after": "tv"}),
            ),
            salud_parada(true),
            salud_perdidas(2.0),
            salud_bd(2_000_000_000, 100_000_000, 1024),
        ] {
            for accion in motor.handle(signal, t(0)) {
                if let AlertAction::Insert { alert, .. } = accion {
                    let porque = alert
                        .details
                        .get("porque")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    assert!(
                        !porque.is_empty(),
                        "la regla {:?} no trae porqué",
                        alert.rule
                    );
                    assert!(porque.chars().count() <= 240);
                    total += 1;
                }
            }
        }
        assert!(total >= 8, "se han recogido {total}");
    }
}
