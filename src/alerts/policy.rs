//! Política de notificación: niveles, puesta al día, horario y tope (§7.2).
//!
//! Solo las alertas **importantes** llegan al escritorio. Durante la puesta al
//! día (§7.9) no se notifica nada: todo se agrupa en el resumen final. Fuera de
//! ella, el horario silencioso y el tope de notificaciones por minuto deciden si
//! la alerta sale ahora, se retiene para el final del minuto o se queda solo en
//! la TUI.

use std::time::{Duration, SystemTime};

use chrono::{DateTime, Local, Timelike};

use super::{AlertsParams, Level};

/// Minutos que dura la ventana del tope de notificaciones (§7.2).
const VENTANA_TOPE: Duration = Duration::from_secs(60);

/// Decisión de la política de notificación para una alerta importante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyDecision {
    /// No notificar (nivel no importante, notificaciones apagadas u horario).
    No,
    /// Agrupar en el resumen de la puesta al día (§7.9).
    Summary,
    /// Retener por el tope de notificaciones por minuto (§7.2).
    RateLimited,
    /// Notificar ahora.
    Notify,
}

/// Horario silencioso «HH:MM-HH:MM» en hora local (§7.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuietHours {
    /// Minuto del día en que empieza (0-1439).
    pub start_min: u16,
    /// Minuto del día en que termina (0-1439).
    pub end_min: u16,
}

impl QuietHours {
    /// Parsea «HH:MM-HH:MM»; `Ok(None)` si la cadena está vacía.
    pub fn parse(s: &str) -> Result<Option<Self>, String> {
        let limpio = s.trim();
        if limpio.is_empty() {
            return Ok(None);
        }
        let (inicio, fin) = limpio.split_once('-').ok_or_else(|| {
            format!("horario silencioso sin «-» entre la hora de inicio y la de fin: «{s}»")
        })?;
        let start_min = parse_minuto(inicio)
            .ok_or_else(|| format!("hora de inicio del horario silencioso inválida: «{s}»"))?;
        let end_min = parse_minuto(fin)
            .ok_or_else(|| format!("hora de fin del horario silencioso inválida: «{s}»"))?;
        if start_min == end_min {
            return Err(format!(
                "el horario silencioso no puede empezar y acabar a la misma hora: «{s}»"
            ));
        }
        Ok(Some(Self { start_min, end_min }))
    }

    /// Indica si una hora local cae dentro del horario (cruza medianoche).
    pub fn contains(&self, hour: u8, minute: u8) -> bool {
        let ahora = u16::from(hour) * 60 + u16::from(minute);
        if self.start_min < self.end_min {
            // Horario normal: [inicio, fin).
            ahora >= self.start_min && ahora < self.end_min
        } else {
            // Cruza la medianoche: [inicio, 24:00) ∪ [00:00, fin).
            ahora >= self.start_min || ahora < self.end_min
        }
    }

    /// Indica si un instante cae dentro del horario, en hora local.
    pub fn contains_at(&self, now: SystemTime) -> bool {
        let local: DateTime<Local> = now.into();
        self.contains(local.hour() as u8, local.minute() as u8)
    }

    /// Texto «HH:MM-HH:MM» del horario.
    pub fn as_string(&self) -> String {
        format!(
            "{:02}:{:02}-{:02}:{:02}",
            self.start_min / 60,
            self.start_min % 60,
            self.end_min / 60,
            self.end_min % 60
        )
    }
}

/// Parsea «HH:MM» a minutos del día (0-1439).
fn parse_minuto(texto: &str) -> Option<u16> {
    let (hora, minuto) = texto.trim().split_once(':')?;
    if hora.is_empty() || hora.len() > 2 || minuto.is_empty() || minuto.len() > 2 {
        return None;
    }
    if !hora.bytes().all(|b| b.is_ascii_digit()) || !minuto.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hora: u16 = hora.parse().ok()?;
    let minuto: u16 = minuto.parse().ok()?;
    if hora > 23 || minuto > 59 {
        return None;
    }
    Some(hora * 60 + minuto)
}

/// Estado de la política de notificación de una sesión.
#[derive(Debug, Clone, Default)]
pub struct NotifyPolicy {
    /// Notificaciones de escritorio encendidas.
    activas: bool,
    /// Horario silencioso configurado, si lo hay.
    quiet_hours: Option<QuietHours>,
    /// Tope de notificaciones por minuto.
    max_por_minuto: u32,
    /// Minutos de puesta al día configurados (0 = sin ella).
    catch_up_minutes: u32,
    /// Instantes de las notificaciones enviadas en el último minuto.
    enviadas: Vec<SystemTime>,
    /// Notificaciones retenidas por el tope, a la espera del fin del minuto.
    retenidas: u32,
    /// Fin de la puesta al día, mientras dure.
    catch_up_end: Option<SystemTime>,
    /// La puesta al día ya ha terminado (o no existía).
    catch_up_done: bool,
    /// La política ya ha tomado su instante de arranque.
    started: bool,
}

impl NotifyPolicy {
    /// Crea la política con los parámetros activos y arranca la puesta al día.
    #[allow(dead_code)] // API del contrato; el motor orquesta start/reload/decide.
    pub fn new(params: &AlertsParams, now: SystemTime) -> Self {
        let mut politica = Self::default();
        politica.reload(params);
        politica.start(now);
        politica
    }

    /// Toma el instante de arranque (idempotente): fija el fin de la puesta al
    /// día. Lo llama el motor en el primer `handle` o `tick` porque `new` no
    /// recibe el reloj.
    pub fn start(&mut self, now: SystemTime) {
        if self.started {
            return;
        }
        self.started = true;
        if self.catch_up_minutes > 0 {
            let minutos = u64::from(self.catch_up_minutes);
            self.catch_up_end = Some(now + Duration::from_secs(minutos * 60));
            self.catch_up_done = false;
        } else {
            self.catch_up_end = None;
            self.catch_up_done = true;
        }
    }

    /// Indica si ya se ha tomado el instante de arranque.
    pub fn started(&self) -> bool {
        self.started
    }

    /// Decide qué hacer con una alerta de un nivel (§7.2).
    pub fn decide(&mut self, level: Level, now: SystemTime) -> NotifyDecision {
        if level != Level::Important || !self.activas {
            return NotifyDecision::No;
        }
        if self.in_catch_up(now) {
            return NotifyDecision::Summary;
        }
        if self.en_hora_silenciosa(now) {
            return NotifyDecision::No;
        }
        self.limpiar_enviadas(now);
        if self.enviadas.len() >= self.max_por_minuto as usize {
            self.retenidas = self.retenidas.saturating_add(1);
            return NotifyDecision::RateLimited;
        }
        self.enviadas.push(now);
        NotifyDecision::Notify
    }

    /// Libera las notificaciones retenidas por el tope al cumplirse el minuto.
    ///
    /// Devuelve el texto de la notificación agrupada («3 alertas importantes
    /// más») o `None` si no hay nada retenido o si para entonces ha empezado el
    /// horario silencioso (en ese caso se quedan retenidas).
    #[allow(dead_code)] // API del contrato; el motor usa sus piezas.
    pub fn tick(&mut self, now: SystemTime) -> Option<String> {
        if self.in_catch_up(now) {
            return None;
        }
        self.catch_up_done = true;
        if self.en_hora_silenciosa(now) {
            return None;
        }
        let retenidas = self.tomar_retenidas(now)?;
        Some(texto_retenidas(retenidas))
    }

    /// Como `tick`, pero devuelve el número de notificaciones retenidas.
    pub fn tomar_retenidas(&mut self, now: SystemTime) -> Option<u32> {
        if self.retenidas == 0 || self.en_hora_silenciosa(now) {
            return None;
        }
        Some(std::mem::take(&mut self.retenidas))
    }

    /// Fin de la puesta al día, mientras siga en curso.
    pub fn catch_up_ends(&self) -> Option<SystemTime> {
        if self.catch_up_done {
            None
        } else {
            self.catch_up_end
        }
    }

    /// Marca la puesta al día como terminada (el motor ya emitió el resumen).
    pub fn mark_catch_up_done(&mut self) {
        self.catch_up_end = None;
        self.catch_up_done = true;
    }

    /// Indica si sigue la puesta al día.
    pub fn in_catch_up(&self, now: SystemTime) -> bool {
        match self.catch_up_end {
            Some(fin) if !self.catch_up_done => now < fin,
            _ => false,
        }
    }

    /// Indica si el instante cae en el horario silencioso.
    pub fn en_hora_silenciosa(&self, now: SystemTime) -> bool {
        self.quiet_hours
            .map(|horario| horario.contains_at(now))
            .unwrap_or(false)
    }

    /// Decisión para la única notificación del resumen de la puesta al día.
    pub fn decide_resumen(&mut self, now: SystemTime) -> NotifyDecision {
        self.decide(Level::Important, now)
    }

    /// Horario silencioso configurado.
    #[allow(dead_code)] // API del contrato: la TUI la usará en Config.
    pub fn quiet_hours(&self) -> Option<QuietHours> {
        self.quiet_hours
    }

    /// Recarga los parámetros (quiet_hours, tope…).
    ///
    /// No toca la puesta al día ni las notificaciones ya contadas: un cambio de
    /// configuración a mitad de sesión no reinicia el minuto.
    pub fn reload(&mut self, params: &AlertsParams) {
        self.activas = params.enabled && params.desktop_notifications;
        self.quiet_hours = params.quiet_hours;
        self.max_por_minuto = params.max_notifications_per_minute;
        self.catch_up_minutes = params.catch_up_minutes;
    }

    /// Descarta las notificaciones enviadas hace más de un minuto.
    fn limpiar_enviadas(&mut self, now: SystemTime) {
        self.enviadas
            .retain(|enviada| diferencia_abs(now, *enviada) < VENTANA_TOPE);
    }
}

/// Texto de la notificación agrupada por el tope (§7.2).
pub fn texto_retenidas(retenidas: u32) -> String {
    if retenidas == 1 {
        "1 alerta importante más".to_string()
    } else {
        format!("{retenidas} alertas importantes más")
    }
}

/// Diferencia absoluta entre dos instantes (§7.17: el reloj puede ir hacia atrás).
fn diferencia_abs(a: SystemTime, b: SystemTime) -> Duration {
    a.duration_since(b)
        .or_else(|_| b.duration_since(a))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeZone};

    /// Instante local de una fecha fija, para pruebas deterministas.
    fn instante(hora: u32, minuto: u32) -> SystemTime {
        Local
            .with_ymd_and_hms(2026, 11, 11, hora, minuto, 0)
            .single()
            .expect("fecha local válida")
            .into()
    }

    fn params() -> AlertsParams {
        // Sin puesta al día salvo en las pruebas que la piden expresamente.
        AlertsParams {
            catch_up_minutes: 0,
            ..AlertsParams::default()
        }
    }

    #[test]
    fn parse_devuelve_none_con_cadena_vacia() {
        assert_eq!(QuietHours::parse("").unwrap(), None);
        assert_eq!(QuietHours::parse("   ").unwrap(), None);
    }

    #[test]
    fn parse_horario_normal() {
        let horario = QuietHours::parse("23:00-08:00").unwrap().unwrap();
        assert_eq!(horario.start_min, 23 * 60);
        assert_eq!(horario.end_min, 8 * 60);
        assert_eq!(horario.as_string(), "23:00-08:00");
    }

    #[test]
    fn parse_rechaza_horarios_invalidos() {
        for invalido in [
            "23:00",
            "23:00-",
            "-08:00",
            "25:00-08:00",
            "23:60-08:00",
            "ab:00-08:00",
            "23:00-23:00",
            "23:00-08:00-01:00",
        ] {
            assert!(
                QuietHours::parse(invalido).is_err(),
                "«{invalido}» debería rechazarse"
            );
        }
    }

    #[test]
    fn ac_horario_que_cruza_la_medianoche() {
        // AC: con quiet_hours = "23:00-08:00", a las 02:10 está activo y a las
        // 08:00 no.
        let horario = QuietHours::parse("23:00-08:00").unwrap().unwrap();
        assert!(horario.contains(2, 10));
        assert!(horario.contains(23, 0));
        assert!(horario.contains(0, 0));
        assert!(horario.contains(7, 59));
        assert!(!horario.contains(8, 0));
        assert!(!horario.contains(12, 0));
        assert!(!horario.contains(22, 59));
        // Y también sobre un instante con hora local.
        assert!(horario.contains_at(instante(2, 10)));
        assert!(!horario.contains_at(instante(8, 0)));
    }

    #[test]
    fn horario_normal_no_cruza_la_medianoche() {
        let horario = QuietHours::parse("13:30-15:00").unwrap().unwrap();
        assert!(!horario.contains(13, 29));
        assert!(horario.contains(13, 30));
        assert!(horario.contains(14, 59));
        assert!(!horario.contains(15, 0));
        assert!(!horario.contains(2, 0));
    }

    #[test]
    fn no_notifican_los_niveles_inferiores() {
        let mut politica = NotifyPolicy::new(&params(), instante(12, 0));
        assert_eq!(
            politica.decide(Level::Info, instante(12, 1)),
            NotifyDecision::No
        );
        assert_eq!(
            politica.decide(Level::Warning, instante(12, 1)),
            NotifyDecision::No
        );
    }

    #[test]
    fn con_notificaciones_apagadas_no_hay_nada() {
        let mut p = params();
        p.desktop_notifications = false;
        let mut politica = NotifyPolicy::new(&p, instante(12, 0));
        assert_eq!(
            politica.decide(Level::Important, instante(20, 0)),
            NotifyDecision::No
        );
    }

    #[test]
    fn puesta_al_dia_agrupa_en_resumen_y_no_notifica() {
        let mut p = params();
        p.catch_up_minutes = 10;
        let arranque = instante(10, 0);
        let mut politica = NotifyPolicy::new(&p, arranque);
        assert!(politica.in_catch_up(arranque));
        assert_eq!(
            politica.decide(Level::Important, arranque),
            NotifyDecision::Summary
        );
        // Al pasar los 10 minutos, la puesta al día termina y ya notifica.
        let fin = arranque + Duration::from_secs(10 * 60);
        assert!(!politica.in_catch_up(fin));
        assert_eq!(
            politica.decide(Level::Important, fin),
            NotifyDecision::Notify
        );
    }

    #[test]
    fn catch_up_cero_no_hay_puesta_al_dia() {
        let mut p = params();
        p.catch_up_minutes = 0;
        let mut politica = NotifyPolicy::new(&p, instante(10, 0));
        assert!(!politica.in_catch_up(instante(10, 0)));
        assert_eq!(politica.catch_up_ends(), None);
        assert_eq!(
            politica.decide(Level::Important, instante(10, 0)),
            NotifyDecision::Notify
        );
    }

    #[test]
    fn catch_up_ends_marca_el_fin_hasta_cerrarla() {
        let mut p = params();
        p.catch_up_minutes = 10;
        let arranque = instante(10, 0);
        let mut politica = NotifyPolicy::new(&p, arranque);
        assert!(politica.catch_up_ends().is_some());
        politica.mark_catch_up_done();
        assert_eq!(politica.catch_up_ends(), None);
        assert!(!politica.in_catch_up(arranque));
    }

    #[test]
    fn ac_horario_silencioso_no_notifica_y_guarda_la_alerta() {
        let mut p = params();
        p.quiet_hours = QuietHours::parse("23:00-08:00").unwrap();
        let mut politica = NotifyPolicy::new(&p, instante(12, 0));
        assert_eq!(
            politica.decide(Level::Important, instante(2, 10)),
            NotifyDecision::No
        );
        // A las 12:00 ya notifica.
        assert_eq!(
            politica.decide(Level::Important, instante(12, 0)),
            NotifyDecision::Notify
        );
    }

    #[test]
    fn tope_de_tres_por_minuto_y_liberacion_al_minuto() {
        let p = params();
        let base = instante(12, 0);
        let mut politica = NotifyPolicy::new(&p, base);
        for i in 0..3 {
            assert_eq!(
                politica.decide(Level::Important, base + Duration::from_secs(i)),
                NotifyDecision::Notify,
                "la notificación {i} debería salir"
            );
        }
        // La cuarta se retiene.
        assert_eq!(
            politica.decide(Level::Important, base + Duration::from_secs(3)),
            NotifyDecision::RateLimited
        );
        assert_eq!(
            politica.decide(Level::Important, base + Duration::from_secs(4)),
            NotifyDecision::RateLimited
        );
        // Al cumplirse el minuto salen juntas.
        let liberada = politica.tick(base + Duration::from_secs(61));
        assert_eq!(liberada.as_deref(), Some("2 alertas importantes más"));
        // Y el contador vuelve a cero.
        assert_eq!(
            politica.tomar_retenidas(base + Duration::from_secs(61)),
            None
        );
        // Ya se puede notificar otra vez.
        assert_eq!(
            politica.decide(Level::Important, base + Duration::from_secs(61)),
            NotifyDecision::Notify
        );
    }

    #[test]
    fn el_horario_silencioso_retrasa_la_liberacion_del_tope() {
        let mut p = params();
        p.catch_up_minutes = 0;
        p.quiet_hours = QuietHours::parse("23:00-08:00").unwrap();
        let mut politica = NotifyPolicy::new(&p, instante(22, 58));
        for i in 0..3 {
            assert_eq!(
                politica.decide(Level::Important, instante(22, 58) + Duration::from_secs(i)),
                NotifyDecision::Notify
            );
        }
        assert_eq!(
            politica.decide(Level::Important, instante(22, 58) + Duration::from_secs(5)),
            NotifyDecision::RateLimited
        );
        // A las 23:01 el horario silencioso está activo: no se liberan.
        assert_eq!(politica.tick(instante(23, 1)), None);
        // A las 08:00 vuelven a salir.
        assert_eq!(
            politica.tick(instante(8, 0)).as_deref(),
            Some("1 alerta importante más")
        );
    }

    #[test]
    fn un_cambio_de_reloj_hacia_atras_no_bloquea_el_tope_para_siempre() {
        let p = params();
        let base = instante(12, 0);
        let mut politica = NotifyPolicy::new(&p, base);
        // Tres notificaciones "en el futuro" respecto al instante siguiente.
        for i in 0..3 {
            politica.decide(Level::Important, base - Duration::from_secs(i));
        }
        // Con el reloj dos minutos por detrás, la ventana se limpia y notifica.
        assert_eq!(
            politica.decide(Level::Important, base - Duration::from_secs(120)),
            NotifyDecision::Notify
        );
    }

    #[test]
    fn el_texto_de_las_retenidas_concuerda_en_numero() {
        assert_eq!(texto_retenidas(1), "1 alerta importante más");
        assert_eq!(texto_retenidas(7), "7 alertas importantes más");
    }
}
