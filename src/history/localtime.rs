//! Día local ⇄ UTC con localtime_r de libc (ADR-56).
//!
//! Los rollups por día usan la fecha local como entero AAAAMMDD y las horas
//! viven en UTC; este módulo es la única frontera entre ambos mundos. Se usa
//! localtime_r/mktime de libc (ya en el stack) para respetar el cambio de hora
//! sin añadir dependencias de fechas: mktime con tm_isdst = -1 resuelve los
//! días de 23, 24 y 25 horas.

// Varias operaciones de esta API son parte del checklist de F5 y solo las usan
// las pruebas o la integración de la TUI; se permite dead_code como en los DAO
// de fases anteriores.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

/// Fecha local como entero AAAAMMDD (por ejemplo 20261111).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalDay(i32);

impl LocalDay {
    /// Construye un día local a partir de una fecha AAAAMMDD.
    pub fn from_aaaammdd(valor: i64) -> Option<Self> {
        let valor = i32::try_from(valor).ok()?;
        let anio = valor / 10_000;
        let mes = (valor / 100) % 100;
        let dia = valor % 100;
        if !(1970..=9999).contains(&anio) || !(1..=12).contains(&mes) || !(1..=31).contains(&dia) {
            return None;
        }
        Some(Self(valor))
    }

    /// Día local a partir de sus componentes.
    pub fn from_ymd(anio: i32, mes: u32, dia: u32) -> Option<Self> {
        if !(1970..=9999).contains(&anio) || !(1..=12).contains(&mes) || !(1..=31).contains(&dia) {
            return None;
        }
        Some(Self(anio * 10_000 + mes as i32 * 100 + dia as i32))
    }

    /// Fecha AAAAMMDD.
    pub fn aaaammdd(self) -> i64 {
        i64::from(self.0)
    }

    /// Año.
    pub fn anio(self) -> i32 {
        self.0 / 10_000
    }

    /// Mes (1-12).
    pub fn mes(self) -> u32 {
        ((self.0 / 100) % 100) as u32
    }

    /// Día del mes (1-31).
    pub fn dia(self) -> u32 {
        (self.0 % 100) as u32
    }

    /// Día local que contiene el instante indicado.
    pub fn from_unix(segundos: i64) -> Self {
        let tm = local_tm(segundos);
        Self((tm.tm_year + 1900) * 10_000 + (tm.tm_mon + 1) * 100 + tm.tm_mday)
    }

    /// Día local actual.
    pub fn today() -> Self {
        Self::from_unix(now_unix())
    }

    /// Día local que contiene el inicio de la hora UTC indicada.
    pub fn from_hour(hora_utc: i64) -> Self {
        Self::from_unix(hora_utc)
    }

    /// Límites UTC del día local: [inicio, fin) en segundos Unix.
    ///
    /// Con mktime y tm_isdst = -1 el resultado respeta el cambio de hora: el día
    /// dura 23, 24 o 25 horas según corresponda.
    pub fn limits(self) -> (i64, i64) {
        let mut tm: libc::tm = sin_tm();
        tm.tm_year = self.anio() - 1900;
        tm.tm_mon = self.mes() as i32 - 1;
        tm.tm_mday = self.dia() as i32;
        tm.tm_hour = 0;
        tm.tm_min = 0;
        tm.tm_sec = 0;
        tm.tm_isdst = -1;
        let inicio = mktime(&mut tm);

        let mut siguiente: libc::tm = sin_tm();
        siguiente.tm_year = self.anio() - 1900;
        siguiente.tm_mon = self.mes() as i32 - 1;
        siguiente.tm_mday = self.dia() as i32 + 1;
        siguiente.tm_hour = 0;
        siguiente.tm_min = 0;
        siguiente.tm_sec = 0;
        siguiente.tm_isdst = -1;
        let fin = mktime(&mut siguiente);
        (inicio, fin)
    }

    /// Horas UTC cuyo inicio cae dentro del día local, en orden.
    ///
    /// La primera hora puede empezar antes de la medianoche local si la zona
    /// tiene un desfase de media hora; en ese caso la hora cuenta entera para el
    /// día que contiene su inicio.
    pub fn hours(self) -> Vec<i64> {
        let (inicio, fin) = self.limits();
        let primera = inicio - inicio.rem_euclid(3600);
        let mut horas = Vec::new();
        let mut hora = primera;
        while hora < fin {
            if Self::from_hour(hora) == self {
                horas.push(hora);
            }
            hora += 3600;
        }
        horas
    }

    /// Número de días que lo separan de otro día local.
    pub fn dias_hasta(self, otro: Self) -> i64 {
        let (a, _) = self.limits();
        let (b, _) = otro.limits();
        (b - a) / 86_400
    }

    /// Suma días naturales al día local (con otro mes o año si hace falta).
    pub fn sumar_dias(self, dias: i64) -> Self {
        let (inicio, _) = self.limits();
        Self::from_unix(inicio + dias * 86_400)
    }

    /// Etiqueta corta «12 oct».
    pub fn label_corto(self) -> String {
        const MESES: [&str; 12] = [
            "ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic",
        ];
        format!("{} {}", self.dia(), MESES[(self.mes() - 1) as usize])
    }
}

/// Instante actual en segundos Unix UTC.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Inicio del minuto UTC que contiene el instante indicado.
pub fn minute_start(segundos: i64) -> i64 {
    segundos - segundos.rem_euclid(60)
}

/// Inicio de la hora UTC que contiene el instante indicado.
pub fn hour_start(segundos: i64) -> i64 {
    segundos - segundos.rem_euclid(3600)
}

/// Hora local (0-23) del instante indicado.
pub fn local_hour(segundos: i64) -> i32 {
    local_tm(segundos).tm_hour
}

/// Minuto local (0-59) del instante indicado.
pub fn local_minute(segundos: i64) -> i32 {
    local_tm(segundos).tm_min
}

/// Etiqueta «HH:MM» en hora local del instante indicado.
pub fn format_hora_local(segundos: i64) -> String {
    let tm = local_tm(segundos);
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

/// Etiqueta «HH:MM» en UTC del instante indicado.
pub fn format_hora_utc(segundos: i64) -> String {
    let restante = segundos.rem_euclid(86_400);
    format!("{:02}:{:02}", restante / 3600, (restante % 3600) / 60)
}

/// Etiqueta «lun 3 nov» en hora local del instante indicado.
pub fn format_dia_local(segundos: i64) -> String {
    const DIAS: [&str; 7] = ["dom", "lun", "mar", "mié", "jue", "vie", "sáb"];
    const MESES: [&str; 12] = [
        "ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic",
    ];
    let tm = local_tm(segundos);
    let dia_semana = ((tm.tm_wday % 7 + 7) % 7) as usize;
    format!(
        "{} {} {}",
        DIAS[dia_semana],
        tm.tm_mday,
        MESES[(((tm.tm_mon % 12) + 12) % 12) as usize]
    )
}

/// Inicio de la semana local (lunes a las 00:00) que contiene el instante.
pub fn week_start(segundos: i64) -> i64 {
    let tm = local_tm(segundos);
    let dia_semana = ((tm.tm_wday % 7 + 7) % 7) as i64; // 0 = domingo
    let dias_desde_lunes = (dia_semana + 6) % 7;
    let inicio_dia = local_midnight_of(segundos);
    inicio_dia - dias_desde_lunes * 86_400
}

/// Medianoche local del día que contiene el instante, en segundos Unix.
pub fn local_midnight_of(segundos: i64) -> i64 {
    LocalDay::from_unix(segundos).limits().0
}

/// Reconstruye la fecha RFC 3339 UTC de un instante Unix.
pub fn rfc3339(segundos: i64) -> String {
    match chrono::DateTime::from_timestamp(segundos, 0) {
        Some(fecha) => fecha.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => String::new(),
    }
}

/// Convierte una fecha RFC 3339 a segundos Unix.
pub fn unix_de_rfc3339(texto: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(texto)
        .ok()
        .map(|fecha| fecha.timestamp())
}

fn sin_tm() -> libc::tm {
    // SAFETY: tm es un struct POD de libc; cero es un valor válido.
    unsafe { std::mem::zeroed() }
}

/// Convierte segundos Unix a hora local descompuesta con localtime_r.
fn local_tm(segundos: i64) -> libc::tm {
    let mut tm = sin_tm();
    let tiempo: libc::time_t = segundos as libc::time_t;
    // SAFETY: localtime_r escribe en el tm local y es reentrante.
    unsafe {
        libc::localtime_r(&tiempo, &mut tm);
    }
    tm
}

/// Convierte una hora local descompuesta a segundos Unix con mktime.
fn mktime(tm: &mut libc::tm) -> i64 {
    // SAFETY: mktime solo lee y normaliza el tm indicado.
    unsafe { libc::mktime(tm) as i64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    // tzset no está expuesta por el crate libc; se declara como en C. setenv
    // solo cambia la variable: hay que refrescar la zona a mano.
    extern "C" {
        fn tzset();
    }

    #[test]
    fn rfc3339_ida_y_vuelta() {
        let segundos = 1_760_000_000;
        let texto = rfc3339(segundos);
        assert_eq!(unix_de_rfc3339(&texto), Some(segundos));
        assert_eq!(unix_de_rfc3339("no es una fecha"), None);
    }

    #[test]
    fn minutos_y_horas_se_alinean() {
        assert_eq!(minute_start(1_760_000_123), 1_760_000_100);
        assert_eq!(hour_start(1_760_000_123), 1_759_996_800);
        assert_eq!(minute_start(1_760_000_100), 1_760_000_100);
    }

    #[test]
    fn los_limites_del_dia_contienen_el_dia() {
        // Propiedad válida en cualquier zona horaria: el inicio pertenece al día,
        // el fin no, y el día dura entre 23 y 25 horas.
        let dia = LocalDay::from_unix(1_760_000_123);
        let (inicio, fin) = dia.limits();
        assert_eq!(LocalDay::from_unix(inicio), dia);
        assert_ne!(LocalDay::from_unix(fin), dia);
        let duracion = fin - inicio;
        assert!(
            (23 * 3600..=25 * 3600).contains(&duracion),
            "duración inesperada: {duracion}"
        );
    }

    #[test]
    fn las_horas_del_dia_pertenecen_al_dia() {
        let dia = LocalDay::from_unix(1_760_000_123);
        let horas = dia.hours();
        assert!((23..=25).contains(&horas.len()));
        for hora in &horas {
            assert_eq!(LocalDay::from_hour(*hora), dia);
        }
    }

    #[test]
    fn los_dias_del_cambio_de_hora_duran_23_y_25_horas() {
        // La zona se fija solo durante este test, bajo un mutex: Europe/Madrid y
        // Europe/Prague comparten las fechas de cambio de hora y el resto de
        // pruebas no dependen de la zona concreta.
        static BLOQUEO: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guardia = BLOQUEO.lock().unwrap_or_else(|error| error.into_inner());
        let original = std::env::var_os("TZ");
        let fijar_zona = |zona: &str| {
            let valor = std::ffi::CString::new(zona).expect("zona sin ceros");
            // SAFETY: setenv/tzset son las funciones de la libc para fijar TZ.
            unsafe {
                libc::setenv(c"TZ".as_ptr(), valor.as_ptr(), 1);
                tzset();
            }
        };
        let restaurar = || {
            // SAFETY: mismas funciones que arriba; se restaura la variable.
            unsafe {
                match &original {
                    Some(valor) => {
                        let valor =
                            std::ffi::CString::new(valor.to_string_lossy().as_bytes().to_vec())
                                .expect("TZ sin ceros");
                        libc::setenv(c"TZ".as_ptr(), valor.as_ptr(), 1);
                    }
                    None => {
                        libc::unsetenv(c"TZ".as_ptr());
                    }
                }
                tzset();
            }
        };

        fijar_zona("Europe/Madrid");
        // 25 de octubre de 2026: termina el horario de verano (día de 25 h).
        let largo = LocalDay::from_ymd(2026, 10, 25).expect("día válido");
        let (inicio, fin) = largo.limits();
        assert_eq!(fin - inicio, 25 * 3600, "el día debe sumar 25 horas");
        assert_eq!(largo.hours().len(), 25);
        // 29 de marzo de 2026: empieza el horario de verano (día de 23 h).
        let corto = LocalDay::from_ymd(2026, 3, 29).expect("día válido");
        let (inicio, fin) = corto.limits();
        assert_eq!(fin - inicio, 23 * 3600, "el día debe sumar 23 horas");
        assert_eq!(corto.hours().len(), 23);
        restaurar();
    }

    #[test]
    fn sumar_dias_cruza_meses() {
        let dia = LocalDay::from_ymd(2026, 1, 31).unwrap();
        assert_eq!(dia.sumar_dias(1), LocalDay::from_ymd(2026, 2, 1).unwrap());
        assert_eq!(dia.dias_hasta(dia.sumar_dias(5)), 5);
    }

    #[test]
    fn fechas_invalidas_se_rechazan() {
        assert_eq!(LocalDay::from_aaaammdd(20261301), None);
        assert_eq!(LocalDay::from_aaaammdd(0), None);
    }
}
