//! Detección de la suspensión del equipo (§7.10 / ADR-73).
//!
//! Compara `CLOCK_BOOTTIME` (cuenta la suspensión) con `CLOCK_MONOTONIC` (no la
//! cuenta) entre dos ticks; si la primera avanza más de 60 s por encima de la
//! segunda, el equipo estuvo suspendido. El hueco se guarda ya cerrado con el
//! reloj de pared de los dos ticks. Un cambio del reloj de pared (NTP, cambio de
//! hora) no afecta a esos dos relojes y, por tanto, no crea huecos.

use std::time::{Duration, SystemTime};

/// Segundos de diferencia entre los dos relojes que delatan una suspensión.
const UMBRAL_SUSPENSION: Duration = Duration::from_secs(60);

/// Suspensión detectada, con el reloj de pared de los dos ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suspension {
    /// Instante (reloj de pared) del tick anterior.
    pub from: SystemTime,
    /// Instante (reloj de pared) del tick actual.
    pub to: SystemTime,
}

impl Suspension {
    /// Duración del hueco según el reloj de pared (puede ir hacia atrás).
    #[allow(dead_code)] // La usará el hilo de la TUI al guardar el hueco.
    pub fn duration(&self) -> Duration {
        self.to
            .duration_since(self.from)
            .or_else(|_| self.from.duration_since(self.to))
            .unwrap_or_default()
    }
}

/// Detector de suspensión por relojes del kernel.
#[derive(Debug, Clone, Default)]
pub struct Suspend {
    /// Referencia del tick anterior: (BOOTTIME, MONOTONIC, reloj de pared).
    anterior: Option<(Duration, Duration, SystemTime)>,
}

impl Suspend {
    /// Crea el detector (el primer tick solo toma la referencia).
    pub fn new() -> Self {
        Self::default()
    }

    /// Comprueba si ha habido suspensión desde el tick anterior.
    pub fn detect(&mut self) -> Option<Suspension> {
        Some(self.observar(
            leer_reloj(libc::CLOCK_BOOTTIME)?,
            leer_reloj(libc::CLOCK_MONOTONIC)?,
            SystemTime::now(),
        ))
        .flatten()
    }

    /// Lógica del detector con los relojes ya leídos (pruebas deterministas).
    fn observar(
        &mut self,
        boottime: Duration,
        monotonic: Duration,
        wall: SystemTime,
    ) -> Option<Suspension> {
        let anterior = self.anterior.replace((boottime, monotonic, wall));
        let (boot_antes, mono_antes, wall_antes) = anterior?;
        let avance_boot = diferencia(boottime, boot_antes);
        let avance_mono = diferencia(monotonic, mono_antes);
        if avance_boot > avance_mono + UMBRAL_SUSPENSION {
            return Some(Suspension {
                from: wall_antes,
                to: wall,
            });
        }
        None
    }
}

/// Lee un reloj del kernel en forma de duración desde su origen.
fn leer_reloj(reloj: libc::clockid_t) -> Option<Duration> {
    // SAFETY: timespec es un tipo POD y el puntero es válido durante la llamada.
    let mut instante = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let resultado = unsafe { libc::clock_gettime(reloj, &mut instante) };
    if resultado != 0 || instante.tv_sec < 0 {
        return None;
    }
    Some(Duration::new(
        instante.tv_sec as u64,
        instante.tv_nsec.clamp(0, 999_999_999) as u32,
    ))
}

/// Diferencia absoluta entre dos lecturas de un mismo reloj.
fn diferencia(actual: Duration, anterior: Duration) -> Duration {
    actual
        .checked_sub(anterior)
        .or_else(|| anterior.checked_sub(actual))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reloj de pared fijo para las pruebas.
    fn pared(segundos: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(segundos)
    }

    #[test]
    fn el_primer_tick_solo_toma_la_referencia() {
        let mut detector = Suspend::new();
        assert_eq!(
            detector.observar(
                Duration::from_secs(100),
                Duration::from_secs(50),
                pared(1_000)
            ),
            None
        );
    }

    #[test]
    fn sin_suspension_los_dos_relojes_avanzan_igual() {
        let mut detector = Suspend::new();
        detector.observar(
            Duration::from_secs(100),
            Duration::from_secs(50),
            pared(1_000),
        );
        // Un tick normal de 1 s.
        assert_eq!(
            detector.observar(
                Duration::from_secs(101),
                Duration::from_secs(51),
                pared(1_001)
            ),
            None
        );
    }

    #[test]
    fn ac_suspension_de_ocho_horas() {
        let mut detector = Suspend::new();
        detector.observar(
            Duration::from_secs(1_000),
            Duration::from_secs(500),
            pared(1_000),
        );
        // 8 h de suspensión: BOOTTIME avanza 8 h, MONOTONIC no.
        let suspension = detector
            .observar(
                Duration::from_secs(29_801),
                Duration::from_secs(501),
                pared(29_801),
            )
            .expect("debe detectar la suspensión");
        assert_eq!(suspension.from, pared(1_000));
        assert_eq!(suspension.to, pared(29_801));
        assert_eq!(suspension.duration(), Duration::from_secs(28_801));
    }

    #[test]
    fn hace_falta_mas_de_sesenta_segundos_de_diferencia() {
        let mut detector = Suspend::new();
        detector.observar(
            Duration::from_secs(1_000),
            Duration::from_secs(500),
            pared(1_000),
        );
        // 60 s justos de diferencia: no es suspensión.
        assert_eq!(
            detector.observar(
                Duration::from_secs(1_061),
                Duration::from_secs(501),
                pared(1_061)
            ),
            None
        );
        // 61 s: sí.
        let mut detector = Suspend::new();
        detector.observar(
            Duration::from_secs(1_000),
            Duration::from_secs(500),
            pared(1_000),
        );
        assert!(detector
            .observar(
                Duration::from_secs(1_062),
                Duration::from_secs(501),
                pared(1_062)
            )
            .is_some());
    }

    #[test]
    fn ac_un_cambio_del_reloj_de_pared_no_crea_hueco() {
        let mut detector = Suspend::new();
        detector.observar(
            Duration::from_secs(1_000),
            Duration::from_secs(500),
            pared(10_000),
        );
        // NTP adelanta el reloj de pared una hora, pero los dos relojes del
        // kernel siguen avanzando un segundo.
        assert_eq!(
            detector.observar(
                Duration::from_secs(1_001),
                Duration::from_secs(501),
                pared(13_600)
            ),
            None
        );
        // Y si el reloj de pared va hacia atrás, tampoco.
        let mut detector = Suspend::new();
        detector.observar(
            Duration::from_secs(1_000),
            Duration::from_secs(500),
            pared(10_000),
        );
        assert_eq!(
            detector.observar(
                Duration::from_secs(1_001),
                Duration::from_secs(501),
                pared(9_000)
            ),
            None
        );
    }

    #[test]
    fn un_cambio_de_reloj_de_pared_no_oculta_una_suspension_real() {
        let mut detector = Suspend::new();
        detector.observar(
            Duration::from_secs(1_000),
            Duration::from_secs(500),
            pared(10_000),
        );
        // Suspensión de 1 h y además el reloj de pared se atrasa 10 min.
        let suspension = detector
            .observar(
                Duration::from_secs(4_601),
                Duration::from_secs(501),
                pared(9_400),
            )
            .expect("los relojes del kernel delatan la suspensión");
        assert_eq!(suspension.from, pared(10_000));
        assert_eq!(suspension.to, pared(9_400));
        // La duración del hueco no depende del sentido del reloj de pared.
        assert_eq!(suspension.duration(), Duration::from_secs(600));
    }
}
