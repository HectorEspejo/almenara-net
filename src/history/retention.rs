//! Purga por resolución y compactación (§7.4).
//!
//! Calcula los cortes de cada resolución a partir de la retención configurada y
//! del primer minuto sin consolidar. El DAO aplica esos cortes en una sola
//! pasada y devuelve PurgeStats para la pestaña Config.

use crate::history::{LocalDay, Retention};

/// Cortes de la purga, en los formatos que usa el SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cortes {
    /// Corte de minutos por antigüedad (segundos Unix UTC).
    pub minutos: i64,
    /// Corte fijo de destinos por minuto: 2 h.
    pub minutos_destinos: i64,
    /// Corte de horas (segundos Unix UTC).
    pub horas: i64,
    /// Corte de destinos por hora (segundos Unix UTC); None = no guardar destinos.
    pub horas_destinos: Option<i64>,
    /// Corte de días (fecha local AAAAMMDD).
    pub dias: i64,
    /// Corte de inventario y sesiones (RFC 3339 UTC).
    pub dias_rfc3339: String,
}

/// Calcula los cortes de la purga.
///
/// sin_consolidar es el inicio de la primera hora pendiente; ningún minuto
/// anterior a ese corte se purga aunque supere la retención (§7.4).
pub fn calcular(ahora: i64, retention: &Retention, sin_consolidar: i64, hoy: LocalDay) -> Cortes {
    let corte_minutos = ahora - i64::from(retention.minute_days) * 86_400;
    let corte_horas = ahora - i64::from(retention.hour_days) * 86_400;
    let dia_limite = hoy.sumar_dias(-i64::from(retention.day_days));
    let corte_dias = LocalDay::from_unix(ahora - i64::from(retention.day_days) * 86_400);
    let horas_destinos = if retention.destination_days == 0 {
        None
    } else {
        Some(ahora - i64::from(retention.destination_days) * 86_400)
    };
    Cortes {
        minutos: corte_minutos.min(sin_consolidar),
        minutos_destinos: (ahora - 2 * 3600).min(sin_consolidar),
        horas: corte_horas,
        horas_destinos,
        dias: dia_limite.aaaammdd(),
        dias_rfc3339: crate::history::localtime::rfc3339(corte_dias.limits().0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cortes_por_defecto() {
        let hoy = LocalDay::from_ymd(2026, 11, 11).unwrap();
        let ahora: i64 = 1_800_000_000;
        let hace_hora = ahora - ahora.rem_euclid(3600);
        let cortes = calcular(ahora, &Retention::default(), hace_hora, hoy);
        assert_eq!(cortes.minutos, ahora - 2 * 86_400);
        assert_eq!(cortes.minutos_destinos, ahora - 7200);
        assert_eq!(cortes.horas, ahora - 90 * 86_400);
        assert_eq!(cortes.horas_destinos, Some(ahora - 30 * 86_400));
        assert_eq!(
            cortes.dias,
            hoy.sumar_dias(-730).aaaammdd(),
            "el corte de días es local y va en AAAAMMDD"
        );
        assert!(cortes.dias_rfc3339.ends_with('Z'));
    }

    #[test]
    fn los_minutos_sin_consolidar_no_se_purgan() {
        let hoy = LocalDay::from_ymd(2026, 11, 11).unwrap();
        let ahora = 1_800_000_000;
        // Una hora sin consolidar de hace tres días es más antigua que la
        // retención de minutos: el corte no puede adelantarse a ella.
        let pendiente = ahora - 3 * 86_400;
        let cortes = calcular(ahora, &Retention::default(), pendiente, hoy);
        assert_eq!(cortes.minutos, pendiente);
        assert_eq!(cortes.minutos_destinos, pendiente);
    }

    #[test]
    fn destination_days_cero_no_guarda_destinos_por_hora() {
        let hoy = LocalDay::from_ymd(2026, 11, 11).unwrap();
        let retention = Retention {
            destination_days: 0,
            ..Retention::default()
        };
        let cortes = calcular(1_800_000_000, &retention, 1_800_000_000, hoy);
        assert_eq!(cortes.horas_destinos, None);
    }
}
