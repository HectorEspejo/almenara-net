//! Aprendizaje de 7 días con datos (§7.3).
//!
//! Un sujeto (un equipo o el propio equipo) aprende mientras acumula días con
//! datos. Un día cuenta si Almenara tuvo al menos 1 h de cobertura de tráfico
//! (sesiones con captura menos los huecos, §7.10) y el sujeto tuvo tráfico en
//! `TRAFFIC_ROLLUP_DAY`. El motor solo decide qué es un día con datos; el
//! recuento y la persistencia son del DAO (`Repo::update_learning`).

/// Parámetros del aprendizaje.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LearningParams {
    /// Días con datos antes de avisar de lo nuevo (`learning_days`).
    pub learning_days: u32,
}

impl Default for LearningParams {
    fn default() -> Self {
        Self { learning_days: 7 }
    }
}

/// Reglas del aprendizaje de un sujeto (ADR-70).
#[derive(Debug, Clone, Copy, Default)]
pub struct Learning;

impl Learning {
    /// Segundos de cobertura de tráfico que debe tener un día para contar.
    pub const COBERTURA_MINIMA_S: u32 = 3600;

    /// Día con datos: al menos 1 h de cobertura de tráfico y bytes del sujeto.
    pub fn is_data_day(coverage_s: u32, subject_bytes: u64) -> bool {
        coverage_s >= Self::COBERTURA_MINIMA_S && subject_bytes > 0
    }

    /// Indica si un sujeto con `data_days` días ha terminado de aprender.
    #[allow(dead_code)] // API para el DAO de aprendizaje (datos).
    pub fn is_learned(data_days: u32, learning_days: u32) -> bool {
        data_days >= learning_days
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_dia_sin_cobertura_no_cuenta() {
        assert!(!Learning::is_data_day(0, 1_000_000));
        assert!(!Learning::is_data_day(3_599, 1_000_000));
    }

    #[test]
    fn un_dia_sin_trafico_del_sujeto_no_cuenta() {
        assert!(!Learning::is_data_day(3_600, 0));
        assert!(!Learning::is_data_day(86_400, 0));
    }

    #[test]
    fn con_una_hora_y_trafico_el_dia_cuenta() {
        assert!(Learning::is_data_day(3_600, 1));
        assert!(Learning::is_data_day(7_200, 4_000_000));
    }

    #[test]
    fn el_dia_del_cambio_de_hora_con_23_horas_sigue_contando_si_llega_a_una_hora() {
        assert!(Learning::is_data_day(3_600, 1));
        assert!(Learning::is_data_day(82_800, 1));
    }

    #[test]
    fn aprendido_a_partir_de_los_dias_configurados() {
        assert!(!Learning::is_learned(6, 7));
        assert!(Learning::is_learned(7, 7));
        // Con learning_days = 0 cualquier sujeto nace aprendido.
        assert!(Learning::is_learned(0, 0));
        assert!(!Learning::is_learned(0, 1));
    }
}
