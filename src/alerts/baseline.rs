//! «Más tráfico de lo habitual»: mediana de 14 días y umbrales (§7.4).
//!
//! La mediana se calcula con `select_nth_unstable` (biblioteca estándar, sin
//! crates de estadística): resiste los picos (una descarga grande no sube la
//! base) y la misma hora local de los días anteriores respeta el ciclo diario.
//! Bajada y subida se evalúan por separado, porque una subida rara es la señal
//! de que algo saca datos.

use super::TrafficHighParams;

/// Resultado de evaluar un sentido de una hora.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HighInfo {
    /// Mediana de las muestras.
    pub median: u64,
    /// Veces la mediana que representa el valor.
    pub factor: f64,
    /// Número de muestras usadas.
    pub samples: usize,
}

/// Línea base de la regla `traffic_high` (ADR-72).
#[derive(Debug, Clone, Copy, Default)]
pub struct Baseline;

impl Baseline {
    /// Evalúa un valor contra sus muestras (§7.4).
    ///
    /// Devuelve `Some` si hay al menos `min_days` muestras, el valor supera
    /// `factor × mediana` y llega al mínimo del sentido.
    pub fn evaluate(
        value: u64,
        samples: &[u64],
        min_bytes: u64,
        p: &TrafficHighParams,
    ) -> Option<HighInfo> {
        if samples.len() < p.min_days as usize {
            return None;
        }
        // Solo cuentan los días que diga la configuración; el DAO puede traer
        // más muestras de las necesarias.
        let dias = (p.baseline_days as usize).min(samples.len());
        let mut valores: Vec<u64> = samples[samples.len() - dias..].to_vec();
        let median = mediana(&mut valores);
        let factor = if median == 0 {
            // Con mediana 0 manda el mínimo: el factor no está definido y se
            // representa como infinito (el texto lo muestra como «sin base»).
            f64::INFINITY
        } else {
            value as f64 / median as f64
        };
        if (value as f64) < p.factor * median as f64 {
            return None;
        }
        if value < min_bytes {
            return None;
        }
        Some(HighInfo {
            median,
            factor,
            samples: dias,
        })
    }
}

/// Mediana entera de un conjunto de muestras (§7.4).
///
/// Con un número par de muestras es la media de las dos centrales (redondeada
/// hacia abajo); con una muestra sola, esa muestra.
fn mediana(valores: &mut [u64]) -> u64 {
    let n = valores.len();
    if n == 0 {
        return 0;
    }
    let mitad = n / 2;
    let (izquierda, &mut central, _) = valores.select_nth_unstable(mitad);
    if n % 2 == 1 {
        return central;
    }
    let inferior = izquierda.iter().copied().max().unwrap_or(central);
    ((inferior as u128 + central as u128) / 2) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1_000_000;

    fn params() -> TrafficHighParams {
        TrafficHighParams::default()
    }

    #[test]
    fn sin_muestras_suficientes_no_hay_base() {
        assert_eq!(Baseline::evaluate(10 * MB, &[], 0, &params()), None);
        assert_eq!(
            Baseline::evaluate(10 * MB, &[1, 2, 3, 4], 0, &params()),
            None
        );
    }

    #[test]
    fn con_menos_de_cinco_muestras_no_avisa() {
        let p = params();
        // Cuatro muestras de 1 MB y un valor enorme: no hay base.
        assert_eq!(Baseline::evaluate(10_000 * MB, &[MB; 4], 0, &p), None);
    }

    #[test]
    fn ac_dos_con_cuatro_gigas_sobre_mediana_de_cuatrocientos_mb() {
        // 5 muestras de 400 MB: mediana 400 MB (200 bytes de MB de 1000²).
        let muestras = [400 * MB; 5];
        let info = Baseline::evaluate(2_400 * MB, &muestras, 200 * MB, &params())
            .expect("2,4 GB es 6 veces la mediana de 400 MB");
        assert_eq!(info.median, 400 * MB);
        assert!((info.factor - 6.0).abs() < f64::EPSILON);
        assert_eq!(info.samples, 5);

        // 1 GB no llega a 3 veces la mediana.
        assert_eq!(
            Baseline::evaluate(1_000 * MB, &muestras, 200 * MB, &params()),
            None
        );
    }

    #[test]
    fn el_minimo_del_sentido_manda_con_mediana_baja() {
        let p = params();
        let muestras = [MB; 5];
        // 190 MB está por debajo del mínimo de bajada (200 MB).
        assert_eq!(Baseline::evaluate(190 * MB, &muestras, 200 * MB, &p), None);
        assert!(Baseline::evaluate(200 * MB, &muestras, 200 * MB, &p).is_some());
    }

    #[test]
    fn con_mediana_cero_manda_el_minimo_y_el_factor_es_infinito() {
        let p = params();
        let muestras = [0u64; 5];
        assert_eq!(
            Baseline::evaluate(100 * MB, &muestras, 200 * MB, &p),
            None,
            "sin tráfico de base, 100 MB no llega al mínimo"
        );
        let info = Baseline::evaluate(200 * MB, &muestras, 200 * MB, &p)
            .expect("200 MB llega al mínimo de bajada");
        assert_eq!(info.median, 0);
        assert!(info.factor.is_infinite());
    }

    #[test]
    fn mediana_impar_y_par() {
        let mut impares = vec![10, 30, 20];
        assert_eq!(mediana(&mut impares), 20);
        let mut pares = vec![10, 20, 30, 40];
        assert_eq!(mediana(&mut pares), 25);
        let mut uno = vec![7];
        assert_eq!(mediana(&mut uno), 7);
        assert_eq!(mediana(&mut []), 0);
    }

    #[test]
    fn solo_usan_los_ultimos_dias_de_la_linea_base() {
        let mut p = params();
        p.baseline_days = 5;
        p.min_days = 3;
        // Las cinco más recientes son 10 MB; las antiguas eran enormes y no
        // deben contaminar la mediana.
        let mut muestras = vec![10_000 * MB; 10];
        muestras.extend_from_slice(&[10 * MB; 5]);
        let info = Baseline::evaluate(100 * MB, &muestras, 0, &p).expect("10 veces la mediana");
        assert_eq!(info.median, 10 * MB);
        assert_eq!(info.samples, 5);
    }

    #[test]
    fn mediana_con_muchas_muestras_no_desborda() {
        let mut valores: Vec<u64> = (1..=14).map(|n| n * MB).collect();
        // 14 muestras: media de las dos centrales (7 y 8 MB).
        assert_eq!(mediana(&mut valores), 7_500_000);
        let mut extremos = vec![u64::MAX; 4];
        assert_eq!(mediana(&mut extremos), u64::MAX);
    }
}
