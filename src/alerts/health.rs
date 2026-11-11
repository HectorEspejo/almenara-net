//! Salud de la captura y de la base de datos (§7.8).
//!
//! El motor no consulta nada: el hilo de la TUI ya tiene las estadísticas de
//! captura de F3 y el tamaño de la base de datos de F5, y cada minuto pasa una
//! muestra de salud con `Health::sample`. Con ella saltan `capture_stopped`,
//! `capture_drops` y `db_size`.

use std::time::SystemTime;

/// Estado de la captura de tráfico.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaptureStats {
    /// `[capture].enabled`.
    pub enabled: bool,
    /// Hay CAP_NET_RAW.
    pub privileged: bool,
    /// La captura está activa.
    pub running: bool,
    /// Error de la captura, si lo hay.
    pub error: Option<String>,
    /// Porcentaje de pérdida del último minuto cerrado (None si no hubo cierre).
    pub drops_pct_minute: Option<f32>,
    /// Paquetes perdidos por el anillo del kernel (acumulado).
    pub kernel_drops: u64,
    /// Paquetes descartados por el límite de pps (acumulado).
    pub limit_drops: u64,
    /// Interfaz en captura.
    pub interface: String,
}

/// Tamaño de la base de datos.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DbSize {
    /// Bytes del fichero principal.
    pub db_bytes: u64,
    /// Bytes del WAL.
    pub wal_bytes: u64,
    /// Límite configurado (`max_db_mb`).
    pub max_db_mb: u64,
}

impl DbSize {
    /// Bytes totales de la base de datos (principal + WAL).
    pub fn total_bytes(&self) -> u64 {
        self.db_bytes.saturating_add(self.wal_bytes)
    }

    /// Indica si la base de datos pasa del límite configurado.
    ///
    /// Con `max_db_mb = 0` no hay límite (no salta la regla).
    pub fn over_limit(&self) -> bool {
        self.max_db_mb > 0 && self.total_bytes() > self.max_db_mb.saturating_mul(1_000_000)
    }
}

/// Estado de la captura ya interpretado para la regla `capture_stopped`.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureHealth {
    /// La captura debería estar activa y no lo está.
    pub stopped: bool,
    /// La captura está activa.
    pub running: bool,
    /// Motivo del parón.
    pub reason: Option<String>,
    /// Interfaz afectada.
    pub interface: String,
    /// Porcentaje de pérdida del minuto, si se conoce.
    pub drops_pct: Option<f32>,
    /// Pérdidas del kernel.
    pub kernel_drops: u64,
    /// Pérdidas por límite.
    pub limit_drops: u64,
}

/// Muestra de salud que se pasa al motor (§7.8).
#[derive(Debug, Clone, PartialEq)]
pub struct HealthSample {
    /// Estado de la captura.
    pub capture: CaptureHealth,
    /// Estado de la base de datos.
    pub db: DbSize,
}

/// Servicio de salud de Almenara.
#[derive(Debug, Clone, Copy, Default)]
pub struct Health;

impl Health {
    /// Toma una muestra de salud a partir de lo que ya tiene el hilo de la TUI.
    ///
    /// En modo degradado (sin CAP_NET_RAW) la captura nunca empieza: no hay
    /// parón que avisar, la barra ya lo dice (F1).
    pub fn sample(stats: &CaptureStats, db: &DbSize, _now: SystemTime) -> HealthSample {
        let deberia_capturar = stats.enabled && stats.privileged;
        let stopped = deberia_capturar && !stats.running;
        HealthSample {
            capture: CaptureHealth {
                stopped,
                running: stats.running,
                reason: stats.error.clone(),
                interface: stats.interface.clone(),
                drops_pct: stats.drops_pct_minute,
                kernel_drops: stats.kernel_drops,
                limit_drops: stats.limit_drops,
            },
            db: *db,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn stats(activa: bool, privilegiado: bool, capturando: bool) -> CaptureStats {
        CaptureStats {
            enabled: activa,
            privileged: privilegiado,
            running: capturando,
            error: None,
            drops_pct_minute: Some(0.2),
            kernel_drops: 3,
            limit_drops: 1,
            interface: "eth0".to_string(),
        }
    }

    fn db(bytes: u64, wal: u64, max_mb: u64) -> DbSize {
        DbSize {
            db_bytes: bytes,
            wal_bytes: wal,
            max_db_mb: max_mb,
        }
    }

    #[test]
    fn captura_parada_con_captura_activada_y_privilegios() {
        let muestra = Health::sample(&stats(true, true, false), &db(0, 0, 0), UNIX_EPOCH);
        assert!(muestra.capture.stopped);
        assert!(!muestra.capture.running);
        assert_eq!(muestra.capture.interface, "eth0");
        assert_eq!(muestra.capture.drops_pct, Some(0.2));
        assert_eq!(muestra.capture.kernel_drops, 3);
        assert_eq!(muestra.capture.limit_drops, 1);
    }

    #[test]
    fn en_modo_degradado_no_hay_paron_que_avisar() {
        let muestra = Health::sample(&stats(true, false, false), &db(0, 0, 0), UNIX_EPOCH);
        assert!(!muestra.capture.stopped);
        assert!(!muestra.capture.running);
        // Y con la captura desactivada en configuración, tampoco.
        let muestra = Health::sample(&stats(false, true, false), &db(0, 0, 0), UNIX_EPOCH);
        assert!(!muestra.capture.stopped);
    }

    #[test]
    fn captura_activa_no_esta_parada() {
        let muestra = Health::sample(&stats(true, true, true), &db(0, 0, 0), UNIX_EPOCH);
        assert!(!muestra.capture.stopped);
        assert!(muestra.capture.running);
    }

    #[test]
    fn el_motivo_del_paron_se_copia() {
        let mut datos = stats(true, true, false);
        datos.error = Some("AF_PACKET: permiso denegado".to_string());
        let muestra = Health::sample(&datos, &db(0, 0, 0), UNIX_EPOCH);
        assert_eq!(
            muestra.capture.reason.as_deref(),
            Some("AF_PACKET: permiso denegado")
        );
    }

    #[test]
    fn el_limite_de_la_base_de_datos_cuenta_el_wal() {
        assert!(!db(900_000_000, 99_000_000, 1024).over_limit());
        assert!(db(900_000_000, 200_000_000, 1024).over_limit());
        assert_eq!(db(1, 2, 3).total_bytes(), 3);
        // Sin límite configurado no salta.
        assert!(!db(u64::MAX, u64::MAX, 0).over_limit());
    }

    #[test]
    fn la_muestra_de_salud_copia_el_tamano_de_la_base_de_datos() {
        let tamano = db(10, 20, 30);
        let muestra = Health::sample(&stats(true, true, true), &tamano, UNIX_EPOCH);
        assert_eq!(muestra.db, tamano);
        assert!(!muestra.capture.stopped);
    }
}
