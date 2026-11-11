//! Catálogo fijo de las 16 reglas de alerta (§7.1) y su configuración.

use super::Level;

/// Identificador de una regla del catálogo fijo (ADR-67).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleId {
    /// Equipo nuevo (`device_new`).
    DeviceNew,
    /// Puerto nuevo o reabierto (`port_new`).
    PortNew,
    /// Cambio de MAC (`mac_changed`).
    MacChanged,
    /// Cambio de nombre (`name_changed`).
    NameChanged,
    /// Cambio de SO (`os_changed`).
    OsChanged,
    /// Cambio de tipo (`type_changed`).
    TypeChanged,
    /// App nueva (`new_app`).
    NewApp,
    /// Categoría nueva (`new_category`).
    NewCategory,
    /// País nuevo (`new_country`).
    NewCountry,
    /// Organización nueva (`new_org`).
    NewOrg,
    /// Huella TLS nueva (`new_ja4`).
    NewJa4,
    /// Más tráfico de lo habitual (`traffic_high`).
    TrafficHigh,
    /// Vigilado ausente o de vuelta (`watched_presence`).
    WatchedPresence,
    /// Captura parada (`capture_stopped`).
    CaptureStopped,
    /// Pérdidas de captura (`capture_drops`).
    CaptureDrops,
    /// Base de datos grande (`db_size`).
    DbSize,
}

#[allow(clippy::should_implement_trait)] // `from_str` inherente como en el resto del crate
impl RuleId {
    /// Las 16 reglas en el orden de la tabla del §7.1.
    pub const ALL: [RuleId; 16] = [
        RuleId::DeviceNew,
        RuleId::PortNew,
        RuleId::MacChanged,
        RuleId::NameChanged,
        RuleId::OsChanged,
        RuleId::TypeChanged,
        RuleId::NewApp,
        RuleId::NewCategory,
        RuleId::NewCountry,
        RuleId::NewOrg,
        RuleId::NewJa4,
        RuleId::TrafficHigh,
        RuleId::WatchedPresence,
        RuleId::CaptureStopped,
        RuleId::CaptureDrops,
        RuleId::DbSize,
    ];

    /// Identificador persistido en ALERTS.rule y en `[alerts.rules]`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceNew => "device_new",
            Self::PortNew => "port_new",
            Self::MacChanged => "mac_changed",
            Self::NameChanged => "name_changed",
            Self::OsChanged => "os_changed",
            Self::TypeChanged => "type_changed",
            Self::NewApp => "new_app",
            Self::NewCategory => "new_category",
            Self::NewCountry => "new_country",
            Self::NewOrg => "new_org",
            Self::NewJa4 => "new_ja4",
            Self::TrafficHigh => "traffic_high",
            Self::WatchedPresence => "watched_presence",
            Self::CaptureStopped => "capture_stopped",
            Self::CaptureDrops => "capture_drops",
            Self::DbSize => "db_size",
        }
    }

    /// Reconstruye la regla desde su identificador persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|regla| regla.as_str() == valor)
    }

    /// Nombre visible en la TUI.
    pub fn name(self) -> &'static str {
        self.def().name
    }

    /// Definición del catálogo de la regla.
    pub fn def(self) -> &'static RuleDef {
        &CATALOGO[posicion(self)]
    }
}

/// Posición de una regla en el catálogo.
fn posicion(regla: RuleId) -> usize {
    match regla {
        RuleId::DeviceNew => 0,
        RuleId::PortNew => 1,
        RuleId::MacChanged => 2,
        RuleId::NameChanged => 3,
        RuleId::OsChanged => 4,
        RuleId::TypeChanged => 5,
        RuleId::NewApp => 6,
        RuleId::NewCategory => 7,
        RuleId::NewCountry => 8,
        RuleId::NewOrg => 9,
        RuleId::NewJa4 => 10,
        RuleId::TrafficHigh => 11,
        RuleId::WatchedPresence => 12,
        RuleId::CaptureStopped => 13,
        RuleId::CaptureDrops => 14,
        RuleId::DbSize => 15,
    }
}

/// Definición inmutable de una regla del catálogo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleDef {
    /// Identificador.
    pub id: RuleId,
    /// Nombre visible.
    pub name: &'static str,
    /// Nivel por defecto.
    pub default_level: Level,
    /// La regla solo salta cuando el sujeto ya ha aprendido (§7.3).
    pub learns: bool,
    /// La regla es de condición: se resuelve cuando desaparece la condición.
    pub condition: bool,
    /// Necesita el histórico de F5 para poder saltar.
    pub needs_history: bool,
    /// Necesita captura de tráfico (CAP_NET_RAW) para poder saltar.
    pub needs_capture: bool,
    /// Necesita escaneo de puertos (no vale `passive_only`).
    pub needs_portscan: bool,
}

/// Servicio del catálogo fijo de reglas (§5 del informe de fase).
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)] // servicio del contrato; el motor usa RuleId::def()
pub struct Rules;

impl Rules {
    /// Las 16 reglas del catálogo con id, nombre, señal, nivel por defecto,
    /// si aprende y si es de condición (§7.1).
    #[allow(dead_code)]
    pub fn catalog() -> &'static [RuleDef] {
        &CATALOGO
    }
}

/// Catálogo fijo (§7.1).
pub static CATALOGO: [RuleDef; 16] = [
    RuleDef {
        id: RuleId::DeviceNew,
        name: "Equipo nuevo",
        default_level: Level::Important,
        learns: false,
        condition: false,
        needs_history: false,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::PortNew,
        name: "Puerto nuevo",
        default_level: Level::Important,
        learns: false,
        condition: false,
        needs_history: false,
        needs_capture: false,
        needs_portscan: true,
    },
    RuleDef {
        id: RuleId::MacChanged,
        name: "Cambio de MAC",
        default_level: Level::Warning,
        learns: false,
        condition: false,
        needs_history: false,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::NameChanged,
        name: "Cambio de nombre",
        default_level: Level::Info,
        learns: false,
        condition: false,
        needs_history: false,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::OsChanged,
        name: "Cambio de SO",
        default_level: Level::Info,
        learns: false,
        condition: false,
        needs_history: false,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::TypeChanged,
        name: "Cambio de tipo",
        default_level: Level::Info,
        learns: false,
        condition: false,
        needs_history: false,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::NewApp,
        name: "App nueva",
        default_level: Level::Info,
        learns: true,
        condition: false,
        needs_history: true,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::NewCategory,
        name: "Categoría nueva",
        default_level: Level::Info,
        learns: true,
        condition: false,
        needs_history: true,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::NewCountry,
        name: "País nuevo",
        default_level: Level::Info,
        learns: true,
        condition: false,
        needs_history: true,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::NewOrg,
        name: "Organización nueva",
        default_level: Level::Info,
        learns: true,
        condition: false,
        needs_history: true,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::NewJa4,
        name: "Huella TLS nueva (JA4)",
        default_level: Level::Info,
        learns: true,
        condition: false,
        needs_history: true,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::TrafficHigh,
        name: "Más tráfico de lo habitual",
        default_level: Level::Warning,
        learns: false,
        condition: false,
        needs_history: true,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::WatchedPresence,
        name: "Vigilado ausente o de vuelta",
        default_level: Level::Warning,
        learns: false,
        condition: true,
        needs_history: false,
        needs_capture: false,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::CaptureStopped,
        name: "Captura parada",
        default_level: Level::Important,
        learns: false,
        condition: true,
        needs_history: false,
        needs_capture: true,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::CaptureDrops,
        name: "Pérdidas de captura",
        default_level: Level::Warning,
        learns: false,
        condition: true,
        needs_history: false,
        needs_capture: true,
        needs_portscan: false,
    },
    RuleDef {
        id: RuleId::DbSize,
        name: "Base de datos grande",
        default_level: Level::Warning,
        learns: false,
        condition: true,
        needs_history: false,
        needs_capture: false,
        needs_portscan: false,
    },
];

/// Ajuste de una regla en `[alerts.rules]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSetting {
    /// Regla activa.
    pub enabled: bool,
    /// Nivel de las alertas de la regla.
    pub level: Level,
    /// Nivel de `device_new` con MAC privada (solo `device_new`).
    pub level_private_mac: Option<Level>,
}

impl RuleSetting {
    /// Ajuste por defecto de una regla del catálogo.
    pub fn default_for(rule: RuleId) -> Self {
        let def = rule.def();
        Self {
            enabled: true,
            level: def.default_level,
            level_private_mac: if rule == RuleId::DeviceNew {
                Some(Level::Warning)
            } else {
                None
            },
        }
    }
}

impl Default for RuleSetting {
    fn default() -> Self {
        Self {
            enabled: true,
            level: Level::Info,
            level_private_mac: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogo_con_las_dieciseis_reglas_en_orden() {
        assert_eq!(RuleId::ALL.len(), 16);
        assert_eq!(CATALOGO.len(), 16);
        for (indice, regla) in RuleId::ALL.into_iter().enumerate() {
            assert_eq!(CATALOGO[indice].id, regla);
            assert_eq!(regla.def().id, regla);
        }
    }

    #[test]
    fn identificadores_ida_y_vuelta() {
        for regla in RuleId::ALL {
            assert_eq!(RuleId::from_str(regla.as_str()), Some(regla));
        }
        assert_eq!(RuleId::from_str("catch_up"), None);
    }

    #[test]
    fn niveles_por_defecto_del_catalogo() {
        assert_eq!(RuleId::DeviceNew.def().default_level, Level::Important);
        assert_eq!(RuleId::MacChanged.def().default_level, Level::Warning);
        assert_eq!(RuleId::NewApp.def().default_level, Level::Info);
        assert!(RuleId::NewApp.def().learns);
        assert!(RuleId::CaptureStopped.def().condition);
        assert!(RuleId::PortNew.def().needs_portscan);
        assert!(RuleId::NewApp.def().needs_history);
        assert!(RuleId::CaptureStopped.def().needs_capture);
    }

    #[test]
    fn ajuste_por_defecto_de_device_new_baja_con_mac_privada() {
        let ajuste = RuleSetting::default_for(RuleId::DeviceNew);
        assert!(ajuste.enabled);
        assert_eq!(ajuste.level, Level::Important);
        assert_eq!(ajuste.level_private_mac, Some(Level::Warning));
        assert_eq!(
            RuleSetting::default_for(RuleId::PortNew).level_private_mac,
            None
        );
    }

    #[test]
    fn los_parametros_por_defecto_tienen_las_dieciseis_reglas() {
        let params = super::super::AlertsParams::default();
        assert_eq!(params.rules.len(), 16);
        assert_eq!(params.level(RuleId::PortNew), Level::Important);
        assert_eq!(params.quiet_hours, None);
        assert_eq!(params.traffic_high.factor, 3.0);
        assert_eq!(params.capture_drops.minutes, 5);
    }
}
