//! DAO de dispositivos (tabla DEVICES) y modelo de dominio asociado.

/// Dispositivo descubierto en la red local, tal como se persiste en SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Identificador interno.
    pub id: i64,
    /// MAC normalizada aa:bb:cc:dd:ee:ff (única).
    pub mac: String,
    /// Última IPv4 vista.
    pub ip: String,
    /// Hostname por reverse DNS o cache.
    pub hostname: Option<String>,
    /// Fabricante según OUI.
    pub vendor: Option<String>,
    /// FK a INTERFACES.
    pub interface_id: i64,
    /// Tipo de dispositivo; en Fase 1 "gateway" o "unknown".
    pub device_type: String,
    /// Estado actual.
    pub is_online: bool,
    /// Primera detección (RFC 3339 UTC).
    pub first_seen: String,
    /// Última detección (RFC 3339 UTC).
    pub last_seen: String,
    /// Alias manual del usuario.
    pub alias: Option<String>,
    /// Notas libres.
    pub notes: Option<String>,
}

impl Device {
    /// Nombre visible: alias, hostname o "?".
    pub fn display_name(&self) -> &str {
        self.alias
            .as_deref()
            .or(self.hostname.as_deref())
            .unwrap_or("?")
    }

    /// Indica si el dispositivo es el gateway de su interfaz.
    pub fn is_gateway(&self) -> bool {
        self.device_type == "gateway"
    }
}

/// Datos de un dispositivo que llegan desde un escaneo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceUpsert {
    /// MAC normalizada.
    pub mac: String,
    /// IPv4 vista.
    pub ip: String,
    /// Hostname resuelto (None si no hay).
    pub hostname: Option<String>,
    /// Fabricante conocido (None si no hay).
    pub vendor: Option<String>,
    /// FK a INTERFACES.
    pub interface_id: i64,
    /// Tipo de dispositivo ("gateway" o "unknown").
    pub device_type: String,
}

/// Cambios detectados al hacer upsert de un dispositivo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet {
    /// Es la primera vez que se ve esta MAC.
    pub is_new: bool,
    /// (anterior, nuevo) si cambió la IP.
    pub ip_changed: Option<(String, String)>,
    /// (anterior, nuevo) si cambió el hostname.
    pub hostname_changed: Option<(Option<String>, Option<String>)>,
    /// (anterior, nuevo) si cambió la MAC (cambio de identidad por IP).
    pub mac_changed: Option<(String, String)>,
    /// El dispositivo estaba offline y ha vuelto a aparecer.
    pub became_online: bool,
}
