//! DAO de dispositivos (tabla DEVICES) y modelo de dominio asociado.

use crate::classify::OsFamily;
use crate::identify::OsSource;

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
    /// Familia de SO estimada por fingerprint (NULL si no supera el umbral).
    pub os_family: Option<String>,
    /// Tipo de dispositivo forzado por el usuario (NULL = automático).
    pub device_type_manual: Option<String>,
    /// Último fingerprint observado en JSON (TTL, opciones TCP, puntuación...).
    pub last_fingerprint: Option<String>,
    /// Modelo anunciado por mDNS o UPnP (máximo 64 caracteres).
    pub model: Option<String>,
    /// Huella DHCP: opción 55 en decimal separada por comas, en su orden.
    pub dhcp_fingerprint: Option<String>,
    /// Fabricante anunciado por DHCP: opción 60 saneada (máximo 64).
    pub dhcp_vendor: Option<String>,
    /// Hostname anunciado por DHCP: opción 12 saneada (máximo 64).
    pub dhcp_hostname: Option<String>,
    /// Último User-Agent HTTP en claro, saneado y truncado a 256 caracteres.
    pub user_agent: Option<String>,
    /// Señal que fijó os_family: tcp / dhcp / model / ua.
    pub os_source: Option<String>,
    /// Equipo vigilado por la persona (§7.7); ninguno por defecto.
    pub watched: bool,
}

impl Device {
    /// Nombre visible: alias, hostname o "?".
    pub fn display_name(&self) -> &str {
        self.alias
            .as_deref()
            .or(self.hostname.as_deref())
            .unwrap_or("?")
    }

    /// Tipo de dispositivo efectivo: el override manual manda sobre el automático.
    pub fn effective_device_type(&self) -> &str {
        self.device_type_manual
            .as_deref()
            .filter(|tipo| !tipo.is_empty())
            .unwrap_or(&self.device_type)
    }

    /// Indica si el dispositivo es el gateway de su interfaz.
    ///
    /// La vista usa el icono por tipo efectivo; se conserva como ayuda de dominio
    /// para el detalle de F3.
    #[allow(dead_code)]
    pub fn is_gateway(&self) -> bool {
        self.effective_device_type() == "gateway"
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
    /// Tipo de dispositivo automático (taxonomía de Fase 2).
    pub device_type: String,
}

/// Identidad de un dispositivo que llega desde las señales de la captura (§7.12).
///
/// Cada campo es opcional porque las señales aparecen en momentos distintos
/// (DHCP en un ciclo, User-Agent en otro): los valores None no pisan lo ya
/// guardado. `os_family` y `os_source` se escriben juntos: cuando llega una
/// familia nueva, la fuente que la justifica la acompaña (y puede ser NULL).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityUpdate {
    /// Modelo de mDNS o UPnP (máximo 64 caracteres).
    pub model: Option<String>,
    /// Huella DHCP: opción 55 en decimal separada por comas.
    pub dhcp_fingerprint: Option<String>,
    /// Fabricante DHCP: opción 60 saneada (máximo 64).
    pub dhcp_vendor: Option<String>,
    /// Hostname DHCP: opción 12 saneada (máximo 64).
    pub dhcp_hostname: Option<String>,
    /// Último User-Agent HTTP en claro (máximo 256).
    pub user_agent: Option<String>,
    /// Familia de SO estimada por la puntuación combinada.
    pub os_family: Option<OsFamily>,
    /// Señal que más aportó a la familia ganadora.
    pub os_source: Option<OsSource>,
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
