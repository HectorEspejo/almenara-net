//! DAO de interfaces de red (tabla INTERFACES).

/// Interfaz de red persistida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Identificador interno.
    pub id: i64,
    /// Nombre único (eth0, wlan0, ...).
    pub name: String,
    /// MAC de la interfaz.
    pub mac: Option<String>,
    /// IPv4 asignada.
    pub ipv4: Option<String>,
    /// Máscara de red.
    pub netmask: Option<String>,
    /// Gateway por defecto.
    pub gateway: Option<String>,
    /// Estado del enlace.
    pub is_up: bool,
    /// Última detección (RFC 3339 UTC).
    pub last_seen: String,
}

impl Interface {
    /// Crea una interfaz sin id (para insertar o actualizar).
    pub fn without_id(
        name: impl Into<String>,
        mac: Option<String>,
        ipv4: Option<String>,
        netmask: Option<String>,
        gateway: Option<String>,
        is_up: bool,
        last_seen: impl Into<String>,
    ) -> Self {
        Self {
            id: 0,
            name: name.into(),
            mac,
            ipv4,
            netmask,
            gateway,
            is_up,
            last_seen: last_seen.into(),
        }
    }
}
