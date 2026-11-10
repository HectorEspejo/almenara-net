//! DAO del histórico de eventos de dispositivo (tabla DEVICE_EVENTS).

/// Tipos de evento emitidos en Fase 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Primera detección de una MAC.
    New,
    /// Equipo que deja de responder N ciclos.
    Disappeared,
    /// Cambio de IPv4.
    IpChanged,
    /// Cambio de identidad (misma IP con nueva MAC).
    MacChanged,
    /// Cambio de hostname.
    HostnameChanged,
}

impl EventType {
    /// Todos los tipos de evento.
    pub const ALL: [Self; 5] = [
        Self::New,
        Self::Disappeared,
        Self::IpChanged,
        Self::MacChanged,
        Self::HostnameChanged,
    ];

    /// Representación persistida.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Disappeared => "disappeared",
            Self::IpChanged => "ip_changed",
            Self::MacChanged => "mac_changed",
            Self::HostnameChanged => "hostname_changed",
        }
    }

    /// Reconstruye el tipo desde la representación persistida.
    pub fn from_str(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tipo| tipo.as_str() == value)
    }
}

/// Evento persistido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEvent {
    /// Identificador interno.
    pub id: i64,
    /// FK a DEVICES.
    pub device_id: i64,
    /// Tipo de evento.
    pub event_type: EventType,
    /// JSON con before/after.
    pub details: String,
    /// Momento del evento (RFC 3339 UTC).
    pub created_at: String,
}
