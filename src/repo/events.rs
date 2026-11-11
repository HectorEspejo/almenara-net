//! DAO del histórico de eventos de dispositivo (tabla DEVICE_EVENTS).

use rusqlite::{params, Connection};

use super::{Protocol, Repo};
use crate::error::Result;

/// Tipos de evento emitidos por Almenara.
///
/// F5 añade reinicios de presencia, servicios e identidad sin cambio de esquema:
/// la columna event_type es TEXT sin CHECK (ADR-61) y los tipos se validan en
/// código, igual que las enumeraciones del resto de la base de datos.
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
    /// Un equipo OFFLINE vuelve a verse (F5).
    Reappeared,
    /// Un escaneo de puertos ve abierto un puerto nuevo o reabierto (F5).
    ServiceNew,
    /// Un escaneo de puertos ve cerrado un puerto que estaba abierto (F5).
    ServiceGone,
    /// Cambia la familia de SO entre dos valores no nulos (F5).
    OsChanged,
    /// Cambia el tipo automático del equipo entre dos valores conocidos (F5).
    TypeChanged,
}

impl EventType {
    /// Todos los tipos de evento.
    pub const ALL: [Self; 10] = [
        Self::New,
        Self::Disappeared,
        Self::IpChanged,
        Self::MacChanged,
        Self::HostnameChanged,
        Self::Reappeared,
        Self::ServiceNew,
        Self::ServiceGone,
        Self::OsChanged,
        Self::TypeChanged,
    ];

    /// Representación persistida.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Disappeared => "disappeared",
            Self::IpChanged => "ip_changed",
            Self::MacChanged => "mac_changed",
            Self::HostnameChanged => "hostname_changed",
            Self::Reappeared => "reappeared",
            Self::ServiceNew => "service_new",
            Self::ServiceGone => "service_gone",
            Self::OsChanged => "os_changed",
            Self::TypeChanged => "type_changed",
        }
    }

    /// Reconstruye el tipo desde la representación persistida.
    pub fn from_str(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tipo| tipo.as_str() == value)
    }

    /// Etiqueta corta del evento para la línea de tiempo.
    ///
    /// API de F5 que consumirá la pestaña Histórico; se permite código muerto
    /// hasta que la TUI la integre, igual que el resto de la API de fase.
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "nuevo",
            Self::Disappeared => "desconectado",
            Self::IpChanged => "cambio de IP",
            Self::MacChanged => "cambio de MAC",
            Self::HostnameChanged => "cambio de nombre",
            Self::Reappeared => "vuelve a estar en línea",
            Self::ServiceNew => "nuevo servicio",
            Self::ServiceGone => "servicio cerrado",
            Self::OsChanged => "cambio de SO",
            Self::TypeChanged => "cambio de tipo",
        }
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

/// Último evento de servicio (`service_new` o `service_gone`) de un puerto.
///
/// API de F5 que la F6 ya no usa: desde la v6 el estado CERRADO de un puerto es
/// `DEVICE_SERVICES.closed_at` (§7.12), no su último evento. Se conserva para
/// el detalle histórico y sus pruebas; se permite código muerto.
#[allow(dead_code)]
pub(crate) fn last_service_event(
    conn: &Connection,
    device_id: i64,
    port: u16,
    protocol: Protocol,
) -> Result<Option<DeviceEvent>> {
    let mut sentencia = conn.prepare(
        "SELECT id, device_id, event_type, details, created_at
         FROM DEVICE_EVENTS
         WHERE device_id = ?1 AND event_type IN (?2, ?3)
         ORDER BY created_at DESC, id DESC",
    )?;
    let filas = sentencia.query_map(
        params![
            device_id,
            EventType::ServiceNew.as_str(),
            EventType::ServiceGone.as_str()
        ],
        |fila| {
            let tipo: String = fila.get(2)?;
            let Some(event_type) = EventType::from_str(&tipo) else {
                return Ok(None);
            };
            Ok(Some(DeviceEvent {
                id: fila.get(0)?,
                device_id: fila.get(1)?,
                event_type,
                details: fila.get(3)?,
                created_at: fila.get(4)?,
            }))
        },
    )?;
    for fila in filas {
        let Some(evento) = fila? else {
            continue;
        };
        if es_evento_del_puerto(&evento.details, port, protocol) {
            return Ok(Some(evento));
        }
    }
    Ok(None)
}

/// Indica si los detalles JSON de un evento de servicio corresponden a un puerto.
#[allow(dead_code)]
fn es_evento_del_puerto(details: &str, port: u16, protocol: Protocol) -> bool {
    let Ok(valor) = serde_json::from_str::<serde_json::Value>(details) else {
        return false;
    };
    valor.get("port").and_then(serde_json::Value::as_u64) == Some(u64::from(port))
        && valor.get("protocol").and_then(serde_json::Value::as_str) == Some(protocol.as_str())
}

impl Repo {
    /// Último evento de servicio de un puerto de un dispositivo (F5).
    ///
    /// La reconciliación ya no lo consulta: el estado CERRADO es
    /// `DEVICE_SERVICES.closed_at` (§7.12). Se conserva por compatibilidad.
    #[allow(dead_code)]
    pub fn last_service_event(
        &self,
        device_id: i64,
        port: u16,
        protocol: Protocol,
    ) -> Result<Option<DeviceEvent>> {
        last_service_event(&self.conn, device_id, port, protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::{EventType, Protocol, Repo};
    use crate::repo::{DeviceUpsert, Interface};

    #[test]
    fn ultimo_evento_de_servicio_por_puerto_y_protocolo() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let interface_id = repo
            .upsert_interface(&Interface::without_id(
                "eth0".to_string(),
                Some("02:00:00:00:00:ff".to_string()),
                Some("192.168.1.1".to_string()),
                Some("255.255.255.0".to_string()),
                None,
                true,
                "2026-01-01T00:00:00Z".to_string(),
            ))
            .unwrap();
        let (device_id, _) = repo
            .upsert_device(&DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.10".to_string(),
                hostname: None,
                vendor: None,
                interface_id,
                device_type: "unknown".to_string(),
            })
            .unwrap();
        assert!(repo
            .last_service_event(device_id, 22, Protocol::Tcp)
            .unwrap()
            .is_none());

        let nuevo =
            serde_json::json!({"port": 22, "protocol": "tcp", "service": "ssh", "reopened": false});
        repo.append_event(device_id, EventType::ServiceNew, &nuevo.to_string())
            .unwrap();
        let cerrado = serde_json::json!({"port": 22, "protocol": "tcp", "service": "ssh"});
        repo.append_event(device_id, EventType::ServiceGone, &cerrado.to_string())
            .unwrap();
        // Un evento de otro puerto y uno de otro protocolo no deben confundirse.
        let otro_puerto = serde_json::json!({"port": 80, "protocol": "tcp", "service": "http", "reopened": false});
        repo.append_event(device_id, EventType::ServiceNew, &otro_puerto.to_string())
            .unwrap();
        let udp =
            serde_json::json!({"port": 22, "protocol": "udp", "service": "ssh", "reopened": false});
        repo.append_event(device_id, EventType::ServiceNew, &udp.to_string())
            .unwrap();

        let ultimo = repo
            .last_service_event(device_id, 22, Protocol::Tcp)
            .unwrap()
            .expect("debe haber un evento del puerto 22/tcp");
        assert_eq!(ultimo.event_type, EventType::ServiceGone);
        assert_eq!(
            repo.last_service_event(device_id, 80, Protocol::Tcp)
                .unwrap()
                .expect("evento del 80/tcp")
                .event_type,
            EventType::ServiceNew
        );
        assert_eq!(
            repo.last_service_event(device_id, 22, Protocol::Udp)
                .unwrap()
                .expect("evento del 22/udp")
                .event_type,
            EventType::ServiceNew
        );
        assert!(repo
            .last_service_event(device_id, 443, Protocol::Tcp)
            .unwrap()
            .is_none());
    }
}
