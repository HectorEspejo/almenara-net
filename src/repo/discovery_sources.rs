//! DAO de fuentes de descubrimiento (tabla DISCOVERY_SOURCES).
//!
//! Registra qué métodos han visto a cada dispositivo: arp, icmp, mdns, ssdp,
//! dhcp, netbios, portscan y capture (equipos observados en la captura de F4).
//! No tiene ciclo de vida propio: se purga con el dispositivo (FK ON DELETE
//! CASCADE). El valor `capture` no necesita cambio de esquema (§3).

use rusqlite::{params, Connection, Row};

use crate::error::Result;

/// Fuente de descubrimiento de un dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiscoverySource {
    /// ARP (barrido activo o lectura de /proc/net/arp).
    Arp,
    /// Ping sweep ICMP.
    Icmp,
    /// Anuncios mDNS.
    Mdns,
    /// SSDP/UPnP.
    Ssdp,
    /// Leases DHCP.
    Dhcp,
    /// Consulta NetBIOS.
    Netbios,
    /// Port scan TCP CONNECT.
    Portscan,
    /// Equipo observado en la captura (ARP, DHCP o tramas IPv4, §7.14).
    Capture,
}

impl DiscoverySource {
    /// Todas las fuentes, en el orden de la especificación.
    pub const ALL: [Self; 8] = [
        Self::Arp,
        Self::Icmp,
        Self::Mdns,
        Self::Ssdp,
        Self::Dhcp,
        Self::Netbios,
        Self::Portscan,
        Self::Capture,
    ];

    /// Representación persistida.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Icmp => "icmp",
            Self::Mdns => "mdns",
            Self::Ssdp => "ssdp",
            Self::Dhcp => "dhcp",
            Self::Netbios => "netbios",
            Self::Portscan => "portscan",
            Self::Capture => "capture",
        }
    }

    /// Reconstruye la fuente desde su representación persistida.
    pub fn from_str(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|fuente| fuente.as_str() == value)
    }

    /// Etiqueta visible en la interfaz.
    pub fn label(self) -> &'static str {
        match self {
            Self::Arp => "ARP",
            Self::Icmp => "ICMP",
            Self::Mdns => "mDNS",
            Self::Ssdp => "SSDP",
            Self::Dhcp => "DHCP",
            Self::Netbios => "NetBIOS",
            Self::Portscan => "puertos",
            Self::Capture => "captura",
        }
    }
}

/// Fila persistida de DISCOVERY_SOURCES.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySourceRow {
    /// FK a DEVICES.
    pub device_id: i64,
    /// Fuente.
    pub source: DiscoverySource,
    /// Última vez que la fuente vio al dispositivo (RFC 3339 UTC).
    pub last_seen: String,
}

/// Marca o actualiza una fuente para un dispositivo.
pub(crate) fn upsert(
    conn: &Connection,
    device_id: i64,
    source: DiscoverySource,
    last_seen: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO DISCOVERY_SOURCES (device_id, source, last_seen)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(device_id, source) DO UPDATE SET last_seen = excluded.last_seen",
        params![device_id, source.as_str(), last_seen],
    )?;
    Ok(())
}

/// Lista las fuentes que han visto a un dispositivo, en orden alfabético.
pub(crate) fn list(conn: &Connection, device_id: i64) -> Result<Vec<DiscoverySourceRow>> {
    let mut sentencia = conn.prepare(
        "SELECT device_id, source, last_seen FROM DISCOVERY_SOURCES
         WHERE device_id = ?1 ORDER BY source",
    )?;
    let filas = sentencia.query_map(params![device_id], fila_a_fuente)?;
    let mut fuentes = Vec::new();
    for fila in filas {
        fuentes.push(fila?);
    }
    Ok(fuentes)
}

/// Reconstruye una fuente a partir de una fila de DISCOVERY_SOURCES.
fn fila_a_fuente(fila: &Row<'_>) -> rusqlite::Result<DiscoverySourceRow> {
    let fuente: String = fila.get(1)?;
    Ok(DiscoverySourceRow {
        device_id: fila.get(0)?,
        source: DiscoverySource::from_str(&fuente).unwrap_or(DiscoverySource::Arp),
        last_seen: fila.get(2)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuentes_ida_y_vuelta() {
        for fuente in DiscoverySource::ALL {
            assert_eq!(DiscoverySource::from_str(fuente.as_str()), Some(fuente));
        }
        assert_eq!(DiscoverySource::from_str("snmp"), None);
        assert_eq!(
            DiscoverySource::from_str("capture"),
            Some(DiscoverySource::Capture)
        );
        assert_eq!(DiscoverySource::ALL.len(), 8);
    }

    #[test]
    fn etiquetas_visibles() {
        assert_eq!(DiscoverySource::Mdns.label(), "mDNS");
        assert_eq!(DiscoverySource::Portscan.label(), "puertos");
        assert_eq!(DiscoverySource::Capture.as_str(), "capture");
        assert_eq!(DiscoverySource::Capture.label(), "captura");
    }
}
