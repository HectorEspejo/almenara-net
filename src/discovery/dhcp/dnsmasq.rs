//! Parser de leases DHCP en formato dnsmasq.
//!
//! Una línea por lease con los campos «caducidad MAC IP hostname client-id».
//! La caducidad es un epoch en segundos (0 representa una concesión infinita) y
//! el hostname desconocido se escribe como «*». Las líneas mal formadas se
//! ignoran: un fichero sin leases válidos devuelve una lista vacía.

use std::net::Ipv4Addr;

use super::{epoch_a_rfc3339, normalizar_hostname, Lease, LeaseSource};
use crate::error::Result;
use crate::oui;

/// Parsea el contenido de un fichero de leases dnsmasq.
pub fn parse(text: &str) -> Result<Vec<Lease>> {
    let mut leases = Vec::new();
    for linea in text.lines() {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 3 {
            continue;
        }
        let Ok(ip) = campos[2].parse::<Ipv4Addr>() else {
            continue;
        };
        let caducidad = campos[0]
            .parse::<i64>()
            .ok()
            .filter(|segundos| *segundos > 0)
            .and_then(epoch_a_rfc3339);
        let mac = oui::normalize_mac(campos[1]);
        let hostname = campos.get(3).and_then(|valor| normalizar_hostname(valor));
        leases.push(Lease {
            mac,
            ip,
            hostname,
            expiry: caducidad,
            source: LeaseSource::Dnsmasq,
            path: None,
        });
    }
    Ok(leases)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
# Lease de dnsmasq
1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 portatil 01:aa:bb:cc:dd:ee:ff
0 11-22-33-44-55-66 192.168.1.101 * *
expired 00:11:22:33:44:55 192.168.1.102 sin-caducidad
linea basura sin ip
";

    #[test]
    fn parsea_varios_leases_y_normaliza_la_mac() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases.len(), 3);

        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(leases[0].ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(leases[0].hostname.as_deref(), Some("portatil"));
        assert_eq!(leases[0].source, LeaseSource::Dnsmasq);
        assert_eq!(leases[0].path, None);
    }

    #[test]
    fn la_caducidad_epoch_se_convierte_a_rfc3339_utc() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases[0].expiry.as_deref(), Some("2023-11-14T22:13:20Z"));
        assert!(chrono::DateTime::parse_from_rfc3339(leases[0].expiry.as_deref().unwrap()).is_ok());
    }

    #[test]
    fn la_concesion_infinita_y_el_hostname_desconocido_son_none() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases[1].expiry, None);
        assert_eq!(leases[1].hostname, None);
        assert_eq!(leases[1].mac.as_deref(), Some("11:22:33:44:55:66"));
    }

    #[test]
    fn una_caducidad_no_numerica_deja_el_lease_sin_fecha() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases[2].expiry, None);
        assert_eq!(leases[2].mac.as_deref(), Some("00:11:22:33:44:55"));
    }

    #[test]
    fn un_texto_sin_leases_devuelve_lista_vacia() {
        assert!(parse("").expect("parseo tolerante").is_empty());
        assert!(parse("# solo comentarios\n\n")
            .expect("parseo tolerante")
            .is_empty());
    }
}
