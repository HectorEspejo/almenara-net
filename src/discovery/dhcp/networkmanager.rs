//! Parser de leases DHCP en formato NetworkManager.
//!
//! NetworkManager guarda sus leases internos en `/var/lib/NetworkManager/*.lease`
//! como pares `CLAVE=valor` (ADDRESS/IPADDR, HWADDR, HOSTNAME, DHCP4_...). Es un
//! formato privado sin especificación estable, así que el parser acepta alias de
//! claves e ignora todo lo que no reconoce.

use super::{parsear_clave_valor, Lease, LeaseSource};
use crate::error::Result;

/// Parsea el contenido de un fichero de leases NetworkManager.
pub fn parse(text: &str) -> Result<Vec<Lease>> {
    Ok(parsear_clave_valor(text, LeaseSource::NetworkManager))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const FIXTURE: &str = "\
# This is private data. Do not parse.
ADDRESS=10.0.0.42
PREFIX=24
GATEWAY=10.0.0.1
SERVER_ADDRESS=10.0.0.1
DHCP4_LAST_UPDATE=1700000000
HWADDR=00:11:22:33:44:55
HOSTNAME=torre-nm
";

    #[test]
    fn parsea_direccion_mac_y_hostname() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, Ipv4Addr::new(10, 0, 0, 42));
        assert_eq!(leases[0].mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(leases[0].hostname.as_deref(), Some("torre-nm"));
        assert_eq!(leases[0].expiry, None);
        assert_eq!(leases[0].source, LeaseSource::NetworkManager);
        assert_eq!(leases[0].path, None);
    }

    #[test]
    fn acepta_el_alias_ipaddr_y_hostname_entrecomillado() {
        let texto =
            "IPADDR=192.168.0.50\nHWADDR=aa-bb-cc-dd-ee-00\nHOSTNAME=\"equipo-entrecomillado\"\n";
        let leases = parse(texto).expect("parseo tolerante");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, Ipv4Addr::new(192, 168, 0, 50));
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:00"));
        assert_eq!(leases[0].hostname.as_deref(), Some("equipo-entrecomillado"));
    }

    #[test]
    fn convierte_la_caducidad_epoch_cuando_existe() {
        let texto = "ADDRESS=10.0.0.43\nEXPIRY=1700000000\n";
        let leases = parse(texto).expect("parseo tolerante");
        assert_eq!(leases[0].expiry.as_deref(), Some("2023-11-14T22:13:20Z"));
    }

    #[test]
    fn las_lineas_sin_clave_igual_se_ignoran() {
        let texto = "ruido sin igual\n\nADDRESS=10.0.0.44\n";
        let leases = parse(texto).expect("parseo tolerante");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, Ipv4Addr::new(10, 0, 0, 44));
    }

    #[test]
    fn un_texto_sin_leases_devuelve_lista_vacia() {
        assert!(parse("").expect("parseo tolerante").is_empty());
        assert!(parse("# solo comentarios\n")
            .expect("parseo tolerante")
            .is_empty());
    }
}
