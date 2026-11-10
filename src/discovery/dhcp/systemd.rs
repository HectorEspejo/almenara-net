//! Parser de leases DHCP en formato systemd-networkd.
//!
//! systemd-networkd guarda sus leases en `/run/systemd/netif/leases/<ifindex>` con
//! pares `CLAVE=valor` (ADDRESS, HOSTNAME, CLIENT_ID...). Es un formato interno
//! sin especificación estable: se aceptan alias de claves, se ignoran las
//! desconocidas y las direcciones IPv6 se descartan porque el inventario de
//! Almenara es IPv4.

use super::{parsear_clave_valor, Lease, LeaseSource};
use crate::error::Result;

/// Parsea el contenido de un fichero de leases systemd-networkd.
pub fn parse(text: &str) -> Result<Vec<Lease>> {
    Ok(parsear_clave_valor(text, LeaseSource::SystemdNetworkd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const FIXTURE: &str = "\
# This is private data. Do not parse.
ADDRESS=192.168.1.150
PREFIXLEN=24
ROUTER=192.168.1.1
SERVER_ADDRESS=192.168.1.1
NEXT_SERVER=0.0.0.0
BROADCAST=192.168.1.255
DNS=192.168.1.1
DOMAINNAME=lan
HOSTNAME=portatil-systemd
CLIENT_ID=01:aa:bb:cc:dd:ee:99
";

    #[test]
    fn parsea_direccion_hostname_y_mac_del_client_id() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, Ipv4Addr::new(192, 168, 1, 150));
        assert_eq!(leases[0].hostname.as_deref(), Some("portatil-systemd"));
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:99"));
        assert_eq!(leases[0].expiry, None);
        assert_eq!(leases[0].source, LeaseSource::SystemdNetworkd);
        assert_eq!(leases[0].path, None);
    }

    #[test]
    fn las_direcciones_ipv6_se_descartan() {
        let texto = "ADDRESS=fe80::1\nHOSTNAME=solo-v6\n";
        assert!(parse(texto).expect("parseo tolerante").is_empty());
    }

    #[test]
    fn un_texto_sin_leases_devuelve_lista_vacia() {
        assert!(parse("").expect("parseo tolerante").is_empty());
        assert!(parse("# This is private data. Do not parse.\n")
            .expect("parseo tolerante")
            .is_empty());
    }
}
