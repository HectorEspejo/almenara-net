//! Equipos observados en la captura como fuente L2 (§7.14).
//!
//! El hilo de captura empuja ARP, DHCP y tramas IPv4; el ciclo de escaneo vacía
//! el buffer y lo trata como una fuente más. Los filtros descartan direcciones
//! que no identifican a un equipo de la LAN: MAC propias o de grupo, IP nula,
//! broadcast o propia, IP fuera de las subredes y la MAC del gateway con otra
//! IP.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::inference::ObservedHost;

use super::mac;

/// Tope de equipos observados por ciclo.
pub const MAX_OBSERVED: usize = 4096;

/// Filtro de equipos observados en la captura.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedFilter {
    /// MAC de las interfaces propias.
    pub local_macs: HashSet<String>,
    /// IPv4 propias del host.
    pub local_ips: HashSet<Ipv4Addr>,
    /// Subredes locales como (red, máscara).
    pub networks: Vec<(Ipv4Addr, Ipv4Addr)>,
    /// IP del gateway.
    pub gateway_ip: Option<Ipv4Addr>,
    /// MAC del gateway.
    pub gateway_mac: Option<String>,
}

impl ObservedFilter {
    /// Indica si una observación es un equipo válido de la subred local.
    pub fn accepts(&self, host: &ObservedHost) -> bool {
        // La MAC llega de la captura: puede estar en cualquier formato o ser
        // basura, así que se normaliza y se rechaza lo que no sea una MAC.
        let Some(mac) = mac::normalize(&host.mac) else {
            return false;
        };

        // MAC propias de las interfaces del host.
        if self
            .local_macs
            .iter()
            .any(|propia| mac::normalize(propia).as_deref() == Some(mac.as_str()))
        {
            return false;
        }

        // MAC de grupo o broadcast: el bit de menor peso del primer octeto.
        let Some(primer_octeto) = mac
            .get(0..2)
            .and_then(|octeto| u8::from_str_radix(octeto, 16).ok())
        else {
            return false;
        };
        if primer_octeto & 0x01 != 0 {
            return false;
        }

        let ip = host.ip;
        if ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_loopback()
            || ip.is_multicast()
            || self.local_ips.contains(&ip)
        {
            return false;
        }

        // Solo se aceptan IPs dentro de alguna subred de las interfaces.
        if !self
            .networks
            .iter()
            .any(|(red, mascara)| contiene(*red, *mascara, ip))
        {
            return false;
        }

        let mac_gateway = self.gateway_mac.as_deref().and_then(mac::normalize);
        // La MAC del gateway solo vale con la IP del gateway (y viceversa): la
        // IP del router con otra MAC no identifica a un equipo de la LAN.
        if mac_gateway.as_deref() == Some(mac.as_str()) && self.gateway_ip != Some(ip) {
            return false;
        }
        if self.gateway_ip == Some(ip) && mac_gateway.as_deref() != Some(mac.as_str()) {
            return false;
        }
        true
    }
}

fn contiene(red: Ipv4Addr, mascara: Ipv4Addr, ip: Ipv4Addr) -> bool {
    (u32::from(ip) & u32::from(mascara)) == (u32::from(red) & u32::from(mascara))
}

/// Buffer de equipos observados en la captura, deduplicado por MAC + IP.
#[derive(Debug, Default)]
pub struct ObservedHosts {
    filter: ObservedFilter,
    hosts: HashMap<(String, Ipv4Addr), ObservedHost>,
    drops: u64,
}

impl ObservedHosts {
    /// Crea el buffer con su filtro.
    pub fn new(filter: ObservedFilter) -> Self {
        Self {
            filter,
            ..Self::default()
        }
    }

    /// Añade un equipo observado. Devuelve `true` si se aceptó.
    pub fn push(&mut self, mut host: ObservedHost) -> bool {
        // La clave de deduplicación usa siempre la MAC normalizada.
        let Some(normalizada) = mac::normalize(&host.mac) else {
            return false;
        };
        host.mac = normalizada;
        if !self.filter.accepts(&host) {
            return false;
        }
        let clave = (host.mac.clone(), host.ip);
        if let Some(actual) = self.hosts.get_mut(&clave) {
            // La primera observación manda, salvo que la nueva aporte la
            // identidad DHCP que faltaba.
            if actual.dhcp.is_none() && host.dhcp.is_some() {
                *actual = host;
            }
            return true;
        }
        if self.hosts.len() >= MAX_OBSERVED {
            self.drops = self.drops.saturating_add(1);
            return false;
        }
        self.hosts.insert(clave, host);
        true
    }

    /// Vacía el buffer y devuelve los equipos observados.
    pub fn drain(&mut self) -> Vec<ObservedHost> {
        self.hosts.drain().map(|(_, host)| host).collect()
    }

    /// Observaciones descartadas por el tope (acumulado desde el arranque).
    pub fn drops(&self) -> u64 {
        self.drops
    }

    /// Número de equipos en el buffer.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Indica si el buffer está vacío.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::ObservedSource;

    /// Filtro de una LAN doméstica de ejemplo: 192.168.1.0/24, host .10,
    /// gateway .1 con MAC aa:bb:cc:dd:ee:01.
    fn filtro() -> ObservedFilter {
        ObservedFilter {
            local_macs: HashSet::from(["de:ad:be:ef:00:01".to_string()]),
            local_ips: HashSet::from([Ipv4Addr::new(192, 168, 1, 10)]),
            networks: vec![(
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(255, 255, 255, 0),
            )],
            gateway_ip: Some(Ipv4Addr::new(192, 168, 1, 1)),
            gateway_mac: Some("aa:bb:cc:dd:ee:01".to_string()),
        }
    }

    /// Observación ARP de un equipo con su MAC e IP.
    fn host(mac: &str, ip: Ipv4Addr) -> ObservedHost {
        ObservedHost {
            mac: mac.to_string(),
            ip,
            source: ObservedSource::Arp,
            dhcp: None,
        }
    }

    #[test]
    fn acepta_un_equipo_normal_de_la_subred() {
        let filtro = filtro();
        assert!(filtro.accepts(&host("3c:22:fb:11:22:33", Ipv4Addr::new(192, 168, 1, 50))));
        // El gateway con su IP es un equipo más de la LAN.
        assert!(filtro.accepts(&host("aa:bb:cc:dd:ee:01", Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn rechaza_las_mac_propias() {
        let filtro = filtro();
        assert!(!filtro.accepts(&host("de:ad:be:ef:00:01", Ipv4Addr::new(192, 168, 1, 50))));
    }

    #[test]
    fn rechaza_mac_de_grupo_y_broadcast() {
        let filtro = filtro();
        // IPv4 multicast (01:00:5e…), IPv6 multicast (33:33…) y broadcast.
        for mac in [
            "01:00:5e:00:00:01",
            "33:33:00:00:00:01",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert!(
                !filtro.accepts(&host(mac, Ipv4Addr::new(192, 168, 1, 50))),
                "{mac} es una MAC de grupo"
            );
        }
    }

    #[test]
    fn rechaza_ip_nula_broadcast_propia_o_fuera_de_subred() {
        let filtro = filtro();
        // 0.0.0.0 (ARP sin IP), broadcast limitado y propio.
        assert!(!filtro.accepts(&host("3c:22:fb:11:22:33", Ipv4Addr::UNSPECIFIED)));
        assert!(!filtro.accepts(&host("3c:22:fb:11:22:33", Ipv4Addr::BROADCAST)));
        assert!(!filtro.accepts(&host("3c:22:fb:11:22:33", Ipv4Addr::new(192, 168, 1, 10))));
        // Otra subred, bucle y multicast.
        for ip in [
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(192, 168, 2, 5),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 251),
        ] {
            assert!(
                !filtro.accepts(&host("3c:22:fb:11:22:33", ip)),
                "{ip} no es una IP de equipo de la subred"
            );
        }
    }

    #[test]
    fn la_mac_del_gateway_necesita_la_ip_del_gateway() {
        let filtro = filtro();
        assert!(!filtro.accepts(&host("aa:bb:cc:dd:ee:01", Ipv4Addr::new(192, 168, 1, 50))));
        // Y la IP del gateway no se atribuye a otra MAC.
        assert!(!filtro.accepts(&host("3c:22:fb:11:22:33", Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn rechaza_mac_malformada() {
        let filtro = filtro();
        assert!(!filtro.accepts(&host("", Ipv4Addr::new(192, 168, 1, 50))));
        assert!(!filtro.accepts(&host("zz:zz:zz:zz:zz:zz", Ipv4Addr::new(192, 168, 1, 50))));
        assert!(!filtro.accepts(&host("aa:bb:cc", Ipv4Addr::new(192, 168, 1, 50))));
    }

    #[test]
    fn sin_subredes_conocidas_no_se_acepta_nada() {
        // Un filtro sin subredes es conservador: no se puede validar la IP.
        let filtro = ObservedFilter::default();
        assert!(!filtro.accepts(&host("3c:22:fb:11:22:33", Ipv4Addr::new(192, 168, 1, 50))));
    }

    #[test]
    fn deduplica_por_mac_e_ip() {
        let mut buffer = ObservedHosts::new(filtro());
        let equipo = || host("3c:22:fb:11:22:33", Ipv4Addr::new(192, 168, 1, 50));
        assert!(buffer.push(equipo()));
        assert!(buffer.push(equipo()));
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.drops(), 0);
    }

    #[test]
    fn normaliza_la_mac_al_entrar() {
        let mut buffer = ObservedHosts::new(filtro());
        assert!(buffer.push(host("3C-22-FB-11-22-33", Ipv4Addr::new(192, 168, 1, 50))));
        // La misma MAC en otro formato ya está deduplicada y sale normalizada.
        assert!(buffer.push(host("3c:22:fb:11:22:33", Ipv4Addr::new(192, 168, 1, 50))));
        let drenado = buffer.drain();
        assert_eq!(drenado.len(), 1);
        assert_eq!(drenado[0].mac, "3c:22:fb:11:22:33");
    }

    #[test]
    fn una_observacion_posterior_completa_la_identidad_dhcp() {
        use crate::inference::DhcpObservation;

        let mut buffer = ObservedHosts::new(filtro());
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        assert!(buffer.push(host("3c:22:fb:11:22:33", ip)));

        let mut con_dhcp = host("3c:22:fb:11:22:33", ip);
        con_dhcp.source = ObservedSource::Dhcp;
        con_dhcp.dhcp = Some(DhcpObservation {
            mac: Some("3c:22:fb:11:22:33".to_string()),
            ip: Some(std::net::IpAddr::V4(ip)),
            message_type: Some(5),
            fingerprint: Some("1,3,6,15".to_string()),
            vendor: Some("MSFT 5.0".to_string()),
            hostname: Some("equipo".to_string()),
            client_id: None,
        });
        assert!(buffer.push(con_dhcp));

        let drenado = buffer.drain();
        assert_eq!(drenado.len(), 1);
        assert!(drenado[0].dhcp.is_some(), "la identidad DHCP se conserva");

        // Al revés: una observación sin DHCP no borra la identidad ya vista.
        let mut segundo = ObservedHosts::new(filtro());
        let mut con_dhcp = host("3c:22:fb:11:22:33", ip);
        con_dhcp.dhcp = Some(DhcpObservation::default());
        assert!(segundo.push(con_dhcp));
        assert!(segundo.push(host("3c:22:fb:11:22:33", ip)));
        let drenado = segundo.drain();
        assert_eq!(drenado.len(), 1);
        assert!(drenado[0].dhcp.is_some());
    }

    #[test]
    fn descarta_los_equipos_filtrados_sin_contarlos_como_drop() {
        let mut buffer = ObservedHosts::new(filtro());
        assert!(!buffer.push(host("de:ad:be:ef:00:01", Ipv4Addr::new(192, 168, 1, 50))));
        assert!(!buffer.push(host("01:00:5e:00:00:01", Ipv4Addr::new(192, 168, 1, 50))));
        assert!(!buffer.push(host("3c:22:fb:11:22:33", Ipv4Addr::UNSPECIFIED)));
        assert!(buffer.is_empty());
        assert_eq!(buffer.drops(), 0);
    }

    #[test]
    fn el_tope_descarta_y_cuenta_sin_perder_los_ya_vistos() {
        // Subred /8 para poder generar 4096 IPs distintas.
        let mut filtro = ObservedFilter::default();
        filtro
            .networks
            .push((Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0)));
        let mut buffer = ObservedHosts::new(filtro);

        for i in 0..MAX_OBSERVED {
            let mac = format!(
                "02:00:{:02x}:{:02x}:{:02x}:00",
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            );
            let ip = Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            );
            assert!(buffer.push(host(&mac, ip)), "cabe el equipo {i}");
        }
        assert_eq!(buffer.len(), MAX_OBSERVED);

        // Al llenarse, una observación nueva se descarta y se cuenta.
        assert!(!buffer.push(host("02:ff:ff:ff:ff:fe", Ipv4Addr::new(10, 255, 255, 254))));
        assert_eq!(buffer.drops(), 1);
        assert_eq!(buffer.len(), MAX_OBSERVED);

        // Un equipo ya presente sigue aceptándose (no consume tope nuevo).
        assert!(buffer.push(host("02:00:00:00:00:00", Ipv4Addr::new(10, 0, 0, 0))));
        assert_eq!(buffer.drops(), 1);

        // El vaciado libera el buffer pero conserva el contador acumulado.
        assert_eq!(buffer.drain().len(), MAX_OBSERVED);
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.drops(), 1);
    }
}
