//! Detección de interfaces de red mediante pnet y /proc/net/route.
//!
//! Contrato público:
//! - [`detect`] enumera las interfaces no loopback con su IPv4, máscara, MAC,
//!   estado y puerta de enlace por defecto.
//! - [`default_gateway`] lee la puerta de enlace por defecto de `/proc/net/route`.
//! - [`parse_route_table`] y [`netmask_to_prefix`] son funciones puras y testeables
//!   sin privilegios.

use std::net::Ipv4Addr;

use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};

/// Fichero del núcleo con la tabla de rutas IPv4.
const RUTA_TABLA_RUTAS: &str = "/proc/net/route";

/// Interfaz detectada en el sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedInterface {
    /// Nombre de la interfaz (eth0, wlan0, ...).
    pub name: String,
    /// MAC de la interfaz, si tiene.
    pub mac: Option<String>,
    /// IPv4 principal de la interfaz, si tiene.
    pub ipv4: Option<Ipv4Addr>,
    /// Máscara de red IPv4, si tiene.
    pub netmask: Option<Ipv4Addr>,
    /// Gateway por defecto asociado, si lo hay.
    pub gateway: Option<Ipv4Addr>,
    /// Estado del enlace.
    pub is_up: bool,
}

impl DetectedInterface {
    /// Red IPv4 derivada de la IP y la máscara.
    pub fn network(&self) -> Option<Ipv4Network> {
        let ip = self.ipv4?;
        let netmask = self.netmask?;
        let prefix = netmask_to_prefix(netmask)?;
        Ipv4Network::new(ip, prefix).ok()
    }

    /// Indica si la interfaz es apta para escaneo activo.
    pub fn is_scan_candidate(&self) -> bool {
        self.is_up && self.mac.is_some() && self.ipv4.is_some() && self.netmask.is_some()
    }
}

/// Enumera las interfaces de red no loopback del sistema.
///
/// Cada interfaz se devuelve con su primera dirección IPv4 (si tiene), la máscara
/// derivada de su prefijo y el gateway por defecto que le asigne el núcleo. El
/// resultado se ordena por nombre para que sea determinista.
pub fn detect() -> Vec<DetectedInterface> {
    let mut detectadas: Vec<DetectedInterface> = datalink::interfaces()
        .into_iter()
        .filter(|interfaz| !es_loopback(interfaz))
        .map(|interfaz| {
            let red_ipv4 = interfaz.ips.iter().find_map(|direccion| match direccion {
                IpNetwork::V4(red) => Some(*red),
                IpNetwork::V6(_) => None,
            });

            DetectedInterface {
                name: interfaz.name.clone(),
                mac: interfaz.mac.map(|mac| mac.to_string()),
                ipv4: red_ipv4.map(|red| red.ip()),
                netmask: red_ipv4.map(|red| red.mask()),
                gateway: default_gateway(&interfaz.name),
                is_up: interfaz.is_up(),
            }
        })
        .collect();

    detectadas.sort_by(|a, b| a.name.cmp(&b.name));
    detectadas.dedup_by(|a, b| a.name == b.name);
    detectadas
}

/// Devuelve el gateway por defecto de una interfaz leyendo /proc/net/route.
pub fn default_gateway(iface: &str) -> Option<Ipv4Addr> {
    let contenido = std::fs::read_to_string(RUTA_TABLA_RUTAS).ok()?;
    parse_route_table(&contenido, iface)
}

/// Parsea /proc/net/route y devuelve el gateway de la interfaz indicada.
///
/// El núcleo imprime el campo `Gateway` en hexadecimal con los octetos de la
/// dirección invertidos: `0101A8C0` corresponde a 192.168.1.1. Por eso se parsea
/// como entero sin signo de 32 bits y se intercambian sus bytes antes de construir
/// la dirección. Las líneas de cabecera y las rutas sin gateway (0.0.0.0) se ignoran.
pub fn parse_route_table(contenido: &str, iface: &str) -> Option<Ipv4Addr> {
    for linea in contenido.lines() {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
        if campos.len() < 8 {
            continue;
        }
        if campos[0] != iface {
            continue;
        }
        if !campos[1].eq_ignore_ascii_case("00000000") {
            continue;
        }
        let Ok(valor) = u32::from_str_radix(campos[2], 16) else {
            continue;
        };
        if valor == 0 {
            continue;
        }
        return Some(Ipv4Addr::from(valor.swap_bytes()));
    }
    None
}

/// Convierte una máscara IPv4 a prefijo CIDR (None si no es contigua).
pub fn netmask_to_prefix(netmask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(netmask);
    let prefijo = bits.leading_ones() as u8;
    let esperada = if prefijo == 0 {
        0
    } else {
        u32::MAX << (32 - prefijo)
    };
    (bits == esperada).then_some(prefijo)
}

/// Indica si una interfaz de pnet es loopback.
///
/// Se descarta la interfaz llamada "lo", la marcada como loopback por el núcleo y
/// cualquier interfaz cuyas únicas direcciones IPv4 pertenezcan a 127/8.
fn es_loopback(interfaz: &NetworkInterface) -> bool {
    if interfaz.name == "lo" || interfaz.is_loopback() {
        return true;
    }

    let mut tiene_ipv4 = false;
    for direccion in &interfaz.ips {
        if let IpNetwork::V4(red) = direccion {
            tiene_ipv4 = true;
            if !red.ip().is_loopback() {
                return false;
            }
        }
    }
    tiene_ipv4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefijo_de_mascaras_contiguas() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(
            netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)),
            Some(32)
        );
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), Some(16));
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(128, 0, 0, 0)), Some(1));
        assert_eq!(
            netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 252)),
            Some(30)
        );
        assert_eq!(
            netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 254)),
            Some(31)
        );
    }

    #[test]
    fn prefijo_de_mascaras_no_contiguas() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 255)), None);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 255, 0, 0)), None);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 253)), None);
    }

    #[test]
    fn red_derivada_de_ip_y_mascara() {
        let interfaz = DetectedInterface {
            name: "eth0".to_string(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 42)),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            is_up: true,
        };
        let red = interfaz.network().expect("red válida");
        assert_eq!(red.prefix(), 24);
        assert_eq!(red.ip(), Ipv4Addr::new(192, 168, 1, 42));
        assert!(red.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(interfaz.is_scan_candidate());
    }

    #[test]
    fn red_nula_si_la_mascara_no_es_contigua() {
        let interfaz = DetectedInterface {
            name: "eth0".to_string(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
            netmask: Some(Ipv4Addr::new(255, 0, 255, 0)),
            gateway: None,
            is_up: true,
        };
        assert!(interfaz.network().is_none());
    }

    /// Tabla de rutas con el formato real de /proc/net/route (columnas con tabuladores).
    const TABLA_RUTAS: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlp3s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlp3s0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";

    #[test]
    fn gateway_por_defecto_de_la_interfaz() {
        assert_eq!(
            parse_route_table(TABLA_RUTAS, "wlp3s0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            parse_route_table(TABLA_RUTAS, "docker0"),
            None,
            "docker0 no tiene ruta por defecto"
        );
        assert_eq!(parse_route_table(TABLA_RUTAS, "eth9"), None);
    }

    #[test]
    fn gateway_ignora_cabecera_y_valores_nulos() {
        let solo_cabecera =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        assert_eq!(parse_route_table(solo_cabecera, "eth0"), None);

        let gateway_cero = "eth0\t00000000\t00000000\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(parse_route_table(gateway_cero, "eth0"), None);

        let gateway_invalido = "eth0\t00000000\tNO-ES-HEX\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(parse_route_table(gateway_invalido, "eth0"), None);

        let linea_corta = "eth0\t00000000\t0101A8C0\n";
        assert_eq!(parse_route_table(linea_corta, "eth0"), None);
    }

    #[test]
    fn gateway_se_convierte_desde_hexadecimal_del_kernel() {
        // La ruta por defecto de 10.0.0.1 se imprime como 0100000A.
        let contenido = "eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(
            parse_route_table(contenido, "eth0"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn detect_no_devuelve_loopback_y_ordena_por_nombre() {
        let detectadas = detect();
        assert!(
            detectadas.iter().all(|interfaz| interfaz.name != "lo"),
            "la interfaz loopback no debe aparecer"
        );
        assert!(
            detectadas.windows(2).all(|par| par[0].name <= par[1].name),
            "las interfaces deben estar ordenadas por nombre"
        );
        for interfaz in &detectadas {
            assert_eq!(
                interfaz.ipv4.is_some(),
                interfaz.netmask.is_some(),
                "IPv4 y máscara se rellenan juntas en {}",
                interfaz.name
            );
            if let Some(ip) = interfaz.ipv4 {
                assert!(!ip.is_loopback(), "ninguna IP debe ser de 127/8");
            }
        }
    }
}
