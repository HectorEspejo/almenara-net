//! Lectura pasiva de la tabla ARP del núcleo (/proc/net/arp).
//!
//! La tabla ARP se puebla sola con el tráfico de la red, por lo que esta fuente
//! funciona incluso sin CAP_NET_RAW (modo degradado). Cada línea tiene el formato:
//!
//! ```text
//! IP address       HW type     Flags       HW address            Mask     Device
//! 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
//! ```

use std::net::Ipv4Addr;
use std::path::Path;

use crate::oui;

/// Ruta por defecto de la tabla ARP del núcleo.
const RUTA_TABLA_ARP: &str = "/proc/net/arp";

/// Entrada de la tabla ARP del núcleo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    /// Dirección IPv4.
    pub ip: Ipv4Addr,
    /// MAC normalizada aa:bb:cc:dd:ee:ff.
    pub mac: String,
    /// Flags del núcleo (0x2 = ATF_COMPLETE).
    pub flags: u16,
    /// Interfaz asociada.
    pub iface: String,
}

impl ArpEntry {
    /// Indica si la entrada está completa (MAC resuelta).
    pub fn is_complete(&self) -> bool {
        self.flags & 0x2 != 0
    }
}

/// Lee la tabla ARP del sistema.
pub fn read() -> Vec<ArpEntry> {
    read_from(Path::new(RUTA_TABLA_ARP))
}

/// Lee la tabla ARP de una ruta concreta (útil en tests).
///
/// Si el fichero no existe o no se puede leer se devuelve una lista vacía: la
/// lectura pasiva nunca debe abortar un ciclo de escaneo.
pub fn read_from(path: &Path) -> Vec<ArpEntry> {
    match std::fs::read_to_string(path) {
        Ok(contenido) => contenido.lines().filter_map(parse_line).collect(),
        Err(_) => Vec::new(),
    }
}

/// Parsea una línea de /proc/net/arp.
///
/// Devuelve `None` para la cabecera, las líneas vacías y cualquier fila cuyo IP,
/// flags o MAC no sean válidos.
pub fn parse_line(line: &str) -> Option<ArpEntry> {
    // Columnas: IP address, HW type, Flags, HW address, Mask, Device.
    let campos: Vec<&str> = line.split_whitespace().collect();
    if campos.len() < 6 {
        return None;
    }

    let ip = campos[0].parse::<Ipv4Addr>().ok()?;
    // El tipo de hardware no se usa, pero debe ser hexadecimal (descarta basura).
    u16::from_str_radix(sin_prefijo_hexadecimal(campos[1]), 16).ok()?;
    let flags = u16::from_str_radix(sin_prefijo_hexadecimal(campos[2]), 16).ok()?;
    let mac = oui::normalize_mac(campos[3])?;
    let iface = campos[5].to_string();

    Some(ArpEntry {
        ip,
        mac,
        flags,
        iface,
    })
}

/// Quita el prefijo `0x`/`0X` que el núcleo usa en las columnas hexadecimales.
fn sin_prefijo_hexadecimal(valor: &str) -> &str {
    valor
        .strip_prefix("0x")
        .or_else(|| valor.strip_prefix("0X"))
        .unwrap_or(valor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tabla ARP realista con cabecera, entradas completas e incompletas.
    const TABLA_ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0
192.168.1.42     0x1         0x2         02:11:22:33:44:55     *        wlan0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.100    0x1         0x2         00:00:00:00:00:00     *        eth0
";

    #[test]
    fn parsea_una_linea_completa() {
        let entrada = parse_line(
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0",
        )
        .expect("línea válida");
        assert_eq!(entrada.ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entrada.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(entrada.flags, 0x2);
        assert_eq!(entrada.iface, "eth0");
        assert!(entrada.is_complete());
    }

    #[test]
    fn normaliza_macs_en_mayusculas() {
        let entrada =
            parse_line("10.0.0.7 0x1 0x2 AA:BB:CC:DD:EE:01 * eth0").expect("línea válida");
        assert_eq!(entrada.mac, "aa:bb:cc:dd:ee:01");
    }

    #[test]
    fn entrada_incompleta_no_esta_completa() {
        let entrada =
            parse_line("192.168.1.99 0x1 0x0 00:00:00:00:00:00 * eth0").expect("línea válida");
        assert_eq!(entrada.flags, 0);
        assert!(!entrada.is_complete());
        assert_eq!(entrada.mac, "00:00:00:00:00:00");
    }

    #[test]
    fn flags_sin_prefijo_tambien_son_validos() {
        let entrada =
            parse_line("192.168.1.5 0x1 0002 aa:bb:cc:dd:ee:02 * eth0").expect("línea válida");
        assert_eq!(entrada.flags, 0x2);
    }

    #[test]
    fn rechaza_cabecera_y_lineas_invalidas() {
        assert!(parse_line(
            "IP address       HW type     Flags       HW address            Mask     Device"
        )
        .is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
        // IP no válida.
        assert!(parse_line("no-es-ip 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0").is_none());
        // MAC no válida.
        assert!(parse_line("192.168.1.1 0x1 0x2 zz:zz:zz:zz:zz:zz * eth0").is_none());
        // Flags no válidos.
        assert!(parse_line("192.168.1.1 0x1 xx aa:bb:cc:dd:ee:ff * eth0").is_none());
        // Faltan columnas.
        assert!(parse_line("192.168.1.1 0x1 0x2 aa:bb:cc:dd:ee:ff").is_none());
    }

    #[test]
    fn lee_tabla_completa_desde_fichero() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("arp");
        std::fs::write(&ruta, TABLA_ARP).expect("escribir tabla de prueba");

        let entradas = read_from(&ruta);
        assert_eq!(
            entradas.len(),
            4,
            "se ignoran la cabecera y las líneas vacías"
        );
        assert_eq!(entradas[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entradas[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(entradas[1].iface, "wlan0");
        assert!(!entradas[2].is_complete());
        assert_eq!(entradas[3].flags, 0x2);
    }

    #[test]
    fn fichero_inexistente_devuelve_lista_vacia() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("no-existe");
        assert!(read_from(&ruta).is_empty());
    }

    #[test]
    fn lectura_del_sistema_es_tolerante() {
        // Sin privilegios /proc/net/arp puede estar vacía o no existir: nunca falla.
        let entradas = read();
        for entrada in &entradas {
            assert_eq!(entrada.mac.len(), 17);
            assert!(entrada.iface.len() <= 32);
        }
    }
}
