//! Conexiones activas del núcleo: `/proc/net/{tcp,udp}{,6}` y `/proc/net/nf_conntrack`.
//!
//! Este módulo es la fuente pasiva de conexiones de la Fase 3: no abre sockets y no
//! lanza tráfico. [`ProcNet`] lee los sockets abiertos por el propio host y
//! [`Conntrack`] la tabla de seguimiento de conexiones del núcleo, en ambos casos
//! con degradación silenciosa cuando el fichero no existe o no hay permisos para leerlo.
//!
//! Formato de `/proc/net/tcp` (los ficheros UDP son análogos, con `udp`/`udp6`):
//!
//! ```text
//!   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
//!    0: 0100007F:0C08 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 48061 ...
//! ```
//!
//! Las direcciones se imprimen en hexadecimal en el orden de bytes nativo del núcleo:
//! en una máquina little-endian `0100007F` es `127.0.0.1`, y en
//! `/proc/net/tcp6` cada dirección son cuatro palabras de 32 bits en ese mismo
//! orden. La décima columna es el inodo del socket, que [`super::process`] cruza
//! con `/proc/[pid]/fd` para atribuir cada conexión a un proceso.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::capture::Protocol;
use crate::error::Result;

/// Fichero del núcleo con los sockets TCP IPv4.
const RUTA_TCP: &str = "/proc/net/tcp";
/// Fichero del núcleo con los sockets TCP IPv6 (puede no existir en el núcleo).
const RUTA_TCP6: &str = "/proc/net/tcp6";
/// Fichero del núcleo con los sockets UDP IPv4.
const RUTA_UDP: &str = "/proc/net/udp";
/// Fichero del núcleo con los sockets UDP IPv6 (puede no existir en el núcleo).
const RUTA_UDP6: &str = "/proc/net/udp6";
/// Tabla de seguimiento de conexiones; sin privilegios suele dar permiso denegado.
const RUTA_CONNTRACK: &str = "/proc/net/nf_conntrack";

/// Entrada de `/proc/net/{tcp,udp}{,6}`: un socket abierto por el propio host.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcNetEntry {
    /// IP local del socket.
    pub local_ip: IpAddr,
    /// Puerto local del socket.
    pub local_port: u16,
    /// IP remota del socket (`0.0.0.0` o `::` en sockets a la escucha).
    pub remote_ip: IpAddr,
    /// Puerto remoto del socket (0 en sockets a la escucha).
    pub remote_port: u16,
    /// Estado TCP en mayúsculas; `None` en UDP y en códigos desconocidos.
    pub state: Option<String>,
    /// Inodo del socket (enlaza con `/proc/[pid]/fd`, ver [`super::process`]).
    pub inode: u64,
    /// Protocolo de transporte de la entrada (`Tcp` o `Udp`).
    pub protocol: Protocol,
}

/// Lector de los sockets del host en `/proc/net/{tcp,udp}{,6}`.
#[derive(Debug, Clone, Copy)]
pub struct ProcNet;

impl ProcNet {
    /// Lee los sockets TCP del host (`/proc/net/tcp` y `/proc/net/tcp6`).
    ///
    /// La ausencia de `/proc/net/tcp6` se tolera (núcleo sin IPv6); si no se puede
    /// leer `/proc/net/tcp` se devuelve el error de E/S correspondiente.
    pub fn read_tcp() -> Result<Vec<ProcNetEntry>> {
        Self::read_tcp_from(Path::new(RUTA_TCP), Path::new(RUTA_TCP6))
    }

    /// Lee los sockets UDP del host (`/proc/net/udp` y `/proc/net/udp6`).
    ///
    /// La ausencia de `/proc/net/udp6` se tolera igual que en TCP.
    pub fn read_udp() -> Result<Vec<ProcNetEntry>> {
        Self::read_udp_from(Path::new(RUTA_UDP), Path::new(RUTA_UDP6))
    }

    /// Parsea el contenido de `/proc/net/tcp` (función pura, testeable sin `/proc`).
    pub fn parse_tcp(content: &str, ipv6: bool) -> Vec<ProcNetEntry> {
        content
            .lines()
            .filter_map(|linea| parsear_linea_procnet(linea, ipv6, true))
            .collect()
    }

    /// Parsea el contenido de `/proc/net/udp` (sin estado: en UDP siempre es `None`).
    pub fn parse_udp(content: &str, ipv6: bool) -> Vec<ProcNetEntry> {
        content
            .lines()
            .filter_map(|linea| parsear_linea_procnet(linea, ipv6, false))
            .collect()
    }

    /// Variante testeable de [`ProcNet::read_tcp`] sobre rutas arbitrarias.
    fn read_tcp_from(tcp: &Path, tcp6: &Path) -> Result<Vec<ProcNetEntry>> {
        let mut entradas = leer_fichero(tcp, false, true)?;
        entradas.extend(leer_fichero_opcional(tcp6, true, true));
        Ok(entradas)
    }

    /// Variante testeable de [`ProcNet::read_udp`] sobre rutas arbitrarias.
    fn read_udp_from(udp: &Path, udp6: &Path) -> Result<Vec<ProcNetEntry>> {
        let mut entradas = leer_fichero(udp, false, false)?;
        entradas.extend(leer_fichero_opcional(udp6, true, false));
        Ok(entradas)
    }
}

/// Entrada de `/proc/net/nf_conntrack`: una conexión seguida por el núcleo.
#[derive(Debug, Clone, PartialEq)]
pub struct ConntrackEntry {
    /// Protocolo de transporte (`Tcp` o `Udp`).
    pub protocol: Protocol,
    /// IP de origen de la dirección original.
    pub src_ip: IpAddr,
    /// Puerto de origen de la dirección original.
    pub src_port: u16,
    /// IP de destino de la dirección original.
    pub dst_ip: IpAddr,
    /// Puerto de destino de la dirección original.
    pub dst_port: u16,
    /// Estado conntrack (`ESTABLISHED`, `TIME_WAIT`, ...); `None` en UDP.
    pub state: Option<String>,
}

/// Lector best-effort de `/proc/net/nf_conntrack`.
#[derive(Debug, Clone, Copy)]
pub struct Conntrack;

impl Conntrack {
    /// Lee `/proc/net/nf_conntrack`.
    ///
    /// Es best-effort: si el fichero no existe o no se puede leer (lo habitual sin
    /// privilegios) devuelve una lista vacía, nunca un error.
    pub fn read() -> Result<Vec<ConntrackEntry>> {
        Self::read_from(Path::new(RUTA_CONNTRACK))
    }

    /// Parsea el contenido de `/proc/net/nf_conntrack` (función pura).
    ///
    /// Solo se aceptan conexiones TCP y UDP: las de ICMP no tienen puertos y las
    /// conexiones de la TUI se construyen con 5-tuple.
    pub fn parse(content: &str) -> Vec<ConntrackEntry> {
        content
            .lines()
            .filter_map(parsear_linea_conntrack)
            .collect()
    }

    /// Variante testeable de [`Conntrack::read`] sobre una ruta arbitraria.
    fn read_from(ruta: &Path) -> Result<Vec<ConntrackEntry>> {
        match std::fs::read_to_string(ruta) {
            Ok(contenido) => Ok(Self::parse(&contenido)),
            Err(_) => Ok(Vec::new()),
        }
    }
}

/// Parsea una línea de `/proc/net/tcp{,6}` o `/proc/net/udp{,6}`.
///
/// Devuelve `None` para la cabecera, las líneas vacías y cualquier fila mal formada.
fn parsear_linea_procnet(linea: &str, ipv6: bool, tcp: bool) -> Option<ProcNetEntry> {
    let campos: Vec<&str> = linea.split_whitespace().collect();
    // sl, local, remoto, estado, cola tx:rx, temporizadores, retrnsmt, uid, timeout
    // e inodo: una fila más corta es la cabecera o basura.
    if campos.len() < 10 || !campos[0].ends_with(':') {
        return None;
    }
    let (local_ip, local_port) = parsear_direccion(campos[1], ipv6)?;
    let (remote_ip, remote_port) = parsear_direccion(campos[2], ipv6)?;
    let inode = campos[9].parse::<u64>().ok()?;
    Some(ProcNetEntry {
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state: if tcp { estado_tcp(campos[3]) } else { None },
        inode,
        protocol: if tcp { Protocol::Tcp } else { Protocol::Udp },
    })
}

/// Parsea el par `dirección:puerto` hexadecimal de una fila de `/proc/net`.
fn parsear_direccion(campo: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (direccion_hex, puerto_hex) = campo.split_once(':')?;
    let puerto = u16::from_str_radix(puerto_hex, 16).ok()?;
    let ip = parsear_ip(direccion_hex, ipv6)?;
    Some((ip, puerto))
}

/// Convierte una dirección hexadecimal de `/proc/net` al orden de red.
///
/// El núcleo imprime cada palabra de 32 bits como un entero sin signo en el orden
/// nativo del host; `to_ne_bytes` recupera exactamente los bytes de red, tanto
/// en IPv4 (`0100007F` -> 127.0.0.1) como en IPv6 (cuatro palabras).
fn parsear_ip(direccion_hex: &str, ipv6: bool) -> Option<IpAddr> {
    if ipv6 {
        if direccion_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (indice, trozo) in direccion_hex.as_bytes().chunks(8).enumerate() {
            let palabra = std::str::from_utf8(trozo).ok()?;
            let valor = u32::from_str_radix(palabra, 16).ok()?;
            bytes[indice * 4..indice * 4 + 4].copy_from_slice(&valor.to_ne_bytes());
        }
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        if direccion_hex.len() != 8 {
            return None;
        }
        let valor = u32::from_str_radix(direccion_hex, 16).ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(valor.to_ne_bytes())))
    }
}

/// Traduce el código hexadecimal de estado TCP de `/proc/net/tcp`.
///
/// Del `01` (ESTABLISHED) al `0C` (NEW_SYN_RECV); cualquier otro código -> `None`.
fn estado_tcp(codigo: &str) -> Option<String> {
    let nombre = match u8::from_str_radix(codigo, 16).ok()? {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        _ => return None,
    };
    Some(nombre.to_string())
}

/// Nombres de estado que imprime conntrack.
const ESTADOS_CONNTRACK: [&str; 13] = [
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "CLOSING",
    "NEW_SYN_RECV",
    "DELETE",
];

/// Parsea una línea de `/proc/net/nf_conntrack`.
///
/// La dirección original es el primer par `src`/`dst`; el segundo par (respuesta)
/// se ignora. El estado es el primer nombre de estado reconocido de la línea.
fn parsear_linea_conntrack(linea: &str) -> Option<ConntrackEntry> {
    let campos: Vec<&str> = linea.split_whitespace().collect();
    // Familia, número de familia, protocolo, número de protocolo, timeout...
    if campos.len() < 8 {
        return None;
    }
    let protocol = if campos[2].eq_ignore_ascii_case("tcp") {
        Protocol::Tcp
    } else if campos[2].eq_ignore_ascii_case("udp") {
        Protocol::Udp
    } else {
        return None;
    };

    let mut src_ip: Option<IpAddr> = None;
    let mut dst_ip: Option<IpAddr> = None;
    let mut src_port: Option<u16> = None;
    let mut dst_port: Option<u16> = None;
    let mut estado: Option<String> = None;
    // Solo cuenta la primera aparición de cada campo (la dirección original). Si
    // esa primera aparición es inválida la fila se descarta, en vez de tomar por
    // error el valor del segundo par (respuesta).
    let (mut src_visto, mut dst_visto) = (false, false);
    let (mut sport_visto, mut dport_visto) = (false, false);

    for campo in &campos[3..] {
        if let Some((clave, valor)) = campo.split_once('=') {
            match clave {
                "src" if !src_visto => {
                    src_visto = true;
                    src_ip = valor.parse().ok();
                }
                "dst" if !dst_visto => {
                    dst_visto = true;
                    dst_ip = valor.parse().ok();
                }
                "sport" if !sport_visto => {
                    sport_visto = true;
                    src_port = valor.parse().ok();
                }
                "dport" if !dport_visto => {
                    dport_visto = true;
                    dst_port = valor.parse().ok();
                }
                _ => {}
            }
        } else if protocol == Protocol::Tcp && estado.is_none() {
            estado = estado_conntrack(campo);
        }
    }

    Some(ConntrackEntry {
        protocol,
        src_ip: src_ip?,
        src_port: src_port?,
        dst_ip: dst_ip?,
        dst_port: dst_port?,
        state: estado,
    })
}

/// Devuelve el nombre canónico de un estado conntrack, si se reconoce.
fn estado_conntrack(campo: &str) -> Option<String> {
    ESTADOS_CONNTRACK
        .iter()
        .find(|estado| campo.eq_ignore_ascii_case(estado))
        .map(|estado| (*estado).to_string())
}

/// Lee un fichero de `/proc/net` que debe existir (propaga el error de E/S).
fn leer_fichero(ruta: &Path, ipv6: bool, tcp: bool) -> Result<Vec<ProcNetEntry>> {
    let contenido = std::fs::read_to_string(ruta)?;
    Ok(parsear_contenido(&contenido, ipv6, tcp))
}

/// Lee un fichero de `/proc/net` que puede no existir (lo trata como vacío).
fn leer_fichero_opcional(ruta: &Path, ipv6: bool, tcp: bool) -> Vec<ProcNetEntry> {
    match std::fs::read_to_string(ruta) {
        Ok(contenido) => parsear_contenido(&contenido, ipv6, tcp),
        Err(_) => Vec::new(),
    }
}

/// Despacha al parser público del protocolo correspondiente.
fn parsear_contenido(contenido: &str, ipv6: bool, tcp: bool) -> Vec<ProcNetEntry> {
    if tcp {
        ProcNet::parse_tcp(contenido, ipv6)
    } else {
        ProcNet::parse_udp(contenido, ipv6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tabla TCP IPv4 de ejemplo: LISTEN, ESTABLISHED, TIME_WAIT y estado
    /// desconocido, más una fila basura que debe ignorarse.
    const TABLA_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0C08 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 48061 1 000000003a185da7 100 0 0 10 0
   1: 0100007F:8E2C 5D8BA8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:D431 0100007F:0035 06 00000000:00000000 03:00000B5E 00000000     0        0 33333 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:1F90 00000000:0000 FF 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000000000000 100 0 0 10 0
  basura sin columnas
";

    /// Tabla TCP IPv6 de ejemplo: escucha en `::` y en `::1`.
    const TABLA_TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11168 1 0000000078a06f27 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18995 1 00000000a3abffdb 100 0 0 10 0
";

    /// Tabla UDP de ejemplo: socket en cualquier dirección, sin estado útil.
    const TABLA_UDP: &str = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 2266: 00000000:5223 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 6090580 2 000000000943f639 0
";

    /// Tabla conntrack de ejemplo: TCP, UDP, TCP IPv6, ICMP (se ignora), una fila
    /// con IP inválida y una línea de basura.
    const TABLA_CONNTRACK: &str = "\
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=1.1.1.1 sport=54321 dport=443 src=1.1.1.1 dst=192.168.1.10 sport=443 dport=54321 [ASSURED] mark=0 use=1
ipv4     2 udp      17 29 src=10.0.0.2 dst=8.8.8.8 sport=5353 dport=53 src=8.8.8.8 dst=10.0.0.2 sport=53 dport=5353 [UNREPLIED] mark=0 use=1
ipv6     2 tcp      6 431999 TIME_WAIT src=2001:db8::1 dst=2001:db8::2 sport=1234 dport=443 src=2001:db8::2 dst=2001:db8::1 sport=443 dport=1234 [ASSURED] mark=0 use=1
ipv4     2 icmp     1 29 src=192.168.1.10 dst=1.1.1.1 type=8 code=0 id=1234 src=1.1.1.1 dst=192.168.1.10 type=0 code=0 id=1234 mark=0 use=1
ipv4     2 tcp      6 1 src=basura dst=1.1.1.1 sport=1 dport=2 src=1.1.1.1 dst=1.1.1.1 sport=2 dport=1
linea basura
";

    #[test]
    fn parsea_tcp_ipv4_con_estado_e_inodo() {
        let entradas = ProcNet::parse_tcp(TABLA_TCP, false);
        assert_eq!(entradas.len(), 4, "la fila basura y la cabecera se ignoran");

        let escucha = &entradas[0];
        assert_eq!(escucha.local_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(escucha.local_port, 3080);
        assert_eq!(escucha.remote_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(escucha.remote_port, 0);
        assert_eq!(escucha.state.as_deref(), Some("LISTEN"));
        assert_eq!(escucha.inode, 48061);
        assert!(matches!(escucha.protocol, Protocol::Tcp));

        let establecida = &entradas[1];
        assert_eq!(establecida.local_port, 0x8E2C);
        assert_eq!(
            establecida.remote_ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 139, 93))
        );
        assert_eq!(establecida.remote_port, 443);
        assert_eq!(establecida.state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(establecida.inode, 22222);

        let cerrada = &entradas[2];
        assert_eq!(cerrada.local_port, 54321);
        assert_eq!(cerrada.remote_port, 53);
        assert_eq!(cerrada.state.as_deref(), Some("TIME_WAIT"));
        assert_eq!(cerrada.inode, 33333);

        let desconocida = &entradas[3];
        assert_eq!(desconocida.local_port, 8080);
        assert!(desconocida.state.is_none(), "0xFF no es un estado TCP");
        assert_eq!(desconocida.inode, 44444);
    }

    #[test]
    fn parsea_tcp6_en_orden_de_red() {
        let entradas = ProcNet::parse_tcp(TABLA_TCP6, true);
        assert_eq!(entradas.len(), 2);
        assert_eq!(entradas[0].local_ip, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(entradas[0].local_port, 22);
        assert_eq!(entradas[1].local_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(entradas[1].local_port, 0x0277);
        assert_eq!(entradas[1].state.as_deref(), Some("LISTEN"));
        assert_eq!(entradas[1].inode, 18995);
    }

    #[test]
    fn parsea_udp_sin_estado() {
        let entradas = ProcNet::parse_udp(TABLA_UDP, false);
        assert_eq!(entradas.len(), 1);
        let entrada = &entradas[0];
        assert_eq!(entrada.local_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(entrada.local_port, 0x5223);
        assert!(entrada.state.is_none(), "en UDP el estado no se usa");
        assert_eq!(entrada.inode, 6090580);
        assert!(matches!(entrada.protocol, Protocol::Udp));
    }

    #[test]
    fn no_mezcla_tablas_ipv4_e_ipv6() {
        assert!(
            ProcNet::parse_tcp(TABLA_TCP6, false).is_empty(),
            "una tabla IPv6 no se parsea como IPv4"
        );
        assert!(
            ProcNet::parse_tcp(TABLA_TCP, true).is_empty(),
            "una tabla IPv4 no se parsea como IPv6"
        );
    }

    #[test]
    fn ignora_la_cabecera_y_las_lineas_mal_formadas() {
        let contenido = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  esto no es una fila valida
   1: 0100007F 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 11111
   2: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 no-es-inodo
   3: 0100007F:F0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 11111
";
        assert!(ProcNet::parse_tcp(contenido, false).is_empty());
    }

    #[test]
    fn lee_un_proc_simulado_y_tolera_tcp6_ausente() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let tcp = directorio.path().join("tcp");
        let tcp6 = directorio.path().join("tcp6");
        std::fs::write(&tcp, TABLA_TCP).expect("escribir tcp simulado");

        // tcp6 ausente: se tolera y la lectura es correcta.
        let entradas = ProcNet::read_tcp_from(&tcp, &tcp6).expect("tcp6 ausente se tolera");
        assert_eq!(entradas.len(), 4);

        // tcp ausente: la lectura principal devuelve error de E/S, sin pánico.
        let inexistente = directorio.path().join("no-existe");
        assert!(ProcNet::read_tcp_from(&inexistente, &tcp6).is_err());

        // Lo mismo para UDP.
        let udp = directorio.path().join("udp");
        std::fs::write(&udp, TABLA_UDP).expect("escribir udp simulado");
        let entradas = ProcNet::read_udp_from(&udp, &inexistente).expect("udp leído");
        assert_eq!(entradas.len(), 1);
        assert!(ProcNet::read_udp_from(&inexistente, &udp).is_err());
    }

    #[test]
    fn lectura_real_de_proc_net_es_tolerante() {
        let tcp = ProcNet::read_tcp().expect("/proc/net/tcp debe existir en Linux");
        for entrada in &tcp {
            assert!(matches!(entrada.protocol, Protocol::Tcp));
        }
        let udp = ProcNet::read_udp().expect("/proc/net/udp debe existir en Linux");
        for entrada in &udp {
            assert!(matches!(entrada.protocol, Protocol::Udp));
            assert!(entrada.state.is_none());
        }
    }

    #[test]
    fn parsea_conntrack_tcp_udp_e_ipv6() {
        let entradas = Conntrack::parse(TABLA_CONNTRACK);
        assert_eq!(
            entradas.len(),
            3,
            "ICMP, las filas inválidas y la basura se ignoran"
        );

        let tcp = &entradas[0];
        assert!(matches!(tcp.protocol, Protocol::Tcp));
        assert_eq!(
            tcp.src_ip,
            "192.168.1.10".parse::<IpAddr>().expect("IPv4 válida")
        );
        assert_eq!(tcp.src_port, 54321);
        assert_eq!(
            tcp.dst_ip,
            "1.1.1.1".parse::<IpAddr>().expect("IPv4 válida")
        );
        assert_eq!(tcp.dst_port, 443);
        assert_eq!(tcp.state.as_deref(), Some("ESTABLISHED"));

        let udp = &entradas[1];
        assert!(matches!(udp.protocol, Protocol::Udp));
        assert_eq!(udp.src_port, 5353);
        assert_eq!(udp.dst_port, 53);
        assert!(udp.state.is_none(), "conntrack no da estado a UDP");

        let ipv6 = &entradas[2];
        assert_eq!(
            ipv6.src_ip,
            "2001:db8::1".parse::<IpAddr>().expect("IPv6 válida")
        );
        assert_eq!(
            ipv6.dst_ip,
            "2001:db8::2".parse::<IpAddr>().expect("IPv6 válida")
        );
        assert_eq!(ipv6.state.as_deref(), Some("TIME_WAIT"));
    }

    #[test]
    fn conntrack_ignora_lineas_invalidas() {
        let contenido = "\
ipv4 2 gre 47 29 src=1.1.1.1 dst=2.2.2.2
ipv4 2 tcp 6 1 basura
ipv6 2 udp 17 29 src=no-es-ip dst=8.8.8.8 sport=1 dport=2
";
        assert!(Conntrack::parse(contenido).is_empty());
    }

    #[test]
    fn conntrack_sin_fichero_es_best_effort() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let inexistente = directorio.path().join("nf_conntrack");
        assert!(Conntrack::read_from(&inexistente)
            .expect("best-effort nunca falla")
            .is_empty());

        let fichero = directorio.path().join("nf_conntrack");
        std::fs::write(&fichero, TABLA_CONNTRACK).expect("escribir conntrack simulado");
        let entradas = Conntrack::read_from(&fichero).expect("conntrack legible");
        assert_eq!(entradas.len(), 3);
    }

    #[test]
    fn lectura_real_de_conntrack_es_best_effort() {
        // Sin privilegios el fichero no se puede leer: se devuelve lista vacía, no error.
        let entradas = Conntrack::read().expect("la lectura de conntrack es best-effort");
        for entrada in &entradas {
            assert!(matches!(entrada.protocol, Protocol::Tcp | Protocol::Udp));
        }
    }
}
