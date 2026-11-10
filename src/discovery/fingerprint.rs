//! Fingerprint heurístico de sistema operativo (TTL + opciones TCP + banner).
//!
//! La detección es una función pura sobre [`TcpFingerprint`] con umbral de
//! confianza: si la puntuación máxima no alcanza [`CONFIDENCE_THRESHOLD`] se
//! devuelve None y la capa de persistencia deja `os_family` a NULL.
//!
//! La puntuación es la de la especificación (§7): TTL inicial estimado, tamaño de
//! ventana, opciones TCP (timestamps, SACK, MSS) y banner. Los empates se
//! resuelven por el orden fijo de [`OsFamily::ALL`].
//!
//! Nota: con las reglas de la especificación macOS e iOS solo suman 1 punto por
//! TTL (más 2 por banner en macOS), por lo que en la práctica no alcanzan el
//! umbral de 4. Es el comportamiento pedido por la especificación, no un fallo.

use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use crate::classify::OsFamily;

/// Umbral de confianza mínimo para reportar una familia de SO.
pub const CONFIDENCE_THRESHOLD: u8 = 4;

/// Bit de `tcpi_options` que indica timestamps TCP activos.
const TCPI_OPT_TIMESTAMPS: u8 = 0x01;
/// Bit de `tcpi_options` que indica SACK permitido.
const TCPI_OPT_SACK: u8 = 0x02;
/// Bit de `tcpi_options` que indica negociación de escala de ventana.
const TCPI_OPT_WSCALE: u8 = 0x04;

/// Protocolo ICMP en la cabecera IPv4.
const PROTOCOLO_ICMP: u8 = 1;
/// Tipo ICMP de un Echo Request.
const ICMP_ECHO_REQUEST: u8 = 8;
/// Tipo ICMP de un Echo Reply.
const ICMP_ECHO_REPLY: u8 = 0;
/// Tamaño mínimo de una cabecera IPv4.
const TAMANO_CABECERA_IPV4: usize = 20;

/// Opciones TCP observadas en una conexión.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpOptions {
    /// El par usa timestamps.
    pub timestamps: bool,
    /// El par permite SACK.
    pub sack_ok: bool,
    /// Factor de escala de ventana negociado.
    pub window_scale: Option<u8>,
    /// MSS negociado.
    pub mss: Option<u16>,
}

/// Datos observados de un equipo para estimar su familia de SO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpFingerprint {
    /// TTL observado en la respuesta ICMP.
    pub observed_ttl: Option<u8>,
    /// Tamaño de ventana TCP (no observable con CONNECT scan; None salvo banner).
    pub window: Option<u16>,
    /// Opciones TCP negociadas.
    pub options: TcpOptions,
    /// Banner(s) obtenidos de los puertos abiertos.
    pub banner: Option<String>,
}

/// Estimador heurístico de familia de SO.
#[derive(Debug, Clone, Copy)]
pub struct Fingerprint;

impl Fingerprint {
    /// Devuelve la familia de SO solo si la confianza alcanza el umbral.
    // API del checklist de Fase 2: el orquestador puede usar detect o
    // detect_with_score; se conserva aunque la integración use la segunda.
    #[allow(dead_code)]
    pub fn detect(fp: &TcpFingerprint) -> Option<OsFamily> {
        Self::detect_with_score(fp).0
    }

    /// Devuelve la mejor familia y su puntuación (aunque no alcance el umbral).
    ///
    /// La puntuación máxima se devuelve siempre; la familia solo cuando alcanza
    /// [`CONFIDENCE_THRESHOLD`]. Los empates se resuelven por el orden de
    /// [`OsFamily::ALL`] (Linux, Windows, MacOs, Ios, Android, Iot).
    pub fn detect_with_score(fp: &TcpFingerprint) -> (Option<OsFamily>, u8) {
        let puntos = Self::puntuar(fp);
        let mut mejor = OsFamily::Linux;
        let mut maxima = 0u8;
        for (indice, familia) in OsFamily::ALL.into_iter().enumerate() {
            if puntos[indice] > maxima {
                maxima = puntos[indice];
                mejor = familia;
            }
        }
        if maxima >= CONFIDENCE_THRESHOLD {
            (Some(mejor), maxima)
        } else {
            (None, maxima)
        }
    }

    /// Estima el TTL inicial a partir del TTL observado (64, 128 o 255).
    ///
    /// Se elige el valor canónico inmediatamente superior: los sistemas Unix
    /// parten de 64, Windows de 128 y algunos equipos de red de 255.
    pub fn estimate_initial_ttl(observed: u8) -> u8 {
        if observed <= 64 {
            64
        } else if observed <= 128 {
            128
        } else {
            255
        }
    }

    /// Observa el TTL de un equipo con un eco ICMP raw (requiere CAP_NET_RAW).
    ///
    /// Devuelve el TTL observado de la cabecera IP de un Echo Reply que coincida
    /// con el identificador enviado. Falla en silencio (`None`) si no hay
    /// privilegios, si el envío falla o si no llega respuesta en el timeout.
    /// El TTL inicial se estima después con [`Self::estimate_initial_ttl`].
    pub fn probe_ttl(ip: Ipv4Addr, timeout: Duration) -> Option<u8> {
        if timeout.is_zero() {
            return None;
        }
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
        if fd < 0 {
            return None;
        }
        let socket = SocketCrudo(fd);
        configurar_timeout_recepcion(socket.0, timeout)?;
        let identificador = std::process::id() as u16;
        let paquete = construir_echo_request(identificador);
        enviar_icmp(socket.0, ip, &paquete)?;

        let limite = Instant::now() + timeout;
        let mut buffer = [0u8; 1500];
        while Instant::now() < limite {
            let recibidos = unsafe {
                libc::recv(
                    socket.0,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(),
                    0,
                )
            };
            if recibidos < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // SO_RCVTIMEO vencido: no hay respuesta que esperar.
                    _ => return None,
                }
            }
            if let Some(ttl) = ttl_de_echo_reply(&buffer[..recibidos as usize], identificador) {
                return Some(ttl);
            }
        }
        None
    }

    /// Parsea los bytes de la estructura tcp_info de Linux.
    ///
    /// Layout de `struct tcp_info` (linux/tcp.h): `tcpi_options` en el byte 5,
    /// `tcpi_snd_wscale`/`tcpi_rcv_wscale` en el byte 6 (nibble bajo = escala
    /// anunciada por el par) y `tcpi_snd_mss` (u32 nativo) en el offset 16.
    /// Un búfer más corto devuelve los campos que quepan y deja None en el resto.
    pub fn options_from_tcp_info(bytes: &[u8]) -> TcpOptions {
        let banderas = bytes.get(5).copied().unwrap_or(0);
        let timestamps = banderas & TCPI_OPT_TIMESTAMPS != 0;
        let sack_ok = banderas & TCPI_OPT_SACK != 0;
        let window_scale = if banderas & TCPI_OPT_WSCALE != 0 {
            bytes.get(6).map(|escalas| escalas & 0x0f)
        } else {
            None
        };
        let mss = match bytes.get(16..20) {
            Some(datos) => {
                let valor = u32::from_ne_bytes([datos[0], datos[1], datos[2], datos[3]]);
                u16::try_from(valor).ok().filter(|mss| *mss > 0)
            }
            None => None,
        };
        TcpOptions {
            timestamps,
            sack_ok,
            window_scale,
            mss,
        }
    }

    /// Lee las opciones TCP negociadas de un socket conectado.
    ///
    /// Usa `getsockopt(TCP_INFO)` sobre el descriptor; devuelve None si el
    /// descriptor no es un socket TCP válido o si el núcleo no lo soporta (no
    /// entra en pánico en ningún caso).
    pub fn read_tcp_options(fd: RawFd) -> Option<TcpOptions> {
        if fd < 0 {
            return None;
        }
        let mut datos = [0u8; 256];
        let mut longitud = datos.len() as libc::socklen_t;
        let resultado = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                datos.as_mut_ptr() as *mut c_void,
                &mut longitud,
            )
        };
        if resultado != 0 {
            return None;
        }
        let longitud = (longitud as usize).min(datos.len());
        Some(Self::options_from_tcp_info(&datos[..longitud]))
    }

    /// Calcula la puntuación de cada familia según la especificación §7.
    ///
    /// El orden del array coincide con [`OsFamily::ALL`]:
    /// `[linux, windows, macos, ios, android, iot]`.
    fn puntuar(fp: &TcpFingerprint) -> [u8; 6] {
        let mut puntos = [0u8; 6];

        // El TTL de la cabecera IP llega decrementado por los saltos; se estima el
        // inicial. Las dos comprobaciones son independientes (así lo define la
        // especificación): un TTL inicial de 64 puntúa a Linux/macOS/iOS y también
        // a Windows/Android.
        if let Some(observado) = fp.observed_ttl {
            let inicial = Self::estimate_initial_ttl(observado);
            if inicial <= 64 {
                puntos[0] += 2; // linux
                puntos[2] += 1; // macos
                puntos[3] += 1; // ios
            }
            if inicial <= 128 {
                puntos[1] += 2; // windows
                puntos[4] += 1; // android
            }
        }

        if let Some(ventana) = fp.window {
            if ventana == 64240 || ventana == 65535 {
                puntos[1] += 1; // windows
            }
            if ventana == 5840 {
                puntos[0] += 1; // linux
            }
        }

        if fp.options.timestamps {
            puntos[0] += 1; // linux
        }
        if fp.options.sack_ok {
            puntos[1] += 1; // windows
            puntos[0] += 1; // linux
        }
        if fp.options.mss == Some(1460) {
            puntos[0] += 1; // linux
            puntos[1] += 1; // windows
        }

        if let Some(banner) = &fp.banner {
            let banner = banner.to_ascii_lowercase();
            if banner.contains("openssh") || banner.contains("ubuntu") || banner.contains("debian")
            {
                puntos[0] += 2; // linux
            }
            if banner.contains("microsoft") || banner.contains("windows") || banner.contains("iis")
            {
                puntos[1] += 2; // windows
            }
            if banner.contains("darwin") || banner.contains("macos") {
                puntos[2] += 2; // macos
            }
        }

        puntos
    }
}

/// Socket crudo que se cierra solo al salir de [`Fingerprint::probe_ttl`].
struct SocketCrudo(RawFd);

impl Drop for SocketCrudo {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Configura el timeout de recepción del socket (`SO_RCVTIMEO`).
fn configurar_timeout_recepcion(fd: RawFd, timeout: Duration) -> Option<()> {
    let microsegundos = timeout.as_micros().min(i64::MAX as u128) as i64;
    let valor = libc::timeval {
        tv_sec: (microsegundos / 1_000_000) as libc::time_t,
        tv_usec: (microsegundos % 1_000_000) as libc::suseconds_t,
    };
    let resultado = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &valor as *const libc::timeval as *const c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    (resultado == 0).then_some(())
}

/// Construye un Echo Request ICMP con el identificador indicado.
fn construir_echo_request(identificador: u16) -> Vec<u8> {
    let mut paquete = vec![
        ICMP_ECHO_REQUEST,
        0,
        0,
        0,
        (identificador >> 8) as u8,
        identificador as u8,
        0,
        1,
        b'A',
        b'L',
        b'M',
        b'E',
        b'N',
        b'A',
        b'R',
        b'A',
    ];
    let suma = checksum(&paquete);
    paquete[2] = (suma >> 8) as u8;
    paquete[3] = suma as u8;
    paquete
}

/// Checksum de Internet (RFC 1071) de un bloque de bytes.
fn checksum(datos: &[u8]) -> u16 {
    let mut suma: u32 = 0;
    let mut indice = 0;
    while indice + 1 < datos.len() {
        suma += u32::from(u16::from_be_bytes([datos[indice], datos[indice + 1]]));
        indice += 2;
    }
    if indice < datos.len() {
        suma += u32::from(datos[indice]) << 8;
    }
    while suma >> 16 != 0 {
        suma = (suma & 0xffff) + (suma >> 16);
    }
    !(suma as u16)
}

/// Envía un paquete ICMP al equipo indicado.
fn enviar_icmp(fd: RawFd, ip: Ipv4Addr, paquete: &[u8]) -> Option<()> {
    let mut direccion: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    direccion.sin_family = libc::AF_INET as libc::sa_family_t;
    direccion.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    let enviados = unsafe {
        libc::sendto(
            fd,
            paquete.as_ptr() as *const c_void,
            paquete.len(),
            0,
            &direccion as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    (enviados == paquete.len() as isize).then_some(())
}

/// Extrae el TTL de la cabecera IPv4 de un paquete recibido.
///
/// Devuelve `(ttl, protocolo, longitud_cabecera)`; None si el paquete no es IPv4
/// o está truncado.
fn ttl_cabecera_ip(paquete: &[u8]) -> Option<(u8, u8, usize)> {
    if paquete.len() < TAMANO_CABECERA_IPV4 {
        return None;
    }
    if paquete[0] >> 4 != 4 {
        return None;
    }
    let longitud_cabecera = usize::from(paquete[0] & 0x0f) * 4;
    if longitud_cabecera < TAMANO_CABECERA_IPV4 || paquete.len() < longitud_cabecera {
        return None;
    }
    Some((paquete[8], paquete[9], longitud_cabecera))
}

/// Devuelve el TTL de un Echo Reply que coincida con el identificador esperado.
fn ttl_de_echo_reply(paquete: &[u8], identificador: u16) -> Option<u8> {
    let (ttl, protocolo, longitud_cabecera) = ttl_cabecera_ip(paquete)?;
    if protocolo != PROTOCOLO_ICMP {
        return None;
    }
    let icmp = paquete.get(longitud_cabecera..)?;
    if icmp.len() < 8 || icmp[0] != ICMP_ECHO_REPLY {
        return None;
    }
    let identificador_respuesta = u16::from_be_bytes([icmp[4], icmp[5]]);
    (identificador_respuesta == identificador).then_some(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye una representación sintética de tcp_info para los tests.
    fn tcp_info_fixture(banderas: u8, escalas: u8, mss: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 24];
        bytes[5] = banderas;
        bytes[6] = escalas;
        bytes[16..20].copy_from_slice(&mss.to_ne_bytes());
        bytes
    }

    /// Construye un fingerprint con comodidad para los tests de puntuación.
    fn fingerprint(
        ttl: Option<u8>,
        window: Option<u16>,
        options: TcpOptions,
        banner: Option<&str>,
    ) -> TcpFingerprint {
        TcpFingerprint {
            observed_ttl: ttl,
            window,
            options,
            banner: banner.map(str::to_string),
        }
    }

    fn opciones(timestamps: bool, sack_ok: bool, mss: Option<u16>) -> TcpOptions {
        TcpOptions {
            timestamps,
            sack_ok,
            window_scale: None,
            mss,
        }
    }

    #[test]
    fn estima_el_ttl_inicial_canonico() {
        assert_eq!(Fingerprint::estimate_initial_ttl(0), 64);
        assert_eq!(Fingerprint::estimate_initial_ttl(1), 64);
        assert_eq!(Fingerprint::estimate_initial_ttl(63), 64);
        assert_eq!(Fingerprint::estimate_initial_ttl(64), 64);
        assert_eq!(Fingerprint::estimate_initial_ttl(65), 128);
        assert_eq!(Fingerprint::estimate_initial_ttl(127), 128);
        assert_eq!(Fingerprint::estimate_initial_ttl(128), 128);
        assert_eq!(Fingerprint::estimate_initial_ttl(129), 255);
        assert_eq!(Fingerprint::estimate_initial_ttl(254), 255);
        assert_eq!(Fingerprint::estimate_initial_ttl(255), 255);
    }

    #[test]
    fn sin_datos_no_hay_familia_ni_puntuacion() {
        let fp = TcpFingerprint::default();
        assert_eq!(Fingerprint::detect_with_score(&fp), (None, 0));
        assert_eq!(Fingerprint::detect(&fp), None);
    }

    #[test]
    fn el_ttl_solo_no_alcanza_el_umbral() {
        // TTL inicial 64: linux=2, macos=1, ios=1, windows=2, android=1.
        let fp = fingerprint(Some(64), None, TcpOptions::default(), None);
        assert_eq!(Fingerprint::detect_with_score(&fp), (None, 2));
        assert_eq!(Fingerprint::detect(&fp), None);
    }

    #[test]
    fn datos_ambiguos_por_debajo_del_umbral_devuelven_none() {
        // TTL 64 + ventana de Windows: windows=3, linux=2 → máximo 3 < 4.
        let fp = fingerprint(Some(64), Some(65535), TcpOptions::default(), None);
        assert_eq!(Fingerprint::detect_with_score(&fp), (None, 3));
        assert_eq!(Fingerprint::detect(&fp), None);
    }

    #[test]
    fn ventana_y_sack_alcanzan_el_umbral_justo_para_windows() {
        // TTL 64 + ventana 65535 + SACK: windows=4, linux=3.
        let fp = fingerprint(Some(64), Some(65535), opciones(false, true, None), None);
        assert_eq!(
            Fingerprint::detect_with_score(&fp),
            (Some(OsFamily::Windows), 4)
        );
        assert_eq!(Fingerprint::detect(&fp), Some(OsFamily::Windows));
    }

    #[test]
    fn timestamps_mss_y_banner_openssh_detectan_linux() {
        // TTL inicial 128: windows=2, android=1; timestamps+mss+banner: linux=4.
        let fp = fingerprint(
            Some(100),
            None,
            opciones(true, false, Some(1460)),
            Some("SSH-2.0-OpenSSH_9.6"),
        );
        assert_eq!(
            Fingerprint::detect_with_score(&fp),
            (Some(OsFamily::Linux), 4)
        );
    }

    #[test]
    fn ventana_5840_y_timestamps_detectan_linux_desde_ttl_64() {
        // linux=2 (TTL) +1 (ventana 5840) +1 (timestamps) = 4.
        let fp = fingerprint(Some(64), Some(5840), opciones(true, false, None), None);
        assert_eq!(
            Fingerprint::detect_with_score(&fp),
            (Some(OsFamily::Linux), 4)
        );
    }

    #[test]
    fn el_banner_de_windows_detecta_windows_sin_opciones() {
        // TTL 128: windows=2; banner Microsoft: +2 → 4.
        let fp = fingerprint(
            Some(128),
            None,
            TcpOptions::default(),
            Some("Microsoft-IIS/10.0"),
        );
        assert_eq!(
            Fingerprint::detect_with_score(&fp),
            (Some(OsFamily::Windows), 4)
        );
    }

    #[test]
    fn el_empate_se_resuelve_por_el_orden_del_enum() {
        // TTL 64 + SACK + MSS 1460: linux=4, windows=4 → gana Linux (orden del enum).
        let fp = fingerprint(Some(64), None, opciones(false, true, Some(1460)), None);
        assert_eq!(
            Fingerprint::detect_with_score(&fp),
            (Some(OsFamily::Linux), 4)
        );
    }

    #[test]
    fn el_banner_de_macos_no_alcanza_el_umbral_especificado() {
        // macOS suma 1 por TTL y 2 por banner = 3; la especificación no le da más
        // señales, así que se queda en None (comportamiento pedido).
        let fp = fingerprint(
            Some(64),
            None,
            TcpOptions::default(),
            Some("Darwin Kernel Version 23.0.0"),
        );
        assert_eq!(Fingerprint::detect_with_score(&fp), (None, 3));
        assert_eq!(Fingerprint::detect(&fp), None);
    }

    #[test]
    fn el_banner_se_compara_sin_distinguir_mayusculas() {
        // TTL inicial 64 (linux=2) + banner Ubuntu en mayúsculas (+2) = 4.
        let fp = fingerprint(Some(64), None, TcpOptions::default(), Some("UBUNTU SSH"));
        assert_eq!(
            Fingerprint::detect_with_score(&fp),
            (Some(OsFamily::Linux), 4)
        );
    }

    #[test]
    fn parsea_tcp_info_completo() {
        // options=timestamps|SACK|WSCALE, escalas: par=2 (nibble alto), propia=7 (bajo).
        let opciones = Fingerprint::options_from_tcp_info(&tcp_info_fixture(0x07, 0x27, 1460));
        assert!(opciones.timestamps);
        assert!(opciones.sack_ok);
        assert_eq!(opciones.window_scale, Some(7));
        assert_eq!(opciones.mss, Some(1460));
    }

    #[test]
    fn parsea_tcp_info_sin_opciones_ni_mss() {
        let opciones = Fingerprint::options_from_tcp_info(&tcp_info_fixture(0x00, 0xff, 0));
        assert!(!opciones.timestamps);
        assert!(!opciones.sack_ok);
        assert_eq!(opciones.window_scale, None);
        assert_eq!(opciones.mss, None);
    }

    #[test]
    fn parsea_tcp_info_con_escala_cero() {
        let opciones = Fingerprint::options_from_tcp_info(&tcp_info_fixture(0x04, 0x20, 536));
        assert_eq!(opciones.window_scale, Some(0));
        assert_eq!(opciones.mss, Some(536));
    }

    #[test]
    fn un_tcp_info_corto_o_vacio_no_entra_en_panico() {
        assert_eq!(
            Fingerprint::options_from_tcp_info(&[]),
            TcpOptions::default()
        );
        assert_eq!(
            Fingerprint::options_from_tcp_info(&[0u8; 4]),
            TcpOptions::default()
        );
        let mut corto = vec![0u8; 10];
        corto[5] = 0x03;
        let opciones = Fingerprint::options_from_tcp_info(&corto);
        assert!(opciones.timestamps);
        assert!(opciones.sack_ok);
        assert_eq!(opciones.window_scale, None);
        assert_eq!(opciones.mss, None);
    }

    #[test]
    fn un_mss_fuera_de_rango_se_descarta() {
        let opciones = Fingerprint::options_from_tcp_info(&tcp_info_fixture(0x00, 0x00, 70_000));
        assert_eq!(opciones.mss, None);
    }

    #[test]
    fn read_tcp_options_con_descriptor_invalido_devuelve_none() {
        assert!(Fingerprint::read_tcp_options(-1).is_none());
    }

    #[test]
    fn read_tcp_options_no_entra_en_panico_con_cualquier_descriptor() {
        // El descriptor 0 puede ser cualquier cosa en el harness de tests: la
        // función debe devolver None o datos, nunca entrar en pánico.
        let _ = Fingerprint::read_tcp_options(0);
    }

    #[test]
    fn el_checksum_del_echo_request_es_valido() {
        let paquete = construir_echo_request(0x1234);
        assert_eq!(paquete[0], ICMP_ECHO_REQUEST);
        assert_eq!(&paquete[4..6], &[0x12, 0x34]);
        assert_eq!(checksum(&paquete), 0);
    }

    #[test]
    fn parsea_el_ttl_de_la_cabecera_ip() {
        let mut paquete = vec![0u8; 28];
        paquete[0] = 0x45; // IPv4 con cabecera de 20 bytes
        paquete[8] = 63; // TTL
        paquete[9] = PROTOCOLO_ICMP;
        assert_eq!(
            ttl_cabecera_ip(&paquete),
            Some((63, PROTOCOLO_ICMP, TAMANO_CABECERA_IPV4))
        );
        paquete[0] = 0x65; // versión 6: no es IPv4
        assert_eq!(ttl_cabecera_ip(&paquete), None);
        assert_eq!(ttl_cabecera_ip(&[]), None);
        assert_eq!(ttl_cabecera_ip(&[0x45]), None);
    }

    #[test]
    fn reconoce_solo_el_echo_reply_esperado() {
        let mut paquete = vec![0u8; 28];
        paquete[0] = 0x45;
        paquete[8] = 57;
        paquete[9] = PROTOCOLO_ICMP;
        paquete[20] = ICMP_ECHO_REPLY;
        paquete[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        assert_eq!(ttl_de_echo_reply(&paquete, 0x1234), Some(57));
        assert_eq!(ttl_de_echo_reply(&paquete, 0x9999), None);
        paquete[20] = ICMP_ECHO_REQUEST;
        assert_eq!(ttl_de_echo_reply(&paquete, 0x1234), None);
        paquete[20] = ICMP_ECHO_REPLY;
        paquete[9] = 6; // TCP: no es ICMP
        assert_eq!(ttl_de_echo_reply(&paquete, 0x1234), None);
    }

    #[test]
    fn probe_ttl_no_entra_en_panico_sin_privilegios() {
        // Sin CAP_NET_RAW devuelve None; con privilegios puede devolver el TTL del
        // loopback. En ningún caso debe entrar en pánico ni bloquearse.
        let _ = Fingerprint::probe_ttl(Ipv4Addr::LOCALHOST, Duration::from_millis(50));
        assert!(Fingerprint::probe_ttl(Ipv4Addr::LOCALHOST, Duration::ZERO).is_none());
    }
}
