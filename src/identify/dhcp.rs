//! Parser de paquetes DHCP capturados (§7.12): opciones 12, 50, 55, 60 y 61.
//!
//! El parser trabaja sobre tráfico hostil: comprueba todas las longitudes antes
//! de leer, nunca entra en pánico y descarta las opciones truncadas o mal
//! formadas. Los campos de texto se sanean con [`sanitize`] (solo imprimibles,
//! 64 caracteres como máximo, §8).

use crate::classify::OsFamily;

/// Información extraída de un paquete DHCP/BOOTP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpInfo {
    /// Tipo de mensaje DHCP (opción 53): 1-13.
    pub message_type: Option<u8>,
    /// MAC del cliente (`chaddr`).
    pub mac: Option<String>,
    /// IP actual del cliente (`ciaddr`).
    pub client_ip: Option<std::net::Ipv4Addr>,
    /// IP asignada (`yiaddr`), útil en un ACK / OFFER.
    pub yiaddr: Option<std::net::Ipv4Addr>,
    /// Opción 55: lista de parámetros en decimal separada por comas.
    pub fingerprint: Option<String>,
    /// Opción 60: vendor class identifier saneado.
    pub vendor: Option<String>,
    /// Opción 12: hostname saneado.
    pub hostname: Option<String>,
    /// Opción 61: client identifier saneado.
    pub client_id: Option<String>,
}

/// Longitud de la cabecera BOOTP, antes de la cookie y las opciones.
const TAMANO_CABECERA: usize = 236;
/// Desplazamiento de `op` (tipo de mensaje BOOTP).
const OFFSET_OP: usize = 0;
/// Desplazamiento de `htype` (tipo de hardware: 1 = Ethernet).
const OFFSET_HTYPE: usize = 1;
/// Desplazamiento de `hlen` (longitud de la dirección de hardware).
const OFFSET_HLEN: usize = 2;
/// Desplazamiento de `ciaddr` (IP actual del cliente).
const OFFSET_CIADDR: usize = 12;
/// Desplazamiento de `yiaddr` (IP asignada por el servidor).
const OFFSET_YIADDR: usize = 16;
/// Desplazamiento de `chaddr` (dirección de hardware del cliente).
const OFFSET_CHADDR: usize = 28;
/// Desplazamiento de la cookie mágica de DHCP.
const OFFSET_COOKIE: usize = TAMANO_CABECERA;
/// Cookie mágica que separa la cabecera BOOTP de las opciones DHCP.
const COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// Longitud máxima de un campo de texto DHCP (§8).
const LIMITE_CAMPO: usize = 64;
/// Tipo de hardware Ethernet (`htype`).
const HTYPE_ETHERNET: u8 = 1;
/// Longitud de una MAC Ethernet (`hlen`).
const HLEN_ETHERNET: u8 = 6;
/// Código TLV de la opción 12 (hostname).
const OPCION_HOSTNAME: u8 = 12;
/// Código TLV de la opción 50 (requested IP address).
const OPCION_REQUESTED_IP: u8 = 50;
/// Código TLV de la opción 53 (DHCP message type).
const OPCION_MESSAGE_TYPE: u8 = 53;
/// Código TLV de la opción 55 (parameter request list).
const OPCION_PRL: u8 = 55;
/// Código TLV de la opción 60 (vendor class identifier).
const OPCION_VENDOR: u8 = 60;
/// Código TLV de la opción 61 (client identifier).
const OPCION_CLIENT_ID: u8 = 61;
/// Código TLV de relleno (padding).
const OPCION_PAD: u8 = 0;
/// Código TLV de fin de opciones.
const OPCION_FIN: u8 = 255;

/// Parsea un datagrama DHCP (UDP 67/68) y devuelve su identidad.
///
/// Se exige la cabecera BOOTP completa, un `op` válido (1 = petición,
/// 2 = respuesta) y la cookie mágica de DHCP. Las opciones TLV se recorren
/// hasta `end` o hasta el final del búfer; una opción truncada interrumpe el
/// recorrido sin pánico y se conserva lo leído hasta ese punto.
pub fn parse(payload: &[u8]) -> Option<DhcpInfo> {
    if payload.len() < OFFSET_COOKIE + COOKIE.len() {
        return None;
    }
    // `op` distingue petición de respuesta; cualquier otro valor no es BOOTP.
    let op = *payload.get(OFFSET_OP)?;
    if op != 1 && op != 2 {
        return None;
    }
    let cookie = payload.get(OFFSET_COOKIE..OFFSET_COOKIE + COOKIE.len())?;
    if cookie != COOKIE.as_slice() {
        return None;
    }

    let htype = *payload.get(OFFSET_HTYPE).unwrap_or(&0);
    let hlen = *payload.get(OFFSET_HLEN).unwrap_or(&0);
    let mut info = DhcpInfo {
        mac: mac_desde_chaddr(payload, htype, hlen),
        client_ip: ipv4_no_nula(payload.get(OFFSET_CIADDR..OFFSET_CIADDR + 4)?),
        yiaddr: ipv4_no_nula(payload.get(OFFSET_YIADDR..OFFSET_YIADDR + 4)?),
        ..DhcpInfo::default()
    };

    parsear_opciones(payload, &mut info);
    Some(info)
}

/// Recorre las opciones TLV de un datagrama DHCP y rellena la identidad.
///
/// Las opciones desconocidas y la 50 se validan pero no se exponen: §7.14 solo
/// admite `ciaddr` o el `yiaddr` de un ACK como IP del equipo observado.
fn parsear_opciones(payload: &[u8], info: &mut DhcpInfo) {
    let mut posicion = OFFSET_COOKIE + COOKIE.len();
    while let Some(&codigo) = payload.get(posicion) {
        if codigo == OPCION_PAD {
            posicion += 1;
            continue;
        }
        if codigo == OPCION_FIN {
            break;
        }
        // Código conocido pero sin byte de longitud: opción mal formada.
        let Some(&longitud) = payload.get(posicion + 1) else {
            break;
        };
        let inicio = posicion + 2;
        let Some(fin) = inicio.checked_add(longitud as usize) else {
            break;
        };
        if fin > payload.len() {
            // Opción truncada por un datagrama corto: se descarta el resto.
            break;
        }
        let valor = &payload[inicio..fin];
        match codigo {
            OPCION_HOSTNAME => info.hostname = sanitize(valor),
            OPCION_REQUESTED_IP => {
                // La opción 50 pide una IP concreta y debe medir 4 bytes. Se
                // parsea y valida, pero no se expone en `DhcpInfo` porque
                // §7.14 solo admite `ciaddr` o el `yiaddr` de un ACK como IP
                // del equipo observado; el recorrido TLV sigue igualmente.
                let _ip_pedida = ipv4_no_nula(valor);
            }
            OPCION_MESSAGE_TYPE => {
                if let Some(&tipo) = valor.first() {
                    if (1..=13).contains(&tipo) {
                        info.message_type = Some(tipo);
                    }
                }
            }
            OPCION_PRL => info.fingerprint = fingerprint(valor),
            OPCION_VENDOR => info.vendor = sanitize(valor),
            OPCION_CLIENT_ID => info.client_id = sanitize(valor),
            // El resto de opciones no aporta identidad; se ignoran.
            _ => {}
        }
        posicion = fin;
    }
}

/// Convierte la información DHCP en la observación del motor de inferencia.
pub fn to_observation(info: &DhcpInfo) -> crate::inference::DhcpObservation {
    crate::inference::DhcpObservation {
        mac: info.mac.clone(),
        ip: info
            .client_ip
            .map(std::net::IpAddr::V4)
            .or_else(|| info.yiaddr.map(std::net::IpAddr::V4)),
        message_type: info.message_type,
        fingerprint: info.fingerprint.clone(),
        vendor: info.vendor.clone(),
        hostname: info.hostname.clone(),
        client_id: info.client_id.clone(),
    }
}

/// Sanea un campo de texto DHCP: solo imprimibles y truncado a 64.
pub fn sanitize(value: &[u8]) -> Option<String> {
    let texto: String = value
        .iter()
        .filter(|byte| (0x20..=0x7E).contains(*byte))
        .map(|byte| *byte as char)
        .take(LIMITE_CAMPO)
        .collect();
    let texto = texto.trim().to_string();
    if texto.is_empty() {
        None
    } else {
        Some(texto)
    }
}

/// Reglas propias de la huella DHCP (§7.12): (familia de SO, puntos).
///
/// Se alimenta del vendor class identifier (opción 60, `vendor`) y de la lista
/// de parámetros pedidos (opción 55, `fingerprint`). Las reglas son pocas y
/// documentadas; cada una indica su origen y se prueba con un paquete sintético
/// fiel al formato real (ver los tests).
pub fn os_hints(vendor: Option<&str>, fingerprint: Option<&str>) -> Vec<(OsFamily, u8)> {
    let mut pistas = Vec::new();
    let vendor = vendor.unwrap_or_default().to_ascii_lowercase();
    let huella = fingerprint.unwrap_or_default();

    // Origen: vendor class que anuncian Windows 10/11 en su DHCP Discover.
    if vendor.starts_with("msft 5.0") {
        pistas.push((OsFamily::Windows, 4));
    }
    // Origen: vendor class de Android desde la versión 11.
    if vendor.starts_with("android-dhcp-") {
        pistas.push((OsFamily::Android, 4));
    }
    // Origen: dhcpcd de Linux declara "dhcpcd-<v>:Linux-<kernel>:<arch>".
    if vendor.contains("dhcpcd") && vendor.contains("linux") {
        pistas.push((OsFamily::Linux, 3));
    }
    // Origen: BusyBox udhcp, habitual en routers y equipos embebidos (IoT).
    if vendor.starts_with("udhcp") {
        pistas.push((OsFamily::Iot, 4));
    }
    // Origen: lA PRL de iOS/macOS lleva 121 como segundo parámetro (los
    // Windows y Android observados no). Aporta 2 puntos a macos y a ios: el
    // modelo anunciado es quien desempata (§7.12).
    if es_prl_apple(huella) {
        pistas.push((OsFamily::MacOs, 2));
        pistas.push((OsFamily::Ios, 2));
    }
    pistas
}

/// Indica si la huella es la PRL de Apple.
///
/// Todas las PRL de Apple observadas empiezan por "1,121,"; se acepta
/// cualquier sufijo porque cambia entre versiones de iOS y macOS.
fn es_prl_apple(huella: &str) -> bool {
    huella.starts_with("1,121,")
}

/// Formatea la MAC del cliente a partir de `chaddr`.
///
/// Solo se anuncia MAC cuando el hardware es Ethernet (`htype` 1) con la
/// longitud canónica de 6 bytes; otro tipo de enlace no se puede representar
/// como MAC y se devuelve `None`.
fn mac_desde_chaddr(payload: &[u8], htype: u8, hlen: u8) -> Option<String> {
    if htype != HTYPE_ETHERNET || hlen != HLEN_ETHERNET {
        return None;
    }
    let bytes = payload.get(OFFSET_CHADDR..OFFSET_CHADDR + HLEN_ETHERNET as usize)?;
    use std::fmt::Write as _;
    let mut mac = String::with_capacity(HLEN_ETHERNET as usize * 3);
    for (indice, byte) in bytes.iter().enumerate() {
        if indice > 0 {
            mac.push(':');
        }
        // `write!` sobre un String no puede fallar.
        let _ = write!(mac, "{byte:02x}");
    }
    Some(mac)
}

/// Lee una IPv4 de 4 bytes y descarta la dirección nula (0.0.0.0 = sin asignar).
fn ipv4_no_nula(bytes: &[u8]) -> Option<std::net::Ipv4Addr> {
    let cuatro: [u8; 4] = bytes.try_into().ok()?;
    let direccion = std::net::Ipv4Addr::from(cuatro);
    if direccion.is_unspecified() {
        None
    } else {
        Some(direccion)
    }
}

/// Convierte la lista de parámetros pedidos (opción 55) en la huella decimal.
///
/// Los valores se mantienen en su orden y separados por comas, que es el orden
/// que usa la huella DHCP. Se acota a [`LIMITE_CAMPO`] caracteres sin partir
/// un número por la mitad.
fn fingerprint(valores: &[u8]) -> Option<String> {
    if valores.is_empty() {
        return None;
    }
    let mut huella = String::new();
    for valor in valores {
        let numero = valor.to_string();
        let necesarios = huella.len() + if huella.is_empty() { 0 } else { 1 } + numero.len();
        if necesarios > LIMITE_CAMPO {
            break;
        }
        if !huella.is_empty() {
            huella.push(',');
        }
        huella.push_str(&numero);
    }
    if huella.is_empty() {
        None
    } else {
        Some(huella)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Construye un datagrama BOOTP/DHCP sintético con cabecera Ethernet.
    ///
    /// El formato es el de RFC 2131: 236 bytes de cabecera BOOTP, la cookie
    /// mágica y las opciones TLV indicadas, cerradas con `end` (255). Los
    /// patrones concretos de cada prueba se describen en su comentario y
    /// proceden de huellas DHCP públicas documentadas.
    fn paquete(
        op: u8,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        chaddr: [u8; 6],
        opciones: &[(u8, &[u8])],
    ) -> Vec<u8> {
        let mut datos = vec![0u8; TAMANO_CABECERA];
        datos[OFFSET_OP] = op;
        datos[OFFSET_HTYPE] = HTYPE_ETHERNET;
        datos[OFFSET_HLEN] = HLEN_ETHERNET;
        datos[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        datos[OFFSET_CIADDR..OFFSET_CIADDR + 4].copy_from_slice(&ciaddr.octets());
        datos[OFFSET_YIADDR..OFFSET_YIADDR + 4].copy_from_slice(&yiaddr.octets());
        datos[OFFSET_CHADDR..OFFSET_CHADDR + 6].copy_from_slice(&chaddr);
        datos.extend_from_slice(&COOKIE);
        for (codigo, valor) in opciones {
            datos.push(*codigo);
            // `pad` y `end` son códigos sueltos, sin longitud ni valor.
            if *codigo == OPCION_PAD || *codigo == OPCION_FIN {
                continue;
            }
            datos.push(valor.len() as u8);
            datos.extend_from_slice(valor);
        }
        datos.push(OPCION_FIN);
        datos
    }

    /// MAC de ejemplo del cliente de las pruebas.
    const MAC_CLIENTE: [u8; 6] = [0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33];

    #[test]
    fn parsea_un_discover_de_windows() {
        // Patrón sintético fiel a la huella DHCP pública de Windows 10/11:
        // vendor class "MSFT 5.0" y PRL 1,3,6,15,119,252,95,44,46.
        let prl = [1u8, 3, 6, 15, 119, 252, 95, 44, 46];
        let datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[
                (OPCION_MESSAGE_TYPE, &[1]),
                (OPCION_HOSTNAME, b"DESKTOP-ABC123"),
                (OPCION_PRL, &prl),
                (OPCION_VENDOR, b"MSFT 5.0"),
            ],
        );

        let info = parse(&datos).expect("paquete DHCP válido");
        assert_eq!(info.message_type, Some(1));
        assert_eq!(info.mac.as_deref(), Some("3c:22:fb:11:22:33"));
        assert_eq!(info.client_ip, None);
        assert_eq!(info.yiaddr, None);
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("1,3,6,15,119,252,95,44,46")
        );
        assert_eq!(info.vendor.as_deref(), Some("MSFT 5.0"));
        assert_eq!(info.hostname.as_deref(), Some("DESKTOP-ABC123"));
        // Windows no envía opción 61 en este patrón.
        assert_eq!(info.client_id, None);
    }

    #[test]
    fn parsea_un_ack_con_yiaddr() {
        // Patrón de un ACK del servidor (op=2): el cliente aún no tiene
        // `ciaddr`, así que la IP asignada llega en `yiaddr`.
        let asignada = Ipv4Addr::new(192, 168, 1, 42);
        let datos = paquete(
            2,
            Ipv4Addr::UNSPECIFIED,
            asignada,
            MAC_CLIENTE,
            &[(OPCION_MESSAGE_TYPE, &[5])],
        );

        let info = parse(&datos).expect("ACK válido");
        assert_eq!(info.message_type, Some(5));
        assert_eq!(info.client_ip, None);
        assert_eq!(info.yiaddr, Some(asignada));
        let observacion = to_observation(&info);
        assert_eq!(
            observacion.ip,
            Some(std::net::IpAddr::V4(asignada)),
            "un ACK aporta la IP asignada como IP del equipo"
        );
        assert_eq!(observacion.mac.as_deref(), Some("3c:22:fb:11:22:33"));
    }

    #[test]
    fn parsea_una_renovacion_con_ciaddr() {
        // En RENEWING/REBINDING el cliente rellena `ciaddr` con su IP actual.
        let actual = Ipv4Addr::new(192, 168, 1, 77);
        let datos = paquete(
            1,
            actual,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_MESSAGE_TYPE, &[3]), (OPCION_HOSTNAME, b"portatil")],
        );

        let info = parse(&datos).expect("REQUEST válido");
        assert_eq!(info.client_ip, Some(actual));
        assert_eq!(
            to_observation(&info).ip,
            Some(std::net::IpAddr::V4(actual)),
            "ciaddr manda sobre cualquier otra IP observada"
        );
    }

    #[test]
    fn parsea_apple_y_sanea_el_client_id() {
        // Patrón de la huella DHCP pública de iOS/macOS: PRL
        // 1,121,3,6,15,119,252,95,44,46 y nombre de host del equipo.
        let prl = [1u8, 121, 3, 6, 15, 119, 252, 95, 44, 46];
        let datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[
                (OPCION_MESSAGE_TYPE, &[1]),
                (OPCION_HOSTNAME, b"iPhone-de-Marta"),
                (OPCION_PRL, &prl),
                (OPCION_VENDOR, b"Apple/iOS"),
                (OPCION_CLIENT_ID, b"cliente-01"),
            ],
        );

        let info = parse(&datos).expect("paquete Apple válido");
        assert_eq!(
            info.fingerprint.as_deref(),
            Some("1,121,3,6,15,119,252,95,44,46")
        );
        assert_eq!(info.vendor.as_deref(), Some("Apple/iOS"));
        assert_eq!(info.hostname.as_deref(), Some("iPhone-de-Marta"));
        assert_eq!(info.client_id.as_deref(), Some("cliente-01"));
    }

    #[test]
    fn la_opcion_50_se_valida_sin_desalinear_las_siguientes() {
        // La opción 50 (requested IP) son 4 bytes; aquí va antes de la 55 para
        // comprobar que el recorrido TLV sigue en la posición correcta.
        let pedida = [192u8, 168, 1, 90];
        let prl = [1u8, 3, 6, 15];
        let datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[
                (OPCION_MESSAGE_TYPE, &[3]),
                (OPCION_REQUESTED_IP, &pedida),
                (OPCION_PRL, &prl),
                (OPCION_VENDOR, b"android-dhcp-13"),
            ],
        );

        let info = parse(&datos).expect("paquete con opción 50");
        // §7.14 solo admite ciaddr o yiaddr como IP observada.
        assert_eq!(info.client_ip, None);
        assert_eq!(info.yiaddr, None);
        assert_eq!(info.fingerprint.as_deref(), Some("1,3,6,15"));
        assert_eq!(info.vendor.as_deref(), Some("android-dhcp-13"));
    }

    #[test]
    fn tolera_padding_y_opciones_desconocidas() {
        // Entre el padding (0) y opciones no soportadas (opción 81) el parser
        // debe seguir hasta el hostname. Longitudes TLV válidas.
        let datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[
                (OPCION_MESSAGE_TYPE, &[1]),
                (OPCION_PAD, &[]),
                (81, &[0, 0, 0, 0x63]),
                (OPCION_HOSTNAME, b"router-casa"),
                (OPCION_PAD, &[]),
            ],
        );

        let info = parse(&datos).expect("paquete con padding");
        assert_eq!(info.hostname.as_deref(), Some("router-casa"));
        assert_eq!(info.message_type, Some(1));
    }

    #[test]
    fn una_opcion_truncada_corta_el_recorrido_sin_panico() {
        // La opción 12 declara 64 bytes y solo quedan 2 (búfer cortado a
        // propósito): se conserva lo leído antes (tipo de mensaje) y no se
        // inventa el hostname.
        let mut datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_MESSAGE_TYPE, &[1])],
        );
        // Quitar el end final y añadir una opción 12 con longitud 64 y dos
        // bytes de valor.
        datos.pop();
        datos.extend_from_slice(&[OPCION_HOSTNAME, 64, b'a', b'b']);

        let info = parse(&datos).expect("la cabecera sigue siendo válida");
        assert_eq!(info.message_type, Some(1));
        assert_eq!(info.hostname, None);
    }

    #[test]
    fn rechaza_cookie_invalida_y_longitudes_cortas() {
        let mut datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_MESSAGE_TYPE, &[1])],
        );
        datos[OFFSET_COOKIE] = 0;
        assert_eq!(parse(&datos), None, "sin cookie mágica no es DHCP");

        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0u8; TAMANO_CABECERA]), None);
        assert_eq!(parse(&[0u8; TAMANO_CABECERA + 3]), None);
    }

    #[test]
    fn rechaza_operaciones_y_tipos_de_mensaje_invalidos() {
        let mut datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_MESSAGE_TYPE, &[1])],
        );
        datos[OFFSET_OP] = 0;
        assert_eq!(parse(&datos), None, "op 0 no es BOOTP");

        // Tipo fuera de 1-13: se ignora.
        let fuera = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_MESSAGE_TYPE, &[14])],
        );
        let info = parse(&fuera).expect("cabecera válida");
        assert_eq!(info.message_type, None);
    }

    #[test]
    fn sin_mac_ethernet_no_se_inventa_una_mac() {
        // htype InfiniBand (32) y hlen 20: no representable como MAC.
        let mut datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_MESSAGE_TYPE, &[1])],
        );
        datos[OFFSET_HTYPE] = 32;
        datos[OFFSET_HLEN] = 20;
        let info = parse(&datos).expect("cabecera válida");
        assert_eq!(info.mac, None);
        assert_eq!(info.message_type, Some(1));
    }

    #[test]
    fn los_campos_largos_se_truncan_a_64_caracteres() {
        let hostname = "h".repeat(80);
        let vendor = "v".repeat(70);
        let datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[
                (OPCION_HOSTNAME, hostname.as_bytes()),
                (OPCION_VENDOR, vendor.as_bytes()),
            ],
        );
        let info = parse(&datos).expect("cabecera válida");
        assert_eq!(info.hostname.as_deref().map(str::len), Some(LIMITE_CAMPO));
        assert_eq!(info.vendor.as_deref().map(str::len), Some(LIMITE_CAMPO));
    }

    #[test]
    fn el_saneado_quita_no_imprimibles_y_espacios_sobrantes() {
        assert_eq!(sanitize(b"  hola\x01mundo  ").as_deref(), Some("holamundo"));
        assert_eq!(sanitize(b"\x00\x01\x02"), None);
        assert_eq!(sanitize(b""), None);
        assert_eq!(sanitize(&[0xff, 0xfe]), None);
    }

    #[test]
    fn la_huella_respeta_el_tope_sin_partir_numeros() {
        // 61 valores consecutivos: la cadena completa no cabe en 64 caracteres.
        let valores: Vec<u8> = (0..=60).collect();
        let huella = fingerprint(&valores).expect("hay huella");
        assert!(huella.len() <= LIMITE_CAMPO, "{huella}");
        assert!(!huella.ends_with(','), "no debe quedar una coma colgando");
        for trozo in huella.split(',') {
            assert!(trozo.parse::<u8>().is_ok(), "{huella}");
        }
        assert_eq!(fingerprint(&[]), None);
    }

    #[test]
    fn todas_las_prefixaciones_y_entradas_aleatorias_son_seguras() {
        // Cualquier prefijo de un paquete válido debe devolver Option sin pánico.
        let valido = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[
                (OPCION_MESSAGE_TYPE, &[1]),
                (OPCION_HOSTNAME, b"equipo"),
                (OPCION_PRL, &[1, 3, 6]),
            ],
        );
        for longitud in 0..=valido.len() {
            let _ = parse(&valido[..longitud]);
        }

        // Ruido determinista (LCG) de diversa longitud, con la cookie a veces
        // presente, para cubrir longitudes TLV absurdas sin depender de rand.
        let mut estado: u64 = 0x2545_f491_4f6c_dd1d;
        for longitud in 0..600usize {
            let mut datos = vec![0u8; longitud];
            for byte in &mut datos {
                estado = estado
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (estado >> 33) as u8;
            }
            if longitud >= OFFSET_COOKIE + 4 {
                datos[OFFSET_OP] = 1;
                datos[OFFSET_COOKIE..OFFSET_COOKIE + 4].copy_from_slice(&COOKIE);
            }
            let _ = parse(&datos);
        }
    }

    #[test]
    fn msft_5_0_es_windows() {
        // Patrón sintético fiel al DHCP Discover de Windows 10/11: vendor class
        // "MSFT 5.0" y PRL 1,3,6,15,119,252,95,44,46.
        let prl = [1u8, 3, 6, 15, 119, 252, 95, 44, 46];
        let datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_VENDOR, b"MSFT 5.0"), (OPCION_PRL, &prl)],
        );
        let info = parse(&datos).expect("paquete Windows válido");
        let pistas = os_hints(info.vendor.as_deref(), info.fingerprint.as_deref());
        assert_eq!(pistas, vec![(OsFamily::Windows, 4)]);
    }

    #[test]
    fn android_dhcp_es_android() {
        // Patrón sintético del vendor class de Android 11+ en su Discover.
        let datos = paquete(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            MAC_CLIENTE,
            &[(OPCION_VENDOR, b"android-dhcp-13")],
        );
        let info = parse(&datos).expect("paquete Android válido");
        assert_eq!(
            os_hints(info.vendor.as_deref(), info.fingerprint.as_deref()),
            vec![(OsFamily::Android, 4)]
        );
    }

    #[test]
    fn udhcp_es_iot() {
        // Patrón sintético del vendor class de BusyBox udhcp (router/IoT).
        assert_eq!(
            os_hints(Some("udhcp 1.36.1"), None),
            vec![(OsFamily::Iot, 4)]
        );
    }

    #[test]
    fn dhcpcd_con_linux_es_linux() {
        // Patrón sintético del vendor class de dhcpcd 9.x en Linux.
        assert_eq!(
            os_hints(Some("dhcpcd-9.4.1:Linux-6.1.0:x86_64"), None),
            vec![(OsFamily::Linux, 3)]
        );
        // Sin la marca de Linux no aplica la regla.
        assert!(os_hints(Some("dhcpcd-9.4.1"), None).is_empty());
        assert!(os_hints(Some("otro-dhcpcd"), None).is_empty());
    }

    #[test]
    fn la_prl_de_apple_aporta_macos_e_ios() {
        // Patrón de la huella DHCP pública de iOS/macOS.
        assert_eq!(
            os_hints(None, Some("1,121,3,6,15,119,252,95,44,46")),
            vec![(OsFamily::MacOs, 2), (OsFamily::Ios, 2)]
        );
        // El sufijo puede variar entre versiones: basta el prefijo 1,121.
        assert_eq!(
            os_hints(None, Some("1,121,3,6,15,119,252")),
            vec![(OsFamily::MacOs, 2), (OsFamily::Ios, 2)]
        );
        // La PRL de Windows no es de Apple: solo aporta la regla del vendor.
        assert_eq!(
            os_hints(Some("MSFT 5.0"), Some("1,3,6,15,119,252,95,44,46")),
            vec![(OsFamily::Windows, 4)]
        );
        assert!(os_hints(None, Some("1,3,6,15,119,252,95,44,46")).is_empty());
    }

    #[test]
    fn sin_vendor_ni_huella_no_hay_pistas() {
        assert!(os_hints(None, None).is_empty());
        assert!(os_hints(Some(""), Some("")).is_empty());
        assert!(os_hints(Some("vendor-desconocido"), Some("1,3,6")).is_empty());
    }
}
