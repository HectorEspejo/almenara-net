//! Parser del ClientHello TLS (RFC 8446) (§7.4).
//!
//! Extrae SNI normalizado, ALPN, versiones soportadas, cifrados, extensiones y
//! algoritmos de firma. Sustituye a capture/sni.rs de la Fase 3.
//!
//! Acepta las dos formas en las que llega un ClientHello al motor de inferencia:
//!
//! - Registro TLS de handshake (16 03 0x) seguido del mensaje, tal y como viaja
//!   sobre TCP. Si el mensaje se reparte en varios registros, se encadenan hasta
//!   completar el handshake.
//! - Mensaje de handshake directo (01 + longitud de 24 bits), sin registro, que
//!   es como viaja dentro de las tramas CRYPTO de QUIC (RFC 9001 §4.1).
//!
//! Todas las entradas son datos de red: cualquier truncamiento o longitud
//! incoherente devuelve [TlsError], nunca provoca un pánico.

use crate::inference::{NameObservation, NameSource, MAX_SERVER_NAME};
use std::net::IpAddr;

/// Tipo de contenido TLS de handshake.
const TLS_REGISTRO_HANDSHAKE: u8 = 0x16;
/// Tipo de mensaje de handshake ClientHello.
const TLS_MENSAJE_CLIENT_HELLO: u8 = 0x01;
/// Longitud de la cabecera de un registro TLS (tipo + versión + longitud).
const CABECERA_REGISTRO: usize = 5;
/// Longitud de la cabecera de un mensaje de handshake (tipo + longitud de 24 bits).
const CABECERA_HANDSHAKE: usize = 4;
/// Longitud fija del inicio del ClientHello: versión (2) + random (32).
const FIJO_CLIENT_HELLO: usize = 34;
/// Número máximo de registros TLS que se encadenan para un ClientHello.
///
/// Un ClientHello normal cabe en uno o dos registros; el tope evita que una
/// secuencia mal formada haga crecer el bucle sin límite.
const MAX_REGISTROS_TLS: usize = 16;

/// Tipo de extensión server_name (SNI).
const EXT_SERVER_NAME: u16 = 0x0000;
/// Tipo de extensión signature_algorithms.
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// Tipo de extensión application_layer_protocol_negotiation (ALPN).
const EXT_ALPN: u16 = 0x0010;
/// Tipo de extensión supported_versions.
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// ClientHello TLS parseado.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// Versión heredada del registro (legacy_version).
    pub legacy_version: u16,
    /// SNI normalizado (minúsculas, sin punto final, máx. 255).
    pub sni: Option<String>,
    /// Protocolos ALPN ofrecidos, en su orden.
    pub alpn: Vec<String>,
    /// Versiones soportadas (extensión supported_versions).
    pub supported_versions: Vec<u16>,
    /// Cifrados ofrecidos, en su orden.
    pub ciphers: Vec<u16>,
    /// Identificadores de extensión, en su orden.
    pub extensions: Vec<u16>,
    /// Algoritmos de firma, en su orden.
    pub signature_algorithms: Vec<u16>,
}

/// Error de parseo del ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsError(pub String);

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TlsError {}

/// Construye un error de parseo con el mensaje indicado.
fn error_tls(mensaje: impl Into<String>) -> TlsError {
    TlsError(mensaje.into())
}

/// Lee una longitud de 24 bits (tres bytes en orden de red).
fn longitud_24(bytes: &[u8]) -> Result<usize, TlsError> {
    if bytes.len() < 3 {
        return Err(error_tls("longitud de handshake truncada"));
    }
    Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
}

/// Parsea un ClientHello TLS completo (registro 16 03 0x + handshake).
///
/// También acepta el mensaje de handshake directo que llevan las tramas CRYPTO
/// de QUIC.
pub fn parse_client_hello(data: &[u8]) -> Result<ClientHello, TlsError> {
    let handshake = reunir_handshake(data)?;
    parsear_handshake(&handshake)
}

/// Reúne el mensaje de handshake a partir de uno o varios registros TLS.
fn reunir_handshake(data: &[u8]) -> Result<Vec<u8>, TlsError> {
    // QUIC: mensaje de handshake directo, sin capa de registro (RFC 9001 §4.1).
    if data.first() == Some(&TLS_MENSAJE_CLIENT_HELLO) {
        if data.len() < CABECERA_HANDSHAKE {
            return Err(error_tls("ClientHello truncado antes de la longitud"));
        }
        let longitud = longitud_24(&data[1..4])?;
        let fin = CABECERA_HANDSHAKE
            .checked_add(longitud)
            .ok_or_else(|| error_tls("longitud de ClientHello desbordada"))?;
        if data.len() < fin {
            return Err(error_tls(format!(
                "ClientHello truncado: faltan {} bytes",
                fin - data.len()
            )));
        }
        return Ok(data[..fin].to_vec());
    }

    let mut handshake = Vec::new();
    let mut cursor = 0usize;
    for _ in 0..MAX_REGISTROS_TLS {
        if handshake.len() >= CABECERA_HANDSHAKE {
            let longitud = longitud_24(&handshake[1..4])?;
            let fin = CABECERA_HANDSHAKE
                .checked_add(longitud)
                .ok_or_else(|| error_tls("longitud de handshake desbordada"))?;
            if handshake.len() >= fin {
                handshake.truncate(fin);
                return Ok(handshake);
            }
        }

        let cabecera = data
            .get(cursor..cursor.saturating_add(CABECERA_REGISTRO))
            .ok_or_else(|| error_tls("registro TLS truncado"))?;
        if cabecera[0] != TLS_REGISTRO_HANDSHAKE || cabecera[1] != 0x03 {
            return Err(error_tls("el registro TLS no es de handshake"));
        }
        let longitud = usize::from(u16::from_be_bytes([cabecera[3], cabecera[4]]));
        if longitud == 0 {
            return Err(error_tls("registro TLS vacío"));
        }
        let inicio = cursor.saturating_add(CABECERA_REGISTRO);
        let fin = inicio
            .checked_add(longitud)
            .ok_or_else(|| error_tls("longitud de registro TLS desbordada"))?;
        let cuerpo = data
            .get(inicio..fin)
            .ok_or_else(|| error_tls("registro TLS truncado"))?;
        handshake.extend_from_slice(cuerpo);
        cursor = fin;
    }
    Err(error_tls("demasiados registros TLS para un ClientHello"))
}

/// Parsea la cabecera y el cuerpo del mensaje de handshake ClientHello.
fn parsear_handshake(handshake: &[u8]) -> Result<ClientHello, TlsError> {
    if handshake.len() < CABECERA_HANDSHAKE {
        return Err(error_tls("mensaje de handshake truncado"));
    }
    if handshake[0] != TLS_MENSAJE_CLIENT_HELLO {
        return Err(error_tls("el mensaje de handshake no es un ClientHello"));
    }
    let longitud = longitud_24(&handshake[1..4])?;
    let fin = CABECERA_HANDSHAKE
        .checked_add(longitud)
        .ok_or_else(|| error_tls("longitud de ClientHello desbordada"))?;
    if handshake.len() != fin {
        return Err(error_tls(
            "la longitud del ClientHello no coincide con los datos",
        ));
    }
    parsear_cuerpo_client_hello(&handshake[CABECERA_HANDSHAKE..])
}

/// Parsea el cuerpo de un ClientHello ya delimitado.
fn parsear_cuerpo_client_hello(cuerpo: &[u8]) -> Result<ClientHello, TlsError> {
    if cuerpo.len() < FIJO_CLIENT_HELLO {
        return Err(error_tls("ClientHello truncado antes del random"));
    }
    let mut hello = ClientHello {
        legacy_version: u16::from_be_bytes([cuerpo[0], cuerpo[1]]),
        ..ClientHello::default()
    };
    let mut cursor = FIJO_CLIENT_HELLO;

    // session_id
    let longitud_sesion = usize::from(
        *cuerpo
            .get(cursor)
            .ok_or_else(|| error_tls("ClientHello truncado en session_id"))?,
    );
    cursor = cursor
        .checked_add(1 + longitud_sesion)
        .ok_or_else(|| error_tls("session_id desbordada"))?;
    if cursor > cuerpo.len() {
        return Err(error_tls("session_id truncada"));
    }

    // cipher_suites
    let bytes_cifrados = cuerpo
        .get(cursor..cursor.saturating_add(2))
        .ok_or_else(|| error_tls("ClientHello truncado en cipher_suites"))?;
    let longitud_cifrados = usize::from(u16::from_be_bytes([bytes_cifrados[0], bytes_cifrados[1]]));
    if longitud_cifrados % 2 != 0 {
        return Err(error_tls("lista de cifrados con longitud impar"));
    }
    cursor += 2;
    let fin_cifrados = cursor
        .checked_add(longitud_cifrados)
        .ok_or_else(|| error_tls("cipher_suites desbordadas"))?;
    let cifrados = cuerpo
        .get(cursor..fin_cifrados)
        .ok_or_else(|| error_tls("cipher_suites truncadas"))?;
    hello.ciphers = cifrados
        .as_chunks::<2>()
        .0
        .iter()
        .map(|par| u16::from_be_bytes(*par))
        .collect();
    cursor = fin_cifrados;

    // compression_methods
    let longitud_compresion = usize::from(
        *cuerpo
            .get(cursor)
            .ok_or_else(|| error_tls("ClientHello truncado en compresión"))?,
    );
    cursor = cursor
        .checked_add(1 + longitud_compresion)
        .ok_or_else(|| error_tls("compresión desbordada"))?;
    if cursor > cuerpo.len() {
        return Err(error_tls("compresión truncada"));
    }

    // Un ClientHello antiguo puede no traer extensiones.
    if cursor == cuerpo.len() {
        return Ok(hello);
    }

    // extensions
    let bytes_extensiones = cuerpo
        .get(cursor..cursor.saturating_add(2))
        .ok_or_else(|| error_tls("ClientHello truncado en extensiones"))?;
    let longitud_extensiones = usize::from(u16::from_be_bytes([
        bytes_extensiones[0],
        bytes_extensiones[1],
    ]));
    cursor += 2;
    let fin_extensiones = cursor
        .checked_add(longitud_extensiones)
        .ok_or_else(|| error_tls("extensiones desbordadas"))?;
    if fin_extensiones > cuerpo.len() {
        return Err(error_tls("extensión truncada"));
    }

    while cursor + 4 <= fin_extensiones {
        let tipo = u16::from_be_bytes([cuerpo[cursor], cuerpo[cursor + 1]]);
        let longitud = usize::from(u16::from_be_bytes([cuerpo[cursor + 2], cuerpo[cursor + 3]]));
        let inicio_datos = cursor + 4;
        let fin_datos = inicio_datos
            .checked_add(longitud)
            .ok_or_else(|| error_tls("longitud de extensión desbordada"))?;
        if fin_datos > fin_extensiones {
            return Err(error_tls("extensión truncada"));
        }
        let datos = &cuerpo[inicio_datos..fin_datos];
        hello.extensions.push(tipo);
        match tipo {
            EXT_SERVER_NAME => interpretar_server_name(datos, &mut hello),
            EXT_ALPN => interpretar_alpn(datos, &mut hello),
            EXT_SUPPORTED_VERSIONS => interpretar_versiones_soportadas(datos, &mut hello),
            EXT_SIGNATURE_ALGORITHMS => interpretar_algoritmos_firma(datos, &mut hello),
            _ => {}
        }
        cursor = fin_datos;
    }
    if cursor != fin_extensiones {
        return Err(error_tls("bloque de extensiones truncado"));
    }
    Ok(hello)
}

/// Interpreta la extensión server_name: guarda el primer host_name.
fn interpretar_server_name(datos: &[u8], hello: &mut ClientHello) {
    let Some(cabecera) = datos.get(0..2) else {
        return;
    };
    let longitud_lista = usize::from(u16::from_be_bytes([cabecera[0], cabecera[1]]));
    let fin_lista = 2usize.saturating_add(longitud_lista).min(datos.len());
    let mut cursor = 2usize;
    while cursor + 3 <= fin_lista {
        let tipo = datos[cursor];
        let longitud = usize::from(u16::from_be_bytes([datos[cursor + 1], datos[cursor + 2]]));
        let inicio = cursor + 3;
        let fin = inicio.saturating_add(longitud);
        if fin > fin_lista {
            return;
        }
        if tipo == 0 {
            if let Ok(nombre) = std::str::from_utf8(&datos[inicio..fin]) {
                hello.sni = normalize_server_name(nombre);
            }
            return;
        }
        cursor = fin;
    }
}

/// Interpreta la extensión ALPN: guarda los protocolos en su orden.
fn interpretar_alpn(datos: &[u8], hello: &mut ClientHello) {
    let Some(cabecera) = datos.get(0..2) else {
        return;
    };
    let longitud_lista = usize::from(u16::from_be_bytes([cabecera[0], cabecera[1]]));
    let fin_lista = 2usize.saturating_add(longitud_lista).min(datos.len());
    let mut cursor = 2usize;
    while cursor < fin_lista {
        let longitud = usize::from(datos[cursor]);
        let inicio = cursor + 1;
        let fin = inicio.saturating_add(longitud);
        if fin > fin_lista {
            return;
        }
        hello
            .alpn
            .push(String::from_utf8_lossy(&datos[inicio..fin]).into_owned());
        cursor = fin;
    }
}

/// Interpreta la extensión supported_versions.
fn interpretar_versiones_soportadas(datos: &[u8], hello: &mut ClientHello) {
    let Some(longitud) = datos.first().copied() else {
        return;
    };
    let longitud = usize::from(longitud);
    if longitud % 2 != 0 || datos.len() < 1 + longitud {
        return;
    }
    hello.supported_versions = datos[1..1 + longitud]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|par| u16::from_be_bytes(*par))
        .collect();
}

/// Interpreta la extensión signature_algorithms.
fn interpretar_algoritmos_firma(datos: &[u8], hello: &mut ClientHello) {
    let Some(cabecera) = datos.get(0..2) else {
        return;
    };
    let longitud = usize::from(u16::from_be_bytes([cabecera[0], cabecera[1]]));
    if longitud % 2 != 0 || datos.len() < 2 + longitud {
        return;
    }
    hello.signature_algorithms = datos[2..2 + longitud]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|par| u16::from_be_bytes(*par))
        .collect();
}

/// Normaliza un SNI/Host: minúsculas, sin punto final y máx. 255 caracteres.
pub fn normalize_server_name(name: &str) -> Option<String> {
    let limpio = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if limpio.is_empty()
        || limpio.len() > MAX_SERVER_NAME
        || limpio.contains(|c: char| c.is_whitespace() || c.is_control() || c == '/')
    {
        return None;
    }
    Some(limpio)
}

/// Observación IP → nombre a partir de un SNI de un flujo hacia ip.
pub fn name_observation(
    ip: IpAddr,
    sni: &str,
    requester: Option<IpAddr>,
) -> Option<NameObservation> {
    Some(NameObservation {
        ip,
        name: normalize_server_name(sni)?,
        source: NameSource::Sni,
        requester,
        ttl_seconds: Some(3600),
    })
}

/// ClientHello sintético mínimo para las pruebas de otros módulos del motor.
#[cfg(test)]
pub(crate) fn fixture_client_hello(sni: &str) -> Vec<u8> {
    let mut extensiones = Vec::new();

    // Extensión server_name.
    let mut datos = Vec::new();
    datos.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
    datos.push(0);
    datos.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    datos.extend_from_slice(sni.as_bytes());
    extensiones.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    extensiones.extend_from_slice(&(datos.len() as u16).to_be_bytes());
    extensiones.extend_from_slice(&datos);

    // Extensión ALPN con h2.
    let mut alpn = Vec::new();
    alpn.extend_from_slice(&3u16.to_be_bytes());
    alpn.push(2);
    alpn.extend_from_slice(b"h2");
    extensiones.extend_from_slice(&EXT_ALPN.to_be_bytes());
    extensiones.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
    extensiones.extend_from_slice(&alpn);

    // Extensión supported_versions con TLS 1.3 y 1.2.
    let mut versiones = vec![4u8];
    versiones.extend_from_slice(&0x0304u16.to_be_bytes());
    versiones.extend_from_slice(&0x0303u16.to_be_bytes());
    extensiones.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    extensiones.extend_from_slice(&(versiones.len() as u16).to_be_bytes());
    extensiones.extend_from_slice(&versiones);

    let mut cuerpo = Vec::new();
    cuerpo.extend_from_slice(&[0x03, 0x03]);
    cuerpo.extend_from_slice(&[0x11; 32]);
    cuerpo.push(0);
    cuerpo.extend_from_slice(&4u16.to_be_bytes());
    cuerpo.extend_from_slice(&0x1301u16.to_be_bytes());
    cuerpo.extend_from_slice(&0xc02bu16.to_be_bytes());
    cuerpo.extend_from_slice(&[1, 0]);
    cuerpo.extend_from_slice(&(extensiones.len() as u16).to_be_bytes());
    cuerpo.extend_from_slice(&extensiones);

    let mut handshake = vec![TLS_MENSAJE_CLIENT_HELLO];
    handshake.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&cuerpo);

    let mut registro = vec![TLS_REGISTRO_HANDSHAKE, 0x03, 0x01];
    registro.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    registro.extend_from_slice(&handshake);
    registro
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodifica una cadena hexadecimal (sin separadores) a bytes.
    fn bytes_hex(texto: &str) -> Vec<u8> {
        texto
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|par| {
                let par = std::str::from_utf8(par).expect("el hexadecimal es ASCII");
                u8::from_str_radix(par, 16).expect("dígito hexadecimal válido")
            })
            .collect()
    }

    /// Vector oficial de FoxIO (pcap tls12.pcap, flujo 0): ClientHello de Firefox.
    /// JA4 esperado: t13d1715h2_5b57614c22b0_3d5424432f57
    const VECTOR_TLS12: &str = concat!(
    "1603010200010001fc0303ecb2691addb2bf6c599c7aaae23de5f42561cc04eb41029acc6fc050a16ac1d22046f8617b",
    "580ac9358e2aa44e306d52466bcc989c87c8ca64309f5faf50ba7b4d0022130113031302c02bc02fcca9cca8c02cc030",
    "c00ac009c013c014009c009d002f00350100019100000021001f00001c636f6e74696c652e73657276696365732e6d6f",
    "7a696c6c612e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010",
    "000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00",
    "208909858fbeb6ed2f1248ba5b9e2978bead0e840110192c61daed0096798b184400170041044d183d91f5eed35791fa",
    "982464e3b0214aaa5f5d1b78616d9b9fbebc22d11f535b2f94c686143136aa795e6e5a875d6c08064ad5b76d44caad76",
    "6e2483012748002b00050403040303000d0018001604030503060308040805080604010501060102030201002d000201",
    "01001c000240010015007a00000000000000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000",
);

    /// Añade una extensión al bloque de extensiones.
    fn anadir_extension(bloque: &mut Vec<u8>, tipo: u16, datos: &[u8]) {
        bloque.extend_from_slice(&tipo.to_be_bytes());
        bloque.extend_from_slice(&(datos.len() as u16).to_be_bytes());
        bloque.extend_from_slice(datos);
    }

    /// Envuelve un cuerpo de ClientHello en el mensaje de handshake y su registro TLS.
    fn envolver_handshake(cuerpo: &[u8]) -> Vec<u8> {
        let mut handshake = vec![TLS_MENSAJE_CLIENT_HELLO];
        let longitud = cuerpo.len() as u32;
        handshake.extend_from_slice(&longitud.to_be_bytes()[1..]);
        handshake.extend_from_slice(cuerpo);

        let mut registro = vec![TLS_REGISTRO_HANDSHAKE, 0x03, 0x01];
        registro.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        registro.extend_from_slice(&handshake);
        registro
    }

    /// Cuerpo base de un ClientHello: versión, random, sesión, cifrados y compresión.
    fn cuerpo_base(cifrados: &[u16]) -> Vec<u8> {
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&[0x03, 0x03]);
        cuerpo.extend_from_slice(&[0x5a; 32]);
        cuerpo.push(0);
        cuerpo.extend_from_slice(&((cifrados.len() * 2) as u16).to_be_bytes());
        for cifrado in cifrados {
            cuerpo.extend_from_slice(&cifrado.to_be_bytes());
        }
        cuerpo.extend_from_slice(&[1, 0]);
        cuerpo
    }

    /// Construye un ClientHello sintético completo con las extensiones indicadas.
    fn construir_client_hello(
        sni: Option<&str>,
        alpn: &[&str],
        versiones: &[u16],
        cifrados: &[u16],
        algoritmos: &[u16],
    ) -> Vec<u8> {
        let mut cuerpo = cuerpo_base(cifrados);
        let mut extensiones = Vec::new();

        if let Some(nombre) = sni {
            let mut datos = Vec::new();
            datos.extend_from_slice(&((nombre.len() + 3) as u16).to_be_bytes());
            datos.push(0);
            datos.extend_from_slice(&(nombre.len() as u16).to_be_bytes());
            datos.extend_from_slice(nombre.as_bytes());
            anadir_extension(&mut extensiones, EXT_SERVER_NAME, &datos);
        }
        if !alpn.is_empty() {
            let mut lista = Vec::new();
            for protocolo in alpn {
                lista.push(protocolo.len() as u8);
                lista.extend_from_slice(protocolo.as_bytes());
            }
            let mut datos = Vec::new();
            datos.extend_from_slice(&(lista.len() as u16).to_be_bytes());
            datos.extend_from_slice(&lista);
            anadir_extension(&mut extensiones, EXT_ALPN, &datos);
        }
        if !versiones.is_empty() {
            let mut datos = vec![(versiones.len() * 2) as u8];
            for version in versiones {
                datos.extend_from_slice(&version.to_be_bytes());
            }
            anadir_extension(&mut extensiones, EXT_SUPPORTED_VERSIONS, &datos);
        }
        if !algoritmos.is_empty() {
            let mut datos = Vec::new();
            datos.extend_from_slice(&((algoritmos.len() * 2) as u16).to_be_bytes());
            for algoritmo in algoritmos {
                datos.extend_from_slice(&algoritmo.to_be_bytes());
            }
            anadir_extension(&mut extensiones, EXT_SIGNATURE_ALGORITHMS, &datos);
        }

        if !extensiones.is_empty() {
            cuerpo.extend_from_slice(&(extensiones.len() as u16).to_be_bytes());
            cuerpo.extend_from_slice(&extensiones);
        }
        envolver_handshake(&cuerpo)
    }

    #[test]
    fn parsea_un_vector_oficial_tls12() {
        let hello = parse_client_hello(&bytes_hex(VECTOR_TLS12)).expect("vector oficial");
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.sni.as_deref(), Some("contile.services.mozilla.com"));
        assert_eq!(hello.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(hello.supported_versions, vec![0x0304, 0x0303]);
        assert_eq!(hello.ciphers.len(), 17);
        assert_eq!(&hello.ciphers[..3], &[0x1301u16, 0x1303, 0x1302][..]);
        assert_eq!(hello.extensions.len(), 15);
        assert_eq!(hello.extensions[0], EXT_SERVER_NAME);
        assert_eq!(hello.extensions[6], EXT_ALPN);
        assert_eq!(
            hello.signature_algorithms,
            vec![
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201
            ]
        );
    }

    #[test]
    fn parsea_un_client_hello_sintetico_y_normaliza_el_sni() {
        let datos = construir_client_hello(
            Some("Example.COM."),
            &["h2", "http/1.1"],
            &[0x0304, 0x0303],
            &[0x1301, 0xc02b],
            &[0x0403, 0x0804],
        );
        let hello = parse_client_hello(&datos).expect("ClientHello sintético");
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(hello.supported_versions, vec![0x0304, 0x0303]);
        assert_eq!(hello.ciphers, vec![0x1301, 0xc02b]);
        assert_eq!(hello.extensions.len(), 4);
        assert_eq!(hello.signature_algorithms, vec![0x0403, 0x0804]);
    }

    #[test]
    fn acepta_un_client_hello_sin_extensiones() {
        let datos = envolver_handshake(&cuerpo_base(&[0x1301]));
        let hello = parse_client_hello(&datos).expect("ClientHello sin extensiones");
        assert_eq!(hello.legacy_version, 0x0303);
        assert!(hello.sni.is_none());
        assert!(hello.alpn.is_empty());
        assert!(hello.extensions.is_empty());
        assert_eq!(hello.ciphers, vec![0x1301]);
    }

    #[test]
    fn acepta_el_handshake_directo_de_quic() {
        let registro = construir_client_hello(
            Some("quic.example.com"),
            &["h3"],
            &[0x0304],
            &[0x1301],
            &[0x0403],
        );
        let directo = &registro[CABECERA_REGISTRO..];
        let hello = parse_client_hello(directo).expect("handshake directo de QUIC");
        assert_eq!(hello.sni.as_deref(), Some("quic.example.com"));
        assert_eq!(hello.alpn, vec!["h3".to_string()]);
    }

    #[test]
    fn encadena_el_handshake_repartido_en_dos_registros() {
        let registro = construir_client_hello(
            Some("partido.example.com"),
            &["h2"],
            &[0x0304],
            &[0x1301],
            &[],
        );
        let contenido = &registro[CABECERA_REGISTRO..];
        let corte = contenido.len() / 2;
        let mut datos = Vec::new();
        for trozo in [&contenido[..corte], &contenido[corte..]] {
            datos.extend_from_slice(&[TLS_REGISTRO_HANDSHAKE, 0x03, 0x01]);
            datos.extend_from_slice(&(trozo.len() as u16).to_be_bytes());
            datos.extend_from_slice(trozo);
        }
        let hello = parse_client_hello(&datos).expect("handshake en dos registros");
        assert_eq!(hello.sni.as_deref(), Some("partido.example.com"));
    }

    #[test]
    fn cualquier_prefijo_del_vector_oficial_falla_sin_panico() {
        let vector = bytes_hex(VECTOR_TLS12);
        for longitud in 0..vector.len() {
            assert!(
                parse_client_hello(&vector[..longitud]).is_err(),
                "un ClientHello truncado a {longitud} bytes no debe parsearse"
            );
        }
    }

    #[test]
    fn cualquier_prefijo_del_handshake_directo_falla_sin_panico() {
        let registro = construir_client_hello(
            Some("recortado.example.com"),
            &["h2"],
            &[0x0304],
            &[0x1301],
            &[],
        );
        let directo = &registro[CABECERA_REGISTRO..];
        for longitud in 0..directo.len() {
            assert!(
                parse_client_hello(&directo[..longitud]).is_err(),
                "un handshake directo truncado a {longitud} bytes no debe parsearse"
            );
        }
    }

    #[test]
    fn rechaza_extensiones_de_longitud_incoherente() {
        let mut datos = construir_client_hello(
            Some("ejemplo.com"),
            &["h2"],
            &[0x0304],
            &[0x1301, 0xc02b],
            &[],
        );
        // El total de extensiones está justo después de la compresión.
        let posicion = CABECERA_REGISTRO + CABECERA_HANDSHAKE + FIJO_CLIENT_HELLO + 1 + 2 + 4 + 2;
        datos[posicion] = 0xff;
        datos[posicion + 1] = 0xff;
        assert!(parse_client_hello(&datos).is_err());
    }

    #[test]
    fn rechaza_el_bloque_de_extensiones_truncado() {
        let mut datos =
            construir_client_hello(Some("ejemplo.com"), &["h2"], &[0x0304], &[0x1301], &[]);
        let posicion = CABECERA_REGISTRO + CABECERA_HANDSHAKE + FIJO_CLIENT_HELLO + 1 + 2 + 2 + 2;
        datos[posicion] = 0x00;
        datos[posicion + 1] = 0x03;
        assert!(parse_client_hello(&datos).is_err());
    }

    #[test]
    fn rechaza_un_registro_que_no_es_de_handshake() {
        let mut datos = construir_client_hello(Some("ejemplo.com"), &[], &[], &[0x1301], &[]);
        datos[0] = 0x17;
        assert!(parse_client_hello(&datos).is_err());
    }

    #[test]
    fn rechaza_un_handshake_que_no_es_client_hello() {
        let mut datos = construir_client_hello(Some("ejemplo.com"), &[], &[], &[0x1301], &[]);
        datos[CABECERA_REGISTRO] = 0x02;
        assert!(parse_client_hello(&datos).is_err());
    }

    #[test]
    fn no_hace_panic_con_datos_aleatorios() {
        for semilla in 0u32..128 {
            let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(17);
            let longitud = (semilla % 96) as usize;
            let mut datos = Vec::with_capacity(longitud);
            for _ in 0..longitud {
                estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                datos.push((estado >> 24) as u8);
            }
            let _ = parse_client_hello(&datos);
            // También el prefijo que empieza como registro TLS.
            let mut registro = vec![0x16, 0x03, 0x01];
            registro.extend_from_slice(&datos);
            let _ = parse_client_hello(&registro);
        }
    }

    #[test]
    fn normaliza_el_nombre_de_servidor() {
        assert_eq!(
            normalize_server_name("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_server_name("  www.ejemplo.es  ").as_deref(),
            Some("www.ejemplo.es")
        );
        assert_eq!(normalize_server_name(""), None);
        assert_eq!(normalize_server_name("   "), None);
        assert_eq!(normalize_server_name("a b.com"), None);
        assert_eq!(normalize_server_name("a/b.com"), None);
        assert_eq!(
            normalize_server_name(&"a".repeat(MAX_SERVER_NAME + 1)),
            None
        );
        let largo = "a".repeat(MAX_SERVER_NAME);
        assert_eq!(
            normalize_server_name(&largo).as_deref(),
            Some(largo.as_str())
        );
    }

    #[test]
    fn construye_la_observacion_de_nombre() {
        let ip: IpAddr = "1.2.3.4".parse().expect("IP válida");
        let observacion = name_observation(ip, "Ejemplo.COM.", None).expect("observación");
        assert_eq!(observacion.ip, ip);
        assert_eq!(observacion.name, "ejemplo.com");
        assert_eq!(observacion.source, NameSource::Sni);
        assert_eq!(observacion.requester, None);
        assert_eq!(observacion.ttl_seconds, Some(3600));
        assert!(name_observation(ip, "", None).is_none());
    }
}
