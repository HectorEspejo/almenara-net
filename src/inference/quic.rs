//! QUIC Initial: detección, derivación de claves, protección de cabecera y AEAD
//! (§7.5, RFC 9001 y RFC 9369).
//!
//! El módulo es puro y sin estado: trabaja sobre el datagrama UDP ya capturado.
//! Solo se descifran paquetes Initial de cliente de QUIC v1 y v2. Las claves se
//! derivan del DCID del propio paquete (son públicas para cualquier observador),
//! así que no hay secretos que guardar ni claves que proteger.
//!
//! Reglas de robustez (§7.16): todo acceso a bytes comprueba límites y ninguna
//! función entra en pánico con datos de red (paquetes truncados, versiones
//! desconocidas o tramas mal formadas).

use aes::cipher::BlockEncrypt;
use aes::Aes128;
use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

/// Versión de QUIC soportada por el descifrado Initial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    /// QUIC v1 (RFC 9000/9001).
    V1,
    /// QUIC v2 (RFC 9369).
    V2,
}

/// Error de descifrado o parseo de un Initial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicError(pub String);

impl std::fmt::Display for QuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for QuicError {}

/// Sal de las claves Initial de QUIC v1 (RFC 9001 §5.2).
const SAL_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Sal de las claves Initial de QUIC v2 (RFC 9369 §3.3.1).
const SAL_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Versión QUIC v1 tal y como aparece en la cabecera larga.
const VERSION_V1: u32 = 0x0000_0001;
/// Versión QUIC v2 (RFC 9369) tal y como aparece en la cabecera larga.
const VERSION_V2: u32 = 0x6b33_43cf;
/// Tipo de paquete Initial de QUIC v1 en los bits 4-5 del primer byte.
const TIPO_INITIAL_V1: u8 = 0x00;
/// Tipo de paquete Initial de QUIC v2 en los bits 4-5 del primer byte.
const TIPO_INITIAL_V2: u8 = 0x10;

/// Longitud máxima de un Initial descifrado (especificación §7.16).
const MAX_PAQUETE_INITIAL: usize = 1500;
/// Longitud del tag de autenticación de AES-128-GCM.
const TAG_BYTES: usize = 16;
/// Tamaño de la muestra de protección de cabecera (AES-ECB de 16 bytes).
const MUESTRA_BYTES: usize = 16;
/// Separación entre el inicio del número de paquete y la muestra de cabecera.
const DESPLAZAMIENTO_MUESTRA: usize = 4;
/// Longitud del nonce AEAD de AES-GCM.
const NONCE_BYTES: usize = 12;
/// Longitud del número de paquete escrito en el nonce (8 bytes a la derecha).
const PN_BYTES: usize = 8;
/// Longitud máxima de un Connection ID (RFC 9000 §17.2).
const MAX_CONNECTION_ID: usize = 20;
/// Bytes máximos de un ClientHello recompuesto en [contains_client_hello].
const MAX_CLIENT_HELLO: usize = 4096;

/// Claves de protección de un Initial de cliente.
struct ClavesInitial {
    /// Clave AEAD AES-128-GCM.
    key: [u8; 16],
    /// IV base del nonce AEAD.
    iv: [u8; NONCE_BYTES],
    /// Clave de protección de cabecera (AES-ECB).
    hp: [u8; 16],
}

/// Cabecera larga de un Initial ya localizada dentro del datagrama.
struct CabeceraInitial<'a> {
    /// Destination Connection ID del que se derivan las claves.
    dcid: &'a [u8],
    /// Desplazamiento del primer byte del número de paquete.
    pn_offset: usize,
    /// Valor del campo Length: número de paquete + carga + tag.
    longitud: u64,
}

/// Cabecera de un Initial tras retirar la protección de cabecera.
struct CabeceraDescifrada {
    /// Cabecera sin proteger (primer byte y número de paquete en claro).
    header: Vec<u8>,
    /// Número de paquete truncado que viaja en el paquete.
    pn: u64,
}

/// Crea un [QuicError] con un mensaje en castellano.
fn error(mensaje: &str) -> QuicError {
    QuicError(mensaje.to_string())
}

/// Reconstruye una [QuicVersion] a partir del número de versión.
fn numero_a_version(numero: u32) -> Option<QuicVersion> {
    match numero {
        VERSION_V1 => Some(QuicVersion::V1),
        VERSION_V2 => Some(QuicVersion::V2),
        _ => None,
    }
}

/// Etiquetas HKDF-Expand-Label de la versión indicada: (key, iv, hp).
fn etiquetas_version(version: QuicVersion) -> (&'static str, &'static str, &'static str) {
    match version {
        QuicVersion::V1 => ("quic key", "quic iv", "quic hp"),
        QuicVersion::V2 => ("quicv2 key", "quicv2 iv", "quicv2 hp"),
    }
}

/// Detecta un paquete Initial de QUIC v1 o v2.
pub fn initial_version(packet: &[u8]) -> Option<QuicVersion> {
    let primer_byte = *packet.first()?;
    // Cabecera larga: bit de forma (0x80) y bit fijo (0x40) a uno.
    if primer_byte & 0xc0 != 0xc0 {
        return None;
    }
    let bytes_version = packet.get(1..5)?;
    let numero = u32::from_be_bytes([
        bytes_version[0],
        bytes_version[1],
        bytes_version[2],
        bytes_version[3],
    ]);
    let version = numero_a_version(numero)?;
    let tipo = primer_byte & 0x30;
    let tipo_esperado = match version {
        QuicVersion::V1 => TIPO_INITIAL_V1,
        QuicVersion::V2 => TIPO_INITIAL_V2,
    };
    if tipo != tipo_esperado {
        return None;
    }
    Some(version)
}

/// Descifra un paquete Initial y devuelve el payload en claro.
///
/// Deriva las claves del DCID, retira la protección de cabecera y descifra el
/// AEAD AES-128-GCM. El payload contiene las tramas (CRYPTO, PADDING, ACK…).
pub fn decrypt_initial(packet: &[u8], version: QuicVersion) -> Result<Vec<u8>, QuicError> {
    let cabecera = leer_cabecera(packet, version)?;
    let claves = claves_desde_dcid(cabecera.dcid, version)?;
    let descifrada = desenmascarar_cabecera(packet, &cabecera, &claves.hp)?;

    // El campo Length cuenta número de paquete + carga cifrada + tag.
    let fin_carga = cabecera
        .pn_offset
        .checked_add(
            usize::try_from(cabecera.longitud).map_err(|_| error("campo Length fuera de rango"))?,
        )
        .ok_or_else(|| error("campo Length fuera de rango"))?;
    let carga = packet
        .get(descifrada.header.len()..fin_carga)
        .ok_or_else(|| error("paquete truncado: falta la carga cifrada"))?;
    if carga.len() < TAG_BYTES {
        return Err(error(
            "la carga cifrada es más corta que el tag de autenticación AEAD",
        ));
    }

    // Nonce = IV XOR número de paquete (el PN ocupa la parte derecha del nonce).
    let mut nonce = claves.iv;
    for (indice, byte) in descifrada.pn.to_be_bytes().iter().enumerate() {
        nonce[NONCE_BYTES - PN_BYTES + indice] ^= *byte;
    }

    let cifrador = Aes128Gcm::new_from_slice(&claves.key)
        .map_err(|_| error("clave AEAD no válida para AES-128-GCM"))?;
    let nonce = GenericArray::<u8, U12>::from_slice(&nonce);
    cifrador
        .decrypt(
            nonce,
            Payload {
                msg: carga,
                aad: &descifrada.header,
            },
        )
        .map_err(|_| error("no se pudo descifrar el Initial: autenticación AES-128-GCM incorrecta"))
}

/// Extrae las tramas CRYPTO de un payload QUIC descifrado: `(offset, datos)`.
///
/// Se ignoran PADDING, PING, ACK y el resto de tramas de RFC 9000 (STREAM,
/// MAX_DATA, CONNECTION_CLOSE…). Ante una trama truncada o un tipo desconocido
/// se detiene el parseo y se devuelven las tramas CRYPTO ya extraídas: nunca se
/// entra en pánico con datos de red.
pub fn crypto_frames(payload: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut tramas = Vec::new();
    let mut pos = 0usize;

    while let Some(&tipo) = payload.get(pos) {
        pos += 1;
        let continuar = match tipo {
            // PADDING: rachas de ceros de cualquier longitud.
            0x00 => {
                avanzar_relleno(payload, &mut pos);
                true
            }
            // PING.
            0x01 => true,
            // ACK y ACK con ECN.
            0x02 | 0x03 => saltar_ack(payload, &mut pos, tipo == 0x03),
            // RESET_STREAM: id, código de error y tamaño final.
            0x04 => saltar_varints(payload, &mut pos, 3),
            // STOP_SENDING: id y código de error.
            0x05 => saltar_varints(payload, &mut pos, 2),
            // CRYPTO: offset, longitud y datos.
            0x06 => extraer_crypto(payload, &mut pos, &mut tramas),
            // NEW_TOKEN: longitud y token.
            0x07 => saltar_longitud_bytes(payload, &mut pos),
            // STREAM: id, offset opcional y longitud opcional.
            0x08..=0x0f => saltar_stream(payload, &mut pos, tipo),
            // MAX_DATA, DATA_BLOCKED.
            0x10 | 0x14 => saltar_varints(payload, &mut pos, 1),
            // MAX_STREAM_DATA, STREAM_DATA_BLOCKED.
            0x11 | 0x15 => saltar_varints(payload, &mut pos, 2),
            // MAX_STREAMS, STREAMS_BLOCKED.
            0x12 | 0x13 | 0x16 | 0x17 => saltar_varints(payload, &mut pos, 1),
            // NEW_CONNECTION_ID: secuencia, retire_prior_to, longitud y CID.
            0x18 => saltar_new_connection_id(payload, &mut pos),
            // RETIRE_CONNECTION_ID.
            0x19 => saltar_varints(payload, &mut pos, 1),
            // PATH_CHALLENGE y PATH_RESPONSE: 8 bytes fijos.
            0x1a | 0x1b => avanzar_bytes(payload, &mut pos, 8),
            // CONNECTION_CLOSE de transporte: código, tipo y motivo.
            0x1c => {
                saltar_varints(payload, &mut pos, 2) && saltar_longitud_bytes(payload, &mut pos)
            }
            // CONNECTION_CLOSE de aplicación: código y motivo.
            0x1d => {
                saltar_varints(payload, &mut pos, 1) && saltar_longitud_bytes(payload, &mut pos)
            }
            // HANDSHAKE_DONE.
            0x1e => true,
            // DATAGRAM sin longitud: ocupa el resto del paquete.
            0x30 => {
                pos = payload.len();
                true
            }
            // DATAGRAM con longitud.
            0x31 => saltar_longitud_bytes(payload, &mut pos),
            // Tipo desconocido: no se conoce su formato y no se puede continuar.
            _ => false,
        };
        if !continuar {
            break;
        }
    }
    tramas
}

/// Indica si el payload contiene un ClientHello TLS completo.
///
/// Acepta tanto el flujo de handshake ya reensamblado (registro TLS `16 03 0x`
/// seguido del mensaje de handshake, o el mensaje de handshake directo tal y
/// como viaja en las tramas CRYPTO de QUIC) como un payload descifrado de un
/// Initial con tramas CRYPTO contiguas desde el offset 0.
pub fn contains_client_hello(payload: &[u8]) -> bool {
    // Registro TLS clásico (uso sobre TCP): `16 03 0x` + longitud.
    if payload.first() == Some(&0x16) {
        if let Some(completo) = client_hello_en_registro(payload) {
            return completo;
        }
    }
    // En QUIC el stream CRYPTO no lleva cabecera de registro TLS: empieza por
    // el mensaje de handshake. Se exige que la longitud sea verosímil para no
    // confundir una trama PING con el inicio de un ClientHello.
    if parece_clienthello(payload) {
        return handshake_es_clienthello_completo(payload);
    }
    // Payload descifrado: recomponer las tramas CRYPTO contiguas desde el 0.
    client_hello_en_tramas(payload).unwrap_or(false)
}

/// Lee una cabecera larga de Initial y comprueba sus límites.
fn leer_cabecera<'a>(
    packet: &'a [u8],
    version: QuicVersion,
) -> Result<CabeceraInitial<'a>, QuicError> {
    if packet.len() > MAX_PAQUETE_INITIAL {
        return Err(error(
            "el paquete Initial supera la longitud máxima de 1500 B",
        ));
    }
    let detectada = initial_version(packet)
        .ok_or_else(|| error("el paquete no es un Initial de QUIC v1 o v2"))?;
    if detectada != version {
        return Err(error("la versión del paquete no coincide con la indicada"));
    }
    // La versión ya se ha comprobado en initial_version: hay al menos 5 bytes.
    let mut pos = 5usize;
    let dcid_len = usize::from(
        *packet
            .get(pos)
            .ok_or_else(|| error("cabecera truncada: falta la longitud del DCID"))?,
    );
    pos += 1;
    if dcid_len > MAX_CONNECTION_ID {
        return Err(error("DCID de longitud no válida"));
    }
    let fin_dcid = pos
        .checked_add(dcid_len)
        .ok_or_else(|| error("cabecera truncada: DCID fuera de rango"))?;
    let dcid = packet
        .get(pos..fin_dcid)
        .ok_or_else(|| error("cabecera truncada: falta el DCID"))?;
    pos = fin_dcid;
    let scid_len = usize::from(
        *packet
            .get(pos)
            .ok_or_else(|| error("cabecera truncada: falta la longitud del SCID"))?,
    );
    pos += 1;
    if scid_len > MAX_CONNECTION_ID {
        return Err(error("SCID de longitud no válida"));
    }
    let fin_scid = pos
        .checked_add(scid_len)
        .ok_or_else(|| error("cabecera truncada: SCID fuera de rango"))?;
    if fin_scid > packet.len() {
        return Err(error("cabecera truncada: falta el SCID"));
    }
    pos = fin_scid;
    // En un Initial siempre hay campo de longitud de token, aunque valga cero.
    let token_len = leer_varint(packet, &mut pos)
        .ok_or_else(|| error("cabecera truncada: falta la longitud del token"))?;
    if !avanzar_bytes(packet, &mut pos, token_len) {
        return Err(error("cabecera truncada: falta el token"));
    }
    // Length: número de paquete + carga cifrada + tag.
    let longitud = leer_varint(packet, &mut pos)
        .ok_or_else(|| error("cabecera truncada: falta el campo Length"))?;
    let pn_offset = pos;
    let fin = pn_offset
        .checked_add(usize::try_from(longitud).map_err(|_| error("campo Length fuera de rango"))?)
        .ok_or_else(|| error("campo Length fuera de rango"))?;
    if fin > packet.len() {
        return Err(error(
            "paquete truncado: el campo Length excede el datagrama",
        ));
    }
    if longitud < (1 + TAG_BYTES) as u64 {
        return Err(error("campo Length demasiado corto para llevar tag AEAD"));
    }
    Ok(CabeceraInitial {
        dcid,
        pn_offset,
        longitud,
    })
}

/// Retira la protección de cabecera: máscara AES-ECB y número de paquete.
fn desenmascarar_cabecera(
    packet: &[u8],
    cabecera: &CabeceraInitial<'_>,
    hp: &[u8; 16],
) -> Result<CabeceraDescifrada, QuicError> {
    let pos_muestra = cabecera
        .pn_offset
        .checked_add(DESPLAZAMIENTO_MUESTRA)
        .ok_or_else(|| error("desplazamiento de muestra fuera de rango"))?;
    let fin_muestra = pos_muestra
        .checked_add(MUESTRA_BYTES)
        .ok_or_else(|| error("desplazamiento de muestra fuera de rango"))?;
    let muestra = packet
        .get(pos_muestra..fin_muestra)
        .ok_or_else(|| error("paquete truncado: falta la muestra de protección de cabecera"))?;

    let cifrador = Aes128::new_from_slice(hp)
        .map_err(|_| error("clave de protección de cabecera no válida"))?;
    let mut bloque = GenericArray::<u8, U16>::default();
    bloque.copy_from_slice(muestra);
    cifrador.encrypt_block(&mut bloque);
    let mascara = &bloque[..5];

    // Solo están protegidos los 4 bits bajos del primer byte.
    let primer_byte = packet.first().ok_or_else(|| error("paquete vacío"))? ^ (mascara[0] & 0x0f);
    let longitud_pn = usize::from(primer_byte & 0x03) + 1;
    let fin_pn = cabecera
        .pn_offset
        .checked_add(longitud_pn)
        .ok_or_else(|| error("número de paquete fuera de rango"))?;
    let mut header = packet
        .get(..cabecera.pn_offset)
        .ok_or_else(|| error("cabecera truncada: falta el primer byte"))?
        .to_vec();
    header[0] = primer_byte;
    let bytes_pn = packet
        .get(cabecera.pn_offset..fin_pn)
        .ok_or_else(|| error("paquete truncado: falta el número de paquete"))?;
    let mut pn = 0u64;
    for (indice, byte) in bytes_pn.iter().enumerate() {
        let claro = byte ^ mascara[1 + indice];
        header.push(claro);
        pn = (pn << 8) | u64::from(claro);
    }
    Ok(CabeceraDescifrada { header, pn })
}

/// Deriva el secreto Initial de cliente a partir del DCID y la versión.
fn secreto_cliente_initial(dcid: &[u8], version: QuicVersion) -> Result<[u8; 32], QuicError> {
    let sal: &[u8] = match version {
        QuicVersion::V1 => &SAL_V1,
        QuicVersion::V2 => &SAL_V2,
    };
    // HKDF-Extract(sal, DCID) = PRK inicial; el secreto de cliente sale del
    // primer HKDF-Expand-Label con la etiqueta "client in" (RFC 9001 §5.2).
    let hkdf = Hkdf::<Sha256>::new(Some(sal), dcid);
    let mut secreto = [0u8; 32];
    let info = info_expand_label("client in", secreto.len())?;
    hkdf.expand(&info, &mut secreto)
        .map_err(|_| error("no se pudo derivar el secreto Initial de cliente"))?;
    Ok(secreto)
}

/// Deriva las claves de protección (key, iv, hp) de un Initial de cliente.
fn claves_desde_dcid(dcid: &[u8], version: QuicVersion) -> Result<ClavesInitial, QuicError> {
    let secreto = secreto_cliente_initial(dcid, version)?;
    let (etiqueta_key, etiqueta_iv, etiqueta_hp) = etiquetas_version(version);
    let mut claves = ClavesInitial {
        key: [0u8; 16],
        iv: [0u8; NONCE_BYTES],
        hp: [0u8; 16],
    };
    hkdf_expand_label(&secreto, etiqueta_key, &mut claves.key)?;
    hkdf_expand_label(&secreto, etiqueta_iv, &mut claves.iv)?;
    hkdf_expand_label(&secreto, etiqueta_hp, &mut claves.hp)?;
    Ok(claves)
}

/// Codifica la estructura HkdfLabel de TLS 1.3 (RFC 8446 §7.1).
fn info_expand_label(etiqueta: &str, longitud: usize) -> Result<Vec<u8>, QuicError> {
    let nombre = format!("tls13 {etiqueta}");
    let longitud_etiqueta =
        u8::try_from(nombre.len()).map_err(|_| error("etiqueta HKDF demasiado larga"))?;
    let longitud_salida =
        u16::try_from(longitud).map_err(|_| error("longitud HKDF fuera de rango"))?;
    let mut info = Vec::with_capacity(2 + 1 + nombre.len() + 1);
    info.extend_from_slice(&longitud_salida.to_be_bytes());
    info.push(longitud_etiqueta);
    info.extend_from_slice(nombre.as_bytes());
    info.push(0); // contexto vacío
    Ok(info)
}

/// HKDF-Expand-Label sobre un PRK de SHA-256.
fn hkdf_expand_label(prk: &[u8], etiqueta: &str, salida: &mut [u8]) -> Result<(), QuicError> {
    let info = info_expand_label(etiqueta, salida.len())?;
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| error("PRK de HKDF no válida"))?;
    hkdf.expand(&info, salida)
        .map_err(|_| error("longitud de salida de HKDF no válida"))
}

/// Lee un varint de QUIC (RFC 9000 §16) y avanza la posición.
fn leer_varint(datos: &[u8], pos: &mut usize) -> Option<u64> {
    let primero = *datos.get(*pos)?;
    let longitud = 1usize << (primero >> 6);
    let fin = pos.checked_add(longitud)?;
    if fin > datos.len() {
        return None;
    }
    let mut valor = u64::from(primero & 0x3f);
    for byte in &datos[*pos + 1..fin] {
        valor = (valor << 8) | u64::from(*byte);
    }
    *pos = fin;
    Some(valor)
}

/// Avanza la posición un número de bytes, comprobando límites.
fn avanzar_bytes(datos: &[u8], pos: &mut usize, cantidad: u64) -> bool {
    let Ok(cantidad) = usize::try_from(cantidad) else {
        return false;
    };
    let Some(fin) = pos.checked_add(cantidad) else {
        return false;
    };
    if fin > datos.len() {
        return false;
    }
    *pos = fin;
    true
}

/// Omite una racha de tramas PADDING (bytes a cero).
fn avanzar_relleno(datos: &[u8], pos: &mut usize) {
    while datos.get(*pos) == Some(&0) {
        *pos += 1;
    }
}

/// Salta el número indicado de varints.
fn saltar_varints(datos: &[u8], pos: &mut usize, cantidad: u8) -> bool {
    for _ in 0..cantidad {
        if leer_varint(datos, pos).is_none() {
            return false;
        }
    }
    true
}

/// Salta un campo longitud (varint) seguido de esa cantidad de bytes.
fn saltar_longitud_bytes(datos: &[u8], pos: &mut usize) -> bool {
    match leer_varint(datos, pos) {
        Some(longitud) => avanzar_bytes(datos, pos, longitud),
        None => false,
    }
}

/// Salta una trama ACK (tipo 0x02) o ACK con ECN (tipo 0x03).
fn saltar_ack(datos: &[u8], pos: &mut usize, con_ecn: bool) -> bool {
    // Mayor reconocido, retardo y primer rango.
    let Some(_mayor) = leer_varint(datos, pos) else {
        return false;
    };
    let Some(_retardo) = leer_varint(datos, pos) else {
        return false;
    };
    let Some(numero_rangos) = leer_varint(datos, pos) else {
        return false;
    };
    let Some(_primer_rango) = leer_varint(datos, pos) else {
        return false;
    };
    // Cada rango adicional son dos varints: hueco y longitud del rango.
    for _ in 0..numero_rangos {
        if !saltar_varints(datos, pos, 2) {
            return false;
        }
    }
    if con_ecn {
        return saltar_varints(datos, pos, 3);
    }
    true
}

/// Salta una trama STREAM (tipos 0x08-0x0f).
fn saltar_stream(datos: &[u8], pos: &mut usize, tipo: u8) -> bool {
    // Identificador del flujo.
    if leer_varint(datos, pos).is_none() {
        return false;
    }
    // Bit OFF (0x04): offset explícito.
    if tipo & 0x04 != 0 && leer_varint(datos, pos).is_none() {
        return false;
    }
    // Bit LEN (0x02): longitud explícita; si no, la trama ocupa el resto.
    if tipo & 0x02 != 0 {
        saltar_longitud_bytes(datos, pos)
    } else {
        *pos = datos.len();
        true
    }
}

/// Salta una trama NEW_CONNECTION_ID (tipo 0x18).
fn saltar_new_connection_id(datos: &[u8], pos: &mut usize) -> bool {
    // Número de secuencia y retire_prior_to.
    if !saltar_varints(datos, pos, 2) {
        return false;
    }
    let Some(&longitud) = datos.get(*pos) else {
        return false;
    };
    *pos += 1;
    if !(1..=MAX_CONNECTION_ID as u8).contains(&longitud) {
        return false;
    }
    avanzar_bytes(datos, pos, u64::from(longitud))
}

/// Extrae una trama CRYPTO (tipo 0x06): offset, longitud y datos.
fn extraer_crypto(datos: &[u8], pos: &mut usize, tramas: &mut Vec<(u64, Vec<u8>)>) -> bool {
    let Some(offset) = leer_varint(datos, pos) else {
        return false;
    };
    let Some(longitud) = leer_varint(datos, pos) else {
        return false;
    };
    let Ok(longitud) = usize::try_from(longitud) else {
        return false;
    };
    let Some(fin) = pos.checked_add(longitud) else {
        return false;
    };
    if fin > datos.len() {
        // Trama truncada: se descarta y se detiene el parseo.
        return false;
    }
    tramas.push((offset, datos[*pos..fin].to_vec()));
    *pos = fin;
    true
}

/// Comprueba si un buffer empieza por un registro TLS con un ClientHello completo.
fn client_hello_en_registro(datos: &[u8]) -> Option<bool> {
    if datos.len() < 3 || datos[0] != 0x16 || datos[1] != 0x03 {
        return None;
    }
    // Versión menor del registro TLS (0x0301 en un ClientHello real).
    if datos[2] > 0x04 {
        return None;
    }
    if datos.len() < 5 {
        return Some(false);
    }
    let longitud = usize::from(u16::from_be_bytes([datos[3], datos[4]]));
    let fin = 5usize.checked_add(longitud)?;
    if datos.len() < fin {
        return Some(false);
    }
    let mensaje = &datos[5..fin];
    Some(mensaje.first() == Some(&0x01) && handshake_es_clienthello_completo(mensaje))
}

/// Heurística: ¿el buffer empieza por un mensaje de handshake ClientHello?
///
/// En QUIC el stream CRYPTO empieza directamente por el mensaje de handshake,
/// así que se exige una longitud verosímil y la versión heredada 0x03 para no
/// confundir una trama PING (0x01) con el inicio de un ClientHello.
fn parece_clienthello(datos: &[u8]) -> bool {
    if datos.len() < 4 || datos[0] != 0x01 {
        return false;
    }
    let longitud = (u32::from(datos[1]) << 16) | (u32::from(datos[2]) << 8) | u32::from(datos[3]);
    // Un ClientHello mínimo (versión, random y listas) mide más de 34 bytes.
    if longitud < 34 {
        return false;
    }
    if let Some(&version_heredada) = datos.get(4) {
        if version_heredada != 0x03 {
            return false;
        }
    }
    true
}

/// Comprueba que un mensaje de handshake es un ClientHello completo.
fn handshake_es_clienthello_completo(datos: &[u8]) -> bool {
    if datos.len() < 4 || datos[0] != 0x01 {
        return false;
    }
    let longitud =
        (usize::from(datos[1]) << 16) | (usize::from(datos[2]) << 8) | usize::from(datos[3]);
    datos.len() >= 4 + longitud
}

/// Busca tramas CRYPTO en un payload descifrado y comprueba si recompuestas
/// desde el offset 0 forman un ClientHello completo.
///
/// Devuelve `None` si no hay ninguna trama CRYPTO en el payload.
fn client_hello_en_tramas(payload: &[u8]) -> Option<bool> {
    let mut tramas = crypto_frames(payload);
    if tramas.is_empty() {
        return None;
    }
    tramas.sort_by_key(|(offset, _)| *offset);
    let mut flujo: Vec<u8> = Vec::new();
    let mut siguiente = 0u64;
    for (offset, datos) in tramas {
        if offset > siguiente {
            // Hueco: el ClientHello no se puede recomponer con este payload.
            return Some(false);
        }
        let solapamiento = (siguiente - offset) as usize;
        if solapamiento < datos.len() {
            flujo.extend_from_slice(&datos[solapamiento..]);
            siguiente += (datos.len() - solapamiento) as u64;
        }
        if flujo.len() > MAX_CLIENT_HELLO {
            return Some(false);
        }
        if flujo.first() != Some(&0x01) {
            return Some(false);
        }
        if flujo.len() >= 4 {
            let longitud = (usize::from(flujo[1]) << 16)
                | (usize::from(flujo[2]) << 8)
                | usize::from(flujo[3]);
            if longitud > MAX_CLIENT_HELLO {
                return Some(false);
            }
            if flujo.len() >= 4 + longitud {
                return Some(true);
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectores del apéndice A de RFC 9001 (v1) y RFC 9369 (v2). El ClientHello
    // es el mismo en ambos RFC: solo cambian la sal, las etiquetas y el tipo.
    /// Initial de cliente protegido del apéndice A.2 de RFC 9001 (1200 B).
    const PAQUETE_CLIENTE_V1: &str = concat!(
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
        "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
        "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
        "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
        "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
        "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
        "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
        "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
        "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
        "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
        "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
        "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
        "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
        "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
        "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
        "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
        "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
        "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
        "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
        "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
        "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
        "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
        "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
        "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
        "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
        "e221af44860018ab0856972e194cd934",
    );

    /// Initial de cliente protegido del apéndice A.2 de RFC 9369 (1200 B).
    const PAQUETE_CLIENTE_V2: &str = concat!(
        "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485",
        "dd04de806071bf03dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad04",
        "9f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d",
        "250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a",
        "12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500",
        "cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68",
        "18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff33",
        "12ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3",
        "d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd",
        "6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520",
        "bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045",
        "636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f",
        "ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c12",
        "16ccce2d0193f958bb3850a833f7ae432b65bc5a53975c155aa4bcb4f7b2c4e5",
        "4df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4",
        "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b",
        "8017c25ca9052ca1079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de7",
        "14d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9",
        "9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91",
        "abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd",
        "80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db",
        "848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18",
        "d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15",
        "c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc",
        "7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61",
        "f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e70710",
        "10d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b",
        "3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e",
        "06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7ca7331dce",
        "8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1",
        "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1",
        "e86215c2d54e6670e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd",
        "5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3",
        "8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89",
        "d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b53",
        "6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19",
        "9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96b",
        "a18b2faa745b6fe189cf772a9f84cbfc",
    );

    /// Trama CRYPTO en claro del apéndice A.2 (245 B: cabecera de trama + ClientHello).
    const TRAMA_CRYPTO_RFC: &str = concat!(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
        "75300901100f088394c8f03e51570806048000ffff",
    );

    /// Convierte una cadena hex de un vector de prueba en bytes.
    fn hex_a_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(
            hex.len() % 2,
            0,
            "el hex del vector de prueba debe tener longitud par"
        );
        let bytes = hex.as_bytes();
        let mut salida = Vec::with_capacity(bytes.len() / 2);
        let mut indice = 0;
        while indice < bytes.len() {
            salida.push((valor_hex(bytes[indice]) << 4) | valor_hex(bytes[indice + 1]));
            indice += 2;
        }
        salida
    }

    /// Valor de un carácter hexadecimal del vector de prueba.
    fn valor_hex(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("carácter no hexadecimal en el vector de prueba"),
        }
    }

    /// Representa bytes como hex en minúsculas para comparar con los RFC.
    fn bytes_a_hex(bytes: &[u8]) -> String {
        let mut salida = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            salida.push_str(&format!("{byte:02x}"));
        }
        salida
    }

    /// Generador determinista para las pruebas con entradas aleatorias.
    fn xorshift(mut estado: u64) -> u64 {
        estado ^= estado << 13;
        estado ^= estado >> 7;
        estado ^= estado << 17;
        estado
    }

    /// Codifica un varint de QUIC (RFC 9000 §16) para construir tramas.
    fn varint(valor: u64) -> Vec<u8> {
        if valor < 64 {
            vec![valor as u8]
        } else if valor < 16_384 {
            vec![0x40 | ((valor >> 8) & 0x3f) as u8, valor as u8]
        } else if valor < 1_073_741_824 {
            vec![
                0x80 | ((valor >> 24) & 0x3f) as u8,
                (valor >> 16) as u8,
                (valor >> 8) as u8,
                valor as u8,
            ]
        } else {
            let mut salida = vec![0xc0 | ((valor >> 56) & 0x3f) as u8];
            for desplazamiento in (0..7).rev() {
                salida.push((valor >> (desplazamiento * 8)) as u8);
            }
            salida
        }
    }

    #[test]
    fn claves_initial_v1_coinciden_con_rfc_9001() {
        let dcid = hex_a_bytes("8394c8f03e515708");
        let secreto =
            secreto_cliente_initial(&dcid, QuicVersion::V1).expect("secreto Initial v1 del RFC");
        assert_eq!(
            bytes_a_hex(&secreto),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        let claves = claves_desde_dcid(&dcid, QuicVersion::V1).expect("claves Initial v1");
        assert_eq!(bytes_a_hex(&claves.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(bytes_a_hex(&claves.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(bytes_a_hex(&claves.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn claves_initial_v2_coinciden_con_rfc_9369() {
        let dcid = hex_a_bytes("8394c8f03e515708");
        let secreto =
            secreto_cliente_initial(&dcid, QuicVersion::V2).expect("secreto Initial v2 del RFC");
        assert_eq!(
            bytes_a_hex(&secreto),
            "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"
        );
        let claves = claves_desde_dcid(&dcid, QuicVersion::V2).expect("claves Initial v2");
        assert_eq!(bytes_a_hex(&claves.key), "8b1a0bc121284290a29e0971b5cd045d");
        assert_eq!(bytes_a_hex(&claves.iv), "91f73e2351d8fa91660e909f");
        assert_eq!(bytes_a_hex(&claves.hp), "45b95e15235d6f45a6b19cbcb0294ba9");
    }

    #[test]
    fn proteccion_de_cabecera_v1_coincide_con_rfc_9001() {
        let paquete = hex_a_bytes(PAQUETE_CLIENTE_V1);
        let cabecera = leer_cabecera(&paquete, QuicVersion::V1).expect("cabecera del RFC 9001");
        assert_eq!(bytes_a_hex(cabecera.dcid), "8394c8f03e515708");
        assert_eq!(cabecera.pn_offset, 18);
        assert_eq!(cabecera.longitud, 1182);
        let claves = claves_desde_dcid(cabecera.dcid, QuicVersion::V1).expect("claves v1");
        let descifrada =
            desenmascarar_cabecera(&paquete, &cabecera, &claves.hp).expect("desenmascarar v1");
        assert_eq!(
            bytes_a_hex(&descifrada.header),
            "c300000001088394c8f03e5157080000449e00000002"
        );
        assert_eq!(descifrada.pn, 2);
    }

    #[test]
    fn proteccion_de_cabecera_v2_coincide_con_rfc_9369() {
        let paquete = hex_a_bytes(PAQUETE_CLIENTE_V2);
        let cabecera = leer_cabecera(&paquete, QuicVersion::V2).expect("cabecera del RFC 9369");
        assert_eq!(bytes_a_hex(cabecera.dcid), "8394c8f03e515708");
        assert_eq!(cabecera.pn_offset, 18);
        assert_eq!(cabecera.longitud, 1182);
        let claves = claves_desde_dcid(cabecera.dcid, QuicVersion::V2).expect("claves v2");
        let descifrada =
            desenmascarar_cabecera(&paquete, &cabecera, &claves.hp).expect("desenmascarar v2");
        assert_eq!(
            bytes_a_hex(&descifrada.header),
            "d36b3343cf088394c8f03e5157080000449e00000002"
        );
        assert_eq!(descifrada.pn, 2);
    }

    #[test]
    fn descifra_initial_v1_del_rfc_9001() {
        let paquete = hex_a_bytes(PAQUETE_CLIENTE_V1);
        assert_eq!(paquete.len(), 1200, "el vector del RFC 9001 mide 1200 B");
        assert_eq!(initial_version(&paquete), Some(QuicVersion::V1));
        let payload = decrypt_initial(&paquete, QuicVersion::V1)
            .expect("el Initial de cliente del RFC 9001 debe descifrarse");
        assert_eq!(
            payload.len(),
            1162,
            "el RFC define una carga en claro de 1162 B"
        );
        let esperado = hex_a_bytes(TRAMA_CRYPTO_RFC);
        assert_eq!(&payload[..esperado.len()], esperado.as_slice());
        assert!(
            payload[esperado.len()..].iter().all(|byte| *byte == 0),
            "el resto de la carga del RFC son tramas PADDING (ceros)"
        );
        // La trama CRYPTO extraída coincide: offset 0 y el ClientHello del RFC.
        let tramas = crypto_frames(&payload);
        assert_eq!(tramas.len(), 1);
        assert_eq!(tramas[0].0, 0);
        assert_eq!(tramas[0].1, esperado[4..].to_vec());
        // ClientHello completo: mensaje de handshake de 241 B (4 + 237).
        assert_eq!(esperado.len(), 245);
        assert!(contains_client_hello(&payload));
        assert!(contains_client_hello(&esperado[4..]));
    }

    #[test]
    fn descifra_initial_v2_del_rfc_9369() {
        let paquete = hex_a_bytes(PAQUETE_CLIENTE_V2);
        assert_eq!(paquete.len(), 1200, "el vector del RFC 9369 mide 1200 B");
        assert_eq!(initial_version(&paquete), Some(QuicVersion::V2));
        let payload = decrypt_initial(&paquete, QuicVersion::V2)
            .expect("el Initial de cliente del RFC 9369 debe descifrarse");
        assert_eq!(payload.len(), 1162);
        let esperado = hex_a_bytes(TRAMA_CRYPTO_RFC);
        assert_eq!(&payload[..esperado.len()], esperado.as_slice());
        assert!(payload[esperado.len()..].iter().all(|byte| *byte == 0));
        assert!(contains_client_hello(&payload));
        // El apéndice A de ambos RFC comparte el mismo ClientHello en claro.
        let v1 = decrypt_initial(&hex_a_bytes(PAQUETE_CLIENTE_V1), QuicVersion::V1)
            .expect("el Initial de cliente del RFC 9001 debe descifrarse");
        assert_eq!(payload, v1);
    }

    #[test]
    fn detecta_initial_v1_y_v2() {
        assert_eq!(
            initial_version(&hex_a_bytes(PAQUETE_CLIENTE_V1)),
            Some(QuicVersion::V1)
        );
        assert_eq!(
            initial_version(&hex_a_bytes(PAQUETE_CLIENTE_V2)),
            Some(QuicVersion::V2)
        );
    }

    #[test]
    fn rechaza_paquetes_que_no_son_initial() {
        assert_eq!(initial_version(&[]), None);
        assert_eq!(initial_version(&[0xc0, 0x00]), None);
        // Cabecera corta: sin bit de forma largo.
        assert_eq!(initial_version(&[0x40, 0x00, 0x00, 0x00, 0x01]), None);
        // Bit fijo a cero.
        assert_eq!(initial_version(&[0x80, 0x00, 0x00, 0x00, 0x01]), None);
        // Versión desconocida.
        assert_eq!(initial_version(&[0xc0, 0x00, 0x00, 0x00, 0x02]), None);
        // Versión v1 con tipo Handshake (bits 4-5 = 10).
        assert_eq!(initial_version(&[0xe0, 0x00, 0x00, 0x00, 0x01]), None);
        // Los tipos de paquete de v1 y v2 no son intercambiables.
        assert_eq!(initial_version(&[0xc0, 0x6b, 0x33, 0x43, 0xcf]), None);
        assert_eq!(initial_version(&[0xd0, 0x00, 0x00, 0x00, 0x01]), None);
    }

    #[test]
    fn paquetes_truncados_devuelven_error_sin_panico() {
        let paquete = hex_a_bytes(PAQUETE_CLIENTE_V1);
        for longitud in 0..paquete.len() {
            let truncado = &paquete[..longitud];
            assert!(
                decrypt_initial(truncado, QuicVersion::V1).is_err(),
                "el prefijo de {longitud} B no puede descifrarse"
            );
            // Ninguna otra función puede entrar en pánico con el prefijo.
            let _ = initial_version(truncado);
            let _ = crypto_frames(truncado);
            let _ = contains_client_hello(truncado);
        }
    }

    #[test]
    fn paquete_manipulado_no_se_descifra() {
        let paquete = hex_a_bytes(PAQUETE_CLIENTE_V1);
        // Un bit cambiado en la carga cifrada rompe la autenticación GCM.
        let mut carga_manipulada = paquete.clone();
        carga_manipulada[22] ^= 0x01;
        assert!(decrypt_initial(&carga_manipulada, QuicVersion::V1).is_err());
        // Un bit cambiado en el tag también.
        let mut tag_manipulado = paquete.clone();
        let ultimo = tag_manipulado.len() - 1;
        tag_manipulado[ultimo] ^= 0x80;
        assert!(decrypt_initial(&tag_manipulado, QuicVersion::V1).is_err());
        // La versión que indica el llamante debe ser la del paquete.
        assert!(decrypt_initial(&paquete, QuicVersion::V2).is_err());
        // Los paquetes que superan el máximo de la especificación se descartan.
        let mut grande = paquete.clone();
        grande.resize(MAX_PAQUETE_INITIAL + 1, 0);
        assert!(decrypt_initial(&grande, QuicVersion::V1).is_err());
    }

    #[test]
    fn crypto_frames_extrae_offset_y_datos() {
        // PING, dos PADDING y dos tramas CRYPTO con offset.
        let mut payload = vec![0x01, 0x00, 0x00];
        payload.extend_from_slice(&[0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc]);
        payload.extend_from_slice(&[0x06, 0x08, 0x02, 0xdd, 0xee]);
        assert_eq!(
            crypto_frames(&payload),
            vec![(0, vec![0xaa, 0xbb, 0xcc]), (8, vec![0xdd, 0xee])]
        );
    }

    #[test]
    fn crypto_frames_ignora_padding_ping_y_ack() {
        // ACK (tipo 0x02): mayor=10, retardo=0, un rango, primer rango=0 y
        // el rango (hueco=0, longitud=0).
        let mut payload = vec![0x02, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00];
        // ACK con ECN (tipo 0x03): añade ect0, ect1 y ce.
        payload.extend_from_slice(&[0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // CRYPTO con offset 0 y un byte de datos.
        payload.extend_from_slice(&[0x06, 0x00, 0x01, 0x7f]);
        assert_eq!(crypto_frames(&payload), vec![(0, vec![0x7f])]);
        assert!(crypto_frames(&[0x00, 0x00, 0x00, 0x01]).is_empty());
    }

    #[test]
    fn crypto_frames_tramas_mal_formadas_no_revientan() {
        // CRYPTO truncada: declara 10 B y solo hay 2.
        assert!(crypto_frames(&[0x06, 0x00, 0x0a, 0xaa, 0xbb]).is_empty());
        // Tipo desconocido: se detiene y no extrae la CRYPTO posterior.
        let mut payload = vec![0xff];
        payload.extend_from_slice(&[0x06, 0x00, 0x01, 0x11]);
        assert!(crypto_frames(&payload).is_empty());
        // Cualquier tipo de trama con el resto truncado termina sin pánico.
        for tipo in 0u8..=0xff {
            let payload = [tipo, 0xff, 0xff, 0xff, 0xff];
            let _ = crypto_frames(&payload);
        }
    }

    #[test]
    fn contains_client_hello_detecta_el_del_rfc() {
        let paquete = hex_a_bytes(PAQUETE_CLIENTE_V1);
        let payload = decrypt_initial(&paquete, QuicVersion::V1).expect("Initial v1 del RFC");
        assert!(contains_client_hello(&payload));
        let trama = hex_a_bytes(TRAMA_CRYPTO_RFC);
        // Stream CRYPTO de QUIC: handshake directo, sin registro TLS.
        assert!(contains_client_hello(&trama[4..]));
        // Registro TLS clásico (uso sobre TCP): 16 03 01 + longitud + ClientHello.
        let mut registro = vec![0x16, 0x03, 0x01, 0x00, 0xf1];
        registro.extend_from_slice(&trama[4..]);
        assert_eq!(registro.len(), 5 + 241);
        assert!(contains_client_hello(&registro));
        // Un ClientHello partido o truncado no está completo.
        assert!(!contains_client_hello(&trama[4..trama.len() - 1]));
        assert!(!contains_client_hello(&registro[..registro.len() - 1]));
        assert!(!contains_client_hello(&[]));
        assert!(!contains_client_hello(&[0x00; 32]));
    }

    #[test]
    fn contains_client_hello_tras_ping_en_el_payload() {
        // Un Initial real puede llevar PING y PADDING antes de la trama CRYPTO.
        let mut payload = vec![0x01, 0x00];
        payload.extend_from_slice(&hex_a_bytes(TRAMA_CRYPTO_RFC));
        assert!(contains_client_hello(&payload));
    }

    #[test]
    fn contains_client_hello_recompone_varias_tramas_crypto() {
        let trama = hex_a_bytes(TRAMA_CRYPTO_RFC);
        let clienthello = &trama[4..];
        let corte = 100usize;
        let mut payload = vec![0x06];
        payload.extend_from_slice(&varint(0));
        payload.extend_from_slice(&varint(corte as u64));
        payload.extend_from_slice(&clienthello[..corte]);
        payload.push(0x06);
        payload.extend_from_slice(&varint(corte as u64));
        payload.extend_from_slice(&varint((clienthello.len() - corte) as u64));
        payload.extend_from_slice(&clienthello[corte..]);
        assert!(contains_client_hello(&payload));
        // Con un hueco entre las dos tramas no se puede recomponer.
        let mut con_hueco = payload.clone();
        con_hueco[2] = 0x01;
        assert!(!contains_client_hello(&con_hueco));
    }

    #[test]
    fn entradas_aleatorias_no_provocan_panico() {
        let mut estado = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..512 {
            estado = xorshift(estado);
            let longitud = (estado as usize) % 257;
            let mut semilla = estado;
            let mut datos = Vec::with_capacity(longitud);
            for _ in 0..longitud {
                semilla = xorshift(semilla);
                datos.push(semilla as u8);
            }
            let _ = initial_version(&datos);
            let _ = decrypt_initial(&datos, QuicVersion::V1);
            let _ = decrypt_initial(&datos, QuicVersion::V2);
            let _ = crypto_frames(&datos);
            let _ = contains_client_hello(&datos);
            // Con una cabecera v1 aparente se llega más lejos en el parseo.
            let mut cabecera = vec![0xc0, 0x00, 0x00, 0x00, 0x01];
            cabecera.extend_from_slice(&datos);
            let _ = decrypt_initial(&cabecera, QuicVersion::V1);
            let _ = crypto_frames(&cabecera);
            let _ = contains_client_hello(&cabecera);
        }
    }
}
