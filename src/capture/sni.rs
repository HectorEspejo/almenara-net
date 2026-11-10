//! Extracción del SNI (server_name) de un ClientHello TLS en el parser de captura.
//!
//! Solo se examina el payload TCP del puerto 443 y de él únicamente se copia el
//! nombre del servidor. El resto del payload se descarta inmediatamente: esta
//! función devuelve únicamente el nombre ya extraído.

/// Tipo de contenido TLS de handshake.
const TLS_HANDSHAKE: u8 = 0x16;
/// Tipo de mensaje de handshake ClientHello.
const TLS_CLIENT_HELLO: u8 = 0x01;
/// Tipo de extensión server_name.
const TLS_EXTENSION_SERVER_NAME: u16 = 0x0000;
/// name_type de host_name dentro de la extensión server_name.
const TLS_NAME_TYPE_HOST_NAME: u8 = 0x00;
/// Longitud de la cabecera de un registro TLS.
const TLS_RECORD_HEADER: usize = 5;
/// Longitud de la cabecera de un mensaje de handshake.
const TLS_HANDSHAKE_HEADER: usize = 4;
/// Longitud de la parte fija del ClientHello (versión + random).
const TLS_CLIENT_HELLO_FIJO: usize = 34;

/// Extrae el SNI de un ClientHello TLS.
///
/// Devuelve `None` si el payload no es un ClientHello válido: registro que no
/// es de handshake, versión TLS fuera de 0x0301..=0x0303, mensaje que no es
/// ClientHello, extensión server_name ausente, name_type distinto de host_name,
/// truncamiento en cualquier punto o nombre que no sea UTF-8 válido.
pub fn extract(payload: &[u8]) -> Option<String> {
    // Registro TLS: tipo, versión y longitud.
    if payload.len() < TLS_RECORD_HEADER {
        return None;
    }
    if payload[0] != TLS_HANDSHAKE {
        return None;
    }
    let version = u16::from_be_bytes([payload[1], payload[2]]);
    if !(0x0301..=0x0303).contains(&version) {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    let record_fin = TLS_RECORD_HEADER.checked_add(record_len)?;
    let registro = payload.get(TLS_RECORD_HEADER..record_fin)?;

    // Mensaje de handshake: ClientHello.
    if registro.len() < TLS_HANDSHAKE_HEADER || registro[0] != TLS_CLIENT_HELLO {
        return None;
    }
    let handshake_len = (usize::from(registro[1]) << 16)
        | (usize::from(registro[2]) << 8)
        | usize::from(registro[3]);
    let handshake_fin = TLS_HANDSHAKE_HEADER.checked_add(handshake_len)?;
    let handshake = registro.get(TLS_HANDSHAKE_HEADER..handshake_fin)?;

    // ClientHello: versión (2), random (32), session_id, cipher_suites,
    // compresión y extensiones.
    if handshake.len() < TLS_CLIENT_HELLO_FIJO {
        return None;
    }
    let mut cursor = TLS_CLIENT_HELLO_FIJO;

    let session_id_len = usize::from(*handshake.get(cursor)?);
    cursor = cursor.checked_add(1 + session_id_len)?;

    let cipher_len = usize::from(u16::from_be_bytes([
        *handshake.get(cursor)?,
        *handshake.get(cursor + 1)?,
    ]));
    cursor = cursor.checked_add(2 + cipher_len)?;

    let compresion_len = usize::from(*handshake.get(cursor)?);
    cursor = cursor.checked_add(1 + compresion_len)?;

    let extensiones_len = usize::from(u16::from_be_bytes([
        *handshake.get(cursor)?,
        *handshake.get(cursor + 1)?,
    ]));
    cursor = cursor.checked_add(2)?;
    let extensiones_fin = cursor.checked_add(extensiones_len)?;
    if extensiones_fin > handshake.len() {
        return None;
    }

    while cursor + 4 <= extensiones_fin {
        let tipo = u16::from_be_bytes([handshake[cursor], handshake[cursor + 1]]);
        let longitud = u16::from_be_bytes([handshake[cursor + 2], handshake[cursor + 3]]) as usize;
        let datos_inicio = cursor + 4;
        let datos_fin = datos_inicio.checked_add(longitud)?;
        if datos_fin > extensiones_fin {
            return None;
        }
        if tipo == TLS_EXTENSION_SERVER_NAME {
            return extraer_server_name(&handshake[datos_inicio..datos_fin]);
        }
        cursor = datos_fin;
    }
    None
}

/// Extrae el host_name de los datos de la extensión server_name.
fn extraer_server_name(datos: &[u8]) -> Option<String> {
    if datos.len() < 2 {
        return None;
    }
    let lista_len = usize::from(u16::from_be_bytes([datos[0], datos[1]]));
    let lista_fin = 2usize.checked_add(lista_len)?;
    let lista = datos.get(2..lista_fin)?;
    let mut cursor = 0usize;
    while cursor + 3 <= lista.len() {
        let name_type = lista[cursor];
        let nombre_len = usize::from(u16::from_be_bytes([lista[cursor + 1], lista[cursor + 2]]));
        let nombre_inicio = cursor + 3;
        let nombre_fin = nombre_inicio.checked_add(nombre_len)?;
        let nombre = lista.get(nombre_inicio..nombre_fin)?;
        if name_type == TLS_NAME_TYPE_HOST_NAME {
            return std::str::from_utf8(nombre).ok().map(str::to_string);
        }
        cursor = nombre_fin;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye un registro TLS con un ClientHello y la extensión server_name.
    fn client_hello(servidor: Option<&str>) -> Vec<u8> {
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&[0x03, 0x03]); // versión TLS 1.2 (legacy)
        cuerpo.extend_from_slice(&[0x11; 32]); // random
        cuerpo.push(0); // session_id vacío
        cuerpo.extend_from_slice(&2u16.to_be_bytes()); // cipher suites
        cuerpo.extend_from_slice(&[0x13, 0x01]);
        cuerpo.push(1); // compresión: solo null
        cuerpo.push(0);

        let mut extensiones = Vec::new();
        if let Some(nombre) = servidor {
            let mut entrada = vec![TLS_NAME_TYPE_HOST_NAME];
            entrada.extend_from_slice(&(nombre.len() as u16).to_be_bytes());
            entrada.extend_from_slice(nombre.as_bytes());
            let mut lista = Vec::new();
            lista.extend_from_slice(&(entrada.len() as u16).to_be_bytes());
            lista.extend_from_slice(&entrada);
            extensiones.extend_from_slice(&TLS_EXTENSION_SERVER_NAME.to_be_bytes());
            extensiones.extend_from_slice(&(lista.len() as u16).to_be_bytes());
            extensiones.extend_from_slice(&lista);
        }
        // Extensión inofensiva relleno para comprobar que se saltan las no buscadas.
        extensiones.extend_from_slice(&0x0017u16.to_be_bytes()); // extended_master_secret
        extensiones.extend_from_slice(&0u16.to_be_bytes());

        cuerpo.extend_from_slice(&(extensiones.len() as u16).to_be_bytes());
        cuerpo.extend_from_slice(&extensiones);

        let mut handshake = vec![TLS_CLIENT_HELLO];
        handshake.push((cuerpo.len() >> 16) as u8);
        handshake.push((cuerpo.len() >> 8) as u8);
        handshake.push(cuerpo.len() as u8);
        handshake.extend_from_slice(&cuerpo);

        let mut registro = vec![TLS_HANDSHAKE, 0x03, 0x01];
        registro.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        registro.extend_from_slice(&handshake);
        registro
    }

    #[test]
    fn extrae_el_sni_de_un_client_hello() {
        let payload = client_hello(Some("example.com"));
        assert_eq!(extract(&payload).as_deref(), Some("example.com"));
    }

    #[test]
    fn extrae_un_sni_con_puntos_y_guiones() {
        let payload = client_hello(Some("nas-2.casa.local"));
        assert_eq!(extract(&payload).as_deref(), Some("nas-2.casa.local"));
    }

    #[test]
    fn devuelve_none_sin_extension_server_name() {
        let payload = client_hello(None);
        assert_eq!(extract(&payload), None);
    }

    #[test]
    fn devuelve_none_si_el_registro_no_es_un_handshake() {
        let mut payload = client_hello(Some("example.com"));
        payload[0] = 0x17; // application_data
        assert_eq!(extract(&payload), None);
    }

    #[test]
    fn devuelve_none_si_la_version_tls_no_soporta_client_hello() {
        let mut payload = client_hello(Some("example.com"));
        payload[1] = 0x02; // versión 0x0200 (SSL 2.0)
        payload[2] = 0x00;
        assert_eq!(extract(&payload), None);
    }

    #[test]
    fn devuelve_none_si_el_handshake_no_es_client_hello() {
        let mut payload = client_hello(Some("example.com"));
        payload[TLS_RECORD_HEADER] = 0x02; // ServerHello
        assert_eq!(extract(&payload), None);
    }

    #[test]
    fn devuelve_none_con_cualquier_prefijo_truncado() {
        let payload = client_hello(Some("example.com"));
        for longitud in 0..payload.len() {
            assert_eq!(
                extract(&payload[..longitud]),
                None,
                "un ClientHello truncado a {longitud} bytes no debe dar SNI"
            );
        }
    }

    #[test]
    fn devuelve_none_si_el_sni_no_es_utf8() {
        // Se construye a mano un ClientHello con bytes no UTF-8 en el nombre.
        let mut payload = client_hello(Some("ab"));
        // Localizar la entrada server_name y sustituir los dos bytes del nombre.
        let pos = payload
            .windows(2)
            .position(|ventana| ventana == b"ab")
            .expect("el nombre debe estar en el payload");
        payload[pos] = 0xFF;
        payload[pos + 1] = 0xFE;
        assert_eq!(extract(&payload), None);
    }

    #[test]
    fn devuelve_none_con_name_type_distinto_de_host_name() {
        let mut payload = client_hello(Some("example.com"));
        let pos = payload
            .windows(2)
            .position(|ventana| ventana == b"ex")
            .expect("el nombre debe estar en el payload");
        // Tres bytes antes del nombre está el name_type (0x00 = host_name),
        // seguido de la longitud del nombre en 2 bytes.
        payload[pos - 3] = 0x01;
        assert_eq!(extract(&payload), None);
    }

    #[test]
    fn no_hace_panic_con_payloads_arbitrarios() {
        for semilla in 0u32..64 {
            let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(7);
            let longitud = (semilla % 80) as usize;
            let mut datos = Vec::with_capacity(longitud);
            for _ in 0..longitud {
                estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                datos.push((estado >> 24) as u8);
            }
            let _ = extract(&datos);
        }
    }
}
