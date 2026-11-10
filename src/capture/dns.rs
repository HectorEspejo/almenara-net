//! Extracción del QNAME de consultas DNS en el parser de captura.
//!
//! Solo se examina el payload del datagrama (puerto 53) y de él únicamente se
//! copia el nombre de la primera pregunta. El resto del payload se descarta
//! inmediatamente y nunca llega a [PacketMeta](super::PacketMeta): esta función
//! devuelve únicamente el nombre ya extraído.

/// Longitud de la cabecera fija de un mensaje DNS.
const CABECERA_DNS: usize = 12;
/// Número máximo de punteros de compresión que se siguen (guarda anti-bucle).
const MAX_SALTOS: usize = 32;
/// Longitud máxima de un nombre DNS en el cable (RFC 1035).
const MAX_NOMBRE: usize = 253;

/// Información extraída de una consulta DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    /// Nombre de la primera pregunta de la consulta (sin punto final).
    pub qname: String,
}

/// Extrae el QNAME de una consulta DNS.
///
/// Devuelve `None` si el payload no es una consulta DNS válida: mensaje
/// truncado, respuesta (QR=1), sin preguntas (QDCOUNT=0), etiquetas inválidas,
/// punteros de compresión fuera de rango o con bucle, o nombre vacío.
pub fn extract(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < CABECERA_DNS {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        // Es una respuesta: no aporta QNAME de consulta.
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let nombre = leer_nombre(payload, CABECERA_DNS)?;
    if nombre.is_empty() {
        // Consulta de la raíz: no aporta un nombre útil.
        return None;
    }
    Some(DnsInfo { qname: nombre })
}

/// Lee un nombre DNS a partir de `inicio`, resolviendo punteros de compresión.
///
/// Se aplican cotas estrictas para no entrar en bucles ni panicar con payloads
/// truncados: máximo de saltos, etiquetas de 1..=63 bytes y nombre de hasta
/// 253 bytes en el cable.
fn leer_nombre(payload: &[u8], inicio: usize) -> Option<String> {
    let mut nombre = String::new();
    let mut cursor = inicio;
    let mut saltos = 0usize;
    let mut longitud_cable = 0usize;

    loop {
        let longitud = *payload.get(cursor)? as usize;
        match longitud & 0xC0 {
            0x00 => {
                if longitud == 0 {
                    return Some(nombre);
                }
                if longitud > MAX_NOMBRE {
                    return None;
                }
                let etiqueta_inicio = cursor.checked_add(1)?;
                let etiqueta_fin = etiqueta_inicio.checked_add(longitud)?;
                let etiqueta = payload.get(etiqueta_inicio..etiqueta_fin)?;
                // Las etiquetas DNS transportan bytes; se exige UTF-8 válido
                // para poder mostrarlas tal cual en la TUI.
                let etiqueta = std::str::from_utf8(etiqueta).ok()?;
                if !nombre.is_empty() {
                    nombre.push('.');
                }
                nombre.push_str(etiqueta);
                longitud_cable = longitud_cable.checked_add(longitud + 1)?;
                if longitud_cable > MAX_NOMBRE {
                    return None;
                }
                cursor = etiqueta_fin;
            }
            0xC0 => {
                // Puntero de compresión: 14 bits de desplazamiento.
                saltos += 1;
                if saltos > MAX_SALTOS {
                    // Guarda anti-bucle: un mensaje malicioso puede apuntarse a sí mismo.
                    return None;
                }
                let segundo = *payload.get(cursor + 1)? as usize;
                let destino = ((longitud & 0x3F) << 8) | segundo;
                if destino < CABECERA_DNS || destino >= payload.len() {
                    return None;
                }
                cursor = destino;
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye una consulta DNS A/IN con el nombre indicado, sin compresión.
    fn consulta(nombre: &str) -> Vec<u8> {
        let mut mensaje = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for etiqueta in nombre.split('.') {
            mensaje.push(etiqueta.len() as u8);
            mensaje.extend_from_slice(etiqueta.as_bytes());
        }
        mensaje.push(0);
        mensaje.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        mensaje.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        mensaje
    }

    #[test]
    fn extrae_el_qname_de_una_consulta_simple() {
        let info = extract(&consulta("example.com")).expect("debe extraer el qname");
        assert_eq!(info.qname, "example.com");
    }

    #[test]
    fn extrae_un_nombre_de_varias_etiquetas() {
        let info = extract(&consulta("nas.casa.lan")).expect("nombre con tres etiquetas");
        assert_eq!(info.qname, "nas.casa.lan");
    }

    #[test]
    fn resuelve_punteros_de_compresion() {
        // Cabecera con una pregunta; el nombre es "www" + puntero a "ejemplo.local"
        // que se coloca después de la pregunta.
        let mut mensaje = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        mensaje.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 22]);
        mensaje.extend_from_slice(&1u16.to_be_bytes());
        mensaje.extend_from_slice(&1u16.to_be_bytes());
        // A partir del byte 22: "ejemplo.local" sin compresión.
        assert_eq!(mensaje.len(), 22);
        for etiqueta in ["ejemplo", "local"] {
            mensaje.push(etiqueta.len() as u8);
            mensaje.extend_from_slice(etiqueta.as_bytes());
        }
        mensaje.push(0);
        let info = extract(&mensaje).expect("debe seguir el puntero");
        assert_eq!(info.qname, "www.ejemplo.local");
    }

    #[test]
    fn descarta_las_respuestas() {
        let mut mensaje = consulta("example.com");
        mensaje[2] |= 0x80; // QR = 1 (respuesta)
        assert_eq!(extract(&mensaje), None);
    }

    #[test]
    fn descarta_los_mensajes_sin_preguntas() {
        let mut mensaje = consulta("example.com");
        mensaje[4] = 0;
        mensaje[5] = 0;
        assert_eq!(extract(&mensaje), None);
    }

    #[test]
    fn descarta_payloads_demasiado_cortos() {
        assert_eq!(extract(&[]), None);
        assert_eq!(extract(&[0u8; 11]), None);
        let mensaje = consulta("example.com");
        assert_eq!(extract(&mensaje[..12]), None);
    }

    #[test]
    fn descarta_las_etiquetas_truncadas() {
        let mensaje = consulta("example.com");
        // Cortar justo después del byte de longitud de la primera etiqueta.
        assert_eq!(extract(&mensaje[..13]), None);
        // Cortar dentro de la etiqueta.
        assert_eq!(extract(&mensaje[..15]), None);
    }

    #[test]
    fn descarta_punteros_fuera_de_rango() {
        let mut mensaje = consulta("example.com");
        // Convertir la primera etiqueta en un puntero al byte 200 (fuera del mensaje).
        mensaje[12] = 0xC0;
        mensaje[13] = 200;
        assert_eq!(extract(&mensaje), None);
        // Puntero a la zona de la cabecera, donde no empieza un nombre.
        mensaje[13] = 4;
        assert_eq!(extract(&mensaje), None);
    }

    #[test]
    fn corta_los_bucles_de_punteros() {
        let mut mensaje = consulta("example.com");
        // Puntero que se apunta a sí mismo.
        mensaje[12] = 0xC0;
        mensaje[13] = 12;
        assert_eq!(extract(&mensaje), None);
    }

    #[test]
    fn descarta_etiquetas_con_bits_reservados() {
        let mut mensaje = consulta("example.com");
        mensaje[12] = 0x40; // 0b01xxxxxx: tipo de etiqueta extendido no soportado
        assert_eq!(extract(&mensaje), None);
    }

    #[test]
    fn descarta_etiquetas_que_no_son_utf8() {
        let mut mensaje = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        mensaje.extend_from_slice(&[2, 0xFF, 0xFE, 0]);
        assert_eq!(extract(&mensaje), None);
    }

    #[test]
    fn descarta_la_consulta_de_la_raiz() {
        let mut mensaje = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        mensaje.push(0);
        assert_eq!(extract(&mensaje), None);
    }

    #[test]
    fn no_hace_panic_con_payloads_arbitrarios() {
        // Barrido determinista de bytes pseudoaleatorios: extract nunca debe panicar.
        for semilla in 0u32..64 {
            let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(1);
            let longitud = (semilla % 40) as usize + 12;
            let mut datos = Vec::with_capacity(longitud);
            for _ in 0..longitud {
                estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                datos.push((estado >> 24) as u8);
            }
            let _ = extract(&datos);
        }
    }
}
