//! Extracción de Host y User-Agent de peticiones HTTP/1.x en claro (§7.6).
//!
//! Solo se admiten peticiones HTTP/1.x con la cabecera completa (línea de
//! petición y cabeceras hasta CRLF CRLF). De todo el payload únicamente salen de
//! este módulo el Host normalizado y el User-Agent saneado y truncado.

use crate::inference::{MAX_SERVER_NAME, MAX_USER_AGENT};

/// Longitud máxima del bloque de cabeceras que se examina.
const MAX_CABECERAS: usize = 8192;
/// Métodos HTTP que se aceptan en la línea de petición.
const METODOS: [&str; 9] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// Datos de una petición HTTP/1.x en claro.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequestInfo {
    /// Cabecera Host normalizada (sin puerto, minúsculas).
    pub host: Option<String>,
    /// Cabecera User-Agent saneada y truncada.
    pub user_agent: Option<String>,
}

/// Parsea una petición HTTP/1.x completa (cabeceras hasta CRLF CRLF).
pub fn parse_request(data: &[u8]) -> Option<HttpRequestInfo> {
    let fin = buscar_fin_de_cabeceras(data)?;
    let bloque = data.get(..fin)?;

    let mut lineas = bloque.split(|byte| *byte == b'\r');
    let peticion = std::str::from_utf8(lineas.next()?).ok()?;
    if !linea_de_peticion_valida(peticion) {
        return None;
    }

    let mut info = HttpRequestInfo::default();
    for linea in lineas {
        // Cada línea empieza por el LF que sigue al CR usado para partir.
        let Some(linea) = linea.strip_prefix(b"\n") else {
            continue;
        };
        if linea.is_empty() {
            continue;
        }
        let Some(posicion) = linea.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let nombre = &linea[..posicion];
        let valor = &linea[posicion + 1..];
        if info.host.is_none() && nombre.eq_ignore_ascii_case(b"host") {
            if let Ok(texto) = std::str::from_utf8(valor) {
                info.host = normalize_host(texto);
            }
        } else if info.user_agent.is_none() && nombre.eq_ignore_ascii_case(b"user-agent") {
            if let Ok(texto) = std::str::from_utf8(valor) {
                info.user_agent = sanitize_user_agent(texto);
            }
        }
    }
    Some(info)
}

/// Devuelve la posición del terminador CRLF CRLF del bloque de cabeceras.
fn buscar_fin_de_cabeceras(data: &[u8]) -> Option<usize> {
    let limite = data.len().min(MAX_CABECERAS);
    data.get(..limite)?
        .windows(4)
        .position(|ventana| ventana == b"\r\n\r\n")
}

/// Comprueba que la línea de petición es «MÉTODO objetivo HTTP/1.x».
fn linea_de_peticion_valida(linea: &str) -> bool {
    let mut partes = linea.split(' ');
    let (Some(metodo), Some(objetivo), Some(version)) =
        (partes.next(), partes.next(), partes.next())
    else {
        return false;
    };
    if partes.next().is_some() {
        return false;
    }
    METODOS.contains(&metodo)
        && !objetivo.is_empty()
        && (version == "HTTP/1.0" || version == "HTTP/1.1")
}

/// Normaliza un Host: minúsculas, sin puerto y sin punto final.
pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim();
    let sin_puerto = if host.starts_with('[') {
        // IPv6 literal: [dirección] o [dirección]:puerto.
        let fin = host.find(']')?;
        &host[..=fin]
    } else {
        match host.rsplit_once(':') {
            Some((izquierda, derecha)) if derecha.chars().all(|c| c.is_ascii_digit()) => izquierda,
            _ => host,
        }
    };
    let limpio = sin_puerto.trim_end_matches('.').to_ascii_lowercase();
    if limpio.is_empty()
        || limpio.len() > MAX_SERVER_NAME
        || limpio.contains(|c: char| c.is_whitespace() || c.is_control() || c == '/')
    {
        return None;
    }
    Some(limpio)
}

/// Sanea un User-Agent: solo imprimibles y truncado a 256.
pub fn sanitize_user_agent(ua: &str) -> Option<String> {
    let limpio: String = ua
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_USER_AGENT)
        .collect();
    let limpio = limpio.trim().to_string();
    if limpio.is_empty() {
        None
    } else {
        Some(limpio)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Genera bytes pseudoaleatorios de forma determinista.
    fn aleatorios(semilla: u32, longitud: usize) -> Vec<u8> {
        let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(11);
        let mut datos = Vec::with_capacity(longitud);
        for _ in 0..longitud {
            estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
            datos.push((estado >> 24) as u8);
        }
        datos
    }

    #[test]
    fn extrae_el_host_y_el_user_agent() {
        let peticion = b"GET /index.html HTTP/1.1\r\nHost: Ejemplo.COM.:8080\r\nUser-Agent: Mozilla/5.0 (X11; Linux)\r\nAccept: */*\r\n\r\n";
        let info = parse_request(peticion).expect("petición HTTP válida");
        assert_eq!(info.host.as_deref(), Some("ejemplo.com"));
        assert_eq!(info.user_agent.as_deref(), Some("Mozilla/5.0 (X11; Linux)"));
    }

    #[test]
    fn acepta_cabeceras_en_minusculas_y_con_espacios() {
        let peticion =
            b"POST /api HTTP/1.0\r\nhost:  www.ejemplo.es  \r\nuser-agent:   curl/8.0  \r\n\r\n";
        let info = parse_request(peticion).expect("petición HTTP válida");
        assert_eq!(info.host.as_deref(), Some("www.ejemplo.es"));
        assert_eq!(info.user_agent.as_deref(), Some("curl/8.0"));
    }

    #[test]
    fn devuelve_los_campos_vacios_si_faltan_las_cabeceras() {
        let info = parse_request(b"GET / HTTP/1.1\r\n\r\n").expect("petición sin cabeceras");
        assert_eq!(info, HttpRequestInfo::default());
    }

    #[test]
    fn rechaza_una_peticion_sin_el_terminador_de_cabeceras() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost: ejemplo.com\r\n"),
            None
        );
    }

    #[test]
    fn rechaza_una_respuesta_http() {
        assert_eq!(
            parse_request(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            None
        );
    }

    #[test]
    fn rechaza_metodos_desconocidos_y_versiones_que_no_son_http1() {
        assert_eq!(parse_request(b"FOO / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_request(b"GET / HTTP/2.0\r\n\r\n"), None);
        assert_eq!(parse_request(b"GET /\r\n\r\n"), None);
        assert_eq!(parse_request(b"GET / HTTP/1.1 extra\r\n\r\n"), None);
    }

    #[test]
    fn ignora_cabeceras_mal_formadas_sin_perder_las_buenas() {
        let peticion =
            b"GET / HTTP/1.1\r\nEsta linea no tiene dos puntos\r\nHost: ejemplo.com\r\n\r\n";
        let info = parse_request(peticion).expect("petición válida");
        assert_eq!(info.host.as_deref(), Some("ejemplo.com"));
    }

    #[test]
    fn normaliza_el_host() {
        assert_eq!(
            normalize_host("Ejemplo.COM.").as_deref(),
            Some("ejemplo.com")
        );
        assert_eq!(
            normalize_host(" ejemplo.com:443 ").as_deref(),
            Some("ejemplo.com")
        );
        assert_eq!(normalize_host("[::1]:8080").as_deref(), Some("[::1]"));
        assert_eq!(
            normalize_host("[2001:db8::1]").as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("   "), None);
        assert_eq!(normalize_host("con espacio.com"), None);
        assert_eq!(normalize_host("con/barra.com"), None);
        assert_eq!(normalize_host(&"a".repeat(MAX_SERVER_NAME + 1)), None);
    }

    #[test]
    fn sanea_el_user_agent() {
        let ua = "Mozilla/5.0\u{0}\u{7} (X11; Linux)";
        assert_eq!(
            sanitize_user_agent(ua).as_deref(),
            Some("Mozilla/5.0 (X11; Linux)")
        );
        assert_eq!(sanitize_user_agent("   "), None);
        assert_eq!(sanitize_user_agent("\u{1}\u{2}"), None);
        let largo = "a".repeat(MAX_USER_AGENT + 100);
        assert_eq!(
            sanitize_user_agent(&largo).map(|texto| texto.len()),
            Some(MAX_USER_AGENT)
        );
    }

    #[test]
    fn no_hace_panic_con_datos_aleatorios() {
        for semilla in 0u32..128 {
            let datos = aleatorios(semilla, (semilla % 200) as usize);
            let _ = parse_request(&datos);
            let mut con_terminador = datos.clone();
            con_terminador.extend_from_slice(b"\r\n\r\n");
            let _ = parse_request(&con_terminador);
        }
    }
}
