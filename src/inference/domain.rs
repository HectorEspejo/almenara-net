//! Dominio registrable (eTLD+1) con la Public Suffix List embebida (§7.10).

use std::net::IpAddr;

/// Devuelve el dominio registrable de un nombre DNS (rr3---sn-x.googlevideo.com
/// → googlevideo.com). Devuelve None para IPs, nombres de una etiqueta y
/// sufijos especiales o desconocidos.
pub fn registrable(name: &str) -> Option<String> {
    let mut normalizado = name.trim().to_ascii_lowercase();
    while normalizado.ends_with('.') {
        normalizado.pop();
    }
    if normalizado.is_empty() {
        return None;
    }
    // Las direcciones IP no tienen dominio registrable.
    if normalizado.parse::<IpAddr>().is_ok() {
        return None;
    }
    // Un nombre de servidor no lleva esquema, ruta, puerto ni comodines.
    if normalizado.contains("://")
        || normalizado.contains('/')
        || normalizado.contains(':')
        || normalizado.contains('*')
        || normalizado.contains(' ')
    {
        return None;
    }
    // Cotas de longitud de un nombre DNS (RFC 1035): se comprueban antes de
    // llamar a psl para no procesar entradas absurdas de la red.
    if normalizado.len() > 253 {
        return None;
    }
    for etiqueta in normalizado.split('.') {
        if etiqueta.is_empty() || etiqueta.len() > 63 {
            return None;
        }
    }
    // psl devuelve None si no reconoce el sufijo o si el nombre es de una sola
    // etiqueta. Un TLD desconocido se trata como sufijo, así que ejemplo.invalid
    // sí tiene dominio registrable (ejemplo.invalid).
    let dominio = psl::domain_str(&normalizado)?;
    let dominio = dominio.trim_end_matches('.').to_ascii_lowercase();
    if dominio.is_empty() {
        return None;
    }
    Some(dominio)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_de_googlevideo() {
        assert_eq!(
            registrable("rr3---sn-x.googlevideo.com"),
            Some("googlevideo.com".to_string())
        );
        assert_eq!(
            registrable("www.youtube.com"),
            Some("youtube.com".to_string())
        );
        assert_eq!(
            registrable("a.b.c.example.co.uk"),
            Some("example.co.uk".to_string())
        );
    }

    #[test]
    fn registrable_normaliza_mayusculas_y_punto_final() {
        assert_eq!(
            registrable("  WWW.Example.COM.  "),
            Some("example.com".to_string())
        );
        assert_eq!(
            registrable("MUSIC.YOUTUBE.COM."),
            Some("youtube.com".to_string())
        );
    }

    #[test]
    fn registrable_de_ip_o_nombre_no_registrable_es_none() {
        assert_eq!(registrable("8.8.8.8"), None);
        assert_eq!(registrable("87.216.1.2"), None);
        assert_eq!(registrable("2001:4860:4860::8888"), None);
        assert_eq!(registrable("::1"), None);
        assert_eq!(registrable("localhost"), None);
        assert_eq!(registrable(""), None);
        assert_eq!(registrable("   "), None);
        assert_eq!(registrable("com"), None);
        assert_eq!(registrable("co.uk"), None);
        // Según la Public Suffix List, un TLD desconocido actúa como sufijo.
        assert_eq!(
            registrable("ejemplo.invalid"),
            Some("ejemplo.invalid".to_string())
        );
        assert_eq!(registrable(&format!("{}.com", "a".repeat(64))), None);
        assert_eq!(registrable("https://youtube.com"), None);
        assert_eq!(registrable("youtube.com:443"), None);
        assert_eq!(registrable("*.youtube.com"), None);
    }

    #[test]
    fn registrable_no_panica_con_entradas_raras() {
        let muestras = [
            ".",
            "..",
            ".com",
            "a..b",
            "-",
            "-.-",
            "a.b.c.d.e.f.g.h.i.j",
            "ñandú.es",
            "MÜNCHEN.DE",
            "xn--mnchen-3ya.de",
        ];
        for muestra in muestras {
            let _ = registrable(muestra);
        }
        // Cadena larga seudorandom determinista: no debe entrar en pánico.
        let mut estado: u64 = 0x5eed_7777;
        let mut texto = String::new();
        for _ in 0..4000 {
            estado = estado
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let byte = b' ' + ((estado >> 33) % 95) as u8;
            texto.push(byte as char);
        }
        let _ = registrable(&texto);
        let largo = format!("{}.com", "a".repeat(10_000));
        assert_eq!(registrable(&largo), None);
    }
}
