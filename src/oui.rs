//! Lookup de fabricante por OUI (base embebida).
//!
//! Usa la base de datos de Wireshark embebida en el binario mediante el crate
//! renombrado como `ouidb`. Las MAC administradas localmente (bit U/L a 1) no
//! tienen fabricante asignable y se muestran como "?" en la interfaz.

use std::str::FromStr;

/// Normaliza una MAC a `aa:bb:cc:dd:ee:ff` en minúsculas.
///
/// Acepta separadores ":" o "-" y también 12 dígitos hexadecimales seguidos.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let limpia: String = raw
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != '-' && *c != '.')
        .collect::<String>()
        .to_ascii_lowercase();

    if limpia.len() != 12 || !limpia.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let octetos: Vec<String> = (0..6)
        .map(|i| limpia[i * 2..i * 2 + 2].to_string())
        .collect();
    Some(octetos.join(":"))
}

/// Indica si una MAC normalizada es administrada localmente.
pub fn is_locally_administered(mac: &str) -> bool {
    normalizar_octetos(mac)
        .map(|octetos| octetos[0] & 0x02 != 0)
        .unwrap_or(false)
}

/// Devuelve el fabricante asociado a la MAC, si se conoce.
pub fn lookup(mac: &str) -> Option<String> {
    let normalized = normalize_mac(mac)?;
    if is_locally_administered(&normalized) {
        return None;
    }
    let parsed = ouidb::MacAddress::from_str(&normalized).ok()?;
    parsed.oui().filter(|vendor| !vendor.trim().is_empty())
}

fn normalizar_octetos(mac: &str) -> Option<[u8; 6]> {
    let normalized = normalize_mac(mac)?;
    let mut octetos = [0u8; 6];
    for (i, octeto) in normalized.split(':').enumerate() {
        octetos[i] = u8::from_str_radix(octeto, 16).ok()?;
    }
    Some(octetos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normaliza_formatos_habituales() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("aa:bb:cc:dd:ee:ff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("aabbccddeeff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize_mac("aa.bb.cc.dd.ee.ff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
    }

    #[test]
    fn rechaza_macs_invalidas() {
        assert!(normalize_mac("").is_none());
        assert!(normalize_mac("zz:zz:zz:zz:zz:zz").is_none());
        assert!(normalize_mac("aa:bb:cc:dd:ee").is_none());
        assert!(normalize_mac("aa:bb:cc:dd:ee:ff:00").is_none());
    }

    #[test]
    fn detecta_mac_local() {
        assert!(is_locally_administered("02:11:22:33:44:55"));
        assert!(is_locally_administered("06:11:22:33:44:55"));
        assert!(!is_locally_administered("00:11:22:33:44:55"));
    }

    #[test]
    fn fabricante_conocido_apple() {
        let vendor = lookup("00:03:93:aa:bb:cc").expect("Apple está en la base OUI");
        assert!(!vendor.is_empty());
    }

    #[test]
    fn mac_local_no_tiene_fabricante() {
        assert!(lookup("02:00:00:00:00:01").is_none());
    }

    #[test]
    fn mac_no_parseable_no_tiene_fabricante() {
        assert!(lookup("no-es-mac").is_none());
    }
}
