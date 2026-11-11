//! MAC privadas y regla de rotación de mac_changed v2 (§7.13).
//!
//! Una MAC privada es una MAC administrada localmente (bit U/L a 1) y unicast
//! (bit de grupo a 0). Los móviles modernos rotan esa MAC; la Regla A del
//! informe solo fusiona identidad cuando hay un único candidato con la misma
//! huella y el mismo nombre DHCP y ese candidato no se ha visto en el ciclo.

/// Comprueba el bit U/L: MAC privada y unicast.
///
/// Devuelve false para MAC mal formadas o para direcciones de grupo/broadcast
/// (el bit de menor peso del primer octeto), que nunca son MAC privadas de un
/// equipo.
pub fn is_private(mac: &str) -> bool {
    let Some(normalizada) = normalize(mac) else {
        return false;
    };
    let Some(primer_octeto) = normalizada
        .get(0..2)
        .and_then(|octeto| u8::from_str_radix(octeto, 16).ok())
    else {
        return false;
    };
    // Bit 1 (0x02) = administrada localmente; bit 0 (0x01) = grupo.
    primer_octeto & 0x02 != 0 && primer_octeto & 0x01 == 0
}

/// Normaliza una MAC a aa:bb:cc:dd:ee:ff en minúsculas.
pub fn normalize(mac: &str) -> Option<String> {
    let limpio: String = mac
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if limpio.len() != 12 {
        return None;
    }
    Some(
        limpio
            .as_bytes()
            .chunks(2)
            .map(|par| std::str::from_utf8(par).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Identidad DHCP de un equipo candidato del ciclo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpIdentity {
    /// MAC normalizada.
    pub mac: String,
    /// Huella DHCP (opción 55).
    pub dhcp_fingerprint: Option<String>,
    /// Nombre DHCP (opción 12).
    pub dhcp_hostname: Option<String>,
}

/// Equipo conocido con su identidad persistida.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// Id en SQLite.
    pub id: i64,
    /// MAC persistida.
    pub mac: String,
    /// Huella DHCP persistida.
    pub dhcp_fingerprint: Option<String>,
    /// Nombre DHCP persistido.
    pub dhcp_hostname: Option<String>,
    /// El equipo se ha visto en el ciclo actual.
    pub seen_this_cycle: bool,
}

/// Regla A de rotación de MAC privada: devuelve el id del único equipo
/// candidato con la misma huella y nombre DHCP, o None si no hay o hay varios.
///
/// Requisitos de §7.13:
/// - la MAC nueva es privada y trae huella y nombre DHCP;
/// - el candidato tiene MAC privada, no se ha visto en el ciclo y coincide en
///   huella y nombre DHCP.
///
/// El nombre DHCP se compara sin distinguir mayúsculas (los nombres de equipo
/// no distinguen mayúsculas en la red, aunque el cliente lo envíe cambiado).
pub fn rotation_match(new: &DhcpIdentity, known: &[DeviceIdentity]) -> Option<i64> {
    if !is_private(&new.mac) {
        return None;
    }
    let huella = texto_no_vacio(new.dhcp_fingerprint.as_deref())?;
    let nombre = texto_no_vacio(new.dhcp_hostname.as_deref())?;

    let mut candidato = None;
    let mut candidatos = 0usize;
    for equipo in known {
        if equipo.seen_this_cycle || !is_private(&equipo.mac) {
            continue;
        }
        let misma_huella = texto_no_vacio(equipo.dhcp_fingerprint.as_deref()) == Some(huella);
        let mismo_nombre = texto_no_vacio(equipo.dhcp_hostname.as_deref())
            .map(|otro| otro.eq_ignore_ascii_case(nombre))
            .unwrap_or(false);
        if misma_huella && mismo_nombre {
            candidatos += 1;
            candidato = Some(equipo.id);
        }
    }
    if candidatos == 1 {
        candidato
    } else {
        None
    }
}

/// Devuelve el texto recortado si no está vacío.
fn texto_no_vacio(valor: Option<&str>) -> Option<&str> {
    valor.map(str::trim).filter(|texto| !texto.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_mac_privada_por_el_bit_ul() {
        // MACs con el bit U/L activo y unicast (bit 0 a 0): aleatorias de
        // Android/iOS y direcciones locales típicas.
        for mac in [
            "da:a1:19:00:00:01",
            "02:11:22:33:44:55",
            "06:aa:bb:cc:dd:ee",
            "0a:00:00:00:00:01",
            "0e:12:34:56:78:9a",
            "7a:11:22:33:44:55",
        ] {
            assert!(is_private(mac), "{mac} debería ser privada");
        }
    }

    #[test]
    fn una_mac_publica_no_es_privada() {
        for mac in [
            "3c:22:fb:11:22:33",
            "00:1a:2b:3c:4d:5e",
            "b8:27:eb:11:22:33",
            "ac:de:48:00:00:01",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert!(!is_private(mac), "{mac} no debería ser privada");
        }
    }

    #[test]
    fn una_mac_de_grupo_no_es_privada() {
        // Bit de grupo a 1: multicast, broadcast o MAC no válidas.
        for mac in [
            "01:00:5e:00:00:01",
            "33:33:00:00:00:01",
            "0b:11:22:33:44:55",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert!(!is_private(mac), "{mac} es de grupo");
        }
    }

    #[test]
    fn tolera_formatos_y_entradas_invalidas_sin_panico() {
        assert!(is_private("DA-A1-19-00-00-01"));
        assert!(is_private("daa119000001"));
        assert!(!is_private(""));
        assert!(!is_private("no-es-una-mac"));
        assert!(!is_private("zz:zz:zz:zz:zz:zz"));
        assert!(!is_private("da:a1:19"));

        assert_eq!(
            normalize("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(
            normalize("aabbccddeeff").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(normalize("aa:bb:cc:dd:ee"), None);
    }

    /// Identidad DHCP de una prueba, con campos opcionales.
    fn identidad(id: i64, mac: &str, huella: Option<&str>, nombre: Option<&str>) -> DeviceIdentity {
        DeviceIdentity {
            id,
            mac: mac.to_string(),
            dhcp_fingerprint: huella.map(str::to_string),
            dhcp_hostname: nombre.map(str::to_string),
            seen_this_cycle: false,
        }
    }

    /// MAC privada nueva de las pruebas (primer octeto 0xda).
    const MAC_NUEVA: &str = "da:a1:19:12:34:56";
    /// Huella DHCP de las pruebas.
    const HUELLA: &str = "1,121,3,6,15,119,252,95,44,46";
    /// Nombre DHCP de las pruebas.
    const NOMBRE: &str = "iPhone-de-Marta";

    /// Construye la MAC privada nueva con la huella y el nombre de las pruebas.
    fn nueva() -> DhcpIdentity {
        DhcpIdentity {
            mac: MAC_NUEVA.to_string(),
            dhcp_fingerprint: Some(HUELLA.to_string()),
            dhcp_hostname: Some(NOMBRE.to_string()),
        }
    }

    #[test]
    fn con_un_unico_candidato_se_conserva_el_equipo() {
        // Criterio de aceptación del checklist: móvil con MAC privada no visto
        // en el ciclo y con la misma huella y nombre → mismo id (el llamador
        // emite mac_changed con reason = rotation).
        let conocidos = vec![
            identidad(7, "02:00:00:00:00:07", Some(HUELLA), Some(NOMBRE)),
            identidad(8, "3c:22:fb:11:22:33", Some(HUELLA), Some(NOMBRE)),
        ];
        assert_eq!(rotation_match(&nueva(), &conocidos), Some(7));
    }

    #[test]
    fn con_varios_candidatos_no_se_fusiona_identidad() {
        let conocidos = vec![
            identidad(7, "02:00:00:00:00:07", Some(HUELLA), Some(NOMBRE)),
            identidad(8, "0e:00:00:00:00:08", Some(HUELLA), Some(NOMBRE)),
        ];
        assert_eq!(rotation_match(&nueva(), &conocidos), None);
    }

    #[test]
    fn un_candidato_visto_en_el_ciclo_no_cuenta() {
        let mut visto = identidad(7, "02:00:00:00:00:07", Some(HUELLA), Some(NOMBRE));
        visto.seen_this_cycle = true;
        assert_eq!(rotation_match(&nueva(), &[visto]), None);
    }

    #[test]
    fn una_candidata_con_mac_publica_no_cuenta() {
        let conocidos = vec![identidad(
            7,
            "3c:22:fb:11:22:33",
            Some(HUELLA),
            Some(NOMBRE),
        )];
        assert_eq!(rotation_match(&nueva(), &conocidos), None);
    }

    #[test]
    fn la_mac_nueva_debe_ser_privada() {
        let mut publica = nueva();
        publica.mac = "3c:22:fb:11:22:33".to_string();
        let conocidos = vec![identidad(
            7,
            "02:00:00:00:00:07",
            Some(HUELLA),
            Some(NOMBRE),
        )];
        assert_eq!(rotation_match(&publica, &conocidos), None);

        // Tampoco una MAC de grupo.
        let mut grupo = nueva();
        grupo.mac = "01:00:5e:00:00:01".to_string();
        assert_eq!(rotation_match(&grupo, &conocidos), None);
    }

    #[test]
    fn sin_huella_o_sin_nombre_no_hay_rotacion() {
        let conocidos = vec![identidad(
            7,
            "02:00:00:00:00:07",
            Some(HUELLA),
            Some(NOMBRE),
        )];

        let mut sin_huella = nueva();
        sin_huella.dhcp_fingerprint = None;
        assert_eq!(rotation_match(&sin_huella, &conocidos), None);

        let mut sin_nombre = nueva();
        sin_nombre.dhcp_hostname = None;
        assert_eq!(rotation_match(&sin_nombre, &conocidos), None);

        // Una cadena vacía equivale a no tener la señal.
        let mut vacia = nueva();
        vacia.dhcp_fingerprint = Some("  ".to_string());
        assert_eq!(rotation_match(&vacia, &conocidos), None);
    }

    #[test]
    fn huella_o_nombre_distintos_no_casan() {
        let conocidos = vec![identidad(
            7,
            "02:00:00:00:00:07",
            Some("1,3,6,15,119,252"),
            Some(NOMBRE),
        )];
        assert_eq!(rotation_match(&nueva(), &conocidos), None);

        let otros = vec![identidad(
            7,
            "02:00:00:00:00:07",
            Some(HUELLA),
            Some("otro-nombre"),
        )];
        assert_eq!(rotation_match(&nueva(), &otros), None);
    }

    #[test]
    fn el_nombre_dhcp_se_compara_sin_mayusculas() {
        let conocidos = vec![identidad(
            7,
            "02:00:00:00:00:07",
            Some(HUELLA),
            Some("iphone-DE-marta "),
        )];
        assert_eq!(rotation_match(&nueva(), &conocidos), Some(7));
    }

    #[test]
    fn sin_equipos_conocidos_no_hay_candidato() {
        assert_eq!(rotation_match(&nueva(), &[]), None);
    }
}
