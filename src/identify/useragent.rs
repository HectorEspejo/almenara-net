//! Pistas de SO y tipo de equipo a partir del User-Agent HTTP (§7.12).
//!
//! Solo se aplican las reglas del informe: cada marcador presente suma sus
//! puntos (las reglas no son excluyentes; la puntuación combinada y el umbral
//! los resuelve Identify::os_family). El User-Agent llega de una petición HTTP
//! en claro, ya saneado y truncado por el extractor de inferencia.

use crate::classify::{DeviceType, OsFamily};

/// Marcadores de User-Agent de televisores, en minúsculas (§7.12).
const MARCADORES_TV: [&str; 3] = ["tizen", "web0s", "smart-tv"];

/// Clientes reconocidos: (marcador en el UA en minúsculas, nombre visible).
///
/// El orden importa: Edge y Opera incluyen Chrome y Safari en su cadena, así
/// que sus marcadores se comprueban antes.
const CLIENTES: [(&str, &str); 16] = [
    ("edg/", "Edge"),
    ("edga/", "Edge"),
    ("edgios/", "Edge"),
    ("opr/", "Opera"),
    ("fxios/", "Firefox"),
    ("firefox/", "Firefox"),
    ("crios/", "Chrome"),
    ("chrome/", "Chrome"),
    ("chromium/", "Chromium"),
    ("safari/", "Safari"),
    ("curl/", "curl"),
    ("wget/", "Wget"),
    ("okhttp/", "OkHttp"),
    ("dalvik/", "Dalvik"),
    ("python-requests/", "Python requests"),
    ("cfnetwork/", "CFNetwork"),
];

/// Pistas inferidas de un User-Agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UaHints {
    /// SO candidatos con sus puntos.
    pub os: Vec<(OsFamily, u8)>,
    /// Tipo de equipo sugerido.
    pub device_type: Option<DeviceType>,
    /// Navegador o cliente reconocido.
    pub client: Option<String>,
    /// El User-Agent corresponde a un televisor.
    pub is_tv: bool,
}

/// Analiza un User-Agent y devuelve las pistas de SO y tipo.
pub fn hints(ua: &str) -> UaHints {
    let mut pistas = UaHints::default();
    let minusculas = ua.to_ascii_lowercase();

    // 1) Televisores: Tizen, Web0S y SMART-TV (§7.12). Manda sobre móvil y
    //    tablet porque un televisor nunca es ninguna de las dos cosas.
    pistas.is_tv = MARCADORES_TV
        .iter()
        .any(|marcador| minusculas.contains(marcador));
    if pistas.is_tv {
        pistas.device_type = Some(DeviceType::Tv);
    }

    // 2) SO: reglas independientes, cada una con sus puntos del informe.
    if minusculas.contains("windows nt") {
        pistas.os.push((OsFamily::Windows, 4));
    }
    if minusculas.contains("iphone os") || minusculas.contains("cpu os") {
        pistas.os.push((OsFamily::Ios, 4));
    }
    if minusculas.contains("android") {
        pistas.os.push((OsFamily::Android, 4));
    }
    if minusculas.contains("macintosh") {
        pistas.os.push((OsFamily::MacOs, 3));
    }
    if minusculas.contains("linux") && !minusculas.contains("android") {
        pistas.os.push((OsFamily::Linux, 3));
    }

    // 3) Tipo de equipo por familia móvil, si la TV no lo ha fijado.
    //
    // En Android el marcador "Mobile" distingue el teléfono de la tableta:
    // Chrome en tabletas envía el mismo UA sin "Mobile" y sin "Tablet".
    if pistas.device_type.is_none() {
        let ipad = minusculas.contains("ipad");
        let iphone = minusculas.contains("iphone") || minusculas.contains("ipod");
        let android = minusculas.contains("android");
        let android_movil = android && minusculas.contains("mobile");
        let tablet = ipad || (android && !android_movil);
        let movil = iphone || android_movil;
        pistas.device_type = if tablet {
            Some(DeviceType::Tablet)
        } else if movil {
            Some(DeviceType::Mobile)
        } else {
            None
        };
    }

    pistas.client = detectar_cliente(&minusculas);
    pistas
}

/// Reconoce el navegador o cliente del User-Agent ya pasado a minúsculas.
fn detectar_cliente(minusculas: &str) -> Option<String> {
    CLIENTES
        .iter()
        .find(|(marcador, _)| minusculas.contains(marcador))
        .map(|(_, nombre)| (*nombre).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UA típico de Chrome en Windows 10.
    const UA_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    /// UA típico de Safari en iPhone.
    const UA_IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
        AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

    #[test]
    fn windows_nt_es_windows_y_chrome() {
        let pistas = hints(UA_WINDOWS);
        assert_eq!(pistas.os, vec![(OsFamily::Windows, 4)]);
        assert_eq!(pistas.client.as_deref(), Some("Chrome"));
        assert_eq!(pistas.device_type, None);
        assert!(!pistas.is_tv);
    }

    #[test]
    fn iphone_es_ios_y_movil() {
        let pistas = hints(UA_IPHONE);
        assert_eq!(pistas.os, vec![(OsFamily::Ios, 4)]);
        assert_eq!(pistas.device_type, Some(DeviceType::Mobile));
        assert_eq!(pistas.client.as_deref(), Some("Safari"));
        assert!(!pistas.is_tv);
    }

    #[test]
    fn ipad_es_ios_y_tablet() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) \
            AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1";
        let pistas = hints(ua);
        assert_eq!(pistas.os, vec![(OsFamily::Ios, 4)]);
        assert_eq!(pistas.device_type, Some(DeviceType::Tablet));
    }

    #[test]
    fn macintosh_es_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
            AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        let pistas = hints(ua);
        assert_eq!(pistas.os, vec![(OsFamily::MacOs, 3)]);
        assert_eq!(pistas.client.as_deref(), Some("Safari"));
        assert_eq!(pistas.device_type, None);

        // Un iPad en modo escritorio también envía Macintosh: por eso la regla
        // de macOS solo aporta 3 puntos y no debe ganar sola.
        let ipad_escritorio = hints(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        );
        assert_eq!(ipad_escritorio.os, vec![(OsFamily::MacOs, 3)]);
    }

    #[test]
    fn linux_sin_android_es_linux() {
        let ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) \
            Gecko/20100101 Firefox/121.0";
        let pistas = hints(ua);
        assert_eq!(pistas.os, vec![(OsFamily::Linux, 3)]);
        assert_eq!(pistas.client.as_deref(), Some("Firefox"));
    }

    #[test]
    fn android_es_android_y_no_linux() {
        let movil = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
        let pistas = hints(movil);
        assert_eq!(pistas.os, vec![(OsFamily::Android, 4)]);
        assert_eq!(pistas.device_type, Some(DeviceType::Mobile));
        assert_eq!(pistas.client.as_deref(), Some("Chrome"));

        let tablet = "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36";
        let pistas = hints(tablet);
        assert_eq!(pistas.os, vec![(OsFamily::Android, 4)]);
        assert_eq!(pistas.device_type, Some(DeviceType::Tablet));
    }

    #[test]
    fn un_televisor_se_marca_como_tv() {
        // UA de un televisor Samsung con Tizen (contiene "Linux" porque Tizen
        // es Linux, aunque la familia principal del anuncio es la TV).
        let tizen = "Mozilla/5.0 (SMART-TV; Linux; Tizen 6.0) AppleWebKit/537.36 \
            (KHTML, like Gecko) 76.0.3809.146/6.0 TV Safari/537.36";
        let pistas = hints(tizen);
        assert!(pistas.is_tv);
        assert_eq!(pistas.device_type, Some(DeviceType::Tv));
        assert!(pistas.os.contains(&(OsFamily::Linux, 3)));

        // UA de un televisor LG con webOS.
        let webos = "Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36 WebAppManager";
        let pistas = hints(webos);
        assert!(pistas.is_tv);
        assert_eq!(pistas.device_type, Some(DeviceType::Tv));
        assert_eq!(pistas.client.as_deref(), Some("Chrome"));

        let smart_tv = "Mozilla/5.0 (SMART-TV; LGE; NetCast 4.0) AppleWebKit/537.36";
        assert!(hints(smart_tv).is_tv);
    }

    #[test]
    fn sin_marcadores_no_hay_pistas() {
        let pistas = hints("");
        assert_eq!(pistas, UaHints::default());
        assert_eq!(pistas.os, Vec::new());
        assert_eq!(pistas.device_type, None);
        assert_eq!(pistas.client, None);
        assert!(!pistas.is_tv);

        let generico = hints("curl/8.5.0");
        assert!(generico.os.is_empty());
        assert_eq!(generico.client.as_deref(), Some("curl"));
    }

    #[test]
    fn edge_no_se_confunde_con_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
            (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        assert_eq!(hints(ua).client.as_deref(), Some("Edge"));
    }

    #[test]
    fn las_reglas_no_distinguen_mayusculas() {
        let pistas = hints("mozilla/5.0 (windows nt 10.0) ... chrome/120");
        assert_eq!(pistas.os, vec![(OsFamily::Windows, 4)]);
        assert_eq!(pistas.client.as_deref(), Some("Chrome"));
    }

    #[test]
    fn un_ua_largo_o_extraño_no_provoca_panicos() {
        let largo = "Mozilla/5.0 ".to_string() + &"x".repeat(10_000);
        let _ = hints(&largo);
        let _ = hints("\u{0}\u{1} ; ; ; ===");
        let _ = hints("iPhone iPhone iPhone");
    }
}
