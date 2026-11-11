//! Modelo de equipo desde los TXT de mDNS y la descripción UPnP (§7.12).
//!
//! Las claves de TXT que publican los equipos (Apple, Google Cast e impresoras
//! IPP) se leen sin distinguir mayúsculas y se sanean antes de exponerlas. Las
//! reglas de tipo y de SO por modelo son las de §7.12 y van antes que las de
//! hostname del clasificador de F2.

use crate::classify::{DeviceType, OsFamily};
use crate::discovery::ssdp::UpnpDescription;

/// Claves de TXT que pueden anunciar el modelo, en orden de preferencia.
const CLAVES_MODELO: [&str; 5] = ["model", "am", "md", "ty", "rpMd"];

/// Puntos que aporta un modelo Apple reconocido como pista de SO (§7.12).
const PUNTOS_MODELO_SO: u8 = 5;

/// Pista de modelo anunciada por mDNS o UPnP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModelHint {
    /// Modelo anunciado, truncado a 64 caracteres.
    pub model: Option<String>,
    /// Fabricante, si se conoce.
    pub vendor: Option<String>,
    /// Pistas de SO con sus puntos.
    pub os: Vec<(OsFamily, u8)>,
    /// Pista de tipo de equipo.
    pub device_type: Option<DeviceType>,
}

/// Extrae el modelo de los TXT de un servicio mDNS.
///
/// Claves: model, am, md, ty y rpMd. La primera clave con valor utilizable (por
/// ese orden) da el modelo; después se aplican las reglas por prefijo de §7.12
/// (Mac…, iPhone, iPad, AppleTV, AudioAccessory, Chromecast) y la regla de
/// impresora por ty. Devuelve None si los TXT no aportan nada.
pub fn from_mdns_txt(service: &str, txt: &[(String, String)]) -> Option<ModelHint> {
    let mut pista = ModelHint::default();
    for clave in CLAVES_MODELO {
        if pista.model.is_none() {
            pista.model = valor_txt(txt, clave);
        }
    }
    if let Some(modelo) = pista.model.clone() {
        aplicar_modelo(&modelo, &mut pista);
    }

    // ty es el modelo legible que anuncian las impresoras (IPP/LPD); solo se
    // usa como tipo cuando el anuncio es de impresión o cuando es el modelo
    // elegido (impresora sin clave model).
    if pista.device_type.is_none() {
        if let Some(tipo) = valor_txt(txt, "ty") {
            let servicio_impresion = es_servicio_de_impresion(service);
            let modelo_es_ty = pista.model.as_deref() == Some(tipo.as_str());
            if servicio_impresion || modelo_es_ty {
                pista.device_type = Some(DeviceType::Printer);
            }
        }
    }

    if pista.model.is_none()
        && pista.vendor.is_none()
        && pista.os.is_empty()
        && pista.device_type.is_none()
    {
        None
    } else {
        Some(pista)
    }
}

/// Extrae el modelo de la descripción UPnP de F2.
///
/// manufacturer alimenta el fabricante y modelName el modelo; las reglas de SO
/// y tipo por prefijo de modelo son las mismas que en mDNS.
pub fn from_upnp(desc: &UpnpDescription) -> Option<ModelHint> {
    let mut pista = ModelHint {
        model: desc.model_name.as_deref().and_then(sanitize_model),
        vendor: desc.manufacturer.as_deref().and_then(sanitize_model),
        ..ModelHint::default()
    };
    if let Some(modelo) = pista.model.clone() {
        aplicar_modelo(&modelo, &mut pista);
    }
    if pista.model.is_none()
        && pista.vendor.is_none()
        && pista.os.is_empty()
        && pista.device_type.is_none()
    {
        None
    } else {
        Some(pista)
    }
}

/// Nombre amigable de Google Cast (`fn`) de un servicio mDNS.
///
/// §7.12 sitúa este nombre al nivel de mDNS en la precedencia de hostname de
/// F2 (el nombre DHCP capturado va al nivel de «DHCP lease»). Se expone aquí
/// porque llega en los mismos TXT que el modelo y necesita el mismo saneado.
pub fn cast_friendly_name(txt: &[(String, String)]) -> Option<String> {
    valor_txt(txt, "fn")
}

/// Sanea un modelo anunciado por la red (solo imprimibles, máx. 64).
pub fn sanitize_model(value: &str) -> Option<String> {
    let limpio: String = value.chars().filter(|c| !c.is_control()).take(64).collect();
    let limpio = limpio.trim().to_string();
    if limpio.is_empty() {
        None
    } else {
        Some(limpio)
    }
}

/// Busca el valor de una clave TXT sin distinguir mayúsculas y lo sanea.
fn valor_txt(txt: &[(String, String)], clave: &str) -> Option<String> {
    txt.iter()
        .find(|(nombre, _)| nombre.trim().eq_ignore_ascii_case(clave))
        .and_then(|(_, valor)| sanitize_model(valor))
}

/// Indica si el tipo de servicio mDNS es de impresión.
fn es_servicio_de_impresion(service: &str) -> bool {
    let servicio = service.to_ascii_lowercase();
    servicio.contains("_ipp")
        || servicio.contains("_printer")
        || servicio.contains("_pdl")
        || servicio.contains("_lpd")
}

/// Aplica las reglas de tipo, SO y fabricante por prefijo de modelo (§7.12).
///
/// Los identificadores internos de Apple (MacBookPro18,3, iPhone14,2,
/// AppleTV6,2, AudioAccessory5,1) y el nombre de modelo de Google Cast
/// (md=Chromecast…) son las pistas que fija el informe.
fn aplicar_modelo(modelo: &str, pista: &mut ModelHint) {
    let minusculas = modelo.to_ascii_lowercase();

    if minusculas.starts_with("macbook")
        || minusculas.starts_with("imac")
        || minusculas.starts_with("macmini")
        || minusculas.starts_with("macpro")
        || minusculas.starts_with("mac1")
    {
        pista.device_type = Some(DeviceType::Pc);
        pista.os.push((OsFamily::MacOs, PUNTOS_MODELO_SO));
        pista.vendor.get_or_insert_with(|| "Apple".to_string());
    } else if minusculas.starts_with("iphone") {
        pista.device_type = Some(DeviceType::Mobile);
        pista.os.push((OsFamily::Ios, PUNTOS_MODELO_SO));
        pista.vendor.get_or_insert_with(|| "Apple".to_string());
    } else if minusculas.starts_with("ipad") {
        pista.device_type = Some(DeviceType::Tablet);
        pista.os.push((OsFamily::Ios, PUNTOS_MODELO_SO));
        pista.vendor.get_or_insert_with(|| "Apple".to_string());
    } else if minusculas.starts_with("appletv") || minusculas.contains("apple tv") {
        pista.device_type = Some(DeviceType::Streaming);
        pista.vendor.get_or_insert_with(|| "Apple".to_string());
    } else if minusculas.starts_with("audioaccessory") {
        pista.device_type = Some(DeviceType::Iot);
        pista.vendor.get_or_insert_with(|| "Apple".to_string());
    } else if minusculas.contains("chromecast") {
        pista.device_type = Some(DeviceType::Streaming);
        pista.vendor.get_or_insert_with(|| "Google".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pares TXT a partir de literales, como los entrega el parser de mDNS.
    fn txt(pares: &[(&str, &str)]) -> Vec<(String, String)> {
        pares
            .iter()
            .map(|(clave, valor)| ((*clave).to_string(), (*valor).to_string()))
            .collect()
    }

    /// Descripción UPnP mínima para las pruebas.
    fn upnp(manufacturer: Option<&str>, model_name: Option<&str>) -> UpnpDescription {
        UpnpDescription {
            friendly_name: None,
            manufacturer: manufacturer.map(str::to_string),
            model_name: model_name.map(str::to_string),
            device_type: None,
            udn: None,
        }
    }

    #[test]
    fn un_macbook_anunciado_por_mdns_es_macos_y_pc() {
        // Caso del criterio de aceptación del checklist: modelo MacBookPro… →
        // os_family = macos y os_source = model (5 puntos, §7.12).
        let pista = from_mdns_txt("_device-info._tcp", &txt(&[("model", "MacBookPro18,3")]))
            .expect("modelo anunciado");
        assert_eq!(pista.model.as_deref(), Some("MacBookPro18,3"));
        assert_eq!(pista.device_type, Some(DeviceType::Pc));
        assert_eq!(pista.os, vec![(OsFamily::MacOs, 5)]);
        assert_eq!(pista.vendor.as_deref(), Some("Apple"));
    }

    #[test]
    fn iphone_e_ipad_se_distinguen_por_el_modelo() {
        let iphone = from_mdns_txt("_device-info._tcp", &txt(&[("model", "iPhone14,2")]))
            .expect("iPhone anunciado");
        assert_eq!(iphone.device_type, Some(DeviceType::Mobile));
        assert_eq!(iphone.os, vec![(OsFamily::Ios, 5)]);

        let ipad = from_mdns_txt("_device-info._tcp", &txt(&[("model", "iPad13,4")]))
            .expect("iPad anunciado");
        assert_eq!(ipad.device_type, Some(DeviceType::Tablet));
        assert_eq!(ipad.os, vec![(OsFamily::Ios, 5)]);
    }

    #[test]
    fn appletv_y_audioaccessory_llegan_por_txt() {
        let apple_tv =
            from_mdns_txt("_airplay._tcp", &txt(&[("model", "AppleTV6,2")])).expect("Apple TV");
        assert_eq!(apple_tv.device_type, Some(DeviceType::Streaming));
        assert_eq!(apple_tv.vendor.as_deref(), Some("Apple"));
        assert!(apple_tv.os.is_empty(), "tvOS no está en la taxonomía");

        let homepod = from_mdns_txt("_airplay._tcp", &txt(&[("model", "AudioAccessory5,1")]))
            .expect("HomePod");
        assert_eq!(homepod.device_type, Some(DeviceType::Iot));
    }

    #[test]
    fn un_chromecast_por_md_es_streaming() {
        // TXT real de _googlecast._tcp: md lleva el modelo legible.
        let chromecast = from_mdns_txt(
            "_googlecast._tcp",
            &txt(&[
                ("id", "8f2f2f0a1b2c3d4e5f60718293a4b5c6"),
                ("md", "Chromecast Ultra"),
                ("fn", "Salón"),
            ]),
        )
        .expect("Chromecast anunciado");
        assert_eq!(chromecast.model.as_deref(), Some("Chromecast Ultra"));
        assert_eq!(chromecast.device_type, Some(DeviceType::Streaming));
        assert_eq!(chromecast.vendor.as_deref(), Some("Google"));
    }

    #[test]
    fn una_impresora_ipp_por_ty_es_printer() {
        // TXT típico de _ipp._tcp (el ty es el modelo legible de la impresora).
        let impresora = from_mdns_txt(
            "_ipp._tcp",
            &txt(&[("rp", "print"), ("ty", "HP LaserJet 400")]),
        )
        .expect("impresora anunciada");
        assert_eq!(impresora.model.as_deref(), Some("HP LaserJet 400"));
        assert_eq!(impresora.device_type, Some(DeviceType::Printer));

        // Sin clave ty no se inventa un modelo.
        assert_eq!(from_mdns_txt("_ipp._tcp", &txt(&[("rp", "print")])), None);
    }

    #[test]
    fn las_claves_se_leen_sin_distinguir_mayusculas() {
        let pista = from_mdns_txt("_device-info._tcp", &txt(&[("Model", "iMac21,1")]))
            .expect("iMac anunciado");
        assert_eq!(pista.model.as_deref(), Some("iMac21,1"));
        assert_eq!(pista.device_type, Some(DeviceType::Pc));
    }

    #[test]
    fn am_y_rpmd_sirven_de_respaldo_del_modelo() {
        let am = from_mdns_txt("_raop._tcp", &txt(&[("am", "AppleTV6,2")])).expect("modelo por am");
        assert_eq!(am.model.as_deref(), Some("AppleTV6,2"));

        let rpmd = from_mdns_txt("_airplay._tcp", &txt(&[("rpMd", "Macmini9,1")]))
            .expect("modelo por rpMd");
        assert_eq!(rpmd.model.as_deref(), Some("Macmini9,1"));
        assert_eq!(rpmd.device_type, Some(DeviceType::Pc));

        // model tiene prioridad sobre las claves de respaldo.
        let ambos = from_mdns_txt(
            "_airplay._tcp",
            &txt(&[("am", "AppleTV6,2"), ("model", "AudioAccessory5,1")]),
        )
        .expect("modelo por model");
        assert_eq!(ambos.model.as_deref(), Some("AudioAccessory5,1"));
    }

    #[test]
    fn sin_pistas_utiles_devuelve_none() {
        assert_eq!(from_mdns_txt("_http._tcp", &[]), None);
        assert_eq!(
            from_mdns_txt("_googlecast._tcp", &txt(&[("fn", "Salón"), ("ve", "05")])),
            None
        );
        assert_eq!(from_mdns_txt("_ipp._tcp", &txt(&[("rp", "print")])), None);
    }

    #[test]
    fn el_modelo_se_sanea_y_se_trunca() {
        let largos = "m".repeat(100);
        let pista = from_mdns_txt("_device-info._tcp", &txt(&[("model", largos.as_str())]))
            .expect("modelo largo");
        assert_eq!(pista.model.as_deref().map(str::len), Some(64));

        // Los caracteres de control se descartan y los espacios sobrantes se
        // recortan; si no queda nada, la clave se ignora.
        let sucio = from_mdns_txt("_device-info._tcp", &txt(&[("model", "  Mac\u{1}Book ")]))
            .expect("modelo saneado");
        assert_eq!(sucio.model.as_deref(), Some("MacBook"));
        assert_eq!(
            from_mdns_txt("_device-info._tcp", &txt(&[("model", "\u{1}\u{2}")])),
            None
        );
    }

    #[test]
    fn upnp_aporta_fabricante_y_modelo() {
        let pista =
            from_upnp(&upnp(Some("Apple Inc."), Some("MacBookPro18,3"))).expect("descripción UPnP");
        assert_eq!(pista.vendor.as_deref(), Some("Apple Inc."));
        assert_eq!(pista.model.as_deref(), Some("MacBookPro18,3"));
        assert_eq!(pista.device_type, Some(DeviceType::Pc));
        assert_eq!(pista.os, vec![(OsFamily::MacOs, 5)]);
    }

    #[test]
    fn upnp_solo_con_fabricante_o_solo_con_modelo() {
        let solo_fabricante = from_upnp(&upnp(Some("Synology"), None)).expect("fabricante");
        assert_eq!(solo_fabricante.vendor.as_deref(), Some("Synology"));
        assert_eq!(solo_fabricante.model, None);

        let solo_modelo = from_upnp(&upnp(None, Some("Apple TV"))).expect("modelo");
        assert_eq!(solo_modelo.model.as_deref(), Some("Apple TV"));
        assert_eq!(solo_modelo.device_type, Some(DeviceType::Streaming));

        assert_eq!(from_upnp(&upnp(None, None)), None);
        assert_eq!(from_upnp(&upnp(Some("  "), Some(""))), None);
    }

    #[test]
    fn upnp_conserva_el_fabricante_anunciado() {
        // Si el fabricante viene en la descripción, no se sustituye por el
        // inferido del modelo.
        let pista =
            from_upnp(&upnp(Some("Apple Inc."), Some("iPhone14,2"))).expect("iPhone por UPnP");
        assert_eq!(pista.vendor.as_deref(), Some("Apple Inc."));
        assert_eq!(pista.device_type, Some(DeviceType::Mobile));
    }

    #[test]
    fn el_nombre_amigable_de_cast_sale_del_txt_fn() {
        // TXT real de _googlecast._tcp: fn es el nombre visible del equipo.
        let nombre = cast_friendly_name(&txt(&[
            ("id", "8f2f2f0a1b2c3d4e5f60718293a4b5c6"),
            ("fn", "Salón TV"),
        ]));
        assert_eq!(nombre.as_deref(), Some("Salón TV"));

        // La clave se lee sin distinguir mayúsculas y se sanea.
        assert_eq!(
            cast_friendly_name(&txt(&[("FN", "  Cocina\u{1} ")])).as_deref(),
            Some("Cocina")
        );
        assert_eq!(cast_friendly_name(&txt(&[("fn", "\u{1}")])), None);
        assert_eq!(cast_friendly_name(&txt(&[("md", "Chromecast")])), None);
    }
}
