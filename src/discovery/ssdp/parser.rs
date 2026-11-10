//! Parser de mensajes SSDP y descarga del XML de descripción UPnP.
//!
//! SSDP viaja sobre HTTPU: una línea inicial ("NOTIFY * HTTP/1.1",
//! "M-SEARCH * HTTP/1.1" o "HTTP/1.1 200 OK") seguida de cabeceras "Clave: valor"
//! y terminadas en CRLF CRLF. El parser es tolerante: acepta saltos LF sueltos,
//! cabeceras en cualquier orden y claves en cualquier combinación de mayúsculas.
//!
//! Decisiones:
//! - El crate ssdp 0.7 del stack no compila en stable (usa #![feature(ip)] y
//!   hyper 0.10), así que el parser de HTTPU es propio.
//! - El XML de descripción UPnP se parsea a mano: solo se necesitan cinco
//!   etiquetas y no merece la pena añadir una dependencia XML.
//! - [fetch_description] solo admite http/https, no sigue redirecciones y corta
//!   la descarga al superar 256 KB, tal y como pide la especificación (sección 9).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::{Error, Result};

/// Tamaño máximo del XML de descripción UPnP (256 KB).
const MAX_DESCRIPCION_BYTES: usize = 256 * 1024;

/// Tipo de mensaje SSDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsdpMessageType {
    /// NOTIFY (anuncio o despedida de un dispositivo).
    Notify,
    /// M-SEARCH (petición de búsqueda).
    Search,
    /// Respuesta a un M-SEARCH.
    Response,
}

/// Mensaje SSDP normalizado.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsdpRecord {
    /// Tipo de mensaje.
    pub message_type: Option<SsdpMessageType>,
    /// IP de origen del datagrama.
    pub source_ip: Option<Ipv4Addr>,
    /// Cabecera ST (search target) de búsquedas y respuestas.
    pub st: Option<String>,
    /// Cabecera NT de los NOTIFY.
    pub nt: Option<String>,
    /// Cabecera NTS de los NOTIFY.
    pub nts: Option<String>,
    /// Cabecera USN.
    pub usn: Option<String>,
    /// Cabecera LOCATION con la URL del XML de descripción.
    pub location: Option<String>,
    /// Cabecera SERVER.
    pub server: Option<String>,
    /// Cabecera MX (segundos de espera) de los M-SEARCH.
    pub mx: Option<u8>,
}

/// Descripción UPnP extraída del XML de LOCATION.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpnpDescription {
    /// Nombre amigable.
    pub friendly_name: Option<String>,
    /// Fabricante.
    pub manufacturer: Option<String>,
    /// Modelo.
    pub model_name: Option<String>,
    /// Tipo de dispositivo (p. ej. "MediaRenderer").
    pub device_type: Option<String>,
    /// UDN del dispositivo.
    pub udn: Option<String>,
}

/// Parsea un datagrama SSDP.
pub fn parse(packet: &[u8]) -> Result<SsdpRecord> {
    let texto = String::from_utf8_lossy(packet);
    parse_con_origen(&texto, None)
}

/// Parsea un datagrama SSDP conociendo la IP de origen.
pub fn parse_from(packet: &[u8], source_ip: Ipv4Addr) -> Result<SsdpRecord> {
    let mut registro = parse(packet)?;
    registro.source_ip = Some(source_ip);
    Ok(registro)
}

/// Descarga y parsea el XML de descripción de un dispositivo UPnP.
pub async fn fetch_description(
    location: reqwest::Url,
    timeout: Duration,
) -> Result<UpnpDescription> {
    let esquema = location.scheme();
    if !(esquema.eq_ignore_ascii_case("http") || esquema.eq_ignore_ascii_case("https")) {
        return Err(Error::Scan(format!(
            "LOCATION con esquema no permitido: {esquema}"
        )));
    }

    let cliente = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| Error::Scan(format!("no se pudo crear el cliente HTTP: {err}")))?;

    let mut respuesta =
        cliente.get(location).send().await.map_err(|err| {
            Error::Scan(format!("no se pudo descargar la descripción UPnP: {err}"))
        })?;
    if !respuesta.status().is_success() {
        return Err(Error::Scan(format!(
            "la descripción UPnP devolvió HTTP {}",
            respuesta.status()
        )));
    }
    if let Some(tamano) = respuesta.content_length() {
        if tamano > MAX_DESCRIPCION_BYTES as u64 {
            return Err(Error::Scan(format!(
                "descripción UPnP demasiado grande: {tamano} bytes"
            )));
        }
    }

    let mut cuerpo: Vec<u8> = Vec::new();
    loop {
        match respuesta.chunk().await {
            Ok(Some(trozo)) => {
                acumular_trozo(&mut cuerpo, &trozo, MAX_DESCRIPCION_BYTES)?;
            }
            Ok(None) => break,
            Err(err) => {
                return Err(Error::Scan(format!(
                    "error leyendo la descripción UPnP: {err}"
                )))
            }
        }
    }

    let texto = String::from_utf8_lossy(&cuerpo);
    if texto.trim().is_empty() {
        return Err(Error::Scan("la descripción UPnP está vacía".to_string()));
    }
    Ok(parse_descripcion(&texto))
}

/// Acumula un trozo del cuerpo respetando el tamaño máximo permitido.
fn acumular_trozo(cuerpo: &mut Vec<u8>, trozo: &[u8], maximo: usize) -> Result<()> {
    if cuerpo.len() + trozo.len() > maximo {
        return Err(Error::Scan(format!(
            "descripción UPnP mayor de {maximo} bytes"
        )));
    }
    cuerpo.extend_from_slice(trozo);
    Ok(())
}

/// Parsea el texto HTTPU y construye el registro normalizado.
fn parse_con_origen(texto: &str, source_ip: Option<Ipv4Addr>) -> Result<SsdpRecord> {
    let mut lineas = texto.split('\n').map(|linea| linea.trim_end_matches('\r'));
    let primera = lineas.next().map(str::trim).unwrap_or("");
    if primera.is_empty() {
        return Err(Error::Scan("mensaje SSDP vacío".to_string()));
    }
    let tipo = tipo_de_mensaje(primera).ok_or_else(|| {
        Error::Scan(format!(
            "mensaje SSDP no reconocido: {}",
            primera.chars().take(80).collect::<String>()
        ))
    })?;

    let mut cabeceras: HashMap<String, String> = HashMap::new();
    for linea in lineas {
        let linea = linea.trim();
        if linea.is_empty() {
            continue;
        }
        if let Some((clave, valor)) = linea.split_once(':') {
            let clave = clave.trim().to_ascii_lowercase();
            if clave.is_empty() {
                continue;
            }
            cabeceras.insert(clave, valor.trim().to_string());
        }
    }

    Ok(SsdpRecord {
        message_type: Some(tipo),
        source_ip,
        st: cabecera(&cabeceras, "st"),
        nt: cabecera(&cabeceras, "nt"),
        nts: cabecera(&cabeceras, "nts"),
        usn: cabecera(&cabeceras, "usn"),
        location: cabecera(&cabeceras, "location"),
        server: cabecera(&cabeceras, "server"),
        mx: cabecera(&cabeceras, "mx").and_then(|valor| valor.parse::<u8>().ok()),
    })
}

/// Identifica el tipo de mensaje a partir de la línea inicial.
fn tipo_de_mensaje(linea: &str) -> Option<SsdpMessageType> {
    let mut partes = linea.split_whitespace();
    let primero = partes.next()?;
    if primero.eq_ignore_ascii_case("NOTIFY") {
        Some(SsdpMessageType::Notify)
    } else if primero.eq_ignore_ascii_case("M-SEARCH") {
        Some(SsdpMessageType::Search)
    } else if primero.to_ascii_uppercase().starts_with("HTTP/") {
        // Respuesta: "HTTP/1.1 200 OK". Solo se aceptan respuestas correctas.
        match partes.next() {
            Some("200") => Some(SsdpMessageType::Response),
            _ => None,
        }
    } else {
        None
    }
}

/// Devuelve el valor no vacío de una cabecera.
fn cabecera(cabeceras: &HashMap<String, String>, clave: &str) -> Option<String> {
    cabeceras
        .get(clave)
        .filter(|valor| !valor.is_empty())
        .cloned()
}

/// Extrae los campos de interés del XML de descripción UPnP.
fn parse_descripcion(xml: &str) -> UpnpDescription {
    UpnpDescription {
        friendly_name: extraer_etiqueta(xml, "friendlyName"),
        manufacturer: extraer_etiqueta(xml, "manufacturer"),
        model_name: extraer_etiqueta(xml, "modelName"),
        device_type: extraer_etiqueta(xml, "deviceType")
            .and_then(|valor| tipo_dispositivo_upnp(&valor)),
        udn: extraer_etiqueta(xml, "UDN"),
    }
}

/// Busca la primera etiqueta con contenido y devuelve su texto desescapado.
fn extraer_etiqueta(xml: &str, etiqueta: &str) -> Option<String> {
    // El XML de UPnP es ASCII en lo que respecta a las etiquetas; pasar todo a
    // minúsculas conserva los índices de byte y simplifica la búsqueda.
    let minusculas = xml.to_ascii_lowercase();
    let apertura = format!("<{}", etiqueta.to_ascii_lowercase());
    let cierre = format!("</{}>", etiqueta.to_ascii_lowercase());
    let inicio = encontrar_apertura(&minusculas, &apertura)?;
    let fin_apertura = minusculas[inicio..].find('>')? + inicio;
    if minusculas[inicio..fin_apertura].trim_end().ends_with('/') {
        // Etiqueta autocerrada, sin contenido.
        return None;
    }
    let arranque = fin_apertura + 1;
    let fin = minusculas[arranque..].find(&cierre)? + arranque;
    let limpio = limpiar_texto_xml(&xml[arranque..fin]);
    if limpio.is_empty() {
        None
    } else {
        Some(limpio)
    }
}

/// Localiza la apertura de una etiqueta sin confundirla con un prefijo.
fn encontrar_apertura(minusculas: &str, apertura: &str) -> Option<usize> {
    let mut desde = 0;
    while let Some(relativo) = minusculas[desde..].find(apertura) {
        let inicio = desde + relativo;
        let siguiente = minusculas.as_bytes().get(inicio + apertura.len()).copied();
        match siguiente {
            Some(b'>') | Some(b'/') | Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') => {
                return Some(inicio)
            }
            _ => desde = inicio + apertura.len(),
        }
    }
    None
}

/// Recorta un texto XML y resuelve CDATA y entidades.
fn limpiar_texto_xml(texto: &str) -> String {
    let mut texto = texto.trim();
    if texto.starts_with("<![CDATA[") && texto.ends_with("]]>") {
        texto = &texto[9..texto.len() - 3];
    }
    desescapar_entidades(texto.trim())
}

/// Desescapa las entidades XML habituales y las referencias numéricas.
fn desescapar_entidades(texto: &str) -> String {
    let mut salida = String::with_capacity(texto.len());
    let mut resto = texto;
    while let Some(posicion) = resto.find('&') {
        salida.push_str(&resto[..posicion]);
        let tras_ampersand = &resto[posicion..];
        match tras_ampersand.find(';') {
            Some(fin) if fin <= 12 => {
                let entidad = &tras_ampersand[1..fin];
                let reemplazo = match entidad {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ => referencia_numerica(entidad),
                };
                match reemplazo {
                    Some(caracter) => {
                        salida.push(caracter);
                        resto = &tras_ampersand[fin + 1..];
                    }
                    None => {
                        salida.push('&');
                        resto = &tras_ampersand[1..];
                    }
                }
            }
            _ => {
                salida.push('&');
                resto = &tras_ampersand[1..];
            }
        }
    }
    salida.push_str(resto);
    salida
}

/// Resuelve una referencia numérica (&#233; o &#xE9;) y devuelve el carácter.
fn referencia_numerica(entidad: &str) -> Option<char> {
    if let Some(hexadecimal) = entidad
        .strip_prefix("#x")
        .or_else(|| entidad.strip_prefix("#X"))
    {
        u32::from_str_radix(hexadecimal, 16)
            .ok()
            .and_then(char::from_u32)
    } else if let Some(decimal) = entidad.strip_prefix('#') {
        decimal.parse::<u32>().ok().and_then(char::from_u32)
    } else {
        None
    }
}

/// Extrae el nombre del tipo de dispositivo de un URN UPnP.
///
/// "urn:schemas-upnp-org:device:MediaRenderer:1" pasa a "MediaRenderer".
fn tipo_dispositivo_upnp(valor: &str) -> Option<String> {
    let valor = valor.trim();
    if valor.is_empty() {
        return None;
    }
    if let Some(posicion) = valor.to_ascii_lowercase().find("device:") {
        let resto = &valor[posicion + "device:".len()..];
        let tipo = resto.split(':').next().unwrap_or(resto).trim();
        if !tipo.is_empty() {
            return Some(tipo.to_string());
        }
    }
    Some(valor.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texto(packet: &str) -> Vec<u8> {
        packet.as_bytes().to_vec()
    }

    #[test]
    fn parsea_un_notify() {
        let paquete = texto(
            "NOTIFY * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             CACHE-CONTROL: max-age=1800\r\n\
             LOCATION: http://192.168.1.10:80/desc.xml\r\n\
             NT: upnp:rootdevice\r\n\
             NTS: ssdp:alive\r\n\
             SERVER: Linux/5.15 UPnP/1.0 MiniUPnPd/2.2.2\r\n\
             USN: uuid:1234::upnp:rootdevice\r\n\r\n",
        );

        let registro = parse(&paquete).expect("NOTIFY válido");

        assert_eq!(registro.message_type, Some(SsdpMessageType::Notify));
        assert_eq!(registro.source_ip, None);
        assert_eq!(registro.nt.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(registro.nts.as_deref(), Some("ssdp:alive"));
        assert_eq!(registro.usn.as_deref(), Some("uuid:1234::upnp:rootdevice"));
        assert_eq!(
            registro.location.as_deref(),
            Some("http://192.168.1.10:80/desc.xml")
        );
        assert!(registro.server.expect("server").contains("MiniUPnPd"));
        assert_eq!(registro.st, None);
        assert_eq!(registro.mx, None);
    }

    #[test]
    fn parsea_un_m_search() {
        let paquete = texto(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 3\r\n\
             ST: ssdp:all\r\n\r\n",
        );

        let registro = parse(&paquete).expect("M-SEARCH válido");

        assert_eq!(registro.message_type, Some(SsdpMessageType::Search));
        assert_eq!(registro.st.as_deref(), Some("ssdp:all"));
        assert_eq!(registro.mx, Some(3));
        assert_eq!(registro.nt, None);
        assert_eq!(registro.location, None);
    }

    #[test]
    fn parsea_una_respuesta_200() {
        let paquete = texto(
            "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=120\r\n\
             EXT:\r\n\
             LOCATION: http://192.168.1.42:49152/description.xml\r\n\
             SERVER: Synology/DSM UPnP/1.0\r\n\
             ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
             USN: uuid:abcd::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n",
        );

        let registro = parse(&paquete).expect("respuesta válida");

        assert_eq!(registro.message_type, Some(SsdpMessageType::Response));
        assert_eq!(
            registro.st.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
        assert_eq!(
            registro.usn.as_deref(),
            Some("uuid:abcd::urn:schemas-upnp-org:device:MediaRenderer:1")
        );
        assert!(registro.location.expect("location").starts_with("http://"));
    }

    #[test]
    fn parse_from_rellena_la_ip_de_origen() {
        let paquete = texto("NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nNTS: ssdp:byebye\r\n\r\n");
        let origen = Ipv4Addr::new(192, 168, 1, 77);

        let registro = parse_from(&paquete, origen).expect("NOTIFY válido");

        assert_eq!(registro.source_ip, Some(origen));
    }

    #[test]
    fn las_cabeceras_son_case_insensitive_y_toleran_lf() {
        let paquete = texto(
            "HTTP/1.1 200 OK\nlocation: http://10.0.0.2/desc.xml\nst: upnp:rootdevice\nmx: 2\n\n",
        );

        let registro = parse(&paquete).expect("respuesta válida");

        assert_eq!(
            registro.location.as_deref(),
            Some("http://10.0.0.2/desc.xml")
        );
        assert_eq!(registro.st.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(registro.mx, Some(2));
    }

    #[test]
    fn rechaza_mensajes_desconocidos_o_vacios() {
        assert!(parse(&[]).is_err());
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_err());
        // Solo se aceptan respuestas 200.
        assert!(parse(b"HTTP/1.1 404 Not Found\r\n\r\n").is_err());
    }

    #[test]
    fn ignora_cabeceras_sin_valor_ni_dos_puntos() {
        let paquete = texto(
            "NOTIFY * HTTP/1.1\r\n\
             CABECERA_SIN_DOS_PUNTOS\r\n\
             NT: \r\n\
             USN: uuid:1\r\n\r\n",
        );

        let registro = parse(&paquete).expect("NOTIFY válido");

        assert_eq!(registro.nt, None);
        assert_eq!(registro.usn.as_deref(), Some("uuid:1"));
    }

    #[test]
    fn parsea_una_descripcion_upnp() {
        let xml = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Salón &amp; Cocina</friendlyName>
    <manufacturer>HP</manufacturer>
    <modelName>LaserJet &quot;Pro&quot;</modelName>
    <UDN>uuid:0d1c2b3a-4e5f-6789-abcd-ef0123456789</UDN>
  </device>
</root>"#;

        let descripcion = parse_descripcion(xml);

        assert_eq!(descripcion.friendly_name.as_deref(), Some("Salón & Cocina"));
        assert_eq!(descripcion.manufacturer.as_deref(), Some("HP"));
        assert_eq!(descripcion.model_name.as_deref(), Some("LaserJet \"Pro\""));
        assert_eq!(descripcion.device_type.as_deref(), Some("MediaRenderer"));
        assert_eq!(
            descripcion.udn.as_deref(),
            Some("uuid:0d1c2b3a-4e5f-6789-abcd-ef0123456789")
        );
    }

    #[test]
    fn un_xml_sin_las_etiquetas_no_rompe() {
        let descripcion =
            parse_descripcion("<root><device><friendlyName></friendlyName></device></root>");

        assert_eq!(descripcion.friendly_name, None);
        assert_eq!(descripcion.manufacturer, None);
        assert_eq!(descripcion.model_name, None);
        assert_eq!(descripcion.device_type, None);
        assert_eq!(descripcion.udn, None);
    }

    #[test]
    fn resuelve_entidades_numericas_y_cdata() {
        assert_eq!(desescapar_entidades("Sal&#243;n"), "Salón");
        assert_eq!(desescapar_entidades("Sal&#xF3;n"), "Salón");
        assert_eq!(desescapar_entidades("a&b"), "a&b");
        assert_eq!(
            limpiar_texto_xml("<![CDATA[valor literal]]>"),
            "valor literal"
        );
    }

    #[test]
    fn extrae_el_tipo_de_dispositivo_del_urn() {
        assert_eq!(
            tipo_dispositivo_upnp("urn:schemas-upnp-org:device:MediaRenderer:1").as_deref(),
            Some("MediaRenderer")
        );
        assert_eq!(
            tipo_dispositivo_upnp("urn:schemas-upnp-org:device:InternetGatewayDevice:1").as_deref(),
            Some("InternetGatewayDevice")
        );
        assert_eq!(tipo_dispositivo_upnp("  ").as_deref(), None);
        assert_eq!(
            tipo_dispositivo_upnp("soloTexto").as_deref(),
            Some("soloTexto")
        );
    }

    #[test]
    fn la_etiqueta_no_se_confunde_con_un_prefijo() {
        let xml = "<friendlyNameX>no</friendlyNameX><friendlyName>sí</friendlyName>";
        assert_eq!(extraer_etiqueta(xml, "friendlyName").as_deref(), Some("sí"));
    }

    #[test]
    fn acota_el_cuerpo_descargado() {
        let mut cuerpo = Vec::new();
        acumular_trozo(&mut cuerpo, &[0u8; 1024], 2048).expect("primer trozo válido");
        assert_eq!(cuerpo.len(), 1024);
        assert!(acumular_trozo(&mut cuerpo, &[0u8; 2000], 2048).is_err());
        // Al rechazar el trozo el cuerpo acumulado no se modifica.
        assert_eq!(cuerpo.len(), 1024);
    }

    #[tokio::test]
    async fn fetch_description_rechaza_esquemas_no_http() {
        let location = reqwest::Url::parse("file:///tmp/descripcion.xml").expect("URL válida");
        let error = fetch_description(location, Duration::from_millis(100))
            .await
            .expect_err("file:// no está permitido");
        assert!(error.to_string().contains("esquema"));
    }
}
