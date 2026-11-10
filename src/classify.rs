//! Clasificación de dispositivos (device_type), servicios y familias de SO.
//!
//! Este módulo es puro (sin E/S) para poder probarlo con fixtures. La taxonomía de
//! la Fase 2 amplía la de Fase 1 a doce valores y aplica una prioridad fija; el
//! override manual vive en DEVICES.device_type_manual y manda siempre sobre el
//! resultado automático (lo aplica la capa que lo consume, no este módulo).

/// Tipo de dispositivo de la taxonomía extendida de Fase 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceType {
    /// Router, punto de acceso o puerta de enlace.
    Gateway,
    /// Ordenador de escritorio o portátil.
    Pc,
    /// Servidor.
    Server,
    /// Almacenamiento en red.
    Nas,
    /// Teléfono móvil.
    Mobile,
    /// Tableta.
    Tablet,
    /// Televisor.
    Tv,
    /// Dispositivo de streaming (Chromecast, Apple TV...).
    Streaming,
    /// Dispositivo del internet de las cosas.
    Iot,
    /// Impresora.
    Printer,
    /// Cámara IP.
    Camera,
    /// Desconocido.
    Unknown,
}

impl DeviceType {
    /// Todos los valores de la taxonomía, en orden de prioridad descendente.
    pub const ALL: [Self; 12] = [
        Self::Gateway,
        Self::Printer,
        Self::Camera,
        Self::Tv,
        Self::Streaming,
        Self::Nas,
        Self::Mobile,
        Self::Tablet,
        Self::Server,
        Self::Pc,
        Self::Iot,
        Self::Unknown,
    ];

    /// Representación persistida en SQLite.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Pc => "pc",
            Self::Server => "server",
            Self::Nas => "nas",
            Self::Mobile => "mobile",
            Self::Tablet => "tablet",
            Self::Tv => "tv",
            Self::Streaming => "streaming",
            Self::Iot => "iot",
            Self::Printer => "printer",
            Self::Camera => "camera",
            Self::Unknown => "unknown",
        }
    }

    /// Reconstruye el tipo desde su representación persistida.
    pub fn from_str(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tipo| tipo.as_str() == value)
    }

    /// Etiqueta visible en la interfaz.
    pub fn label(self) -> &'static str {
        match self {
            Self::Gateway => "Gateway",
            Self::Pc => "PC",
            Self::Server => "Servidor",
            Self::Nas => "NAS",
            Self::Mobile => "Móvil",
            Self::Tablet => "Tablet",
            Self::Tv => "TV",
            Self::Streaming => "Streaming",
            Self::Iot => "IoT",
            Self::Printer => "Impresora",
            Self::Camera => "Cámara",
            Self::Unknown => "Desconocido",
        }
    }
}

/// Familia de sistema operativo estimada por fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OsFamily {
    /// Linux.
    Linux,
    /// Windows.
    Windows,
    /// macOS.
    MacOs,
    /// iOS.
    Ios,
    /// Android.
    Android,
    /// Sistema embebido o IoT.
    Iot,
}

impl OsFamily {
    /// Todas las familias.
    pub const ALL: [Self; 6] = [
        Self::Linux,
        Self::Windows,
        Self::MacOs,
        Self::Ios,
        Self::Android,
        Self::Iot,
    ];

    /// Representación persistida.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Iot => "iot",
        }
    }

    /// Reconstruye la familia desde su representación persistida.
    ///
    /// Forma parte de la API de la taxonomía exigida por el checklist; la
    /// usará la persistencia en fases posteriores, igual que DeviceType.
    #[allow(dead_code)]
    pub fn from_str(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|familia| familia.as_str() == value)
    }
}

/// Servicio identificado por puerto y/o banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceKind {
    /// HTTP.
    Http,
    /// HTTPS.
    Https,
    /// SSH.
    Ssh,
    /// SMB/CIFS.
    Smb,
    /// UPnP.
    Upnp,
    /// Impresión (IPP, LPD, JetDirect).
    Printer,
    /// RTSP.
    Rtsp,
    /// MQTT.
    Mqtt,
    /// Escritorio remoto de Windows.
    Rdp,
    /// DNS.
    Dns,
    /// mDNS.
    Mdns,
    /// Plex.
    Plex,
    /// ADB.
    Adb,
    /// Telnet.
    Telnet,
    /// FTP.
    Ftp,
    /// NFS.
    Nfs,
}

impl ServiceKind {
    /// Todos los servicios identificables.
    ///
    /// Lista completa de la taxonomía exigida por el checklist; hoy se
    /// clasifica por puerto y banner, pero se usará en fases posteriores
    /// (filtros y pantalla de detalle entre otros).
    #[allow(dead_code)]
    pub const ALL: [Self; 16] = [
        Self::Http,
        Self::Https,
        Self::Ssh,
        Self::Smb,
        Self::Upnp,
        Self::Printer,
        Self::Rtsp,
        Self::Mqtt,
        Self::Rdp,
        Self::Dns,
        Self::Mdns,
        Self::Plex,
        Self::Adb,
        Self::Telnet,
        Self::Ftp,
        Self::Nfs,
    ];

    /// Representación persistida en DEVICE_SERVICES.service.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Ssh => "ssh",
            Self::Smb => "smb",
            Self::Upnp => "upnp",
            Self::Printer => "printer",
            Self::Rtsp => "rtsp",
            Self::Mqtt => "mqtt",
            Self::Rdp => "rdp",
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Plex => "plex",
            Self::Adb => "adb",
            Self::Telnet => "telnet",
            Self::Ftp => "ftp",
            Self::Nfs => "nfs",
        }
    }

    /// Reconstruye el servicio desde su representación persistida.
    ///
    /// Forma parte de la API de la taxonomía exigida por el checklist; la
    /// usará la persistencia en fases posteriores.
    #[allow(dead_code)]
    pub fn from_str(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|servicio| servicio.as_str() == value)
    }
}

/// Contexto del que dispone el clasificador automático.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceCtx {
    /// Es la puerta de enlace por defecto de su interfaz.
    pub is_gateway: bool,
    /// Fabricante según OUI.
    pub vendor: Option<String>,
    /// Hostname resuelto (mDNS, NetBIOS, DHCP o DNS inverso).
    pub hostname: Option<String>,
    /// Familia de SO estimada, si se conoce.
    pub os_family: Option<OsFamily>,
    /// Servicios detectados por puerto/banner.
    pub services: Vec<ServiceKind>,
    /// Tipos de servicio mDNS anunciados (p. ej. "_ipp._tcp").
    pub mdns_services: Vec<String>,
    /// Tipos de dispositivo UPnP (p. ej. "MediaRenderer").
    pub upnp_types: Vec<String>,
    /// El llamador ha deducido que es un televisor.
    pub is_tv: bool,
}

impl DeviceCtx {
    /// Indica si se ha detectado el servicio indicado.
    pub fn has_service(&self, kind: ServiceKind) -> bool {
        self.services.contains(&kind)
    }

    /// Indica si se ha anunciado un servicio mDNS que contiene el texto dado.
    pub fn has_mdns(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        self.mdns_services
            .iter()
            .any(|servicio| servicio.to_ascii_lowercase().contains(&needle))
    }
}

/// Fabricantes (subcadenas, sin distinguir mayúsculas) asociados a impresoras.
///
/// La comparación se hace por subcadena sobre el nombre del fabricante que
/// devuelve el OUI, porque cada base de datos escribe el nombre de forma
/// distinta ("HP", "Hewlett Packard", "Canon Inc.", ...).
pub const PRINTER_VENDORS: &[&str] = &[
    "hp", "canon", "epson", "brother", "xerox", "lexmark", "ricoh", "kyocera",
];

/// Fabricantes asociados a sistemas de almacenamiento en red (NAS).
pub const NAS_VENDORS: &[&str] = &[
    "synology",
    "qnap",
    "western digital",
    "asustor",
    "buffalo",
    "readynas",
];

/// Fabricantes asociados a dispositivos del internet de las cosas (IoT).
/// Fabricantes que se consideran de móvil o tablet cuando no hay otra evidencia.
///
/// Es una heurística conservadora; el override manual con la tecla t permite
/// corregirla.
pub const MOBILE_VENDORS: &[&str] = &[
    "honor", "xiaomi", "redmi", "oneplus", "oppo", "vivo", "realme", "motorola", "nokia", "tecno",
    "infinix", "nothing",
];

pub const IOT_VENDORS: &[&str] = &[
    "espressif",
    "tuya",
    "shelly",
    "sonoff",
    "philips hue",
    "nest",
    "ring",
    "broadlink",
];

/// Puertos TCP con un servicio inequívoco, independientemente del banner.
///
/// Cubre los puertos TOP por defecto de la configuración ([scan].top_ports)
/// y los puertos estándar de los servicios que necesita el clasificador
/// (RTSP 554, NFS 2049, UPnP 1900) aunque el usuario no los tenga configurados.
const PORT_SERVICES: &[(u16, ServiceKind)] = &[
    (21, ServiceKind::Ftp),
    (22, ServiceKind::Ssh),
    (23, ServiceKind::Telnet),
    (53, ServiceKind::Dns),
    (80, ServiceKind::Http),
    (139, ServiceKind::Smb),
    (443, ServiceKind::Https),
    (445, ServiceKind::Smb),
    (515, ServiceKind::Printer),
    (554, ServiceKind::Rtsp),
    (631, ServiceKind::Printer),
    (1883, ServiceKind::Mqtt),
    (1900, ServiceKind::Upnp),
    (2049, ServiceKind::Nfs),
    (3389, ServiceKind::Rdp),
    (5000, ServiceKind::Upnp),
    (5353, ServiceKind::Mdns),
    (5555, ServiceKind::Adb),
    (8008, ServiceKind::Http),
    (8080, ServiceKind::Http),
    (8443, ServiceKind::Https),
    (9100, ServiceKind::Printer),
    (32400, ServiceKind::Plex),
];

/// Indica si el fabricante contiene alguna de las subcadenas indicadas.
fn vendor_matches(vendor: Option<&str>, needles: &[&str]) -> bool {
    let Some(vendor) = vendor else {
        return false;
    };
    let vendor = vendor.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| vendor.contains(&needle.to_ascii_lowercase()))
}

/// Indica si algún tipo UPnP anunciado contiene el texto dado.
fn has_upnp(ctx: &DeviceCtx, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    ctx.upnp_types
        .iter()
        .any(|tipo| tipo.to_ascii_lowercase().contains(&needle))
}

/// Clasifica un dispositivo aplicando la prioridad de la especificación:
/// gateway > impresora > cámara > TV/streaming > NAS > móvil/tablet >
/// servidor/PC > IoT > desconocido.
pub fn device_type(ctx: &DeviceCtx) -> DeviceType {
    // 1) Puerta de enlace. Además de la puerta de enlace por defecto, un
    //    dispositivo que se anuncia como InternetGatewayDevice por UPnP es un
    //    router aunque no sea la puerta de enlace de nuestra interfaz.
    if ctx.is_gateway || has_upnp(ctx, "internetgatewaydevice") {
        return DeviceType::Gateway;
    }

    // 2) Impresora: servicio de impresión o fabricante de impresoras.
    if ctx.has_service(ServiceKind::Printer)
        || vendor_matches(ctx.vendor.as_deref(), PRINTER_VENDORS)
    {
        return DeviceType::Printer;
    }

    // 3) Cámara IP: RTSP, ONVIF (mDNS/UPnP) o tipo UPnP de cámara.
    if ctx.has_service(ServiceKind::Rtsp)
        || ctx.has_mdns("_rtsp")
        || ctx.has_mdns("_onvif")
        || has_upnp(ctx, "onvif")
        || has_upnp(ctx, "camera")
    {
        return DeviceType::Camera;
    }

    // 4) TV y streaming: MediaRenderer por UPnP o Cast/AirPlay por mDNS.
    if has_upnp(ctx, "mediarenderer") || ctx.has_mdns("_googlecast") || ctx.has_mdns("_airplay") {
        // La especificación distingue TV de dispositivo de streaming con la
        // pista que aporta el llamador (nombre, OUI...); si no la hay, se
        // asume streaming, que es el caso más habitual en estos anuncios.
        return if ctx.is_tv {
            DeviceType::Tv
        } else {
            DeviceType::Streaming
        };
    }

    // 5) NAS: fabricante de NAS o SMB y NFS a la vez.
    if vendor_matches(ctx.vendor.as_deref(), NAS_VENDORS)
        || (ctx.has_service(ServiceKind::Smb) && ctx.has_service(ServiceKind::Nfs))
    {
        return DeviceType::Nas;
    }

    // 6) Móviles y tablets por hostname. Se comprueba primero la tablet para
    //    que "iPad" no se confunda con un móvil por el prefijo "ip".
    if let Some(hostname) = ctx.hostname.as_deref() {
        let hostname = hostname.to_ascii_lowercase();
        if hostname.contains("ipad") || hostname.contains("tablet") {
            return DeviceType::Tablet;
        }
        if hostname.contains("iphone") || hostname.contains("ipod") || hostname.contains("android")
        {
            return DeviceType::Mobile;
        }
    }

    // 6b) Fabricante de móvil o tablet cuando el hostname no lo revela. Es una
    //     heurística conservadora (Honor, Xiaomi, OnePlus...); el override
    //     manual permite corregirla.
    if vendor_matches(ctx.vendor.as_deref(), MOBILE_VENDORS) {
        return DeviceType::Mobile;
    }

    // 7) Servidor o PC: SSH, o HTTP junto a un SO de escritorio conocido.
    let tiene_ssh = ctx.has_service(ServiceKind::Ssh);
    let tiene_http = ctx.has_service(ServiceKind::Http);
    let os_conocido = matches!(ctx.os_family, Some(OsFamily::Linux | OsFamily::Windows));
    if tiene_ssh || (tiene_http && os_conocido) {
        return if tiene_ssh && tiene_http {
            DeviceType::Server
        } else {
            DeviceType::Pc
        };
    }

    // 8) IoT por fabricante.
    if vendor_matches(ctx.vendor.as_deref(), IOT_VENDORS) {
        return DeviceType::Iot;
    }

    DeviceType::Unknown
}

/// Identifica el servicio de un puerto abierto, usando el banner si lo hay.
///
/// El banner solo se usa para protocolos que se anuncian por sí mismos (SSH,
/// RTSP, FTP) y para afinar puertos no estándar (HTTP, UPnP, Plex); el puerto
/// conocido manda en el resto para no etiquetar mal servicios HTTP sobre
/// puertos con significado propio (Plex en 32400, IPP en 631...).
pub fn service(port: u16, banner: Option<&str>) -> Option<ServiceKind> {
    if let Some(banner) = banner {
        let texto = banner.trim();
        let minusculas = texto.to_ascii_lowercase();
        if texto.starts_with("SSH-") {
            return Some(ServiceKind::Ssh);
        }
        if texto.starts_with("RTSP/") {
            return Some(ServiceKind::Rtsp);
        }
        // El FTP saluda con el código 220 y menciona el servicio en el banner.
        if texto.starts_with("220") && minusculas.contains("ftp") {
            return Some(ServiceKind::Ftp);
        }
    }

    if let Some((_, servicio)) = PORT_SERVICES.iter().find(|(puerto, _)| *puerto == port) {
        return Some(*servicio);
    }

    // Puertos no estándar: pistas del banner, de la más específica a la más
    // genérica (UPnP y Plex anuncian "Server:" en su cabecera HTTP).
    let banner = banner?;
    let minusculas = banner.to_ascii_lowercase();
    if minusculas.contains("upnp/") || minusculas.contains("internetgatewaydevice") {
        return Some(ServiceKind::Upnp);
    }
    if minusculas.contains("plex") {
        return Some(ServiceKind::Plex);
    }
    if minusculas.contains("http/") || minusculas.contains("server:") {
        return Some(ServiceKind::Http);
    }
    None
}

/// Grupo de la vista agrupada por categoría.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceGroup {
    /// Infraestructura (gateway y NAS).
    Infrastructure,
    /// Puestos y servidores.
    Workstations,
    /// Móviles y tablets.
    Mobile,
    /// TV y streaming.
    TvStreaming,
    /// Impresoras.
    Printers,
    /// Cámaras.
    Cameras,
    /// IoT.
    Iot,
    /// Desconocidos.
    Unknown,
}

impl DeviceGroup {
    /// Todos los grupos, en el orden en que se muestran.
    pub const ALL: [Self; 8] = [
        Self::Infrastructure,
        Self::Workstations,
        Self::Mobile,
        Self::TvStreaming,
        Self::Printers,
        Self::Cameras,
        Self::Iot,
        Self::Unknown,
    ];

    /// Cabecera visible del grupo.
    pub fn label(self) -> &'static str {
        match self {
            Self::Infrastructure => "Infraestructura",
            Self::Workstations => "Puestos y servidores",
            Self::Mobile => "Móviles y tablets",
            Self::TvStreaming => "TV y streaming",
            Self::Printers => "Impresoras",
            Self::Cameras => "Cámaras",
            Self::Iot => "IoT",
            Self::Unknown => "Desconocidos",
        }
    }

    /// Indica si un tipo de dispositivo pertenece a este grupo.
    pub fn accepts(self, tipo: DeviceType) -> bool {
        matches!(
            (self, tipo),
            (Self::Infrastructure, DeviceType::Gateway | DeviceType::Nas)
                | (Self::Workstations, DeviceType::Pc | DeviceType::Server)
                | (Self::Mobile, DeviceType::Mobile | DeviceType::Tablet)
                | (Self::TvStreaming, DeviceType::Tv | DeviceType::Streaming)
                | (Self::Printers, DeviceType::Printer)
                | (Self::Cameras, DeviceType::Camera)
                | (Self::Iot, DeviceType::Iot)
                | (Self::Unknown, DeviceType::Unknown)
        )
    }
}

/// Grupo al que pertenece un tipo de dispositivo.
pub fn group_for(tipo: DeviceType) -> DeviceGroup {
    DeviceGroup::ALL
        .into_iter()
        .find(|grupo| grupo.accepts(tipo))
        .unwrap_or(DeviceGroup::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomia_tiene_doce_tipos_unicos() {
        assert_eq!(DeviceType::ALL.len(), 12);
        let mut valores: Vec<&str> = DeviceType::ALL.iter().map(|tipo| tipo.as_str()).collect();
        valores.sort_unstable();
        valores.dedup();
        assert_eq!(valores.len(), 12);
        for tipo in DeviceType::ALL {
            assert_eq!(DeviceType::from_str(tipo.as_str()), Some(tipo));
        }
        assert_eq!(DeviceType::from_str("otro"), None);
    }

    #[test]
    fn familias_de_so_son_estables() {
        for familia in OsFamily::ALL {
            assert_eq!(OsFamily::from_str(familia.as_str()), Some(familia));
        }
        assert_eq!(OsFamily::ALL.len(), 6);
    }

    #[test]
    fn grupos_cubren_todos_los_tipos() {
        for tipo in DeviceType::ALL {
            let grupo = group_for(tipo);
            assert!(grupo.accepts(tipo));
        }
        assert_eq!(group_for(DeviceType::Nas), DeviceGroup::Infrastructure);
        assert_eq!(group_for(DeviceType::Server), DeviceGroup::Workstations);
        assert_eq!(group_for(DeviceType::Unknown), DeviceGroup::Unknown);
    }

    /// Contexto vacío sobre el que aplicar cada caso de prioridad.
    fn contexto() -> DeviceCtx {
        DeviceCtx::default()
    }

    #[test]
    fn sin_pistas_el_tipo_es_desconocido() {
        assert_eq!(device_type(&contexto()), DeviceType::Unknown);
    }

    #[test]
    fn la_puerta_de_enlace_manda_sobre_todo_lo_demas() {
        let ctx = DeviceCtx {
            is_gateway: true,
            vendor: Some("Canon Inc.".to_string()),
            services: vec![ServiceKind::Printer, ServiceKind::Rtsp],
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Gateway);
    }

    #[test]
    fn upnp_internetgatewaydevice_tambien_es_gateway() {
        let ctx = DeviceCtx {
            upnp_types: vec!["urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string()],
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Gateway);
    }

    #[test]
    fn la_impresora_manda_sobre_camara_y_resto() {
        let por_servicio = DeviceCtx {
            services: vec![ServiceKind::Printer, ServiceKind::Rtsp],
            ..contexto()
        };
        assert_eq!(device_type(&por_servicio), DeviceType::Printer);

        let por_fabricante = DeviceCtx {
            vendor: Some("Brother Industries".to_string()),
            services: vec![ServiceKind::Rtsp],
            ..contexto()
        };
        assert_eq!(device_type(&por_fabricante), DeviceType::Printer);
    }

    #[test]
    fn fabricantes_se_comparan_sin_distinguir_mayusculas() {
        let ctx = DeviceCtx {
            vendor: Some("EPSON".to_string()),
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Printer);
    }

    #[test]
    fn la_camara_manda_sobre_tv_y_nas() {
        let ctx = DeviceCtx {
            vendor: Some("Synology".to_string()),
            services: vec![ServiceKind::Rtsp],
            upnp_types: vec!["MediaRenderer".to_string()],
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Camera);
    }

    #[test]
    fn onvif_por_upnp_es_camara() {
        let ctx = DeviceCtx {
            upnp_types: vec!["urn:schemas-upnp-org:device:NetworkCamera:2".to_string()],
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Camera);
    }

    #[test]
    fn cast_y_airplay_son_streaming_salvo_que_se_sepa_que_es_tv() {
        let cast = DeviceCtx {
            mdns_services: vec!["_googlecast._tcp".to_string()],
            ..contexto()
        };
        assert_eq!(device_type(&cast), DeviceType::Streaming);

        let airplay = DeviceCtx {
            mdns_services: vec!["_airplay._tcp".to_string()],
            ..contexto()
        };
        assert_eq!(device_type(&airplay), DeviceType::Streaming);

        let televisor = DeviceCtx {
            mdns_services: vec!["_airplay._tcp".to_string()],
            is_tv: true,
            ..contexto()
        };
        assert_eq!(device_type(&televisor), DeviceType::Tv);
    }

    #[test]
    fn media_renderer_es_streaming() {
        let ctx = DeviceCtx {
            upnp_types: vec!["urn:schemas-upnp-org:device:MediaRenderer:1".to_string()],
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Streaming);
    }

    #[test]
    fn el_nas_manda_sobre_el_hostname_de_movil() {
        let ctx = DeviceCtx {
            vendor: Some("QNAP Systems".to_string()),
            hostname: Some("iPhone-Marta".to_string()),
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Nas);
    }

    #[test]
    fn smb_mas_nfs_es_nas() {
        let ctx = DeviceCtx {
            services: vec![ServiceKind::Smb, ServiceKind::Nfs],
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Nas);

        // Solo SMB no basta.
        let solo_smb = DeviceCtx {
            services: vec![ServiceKind::Smb],
            ..contexto()
        };
        assert_eq!(device_type(&solo_smb), DeviceType::Unknown);
    }

    #[test]
    fn el_hostname_distingue_movil_y_tablet() {
        for hostname in ["iPhone-Marta", "android-abc123", "ipod-de-juan"] {
            let ctx = DeviceCtx {
                hostname: Some(hostname.to_string()),
                ..contexto()
            };
            assert_eq!(device_type(&ctx), DeviceType::Mobile, "{hostname}");
        }
        for hostname in ["iPad", "tablet-sala", "android-tablet"] {
            let ctx = DeviceCtx {
                hostname: Some(hostname.to_string()),
                ..contexto()
            };
            assert_eq!(device_type(&ctx), DeviceType::Tablet, "{hostname}");
        }
    }

    #[test]
    fn servidor_y_pc_se_deciden_por_ssh_y_http() {
        let servidor = DeviceCtx {
            services: vec![ServiceKind::Ssh, ServiceKind::Http],
            ..contexto()
        };
        assert_eq!(device_type(&servidor), DeviceType::Server);

        let pc_ssh = DeviceCtx {
            services: vec![ServiceKind::Ssh],
            ..contexto()
        };
        assert_eq!(device_type(&pc_ssh), DeviceType::Pc);

        let pc_http = DeviceCtx {
            services: vec![ServiceKind::Http],
            os_family: Some(OsFamily::Windows),
            ..contexto()
        };
        assert_eq!(device_type(&pc_http), DeviceType::Pc);

        // HTTP sin SO conocido no basta para decidir PC.
        let solo_http = DeviceCtx {
            services: vec![ServiceKind::Http],
            ..contexto()
        };
        assert_eq!(device_type(&solo_http), DeviceType::Unknown);
    }

    #[test]
    fn el_movil_manda_sobre_el_servidor() {
        let ctx = DeviceCtx {
            hostname: Some("iPhone de Marta".to_string()),
            services: vec![ServiceKind::Ssh, ServiceKind::Http],
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Mobile);
    }

    #[test]
    fn el_fabricante_iot_solo_cuenta_como_ultimo_recurso() {
        let ctx = DeviceCtx {
            vendor: Some("Espressif Inc.".to_string()),
            ..contexto()
        };
        assert_eq!(device_type(&ctx), DeviceType::Iot);

        // Un fabricante IoT con evidencias más fuertes se clasifica por ellas.
        let impresora = DeviceCtx {
            vendor: Some("Espressif Inc.".to_string()),
            services: vec![ServiceKind::Printer],
            ..contexto()
        };
        assert_eq!(device_type(&impresora), DeviceType::Printer);
    }

    #[test]
    fn clasifica_servicios_por_puerto_conocido() {
        assert_eq!(service(21, None), Some(ServiceKind::Ftp));
        assert_eq!(service(22, None), Some(ServiceKind::Ssh));
        assert_eq!(service(23, None), Some(ServiceKind::Telnet));
        assert_eq!(service(53, None), Some(ServiceKind::Dns));
        assert_eq!(service(80, None), Some(ServiceKind::Http));
        assert_eq!(service(139, None), Some(ServiceKind::Smb));
        assert_eq!(service(443, None), Some(ServiceKind::Https));
        assert_eq!(service(445, None), Some(ServiceKind::Smb));
        assert_eq!(service(515, None), Some(ServiceKind::Printer));
        assert_eq!(service(554, None), Some(ServiceKind::Rtsp));
        assert_eq!(service(631, None), Some(ServiceKind::Printer));
        assert_eq!(service(1883, None), Some(ServiceKind::Mqtt));
        assert_eq!(service(1900, None), Some(ServiceKind::Upnp));
        assert_eq!(service(2049, None), Some(ServiceKind::Nfs));
        assert_eq!(service(3389, None), Some(ServiceKind::Rdp));
        assert_eq!(service(5000, None), Some(ServiceKind::Upnp));
        assert_eq!(service(5353, None), Some(ServiceKind::Mdns));
        assert_eq!(service(5555, None), Some(ServiceKind::Adb));
        assert_eq!(service(8008, None), Some(ServiceKind::Http));
        assert_eq!(service(8080, None), Some(ServiceKind::Http));
        assert_eq!(service(8443, None), Some(ServiceKind::Https));
        assert_eq!(service(9100, None), Some(ServiceKind::Printer));
        assert_eq!(service(32400, None), Some(ServiceKind::Plex));
        assert_eq!(service(9999, None), None);
    }

    #[test]
    fn clasifica_servicios_que_se_anuncian_en_el_banner() {
        assert_eq!(
            service(2222, Some("SSH-2.0-OpenSSH_9.6")),
            Some(ServiceKind::Ssh)
        );
        assert_eq!(
            service(8554, Some("RTSP/1.0 200 OK")),
            Some(ServiceKind::Rtsp)
        );
        assert_eq!(
            service(2121, Some("220 ProFTPD Server (ftp)")),
            Some(ServiceKind::Ftp)
        );
        assert_eq!(
            service(9999, Some("HTTP/1.1 200 OK\r\nServer: nginx")),
            Some(ServiceKind::Http)
        );
        assert_eq!(
            service(9999, Some("Server: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1")),
            Some(ServiceKind::Upnp)
        );
        assert_eq!(
            service(9999, Some("HTTP/1.1 200 OK\r\nX-Plex-Protocol: 1.0")),
            Some(ServiceKind::Plex)
        );
        assert_eq!(service(9999, Some("texto cualquiera")), None);
    }

    #[test]
    fn el_puerto_manda_sobre_una_pista_generica_de_http() {
        // Plex sirve HTTP en 32400, pero el puerto tiene prioridad.
        assert_eq!(
            service(32400, Some("HTTP/1.1 200 OK")),
            Some(ServiceKind::Plex)
        );
        // IPP también habla HTTP en 631.
        assert_eq!(
            service(631, Some("HTTP/1.1 200 OK")),
            Some(ServiceKind::Printer)
        );
    }
}
