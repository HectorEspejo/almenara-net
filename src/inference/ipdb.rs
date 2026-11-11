//! Organización (ASN) y país de una IP con las bases DB-IP Lite embebidas (§7.10).

use std::net::IpAddr;

use maxminddb::geoip2;

/// Bases de datos DB-IP Lite embebidas en el binario.
///
/// Atribución obligatoria (CC BY 4.0): IP Geolocation by DB-IP
/// (https://db-ip.com). Ver data/FUENTES.md.
const ASN_DB: &[u8] = include_bytes!("../../data/dbip-asn-lite.mmdb");
const COUNTRY_DB: &[u8] = include_bytes!("../../data/dbip-country-lite.mmdb");

/// Tamaño total de las bases MMDB embebidas en el binario.
pub const BYTES_EMBEBIDOS: u64 = (ASN_DB.len() + COUNTRY_DB.len()) as u64;

/// Información de una IP según las bases embebidas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpInfo {
    /// Número de ASN, si se conoce.
    pub asn: Option<u32>,
    /// Organización del ASN.
    pub org: Option<String>,
    /// País ISO 3166-1 alfa-2.
    pub country: Option<String>,
}

/// Error de apertura de las bases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpDbError(pub String);

impl std::fmt::Display for IpDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IpDbError {}

/// Bases DB-IP Lite embebidas en el binario.
#[derive(Debug)]
pub struct IpDb {
    asn: maxminddb::Reader<Vec<u8>>,
    country: maxminddb::Reader<Vec<u8>>,
}

impl IpDb {
    /// Abre las bases embebidas del repositorio.
    pub fn embedded() -> Result<Self, IpDbError> {
        let asn = maxminddb::Reader::from_source(ASN_DB.to_vec()).map_err(|error| {
            IpDbError(format!(
                "no se pudo abrir la base DB-IP de ASN embebida: {error}"
            ))
        })?;
        let country = maxminddb::Reader::from_source(COUNTRY_DB.to_vec()).map_err(|error| {
            IpDbError(format!(
                "no se pudo abrir la base DB-IP de país embebida: {error}"
            ))
        })?;
        Ok(Self { asn, country })
    }

    /// Busca ASN, organización y país de una IP.
    ///
    /// Devuelve None para IPs privadas, de enlace local, loopback, multicast y
    /// sin datos en las bases, y no hace ninguna consulta de red.
    pub fn lookup(&self, ip: IpAddr) -> Option<IpInfo> {
        // Los clientes pueden traer IPv4 mapeada en IPv6 (::ffff:8.8.8.8).
        let ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => ip,
            },
            IpAddr::V4(_) => ip,
        };
        if !es_ip_publica(ip) {
            return None;
        }
        let mut info = IpInfo::default();
        if let Some(registro) = self.lookup_asn(ip) {
            info.asn = registro.autonomous_system_number;
            info.org = registro
                .autonomous_system_organization
                .map(|organizacion| organizacion.to_string());
        }
        if let Some(registro) = self.lookup_country(ip) {
            info.country = registro
                .country
                .and_then(|pais| pais.iso_code)
                .map(|iso| iso.to_string());
        }
        if info.asn.is_none() && info.org.is_none() && info.country.is_none() {
            return None;
        }
        Some(info)
    }

    /// Busca ASN y organización; los errores de decodificación se tratan como
    /// ausencia de dato (las bases son dato externo y no deben romper nada).
    fn lookup_asn(&self, ip: IpAddr) -> Option<geoip2::Asn<'_>> {
        let registro: geoip2::Asn<'_> = self.asn.lookup(ip).ok().flatten()?;
        if registro.autonomous_system_number.is_none()
            && registro.autonomous_system_organization.is_none()
        {
            return None;
        }
        Some(registro)
    }

    /// Busca el país; los errores de decodificación se tratan como ausencia.
    fn lookup_country(&self, ip: IpAddr) -> Option<geoip2::Country<'_>> {
        let registro: geoip2::Country<'_> = self.country.lookup(ip).ok().flatten()?;
        registro.country.as_ref()?;
        Some(registro)
    }

    /// Fecha de compilación de las bases (para la pestaña Config y Ayuda).
    ///
    /// Prefiere el mes que DB-IP escribe en la descripción de la base
    /// (por ejemplo "DBIP-ASN-Lite (2026-11)"); si no hay, usa build_epoch.
    pub fn build_date(&self) -> Option<String> {
        fecha_de_metadatos(&self.asn.metadata)
            .or_else(|| fecha_de_metadatos(&self.country.metadata))
    }
}

/// Indica si una IP es pública y por tanto tiene sentido consultarla.
fn es_ip_publica(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unique_local()
                && !v6.is_unicast_link_local()
        }
    }
}

/// Extrae la fecha de los metadatos de una base MMDB.
fn fecha_de_metadatos(metadata: &maxminddb::Metadata) -> Option<String> {
    for descripcion in metadata.description.values() {
        if let Some(mes) = extraer_mes(descripcion) {
            return Some(mes);
        }
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp(metadata.build_epoch as i64, 0)
        .map(|fecha| fecha.format("%Y-%m-%d").to_string())
}

/// Busca un mes en formato AAAA-MM dentro de un texto.
fn extraer_mes(texto: &str) -> Option<String> {
    let caracteres: Vec<char> = texto.chars().collect();
    if caracteres.len() < 7 {
        return None;
    }
    for inicio in 0..=caracteres.len() - 7 {
        let ventana = &caracteres[inicio..inicio + 7];
        let digitos_anio = ventana[0..4]
            .iter()
            .all(|caracter| caracter.is_ascii_digit());
        let digitos_mes = ventana[5..7]
            .iter()
            .all(|caracter| caracter.is_ascii_digit());
        if !digitos_anio || ventana[4] != '-' || !digitos_mes {
            continue;
        }
        let anio_texto: String = ventana[0..4].iter().collect();
        let Ok(anio) = anio_texto.parse::<u32>() else {
            continue;
        };
        if !(2000..=2100).contains(&anio) {
            continue;
        }
        return Some(ventana.iter().collect());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba válida")
    }

    #[test]
    fn bases_embebidas_abren_y_tienen_fecha() {
        let db = IpDb::embedded().expect("las MMDB embebidas deben abrir");
        let fecha = db.build_date().expect("las bases deben traer fecha");
        assert!(!fecha.is_empty());
        assert!(fecha.contains('-'), "fecha inesperada: {fecha}");
    }

    #[test]
    fn lookup_google_v4() {
        let db = IpDb::embedded().expect("MMDB embebidas");
        let info = db.lookup(ip("8.8.8.8")).expect("8.8.8.8 está en las bases");
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.country.as_deref(), Some("US"));
        let organizacion = info.org.expect("organización del ASN");
        assert!(
            organizacion.to_ascii_uppercase().contains("GOOGLE"),
            "organización inesperada: {organizacion}"
        );
    }

    #[test]
    fn lookup_google_v6() {
        let db = IpDb::embedded().expect("MMDB embebidas");
        let info = db
            .lookup(ip("2001:4860:4860::8888"))
            .expect("el DNS de Google en IPv6 está en las bases");
        assert_eq!(info.asn, Some(15169));
        // El país de una dirección anycast puede variar entre versiones de la
        // base (DB-IP 2026-11 la sitúa en Canadá), así que solo se exige que
        // haya país y organización.
        assert!(info.country.is_some(), "falta el país: {info:?}");
        assert!(info.org.is_some(), "falta la organización: {info:?}");
    }

    #[test]
    fn lookup_ipv4_mapeada_en_ipv6() {
        let db = IpDb::embedded().expect("MMDB embebidas");
        let info = db
            .lookup(ip("::ffff:8.8.8.8"))
            .expect("la IPv4 mapeada se consulta como IPv4");
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.country.as_deref(), Some("US"));
    }

    #[test]
    fn lookup_privadas_enlace_local_loopback_y_multicast_es_none() {
        let db = IpDb::embedded().expect("MMDB embebidas");
        let reservadas = [
            "10.0.0.1",
            "172.16.4.2",
            "192.168.1.20",
            "127.0.0.1",
            "169.254.10.10",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "ff02::1",
            "::",
        ];
        for texto in reservadas {
            assert_eq!(db.lookup(ip(texto)), None, "{texto} no debe consultarse");
        }
    }

    #[test]
    fn lookup_ip_sin_datos_en_las_bases_es_none() {
        let db = IpDb::embedded().expect("MMDB embebidas");
        // Rangos de documentación (RFC 5737 y RFC 3849): no tienen datos.
        assert_eq!(db.lookup(ip("203.0.113.1")), None);
        assert_eq!(db.lookup(ip("2001:db8::1")), None);
    }

    #[test]
    fn extraer_mes_de_las_descripciones() {
        assert_eq!(
            extraer_mes("DBIP-ASN-Lite (2026-11)"),
            Some("2026-11".to_string())
        );
        assert_eq!(
            extraer_mes("IP to Country Lite 2025-07"),
            Some("2025-07".to_string())
        );
        assert_eq!(extraer_mes("sin fecha"), None);
        assert_eq!(extraer_mes("1999-01"), None);
        assert_eq!(extraer_mes("2026-1"), None);
        assert_eq!(extraer_mes(""), None);
        assert_eq!(extraer_mes("2026-11-30"), Some("2026-11".to_string()));
    }
}
