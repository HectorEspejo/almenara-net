//! Lectura de leases DHCP (dnsmasq, dhclient, NetworkManager y systemd-networkd).
//!
//! Los formatos de lease son texto estable; cada parser es independiente y
//! tolerante: las líneas desconocidas se ignoran y un fichero sin leases válidos
//! devuelve una lista vacía.
//!
//! [`DhcpLeases::read_all`] recorre las rutas por defecto de los cuatro formatos
//! más las rutas manuales de `[scan].dhcp_lease_paths`. Los ficheros inexistentes
//! o ilegibles se omiten y los leases leídos de una ruta manual se marcan con
//! [`LeaseSource::Manual`].

pub mod dhclient;
pub mod dnsmasq;
pub mod networkmanager;
pub mod systemd;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};

use crate::error::{Error, Result};
use crate::oui;

/// Ruta por defecto de los leases de dnsmasq.
const RUTA_DNSMASQ: &str = "/var/lib/misc/dnsmasq.leases";
/// Ruta por defecto de los leases de dhclient.
const RUTA_DHCLIENT: &str = "/var/lib/dhcp/dhclient.leases";
/// Directorio de los leases internos de NetworkManager.
const DIRECTORIO_NETWORKMANAGER: &str = "/var/lib/NetworkManager";
/// Directorio de los leases de systemd-networkd.
const DIRECTORIO_SYSTEMD: &str = "/run/systemd/netif/leases";

/// Origen del lease DHCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseSource {
    /// dnsmasq.
    Dnsmasq,
    /// dhclient.
    Dhclient,
    /// NetworkManager.
    NetworkManager,
    /// systemd-networkd.
    SystemdNetworkd,
    /// Ruta manual configurada por el usuario.
    Manual,
}

/// Lease DHCP normalizado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// MAC del cliente, normalizada si el formato la incluye.
    pub mac: Option<String>,
    /// IPv4 concedida.
    pub ip: Ipv4Addr,
    /// Hostname declarado por el cliente o por el servidor.
    pub hostname: Option<String>,
    /// Caducidad en RFC 3339 UTC, si el formato la incluye.
    pub expiry: Option<String>,
    /// Origen del lease.
    pub source: LeaseSource,
    /// Fichero del que se leyó.
    pub path: Option<PathBuf>,
}

/// Lector de leases DHCP de todos los formatos soportados.
#[derive(Debug, Clone, Copy)]
pub struct DhcpLeases;

impl DhcpLeases {
    /// Rutas por defecto de los cuatro formatos soportados.
    ///
    /// Además de los dos ficheros con ruta fija se expanden los directorios de
    /// NetworkManager (ficheros `*.lease`) y de systemd-networkd (un fichero por
    /// interfaz). Los directorios que no existan se omiten sin error; el
    /// resultado va ordenado para que la lectura sea determinista.
    // API del checklist de Fase 2: read_all la usa internamente y también se
    // expone para que el orquestador pueda inspeccionar las rutas por defecto.
    #[allow(dead_code)]
    pub fn default_paths() -> Vec<PathBuf> {
        let mut rutas = vec![PathBuf::from(RUTA_DNSMASQ), PathBuf::from(RUTA_DHCLIENT)];
        rutas.extend(ficheros_de_directorio(
            Path::new(DIRECTORIO_NETWORKMANAGER),
            Some(".lease"),
        ));
        rutas.extend(ficheros_de_directorio(Path::new(DIRECTORIO_SYSTEMD), None));
        rutas
    }

    /// Lee los leases de las rutas por defecto y de las rutas manuales indicadas.
    ///
    /// Las rutas manuales se interpretan con el parser de su formato (por el
    /// nombre del fichero o, si no se reconoce, probando cada formato en orden).
    /// Una ruta inexistente, ilegible o sin leases válidos se omite sin error.
    /// Las rutas repetidas se leen una sola vez.
    pub fn read_all(extra: &[PathBuf]) -> Result<Vec<Lease>> {
        let por_defecto = Self::default_paths();
        let mut vistas: HashSet<PathBuf> = HashSet::new();
        let mut leases = Vec::new();

        for ruta in por_defecto.iter().chain(extra.iter()) {
            if !vistas.insert(ruta.clone()) {
                continue;
            }
            let es_manual = extra.iter().any(|manual| manual == ruta);
            let Some(leidos) = leer_fichero(ruta)? else {
                continue;
            };
            for mut lease in leidos {
                lease.path = Some(ruta.clone());
                if es_manual {
                    lease.source = LeaseSource::Manual;
                }
                leases.push(lease);
            }
        }
        Ok(leases)
    }
}

/// Formato de lease reconocido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatoLease {
    /// Un lease por línea con campos separados por espacios.
    Dnsmasq,
    /// Bloques `lease { ... }`.
    Dhclient,
    /// Claves y valores propios de NetworkManager.
    NetworkManager,
    /// Claves y valores propios de systemd-networkd.
    SystemdNetworkd,
}

/// Lista los ficheros regulares de un directorio, opcionalmente filtrados por sufijo.
///
/// Los directorios inexistentes o ilegibles devuelven una lista vacía; se ignoran
/// los ficheros ocultos y las rutas ordenadas alfabéticamente.
fn ficheros_de_directorio(directorio: &Path, sufijo: Option<&str>) -> Vec<PathBuf> {
    let Ok(entradas) = std::fs::read_dir(directorio) else {
        return Vec::new();
    };
    let mut rutas: Vec<PathBuf> = entradas
        .filter_map(|entrada| entrada.ok())
        .map(|entrada| entrada.path())
        .filter(|ruta| ruta.is_file())
        .filter(|ruta| {
            !ruta
                .file_name()
                .is_some_and(|nombre| nombre.to_string_lossy().starts_with('.'))
        })
        .filter(|ruta| match sufijo {
            Some(sufijo) => ruta
                .file_name()
                .is_some_and(|nombre| nombre.to_string_lossy().ends_with(sufijo)),
            None => true,
        })
        .collect();
    rutas.sort();
    rutas
}

/// Deduce el formato de un fichero a partir de su ruta.
fn formato_por_ruta(ruta: &Path) -> Option<FormatoLease> {
    let nombre = ruta.file_name()?.to_string_lossy().to_ascii_lowercase();
    if ruta.starts_with(DIRECTORIO_SYSTEMD) {
        return Some(FormatoLease::SystemdNetworkd);
    }
    if nombre == "dnsmasq.leases" {
        return Some(FormatoLease::Dnsmasq);
    }
    if nombre.contains("dhclient") && nombre.contains("lease") {
        return Some(FormatoLease::Dhclient);
    }
    if nombre.ends_with(".lease") {
        return Some(FormatoLease::NetworkManager);
    }
    None
}

/// Selecciona el parser y devuelve los leases del contenido.
///
/// Si la ruta no identifica el formato se prueban todos los parsers en orden y
/// se usa el primero que devuelva leases; así una ruta manual con un nombre
/// arbitrario sigue funcionando.
fn interpretar(ruta: &Path, texto: &str) -> Result<Vec<Lease>> {
    if let Some(formato) = formato_por_ruta(ruta) {
        return parsear_con_formato(formato, texto);
    }
    for formato in [
        FormatoLease::Dnsmasq,
        FormatoLease::Dhclient,
        FormatoLease::NetworkManager,
        FormatoLease::SystemdNetworkd,
    ] {
        let leases = parsear_con_formato(formato, texto)?;
        if !leases.is_empty() {
            return Ok(leases);
        }
    }
    Ok(Vec::new())
}

/// Ejecuta el parser del formato indicado.
fn parsear_con_formato(formato: FormatoLease, texto: &str) -> Result<Vec<Lease>> {
    match formato {
        FormatoLease::Dnsmasq => dnsmasq::parse(texto),
        FormatoLease::Dhclient => dhclient::parse(texto),
        FormatoLease::NetworkManager => networkmanager::parse(texto),
        FormatoLease::SystemdNetworkd => systemd::parse(texto),
    }
}

/// Lee y parsea un fichero de leases.
///
/// Devuelve `Ok(None)` cuando el fichero no existe, no es un fichero regular o
/// no se puede leer por permisos (caso habitual de los leases del sistema).
fn leer_fichero(ruta: &Path) -> Result<Option<Vec<Lease>>> {
    if !ruta.is_file() {
        return Ok(None);
    }
    let contenido = match std::fs::read(ruta) {
        Ok(contenido) => contenido,
        Err(error) => {
            return match error.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
                    tracing::debug!(
                        ruta = %ruta.display(),
                        %error,
                        "lease DHCP ilegible; se omite"
                    );
                    Ok(None)
                }
                _ => Err(Error::Scan(format!(
                    "no se pudo leer el fichero de leases DHCP {}: {error}",
                    ruta.display()
                ))),
            }
        }
    };
    // Un fichero de leases no debería tener binario, pero si lo tuviera no se
    // aborta la lectura: los bytes inválidos se sustituyen y las líneas raras
    // se ignoran en los parsers.
    let texto = String::from_utf8_lossy(&contenido);
    Ok(Some(interpretar(ruta, &texto)?))
}

/// Convierte un epoch en segundos a RFC 3339 UTC con precisión de segundos.
pub(crate) fn epoch_a_rfc3339(segundos: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(segundos, 0)
        .map(|fecha| fecha.to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// Convierte un valor de texto (epoch o RFC 3339) a RFC 3339 UTC.
pub(crate) fn texto_a_rfc3339(valor: &str) -> Option<String> {
    let limpio = valor.trim().trim_matches('"').trim_matches('\'').trim();
    if limpio.is_empty() {
        return None;
    }
    if let Ok(segundos) = limpio.parse::<i64>() {
        return (segundos > 0).then(|| epoch_a_rfc3339(segundos)).flatten();
    }
    DateTime::parse_from_rfc3339(limpio).ok().map(|fecha| {
        fecha
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Secs, true)
    })
}

/// Parsea una IPv4 de un valor de lease, admitiendo prefijo de red y comillas.
pub(crate) fn parsear_ipv4(valor: &str) -> Option<Ipv4Addr> {
    let limpio = valor.trim().trim_matches('"').trim_matches('\'');
    let sin_prefijo = limpio.split('/').next().unwrap_or(limpio).trim();
    sin_prefijo.parse().ok()
}

/// Normaliza un hostname de lease: quita comillas y descarta marcadores vacíos.
pub(crate) fn normalizar_hostname(valor: &str) -> Option<String> {
    let limpio = valor.trim().trim_matches('"').trim_matches('\'').trim();
    if limpio.is_empty() {
        return None;
    }
    let marcador = limpio.to_ascii_lowercase();
    if matches!(
        marcador.as_str(),
        "*" | "-" | "(none)" | "<none>" | "none" | "unknown"
    ) {
        return None;
    }
    Some(limpio.to_string())
}

/// Extrae una MAC de un identificador de cliente DHCP (tipo hardware 1 + MAC).
fn mac_de_client_id(valor: &str) -> Option<String> {
    let partes: Vec<&str> = valor
        .trim()
        .trim_matches('"')
        .split([':', '-'])
        .filter(|parte| !parte.is_empty())
        .collect();
    if partes.len() == 7 && partes[0].eq_ignore_ascii_case("01") {
        return oui::normalize_mac(&partes[1..].join(":"));
    }
    None
}

/// Parsea un lease en formato CLAVE=valor (NetworkManager y systemd-networkd).
///
/// Son formatos internos sin especificación estable: se aceptan varios alias de
/// clave, se ignoran las claves desconocidas y cada línea de dirección produce
/// un lease. El formato es el mismo en ambos orígenes; solo cambia la fuente.
pub(crate) fn parsear_clave_valor(texto: &str, fuente: LeaseSource) -> Vec<Lease> {
    let mut direcciones: Vec<Ipv4Addr> = Vec::new();
    let mut mac: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut expiry: Option<String> = None;

    for linea in texto.lines() {
        let linea = linea.trim();
        if linea.is_empty() || linea.starts_with('#') {
            continue;
        }
        let Some((clave, valor)) = linea.split_once('=') else {
            continue;
        };
        let clave = clave.trim().to_ascii_uppercase();
        let valor = valor.trim();
        match clave.as_str() {
            "ADDRESS" | "IPADDR" | "IP4_ADDRESS" | "DHCP4_ADDRESS" | "DHCP4_IP_ADDRESS" => {
                if let Some(ip) = parsear_ipv4(valor) {
                    if !direcciones.contains(&ip) {
                        direcciones.push(ip);
                    }
                }
            }
            "HWADDR" | "MAC_ADDRESS" | "CLIENT_MAC" | "DHCP4_MAC_ADDRESS" => {
                if let Some(normalizada) = oui::normalize_mac(valor) {
                    mac = Some(normalizada);
                }
            }
            "CLIENT_ID" | "DHCP_CLIENT_IDENTIFIER" => {
                if mac.is_none() {
                    mac = mac_de_client_id(valor);
                }
            }
            "HOSTNAME" | "HOST_NAME" | "DHCP4_HOSTNAME" | "DHCP_HOSTNAME" => {
                hostname = normalizar_hostname(valor);
            }
            "EXPIRY" | "EXPIRE" | "EXPIRES" | "LEASE_EXPIRY" | "LEASE_EXPIRES" | "DHCP4_EXPIRY" => {
                expiry = texto_a_rfc3339(valor);
            }
            _ => {}
        }
    }

    direcciones
        .into_iter()
        .map(|ip| Lease {
            mac: mac.clone(),
            ip,
            hostname: hostname.clone(),
            expiry: expiry.clone(),
            source: fuente,
            path: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn las_rutas_por_defecto_incluyen_los_formatos_conocidos() {
        let rutas = DhcpLeases::default_paths();
        assert!(rutas
            .iter()
            .any(|ruta| ruta.as_path() == Path::new(RUTA_DNSMASQ)));
        assert!(rutas
            .iter()
            .any(|ruta| ruta.as_path() == Path::new(RUTA_DHCLIENT)));
        // Las expansiones de directorio nunca devuelven directorios ni ficheros ocultos.
        assert!(rutas.iter().all(|ruta| ruta.is_file() || !ruta.exists()));
        assert!(rutas.iter().all(|ruta| !ruta
            .file_name()
            .is_some_and(|nombre| nombre.to_string_lossy().starts_with('.'))));
    }

    #[test]
    fn read_all_lee_una_ruta_manual_y_marca_la_fuente() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("router-dnsmasq.leases");
        fs::write(
            &ruta,
            "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 portatil *\n",
        )
        .expect("fixture de lease");

        let leases = DhcpLeases::read_all(std::slice::from_ref(&ruta)).expect("lectura tolerante");
        let lease = leases
            .iter()
            .find(|lease| lease.path.as_deref() == Some(ruta.as_path()))
            .expect("lease de la ruta manual");

        assert_eq!(lease.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(lease.ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(lease.hostname.as_deref(), Some("portatil"));
        assert_eq!(lease.source, LeaseSource::Manual);
        assert_eq!(lease.expiry.as_deref(), Some("2023-11-14T22:13:20Z"));
    }

    #[test]
    fn read_all_detecta_el_formato_por_el_contenido() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("leases-del-router.txt");
        fs::write(
            &ruta,
            "lease {\n  fixed-address 10.0.0.7;\n  option host-name \"router\";\n}\n",
        )
        .expect("fixture de lease");

        let leases = DhcpLeases::read_all(std::slice::from_ref(&ruta)).expect("lectura tolerante");
        let lease = leases
            .iter()
            .find(|lease| lease.path.as_deref() == Some(ruta.as_path()))
            .expect("lease de la ruta manual");

        assert_eq!(lease.ip, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(lease.hostname.as_deref(), Some("router"));
        assert_eq!(lease.source, LeaseSource::Manual);
    }

    #[test]
    fn read_all_omite_rutas_inexistentes_o_sin_leases() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let inexistente = directorio.path().join("no-existe.leases");
        let vacio = directorio.path().join("vacio.leases");
        fs::write(&vacio, "# sin leases\n").expect("fixture");

        let leases =
            DhcpLeases::read_all(&[inexistente.clone(), vacio.clone()]).expect("lectura tolerante");
        assert!(leases
            .iter()
            .all(|lease| lease.path.as_deref() != Some(inexistente.as_path())));
        assert!(leases
            .iter()
            .all(|lease| lease.path.as_deref() != Some(vacio.as_path())));
    }

    #[test]
    fn read_all_no_duplica_las_rutas_repetidas() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("duplicada.leases");
        fs::write(&ruta, "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 host *\n").expect("fixture");

        let leases =
            DhcpLeases::read_all(&[ruta.clone(), ruta.clone()]).expect("lectura tolerante");
        assert_eq!(
            leases
                .iter()
                .filter(|lease| lease.path.as_deref() == Some(ruta.as_path()))
                .count(),
            1
        );
    }

    #[test]
    fn un_fichero_sin_leases_validos_no_es_error() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("ruido.txt");
        fs::write(&ruta, "esto no es un lease\n\n# ni esto\n").expect("fixture");
        assert!(DhcpLeases::read_all(&[ruta]).is_ok());
    }
}
