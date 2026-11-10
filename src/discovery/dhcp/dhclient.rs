//! Parser de leases DHCP en formato dhclient.
//!
//! El fichero contiene bloques `lease { ... }` con directivas: `fixed-address`,
//! `hardware ethernet`, `option host-name` y `expire`/`ends`. La fecha de
//! caducidad se escribe en hora local y se convierte a RFC 3339 UTC. Los bloques
//! sin dirección o las directivas desconocidas se ignoran sin abortar el parseo.

use std::net::Ipv4Addr;

use chrono::{Local, NaiveDate, SecondsFormat, TimeZone, Utc};

use super::{normalizar_hostname, parsear_ipv4, Lease, LeaseSource};
use crate::error::Result;
use crate::oui;

/// Parsea el contenido de un fichero de leases dhclient.
pub fn parse(text: &str) -> Result<Vec<Lease>> {
    let mut leases = Vec::new();
    let mut bloque: Option<BloqueDhclient> = None;

    for linea in text.lines() {
        let limpia = linea.trim();
        if limpia.is_empty() || limpia.starts_with('#') {
            continue;
        }
        if bloque.is_none() {
            if es_inicio_de_lease(limpia) {
                bloque = Some(BloqueDhclient::default());
            }
            continue;
        }
        if limpia.starts_with('}') {
            if let Some(actual) = bloque.take() {
                if let Some(lease) = actual.a_lease() {
                    leases.push(lease);
                }
            }
            continue;
        }
        if let Some(actual) = bloque.as_mut() {
            actual.acumular(limpia);
        }
    }

    // Bloque sin cerrar (fichero truncado): se aprovecha lo leído hasta el final.
    if let Some(actual) = bloque.take() {
        if let Some(lease) = actual.a_lease() {
            leases.push(lease);
        }
    }
    Ok(leases)
}

/// Indica si la línea abre un bloque `lease { ... }`.
fn es_inicio_de_lease(linea: &str) -> bool {
    linea.starts_with("lease") && linea.ends_with('{')
}

/// Datos acumulados de un bloque de dhclient.
#[derive(Debug, Default)]
struct BloqueDhclient {
    ip: Option<Ipv4Addr>,
    mac: Option<String>,
    hostname: Option<String>,
    expiry: Option<String>,
}

impl BloqueDhclient {
    /// Acumula una línea del bloque (ya sin comentarios ni llaves de cierre).
    fn acumular(&mut self, linea: &str) {
        let contenido = linea.trim_end_matches(';').trim();
        if let Some(resto) = contenido.strip_prefix("fixed-address") {
            if self.ip.is_none() {
                self.ip = extraer_ipv4(resto);
            }
        } else if let Some(resto) = contenido.strip_prefix("hardware ethernet") {
            if self.mac.is_none() {
                self.mac = oui::normalize_mac(resto.trim());
            }
        } else if let Some(resto) = contenido.strip_prefix("option host-name") {
            self.hostname = normalizar_hostname(resto);
        } else if let Some(resto) = contenido.strip_prefix("expire") {
            if self.expiry.is_none() {
                self.expiry = fecha_local_a_rfc3339(resto);
            }
        } else if let Some(resto) = contenido.strip_prefix("ends") {
            if self.expiry.is_none() {
                self.expiry = fecha_local_a_rfc3339(resto);
            }
        }
    }

    /// Convierte el bloque en un lease, si tiene dirección.
    fn a_lease(&self) -> Option<Lease> {
        Some(Lease {
            mac: self.mac.clone(),
            ip: self.ip?,
            hostname: self.hostname.clone(),
            expiry: self.expiry.clone(),
            source: LeaseSource::Dhclient,
            path: None,
        })
    }
}

/// Busca la primera IPv4 en el valor de una directiva.
fn extraer_ipv4(texto: &str) -> Option<Ipv4Addr> {
    texto
        .split(|caracter: char| caracter.is_whitespace() || caracter == ',')
        .find_map(parsear_ipv4)
}

/// Convierte una fecha local de dhclient («dia 2026/11/10 15:00:00») a RFC 3339 UTC.
fn fecha_local_a_rfc3339(texto: &str) -> Option<String> {
    let tokens: Vec<&str> = texto.split_whitespace().collect();
    let posicion = tokens.iter().position(|token| token.contains('/'))?;
    let fecha = tokens[posicion];
    let hora = tokens.get(posicion + 1)?.trim_end_matches(';');

    let mut partes_fecha = fecha.split('/');
    let anyo: i32 = partes_fecha.next()?.parse().ok()?;
    let mes: u32 = partes_fecha.next()?.parse().ok()?;
    let dia: u32 = partes_fecha.next()?.parse().ok()?;

    let mut partes_hora = hora.split(':');
    let horas: u32 = partes_hora.next()?.parse().ok()?;
    let minutos: u32 = partes_hora.next()?.parse().ok()?;
    let segundos: u32 = partes_hora.next()?.parse().ok()?;

    let naive = NaiveDate::from_ymd_opt(anyo, mes, dia)?.and_hms_opt(horas, minutos, segundos)?;
    let local = match Local.from_local_datetime(&naive) {
        chrono::LocalResult::Single(fecha_local)
        | chrono::LocalResult::Ambiguous(fecha_local, _) => fecha_local,
        chrono::LocalResult::None => return None,
    };
    Some(
        local
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
# Fichero de leases de prueba
lease {
  interface \"eth0\";
  fixed-address 192.168.1.120;
  hardware ethernet AA:BB:CC:DD:EE:01;
  option host-name \"portatil-dhclient\";
  option dhcp-lease-time 86400;
  renew 2 2026/11/10 09:00:00;
  rebind 2 2026/11/10 13:00:00;
  expire 2 2026/11/10 15:00:00;
}
lease {
  interface \"eth0\";
  fixed-address 192.168.1.121;
  hardware ethernet aa-bb-cc-dd-ee-02;
}
";

    #[test]
    fn parsea_bloques_y_normaliza_la_mac() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases.len(), 2);

        assert_eq!(leases[0].ip, Ipv4Addr::new(192, 168, 1, 120));
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(leases[0].hostname.as_deref(), Some("portatil-dhclient"));
        assert_eq!(leases[0].source, LeaseSource::Dhclient);
        assert_eq!(leases[0].path, None);
    }

    #[test]
    fn la_fecha_de_expire_se_convierte_a_rfc3339_utc() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        let expiry = leases[0].expiry.as_deref().expect("caducidad");
        assert!(expiry.ends_with('Z'), "se esperaba UTC: {expiry}");
        let fecha = chrono::DateTime::parse_from_rfc3339(expiry).expect("RFC 3339 válido");
        assert_eq!(fecha.offset().local_minus_utc(), 0);
    }

    #[test]
    fn un_bloque_sin_fecha_ni_hostname_deja_none() {
        let leases = parse(FIXTURE).expect("parseo tolerante");
        assert_eq!(leases[1].expiry, None);
        assert_eq!(leases[1].hostname, None);
        assert_eq!(leases[1].mac.as_deref(), Some("aa:bb:cc:dd:ee:02"));
    }

    #[test]
    fn un_bloque_sin_direccion_se_ignora() {
        let texto = "lease {\n  interface \"eth0\";\n  hardware ethernet aa:bb:cc:dd:ee:03;\n}\n";
        assert!(parse(texto).expect("parseo tolerante").is_empty());
    }

    #[test]
    fn expire_never_no_rompe_el_parseo() {
        let texto = "lease {\n  fixed-address 192.168.1.122;\n  expire never;\n}\n";
        let leases = parse(texto).expect("parseo tolerante");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].expiry, None);
    }

    #[test]
    fn una_fecha_invalida_deja_el_lease_sin_caducidad() {
        let texto = "lease {\n  fixed-address 192.168.1.123;\n  expire 2 2026/13/45 99:99:99;\n}\n";
        let leases = parse(texto).expect("parseo tolerante");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].expiry, None);
    }

    #[test]
    fn un_texto_sin_bloques_devuelve_lista_vacia() {
        assert!(parse("").expect("parseo tolerante").is_empty());
        assert!(parse("# nada\nruido\n")
            .expect("parseo tolerante")
            .is_empty());
    }
}
