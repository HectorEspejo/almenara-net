//! Implementación interna de [crate::inference::LabelResolver].

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::capture::{ConnectionKey, Endpoint};
use crate::inference::{
    catalog, domain, ipdb, protocols, AppSource, DestinationInfo, DestinationKind, FlowEvidence,
    FlowLabel, LabelResolver, NameObservation, NameSource, L4,
};

/// Resuelve la etiqueta de un flujo a partir de la evidencia (§7.8).
pub(crate) fn resolve(
    resolver: &mut LabelResolver,
    key: &ConnectionKey,
    ev: &FlowEvidence,
) -> FlowLabel {
    let (cliente_ip, servidor_ip) = extremos_evidencia(resolver, key, ev);
    let actual = resolver.labels.get(key).cloned().unwrap_or_else(|| {
        let mut vacia = FlowLabel::empty(servidor_ip.unwrap_or(key.destination.ip));
        if let Some(servidor) = servidor_ip {
            vacia.destination = resolver.destino(&mut HashMap::new(), servidor, None);
        }
        vacia
    });
    let fuerza_actual = actual.strength;

    // 1) Nombre por precedencia SNI > Host > caché.
    let (nombre, fuente) = if let Some(sni) = ev.sni.as_deref() {
        (Some(sni.to_string()), Some(NameSource::Sni))
    } else if let Some(host) = ev.http_host.as_deref() {
        (Some(host.to_string()), Some(NameSource::Http))
    } else if let Some(servidor) = servidor_ip {
        match resolver
            .names
            .lookup(servidor, cliente_ip, SystemTime::now())
        {
            Some(entrada) => (Some(entrada.name), Some(NameSource::Cache)),
            None => (actual.server_name.clone(), actual.name_source),
        }
    } else {
        (actual.server_name.clone(), actual.name_source)
    };

    // 2) App por precedencia dominio > servicio de F2 > ASN > puerto.
    let l4 = L4::from_protocol(key.protocol);
    let mut app: Option<String> = None;
    let mut category: Option<String> = None;
    let mut app_source: Option<AppSource> = None;
    let mut fuerza = 0u8;

    if let Some(nombre) = nombre.as_deref() {
        if let Some(coincidencia) = resolver.catalog.match_name(nombre) {
            app = Some(coincidencia.key.clone());
            category = Some(coincidencia.category.clone());
            app_source = Some(AppSource::Domain);
            fuerza = AppSource::Domain.strength(fuente);
        }
    }
    if app.is_none() {
        if let (Some(servidor), Some(puerto)) =
            (servidor_ip, key.destination.port.or(key.origin.port))
        {
            if resolver.devices.contains_key(&servidor) {
                if let Some(servicios) = resolver.services.get(&(servidor, puerto)) {
                    for servicio in servicios {
                        if let Some(aplicacion) = resolver.catalog.lan_app(servicio) {
                            app = Some(aplicacion.key.clone());
                            category = Some(aplicacion.category.clone());
                            app_source = Some(AppSource::LanService);
                            fuerza = AppSource::LanService.strength(None);
                            break;
                        }
                    }
                }
            }
        }
    }
    if app.is_none() {
        if let Some(servidor) = servidor_ip {
            if let Some(info) = ip_info(resolver, servidor) {
                if let Some(asn) = info.asn {
                    if let Some(coincidencia) = resolver.catalog.match_asn(asn) {
                        app = Some(coincidencia.key.clone());
                        category = Some(coincidencia.category.clone());
                        app_source = Some(AppSource::Asn);
                        fuerza = AppSource::Asn.strength(None);
                    }
                }
            }
        }
    }
    if app.is_none() {
        if let (Some(l4), Some(puerto)) = (
            l4,
            match (key.origin.port, key.destination.port) {
                (Some(a), Some(b)) => Some(servidor_puerto(ev, a, b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
        ) {
            if let Some(coincidencia) = resolver.catalog.match_port(l4, puerto) {
                app = Some(coincidencia.key.clone());
                category = Some(coincidencia.category.clone());
                app_source = Some(AppSource::Port);
                fuerza = AppSource::Port.strength(None);
            }
        }
    }

    // 3) Solo sube la fuerza: se conserva la etiqueta anterior si no mejora.
    let mut resultado = actual.clone();
    if fuerza > fuerza_actual {
        resultado.app = app;
        resultado.category = category;
        resultado.app_source = app_source;
        resultado.strength = fuerza;
    }
    // El nombre se guarda aunque no case en el catálogo (ranking por destino).
    if let (Some(nombre), Some(fuente)) = (nombre, fuente) {
        let fuerza_nombre = match fuente {
            NameSource::Sni | NameSource::Http => 5,
            NameSource::Cache => 4,
            NameSource::Dns => 4,
        };
        if fuerza_nombre >= resultado.strength || resultado.server_name.is_none() {
            resultado.server_name = Some(nombre);
            resultado.name_source = Some(fuente);
        }
    }
    // Protocolo, JA4 y rol se fusionan siempre (no compiten por fuerza).
    if let Some(protocolo) = ev.app_protocol {
        resultado.app_protocol = Some(protocolo);
    }
    if ev.ja4.is_some() {
        resultado.ja4 = ev.ja4.clone();
    }
    if ev.client_is_src.is_some() {
        resultado.client_is_src = ev.client_is_src;
    }
    // 4) Destino: dominio registrable, IP remota o equipo de la LAN.
    if let Some(servidor) = servidor_ip {
        let mut cache = take_ip_cache(resolver);
        resultado.destination =
            resolver.destino(&mut cache, servidor, resultado.server_name.as_deref());
        put_ip_cache(resolver, cache);
    }
    resolver.labels.insert(*key, resultado.clone());
    resultado
}

/// Construye la etiqueta débil de un flujo cuando aún no hay evidencia.
pub(crate) fn label_for<'a>(resolver: &'a mut LabelResolver, key: &ConnectionKey) -> &'a FlowLabel {
    if !resolver.labels.contains_key(key) {
        let (cliente, servidor) = extremos_clave(resolver, key);
        let l4 = L4::from_protocol(key.protocol);
        let mut etiqueta = FlowLabel::empty(servidor.unwrap_or(key.destination.ip));
        // Nombre en caché.
        if let Some(servidor) = servidor {
            if let Some(entrada) = resolver.names.lookup(servidor, cliente, SystemTime::now()) {
                etiqueta.server_name = Some(entrada.name);
                etiqueta.name_source = Some(NameSource::Cache);
            }
        }
        // Protocolo de aplicación por puerto (provisional).
        if let Some(l4) = l4 {
            let puertos = (
                key.origin.port.unwrap_or(0),
                key.destination.port.unwrap_or(0),
            );
            if let Some((protocolo, _certeza)) = protocols::identify(l4, puertos, &[], &[]) {
                etiqueta.app_protocol = Some(protocolo);
            }
        }
        // App por dominio en caché > servicio de F2 > ASN > puerto.
        let mut fuerza = 0u8;
        if let (Some(nombre), Some(fuente)) =
            (etiqueta.server_name.as_deref(), etiqueta.name_source)
        {
            if let Some(coincidencia) = resolver.catalog.match_name(nombre) {
                etiqueta.app = Some(coincidencia.key.clone());
                etiqueta.category = Some(coincidencia.category.clone());
                etiqueta.app_source = Some(AppSource::Domain);
                fuerza = AppSource::Domain.strength(Some(fuente));
            }
        }
        if etiqueta.app.is_none() {
            if let (Some(servidor), Some(puerto)) = (servidor, puerto_servidor_heuristico(key)) {
                let mut resuelto = false;
                if resolver.devices.contains_key(&servidor) {
                    if let Some(servicios) = resolver.services.get(&(servidor, puerto)) {
                        for servicio in servicios {
                            if let Some(aplicacion) = resolver.catalog.lan_app(servicio) {
                                etiqueta.app = Some(aplicacion.key.clone());
                                etiqueta.category = Some(aplicacion.category.clone());
                                etiqueta.app_source = Some(AppSource::LanService);
                                fuerza = AppSource::LanService.strength(None);
                                resuelto = true;
                                break;
                            }
                        }
                    }
                }
                if !resuelto {
                    if let Some(info) = ip_info(resolver, servidor) {
                        if let Some(asn) = info.asn {
                            if let Some(coincidencia) = resolver.catalog.match_asn(asn) {
                                etiqueta.app = Some(coincidencia.key.clone());
                                etiqueta.category = Some(coincidencia.category.clone());
                                etiqueta.app_source = Some(AppSource::Asn);
                                fuerza = AppSource::Asn.strength(None);
                            }
                        }
                    }
                }
            }
        }
        if etiqueta.app.is_none() {
            if let (Some(l4), Some(puerto)) = (l4, puerto_servidor_heuristico(key)) {
                if let Some(coincidencia) = resolver.catalog.match_port(l4, puerto) {
                    etiqueta.app = Some(coincidencia.key.clone());
                    etiqueta.category = Some(coincidencia.category.clone());
                    etiqueta.app_source = Some(AppSource::Port);
                    fuerza = AppSource::Port.strength(None);
                }
            }
        }
        etiqueta.strength = fuerza;
        if let Some(servidor) = servidor {
            let mut cache = take_ip_cache(resolver);
            etiqueta.destination =
                resolver.destino(&mut cache, servidor, etiqueta.server_name.as_deref());
            put_ip_cache(resolver, cache);
        }
        resolver.labels.insert(*key, etiqueta);
    }
    resolver.labels.get(key).expect("etiqueta insertada")
}

/// Alimenta la caché de nombres.
pub(crate) fn observe_name(resolver: &mut LabelResolver, obs: NameObservation) {
    resolver.names.observe(obs, SystemTime::now());
}

/// Consulta con caché la organización y el país de una IP.
pub(crate) fn ip_info(resolver: &mut LabelResolver, ip: IpAddr) -> Option<ipdb::IpInfo> {
    if !es_ip_de_internet(ip) {
        return None;
    }
    if let Some(informacion) = resolver.ip_info.get(&ip) {
        return informacion.clone();
    }
    let informacion = resolver.ipdb.as_ref().and_then(|base| base.lookup(ip));
    if resolver.ip_info.len() >= 8192 {
        resolver.ip_info.clear();
    }
    resolver.ip_info.insert(ip, informacion.clone());
    informacion
}

/// Indica si una IP es de Internet (no privada, de enlace local ni especial).
fn es_ip_de_internet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            !(ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_multicast()
                || ipv4.is_unspecified())
        }
        IpAddr::V6(ipv6) => {
            !(ipv6.is_loopback()
                || ipv6.is_multicast()
                || ipv6.is_unspecified()
                || es_ipv6_privada(&ipv6))
        }
    }
}

fn es_ipv6_privada(ip: &std::net::Ipv6Addr) -> bool {
    let primeros = ip.segments()[0];
    // fc00::/7 (unique local) y fe80::/10 (enlace local).
    (primeros & 0xFE00) == 0xFC00 || (primeros & 0xFFC0) == 0xFE80
}

/// Devuelve (cliente, servidor) a partir del rol de la etiqueta o de la caché.
fn extremos_evidencia(
    resolver: &LabelResolver,
    key: &ConnectionKey,
    ev: &FlowEvidence,
) -> (Option<IpAddr>, Option<IpAddr>) {
    match ev.client_is_src {
        Some(true) => (Some(key.origin.ip), Some(key.destination.ip)),
        Some(false) => (Some(key.destination.ip), Some(key.origin.ip)),
        None => match (ev.client_ip, ev.server_ip) {
            (Some(cliente), Some(servidor)) => (Some(cliente), Some(servidor)),
            _ => extremos_clave(resolver, key),
        },
    }
}

/// Sin rol: el extremo local es el cliente y, si ninguno lo es, el origen canónico.
fn extremos_clave(
    resolver: &LabelResolver,
    key: &ConnectionKey,
) -> (Option<IpAddr>, Option<IpAddr>) {
    if resolver.local_ips.contains(&key.origin.ip) {
        (Some(key.origin.ip), Some(key.destination.ip))
    } else if resolver.local_ips.contains(&key.destination.ip) {
        (Some(key.destination.ip), Some(key.origin.ip))
    } else {
        (Some(key.origin.ip), Some(key.destination.ip))
    }
}

/// Puerto del lado servidor cuando aún no se conoce el rol: el puerto de
/// servicio si solo hay uno, o el menor si ambos podrían serlo.
fn puerto_servidor_heuristico(key: &ConnectionKey) -> Option<u16> {
    let (origen, destino) = (key.origin.port, key.destination.port);
    match (origen, destino) {
        (Some(a), Some(b)) => {
            let a_servicio = es_puerto_servicio(a);
            let b_servicio = es_puerto_servicio(b);
            if a_servicio && !b_servicio {
                Some(a)
            } else if b_servicio && !a_servicio {
                Some(b)
            } else {
                Some(a.min(b))
            }
        }
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Indica si un puerto parece de servicio (puerto bajo o firma conocida).
fn es_puerto_servicio(puerto: u16) -> bool {
    puerto < 1024 || crate::inference::protocols::is_service_port(puerto)
}

/// Puerto del lado servidor según el rol de la clave (o el mayor si no se sabe).
#[allow(dead_code)]
fn puerto_servidor(key: &ConnectionKey) -> Option<u16> {
    match (key.origin.port, key.destination.port) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn servidor_puerto(ev: &FlowEvidence, origen: u16, destino: u16) -> u16 {
    match ev.client_is_src {
        Some(true) => destino,
        Some(false) => origen,
        None => origen.max(destino),
    }
}

impl LabelResolver {
    /// Construye la información de destino de una IP y su nombre.
    fn destino(
        &mut self,
        ip_cache: &mut HashMap<IpAddr, Option<ipdb::IpInfo>>,
        ip: IpAddr,
        nombre: Option<&str>,
    ) -> DestinationInfo {
        // Equipo de la LAN: la clave es lan:<id> y el nombre el del equipo.
        if let Some((id, nombre_equipo)) = self.devices.get(&ip) {
            return DestinationInfo {
                key: format!("lan:{id}"),
                label: nombre_equipo.clone(),
                org: None,
                country: None,
                kind: DestinationKind::Lan,
            };
        }
        let informacion = if let Some(informacion) = ip_cache.get(&ip) {
            informacion.clone()
        } else {
            let informacion = if es_ip_de_internet(ip) {
                self.ipdb.as_ref().and_then(|base| base.lookup(ip))
            } else {
                None
            };
            ip_cache.insert(ip, informacion.clone());
            informacion
        };
        let (org, country) = match informacion {
            Some(informacion) => (informacion.org, informacion.country),
            None => (None, None),
        };
        match nombre {
            Some(nombre) => match domain::registrable(nombre) {
                Some(registrable) => DestinationInfo {
                    key: registrable.clone(),
                    label: registrable,
                    org,
                    country,
                    kind: DestinationKind::Domain,
                },
                None => DestinationInfo {
                    key: nombre.to_string(),
                    label: nombre.to_string(),
                    org,
                    country,
                    kind: DestinationKind::Domain,
                },
            },
            None => DestinationInfo {
                key: ip.to_string(),
                label: ip.to_string(),
                org,
                country,
                kind: DestinationKind::Ip,
            },
        }
    }
}

/// Extrae la caché de IPs del resolutor (para evitar problemas de préstamo).
fn take_ip_cache(resolver: &mut LabelResolver) -> HashMap<IpAddr, Option<ipdb::IpInfo>> {
    std::mem::take(&mut resolver.ip_info)
}

/// Devuelve la caché de IPs al resolutor.
fn put_ip_cache(resolver: &mut LabelResolver, cache: HashMap<IpAddr, Option<ipdb::IpInfo>>) {
    resolver.ip_info = cache;
}

/// Evita el aviso de imports sin usar cuando se compila sin ciertas ramas.
#[allow(dead_code)]
fn _tipos(_: Endpoint, _: catalog::Catalog) {}
