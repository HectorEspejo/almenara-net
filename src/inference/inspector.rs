//! Implementación interna de [crate::inference::FlowInspector].
//!
//! Vive en el hilo de captura. Recibe el payload solo como préstamo prestado de
//! la trama: no se copia ni se guarda fuera de los reensamblados acotados, que
//! se liberan en cuanto se extrae la etiqueta (o al agotarse/caducar).

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use crate::capture::{ConnectionKey, PacketMeta, Protocol};
use crate::identify;
use crate::inference::protocols::Certainty;
use crate::inference::reassembly::{PushResult, StreamStart};
use crate::inference::{
    dns, http, ja4, protocols, quic, role, tls, AppProtocol, Evidence, FlowEvidence, FlowInspector,
    FlowState, NameObservation, NameSource, ObservedHost, ObservedSource, ASSEMBLY_TIMEOUT,
    FLOW_IDLE_TIMEOUT, L4, MAX_ASSEMBLY_PACKETS, MAX_REASSEMBLIES, QUIC_MAX_INITIALS,
};

/// Puertos que se prueban como HTTP en claro.
const PUERTOS_HTTP: [u16; 6] = [80, 8000, 8008, 8080, 8443, 8888];
/// Puerto TLS por defecto.
const PUERTO_TLS: u16 = 443;
/// Puerto DNS.
const PUERTO_DNS: u16 = 53;
/// Puertos DHCP (cliente y servidor).
const PUERTO_DHCP_CLIENTE: u16 = 68;
/// Puerto DHCP servidor.
const PUERTO_DHCP_SERVIDOR: u16 = 67;

/// Estado de las extracciones ya realizadas para un flujo.
#[derive(Debug, Default)]
struct Flags {
    protocol_done: bool,
    tls_done: bool,
    http_done: bool,
    dns_done: bool,
}

impl FlowInspector {
    /// Inspecciona un paquete capturado y devuelve las evidencias extraídas.
    pub(crate) fn inspect_impl(
        &mut self,
        meta: &PacketMeta,
        payload: &[u8],
        now: Instant,
    ) -> Vec<Evidence> {
        let mut out = Vec::new();
        let key = ConnectionKey::from_packet(meta);
        let enabled = self.config.enabled;

        // 1) DHCP: identidad del equipo y protocolo de aplicación.
        if enabled
            && meta.protocol == Protocol::Udp
            && (es_puerto_dhcp(meta.src_port) || es_puerto_dhcp(meta.dst_port))
        {
            return inspeccionar_dhcp(&key, payload);
        }

        // 2) Respuestas DNS (UDP): alimentan la caché IP → nombre.
        if enabled
            && meta.protocol == Protocol::Udp
            && meta.src_port == Some(PUERTO_DNS)
            && !payload.is_empty()
        {
            for observacion in dns::extract_answers(payload, meta.dst_ip) {
                out.push(Evidence::Name(observacion));
            }
        }

        let Some(l4) = L4::from_protocol(meta.protocol) else {
            return out;
        };

        // 3) Estado del flujo: alta acotada por el tope de reensamblados.
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= MAX_REASSEMBLIES {
                self.counters.reassembly_drops = self.counters.reassembly_drops.saturating_add(1);
                return out;
            }
            let flujo = crate::inference::InspectedFlow {
                last_seen: now,
                state: Some(FlowState {
                    key,
                    first_seen: now,
                    is_new: true,
                    l4: Some(l4),
                    app_protocol: None,
                    client_is_src: None,
                    quic: false,
                }),
                ..crate::inference::InspectedFlow::default()
            };
            self.flows.insert(key, flujo);
        }

        // 4) Rol cliente/servidor (solo hasta deducirlo). Es una regla de
        // cabeceras de transporte, así que se aplica aunque la inferencia esté
        // desactivada.
        {
            let rol_pendiente = self
                .flows
                .get(&key)
                .and_then(|flujo| flujo.state.as_ref())
                .map(|estado| estado.client_is_src.is_none())
                .unwrap_or(false);
            if rol_pendiente {
                let mut estado = self
                    .flows
                    .get(&key)
                    .and_then(|flujo| flujo.state.clone())
                    .unwrap_or(FlowState {
                        key,
                        first_seen: now,
                        is_new: true,
                        l4: Some(l4),
                        app_protocol: None,
                        client_is_src: None,
                        quic: false,
                    });
                let escucha = self
                    .listening
                    .read()
                    .map(|conjunto| conjunto.clone())
                    .unwrap_or_default();
                if let Some(rol) = role::infer(&estado, meta, &escucha) {
                    estado.client_is_src = Some(rol);
                    if let Some(flujo) = self.flows.get_mut(&key) {
                        if let Some(estado) = &mut flujo.state {
                            estado.client_is_src = Some(rol);
                        }
                        flujo.role_done = true;
                    }
                    let (cliente, servidor) = extremos(&estado, &key, &self.local_ips);
                    let mut evidencia = FlowEvidence::empty(key);
                    evidencia.client_is_src = Some(rol);
                    evidencia.client_ip = cliente;
                    evidencia.server_ip = servidor;
                    out.push(Evidence::Flow(evidencia));
                }
            }
        }

        if payload.is_empty() {
            if let Some(flujo) = self.flows.get_mut(&key) {
                flujo.last_seen = now;
                if flujo.state.is_none() {
                    flujo.state = Some(FlowState {
                        key,
                        first_seen: now,
                        is_new: false,
                        l4: Some(l4),
                        app_protocol: None,
                        client_is_src: None,
                        quic: false,
                    });
                }
            }
            return out;
        }

        let estado = self
            .flows
            .get(&key)
            .and_then(|flujo| flujo.state.clone())
            .unwrap_or(FlowState {
                key,
                first_seen: now,
                is_new: false,
                l4: Some(l4),
                app_protocol: None,
                client_is_src: None,
                quic: false,
            });
        let (cliente_ip, servidor_ip) = extremos(&estado, &key, &self.local_ips);

        // 5) QUIC: Initial de cabecera larga, claves derivadas del DCID y AEAD.
        // Se procesan todos los Initial mientras el ClientHello no esté completo
        // (puede venir repartido en varios paquetes).
        let quic_done = self
            .flows
            .get(&key)
            .map(|flujo| flujo.quic_done)
            .unwrap_or(false);
        if enabled && l4 == L4::Udp && !quic_done {
            if let Some(version) = quic::initial_version(payload) {
                let desde_cliente = estado.client_is_src.map(|rol| {
                    if rol {
                        meta.src() == key.origin
                    } else {
                        meta.src() != key.origin
                    }
                });
                let es_cliente = desde_cliente.unwrap_or_else(|| {
                    meta.dst_port == Some(PUERTO_TLS)
                        || meta.src_port.map(|puerto| puerto >= 32768).unwrap_or(false)
                });
                self.inspect_quic(
                    &key,
                    &estado,
                    payload,
                    version,
                    cliente_ip,
                    servidor_ip,
                    es_cliente,
                    now,
                    &mut out,
                );
            }
        }

        // 6) Reensamblado TCP o firma directa de UDP.
        let extra: Extraccion;
        let mut liberar = false;
        match l4 {
            L4::Tcp => {
                let Some(flujo) = self.flows.get_mut(&key) else {
                    return out;
                };
                flujo.last_seen = now;
                flujo.first_data.get_or_insert(now);
                let cliente_es_origen = match estado.client_is_src {
                    Some(rol) => rol,
                    None => match flujo.client_guess {
                        Some(adivinado) => adivinado,
                        None => {
                            let adivinado = meta.src() == key.origin;
                            flujo.client_guess = Some(adivinado);
                            adivinado
                        }
                    },
                };
                let es_c2s = if cliente_es_origen {
                    meta.src() == key.origin
                } else {
                    meta.src() != key.origin
                };
                let seq = meta.headers.as_ref().map(|cab| cab.tcp_seq).unwrap_or(0);
                flujo.packets_with_data = flujo.packets_with_data.saturating_add(1);
                let resultado = if es_c2s {
                    flujo.c2s.push(seq, payload)
                } else {
                    flujo.s2c.push(seq, payload)
                };
                let puertos = (meta.src_port.unwrap_or(0), meta.dst_port.unwrap_or(0));
                extra = extraer_tcp(
                    enabled,
                    &mut flujo.c2s,
                    &mut flujo.s2c,
                    puertos,
                    cliente_ip,
                    servidor_ip,
                    key,
                    &mut Flags {
                        protocol_done: flujo.protocol_done,
                        tls_done: flujo.tls_done,
                        http_done: flujo.http_done,
                        dns_done: flujo.dns_done,
                    },
                );
                // El estado de los flags se reconstruye del resultado: si hubo
                // evidencia de un extractor, queda marcado.
                if extra.tls {
                    flujo.tls_done = true;
                }
                if extra.http {
                    flujo.http_done = true;
                }
                if extra.dns {
                    flujo.dns_done = true;
                }
                if extra.protocol {
                    flujo.protocol_done = true;
                    if let Some(protocolo) = extra.protocolo {
                        if let Some(estado) = &mut flujo.state {
                            estado.app_protocol = Some(protocolo);
                        }
                    }
                }
                let agotado = matches!(resultado, PushResult::Complete | PushResult::Overflow)
                    || flujo.packets_with_data >= MAX_ASSEMBLY_PACKETS;
                liberar = agotado
                    || flujo.tls_done
                    || flujo.http_done
                    || (flujo.protocol_done && !es_candidato_tls(meta) && !es_candidato_http(meta));
            }
            L4::Udp => {
                extra = extraer_udp(
                    enabled,
                    payload,
                    (meta.src_port.unwrap_or(0), meta.dst_port.unwrap_or(0)),
                    cliente_ip,
                    servidor_ip,
                    key,
                );
                if let Some(flujo) = self.flows.get_mut(&key) {
                    flujo.last_seen = now;
                    if extra.protocol {
                        flujo.protocol_done = true;
                        if let Some(protocolo) = extra.protocolo {
                            if let Some(estado) = &mut flujo.state {
                                estado.app_protocol = Some(protocolo);
                            }
                        }
                    }
                }
            }
        }
        if liberar {
            if let Some(flujo) = self.flows.get_mut(&key) {
                flujo.c2s.release();
                flujo.s2c.release();
            }
        }

        // 7) Contadores y evidencias.
        if extra.inference_errors > 0 {
            self.counters.inference_errors = self
                .counters
                .inference_errors
                .saturating_add(extra.inference_errors);
        }
        let con_etiqueta = extra
            .evidencias
            .iter()
            .any(|evidencia| matches!(evidencia, Evidence::Flow(flujo) if flujo.app_protocol.is_some() || flujo.sni.is_some() || flujo.http_host.is_some() || flujo.ja4.is_some()));
        if con_etiqueta {
            if let Some(flujo) = self.flows.get_mut(&key) {
                if !flujo.labelled {
                    flujo.labelled = true;
                    self.counters.labelled_flows = self.counters.labelled_flows.saturating_add(1);
                }
            }
        }
        out.extend(extra.evidencias);
        // Completar rol y extremos en todas las evidencias del flujo: los
        // extractores no siempre los conocen.
        let rol = self
            .flows
            .get(&key)
            .and_then(|flujo| flujo.state.as_ref())
            .and_then(|estado| estado.client_is_src);
        for evidencia in &mut out {
            if let Evidence::Flow(flujo) = evidencia {
                if flujo.client_is_src.is_none() {
                    flujo.client_is_src = rol;
                }
                if flujo.client_ip.is_none() {
                    flujo.client_ip = cliente_ip;
                }
                if flujo.server_ip.is_none() {
                    flujo.server_ip = servidor_ip;
                }
            }
        }
        out
    }

    /// Avanza los temporizadores de los reensamblados.
    pub(crate) fn tick_impl(&mut self, now: Instant) {
        if self.flows.is_empty() {
            return;
        }
        let mut caducados = Vec::new();
        for (key, flujo) in &mut self.flows {
            let inactivo = now.saturating_duration_since(flujo.last_seen);
            if inactivo >= FLOW_IDLE_TIMEOUT {
                caducados.push(*key);
                continue;
            }
            if let Some(primero) = flujo.first_data {
                if now.saturating_duration_since(primero) >= ASSEMBLY_TIMEOUT
                    && (!flujo.c2s.is_finished() || !flujo.s2c.is_finished())
                {
                    flujo.c2s.release();
                    flujo.s2c.release();
                }
            }
            if flujo.quic.packets() >= QUIC_MAX_INITIALS && !flujo.quic_done {
                flujo.quic.release();
            }
        }
        for key in caducados {
            self.flows.remove(&key);
        }
    }

    /// Procesa un paquete Initial de QUIC.
    #[allow(clippy::too_many_arguments)]
    fn inspect_quic(
        &mut self,
        key: &ConnectionKey,
        _estado: &FlowState,
        payload: &[u8],
        version: quic::QuicVersion,
        cliente_ip: Option<IpAddr>,
        servidor_ip: Option<IpAddr>,
        es_cliente: bool,
        now: Instant,
        out: &mut Vec<Evidence>,
    ) {
        if !es_cliente {
            // Los Initial del servidor no se descifran con las claves del DCID
            // del cliente y no aportan SNI: se descartan en silencio.
            return;
        }
        match quic::decrypt_initial(payload, version) {
            Ok(descifrado) => {
                let Some(flujo) = self.flows.get_mut(key) else {
                    return;
                };
                flujo.last_seen = now;
                flujo.first_data.get_or_insert(now);
                for (offset, datos) in quic::crypto_frames(&descifrado) {
                    let _ = flujo.quic.push(offset, &datos);
                }
                if let Some(estado) = &mut flujo.state {
                    estado.quic = true;
                    if estado.app_protocol.is_none() {
                        estado.app_protocol = Some(AppProtocol::Quic);
                    }
                }
                if flujo.quic_done {
                    return;
                }
                let completo = flujo.quic.client_hello_complete()
                    || quic::contains_client_hello(flujo.quic.data());
                if completo {
                    match tls::parse_client_hello(flujo.quic.data()) {
                        Ok(hello) => {
                            let mut evidencia = FlowEvidence::empty(*key);
                            evidencia.app_protocol = Some(AppProtocol::Quic);
                            evidencia.quic = true;
                            evidencia.ja4 = Some(ja4::compute(&hello, ja4::Ja4Transport::Quic));
                            evidencia.sni = hello.sni.clone();
                            evidencia.client_is_src =
                                flujo.state.as_ref().and_then(|estado| estado.client_is_src);
                            evidencia.client_ip = cliente_ip;
                            evidencia.server_ip = servidor_ip;
                            if let (Some(sni), Some(servidor)) = (&hello.sni, servidor_ip) {
                                out.push(Evidence::Name(NameObservation {
                                    ip: servidor,
                                    name: sni.clone(),
                                    source: NameSource::Sni,
                                    requester: cliente_ip,
                                    ttl_seconds: Some(3600),
                                }));
                            }
                            out.push(Evidence::Flow(evidencia));
                            flujo.quic_done = true;
                            flujo.protocol_done = true;
                            if let Some(estado) = &mut flujo.state {
                                estado.app_protocol = Some(AppProtocol::Quic);
                            }
                            flujo.labelled = true;
                            self.counters.labelled_flows =
                                self.counters.labelled_flows.saturating_add(1);
                            flujo.quic.release();
                        }
                        Err(_) => {
                            if flujo.quic.packets() >= QUIC_MAX_INITIALS {
                                self.counters.inference_errors =
                                    self.counters.inference_errors.saturating_add(1);
                                flujo.quic_done = true;
                                flujo.quic.release();
                            }
                        }
                    }
                } else if flujo.quic.packets() >= QUIC_MAX_INITIALS {
                    // Sin ClientHello completo: se etiqueta por caché, ASN o puerto.
                    flujo.quic_done = true;
                    flujo.quic.release();
                    let mut evidencia = FlowEvidence::empty(*key);
                    evidencia.app_protocol = Some(AppProtocol::Quic);
                    evidencia.quic = true;
                    evidencia.client_ip = cliente_ip;
                    evidencia.server_ip = servidor_ip;
                    out.push(Evidence::Flow(evidencia));
                }
            }
            Err(_) => {
                self.counters.quic_errors = self.counters.quic_errors.saturating_add(1);
            }
        }
    }
}

/// Evidencias extraídas y estado de los extractores tras procesar un paquete.
#[derive(Debug, Default)]
struct Extraccion {
    evidencias: Vec<Evidence>,
    protocol: bool,
    protocolo: Option<AppProtocol>,
    tls: bool,
    http: bool,
    dns: bool,
    inference_errors: u64,
}

/// Extrae etiquetas del inicio de un flujo TCP reensamblado.
#[allow(clippy::too_many_arguments)]
fn extraer_tcp(
    enabled: bool,
    c2s: &mut StreamStart,
    s2c: &mut StreamStart,
    puertos: (u16, u16),
    cliente_ip: Option<IpAddr>,
    servidor_ip: Option<IpAddr>,
    key: ConnectionKey,
    flags: &mut Flags,
) -> Extraccion {
    let mut extra = Extraccion::default();
    if !enabled {
        // Con la inferencia desactivada no se lee el payload: solo quedan las
        // etiquetas débiles (servicio de F2, ASN, puerto y proceso) del agregador.
        return extra;
    }

    // TLS ClientHello: SNI y JA4 t….
    if !flags.tls_done && parece_tls(c2s.data(), puertos) {
        match tls::parse_client_hello(c2s.data()) {
            Ok(hello) => {
                let mut evidencia = FlowEvidence::empty(key);
                evidencia.app_protocol = Some(AppProtocol::Tls);
                evidencia.ja4 = Some(ja4::compute(&hello, ja4::Ja4Transport::Tcp));
                evidencia.sni = hello.sni.clone();
                evidencia.client_ip = cliente_ip;
                evidencia.server_ip = servidor_ip;
                if let (Some(sni), Some(servidor)) = (&hello.sni, servidor_ip) {
                    extra.evidencias.push(Evidence::Name(NameObservation {
                        ip: servidor,
                        name: sni.clone(),
                        source: NameSource::Sni,
                        requester: cliente_ip,
                        ttl_seconds: Some(3600),
                    }));
                }
                extra.evidencias.push(Evidence::Flow(evidencia));
                extra.tls = true;
                extra.protocol = true;
                extra.protocolo = Some(AppProtocol::Tls);
            }
            Err(_) => {
                if c2s.is_finished() {
                    extra.inference_errors = 1;
                    extra.tls = true;
                }
            }
        }
    }

    // HTTP/1.x en claro: Host y User-Agent.
    if !flags.http_done && parece_http(c2s.data(), puertos) {
        match http::parse_request(c2s.data()) {
            Some(peticion) => {
                let mut evidencia = FlowEvidence::empty(key);
                evidencia.app_protocol = Some(AppProtocol::Http);
                evidencia.http_host = peticion.host.clone();
                evidencia.user_agent = peticion.user_agent.clone();
                evidencia.client_ip = cliente_ip;
                evidencia.server_ip = servidor_ip;
                if let (Some(host), Some(servidor)) = (&peticion.host, servidor_ip) {
                    extra.evidencias.push(Evidence::Name(NameObservation {
                        ip: servidor,
                        name: host.clone(),
                        source: NameSource::Http,
                        requester: cliente_ip,
                        ttl_seconds: Some(3600),
                    }));
                }
                extra.evidencias.push(Evidence::Flow(evidencia));
                extra.http = true;
                extra.protocol = true;
                extra.protocolo = Some(AppProtocol::Http);
            }
            None => {
                if c2s.is_finished() {
                    extra.http = true;
                }
            }
        }
    }

    // DNS sobre TCP: longitud de 2 bytes por mensaje.
    if !flags.dns_done
        && (es_puerto_dns(puertos.0) || es_puerto_dns(puertos.1))
        && c2s.data().len() > 2
    {
        let mut observaciones = dns::extract_answers(
            &c2s.data()[2..],
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        );
        if !observaciones.is_empty() {
            for observacion in &mut observaciones {
                observacion.requester = cliente_ip;
            }
            extra
                .evidencias
                .extend(observaciones.into_iter().map(Evidence::Name));
            extra.dns = true;
            extra.protocol = true;
            extra.protocolo = Some(AppProtocol::Dns);
        }
    }

    // Firma genérica de protocolo cuando ningún extractor específico la resolvió
    // (SSH, FTP, SMB, MQTT… y también TLS/HTTP sin datos suficientes).
    if !flags.protocol_done && !extra.protocol && (!c2s.is_empty() || !s2c.is_empty()) {
        if let Some((protocolo, Certainty::Signature)) =
            protocols::identify(L4::Tcp, puertos, c2s.data(), s2c.data())
        {
            let mut evidencia = FlowEvidence::empty(key);
            evidencia.app_protocol = Some(protocolo);
            evidencia.client_ip = cliente_ip;
            evidencia.server_ip = servidor_ip;
            extra.evidencias.push(Evidence::Flow(evidencia));
            extra.protocol = true;
            extra.protocolo = Some(protocolo);
        }
    }

    extra
}

/// Extrae la firma de un datagrama UDP (DNS, mDNS, NTP, SSDP, STUN…).
fn extraer_udp(
    enabled: bool,
    payload: &[u8],
    puertos: (u16, u16),
    cliente_ip: Option<IpAddr>,
    servidor_ip: Option<IpAddr>,
    key: ConnectionKey,
) -> Extraccion {
    let mut extra = Extraccion::default();
    if !enabled {
        return extra;
    }
    if let Some((protocolo, _certeza)) = protocols::identify(L4::Udp, puertos, payload, &[]) {
        let mut evidencia = FlowEvidence::empty(key);
        evidencia.app_protocol = Some(protocolo);
        evidencia.client_ip = cliente_ip;
        evidencia.server_ip = servidor_ip;
        extra.evidencias.push(Evidence::Flow(evidencia));
        extra.protocol = true;
        extra.protocolo = Some(protocolo);
    }
    extra
}

/// Inspecciona un datagrama DHCP: identidad del equipo y protocolo.
fn inspeccionar_dhcp(key: &ConnectionKey, payload: &[u8]) -> Vec<Evidence> {
    let mut out = Vec::new();
    let Some(info) = identify::dhcp::parse(payload) else {
        return out;
    };
    let observacion = identify::dhcp::to_observation(&info);
    if let (Some(mac), Some(IpAddr::V4(ip))) = (observacion.mac.clone(), observacion.ip) {
        out.push(Evidence::Host(ObservedHost {
            mac,
            ip,
            source: ObservedSource::Dhcp,
            dhcp: Some(observacion.clone()),
        }));
    }
    if observacion.mac.is_some() {
        out.push(Evidence::Dhcp(observacion));
    }
    let mut evidencia = FlowEvidence::empty(*key);
    evidencia.app_protocol = Some(AppProtocol::Dhcp);
    evidencia.client_is_src = Some(
        key.origin.port == Some(PUERTO_DHCP_CLIENTE)
            || key.destination.port == Some(PUERTO_DHCP_CLIENTE),
    );
    out.push(Evidence::Flow(evidencia));
    out
}

/// Devuelve (cliente, servidor) según el rol; sin rol, el extremo local es el cliente.
fn extremos(
    estado: &FlowState,
    key: &ConnectionKey,
    local_ips: &HashSet<IpAddr>,
) -> (Option<IpAddr>, Option<IpAddr>) {
    match estado.client_is_src {
        Some(true) => (Some(key.origin.ip), Some(key.destination.ip)),
        Some(false) => (Some(key.destination.ip), Some(key.origin.ip)),
        None => {
            if local_ips.contains(&key.origin.ip) {
                (Some(key.origin.ip), Some(key.destination.ip))
            } else if local_ips.contains(&key.destination.ip) {
                (Some(key.destination.ip), Some(key.origin.ip))
            } else {
                (Some(key.origin.ip), Some(key.destination.ip))
            }
        }
    }
}

fn es_puerto_dhcp(puerto: Option<u16>) -> bool {
    matches!(
        puerto,
        Some(PUERTO_DHCP_CLIENTE) | Some(PUERTO_DHCP_SERVIDOR)
    )
}

fn es_puerto_dns(puerto: u16) -> bool {
    puerto == PUERTO_DNS
}

fn parece_tls(datos: &[u8], puertos: (u16, u16)) -> bool {
    puertos.0 == PUERTO_TLS
        || puertos.1 == PUERTO_TLS
        || datos.len() >= 3 && datos[0] == 0x16 && datos[1] == 0x03
}

fn parece_http(datos: &[u8], puertos: (u16, u16)) -> bool {
    if PUERTOS_HTTP.contains(&puertos.0) || PUERTOS_HTTP.contains(&puertos.1) {
        return true;
    }
    const METODOS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    METODOS
        .iter()
        .any(|metodo| datos.starts_with(metodo) || datos.starts_with(b"HTTP/1."))
}

fn es_candidato_tls(meta: &PacketMeta) -> bool {
    meta.src_port == Some(PUERTO_TLS) || meta.dst_port == Some(PUERTO_TLS)
}

fn es_candidato_http(meta: &PacketMeta) -> bool {
    meta.src_port
        .map(|puerto| PUERTOS_HTTP.contains(&puerto))
        .unwrap_or(false)
        || meta
            .dst_port
            .map(|puerto| PUERTOS_HTTP.contains(&puerto))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    use crate::capture::parser::Parser;
    use crate::capture::ParsedFrame;
    use crate::config::InferenceConfig;
    use crate::identify::observed::ObservedFilter;
    use crate::inference::role::ListenSet;
    use crate::inference::{catalog, AppProtocol, Evidence, FlowLabel, LabelResolver, NameSource};

    /// Lee las tramas Ethernet de un fichero pcap (little endian, EN10MB).
    fn leer_pcap(contenido: &[u8]) -> Vec<Vec<u8>> {
        assert!(contenido.len() >= 24, "cabecera pcap incompleta");
        let mut tramas = Vec::new();
        let mut posicion = 24;
        while posicion + 16 <= contenido.len() {
            let incl_len = u32::from_le_bytes([
                contenido[posicion + 8],
                contenido[posicion + 9],
                contenido[posicion + 10],
                contenido[posicion + 11],
            ]) as usize;
            posicion += 16;
            if posicion + incl_len > contenido.len() {
                break;
            }
            tramas.push(contenido[posicion..posicion + incl_len].to_vec());
            posicion += incl_len;
        }
        tramas
    }

    fn fixture() -> Vec<Vec<u8>> {
        let ruta = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/fase4-replay.pcap");
        leer_pcap(&std::fs::read(&ruta).expect("fixture de F4"))
    }

    fn inspector_prueba() -> FlowInspector {
        let mut locales: HashSet<IpAddr> = HashSet::new();
        locales.insert("192.168.1.49".parse().unwrap());
        FlowInspector::new(
            &InferenceConfig::default(),
            locales,
            Arc::new(RwLock::new(ListenSet::new())),
        )
    }

    fn resolver_prueba() -> LabelResolver {
        let (catalogo, _avisos) = catalog::Catalog::load(catalog::EMBEDDED, None);
        let mut locales: HashSet<IpAddr> = HashSet::new();
        locales.insert("192.168.1.49".parse().unwrap());
        LabelResolver::new(&InferenceConfig::default(), catalogo, None, locales)
    }

    /// Pasa el fixture mixto (TLS partido, QUIC, DNS, DHCP y ARP) por el
    /// inspector y devuelve las evidencias, incluidas las de equipos observados.
    fn inspeccionar_fixture() -> Vec<Evidence> {
        let mut inspector = inspector_prueba();
        let parser = Parser::with_defaults();
        let mut evidencias = Vec::new();
        let filtro = ObservedFilter {
            local_macs: HashSet::new(),
            local_ips: HashSet::from([Ipv4Addr::new(192, 168, 1, 49)]),
            networks: vec![(
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(255, 255, 255, 0),
            )],
            gateway_ip: None,
            gateway_mac: None,
        };
        let ahora = Instant::now();
        for trama in fixture() {
            match parser.parse_frame(&trama).expect("trama parseable") {
                ParsedFrame::Ip(paquete) => {
                    let payload = paquete.payload(&trama);
                    evidencias.extend(inspector.inspect(&paquete.meta, payload, ahora));
                    // Equipo observado por una trama IPv4 de la subred local.
                    if let IpAddr::V4(ip) = paquete.meta.src_ip {
                        let equipo = ObservedHost {
                            mac: crate::capture::formatear_mac(paquete.src_mac),
                            ip,
                            source: ObservedSource::Frame,
                            dhcp: None,
                        };
                        if filtro.accepts(&equipo) {
                            evidencias.push(Evidence::Host(equipo));
                        }
                    }
                }
                ParsedFrame::Arp(marco) => {
                    let equipo = ObservedHost {
                        mac: crate::capture::formatear_mac(marco.arp.sender_mac),
                        ip: marco.arp.sender_ip,
                        source: ObservedSource::Arp,
                        dhcp: None,
                    };
                    if filtro.accepts(&equipo) {
                        evidencias.push(Evidence::Host(equipo));
                    }
                }
                ParsedFrame::Ignorada(_) => {}
            }
        }
        // Los temporizadores no deben hacer perder evidencias ya emitidas.
        inspector.tick(ahora + Duration::from_secs(10));
        evidencias
    }

    #[test]
    fn replay_mixto_extrae_tls_dns_dhcp_arp_y_quic() {
        let evidencias = inspeccionar_fixture();

        // TLS partido en dos segmentos desordenados.
        let tls: Vec<&FlowEvidence> = evidencias
            .iter()
            .filter_map(|evidencia| match evidencia {
                Evidence::Flow(flujo)
                    if flujo.app_protocol == Some(AppProtocol::Tls) && flujo.ja4.is_some() =>
                {
                    Some(flujo)
                }
                _ => None,
            })
            .collect();
        assert!(!tls.is_empty(), "debe haber evidencia TLS: {evidencias:?}");
        let tls = tls[0];
        assert_eq!(tls.sni.as_deref(), Some("example.com"));
        assert_eq!(tls.client_is_src, Some(false));
        let ja4_tcp = tls.ja4.as_deref().expect("JA4 de TLS");
        assert!(ja4_tcp.starts_with("t13d"), "JA4 TLS inesperado: {ja4_tcp}");

        // QUIC Initial del RFC 9001 descifrado por el inspector.
        let quic: Vec<&FlowEvidence> = evidencias
            .iter()
            .filter_map(|evidencia| match evidencia {
                Evidence::Flow(flujo)
                    if flujo.quic && flujo.app_protocol == Some(AppProtocol::Quic) =>
                {
                    Some(flujo)
                }
                _ => None,
            })
            .collect();
        assert!(
            !quic.is_empty(),
            "debe haber evidencia QUIC: {evidencias:?}"
        );
        let quic = quic[0];
        assert_eq!(quic.sni.as_deref(), Some("example.com"));
        let ja4_quic = quic.ja4.as_deref().expect("JA4 de QUIC");
        assert!(ja4_quic.starts_with('q'), "JA4 QUIC inesperado: {ja4_quic}");

        // Respuesta DNS: la IP final queda asociada al nombre consultado.
        let nombres: Vec<_> = evidencias
            .iter()
            .filter_map(|evidencia| match evidencia {
                Evidence::Name(nombre) => Some(nombre.clone()),
                _ => None,
            })
            .collect();
        assert!(
            nombres.iter().any(|nombre| {
                nombre.name == "www.example.com"
                    && nombre.ip == "142.250.1.2".parse::<IpAddr>().unwrap()
                    && nombre.source == NameSource::Dns
            }),
            "observaciones DNS inesperadas: {nombres:?}"
        );

        // Identidad DHCP: opción 55, 60 y 12.
        let dhcp: Vec<_> = evidencias
            .iter()
            .filter_map(|evidencia| match evidencia {
                Evidence::Dhcp(identidad) => Some(identidad.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(dhcp.len(), 2, "DISCOVER y ACK: {dhcp:?}");
        assert_eq!(
            dhcp[0].fingerprint.as_deref(),
            Some("1,121,3,6,15,108,114,119,252")
        );
        assert_eq!(dhcp[0].vendor.as_deref(), Some("MSFT 5.0"));
        assert_eq!(dhcp[0].hostname.as_deref(), Some("equipo-dhcp"));

        // Equipos observados: ARP y DHCP con IP asignada.
        let observados: Vec<_> = evidencias
            .iter()
            .filter_map(|evidencia| match evidencia {
                Evidence::Host(equipo) => Some(equipo.clone()),
                _ => None,
            })
            .collect();
        assert!(
            observados
                .iter()
                .any(|equipo| equipo.mac == "aa:bb:cc:dd:ee:02"
                    && equipo.ip == Ipv4Addr::new(192, 168, 1, 60)
                    && equipo.source == ObservedSource::Arp),
            "falta el equipo observado por ARP: {observados:?}"
        );
        assert!(
            observados
                .iter()
                .any(|equipo| equipo.mac == "aa:bb:cc:dd:ee:01"
                    && equipo.ip == Ipv4Addr::new(192, 168, 1, 60)
                    && equipo.source == ObservedSource::Dhcp),
            "falta el equipo observado por DHCP: {observados:?}"
        );
    }

    #[test]
    fn replay_resuelve_etiquetas_y_cache_de_nombres() {
        let evidencias = inspeccionar_fixture();
        let mut resolver = resolver_prueba();
        let mut etiquetas: Vec<FlowLabel> = Vec::new();
        for evidencia in evidencias {
            match evidencia {
                Evidence::Name(nombre) => resolver.observe_name(nombre),
                Evidence::Flow(flujo) => etiquetas.push(resolver.resolve(&flujo.key, &flujo)),
                _ => {}
            }
        }

        // El flujo TLS queda etiquetado por SNI con JA4 y rol.
        let tls = etiquetas
            .iter()
            .find(|etiqueta| etiqueta.app_protocol == Some(AppProtocol::Tls))
            .expect("etiqueta TLS");
        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
        assert_eq!(tls.name_source, Some(NameSource::Sni));
        assert_eq!(tls.client_is_src, Some(false));
        assert!(tls.ja4.as_deref().unwrap_or_default().starts_with("t13d"));

        // La caché de nombres conserva la respuesta DNS.
        let entrada = resolver
            .names()
            .entries()
            .iter()
            .find(|entrada| entrada.name == "www.example.com")
            .expect("entrada en caché");
        assert_eq!(entrada.ip, "142.250.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(entrada.source, NameSource::Dns);
        assert!(entrada.expires_at > std::time::SystemTime::UNIX_EPOCH);
    }
}
