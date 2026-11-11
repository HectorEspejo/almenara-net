//! Panel de detalle de equipo (master-detail): identidad de F4 (modelo, SO y su
//! fuente, huella DHCP abreviada, MAC privada), tráfico de F3, top 5 de apps y
//! destinos de la ventana de 5 min, clientes TLS distintos (JA4), conexiones
//! activas y servicios de F2.
//!
//! Todo el panel se dibuja como una única lista de líneas desplazable con j/k
//! cuando tiene el foco y el contenido no cabe (F4).

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::identify::mac::is_private;
use crate::identify::OsSource;
use crate::rankings::RankRow;
use crate::repo::DeviceService;
use crate::traffic::{formatear_bytes, formatear_bytes_por_segundo, ConnectionView};
use crate::tui::app::App;
use crate::tui::theme::device_icon;
use crate::tui::traffic_state::FocusPanel;

/// Dibuja el panel de detalle de un equipo.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let estilo_borde = if app.detail_focus == FocusPanel::Detalle {
        app.theme.accent
    } else {
        app.theme.border
    };
    let Some(device) = app.detail_device().cloned() else {
        let bloque = Block::bordered()
            .border_style(estilo_borde)
            .title(Span::styled("Detalle de equipo", app.theme.title));
        let interior = bloque.inner(area);
        frame.render_widget(bloque, area);
        frame.render_widget(
            Paragraph::new(Span::styled(
                "El equipo seleccionado ya no existe; pulsa Esc para cerrar.",
                app.theme.warning,
            )),
            interior,
        );
        return;
    };

    let titulo = format!("Detalle: {} ({})", device.display_name(), device.ip);
    let bloque = Block::bordered()
        .border_style(estilo_borde)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let lineas = construir_lineas(app, &device, interior.width);

    // Desplazamiento del panel derecho cuando no cabe (j/k con el foco).
    let maximo = lineas.len().saturating_sub(usize::from(interior.height));
    app.detail_max_scroll = maximo;
    app.detail_scroll = app.detail_scroll.min(maximo);
    let desplazamiento = u16::try_from(app.detail_scroll).unwrap_or(u16::MAX);

    frame.render_widget(
        Paragraph::new(lineas)
            .style(app.theme.normal)
            .scroll((desplazamiento, 0)),
        interior,
    );
}

fn construir_lineas(
    app: &App,
    device: &crate::repo::devices::Device,
    ancho: u16,
) -> Vec<Line<'static>> {
    let mut lineas: Vec<Line> = Vec::new();

    // Identidad y estado.
    let (icono, estilo_icono) = device_icon(device, &app.theme);
    let estado = if device.is_online {
        "online"
    } else {
        "offline"
    };
    lineas.push(Line::from(vec![
        Span::styled(icono, estilo_icono),
        Span::styled(format!(" {} ", device.display_name()), app.theme.accent),
        Span::styled(format!("({})", device.ip), app.theme.normal),
        Span::styled(
            format!(" · {estado}"),
            if device.is_online {
                app.theme.online
            } else {
                app.theme.offline
            },
        ),
        Span::styled(format!(" (visto {})", device.last_seen), app.theme.dim),
    ]));
    let tipo = crate::classify::DeviceType::from_str(device.effective_device_type())
        .unwrap_or(crate::classify::DeviceType::Unknown);
    let vendor = device.vendor.clone().unwrap_or_else(|| "?".to_string());
    let modelo = device.model.clone().unwrap_or_else(|| "—".to_string());
    lineas.push(Line::from(vec![
        Span::styled(vendor, app.theme.normal),
        Span::styled(format!(" · {} · ", tipo.label()), app.theme.dim),
        Span::styled(
            device.os_family.clone().unwrap_or_else(|| "—".to_string()),
            app.theme.normal,
        ),
        Span::styled(
            format!(
                " (fuente: {})",
                os_source_label(device.os_source.as_deref())
            ),
            app.theme.dim,
        ),
        Span::styled(format!(" · modelo: {modelo}"), app.theme.dim),
    ]));
    let interfaz = app
        .interfaces
        .iter()
        .find(|interfaz| interfaz.id == device.interface_id)
        .map(|interfaz| interfaz.name.clone())
        .unwrap_or_else(|| "?".to_string());
    let mac = mac_abreviada(&device.mac);
    let privacidad = if is_private(&device.mac) {
        Span::styled(" (MAC privada)", app.theme.warning)
    } else {
        Span::styled("", app.theme.dim)
    };
    lineas.push(Line::from(vec![
        Span::styled("MAC: ", app.theme.accent),
        Span::styled(mac, app.theme.normal),
        privacidad,
        Span::styled(format!(" · interfaz: {interfaz}"), app.theme.dim),
    ]));
    let mut dhcp = Line::from(vec![Span::styled("DHCP: ", app.theme.accent)]);
    match device.dhcp_fingerprint.as_deref() {
        Some(huella) => {
            dhcp.spans.push(Span::styled(
                format!("huella {}", huella_dhcp_abreviada(huella)),
                app.theme.normal,
            ));
        }
        None => dhcp.spans.push(Span::styled("sin huella", app.theme.dim)),
    }
    if let Some(nombre) = device.dhcp_hostname.as_deref() {
        dhcp.spans
            .push(Span::styled(format!(" · nombre «{nombre}»"), app.theme.dim));
    }
    if let Some(proveedor) = device.dhcp_vendor.as_deref() {
        dhcp.spans.push(Span::styled(
            format!(" · proveedor «{proveedor}»"),
            app.theme.dim,
        ));
    }
    lineas.push(dhcp);
    lineas.push(Line::from(""));

    // Tráfico (F3).
    lineas.push(Line::from(Span::styled("Tráfico", app.theme.accent)));
    let estadisticas = app.traffic.device_stats(device.id);
    match &estadisticas {
        Some(estadisticas) => {
            let ancho_serie = usize::from(ancho).saturating_sub(12).max(10);
            let serie_60 = sumar_series(&estadisticas.series_60s_in, &estadisticas.series_60s_out);
            let serie_5min =
                sumar_series(&estadisticas.series_5min_in, &estadisticas.series_5min_out);
            lineas.push(Line::from(vec![
                Span::styled("  60 s: ", app.theme.dim),
                Span::styled(ultimos(&serie_60, ancho_serie), app.theme.accent),
            ]));
            lineas.push(Line::from(vec![
                Span::styled("  ↓ ", app.theme.online),
                Span::styled(
                    formatear_bytes_por_segundo(estadisticas.rate_in),
                    app.theme.normal,
                ),
                Span::styled("   ↑ ", app.theme.accent),
                Span::styled(
                    formatear_bytes_por_segundo(estadisticas.rate_out),
                    app.theme.normal,
                ),
                Span::styled("   pico ", app.theme.dim),
                Span::styled(
                    formatear_bytes_por_segundo(estadisticas.peak_bps),
                    app.theme.normal,
                ),
            ]));
            lineas.push(Line::from(vec![
                Span::styled("  5 min: ", app.theme.dim),
                Span::styled(ultimos(&serie_5min, ancho_serie), app.theme.accent),
            ]));
            let puertos = estadisticas
                .top_ports
                .iter()
                .take(5)
                .map(|puerto| {
                    format!(
                        "{}/{} {}",
                        puerto.port,
                        puerto.protocol.as_str(),
                        formatear_bytes(puerto.bytes)
                    )
                })
                .collect::<Vec<_>>();
            let resumen = if puertos.is_empty() {
                "—".to_string()
            } else {
                puertos.join(" · ")
            };
            lineas.push(Line::from(vec![
                Span::styled("  Top puertos (5): ", app.theme.dim),
                Span::styled(resumen, app.theme.normal),
            ]));
        }
        None => {
            lineas.push(Line::from(Span::styled(
                "  Sin tráfico observado todavía para este equipo",
                app.theme.dim,
            )));
        }
    }
    lineas.push(Line::from(""));

    // Top 5 de apps y destinos (ventana de 5 min).
    let ranking = app.traffic.device_ranking(device.id);
    let (apps, destinos, cabecera_apps) = match ranking {
        Some(ranking) if !ranking.apps.is_empty() || !ranking.destinations.is_empty() => (
            ranking.apps.iter().take(5).cloned().collect::<Vec<_>>(),
            ranking
                .destinations
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>(),
            "Top apps (5 min)",
        ),
        _ => {
            let (apps, destinos) = resumen_desde_conexiones(app, device);
            (apps, destinos, "Top apps (conexiones activas)")
        }
    };
    let ancho_mitad = (usize::from(ancho).saturating_sub(4) / 2).max(12);
    lineas.push(Line::from(vec![
        Span::styled(cabecera_apps, app.theme.accent),
        Span::styled(
            format!(
                "{}{}",
                " ".repeat(ancho_mitad.saturating_sub(18)),
                "Top destinos"
            ),
            app.theme.accent,
        ),
    ]));
    let total_apps: u64 = apps.iter().map(RankRow::total).sum();
    let total_destinos: u64 = destinos.iter().map(RankRow::total).sum();
    for posicion in 0..5 {
        let izquierda = fila_par(app, apps.get(posicion), total_apps, ancho_mitad);
        let derecha = fila_par(app, destinos.get(posicion), total_destinos, ancho_mitad);
        lineas.push(Line::from(vec![izquierda, derecha]));
    }
    lineas.push(Line::from(""));

    // Clientes TLS distintos (JA4).
    let (ja4, distintos) = clientes_tls(app, device);
    let texto_ja4 = match ja4.first() {
        Some(huella) => {
            let mut texto = format!("{huella} ({distintos} distintos)");
            if let Some(segunda) = ja4.get(1) {
                texto.push_str(&format!(" · {segunda}"));
            }
            texto
        }
        None => "—".to_string(),
    };
    lineas.push(Line::from(vec![
        Span::styled("Clientes TLS (JA4): ", app.theme.accent),
        Span::styled(texto_ja4, app.theme.normal),
    ]));

    // Conexiones activas (F3).
    let conexiones = app.traffic.connections_of_ip(&device.ip);
    let titulo_conexiones = format!("Conexiones activas ({})", conexiones.len());
    lineas.push(Line::from(Span::styled(
        titulo_conexiones,
        app.theme.accent,
    )));
    if conexiones.is_empty() {
        lineas.push(Line::from(Span::styled(
            "  (sin conexiones)",
            app.theme.dim,
        )));
    } else {
        for conexion in conexiones.iter().take(5) {
            lineas.push(linea_conexion(app, device, conexion));
        }
    }

    // Servicios de Fase 2.
    let servicios = app.detail_services();
    let texto_servicios = if servicios.is_empty() {
        "Servicios (F2): —".to_string()
    } else {
        format!(
            "Servicios (F2): {}",
            servicios
                .iter()
                .take(8)
                .map(descripcion_servicio)
                .collect::<Vec<_>>()
                .join(" · ")
        )
    };
    lineas.push(Line::from(Span::styled(texto_servicios, app.theme.dim)));

    lineas
}

/// Identidad de SO a partir de la señal persistida.
pub fn os_source_label(valor: Option<&str>) -> String {
    valor
        .and_then(OsSource::from_str)
        .map(|fuente| fuente.label().to_string())
        .unwrap_or_else(|| "desconocida".to_string())
}

/// Abrevia una MAC como «5a:1c:…:9e».
pub fn mac_abreviada(mac: &str) -> String {
    let octetos: Vec<&str> = mac.split(':').collect();
    if octetos.len() <= 3 {
        return mac.to_string();
    }
    format!(
        "{}:{}:…:{}",
        octetos[0],
        octetos[1],
        octetos[octetos.len() - 1]
    )
}

/// Abrevia una huella DHCP (opción 55) a los primeros valores.
pub fn huella_dhcp_abreviada(huella: &str) -> String {
    let valores: Vec<&str> = huella
        .split(',')
        .map(str::trim)
        .filter(|valor| !valor.is_empty())
        .collect();
    if valores.len() <= 8 {
        return huella.trim().to_string();
    }
    format!("{},…", valores[..8].join(","))
}

fn sumar_series(entrada: &[u64; 60], salida: &[u64; 60]) -> Vec<u64> {
    entrada
        .iter()
        .zip(salida.iter())
        .map(|(a, b)| a.saturating_add(*b))
        .collect()
}

/// Últimos n puntos de la serie, dibujados como sparkline.
fn ultimos(serie: &[u64], n: usize) -> String {
    let inicio = serie.len().saturating_sub(n.max(1));
    crate::traffic::sparkline(&serie[inicio..])
}

fn descripcion_servicio(servicio: &DeviceService) -> String {
    match servicio.service.as_deref() {
        Some(nombre) => format!("{}/{} {nombre}", servicio.port, servicio.protocol.as_str()),
        None => format!("{}/{}", servicio.port, servicio.protocol.as_str()),
    }
}

/// Celda izquierda o derecha de la tabla de dos columnas del detalle.
fn fila_par(app: &App, fila: Option<&RankRow>, total: u64, ancho: usize) -> Span<'static> {
    match fila {
        Some(fila) => {
            let porcentaje = if total > 0 {
                (fila.total() as f64 * 100.0 / total as f64).round() as u32
            } else {
                0
            };
            let etiqueta = if fila.label.trim().is_empty() {
                fila.key.clone()
            } else {
                fila.label.clone()
            };
            let ancho_etiqueta = ancho.saturating_sub(16).max(6);
            let etiqueta = recortar(&etiqueta, ancho_etiqueta);
            Span::styled(
                format!(
                    "  {etiqueta:<ancho_etiqueta$} {:>8} {porcentaje:>3} %",
                    formatear_bytes(fila.total()),
                ),
                app.theme.normal,
            )
        }
        None => Span::styled("", app.theme.normal),
    }
}

/// Recorta un texto y añade puntos suspensivos si no cabe.
fn recortar(texto: &str, ancho: usize) -> String {
    if texto.chars().count() <= ancho {
        return texto.to_string();
    }
    let mut recortado: String = texto.chars().take(ancho.saturating_sub(1)).collect();
    recortado.push('…');
    recortado
}

/// Top de apps y destinos calculado con las conexiones activas (respaldo).
fn resumen_desde_conexiones(
    app: &App,
    device: &crate::repo::devices::Device,
) -> (Vec<RankRow>, Vec<RankRow>) {
    use std::collections::HashMap;
    let mut apps: HashMap<String, (String, u64)> = HashMap::new();
    let mut destinos: HashMap<String, (String, u64)> = HashMap::new();
    for conexion in app.traffic.connections_of_ip(&device.ip) {
        let bytes = conexion.bytes_in.saturating_add(conexion.bytes_out);
        if bytes == 0 {
            continue;
        }
        let app = conexion.app_label();
        let entrada = apps.entry(app.clone()).or_insert_with(|| (app.clone(), 0));
        entrada.1 = entrada.1.saturating_add(bytes);
        let (_, _, servidor) = crate::tui::traffic_state::lados_conexion(conexion);
        let destino = conexion
            .label
            .as_ref()
            .and_then(|etiqueta| etiqueta.server_name.clone())
            .unwrap_or_else(|| servidor.ip.to_string());
        let entrada = destinos
            .entry(destino.clone())
            .or_insert_with(|| (destino.clone(), 0));
        entrada.1 = entrada.1.saturating_add(bytes);
    }
    let mut apps: Vec<RankRow> = apps
        .into_values()
        .map(|(etiqueta, bytes)| rank_row(etiqueta, bytes))
        .collect();
    let mut destinos: Vec<RankRow> = destinos
        .into_values()
        .map(|(etiqueta, bytes)| rank_row(etiqueta, bytes))
        .collect();
    apps.sort_by(|a, b| {
        b.total()
            .cmp(&a.total())
            .then_with(|| a.label.cmp(&b.label))
    });
    destinos.sort_by(|a, b| {
        b.total()
            .cmp(&a.total())
            .then_with(|| a.label.cmp(&b.label))
    });
    apps.truncate(5);
    destinos.truncate(5);
    (apps, destinos)
}

fn rank_row(etiqueta: String, bytes: u64) -> RankRow {
    RankRow {
        key: etiqueta.clone(),
        label: etiqueta,
        subtitle: None,
        device_id: None,
        bytes_down: bytes,
        bytes_up: 0,
        devices: 1,
        connections: 0,
        series_60s: [0; 60],
    }
}

/// Huellas JA4 distintas del equipo (de sus conexiones activas).
fn clientes_tls(app: &App, device: &crate::repo::devices::Device) -> (Vec<String>, usize) {
    let mut huellas: Vec<String> = Vec::new();
    for conexion in app.traffic.connections_of_ip(&device.ip) {
        if conexion.device_id != Some(device.id)
            && conexion.origin.device_id != Some(device.id)
            && conexion.destination.device_id != Some(device.id)
        {
            continue;
        }
        if let Some(huella) = conexion
            .label
            .as_ref()
            .and_then(|etiqueta| etiqueta.ja4.clone())
        {
            if !huellas.contains(&huella) {
                huellas.push(huella);
            }
        }
    }
    let distintos = huellas.len();
    (huellas, distintos)
}

/// Línea compacta de una conexión activa del equipo.
fn linea_conexion(
    app: &App,
    device: &crate::repo::devices::Device,
    conexion: &ConnectionView,
) -> Line<'static> {
    let (_, cliente, servidor) = crate::tui::traffic_state::lados_conexion(conexion);
    let es_cliente = cliente.ip.to_string() == device.ip;
    let otro = if es_cliente {
        conexion
            .label
            .as_ref()
            .and_then(|etiqueta| etiqueta.server_name.clone())
            .unwrap_or_else(|| servidor.ip.to_string())
    } else {
        cliente.ip.to_string()
    };
    let flecha = if es_cliente { "→" } else { "←" };
    Line::from(vec![
        Span::styled(format!("  {flecha} {otro}  "), app.theme.normal),
        Span::styled(
            format!(
                "{} · {} · {}",
                conexion.app_label(),
                conexion.state_label(),
                conexion.age_label()
            ),
            app.theme.dim,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::aggregate::DeviceTraffic;
    use crate::capture::{ConnectionKey, Endpoint, Protocol as CaptureProtocol};
    use crate::config::Config;
    use crate::inference::{DestinationInfo, DestinationKind, FlowLabel};
    use crate::rankings::{RankRow, Window};
    use crate::repo::devices::Device;
    use crate::repo::{DeviceService, Protocol as RepoProtocol};
    use crate::traffic::{ConnectionView, DeviceRankingView, EndpointView};
    use crate::tui::app::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba")
    }

    fn dispositivo() -> Device {
        Device {
            id: 1,
            mac: "5a:1c:2d:3e:4f:9e".to_string(),
            ip: "192.168.1.57".to_string(),
            hostname: Some("iPhone-Marta".to_string()),
            vendor: Some("Apple".to_string()),
            interface_id: 1,
            device_type: "mobile".to_string(),
            is_online: true,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:03Z".to_string(),
            alias: None,
            notes: None,
            os_family: Some("ios".to_string()),
            device_type_manual: None,
            last_fingerprint: None,
            model: Some("iPhone15,3".to_string()),
            dhcp_fingerprint: Some("1,121,3,6,15,108,114,119,252".to_string()),
            dhcp_vendor: Some("android-dhcp-13".to_string()),
            dhcp_hostname: Some("iPhone-de-Marta".to_string()),
            user_agent: None,
            os_source: Some("model".to_string()),
        }
    }

    fn estadisticas() -> DeviceTraffic {
        DeviceTraffic {
            device_id: 1,
            bytes_in: 120_000,
            bytes_out: 45_000,
            packets_in: 10,
            packets_out: 5,
            rate_in: 120_000,
            rate_out: 45_000,
            peak_bps: 410_000,
            series_60s_in: [1; 60],
            series_60s_out: [0; 60],
            series_5min_in: [1; 60],
            series_5min_out: [0; 60],
            top_ports: vec![crate::capture::aggregate::PortStat {
                port: 443,
                protocol: CaptureProtocol::Tcp,
                bytes: 1_200_000,
            }],
        }
    }

    fn fila(clave: &str, etiqueta: &str, bytes: u64) -> RankRow {
        RankRow {
            key: clave.to_string(),
            label: etiqueta.to_string(),
            subtitle: None,
            device_id: None,
            bytes_down: bytes,
            bytes_up: 0,
            devices: 1,
            connections: 1,
            series_60s: [0; 60],
        }
    }

    fn conexion_ja4(huella: &str) -> ConnectionView {
        let mut etiqueta = FlowLabel::empty(ip("17.253.1.1"));
        etiqueta.client_is_src = Some(true);
        etiqueta.server_name = Some("icloud.com".to_string());
        etiqueta.ja4 = Some(huella.to_string());
        etiqueta.destination = DestinationInfo {
            key: "icloud.com".to_string(),
            label: "icloud.com".to_string(),
            org: Some("Apple Inc.".to_string()),
            country: Some("US".to_string()),
            kind: DestinationKind::Domain,
        };
        ConnectionView {
            key: ConnectionKey::from_endpoints(
                CaptureProtocol::Tcp,
                Endpoint::new(ip("192.168.1.57"), Some(50000)),
                Endpoint::new(ip("17.253.1.1"), Some(443)),
            ),
            state: Some("ESTABLISHED".to_string()),
            bytes_in: 1_000,
            bytes_out: 100,
            age: Duration::from_secs(60),
            idle: Duration::from_secs(2),
            pid: None,
            comm: None,
            device_id: Some(1),
            origin: EndpointView {
                ip: ip("192.168.1.57"),
                port: Some(50000),
                device_id: Some(1),
                tag: None,
            },
            destination: EndpointView {
                ip: ip("17.253.1.1"),
                port: Some(443),
                device_id: None,
                tag: Some("?"),
            },
            headers: None,
            seen_capture: true,
            seen_kernel: true,
            label: Some(etiqueta),
            app_name: Some("iCloud".to_string()),
            category_name: Some("Nube".to_string()),
        }
    }

    fn app_detalle() -> App {
        let mut app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        );
        app.set_data(vec![dispositivo()], Vec::new());
        app.traffic.devices = vec![estadisticas()];
        app.traffic.device_rankings = vec![DeviceRankingView {
            device_id: 1,
            window: Window::FiveMin,
            apps: vec![
                fila("instagram", "Instagram", 2_100_000),
                fila("whatsapp", "WhatsApp", 900_000),
            ],
            destinations: vec![
                fila("cdninstagram.com", "cdninstagram.com", 1_900_000),
                fila("whatsapp.net", "whatsapp.net", 900_000),
            ],
        }];
        app.traffic.connections = vec![
            conexion_ja4("t13d1516h2_8daaf6152771_02713d6af862"),
            conexion_ja4("t13d1517h2_9daaf6152771_02713d6af863"),
        ];
        let servicios = vec![DeviceService {
            id: 1,
            device_id: 1,
            port: 22,
            protocol: RepoProtocol::Tcp,
            service: Some("ssh".to_string()),
            banner: None,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:03Z".to_string(),
        }];
        app.open_detail(1, servicios, true);
        app
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app, frame.area()))
            .expect("dibujado del detalle");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    fn tecla(codigo: KeyCode) -> KeyEvent {
        KeyEvent::new(codigo, KeyModifiers::NONE)
    }

    #[test]
    fn el_detalle_muestra_la_identidad_de_f4() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 120, 40);
        assert!(texto.contains("Detalle: iPhone-Marta (192.168.1.57)"));
        assert!(texto.contains("modelo: iPhone15,3"));
        assert!(texto.contains("ios"));
        assert!(texto.contains("fuente: modelo"));
        assert!(
            texto.contains("MAC: 5a:1c:…:9e (MAC privada)"),
            "la MAC se abrevia y se marca como privada"
        );
        assert!(texto.contains("huella 1,121,3,6,15,108,114,119,…"));
        assert!(texto.contains("nombre «iPhone-de-Marta»"));
        assert!(texto.contains("proveedor «android-dhcp-13»"));
    }

    #[test]
    fn el_detalle_muestra_top_apps_y_destinos_de_cinco_minutos() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 160, 40);
        assert!(texto.contains("Top apps (5 min)"));
        assert!(texto.contains("Top destinos"));
        assert!(texto.contains("Instagram"));
        assert!(texto.contains("WhatsApp"));
        assert!(texto.contains("cdninstagram.com"));
        assert!(texto.contains("whatsapp.net"));
        assert!(texto.contains("2.1 M"), "los bytes se formatean compactos");
    }

    #[test]
    fn el_detalle_sin_ranking_usa_las_conexiones_activas() {
        let mut app = app_detalle();
        app.traffic.device_rankings.clear();
        let texto = dibujar(&mut app, 160, 40);
        assert!(texto.contains("Top apps (conexiones activas)"));
        assert!(texto.contains("iCloud"));
        assert!(texto.contains("icloud.com"));
    }

    #[test]
    fn el_detalle_muestra_los_clientes_tls_distintos() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 160, 40);
        assert!(texto.contains("Clientes TLS (JA4):"));
        assert!(texto.contains("t13d1516h2_8daaf6152771_02713d6af862"));
        assert!(texto.contains("(2 distintos)"));
    }

    #[test]
    fn el_detalle_mantiene_el_trafico_las_conexiones_y_los_servicios_de_f3() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 160, 44);
        assert!(texto.contains("Tráfico"));
        assert!(texto.contains("60 s:"));
        assert!(texto.contains("5 min:"));
        assert!(texto.contains("Top puertos (5): 443/tcp 1.2 M"));
        assert!(texto.contains("Conexiones activas (2)"));
        assert!(texto.contains("Servicios (F2): 22/tcp ssh"));
    }

    #[test]
    fn el_detalle_se_desplaza_con_j_k_cuando_no_cabe() {
        let mut app = app_detalle();
        let _ = dibujar(&mut app, 100, 16);
        assert!(
            app.detail_max_scroll > 0,
            "a poca altura el panel debe poder desplazarse"
        );
        assert!(app.detail_focus == FocusPanel::Detalle);
        app.handle_key(tecla(KeyCode::Char('j')));
        assert_eq!(app.detail_scroll, 1);
        for _ in 0..50 {
            app.handle_key(tecla(KeyCode::Char('j')));
        }
        assert_eq!(app.detail_scroll, app.detail_max_scroll);
        app.handle_key(tecla(KeyCode::Char('k')));
        assert_eq!(app.detail_scroll, app.detail_max_scroll - 1);
        // El dibujado mantiene el desplazamiento dentro de límites.
        let _ = dibujar(&mut app, 100, 16);
        assert!(app.detail_scroll <= app.detail_max_scroll);
    }

    #[test]
    fn el_detalle_de_un_equipo_inexistente_avisa() {
        let mut app = app_detalle();
        app.close_detail();
        app.open_detail(99, Vec::new(), true);
        let texto = dibujar(&mut app, 120, 24);
        assert!(texto.contains("ya no existe"));
    }

    #[test]
    fn los_formateos_del_detalle_abrevian_mac_y_huella() {
        assert_eq!(mac_abreviada("5a:1c:2d:3e:4f:9e"), "5a:1c:…:9e");
        assert_eq!(mac_abreviada("00:11:22"), "00:11:22");
        assert_eq!(
            huella_dhcp_abreviada("1,121,3,6,15,108,114,119,252"),
            "1,121,3,6,15,108,114,119,…"
        );
        assert_eq!(huella_dhcp_abreviada("1,3,6"), "1,3,6");
        assert_eq!(os_source_label(Some("model")), "modelo");
        assert_eq!(os_source_label(Some("dhcp")), "DHCP");
        assert_eq!(os_source_label(Some("ua")), "User-Agent");
        assert_eq!(os_source_label(None), "desconocida");
    }
}
