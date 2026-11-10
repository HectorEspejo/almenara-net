//! Panel de detalle de equipo (master-detail) de la pestaña Equipos.
//!
//! Muestra identidad y estado del equipo, las sparklines de 60 s y 5 min con
//! sus ritmos y pico, el top-5 de puertos, las conexiones activas y los
//! servicios detectados en Fase 2 (DEVICE_SERVICES).

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::repo::DeviceService;
use crate::traffic::{formatear_bytes_por_segundo, sparkline};
use crate::tui::app::App;
use crate::tui::theme::device_icon;
use crate::tui::traffic_state::FocusPanel;

/// Dibuja el panel de detalle de un equipo.
pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let estilo_borde = if app.detail_focus == FocusPanel::Detalle {
        app.theme.accent
    } else {
        app.theme.border
    };
    let Some(device) = app.detail_device() else {
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

    let zonas = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(5),
        Constraint::Min(6),
        Constraint::Length(2),
    ])
    .split(interior);

    // Identidad y estado.
    let (icono, estilo_icono) = device_icon(device, &app.theme);
    let tipo = crate::classify::DeviceType::from_str(device.effective_device_type())
        .unwrap_or(crate::classify::DeviceType::Unknown);
    let vendor = device.vendor.clone().unwrap_or_else(|| "?".to_string());
    let familia = device.os_family.clone().unwrap_or_else(|| "?".to_string());
    let estado = if device.is_online {
        "online"
    } else {
        "offline"
    };
    let interfaz = app
        .interfaces
        .iter()
        .find(|interfaz| interfaz.id == device.interface_id)
        .map(|interfaz| interfaz.name.clone())
        .unwrap_or_else(|| "?".to_string());
    let identidad = vec![
        Line::from(vec![
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
        ]),
        Line::from(Span::styled(
            format!("{vendor} · {} · {familia}", tipo.label()),
            app.theme.normal,
        )),
        Line::from(Span::styled(
            format!("MAC: {} · interfaz: {interfaz}", device.mac),
            app.theme.dim,
        )),
    ];
    frame.render_widget(Paragraph::new(identidad), zonas[0]);

    // Tráfico de la ventana de 60 s y 5 min.
    let estadisticas = app.traffic.device_stats(device.id);
    let mut trafico: Vec<Line> = Vec::new();
    trafico.push(Line::from(Span::styled("Tráfico", app.theme.accent)));
    match &estadisticas {
        Some(estadisticas) => {
            let ancho = usize::from(zonas[1].width).saturating_sub(7).max(10);
            let serie_60 = sumar_series(&estadisticas.series_60s_in, &estadisticas.series_60s_out);
            let serie_5min =
                sumar_series(&estadisticas.series_5min_in, &estadisticas.series_5min_out);
            trafico.push(Line::from(vec![
                Span::styled("60s: ", app.theme.dim),
                Span::styled(ultimos(&serie_60, ancho), app.theme.accent),
            ]));
            trafico.push(Line::from(vec![
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
            trafico.push(Line::from(vec![
                Span::styled("5min: ", app.theme.dim),
                Span::styled(
                    ultimos(&serie_5min, ancho.saturating_sub(1)),
                    app.theme.accent,
                ),
            ]));
        }
        None => {
            trafico.push(Line::from(Span::styled(
                "Sin tráfico observado todavía para este equipo",
                app.theme.dim,
            )));
        }
    }
    frame.render_widget(Paragraph::new(trafico), zonas[1]);

    // Dos columnas: top-5 puertos y conexiones activas.
    let columnas = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(zonas[2]);
    let puertos = estadisticas
        .as_ref()
        .map(|estadisticas| {
            estadisticas
                .top_ports
                .iter()
                .take(5)
                .map(|puerto| {
                    format!(
                        "  {}/{}  {}",
                        puerto.port,
                        puerto.protocol.as_str(),
                        crate::traffic::formatear_bytes(puerto.bytes)
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut lineas_puertos: Vec<Line> = vec![Line::from(Span::styled(
        "Top puertos (5)",
        app.theme.accent,
    ))];
    if puertos.is_empty() {
        lineas_puertos.push(Line::from(Span::styled("  (sin datos)", app.theme.dim)));
    } else {
        for puerto in puertos {
            lineas_puertos.push(Line::from(Span::styled(puerto, app.theme.normal)));
        }
    }
    frame.render_widget(Paragraph::new(lineas_puertos), columnas[0]);

    let conexiones = app.traffic.connections_of_ip(&device.ip);
    let mut lineas_conexiones: Vec<Line> = vec![Line::from(Span::styled(
        "Conexiones activas (5)",
        app.theme.accent,
    ))];
    if conexiones.is_empty() {
        lineas_conexiones.push(Line::from(Span::styled(
            "  (sin conexiones)",
            app.theme.dim,
        )));
    } else {
        for conexion in conexiones.iter().take(5) {
            let otro = if conexion.origin.ip.to_string() == device.ip {
                conexion.destination.display()
            } else {
                conexion.origin.display()
            };
            lineas_conexiones.push(Line::from(vec![
                Span::styled(format!("  → {otro}  "), app.theme.normal),
                Span::styled(
                    format!("{}  {}", conexion.state_label(), conexion.age_label()),
                    app.theme.dim,
                ),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lineas_conexiones), columnas[1]);

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
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(texto_servicios, app.theme.dim))),
        zonas[3],
    );
}

fn descripcion_servicio(servicio: &DeviceService) -> String {
    match servicio.service.as_deref() {
        Some(nombre) => format!("{}/{} {nombre}", servicio.port, servicio.protocol.as_str()),
        None => format!("{}/{}", servicio.port, servicio.protocol.as_str()),
    }
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
    sparkline(&serie[inicio..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::aggregate::DeviceTraffic;
    use crate::capture::{ConnectionKey, Endpoint, Protocol as CaptureProtocol};
    use crate::classify::DeviceType;
    use crate::config::Config;
    use crate::repo::devices::Device;
    use crate::repo::{DeviceService, Protocol as RepoProtocol};
    use crate::traffic::{ConnectionView, EndpointView};
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba")
    }

    fn dispositivo() -> Device {
        let mut device = Device {
            id: 1,
            mac: "aa:bb:cc:dd:ee:01".to_string(),
            ip: "192.168.1.42".to_string(),
            hostname: Some("laptop-juan".to_string()),
            vendor: Some("Apple".to_string()),
            interface_id: 1,
            device_type: "pc".to_string(),
            is_online: true,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-11-10T10:00:00Z".to_string(),
            alias: None,
            notes: None,
            os_family: Some("macos".to_string()),
            device_type_manual: None,
            last_fingerprint: None,
        };
        device.device_type = DeviceType::Pc.as_str().to_string();
        device
    }

    fn servicio(port: u16, nombre: &str) -> DeviceService {
        DeviceService {
            id: i64::from(port),
            device_id: 1,
            port,
            protocol: RepoProtocol::Tcp,
            service: Some(nombre.to_string()),
            banner: None,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
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
        let device = dispositivo();
        app.set_data(vec![device.clone()], Vec::new());
        let mut serie_60 = [0u64; 60];
        serie_60[59] = 10_000;
        let mut serie_5 = [0u64; 60];
        serie_5[59] = 50_000;
        app.traffic.devices = vec![DeviceTraffic {
            device_id: 1,
            bytes_in: 1_500_000,
            bytes_out: 320_000,
            packets_in: 120,
            packets_out: 40,
            rate_in: 1400,
            rate_out: 320,
            peak_bps: 1_900_000,
            series_60s_in: serie_60,
            series_60s_out: [0; 60],
            series_5min_in: serie_5,
            series_5min_out: [0; 60],
            top_ports: vec![
                crate::capture::aggregate::PortStat {
                    port: 443,
                    protocol: CaptureProtocol::Tcp,
                    bytes: 1_500_000,
                },
                crate::capture::aggregate::PortStat {
                    port: 22,
                    protocol: CaptureProtocol::Tcp,
                    bytes: 280_000,
                },
            ],
        }];
        app.traffic.connections = vec![ConnectionView {
            key: ConnectionKey::from_endpoints(
                CaptureProtocol::Tcp,
                Endpoint::new(ip("192.168.1.42"), Some(50000)),
                Endpoint::new(ip("140.82.0.1"), Some(443)),
            ),
            state: Some("ESTABLISHED".to_string()),
            bytes_in: 100,
            bytes_out: 200,
            age: Duration::from_secs(60),
            idle: Duration::from_secs(1),
            pid: None,
            comm: None,
            device_id: Some(1),
            origin: EndpointView {
                ip: ip("192.168.1.42"),
                port: Some(50000),
                device_id: Some(1),
                tag: None,
            },
            destination: EndpointView {
                ip: ip("140.82.0.1"),
                port: Some(443),
                device_id: None,
                tag: Some("?"),
            },
            headers: None,
            seen_capture: true,
            seen_kernel: false,
        }];
        app.open_detail(1, vec![servicio(22, "ssh"), servicio(443, "https")], true);
        app
    }

    fn dibujar(app: &App, ancho: u16, alto: u16) -> String {
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

    #[test]
    fn detalle_muestra_identidad_trafico_puertos_y_servicios() {
        let app = app_detalle();
        let contenido = dibujar(&app, 110, 40);
        assert!(contenido.contains("Detalle: laptop-juan"));
        assert!(contenido.contains("192.168.1.42"));
        assert!(contenido.contains("MAC:"));
        assert!(contenido.contains("Tráfico"));
        assert!(contenido.contains("60s:"));
        assert!(contenido.contains("5min:"));
        assert!(contenido.contains("Top puertos (5)"));
        assert!(contenido.contains("443/tcp"));
        assert!(contenido.contains("Conexiones activas"));
        assert!(contenido.contains("Servicios (F2)"));
        assert!(contenido.contains("22/tcp ssh"));
    }

    #[test]
    fn detalle_sin_datos_no_entra_en_panico() {
        let mut app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: false,
                detail: "sin CAP_NET_RAW".to_string(),
            },
            None,
        );
        app.set_data(vec![dispositivo()], Vec::new());
        app.open_detail(1, Vec::new(), false);
        let contenido = dibujar(&app, 110, 40);
        assert!(contenido.contains("Sin tráfico observado"));
        assert!(contenido.contains("Servicios (F2): —"));
    }

    #[test]
    fn detalle_de_equipo_inexistente_avisa() {
        let mut app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: false,
                detail: String::new(),
            },
            None,
        );
        app.set_data(vec![dispositivo()], Vec::new());
        app.open_detail(99, Vec::new(), false);
        let contenido = dibujar(&app, 110, 40);
        assert!(contenido.contains("ya no existe"));
    }
}
