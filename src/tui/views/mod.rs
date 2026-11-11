//! Composición de la pantalla y utilidades comunes de las vistas.
//!
//! Layout de la TUI: barra de pestañas, contenido, notificación no bloqueante,
//! barra de estado (2 líneas en terminales estrechas, 3 en anchos) y pie con los
//! atajos. Si el terminal es menor de 80x24 se muestra un mensaje claro.

pub mod config_view;
pub mod connections;
pub mod device_detail;
pub mod devices;
pub mod help;
pub mod placeholder;
pub mod traffic;

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Tabs};
use ratatui::Frame;

use crate::traffic::formatear_bytes_por_segundo;
use crate::tui::app::{App, InputMode, Tab, MIN_HEIGHT, MIN_WIDTH};

/// Ancho a partir del cual la barra de estado usa tres líneas.
pub const STATUS_WIDTH_ANCHO: u16 = 100;

/// Dibuja la interfaz completa.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        draw_too_small(frame, app, area);
        return;
    }

    let alto_estado = if area.width >= STATUS_WIDTH_ANCHO {
        3
    } else {
        2
    };
    let layout = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(alto_estado),
        Constraint::Length(2),
    ])
    .split(area);

    draw_tabs(frame, app, layout[0]);
    draw_content(frame, app, layout[1]);
    draw_notification(frame, app, layout[2]);
    draw_status(frame, app, layout[3]);
    draw_footer(frame, app, layout[4]);
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    // Títulos compactos: las siete pestañas deben caber en 80 columnas.
    let titulos: Vec<Line> = Tab::ALL.iter().map(|tab| Line::from(tab.title())).collect();
    let tabs = Tabs::new(titulos)
        .select(app.tab.index())
        .divider(Span::styled("·", app.theme.dim))
        .highlight_style(app.theme.accent.add_modifier(Modifier::REVERSED))
        .style(app.theme.dim);
    frame.render_widget(tabs, area);
}

fn draw_content(frame: &mut Frame, app: &mut App, area: Rect) {
    let area = if app.input.is_some() {
        let division = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(area);
        draw_input_line(frame, app, division[0]);
        division[1]
    } else {
        area
    };

    match app.tab {
        Tab::Equipos => devices::draw(frame, app, area),
        Tab::Trafico => traffic::draw(frame, app, area),
        Tab::Conexiones => connections::draw(frame, app, area),
        Tab::Config => config_view::draw(frame, app, area),
        Tab::Ayuda => help::draw(frame, app, area),
        otro if otro.is_placeholder() => placeholder::draw(frame, app, area),
        _ => {}
    }
}

fn draw_input_line(frame: &mut Frame, app: &App, area: Rect) {
    let Some(input) = app.input.as_ref() else {
        return;
    };
    let etiqueta = match input.mode {
        InputMode::Search => "Buscar: ".to_string(),
        InputMode::ConnectionSearch => "Buscar conexiones: ".to_string(),
        InputMode::Alias => {
            let ip = app
                .devices
                .iter()
                .find(|device| Some(device.id) == input.device_id)
                .map(|device| device.ip.clone())
                .unwrap_or_default();
            format!("Alias de {ip}: ")
        }
        InputMode::Notes => {
            let ip = app
                .devices
                .iter()
                .find(|device| Some(device.id) == input.device_id)
                .map(|device| device.ip.clone())
                .unwrap_or_default();
            format!("Notas de {ip}: ")
        }
    };
    let ayuda = match input.mode {
        InputMode::Search | InputMode::ConnectionSearch => "  [Enter] confirmar  [Esc] cancelar",
        InputMode::Alias | InputMode::Notes => "  [Enter] guardar  [Esc] cancelar",
    };
    let linea = Line::from(vec![
        Span::styled(etiqueta, app.theme.accent),
        Span::styled(input.buffer.clone(), app.theme.normal),
        Span::styled("█", app.theme.accent),
        Span::styled(ayuda, app.theme.dim),
    ]);
    frame.render_widget(Paragraph::new(linea).style(app.theme.normal), area);
}

fn draw_notification(frame: &mut Frame, app: &App, area: Rect) {
    let Some(notification) = app.notifier.current() else {
        return;
    };
    let linea = Line::from(Span::styled(
        format!("{}: {}", notification.level.label(), notification.message),
        app.theme.level_style(notification.level),
    ));
    frame.render_widget(Paragraph::new(linea).alignment(Alignment::Right), area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    if area.height >= 3 {
        let filas = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);
        draw_status_summary(frame, app, filas[0]);
        draw_status_capture(frame, app, filas[1]);
        draw_status_visibility(frame, app, filas[2]);
    } else {
        let filas = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
        draw_status_summary(frame, app, filas[0]);
        draw_status_capture(frame, app, filas[1]);
    }
}

fn draw_status_summary(frame: &mut Frame, app: &App, area: Rect) {
    // El modo pasivo consciente también se destaca como aviso, igual que el
    // degradado: en ambos casos hay descubrimiento activo desactivado.
    let estilo_modo = if app.is_degraded() || app.is_passive() {
        app.theme.warning
    } else {
        app.theme.online
    };
    let modo = app.mode_label();
    let ancho_modo = (modo.chars().count() as u16 + 2).min(area.width);
    let columnas =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(ancho_modo)]).split(area);

    frame.render_widget(
        Paragraph::new(app.status_summary()).style(app.theme.dim),
        columnas[0],
    );
    frame.render_widget(
        Paragraph::new(modo)
            .alignment(Alignment::Right)
            .style(estilo_modo),
        columnas[1],
    );
}

/// Línea de estado de la captura (izquierda) y tráfico global (derecha).
fn draw_status_capture(frame: &mut Frame, app: &App, area: Rect) {
    let mut captura = app.capture_status_line();
    if !app.theme.color {
        captura = format!("{} {captura}", app.traffic.capture.no_color_prefix());
    }
    let estilo = if app.traffic.capture.active {
        app.theme.online
    } else {
        app.theme.warning
    };

    // En terminales estrechos la segunda línea muestra la captura y la
    // visibilidad (no caben además los totales globales).
    if area.width < STATUS_WIDTH_ANCHO {
        let visibilidad = app.visibility_line();
        let ancho_vis = (visibilidad.chars().count() as u16 + 2).min(area.width);
        let columnas =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(ancho_vis)]).split(area);
        frame.render_widget(Paragraph::new(Span::styled(captura, estilo)), columnas[0]);
        frame.render_widget(
            Paragraph::new(visibilidad)
                .alignment(Alignment::Right)
                .style(app.theme.accent),
            columnas[1],
        );
        return;
    }

    let (entrada, salida) = app.traffic.global_rates();
    let hay_datos = app.traffic.has_live_data()
        || !app.traffic.ranked_devices().is_empty()
        || app.traffic.connections_total > 0;
    let global = if hay_datos {
        format!(
            "↓ {} · ↑ {} · {} conexiones",
            formatear_bytes_por_segundo(entrada),
            formatear_bytes_por_segundo(salida),
            app.traffic.connections_total
        )
    } else {
        String::new()
    };
    let ancho_global = if global.is_empty() {
        0
    } else {
        (global.chars().count() as u16 + 2).min(area.width)
    };
    let columnas =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(ancho_global)]).split(area);
    frame.render_widget(Paragraph::new(Span::styled(captura, estilo)), columnas[0]);
    if !global.is_empty() {
        frame.render_widget(
            Paragraph::new(global)
                .alignment(Alignment::Right)
                .style(app.theme.dim),
            columnas[1],
        );
    }
}

/// Línea de visibilidad honesta (izquierda) y fuentes de descubrimiento (derecha).
fn draw_status_visibility(frame: &mut Frame, app: &App, area: Rect) {
    let visibilidad = app.visibility_line();
    let ancho_vis = (visibilidad.chars().count() as u16 + 2).min(area.width);
    let columnas =
        Layout::horizontal([Constraint::Length(ancho_vis), Constraint::Min(0)]).split(area);
    frame.render_widget(
        Paragraph::new(Span::styled(visibilidad, app.theme.accent)),
        columnas[0],
    );
    let texto = texto_fuentes(app, columnas[1].width);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Fuentes: ", app.theme.accent),
            Span::styled(texto, app.theme.dim),
        ])),
        columnas[1],
    );
}

/// Texto de las fuentes de descubrimiento activas, abreviado si no cabe.
fn texto_fuentes(app: &App, ancho: u16) -> String {
    let fuentes = app.active_sources();
    let completas = fuentes.join(" · ");
    if completas.chars().count() <= usize::from(ancho) {
        completas
    } else {
        fuentes
            .iter()
            .map(|fuente| etiqueta_fuente(fuente))
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// Abreviaturas de las fuentes con nombre largo en la barra de estado.
fn etiqueta_fuente(fuente: &str) -> &str {
    match fuente {
        "DNS inverso" => "DNS inv.",
        otra => otra,
    }
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let atajos = crate::tui::keys::footer_para(app.tab, app.detail_open(), app.who_uses_open());
    let lineas: Vec<Line> = atajos
        .iter()
        .map(|linea| Line::from(Span::styled(*linea, app.theme.dim)))
        .collect();
    frame.render_widget(Paragraph::new(lineas), area);
}

fn draw_too_small(frame: &mut Frame, app: &App, area: Rect) {
    let bloque = Block::bordered()
        .border_style(app.theme.warning)
        .title(Span::styled(
            "Terminal demasiado pequeño",
            app.theme.warning,
        ));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);
    let lineas = vec![
        Line::from(Span::styled(
            format!(
                "La interfaz necesita al menos {}×{} caracteres",
                MIN_WIDTH, MIN_HEIGHT
            ),
            app.theme.warning,
        )),
        Line::from(Span::styled(
            format!("Tamaño actual: {}×{}", area.width, area.height),
            app.theme.dim,
        )),
        Line::from(Span::styled(
            "Amplía la ventana del terminal para continuar",
            app.theme.dim,
        )),
    ];
    let parrafo = Paragraph::new(lineas)
        .alignment(Alignment::Center)
        .style(app.theme.normal);
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Fill(1),
    ]);
    let vertical = vertical.split(interior);
    frame.render_widget(parrafo, vertical[1]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::aggregate::DeviceTraffic;
    use crate::config::Config;
    use crate::rankings::{Dimension, RankRow, Window};
    use crate::repo::devices::Device;
    use crate::traffic::{CaptureStatus, RankingView};
    use crate::tui::app::Tab;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_vacia() -> App {
        App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: false,
                detail: "sin CAP_NET_RAW".to_string(),
            },
            None,
        )
    }

    fn dispositivo(online: bool) -> Device {
        Device {
            id: 1,
            mac: "aa:bb:cc:dd:ee:01".to_string(),
            ip: "10.0.0.2".to_string(),
            hostname: Some("equipo".to_string()),
            vendor: Some("Apple".to_string()),
            interface_id: 1,
            device_type: if online { "gateway" } else { "unknown" }.to_string(),
            is_online: online,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
            alias: None,
            notes: None,
            os_family: None,
            device_type_manual: None,
            last_fingerprint: None,
            model: None,
            dhcp_fingerprint: None,
            dhcp_vendor: None,
            dhcp_hostname: None,
            user_agent: None,
            os_source: None,
        }
    }

    fn estadisticas(device_id: i64) -> DeviceTraffic {
        DeviceTraffic {
            device_id,
            bytes_in: 1000,
            bytes_out: 500,
            packets_in: 10,
            packets_out: 5,
            rate_in: 100,
            rate_out: 50,
            peak_bps: 1200,
            series_60s_in: [1; 60],
            series_60s_out: [0; 60],
            series_5min_in: [1; 60],
            series_5min_out: [0; 60],
            top_ports: Vec::new(),
        }
    }

    fn buffer_texto(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app))
            .expect("dibujado de la interfaz");
        buffer_texto(&terminal)
    }

    fn app_con_capacidades(config: Config, raw_sockets: bool) -> App {
        App::new(
            config,
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets,
                detail: if raw_sockets {
                    "CAP_NET_RAW detectada".to_string()
                } else {
                    "sin CAP_NET_RAW".to_string()
                },
            },
            None,
        )
    }

    fn app_con_trafico() -> App {
        let mut app = app_con_capacidades(Config::default(), true);
        app.set_data(vec![dispositivo(true)], Vec::new());
        app.traffic.devices = vec![estadisticas(1)];
        app.traffic.capture = CaptureStatus {
            active: true,
            pps: 2400,
            interfaces: vec!["eth0".to_string()],
            ..CaptureStatus::default()
        };
        app
    }

    #[test]
    fn terminal_pequeno_muestra_aviso() {
        let mut app = app_vacia();
        let texto = dibujar(&mut app, 60, 20);
        assert!(texto.contains("demasiado"));
        assert!(texto.contains("80×24"));
    }

    #[test]
    fn terminal_normal_dibuja_pestanas_y_estado() {
        let mut app = app_vacia();
        app.set_data(vec![dispositivo(true), dispositivo(false)], Vec::new());
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("Equipos"));
        assert!(texto.contains("Config"));
        assert!(texto.contains("Ayuda"));
        assert!(texto.contains("10.0.0.2"));
        assert!(texto.contains("modo: degradado"));
        assert!(texto.contains("equipos"));
        assert!(texto.contains("visibilidad: propia + broadcast"));
    }

    #[test]
    fn pestana_placeholder_muestra_no_disponible() {
        let mut app = app_vacia();
        app.tab = Tab::Historico;
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("no disponible"));
        assert!(texto.contains("Histórico"));
    }

    #[test]
    fn notificacion_visible_en_barra() {
        let mut app = app_vacia();
        app.push_notification(crate::notifier::Level::Warn, "modo degradado");
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("aviso: modo degradado"));
    }

    #[test]
    fn barra_muestra_modo_pasivo_y_solo_fuentes_pasivas() {
        let mut config = Config::default();
        config.scan.passive_only = true;
        let mut app = app_con_capacidades(config, true);
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("modo: pasivo"));
        assert!(texto.contains("Fuentes:"));
        for fuente in ["/proc", "mDNS", "SSDP", "DHCP", "NetBIOS", "DNS inverso"] {
            assert!(texto.contains(fuente), "falta la fuente {fuente}");
        }
        assert!(
            !texto.contains("ARP"),
            "el modo pasivo no debe anunciar fuentes activas"
        );
    }

    #[test]
    fn barra_muestra_el_estado_de_la_inferencia() {
        let mut app = app_con_trafico();
        app.traffic.capture.inference_enabled = true;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("inferencia: activa"));
        app.traffic.capture.inference_enabled = false;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("inferencia: desactivada"));
    }

    #[test]
    fn barra_estrecha_muestra_captura_y_visibilidad_sin_fuentes() {
        let mut app = app_con_trafico();
        let texto = dibujar(&mut app, 80, 24);
        assert!(texto.contains("modo: privilegiado"));
        assert!(texto.contains("capturando"));
        assert!(texto.contains("propia + broadcast"));
        assert!(
            !texto.contains("Fuentes:"),
            "a 80 columnas la barra usa dos líneas"
        );
    }

    #[test]
    fn barra_ancha_muestra_fuentes_y_captura() {
        let mut app = app_con_trafico();
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("capturando"));
        assert!(texto.contains("filtro:"));
        assert!(texto.contains("Fuentes:"));
        assert!(texto.contains("visibilidad: propia + broadcast"));
        assert!(texto.contains("conexiones"));
    }

    #[test]
    fn sin_color_prefixa_el_estado_de_captura() {
        let mut config = Config::default();
        config.ui.no_color = true;
        let mut app = app_con_capacidades(config, true);
        app.traffic.capture = CaptureStatus {
            active: true,
            ..CaptureStatus::default()
        };
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("[CAP]"));
    }

    #[test]
    fn barra_privilegiada_anuncia_fuentes_activas() {
        let mut app = app_con_capacidades(Config::default(), true);
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("modo: privilegiado"));
        for fuente in ["/proc", "mDNS", "ARP", "ICMP", "puertos"] {
            assert!(texto.contains(fuente), "falta la fuente {fuente}");
        }
    }

    #[test]
    fn barra_degradada_anuncia_fuentes_pasivas() {
        let mut app = app_con_capacidades(Config::default(), false);
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("modo: degradado"));
        assert!(texto.contains("Fuentes:"));
        assert!(!texto.contains("ARP"));
    }

    #[test]
    fn pie_cambia_por_pestana_y_con_el_detalle() {
        let mut app = app_con_trafico();
        app.tab = Tab::Conexiones;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("[i]nombres/IPs"));
        assert!(texto.contains("[v]detalle"));
        app.tab = Tab::Trafico;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("[g]agrupar"));
        assert!(texto.contains("[Enter]¿quién?"));
        // Con el panel «¿Quién lo usa?» abierto el pie cambia.
        app.traffic_group = Dimension::App;
        app.traffic.rankings = vec![RankingView {
            dimension: Dimension::App,
            window: Window::Sixty,
            rows: vec![RankRow {
                key: "youtube".to_string(),
                label: "YouTube".to_string(),
                subtitle: Some("Vídeo".to_string()),
                device_id: None,
                bytes_down: 900,
                bytes_up: 10,
                devices: 1,
                connections: 2,
                series_60s: [0; 60],
            }],
        }];
        app.open_who_uses();
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("[Esc]cerrar panel"));
        app.close_who_uses();
        app.tab = Tab::Equipos;
        app.open_detail(1, Vec::new(), false);
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("[Tab]panel"));
    }

    #[test]
    fn pestana_trafico_dibuja_ranking() {
        let mut app = app_con_trafico();
        app.tab = Tab::Trafico;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("ranking por equipo"));
        assert!(texto.contains("sparkline 60 s"));
        assert!(texto.contains("sin identificar:"));
    }

    #[test]
    fn pestana_conexiones_dibuja_tabla_vacia() {
        let mut app = app_con_trafico();
        app.tab = Tab::Conexiones;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("Conexiones activas"));
        assert!(texto.contains("Sin conexiones"));
        assert!(texto.contains("filtro:"));
    }
}
