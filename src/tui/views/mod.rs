//! Composición de la pantalla y utilidades comunes de las vistas.
//!
//! Layout de la TUI: barra de pestañas, contenido, notificación no bloqueante,
//! barra de estado y pie con los atajos. Si el terminal es menor de 80x24 se
//! muestra un mensaje claro en lugar de la interfaz.

pub mod config_view;
pub mod devices;
pub mod help;
pub mod placeholder;

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Tabs};
use ratatui::Frame;

use crate::tui::app::{App, InputMode, Tab, MIN_HEIGHT, MIN_WIDTH};

/// Dibuja la interfaz completa.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        draw_too_small(frame, app, area);
        return;
    }

    let layout = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
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
    let ayuda = if input.mode == InputMode::Search {
        "  [Enter] confirmar  [Esc] cancelar"
    } else {
        "  [Enter] guardar  [Esc] cancelar"
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
    let estilo_modo = if app.is_degraded() {
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

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let atajos = if app.tab == Tab::Equipos {
        crate::tui::keys::FOOTER_EQUIPOS
    } else {
        crate::tui::keys::FOOTER_OTROS
    };
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
    ])
    .split(interior);
    frame.render_widget(parrafo, vertical[1]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::repo::devices::Device;
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

    #[test]
    fn terminal_pequeno_muestra_aviso() {
        let backend = TestBackend::new(60, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = app_vacia();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let texto = buffer_texto(&terminal);
        assert!(texto.contains("demasiado"));
        assert!(texto.contains("80×24"));
    }

    #[test]
    fn terminal_normal_dibuja_pestanas_y_estado() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = app_vacia();
        app.set_data(vec![dispositivo(true), dispositivo(false)], Vec::new());
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let texto = buffer_texto(&terminal);
        assert!(texto.contains("Equipos"));
        assert!(texto.contains("Config"));
        assert!(texto.contains("Ayuda"));
        assert!(texto.contains("10.0.0.2"));
        assert!(texto.contains("modo: degradado"));
        assert!(texto.contains("equipos"));
    }

    #[test]
    fn pestana_placeholder_muestra_no_disponible() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = app_vacia();
        app.tab = Tab::Trafico;
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let texto = buffer_texto(&terminal);
        assert!(texto.contains("no disponible"));
    }

    #[test]
    fn notificacion_visible_en_barra() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = app_vacia();
        app.push_notification(crate::notifier::Level::Warn, "modo degradado");
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let texto = buffer_texto(&terminal);
        assert!(texto.contains("aviso: modo degradado"));
    }
}
