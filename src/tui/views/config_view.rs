//! Pestaña Config: configuración activa en modo solo lectura.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::config::Config;
use crate::tui::app::App;

/// Dibuja la pestaña Config.
pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled(
            "Configuración activa (solo lectura en Fase 1)",
            app.theme.title,
        ));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let log_dir = Config::log_dir()
        .map(|ruta| ruta.display().to_string())
        .unwrap_or_else(|err| format!("(no disponible: {err})"));

    let mut lineas: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Ruta: ", app.theme.accent),
            Span::raw(app.config_path.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Base de datos: ", app.theme.accent),
            Span::raw(app.db_path.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("Logs: ", app.theme.accent),
            Span::raw(log_dir),
        ]),
        Line::from(""),
    ];
    for linea in app.config.to_toml().lines() {
        lineas.push(Line::from(linea.to_string()));
    }

    frame.render_widget(
        Paragraph::new(lineas)
            .block(Block::default())
            .style(app.theme.normal)
            .wrap(Wrap { trim: false }),
        interior,
    );
}

#[cfg(test)]
mod tests {
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    #[test]
    fn muestra_rutas_y_secciones_toml() {
        let backend = TestBackend::new(110, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: false,
                detail: "sin CAP_NET_RAW".to_string(),
            },
            None,
        );
        terminal
            .draw(|frame| super::draw(frame, &app, frame.area()))
            .unwrap();
        let contenido: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect();
        assert!(contenido.contains("/tmp/config.toml"));
        assert!(contenido.contains("[scan]"));
        assert!(contenido.contains("[storage]"));
        assert!(contenido.contains("[ui]"));
        assert!(contenido.contains("solo lectura"));
    }
}
