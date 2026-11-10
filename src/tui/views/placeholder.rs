//! Vistas placeholder de las pestañas no disponibles en Fase 1.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::tui::app::{App, Tab};

/// Dibuja la pestaña placeholder activa.
pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled(app.tab.title(), app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let fase_futura = match app.tab {
        Tab::Trafico | Tab::Conexiones => "Fase 3",
        Tab::Historico => "Fase 5",
        Tab::Alertas => "Fase 6",
        _ => "una fase posterior",
    };
    let lineas = vec![
        Line::from(Span::styled("no disponible en F1", app.theme.warning)),
        Line::from(""),
        Line::from(Span::styled(
            format!("Esta pestaña llegará en {fase_futura}."),
            app.theme.dim,
        )),
        Line::from(Span::styled(
            "Pulsa [?] para ver la ayuda o [Tab] para cambiar de pestaña.",
            app.theme.dim,
        )),
    ];
    let parrafo = Paragraph::new(lineas).alignment(Alignment::Center);
    let filas = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(4),
        Constraint::Fill(1),
    ])
    .split(interior);
    frame.render_widget(parrafo, filas[1]);
}

#[cfg(test)]
mod tests {
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::tui::app::{App, Tab};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    #[test]
    fn placeholder_dice_no_disponible_en_f1() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
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
        app.tab = Tab::Historico;
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
        assert!(contenido.contains("no disponible en F1"));
        assert!(contenido.contains("Histórico"));
    }
}
