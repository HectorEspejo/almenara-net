//! Pestaña Ayuda: keybindings, estado de capacidades y aviso legal.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::App;

/// Dibuja la pestaña Ayuda.
pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled("Ayuda", app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let claro = Span::styled("", app.theme.normal);
    let mut lineas: Vec<Line> = Vec::new();
    lineas.push(Line::from(Span::styled(
        format!(
            "Almenara v{} — Fase 1: fundación y descubrimiento básico",
            env!("CARGO_PKG_VERSION")
        ),
        app.theme.title,
    )));
    lineas.push(Line::from(claro.clone()));
    lineas.push(Line::from(Span::styled("Navegación", app.theme.accent)));
    for fila in crate::tui::keys::HELP_ROWS {
        lineas.push(Line::from(vec![
            Span::styled(format!("  {:<18}", fila.keys), app.theme.accent),
            Span::styled(fila.description, app.theme.normal),
        ]));
    }
    lineas.push(Line::from(claro.clone()));
    lineas.push(Line::from(Span::styled("Estado", app.theme.accent)));
    let estado = if app.capabilities.raw_sockets {
        "privilegiado (CAP_NET_RAW detectada): ARP scan y ping sweep activos".to_string()
    } else {
        "degradado (sin CAP_NET_RAW): solo lectura pasiva de /proc/net/arp".to_string()
    };
    let estilo_estado = if app.capabilities.raw_sockets {
        app.theme.online
    } else {
        app.theme.warning
    };
    lineas.push(Line::from(vec![
        Span::styled("  Estado: ", app.theme.accent),
        Span::styled(estado, estilo_estado),
    ]));
    lineas.push(Line::from(claro.clone()));
    lineas.push(Line::from(Span::styled("Aviso legal", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  Utiliza Almenara únicamente en redes propias o con autorización expresa.",
        app.theme.warning,
    )));
    lineas.push(Line::from(Span::styled(
        "  Monitorizar redes ajenas puede ser ilegal en muchos países.",
        app.theme.warning,
    )));
    lineas.push(Line::from(claro));
    lineas.push(Line::from(Span::styled(
        "  Datos técnicos de red guardados solo en local (SQLite): IP, MAC, hostname y fabricante.",
        app.theme.dim,
    )));

    frame.render_widget(
        Paragraph::new(lineas)
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
    fn ayuda_incluye_atajos_estado_y_aviso_legal() {
        let backend = TestBackend::new(110, 45);
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
        assert!(contenido.contains("Navegación"));
        assert!(contenido.contains("Shift-Tab"));
        assert!(contenido.contains("degradado"));
        assert!(contenido.contains("Aviso legal"));
        assert!(contenido.contains("redes propias"));
    }
}
