//! Pestaña Ayuda: keybindings, leyenda de iconos, modos de descubrimiento y aviso legal.

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

    let mut lineas: Vec<Line> = Vec::new();
    lineas.push(Line::from(Span::styled(
        format!(
            "Almenara v{} — Fase 2: descubrimiento avanzado",
            env!("CARGO_PKG_VERSION")
        ),
        app.theme.title,
    )));
    lineas.push(Line::from(""));

    lineas.push(Line::from(Span::styled("Navegación", app.theme.accent)));
    for fila in crate::tui::keys::HELP_ROWS {
        lineas.push(Line::from(vec![
            Span::styled(format!("  {:<18}", fila.keys), app.theme.accent),
            Span::styled(fila.description, app.theme.normal),
        ]));
    }

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Vista", app.theme.accent)));
    lineas.push(Line::from(vec![
        Span::styled("  Vista actual: ", app.theme.accent),
        Span::styled(app.list_view.label(), app.theme.normal),
        Span::styled("  [g] alterna plana / agrupada", app.theme.dim),
    ]));
    lineas.push(Line::from(Span::styled(
        "  Agrupada: cabeceras por categoría (Infraestructura, Puestos y servidores, …)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Tipo manual: [t] cicla automático → gateway → printer → … → unknown → automático",
        app.theme.normal,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Iconos por tipo",
        app.theme.accent,
    )));
    lineas.push(Line::from(Span::styled(
        "  [⌂] gateway   [▣] pc/server   [▯] móvil/tablet   [●] iot",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  [P] impresora [C] cámara      [▶] tv/streaming   [?] desconocido",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  ○    offline",
        app.theme.offline,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Modo", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  privilegiado   CAP_NET_RAW disponible; todos los métodos activos",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  pasivo         [scan] passive_only = true; sin tráfico activo",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  degradado      sin CAP_NET_RAW; solo fuentes pasivas",
        app.theme.normal,
    )));
    let estilo_modo = if app.is_degraded() || app.is_passive() {
        app.theme.warning
    } else {
        app.theme.online
    };
    let modo = app.mode_label();
    let detalle = modo.strip_prefix("modo: ").unwrap_or(&modo).to_string();
    lineas.push(Line::from(vec![
        Span::styled("  Modo actual: ", app.theme.accent),
        Span::styled(detalle, estilo_modo),
    ]));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Aviso legal", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  Utiliza Almenara únicamente en redes propias o con autorización expresa.",
        app.theme.warning,
    )));
    lineas.push(Line::from(Span::styled(
        "  Monitorizar redes ajenas puede ser ilegal en muchos países.",
        app.theme.warning,
    )));
    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "  Datos técnicos de red guardados solo en local (SQLite): IP, MAC, hostname, fabricante",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  y familia de SO estimada por fingerprint.",
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

    fn dibujar(app: &App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| super::draw(frame, app, frame.area()))
            .expect("dibujado de la ayuda");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn ayuda_incluye_atajos_estado_y_aviso_legal() {
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
        let contenido = dibujar(&app, 110, 55);
        assert!(contenido.contains("Navegación"));
        assert!(contenido.contains("Shift-Tab"));
        assert!(contenido.contains("degradado"));
        assert!(contenido.contains("Aviso legal"));
        assert!(contenido.contains("redes propias"));
    }

    #[test]
    fn ayuda_documenta_vista_e_iconos() {
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
        let contenido = dibujar(&app, 110, 55);
        assert!(contenido.contains("Vista actual"));
        assert!(contenido.contains("plana"));
        assert!(contenido.contains("agrupada"));
        assert!(contenido.contains("Iconos por tipo"));
        for icono in ["[⌂]", "[▣]", "[▯]", "[▶]", "[P]", "[C]", "[●]", "[?]", "○"] {
            assert!(contenido.contains(icono), "falta el icono {icono}");
        }
    }

    #[test]
    fn ayuda_describe_los_tres_modos() {
        let app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        );
        let contenido = dibujar(&app, 110, 55);
        for modo in ["privilegiado", "pasivo", "degradado"] {
            assert!(contenido.contains(modo), "falta el modo {modo}");
        }
        assert!(contenido.contains("Modo actual"));
    }
}
