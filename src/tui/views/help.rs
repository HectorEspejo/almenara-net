//! Pestaña Ayuda: keybindings, pestañas, captura de tráfico, modos de
//! descubrimiento y aviso legal.

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
            "Almenara v{} — Fase 3: tráfico en vivo (pasivo + local)",
            env!("CARGO_PKG_VERSION")
        ),
        app.theme.title,
    )));
    lineas.push(Line::from(""));

    lineas.push(Line::from(Span::styled("Navegación", app.theme.accent)));
    for fila in crate::tui::keys::HELP_ROWS {
        lineas.push(Line::from(vec![
            Span::styled(format!("  {:<20}", fila.keys), app.theme.accent),
            Span::styled(fila.description, app.theme.normal),
        ]));
    }

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Pestañas", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  Equipos       inventario (plana o agrupada) y detalle master-detail con Enter",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Tráfico       ranking top-10 por consumo en la ventana de 60 s",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Conexiones    tabla plana ordenable y filtrable; [v] muestra cabeceras",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Histórico y Alertas: llegarán en las fases 5 y 6",
        app.theme.dim,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Vista de equipos",
        app.theme.accent,
    )));
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
    lineas.push(Line::from(Span::styled(
        "  Detalle: Enter abre el panel (mitad derecha ≥100 columnas, completa por debajo);",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "           Tab alterna el foco lista/detalle y Esc cierra el panel.",
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
    lineas.push(Line::from(Span::styled(
        "Captura de tráfico",
        app.theme.accent,
    )));
    let estado_captura = app.capture_status_line();
    let estilo_captura = if app.traffic.capture.active {
        app.theme.online
    } else {
        app.theme.warning
    };
    lineas.push(Line::from(vec![
        Span::styled("  Estado: ", app.theme.accent),
        Span::styled(estado_captura, estilo_captura),
    ]));
    lineas.push(Line::from(Span::styled(
        "  AF_PACKET + TPACKET_V3 (sin libpcap), un hilo por interfaz y anillo de 64 MB.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Filtro: [capture].filter con BPF clásico adjunto al socket (SO_ATTACH_FILTER);",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "          vacío = sin filtro. Si el filtro no compila se avisa y se captura sin él.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Límite: [capture].max_pps (0 = sin límite). Se avisa una vez por minuto al alcanzarlo.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Requiere CAP_NET_RAW: sudo setcap cap_net_raw+ep target/debug/almenara",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Sin CAP_NET_RAW la captura se deshabilita y la barra muestra [CAP:off].",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  En Tráfico, el tráfico del propio host se muestra como fila [host] (no es",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  un equipo del inventario) para que la pestaña no aparezca vacía.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Visibilidad honesta: en red conmutada se ve todo el tráfico propio y el",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  broadcast; del unicast entre terceros solo lo que llegue a esta interfaz.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Ventanas en memoria: 60 s (1 punto/s) y 5 min (punto cada 5 s); parten a cero.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  El último snapshot por equipo (TRAFFIC_SNAPSHOT) se usa como semilla al reabrir.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  passive_only permite captura pasiva: escuchar no emite tráfico.",
        app.theme.normal,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Modo", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  privilegiado   CAP_NET_RAW disponible; todos los métodos activos",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  pasivo         [scan] passive_only = true; sin tráfico activo (captura pasiva sí)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  degradado      sin CAP_NET_RAW; solo fuentes pasivas y sin captura de paquetes",
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
    lineas.push(Line::from(Span::styled(
        "Privacidad y aviso legal",
        app.theme.accent,
    )));
    lineas.push(Line::from(Span::styled(
        "  Utiliza Almenara únicamente en redes propias o con autorización expresa.",
        app.theme.warning,
    )));
    lineas.push(Line::from(Span::styled(
        "  Monitorizar redes ajenas puede ser ilegal en muchos países.",
        app.theme.warning,
    )));
    lineas.push(Line::from(Span::styled(
        "  El payload de los paquetes NUNCA se persiste: con inspect_payload = false se",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  descarta al instante; con true solo se extraen QNAME de DNS y SNI de TLS.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Datos técnicos guardados solo en local (SQLite): IP, MAC, hostname, fabricante,",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  familia de SO, puertos/servicios y metadatos de conexiones (5-tuple y bytes).",
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

    fn app_prueba(raw: bool) -> App {
        App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: raw,
                detail: if raw {
                    "CAP_NET_RAW detectada".to_string()
                } else {
                    "sin CAP_NET_RAW".to_string()
                },
            },
            None,
        )
    }

    #[test]
    fn ayuda_incluye_atajos_estado_y_aviso_legal() {
        let app = app_prueba(false);
        let contenido = dibujar(&app, 130, 70);
        assert!(contenido.contains("Navegación"));
        assert!(contenido.contains("Shift-Tab"));
        assert!(contenido.contains("degradado"));
        assert!(contenido.contains("Aviso legal") || contenido.contains("aviso legal"));
        assert!(contenido.contains("redes propias"));
        assert!(contenido.contains("Fase 3"));
        assert!(contenido.contains("[v]"));
    }

    #[test]
    fn ayuda_documenta_vista_e_iconos() {
        let app = app_prueba(false);
        let contenido = dibujar(&app, 130, 70);
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
        let app = app_prueba(true);
        let contenido = dibujar(&app, 130, 70);
        for modo in ["privilegiado", "pasivo", "degradado"] {
            assert!(contenido.contains(modo), "falta el modo {modo}");
        }
        assert!(contenido.contains("Modo actual"));
    }

    #[test]
    fn ayuda_documenta_la_captura_y_sus_limites() {
        let app = app_prueba(true);
        let contenido = dibujar(&app, 130, 80);
        assert!(contenido.contains("Captura de tráfico"));
        assert!(contenido.contains("CAP_NET_RAW"));
        assert!(contenido.contains("max_pps"));
        assert!(contenido.contains("SO_ATTACH_FILTER"));
        assert!(contenido.contains("payload"));
        assert!(contenido.contains("TRAFFIC_SNAPSHOT"));
        assert!(contenido.contains("passive_only"));
        assert!(contenido.contains("visibilidad") || contenido.contains("Visibilidad"));
    }
}
