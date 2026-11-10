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
            "Configuración activa (solo lectura)",
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

    // Fingerprint de SO por dispositivo (solo lectura): el detalle completo se
    // abre con Enter en la pestaña Equipos (panel master-detail de Fase 3).
    lineas.push(Line::from(Span::styled(
        "Fingerprint de SO por dispositivo",
        app.theme.accent,
    )));
    if app.devices.is_empty() {
        lineas.push(Line::from(Span::styled(
            "  (todavía no hay equipos descubiertos)",
            app.theme.dim,
        )));
    } else {
        for device in &app.devices {
            let familia = device.os_family.as_deref().unwrap_or("?");
            lineas.push(Line::from(vec![
                Span::styled(format!("  {:<15} ", device.ip), app.theme.normal),
                Span::styled(familia.to_string(), app.theme.dim),
            ]));
        }
    }
    lineas.push(Line::from(""));

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
    use crate::repo::devices::Device;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_prueba(devices: Vec<Device>) -> App {
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
        app.set_data(devices, Vec::new());
        app
    }

    fn dispositivo(id: i64, ip: &str, os_family: Option<&str>) -> Device {
        Device {
            id,
            mac: format!("aa:bb:cc:dd:ee:0{id}"),
            ip: ip.to_string(),
            hostname: Some(format!("equipo-{id}")),
            vendor: None,
            interface_id: 1,
            device_type: "unknown".to_string(),
            is_online: true,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
            alias: None,
            notes: None,
            os_family: os_family.map(str::to_string),
            device_type_manual: None,
            last_fingerprint: None,
        }
    }

    fn texto(app: &App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| super::draw(frame, app, frame.area()))
            .expect("dibujado de la configuración");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn muestra_rutas_y_secciones_toml() {
        // La pestaña Config es larga (TOML completo): el backend de pruebas
        // necesita altura suficiente para que [ui] entre en el viewport.
        let app = app_prueba(Vec::new());
        let contenido = texto(&app, 110, 60);
        assert!(contenido.contains("/tmp/config.toml"));
        assert!(contenido.contains("[scan]"));
        assert!(contenido.contains("[storage]"));
        assert!(contenido.contains("[ui]"));
        assert!(contenido.contains("solo lectura"));
    }

    #[test]
    fn muestra_fingerprint_de_so_por_dispositivo() {
        let app = app_prueba(vec![
            dispositivo(1, "10.0.0.2", Some("linux")),
            dispositivo(2, "10.0.0.3", None),
        ]);
        let contenido = texto(&app, 110, 60);
        assert!(contenido.contains("Fingerprint de SO"));
        assert!(contenido.contains("10.0.0.2"));
        assert!(contenido.contains("linux"));
        assert!(contenido.contains("10.0.0.3"));
    }

    #[test]
    fn sin_equipos_avisa_de_fingerprint_vacio() {
        let app = app_prueba(Vec::new());
        let contenido = texto(&app, 110, 60);
        assert!(contenido.contains("todavía no hay equipos"));
    }
}
