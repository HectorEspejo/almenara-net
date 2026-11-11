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

    // Inferencia, catálogo y bases IP (Fase 4).
    lineas.push(Line::from(Span::styled(
        "Inferencia y datos (F4)",
        app.theme.accent,
    )));
    let inferencia = if app.config.inference.enabled {
        "activa"
    } else {
        "desactivada"
    };
    let apps_file = app
        .config
        .inference
        .apps_file_path()
        .map(|ruta| ruta.display().to_string())
        .unwrap_or_else(|| "(ruta no válida)".to_string());
    lineas.push(Line::from(vec![
        Span::styled("  [inference] ", app.theme.accent),
        Span::styled(format!("enabled = {inferencia}"), app.theme.normal),
        Span::styled(format!(" · apps_file: {apps_file}"), app.theme.dim),
    ]));
    let catalogo = app.catalog_counts;
    lineas.push(Line::from(vec![
        Span::styled("  Catálogo de apps: ", app.theme.accent),
        Span::styled(
            format!(
                "{} embebidas · {} propias · {} avisos",
                catalogo.embedded_apps, catalogo.user_apps, catalogo.warnings
            ),
            app.theme.normal,
        ),
    ]));
    let bases = app
        .ipdb_date
        .clone()
        .map(|fecha| format!("DB-IP Lite {fecha}"))
        .unwrap_or_else(|| "no disponibles".to_string());
    lineas.push(Line::from(vec![
        Span::styled("  Bases IP: ", app.theme.accent),
        Span::styled(bases, app.theme.normal),
    ]));
    if !app.config.inference.enabled {
        lineas.push(Line::from(Span::styled(
            "  La inferencia está desactivada: solo hay etiquetas por servicio de F2, ASN, puerto y proceso.",
            app.theme.warning,
        )));
    }
    lineas.push(Line::from(""));

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
            model: None,
            dhcp_fingerprint: None,
            dhcp_vendor: None,
            dhcp_hostname: None,
            user_agent: None,
            os_source: None,
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

#[cfg(test)]
mod tests_f4 {
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::inference::catalog::CatalogCounts;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_prueba(inference: bool) -> App {
        let mut config = Config::default();
        config.inference.enabled = inference;
        let mut app = App::new(
            config,
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        );
        app.catalog_counts = CatalogCounts {
            embedded_apps: 162,
            user_apps: 2,
            warnings: 1,
        };
        app.ipdb_date = Some("2026-11".to_string());
        app
    }

    fn texto(app: &App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| super::draw(frame, app, frame.area()))
            .expect("dibujado de Config");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn config_muestra_inferencia_catalogo_y_bases_ip() {
        let app = app_prueba(true);
        let contenido = texto(&app, 160, 60);
        assert!(contenido.contains("Inferencia y datos (F4)"));
        assert!(contenido.contains("[inference]"));
        assert!(contenido.contains("enabled = activa"));
        assert!(contenido.contains("apps_file:"));
        assert!(contenido.contains("162 embebidas · 2 propias · 1 avisos"));
        assert!(contenido.contains("DB-IP Lite 2026-11"));
        // La plantilla TOML sigue mostrando la sección [inference].
        assert!(contenido.contains("[inference]"));
    }

    #[test]
    fn config_avisa_cuando_la_inferencia_esta_desactivada() {
        let app = app_prueba(false);
        let contenido = texto(&app, 160, 60);
        assert!(contenido.contains("enabled = desactivada"));
        assert!(contenido.contains("La inferencia está desactivada"));
        assert!(contenido.contains("servicio de F2"));
    }

    #[test]
    fn config_sin_fecha_de_bases_ip_avisa() {
        let mut app = app_prueba(true);
        app.ipdb_date = None;
        let contenido = texto(&app, 160, 60);
        assert!(contenido.contains("Bases IP:"));
        assert!(contenido.contains("no disponibles"));
    }
}
