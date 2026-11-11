//! Pestaña Config: configuración activa en modo solo lectura.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::alerts::RuleId;
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

    // Alertas (F6): [alerts], notificador, horario silencioso y propio equipo.
    lineas.extend(bloque_alertas(app));
    lineas.push(Line::from(""));

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

    // Histórico (F5): [history], tamaño de la base de datos y última purga.
    lineas.extend(bloque_historico(app));
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

/// Sección [alerts] de F6 y estado de las notificaciones (§6, mockup 5).
///
/// Pinta la configuración activa, el notificador (servidor o próximo intento),
/// el horario silencioso, las notificaciones descartadas y el aprendizaje y el
/// inventario del propio equipo.
fn bloque_alertas(app: &App) -> Vec<Line<'static>> {
    let alerts = &app.config.alerts;
    let mut lineas: Vec<Line> = Vec::new();
    lineas.push(Line::from(Span::styled("Alertas (F6)", app.theme.accent)));
    lineas.push(Line::from(vec![
        Span::styled("  [alerts] ", app.theme.accent),
        Span::styled(
            format!(
                "enabled = {}   retention_days = {}   learning_days = {}",
                alerts.enabled, alerts.retention_days, alerts.learning_days
            ),
            app.theme.normal,
        ),
    ]));
    lineas.push(Line::from(Span::styled(
        format!(
            "    catch_up_minutes = {}   dedup_hours = {}   quiet_hours = {}",
            alerts.catch_up_minutes,
            alerts.dedup_hours,
            if alerts.quiet_hours.trim().is_empty() {
                "«ninguno»".to_string()
            } else {
                format!("\"{}\"", alerts.quiet_hours.trim())
            }
        ),
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        format!(
            "    desktop_notifications = {}   max_notifications_per_minute = {}",
            alerts.desktop_notifications, alerts.max_notifications_per_minute
        ),
        app.theme.normal,
    )));
    let traffic = alerts.traffic_high;
    lineas.push(Line::from(Span::styled(
        format!(
            "    traffic_high: ×{} la mediana · {} días · mínimo {} · ↓ {} MB · ↑ {} MB/h",
            traffic.factor,
            traffic.baseline_days,
            traffic.min_days,
            traffic.min_mb_down,
            traffic.min_mb_up
        ),
        app.theme.normal,
    )));
    let reglas_activas = RuleId::ALL
        .iter()
        .filter(|regla| alerts.rule(**regla).enabled)
        .count();
    lineas.push(Line::from(Span::styled(
        format!(
            "    capture_drops: > {} % durante {} min · reglas: {reglas_activas} de {} activas",
            alerts.capture_drops.percent,
            alerts.capture_drops.minutes,
            RuleId::ALL.len()
        ),
        app.theme.normal,
    )));
    lineas.push(Line::from(""));

    lineas.push(linea_notificador(app));
    lineas.push(linea_horario_silencioso(app));
    if let Some(notificador) = app.alert_notifier.as_ref() {
        let descartadas = notificador.drops();
        if descartadas > 0 {
            lineas.push(Line::from(vec![
                Span::styled("  Notificaciones descartadas: ", app.theme.accent),
                Span::styled(
                    format!("{descartadas} (el canal del notificador estaba lleno)"),
                    app.theme.warning,
                ),
            ]));
        }
    }
    lineas.push(linea_propio_equipo(app));
    lineas
}

/// Estado del notificador de escritorio, con el servidor o el próximo intento.
fn linea_notificador(app: &App) -> Line<'static> {
    let (texto, estilo) = match app.alert_notifier.as_ref() {
        Some(notificador) => {
            let estado = notificador.status();
            let estilo = match estado {
                crate::notify::NotifierStatus::Disponible { .. } => app.theme.online,
                crate::notify::NotifierStatus::Apagado => app.theme.dim,
                crate::notify::NotifierStatus::NoDisponible { .. } => app.theme.warning,
            };
            let mut texto = estado.summary();
            let enviadas = notificador.enviadas();
            if enviadas > 0 {
                texto.push_str(&format!(" · {enviadas} enviadas"));
            }
            (texto, estilo)
        }
        None => (
            "sin notificador en esta sesión (solo pruebas)".to_string(),
            app.theme.dim,
        ),
    };
    Line::from(vec![
        Span::styled("  Notificaciones de escritorio: ", app.theme.accent),
        Span::styled(texto, estilo),
    ])
}

/// Horario silencioso de las notificaciones: activo o no y cuándo empieza (§7.14).
fn linea_horario_silencioso(app: &App) -> Line<'static> {
    match crate::alerts::QuietHours::parse(&app.config.alerts.quiet_hours) {
        Ok(None) => Line::from(vec![
            Span::styled("  Horario silencioso: ", app.theme.accent),
            Span::styled("sin horario configurado", app.theme.dim),
        ]),
        Ok(Some(horario)) => {
            let activo = horario.contains_at(std::time::SystemTime::now());
            let texto = if activo {
                format!(
                    "ahora sí (hasta las {:02}:{:02})",
                    horario.end_min / 60,
                    horario.end_min % 60
                )
            } else {
                format!(
                    "ahora no (empieza a las {:02}:{:02})",
                    horario.start_min / 60,
                    horario.start_min % 60
                )
            };
            Line::from(vec![
                Span::styled("  Horario silencioso: ", app.theme.accent),
                Span::styled(
                    texto,
                    if activo {
                        app.theme.warning
                    } else {
                        app.theme.normal
                    },
                ),
                Span::styled(format!(" · {}", horario.as_string()), app.theme.dim),
            ])
        }
        Err(_) => Line::from(vec![
            Span::styled("  Horario silencioso: ", app.theme.accent),
            Span::styled(
                format!("«{}» no es válido", app.config.alerts.quiet_hours),
                app.theme.warning,
            ),
        ]),
    }
}

/// Aprendizaje e inventario del propio equipo (§7.3 y §7.11).
fn linea_propio_equipo(app: &App) -> Line<'static> {
    let dias = app.config.alerts.learning_days;
    let mut spans = vec![Span::styled("  Propio equipo: ", app.theme.accent)];
    match app.alerts.host_summary.as_ref() {
        None => spans.push(Span::styled("cargando…", app.theme.dim)),
        Some(resumen) => {
            spans.push(Span::styled(
                texto_aprendizaje(resumen.learning.as_ref(), dias),
                app.theme.normal,
            ));
            if let Some(inventario) = resumen.inventory.as_ref() {
                spans.push(Span::styled(
                    format!(
                        " · inventario: {} apps, {} categorías, {} organizaciones, {} países, {} huellas JA4",
                        inventario.count(crate::history::SeenKind::App),
                        inventario.count(crate::history::SeenKind::Category),
                        inventario.count(crate::history::SeenKind::Org),
                        inventario.count(crate::history::SeenKind::Country),
                        inventario.count(crate::history::SeenKind::Ja4)
                    ),
                    app.theme.dim,
                ));
            }
        }
    }
    Line::from(spans)
}

/// Texto del aprendizaje de lo nuevo para un sujeto (§7.3).
fn texto_aprendizaje(learning: Option<&crate::alerts::LearningState>, dias: u32) -> String {
    match learning {
        None => "sin datos de aprendizaje todavía".to_string(),
        Some(estado) => match estado.learned_at {
            Some(instante) => {
                let unix = instante
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duracion| duracion.as_secs() as i64)
                    .unwrap_or(0);
                let fecha = crate::history::LocalDay::from_unix(unix).label_corto();
                format!("aprendido el {fecha} ({} días con datos)", estado.data_days)
            }
            None if dias == 0 => "sin aprendizaje ([alerts].learning_days = 0)".to_string(),
            None => format!(
                "aprendiendo ({} de {dias} días con datos)",
                estado.data_days
            ),
        },
    }
}

/// Sección [history] de la configuración y estado de la base de datos (F5).
fn bloque_historico(app: &App) -> Vec<Line<'static>> {
    let history = &app.config.history;
    let mut lineas: Vec<Line> = Vec::new();
    lineas.push(Line::from(Span::styled("Histórico (F5)", app.theme.accent)));
    let enabled = if history.enabled { "true" } else { "false" };
    lineas.push(Line::from(vec![
        Span::styled("  [history] ", app.theme.accent),
        Span::styled(format!("enabled = {enabled}"), app.theme.normal),
    ]));
    lineas.push(Line::from(vec![Span::styled(
        format!(
            "    minute_days = {}  (destinos: 2 h)   destination_days = {}",
            history.minute_days, history.destination_days
        ),
        app.theme.normal,
    )]));
    lineas.push(Line::from(Span::styled(
        format!(
            "    hour_days = {}   day_days = {}   top_keys = {}   max_db_mb = {}",
            history.hour_days, history.day_days, history.top_keys, history.max_db_mb
        ),
        app.theme.normal,
    )));
    if !history.enabled {
        lineas.push(Line::from(Span::styled(
            "  El histórico está desactivado ([history] enabled = false): no se guardan rollups ni inventario",
            app.theme.warning,
        )));
    }

    match &app.history.db_stats {
        Some(stats) => {
            let wal = if stats.wal_bytes > 0 {
                format!(" (+ WAL {})", megas(stats.wal_bytes))
            } else {
                String::new()
            };
            let desde = stats
                .data_since
                .as_deref()
                .and_then(crate::history::localtime::unix_de_rfc3339)
                .map(|unix| {
                    let dia = crate::history::LocalDay::from_unix(unix);
                    format!(" · datos desde el {} {}", dia.label_corto(), dia.anio())
                })
                .unwrap_or_default();
            let estilo_tamano = if app.history.db_over_limit {
                app.theme.error
            } else {
                app.theme.normal
            };
            let mut spans = vec![
                Span::styled("  Base de datos: ", app.theme.accent),
                Span::styled(megas(stats.db_bytes), estilo_tamano),
                Span::styled(wal, app.theme.dim),
            ];
            if app.history.db_over_limit {
                spans.push(Span::styled(
                    format!(" · por encima del límite de {} MB", history.max_db_mb),
                    app.theme.error,
                ));
            }
            spans.push(Span::styled(desde, app.theme.dim));
            lineas.push(Line::from(spans));
        }
        None => {
            lineas.push(Line::from(Span::styled(
                "  Base de datos: sin estadísticas todavía",
                app.theme.dim,
            )));
        }
    }

    let mut purga = match &app.history.last_purge {
        Some(stats) => {
            let ahora = crate::history::localtime::now_unix();
            let hace = ahora.saturating_sub(stats.at).max(0);
            let cuando = if hace < 60 {
                format!("hace {hace} s")
            } else if hace < 3600 {
                format!("hace {} min", hace / 60)
            } else if hace < 86_400 {
                format!("hace {} h", hace / 3600)
            } else {
                format!("hace {} d", hace / 86_400)
            };
            format!(
                "  Última purga: {cuando} ({} filas)",
                miles(stats.total_filas())
            )
        }
        None => "  Última purga: todavía no ha corrido".to_string(),
    };
    if let Some(stats) = &app.history.db_stats {
        purga.push_str(&format!(
            " · cobertura en 30 días: {}",
            crate::tui::views::charts::formatear_pct(stats.coverage_30d_pct)
        ));
    }
    lineas.push(Line::from(Span::styled(purga, app.theme.dim)));
    lineas
}

/// Tamaño en MB o GB con una cifra decimal.
fn megas(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.0} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.0} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

/// Agrupa los millares con espacios («4 320»).
fn miles(numero: u64) -> String {
    let texto = numero.to_string();
    let mut salida = String::with_capacity(texto.len() + texto.len() / 3);
    for (posicion, caracter) in texto.chars().enumerate() {
        if posicion > 0 && (texto.len() - posicion).is_multiple_of(3) {
            salida.push(' ');
        }
        salida.push(caracter);
    }
    salida
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
            watched: false,
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
        let contenido = texto(&app, 110, 140);
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

#[cfg(test)]
mod tests_f5 {
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::history::{DbStats, PurgeStats};
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_prueba() -> App {
        App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        )
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
    fn config_muestra_la_seccion_history_y_el_estado_de_la_base_de_datos() {
        let mut app = app_prueba();
        app.history.db_stats = Some(DbStats {
            db_bytes: 212_000_000,
            wal_bytes: 4_000_000,
            data_since: Some("2026-10-12T00:00:00Z".to_string()),
            coverage_30d_pct: 91.0,
        });
        app.history.last_purge = Some(PurgeStats {
            rollup_rows: 3_200,
            seen_rows: 1_000,
            session_rows: 20,
            event_rows: 100,
            vacuum_pages: 0,
            at: crate::history::localtime::now_unix() - 720,
        });
        let contenido = texto(&app, 160, 100);
        assert!(contenido.contains("Histórico (F5)"));
        assert!(contenido.contains("[history]"));
        assert!(contenido.contains("enabled = true"));
        assert!(contenido.contains("minute_days = 2"));
        assert!(contenido.contains("hour_days = 90"));
        assert!(contenido.contains("day_days = 730"));
        assert!(contenido.contains("destination_days = 30"));
        assert!(contenido.contains("top_keys = 20"));
        assert!(contenido.contains("max_db_mb = 1024"));
        assert!(contenido.contains("Base de datos: 212 MB (+ WAL 4 MB)"));
        assert!(contenido.contains("datos desde el 12 oct 2026"));
        assert!(contenido.contains("Última purga: hace 12 min (4 320 filas)"));
        assert!(contenido.contains("cobertura en 30 días: 91 %"));
    }

    #[test]
    fn config_resalta_la_base_de_datos_por_encima_del_limite() {
        let mut app = app_prueba();
        app.history.db_stats = Some(DbStats {
            db_bytes: 2_000_000_000,
            wal_bytes: 0,
            data_since: None,
            coverage_30d_pct: 0.0,
        });
        app.history.db_over_limit = true;
        let contenido = texto(&app, 160, 100);
        assert!(contenido.contains("por encima del límite de 1024 MB"));
        assert!(contenido.contains("2.0 GB"));
    }

    #[test]
    fn config_avisa_cuando_el_historico_esta_desactivado() {
        let mut app = app_prueba();
        app.config.history.enabled = false;
        let contenido = texto(&app, 160, 100);
        assert!(contenido.contains("enabled = false"));
        assert!(contenido.contains("El histórico está desactivado"));
        assert!(contenido.contains("[history] enabled = false"));
    }

    #[test]
    fn config_sin_estadisticas_lo_dice_sin_fallar() {
        let app = app_prueba();
        let contenido = texto(&app, 160, 100);
        assert!(contenido.contains("sin estadísticas todavía"));
        assert!(contenido.contains("Última purga: todavía no ha corrido"));
    }
}

#[cfg(test)]
mod tests_f6 {
    use crate::alerts::{AlertCounts, LearningState, Subject};
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::history::{AlertSummary, Inventory, SeenRow, SubjectSel};
    use crate::tui::app::App;
    use chrono::Timelike;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    fn app_prueba() -> App {
        App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        )
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

    fn filas(cantidad: usize, prefijo: &str) -> Vec<SeenRow> {
        (0..cantidad)
            .map(|indice| SeenRow {
                key: format!("{prefijo}{indice}"),
                label: format!("{prefijo}{indice}"),
                first_seen: "2026-10-12T00:00:00Z".to_string(),
                last_seen: "2026-10-12T00:00:00Z".to_string(),
            })
            .collect()
    }

    fn inventario_host() -> Inventory {
        Inventory {
            device_id: 0,
            since: Some("2026-10-12T00:00:00Z".to_string()),
            apps: filas(41, "app"),
            categories: filas(12, "cat"),
            orgs: filas(230, "org"),
            countries: filas(19, "pais"),
            ja4: filas(27, "ja4"),
            ports: Vec::new(),
        }
    }

    #[test]
    fn config_muestra_la_seccion_alerts() {
        let app = app_prueba();
        let contenido = texto(&app, 160, 120);
        assert!(contenido.contains("Alertas (F6)"));
        assert!(contenido.contains("[alerts]"));
        assert!(contenido.contains("enabled = true"));
        assert!(contenido.contains("retention_days = 90"));
        assert!(contenido.contains("learning_days = 7"));
        assert!(contenido.contains("catch_up_minutes = 10"));
        assert!(contenido.contains("dedup_hours = 24"));
        assert!(contenido.contains("quiet_hours = «ninguno»"));
        assert!(contenido.contains("desktop_notifications = true"));
        assert!(contenido.contains("max_notifications_per_minute = 3"));
        assert!(contenido
            .contains("traffic_high: ×3 la mediana · 14 días · mínimo 5 · ↓ 200 MB · ↑ 50 MB/h"));
        assert!(contenido.contains("capture_drops: > 1 % durante 5 min · reglas: 16 de 16 activas"));
        assert!(contenido.contains("Notificaciones de escritorio:"));
        assert!(contenido.contains("Horario silencioso: sin horario configurado"));
    }

    #[test]
    fn config_muestra_el_notificador_apagado() {
        let mut app = app_prueba();
        app.alert_notifier = Some(crate::notify::spawn(crate::notify::NotifyConfig {
            enabled: false,
        }));
        let contenido = texto(&app, 160, 120);
        assert!(contenido.contains("Notificaciones de escritorio: APAGADO"));
        assert!(contenido.contains("desktop_notifications = false"));
        assert!(!contenido.contains("Notificaciones descartadas"));
    }

    #[test]
    fn config_muestra_si_el_horario_silencioso_esta_activo() {
        let mut app = app_prueba();
        let hora = chrono::Local::now().hour();
        // Ventana de tres horas alrededor de la hora local: siempre activa.
        app.config.alerts.quiet_hours =
            format!("{:02}:00-{:02}:00", (hora + 23) % 24, (hora + 2) % 24);
        let contenido = texto(&app, 160, 120);
        assert!(
            contenido.contains("Horario silencioso: ahora sí"),
            "la ventana contiene la hora actual"
        );
        // Ventana al otro lado del día: ahora no.
        app.config.alerts.quiet_hours =
            format!("{:02}:00-{:02}:00", (hora + 3) % 24, (hora + 5) % 24);
        let contenido = texto(&app, 160, 120);
        assert!(contenido.contains("Horario silencioso: ahora no"));
    }

    #[test]
    fn config_muestra_el_aprendizaje_y_el_inventario_del_propio_equipo() {
        let mut app = app_prueba();
        app.alerts.host_summary = Some(AlertSummary {
            subject: SubjectSel::Host,
            recent: Vec::new(),
            unseen: AlertCounts::default(),
            mutes: Vec::new(),
            learning: Some(LearningState {
                subject: Subject::Host,
                learning_from: SystemTime::now() - Duration::from_secs(7 * 86_400),
                data_days: 4,
                learned_at: None,
            }),
            inventory: Some(inventario_host()),
        });
        let contenido = texto(&app, 200, 120);
        assert!(contenido.contains("Propio equipo: aprendiendo (4 de 7 días con datos)"));
        assert!(contenido.contains(
            "inventario: 41 apps, 12 categorías, 230 organizaciones, 19 países, 27 huellas JA4"
        ));
    }

    #[test]
    fn config_muestra_el_aprendizaje_terminado() {
        let mut app = app_prueba();
        app.alerts.host_summary = Some(AlertSummary {
            subject: SubjectSel::Host,
            recent: Vec::new(),
            unseen: AlertCounts::default(),
            mutes: Vec::new(),
            learning: Some(LearningState {
                subject: Subject::Host,
                learning_from: SystemTime::now() - Duration::from_secs(7 * 86_400),
                data_days: 7,
                learned_at: Some(SystemTime::now() - Duration::from_secs(86_400)),
            }),
            inventory: None,
        });
        let contenido = texto(&app, 200, 120);
        assert!(contenido.contains("aprendido el"));
        assert!(contenido.contains("(7 días con datos)"));
        assert!(!contenido.contains("inventario:"));
    }

    #[test]
    fn la_seccion_de_alertas_cabe_en_ochenta_por_veinticuatro() {
        let app = app_prueba();
        let contenido = texto(&app, 80, 24);
        assert!(contenido.contains("Alertas (F6)"));
        assert!(contenido.contains("Notificaciones de escritorio:"));
        assert!(contenido.contains("Horario silencioso:"));
    }

    #[test]
    fn la_seccion_de_alertas_cabe_en_ciento_veinte_por_cuarenta() {
        let app = app_prueba();
        let contenido = texto(&app, 120, 40);
        assert!(contenido.contains("Alertas (F6)"));
        assert!(contenido.contains("[alerts]"));
        assert!(contenido.contains("Propio equipo:"));
    }
}
