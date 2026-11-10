//! Interfaz de terminal (ratatui + crossterm): arranque, bucle de eventos y modal.
//!
//! El bucle escucha tres fuentes con tokio::select!: eventos de teclado y redimensionado
//! de crossterm, eventos de la aplicación (resultados de escaneo) y un tick periódico
//! para caducar notificaciones. La base de datos se usa solo desde este hilo.

pub mod app;
pub mod keys;
pub mod theme;
pub mod views;

use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use crossterm::event::{Event as CrosstermEvent, EventStream};
use futures::StreamExt;
use ratatui::widgets::{Block, Clear, Paragraph};
use ratatui::DefaultTerminal;
use tokio::sync::broadcast;

use crate::error::{Error, Result};
use crate::events::{AppEvent, ScanCommand};
use crate::notifier::Level;
use crate::repo::Repo;
use crate::scanner::{self, OnlineTracker, ScanReport};

use app::{Action, App};

/// Periodo del tick interno (caducidad de notificaciones).
const TICK: Duration = Duration::from_millis(100);

/// Inicializa la terminal en modo TUI (pantalla alternativa + raw mode).
pub fn init_terminal() -> Result<DefaultTerminal> {
    ratatui::try_init()
        .map_err(|err| Error::Terminal(format!("no se pudo inicializar la terminal: {err}")))
}

/// Restaura la terminal a su estado normal.
pub fn restore_terminal() {
    let _ = ratatui::try_restore();
}

/// Modal bloqueante mostrado cuando la base de datos no se puede abrir al arrancar.
///
/// Abre una terminal temporal, dibuja el error y espera tecla. Devuelve true si el
/// usuario quiere reintentar y false si prefiere salir.
pub fn db_error_modal(
    theme: &theme::Theme,
    error: &Error,
    db_path: &std::path::Path,
) -> Result<bool> {
    let mut terminal = init_terminal()?;
    let resultado = modal_loop(&mut terminal, theme, error, db_path);
    restore_terminal();
    resultado
}

fn modal_loop(
    terminal: &mut DefaultTerminal,
    theme: &theme::Theme,
    error: &Error,
    db_path: &std::path::Path,
) -> Result<bool> {
    loop {
        terminal
            .draw(|frame| {
                let area = frame.area();
                frame.render_widget(Clear, area);
                let bloque = Block::bordered()
                    .border_style(theme.warning)
                    .title("Base de datos inaccesible");
                let interior = bloque.inner(area);
                frame.render_widget(bloque, area);
                let lineas = vec![
                    ratatui::text::Line::from(format!(
                        "No se pudo abrir la base de datos en {}",
                        db_path.display()
                    )),
                    ratatui::text::Line::from(""),
                    ratatui::text::Line::from(format!("Detalle: {error}")),
                    ratatui::text::Line::from(""),
                    ratatui::text::Line::from("Opciones: [Reintentar] (R)   [Salir] (S)"),
                ];
                frame.render_widget(
                    Paragraph::new(lineas)
                        .alignment(ratatui::layout::Alignment::Center)
                        .style(theme.normal),
                    interior,
                );
            })
            .map_err(|err| Error::Terminal(format!("no se pudo dibujar el modal: {err}")))?;

        match crossterm::event::read() {
            Ok(CrosstermEvent::Key(key)) => match key.code {
                crossterm::event::KeyCode::Char('r' | 'R') => return Ok(true),
                crossterm::event::KeyCode::Char('s' | 'S') | crossterm::event::KeyCode::Esc => {
                    return Ok(false)
                }
                _ => {}
            },
            Ok(_) => {}
            Err(err) => {
                return Err(Error::Terminal(format!(
                    "no se pudo leer una tecla del modal: {err}"
                )))
            }
        }
    }
}

/// Ejecuta el bucle principal de la TUI hasta que el usuario salga.
pub async fn run(
    mut app: App,
    mut repo: Repo,
    mut event_rx: broadcast::Receiver<AppEvent>,
) -> Result<()> {
    let mut terminal = init_terminal()?;
    let mut tracker = OnlineTracker::new(app.config.scan.offline_after_cycles);
    let mut stream = EventStream::new();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let resultado = bucle(
        &mut terminal,
        &mut app,
        &mut repo,
        &mut event_rx,
        &mut tracker,
        &mut stream,
        &mut ticker,
    )
    .await;

    if let Some(tx) = &app.command_tx {
        let _ = tx.try_send(ScanCommand::Stop);
    }
    restore_terminal();
    resultado
}

async fn bucle(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    repo: &mut Repo,
    event_rx: &mut broadcast::Receiver<AppEvent>,
    tracker: &mut OnlineTracker,
    stream: &mut EventStream,
    ticker: &mut tokio::time::Interval,
) -> Result<()> {
    loop {
        terminal
            .draw(|frame| views::draw(frame, app))
            .map_err(|err| Error::Terminal(format!("no se pudo dibujar la interfaz: {err}")))?;

        if app.should_quit {
            return Ok(());
        }

        tokio::select! {
            evento = stream.next() => {
                match evento {
                    Some(Ok(CrosstermEvent::Key(key))) => {
                        let accion = app.handle_key(key);
                        aplicar_accion(accion, app, repo);
                    }
                    Some(Ok(CrosstermEvent::Resize(_, _))) => {}
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        tracing::warn!(%err, "error leyendo eventos de terminal");
                        app.push_notification(Level::Warn, format!("Error de terminal: {err}"));
                    }
                    None => return Ok(()),
                }
            }
            evento = event_rx.recv() => {
                match evento {
                    Ok(AppEvent::ScanStarted) => {
                        app.scanning = true;
                    }
                    Ok(AppEvent::Devices(report)) => {
                        procesar_escaneo(*report, app, repo, tracker);
                    }
                    Ok(AppEvent::Quit) => app.should_quit = true,
                    Err(broadcast::error::RecvError::Lagged(perdidos)) => {
                        app.push_notification(
                            Level::Warn,
                            format!("Se han perdido {perdidos} eventos internos"),
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
            _ = ticker.tick() => {
                app.tick();
            }
        }
    }
}

fn aplicar_accion(accion: Action, app: &mut App, repo: &mut Repo) {
    match accion {
        Action::None => {}
        Action::Quit => app.should_quit = true,
        Action::Rescan => {
            app.request_rescan();
        }
        Action::SaveAlias { id, value } => match repo.set_alias(id, value.as_deref()) {
            Ok(()) => {
                recargar_dispositivos(app, repo);
                app.push_notification(Level::Info, "Alias guardado");
            }
            Err(err) => {
                app.push_notification(Level::Error, format!("No se pudo guardar el alias: {err}"))
            }
        },
        Action::SaveNotes { id, value } => match repo.set_notes(id, value.as_deref()) {
            Ok(()) => {
                recargar_dispositivos(app, repo);
                app.push_notification(Level::Info, "Notas guardadas");
            }
            Err(err) => app.push_notification(
                Level::Error,
                format!("No se pudieron guardar las notas: {err}"),
            ),
        },
        Action::SetListView(vista) => {
            // La preferencia se persiste en [ui].list_view (una escritura por pulsación).
            app.list_view = vista;
            app.config.ui.list_view = vista;
            match crate::config::Config::save(&app.config, &app.config_path) {
                Ok(()) => app.push_notification(
                    Level::Info,
                    format!("Vista {} ([g] para alternar)", vista.label()),
                ),
                Err(err) => app.push_notification(
                    Level::Error,
                    format!("No se pudo guardar [ui].list_view: {err}"),
                ),
            }
        }
        Action::SetDeviceTypeManual { id, value } => {
            // La recarga puede mover el equipo de grupo en la vista agrupada:
            // se conserva la selección por id, no por índice.
            let seleccionado = app.selected_device().map(|device| device.id);
            match repo.set_device_type_manual(id, value) {
                Ok(()) => {
                    recargar_dispositivos(app, repo);
                    if let Some(device_id) = seleccionado {
                        reseleccionar_por_id(app, device_id);
                    }
                    let etiqueta = value
                        .map(|tipo| format!("Tipo manual: {}", tipo.label()))
                        .unwrap_or_else(|| "Tipo automático".to_string());
                    app.push_notification(Level::Info, etiqueta);
                }
                Err(err) => app.push_notification(
                    Level::Error,
                    format!("No se pudo guardar el tipo manual: {err}"),
                ),
            }
        }
    }
}

/// Reselecciona el equipo indicado por id tras recargar la lista.
fn reseleccionar_por_id(app: &mut App, device_id: i64) {
    let indices = app.visible_indices();
    if let Some(posicion) = indices.iter().position(|indice| {
        app.devices
            .get(*indice)
            .map(|device| device.id == device_id)
            .unwrap_or(false)
    }) {
        app.selected = posicion;
        app.clamp_selection();
    }
}

fn recargar_dispositivos(app: &mut App, repo: &Repo) {
    match repo.list_devices() {
        Ok(devices) => {
            app.devices = devices;
            app.clamp_selection();
        }
        Err(err) => app.push_notification(
            Level::Error,
            format!("No se pudo recargar la lista de equipos: {err}"),
        ),
    }
}

fn procesar_escaneo(
    report: ScanReport,
    app: &mut App,
    repo: &mut Repo,
    tracker: &mut OnlineTracker,
) {
    app.scanning = false;
    app.last_scan = Some(Instant::now());
    app.last_scan_devices = report.hosts.len();

    if !report.privileged && !report.passive_only && !app.degraded_warned {
        app.push_notification(
            Level::Warn,
            "Modo degradado: sin CAP_NET_RAW. Solo fuentes pasivas; para activo: sudo setcap cap_net_raw+ep target/debug/almenara",
        );
        app.degraded_warned = true;
    }

    for error in &report.errors {
        if error.starts_with("Sin CAP_NET_RAW") {
            continue;
        }
        app.push_notification(Level::Warn, format!("Aviso del escaneo: {error}"));
    }
    tracing::debug!(
        equipos = report.hosts.len(),
        respondedores_icmp = report.icmp_responders.len(),
        duracion_ms = report.duration.as_millis(),
        "resultado del escaneo de red"
    );

    let retencion = app.config.storage.events_retention_days;
    // Umbral de obsolescencia de servicios: N ciclos sin verse (STALE derivado).
    let segundos_obsoletos = app
        .config
        .scan
        .interval_s
        .saturating_mul(u64::from(app.config.scan.offline_after_cycles));
    let stale_before = (Utc::now() - chrono::Duration::seconds(segundos_obsoletos as i64))
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    match scanner::reconcile(repo, &report, tracker, retencion, &stale_before) {
        Ok(reconciliacion) => {
            let notificaciones = reconciliacion.notifications();
            let errores = reconciliacion.errors.clone();
            let mut resumen = format!(
                "Escaneo completado en {:.1} s: {} equipos, {} nuevos, {} offline",
                report.duration.as_secs_f64(),
                reconciliacion.devices.len(),
                reconciliacion.new_devices,
                reconciliacion.marked_offline
            );
            if reconciliacion.services_detected > 0 {
                resumen.push_str(&format!(", {} servicios", reconciliacion.services_detected));
            }
            if reconciliacion.pruned_events > 0 {
                resumen.push_str(&format!(
                    ", {} eventos purgados",
                    reconciliacion.pruned_events
                ));
            }
            if reconciliacion.stale_services > 0 {
                resumen.push_str(&format!(
                    ", {} servicios obsoletos",
                    reconciliacion.stale_services
                ));
            }
            if reconciliacion.pruned_services > 0 {
                resumen.push_str(&format!(
                    ", {} servicios purgados",
                    reconciliacion.pruned_services
                ));
            }
            app.apply_reconciliation(reconciliacion);
            app.push_notification(Level::Info, resumen);
            for notification in notificaciones {
                app.push_notification_obj(notification);
            }
            for error in errores {
                app.push_notification(Level::Error, error);
            }
        }
        Err(err) => {
            app.push_notification(
                Level::Error,
                format!("No se pudo guardar el resultado del escaneo: {err}"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::tui::app::App;
    use std::path::PathBuf;

    fn app_prueba() -> App {
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

    #[test]
    fn las_acciones_modifican_el_estado() {
        let mut app = app_prueba();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("data.db");
        let mut repo = Repo::init(&db).unwrap();
        aplicar_accion(Action::Quit, &mut app, &mut repo);
        assert!(app.should_quit);

        let mut app = app_prueba();
        aplicar_accion(Action::None, &mut app, &mut repo);
        assert!(!app.should_quit);
    }

    fn app_con_config(dir: &tempfile::TempDir) -> App {
        let mut app = app_prueba();
        app.config_path = dir.path().join("config.toml");
        app
    }

    #[test]
    fn set_list_view_persiste_la_preferencia() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("data.db");
        let mut repo = Repo::init(&db).unwrap();
        let mut app = app_con_config(&dir);

        aplicar_accion(
            Action::SetListView(crate::config::ListView::Grouped),
            &mut app,
            &mut repo,
        );
        assert_eq!(app.list_view, crate::config::ListView::Grouped);
        assert_eq!(app.config.ui.list_view, crate::config::ListView::Grouped);
        let guardada = Config::load(Some(&app.config_path)).expect("recargar configuración");
        assert_eq!(guardada.ui.list_view, crate::config::ListView::Grouped);

        aplicar_accion(
            Action::SetListView(crate::config::ListView::Flat),
            &mut app,
            &mut repo,
        );
        let guardada = Config::load(Some(&app.config_path)).expect("recargar configuración");
        assert_eq!(guardada.ui.list_view, crate::config::ListView::Flat);
    }

    #[test]
    fn set_device_type_manual_persiste_y_conserva_la_seleccion() {
        let dir = tempfile::tempdir().unwrap();
        let mut repo = Repo::init(&dir.path().join("data.db")).unwrap();
        let id_interfaz = repo
            .upsert_interface(&crate::repo::Interface::without_id(
                "eth0",
                Some("aa:bb:cc:dd:ee:ff".to_string()),
                Some("192.168.1.10".to_string()),
                Some("255.255.255.0".to_string()),
                Some("192.168.1.1".to_string()),
                true,
                "2026-01-01T00:00:00Z",
            ))
            .unwrap();
        let (id, _) = repo
            .upsert_device(&crate::repo::DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.50".to_string(),
                hostname: Some("laptop".to_string()),
                vendor: None,
                interface_id: id_interfaz,
                device_type: "unknown".to_string(),
            })
            .unwrap();

        let mut app = app_prueba();
        app.config.ui.list_view = crate::config::ListView::Grouped;
        app.list_view = crate::config::ListView::Grouped;
        app.set_data(
            repo.list_devices().unwrap(),
            repo.list_interfaces().unwrap(),
        );
        assert_eq!(app.selected_device().map(|device| device.id), Some(id));

        aplicar_accion(
            Action::SetDeviceTypeManual {
                id,
                value: Some(crate::classify::DeviceType::Printer),
            },
            &mut app,
            &mut repo,
        );
        let dispositivo = repo
            .get_device_by_mac("aa:bb:cc:dd:ee:01")
            .unwrap()
            .unwrap();
        assert_eq!(dispositivo.device_type_manual.as_deref(), Some("printer"));
        assert_eq!(dispositivo.effective_device_type(), "printer");
        assert_eq!(
            app.selected_device().map(|device| device.id),
            Some(id),
            "la selección debe conservarse tras moverse de grupo"
        );
    }
}
