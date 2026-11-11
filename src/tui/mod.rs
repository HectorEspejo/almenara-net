//! Interfaz de terminal (ratatui + crossterm): arranque, bucle de eventos y modal.
//!
//! El bucle escucha tres fuentes con tokio::select!: eventos de teclado y redimensionado
//! de crossterm, eventos de la aplicación (resultados de escaneo) y un tick periódico
//! para caducar notificaciones. La base de datos se usa solo desde este hilo.

pub mod alerts_state;
pub mod app;
pub mod history_state;
pub mod keys;
pub mod theme;
pub mod traffic_state;
pub mod views;

use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use crossterm::event::{Event as CrosstermEvent, EventStream};
use futures::StreamExt;
use ratatui::widgets::{Block, Clear, Paragraph};
use ratatui::DefaultTerminal;
use tokio::sync::broadcast;

use crate::error::{Error, Result};
use crate::events::{AppEvent, ScanCommand, TrafficCommand};
use crate::notifier::Level;
use crate::repo::{ConnectionProtocol, ConnectionUpdate, Repo, SnapshotUpdate};
use crate::scanner::{self, OnlineTracker, ScanReport};
use crate::traffic::DeviceRef;

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
    // F6: motor de alertas, notificador y estado de la pestaña (antes del bucle).
    preparar_alertas(&mut app, &repo);
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
    if let Some(tx) = &app.traffic_command_tx {
        let _ = tx.try_send(TrafficCommand::Stop);
    }

    // Cierre ordenado (§4.8): el agregador cierra el minuto parcial, la TUI lo
    // escribe antes de cerrar la sesión y espera como mucho 2 s a que pare.
    let limite = Instant::now() + Duration::from_secs(2);
    while !app.traffic_stopped && Instant::now() < limite {
        let espera = tokio::time::timeout(Duration::from_millis(100), event_rx.recv()).await;
        match espera {
            Ok(Ok(AppEvent::Rollup(lote))) => {
                escribir_lote_historico(&mut app, &mut repo, *lote);
            }
            Ok(Ok(AppEvent::TrafficStopped)) => app.traffic_stopped = true,
            Ok(Ok(_)) => {}
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => break,
            Err(_) => {}
        }
    }
    // Reintento final de los lotes pendientes (si falla, se pierde como mucho el
    // último minuto; la sesión se cierra igualmente).
    escribir_pendientes(&mut app, &mut repo);
    // F6: al salir, los huecos abiertos se cierran con el cierre de la sesión (§7.10).
    if let Some(id) = app.capture_gap.take() {
        let _ = repo.close_gap(id, std::time::SystemTime::now());
    }
    if let Some(id) = app.session_id {
        if let Err(err) = repo.close_open_gaps(id, std::time::SystemTime::now()) {
            tracing::warn!(%err, "no se pudieron cerrar los huecos abiertos de la sesión");
        }
    }
    if let Some(id) = app.session_id {
        if let Err(err) = repo.close_session(id, std::time::SystemTime::now()) {
            tracing::warn!(%err, "no se pudo cerrar la sesión de Almenara");
        }
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
        // Contexto del histórico (pestaña, detalle, agrupación y ventana): la
        // vista decide qué consultas necesita y el render nunca toca la BD.
        app.history.sync_context(
            app.tab,
            app.detail.as_ref().map(|detalle| detalle.device_id),
            app.traffic_group,
            app.traffic_window,
        );
        app.history.set_history_enabled(app.config.history.enabled);

        terminal
            .draw(|frame| views::draw(frame, app))
            .map_err(|err| Error::Terminal(format!("no se pudo dibujar la interfaz: {err}")))?;

        if app.should_quit {
            return Ok(());
        }

        // Consultas del histórico y de la pestaña Alertas: el lector responde por
        // AppEvent::History con el identificador de la petición (F5 y F6).
        if let Some(lector) = app.history_reader.clone() {
            let ahora_unix = Utc::now().timestamp();
            for (id, consulta) in app.history.history_pending_requests(ahora_unix) {
                lector.query(id, consulta);
            }
            let ctx = crate::tui::alerts_state::AlertsRequestCtx {
                active: app.tab == crate::tui::app::Tab::Alertas,
                config_active: app.tab == crate::tui::app::Tab::Config,
                detail_device: app.detail.as_ref().map(|detalle| detalle.device_id),
                now: ahora_unix,
            };
            for (id, consulta) in app.alerts.pending_requests(&ctx) {
                lector.query(id, consulta);
            }
        }

        tokio::select! {
            evento = stream.next() => {
                match evento {
                    Some(Ok(CrosstermEvent::Key(key))) => {
                        // «¿Quién lo usa?» necesita respuesta con oneshot y timeout:
                        // se resuelve aquí, en el bucle async, no en handle_key.
                        let accion = app.handle_key(key);
                        match accion {
                            Action::WhoUses {
                                dimension,
                                key,
                                label,
                                window,
                            } => {
                                if window.history().is_some() {
                                    // Ventanas de 1 h y 24 h: la respuesta sale del
                                    // lector del histórico, no de la tarea de tráfico.
                                    app.history.ask_who_uses(dimension, key, label, window);
                                } else {
                                    pedir_quien_lo_usa(app, dimension, key, label, window).await;
                                }
                            }
                            otra => aplicar_accion(otra, app, repo),
                        }
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
                    Ok(AppEvent::Traffic(update)) => {
                        app.apply_traffic(*update);
                        if app.should_persist_traffic() {
                            persistir_trafico(app, repo);
                        }
                    }
                    Ok(AppEvent::CaptureNotice { level, message }) => {
                        app.push_notification(level, message);
                    }
                    Ok(AppEvent::History { id, response }) => {
                        // F6: las respuestas de la pestaña Alertas se aplican primero;
                        // si no son suyas, las consume el histórico de F5.
                        if !app.alerts.apply_response(id, &response) {
                            app.history.apply_history_response(id, &response);
                        }
                    }
                    Ok(AppEvent::Rollup(lote)) => {
                        escribir_lote_historico(app, repo, *lote);
                    }
                    Ok(AppEvent::TrafficStopped) => {
                        app.traffic_stopped = true;
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
                if app.traffic.has_live_data() && app.should_persist_traffic() {
                    persistir_trafico(app, repo);
                }
                let consolidar = app
                    .last_consolidation
                    .map(|instante| instante.elapsed() >= Duration::from_secs(1))
                    .unwrap_or(true);
                if consolidar {
                    consolidar_pendientes(app, repo);
                }
                latir_sesion(app, repo);
                tick_alertas(app, repo);
                purgar_si_toca(app, repo);
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
        Action::WhoUses { .. } => {
            // El bucle la resuelve con oneshot y timeout; ver pedir_quien_lo_usa.
        }
        Action::SetTrafficGroup(grupo) => {
            // La preferencia se persiste en [ui].traffic_group, igual que
            // [ui].list_view con el g de Equipos.
            app.config.ui.traffic_group = grupo;
            match crate::config::Config::save(&app.config, &app.config_path) {
                Ok(()) => app.push_notification(
                    Level::Info,
                    format!("Ranking por {} ([ui].traffic_group)", grupo.label()),
                ),
                Err(err) => app.push_notification(
                    Level::Error,
                    format!("No se pudo guardar [ui].traffic_group: {err}"),
                ),
            }
        }
        Action::OpenDetail { device_id } => {
            let drill_down = app.tab == crate::tui::app::Tab::Trafico;
            // `e` en Alertas abre el equipo en Equipos con su detalle (§6): hay que
            // cambiar de pestaña, porque el master-detail solo se pinta en Equipos.
            let desde_alertas = app.tab == crate::tui::app::Tab::Alertas;
            let servicios = match repo.list_services(device_id) {
                Ok(servicios) => servicios,
                Err(err) => {
                    app.push_notification(
                        Level::Warn,
                        format!("No se pudieron cargar los servicios del equipo: {err}"),
                    );
                    Vec::new()
                }
            };
            if drill_down || desde_alertas {
                app.tab = crate::tui::app::Tab::Equipos;
                reseleccionar_por_id(app, device_id);
            }
            app.open_detail(device_id, servicios, drill_down);
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
        Action::MarkAlertSeen(sel) => match repo.mark_seen(sel, std::time::SystemTime::now()) {
            Ok(_) => {
                refrescar_contadores_alertas(app, repo);
                app.alerts.mark_dirty();
            }
            Err(err) => app.push_notification(
                Level::Error,
                format!("No se pudo marcar la alerta como vista: {err}"),
            ),
        },
        Action::MarkAlertsSeen(scope) => {
            let sel = crate::repo::SeenSel::Filter(scope);
            match repo.mark_seen(sel, std::time::SystemTime::now()) {
                Ok(marcadas) => {
                    refrescar_contadores_alertas(app, repo);
                    app.alerts.mark_dirty();
                    app.push_notification(
                        Level::Info,
                        format!("{marcadas} alertas marcadas como vistas"),
                    );
                }
                Err(err) => app.push_notification(
                    Level::Error,
                    format!("No se pudieron marcar las alertas como vistas: {err}"),
                ),
            }
        }
        Action::MuteAlert {
            rule,
            subject,
            until,
        } => match repo.upsert_mute(rule, subject, until) {
            Ok(_) => {
                recargar_silencios(app, repo);
                app.push_notification(
                    Level::Info,
                    format!("Regla «{}» silenciada para este sujeto", rule.name()),
                );
            }
            Err(err) => {
                app.push_notification(Level::Error, format!("No se pudo crear el silencio: {err}"))
            }
        },
        Action::DeleteMute(id) => match repo.delete_mute(id) {
            Ok(()) => {
                recargar_silencios(app, repo);
                app.push_notification(Level::Info, "Silencio eliminado");
            }
            Err(err) => app.push_notification(
                Level::Error,
                format!("No se pudo quitar el silencio: {err}"),
            ),
        },
        Action::SaveRuleSetting { rule, setting } => {
            app.config.alerts.set_rule(rule, &setting);
            if let Err(err) = crate::config::save_rule(&app.config_path, rule, &setting) {
                if !app.alert_rule_save_warned {
                    app.alert_rule_save_warned = true;
                    app.push_notification(
                        Level::Warn,
                        format!(
                            "No se pudo guardar [alerts.rules].{} en config.toml ({err}); el cambio vale para esta sesión",
                            rule.as_str()
                        ),
                    );
                }
            }
            app.alerts.set_rule_settings(&app.config.alerts.params());
            if let Some(motor) = app.alert_engine.as_mut() {
                let acciones = motor.set_rule(rule, setting, std::time::SystemTime::now());
                aplicar_acciones_alertas(app, repo, acciones);
            }
            app.alerts.mark_dirty();
            let estado = if setting.enabled {
                format!("{} ({})", rule.name(), setting.level.label())
            } else {
                format!("{} apagada", rule.name())
            };
            app.push_notification(Level::Info, format!("Regla: {estado}"));
        }
        Action::SetWatched { device_id, watched } => match repo.set_watched(device_id, watched) {
            Ok(()) => {
                recargar_dispositivos(app, repo);
                if let Some(motor) = app.alert_engine.as_mut() {
                    let acciones =
                        motor.set_watched(device_id, watched, std::time::SystemTime::now());
                    aplicar_acciones_alertas(app, repo, acciones);
                }
                app.alerts.mark_dirty();
                let mensaje = if watched {
                    "Equipo vigilado ([p] para desmarcarlo)"
                } else {
                    "El equipo ya no está vigilado"
                };
                app.push_notification(Level::Info, mensaje);
            }
            Err(err) => app.push_notification(
                Level::Error,
                format!("No se pudo cambiar el estado vigilado: {err}"),
            ),
        },
    }
}

/// Recarga los silencios vigentes en el motor tras crearlos o quitarlos (§7.6).
fn recargar_silencios(app: &mut App, repo: &Repo) {
    match repo.active_mutes(std::time::SystemTime::now()) {
        Ok(mutes) => {
            if let Some(motor) = app.alert_engine.as_mut() {
                motor.set_mutes(mutes);
            }
            app.alerts.mark_dirty();
        }
        Err(err) => tracing::warn!(%err, "no se pudieron recargar los silencios"),
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

/// Tope de lotes del minuto pendientes de escribir (§4.1).
const MAX_LOTES_PENDIENTES: usize = 10;

/// Escribe el lote del minuto y su inventario, con reintento y descarte.
///
/// El hilo de la TUI es el único escritor (ADR-35). Si la escritura falla, el
/// lote espera al minuto siguiente; con más de MAX_LOTES_PENDIENTES se descarta el
/// más antiguo, se cuenta en rollup_drops y se avisa una sola vez.
fn escribir_lote_historico(app: &mut App, repo: &mut Repo, lote: crate::history::RollupBatch) {
    app.pending_rollups.push(lote);
    while app.pending_rollups.len() > MAX_LOTES_PENDIENTES {
        app.pending_rollups.remove(0);
        app.rollup_counters.drops = app.rollup_counters.drops.saturating_add(1);
        if !app.rollup_dropped_warned {
            app.rollup_dropped_warned = true;
            app.push_notification(
                Level::Warn,
                "No se puede escribir el histórico: se descartan lotes antiguos (rollup_drops)",
            );
        }
    }
    escribir_pendientes(app, repo);
}

/// Intenta escribir en orden todos los lotes pendientes; para al primer fallo.
fn escribir_pendientes(app: &mut App, repo: &mut Repo) {
    while let Some(lote) = app.pending_rollups.first().cloned() {
        let inicio_escritura = Instant::now();
        match repo.insert_minute_batch(&lote) {
            Ok(cambio) => {
                // Medición de F5/F6: escritura del lote del minuto con tráfico real.
                tracing::debug!(
                    minuto = lote.minute,
                    filas = lote.rows.len(),
                    inventario = lote.seen.len(),
                    duracion_ms = inicio_escritura.elapsed().as_millis(),
                    "lote del minuto escrito"
                );
                app.pending_rollups.remove(0);
                app.rollup_counters.batches = app.rollup_counters.batches.saturating_add(1);
                app.rollup_counters.overflow =
                    app.rollup_counters.overflow.saturating_add(lote.overflow);
                // F6: lo nuevo del inventario (equipos y propio equipo) va al motor.
                let senales = senales_de_inventario(app, repo, &cambio);
                procesar_senales_alertas(app, repo, senales);
                // Si el lote cierra una hora, se consolida en el acto (§4.1) y se
                // evalúa en vivo para «más tráfico de lo habitual» (§7.4).
                if (lote.minute + 60).rem_euclid(3600) == 0 {
                    let hora = lote.minute - lote.minute.rem_euclid(3600);
                    let top_keys = app.config.history.top_keys;
                    match repo.build_hour(hora, top_keys) {
                        Ok(_) => evaluar_hora_cerrada(app, repo, hora),
                        Err(err) => {
                            tracing::warn!(%err, hora, "no se pudo consolidar la hora del histórico");
                        }
                    }
                    limpiar_destinos_si_apagados(app, repo);
                }
                app.history.history_refresh();
            }
            Err(err) => {
                tracing::warn!(%err, "no se pudo escribir el lote del histórico; se reintentará");
                break;
            }
        }
    }
}

/// Construye las horas y días pendientes en tandas de 10 (§4.2 y §4.3).
fn consolidar_pendientes(app: &mut App, repo: &mut Repo) {
    app.last_consolidation = Some(Instant::now());
    if !app.config.history.enabled {
        return;
    }
    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let hora_actual = crate::history::localtime::hour_start(ahora);
    let hoy = crate::history::LocalDay::from_unix(ahora);
    let top_keys = app.config.history.top_keys;

    let pendientes = match repo.pending_hours(hora_actual) {
        Ok(horas) => horas,
        Err(err) => {
            tracing::warn!(%err, "no se pudieron leer las horas pendientes del histórico");
            return;
        }
    };
    let mut consolidadas = 0usize;
    for hora in pendientes.iter().take(10) {
        match repo.build_hour(*hora, top_keys) {
            Ok(_) => consolidadas += 1,
            Err(err) => {
                tracing::warn!(%err, hora, "no se pudo consolidar una hora del histórico");
                break;
            }
        }
    }

    // Un día solo se consolida cuando todas sus horas lo están (23, 24 o 25).
    match repo.pending_days(hoy) {
        Ok(dias) => {
            for dia in dias.iter().take(10) {
                let (desde, hasta) = dia.limits();
                let quedan_horas = match repo.pending_hours(hasta) {
                    Ok(horas) => horas.iter().any(|hora| *hora >= desde && *hora < hasta),
                    Err(_) => true,
                };
                if quedan_horas {
                    continue;
                }
                match repo.build_day(*dia, top_keys) {
                    Ok(_) => {
                        consolidadas += 1;
                        // F6: al consolidar un día local se cuenta el aprendizaje (§7.3).
                        actualizar_aprendizaje(app, repo, *dia);
                    }
                    Err(err) => {
                        tracing::warn!(%err, dia = dia.aaaammdd(), "no se pudo consolidar un día");
                        break;
                    }
                }
            }
        }
        Err(err) => tracing::warn!(%err, "no se pudieron leer los días pendientes"),
    }

    if consolidadas > 0 {
        limpiar_destinos_si_apagados(app, repo);
        app.history.history_refresh();
    }
}

/// Con destination_days = 0 no se guardan destinos por hora (§7.4): se limpian
/// en cuanto se consolida la hora que los tenía por minuto.
fn limpiar_destinos_si_apagados(app: &App, repo: &mut Repo) {
    if app.config.history.destination_days != 0 {
        return;
    }
    if let Err(err) = repo.clear_destination_hours() {
        tracing::warn!(%err, "no se pudieron limpiar los destinos por hora");
    }
}

/// Purga el histórico una vez por hora y avisa si la BD supera el límite (§7.4).
fn purgar_si_toca(app: &mut App, repo: &mut Repo) {
    let toca = app
        .last_purge
        .map(|instante| instante.elapsed() >= Duration::from_secs(3600))
        .unwrap_or(true);
    if !toca {
        return;
    }
    app.last_purge = Some(Instant::now());
    let retencion = app.config.history.retention();
    match repo.purge_history(std::time::SystemTime::now(), &retencion) {
        Ok(stats) => {
            tracing::info!(
                filas = stats.total_filas(),
                paginas = stats.vacuum_pages,
                "purga del histórico"
            );
            app.history.last_purge = Some(stats);
            let bytes = std::fs::metadata(&app.db_path)
                .map(|metadatos| metadatos.len())
                .unwrap_or(0);
            let mb = bytes / (1024 * 1024);
            let limite = app.config.history.max_db_mb;
            let por_encima = mb > limite;
            app.history.db_over_limit = por_encima;
            if por_encima && !app.db_size_warned {
                app.db_size_warned = true;
                app.push_notification(
                    Level::Warn,
                    format!(
                        "La base de datos ({mb} MB) supera [history].max_db_mb = {limite} MB; baja las retenciones o borra la BD"
                    ),
                );
            }
        }
        Err(err) => tracing::warn!(%err, "no se pudo purgar el histórico"),
    }
    if let Err(err) = repo.prune_events(app.config.storage.events_retention_days) {
        tracing::warn!(%err, "no se pudieron podar los eventos");
    }
    // F6: alertas vencidas, silencios caducados, HOST_SEEN y tamaño de la BD.
    purgar_alertas(app, repo);
    // Checkpoint del WAL tras la purga horaria, fuera del cierre del minuto.
    if let Err(err) = repo.wal_checkpoint() {
        tracing::warn!(%err, "no se pudo hacer checkpoint del WAL tras la purga");
    }
}

/// Da el latido de la sesión cada minuto, haya tráfico o no (§7.6).
fn latir_sesion(app: &mut App, repo: &mut Repo) {
    let Some(id) = app.session_id else {
        return;
    };
    let toca = app
        .last_beat
        .map(|instante| instante.elapsed() >= Duration::from_secs(60))
        .unwrap_or(true);
    if !toca {
        return;
    }
    match repo.beat_session(id, std::time::SystemTime::now()) {
        Ok(()) => app.last_beat = Some(Instant::now()),
        Err(err) => tracing::warn!(%err, "no se pudo dar el latido de la sesión"),
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
            // F6: señales del ciclo al motor y aprendizaje de los equipos nuevos
            // (§4.1 y §7.3). La línea base termina tras el primer ciclo completo.
            let senales = senales_de_escaneo(&reconciliacion);
            for evento in &reconciliacion.events {
                if evento.event_type == crate::repo::EventType::New {
                    let desde = reconciliacion
                        .devices
                        .iter()
                        .find(|device| device.id == evento.device_id)
                        .and_then(|device| crate::repo::rfc3339_a_instante(&device.first_seen))
                        .unwrap_or_else(std::time::SystemTime::now);
                    if let Err(err) = repo.ensure_learning(
                        crate::alerts::Subject::Device(evento.device_id),
                        desde,
                        app.config.alerts.learning_days,
                    ) {
                        tracing::warn!(%err, "no se pudo crear el aprendizaje del equipo nuevo");
                    }
                }
            }
            app.apply_reconciliation(reconciliacion);
            app.alerts.mark_dirty();
            // La línea base termina DESPUÉS de pasar las señales del primer ciclo:
            // así la red de partida de una BD nueva no genera «equipo nuevo» (§7.9).
            procesar_senales_alertas(app, repo, senales);
            if let Some(motor) = app.alert_engine.as_mut() {
                motor.end_baseline();
            }
            app.history.history_refresh();
            actualizar_mapa_dispositivos(app, repo);
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

/// Persiste el snapshot por dispositivo, las conexiones con sus etiquetas y la
/// caché de nombres cada 5 s.
///
/// Es la única escritura de tráfico en SQLite y se ejecuta en el hilo de la TUI,
/// respetando la regla de una única conexión de escritura.
fn persistir_trafico(app: &mut App, repo: &mut Repo) {
    for estadisticas in &app.traffic.devices {
        let snapshot = SnapshotUpdate {
            device_id: estadisticas.device_id,
            bytes_in: estadisticas.bytes_in.min(i64::MAX as u64) as i64,
            bytes_out: estadisticas.bytes_out.min(i64::MAX as u64) as i64,
            packets_in: estadisticas.packets_in.min(i64::MAX as u64) as i64,
            packets_out: estadisticas.packets_out.min(i64::MAX as u64) as i64,
            peak_bps: estadisticas.peak_bps.min(i64::MAX as u64) as i64,
            window_s: 60,
        };
        if let Err(err) = repo.upsert_snapshot(&snapshot) {
            tracing::warn!(%err, "no se pudo guardar el snapshot de tráfico");
            return;
        }
    }
    for conexion in &app.traffic.connections {
        // Etiquetas de F4 resueltas por el motor de inferencia: rol, protocolo de
        // app, nombre del servidor y su fuente, app, categoría, fuente y JA4.
        let etiqueta = conexion.label.as_ref();
        let update = ConnectionUpdate {
            id: None,
            device_id: conexion.device_id,
            protocol: protocolo_repo(conexion.protocol()),
            src_ip: conexion.origin.ip.to_string(),
            src_port: conexion.origin.port,
            dst_ip: conexion.destination.ip.to_string(),
            dst_port: conexion.destination.port,
            state: conexion.state.clone(),
            bytes_in: conexion.bytes_in.min(i64::MAX as u64) as i64,
            bytes_out: conexion.bytes_out.min(i64::MAX as u64) as i64,
            client_is_src: etiqueta.and_then(|valor| valor.client_is_src),
            app_protocol: etiqueta
                .and_then(|valor| valor.app_protocol)
                .map(|protocolo| protocolo.as_str().to_string()),
            server_name: etiqueta.and_then(|valor| valor.server_name.clone()),
            name_source: etiqueta
                .and_then(|valor| valor.name_source)
                .map(|fuente| fuente.as_str().to_string()),
            app: etiqueta.and_then(|valor| valor.app.clone()),
            category: etiqueta.and_then(|valor| valor.category.clone()),
            app_source: etiqueta
                .and_then(|valor| valor.app_source)
                .map(|fuente| fuente.as_str().to_string()),
            ja4: etiqueta.and_then(|valor| valor.ja4.clone()),
        };
        if let Err(err) = repo.upsert_connection(&update) {
            tracing::warn!(%err, "no se pudo guardar la conexión");
            return;
        }
    }
    match repo.prune_expired_connections(std::time::SystemTime::now()) {
        Ok(borradas) if borradas > 0 => {
            tracing::debug!(borradas, "conexiones caducadas purgadas");
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, "no se pudieron purgar las conexiones"),
    }

    // NAME_CACHE: entradas nuevas o refrescadas del último ciclo y purga de las
    // caducadas, en el mismo ciclo de 5 s.
    if !app.traffic.pending_names.is_empty() {
        let entradas = std::mem::take(&mut app.traffic.pending_names);
        match repo.upsert_names(&entradas) {
            Ok(guardadas) => {
                tracing::debug!(guardadas, "caché de nombres persistida");
            }
            Err(err) => tracing::warn!(%err, "no se pudo persistir la caché de nombres"),
        }
    }
    match repo.prune_names(std::time::SystemTime::now()) {
        Ok(purgadas) if purgadas > 0 => {
            tracing::debug!(purgadas, "nombres caducados purgados");
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, "no se pudieron purgar los nombres caducados"),
    }
}

/// Traduce el protocolo de captura al de la capa de persistencia.
fn protocolo_repo(protocolo: crate::capture::Protocol) -> ConnectionProtocol {
    match protocolo {
        crate::capture::Protocol::Tcp => ConnectionProtocol::Tcp,
        crate::capture::Protocol::Udp => ConnectionProtocol::Udp,
        crate::capture::Protocol::Icmp | crate::capture::Protocol::Icmpv6 => {
            ConnectionProtocol::Icmp
        }
        crate::capture::Protocol::Other => ConnectionProtocol::Other,
    }
}

/// Envía a la tarea de tráfico el mapa de dispositivos con nombre y servicios.
///
/// El nombre visible y los servicios de F2 se usan para etiquetar destinos de la
/// LAN (app por servicio) y para los rankings; sin ellos, la tarea de tráfico
/// solo podría etiquetar por IP.
fn actualizar_mapa_dispositivos(app: &App, repo: &Repo) {
    let Some(tx) = &app.traffic_command_tx else {
        return;
    };
    let devices: Vec<DeviceRef> = app
        .devices
        .iter()
        .map(|device| {
            let servicios = repo
                .list_services(device.id)
                .unwrap_or_default()
                .into_iter()
                .map(|servicio| crate::traffic::ServiceRef {
                    port: servicio.port,
                    protocol: match servicio.protocol {
                        crate::repo::Protocol::Tcp => crate::capture::Protocol::Tcp,
                        crate::repo::Protocol::Udp => crate::capture::Protocol::Udp,
                    },
                    service: servicio.service.clone(),
                })
                .collect();
            DeviceRef::with_details(
                device.id,
                device.ip.clone(),
                device.mac.clone(),
                Some(device.display_name().to_string()),
                servicios,
            )
        })
        .collect();
    let _ = tx.try_send(TrafficCommand::UpdateDevices(devices));
}

/// Resuelve «¿Quién lo usa?» con [TrafficCommand::WhoUses] y un timeout de 200 ms.
///
/// La consulta se calcula al momento en el agregador; si la tarea no responde a
/// tiempo se avisa y se cierra el panel para no dejar la interfaz «Consultando…».
async fn pedir_quien_lo_usa(
    app: &mut App,
    dimension: crate::rankings::Dimension,
    key: String,
    label: String,
    window: crate::rankings::Window,
) {
    let Some(tx) = app.traffic_command_tx.clone() else {
        app.close_who_uses();
        app.push_notification(
            Level::Info,
            "La tarea de tráfico no está disponible en este momento",
        );
        return;
    };
    let (respuesta_tx, respuesta_rx) = tokio::sync::oneshot::channel();
    let orden = TrafficCommand::WhoUses {
        dimension,
        key,
        window,
        reply: respuesta_tx,
    };
    if tx.send(orden).await.is_err() {
        app.close_who_uses();
        app.push_notification(
            Level::Warn,
            "No se pudo consultar «¿Quién lo usa?»: la tarea de tráfico no responde",
        );
        return;
    }
    match tokio::time::timeout(Duration::from_millis(200), respuesta_rx).await {
        Ok(Ok(filas)) => {
            if filas.is_empty() {
                app.push_notification(
                    Level::Info,
                    format!("Ningún equipo usa «{label}» en esta ventana"),
                );
            }
            app.set_who_uses(filas);
        }
        Ok(Err(_)) => {
            app.close_who_uses();
            app.push_notification(
                Level::Warn,
                "La tarea de tráfico cerró sin responder a «¿Quién lo usa?»",
            );
        }
        Err(_) => {
            app.close_who_uses();
            app.push_notification(
                Level::Warn,
                "«¿Quién lo usa?» no respondió en 200 ms; inténtalo de nuevo",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Fase 6: alertas (motor puro, notificador y señales en vivo)
// ---------------------------------------------------------------------------

/// Prepara el motor de alertas, el notificador y el estado de la pestaña (§4.4).
fn preparar_alertas(app: &mut App, repo: &Repo) {
    app.alerts.set_rule_settings(&app.config.alerts.params());
    app.alerts.mark_dirty();
    if let Ok(counts) = repo.unseen_counts() {
        app.alerts.set_counts(counts);
    }
    let params = app.config.alerts.params();
    let snapshot = match repo.engine_snapshot(std::time::SystemTime::now()) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            tracing::warn!(%err, "no se pudo cargar el estado inicial del motor de alertas");
            Default::default()
        }
    };
    if snapshot.devices_empty {
        tracing::debug!("línea base de alertas activa: la red de partida no avisa");
    }
    app.alert_engine = Some(crate::alerts::AlertEngine::new(params, snapshot));
    app.alert_notifier = Some(crate::notify::spawn(crate::notify::NotifyConfig {
        enabled: app.config.alerts.desktop_notifications,
    }));
}

/// Pasa una tanda de señales al motor y aplica las acciones que devuelve.
fn procesar_senales_alertas(app: &mut App, repo: &mut Repo, senales: Vec<crate::alerts::Signal>) {
    if senales.is_empty() {
        return;
    }
    let ahora = std::time::SystemTime::now();
    let mut acciones = Vec::new();
    if let Some(motor) = app.alert_engine.as_mut() {
        for senal in senales {
            acciones.extend(motor.handle(senal, ahora));
        }
    }
    aplicar_acciones_alertas(app, repo, acciones);
}

/// Aplica las acciones que devuelve el motor de alertas (ADR-68).
fn aplicar_acciones_alertas(
    app: &mut App,
    repo: &mut Repo,
    acciones: Vec<crate::alerts::AlertAction>,
) {
    if acciones.is_empty() {
        return;
    }
    for accion in acciones {
        aplicar_accion_alerta(app, repo, accion);
    }
    refrescar_contadores_alertas(app, repo);
}

fn refrescar_contadores_alertas(app: &mut App, repo: &Repo) {
    match repo.unseen_counts() {
        Ok(counts) => app.alerts.set_counts(counts),
        Err(err) => tracing::warn!(%err, "no se pudieron leer los contadores de alertas"),
    }
    match repo.unseen_device_ids() {
        Ok(ids) => app.alerts.set_device_unseen(ids),
        Err(err) => tracing::warn!(%err, "no se pudieron leer los equipos con alertas sin ver"),
    }
    app.last_alert_counts = Some(Instant::now());
}

/// Aplica una acción suelta del motor; si falla la escritura, la deja pendiente
/// para reintentarla en el minuto siguiente (§7.5).
fn aplicar_accion_alerta(app: &mut App, repo: &mut Repo, accion: crate::alerts::AlertAction) {
    use crate::alerts::AlertAction;
    let ahora = std::time::SystemTime::now();
    match accion {
        AlertAction::Insert { alert, notify } => match repo.insert_alert(&alert, ahora) {
            Ok(id) => {
                if let Some(clave) = alert.dedup_key() {
                    if let Some(motor) = app.alert_engine.as_mut() {
                        motor.inserted(&clave, id);
                    }
                }
                if let Some(notice) = notify {
                    notificar_alerta(app, repo, id, &alert.title, notice);
                }
                tracing::debug!(regla = alert.rule.as_str(), id, "alerta creada");
                app.alerts.mark_dirty();
            }
            Err(err) => {
                tracing::warn!(%err, "no se pudo escribir la alerta; se reintentará en el minuto siguiente");
                if !app.alert_write_warned {
                    app.alert_write_warned = true;
                    app.push_notification(
                        Level::Error,
                        "No se pudieron guardar las alertas; se reintentará en el minuto siguiente",
                    );
                }
                app.pending_alert_actions
                    .push(AlertAction::Insert { alert, notify });
            }
        },
        AlertAction::InsertSummary {
            alert,
            grouped,
            notify,
        } => match repo.insert_summary(&alert, &grouped, ahora) {
            Ok(id) => {
                if let Some(notice) = notify {
                    notificar_alerta(app, repo, id, &alert.title, notice);
                }
                app.alerts.mark_dirty();
            }
            Err(err) => {
                tracing::warn!(%err, "no se pudo escribir el resumen de alertas");
                app.pending_alert_actions.push(AlertAction::InsertSummary {
                    alert,
                    grouped,
                    notify,
                });
            }
        },
        AlertAction::Repeat {
            id,
            at,
            details,
            reactivate,
        } => match repo.repeat_alert(id, at, &details, reactivate) {
            Ok(()) => {
                app.alerts.mark_dirty();
            }
            Err(err) => {
                tracing::warn!(%err, id, "no se pudo repetir la alerta");
                app.pending_alert_actions.push(AlertAction::Repeat {
                    id,
                    at,
                    details,
                    reactivate,
                });
            }
        },
        AlertAction::Resolve { id, at } => match repo.resolve_alert(id, at) {
            Ok(()) => {
                app.alerts.mark_dirty();
            }
            Err(err) => {
                tracing::warn!(%err, id, "no se pudo resolver la alerta");
                app.pending_alert_actions
                    .push(AlertAction::Resolve { id, at });
            }
        },
        AlertAction::Notify(notice) => {
            if let Some(notificador) = app.alert_notifier.as_ref() {
                notificador.notify(notice);
            }
        }
    }
}

/// Encola una notificación de escritorio y marca notified solo si salió de
/// verdad en una notificación propia (§7.2); deja el aviso de una línea de 10 s.
fn notificar_alerta(
    app: &mut App,
    repo: &mut Repo,
    id: i64,
    titulo: &str,
    notice: crate::alerts::Notice,
) {
    let entregada = app
        .alert_notifier
        .as_ref()
        .map(|notificador| notificador.notify(notice))
        .unwrap_or(false);
    if entregada {
        if let Err(err) = repo.mark_alert_notified(id) {
            tracing::warn!(%err, id, "no se pudo marcar la alerta como notificada");
        }
        if app.tab != crate::tui::app::Tab::Alertas {
            app.push_alert_notice(format!("▲ Alerta importante: {titulo} · [5] para verla"));
        }
    }
}

/// Reintenta las acciones del motor que no se pudieron escribir (una vez por minuto).
fn reintentar_alertas(app: &mut App, repo: &mut Repo) {
    if app.pending_alert_actions.is_empty() {
        return;
    }
    let toca = app
        .last_alert_retry
        .map(|ultimo| ultimo.elapsed() >= std::time::Duration::from_secs(60))
        .unwrap_or(true);
    if !toca {
        return;
    }
    app.last_alert_retry = Some(Instant::now());
    let pendientes = std::mem::take(&mut app.pending_alert_actions);
    aplicar_acciones_alertas(app, repo, pendientes);
}

/// Tareas periódicas de la F6 en cada tick de la TUI.
fn tick_alertas(app: &mut App, repo: &mut Repo) {
    let ahora = std::time::SystemTime::now();

    // Contadores de la barra y marcas de Equipos: cada 5 s y tras entrar en la
    // pestaña Alertas, se piden al escritor (consultas de agregación baratas).
    let toca_contadores = app
        .last_alert_counts
        .map(|ultimo| ultimo.elapsed() >= std::time::Duration::from_secs(5))
        .unwrap_or(true);
    if toca_contadores {
        refrescar_contadores_alertas(app, repo);
    }
    if app.tab == crate::tui::app::Tab::Alertas && !app.alert_tab_active {
        app.alerts.mark_dirty();
    }
    app.alert_tab_active = app.tab == crate::tui::app::Tab::Alertas;

    // El resto de tareas (suspensión, huecos, motor y reintentos) se ejecuta una
    // vez por segundo, como pide §7.10; el tick de la TUI es de 100 ms.
    let toca_tick = app
        .last_alert_tick
        .map(|ultimo| ultimo.elapsed() >= std::time::Duration::from_secs(1))
        .unwrap_or(true);
    if !toca_tick {
        return;
    }
    app.last_alert_tick = Some(Instant::now());

    // Suspensión del equipo: hueco suspend ya cerrado (§7.10).
    if let Some(suspension) = app.suspend.detect() {
        if let Some(session_id) = app.session_id {
            match repo.open_gap(
                session_id,
                crate::repo::GapKind::Suspend,
                suspension.from,
                Some(suspension.to),
            ) {
                Ok(_) => {
                    tracing::info!(
                        desde = %crate::repo::instante_a_rfc3339(suspension.from),
                        "suspensión del equipo detectada; hueco guardado"
                    );
                    app.history.history_refresh();
                    app.alerts.mark_dirty();
                }
                Err(err) => tracing::warn!(%err, "no se pudo guardar el hueco de suspensión"),
            }
        }
    }

    // Captura parada dentro de la sesión: hueco capture abierto al pararse y
    // cerrado al volver (§7.10). No se abre si la captura nunca debió empezar.
    let deberia_capturar = app.config.capture.enabled && app.capabilities.raw_sockets;
    let capturando = app.traffic.capture.active;
    if deberia_capturar && !capturando && app.capture_gap.is_none() {
        if let Some(session_id) = app.session_id {
            match repo.open_gap(session_id, crate::repo::GapKind::Capture, ahora, None) {
                Ok(id) => {
                    app.capture_gap = Some(id);
                    app.history.history_refresh();
                }
                Err(err) => tracing::warn!(%err, "no se pudo abrir el hueco de captura parada"),
            }
        }
    } else if capturando {
        if let Some(id) = app.capture_gap.take() {
            match repo.close_gap(id, ahora) {
                Ok(()) => {
                    app.history.history_refresh();
                    app.alerts.mark_dirty();
                    // Resolver capture_stopped en el acto (§7.8).
                    muestrear_salud(app, repo);
                }
                Err(err) => tracing::warn!(%err, "no se pudo cerrar el hueco de captura parada"),
            }
        }
    }
    app.capture_was_active = capturando;

    // Salud de la captura y de la BD: una muestra por minuto (§7.8).
    let toca_salud = app
        .last_health
        .map(|ultimo| ultimo.elapsed() >= std::time::Duration::from_secs(60))
        .unwrap_or(true);
    if toca_salud {
        app.last_health = Some(Instant::now());
        muestrear_salud(app, repo);
    }

    // Tareas del motor: fin de la puesta al día y liberación del tope de
    // notificaciones (§7.2 y §7.9).
    let acciones = app
        .alert_engine
        .as_mut()
        .map(|motor| motor.tick(ahora))
        .unwrap_or_default();
    aplicar_acciones_alertas(app, repo, acciones);

    reintentar_alertas(app, repo);
}

/// Toma una muestra de salud con lo que ya tiene el hilo de la TUI (§7.8).
fn muestrear_salud(app: &mut App, repo: &mut Repo) {
    let Some(motor) = app.alert_engine.as_mut() else {
        return;
    };
    let captura = &app.traffic.capture;
    let total = captura.total;
    let drops = captura.drops;
    let limit = captura.limit_drops;
    let nuevos = total.saturating_sub(app.health_prev_total);
    let perdidos = drops.saturating_sub(app.health_prev_drops);
    let limitados = limit.saturating_sub(app.health_prev_limit_drops);
    let perdidos_totales = perdidos.saturating_add(limitados);
    let denominador = nuevos.saturating_add(perdidos_totales);
    let drops_pct_minute = if denominador > 0 {
        Some((perdidos_totales as f64 * 100.0 / denominador as f64) as f32)
    } else {
        None
    };
    app.health_prev_total = total;
    app.health_prev_drops = drops;
    app.health_prev_limit_drops = limit;

    let stats = crate::alerts::CaptureStats {
        enabled: app.config.capture.enabled,
        privileged: app.capabilities.raw_sockets,
        running: captura.active,
        error: captura.disabled_reason.clone(),
        drops_pct_minute,
        kernel_drops: drops,
        limit_drops: limit,
        interface: captura.interfaces.join(","),
    };
    let db = crate::alerts::DbSize {
        db_bytes: std::fs::metadata(&app.db_path)
            .map(|metadatos| metadatos.len())
            .unwrap_or(0),
        wal_bytes: std::fs::metadata(format!("{}-wal", app.db_path.display()))
            .map(|metadatos| metadatos.len())
            .unwrap_or(0),
        max_db_mb: app.config.history.max_db_mb,
    };
    let sample = crate::alerts::Health::sample(&stats, &db, std::time::SystemTime::now());
    let acciones = motor.handle(
        crate::alerts::Signal::Health(sample),
        std::time::SystemTime::now(),
    );
    aplicar_acciones_alertas(app, repo, acciones);
}

/// Convierte el tipo de evento persistido en una señal del motor.
fn tipo_de_senal(event_type: crate::repo::EventType) -> Option<crate::alerts::EventKind> {
    use crate::alerts::EventKind;
    use crate::repo::EventType;
    Some(match event_type {
        EventType::New => EventKind::New,
        EventType::Disappeared => EventKind::Disappeared,
        EventType::Reappeared => EventKind::Reappeared,
        EventType::MacChanged => EventKind::MacChanged,
        EventType::HostnameChanged => EventKind::HostnameChanged,
        EventType::ServiceNew => EventKind::ServiceNew,
        EventType::OsChanged => EventKind::OsChanged,
        EventType::TypeChanged => EventKind::TypeChanged,
        EventType::IpChanged | EventType::ServiceGone => return None,
    })
}

/// Construye los datos del equipo que viajan en una señal de evento.
fn datos_de_equipo(
    device: &crate::repo::Device,
    fuente: crate::alerts::DeviceSource,
) -> crate::alerts::DeviceSignal {
    crate::alerts::DeviceSignal {
        device_id: device.id,
        label: device.display_name().to_string(),
        mac: device.mac.clone(),
        mac_random: crate::identify::mac::is_private(&device.mac),
        vendor: device.vendor.clone(),
        ip: device.ip.clone(),
        hostname: device.hostname.clone(),
        watched: device.watched,
        os_family: device.os_family.clone(),
        device_type: device.effective_device_type().to_string(),
        first_seen: crate::repo::rfc3339_a_instante(&device.first_seen)
            .unwrap_or_else(std::time::SystemTime::now),
        last_seen: crate::repo::rfc3339_a_instante(&device.last_seen)
            .unwrap_or_else(std::time::SystemTime::now),
        source: fuente,
    }
}

/// Señales de evento de un ciclo de escaneo (§4.1 y §7.1).
fn senales_de_escaneo(
    reconciliacion: &crate::scanner::Reconciliation,
) -> Vec<crate::alerts::Signal> {
    let mut senales = Vec::new();
    for evento in &reconciliacion.events {
        let Some(tipo) = tipo_de_senal(evento.event_type) else {
            continue;
        };
        let Some(device) = reconciliacion
            .devices
            .iter()
            .find(|device| device.id == evento.device_id)
        else {
            continue;
        };
        let details: serde_json::Value =
            serde_json::from_str(&evento.details).unwrap_or(serde_json::Value::Null);
        let fuente = match details.get("source").and_then(serde_json::Value::as_str) {
            Some("capture") => crate::alerts::DeviceSource::Capture,
            _ => crate::alerts::DeviceSource::Scan,
        };
        senales.push(crate::alerts::Signal::Event(crate::alerts::EventSignal {
            device: datos_de_equipo(device, fuente),
            kind: tipo,
            details,
            event_id: evento.event_id,
        }));
    }
    senales
}

/// Señales de inventario nuevo de un lote del minuto (§7.11).
fn senales_de_inventario(
    app: &App,
    repo: &Repo,
    cambio: &crate::repo::SeenChange,
) -> Vec<crate::alerts::Signal> {
    use crate::alerts::{SeenNew, SeenSignal, Subject};
    use std::collections::BTreeMap;

    let aprendizaje = repo.learning_rows().unwrap_or_default();
    let mut por_sujeto: BTreeMap<Subject, Vec<SeenNew>> = BTreeMap::new();
    for entrada in &cambio.new_items {
        let Some(subject) = sujeto_de_alerta(entrada.subject) else {
            continue;
        };
        let primera_vez = match entrada.subject {
            crate::history::Subject::Device(id) => app
                .devices
                .iter()
                .find(|device| device.id == id)
                .and_then(|device| crate::repo::rfc3339_a_instante(&device.first_seen)),
            _ => None,
        };
        let item = SeenNew {
            kind: entrada.kind,
            key: entrada.key.clone(),
            label: etiqueta_de_inventario(entrada.kind, &entrada.key),
            first_seen: primera_vez.unwrap_or_else(std::time::SystemTime::now),
        };
        por_sujeto.entry(subject).or_default().push(item);
    }

    let mut senales = Vec::new();
    for (subject, items) in por_sujeto {
        let (label, aprendido) = match subject {
            Subject::Device(id) => (
                app.devices
                    .iter()
                    .find(|device| device.id == id)
                    .map(|device| device.display_name().to_string())
                    .unwrap_or_else(|| format!("Equipo #{id}")),
                aprendizaje
                    .iter()
                    .find(|fila| fila.subject == subject)
                    .and_then(|fila| fila.learned_at),
            ),
            Subject::Host => (
                "Este equipo".to_string(),
                aprendizaje
                    .iter()
                    .find(|fila| fila.subject == subject)
                    .and_then(|fila| fila.learned_at),
            ),
            _ => (subject.label().to_string(), None),
        };
        senales.push(crate::alerts::Signal::Seen(SeenSignal {
            subject,
            subject_label: label,
            learned: aprendido.is_some() || app.config.alerts.learning_days == 0,
            learned_at: aprendido,
            items,
        }));
    }
    senales
}

/// Traduce el sujeto del histórico al del motor de alertas.
fn sujeto_de_alerta(subject: crate::history::Subject) -> Option<crate::alerts::Subject> {
    Some(match subject {
        crate::history::Subject::Device(id) => crate::alerts::Subject::Device(id),
        crate::history::Subject::Host => crate::alerts::Subject::Host,
        crate::history::Subject::Network => crate::alerts::Subject::Network,
        crate::history::Subject::Other => return None,
    })
}

/// Etiqueta visible de una clave del inventario (el motor la sanea y capitaliza).
fn etiqueta_de_inventario(kind: crate::history::SeenKind, key: &str) -> String {
    match kind {
        crate::history::SeenKind::Country => key.to_ascii_uppercase(),
        _ => key.to_string(),
    }
}

/// Evalúa una hora recién consolidada en vivo para «más tráfico de lo habitual».
fn evaluar_hora_cerrada(app: &mut App, repo: &mut Repo, hora: i64) {
    if !app.config.history.enabled {
        return;
    }
    let params = app.config.alerts.params();
    let Some(motor) = app.alert_engine.as_mut() else {
        return;
    };
    match repo.hour_baseline(hora, &params.traffic_high) {
        Ok(subjects) if !subjects.is_empty() => {
            let senal = crate::alerts::Signal::HourClosed(crate::alerts::HourClosedSignal {
                hour_start: hora,
                subjects,
            });
            let acciones = motor.handle(senal, std::time::SystemTime::now());
            aplicar_acciones_alertas(app, repo, acciones);
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, hora, "no se pudo leer la línea base de la hora"),
    }
}

/// Actualiza el aprendizaje al consolidar un día local (§4.3).
fn actualizar_aprendizaje(app: &mut App, repo: &mut Repo, dia: crate::history::LocalDay) {
    let params = crate::alerts::LearningParams {
        learning_days: app.config.alerts.learning_days,
    };
    match repo.update_learning(dia, &params) {
        Ok(cambios) if !cambios.is_empty() => match repo.learning_rows() {
            Ok(filas) => {
                if let Some(motor) = app.alert_engine.as_mut() {
                    motor.set_learning(filas);
                }
                app.alerts.mark_dirty();
            }
            Err(err) => tracing::warn!(%err, "no se pudo recargar el aprendizaje"),
        },
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(%err, dia = dia.aaaammdd(), "no se pudo actualizar el aprendizaje")
        }
    }
}

/// Purga las alertas, los silencios y el inventario del propio equipo (§7.15).
fn purgar_alertas(app: &mut App, repo: &mut Repo) {
    let ahora = std::time::SystemTime::now();
    if let Err(err) = repo.purge_alerts(ahora, app.config.alerts.retention_days) {
        tracing::warn!(%err, "no se pudieron purgar las alertas");
    }
    let corte = ahora
        .checked_sub(std::time::Duration::from_secs(
            u64::from(app.config.history.day_days) * 86_400,
        ))
        .unwrap_or(std::time::UNIX_EPOCH);
    if let Err(err) = repo.prune_host_seen(corte) {
        tracing::warn!(%err, "no se pudo purgar el inventario del propio equipo");
    }
    app.alerts.mark_dirty();
    // El tamaño tras la purga alimenta la regla db_size (§7.8).
    muestrear_salud(app, repo);
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
    fn persistir_trafico_guarda_snapshot_y_conexiones() {
        use crate::capture::aggregate::DeviceTraffic;
        use crate::capture::{ConnectionKey, Endpoint, HeaderSnapshot, Protocol};
        use crate::inference::{
            AppProtocol, AppSource, DestinationInfo, DestinationKind, FlowLabel, NameSource,
        };
        use crate::repo::{DeviceUpsert, Interface};
        use crate::traffic::{ConnectionView, EndpointView};
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repositorio");
        let id_interfaz = repo
            .upsert_interface(&Interface::without_id(
                "eth0",
                Some("aa:bb:cc:dd:ee:ff".to_string()),
                Some("192.168.1.10".to_string()),
                Some("255.255.255.0".to_string()),
                Some("192.168.1.1".to_string()),
                true,
                "2026-11-10T10:00:00Z",
            ))
            .expect("interfaz");
        let (device_id, _) = repo
            .upsert_device(&DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.42".to_string(),
                hostname: Some("laptop".to_string()),
                vendor: None,
                interface_id: id_interfaz,
                device_type: "pc".to_string(),
            })
            .expect("dispositivo");

        let mut app = app_prueba();
        app.traffic.devices = vec![DeviceTraffic {
            device_id,
            bytes_in: 1000,
            bytes_out: 500,
            packets_in: 10,
            packets_out: 5,
            rate_in: 100,
            rate_out: 50,
            peak_bps: 1200,
            series_60s_in: [0; 60],
            series_60s_out: [0; 60],
            series_5min_in: [0; 60],
            series_5min_out: [0; 60],
            top_ports: Vec::new(),
        }];
        let mut etiqueta = FlowLabel::empty("1.1.1.1".parse().unwrap());
        etiqueta.client_is_src = Some(true);
        etiqueta.app_protocol = Some(AppProtocol::Tls);
        etiqueta.server_name = Some("github.com".to_string());
        etiqueta.name_source = Some(NameSource::Sni);
        etiqueta.app = Some("github".to_string());
        etiqueta.category = Some("developer".to_string());
        etiqueta.app_source = Some(AppSource::Domain);
        etiqueta.ja4 = Some("t13d1516h2_8daaf6152771_02713d6af862".to_string());
        etiqueta.destination = DestinationInfo {
            key: "github.com".to_string(),
            label: "github.com".to_string(),
            org: Some("GitHub".to_string()),
            country: Some("US".to_string()),
            kind: DestinationKind::Domain,
        };
        app.traffic.connections = vec![ConnectionView {
            key: ConnectionKey::from_endpoints(
                Protocol::Tcp,
                Endpoint::new("192.168.1.42".parse().unwrap(), Some(40000)),
                Endpoint::new("1.1.1.1".parse().unwrap(), Some(443)),
            ),
            state: Some("ESTABLISHED".to_string()),
            bytes_in: 400,
            bytes_out: 200,
            age: Duration::from_secs(30),
            idle: Duration::from_secs(1),
            pid: Some(42),
            comm: Some("firefox".to_string()),
            device_id: Some(device_id),
            origin: EndpointView {
                ip: "192.168.1.42".parse().unwrap(),
                port: Some(40000),
                device_id: Some(device_id),
                tag: None,
            },
            destination: EndpointView {
                ip: "1.1.1.1".parse().unwrap(),
                port: Some(443),
                device_id: None,
                tag: Some("?"),
            },
            headers: Some(HeaderSnapshot::default()),
            seen_capture: true,
            seen_kernel: true,
            label: Some(etiqueta),
            app_name: Some("GitHub".to_string()),
            category_name: Some("Desarrollo".to_string()),
        }];

        persistir_trafico(&mut app, &mut repo);

        let snapshots = repo.list_snapshots().expect("listar snapshots");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].device_id, device_id);
        assert_eq!(snapshots[0].bytes_in, 1000);
        assert_eq!(snapshots[0].window_s, 60);
        let conexiones = repo.list_connections(None).expect("listar conexiones");
        assert_eq!(conexiones.len(), 1);
        assert_eq!(conexiones[0].protocol.as_str(), "tcp");
        assert_eq!(conexiones[0].state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(conexiones[0].device_id, Some(device_id));
        // Etiquetas de F4 persistidas desde ConnectionView.label.
        assert_eq!(conexiones[0].client_is_src, Some(true));
        assert_eq!(conexiones[0].app_protocol.as_deref(), Some("tls"));
        assert_eq!(conexiones[0].server_name.as_deref(), Some("github.com"));
        assert_eq!(conexiones[0].name_source.as_deref(), Some("sni"));
        assert_eq!(conexiones[0].app.as_deref(), Some("github"));
        assert_eq!(conexiones[0].category.as_deref(), Some("developer"));
        assert_eq!(conexiones[0].app_source.as_deref(), Some("domain"));
        assert_eq!(
            conexiones[0].ja4.as_deref(),
            Some("t13d1516h2_8daaf6152771_02713d6af862")
        );

        // Un segundo ciclo no duplica la conexión (upsert por 5-tuple).
        persistir_trafico(&mut app, &mut repo);
        assert_eq!(repo.list_connections(None).expect("listar").len(), 1);
    }

    #[test]
    fn persistir_trafico_guarda_y_purga_la_cache_de_nombres() {
        use crate::inference::names::NameEntry;
        use crate::inference::NameSource;
        use std::time::{Duration, SystemTime};

        let dir = tempfile::tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repositorio");
        let mut app = app_prueba();
        let ahora = SystemTime::now();
        app.traffic.pending_names = vec![
            NameEntry {
                ip: "1.1.1.1".parse().unwrap(),
                name: "one.one.one.one".to_string(),
                source: NameSource::Dns,
                first_seen: ahora,
                last_seen: ahora,
                expires_at: ahora + Duration::from_secs(3600),
                requester: None,
            },
            NameEntry {
                ip: "8.8.8.8".parse().unwrap(),
                name: "dns.google".to_string(),
                source: NameSource::Dns,
                first_seen: ahora - Duration::from_secs(90_000),
                last_seen: ahora - Duration::from_secs(90_000),
                expires_at: ahora - Duration::from_secs(10),
                requester: None,
            },
        ];
        persistir_trafico(&mut app, &mut repo);
        assert!(
            app.traffic.pending_names.is_empty(),
            "el buffer se vacía tras persistir"
        );
        let nombres = repo.list_names(SystemTime::now()).expect("listar nombres");
        assert_eq!(nombres.len(), 1, "la entrada caducada no se conserva");
        assert_eq!(nombres[0].name, "one.one.one.one");
    }

    #[test]
    fn set_traffic_group_persiste_la_preferencia() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("data.db");
        let mut repo = Repo::init(&db).unwrap();
        let mut app = app_con_config(&dir);

        aplicar_accion(
            Action::SetTrafficGroup(crate::config::TrafficGroup::App),
            &mut app,
            &mut repo,
        );
        assert_eq!(
            app.config.ui.traffic_group,
            crate::config::TrafficGroup::App
        );
        let guardada = Config::load(Some(&app.config_path)).expect("recargar configuración");
        assert_eq!(guardada.ui.traffic_group, crate::config::TrafficGroup::App);
    }

    #[tokio::test]
    async fn pedir_quien_lo_usa_rellena_el_panel_con_la_respuesta() {
        use crate::events::TrafficCommand;
        use crate::rankings::{DeviceShare, Dimension, RankRow, Window};
        use crate::traffic::RankingView;

        let (tx, mut rx) = crate::events::traffic_command_channel();
        let mut app = app_prueba();
        app.traffic_command_tx = Some(tx);
        app.traffic_group = Dimension::App;
        app.tab = crate::tui::app::Tab::Trafico;
        app.traffic.rankings = vec![RankingView {
            dimension: Dimension::App,
            window: Window::Sixty,
            rows: vec![RankRow {
                key: "youtube".to_string(),
                label: "YouTube".to_string(),
                subtitle: None,
                device_id: None,
                bytes_down: 900,
                bytes_up: 10,
                devices: 1,
                connections: 2,
                series_60s: [0; 60],
            }],
        }];
        app.open_who_uses().expect("petición abierta");
        let respondedor = tokio::spawn(async move {
            if let Some(TrafficCommand::WhoUses { reply, .. }) = rx.recv().await {
                let _ = reply.send(vec![DeviceShare {
                    device_id: 1,
                    label: "laptop-juan".to_string(),
                    bytes: 900,
                    pct: 90.0,
                }]);
            }
        });
        pedir_quien_lo_usa(
            &mut app,
            Dimension::App,
            "youtube".to_string(),
            "YouTube".to_string(),
            Window::Sixty,
        )
        .await;
        respondedor.await.expect("respondedor");
        let panel = app.traffic.who_uses.as_ref().expect("panel");
        assert!(!panel.pending);
        assert_eq!(panel.rows.len(), 1);
        assert_eq!(panel.rows[0].label, "laptop-juan");
        assert_eq!(panel.rows[0].pct, 90.0);
    }

    #[tokio::test]
    async fn pedir_quien_lo_usa_cierra_el_panel_si_no_hay_respuesta() {
        use crate::rankings::{Dimension, Window};

        let (tx, mut rx) = crate::events::traffic_command_channel();
        let mut app = app_prueba();
        app.traffic_command_tx = Some(tx);
        app.traffic_group = Dimension::App;
        app.traffic.who_uses = Some(crate::tui::traffic_state::WhoUsesState {
            dimension: Dimension::App,
            key: "youtube".to_string(),
            label: "YouTube".to_string(),
            window: Window::Sixty,
            rows: Vec::new(),
            selected: 0,
            pending: true,
        });
        pedir_quien_lo_usa(
            &mut app,
            Dimension::App,
            "youtube".to_string(),
            "YouTube".to_string(),
            Window::Sixty,
        )
        .await;
        assert!(!app.who_uses_open(), "sin respuesta se cierra el panel");
        assert!(app
            .notifier
            .current()
            .expect("aviso de timeout")
            .message
            .contains("200 ms"));
        // El receptor sigue vivo: la orden llegó pero nadie respondió.
        assert!(rx.try_recv().is_ok());
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

    /// Construye un lote de un minuto con una fila total y una entrada de
    /// inventario para las pruebas del hilo de la TUI.
    fn lote_de_prueba(minute: i64, device_id: i64) -> crate::history::RollupBatch {
        use crate::history::{
            Counter, Dimension, RollupBatch, RollupRow, SeenItem, SeenKind, Subject,
        };
        RollupBatch {
            minute,
            rows: vec![RollupRow {
                subject: Subject::Device(device_id),
                dimension: Dimension::Total,
                key: String::new(),
                counter: Counter {
                    down: 100,
                    up: 10,
                    connections: 1,
                },
            }],
            seen: vec![SeenItem::de_equipo(device_id, SeenKind::App, "youtube")],
            overflow: 0,
        }
    }

    fn repo_con_equipo() -> (tempfile::TempDir, Repo, i64) {
        use crate::repo::{DeviceUpsert, Interface};
        let dir = tempfile::tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repositorio");
        let id_interfaz = repo
            .upsert_interface(&Interface::without_id(
                "eth0",
                Some("aa:bb:cc:dd:ee:ff".to_string()),
                Some("192.168.1.10".to_string()),
                None,
                None,
                true,
                "2026-11-10T10:00:00Z",
            ))
            .expect("interfaz");
        let (device_id, _) = repo
            .upsert_device(&DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.50".to_string(),
                hostname: Some("laptop".to_string()),
                vendor: None,
                interface_id: id_interfaz,
                device_type: "pc".to_string(),
            })
            .expect("equipo");
        (dir, repo, device_id)
    }

    #[test]
    fn el_lote_del_minuto_se_escribe_con_su_inventario() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let mut app = app_prueba();
        escribir_lote_historico(
            &mut app,
            &mut repo,
            lote_de_prueba(1_800_000_000, device_id),
        );
        assert!(app.pending_rollups.is_empty());
        assert_eq!(app.rollup_counters.batches, 1);
        let minutos: i64 = repo
            .connection()
            .query_row("SELECT COUNT(*) FROM TRAFFIC_ROLLUP_MINUTE", [], |fila| {
                fila.get(0)
            })
            .unwrap();
        assert_eq!(minutos, 1);
        let inventario: i64 = repo
            .connection()
            .query_row("SELECT COUNT(*) FROM DEVICE_SEEN", [], |fila| fila.get(0))
            .unwrap();
        assert_eq!(inventario, 1);
    }

    #[test]
    fn al_cerrar_la_hora_se_consolida_en_el_mismo_lote() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let mut app = app_prueba();
        // Último minuto de la hora H: (bucket + 60) % 3600 == 0.
        let hora = 1_800_000_000;
        escribir_lote_historico(&mut app, &mut repo, lote_de_prueba(hora + 3540, device_id));
        let horas: i64 = repo
            .connection()
            .query_row("SELECT COUNT(*) FROM TRAFFIC_ROLLUP_HOUR", [], |fila| {
                fila.get(0)
            })
            .unwrap();
        assert_eq!(horas, 1, "la hora cerrada debe consolidarse en el acto");
        let bajada: i64 = repo
            .connection()
            .query_row(
                "SELECT SUM(bytes_down) FROM TRAFFIC_ROLLUP_HOUR WHERE dimension = 'total'",
                [],
                |fila| fila.get(0),
            )
            .unwrap();
        assert_eq!(bajada, 100);
    }

    #[test]
    fn los_lotes_fallidos_se_reintentan_y_se_descarta_el_mas_antiguo() {
        let (_dir, mut repo, _device_id) = repo_con_equipo();
        let mut app = app_prueba();
        // El inventario apunta a un equipo inexistente: la transacción falla.
        let fallido = lote_de_prueba(1_800_000_000, 999_999);
        for indice in 0..12i64 {
            let mut lote = fallido.clone();
            lote.minute += indice * 60;
            escribir_lote_historico(&mut app, &mut repo, lote);
        }
        assert_eq!(app.pending_rollups.len(), MAX_LOTES_PENDIENTES);
        assert!(app.rollup_counters.drops >= 2);
        assert_eq!(app.rollup_counters.batches, 0);
        assert!(
            app.rollup_dropped_warned,
            "se avisa una sola vez del descarte"
        );
    }

    #[test]
    fn abrir_equipo_desde_alertas_cambia_a_equipos_y_abre_el_detalle() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let mut app = app_prueba();
        app.tab = crate::tui::app::Tab::Alertas;
        aplicar_accion(Action::OpenDetail { device_id }, &mut app, &mut repo);
        assert_eq!(app.tab, crate::tui::app::Tab::Equipos);
        assert_eq!(
            app.detail.as_ref().map(|detalle| detalle.device_id),
            Some(device_id)
        );
    }
}
