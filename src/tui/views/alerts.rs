//! Pestaña Alertas (F6): lista con detalle, Reglas y Silencios.
//!
//! El render no consulta la base de datos: pinta lo último que ha guardado
//! [crate::tui::alerts_state::AlertsState] (§6). Nivel, no vista, resuelta,
//! vigilado y silenciada se muestran con texto y símbolo, no solo con color, y
//! la lista y el detalle caben en 80x24.

use chrono::{Datelike, Local, TimeZone};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

#[cfg(test)]
use crate::alerts::AlertRule;
use crate::alerts::{AlertCounts, Level, RuleId, Subject};
use crate::history::{AlertDetail, AlertRow, MuteRow, RuleStat};
use crate::tui::alerts_state::{rule_rows, AlertsView, RuleRow};
use crate::tui::app::App;

/// Columnas de la lista en pantallas normales.
const ANCHO_CUANDO: u16 = 13;
const ANCHO_NIVEL: u16 = 8;
const ANCHO_EQUIPO: u16 = 18;

/// Dibuja la pestaña Alertas.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled("Alertas", app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let alto_detalle = if app.alerts.detail_open {
        (interior.height / 3).clamp(6, 9)
    } else {
        0
    };
    let filas = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(alto_detalle),
        Constraint::Length(1),
    ])
    .split(interior);

    draw_cabecera(frame, app, filas[0]);
    match app.alerts.view {
        AlertsView::Lista => {
            draw_lista(frame, app, filas[1]);
            if app.alerts.detail_open {
                draw_detalle(frame, app, filas[2]);
            }
        }
        AlertsView::Reglas => draw_reglas(frame, app, filas[1]),
        AlertsView::Silencios => draw_silencios(frame, app, filas[1]),
    }
    draw_pie(frame, app, filas[3]);
}

/// Cabecera con la vista activa, los no vistos y el filtro.
fn draw_cabecera(frame: &mut Frame, app: &App, area: Rect) {
    let estado = &app.alerts;
    let mut spans: Vec<Span> = Vec::new();
    for (indice, vista) in AlertsView::ALL.iter().enumerate() {
        if indice > 0 {
            spans.push(Span::styled(" · ", app.theme.dim));
        }
        let activa = *vista == estado.view;
        let texto = if activa {
            format!("[{}]", vista.title())
        } else {
            vista.title().to_string()
        };
        spans.push(Span::styled(
            texto,
            if activa {
                app.theme.accent
            } else {
                app.theme.dim
            },
        ));
    }
    spans.push(Span::styled("   ", app.theme.dim));

    match estado.view {
        AlertsView::Lista => {
            if !app.config.alerts.enabled {
                spans.push(Span::styled(
                    "alertas desactivadas ([alerts] enabled = false)",
                    app.theme.warning,
                ));
            } else {
                spans.push(Span::styled(
                    format!("{} sin ver", estado.counts.badge()),
                    app.theme.normal,
                ));
                spans.push(Span::styled(" · filtro: ", app.theme.dim));
                spans.push(Span::styled(estado.level_filter.label(), app.theme.normal));
                if estado.unseen_only {
                    spans.push(Span::styled(" · solo sin ver", app.theme.accent));
                }
                if !estado.search.trim().is_empty() {
                    spans.push(Span::styled(
                        format!(" · equipo: {}", estado.search.trim()),
                        app.theme.accent,
                    ));
                }
                spans.push(Span::styled(
                    format!(" · {} días", app.config.alerts.retention_days),
                    app.theme.dim,
                ));
            }
        }
        AlertsView::Reglas => spans.push(Span::styled(
            "lo nuevo aprende con días con datos",
            app.theme.dim,
        )),
        AlertsView::Silencios => spans.push(Span::styled(
            format!("{} silencios", estado.mutes.len()),
            app.theme.dim,
        )),
    }
    if let Some(error) = &estado.error {
        spans.push(Span::styled(format!(" · {error}"), app.theme.error));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Lista de alertas ordenada por la última repetición (§6).
fn draw_lista(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.alerts.rows.is_empty() {
        let texto = if !app.config.alerts.enabled {
            "Las alertas están desactivadas ([alerts] enabled = false); las guardadas se siguen viendo"
        } else if app.alerts.loading {
            "Cargando…"
        } else {
            "Sin alertas en este filtro"
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(texto, app.theme.dim))),
            area,
        );
        return;
    }

    let cabecera = Row::new(vec!["Cuándo", "Nivel", "Qué", "Equipo"]).style(app.theme.accent);
    let ahora = Local::now().timestamp();
    let filas: Vec<Row> = app
        .alerts
        .rows
        .iter()
        .map(|alerta| fila_de_alerta(alerta, &app.theme, ahora))
        .collect();
    let tabla = Table::new(
        filas,
        [
            Constraint::Length(ANCHO_CUANDO),
            Constraint::Length(ANCHO_NIVEL),
            Constraint::Min(12),
            Constraint::Length(ANCHO_EQUIPO),
        ],
    )
    .header(cabecera)
    .column_spacing(1)
    .row_highlight_style(app.theme.selected)
    .highlight_symbol(Span::styled("▸ ", app.theme.accent))
    .style(app.theme.normal);

    let seleccion = app.alerts.selected;
    *app.alerts.table_state.selected_mut() = Some(seleccion);
    frame.render_stateful_widget(tabla, area, &mut app.alerts.table_state);
}

fn fila_de_alerta(alerta: &AlertRow, theme: &crate::tui::theme::Theme, ahora: i64) -> Row<'static> {
    let marca_vista = if alerta.seen { "  " } else { "● " };
    let cuando = format!("{marca_vista}{}", etiqueta_cuando(alerta.last_at, ahora));
    let nivel = Span::styled(alerta.level.badge(), estilo_nivel(theme, alerta.level));
    let mut titulo = alerta.title.clone();
    if alerta.count > 1 {
        titulo.push_str(&format!(" ×{}", alerta.count));
    }
    if alerta.resolved {
        titulo.push_str(" · resuelta");
    }
    let equipo = etiqueta_sujeto(alerta);
    Row::new(vec![
        Cell::from(Span::styled(cuando, theme.normal)),
        Cell::from(nivel),
        Cell::from(Span::styled(
            titulo,
            if alerta.seen {
                theme.normal
            } else {
                theme.normal.add_modifier(Modifier::BOLD)
            },
        )),
        Cell::from(Span::styled(equipo, theme.dim)),
    ])
}

fn estilo_nivel(theme: &crate::tui::theme::Theme, nivel: Level) -> Style {
    match nivel {
        Level::Important => theme.error,
        Level::Warning => theme.warning,
        Level::Info => theme.normal,
    }
}

fn etiqueta_sujeto(alerta: &AlertRow) -> String {
    match alerta.subject {
        Subject::Device(_) => alerta.subject_label.clone(),
        Subject::Host => "[host]".to_string(),
        Subject::Network => "Toda la red".to_string(),
        Subject::Almenara => "Almenara".to_string(),
    }
}

/// Panel de detalle de la alerta seleccionada (§6).
fn draw_detalle(frame: &mut Frame, app: &App, area: Rect) {
    let Some(detalle) = app.alerts.detail.as_ref() else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled("Cargando…", app.theme.dim))),
            area,
        );
        return;
    };
    let lineas = lineas_de_detalle(detalle, &app.theme);
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled("Detalle", app.theme.title));
    frame.render_widget(
        Paragraph::new(lineas)
            .block(bloque)
            .wrap(Wrap { trim: true })
            .style(app.theme.normal),
        area,
    );
}

fn lineas_de_detalle(
    detalle: &AlertDetail,
    theme: &crate::tui::theme::Theme,
) -> Vec<Line<'static>> {
    let fila = &detalle.row;
    let mut lineas = Vec::new();
    let regla = fila.rule.name();
    lineas.push(Line::from(vec![
        Span::styled(regla.to_string(), theme.accent),
        Span::styled(format!(" · {}", etiqueta_sujeto(fila)), theme.normal),
        Span::styled(
            format!(" · {}", fila.level.badge()),
            estilo_nivel(theme, fila.level),
        ),
    ]));

    let porque = detalle
        .details
        .get("porque")
        .and_then(serde_json::Value::as_str)
        .map(|texto| texto.to_string())
        .unwrap_or_else(|| texto_generico(detalle));
    if !porque.is_empty() {
        lineas.push(Line::from(Span::styled(porque, theme.normal)));
    }

    let ahora = Local::now().timestamp();
    let repeticiones = if fila.count > 1 {
        format!("{} repeticiones", fila.count)
    } else {
        "sin repeticiones".to_string()
    };
    let primera = etiqueta_cuando(fila.created_at, ahora);
    let ultima = etiqueta_cuando(fila.last_at, ahora);
    let resuelta = if fila.resolved { " · resuelta" } else { "" };
    lineas.push(Line::from(Span::styled(
        format!("Creada {primera} · última {ultima} · {repeticiones}{resuelta}"),
        theme.dim,
    )));
    if fila.notified {
        lineas.push(Line::from(Span::styled(
            "Notificada en el escritorio",
            theme.dim,
        )));
    }
    if !detalle.grouped.is_empty() {
        lineas.push(Line::from(Span::styled(
            format!(
                "Agrupa {} alertas: {}",
                detalle.grouped.len(),
                detalle
                    .grouped
                    .iter()
                    .take(3)
                    .map(|agrupada| agrupada.title.clone())
                    .collect::<Vec<_>>()
                    .join(" · ")
            ),
            theme.dim,
        )));
    }
    let pie = match fila.rule.rule_id() {
        Some(_) => "[m] silenciar · [e] ir al equipo · [Esc] cerrar",
        None => "[Esc] cerrar",
    };
    lineas.push(Line::from(Span::styled(pie, theme.dim)));
    lineas
}

fn texto_generico(detalle: &AlertDetail) -> String {
    let fila = &detalle.row;
    match fila.subject {
        Subject::Almenara => "Resumen de la puesta al día".to_string(),
        _ => format!("{}: {}", fila.rule.name(), fila.subject_label),
    }
}

/// Vista Reglas: estado, nivel, alertas de 7 días y silencios (§6).
fn draw_reglas(frame: &mut Frame, app: &mut App, area: Rect) {
    let cabecera =
        Row::new(vec!["Regla", "Activa", "Nivel", "7 días", "Silencios"]).style(app.theme.accent);
    let filas_estado: Vec<Row> = rule_rows()
        .iter()
        .map(|fila| fila_de_regla(*fila, app))
        .collect();
    let tabla = Table::new(
        filas_estado,
        [
            Constraint::Min(24),
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Length(7),
            Constraint::Length(10),
        ],
    )
    .header(cabecera)
    .column_spacing(1)
    .row_highlight_style(app.theme.selected)
    .highlight_symbol(Span::styled("▸ ", app.theme.accent))
    .style(app.theme.normal);
    let seleccion = app.alerts.selected_rule;
    *app.alerts.rules_table_state.selected_mut() = Some(seleccion);
    frame.render_stateful_widget(tabla, area, &mut app.alerts.rules_table_state);
}

fn fila_de_regla(fila: RuleRow, app: &App) -> Row<'static> {
    let theme = &app.theme;
    let ajuste = match fila {
        RuleRow::Rule(regla) => app.alerts.setting_actual(regla),
        RuleRow::PrivateMac => app.alerts.setting_actual(RuleId::DeviceNew),
    };
    let (nombre, activa, nivel) = match fila {
        RuleRow::Rule(regla) => (
            regla.name().to_string(),
            if ajuste.enabled { "sí" } else { "no" },
            ajuste.level.label().to_string(),
        ),
        RuleRow::PrivateMac => (
            "  con MAC privada".to_string(),
            "—",
            ajuste
                .level_private_mac
                .unwrap_or(Level::Warning)
                .label()
                .to_string(),
        ),
    };
    let (cuenta, silencios) = match fila {
        RuleRow::Rule(regla) => estadisticas(app, regla),
        RuleRow::PrivateMac => (0, 0),
    };
    let mut nota = String::new();
    if let RuleRow::Rule(regla) = fila {
        if let Some(motivo) = regla_no_disponible(app, regla) {
            nota = format!("   {motivo}");
        }
    }
    Row::new(vec![
        Cell::from(Span::styled(format!("{nombre}{nota}"), theme.normal)),
        Cell::from(Span::styled(
            activa,
            if activa == "no" {
                theme.warning
            } else {
                theme.normal
            },
        )),
        Cell::from(Span::styled(level_label(&nivel), theme.normal)),
        Cell::from(Span::styled(
            if cuenta == 0 {
                "—".to_string()
            } else {
                cuenta.to_string()
            },
            theme.dim,
        )),
        Cell::from(Span::styled(silencios.to_string(), theme.dim)),
    ])
}

fn level_label(nivel: &str) -> String {
    match nivel {
        "importante" => "importante".to_string(),
        "aviso" => "aviso".to_string(),
        _ => "info".to_string(),
    }
}

fn estadisticas(app: &App, regla: RuleId) -> (u32, u32) {
    app.alerts
        .stats
        .iter()
        .find(|stat| stat.rule == regla)
        .map(|stat: &RuleStat| (stat.count_7d, stat.mutes))
        .unwrap_or((0, 0))
}

/// Motivo por el que una regla no puede saltar (§6).
fn regla_no_disponible(app: &App, regla: RuleId) -> Option<&'static str> {
    let def = regla.def();
    if def.needs_history && !app.config.history.enabled {
        return Some("necesita el histórico");
    }
    if def.needs_capture && !(app.config.capture.enabled && app.capabilities.raw_sockets) {
        return Some("necesita captura");
    }
    if def.needs_portscan && app.config.scan.passive_only {
        return Some("sin escaneo de puertos");
    }
    None
}

/// Vista Silencios: regla, equipo, hasta y desde (§6).
fn draw_silencios(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.alerts.mutes.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "No hay silencios vigentes",
                app.theme.dim,
            ))),
            area,
        );
        return;
    }
    let cabecera = Row::new(vec!["Regla", "Equipo", "Hasta", "Desde"]).style(app.theme.accent);
    let ahora = Local::now().timestamp();
    let filas: Vec<Row> = app
        .alerts
        .mutes
        .iter()
        .map(|silencio| fila_de_silencio(silencio, &app.theme, ahora))
        .collect();
    let tabla = Table::new(
        filas,
        [
            Constraint::Min(24),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(12),
        ],
    )
    .header(cabecera)
    .column_spacing(1)
    .row_highlight_style(app.theme.selected)
    .highlight_symbol(Span::styled("▸ ", app.theme.accent))
    .style(app.theme.normal);
    let seleccion = app.alerts.selected_mute;
    *app.alerts.mutes_table_state.selected_mut() = Some(seleccion);
    frame.render_stateful_widget(tabla, area, &mut app.alerts.mutes_table_state);
}

fn fila_de_silencio(
    silencio: &MuteRow,
    theme: &crate::tui::theme::Theme,
    ahora: i64,
) -> Row<'static> {
    let equipo = match silencio.subject {
        Subject::Device(_) => silencio
            .device_label
            .clone()
            .unwrap_or_else(|| format!("Equipo #{}", silencio.device_id)),
        Subject::Host => "[host]".to_string(),
        Subject::Network => "Toda la red".to_string(),
        Subject::Almenara => "Almenara".to_string(),
    };
    let hasta = match silencio.until {
        None => "siempre".to_string(),
        Some(unix) => etiqueta_cuando(unix, ahora),
    };
    Row::new(vec![
        Cell::from(Span::styled(silencio.rule.name().to_string(), theme.normal)),
        Cell::from(Span::styled(equipo, theme.normal)),
        Cell::from(Span::styled(hasta, theme.normal)),
        Cell::from(Span::styled(
            etiqueta_cuando(silencio.created_at, ahora),
            theme.dim,
        )),
    ])
}

/// Pie de la pestaña con el menú de silencio y el aviso de confirmación.
fn draw_pie(frame: &mut Frame, app: &App, area: Rect) {
    let estado = &app.alerts;
    let mut spans: Vec<Span> = Vec::new();
    if estado.mute_menu {
        spans.push(Span::styled(
            "Silenciar esta regla en este sujeto: [1] 1 día  [2] 7 días  [3] siempre  [Esc] cancelar",
            app.theme.accent,
        ));
    } else if estado.confirm_seen_all {
        spans.push(Span::styled(
            "¿Marcar como vistas todas las alertas del filtro? Pulsa [T] otra vez para confirmar",
            app.theme.warning,
        ));
    } else if estado.search_editing {
        spans.push(Span::styled(
            format!(
                "Equipo: {}_  [Enter] aplicar  [Esc] cancelar",
                estado.search
            ),
            app.theme.accent,
        ));
    } else {
        let pista = match estado.view {
            AlertsView::Lista => {
                "[Enter]ver [espacio]vista [T]todas [f]nivel [u]sin ver [/]equipo [m]silenciar [e]equipo"
            }
            AlertsView::Reglas => "[espacio]activar/apagar [n]nivel [Tab]siguiente",
            AlertsView::Silencios => "[x]quitar [Tab]siguiente",
        };
        spans.push(Span::styled(pista, app.theme.dim));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Etiqueta «hoy 10:44», «ayer 22:17», día de la semana o fecha (§6).
pub fn etiqueta_cuando(unix: i64, ahora: i64) -> String {
    let Some(fecha) = Local.timestamp_opt(unix, 0).single() else {
        return "—".to_string();
    };
    let Some(hoy) = Local.timestamp_opt(ahora, 0).single() else {
        return fecha.format("%d %b %H:%M").to_string();
    };
    let dias = (hoy.date_naive() - fecha.date_naive()).num_days();
    let hora = fecha.format("%H:%M");
    match dias {
        0 => format!("hoy {hora}"),
        1 => format!("ayer {hora}"),
        2..=6 => {
            let nombre = match fecha.weekday() {
                chrono::Weekday::Mon => "lun",
                chrono::Weekday::Tue => "mar",
                chrono::Weekday::Wed => "mié",
                chrono::Weekday::Thu => "jue",
                chrono::Weekday::Fri => "vie",
                chrono::Weekday::Sat => "sáb",
                chrono::Weekday::Sun => "dom",
            };
            format!("{nombre} {hora}")
        }
        _ => fecha.format("%d %b %H:%M").to_string(),
    }
}

/// Texto de «hoy tienes N alertas» para la barra de estado: solo lo no visto
/// importante y de aviso (§6).
pub fn contador_barra(counts: AlertCounts) -> String {
    format!("Alertas {}", counts.badge())
}

/// Nombre de la vista para la barra y las pruebas.
#[cfg(test)]
pub fn etiqueta_de_vista(vista: AlertsView) -> &'static str {
    vista.title()
}

/// Nombre de una regla para la lista (también catch_up).
#[cfg(test)]
pub fn nombre_de_regla(regla: AlertRule) -> &'static str {
    regla.name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::AlertRule;
    use crate::tui::alerts_state::LevelFilter;

    #[test]
    fn etiquetas_de_cuando_relativas() {
        let ahora = Local
            .with_ymd_and_hms(2026, 11, 11, 12, 0, 0)
            .unwrap()
            .timestamp();
        let hoy = Local
            .with_ymd_and_hms(2026, 11, 11, 10, 44, 0)
            .unwrap()
            .timestamp();
        assert_eq!(etiqueta_cuando(hoy, ahora), "hoy 10:44");
        let ayer = hoy - 86_400;
        assert!(etiqueta_cuando(ayer, ahora).starts_with("ayer "));
    }

    #[test]
    fn el_contador_solo_suma_importantes_y_avisos() {
        let counts = AlertCounts {
            important: 2,
            warning: 1,
            info: 9,
        };
        assert_eq!(contador_barra(counts), "Alertas 3");
        assert_eq!(contador_barra(AlertCounts::default()), "Alertas 0");
    }

    #[test]
    fn niveles_y_reglas_tienen_texto_propio() {
        assert_eq!(Level::Important.badge(), "!! IMP");
        assert_eq!(Level::Warning.badge(), "!  AVI");
        assert_eq!(Level::Info.badge(), "   INF");
        assert_eq!(nombre_de_regla(AlertRule::CatchUp), "Resumen al arrancar");
        assert_eq!(etiqueta_de_vista(AlertsView::Reglas), "Reglas");
    }

    #[test]
    fn las_reglas_del_mockup_tienen_su_no_disponibilidad() {
        assert_eq!(RuleId::NewApp.name(), "App nueva");
        assert_eq!(RuleId::PortNew.name(), "Puerto nuevo");
        assert!(RuleId::CaptureStopped.def().needs_capture);
    }

    #[test]
    fn el_filtro_de_nivel_cicla() {
        assert_eq!(LevelFilter::Todas.next(), LevelFilter::Importantes);
        assert_eq!(LevelFilter::Info.next(), LevelFilter::Todas);
    }
}
