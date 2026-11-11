//! Pestaña Histórico (F5): sujeto, rango, gráfica con huecos y cursor,
//! «Más tráfico» y línea de tiempo de eventos y sesiones.
//!
//! El render no consulta la base de datos: pinta el último resultado que ha
//! guardado [crate::tui::history_state::HistoryState] (§4.5). Los huecos se
//! dibujan con ░ y el tiempo que aún no ha pasado se deja en blanco; nunca se
//! interpola. Todo es legible en 80x24 y nada depende solo del color.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};
use ratatui::Frame;

use crate::history::{Range, TimelineKind, TopRow};
use crate::traffic::formatear_bytes;
use crate::tui::app::App;
use crate::tui::history_state::HistoryFocus;
use crate::tui::views::charts;

/// Ancho mínimo del panel «Más tráfico» a partir del cual se muestran porcentajes.
const ANCHO_MINIMO_PCT: u16 = 34;

/// Dibuja la pestaña Histórico.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled("Histórico", app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let alto_inferior = (interior.height / 2)
        .clamp(5, 14)
        .min(interior.height.saturating_sub(6));
    let filas = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(alto_inferior),
        Constraint::Length(1),
    ])
    .split(interior);

    draw_cabecera(frame, app, filas[0]);
    draw_grafica(frame, app, filas[1]);

    let columnas = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(filas[2]);
    draw_mas_trafico(frame, app, columnas[0]);
    draw_eventos(frame, app, columnas[1]);
    draw_pie(frame, app, filas[3]);

    if app.history.selector_abierto() {
        draw_selector(frame, app, interior);
    }
}

/// Cabecera con el sujeto y el rango activos.
fn draw_cabecera(frame: &mut Frame, app: &App, area: Rect) {
    let sujeto = app.history.subject_label();
    let rango = app.history.range.label();
    let columnas = Layout::horizontal([Constraint::Min(20), Constraint::Length(26)]).split(area);
    let marca_grafica = if app.history.focus == HistoryFocus::Grafica {
        "▸ "
    } else {
        ""
    };
    let izquierda = Line::from(vec![
        Span::styled(format!("{marca_grafica}Histórico · "), app.theme.title),
        Span::styled(sujeto, app.theme.accent),
        Span::styled(" · ", app.theme.dim),
        Span::styled(rango, app.theme.accent),
    ]);
    frame.render_widget(Paragraph::new(izquierda), columnas[0]);
    let derecha = Line::from(Span::styled("[e] equipo · [w] rango", app.theme.dim))
        .alignment(Alignment::Right);
    frame.render_widget(Paragraph::new(derecha), columnas[1]);
}

/// Gráfica de tráfico del rango con su cabecera, eje y leyenda.
fn draw_grafica(frame: &mut Frame, app: &App, area: Rect) {
    if area.height == 0 {
        return;
    }
    if !app.config.history.enabled {
        draw_mensaje(
            frame,
            app,
            area,
            "El histórico está desactivado ([history] enabled = false)",
            Some("La línea de tiempo de eventos sigue disponible"),
        );
        return;
    }
    let Some(series) = app.history.series.as_ref() else {
        if let Some(error) = app.history.error_actual() {
            draw_mensaje(
                frame,
                app,
                area,
                &format!("Error del histórico: {error}"),
                None,
            );
        } else if app.history.serie_cargando() {
            draw_mensaje(frame, app, area, "Cargando…", None);
        } else {
            draw_mensaje(frame, app, area, "Sin datos en este rango", None);
        }
        return;
    };
    if series.points.is_empty() || series.total() == 0 {
        draw_mensaje(frame, app, area, "Sin datos en este rango", None);
        return;
    }

    let filas = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    draw_cabecera_grafica(frame, app, series, filas[0]);
    let maximo = charts::maximo_de_serie(series);
    let alto_barras = filas[1].height;
    let puntos = charts::puntos_de_serie(series);
    // El cursor se resalta solo cuando la gráfica tiene el foco (Tab).
    let cursor = if app.history.focus == HistoryFocus::Grafica {
        app.history.cursor
    } else {
        None
    };
    let lineas = charts::barras(
        &puntos,
        maximo,
        filas[1].width,
        alto_barras,
        cursor,
        &app.theme,
    );
    frame.render_widget(Paragraph::new(lineas), filas[1]);
    frame.render_widget(
        Paragraph::new(charts::eje_fechas(series, filas[2].width, &app.theme)),
        filas[2],
    );
    draw_leyenda(frame, app, series, filas[3]);
}

/// Cabecera de la gráfica: totales, resolución y punto máximo.
fn draw_cabecera_grafica(
    frame: &mut Frame,
    app: &App,
    series: &crate::history::Series,
    area: Rect,
) {
    let mut spans = vec![
        Span::styled("↓ ", app.theme.online),
        Span::styled(formatear_bytes(series.total_down), app.theme.normal),
        Span::styled(" · ↑ ", app.theme.accent),
        Span::styled(formatear_bytes(series.total_up), app.theme.normal),
        Span::styled(
            format!(" · {} ", charts::formatear_resolucion(series.range)),
            app.theme.dim,
        ),
    ];
    if let Some((indice, _)) = series.max {
        if let Some(punto) = series.points.get(indice) {
            spans.push(Span::styled("· máximo: ", app.theme.dim));
            spans.push(Span::styled(
                format!(
                    "{} ({})",
                    charts::etiqueta_punto(punto.at, series.range),
                    formatear_bytes(punto.total())
                ),
                app.theme.accent,
            ));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Leyenda de la gráfica: cursor en texto, huecos y foco.
fn draw_leyenda(frame: &mut Frame, app: &App, series: &crate::history::Series, area: Rect) {
    if let Some(error) = app.history.error_actual() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("Error del histórico: {error}"),
                app.theme.warning,
            )),
            area,
        );
        return;
    }
    let mut spans: Vec<Span> = Vec::new();
    if let Some(punto) = app.history.cursor_point() {
        spans.push(Span::styled("[<>] ", app.theme.accent));
        spans.push(Span::styled(
            charts::etiqueta_punto(punto.at, series.range),
            app.theme.normal,
        ));
        if punto.future {
            spans.push(Span::styled(" (aún no ha pasado)", app.theme.dim));
        } else if punto.gap {
            spans.push(Span::styled(": sin datos", app.theme.dim));
        } else {
            spans.push(Span::styled(": ↓ ", app.theme.online));
            spans.push(Span::styled(
                formatear_bytes(punto.bytes_down),
                app.theme.normal,
            ));
            spans.push(Span::styled(" · ↑ ", app.theme.accent));
            spans.push(Span::styled(
                formatear_bytes(punto.bytes_up),
                app.theme.normal,
            ));
        }
        spans.push(Span::styled(" · ", app.theme.dim));
    }
    let huecos = series.points.iter().filter(|punto| punto.gap).count();
    spans.push(Span::styled(
        format!("{} · {huecos} huecos", charts::LEYENDA_HUECOS),
        app.theme.dim,
    ));
    spans.push(Span::styled(
        format!(" · foco: {} ([Tab])", app.history.focus.label()),
        app.theme.dim,
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Panel «Más tráfico» del rango: equipos y apps en la red; apps, destinos,
/// organizaciones y países en un equipo.
fn draw_mas_trafico(frame: &mut Frame, app: &App, area: Rect) {
    let borde = if app.history.focus == HistoryFocus::MasTrafico {
        app.theme.accent
    } else {
        app.theme.border
    };
    let marca = if app.history.focus == HistoryFocus::MasTrafico {
        "▸ "
    } else {
        ""
    };
    let titulo = format!("{marca}Más tráfico · {}", app.history.range.label());
    let bloque = Block::bordered()
        .border_style(borde)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let mut lineas: Vec<Line> = Vec::new();
    if !app.config.history.enabled {
        lineas.push(Line::from(Span::styled(
            "El histórico está desactivado",
            app.theme.dim,
        )));
        frame.render_widget(Paragraph::new(lineas), interior);
        return;
    }
    let secciones = app.history.top_sections();
    let total_filas = app.history.top_total_filas();
    if total_filas == 0 {
        let mensaje = if app.history.error_actual().is_some() {
            "Error al cargar el histórico"
        } else if app.history.top_cargando() {
            "Cargando…"
        } else {
            "Sin datos en este rango"
        };
        lineas.push(Line::from(Span::styled(mensaje, app.theme.dim)));
        frame.render_widget(Paragraph::new(lineas), interior);
        return;
    }

    // Aviso de privacidad de destinos en el rango de un año.
    let aviso_destinos = !app.history.range.admite_destinos();
    let mut indice_fila = 0usize;
    let mut filas_disponibles = usize::from(interior.height);
    if aviso_destinos {
        filas_disponibles = filas_disponibles.saturating_sub(1);
    }
    let con_porcentaje = interior.width >= ANCHO_MINIMO_PCT;
    let ancho_etiqueta = usize::from(interior.width)
        .saturating_sub(if con_porcentaje { 20 } else { 12 })
        .max(8);
    for (titulo_seccion, filas) in secciones {
        if filas.is_empty() || lineas.len() >= filas_disponibles {
            continue;
        }
        lineas.push(Line::from(Span::styled(
            format!("  {titulo_seccion}"),
            app.theme.accent,
        )));
        for fila in filas {
            if lineas.len() >= filas_disponibles {
                break;
            }
            let seleccionada = app.history.focus == HistoryFocus::MasTrafico
                && indice_fila == app.history.top_selected;
            lineas.push(linea_top(
                app,
                fila,
                ancho_etiqueta,
                con_porcentaje,
                seleccionada,
            ));
            indice_fila += 1;
        }
    }
    if aviso_destinos && lineas.len() < usize::from(interior.height) {
        lineas.push(Line::from(Span::styled(
            "Destinos: solo los últimos 30 días",
            app.theme.warning,
        )));
    }
    frame.render_widget(Paragraph::new(lineas), interior);
}

/// Línea de una fila de «Más tráfico».
fn linea_top(
    app: &App,
    fila: &TopRow,
    ancho_etiqueta: usize,
    con_porcentaje: bool,
    seleccionada: bool,
) -> Line<'static> {
    let etiqueta = recortar(&fila.label, ancho_etiqueta);
    let estilo = if seleccionada {
        app.theme.selected
    } else {
        app.theme.normal
    };
    let mut spans = vec![
        Span::styled(
            format!("  {} ", if seleccionada { "▸" } else { " " }),
            if seleccionada {
                app.theme.accent
            } else {
                app.theme.dim
            },
        ),
        Span::styled(format!("{etiqueta:<ancho_etiqueta$} "), estilo),
        Span::styled(format!("{:>9} ", formatear_bytes(fila.total())), estilo),
    ];
    if con_porcentaje {
        spans.push(Span::styled(
            charts::formatear_pct(fila.pct),
            if seleccionada {
                app.theme.selected
            } else {
                app.theme.accent
            },
        ));
    }
    Line::from(spans)
}

/// Panel «Eventos»: eventos y sesiones del rango, más recientes primero.
fn draw_eventos(frame: &mut Frame, app: &App, area: Rect) {
    let borde = if app.history.focus == HistoryFocus::Eventos {
        app.theme.accent
    } else {
        app.theme.border
    };
    let marca = if app.history.focus == HistoryFocus::Eventos {
        "▸ "
    } else {
        ""
    };
    let titulo = format!("{marca}Eventos · filtro: {}", app.history.filter.label());
    let bloque = Block::bordered()
        .border_style(borde)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let mut lineas: Vec<Line> = Vec::new();
    if app.history.busqueda_activa() {
        lineas.push(Line::from(vec![
            Span::styled("Buscar: ", app.theme.accent),
            Span::styled(app.history.busqueda_texto().to_string(), app.theme.normal),
            Span::styled("█", app.theme.accent),
        ]));
    } else if !app.history.event_search.is_empty() {
        lineas.push(Line::from(vec![
            Span::styled("búsqueda: ", app.theme.dim),
            Span::styled(app.history.event_search.clone(), app.theme.normal),
        ]));
    }

    let visibles = app.history.timeline_visible();
    if visibles.is_empty() {
        let mensaje = if app.history.busqueda_activa() {
            String::new()
        } else if app.history.error_actual().is_some() {
            "Error al cargar los eventos".to_string()
        } else if !app.history.event_search.is_empty() {
            "Ningún evento coincide con la búsqueda".to_string()
        } else if app.history.timeline_cargando() {
            "Cargando…".to_string()
        } else {
            "Sin eventos en este rango".to_string()
        };
        if !mensaje.is_empty() {
            lineas.push(Line::from(Span::styled(mensaje, app.theme.dim)));
        }
        frame.render_widget(Paragraph::new(lineas), interior);
        return;
    }

    let ancho_fecha = match app.history.range {
        Range::Hours24 => 5,
        Range::Days7 => 9,
        _ => 9,
    };
    let ancho_resumen = usize::from(interior.width)
        .saturating_sub(ancho_fecha + 4)
        .max(8);
    for (posicion, item) in visibles.iter().enumerate() {
        if lineas.len() >= usize::from(interior.height) {
            break;
        }
        let fecha = etiqueta_evento(item, app.history.range);
        let seleccionado =
            app.history.focus == HistoryFocus::Eventos && posicion == app.history.timeline_selected;
        let estilo = if seleccionado {
            app.theme.selected
        } else {
            app.theme.normal
        };
        let mut spans = vec![
            Span::styled(
                format!(
                    "{} ",
                    if seleccionado {
                        "▸"
                    } else if item.kind == TimelineKind::Session {
                        "·"
                    } else {
                        " "
                    }
                ),
                if seleccionado {
                    app.theme.accent
                } else {
                    app.theme.dim
                },
            ),
            Span::styled(
                format!("{fecha:<ancho_fecha$} "),
                if seleccionado {
                    app.theme.selected
                } else {
                    app.theme.dim
                },
            ),
        ];
        spans.push(Span::styled(
            recortar(&item.summary, ancho_resumen),
            if item.kind == TimelineKind::Session && !seleccionado {
                app.theme.dim
            } else {
                estilo
            },
        ));
        lineas.push(Line::from(spans).style(estilo));
    }
    frame.render_widget(Paragraph::new(lineas), interior);
}

/// Fecha corta de un evento o sesión.
fn etiqueta_evento(item: &crate::history::TimelineItem, range: Range) -> String {
    let hora = charts::hora_local(item.at_unix);
    match range {
        Range::Hours24 => hora,
        Range::Days7 | Range::Days30 => {
            format!("{} {hora}", charts::etiqueta_dia_corto(item.at_unix))
        }
        Range::Year1 => charts::etiqueta_dia_corto(item.at_unix),
    }
}

/// Línea inferior con la antigüedad de los datos, la cobertura y el tamaño de la BD.
fn draw_pie(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    if let Some(stats) = &app.history.db_stats {
        if let Some(desde) = &stats.data_since {
            if let Some(unix) = crate::history::localtime::unix_de_rfc3339(desde) {
                let dia = crate::history::LocalDay::from_unix(unix);
                spans.push(Span::styled(
                    format!("Datos desde {}", dia.label_corto()),
                    app.theme.dim,
                ));
            }
        }
        if let Some(pct) = app.history.cobertura_pct() {
            if !spans.is_empty() {
                spans.push(Span::styled(" · ", app.theme.dim));
            }
            spans.push(Span::styled(
                format!(
                    "cobertura en {}: {}",
                    app.history.range.label(),
                    charts::formatear_pct(pct)
                ),
                app.theme.dim,
            ));
        }
        if stats.db_bytes > 0 {
            if !spans.is_empty() {
                spans.push(Span::styled(" · ", app.theme.dim));
            }
            spans.push(Span::styled(
                format!("BD {}", formatear_bytes(stats.db_bytes)),
                if app.history.db_over_limit {
                    app.theme.warning
                } else {
                    app.theme.dim
                },
            ));
            if app.history.db_over_limit {
                spans.push(Span::styled(" (por encima del límite)", app.theme.warning));
            }
        }
    }
    if spans.is_empty() {
        let texto = if app.config.history.enabled {
            "Los datos del histórico se actualizan cada minuto"
        } else {
            "Histórico desactivado ([history] enabled = false)"
        };
        spans.push(Span::styled(texto, app.theme.dim));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Mensaje centrado dentro de un área (cargando, sin datos, desactivado).
fn draw_mensaje(frame: &mut Frame, app: &App, area: Rect, mensaje: &str, ayuda: Option<&str>) {
    let mut lineas = vec![Line::from(Span::styled(mensaje.to_string(), app.theme.dim))];
    if let Some(ayuda) = ayuda {
        lineas.push(Line::from(Span::styled(ayuda.to_string(), app.theme.dim)));
    }
    let alto = lineas.len() as u16;
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(alto),
        Constraint::Fill(1),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(lineas).alignment(Alignment::Center),
        vertical[1],
    );
}

/// Selector de sujeto (e) con búsqueda de equipos (/).
fn draw_selector(frame: &mut Frame, app: &App, area: Rect) {
    let filas = app.history.selector_filas();
    let ancho = area.width.saturating_sub(8).min(46);
    let alto = (filas.len() as u16 + 5).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(ancho)) / 2;
    let y = area.y + (area.height.saturating_sub(alto)) / 2;
    let zona = Rect::new(x, y, ancho, alto);
    frame.render_widget(Clear, zona);
    let titulo = if app.history.selector_editando() {
        "Sujeto · buscar equipo"
    } else {
        "Sujeto · [e]"
    };
    let bloque = Block::bordered()
        .border_style(app.theme.accent)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(zona);
    frame.render_widget(bloque, zona);

    let mut lineas: Vec<Line> = Vec::new();
    if app.history.selector_editando() {
        lineas.push(Line::from(vec![
            Span::styled("Buscar: ", app.theme.accent),
            Span::styled(
                app.history.selector_consulta().to_string(),
                app.theme.normal,
            ),
            Span::styled("█", app.theme.accent),
        ]));
    }
    for (etiqueta, seleccionada) in filas {
        if lineas.len() >= usize::from(interior.height.saturating_sub(1)) {
            break;
        }
        let estilo = if seleccionada {
            app.theme.selected
        } else {
            app.theme.normal
        };
        lineas.push(Line::from(vec![
            Span::styled(if seleccionada { " ▸ " } else { "   " }, app.theme.accent),
            Span::styled(etiqueta, estilo),
        ]));
    }
    lineas.push(Line::from(Span::styled(
        "[/]buscar  [Enter]elegir  [Esc]cerrar",
        app.theme.dim,
    )));
    frame.render_widget(Paragraph::new(lineas), interior);
}

/// Recorta un texto y añade puntos suspensivos si no cabe.
fn recortar(texto: &str, ancho: usize) -> String {
    if texto.chars().count() <= ancho {
        return texto.to_string();
    }
    let mut recortado: String = texto.chars().take(ancho.saturating_sub(1)).collect();
    recortado.push('…');
    recortado
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::history::{
        DbStats, EventFilter, Gap, HistRankRow, HistWindow, PresenceSpan, RankingResult, Series,
        SeriesPoint, TimelineItem, TimelineKind, TopRow,
    };
    use crate::rankings::Dimension as RankDimension;
    use crate::repo::devices::Device;
    use crate::tui::app::{App, Tab};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn dispositivo(id: i64, ip: &str, nombre: Option<&str>) -> Device {
        Device {
            id,
            mac: format!("aa:bb:cc:dd:ee:0{id}"),
            ip: ip.to_string(),
            hostname: nombre.map(str::to_string),
            vendor: Some("Apple".to_string()),
            interface_id: 1,
            device_type: "pc".to_string(),
            is_online: true,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
            alias: None,
            notes: None,
            os_family: None,
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

    fn app_prueba() -> App {
        let mut app = App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        );
        app.set_data(
            vec![
                dispositivo(1, "192.168.1.42", Some("tv-sala")),
                dispositivo(2, "192.168.1.57", Some("iPhone-Marta")),
            ],
            Vec::new(),
        );
        app.tab = Tab::Historico;
        app.history.set_history_enabled(app.config.history.enabled);
        app.history.sync_context(
            Tab::Historico,
            None,
            RankDimension::Device,
            crate::rankings::Window::Sixty,
        );
        app
    }

    fn serie_ejemplo() -> Series {
        let puntos = (0..48)
            .map(|indice| SeriesPoint {
                at: 1_760_000_000 + indice * 1800,
                bytes_down: (indice as u64 + 1) * 1_000_000,
                bytes_up: (indice as u64 + 1) * 100_000,
                gap: (9..=11).contains(&indice),
                future: indice >= 46,
            })
            .collect();
        Series {
            range: Range::Hours24,
            points: puntos,
            total_down: 48 * 1_000_000,
            total_up: 48 * 100_000,
            max: Some((40, 44_000_000)),
        }
    }

    fn fila_top(clave: &str, etiqueta: &str, total: u64, device_id: Option<i64>) -> TopRow {
        TopRow {
            key: clave.to_string(),
            label: etiqueta.to_string(),
            subtitle: None,
            device_id,
            bytes_down: total,
            bytes_up: total / 10,
            pct: 42.0,
            devices: 1,
        }
    }

    fn evento(at_unix: i64, resumen: &str) -> TimelineItem {
        TimelineItem {
            at: "2026-11-11T10:12:00Z".to_string(),
            at_unix,
            kind: TimelineKind::Event,
            device_id: Some(1),
            device_label: Some("tv-sala".to_string()),
            event_type: "new".to_string(),
            summary: resumen.to_string(),
            session_reason: None,
        }
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app, frame.area()))
            .expect("dibujado del histórico");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    /// Datos con los que responder a las consultas del histórico en las pruebas.
    #[derive(Default)]
    struct DatosPrueba {
        serie: Option<Series>,
        equipos: Vec<TopRow>,
        apps: Vec<TopRow>,
        timeline: Vec<TimelineItem>,
        coverage: Option<Vec<Gap>>,
    }

    /// Responde a las consultas pendientes de la pestaña Histórico con datos de
    /// prueba, ejercitando el mismo camino que el lector real.
    fn inyectar(app: &mut App, datos: DatosPrueba) {
        app.history.history_refresh();
        let ahora = 1_760_000_000;
        let peticiones = app.history.history_pending_requests(ahora);
        for (id, consulta) in peticiones {
            let respuesta = match consulta {
                crate::history::HistoryQuery::Series { .. } => datos
                    .serie
                    .clone()
                    .map(crate::history::HistoryResponse::Series),
                crate::history::HistoryQuery::Top { dimension, .. } => {
                    let filas = match dimension {
                        crate::history::Dimension::Total => datos.equipos.clone(),
                        crate::history::Dimension::App => datos.apps.clone(),
                        _ => Vec::new(),
                    };
                    Some(crate::history::HistoryResponse::Top(filas))
                }
                crate::history::HistoryQuery::Timeline { .. } => Some(
                    crate::history::HistoryResponse::Timeline(datos.timeline.clone()),
                ),
                crate::history::HistoryQuery::Coverage { .. } => datos
                    .coverage
                    .clone()
                    .map(crate::history::HistoryResponse::Coverage),
                crate::history::HistoryQuery::LastEvent => {
                    Some(crate::history::HistoryResponse::LastEvent(None))
                }
                crate::history::HistoryQuery::DbStats => {
                    Some(crate::history::HistoryResponse::DbStats(DbStats::default()))
                }
                _ => None,
            };
            if let Some(respuesta) = respuesta {
                app.history.apply_history_response(id, &Ok(respuesta));
            }
        }
    }

    #[test]
    fn la_pestana_muestra_cabecera_grafica_y_paneles_en_80x24() {
        let mut app = app_prueba();
        inyectar(
            &mut app,
            DatosPrueba {
                serie: Some(serie_ejemplo()),
                equipos: vec![fila_top("1", "tv-sala", 21_000_000_000, Some(1))],
                apps: vec![fila_top("youtube", "YouTube", 18_000_000_000, None)],
                timeline: vec![evento(1_760_000_000, "iPhone-Marta vuelve")],
                coverage: None,
            },
        );
        app.history.cursor = Some(40);
        let texto = dibujar(&mut app, 80, 24);
        assert!(texto.contains("Histórico"));
        assert!(texto.contains("Toda la red"));
        assert!(texto.contains("24 h"));
        assert!(texto.contains("puntos de 30 min"));
        assert!(texto.contains("máximo"));
        assert!(texto.contains("Más tráfico"));
        assert!(texto.contains("Eventos"));
        assert!(texto.contains("tv-sala"));
        assert!(texto.contains("YouTube"));
        assert!(texto.contains("iPhone-Marta vuelve"));
        assert!(texto.contains("sin datos"), "leyenda de huecos");
    }

    #[test]
    fn los_huecos_y_el_futuro_se_distinguen_en_la_grafica() {
        let mut app = app_prueba();
        inyectar(
            &mut app,
            DatosPrueba {
                serie: Some(serie_ejemplo()),
                ..DatosPrueba::default()
            },
        );
        let texto = dibujar(&mut app, 120, 40);
        assert!(texto.contains('░'), "los huecos se dibujan con ░");
        assert!(texto.contains('█'), "las barras se dibujan con █");
        app.history.focus = HistoryFocus::Grafica;
        app.history.cursor = Some(10);
        let texto = dibujar(&mut app, 120, 40);
        assert!(
            texto.contains("sin datos"),
            "el cursor sobre un hueco lo dice"
        );
    }

    #[test]
    fn sin_datos_avisa_del_rango_vacio() {
        let mut app = app_prueba();
        let mut vacia = serie_ejemplo();
        for punto in &mut vacia.points {
            punto.bytes_down = 0;
            punto.bytes_up = 0;
            punto.gap = true;
        }
        vacia.total_down = 0;
        vacia.total_up = 0;
        inyectar(
            &mut app,
            DatosPrueba {
                serie: Some(vacia),
                ..DatosPrueba::default()
            },
        );
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("Sin datos en este rango"));
    }

    #[test]
    fn cargando_se_muestra_mientras_no_llega_la_serie() {
        let mut app = app_prueba();
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("Cargando…"));
    }

    #[test]
    fn con_el_historico_desactivado_se_avisa() {
        let mut app = app_prueba();
        app.config.history.enabled = false;
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("El histórico está desactivado"));
        assert!(texto.contains("[history] enabled = false"));
        assert!(
            texto.contains("La línea de tiempo de eventos sigue disponible"),
            "la línea de tiempo sigue"
        );
    }

    #[test]
    fn los_destinos_se_avisan_en_el_rango_de_un_ano() {
        let mut app = app_prueba();
        app.history.subject = Some(crate::history::SubjectSel::Device(1));
        app.history.range = Range::Year1;
        inyectar(
            &mut app,
            DatosPrueba {
                apps: vec![fila_top("youtube", "YouTube", 100, None)],
                ..DatosPrueba::default()
            },
        );
        let texto = dibujar(&mut app, 120, 34);
        assert!(texto.contains("Destinos: solo los últimos 30 días"));
    }

    #[test]
    fn el_selector_de_sujeto_se_dibuja_con_sus_equipos() {
        let mut app = app_prueba();
        app.history.series = Some(serie_ejemplo());
        dibujar(&mut app, 100, 30);
        app.history
            .history_handle_key(crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char('e'),
                crossterm::event::KeyModifiers::NONE,
            ));
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("Sujeto · [e]"));
        assert!(texto.contains("Toda la red"));
        assert!(texto.contains("Este equipo"));
        assert!(texto.contains("tv-sala"));
    }

    #[test]
    fn el_bloque_de_detalle_muestra_presencia_sobre_el_mismo_eje() {
        // La fila de presencia y la rejilla las pinta device_detail; aquí se
        // comprueba la utilidad compartida en el ancho del panel.
        let theme = crate::tui::theme::Theme::new(true);
        let tramos = vec![PresenceSpan {
            start: 1_760_000_000 - 3600,
            end: 1_760_000_000,
            state: crate::history::PresenceState::Present,
        }];
        let fila = charts::fila_presencia(&tramos, Range::Hours24, 1_760_000_000, 40, &theme);
        let texto: String = fila.spans.iter().map(|span| span.content.clone()).collect();
        assert_eq!(texto.chars().count(), 40);
        assert!(texto.contains('█'));
    }

    #[test]
    fn el_pie_muestra_cobertura_y_tamano_de_la_base_de_datos() {
        let mut app = app_prueba();
        inyectar(
            &mut app,
            DatosPrueba {
                serie: Some(serie_ejemplo()),
                coverage: Some(vec![Gap {
                    start: 1_760_000_000,
                    end: 1_760_000_000 + 3600,
                }]),
                ..DatosPrueba::default()
            },
        );
        app.history.db_stats = Some(DbStats {
            db_bytes: 212_000_000,
            wal_bytes: 4_000_000,
            data_since: Some("2026-10-12T00:00:00Z".to_string()),
            coverage_30d_pct: 91.0,
        });
        let texto = dibujar(&mut app, 120, 34);
        assert!(texto.contains("Datos desde"));
        assert!(texto.contains("cobertura en 24 h"));
        assert!(texto.contains("BD"));
    }

    #[test]
    fn la_ventana_historica_de_trafico_no_usa_esta_vista() {
        // El ranking de 1 h/24 h se pinta en traffic.rs; el estado lo convierte.
        let mut estado = crate::tui::history_state::HistoryState::new();
        estado.set_history_enabled(true);
        estado.sync_context(
            Tab::Trafico,
            None,
            RankDimension::Destination,
            crate::rankings::Window::Day24,
        );
        estado.traffic_ranking = Some(RankingResult {
            window: HistWindow::Day24,
            dimension: crate::history::Dimension::Destination,
            rows: vec![HistRankRow {
                key: "googlevideo.com".to_string(),
                label: "googlevideo.com".to_string(),
                subtitle: None,
                device_id: None,
                bytes_down: 10,
                bytes_up: 2,
                devices: 3,
                connections: 7,
            }],
            total_down: 10,
            total_up: 2,
            unidentified_pct: 4.0,
            closed_until: 1_760_000_000,
            gap_seconds: 0,
        });
        let filas = estado
            .ranking_rows_trafico(crate::rankings::Window::Day24)
            .expect("filas");
        assert_eq!(filas.len(), 1);
        assert_eq!(filas[0].devices, 3);
    }

    #[test]
    fn la_leyenda_de_eventos_muestra_el_filtro_activo() {
        let mut app = app_prueba();
        app.history.filter = EventFilter::Services;
        inyectar(
            &mut app,
            DatosPrueba {
                timeline: vec![evento(1_760_000_000, "nas: cierra 445/tcp")],
                ..DatosPrueba::default()
            },
        );
        let texto = dibujar(&mut app, 120, 34);
        assert!(texto.contains("filtro: servicios"));
        assert!(texto.contains("nas: cierra 445/tcp"));
    }

    #[test]
    fn el_estado_del_histórico_usa_los_equipos_para_el_sujeto() {
        let app = app_prueba();
        let etiqueta = app
            .history
            .label_de_sujeto(crate::history::SubjectSel::Device(2));
        assert_eq!(etiqueta, "iPhone-Marta");
    }
}
