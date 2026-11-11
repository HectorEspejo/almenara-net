//! Pestaña Tráfico: ranking por equipo, destino, app, categoría, protocolo o
//! proceso (Fase 4), con ventana de 60 s, 5 min o sesión, panel «¿Quién lo usa?»
//! y pie con los totales y el porcentaje sin identificar.
//!
//! Las filas las publica el agregador de tráfico (top 50 por dimensión y
//! ventana); la TUI solo las reordena con «s» y las pinta. La agrupación (g) se
//! persiste en [ui].traffic_group; la ventana (w) no se persiste y arranca en
//! 60 s. Sin datos se muestra un mensaje claro y, si no hay captura, el aviso de
//! F3 con la semilla de TRAFFIC_SNAPSHOT.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::classify::DeviceType;
use crate::history::HistWindow;
use crate::rankings::{Dimension, RankRow, Window};
use crate::traffic::{formatear_bytes, formatear_bytes_por_segundo, sparkline};
use crate::tui::app::App;
use crate::tui::theme::device_icon;
use crate::tui::views::charts;

/// Número máximo de filas del ranking.
pub const TOP_RANKING: usize = 10;
/// Puntos de sparkline que se muestran como mínimo en pantallas estrechas.
const SPARK_ANCHO_MIN: u16 = 10;
/// Filas máximas visibles del panel «¿Quién lo usa?».
const MAX_FILAS_QUIEN: usize = 8;

/// Cabeceras de cada agrupación (§6, notas de UX).
///
/// En las ventanas de 1 h y 24 h las cifras son volúmenes (no velocidades), no
/// hay sparkline y se añade la columna de conexiones de la ventana.
fn cabeceras(dimension: Dimension, historica: bool) -> Vec<&'static str> {
    match (dimension, historica) {
        (Dimension::Device, false) => vec![
            "#",
            "Dispositivo",
            "Tipo",
            "↓ in",
            "↑ out",
            "Total",
            "sparkline 60 s",
        ],
        (Dimension::Device, true) => vec![
            "#",
            "Dispositivo",
            "Tipo",
            "↓ bajada",
            "↑ subida",
            "Total",
            "Conexiones",
        ],
        (Dimension::Destination, false) => vec![
            "#",
            "Destino",
            "Organización · país",
            "↓ bajada",
            "↑ subida",
            "Equipos",
        ],
        (Dimension::Destination, true) => vec![
            "#",
            "Destino",
            "Organización · país",
            "↓ bajada",
            "↑ subida",
            "Equipos",
            "Conexiones",
        ],
        (Dimension::App, false) => vec![
            "#",
            "App",
            "Categoría",
            "↓ bajada",
            "↑ subida",
            "Equipos",
            "sparkline 60 s",
        ],
        (Dimension::App, true) => vec![
            "#",
            "App",
            "Categoría",
            "↓ bajada",
            "↑ subida",
            "Equipos",
            "Conexiones",
        ],
        (Dimension::Category, false) => {
            vec!["#", "Categoría", "↓ bajada", "↑ subida", "Apps", "Equipos"]
        }
        (Dimension::Category, true) => vec![
            "#",
            "Categoría",
            "↓ bajada",
            "↑ subida",
            "Equipos",
            "Conexiones",
        ],
        (Dimension::Protocol, false) => {
            vec!["#", "Protocolo", "↓ bajada", "↑ subida", "Conexiones"]
        }
        (Dimension::Protocol, true) => {
            vec!["#", "Protocolo", "↓ bajada", "↑ subida", "Conexiones"]
        }
        (Dimension::Process, false) => {
            vec!["#", "Proceso (pid)", "↓ bajada", "↑ subida", "Conexiones"]
        }
        (Dimension::Process, true) => {
            vec!["#", "Proceso (pid)", "↓ bajada", "↑ subida", "Conexiones"]
        }
    }
}

/// Anchos base de las columnas y columnas flexibles de cada agrupación.
fn anchos_base(dimension: Dimension, historica: bool) -> (Vec<u16>, Vec<usize>) {
    match (dimension, historica) {
        (Dimension::Device, false) => (vec![2, 16, 7, 9, 9, 9, 14], vec![1]),
        (Dimension::Device, true) => (vec![2, 15, 7, 9, 9, 9, 10], vec![1]),
        (Dimension::Destination, false) => (vec![2, 16, 18, 9, 9, 7], vec![1, 2]),
        (Dimension::Destination, true) => (vec![2, 14, 16, 9, 9, 7, 10], vec![1, 2]),
        (Dimension::App, false) => (vec![2, 16, 13, 9, 9, 7, 10], vec![1, 2, 6]),
        (Dimension::App, true) => (vec![2, 14, 12, 9, 9, 7, 10], vec![1, 2]),
        (Dimension::Category, false) => (vec![2, 16, 9, 9, 7, 7], vec![1]),
        (Dimension::Category, true) => (vec![2, 18, 9, 9, 7, 10], vec![1]),
        (Dimension::Protocol, _) => (vec![2, 14, 9, 9, 10], vec![1]),
        (Dimension::Process, _) => (vec![2, 18, 9, 9, 10], vec![1]),
    }
}

/// Restricciones de ancho de una agrupación para el ancho disponible.
///
/// El espacio sobrante se reparte entre las columnas flexibles (nombre,
/// organización o sparkline) para que 80 columnas sea siempre el mínimo.
fn constraints(dimension: Dimension, ancho: u16, historica: bool) -> Vec<Constraint> {
    let (mut bases, flexibles) = anchos_base(dimension, historica);
    let separaciones = bases.len().saturating_sub(1) as u16;
    let fijo: u16 = bases.iter().sum::<u16>() + separaciones;
    let extra = ancho.saturating_sub(fijo);
    if !flexibles.is_empty() {
        let cuota = extra / flexibles.len() as u16;
        let resto = extra % flexibles.len() as u16;
        for (posicion, indice) in flexibles.iter().enumerate() {
            let suma = cuota + u16::from(posicion == 0) * resto;
            if let Some(ancho_columna) = bases.get_mut(*indice) {
                *ancho_columna = ancho_columna.saturating_add(suma);
            }
        }
    }
    bases.into_iter().map(Constraint::Length).collect()
}

/// Ancho de la columna de sparkline (0 si la agrupación no la tiene).
fn ancho_sparkline(dimension: Dimension, ancho: u16, historica: bool) -> u16 {
    if historica {
        return 0;
    }
    let (bases, flexibles) = anchos_base(dimension, false);
    let separaciones = bases.len().saturating_sub(1) as u16;
    let fijo: u16 = bases.iter().sum::<u16>() + separaciones;
    let extra = ancho.saturating_sub(fijo);
    let con_sparkline = bases.len() - 1;
    let mut base_spark = bases[con_sparkline];
    if flexibles.contains(&con_sparkline) {
        let cuota = extra / flexibles.len() as u16;
        let resto = extra % flexibles.len() as u16;
        let posicion = flexibles
            .iter()
            .position(|indice| *indice == con_sparkline)
            .unwrap_or(0);
        base_spark = base_spark.saturating_add(cuota + u16::from(posicion == 0) * resto);
    }
    base_spark
}

/// Dibuja la pestaña Tráfico.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let historica = app.ventana_historica().is_some();
    let sufijo = if historica { " · histórico" } else { "" };
    let pista = format!(
        "[g] {} · [w] {}{sufijo} · [s] {}",
        app.traffic_group.label(),
        app.traffic_window.label(),
        app.rank_sort.label()
    );
    let titulo = format!(
        "Tráfico — ranking por {} · ventana {pista}",
        app.traffic_group.label()
    );
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    // Sin captura activa ni datos en vivo: aviso claro + snapshot de la semilla.
    // Las ventanas de 1 h y 24 h no dependen de la captura: salen del histórico.
    if !app.traffic.capture.active && !app.traffic.has_live_data() && !historica {
        draw_sin_captura(frame, app, interior);
        return;
    }

    let filas = app.ranking_rows();
    let panel_abierto = app.who_uses_open() || app.history.history_who_uses_open();
    let zonas = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(interior);
    let (area_ranking, area_panel) = if panel_abierto {
        let alto_panel = alto_panel_quien(app).min(zonas[0].height.saturating_sub(2));
        let alto_panel = alto_panel.max(3);
        let sub =
            Layout::vertical([Constraint::Min(1), Constraint::Length(alto_panel)]).split(zonas[0]);
        (sub[0], Some(sub[1]))
    } else {
        (zonas[0], None)
    };

    if filas.is_empty() {
        let (mensaje, ayuda) = if historica {
            if app.history.error_actual().is_some() {
                (
                    "Error al cargar el histórico",
                    "(revisa la pestaña Histórico)",
                )
            } else if app.history.traffic_ranking.is_none()
                && app.history.ranking_trafico_cargando()
            {
                ("Cargando…", "(minutos cerrados del histórico)")
            } else {
                (
                    "Sin datos en esta ventana",
                    "(no hay minutos cerrados con tráfico)",
                )
            }
        } else if app.traffic.capture.active {
            (
                "Sin tráfico en esta ventana",
                "(esperando al primer ciclo de captura)",
            )
        } else {
            (
                "Sin tráfico en esta ventana",
                "(la captura está deshabilitada; revisa la pestaña Ayuda)",
            )
        };
        let parrafo = Paragraph::new(vec![
            Line::from(Span::styled(mensaje, app.theme.dim)),
            Line::from(Span::styled(ayuda, app.theme.dim)),
        ])
        .alignment(Alignment::Center);
        let vertical = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(2),
            Constraint::Fill(1),
        ])
        .split(area_ranking);
        frame.render_widget(parrafo, vertical[1]);
    } else {
        draw_ranking(frame, app, &filas, area_ranking);
    }
    if let Some(area) = area_panel {
        if app.history.history_who_uses_open() {
            draw_quien_lo_usa_historico(frame, app, area);
        } else {
            draw_quien_lo_usa(frame, app, area);
        }
    }
    draw_resumen(frame, app, zonas[1]);
}

fn draw_ranking(frame: &mut Frame, app: &mut App, filas_ranking: &[RankRow], area: Rect) {
    let dimension = app.traffic_group;
    let window = app.traffic_window;
    let historica = window.history().is_some();
    let cabecera = Row::new(cabeceras(dimension, historica)).style(app.theme.accent);
    let ancho_spark = ancho_sparkline(dimension, area.width, historica);

    let dispositivos: Vec<(i64, String, String)> = app
        .devices
        .iter()
        .map(|device| {
            let (icono, _estilo) = device_icon(device, &app.theme);
            (
                device.id,
                icono.to_string(),
                device.display_name().to_string(),
            )
        })
        .collect();

    let filas: Vec<Row> = filas_ranking
        .iter()
        .take(TOP_RANKING)
        .enumerate()
        .map(|(posicion, fila)| {
            let numero = Cell::from(Span::styled(format!("{}", posicion + 1), app.theme.dim));
            if historica {
                return fila_historica(app, fila, numero, dimension);
            }
            match dimension {
                Dimension::Device => fila_equipo(app, fila, numero, ancho_spark, &dispositivos),
                Dimension::Destination => fila_destino(app, fila, numero, window),
                Dimension::App => fila_app(app, fila, numero, window, ancho_spark),
                Dimension::Category => fila_categoria(app, fila, numero, window),
                Dimension::Protocol => fila_protocolo(app, fila, numero, window),
                Dimension::Process => fila_proceso(app, fila, numero, window),
            }
        })
        .collect();

    let tabla = Table::new(filas, constraints(dimension, area.width, historica))
        .header(cabecera)
        .column_spacing(1)
        .row_highlight_style(app.theme.selected)
        .highlight_symbol(Span::styled("▸ ", app.theme.accent))
        .style(app.theme.normal);

    *app.traffic_table_state.selected_mut() = Some(app.traffic_selected);
    frame.render_stateful_widget(tabla, area, &mut app.traffic_table_state);
}

/// Nombre visible de un equipo del ranking (con [host] para el tráfico propio).
fn nombre_equipo(app: &App, device_id: Option<i64>, etiqueta: &str) -> String {
    match device_id {
        Some(crate::traffic::DEVICE_ID_HOST) => "[host]".to_string(),
        Some(id) => app
            .devices
            .iter()
            .find(|device| device.id == id)
            .map(|device| device.display_name().to_string())
            .unwrap_or_else(|| etiqueta.to_string()),
        None => etiqueta.to_string(),
    }
}

fn celda_equipo(
    app: &App,
    fila: &RankRow,
    dispositivos: &[(i64, String, String)],
) -> Cell<'static> {
    let device_id = fila.device_id;
    let es_host = device_id == Some(crate::traffic::DEVICE_ID_HOST);
    let (icono, estilo_icono) = if es_host {
        ("", app.theme.accent)
    } else {
        match device_id.and_then(|id| dispositivos.iter().find(|(ident, _, _)| *ident == id)) {
            Some((_, icono, _)) => (icono.as_str(), app.theme.accent),
            None => ("[?]", app.theme.dim),
        }
    };
    let nombre = nombre_equipo(app, device_id, &fila.label);
    let estilo_nombre = if es_host {
        app.theme.accent.add_modifier(Modifier::BOLD)
    } else {
        app.theme.normal
    };
    Cell::from(Line::from(vec![
        Span::styled(icono.to_string(), estilo_icono),
        Span::styled(format!(" {nombre}"), estilo_nombre),
    ]))
}

fn fila_equipo(
    app: &App,
    fila: &RankRow,
    numero: Cell<'static>,
    ancho_spark: u16,
    dispositivos: &[(i64, String, String)],
) -> Row<'static> {
    let estadisticas = fila.device_id.and_then(|id| app.traffic.device_stats(id));
    let tipo = match fila.device_id {
        Some(crate::traffic::DEVICE_ID_HOST) => "host".to_string(),
        Some(id) => app
            .devices
            .iter()
            .find(|device| device.id == id)
            .map(|device| {
                DeviceType::from_str(device.effective_device_type())
                    .unwrap_or(DeviceType::Unknown)
                    .label()
                    .to_string()
            })
            .unwrap_or_else(|| "?".to_string()),
        None => "?".to_string(),
    };
    let (tasa_bajada, tasa_subida) = match &estadisticas {
        Some(estadisticas) => (estadisticas.rate_in, estadisticas.rate_out),
        None => (
            app.bytes_por_segundo_en_ventana(fila.bytes_down, app.traffic_window),
            app.bytes_por_segundo_en_ventana(fila.bytes_up, app.traffic_window),
        ),
    };
    let serie: Vec<u64> = match &estadisticas {
        Some(estadisticas) => estadisticas
            .series_60s_in
            .iter()
            .zip(estadisticas.series_60s_out.iter())
            .map(|(entrada, salida)| entrada.saturating_add(*salida))
            .collect(),
        None => fila.series_60s.to_vec(),
    };
    let dibujo = dibujar_sparkline(&serie, ancho_spark);
    Row::new(vec![
        numero,
        celda_equipo(app, fila, dispositivos),
        Cell::from(Span::styled(tipo, app.theme.dim)),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(tasa_bajada),
            app.theme.online,
        )),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(tasa_subida),
            app.theme.accent.add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            formatear_bytes(fila.total()),
            app.theme.normal,
        )),
        Cell::from(Span::styled(dibujo, app.theme.accent)),
    ])
}

fn fila_destino(app: &App, fila: &RankRow, numero: Cell<'static>, window: Window) -> Row<'static> {
    let subtitulo = fila
        .subtitle
        .clone()
        .filter(|texto| !texto.trim().is_empty())
        .unwrap_or_else(|| "—".to_string());
    Row::new(vec![
        numero,
        Cell::from(Span::styled(fila.label.clone(), app.theme.normal)),
        Cell::from(Span::styled(subtitulo, app.theme.dim)),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_down, window)),
            app.theme.online,
        )),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_up, window)),
            app.theme.accent.add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(fila.devices.to_string(), app.theme.dim)),
    ])
}

fn fila_app(
    app: &App,
    fila: &RankRow,
    numero: Cell<'static>,
    window: Window,
    ancho_spark: u16,
) -> Row<'static> {
    let categoria = fila
        .subtitle
        .clone()
        .filter(|texto| !texto.trim().is_empty())
        .unwrap_or_else(|| "—".to_string());
    let dibujo = dibujar_sparkline(&fila.series_60s, ancho_spark);
    Row::new(vec![
        numero,
        Cell::from(Span::styled(fila.label.clone(), app.theme.normal)),
        Cell::from(Span::styled(categoria, app.theme.dim)),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_down, window)),
            app.theme.online,
        )),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_up, window)),
            app.theme.accent.add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(fila.devices.to_string(), app.theme.dim)),
        Cell::from(Span::styled(dibujo, app.theme.accent)),
    ])
}

fn fila_categoria(
    app: &App,
    fila: &RankRow,
    numero: Cell<'static>,
    window: Window,
) -> Row<'static> {
    let apps = contar_apps_de_categoria(app, fila, window);
    let texto_apps = match apps {
        Some(cuantas) => cuantas.to_string(),
        None => "—".to_string(),
    };
    Row::new(vec![
        numero,
        Cell::from(Span::styled(fila.label.clone(), app.theme.normal)),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_down, window)),
            app.theme.online,
        )),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_up, window)),
            app.theme.accent.add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(texto_apps, app.theme.dim)),
        Cell::from(Span::styled(fila.devices.to_string(), app.theme.dim)),
    ])
}

fn fila_protocolo(
    app: &App,
    fila: &RankRow,
    numero: Cell<'static>,
    window: Window,
) -> Row<'static> {
    Row::new(vec![
        numero,
        Cell::from(Span::styled(fila.label.clone(), app.theme.normal)),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_down, window)),
            app.theme.online,
        )),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_up, window)),
            app.theme.accent.add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(fila.connections.to_string(), app.theme.dim)),
    ])
}

fn fila_proceso(app: &App, fila: &RankRow, numero: Cell<'static>, window: Window) -> Row<'static> {
    let proceso = if fila.label.trim().is_empty() {
        fila.key.clone()
    } else {
        fila.label.clone()
    };
    Row::new(vec![
        numero,
        Cell::from(Span::styled(proceso, app.theme.normal)),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_down, window)),
            app.theme.online,
        )),
        Cell::from(Span::styled(
            formatear_bytes_por_segundo(app.bytes_por_segundo_en_ventana(fila.bytes_up, window)),
            app.theme.accent.add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(fila.connections.to_string(), app.theme.dim)),
    ])
}

/// Fila del ranking de una ventana histórica (1 h o 24 h): volúmenes y conexiones.
fn fila_historica(
    app: &App,
    fila: &RankRow,
    numero: Cell<'static>,
    dimension: Dimension,
) -> Row<'static> {
    let subtitulo = fila
        .subtitle
        .clone()
        .filter(|texto| !texto.trim().is_empty())
        .unwrap_or_else(|| "—".to_string());
    let bajada = Cell::from(Span::styled(
        formatear_bytes(fila.bytes_down),
        app.theme.online,
    ));
    let subida = Cell::from(Span::styled(
        formatear_bytes(fila.bytes_up),
        app.theme.accent.add_modifier(Modifier::BOLD),
    ));
    let equipos = Cell::from(Span::styled(fila.devices.to_string(), app.theme.dim));
    let conexiones = Cell::from(Span::styled(fila.connections.to_string(), app.theme.dim));
    let etiqueta = || Cell::from(Span::styled(fila.label.clone(), app.theme.normal));
    match dimension {
        Dimension::Device => {
            let dispositivo = crate::traffic::DEVICE_ID_HOST == fila.device_id.unwrap_or(i64::MIN);
            let tipo = if dispositivo {
                "host".to_string()
            } else {
                fila.device_id
                    .and_then(|id| app.devices.iter().find(|device| device.id == id))
                    .map(|device| {
                        DeviceType::from_str(device.effective_device_type())
                            .unwrap_or(DeviceType::Unknown)
                            .label()
                            .to_string()
                    })
                    .unwrap_or_else(|| "?".to_string())
            };
            Row::new(vec![
                numero,
                Cell::from(Span::styled(
                    nombre_equipo(app, fila.device_id, &fila.label),
                    app.theme.normal,
                )),
                Cell::from(Span::styled(tipo, app.theme.dim)),
                bajada,
                subida,
                Cell::from(Span::styled(
                    formatear_bytes(fila.total()),
                    app.theme.normal,
                )),
                conexiones,
            ])
        }
        Dimension::Destination => Row::new(vec![
            numero,
            etiqueta(),
            Cell::from(Span::styled(subtitulo, app.theme.dim)),
            bajada,
            subida,
            equipos,
            conexiones,
        ]),
        Dimension::App => Row::new(vec![
            numero,
            etiqueta(),
            Cell::from(Span::styled(subtitulo, app.theme.dim)),
            bajada,
            subida,
            equipos,
            conexiones,
        ]),
        Dimension::Category => Row::new(vec![
            numero,
            etiqueta(),
            bajada,
            subida,
            equipos,
            conexiones,
        ]),
        Dimension::Protocol | Dimension::Process => {
            Row::new(vec![numero, etiqueta(), bajada, subida, conexiones])
        }
    }
}

/// Cuenta las apps distintas de una categoría a partir del ranking de apps.
///
/// El ranking publica las métricas de categoría con equipos y conexiones; el
/// número de apps se deduce de las filas de la dimensión app de la misma ventana
/// (categoría corta en el subtítulo). Si no hay forma de deducirlo devuelve None
/// y la celda muestra «—».
fn contar_apps_de_categoria(app: &App, fila: &RankRow, window: Window) -> Option<u32> {
    let apps = app.traffic.rank_rows(Dimension::App, window);
    if apps.is_empty() {
        return None;
    }
    let mut claves: Vec<&str> = Vec::new();
    for app in &apps {
        let categoria = app.subtitle.as_deref().unwrap_or("");
        let coincide = categoria.eq_ignore_ascii_case(&fila.label)
            || categoria.eq_ignore_ascii_case(fila.subtitle.as_deref().unwrap_or(""))
            || app
                .subtitle
                .as_deref()
                .map(|texto| texto.eq_ignore_ascii_case(&fila.key))
                .unwrap_or(false);
        if coincide && !claves.contains(&app.key.as_str()) {
            claves.push(app.key.as_str());
        }
    }
    if claves.is_empty() {
        None
    } else {
        Some(claves.len() as u32)
    }
}

/// Sparkline recortada al ancho disponible (mínimo 10 puntos).
fn dibujar_sparkline(serie: &[u64], ancho: u16) -> String {
    let ancho = usize::from(ancho.max(SPARK_ANCHO_MIN));
    if serie.is_empty() {
        return "─".repeat(ancho);
    }
    let inicio = serie.len().saturating_sub(ancho);
    sparkline(&serie[inicio..])
}

/// Alto del panel «¿Quién lo usa?» según las filas.
fn alto_panel_quien(app: &App) -> u16 {
    let filas = if let Some(panel) = app.history.who_uses.as_ref() {
        panel.rows.len()
    } else {
        app.traffic
            .who_uses
            .as_ref()
            .map(|panel| panel.rows.len())
            .unwrap_or(0)
    };
    (filas.clamp(1, MAX_FILAS_QUIEN) as u16).saturating_add(2)
}

/// Panel «¿Quién lo usa?» de una ventana histórica (1 h o 24 h).
fn draw_quien_lo_usa_historico(frame: &mut Frame, app: &App, area: Rect) {
    let Some(panel) = app.history.who_uses.as_ref() else {
        return;
    };
    let titulo = format!(
        "¿Quién lo usa? {} · {} · [Enter]detalle [Esc]cerrar",
        panel.label,
        panel.window.label()
    );
    let bloque = Block::bordered()
        .border_style(app.theme.accent)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let mut lineas: Vec<Line> = Vec::new();
    if panel.pending {
        lineas.push(Line::from(Span::styled("Consultando…", app.theme.dim)));
    } else if panel.rows.is_empty() {
        lineas.push(Line::from(Span::styled(
            "Sin equipos para esta clave en la ventana",
            app.theme.dim,
        )));
    } else {
        let ancho_nombre = usize::from(interior.width).saturating_sub(30).clamp(8, 40);
        for (posicion, cuota) in panel.rows.iter().take(MAX_FILAS_QUIEN).enumerate() {
            let es_host = cuota.device_id == crate::traffic::DEVICE_ID_HOST;
            let (icono, estilo_icono) = match app.devices.iter().find(|d| d.id == cuota.device_id) {
                Some(device) => {
                    let (icono, estilo) = device_icon(device, &app.theme);
                    (icono.to_string(), estilo)
                }
                None if es_host => (String::new(), app.theme.accent),
                None => ("[?]".to_string(), app.theme.dim),
            };
            let nombre = if es_host {
                "[host]".to_string()
            } else {
                cuota.label.clone()
            };
            let nombre = recortar(&nombre, ancho_nombre);
            let linea = Line::from(vec![
                Span::styled(
                    format!(
                        "  {} ",
                        if posicion == panel.selected {
                            "▸"
                        } else {
                            " "
                        }
                    ),
                    app.theme.accent,
                ),
                Span::styled(format!("{icono} "), estilo_icono),
                Span::styled(
                    format!("{nombre:<ancho$} ", ancho = ancho_nombre),
                    app.theme.normal,
                ),
                Span::styled(
                    format!("{:>10} ", formatear_bytes(cuota.bytes)),
                    app.theme.online,
                ),
                Span::styled(format!("{:>4.0} %", cuota.pct), app.theme.accent),
            ]);
            let estilo = if posicion == panel.selected {
                app.theme.selected
            } else {
                app.theme.normal
            };
            lineas.push(linea.style(estilo));
        }
    }
    frame.render_widget(Paragraph::new(lineas), interior);
}

fn draw_quien_lo_usa(frame: &mut Frame, app: &App, area: Rect) {
    let Some(panel) = app.traffic.who_uses.as_ref() else {
        return;
    };
    let titulo = format!(
        "¿Quién lo usa? {} · {} · [Enter]detalle [Esc]cerrar",
        panel.label,
        panel.window.label()
    );
    let bloque = Block::bordered()
        .border_style(app.theme.accent)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let mut lineas: Vec<Line> = Vec::new();
    if panel.pending {
        lineas.push(Line::from(Span::styled("Consultando…", app.theme.dim)));
    } else if panel.rows.is_empty() {
        lineas.push(Line::from(Span::styled(
            "Sin equipos para esta clave en la ventana",
            app.theme.dim,
        )));
    } else {
        let ancho_nombre = usize::from(interior.width).saturating_sub(34).clamp(8, 40);
        for (posicion, cuota) in panel.rows.iter().take(MAX_FILAS_QUIEN).enumerate() {
            let es_host = cuota.device_id == crate::traffic::DEVICE_ID_HOST;
            let (icono, estilo_icono) = match app.devices.iter().find(|d| d.id == cuota.device_id) {
                Some(device) => {
                    let (icono, estilo) = device_icon(device, &app.theme);
                    (icono.to_string(), estilo)
                }
                None if es_host => (String::new(), app.theme.accent),
                None => ("[?]".to_string(), app.theme.dim),
            };
            let nombre = if es_host {
                "[host]".to_string()
            } else {
                cuota.label.clone()
            };
            let nombre = recortar(&nombre, ancho_nombre);
            let tasa = formatear_bytes_por_segundo(
                app.bytes_por_segundo_en_ventana(cuota.bytes, panel.window),
            );
            let linea = Line::from(vec![
                Span::styled(
                    format!(
                        "  {} ",
                        if posicion == panel.selected {
                            "▸"
                        } else {
                            " "
                        }
                    ),
                    app.theme.accent,
                ),
                Span::styled(format!("{icono} "), estilo_icono),
                Span::styled(
                    format!("{nombre:<ancho$} ", ancho = ancho_nombre),
                    app.theme.normal,
                ),
                Span::styled(format!("{tasa:>10} "), app.theme.online),
                Span::styled(format!("{:>4.0} %", cuota.pct), app.theme.accent),
            ]);
            let estilo = if posicion == panel.selected {
                app.theme.selected
            } else {
                app.theme.normal
            };
            lineas.push(linea.style(estilo));
        }
    }
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

fn draw_resumen(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(window) = app.ventana_historica() {
        draw_resumen_historico(frame, app, area, window);
        return;
    }
    let (entrada, salida) = app.traffic.global_rates();
    let sin_identificar = app.traffic.unidentified_pct(app.traffic_window);
    let totales = format!(
        "Total: ↓ {} · ↑ {} · sin identificar: {sin_identificar:.0} %",
        formatear_bytes_por_segundo(entrada),
        formatear_bytes_por_segundo(salida)
    );
    let mut visibilidad = format!(
        "{} · ventana: {} · orden: {}",
        app.visibility_line(),
        app.traffic_window.label(),
        app.rank_sort.label()
    );
    // Se conserva la difusión de F3 cuando la hay.
    let difusion = app.traffic.broadcast_bytes();
    if difusion > 0 {
        visibilidad.push_str(&format!(" · difusión {}", formatear_bytes(difusion)));
    }
    if !app.traffic.capture.active {
        if let Some(fecha) = app.traffic.seed_label() {
            visibilidad.push_str(&format!(" · snapshot: {fecha}"));
        }
    }
    let filas = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
    frame.render_widget(
        Paragraph::new(Span::styled(totales, app.theme.normal)).style(app.theme.normal),
        filas[0],
    );
    frame.render_widget(
        Paragraph::new(Span::styled(visibilidad, app.theme.dim)),
        filas[1],
    );
}

/// Pie de una ventana histórica: volúmenes, minutos cerrados y huecos.
fn draw_resumen_historico(frame: &mut Frame, app: &App, area: Rect, window: HistWindow) {
    let (bajada, subida) = app
        .history
        .traffic_ranking
        .as_ref()
        .map(|ranking| (ranking.total_down, ranking.total_up))
        .unwrap_or((0, 0));
    let pct = app.sin_identificar_ventana();
    let totales = format!(
        "Total {}: ↓ {} · ↑ {} · sin identificar: {}",
        window.label(),
        formatear_bytes(bajada),
        formatear_bytes(subida),
        charts::formatear_pct(pct)
    );
    let mut pie = match app.history.cerrado_hasta() {
        Some(hasta) => format!(
            "Minutos cerrados hasta {}",
            crate::history::localtime::format_hora_local(hasta)
        ),
        None => "Esperando a que cierre el primer minuto…".to_string(),
    };
    if let Some(segundos) = app.history.huecos_trafico() {
        pie.push_str(&format!(
            " · huecos: {} sin datos",
            charts::formatear_hueco(segundos)
        ));
    } else if let Some(ranking) = app.history.traffic_ranking.as_ref() {
        pie.push_str(&format!(
            " · huecos: {} sin datos",
            charts::formatear_hueco(ranking.gap_seconds)
        ));
    }
    pie.push_str(&format!(
        " · ventana: {} · orden: {}",
        window.label(),
        app.rank_sort.label()
    ));
    if let Some(error) = app.history.error_actual() {
        pie.push_str(&format!(" · error: {error}"));
    }
    let filas = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);
    frame.render_widget(
        Paragraph::new(Span::styled(totales, app.theme.normal)),
        filas[0],
    );
    frame.render_widget(
        Paragraph::new(Span::styled(
            pie,
            if app.history.error_actual().is_some() {
                app.theme.warning
            } else {
                app.theme.dim
            },
        )),
        filas[1],
    );
}

fn draw_sin_captura(frame: &mut Frame, app: &App, area: Rect) {
    let motivo = app
        .traffic
        .capture
        .disabled_reason
        .clone()
        .unwrap_or_else(|| "captura desactivada".to_string());
    let mut lineas: Vec<Line> = Vec::new();
    lineas.push(Line::from(Span::styled(
        format!("Captura deshabilitada: {motivo}."),
        app.theme.warning,
    )));
    if app.traffic.capture.available {
        lineas.push(Line::from(Span::styled(
            "Revisa la configuración de captura en el fichero TOML.",
            app.theme.dim,
        )));
    } else {
        lineas.push(Line::from(Span::styled(
            "Consulta la pestaña Ayuda para habilitar la captura (setcap cap_net_raw+ep).",
            app.theme.dim,
        )));
    }
    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Sin tráfico en esta ventana: la captura está deshabilitada.",
        app.theme.dim,
    )));

    let filas_ranking = app.traffic.ranked_devices();
    if !app.traffic.has_seed() || filas_ranking.is_empty() {
        lineas.push(Line::from(Span::styled(
            "Todavía no hay ningún snapshot de tráfico guardado.",
            app.theme.dim,
        )));
    } else {
        let fecha = app.traffic.seed_label().unwrap_or_default();
        lineas.push(Line::from(Span::styled(
            format!("Snapshot del último ciclo capturado ({fecha}):"),
            app.theme.accent,
        )));
        let resumen = filas_ranking
            .iter()
            .take(TOP_RANKING)
            .map(|estadisticas| {
                let nombre = nombre_equipo(app, Some(estadisticas.device_id), "equipo");
                format!(
                    "{nombre} {}",
                    formatear_bytes(estadisticas.bytes_in.saturating_add(estadisticas.bytes_out))
                )
            })
            .collect::<Vec<_>>()
            .join(" · ");
        lineas.push(Line::from(Span::styled(resumen, app.theme.normal)));
    }

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Modo degradado: la captura pasiva requiere CAP_NET_RAW · ver Ayuda",
        app.theme.dim,
    )));

    let parrafo = Paragraph::new(lineas)
        .alignment(Alignment::Left)
        .style(app.theme.normal);
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(10),
        Constraint::Fill(1),
    ])
    .split(area);
    frame.render_widget(parrafo, vertical[1]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::aggregate::DeviceTraffic;
    use crate::config::Config;
    use crate::rankings::{DeviceShare, Dimension, RankRow, Window};
    use crate::repo::devices::Device;
    use crate::traffic::{CaptureStatus, RankingView};
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;
    use std::time::Instant;

    fn dispositivo(id: i64, ip: &str) -> Device {
        Device {
            id,
            mac: format!("00:1a:2b:3c:4d:{:02x}", id),
            ip: ip.to_string(),
            hostname: Some(format!("equipo-{id}")),
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
            watched: false,
        }
    }

    fn estadisticas(device_id: i64, bytes: u64) -> DeviceTraffic {
        DeviceTraffic {
            device_id,
            bytes_in: bytes,
            bytes_out: bytes / 2,
            packets_in: 10,
            packets_out: 5,
            rate_in: 120,
            rate_out: 60,
            peak_bps: bytes,
            series_60s_in: [1; 60],
            series_60s_out: [0; 60],
            series_5min_in: [1; 60],
            series_5min_out: [0; 60],
            top_ports: Vec::new(),
        }
    }

    fn fila(clave: &str, etiqueta: &str, bajada: u64, subida: u64) -> RankRow {
        RankRow {
            key: clave.to_string(),
            label: etiqueta.to_string(),
            subtitle: None,
            device_id: None,
            bytes_down: bajada,
            bytes_up: subida,
            devices: 2,
            connections: 3,
            series_60s: [1; 60],
        }
    }

    fn vista(dimension: Dimension, window: Window, rows: Vec<RankRow>) -> RankingView {
        RankingView {
            dimension,
            window,
            rows,
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
        app.set_data(vec![dispositivo(1, "192.168.1.42")], Vec::new());
        app.traffic.capture = CaptureStatus {
            active: true,
            pps: 2400,
            interfaces: vec!["eth0".to_string()],
            ..CaptureStatus::default()
        };
        app.traffic.updated_at = Some(Instant::now());
        app.traffic.unidentified = [3.0, 4.0, 5.0];
        app
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app, frame.area()))
            .expect("dibujado de Tráfico");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    fn app_con_agrupacion(dimension: Dimension, rows: Vec<RankRow>) -> App {
        let mut app = app_prueba();
        app.traffic_group = dimension;
        app.traffic.rankings = vec![vista(dimension, Window::Sixty, rows)];
        app
    }

    #[test]
    fn cada_agrupacion_muestra_sus_columnas_del_informe() {
        let casos: Vec<(Dimension, Vec<RankRow>, Vec<&str>)> = vec![
            (
                Dimension::Destination,
                vec![fila("googlevideo.com", "googlevideo.com", 9_000, 100)],
                vec![
                    "Destino",
                    "Organización · país",
                    "↓ bajada",
                    "↑ subida",
                    "Equipos",
                ],
            ),
            (
                Dimension::App,
                vec![fila("youtube", "YouTube", 9_000, 100)],
                vec![
                    "App",
                    "Categoría",
                    "↓ bajada",
                    "↑ subida",
                    "Equipos",
                    "sparkline 60 s",
                ],
            ),
            (
                Dimension::Category,
                vec![fila("video", "Vídeo", 9_000, 100)],
                vec!["Categoría", "↓ bajada", "↑ subida", "Apps", "Equipos"],
            ),
            (
                Dimension::Protocol,
                vec![fila("tls", "tls", 9_000, 100)],
                vec!["Protocolo", "↓ bajada", "↑ subida", "Conexiones"],
            ),
            (
                Dimension::Process,
                vec![fila("1234", "firefox (1234)", 9_000, 100)],
                vec!["Proceso (pid)", "↓ bajada", "↑ subida", "Conexiones"],
            ),
        ];
        for (dimension, rows, columnas) in casos {
            let mut app = app_con_agrupacion(dimension, rows);
            let texto = dibujar(&mut app, 120, 30);
            for columna in columnas {
                assert!(
                    texto.contains(columna),
                    "la agrupación {} no muestra la columna {columna}",
                    dimension.label()
                );
            }
        }

        // La agrupación por equipo son las columnas de F3.
        let mut app = app_prueba();
        app.traffic.devices = vec![estadisticas(1, 1_000)];
        let texto = dibujar(&mut app, 120, 30);
        for columna in [
            "Dispositivo",
            "Tipo",
            "↓ in",
            "↑ out",
            "Total",
            "sparkline 60 s",
        ] {
            assert!(texto.contains(columna), "falta la columna {columna}");
        }
    }

    #[test]
    fn el_ranking_por_app_muestra_categoria_y_equipos() {
        let mut fila = fila("youtube", "YouTube", 9_000, 100);
        fila.subtitle = Some("Vídeo".to_string());
        let mut app = app_con_agrupacion(Dimension::App, vec![fila]);
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("YouTube"));
        assert!(texto.contains("Vídeo"));
    }

    #[test]
    fn el_ranking_por_destino_muestra_organizacion_y_pais() {
        let mut fila = fila("googlevideo.com", "googlevideo.com", 9_000, 100);
        fila.subtitle = Some("Google LLC · US".to_string());
        let mut app = app_con_agrupacion(Dimension::Destination, vec![fila]);
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("googlevideo.com"));
        assert!(texto.contains("Google LLC · US"));
    }

    #[test]
    fn el_ranking_por_categoria_cuenta_las_apps() {
        let mut categoria = fila("video", "Vídeo", 9_000, 100);
        categoria.subtitle = Some("video".to_string());
        let mut app = app_con_agrupacion(Dimension::Category, vec![categoria]);
        let mut youtube = fila("youtube", "YouTube", 5_000, 50);
        youtube.subtitle = Some("Vídeo".to_string());
        let mut netflix = fila("netflix", "Netflix", 4_000, 50);
        netflix.subtitle = Some("Vídeo".to_string());
        app.traffic
            .rankings
            .push(vista(Dimension::App, Window::Sixty, vec![youtube, netflix]));
        let filas = app.ranking_rows();
        assert_eq!(filas.len(), 1);
        assert_eq!(
            contar_apps_de_categoria(&app, &filas[0], Window::Sixty),
            Some(2),
            "cuenta las apps distintas de la categoría"
        );
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("Apps"));
    }

    #[test]
    fn el_pie_muestra_sin_identificar_y_la_visibilidad() {
        let app_rows = vec![fila("youtube", "YouTube", 9_000, 100)];
        let mut app = app_con_agrupacion(Dimension::App, app_rows);
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("sin identificar: 3 %"));
        assert!(texto.contains("visibilidad: propia + broadcast"));
    }

    #[test]
    fn el_pie_usa_el_porcentaje_de_la_ventana_activa() {
        let mut app =
            app_con_agrupacion(Dimension::App, vec![fila("youtube", "YouTube", 9_000, 100)]);
        app.traffic_window = Window::FiveMin;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("sin identificar: 4 %"));
        assert!(texto.contains("ventana: 5 min"));
    }

    #[test]
    fn sin_datos_en_la_ventana_muestra_un_mensaje_claro() {
        let mut app = app_prueba();
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("Sin tráfico en esta ventana"));
        assert!(
            texto.contains("sin identificar: 3 %"),
            "el pie siempre está"
        );
    }

    #[test]
    fn sin_captura_muestra_el_aviso_de_fase3() {
        let mut app = app_prueba();
        app.traffic.capture = CaptureStatus::default();
        app.traffic.updated_at = None;
        let texto = dibujar(&mut app, 100, 30);
        assert!(texto.contains("Captura deshabilitada"));
        assert!(texto.contains("Todavía no hay ningún snapshot"));
    }

    #[test]
    fn el_panel_quien_lo_usa_lista_equipos_con_porcentaje() {
        let mut app =
            app_con_agrupacion(Dimension::App, vec![fila("youtube", "YouTube", 9_000, 100)]);
        app.open_who_uses().expect("petición");
        app.set_who_uses(vec![
            DeviceShare {
                device_id: 1,
                label: "chromecast-sala".to_string(),
                bytes: 6_900,
                pct: 79.0,
            },
            DeviceShare {
                device_id: 99,
                label: "laptop-juan".to_string(),
                bytes: 1_800,
                pct: 21.0,
            },
        ]);
        let texto = dibujar(&mut app, 120, 34);
        assert!(texto.contains("¿Quién lo usa?"));
        assert!(texto.contains("YouTube"));
        assert!(texto.contains("chromecast-sala"));
        assert!(texto.contains("laptop-juan"));
        assert!(texto.contains("79 %"));
    }

    #[test]
    fn el_panel_quien_lo_usa_muestra_consultando_sin_respuesta() {
        let mut app =
            app_con_agrupacion(Dimension::App, vec![fila("youtube", "YouTube", 9_000, 100)]);
        app.open_who_uses().expect("petición");
        let texto = dibujar(&mut app, 120, 34);
        assert!(texto.contains("Consultando…"));
    }

    #[test]
    fn el_ranking_cabe_en_ochenta_columnas() {
        let mut app = app_con_agrupacion(
            Dimension::App,
            vec![
                fila("youtube", "YouTube", 9_000, 100),
                fila("netflix", "Netflix", 4_000, 50),
            ],
        );
        let texto = dibujar(&mut app, 80, 24);
        assert!(texto.contains("YouTube"));
        assert!(texto.contains("Equipos"));
        assert!(texto.contains("sin identificar:"));
    }

    #[test]
    fn el_titulo_indica_agrupacion_y_ventana() {
        let mut app = app_con_agrupacion(
            Dimension::Destination,
            vec![fila("googlevideo.com", "googlevideo.com", 9_000, 100)],
        );
        app.traffic_window = Window::FiveMin;
        app.rank_sort = crate::rankings::SortKey::Down;
        let texto = dibujar(&mut app, 140, 30);
        assert!(texto.contains("ranking por destino"));
        assert!(texto.contains("5 min"));
        assert!(texto.contains("↓"));
    }

    fn ranking_historico() -> crate::history::RankingResult {
        crate::history::RankingResult {
            window: crate::history::HistWindow::Day24,
            dimension: crate::history::Dimension::Destination,
            rows: vec![
                crate::history::HistRankRow {
                    key: "googlevideo.com".to_string(),
                    label: "googlevideo.com".to_string(),
                    subtitle: Some("Google LLC · US".to_string()),
                    device_id: None,
                    bytes_down: 14_200_000_000,
                    bytes_up: 210_000_000,
                    devices: 3,
                    connections: 42,
                },
                crate::history::HistRankRow {
                    key: "nflxvideo.net".to_string(),
                    label: "nflxvideo.net".to_string(),
                    subtitle: Some("Netflix · NL".to_string()),
                    device_id: None,
                    bytes_down: 9_600_000_000,
                    bytes_up: 95_000_000,
                    devices: 1,
                    connections: 12,
                },
            ],
            total_down: 38_400_000_000,
            total_up: 4_600_000_000,
            unidentified_pct: 4.0,
            closed_until: 1_760_000_040,
            gap_seconds: 8 * 3600 + 21 * 60,
        }
    }

    fn app_ventana_historica() -> App {
        let mut app = app_prueba();
        app.traffic_group = Dimension::Destination;
        app.traffic_window = Window::Day24;
        app.history.set_history_enabled(true);
        app.history.sync_context(
            crate::tui::app::Tab::Trafico,
            None,
            Dimension::Destination,
            Window::Day24,
        );
        app.history.traffic_ranking = Some(ranking_historico());
        app
    }

    #[test]
    fn la_ventana_historica_muestra_volumenes_conexiones_y_minutos_cerrados() {
        let mut app = app_ventana_historica();
        let texto = dibujar(&mut app, 140, 34);
        assert!(texto.contains("histórico"));
        assert!(texto.contains("↓ bajada"));
        assert!(texto.contains("Conexiones"));
        assert!(texto.contains("14.2 G"), "las cifras son volúmenes");
        assert!(texto.contains("42"), "la columna de conexiones");
        assert!(texto.contains("Minutos cerrados hasta"));
        assert!(
            texto.contains("8 h 21 min sin datos"),
            "los huecos de la ventana"
        );
        assert!(texto.contains("sin identificar: 4 %"));
    }

    #[test]
    fn la_ventana_historica_sin_datos_avisa_y_mientras_carga_lo_dice() {
        let mut app = app_prueba();
        app.traffic_group = Dimension::Destination;
        app.traffic_window = Window::Day24;
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("Cargando…"));
        let mut app = app_ventana_historica();
        app.history.traffic_ranking = Some(crate::history::RankingResult {
            window: crate::history::HistWindow::Day24,
            dimension: crate::history::Dimension::Destination,
            rows: Vec::new(),
            total_down: 0,
            total_up: 0,
            unidentified_pct: 0.0,
            closed_until: 1_760_000_040,
            gap_seconds: 0,
        });
        let texto = dibujar(&mut app, 120, 30);
        assert!(texto.contains("Sin datos en esta ventana"));
    }

    #[test]
    fn el_panel_quien_lo_usa_de_una_ventana_historica_sale_del_lector() {
        let mut app = app_ventana_historica();
        app.history.ask_who_uses(
            Dimension::Destination,
            "googlevideo.com".to_string(),
            "googlevideo.com".to_string(),
            Window::Day24,
        );
        let peticiones = app
            .history
            .history_pending_requests(crate::history::localtime::now_unix());
        let id = peticiones
            .iter()
            .find(|(_, consulta)| matches!(consulta, crate::history::HistoryQuery::WhoUses { .. }))
            .map(|(id, _)| *id)
            .expect("petición de quién lo usa");
        app.history.apply_history_response(
            id,
            &Ok(crate::history::HistoryResponse::WhoUses(vec![
                crate::rankings::DeviceShare {
                    device_id: 1,
                    label: "chromecast-sala".to_string(),
                    bytes: 6_900_000_000,
                    pct: 79.0,
                },
            ])),
        );
        let texto = dibujar(&mut app, 140, 40);
        assert!(texto.contains("¿Quién lo usa?"));
        assert!(texto.contains("chromecast-sala"));
        assert!(texto.contains("79 %"));
        assert!(texto.contains("6.9 G"));
    }
}
