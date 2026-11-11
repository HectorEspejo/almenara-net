//! Panel de detalle de equipo (master-detail): identidad de F4 (modelo, SO y su
//! fuente, huella DHCP abreviada, MAC privada), tráfico de F3, top 5 de apps y
//! destinos de la ventana de 5 min, clientes TLS distintos (JA4), conexiones
//! activas y servicios de F2.
//!
//! Todo el panel se dibuja como una única lista de líneas desplazable con j/k
//! cuando tiene el foco y el contenido no cabe (F4).

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::alerts::Level;
use crate::history::{AlertRow, AlertSummary, Inventory, SeenKind};
use crate::identify::mac::is_private;
use crate::identify::OsSource;
use crate::rankings::RankRow;
use crate::repo::devices::Device;
use crate::repo::DeviceService;
use crate::traffic::{formatear_bytes, formatear_bytes_por_segundo, ConnectionView};
use crate::tui::app::App;
use crate::tui::theme::{device_icon, Theme};
use crate::tui::traffic_state::FocusPanel;
use crate::tui::views::alerts::etiqueta_cuando;
use crate::tui::views::charts;

/// Dibuja el panel de detalle de un equipo.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let estilo_borde = if app.detail_focus == FocusPanel::Detalle {
        app.theme.accent
    } else {
        app.theme.border
    };
    let Some(device) = app.detail_device().cloned() else {
        let bloque = Block::bordered()
            .border_style(estilo_borde)
            .title(Span::styled("Detalle de equipo", app.theme.title));
        let interior = bloque.inner(area);
        frame.render_widget(bloque, area);
        frame.render_widget(
            Paragraph::new(Span::styled(
                "El equipo seleccionado ya no existe; pulsa Esc para cerrar.",
                app.theme.warning,
            )),
            interior,
        );
        return;
    };

    let vigilado = if device.watched { " · vigilado" } else { "" };
    let titulo = format!(
        "Detalle: {} ({}){vigilado}",
        device.display_name(),
        device.ip
    );
    let bloque = Block::bordered()
        .border_style(estilo_borde)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let lineas = construir_lineas(app, &device, interior.width);

    // Desplazamiento del panel derecho cuando no cabe (j/k con el foco).
    let maximo = lineas.len().saturating_sub(usize::from(interior.height));
    app.detail_max_scroll = maximo;
    app.detail_scroll = app.detail_scroll.min(maximo);
    let desplazamiento = u16::try_from(app.detail_scroll).unwrap_or(u16::MAX);

    frame.render_widget(
        Paragraph::new(lineas)
            .style(app.theme.normal)
            .scroll((desplazamiento, 0)),
        interior,
    );
}

fn construir_lineas(
    app: &App,
    device: &crate::repo::devices::Device,
    ancho: u16,
) -> Vec<Line<'static>> {
    let mut lineas: Vec<Line> = Vec::new();

    // Identidad y estado.
    let (icono, estilo_icono) = device_icon(device, &app.theme);
    let estado = if device.is_online {
        "online"
    } else {
        "offline"
    };
    lineas.push(Line::from(vec![
        Span::styled(icono, estilo_icono),
        Span::styled(format!(" {} ", device.display_name()), app.theme.accent),
        Span::styled(format!("({})", device.ip), app.theme.normal),
        Span::styled(
            format!(" · {estado}"),
            if device.is_online {
                app.theme.online
            } else {
                app.theme.offline
            },
        ),
        Span::styled(format!(" (visto {})", device.last_seen), app.theme.dim),
    ]));
    let tipo = crate::classify::DeviceType::from_str(device.effective_device_type())
        .unwrap_or(crate::classify::DeviceType::Unknown);
    let vendor = device.vendor.clone().unwrap_or_else(|| "?".to_string());
    let modelo = device.model.clone().unwrap_or_else(|| "—".to_string());
    lineas.push(Line::from(vec![
        Span::styled(vendor, app.theme.normal),
        Span::styled(format!(" · {} · ", tipo.label()), app.theme.dim),
        Span::styled(
            device.os_family.clone().unwrap_or_else(|| "—".to_string()),
            app.theme.normal,
        ),
        Span::styled(
            format!(
                " (fuente: {})",
                os_source_label(device.os_source.as_deref())
            ),
            app.theme.dim,
        ),
        Span::styled(format!(" · modelo: {modelo}"), app.theme.dim),
    ]));
    let interfaz = app
        .interfaces
        .iter()
        .find(|interfaz| interfaz.id == device.interface_id)
        .map(|interfaz| interfaz.name.clone())
        .unwrap_or_else(|| "?".to_string());
    let mac = mac_abreviada(&device.mac);
    let privacidad = if is_private(&device.mac) {
        Span::styled(" (MAC privada)", app.theme.warning)
    } else {
        Span::styled("", app.theme.dim)
    };
    lineas.push(Line::from(vec![
        Span::styled("MAC: ", app.theme.accent),
        Span::styled(mac, app.theme.normal),
        privacidad,
        Span::styled(format!(" · interfaz: {interfaz}"), app.theme.dim),
    ]));
    let mut dhcp = Line::from(vec![Span::styled("DHCP: ", app.theme.accent)]);
    match device.dhcp_fingerprint.as_deref() {
        Some(huella) => {
            dhcp.spans.push(Span::styled(
                format!("huella {}", huella_dhcp_abreviada(huella)),
                app.theme.normal,
            ));
        }
        None => dhcp.spans.push(Span::styled("sin huella", app.theme.dim)),
    }
    if let Some(nombre) = device.dhcp_hostname.as_deref() {
        dhcp.spans
            .push(Span::styled(format!(" · nombre «{nombre}»"), app.theme.dim));
    }
    if let Some(proveedor) = device.dhcp_vendor.as_deref() {
        dhcp.spans.push(Span::styled(
            format!(" · proveedor «{proveedor}»"),
            app.theme.dim,
        ));
    }
    lineas.push(dhcp);
    lineas.push(Line::from(""));

    // Alertas de F6: últimas del equipo, vigilado, aprendizaje y silencios (§6).
    lineas.extend(bloque_alertas(app, device, ancho));
    lineas.push(Line::from(""));

    // Histórico de F5: tráfico y presencia sobre el mismo eje, rejilla de
    // presencia de 7 días e inventario de lo visto en el equipo.
    lineas.extend(bloque_historico(app, ancho));
    lineas.push(Line::from(""));

    // Tráfico (F3).
    lineas.push(Line::from(Span::styled("Tráfico", app.theme.accent)));
    let estadisticas = app.traffic.device_stats(device.id);
    match &estadisticas {
        Some(estadisticas) => {
            let ancho_serie = usize::from(ancho).saturating_sub(12).max(10);
            let serie_60 = sumar_series(&estadisticas.series_60s_in, &estadisticas.series_60s_out);
            let serie_5min =
                sumar_series(&estadisticas.series_5min_in, &estadisticas.series_5min_out);
            lineas.push(Line::from(vec![
                Span::styled("  60 s: ", app.theme.dim),
                Span::styled(ultimos(&serie_60, ancho_serie), app.theme.accent),
            ]));
            lineas.push(Line::from(vec![
                Span::styled("  ↓ ", app.theme.online),
                Span::styled(
                    formatear_bytes_por_segundo(estadisticas.rate_in),
                    app.theme.normal,
                ),
                Span::styled("   ↑ ", app.theme.accent),
                Span::styled(
                    formatear_bytes_por_segundo(estadisticas.rate_out),
                    app.theme.normal,
                ),
                Span::styled("   pico ", app.theme.dim),
                Span::styled(
                    formatear_bytes_por_segundo(estadisticas.peak_bps),
                    app.theme.normal,
                ),
            ]));
            lineas.push(Line::from(vec![
                Span::styled("  5 min: ", app.theme.dim),
                Span::styled(ultimos(&serie_5min, ancho_serie), app.theme.accent),
            ]));
            let puertos = estadisticas
                .top_ports
                .iter()
                .take(5)
                .map(|puerto| {
                    format!(
                        "{}/{} {}",
                        puerto.port,
                        puerto.protocol.as_str(),
                        formatear_bytes(puerto.bytes)
                    )
                })
                .collect::<Vec<_>>();
            let resumen = if puertos.is_empty() {
                "—".to_string()
            } else {
                puertos.join(" · ")
            };
            lineas.push(Line::from(vec![
                Span::styled("  Top puertos (5): ", app.theme.dim),
                Span::styled(resumen, app.theme.normal),
            ]));
        }
        None => {
            lineas.push(Line::from(Span::styled(
                "  Sin tráfico observado todavía para este equipo",
                app.theme.dim,
            )));
        }
    }
    lineas.push(Line::from(""));

    // Top 5 de apps y destinos (ventana de 5 min).
    let ranking = app.traffic.device_ranking(device.id);
    let (apps, destinos, cabecera_apps) = match ranking {
        Some(ranking) if !ranking.apps.is_empty() || !ranking.destinations.is_empty() => (
            ranking.apps.iter().take(5).cloned().collect::<Vec<_>>(),
            ranking
                .destinations
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>(),
            "Top apps (5 min)",
        ),
        _ => {
            let (apps, destinos) = resumen_desde_conexiones(app, device);
            (apps, destinos, "Top apps (conexiones activas)")
        }
    };
    let ancho_mitad = (usize::from(ancho).saturating_sub(4) / 2).max(12);
    lineas.push(Line::from(vec![
        Span::styled(cabecera_apps, app.theme.accent),
        Span::styled(
            format!(
                "{}{}",
                " ".repeat(ancho_mitad.saturating_sub(18)),
                "Top destinos"
            ),
            app.theme.accent,
        ),
    ]));
    let total_apps: u64 = apps.iter().map(RankRow::total).sum();
    let total_destinos: u64 = destinos.iter().map(RankRow::total).sum();
    for posicion in 0..5 {
        let izquierda = fila_par(app, apps.get(posicion), total_apps, ancho_mitad);
        let derecha = fila_par(app, destinos.get(posicion), total_destinos, ancho_mitad);
        lineas.push(Line::from(vec![izquierda, derecha]));
    }
    lineas.push(Line::from(""));

    // Clientes TLS distintos (JA4).
    let (ja4, distintos) = clientes_tls(app, device);
    let texto_ja4 = match ja4.first() {
        Some(huella) => {
            let mut texto = format!("{huella} ({distintos} distintos)");
            if let Some(segunda) = ja4.get(1) {
                texto.push_str(&format!(" · {segunda}"));
            }
            texto
        }
        None => "—".to_string(),
    };
    lineas.push(Line::from(vec![
        Span::styled("Clientes TLS (JA4): ", app.theme.accent),
        Span::styled(texto_ja4, app.theme.normal),
    ]));

    // Conexiones activas (F3).
    let conexiones = app.traffic.connections_of_ip(&device.ip);
    let titulo_conexiones = format!("Conexiones activas ({})", conexiones.len());
    lineas.push(Line::from(Span::styled(
        titulo_conexiones,
        app.theme.accent,
    )));
    if conexiones.is_empty() {
        lineas.push(Line::from(Span::styled(
            "  (sin conexiones)",
            app.theme.dim,
        )));
    } else {
        for conexion in conexiones.iter().take(5) {
            lineas.push(linea_conexion(app, device, conexion));
        }
    }

    // Puertos (F2 + F6): estado abierto o cerrado con `closed_at` (§7.12).
    lineas.extend(bloque_puertos(app, ancho));

    lineas
}

/// Bloque «Alertas» del detalle de un equipo (§6, mockup 4).
///
/// Pinta las cinco últimas alertas del equipo, cuántas quedan sin ver, si está
/// vigilado (`p`), el estado del aprendizaje y sus silencios vigentes.
fn bloque_alertas(app: &App, device: &Device, ancho: u16) -> Vec<Line<'static>> {
    let mut lineas: Vec<Line> = Vec::new();
    let resumen = app
        .alerts
        .device_summary
        .as_ref()
        .filter(|_resumen| app.alerts.device_summary_for == Some(device.id));
    let sin_ver = resumen
        .map(|resumen| {
            resumen
                .unseen
                .important
                .saturating_add(resumen.unseen.warning)
                .saturating_add(resumen.unseen.info)
        })
        .unwrap_or(0);
    let texto_sin_ver = match resumen {
        None => "cargando…".to_string(),
        Some(_) if sin_ver == 0 => "ninguna sin ver".to_string(),
        Some(_) => format!("{sin_ver} sin ver"),
    };
    let izquierda = format!("Alertas · {texto_sin_ver}");
    let derecha = format!("[p] vigilado: {}", if device.watched { "sí" } else { "no" });
    let hueco = usize::from(ancho)
        .saturating_sub(izquierda.chars().count() + derecha.chars().count())
        .max(2);
    lineas.push(Line::from(vec![
        Span::styled(izquierda, app.theme.accent),
        Span::styled(" ".repeat(hueco), app.theme.dim),
        Span::styled(
            derecha,
            if device.watched {
                app.theme.accent
            } else {
                app.theme.dim
            },
        ),
    ]));

    match resumen {
        None => lineas.push(Line::from(Span::styled(
            "  (cargando las alertas del equipo)",
            app.theme.dim,
        ))),
        Some(resumen) => {
            if resumen.recent.is_empty() {
                lineas.push(Line::from(Span::styled(
                    "  (sin alertas de este equipo)",
                    app.theme.dim,
                )));
            } else {
                let ahora = crate::history::localtime::now_unix();
                for alerta in resumen.recent.iter().take(5) {
                    lineas.push(linea_alerta_detalle(alerta, &app.theme, ahora, ancho));
                }
            }
            lineas.push(linea_aprendizaje(app, resumen, ancho));
            lineas.push(linea_silencios(resumen, &app.theme, ancho));
        }
    }
    lineas
}

/// Línea de una alerta del equipo en el detalle: marca de vista, cuándo, nivel
/// y título, sin depender solo del color (§6).
fn linea_alerta_detalle(alerta: &AlertRow, theme: &Theme, ahora: i64, ancho: u16) -> Line<'static> {
    let marca = if alerta.seen { "  " } else { "● " };
    let cuando = etiqueta_cuando(alerta.last_at, ahora);
    let badge = alerta.level.badge();
    let mut titulo = alerta.title.clone();
    if alerta.count > 1 {
        titulo.push_str(&format!(" ×{}", alerta.count));
    }
    if alerta.resolved {
        titulo.push_str(" · resuelta");
    }
    let fijo = 2 + marca.chars().count() + cuando.chars().count() + 2 + badge.chars().count() + 2;
    let disponible = usize::from(ancho).saturating_sub(fijo).max(8);
    let titulo = recortar(&titulo, disponible);
    let estilo_titulo = if alerta.seen {
        theme.normal
    } else {
        theme.normal.add_modifier(Modifier::BOLD)
    };
    Line::from(vec![
        Span::styled(
            format!("  {marca}"),
            if alerta.seen { theme.dim } else { theme.accent },
        ),
        Span::styled(cuando, theme.dim),
        Span::styled("  ", theme.dim),
        Span::styled(badge, estilo_nivel(theme, alerta.level)),
        Span::styled(format!("  {titulo}"), estilo_titulo),
    ])
}

/// Estilo del nivel de una alerta.
fn estilo_nivel(theme: &Theme, nivel: Level) -> Style {
    match nivel {
        Level::Important => theme.error,
        Level::Warning => theme.warning,
        Level::Info => theme.normal,
    }
}

/// Línea «Lo nuevo de este equipo» con el estado del aprendizaje (§7.3).
fn linea_aprendizaje(app: &App, resumen: &AlertSummary, ancho: u16) -> Line<'static> {
    let dias_config = app.config.alerts.learning_days;
    let mut texto = String::from("Lo nuevo de este equipo: ");
    match &resumen.learning {
        None => texto.push_str("sin datos de aprendizaje todavía"),
        Some(aprendizaje) => match aprendizaje.learned_at {
            Some(instante) => {
                let unix = instante
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duracion| duracion.as_secs() as i64)
                    .unwrap_or(0);
                let fecha = crate::history::LocalDay::from_unix(unix).label_corto();
                texto.push_str(&format!(
                    "aprendido el {fecha} ({} días con datos)",
                    aprendizaje.data_days
                ));
            }
            None if dias_config == 0 => {
                texto.push_str("sin aprendizaje ([alerts].learning_days = 0)")
            }
            None => texto.push_str(&format!(
                "aprendiendo ({} de {dias_config} días con datos)",
                aprendizaje.data_days
            )),
        },
    }
    Line::from(Span::styled(
        recortar(&texto, usize::from(ancho)),
        app.theme.dim,
    ))
}

/// Línea «Silencios» del detalle: regla y hasta cuándo (§7.6).
fn linea_silencios(resumen: &AlertSummary, theme: &Theme, ancho: u16) -> Line<'static> {
    let ahora = crate::history::localtime::now_unix();
    let texto = if resumen.mutes.is_empty() {
        "Silencios: ninguno".to_string()
    } else {
        let mut partes = Vec::new();
        for silencio in resumen.mutes.iter().take(2) {
            let hasta = match silencio.until {
                None => "siempre".to_string(),
                Some(unix) => etiqueta_cuando(unix, ahora),
            };
            partes.push(format!("{} hasta {hasta}", silencio.rule.name()));
        }
        let mut texto = format!("Silencios: {}", partes.join(" · "));
        if resumen.mutes.len() > 2 {
            texto.push_str(&format!(" (+{})", resumen.mutes.len() - 2));
        }
        texto
    };
    Line::from(Span::styled(
        recortar(&texto, usize::from(ancho)),
        theme.dim,
    ))
}

/// Bloque «Histórico» del detalle: tráfico y presencia sobre el mismo eje
/// (24 h ⇄ 7 días con w), rejilla de presencia de 7 días e inventario.
fn bloque_historico(app: &App, ancho: u16) -> Vec<Line<'static>> {
    let mut lineas: Vec<Line> = Vec::new();
    let rango = app.history.detail_range;
    let etiqueta = rango.label();
    let ahora = crate::history::localtime::now_unix();

    if !app.config.history.enabled {
        lineas.push(Line::from(vec![
            Span::styled("Histórico · ", app.theme.accent),
            Span::styled("desactivado ([history] enabled = false)", app.theme.warning),
        ]));
        lineas.push(Line::from(Span::styled(
            "  La presencia se calcula con los eventos, que siguen activos",
            app.theme.dim,
        )));
    } else {
        let (bajada, subida) = app
            .history
            .detail_series
            .as_ref()
            .map(|serie| (serie.total_down, serie.total_up))
            .unwrap_or((0, 0));
        lineas.push(Line::from(vec![
            Span::styled(format!("Histórico · {etiqueta}"), app.theme.accent),
            Span::styled(
                format!(
                    "   ↓ {} · ↑ {}",
                    formatear_bytes(bajada),
                    formatear_bytes(subida)
                ),
                app.theme.normal,
            ),
            Span::styled("   [w] 24 h ⇄ 7 días", app.theme.dim),
        ]));

        let ancho_serie = ancho.saturating_sub(14).max(10);
        let mut fila_trafico = vec![Span::styled("  tráfico    ", app.theme.dim)];
        match app.history.detail_series.as_ref() {
            Some(serie) => {
                fila_trafico.extend(charts::fila_trafico(serie, ancho_serie, &app.theme).spans)
            }
            None if app.history.detalle_cargando() => {
                fila_trafico.push(Span::styled("Cargando…", app.theme.dim))
            }
            None => fila_trafico.push(Span::styled("sin datos en el rango", app.theme.dim)),
        }
        lineas.push(Line::from(fila_trafico));

        let tramos = app.history.detail_presence.as_deref().unwrap_or(&[]);
        let mut fila_presencia = vec![Span::styled("  presencia  ", app.theme.dim)];
        fila_presencia
            .extend(charts::fila_presencia(tramos, rango, ahora, ancho_serie, &app.theme).spans);
        lineas.push(Line::from(fila_presencia));

        if let Some(error) = app.history.error_actual() {
            lineas.push(Line::from(Span::styled(
                format!("  Error del histórico: {error}"),
                app.theme.warning,
            )));
        }

        if let Some(serie) = app.history.detail_series.as_ref() {
            let eje = charts::eje_fechas(serie, ancho_serie, &app.theme);
            let mut spans = vec![Span::styled(" ".repeat(14), app.theme.dim)];
            spans.extend(eje.spans);
            lineas.push(Line::from(spans));
        }
        lineas.push(Line::from(""));
    }

    // La presencia no depende de [history].enabled: sale de los eventos de F1.
    let tramos = app.history.detail_presence.as_deref().unwrap_or(&[]);
    lineas.push(Line::from(Span::styled(
        "Presencia · 7 días",
        app.theme.accent,
    )));
    lineas.extend(charts::rejilla_presencia(tramos, ahora, &app.theme));
    lineas.push(Line::from(Span::styled(
        charts::LEYENDA_PRESENCIA,
        app.theme.dim,
    )));
    lineas.push(Line::from(""));

    lineas.extend(bloque_inventario(app, rango));
    lineas
}

/// Bloque «Visto en este equipo»: recuentos por tipo, lo nuevo de los últimos
/// 7 días, la fecha de inicio y los puertos abiertos.
fn bloque_inventario(app: &App, _rango: crate::history::Range) -> Vec<Line<'static>> {
    let mut lineas: Vec<Line> = Vec::new();
    let Some(inventario) = app.history.detail_inventory.as_ref() else {
        let mensaje = if app.config.history.enabled {
            "Visto en este equipo: Cargando…"
        } else {
            "Visto en este equipo: inventario desactivado ([history] enabled = false)"
        };
        lineas.push(Line::from(Span::styled(mensaje, app.theme.dim)));
        return lineas;
    };
    let desde = inventario
        .since
        .as_deref()
        .and_then(crate::history::localtime::unix_de_rfc3339)
        .map(|unix| crate::history::LocalDay::from_unix(unix).label_corto());
    let titulo = match desde {
        Some(desde) => format!("Visto en este equipo (desde {desde})"),
        None => "Visto en este equipo".to_string(),
    };
    lineas.push(Line::from(Span::styled(titulo, app.theme.accent)));

    let nuevas = apps_nuevas(inventario, crate::history::localtime::now_unix());
    let texto_nuevas = if nuevas.is_empty() {
        "—".to_string()
    } else {
        nuevas.join(" · ")
    };
    lineas.push(Line::from(vec![
        Span::styled(
            format!("  Apps ({})", inventario.count(SeenKind::App)),
            app.theme.normal,
        ),
        Span::styled(" · nuevas en 7 días: ", app.theme.dim),
        Span::styled(texto_nuevas, app.theme.accent),
    ]));
    lineas.push(Line::from(vec![
        Span::styled(
            format!("  Organizaciones ({})", inventario.count(SeenKind::Org)),
            app.theme.normal,
        ),
        Span::styled(": ", app.theme.dim),
        Span::styled(lista_corta(&inventario.orgs, 5), app.theme.normal),
    ]));
    let paises = inventario
        .countries
        .iter()
        .map(|pais| pais.key.clone())
        .collect::<Vec<_>>();
    let texto_paises = if paises.is_empty() {
        "—".to_string()
    } else {
        paises.join(" ")
    };
    lineas.push(Line::from(vec![
        Span::styled(
            format!("  Países ({})", inventario.count(SeenKind::Country)),
            app.theme.normal,
        ),
        Span::styled(format!(": {texto_paises}"), app.theme.normal),
        Span::styled(
            format!(" · Clientes TLS (JA4): {}", inventario.count(SeenKind::Ja4)),
            app.theme.dim,
        ),
    ]));
    let puertos = if inventario.ports.is_empty() {
        "—".to_string()
    } else {
        inventario
            .ports
            .iter()
            .take(6)
            .map(|puerto| {
                let desde = crate::history::localtime::unix_de_rfc3339(&puerto.first_seen)
                    .map(|unix| crate::history::LocalDay::from_unix(unix).label_corto());
                match (puerto.service.as_deref(), desde) {
                    (Some(servicio), Some(desde)) => {
                        format!(
                            "{}/{} {servicio} (desde {desde})",
                            puerto.port, puerto.protocol
                        )
                    }
                    (Some(servicio), None) => {
                        format!("{}/{} {servicio}", puerto.port, puerto.protocol)
                    }
                    (None, Some(desde)) => {
                        format!("{}/{} (desde {desde})", puerto.port, puerto.protocol)
                    }
                    (None, None) => format!("{}/{}", puerto.port, puerto.protocol),
                }
            })
            .collect::<Vec<_>>()
            .join(" · ")
    };
    lineas.push(Line::from(vec![
        Span::styled("  Puertos abiertos: ", app.theme.normal),
        Span::styled(puertos, app.theme.normal),
    ]));
    lineas
}

/// Apps vistas por primera vez en los últimos 7 días («Temu (ayer)»).
fn apps_nuevas(inventario: &Inventory, ahora: i64) -> Vec<String> {
    let limite = ahora - 7 * 86_400;
    inventario
        .apps
        .iter()
        .filter_map(|app| {
            let unix = crate::history::localtime::unix_de_rfc3339(&app.first_seen)?;
            (unix >= limite).then(|| format!("{} ({})", app.label, etiqueta_novedad(unix, ahora)))
        })
        .take(3)
        .collect()
}

/// Etiqueta de una novedad respecto a ahora: hoy, ayer, hace N días o la fecha.
fn etiqueta_novedad(unix: i64, ahora: i64) -> String {
    let dias = (ahora - unix).max(0) / 86_400;
    match dias {
        0 => "hoy".to_string(),
        1 => "ayer".to_string(),
        2..=6 => format!("hace {dias} días"),
        _ => crate::history::LocalDay::from_unix(unix).label_corto(),
    }
}

/// Lista corta de claves («Meta, Apple, Google…»).
fn lista_corta(filas: &[crate::history::SeenRow], maximo: usize) -> String {
    if filas.is_empty() {
        return "—".to_string();
    }
    let mut texto = filas
        .iter()
        .take(maximo)
        .map(|fila| fila.label.clone())
        .collect::<Vec<_>>()
        .join(", ");
    if filas.len() > maximo {
        texto.push('…');
    }
    texto
}

/// Identidad de SO a partir de la señal persistida.
pub fn os_source_label(valor: Option<&str>) -> String {
    valor
        .and_then(OsSource::from_str)
        .map(|fuente| fuente.label().to_string())
        .unwrap_or_else(|| "desconocida".to_string())
}

/// Abrevia una MAC como «5a:1c:…:9e».
pub fn mac_abreviada(mac: &str) -> String {
    let octetos: Vec<&str> = mac.split(':').collect();
    if octetos.len() <= 3 {
        return mac.to_string();
    }
    format!(
        "{}:{}:…:{}",
        octetos[0],
        octetos[1],
        octetos[octetos.len() - 1]
    )
}

/// Abrevia una huella DHCP (opción 55) a los primeros valores.
pub fn huella_dhcp_abreviada(huella: &str) -> String {
    let valores: Vec<&str> = huella
        .split(',')
        .map(str::trim)
        .filter(|valor| !valor.is_empty())
        .collect();
    if valores.len() <= 8 {
        return huella.trim().to_string();
    }
    format!("{},…", valores[..8].join(","))
}

fn sumar_series(entrada: &[u64; 60], salida: &[u64; 60]) -> Vec<u64> {
    entrada
        .iter()
        .zip(salida.iter())
        .map(|(a, b)| a.saturating_add(*b))
        .collect()
}

/// Últimos n puntos de la serie, dibujados como sparkline.
fn ultimos(serie: &[u64], n: usize) -> String {
    let inicio = serie.len().saturating_sub(n.max(1));
    crate::traffic::sparkline(&serie[inicio..])
}

/// Número máximo de puertos que se listan en el detalle.
const MAX_PUERTOS_DETALLE: usize = 10;

/// Bloque «Puertos» (F2 + F6): estado ABIERTO o CERRADO con `closed_at` (§7.12).
fn bloque_puertos(app: &App, ancho: u16) -> Vec<Line<'static>> {
    let mut lineas: Vec<Line> = Vec::new();
    lineas.push(Line::from(Span::styled("Puertos", app.theme.accent)));
    let servicios = app.detail_services();
    if servicios.is_empty() {
        lineas.push(Line::from(Span::styled(
            "  (sin puertos conocidos)",
            app.theme.dim,
        )));
        return lineas;
    }
    let ahora = crate::history::localtime::now_unix();
    for servicio in servicios.iter().take(MAX_PUERTOS_DETALLE) {
        lineas.push(linea_puerto(servicio, &app.theme, ahora, ancho));
    }
    if servicios.len() > MAX_PUERTOS_DETALLE {
        lineas.push(Line::from(Span::styled(
            format!("  … y {} más", servicios.len() - MAX_PUERTOS_DETALLE),
            app.theme.dim,
        )));
    }
    lineas
}

/// Línea de un puerto: servicio, protocolo y estado (abierto o cerrado).
fn linea_puerto(servicio: &DeviceService, theme: &Theme, ahora: i64, ancho: u16) -> Line<'static> {
    let nombre = servicio.service.as_deref().unwrap_or("—");
    let prefijo = format!(
        "  {}/{} {nombre:<8} ",
        servicio.port,
        servicio.protocol.as_str()
    );
    let (estado, estilo) = match servicio.closed_at.as_deref() {
        Some(cerrado) => {
            let mut texto = match crate::history::localtime::unix_de_rfc3339(cerrado) {
                Some(unix) => format!("cerrado el {}", fecha_corta(unix, ahora)),
                None => "cerrado".to_string(),
            };
            if let Some(unix) = crate::history::localtime::unix_de_rfc3339(&servicio.last_seen) {
                texto.push_str(&format!(
                    "; abierto por última vez el {}",
                    fecha_corta(unix, ahora)
                ));
            }
            (texto, theme.dim)
        }
        None => {
            let texto = match crate::history::localtime::unix_de_rfc3339(&servicio.first_seen) {
                Some(unix) => format!("abierto desde {}", fecha_corta(unix, ahora)),
                None => "abierto".to_string(),
            };
            (texto, theme.normal)
        }
    };
    let disponible = usize::from(ancho)
        .saturating_sub(prefijo.chars().count())
        .max(8);
    Line::from(vec![
        Span::styled(prefijo, theme.normal),
        Span::styled(recortar(&estado, disponible), estilo),
    ])
}

/// Fecha corta de un puerto: relativa («hoy 08:53», «lun 12:30») o «4 nov».
fn fecha_corta(unix: i64, ahora: i64) -> String {
    let dias = ahora.saturating_sub(unix) / 86_400;
    if (0..=6).contains(&dias) {
        etiqueta_cuando(unix, ahora)
    } else {
        crate::history::LocalDay::from_unix(unix).label_corto()
    }
}

/// Celda izquierda o derecha de la tabla de dos columnas del detalle.
fn fila_par(app: &App, fila: Option<&RankRow>, total: u64, ancho: usize) -> Span<'static> {
    match fila {
        Some(fila) => {
            let porcentaje = if total > 0 {
                (fila.total() as f64 * 100.0 / total as f64).round() as u32
            } else {
                0
            };
            let etiqueta = if fila.label.trim().is_empty() {
                fila.key.clone()
            } else {
                fila.label.clone()
            };
            let ancho_etiqueta = ancho.saturating_sub(16).max(6);
            let etiqueta = recortar(&etiqueta, ancho_etiqueta);
            Span::styled(
                format!(
                    "  {etiqueta:<ancho_etiqueta$} {:>8} {porcentaje:>3} %",
                    formatear_bytes(fila.total()),
                ),
                app.theme.normal,
            )
        }
        None => Span::styled("", app.theme.normal),
    }
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

/// Top de apps y destinos calculado con las conexiones activas (respaldo).
fn resumen_desde_conexiones(
    app: &App,
    device: &crate::repo::devices::Device,
) -> (Vec<RankRow>, Vec<RankRow>) {
    use std::collections::HashMap;
    let mut apps: HashMap<String, (String, u64)> = HashMap::new();
    let mut destinos: HashMap<String, (String, u64)> = HashMap::new();
    for conexion in app.traffic.connections_of_ip(&device.ip) {
        let bytes = conexion.bytes_in.saturating_add(conexion.bytes_out);
        if bytes == 0 {
            continue;
        }
        let app = conexion.app_label();
        let entrada = apps.entry(app.clone()).or_insert_with(|| (app.clone(), 0));
        entrada.1 = entrada.1.saturating_add(bytes);
        let (_, _, servidor) = crate::tui::traffic_state::lados_conexion(conexion);
        let destino = conexion
            .label
            .as_ref()
            .and_then(|etiqueta| etiqueta.server_name.clone())
            .unwrap_or_else(|| servidor.ip.to_string());
        let entrada = destinos
            .entry(destino.clone())
            .or_insert_with(|| (destino.clone(), 0));
        entrada.1 = entrada.1.saturating_add(bytes);
    }
    let mut apps: Vec<RankRow> = apps
        .into_values()
        .map(|(etiqueta, bytes)| rank_row(etiqueta, bytes))
        .collect();
    let mut destinos: Vec<RankRow> = destinos
        .into_values()
        .map(|(etiqueta, bytes)| rank_row(etiqueta, bytes))
        .collect();
    apps.sort_by(|a, b| {
        b.total()
            .cmp(&a.total())
            .then_with(|| a.label.cmp(&b.label))
    });
    destinos.sort_by(|a, b| {
        b.total()
            .cmp(&a.total())
            .then_with(|| a.label.cmp(&b.label))
    });
    apps.truncate(5);
    destinos.truncate(5);
    (apps, destinos)
}

fn rank_row(etiqueta: String, bytes: u64) -> RankRow {
    RankRow {
        key: etiqueta.clone(),
        label: etiqueta,
        subtitle: None,
        device_id: None,
        bytes_down: bytes,
        bytes_up: 0,
        devices: 1,
        connections: 0,
        series_60s: [0; 60],
    }
}

/// Huellas JA4 distintas del equipo (de sus conexiones activas).
fn clientes_tls(app: &App, device: &crate::repo::devices::Device) -> (Vec<String>, usize) {
    let mut huellas: Vec<String> = Vec::new();
    for conexion in app.traffic.connections_of_ip(&device.ip) {
        if conexion.device_id != Some(device.id)
            && conexion.origin.device_id != Some(device.id)
            && conexion.destination.device_id != Some(device.id)
        {
            continue;
        }
        if let Some(huella) = conexion
            .label
            .as_ref()
            .and_then(|etiqueta| etiqueta.ja4.clone())
        {
            if !huellas.contains(&huella) {
                huellas.push(huella);
            }
        }
    }
    let distintos = huellas.len();
    (huellas, distintos)
}

/// Línea compacta de una conexión activa del equipo.
fn linea_conexion(
    app: &App,
    device: &crate::repo::devices::Device,
    conexion: &ConnectionView,
) -> Line<'static> {
    let (_, cliente, servidor) = crate::tui::traffic_state::lados_conexion(conexion);
    let es_cliente = cliente.ip.to_string() == device.ip;
    let otro = if es_cliente {
        conexion
            .label
            .as_ref()
            .and_then(|etiqueta| etiqueta.server_name.clone())
            .unwrap_or_else(|| servidor.ip.to_string())
    } else {
        cliente.ip.to_string()
    };
    let flecha = if es_cliente { "→" } else { "←" };
    Line::from(vec![
        Span::styled(format!("  {flecha} {otro}  "), app.theme.normal),
        Span::styled(
            format!(
                "{} · {} · {}",
                conexion.app_label(),
                conexion.state_label(),
                conexion.age_label()
            ),
            app.theme.dim,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::aggregate::DeviceTraffic;
    use crate::capture::{ConnectionKey, Endpoint, Protocol as CaptureProtocol};
    use crate::config::Config;
    use crate::inference::{DestinationInfo, DestinationKind, FlowLabel};
    use crate::rankings::{RankRow, Window};
    use crate::repo::devices::Device;
    use crate::repo::{DeviceService, Protocol as RepoProtocol};
    use crate::traffic::{ConnectionView, DeviceRankingView, EndpointView};
    use crate::tui::app::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba")
    }

    fn dispositivo() -> Device {
        Device {
            id: 1,
            mac: "5a:1c:2d:3e:4f:9e".to_string(),
            ip: "192.168.1.57".to_string(),
            hostname: Some("iPhone-Marta".to_string()),
            vendor: Some("Apple".to_string()),
            interface_id: 1,
            device_type: "mobile".to_string(),
            is_online: true,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:03Z".to_string(),
            alias: None,
            notes: None,
            os_family: Some("ios".to_string()),
            device_type_manual: None,
            last_fingerprint: None,
            model: Some("iPhone15,3".to_string()),
            dhcp_fingerprint: Some("1,121,3,6,15,108,114,119,252".to_string()),
            dhcp_vendor: Some("android-dhcp-13".to_string()),
            dhcp_hostname: Some("iPhone-de-Marta".to_string()),
            user_agent: None,
            os_source: Some("model".to_string()),
            watched: false,
        }
    }

    fn estadisticas() -> DeviceTraffic {
        DeviceTraffic {
            device_id: 1,
            bytes_in: 120_000,
            bytes_out: 45_000,
            packets_in: 10,
            packets_out: 5,
            rate_in: 120_000,
            rate_out: 45_000,
            peak_bps: 410_000,
            series_60s_in: [1; 60],
            series_60s_out: [0; 60],
            series_5min_in: [1; 60],
            series_5min_out: [0; 60],
            top_ports: vec![crate::capture::aggregate::PortStat {
                port: 443,
                protocol: CaptureProtocol::Tcp,
                bytes: 1_200_000,
            }],
        }
    }

    fn fila(clave: &str, etiqueta: &str, bytes: u64) -> RankRow {
        RankRow {
            key: clave.to_string(),
            label: etiqueta.to_string(),
            subtitle: None,
            device_id: None,
            bytes_down: bytes,
            bytes_up: 0,
            devices: 1,
            connections: 1,
            series_60s: [0; 60],
        }
    }

    fn conexion_ja4(huella: &str) -> ConnectionView {
        let mut etiqueta = FlowLabel::empty(ip("17.253.1.1"));
        etiqueta.client_is_src = Some(true);
        etiqueta.server_name = Some("icloud.com".to_string());
        etiqueta.ja4 = Some(huella.to_string());
        etiqueta.destination = DestinationInfo {
            key: "icloud.com".to_string(),
            label: "icloud.com".to_string(),
            org: Some("Apple Inc.".to_string()),
            country: Some("US".to_string()),
            kind: DestinationKind::Domain,
        };
        ConnectionView {
            key: ConnectionKey::from_endpoints(
                CaptureProtocol::Tcp,
                Endpoint::new(ip("192.168.1.57"), Some(50000)),
                Endpoint::new(ip("17.253.1.1"), Some(443)),
            ),
            state: Some("ESTABLISHED".to_string()),
            bytes_in: 1_000,
            bytes_out: 100,
            age: Duration::from_secs(60),
            idle: Duration::from_secs(2),
            pid: None,
            comm: None,
            device_id: Some(1),
            origin: EndpointView {
                ip: ip("192.168.1.57"),
                port: Some(50000),
                device_id: Some(1),
                tag: None,
            },
            destination: EndpointView {
                ip: ip("17.253.1.1"),
                port: Some(443),
                device_id: None,
                tag: Some("?"),
            },
            headers: None,
            seen_capture: true,
            seen_kernel: true,
            label: Some(etiqueta),
            app_name: Some("iCloud".to_string()),
            category_name: Some("Nube".to_string()),
        }
    }

    fn app_detalle() -> App {
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
        app.set_data(vec![dispositivo()], Vec::new());
        app.traffic.devices = vec![estadisticas()];
        app.traffic.device_rankings = vec![DeviceRankingView {
            device_id: 1,
            window: Window::FiveMin,
            apps: vec![
                fila("instagram", "Instagram", 2_100_000),
                fila("whatsapp", "WhatsApp", 900_000),
            ],
            destinations: vec![
                fila("cdninstagram.com", "cdninstagram.com", 1_900_000),
                fila("whatsapp.net", "whatsapp.net", 900_000),
            ],
        }];
        app.traffic.connections = vec![
            conexion_ja4("t13d1516h2_8daaf6152771_02713d6af862"),
            conexion_ja4("t13d1517h2_9daaf6152771_02713d6af863"),
        ];
        app.open_detail(1, servicios_de_f2(), true);
        app
    }

    fn servicios_de_f2() -> Vec<DeviceService> {
        vec![
            DeviceService {
                id: 1,
                device_id: 1,
                port: 22,
                protocol: RepoProtocol::Tcp,
                service: Some("ssh".to_string()),
                banner: None,
                first_seen: "2025-10-03T00:00:00Z".to_string(),
                last_seen: "2025-10-03T00:00:00Z".to_string(),
                closed_at: None,
            },
            DeviceService {
                id: 2,
                device_id: 1,
                port: 139,
                protocol: RepoProtocol::Tcp,
                service: Some("netbios".to_string()),
                banner: None,
                first_seen: "2025-10-03T00:00:00Z".to_string(),
                last_seen: "2025-11-04T10:00:00Z".to_string(),
                closed_at: Some("2025-11-04T10:00:00Z".to_string()),
            },
        ]
    }

    fn alerta(
        id: i64,
        titulo: &str,
        nivel: Level,
        hace: i64,
        vista: bool,
    ) -> crate::history::AlertRow {
        let ahora = crate::history::localtime::now_unix();
        crate::history::AlertRow {
            id,
            rule: crate::alerts::AlertRule::Rule(crate::alerts::RuleId::WatchedPresence),
            level: nivel,
            subject: crate::alerts::Subject::Device(1),
            device_id: Some(1),
            title: titulo.to_string(),
            subject_label: "iPhone-Marta".to_string(),
            created_at: ahora - hace,
            last_at: ahora - hace,
            count: 1,
            seen: vista,
            resolved: false,
            notified: false,
            summary_id: None,
        }
    }

    /// Resumen de alertas del equipo 1 para el bloque «Alertas» del detalle.
    fn datos_alertas(app: &mut App) {
        let ahora = crate::history::localtime::now_unix();
        let aprendizaje = crate::alerts::LearningState {
            subject: crate::alerts::Subject::Device(1),
            learning_from: std::time::SystemTime::now()
                - std::time::Duration::from_secs(7 * 86_400),
            data_days: 7,
            learned_at: Some(std::time::SystemTime::now() - std::time::Duration::from_secs(86_400)),
        };
        app.alerts.device_summary = Some(crate::history::AlertSummary {
            subject: crate::history::SubjectSel::Device(1),
            recent: vec![
                alerta(
                    1,
                    "Vigilado de vuelta tras 41 min",
                    Level::Warning,
                    3_600,
                    false,
                ),
                alerta(
                    2,
                    "Puerto nuevo: 22/tcp (ssh)",
                    Level::Important,
                    7_200,
                    true,
                ),
            ],
            unseen: crate::alerts::AlertCounts {
                important: 1,
                warning: 1,
                info: 0,
            },
            mutes: vec![crate::history::MuteRow {
                id: 1,
                rule: crate::alerts::RuleId::TrafficHigh,
                subject: crate::alerts::Subject::Device(1),
                device_id: 1,
                device_label: Some("iPhone-Marta".to_string()),
                until: Some(ahora + 7 * 86_400),
                created_at: ahora,
            }],
            learning: Some(aprendizaje),
            inventory: None,
        });
        app.alerts.device_summary_for = Some(1);
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app, frame.area()))
            .expect("dibujado del detalle");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    fn tecla(codigo: KeyCode) -> KeyEvent {
        KeyEvent::new(codigo, KeyModifiers::NONE)
    }

    #[test]
    fn el_detalle_muestra_la_identidad_de_f4() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 120, 40);
        assert!(texto.contains("Detalle: iPhone-Marta (192.168.1.57)"));
        assert!(texto.contains("modelo: iPhone15,3"));
        assert!(texto.contains("ios"));
        assert!(texto.contains("fuente: modelo"));
        assert!(
            texto.contains("MAC: 5a:1c:…:9e (MAC privada)"),
            "la MAC se abrevia y se marca como privada"
        );
        assert!(texto.contains("huella 1,121,3,6,15,108,114,119,…"));
        assert!(texto.contains("nombre «iPhone-de-Marta»"));
        assert!(texto.contains("proveedor «android-dhcp-13»"));
    }

    #[test]
    fn el_detalle_muestra_top_apps_y_destinos_de_cinco_minutos() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 160, 76);
        assert!(texto.contains("Top apps (5 min)"));
        assert!(texto.contains("Top destinos"));
        assert!(texto.contains("Instagram"));
        assert!(texto.contains("WhatsApp"));
        assert!(texto.contains("cdninstagram.com"));
        assert!(texto.contains("whatsapp.net"));
        assert!(texto.contains("2.1 M"), "los bytes se formatean compactos");
    }

    #[test]
    fn el_detalle_sin_ranking_usa_las_conexiones_activas() {
        let mut app = app_detalle();
        app.traffic.device_rankings.clear();
        let texto = dibujar(&mut app, 160, 90);
        assert!(texto.contains("Top apps (conexiones activas)"));
        assert!(texto.contains("iCloud"));
        assert!(texto.contains("icloud.com"));
    }

    #[test]
    fn el_detalle_muestra_los_clientes_tls_distintos() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 160, 90);
        assert!(texto.contains("Clientes TLS (JA4):"));
        assert!(texto.contains("t13d1516h2_8daaf6152771_02713d6af862"));
        assert!(texto.contains("(2 distintos)"));
    }

    #[test]
    fn el_detalle_mantiene_el_trafico_las_conexiones_y_los_servicios_de_f3() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 160, 110);
        assert!(texto.contains("Tráfico"));
        assert!(texto.contains("60 s:"));
        assert!(texto.contains("5 min:"));
        assert!(texto.contains("Top puertos (5): 443/tcp 1.2 M"));
        assert!(texto.contains("Conexiones activas (2)"));
        assert!(texto.contains("Puertos"));
        assert!(texto.contains("22/tcp ssh"));
        assert!(texto.contains("abierto desde 3 oct"));
    }

    #[test]
    fn el_detalle_se_desplaza_con_j_k_cuando_no_cabe() {
        let mut app = app_detalle();
        let _ = dibujar(&mut app, 100, 16);
        assert!(
            app.detail_max_scroll > 0,
            "a poca altura el panel debe poder desplazarse"
        );
        assert!(app.detail_focus == FocusPanel::Detalle);
        app.handle_key(tecla(KeyCode::Char('j')));
        assert_eq!(app.detail_scroll, 1);
        for _ in 0..50 {
            app.handle_key(tecla(KeyCode::Char('j')));
        }
        assert_eq!(app.detail_scroll, app.detail_max_scroll);
        app.handle_key(tecla(KeyCode::Char('k')));
        assert_eq!(app.detail_scroll, app.detail_max_scroll - 1);
        // El dibujado mantiene el desplazamiento dentro de límites.
        let _ = dibujar(&mut app, 100, 16);
        assert!(app.detail_scroll <= app.detail_max_scroll);
    }

    #[test]
    fn el_detalle_muestra_el_bloque_de_alertas_y_el_vigilado() {
        let mut app = app_detalle();
        datos_alertas(&mut app);
        app.devices[0].watched = true;
        let texto = dibujar(&mut app, 120, 40);
        assert!(texto.contains("Alertas · 2 sin ver"));
        assert!(texto.contains("[p] vigilado: sí"));
        assert!(texto.contains("Vigilado de vuelta tras 41 min"));
        assert!(texto.contains("Puerto nuevo: 22/tcp (ssh)"));
        assert!(texto.contains("aprendido el"));
        assert!(texto.contains("días con datos"));
        assert!(texto.contains("Silencios: Más tráfico de lo habitual hasta"));
    }

    #[test]
    fn el_detalle_muestra_el_aprendizaje_en_curso() {
        let mut app = app_detalle();
        datos_alertas(&mut app);
        if let Some(aprendizaje) = app
            .alerts
            .device_summary
            .as_mut()
            .and_then(|resumen| resumen.learning.as_mut())
        {
            aprendizaje.learned_at = None;
            aprendizaje.data_days = 4;
        }
        let texto = dibujar(&mut app, 120, 40);
        assert!(texto.contains("aprendiendo (4 de 7 días con datos)"));
        assert!(texto.contains("[p] vigilado: no"));
    }

    #[test]
    fn el_bloque_de_alertas_cabe_en_ochenta_por_veinticuatro() {
        let mut app = app_detalle();
        datos_alertas(&mut app);
        let texto = dibujar(&mut app, 80, 24);
        assert!(texto.contains("Alertas ·"));
        assert!(texto.contains("[p] vigilado:"));
        assert!(!texto.contains("El equipo seleccionado ya no existe"));
    }

    #[test]
    fn los_puertos_muestran_el_estado_y_el_cierre() {
        let mut app = app_detalle();
        let texto = dibujar(&mut app, 140, 110);
        assert!(texto.contains("Puertos"));
        assert!(texto.contains("22/tcp ssh"));
        assert!(texto.contains("abierto desde 3 oct"));
        assert!(texto.contains("139/tcp netbios"));
        assert!(
            texto.contains("cerrado el 4 nov"),
            "el puerto cerrado muestra la fecha de cierre"
        );
        assert!(
            texto.contains("abierto por última vez el 4 nov"),
            "el puerto cerrado recuerda cuándo se vio abierto"
        );
    }

    #[test]
    fn el_detalle_de_un_equipo_inexistente_avisa() {
        let mut app = app_detalle();
        app.close_detail();
        app.open_detail(99, Vec::new(), true);
        let texto = dibujar(&mut app, 120, 24);
        assert!(texto.contains("ya no existe"));
    }

    #[test]
    fn los_formateos_del_detalle_abrevian_mac_y_huella() {
        assert_eq!(mac_abreviada("5a:1c:2d:3e:4f:9e"), "5a:1c:…:9e");
        assert_eq!(mac_abreviada("00:11:22"), "00:11:22");
        assert_eq!(
            huella_dhcp_abreviada("1,121,3,6,15,108,114,119,252"),
            "1,121,3,6,15,108,114,119,…"
        );
        assert_eq!(huella_dhcp_abreviada("1,3,6"), "1,3,6");
        assert_eq!(os_source_label(Some("model")), "modelo");
        assert_eq!(os_source_label(Some("dhcp")), "DHCP");
        assert_eq!(os_source_label(Some("ua")), "User-Agent");
        assert_eq!(os_source_label(None), "desconocida");
    }

    fn datos_historicos(app: &mut App) {
        let ahora = crate::history::localtime::now_unix();
        let puntos = (0..48)
            .map(|indice| crate::history::SeriesPoint {
                at: ahora - 86_400 + indice * 1800,
                bytes_down: 1_000,
                bytes_up: 200,
                gap: (10..=12).contains(&indice),
                future: indice >= 47,
            })
            .collect();
        app.history.detail_range = crate::history::Range::Hours24;
        app.history.detail_series = Some(crate::history::Series {
            range: crate::history::Range::Hours24,
            points: puntos,
            total_down: 2_100_000_000,
            total_up: 340_000_000,
            max: Some((20, 3_000_000_000)),
        });
        app.history.detail_presence = Some(vec![
            crate::history::PresenceSpan {
                start: ahora - 7200,
                end: ahora - 3600,
                state: crate::history::PresenceState::Present,
            },
            crate::history::PresenceSpan {
                start: ahora - 3600,
                end: ahora - 1800,
                state: crate::history::PresenceState::Absent,
            },
        ]);
        app.history.detail_inventory = Some(crate::history::Inventory {
            device_id: 1,
            since: Some("2026-10-12T00:00:00Z".to_string()),
            apps: vec![
                crate::history::SeenRow {
                    key: "temu".to_string(),
                    label: "Temu".to_string(),
                    first_seen: crate::history::localtime::rfc3339(ahora - 86_400),
                    last_seen: crate::history::localtime::rfc3339(ahora),
                },
                crate::history::SeenRow {
                    key: "instagram".to_string(),
                    label: "Instagram".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: crate::history::localtime::rfc3339(ahora),
                },
            ],
            categories: Vec::new(),
            orgs: vec![
                crate::history::SeenRow {
                    key: "meta".to_string(),
                    label: "Meta".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: "2026-10-12T00:00:00Z".to_string(),
                },
                crate::history::SeenRow {
                    key: "apple".to_string(),
                    label: "Apple".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: "2026-10-12T00:00:00Z".to_string(),
                },
            ],
            countries: vec![
                crate::history::SeenRow {
                    key: "US".to_string(),
                    label: "US".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: "2026-10-12T00:00:00Z".to_string(),
                },
                crate::history::SeenRow {
                    key: "IE".to_string(),
                    label: "IE".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: "2026-10-12T00:00:00Z".to_string(),
                },
            ],
            ja4: vec![
                crate::history::SeenRow {
                    key: "t13d".to_string(),
                    label: "t13d".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: "2026-10-12T00:00:00Z".to_string(),
                },
                crate::history::SeenRow {
                    key: "t13e".to_string(),
                    label: "t13e".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: "2026-10-12T00:00:00Z".to_string(),
                },
                crate::history::SeenRow {
                    key: "t13f".to_string(),
                    label: "t13f".to_string(),
                    first_seen: "2026-10-12T00:00:00Z".to_string(),
                    last_seen: "2026-10-12T00:00:00Z".to_string(),
                },
            ],
            ports: vec![crate::history::InventoryPort {
                port: 62078,
                protocol: "tcp".to_string(),
                service: None,
                first_seen: "2026-10-03T00:00:00Z".to_string(),
                closed_at: None,
            }],
        });
    }

    #[test]
    fn el_detalle_muestra_el_historico_y_la_presencia() {
        let mut app = app_detalle();
        datos_historicos(&mut app);
        let texto = dibujar(&mut app, 140, 110);
        assert!(texto.contains("Histórico · 24 h"));
        assert!(texto.contains("tráfico"));
        assert!(texto.contains("presencia"));
        assert!(texto.contains("[w] 24 h ⇄ 7 días"));
        assert!(texto.contains("Presencia · 7 días"));
        assert!(texto.contains("█ presente · · ausente · ░ sin datos"));
        assert!(texto.contains("↓ 2.1 G"));
    }

    #[test]
    fn la_tecla_w_alterna_el_rango_del_historico_del_detalle() {
        let mut app = app_detalle();
        datos_historicos(&mut app);
        assert_eq!(app.history.detail_range, crate::history::Range::Hours24);
        app.handle_key(tecla(KeyCode::Char('w')));
        assert_eq!(app.history.detail_range, crate::history::Range::Days7);
        let texto = dibujar(&mut app, 140, 110);
        assert!(texto.contains("Histórico · 7 días"));
        app.handle_key(tecla(KeyCode::Char('w')));
        assert_eq!(app.history.detail_range, crate::history::Range::Hours24);
    }

    #[test]
    fn el_bloque_visto_en_el_equipo_muestra_recuentos_y_puertos() {
        let mut app = app_detalle();
        datos_historicos(&mut app);
        let texto = dibujar(&mut app, 140, 110);
        assert!(texto.contains("Visto en este equipo (desde 12 oct)"));
        assert!(texto.contains("Apps (2)"));
        assert!(texto.contains("nuevas en 7 días: Temu (ayer)"));
        assert!(texto.contains("Organizaciones (2): Meta, Apple"));
        assert!(texto.contains("Países (2): US IE"));
        assert!(texto.contains("Clientes TLS (JA4): 3"));
        assert!(texto.contains("62078/tcp (desde 3 oct)"));
    }

    #[test]
    fn con_el_historico_desactivado_el_detalle_lo_avisa() {
        let mut app = app_detalle();
        app.config.history.enabled = false;
        let texto = dibujar(&mut app, 140, 110);
        assert!(texto.contains("desactivado ([history] enabled = false)"));
        assert!(texto.contains("inventario desactivado"));
    }
}
