//! Pestaña Tráfico: ranking top-10 por consumo en la ventana de 60 s.
//!
//! La fila muestra el icono y nombre del equipo, su tipo, los ritmos de entrada
//! y salida del último segundo, el total de la ventana de 60 s y una sparkline
//! de esa misma ventana. Al arrancar sin captura se muestra el último snapshot
//! persistido (TRAFFIC_SNAPSHOT) y un aviso claro si falta CAP_NET_RAW.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::capture::aggregate::DeviceTraffic;
use crate::classify::DeviceType;
use crate::traffic::{formatear_bytes, formatear_bytes_por_segundo, sparkline};
use crate::tui::app::App;
use crate::tui::theme::device_icon;

/// Número máximo de filas del ranking.
pub const TOP_RANKING: usize = 10;
/// Puntos de sparkline que se muestran como mínimo en pantallas estrechas.
const SPARK_ANCHO_MIN: u16 = 10;

/// Anchos de las columnas del ranking.
#[derive(Debug, Clone, Copy)]
struct Columnas {
    numero: u16,
    dispositivo: u16,
    tipo: u16,
    entrada: u16,
    salida: u16,
    total: u16,
    sparkline: u16,
}

impl Columnas {
    /// Reparte el ancho disponible para que quepa en 80 columnas.
    fn para(ancho: u16) -> Self {
        let base: [u16; 7] = [2, 16, 7, 9, 9, 9, 14];
        let fijo: u16 = base.iter().sum::<u16>() + 6;
        let extra = ancho.saturating_sub(fijo);
        let extra_dispositivo = extra / 2;
        let extra_sparkline = extra - extra_dispositivo;
        Self {
            numero: base[0],
            dispositivo: base[1] + extra_dispositivo,
            tipo: base[2],
            entrada: base[3],
            salida: base[4],
            total: base[5],
            sparkline: base[6].saturating_add(extra_sparkline),
        }
    }

    fn constraints(self) -> Vec<Constraint> {
        vec![
            Constraint::Length(self.numero),
            Constraint::Length(self.dispositivo),
            Constraint::Length(self.tipo),
            Constraint::Length(self.entrada),
            Constraint::Length(self.salida),
            Constraint::Length(self.total),
            Constraint::Length(self.sparkline),
        ]
    }
}

/// Dibuja la pestaña Tráfico.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let titulo = if app.traffic.capture.active {
        format!(
            "Tráfico — ranking en vivo (ventana 60 s) · {}",
            app.traffic.capture.summary()
        )
    } else {
        "Tráfico — ranking en vivo (ventana 60 s)".to_string()
    };
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    // Sin captura activa ni datos en vivo: aviso claro + snapshot de la semilla.
    if !app.traffic.capture.active && !app.traffic.has_live_data() {
        draw_sin_captura(frame, app, interior);
        return;
    }

    let filas_ranking = app.traffic_rows();
    if filas_ranking.is_empty() {
        let mensaje = if app.traffic.capture.active {
            "Capturando… aún no se ha observado tráfico IP (en red conmutada solo se ve el propio y la difusión)"
        } else {
            "Todavía no hay tráfico capturado"
        };
        let paragraph =
            Paragraph::new(Span::styled(mensaje, app.theme.dim)).alignment(Alignment::Center);
        let filas = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(interior);
        frame.render_widget(paragraph, filas[1]);
        return;
    }

    let zonas = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(interior);
    draw_ranking(frame, app, &filas_ranking, zonas[0]);
    draw_resumen(frame, app, zonas[1]);
}

fn draw_ranking(frame: &mut Frame, app: &mut App, filas_ranking: &[DeviceTraffic], area: Rect) {
    let columnas = Columnas::para(area.width);
    let cabecera = Row::new(vec![
        "#",
        "Dispositivo",
        "Tipo",
        "↓ in",
        "↑ out",
        "Total",
        "sparkline 60 s",
    ])
    .style(app.theme.accent);

    let filas: Vec<Row> = filas_ranking
        .iter()
        .take(TOP_RANKING)
        .enumerate()
        .map(|(posicion, estadisticas)| {
            let es_host = estadisticas.device_id == crate::traffic::DEVICE_ID_HOST;
            let dispositivo = app
                .devices
                .iter()
                .find(|device| device.id == estadisticas.device_id);
            let (icono, estilo_icono) = if es_host {
                ("", app.theme.accent)
            } else {
                match dispositivo {
                    Some(device) => device_icon(device, &app.theme),
                    None => ("[?]", app.theme.dim),
                }
            };
            let nombre = if es_host {
                "[host]".to_string()
            } else {
                dispositivo
                    .map(|device| device.display_name().to_string())
                    .unwrap_or_else(|| format!("equipo {}", estadisticas.device_id))
            };
            let tipo = if es_host {
                "host"
            } else {
                dispositivo
                    .map(|device| {
                        DeviceType::from_str(device.effective_device_type())
                            .unwrap_or(DeviceType::Unknown)
                            .label()
                    })
                    .unwrap_or("?")
            };
            let estilo_nombre = if es_host {
                app.theme.accent.add_modifier(Modifier::BOLD)
            } else {
                app.theme.normal
            };
            let total = estadisticas.bytes_in.saturating_add(estadisticas.bytes_out);
            let serie = serie_total(estadisticas);
            let ancho_spark = usize::from(columnas.sparkline.max(SPARK_ANCHO_MIN));
            let puntos = serie.len().saturating_sub(ancho_spark);
            let dibujo = sparkline(&serie[puntos..]);

            Row::new(vec![
                Cell::from(Span::styled(format!("{}", posicion + 1), app.theme.dim)),
                Cell::from(Line::from(vec![
                    Span::styled(icono, estilo_icono),
                    Span::styled(format!(" {nombre}"), estilo_nombre),
                ])),
                Cell::from(Span::styled(tipo, app.theme.dim)),
                Cell::from(Span::styled(
                    formatear_bytes_por_segundo(estadisticas.rate_in),
                    app.theme.online,
                )),
                Cell::from(Span::styled(
                    formatear_bytes_por_segundo(estadisticas.rate_out),
                    app.theme.accent.add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(formatear_bytes(total), app.theme.normal)),
                Cell::from(Span::styled(dibujo, app.theme.accent)),
            ])
        })
        .collect();

    let tabla = Table::new(filas, columnas.constraints())
        .header(cabecera)
        .column_spacing(1)
        .row_highlight_style(app.theme.selected)
        .highlight_symbol(Span::styled("▸ ", app.theme.accent))
        .style(app.theme.normal);

    *app.traffic_table_state.selected_mut() = Some(app.traffic_selected);
    frame.render_stateful_widget(tabla, area, &mut app.traffic_table_state);
}

fn draw_resumen(frame: &mut Frame, app: &App, area: Rect) {
    let (entrada, salida) = app.traffic.global_rates();
    let conexiones = app.traffic.connections_total;
    let mut texto = format!(
        "Total observado: ↓ {}/s · ↑ {}/s · {conexiones} conexiones",
        formatear_bytes_por_segundo(entrada),
        formatear_bytes_por_segundo(salida)
    );
    let difusion = app.traffic.broadcast_bytes();
    if difusion > 0 {
        texto.push_str(&format!(" · difusión {}", formatear_bytes(difusion)));
    }
    if !app.traffic.capture.active {
        if let Some(fecha) = app.traffic.seed_label() {
            texto.push_str(&format!(" · snapshot: {fecha}"));
        }
    }
    frame.render_widget(
        Paragraph::new(Span::styled(texto, app.theme.dim)).style(app.theme.normal),
        area,
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

    let filas_ranking = app.traffic_rows();
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
                let nombre = app
                    .devices
                    .iter()
                    .find(|device| device.id == estadisticas.device_id)
                    .map(|device| device.display_name().to_string())
                    .unwrap_or_else(|| format!("equipo {}", estadisticas.device_id));
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
        Constraint::Length(8),
        Constraint::Fill(1),
    ])
    .split(area);
    frame.render_widget(parrafo, vertical[1]);
}

/// Suma las series de entrada y salida para una única sparkline.
fn serie_total(estadisticas: &DeviceTraffic) -> Vec<u64> {
    estadisticas
        .series_60s_in
        .iter()
        .zip(estadisticas.series_60s_out.iter())
        .map(|(entrada, salida)| entrada.saturating_add(*salida))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::aggregate::GlobalTraffic;
    use crate::config::Config;
    use crate::repo::devices::Device;
    use crate::traffic::CaptureStatus;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn device(id: i64, ip: &str) -> Device {
        Device {
            id,
            mac: format!("aa:bb:cc:dd:ee:0{id}"),
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
        }
    }

    fn estadisticas(device_id: i64, bytes: u64) -> DeviceTraffic {
        let mut serie = [0u64; 60];
        for (posicion, valor) in serie.iter_mut().enumerate() {
            *valor = (posicion as u64 + 1) * bytes / 60;
        }
        DeviceTraffic {
            device_id,
            bytes_in: bytes,
            bytes_out: bytes / 2,
            packets_in: 10,
            packets_out: 5,
            rate_in: 1200,
            rate_out: 600,
            peak_bps: bytes,
            series_60s_in: serie,
            series_60s_out: [0; 60],
            series_5min_in: [0; 60],
            series_5min_out: [0; 60],
            top_ports: Vec::new(),
        }
    }

    fn app_con_trafico(activa: bool) -> App {
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
            vec![device(1, "10.0.0.2"), device(2, "10.0.0.3")],
            Vec::new(),
        );
        app.traffic.devices = vec![estadisticas(1, 10_000_000), estadisticas(2, 5_000_000)];
        app.traffic.global = GlobalTraffic {
            bytes_in: 100,
            bytes_out: 50,
            broadcast_bytes: 0,
            packets_total: 20,
        };
        app.traffic.connections_total = 3;
        app.traffic.capture = CaptureStatus {
            active: activa,
            ..CaptureStatus::default()
        };
        app
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app, frame.area()))
            .expect("dibujado del ranking");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn ranking_muestra_columnas_y_top_10() {
        let mut app = app_con_trafico(true);
        app.traffic.devices = (1..=12)
            .map(|id| estadisticas(id, 10_000 * id as u64))
            .collect();
        let contenido = dibujar(&mut app, 140, 30);
        assert!(contenido.contains("Dispositivo"));
        assert!(contenido.contains("sparkline 60 s"));
        assert!(contenido.contains("ranking en vivo"));
        // El ranking ordena por consumo: el 12 entra y el menos activo (2) queda fuera.
        assert!(contenido.contains("equipo 12"));
        assert!(!contenido.contains("equipo 2 "), "solo top-10");
    }

    #[test]
    fn ranking_cabe_en_ochenta_columnas() {
        let mut app = app_con_trafico(true);
        let contenido = dibujar(&mut app, 80, 24);
        assert!(contenido.contains("Dispositivo"));
        assert!(contenido.contains("Total"));
        assert!(contenido.contains("equipo-1"));
    }

    #[test]
    fn sin_captura_muestra_aviso_y_snapshot() {
        let mut app = app_con_trafico(false);
        app.traffic.devices.clear();
        app.traffic.seed = vec![crate::repo::TrafficSnapshot {
            device_id: 1,
            bytes_in: 2_000_000,
            bytes_out: 500_000,
            packets_in: 100,
            packets_out: 40,
            peak_bps: 3_000_000,
            window_s: 60,
            updated_at: "2026-11-10T10:00:00Z".to_string(),
        }];
        app.traffic.capture.disabled_reason = Some("requiere CAP_NET_RAW".to_string());
        app.traffic.capture.available = false;
        let contenido = dibujar(&mut app, 110, 30);
        assert!(contenido.contains("Captura deshabilitada"));
        assert!(contenido.contains("CAP_NET_RAW"));
        assert!(contenido.contains("Ayuda"));
        assert!(contenido.contains("Snapshot del último ciclo"));
    }

    #[test]
    fn ranking_muestra_el_trafico_propio_como_host() {
        let mut app = app_con_trafico(true);
        app.traffic.devices.clear();
        let mut host = estadisticas(1, 500);
        host.device_id = crate::traffic::DEVICE_ID_HOST;
        host.rate_in = 10;
        host.rate_out = 5;
        app.traffic.host = host;
        app.traffic.updated_at = Some(std::time::Instant::now());
        let contenido = dibujar(&mut app, 110, 30);
        assert!(contenido.contains("[host]"));
        assert!(contenido.contains("host"));
    }

    #[test]
    fn seleccion_y_enter_en_ranking() {
        let mut app = app_con_trafico(true);
        assert_eq!(app.selected_traffic_device().map(|e| e.device_id), Some(1));
        app.move_traffic_selection(1);
        assert_eq!(app.selected_traffic_device().map(|e| e.device_id), Some(2));
    }

    #[test]
    fn resumen_muestra_totales_y_conexiones() {
        let mut app = app_con_trafico(true);
        let contenido = dibujar(&mut app, 110, 30);
        assert!(contenido.contains("Total observado"));
        assert!(contenido.contains("conexiones"));
    }
}
