//! Pestaña Conexiones: tabla plana ordenable/filtrable y panel de cabeceras.
//!
//! La tabla mezcla las conexiones del kernel (/proc/net/*, con estado y proceso)
//! y las observadas por captura (bytes reales de terceros). Las etiquetas
//! [host], [broadcast] y [?] se muestran en dim cuando el extremo no está
//! atribuido a un equipo inventariado. La tecla v abre un panel inferior no
//! modal con las cabeceras IP/TCP guardadas en memoria.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::capture::Protocol;
use crate::traffic::{formatear_bytes, ConnectionView};
use crate::tui::app::App;
use crate::tui::theme::device_icon;

/// Alto del panel de cabeceras (tecla v).
const ALTO_CABECERAS: u16 = 11;

/// Anchos de las columnas de la tabla de conexiones.
#[derive(Debug, Clone, Copy)]
struct Columnas {
    protocolo: u16,
    origen: u16,
    destino: u16,
    estado: u16,
    enviado: u16,
    recibido: u16,
    edad: u16,
}

impl Columnas {
    /// Reparte el ancho disponible para que quepa en 80 columnas.
    fn para(ancho: u16) -> Self {
        let base: [u16; 7] = [5, 18, 17, 11, 8, 8, 5];
        let fijo: u16 = base.iter().sum::<u16>() + 6;
        let extra = ancho.saturating_sub(fijo);
        let extra_origen = extra / 2;
        let extra_destino = extra - extra_origen;
        Self {
            protocolo: base[0],
            origen: base[1] + extra_origen,
            destino: base[2] + extra_destino,
            estado: base[3],
            enviado: base[4],
            recibido: base[5],
            edad: base[6],
        }
    }

    fn constraints(self) -> Vec<Constraint> {
        vec![
            Constraint::Length(self.protocolo),
            Constraint::Length(self.origen),
            Constraint::Length(self.destino),
            Constraint::Length(self.estado),
            Constraint::Length(self.enviado),
            Constraint::Length(self.recibido),
            Constraint::Length(self.edad),
        ]
    }
}

/// Dibuja la pestaña Conexiones.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let (area_tabla, area_cabeceras) = if app.headers_open() {
        let zonas =
            Layout::vertical([Constraint::Min(3), Constraint::Length(ALTO_CABECERAS)]).split(area);
        (zonas[0], Some(zonas[1]))
    } else {
        (area, None)
    };
    draw_tabla(frame, app, area_tabla);
    if let Some(area) = area_cabeceras {
        draw_cabeceras(frame, app, area);
    }
}

fn draw_tabla(frame: &mut Frame, app: &mut App, area: Rect) {
    let visibles = app.filtered_connections();
    let total = app.traffic.connections_total;
    let titulo = format!(
        "Conexiones activas ({} de {total}) · filtro: {} · orden: {}",
        visibles.len(),
        app.connection_filter_label(),
        app.conn_sort.label()
    );
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    if visibles.is_empty() {
        let mensaje = if app.traffic.connections_total == 0 {
            if app.traffic.capture.active {
                "Sin conexiones activas todavía (esperando al primer ciclo de captura)"
            } else {
                "Sin conexiones: la captura está deshabilitada y el kernel no ofrece sockets activos"
            }
        } else {
            "No hay conexiones que coincidan con el filtro"
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

    // Los índices se calculan sobre la lista filtrada y ordenada.
    let columnas = Columnas::para(interior.width);
    let cabecera = Row::new(vec![
        "Proto", "Origen", "Destino", "Estado", "↑", "↓", "Edad",
    ])
    .style(app.theme.accent);

    // Se copian las celdas antes de pedir el estado mutable de la tabla.
    let dispositivos: Vec<(i64, String, String)> = app
        .devices
        .iter()
        .map(|device| {
            let (icono, _) = device_icon(device, &app.theme);
            (
                device.id,
                icono.to_string(),
                device.display_name().to_string(),
            )
        })
        .collect();
    let filas: Vec<Row> = visibles
        .iter()
        .map(|conexion| fila_conexion(conexion, &dispositivos, &app.theme))
        .collect();

    let tabla = Table::new(filas, columnas.constraints())
        .header(cabecera)
        .column_spacing(1)
        .row_highlight_style(app.theme.selected)
        .highlight_symbol(Span::styled("▸ ", app.theme.accent))
        .style(app.theme.normal);
    *app.conn_table_state.selected_mut() = Some(app.conn_selected);
    frame.render_stateful_widget(tabla, interior, &mut app.conn_table_state);
}

fn fila_conexion(
    conexion: &ConnectionView,
    dispositivos: &[(i64, String, String)],
    theme: &crate::tui::theme::Theme,
) -> Row<'static> {
    let origen = celda_endpoint(&conexion.origin, dispositivos, theme);
    let destino = celda_endpoint(&conexion.destination, dispositivos, theme);
    let estado_estilo = match conexion.state.as_deref() {
        Some("ESTABLISHED") => theme.online,
        Some("TIME_WAIT") | Some("CLOSE_WAIT") | Some("SYN_SENT") => theme.warning,
        Some("RESET") | Some("CLOSE") => theme.error,
        _ => theme.dim,
    };
    Row::new(vec![
        Cell::from(Span::styled(conexion.protocol().as_str(), theme.normal)),
        origen,
        destino,
        Cell::from(Span::styled(
            conexion.state_label().to_string(),
            estado_estilo,
        )),
        Cell::from(Span::styled(
            formatear_bytes(conexion.bytes_out),
            theme.accent,
        )),
        Cell::from(Span::styled(
            formatear_bytes(conexion.bytes_in),
            theme.online,
        )),
        Cell::from(Span::styled(conexion.age_label(), theme.dim)),
    ])
}

/// Celda de un extremo: icono del dispositivo o etiqueta dim + ip:puerto.
fn celda_endpoint(
    extremo: &crate::traffic::EndpointView,
    dispositivos: &[(i64, String, String)],
    theme: &crate::tui::theme::Theme,
) -> Cell<'static> {
    let mut spans: Vec<Span> = Vec::new();
    if let Some(id) = extremo.device_id {
        if let Some((_, icono, _)) = dispositivos.iter().find(|(ident, _, _)| *ident == id) {
            spans.push(Span::styled(icono.clone(), theme.accent));
        }
    } else if let Some(etiqueta) = extremo.tag {
        spans.push(Span::styled(format!("[{etiqueta}]"), theme.dim));
    }
    spans.push(Span::styled(extremo.display(), theme.normal));
    Cell::from(Line::from(spans))
}

fn draw_cabeceras(frame: &mut Frame, app: &App, area: Rect) {
    let Some(panel) = app.headers.as_ref() else {
        return;
    };
    let conexion = &panel.connection;
    let titulo = format!(
        "Cabeceras IP/TCP — {} {} → {} (Esc cierra)",
        conexion.protocol().as_str(),
        conexion.origin.display(),
        conexion.destination.display()
    );
    let bloque = Block::bordered()
        .border_style(app.theme.accent)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let mut lineas: Vec<Line> = Vec::new();
    match conexion.headers {
        Some(cabeceras) => {
            lineas.push(Line::from(Span::styled(
                format!(
                    "IP v{} · cabecera {} B · total {} B · TTL {} · TOS {} · protocolo {}",
                    cabeceras.ip_version,
                    cabeceras.ip_header_len,
                    cabeceras.ip_total_len,
                    cabeceras.ttl,
                    cabeceras.tos,
                    cabeceras.ip_protocol
                ),
                app.theme.normal,
            )));
            lineas.push(Line::from(Span::styled(
                format!("IP  {}", hex(cabeceras.ip_bytes())),
                app.theme.dim,
            )));
            match conexion.protocol() {
                Protocol::Tcp => {
                    lineas.push(Line::from(Span::styled(
                        format!(
                            "TCP puertos {} → {} · flags {} · seq {} · ack {} · ventana {}",
                            conexion.origin.port.unwrap_or(0),
                            conexion.destination.port.unwrap_or(0),
                            crate::capture::TcpFlags::from_bits(cabeceras.tcp_flags).label(),
                            cabeceras.tcp_seq,
                            cabeceras.tcp_ack,
                            cabeceras.tcp_window
                        ),
                        app.theme.normal,
                    )));
                }
                Protocol::Udp => {
                    lineas.push(Line::from(Span::styled(
                        format!(
                            "UDP puertos {} → {} · longitud {}",
                            conexion.origin.port.unwrap_or(0),
                            conexion.destination.port.unwrap_or(0),
                            cabeceras
                                .ip_total_len
                                .saturating_sub(u16::from(cabeceras.ip_header_len))
                        ),
                        app.theme.normal,
                    )));
                }
                Protocol::Icmp | Protocol::Icmpv6 => {
                    lineas.push(Line::from(Span::styled(
                        "ICMP: sin puertos de transporte",
                        app.theme.normal,
                    )));
                }
                Protocol::Other => {
                    lineas.push(Line::from(Span::styled(
                        "Protocolo de transporte no interpretado",
                        app.theme.normal,
                    )));
                }
            }
            lineas.push(Line::from(Span::styled(
                format!("L4  {}", hex(cabeceras.transport_bytes())),
                app.theme.dim,
            )));
        }
        None => {
            lineas.push(Line::from(Span::styled(
                "Sin cabeceras en memoria para esta conexión (solo se observó en /proc/net/*).",
                app.theme.warning,
            )));
        }
    }
    if let Some(proceso) = conexion.process_label() {
        lineas.push(Line::from(Span::styled(
            format!("Proceso local: {proceso}"),
            app.theme.accent,
        )));
    }
    lineas.push(Line::from(Span::styled(
        format!(
            "Bytes: ↑ {} · ↓ {} · edad {} · inactiva {}",
            formatear_bytes(conexion.bytes_out),
            formatear_bytes(conexion.bytes_in),
            conexion.age_label(),
            conexion.idle_label()
        ),
        app.theme.dim,
    )));

    frame.render_widget(Paragraph::new(lineas).style(app.theme.normal), interior);
}

/// Representación hexadecimal separada por espacios.
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(sin bytes)".to_string();
    }
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::Capabilities;
    use crate::capture::{ConnectionKey, Endpoint, HeaderSnapshot, Protocol};
    use crate::config::Config;
    use crate::repo::devices::Device;
    use crate::traffic::EndpointView;
    use crate::tui::app::App;
    use crate::tui::traffic_state::HeadersView;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Duration;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP de prueba")
    }

    fn dispositivo(id: i64, ip_texto: &str) -> Device {
        Device {
            id,
            mac: format!("aa:bb:cc:dd:ee:0{id}"),
            ip: ip_texto.to_string(),
            hostname: Some(format!("equipo-{id}")),
            vendor: None,
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

    fn conexion(
        origen: (&str, u16, Option<i64>, Option<&'static str>),
        destino: (&str, u16, Option<i64>, Option<&'static str>),
        estado: &str,
    ) -> ConnectionView {
        let cabeceras = HeaderSnapshot {
            ip_version: 4,
            ip_header_len: 20,
            ip_total_len: 60,
            ttl: 64,
            tos: 0,
            ip_protocol: 6,
            ip_raw: [0x45; 40],
            ip_raw_len: 20,
            transport_raw: [0x01; 20],
            transport_raw_len: 20,
            tcp_seq: 123,
            tcp_ack: 456,
            tcp_window: 65535,
            tcp_flags: 0x12,
        };
        ConnectionView {
            key: ConnectionKey::from_endpoints(
                Protocol::Tcp,
                Endpoint::new(ip(origen.0), Some(origen.1)),
                Endpoint::new(ip(destino.0), Some(destino.1)),
            ),
            state: Some(estado.to_string()),
            bytes_in: 4096,
            bytes_out: 2048,
            age: Duration::from_secs(125),
            idle: Duration::from_secs(5),
            pid: Some(1234),
            comm: Some("firefox".to_string()),
            device_id: origen.2.or(destino.2),
            origin: EndpointView {
                ip: ip(origen.0),
                port: Some(origen.1),
                device_id: origen.2,
                tag: origen.3,
            },
            destination: EndpointView {
                ip: ip(destino.0),
                port: Some(destino.1),
                device_id: destino.2,
                tag: destino.3,
            },
            headers: Some(cabeceras),
            seen_capture: true,
            seen_kernel: true,
        }
    }

    fn app_con(conexiones: Vec<ConnectionView>) -> App {
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
                dispositivo(1, "192.168.1.42"),
                dispositivo(2, "192.168.1.1"),
            ],
            Vec::new(),
        );
        app.traffic.connections = conexiones;
        app.traffic.connections_total = app.traffic.connections.len();
        app
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app, frame.area()))
            .expect("dibujado de conexiones");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn tabla_muestra_columnas_y_etiquetas_dim() {
        let mut app = app_con(vec![
            conexion(
                ("192.168.1.42", 54321, Some(1), None),
                ("1.1.1.1", 443, None, Some("?")),
                "ESTABLISHED",
            ),
            conexion(
                ("192.168.1.10", 5353, None, Some("host")),
                ("224.0.0.251", 5353, None, Some("broadcast")),
                "—",
            ),
        ]);
        let contenido = dibujar(&mut app, 110, 30);
        assert!(contenido.contains("Proto"));
        assert!(contenido.contains("Origen"));
        assert!(contenido.contains("Destino"));
        assert!(contenido.contains("Estado"));
        assert!(contenido.contains("Edad"));
        assert!(contenido.contains("ESTABLISHED"));
        assert!(contenido.contains("[host]"));
        assert!(contenido.contains("[broadcast]"));
    }

    #[test]
    fn tabla_ordena_y_filtra() {
        let mut app = app_con(vec![
            conexion(
                ("192.168.1.42", 1000, Some(1), None),
                ("8.8.8.8", 53, None, Some("?")),
                "ESTABLISHED",
            ),
            conexion(
                ("192.168.1.42", 2000, Some(1), None),
                ("1.1.1.1", 443, None, Some("?")),
                "TIME_WAIT",
            ),
        ]);
        assert_eq!(app.filtered_connections().len(), 2);
        app.cycle_connection_filter();
        assert_eq!(app.connection_filter_label(), "tcp");
        assert_eq!(app.filtered_connections().len(), 2);
        for _ in 0..3 {
            app.cycle_connection_filter();
        }
        assert_eq!(app.connection_filter_label(), "established");
        assert_eq!(app.filtered_connections().len(), 1);
        app.cycle_connection_sort();
        assert!(app.conn_sort.label().contains('↑') || app.conn_sort.label().contains('↓'));
    }

    #[test]
    fn tecla_v_abre_panel_de_cabeceras_y_esc_lo_cierra() {
        let mut app = app_con(vec![conexion(
            ("192.168.1.42", 54321, Some(1), None),
            ("1.1.1.1", 443, None, Some("?")),
            "ESTABLISHED",
        )]);
        app.tab = crate::tui::app::Tab::Conexiones;
        app.handle_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('v'),
            crossterm::event::KeyModifiers::NONE,
        ));
        assert!(app.headers_open());
        let contenido = dibujar(&mut app, 110, 30);
        assert!(contenido.contains("Cabeceras IP/TCP"));
        assert!(contenido.contains("TCP puertos"));
        assert!(contenido.contains("firefox"));
        app.handle_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Esc,
            crossterm::event::KeyModifiers::NONE,
        ));
        assert!(!app.headers_open());
    }

    #[test]
    fn v_sin_conexion_avisa() {
        let mut app = app_con(Vec::new());
        app.tab = crate::tui::app::Tab::Conexiones;
        assert!(!app.open_headers());
        assert!(app
            .notifier
            .current()
            .expect("notificación")
            .message
            .contains("conexión"));
    }

    #[test]
    fn panel_sin_cabeceras_muestra_aviso() {
        let mut conexion = conexion(
            ("192.168.1.42", 54321, Some(1), None),
            ("1.1.1.1", 443, None, Some("?")),
            "ESTABLISHED",
        );
        conexion.headers = None;
        let mut app = app_con(vec![conexion]);
        app.headers = Some(HeadersView {
            connection: app.traffic.connections[0].clone(),
        });
        let contenido = dibujar(&mut app, 110, 30);
        assert!(contenido.contains("Sin cabeceras en memoria"));
    }

    #[test]
    fn tabla_cabe_en_ochenta_columnas() {
        let mut app = app_con(vec![conexion(
            ("192.168.1.42", 54321, Some(1), None),
            ("1.1.1.1", 443, None, Some("?")),
            "ESTABLISHED",
        )]);
        let contenido = dibujar(&mut app, 80, 24);
        assert!(contenido.contains("Proto"));
        assert!(contenido.contains("Edad"));
        assert_eq!(Ipv4Addr::new(192, 168, 1, 42).to_string(), "192.168.1.42");
    }
}
