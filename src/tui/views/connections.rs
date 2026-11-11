//! Pestaña Conexiones: tabla plana ordenable, filtrable y buscable, con las
//! columnas de F4 (Prot. · Equipo · Destino · App · ↑ · ↓ · Edad y Estado a
//! partir de 100 columnas) y el panel de detalle de la tecla v.
//!
//! Equipo es el lado cliente (o el de la LAN) y Destino el lado servidor,
//! deducidos del rol de §7.1; sin rol la fila sale en orden canónico con «?»
//! delante del destino. La tecla i alterna nombres ⇄ IPs (sin persistir).

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::capture::Protocol;
use crate::traffic::{formatear_bytes, ConnectionView, EndpointView};
use crate::tui::app::App;
use crate::tui::theme::{device_icon, Theme};
use crate::tui::traffic_state::{bytes_orientados, lados_conexion, ConnectionFilter};

/// Alto del panel de detalle de conexión (tecla v).
const ALTO_CABECERAS: u16 = 13;
/// Ancho a partir del cual aparece la columna Estado.
pub const ANCHO_CON_ESTADO: u16 = 100;

/// Anchos de las columnas de la tabla de conexiones.
#[derive(Debug, Clone, Copy)]
struct Columnas {
    protocolo: u16,
    equipo: u16,
    destino: u16,
    app: u16,
    subida: u16,
    bajada: u16,
    edad: u16,
    estado: Option<u16>,
}

impl Columnas {
    /// Reparte el ancho disponible para que quepa en 80 columnas.
    fn para(ancho: u16) -> Self {
        let con_estado = ancho >= ANCHO_CON_ESTADO;
        let mut base = vec![5u16, 17, 17, 15, 7, 7, 5];
        if con_estado {
            base.push(9);
        }
        let separaciones = base.len().saturating_sub(1) as u16;
        let fijo: u16 = base.iter().sum::<u16>() + separaciones;
        let extra = ancho.saturating_sub(fijo);
        let extra_equipo = extra / 2;
        let extra_destino = extra - extra_equipo;
        Self {
            protocolo: base[0],
            equipo: base[1] + extra_equipo,
            destino: base[2] + extra_destino,
            app: base[3],
            subida: base[4],
            bajada: base[5],
            edad: base[6],
            estado: con_estado.then(|| base[7]),
        }
    }

    fn constraints(self) -> Vec<Constraint> {
        let mut columnas = vec![
            Constraint::Length(self.protocolo),
            Constraint::Length(self.equipo),
            Constraint::Length(self.destino),
            Constraint::Length(self.app),
            Constraint::Length(self.subida),
            Constraint::Length(self.bajada),
            Constraint::Length(self.edad),
        ];
        if let Some(estado) = self.estado {
            columnas.push(Constraint::Length(estado));
        }
        columnas
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
    let vista = if app.show_names { "nombres" } else { "IPs" };
    let mut titulo = format!(
        "Conexiones activas ({} de {total}) · vista: {vista} · filtro: {} · orden: {}",
        visibles.len(),
        app.connection_filter_label(),
        app.conn_sort.label()
    );
    let busqueda = app.effective_conn_search().trim().to_string();
    if !busqueda.is_empty() {
        titulo.push_str(&format!(" · búsqueda: \"{busqueda}\""));
    }
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    if visibles.is_empty() {
        let mensaje = if !busqueda.is_empty() {
            "No hay conexiones que coincidan con la búsqueda"
        } else if matches!(app.conn_filter, ConnectionFilter::Proceso { .. }) {
            "No hay conexiones del proceso seleccionado"
        } else if app.traffic.connections_total == 0 {
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
    let mut cabecera = vec!["Prot.", "Equipo", "Destino", "App", "↑", "↓", "Edad"];
    if columnas.estado.is_some() {
        cabecera.push("Estado");
    }
    let cabecera = Row::new(cabecera).style(app.theme.accent);

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
        .map(|conexion| {
            fila_conexion(
                conexion,
                &dispositivos,
                &app.theme,
                app.show_names,
                columnas.estado.is_some(),
            )
        })
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
    theme: &Theme,
    mostrar_nombres: bool,
    con_estado: bool,
) -> Row<'static> {
    let (rol, cliente, servidor) = lados_conexion(conexion);
    let equipo = celda_equipo(conexion, &cliente, dispositivos, theme, mostrar_nombres);
    let destino = celda_destino(conexion, &servidor, theme, mostrar_nombres, rol.sin_rol());
    let (subida, bajada) = bytes_orientados(conexion);
    let app = conexion.app_label();
    let estilo_app = if app == "Sin identificar" {
        theme.dim
    } else {
        theme.normal
    };
    let mut celdas = vec![
        Cell::from(Span::styled(
            conexion.app_protocol_label().to_string(),
            theme.normal,
        )),
        equipo,
        destino,
        Cell::from(Span::styled(app, estilo_app)),
        Cell::from(Span::styled(formatear_bytes(subida), theme.accent)),
        Cell::from(Span::styled(formatear_bytes(bajada), theme.online)),
        Cell::from(Span::styled(conexion.age_label(), theme.dim)),
    ];
    if con_estado {
        let estado_estilo = match conexion.state.as_deref() {
            Some("ESTABLISHED") => theme.online,
            Some("TIME_WAIT") | Some("CLOSE_WAIT") | Some("SYN_SENT") => theme.warning,
            Some("RESET") | Some("CLOSE") => theme.error,
            _ => theme.dim,
        };
        celdas.push(Cell::from(Span::styled(
            conexion.state_label().to_string(),
            estado_estilo,
        )));
    }
    Row::new(celdas)
}

/// Celda del lado cliente (o de la LAN): icono y nombre, o IP con «i».
fn celda_equipo(
    conexion: &ConnectionView,
    cliente: &EndpointView,
    dispositivos: &[(i64, String, String)],
    theme: &Theme,
    mostrar_nombres: bool,
) -> Cell<'static> {
    let mut spans: Vec<Span> = Vec::new();
    if let Some(id) = cliente.device_id {
        if let Some((_, icono, _)) = dispositivos.iter().find(|(ident, _, _)| *ident == id) {
            spans.push(Span::styled(icono.clone(), theme.accent));
            if mostrar_nombres {
                if let Some((_, _, nombre)) = dispositivos.iter().find(|(ident, _, _)| *ident == id)
                {
                    spans.push(Span::styled(format!(" {nombre}"), theme.normal));
                }
            } else {
                spans.push(Span::styled(format!(" {}", cliente.ip), theme.normal));
            }
        }
    } else if mostrar_nombres && cliente.tag == Some("host") {
        spans.push(Span::styled("[host]", theme.dim));
        if let Some(comm) = &conexion.comm {
            spans.push(Span::styled(comm.clone(), theme.normal));
        }
    } else {
        if let Some(etiqueta) = cliente.tag {
            spans.push(Span::styled(format!("[{etiqueta}]"), theme.dim));
        }
        spans.push(Span::styled(cliente.ip.to_string(), theme.normal));
    }
    Cell::from(Line::from(spans))
}

/// Celda del lado servidor: nombre del servidor o IP con organización y país.
fn celda_destino(
    conexion: &ConnectionView,
    servidor: &EndpointView,
    theme: &Theme,
    mostrar_nombres: bool,
    sin_rol: bool,
) -> Cell<'static> {
    let mut spans: Vec<Span> = Vec::new();
    if sin_rol {
        spans.push(Span::styled("?", theme.warning));
    }
    let etiqueta = conexion.label.as_ref();
    if mostrar_nombres {
        match etiqueta.and_then(|valor| valor.server_name.clone()) {
            Some(nombre) => spans.push(Span::styled(nombre, theme.normal)),
            None => {
                spans.push(Span::styled(servidor.ip.to_string(), theme.normal));
                let subtitulo = etiqueta
                    .map(|valor| valor.destination.subtitle())
                    .unwrap_or_default();
                if !subtitulo.is_empty() {
                    spans.push(Span::styled(format!(" ({subtitulo})"), theme.dim));
                }
            }
        }
    } else {
        spans.push(Span::styled(servidor.ip.to_string(), theme.normal));
    }
    Cell::from(Line::from(spans))
}

fn draw_cabeceras(frame: &mut Frame, app: &App, area: Rect) {
    let Some(panel) = app.headers.as_ref() else {
        return;
    };
    let conexion = &panel.connection;
    let titulo = format!(
        "Detalle de conexión — {} {} → {} (Esc cierra)",
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
    lineas.push(Line::from(vec![
        Span::styled("Rol: ", app.theme.accent),
        Span::styled(rol_label(conexion), app.theme.normal),
    ]));
    lineas.push(Line::from(vec![
        Span::styled("Servidor: ", app.theme.accent),
        Span::styled(servidor_label(conexion), app.theme.normal),
        Span::styled(
            format!(" · fuente del nombre: {}", fuente_nombre(conexion)),
            app.theme.dim,
        ),
    ]));
    lineas.push(Line::from(vec![
        Span::styled("App: ", app.theme.accent),
        Span::styled(conexion.app_label(), app.theme.normal),
        Span::styled(
            format!(
                " · categoría: {} · fuente: {}",
                conexion.category_label(),
                fuente_app(conexion)
            ),
            app.theme.dim,
        ),
    ]));
    lineas.push(Line::from(vec![
        Span::styled("JA4: ", app.theme.accent),
        Span::styled(ja4_label(conexion), app.theme.normal),
    ]));
    if let Some(proceso) = conexion.process_label() {
        lineas.push(Line::from(Span::styled(
            format!("Proceso local: {proceso}"),
            app.theme.accent,
        )));
    }

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

/// Texto del rol cliente/servidor de la conexión.
pub fn rol_label(conexion: &ConnectionView) -> String {
    match conexion
        .label
        .as_ref()
        .and_then(|etiqueta| etiqueta.client_is_src)
    {
        Some(true) => "cliente en el origen · servidor en el destino".to_string(),
        Some(false) => "cliente en el destino · servidor en el origen".to_string(),
        None => "desconocido (orden canónico origen → destino)".to_string(),
    }
}

fn servidor_label(conexion: &ConnectionView) -> String {
    match conexion
        .label
        .as_ref()
        .and_then(|etiqueta| etiqueta.server_name.clone())
    {
        Some(nombre) => nombre,
        None => conexion.server_label(),
    }
}

fn fuente_nombre(conexion: &ConnectionView) -> String {
    conexion
        .label
        .as_ref()
        .and_then(|etiqueta| etiqueta.name_source)
        .map(|fuente| fuente.label().to_string())
        .unwrap_or_else(|| "sin nombre".to_string())
}

fn fuente_app(conexion: &ConnectionView) -> String {
    conexion
        .label
        .as_ref()
        .and_then(|etiqueta| etiqueta.app_source)
        .map(|fuente| fuente.label().to_string())
        .unwrap_or_else(|| "sin identificar".to_string())
}

fn ja4_label(conexion: &ConnectionView) -> String {
    match conexion
        .label
        .as_ref()
        .and_then(|etiqueta| etiqueta.ja4.clone())
    {
        Some(huella) => huella,
        None => "—".to_string(),
    }
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
    use crate::capture::{ConnectionKey, Endpoint, Protocol as CaptureProtocol};
    use crate::config::Config;
    use crate::inference::{AppSource, DestinationInfo, DestinationKind, FlowLabel, NameSource};
    use crate::repo::devices::Device;
    use crate::traffic::EndpointView;
    use crate::tui::app::App;
    use crate::tui::traffic_state::ConnectionFilter;
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
            mac: "00:1a:2b:3c:4d:01".to_string(),
            ip: "192.168.1.42".to_string(),
            hostname: Some("laptop-juan".to_string()),
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

    fn etiqueta() -> FlowLabel {
        let mut etiqueta = FlowLabel::empty(ip("1.1.1.1"));
        etiqueta.client_is_src = Some(true);
        etiqueta.app_protocol = Some(crate::inference::AppProtocol::Tls);
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
        etiqueta
    }

    fn conexion() -> ConnectionView {
        ConnectionView {
            key: ConnectionKey::from_endpoints(
                CaptureProtocol::Tcp,
                Endpoint::new(ip("192.168.1.42"), Some(40000)),
                Endpoint::new(ip("1.1.1.1"), Some(443)),
            ),
            state: Some("ESTABLISHED".to_string()),
            bytes_in: 900,
            bytes_out: 100,
            age: Duration::from_secs(120),
            idle: Duration::from_secs(2),
            pid: Some(1234),
            comm: Some("firefox".to_string()),
            device_id: Some(1),
            origin: EndpointView {
                ip: ip("192.168.1.42"),
                port: Some(40000),
                device_id: Some(1),
                tag: None,
            },
            destination: EndpointView {
                ip: ip("1.1.1.1"),
                port: Some(443),
                device_id: None,
                tag: Some("?"),
            },
            headers: None,
            seen_capture: true,
            seen_kernel: true,
            label: Some(etiqueta()),
            app_name: Some("GitHub".to_string()),
            category_name: Some("Desarrollo".to_string()),
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
        app.set_data(vec![dispositivo()], Vec::new());
        app.traffic.connections = conexiones;
        app.traffic.connections_total = app.traffic.connections.len();
        app
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| draw(frame, app, frame.area()))
            .expect("dibujado de Conexiones");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn la_tabla_muestra_las_columnas_de_f4_a_ochenta_columnas() {
        let mut app = app_con(vec![conexion()]);
        let texto = dibujar(&mut app, 80, 24);
        for columna in ["Prot.", "Equipo", "Destino", "App", "↑", "↓", "Edad"] {
            assert!(texto.contains(columna), "falta la columna {columna}");
        }
        assert!(
            !texto.contains("Estado"),
            "a 80 columnas no se muestra el Estado"
        );
        assert!(texto.contains("tls"), "Prot. usa el protocolo de app");
        assert!(texto.contains("GitHub"));
    }

    #[test]
    fn el_estado_aparece_a_partir_de_cien_columnas() {
        let mut app = app_con(vec![conexion()]);
        let texto = dibujar(&mut app, 120, 24);
        assert!(texto.contains("Estado"));
        assert!(
            texto.contains("ESTABLISH"),
            "el estado aparece aunque se recorte"
        );
    }

    #[test]
    fn el_destino_muestra_el_servidor_y_si_no_hay_ip_con_organizacion() {
        let mut sin_nombre = conexion();
        sin_nombre.label.as_mut().unwrap().server_name = None;
        sin_nombre.app_name = Some("Sin identificar".to_string());
        let mut app = app_con(vec![conexion(), sin_nombre]);
        let texto = dibujar(&mut app, 160, 24);
        assert!(texto.contains("github.com"));
        assert!(
            texto.contains("1.1.1.1 (GitHub · US)"),
            "sin nombre se muestra la IP con organización y país"
        );
    }

    #[test]
    fn la_tecla_i_alterna_nombres_e_ips() {
        let mut app = app_con(vec![conexion()]);
        let texto = dibujar(&mut app, 140, 24);
        assert!(texto.contains("laptop-juan"));
        assert!(texto.contains("github.com"));

        app.show_names = false;
        let texto = dibujar(&mut app, 140, 24);
        assert!(texto.contains("vista: IPs"));
        assert!(texto.contains("192.168.1.42"));
        assert!(texto.contains("1.1.1.1"));
        assert!(
            !texto.contains("laptop-juan"),
            "en modo IPs no se pinta el nombre del equipo"
        );
        assert!(!texto.contains("github.com"));
    }

    #[test]
    fn sin_rol_se_marca_el_destino_con_interrogacion() {
        let mut conexion = conexion();
        conexion.label.as_mut().unwrap().client_is_src = None;
        let mut app = app_con(vec![conexion]);
        let texto = dibujar(&mut app, 140, 24);
        assert!(
            texto.contains("?github.com"),
            "sin rol la fila va en orden canónico con ? delante del destino"
        );
    }

    #[test]
    fn el_equipo_es_el_lado_cliente_aunque_el_cliente_sea_el_destino() {
        let mut conexion = conexion();
        conexion.label.as_mut().unwrap().client_is_src = Some(false);
        conexion.origin.device_id = None;
        conexion.origin.tag = Some("?");
        conexion.destination.device_id = Some(1);
        conexion.destination.tag = None;
        let mut app = app_con(vec![conexion]);
        let texto = dibujar(&mut app, 160, 24);
        assert!(
            texto.contains("laptop-juan"),
            "el equipo se pinta como cliente"
        );
        // La subida es el sentido cliente → servidor: el cliente recibe 900.
        assert!(texto.contains("900"));
    }

    #[test]
    fn el_panel_v_muestra_rol_fuentes_ja4_y_proceso() {
        let mut app = app_con(vec![conexion()]);
        assert!(app.open_headers());
        let texto = dibujar(&mut app, 160, 40);
        assert!(texto.contains("Detalle de conexión"));
        assert!(texto.contains("Rol: cliente en el origen"));
        assert!(texto.contains("fuente del nombre: SNI"));
        assert!(texto.contains("fuente: dominio"));
        assert!(texto.contains("JA4: t13d"));
        assert!(texto.contains("Proceso local: 1234 firefox"));
        assert!(texto.contains("GitHub"));
        assert!(texto.contains("Desarrollo"));
    }

    #[test]
    fn el_panel_v_sin_cabeceras_avisa_sin_panico() {
        let mut app = app_con(vec![conexion()]);
        assert!(app.open_headers());
        let texto = dibujar(&mut app, 120, 34);
        assert!(texto.contains("Sin cabeceras en memoria"));
    }

    #[test]
    fn la_app_sin_etiqueta_sale_sin_identificar() {
        let mut conexion = conexion();
        conexion.label = None;
        conexion.app_name = None;
        conexion.category_name = None;
        let mut app = app_con(vec![conexion]);
        let texto = dibujar(&mut app, 140, 24);
        assert!(texto.contains("Sin identificar"));
    }

    #[test]
    fn el_filtro_por_proceso_y_la_busqueda_se_ven_en_el_titulo() {
        let mut app = app_con(vec![conexion()]);
        app.conn_filter = ConnectionFilter::Proceso {
            pid: Some(1234),
            comm: "firefox".to_string(),
        };
        app.conn_search = "github".to_string();
        let texto = dibujar(&mut app, 200, 24);
        assert!(texto.contains("proceso firefox (1234)"));
        assert!(texto.contains("búsqueda:"));
        assert!(texto.contains("github"));
    }

    #[test]
    fn sin_conexiones_muestra_mensajes_distintos_por_filtro() {
        let mut app = app_con(vec![conexion()]);
        app.conn_filter = ConnectionFilter::Proceso {
            pid: Some(999),
            comm: "curl".to_string(),
        };
        let texto = dibujar(&mut app, 120, 24);
        assert!(texto.contains("No hay conexiones del proceso seleccionado"));

        app.conn_filter = ConnectionFilter::Todas;
        app.conn_search = "no-existe".to_string();
        let texto = dibujar(&mut app, 120, 24);
        assert!(texto.contains("No hay conexiones que coincidan con la búsqueda"));
    }
}
