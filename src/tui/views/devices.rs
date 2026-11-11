//! Vista principal: lista detallada de equipos descubiertos.
//!
//! Hay dos modos de presentación según la preferencia `[ui].list_view`: la lista
//! plana (comportamiento de Fase 1) y la lista agrupada por categoría, con una
//! cabecera de sección por cada grupo no vacío. La selección de [App] es siempre
//! un índice de la lista visible de equipos (sin contar cabeceras); la vista
//! agrupada la traduce a la fila correspondiente de la tabla.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::classify::DeviceGroup;
use crate::config::ListView;
use crate::identify::mac::is_private;
use crate::repo::devices::Device;
use crate::tui::app::{grupo_de, App, Filter};
use crate::tui::theme::{device_icon, Theme};
use crate::tui::traffic_state::{FocusPanel, DETAIL_MIN_WIDTH};

use super::device_detail;

/// Anchos de las columnas de la lista de equipos.
#[derive(Debug, Clone, Copy)]
struct Columnas {
    icono: u16,
    ip: u16,
    hostname: u16,
    fabricante: u16,
    trafico: u16,
    estado: u16,
}

impl Columnas {
    /// Reparte el ancho disponible entre las columnas base pensadas para 80x24.
    ///
    /// Hay cinco separaciones entre las seis columnas; el espacio extra se
    /// reparte entre hostname y MAC/fabricante.
    fn para(ancho: u16) -> Self {
        let base: [u16; 6] = [5, 15, 16, 22, 7, 8];
        let fijo: u16 = base.iter().sum::<u16>() + 5;
        let extra = ancho.saturating_sub(fijo);
        let extra_hostname = extra / 2;
        let extra_mac = extra - extra_hostname;
        Self {
            icono: base[0],
            ip: base[1],
            hostname: base[2] + extra_hostname,
            fabricante: base[3] + extra_mac,
            trafico: base[4],
            estado: base[5],
        }
    }

    /// Reparte el ancho de la vista agrupada.
    ///
    /// La vista agrupada reparte las columnas a mano (una única columna de
    /// tabla); se reserva un carácter más para MAC/Fabricante y uno menos para
    /// hostname, de modo que a 80 columnas el fabricante no se recorte.
    fn para_agrupada(ancho: u16) -> Self {
        let base: [u16; 6] = [5, 15, 15, 23, 7, 8];
        let fijo: u16 = base.iter().sum::<u16>() + 5;
        let extra = ancho.saturating_sub(fijo);
        let extra_hostname = extra / 2;
        let extra_mac = extra - extra_hostname;
        Self {
            icono: base[0],
            ip: base[1],
            hostname: base[2] + extra_hostname,
            fabricante: base[3] + extra_mac,
            trafico: base[4],
            estado: base[5],
        }
    }

    /// Restricciones de ancho para la tabla plana.
    fn constraints(self) -> Vec<Constraint> {
        vec![
            Constraint::Length(self.icono),
            Constraint::Length(self.ip),
            Constraint::Length(self.hostname),
            Constraint::Length(self.fabricante),
            Constraint::Length(self.trafico),
            Constraint::Length(self.estado),
        ]
    }
}

/// Marcas de F6 tras el icono de un equipo (§6, mockup 5): `*` si está
/// vigilado (§7.7) y `!` si tiene alertas importantes o avisos sin ver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Marcas {
    /// El equipo está vigilado (`DEVICES.watched`).
    vigilado: bool,
    /// Tiene alertas importantes o de aviso sin ver.
    alertas: bool,
}

impl Marcas {
    /// Marcas del equipo con el estado que publica [App].
    fn de(app: &App, device: &Device) -> Self {
        Self {
            vigilado: device.watched,
            alertas: app.alerts.has_unseen(device.id),
        }
    }
}

/// Spans de la celda del icono: icono, marcas de F6 y relleno hasta el ancho.
///
/// Las marcas van tras el icono y no dependen solo del color (§6).
fn spans_icono(
    icono: &'static str,
    estilo: Style,
    marcas: Marcas,
    ancho: usize,
    theme: &Theme,
) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(icono, estilo)];
    if marcas.vigilado {
        spans.push(Span::styled("*", theme.accent));
    }
    if marcas.alertas {
        spans.push(Span::styled("!", theme.warning));
    }
    let ocupado =
        icono.chars().count() + usize::from(marcas.vigilado) + usize::from(marcas.alertas);
    if ancho > ocupado {
        spans.push(Span::styled(" ".repeat(ancho - ocupado), theme.normal));
    }
    spans
}

/// Dibuja la pestaña Equipos, con el panel master-detail si está abierto.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.detail_open() {
        draw_master_detail(frame, app, area);
    } else {
        draw_lista(frame, app, area);
    }
}

/// Reparto master-detail: mitad derecha en pantallas anchas, pantalla completa
/// con foco alternable en pantallas estrechas.
fn draw_master_detail(frame: &mut Frame, app: &mut App, area: Rect) {
    if area.width >= DETAIL_MIN_WIDTH {
        let columnas = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        draw_lista(frame, app, columnas[0]);
        device_detail::draw(frame, app, columnas[1]);
    } else {
        match app.detail_focus {
            FocusPanel::Lista => draw_lista(frame, app, area),
            FocusPanel::Detalle => device_detail::draw(frame, app, area),
        }
    }
}

fn draw_lista(frame: &mut Frame, app: &mut App, area: Rect) {
    let indices = app.visible_indices();
    let total = app.devices.len();
    let visibles = indices.len();
    let base = if app.filter == Filter::Alert {
        "Equipos — el filtro de alertas no está disponible".to_string()
    } else if !app.effective_search().is_empty() {
        format!("Equipos — {visibles} resultado(s) de {total}")
    } else {
        format!("Equipos — {visibles} equipos")
    };
    // Pista de la vista siguiente, como en los mockups (arriba a la derecha).
    let pista = match app.list_view {
        ListView::Flat => "[g]agrupar",
        ListView::Grouped => "[g]plana",
    };
    let titulo = format!("{base} · {pista}");

    let estilo_borde = if app.detail_open() && app.detail_focus == FocusPanel::Lista {
        app.theme.accent
    } else {
        app.theme.border
    };
    let bloque = Block::bordered()
        .border_style(estilo_borde)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    // Pie del contenido: la leyenda de las marcas de F6 (bajo la lista) y la
    // línea «Último evento» de F5. Se ocultan si no caben o si el texto no cabe
    // en el ancho disponible (§6, mockup 5).
    let mut pies: Vec<Line<'static>> = Vec::new();
    if !indices.is_empty() {
        if let Some(leyenda) = linea_leyenda(app, interior.width) {
            pies.push(leyenda);
        }
    }
    if let Some(evento) = linea_ultimo_evento(app, interior.width) {
        pies.push(evento);
    }
    let alto_pie = u16::try_from(pies.len()).unwrap_or(u16::MAX);
    let (area_lista, area_pie) = if alto_pie > 0 && interior.height > alto_pie + 2 {
        let filas =
            Layout::vertical([Constraint::Min(1), Constraint::Length(alto_pie)]).split(interior);
        (filas[0], Some(filas[1]))
    } else {
        (interior, None)
    };

    if indices.is_empty() {
        let mensaje = if app.filter == Filter::Alert {
            "No hay alertas: esta pestaña llegará en una fase posterior"
        } else if !app.effective_search().is_empty() || app.filter != Filter::All {
            "Ningún equipo coincide con el filtro o la búsqueda"
        } else {
            "Todavía no hay equipos. Pulsa [r] para escanear la red"
        };
        let parrafo =
            Paragraph::new(Span::styled(mensaje, app.theme.dim)).alignment(Alignment::Center);
        let filas = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(area_lista);
        frame.render_widget(parrafo, filas[1]);
    } else {
        match app.list_view {
            ListView::Flat => draw_flat(frame, app, &indices, area_lista),
            ListView::Grouped => draw_grouped(frame, app, &indices, area_lista),
        }
    }
    if let Some(area) = area_pie {
        frame.render_widget(Paragraph::new(pies), area);
    }
}

/// Línea «Último evento: hace N min · <equipo> <qué pasó>».
///
/// Devuelve None si todavía no hay evento o si el texto no cabe en el ancho
/// disponible (se oculta sin recortar).
fn linea_ultimo_evento(app: &App, ancho: u16) -> Option<Line<'static>> {
    let evento = app.history.last_event.as_ref()?;
    let ahora = crate::history::localtime::now_unix();
    let hace = hace_cuanto(ahora.saturating_sub(evento.at_unix));
    let detalle = match &evento.device_label {
        Some(equipo)
            if !evento
                .summary
                .to_lowercase()
                .contains(&equipo.to_lowercase()) =>
        {
            format!("{equipo}: {}", evento.summary)
        }
        _ => evento.summary.clone(),
    };
    let texto = format!("Último evento: hace {hace} · {detalle}");
    if texto.chars().count() > usize::from(ancho) {
        return None;
    }
    Some(Line::from(vec![
        Span::styled("Último evento: ", app.theme.accent),
        Span::styled(format!("hace {hace}"), app.theme.dim),
        Span::styled(" · ", app.theme.dim),
        Span::styled(detalle, app.theme.normal),
    ]))
}

/// Leyenda de las marcas de la lista de equipos (§6, mockup 5).
///
/// El mockup pide «* vigilado · ! alertas sin ver»; si el pie de teclas ya
/// anuncia `[p]vigilar` (keys.rs) no se repite aquí. Se oculta si no cabe.
fn linea_leyenda(app: &App, ancho: u16) -> Option<Line<'static>> {
    const BASE: &str = "* vigilado · ! alertas sin ver";
    const EXTRA: &str = " · [p]vigilar";
    let disponible = usize::from(ancho);
    if BASE.chars().count() > disponible {
        return None;
    }
    let mut spans = vec![
        Span::styled("*", app.theme.accent),
        Span::styled(" vigilado · ", app.theme.dim),
        Span::styled("!", app.theme.warning),
        Span::styled(" alertas sin ver", app.theme.dim),
    ];
    let pie_lo_dice = crate::tui::keys::FOOTER_EQUIPOS
        .iter()
        .any(|linea| linea.contains("[p]"));
    if !pie_lo_dice && BASE.chars().count() + EXTRA.chars().count() <= disponible {
        spans.push(Span::styled(EXTRA, app.theme.dim));
    }
    Some(Line::from(spans))
}

/// Texto de «hace cuánto» de un evento («2 min», «3 h», «2 d»).
fn hace_cuanto(segundos: i64) -> String {
    let segundos = segundos.max(0);
    if segundos < 60 {
        format!("{segundos} s")
    } else if segundos < 3600 {
        format!("{} min", segundos / 60)
    } else if segundos < 86_400 {
        format!("{} h", segundos / 3600)
    } else {
        format!("{} d", segundos / 86_400)
    }
}

/// Lista plana de Fase 1 (con los iconos extendidos de Fase 2).
fn draw_flat(frame: &mut Frame, app: &mut App, indices: &[usize], area: Rect) {
    let columnas = Columnas::para(area.width);
    let cabecera = Row::new(vec![
        "Icono",
        "IP",
        "Hostname",
        "MAC/Fabricante",
        "Tráfico",
        "Estado",
    ])
    .style(app.theme.accent);

    let filas: Vec<Row> = indices
        .iter()
        .map(|indice| fila(app, &app.devices[*indice], columnas.icono))
        .collect();

    let tabla = Table::new(filas, columnas.constraints())
        .header(cabecera)
        .column_spacing(1)
        .row_highlight_style(app.theme.selected)
        .highlight_symbol(Span::styled("▸ ", app.theme.accent))
        .style(app.theme.normal);

    *app.table_state.selected_mut() = Some(app.selected);
    frame.render_stateful_widget(tabla, area, &mut app.table_state);
}

/// Lista agrupada por categoría con cabeceras de sección.
fn draw_grouped(frame: &mut Frame, app: &mut App, indices: &[usize], area: Rect) {
    let columnas = Columnas::para_agrupada(area.width);
    let mut filas: Vec<Row> = Vec::new();
    let mut fila_seleccionada: Option<usize> = None;
    let mut grupo_anterior: Option<DeviceGroup> = None;

    for (posicion, indice) in indices.iter().enumerate() {
        let device = &app.devices[*indice];
        let grupo = grupo_de(device);
        if grupo_anterior != Some(grupo) {
            filas.push(cabecera_grupo(grupo, area.width, &app.theme));
            grupo_anterior = Some(grupo);
        }
        if posicion == app.selected {
            fila_seleccionada = Some(filas.len());
        }
        filas.push(fila_agrupada(app, device, columnas));
    }

    // Una única columna con la línea completa ya formateada: así las cabeceras
    // de grupo pueden ocupar todo el ancho sin encajar en las columnas.
    let tabla = Table::new(filas, [Constraint::Fill(1)])
        .column_spacing(0)
        .row_highlight_style(app.theme.selected)
        .style(app.theme.normal);

    *app.table_state.selected_mut() = Some(fila_seleccionada.unwrap_or(0));
    frame.render_stateful_widget(tabla, area, &mut app.table_state);
}

/// Fila de la lista plana, con las marcas de F6 tras el icono.
fn fila(app: &App, device: &Device, ancho_icono: u16) -> Row<'static> {
    let theme = &app.theme;
    let (icono, estilo_icono) = device_icon(device, theme);
    let marcas = Marcas::de(app, device);
    let celda_icono = spans_icono(icono, estilo_icono, marcas, usize::from(ancho_icono), theme);
    let fabricante = texto_fabricante(device);
    let hostname = device.display_name().to_string();
    let estilo_hostname = if device.alias.is_some() {
        theme.accent.add_modifier(Modifier::BOLD)
    } else {
        theme.normal
    };
    let estado = if device.is_online {
        Span::styled("online", theme.online)
    } else {
        Span::styled("offline", theme.offline)
    };

    Row::new(vec![
        Cell::from(Line::from(celda_icono)),
        Cell::from(Span::raw(device.ip.clone())),
        Cell::from(Span::styled(hostname, estilo_hostname)),
        Cell::from(Span::styled(fabricante, theme.dim)),
        Cell::from(Span::styled("—", theme.dim)),
        Cell::from(estado),
    ])
}

/// Fila de un equipo en la vista agrupada (línea formateada a mano).
///
/// La columna del icono reserva sitio para las dos marcas de F6 (`*` y `!`),
/// de modo que todos los equipos quedan alineados (§6, mockup 5).
fn fila_agrupada(app: &App, device: &Device, columnas: Columnas) -> Row<'static> {
    let theme = &app.theme;
    let (icono, estilo_icono) = device_icon(device, theme);
    let marcas = Marcas::de(app, device);
    let fabricante = texto_fabricante(device);
    let hostname = device.display_name().to_string();
    let estilo_hostname = if device.alias.is_some() {
        theme.accent.add_modifier(Modifier::BOLD)
    } else {
        theme.normal
    };
    let estilo_estado = if device.is_online {
        theme.online
    } else {
        theme.offline
    };
    let texto_estado = if device.is_online {
        "online"
    } else {
        "offline"
    };

    let mut spans = spans_icono(
        icono,
        estilo_icono,
        marcas,
        usize::from(columnas.icono),
        theme,
    );
    spans.extend([
        Span::styled(" ", theme.normal),
        Span::styled(ajustar(&device.ip, usize::from(columnas.ip)), theme.normal),
        Span::styled(" ", theme.normal),
        Span::styled(
            ajustar(&hostname, usize::from(columnas.hostname)),
            estilo_hostname,
        ),
        Span::styled(" ", theme.normal),
        Span::styled(
            ajustar(&fabricante, usize::from(columnas.fabricante)),
            theme.dim,
        ),
        Span::styled(" ", theme.normal),
        Span::styled(ajustar("—", usize::from(columnas.trafico)), theme.dim),
        Span::styled(" ", theme.normal),
        Span::styled(
            ajustar(texto_estado, usize::from(columnas.estado)),
            estilo_estado,
        ),
    ]);

    Row::new(vec![Cell::from(Line::from(spans))])
}

/// Texto de la columna Fabricante: MAC y OUI, o «MAC privada» si el bit U/L
/// está activo (F4, §7.13).
fn texto_fabricante(device: &Device) -> String {
    if is_private(&device.mac) {
        return format!("{} MAC privada", device.mac);
    }
    let vendor = device.vendor.clone().unwrap_or_else(|| "?".to_string());
    format!("{} {}", device.mac, vendor)
}

/// Cabecera de sección de la vista agrupada: «── Etiqueta ──────».
fn cabecera_grupo(grupo: DeviceGroup, ancho: u16, theme: &Theme) -> Row<'static> {
    let etiqueta = format!("── {} ", grupo.label());
    let usado = etiqueta.chars().count();
    let relleno = "─".repeat(usize::from(ancho).saturating_sub(usado));
    let linea = Line::from(Span::styled(format!("{etiqueta}{relleno}"), theme.accent));
    Row::new(vec![Cell::from(linea)])
}

/// Recorta o rellena un texto hasta un ancho fijo en caracteres.
fn ajustar(texto: &str, ancho: usize) -> String {
    if ancho == 0 {
        return String::new();
    }
    let mut recortado: String = texto.chars().take(ancho).collect();
    let largo = recortado.chars().count();
    recortado.push_str(&" ".repeat(ancho.saturating_sub(largo)));
    recortado
}

#[cfg(test)]
mod tests {
    use super::{hace_cuanto, linea_leyenda};
    use crate::capabilities::Capabilities;
    use crate::config::{Config, ListView};
    use crate::repo::devices::Device;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_con(devices: Vec<Device>) -> App {
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
        app.set_data(devices, Vec::new());
        app
    }

    fn app_agrupada(devices: Vec<Device>) -> App {
        let mut app = app_con(devices);
        app.list_view = ListView::Grouped;
        app
    }

    fn dispositivo(id: i64, ip: &str, online: bool, gateway: bool) -> Device {
        Device {
            id,
            mac: format!("00:1a:2b:3c:4d:{:02x}", id % 256),
            ip: ip.to_string(),
            hostname: Some(format!("equipo-{id}")),
            vendor: Some("Apple".to_string()),
            interface_id: 1,
            device_type: if gateway { "gateway" } else { "unknown" }.to_string(),
            is_online: online,
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

    fn dispositivo_de_tipo(id: i64, ip: &str, tipo: &str) -> Device {
        let mut device = dispositivo(id, ip, true, false);
        device.device_type = tipo.to_string();
        device
    }

    fn texto(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    fn dibujar(app: &mut App, ancho: u16, alto: u16) -> String {
        let backend = TestBackend::new(ancho, alto);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| super::draw(frame, app, frame.area()))
            .expect("dibujado de la lista");
        texto(&terminal)
    }

    #[test]
    fn lista_muestra_columnas_e_iconos() {
        let mut app = app_con(vec![
            dispositivo(1, "10.0.0.1", true, true),
            dispositivo(2, "10.0.0.2", true, false),
            dispositivo(3, "10.0.0.3", false, false),
        ]);
        let contenido = dibujar(&mut app, 100, 24);
        assert!(contenido.contains("MAC/Fabricante"));
        assert!(contenido.contains("Tráfico"));
        assert!(contenido.contains("[⌂]"));
        assert!(contenido.contains("[?]"));
        assert!(contenido.contains("○"));
        assert!(contenido.contains("online"));
        assert!(contenido.contains("offline"));
        assert!(contenido.contains("10.0.0.2"));
    }

    #[test]
    fn iconos_extendidos_por_tipo() {
        let mut devices = Vec::new();
        for (indice, tipo) in [
            "gateway",
            "pc",
            "server",
            "nas",
            "mobile",
            "tablet",
            "tv",
            "streaming",
            "printer",
            "camera",
            "iot",
            "unknown",
        ]
        .iter()
        .enumerate()
        {
            devices.push(dispositivo_de_tipo(
                indice as i64 + 1,
                &format!("10.0.0.{}", indice + 1),
                tipo,
            ));
        }
        devices.push(dispositivo(99, "10.0.0.99", false, false));
        let mut app = app_con(devices);
        let contenido = dibujar(&mut app, 100, 34);
        for icono in ["[⌂]", "[▣]", "[▯]", "[▶]", "[P]", "[C]", "[●]", "[?]", "○"] {
            assert!(contenido.contains(icono), "falta el icono {icono}");
        }
    }

    #[test]
    fn busqueda_vacia_muestra_aviso() {
        let mut app = app_con(vec![]);
        assert!(dibujar(&mut app, 100, 24).contains("Todavía no hay equipos"));
    }

    #[test]
    fn filtro_alertas_muestra_aviso() {
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, false)]);
        app.filter = crate::tui::app::Filter::Alert;
        let contenido = dibujar(&mut app, 100, 24);
        assert!(contenido.contains("No hay alertas"));
    }

    #[test]
    fn vista_agrupada_muestra_cabeceras_solo_de_grupos_no_vacios() {
        let mut app = app_agrupada(vec![
            dispositivo_de_tipo(1, "10.0.0.1", "gateway"),
            dispositivo_de_tipo(2, "10.0.0.10", "nas"),
            dispositivo_de_tipo(3, "10.0.0.42", "pc"),
            dispositivo_de_tipo(4, "10.0.0.57", "mobile"),
            dispositivo_de_tipo(5, "10.0.0.20", "printer"),
        ]);
        let contenido = dibujar(&mut app, 100, 30);
        for cabecera in [
            "── Infraestructura",
            "── Puestos y servidores",
            "── Móviles y tablets",
            "── Impresoras",
        ] {
            assert!(contenido.contains(cabecera), "falta la cabecera {cabecera}");
        }
        for vacio in ["TV y streaming", "Cámaras", "IoT", "Desconocidos"] {
            assert!(
                !contenido.contains(vacio),
                "no debe mostrarse el grupo vacío {vacio}"
            );
        }
        assert!(contenido.contains("10.0.0.42"));
    }

    #[test]
    fn vista_agrupada_cabe_en_ochenta_columnas_sin_recortar_fabricante() {
        let mut app = app_agrupada(vec![dispositivo_de_tipo(1, "10.0.0.1", "gateway")]);
        let contenido = dibujar(&mut app, 80, 24);
        assert!(contenido.contains("── Infraestructura"));
        assert!(
            contenido.contains("00:1a:2b:3c:4d:01 Apple"),
            "el MAC y el fabricante deben verse completos a 80 columnas"
        );
    }

    #[test]
    fn la_columna_fabricante_muestra_mac_privada() {
        let mut device = dispositivo_de_tipo(1, "10.0.0.1", "mobile");
        // 5a tiene el bit U/L (0x02) activo y el de grupo (0x01) a cero.
        device.mac = "5a:1c:2d:3e:4f:9e".to_string();
        let mut app = app_con(vec![device]);
        let contenido = dibujar(&mut app, 100, 24);
        assert!(
            contenido.contains("5a:1c:2d:3e:4f:9e MAC privada"),
            "una MAC con el bit U/L debe mostrarse como MAC privada"
        );
        assert!(
            !contenido.contains("5a:1c:2d:3e:4f:9e Apple"),
            "no se muestra el fabricante de una MAC privada"
        );

        // La vista agrupada usa el mismo texto.
        let mut app = app_agrupada(vec![dispositivo_de_tipo(2, "10.0.0.2", "pc")]);
        app.devices[0].mac = "5a:1c:2d:3e:4f:9e".to_string();
        let contenido = dibujar(&mut app, 100, 24);
        assert!(contenido.contains("MAC privada"));
    }

    #[test]
    fn seleccion_agrupada_mapea_a_la_fila_de_la_tabla() {
        let mut app = app_agrupada(vec![
            dispositivo_de_tipo(1, "10.0.0.1", "gateway"),
            dispositivo_de_tipo(2, "10.0.0.42", "pc"),
            dispositivo_de_tipo(3, "10.0.0.20", "printer"),
        ]);
        // Orden visible agrupado: gateway(0), pc(1), impresora(2). Cada grupo
        // tiene su cabecera: gateway en la fila 1, pc tras 2 cabeceras en la 3.
        app.selected = 1;
        dibujar(&mut app, 100, 30);
        assert_eq!(app.table_state.selected(), Some(3));

        app.selected = 0;
        dibujar(&mut app, 100, 30);
        assert_eq!(app.table_state.selected(), Some(1));

        app.selected = 2;
        dibujar(&mut app, 100, 30);
        assert_eq!(app.table_state.selected(), Some(5));
    }

    #[test]
    fn master_detail_ocupa_la_mitad_derecha_en_pantalla_ancha() {
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, true)]);
        app.open_detail(1, Vec::new(), false);
        let contenido = dibujar(&mut app, 120, 30);
        assert!(contenido.contains("Detalle:"), "falta el panel derecho");
        assert!(contenido.contains("equipo-1"), "falta la lista izquierda");
        assert!(contenido.contains("Tráfico"), "falta el bloque de tráfico");
    }

    #[test]
    fn master_detail_en_pantalla_estrecha_alterna_con_tab() {
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, true)]);
        app.open_detail(1, Vec::new(), true);
        let contenido = dibujar(&mut app, 80, 24);
        assert!(
            contenido.contains("Detalle:"),
            "con foco en detalle a pantalla completa"
        );
        app.toggle_detail_focus();
        assert_eq!(
            app.detail_focus,
            crate::tui::traffic_state::FocusPanel::Lista
        );
        let contenido = dibujar(&mut app, 80, 24);
        assert!(contenido.contains("Equipos"));
        assert!(!contenido.contains("Detalle: equipo-1"));
    }

    #[test]
    fn vista_plana_mantiene_la_seleccion_uno_a_uno() {
        let mut app = app_con(vec![
            dispositivo(1, "10.0.0.1", true, true),
            dispositivo(2, "10.0.0.2", true, false),
            dispositivo(3, "10.0.0.3", true, false),
        ]);
        app.selected = 2;
        dibujar(&mut app, 100, 24);
        assert_eq!(app.table_state.selected(), Some(2));
    }

    fn ultimo_evento(resumen: &str) -> crate::history::TimelineItem {
        let ahora = crate::history::localtime::now_unix();
        crate::history::TimelineItem {
            at: crate::history::localtime::rfc3339(ahora - 120),
            at_unix: ahora - 120,
            kind: crate::history::TimelineKind::Event,
            device_id: Some(1),
            device_label: Some("iPhone-Marta".to_string()),
            event_type: "reappeared".to_string(),
            summary: resumen.to_string(),
            session_reason: None,
        }
    }

    #[test]
    fn la_linea_de_ultimo_evento_se_muestra_encima_de_la_barra() {
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, true)]);
        app.history.last_event = Some(ultimo_evento("iPhone-Marta vuelve a estar en línea"));
        let contenido = dibujar(&mut app, 100, 24);
        assert!(contenido.contains("Último evento:"));
        assert!(contenido.contains("hace 2 min"));
        assert!(contenido.contains("iPhone-Marta vuelve a estar en línea"));
    }

    #[test]
    fn sin_ultimo_evento_no_se_muestra_la_linea() {
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, true)]);
        let contenido = dibujar(&mut app, 100, 24);
        assert!(!contenido.contains("Último evento:"));
    }

    #[test]
    fn la_linea_de_ultimo_evento_se_oculta_si_no_cabe() {
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, true)]);
        app.history.last_event = Some(ultimo_evento(&"x".repeat(90)));
        let contenido = dibujar(&mut app, 80, 24);
        assert!(!contenido.contains("Último evento:"));
    }

    #[test]
    fn el_texto_de_hace_cuanto_usa_minutos_horas_y_dias() {
        assert_eq!(hace_cuanto(30), "30 s");
        assert_eq!(hace_cuanto(120), "2 min");
        assert_eq!(hace_cuanto(3 * 3600), "3 h");
        assert_eq!(hace_cuanto(2 * 86_400), "2 d");
    }

    /// Equipo de tipo NAS (icono «[▣]») y vigilado.
    fn dispositivo_vigilado(id: i64, ip: &str) -> Device {
        let mut device = dispositivo_de_tipo(id, ip, "nas");
        device.watched = true;
        device
    }

    #[test]
    fn las_marcas_de_f6_van_tras_el_icono_en_la_vista_plana() {
        let mut app = app_con(vec![
            dispositivo_vigilado(1, "10.0.0.1"),
            dispositivo_de_tipo(2, "10.0.0.2", "pc"),
        ]);
        app.alerts.set_device_unseen(vec![2]);
        let contenido = dibujar(&mut app, 100, 24);
        assert!(
            contenido.contains("[▣]*"),
            "el equipo vigilado lleva * tras el icono"
        );
        assert!(
            contenido.contains("[▣]!"),
            "el equipo con alertas sin ver lleva ! tras el icono"
        );
        assert!(contenido.contains("* vigilado · ! alertas sin ver"));

        // Las mismas marcas y la leyenda en pantalla grande.
        let contenido = dibujar(&mut app, 120, 40);
        assert!(contenido.contains("[▣]*"));
        assert!(contenido.contains("[▣]!"));
        assert!(contenido.contains("* vigilado · ! alertas sin ver"));
    }

    #[test]
    fn sin_vigilado_ni_alertas_no_hay_marcas() {
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, false)]);
        let contenido = dibujar(&mut app, 120, 40);
        assert!(!contenido.contains("[?]*"));
        assert!(!contenido.contains("[?]!"));
        assert!(contenido.contains("[?]"), "el icono se sigue viendo");
    }

    #[test]
    fn las_marcas_y_la_leyenda_caben_en_ochenta_por_veinticuatro() {
        let mut app = app_con(vec![
            dispositivo_vigilado(1, "10.0.0.1"),
            dispositivo_de_tipo(2, "10.0.0.2", "pc"),
        ]);
        app.alerts.set_device_unseen(vec![2]);
        let contenido = dibujar(&mut app, 80, 24);
        assert!(contenido.contains("[▣]*"));
        assert!(contenido.contains("! alertas sin ver"));
        assert!(!contenido.contains("demasiado pequeño"));
    }

    #[test]
    fn la_vista_agrupada_tambien_muestra_las_marcas() {
        let mut app = app_agrupada(vec![dispositivo_vigilado(1, "10.0.0.1")]);
        app.alerts.set_device_unseen(vec![1]);
        let contenido = dibujar(&mut app, 80, 24);
        assert!(contenido.contains("[▣]*!"));
        assert!(contenido.contains("* vigilado · ! alertas sin ver"));
    }

    #[test]
    fn la_leyenda_anade_p_vigilar_solo_si_el_pie_no_lo_trae() {
        let app = app_con(vec![dispositivo(1, "10.0.0.1", true, false)]);
        let linea = linea_leyenda(&app, 80).expect("la leyenda cabe a 80 columnas");
        let texto: String = linea
            .spans
            .iter()
            .map(|span| span.content.clone())
            .collect();
        assert!(texto.starts_with("* vigilado · ! alertas sin ver"));
        let pie_lo_dice = crate::tui::keys::FOOTER_EQUIPOS
            .iter()
            .any(|linea| linea.contains("[p]"));
        assert_eq!(texto.contains("[p]vigilar"), !pie_lo_dice);
        // A un ancho mínimo que solo deja la leyenda base, no se añade nada.
        let estrecha = linea_leyenda(&app, 30).expect("la leyenda base cabe en 30");
        let texto_estrecho: String = estrecha
            .spans
            .iter()
            .map(|span| span.content.clone())
            .collect();
        assert_eq!(texto_estrecho, "* vigilado · ! alertas sin ver");
        assert!(linea_leyenda(&app, 10).is_none());
    }
}
