//! Vista principal: lista detallada de equipos descubiertos.
//!
//! Hay dos modos de presentación según la preferencia `[ui].list_view`: la lista
//! plana (comportamiento de Fase 1) y la lista agrupada por categoría, con una
//! cabecera de sección por cada grupo no vacío. La selección de [App] es siempre
//! un índice de la lista visible de equipos (sin contar cabeceras); la vista
//! agrupada la traduce a la fila correspondiente de la tabla.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::classify::DeviceGroup;
use crate::config::ListView;
use crate::repo::devices::Device;
use crate::tui::app::{grupo_de, App, Filter};
use crate::tui::theme::{device_icon, Theme};

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

/// Dibuja la pestaña Equipos.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
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

    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled(titulo, app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

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
        .split(interior);
        frame.render_widget(parrafo, filas[1]);
        return;
    }

    match app.list_view {
        ListView::Flat => draw_flat(frame, app, &indices, interior),
        ListView::Grouped => draw_grouped(frame, app, &indices, interior),
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
        .map(|indice| fila(&app.devices[*indice], &app.theme))
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
        filas.push(fila_agrupada(device, columnas, &app.theme));
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

/// Fila de la lista plana.
fn fila(device: &Device, theme: &Theme) -> Row<'static> {
    let (icono, estilo_icono) = device_icon(device, theme);
    let vendor = device.vendor.clone().unwrap_or_else(|| "?".to_string());
    let fabricante = format!("{} {}", device.mac, vendor);
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
        Cell::from(Span::styled(icono, estilo_icono)),
        Cell::from(Span::raw(device.ip.clone())),
        Cell::from(Span::styled(hostname, estilo_hostname)),
        Cell::from(Span::styled(fabricante, theme.dim)),
        Cell::from(Span::styled("—", theme.dim)),
        Cell::from(estado),
    ])
}

/// Fila de un equipo en la vista agrupada (línea formateada a mano).
fn fila_agrupada(device: &Device, columnas: Columnas, theme: &Theme) -> Row<'static> {
    let (icono, estilo_icono) = device_icon(device, theme);
    let vendor = device.vendor.clone().unwrap_or_else(|| "?".to_string());
    let fabricante = format!("{} {}", device.mac, vendor);
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
    let ancho_icono = usize::from(columnas.icono).saturating_sub(2);
    let texto_estado = if device.is_online {
        "online"
    } else {
        "offline"
    };

    let linea = Line::from(vec![
        Span::styled(format!("  {}", ajustar(icono, ancho_icono)), estilo_icono),
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

    Row::new(vec![Cell::from(linea)])
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
            mac: format!("aa:bb:cc:dd:ee:0{id}"),
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
            contenido.contains("aa:bb:cc:dd:ee:01 Apple"),
            "el MAC y el fabricante deben verse completos a 80 columnas"
        );
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
}
