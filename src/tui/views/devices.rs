//! Vista principal: lista detallada de equipos descubiertos.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::repo::devices::Device;
use crate::tui::app::{App, Filter};
use crate::tui::theme::Theme;

/// Dibuja la pestaña Equipos.
pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let indices = app.visible_indices();
    let total = app.devices.len();
    let visibles = indices.len();
    let titulo = if app.filter == Filter::Alert {
        "Equipos — el filtro de alertas no está disponible en Fase 1".to_string()
    } else if !app.effective_search().is_empty() {
        format!("Equipos — {visibles} resultado(s) de {total}")
    } else {
        format!("Equipos — {visibles} equipos")
    };

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

    // Columnas base pensadas para 80x24; el espacio extra se reparte entre
    // hostname y MAC/fabricante. Hay cinco separaciones entre las seis columnas.
    let base: [u16; 6] = [5, 15, 16, 22, 7, 8];
    let fijo: u16 = base.iter().sum::<u16>() + 5;
    let extra = interior.width.saturating_sub(fijo);
    let extra_hostname = extra / 2;
    let extra_mac = extra - extra_hostname;
    let anchos = vec![
        Constraint::Length(base[0]),
        Constraint::Length(base[1]),
        Constraint::Length(base[2] + extra_hostname),
        Constraint::Length(base[3] + extra_mac),
        Constraint::Length(base[4]),
        Constraint::Length(base[5]),
    ];

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

    let tabla = Table::new(filas, anchos)
        .header(cabecera)
        .column_spacing(1)
        .row_highlight_style(app.theme.selected)
        .highlight_symbol(Span::styled("▸ ", app.theme.accent))
        .style(app.theme.normal);

    *app.table_state.selected_mut() = Some(app.selected);
    frame.render_stateful_widget(tabla, interior, &mut app.table_state);
}

fn fila(device: &Device, theme: &Theme) -> Row<'static> {
    let (icono, estilo_icono) = if !device.is_online {
        ("○", theme.offline)
    } else if device.is_gateway() {
        ("[⌂]", theme.accent)
    } else {
        ("[?]", theme.normal)
    };
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
        let estilo = Style::default()
            .fg(theme.offline.fg.unwrap_or_default())
            .add_modifier(Modifier::DIM);
        Span::styled("offline", estilo)
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

#[cfg(test)]
mod tests {
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_con(devices: Vec<crate::repo::devices::Device>) -> App {
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

    fn dispositivo(id: i64, ip: &str, online: bool, gateway: bool) -> crate::repo::devices::Device {
        crate::repo::devices::Device {
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
        }
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

    #[test]
    fn lista_muestra_columnas_e_iconos() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = app_con(vec![
            dispositivo(1, "10.0.0.1", true, true),
            dispositivo(2, "10.0.0.2", true, false),
            dispositivo(3, "10.0.0.3", false, false),
        ]);
        terminal
            .draw(|frame| super::draw(frame, &mut app, frame.area()))
            .unwrap();
        let contenido = texto(&terminal);
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
    fn busqueda_vacia_muestra_aviso() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = app_con(vec![]);
        terminal
            .draw(|frame| super::draw(frame, &mut app, frame.area()))
            .unwrap();
        assert!(texto(&terminal).contains("Todavía no hay equipos"));
    }

    #[test]
    fn filtro_alertas_muestra_aviso() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = app_con(vec![dispositivo(1, "10.0.0.1", true, false)]);
        app.filter = crate::tui::app::Filter::Alert;
        terminal
            .draw(|frame| super::draw(frame, &mut app, frame.area()))
            .unwrap();
        let contenido = texto(&terminal);
        assert!(contenido.contains("No hay alertas"));
    }
}
