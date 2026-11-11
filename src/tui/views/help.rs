//! Pestaña Ayuda: keybindings, pestañas, captura, inferencia y privacidad,
//! modos de descubrimiento, atribución de datos y aviso legal.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::App;

/// Dibuja la pestaña Ayuda.
pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let bloque = Block::bordered()
        .border_style(app.theme.border)
        .title(Span::styled("Ayuda", app.theme.title));
    let interior = bloque.inner(area);
    frame.render_widget(bloque, area);

    let mut lineas: Vec<Line> = Vec::new();
    lineas.push(Line::from(Span::styled(
        format!(
            "Almenara v{} — Fase 6: alertas locales y de escritorio",
            env!("CARGO_PKG_VERSION")
        ),
        app.theme.title,
    )));
    lineas.push(Line::from(""));

    lineas.push(Line::from(Span::styled("Navegación", app.theme.accent)));
    for fila in crate::tui::keys::HELP_ROWS {
        lineas.push(Line::from(vec![
            Span::styled(format!("  {:<20}", fila.keys), app.theme.accent),
            Span::styled(fila.description, app.theme.normal),
        ]));
    }

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Pestañas", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  Equipos       inventario (plana o agrupada), identidad ampliada y detalle",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Tráfico       ranking por equipo, destino, app, categoría, protocolo o proceso",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Conexiones    rol cliente/servidor, nombre del servidor, app y proceso local",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Histórico     gráfica con huecos y cursor, más tráfico del rango y eventos",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Alertas       lo que cambia: lista y detalle, reglas y silencios",
        app.theme.normal,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Tráfico", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  g      agrupar: equipo → destino → app → categoría → protocolo → proceso",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  w      ventana: 60 s → 5 min → 1 h → 24 h → sesión (no se guarda)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "         1 h y 24 h salen del histórico (minutos cerrados); con",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "         [history] enabled = false se saltan",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  Enter  ¿quién lo usa? en destino/app/categoría/protocolo; en proceso abre",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "         Conexiones filtradas; en equipo, su detalle completo",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  s      ordenar el ranking: ↓, ↑, total o equipos",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  El pie muestra siempre «sin identificar: N %» y la visibilidad honesta de",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  la red conmutada: solo se ve el tráfico propio y la difusión.",
        app.theme.dim,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Histórico (F5)", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  e      sujeto: toda la red, este equipo o un equipo (con /)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  w      rango: 24 h → 7 días → 30 días → 1 año",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Tab    foco entre la gráfica, «Más tráfico» y Eventos",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  < >    cursor de la gráfica: fecha, bajada y subida del punto en texto",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  f      filtro de eventos: todos, altas y presencia, identidad, servicios o",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "         Almenara; / busca por nombre de equipo; Enter abre el detalle",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  En el detalle de equipo, w alterna su histórico entre 24 h y 7 días.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Los huecos se dibujan con ░ y nunca se interpolan; el tiempo que aún no",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  ha pasado se deja en blanco.",
        app.theme.dim,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Alertas (F6)", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  Tab    dentro de Alertas: lista → Reglas → Silencios y vuelve",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Niveles: !! IMP (importante), !  AVI (aviso) y   INF (info); solo",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  importantes y avisos cuentan en «Alertas N» de la barra. Una alerta no",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  vista lleva ●; la seleccionada, ▸. Nada depende solo del color.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Enter  detalle de la alerta (la marca como vista) · espacio  vista",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  T      marcar todas las del filtro como vistas (pide confirmar si >20)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  f / u / /   filtro de nivel / solo sin ver / filtrar por equipo",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  m      silenciar la regla para ese sujeto: 1 día, 7 días o siempre",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  e      abrir el equipo de la alerta en Equipos (si no es de un equipo,",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "         no hace nada)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  En Reglas: espacio activa o apaga y n cicla el nivel (importante → aviso",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  → info); se guarda en config.toml. Una regla que no puede saltar lo dice:",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  «necesita el histórico», «necesita captura» o «sin escaneo de puertos».",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  En Silencios: x quita el seleccionado; los caducados se borran solos.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Las 16 reglas configurables y sus alertas de 7 días se ven en Reglas.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Presencia: solo los equipos vigilados ([p] en Equipos y en su detalle)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  avisan de ausencia o vuelta; ninguno está vigilado por defecto.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Lo nuevo (apps, categorías, organizaciones, países y huellas JA4) aprende",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  durante learning_days (7 días con datos) antes de avisar; la suspensión",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  y la captura parada restan cobertura. Los silencios evitan crear alertas",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  nuevas, pero no cambian las que ya existen.",
        app.theme.normal,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Conexiones", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  Prot. · Equipo (cliente o LAN) · Destino (servidor) · App · ↑ · ↓ · Edad;",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  a partir de 100 columnas se añade el Estado. Sin rol, la fila va en orden",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  canónico con «?» delante del destino.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  i      alternar nombres ⇄ IPs (no se persiste)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  v      detalle: cabeceras IP/TCP, rol, fuentes del nombre y de la app,",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "         JA4 y proceso local",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  /      buscar por servidor, app, proceso, IP o equipo",
        app.theme.normal,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Inferencia y privacidad",
        app.theme.accent,
    )));
    lineas.push(Line::from(Span::styled(
        "  Almenara lee cabeceras DNS/TLS/HTTP/QUIC y los primeros bytes de cada",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  conexión para ponerle nombre. No guarda el contenido. Los dominios son,",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  en la práctica, historial de navegación: se borran al cerrarse la conexión",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  o al caducar (24 h como máximo). El payload nunca se persiste.",
        app.theme.normal,
    )));
    lineas.push(Line::from(vec![
        Span::styled("  Para desactivarla: ", app.theme.normal),
        Span::styled("[inference] enabled = false", app.theme.accent),
        Span::styled(" en config.toml", app.theme.normal),
    ]));
    lineas.push(Line::from(Span::styled(
        "  Con la inferencia apagada solo quedan etiquetas por servicio de F2, ASN,",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  puerto y proceso local; la barra muestra «inferencia: desactivada».",
        app.theme.dim,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Privacidad del histórico (F5)",
        app.theme.accent,
    )));
    lineas.push(Line::from(Span::styled(
        "  Solo se guardan agregados: bytes y conexiones por equipo y dimensión.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Nunca se guarda contenido ni nombres completos: el destino es el dominio",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  registrable, la IP o el equipo de la LAN. Sin registro de conexiones.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Retención: minutos 48 h, horas 90 días y días 2 años. Los destinos solo",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  viven 2 h por minuto y 30 días por hora; nunca en los días ni en el",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  inventario. La presencia se deriva de los eventos y dura lo que ellos,",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  90 días: la presencia de un móvil es la de su dueño. Si en casa viven",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  más personas, conviene que lo sepan. Todo es local: nada sale del equipo.",
        app.theme.normal,
    )));
    lineas.push(Line::from(vec![
        Span::styled("  Para desactivarlo: ", app.theme.normal),
        Span::styled("[history] enabled = false", app.theme.accent),
        Span::styled(
            " (deja de guardar rollups e inventario; los eventos y las sesiones siguen)",
            app.theme.normal,
        ),
    ]));
    lineas.push(Line::from(Span::styled(
        "  Para borrarlo: cierra Almenara y borra la base de datos, o baja las",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  retenciones en [history]. Deja Almenara abierta (p. ej. en tmux) para",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  tener histórico continuo: solo se guarda mientras está abierta.",
        app.theme.dim,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Privacidad de las alertas (F6)",
        app.theme.accent,
    )));
    lineas.push(Line::from(Span::styled(
        "  Las alertas se ven en la pestaña Alertas y solo las importantes se",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  notifican en el escritorio; el servidor de notificaciones puede",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  guardarlas en su historial. Para desactivarlas:",
        app.theme.normal,
    )));
    lineas.push(Line::from(vec![
        Span::styled("  [alerts] desktop_notifications = false", app.theme.accent),
        Span::styled(" (las alertas siguen en la TUI)", app.theme.normal),
    ]));
    lineas.push(Line::from(Span::styled(
        "  Las alertas no guardan dominios, SNI, Host ni contenido: solo la etiqueta",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  del cambio (equipo, app, categoría, organización, país o JA4). El texto",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  que viene de la red se sanea: sin caracteres de control ni ANSI. La",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  presencia solo se avisa de los equipos marcados como vigilados y todo es",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  local: nada sale del equipo. Desactivar el motor con",
        app.theme.normal,
    )));
    lineas.push(Line::from(vec![
        Span::styled("  [alerts] enabled = false", app.theme.accent),
        Span::styled(" deja ver las alertas guardadas.", app.theme.normal),
    ]));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Captura de tráfico",
        app.theme.accent,
    )));
    let estado_captura = app.capture_status_line();
    let estilo_captura = if app.traffic.capture.active {
        app.theme.online
    } else {
        app.theme.warning
    };
    lineas.push(Line::from(vec![
        Span::styled("  Estado: ", app.theme.accent),
        Span::styled(estado_captura, estilo_captura),
    ]));
    lineas.push(Line::from(Span::styled(
        "  AF_PACKET + TPACKET_V3 (sin libpcap), un hilo por interfaz y anillo de 64 MB.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Requiere CAP_NET_RAW: sudo setcap cap_net_raw+ep target/debug/almenara",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Sin CAP_NET_RAW la captura se deshabilita y la barra muestra [CAP:off].",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  En Tráfico, el tráfico del propio host se muestra como fila [host] (no es",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  un equipo del inventario) para que la pestaña no aparezca vacía.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Ventanas en memoria: 60 s y 5 min; la de sesión no se guarda (el histórico",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  llega en la fase 5). passive_only permite captura pasiva: escuchar no",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  emite tráfico.",
        app.theme.normal,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled("Modo", app.theme.accent)));
    lineas.push(Line::from(Span::styled(
        "  privilegiado   CAP_NET_RAW disponible; todos los métodos activos",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  pasivo         solo escucha: sin escaneos, sin NetBIOS, sin DNS inverso;",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "                 la captura, la lectura de /proc y los leases DHCP siguen activos",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  degradado      sin CAP_NET_RAW; solo fuentes pasivas y sin captura de paquetes",
        app.theme.normal,
    )));
    let estilo_modo = if app.is_degraded() || app.is_passive() {
        app.theme.warning
    } else {
        app.theme.online
    };
    let modo = app.mode_label();
    let detalle = modo.strip_prefix("modo: ").unwrap_or(&modo).to_string();
    lineas.push(Line::from(vec![
        Span::styled("  Modo actual: ", app.theme.accent),
        Span::styled(detalle, estilo_modo),
    ]));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Privacidad y aviso legal",
        app.theme.accent,
    )));
    lineas.push(Line::from(Span::styled(
        "  Utiliza Almenara únicamente en redes propias o con autorización expresa.",
        app.theme.warning,
    )));
    lineas.push(Line::from(Span::styled(
        "  Monitorizar redes ajenas puede ser ilegal en muchos países.",
        app.theme.warning,
    )));
    lineas.push(Line::from(Span::styled(
        "  El payload de los paquetes NUNCA se persiste: se descarta en el hilo de",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  captura tras extraer la etiqueta. Solo se guardan etiquetas derivadas.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Dominios, SNI, Host y User-Agent solo aparecen en logs de nivel debug.",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  Datos técnicos guardados solo en local (SQLite): IP, MAC, hostname, modelo,",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  fabricante, familia de SO, huella DHCP, puertos/servicios y metadatos de",
        app.theme.dim,
    )));
    lineas.push(Line::from(Span::styled(
        "  conexiones (5-tuple, bytes, etiquetas y JA4).",
        app.theme.dim,
    )));

    lineas.push(Line::from(""));
    lineas.push(Line::from(Span::styled(
        "Datos y licencias",
        app.theme.accent,
    )));
    lineas.push(Line::from(Span::styled(
        "  IP Geolocation by DB-IP (db-ip.com), CC BY 4.0 · Public Suffix List",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        "  (Mozilla, MPL 2.0) · catálogo de apps propio · huellas JA4 (FoxIO, BSD-3)",
        app.theme.normal,
    )));
    lineas.push(Line::from(Span::styled(
        format!(
            "  Almenara v{} — Fase 6. Detalle de fuentes en data/FUENTES.md",
            env!("CARGO_PKG_VERSION")
        ),
        app.theme.dim,
    )));

    frame.render_widget(
        Paragraph::new(lineas)
            .style(app.theme.normal)
            .wrap(Wrap { trim: false }),
        interior,
    );
}

#[cfg(test)]
mod tests_f4 {
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_prueba(passive: bool) -> App {
        let mut config = Config::default();
        config.scan.passive_only = passive;
        App::new(
            config,
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        )
    }

    fn texto(app: &App) -> String {
        let backend = TestBackend::new(200, 260);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| super::draw(frame, app, frame.area()))
            .expect("dibujado de Ayuda");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn la_ayuda_documenta_las_teclas_nuevas_de_f4() {
        let app = app_prueba(false);
        let contenido = texto(&app);
        for tecla in [
            "g (Tráfico)",
            "w (Tráfico)",
            "i (Conexiones)",
            "v (Conexiones)",
            "Enter",
        ] {
            assert!(contenido.contains(tecla), "falta el atajo {tecla}");
        }
        assert!(contenido.contains("agrupar: equipo → destino → app"));
        assert!(contenido.contains("ventana: 60 s → 5 min → 1 h → 24 h → sesión"));
        assert!(contenido.contains("alternar nombres ⇄ IPs"));
    }

    #[test]
    fn la_ayuda_explica_la_privacidad_de_la_inferencia() {
        let app = app_prueba(false);
        let contenido = texto(&app);
        assert!(contenido.contains("Inferencia y privacidad"));
        assert!(contenido.contains("No guarda el contenido"));
        assert!(contenido.contains("historial de navegación"));
        assert!(contenido.contains("[inference] enabled = false"));
        assert!(contenido.contains("El payload nunca se persiste"));
        assert!(contenido.contains("logs de nivel debug"));
    }

    #[test]
    fn la_ayuda_redefine_el_modo_pasivo_y_atribuye_los_datos() {
        let app = app_prueba(true);
        let contenido = texto(&app);
        assert!(contenido
            .contains("pasivo         solo escucha: sin escaneos, sin NetBIOS, sin DNS inverso"));
        assert!(contenido.contains("IP Geolocation by DB-IP (db-ip.com), CC BY 4.0"));
        assert!(contenido.contains("Public Suffix List"));
        assert!(contenido.contains("MPL 2.0"));
        assert!(contenido.contains("Fase 6"));
        assert!(contenido.contains("Fase 6: alertas locales y de escritorio"));
        assert!(contenido.contains(" — Fase 6"));
    }

    #[test]
    fn la_ayuda_documenta_las_teclas_del_historico_de_f5() {
        let app = app_prueba(false);
        let contenido = texto(&app);
        for tecla in [
            "e (Histórico)",
            "w (Histórico)",
            "< > (Histórico)",
            "f (Histórico)",
            "Tab (Histórico)",
            "w (detalle)",
        ] {
            assert!(contenido.contains(tecla), "falta el atajo {tecla}");
        }
        assert!(contenido.contains("sujeto: toda la red, este equipo o un equipo"));
        assert!(contenido.contains("rango: 24 h → 7 días → 30 días → 1 año"));
        assert!(contenido.contains("cursor de la gráfica: fecha, bajada y subida"));
        assert!(contenido.contains("Histórico (F5)"));
        assert!(contenido.contains("alterna su histórico entre 24 h y 7 días"));
    }

    #[test]
    fn la_ayuda_explica_la_privacidad_del_historico() {
        let app = app_prueba(false);
        let contenido = texto(&app);
        assert!(contenido.contains("Privacidad del histórico (F5)"));
        assert!(contenido.contains("Solo se guardan agregados"));
        assert!(contenido.contains("Sin registro de conexiones"));
        assert!(contenido.contains("minutos 48 h, horas 90 días y días 2 años"));
        assert!(contenido.contains("Los destinos solo"));
        assert!(contenido.contains("30 días por hora"));
        assert!(
            contenido.contains("la presencia de un móvil es la de su dueño"),
            "debe avisar de que la presencia es la de la persona"
        );
        assert!(contenido.contains("[history] enabled = false"));
        assert!(contenido.contains("Todo es local"));
        assert!(contenido.contains("borra la base de datos"));
    }
}

#[cfg(test)]
mod tests_f6 {
    use crate::capabilities::Capabilities;
    use crate::config::Config;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn app_prueba() -> App {
        App::new(
            Config::default(),
            PathBuf::from("/tmp/config.toml"),
            PathBuf::from("/tmp/data.db"),
            Capabilities {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            },
            None,
        )
    }

    fn texto(app: &App) -> String {
        let backend = TestBackend::new(200, 260);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| super::draw(frame, app, frame.area()))
            .expect("dibujado de Ayuda");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect()
    }

    #[test]
    fn la_ayuda_documenta_las_alertas_de_f6() {
        let contenido = texto(&app_prueba());
        assert!(contenido.contains("Alertas (F6)"));
        assert!(contenido.contains("!! IMP"));
        assert!(contenido.contains("!  AVI"));
        assert!(contenido.contains("   INF"));
        assert!(contenido.contains("solo"));
        assert!(contenido.contains("importantes y avisos cuentan en «Alertas N»"));
        assert!(contenido.contains("Tab    dentro de Alertas"));
        assert!(contenido.contains("m      silenciar la regla"));
        assert!(contenido.contains("e      abrir el equipo de la alerta"));
        assert!(contenido.contains("x quita el seleccionado"));
        assert!(contenido.contains("Las 16 reglas configurables"));
        assert!(contenido.contains("learning_days (7 días con datos)"));
        assert!(contenido.contains("Presencia: solo los equipos vigilados"));
        assert!(contenido.contains("espacio activa o apaga"));
        assert!(contenido.contains("n cicla el nivel"));
    }

    #[test]
    fn la_ayuda_explica_la_privacidad_de_las_notificaciones() {
        let contenido = texto(&app_prueba());
        assert!(contenido.contains("Privacidad de las alertas (F6)"));
        assert!(contenido.contains("solo las importantes se"));
        assert!(contenido.contains("el servidor de notificaciones puede"));
        assert!(contenido.contains("guardarlas en su historial"));
        assert!(contenido.contains("[alerts] desktop_notifications = false"));
        assert!(contenido.contains("no guardan dominios, SNI, Host ni contenido"));
        assert!(contenido.contains("sin caracteres de control ni ANSI"));
        assert!(contenido.contains("presencia solo se avisa de los equipos marcados"));
        assert!(contenido.contains("[alerts] enabled = false"));
    }

    #[test]
    fn la_ayuda_se_dibuja_sin_panico_en_ochenta_por_veinticuatro() {
        let app = app_prueba();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal de pruebas");
        terminal
            .draw(|frame| super::draw(frame, &app, frame.area()))
            .expect("la Ayuda cabe en 80x24");
        let contenido: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|celda| celda.symbol())
            .collect();
        assert!(contenido.contains("Almenara v"));
    }

    #[test]
    fn la_ayuda_ya_no_anuncia_la_pestana_de_alertas() {
        let contenido = texto(&app_prueba());
        assert!(!contenido.contains("llegarán en la fase 6"));
        assert!(contenido.contains("lo que cambia: lista y detalle, reglas y silencios"));
        assert!(contenido.contains("Fase 6: alertas locales y de escritorio"));
        assert!(contenido.contains(" — Fase 6."));
    }
}
