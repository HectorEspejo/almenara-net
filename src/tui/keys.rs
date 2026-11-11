//! Definición central de los keybindings de la TUI.
//!
//! La traducción de teclas a acciones vive en [crate::tui::app::App::handle_key];
//! este módulo es la fuente única de verdad para mostrar los atajos en la pestaña
//! Ayuda y en el pie de la interfaz, de modo que documentación y código no se
//! desincronicen.

/// Descripción de un atajo para la pestaña Ayuda.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHelp {
    /// Combinación de teclas visible.
    pub keys: &'static str,
    /// Descripción de la acción.
    pub description: &'static str,
}

/// Atajos mostrados en la pestaña Ayuda.
pub const HELP_ROWS: &[KeyHelp] = &[
    KeyHelp {
        keys: "hjkl / flechas",
        description: "mover la selección (j/k) o cambiar de pestaña (h/l)",
    },
    KeyHelp {
        keys: "Tab / Shift-Tab",
        description: "cambiar de pestaña",
    },
    KeyHelp {
        keys: "1-7",
        description: "ir directamente a una pestaña",
    },
    KeyHelp {
        keys: "Enter",
        description: "detalle del equipo; en Tráfico, «¿quién lo usa?», proceso o detalle",
    },
    KeyHelp {
        keys: "Tab (detalle)",
        description: "alternar el foco entre la lista y el panel de detalle",
    },
    KeyHelp {
        keys: "g (Equipos)",
        description: "alternar la lista plana / agrupada por categoría",
    },
    KeyHelp {
        keys: "g (Tráfico)",
        description: "agrupar: equipo → destino → app → categoría → protocolo → proceso",
    },
    KeyHelp {
        keys: "w (Tráfico)",
        description: "ventana: 60 s → 5 min → 1 h → 24 h → sesión (no se guarda)",
    },
    KeyHelp {
        keys: "e (Histórico)",
        description: "sujeto: toda la red, este equipo o un equipo (con /)",
    },
    KeyHelp {
        keys: "w (Histórico)",
        description: "rango: 24 h → 7 días → 30 días → 1 año",
    },
    KeyHelp {
        keys: "< > (Histórico)",
        description: "cursor de la gráfica: fecha, bajada y subida del punto",
    },
    KeyHelp {
        keys: "f (Histórico)",
        description: "filtro de eventos: todos, altas y presencia, identidad, servicios, Almenara",
    },
    KeyHelp {
        keys: "Tab (Histórico)",
        description: "foco entre gráfica, «Más tráfico» y Eventos",
    },
    KeyHelp {
        keys: "w (detalle)",
        description: "histórico del equipo: 24 h ⇄ 7 días",
    },
    KeyHelp {
        keys: "i (Conexiones)",
        description: "alternar nombres ⇄ IPs (sin persistir)",
    },
    KeyHelp {
        keys: "v (Conexiones)",
        description: "detalle: cabeceras, rol, fuentes, JA4 y proceso local",
    },
    KeyHelp {
        keys: "s / f (Conexiones)",
        description: "ordenar / filtrar la tabla de conexiones",
    },
    KeyHelp {
        keys: "/",
        description: "buscar equipos; en Conexiones, por servidor, app o proceso",
    },
    KeyHelp {
        keys: "s",
        description: "ordenar por columna o, en Tráfico, el ranking (↓, ↑, total, equipos)",
    },
    KeyHelp {
        keys: "f",
        description: "filtrar: todos / online / offline / nuevos / alertas",
    },
    KeyHelp {
        keys: "r",
        description: "rescaneo manual",
    },
    KeyHelp {
        keys: "t",
        description: "ciclar el tipo de dispositivo del equipo seleccionado (automático o manual)",
    },
    KeyHelp {
        keys: "a",
        description: "editar el alias del equipo seleccionado",
    },
    KeyHelp {
        keys: "n",
        description: "editar las notas del equipo seleccionado",
    },
    KeyHelp {
        keys: "p (Equipos/detalle)",
        description: "marcar o desmarcar el equipo como vigilado (solo esos avisan de presencia)",
    },
    KeyHelp {
        keys: "Tab (Alertas)",
        description: "Alertas → Reglas → Silencios",
    },
    KeyHelp {
        keys: "Enter / espacio (Alertas)",
        description: "ver el detalle y marcar como vista / marcar como vista",
    },
    KeyHelp {
        keys: "T (Alertas)",
        description: "marcar como vistas todas las del filtro (pide confirmación si son más de 20)",
    },
    KeyHelp {
        keys: "f / u / / (Alertas)",
        description: "filtro de nivel / solo sin ver / filtrar por equipo",
    },
    KeyHelp {
        keys: "m (Alertas)",
        description: "silenciar la regla para el sujeto y el equipo: 1 día, 7 días o siempre",
    },
    KeyHelp {
        keys: "e (Alertas)",
        description: "abrir el equipo de la alerta en Equipos",
    },
    KeyHelp {
        keys: "espacio / n (Reglas)",
        description: "activar o apagar una regla / ciclar su nivel (se guarda en config.toml)",
    },
    KeyHelp {
        keys: "x (Silencios)",
        description: "quitar el silencio seleccionado",
    },
    KeyHelp {
        keys: "?",
        description: "esta ayuda",
    },
    KeyHelp {
        keys: "q",
        description: "salir",
    },
    KeyHelp {
        keys: "Esc",
        description: "cerrar paneles, detalle o búsqueda; volver a Equipos",
    },
];

/// Pie de teclas de la pestaña Equipos (dos líneas para que quepa en 80 columnas).
pub const FOOTER_EQUIPOS: [&str; 2] = [
    "[hjkl]mover [Tab]pestaña [1-7]atajo [/]buscar [s]orden [f]filtro",
    "[r]rescan [g]vista [t]tipo [a]alias [n]notas [p]vigilar [?]ayuda [q]salir",
];

/// Pie de teclas del resto de pestañas (dos líneas).
pub const FOOTER_OTROS: [&str; 2] = [
    "[Tab/Shift-Tab]pestañas [1-7]atajo [Esc]volver",
    "[?]ayuda [q]salir",
];

/// Pie de teclas de la pestaña Tráfico (ranking de F4).
pub const FOOTER_TRAFICO: [&str; 2] = [
    "[hjkl]mover [g]agrupar [w]ventana [s]orden [Enter]¿quién?",
    "[/]buscar [Tab]pestaña [Esc]cerrar [?]ayuda [q]salir",
];

/// Pie de teclas con el panel «¿Quién lo usa?» abierto.
pub const FOOTER_TRAFICO_PANEL: [&str; 2] = [
    "[hjkl]mover panel [Enter]detalle [Esc]cerrar panel",
    "[g]agrupar [w]ventana [?]ayuda [q]salir",
];

/// Pie de teclas de la pestaña Conexiones (tabla plana de F4).
pub const FOOTER_CONEXIONES: [&str; 2] = [
    "[hjkl]mover [i]nombres/IPs [v]detalle [s]orden [f]filtro",
    "[/]buscar [Tab]pestañas [Esc]cerrar [1-7]atajo [?]ayuda",
];

/// Pie de teclas de la pestaña Histórico (F5).
pub const FOOTER_HISTORICO: [&str; 2] = [
    "[e]equipo [w]rango [Tab]panel [<>]cursor [f]filtro",
    "[/]buscar [Enter]detalle [?]ayuda [q]salir",
];

/// Pie de teclas del panel de detalle master-detail.
pub const FOOTER_DETALLE: [&str; 2] = [
    "[hjkl]mover [Tab]panel [p]vigilar [Esc]cerrar detalle",
    "[j/k]desplazar [v]conexión [?]ayuda [q]salir",
];

/// Pie de teclas de la pestaña Alertas: lista (F6).
pub const FOOTER_ALERTAS: [&str; 2] = [
    "[Enter]ver [espacio]vista [T]todas [f]nivel [u]sin ver [/]equipo",
    "[m]silenciar [e]equipo [Tab]reglas [?]ayuda [q]salir",
];

/// Pie de teclas de la vista Reglas de la pestaña Alertas (F6).
pub const FOOTER_REGLAS: [&str; 2] = [
    "[espacio]activar/apagar [n]nivel [hjkl]mover",
    "[Tab]silencios [?]ayuda [q]salir",
];

/// Pie de teclas de la vista Silencios de la pestaña Alertas (F6).
pub const FOOTER_SILENCIOS: [&str; 2] = [
    "[x]quitar silencio [hjkl]mover",
    "[Tab]alertas [?]ayuda [q]salir",
];

/// Pie de teclas que corresponde a una pestaña (y al detalle o panel abiertos).
pub fn footer_para(
    tab: crate::tui::app::Tab,
    detalle_abierto: bool,
    quien_abierto: bool,
    vista_alertas: crate::tui::alerts_state::AlertsView,
) -> &'static [&'static str; 2] {
    if detalle_abierto {
        return &FOOTER_DETALLE;
    }
    match tab {
        crate::tui::app::Tab::Equipos => &FOOTER_EQUIPOS,
        crate::tui::app::Tab::Trafico => {
            if quien_abierto {
                &FOOTER_TRAFICO_PANEL
            } else {
                &FOOTER_TRAFICO
            }
        }
        crate::tui::app::Tab::Conexiones => &FOOTER_CONEXIONES,
        crate::tui::app::Tab::Historico => &FOOTER_HISTORICO,
        crate::tui::app::Tab::Alertas => match vista_alertas {
            crate::tui::alerts_state::AlertsView::Lista => &FOOTER_ALERTAS,
            crate::tui::alerts_state::AlertsView::Reglas => &FOOTER_REGLAS,
            crate::tui::alerts_state::AlertsView::Silencios => &FOOTER_SILENCIOS,
        },
        _ => &FOOTER_OTROS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hay_un_atajo_para_cada_accion_requerida() {
        let claves: Vec<&str> = HELP_ROWS.iter().map(|fila| fila.keys).collect();
        for requerida in [
            "Tab", "1-7", "/", "s", "f", "r", "g", "t", "?", "q", "Esc", "Enter", "v", "w", "i",
        ] {
            assert!(
                claves.iter().any(|clave| clave.contains(requerida)),
                "falta el atajo {requerida}"
            );
        }
        assert!(FOOTER_EQUIPOS.iter().any(|linea| linea.contains("rescan")));
        assert!(FOOTER_OTROS.iter().any(|linea| linea.contains("pestañas")));
        for footer in [
            FOOTER_TRAFICO,
            FOOTER_TRAFICO_PANEL,
            FOOTER_CONEXIONES,
            FOOTER_HISTORICO,
            FOOTER_DETALLE,
            FOOTER_ALERTAS,
            FOOTER_REGLAS,
            FOOTER_SILENCIOS,
        ] {
            assert!(
                footer.iter().any(|linea| linea.contains("[?]ayuda")),
                "los pies deben recordar la ayuda"
            );
        }
        assert!(FOOTER_CONEXIONES
            .iter()
            .any(|linea| linea.contains("[v]detalle")));
        assert!(FOOTER_TRAFICO
            .iter()
            .any(|linea| linea.contains("[g]agrupar")));
        assert!(FOOTER_TRAFICO
            .iter()
            .any(|linea| linea.contains("[w]ventana")));
    }

    #[test]
    fn pies_caben_en_ochenta_columnas() {
        let todos = FOOTER_EQUIPOS
            .iter()
            .chain(FOOTER_OTROS.iter())
            .chain(FOOTER_TRAFICO.iter())
            .chain(FOOTER_TRAFICO_PANEL.iter())
            .chain(FOOTER_CONEXIONES.iter())
            .chain(FOOTER_HISTORICO.iter())
            .chain(FOOTER_DETALLE.iter())
            .chain(FOOTER_ALERTAS.iter())
            .chain(FOOTER_REGLAS.iter())
            .chain(FOOTER_SILENCIOS.iter());
        for linea in todos {
            assert!(
                linea.chars().count() <= 80,
                "el pie no cabe en 80 columnas: {linea}"
            );
        }
        assert!(FOOTER_EQUIPOS
            .iter()
            .any(|linea| linea.contains("[g]vista")));
        assert!(FOOTER_EQUIPOS.iter().any(|linea| linea.contains("[t]tipo")));
    }
}
