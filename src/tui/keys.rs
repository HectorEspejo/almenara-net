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
    "[r]rescan [g]vista [t]tipo [a]alias [n]notas [?]ayuda [q]salir",
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
    "[hjkl]mover [Tab]panel [Esc]cerrar detalle",
    "[j/k]desplazar [v]conexión [?]ayuda [q]salir",
];

/// Pie de teclas que corresponde a una pestaña (y al detalle o panel abiertos).
pub fn footer_para(
    tab: crate::tui::app::Tab,
    detalle_abierto: bool,
    quien_abierto: bool,
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
            .chain(FOOTER_DETALLE.iter());
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
