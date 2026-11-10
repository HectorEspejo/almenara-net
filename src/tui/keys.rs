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
        description: "abrir el detalle del equipo seleccionado (master-detail)",
    },
    KeyHelp {
        keys: "Tab (detalle)",
        description: "alternar el foco entre la lista y el panel de detalle",
    },
    KeyHelp {
        keys: "v",
        description: "cabeceras IP/TCP de la conexión seleccionada (pestaña Conexiones)",
    },
    KeyHelp {
        keys: "s / f (Conexiones)",
        description: "ordenar / filtrar la tabla de conexiones",
    },
    KeyHelp {
        keys: "/",
        description: "buscar por IP, MAC, hostname, fabricante o alias",
    },
    KeyHelp {
        keys: "s",
        description: "ordenar por columna (cicla ascendente/descendente)",
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
        keys: "g",
        description: "alternar la lista plana / agrupada por categoría (pestaña Equipos)",
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
        description: "cerrar cabeceras, detalle o búsqueda; volver a Equipos",
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

/// Pie de teclas de la pestaña Tráfico (ranking top-10).
pub const FOOTER_TRAFICO: [&str; 2] = [
    "[hjkl]mover [Enter]detalle [Tab]pestaña [1-7]atajo",
    "[?]ayuda [q]salir",
];

/// Pie de teclas de la pestaña Conexiones (tabla plana).
pub const FOOTER_CONEXIONES: [&str; 2] = [
    "[hjkl]mover [v]cabeceras [s]orden [f]filtro",
    "[Tab/Shift-Tab]pestañas [Esc]cerrar [1-7]atajo [?]ayuda",
];

/// Pie de teclas del panel de detalle master-detail.
pub const FOOTER_DETALLE: [&str; 2] = [
    "[hjkl]mover [Tab]panel [Esc]cerrar detalle",
    "[?]ayuda [q]salir",
];

/// Pie de teclas que corresponde a una pestaña (y al detalle abierto).
pub fn footer_para(tab: crate::tui::app::Tab, detalle_abierto: bool) -> &'static [&'static str; 2] {
    if detalle_abierto {
        return &FOOTER_DETALLE;
    }
    match tab {
        crate::tui::app::Tab::Equipos => &FOOTER_EQUIPOS,
        crate::tui::app::Tab::Trafico => &FOOTER_TRAFICO,
        crate::tui::app::Tab::Conexiones => &FOOTER_CONEXIONES,
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
            "Tab", "1-7", "/", "s", "f", "r", "g", "t", "?", "q", "Esc", "Enter", "v",
        ] {
            assert!(
                claves.iter().any(|clave| clave.contains(requerida)),
                "falta el atajo {requerida}"
            );
        }
        assert!(FOOTER_EQUIPOS.iter().any(|linea| linea.contains("rescan")));
        assert!(FOOTER_OTROS.iter().any(|linea| linea.contains("pestañas")));
        for footer in [FOOTER_TRAFICO, FOOTER_CONEXIONES, FOOTER_DETALLE] {
            assert!(
                footer.iter().any(|linea| linea.contains("[?]ayuda")),
                "los pies deben recordar la ayuda"
            );
        }
        assert!(FOOTER_CONEXIONES
            .iter()
            .any(|linea| linea.contains("[v]cabeceras")));
    }

    #[test]
    fn pies_caben_en_ochenta_columnas() {
        let todos = FOOTER_EQUIPOS
            .iter()
            .chain(FOOTER_OTROS.iter())
            .chain(FOOTER_TRAFICO.iter())
            .chain(FOOTER_CONEXIONES.iter())
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
