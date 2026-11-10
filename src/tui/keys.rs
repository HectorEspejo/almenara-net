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
        description: "detalle del equipo (llegará en Fase 3)",
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
        description: "cerrar la búsqueda o volver a Equipos",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hay_un_atajo_para_cada_accion_requerida() {
        let claves: Vec<&str> = HELP_ROWS.iter().map(|fila| fila.keys).collect();
        for requerida in ["Tab", "1-7", "/", "s", "f", "r", "g", "t", "?", "q", "Esc"] {
            assert!(
                claves.iter().any(|clave| clave.contains(requerida)),
                "falta el atajo {requerida}"
            );
        }
        assert!(FOOTER_EQUIPOS.iter().any(|linea| linea.contains("rescan")));
        assert!(FOOTER_OTROS.iter().any(|linea| linea.contains("pestañas")));
    }

    #[test]
    fn pies_caben_en_ochenta_columnas() {
        for linea in FOOTER_EQUIPOS.iter().chain(FOOTER_OTROS.iter()) {
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
