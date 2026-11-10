//! Paleta de 256 colores de la TUI y respeto a NO_COLOR.
//!
//! Cuatro roles principales: normal, acento (cabeceras y elementos activos),
//! aviso (alertas y modo degradado) y atenuado (equipos offline). Con NO_COLOR
//! (o --no-color) la interfaz pasa a monocromo usando símbolos y modificadores.

use ratatui::style::{Color, Modifier, Style};

/// Paleta completa de la interfaz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Theme {
    /// El color está activado.
    pub color: bool,
    /// Texto normal.
    pub normal: Style,
    /// Cabeceras, pestaña activa y elementos destacados.
    pub accent: Style,
    /// Avisos (modo degradado, equipos nuevos o desconectados).
    pub warning: Style,
    /// Errores.
    pub error: Style,
    /// Texto secundario y equipos offline.
    pub dim: Style,
    /// Borde de bloques.
    pub border: Style,
    /// Fila seleccionada de la lista.
    pub selected: Style,
    /// Estado online.
    pub online: Style,
    /// Estado offline.
    pub offline: Style,
    /// Título de bloque.
    pub title: Style,
}

impl Theme {
    /// Construye el tema según la configuración, el flag --no-color y NO_COLOR.
    pub fn from_flags(config_no_color: bool, cli_no_color: bool) -> Self {
        let no_color = config_no_color || cli_no_color || std::env::var_os("NO_COLOR").is_some();
        Self::new(!no_color)
    }

    /// Construye el tema con o sin color.
    pub fn new(color: bool) -> Self {
        if color {
            Self::color_theme()
        } else {
            Self::monochrome_theme()
        }
    }

    fn color_theme() -> Self {
        // Índices de la paleta de 256 colores con contraste >= 4.5:1 sobre fondo negro.
        let acento = Color::Indexed(45);
        let aviso = Color::Indexed(214);
        let error = Color::Indexed(196);
        let atenuado = Color::Indexed(245);
        let normal = Color::Indexed(252);
        let exito = Color::Indexed(114);
        Self {
            color: true,
            normal: Style::default().fg(normal),
            accent: Style::default().fg(acento).add_modifier(Modifier::BOLD),
            warning: Style::default().fg(aviso).add_modifier(Modifier::BOLD),
            error: Style::default().fg(error).add_modifier(Modifier::BOLD),
            dim: Style::default().fg(atenuado),
            border: Style::default().fg(Color::Indexed(240)),
            selected: Style::default()
                .fg(Color::Indexed(255))
                .bg(Color::Indexed(236))
                .add_modifier(Modifier::BOLD),
            online: Style::default().fg(exito),
            offline: Style::default().fg(atenuado).add_modifier(Modifier::DIM),
            title: Style::default().fg(acento).add_modifier(Modifier::BOLD),
        }
    }

    fn monochrome_theme() -> Self {
        Self {
            color: false,
            normal: Style::default(),
            accent: Style::default().add_modifier(Modifier::BOLD),
            warning: Style::default().add_modifier(Modifier::BOLD),
            error: Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
            dim: Style::default().add_modifier(Modifier::DIM),
            border: Style::default(),
            selected: Style::default().add_modifier(Modifier::REVERSED),
            online: Style::default(),
            offline: Style::default().add_modifier(Modifier::DIM),
            title: Style::default().add_modifier(Modifier::BOLD),
        }
    }

    /// Estilo según el nivel de notificación.
    pub fn level_style(&self, level: crate::notifier::Level) -> Style {
        match level {
            crate::notifier::Level::Info => self.normal,
            crate::notifier::Level::Warn => self.warning,
            crate::notifier::Level::Error => self.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sin_color_no_usa_colores() {
        let theme = Theme::new(false);
        assert!(!theme.color);
        assert_eq!(theme.normal.fg, None);
        assert_eq!(theme.selected.fg, None);
        assert_eq!(theme.warning.fg, None);
    }

    #[test]
    fn con_color_usa_indices_de_256() {
        let theme = Theme::new(true);
        assert!(theme.color);
        assert!(matches!(theme.accent.fg, Some(Color::Indexed(_))));
        assert!(matches!(theme.warning.fg, Some(Color::Indexed(_))));
        assert!(matches!(theme.selected.bg, Some(Color::Indexed(_))));
    }

    #[test]
    fn estilos_de_nivel_diferentes() {
        let theme = Theme::new(true);
        assert_ne!(
            theme.level_style(crate::notifier::Level::Warn),
            theme.level_style(crate::notifier::Level::Info)
        );
    }
}
