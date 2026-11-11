//! Paleta de 256 colores de la TUI y respeto a NO_COLOR.
//!
//! Cuatro roles principales: normal, acento (cabeceras y elementos activos),
//! aviso (alertas y modo degradado) y atenuado (equipos offline). Con NO_COLOR
//! (o --no-color) la interfaz pasa a monocromo usando símbolos y modificadores.

use ratatui::style::{Color, Modifier, Style};

use crate::classify::DeviceType;
use crate::repo::devices::Device;

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

/// Icono ASCII del tipo de dispositivo (sin tener en cuenta el estado).
///
/// La taxonomía de Fase 2 se representa con estos símbolos; es reutilizable por
/// cualquier vista que necesite identificar el tipo de un equipo.
pub fn icon_for_type(tipo: DeviceType) -> &'static str {
    match tipo {
        DeviceType::Gateway => "[⌂]",
        DeviceType::Pc | DeviceType::Server | DeviceType::Nas => "[▣]",
        DeviceType::Mobile | DeviceType::Tablet => "[▯]",
        DeviceType::Tv | DeviceType::Streaming => "[▶]",
        DeviceType::Printer => "[P]",
        DeviceType::Camera => "[C]",
        DeviceType::Iot => "[●]",
        DeviceType::Unknown => "[?]",
    }
}

/// Icono y estilo de un dispositivo según su tipo efectivo.
///
/// Usa [Device::effective_device_type], de modo que el override manual manda
/// sobre la clasificación automática. Cualquier equipo offline se dibuja como
/// `○` con el estilo atenuado, independientemente de su tipo.
pub fn device_icon(device: &Device, theme: &Theme) -> (&'static str, Style) {
    if !device.is_online {
        return ("○", theme.offline);
    }
    let tipo = DeviceType::from_str(device.effective_device_type()).unwrap_or(DeviceType::Unknown);
    let estilo = if tipo == DeviceType::Gateway {
        theme.accent
    } else {
        theme.normal
    };
    (icon_for_type(tipo), estilo)
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

    fn dispositivo(device_type: &str, online: bool) -> Device {
        Device {
            id: 1,
            mac: "aa:bb:cc:dd:ee:01".to_string(),
            ip: "10.0.0.2".to_string(),
            hostname: Some("equipo".to_string()),
            vendor: None,
            interface_id: 1,
            device_type: device_type.to_string(),
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
        }
    }

    #[test]
    fn icono_por_tipo_de_dispositivo() {
        let theme = Theme::new(false);
        let casos = [
            ("gateway", "[⌂]"),
            ("pc", "[▣]"),
            ("server", "[▣]"),
            ("nas", "[▣]"),
            ("mobile", "[▯]"),
            ("tablet", "[▯]"),
            ("tv", "[▶]"),
            ("streaming", "[▶]"),
            ("printer", "[P]"),
            ("camera", "[C]"),
            ("iot", "[●]"),
            ("unknown", "[?]"),
        ];
        for (device_type, esperado) in casos {
            let device = dispositivo(device_type, true);
            assert_eq!(
                device_icon(&device, &theme).0,
                esperado,
                "icono de {device_type}"
            );
        }
        assert_eq!(icon_for_type(DeviceType::Gateway), "[⌂]");
    }

    #[test]
    fn offline_siempre_muestra_circulo_y_estilo_atenuado() {
        let color = Theme::new(true);
        let mut device = dispositivo("gateway", false);
        let (icono, estilo) = device_icon(&device, &color);
        assert_eq!(icono, "○");
        assert_eq!(estilo, color.offline);
        // Un tipo inválido cae a desconocido y el override manual manda.
        let mut desconocido = dispositivo("tipo-invalido", true);
        assert_eq!(device_icon(&desconocido, &color).0, "[?]");
        desconocido.device_type_manual = Some("printer".to_string());
        assert_eq!(device_icon(&desconocido, &color).0, "[P]");
        device.is_online = true;
        assert_eq!(device_icon(&device, &color).0, "[⌂]");
    }
}
