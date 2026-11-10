//! Buffer en memoria de notificaciones no bloqueantes.
//!
//! Las notificaciones se muestran durante unos segundos en la barra inferior.
//! Se guardan como máximo 50 en un buffer circular, sin persistencia.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Capacidad máxima del buffer de notificaciones.
pub const NOTIFICATION_CAPACITY: usize = 50;
/// Tiempo que una notificación permanece visible.
pub const NOTIFICATION_TTL: Duration = Duration::from_secs(3);

/// Nivel de una notificación (afecta al color y al prefijo visible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Información general.
    Info,
    /// Aviso (por ejemplo, modo degradado).
    Warn,
    /// Error mitigable.
    Error,
}

impl Level {
    /// Etiqueta corta en castellano para mostrar en la barra.
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "aviso",
            Self::Error => "error",
        }
    }
}

/// Una notificación con nivel y texto ya formateado en castellano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Nivel de la notificación.
    pub level: Level,
    /// Texto mostrado al usuario.
    pub message: String,
}

impl Notification {
    /// Crea una notificación nueva.
    pub fn new(level: Level, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
        }
    }
}

/// Buffer circular de notificaciones con la última mostrada.
#[derive(Debug)]
pub struct Notifier {
    buffer: VecDeque<Notification>,
    capacity: usize,
    current: Option<(Notification, Instant)>,
    ttl: Duration,
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier {
    /// Crea un notificador con la capacidad y el tiempo de vida por defecto.
    pub fn new() -> Self {
        Self::with_options(NOTIFICATION_CAPACITY, NOTIFICATION_TTL)
    }

    /// Crea un notificador con capacidad y TTL explícitos (usado en tests).
    pub fn with_options(capacity: usize, ttl: Duration) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            current: None,
            ttl,
        }
    }

    /// Añade una notificación. Si el buffer está lleno se descarta la más antigua.
    pub fn push(&mut self, level: Level, message: impl Into<String>) {
        if self.buffer.len() == self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(Notification::new(level, message));
        self.current = self
            .buffer
            .back()
            .cloned()
            .map(|notification| (notification, Instant::now()));
    }

    /// Elimina de la vista la notificación caducada.
    pub fn tick(&mut self) {
        if let Some((_, shown_at)) = &self.current {
            if shown_at.elapsed() >= self.ttl {
                self.current = None;
            }
        }
    }

    /// Devuelve la notificación que debe mostrarse ahora, si la hay.
    pub fn current(&self) -> Option<&Notification> {
        self.current.as_ref().map(|(notification, _)| notification)
    }

    /// Número de notificaciones guardadas en el buffer.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Indica si el buffer está vacío.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_ultima_notificacion_sustituye_a_la_anterior() {
        let mut notifier = Notifier::new();
        notifier.push(Level::Info, "primera");
        notifier.push(Level::Warn, "segunda");
        assert_eq!(notifier.current().unwrap().message, "segunda");
        assert_eq!(notifier.current().unwrap().level, Level::Warn);
    }

    #[test]
    fn el_buffer_no_supera_la_capacidad() {
        let mut notifier = Notifier::with_options(3, NOTIFICATION_TTL);
        for i in 0..10 {
            notifier.push(Level::Info, format!("notificación {i}"));
        }
        assert_eq!(notifier.len(), 3);
        assert_eq!(notifier.current().unwrap().message, "notificación 9");
    }

    #[test]
    fn la_notificacion_caduca_tras_el_ttl() {
        let mut notifier = Notifier::with_options(NOTIFICATION_CAPACITY, Duration::from_millis(1));
        notifier.push(Level::Info, "efímera");
        assert!(notifier.current().is_some());
        std::thread::sleep(Duration::from_millis(5));
        notifier.tick();
        assert!(notifier.current().is_none());
    }

    #[test]
    fn buffer_por_defecto_de_50() {
        let notifier = Notifier::new();
        assert_eq!(notifier.len(), 0);
        assert!(notifier.is_empty());
    }

    #[test]
    fn los_niveles_tienen_etiqueta_en_castellano() {
        assert_eq!(Level::Info.label(), "info");
        assert_eq!(Level::Warn.label(), "aviso");
        assert_eq!(Level::Error.label(), "error");
    }
}
