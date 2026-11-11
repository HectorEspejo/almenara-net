//! Notificador de escritorio de la F6 (ADR-76).
//!
//! `notify-rust` 4.17 sobre `zbus` 5 (Rust puro, sin libdbus) en un hilo propio
//! con un canal acotado (`NOTIFY_CHANNEL_CAPACITY`): la TUI solo encola y nunca
//! espera a D-Bus. Sin servidor de notificaciones, el notificador queda NO
//! DISPONIBLE, avisa una vez en Config y reintenta como mucho cada 10 minutos;
//! las alertas siguen en la pestaña Alertas.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::alerts::{Notice, NOTIFY_CHANNEL_CAPACITY};

/// Intervalo mínimo entre reintentos cuando el servidor no está disponible.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(600);
/// Nombre de la aplicación que se muestra en la notificación.
pub const APP_NAME: &str = "Almenara";
/// Icono estándar del escritorio.
pub const ICON: &str = "network-wired";

/// Configuración del notificador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyConfig {
    /// Notificaciones de escritorio encendidas (`[alerts].desktop_notifications`).
    pub enabled: bool,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Estado del notificador (lo muestra la pestaña Config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifierStatus {
    /// `desktop_notifications = false`.
    Apagado,
    /// Hay servidor y se envían las notificaciones.
    Disponible {
        /// Nombre del servidor (`mako`, `GNOME Shell`…), si se conoce.
        server: Option<String>,
    },
    /// Hubo un error de D-Bus o no hay servidor de notificaciones.
    NoDisponible {
        /// Próximo intento permitido.
        next_retry: SystemTime,
        /// Motivo del fallo.
        error: String,
    },
}

impl NotifierStatus {
    /// Etiqueta corta en mayúsculas para Config.
    #[allow(dead_code)] // Config la muestra a través de summary(); se conserva por contrato
    pub fn label(&self) -> &'static str {
        match self {
            Self::Apagado => "APAGADO",
            Self::Disponible { .. } => "DISPONIBLE",
            Self::NoDisponible { .. } => "NO DISPONIBLE",
        }
    }

    /// Texto para Config con el servidor o el próximo intento.
    pub fn summary(&self) -> String {
        match self {
            Self::Apagado => "APAGADO (desktop_notifications = false)".to_string(),
            Self::Disponible {
                server: Some(server),
            } => {
                format!("DISPONIBLE (servidor: {server})")
            }
            Self::Disponible { server: None } => "DISPONIBLE".to_string(),
            Self::NoDisponible { next_retry, error } => format!(
                "NO DISPONIBLE ({error}; próximo intento: {})",
                formatear_hora(*next_retry)
            ),
        }
    }

    /// Indica si se pueden enviar notificaciones ahora mismo.
    pub fn disponible(&self) -> bool {
        matches!(self, Self::Disponible { .. })
    }
}

/// Estado compartido entre el hilo del notificador y la TUI.
#[derive(Debug)]
struct Compartido {
    status: Mutex<NotifierStatus>,
    drops: AtomicU64,
    enviadas: AtomicU64,
}

impl Compartido {
    fn status(&self) -> NotifierStatus {
        self.status
            .lock()
            .map(|estado| estado.clone())
            .unwrap_or(NotifierStatus::NoDisponible {
                next_retry: SystemTime::now(),
                error: "estado del notificador bloqueado".to_string(),
            })
    }

    fn fijar_status(&self, nuevo: NotifierStatus) {
        if let Ok(mut estado) = self.status.lock() {
            *estado = nuevo;
        }
    }
}

/// Maneja el notificador desde el hilo de la TUI.
#[derive(Debug, Clone)]
pub struct NotifierHandle {
    tx: SyncSender<Notice>,
    compartido: Arc<Compartido>,
}

impl NotifierHandle {
    /// Encola una notificación sin bloquear (ADR-76).
    ///
    /// Devuelve `true` si ha quedado encolada; con el canal lleno la descarta y
    /// cuenta `notify_drops` (lo muestra Config).
    pub fn notify(&self, notice: Notice) -> bool {
        match self.tx.try_send(notice) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.compartido.drops.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Estado actual del notificador.
    pub fn status(&self) -> NotifierStatus {
        self.compartido.status()
    }

    /// Notificaciones descartadas por el canal lleno (`notify_drops`).
    pub fn drops(&self) -> u64 {
        self.compartido.drops.load(Ordering::Relaxed)
    }

    /// Notificaciones entregadas al servidor.
    pub fn enviadas(&self) -> u64 {
        self.compartido.enviadas.load(Ordering::Relaxed)
    }
}

/// Servicio `Notifier::spawn` del contrato (§5): alias de [`spawn`].
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)] // servicio del contrato; la TUI usa notify::spawn
pub struct Notifier;

impl Notifier {
    /// Arranca el hilo del notificador y devuelve su handle (ADR-76).
    #[allow(dead_code)]
    pub fn spawn(config: &NotifyConfig) -> NotifierHandle {
        spawn(*config)
    }
}

/// Arranca el hilo del notificador y devuelve su handle (ADR-76).
pub fn spawn(config: NotifyConfig) -> NotifierHandle {
    let estado_inicial = if config.enabled {
        // El nombre del servidor se pide en el hilo; hasta entonces se considera
        // disponible (si falla el primer envío pasará a NO DISPONIBLE).
        NotifierStatus::Disponible { server: None }
    } else {
        NotifierStatus::Apagado
    };
    let compartido = Arc::new(Compartido {
        status: Mutex::new(estado_inicial),
        drops: AtomicU64::new(0),
        enviadas: AtomicU64::new(0),
    });
    let (tx, rx) = mpsc::sync_channel(NOTIFY_CHANNEL_CAPACITY);
    if config.enabled {
        let estado = Arc::clone(&compartido);
        let resultado = thread::Builder::new()
            .name("almenara-notificaciones".to_string())
            .spawn(move || bucle(rx, estado));
        if let Err(err) = resultado {
            tracing::warn!(%err, "no se pudo arrancar el hilo del notificador");
            compartido.fijar_status(NotifierStatus::NoDisponible {
                next_retry: SystemTime::now() + RETRY_INTERVAL,
                error: format!("no se pudo arrancar el hilo: {err}"),
            });
        }
    } else {
        // Sin hilo: el receptor se cierra y notify() devuelve false.
        drop(rx);
    }
    NotifierHandle { tx, compartido }
}

/// Bucle del hilo del notificador.
fn bucle(rx: Receiver<Notice>, estado: Arc<Compartido>) {
    // Se pide el nombre del servidor al arrancar (§7.14 y §9).
    let mut servidor: Option<String> = None;
    match notify_rust::get_server_information() {
        Ok(info) => {
            servidor = Some(info.name);
            estado.fijar_status(NotifierStatus::Disponible {
                server: servidor.clone(),
            });
        }
        Err(err) => {
            tracing::warn!(%err, "no hay servidor de notificaciones de escritorio");
            estado.fijar_status(NotifierStatus::NoDisponible {
                next_retry: SystemTime::now() + RETRY_INTERVAL,
                error: err.to_string(),
            });
        }
    }

    while let Ok(notice) = rx.recv() {
        // Reintento como mucho cada RETRY_INTERVAL (§7.8 y §7.17).
        if let NotifierStatus::NoDisponible { next_retry, .. } = estado.status() {
            if SystemTime::now() < next_retry {
                continue;
            }
        }
        match enviar(&notice) {
            Ok(()) => {
                estado.enviadas.fetch_add(1, Ordering::Relaxed);
                if !estado.status().disponible() {
                    estado.fijar_status(NotifierStatus::Disponible {
                        server: servidor.clone(),
                    });
                }
            }
            Err(err) => {
                tracing::warn!(%err, "no se pudo enviar la notificación de escritorio");
                estado.fijar_status(NotifierStatus::NoDisponible {
                    next_retry: SystemTime::now() + RETRY_INTERVAL,
                    error: err.to_string(),
                });
            }
        }
    }
}

/// Envía una notificación por D-Bus de sesión.
fn enviar(notice: &Notice) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use notify_rust::{Notification, Timeout, Urgency};
    Notification::new()
        .appname(APP_NAME)
        .summary(&notice.summary)
        .body(&notice.body)
        .icon(ICON)
        .urgency(Urgency::Normal)
        .timeout(Timeout::Default)
        .show()
        .map(|_| ())
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
}

/// Formatea el reloj de pared de un reintento en hora local (HH:MM).
fn formatear_hora(instante: SystemTime) -> String {
    let local: chrono::DateTime<chrono::Local> = instante.into();
    local.format("%H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle_de_prueba(capacidad: usize) -> (NotifierHandle, Receiver<Notice>, Arc<Compartido>) {
        let (tx, rx) = mpsc::sync_channel(capacidad);
        let compartido = Arc::new(Compartido {
            status: Mutex::new(NotifierStatus::Disponible { server: None }),
            drops: AtomicU64::new(0),
            enviadas: AtomicU64::new(0),
        });
        (
            NotifierHandle {
                tx,
                compartido: Arc::clone(&compartido),
            },
            rx,
            compartido,
        )
    }

    #[test]
    fn apagado_no_encola_ni_envia() {
        let handle = spawn(NotifyConfig { enabled: false });
        assert_eq!(handle.status(), NotifierStatus::Apagado);
        assert!(!handle.notify(Notice {
            summary: "Almenara · Equipo nuevo".to_string(),
            body: "192.168.1.201".to_string(),
        }));
        assert_eq!(handle.drops(), 0);
    }

    #[test]
    fn el_canal_lleno_descarta_y_cuenta() {
        let (handle, _rx, _estado) = handle_de_prueba(1);
        assert!(handle.notify(Notice {
            summary: "uno".to_string(),
            body: "cuerpo".to_string(),
        }));
        assert!(!handle.notify(Notice {
            summary: "dos".to_string(),
            body: "cuerpo".to_string(),
        }));
        assert_eq!(handle.drops(), 1);
    }

    #[test]
    fn las_etiquetas_del_estado_son_texto_propio() {
        assert_eq!(NotifierStatus::Apagado.label(), "APAGADO");
        assert_eq!(
            NotifierStatus::Disponible {
                server: Some("mako".to_string())
            }
            .label(),
            "DISPONIBLE"
        );
        assert_eq!(
            NotifierStatus::NoDisponible {
                next_retry: SystemTime::now(),
                error: "sin bus".to_string(),
            }
            .label(),
            "NO DISPONIBLE"
        );
        assert!(NotifierStatus::Disponible { server: None }
            .summary()
            .contains("DISPONIBLE"));
        assert!(!NotifierStatus::Apagado.disponible());
    }
}
