//! Eventos de la aplicación y bus de comunicación entre tareas.
//!
//! La tarea de escaneo publica [`AppEvent`] en un canal `tokio::sync::broadcast`
//! (el bus de eventos); el bucle de la TUI los consume. Las órdenes de la TUI
//! hacia el escáner viajan por un canal `mpsc`.

use tokio::sync::{broadcast, mpsc};

use crate::scanner::ScanReport;

/// Capacidad del bus de eventos.
pub const EVENT_BUS_CAPACITY: usize = 64;

/// Eventos que viajan por el bus de la aplicación.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Comienza un ciclo de escaneo.
    ScanStarted,
    /// Un escaneo terminó y hay datos nuevos de equipos para refrescar la TUI.
    ///
    /// El payload es el informe de red; la reconciliación con la base de datos la
    /// hace el bucle de la TUI antes de actualizar la vista.
    Devices(Box<ScanReport>),
    /// Petición de cierre coordinado.
    Quit,
}

/// Órdenes que la TUI envía a la tarea de escaneo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCommand {
    /// Fuerza un escaneo inmediato.
    Rescan,
    /// Termina la tarea de escaneo.
    Stop,
}

/// Crea el bus de eventos y un receptor suscrito.
pub fn bus() -> (broadcast::Sender<AppEvent>, broadcast::Receiver<AppEvent>) {
    broadcast::channel(EVENT_BUS_CAPACITY)
}

/// Crea el canal de órdenes hacia el escáner.
pub fn command_channel() -> (mpsc::Sender<ScanCommand>, mpsc::Receiver<ScanCommand>) {
    mpsc::channel(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_bus_entrega_eventos_a_los_suscriptores() {
        let (tx, mut rx) = bus();
        tx.send(AppEvent::ScanStarted).unwrap();
        let evento = rx.try_recv().expect("debe haber un evento");
        assert!(matches!(evento, AppEvent::ScanStarted));
    }

    #[test]
    fn el_bus_sin_suscriptores_no_falla() {
        let (tx, rx) = bus();
        drop(rx);
        // Publicar sin receptores es un error controlado, no un panic.
        assert!(tx.send(AppEvent::ScanStarted).is_err());
    }
}
