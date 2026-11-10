//! Eventos de la aplicación y bus de comunicación entre tareas.
//!
//! La tarea de escaneo publica [`AppEvent`] en un canal `tokio::sync::broadcast`
//! (el bus de eventos); el bucle de la TUI los consume. Las órdenes de la TUI
//! hacia el escáner viajan por un canal `mpsc`.

use tokio::sync::{broadcast, mpsc};

use crate::notifier::Level;
use crate::scanner::ScanReport;
use crate::traffic::{DeviceRef, TrafficUpdate};

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
    /// Actualización periódica del tráfico en vivo (agregados, caché de
    /// conexiones y estado de la captura). Se publica una vez por segundo.
    Traffic(Box<TrafficUpdate>),
    /// Aviso asíncrono del subsistema de captura (filtro BPF inválido, límite
    /// max_pps alcanzado, descartes...). Se muestra como notificación normal.
    CaptureNotice {
        /// Nivel de la notificación.
        level: Level,
        /// Texto ya formateado en castellano.
        message: String,
    },
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

/// Órdenes que la TUI envía a la tarea de tráfico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficCommand {
    /// Sustituye el mapa de dispositivos usado para atribuir tráfico por IP.
    UpdateDevices(Vec<DeviceRef>),
    /// Termina la tarea de tráfico y para la captura.
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

/// Crea el canal de órdenes hacia la tarea de tráfico.
pub fn traffic_command_channel() -> (mpsc::Sender<TrafficCommand>, mpsc::Receiver<TrafficCommand>) {
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

    #[tokio::test]
    async fn el_canal_de_trafico_entrega_ordenes() {
        let (tx, mut rx) = traffic_command_channel();
        tx.send(TrafficCommand::UpdateDevices(vec![DeviceRef::new(
            1,
            "192.168.1.42",
        )]))
        .await
        .expect("enviar orden de tráfico");
        match rx.recv().await {
            Some(TrafficCommand::UpdateDevices(devices)) => {
                assert_eq!(devices[0].id, 1);
                assert_eq!(devices[0].ip, "192.168.1.42");
            }
            otro => panic!("orden inesperada: {otro:?}"),
        }
        assert!(tx.send(TrafficCommand::Stop).await.is_ok());
        assert_eq!(rx.recv().await, Some(TrafficCommand::Stop));
    }

    #[test]
    fn el_aviso_de_captura_lleva_nivel_y_mensaje() {
        let (tx, mut rx) = bus();
        tx.send(AppEvent::CaptureNotice {
            level: Level::Warn,
            message: "captura limitada a 1000 pps".to_string(),
        })
        .expect("publicar aviso");
        match rx.try_recv().expect("evento de aviso") {
            AppEvent::CaptureNotice { level, message } => {
                assert_eq!(level, Level::Warn);
                assert!(message.contains("limitada"));
            }
            otro => panic!("evento inesperado: {otro:?}"),
        }
    }
}
