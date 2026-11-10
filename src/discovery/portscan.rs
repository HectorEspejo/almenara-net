//! Port scan TCP CONNECT sobre una lista de puertos.
//!
//! Decisiones:
//! - Se usa TCP CONNECT (sin privilegios) en lugar de SYN scan; encaja con el
//!   modo degradado y con [scan].passive_only, que desactiva el escaneo entero.
//! - Timeout por puerto y concurrencia limitada con `buffer_unordered`: el
//!   escaneo de los 20 puertos TOP sobre un equipo tarda como mucho una tanda
//!   de conexiones.
//! - Un fallo de conexión (rechazo, timeout, host inalcanzable) significa
//!   "puerto cerrado", no un error del escaneo: se devuelve la lista de
//!   puertos abiertos, ordenada y sin duplicados.
//! - Las opciones TCP se leen del socket ya conectado con
//!   Fingerprint::read_tcp_options; si no se pueden leer, se usan las opciones
//!   por defecto (vacías) y el puerto sigue contando como abierto.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;

use crate::error::Result;

use super::fingerprint::{Fingerprint, TcpOptions};

/// Puerto abierto detectado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenPort {
    /// Puerto TCP abierto.
    pub port: u16,
    /// Opciones TCP observadas al conectar.
    pub tcp_options: TcpOptions,
}

/// Escáner TCP CONNECT.
#[derive(Debug, Clone, Copy)]
pub struct PortScan;

impl PortScan {
    /// Escanea los puertos indicados con timeout y concurrencia limitada.
    ///
    /// Prueba como máximo `concurrency` puertos en paralelo (si se pasa 0 se
    /// trata como 1 para no romper el flujo). Devuelve los puertos abiertos de
    /// menor a mayor, sin duplicados.
    pub async fn scan(
        ip: Ipv4Addr,
        ports: &[u16],
        timeout: Duration,
        concurrency: usize,
    ) -> Result<Vec<OpenPort>> {
        if ports.is_empty() {
            return Ok(Vec::new());
        }

        let limite = concurrency.max(1);
        let mut sondeos = stream::iter(ports.iter().copied())
            .map(|port| Self::probe(ip, port, timeout))
            .buffer_unordered(limite);

        let mut abiertos = Vec::new();
        while let Some(abierto) = sondeos.next().await {
            if let Some(abierto) = abierto {
                abiertos.push(abierto);
            }
        }

        abiertos.sort_unstable_by_key(|abierto| abierto.port);
        abiertos.dedup_by_key(|abierto| abierto.port);
        Ok(abiertos)
    }

    /// Prueba un único puerto; devuelve sus opciones TCP si está abierto.
    async fn probe(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<OpenPort> {
        let destino = SocketAddr::from((ip, port));
        let stream = match tokio::time::timeout(timeout, TcpStream::connect(destino)).await {
            Ok(Ok(stream)) => stream,
            // Timeout, conexión rechazada, host inalcanzable...: puerto cerrado.
            _ => return None,
        };

        // tcp_info se lee del socket conectado: refleja las opciones negociadas
        // en el saludo TCP (MSS, timestamps, SACK, escala de ventana).
        let tcp_options = Fingerprint::read_tcp_options(stream.as_raw_fd()).unwrap_or_default();
        Some(OpenPort { port, tcp_options })
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use tokio::net::TcpListener;

    use super::*;

    /// Abre un listener local efímero; devuelve None si el entorno no permite
    /// crear sockets, en cuyo caso el test se omite.
    async fn listener_local() -> Option<(TcpListener, Ipv4Addr, u16)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.ok()?;
        let direccion = listener.local_addr().ok()?;
        let IpAddr::V4(ip) = direccion.ip() else {
            return None;
        };
        Some((listener, ip, direccion.port()))
    }

    /// Reserva un puerto local y lo libera. La probabilidad de que otro proceso
    /// lo ocupe entre ambas acciones es despreciable.
    fn puerto_cerrado() -> Option<u16> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let puerto = listener.local_addr().ok()?.port();
        drop(listener);
        Some(puerto)
    }

    #[tokio::test]
    async fn sin_puertos_no_hay_resultados() {
        let resultado = PortScan::scan(Ipv4Addr::LOCALHOST, &[], Duration::from_millis(100), 4)
            .await
            .expect("un escaneo vacío no falla");
        assert!(resultado.is_empty());
    }

    #[tokio::test]
    async fn detecta_puertos_abiertos_locales_y_descarta_los_cerrados() {
        let Some((listener, ip, puerto_abierto)) = listener_local().await else {
            return;
        };
        let Some(puerto_cerrado) = puerto_cerrado() else {
            return;
        };

        // Se aceptan las conexiones en segundo plano para no llenar la cola.
        let aceptador = tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        let abiertos = PortScan::scan(
            ip,
            &[puerto_abierto, puerto_cerrado],
            Duration::from_millis(300),
            8,
        )
        .await
        .expect("el escaneo no falla");

        assert!(abiertos
            .iter()
            .any(|abierto| abierto.port == puerto_abierto));
        assert!(!abiertos
            .iter()
            .any(|abierto| abierto.port == puerto_cerrado));
        aceptador.abort();
    }

    #[tokio::test]
    async fn devuelve_los_puertos_abiertos_ordenados() {
        let Some((primero, ip, puerto_a)) = listener_local().await else {
            return;
        };
        let Some((segundo, _, puerto_b)) = listener_local().await else {
            return;
        };
        // Un listener vivo basta: el connect completa sin necesidad de accept.
        let (mayor, menor) = if puerto_a > puerto_b {
            (puerto_a, puerto_b)
        } else {
            (puerto_b, puerto_a)
        };

        let abiertos = PortScan::scan(ip, &[mayor, menor], Duration::from_millis(300), 2)
            .await
            .expect("el escaneo no falla");
        let puertos: Vec<u16> = abiertos.iter().map(|abierto| abierto.port).collect();

        assert_eq!(puertos, vec![menor, mayor]);
        drop((primero, segundo));
    }
}
