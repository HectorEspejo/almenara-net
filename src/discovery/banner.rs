//! Banner grabbing por puerto abierto: lectura inicial, saneado y truncado.
//!
//! Decisiones:
//! - No se envían payloads: solo se lee lo que el servicio anuncia al conectar,
//!   respetando la especificación de seguridad de la Fase 2.
//! - Lectura máxima de MAX_BANNER_BYTES y timeout global de `timeout` (1 s en
//!   la orquestación); se deja de leer en cuanto el servicio calla, cierra o se
//!   agota el presupuesto de tiempo.
//! - El saneado sustituye cualquier byte no imprimible por '.', trunca a
//!   MAX_BANNER_CHARS caracteres y recorta los '.' y espacios de los extremos;
//!   así el CRLF final de los banners SSH/HTTP no ensucia el texto persistido.
//! - Antes de persistir solo se conserva el banner saneado; el original no se
//!   guarda nunca (minimización de datos).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;

/// Lectura máxima del banner en bytes.
pub const MAX_BANNER_BYTES: usize = 512;
/// Longitud máxima del banner saneado en caracteres.
pub const MAX_BANNER_CHARS: usize = 128;

/// Lector de banners.
#[derive(Debug, Clone, Copy)]
pub struct BannerGrab;

impl BannerGrab {
    /// Lee el banner inicial de un puerto abierto, si lo hay.
    ///
    /// Devuelve None si la conexión falla, si el servicio no anuncia nada en el
    /// timeout o si el banner se queda vacío tras el saneado.
    pub async fn grab(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
        let destino = SocketAddr::from((ip, port));
        let stream = tokio::time::timeout(timeout, TcpStream::connect(destino))
            .await
            .ok()?
            .ok()?;

        let limite = tokio::time::Instant::now() + timeout;
        let mut buffer = [0u8; MAX_BANNER_BYTES];
        let mut leidos = 0usize;

        while leidos < buffer.len() {
            let restante = limite.saturating_duration_since(tokio::time::Instant::now());
            if restante.is_zero() {
                break;
            }
            // Esperar a que haya datos disponibles o a que el otro extremo
            // cierre la conexión.
            match tokio::time::timeout(restante, stream.readable()).await {
                Ok(Ok(())) => {}
                _ => break,
            }
            match stream.try_read(&mut buffer[leidos..]) {
                Ok(0) => break, // fin de la conexión
                Ok(leidos_ahora) => leidos += leidos_ahora,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }

        if leidos == 0 {
            return None;
        }
        let saneado = Self::sanitize(&buffer[..leidos]);
        if saneado.is_empty() {
            None
        } else {
            Some(saneado)
        }
    }

    /// Sanea un banner: solo ASCII imprimible, trunca y recorta.
    ///
    /// Los bytes fuera del rango imprimible (0x20-0x7e) se sustituyen por '.',
    /// se trunca a MAX_BANNER_CHARS caracteres y se recortan los '.' y espacios
    /// de los extremos.
    pub fn sanitize(raw: &[u8]) -> String {
        let texto: String = raw
            .iter()
            .map(|byte| {
                if (0x20..=0x7e).contains(byte) {
                    *byte as char
                } else {
                    '.'
                }
            })
            .collect();
        let truncado: String = texto.chars().take(MAX_BANNER_CHARS).collect();
        truncado
            .trim_matches(|caracter: char| caracter.is_whitespace() || caracter == '.')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn sustituye_los_bytes_no_imprimibles() {
        assert_eq!(BannerGrab::sanitize(b"A\x00B"), "A.B");
        // Los bytes de negociación telnet (IAC) y los no ASCII quedan como
        // puntos y se recortan en los extremos.
        assert_eq!(
            BannerGrab::sanitize(&[0xff, 0xfd, 0x18, b'Z', 0xc3, 0xa9]),
            "Z"
        );
    }

    #[test]
    fn recorta_el_final_de_linea_y_los_espacios() {
        assert_eq!(BannerGrab::sanitize(b"\r\n"), "");
        assert_eq!(
            BannerGrab::sanitize(b"SSH-2.0-OpenSSH_9.6\r\n"),
            "SSH-2.0-OpenSSH_9.6"
        );
        assert_eq!(BannerGrab::sanitize(b"  hola  "), "hola");
    }

    #[test]
    fn trunca_a_ciento_veintiocho_caracteres() {
        let largo = vec![b'A'; MAX_BANNER_BYTES];
        assert_eq!(
            BannerGrab::sanitize(&largo).chars().count(),
            MAX_BANNER_CHARS
        );
    }

    #[tokio::test]
    async fn lee_el_banner_de_un_servidor_local() {
        let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(listener) => listener,
            Err(_) => return, // entorno sin sockets locales: test omitido
        };
        let direccion = match listener.local_addr() {
            Ok(direccion) => direccion,
            Err(_) => return,
        };
        let IpAddr::V4(ip) = direccion.ip() else {
            return;
        };

        let servidor = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut pendiente: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
            while !pendiente.is_empty() {
                if stream.writable().await.is_err() {
                    break;
                }
                match stream.try_write(pendiente) {
                    Ok(escritos) => pendiente = &pendiente[escritos..],
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
        });

        let banner = BannerGrab::grab(ip, direccion.port(), Duration::from_secs(1)).await;
        assert_eq!(banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
        servidor.abort();
    }

    #[tokio::test]
    async fn un_puerto_cerrado_no_devuelve_banner() {
        // Puerto reservado y liberado: el connect se rechaza.
        let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", 0)) else {
            return;
        };
        let Ok(direccion) = listener.local_addr() else {
            return;
        };
        drop(listener);
        let IpAddr::V4(ip) = direccion.ip() else {
            return;
        };

        let banner = BannerGrab::grab(ip, direccion.port(), Duration::from_millis(300)).await;
        assert!(banner.is_none());
    }
}
