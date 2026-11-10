//! M-SEARCH activo SSDP.
//!
//! Envía un M-SEARCH al grupo 239.255.255.250:1900 y recoge las respuestas
//! unicast hasta agotar el timeout. El mensaje HTTPU se construye a mano porque
//! el crate ssdp 0.7 no compila en stable.
//!
//! Decisiones:
//! - El socket se liga a un puerto efímero: SSDP responde por unicast a la IP y
//!   puerto de origen, así no hace falta compartir el 1900 con el listener.
//! - El destinatario (ST) se valida antes de abrir el socket para no permitir
//!   inyección de cabeceras con saltos de línea.
//! - TTL multicast 2, el valor habitual para SSDP; si el sistema no lo acepta
//!   se continúa igualmente.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::error::{Error, Result};

use super::parser::{self, SsdpRecord};

/// Grupo multicast estándar de SSDP.
const GRUPO_SSDP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// Puerto estándar de SSDP.
const PUERTO_SSDP: u16 = 1900;
/// Tamaño máximo de un datagrama SSDP.
const MAX_DATAGRAMA: usize = 8192;
/// Respuestas máximas que se recopilan en una consulta.
const MAX_RESPUESTAS: usize = 256;

/// Consulta activa SSDP.
#[derive(Debug, Clone, Copy)]
pub struct SsdpQuery;

impl SsdpQuery {
    /// Envía un M-SEARCH y recoge las respuestas hasta el timeout.
    ///
    /// API del contrato; la orquestación usa [SsdpQuery::m_search_on] para
    /// enviar el multicast por la interfaz concreta del equipo.
    #[allow(dead_code)]
    pub async fn m_search(st: &str, timeout: Duration) -> Result<Vec<SsdpRecord>> {
        Self::m_search_on(Ipv4Addr::UNSPECIFIED, st, timeout).await
    }

    /// Igual que [SsdpQuery::m_search], enviando el multicast por la interfaz dada.
    pub async fn m_search_on(
        interface: Ipv4Addr,
        st: &str,
        timeout: Duration,
    ) -> Result<Vec<SsdpRecord>> {
        let peticion = construir_m_search(st)?;
        let socket = tokio::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|err| Error::Scan(format!("no se pudo abrir el socket SSDP: {err}")))?;
        if let Err(err) = socket.set_multicast_ttl_v4(2) {
            tracing::debug!(%err, "no se pudo fijar el TTL multicast de la consulta SSDP");
        }
        fijar_interfaz_multicast(&socket, interface);
        socket
            .send_to(&peticion, SocketAddrV4::new(GRUPO_SSDP, PUERTO_SSDP))
            .await
            .map_err(|err| Error::Scan(format!("no se pudo enviar el M-SEARCH: {err}")))?;

        let limite = tokio::time::Instant::now() + timeout;
        let mut datos = [0u8; MAX_DATAGRAMA];
        let mut respuestas: Vec<SsdpRecord> = Vec::new();
        loop {
            let restante = limite.saturating_duration_since(tokio::time::Instant::now());
            if restante.is_zero() || respuestas.len() >= MAX_RESPUESTAS {
                break;
            }
            match tokio::time::timeout(restante, socket.recv_from(&mut datos)).await {
                Err(_) => break,
                Ok(Err(err)) => {
                    tracing::debug!(%err, "error recibiendo respuestas SSDP");
                    break;
                }
                Ok(Ok((leidos, origen))) => {
                    if leidos == 0 {
                        continue;
                    }
                    match origen {
                        std::net::SocketAddr::V4(direccion) => {
                            if let Ok(registro) =
                                parser::parse_from(&datos[..leidos], *direccion.ip())
                            {
                                if respuestas.len() < MAX_RESPUESTAS {
                                    respuestas.push(registro);
                                }
                            }
                        }
                        std::net::SocketAddr::V6(_) => {}
                    }
                }
            }
        }
        Ok(respuestas)
    }
}

/// Fija la interfaz de salida del multicast (IP_MULTICAST_IF) si se conoce.
fn fijar_interfaz_multicast(socket: &tokio::net::UdpSocket, interface: Ipv4Addr) {
    if interface.is_unspecified() {
        return;
    }
    let direccion = libc::in_addr {
        s_addr: u32::from_ne_bytes(interface.octets()),
    };
    // SAFETY: se pasa un in_addr válido con su tamaño; un fallo solo implica que
    // se usa la interfaz por defecto del núcleo.
    let resultado = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            (&direccion as *const libc::in_addr).cast(),
            std::mem::size_of::<libc::in_addr>() as libc::socklen_t,
        )
    };
    if resultado != 0 {
        tracing::debug!(
            %interface,
            error = %std::io::Error::last_os_error(),
            "no se pudo fijar la interfaz multicast de la consulta SSDP"
        );
    }
}

/// Construye el datagrama M-SEARCH validando el destinatario.
fn construir_m_search(st: &str) -> Result<Vec<u8>> {
    let st = st.trim();
    if st.is_empty() {
        return Err(Error::Scan(
            "el destinatario del M-SEARCH (ST) no puede estar vacío".to_string(),
        ));
    }
    if st.chars().any(|caracter| caracter.is_control()) {
        return Err(Error::Scan(format!(
            "el destinatario del M-SEARCH (ST) no puede contener caracteres de control: {st}"
        )));
    }
    let peticion = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {GRUPO_SSDP}:{PUERTO_SSDP}\r\n\
         MAN: \"ssdp:all\"\r\n\
         MX: 1\r\n\
         ST: {st}\r\n\r\n"
    );
    Ok(peticion.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construye_un_m_search_valido() {
        let bytes = construir_m_search("ssdp:all").expect("M-SEARCH válido");
        let texto = String::from_utf8(bytes).expect("M-SEARCH es texto");

        assert!(texto.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(texto.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(texto.contains("MAN: \"ssdp:all\"\r\n"));
        assert!(texto.contains("MX: 1\r\n"));
        assert!(texto.contains("ST: ssdp:all\r\n"));
        assert!(texto.ends_with("\r\n\r\n"));
    }

    #[test]
    fn recorta_el_st_de_espacios() {
        let bytes = construir_m_search("  ssdp:all  ").expect("M-SEARCH válido");
        let texto = String::from_utf8(bytes).expect("M-SEARCH es texto");
        assert!(texto.contains("\r\nST: ssdp:all\r\n"));
    }

    #[test]
    fn rechaza_st_vacio_o_con_caracteres_de_control() {
        assert!(construir_m_search("").is_err());
        assert!(construir_m_search("   ").is_err());
        assert!(construir_m_search("ssdp:all\r\nInyectado: 1").is_err());
    }

    #[tokio::test]
    async fn m_search_rechaza_un_st_invalido_antes_de_abrir_el_socket() {
        let resultado = SsdpQuery::m_search("ssdp:all\nX: 1", Duration::from_millis(1)).await;
        assert!(resultado.is_err());
    }
}
