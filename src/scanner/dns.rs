//! Resolución inversa de nombres (reverse DNS) con timeout y concurrencia limitada.
//!
//! La consulta real usa `getnameinfo(3)` en un hilo del pool de tokio para no
//! bloquear el runtime, y se envuelve en `tokio::time::timeout`. Sin PTR válido la
//! función devuelve `None`: nunca se usa la representación numérica de la IP como
//! si fuera un hostname.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::StreamExt;
use tokio::task::spawn_blocking;

/// Resuelve el nombre inverso de una IPv4. Devuelve None si falla o agota el timeout.
pub async fn resolve(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    if timeout.is_zero() {
        return None;
    }

    let consulta = spawn_blocking(move || resolver_con_getnameinfo(ip));
    match tokio::time::timeout(timeout, consulta).await {
        Ok(Ok(nombre)) => nombre,
        // Timeout agotado o tarea bloqueante cancelada: sin nombre.
        _ => None,
    }
}

/// Resuelve varios nombres con concurrencia limitada.
///
/// Las IPs repetidas se consultan una sola vez y el resultado se ordena por IP para
/// que sea determinista.
pub async fn resolve_many(
    ips: &[Ipv4Addr],
    timeout: Duration,
    concurrency: usize,
) -> Vec<(Ipv4Addr, String)> {
    let mut unicas = ips.to_vec();
    unicas.sort_unstable();
    unicas.dedup();

    if unicas.is_empty() || timeout.is_zero() {
        return Vec::new();
    }

    let limite = concurrency.max(1);
    let mut resueltos: Vec<(Ipv4Addr, String)> = futures::stream::iter(unicas)
        .map(|ip| async move { resolve(ip, timeout).await.map(|nombre| (ip, nombre)) })
        .buffer_unordered(limite)
        .filter_map(|resultado| async move { resultado })
        .collect()
        .await;

    resueltos.sort_by_key(|(ip, _)| *ip);
    resueltos
}

/// Consulta el nombre inverso de una IPv4 con `getnameinfo(3)`.
///
/// Se ejecuta en un hilo bloqueante; devuelve `None` si la resolución falla, si no
/// hay PTR (NI_NAMEREQD) o si el resultado es una representación numérica.
fn resolver_con_getnameinfo(ip: Ipv4Addr) -> Option<String> {
    // sockaddr_in con la IP en orden de red.
    let mut direccion: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    direccion.sin_family = libc::AF_INET as libc::sa_family_t;
    direccion.sin_port = 0;
    direccion.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());

    let mut buffer = [0 as libc::c_char; libc::NI_MAXHOST as usize];
    let resultado = unsafe {
        libc::getnameinfo(
            &direccion as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            buffer.as_mut_ptr(),
            buffer.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };

    if resultado != 0 {
        return None;
    }

    let nombre = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .trim()
        .trim_end_matches('.')
        .to_string();

    if nombre.is_empty() || nombre.parse::<Ipv4Addr>().is_ok() {
        None
    } else {
        Some(nombre)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_cero_no_resuelve() {
        assert!(resolve(Ipv4Addr::new(192, 0, 2, 1), Duration::ZERO)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn resolve_many_vacio_devuelve_vacio() {
        let resueltos = resolve_many(&[], Duration::from_millis(100), 4).await;
        assert!(resueltos.is_empty());
    }

    #[tokio::test]
    async fn resolve_many_con_timeout_cero_no_consulta_la_red() {
        let ips = [
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
            Ipv4Addr::new(192, 0, 2, 1),
        ];
        let resueltos = resolve_many(&ips, Duration::ZERO, 2).await;
        assert!(
            resueltos.is_empty(),
            "sin margen de tiempo no se resuelve nada"
        );
    }
}
