//! Detección de capabilities del proceso.
//!
//! La aplicación arranca siempre, pero si no puede crear sockets raw muestra un
//! modo degradado visible en la barra de estado. La detección se basa en intentar
//! abrir un socket raw ICMP: si el núcleo lo permite, existe CAP_NET_RAW efectiva.

/// Capacidades del proceso relativas a la red.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Indica si se pueden crear sockets raw (ARP/ICMP activos).
    pub raw_sockets: bool,
    /// Detalle legible para la interfaz.
    pub detail: String,
}

impl Capabilities {
    /// Detecta las capacidades del proceso actual.
    pub fn detect() -> Self {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
            Self {
                raw_sockets: true,
                detail: "CAP_NET_RAW detectada".to_string(),
            }
        } else {
            let err = std::io::Error::last_os_error();
            Self {
                raw_sockets: false,
                detail: format!("sin CAP_NET_RAW ({err})"),
            }
        }
    }

    /// Indica si la aplicación funciona en modo degradado.
    pub fn degraded(&self) -> bool {
        !self.raw_sockets
    }

    /// Etiqueta del modo para la barra de estado.
    pub fn mode_label(&self) -> &'static str {
        if self.raw_sockets {
            "privilegiado"
        } else {
            "degradado"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_no_entra_en_panico() {
        let caps = Capabilities::detect();
        if caps.raw_sockets {
            assert_eq!(caps.mode_label(), "privilegiado");
            assert!(!caps.degraded());
        } else {
            assert_eq!(caps.mode_label(), "degradado");
            assert!(caps.degraded());
        }
    }

    #[test]
    fn constructores_para_pruebas() {
        let degradado = Capabilities {
            raw_sockets: false,
            detail: "sin CAP_NET_RAW".to_string(),
        };
        assert!(degradado.degraded());
        assert_eq!(degradado.mode_label(), "degradado");
    }
}
