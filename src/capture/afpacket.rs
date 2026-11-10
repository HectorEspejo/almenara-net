//! Socket AF_PACKET con anillo TPACKET_V3 para la captura en vivo de Almenara.
//!
//! El socket recibe todas las tramas de una interfaz (`ETH_P_ALL`) y el kernel
//! las deposita en un anillo de bloques mapeado en memoria con `mmap`. Cada
//! bloque se entrega al espacio de usuario con `TP_STATUS_USER` y se devuelve
//! al kernel con `TP_STATUS_KERNEL` en cuanto se han recorrido sus tramas. El
//! filtro BPF clásico se adjunta con `SO_ATTACH_FILTER` para descartar en el
//! kernel lo que no interesa. No se activa el modo promiscuo: Almenara solo
//! escucha el tráfico que la interfaz recibe de forma normal.
//!
//! La lectura evita copias intermedias: [AfPacketSocket::poll_frames] entrega a
//! la llamada de retorno una rebanada de la trama dentro del propio `mmap`, y
//! el consumidor copia solo las cabeceras que necesita.
//!
//! Este módulo es la única parte de la captura que necesita `CAP_NET_RAW`:
//! el resto (BPF, parser, agregación) se puede ejecutar y probar sin privilegios.

// El contrato de la fase expone ifindex, frames_total y drops_total para la
// integración con la TUI y el replay; la captura en vivo de F3 todavía no los
// consulta, así que el análisis de código muerto del binario los marcaría.
#![allow(dead_code)]

use std::fmt;
use std::io;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;

use crate::capture::bpf::BpfProgram;
use crate::capture::RingConfig;

/// Tiempo máximo que el kernel acumula paquetes en un bloque antes de
/// entregarlo aunque no esté lleno (100 ms, como recomienda la documentación
/// de TPACKET_V3 para captura interactiva).
const RETIRE_BLK_TOV_MS: u32 = 100;

/// Resultado de una vuelta de [AfPacketSocket::poll_frames].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollOutcome {
    /// Tramas entregadas a la llamada de retorno en esta vuelta.
    pub frames: u64,
    /// Paquetes descartados por el kernel desde la lectura anterior de
    /// estadísticas (anillo lleno, bloque perdido, etc.).
    pub drops: u64,
    /// Indica que `poll` agotó el tiempo de espera sin datos nuevos.
    pub timed_out: bool,
}

/// Error al abrir o leer el socket AF_PACKET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfPacketError {
    /// Mensaje legible en castellano.
    pub message: String,
}

impl AfPacketError {
    fn nuevo(mensaje: impl Into<String>) -> Self {
        Self {
            message: mensaje.into(),
        }
    }
}

impl fmt::Display for AfPacketError {
    fn fmt(&self, formateador: &mut fmt::Formatter<'_>) -> fmt::Result {
        formateador.write_str(&self.message)
    }
}

impl std::error::Error for AfPacketError {}

/// Socket AF_PACKET con un anillo TPACKET_V3 mapeado en memoria.
#[derive(Debug)]
pub struct AfPacketSocket {
    fd: libc::c_int,
    /// Base del `mmap` del anillo; nula si el socket aún no está mapeado.
    base: *mut u8,
    mmap_len: usize,
    ring: RingConfig,
    ifindex: i32,
    ifname: String,
    frames_totales: u64,
    drops_totales: u64,
}

// Safety: el socket no comparte estado mutable con otros hilos; moverlo a otro
// hilo es seguro porque todas las lecturas del anillo pasan por `&mut self` y
// el `mmap` solo se libera en Drop.
unsafe impl Send for AfPacketSocket {}

impl AfPacketSocket {
    /// Abre el socket AF_PACKET, prepara el anillo TPACKET_V3 y, si hay filtro,
    /// lo adjunta con `SO_ATTACH_FILTER`.
    ///
    /// Sin `CAP_NET_RAW` devuelve un error claro que empieza por
    /// "sin CAP_NET_RAW". Si la interfaz no existe, el error lo indica antes de
    /// intentar abrir el socket.
    pub fn open(
        ifname: &str,
        ring: RingConfig,
        filter: Option<&BpfProgram>,
    ) -> Result<Self, AfPacketError> {
        validar_anillo(&ring)?;
        let ifindex = buscar_ifindex(ifname)?;
        let fd = configurar_socket(ifname, ifindex, &ring)?;
        let mmap_len = ring.bytes();
        let base = mapear_anillo(fd, mmap_len)?;
        if let Some(programa) = filter {
            if !programa.is_empty() {
                if let Err(error) = programa.attach(fd) {
                    unsafe {
                        libc::munmap(base.cast::<libc::c_void>(), mmap_len);
                        libc::close(fd);
                    }
                    return Err(AfPacketError::nuevo(format!(
                        "no se pudo adjuntar el filtro BPF al socket AF_PACKET: {error}"
                    )));
                }
            }
        }
        Ok(Self {
            fd,
            base,
            mmap_len,
            ring,
            ifindex,
            ifname: ifname.to_string(),
            frames_totales: 0,
            drops_totales: 0,
        })
    }

    /// Nombre de la interfaz sobre la que captura el socket.
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Índice de la interfaz (lo usa el kernel para` bind`).
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Tramas entregadas desde que se abrió el socket.
    pub fn frames_total(&self) -> u64 {
        self.frames_totales
    }

    /// Paquetes descartados por el kernel desde que se abrió el socket.
    pub fn drops_total(&self) -> u64 {
        self.drops_totales
    }

    /// Espera datos con `poll` y recorre todos los bloques que el kernel haya
    /// entregado, llamando a `on_frame` con cada trama Ethernet (hasta
    /// `tp_snaplen` bytes) y reciclando los bloques al terminar.
    ///
    /// `timed_out` vale `true` cuando `poll` agota el tiempo sin datos; en ese
    /// caso no se leen las estadísticas del kernel y `drops` es cero.
    pub fn poll_frames(
        &mut self,
        timeout: Duration,
        on_frame: &mut dyn FnMut(&[u8]),
    ) -> Result<PollOutcome, AfPacketError> {
        if self.fd < 0 {
            return Err(AfPacketError::nuevo("el socket AF_PACKET no está abierto"));
        }
        if self.base.is_null() {
            return Err(AfPacketError::nuevo("el anillo AF_PACKET no está mapeado"));
        }

        let mut descriptor = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let listos = unsafe { libc::poll(&mut descriptor, 1, timeout_a_milisegundos(timeout)) };
        if listos < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                // Una señal interrumpió la espera: se trata como tiempo agotado
                // para no perder el bucle de captura.
                return Ok(PollOutcome {
                    frames: 0,
                    drops: 0,
                    timed_out: true,
                });
            }
            return Err(AfPacketError::nuevo(format!(
                "error al esperar datos del anillo AF_PACKET: {error}"
            )));
        }
        if listos == 0 {
            return Ok(PollOutcome {
                frames: 0,
                drops: 0,
                timed_out: true,
            });
        }

        let mut resultado = PollOutcome {
            frames: 0,
            drops: 0,
            timed_out: false,
        };
        let tamano_bloque = self.ring.block_size as usize;
        for indice in 0..self.ring.block_nr as usize {
            let base_bloque = unsafe { self.base.add(indice * tamano_bloque) };
            resultado.frames += unsafe { self.procesar_bloque(base_bloque, on_frame) };
        }
        resultado.drops = self.leer_drops()?;
        self.frames_totales = self.frames_totales.saturating_add(resultado.frames);
        self.drops_totales = self.drops_totales.saturating_add(resultado.drops);
        Ok(resultado)
    }

    /// Recorre las tramas de un bloque si el kernel se lo ha entregado.
    ///
    /// Seguridad: `base` debe apuntar al inicio de un bloque del anillo (al
    /// menos `ring.block_size` bytes) y estar alineado a 8 bytes, que es la
    /// alineación que garantiza el `mmap` cuando el tamaño de bloque es
    /// múltiplo de página (siempre, tras validar la configuración).
    ///
    /// Cualquier anillo truncado o corrupto corta la lectura sin panic y recicla
    /// el bloque igualmente.
    unsafe fn procesar_bloque(&self, base: *mut u8, on_frame: &mut dyn FnMut(&[u8])) -> u64 {
        let tamano_bloque = self.ring.block_size as usize;
        let descripcion = base.cast::<libc::tpacket_block_desc>();
        // Safety: el bloque está alineado y tiene el tamaño configurado; el
        // acceso a la unión `hdr` es válido porque el kernel usa la variante v1
        // al configurar el anillo en TPACKET_V3.
        let estado = unsafe { (*descripcion).hdr.bh1.block_status };
        if estado & libc::TP_STATUS_USER == 0 {
            return 0;
        }
        let num_paquetes = unsafe { (*descripcion).hdr.bh1.num_pkts } as usize;
        let mut desplazamiento = unsafe { (*descripcion).hdr.bh1.offset_to_first_pkt } as usize;
        let tamano_cabecera = std::mem::size_of::<libc::tpacket3_hdr>();
        let limite_frame = self.ring.frame_size as usize;
        let mut tramas = 0u64;

        for _ in 0..num_paquetes {
            // Si la cabecera no cabe entera, el anillo está corrupto: se corta.
            let Some(fin_cabecera) = desplazamiento.checked_add(tamano_cabecera) else {
                break;
            };
            if fin_cabecera > tamano_bloque {
                break;
            }
            let cabecera_paquete = base.add(desplazamiento).cast::<libc::tpacket3_hdr>();
            // Safety: la cabecera cabe en el bloque y el bloque es propiedad del
            // espacio de usuario (TP_STATUS_USER).
            let paquete = unsafe { &*cabecera_paquete };
            // tp_mac es el desplazamiento desde el inicio de ESTA cabecera hasta
            // la cabecera MAC: el kernel escribe la trama en h.raw + tp_mac.
            let Some(inicio_trama) = desplazamiento.checked_add(paquete.tp_mac as usize) else {
                break;
            };
            let longitud = paquete.tp_snaplen as usize;
            if longitud > limite_frame {
                break;
            }
            let Some(fin_trama) = inicio_trama.checked_add(longitud) else {
                break;
            };
            if fin_trama > tamano_bloque {
                break;
            }
            // Safety: la trama está dentro del bloque mapeado y el kernel ya no
            // la escribe mientras el bloque está en TP_STATUS_USER.
            let trama = unsafe { std::slice::from_raw_parts(base.add(inicio_trama), longitud) };
            on_frame(trama);
            tramas += 1;

            if paquete.tp_next_offset == 0 {
                break;
            }
            let Some(siguiente) = desplazamiento.checked_add(paquete.tp_next_offset as usize)
            else {
                break;
            };
            if siguiente <= desplazamiento || siguiente >= tamano_bloque {
                break;
            }
            desplazamiento = siguiente;
        }

        // Devolver el bloque al kernel. La barrera evita que el compilador
        // mueva la escritura de estado por delante de las lecturas.
        compiler_fence(Ordering::Release);
        unsafe {
            std::ptr::write_volatile(
                std::ptr::addr_of_mut!((*descripcion).hdr.bh1.block_status),
                libc::TP_STATUS_KERNEL,
            );
        }
        compiler_fence(Ordering::Acquire);
        tramas
    }

    /// Lee y reinicia los contadores de descartes del kernel (`PACKET_STATISTICS`).
    fn leer_drops(&self) -> Result<u64, AfPacketError> {
        // El kernel usa `tpacket_stats_v3` (12 bytes) para anillos V3; los dos
        // primeros campos coinciden con `tpacket_stats`.
        let mut estadisticas = libc::tpacket_stats_v3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };
        let mut longitud = std::mem::size_of::<libc::tpacket_stats_v3>() as libc::socklen_t;
        let resultado = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                std::ptr::addr_of_mut!(estadisticas).cast::<libc::c_void>(),
                &mut longitud,
            )
        };
        if resultado < 0 {
            return Err(AfPacketError::nuevo(format!(
                "no se pudieron leer las estadísticas del anillo AF_PACKET: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(u64::from(estadisticas.tp_drops))
    }
}

impl Drop for AfPacketSocket {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                libc::munmap(self.base.cast::<libc::c_void>(), self.mmap_len);
            }
            self.base = std::ptr::null_mut();
        }
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

/// Valida la configuración del anillo antes de tocar el kernel.
///
/// Las restricciones son las que impone `packet_set_ring`: tamaño de bloque
/// múltiplo de página, frame alineado a 16 bytes y mayor que la cabecera
/// TPACKET_V3, y bloque dividido en frames enteros.
fn validar_anillo(ring: &RingConfig) -> Result<(), AfPacketError> {
    if ring.block_nr == 0 {
        return Err(AfPacketError::nuevo(
            "configuración del anillo inválida: «block_nr» debe ser mayor que cero",
        ));
    }
    if ring.block_size == 0 {
        return Err(AfPacketError::nuevo(
            "configuración del anillo inválida: «block_size» debe ser mayor que cero",
        ));
    }
    if ring.frame_size == 0 {
        return Err(AfPacketError::nuevo(
            "configuración del anillo inválida: «frame_size» debe ser mayor que cero",
        ));
    }
    let pagina = tamano_pagina();
    if !(ring.block_size as usize).is_multiple_of(pagina) {
        return Err(AfPacketError::nuevo(format!(
            "configuración del anillo inválida: «block_size» ({}) debe ser múltiplo del tamaño de página ({pagina})",
            ring.block_size
        )));
    }
    if !(ring.frame_size as usize).is_multiple_of(libc::TPACKET_ALIGNMENT) {
        return Err(AfPacketError::nuevo(format!(
            "configuración del anillo inválida: «frame_size» ({}) debe ser múltiplo de {}",
            ring.frame_size,
            libc::TPACKET_ALIGNMENT
        )));
    }
    if (ring.frame_size as usize) < libc::TPACKET3_HDRLEN {
        return Err(AfPacketError::nuevo(format!(
            "configuración del anillo inválida: «frame_size» ({}) es menor que la cabecera TPACKET_V3 ({} bytes)",
            ring.frame_size,
            libc::TPACKET3_HDRLEN
        )));
    }
    if !ring.block_size.is_multiple_of(ring.frame_size) {
        return Err(AfPacketError::nuevo(format!(
            "configuración del anillo inválida: «block_size» ({}) debe ser múltiplo de «frame_size» ({})",
            ring.block_size, ring.frame_size
        )));
    }
    let total = u64::from(ring.block_size) * u64::from(ring.block_nr);
    if usize::try_from(total).is_err() {
        return Err(AfPacketError::nuevo(
            "configuración del anillo inválida: el tamaño total no cabe en memoria",
        ));
    }
    if frames_totales(ring).is_none() {
        return Err(AfPacketError::nuevo(
            "configuración del anillo inválida: el número total de frames desborda u32",
        ));
    }
    Ok(())
}

/// Número total de frames del anillo: block_nr * (block_size / frame_size).
///
/// Es el valor que el kernel valida contra tp_frame_nr en packet_set_ring;
/// debe caber en u32. Solo se llama con una configuración ya validada (bloque
/// múltiplo del frame y no vacío).
fn frames_totales(ring: &RingConfig) -> Option<u32> {
    let frames_por_bloque = ring.block_size / ring.frame_size;
    frames_por_bloque.checked_mul(ring.block_nr)
}

/// Tamaño de página del sistema (4 KB si `sysconf` falla).
fn tamano_pagina() -> usize {
    let pagina = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pagina <= 0 {
        4096
    } else {
        pagina as usize
    }
}

/// Índice de la interfaz a partir de su nombre.
fn buscar_ifindex(ifname: &str) -> Result<i32, AfPacketError> {
    if ifname.is_empty() {
        return Err(AfPacketError::nuevo("el nombre de la interfaz está vacío"));
    }
    if ifname.len() >= libc::IFNAMSIZ {
        return Err(AfPacketError::nuevo(format!(
            "el nombre de la interfaz «{ifname}» es demasiado largo (máximo {} caracteres)",
            libc::IFNAMSIZ - 1
        )));
    }
    let nombre = std::ffi::CString::new(ifname)
        .map_err(|_| AfPacketError::nuevo("el nombre de la interfaz contiene un byte nulo"))?;
    let indice = unsafe { libc::if_nametoindex(nombre.as_ptr()) };
    if indice == 0 {
        return Err(AfPacketError::nuevo(format!(
            "interfaz no encontrada: «{ifname}» ({})",
            io::Error::last_os_error()
        )));
    }
    i32::try_from(indice).map_err(|_| {
        AfPacketError::nuevo(format!("índice de interfaz fuera de rango para «{ifname}»"))
    })
}

/// Mensaje de error al crear el socket, distinguiendo la falta de privilegios.
fn error_al_abrir_socket(ifname: &str, error: &io::Error) -> AfPacketError {
    match error.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => AfPacketError::nuevo(format!(
            "sin CAP_NET_RAW: no se puede abrir el socket AF_PACKET en «{ifname}»: {error}"
        )),
        _ => AfPacketError::nuevo(format!(
            "no se puede abrir el socket AF_PACKET en «{ifname}»: {error}"
        )),
    }
}

/// Crea el socket AF_PACKET y lo configura con el anillo TPACKET_V3.
fn configurar_socket(
    ifname: &str,
    ifindex: i32,
    ring: &RingConfig,
) -> Result<libc::c_int, AfPacketError> {
    let protocolo = (libc::ETH_P_ALL as u16).to_be();
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::c_int::from(protocolo),
        )
    };
    if fd < 0 {
        return Err(error_al_abrir_socket(ifname, &io::Error::last_os_error()));
    }
    match preparar_anillo(fd, ifname, ifindex, protocolo, ring) {
        Ok(()) => Ok(fd),
        Err(error) => {
            unsafe {
                libc::close(fd);
            }
            Err(error)
        }
    }
}

/// Asocia el socket a la interfaz y le configura `PACKET_VERSION` y
/// `PACKET_RX_RING`. No cierra el descriptor si falla: lo hace el llamante.
fn preparar_anillo(
    fd: libc::c_int,
    ifname: &str,
    ifindex: i32,
    protocolo: u16,
    ring: &RingConfig,
) -> Result<(), AfPacketError> {
    let direccion = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocolo,
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let resultado = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(direccion).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if resultado < 0 {
        return Err(AfPacketError::nuevo(format!(
            "no se pudo asociar el socket AF_PACKET a la interfaz «{ifname}»: {}",
            io::Error::last_os_error()
        )));
    }

    let version = libc::tpacket_versions::TPACKET_V3 as libc::c_int;
    opcion_socket(
        fd,
        libc::PACKET_VERSION,
        std::ptr::addr_of!(version).cast::<libc::c_void>(),
        std::mem::size_of::<libc::c_int>(),
        "no se pudo configurar el anillo en TPACKET_V3",
    )?;

    // packet_set_ring exige que tp_frame_nr sea exactamente
    // block_nr * (block_size / frame_size) también en TPACKET_V3: si se deja
    // a cero el kernel devuelve EINVAL. validar_anillo garantiza que el
    // producto cabe en u32.
    let frames = frames_totales(ring).ok_or_else(|| {
        AfPacketError::nuevo(
            "configuración del anillo inválida: el número total de frames desborda u32",
        )
    })?;
    let peticion = libc::tpacket_req3 {
        tp_block_size: ring.block_size,
        tp_block_nr: ring.block_nr,
        tp_frame_size: ring.frame_size,
        tp_frame_nr: frames,
        tp_retire_blk_tov: RETIRE_BLK_TOV_MS,
        tp_sizeof_priv: 0,
        tp_feature_req_word: 0,
    };
    opcion_socket(
        fd,
        libc::PACKET_RX_RING,
        std::ptr::addr_of!(peticion).cast::<libc::c_void>(),
        std::mem::size_of::<libc::tpacket_req3>(),
        "no se pudo crear el anillo TPACKET_V3",
    )?;
    Ok(())
}

/// Wrapper de `setsockopt` sobre el nivel `SOL_PACKET` con mensaje propio.
fn opcion_socket(
    fd: libc::c_int,
    opcion: libc::c_int,
    valor: *const libc::c_void,
    longitud: usize,
    contexto: &str,
) -> Result<(), AfPacketError> {
    let resultado = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            opcion,
            valor,
            longitud as libc::socklen_t,
        )
    };
    if resultado < 0 {
        return Err(AfPacketError::nuevo(format!(
            "{contexto}: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Mapea el anillo. Si `mmap` falla, cierra el descriptor antes de devolver el
/// error (el llamante ya no puede seguir usando el socket).
fn mapear_anillo(fd: libc::c_int, mmap_len: usize) -> Result<*mut u8, AfPacketError> {
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mmap_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(AfPacketError::nuevo(format!(
            "no se pudo mapear el anillo TPACKET_V3: {error}"
        )));
    }
    Ok(base.cast::<u8>())
}

/// Convierte un `Duration` al `timeout` de `poll` en milisegundos.
fn timeout_a_milisegundos(timeout: Duration) -> libc::c_int {
    let milisegundos = timeout.as_millis();
    if milisegundos > i32::MAX as u128 {
        i32::MAX
    } else {
        milisegundos as libc::c_int
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // --- Configuración del anillo -----------------------------------------

    #[test]
    fn el_anillo_por_defecto_es_valido() {
        validar_anillo(&RingConfig::default()).expect("el anillo por defecto debe ser válido");
    }

    #[test]
    fn el_numero_de_frames_se_calcula_para_tpacket_v3() {
        // El kernel valida tp_frame_nr == block_nr * (block_size / frame_size);
        // dejar tp_frame_nr a cero provoca EINVAL en PACKET_RX_RING.
        let por_defecto = RingConfig::default();
        assert_eq!(frames_totales(&por_defecto), Some(16_384));
        assert_eq!(
            frames_totales(&RingConfig {
                block_size: 65_536,
                block_nr: 4,
                frame_size: 4096,
            }),
            Some(64)
        );
        assert_eq!(
            frames_totales(&RingConfig {
                block_size: 1_048_576,
                block_nr: 1,
                frame_size: 4096,
            }),
            Some(256)
        );
    }

    #[test]
    fn un_numero_de_frames_desbordado_se_rechaza_antes_del_kernel() {
        let ring = RingConfig {
            block_size: u32::MAX - 4095,
            block_nr: u32::MAX,
            frame_size: 4096,
        };
        assert_eq!(frames_totales(&ring), None);
        let error = validar_anillo(&ring).expect_err("debe rechazarse");
        assert!(error.message.contains("frames"), "{error}");
    }

    #[test]
    fn rechaza_anillos_invalidos_con_mensaje_claro() {
        let casos: [(RingConfig, &str); 6] = [
            (
                RingConfig {
                    block_nr: 0,
                    ..RingConfig::default()
                },
                "block_nr",
            ),
            (
                RingConfig {
                    block_size: 0,
                    ..RingConfig::default()
                },
                "block_size",
            ),
            (
                RingConfig {
                    frame_size: 0,
                    ..RingConfig::default()
                },
                "frame_size",
            ),
            (
                RingConfig {
                    block_size: 1000,
                    block_nr: 1,
                    frame_size: 512,
                },
                "tamaño de página",
            ),
            (
                RingConfig {
                    block_size: 4096,
                    block_nr: 1,
                    frame_size: 4088,
                },
                "múltiplo de 16",
            ),
            (
                RingConfig {
                    block_size: 4096,
                    block_nr: 1,
                    frame_size: 3072,
                },
                "múltiplo de «frame_size»",
            ),
        ];
        for (anillo, fragmento) in casos {
            let error = validar_anillo(&anillo).expect_err("el anillo debería ser inválido");
            assert!(
                error.message.contains(fragmento),
                "mensaje inesperado para {anillo:?}: {error}"
            );
        }
    }

    #[test]
    fn el_error_se_muestra_en_castellano_y_es_std_error() {
        let error = validar_anillo(&RingConfig {
            block_nr: 0,
            ..RingConfig::default()
        })
        .expect_err("anillo inválido");
        assert_eq!(error.to_string(), error.message);
        assert!(std::error::Error::source(&error).is_none());
    }

    // --- Interfaz ---------------------------------------------------------

    #[test]
    fn interfaz_inexistente_devuelve_error_en_castellano() {
        let error = buscar_ifindex("almenara0").expect_err("la interfaz no existe");
        assert!(error.message.contains("interfaz no encontrada"), "{error}");
        assert!(error.message.contains("almenara0"), "{error}");
    }

    #[test]
    fn nombres_de_interfaz_invalidos() {
        let vacio = buscar_ifindex("").expect_err("nombre vacío");
        assert!(vacio.message.contains("vacío"), "{vacio}");

        let largo = "a".repeat(libc::IFNAMSIZ);
        let error = buscar_ifindex(&largo).expect_err("nombre demasiado largo");
        assert!(error.message.contains("demasiado largo"), "{error}");

        let nulo = buscar_ifindex("con\0nulo").expect_err("contiene un byte nulo");
        assert!(nulo.message.contains("nulo"), "{nulo}");
    }

    #[test]
    fn el_error_sin_cap_net_raw_es_claro() {
        let sin_permiso = io::Error::from_raw_os_error(libc::EPERM);
        let error = error_al_abrir_socket("eth0", &sin_permiso);
        assert!(
            error
                .message
                .starts_with("sin CAP_NET_RAW: no se puede abrir el socket AF_PACKET"),
            "{error}"
        );

        let sin_acceso = io::Error::from_raw_os_error(libc::EACCES);
        assert!(error_al_abrir_socket("eth0", &sin_acceso)
            .message
            .contains("CAP_NET_RAW"));

        let otro = io::Error::from_raw_os_error(libc::ENOBUFS);
        let error = error_al_abrir_socket("eth0", &otro);
        assert!(!error.message.contains("CAP_NET_RAW"), "{error}");
        assert!(error.message.contains("eth0"), "{error}");
    }

    #[test]
    fn abrir_con_un_anillo_invalido_falla_antes_de_tocar_el_kernel() {
        let anillo = RingConfig {
            block_size: 0,
            ..RingConfig::default()
        };
        let error = AfPacketSocket::open("lo", anillo, None)
            .expect_err("el anillo es inválido aunque la interfaz exista");
        assert!(error.message.contains("block_size"), "{error}");
    }

    #[test]
    fn abrir_una_interfaz_inexistente_no_necesita_privilegios() {
        let error = AfPacketSocket::open("almenara0", RingConfig::default(), None)
            .expect_err("la interfaz no existe");
        assert!(error.message.contains("interfaz no encontrada"), "{error}");
    }

    // --- Utilidades -------------------------------------------------------

    #[test]
    fn convierte_el_timeout_a_milisegundos() {
        assert_eq!(timeout_a_milisegundos(Duration::from_millis(150)), 150);
        assert_eq!(timeout_a_milisegundos(Duration::from_secs(10)), 10_000);
        assert_eq!(timeout_a_milisegundos(Duration::ZERO), 0);
        assert_eq!(timeout_a_milisegundos(Duration::MAX), i32::MAX);
    }

    #[test]
    fn el_socket_se_puede_mover_entre_hilos() {
        fn requiere_send<T: Send>() {}
        requiere_send::<AfPacketSocket>();
    }

    // --- Bloques sintéticos -----------------------------------------------

    /// Búfer alineado a 64 bytes para escribir cabeceras TPACKET_V3 en pruebas.
    #[repr(align(64))]
    struct BloqueSintetico([u8; 2048]);

    fn socket_falso(block_size: u32, frame_size: u32) -> AfPacketSocket {
        AfPacketSocket {
            fd: -1,
            base: std::ptr::null_mut(),
            mmap_len: 0,
            ring: RingConfig {
                block_size,
                block_nr: 1,
                frame_size,
            },
            ifindex: 7,
            ifname: "prueba0".to_string(),
            frames_totales: 0,
            drops_totales: 0,
        }
    }

    /// Escribe un bloque sintético con las tramas indicadas y devuelve su base.
    fn preparar_bloque(buffer: &mut BloqueSintetico, tramas: &[&[u8]]) -> *mut u8 {
        let base = buffer.0.as_mut_ptr();
        let tamano_bloque = buffer.0.len();
        let tamano_cabecera = std::mem::size_of::<libc::tpacket3_hdr>();
        let primero = 64usize;
        unsafe {
            let descripcion = base.cast::<libc::tpacket_block_desc>();
            (*descripcion).version = libc::tpacket_versions::TPACKET_V3 as u32;
            (*descripcion).offset_to_priv = 0;
            (*descripcion).hdr.bh1.block_status = libc::TP_STATUS_USER;
            (*descripcion).hdr.bh1.num_pkts = tramas.len() as u32;
            (*descripcion).hdr.bh1.offset_to_first_pkt = primero as u32;
            (*descripcion).hdr.bh1.blk_len = tamano_bloque as u32;
            (*descripcion).hdr.bh1.seq_num = 1;
        }
        let mut desplazamiento = primero;
        for (indice, trama) in tramas.iter().enumerate() {
            let inicio_datos = desplazamiento + tamano_cabecera;
            let cabecera = base
                .wrapping_add(desplazamiento)
                .cast::<libc::tpacket3_hdr>();
            let es_ultima = indice + 1 == tramas.len();
            let tamano_frame = (tamano_cabecera + trama.len()).div_ceil(16) * 16;
            unsafe {
                (*cabecera).tp_sec = 1;
                (*cabecera).tp_nsec = 0;
                (*cabecera).tp_snaplen = trama.len() as u32;
                (*cabecera).tp_len = trama.len() as u32;
                (*cabecera).tp_status = libc::TP_STATUS_USER;
                // tp_mac es relativo al inicio de la cabecera TPACKET3, no al bloque.
                (*cabecera).tp_mac = tamano_cabecera as u16;
                (*cabecera).tp_net = 0;
                std::ptr::copy_nonoverlapping(trama.as_ptr(), base.add(inicio_datos), trama.len());
                (*cabecera).tp_next_offset = if es_ultima { 0 } else { tamano_frame as u32 };
            }
            if !es_ultima {
                desplazamiento += tamano_frame;
            }
        }
        base
    }

    #[test]
    fn expone_el_nombre_el_indice_y_los_contadores() {
        let socket = socket_falso(2048, 512);
        assert_eq!(socket.ifname(), "prueba0");
        assert_eq!(socket.ifindex(), 7);
        assert_eq!(socket.frames_total(), 0);
        assert_eq!(socket.drops_total(), 0);
    }

    #[test]
    fn procesa_un_bloque_con_dos_tramas_y_lo_recicla() {
        let mut buffer = Box::new(BloqueSintetico([0u8; 2048]));
        let primera = b"\x00\x11\x22\x33\x44\x55";
        let segunda = b"\xaa\xbb\xcc";
        let base = preparar_bloque(&mut buffer, &[&primera[..], &segunda[..]]);
        let socket = socket_falso(2048, 512);
        let mut recibidas: Vec<Vec<u8>> = Vec::new();
        let tramas = unsafe {
            socket.procesar_bloque(base, &mut |trama: &[u8]| recibidas.push(trama.to_vec()))
        };
        assert_eq!(tramas, 2);
        assert_eq!(recibidas, vec![primera.to_vec(), segunda.to_vec()]);
        let estado = unsafe {
            (*base.cast::<libc::tpacket_block_desc>())
                .hdr
                .bh1
                .block_status
        };
        assert_eq!(estado, libc::TP_STATUS_KERNEL);
    }

    #[test]
    fn ignora_los_bloques_que_siguen_en_el_kernel() {
        let mut buffer = Box::new(BloqueSintetico([0u8; 2048]));
        let base = buffer.0.as_mut_ptr();
        let socket = socket_falso(2048, 512);
        let tramas = unsafe {
            socket.procesar_bloque(base, &mut |_: &[u8]| panic!("no debería leer tramas"))
        };
        assert_eq!(tramas, 0);
    }

    #[test]
    fn un_bloque_truncado_no_hace_panic_y_se_recicla() {
        let mut buffer = Box::new(BloqueSintetico([0u8; 2048]));
        let base = buffer.0.as_mut_ptr();
        unsafe {
            let descripcion = base.cast::<libc::tpacket_block_desc>();
            (*descripcion).hdr.bh1.block_status = libc::TP_STATUS_USER;
            (*descripcion).hdr.bh1.num_pkts = 100;
            // El primer paquete empieza donde ya no cabe su cabecera.
            (*descripcion).hdr.bh1.offset_to_first_pkt = 2048 - 8;
            (*descripcion).hdr.bh1.blk_len = 2048;
        }
        let socket = socket_falso(2048, 512);
        let mut llamadas = 0u32;
        let tramas = unsafe { socket.procesar_bloque(base, &mut |_: &[u8]| llamadas += 1) };
        assert_eq!(tramas, 0);
        assert_eq!(llamadas, 0);
        let estado = unsafe {
            (*base.cast::<libc::tpacket_block_desc>())
                .hdr
                .bh1
                .block_status
        };
        assert_eq!(estado, libc::TP_STATUS_KERNEL);
    }

    #[test]
    fn una_trama_con_longitud_imposible_no_hace_panic() {
        let mut buffer = Box::new(BloqueSintetico([0u8; 2048]));
        let base = buffer.0.as_mut_ptr();
        unsafe {
            let descripcion = base.cast::<libc::tpacket_block_desc>();
            (*descripcion).hdr.bh1.block_status = libc::TP_STATUS_USER;
            (*descripcion).hdr.bh1.num_pkts = 1;
            (*descripcion).hdr.bh1.offset_to_first_pkt = 64;
            (*descripcion).hdr.bh1.blk_len = 2048;
            let cabecera = base.add(64).cast::<libc::tpacket3_hdr>();
            (*cabecera).tp_snaplen = 4096;
            (*cabecera).tp_mac = 48;
            (*cabecera).tp_next_offset = 0;
        }
        let socket = socket_falso(2048, 512);
        let mut llamadas = 0u32;
        let tramas = unsafe { socket.procesar_bloque(base, &mut |_: &[u8]| llamadas += 1) };
        assert_eq!(tramas, 0);
        assert_eq!(llamadas, 0);
    }

    #[test]
    fn poll_frames_sobre_un_socket_cerrado_devuelve_error() {
        let mut socket = socket_falso(2048, 512);
        let error = socket
            .poll_frames(Duration::from_millis(1), &mut |_: &[u8]| {})
            .expect_err("el socket falso no está abierto");
        assert!(error.message.contains("no está abierto"), "{error}");
    }

    #[test]
    fn soltar_un_socket_falso_no_hace_panic() {
        let socket = socket_falso(2048, 512);
        drop(socket);
    }

    // --- Captura real (requiere privilegios, no se ejecuta por defecto) ----

    #[test]
    #[ignore = "requiere CAP_NET_RAW y una interfaz real"]
    fn captura_real_en_loopback() {
        let anillo = RingConfig {
            block_size: 65536,
            block_nr: 8,
            frame_size: 2048,
        };
        let mut socket = match AfPacketSocket::open("lo", anillo, None) {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!("captura real omitida: {error}");
                return;
            }
        };

        // Generar tráfico en loopback con un datagrama UDP al puerto 9.
        let emisor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(emisor >= 0, "no se pudo crear el socket UDP de prueba");
        let destino = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 9u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        let datos = [0u8; 16];
        let enviados = unsafe {
            libc::sendto(
                emisor,
                datos.as_ptr().cast::<libc::c_void>(),
                datos.len(),
                0,
                std::ptr::addr_of!(destino).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        unsafe {
            libc::close(emisor);
        }
        assert!(enviados >= 0, "no se pudo enviar el datagrama de prueba");

        let inicio = Instant::now();
        let mut tramas: Vec<Vec<u8>> = Vec::new();
        while tramas.is_empty() && inicio.elapsed() < Duration::from_secs(2) {
            socket
                .poll_frames(Duration::from_millis(100), &mut |trama: &[u8]| {
                    tramas.push(trama.to_vec());
                })
                .expect("fallo al leer el anillo de loopback");
        }
        assert!(
            !tramas.is_empty(),
            "no se capturó el tráfico generado en loopback"
        );

        // Además de capturar, las tramas deben ser Ethernet/IP válidas: así se
        // comprueba que el offset tp_mac se aplica como marca el kernel
        // (relativo al inicio de la cabecera TPACKET3).
        let parser = crate::capture::parser::Parser::with_defaults();
        let es_udp_de_prueba = tramas
            .iter()
            .filter_map(|trama| parser.parse(trama).ok())
            .any(|meta| {
                meta.protocol == crate::capture::Protocol::Udp
                    && (meta.src_port == Some(9) || meta.dst_port == Some(9))
            });
        assert!(
            es_udp_de_prueba,
            "las tramas capturadas no se parsearon como el datagrama UDP de prueba"
        );
    }
}
