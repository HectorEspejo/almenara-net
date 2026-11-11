//! Reensamblado acotado del inicio de flujo TCP y de las tramas CRYPTO de QUIC (§7.2).
//!
//! Los buffers viven en el hilo de captura y se liberan al completar el mensaje,
//! al llegar al tope de bytes, al llegar al tope de paquetes o al caducar.
//!
//! Contrato de [StreamStart::push] (lo usa el inspector del hilo de captura):
//!
//! - Devuelve [PushResult::Buffered] mientras el inicio del mensaje siga
//!   incompleto.
//! - Devuelve [PushResult::Complete] cuando el mensaje ya está delimitado: el
//!   registro TLS completo, la petición/respuesta HTTP completa (cabeceras hasta
//!   CRLF CRLF) o el saludo de un protocolo de texto (primera línea terminada).
//! - Devuelve [PushResult::Overflow] al alcanzar el tope de bytes del sentido o
//!   los 8 paquetes con datos; el llamante extrae lo que haya y libera.
//!
//! El primer segmento con datos fija la base de la ventana. Un segmento que
//! llegue antes que la base (captura desordenada) desplaza la ventana hacia
//! atrás; los segmentos adelantados se guardan aparte hasta que se rellena el
//! hueco. Los duplicados no consumen paquete ni memoria.

use std::collections::BTreeMap;

use crate::inference::{
    CLIENT_ASSEMBLY_BYTES, MAX_ASSEMBLY_PACKETS, QUIC_MAX_INITIALS, SERVER_ASSEMBLY_BYTES,
};

/// Mitad del espacio de números de secuencia: separa «adelantado» de «atrasado».
const MITAD_VENTANA: u32 = 0x8000_0000;
/// Longitud de la cabecera de un registro TLS.
const CABECERA_TLS: usize = 5;

/// Resultado de insertar datos en un reensamblado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// Datos aceptados; el mensaje aún no está completo.
    Buffered,
    /// Mensaje completo.
    Complete,
    /// Tope de bytes o de paquetes alcanzado: se extrae lo que haya.
    Overflow,
}

/// Inicio del flujo TCP en un sentido.
#[derive(Debug)]
pub struct StreamStart {
    /// Buffer reensamblado.
    data: Vec<u8>,
    /// Siguiente byte esperado (número de secuencia relativo).
    next_seq: Option<u32>,
    /// Número de paquetes con datos aceptados.
    packets: u8,
    /// Tope de bytes del sentido.
    max_bytes: usize,
    /// El mensaje ya se ha extraído.
    finished: bool,
    /// Resultado ya devuelto al cerrar el buffer (completo o desbordado).
    cerrado: Option<PushResult>,
    /// Número de secuencia del primer byte de `data` (base de la ventana).
    base_seq: Option<u32>,
    /// Segmentos adelantados pendientes de que se rellene el hueco.
    pending: BTreeMap<u32, Vec<u8>>,
}

impl Default for StreamStart {
    /// Reensamblado por defecto: el del sentido cliente → servidor (4 KB).
    ///
    /// El inspector reemplaza el del sentido servidor → cliente por
    /// [StreamStart::server] (64 B).
    fn default() -> Self {
        Self::new(CLIENT_ASSEMBLY_BYTES)
    }
}

impl StreamStart {
    /// Crea un reensamblado con el tope de bytes indicado.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            data: Vec::new(),
            next_seq: None,
            packets: 0,
            max_bytes,
            finished: false,
            cerrado: None,
            base_seq: None,
            pending: BTreeMap::new(),
        }
    }

    /// Reensamblado cliente → servidor (4 KB).
    pub fn client() -> Self {
        Self::new(CLIENT_ASSEMBLY_BYTES)
    }

    /// Reensamblado servidor → cliente (64 B).
    pub fn server() -> Self {
        Self::new(SERVER_ASSEMBLY_BYTES)
    }

    /// Inserta un segmento del flujo.
    pub fn push(&mut self, seq: u32, data: &[u8]) -> PushResult {
        if let Some(resultado) = self.cerrado {
            return resultado;
        }
        if self.finished {
            return PushResult::Complete;
        }
        if data.is_empty() {
            return self.estado();
        }

        let Some(base) = self.base_seq else {
            // Primer segmento con datos: fija la base de la ventana.
            self.base_seq = Some(seq);
            self.data.extend_from_slice(data);
            self.packets = 1;
            self.recortar_al_tope();
            return self.estado();
        };

        let relativo = seq.wrapping_sub(base);
        if relativo < MITAD_VENTANA {
            self.insertar_en_ventana(relativo as usize, data);
        } else {
            let adelanto = base.wrapping_sub(seq);
            self.insertar_antes_de_la_base(seq, adelanto, data);
        }
        self.vaciar_pendientes();
        self.recortar_al_tope();
        self.estado()
    }

    /// Inserta un segmento que empieza dentro de la ventana ya reunida.
    fn insertar_en_ventana(&mut self, relativo: usize, data: &[u8]) {
        let longitud = self.data.len();
        if relativo > longitud {
            // Hay un hueco por delante: se guarda hasta que se rellene.
            if let Some(base) = self.base_seq {
                if self.guardar_pendiente(base.wrapping_add(relativo as u32), data) {
                    self.packets = self.packets.saturating_add(1);
                }
            }
            return;
        }
        let solapamiento = longitud - relativo;
        if data.len() > solapamiento {
            self.data.extend_from_slice(&data[solapamiento..]);
            self.packets = self.packets.saturating_add(1);
        }
    }

    /// Inserta un segmento anterior a la base actual, desplazando la ventana.
    fn insertar_antes_de_la_base(&mut self, seq: u32, adelanto: u32, data: &[u8]) {
        let adelanto = adelanto as usize;
        if adelanto > self.max_bytes {
            // Fuera de la ventana: no cabe en el buffer.
            return;
        }
        if data.len() >= adelanto {
            // El segmento alcanza la base actual: se fusiona por delante.
            let solapamiento = data.len() - adelanto;
            let mut nuevo = data.to_vec();
            if solapamiento < self.data.len() {
                nuevo.extend_from_slice(&self.data[solapamiento..]);
            }
            self.data = nuevo;
            self.base_seq = Some(seq);
            self.packets = self.packets.saturating_add(1);
        } else {
            // Queda un hueco entre el segmento y el buffer actual: el buffer
            // reunido pasa a pendiente y la ventana se desplaza al segmento nuevo.
            if let Some(base) = self.base_seq {
                let anterior = std::mem::take(&mut self.data);
                self.guardar_pendiente(base, &anterior);
            }
            self.base_seq = Some(seq);
            self.data = data.to_vec();
            self.packets = self.packets.saturating_add(1);
        }
    }

    /// Guarda un segmento adelantado dentro de la ventana (sin pasarse del tope).
    ///
    /// Devuelve `true` si el segmento era nuevo y quedó guardado; los duplicados
    /// no consumen paquete ni memoria.
    fn guardar_pendiente(&mut self, seq: u32, data: &[u8]) -> bool {
        if self.pending.len() >= usize::from(MAX_ASSEMBLY_PACKETS)
            || self.pending.contains_key(&seq)
        {
            return false;
        }
        let base = self.base_seq.unwrap_or(seq);
        let relativo = seq.wrapping_sub(base);
        if relativo >= MITAD_VENTANA || relativo as usize > self.max_bytes {
            return false;
        }
        let limite = self.max_bytes.saturating_sub(relativo as usize);
        if limite == 0 {
            return false;
        }
        let mut datos = data.to_vec();
        if datos.len() > limite {
            datos.truncate(limite);
        }
        self.pending.insert(seq, datos);
        true
    }

    /// Encadena los segmentos pendientes que ya son contiguos al buffer.
    fn vaciar_pendientes(&mut self) {
        let Some(base) = self.base_seq else {
            return;
        };
        loop {
            let esperado = base.wrapping_add(self.data.len() as u32);
            let Some(datos) = self.pending.remove(&esperado) else {
                break;
            };
            self.data.extend_from_slice(&datos);
        }
        // Pendientes que ya quedaron cubiertos o fuera de la ventana se descartan.
        let longitud = self.data.len();
        let max_bytes = self.max_bytes;
        self.pending.retain(|seq, datos| {
            let relativo = seq.wrapping_sub(base);
            if relativo >= MITAD_VENTANA {
                return false;
            }
            let relativo = relativo as usize;
            relativo >= longitud && relativo.saturating_add(datos.len()) <= max_bytes
        });
    }

    /// Recorta el buffer al tope de bytes del sentido.
    fn recortar_al_tope(&mut self) {
        if self.data.len() > self.max_bytes {
            self.data.truncate(self.max_bytes);
        }
        if let Some(base) = self.base_seq {
            self.next_seq = Some(base.wrapping_add(self.data.len() as u32));
        }
    }

    /// Estado resultante del buffer.
    ///
    /// Al llegar a [PushResult::Complete] o [PushResult::Overflow] el buffer
    /// queda cerrado: los paquetes siguientes no lo modifican hasta que el
    /// llamante haga [StreamStart::release] o [StreamStart::reset].
    fn estado(&mut self) -> PushResult {
        if self.finished {
            return PushResult::Complete;
        }
        if mensaje_completo(&self.data) {
            self.cerrado = Some(PushResult::Complete);
            return PushResult::Complete;
        }
        if !self.data.is_empty()
            && (self.data.len() >= self.max_bytes || self.packets >= MAX_ASSEMBLY_PACKETS)
        {
            self.cerrado = Some(PushResult::Overflow);
            return PushResult::Overflow;
        }
        PushResult::Buffered
    }

    /// Bytes reensamblados hasta ahora.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Indica si no hay datos.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Indica si el buffer está liberado.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Marca el buffer como extraído y lo libera.
    pub fn release(&mut self) {
        self.data = Vec::new();
        self.pending.clear();
        self.finished = true;
    }

    /// Número de paquetes con datos aceptados.
    pub fn packets(&self) -> u8 {
        self.packets
    }

    /// Devuelve un `StreamStart` vacío reutilizable.
    pub fn reset(&mut self) {
        *self = Self::new(self.max_bytes);
    }
}

/// Indica si el buffer ya contiene un mensaje delimitado.
fn mensaje_completo(datos: &[u8]) -> bool {
    // Registro TLS de handshake con su longitud completa.
    if datos.len() >= CABECERA_TLS && datos[0] == 0x16 && datos[1] == 0x03 {
        let longitud = usize::from(u16::from_be_bytes([datos[3], datos[4]]));
        return datos.len() >= CABECERA_TLS + longitud;
    }
    // Petición o respuesta HTTP/1.x: cabeceras hasta la línea vacía.
    if parece_http(datos) {
        return datos.windows(4).any(|ventana| ventana == b"\r\n\r\n");
    }
    // Saludos de protocolos de texto (SSH, FTP, SMTP, IMAP, POP3, VNC…): la
    // primera línea terminada basta para identificar el protocolo.
    if datos
        .first()
        .is_some_and(|byte| (0x20..=0x7e).contains(byte))
    {
        return datos.contains(&b'\n');
    }
    false
}

/// Indica si los primeros bytes parecen una petición o respuesta HTTP/1.x.
fn parece_http(datos: &[u8]) -> bool {
    const METODOS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    METODOS.iter().any(|metodo| datos.starts_with(metodo)) || datos.starts_with(b"HTTP/1.")
}

/// Recomposición de las tramas CRYPTO de QUIC por offset.
#[derive(Debug, Default)]
pub struct CryptoStream {
    /// Buffer reensamblado por offset.
    data: Vec<u8>,
    /// Máximo offset recibido.
    max_offset: usize,
    /// Número de paquetes Initial aceptados.
    packets: u8,
    /// Resultado ya devuelto al cerrar el buffer.
    cerrado: Option<PushResult>,
    /// Tramas adelantadas pendientes de que se rellene el hueco.
    pending: Vec<(u64, Vec<u8>)>,
}

/// Bytes máximos de tramas CRYPTO por flujo QUIC.
pub const MAX_CRYPTO_BYTES: usize = 4096;
/// Inicio del ClientHello dentro del buffer CRYPTO.
const TLS_HANDSHAKE_TYPE: u8 = 0x01;

impl CryptoStream {
    /// Crea un `CryptoStream` vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserta una trama CRYPTO.
    pub fn push(&mut self, offset: u64, data: &[u8]) -> PushResult {
        if let Some(resultado) = self.cerrado {
            return resultado;
        }
        if data.is_empty() {
            return self.estado();
        }
        let Ok(offset) = usize::try_from(offset) else {
            return PushResult::Overflow;
        };
        self.packets = self.packets.saturating_add(1);

        if offset <= self.data.len() {
            let solapamiento = self.data.len() - offset;
            if data.len() > solapamiento {
                self.data.extend_from_slice(&data[solapamiento..]);
            }
            self.max_offset = self.max_offset.max(offset.saturating_add(data.len()));
        } else {
            self.guardar_pendiente(offset, data);
        }
        self.vaciar_pendientes();
        if self.data.len() > MAX_CRYPTO_BYTES {
            self.data.truncate(MAX_CRYPTO_BYTES);
        }
        self.estado()
    }

    /// Guarda una trama adelantada dentro del tope de bytes.
    fn guardar_pendiente(&mut self, offset: usize, data: &[u8]) {
        if self.pending.len() >= usize::from(QUIC_MAX_INITIALS) || offset >= MAX_CRYPTO_BYTES {
            return;
        }
        let limite = MAX_CRYPTO_BYTES - offset;
        let mut datos = data.to_vec();
        if datos.len() > limite {
            datos.truncate(limite);
        }
        let offset = offset as u64;
        if !self.pending.iter().any(|(inicio, _)| *inicio == offset) {
            self.pending.push((offset, datos));
        }
        self.max_offset = self.max_offset.max(offset as usize);
    }

    /// Encadena las tramas pendientes que ya son contiguas al buffer.
    fn vaciar_pendientes(&mut self) {
        let mut posicion = 0;
        while posicion < self.pending.len() {
            if self.pending[posicion].0 as usize == self.data.len() {
                let (_, datos) = self.pending.remove(posicion);
                self.data.extend_from_slice(&datos);
                self.max_offset = self.max_offset.max(self.data.len());
                posicion = 0;
            } else {
                posicion += 1;
            }
        }
        let longitud = self.data.len();
        self.pending
            .retain(|(inicio, datos)| *inicio as usize + datos.len() > longitud);
    }

    /// Estado resultante del buffer.
    ///
    /// Al llegar a [PushResult::Complete] o [PushResult::Overflow] el buffer
    /// queda cerrado hasta que el llamante haga [CryptoStream::release].
    fn estado(&mut self) -> PushResult {
        if self.client_hello_complete() {
            self.cerrado = Some(PushResult::Complete);
            return PushResult::Complete;
        }
        if self.data.len() >= MAX_CRYPTO_BYTES || self.packets >= QUIC_MAX_INITIALS {
            self.cerrado = Some(PushResult::Overflow);
            return PushResult::Overflow;
        }
        PushResult::Buffered
    }

    /// Buffer CRYPTO reensamblado.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Indica si el ClientHello está completo (registro TLS con su longitud).
    ///
    /// Acepta también el mensaje de handshake directo de QUIC, que no lleva
    /// cabecera de registro TLS (RFC 9001 §4.1).
    pub fn client_hello_complete(&self) -> bool {
        let datos = &self.data;
        if datos.len() >= CABECERA_TLS && datos[0] == 0x16 && datos[1] == 0x03 {
            let longitud = usize::from(u16::from_be_bytes([datos[3], datos[4]]));
            return datos.len() >= CABECERA_TLS + longitud;
        }
        if datos.len() >= 4 && datos[0] == TLS_HANDSHAKE_TYPE {
            let longitud = (usize::from(datos[1]) << 16)
                | (usize::from(datos[2]) << 8)
                | usize::from(datos[3]);
            return datos.len() >= 4 + longitud;
        }
        false
    }

    /// Libera el buffer tras extraer el ClientHello.
    pub fn release(&mut self) {
        self.data = Vec::new();
        self.max_offset = 0;
        self.pending.clear();
    }

    /// Número de paquetes Initial aceptados.
    pub fn packets(&self) -> u8 {
        self.packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::http::parse_request;
    use crate::inference::tls::{fixture_client_hello, parse_client_hello};

    /// Carga binaria que nunca completa un mensaje (registro TLS de longitud falsa).
    fn carga_incompleta(longitud: usize) -> Vec<u8> {
        let mut datos = vec![0x16, 0x03, 0x01, 0xff, 0xff];
        datos.resize(longitud.max(5), 0xab);
        datos
    }

    #[test]
    fn reensambla_el_client_hello_partido_y_desordenado() {
        let hello = fixture_client_hello("partido.example.com");
        let corte = 20;
        let mut flujo = StreamStart::client();

        let segundo = flujo.push(5000 + corte as u32, &hello[corte..]);
        assert_eq!(segundo, PushResult::Buffered);
        assert_eq!(flujo.data(), &hello[corte..]);

        let primero = flujo.push(5000, &hello[..corte]);
        assert_eq!(primero, PushResult::Complete);
        assert_eq!(flujo.data(), hello.as_slice());
        assert_eq!(flujo.packets(), 2);

        let parseado = parse_client_hello(flujo.data()).expect("ClientHello reensamblado");
        assert_eq!(parseado.sni.as_deref(), Some("partido.example.com"));
    }

    #[test]
    fn descarta_los_segmentos_duplicados() {
        let hello = fixture_client_hello("duplicado.example.com");
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(1000, &hello), PushResult::Complete);
        assert_eq!(flujo.packets(), 1);
        assert_eq!(flujo.push(1000, &hello), PushResult::Complete);
        assert_eq!(flujo.data(), hello.as_slice());
        assert_eq!(flujo.packets(), 1);
    }

    #[test]
    fn rellena_un_hueco_con_un_segmento_que_llega_tarde() {
        let carga = carga_incompleta(500);
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(1000, &carga[..100]), PushResult::Buffered);
        assert_eq!(flujo.push(1200, &carga[200..300]), PushResult::Buffered);
        assert_eq!(flujo.data(), &carga[..100]);
        assert_eq!(flujo.push(1100, &carga[100..200]), PushResult::Buffered);
        assert_eq!(flujo.data(), &carga[..300]);
        assert_eq!(flujo.packets(), 3);
    }

    #[test]
    fn desplaza_la_ventana_si_el_segmento_anterior_deja_hueco() {
        let carga = carga_incompleta(500);
        let mut flujo = StreamStart::client();
        // Llega antes el segundo segmento: fija la base.
        assert_eq!(flujo.push(1100, &carga[100..200]), PushResult::Buffered);
        // Llega un trozo anterior que no alcanza la base: la ventana se desplaza.
        assert_eq!(flujo.push(1000, &carga[..50]), PushResult::Buffered);
        assert_eq!(flujo.data(), &carga[..50]);
        // Se rellena el hueco y se encadena el segmento que estaba pendiente.
        assert_eq!(flujo.push(1050, &carga[50..100]), PushResult::Buffered);
        assert_eq!(flujo.data(), &carga[..200]);
        assert_eq!(flujo.packets(), 3);
    }

    #[test]
    fn desborda_al_llegar_al_tope_de_bytes() {
        let carga = carga_incompleta(5000);
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(0, &carga), PushResult::Overflow);
        assert_eq!(flujo.data().len(), CLIENT_ASSEMBLY_BYTES);
        assert!(flujo.data().len() <= CLIENT_ASSEMBLY_BYTES);
    }

    #[test]
    fn desborda_a_los_ocho_paquetes() {
        let carga = carga_incompleta(400);
        let mut flujo = StreamStart::client();
        let mut resultado = PushResult::Buffered;
        for indice in 0..8u32 {
            let inicio = (indice as usize) * 10;
            resultado = flujo.push(inicio as u32, &carga[inicio..inicio + 10]);
            if indice < 7 {
                assert_eq!(resultado, PushResult::Buffered, "paquete {indice}");
            }
        }
        assert_eq!(resultado, PushResult::Overflow);
        assert_eq!(flujo.packets(), 8);
        assert_eq!(flujo.data().len(), 80);
    }

    #[test]
    fn completa_con_una_peticion_http() {
        let peticion =
            b"GET /index.html HTTP/1.1\r\nHost: ejemplo.com\r\nUser-Agent: prueba/1.0\r\n\r\n";
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(1, peticion), PushResult::Complete);
        let info = parse_request(flujo.data()).expect("petición HTTP completa");
        assert_eq!(info.host.as_deref(), Some("ejemplo.com"));
        assert_eq!(info.user_agent.as_deref(), Some("prueba/1.0"));
    }

    #[test]
    fn completa_con_el_saludo_de_un_protocolo_de_texto() {
        let saludo = b"SSH-2.0-OpenSSH_9.6\r\n";
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(1, saludo), PushResult::Complete);
        assert_eq!(flujo.data(), saludo.as_slice());
    }

    #[test]
    fn el_sentido_servidor_se_limita_a_sesenta_y_cuatro_bytes() {
        let mut flujo = StreamStart::server();
        assert_eq!(flujo.push(0, &carga_incompleta(100)), PushResult::Overflow);
        assert_eq!(flujo.data().len(), SERVER_ASSEMBLY_BYTES);
    }

    #[test]
    fn el_valor_por_defecto_es_el_sentido_cliente() {
        let mut flujo = StreamStart::default();
        assert_eq!(flujo.push(0, &carga_incompleta(1000)), PushResult::Buffered);
        assert_eq!(flujo.data().len(), 1000);
    }

    #[test]
    fn libera_el_buffer_tras_extraer_el_mensaje() {
        let hello = fixture_client_hello("liberado.example.com");
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(0, &hello), PushResult::Complete);
        flujo.release();
        assert!(flujo.is_finished());
        assert!(flujo.is_empty());
        // Nuevos paquetes ya no se reensamblan.
        assert_eq!(flujo.push(0, &hello), PushResult::Complete);
        assert!(flujo.is_empty());
    }

    #[test]
    fn reset_devuelve_el_reensamblado_al_estado_inicial() {
        let carga = carga_incompleta(100);
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(0, &carga[..50]), PushResult::Buffered);
        flujo.reset();
        assert!(flujo.is_empty());
        assert!(!flujo.is_finished());
        let hello = fixture_client_hello("reiniciado.example.com");
        assert_eq!(flujo.push(7, &hello), PushResult::Complete);
        assert_eq!(flujo.data(), hello.as_slice());
    }

    #[test]
    fn no_hace_panic_con_segmentos_aleatorios_del_flujo() {
        for semilla in 0u32..64 {
            let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(5);
            let mut flujo = StreamStart::client();
            for _ in 0..12 {
                estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                let seq = (estado >> 8) % 5000;
                let longitud = (estado % 64) as usize;
                let mut datos = Vec::with_capacity(longitud);
                for _ in 0..longitud {
                    estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                    datos.push((estado >> 24) as u8);
                }
                let _ = flujo.push(seq, &datos);
                let _ = flujo.is_empty();
                let _ = flujo.packets();
            }
        }
    }

    #[test]
    fn recompone_el_handshake_de_quic_repartido_y_desordenado() {
        let registro = fixture_client_hello("quic.example.com");
        let handshake = &registro[CABECERA_TLS..];
        let corte = 25;
        let mut flujo = CryptoStream::new();

        // Llega antes la segunda trama CRYPTO.
        assert_eq!(
            flujo.push(corte as u64, &handshake[corte..]),
            PushResult::Buffered
        );
        assert!(!flujo.client_hello_complete());
        assert_eq!(flujo.push(0, &handshake[..corte]), PushResult::Complete);
        assert!(flujo.client_hello_complete());
        assert_eq!(flujo.data(), handshake);
        assert_eq!(flujo.packets(), 2);

        let parseado = parse_client_hello(flujo.data()).expect("ClientHello de QUIC");
        assert_eq!(parseado.sni.as_deref(), Some("quic.example.com"));
    }

    #[test]
    fn recompone_el_registro_tls_completo_de_tcp() {
        let registro = fixture_client_hello("registro.example.com");
        let mut flujo = CryptoStream::new();
        assert_eq!(flujo.push(0, &registro), PushResult::Complete);
        assert!(flujo.client_hello_complete());
        let parseado = parse_client_hello(flujo.data()).expect("ClientHello con registro");
        assert_eq!(parseado.sni.as_deref(), Some("registro.example.com"));
    }

    #[test]
    fn rellena_el_hueco_de_las_tramas_crypto() {
        let registro = fixture_client_hello("hueco.example.com");
        let handshake = &registro[CABECERA_TLS..];
        let mut flujo = CryptoStream::new();
        assert_eq!(flujo.push(20, &handshake[20..]), PushResult::Buffered);
        assert!(!flujo.client_hello_complete());
        assert_eq!(flujo.push(0, &handshake[..20]), PushResult::Complete);
        assert_eq!(flujo.data(), handshake);
    }

    #[test]
    fn desborda_a_los_cuatro_initial() {
        let carga = carga_incompleta(400);
        let mut flujo = CryptoStream::new();
        let mut resultado = PushResult::Buffered;
        for indice in 0..4u64 {
            let inicio = (indice as usize) * 100;
            resultado = flujo.push(inicio as u64, &carga[inicio..inicio + 100]);
            if indice < 3 {
                assert_eq!(resultado, PushResult::Buffered, "initial {indice}");
            }
        }
        assert_eq!(resultado, PushResult::Overflow);
        assert_eq!(flujo.packets(), 4);
    }

    #[test]
    fn el_crypto_stream_no_se_completa_con_basura() {
        let mut flujo = CryptoStream::new();
        assert_eq!(
            flujo.push(0, &[0x17, 0x03, 0x03, 0x00]),
            PushResult::Buffered
        );
        assert!(!flujo.client_hello_complete());
        assert_eq!(flujo.push(0, &[0x01]), PushResult::Buffered);
        assert!(!flujo.client_hello_complete());
    }

    #[test]
    fn no_hace_panic_con_tramas_crypto_aleatorias() {
        for semilla in 0u32..64 {
            let mut estado = semilla.wrapping_mul(2654435761).wrapping_add(9);
            let mut flujo = CryptoStream::new();
            for _ in 0..8 {
                estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                let offset = (estado >> 4) % 6000;
                let longitud = (estado % 48) as usize;
                let mut datos = Vec::with_capacity(longitud);
                for _ in 0..longitud {
                    estado = estado.wrapping_mul(1664525).wrapping_add(1013904223);
                    datos.push((estado >> 24) as u8);
                }
                let _ = flujo.push(u64::from(offset), &datos);
                let _ = flujo.client_hello_complete();
                let _ = flujo.packets();
            }
        }
    }

    #[test]
    fn un_buffer_completo_ignora_los_paquetes_siguientes() {
        let hello = fixture_client_hello("cerrado.example.com");
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(0, &hello), PushResult::Complete);
        let antes = flujo.data().to_vec();
        assert_eq!(
            flujo.push(hello.len() as u32, &[1, 2, 3]),
            PushResult::Complete
        );
        assert_eq!(flujo.data(), antes.as_slice());
    }

    #[test]
    fn un_buffer_desbordado_ignora_los_paquetes_siguientes() {
        let carga = carga_incompleta(5000);
        let mut flujo = StreamStart::client();
        assert_eq!(flujo.push(0, &carga), PushResult::Overflow);
        let antes = flujo.data().len();
        assert_eq!(flujo.push(5000, &[1, 2, 3]), PushResult::Overflow);
        assert_eq!(flujo.data().len(), antes);
    }

    #[test]
    fn el_crypto_stream_ignora_las_tramas_siguientes_tras_completarse() {
        let registro = fixture_client_hello("cerrado-quic.example.com");
        let handshake = &registro[CABECERA_TLS..];
        let mut flujo = CryptoStream::new();
        assert_eq!(flujo.push(0, handshake), PushResult::Complete);
        let antes = flujo.data().to_vec();
        assert_eq!(flujo.push(0, &[9, 9, 9]), PushResult::Complete);
        assert_eq!(flujo.data(), antes.as_slice());
    }
}
