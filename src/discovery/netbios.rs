//! Consulta NetBIOS (NBNS, UDP 137) para obtener hostname y workgroup.
//!
//! La consulta es un Node Status Request (NBSTAT) que devuelve la lista de
//! nombres registrados por el equipo; de ahí se extraen el nombre de estación y
//! el grupo de trabajo. Timeout corto y fallo silencioso: quien orquesta el ciclo
//! ignora el error (solo lo deja en el log de depuración).
//!
//! El workgroup se obtiene del propio Node Status: es el nombre con sufijo 0x00
//! y el bit de grupo activo. Los puertos 138/139 son puertos de servicio y no
//! endpoints de consulta, así que no se usan.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::{Error, Result};

/// Puerto UDP del servicio NetBIOS Name Service.
const PUERTO_NBNS: u16 = 137;
/// Tamaño máximo de una respuesta NBSTAT (holgado para un Node Status típico).
const TAMANO_MAXIMO_RESPUESTA: usize = 2048;
/// Tipo de registro NBSTAT (Node Status) dentro de la respuesta DNS/NBNS.
const TIPO_NBSTAT: u16 = 0x0021;
/// Sufijo NetBIOS del nombre de estación y del grupo de trabajo.
const SUFIJO_ESTACION: u8 = 0x00;
/// Longitud de cada entrada de nombre en el Node Status (15 + sufijo + flags).
const TAMANO_ENTRADA_NOMBRE: usize = 18;
/// Marca de nombre de grupo en las banderas de la entrada.
const BANDERA_GRUPO: u16 = 0x8000;

/// Información NetBIOS de un equipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbiosInfo {
    /// IPv4 consultada.
    pub ip: Ipv4Addr,
    /// Nombre de estación de trabajo.
    pub hostname: Option<String>,
    /// Grupo de trabajo.
    pub workgroup: Option<String>,
    /// Todos los nombres devueltos por el equipo.
    pub names: Vec<String>,
}

/// Cliente NetBIOS.
#[derive(Debug, Clone, Copy)]
pub struct Netbios;

impl Netbios {
    /// Consulta el Node Status de un equipo por UDP 137.
    ///
    /// Falla en silencio desde el punto de vista de la interfaz: el error se
    /// devuelve para que el orquestador lo registre en el log y siga el ciclo.
    pub async fn query_name(ip: Ipv4Addr, timeout: Duration) -> Result<NetbiosInfo> {
        let transmision = identificador_transaccion();
        let consulta = build_nbstat_query(transmision);
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|error| {
                Error::Scan(format!("NetBIOS: no se pudo abrir el socket UDP: {error}"))
            })?;
        socket
            .send_to(&consulta, (ip, PUERTO_NBNS))
            .await
            .map_err(|error| {
                Error::Scan(format!(
                    "NetBIOS: no se pudo enviar la consulta a {ip}: {error}"
                ))
            })?;

        let limite = tokio::time::Instant::now() + timeout;
        let mut respuesta = vec![0u8; TAMANO_MAXIMO_RESPUESTA];
        loop {
            let restante = limite.saturating_duration_since(tokio::time::Instant::now());
            if restante.is_zero() {
                return Err(sin_respuesta(ip, timeout));
            }
            let recibidos =
                match tokio::time::timeout(restante, socket.recv_from(&mut respuesta)).await {
                    Ok(Ok((cantidad, _origen))) => cantidad,
                    Ok(Err(error)) => {
                        return Err(Error::Scan(format!(
                            "NetBIOS: error recibiendo la respuesta de {ip}: {error}"
                        )))
                    }
                    Err(_) => return Err(sin_respuesta(ip, timeout)),
                };
            // Se ignoran los paquetes ajenos (otra transacción o ruido del socket).
            if recibidos < 2 || u16::from_be_bytes([respuesta[0], respuesta[1]]) != transmision {
                continue;
            }
            let mut info = parse_nbstat_response(&respuesta[..recibidos])?;
            info.ip = ip;
            return Ok(info);
        }
    }

    /// Consulta el grupo de trabajo del equipo.
    ///
    /// Reutiliza la consulta NBSTAT porque el Node Status ya incluye el grupo;
    /// no se envía tráfico a los puertos 138/139 (son de servicio, no de consulta).
    // API del checklist de Fase 2: la integración lee el workgroup de
    // NetbiosInfo, pero la operación pública se conserva por contrato.
    #[allow(dead_code)]
    pub async fn query_workgroup(ip: Ipv4Addr, timeout: Duration) -> Result<Option<String>> {
        Ok(Self::query_name(ip, timeout).await?.workgroup)
    }
}

/// Construye una consulta NBSTAT con el identificador de transacción indicado.
///
/// Formato: cabecera DNS/NBNS de 12 bytes, nombre NetBIOS «*» codificado como
/// 32 caracteres (un nombre de 16 bytes con ceros de relleno, cada byte separado
/// en dos nibbles sumados a 'A') y el tipo/clase NBSTAT-IN.
pub fn build_nbstat_query(txid: u16) -> Vec<u8> {
    let mut consulta = Vec::with_capacity(50);
    consulta.extend_from_slice(&txid.to_be_bytes());
    consulta.extend_from_slice(&0u16.to_be_bytes()); // banderas: consulta estándar
    consulta.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    consulta.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    consulta.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    consulta.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Nombre comodín de NBSTAT: '*' seguido de 15 ceros de relleno.
    let mut nombre = [0u8; 16];
    nombre[0] = b'*';
    consulta.push(0x20); // longitud del nombre codificado (32 bytes)
    for byte in nombre {
        consulta.push(b'A' + (byte >> 4));
        consulta.push(b'A' + (byte & 0x0f));
    }
    consulta.push(0x00); // fin del nombre
    consulta.extend_from_slice(&TIPO_NBSTAT.to_be_bytes());
    consulta.extend_from_slice(&1u16.to_be_bytes()); // clase IN
    consulta
}

/// Parsea la respuesta a una consulta NBSTAT.
///
/// La IP de origen no viaja en el paquete UDP, así que el resultado lleva
/// [`Ipv4Addr::UNSPECIFIED`]; [`Netbios::query_name`] la completa con la IP
/// consultada. Acepta respuestas con o sin la pregunta ecoada y con el nombre del
/// registro comprimido o completo.
pub fn parse_nbstat_response(packet: &[u8]) -> Result<NetbiosInfo> {
    if packet.len() < 12 {
        return Err(respuesta_corta());
    }
    let banderas = u16::from_be_bytes([packet[2], packet[3]]);
    if banderas & 0x8000 == 0 {
        return Err(Error::Scan(
            "NetBIOS: el paquete no es una respuesta".to_string(),
        ));
    }
    let preguntas = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let respuestas = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    if respuestas == 0 {
        return Err(Error::Scan(
            "NetBIOS: la respuesta no trae registros".to_string(),
        ));
    }

    let mut posicion = 12;
    for _ in 0..preguntas {
        posicion = saltar_nombre(packet, posicion)?;
        posicion = avanzar(packet, posicion, 4)?; // tipo + clase de la pregunta
    }

    for _ in 0..respuestas {
        posicion = saltar_nombre(packet, posicion)?;
        let tipo = leer_u16(packet, posicion)?;
        let desplazamiento_longitud = posicion.checked_add(8).ok_or_else(respuesta_corta)?;
        let longitud_datos = usize::from(leer_u16(packet, desplazamiento_longitud)?);
        // type(2) + class(2) + ttl(4) + rdlength(2)
        posicion = avanzar(packet, posicion, 10)?;
        let fin = avanzar(packet, posicion, longitud_datos)?;
        if tipo == TIPO_NBSTAT {
            return parsear_datos_nbstat(&packet[posicion..fin]);
        }
        posicion = fin;
    }
    Err(Error::Scan(
        "NetBIOS: la respuesta no contiene un registro NBSTAT".to_string(),
    ))
}

/// Parsea los datos (RDATA) de un registro NBSTAT.
fn parsear_datos_nbstat(datos: &[u8]) -> Result<NetbiosInfo> {
    let Some((&cantidad, _)) = datos.split_first() else {
        return Err(respuesta_corta());
    };
    let cantidad = usize::from(cantidad);
    if cantidad == 0 {
        return Err(Error::Scan(
            "NetBIOS: el Node Status no trae nombres".to_string(),
        ));
    }
    let longitud_necesaria = 1 + cantidad * TAMANO_ENTRADA_NOMBRE;
    if datos.len() < longitud_necesaria {
        return Err(respuesta_corta());
    }

    let mut nombres: Vec<String> = Vec::with_capacity(cantidad);
    let mut hostname = None;
    let mut workgroup = None;
    for indice in 0..cantidad {
        let base = 1 + indice * TAMANO_ENTRADA_NOMBRE;
        let entrada = &datos[base..base + TAMANO_ENTRADA_NOMBRE];
        let sufijo = entrada[15];
        let es_grupo = u16::from_be_bytes([entrada[16], entrada[17]]) & BANDERA_GRUPO != 0;
        let Some(nombre) = texto_netbios(&entrada[..15]) else {
            continue;
        };
        // El nombre de estación es el sufijo 0x00 sin bandera de grupo; el grupo
        // de trabajo es el sufijo 0x00 con bandera de grupo.
        if sufijo == SUFIJO_ESTACION {
            if es_grupo {
                if workgroup.is_none() {
                    workgroup = Some(nombre.clone());
                }
            } else if hostname.is_none() {
                hostname = Some(nombre.clone());
            }
        }
        if !nombres.contains(&nombre) {
            nombres.push(nombre);
        }
    }

    Ok(NetbiosInfo {
        ip: Ipv4Addr::UNSPECIFIED,
        hostname,
        workgroup,
        names: nombres,
    })
}

/// Decodifica un nombre NetBIOS de 15 bytes (rellenado con ceros y espacios).
fn texto_netbios(bytes: &[u8]) -> Option<String> {
    let fin = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let texto = String::from_utf8_lossy(&bytes[..fin]);
    let limpio: String = texto
        .chars()
        .filter(|caracter| !caracter.is_control())
        .collect();
    let limpio = limpio.trim().trim_end_matches('�').trim().to_string();
    if limpio.is_empty() {
        None
    } else {
        Some(limpio)
    }
}

/// Avanza la posición indicada comprobando que no se sale del paquete.
fn avanzar(packet: &[u8], posicion: usize, cantidad: usize) -> Result<usize> {
    let fin = posicion.checked_add(cantidad).ok_or_else(respuesta_corta)?;
    if fin > packet.len() {
        return Err(respuesta_corta());
    }
    Ok(fin)
}

/// Lee un entero de 16 bits en orden de red.
fn leer_u16(packet: &[u8], posicion: usize) -> Result<u16> {
    let fin = posicion.checked_add(2).ok_or_else(respuesta_corta)?;
    let bytes = packet.get(posicion..fin).ok_or_else(respuesta_corta)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Salta un nombre DNS/NBNS (etiquetas o puntero de compresión).
fn saltar_nombre(packet: &[u8], mut posicion: usize) -> Result<usize> {
    loop {
        let longitud = *packet.get(posicion).ok_or_else(respuesta_corta)?;
        if longitud == 0 {
            return Ok(posicion + 1);
        }
        if longitud & 0xC0 == 0xC0 {
            // Puntero de compresión: dos bytes y fin del nombre.
            return avanzar(packet, posicion, 2);
        }
        if longitud & 0xC0 != 0 {
            return Err(respuesta_corta());
        }
        posicion = avanzar(packet, posicion, 1 + usize::from(longitud))?;
    }
}

/// Error común para paquetes truncados o mal formados.
fn respuesta_corta() -> Error {
    Error::Scan("NetBIOS: respuesta truncada o mal formada".to_string())
}

/// Error de timeout sin respuesta.
fn sin_respuesta(ip: Ipv4Addr, timeout: Duration) -> Error {
    Error::Scan(format!("NetBIOS: {ip} no respondió en {timeout:?}"))
}

/// Genera un identificador de transacción pseudoaleatorio (nanos + PID).
fn identificador_transaccion() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duracion| duracion.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ std::process::id()) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codifica un nombre NetBIOS de 16 bytes con la codificación de primer nivel.
    fn nombre_codificado(nombre: &str) -> Vec<u8> {
        let mut bytes = [0x20u8; 16];
        let ascii = nombre.as_bytes();
        let cantidad = ascii.len().min(15);
        bytes[..cantidad].copy_from_slice(&ascii[..cantidad]);
        let mut codificado = vec![0x20u8];
        for byte in bytes {
            codificado.push(b'A' + (byte >> 4));
            codificado.push(b'A' + (byte & 0x0f));
        }
        codificado.push(0x00);
        codificado
    }

    /// Construye una respuesta NBSTAT sintética con los nombres indicados.
    fn respuesta_nbstat(txid: u16, nombres: &[(&str, u8, bool)], con_pregunta: bool) -> Vec<u8> {
        let mut paquete = Vec::new();
        paquete.extend_from_slice(&txid.to_be_bytes());
        paquete.extend_from_slice(&0x8400u16.to_be_bytes()); // respuesta autoritativa
        paquete.extend_from_slice(&if con_pregunta { 1u16 } else { 0u16 }.to_be_bytes());
        paquete.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        paquete.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        paquete.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        if con_pregunta {
            let consulta = build_nbstat_query(txid);
            paquete.extend_from_slice(&consulta[12..]);
            paquete.extend_from_slice(&[0xC0, 0x0C]); // puntero a la pregunta
        } else {
            paquete.extend_from_slice(&nombre_codificado("*")); // nombre completo
        }
        paquete.extend_from_slice(&TIPO_NBSTAT.to_be_bytes());
        paquete.extend_from_slice(&1u16.to_be_bytes()); // clase IN
        paquete.extend_from_slice(&[0, 0, 0, 0]); // TTL

        let longitud_datos = 1 + nombres.len() * TAMANO_ENTRADA_NOMBRE;
        paquete.extend_from_slice(&(longitud_datos as u16).to_be_bytes());
        paquete.push(nombres.len() as u8);
        for (nombre, sufijo, grupo) in nombres {
            let mut campo = [b' '; 15];
            let ascii = nombre.as_bytes();
            let cantidad = ascii.len().min(15);
            campo[..cantidad].copy_from_slice(&ascii[..cantidad]);
            paquete.extend_from_slice(&campo);
            paquete.push(*sufijo);
            let banderas: u16 = if *grupo { BANDERA_GRUPO } else { 0 };
            paquete.extend_from_slice(&banderas.to_be_bytes());
        }
        paquete
    }

    #[test]
    fn la_consulta_nbstat_tiene_el_formato_esperado() {
        let consulta = build_nbstat_query(0x1234);
        assert_eq!(consulta.len(), 50);
        assert_eq!(&consulta[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([consulta[2], consulta[3]]), 0); // banderas
        assert_eq!(u16::from_be_bytes([consulta[4], consulta[5]]), 1); // QDCOUNT
        assert_eq!(consulta[12], 0x20); // longitud del nombre codificado
        let nombre = std::str::from_utf8(&consulta[13..45]).expect("nombre ASCII");
        // El comodín NBSTAT es '*' (0x2A) seguido de 15 ceros de relleno: la
        // codificación de primer nivel da "CK" y quince veces "AA".
        assert_eq!(&nombre[0..2], "CK");
        assert_eq!(&nombre[2..], "AA".repeat(15).as_str());
        assert_eq!(consulta[45], 0x00); // fin del nombre
        assert_eq!(
            u16::from_be_bytes([consulta[46], consulta[47]]),
            TIPO_NBSTAT
        );
        assert_eq!(u16::from_be_bytes([consulta[48], consulta[49]]), 1); // clase IN
    }

    #[test]
    fn ida_y_vuelta_con_la_pregunta_ecoada() {
        let paquete = respuesta_nbstat(
            0x1234,
            &[
                ("MI-PC", 0x00, false),
                ("TRABAJO", 0x00, true),
                ("MI-PC", 0x20, false),
            ],
            true,
        );
        let info = parse_nbstat_response(&paquete).expect("respuesta válida");
        assert_eq!(info.hostname.as_deref(), Some("MI-PC"));
        assert_eq!(info.workgroup.as_deref(), Some("TRABAJO"));
        assert_eq!(info.names, vec!["MI-PC".to_string(), "TRABAJO".to_string()]);
        assert_eq!(info.ip, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn ida_y_vuelta_con_el_nombre_completo_sin_pregunta() {
        let paquete = respuesta_nbstat(
            0x4321,
            &[("SERVIDOR", 0x00, false), ("CASA", 0x00, true)],
            false,
        );
        let info = parse_nbstat_response(&paquete).expect("respuesta válida");
        assert_eq!(info.hostname.as_deref(), Some("SERVIDOR"));
        assert_eq!(info.workgroup.as_deref(), Some("CASA"));
    }

    #[test]
    fn una_respuesta_vacia_o_truncada_no_entra_en_panico() {
        assert!(parse_nbstat_response(&[]).is_err());
        assert!(parse_nbstat_response(&[0u8; 11]).is_err());
        // Cabecera válida con ANCOUNT=1 pero sin el registro.
        let mut truncada = respuesta_nbstat(1, &[("PC", 0x00, false)], true);
        truncada.truncate(20);
        assert!(parse_nbstat_response(&truncada).is_err());
    }

    #[test]
    fn rechaza_un_paquete_que_no_es_respuesta() {
        let consulta = build_nbstat_query(7);
        assert!(parse_nbstat_response(&consulta).is_err());
    }

    #[test]
    fn rechaza_una_respuesta_sin_nombres() {
        let mut paquete = respuesta_nbstat(3, &[("PC", 0x00, false)], true);
        // Tras la pregunta, el RDATA empieza con la cuenta de nombres: se pone a 0.
        let consulta = build_nbstat_query(3);
        let inicio_rdata = 12 + (consulta.len() - 12) + 2 + 10;
        paquete[inicio_rdata] = 0;
        assert!(parse_nbstat_response(&paquete).is_err());
    }

    #[test]
    fn una_respuesta_con_longitud_de_datos_excesiva_falla() {
        let mut paquete = respuesta_nbstat(5, &[("PC", 0x00, false)], true);
        let consulta = build_nbstat_query(5);
        let posicion_longitud = 12 + (consulta.len() - 12) + 2 + 8;
        paquete[posicion_longitud] = 0xFF;
        paquete[posicion_longitud + 1] = 0xFF;
        assert!(parse_nbstat_response(&paquete).is_err());
    }

    #[test]
    fn el_nombre_y_el_grupo_se_extraen_del_sufijo_cero() {
        let paquete = respuesta_nbstat(
            9,
            &[
                ("PC", 0x00, false),
                ("GRUPO", 0x00, true),
                ("SERVICIO", 0x1c, true),
            ],
            true,
        );
        let info = parse_nbstat_response(&paquete).expect("respuesta válida");
        assert_eq!(info.hostname.as_deref(), Some("PC"));
        assert_eq!(info.workgroup.as_deref(), Some("GRUPO"));
        assert!(info.names.contains(&"SERVICIO".to_string()));
    }

    #[test]
    fn consulta_sin_servidor_falla_sin_panico() {
        // Sin responder en loopback: se espera error, pero si hubiera un servicio
        // NetBIOS local el resultado debe ser coherente. Nunca debe entrar en pánico.
        let ip = Ipv4Addr::LOCALHOST;
        if let Ok(info) = tokio::runtime::Runtime::new()
            .expect("runtime de tokio")
            .block_on(Netbios::query_name(ip, Duration::from_millis(80)))
        {
            assert_eq!(info.ip, ip);
        }
    }
}
