//! DAO de conexiones activas y tabla caliente (tabla CONNECTIONS).
//!
//! CONNECTIONS no es histórico (el histórico es Fase 5): cada ciclo de snapshot
//! (5 s) hace upsert de las conexiones observadas por su 5-tuple canónica
//! (protocolo, IP y puerto de origen, IP y puerto de destino) y purga las que
//! llevan más tiempo del que marca su timeout sin tráfico.
//!
//! device_id NULL significa que la conexión no está atribuida a ningún equipo
//! de DEVICES: host propio (`[host]`), broadcast (`[broadcast]`) o equipo aún no
//! descubierto (`[?]`). Esa etiqueta la decide la capa de tráfico; este DAO solo
//! persiste el NULL. La clave foránea es ON DELETE SET NULL, de modo que borrar
//! un equipo no borra sus conexiones, solo las deja sin atribuir.

use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection as SqliteConnection, OptionalExtension, Row};

use super::ahora_rfc3339;
use crate::error::Result;

/// Timeout sin tráfico de una conexión TCP establecida: 300 s.
pub const TIMEOUT_TCP_S: u64 = 300;
/// Timeout sin tráfico de una conexión TCP en TIME_WAIT o CLOSE_WAIT: 60 s.
pub const TIMEOUT_TCP_CIERRE_S: u64 = 60;
/// Timeout sin tráfico de una conexión UDP: 60 s.
pub const TIMEOUT_UDP_S: u64 = 60;
/// Timeout sin tráfico de una conexión ICMP/ICMPv6: 30 s.
pub const TIMEOUT_ICMP_S: u64 = 30;
/// Timeout sin tráfico del resto de protocolos: 300 s.
pub const TIMEOUT_OTROS_S: u64 = 300;

/// Protocolo de transporte persistido en CONNECTIONS.
///
/// Es un enum propio (no reutiliza `capture::Protocol`) para mantener la capa de
/// persistencia independiente de la de captura. ICMPv6 y los protocolos IP no
/// soportados se guardan como [ConnectionProtocol::Other].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ConnectionProtocol {
    /// TCP.
    #[default]
    Tcp,
    /// UDP.
    Udp,
    /// ICMP (IPv4 e IPv6).
    Icmp,
    /// Cualquier otro protocolo IP.
    Other,
}

impl ConnectionProtocol {
    /// Todos los protocolos persistibles.
    pub const ALL: [Self; 4] = [Self::Tcp, Self::Udp, Self::Icmp, Self::Other];

    /// Representación persistida (columna protocol).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Other => "other",
        }
    }

    /// Reconstruye el protocolo desde su representación persistida.
    pub fn from_str(valor: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protocolo| protocolo.as_str() == valor)
    }

    /// Etiqueta visible en la interfaz.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Other => "otros",
        }
    }
}

/// Fila persistida de CONNECTIONS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Identificador interno (PK).
    pub id: i64,
    /// FK a DEVICES; NULL si no se atribuyó a ningún equipo.
    pub device_id: Option<i64>,
    /// Protocolo.
    pub protocol: ConnectionProtocol,
    /// IP de origen (texto tal cual la reporta el origen: IPv4 o IPv6).
    pub src_ip: String,
    /// Puerto de origen (None en ICMP/ICMPv6).
    pub src_port: Option<u16>,
    /// IP de destino.
    pub dst_ip: String,
    /// Puerto de destino (None en ICMP/ICMPv6).
    pub dst_port: Option<u16>,
    /// Estado TCP ("ESTABLISHED", "TIME_WAIT"...); None en UDP/ICMP.
    pub state: Option<String>,
    /// Bytes recibidos acumulados.
    pub bytes_in: i64,
    /// Bytes enviados acumulados.
    pub bytes_out: i64,
    /// Primera observación (RFC 3339 UTC); se conserva en los updates.
    pub first_seen: String,
    /// Última observación (RFC 3339 UTC).
    pub last_seen: String,
}

/// Datos para hacer upsert de una conexión.
///
/// Con `id` a None el upsert busca por la 5-tuple (protocol, src_ip, src_port,
/// dst_ip, dst_port): si existe actualiza esa fila y si no se inserta. Con
/// `id` a Some actualiza directamente esa fila y, si ya no existe (por ejemplo
/// porque la purgó un ciclo anterior), se trata como inserción por 5-tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionUpdate {
    /// Id de la fila a actualizar, si se conoce.
    pub id: Option<i64>,
    /// FK a DEVICES; None = sin atribuir (host, broadcast o desconocido).
    pub device_id: Option<i64>,
    /// Protocolo.
    pub protocol: ConnectionProtocol,
    /// IP de origen.
    pub src_ip: String,
    /// Puerto de origen.
    pub src_port: Option<u16>,
    /// IP de destino.
    pub dst_ip: String,
    /// Puerto de destino.
    pub dst_port: Option<u16>,
    /// Estado TCP, si se conoce.
    pub state: Option<String>,
    /// Bytes recibidos acumulados.
    pub bytes_in: i64,
    /// Bytes enviados acumulados.
    pub bytes_out: i64,
}

/// Columnas de CONNECTIONS en el mismo orden que reconstruye fila_a_conexion.
const SQL_SELECCION: &str = "SELECT id, device_id, protocol, src_ip, src_port, dst_ip, \
     dst_port, state, bytes_in, bytes_out, first_seen, last_seen FROM CONNECTIONS";

/// Sentencia SET común a los updates por id y por 5-tuple (first_seen se omite
/// a propósito: nunca se pisa en un update).
const SQL_ACTUALIZAR: &str = "UPDATE CONNECTIONS SET
         device_id = ?1,
         protocol = ?2,
         src_ip = ?3,
         src_port = ?4,
         dst_ip = ?5,
         dst_port = ?6,
         state = ?7,
         bytes_in = ?8,
         bytes_out = ?9,
         last_seen = ?10
     WHERE id = ?11";

/// El filtro de list convierte el estado o el protocolo en su forma persistida:
/// el resto de búsquedas (IP) es un LIKE a la representación textual.
fn patron_like(filtro: &str) -> String {
    format!("%{filtro}%")
}

/// Inserta o actualiza una conexión y devuelve su id.
///
/// En los updates se conserva first_seen y se refresca last_seen; el resto de
/// columnas se sobrescriben con lo que traiga el update (es un snapshot del
/// estado observado, no un incremento). Si el id indicado ya no existe, se
/// continúa por la senda de la 5-tuple para no perder la conexión.
pub(crate) fn upsert(conn: &SqliteConnection, conexion: &ConnectionUpdate) -> Result<i64> {
    let ahora = ahora_rfc3339();

    if let Some(id) = conexion.id {
        let actualizadas = actualizar(conn, id, conexion, &ahora)?;
        if actualizadas > 0 {
            return Ok(id);
        }
    }

    if let Some(id) = buscar_por_cinco_tupla(conn, conexion)? {
        actualizar(conn, id, conexion, &ahora)?;
        return Ok(id);
    }

    let id = conn.query_row(
        "INSERT INTO CONNECTIONS (
             device_id, protocol, src_ip, src_port, dst_ip, dst_port,
             state, bytes_in, bytes_out, first_seen, last_seen
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
         RETURNING id",
        params![
            conexion.device_id,
            conexion.protocol.as_str(),
            conexion.src_ip,
            conexion.src_port,
            conexion.dst_ip,
            conexion.dst_port,
            conexion.state,
            conexion.bytes_in,
            conexion.bytes_out,
            ahora
        ],
        |fila| fila.get(0),
    )?;
    Ok(id)
}

/// Lista las conexiones activas ordenadas por last_seen descendente.
///
/// Con filtro None devuelve todas. Con Some(texto) casa si el protocolo o el
/// estado son exactamente ese texto, o si la IP de origen o la de destino
/// contienen el texto (LIKE, sin distinguir mayúsculas en ASCII). El texto vacío
/// actúa como comodín y devuelve todas.
pub(crate) fn list(conn: &SqliteConnection, filtro: Option<&str>) -> Result<Vec<Connection>> {
    match filtro {
        Some(texto) => {
            let mut sentencia = conn.prepare(&format!(
                "{SQL_SELECCION} WHERE protocol = ?1 OR state = ?1
                 OR src_ip LIKE ?2 OR dst_ip LIKE ?2
                 ORDER BY last_seen DESC, id DESC"
            ))?;
            let filas = sentencia.query_map(params![texto, patron_like(texto)], fila_a_conexion)?;
            recolectar(filas)
        }
        None => {
            let mut sentencia =
                conn.prepare(&format!("{SQL_SELECCION} ORDER BY last_seen DESC, id DESC"))?;
            let filas = sentencia.query_map([], fila_a_conexion)?;
            recolectar(filas)
        }
    }
}

/// Recupera una conexión por id (para el panel de cabeceras de la tecla v).
pub(crate) fn get(conn: &SqliteConnection, id: i64) -> Result<Option<Connection>> {
    let sql = format!("{SQL_SELECCION} WHERE id = ?1");
    let conexion = conn
        .query_row(&sql, params![id], fila_a_conexion)
        .optional()?;
    Ok(conexion)
}

/// Purga las conexiones que llevan más de su timeout sin tráfico.
///
/// Timeouts: TCP 300 s; TCP en TIME_WAIT o CLOSE_WAIT 60 s; UDP 60 s; ICMP 30 s;
/// el resto 300 s. `now` fija el instante de referencia para que el resultado
/// sea determinista en los tests; en producción se pasa SystemTime::now().
pub(crate) fn prune_expired(conn: &SqliteConnection, now: SystemTime) -> Result<usize> {
    let ahora: DateTime<Utc> = now.into();
    let corte = |segundos: u64| {
        (ahora - chrono::Duration::seconds(segundos as i64))
            .to_rfc3339_opts(SecondsFormat::Secs, true)
    };

    let borrados = conn.execute(
        "DELETE FROM CONNECTIONS
         WHERE (protocol = 'tcp' AND state IN ('TIME_WAIT', 'CLOSE_WAIT')
                AND last_seen < ?1)
            OR (protocol = 'tcp'
                AND (state IS NULL OR state NOT IN ('TIME_WAIT', 'CLOSE_WAIT'))
                AND last_seen < ?2)
            OR (protocol = 'udp' AND last_seen < ?3)
            OR (protocol = 'icmp' AND last_seen < ?4)
            OR (protocol NOT IN ('tcp', 'udp', 'icmp') AND last_seen < ?5)",
        params![
            corte(TIMEOUT_TCP_CIERRE_S),
            corte(TIMEOUT_TCP_S),
            corte(TIMEOUT_UDP_S),
            corte(TIMEOUT_ICMP_S),
            corte(TIMEOUT_OTROS_S)
        ],
    )?;
    Ok(borrados)
}

/// Actualiza una fila por id y devuelve cuántas filas cambió.
fn actualizar(
    conn: &SqliteConnection,
    id: i64,
    conexion: &ConnectionUpdate,
    ahora: &str,
) -> Result<usize> {
    let actualizadas = conn.execute(
        SQL_ACTUALIZAR,
        params![
            conexion.device_id,
            conexion.protocol.as_str(),
            conexion.src_ip,
            conexion.src_port,
            conexion.dst_ip,
            conexion.dst_port,
            conexion.state,
            conexion.bytes_in,
            conexion.bytes_out,
            ahora,
            id
        ],
    )?;
    Ok(actualizadas)
}

/// Busca el id de una conexión por su 5-tuple canónica (sin device_id).
fn buscar_por_cinco_tupla(
    conn: &SqliteConnection,
    conexion: &ConnectionUpdate,
) -> Result<Option<i64>> {
    let id = conn
        .query_row(
            "SELECT id FROM CONNECTIONS
             WHERE protocol = ?1
               AND src_ip = ?2 AND src_port IS ?3
               AND dst_ip = ?4 AND dst_port IS ?5
             ORDER BY id LIMIT 1",
            params![
                conexion.protocol.as_str(),
                conexion.src_ip,
                conexion.src_port,
                conexion.dst_ip,
                conexion.dst_port
            ],
            |fila| fila.get(0),
        )
        .optional()?;
    Ok(id)
}

/// Recoge las filas ya mapeadas, propagando el primer error de SQLite.
fn recolectar(
    filas: impl Iterator<Item = rusqlite::Result<Connection>>,
) -> Result<Vec<Connection>> {
    let mut conexiones = Vec::new();
    for fila in filas {
        conexiones.push(fila?);
    }
    Ok(conexiones)
}

/// Reconstruye una conexión a partir de una fila de SQL_SELECCION.
fn fila_a_conexion(fila: &Row<'_>) -> rusqlite::Result<Connection> {
    let protocolo: String = fila.get(2)?;
    Ok(Connection {
        id: fila.get(0)?,
        device_id: fila.get(1)?,
        // Un protocolo escrito por una versión futura se muestra como "otros"
        // en vez de romper la vista de Conexiones.
        protocol: ConnectionProtocol::from_str(&protocolo).unwrap_or(ConnectionProtocol::Other),
        src_ip: fila.get(3)?,
        src_port: fila.get(4)?,
        dst_ip: fila.get(5)?,
        dst_port: fila.get(6)?,
        state: fila.get(7)?,
        bytes_in: fila.get(8)?,
        bytes_out: fila.get(9)?,
        first_seen: fila.get(10)?,
        last_seen: fila.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::time::Duration;

    /// Instante fijo de referencia para las pruebas de purga: 2027-01-15T08:00:00Z.
    fn instante_fijo() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    /// Fecha RFC 3339 UTC de hace `segundos` respecto al instante fijo.
    fn fecha_hace(segundos: u64) -> String {
        let ahora: DateTime<Utc> = instante_fijo().into();
        (ahora - chrono::Duration::seconds(segundos as i64))
            .to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    /// Conexión en memoria con el esquema migrado y un equipo de prueba (id 1).
    fn conexion_con_equipo() -> (SqliteConnection, i64) {
        let mut conn = SqliteConnection::open_in_memory().expect("abrir SQLite en memoria");
        conn.pragma_update(None, "foreign_keys", "ON")
            .expect("activar claves foráneas");
        crate::repo::migrations::apply_all(&mut conn).expect("aplicar migraciones");

        conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '192.168.1.10', '255.255.255.0',
                     '192.168.1.1', 1, '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("insertar interfaz");
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, interface_id, device_type, is_online, first_seen, last_seen)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 1, 'unknown', 1,
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("insertar equipo");
        let device_id = conn.last_insert_rowid();
        (conn, device_id)
    }

    /// Datos de upsert de una conexión TCP con los valores indicados.
    fn actualizacion_tcp(bytes_in: i64, bytes_out: i64) -> ConnectionUpdate {
        ConnectionUpdate {
            id: None,
            device_id: None,
            protocol: ConnectionProtocol::Tcp,
            src_ip: "192.168.1.50".to_string(),
            src_port: Some(40_000),
            dst_ip: "93.184.216.34".to_string(),
            dst_port: Some(443),
            state: Some("ESTABLISHED".to_string()),
            bytes_in,
            bytes_out,
        }
    }

    /// Inserta una conexión directamente (sin pasar por el DAO) con la fecha de
    /// última actividad indicada. Devuelve el id insertado.
    fn insertar_cruda(
        conn: &SqliteConnection,
        protocolo: ConnectionProtocol,
        estado: Option<&str>,
        ultima: &str,
    ) -> i64 {
        conn.execute(
            "INSERT INTO CONNECTIONS (
                 device_id, protocol, src_ip, src_port, dst_ip, dst_port,
                 state, bytes_in, bytes_out, first_seen, last_seen
             ) VALUES (NULL, ?1, '10.0.0.1', 1000, '10.0.0.2', 2000, ?2, 0, 0, ?3, ?3)",
            params![protocolo.as_str(), estado, ultima],
        )
        .expect("insertar conexión");
        conn.last_insert_rowid()
    }

    #[test]
    fn protocolo_ida_y_vuelta_y_etiquetas() {
        for protocolo in ConnectionProtocol::ALL {
            assert_eq!(
                ConnectionProtocol::from_str(protocolo.as_str()),
                Some(protocolo)
            );
        }
        assert_eq!(ConnectionProtocol::from_str("sctp"), None);
        assert_eq!(ConnectionProtocol::default(), ConnectionProtocol::Tcp);
        assert_eq!(ConnectionProtocol::Tcp.label(), "TCP");
        assert_eq!(ConnectionProtocol::Udp.label(), "UDP");
        assert_eq!(ConnectionProtocol::Icmp.label(), "ICMP");
        assert_eq!(ConnectionProtocol::Other.label(), "otros");
    }

    #[test]
    fn upsert_inserta_y_actualiza_por_cinco_tupla_sin_duplicar() {
        let (conn, device_id) = conexion_con_equipo();

        let mut primera = actualizacion_tcp(1_000, 500);
        primera.device_id = Some(device_id);
        let id = upsert(&conn, &primera).expect("insertar conexión");
        assert!(id > 0);

        let conexiones = list(&conn, None).expect("listar conexiones");
        assert_eq!(conexiones.len(), 1);
        assert_eq!(conexiones[0].device_id, Some(device_id));
        assert_eq!(conexiones[0].protocol, ConnectionProtocol::Tcp);
        assert_eq!(conexiones[0].src_port, Some(40_000));
        assert_eq!(conexiones[0].dst_port, Some(443));
        assert_eq!(conexiones[0].state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(conexiones[0].bytes_in, 1_000);
        assert_eq!(conexiones[0].bytes_out, 500);
        assert!(conexiones[0].first_seen.ends_with('Z'));
        assert_eq!(conexiones[0].first_seen, conexiones[0].last_seen);

        // Se envejece first_seen a mano para comprobar que el update lo conserva.
        conn.execute(
            "UPDATE CONNECTIONS SET first_seen = '2026-01-01T00:00:00Z' WHERE id = ?1",
            params![id],
        )
        .expect("envejecer first_seen");

        let mut segunda = actualizacion_tcp(9_000, 4_500);
        segunda.state = Some("CLOSE_WAIT".to_string());
        let id_repetido = upsert(&conn, &segunda).expect("actualizar conexión");
        assert_eq!(id_repetido, id, "la 5-tuple debe conservar el id");

        let conexiones = list(&conn, None).expect("listar conexiones");
        assert_eq!(conexiones.len(), 1, "no debe duplicar la conexión");
        assert_eq!(conexiones[0].first_seen, "2026-01-01T00:00:00Z");
        assert_eq!(conexiones[0].bytes_in, 9_000);
        assert_eq!(conexiones[0].bytes_out, 4_500);
        assert_eq!(conexiones[0].state.as_deref(), Some("CLOSE_WAIT"));
    }

    #[test]
    fn upsert_por_id_actualiza_la_fila_indicada() {
        let (conn, device_id) = conexion_con_equipo();
        let id = upsert(&conn, &actualizacion_tcp(100, 200)).expect("insertar conexión");
        let primero = get(&conn, id).expect("buscar conexión").expect("existe");

        let mut update = actualizacion_tcp(300, 400);
        update.id = Some(id);
        update.device_id = Some(device_id);
        update.state = Some("TIME_WAIT".to_string());
        update.bytes_in = 300;
        update.bytes_out = 400;
        let id_actualizado = upsert(&conn, &update).expect("actualizar por id");

        assert_eq!(id_actualizado, id);
        let conexion = get(&conn, id).expect("buscar conexión").expect("existe");
        assert_eq!(conexion.device_id, Some(device_id));
        assert_eq!(conexion.state.as_deref(), Some("TIME_WAIT"));
        assert_eq!(conexion.bytes_in, 300);
        assert_eq!(conexion.bytes_out, 400);
        assert_eq!(
            conexion.first_seen, primero.first_seen,
            "first_seen se conserva en el update"
        );
    }

    #[test]
    fn upsert_por_id_purgado_reinserta_la_conexion() {
        let (conn, _) = conexion_con_equipo();
        let mut update = actualizacion_tcp(10, 20);
        update.id = Some(999);
        let id = upsert(&conn, &update).expect("insertar al no existir el id");

        assert_ne!(id, 999);
        let conexiones = list(&conn, None).expect("listar conexiones");
        assert_eq!(conexiones.len(), 1);
        assert_eq!(conexiones[0].id, id);
    }

    #[test]
    fn get_devuelve_none_si_no_existe() {
        let (conn, _) = conexion_con_equipo();
        assert!(get(&conn, 42).expect("buscar inexistente").is_none());
    }

    #[test]
    fn list_ordena_por_last_seen_desc_y_filtra() {
        let (conn, _) = conexion_con_equipo();
        // Dos TCP con la misma 5-tuple no (se actualizaría); se usan puertos
        // distintos para tener filas separadas.
        let mut vieja = actualizacion_tcp(10, 20);
        vieja.src_ip = "192.168.1.60".to_string();
        vieja.state = Some("ESTABLISHED".to_string());
        let id_vieja = upsert(&conn, &vieja).expect("insertar conexión vieja");
        let mut nueva = actualizacion_tcp(30, 40);
        nueva.src_ip = "192.168.1.61".to_string();
        nueva.state = Some("LISTEN".to_string());
        let id_nueva = upsert(&conn, &nueva).expect("insertar conexión nueva");
        conn.execute(
            "UPDATE CONNECTIONS SET last_seen = '2026-01-01T00:00:00Z' WHERE id = ?1",
            params![id_vieja],
        )
        .expect("envejecer la primera");

        let todas = list(&conn, None).expect("listar todas");
        assert_eq!(todas.len(), 2);
        assert_eq!(todas[0].id, id_nueva, "la más reciente va primero");
        assert_eq!(todas[1].id, id_vieja);

        // Filtro por protocolo.
        assert_eq!(
            list(&conn, Some("tcp"))
                .expect("filtrar por protocolo")
                .len(),
            2
        );
        // Filtro por estado exacto.
        let por_estado = list(&conn, Some("LISTEN")).expect("filtrar por estado");
        assert_eq!(por_estado.len(), 1);
        assert_eq!(por_estado[0].id, id_nueva);
        // Filtro por IP (LIKE en origen o destino).
        assert_eq!(
            list(&conn, Some("192.168.1.60"))
                .expect("filtrar por IP")
                .len(),
            1
        );
        assert_eq!(
            list(&conn, Some("93.184.216")).expect("filtrar por IP destino"),
            todas
                .iter()
                .filter(|conexion| conexion.dst_ip.contains("93.184.216"))
                .cloned()
                .collect::<Vec<_>>()
        );
        // Sin coincidencias.
        assert!(list(&conn, Some("udp")).expect("filtrar udp").is_empty());
        assert!(list(&conn, Some("no-existe"))
            .expect("filtrar inexistente")
            .is_empty());
    }

    #[test]
    fn prune_expired_respeta_cada_timeout() {
        let (conn, _) = conexion_con_equipo();

        // TCP establecidas: 299 s se conserva, 300 s justo en el límite se
        // conserva, 301 s se purga.
        let tcp_299 = insertar_cruda(
            &conn,
            ConnectionProtocol::Tcp,
            Some("ESTABLISHED"),
            &fecha_hace(299),
        );
        let tcp_300 = insertar_cruda(
            &conn,
            ConnectionProtocol::Tcp,
            Some("ESTABLISHED"),
            &fecha_hace(300),
        );
        let tcp_301 = insertar_cruda(
            &conn,
            ConnectionProtocol::Tcp,
            Some("ESTABLISHED"),
            &fecha_hace(301),
        );
        // TCP en cierre: 60 s.
        let tw_59 = insertar_cruda(
            &conn,
            ConnectionProtocol::Tcp,
            Some("TIME_WAIT"),
            &fecha_hace(59),
        );
        let tw_61 = insertar_cruda(
            &conn,
            ConnectionProtocol::Tcp,
            Some("TIME_WAIT"),
            &fecha_hace(61),
        );
        let cw_61 = insertar_cruda(
            &conn,
            ConnectionProtocol::Tcp,
            Some("CLOSE_WAIT"),
            &fecha_hace(61),
        );
        // UDP: 60 s.
        let udp_59 = insertar_cruda(&conn, ConnectionProtocol::Udp, None, &fecha_hace(59));
        let udp_61 = insertar_cruda(&conn, ConnectionProtocol::Udp, None, &fecha_hace(61));
        // ICMP: 30 s.
        let icmp_29 = insertar_cruda(&conn, ConnectionProtocol::Icmp, None, &fecha_hace(29));
        let icmp_31 = insertar_cruda(&conn, ConnectionProtocol::Icmp, None, &fecha_hace(31));
        // Resto: 300 s.
        let otros_299 = insertar_cruda(&conn, ConnectionProtocol::Other, None, &fecha_hace(299));
        let otros_301 = insertar_cruda(&conn, ConnectionProtocol::Other, None, &fecha_hace(301));

        let borrados = prune_expired(&conn, instante_fijo()).expect("purgar conexiones");
        assert_eq!(borrados, 6, "se purga una fila por cada timeout superado");

        for id in [tcp_301, tw_61, cw_61, udp_61, icmp_31, otros_301] {
            assert!(
                get(&conn, id).expect("buscar purgada").is_none(),
                "la conexión {id} debería haberse purgado"
            );
        }
        for id in [tcp_299, tcp_300, tw_59, udp_59, icmp_29, otros_299] {
            assert!(
                get(&conn, id).expect("buscar conservada").is_some(),
                "la conexión {id} debería conservarse"
            );
        }

        // Una segunda purga no borra nada más.
        assert_eq!(
            prune_expired(&conn, instante_fijo()).expect("segunda purga"),
            0
        );
    }

    #[test]
    fn borrar_el_equipo_deja_las_conexiones_sin_atribuir() {
        let (conn, device_id) = conexion_con_equipo();
        let mut update = actualizacion_tcp(10, 20);
        update.device_id = Some(device_id);
        let id = upsert(&conn, &update).expect("insertar conexión atribuida");

        conn.execute("DELETE FROM DEVICES WHERE id = ?1", params![device_id])
            .expect("borrar el equipo");

        let conexion = get(&conn, id).expect("buscar conexión").expect("existe");
        assert_eq!(
            conexion.device_id, None,
            "ON DELETE SET NULL deja la conexión sin atribuir"
        );
        assert_eq!(
            conexion.bytes_in, 10,
            "los datos de la conexión se conservan"
        );
    }

    #[test]
    fn una_conexion_con_equipo_inexistente_falla_por_clave_foranea() {
        let (conn, _) = conexion_con_equipo();
        let mut update = actualizacion_tcp(0, 0);
        update.device_id = Some(999);
        let error = upsert(&conn, &update).expect_err("la FK debe rechazar el device_id");
        assert!(matches!(error, Error::Database(_)), "error: {error}");
        assert!(
            error.to_string().contains("FOREIGN KEY"),
            "el error debe explicar la violación de clave foránea: {error}"
        );
    }
}
