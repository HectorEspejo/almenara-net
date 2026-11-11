//! DAO de los rollups del histórico (TRAFFIC_ROLLUP_MINUTE/HOUR/DAY).
//!
//! Los cubos son enteros: segundos Unix UTC en minutos y horas, y fecha local
//! AAAAMMDD en días (ADR-56). La escritura del minuto suma si el cubo ya existe
//! (upsert), de modo que un reintento o un salto atrás del reloj nunca pierde ni
//! duplica bytes. La consolidación de horas y días es idempotente: borra el cubo
//! y lo reconstruye entero en la misma transacción.

use std::collections::HashSet;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;
use crate::history::build::aplicar_topes;
use crate::history::localtime;
use crate::history::{Counter, Dimension, PurgeStats, RollupBatch, RollupRow, Subject};
use crate::repo::seen::SeenChange;

/// Columnas de un rollup, en el orden de inserción.
const SQL_INSERTAR_MINUTO: &str = "\
INSERT INTO TRAFFIC_ROLLUP_MINUTE
    (bucket, subject, device_id, dimension, key, bytes_down, bytes_up, connections)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
ON CONFLICT (bucket, subject, device_id, dimension, key) DO UPDATE SET
    bytes_down  = bytes_down + excluded.bytes_down,
    bytes_up    = bytes_up + excluded.bytes_up,
    connections = connections + excluded.connections";

/// Inserción sin suma, para la consolidación (el cubo se borra antes).
const SQL_INSERTAR_HORA: &str = "\
INSERT INTO TRAFFIC_ROLLUP_HOUR
    (bucket, subject, device_id, dimension, key, bytes_down, bytes_up, connections)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";

/// Insertar de un día consolidado.
const SQL_INSERTAR_DIA: &str = "\
INSERT INTO TRAFFIC_ROLLUP_DAY
    (bucket, subject, device_id, dimension, key, bytes_down, bytes_up, connections)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";

/// Escribe el lote del minuto y su inventario en una única transacción.
///
/// Devuelve las entradas de inventario nuevas (equipos y propio equipo): son la
/// señal de las reglas de lo nuevo (§7.11).
pub(crate) fn insert_minute_batch(
    conn: &mut Connection,
    batch: &RollupBatch,
) -> Result<SeenChange> {
    let marca = localtime::rfc3339(batch.minute);
    let transaccion = conn.transaction()?;
    {
        let mut sentencia = transaccion.prepare(SQL_INSERTAR_MINUTO)?;
        for fila in &batch.rows {
            sentencia.execute(params![
                batch.minute,
                fila.subject.as_str(),
                fila.subject.device_id(),
                fila.dimension.as_str(),
                fila.key,
                entero(fila.counter.down),
                entero(fila.counter.up),
                entero(fila.counter.connections),
            ])?;
        }
    }
    let cambio = crate::repo::seen::upsert_seen_en(&transaccion, &batch.seen, &marca)?;
    transaccion.commit()?;
    Ok(cambio)
}

/// Consolida una hora a partir de sus minutos (§7.3).
pub(crate) fn build_hour(conn: &mut Connection, hour: i64, top_keys: usize) -> Result<usize> {
    let filas = agregar(
        conn,
        "SELECT subject, device_id, dimension, key,
                SUM(bytes_down), SUM(bytes_up), SUM(connections)
           FROM TRAFFIC_ROLLUP_MINUTE
          WHERE bucket >= ?1 AND bucket < ?2
          GROUP BY subject, device_id, dimension, key",
        hour,
        hour + 3600,
    )?;
    let filas = aplicar_topes(filas, top_keys);
    let transaccion = conn.transaction()?;
    transaccion.execute(
        "DELETE FROM TRAFFIC_ROLLUP_HOUR WHERE bucket = ?1",
        params![hour],
    )?;
    let escritas = insertar_filas(&transaccion, SQL_INSERTAR_HORA, hour, &filas)?;
    transaccion.commit()?;
    Ok(escritas)
}

/// Consolida un día local a partir de sus horas reales, sin destinos (§7.3).
pub(crate) fn build_day(
    conn: &mut Connection,
    dia: crate::history::LocalDay,
    top_keys: usize,
) -> Result<usize> {
    let (desde, hasta) = dia.limits();
    let filas = agregar(
        conn,
        "SELECT subject, device_id, dimension, key,
                SUM(bytes_down), SUM(bytes_up), SUM(connections)
           FROM TRAFFIC_ROLLUP_HOUR
          WHERE bucket >= ?1 AND bucket < ?2 AND dimension <> 'destination'
          GROUP BY subject, device_id, dimension, key",
        desde,
        hasta,
    )?;
    let filas = aplicar_topes(filas, top_keys);
    let transaccion = conn.transaction()?;
    transaccion.execute(
        "DELETE FROM TRAFFIC_ROLLUP_DAY WHERE bucket = ?1",
        params![dia.aaaammdd()],
    )?;
    let escritas = insertar_filas(&transaccion, SQL_INSERTAR_DIA, dia.aaaammdd(), &filas)?;
    transaccion.commit()?;
    Ok(escritas)
}

/// Horas anteriores a before que tienen minutos y no están consolidadas.
pub(crate) fn pending_hours(conn: &Connection, before: i64) -> Result<Vec<i64>> {
    let mut sentencia = conn.prepare(
        "SELECT DISTINCT (m.bucket / 3600) * 3600 AS hora
           FROM TRAFFIC_ROLLUP_MINUTE m
          WHERE m.bucket < ?1
            AND NOT EXISTS (
                SELECT 1 FROM TRAFFIC_ROLLUP_HOUR h
                 WHERE h.bucket = (m.bucket / 3600) * 3600
            )
          ORDER BY hora",
    )?;
    let filas = sentencia.query_map(params![before], |fila| fila.get(0))?;
    let mut horas = Vec::new();
    for fila in filas {
        horas.push(fila?);
    }
    Ok(horas)
}

/// Días locales anteriores a today que tienen horas y no están consolidados.
pub(crate) fn pending_days(
    conn: &Connection,
    today: crate::history::LocalDay,
) -> Result<Vec<crate::history::LocalDay>> {
    let mut sentencia = conn.prepare("SELECT DISTINCT bucket FROM TRAFFIC_ROLLUP_HOUR")?;
    let filas = sentencia.query_map([], |fila| fila.get::<_, i64>(0))?;
    let mut dias = Vec::new();
    let mut vistos = HashSet::new();
    for fila in filas {
        let dia = crate::history::LocalDay::from_hour(fila?);
        if dia < today && vistos.insert(dia) {
            dias.push(dia);
        }
    }
    dias.sort();
    let consolidados: HashSet<i64> = {
        let mut sentencia = conn.prepare("SELECT bucket FROM TRAFFIC_ROLLUP_DAY")?;
        let filas = sentencia.query_map([], |fila| fila.get::<_, i64>(0))?;
        let mut conjunto = HashSet::new();
        for fila in filas {
            conjunto.insert(fila?);
        }
        conjunto
    };
    Ok(dias
        .into_iter()
        .filter(|dia| !consolidados.contains(&dia.aaaammdd()))
        .collect())
}

/// Primera hora con minutos sin consolidar, anterior a before (§7.4).
///
/// Se busca por tramos con la clave primaria de TRAFFIC_ROLLUP_MINUTE (bucket
/// primero) en vez de recorrer todos los minutos: la purga se ejecuta cada hora
/// y no puede permitirse un escaneo completo de 48 h de minutos.
pub(crate) fn first_pending_hour(conn: &Connection, before: i64) -> Result<Option<i64>> {
    let mut desde: Option<i64> = None;
    loop {
        let minimo: Option<i64> = match desde {
            None => conn
                .query_row(
                    "SELECT MIN(bucket) FROM TRAFFIC_ROLLUP_MINUTE WHERE bucket < ?1",
                    params![before],
                    |fila| fila.get(0),
                )
                .optional()?
                .flatten(),
            Some(desde) => conn
                .query_row(
                    "SELECT MIN(bucket) FROM TRAFFIC_ROLLUP_MINUTE
                      WHERE bucket >= ?2 AND bucket < ?1",
                    params![before, desde],
                    |fila| fila.get(0),
                )
                .optional()?
                .flatten(),
        };
        let Some(bucket) = minimo else {
            return Ok(None);
        };
        let hora = bucket - bucket.rem_euclid(3600);
        let consolidada: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM TRAFFIC_ROLLUP_HOUR WHERE bucket = ?1)",
            params![hora],
            |fila| fila.get(0),
        )?;
        if !consolidada {
            return Ok(Some(hora));
        }
        desde = Some(hora + 3600);
        if desde.unwrap_or(i64::MAX) >= before {
            return Ok(None);
        }
    }
}

/// Aplica la purga por resolución (§7.4) y devuelve las filas borradas.
pub(crate) fn purge(
    conn: &mut Connection,
    cortes: &crate::history::retention::Cortes,
) -> Result<PurgeStats> {
    let transaccion = conn.transaction()?;
    let mut stats = PurgeStats {
        at: localtime::now_unix(),
        ..PurgeStats::default()
    };
    stats.rollup_rows += borrar(
        &transaccion,
        "DELETE FROM TRAFFIC_ROLLUP_MINUTE WHERE bucket < ?1",
        params![cortes.minutos],
    )? as u64;
    stats.rollup_rows += borrar(
        &transaccion,
        "DELETE FROM TRAFFIC_ROLLUP_MINUTE
          WHERE dimension = 'destination' AND bucket < ?1",
        params![cortes.minutos_destinos],
    )? as u64;
    stats.rollup_rows += borrar(
        &transaccion,
        "DELETE FROM TRAFFIC_ROLLUP_HOUR WHERE bucket < ?1",
        params![cortes.horas],
    )? as u64;
    match cortes.horas_destinos {
        Some(corte) => {
            stats.rollup_rows += borrar(
                &transaccion,
                "DELETE FROM TRAFFIC_ROLLUP_HOUR
                  WHERE dimension = 'destination' AND bucket < ?1",
                params![corte],
            )? as u64;
        }
        None => {
            stats.rollup_rows += borrar(
                &transaccion,
                "DELETE FROM TRAFFIC_ROLLUP_HOUR WHERE dimension = 'destination'",
                [],
            )? as u64;
        }
    }
    stats.rollup_rows += borrar(
        &transaccion,
        "DELETE FROM TRAFFIC_ROLLUP_DAY WHERE bucket < ?1",
        params![cortes.dias],
    )? as u64;
    stats.seen_rows = borrar(
        &transaccion,
        "DELETE FROM DEVICE_SEEN WHERE last_seen < ?1",
        params![cortes.dias_rfc3339],
    )? as u64;
    stats.session_rows = borrar(
        &transaccion,
        "DELETE FROM APP_SESSIONS WHERE ended_at IS NOT NULL AND ended_at < ?1",
        params![cortes.dias_rfc3339],
    )? as u64;
    transaccion.commit()?;
    Ok(stats)
}

/// Libera como mucho max_pages páginas libres y devuelve cuántas liberó.
pub(crate) fn incremental_vacuum(conn: &Connection, max_pages: u32) -> Result<u32> {
    let antes: i64 = conn.query_row("PRAGMA freelist_count", [], |fila| fila.get(0))?;
    conn.execute_batch(&format!("PRAGMA incremental_vacuum({max_pages});"))?;
    let despues: i64 = conn.query_row("PRAGMA freelist_count", [], |fila| fila.get(0))?;
    Ok((antes - despues).max(0) as u32)
}

/// Borra los destinos consolidados por hora (destination_days = 0, §7.4).
///
/// Con destination_days = 0 no se guardan destinos por hora; el minuto los
/// conserva 2 h (para la ventana de 1 h y para construir la hora) y la hora se
/// limpia en cuanto se consolida.
pub(crate) fn clear_destination_hours(conn: &Connection) -> Result<usize> {
    let borradas = conn.execute(
        "DELETE FROM TRAFFIC_ROLLUP_HOUR WHERE dimension = 'destination'",
        [],
    )?;
    Ok(borradas)
}

/// Borra los rollups de un equipo (relación lógica sin clave ajena, §3).
pub(crate) fn delete_device_rollups(conn: &Connection, device_id: i64) -> Result<usize> {
    let mut borradas = 0usize;
    for tabla in [
        "TRAFFIC_ROLLUP_MINUTE",
        "TRAFFIC_ROLLUP_HOUR",
        "TRAFFIC_ROLLUP_DAY",
    ] {
        borradas += conn.execute(
            &format!("DELETE FROM {tabla} WHERE subject = 'device' AND device_id = ?1"),
            params![device_id],
        )?;
    }
    Ok(borradas)
}

/// Agrega las filas de una resolución inferior a la superior indicada.
fn agregar(conn: &Connection, sql: &str, desde: i64, hasta: i64) -> Result<Vec<RollupRow>> {
    let mut sentencia = conn.prepare(sql)?;
    let filas = sentencia.query_map(params![desde, hasta], |fila| {
        let subject: String = fila.get(0)?;
        let device_id: i64 = fila.get(1)?;
        let dimension: String = fila.get(2)?;
        let key: String = fila.get(3)?;
        let down: i64 = fila.get(4)?;
        let up: i64 = fila.get(5)?;
        let connections: i64 = fila.get(6)?;
        Ok((subject, device_id, dimension, key, down, up, connections))
    })?;
    let mut filas_agregadas = Vec::new();
    for fila in filas {
        let (subject, device_id, dimension, key, down, up, connections) = fila?;
        let Some(subject) = Subject::from_parts(&subject, device_id) else {
            tracing::debug!(subject, "sujeto desconocido en el histórico; se omite");
            continue;
        };
        let Some(dimension) = Dimension::from_str(&dimension) else {
            tracing::debug!(dimension, "dimensión desconocida en el histórico; se omite");
            continue;
        };
        filas_agregadas.push(RollupRow {
            subject,
            dimension,
            key,
            counter: Counter {
                down: maximo(down),
                up: maximo(up),
                connections: maximo(connections),
            },
        });
    }
    Ok(filas_agregadas)
}

/// Inserta filas de una resolución con su bucket, sin sumar.
fn insertar_filas(conn: &Connection, sql: &str, bucket: i64, filas: &[RollupRow]) -> Result<usize> {
    let mut sentencia = conn.prepare(sql)?;
    let mut escritas = 0usize;
    for fila in filas {
        sentencia.execute(params![
            bucket,
            fila.subject.as_str(),
            fila.subject.device_id(),
            fila.dimension.as_str(),
            fila.key,
            entero(fila.counter.down),
            entero(fila.counter.up),
            entero(fila.counter.connections),
        ])?;
        escritas += 1;
    }
    Ok(escritas)
}

fn borrar(conn: &Connection, sql: &str, parametros: impl rusqlite::Params) -> Result<usize> {
    Ok(conn.execute(sql, parametros)?)
}

fn entero(valor: u64) -> i64 {
    valor.min(i64::MAX as u64) as i64
}

fn maximo(valor: i64) -> u64 {
    valor.max(0) as u64
}

/// Devuelve el número de filas de una tabla de rollup (solo pruebas).
// API de la Fase 5 sobre el repositorio: la usa el hilo de la TUI, único
// escritor de la base de datos (ADR-35).
#[allow(dead_code)]
impl crate::repo::Repo {
    /// Escribe el lote del minuto y su inventario en una transacción (§7.11).
    pub fn insert_minute_batch(
        &mut self,
        batch: &crate::history::RollupBatch,
    ) -> crate::error::Result<SeenChange> {
        insert_minute_batch(&mut self.conn, batch)
    }

    /// Consolida una hora a partir de sus minutos (§7.3).
    pub fn build_hour(&mut self, hour: i64, top_keys: usize) -> crate::error::Result<usize> {
        build_hour(&mut self.conn, hour, top_keys)
    }

    /// Consolida un día local desde sus horas, sin destinos.
    pub fn build_day(
        &mut self,
        dia: crate::history::LocalDay,
        top_keys: usize,
    ) -> crate::error::Result<usize> {
        build_day(&mut self.conn, dia, top_keys)
    }

    /// Horas con minutos y sin consolidar, anteriores a before.
    pub fn pending_hours(&self, before: i64) -> crate::error::Result<Vec<i64>> {
        pending_hours(&self.conn, before)
    }

    /// Días locales con horas y sin consolidar, anteriores a today.
    pub fn pending_days(
        &self,
        today: crate::history::LocalDay,
    ) -> crate::error::Result<Vec<crate::history::LocalDay>> {
        pending_days(&self.conn, today)
    }

    /// Purga el histórico por resolución y compacta con incremental_vacuum.
    pub fn purge_history(
        &mut self,
        now: std::time::SystemTime,
        retention: &crate::history::Retention,
    ) -> crate::error::Result<crate::history::PurgeStats> {
        let ahora = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let hora_actual = localtime::hour_start(ahora);
        // Nunca se purgan minutos de una hora sin consolidar: el corte es el
        // inicio de la primera hora pendiente (si no hay, la hora en curso).
        let sin_consolidar = first_pending_hour(&self.conn, hora_actual)?.unwrap_or(hora_actual);
        let hoy = crate::history::LocalDay::from_unix(ahora);
        let cortes = crate::history::retention::calcular(ahora, retention, sin_consolidar, hoy);
        let mut stats = purge(&mut self.conn, &cortes)?;
        stats.vacuum_pages = u64::from(incremental_vacuum(&self.conn, 2000)?);
        Ok(stats)
    }

    /// Devuelve como mucho max_pages páginas libres al sistema.
    pub fn incremental_vacuum(&mut self, max_pages: u32) -> crate::error::Result<u32> {
        incremental_vacuum(&self.conn, max_pages)
    }

    /// Borra los destinos por hora cuando destination_days = 0.
    pub fn clear_destination_hours(&mut self) -> crate::error::Result<usize> {
        clear_destination_hours(&self.conn)
    }

    /// Borra un equipo, sus rollups y sus datos lógicos (§7.17).
    ///
    /// Las relaciones sin clave ajena se borran a mano: los rollups del equipo,
    /// sus silencios y su aprendizaje. Las alertas sobreviven con
    /// `device_id = NULL` (clave ajena con ON DELETE SET NULL) y conservan su
    /// `subject_label`; el aprendizaje del propio equipo no se toca.
    pub fn delete_device(&mut self, device_id: i64) -> crate::error::Result<bool> {
        let transaccion = self.conn.transaction()?;
        delete_device_rollups(&transaccion, device_id)?;
        transaccion.execute(
            "DELETE FROM ALERT_MUTES WHERE subject = 'device' AND device_id = ?1",
            params![device_id],
        )?;
        transaccion.execute(
            "DELETE FROM ALERT_LEARNING WHERE subject = 'device' AND device_id = ?1",
            params![device_id],
        )?;
        let borrados =
            transaccion.execute("DELETE FROM DEVICES WHERE id = ?1", params![device_id])?;
        transaccion.commit()?;
        Ok(borrados > 0)
    }
}

#[cfg(test)]
fn contar(conn: &Connection, tabla: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |fila| {
        fila.get(0)
    })
    .expect("contar filas")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{LocalDay, Retention, SeenItem, SeenKind};
    use tempfile::tempdir;

    fn conexion() -> Connection {
        let mut conn = Connection::open_in_memory().expect("abrir SQLite en memoria");
        crate::repo::migrations::apply_all(&mut conn).expect("aplicar migraciones");
        conn
    }

    fn fila(subject: Subject, dimension: Dimension, key: &str, down: u64, up: u64) -> RollupRow {
        RollupRow {
            subject,
            dimension,
            key: key.to_string(),
            counter: Counter {
                down,
                up,
                connections: 1,
            },
        }
    }

    #[test]
    fn el_lote_del_minuto_suma_si_el_cubo_ya_existe() {
        let mut conn = conexion();
        let minuto = 1_800_000_000;
        let lote = RollupBatch {
            minute: minuto,
            rows: vec![
                fila(Subject::Device(1), Dimension::Total, "", 100, 10),
                fila(Subject::Device(1), Dimension::App, "youtube", 80, 5),
            ],
            seen: vec![
                SeenItem::de_equipo(1, SeenKind::App, "youtube"),
                SeenItem::del_host(SeenKind::App, "steam"),
            ],
            overflow: 0,
        };
        // El inventario exige que el equipo exista (FK a DEVICES).
        conn.execute_batch(
            "INSERT INTO INTERFACES (name, is_up, last_seen) VALUES ('eth0', 1, '2026-01-01T00:00:00Z');
             INSERT INTO DEVICES (mac, ip, interface_id, device_type, is_online, first_seen, last_seen)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 1, 'unknown', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("equipo de prueba");
        let cambio = insert_minute_batch(&mut conn, &lote).expect("primer lote");
        assert_eq!(cambio.new_items.len(), 2, "la app del equipo y la del host");
        let cambio = insert_minute_batch(&mut conn, &lote).expect("segundo lote");
        assert!(cambio.is_empty(), "repetir el lote no descubre nada nuevo");
        assert_eq!(contar(&conn, "TRAFFIC_ROLLUP_MINUTE"), 2);
        assert_eq!(
            contar(&conn, "HOST_SEEN"),
            1,
            "el inventario del host se escribe"
        );
        assert_eq!(contar(&conn, "DEVICE_SEEN"), 1);
        let (down, up): (i64, i64) = conn
            .query_row(
                "SELECT bytes_down, bytes_up FROM TRAFFIC_ROLLUP_MINUTE
                  WHERE subject = 'device' AND dimension = 'total'",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .unwrap();
        assert_eq!((down, up), (200, 20));
        let (primera, ultima): (String, String) = conn
            .query_row(
                "SELECT first_seen, last_seen FROM DEVICE_SEEN WHERE kind = 'app'",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .unwrap();
        assert_eq!(primera, ultima);
        assert!(primera.ends_with('Z'));
    }

    fn sembrar_horas(conn: &mut Connection, hora: i64) {
        let mut sentencia = conn
            .prepare(SQL_INSERTAR_MINUTO)
            .expect("preparar inserción de minutos");
        for indice in 0..60i64 {
            let bucket = hora + indice * 60;
            for clave in ["youtube", "netflix", "twitch"] {
                sentencia
                    .execute(params![bucket, "device", 1, "app", clave, 10, 5, 0])
                    .expect("insertar minuto");
            }
            sentencia
                .execute(params![bucket, "device", 1, "total", "", 30, 15, 1])
                .expect("insertar total");
        }
    }

    #[test]
    fn build_hour_agrega_y_aplica_topes() {
        let mut conn = conexion();
        let hora = 1_800_000_000;
        sembrar_horas(&mut conn, hora);
        let escritas = build_hour(&mut conn, hora, 2).expect("consolidar hora");
        // total + 2 apps + ~otros
        assert_eq!(escritas, 4);
        let total: i64 = conn
            .query_row(
                "SELECT SUM(bytes_down) FROM TRAFFIC_ROLLUP_HOUR
                  WHERE dimension = 'total'",
                [],
                |fila| fila.get(0),
            )
            .unwrap();
        assert_eq!(total, 60 * 30);
        let apps: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM TRAFFIC_ROLLUP_HOUR
                  WHERE dimension = 'app' AND key NOT LIKE '~%'",
                [],
                |fila| fila.get(0),
            )
            .unwrap();
        assert_eq!(apps, 2);
        // Rehacer la hora da el mismo resultado (idempotente).
        build_hour(&mut conn, hora, 2).expect("rehacer hora");
        assert_eq!(contar(&conn, "TRAFFIC_ROLLUP_HOUR"), 4);
    }

    #[test]
    fn las_horas_pendientes_son_las_que_tienen_minutos_sin_consolidar() {
        let mut conn = conexion();
        let hora = 1_800_000_000;
        sembrar_horas(&mut conn, hora);
        sembrar_horas(&mut conn, hora + 3600);
        let pendientes = pending_hours(&conn, hora + 3 * 3600).expect("pendientes");
        assert_eq!(pendientes, vec![hora, hora + 3600]);
        build_hour(&mut conn, hora, 20).expect("consolidar primera");
        let pendientes = pending_hours(&conn, hora + 3 * 3600).expect("pendientes");
        assert_eq!(pendientes, vec![hora + 3600]);
        // La hora en curso no se considera pendiente.
        let pendientes = pending_hours(&conn, hora + 3600).expect("pendientes");
        assert!(pendientes.is_empty());
    }

    #[test]
    fn build_day_suma_sus_horas_sin_destinos() {
        let mut conn = conexion();
        let dia = LocalDay::from_unix(1_800_000_000);
        for hora in dia.hours() {
            let mut sentencia = conn.prepare(SQL_INSERTAR_HORA).expect("preparar");
            sentencia
                .execute(params![hora, "device", 1, "total", "", 100, 10, 1])
                .expect("insertar total");
            sentencia
                .execute(params![
                    hora,
                    "device",
                    1,
                    "destination",
                    "youtube.com",
                    90,
                    9,
                    1
                ])
                .expect("insertar destino");
        }
        let escritas = build_day(&mut conn, dia, 20).expect("consolidar día");
        assert_eq!(escritas, 1);
        let destinos: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM TRAFFIC_ROLLUP_DAY WHERE dimension = 'destination'",
                [],
                |fila| fila.get(0),
            )
            .unwrap();
        assert_eq!(destinos, 0);
        let total: i64 = conn
            .query_row(
                "SELECT SUM(bytes_down) FROM TRAFFIC_ROLLUP_DAY",
                [],
                |fila| fila.get(0),
            )
            .unwrap();
        assert_eq!(total as usize, dia.hours().len() * 100);
        // Idempotente.
        build_day(&mut conn, dia, 20).expect("rehacer día");
        assert_eq!(contar(&conn, "TRAFFIC_ROLLUP_DAY"), 1);
    }

    #[test]
    fn los_dias_pendientes_son_los_que_tienen_horas_sin_consolidar() {
        let mut conn = conexion();
        let hoy = LocalDay::from_unix(1_800_000_000);
        let ayer = hoy.sumar_dias(-1);
        {
            let mut sentencia = conn.prepare(SQL_INSERTAR_HORA).expect("preparar");
            for hora in ayer.hours() {
                sentencia
                    .execute(params![hora, "device", 1, "total", "", 10, 1, 1])
                    .expect("insertar hora");
            }
        }
        let pendientes = pending_days(&conn, hoy).expect("pendientes");
        assert_eq!(pendientes, vec![ayer]);
        build_day(&mut conn, ayer, 20).expect("consolidar ayer");
        assert!(pending_days(&conn, hoy).expect("pendientes").is_empty());
        // El día en curso nunca está pendiente.
        assert!(pending_days(&conn, ayer).expect("pendientes").is_empty());
    }

    #[test]
    fn la_purga_respeta_resoluciones_y_destinos() {
        let mut conn = conexion();
        let ahora = 1_800_000_000;
        let hace_3_dias = ahora - 3 * 86_400;
        let hace_100_dias = ahora - 100 * 86_400;
        {
            let mut sentencia = conn.prepare(SQL_INSERTAR_MINUTO).expect("preparar");
            sentencia
                .execute(params![hace_3_dias, "device", 1, "total", "", 10, 1, 1])
                .expect("minuto antiguo");
            sentencia
                .execute(params![ahora - 3600, "device", 1, "total", "", 10, 1, 1])
                .expect("minuto reciente");
            sentencia
                .execute(params![
                    hace_3_dias,
                    "device",
                    1,
                    "destination",
                    "x",
                    10,
                    1,
                    1
                ])
                .expect("destino antiguo");
        }
        {
            let mut sentencia = conn.prepare(SQL_INSERTAR_HORA).expect("preparar");
            sentencia
                .execute(params![
                    hace_100_dias - (hace_100_dias % 3600),
                    "device",
                    1,
                    "total",
                    "",
                    10,
                    1,
                    1
                ])
                .expect("hora antigua");
            sentencia
                .execute(params![
                    hace_100_dias - (hace_100_dias % 3600),
                    "device",
                    1,
                    "destination",
                    "x",
                    10,
                    1,
                    1
                ])
                .expect("destino por hora antiguo");
            sentencia
                .execute(params![ahora - 3600, "device", 1, "total", "", 10, 1, 1])
                .expect("hora reciente");
        }
        let hoy = LocalDay::from_unix(ahora);
        let cortes = crate::history::retention::calcular(
            ahora,
            &Retention::default(),
            ahora - (ahora % 3600),
            hoy,
        );
        let stats = purge(&mut conn, &cortes).expect("purgar");
        assert!(stats.rollup_rows >= 3);
        // El minuto reciente y su hora siguen; el antiguo y sus destinos no.
        assert_eq!(contar(&conn, "TRAFFIC_ROLLUP_MINUTE"), 1);
        assert_eq!(contar(&conn, "TRAFFIC_ROLLUP_HOUR"), 1);
    }

    #[test]
    fn incremental_vacuum_no_falla_y_devuelve_paginas_acotadas() {
        let conn = conexion();
        let liberadas = incremental_vacuum(&conn, 2000).expect("vacuum incremental");
        assert!(liberadas <= 2000);
        // Con la base recién creada no hay páginas libres.
        assert_eq!(liberadas, 0);
    }

    #[test]
    fn borrar_los_rollups_de_un_equipo_no_toca_los_demas() {
        let conn = conexion();
        let mut sentencia = conn.prepare(SQL_INSERTAR_MINUTO).expect("preparar");
        for id in [1i64, 2] {
            sentencia
                .execute(params![1_800_000_000, "device", id, "total", "", 10, 1, 1])
                .expect("insertar total");
        }
        sentencia
            .execute(params![1_800_000_000, "network", 0, "total", "", 10, 1, 1])
            .expect("insertar red");
        let borradas = delete_device_rollups(&conn, 1).expect("borrar");
        assert_eq!(borradas, 1);
        let restantes = contar(&conn, "TRAFFIC_ROLLUP_MINUTE");
        assert_eq!(restantes, 2);
    }

    #[test]
    #[ignore]
    fn medir_lote_minuto() {
        // §8: escritura del lote del minuto con 50 equipos ≤ 10 ms.
        use crate::history::{Counter, Dimension, RollupBatch, RollupRow, Subject};
        let dir = tempfile::tempdir().expect("directorio temporal");
        let mut repo = crate::repo::Repo::init(&dir.path().join("data.db")).expect("repo");
        let mut filas = Vec::new();
        for device_id in 1..=50i64 {
            for dimension in Dimension::ALL {
                for indice in 0..20 {
                    filas.push(RollupRow {
                        subject: Subject::Device(device_id),
                        dimension,
                        key: format!("clave{dimension:?}{indice}"),
                        counter: Counter {
                            down: 1_000,
                            up: 100,
                            connections: 1,
                        },
                    });
                }
            }
        }
        let lote = RollupBatch {
            minute: 1_800_000_000,
            rows: filas,
            seen: Vec::new(),
            overflow: 0,
        };
        let escritas = lote.rows.len();
        let inicio = std::time::Instant::now();
        repo.insert_minute_batch(&lote).expect("lote");
        let transcurrido = inicio.elapsed();
        println!(
            "lote del minuto: {escritas} filas en {transcurrido:?} ({:.2} ms)",
            transcurrido.as_secs_f64() * 1000.0
        );
        assert!(
            transcurrido.as_millis() <= 10,
            "el lote del minuto debe escribirse en ≤ 10 ms (medido {transcurrido:?})"
        );
    }

    #[test]
    #[ignore]
    fn medir_purga_historial_real() {
        // §8: purga + incremental_vacuum ≤ 100 ms con la retención por defecto
        // sobre el perfil de referencia de dos años.
        use crate::history::synthetic::{Synthetic, SyntheticProfile};
        let dir = tempfile::tempdir().expect("directorio temporal");
        let mut repo = crate::repo::Repo::init(&dir.path().join("data.db")).expect("repo");
        let perfil = SyntheticProfile::default();
        let stats_generado = Synthetic::generate(repo.connection_mut(), &perfil)
            .expect("generar histórico sintético");
        let inicio = std::time::Instant::now();
        let stats = repo
            .purge_history(
                std::time::SystemTime::now(),
                &crate::history::Retention::default(),
            )
            .expect("purga");
        let transcurrido = inicio.elapsed();
        println!(
            "purga real: {} filas generadas ({stats_generado:?}) · {} filas borradas y {} páginas en {transcurrido:?} ({:.2} ms)",
            stats_generado.total_filas(),
            stats.total_filas(),
            stats.vacuum_pages,
            transcurrido.as_secs_f64() * 1000.0
        );
        assert!(
            transcurrido.as_millis() <= 100,
            "la purga con la retención por defecto debe durar ≤ 100 ms (medido {transcurrido:?})"
        );
    }

    #[test]
    #[ignore]
    fn medir_purga_vacuum() {
        // §8: purga + incremental_vacuum ≤ 100 ms por ejecución.
        let dir = tempfile::tempdir().expect("directorio temporal");
        let mut repo = crate::repo::Repo::init(&dir.path().join("data.db")).expect("repo");
        let ahora = std::time::SystemTime::now();
        let retencion = crate::history::Retention::default();
        let inicio = std::time::Instant::now();
        let stats = repo.purge_history(ahora, &retencion).expect("purga");
        let transcurrido = inicio.elapsed();
        println!(
            "purga + vacuum: {} filas y {} páginas en {transcurrido:?} ({:.2} ms)",
            stats.total_filas(),
            stats.vacuum_pages,
            transcurrido.as_secs_f64() * 1000.0
        );
        assert!(
            transcurrido.as_millis() <= 100,
            "la purga debe durar ≤ 100 ms (medido {transcurrido:?})"
        );
    }

    #[test]
    fn el_inventario_actualiza_last_seen_y_conserva_first_seen() {
        let mut conn = conexion();
        conn.execute_batch(
            "INSERT INTO INTERFACES (name, is_up, last_seen) VALUES ('eth0', 1, '2026-01-01T00:00:00Z');
             INSERT INTO DEVICES (mac, ip, interface_id, device_type, is_online, first_seen, last_seen)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 1, 'unknown', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');",
        )
        .expect("equipo");
        let items = vec![SeenItem::de_equipo(1, SeenKind::Org, "Google LLC")];
        crate::repo::seen::upsert_seen(&mut conn, &items, "2026-01-01T10:00:00Z")
            .expect("primera vez");
        crate::repo::seen::upsert_seen(&mut conn, &items, "2026-01-01T11:00:00Z")
            .expect("segunda vez");
        let (primera, ultima): (String, String) = conn
            .query_row(
                "SELECT first_seen, last_seen FROM DEVICE_SEEN",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .unwrap();
        assert_eq!(primera, "2026-01-01T10:00:00Z");
        assert_eq!(ultima, "2026-01-01T11:00:00Z");
        assert_eq!(contar(&conn, "DEVICE_SEEN"), 1);
    }

    #[test]
    fn el_dao_de_equipos_borra_sus_rollups() {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = crate::repo::Repo::init(&dir.path().join("data.db")).expect("repo");
        let id = repo
            .upsert_interface(&crate::repo::Interface::without_id(
                "eth0",
                None,
                Some("192.168.1.10".to_string()),
                None,
                None,
                true,
                "2026-01-01T00:00:00Z",
            ))
            .expect("interfaz");
        let (device_id, _) = repo
            .upsert_device(&crate::repo::DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.50".to_string(),
                hostname: None,
                vendor: None,
                interface_id: id,
                device_type: "unknown".to_string(),
            })
            .expect("equipo");
        let lote = RollupBatch {
            minute: 1_800_000_000,
            rows: vec![fila(
                Subject::Device(device_id),
                Dimension::Total,
                "",
                10,
                1,
            )],
            seen: Vec::new(),
            overflow: 0,
        };
        repo.insert_minute_batch(&lote).expect("lote");
        assert_eq!(contar(repo.connection(), "TRAFFIC_ROLLUP_MINUTE"), 1);
        // Silencios, aprendizaje y una alerta del equipo antes de borrarlo.
        repo.connection()
            .execute(
                "INSERT INTO ALERT_MUTES (rule, subject, device_id, until, created_at)
                 VALUES ('new_app', 'device', ?1, NULL, '2026-01-01T00:00:00Z')",
                params![device_id],
            )
            .expect("silencio del equipo");
        repo.connection()
            .execute(
                "INSERT INTO ALERT_LEARNING
                     (subject, device_id, learning_from, data_days, learned_at, updated_day)
                 VALUES ('device', ?1, '2026-01-01T00:00:00Z', 0, NULL, 0)",
                params![device_id],
            )
            .expect("aprendizaje del equipo");
        repo.connection()
            .execute(
                "INSERT INTO ALERTS
                     (rule, level, subject, device_id, key, title, subject_label, details,
                      created_at, last_at)
                 VALUES ('device_new', 'important', 'device', ?1, '', 'Equipo nuevo', 'nas',
                         '{}', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                params![device_id],
            )
            .expect("alerta del equipo");

        repo.delete_device(device_id).expect("borrar equipo");
        assert_eq!(contar(repo.connection(), "TRAFFIC_ROLLUP_MINUTE"), 0);
        assert_eq!(
            contar(repo.connection(), "ALERT_MUTES"),
            0,
            "sus silencios se borran con él"
        );
        assert_eq!(
            contar(repo.connection(), "ALERT_LEARNING"),
            1,
            "su aprendizaje se borra; el del propio equipo se queda"
        );
        let (device_id_alerta, etiqueta): (Option<i64>, String) = repo
            .connection()
            .query_row("SELECT device_id, subject_label FROM ALERTS", [], |fila| {
                Ok((fila.get(0)?, fila.get(1)?))
            })
            .expect("alerta superviviente");
        assert_eq!(device_id_alerta, None, "la alerta sobrevive sin device_id");
        assert_eq!(etiqueta, "nas");
    }
}
