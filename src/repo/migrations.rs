//! Migraciones versionadas del esquema SQLite.
//!
//! Cada migración es idempotente, se aplica en orden y se registra en la tabla
//! SCHEMA_MIGRATIONS. Implementado por el equipo de persistencia.

use rusqlite::{params, Connection};

use crate::error::Result;

/// Migración versionada del esquema.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Número de versión (debe ser creciente).
    pub version: u32,
    /// Nombre legible.
    pub name: &'static str,
    /// SQL idempotente (o con comprobación previa en already_applied).
    pub sql: &'static str,
    /// Comprobación opcional de que la migración ya está presente.
    ///
    /// SQLite no admite `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, así que las
    /// migraciones que añaden columnas necesitan comprobar el esquema antes de
    /// ejecutar el SQL para poder reaplicarse sin error (idempotencia real).
    pub already_applied: Option<fn(&Connection) -> rusqlite::Result<bool>>,
    /// Hook de post-procesado en Rust (rellenos de datos de la migración).
    ///
    /// Se ejecuta dentro de la misma transacción que el SQL y solo cuando la
    /// migración se aplica de verdad: en una reaplicación idempotente no se
    /// repite. Las migraciones anteriores a la v6 no lo necesitan.
    pub post: Option<MigrationPost>,
}

/// Hook de post-procesado de una migración, dentro de su transacción.
///
/// Recibe la conexión de la transacción abierta por `apply_all` (solo lectura
/// del préstamo: SQLite permite escribir con ella); no puede abrir
/// transacciones anidadas, así que los rellenos usan variantes que trabajan
/// sobre una conexión ya transaccionada (`backfill_learning_en`).
pub type MigrationPost = fn(&Connection) -> Result<()>;

/// Esquema inicial de la Fase 1 (versión 1).
///
/// Todas las sentencias usan `IF NOT EXISTS` para poder reejecutarse sin error.
/// Las tablas, columnas y claves foráneas siguen la definición del informe de
/// Fase 1 (sección 3, «Definición de tablas»).
const SQL_ESQUEMA_INICIAL: &str = "\
CREATE TABLE IF NOT EXISTS INTERFACES (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    mac TEXT,
    ipv4 TEXT,
    netmask TEXT,
    gateway TEXT,
    is_up INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS DEVICES (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    hostname TEXT,
    vendor TEXT,
    interface_id INTEGER NOT NULL REFERENCES INTERFACES(id),
    device_type TEXT NOT NULL DEFAULT 'unknown',
    is_online INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    alias TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS DEVICE_EVENTS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES DEVICES(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_is_online ON DEVICES(is_online);
CREATE INDEX IF NOT EXISTS idx_device_events_created_at ON DEVICE_EVENTS(created_at);
CREATE INDEX IF NOT EXISTS idx_device_events_device_created_at
    ON DEVICE_EVENTS(device_id, created_at);
";

/// Esquema de la Fase 2 (versión 2): columnas nuevas de DEVICES y tablas de
/// servicios y fuentes de descubrimiento. Es una migración aditiva: no borra ni
/// renombra nada de la Fase 1.
const SQL_ESQUEMA_FASE_2: &str = "\
ALTER TABLE DEVICES ADD COLUMN os_family TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN device_type_manual TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN last_fingerprint TEXT NULL;

CREATE TABLE IF NOT EXISTS DEVICE_SERVICES (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES DEVICES(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service TEXT NULL,
    banner TEXT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (device_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS DISCOVERY_SOURCES (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES DEVICES(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (device_id, source)
);

CREATE INDEX IF NOT EXISTS IDX_SERVICES_DEVICE ON DEVICE_SERVICES(device_id);
CREATE INDEX IF NOT EXISTS IDX_SOURCES_DEVICE ON DISCOVERY_SOURCES(device_id);
";

/// Esquema de la Fase 3 (versión 3): tablas de tráfico en vivo.
///
/// `TRAFFIC_SNAPSHOT` guarda el último valor por dispositivo (se sobrescribe
/// cada 5 s; no es histórico) y `CONNECTIONS` es la tabla caliente de
/// conexiones, que se purga por timeout. Es una migración aditiva: no borra ni
/// renombra nada de F1/F2.
const SQL_ESQUEMA_FASE_3: &str = "\
CREATE TABLE IF NOT EXISTS TRAFFIC_SNAPSHOT (
    device_id   INTEGER PRIMARY KEY REFERENCES DEVICES(id) ON DELETE CASCADE,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    packets_in  INTEGER NOT NULL DEFAULT 0,
    packets_out INTEGER NOT NULL DEFAULT 0,
    peak_bps    INTEGER NOT NULL DEFAULT 0,
    window_s    INTEGER NOT NULL DEFAULT 60,
    updated_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS CONNECTIONS (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NULL REFERENCES DEVICES(id) ON DELETE SET NULL,
    protocol    TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    src_port    INTEGER NULL,
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER NULL,
    state       TEXT NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    first_seen  TIMESTAMP NOT NULL,
    last_seen   TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS IDX_CONN_DEVICE    ON CONNECTIONS(device_id);
CREATE INDEX IF NOT EXISTS IDX_CONN_LAST_SEEN ON CONNECTIONS(last_seen);
CREATE INDEX IF NOT EXISTS IDX_CONN_STATE     ON CONNECTIONS(state);
";

/// Esquema de la Fase 4 (versión 4): protocolos, etiquetas y caché de nombres.
///
/// Migración aditiva: añade ocho columnas a CONNECTIONS (rol, etiquetas y JA4),
/// seis a DEVICES (identidad) y crea la tabla caliente NAME_CACHE con sus
/// índices. Los valores enumerados se guardan como TEXT y se validan en código;
/// SQLite no lleva CHECK (§3). El SQL es exactamente el de la especificación.
const SQL_ESQUEMA_FASE_4: &str = "\
-- v4 — Fase 4: protocolos, apps y top talkers

ALTER TABLE CONNECTIONS ADD COLUMN client_is_src BOOLEAN NULL;
ALTER TABLE CONNECTIONS ADD COLUMN app_protocol  TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN server_name   TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN name_source   TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN app           TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN category      TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN app_source    TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN ja4           TEXT NULL;

ALTER TABLE DEVICES ADD COLUMN model            TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN dhcp_fingerprint TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN dhcp_vendor      TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN dhcp_hostname    TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN user_agent       TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN os_source        TEXT NULL;

CREATE TABLE NAME_CACHE (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ip          TEXT NOT NULL,
  name        TEXT NOT NULL,
  source      TEXT NOT NULL,          -- 'dns' | 'sni' | 'http'
  first_seen  TIMESTAMP NOT NULL,
  last_seen   TIMESTAMP NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  UNIQUE (ip, name)
);

CREATE INDEX IDX_NAME_CACHE_IP      ON NAME_CACHE(ip);
CREATE INDEX IDX_NAME_CACHE_EXPIRES ON NAME_CACHE(expires_at);
CREATE INDEX IDX_CONN_APP           ON CONNECTIONS(app);
";

/// Esquema de la Fase 5 (versión 5): histórico, rollups y eventos.
///
/// Migración aditiva: crea las tres resoluciones del histórico (WITHOUT ROWID,
/// con la clave primaria empezando por bucket), el inventario por equipo y las
/// sesiones de Almenara. DEVICE_EVENTS no cambia de esquema (sus tipos nuevos se
/// validan en código). El PRAGMA auto_vacuum = INCREMENTAL y su VACUUM se
/// aplican en apply_all, fuera de la transacción de la migración y una sola vez.
const SQL_ESQUEMA_FASE_5: &str = "\
-- v5 — Fase 5: histórico, rollups y eventos

CREATE TABLE TRAFFIC_ROLLUP_MINUTE (
    bucket      INTEGER NOT NULL,
    subject     TEXT    NOT NULL,
    device_id   INTEGER NOT NULL DEFAULT 0,
    dimension   TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, subject, device_id, dimension, key)
) WITHOUT ROWID;

CREATE TABLE TRAFFIC_ROLLUP_HOUR (
    bucket      INTEGER NOT NULL,
    subject     TEXT    NOT NULL,
    device_id   INTEGER NOT NULL DEFAULT 0,
    dimension   TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, subject, device_id, dimension, key)
) WITHOUT ROWID;

CREATE TABLE TRAFFIC_ROLLUP_DAY (
    bucket      INTEGER NOT NULL,
    subject     TEXT    NOT NULL,
    device_id   INTEGER NOT NULL DEFAULT 0,
    dimension   TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, subject, device_id, dimension, key)
) WITHOUT ROWID;

CREATE TABLE DEVICE_SEEN (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES DEVICES(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    key         TEXT NOT NULL,
    first_seen  TIMESTAMP NOT NULL,
    last_seen   TIMESTAMP NOT NULL,
    UNIQUE (device_id, kind, key)
);

CREATE INDEX IDX_SEEN_LAST_SEEN ON DEVICE_SEEN(last_seen);

CREATE TABLE APP_SESSIONS (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TIMESTAMP NOT NULL,
    ended_at     TIMESTAMP NULL,
    last_beat    TIMESTAMP NOT NULL,
    end_reason   TEXT NULL,
    mode         TEXT NOT NULL,
    capture      BOOLEAN NOT NULL,
    passive_only BOOLEAN NOT NULL,
    version      TEXT NOT NULL
);

CREATE INDEX IDX_APP_SESSIONS_ENDED ON APP_SESSIONS(ended_at);
";

/// Esquema de la Fase 6 (versión 6): alertas, inventario del propio equipo,
/// huecos de cobertura y equipos vigilados (§3).
///
/// Migración aditiva: crea ALERTS, ALERT_MUTES, ALERT_LEARNING, HOST_SEEN y
/// COVERAGE_GAPS con sus índices y añade DEVICES.watched y
/// DEVICE_SERVICES.closed_at. Los rellenos (closed_at desde el último evento de
/// servicio y aprendizaje inicial desde el histórico de F5) van en el hook
/// v6_post, dentro de la misma transacción. Sin CHECK en las enumeraciones:
/// rule, level, subject y kind se validan en el código.
const SQL_ESQUEMA_FASE_6: &str = "\
-- v6 — Fase 6: alertas

CREATE TABLE IF NOT EXISTS ALERTS (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  rule           TEXT NOT NULL,
  level          TEXT NOT NULL,
  subject        TEXT NOT NULL,
  device_id      INTEGER NULL REFERENCES DEVICES(id) ON DELETE SET NULL,
  key            TEXT NOT NULL DEFAULT '',
  title          TEXT NOT NULL,
  subject_label  TEXT NOT NULL,
  details        TEXT NOT NULL DEFAULT '{}',
  event_id       INTEGER NULL,
  summary_id     INTEGER NULL,
  created_at     TIMESTAMP NOT NULL,
  last_at        TIMESTAMP NOT NULL,
  count          INTEGER NOT NULL DEFAULT 1,
  seen_at        TIMESTAMP NULL,
  resolved_at    TIMESTAMP NULL,
  notified       BOOLEAN NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS IDX_ALERTS_LAST_AT ON ALERTS(last_at);
CREATE INDEX IF NOT EXISTS IDX_ALERTS_DEVICE ON ALERTS(device_id, last_at);
CREATE INDEX IF NOT EXISTS IDX_ALERTS_UNSEEN ON ALERTS(level) WHERE seen_at IS NULL;

CREATE TABLE IF NOT EXISTS ALERT_MUTES (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  rule        TEXT NOT NULL,
  subject     TEXT NOT NULL,
  device_id   INTEGER NOT NULL DEFAULT 0,
  until       TIMESTAMP NULL,
  created_at  TIMESTAMP NOT NULL,
  UNIQUE (rule, subject, device_id)
);

CREATE TABLE IF NOT EXISTS ALERT_LEARNING (
  subject        TEXT NOT NULL,
  device_id      INTEGER NOT NULL DEFAULT 0,
  learning_from  TIMESTAMP NOT NULL,
  data_days      INTEGER NOT NULL DEFAULT 0,
  learned_at     TIMESTAMP NULL,
  updated_day    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (subject, device_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS HOST_SEEN (
  kind        TEXT NOT NULL,
  key         TEXT NOT NULL,
  first_seen  TIMESTAMP NOT NULL,
  last_seen   TIMESTAMP NOT NULL,
  PRIMARY KEY (kind, key)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS IDX_HOST_SEEN_LAST_SEEN ON HOST_SEEN(last_seen);

CREATE TABLE IF NOT EXISTS COVERAGE_GAPS (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id  INTEGER NOT NULL REFERENCES APP_SESSIONS(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  started_at  TIMESTAMP NOT NULL,
  ended_at    TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS IDX_GAPS_SESSION ON COVERAGE_GAPS(session_id);
CREATE INDEX IF NOT EXISTS IDX_GAPS_STARTED ON COVERAGE_GAPS(started_at);

ALTER TABLE DEVICES ADD COLUMN watched BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE DEVICE_SERVICES ADD COLUMN closed_at TIMESTAMP NULL;
";

/// Lista ordenada de migraciones.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "esquema_inicial",
        sql: SQL_ESQUEMA_INICIAL,
        already_applied: None,
        post: None,
    },
    Migration {
        version: 2,
        name: "descubrimiento_avanzado",
        sql: SQL_ESQUEMA_FASE_2,
        already_applied: Some(v2_ya_aplicada),
        post: None,
    },
    Migration {
        version: 3,
        name: "trafico_en_vivo",
        sql: SQL_ESQUEMA_FASE_3,
        already_applied: Some(v3_ya_aplicada),
        post: None,
    },
    Migration {
        version: 4,
        name: "protocolos_y_etiquetas",
        sql: SQL_ESQUEMA_FASE_4,
        already_applied: Some(v4_ya_aplicada),
        post: None,
    },
    Migration {
        version: 5,
        name: "historico_y_rollups",
        sql: SQL_ESQUEMA_FASE_5,
        already_applied: Some(v5_ya_aplicada),
        post: None,
    },
    Migration {
        version: 6,
        name: "alertas",
        sql: SQL_ESQUEMA_FASE_6,
        already_applied: Some(v6_ya_aplicada),
        post: Some(v6_post),
    },
];

/// Comprueba si la migración v2 ya está presente (columna os_family de DEVICES).
fn v2_ya_aplicada(conn: &Connection) -> rusqlite::Result<bool> {
    let mut sentencia = conn.prepare("SELECT name FROM pragma_table_info('DEVICES')")?;
    let columnas = sentencia.query_map([], |fila| fila.get::<_, String>(0))?;
    for columna in columnas {
        if columna? == "os_family" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Comprueba si la migración v3 ya está presente (tabla TRAFFIC_SNAPSHOT).
///
/// La tabla es la primera que crea la migración, así que su existencia en
/// sqlite_master basta para saber que el bloque se aplicó; permite reaplicar la
/// migración sin error aunque se haya perdido su fila de SCHEMA_MIGRATIONS.
fn v3_ya_aplicada(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'TRAFFIC_SNAPSHOT'
         )",
        [],
        |fila| fila.get(0),
    )
}

/// Comprueba si la migración v4 ya está presente.
///
/// SQLite no admite `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, así que hay que
/// mirar el esquema antes de reejecutar el bloque. Basta con que exista la tabla
/// NAME_CACHE o la columna DEVICES.model: apply_all ejecuta la migración entera
/// en una transacción, de modo que no puede quedar aplicada a medias.
fn v4_ya_aplicada(conn: &Connection) -> rusqlite::Result<bool> {
    let tabla: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'NAME_CACHE'
         )",
        [],
        |fila| fila.get(0),
    )?;
    if tabla {
        return Ok(true);
    }

    let mut sentencia = conn.prepare("SELECT name FROM pragma_table_info('DEVICES')")?;
    let columnas = sentencia.query_map([], |fila| fila.get::<_, String>(0))?;
    for columna in columnas {
        if columna? == "model" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Comprueba si la migración v5 ya está presente.
///
/// La primera tabla de la migración es TRAFFIC_ROLLUP_MINUTE: si existe, el
/// bloque se aplicó entero (apply_all lo ejecuta en una transacción).
fn v5_ya_aplicada(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'TRAFFIC_ROLLUP_MINUTE'
         )",
        [],
        |fila| fila.get(0),
    )
}

/// Comprueba si la migración v6 ya está presente.
///
/// La primera tabla de la migración es ALERTS: si existe, el bloque se aplicó
/// entero y su hook de relleno ya corrió (apply_all lo ejecuta en una
/// transacción). Se usa también para las reaplicaciones idempotentes.
fn v6_ya_aplicada(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'ALERTS'
         )",
        [],
        |fila| fila.get(0),
    )
}

/// Rellenos de la migración v6 dentro de su transacción (§7.3 y §7.12).
///
/// Fija DEVICE_SERVICES.closed_at para los puertos cuyo último evento de
/// servicio es un service_gone y crea el aprendizaje inicial de los equipos
/// existentes desde el histórico de F5, más la fila del propio equipo con
/// learning_from igual a la fecha de la migración y sin días contados.
fn v6_post(conn: &Connection) -> Result<()> {
    let cerrados = crate::repo::device_services::backfill_closed_at(conn)?;
    let aprendizajes = crate::repo::learning::backfill_learning_en(
        conn,
        std::time::SystemTime::now(),
        &crate::alerts::LearningParams::default(),
    )?;
    tracing::debug!(
        cerrados,
        aprendizajes,
        "relleno de la migración v6 (closed_at y aprendizaje inicial)"
    );
    Ok(())
}

/// Tabla interna que registra las migraciones ya aplicadas.
const SQL_CREAR_SCHEMA_MIGRATIONS: &str = "\
CREATE TABLE IF NOT EXISTS SCHEMA_MIGRATIONS (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);";

/// Aplica todas las migraciones pendientes y devuelve la versión final.
///
/// Es idempotente: las migraciones ya registradas se saltan y cada migración
/// pendiente se aplica dentro de una transacción junto con su registro en
/// SCHEMA_MIGRATIONS, de modo que nunca queda una migración a medias.
pub fn apply_all(conn: &mut Connection) -> Result<u32> {
    conn.execute_batch(SQL_CREAR_SCHEMA_MIGRATIONS)?;

    let mut version = current_version(conn)?;
    let mut pendientes: Vec<Migration> = MIGRATIONS
        .iter()
        .copied()
        .filter(|migracion| migracion.version > version)
        .collect();
    pendientes.sort_by_key(|migracion| migracion.version);

    for migracion in pendientes {
        tracing::debug!(
            version = migracion.version,
            nombre = migracion.name,
            "aplicando migración de esquema"
        );
        let transaccion = conn.transaction()?;
        let ya_presente = match migracion.already_applied {
            Some(comprobar) => comprobar(&transaccion)?,
            None => false,
        };
        if !ya_presente {
            transaccion.execute_batch(migracion.sql)?;
            if let Some(post) = migracion.post {
                post(&transaccion)?;
            }
        }
        transaccion.execute(
            "INSERT OR IGNORE INTO SCHEMA_MIGRATIONS (version, applied_at) VALUES (?1, ?2)",
            params![migracion.version, super::ahora_rfc3339()],
        )?;
        transaccion.commit()?;
        version = migracion.version;
    }

    // auto_vacuum = INCREMENTAL se aplica una sola vez, fuera de la transacción
    // de la migración (VACUUM no puede ir dentro). Con una base ya en v5 y el
    // modo activo no se repite el VACUUM en cada arranque (AC del checklist).
    if version >= 5 {
        let modo: i64 = conn.query_row("PRAGMA auto_vacuum", [], |fila| fila.get(0))?;
        if modo != 2 {
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
            tracing::debug!("auto_vacuum incremental activado con VACUUM");
        }
    }

    Ok(version)
}

/// Devuelve la versión actual del esquema (0 si no hay ninguna aplicada).
pub fn current_version(conn: &Connection) -> Result<u32> {
    let existe: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'SCHEMA_MIGRATIONS'
         )",
        [],
        |fila| fila.get(0),
    )?;
    if !existe {
        return Ok(0);
    }

    let version: u32 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM SCHEMA_MIGRATIONS",
        [],
        |fila| fila.get(0),
    )?;
    Ok(version)
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use super::*;

    /// Conexión SQLite en memoria vacía (sin la tabla SCHEMA_MIGRATIONS).
    fn conexion_vacia() -> Connection {
        Connection::open_in_memory().expect("abrir SQLite en memoria")
    }

    /// Nombres de los objetos (tabla, índice...) del esquema, sin los internos.
    fn objetos(conn: &Connection, tipo: &str) -> Vec<String> {
        let mut sentencia = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = ?1 AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("preparar consulta de sqlite_master");
        sentencia
            .query_map([tipo], |fila| fila.get(0))
            .expect("consultar sqlite_master")
            .collect::<rusqlite::Result<Vec<String>>>()
            .expect("leer nombres del esquema")
    }

    /// Nombres de las columnas de una tabla, en el orden de definición.
    fn columnas(conn: &Connection, tabla: &str) -> Vec<String> {
        let mut sentencia = conn
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .expect("preparar consulta de columnas");
        sentencia
            .query_map([tabla], |fila| fila.get(0))
            .expect("consultar columnas")
            .collect::<rusqlite::Result<Vec<String>>>()
            .expect("leer columnas")
    }

    #[test]
    fn version_cero_sin_tabla_de_migraciones() {
        let conn = conexion_vacia();
        assert_eq!(current_version(&conn).expect("leer versión inicial"), 0);
    }

    #[test]
    fn apply_all_es_idempotente_y_llega_a_la_ultima_version() {
        let mut conn = conexion_vacia();

        let primera = apply_all(&mut conn).expect("aplicar migraciones");
        assert_eq!(primera, 6);
        assert_eq!(current_version(&conn).expect("leer versión"), 6);

        // Una segunda aplicación no debe duplicar registros ni fallar.
        let segunda = apply_all(&mut conn).expect("reaplicar migraciones");
        assert_eq!(segunda, 6);

        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones aplicadas");
        assert_eq!(registros, 6);

        let (version, aplicada): (u32, String) = conn
            .query_row(
                "SELECT version, applied_at FROM SCHEMA_MIGRATIONS WHERE version = 6",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer registro de migración v6");
        assert_eq!(version, 6);
        chrono::DateTime::parse_from_rfc3339(&aplicada)
            .expect("applied_at debe ser RFC 3339 en UTC");
        assert!(aplicada.ends_with('Z'), "applied_at debe estar en UTC");
    }

    #[test]
    fn la_migracion_v2_es_idempotente_aunque_se_borre_su_registro() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        // Simula una base con el esquema v2 pero sin los registros de las
        // migraciones 2, 3 y 4: el SQL de v2 no debe reejecutarse (ALTER TABLE
        // fallaría) y los de v3 y v4 se saltan por already_applied.
        conn.execute("DELETE FROM SCHEMA_MIGRATIONS WHERE version >= 2", [])
            .expect("borrar registros de v2, v3 y v4");
        assert_eq!(current_version(&conn).expect("leer versión"), 1);

        let version = apply_all(&mut conn).expect("reaplicar migraciones v2, v3 y v4");
        assert_eq!(version, 6);
        assert_eq!(current_version(&conn).expect("leer versión"), 6);
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 6, "los seis registros deben quedar anotados");
    }

    #[test]
    fn migracion_v2_conserva_datos_de_una_bd_de_fase_1() {
        let mut conn = conexion_vacia();

        // Base de datos de Fase 1: esquema v1 y un equipo con datos.
        conn.execute_batch(SQL_CREAR_SCHEMA_MIGRATIONS)
            .expect("crear SCHEMA_MIGRATIONS");
        conn.execute_batch(SQL_ESQUEMA_INICIAL)
            .expect("aplicar esquema v1");
        conn.execute(
            "INSERT INTO SCHEMA_MIGRATIONS (version, applied_at) VALUES (1, ?1)",
            params!["2026-11-10T10:00:00Z"],
        )
        .expect("registrar v1");
        conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '192.168.1.10', '255.255.255.0', '192.168.1.1', 1, '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar interfaz de F1");
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, hostname, vendor, interface_id, device_type, is_online, first_seen, last_seen)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 'portatil', 'Apple', 1, 'unknown', 1,
                     '2026-11-10T10:00:00Z', '2026-11-10T10:05:00Z')",
            [],
        )
        .expect("insertar equipo de F1");

        let version = apply_all(&mut conn).expect("migrar F1 hasta la última versión");
        assert_eq!(version, 6);

        // Los datos de F1 siguen ahí y las columnas nuevas son NULL.
        let (mac, hostname, os_family, manual, model, os_source): (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT mac, hostname, os_family, device_type_manual, model, os_source
                 FROM DEVICES",
                [],
                |fila| {
                    Ok((
                        fila.get(0)?,
                        fila.get(1)?,
                        fila.get(2)?,
                        fila.get(3)?,
                        fila.get(4)?,
                        fila.get(5)?,
                    ))
                },
            )
            .expect("leer equipo migrado");
        assert_eq!(mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(hostname.as_deref(), Some("portatil"));
        assert_eq!(os_family, None);
        assert_eq!(manual, None);
        assert_eq!(model, None, "DEVICES.model nace NULL en F1");
        assert_eq!(os_source, None, "DEVICES.os_source nace NULL en F1");
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM DEVICES", [], |fila| fila
                .get::<_, i64>(0))
                .expect("contar equipos"),
            1
        );

        // Las tablas nuevas existen y aceptan filas con FK.
        conn.execute(
            "INSERT INTO DEVICE_SERVICES (device_id, port, protocol, service, first_seen, last_seen)
             VALUES (1, 22, 'tcp', 'ssh', '2026-11-10T10:10:00Z', '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar servicio");
        conn.execute(
            "INSERT INTO DISCOVERY_SOURCES (device_id, source, last_seen)
             VALUES (1, 'arp', '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar fuente");
    }

    #[test]
    fn las_migraciones_estan_ordenadas_y_son_validas() {
        assert_eq!(MIGRATIONS.len(), 6);
        for (indice, migracion) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migracion.version, indice as u32 + 1);
            assert!(!migracion.sql.trim().is_empty());
        }
        assert_eq!(MIGRATIONS[0].name, "esquema_inicial");
        assert_eq!(MIGRATIONS[1].name, "descubrimiento_avanzado");
        assert_eq!(MIGRATIONS[2].name, "trafico_en_vivo");
        assert_eq!(MIGRATIONS[3].name, "protocolos_y_etiquetas");
        assert_eq!(MIGRATIONS[4].name, "historico_y_rollups");
        assert_eq!(MIGRATIONS[5].name, "alertas");
        assert!(MIGRATIONS[0].already_applied.is_none());
        assert!(MIGRATIONS[1].already_applied.is_some());
        assert!(MIGRATIONS[2].already_applied.is_some());
        assert!(MIGRATIONS[3].already_applied.is_some());
        assert!(MIGRATIONS[4].already_applied.is_some());
        assert!(MIGRATIONS[5].already_applied.is_some());
        assert!(MIGRATIONS[0].post.is_none());
        assert!(MIGRATIONS[1].post.is_none());
        assert!(MIGRATIONS[2].post.is_none());
        assert!(MIGRATIONS[3].post.is_none());
        assert!(MIGRATIONS[4].post.is_none());
        assert!(
            MIGRATIONS[5].post.is_some(),
            "la v6 rellena closed_at y el aprendizaje inicial en su hook"
        );
    }

    /// Acciones ON DELETE declaradas en las claves foráneas de una tabla.
    ///
    /// Devuelve tuplas (tabla referenciada, columna, acción ON DELETE); el orden
    /// de las columnas de pragma_foreign_key_list es id, seq, table, from, to,
    /// on_update, on_delete, match.
    fn claves_foraneas(conn: &Connection, tabla: &str) -> Vec<(String, String, String)> {
        let mut sentencia = conn
            .prepare("SELECT * FROM pragma_foreign_key_list(?1)")
            .expect("preparar consulta de claves foráneas");
        sentencia
            .query_map([tabla], |fila| {
                Ok((fila.get(2)?, fila.get(3)?, fila.get(6)?))
            })
            .expect("consultar claves foráneas")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("leer claves foráneas")
    }

    #[test]
    fn las_migraciones_crean_tablas_columnas_e_indices() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        let tablas = objetos(&conn, "table");
        for esperada in [
            "CONNECTIONS",
            "DEVICES",
            "DEVICE_EVENTS",
            "DEVICE_SERVICES",
            "DISCOVERY_SOURCES",
            "INTERFACES",
            "NAME_CACHE",
            "SCHEMA_MIGRATIONS",
            "TRAFFIC_SNAPSHOT",
            "TRAFFIC_ROLLUP_MINUTE",
            "TRAFFIC_ROLLUP_HOUR",
            "TRAFFIC_ROLLUP_DAY",
            "DEVICE_SEEN",
            "APP_SESSIONS",
            "ALERTS",
            "ALERT_MUTES",
            "ALERT_LEARNING",
            "HOST_SEEN",
            "COVERAGE_GAPS",
        ] {
            assert!(
                tablas.contains(&esperada.to_string()),
                "falta la tabla {esperada}"
            );
        }
        assert_eq!(
            tablas.len(),
            19,
            "el esquema completo debe tener diecinueve tablas: {tablas:?}"
        );

        let indices = objetos(&conn, "index");
        for esperado in [
            "idx_devices_is_online",
            "idx_device_events_created_at",
            "idx_device_events_device_created_at",
            "IDX_SERVICES_DEVICE",
            "IDX_SOURCES_DEVICE",
            "IDX_CONN_DEVICE",
            "IDX_CONN_LAST_SEEN",
            "IDX_CONN_STATE",
            "IDX_CONN_APP",
            "IDX_NAME_CACHE_IP",
            "IDX_NAME_CACHE_EXPIRES",
            "IDX_SEEN_LAST_SEEN",
            "IDX_APP_SESSIONS_ENDED",
            "IDX_ALERTS_LAST_AT",
            "IDX_ALERTS_DEVICE",
            "IDX_ALERTS_UNSEEN",
            "IDX_HOST_SEEN_LAST_SEEN",
            "IDX_GAPS_SESSION",
            "IDX_GAPS_STARTED",
        ] {
            assert!(
                indices.contains(&esperado.to_string()),
                "falta el índice {esperado}"
            );
        }

        assert_eq!(
            columnas(&conn, "INTERFACES"),
            vec![
                "id",
                "name",
                "mac",
                "ipv4",
                "netmask",
                "gateway",
                "is_up",
                "last_seen"
            ]
        );
        assert_eq!(
            columnas(&conn, "DEVICES"),
            vec![
                "id",
                "mac",
                "ip",
                "hostname",
                "vendor",
                "interface_id",
                "device_type",
                "is_online",
                "first_seen",
                "last_seen",
                "alias",
                "notes",
                "os_family",
                "device_type_manual",
                "last_fingerprint",
                "model",
                "dhcp_fingerprint",
                "dhcp_vendor",
                "dhcp_hostname",
                "user_agent",
                "os_source",
                "watched"
            ]
        );
        assert_eq!(
            columnas(&conn, "DEVICE_EVENTS"),
            vec!["id", "device_id", "event_type", "details", "created_at"]
        );
        assert_eq!(
            columnas(&conn, "DEVICE_SERVICES"),
            vec![
                "id",
                "device_id",
                "port",
                "protocol",
                "service",
                "banner",
                "first_seen",
                "last_seen",
                "closed_at"
            ]
        );
        assert_eq!(
            columnas(&conn, "DISCOVERY_SOURCES"),
            vec!["id", "device_id", "source", "last_seen"]
        );
        assert_eq!(
            columnas(&conn, "TRAFFIC_SNAPSHOT"),
            vec![
                "device_id",
                "bytes_in",
                "bytes_out",
                "packets_in",
                "packets_out",
                "peak_bps",
                "window_s",
                "updated_at"
            ]
        );
        assert_eq!(
            columnas(&conn, "CONNECTIONS"),
            vec![
                "id",
                "device_id",
                "protocol",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "state",
                "bytes_in",
                "bytes_out",
                "first_seen",
                "last_seen",
                "client_is_src",
                "app_protocol",
                "server_name",
                "name_source",
                "app",
                "category",
                "app_source",
                "ja4"
            ]
        );
        assert_eq!(
            columnas(&conn, "NAME_CACHE"),
            vec![
                "id",
                "ip",
                "name",
                "source",
                "first_seen",
                "last_seen",
                "expires_at"
            ]
        );
        for tabla in [
            "TRAFFIC_ROLLUP_MINUTE",
            "TRAFFIC_ROLLUP_HOUR",
            "TRAFFIC_ROLLUP_DAY",
        ] {
            assert_eq!(
                columnas(&conn, tabla),
                vec![
                    "bucket",
                    "subject",
                    "device_id",
                    "dimension",
                    "key",
                    "bytes_down",
                    "bytes_up",
                    "connections"
                ],
                "columnas de {tabla}"
            );
        }
        assert_eq!(
            columnas(&conn, "DEVICE_SEEN"),
            vec!["id", "device_id", "kind", "key", "first_seen", "last_seen"]
        );
        assert_eq!(
            columnas(&conn, "APP_SESSIONS"),
            vec![
                "id",
                "started_at",
                "ended_at",
                "last_beat",
                "end_reason",
                "mode",
                "capture",
                "passive_only",
                "version"
            ]
        );
        assert_eq!(
            columnas(&conn, "ALERTS"),
            vec![
                "id",
                "rule",
                "level",
                "subject",
                "device_id",
                "key",
                "title",
                "subject_label",
                "details",
                "event_id",
                "summary_id",
                "created_at",
                "last_at",
                "count",
                "seen_at",
                "resolved_at",
                "notified"
            ]
        );
        assert_eq!(
            columnas(&conn, "ALERT_MUTES"),
            vec!["id", "rule", "subject", "device_id", "until", "created_at"]
        );
        assert_eq!(
            columnas(&conn, "ALERT_LEARNING"),
            vec![
                "subject",
                "device_id",
                "learning_from",
                "data_days",
                "learned_at",
                "updated_day"
            ]
        );
        assert_eq!(
            columnas(&conn, "HOST_SEEN"),
            vec!["kind", "key", "first_seen", "last_seen"]
        );
        assert_eq!(
            columnas(&conn, "COVERAGE_GAPS"),
            vec!["id", "session_id", "kind", "started_at", "ended_at"]
        );
    }

    #[test]
    fn la_migracion_v3_es_idempotente_aunque_se_borre_su_registro() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        // Con las tablas v3 (y v4) ya creadas pero sin sus registros, la
        // comprobación already_applied debe evitar reejecutar los ALTER TABLE y
        // volver a anotar las versiones. Se borran v3 y v4 porque la versión
        // actual se lee como MAX(version): con solo borrar v3, apply_all seguiría
        // viendo la base en v4.
        conn.execute("DELETE FROM SCHEMA_MIGRATIONS WHERE version >= 3", [])
            .expect("borrar registros de v3 y v4");
        assert_eq!(current_version(&conn).expect("leer versión"), 2);

        let version = apply_all(&mut conn).expect("reaplicar migraciones v3 y v4");
        assert_eq!(version, 6);
        assert_eq!(current_version(&conn).expect("leer versión"), 6);
        assert!(objetos(&conn, "table").contains(&"TRAFFIC_SNAPSHOT".to_string()));
        assert!(objetos(&conn, "table").contains(&"NAME_CACHE".to_string()));
    }

    #[test]
    fn migracion_v3_conserva_datos_de_una_bd_de_fase_2() {
        let mut conn = conexion_vacia();

        // Base de datos de Fase 2: esquema v1+v2 registrado y datos de F1/F2.
        conn.execute_batch(SQL_CREAR_SCHEMA_MIGRATIONS)
            .expect("crear SCHEMA_MIGRATIONS");
        conn.execute_batch(SQL_ESQUEMA_INICIAL)
            .expect("aplicar esquema v1");
        conn.execute_batch(SQL_ESQUEMA_FASE_2)
            .expect("aplicar esquema v2");
        conn.execute(
            "INSERT INTO SCHEMA_MIGRATIONS (version, applied_at) VALUES (1, ?1), (2, ?1)",
            params!["2026-11-10T10:00:00Z"],
        )
        .expect("registrar v1 y v2");
        assert_eq!(current_version(&conn).expect("leer versión"), 2);

        conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '192.168.1.10', '255.255.255.0', '192.168.1.1', 1,
                     '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar interfaz de F1");
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, hostname, vendor, interface_id, device_type, is_online,
                                  first_seen, last_seen, alias, notes, os_family,
                                  device_type_manual, last_fingerprint)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 'portatil', 'Apple', 1, 'pc', 1,
                     '2026-11-10T10:00:00Z', '2026-11-10T10:05:00Z', 'mi portatil', 'no tocar',
                     'darwin', 'pc', '{\"ttl\":64}')",
            [],
        )
        .expect("insertar equipo con datos de F1/F2");
        conn.execute(
            "INSERT INTO DEVICE_SERVICES (device_id, port, protocol, service, banner, first_seen, last_seen)
             VALUES (1, 22, 'tcp', 'ssh', 'SSH-2.0-OpenSSH_9.6', '2026-11-10T10:10:00Z',
                     '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar servicio de F2");
        conn.execute(
            "INSERT INTO DISCOVERY_SOURCES (device_id, source, last_seen)
             VALUES (1, 'arp', '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar fuente de F2");

        // Migración aditiva hasta la última versión: los datos anteriores se
        // conservan.
        let version = apply_all(&mut conn).expect("migrar F2 a la última versión");
        assert_eq!(version, 6);

        let (ip, alias, os_family): (String, Option<String>, Option<String>) = conn
            .query_row("SELECT ip, alias, os_family FROM DEVICES", [], |fila| {
                Ok((fila.get(0)?, fila.get(1)?, fila.get(2)?))
            })
            .expect("leer equipo migrado");
        assert_eq!(ip, "192.168.1.50");
        assert_eq!(alias.as_deref(), Some("mi portatil"));
        assert_eq!(os_family.as_deref(), Some("darwin"));
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM DEVICE_SERVICES", [], |fila| fila
                .get::<_, i64>(0))
                .expect("contar servicios"),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM DISCOVERY_SOURCES", [], |fila| fila
                .get::<_, i64>(0))
                .expect("contar fuentes"),
            1
        );

        // Las tablas nuevas existen y aceptan filas con FK al equipo migrado.
        conn.execute(
            "INSERT INTO TRAFFIC_SNAPSHOT (device_id, updated_at)
             VALUES (1, '2026-11-10T10:15:00Z')",
            [],
        )
        .expect("insertar snapshot");
        conn.execute(
            "INSERT INTO CONNECTIONS (device_id, protocol, src_ip, src_port, dst_ip, dst_port,
                                      state, first_seen, last_seen)
             VALUES (1, 'tcp', '192.168.1.50', 40000, '93.184.216.34', 443, 'ESTABLISHED',
                     '2026-11-10T10:15:00Z', '2026-11-10T10:15:00Z')",
            [],
        )
        .expect("insertar conexión");
    }

    #[test]
    fn la_migracion_v3_declara_claves_foraneas_y_valores_por_defecto() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        assert_eq!(
            claves_foraneas(&conn, "TRAFFIC_SNAPSHOT"),
            vec![(
                "DEVICES".to_string(),
                "device_id".to_string(),
                "CASCADE".to_string()
            )],
            "el snapshot desaparece con su equipo"
        );
        assert_eq!(
            claves_foraneas(&conn, "CONNECTIONS"),
            vec![(
                "DEVICES".to_string(),
                "device_id".to_string(),
                "SET NULL".to_string()
            )],
            "borrar un equipo deja sus conexiones sin atribuir"
        );

        // Los contadores nacen a cero y la ventana por defecto es de 60 s.
        conn.execute(
            "INSERT INTO INTERFACES (name, last_seen)
             VALUES ('eth0', '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar interfaz");
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, interface_id, first_seen, last_seen)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 1,
                     '2026-11-10T10:00:00Z', '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar equipo");
        conn.execute(
            "INSERT INTO TRAFFIC_SNAPSHOT (device_id, updated_at)
             VALUES (1, '2026-11-10T10:15:00Z')",
            [],
        )
        .expect("insertar snapshot mínimo");
        let (bytes_in, bytes_out, packets_in, packets_out, peak_bps, window_s): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = conn
            .query_row(
                "SELECT bytes_in, bytes_out, packets_in, packets_out, peak_bps, window_s
                 FROM TRAFFIC_SNAPSHOT",
                [],
                |fila| {
                    Ok((
                        fila.get(0)?,
                        fila.get(1)?,
                        fila.get(2)?,
                        fila.get(3)?,
                        fila.get(4)?,
                        fila.get(5)?,
                    ))
                },
            )
            .expect("leer valores por defecto");
        assert_eq!(
            (bytes_in, bytes_out, packets_in, packets_out, peak_bps),
            (0, 0, 0, 0, 0)
        );
        assert_eq!(window_s, 60);

        conn.execute(
            "INSERT INTO CONNECTIONS (protocol, src_ip, dst_ip, first_seen, last_seen)
             VALUES ('udp', '192.168.1.50', '224.0.0.251', '2026-11-10T10:15:00Z',
                     '2026-11-10T10:15:00Z')",
            [],
        )
        .expect("insertar conexión mínima");
        let (device_id, bytes_in, bytes_out): (Option<i64>, i64, i64) = conn
            .query_row(
                "SELECT device_id, bytes_in, bytes_out FROM CONNECTIONS",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?, fila.get(2)?)),
            )
            .expect("leer valores por defecto de la conexión");
        assert_eq!(device_id, None, "sin atribuir se guarda NULL");
        assert_eq!((bytes_in, bytes_out), (0, 0));
    }

    #[test]
    fn migracion_v4_conserva_datos_de_una_bd_de_fase_3() {
        let mut conn = conexion_vacia();

        // Base de datos de Fase 3: esquema v1+v2+v3 registrado y datos de F1-F3.
        conn.execute_batch(SQL_CREAR_SCHEMA_MIGRATIONS)
            .expect("crear SCHEMA_MIGRATIONS");
        conn.execute_batch(SQL_ESQUEMA_INICIAL)
            .expect("aplicar esquema v1");
        conn.execute_batch(SQL_ESQUEMA_FASE_2)
            .expect("aplicar esquema v2");
        conn.execute_batch(SQL_ESQUEMA_FASE_3)
            .expect("aplicar esquema v3");
        conn.execute(
            "INSERT INTO SCHEMA_MIGRATIONS (version, applied_at)
             VALUES (1, ?1), (2, ?1), (3, ?1)",
            params!["2026-11-10T10:00:00Z"],
        )
        .expect("registrar v1, v2 y v3");
        assert_eq!(current_version(&conn).expect("leer versión"), 3);

        conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '192.168.1.10', '255.255.255.0',
                     '192.168.1.1', 1, '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar interfaz de F1");
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, hostname, vendor, interface_id, device_type,
                                  is_online, first_seen, last_seen, alias, notes, os_family,
                                  device_type_manual, last_fingerprint)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 'portatil', 'Apple', 1, 'pc', 1,
                     '2026-11-10T10:00:00Z', '2026-11-10T10:05:00Z', 'mi portatil',
                     'no tocar', 'macos', 'pc', '{\"ttl\":64}')",
            [],
        )
        .expect("insertar equipo de F1/F2");
        conn.execute(
            "INSERT INTO DEVICE_SERVICES (device_id, port, protocol, service, banner,
                                          first_seen, last_seen)
             VALUES (1, 22, 'tcp', 'ssh', 'SSH-2.0-OpenSSH_9.6',
                     '2026-11-10T10:10:00Z', '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar servicio de F2");
        conn.execute(
            "INSERT INTO DISCOVERY_SOURCES (device_id, source, last_seen)
             VALUES (1, 'arp', '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar fuente de F2");
        conn.execute(
            "INSERT INTO TRAFFIC_SNAPSHOT (device_id, bytes_in, bytes_out, packets_in,
                                           packets_out, peak_bps, window_s, updated_at)
             VALUES (1, 100, 200, 3, 4, 500, 60, '2026-11-10T10:15:00Z')",
            [],
        )
        .expect("insertar snapshot de F3");
        conn.execute(
            "INSERT INTO CONNECTIONS (device_id, protocol, src_ip, src_port, dst_ip, dst_port,
                                      state, bytes_in, bytes_out, first_seen, last_seen)
             VALUES (1, 'tcp', '192.168.1.50', 40000, '93.184.216.34', 443, 'ESTABLISHED',
                     1000, 500, '2026-11-10T10:15:00Z', '2026-11-10T10:16:00Z')",
            [],
        )
        .expect("insertar conexión de F3");

        // Migración aditiva a v4: no se pierde ninguna fila.
        let version = apply_all(&mut conn).expect("migrar F3 a F4");
        assert_eq!(version, 6);
        assert_eq!(current_version(&conn).expect("leer versión"), 6);

        // DEVICES conserva lo de F1/F2 y las seis columnas nuevas están a NULL.
        let (mac, ip, hostname, alias, os_family): (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT mac, ip, hostname, alias, os_family FROM DEVICES",
                [],
                |fila| {
                    Ok((
                        fila.get(0)?,
                        fila.get(1)?,
                        fila.get(2)?,
                        fila.get(3)?,
                        fila.get(4)?,
                    ))
                },
            )
            .expect("leer equipo migrado");
        assert_eq!(mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(ip, "192.168.1.50");
        assert_eq!(hostname.as_deref(), Some("portatil"));
        assert_eq!(alias.as_deref(), Some("mi portatil"));
        assert_eq!(os_family.as_deref(), Some("macos"));

        let (model, dhcp_fingerprint, dhcp_vendor, dhcp_hostname, user_agent, os_source): (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT model, dhcp_fingerprint, dhcp_vendor, dhcp_hostname, user_agent,
                        os_source
                 FROM DEVICES",
                [],
                |fila| {
                    Ok((
                        fila.get(0)?,
                        fila.get(1)?,
                        fila.get(2)?,
                        fila.get(3)?,
                        fila.get(4)?,
                        fila.get(5)?,
                    ))
                },
            )
            .expect("leer identidad migrada");
        assert_eq!(model, None);
        assert_eq!(dhcp_fingerprint, None);
        assert_eq!(dhcp_vendor, None);
        assert_eq!(dhcp_hostname, None);
        assert_eq!(user_agent, None);
        assert_eq!(os_source, None);

        // CONNECTIONS conserva la fila de F3 y sus ocho columnas nuevas son NULL.
        let (protocolo, estado, bytes_in, client_is_src, app_protocol, app, ja4): (
            String,
            Option<String>,
            i64,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT protocol, state, bytes_in, client_is_src, app_protocol, app, ja4
                 FROM CONNECTIONS",
                [],
                |fila| {
                    Ok((
                        fila.get(0)?,
                        fila.get(1)?,
                        fila.get(2)?,
                        fila.get(3)?,
                        fila.get(4)?,
                        fila.get(5)?,
                        fila.get(6)?,
                    ))
                },
            )
            .expect("leer conexión migrada");
        assert_eq!(protocolo, "tcp");
        assert_eq!(estado.as_deref(), Some("ESTABLISHED"));
        assert_eq!(bytes_in, 1000);
        assert_eq!(client_is_src, None);
        assert_eq!(app_protocol, None);
        assert_eq!(app, None);
        assert_eq!(ja4, None);

        // Ninguna tabla pierde filas y NAME_CACHE nace vacía pero utilizable.
        for (tabla, esperadas) in [
            ("DEVICES", 1_i64),
            ("DEVICE_SERVICES", 1),
            ("DISCOVERY_SOURCES", 1),
            ("TRAFFIC_SNAPSHOT", 1),
            ("CONNECTIONS", 1),
            ("NAME_CACHE", 0),
        ] {
            let total: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |fila| {
                    fila.get(0)
                })
                .expect("contar filas");
            assert_eq!(total, esperadas, "{tabla} no debe perder filas");
        }
        conn.execute(
            "INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
             VALUES ('93.184.216.34', 'example.com', 'dns',
                     '2026-11-10T10:00:00Z', '2026-11-10T10:00:00Z',
                     '2026-11-10T11:00:00Z')",
            [],
        )
        .expect("insertar una entrada de NAME_CACHE");

        // Reaplicar no falla, no duplica registros ni toca los datos.
        assert_eq!(apply_all(&mut conn).expect("reaplicar migraciones"), 6);
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 6);
        let filas_cache: i64 = conn
            .query_row("SELECT COUNT(*) FROM NAME_CACHE", [], |fila| fila.get(0))
            .expect("contar NAME_CACHE");
        assert_eq!(filas_cache, 1, "los datos de NAME_CACHE se conservan");
    }

    #[test]
    fn migracion_v5_conserva_datos_de_una_bd_de_fase_4() {
        let mut conn = conexion_vacia();

        // Base de datos de Fase 4: esquema v1..v4 registrado y datos de todas
        // las tablas anteriores.
        conn.execute_batch(SQL_CREAR_SCHEMA_MIGRATIONS)
            .expect("crear SCHEMA_MIGRATIONS");
        conn.execute_batch(SQL_ESQUEMA_INICIAL)
            .expect("aplicar esquema v1");
        conn.execute_batch(SQL_ESQUEMA_FASE_2)
            .expect("aplicar esquema v2");
        conn.execute_batch(SQL_ESQUEMA_FASE_3)
            .expect("aplicar esquema v3");
        conn.execute_batch(SQL_ESQUEMA_FASE_4)
            .expect("aplicar esquema v4");
        conn.execute(
            "INSERT INTO SCHEMA_MIGRATIONS (version, applied_at)
             VALUES (1, ?1), (2, ?1), (3, ?1), (4, ?1)",
            params!["2026-11-10T10:00:00Z"],
        )
        .expect("registrar v1..v4");
        assert_eq!(current_version(&conn).expect("leer versión"), 4);

        conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '192.168.1.10', '255.255.255.0',
                     '192.168.1.1', 1, '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar interfaz de F1");
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, hostname, vendor, interface_id, device_type,
                                  is_online, first_seen, last_seen, alias, notes, os_family,
                                  device_type_manual, last_fingerprint, model, dhcp_fingerprint,
                                  dhcp_vendor, dhcp_hostname, user_agent, os_source)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 'portatil', 'Apple', 1, 'pc', 1,
                     '2026-11-10T10:00:00Z', '2026-11-10T10:05:00Z', 'mi portatil', 'no tocar',
                     'linux', 'pc', '{\"ttl\":64}', 'MacBookPro18,3', '1,3,6', 'MSFT 5.0',
                     'portatil', 'Mozilla/5.0', 'dhcp')",
            [],
        )
        .expect("insertar equipo de F1/F2/F4");
        conn.execute(
            "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
             VALUES (1, 'new', '{}', '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar evento");
        conn.execute(
            "INSERT INTO DEVICE_SERVICES
                 (device_id, port, protocol, service, banner, first_seen, last_seen)
             VALUES (1, 22, 'tcp', 'ssh', 'SSH-2.0', '2026-11-10T10:10:00Z',
                     '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar servicio");
        conn.execute(
            "INSERT INTO DISCOVERY_SOURCES (device_id, source, last_seen)
             VALUES (1, 'arp', '2026-11-10T10:10:00Z')",
            [],
        )
        .expect("insertar fuente");
        conn.execute(
            "INSERT INTO TRAFFIC_SNAPSHOT
                 (device_id, bytes_in, bytes_out, packets_in, packets_out, peak_bps,
                  window_s, updated_at)
             VALUES (1, 100, 200, 1, 2, 300, 60, '2026-11-10T10:11:00Z')",
            [],
        )
        .expect("insertar snapshot");
        conn.execute(
            "INSERT INTO CONNECTIONS
                 (device_id, protocol, src_ip, src_port, dst_ip, dst_port, state,
                  bytes_in, bytes_out, first_seen, last_seen, client_is_src,
                  app_protocol, server_name, name_source, app, category, app_source, ja4)
             VALUES (1, 'tcp', '192.168.1.50', 40000, '1.1.1.1', 443, 'ESTABLISHED',
                     10, 20, '2026-11-10T10:12:00Z', '2026-11-10T10:13:00Z', 1,
                     'tls', 'youtube.com', 'sni', 'youtube', 'streaming', 'domain',
                     't13d1516h2')",
            [],
        )
        .expect("insertar conexión");
        conn.execute(
            "INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
             VALUES ('1.1.1.1', 'youtube.com', 'dns', '2026-11-10T10:12:00Z',
                     '2026-11-10T10:12:00Z', '2026-11-10T11:12:00Z')",
            [],
        )
        .expect("insertar nombre");

        // Abrir hasta la última versión: v5 es aditiva y v6 (alertas) también.
        let version = apply_all(&mut conn).expect("migrar F4 hasta la última versión");
        assert_eq!(version, 6);

        // Todos los datos de F4 se conservan.
        for (tabla, filas) in [
            ("INTERFACES", 1i64),
            ("DEVICES", 1),
            ("DEVICE_EVENTS", 1),
            ("DEVICE_SERVICES", 1),
            ("DISCOVERY_SOURCES", 1),
            ("TRAFFIC_SNAPSHOT", 1),
            ("CONNECTIONS", 1),
            ("NAME_CACHE", 1),
        ] {
            let total: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |fila| {
                    fila.get(0)
                })
                .expect("contar filas de F4");
            assert_eq!(total, filas, "se perdieron filas de {tabla}");
        }
        let (alias, os_family, ja4): (String, String, String) = conn
            .query_row(
                "SELECT d.alias, d.os_family, c.ja4
                   FROM DEVICES d, CONNECTIONS c
                  WHERE d.id = c.device_id",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?, fila.get(2)?)),
            )
            .expect("leer datos de F4");
        assert_eq!(alias, "mi portatil");
        assert_eq!(os_family, "linux");
        assert_eq!(ja4, "t13d1516h2");

        // Las tablas nuevas existen y están vacías (salvo el aprendizaje del
        // propio equipo, que la v6 crea de cero).
        for tabla in [
            "TRAFFIC_ROLLUP_MINUTE",
            "TRAFFIC_ROLLUP_HOUR",
            "TRAFFIC_ROLLUP_DAY",
            "DEVICE_SEEN",
            "APP_SESSIONS",
            "ALERTS",
            "ALERT_MUTES",
            "HOST_SEEN",
            "COVERAGE_GAPS",
        ] {
            let total: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |fila| {
                    fila.get(0)
                })
                .expect("contar tabla nueva");
            assert_eq!(total, 0, "la tabla nueva {tabla} debe quedar vacía");
        }
        let (subject, device_id, data_days, learned_at): (String, i64, i64, Option<String>) = conn
            .query_row(
                "SELECT subject, device_id, data_days, learned_at FROM ALERT_LEARNING
                  WHERE subject = 'host' AND device_id = 0",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?, fila.get(2)?, fila.get(3)?)),
            )
            .expect("leer aprendizaje del propio equipo");
        assert_eq!(subject, "host");
        assert_eq!(device_id, 0);
        assert_eq!(data_days, 0, "el propio equipo empieza de cero");
        assert_eq!(learned_at, None);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM ALERT_LEARNING", [], |fila| fila
                .get::<_, i64>(0))
                .expect("contar aprendizaje"),
            2,
            "el equipo existente y el propio equipo tienen su fila"
        );

        // auto_vacuum = INCREMENTAL (2) tras el VACUUM de la migración.
        let modo: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |fila| fila.get(0))
            .expect("leer auto_vacuum");
        assert_eq!(modo, 2, "auto_vacuum debe ser INCREMENTAL");

        // Una segunda apertura no repite nada (ni el relleno de la v6).
        let version = apply_all(&mut conn).expect("reaplicar migraciones");
        assert_eq!(version, 6);
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 6);
        let aprendizajes: i64 = conn
            .query_row("SELECT COUNT(*) FROM ALERT_LEARNING", [], |fila| {
                fila.get(0)
            })
            .expect("contar ALERT_LEARNING");
        assert_eq!(
            aprendizajes, 2,
            "las filas de aprendizaje no se duplican al reabrir"
        );
    }

    #[test]
    fn la_migracion_v5_es_idempotente_aunque_se_borre_su_registro() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        // Se borran v5 y v6: la versión actual se lee como MAX(version).
        conn.execute("DELETE FROM SCHEMA_MIGRATIONS WHERE version >= 5", [])
            .expect("borrar registros de v5 y v6");
        assert_eq!(current_version(&conn).expect("leer versión"), 4);

        let version = apply_all(&mut conn).expect("reaplicar migraciones v5 y v6");
        assert_eq!(version, 6);
        assert_eq!(current_version(&conn).expect("leer versión"), 6);
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 6, "los registros vuelven a quedar anotados");
        assert!(objetos(&conn, "table").contains(&"TRAFFIC_ROLLUP_MINUTE".to_string()));
        assert!(objetos(&conn, "table").contains(&"ALERTS".to_string()));
    }

    /// Comprueba que las tablas de rollup son WITHOUT ROWID con la clave
    /// primaria en el orden del §3.
    #[test]
    fn las_tablas_de_rollup_son_without_rowid_con_su_clave() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");
        for tabla in [
            "TRAFFIC_ROLLUP_MINUTE",
            "TRAFFIC_ROLLUP_HOUR",
            "TRAFFIC_ROLLUP_DAY",
        ] {
            let sin_rowid: i64 = conn
                .query_row(
                    "SELECT wr FROM pragma_table_list WHERE name = ?1",
                    params![tabla],
                    |fila| fila.get(0),
                )
                .expect("leer without rowid");
            assert_eq!(sin_rowid, 1, "{tabla} debe ser WITHOUT ROWID");
            // Orden de definición de las columnas.
            let mut sentencia = conn
                .prepare(&format!(
                    "SELECT name FROM pragma_table_info('{tabla}') ORDER BY cid"
                ))
                .expect("preparar columnas");
            let columnas: Vec<String> = sentencia
                .query_map([], |fila| fila.get(0))
                .expect("consultar columnas")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("leer columnas");
            assert_eq!(
                columnas,
                vec![
                    "bucket",
                    "subject",
                    "device_id",
                    "dimension",
                    "key",
                    "bytes_down",
                    "bytes_up",
                    "connections"
                ],
                "columnas de {tabla}"
            );
            // Orden de la clave primaria (los cinco primeros, en orden).
            let mut sentencia = conn
                .prepare(&format!(
                    "SELECT name FROM pragma_table_info('{tabla}') WHERE pk > 0 ORDER BY pk"
                ))
                .expect("preparar clave primaria");
            let clave: Vec<String> = sentencia
                .query_map([], |fila| fila.get(0))
                .expect("consultar clave primaria")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("leer clave primaria");
            assert_eq!(
                clave,
                vec!["bucket", "subject", "device_id", "dimension", "key"],
                "clave primaria de {tabla}"
            );
        }
    }

    #[test]
    fn la_migracion_v4_es_idempotente_aunque_se_borre_su_registro() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        // Datos de F4 que no deben perderse al reaplicar la migración.
        conn.execute(
            "INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
             VALUES ('93.184.216.34', 'example.com', 'dns',
                     '2026-11-10T10:00:00Z', '2026-11-10T10:00:00Z',
                     '2026-11-10T11:00:00Z')",
            [],
        )
        .expect("insertar entrada de NAME_CACHE");

        // Se borran v4, v5 y v6: la versión actual se lee como MAX(version).
        conn.execute("DELETE FROM SCHEMA_MIGRATIONS WHERE version >= 4", [])
            .expect("borrar registros de v4, v5 y v6");
        assert_eq!(current_version(&conn).expect("leer versión"), 3);

        // already_applied detecta la tabla NAME_CACHE y evita reejecutar los
        // ALTER TABLE, que fallarían con "duplicate column name"; v5 y v6 se
        // saltan por sus tablas TRAFFIC_ROLLUP_MINUTE y ALERTS.
        let version = apply_all(&mut conn).expect("reaplicar migraciones v4, v5 y v6");
        assert_eq!(version, 6);
        assert_eq!(current_version(&conn).expect("leer versión"), 6);
        let filas: i64 = conn
            .query_row("SELECT COUNT(*) FROM NAME_CACHE", [], |fila| fila.get(0))
            .expect("contar NAME_CACHE");
        assert_eq!(filas, 1, "los datos de NAME_CACHE se conservan");
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 6, "los registros vuelven a quedar anotados");
    }

    #[test]
    fn migracion_v6_conserva_datos_de_una_bd_de_fase_5() {
        let mut conn = conexion_vacia();

        // Base de datos de Fase 5: esquema v1..v5 registrado y datos con su
        // histórico (sesiones y rollups de día) que alimentan los rellenos.
        conn.execute_batch(SQL_CREAR_SCHEMA_MIGRATIONS)
            .expect("crear SCHEMA_MIGRATIONS");
        conn.execute_batch(SQL_ESQUEMA_INICIAL)
            .expect("aplicar esquema v1");
        conn.execute_batch(SQL_ESQUEMA_FASE_2)
            .expect("aplicar esquema v2");
        conn.execute_batch(SQL_ESQUEMA_FASE_3)
            .expect("aplicar esquema v3");
        conn.execute_batch(SQL_ESQUEMA_FASE_4)
            .expect("aplicar esquema v4");
        conn.execute_batch(SQL_ESQUEMA_FASE_5)
            .expect("aplicar esquema v5");
        conn.execute(
            "INSERT INTO SCHEMA_MIGRATIONS (version, applied_at)
             VALUES (1, ?1), (2, ?1), (3, ?1), (4, ?1), (5, ?1)",
            params!["2026-11-10T10:00:00Z"],
        )
        .expect("registrar v1..v5");
        assert_eq!(current_version(&conn).expect("leer versión"), 5);

        let hoy = crate::history::LocalDay::today();
        let primer_dia = hoy.sumar_dias(-8);
        let inicio = crate::history::localtime::rfc3339(primer_dia.limits().0);
        let fin_ayer = hoy.sumar_dias(-1).limits().1;
        let fin_ayer = crate::history::localtime::rfc3339(fin_ayer);
        conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES ('eth0', 'aa:bb:cc:dd:ee:ff', '192.168.1.10', '255.255.255.0',
                     '192.168.1.1', 1, ?1)",
            params![inicio],
        )
        .expect("insertar interfaz");
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, hostname, interface_id, first_seen, last_seen)
             VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 'portatil', 1, ?1, ?1)",
            params![inicio],
        )
        .expect("insertar equipo");
        // Una sesión con captura cubre los ocho días de histórico.
        conn.execute(
            "INSERT INTO APP_SESSIONS
                 (started_at, ended_at, last_beat, end_reason, mode, capture, passive_only,
                  version)
             VALUES (?1, ?2, ?2, 'quit', 'privileged', 1, 0, '0.5.0')",
            params![inicio, fin_ayer],
        )
        .expect("insertar sesión");
        for atras in 1..=8 {
            let dia = hoy.sumar_dias(-atras);
            conn.execute(
                "INSERT INTO TRAFFIC_ROLLUP_DAY
                     (bucket, subject, device_id, dimension, key, bytes_down, bytes_up,
                      connections)
                 VALUES (?1, 'device', 1, 'total', '', 100, 10, 1)",
                params![dia.aaaammdd()],
            )
            .expect("insertar día de tráfico");
        }
        // El último evento de servicio del 22/tcp es un service_gone.
        for (tipo, created_at) in [
            ("service_new", "2026-11-04T10:00:00Z"),
            ("service_gone", "2026-11-04T11:00:00Z"),
        ] {
            conn.execute(
                "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
                 VALUES (1, ?1, ?2, ?3)",
                params![tipo, r#"{"port":22,"protocol":"tcp"}"#, created_at],
            )
            .expect("insertar evento de servicio");
        }
        conn.execute(
            "INSERT INTO DEVICE_SERVICES
                 (device_id, port, protocol, service, first_seen, last_seen)
             VALUES (1, 22, 'tcp', 'ssh', '2026-10-01T10:00:00Z', '2026-11-04T10:00:00Z')",
            [],
        )
        .expect("insertar servicio");

        let version = apply_all(&mut conn).expect("migrar F5 a F6");
        assert_eq!(version, 6);

        // Nada de F1–F5 se pierde.
        for (tabla, filas) in [
            ("INTERFACES", 1i64),
            ("DEVICES", 1),
            ("DEVICE_EVENTS", 2),
            ("DEVICE_SERVICES", 1),
            ("APP_SESSIONS", 1),
            ("TRAFFIC_ROLLUP_DAY", 8),
        ] {
            let total: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |fila| {
                    fila.get(0)
                })
                .expect("contar filas de F5");
            assert_eq!(total, filas, "se perdieron filas de {tabla}");
        }

        // DEVICES.watched nace a 0 (ninguno vigilado por defecto, §7.7).
        let watched: i64 = conn
            .query_row("SELECT watched FROM DEVICES WHERE id = 1", [], |fila| {
                fila.get(0)
            })
            .expect("leer watched");
        assert_eq!(watched, 0);

        // closed_at se rellena con el último service_gone y last_seen no cambia
        // (sigue siendo la última vez que el puerto se vio abierto, §7.12).
        let (closed_at, last_seen): (Option<String>, String) = conn
            .query_row(
                "SELECT closed_at, last_seen FROM DEVICE_SERVICES
                  WHERE device_id = 1 AND port = 22 AND protocol = 'tcp'",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer servicio migrado");
        assert_eq!(closed_at.as_deref(), Some("2026-11-04T11:00:00Z"));
        assert_eq!(
            last_seen, "2026-11-04T10:00:00Z",
            "last_seen sigue siendo la última vez que se vio abierto"
        );

        // Aprendizaje inicial: 8 días con datos → aprendido al final del 7.º.
        let (learning_from, data_days, learned_at, updated_day): (
            String,
            i64,
            Option<String>,
            i64,
        ) = conn
            .query_row(
                "SELECT learning_from, data_days, learned_at, updated_day
                   FROM ALERT_LEARNING WHERE subject = 'device' AND device_id = 1",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?, fila.get(2)?, fila.get(3)?)),
            )
            .expect("leer aprendizaje del equipo");
        assert_eq!(learning_from, inicio, "el aprendizaje empieza en su alta");
        assert_eq!(data_days, 7, "cuenta los días con datos hasta aprender");
        let septimo = hoy.sumar_dias(-2);
        assert_eq!(
            learned_at.as_deref(),
            Some(crate::history::localtime::rfc3339(septimo.limits().1).as_str()),
            "learned_at es el fin de su 7.º día con datos"
        );
        assert_eq!(updated_day, hoy.sumar_dias(-1).aaaammdd());

        // El propio equipo empieza de cero con learning_from = migración.
        let (host_dias, host_aprendido): (i64, Option<String>) = conn
            .query_row(
                "SELECT data_days, learned_at FROM ALERT_LEARNING
                  WHERE subject = 'host' AND device_id = 0",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer aprendizaje del propio equipo");
        assert_eq!(host_dias, 0);
        assert_eq!(host_aprendido, None);

        // Reaplicar no repite el hook: ni duplica aprendizaje ni toca closed_at.
        assert_eq!(apply_all(&mut conn).expect("reaplicar migraciones"), 6);
        let aprendizajes: i64 = conn
            .query_row("SELECT COUNT(*) FROM ALERT_LEARNING", [], |fila| {
                fila.get(0)
            })
            .expect("contar ALERT_LEARNING");
        assert_eq!(aprendizajes, 2, "las filas de aprendizaje no se duplican");
        let (closed_at, _): (Option<String>, String) = conn
            .query_row(
                "SELECT closed_at, last_seen FROM DEVICE_SERVICES
                  WHERE device_id = 1 AND port = 22 AND protocol = 'tcp'",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("releer servicio");
        assert_eq!(closed_at.as_deref(), Some("2026-11-04T11:00:00Z"));
    }

    #[test]
    fn la_migracion_v6_es_idempotente_aunque_se_borre_su_registro() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");
        let antes: i64 = conn
            .query_row("SELECT COUNT(*) FROM ALERT_LEARNING", [], |fila| {
                fila.get(0)
            })
            .expect("contar aprendizaje");
        assert_eq!(antes, 1, "la migración crea la fila del propio equipo");

        conn.execute("DELETE FROM SCHEMA_MIGRATIONS WHERE version = 6", [])
            .expect("borrar registro de v6");
        assert_eq!(current_version(&conn).expect("leer versión"), 5);

        let version = apply_all(&mut conn).expect("reaplicar migración v6");
        assert_eq!(version, 6);
        assert_eq!(current_version(&conn).expect("leer versión"), 6);
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 6);
        assert_eq!(
            objetos(&conn, "table")
                .iter()
                .filter(|tabla| tabla.as_str() == "ALERTS")
                .count(),
            1,
            "las tablas nuevas existen una sola vez"
        );
        let despues: i64 = conn
            .query_row("SELECT COUNT(*) FROM ALERT_LEARNING", [], |fila| {
                fila.get(0)
            })
            .expect("contar aprendizaje");
        assert_eq!(despues, antes, "el hook de relleno no se repite");
    }

    #[test]
    fn la_migracion_v6_declara_claves_foraneas_y_tablas_sin_rowid() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        assert_eq!(
            claves_foraneas(&conn, "ALERTS"),
            vec![(
                "DEVICES".to_string(),
                "device_id".to_string(),
                "SET NULL".to_string()
            )],
            "borrar el equipo deja la alerta con subject_label"
        );
        assert_eq!(
            claves_foraneas(&conn, "COVERAGE_GAPS"),
            vec![(
                "APP_SESSIONS".to_string(),
                "session_id".to_string(),
                "CASCADE".to_string()
            )],
            "los huecos viven lo que su sesión"
        );

        for tabla in ["ALERT_LEARNING", "HOST_SEEN"] {
            let sin_rowid: i64 = conn
                .query_row(
                    "SELECT wr FROM pragma_table_list WHERE name = ?1",
                    params![tabla],
                    |fila| fila.get(0),
                )
                .expect("leer without rowid");
            assert_eq!(sin_rowid, 1, "{tabla} debe ser WITHOUT ROWID");
        }
        let clave = |tabla: &str| -> Vec<String> {
            let mut sentencia = conn
                .prepare(&format!(
                    "SELECT name FROM pragma_table_info('{tabla}') WHERE pk > 0 ORDER BY pk"
                ))
                .expect("preparar clave primaria");
            sentencia
                .query_map([], |fila| fila.get(0))
                .expect("consultar clave primaria")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("leer clave primaria")
        };
        assert_eq!(clave("ALERT_LEARNING"), vec!["subject", "device_id"]);
        assert_eq!(clave("HOST_SEEN"), vec!["kind", "key"]);

        // Un silencio único por regla, sujeto y equipo (§7.6).
        conn.execute(
            "INSERT INTO ALERT_MUTES (rule, subject, device_id, until, created_at)
             VALUES ('new_app', 'host', 0, NULL, '2026-11-10T10:00:00Z')",
            [],
        )
        .expect("insertar silencio");
        let error = conn
            .execute(
                "INSERT INTO ALERT_MUTES (rule, subject, device_id, until, created_at)
                 VALUES ('new_app', 'host', 0, NULL, '2026-11-10T11:00:00Z')",
                [],
            )
            .expect_err("el silencio duplicado debe fallar");
        assert!(error.to_string().contains("UNIQUE"));
    }
}
