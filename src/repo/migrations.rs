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
}

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

/// Lista ordenada de migraciones.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "esquema_inicial",
        sql: SQL_ESQUEMA_INICIAL,
        already_applied: None,
    },
    Migration {
        version: 2,
        name: "descubrimiento_avanzado",
        sql: SQL_ESQUEMA_FASE_2,
        already_applied: Some(v2_ya_aplicada),
    },
    Migration {
        version: 3,
        name: "trafico_en_vivo",
        sql: SQL_ESQUEMA_FASE_3,
        already_applied: Some(v3_ya_aplicada),
    },
    Migration {
        version: 4,
        name: "protocolos_y_etiquetas",
        sql: SQL_ESQUEMA_FASE_4,
        already_applied: Some(v4_ya_aplicada),
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
        }
        transaccion.execute(
            "INSERT OR IGNORE INTO SCHEMA_MIGRATIONS (version, applied_at) VALUES (?1, ?2)",
            params![migracion.version, super::ahora_rfc3339()],
        )?;
        transaccion.commit()?;
        version = migracion.version;
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
    fn apply_all_es_idempotente_y_llega_a_la_version_4() {
        let mut conn = conexion_vacia();

        let primera = apply_all(&mut conn).expect("aplicar migraciones");
        assert_eq!(primera, 4);
        assert_eq!(current_version(&conn).expect("leer versión"), 4);

        // Una segunda aplicación no debe duplicar registros ni fallar.
        let segunda = apply_all(&mut conn).expect("reaplicar migraciones");
        assert_eq!(segunda, 4);

        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones aplicadas");
        assert_eq!(registros, 4);

        let (version, aplicada): (u32, String) = conn
            .query_row(
                "SELECT version, applied_at FROM SCHEMA_MIGRATIONS WHERE version = 4",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer registro de migración v4");
        assert_eq!(version, 4);
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
        assert_eq!(version, 4);
        assert_eq!(current_version(&conn).expect("leer versión"), 4);
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 4, "los cuatro registros deben quedar anotados");
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
        assert_eq!(version, 4);

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
        assert_eq!(MIGRATIONS.len(), 4);
        for (indice, migracion) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migracion.version, indice as u32 + 1);
            assert!(!migracion.sql.trim().is_empty());
        }
        assert_eq!(MIGRATIONS[0].name, "esquema_inicial");
        assert_eq!(MIGRATIONS[1].name, "descubrimiento_avanzado");
        assert_eq!(MIGRATIONS[2].name, "trafico_en_vivo");
        assert_eq!(MIGRATIONS[3].name, "protocolos_y_etiquetas");
        assert!(MIGRATIONS[0].already_applied.is_none());
        assert!(MIGRATIONS[1].already_applied.is_some());
        assert!(MIGRATIONS[2].already_applied.is_some());
        assert!(MIGRATIONS[3].already_applied.is_some());
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
        ] {
            assert!(
                tablas.contains(&esperada.to_string()),
                "falta la tabla {esperada}"
            );
        }
        assert_eq!(
            tablas.len(),
            9,
            "el esquema completo debe tener nueve tablas: {tablas:?}"
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
                "os_source"
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
                "last_seen"
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
        assert_eq!(version, 4);
        assert_eq!(current_version(&conn).expect("leer versión"), 4);
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
        assert_eq!(version, 4);

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
        assert_eq!(version, 4);
        assert_eq!(current_version(&conn).expect("leer versión"), 4);

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
        assert_eq!(apply_all(&mut conn).expect("reaplicar migraciones"), 4);
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 4);
        let filas_cache: i64 = conn
            .query_row("SELECT COUNT(*) FROM NAME_CACHE", [], |fila| fila.get(0))
            .expect("contar NAME_CACHE");
        assert_eq!(filas_cache, 1, "los datos de NAME_CACHE se conservan");
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

        conn.execute("DELETE FROM SCHEMA_MIGRATIONS WHERE version = 4", [])
            .expect("borrar registro de v4");
        assert_eq!(current_version(&conn).expect("leer versión"), 3);

        // already_applied detecta la tabla NAME_CACHE y evita reejecutar los
        // ALTER TABLE, que fallarían con "duplicate column name".
        let version = apply_all(&mut conn).expect("reaplicar migración v4");
        assert_eq!(version, 4);
        assert_eq!(current_version(&conn).expect("leer versión"), 4);
        let filas: i64 = conn
            .query_row("SELECT COUNT(*) FROM NAME_CACHE", [], |fila| fila.get(0))
            .expect("contar NAME_CACHE");
        assert_eq!(filas, 1, "los datos de NAME_CACHE se conservan");
        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones");
        assert_eq!(registros, 4, "el registro de v4 vuelve a quedar anotado");
    }
}
