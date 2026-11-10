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
    /// SQL idempotente.
    pub sql: &'static str,
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

/// Lista ordenada de migraciones.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "esquema_inicial",
    sql: SQL_ESQUEMA_INICIAL,
}];

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
        transaccion.execute_batch(migracion.sql)?;
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
    fn apply_all_es_idempotente_y_llega_a_la_version_1() {
        let mut conn = conexion_vacia();

        let primera = apply_all(&mut conn).expect("aplicar migraciones");
        assert_eq!(primera, 1);
        assert_eq!(current_version(&conn).expect("leer versión"), 1);

        // Una segunda aplicación no debe duplicar registros ni fallar.
        let segunda = apply_all(&mut conn).expect("reaplicar migraciones");
        assert_eq!(segunda, 1);

        let registros: i64 = conn
            .query_row("SELECT COUNT(*) FROM SCHEMA_MIGRATIONS", [], |fila| {
                fila.get(0)
            })
            .expect("contar migraciones aplicadas");
        assert_eq!(registros, 1);

        let (version, aplicada): (u32, String) = conn
            .query_row(
                "SELECT version, applied_at FROM SCHEMA_MIGRATIONS",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer registro de migración");
        assert_eq!(version, 1);
        chrono::DateTime::parse_from_rfc3339(&aplicada)
            .expect("applied_at debe ser RFC 3339 en UTC");
        assert!(aplicada.ends_with('Z'), "applied_at debe estar en UTC");
    }

    #[test]
    fn la_migracion_inicial_es_el_esquema_inicial() {
        assert_eq!(MIGRATIONS.len(), 1);
        assert_eq!(MIGRATIONS[0].version, 1);
        assert_eq!(MIGRATIONS[0].name, "esquema_inicial");
        assert!(!MIGRATIONS[0].sql.trim().is_empty());
    }

    #[test]
    fn la_migracion_inicial_crea_tablas_columnas_e_indices() {
        let mut conn = conexion_vacia();
        apply_all(&mut conn).expect("aplicar migraciones");

        let tablas = objetos(&conn, "table");
        for esperada in [
            "DEVICES",
            "DEVICE_EVENTS",
            "INTERFACES",
            "SCHEMA_MIGRATIONS",
        ] {
            assert!(
                tablas.contains(&esperada.to_string()),
                "falta la tabla {esperada}"
            );
        }

        let indices = objetos(&conn, "index");
        for esperado in [
            "idx_devices_is_online",
            "idx_device_events_created_at",
            "idx_device_events_device_created_at",
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
                "notes"
            ]
        );
        assert_eq!(
            columnas(&conn, "DEVICE_EVENTS"),
            vec!["id", "device_id", "event_type", "details", "created_at"]
        );
    }
}
