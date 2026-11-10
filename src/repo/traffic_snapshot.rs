//! DAO del snapshot de tráfico por dispositivo (tabla TRAFFIC_SNAPSHOT).
//!
//! TRAFFIC_SNAPSHOT es una tabla de estado, no histórica: guarda una única fila
//! por dispositivo con el último valor agregado (bytes y paquetes de la ventana
//! de 60 s, y el pico de bits por segundo de esa ventana) y se sobrescribe cada
//! 5 s desde el hilo de la TUI. Sirve como semilla inicial de las sparklines al
//! reabrir la aplicación (el histórico real es Fase 5).
//!
//! La fila se identifica por device_id: el upsert nunca duplica. La clave
//! foránea es ON DELETE CASCADE, de modo que el snapshot desaparece con el
//! equipo.

use rusqlite::{params, Connection, Row};

use super::ahora_rfc3339;
use crate::error::Result;

/// Datos de un ciclo de snapshot de tráfico para hacer upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotUpdate {
    /// FK a DEVICES (clave primaria de TRAFFIC_SNAPSHOT).
    pub device_id: i64,
    /// Bytes recibidos en la ventana.
    pub bytes_in: i64,
    /// Bytes enviados en la ventana.
    pub bytes_out: i64,
    /// Paquetes recibidos en la ventana.
    pub packets_in: i64,
    /// Paquetes enviados en la ventana.
    pub packets_out: i64,
    /// Pico de (bytes_in + bytes_out) por segundo dentro de la ventana.
    pub peak_bps: i64,
    /// Longitud de la ventana en segundos (60 en Fase 3).
    pub window_s: i64,
}

/// Fila persistida de TRAFFIC_SNAPSHOT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSnapshot {
    /// FK a DEVICES.
    pub device_id: i64,
    /// Bytes recibidos en la ventana.
    pub bytes_in: i64,
    /// Bytes enviados en la ventana.
    pub bytes_out: i64,
    /// Paquetes recibidos en la ventana.
    pub packets_in: i64,
    /// Paquetes enviados en la ventana.
    pub packets_out: i64,
    /// Pico de (bytes_in + bytes_out) por segundo dentro de la ventana.
    pub peak_bps: i64,
    /// Longitud de la ventana en segundos.
    pub window_s: i64,
    /// Momento del último upsert (RFC 3339 UTC).
    pub updated_at: String,
}

/// Columnas de TRAFFIC_SNAPSHOT en el mismo orden que reconstruye fila_a_snapshot.
const SQL_SELECCION: &str = "SELECT device_id, bytes_in, bytes_out, packets_in, \
     packets_out, peak_bps, window_s, updated_at FROM TRAFFIC_SNAPSHOT";

/// Inserta o sobrescribe el snapshot de un dispositivo.
///
/// El upsert es por device_id: una segunda llamada actualiza la fila existente
/// (no duplica) y refresca updated_at. El momento se genera aquí con
/// ahora_rfc3339(), igual que el resto de la capa de persistencia.
pub(crate) fn upsert(conn: &Connection, snapshot: &SnapshotUpdate) -> Result<()> {
    conn.execute(
        "INSERT INTO TRAFFIC_SNAPSHOT (
             device_id, bytes_in, bytes_out, packets_in, packets_out,
             peak_bps, window_s, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(device_id) DO UPDATE SET
             bytes_in = excluded.bytes_in,
             bytes_out = excluded.bytes_out,
             packets_in = excluded.packets_in,
             packets_out = excluded.packets_out,
             peak_bps = excluded.peak_bps,
             window_s = excluded.window_s,
             updated_at = excluded.updated_at",
        params![
            snapshot.device_id,
            snapshot.bytes_in,
            snapshot.bytes_out,
            snapshot.packets_in,
            snapshot.packets_out,
            snapshot.peak_bps,
            snapshot.window_s,
            ahora_rfc3339()
        ],
    )?;
    Ok(())
}

/// Lista los snapshots persistidos, ordenados por device_id.
pub(crate) fn list(conn: &Connection) -> Result<Vec<TrafficSnapshot>> {
    let mut sentencia = conn.prepare(&format!("{SQL_SELECCION} ORDER BY device_id"))?;
    let filas = sentencia.query_map([], fila_a_snapshot)?;
    let mut snapshots = Vec::new();
    for fila in filas {
        snapshots.push(fila?);
    }
    Ok(snapshots)
}

/// Reconstruye un snapshot a partir de una fila de SQL_SELECCION.
fn fila_a_snapshot(fila: &Row<'_>) -> rusqlite::Result<TrafficSnapshot> {
    Ok(TrafficSnapshot {
        device_id: fila.get(0)?,
        bytes_in: fila.get(1)?,
        bytes_out: fila.get(2)?,
        packets_in: fila.get(3)?,
        packets_out: fila.get(4)?,
        peak_bps: fila.get(5)?,
        window_s: fila.get(6)?,
        updated_at: fila.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    /// Conexión en memoria con el esquema migrado y dos equipos de prueba.
    ///
    /// Devuelve también los ids de los equipos insertados (1 y 2) para usarlos
    /// como FK en los snapshots.
    fn conexion_con_equipos() -> (Connection, i64, i64) {
        let mut conn = Connection::open_in_memory().expect("abrir SQLite en memoria");
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

        let primero = insertar_equipo(&conn, "aa:bb:cc:dd:ee:01", "192.168.1.50");
        let segundo = insertar_equipo(&conn, "aa:bb:cc:dd:ee:02", "192.168.1.51");
        (conn, primero, segundo)
    }

    /// Inserta un equipo mínimo y devuelve su id.
    fn insertar_equipo(conn: &Connection, mac: &str, ip: &str) -> i64 {
        conn.execute(
            "INSERT INTO DEVICES (mac, ip, interface_id, device_type, is_online, first_seen, last_seen)
             VALUES (?1, ?2, 1, 'unknown', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![mac, ip],
        )
        .expect("insertar equipo");
        conn.last_insert_rowid()
    }

    /// Datos de snapshot con los contadores indicados.
    fn actualizacion(device_id: i64, bytes_in: i64, bytes_out: i64) -> SnapshotUpdate {
        SnapshotUpdate {
            device_id,
            bytes_in,
            bytes_out,
            packets_in: bytes_in / 100,
            packets_out: bytes_out / 100,
            peak_bps: bytes_in.max(bytes_out),
            window_s: 60,
        }
    }

    #[test]
    fn upsert_sobrescribe_el_snapshot_sin_duplicar() {
        let (conn, primero, _) = conexion_con_equipos();

        upsert(&conn, &actualizacion(primero, 1_000, 2_000)).expect("primer snapshot");
        let snapshots = list(&conn).expect("listar snapshots");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].device_id, primero);
        assert_eq!(snapshots[0].bytes_in, 1_000);
        assert_eq!(snapshots[0].bytes_out, 2_000);
        assert_eq!(snapshots[0].packets_in, 10);
        assert_eq!(snapshots[0].packets_out, 20);
        assert_eq!(snapshots[0].peak_bps, 2_000);
        assert_eq!(snapshots[0].window_s, 60);
        assert!(
            snapshots[0].updated_at.ends_with('Z'),
            "updated_at debe estar en UTC"
        );
        chrono::DateTime::parse_from_rfc3339(&snapshots[0].updated_at)
            .expect("updated_at debe ser RFC 3339");

        // El segundo ciclo de 5 s sobrescribe y no crea una fila nueva.
        upsert(&conn, &actualizacion(primero, 3_000, 4_000)).expect("segundo snapshot");
        let snapshots = list(&conn).expect("listar snapshots");
        assert_eq!(snapshots.len(), 1, "un equipo debe tener una sola fila");
        assert_eq!(snapshots[0].bytes_in, 3_000);
        assert_eq!(snapshots[0].bytes_out, 4_000);
        assert_eq!(snapshots[0].peak_bps, 4_000);
    }

    #[test]
    fn list_ordena_por_device_id() {
        let (conn, primero, segundo) = conexion_con_equipos();
        // Se inserta primero el equipo de id mayor y se comprueba el orden.
        upsert(&conn, &actualizacion(segundo, 10, 20)).expect("snapshot del segundo");
        upsert(&conn, &actualizacion(primero, 30, 40)).expect("snapshot del primero");

        let snapshots = list(&conn).expect("listar snapshots");
        let ids: Vec<i64> = snapshots
            .iter()
            .map(|snapshot| snapshot.device_id)
            .collect();
        assert_eq!(ids, vec![primero, segundo], "se ordenan por device_id");
    }

    #[test]
    fn los_valores_por_defecto_del_esquema_son_cero_y_ventana_60() {
        let (conn, primero, _) = conexion_con_equipos();
        // Inserción directa sin contadores: se aplican los DEFAULT del esquema.
        conn.execute(
            "INSERT INTO TRAFFIC_SNAPSHOT (device_id, updated_at)
             VALUES (?1, '2026-01-01T00:00:00Z')",
            params![primero],
        )
        .expect("insertar snapshot con valores por defecto");

        let snapshots = list(&conn).expect("listar snapshots");
        assert_eq!(snapshots[0].bytes_in, 0);
        assert_eq!(snapshots[0].bytes_out, 0);
        assert_eq!(snapshots[0].packets_in, 0);
        assert_eq!(snapshots[0].packets_out, 0);
        assert_eq!(snapshots[0].peak_bps, 0);
        assert_eq!(snapshots[0].window_s, 60);
    }

    #[test]
    fn el_snapshot_de_un_equipo_inexistente_falla_por_clave_foranea() {
        let (conn, _, _) = conexion_con_equipos();
        let error = upsert(&conn, &actualizacion(999, 1, 2))
            .expect_err("la FK debe impedir un device_id inexistente");
        assert!(matches!(error, Error::Database(_)), "error: {error}");
        assert!(
            error.to_string().contains("FOREIGN KEY"),
            "el error debe explicar la violación de clave foránea: {error}"
        );
    }

    #[test]
    fn borrar_el_equipo_elimina_su_snapshot_en_cascada() {
        let (conn, primero, segundo) = conexion_con_equipos();
        upsert(&conn, &actualizacion(primero, 1, 2)).expect("snapshot del primero");
        upsert(&conn, &actualizacion(segundo, 3, 4)).expect("snapshot del segundo");

        conn.execute("DELETE FROM DEVICES WHERE id = ?1", params![primero])
            .expect("borrar el primer equipo");

        let snapshots = list(&conn).expect("listar snapshots");
        assert_eq!(
            snapshots.len(),
            1,
            "el snapshot del equipo borrado desaparece"
        );
        assert_eq!(snapshots[0].device_id, segundo);
    }
}
