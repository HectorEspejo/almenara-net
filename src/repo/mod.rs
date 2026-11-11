//! Capa de persistencia SQLite (rusqlite bundled).
//!
//! Repo envuelve una conexión a la base de datos, aplica las migraciones
//! versionadas al abrirla y expone operaciones sencillas para la TUI y el
//! reconciliador de escaneos.
//!
//! Decisiones de la capa de persistencia:
//!
//! - Todas las fechas se guardan en RFC 3339 UTC con precisión de segundos
//!   (por ejemplo 2026-11-10T10:30:00Z), de modo que compararlas como texto en
//!   SQL equivale a compararlas cronológicamente.
//! - Todo el SQL con datos variables usa parámetros (?1, ?2...); nunca se
//!   concatena un valor en la sentencia.
//! - upsert_device nunca pisa alias ni notes (son datos manuales del usuario) y
//!   conserva el hostname y el vendor anteriores si la detección nueva no trae
//!   valor.
//! - list_events omite las filas con un event_type desconocido: permite que una
//!   base de datos escrita por una versión futura no rompa la TUI actual.

// Los DAOs de F2 y F3 exponen la API completa exigida por el checklist
// (incluidas operaciones que la TUI todavía no consume); se permite dead_code en
// el binario y quedan cubiertos por tests.
#[allow(dead_code)]
pub mod alerts;
#[allow(dead_code)]
pub mod connections;
#[allow(dead_code)]
pub mod device_services;
pub mod devices;
#[allow(dead_code)]
pub mod discovery_sources;
pub mod events;
#[allow(dead_code)]
pub mod gaps;
pub mod interfaces;
#[allow(dead_code)]
pub mod learning;
pub mod migrations;
#[allow(dead_code)]
pub mod names;
#[allow(dead_code)]
pub mod rollups;
#[allow(dead_code)]
pub mod seen;
#[allow(dead_code)]
pub mod sessions;
#[allow(dead_code)]
pub mod traffic_snapshot;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{SecondsFormat, Utc};
// El alias evita el choque entre rusqlite::Connection y el struct Connection de
// la tabla CONNECTIONS que reexporta esta capa.
use rusqlite::{params, Connection as SqliteConnection, OptionalExtension, Row};

use crate::classify::{DeviceType, OsFamily};
use crate::error::{Error, Result};
use crate::identify::OsSource;
use crate::inference::names::NameEntry;

pub use alerts::{AlertScope, SeenSel};
pub use connections::{Connection, ConnectionProtocol, ConnectionUpdate};
pub use device_services::{DeviceService, Protocol, ServiceUpsert};
pub use devices::{ChangeSet, Device, DeviceUpsert, IdentityUpdate};
pub use discovery_sources::{DiscoverySource, DiscoverySourceRow};
pub use events::{DeviceEvent, EventType};
pub use gaps::GapKind;
pub use interfaces::Interface;
#[allow(unused_imports)]
pub use learning::LearningChange;
#[allow(unused_imports)]
pub use seen::{HostSeenEntry, SeenChange, SeenEntry};
pub use traffic_snapshot::{SnapshotUpdate, TrafficSnapshot};

/// Tiempo máximo que SQLite espera a que se libere un bloqueo (en milisegundos).
const TIEMPO_ESPERA_BLOQUEO_MS: u64 = 5_000;

/// Columnas de INTERFACES en el mismo orden que reconstruye fila_a_interfaz.
const SQL_SELECCION_INTERFAZ: &str =
    "SELECT id, name, mac, ipv4, netmask, gateway, is_up, last_seen FROM INTERFACES";

/// Columnas de DEVICES en el mismo orden que reconstruye fila_a_dispositivo.
const SQL_SELECCION_DISPOSITIVO: &str =
    "SELECT id, mac, ip, hostname, vendor, interface_id, device_type, is_online,
            first_seen, last_seen, alias, notes, os_family, device_type_manual,
            last_fingerprint, model, dhcp_fingerprint, dhcp_vendor, dhcp_hostname,
            user_agent, os_source, watched FROM DEVICES";

/// Repositorio SQLite de Almenara.
#[derive(Debug)]
pub struct Repo {
    conn: SqliteConnection,
    path: PathBuf,
}

impl Repo {
    /// Abre la base de datos en path, crea directorios y aplica migraciones.
    ///
    /// Configura la conexión con journal_mode = WAL (mejor concurrencia entre
    /// lectura y escritura), foreign_keys = ON (se aplican las claves foráneas
    /// declaradas) y un busy_timeout de cinco segundos para esperar bloqueos de
    /// otro proceso o conexión.
    pub fn init(path: &Path) -> Result<Self> {
        if let Some(padre) = path.parent().filter(|padre| !padre.as_os_str().is_empty()) {
            std::fs::create_dir_all(padre).map_err(|err| Error::DatabaseOpen {
                path: path.to_path_buf(),
                reason: format!(
                    "no se pudo crear el directorio de la base de datos ({}): {err}",
                    padre.display()
                ),
            })?;
        }

        let mut conn =
            SqliteConnection::open(path).map_err(|err| Error::database_open(path, &err))?;

        conn.busy_timeout(Duration::from_millis(TIEMPO_ESPERA_BLOQUEO_MS))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Rendimiento de escritura (F6 §8: el lote del minuto con tráfico real
        // debe escribirse en ≤ 10 ms): en WAL, synchronous = NORMAL evita un
        // fsync por transacción y el autocheckpoint se desactiva (0); el
        // checkpoint se hace en la purga horaria, fuera del cierre del minuto,
        // para que el lote no pague el fsync periódico (picos de 11–20 ms con
        // el automático). La base sigue siendo íntegra; ante un corte de energía
        // se puede perder el último lote, nunca corromperse (compromiso habitual
        // de WAL con lectores concurrentes).
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "wal_autocheckpoint", 0)?;

        let modo_diario: String =
            conn.query_row("PRAGMA journal_mode = WAL", [], |fila| fila.get(0))?;
        if !modo_diario.eq_ignore_ascii_case("wal") {
            return Err(Error::DatabaseOpen {
                path: path.to_path_buf(),
                reason: format!("no se pudo activar el modo WAL (journal_mode = {modo_diario})"),
            });
        }

        migrations::apply_all(&mut conn)?;

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Ruta del fichero de base de datos abierto.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Acceso de solo lectura a la conexión (solo para pruebas internas).
    #[cfg(test)]
    pub fn connection(&self) -> &SqliteConnection {
        &self.conn
    }

    /// Acceso mutable a la conexión (solo para pruebas internas).
    #[cfg(test)]
    pub fn connection_mut(&mut self) -> &mut SqliteConnection {
        &mut self.conn
    }

    /// Inserta o actualiza una interfaz por nombre y devuelve su id.
    pub fn upsert_interface(&mut self, interface: &Interface) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(name) DO UPDATE SET
                 mac = excluded.mac,
                 ipv4 = excluded.ipv4,
                 netmask = excluded.netmask,
                 gateway = excluded.gateway,
                 is_up = excluded.is_up,
                 last_seen = excluded.last_seen",
            params![
                interface.name,
                interface.mac,
                interface.ipv4,
                interface.netmask,
                interface.gateway,
                interface.is_up,
                interface.last_seen
            ],
        )?;

        let id = self.conn.query_row(
            "SELECT id FROM INTERFACES WHERE name = ?1",
            params![interface.name],
            |fila| fila.get(0),
        )?;
        Ok(id)
    }

    /// Lista todas las interfaces persistidas, ordenadas por nombre.
    pub fn list_interfaces(&self) -> Result<Vec<Interface>> {
        let sql = format!("{SQL_SELECCION_INTERFAZ} ORDER BY name");
        let mut sentencia = self.conn.prepare(&sql)?;
        let filas = sentencia.query_map([], fila_a_interfaz)?;
        let mut interfaces = Vec::new();
        for fila in filas {
            interfaces.push(fila?);
        }
        Ok(interfaces)
    }

    /// Inserta o actualiza un dispositivo por MAC y devuelve id y cambios.
    ///
    /// En el alta se usa el momento actual como first_seen y last_seen y el
    /// dispositivo queda online. En la actualización se conservan el hostname y
    /// el vendor anteriores cuando la detección nueva no los trae, y se dejan
    /// intactos alias y notes. mac_changed siempre es None: el cambio de MAC se
    /// gestiona con Repo::update_device_mac.
    pub fn upsert_device(&mut self, upsert: &DeviceUpsert) -> Result<(i64, ChangeSet)> {
        let ahora = ahora_rfc3339();

        let Some(previo) = self.get_device_by_mac(&upsert.mac)? else {
            self.conn.execute(
                "INSERT INTO DEVICES (
                     mac, ip, hostname, vendor, interface_id, device_type,
                     is_online, first_seen, last_seen
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)",
                params![
                    upsert.mac,
                    upsert.ip,
                    upsert.hostname,
                    upsert.vendor,
                    upsert.interface_id,
                    upsert.device_type,
                    ahora
                ],
            )?;
            let id = self.conn.last_insert_rowid();
            return Ok((
                id,
                ChangeSet {
                    is_new: true,
                    ..ChangeSet::default()
                },
            ));
        };

        let hostname_efectivo = upsert.hostname.clone().or_else(|| previo.hostname.clone());
        let vendor_efectivo = upsert.vendor.clone().or_else(|| previo.vendor.clone());

        let mut cambios = ChangeSet::default();
        if previo.ip != upsert.ip {
            cambios.ip_changed = Some((previo.ip.clone(), upsert.ip.clone()));
        }
        if previo.hostname != hostname_efectivo {
            cambios.hostname_changed = Some((previo.hostname.clone(), hostname_efectivo.clone()));
        }
        cambios.became_online = !previo.is_online;

        self.conn.execute(
            "UPDATE DEVICES SET
                 ip = ?1,
                 hostname = ?2,
                 vendor = ?3,
                 interface_id = ?4,
                 device_type = ?5,
                 last_seen = ?6,
                 is_online = 1
             WHERE id = ?7",
            params![
                upsert.ip,
                hostname_efectivo,
                vendor_efectivo,
                upsert.interface_id,
                upsert.device_type,
                ahora,
                previo.id
            ],
        )?;

        Ok((previo.id, cambios))
    }

    /// Lista todos los dispositivos persistidos, ordenados por id.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let sql = format!("{SQL_SELECCION_DISPOSITIVO} ORDER BY id");
        let mut sentencia = self.conn.prepare(&sql)?;
        let filas = sentencia.query_map([], fila_a_dispositivo)?;
        let mut dispositivos = Vec::new();
        for fila in filas {
            dispositivos.push(fila?);
        }
        Ok(dispositivos)
    }

    /// Busca un dispositivo por MAC normalizada.
    pub fn get_device_by_mac(&self, mac: &str) -> Result<Option<Device>> {
        let sql = format!("{SQL_SELECCION_DISPOSITIVO} WHERE mac = ?1");
        let dispositivo = self
            .conn
            .query_row(&sql, params![mac], fila_a_dispositivo)
            .optional()?;
        Ok(dispositivo)
    }

    /// Busca un dispositivo por su última IPv4 conocida.
    ///
    /// Lo usan las fuentes pasivas de Fase 2 (mDNS, SSDP, DHCP) para asociar un
    /// anuncio a un equipo ya persistido cuando la MAC no viaja en el anuncio.
    pub fn get_device_by_ip(&self, ip: &str) -> Result<Option<Device>> {
        let sql = format!("{SQL_SELECCION_DISPOSITIVO} WHERE ip = ?1 ORDER BY id LIMIT 1");
        let dispositivo = self
            .conn
            .query_row(&sql, params![ip], fila_a_dispositivo)
            .optional()?;
        Ok(dispositivo)
    }

    /// Asigna o limpia el hostname de un dispositivo.
    ///
    /// Un hostname vacío o solo con espacios se guarda como NULL.
    pub fn set_hostname(&mut self, id: i64, hostname: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET hostname = ?1 WHERE id = ?2",
            params![normalizar_texto_opcional(hostname), id],
        )?;
        Ok(())
    }

    /// Persiste la familia de SO estimada por fingerprint.
    pub fn set_os_family(&mut self, id: i64, os_family: Option<OsFamily>) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET os_family = ?1 WHERE id = ?2",
            params![os_family.map(OsFamily::as_str), id],
        )?;
        Ok(())
    }

    /// Persiste el JSON del último fingerprint observado.
    pub fn set_last_fingerprint(&mut self, id: i64, fingerprint: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET last_fingerprint = ?1 WHERE id = ?2",
            params![normalizar_texto_opcional(fingerprint), id],
        )?;
        Ok(())
    }

    /// Asigna o limpia el override manual de device_type.
    pub fn set_device_type_manual(
        &mut self,
        id: i64,
        device_type: Option<DeviceType>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET device_type_manual = ?1 WHERE id = ?2",
            params![device_type.map(DeviceType::as_str), id],
        )?;
        Ok(())
    }

    /// Marca un dispositivo como online u offline.
    ///
    /// Si el id no existe la sentencia no modifica ninguna fila; es un no-op
    /// silencioso, igual que el resto de actualizaciones por id.
    pub fn set_device_online(&mut self, id: i64, online: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET is_online = ?1 WHERE id = ?2",
            params![online, id],
        )?;
        Ok(())
    }

    /// Cambia la MAC de un dispositivo (cambio de identidad detectado por IP).
    ///
    /// La MAC es única: si ya pertenece a otro dispositivo, el error UNIQUE de
    /// SQLite se propaga como Error::Database con un mensaje claro.
    pub fn update_device_mac(&mut self, id: i64, new_mac: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET mac = ?1 WHERE id = ?2",
            params![new_mac, id],
        )?;
        Ok(())
    }

    /// Asigna o limpia el alias manual de un dispositivo.
    ///
    /// Un alias vacío o formado solo por espacios se guarda como NULL; en caso
    /// contrario se recorta antes de persistirlo.
    pub fn set_alias(&mut self, id: i64, alias: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET alias = ?1 WHERE id = ?2",
            params![normalizar_texto_opcional(alias), id],
        )?;
        Ok(())
    }

    /// Asigna o limpia las notas libres de un dispositivo.
    ///
    /// Unas notas vacías o formadas solo por espacios se guardan como NULL; en
    /// caso contrario se recortan antes de persistirlas.
    pub fn set_notes(&mut self, id: i64, notes: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE DEVICES SET notes = ?1 WHERE id = ?2",
            params![normalizar_texto_opcional(notes), id],
        )?;
        Ok(())
    }

    /// Añade un evento al histórico del dispositivo.
    ///
    /// El created_at se genera en el momento de la llamada (RFC 3339 UTC). La
    /// clave foránea exige que el dispositivo exista. La reconciliación de F6
    /// usa `append_event_id`, que devuelve el id; se conserva como API de F1.
    #[allow(dead_code)]
    pub fn append_event(&mut self, device_id: i64, event: EventType, details: &str) -> Result<()> {
        self.append_event_id(device_id, event, details).map(|_| ())
    }

    /// Igual que [`Repo::append_event`] pero devuelve el id del evento creado.
    ///
    /// La F6 lo guarda en `ALERTS.event_id` como referencia lógica del origen de
    /// una alerta (§3).
    pub fn append_event_id(
        &mut self,
        device_id: i64,
        event: EventType,
        details: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![device_id, event.as_str(), details, ahora_rfc3339()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Elimina eventos más antiguos que retention_days y devuelve cuántos borró.
    pub fn prune_events(&mut self, retention_days: u32) -> Result<usize> {
        let corte = Utc::now() - chrono::Duration::days(i64::from(retention_days));
        let corte = corte.to_rfc3339_opts(SecondsFormat::Secs, true);
        let borrados = self.conn.execute(
            "DELETE FROM DEVICE_EVENTS WHERE created_at < ?1",
            params![corte],
        )?;
        Ok(borrados)
    }

    /// Lista los eventos de un dispositivo ordenados por fecha ascendente.
    ///
    /// Se ordena por created_at y, para los eventos del mismo segundo, por id
    /// (orden real de inserción). Las filas cuyo event_type no reconoce esta
    /// versión del programa se omiten sin devolver error.
    #[allow(dead_code)]
    pub fn list_events(&self, device_id: i64) -> Result<Vec<DeviceEvent>> {
        let mut sentencia = self.conn.prepare(
            "SELECT id, device_id, event_type, details, created_at
             FROM DEVICE_EVENTS
             WHERE device_id = ?1
             ORDER BY created_at ASC, id ASC",
        )?;
        let filas = sentencia.query_map(params![device_id], |fila| {
            let tipo: String = fila.get(2)?;
            let Some(event_type) = EventType::from_str(&tipo) else {
                return Ok(None);
            };
            Ok(Some(DeviceEvent {
                id: fila.get(0)?,
                device_id: fila.get(1)?,
                event_type,
                details: fila.get(3)?,
                created_at: fila.get(4)?,
            }))
        })?;

        let mut eventos = Vec::new();
        for fila in filas {
            if let Some(evento) = fila? {
                eventos.push(evento);
            }
        }
        Ok(eventos)
    }

    /// Inserta o actualiza un servicio detectado y devuelve su id.
    pub fn upsert_service(&mut self, servicio: &ServiceUpsert) -> Result<i64> {
        device_services::upsert(&self.conn, servicio)
    }

    /// Lista los servicios activos de un dispositivo.
    ///
    /// La usa la reconciliación para clasificar con los servicios ya
    /// persistidos; también llegará a la TUI con el detalle de F3.
    pub fn list_services(&self, device_id: i64) -> Result<Vec<DeviceService>> {
        device_services::list(&self.conn, device_id)
    }

    /// Cuenta los servicios de un dispositivo obsoletos desde el corte indicado.
    pub fn mark_stale_services(&self, device_id: i64, older_than: &str) -> Result<usize> {
        device_services::mark_stale(&self.conn, device_id, older_than)
    }

    /// Purga definitivamente los servicios con last_seen anterior al corte.
    pub fn prune_services(&mut self, older_than: &str) -> Result<usize> {
        device_services::prune(&self.conn, older_than)
    }

    /// Marca que una fuente de descubrimiento ha visto a un dispositivo.
    pub fn upsert_source(&mut self, device_id: i64, source: DiscoverySource) -> Result<()> {
        discovery_sources::upsert(&self.conn, device_id, source, &ahora_rfc3339())
    }

    /// Lista las fuentes de descubrimiento que han visto a un dispositivo.
    ///
    /// API del checklist de F2; la TUI aún no la consume. Cubierta por tests.
    #[allow(dead_code)]
    pub fn list_sources(&self, device_id: i64) -> Result<Vec<DiscoverySourceRow>> {
        discovery_sources::list(&self.conn, device_id)
    }

    /// Versión actual del esquema aplicado.
    pub fn schema_version(&self) -> Result<u32> {
        migrations::current_version(&self.conn)
    }

    /// Fuerza un checkpoint del WAL.
    ///
    /// Se llama en la purga horaria, fuera del cierre del minuto, para que los
    /// lotes del minuto no paguen el fsync del checkpoint automático (F6 §8).
    pub fn wal_checkpoint(&mut self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Número de dispositivos en la base de datos.
    pub fn count_devices(&self) -> Result<u32> {
        let total: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM DEVICES", [], |fila| fila.get(0))?;
        Ok(total)
    }
}

// API de persistencia de la Fase 3 (tráfico en vivo). Se permite dead_code
// hasta que la TUI de F3 la consuma, igual que ocurre con los DAOs de F2.
#[allow(dead_code)]
impl Repo {
    /// Guarda (o sobrescribe) el snapshot de tráfico de un dispositivo.
    ///
    /// TRAFFIC_SNAPSHOT es una tabla de estado, no histórica: el upsert es por
    /// device_id y refresca updated_at en cada ciclo de 5 s.
    pub fn upsert_snapshot(&mut self, snapshot: &SnapshotUpdate) -> Result<()> {
        traffic_snapshot::upsert(&self.conn, snapshot)
    }

    /// Lista los snapshots de tráfico persistidos, ordenados por device_id.
    ///
    /// La TUI los usa como semilla de las sparklines al arrancar.
    pub fn list_snapshots(&self) -> Result<Vec<TrafficSnapshot>> {
        traffic_snapshot::list(&self.conn)
    }

    /// Inserta o actualiza una conexión y devuelve su id.
    ///
    /// Con id en None el upsert es por 5-tuple canónica; con id en Some actualiza
    /// esa fila (y la reinserta si un ciclo de purga ya la había borrado).
    pub fn upsert_connection(&mut self, conexion: &ConnectionUpdate) -> Result<i64> {
        connections::upsert(&self.conn, conexion)
    }

    /// Lista las conexiones activas ordenadas por actividad reciente.
    ///
    /// Con filtro None devuelve todas; con Some(texto) casa por protocolo,
    /// estado o IP de origen/destino.
    pub fn list_connections(&self, filtro: Option<&str>) -> Result<Vec<Connection>> {
        connections::list(&self.conn, filtro)
    }

    /// Purga las conexiones que han superado su timeout sin tráfico.
    ///
    /// Se pasa `now` explícito (SystemTime en vez del Instant de la
    /// especificación) porque la purga compara contra fechas RFC 3339
    /// persistidas; en producción se usa SystemTime::now().
    pub fn prune_expired_connections(&mut self, now: SystemTime) -> Result<usize> {
        connections::prune_expired(&self.conn, now)
    }

    /// Recupera una conexión por id (panel de cabeceras de la tecla v).
    pub fn get_connection(&self, id: i64) -> Result<Option<Connection>> {
        connections::get(&self.conn, id)
    }
}

// API de persistencia de la Fase 4: caché de nombres e identidad de equipos.
#[allow(dead_code)]
impl Repo {
    /// Persiste las entradas nuevas o refrescadas de la caché de nombres (§7.7).
    ///
    /// Devuelve cuántas entradas se han escrito. La caducidad no se filtra
    /// aquí: el mismo ciclo de 5 s llama después a Repo::prune_names.
    pub fn upsert_names(&mut self, entradas: &[NameEntry]) -> Result<usize> {
        names::upsert(&self.conn, entradas)
    }

    /// Lista las entradas de NAME_CACHE vigentes en el instante indicado.
    ///
    /// Se usa al arrancar en caliente; el equipo que hizo cada consulta no se
    /// persiste, así que las entradas vuelven con `requester = None`.
    pub fn list_names(&self, ahora: SystemTime) -> Result<Vec<NameEntry>> {
        names::list(&self.conn, ahora)
    }

    /// Purga las entradas de NAME_CACHE caducadas en el instante indicado.
    pub fn prune_names(&mut self, ahora: SystemTime) -> Result<usize> {
        names::prune(&self.conn, ahora)
    }

    /// Actualiza la identidad de un dispositivo con las señales de la captura.
    ///
    /// Los campos a None conservan el valor anterior, porque las señales llegan
    /// en momentos distintos (huella DHCP, modelo mDNS/UPnP, User-Agent) y no
    /// deben pisarse entre sí. Cuando llega una familia de SO nueva se escribe
    /// también su fuente (`os_source`), que puede quedar a NULL. Los textos se
    /// recortan y se truncan a los máximos de §3.
    pub fn set_device_identity(&mut self, device_id: i64, upd: &IdentityUpdate) -> Result<()> {
        let model = texto_identidad(upd.model.as_deref(), MAX_MODEL);
        let dhcp_fingerprint = normalizar_texto_opcional(upd.dhcp_fingerprint.as_deref());
        let dhcp_vendor = texto_identidad(upd.dhcp_vendor.as_deref(), MAX_DHCP_TEXTO);
        let dhcp_hostname = texto_identidad(upd.dhcp_hostname.as_deref(), MAX_DHCP_TEXTO);
        let user_agent = texto_identidad(upd.user_agent.as_deref(), MAX_USER_AGENT);

        self.conn.execute(
            "UPDATE DEVICES SET
                 model = COALESCE(?1, model),
                 dhcp_fingerprint = COALESCE(?2, dhcp_fingerprint),
                 dhcp_vendor = COALESCE(?3, dhcp_vendor),
                 dhcp_hostname = COALESCE(?4, dhcp_hostname),
                 user_agent = COALESCE(?5, user_agent),
                 os_family = CASE WHEN ?6 IS NULL THEN os_family ELSE ?6 END,
                 os_source = CASE WHEN ?6 IS NULL THEN os_source ELSE ?7 END
             WHERE id = ?8",
            params![
                model,
                dhcp_fingerprint,
                dhcp_vendor,
                dhcp_hostname,
                user_agent,
                upd.os_family.map(OsFamily::as_str),
                upd.os_source.map(OsSource::as_str),
                device_id
            ],
        )?;
        Ok(())
    }
}

/// Longitud máxima de DEVICES.model (§3).
const MAX_MODEL: usize = 64;
/// Longitud máxima de los textos DHCP saneados de DEVICES (§3).
const MAX_DHCP_TEXTO: usize = 64;
/// Longitud máxima de DEVICES.user_agent (§3).
const MAX_USER_AGENT: usize = 256;

/// Marca temporal actual en RFC 3339 UTC con precisión de segundos.
///
/// Es el formato único de la capa de persistencia; lo usan las migraciones y
/// todas las operaciones que guardan fechas.
pub(crate) fn ahora_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Convierte un instante a RFC 3339 UTC con precisión de segundos.
///
/// Es la conversión inversa de [rfc3339_a_instante]; la usan los DAOs que
/// manejan fechas tipadas como SystemTime (por ejemplo NAME_CACHE).
pub(crate) fn instante_a_rfc3339(instante: SystemTime) -> String {
    let fecha: chrono::DateTime<Utc> = instante.into();
    fecha.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Convierte una fecha RFC 3339 al instante correspondiente.
///
/// Devuelve None si el texto no es una fecha RFC 3339 válida (dato corrupto en
/// la base de datos); nunca entra en pánico.
pub(crate) fn rfc3339_a_instante(texto: &str) -> Option<SystemTime> {
    chrono::DateTime::parse_from_rfc3339(texto)
        .ok()
        .map(|fecha| fecha.with_timezone(&Utc).into())
}

/// Reconstruye una interfaz a partir de una fila de SQL_SELECCION_INTERFAZ.
fn fila_a_interfaz(fila: &Row<'_>) -> rusqlite::Result<Interface> {
    Ok(Interface {
        id: fila.get(0)?,
        name: fila.get(1)?,
        mac: fila.get(2)?,
        ipv4: fila.get(3)?,
        netmask: fila.get(4)?,
        gateway: fila.get(5)?,
        is_up: fila.get(6)?,
        last_seen: fila.get(7)?,
    })
}

/// Reconstruye un dispositivo a partir de una fila de SQL_SELECCION_DISPOSITIVO.
fn fila_a_dispositivo(fila: &Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: fila.get(0)?,
        mac: fila.get(1)?,
        ip: fila.get(2)?,
        hostname: fila.get(3)?,
        vendor: fila.get(4)?,
        interface_id: fila.get(5)?,
        device_type: fila.get(6)?,
        is_online: fila.get(7)?,
        first_seen: fila.get(8)?,
        last_seen: fila.get(9)?,
        alias: fila.get(10)?,
        notes: fila.get(11)?,
        os_family: fila.get(12)?,
        device_type_manual: fila.get(13)?,
        last_fingerprint: fila.get(14)?,
        model: fila.get(15)?,
        dhcp_fingerprint: fila.get(16)?,
        dhcp_vendor: fila.get(17)?,
        dhcp_hostname: fila.get(18)?,
        user_agent: fila.get(19)?,
        os_source: fila.get(20)?,
        watched: fila.get(21)?,
    })
}

/// Normaliza un texto opcional: recorta y convierte el vacío en None.
fn normalizar_texto_opcional(valor: Option<&str>) -> Option<String> {
    valor
        .map(|texto| texto.trim())
        .filter(|texto| !texto.is_empty())
        .map(str::to_string)
}

/// Normaliza un texto opcional de identidad y lo trunca a un máximo de
/// caracteres (no de bytes), como piden las columnas de DEVICES en §3.
fn texto_identidad(valor: Option<&str>, maximo: usize) -> Option<String> {
    normalizar_texto_opcional(valor).map(|texto| texto.chars().take(maximo).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::identify::OsSource;
    use crate::inference::names::NameEntry;
    use crate::inference::NameSource;
    use rusqlite::params;
    use tempfile::{tempdir, TempDir};

    const MAC_PRIMERA: &str = "aa:bb:cc:dd:ee:01";
    const MAC_SEGUNDA: &str = "aa:bb:cc:dd:ee:02";

    /// Abre un repositorio sobre un fichero data.db dentro del directorio dado.
    ///
    /// El directorio se declara antes que el repositorio en cada test, así que el
    /// repositorio (y su conexión) se libera primero al terminar el test.
    fn repo_temporal(directorio: &TempDir) -> Repo {
        Repo::init(&directorio.path().join("data.db")).expect("inicializar el repositorio")
    }

    /// Crea un repositorio con una interfaz eth0 y devuelve el id de la interfaz.
    fn repo_con_interfaz(directorio: &TempDir) -> (Repo, i64) {
        let mut repo = repo_temporal(directorio);
        let id = repo
            .upsert_interface(&interfaz("eth0"))
            .expect("insertar la interfaz eth0");
        (repo, id)
    }

    /// Interfaz de prueba con valores válidos.
    fn interfaz(nombre: &str) -> Interface {
        Interface::without_id(
            nombre,
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("192.168.1.10".to_string()),
            Some("255.255.255.0".to_string()),
            Some("192.168.1.1".to_string()),
            true,
            ahora_rfc3339(),
        )
    }

    /// Datos de upsert mínimos para una MAC e IP dadas.
    fn upsert(mac: &str, ip: &str, interface_id: i64) -> DeviceUpsert {
        DeviceUpsert {
            mac: mac.to_string(),
            ip: ip.to_string(),
            hostname: None,
            vendor: None,
            interface_id,
            device_type: "unknown".to_string(),
        }
    }

    #[test]
    fn init_crea_directorios_y_aplica_migraciones() {
        let directorio = tempdir().expect("crear directorio temporal");
        let ruta = directorio
            .path()
            .join("sub")
            .join("directorio")
            .join("data.db");
        let repo = Repo::init(&ruta).expect("inicializar la base de datos");

        assert!(ruta.exists(), "debe existir el fichero de base de datos");
        assert_eq!(repo.path(), ruta.as_path());
        assert_eq!(repo.schema_version().expect("leer versión"), 6);
        assert_eq!(repo.count_devices().expect("contar dispositivos"), 0);
    }

    #[test]
    fn init_dos_veces_no_falla_ni_duplica_migraciones() {
        let directorio = tempdir().expect("crear directorio temporal");
        let ruta = directorio.path().join("data.db");

        let primera = Repo::init(&ruta).expect("primer init");
        assert_eq!(primera.schema_version().expect("leer versión"), 6);
        drop(primera);

        let segunda = Repo::init(&ruta).expect("segundo init sobre el mismo fichero");
        assert_eq!(segunda.schema_version().expect("leer versión"), 6);
    }

    #[test]
    fn init_deja_el_esquema_y_los_pragmas_configurados() {
        let directorio = tempdir().expect("crear directorio temporal");
        let repo = repo_temporal(&directorio);

        let tablas: i64 = repo
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table'
                   AND name IN ('INTERFACES', 'DEVICES', 'DEVICE_EVENTS',
                                 'DEVICE_SERVICES', 'DISCOVERY_SOURCES',
                                 'SCHEMA_MIGRATIONS', 'TRAFFIC_SNAPSHOT',
                                 'CONNECTIONS', 'NAME_CACHE',
                                 'TRAFFIC_ROLLUP_MINUTE', 'TRAFFIC_ROLLUP_HOUR',
                                 'TRAFFIC_ROLLUP_DAY', 'DEVICE_SEEN',
                                 'APP_SESSIONS')",
                [],
                |fila| fila.get(0),
            )
            .expect("contar tablas del esquema");
        assert_eq!(tablas, 14, "deben existir las catorce tablas del esquema");

        let modo: String = repo
            .connection()
            .query_row("PRAGMA journal_mode", [], |fila| fila.get(0))
            .expect("leer journal_mode");
        assert_eq!(modo.to_lowercase(), "wal", "journal_mode debe ser WAL");

        let claves_foraneas: i64 = repo
            .connection()
            .query_row("PRAGMA foreign_keys", [], |fila| fila.get(0))
            .expect("leer foreign_keys");
        assert_eq!(
            claves_foraneas, 1,
            "las claves foráneas deben estar activas"
        );

        let espera: i64 = repo
            .connection()
            .query_row("PRAGMA busy_timeout", [], |fila| fila.get(0))
            .expect("leer busy_timeout");
        assert_eq!(espera, 5_000, "busy_timeout debe ser de cinco segundos");
    }

    #[test]
    fn upsert_interface_inserta_actualiza_y_ordena_sin_duplicar() {
        let directorio = tempdir().expect("crear directorio temporal");
        let mut repo = repo_temporal(&directorio);

        let id = repo
            .upsert_interface(&interfaz("eth0"))
            .expect("insertar la interfaz");

        let mut actualizada = interfaz("eth0");
        actualizada.mac = Some("aa:bb:cc:00:00:02".to_string());
        actualizada.ipv4 = Some("192.168.1.20".to_string());
        actualizada.gateway = None;
        actualizada.is_up = false;
        actualizada.last_seen = ahora_rfc3339();
        let id_repetido = repo
            .upsert_interface(&actualizada)
            .expect("actualizar la interfaz");

        assert_eq!(id, id_repetido, "el upsert debe conservar el id");

        repo.upsert_interface(&interfaz("wlan0"))
            .expect("insertar la interfaz wlan0");
        let interfaces = repo.list_interfaces().expect("listar interfaces");

        assert_eq!(interfaces.len(), 2, "no debe duplicar la interfaz eth0");
        let nombres: Vec<&str> = interfaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(nombres, vec!["eth0", "wlan0"], "se ordenan por nombre");
        assert_eq!(interfaces[0].id, id);
        assert_eq!(interfaces[0].mac.as_deref(), Some("aa:bb:cc:00:00:02"));
        assert_eq!(interfaces[0].ipv4.as_deref(), Some("192.168.1.20"));
        assert_eq!(interfaces[0].gateway, None);
        assert!(!interfaces[0].is_up);
    }

    #[test]
    fn upsert_device_nuevo_y_repetido_sin_cambios() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);

        let datos = upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz);
        let (id, cambios) = repo.upsert_device(&datos).expect("alta inicial");

        assert!(cambios.is_new, "la primera vez debe marcarse como nuevo");
        assert_eq!(cambios.ip_changed, None);
        assert_eq!(cambios.hostname_changed, None);
        assert_eq!(cambios.mac_changed, None);
        assert!(!cambios.became_online);
        assert_eq!(repo.count_devices().expect("contar"), 1);

        let (id_repetido, cambios_repetidos) = repo
            .upsert_device(&datos)
            .expect("upsert de un dispositivo ya conocido");
        assert_eq!(id, id_repetido, "el upsert debe conservar el id");
        assert_eq!(
            cambios_repetidos,
            ChangeSet::default(),
            "repetir los mismos datos no debe reportar cambios"
        );
        assert_eq!(repo.count_devices().expect("contar"), 1);

        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir el dispositivo");
        assert_eq!(dispositivo.id, id);
        assert_eq!(dispositivo.ip, "192.168.1.50");
        assert!(dispositivo.is_online);
        assert_eq!(dispositivo.interface_id, id_interfaz);
        assert_eq!(dispositivo.device_type, "unknown");
        assert!(repo
            .get_device_by_mac("aa:bb:cc:dd:ee:99")
            .expect("buscar una MAC inexistente")
            .is_none());
    }

    #[test]
    fn upsert_device_detecta_cambio_de_ip_y_hostname() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);

        let mut datos = upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz);
        datos.hostname = Some("impresora".to_string());
        datos.vendor = Some("HP".to_string());
        let (id, _) = repo.upsert_device(&datos).expect("alta inicial");

        let mut actualizados = datos.clone();
        actualizados.ip = "192.168.1.51".to_string();
        actualizados.hostname = Some("impresora-nueva".to_string());
        actualizados.vendor = None;
        actualizados.device_type = "gateway".to_string();
        let (id_repetido, cambios) = repo
            .upsert_device(&actualizados)
            .expect("upsert con cambios");

        assert_eq!(id, id_repetido);
        assert_eq!(
            cambios.ip_changed,
            Some(("192.168.1.50".to_string(), "192.168.1.51".to_string()))
        );
        assert_eq!(
            cambios.hostname_changed,
            Some((
                Some("impresora".to_string()),
                Some("impresora-nueva".to_string())
            ))
        );
        assert_eq!(cambios.mac_changed, None);
        assert!(!cambios.became_online);

        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir");
        assert_eq!(dispositivo.ip, "192.168.1.51");
        assert_eq!(dispositivo.hostname.as_deref(), Some("impresora-nueva"));
        assert_eq!(
            dispositivo.vendor.as_deref(),
            Some("HP"),
            "un vendor desconocido no debe borrar el anterior"
        );
        assert_eq!(dispositivo.device_type, "gateway");
    }

    #[test]
    fn hostname_none_conserva_el_anterior() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);

        let mut datos = upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz);
        datos.hostname = Some("router".to_string());
        repo.upsert_device(&datos).expect("alta con hostname");

        // Sin hostname nuevo y con la misma IP: no hay cambio de hostname.
        let mut sin_hostname = datos.clone();
        sin_hostname.hostname = None;
        let (_, cambios) = repo
            .upsert_device(&sin_hostname)
            .expect("upsert sin hostname");

        assert_eq!(cambios.hostname_changed, None);
        assert_eq!(cambios.ip_changed, None);
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir");
        assert_eq!(dispositivo.hostname.as_deref(), Some("router"));
    }

    #[test]
    fn became_online_cuando_reaparece_un_dispositivo_offline() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);

        let datos = upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz);
        let (id, _) = repo.upsert_device(&datos).expect("alta inicial");
        repo.set_device_online(id, false)
            .expect("marcar el dispositivo offline");
        assert!(!repo.list_devices().expect("listar")[0].is_online);

        let (_, cambios) = repo.upsert_device(&datos).expect("reaparición");
        assert!(
            cambios.became_online,
            "debe detectar que vuelve a estar online"
        );
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir");
        assert!(dispositivo.is_online);

        // Un upsert inmediatamente posterior ya no reporta la transición.
        let (_, cambios) = repo.upsert_device(&datos).expect("upsert posterior");
        assert!(!cambios.became_online);
    }

    #[test]
    fn set_device_online_se_refleja_en_list_devices() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);
        let (id, _) = repo
            .upsert_device(&upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz))
            .expect("alta inicial");

        assert!(repo.list_devices().expect("listar")[0].is_online);
        repo.set_device_online(id, false).expect("marcar offline");
        assert!(!repo.list_devices().expect("listar")[0].is_online);
        repo.set_device_online(id, true).expect("marcar online");
        assert!(repo.list_devices().expect("listar")[0].is_online);
    }

    #[test]
    fn set_alias_y_notes_ponen_y_limpian() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);
        let datos = upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz);
        let (id, _) = repo.upsert_device(&datos).expect("alta inicial");

        repo.set_alias(id, Some("  portátil salón  "))
            .expect("guardar alias");
        repo.set_notes(id, Some("no tocar")).expect("guardar notas");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir");
        assert_eq!(dispositivo.alias.as_deref(), Some("portátil salón"));
        assert_eq!(dispositivo.notes.as_deref(), Some("no tocar"));

        // El upsert de un escaneo no debe pisar alias ni notas.
        repo.upsert_device(&upsert(MAC_PRIMERA, "192.168.1.60", id_interfaz))
            .expect("upsert posterior");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir");
        assert_eq!(dispositivo.alias.as_deref(), Some("portátil salón"));
        assert_eq!(dispositivo.notes.as_deref(), Some("no tocar"));

        // Textos vacíos o solo con espacios se convierten en NULL.
        repo.set_alias(id, Some("   ")).expect("limpiar alias");
        repo.set_notes(id, Some("")).expect("limpiar notas");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir");
        assert_eq!(dispositivo.alias, None);
        assert_eq!(dispositivo.notes, None);

        // Y también se pueden limpiar con None.
        repo.set_alias(id, Some("tablet")).expect("guardar alias");
        repo.set_alias(id, None).expect("limpiar alias con None");
        repo.set_notes(id, None).expect("limpiar notas con None");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar por MAC")
            .expect("debe existir");
        assert_eq!(dispositivo.alias, None);
        assert_eq!(dispositivo.notes, None);
    }

    #[test]
    fn update_device_mac_respeta_la_restriccion_unique() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);
        let (id_primera, _) = repo
            .upsert_device(&upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz))
            .expect("alta del primer dispositivo");
        repo.upsert_device(&upsert(MAC_SEGUNDA, "192.168.1.51", id_interfaz))
            .expect("alta del segundo dispositivo");

        // Cambiar a una MAC que ya pertenece a otro dispositivo debe fallar.
        let error = repo
            .update_device_mac(id_primera, MAC_SEGUNDA)
            .expect_err("la MAC ya existe y debe fallar");
        assert!(matches!(error, Error::Database(_)));
        assert!(
            error.to_string().contains("UNIQUE"),
            "el error debe explicar el conflicto de unicidad: {error}"
        );
        assert_eq!(
            repo.get_device_by_mac(MAC_PRIMERA)
                .expect("buscar por MAC")
                .expect("debe existir")
                .id,
            id_primera
        );

        // Cambiar a una MAC libre debe funcionar.
        let mac_libre = "aa:bb:cc:dd:ee:03";
        repo.update_device_mac(id_primera, mac_libre)
            .expect("cambiar a una MAC libre");
        assert!(repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar la MAC antigua")
            .is_none());
        assert_eq!(
            repo.get_device_by_mac(mac_libre)
                .expect("buscar la MAC nueva")
                .expect("debe existir")
                .id,
            id_primera
        );
    }

    #[test]
    fn append_event_list_events_y_prune_events() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);
        let (id, _) = repo
            .upsert_device(&upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz))
            .expect("alta inicial");

        repo.append_event(id, EventType::New, r#"{"before":null}"#)
            .expect("registrar evento new");
        repo.append_event(id, EventType::IpChanged, r#"{"before":"192.168.1.49"}"#)
            .expect("registrar evento ip_changed");

        let eventos = repo.list_events(id).expect("listar eventos");
        assert_eq!(eventos.len(), 2);
        assert_eq!(eventos[0].event_type, EventType::New);
        assert_eq!(eventos[1].event_type, EventType::IpChanged);
        assert_eq!(eventos[0].device_id, id);
        assert!(eventos[0].id < eventos[1].id, "mismo segundo: orden por id");
        assert_eq!(eventos[1].details, r#"{"before":"192.168.1.49"}"#);
        assert!(eventos[0].created_at.ends_with('Z'));

        // Evento retroactivo insertado a mano: debe poder podarse.
        repo.connection()
            .execute(
                "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, "disappeared", "{}", "2020-01-01T00:00:00Z"],
            )
            .expect("insertar evento antiguo");
        assert_eq!(repo.list_events(id).expect("listar eventos").len(), 3);

        let podados = repo.prune_events(90).expect("podar eventos");
        assert_eq!(podados, 1, "solo debe podarse el evento de 2020");
        let restantes = repo.list_events(id).expect("listar tras podar");
        assert_eq!(restantes.len(), 2);
        assert!(restantes
            .iter()
            .all(|evento| evento.created_at != "2020-01-01T00:00:00Z"));
    }

    #[test]
    fn list_events_filtra_por_dispositivo_y_omite_tipos_desconocidos() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id_interfaz) = repo_con_interfaz(&directorio);
        let (primera, _) = repo
            .upsert_device(&upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz))
            .expect("alta del primer dispositivo");
        let (segunda, _) = repo
            .upsert_device(&upsert(MAC_SEGUNDA, "192.168.1.51", id_interfaz))
            .expect("alta del segundo dispositivo");

        repo.append_event(primera, EventType::New, "{}")
            .expect("evento del primer dispositivo");
        repo.append_event(segunda, EventType::New, "{}")
            .expect("evento del segundo dispositivo");

        assert_eq!(repo.list_events(primera).expect("listar").len(), 1);
        assert_eq!(repo.list_events(segunda).expect("listar").len(), 1);

        // Un tipo de evento desconocido (versión futura) se omite sin error.
        repo.connection()
            .execute(
                "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![primera, "evento_futuro", "{}", ahora_rfc3339()],
            )
            .expect("insertar evento desconocido");
        let eventos = repo.list_events(primera).expect("listar eventos");
        assert_eq!(eventos.len(), 1, "el tipo desconocido debe omitirse");
        assert_eq!(eventos[0].event_type, EventType::New);
    }

    #[test]
    fn dos_repos_sobre_el_mismo_fichero_operan_secuencialmente() {
        let directorio = tempdir().expect("crear directorio temporal");
        let ruta = directorio.path().join("data.db");

        let mut primero = Repo::init(&ruta).expect("primer repositorio");
        let id_interfaz = primero
            .upsert_interface(&interfaz("eth0"))
            .expect("insertar interfaz desde el primer repositorio");

        // El segundo repositorio se abre con el primero aún vivo (modo WAL).
        let mut segundo = Repo::init(&ruta).expect("segundo repositorio sobre el mismo fichero");
        assert_eq!(segundo.schema_version().expect("leer versión"), 6);
        assert_eq!(segundo.list_interfaces().expect("listar").len(), 1);

        segundo
            .upsert_device(&upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz))
            .expect("escribir desde el segundo repositorio");
        assert_eq!(
            primero.count_devices().expect("contar desde el primero"),
            1,
            "el primero debe ver lo escrito por el segundo"
        );

        primero
            .upsert_device(&upsert(MAC_SEGUNDA, "192.168.1.51", id_interfaz))
            .expect("escribir desde el primer repositorio");
        assert_eq!(
            segundo.count_devices().expect("contar desde el segundo"),
            2,
            "el segundo debe ver lo escrito por el primero"
        );

        // La interfaz también es visible y actualizable desde ambos.
        let id_actualizado = segundo
            .upsert_interface(&interfaz("eth0"))
            .expect("actualizar interfaz desde el segundo");
        assert_eq!(id_actualizado, id_interfaz);
        assert_eq!(primero.list_interfaces().expect("listar").len(), 1);
    }

    /// Crea un repositorio con una interfaz y un dispositivo de prueba.
    fn repo_con_dispositivo(directorio: &TempDir) -> (Repo, i64) {
        let (mut repo, id_interfaz) = repo_con_interfaz(directorio);
        let (id, _) = repo
            .upsert_device(&upsert(MAC_PRIMERA, "192.168.1.50", id_interfaz))
            .expect("alta del dispositivo");
        (repo, id)
    }

    #[test]
    fn upsert_service_lista_y_actualiza_por_puerto_y_protocolo() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);

        let servicio = ServiceUpsert {
            device_id: id,
            port: 22,
            protocol: Protocol::Tcp,
            service: Some("ssh".to_string()),
            banner: Some("SSH-2.0-OpenSSH_9.6".to_string()),
        };
        let id_servicio = repo.upsert_service(&servicio).expect("insertar servicio");
        assert!(id_servicio > 0);

        let servicios = repo.list_services(id).expect("listar servicios");
        assert_eq!(servicios.len(), 1);
        assert_eq!(servicios[0].port, 22);
        assert_eq!(servicios[0].protocol, Protocol::Tcp);
        assert_eq!(servicios[0].service.as_deref(), Some("ssh"));
        assert!(servicios[0].last_seen.ends_with('Z'));

        // Repetir el upsert no duplica y actualiza last_seen/banner.
        let mut actualizado = servicio.clone();
        actualizado.banner = Some("SSH-2.0-OpenSSH_9.7".to_string());
        repo.upsert_service(&actualizado)
            .expect("actualizar servicio");
        let servicios = repo.list_services(id).expect("listar servicios");
        assert_eq!(servicios.len(), 1);
        assert_eq!(servicios[0].banner.as_deref(), Some("SSH-2.0-OpenSSH_9.7"));

        // Un None no borra el servicio ni el banner anteriores.
        let sin_datos = ServiceUpsert {
            device_id: id,
            port: 22,
            protocol: Protocol::Tcp,
            service: None,
            banner: None,
        };
        repo.upsert_service(&sin_datos).expect("upsert sin datos");
        let servicios = repo.list_services(id).expect("listar servicios");
        assert_eq!(servicios[0].service.as_deref(), Some("ssh"));
        assert!(servicios[0].banner.is_some());

        // Otro protocolo en el mismo puerto es una fila distinta.
        let udp = ServiceUpsert {
            device_id: id,
            port: 22,
            protocol: Protocol::Udp,
            service: None,
            banner: None,
        };
        repo.upsert_service(&udp).expect("insertar udp");
        assert_eq!(repo.list_services(id).expect("listar").len(), 2);
    }

    #[test]
    fn mark_stale_y_prune_services_respetan_el_corte() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);
        for puerto in [22_u16, 80, 443] {
            repo.upsert_service(&ServiceUpsert {
                device_id: id,
                port: puerto,
                protocol: Protocol::Tcp,
                service: None,
                banner: None,
            })
            .expect("insertar servicio");
        }

        // Un corte en el pasado no marca nada; uno en el futuro los marca todos.
        assert_eq!(
            repo.mark_stale_services(id, "2000-01-01T00:00:00Z")
                .expect("marcar obsoletos"),
            0
        );
        assert_eq!(
            repo.mark_stale_services(id, "2999-01-01T00:00:00Z")
                .expect("marcar obsoletos"),
            3
        );
        assert_eq!(repo.list_services(id).expect("listar").len(), 3);

        let borrados = repo
            .prune_services("2999-01-01T00:00:00Z")
            .expect("purgar servicios");
        assert_eq!(borrados, 3);
        assert!(repo.list_services(id).expect("listar").is_empty());
        assert_eq!(
            repo.prune_services("2999-01-01T00:00:00Z")
                .expect("purgar de nuevo"),
            0
        );
    }

    #[test]
    fn upsert_source_y_list_sources() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);

        for fuente in [DiscoverySource::Arp, DiscoverySource::Mdns] {
            repo.upsert_source(id, fuente).expect("marcar fuente");
        }
        // Repetir la misma fuente actualiza last_seen sin duplicar.
        repo.upsert_source(id, DiscoverySource::Arp)
            .expect("repetir fuente");

        let fuentes = repo.list_sources(id).expect("listar fuentes");
        assert_eq!(fuentes.len(), 2);
        assert_eq!(fuentes[0].source, DiscoverySource::Arp);
        assert_eq!(fuentes[1].source, DiscoverySource::Mdns);
        assert!(fuentes.iter().all(|fila| fila.device_id == id));
    }

    #[test]
    fn os_family_y_override_manual_se_persisten() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);

        repo.set_os_family(id, Some(OsFamily::Linux))
            .expect("guardar os_family");
        repo.set_last_fingerprint(id, Some("{\"ttl\":64}"))
            .expect("guardar fingerprint");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.os_family.as_deref(), Some("linux"));
        assert_eq!(
            dispositivo.last_fingerprint.as_deref(),
            Some("{\"ttl\":64}")
        );
        assert_eq!(dispositivo.effective_device_type(), "unknown");

        // El override manual manda sobre el tipo automático.
        repo.set_device_type_manual(id, Some(DeviceType::Pc))
            .expect("guardar override");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.device_type, "unknown");
        assert_eq!(dispositivo.effective_device_type(), "pc");
        assert!(!dispositivo.is_gateway());

        // Limpiar el override devuelve el tipo automático.
        repo.set_device_type_manual(id, None)
            .expect("limpiar override");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.effective_device_type(), "unknown");
        assert_eq!(dispositivo.device_type_manual, None);

        // Limpiar os_family también funciona.
        repo.set_os_family(id, None).expect("limpiar os_family");
        assert_eq!(
            repo.get_device_by_mac(MAC_PRIMERA)
                .expect("buscar")
                .expect("existe")
                .os_family,
            None
        );
    }

    #[test]
    fn get_device_by_ip_y_set_hostname() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);

        let dispositivo = repo
            .get_device_by_ip("192.168.1.50")
            .expect("buscar por IP")
            .expect("debe existir");
        assert_eq!(dispositivo.id, id);
        assert!(repo
            .get_device_by_ip("192.168.1.99")
            .expect("buscar IP inexistente")
            .is_none());

        repo.set_hostname(id, Some("  impresora.local  "))
            .expect("guardar hostname");
        assert_eq!(
            repo.get_device_by_mac(MAC_PRIMERA)
                .expect("buscar")
                .expect("existe")
                .hostname
                .as_deref(),
            Some("impresora.local")
        );
        repo.set_hostname(id, Some("   "))
            .expect("limpiar hostname");
        assert_eq!(
            repo.get_device_by_mac(MAC_PRIMERA)
                .expect("buscar")
                .expect("existe")
                .hostname,
            None
        );
    }

    #[test]
    fn upsert_snapshot_y_list_snapshots_persisten_por_dispositivo() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);

        let primero = SnapshotUpdate {
            device_id: id,
            bytes_in: 1_024,
            bytes_out: 2_048,
            packets_in: 10,
            packets_out: 20,
            peak_bps: 4_096,
            window_s: 60,
        };
        repo.upsert_snapshot(&primero).expect("guardar snapshot");

        let snapshots = repo.list_snapshots().expect("listar snapshots");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].device_id, id);
        assert_eq!(snapshots[0].bytes_in, 1_024);
        assert_eq!(snapshots[0].bytes_out, 2_048);
        assert_eq!(snapshots[0].peak_bps, 4_096);
        assert_eq!(snapshots[0].window_s, 60);
        assert!(snapshots[0].updated_at.ends_with('Z'));

        // El siguiente ciclo de 5 s sobrescribe la misma fila.
        let segundo = SnapshotUpdate {
            bytes_in: 3_000,
            peak_bps: 8_192,
            ..primero
        };
        repo.upsert_snapshot(&segundo)
            .expect("sobrescribir snapshot");
        let snapshots = repo.list_snapshots().expect("listar snapshots");
        assert_eq!(snapshots.len(), 1, "un equipo solo tiene un snapshot");
        assert_eq!(snapshots[0].bytes_in, 3_000);
        assert_eq!(snapshots[0].peak_bps, 8_192);
    }

    #[test]
    fn upsert_connection_por_cinco_tupla_lista_filtra_y_get() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);

        let conexion = ConnectionUpdate {
            id: None,
            device_id: Some(id),
            protocol: ConnectionProtocol::Tcp,
            src_ip: "192.168.1.50".to_string(),
            src_port: Some(40_000),
            dst_ip: "93.184.216.34".to_string(),
            dst_port: Some(443),
            state: Some("ESTABLISHED".to_string()),
            bytes_in: 100,
            bytes_out: 200,
            client_is_src: Some(true),
            app_protocol: Some("tls".to_string()),
            server_name: Some("example.com".to_string()),
            name_source: Some("sni".to_string()),
            app: Some("ejemplo".to_string()),
            category: Some("otros".to_string()),
            app_source: Some("domain".to_string()),
            ja4: Some("t13d1516h2_8daaf6152771_02713d6af862".to_string()),
        };
        let id_conexion = repo
            .upsert_connection(&conexion)
            .expect("insertar conexión");
        assert!(id_conexion > 0);

        let conexiones = repo.list_connections(None).expect("listar conexiones");
        assert_eq!(conexiones.len(), 1);
        assert_eq!(conexiones[0].id, id_conexion);
        assert_eq!(conexiones[0].device_id, Some(id));
        assert_eq!(conexiones[0].protocol, ConnectionProtocol::Tcp);
        assert_eq!(conexiones[0].src_port, Some(40_000));
        assert_eq!(conexiones[0].dst_port, Some(443));
        assert_eq!(conexiones[0].client_is_src, Some(true));
        assert_eq!(conexiones[0].app_protocol.as_deref(), Some("tls"));
        assert_eq!(conexiones[0].server_name.as_deref(), Some("example.com"));
        assert_eq!(conexiones[0].name_source.as_deref(), Some("sni"));
        assert_eq!(conexiones[0].app.as_deref(), Some("ejemplo"));
        assert_eq!(conexiones[0].category.as_deref(), Some("otros"));
        assert_eq!(conexiones[0].app_source.as_deref(), Some("domain"));
        assert_eq!(
            conexiones[0].ja4.as_deref(),
            Some("t13d1516h2_8daaf6152771_02713d6af862")
        );

        // El update por 5-tuple conserva el id y first_seen.
        let mut actualizada = conexion.clone();
        actualizada.bytes_in = 500;
        actualizada.state = Some("CLOSE_WAIT".to_string());
        let id_repetido = repo
            .upsert_connection(&actualizada)
            .expect("actualizar conexión");
        assert_eq!(id_repetido, id_conexion);
        let conexiones = repo.list_connections(None).expect("listar conexiones");
        assert_eq!(conexiones.len(), 1, "no debe duplicar por 5-tuple");
        assert_eq!(conexiones[0].bytes_in, 500);
        assert_eq!(conexiones[0].state.as_deref(), Some("CLOSE_WAIT"));

        let recuperada = repo
            .get_connection(id_conexion)
            .expect("buscar conexión")
            .expect("debe existir");
        assert_eq!(recuperada.id, id_conexion);
        assert!(repo
            .get_connection(id_conexion + 1_000)
            .expect("buscar inexistente")
            .is_none());

        // Filtros de la vista Conexiones.
        assert_eq!(
            repo.list_connections(Some("tcp"))
                .expect("filtrar por protocolo")
                .len(),
            1
        );
        assert_eq!(
            repo.list_connections(Some("CLOSE_WAIT"))
                .expect("filtrar por estado")
                .len(),
            1
        );
        assert_eq!(
            repo.list_connections(Some("93.184.216"))
                .expect("filtrar por IP")
                .len(),
            1
        );
        assert!(repo
            .list_connections(Some("udp"))
            .expect("filtrar sin coincidencias")
            .is_empty());
    }

    #[test]
    fn prune_expired_connections_purga_por_timeout_desde_el_repo() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, _) = repo_con_dispositivo(&directorio);

        // Instante fijo para que el corte sea determinista: 2027-01-15T08:00:00Z.
        let ahora = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let fecha_hace = |segundos: u64| {
            let instante: chrono::DateTime<chrono::Utc> = ahora.into();
            (instante - chrono::Duration::seconds(segundos as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        };

        // TCP de hace 301 s (purga), UDP de hace 59 s (se conserva) e ICMP de
        // hace 31 s (purga).
        for (protocolo, estado, segundos) in [
            ("tcp", Some("ESTABLISHED"), 301_u64),
            ("udp", None, 59),
            ("icmp", None, 31),
        ] {
            repo.connection()
                .execute(
                    "INSERT INTO CONNECTIONS (
                         device_id, protocol, src_ip, src_port, dst_ip, dst_port,
                         state, first_seen, last_seen
                     ) VALUES (NULL, ?1, '10.0.0.1', NULL, '10.0.0.2', NULL, ?2, ?3, ?3)",
                    params![protocolo, estado, fecha_hace(segundos)],
                )
                .expect("insertar conexión antigua");
        }

        let purgadas = repo
            .prune_expired_connections(ahora)
            .expect("purgar conexiones caducadas");
        assert_eq!(purgadas, 2, "se purgan TCP (300 s) e ICMP (30 s)");

        let restantes = repo.list_connections(None).expect("listar conexiones");
        assert_eq!(restantes.len(), 1);
        assert_eq!(restantes[0].protocol, ConnectionProtocol::Udp);
    }

    /// Entrada de la caché de nombres con instantes fijos para las pruebas.
    fn entrada_nombre(ip: &str, nombre: &str, source: NameSource, ahora: SystemTime) -> NameEntry {
        NameEntry {
            ip: ip.parse().expect("IP de prueba"),
            name: nombre.to_string(),
            source,
            first_seen: ahora,
            last_seen: ahora,
            expires_at: ahora + Duration::from_secs(3_600),
            requester: None,
        }
    }

    #[test]
    fn upsert_list_names_y_prune_names_desde_el_repo() {
        let directorio = tempdir().expect("crear directorio temporal");
        let mut repo = repo_temporal(&directorio);

        let ahora = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let vigente = NameEntry {
            requester: Some("192.168.1.50".parse().expect("IP de prueba")),
            ..entrada_nombre("93.184.216.34", "example.com", NameSource::Dns, ahora)
        };
        let caducada = NameEntry {
            expires_at: ahora - Duration::from_secs(1),
            ..entrada_nombre("10.0.0.2", "viejo.local", NameSource::Sni, ahora)
        };
        assert_eq!(
            repo.upsert_names(&[vigente.clone(), caducada])
                .expect("persistir caché de nombres"),
            2
        );

        // La carga en caliente solo devuelve las vigentes y sin requester.
        let cargadas = repo.list_names(ahora).expect("listar vigentes");
        assert_eq!(cargadas.len(), 1);
        assert_eq!(cargadas[0].ip, vigente.ip);
        assert_eq!(cargadas[0].name, "example.com");
        assert_eq!(cargadas[0].source, NameSource::Dns);
        assert_eq!(cargadas[0].first_seen, ahora);
        assert!(
            cargadas[0].requester.is_none(),
            "el equipo que preguntó no se persiste"
        );

        // La purga borra la caducada y es idempotente.
        assert_eq!(repo.prune_names(ahora).expect("purgar caducadas"), 1);
        assert_eq!(repo.prune_names(ahora).expect("segunda purga"), 0);
        assert_eq!(repo.list_names(ahora).expect("listar tras purgar").len(), 1);
        // Pasado el TTL, la vigente también deja de cargarse.
        assert!(repo
            .list_names(ahora + Duration::from_secs(3_600))
            .expect("listar más tarde")
            .is_empty());
    }

    #[test]
    fn set_device_identity_persiste_y_conserva_las_senales_que_no_llegan() {
        let directorio = tempdir().expect("crear directorio temporal");
        let (mut repo, id) = repo_con_dispositivo(&directorio);

        let identidad = IdentityUpdate {
            model: Some("  MacBookPro18,3  ".to_string()),
            dhcp_fingerprint: Some("1,3,6,15,119,252".to_string()),
            dhcp_vendor: Some("MSFT 5.0".to_string()),
            dhcp_hostname: Some("portatil-hx".to_string()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
            os_family: Some(OsFamily::Windows),
            os_source: Some(OsSource::Dhcp),
        };
        repo.set_device_identity(id, &identidad)
            .expect("guardar identidad");

        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.model.as_deref(), Some("MacBookPro18,3"));
        assert_eq!(
            dispositivo.dhcp_fingerprint.as_deref(),
            Some("1,3,6,15,119,252")
        );
        assert_eq!(dispositivo.dhcp_vendor.as_deref(), Some("MSFT 5.0"));
        assert_eq!(dispositivo.dhcp_hostname.as_deref(), Some("portatil-hx"));
        assert!(dispositivo
            .user_agent
            .as_deref()
            .expect("user agent")
            .contains("Windows NT"));
        assert_eq!(dispositivo.os_family.as_deref(), Some("windows"));
        assert_eq!(dispositivo.os_source.as_deref(), Some("dhcp"));

        // Una señal aislada (User-Agent) no borra las anteriores.
        repo.set_device_identity(
            id,
            &IdentityUpdate {
                user_agent: Some("curl/8.5.0".to_string()),
                ..IdentityUpdate::default()
            },
        )
        .expect("actualizar solo el User-Agent");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.model.as_deref(), Some("MacBookPro18,3"));
        assert_eq!(dispositivo.dhcp_hostname.as_deref(), Some("portatil-hx"));
        assert_eq!(dispositivo.user_agent.as_deref(), Some("curl/8.5.0"));
        assert_eq!(dispositivo.os_family.as_deref(), Some("windows"));

        // Una familia nueva actualiza también la fuente que la justifica.
        repo.set_device_identity(
            id,
            &IdentityUpdate {
                os_family: Some(OsFamily::MacOs),
                os_source: Some(OsSource::Model),
                ..IdentityUpdate::default()
            },
        )
        .expect("cambiar la familia de SO");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.os_family.as_deref(), Some("macos"));
        assert_eq!(dispositivo.os_source.as_deref(), Some("model"));

        // Sin fuente, una familia nueva deja os_source a NULL.
        repo.set_device_identity(
            id,
            &IdentityUpdate {
                os_family: Some(OsFamily::Linux),
                ..IdentityUpdate::default()
            },
        )
        .expect("familia sin fuente");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.os_family.as_deref(), Some("linux"));
        assert_eq!(dispositivo.os_source, None);

        // Los textos se truncan a los máximos de §3.
        repo.set_device_identity(
            id,
            &IdentityUpdate {
                model: Some("m".repeat(100)),
                dhcp_vendor: Some("v".repeat(100)),
                dhcp_hostname: Some("h".repeat(100)),
                user_agent: Some("u".repeat(300)),
                ..IdentityUpdate::default()
            },
        )
        .expect("guardar textos largos");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.model.as_deref().map(str::len), Some(64));
        assert_eq!(dispositivo.dhcp_vendor.as_deref().map(str::len), Some(64));
        assert_eq!(dispositivo.dhcp_hostname.as_deref().map(str::len), Some(64));
        assert_eq!(dispositivo.user_agent.as_deref().map(str::len), Some(256));

        // Una identidad vacía y un id inexistente no fallan ni cambian nada.
        repo.set_device_identity(id, &IdentityUpdate::default())
            .expect("identidad vacía");
        repo.set_device_identity(9_999, &identidad)
            .expect("id inexistente");
        let dispositivo = repo
            .get_device_by_mac(MAC_PRIMERA)
            .expect("buscar")
            .expect("existe");
        assert_eq!(dispositivo.model.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn la_conexion_usa_wal_con_synchronous_normal_y_autocheckpoint_desactivado() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repo::init(&dir.path().join("data.db")).expect("repositorio");
        let sincrono: i64 = repo
            .connection()
            .query_row("PRAGMA synchronous", [], |fila| fila.get(0))
            .expect("leer synchronous");
        assert_eq!(sincrono, 1, "synchronous debe ser NORMAL (1)");
        let checkpoint: i64 = repo
            .connection()
            .query_row("PRAGMA wal_autocheckpoint", [], |fila| fila.get(0))
            .expect("leer wal_autocheckpoint");
        assert_eq!(
            checkpoint, 0,
            "el autocheckpoint se hace en la purga horaria, no en cada transacción"
        );
        // El checkpoint explícito de la purga no falla sobre una BD recién creada.
        let mut repo = repo;
        repo.wal_checkpoint().expect("checkpoint del WAL");
    }
}
