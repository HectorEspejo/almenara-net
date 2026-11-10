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

pub mod devices;
pub mod events;
pub mod interfaces;
pub mod migrations;

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::error::{Error, Result};

pub use devices::{ChangeSet, Device, DeviceUpsert};
pub use events::{DeviceEvent, EventType};
pub use interfaces::Interface;

/// Tiempo máximo que SQLite espera a que se libere un bloqueo (en milisegundos).
const TIEMPO_ESPERA_BLOQUEO_MS: u64 = 5_000;

/// Columnas de INTERFACES en el mismo orden que reconstruye fila_a_interfaz.
const SQL_SELECCION_INTERFAZ: &str =
    "SELECT id, name, mac, ipv4, netmask, gateway, is_up, last_seen FROM INTERFACES";

/// Columnas de DEVICES en el mismo orden que reconstruye fila_a_dispositivo.
const SQL_SELECCION_DISPOSITIVO: &str =
    "SELECT id, mac, ip, hostname, vendor, interface_id, device_type, is_online,
            first_seen, last_seen, alias, notes FROM DEVICES";

/// Repositorio SQLite de Almenara.
#[derive(Debug)]
pub struct Repo {
    conn: Connection,
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

        let mut conn = Connection::open(path).map_err(|err| Error::database_open(path, &err))?;

        conn.busy_timeout(Duration::from_millis(TIEMPO_ESPERA_BLOQUEO_MS))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

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
    pub fn connection(&self) -> &Connection {
        &self.conn
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
    /// clave foránea exige que el dispositivo exista.
    pub fn append_event(&mut self, device_id: i64, event: EventType, details: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![device_id, event.as_str(), details, ahora_rfc3339()],
        )?;
        Ok(())
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

    /// Versión actual del esquema aplicado.
    pub fn schema_version(&self) -> Result<u32> {
        migrations::current_version(&self.conn)
    }

    /// Número de dispositivos en la base de datos.
    pub fn count_devices(&self) -> Result<u32> {
        let total: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM DEVICES", [], |fila| fila.get(0))?;
        Ok(total)
    }
}

/// Marca temporal actual en RFC 3339 UTC con precisión de segundos.
///
/// Es el formato único de la capa de persistencia; lo usan las migraciones y
/// todas las operaciones que guardan fechas.
pub(crate) fn ahora_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
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
    })
}

/// Normaliza un texto opcional: recorta y convierte el vacío en None.
fn normalizar_texto_opcional(valor: Option<&str>) -> Option<String> {
    valor
        .map(|texto| texto.trim())
        .filter(|texto| !texto.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
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
        assert_eq!(repo.schema_version().expect("leer versión"), 1);
        assert_eq!(repo.count_devices().expect("contar dispositivos"), 0);
    }

    #[test]
    fn init_dos_veces_no_falla_ni_duplica_migraciones() {
        let directorio = tempdir().expect("crear directorio temporal");
        let ruta = directorio.path().join("data.db");

        let primera = Repo::init(&ruta).expect("primer init");
        assert_eq!(primera.schema_version().expect("leer versión"), 1);
        drop(primera);

        let segunda = Repo::init(&ruta).expect("segundo init sobre el mismo fichero");
        assert_eq!(segunda.schema_version().expect("leer versión"), 1);
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
                   AND name IN ('INTERFACES', 'DEVICES', 'DEVICE_EVENTS', 'SCHEMA_MIGRATIONS')",
                [],
                |fila| fila.get(0),
            )
            .expect("contar tablas del esquema");
        assert_eq!(tablas, 4, "deben existir las cuatro tablas del esquema");

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
        assert_eq!(segundo.schema_version().expect("leer versión"), 1);
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
}
