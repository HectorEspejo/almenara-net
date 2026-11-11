//! Histórico sintético para pruebas y mediciones (§7.14).
//!
//! El generador llena una base de datos vacía con el perfil de referencia de la
//! fase: 30 equipos (15 activos por minuto de media), ciclo diario de uso, apps
//! y destinos del catálogo de F4 (claves estables), 2 años de días, 90 días de
//! horas, 48 h de minutos, inventario, eventos y sesiones con un 10 % del tiempo
//! sin sesión. Todo es determinista a partir de la semilla del perfil y no usa
//! dependencias nuevas: el RNG es un xorshift64* propio.
//!
//! Las tres resoluciones se generan por separado con magnitudes coherentes (cada
//! una es un perfil de referencia para medir tamaño y tiempos, no una
//! reconstrucción exacta de las otras): así el generador no depende del DAO de
//! consolidación y sirve con la base de datos recién migrada.
//!
//! La prueba ignorada [medir_historial] se ejecuta con:
//!
//! ```text
//! cargo test --release -- --ignored medir_historial -- --nocapture
//! ```

#![allow(dead_code)]

use rusqlite::{params, Connection, Statement};

use crate::alerts::{AlertRule, Level, RuleId, Subject as AlertSubject};
use crate::error::Result;
use crate::history::localtime::{self, LocalDay};
use crate::repo::migrations;

/// Tope de bytes de un minuto para un equipo muy activo (base del ciclo diario).
const BASE_BYTES_MINUTO: f64 = 2_000_000.0;
/// Bytes base de un equipo en una hora activa.
const BASE_BYTES_HORA: f64 = 120_000_000.0;
/// Bytes base de un equipo en un día activo.
const BASE_BYTES_DIA: f64 = 2_800_000_000.0;
/// Factor de actividad por hora local (índice 0 = 00:00 local).
const FACTOR_HORARIO: [f64; 24] = [
    0.15, 0.10, 0.08, 0.08, 0.10, 0.20, 0.40, 0.80, 1.20, 1.40, 1.30, 1.20, 1.10, 1.20, 1.30, 1.50,
    1.80, 2.20, 2.60, 3.00, 3.20, 2.80, 2.00, 1.00,
];
/// Equipos de media activos por minuto en el perfil de referencia.
const ACTIVOS_MEDIA: f64 = 15.0;
/// Equipos del perfil de referencia.
const EQUIPOS_REFERENCIA: usize = 30;
/// Fracción de tiempo sin sesión de Almenara (10 %).
const FRACCION_SIN_SESION: f64 = 0.10;
/// Alertas del perfil de referencia: 20 000 en 90 días (§7.16).
const ALERTAS_REFERENCIA: usize = 20_000;
/// Días de alertas del perfil de referencia.
const ALERTAS_DIAS_REFERENCIA: i64 = 90;
/// Silencios del perfil de referencia (§7.16).
const SILENCIOS_REFERENCIA: usize = 20;
/// Entradas de inventario del propio equipo del perfil de referencia (§7.16).
const HOST_SEEN_REFERENCIA: usize = 300;
/// Una suspensión nocturna: de 02:00 a 04:30 locales.
const SUSPENSION_HORA_LOCAL: i64 = 2;
/// Duración de la suspensión nocturna en segundos (2,5 h).
const SUSPENSION_DURACION: i64 = 2 * 3_600 + 30 * 60;
/// Huellas JA4 estables del generador.
const JA4_SINTETICAS: [&str; 3] = [
    "t13d1516h2_8daaf6152771_02713d6af862",
    "t13d1715h2_5b57614c22b0_3d5424432f57",
    "t13d1517h2_8daaf6152771_b1ff8a24a2c4",
];

/// App del catálogo de F4 usada por el generador (claves estables inventadas).
#[derive(Debug, Clone, Copy)]
struct AppSintetica {
    clave: &'static str,
    categoria: &'static str,
    org: &'static str,
    pais: &'static str,
    protocolo: &'static str,
    destino: &'static str,
}

/// Catálogo estable de apps, organizaciones, países y destinos del generador.
const APPS: [AppSintetica; 16] = [
    AppSintetica {
        clave: "youtube",
        categoria: "streaming",
        org: "Google LLC",
        pais: "US",
        protocolo: "quic",
        destino: "googlevideo.com",
    },
    AppSintetica {
        clave: "netflix",
        categoria: "streaming",
        org: "Netflix",
        pais: "NL",
        protocolo: "tls",
        destino: "nflxvideo.net",
    },
    AppSintetica {
        clave: "spotify",
        categoria: "streaming",
        org: "Spotify",
        pais: "SE",
        protocolo: "tls",
        destino: "spotify.com",
    },
    AppSintetica {
        clave: "twitch",
        categoria: "streaming",
        org: "Amazon",
        pais: "US",
        protocolo: "tls",
        destino: "twitch.tv",
    },
    AppSintetica {
        clave: "instagram",
        categoria: "social",
        org: "Meta",
        pais: "IE",
        protocolo: "tls",
        destino: "instagram.com",
    },
    AppSintetica {
        clave: "whatsapp",
        categoria: "mensajeria",
        org: "Meta",
        pais: "IE",
        protocolo: "quic",
        destino: "whatsapp.net",
    },
    AppSintetica {
        clave: "telegram",
        categoria: "mensajeria",
        org: "Telegram",
        pais: "SG",
        protocolo: "tls",
        destino: "telegram.org",
    },
    AppSintetica {
        clave: "discord",
        categoria: "mensajeria",
        org: "Discord",
        pais: "US",
        protocolo: "tls",
        destino: "discord.com",
    },
    AppSintetica {
        clave: "chrome",
        categoria: "web",
        org: "Google LLC",
        pais: "US",
        protocolo: "quic",
        destino: "google.com",
    },
    AppSintetica {
        clave: "wikipedia",
        categoria: "web",
        org: "Wikimedia",
        pais: "US",
        protocolo: "tls",
        destino: "wikipedia.org",
    },
    AppSintetica {
        clave: "github",
        categoria: "trabajo",
        org: "GitHub",
        pais: "US",
        protocolo: "tls",
        destino: "github.com",
    },
    AppSintetica {
        clave: "teams",
        categoria: "trabajo",
        org: "Microsoft",
        pais: "US",
        protocolo: "quic",
        destino: "teams.microsoft.com",
    },
    AppSintetica {
        clave: "icloud",
        categoria: "nube",
        org: "Apple",
        pais: "US",
        protocolo: "tls",
        destino: "icloud.com",
    },
    AppSintetica {
        clave: "dropbox",
        categoria: "nube",
        org: "Dropbox",
        pais: "US",
        protocolo: "tls",
        destino: "dropbox.com",
    },
    AppSintetica {
        clave: "steam",
        categoria: "juegos",
        org: "Valve",
        pais: "ES",
        protocolo: "tls",
        destino: "steamcontent.com",
    },
    AppSintetica {
        clave: "amazon",
        categoria: "compras",
        org: "Amazon",
        pais: "DE",
        protocolo: "tls",
        destino: "amazon.es",
    },
];

/// Perfil del histórico sintético.
#[derive(Debug, Clone, PartialEq)]
pub struct SyntheticProfile {
    /// Semilla del RNG (determinista).
    pub seed: u64,
    /// Equipos simulados (30 en el perfil de referencia).
    pub devices: usize,
    /// Días locales de histórico (730 = 2 años).
    pub days: i64,
    /// Días de horas (90).
    pub hour_days: i64,
    /// Horas de minutos (48).
    pub minute_hours: i64,
    /// Días con destinos por hora (30).
    pub destination_days: i64,
    /// Tope de claves por sujeto, dimensión y cubo (20).
    pub top_keys: usize,
    /// Alertas generadas (20 000 en el perfil de referencia).
    pub alerts: usize,
    /// Días sobre los que se reparten las alertas (90).
    pub alert_days: i64,
    /// Silencios generados (20).
    pub mutes: usize,
    /// Entradas de HOST_SEEN generadas (300).
    pub host_seen: usize,
    /// Instante final del histórico, en segundos Unix UTC.
    pub end: i64,
}

impl Default for SyntheticProfile {
    fn default() -> Self {
        let ahora = localtime::now_unix();
        Self {
            seed: 0x5EED_2026_0A1E_5A5A,
            devices: EQUIPOS_REFERENCIA,
            days: 730,
            hour_days: 90,
            minute_hours: 48,
            destination_days: 30,
            top_keys: 20,
            alerts: ALERTAS_REFERENCIA,
            alert_days: ALERTAS_DIAS_REFERENCIA,
            mutes: SILENCIOS_REFERENCIA,
            host_seen: HOST_SEEN_REFERENCIA,
            end: ahora - ahora.rem_euclid(3600),
        }
    }
}

impl SyntheticProfile {
    /// Perfil pequeño y fijo para las pruebas unitarias (determinista).
    pub fn de_prueba() -> Self {
        Self {
            seed: 0x1234_5678_9ABC_DEF0,
            devices: 4,
            days: 5,
            hour_days: 1,
            minute_hours: 1,
            destination_days: 1,
            top_keys: 5,
            alerts: 60,
            alert_days: 5,
            mutes: 3,
            host_seen: 6,
            end: 1_800_000_000 - 1_800_000_000_i64.rem_euclid(3600),
        }
    }

    /// Acota los valores del perfil a rangos razonables para no desbordar.
    fn saneado(&self) -> Self {
        Self {
            seed: self.seed | 1,
            devices: self.devices.clamp(1, 1_000),
            days: self.days.clamp(1, 3_650),
            hour_days: self.hour_days.clamp(1, 365),
            minute_hours: self.minute_hours.clamp(1, 168),
            destination_days: self.destination_days.clamp(0, self.hour_days),
            top_keys: self.top_keys.clamp(1, 100),
            alerts: self.alerts.clamp(0, 200_000),
            alert_days: self.alert_days.clamp(1, 730),
            mutes: self.mutes.clamp(0, 1_000),
            host_seen: self.host_seen.clamp(0, 100_000),
            end: self.end,
        }
    }
}

/// Filas generadas, para el informe de implementación y las pruebas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyntheticStats {
    /// Equipos creados en DEVICES.
    pub devices: u64,
    /// Filas de TRAFFIC_ROLLUP_MINUTE.
    pub minutes: u64,
    /// Filas de TRAFFIC_ROLLUP_HOUR.
    pub hours: u64,
    /// Filas de TRAFFIC_ROLLUP_DAY.
    pub days: u64,
    /// Filas de DEVICE_SEEN.
    pub seen: u64,
    /// Filas de DEVICE_EVENTS.
    pub events: u64,
    /// Filas de APP_SESSIONS.
    pub sessions: u64,
    /// Bytes totales generados en las tres resoluciones.
    pub bytes: u64,
    /// Filas de ALERTS (incluidos los resúmenes de la puesta al día).
    pub alerts: u64,
    /// Filas de ALERT_MUTES.
    pub mutes: u64,
    /// Filas de ALERT_LEARNING (equipos y propio equipo).
    pub learning: u64,
    /// Filas de HOST_SEEN.
    pub host_seen: u64,
    /// Filas de COVERAGE_GAPS.
    pub gaps: u64,
}

impl SyntheticStats {
    /// Total de filas del histórico generadas.
    pub fn total_filas(&self) -> u64 {
        self.minutes
            .saturating_add(self.hours)
            .saturating_add(self.days)
            .saturating_add(self.seen)
            .saturating_add(self.events)
            .saturating_add(self.sessions)
            .saturating_add(self.alerts)
            .saturating_add(self.mutes)
            .saturating_add(self.learning)
            .saturating_add(self.host_seen)
            .saturating_add(self.gaps)
    }
}

/// Generador del histórico sintético.
pub struct Synthetic;

impl Synthetic {
    /// Genera el perfil completo (histórico de F5 y datos de la F6) en una base
    /// de datos ya migrada (o vacía).
    ///
    /// Escribe directamente en las tablas del histórico; está pensado para una
    /// base de datos temporal de pruebas, no para una base de datos real.
    pub fn generate(conn: &mut Connection, profile: &SyntheticProfile) -> Result<SyntheticStats> {
        let perfil = profile.saneado();
        migrations::apply_all(conn)?;
        let mut rng = Rng::nuevo(perfil.seed);
        let dispositivos = generar_historico(conn, &perfil, &mut rng)?;
        crear_huecos(conn, &perfil, &mut rng)?;
        crear_alertas(conn, &perfil, &dispositivos, &mut rng)?;
        crear_silencios(conn, &perfil, &dispositivos, &mut rng)?;
        crear_aprendizaje(conn, &perfil, &dispositivos, &mut rng)?;
        crear_host_seen(conn, &perfil, &mut rng)?;
        let stats = SyntheticStats {
            devices: dispositivos.len() as u64,
            minutes: contar(conn, "TRAFFIC_ROLLUP_MINUTE")?,
            hours: contar(conn, "TRAFFIC_ROLLUP_HOUR")?,
            days: contar(conn, "TRAFFIC_ROLLUP_DAY")?,
            seen: contar(conn, "DEVICE_SEEN")?,
            events: contar(conn, "DEVICE_EVENTS")?,
            sessions: contar(conn, "APP_SESSIONS")?,
            bytes: bytes_generados(conn)?,
            alerts: contar(conn, "ALERTS")?,
            mutes: contar(conn, "ALERT_MUTES")?,
            learning: contar(conn, "ALERT_LEARNING")?,
            host_seen: contar(conn, "HOST_SEEN")?,
            gaps: contar(conn, "COVERAGE_GAPS")?,
        };
        Ok(stats)
    }

    /// Genera solo el histórico de F5 (sin datos de la F6) sobre una base ya en
    /// la versión v5. Lo usa la medición de la migración v6 con sus rellenos.
    pub fn generate_historico_v5(
        conn: &mut Connection,
        profile: &SyntheticProfile,
    ) -> Result<SyntheticStats> {
        let perfil = profile.saneado();
        let mut rng = Rng::nuevo(perfil.seed);
        let dispositivos = generar_historico(conn, &perfil, &mut rng)?;
        Ok(SyntheticStats {
            devices: dispositivos.len() as u64,
            minutes: contar(conn, "TRAFFIC_ROLLUP_MINUTE")?,
            hours: contar(conn, "TRAFFIC_ROLLUP_HOUR")?,
            days: contar(conn, "TRAFFIC_ROLLUP_DAY")?,
            seen: contar(conn, "DEVICE_SEEN")?,
            events: contar(conn, "DEVICE_EVENTS")?,
            sessions: contar(conn, "APP_SESSIONS")?,
            bytes: bytes_generados(conn)?,
            ..SyntheticStats::default()
        })
    }
}

/// Genera el histórico de F5 (tres resoluciones, inventario, eventos y
/// sesiones) y devuelve los ids de los equipos creados.
fn generar_historico(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    rng: &mut Rng,
) -> Result<Vec<i64>> {
    let interfaz = crear_interfaz(conn, perfil.end)?;
    let dispositivos = crear_dispositivos(conn, perfil, interfaz, rng)?;
    crear_sesiones(conn, perfil, rng)?;
    crear_minutos(conn, perfil, &dispositivos, rng)?;
    crear_horas(conn, perfil, &dispositivos, rng)?;
    crear_dias(conn, perfil, &dispositivos, rng)?;
    crear_inventario(conn, perfil, &dispositivos, rng)?;
    crear_servicios(conn, perfil, &dispositivos, rng)?;
    crear_eventos(conn, perfil, &dispositivos, rng)?;
    Ok(dispositivos)
}

/// Número de filas de una tabla.
fn contar(conn: &Connection, tabla: &str) -> Result<u64> {
    let filas: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |fila| {
        fila.get(0)
    })?;
    Ok(filas.max(0) as u64)
}

/// Bytes totales de las tres resoluciones.
fn bytes_generados(conn: &Connection) -> Result<u64> {
    let total: i64 = conn.query_row(
        "SELECT
             (SELECT COALESCE(SUM(bytes_down + bytes_up), 0) FROM TRAFFIC_ROLLUP_MINUTE)
           + (SELECT COALESCE(SUM(bytes_down + bytes_up), 0) FROM TRAFFIC_ROLLUP_HOUR)
           + (SELECT COALESCE(SUM(bytes_down + bytes_up), 0) FROM TRAFFIC_ROLLUP_DAY)",
        [],
        |fila| fila.get(0),
    )?;
    Ok(total.max(0) as u64)
}

// ---------------------------------------------------------------------------
// RNG determinista (xorshift64*, sin dependencias)
// ---------------------------------------------------------------------------

/// Generador pseudoaleatorio xorshift64* (semilla distinta de cero).
#[derive(Debug, Clone, Copy)]
struct Rng(u64);

impl Rng {
    fn nuevo(semilla: u64) -> Self {
        Self(semilla | 1)
    }

    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Número real uniforme en [0, 1).
    fn unidad(&mut self) -> f64 {
        (self.siguiente() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Entero uniforme en [0, n).
    fn rango(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.siguiente() % n as u64) as usize
    }

    /// Entero uniforme en [min, max].
    fn entre(&mut self, min: i64, max: i64) -> i64 {
        if max <= min {
            return min;
        }
        min + (self.siguiente() % ((max - min + 1) as u64)) as i64
    }
}

/// Probabilidad de que un equipo esté activo en un cubo de la hora local dada.
fn probabilidad_activa(factor: f64) -> f64 {
    // Con los 24 factores del ciclo, la media queda en ~15 de 30 equipos.
    (factor * ACTIVOS_MEDIA / 30.0 / 1.35).clamp(0.02, 0.98)
}

/// Factor de actividad de la hora local del instante indicado.
fn factor_horario(segundos: i64) -> f64 {
    let hora = localtime::local_hour(segundos).clamp(0, 23) as usize;
    FACTOR_HORARIO[hora]
}

/// Media de los factores del ciclo, para repartir bytes con la escala correcta.
fn factor_medio() -> f64 {
    FACTOR_HORARIO.iter().sum::<f64>() / 24.0
}

// ---------------------------------------------------------------------------
// Helpers de inserción
// ---------------------------------------------------------------------------

fn entero(valor: u64) -> i64 {
    valor.min(i64::MAX as u64) as i64
}

/// Inserta una fila de rollup con la sentencia preparada indicada.
#[allow(clippy::too_many_arguments)]
fn insertar_rollup(
    sentencia: &mut Statement<'_>,
    bucket: i64,
    subject: &str,
    device_id: i64,
    dimension: &str,
    key: &str,
    down: u64,
    up: u64,
    connections: u64,
) -> rusqlite::Result<()> {
    sentencia.execute(params![
        bucket,
        subject,
        device_id,
        dimension,
        key,
        entero(down),
        entero(up),
        entero(connections),
    ])?;
    Ok(())
}

fn preparar_rollup<'a>(
    tx: &'a rusqlite::Transaction<'_>,
    tabla: &str,
) -> rusqlite::Result<Statement<'a>> {
    tx.prepare(&format!(
        "INSERT INTO {tabla}
             (bucket, subject, device_id, dimension, key, bytes_down, bytes_up, connections)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    ))
}

/// Crea la interfaz de red del histórico sintético y devuelve su id.
fn crear_interfaz(conn: &Connection, ahora: i64) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO INTERFACES
             (name, mac, ipv4, netmask, gateway, is_up, last_seen)
         VALUES ('sintetica0', NULL, '192.168.10.1', NULL, NULL, 1, ?1)",
        params![localtime::rfc3339(ahora)],
    )?;
    let id = conn.query_row(
        "SELECT id FROM INTERFACES WHERE name = 'sintetica0'",
        [],
        |fila| fila.get(0),
    )?;
    Ok(id)
}

/// Crea los equipos del perfil y devuelve sus ids.
fn crear_dispositivos(
    conn: &Connection,
    perfil: &SyntheticProfile,
    interfaz: i64,
    rng: &mut Rng,
) -> Result<Vec<i64>> {
    let tipos = [
        "pc",
        "movil",
        "tablet",
        "television",
        "iot",
        "impresora",
        "nas",
    ];
    let inicio = perfil.end - perfil.days * 86_400;
    let mut ids = Vec::with_capacity(perfil.devices);
    for indice in 0..perfil.devices {
        let mac = format!(
            "02:00:00:00:{:02x}:{:02x}",
            (indice >> 8) & 0xff,
            indice & 0xff
        );
        let ip = format!("192.168.10.{}", 10 + indice % 200);
        let hostname = format!("equipo-{:02}", indice + 1);
        let alias = (indice % 5 == 0).then(|| format!("alias-{:02}", indice + 1));
        let tipo = tipos[indice % tipos.len()];
        let alta = inicio + rng.entre(0, 3_600);
        let online = i64::from(indice % 2 == 0);
        conn.execute(
            "INSERT OR IGNORE INTO DEVICES
                 (mac, ip, hostname, vendor, interface_id, device_type, is_online,
                  first_seen, last_seen, alias)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                mac,
                ip,
                hostname,
                interfaz,
                tipo,
                online,
                localtime::rfc3339(alta),
                localtime::rfc3339(perfil.end),
                alias
            ],
        )?;
        let id = conn.query_row(
            "SELECT id FROM DEVICES WHERE mac = ?1",
            params![mac],
            |fila| fila.get(0),
        )?;
        ids.push(id);
    }
    Ok(ids)
}

/// Sesiones de Almenara: un 10 % de los días sin sesión y ~10 % sin captura.
fn crear_sesiones(conn: &mut Connection, perfil: &SyntheticProfile, rng: &mut Rng) -> Result<()> {
    let inicio_dia = LocalDay::from_unix(perfil.end).sumar_dias(-(perfil.days - 1));
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT INTO APP_SESSIONS
                 (started_at, ended_at, last_beat, end_reason, mode, capture,
                  passive_only, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, '0.5.0')",
        )?;
        for indice in 0..perfil.days {
            let dia = inicio_dia.sumar_dias(indice);
            if rng.unidad() < FRACCION_SIN_SESION {
                continue;
            }
            let (inicio, fin) = dia.limits();
            let captura = rng.unidad() > FRACCION_SIN_SESION;
            let abierta = indice == perfil.days - 1;
            let (ended_at, last_beat, motivo) = if abierta {
                (None, perfil.end, None)
            } else if rng.unidad() < 0.05 {
                // Cierre interrumpido: ended_at = last_beat, unos minutos antes.
                let latido = fin - rng.entre(60, 3_600);
                (Some(latido), latido, Some("interrupted"))
            } else {
                (Some(fin), fin, Some("quit"))
            };
            sentencia.execute(params![
                localtime::rfc3339(inicio),
                ended_at.map(localtime::rfc3339),
                localtime::rfc3339(last_beat),
                motivo,
                if captura { "privileged" } else { "degraded" },
                captura,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Nombre del protocolo de una app del catálogo.
fn protocolo_de(app: &AppSintetica) -> &'static str {
    app.protocolo
}

/// Índices de apps distintos para un cubo, en orden pseudoaleatorio.
fn elegir_apps(rng: &mut Rng, cuantas: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..APPS.len()).collect();
    let cuantas = cuantas.min(indices.len());
    for posicion in 0..cuantas {
        let otra = posicion + rng.rango(indices.len() - posicion);
        indices.swap(posicion, otra);
    }
    indices.truncate(cuantas);
    indices
}

/// Inserta las dimensiones de un flujo de bytes repartidos entre claves.
#[allow(clippy::too_many_arguments)]
fn insertar_dimensiones(
    sentencia: &mut Statement<'_>,
    bucket: i64,
    subject: &str,
    device_id: i64,
    apps: &[usize],
    bytes: u64,
    con_destinos: bool,
    conexiones: u64,
) -> rusqlite::Result<()> {
    if apps.is_empty() {
        return Ok(());
    }
    let reparto = bytes / apps.len() as u64;
    let mut restante = bytes;
    let mut categorias: Vec<&str> = Vec::new();
    let mut organizaciones: Vec<&str> = Vec::new();
    let mut paises: Vec<&str> = Vec::new();
    let mut protocolos: Vec<&str> = Vec::new();
    let mut destinos: Vec<&str> = Vec::new();
    for (posicion, indice) in apps.iter().enumerate() {
        let app = &APPS[*indice];
        let parte = if posicion + 1 == apps.len() {
            restante
        } else {
            reparto.min(restante)
        };
        restante = restante.saturating_sub(parte);
        if parte == 0 {
            continue;
        }
        insertar_rollup(
            sentencia, bucket, subject, device_id, "app", app.clave, parte, 0, conexiones,
        )?;
        if !categorias.contains(&app.categoria) {
            categorias.push(app.categoria);
        }
        if !organizaciones.contains(&app.org) {
            organizaciones.push(app.org);
        }
        if !paises.contains(&app.pais) {
            paises.push(app.pais);
        }
        if !protocolos.contains(&protocolo_de(app)) {
            protocolos.push(protocolo_de(app));
        }
        if con_destinos && !destinos.contains(&app.destino) {
            destinos.push(app.destino);
        }
    }
    let dimensiones: [(&str, &Vec<&str>); 5] = [
        ("category", &categorias),
        ("org", &organizaciones),
        ("country", &paises),
        ("protocol", &protocolos),
        ("destination", &destinos),
    ];
    for (dimension, claves) in dimensiones {
        if claves.is_empty() {
            continue;
        }
        let parte = bytes / claves.len() as u64;
        for clave in claves.iter() {
            insertar_rollup(
                sentencia, bucket, subject, device_id, dimension, clave, parte, 0, 0,
            )?;
        }
    }
    Ok(())
}

/// Minutos de las últimas minute_hours horas (48 h por defecto).
fn crear_minutos(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    let fin = perfil.end - perfil.end.rem_euclid(60);
    let inicio = fin - perfil.minute_hours * 3_600;
    let fin_destinos = fin - 2 * 3_600;
    let escala = 1.0 / factor_medio();
    let tx = conn.transaction()?;
    {
        let mut sentencia = preparar_rollup(&tx, "TRAFFIC_ROLLUP_MINUTE")?;
        let mut bucket = inicio;
        while bucket < fin {
            let factor = factor_horario(bucket);
            let mut total_red = 0u64;
            for (indice, device_id) in dispositivos.iter().enumerate() {
                if rng.unidad() >= probabilidad_activa(factor) {
                    continue;
                }
                let total = (BASE_BYTES_MINUTO * factor * escala * (0.5 + rng.unidad())) as u64;
                total_red = total_red.saturating_add(total);
                let down = total - total / 10;
                let up = total / 10;
                insertar_rollup(
                    &mut sentencia,
                    bucket,
                    "device",
                    *device_id,
                    "total",
                    "",
                    down,
                    up,
                    (indice % 3) as u64,
                )?;
                let cuantas = 1 + rng.rango(3);
                let apps = elegir_apps(rng, cuantas);
                insertar_dimensiones(
                    &mut sentencia,
                    bucket,
                    "device",
                    *device_id,
                    &apps,
                    total,
                    bucket >= fin_destinos,
                    1,
                )?;
                // Destinos de la red local en la franja reciente.
                if bucket >= fin_destinos && rng.rango(6) == 0 && dispositivos.len() > 1 {
                    let otro = dispositivos[(indice + 1) % dispositivos.len()];
                    let clave = format!("lan:{otro}");
                    insertar_rollup(
                        &mut sentencia,
                        bucket,
                        "device",
                        *device_id,
                        "destination",
                        &clave,
                        total / 20,
                        0,
                        0,
                    )?;
                }
            }
            // Tráfico del propio equipo (host): total, apps y proceso.
            if rng.unidad() < 0.35 {
                let total = (BASE_BYTES_MINUTO * factor * escala * 0.2 * rng.unidad()) as u64;
                total_red = total_red.saturating_add(total);
                insertar_rollup(&mut sentencia, bucket, "host", 0, "total", "", total, 0, 1)?;
                let cuantas = 1 + rng.rango(2);
                let apps = elegir_apps(rng, cuantas);
                insertar_dimensiones(
                    &mut sentencia,
                    bucket,
                    "host",
                    0,
                    &apps,
                    total,
                    bucket >= fin_destinos,
                    1,
                )?;
                if let Some(app) = apps.first() {
                    insertar_rollup(
                        &mut sentencia,
                        bucket,
                        "host",
                        0,
                        "process",
                        APPS[*app].clave,
                        total,
                        0,
                        0,
                    )?;
                }
            }
            insertar_rollup(
                &mut sentencia,
                bucket,
                "network",
                0,
                "total",
                "",
                total_red,
                0,
                0,
            )?;
            bucket += 60;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Horas de los últimos hour_days días (90 por defecto).
fn crear_horas(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    let fin = perfil.end - perfil.end.rem_euclid(3_600);
    let inicio = fin - perfil.hour_days * 24 * 3_600;
    let fin_destinos = fin - perfil.destination_days * 86_400;
    let escala = 1.0 / factor_medio();
    let tx = conn.transaction()?;
    {
        let mut sentencia = preparar_rollup(&tx, "TRAFFIC_ROLLUP_HOUR")?;
        let mut bucket = inicio;
        while bucket < fin {
            let factor = factor_horario(bucket);
            let mut total_red = 0u64;
            for (indice, device_id) in dispositivos.iter().enumerate() {
                if rng.unidad() >= probabilidad_activa(factor) {
                    continue;
                }
                let total = (BASE_BYTES_HORA * factor * escala * (0.4 + rng.unidad())) as u64;
                total_red = total_red.saturating_add(total);
                let down = total - total / 10;
                let up = total / 10;
                insertar_rollup(
                    &mut sentencia,
                    bucket,
                    "device",
                    *device_id,
                    "total",
                    "",
                    down,
                    up,
                    (indice % 7) as u64,
                )?;
                let cuantas = 6 + rng.rango(perfil.top_keys.min(8));
                let apps = elegir_apps(rng, cuantas);
                insertar_dimensiones(
                    &mut sentencia,
                    bucket,
                    "device",
                    *device_id,
                    &apps,
                    total,
                    bucket >= fin_destinos,
                    1,
                )?;
            }
            if rng.unidad() < 0.5 {
                let total = (BASE_BYTES_HORA * factor * escala * 0.15 * rng.unidad()) as u64;
                total_red = total_red.saturating_add(total);
                insertar_rollup(&mut sentencia, bucket, "host", 0, "total", "", total, 0, 1)?;
                let cuantas = 2 + rng.rango(2);
                let apps = elegir_apps(rng, cuantas);
                insertar_dimensiones(
                    &mut sentencia,
                    bucket,
                    "host",
                    0,
                    &apps,
                    total,
                    bucket >= fin_destinos,
                    1,
                )?;
            }
            insertar_rollup(
                &mut sentencia,
                bucket,
                "network",
                0,
                "total",
                "",
                total_red,
                0,
                0,
            )?;
            bucket += 3_600;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Días locales de los últimos days días (730 por defecto), sin destinos.
fn crear_dias(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    let hoy = LocalDay::from_unix(perfil.end);
    let primero = hoy.sumar_dias(-(perfil.days - 1));
    let tx = conn.transaction()?;
    {
        let mut sentencia = preparar_rollup(&tx, "TRAFFIC_ROLLUP_DAY")?;
        for indice in 0..perfil.days {
            let dia = primero.sumar_dias(indice);
            let bucket = dia.aaaammdd();
            let factor = 1.0 + 0.3 * rng.unidad();
            let mut total_red = 0u64;
            for (posicion, device_id) in dispositivos.iter().enumerate() {
                if rng.unidad() >= 0.5 {
                    continue;
                }
                let total = (BASE_BYTES_DIA * factor * (0.4 + rng.unidad())) as u64;
                total_red = total_red.saturating_add(total);
                let down = total - total / 10;
                let up = total / 10;
                insertar_rollup(
                    &mut sentencia,
                    bucket,
                    "device",
                    *device_id,
                    "total",
                    "",
                    down,
                    up,
                    (posicion % 5) as u64,
                )?;
                let cuantas = 5 + rng.rango(4);
                let apps = elegir_apps(rng, cuantas);
                insertar_dimensiones(
                    &mut sentencia,
                    bucket,
                    "device",
                    *device_id,
                    &apps,
                    total,
                    false,
                    1,
                )?;
            }
            if rng.unidad() < 0.6 {
                let total = (BASE_BYTES_DIA * factor * 0.12 * rng.unidad()) as u64;
                total_red = total_red.saturating_add(total);
                insertar_rollup(&mut sentencia, bucket, "host", 0, "total", "", total, 0, 1)?;
                let cuantas = 2 + rng.rango(2);
                let apps = elegir_apps(rng, cuantas);
                insertar_dimensiones(&mut sentencia, bucket, "host", 0, &apps, total, false, 1)?;
            }
            insertar_rollup(
                &mut sentencia,
                bucket,
                "network",
                0,
                "total",
                "",
                total_red,
                0,
                0,
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Inventario por equipo: apps, categorías, organizaciones, países y JA4.
fn crear_inventario(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    let ja4 = [
        "t13d1516h2_8daaf6152771_02713d6af862",
        "t13d1715h2_5b57614c22b0_3d5424432f57",
        "t13d1517h2_8daaf6152771_b1ff8a24a2c4",
    ];
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT INTO DEVICE_SEEN (device_id, kind, key, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (device_id, kind, key) DO UPDATE SET
                 last_seen = excluded.last_seen",
        )?;
        for device_id in dispositivos {
            let mut claves: Vec<(&str, &str)> = Vec::new();
            for app in APPS.iter() {
                claves.push(("app", app.clave));
                claves.push(("category", app.categoria));
                claves.push(("org", app.org));
                claves.push(("country", app.pais));
            }
            for huella in ja4.iter() {
                claves.push(("ja4", huella));
            }
            claves.sort_by_key(|(kind, clave)| (*kind, *clave));
            claves.dedup_by(|a, b| *a == *b);
            for (posicion, (kind, clave)) in claves.iter().enumerate() {
                // Un 10 % de las claves son «nuevas» (vistas por primera vez en
                // los últimos 7 días); el resto, repartidas por el último año.
                let primera = if posicion % 10 == 0 {
                    perfil.end - rng.entre(0, 7 * 86_400)
                } else {
                    perfil.end - rng.entre(7 * 86_400, 365 * 86_400)
                };
                let ultima = perfil.end - rng.entre(0, 3 * 86_400);
                sentencia.execute(params![
                    device_id,
                    kind,
                    clave,
                    localtime::rfc3339(primera),
                    localtime::rfc3339(ultima)
                ])?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// Servicios de F2 de los equipos sintéticos, para que el relleno de
/// DEVICE_SERVICES.closed_at de la migración v6 tenga datos que rellenar.
fn crear_servicios(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT OR IGNORE INTO DEVICE_SERVICES
                 (device_id, port, protocol, service, banner, first_seen, last_seen)
             VALUES (?1, ?2, 'tcp', ?3, NULL, ?4, ?5)",
        )?;
        for (indice, device_id) in dispositivos.iter().enumerate() {
            let puertos: [(i64, &str); 2] = if indice % 2 == 0 {
                [(445, "microsoft-ds"), (22, "ssh")]
            } else {
                [(22, "ssh"), (80, "http")]
            };
            for (puerto, servicio) in puertos {
                let primera = perfil.end - rng.entre(30, 365) * 86_400;
                let ultima = perfil.end - rng.entre(0, 30) * 86_400;
                let (primera, ultima) = if primera <= ultima {
                    (primera, ultima)
                } else {
                    (ultima, primera)
                };
                sentencia.execute(params![
                    device_id,
                    puerto,
                    servicio,
                    localtime::rfc3339(primera),
                    localtime::rfc3339(ultima)
                ])?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// Eventos: alta, presencia (new/disappeared/reappeared), servicios e identidad.
fn crear_eventos(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    let inicio = perfil.end - 90 * 86_400;
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (indice, device_id) in dispositivos.iter().enumerate() {
            let alta = inicio + indice as i64 * 60;
            let details = format!(
                r#"{{"before":null,"after":{{"ip":"192.168.10.{}","hostname":"equipo-{:02}","vendor":null}},"mac_random":false}}"#,
                10 + indice % 200,
                indice + 1
            );
            sentencia.execute(params![device_id, "new", details, localtime::rfc3339(alta)])?;
            // Ciclos de presencia cada ~4 días durante los últimos 90 días.
            let mut momento = alta + 86_400;
            let mut presente = true;
            while momento < perfil.end {
                if presente {
                    let last_seen = momento - rng.entre(60, 600);
                    let details = format!(
                        r#"{{"before":{{"ip":"192.168.10.{}","is_online":true}},"after":{{"is_online":false}},"last_seen":"{}"}}"#,
                        10 + indice % 200,
                        localtime::rfc3339(last_seen)
                    );
                    sentencia.execute(params![
                        device_id,
                        "disappeared",
                        details,
                        localtime::rfc3339(momento)
                    ])?;
                } else {
                    let details = format!(
                        r#"{{"away_since":"{}","away_s":{}}}"#,
                        localtime::rfc3339(momento - 3_600),
                        rng.entre(60, 7_200)
                    );
                    sentencia.execute(params![
                        device_id,
                        "reappeared",
                        details,
                        localtime::rfc3339(momento)
                    ])?;
                }
                presente = !presente;
                momento += 4 * 86_400 + rng.entre(0, 3_600);
            }
            // Servicios: 445/tcp y 22/tcp, con algún cierre.
            let puerto = if indice % 2 == 0 { 445 } else { 22 };
            let servicio = if puerto == 445 { "microsoft-ds" } else { "ssh" };
            let cuando = perfil.end - rng.entre(86_400, 30 * 86_400);
            let details = format!(
                r#"{{"port":{puerto},"protocol":"tcp","service":"{servicio}","reopened":false}}"#
            );
            sentencia.execute(params![
                device_id,
                "service_new",
                details,
                localtime::rfc3339(cuando)
            ])?;
            if indice % 3 == 0 {
                let details =
                    format!(r#"{{"port":{puerto},"protocol":"tcp","service":"{servicio}"}}"#);
                sentencia.execute(params![
                    device_id,
                    "service_gone",
                    details,
                    localtime::rfc3339(cuando + 3_600)
                ])?;
            }
            // Identidad: cambios de IP, SO y tipo repartidos por el último mes.
            for (tipo, antes, despues) in [
                ("ip_changed", "192.168.10.20", "192.168.10.21"),
                ("os_changed", "linux", "android"),
                ("type_changed", "unknown", "movil"),
            ] {
                if rng.rango(3) != 0 {
                    continue;
                }
                let details = format!(r#"{{"before":"{antes}","after":"{despues}"}}"#);
                sentencia.execute(params![
                    device_id,
                    tipo,
                    details,
                    localtime::rfc3339(perfil.end - rng.entre(3_600, 30 * 86_400))
                ])?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Datos de la Fase 6: huecos, alertas, silencios, aprendizaje e inventario host
// ---------------------------------------------------------------------------

/// Huecos de cobertura: una suspensión nocturna diaria (§7.16).
fn crear_huecos(conn: &mut Connection, perfil: &SyntheticProfile, rng: &mut Rng) -> Result<()> {
    let sesiones = sesiones_para_huecos(conn)?;
    let hoy = LocalDay::from_unix(perfil.end);
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT INTO COVERAGE_GAPS (session_id, kind, started_at, ended_at)
             VALUES (?1, 'suspend', ?2, ?3)",
        )?;
        for indice in 0..perfil.days {
            let dia = hoy.sumar_dias(-(perfil.days - 1 - indice));
            let inicio = dia.limits().0 + SUSPENSION_HORA_LOCAL * 3_600 + rng.entre(0, 30 * 60);
            let fin = inicio + SUSPENSION_DURACION;
            let Some(sesion_id) = sesion_que_cubre(&sesiones, inicio, fin) else {
                continue;
            };
            sentencia.execute(params![
                sesion_id,
                localtime::rfc3339(inicio),
                localtime::rfc3339(fin)
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Sesiones de Almenara como (id, inicio, fin) en segundos Unix UTC.
fn sesiones_para_huecos(conn: &Connection) -> Result<Vec<(i64, i64, i64)>> {
    let mut sentencia =
        conn.prepare("SELECT id, started_at, ended_at FROM APP_SESSIONS ORDER BY started_at")?;
    let filas = sentencia.query_map([], |fila| {
        let id: i64 = fila.get(0)?;
        let inicio: String = fila.get(1)?;
        let fin: Option<String> = fila.get(2)?;
        Ok((id, inicio, fin))
    })?;
    let mut sesiones = Vec::new();
    for fila in filas {
        let (id, inicio, fin) = fila?;
        let Some(inicio) = localtime::unix_de_rfc3339(&inicio) else {
            continue;
        };
        let Some(fin) = fin.as_deref().and_then(localtime::unix_de_rfc3339) else {
            continue;
        };
        sesiones.push((id, inicio, fin));
    }
    Ok(sesiones)
}

/// Sesión que contiene por completo [inicio, fin), si la hay.
fn sesion_que_cubre(sesiones: &[(i64, i64, i64)], inicio: i64, fin: i64) -> Option<i64> {
    sesiones
        .iter()
        .find(|(_, desde, hasta)| *desde <= inicio && fin <= *hasta)
        .map(|(id, _, _)| *id)
}

/// Alertas del perfil de referencia: 20 000 en 90 días con un 90 % de info.
fn crear_alertas(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    if perfil.alerts == 0 || dispositivos.is_empty() {
        return Ok(());
    }
    let dias = perfil.alert_days.max(1);
    let inicio = perfil.end - dias * 86_400;
    let ventana = dias * 86_400;
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT INTO ALERTS
                 (rule, level, subject, device_id, key, title, subject_label, details,
                  created_at, last_at, count, seen_at, resolved_at, notified, summary_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL)",
        )?;
        let mut ultimas: Vec<i64> = Vec::new();
        for indice in 0..perfil.alerts {
            let regla = regla_sintetica(rng);
            let nivel = nivel_sintetico(indice, rng);
            let (subject, device_id, equipo) = sujeto_sintetico(regla, dispositivos, rng);
            let (clave, titulo) = clave_y_titulo(regla, rng);
            let etiqueta = etiqueta_de_sujeto(&subject, equipo, dispositivos);
            let details = detalles_sinteticos(regla, &clave, rng);
            let creada = inicio + rng.entre(0, ventana - 1);
            let last = (creada + rng.entre(0, 3_600)).min(perfil.end);
            let count = 1 + rng.entre(0, 4);
            let vista =
                (rng.unidad() < 0.65).then(|| (last + rng.entre(0, 86_400)).min(perfil.end));
            let resuelta = (es_condicion(regla) && rng.unidad() < 0.4)
                .then(|| (last + rng.entre(60, 86_400)).min(perfil.end));
            let notificada = nivel == Level::Important && rng.unidad() < 0.7;
            sentencia.execute(params![
                AlertRule::Rule(regla).as_str(),
                nivel.as_str(),
                subject.as_str(),
                device_id,
                clave,
                titulo,
                etiqueta,
                details,
                localtime::rfc3339(creada),
                localtime::rfc3339(last),
                count,
                vista.map(localtime::rfc3339),
                resuelta.map(localtime::rfc3339),
                notificada,
            ])?;
            let id = tx.last_insert_rowid();
            ultimas.push(id);
            if ultimas.len() > 4 {
                ultimas.remove(0);
            }
            // De vez en cuando, un resumen de la puesta al día que agrupa las
            // últimas alertas (para el detalle y la vista de la TUI).
            if indice > 0 && indice % 200 == 0 {
                insertar_resumen(&tx, perfil, &ultimas, rng)?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// Regla del catálogo con la distribución del generador.
fn regla_sintetica(rng: &mut Rng) -> RuleId {
    match rng.rango(100) {
        0..=9 => RuleId::NewApp,
        10..=17 => RuleId::NewCategory,
        18..=24 => RuleId::NewOrg,
        25..=30 => RuleId::NewCountry,
        31..=36 => RuleId::NewJa4,
        37..=47 => RuleId::TrafficHigh,
        48..=57 => RuleId::DeviceNew,
        58..=64 => RuleId::PortNew,
        65..=70 => RuleId::MacChanged,
        71..=74 => RuleId::NameChanged,
        75..=77 => RuleId::OsChanged,
        78..=80 => RuleId::TypeChanged,
        81..=83 => RuleId::WatchedPresence,
        84..=86 => RuleId::CaptureStopped,
        87..=89 => RuleId::CaptureDrops,
        90..=92 => RuleId::DbSize,
        93..=95 => RuleId::NewApp,
        _ => RuleId::TrafficHigh,
    }
}

/// Nivel con el 90 % exacto de info del perfil de referencia (§7.16).
///
/// Uno de cada diez es importante o aviso; así la proporción no depende de la
/// suerte del RNG y cuadra con lo que pide el informe.
fn nivel_sintetico(indice: usize, rng: &mut Rng) -> Level {
    if !indice.is_multiple_of(10) {
        Level::Info
    } else if rng.rango(2) == 0 {
        Level::Important
    } else {
        Level::Warning
    }
}

/// Sujeto, device_id e índice del equipo de una alerta sintética.
fn sujeto_sintetico(
    regla: RuleId,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> (AlertSubject, Option<i64>, Option<usize>) {
    let indice = rng.rango(dispositivos.len());
    let de_equipo = |indice: usize| {
        (
            AlertSubject::Device(dispositivos[indice]),
            Some(dispositivos[indice]),
            Some(indice),
        )
    };
    match regla {
        RuleId::NewApp
        | RuleId::NewCategory
        | RuleId::NewOrg
        | RuleId::NewCountry
        | RuleId::NewJa4 => {
            if rng.unidad() < 0.5 {
                (AlertSubject::Host, None, None)
            } else {
                de_equipo(indice)
            }
        }
        RuleId::TrafficHigh => match rng.rango(10) {
            0 => (AlertSubject::Host, None, None),
            1 => (AlertSubject::Network, None, None),
            _ => de_equipo(indice),
        },
        RuleId::WatchedPresence
        | RuleId::DeviceNew
        | RuleId::PortNew
        | RuleId::MacChanged
        | RuleId::NameChanged
        | RuleId::OsChanged
        | RuleId::TypeChanged => de_equipo(indice),
        RuleId::CaptureStopped | RuleId::CaptureDrops | RuleId::DbSize => {
            (AlertSubject::Almenara, None, None)
        }
    }
}

/// Clave y título de una alerta sintética.
fn clave_y_titulo(regla: RuleId, rng: &mut Rng) -> (String, String) {
    match regla {
        RuleId::NewApp => {
            let app = &APPS[rng.rango(APPS.len())];
            (app.clave.to_string(), format!("App nueva: {}", app.clave))
        }
        RuleId::NewCategory => {
            let app = &APPS[rng.rango(APPS.len())];
            (
                app.categoria.to_string(),
                format!("Categoría nueva: {}", app.categoria),
            )
        }
        RuleId::NewOrg => {
            let app = &APPS[rng.rango(APPS.len())];
            (
                app.org.to_string(),
                format!("Organización nueva: {}", app.org),
            )
        }
        RuleId::NewCountry => {
            let app = &APPS[rng.rango(APPS.len())];
            (app.pais.to_string(), format!("País nuevo: {}", app.pais))
        }
        RuleId::NewJa4 => {
            let huella = JA4_SINTETICAS[rng.rango(JA4_SINTETICAS.len())];
            (huella.to_string(), "Huella TLS nueva (JA4)".to_string())
        }
        RuleId::TrafficHigh => {
            let sentido = if rng.rango(2) == 0 { "down" } else { "up" };
            (
                sentido.to_string(),
                "Más tráfico de lo habitual".to_string(),
            )
        }
        RuleId::DeviceNew => (String::new(), "Equipo nuevo".to_string()),
        RuleId::PortNew => {
            let puerto = if rng.rango(2) == 0 {
                "22/tcp"
            } else {
                "445/tcp"
            };
            (puerto.to_string(), format!("Puerto nuevo: {puerto}"))
        }
        RuleId::MacChanged => (String::new(), "Cambio de MAC".to_string()),
        RuleId::NameChanged => (String::new(), "Cambio de nombre".to_string()),
        RuleId::OsChanged => (String::new(), "Cambio de SO".to_string()),
        RuleId::TypeChanged => (String::new(), "Cambio de tipo".to_string()),
        RuleId::WatchedPresence => {
            if rng.rango(2) == 0 {
                ("gone".to_string(), "Vigilado ausente".to_string())
            } else {
                ("back".to_string(), "Vigilado de vuelta".to_string())
            }
        }
        RuleId::CaptureStopped => ("capture".to_string(), "Captura parada".to_string()),
        RuleId::CaptureDrops => ("drops".to_string(), "Pérdidas de captura".to_string()),
        RuleId::DbSize => ("db".to_string(), "Base de datos grande".to_string()),
    }
}

/// El porqué (JSON) de una alerta sintética.
fn detalles_sinteticos(regla: RuleId, clave: &str, rng: &mut Rng) -> String {
    match regla {
        RuleId::TrafficHigh => {
            let valor = 400_000_000 + rng.entre(0, 3_000_000_000);
            let factor = valor / 400_000_000;
            format!(
                r#"{{"direction":"{clave}","value":{valor},"median":400000000,"factor":{factor},"samples":14}}"#
            )
        }
        RuleId::NewApp
        | RuleId::NewCategory
        | RuleId::NewOrg
        | RuleId::NewCountry
        | RuleId::NewJa4 => {
            let tipo = tipo_de_clave(regla);
            format!(r#"{{"kind":"{tipo}","key":"{clave}"}}"#)
        }
        _ => "{}".to_string(),
    }
}

/// Tipo de clave de inventario de una regla de lo nuevo.
fn tipo_de_clave(regla: RuleId) -> &'static str {
    match regla {
        RuleId::NewApp => "app",
        RuleId::NewCategory => "category",
        RuleId::NewOrg => "org",
        RuleId::NewCountry => "country",
        _ => "ja4",
    }
}

/// Indica si la regla es de condición (puede quedar resuelta).
fn es_condicion(regla: RuleId) -> bool {
    matches!(
        regla,
        RuleId::WatchedPresence | RuleId::CaptureStopped | RuleId::CaptureDrops | RuleId::DbSize
    )
}

/// Etiqueta visible de un sujeto de alerta sintética.
fn etiqueta_de_sujeto(
    subject: &AlertSubject,
    equipo: Option<usize>,
    dispositivos: &[i64],
) -> String {
    match subject {
        AlertSubject::Device(id) => {
            let indice = equipo.unwrap_or_else(|| {
                dispositivos
                    .iter()
                    .position(|candidato| candidato == id)
                    .unwrap_or(0)
            });
            etiqueta_de_equipo_sintetico(indice)
        }
        otro => otro.label().to_string(),
    }
}

/// Nombre visible de un equipo del generador (el mismo con el que se crea).
fn etiqueta_de_equipo_sintetico(indice: usize) -> String {
    if indice.is_multiple_of(5) {
        format!("alias-{:02}", indice + 1)
    } else {
        format!("equipo-{:02}", indice + 1)
    }
}

/// Resumen de la puesta al día que agrupa las últimas alertas.
fn insertar_resumen(
    tx: &Connection,
    perfil: &SyntheticProfile,
    agrupadas: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    if agrupadas.is_empty() {
        return Ok(());
    }
    let creada = perfil.end - rng.entre(0, perfil.alert_days.max(1) * 86_400);
    let titulo = format!("Resumen al arrancar ({} alertas)", agrupadas.len());
    tx.execute(
        "INSERT INTO ALERTS
             (rule, level, subject, device_id, key, title, subject_label, details,
              created_at, last_at, count, seen_at, resolved_at, notified, summary_id)
         VALUES (?1, 'important', 'almenara', NULL, '', ?2, 'Almenara', ?3, ?4, ?4, 1,
                 NULL, NULL, 0, NULL)",
        params![
            AlertRule::CatchUp.as_str(),
            titulo,
            format!(r#"{{"grouped":{}}}"#, agrupadas.len()),
            localtime::rfc3339(creada)
        ],
    )?;
    let resumen = tx.last_insert_rowid();
    for agrupada in agrupadas {
        tx.execute(
            "UPDATE ALERTS SET summary_id = ?1 WHERE id = ?2",
            params![resumen, agrupada],
        )?;
    }
    Ok(())
}

/// Silencios del perfil de referencia (20).
fn crear_silencios(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    if perfil.mutes == 0 || dispositivos.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT OR IGNORE INTO ALERT_MUTES (rule, subject, device_id, until, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        // El UNIQUE (rule, subject, device_id) puede descartar un sorteo repetido:
        // se reintenta (con el mismo RNG determinista) hasta llegar al número pedido.
        let mut insertados = 0usize;
        let mut intentos = 0usize;
        while insertados < perfil.mutes && intentos < perfil.mutes * 20 {
            intentos += 1;
            let regla = regla_sintetica(rng);
            let indice = rng.rango(dispositivos.len());
            let (subject, device_id) = if rng.rango(4) == 0 {
                (AlertSubject::Host, 0)
            } else {
                (
                    AlertSubject::Device(dispositivos[indice]),
                    dispositivos[indice],
                )
            };
            let until = match rng.rango(3) {
                0 => None,
                1 => Some(perfil.end + 86_400),
                _ => Some(perfil.end + 7 * 86_400),
            };
            let creado = perfil.end - rng.entre(0, 30 * 86_400);
            insertados += sentencia.execute(params![
                AlertRule::Rule(regla).as_str(),
                subject.as_str(),
                device_id,
                until.map(localtime::rfc3339),
                localtime::rfc3339(creado)
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Aprendizaje de los equipos y del propio equipo (§7.3 y §7.16).
fn crear_aprendizaje(
    conn: &mut Connection,
    perfil: &SyntheticProfile,
    dispositivos: &[i64],
    rng: &mut Rng,
) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT OR REPLACE INTO ALERT_LEARNING
                 (subject, device_id, learning_from, data_days, learned_at, updated_day)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        let ayer = LocalDay::from_unix(perfil.end).sumar_dias(-1).aaaammdd();
        for device_id in dispositivos {
            let dias = rng.rango(9) as i64;
            let desde = perfil.end - rng.entre(30, 365) * 86_400;
            let aprendido = (dias >= 7).then(|| perfil.end - rng.entre(0, 7) * 86_400);
            sentencia.execute(params![
                "device",
                device_id,
                localtime::rfc3339(desde),
                dias,
                aprendido.map(localtime::rfc3339),
                ayer
            ])?;
        }
        // El propio equipo empieza de cero en la v6 (§7.3).
        let dias = rng.rango(9) as i64;
        let desde = perfil.end - 10 * 86_400;
        let aprendido = (dias >= 7).then(|| perfil.end - 86_400);
        sentencia.execute(params![
            "host",
            0i64,
            localtime::rfc3339(desde),
            dias,
            aprendido.map(localtime::rfc3339),
            ayer
        ])?;
    }
    tx.commit()?;
    Ok(())
}

/// Inventario del propio equipo (HOST_SEEN): 300 entradas en el perfil de
/// referencia (§7.16), sin claves especiales ni destinos.
fn crear_host_seen(conn: &mut Connection, perfil: &SyntheticProfile, rng: &mut Rng) -> Result<()> {
    if perfil.host_seen == 0 {
        return Ok(());
    }
    // Reparto por tipo que garantiza exactamente perfil.host_seen claves (los
    // países solo se repiten hasta su catálogo; el resto se reparte entre apps,
    // categorías, organizaciones y huellas JA4).
    let paises = ["US", "IE", "NL", "DE", "ES", "SE", "SG", "GB", "FR", "JP"];
    let total = perfil.host_seen;
    let paises_n = (total / 10).max(1).min(paises.len()).min(total);
    let resto = total - paises_n;
    let apps_n = resto * 30 / 100;
    let cats_n = resto * 15 / 100;
    let orgs_n = resto * 25 / 100;
    let ja4_n = resto - apps_n - cats_n - orgs_n;
    let mut claves: Vec<(&'static str, String)> = Vec::with_capacity(total);
    for indice in 0..paises_n {
        claves.push(("country", paises[indice % paises.len()].to_string()));
    }
    for indice in 0..apps_n {
        claves.push(("app", format!("app-sintetica-{indice:03}")));
    }
    for indice in 0..cats_n {
        claves.push(("category", format!("categoria-{indice}")));
    }
    for indice in 0..orgs_n {
        claves.push(("org", format!("org-sintetica-{indice:03}")));
    }
    for indice in 0..ja4_n {
        claves.push(("ja4", format!("t13d1516h2_{indice:012x}")));
    }
    let tx = conn.transaction()?;
    {
        let mut sentencia = tx.prepare(
            "INSERT INTO HOST_SEEN (kind, key, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (kind, key) DO UPDATE SET last_seen = excluded.last_seen",
        )?;
        for (kind, key) in claves {
            let primero = perfil.end - rng.entre(0, 365 * 86_400);
            let ultimo = perfil.end - rng.entre(0, 30 * 86_400);
            let (primero, ultimo) = if primero <= ultimo {
                (primero, ultimo)
            } else {
                (ultimo, primero)
            };
            sentencia.execute(params![
                kind,
                key,
                localtime::rfc3339(primero),
                localtime::rfc3339(ultimo)
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Pruebas y mediciones
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params_from_iter;
    use std::time::{Duration, Instant};

    use crate::alerts::{LearningParams, Level};
    use crate::history::queries::Queries;
    use crate::history::{AlertFilter, Page, Retention, SubjectSel};
    use crate::repo::Repo;

    fn conexion_en_memoria() -> Connection {
        let mut conn = Connection::open_in_memory().expect("SQLite en memoria");
        migrations::apply_all(&mut conn).expect("aplicar migraciones");
        crate::history::esquema_v6_de_pruebas(&conn).expect("esquema v6 de pruebas");
        conn
    }

    fn contar_tabla(conn: &Connection, tabla: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |fila| {
            fila.get(0)
        })
        .expect("contar filas")
    }

    #[test]
    fn el_rng_es_determinista_y_no_se_queda_a_cero() {
        let mut uno = Rng::nuevo(12345);
        let mut otro = Rng::nuevo(12345);
        for _ in 0..100 {
            assert_eq!(uno.siguiente(), otro.siguiente());
        }
        let mut rng = Rng::nuevo(0);
        assert_ne!(rng.siguiente(), 0, "la semilla cero se corrige");
        let valores: Vec<usize> = (0..10).map(|_| rng.rango(5)).collect();
        assert!(valores.iter().all(|valor| *valor < 5));
    }

    #[test]
    fn el_perfil_es_determinista() {
        let perfil = SyntheticProfile::de_prueba();
        let mut primera = conexion_en_memoria();
        let stats_uno = Synthetic::generate(&mut primera, &perfil).expect("generar primera");
        let mut segunda = conexion_en_memoria();
        let stats_dos = Synthetic::generate(&mut segunda, &perfil).expect("generar segunda");
        assert_eq!(stats_uno, stats_dos, "el perfil debe ser determinista");
        for tabla in [
            "TRAFFIC_ROLLUP_MINUTE",
            "TRAFFIC_ROLLUP_HOUR",
            "TRAFFIC_ROLLUP_DAY",
            "DEVICE_SEEN",
            "DEVICE_EVENTS",
            "APP_SESSIONS",
            "ALERTS",
            "ALERT_MUTES",
            "ALERT_LEARNING",
            "HOST_SEEN",
            "COVERAGE_GAPS",
            "DEVICE_SERVICES",
        ] {
            assert_eq!(
                contar_tabla(&primera, tabla),
                contar_tabla(&segunda, tabla),
                "filas distintas en {tabla}"
            );
        }
        let suma_uno: i64 = primera
            .query_row(
                "SELECT SUM(bytes_down + bytes_up) FROM TRAFFIC_ROLLUP_MINUTE",
                [],
                |fila| fila.get(0),
            )
            .expect("suma");
        let suma_dos: i64 = segunda
            .query_row(
                "SELECT SUM(bytes_down + bytes_up) FROM TRAFFIC_ROLLUP_MINUTE",
                [],
                |fila| fila.get(0),
            )
            .expect("suma");
        assert_eq!(suma_uno, suma_dos, "los bytes deben ser deterministas");
    }

    #[test]
    fn genera_las_tres_resoluciones_el_inventario_y_las_sesiones() {
        let perfil = SyntheticProfile::de_prueba();
        let mut conn = conexion_en_memoria();
        let stats = Synthetic::generate(&mut conn, &perfil).expect("generar");
        assert_eq!(stats.devices, perfil.devices as u64);
        assert!(stats.minutes > 0 && stats.hours > 0 && stats.days > 0);
        assert!(stats.seen > 0 && stats.events > 0 && stats.sessions > 0);
        assert!(stats.bytes > 0);
        assert_eq!(
            contar_tabla(&conn, "TRAFFIC_ROLLUP_MINUTE") as u64,
            stats.minutes
        );
        assert_eq!(
            contar_tabla(&conn, "TRAFFIC_ROLLUP_HOUR") as u64,
            stats.hours
        );
        assert_eq!(contar_tabla(&conn, "TRAFFIC_ROLLUP_DAY") as u64, stats.days);
        assert_eq!(contar_tabla(&conn, "DEVICE_SEEN") as u64, stats.seen);
        assert_eq!(contar_tabla(&conn, "DEVICE_EVENTS") as u64, stats.events);
        assert_eq!(contar_tabla(&conn, "APP_SESSIONS") as u64, stats.sessions);
        // Los minutos están dentro de la ventana y alineados al minuto.
        let (minimo, maximo): (i64, i64) = conn
            .query_row(
                "SELECT MIN(bucket), MAX(bucket) FROM TRAFFIC_ROLLUP_MINUTE",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("ventana de minutos");
        assert!(minimo >= perfil.end - perfil.minute_hours * 3_600);
        assert!(maximo < perfil.end);
        assert_eq!(minimo.rem_euclid(60), 0);
        // Los días son fechas locales AAAAMMDD válidas.
        let mut sentencia = conn
            .prepare("SELECT DISTINCT bucket FROM TRAFFIC_ROLLUP_DAY")
            .expect("días");
        let dias = sentencia
            .query_map([], |fila| fila.get::<_, i64>(0))
            .expect("leer días");
        for dia in dias {
            assert!(LocalDay::from_aaaammdd(dia.expect("día")).is_some());
        }
        // Hay sesiones con captura y sin captura.
        let con_captura: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM APP_SESSIONS WHERE capture = 1",
                [],
                |fila| fila.get(0),
            )
            .expect("captura");
        assert!(con_captura > 0);
        let sin_captura: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM APP_SESSIONS WHERE capture = 0",
                [],
                |fila| fila.get(0),
            )
            .expect("captura");
        assert!(sin_captura >= 0);
        // Datos de la F6 (§7.16).
        assert_eq!(
            contar_tabla(&conn, "ALERTS") as u64,
            stats.alerts,
            "las alertas generadas cuadran"
        );
        assert!(
            stats.alerts >= perfil.alerts as u64,
            "al menos las alertas pedidas (más los resúmenes)"
        );
        assert_eq!(
            stats.mutes, perfil.mutes as u64,
            "los silencios pedidos se generan todos (el UNIQUE reintenta)"
        );
        assert_eq!(
            stats.learning,
            perfil.devices as u64 + 1,
            "aprendizaje de los equipos y del propio equipo"
        );
        assert_eq!(stats.host_seen, perfil.host_seen as u64);
        assert!(stats.gaps > 0, "hay suspensiones nocturnas");
        let info: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ALERTS WHERE level = 'info'",
                [],
                |fila| fila.get(0),
            )
            .expect("alertas info");
        let porcentaje_info = info as f64 / stats.alerts as f64;
        assert!(
            porcentaje_info > 0.85,
            "el perfil de referencia es ~90 % info (medido {porcentaje_info:.2})"
        );
        let aprendizaje_host: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ALERT_LEARNING
                  WHERE subject = 'host' AND device_id = 0",
                [],
                |fila| fila.get(0),
            )
            .expect("aprendizaje del host");
        assert_eq!(aprendizaje_host, 1);
        let suspensiones: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM COVERAGE_GAPS WHERE kind = 'suspend'",
                [],
                |fila| fila.get(0),
            )
            .expect("suspensiones");
        assert_eq!(suspensiones as u64, stats.gaps);
        // El inventario del propio equipo no guarda claves especiales.
        let especiales: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM HOST_SEEN WHERE key LIKE '~%'",
                [],
                |fila| fila.get(0),
            )
            .expect("claves especiales");
        assert_eq!(especiales, 0);
    }

    #[test]
    #[ignore]
    fn medir_historial() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("historico-sintetico.db");
        let mut conn = Connection::open(&ruta).expect("abrir BD");
        migrations::apply_all(&mut conn).expect("aplicar migraciones");
        crate::history::esquema_v6_de_pruebas(&conn).expect("esquema v6 de pruebas");
        let perfil = SyntheticProfile::default();
        println!("== medir_historial: perfil de referencia (§7.14) ==");
        println!(
            "perfil: {} equipos · {} días · {} días de horas · {} h de minutos · semilla {:#x}",
            perfil.devices, perfil.days, perfil.hour_days, perfil.minute_hours, perfil.seed
        );

        let inicio = Instant::now();
        let stats = Synthetic::generate(&mut conn, &perfil).expect("generar histórico");
        let generacion = inicio.elapsed();
        println!(
            "generación: {:.2} s ({} equipos, {} filas de histórico)",
            generacion.as_secs_f64(),
            stats.devices,
            stats.total_filas()
        );

        // Tamaño real de la base de datos (páginas) y del WAL.
        let paginas: i64 = conn
            .query_row("PRAGMA page_count", [], |fila| fila.get(0))
            .expect("páginas");
        let tamano_pagina: i64 = conn
            .query_row("PRAGMA page_size", [], |fila| fila.get(0))
            .expect("tamaño de página");
        let mb = (paginas as f64 * tamano_pagina as f64) / 1_000_000.0;
        let wal = std::fs::metadata(ruta.with_extension("db-wal"))
            .map(|meta| meta.len() as f64 / 1_000_000.0)
            .unwrap_or(0.0);
        println!(
            "BD: {:.1} MB ({} páginas de {} B) · WAL {:.1} MB",
            mb, paginas, tamano_pagina, wal
        );
        println!(
            "filas: minutos={} horas={} días={} inventario={} eventos={} sesiones={}",
            contar_tabla(&conn, "TRAFFIC_ROLLUP_MINUTE"),
            contar_tabla(&conn, "TRAFFIC_ROLLUP_HOUR"),
            contar_tabla(&conn, "TRAFFIC_ROLLUP_DAY"),
            contar_tabla(&conn, "DEVICE_SEEN"),
            contar_tabla(&conn, "DEVICE_EVENTS"),
            contar_tabla(&conn, "APP_SESSIONS"),
        );
        println!(
            "filas F6: alertas={} silencios={} aprendizaje={} host_seen={} huecos={}",
            contar_tabla(&conn, "ALERTS"),
            contar_tabla(&conn, "ALERT_MUTES"),
            contar_tabla(&conn, "ALERT_LEARNING"),
            contar_tabla(&conn, "HOST_SEEN"),
            contar_tabla(&conn, "COVERAGE_GAPS"),
        );

        // Construcción de una hora: agregación de sus minutos (como build_hour).
        let fin_hora = perfil.end - perfil.end.rem_euclid(3_600);
        let hora = fin_hora - 3_600;
        let inicio = Instant::now();
        conn.execute_batch(
            "DROP TABLE IF EXISTS MEDIDA_HORA;
             CREATE TEMP TABLE MEDIDA_HORA AS
             SELECT subject, device_id, dimension, key,
                    SUM(bytes_down) AS bytes_down, SUM(bytes_up) AS bytes_up,
                    SUM(connections) AS connections
               FROM TRAFFIC_ROLLUP_MINUTE
              WHERE bucket >= 0 AND bucket < 0
              GROUP BY subject, device_id, dimension, key;",
        )
        .expect("preparar tabla de medida");
        conn.execute(
            "INSERT INTO MEDIDA_HORA
             SELECT subject, device_id, dimension, key,
                    SUM(bytes_down), SUM(bytes_up), SUM(connections)
               FROM TRAFFIC_ROLLUP_MINUTE
              WHERE bucket >= ?1 AND bucket < ?2
              GROUP BY subject, device_id, dimension, key",
            params![hora, hora + 3_600],
        )
        .expect("agregar hora");
        let filas_hora = contar_tabla(&conn, "MEDIDA_HORA");
        let tiempo_hora = inicio.elapsed();
        println!(
            "construcción de una hora: {:.2} ms ({} filas)",
            tiempo_hora.as_secs_f64() * 1_000.0,
            filas_hora
        );

        // Construcción de un día local: agregación de sus horas (sin destinos).
        let ayer = LocalDay::from_unix(perfil.end).sumar_dias(-1);
        let (desde_dia, hasta_dia) = ayer.limits();
        let inicio = Instant::now();
        conn.execute_batch(
            "DROP TABLE IF EXISTS MEDIDA_DIA;
             CREATE TEMP TABLE MEDIDA_DIA AS
             SELECT subject, device_id, dimension, key,
                    SUM(bytes_down) AS bytes_down, SUM(bytes_up) AS bytes_up,
                    SUM(connections) AS connections
               FROM TRAFFIC_ROLLUP_HOUR
              WHERE bucket >= 0 AND bucket < 0 AND dimension <> 'destination'
              GROUP BY subject, device_id, dimension, key;",
        )
        .expect("preparar tabla de día");
        conn.execute(
            "INSERT INTO MEDIDA_DIA
             SELECT subject, device_id, dimension, key,
                    SUM(bytes_down), SUM(bytes_up), SUM(connections)
               FROM TRAFFIC_ROLLUP_HOUR
              WHERE bucket >= ?1 AND bucket < ?2 AND dimension <> 'destination'
              GROUP BY subject, device_id, dimension, key",
            params![desde_dia, hasta_dia],
        )
        .expect("agregar día");
        let filas_dia = contar_tabla(&conn, "MEDIDA_DIA");
        let tiempo_dia = inicio.elapsed();
        println!(
            "construcción de un día: {:.2} ms ({} filas)",
            tiempo_dia.as_secs_f64() * 1_000.0,
            filas_dia
        );
        conn.execute_batch("DROP TABLE MEDIDA_HORA; DROP TABLE MEDIDA_DIA;")
            .expect("limpiar medidas");

        // Purga por resolución con retenciones más cortas (para que borre algo).
        let retencion = Retention {
            minute_days: 1,
            hour_days: 30,
            day_days: 365,
            destination_days: 7,
        };
        let ahora = perfil.end;
        let inicio = Instant::now();
        let mut borradas = 0i64;
        borradas += conn
            .execute(
                "DELETE FROM TRAFFIC_ROLLUP_MINUTE WHERE bucket < ?1",
                params![ahora - i64::from(retencion.minute_days) * 86_400],
            )
            .expect("purga de minutos") as i64;
        borradas += conn
            .execute(
                "DELETE FROM TRAFFIC_ROLLUP_MINUTE
                  WHERE dimension = 'destination' AND bucket < ?1",
                params![ahora - 2 * 3_600],
            )
            .expect("purga de destinos por minuto") as i64;
        borradas += conn
            .execute(
                "DELETE FROM TRAFFIC_ROLLUP_HOUR WHERE bucket < ?1",
                params![ahora - i64::from(retencion.hour_days) * 86_400],
            )
            .expect("purga de horas") as i64;
        borradas += conn
            .execute(
                "DELETE FROM TRAFFIC_ROLLUP_HOUR
                  WHERE dimension = 'destination' AND bucket < ?1",
                params![ahora - i64::from(retencion.destination_days) * 86_400],
            )
            .expect("purga de destinos por hora") as i64;
        borradas += conn
            .execute(
                "DELETE FROM TRAFFIC_ROLLUP_DAY WHERE bucket < ?1",
                params![LocalDay::from_unix(ahora)
                    .sumar_dias(-i64::from(retencion.day_days))
                    .aaaammdd()],
            )
            .expect("purga de días") as i64;
        conn.execute_batch("PRAGMA incremental_vacuum(2000);")
            .expect("compactar");
        let tiempo_purga = inicio.elapsed();
        println!(
            "purga + incremental_vacuum: {:.2} ms ({} filas borradas)",
            tiempo_purga.as_secs_f64() * 1_000.0,
            borradas
        );

        // Consultas de 24 h, 7 días, 30 días y 1 año (SQL directo, como el lector).
        let fin_hora = perfil.end - perfil.end.rem_euclid(3_600);
        let hoy = LocalDay::from_unix(perfil.end);
        let consultas: [(&str, &str, Vec<i64>); 4] = [
            (
                "24 h (minutos)",
                "SELECT SUM(bytes_down), SUM(bytes_up) FROM TRAFFIC_ROLLUP_MINUTE
                  WHERE bucket >= ?1 AND bucket < ?2 AND subject = 'network'
                    AND dimension = 'total'",
                vec![fin_hora - 24 * 3_600, fin_hora],
            ),
            (
                "7 días (horas)",
                "SELECT SUM(bytes_down), SUM(bytes_up) FROM TRAFFIC_ROLLUP_HOUR
                  WHERE bucket >= ?1 AND bucket < ?2 AND subject = 'network'
                    AND dimension = 'total'",
                vec![fin_hora - 7 * 86_400, fin_hora],
            ),
            (
                "30 días (días)",
                "SELECT SUM(bytes_down), SUM(bytes_up) FROM TRAFFIC_ROLLUP_DAY
                  WHERE bucket >= ?1 AND bucket < ?2 AND subject = 'network'
                    AND dimension = 'total'",
                vec![hoy.sumar_dias(-29).aaaammdd(), hoy.aaaammdd()],
            ),
            (
                "1 año (días)",
                "SELECT SUM(bytes_down), SUM(bytes_up) FROM TRAFFIC_ROLLUP_DAY
                  WHERE bucket >= ?1 AND bucket < ?2 AND subject = 'network'
                    AND dimension = 'total'",
                vec![hoy.sumar_dias(-365).aaaammdd(), hoy.aaaammdd()],
            ),
        ];
        let mut tiempos = Vec::new();
        for (nombre, sql, parametros) in consultas {
            let inicio = Instant::now();
            let (down, up): (Option<i64>, Option<i64>) = conn
                .query_row(sql, params_from_iter(parametros), |fila| {
                    Ok((fila.get(0)?, fila.get(1)?))
                })
                .expect("consulta del rango");
            let tiempo = inicio.elapsed();
            println!(
                "consulta {}: {:.2} ms ({} bytes)",
                nombre,
                tiempo.as_secs_f64() * 1_000.0,
                down.unwrap_or(0) + up.unwrap_or(0)
            );
            tiempos.push(tiempo);
        }

        // «Más tráfico» de 7 días por app: la consulta más pesada del lector.
        let inicio = Instant::now();
        let mut sentencia = conn
            .prepare(
                "SELECT key, SUM(bytes_down + bytes_up) AS total
                   FROM TRAFFIC_ROLLUP_HOUR
                  WHERE bucket >= ?1 AND bucket < ?2 AND dimension = 'app'
                    AND subject <> 'network'
                  GROUP BY key
                  ORDER BY total DESC
                  LIMIT 20",
            )
            .expect("preparar top");
        let filas_top = sentencia
            .query_map(params![fin_hora - 7 * 86_400, fin_hora], |_fila| Ok(()))
            .expect("top")
            .count();
        let tiempo_top = inicio.elapsed();
        println!(
            "consulta top 7 días por app: {:.2} ms ({} filas)",
            tiempo_top.as_secs_f64() * 1_000.0,
            filas_top
        );

        // Aserciones holgadas de rendimiento: el objetivo del informe es anotar
        // las cifras reales, no fijar umbrales estrictos.
        assert!(
            generacion.as_secs() < 180,
            "la generación es demasiado lenta"
        );
        assert!(mb < 1_024.0, "la BD sintética supera 1 GB");
        assert!(
            tiempo_hora.as_millis() < 1_000,
            "build_hour demasiado lento"
        );
        assert!(tiempo_dia.as_millis() < 2_000, "build_day demasiado lento");
        assert!(
            tiempo_purga.as_millis() < 3_000,
            "la purga es demasiado lenta"
        );
        for tiempo in &tiempos {
            assert!(
                tiempo.as_millis() < 2_000,
                "una consulta del lector supera 2 s"
            );
        }
        assert!(filas_hora > 0 && filas_dia > 0);
        assert!(filas_top > 0);
    }

    /// Aplica solo las migraciones hasta la versión indicada (para medir la v6
    /// sobre una base en la v5 sin el VACUUM inicial de F5).
    fn aplicar_hasta(conn: &mut Connection, version_max: u32) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS SCHEMA_MIGRATIONS (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );",
        )?;
        for migracion in migrations::MIGRATIONS
            .iter()
            .filter(|migracion| migracion.version <= version_max)
        {
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
                params![migracion.version, "2026-01-01T00:00:00Z"],
            )?;
            transaccion.commit()?;
        }
        let modo: i64 = conn.query_row("PRAGMA auto_vacuum", [], |fila| fila.get(0))?;
        if modo != 2 {
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
        }
        Ok(())
    }

    #[test]
    #[ignore]
    fn medir_alertas_consulta() {
        let mut conn = conexion_en_memoria();
        let perfil = SyntheticProfile::default();
        println!("== medir_alertas_consulta: 20 000 alertas en 90 días (§8) ==");
        let stats = Synthetic::generate(&mut conn, &perfil).expect("generar");
        println!(
            "alertas={} · silencios={} · aprendizaje={} · host_seen={} · huecos={}",
            stats.alerts, stats.mutes, stats.learning, stats.host_seen, stats.gaps
        );
        let consultas: [(&str, AlertFilter, Page); 5] = [
            (
                "todas",
                AlertFilter::default(),
                Page {
                    limit: 50,
                    offset: 0,
                },
            ),
            (
                "sin ver",
                AlertFilter {
                    unseen_only: true,
                    ..AlertFilter::default()
                },
                Page {
                    limit: 50,
                    offset: 0,
                },
            ),
            (
                "importantes",
                AlertFilter {
                    level: Some(Level::Important),
                    ..AlertFilter::default()
                },
                Page {
                    limit: 50,
                    offset: 0,
                },
            ),
            (
                "página honda",
                AlertFilter::default(),
                Page {
                    limit: 50,
                    offset: 15_000,
                },
            ),
            (
                "búsqueda",
                AlertFilter {
                    search: Some("equipo-03".to_string()),
                    ..AlertFilter::default()
                },
                Page {
                    limit: 50,
                    offset: 0,
                },
            ),
        ];
        let mut peor = Duration::ZERO;
        for (nombre, filtro, pagina) in consultas {
            let inicio = Instant::now();
            let filas = Queries::alerts(&conn, &filtro, pagina).expect("consulta de alertas");
            let tiempo = inicio.elapsed();
            peor = peor.max(tiempo);
            println!(
                "{nombre}: {:.2} ms ({} filas)",
                tiempo.as_secs_f64() * 1_000.0,
                filas.len()
            );
        }
        let inicio = Instant::now();
        let detalle = Queries::alert_detail(&conn, 1).expect("detalle de la alerta 1");
        let tiempo_detalle = inicio.elapsed();
        println!(
            "detalle: {:.2} ms ({} alertas agrupadas)",
            tiempo_detalle.as_secs_f64() * 1_000.0,
            detalle.grouped.len()
        );
        assert!(
            peor.as_millis() <= 100,
            "Queries::alerts ≤ 100 ms con 20 000 alertas (peor {peor:?})"
        );
        assert!(
            tiempo_detalle.as_millis() <= 100,
            "alert_detail ≤ 100 ms con 20 000 alertas"
        );
        assert_eq!(detalle.row.id, 1);

        // Resúmenes de equipo (detalle), del host (Config), reglas y silencios:
        // son consultas del lector y van con el mismo límite de 100 ms.
        let dispositivos: Vec<i64> = {
            let mut sentencia = conn
                .prepare("SELECT id FROM DEVICES ORDER BY id")
                .expect("equipos");
            let filas = sentencia
                .query_map([], |fila| fila.get(0))
                .expect("ids de los equipos");
            filas.map(|fila| fila.expect("id")).collect()
        };
        let inicio = Instant::now();
        let mut recientes = 0;
        for device_id in &dispositivos {
            let resumen = Queries::alert_summary(&conn, SubjectSel::Device(*device_id), perfil.end)
                .expect("resumen del equipo");
            recientes += resumen.recent.len();
        }
        let host = Queries::alert_summary(&conn, SubjectSel::Host, perfil.end)
            .expect("resumen del propio equipo");
        assert!(
            host.inventory.is_some(),
            "el resumen del host trae su inventario"
        );
        let reglas = Queries::rule_stats(&conn, perfil.end - 7 * 86_400).expect("reglas");
        let silencios = Queries::mutes(&conn, perfil.end).expect("silencios");
        let tiempo_resumenes = inicio.elapsed();
        println!(
            "resúmenes de {} equipos + host, reglas y silencios: {:.2} ms ({} alertas recientes, {} reglas, {} silencios)",
            dispositivos.len(),
            tiempo_resumenes.as_secs_f64() * 1_000.0,
            recientes,
            reglas.len(),
            silencios.len()
        );
        assert!(
            tiempo_resumenes.as_millis() <= 100,
            "las consultas de resumen deben cumplir ≤ 100 ms (medido {tiempo_resumenes:?})"
        );
    }

    #[test]
    #[ignore]
    fn medir_alertas_aprendizaje() {
        // §8: aprendizaje de un día ≤ 50 ms con 50 equipos (Repo::update_learning).
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("aprendizaje.db");
        let mut repo = Repo::init(&ruta).expect("repositorio de prueba");
        let perfil = SyntheticProfile {
            devices: 50,
            ..SyntheticProfile::default()
        };
        println!("== medir_alertas_aprendizaje: día con datos de 50 equipos (§8) ==");
        let stats = Synthetic::generate(repo.connection_mut(), &perfil).expect("generar");
        println!(
            "perfil: {} equipos · {} filas de aprendizaje · {} sesiones · {} huecos",
            stats.devices, stats.learning, stats.sessions, stats.gaps
        );
        // El generador deja el día de ayer ya contado; se reinicia el aprendizaje
        // para medir la consolidación completa de ese día.
        repo.connection_mut()
            .execute(
                "UPDATE ALERT_LEARNING
                    SET updated_day = 0, data_days = 0, learned_at = NULL",
                [],
            )
            .expect("reiniciar aprendizaje");
        let ayer = LocalDay::from_unix(perfil.end).sumar_dias(-1);
        let parametros = LearningParams::default();
        let inicio = Instant::now();
        let cambios = repo
            .update_learning(ayer, &parametros)
            .expect("aprendizaje del día");
        let tiempo = inicio.elapsed();
        println!(
            "Repo::update_learning de {} equipos + host: {:.2} ms ({} sujetos llegan a aprendidos)",
            stats.devices,
            tiempo.as_secs_f64() * 1_000.0,
            cambios.len()
        );
        assert!(
            tiempo.as_millis() <= 50,
            "el aprendizaje de un día debe cumplir ≤ 50 ms (medido {tiempo:?})"
        );
    }

    #[test]
    #[ignore]
    fn medir_migracion_v6() {
        let directorio = tempfile::tempdir().expect("directorio temporal");
        let ruta = directorio.path().join("migracion-v6.db");
        let mut conn = Connection::open(&ruta).expect("abrir BD");
        aplicar_hasta(&mut conn, 5).expect("esquema v5");
        let perfil = SyntheticProfile::default();
        println!("== medir_migracion_v6: histórico sintético de 2 años (§8) ==");
        let stats = Synthetic::generate_historico_v5(&mut conn, &perfil)
            .expect("histórico sintético de la v5");
        println!(
            "BD v5: {} equipos · minutos={} horas={} días={} inventario={} eventos={} sesiones={} ({:.0} MB)",
            stats.devices,
            stats.minutes,
            stats.hours,
            stats.days,
            stats.seen,
            stats.events,
            stats.sessions,
            (conn
                .query_row("PRAGMA page_count", [], |fila| fila.get::<_, i64>(0))
                .unwrap_or(0) as f64
                * conn
                    .query_row("PRAGMA page_size", [], |fila| fila.get::<_, i64>(0))
                    .unwrap_or(0) as f64)
                / 1_000_000.0
        );
        let inicio = Instant::now();
        let version = migrations::apply_all(&mut conn).expect("migrar a la v6");
        let tiempo = inicio.elapsed();
        println!(
            "migración v5→v6 con sus rellenos: {:.2} ms (versión {version})",
            tiempo.as_secs_f64() * 1_000.0
        );
        if version >= 6 {
            let aprendidos: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM ALERT_LEARNING WHERE learned_at IS NOT NULL",
                    [],
                    |fila| fila.get(0),
                )
                .expect("equipos aprendidos");
            let cerrados: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM DEVICE_SERVICES WHERE closed_at IS NOT NULL",
                    [],
                    |fila| fila.get(0),
                )
                .expect("puertos cerrados");
            println!(
                "rellenos: {aprendidos} equipos aprendidos · {cerrados} puertos cerrados · {} entradas de aprendizaje",
                conn.query_row("SELECT COUNT(*) FROM ALERT_LEARNING", [], |fila| fila
                    .get::<_, i64>(0))
                .unwrap_or(0)
            );
            assert!(
                cerrados > 0,
                "el histórico sintético tiene puertos cerrados que rellenar"
            );
            assert!(
                tiempo.as_millis() <= 2_000,
                "la migración v6 con rellenos debe cumplir ≤ 2 s (medida {tiempo:?})"
            );
        } else {
            println!("la migración v6 todavía no existe: medición pendiente del equipo de datos");
        }
    }
}
