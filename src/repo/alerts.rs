//! DAO de las alertas y los silencios (ALERTS y ALERT_MUTES, §3).
//!
//! Solo el hilo de la TUI escribe estas tablas (ADR-35). El motor de alertas es
//! puro y devuelve acciones; este DAO las materializa: crea alertas y resúmenes,
//! suma repeticiones, resuelve condiciones, marca vistas, mantiene los silencios
//! y da al arrancar el estado que necesita `AlertEngine::new`.
//!
//! Las claves de deduplicación viven 24 h contadas desde `created_at`; al cargar
//! el estado del motor se traen las alertas del plazo máximo configurable (168 h)
//! y todas las condiciones activas, y el motor filtra con su plazo real.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime};

use rusqlite::{params, params_from_iter, Connection, ToSql};

use crate::alerts::{
    AlertCounts, DedupKey, EngineSnapshot, HourSubject, Level, MuteState, NewAlert, RecentState,
    RuleId, Subject, TrafficHighParams,
};
use crate::error::Result;
use crate::history::{localtime, LocalDay};
use crate::repo::gaps::{self, unix_de_instante};
use crate::repo::{instante_a_rfc3339, rfc3339_a_instante};

/// Plazo máximo de deduplicación admitido por la configuración (168 h, §7.14).
const DEDUP_MAX_HORAS: i64 = 168;

/// Reglas de condición, únicas cuyas alertas se resuelven (§7.5).
const REGLAS_CONDICION: &str = "'watched_presence', 'capture_stopped', 'capture_drops', 'db_size'";

/// Selección de alertas para marcarlas como vistas (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeenSel {
    /// Una alerta concreta; si es un resumen, también lo que agrupa.
    Alert(i64),
    /// Todas las alertas del filtro de la lista.
    Filter(AlertScope),
}

/// Filtro de la pestaña Alertas con el que se marcan todas como vistas.
///
/// Es la misma selección que pinta la lista: nivel, sin ver, equipo y búsqueda
/// por título o etiqueta del sujeto.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertScope {
    /// Nivel, si la lista está filtrada por nivel.
    pub level: Option<Level>,
    /// Solo alertas sin ver (irrelevante al marcar como vistas).
    pub unseen_only: bool,
    /// Equipo de la alerta, si la lista está filtrada por equipo.
    pub device_id: Option<i64>,
    /// Texto de búsqueda sobre el título o la etiqueta del sujeto.
    pub search: Option<String>,
}

/// Crea una alerta y devuelve su id (§4.1).
pub(crate) fn insert(conn: &Connection, alerta: &NewAlert, at: SystemTime) -> Result<i64> {
    let marca = instante_a_rfc3339(at);
    let id = conn.query_row(
        "INSERT INTO ALERTS
             (rule, level, subject, device_id, key, title, subject_label, details,
              event_id, summary_id, created_at, last_at, count, seen_at, resolved_at,
              notified)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?10, 1, NULL, NULL, 0)
         RETURNING id",
        params![
            alerta.rule.as_str(),
            alerta.level.as_str(),
            alerta.subject.as_str(),
            alerta.device_id,
            alerta.key,
            alerta.title,
            alerta.subject_label,
            alerta.details.to_string(),
            alerta.event_id,
            marca
        ],
        |fila| fila.get(0),
    )?;
    Ok(id)
}

/// Crea el resumen de la puesta al día y apunta `summary_id` en las agrupadas.
///
/// El motor construye el resumen con la regla especial `catch_up` (§7.9): su
/// `rule.as_str()` ya da `catch_up`. La fila queda con sujeto `almenara` y sin
/// `device_id`.
pub(crate) fn insert_summary(
    conn: &mut Connection,
    alerta: &NewAlert,
    grouped: &[i64],
    at: SystemTime,
) -> Result<i64> {
    let marca = instante_a_rfc3339(at);
    let transaccion = conn.transaction()?;
    let id = transaccion.query_row(
        "INSERT INTO ALERTS
             (rule, level, subject, device_id, key, title, subject_label, details,
              event_id, summary_id, created_at, last_at, count, seen_at, resolved_at,
              notified)
         VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?9, 1, NULL, NULL, 0)
         RETURNING id",
        params![
            alerta.rule.as_str(),
            alerta.level.as_str(),
            alerta.subject.as_str(),
            alerta.key,
            alerta.title,
            alerta.subject_label,
            alerta.details.to_string(),
            alerta.event_id,
            marca
        ],
        |fila| fila.get(0),
    )?;
    {
        let mut sentencia =
            transaccion.prepare("UPDATE ALERTS SET summary_id = ?1 WHERE id = ?2")?;
        for agrupada in grouped {
            sentencia.execute(params![id, agrupada])?;
        }
    }
    transaccion.commit()?;
    Ok(id)
}

/// Marca que una alerta se envió en una notificación de escritorio propia.
pub(crate) fn mark_notified(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("UPDATE ALERTS SET notified = 1 WHERE id = ?1", params![id])?;
    Ok(())
}

/// Suma una repetición a la alerta y refresca sus detalles (§7.5).
///
/// Con `reactivate` vuelve a poner `resolved_at = NULL` (una condición que
/// reaparece dentro del plazo de deduplicación). Nunca cambia `seen_at` ni
/// vuelve a notificar.
pub(crate) fn repeat(
    conn: &Connection,
    id: i64,
    at: SystemTime,
    details: &serde_json::Value,
    reactivate: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE ALERTS
            SET count = count + 1,
                last_at = ?1,
                details = ?2,
                resolved_at = CASE WHEN ?3 != 0 THEN NULL ELSE resolved_at END
          WHERE id = ?4",
        params![
            instante_a_rfc3339(at),
            details.to_string(),
            i64::from(reactivate),
            id
        ],
    )?;
    Ok(())
}

/// Resuelve una alerta de condición (§7.5).
///
/// Solo las reglas de condición se resuelven: las alertas normales tienen
/// `resolved_at` siempre NULL y no son condiciones que desaparezcan.
pub(crate) fn resolve(conn: &Connection, id: i64, at: SystemTime) -> Result<()> {
    let sql = format!(
        "UPDATE ALERTS SET resolved_at = ?1
          WHERE id = ?2 AND resolved_at IS NULL AND rule IN ({REGLAS_CONDICION})"
    );
    conn.execute(&sql, params![instante_a_rfc3339(at), id])?;
    Ok(())
}

/// Resuelve las condiciones activas de una regla (al apagarla, §7.5).
///
/// Solo tiene efecto en reglas de condición: las alertas normales nunca se
/// resuelven (su `resolved_at` es siempre NULL y no son condiciones).
pub(crate) fn resolve_by_rule(conn: &Connection, rule: RuleId, at: SystemTime) -> Result<usize> {
    if !rule.def().condition {
        return Ok(0);
    }
    let resueltas = conn.execute(
        "UPDATE ALERTS SET resolved_at = ?1
          WHERE rule = ?2 AND resolved_at IS NULL",
        params![instante_a_rfc3339(at), rule.as_str()],
    )?;
    Ok(resueltas)
}

/// Marca como vistas las alertas seleccionadas y devuelve cuántas cambian (§6).
pub(crate) fn mark_seen(conn: &Connection, sel: SeenSel, at: SystemTime) -> Result<usize> {
    let marca = instante_a_rfc3339(at);
    match sel {
        SeenSel::Alert(id) => {
            let mut marcadas = conn.execute(
                "UPDATE ALERTS SET seen_at = ?1 WHERE id = ?2 AND seen_at IS NULL",
                params![marca, id],
            )?;
            // Marcar un resumen marca también lo que agrupa (§6).
            marcadas += conn.execute(
                "UPDATE ALERTS SET seen_at = ?1 WHERE summary_id = ?2 AND seen_at IS NULL",
                params![marca, id],
            )?;
            Ok(marcadas)
        }
        SeenSel::Filter(scope) => {
            // El filtro de la lista busca también en los datos actuales del
            // equipo (alias, hostname e IP), no solo en la etiqueta guardada:
            // así «T» marca exactamente lo que pinta la pestaña Alertas.
            let filtro = filtro_scope(&scope, 2);
            let sql = format!(
                "UPDATE ALERTS SET seen_at = ?1
                  WHERE id IN (
                        SELECT a.id FROM ALERTS a
                          LEFT JOIN DEVICES d ON d.id = a.device_id
                         WHERE a.seen_at IS NULL{})",
                filtro.condicion
            );
            let mut parametros: Vec<Box<dyn ToSql>> = vec![Box::new(marca)];
            parametros.extend(filtro.valores);
            let marcadas = conn.execute(&sql, params_from_iter(parametros.iter()))?;
            Ok(marcadas)
        }
    }
}

/// Contadores de alertas no vistas por nivel (contador de la barra, §7.2).
pub(crate) fn unseen_counts(conn: &Connection) -> Result<AlertCounts> {
    let mut sentencia =
        conn.prepare("SELECT level, COUNT(*) FROM ALERTS WHERE seen_at IS NULL GROUP BY level")?;
    let filas = sentencia.query_map([], |fila| {
        Ok((fila.get::<_, String>(0)?, fila.get::<_, i64>(1)?))
    })?;
    let mut contadores = AlertCounts::default();
    for fila in filas {
        let (nivel, total) = fila?;
        let total = u32::try_from(total.max(0)).unwrap_or(u32::MAX);
        match Level::from_str(&nivel) {
            Some(Level::Important) => contadores.important = total,
            Some(Level::Warning) => contadores.warning = total,
            Some(Level::Info) => contadores.info = total,
            None => {
                tracing::debug!(nivel, "nivel de alerta desconocido; se omite del contador");
            }
        }
    }
    Ok(contadores)
}

/// Equipos con alertas no vistas de nivel importante o aviso (§6).
///
/// La barra y la marca `!` de Equipos lo usan; el criterio es el mismo que el
/// de `unseen_counts`: una alerta resuelta que nadie ha visto sigue contando.
pub(crate) fn unseen_device_ids(conn: &Connection) -> Result<Vec<i64>> {
    let mut sentencia = conn.prepare(
        "SELECT DISTINCT device_id FROM ALERTS
          WHERE seen_at IS NULL
            AND level IN ('important', 'warning')
            AND device_id IS NOT NULL
          ORDER BY device_id",
    )?;
    let filas = sentencia.query_map([], |fila| fila.get::<_, i64>(0))?;
    let mut equipos = Vec::new();
    for fila in filas {
        equipos.push(fila?);
    }
    Ok(equipos)
}

/// Estado inicial del motor desde la BD (§4.4 y §7.5).
///
/// Devuelve los silencios vigentes, el aprendizaje, las alertas de las últimas
/// 168 h (el plazo máximo de deduplicación; el motor filtra con el real) y las
/// condiciones activas de las reglas de condición, más si `DEVICES` está vacía
/// (línea base, §7.9).
pub(crate) fn engine_snapshot(conn: &Connection, now: SystemTime) -> Result<EngineSnapshot> {
    let desde = now
        .checked_sub(Duration::from_secs((DEDUP_MAX_HORAS * 3600) as u64))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let desde = instante_a_rfc3339(desde);

    let recientes = {
        let sql = format!(
            "SELECT id, rule, subject, device_id, key, created_at, last_at, resolved_at,
                    details
               FROM ALERTS
              WHERE created_at >= ?1
                 OR (resolved_at IS NULL AND rule IN ({REGLAS_CONDICION}))
              ORDER BY created_at, id"
        );
        let mut sentencia = conn.prepare(&sql)?;
        let filas = sentencia.query_map(params![desde], |fila| {
            Ok((
                fila.get::<_, i64>(0)?,
                fila.get::<_, String>(1)?,
                fila.get::<_, String>(2)?,
                fila.get::<_, Option<i64>>(3)?,
                fila.get::<_, String>(4)?,
                fila.get::<_, String>(5)?,
                fila.get::<_, String>(6)?,
                fila.get::<_, Option<String>>(7)?,
                fila.get::<_, String>(8)?,
            ))
        })?;
        let mut recientes = Vec::new();
        for fila in filas {
            let (id, rule, subject, device_id, key, created_at, last_at, resolved_at, details) =
                fila?;
            let Some(rule) = RuleId::from_str(&rule) else {
                // `catch_up` y reglas futuras no intervienen en la deduplicación.
                tracing::debug!(rule, "alerta con regla no deduplicable; se omite");
                continue;
            };
            let Some(created_at) = rfc3339_a_instante(&created_at) else {
                continue;
            };
            let Some(last_at) = rfc3339_a_instante(&last_at) else {
                continue;
            };
            let Some(subject) = Subject::from_parts(&subject, device_id.unwrap_or(0)) else {
                continue;
            };
            let activa = resolved_at.is_none();
            let detalles = serde_json::from_str(&details).unwrap_or(serde_json::Value::Null);
            recientes.push(RecentState {
                key: DedupKey::new(rule, subject, key),
                id,
                created_at,
                last_at,
                active: activa,
                details: detalles,
            });
        }
        recientes
    };

    let mutes = active_mutes(conn, now)?;

    let devices_empty = conn.query_row("SELECT COUNT(*) FROM DEVICES", [], |fila| {
        fila.get::<_, i64>(0)
    })? == 0;

    Ok(EngineSnapshot {
        mutes,
        learning: crate::repo::learning::learning_rows(conn)?,
        recent: recientes,
        devices_empty,
    })
}

/// Silencios vigentes en el instante indicado (§7.6).
pub(crate) fn active_mutes(conn: &Connection, now: SystemTime) -> Result<Vec<MuteState>> {
    let ahora = instante_a_rfc3339(now);
    let mut sentencia = conn.prepare(
        "SELECT rule, subject, device_id, until FROM ALERT_MUTES
          WHERE until IS NULL OR until > ?1
          ORDER BY rule, subject, device_id",
    )?;
    let filas = sentencia.query_map(params![ahora], |fila| {
        Ok((
            fila.get::<_, String>(0)?,
            fila.get::<_, String>(1)?,
            fila.get::<_, i64>(2)?,
            fila.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut mutes = Vec::new();
    for fila in filas {
        let (rule, subject, device_id, until) = fila?;
        let Some(rule) = RuleId::from_str(&rule) else {
            continue;
        };
        let Some(subject) = Subject::from_parts(&subject, device_id) else {
            continue;
        };
        mutes.push(MuteState {
            rule,
            subject,
            until: until.and_then(|texto| rfc3339_a_instante(&texto)),
        });
    }
    Ok(mutes)
}

/// Crea o sustituye el silencio de una regla, sujeto y equipo (§7.6).
///
/// `until = None` es «siempre». Un silencio nuevo para la misma regla y equipo
/// sustituye al anterior (misma fila).
pub(crate) fn upsert_mute(
    conn: &Connection,
    rule: RuleId,
    subject: Subject,
    until: Option<SystemTime>,
) -> Result<i64> {
    let id = conn.query_row(
        "INSERT INTO ALERT_MUTES (rule, subject, device_id, until, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (rule, subject, device_id) DO UPDATE SET
             until = excluded.until,
             created_at = excluded.created_at
         RETURNING id",
        params![
            rule.as_str(),
            subject.as_str(),
            subject.device_id(),
            until.map(instante_a_rfc3339),
            crate::repo::ahora_rfc3339()
        ],
        |fila| fila.get(0),
    )?;
    Ok(id)
}

/// Quita un silencio (§7.6).
pub(crate) fn delete_mute(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM ALERT_MUTES WHERE id = ?1", params![id])?;
    Ok(())
}

/// Purga las alertas vencidas y los silencios caducados (§7.15).
///
/// Las alertas se purgan por `last_at` (retención de `retention_days`); los
/// silencios, cuando pasa su `until` (los de «siempre» no caducan). Devuelve el
/// total de filas borradas.
pub(crate) fn purge(conn: &mut Connection, now: SystemTime, retention_days: u32) -> Result<usize> {
    let corte = now
        .checked_sub(Duration::from_secs(u64::from(retention_days) * 86_400))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let transaccion = conn.transaction()?;
    let alertas = transaccion.execute(
        "DELETE FROM ALERTS WHERE last_at < ?1",
        params![instante_a_rfc3339(corte)],
    )?;
    let silencios = transaccion.execute(
        "DELETE FROM ALERT_MUTES WHERE until IS NOT NULL AND until < ?1",
        params![instante_a_rfc3339(now)],
    )?;
    transaccion.commit()?;
    Ok(alertas + silencios)
}

/// Marca o desmarca un equipo como vigilado (§7.7).
pub(crate) fn set_watched(conn: &Connection, device_id: i64, watched: bool) -> Result<()> {
    conn.execute(
        "UPDATE DEVICES SET watched = ?1 WHERE id = ?2",
        params![watched, device_id],
    )?;
    Ok(())
}

/// Valor de la hora cerrada y muestras de los 14 días anteriores (§7.4).
///
/// Solo se evalúa si la hora tiene cobertura de tráfico completa; las muestras
/// son la misma hora local de los días anteriores, solo si esa hora también
/// estuvo cubierta y desde el alta del equipo. El valor de una hora cubierta sin
/// fila es 0. El motor aplica la mediana, el factor y los mínimos.
pub(crate) fn hour_baseline(
    conn: &Connection,
    hour: i64,
    p: &TrafficHighParams,
) -> Result<Vec<HourSubject>> {
    let ahora = localtime::now_unix();
    if !gaps::hora_con_cobertura(conn, hour, ahora)? {
        return Ok(Vec::new());
    }
    let valores = valores_hora(conn, hour)?;
    if valores.is_empty() {
        return Ok(Vec::new());
    }

    let equipos = datos_equipos(conn)?;
    let dia_actual = LocalDay::from_unix(hour);
    let hora_local = localtime::local_hour(hour);
    let mut muestras: HashMap<Subject, Vec<(u64, u64)>> = HashMap::new();
    for atras in 1..=i64::from(p.baseline_days) {
        let dia = dia_actual.sumar_dias(-atras);
        let Some(muestra) = hora_local_de_dia(dia, hora_local) else {
            // El día del cambio de hora no tiene esa hora local: se salta.
            continue;
        };
        if !gaps::hora_con_cobertura(conn, muestra, ahora)? {
            continue;
        }
        let valores_muestra = valores_hora(conn, muestra)?;
        for subject in valores.keys() {
            if let Subject::Device(device_id) = subject {
                let primera_vez = equipos.get(device_id).and_then(|datos| datos.primera_vez);
                match primera_vez {
                    // Antes del alta del equipo no enseña nada de él.
                    Some(primera) if muestra < primera => continue,
                    None => continue,
                    _ => {}
                }
            }
            let (down, up) = valores_muestra.get(subject).copied().unwrap_or((0, 0));
            muestras.entry(*subject).or_default().push((down, up));
        }
    }

    let mut filas = BTreeMap::new();
    for (subject, (down, up)) in valores {
        filas.insert(
            subject,
            HourSubject {
                subject,
                label: etiqueta_sujeto(subject, &equipos),
                down,
                up,
                samples: muestras.remove(&subject).unwrap_or_default(),
            },
        );
    }
    Ok(filas.into_values().collect())
}

/// Valores de total de una hora por sujeto (dimensión `total`).
fn valores_hora(conn: &Connection, bucket: i64) -> Result<HashMap<Subject, (u64, u64)>> {
    let mut sentencia = conn.prepare(
        "SELECT subject, device_id, bytes_down, bytes_up
           FROM TRAFFIC_ROLLUP_HOUR
          WHERE bucket = ?1 AND dimension = 'total'",
    )?;
    let filas = sentencia.query_map(params![bucket], |fila| {
        Ok((
            fila.get::<_, String>(0)?,
            fila.get::<_, i64>(1)?,
            fila.get::<_, i64>(2)?,
            fila.get::<_, i64>(3)?,
        ))
    })?;
    let mut valores = HashMap::new();
    for fila in filas {
        let (subject, device_id, down, up) = fila?;
        let Some(subject) = Subject::from_parts(&subject, device_id) else {
            continue;
        };
        if !matches!(
            subject,
            Subject::Device(_) | Subject::Host | Subject::Network
        ) {
            continue;
        }
        valores.insert(subject, (maximo(down), maximo(up)));
    }
    Ok(valores)
}

/// Inicio UTC de la hora local indicada dentro de un día local (§7.4).
///
/// Recorre las horas del día con mktime: una hora que no existe (cambio de hora
/// de primavera) devuelve None y una repetida (otoño) usa la primera.
fn hora_local_de_dia(dia: LocalDay, hora: i32) -> Option<i64> {
    let (inicio, fin) = dia.limits();
    let mut bucket = inicio - inicio.rem_euclid(3600);
    while bucket < fin {
        if localtime::local_hour(bucket) == hora && LocalDay::from_unix(bucket) == dia {
            return Some(bucket);
        }
        bucket += 3600;
    }
    None
}

/// Datos de un equipo que necesita la línea base de `traffic_high`.
struct DatosEquipo {
    /// Instante de su alta (para no usar muestras anteriores).
    primera_vez: Option<i64>,
    /// Nombre visible actual (alias, hostname o IP), como `Device::display_name`.
    etiqueta: String,
}

/// Datos de todos los equipos por id, para etiquetar y acotar la línea base.
fn datos_equipos(conn: &Connection) -> Result<HashMap<i64, DatosEquipo>> {
    let mut sentencia = conn.prepare("SELECT id, first_seen, alias, hostname, ip FROM DEVICES")?;
    let filas = sentencia.query_map([], |fila| {
        Ok((
            fila.get::<_, i64>(0)?,
            fila.get::<_, String>(1)?,
            fila.get::<_, Option<String>>(2)?,
            fila.get::<_, Option<String>>(3)?,
            fila.get::<_, String>(4)?,
        ))
    })?;
    let mut equipos = HashMap::new();
    for fila in filas {
        let (id, first_seen, alias, hostname, ip) = fila?;
        let etiqueta = alias
            .as_deref()
            .map(str::trim)
            .filter(|texto| !texto.is_empty())
            .or_else(|| {
                hostname
                    .as_deref()
                    .map(str::trim)
                    .filter(|texto| !texto.is_empty())
            })
            .unwrap_or(ip.as_str())
            .to_string();
        let primera_vez = rfc3339_a_instante(&first_seen).and_then(unix_de_instante);
        equipos.insert(
            id,
            DatosEquipo {
                primera_vez,
                etiqueta,
            },
        );
    }
    Ok(equipos)
}

/// Etiqueta visible de un sujeto de la hora cerrada (§7.4).
fn etiqueta_sujeto(subject: Subject, equipos: &HashMap<i64, DatosEquipo>) -> String {
    match subject {
        Subject::Device(device_id) => equipos
            .get(&device_id)
            .map(|datos| datos.etiqueta.clone())
            .unwrap_or_else(|| format!("Equipo #{device_id}")),
        Subject::Host => "Este equipo".to_string(),
        Subject::Network => "Toda la red".to_string(),
        Subject::Almenara => "Almenara".to_string(),
    }
}

/// Filtro de la lista de alertas ya traducido a cláusula SQL.
struct FiltroScope {
    /// Cláusula que encadena `AND` detrás del `WHERE` (con alias `a` para
    /// ALERTS y `d` para DEVICES), o cadena vacía si no hay filtro.
    condicion: String,
    /// Valores de los parámetros, en orden desde el índice indicado.
    valores: Vec<Box<dyn ToSql>>,
}

/// Condiciones y valores del filtro de la lista de alertas.
///
/// Los parámetros empiezan en `primer_indice` para encadenarse detrás de los de
/// la sentencia; el patrón de búsqueda se referencia cuatro veces con el mismo
/// índice. La búsqueda casa la etiqueta guardada del sujeto y los datos
/// actuales del equipo (alias, hostname e IP), como la lista (§6).
fn filtro_scope(scope: &AlertScope, primer_indice: usize) -> FiltroScope {
    let mut condiciones = Vec::new();
    let mut valores: Vec<Box<dyn ToSql>> = Vec::new();
    let mut indice = primer_indice;
    if let Some(level) = scope.level {
        condiciones.push(format!("a.level = ?{indice}"));
        valores.push(Box::new(level.as_str().to_string()));
        indice += 1;
    }
    if let Some(device_id) = scope.device_id {
        condiciones.push(format!("a.device_id = ?{indice}"));
        valores.push(Box::new(device_id));
        indice += 1;
    }
    if let Some(texto) = scope
        .search
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        let patron = patron_like(texto);
        condiciones.push(format!(
            r"(a.subject_label LIKE ?{indice} ESCAPE '\'
              OR d.alias LIKE ?{indice} ESCAPE '\'
              OR d.hostname LIKE ?{indice} ESCAPE '\'
              OR d.ip LIKE ?{indice} ESCAPE '\')"
        ));
        valores.push(Box::new(patron));
    }
    let condicion = if condiciones.is_empty() {
        String::new()
    } else {
        format!(" AND {}", condiciones.join(" AND "))
    };
    FiltroScope { condicion, valores }
}

/// Patrón LIKE que busca el texto literal (escapa `%`, `_` y `\\`).
fn patron_like(texto: &str) -> String {
    let mut patron = String::with_capacity(texto.len() + 2);
    patron.push('%');
    for caracter in texto.chars() {
        if matches!(caracter, '%' | '_' | '\\') {
            patron.push('\\');
        }
        patron.push(caracter);
    }
    patron.push('%');
    patron
}

/// Convierte un contador de SQLite en u64 sin desbordar.
fn maximo(valor: i64) -> u64 {
    valor.max(0) as u64
}

impl crate::repo::Repo {
    /// Crea una alerta (§4.1).
    pub fn insert_alert(&mut self, alerta: &NewAlert, at: SystemTime) -> crate::error::Result<i64> {
        insert(&self.conn, alerta, at)
    }

    /// Marca que una alerta se envió en una notificación de escritorio.
    pub fn mark_alert_notified(&mut self, id: i64) -> crate::error::Result<()> {
        mark_notified(&self.conn, id)
    }

    /// Crea el resumen de la puesta al día y agrupa las alertas indicadas (§7.9).
    pub fn insert_summary(
        &mut self,
        alerta: &NewAlert,
        grouped: &[i64],
        at: SystemTime,
    ) -> crate::error::Result<i64> {
        insert_summary(&mut self.conn, alerta, grouped, at)
    }

    /// Suma una repetición a una alerta (§7.5).
    pub fn repeat_alert(
        &mut self,
        id: i64,
        at: SystemTime,
        details: &serde_json::Value,
        reactivate: bool,
    ) -> crate::error::Result<()> {
        repeat(&self.conn, id, at, details, reactivate)
    }

    /// Resuelve una alerta de condición (§7.5).
    pub fn resolve_alert(&mut self, id: i64, at: SystemTime) -> crate::error::Result<()> {
        resolve(&self.conn, id, at)
    }

    /// Resuelve las condiciones activas de una regla apagada (§7.5).
    pub fn resolve_alerts_by_rule(
        &mut self,
        rule: RuleId,
        at: SystemTime,
    ) -> crate::error::Result<usize> {
        resolve_by_rule(&self.conn, rule, at)
    }

    /// Marca como vistas las alertas seleccionadas (§6).
    pub fn mark_seen(&mut self, sel: SeenSel, at: SystemTime) -> crate::error::Result<usize> {
        mark_seen(&self.conn, sel, at)
    }

    /// Contadores de alertas no vistas por nivel (§7.2).
    pub fn unseen_counts(&self) -> crate::error::Result<AlertCounts> {
        unseen_counts(&self.conn)
    }

    /// Equipos con alertas no vistas de nivel importante o aviso (§6).
    pub fn unseen_device_ids(&self) -> crate::error::Result<Vec<i64>> {
        unseen_device_ids(&self.conn)
    }

    /// Estado inicial del motor desde la BD (§4.4).
    pub fn engine_snapshot(&self, now: SystemTime) -> crate::error::Result<EngineSnapshot> {
        engine_snapshot(&self.conn, now)
    }

    /// Silencios vigentes en el instante indicado (recarga del motor, §7.6).
    pub fn active_mutes(&self, now: SystemTime) -> crate::error::Result<Vec<MuteState>> {
        active_mutes(&self.conn, now)
    }

    /// Crea o sustituye el silencio de una regla, sujeto y equipo (§7.6).
    pub fn upsert_mute(
        &mut self,
        rule: RuleId,
        subject: Subject,
        until: Option<SystemTime>,
    ) -> crate::error::Result<i64> {
        upsert_mute(&self.conn, rule, subject, until)
    }

    /// Quita un silencio (§7.6).
    pub fn delete_mute(&mut self, id: i64) -> crate::error::Result<()> {
        delete_mute(&self.conn, id)
    }

    /// Purga alertas vencidas y silencios caducados (§7.15).
    pub fn purge_alerts(
        &mut self,
        now: SystemTime,
        retention_days: u32,
    ) -> crate::error::Result<usize> {
        purge(&mut self.conn, now, retention_days)
    }

    /// Marca o desmarca un equipo como vigilado (§7.7).
    pub fn set_watched(&mut self, device_id: i64, watched: bool) -> crate::error::Result<()> {
        set_watched(&self.conn, device_id, watched)
    }

    /// Valor de la hora cerrada y muestras de los 14 días anteriores (§7.4).
    pub fn hour_baseline(
        &self,
        hour: i64,
        p: &TrafficHighParams,
    ) -> crate::error::Result<Vec<HourSubject>> {
        hour_baseline(&self.conn, hour, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::AlertRule;
    use crate::repo::{DeviceUpsert, Interface, Repo};
    use tempfile::tempdir;

    /// Repositorio con una interfaz y un equipo, y el id del equipo.
    fn repo_con_equipo() -> (tempfile::TempDir, Repo, i64) {
        let dir = tempdir().expect("directorio temporal");
        let mut repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let id = repo
            .upsert_interface(&Interface::without_id(
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
            .upsert_device(&DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:01".to_string(),
                ip: "192.168.1.50".to_string(),
                hostname: Some("portatil".to_string()),
                vendor: None,
                interface_id: id,
                device_type: "unknown".to_string(),
            })
            .expect("equipo");
        (dir, repo, device_id)
    }

    fn instante(texto: &str) -> SystemTime {
        rfc3339_a_instante(texto).expect("fecha de prueba")
    }

    fn alerta(
        regla: RuleId,
        nivel: Level,
        sujeto: Subject,
        titulo: &str,
        etiqueta: &str,
    ) -> NewAlert {
        NewAlert {
            rule: AlertRule::Rule(regla),
            level: nivel,
            subject: sujeto,
            device_id: match sujeto {
                Subject::Device(id) => Some(id),
                _ => None,
            },
            key: String::new(),
            title: titulo.to_string(),
            subject_label: etiqueta.to_string(),
            details: serde_json::json!({}),
            event_id: None,
        }
    }

    #[test]
    fn insertar_alerta_marcar_notificada_y_contar_no_vistas() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let at = instante("2026-11-11T10:00:00Z");
        let importante = repo
            .insert_alert(
                &alerta(
                    RuleId::DeviceNew,
                    Level::Important,
                    Subject::Device(device_id),
                    "Equipo nuevo",
                    "portatil",
                ),
                at,
            )
            .expect("alerta importante");
        assert!(importante > 0);
        repo.insert_alert(
            &alerta(
                RuleId::NewApp,
                Level::Info,
                Subject::Device(device_id),
                "App nueva: steam",
                "portatil",
            ),
            at,
        )
        .expect("alerta info");

        let counts = repo.unseen_counts().expect("contadores");
        assert_eq!(counts.important, 1);
        assert_eq!(counts.warning, 0);
        assert_eq!(counts.info, 1);
        assert_eq!(counts.badge(), 1);
        assert_eq!(repo.unseen_device_ids().expect("equipos"), vec![device_id]);

        repo.mark_alert_notified(importante).expect("notificada");
        let (notified, created_at, last_at, count, seen_at): (
            i64,
            String,
            String,
            i64,
            Option<String>,
        ) = repo
            .connection()
            .query_row(
                "SELECT notified, created_at, last_at, count, seen_at FROM ALERTS WHERE id = ?1",
                params![importante],
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
            .expect("leer alerta");
        assert_eq!(notified, 1);
        assert_eq!(created_at, "2026-11-11T10:00:00Z");
        assert_eq!(last_at, created_at);
        assert_eq!(count, 1);
        assert_eq!(seen_at, None);

        assert_eq!(
            repo.mark_seen(SeenSel::Alert(importante), at)
                .expect("marcar vista"),
            1
        );
        assert_eq!(repo.unseen_counts().expect("contadores").important, 0);
        assert!(repo.unseen_device_ids().expect("equipos").is_empty());
    }

    #[test]
    fn marcar_todas_las_vistas_aplica_el_filtro_de_la_lista() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let at = instante("2026-11-11T10:00:00Z");
        repo.insert_alert(
            &alerta(
                RuleId::DeviceNew,
                Level::Important,
                Subject::Device(device_id),
                "Equipo nuevo",
                "192.168.1.50",
            ),
            at,
        )
        .expect("importante del equipo");
        repo.insert_alert(
            &alerta(
                RuleId::NewApp,
                Level::Info,
                Subject::Host,
                "App nueva: steam",
                "Este equipo",
            ),
            at,
        )
        .expect("info del host");
        repo.insert_alert(
            &alerta(
                RuleId::PortNew,
                Level::Warning,
                Subject::Device(device_id),
                "Puerto nuevo: 22/tcp",
                "192.168.1.50",
            ),
            at,
        )
        .expect("aviso del equipo");
        repo.set_alias(device_id, Some("portatil")).expect("alias");

        // Por nivel: solo la importante del equipo.
        let scope = AlertScope {
            level: Some(Level::Important),
            ..AlertScope::default()
        };
        assert_eq!(
            repo.mark_seen(SeenSel::Filter(scope), at).expect("nivel"),
            1
        );
        // Por equipo: queda el aviso del equipo (el info es del host).
        let scope = AlertScope {
            device_id: Some(device_id),
            ..AlertScope::default()
        };
        assert_eq!(
            repo.mark_seen(SeenSel::Filter(scope), at).expect("equipo"),
            1
        );
        // La búsqueda casa el alias actual del equipo, no solo la etiqueta.
        repo.insert_alert(
            &alerta(
                RuleId::MacChanged,
                Level::Warning,
                Subject::Device(device_id),
                "Cambio de MAC",
                "192.168.1.50",
            ),
            at,
        )
        .expect("aviso del equipo");
        let scope = AlertScope {
            search: Some("portatil".to_string()),
            ..AlertScope::default()
        };
        assert_eq!(
            repo.mark_seen(SeenSel::Filter(scope), at).expect("alias"),
            1
        );
        // Y la IP actual del equipo (el filtro / de la pestaña es por equipo).
        repo.insert_alert(
            &alerta(
                RuleId::TypeChanged,
                Level::Warning,
                Subject::Device(device_id),
                "Cambio de tipo",
                "192.168.1.50",
            ),
            at,
        )
        .expect("otro aviso del equipo");
        let scope = AlertScope {
            search: Some("192.168.1.50".to_string()),
            ..AlertScope::default()
        };
        assert_eq!(repo.mark_seen(SeenSel::Filter(scope), at).expect("ip"), 1);
        // Una búsqueda sin coincidencias no marca nada.
        let scope = AlertScope {
            search: Some("sin-coincidencias".to_string()),
            ..AlertScope::default()
        };
        assert_eq!(
            repo.mark_seen(SeenSel::Filter(scope), at)
                .expect("sin coincidencias"),
            0
        );
        assert_eq!(repo.unseen_counts().expect("contadores").badge(), 0);
        assert!(repo.unseen_device_ids().expect("equipos").is_empty());

        // Un filtro sin condiciones (solo «sin ver») marca lo que queda sin ver.
        let scope = AlertScope {
            unseen_only: true,
            ..AlertScope::default()
        };
        assert_eq!(
            repo.mark_seen(SeenSel::Filter(scope), at).expect("sin ver"),
            1,
            "solo queda sin ver el info del host"
        );
        assert_eq!(repo.unseen_counts().expect("contadores").info, 0);
    }

    #[test]
    fn el_resumen_guarda_catch_up_y_marcarlo_marca_lo_que_agrupa() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let at = instante("2026-11-11T10:00:00Z");
        let uno = repo
            .insert_alert(
                &alerta(
                    RuleId::DeviceNew,
                    Level::Important,
                    Subject::Device(device_id),
                    "Equipo nuevo",
                    "portatil",
                ),
                instante("2026-11-11T09:00:00Z"),
            )
            .expect("primera agrupada");
        let dos = repo
            .insert_alert(
                &alerta(
                    RuleId::PortNew,
                    Level::Warning,
                    Subject::Device(device_id),
                    "Puerto nuevo: 22/tcp",
                    "portatil",
                ),
                instante("2026-11-11T09:05:00Z"),
            )
            .expect("segunda agrupada");
        let mut resumen = alerta(
            RuleId::DeviceNew,
            Level::Important,
            Subject::Almenara,
            "Resumen al arrancar (2 alertas)",
            "Almenara",
        );
        resumen.rule = AlertRule::CatchUp;
        let id = repo
            .insert_summary(&resumen, &[uno, dos], at)
            .expect("resumen");

        let (regla, etiqueta, summary_id): (String, String, Option<i64>) = repo
            .connection()
            .query_row(
                "SELECT rule, subject_label, summary_id FROM ALERTS WHERE id = ?1",
                params![uno],
                |fila| Ok((fila.get(0)?, fila.get(1)?, fila.get(2)?)),
            )
            .expect("leer agrupada");
        assert_eq!(regla, "device_new");
        assert_eq!(etiqueta, "portatil");
        assert_eq!(summary_id, Some(id));
        let (regla_resumen, device_id_resumen): (String, Option<i64>) = repo
            .connection()
            .query_row(
                "SELECT rule, device_id FROM ALERTS WHERE id = ?1",
                params![id],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer resumen");
        assert_eq!(regla_resumen, "catch_up");
        assert_eq!(device_id_resumen, None);

        // Marcar el resumen marca también sus agrupadas (§6).
        assert_eq!(
            repo.mark_seen(SeenSel::Alert(id), at)
                .expect("marcar resumen"),
            3
        );
        assert_eq!(repo.unseen_counts().expect("contadores").badge(), 0);
    }

    #[test]
    fn repetir_suma_contador_y_reactiva_condiciones() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let at = instante("2026-11-11T10:00:00Z");
        let id = repo
            .insert_alert(
                &alerta(
                    RuleId::DeviceNew,
                    Level::Important,
                    Subject::Device(device_id),
                    "Equipo nuevo",
                    "portatil",
                ),
                instante("2026-11-11T09:00:00Z"),
            )
            .expect("alerta");
        let detalles = serde_json::json!({"valor": 2});
        repo.repeat_alert(id, at, &detalles, false)
            .expect("repetir");
        let (count, last_at, seen, notified, guardado): (i64, String, Option<String>, i64, String) =
            repo.connection()
                .query_row(
                    "SELECT count, last_at, seen_at, notified, details FROM ALERTS WHERE id = ?1",
                    params![id],
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
                .expect("leer alerta repetida");
        assert_eq!(count, 2);
        assert_eq!(last_at, "2026-11-11T10:00:00Z");
        assert_eq!(seen, None, "repetir no marca como vista");
        assert_eq!(notified, 0, "una repetición nunca notifica");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&guardado).expect("json"),
            detalles
        );

        // Una condición resuelta que reaparece dentro del plazo se reactiva.
        let cond = repo
            .insert_alert(
                &alerta(
                    RuleId::CaptureStopped,
                    Level::Important,
                    Subject::Almenara,
                    "Captura parada",
                    "Almenara",
                ),
                instante("2026-11-11T09:30:00Z"),
            )
            .expect("condición");
        repo.resolve_alert(cond, instante("2026-11-11T09:40:00Z"))
            .expect("resolver");
        let resuelta: Option<String> = repo
            .connection()
            .query_row(
                "SELECT resolved_at FROM ALERTS WHERE id = ?1",
                params![cond],
                |fila| fila.get(0),
            )
            .expect("leer resolución");
        assert!(resuelta.is_some());
        repo.repeat_alert(cond, at, &serde_json::json!({}), true)
            .expect("reactivar");
        let resuelta: Option<String> = repo
            .connection()
            .query_row(
                "SELECT resolved_at FROM ALERTS WHERE id = ?1",
                params![cond],
                |fila| fila.get(0),
            )
            .expect("leer reactivación");
        assert_eq!(resuelta, None);

        // Una alerta normal no se resuelve y apagar una regla normal no toca nada.
        repo.resolve_alert(id, at).expect("resolver normal");
        let normal: Option<String> = repo
            .connection()
            .query_row(
                "SELECT resolved_at FROM ALERTS WHERE id = ?1",
                params![id],
                |fila| fila.get(0),
            )
            .expect("leer normal");
        assert_eq!(normal, None, "las alertas normales no se resuelven");
        assert_eq!(
            repo.resolve_alerts_by_rule(RuleId::DeviceNew, at)
                .expect("regla normal"),
            0
        );
        assert_eq!(
            repo.resolve_alerts_by_rule(RuleId::CaptureStopped, at)
                .expect("condición"),
            1
        );
        assert_eq!(
            repo.resolve_alerts_by_rule(RuleId::CaptureStopped, at)
                .expect("ya resuelta"),
            0
        );
    }

    #[test]
    fn la_purga_borra_alertas_vencidas_y_silencios_caducados() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let ahora = instante("2026-11-11T12:00:00Z");
        let vieja = repo
            .insert_alert(
                &alerta(
                    RuleId::NewApp,
                    Level::Info,
                    Subject::Device(device_id),
                    "App nueva: vieja",
                    "portatil",
                ),
                instante("2026-08-01T00:00:00Z"),
            )
            .expect("alerta vieja");
        assert!(vieja > 0);
        let reciente = repo
            .insert_alert(
                &alerta(
                    RuleId::NewApp,
                    Level::Info,
                    Subject::Device(device_id),
                    "App nueva: reciente",
                    "portatil",
                ),
                ahora
                    .checked_sub(Duration::from_secs(3600))
                    .expect("instante"),
            )
            .expect("alerta reciente");
        repo.upsert_mute(RuleId::NewApp, Subject::Host, None)
            .expect("silencio de siempre");
        repo.connection()
            .execute(
                "INSERT INTO ALERT_MUTES (rule, subject, device_id, until, created_at)
                 VALUES ('new_ja4', 'host', 0, '2026-11-11T11:00:00Z',
                         '2026-11-01T00:00:00Z')",
                [],
            )
            .expect("silencio caducado");

        assert_eq!(repo.purge_alerts(ahora, 90).expect("purgar"), 2);
        let quedan: Vec<i64> = {
            let mut sentencia = repo
                .connection()
                .prepare("SELECT id FROM ALERTS ORDER BY id")
                .expect("preparar alertas");
            sentencia
                .query_map([], |fila| fila.get(0))
                .expect("consultar")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("leer")
        };
        assert_eq!(quedan, vec![reciente]);
        let silencios: i64 = repo
            .connection()
            .query_row("SELECT COUNT(*) FROM ALERT_MUTES", [], |fila| fila.get(0))
            .expect("contar silencios");
        assert_eq!(silencios, 1, "el silencio de siempre no caduca");
    }

    #[test]
    fn el_silencio_sustituye_al_anterior_y_se_puede_quitar() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let hasta = instante("2026-11-18T10:00:00Z");
        let id = repo
            .upsert_mute(RuleId::NewApp, Subject::Device(device_id), Some(hasta))
            .expect("silencio");
        let id2 = repo
            .upsert_mute(RuleId::NewApp, Subject::Device(device_id), None)
            .expect("sustituir");
        assert_eq!(id, id2, "un silencio nuevo sustituye al anterior");
        let (rule, subject, device, until): (String, String, i64, Option<String>) = repo
            .connection()
            .query_row(
                "SELECT rule, subject, device_id, until FROM ALERT_MUTES WHERE id = ?1",
                params![id],
                |fila| Ok((fila.get(0)?, fila.get(1)?, fila.get(2)?, fila.get(3)?)),
            )
            .expect("leer silencio");
        assert_eq!(rule, "new_app");
        assert_eq!(subject, "device");
        assert_eq!(device, device_id);
        assert_eq!(until, None);

        // El mismo silencio para otro sujeto es otra fila.
        let otro = repo
            .upsert_mute(RuleId::NewApp, Subject::Host, None)
            .expect("silencio del host");
        assert_ne!(otro, id);
        repo.delete_mute(id).expect("quitar silencio");
        let total: i64 = repo
            .connection()
            .query_row("SELECT COUNT(*) FROM ALERT_MUTES", [], |fila| fila.get(0))
            .expect("contar");
        assert_eq!(total, 1);
    }

    #[test]
    fn engine_snapshot_carga_vigentes_condiciones_y_aprendizaje() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        let ahora = instante("2026-11-11T12:00:00Z");
        let hace = |segundos: u64| ahora - Duration::from_secs(segundos);
        let at = ahora;

        let reciente = repo
            .insert_alert(
                &alerta(
                    RuleId::DeviceNew,
                    Level::Important,
                    Subject::Device(device_id),
                    "Equipo nuevo",
                    "portatil",
                ),
                hace(3600),
            )
            .expect("alerta reciente");
        let condicion = repo
            .insert_alert(
                &alerta(
                    RuleId::CaptureStopped,
                    Level::Important,
                    Subject::Almenara,
                    "Captura parada",
                    "Almenara",
                ),
                hace(30 * 86_400),
            )
            .expect("condición activa antigua");
        // Una alerta normal y una condición resuelta fuera del plazo no entran.
        let normal_vieja = repo
            .insert_alert(
                &alerta(
                    RuleId::NewApp,
                    Level::Info,
                    Subject::Device(device_id),
                    "App nueva",
                    "portatil",
                ),
                hace(30 * 86_400),
            )
            .expect("normal antigua");
        let resuelta = repo
            .insert_alert(
                &alerta(
                    RuleId::DbSize,
                    Level::Warning,
                    Subject::Almenara,
                    "Base de datos grande",
                    "Almenara",
                ),
                hace(40 * 86_400),
            )
            .expect("condición resuelta");
        repo.resolve_alert(resuelta, hace(39 * 86_400))
            .expect("resolver");

        let silencio = repo
            .upsert_mute(RuleId::NewApp, Subject::Device(device_id), None)
            .expect("silencio de siempre");
        let temporal = repo
            .upsert_mute(
                RuleId::PortNew,
                Subject::Device(device_id),
                Some(ahora + Duration::from_secs(3600)),
            )
            .expect("silencio temporal");
        repo.connection()
            .execute(
                "INSERT INTO ALERT_MUTES (rule, subject, device_id, until, created_at)
                 VALUES ('mac_changed', 'host', 0, ?1, '2026-11-01T00:00:00Z')",
                params![instante_a_rfc3339(hace(3600))],
            )
            .expect("silencio caducado");

        let snapshot = repo.engine_snapshot(at).expect("snapshot");
        assert!(!snapshot.devices_empty);
        let ids: Vec<i64> = snapshot.recent.iter().map(|fila| fila.id).collect();
        assert!(ids.contains(&reciente));
        assert!(
            ids.contains(&condicion),
            "una condición activa antigua se carga"
        );
        assert!(!ids.contains(&normal_vieja), "una alerta normal antigua no");
        assert!(!ids.contains(&resuelta), "una condición resuelta no");
        let activa = snapshot
            .recent
            .iter()
            .find(|fila| fila.id == condicion)
            .expect("condición");
        assert!(activa.active);
        assert_eq!(activa.key.rule, RuleId::CaptureStopped);
        assert_eq!(activa.key.subject, Subject::Almenara);

        let mutes: Vec<i64> = snapshot.mutes.iter().map(|_| 0).collect();
        assert_eq!(mutes.len(), 2, "solo los dos silencios vigentes");
        let reglas: Vec<RuleId> = snapshot.mutes.iter().map(|mute| mute.rule).collect();
        assert!(reglas.contains(&RuleId::NewApp));
        assert!(reglas.contains(&RuleId::PortNew));
        assert!(silencio > 0 && temporal > 0);
        assert!(
            snapshot
                .learning
                .iter()
                .any(|fila| fila.subject == Subject::Host),
            "el snapshot trae el aprendizaje de todos los sujetos"
        );
    }

    #[test]
    fn devices_empty_indica_la_linea_base() {
        let dir = tempdir().expect("directorio temporal");
        let repo = Repo::init(&dir.path().join("data.db")).expect("repo");
        let snapshot = repo
            .engine_snapshot(instante("2026-11-11T12:00:00Z"))
            .expect("snapshot");
        assert!(
            snapshot.devices_empty,
            "una base sin equipos arranca en línea base"
        );
    }

    #[test]
    fn set_watched_marca_y_desmarca_el_equipo() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        assert!(
            !repo.list_devices().expect("listar")[0].watched,
            "ninguno vigilado por defecto"
        );
        repo.set_watched(device_id, true).expect("vigilar");
        assert!(repo.list_devices().expect("listar")[0].watched);
        repo.set_watched(device_id, false).expect("desmarcar");
        assert!(!repo.list_devices().expect("listar")[0].watched);
    }

    /// Inicio UTC de la hora local dentro de un día local (misma regla que el DAO).
    fn hora_local_en_dia(dia: LocalDay, hora: i32) -> Option<i64> {
        let (inicio, fin) = dia.limits();
        let mut bucket = inicio - inicio.rem_euclid(3600);
        while bucket < fin {
            if localtime::local_hour(bucket) == hora && LocalDay::from_unix(bucket) == dia {
                return Some(bucket);
            }
            bucket += 3600;
        }
        None
    }

    /// Inserta un total por hora de un equipo.
    fn hora_con_total(repo: &Repo, bucket: i64, device_id: i64, down: i64, up: i64) {
        repo.connection()
            .execute(
                "INSERT INTO TRAFFIC_ROLLUP_HOUR
                     (bucket, subject, device_id, dimension, key, bytes_down, bytes_up,
                      connections)
                 VALUES (?1, 'device', ?2, 'total', '', ?3, ?4, 1)",
                params![bucket, device_id, down, up],
            )
            .expect("hora de tráfico");
    }

    #[test]
    fn hour_baseline_da_el_valor_y_las_muestras_de_la_misma_hora_local() {
        let (_dir, mut repo, device_id) = repo_con_equipo();
        // Un segundo equipo recién dado de alta (sin muestras anteriores).
        let (otro, _) = repo
            .upsert_device(&DeviceUpsert {
                mac: "aa:bb:cc:dd:ee:02".to_string(),
                ip: "192.168.1.51".to_string(),
                hostname: None,
                vendor: None,
                interface_id: 1,
                device_type: "unknown".to_string(),
            })
            .expect("segundo equipo");
        let ahora = localtime::now_unix();
        let hora = localtime::hour_start(ahora) - 3600;
        let dia_actual = LocalDay::from_unix(hora);
        let hora_del_dia = localtime::local_hour(hora);
        let desde = hora - 15 * 86_400;
        let hasta = hora + 3600;
        // Una sesión con captura cubre la hora y todas sus muestras.
        repo.connection()
            .execute(
                "INSERT INTO APP_SESSIONS
                     (started_at, ended_at, last_beat, end_reason, mode, capture,
                      passive_only, version)
                 VALUES (?1, ?2, ?2, 'quit', 'privileged', 1, 0, '0.6.0')",
                params![localtime::rfc3339(desde), localtime::rfc3339(hasta)],
            )
            .expect("sesión");
        // El primer equipo existe desde antes de las muestras.
        repo.connection()
            .execute(
                "UPDATE DEVICES SET first_seen = ?1 WHERE id = ?2",
                params![localtime::rfc3339(desde), device_id],
            )
            .expect("first_seen");
        hora_con_total(&repo, hora, device_id, 1_234_567, 89);
        hora_con_total(&repo, hora, otro, 500, 1);

        let mut muestras_esperadas = Vec::new();
        for atras in 1..=14i64 {
            let dia = dia_actual.sumar_dias(-atras);
            if let Some(muestra) = hora_local_en_dia(dia, hora_del_dia) {
                hora_con_total(&repo, muestra, device_id, atras * 1000, 1);
                muestras_esperadas.push((atras as u64 * 1000, 1));
            }
        }
        muestras_esperadas.sort_unstable();

        let base = repo
            .hour_baseline(hora, &TrafficHighParams::default())
            .expect("línea base");
        let primero = base
            .iter()
            .find(|fila| fila.subject == Subject::Device(device_id))
            .expect("el equipo con tráfico está");
        assert_eq!(primero.down, 1_234_567);
        assert_eq!(primero.up, 89);
        assert_eq!(primero.label, "portatil", "alias, hostname o IP del equipo");
        let mut muestras = primero.samples.clone();
        muestras.sort_unstable();
        assert_eq!(muestras, muestras_esperadas);
        let segundo = base
            .iter()
            .find(|fila| fila.subject == Subject::Device(otro))
            .expect("el equipo nuevo también aparece");
        assert!(
            segundo.samples.is_empty(),
            "sin días anteriores a su alta no tiene muestras"
        );
        assert_eq!(segundo.label, "192.168.1.51");

        // Una hora sin cobertura no se evalúa.
        let sin_cobertura = hora - 40 * 86_400;
        hora_con_total(&repo, sin_cobertura, device_id, 10, 1);
        assert!(repo
            .hour_baseline(sin_cobertura, &TrafficHighParams::default())
            .expect("hora sin cobertura")
            .is_empty());
    }
}
