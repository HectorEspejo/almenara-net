//! Consultas del lector del histórico (§7.5, §7.6, §7.8, §7.9 y §7.11).
//!
//! Todas las funciones reciben la conexión de solo lectura del lector y nunca
//! escriben. Los valores que vienen de la red (dominios, organizaciones,
//! procesos o claves de app) siempre viajan como parámetros SQL; solo los
//! nombres de tabla, las dimensiones y los sujetos, que salen de enumeraciones
//! del código, se incrustan en la sentencia.
//!
//! Las ventanas se calculan con los cubos del rollup (§7.11): 24 h con puntos de
//! 30 min, 7 días con puntos de 3 h (horas cerradas más los minutos de la hora
//! en curso), 30 días locales (días cerrados más las horas del día en curso) y
//! 1 año con 53 semanas locales (lunes a domingo). Un punto es hueco cuando más
//! de la mitad de su tiempo no tiene cobertura de tráfico y nunca se interpola.
//!
//! Cobertura y huecos de tráfico usan solo las sesiones con captura; la
//! presencia usa todas las sesiones (basta el escaneo, §7.8).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, Row};

use crate::error::Result;
use crate::history::localtime::{self, LocalDay};
use crate::history::{
    DbStats, Dimension, EventFilter, Gap, HistRankRow, HistWindow, HistoryQuery, HistoryResponse,
    Inventory, InventoryPort, Page, PresenceSpan, PresenceState, Range, RankingResult, SeenKind,
    SeenRow, Series, SeriesPoint, SubjectSel, TimelineItem, TimelineKind, TopRow, KEY_UNIDENTIFIED,
};
use crate::rankings::DeviceShare;
use crate::traffic::DEVICE_ID_HOST;

/// Consultas del histórico. Es un tipo sin estado: agrupar las funciones bajo
/// Queries mantiene la nomenclatura de los servicios internos del informe.
#[derive(Debug, Clone, Copy, Default)]
pub struct Queries;

/// Ejecuta una consulta del histórico y devuelve su respuesta.
///
/// Es el punto de entrada único del hilo lector (history::reader): hace el match
/// sobre HistoryQuery y delega en las consultas de este módulo. El error se
/// traduce a un mensaje de vista en el propio lector (incluido el corte a 2 s).
pub fn ejecutar(conexion: &Connection, consulta: &HistoryQuery) -> Result<HistoryResponse> {
    Ok(match consulta {
        HistoryQuery::Series {
            subject,
            range,
            now,
        } => HistoryResponse::Series(Queries::series(conexion, *subject, *range, *now)?),
        HistoryQuery::Top {
            subject,
            dimension,
            range,
            n,
            now,
        } => HistoryResponse::Top(Queries::top(
            conexion, *subject, *dimension, *range, *n, *now,
        )?),
        HistoryQuery::Timeline {
            filter,
            range,
            page,
            now,
        } => HistoryResponse::Timeline(Queries::timeline(conexion, *filter, *range, *page, *now)?),
        HistoryQuery::Presence {
            device_id,
            range,
            now,
        } => HistoryResponse::Presence(Queries::presence(conexion, *device_id, *range, *now)?),
        HistoryQuery::Inventory { device_id } => {
            HistoryResponse::Inventory(Box::new(Queries::inventory(conexion, *device_id)?))
        }
        HistoryQuery::Coverage { range, now } => {
            HistoryResponse::Coverage(Queries::coverage(conexion, *range, *now)?)
        }
        HistoryQuery::LastEvent => HistoryResponse::LastEvent(Queries::last_event(conexion)?),
        HistoryQuery::DbStats => {
            HistoryResponse::DbStats(Queries::db_stats(conexion, &ruta_de_la_bd(conexion))?)
        }
        HistoryQuery::WindowRanking {
            dimension,
            window,
            now_minute,
        } => HistoryResponse::WindowRanking(Queries::window_ranking(
            conexion,
            *dimension,
            *window,
            *now_minute,
        )?),
        HistoryQuery::WhoUses {
            dimension,
            key,
            window,
            now_minute,
        } => HistoryResponse::WhoUses(Queries::who_uses(
            conexion,
            *dimension,
            key,
            *window,
            *now_minute,
        )?),
    })
}

/// Ruta del fichero principal de la base de datos, según la propia conexión.
///
/// El lector no recibe la ruta (solo la conexión); PRAGMA database_list la da.
fn ruta_de_la_bd(conexion: &Connection) -> PathBuf {
    let Ok(mut sentencia) = conexion.prepare("PRAGMA database_list") else {
        return PathBuf::new();
    };
    let fila = sentencia.query_row([], |fila| {
        let ruta: Option<String> = fila.get(2)?;
        Ok(ruta)
    });
    match fila {
        Ok(Some(ruta)) if !ruta.is_empty() => PathBuf::from(ruta),
        _ => PathBuf::new(),
    }
}

/// Tabla de rollup de la que sale una ventana.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tabla {
    /// Cubos de un minuto (segundos Unix UTC).
    Minuto,
    /// Cubos de una hora (segundos Unix UTC).
    Hora,
    /// Cubos de un día local (fecha AAAAMMDD).
    Dia,
}

impl Tabla {
    /// Nombre de la tabla en el esquema.
    fn nombre(self) -> &'static str {
        match self {
            Self::Minuto => "TRAFFIC_ROLLUP_MINUTE",
            Self::Hora => "TRAFFIC_ROLLUP_HOUR",
            Self::Dia => "TRAFFIC_ROLLUP_DAY",
        }
    }
}

/// Cubos de un tramo: un rango [desde, hasta) o una lista concreta de cubos.
#[derive(Debug, Clone)]
enum Cubos {
    /// Rango semiabierto [desde, hasta).
    Rango(i64, i64),
    /// Lista de cubos exactos (las horas de hoy en el rango de 30 días).
    Lista(Vec<i64>),
}

/// Tramo de una consulta: tabla del rollup y cubos que entran.
#[derive(Debug, Clone)]
struct Tramo {
    tabla: Tabla,
    cubos: Cubos,
}

impl Tramo {
    fn rango(tabla: Tabla, desde: i64, hasta: i64) -> Self {
        Self {
            tabla,
            cubos: Cubos::Rango(desde, hasta),
        }
    }

    fn lista(tabla: Tabla, cubos: Vec<i64>) -> Self {
        Self {
            tabla,
            cubos: Cubos::Lista(cubos),
        }
    }

    /// Condición SQL sobre bucket y sus parámetros, en orden.
    fn condicion(&self) -> (String, Vec<Value>) {
        match &self.cubos {
            Cubos::Rango(desde, hasta) => (
                "bucket >= ? AND bucket < ?".to_string(),
                vec![Value::Integer(*desde), Value::Integer(*hasta)],
            ),
            Cubos::Lista(cubos) => {
                if cubos.is_empty() {
                    return ("0".to_string(), Vec::new());
                }
                let marcadores = vec!["?"; cubos.len()].join(", ");
                (
                    format!("bucket IN ({marcadores})"),
                    cubos.iter().copied().map(Value::Integer).collect(),
                )
            }
        }
    }
}

/// Ventana temporal de un rango de la pestaña Histórico (§7.11).
#[derive(Debug, Clone)]
struct Ventana {
    /// Inicio del primer punto, en segundos Unix UTC.
    desde: i64,
    /// Fin teórico del último punto (puede caer en el futuro dentro del cubo).
    hasta: i64,
    /// Tramos de rollup que suman el rango, sin solaparse.
    tramos: Vec<Tramo>,
}

impl Ventana {
    /// Fin real de la ventana: nunca más allá del instante consultado.
    fn hasta_real(&self, now: i64) -> i64 {
        self.hasta.min(now)
    }
}

/// Punto crudo de una serie, antes de calcular cobertura y huecos.
#[derive(Debug, Clone, Copy)]
struct PuntoCrudo {
    at: i64,
    fin: i64,
    down: u64,
    up: u64,
}

/// Intervalo cerrado por la izquierda y abierto por la derecha.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Intervalo {
    start: i64,
    end: i64,
}

fn rfc_a_unix(texto: &str) -> Option<i64> {
    localtime::unix_de_rfc3339(texto)
}

fn unix_a_rfc(segundos: i64) -> String {
    localtime::rfc3339(segundos)
}

/// Etiqueta visible de un equipo: alias, si no hostname, si no IP y, si no hay
/// fila, «#id» (§7.8 del informe y convención de F4).
fn etiqueta_de_equipo(
    device_id: i64,
    alias: Option<&str>,
    hostname: Option<&str>,
    ip: Option<&str>,
) -> String {
    let alias = alias.map(str::trim).filter(|valor| !valor.is_empty());
    if let Some(alias) = alias {
        return alias.to_string();
    }
    let hostname = hostname.map(str::trim).filter(|valor| !valor.is_empty());
    if let Some(hostname) = hostname {
        return hostname.to_string();
    }
    let ip = ip.map(str::trim).filter(|valor| !valor.is_empty());
    if let Some(ip) = ip {
        return ip.to_string();
    }
    format!("#{device_id}")
}

/// Carga las etiquetas visibles de todos los equipos.
fn etiquetas_de_equipos(conn: &Connection) -> Result<HashMap<i64, String>> {
    let mut sentencia = conn.prepare("SELECT id, alias, hostname, ip FROM DEVICES")?;
    let filas = sentencia.query_map([], |fila| {
        let id: i64 = fila.get(0)?;
        let alias: Option<String> = fila.get(1)?;
        let hostname: Option<String> = fila.get(2)?;
        let ip: Option<String> = fila.get(3)?;
        Ok((
            id,
            etiqueta_de_equipo(id, alias.as_deref(), hostname.as_deref(), ip.as_deref()),
        ))
    })?;
    let mut etiquetas = HashMap::new();
    for fila in filas {
        let (id, etiqueta) = fila?;
        etiquetas.insert(id, etiqueta);
    }
    Ok(etiquetas)
}

fn etiqueta_conocida(etiquetas: &HashMap<i64, String>, device_id: i64) -> String {
    etiquetas
        .get(&device_id)
        .cloned()
        .unwrap_or_else(|| format!("#{device_id}"))
}

/// Etiqueta de un sujeto de la dimensión total: equipo, [host] u otros.
fn etiqueta_de_sujeto(
    subject: &str,
    device_id: i64,
    etiquetas: &HashMap<i64, String>,
) -> (String, String, Option<i64>) {
    match subject {
        "device" => (
            device_id.to_string(),
            etiqueta_conocida(etiquetas, device_id),
            Some(device_id),
        ),
        "host" => ("host".to_string(), "[host]".to_string(), None),
        _ => ("other".to_string(), "Otros".to_string(), None),
    }
}

/// Devuelve el id del equipo si la clave es un destino de la red local.
fn parsear_destino_lan(clave: &str) -> Option<i64> {
    clave
        .strip_prefix("lan:")
        .and_then(|resto| resto.parse::<i64>().ok())
}

/// Resuelve la etiqueta de una clave de destino.
///
/// Los destinos de la LAN se resuelven al nombre del equipo; el resto de claves
/// se muestran tal cual porque el hilo lector no tiene el catálogo de apps.
fn etiqueta_de_clave(
    dimension: Dimension,
    clave: &str,
    etiquetas: &HashMap<i64, String>,
) -> (String, Option<String>, Option<i64>) {
    if dimension == Dimension::Destination {
        if let Some(device_id) = parsear_destino_lan(clave) {
            return (
                etiqueta_conocida(etiquetas, device_id),
                Some("red local".to_string()),
                Some(device_id),
            );
        }
    }
    (clave.to_string(), None, None)
}

/// Porcentaje sobre un total, sin redondear y acotado a [0, 100].
fn porcentaje(parte: u64, total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let pct = (parte as f64 / total as f64 * 100.0) as f32;
    pct.clamp(0.0, 100.0)
}

/// Lee una columna entera que puede ser NULL como u64.
fn entero_u64(fila: &Row<'_>, indice: usize) -> rusqlite::Result<u64> {
    let valor: Option<i64> = fila.get(indice)?;
    Ok(valor.unwrap_or(0).max(0) as u64)
}

// ---------------------------------------------------------------------------
// Ventanas de los rangos
// ---------------------------------------------------------------------------

/// Horas cerradas del día local que empiezan antes del inicio de la hora en
/// curso (para el punto en progreso del rango de 30 días).
fn horas_del_dia_antes_de(dia: LocalDay, hora_actual: i64) -> Vec<i64> {
    dia.hours()
        .into_iter()
        .filter(|hora| *hora < hora_actual)
        .collect()
}

/// Calcula la ventana de un rango (§7.11).
fn ventana_rango(range: Range, now: i64) -> Ventana {
    match range {
        Range::Hours24 => {
            let fin = now - now.rem_euclid(1800);
            let desde = fin - 47 * 1800;
            Ventana {
                desde,
                hasta: fin + 1800,
                tramos: vec![Tramo::rango(Tabla::Minuto, desde, fin + 1800)],
            }
        }
        Range::Days7 => {
            let fin = now - now.rem_euclid(3 * 3600);
            let desde = fin - 55 * 3 * 3600;
            let hora_actual = now - now.rem_euclid(3600);
            Ventana {
                desde,
                hasta: fin + 3 * 3600,
                tramos: vec![
                    Tramo::rango(Tabla::Hora, desde, hora_actual),
                    Tramo::rango(Tabla::Minuto, hora_actual, now),
                ],
            }
        }
        Range::Days30 => {
            let hoy = LocalDay::from_unix(now);
            let primero = hoy.sumar_dias(-29);
            let hora_actual = now - now.rem_euclid(3600);
            Ventana {
                desde: primero.limits().0,
                hasta: now,
                tramos: vec![
                    Tramo::rango(Tabla::Dia, primero.aaaammdd(), hoy.aaaammdd()),
                    Tramo::lista(Tabla::Hora, horas_del_dia_antes_de(hoy, hora_actual)),
                ],
            }
        }
        Range::Year1 => {
            let hoy = LocalDay::from_unix(now);
            let semana = LocalDay::from_unix(localtime::week_start(now));
            let primera = semana.sumar_dias(-52 * 7);
            Ventana {
                desde: primera.limits().0,
                hasta: now,
                tramos: vec![Tramo::rango(Tabla::Dia, primera.aaaammdd(), hoy.aaaammdd())],
            }
        }
    }
}

/// Tramos de las ventanas de 1 h y 24 h de la pestaña Tráfico (§7.5).
fn tramos_ventana(window: HistWindow, now_minute: i64) -> (Vec<Tramo>, i64, i64) {
    match window {
        HistWindow::OneHour => (
            vec![Tramo::rango(Tabla::Minuto, now_minute - 3600, now_minute)],
            now_minute - 3600,
            now_minute,
        ),
        HistWindow::Day24 => {
            let hora = now_minute - now_minute.rem_euclid(3600);
            (
                vec![
                    Tramo::rango(Tabla::Hora, hora - 23 * 3600, hora),
                    Tramo::rango(Tabla::Minuto, hora, now_minute),
                ],
                hora - 23 * 3600,
                now_minute,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Cobertura de tráfico
// ---------------------------------------------------------------------------

/// Sesiones con captura que solapan [desde, hasta), recortadas y fusionadas.
fn cobertura_trafico(conn: &Connection, desde: i64, hasta: i64) -> Result<Vec<Intervalo>> {
    if desde >= hasta {
        return Ok(Vec::new());
    }
    let mut sentencia = conn.prepare(
        "SELECT started_at, ended_at
           FROM APP_SESSIONS
          WHERE capture = 1
            AND started_at < ?1
            AND (ended_at IS NULL OR ended_at > ?2)
          ORDER BY started_at",
    )?;
    let filas = sentencia.query_map(params![unix_a_rfc(hasta), unix_a_rfc(desde)], |fila| {
        let inicio: String = fila.get(0)?;
        let fin: Option<String> = fila.get(1)?;
        Ok((inicio, fin))
    })?;
    let mut intervalos: Vec<Intervalo> = Vec::new();
    for fila in filas {
        let (inicio, fin) = fila?;
        let Some(inicio) = rfc_a_unix(&inicio) else {
            continue;
        };
        let fin = fin
            .as_deref()
            .and_then(rfc_a_unix)
            .unwrap_or(hasta)
            .min(hasta);
        let inicio = inicio.max(desde);
        if inicio >= fin {
            continue;
        }
        match intervalos.last_mut() {
            Some(anterior) if inicio <= anterior.end => anterior.end = anterior.end.max(fin),
            _ => intervalos.push(Intervalo {
                start: inicio,
                end: fin,
            }),
        }
    }
    Ok(intervalos)
}

/// Tiempo cubierto por los intervalos dentro de [desde, hasta).
fn tiempo_cubierto(intervalos: &[Intervalo], desde: i64, hasta: i64) -> i64 {
    if desde >= hasta {
        return 0;
    }
    intervalos
        .iter()
        .map(|intervalo| {
            let inicio = intervalo.start.max(desde);
            let fin = intervalo.end.min(hasta);
            (fin - inicio).max(0)
        })
        .sum()
}

/// Complemento de los intervalos en [desde, hasta): los huecos de cobertura.
fn huecos_de(intervalos: &[Intervalo], desde: i64, hasta: i64) -> Vec<Gap> {
    let mut huecos = Vec::new();
    let mut cursor = desde;
    for intervalo in intervalos {
        let inicio = intervalo.start.max(desde);
        let fin = intervalo.end.min(hasta);
        if fin <= cursor {
            continue;
        }
        if inicio > cursor {
            huecos.push(Gap {
                start: cursor,
                end: inicio,
            });
        }
        cursor = cursor.max(fin);
    }
    if cursor < hasta {
        huecos.push(Gap {
            start: cursor,
            end: hasta,
        });
    }
    huecos
}

// ---------------------------------------------------------------------------
// Series de tráfico (§7.11)
// ---------------------------------------------------------------------------

impl Queries {
    /// Serie de tráfico de un sujeto con sus huecos y sus totales.
    pub fn series(
        conn: &Connection,
        subject: SubjectSel,
        range: Range,
        now: i64,
    ) -> Result<Series> {
        let ventana = ventana_rango(range, now);
        let puntos = leer_serie(conn, subject, range, now, &ventana)?;
        let intervalos = cobertura_trafico(conn, ventana.desde, ventana.hasta_real(now))?;
        Ok(montar_serie(range, now, puntos, &intervalos))
    }

    /// «Más tráfico» del rango (§7.11).
    pub fn top(
        conn: &Connection,
        subject: SubjectSel,
        dimension: Dimension,
        range: Range,
        n: usize,
        now: i64,
    ) -> Result<Vec<TopRow>> {
        let ventana = ventana_rango(range, now);
        let etiquetas = etiquetas_de_equipos(conn)?;
        let (total_down, total_up) = total_del_rango(conn, subject, &ventana)?;
        let total = total_down.saturating_add(total_up);
        let mut filas = if dimension == Dimension::Total {
            top_por_sujeto(conn, subject, &ventana, &etiquetas)?
        } else {
            top_por_clave(conn, subject, dimension, &ventana, &etiquetas)?
        };
        for fila in &mut filas {
            fila.pct = porcentaje(fila.total(), total);
        }
        filas.sort_by(|a, b| b.total().cmp(&a.total()).then_with(|| a.key.cmp(&b.key)));
        if n > 0 {
            filas.truncate(n);
        }
        Ok(filas)
    }

    /// Ranking de 1 h o 24 h de la pestaña Tráfico (§7.5).
    pub fn window_ranking(
        conn: &Connection,
        dimension: Dimension,
        window: HistWindow,
        now_minute: i64,
    ) -> Result<RankingResult> {
        let (tramos, desde, hasta) = tramos_ventana(window, now_minute);
        let etiquetas = etiquetas_de_equipos(conn)?;
        let dimension_sql = dimension.as_str();
        let (total_down, total_up) = total_de_tramos(conn, &tramos, "network", 0)?;
        let total = total_down.saturating_add(total_up);
        let mut acumulados: HashMap<ClaveRanking, AcumuladoRanking> = HashMap::new();
        for tramo in &tramos {
            let (condicion, parametros) = tramo.condicion();
            let sql = format!(
                "SELECT subject, device_id, key, SUM(bytes_down), SUM(bytes_up), SUM(connections)
                   FROM {}
                  WHERE {condicion} AND dimension = ? AND subject <> 'network'
                  GROUP BY subject, device_id, key",
                tramo.tabla.nombre()
            );
            let mut sentencia = conn.prepare(&sql)?;
            let mut valores = parametros;
            valores.push(Value::Text(dimension_sql.to_string()));
            let filas = sentencia.query_map(params_from_iter(valores), |fila| {
                let subject: String = fila.get(0)?;
                let device_id: i64 = fila.get(1)?;
                let key: String = fila.get(2)?;
                let down = entero_u64(fila, 3)?;
                let up = entero_u64(fila, 4)?;
                let connections = entero_u64(fila, 5)?;
                Ok((subject, device_id, key, down, up, connections))
            })?;
            for fila in filas {
                let (subject, device_id, key, down, up, connections) = fila?;
                let clave = if dimension == Dimension::Total {
                    ClaveRanking::Sujeto(subject.clone(), device_id)
                } else {
                    ClaveRanking::Clave(key)
                };
                let acumulado = acumulados.entry(clave).or_default();
                acumulado.down = acumulado.down.saturating_add(down);
                acumulado.up = acumulado.up.saturating_add(up);
                acumulado.connections = acumulado.connections.saturating_add(connections);
                if subject == "device" {
                    acumulado.devices.insert(device_id);
                }
            }
        }
        let mut filas: Vec<HistRankRow> = acumulados
            .into_iter()
            .map(|(clave, acumulado)| match clave {
                ClaveRanking::Sujeto(subject, device_id) => {
                    let (key, label, device) = etiqueta_de_sujeto(&subject, device_id, &etiquetas);
                    HistRankRow {
                        key,
                        label,
                        subtitle: None,
                        device_id: device,
                        bytes_down: acumulado.down,
                        bytes_up: acumulado.up,
                        devices: if device.is_some() { 1 } else { 0 },
                        connections: acumulado.connections,
                    }
                }
                ClaveRanking::Clave(key) => {
                    let (label, subtitle, device_id) =
                        etiqueta_de_clave(dimension, &key, &etiquetas);
                    HistRankRow {
                        key,
                        label,
                        subtitle,
                        device_id,
                        bytes_down: acumulado.down,
                        bytes_up: acumulado.up,
                        devices: acumulado.devices.len() as u32,
                        connections: acumulado.connections,
                    }
                }
            })
            .collect();
        filas.sort_by(|a, b| b.total().cmp(&a.total()).then_with(|| a.key.cmp(&b.key)));
        filas.truncate(50);
        let unidentified_pct = if dimension == Dimension::App {
            let sin_identificar = bytes_de_clave(conn, &tramos, Dimension::App, KEY_UNIDENTIFIED)?;
            porcentaje(sin_identificar, total)
        } else {
            0.0
        };
        let intervalos = cobertura_trafico(conn, desde, hasta)?;
        let gap_seconds = huecos_de(&intervalos, desde, hasta)
            .into_iter()
            .map(Gap::dur)
            .sum();
        Ok(RankingResult {
            window,
            dimension,
            rows: filas,
            total_down,
            total_up,
            unidentified_pct,
            closed_until: now_minute - 60,
            gap_seconds,
        })
    }

    /// «¿Quién lo usa?» de una clave en 1 h o 24 h (§7.5).
    pub fn who_uses(
        conn: &Connection,
        dimension: Dimension,
        key: &str,
        window: HistWindow,
        now_minute: i64,
    ) -> Result<Vec<DeviceShare>> {
        let (tramos, _, _) = tramos_ventana(window, now_minute);
        let etiquetas = etiquetas_de_equipos(conn)?;
        if dimension == Dimension::Total {
            shares_de_sujeto(conn, &tramos, key, &etiquetas)
        } else {
            shares_de_clave(conn, &tramos, dimension, key, &etiquetas)
        }
    }

    /// Línea de tiempo de eventos y sesiones del rango, más recientes primero.
    pub fn timeline(
        conn: &Connection,
        filter: EventFilter,
        range: Range,
        page: Page,
        now: i64,
    ) -> Result<Vec<TimelineItem>> {
        let desde = now - range.dur_s();
        let capacidad = match page.limit {
            0 => -1,
            limit => i64::try_from(page.offset.saturating_add(limit)).unwrap_or(-1),
        };
        let mut items = Vec::new();
        let tipos = filter.tipos();
        if !tipos.is_empty() {
            let marcadores = vec!["?"; tipos.len()].join(", ");
            let sql = format!(
                "SELECT e.device_id, e.event_type, e.details, e.created_at,
                        d.alias, d.hostname, d.ip
                   FROM DEVICE_EVENTS e
                   LEFT JOIN DEVICES d ON d.id = e.device_id
                  WHERE e.event_type IN ({marcadores})
                    AND e.created_at >= ? AND e.created_at <= ?
                  ORDER BY e.created_at DESC, e.id DESC
                  LIMIT ?"
            );
            let mut valores: Vec<Value> = tipos
                .iter()
                .map(|tipo| Value::Text(tipo.to_string()))
                .collect();
            valores.push(Value::Text(unix_a_rfc(desde)));
            valores.push(Value::Text(unix_a_rfc(now)));
            valores.push(Value::Integer(capacidad));
            let mut sentencia = conn.prepare(&sql)?;
            let filas = sentencia.query_map(params_from_iter(valores), |fila| {
                let device_id: i64 = fila.get(0)?;
                let event_type: String = fila.get(1)?;
                let details: String = fila.get(2)?;
                let created_at: String = fila.get(3)?;
                let alias: Option<String> = fila.get(4)?;
                let hostname: Option<String> = fila.get(5)?;
                let ip: Option<String> = fila.get(6)?;
                Ok((
                    device_id, event_type, details, created_at, alias, hostname, ip,
                ))
            })?;
            for fila in filas {
                let (device_id, event_type, details, created_at, alias, hostname, ip) = fila?;
                let etiqueta = etiqueta_de_equipo(
                    device_id,
                    alias.as_deref(),
                    hostname.as_deref(),
                    ip.as_deref(),
                );
                if let Some(item) =
                    item_de_evento(device_id, &event_type, &details, &created_at, &etiqueta)
                {
                    items.push(item);
                }
            }
        }
        if filter.incluye_sesiones() {
            let mut sentencia = conn.prepare(
                "SELECT started_at, ended_at, end_reason
                   FROM APP_SESSIONS
                  WHERE started_at <= ?1
                    AND (started_at >= ?2 OR (ended_at IS NOT NULL AND ended_at >= ?2))
                  ORDER BY started_at DESC, id DESC",
            )?;
            let filas =
                sentencia.query_map(params![unix_a_rfc(now), unix_a_rfc(desde)], |fila| {
                    let inicio: String = fila.get(0)?;
                    let fin: Option<String> = fila.get(1)?;
                    let motivo: Option<String> = fila.get(2)?;
                    Ok((inicio, fin, motivo))
                })?;
            for fila in filas {
                let (inicio, fin, motivo) = fila?;
                items.extend(items_de_sesion(&inicio, fin.as_deref(), motivo.as_deref()));
            }
        }
        items.sort_by_key(|item| std::cmp::Reverse(item.at_unix));
        let inicio = page.offset.min(items.len());
        let fin = match page.limit {
            0 => items.len(),
            limit => inicio.saturating_add(limit).min(items.len()),
        };
        Ok(items[inicio..fin].to_vec())
    }

    /// Tramos de presencia de un equipo (§7.8).
    ///
    /// Usa todas las sesiones (con o sin captura: basta el escaneo) y calcula
    /// los tramos al vuelo desde los eventos new/disappeared/reappeared. Si el
    /// primer disappeared de una sesión lleva un last_seen anterior a su
    /// arranque, el equipo se marca ausente desde el inicio de la sesión.
    pub fn presence(
        conn: &Connection,
        device_id: i64,
        range: Range,
        now: i64,
    ) -> Result<Vec<PresenceSpan>> {
        let desde = now - range.dur_s();
        let hasta = now;
        if desde >= hasta {
            return Ok(Vec::new());
        }
        let Some(primera_vez) = primera_vez_visto(conn, device_id)? else {
            return Ok(vec![PresenceSpan {
                start: desde,
                end: hasta,
                state: PresenceState::NoData,
            }]);
        };
        let eventos = eventos_de_presencia(conn, device_id)?;
        let sesiones = sesiones_solapadas(conn, desde, hasta)?;
        let mut tramos: Vec<PresenceSpan> = Vec::new();
        for (inicio_sesion, fin_sesion) in sesiones {
            let inicio_visible = inicio_sesion.max(desde);
            let fin_visible = fin_sesion.min(hasta);
            if inicio_visible >= fin_visible {
                continue;
            }
            let mut estado = estado_previo(&eventos, inicio_sesion, primera_vez);
            let mut t = inicio_sesion;
            for evento in eventos
                .iter()
                .filter(|evento| evento.at >= inicio_sesion && evento.at < fin_sesion)
            {
                let cambio = evento.cambio.clamp(inicio_sesion, fin_sesion);
                if let Some(estado_actual) = estado {
                    if cambio > t {
                        let inicio_tramo = t.max(desde);
                        let fin_tramo = cambio.min(fin_visible);
                        if inicio_tramo < fin_tramo {
                            tramos.push(PresenceSpan {
                                start: inicio_tramo,
                                end: fin_tramo,
                                state: estado_actual,
                            });
                        }
                    }
                }
                estado = Some(evento.estado);
                t = t.max(cambio);
            }
            if let Some(estado_actual) = estado {
                let inicio_tramo = t.max(desde);
                if inicio_tramo < fin_visible {
                    tramos.push(PresenceSpan {
                        start: inicio_tramo,
                        end: fin_visible,
                        state: estado_actual,
                    });
                }
            }
        }
        Ok(rellenar_huecos(tramos, desde, hasta))
    }

    /// Inventario de un equipo (§7.9).
    ///
    /// Los puertos salen de DEVICE_SERVICES. Como el lector no tiene la config
    /// del escaneo, el estado CERRADO se materializa con el último evento de
    /// servicio de cada (puerto, protocolo): si es service_gone, el puerto ya
    /// no está abierto y no se muestra. Sin eventos, la fila de F2 se incluye.
    pub fn inventory(conn: &Connection, device_id: i64) -> Result<Inventory> {
        let mut inventario = Inventory {
            device_id,
            ..Inventory::default()
        };
        let mut sentencia = conn.prepare(
            "SELECT kind, key, first_seen, last_seen
               FROM DEVICE_SEEN
              WHERE device_id = ?1
              ORDER BY first_seen, key",
        )?;
        let filas = sentencia.query_map(params![device_id], |fila| {
            let kind: String = fila.get(0)?;
            let key: String = fila.get(1)?;
            let first_seen: String = fila.get(2)?;
            let last_seen: String = fila.get(3)?;
            Ok((kind, key, first_seen, last_seen))
        })?;
        let mut since: Option<String> = None;
        for fila in filas {
            let (kind, key, first_seen, last_seen) = fila?;
            let Some(kind) = SeenKind::from_str(&kind) else {
                continue;
            };
            if since
                .as_deref()
                .is_none_or(|actual| first_seen.as_str() < actual)
            {
                since = Some(first_seen.clone());
            }
            let entrada = SeenRow {
                key: key.clone(),
                label: key,
                first_seen,
                last_seen,
            };
            match kind {
                SeenKind::App => inventario.apps.push(entrada),
                SeenKind::Category => inventario.categories.push(entrada),
                SeenKind::Org => inventario.orgs.push(entrada),
                SeenKind::Country => inventario.countries.push(entrada),
                SeenKind::Ja4 => inventario.ja4.push(entrada),
            }
        }
        // Último evento de servicio por (puerto, protocolo): manda el más reciente.
        let cerrados = puertos_cerrados(conn, device_id)?;
        let mut sentencia = conn.prepare(
            "SELECT port, protocol, service, first_seen
               FROM DEVICE_SERVICES
              WHERE device_id = ?1
              ORDER BY port, protocol",
        )?;
        let filas = sentencia.query_map(params![device_id], |fila| {
            let port: i64 = fila.get(0)?;
            let protocol: String = fila.get(1)?;
            let service: Option<String> = fila.get(2)?;
            let first_seen: String = fila.get(3)?;
            Ok((port, protocol, service, first_seen))
        })?;
        for fila in filas {
            let (port, protocol, service, first_seen) = fila?;
            let Ok(port) = u16::try_from(port) else {
                continue;
            };
            if cerrados.contains(&(port, protocol.clone())) {
                continue;
            }
            if since
                .as_deref()
                .is_none_or(|actual| first_seen.as_str() < actual)
            {
                since = Some(first_seen.clone());
            }
            inventario.ports.push(InventoryPort {
                port,
                protocol,
                service,
                first_seen,
            });
        }
        inventario.since = since;
        Ok(inventario)
    }

    /// Huecos de cobertura de tráfico de un rango (§7.6).
    pub fn coverage(conn: &Connection, range: Range, now: i64) -> Result<Vec<Gap>> {
        let desde = now - range.dur_s();
        let intervalos = cobertura_trafico(conn, desde, now)?;
        Ok(huecos_de(&intervalos, desde, now))
    }

    /// Evento de dispositivo más reciente (línea «Último evento» de Equipos).
    pub fn last_event(conn: &Connection) -> Result<Option<TimelineItem>> {
        let mut sentencia = conn.prepare(
            "SELECT e.device_id, e.event_type, e.details, e.created_at,
                    d.alias, d.hostname, d.ip
               FROM DEVICE_EVENTS e
               LEFT JOIN DEVICES d ON d.id = e.device_id
              ORDER BY e.created_at DESC, e.id DESC
              LIMIT 1",
        )?;
        let fila = sentencia
            .query_row([], |fila| {
                let device_id: i64 = fila.get(0)?;
                let event_type: String = fila.get(1)?;
                let details: String = fila.get(2)?;
                let created_at: String = fila.get(3)?;
                let alias: Option<String> = fila.get(4)?;
                let hostname: Option<String> = fila.get(5)?;
                let ip: Option<String> = fila.get(6)?;
                Ok((
                    device_id, event_type, details, created_at, alias, hostname, ip,
                ))
            })
            .map(Some)
            .or_else(|err| match err {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                otro => Err(otro),
            })?;
        let Some((device_id, event_type, details, created_at, alias, hostname, ip)) = fila else {
            return Ok(None);
        };
        let etiqueta = etiqueta_de_equipo(
            device_id,
            alias.as_deref(),
            hostname.as_deref(),
            ip.as_deref(),
        );
        Ok(item_de_evento(
            device_id,
            &event_type,
            &details,
            &created_at,
            &etiqueta,
        ))
    }

    /// Estadísticas de la base de datos para la pestaña Config (§7.6 y §8).
    pub fn db_stats(conn: &Connection, db_path: &Path) -> Result<DbStats> {
        let paginas: i64 = conn.query_row("PRAGMA page_count", [], |fila| fila.get(0))?;
        let tamano_pagina: i64 = conn.query_row("PRAGMA page_size", [], |fila| fila.get(0))?;
        let db_bytes = (paginas.max(0) as u64).saturating_mul(tamano_pagina.max(0) as u64);
        let wal_bytes = tamano_wal(db_path);
        let data_since = primer_dato(conn)?;
        let ahora = localtime::now_unix();
        let desde = ahora - 30 * 86_400;
        let intervalos = cobertura_trafico(conn, desde, ahora)?;
        let cubierto = tiempo_cubierto(&intervalos, desde, ahora);
        let coverage_30d_pct = porcentaje(cubierto.max(0) as u64, (ahora - desde).max(0) as u64);
        Ok(DbStats {
            db_bytes,
            wal_bytes,
            data_since,
            coverage_30d_pct,
        })
    }
}

/// Puertos cuyo último evento de servicio es service_gone.
fn puertos_cerrados(conn: &Connection, device_id: i64) -> Result<HashSet<(u16, String)>> {
    let mut sentencia = conn.prepare(
        "SELECT event_type, details
           FROM DEVICE_EVENTS
          WHERE device_id = ?1
            AND event_type IN ('service_new', 'service_gone')
          ORDER BY created_at DESC, id DESC",
    )?;
    let filas = sentencia.query_map(params![device_id], |fila| {
        let tipo: String = fila.get(0)?;
        let details: String = fila.get(1)?;
        Ok((tipo, details))
    })?;
    let mut cerrados = HashSet::new();
    let mut vistos: HashSet<(u16, String)> = HashSet::new();
    for fila in filas {
        let (tipo, details) = fila?;
        let Some(puerto) = detalle_texto(&details, "port").and_then(|p| p.parse::<u16>().ok())
        else {
            continue;
        };
        let protocolo = detalle_texto(&details, "protocol").unwrap_or_else(|| "tcp".to_string());
        let clave = (puerto, protocolo);
        if !vistos.insert(clave.clone()) {
            continue;
        }
        if tipo == "service_gone" {
            cerrados.insert(clave);
        }
    }
    Ok(cerrados)
}

/// Clave de agrupación del ranking de ventana.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ClaveRanking {
    /// Fila de un sujeto en la dimensión total.
    Sujeto(String, i64),
    /// Fila de una clave de una dimensión.
    Clave(String),
}

/// Acumulador de una fila del ranking de ventana.
#[derive(Debug, Default)]
struct AcumuladoRanking {
    down: u64,
    up: u64,
    connections: u64,
    devices: HashSet<i64>,
}

/// Tamaño del fichero -wal; 0 si no existe (por ejemplo, BD en memoria).
fn tamano_wal(db_path: &Path) -> u64 {
    if db_path.as_os_str().is_empty() {
        return 0;
    }
    let mut ruta = db_path.as_os_str().to_os_string();
    ruta.push("-wal");
    std::fs::metadata(Path::new(&ruta))
        .map(|metadatos| metadatos.len())
        .unwrap_or(0)
}

/// Fecha RFC 3339 del dato más antiguo de las tres resoluciones.
fn primer_dato(conn: &Connection) -> Result<Option<String>> {
    let mut candidatos: Vec<i64> = Vec::new();
    for tabla in ["TRAFFIC_ROLLUP_MINUTE", "TRAFFIC_ROLLUP_HOUR"] {
        let bucket: Option<i64> =
            conn.query_row(&format!("SELECT MIN(bucket) FROM {tabla}"), [], |fila| {
                fila.get(0)
            })?;
        if let Some(bucket) = bucket {
            candidatos.push(bucket);
        }
    }
    let dia: Option<i64> =
        conn.query_row("SELECT MIN(bucket) FROM TRAFFIC_ROLLUP_DAY", [], |fila| {
            fila.get(0)
        })?;
    if let Some(dia) = dia.and_then(LocalDay::from_aaaammdd) {
        candidatos.push(dia.limits().0);
    }
    Ok(candidatos.into_iter().min().map(unix_a_rfc))
}

// ---------------------------------------------------------------------------
// Series: lectura de los cubos y montaje de los puntos
// ---------------------------------------------------------------------------

/// Sujeto persistido (subject, device_id) de un selector.
fn partes_de_sujeto(subject: SubjectSel) -> (&'static str, i64) {
    match subject {
        SubjectSel::Network => ("network", 0),
        SubjectSel::Host => ("host", 0),
        SubjectSel::Device(id) => ("device", id),
    }
}

/// Lee los cubos de un rango y los coloca en sus puntos.
fn leer_serie(
    conn: &Connection,
    subject: SubjectSel,
    range: Range,
    now: i64,
    ventana: &Ventana,
) -> Result<Vec<PuntoCrudo>> {
    let (subject_sql, device_id) = partes_de_sujeto(subject);
    let mut puntos = puntos_de_rango(range, now, ventana);
    for tramo in &ventana.tramos {
        let (condicion, parametros) = tramo.condicion();
        let sql = format!(
            "SELECT bucket, SUM(bytes_down), SUM(bytes_up)
               FROM {}
              WHERE {condicion} AND subject = ? AND device_id = ? AND dimension = 'total'
              GROUP BY bucket",
            tramo.tabla.nombre()
        );
        let mut sentencia = conn.prepare(&sql)?;
        let mut valores = parametros;
        valores.push(Value::Text(subject_sql.to_string()));
        valores.push(Value::Integer(device_id));
        let filas = sentencia.query_map(params_from_iter(valores), |fila| {
            Ok((
                fila.get::<_, i64>(0)?,
                entero_u64(fila, 1)?,
                entero_u64(fila, 2)?,
            ))
        })?;
        for fila in filas {
            let (bucket, down, up) = fila?;
            if let Some(indice) = indice_de_bucket(range, tramo.tabla, &puntos, bucket, now) {
                puntos[indice].down = puntos[indice].down.saturating_add(down);
                puntos[indice].up = puntos[indice].up.saturating_add(up);
            }
        }
    }
    Ok(puntos)
}

/// Puntos vacíos del rango con su inicio y su fin teórico.
fn puntos_de_rango(range: Range, now: i64, ventana: &Ventana) -> Vec<PuntoCrudo> {
    match range {
        Range::Hours24 => (0..48)
            .map(|i| {
                let at = ventana.desde + i * 1800;
                PuntoCrudo {
                    at,
                    fin: at + 1800,
                    down: 0,
                    up: 0,
                }
            })
            .collect(),
        Range::Days7 => (0..56)
            .map(|i| {
                let at = ventana.desde + i * 10_800;
                PuntoCrudo {
                    at,
                    fin: at + 10_800,
                    down: 0,
                    up: 0,
                }
            })
            .collect(),
        Range::Days30 => {
            let hoy = LocalDay::from_unix(now);
            let primero = hoy.sumar_dias(-29);
            (0..30)
                .map(|i| {
                    let dia = primero.sumar_dias(i);
                    PuntoCrudo {
                        at: dia.limits().0,
                        fin: dia.sumar_dias(1).limits().0,
                        down: 0,
                        up: 0,
                    }
                })
                .collect()
        }
        Range::Year1 => {
            let semana = LocalDay::from_unix(localtime::week_start(now));
            let primera = semana.sumar_dias(-52 * 7);
            (0..53)
                .map(|i| {
                    let inicio = primera.sumar_dias(i * 7);
                    PuntoCrudo {
                        at: inicio.limits().0,
                        fin: primera.sumar_dias((i + 1) * 7).limits().0,
                        down: 0,
                        up: 0,
                    }
                })
                .collect()
        }
    }
}

/// Índice del punto al que pertenece un cubo, si cae dentro del rango.
fn indice_de_bucket(
    range: Range,
    tabla: Tabla,
    puntos: &[PuntoCrudo],
    bucket: i64,
    now: i64,
) -> Option<usize> {
    match range {
        Range::Hours24 => {
            let primero = puntos.first()?.at;
            if bucket < primero {
                return None;
            }
            let indice = usize::try_from((bucket - primero) / 1800).ok()?;
            (indice < puntos.len()).then_some(indice)
        }
        Range::Days7 => {
            let primero = puntos.first()?.at;
            if bucket < primero {
                return None;
            }
            let indice = usize::try_from((bucket - primero) / 10_800).ok()?;
            (indice < puntos.len()).then_some(indice)
        }
        Range::Days30 => {
            if tabla == Tabla::Hora {
                return Some(puntos.len() - 1);
            }
            let hoy = LocalDay::from_unix(now);
            let primero = hoy.sumar_dias(-29);
            let dia = LocalDay::from_aaaammdd(bucket)?;
            let indice = usize::try_from(primero.dias_hasta(dia)).ok()?;
            (indice < puntos.len()).then_some(indice)
        }
        Range::Year1 => {
            if tabla != Tabla::Dia {
                return None;
            }
            let hoy = LocalDay::from_unix(now);
            let semana = LocalDay::from_unix(localtime::week_start(now));
            let primera = semana.sumar_dias(-52 * 7);
            let dia = LocalDay::from_aaaammdd(bucket)?;
            let indice = usize::try_from(primera.dias_hasta(dia) / 7).ok()?;
            (indice < puntos.len() && dia < hoy).then_some(indice)
        }
    }
}

/// Monta la serie: cobertura por punto, huecos, totales y máximo.
fn montar_serie(
    range: Range,
    now: i64,
    puntos: Vec<PuntoCrudo>,
    intervalos: &[Intervalo],
) -> Series {
    let mut serie = Series {
        range,
        points: Vec::with_capacity(puntos.len()),
        total_down: 0,
        total_up: 0,
        max: None,
    };
    let mut maximo: Option<(usize, u64)> = None;
    for (indice, punto) in puntos.into_iter().enumerate() {
        let future = punto.at > now;
        let fin_tiempo = punto.fin.min(now);
        let duracion = (fin_tiempo - punto.at).max(0);
        let cubierto = if future {
            0
        } else {
            tiempo_cubierto(intervalos, punto.at, fin_tiempo)
        };
        let gap = !future && duracion > 0 && cubierto.saturating_mul(2) < duracion;
        let total = punto.down.saturating_add(punto.up);
        if !future && total > 0 && maximo.is_none_or(|(_, valor)| total > valor) {
            maximo = Some((indice, total));
        }
        serie.total_down = serie.total_down.saturating_add(punto.down);
        serie.total_up = serie.total_up.saturating_add(punto.up);
        serie.points.push(SeriesPoint {
            at: punto.at,
            bytes_down: punto.down,
            bytes_up: punto.up,
            gap,
            future,
        });
    }
    serie.max = maximo;
    serie
}

// ---------------------------------------------------------------------------
// «Más tráfico»: tops por sujeto y por clave
// ---------------------------------------------------------------------------

/// Suma total (bajada y subida) del sujeto en la ventana.
fn total_del_rango(
    conn: &Connection,
    subject: SubjectSel,
    ventana: &Ventana,
) -> Result<(u64, u64)> {
    let (subject_sql, device_id) = partes_de_sujeto(subject);
    total_de_tramos(conn, &ventana.tramos, subject_sql, device_id)
}

fn total_de_tramos(
    conn: &Connection,
    tramos: &[Tramo],
    subject: &str,
    device_id: i64,
) -> Result<(u64, u64)> {
    let mut down = 0u64;
    let mut up = 0u64;
    for tramo in tramos {
        let (condicion, parametros) = tramo.condicion();
        let sql = format!(
            "SELECT SUM(bytes_down), SUM(bytes_up)
               FROM {}
              WHERE {condicion} AND subject = ? AND device_id = ? AND dimension = 'total'",
            tramo.tabla.nombre()
        );
        let mut valores = parametros;
        valores.push(Value::Text(subject.to_string()));
        valores.push(Value::Integer(device_id));
        let mut sentencia = conn.prepare(&sql)?;
        let (parcial_down, parcial_up) = sentencia
            .query_row(params_from_iter(valores), |fila| {
                Ok((entero_u64(fila, 0)?, entero_u64(fila, 1)?))
            })?;
        down = down.saturating_add(parcial_down);
        up = up.saturating_add(parcial_up);
    }
    Ok((down, up))
}

/// Bytes totales de una clave de una dimensión en los tramos.
fn bytes_de_clave(
    conn: &Connection,
    tramos: &[Tramo],
    dimension: Dimension,
    clave: &str,
) -> Result<u64> {
    let mut bytes = 0u64;
    for tramo in tramos {
        let (condicion, parametros) = tramo.condicion();
        let sql = format!(
            "SELECT SUM(bytes_down), SUM(bytes_up)
               FROM {}
              WHERE {condicion} AND dimension = ? AND key = ? AND subject <> 'network'",
            tramo.tabla.nombre()
        );
        let mut valores = parametros;
        valores.push(Value::Text(dimension.as_str().to_string()));
        valores.push(Value::Text(clave.to_string()));
        let mut sentencia = conn.prepare(&sql)?;
        let (down, up) = sentencia.query_row(params_from_iter(valores), |fila| {
            Ok((entero_u64(fila, 0)?, entero_u64(fila, 1)?))
        })?;
        bytes = bytes.saturating_add(down).saturating_add(up);
    }
    Ok(bytes)
}

/// «Más tráfico» de la dimensión total: una fila por sujeto.
fn top_por_sujeto(
    conn: &Connection,
    subject: SubjectSel,
    ventana: &Ventana,
    etiquetas: &HashMap<i64, String>,
) -> Result<Vec<TopRow>> {
    let mut acumulados: HashMap<(String, i64), (u64, u64)> = HashMap::new();
    for tramo in &ventana.tramos {
        let (condicion, parametros) = tramo.condicion();
        let (filtro, valores) = match subject {
            SubjectSel::Network => (
                "subject IN ('device', 'host', 'other')".to_string(),
                parametros,
            ),
            SubjectSel::Host => ("subject = 'host'".to_string(), parametros),
            SubjectSel::Device(id) => {
                let mut valores = parametros;
                valores.push(Value::Integer(id));
                ("subject = 'device' AND device_id = ?".to_string(), valores)
            }
        };
        let sql = format!(
            "SELECT subject, device_id, SUM(bytes_down), SUM(bytes_up)
               FROM {}
              WHERE {condicion} AND dimension = 'total' AND {filtro}
              GROUP BY subject, device_id",
            tramo.tabla.nombre()
        );
        let mut sentencia = conn.prepare(&sql)?;
        let filas = sentencia.query_map(params_from_iter(valores), |fila| {
            let sujeto: String = fila.get(0)?;
            let id: i64 = fila.get(1)?;
            let down = entero_u64(fila, 2)?;
            let up = entero_u64(fila, 3)?;
            Ok((sujeto, id, down, up))
        })?;
        for fila in filas {
            let (sujeto, id, down, up) = fila?;
            let entrada = acumulados.entry((sujeto, id)).or_insert((0, 0));
            entrada.0 = entrada.0.saturating_add(down);
            entrada.1 = entrada.1.saturating_add(up);
        }
    }
    let mut filas = Vec::with_capacity(acumulados.len());
    for ((sujeto, id), (down, up)) in acumulados {
        let (key, label, device_id) = etiqueta_de_sujeto(&sujeto, id, etiquetas);
        filas.push(TopRow {
            key,
            label,
            subtitle: None,
            device_id,
            bytes_down: down,
            bytes_up: up,
            pct: 0.0,
            devices: if device_id.is_some() { 1 } else { 0 },
        });
    }
    Ok(filas)
}

/// «Más tráfico» de una dimensión distinta de total: una fila por clave.
fn top_por_clave(
    conn: &Connection,
    subject: SubjectSel,
    dimension: Dimension,
    ventana: &Ventana,
    etiquetas: &HashMap<i64, String>,
) -> Result<Vec<TopRow>> {
    let mut acumulados: HashMap<String, (u64, u64, u32)> = HashMap::new();
    for tramo in &ventana.tramos {
        let (condicion, parametros) = tramo.condicion();
        let filtro = match subject {
            SubjectSel::Network => "subject IN ('device', 'host', 'other')".to_string(),
            SubjectSel::Host => "subject = 'host'".to_string(),
            SubjectSel::Device(_) => "subject = 'device' AND device_id = ?".to_string(),
        };
        let sql = format!(
            "SELECT key, SUM(bytes_down), SUM(bytes_up),
                    COUNT(DISTINCT CASE WHEN subject = 'device' THEN device_id END)
               FROM {}
              WHERE {condicion} AND dimension = ? AND {filtro}
              GROUP BY key",
            tramo.tabla.nombre()
        );
        let mut valores = parametros;
        valores.push(Value::Text(dimension.as_str().to_string()));
        if let SubjectSel::Device(id) = subject {
            valores.push(Value::Integer(id));
        }
        let mut sentencia = conn.prepare(&sql)?;
        let filas = sentencia.query_map(params_from_iter(valores), |fila| {
            let clave: String = fila.get(0)?;
            let down = entero_u64(fila, 1)?;
            let up = entero_u64(fila, 2)?;
            let equipos: i64 = fila.get(3)?;
            Ok((clave, down, up, equipos))
        })?;
        for fila in filas {
            let (clave, down, up, equipos) = fila?;
            let entrada = acumulados.entry(clave).or_insert((0, 0, 0));
            entrada.0 = entrada.0.saturating_add(down);
            entrada.1 = entrada.1.saturating_add(up);
            entrada.2 = entrada.2.saturating_add(equipos.max(0) as u32);
        }
    }
    let mut filas = Vec::with_capacity(acumulados.len());
    for (clave, (down, up, equipos)) in acumulados {
        let (label, subtitle, device_id) = etiqueta_de_clave(dimension, &clave, etiquetas);
        filas.push(TopRow {
            key: clave,
            label,
            subtitle,
            device_id,
            bytes_down: down,
            bytes_up: up,
            pct: 0.0,
            devices: equipos,
        });
    }
    Ok(filas)
}

// ---------------------------------------------------------------------------
// «¿Quién lo usa?» de la ventana
// ---------------------------------------------------------------------------

/// Cuotas por equipo de una clave de dimensión en la ventana.
fn shares_de_clave(
    conn: &Connection,
    tramos: &[Tramo],
    dimension: Dimension,
    key: &str,
    etiquetas: &HashMap<i64, String>,
) -> Result<Vec<DeviceShare>> {
    let mut acumulados: HashMap<(String, i64), u64> = HashMap::new();
    for tramo in tramos {
        let (condicion, parametros) = tramo.condicion();
        let sql = format!(
            "SELECT subject, device_id, SUM(bytes_down), SUM(bytes_up)
               FROM {}
              WHERE {condicion} AND dimension = ? AND key = ?
              GROUP BY subject, device_id",
            tramo.tabla.nombre()
        );
        let mut valores = parametros;
        valores.push(Value::Text(dimension.as_str().to_string()));
        valores.push(Value::Text(key.to_string()));
        let mut sentencia = conn.prepare(&sql)?;
        let filas = sentencia.query_map(params_from_iter(valores), |fila| {
            let subject: String = fila.get(0)?;
            let device_id: i64 = fila.get(1)?;
            let down = entero_u64(fila, 2)?;
            let up = entero_u64(fila, 3)?;
            Ok((subject, device_id, down.saturating_add(up)))
        })?;
        for fila in filas {
            let (subject, device_id, bytes) = fila?;
            let entrada = acumulados.entry((subject, device_id)).or_insert(0);
            *entrada = entrada.saturating_add(bytes);
        }
    }
    let total: u64 = acumulados.values().copied().sum();
    let mut cuotas = Vec::new();
    for ((subject, device_id), bytes) in acumulados {
        if bytes == 0 {
            continue;
        }
        let (id, label) = match subject.as_str() {
            "device" => (device_id, etiqueta_conocida(etiquetas, device_id)),
            "host" => (DEVICE_ID_HOST, "[host]".to_string()),
            // El sujeto other no se puede atribuir a un equipo.
            _ => continue,
        };
        cuotas.push(DeviceShare {
            device_id: id,
            label,
            bytes,
            pct: porcentaje(bytes, total),
        });
    }
    cuotas.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.device_id.cmp(&b.device_id))
    });
    Ok(cuotas)
}

/// Cuotas por equipo de una fila de la dimensión total (un solo sujeto).
fn shares_de_sujeto(
    conn: &Connection,
    tramos: &[Tramo],
    key: &str,
    etiquetas: &HashMap<i64, String>,
) -> Result<Vec<DeviceShare>> {
    if key == "host" {
        let (down, up) = total_de_tramos(conn, tramos, "host", 0)?;
        let bytes = down.saturating_add(up);
        if bytes == 0 {
            return Ok(Vec::new());
        }
        return Ok(vec![DeviceShare {
            device_id: DEVICE_ID_HOST,
            label: "[host]".to_string(),
            bytes,
            pct: 100.0,
        }]);
    }
    let Ok(device_id) = key.parse::<i64>() else {
        return Ok(Vec::new());
    };
    let (down, up) = total_de_tramos(conn, tramos, "device", device_id)?;
    let bytes = down.saturating_add(up);
    if bytes == 0 {
        return Ok(Vec::new());
    }
    Ok(vec![DeviceShare {
        device_id,
        label: etiqueta_conocida(etiquetas, device_id),
        bytes,
        pct: 100.0,
    }])
}

// ---------------------------------------------------------------------------
// Línea de tiempo: eventos y sesiones
// ---------------------------------------------------------------------------

/// Extrae un dato de texto de los detalles JSON de un evento sin fallar.
fn detalle_texto(details: &str, clave: &str) -> Option<String> {
    let valor: serde_json::Value = serde_json::from_str(details).ok()?;
    match valor.get(clave)? {
        serde_json::Value::String(texto) => Some(texto.clone()),
        serde_json::Value::Number(numero) => Some(numero.to_string()),
        serde_json::Value::Bool(valor) => Some(valor.to_string()),
        _ => None,
    }
}

/// Indica si un detalle booleano de los detalles JSON es cierto.
fn detalle_booleano(details: &str, clave: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(details)
        .ok()
        .and_then(|valor| valor.get(clave).and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// Resumen «antes → después» de un cambio de identidad.
fn resumen_cambio(
    equipo: &str,
    etiqueta: &str,
    details: &str,
    defecto: impl FnOnce() -> String,
) -> String {
    match (
        detalle_texto(details, "before"),
        detalle_texto(details, "after"),
    ) {
        (Some(antes), Some(despues)) => format!("{equipo}: {etiqueta} {antes} → {despues}"),
        _ => defecto(),
    }
}

/// Compone el resumen en castellano de un evento de dispositivo.
fn resumen_de_evento(event_type: &str, details: &str, equipo: &str, at: i64) -> String {
    match event_type {
        "new" => format!("{equipo}: nuevo"),
        "disappeared" => {
            let visto = detalle_texto(details, "last_seen")
                .as_deref()
                .and_then(rfc_a_unix)
                .unwrap_or(at);
            format!(
                "{equipo}: desconectado (última vez {})",
                localtime::format_hora_local(visto)
            )
        }
        "reappeared" => format!("{equipo}: vuelve a estar en línea"),
        "ip_changed" => resumen_cambio(equipo, "IP", details, || format!("{equipo}: cambia la IP")),
        "hostname_changed" => resumen_cambio(equipo, "nombre", details, || {
            format!("{equipo}: cambia el nombre")
        }),
        "mac_changed" => resumen_cambio(equipo, "MAC", details, || {
            format!("{equipo}: cambia la MAC")
        }),
        "os_changed" => resumen_cambio(equipo, "SO", details, || format!("{equipo}: cambia el SO")),
        "type_changed" => resumen_cambio(equipo, "tipo", details, || {
            format!("{equipo}: cambia el tipo")
        }),
        "service_new" => {
            let puerto = detalle_texto(details, "port").unwrap_or_else(|| "?".to_string());
            let protocolo = detalle_texto(details, "protocol").unwrap_or_else(|| "tcp".to_string());
            let mut resumen = format!("{equipo}: abre {puerto}/{protocolo}");
            if let Some(servicio) =
                detalle_texto(details, "service").filter(|servicio| !servicio.is_empty())
            {
                resumen.push_str(&format!(" ({servicio})"));
            }
            if detalle_booleano(details, "reopened") {
                resumen.push_str(" (reabierto)");
            }
            resumen
        }
        "service_gone" => {
            let puerto = detalle_texto(details, "port").unwrap_or_else(|| "?".to_string());
            let protocolo = detalle_texto(details, "protocol").unwrap_or_else(|| "tcp".to_string());
            format!("{equipo}: cierra {puerto}/{protocolo}")
        }
        otro => format!("{equipo}: {otro}"),
    }
}

/// Construye el elemento de línea de tiempo de un evento persistido.
fn item_de_evento(
    device_id: i64,
    event_type: &str,
    details: &str,
    created_at: &str,
    equipo: &str,
) -> Option<TimelineItem> {
    let at_unix = rfc_a_unix(created_at)?;
    Some(TimelineItem {
        at: created_at.to_string(),
        at_unix,
        kind: TimelineKind::Event,
        device_id: Some(device_id),
        device_label: Some(equipo.to_string()),
        event_type: event_type.to_string(),
        summary: resumen_de_evento(event_type, details, equipo, at_unix),
        session_reason: None,
    })
}

/// Elementos de una sesión de Almenara: arranque y cierre, si caen en el rango.
fn items_de_sesion(inicio: &str, fin: Option<&str>, motivo: Option<&str>) -> Vec<TimelineItem> {
    let mut items = Vec::new();
    if let Some(inicio_unix) = rfc_a_unix(inicio) {
        items.push(TimelineItem {
            at: inicio.to_string(),
            at_unix: inicio_unix,
            kind: TimelineKind::Session,
            device_id: None,
            device_label: None,
            event_type: "session".to_string(),
            summary: "Almenara arrancada".to_string(),
            session_reason: None,
        });
    }
    if let Some(fin) = fin {
        if let Some(fin_unix) = rfc_a_unix(fin) {
            let resumen = match motivo {
                Some("interrupted") => "Almenara interrumpida",
                _ => "Almenara cerrada",
            };
            items.push(TimelineItem {
                at: fin.to_string(),
                at_unix: fin_unix,
                kind: TimelineKind::Session,
                device_id: None,
                device_label: None,
                event_type: "session".to_string(),
                summary: resumen.to_string(),
                session_reason: motivo.map(str::to_string),
            });
        }
    }
    items
}

// ---------------------------------------------------------------------------
// Presencia
// ---------------------------------------------------------------------------

/// Evento de presencia ya interpretado para el cálculo de tramos.
#[derive(Debug, Clone, Copy)]
struct EventoPresencia {
    at: i64,
    cambio: i64,
    estado: PresenceState,
}

/// Fecha de alta del equipo en DEVICES, en segundos Unix UTC.
fn primera_vez_visto(conn: &Connection, device_id: i64) -> Result<Option<i64>> {
    let fecha: Option<String> = conn
        .query_row(
            "SELECT first_seen FROM DEVICES WHERE id = ?1",
            params![device_id],
            |fila| fila.get(0),
        )
        .map(Some)
        .or_else(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            otro => Err(otro),
        })?;
    Ok(fecha.as_deref().and_then(rfc_a_unix))
}

/// Eventos de presencia (new, disappeared y reappeared) del equipo.
fn eventos_de_presencia(conn: &Connection, device_id: i64) -> Result<Vec<EventoPresencia>> {
    let mut sentencia = conn.prepare(
        "SELECT event_type, details, created_at
           FROM DEVICE_EVENTS
          WHERE device_id = ?1
            AND event_type IN ('new', 'disappeared', 'reappeared')
          ORDER BY created_at, id",
    )?;
    let filas = sentencia.query_map(params![device_id], |fila| {
        let event_type: String = fila.get(0)?;
        let details: String = fila.get(1)?;
        let created_at: String = fila.get(2)?;
        Ok((event_type, details, created_at))
    })?;
    let mut eventos = Vec::new();
    for fila in filas {
        let (event_type, details, created_at) = fila?;
        let Some(at) = rfc_a_unix(&created_at) else {
            continue;
        };
        match event_type.as_str() {
            "disappeared" => {
                let cambio = detalle_texto(&details, "last_seen")
                    .as_deref()
                    .and_then(rfc_a_unix)
                    .unwrap_or(at);
                eventos.push(EventoPresencia {
                    at,
                    cambio,
                    estado: PresenceState::Absent,
                });
            }
            "new" | "reappeared" => eventos.push(EventoPresencia {
                at,
                cambio: at,
                estado: PresenceState::Present,
            }),
            _ => {}
        }
    }
    Ok(eventos)
}

/// Sesiones que solapan [desde, hasta), recortadas a ese intervalo.
fn sesiones_solapadas(conn: &Connection, desde: i64, hasta: i64) -> Result<Vec<(i64, i64)>> {
    let mut sentencia = conn.prepare(
        "SELECT started_at, ended_at
           FROM APP_SESSIONS
          WHERE started_at < ?1
            AND (ended_at IS NULL OR ended_at > ?2)
          ORDER BY started_at",
    )?;
    let filas = sentencia.query_map(params![unix_a_rfc(hasta), unix_a_rfc(desde)], |fila| {
        let inicio: String = fila.get(0)?;
        let fin: Option<String> = fila.get(1)?;
        Ok((inicio, fin))
    })?;
    let mut sesiones = Vec::new();
    for fila in filas {
        let (inicio, fin) = fila?;
        let Some(inicio) = rfc_a_unix(&inicio) else {
            continue;
        };
        let fin = fin
            .as_deref()
            .and_then(rfc_a_unix)
            .unwrap_or(hasta)
            .min(hasta);
        let inicio = inicio.max(desde);
        if inicio >= fin {
            continue;
        }
        sesiones.push((inicio, fin));
    }
    Ok(sesiones)
}

/// Estado del equipo justo antes del arranque de una sesión.
///
/// Devuelve None si el equipo no existía todavía o si no hay ningún evento de
/// presencia anterior: en ese caso no se inventa ni «presente» ni «ausente».
fn estado_previo(
    eventos: &[EventoPresencia],
    inicio_sesion: i64,
    primera_vez: i64,
) -> Option<PresenceState> {
    if primera_vez > inicio_sesion {
        return None;
    }
    eventos
        .iter()
        .rfind(|evento| evento.at < inicio_sesion)
        .map(|evento| evento.estado)
}

/// Rellena los huecos con «sin datos» y fusiona tramos contiguos del mismo estado.
fn rellenar_huecos(mut tramos: Vec<PresenceSpan>, desde: i64, hasta: i64) -> Vec<PresenceSpan> {
    tramos.retain(|tramo| tramo.end > desde && tramo.start < hasta);
    tramos.sort_by_key(|tramo| tramo.start);
    let mut resultado: Vec<PresenceSpan> = Vec::new();
    let mut cursor = desde;
    for tramo in tramos {
        let inicio = tramo.start.max(cursor);
        let fin = tramo.end.min(hasta);
        if inicio >= fin {
            continue;
        }
        if inicio > cursor {
            resultado.push(PresenceSpan {
                start: cursor,
                end: inicio,
                state: PresenceState::NoData,
            });
        }
        match resultado.last_mut() {
            Some(anterior) if anterior.state == tramo.state && anterior.end == inicio => {
                anterior.end = fin;
            }
            _ => resultado.push(PresenceSpan {
                start: inicio,
                end: fin,
                state: tramo.state,
            }),
        }
        cursor = fin;
    }
    if cursor < hasta {
        resultado.push(PresenceSpan {
            start: cursor,
            end: hasta,
            state: PresenceState::NoData,
        });
    }
    resultado
}

// ---------------------------------------------------------------------------
// Pruebas
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::migrations;
    use rusqlite::Connection as SqliteConnection;

    /// Instante de referencia alineado a la hora y al tramo de 30 min.
    const T0: i64 = 1_800_000_000;

    fn conexion() -> SqliteConnection {
        let mut conn = SqliteConnection::open_in_memory().expect("SQLite en memoria");
        migrations::apply_all(&mut conn).expect("aplicar migraciones");
        conn
    }

    fn interfaz(conn: &SqliteConnection) -> i64 {
        conn.execute(
            "INSERT INTO INTERFACES (name, mac, ipv4, netmask, gateway, is_up, last_seen)
             VALUES ('eth0', NULL, '192.168.1.2', NULL, NULL, 1, ?1)",
            params![unix_a_rfc(T0)],
        )
        .expect("interfaz");
        conn.query_row(
            "SELECT id FROM INTERFACES WHERE name = 'eth0'",
            [],
            |fila| fila.get(0),
        )
        .expect("id de interfaz")
    }

    fn equipo(
        conn: &SqliteConnection,
        interface_id: i64,
        mac: &str,
        ip: &str,
        alias: Option<&str>,
        hostname: Option<&str>,
        first_seen: i64,
    ) -> i64 {
        conn.execute(
            "INSERT INTO DEVICES
                 (mac, ip, hostname, vendor, interface_id, device_type, is_online,
                  first_seen, last_seen, alias)
             VALUES (?1, ?2, ?3, NULL, ?4, 'unknown', 1, ?5, ?5, ?6)",
            params![
                mac,
                ip,
                hostname,
                interface_id,
                unix_a_rfc(first_seen),
                alias
            ],
        )
        .expect("equipo");
        conn.query_row(
            "SELECT id FROM DEVICES WHERE mac = ?1",
            params![mac],
            |fila| fila.get(0),
        )
        .expect("id de equipo")
    }

    #[allow(clippy::too_many_arguments)]
    fn rollup(
        conn: &SqliteConnection,
        tabla: Tabla,
        bucket: i64,
        subject: &str,
        device_id: i64,
        dimension: &str,
        key: &str,
        down: i64,
        up: i64,
        connections: i64,
    ) {
        conn.execute(
            &format!(
                "INSERT INTO {} (bucket, subject, device_id, dimension, key,
                                 bytes_down, bytes_up, connections)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                tabla.nombre()
            ),
            params![
                bucket,
                subject,
                device_id,
                dimension,
                key,
                down,
                up,
                connections
            ],
        )
        .expect("fila de rollup");
    }

    fn sesion(conn: &SqliteConnection, inicio: i64, fin: Option<i64>, capture: bool) {
        conn.execute(
            "INSERT INTO APP_SESSIONS
                 (started_at, ended_at, last_beat, end_reason, mode, capture,
                  passive_only, version)
             VALUES (?1, ?2, ?3, ?4, 'privileged', ?5, 0, '0.5.0')",
            params![
                unix_a_rfc(inicio),
                fin.map(unix_a_rfc),
                unix_a_rfc(fin.unwrap_or(inicio)),
                fin.map(|_| "quit"),
                capture
            ],
        )
        .expect("sesión");
    }

    fn evento(conn: &SqliteConnection, device_id: i64, event_type: &str, details: &str, at: i64) {
        conn.execute(
            "INSERT INTO DEVICE_EVENTS (device_id, event_type, details, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![device_id, event_type, details, unix_a_rfc(at)],
        )
        .expect("evento");
    }

    #[test]
    fn serie_de_24h_con_huecos_y_sin_puntos_futuros() {
        let conn = conexion();
        let ahora = T0;
        let desde = ahora - 47 * 1800;
        for i in 0..48 {
            if i == 2 {
                continue;
            }
            let bucket = desde + i * 1800;
            rollup(
                &conn,
                Tabla::Minuto,
                bucket,
                "network",
                0,
                "total",
                "",
                (i + 1) * 10,
                0,
                1,
            );
        }
        sesion(&conn, desde, Some(desde + 2 * 1800), true);
        let serie =
            Queries::series(&conn, SubjectSel::Network, Range::Hours24, ahora).expect("serie");
        assert_eq!(serie.points.len(), 48);
        assert_eq!(serie.range, Range::Hours24);
        assert!(!serie.points[0].gap, "el primer punto está cubierto");
        assert!(!serie.points[1].gap);
        assert!(serie.points[2].gap, "el tercer punto es un hueco");
        assert_eq!(serie.points[2].bytes_down, 0);
        assert!(serie.points[3].gap);
        assert!(
            !serie.points.iter().any(|punto| punto.future),
            "con los cubos cerrados no hay puntos futuros"
        );
        assert_eq!(
            serie.total_down,
            (1..=48).filter(|i| *i != 3).sum::<i64>() as u64 * 10
        );
        assert_eq!(serie.max, Some((47, 480)), "el máximo es el último punto");
        assert_eq!(serie.first_future(), serie.points.len());
    }

    #[test]
    fn serie_de_7dias_suma_horas_y_minutos_del_ultimo_punto() {
        let conn = conexion();
        let ahora = T0 + 600;
        let fin = ahora - ahora.rem_euclid(10_800);
        let desde = fin - 55 * 10_800;
        let hora_actual = ahora - ahora.rem_euclid(3600);
        let hora_penultima = fin - 10_800;
        rollup(
            &conn,
            Tabla::Hora,
            hora_penultima,
            "host",
            0,
            "total",
            "",
            1_000,
            100,
            3,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            hora_actual,
            "host",
            0,
            "total",
            "",
            200,
            20,
            1,
        );
        sesion(&conn, desde, Some(ahora), true);
        let serie = Queries::series(&conn, SubjectSel::Host, Range::Days7, ahora).expect("serie");
        assert_eq!(serie.points.len(), 56);
        assert_eq!(serie.points[54].bytes_down, 1_000);
        assert_eq!(serie.points[55].bytes_down, 200);
        assert_eq!(serie.total_down, 1_200);
        assert_eq!(serie.total_up, 120);
        assert!(!serie.points[55].gap);
    }

    #[test]
    fn serie_de_30_dias_usa_dias_cerrados_y_horas_de_hoy() {
        let conn = conexion();
        let ahora = T0 + 3_600;
        let hoy = LocalDay::from_unix(ahora);
        let ayer = hoy.sumar_dias(-1);
        rollup(
            &conn,
            Tabla::Dia,
            ayer.aaaammdd(),
            "device",
            1,
            "total",
            "",
            5_000,
            500,
            2,
        );
        // La hora EN CURSO no está cerrada: la serie suma la hora anterior.
        let hora_cerrada_hoy = localtime::hour_start(ahora) - 3600;
        rollup(
            &conn,
            Tabla::Hora,
            hora_cerrada_hoy,
            "device",
            1,
            "total",
            "",
            300,
            30,
            1,
        );
        sesion(&conn, ahora - 30 * 86_400, Some(ahora), true);
        let serie =
            Queries::series(&conn, SubjectSel::Device(1), Range::Days30, ahora).expect("serie");
        assert_eq!(serie.points.len(), 30);
        assert_eq!(serie.points[28].bytes_down, 5_000);
        assert_eq!(
            serie.points[29].bytes_down, 300,
            "las horas de hoy van al último punto"
        );
        assert_eq!(serie.total_down, 5_300);
        assert_eq!(serie.max, Some((28, 5_500)));
    }

    #[test]
    fn serie_de_un_ano_tiene_53_semanas_locales() {
        let conn = conexion();
        let ahora = T0;
        let semana = LocalDay::from_unix(localtime::week_start(ahora));
        let primera = semana.sumar_dias(-52 * 7);
        let hoy = LocalDay::from_unix(ahora);
        let dia_inicial = primera.sumar_dias(2);
        rollup(
            &conn,
            Tabla::Dia,
            dia_inicial.aaaammdd(),
            "network",
            0,
            "total",
            "",
            900,
            0,
            1,
        );
        let lunes_actual = semana;
        let mut esperado = 900u64;
        if lunes_actual < hoy {
            rollup(
                &conn,
                Tabla::Dia,
                lunes_actual.aaaammdd(),
                "network",
                0,
                "total",
                "",
                100,
                0,
                1,
            );
            esperado += 100;
        }
        sesion(&conn, ahora - 366 * 86_400, Some(ahora), true);
        let serie =
            Queries::series(&conn, SubjectSel::Network, Range::Year1, ahora).expect("serie");
        assert_eq!(serie.points.len(), 53);
        assert_eq!(serie.points[0].bytes_down, 900);
        if lunes_actual < hoy {
            assert_eq!(serie.points[52].bytes_down, 100);
        }
        assert_eq!(serie.total_down, esperado);
    }

    #[test]
    fn ejecutar_despacha_series_cobertura_ultimo_evento_y_estadisticas() {
        let conn = conexion();
        sesion(&conn, T0 - 3_600, Some(T0), true);
        let ahora = T0;
        let serie = ejecutar(
            &conn,
            &HistoryQuery::Series {
                subject: SubjectSel::Network,
                range: Range::Hours24,
                now: ahora,
            },
        )
        .expect("ejecutar serie");
        match serie {
            HistoryResponse::Series(serie) => assert_eq!(serie.points.len(), 48),
            otra => panic!("respuesta inesperada: {otra:?}"),
        }
        let cobertura = ejecutar(
            &conn,
            &HistoryQuery::Coverage {
                range: Range::Hours24,
                now: ahora,
            },
        )
        .expect("ejecutar cobertura");
        match cobertura {
            HistoryResponse::Coverage(huecos) => {
                assert_eq!(huecos.len(), 1, "solo la última hora está cubierta");
                assert_eq!(huecos[0].dur(), 23 * 3_600);
            }
            otra => panic!("respuesta inesperada: {otra:?}"),
        }
        let ultimo = ejecutar(&conn, &HistoryQuery::LastEvent).expect("ejecutar último evento");
        assert!(matches!(ultimo, HistoryResponse::LastEvent(None)));
        let stats = ejecutar(&conn, &HistoryQuery::DbStats).expect("ejecutar estadísticas");
        match stats {
            HistoryResponse::DbStats(stats) => assert!(stats.db_bytes > 0),
            otra => panic!("respuesta inesperada: {otra:?}"),
        }
    }

    #[test]
    fn top_de_la_red_suma_sujetos_y_resuelve_destinos_lan() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let portatil = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:01",
            "192.168.1.50",
            Some("portatil"),
            None,
            T0 - 10_000,
        );
        let nas = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:02",
            "192.168.1.60",
            None,
            Some("nas"),
            T0 - 10_000,
        );
        let bucket = T0 - 60;
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            portatil,
            "total",
            "",
            100,
            10,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            nas,
            "total",
            "",
            50,
            5,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "host",
            0,
            "total",
            "",
            25,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "other",
            0,
            "total",
            "",
            5,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "network",
            0,
            "total",
            "",
            180,
            15,
            3,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            portatil,
            "app",
            "youtube",
            60,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            nas,
            "app",
            "youtube",
            20,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "host",
            0,
            "app",
            "youtube",
            10,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            portatil,
            "app",
            "netflix",
            40,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            portatil,
            "destination",
            &format!("lan:{nas}"),
            30,
            0,
            1,
        );
        let totales = Queries::top(
            &conn,
            SubjectSel::Network,
            Dimension::Total,
            Range::Hours24,
            10,
            T0,
        )
        .expect("top de totales");
        assert_eq!(totales.len(), 4, "tres sujetos con tráfico y la red no");
        assert_eq!(totales[0].label, "portatil");
        assert_eq!(totales[0].device_id, Some(portatil));
        assert!((totales[0].pct - 100.0 * 110.0 / 195.0).abs() < 0.01);
        assert!(totales.iter().all(|fila| fila.key != "network"));
        let apps = Queries::top(
            &conn,
            SubjectSel::Network,
            Dimension::App,
            Range::Hours24,
            10,
            T0,
        )
        .expect("top de apps");
        let youtube = apps
            .iter()
            .find(|fila| fila.key == "youtube")
            .expect("fila de youtube");
        assert_eq!(youtube.total(), 90, "la red no duplica el tráfico LAN↔LAN");
        assert_eq!(youtube.devices, 2, "portátil y NAS usan youtube");
        assert_eq!(apps[0].key, "youtube");
        let destinos = Queries::top(
            &conn,
            SubjectSel::Device(portatil),
            Dimension::Destination,
            Range::Hours24,
            10,
            T0,
        )
        .expect("top de destinos del portátil");
        assert_eq!(destinos.len(), 1);
        assert_eq!(destinos[0].label, "nas");
        assert_eq!(destinos[0].subtitle.as_deref(), Some("red local"));
        assert_eq!(destinos[0].device_id, Some(nas));
    }

    #[test]
    fn ranking_de_una_hora_cuadra_con_los_minutos() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let id = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:03",
            "192.168.1.70",
            Some("tv"),
            None,
            T0 - 10_000,
        );
        let ahora_min = T0;
        for i in 0..10 {
            rollup(
                &conn,
                Tabla::Minuto,
                ahora_min - 3600 + i * 60,
                "device",
                id,
                "total",
                "",
                10,
                1,
                1,
            );
            rollup(
                &conn,
                Tabla::Minuto,
                ahora_min - 3600 + i * 60,
                "device",
                id,
                "app",
                "youtube",
                10,
                1,
                1,
            );
            rollup(
                &conn,
                Tabla::Minuto,
                ahora_min - 3600 + i * 60,
                "network",
                0,
                "total",
                "",
                10,
                1,
                1,
            );
        }
        rollup(
            &conn,
            Tabla::Minuto,
            ahora_min - 600,
            "device",
            id,
            "app",
            KEY_UNIDENTIFIED,
            30,
            0,
            0,
        );
        sesion(&conn, ahora_min - 3600, Some(ahora_min), true);
        let ranking =
            Queries::window_ranking(&conn, Dimension::App, HistWindow::OneHour, ahora_min)
                .expect("ranking de 1 h");
        assert_eq!(ranking.rows.len(), 2);
        assert_eq!(ranking.rows[0].key, "youtube");
        assert_eq!(ranking.rows[0].bytes_down, 100);
        assert_eq!(ranking.rows[0].devices, 1);
        assert_eq!(ranking.total_down, 100);
        assert_eq!(ranking.closed_until, ahora_min - 60);
        assert_eq!(ranking.gap_seconds, 0, "la sesión cubre la hora entera");
        assert!(ranking.unidentified_pct > 0.0);
    }

    #[test]
    fn ranking_de_24h_usa_horas_cerradas_y_minutos_de_la_hora() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let id = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:04",
            "192.168.1.71",
            Some("movil"),
            None,
            T0 - 10_000,
        );
        let ahora_min = T0 + 120;
        let hora = ahora_min - ahora_min.rem_euclid(3600);
        rollup(
            &conn,
            Tabla::Hora,
            hora - 3600,
            "device",
            id,
            "total",
            "",
            500,
            50,
            2,
        );
        rollup(
            &conn,
            Tabla::Hora,
            hora - 3600,
            "network",
            0,
            "total",
            "",
            500,
            50,
            2,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            hora + 60,
            "device",
            id,
            "total",
            "",
            100,
            10,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            hora + 60,
            "network",
            0,
            "total",
            "",
            100,
            10,
            1,
        );
        sesion(&conn, hora - 24 * 3600, Some(ahora_min), true);
        let ranking =
            Queries::window_ranking(&conn, Dimension::Total, HistWindow::Day24, ahora_min)
                .expect("ranking de 24 h");
        assert_eq!(ranking.rows.len(), 1);
        assert_eq!(ranking.rows[0].key, id.to_string());
        assert_eq!(ranking.rows[0].label, "movil");
        assert_eq!(ranking.rows[0].total(), 660);
        assert_eq!(ranking.total_down, 600);
        assert_eq!(ranking.total_up, 60);
    }

    #[test]
    fn quien_lo_usa_reparte_por_equipo() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let uno = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:05",
            "192.168.1.72",
            Some("uno"),
            None,
            T0 - 10_000,
        );
        let dos = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:06",
            "192.168.1.73",
            Some("dos"),
            None,
            T0 - 10_000,
        );
        let bucket = T0 - 60;
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            uno,
            "app",
            "youtube",
            75,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Minuto,
            bucket,
            "device",
            dos,
            "app",
            "youtube",
            25,
            0,
            1,
        );
        let cuotas = Queries::who_uses(&conn, Dimension::App, "youtube", HistWindow::OneHour, T0)
            .expect("quién lo usa");
        assert_eq!(cuotas.len(), 2);
        assert_eq!(cuotas[0].device_id, uno);
        assert_eq!(cuotas[0].label, "uno");
        assert_eq!(cuotas[0].bytes, 75);
        assert_eq!(cuotas[0].pct, 75.0);
        assert_eq!(cuotas[1].device_id, dos);
        assert_eq!(cuotas[1].pct, 25.0);
    }

    #[test]
    fn timeline_mezcla_eventos_y_sesiones_con_filtro() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let nas = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:07",
            "192.168.1.80",
            Some("nas"),
            None,
            T0 - 100_000,
        );
        evento(&conn, nas, "new", "{}", T0 - 90_000);
        evento(
            &conn,
            nas,
            "disappeared",
            &format!(r#"{{"last_seen":"{}"}}"#, unix_a_rfc(T0 - 3_600)),
            T0 - 1_800,
        );
        evento(
            &conn,
            nas,
            "service_new",
            r#"{"port":445,"protocol":"tcp","service":"microsoft-ds","reopened":true}"#,
            T0 - 1_500,
        );
        evento(
            &conn,
            nas,
            "service_gone",
            r#"{"port":445,"protocol":"tcp","service":"microsoft-ds"}"#,
            T0 - 1_200,
        );
        evento(
            &conn,
            nas,
            "reappeared",
            r#"{"away_since":"2027-01-01T00:00:00Z","away_s":60}"#,
            T0 - 900,
        );
        sesion(&conn, T0 - 7_200, Some(T0 - 60), true);
        let todos = Queries::timeline(&conn, EventFilter::All, Range::Hours24, Page::default(), T0)
            .expect("línea de tiempo");
        // El evento new (T0-90 000) queda fuera de las últimas 24 h: entran 4
        // eventos y los 2 elementos de la sesión (arranque y cierre).
        assert_eq!(todos.len(), 6, "4 eventos en rango y 2 de la sesión");
        assert_eq!(todos[0].at_unix, T0 - 60, "más recientes primero");
        assert!(todos[0].summary.contains("Almenara cerrada"));
        let servicios = Queries::timeline(
            &conn,
            EventFilter::Services,
            Range::Hours24,
            Page::default(),
            T0,
        )
        .expect("filtro de servicios");
        assert_eq!(servicios.len(), 2);
        assert!(servicios
            .iter()
            .all(|item| item.kind == TimelineKind::Event));
        assert!(servicios
            .iter()
            .any(|item| item.summary == "nas: abre 445/tcp (microsoft-ds) (reabierto)"));
        assert!(servicios
            .iter()
            .any(|item| item.summary == "nas: cierra 445/tcp"));
        let almenara = Queries::timeline(
            &conn,
            EventFilter::Almanara,
            Range::Hours24,
            Page::default(),
            T0,
        )
        .expect("filtro de Almenara");
        assert_eq!(almenara.len(), 2);
        assert!(almenara
            .iter()
            .any(|item| item.summary == "Almenara arrancada"));
        let pagina = Queries::timeline(
            &conn,
            EventFilter::All,
            Range::Hours24,
            Page {
                limit: 2,
                offset: 1,
            },
            T0,
        )
        .expect("página");
        assert_eq!(pagina.len(), 2);
        assert_eq!(pagina[0].at_unix, T0 - 900);
        assert_eq!(
            pagina[1].at_unix,
            T0 - 1_200,
            "el orden se conserva al paginar"
        );
        let desaparecido = Queries::timeline(
            &conn,
            EventFilter::Presence,
            Range::Hours24,
            Page::default(),
            T0,
        )
        .expect("eventos de presencia");
        assert!(desaparecido
            .iter()
            .any(|item| item.summary.starts_with("nas: desconectado (última vez")));
    }

    #[test]
    fn presencia_con_ida_y_vuelta_y_huecos_sin_datos() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let movil = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:08",
            "192.168.1.90",
            Some("movil"),
            None,
            T0,
        );
        evento(&conn, movil, "new", "{}", T0);
        evento(
            &conn,
            movil,
            "disappeared",
            &format!(r#"{{"last_seen":"{}"}}"#, unix_a_rfc(T0 + 8 * 3_600 - 60)),
            T0 + 8 * 3_600,
        );
        evento(
            &conn,
            movil,
            "reappeared",
            r#"{"away_s":37800}"#,
            T0 + 18 * 3_600 + 1_800,
        );
        sesion(&conn, T0, Some(T0 + 24 * 3_600), true);
        let tramos =
            Queries::presence(&conn, movil, Range::Hours24, T0 + 24 * 3_600).expect("presencia");
        assert_eq!(tramos.first().map(|tramo| tramo.start), Some(T0));
        assert_eq!(tramos.last().map(|tramo| tramo.end), Some(T0 + 24 * 3_600));
        assert_eq!(tramos[0].state, PresenceState::Present);
        let ausente = tramos
            .iter()
            .find(|tramo| tramo.state == PresenceState::Absent)
            .expect("tramo ausente");
        assert_eq!(ausente.start, T0 + 8 * 3_600 - 60);
        assert_eq!(ausente.end, T0 + 18 * 3_600 + 1_800);
        assert_eq!(
            tramos.last().map(|tramo| tramo.state),
            Some(PresenceState::Present)
        );
        let tramos = Queries::presence(&conn, movil, Range::Days7, T0 + 24 * 3_600)
            .expect("presencia de 7 días");
        let sin_datos = tramos
            .iter()
            .filter(|tramo| tramo.state == PresenceState::NoData)
            .map(|tramo| tramo.end - tramo.start)
            .sum::<i64>();
        assert_eq!(sin_datos, 6 * 86_400, "los seis días previos son sin datos");
    }

    #[test]
    fn presencia_de_equipo_que_se_fue_con_almenara_cerrada() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let equipo_id = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:09",
            "192.168.1.91",
            Some("impresora"),
            None,
            T0 - 86_400,
        );
        evento(&conn, equipo_id, "new", "{}", T0 - 86_400);
        sesion(&conn, T0 - 86_400, Some(T0 - 3_600), true);
        sesion(&conn, T0, None, true);
        evento(
            &conn,
            equipo_id,
            "disappeared",
            &format!(r#"{{"last_seen":"{}"}}"#, unix_a_rfc(T0 - 5_000)),
            T0 + 120,
        );
        let tramos =
            Queries::presence(&conn, equipo_id, Range::Hours24, T0 + 3_600).expect("presencia");
        let desde_sesion = tramos
            .iter()
            .find(|tramo| tramo.start >= T0)
            .expect("tramo de la sesión en curso");
        assert_eq!(
            desde_sesion.state,
            PresenceState::Absent,
            "se marca ausente desde el inicio de la sesión"
        );
        assert_eq!(desde_sesion.start, T0);
    }

    #[test]
    fn inventario_con_puertos_abiertos_y_cerrados() {
        let conn = conexion();
        let interface_id = interfaz(&conn);
        let id = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:0a",
            "192.168.1.92",
            Some("nas"),
            None,
            T0 - 100_000,
        );
        conn.execute(
            "INSERT INTO DEVICE_SEEN (device_id, kind, key, first_seen, last_seen)
             VALUES (?1, 'app', 'youtube', ?2, ?3), (?1, 'app', 'netflix', ?2, ?3),
                    (?1, 'country', 'US', ?2, ?3), (?1, 'ja4', 't13d', ?2, ?3)",
            params![id, unix_a_rfc(T0 - 86_400), unix_a_rfc(T0)],
        )
        .expect("inventario");
        conn.execute(
            "INSERT INTO DEVICE_SERVICES
                 (device_id, port, protocol, service, banner, first_seen, last_seen)
             VALUES (?1, 445, 'tcp', 'microsoft-ds', NULL, ?2, ?3),
                    (?1, 22, 'tcp', 'ssh', NULL, ?2, ?3),
                    (?1, 443, 'tcp', 'https', NULL, ?2, ?3)",
            params![id, unix_a_rfc(T0 - 200_000), unix_a_rfc(T0)],
        )
        .expect("servicios");
        // 445 se cerró en el último evento; 443 se cerró y se reabrió; 22 no tiene eventos.
        evento(
            &conn,
            id,
            "service_new",
            r#"{"port":445,"protocol":"tcp","service":"microsoft-ds"}"#,
            T0 - 2_000,
        );
        evento(
            &conn,
            id,
            "service_gone",
            r#"{"port":445,"protocol":"tcp","service":"microsoft-ds"}"#,
            T0 - 1_000,
        );
        evento(
            &conn,
            id,
            "service_gone",
            r#"{"port":443,"protocol":"tcp","service":"https"}"#,
            T0 - 2_000,
        );
        evento(
            &conn,
            id,
            "service_new",
            r#"{"port":443,"protocol":"tcp","service":"https","reopened":true}"#,
            T0 - 1_000,
        );
        let inventario = Queries::inventory(&conn, id).expect("inventario");
        assert_eq!(inventario.apps.len(), 2);
        assert_eq!(inventario.countries.len(), 1);
        assert_eq!(inventario.ja4.len(), 1);
        assert_eq!(inventario.apps[0].label, inventario.apps[0].key);
        assert_eq!(
            inventario.ports.len(),
            2,
            "445 está cerrado y no se muestra"
        );
        assert_eq!(inventario.ports[0].port, 22, "ordenado por puerto");
        assert_eq!(inventario.ports[1].port, 443);
        assert_eq!(
            inventario.since.as_deref(),
            Some(unix_a_rfc(T0 - 200_000).as_str()),
            "el inicio es el primer first_seen de inventario y puertos"
        );
    }

    #[test]
    fn cobertura_solo_cuenta_sesiones_con_captura() {
        let conn = conexion();
        sesion(&conn, T0 - 24 * 3_600, Some(T0 - 12 * 3_600), true);
        sesion(&conn, T0 - 12 * 3_600, Some(T0 - 6 * 3_600), false);
        sesion(&conn, T0 - 6 * 3_600, None, true);
        let huecos = Queries::coverage(&conn, Range::Hours24, T0).expect("cobertura");
        assert_eq!(huecos.len(), 1);
        assert_eq!(huecos[0].start, T0 - 12 * 3_600);
        assert_eq!(huecos[0].end, T0 - 6 * 3_600);
        assert_eq!(huecos[0].dur(), 6 * 3_600);
    }

    #[test]
    fn ultimo_evento_sin_sesiones() {
        let conn = conexion();
        assert!(Queries::last_event(&conn).expect("sin eventos").is_none());
        let interface_id = interfaz(&conn);
        let id = equipo(
            &conn,
            interface_id,
            "aa:bb:cc:dd:ee:0b",
            "192.168.1.93",
            Some("tv"),
            None,
            T0 - 10_000,
        );
        evento(&conn, id, "new", "{}", T0 - 5_000);
        sesion(&conn, T0 - 3_600, Some(T0), true);
        let ultimo = Queries::last_event(&conn)
            .expect("último evento")
            .expect("hay evento");
        assert_eq!(ultimo.at_unix, T0 - 5_000);
        assert_eq!(ultimo.summary, "tv: nuevo");
        assert_eq!(ultimo.device_label.as_deref(), Some("tv"));
    }

    #[test]
    fn estadisticas_de_la_base_de_datos() {
        let conn = conexion();
        let hoy = LocalDay::from_ymd(2026, 11, 11).expect("fecha");
        let dia = hoy.sumar_dias(-730);
        rollup(
            &conn,
            Tabla::Dia,
            dia.aaaammdd(),
            "network",
            0,
            "total",
            "",
            10,
            0,
            1,
        );
        rollup(
            &conn,
            Tabla::Hora,
            T0 - 3_600,
            "network",
            0,
            "total",
            "",
            5,
            0,
            1,
        );
        sesion(&conn, localtime::now_unix() - 86_400, None, true);
        let stats = Queries::db_stats(&conn, Path::new(":memory:")).expect("estadísticas");
        assert!(stats.db_bytes > 0);
        assert_eq!(stats.wal_bytes, 0, "una BD en memoria no tiene WAL");
        assert_eq!(
            stats.data_since.as_deref(),
            Some(unix_a_rfc(dia.limits().0).as_str())
        );
        assert!(
            stats.coverage_30d_pct > 0.0 && stats.coverage_30d_pct < 100.0,
            "un día de sesión sobre treinta"
        );
    }
}
