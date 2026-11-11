//! DAO del aprendizaje de lo nuevo por sujeto (ALERT_LEARNING, §7.3).
//!
//! Cada equipo y el propio equipo tienen una fila con el día local desde el que
//! cuentan sus días (su alta o la fecha de la migración v6), los días con datos
//! contados y el fin del día en que terminó el aprendizaje. Un día con datos es
//! un día local con al menos una hora de cobertura de tráfico (sesiones con
//! captura menos huecos, §7.10) y tráfico del sujeto en `TRAFFIC_ROLLUP_DAY`.
//! Un sujeto aprendido no vuelve a aprender.

use std::collections::HashSet;
use std::time::SystemTime;

use rusqlite::{params, Connection};

use crate::alerts::{Learning, LearningParams, LearningState, Subject};
use crate::error::Result;
use crate::history::LocalDay;
use crate::repo::gaps::{self, unix_de_instante};
use crate::repo::{instante_a_rfc3339, rfc3339_a_instante};

/// Cambio de aprendizaje de un sujeto al contar un día (§4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningChange {
    /// Sujeto que aprende.
    pub subject: Subject,
    /// Días con datos acumulados.
    pub data_days: u32,
    /// Fin del día en que terminó el aprendizaje, si terminó en esta llamada.
    pub learned_at: Option<SystemTime>,
}

/// Fila de ALERT_LEARNING mientras aprende.
struct FilaAprendizaje {
    subject: Subject,
    learning_from: String,
    data_days: u32,
    updated_day: i64,
}

/// Crea la fila de aprendizaje de un sujeto si no existe (§7.3).
///
/// `from` es el alta del equipo (su `first_seen`) o la fecha de la migración v6
/// para el propio equipo. Con `learning_days = 0` el sujeto nace aprendido:
/// la fila se inserta con `learned_at = from`, sin días contados y con el día
/// local de `from` ya procesado. Solo aprende un equipo o el propio equipo: los
/// demás sujetos se ignoran sin error.
pub(crate) fn ensure_learning(
    conn: &Connection,
    subject: Subject,
    from: SystemTime,
    learning_days: u32,
) -> Result<()> {
    if !matches!(subject, Subject::Device(_) | Subject::Host) {
        return Ok(());
    }
    let desde = instante_a_rfc3339(from);
    let (learned_at, updated_day) = if learning_days == 0 {
        let dia = unix_de_instante(from)
            .map(LocalDay::from_unix)
            .map(LocalDay::aaaammdd)
            .unwrap_or(0);
        (Some(desde.clone()), dia)
    } else {
        (None, 0)
    };
    conn.execute(
        "INSERT OR IGNORE INTO ALERT_LEARNING
             (subject, device_id, learning_from, data_days, learned_at, updated_day)
         VALUES (?1, ?2, ?3, 0, ?4, ?5)",
        params![
            subject.as_str(),
            subject.device_id(),
            desde,
            learned_at,
            updated_day
        ],
    )?;
    Ok(())
}

/// Cuenta el día local cerrado en cada sujeto que sigue aprendiendo (§7.3).
///
/// Devuelve los sujetos cuyo número de días cambió o que terminaron de aprender
/// en esta llamada, para que el motor recargue el aprendizaje (§4.3). Los días
/// anteriores a `learning_from`, los ya contados y los días sin cobertura o sin
/// tráfico del sujeto no cuentan.
pub(crate) fn update_learning(
    conn: &mut Connection,
    day: LocalDay,
    p: &LearningParams,
) -> Result<Vec<LearningChange>> {
    let aaaammdd = day.aaaammdd();
    let (inicio_dia, fin_dia) = day.limits();
    let ahora = crate::history::localtime::now_unix();
    let cobertura = gaps::cobertura_trafico(conn, inicio_dia, fin_dia.min(ahora), ahora)?;

    let filas = filas_sin_aprender(conn)?;
    if filas.is_empty() {
        return Ok(Vec::new());
    }

    let transaccion = conn.transaction()?;
    let mut cambios = Vec::new();
    for fila in filas {
        if aaaammdd <= fila.updated_day {
            continue;
        }
        let Some(desde) = rfc3339_a_instante(&fila.learning_from).and_then(unix_de_instante) else {
            tracing::debug!(
                learning_from = %fila.learning_from,
                "fecha de aprendizaje corrupta; se omite el sujeto"
            );
            continue;
        };
        // Un día que terminó antes del alta del sujeto no enseña nada de él.
        if fin_dia <= desde {
            continue;
        }
        let bytes = total_bytes_dia(&transaccion, fila.subject, aaaammdd)?;
        let mut data_days = fila.data_days;
        if dia_con_datos(cobertura, bytes) {
            data_days = data_days.saturating_add(1);
        }
        let aprendido = data_days >= p.learning_days;
        let learned_at = if aprendido { Some(fin_dia) } else { None };
        transaccion.execute(
            "UPDATE ALERT_LEARNING
                SET data_days = ?1, updated_day = ?2, learned_at = COALESCE(learned_at, ?3)
              WHERE subject = ?4 AND device_id = ?5",
            params![
                data_days,
                aaaammdd,
                learned_at.map(crate::history::localtime::rfc3339),
                fila.subject.as_str(),
                fila.subject.device_id()
            ],
        )?;
        if aprendido || data_days != fila.data_days {
            cambios.push(LearningChange {
                subject: fila.subject,
                data_days,
                learned_at: learned_at.and_then(unix_a_instante),
            });
        }
    }
    transaccion.commit()?;
    Ok(cambios)
}

/// Filas de aprendizaje de todos los sujetos (§4.4).
pub(crate) fn learning_rows(conn: &Connection) -> Result<Vec<LearningState>> {
    let mut sentencia = conn.prepare(
        "SELECT subject, device_id, learning_from, data_days, learned_at
           FROM ALERT_LEARNING
          ORDER BY subject, device_id",
    )?;
    let filas = sentencia.query_map([], |fila| {
        Ok((
            fila.get::<_, String>(0)?,
            fila.get::<_, i64>(1)?,
            fila.get::<_, String>(2)?,
            fila.get::<_, i64>(3)?,
            fila.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut estados = Vec::new();
    for fila in filas {
        let (subject, device_id, learning_from, data_days, learned_at) = fila?;
        let Some(subject) = Subject::from_parts(&subject, device_id) else {
            tracing::debug!(subject, "sujeto de aprendizaje desconocido; se omite");
            continue;
        };
        if !matches!(subject, Subject::Device(_) | Subject::Host) {
            continue;
        }
        let Some(learning_from) = rfc3339_a_instante(&learning_from) else {
            tracing::debug!(
                learning_from,
                "fecha de aprendizaje corrupta; se omite la fila"
            );
            continue;
        };
        let learned_at = learned_at.and_then(|texto| rfc3339_a_instante(&texto));
        estados.push(LearningState {
            subject,
            learning_from,
            data_days: u32::try_from(data_days.max(0)).unwrap_or(0),
            learned_at,
        });
    }
    Ok(estados)
}

/// Rellena el aprendizaje inicial desde el histórico de F5 (migración v6, §7.3).
///
/// Para cada equipo existente sin fila de aprendizaje cuenta sus días con datos
/// en `TRAFFIC_ROLLUP_DAY` desde su `first_seen`; si llega a `learning_days`,
/// queda aprendido con `learned_at` al final de su último día contado. Después
/// crea la fila del propio equipo (que empieza de cero). Devuelve cuántas filas
/// ha creado.
pub(crate) fn backfill_learning(
    conn: &mut Connection,
    now: SystemTime,
    p: &LearningParams,
) -> Result<usize> {
    let transaccion = conn.transaction()?;
    let escritas = backfill_learning_en(&transaccion, now, p)?;
    transaccion.commit()?;
    Ok(escritas)
}

/// Cuerpo del relleno del aprendizaje, sobre una conexión ya transaccionada.
///
/// Lo usa la migración v6 desde su propio hook de post-procesado, que ya corre
/// dentro de la transacción de la migración.
pub(crate) fn backfill_learning_en(
    conn: &Connection,
    now: SystemTime,
    p: &LearningParams,
) -> Result<usize> {
    let ahora = unix_de_instante(now).unwrap_or_else(crate::history::localtime::now_unix);
    let ayer = LocalDay::from_unix(ahora).sumar_dias(-1);
    let existentes = sujetos_con_fila(conn)?;
    let equipos: Vec<(i64, String)> = {
        let mut sentencia = conn.prepare("SELECT id, first_seen FROM DEVICES ORDER BY id")?;
        let filas = sentencia.query_map([], |fila| {
            Ok((fila.get::<_, i64>(0)?, fila.get::<_, String>(1)?))
        })?;
        let mut equipos = Vec::new();
        for fila in filas {
            equipos.push(fila?);
        }
        equipos
    };

    let mut escritas = 0usize;
    for (device_id, first_seen) in equipos {
        if existentes.contains(&(Subject::Device(device_id), 0)) {
            continue;
        }
        let Some(desde) = rfc3339_a_instante(&first_seen).and_then(unix_de_instante) else {
            tracing::debug!(
                first_seen,
                "first_seen corrupto; no se rellena su aprendizaje"
            );
            continue;
        };
        let desde_dia = LocalDay::from_unix(desde);
        let mut data_days = 0u32;
        let mut learned_at: Option<i64> = None;
        if p.learning_days == 0 {
            // Con learning_days = 0 el sujeto nace aprendido.
            learned_at = Some(ahora);
        } else {
            for (dia, bytes) in dias_con_datos(conn, Subject::Device(device_id), desde_dia)? {
                let (inicio, fin) = dia.limits();
                if fin <= desde {
                    continue;
                }
                let cobertura = gaps::cobertura_trafico(conn, inicio, fin.min(ahora), ahora)?;
                if dia_con_datos(cobertura, bytes) {
                    data_days = data_days.saturating_add(1);
                    if data_days >= p.learning_days {
                        learned_at = Some(fin);
                        break;
                    }
                }
            }
        }
        conn.execute(
            "INSERT OR IGNORE INTO ALERT_LEARNING
                 (subject, device_id, learning_from, data_days, learned_at, updated_day)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Subject::Device(device_id).as_str(),
                device_id,
                first_seen,
                data_days,
                learned_at.map(crate::history::localtime::rfc3339),
                ayer.aaaammdd()
            ],
        )?;
        escritas += 1;
    }

    // El propio equipo empieza de cero: F5 no guardó su inventario (§7.3).
    escritas += conn.execute(
        "INSERT OR IGNORE INTO ALERT_LEARNING
             (subject, device_id, learning_from, data_days, learned_at, updated_day)
         VALUES ('host', 0, ?1, 0, NULL, 0)",
        params![instante_a_rfc3339(now)],
    )?;
    Ok(escritas)
}

/// Filas de aprendizaje que aún no han terminado (§7.3).
fn filas_sin_aprender(conn: &Connection) -> Result<Vec<FilaAprendizaje>> {
    let mut sentencia = conn.prepare(
        "SELECT subject, device_id, learning_from, data_days, updated_day
           FROM ALERT_LEARNING
          WHERE learned_at IS NULL
          ORDER BY subject, device_id",
    )?;
    let filas = sentencia.query_map([], |fila| {
        Ok((
            fila.get::<_, String>(0)?,
            fila.get::<_, i64>(1)?,
            fila.get::<_, String>(2)?,
            fila.get::<_, i64>(3)?,
            fila.get::<_, i64>(4)?,
        ))
    })?;
    let mut aprendizajes = Vec::new();
    for fila in filas {
        let (subject, device_id, learning_from, data_days, updated_day) = fila?;
        let Some(subject) = Subject::from_parts(&subject, device_id) else {
            continue;
        };
        if !matches!(subject, Subject::Device(_) | Subject::Host) {
            continue;
        }
        aprendizajes.push(FilaAprendizaje {
            subject,
            learning_from,
            data_days: u32::try_from(data_days.max(0)).unwrap_or(0),
            updated_day,
        });
    }
    Ok(aprendizajes)
}

/// Sujetos que ya tienen fila de aprendizaje.
fn sujetos_con_fila(conn: &Connection) -> Result<HashSet<(Subject, i64)>> {
    let mut sentencia = conn.prepare("SELECT subject, device_id FROM ALERT_LEARNING")?;
    let filas = sentencia.query_map([], |fila| {
        Ok((fila.get::<_, String>(0)?, fila.get::<_, i64>(1)?))
    })?;
    let mut sujetos = HashSet::new();
    for fila in filas {
        let (subject, device_id) = fila?;
        if let Some(subject) = Subject::from_parts(&subject, device_id) {
            sujetos.insert((subject, 0));
        }
    }
    Ok(sujetos)
}

/// Bytes del sujeto en el total del día local indicado.
fn total_bytes_dia(conn: &Connection, subject: Subject, aaaammdd: i64) -> Result<i64> {
    let bytes: i64 = conn.query_row(
        "SELECT COALESCE(SUM(bytes_down + bytes_up), 0)
           FROM TRAFFIC_ROLLUP_DAY
          WHERE bucket = ?1 AND subject = ?2 AND device_id = ?3 AND dimension = 'total'",
        params![aaaammdd, subject.as_str(), subject.device_id()],
        |fila| fila.get(0),
    )?;
    Ok(bytes)
}

/// Días locales con filas de total con bytes del sujeto, desde el día indicado.
fn dias_con_datos(
    conn: &Connection,
    subject: Subject,
    desde: LocalDay,
) -> Result<Vec<(LocalDay, i64)>> {
    let mut sentencia = conn.prepare(
        "SELECT bucket, SUM(bytes_down + bytes_up)
           FROM TRAFFIC_ROLLUP_DAY
          WHERE subject = ?1 AND device_id = ?2 AND dimension = 'total' AND bucket >= ?3
          GROUP BY bucket
         HAVING SUM(bytes_down + bytes_up) > 0
          ORDER BY bucket",
    )?;
    let filas = sentencia.query_map(
        params![subject.as_str(), subject.device_id(), desde.aaaammdd()],
        |fila| Ok((fila.get::<_, i64>(0)?, fila.get::<_, i64>(1)?)),
    )?;
    let mut dias = Vec::new();
    for fila in filas {
        let (bucket, bytes) = fila?;
        let Some(dia) = LocalDay::from_aaaammdd(bucket) else {
            continue;
        };
        dias.push((dia, bytes));
    }
    Ok(dias)
}

/// Aplica `Learning::is_data_day` a una cobertura y unos bytes medidos.
fn dia_con_datos(cobertura_s: i64, subject_bytes: i64) -> bool {
    let cobertura = u32::try_from(cobertura_s.max(0)).unwrap_or(u32::MAX);
    let bytes = u64::try_from(subject_bytes.max(0)).unwrap_or(0);
    Learning::is_data_day(cobertura, bytes)
}

/// Convierte segundos Unix en un instante.
fn unix_a_instante(segundos: i64) -> Option<SystemTime> {
    if segundos < 0 {
        return None;
    }
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(segundos as u64))
}

impl crate::repo::Repo {
    /// Crea la fila de aprendizaje de un sujeto si no existe (§7.3).
    ///
    /// Con `learning_days = 0` el sujeto nuevo nace aprendido.
    pub fn ensure_learning(
        &mut self,
        subject: Subject,
        from: SystemTime,
        learning_days: u32,
    ) -> crate::error::Result<()> {
        ensure_learning(&self.conn, subject, from, learning_days)
    }

    /// Cuenta el día local cerrado en cada sujeto que sigue aprendiendo (§7.3).
    pub fn update_learning(
        &mut self,
        day: LocalDay,
        p: &LearningParams,
    ) -> crate::error::Result<Vec<LearningChange>> {
        update_learning(&mut self.conn, day, p)
    }

    /// Filas de aprendizaje de todos los sujetos.
    pub fn learning_rows(&self) -> crate::error::Result<Vec<LearningState>> {
        learning_rows(&self.conn)
    }

    /// Relleno del aprendizaje inicial desde el histórico de F5 (migración v6).
    pub fn backfill_learning(
        &mut self,
        now: SystemTime,
        p: &LearningParams,
    ) -> crate::error::Result<usize> {
        backfill_learning(&mut self.conn, now, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::localtime;
    use std::time::Duration;

    /// Repositorio vacío recién migrado (con la fila del propio equipo).
    fn repo_temporal() -> (tempfile::TempDir, crate::repo::Repo) {
        let dir = tempfile::tempdir().expect("directorio temporal");
        let repo = crate::repo::Repo::init(&dir.path().join("data.db")).expect("repo");
        (dir, repo)
    }

    fn instante_de(segundos: i64) -> SystemTime {
        if segundos >= 0 {
            SystemTime::UNIX_EPOCH + Duration::from_secs(segundos as u64)
        } else {
            SystemTime::UNIX_EPOCH - Duration::from_secs((-segundos) as u64)
        }
    }

    /// Inserta una sesión con captura que cubre el intervalo indicado.
    fn sesion_con_captura(repo: &crate::repo::Repo, desde: i64, hasta: i64) {
        repo.connection()
            .execute(
                "INSERT INTO APP_SESSIONS
                     (started_at, ended_at, last_beat, end_reason, mode, capture,
                      passive_only, version)
                 VALUES (?1, ?2, ?2, 'quit', 'privileged', 1, 0, '0.6.0')",
                params![localtime::rfc3339(desde), localtime::rfc3339(hasta)],
            )
            .expect("sesión con captura");
    }

    /// Inserta el total de un día local para un equipo.
    fn dia_con_trafico(repo: &crate::repo::Repo, dia: LocalDay, device_id: i64, bytes: i64) {
        repo.connection()
            .execute(
                "INSERT INTO TRAFFIC_ROLLUP_DAY
                     (bucket, subject, device_id, dimension, key, bytes_down, bytes_up,
                      connections)
                 VALUES (?1, 'device', ?2, 'total', '', ?3, 0, 1)",
                params![dia.aaaammdd(), device_id, bytes],
            )
            .expect("día de tráfico");
    }

    /// Sesión y ocho días con datos desde el alta, los cimientos de los tests.
    fn sembrar_ocho_dias(repo: &crate::repo::Repo, device_id: i64) -> i64 {
        let hoy = LocalDay::today();
        let principio = hoy.sumar_dias(-9).limits().0;
        sesion_con_captura(repo, principio, hoy.sumar_dias(-1).limits().1);
        for atras in 1..=8 {
            dia_con_trafico(repo, hoy.sumar_dias(-atras), device_id, 100);
        }
        principio
    }

    #[test]
    fn ensure_learning_no_duplica_y_solo_aprende_equipos_y_host() {
        let (_dir, mut repo) = repo_temporal();
        let desde = instante_de(LocalDay::today().sumar_dias(-3).limits().0);
        assert_eq!(
            repo.learning_rows().expect("filas").len(),
            1,
            "la fila del propio equipo nace en la migración"
        );
        repo.ensure_learning(Subject::Device(7), desde, 7)
            .expect("aprendizaje del equipo");
        repo.ensure_learning(Subject::Device(7), desde, 7)
            .expect("repetir no duplica");
        repo.ensure_learning(Subject::Network, desde, 7)
            .expect("la red no aprende");
        repo.ensure_learning(Subject::Almenara, desde, 7)
            .expect("Almenara no aprende");

        let filas = repo.learning_rows().expect("filas");
        assert_eq!(filas.len(), 2);
        let equipo = filas
            .iter()
            .find(|fila| fila.subject == Subject::Device(7))
            .expect("fila del equipo");
        assert_eq!(equipo.data_days, 0);
        assert_eq!(equipo.learned_at, None);
        assert_eq!(equipo.learning_from, desde);
        assert!(filas.iter().any(|fila| fila.subject == Subject::Host));
    }

    #[test]
    fn con_learning_days_cero_el_sujeto_nace_aprendido() {
        let (_dir, mut repo) = repo_temporal();
        let desde = instante_de(LocalDay::today().limits().0);
        repo.ensure_learning(Subject::Device(9), desde, 0)
            .expect("sujeto nuevo con learning_days = 0");
        let fila = repo
            .learning_rows()
            .expect("filas")
            .into_iter()
            .find(|fila| fila.subject == Subject::Device(9))
            .expect("fila del equipo");
        assert_eq!(fila.data_days, 0, "nace aprendido sin días contados");
        assert_eq!(fila.learned_at, Some(desde));
        let updated_day: i64 = repo
            .connection()
            .query_row(
                "SELECT updated_day FROM ALERT_LEARNING
                  WHERE subject = 'device' AND device_id = 9",
                [],
                |fila| fila.get(0),
            )
            .expect("leer updated_day");
        assert_eq!(updated_day, LocalDay::today().aaaammdd());
    }

    #[test]
    fn update_learning_cuenta_los_dias_con_datos_hasta_aprender() {
        let (_dir, mut repo) = repo_temporal();
        let hoy = LocalDay::today();
        let principio = sembrar_ocho_dias(&repo, 1);
        repo.ensure_learning(Subject::Device(1), instante_de(principio), 7)
            .expect("fila de aprendizaje");

        let params = LearningParams::default();
        let mut dias = Vec::new();
        let mut aprendido = None;
        for atras in (1..=8).rev() {
            let dia = hoy.sumar_dias(-atras);
            for cambio in repo.update_learning(dia, &params).expect("contar día") {
                if cambio.subject != Subject::Device(1) {
                    continue;
                }
                dias.push(cambio.data_days);
                if cambio.learned_at.is_some() {
                    aprendido = cambio.learned_at;
                }
            }
        }
        assert_eq!(
            dias,
            vec![1, 2, 3, 4, 5, 6, 7],
            "cuenta un día con datos por vuelta y aprende al llegar a 7"
        );
        let septimo = hoy.sumar_dias(-2);
        assert_eq!(aprendido, Some(instante_de(septimo.limits().1)));

        let (data_days, learned_at): (i64, Option<String>) = repo
            .connection()
            .query_row(
                "SELECT data_days, learned_at FROM ALERT_LEARNING
                  WHERE subject = 'device' AND device_id = 1",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer aprendizaje");
        assert_eq!(data_days, 7);
        assert_eq!(
            learned_at.as_deref(),
            Some(localtime::rfc3339(septimo.limits().1).as_str())
        );

        // Un sujeto aprendido no vuelve a procesarse.
        let cambios = repo
            .update_learning(hoy, &params)
            .expect("día posterior a aprender");
        assert!(cambios
            .iter()
            .all(|cambio| cambio.subject != Subject::Device(1)));
    }

    #[test]
    fn los_dias_sin_cobertura_no_cuentan_pero_quedan_procesados() {
        let (_dir, mut repo) = repo_temporal();
        let hoy = LocalDay::today();
        let dia = hoy.sumar_dias(-1);
        repo.ensure_learning(
            Subject::Device(2),
            instante_de(hoy.sumar_dias(-2).limits().0),
            7,
        )
        .expect("fila de aprendizaje");
        // Hay tráfico del sujeto, pero ninguna sesión cubre el día.
        dia_con_trafico(&repo, dia, 2, 100);

        let cambios = repo
            .update_learning(dia, &LearningParams::default())
            .expect("día sin cobertura");
        assert!(
            cambios
                .iter()
                .all(|cambio| cambio.subject != Subject::Device(2)),
            "sin cobertura el día no cuenta"
        );
        let (data_days, updated_day): (i64, i64) = repo
            .connection()
            .query_row(
                "SELECT data_days, updated_day FROM ALERT_LEARNING
                  WHERE subject = 'device' AND device_id = 2",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer aprendizaje");
        assert_eq!(data_days, 0);
        assert_eq!(updated_day, dia.aaaammdd(), "el día queda procesado");
    }

    #[test]
    fn un_dia_cubierto_sin_trafico_del_sujeto_no_cuenta() {
        let (_dir, mut repo) = repo_temporal();
        let hoy = LocalDay::today();
        let dia = hoy.sumar_dias(-1);
        repo.ensure_learning(
            Subject::Device(3),
            instante_de(hoy.sumar_dias(-2).limits().0),
            7,
        )
        .expect("fila de aprendizaje");
        // Cobertura de tráfico completa, pero sin filas del sujeto.
        sesion_con_captura(&repo, dia.limits().0, dia.limits().1);

        let cambios = repo
            .update_learning(dia, &LearningParams::default())
            .expect("día sin tráfico del sujeto");
        assert!(cambios
            .iter()
            .all(|cambio| cambio.subject != Subject::Device(3)));
    }

    #[test]
    fn backfill_learning_rellena_los_equipos_existentes_y_la_migracion_ya_crea_el_host() {
        let (_dir, mut repo) = repo_temporal();
        let hoy = LocalDay::today();
        let principio = sembrar_ocho_dias(&repo, 1);
        // Equipo existente de F5 con su first_seen.
        repo.connection()
            .execute(
                "INSERT INTO INTERFACES (name, is_up, last_seen) VALUES ('eth0', 1, ?1)",
                params![localtime::rfc3339(principio)],
            )
            .expect("interfaz");
        repo.connection()
            .execute(
                "INSERT INTO DEVICES (mac, ip, interface_id, first_seen, last_seen)
                 VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', 1, ?1, ?1)",
                params![localtime::rfc3339(principio)],
            )
            .expect("equipo");

        let creadas = repo
            .backfill_learning(SystemTime::now(), &LearningParams::default())
            .expect("relleno del aprendizaje");
        assert_eq!(creadas, 1, "el host ya lo creó la migración v6");
        let (data_days, learned_at): (i64, Option<String>) = repo
            .connection()
            .query_row(
                "SELECT data_days, learned_at FROM ALERT_LEARNING
                  WHERE subject = 'device' AND device_id = 1",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer aprendizaje del equipo");
        assert_eq!(data_days, 7);
        let septimo = hoy.sumar_dias(-2);
        assert_eq!(
            learned_at.as_deref(),
            Some(localtime::rfc3339(septimo.limits().1).as_str())
        );

        // La fila del propio equipo sigue empezando de cero.
        let (host_dias, host_aprendido): (i64, Option<String>) = repo
            .connection()
            .query_row(
                "SELECT data_days, learned_at FROM ALERT_LEARNING
                  WHERE subject = 'host' AND device_id = 0",
                [],
                |fila| Ok((fila.get(0)?, fila.get(1)?)),
            )
            .expect("leer aprendizaje del host");
        assert_eq!(host_dias, 0);
        assert_eq!(host_aprendido, None);

        // Idempotente: la segunda vez no crea nada.
        assert_eq!(
            repo.backfill_learning(SystemTime::now(), &LearningParams::default())
                .expect("segundo relleno"),
            0
        );
    }
}
