//! DAO de la caché de nombres IP → nombre (tabla NAME_CACHE).
//!
//! NAME_CACHE es una tabla caliente sin claves ajenas: se cruza por valor con la
//! IP del lado servidor de CONNECTIONS. Cada fila es un nombre observado para
//! una IP; una misma IP puede tener varias filas (CDN) y el UNIQUE (ip, name)
//! evita duplicados. La caducidad la decide la caché en memoria (§7.7); aquí
//! solo se persiste, se listan las vigentes y se purgan las caducadas.
//!
//! Las fechas se guardan como TEXT RFC 3339 UTC con precisión de segundos, el
//! formato único de la capa de persistencia.

use std::net::IpAddr;
use std::time::SystemTime;

use rusqlite::{params, types::Type, Connection as SqliteConnection, Row};

use super::{instante_a_rfc3339, rfc3339_a_instante};
use crate::error::Result;
use crate::inference::names::NameEntry;
use crate::inference::NameSource;

/// Columnas de NAME_CACHE en el mismo orden que reconstruye fila_a_entrada.
const SQL_SELECCION: &str =
    "SELECT ip, name, source, first_seen, last_seen, expires_at FROM NAME_CACHE";

/// Upsert por (ip, name): refresca la fuente y la caducidad y conserva la
/// primera observación, que no se pisa.
const SQL_UPSERT: &str = "\
INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT(ip, name) DO UPDATE SET
    source = excluded.source,
    last_seen = excluded.last_seen,
    expires_at = excluded.expires_at";

/// Persiste entradas nuevas o refrescadas y devuelve cuántas se han escrito.
///
/// Se descartan los nombres vacíos (no aportan nada al ranking de destinos) y
/// los duplicados del mismo lote se funden por el UNIQUE (ip, name). El lote se
/// escribe en una sola transacción: con el tope de 10 000 entradas, confirmar
/// una a una cada ciclo de 5 s sería demasiado caro.
pub(crate) fn upsert(conn: &SqliteConnection, entradas: &[NameEntry]) -> Result<usize> {
    if entradas.is_empty() {
        return Ok(0);
    }

    let transaccion = conn.unchecked_transaction()?;
    let mut escritas = 0_usize;
    {
        let mut sentencia = transaccion.prepare_cached(SQL_UPSERT)?;
        for entrada in entradas {
            let nombre = entrada.name.trim();
            if nombre.is_empty() {
                continue;
            }
            sentencia.execute(params![
                entrada.ip.to_string(),
                nombre,
                entrada.source.as_str(),
                instante_a_rfc3339(entrada.first_seen),
                instante_a_rfc3339(entrada.last_seen),
                instante_a_rfc3339(entrada.expires_at),
            ])?;
            escritas += 1;
        }
    }
    transaccion.commit()?;
    Ok(escritas)
}

/// Lista las entradas vigentes (`expires_at > ahora`) para la carga en caliente.
///
/// Se ordenan de la más reciente a la más antigua. El equipo que hizo la
/// consulta no se persiste (solo vive en memoria, §7.7), así que `requester`
/// siempre vuelve a None.
pub(crate) fn list(conn: &SqliteConnection, ahora: SystemTime) -> Result<Vec<NameEntry>> {
    let corte = instante_a_rfc3339(ahora);
    let sql = format!("{SQL_SELECCION} WHERE expires_at > ?1 ORDER BY last_seen DESC, id DESC");
    let mut sentencia = conn.prepare(&sql)?;
    let filas = sentencia.query_map(params![corte], fila_a_entrada)?;
    let mut entradas = Vec::new();
    for fila in filas {
        entradas.push(fila?);
    }
    Ok(entradas)
}

/// Purga las entradas caducadas (`expires_at <= ahora`) y devuelve cuántas.
pub(crate) fn prune(conn: &SqliteConnection, ahora: SystemTime) -> Result<usize> {
    let borrados = conn.execute(
        "DELETE FROM NAME_CACHE WHERE expires_at <= ?1",
        params![instante_a_rfc3339(ahora)],
    )?;
    Ok(borrados)
}

/// Dato persistido que no se puede interpretar (fecha o IP).
#[derive(Debug)]
struct DatoInvalido(String);

impl std::fmt::Display for DatoInvalido {
    fn fmt(&self, formateador: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formateador, "dato inválido en NAME_CACHE: {}", self.0)
    }
}

impl std::error::Error for DatoInvalido {}

/// Convierte un dato corrupto en un error de conversión de SQLite (sin pánico).
fn error_conversion(columna: usize, detalle: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(columna, Type::Text, Box::new(DatoInvalido(detalle)))
}

/// Lee una columna de fecha RFC 3339 y la convierte en instante.
fn columna_instante(fila: &Row<'_>, columna: usize) -> rusqlite::Result<SystemTime> {
    let texto: String = fila.get(columna)?;
    rfc3339_a_instante(&texto)
        .ok_or_else(|| error_conversion(columna, format!("fecha RFC 3339 no válida: {texto}")))
}

/// Reconstruye una entrada a partir de una fila de SQL_SELECCION.
fn fila_a_entrada(fila: &Row<'_>) -> rusqlite::Result<NameEntry> {
    let ip_texto: String = fila.get(0)?;
    let ip: IpAddr = ip_texto
        .parse()
        .map_err(|_| error_conversion(0, format!("IP no válida: {ip_texto}")))?;
    let fuente_texto: String = fila.get(2)?;
    // Una fuente desconocida (base escrita por una versión futura) se muestra
    // como DNS en vez de bloquear la carga de la caché al arrancar.
    let source = NameSource::from_str(&fuente_texto).unwrap_or(NameSource::Dns);
    Ok(NameEntry {
        ip,
        name: fila.get(1)?,
        source,
        first_seen: columna_instante(fila, 3)?,
        last_seen: columna_instante(fila, 4)?,
        expires_at: columna_instante(fila, 5)?,
        // El equipo que preguntó no se persiste (§7.7).
        requester: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Instante de referencia de las pruebas: 2027-01-15T08:00:00Z.
    const BASE_S: u64 = 1_800_000_000;

    /// Instante base desplazado los segundos indicados (puede ser negativo).
    fn instante(desplazamiento_s: i64) -> SystemTime {
        if desplazamiento_s >= 0 {
            SystemTime::UNIX_EPOCH + Duration::from_secs(BASE_S + desplazamiento_s as u64)
        } else {
            SystemTime::UNIX_EPOCH + Duration::from_secs(BASE_S - (-desplazamiento_s) as u64)
        }
    }

    /// Conexión SQLite en memoria con el esquema migrado (incluida NAME_CACHE).
    fn conexion_migrada() -> SqliteConnection {
        let mut conn = SqliteConnection::open_in_memory().expect("abrir SQLite en memoria");
        crate::repo::migrations::apply_all(&mut conn).expect("aplicar migraciones");
        conn
    }

    /// Entrada de prueba con la caducidad a una hora vista.
    fn entrada(ip: &str, nombre: &str, source: NameSource) -> NameEntry {
        NameEntry {
            ip: ip.parse().expect("IP de prueba"),
            name: nombre.to_string(),
            source,
            first_seen: instante(0),
            last_seen: instante(0),
            expires_at: instante(3600),
            requester: None,
        }
    }

    #[test]
    fn upsert_lista_y_round_trip() {
        let conn = conexion_migrada();
        let dns = entrada("93.184.216.34", "example.com", NameSource::Dns);
        let sni = entrada("142.250.1.1", "youtube.com", NameSource::Sni);

        assert_eq!(
            upsert(&conn, &[dns.clone(), sni.clone()]).expect("insertar"),
            2
        );
        let entradas = list(&conn, instante(60)).expect("listar vigentes");
        assert_eq!(entradas.len(), 2);

        let encontrada = |nombre: &str| {
            entradas
                .iter()
                .find(|entrada| entrada.name == nombre)
                .cloned()
                .expect("la entrada debe estar")
        };
        assert_eq!(encontrada("example.com"), dns);
        assert_eq!(encontrada("youtube.com"), sni);
        assert!(entradas.iter().all(|entrada| entrada.requester.is_none()));
    }

    #[test]
    fn upsert_vacio_no_escribe_nada() {
        let conn = conexion_migrada();
        assert_eq!(upsert(&conn, &[]).expect("lote vacío"), 0);
        assert!(list(&conn, instante(0)).expect("listar").is_empty());
    }

    #[test]
    fn upsert_refresca_sin_duplicar_y_conserva_first_seen() {
        let conn = conexion_migrada();
        let primera = entrada("93.184.216.34", "example.com", NameSource::Dns);
        upsert(&conn, std::slice::from_ref(&primera)).expect("insertar");

        // La segunda observación llega con otro first_seen, otra fuente y otra
        // caducidad: first_seen no debe pisarse.
        let refrescada = NameEntry {
            first_seen: instante(120),
            last_seen: instante(240),
            expires_at: instante(9000),
            source: NameSource::Http,
            ..primera
        };
        assert_eq!(upsert(&conn, &[refrescada]).expect("refrescar"), 1);

        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM NAME_CACHE", [], |fila| fila.get(0))
            .expect("contar filas");
        assert_eq!(total, 1, "el UNIQUE (ip, name) debe evitar duplicados");

        let entradas = list(&conn, instante(300)).expect("listar");
        assert_eq!(entradas.len(), 1);
        assert_eq!(entradas[0].first_seen, instante(0));
        assert_eq!(entradas[0].last_seen, instante(240));
        assert_eq!(entradas[0].expires_at, instante(9000));
        assert_eq!(entradas[0].source, NameSource::Http);
        assert_eq!(entradas[0].name, "example.com");
    }

    #[test]
    fn upsert_descarta_nombres_vacios() {
        let conn = conexion_migrada();
        let mut vacia = entrada("93.184.216.34", "   ", NameSource::Dns);
        vacia.name = "\t \n".to_string();
        assert_eq!(upsert(&conn, &[vacia]).expect("insertar vacía"), 0);
        assert!(list(&conn, instante(0)).expect("listar").is_empty());
    }

    #[test]
    fn list_filtra_por_caducidad_estricta() {
        let conn = conexion_migrada();
        let vigente = entrada("10.0.0.1", "vigente.local", NameSource::Dns);
        let caducada = NameEntry {
            expires_at: instante(-1),
            ..entrada("10.0.0.2", "caducada.local", NameSource::Dns)
        };
        let justo_ahora = NameEntry {
            expires_at: instante(0),
            ..entrada("10.0.0.3", "limite.local", NameSource::Dns)
        };
        upsert(&conn, &[vigente.clone(), caducada, justo_ahora]).expect("insertar");

        // expires_at > ahora: el límite exacto ya no es vigente.
        let entradas = list(&conn, instante(0)).expect("listar vigentes");
        assert_eq!(entradas.len(), 1);
        assert_eq!(entradas[0], vigente);
    }

    #[test]
    fn prune_borra_las_caducadas_y_devuelve_cuantas() {
        let conn = conexion_migrada();
        let vigente = entrada("10.0.0.1", "vigente.local", NameSource::Dns);
        let caducada = NameEntry {
            expires_at: instante(-10),
            ..entrada("10.0.0.2", "caducada.local", NameSource::Dns)
        };
        upsert(&conn, &[vigente.clone(), caducada]).expect("insertar");

        assert_eq!(prune(&conn, instante(0)).expect("purgar"), 1);
        assert_eq!(prune(&conn, instante(0)).expect("segunda purga"), 0);
        assert_eq!(list(&conn, instante(0)).expect("listar"), vec![vigente]);
    }

    #[test]
    fn unique_por_ip_y_nombre_impide_duplicados_crudos() {
        let conn = conexion_migrada();
        let insertar = || {
            conn.execute(
                "INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
                 VALUES ('93.184.216.34', 'example.com', 'dns',
                         '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                         '2026-01-01T01:00:00Z')",
                [],
            )
        };
        insertar().expect("primera inserción");
        let error = insertar().expect_err("el UNIQUE (ip, name) debe rechazar el duplicado");
        assert!(matches!(error, rusqlite::Error::SqliteFailure(_, _)));
    }

    #[test]
    fn list_falla_sin_panico_con_datos_corruptos() {
        let conn = conexion_migrada();
        // Fecha ilegible: list debe devolver error, no entrar en pánico.
        conn.execute(
            "INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
             VALUES ('93.184.216.34', 'example.com', 'dns', 'no-es-fecha',
                     '2026-01-01T00:00:00Z', '2999-01-01T00:00:00Z')",
            [],
        )
        .expect("insertar fila corrupta");
        assert!(list(&conn, instante(0)).is_err());

        // IP ilegible: también error controlado.
        conn.execute("DELETE FROM NAME_CACHE", []).expect("limpiar");
        conn.execute(
            "INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
             VALUES ('999.1.1.1', 'example.com', 'dns', '2026-01-01T00:00:00Z',
                     '2026-01-01T00:00:00Z', '2999-01-01T00:00:00Z')",
            [],
        )
        .expect("insertar IP corrupta");
        assert!(list(&conn, instante(0)).is_err());
    }

    #[test]
    fn fuente_desconocida_se_lee_como_dns_sin_romper() {
        let conn = conexion_migrada();
        conn.execute(
            "INSERT INTO NAME_CACHE (ip, name, source, first_seen, last_seen, expires_at)
             VALUES ('93.184.216.34', 'example.com', 'quic', '2026-01-01T00:00:00Z',
                     '2026-01-01T00:00:00Z', '2999-01-01T00:00:00Z')",
            [],
        )
        .expect("insertar fuente futura");
        let entradas = list(&conn, instante(0)).expect("listar");
        assert_eq!(entradas.len(), 1);
        assert_eq!(entradas[0].source, NameSource::Dns);
    }
}
