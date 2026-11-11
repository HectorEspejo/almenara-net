# Almenara - Fase 5: Histórico, rollups y eventos

## Informe de implementación

**Versión:** 0.5.0
**Fecha:** 2026-11-11
**Estado:** Fase 5 completada (141 / 141 funcionalidades del checklist).
Pendiente: entregar este informe al analista funcional antes de especificar la
Fase 6.

---

## Resumen de lo implementado

La Fase 5 guarda el histórico del tráfico en SQLite como agregados por minuto,
hora y día, alimentados por el mismo volcado por flujo y segundo que los
rankings de F4, y los lee con un hilo propio de solo lectura. Además completa
los eventos del escaneo (vuelta a estar en línea, servicios, sistema operativo y
tipo), calcula la presencia al vuelo desde esos eventos y las sesiones, guarda
el inventario por equipo en DEVICE_SEEN y ofrece la pestaña Histórico, las
ventanas de 1 h y 24 h de Tráfico y el histórico del detalle de equipo.

Resumen por bloques:

- **Migración v5** aditiva e idempotente: TRAFFIC_ROLLUP_MINUTE/HOUR/DAY
  (WITHOUT ROWID), DEVICE_SEEN y APP_SESSIONS; auto_vacuum = INCREMENTAL con un
  único VACUUM fuera de la transacción de la migración. Con test de
  compatibilidad F4 → F5 sin pérdida de datos.
- **[history]** en la configuración, con validación tolerante (aviso único y
  valor por defecto; nunca aborta el arranque) y plantilla por defecto.
- **Instancia única** por base de datos con flock sobre data.db.lock (ADR-65).
- **Sesiones** de Almenara con latido por minuto, cierre ordenado con q y cierre
  de las interrumpidas en el arranque siguiente.
- **Rollups por minuto** con sujetos device/host/other/network, dimensiones
  total/app/category/destination/protocol/process/org/country, claves especiales
  (~sin_identificar, ~lan, ~desconocido), topes de top_keys con ~otros, tope de
  20 000 entradas y contador rollup_overflow.
- **Lote del minuto** por AppEvent::Rollup, escrito por el hilo de la TUI en una
  transacción con suma si el minuto ya existe; reintentos con hasta 10 lotes
  pendientes, descarte con rollup_drops y aviso único; minuto parcial al salir.
- **Consolidación** de horas y días (día local con libc::localtime_r, 23/25 h en
  los cambios de hora), pendientes al arrancar y tras cada lote en tandas de 10
  por segundo.
- **Retención y purga** por resolución (minutos 48 h, destinos 2 h; horas 90
  días, destinos 30 días; días 2 años; inventario y sesiones 2 años), sin purgar
  minutos de horas sin consolidar, con incremental_vacuum y aviso de tamaño.
- **Eventos nuevos**: reappeared (con away_since/away_s), disappeared con
  last_seen, service_new (incluido reopened), service_gone, os_changed y
  type_changed.
- **Presencia** calculada al vuelo desde new/disappeared/reappeared y las
  sesiones, con tramos de presente/ausente/sin datos.
- **Inventario por equipo** (DEVICE_SEEN) y puertos desde DEVICE_SERVICES.
- **Lector del histórico** con conexión de solo lectura (SQLITE_OPEN_READ_ONLY +
  query_only), peticiones con identificador, corte a los 2 s con
  progress_handler y descarte de respuestas obsoletas en la TUI.
- **TUI**: pestaña Histórico (sujeto, rango, gráfica con huecos y cursor, más
  tráfico, línea de tiempo con filtro y búsqueda), ventanas de 1 h y 24 h en
  Tráfico, histórico y presencia en el detalle, «Último evento» en Equipos,
  [history] y tamaño de la BD en Config y Ayuda con la privacidad del histórico.
- **Histórico sintético** determinista y prueba ignorada de medición.
- **Pruebas, README, CHANGELOG, versión 0.5.0 e informe**: ver el apartado de
  pendientes según avance la sesión.

Mediciones ya tomadas (equipo de desarrollo, cargo test --release):

- MinuteRollup::add: **2 016 877 llamadas/s** (1 000 000 en 495,8 ms), por encima
  del 1 millón/s exigido en §8. La medición usa 8 flujos precomputados y claves
  reales del catálogo, con el mapa anidado (sujeto, dimensión) → clave →
  contador para no asignar memoria en el camino caliente.

Las 141 funcionalidades del checklist están implementadas y verificadas: la fase
cierra con la migración v5, el histórico por minuto/hora/día con retención y
purga, las sesiones e instancia única, los eventos nuevos y la presencia, el
inventario, el lector de solo lectura con sus diez consultas, la pestaña
Histórico, las ventanas de 1 h y 24 h, el detalle con histórico y la
documentación de usuario. El informe de fase completo está en
docs/fase5/almenara-fase5-informe.md y el checklist marcado en
docs/fase5/almenara-fase5-checklist.md.

Mediciones finales (cargo test --release, ignora los tests normales):

| Métrica de §8 | Límite | Medido |
|---|---|---|
| Escritura del lote del minuto (50 equipos, 8000 filas) | ≤ 10 ms | **5,05 ms** |
| Construcción de una hora | ≤ 50 ms | **4,26 ms** |
| Construcción de un día local | ≤ 100 ms | **4,86 ms** |
| Purga + incremental_vacuum con la retención por defecto | ≤ 100 ms | **34,41 ms** |
| Consulta de 24 h (minutos) | ≤ 200 ms | **6,27 ms** |
| Consulta de 7 días (horas) | ≤ 200 ms | **2,99 ms** |
| Consulta de 30 días (días) | ≤ 200 ms | **0,36 ms** |
| Consulta de 1 año (días) | ≤ 500 ms | **4,03 ms** |
| Top de 7 días por app | ≤ 200 ms | **6,82 ms** |
| Base de datos con el perfil de referencia (30 equipos, 2 años) | ≤ 300 MB | **75,5 MB** |
| Memoria añadida (20 000 entradas + 10 lotes pendientes) | ≤ 16 MB | **11,3 MB** |
| MinuteRollup::add (release, un núcleo) | ≥ 1 000 000/s | **1 892 142/s** |
| Render con Histórico abierto en 80×24 | ≤ 16 ms | **0,083 ms** |
| Render con Histórico abierto en 120×40 | ≤ 33 ms | **0,222 ms** |

El detalle de las cifras y de cómo reproducirlas está en «Ejecución y pruebas».


## Desviaciones respecto a la especificación (qué y por qué)

Se anotan aquí las desviaciones reales, con su motivo, tal y como pide el
informe de fase:

1. **Prueba de medición como test unitario ignorado** en src/history/synthetic.rs
   en lugar de tests/historial_sintetico.rs: el crate es solo binario (no hay
   lib.rs), así que un test de integración no puede acceder a los módulos
   internos. Se ejecuta igual con
   cargo test --release -- --ignored medir_historial y sus cifras están en este
   informe.
2. **Feature hooks de rusqlite** activada en Cargo.toml (bundled + hooks) para
   poder usar Connection::progress_handler, que el informe exige en §7.10. No
   es una dependencia nueva: es una feature opcional del mismo crate ya
   empaquetado.
3. **Sesiones siempre registradas** aunque [history].enabled = false: la
   comprobación del checklist solo exige que con el histórico desactivado no se
   acumulen ni escriban rollups ni inventario (y que w se salte 1 h y 24 h).
   Las sesiones no contienen tráfico, son metadatos baratos que mantienen la
   línea de tiempo y la presencia coherentes; la TUI, además, sigue mostrando
   la línea de tiempo y la presencia con el histórico desactivado. Queda anotado
   por si el analista prefiere apagarlas también.
4. **Firmas de los servicios internos adaptadas a la arquitectura real** (el
   informe da firmas de referencia, no contratos de compilación):
   - Rankings::tick(now: Instant) se amplía como tick(now, wall: SystemTime) y
     devuelve Option<RollupBatch>; la tarea de tráfico es quien lo convierte en
     AppEvent::Rollup porque es la dueña del canal de eventos.
   - MinuteRollup::flush(minute) usa el tope configurado con set_top_keys en vez
     de recibirlo en cada cierre (el tope no cambia en ejecución).
   - MinuteRollup::add_flow recibe además una huella del flujo para contarlo una
     sola vez por minuto y refrescar su etiqueta hasta el cierre; add conserva
     la firma del §5.
   - HistoryReader::spawn devuelve Result<HistoryHandle> en vez de
     HistoryHandle para propagar el fallo al abrir la conexión de solo lectura;
     main.rs avisa y sigue sin lector si falla.
   - Repo::purge_history recibe now: SystemTime (igual que el resto de DAOs de
     fechas) y devuelve PurgeStats con las páginas liberadas por
     incremental_vacuum.
5. **El tope de claves se aplica también en el minuto**: el §7.2 lo aplica al
   cerrar el minuto y la hora reconstruida vuelve a aplicarlo (idempotente). El
   inventario se anota antes del tope, como pide §7.9.
6. **Contador de conexiones del cubo**: se cuenta el flujo en el primer volcado
   en que aparece (detectado por la caché de conexiones) y su etiqueta se
   refresca en los volcados siguientes del mismo minuto, de modo que la conexión
   queda contada con la etiqueta que tiene al cerrar el minuto.
7. **Serie del detalle de equipo**: el detalle pide una consulta Series con
   subject = Device(id) y su propio identificador, además de Presence e
   Inventory; es una consulta más de las previstas en el §5 (que ya define
   Queries::series para cualquier sujeto) y no añade tipos nuevos.
8. **destination_days = 0**: los destinos por hora se construyen al consolidar la
   hora y se borran en el mismo momento con Repo::clear_destination_hours, para
   que con la configuración a 0 no queden destinos por hora (solo los minutos de
   2 h).
9. **JA4 en el inventario**: solo se apunta la huella de los flujos en los que
   la columna Equipo es el cliente (campo es_cliente de FlowCtx), no la de un
   cliente remoto en el inventario del servidor de la LAN.
10. **Consultas con parámetros**: todas las claves que vienen de la red viajan
    como parámetros SQL; las únicas interpolaciones de texto son nombres de
    tabla constantes internas (TRAFFIC_ROLLUP_MINUTE/HOUR/DAY) elegidos por el
    propio código, nunca datos de la red.
11. **Estado CERRADO de un servicio sin cambiar el esquema**: F2 deriva el estado
    de last_seen y no tiene columna de estado. F5 materializa el cierre dejando
    last_seen justo por debajo del umbral de obsolescencia (Repo::mark_service_closed)
    para que F2 lo derive STALE de inmediato, conservar la fila para reopened y
    no duplicar service_gone; el estado CERRADO se recuerda además con el último
    evento de servicio del puerto.
12. **Cobertura de las ventanas de 1 h**: history::Range no tiene un rango de
    1 h, así que la TUI pide Coverage con Range::Hours24 y recorta los huecos a
    la ventana; si la respuesta no ha llegado usa RankingResult.gap_seconds.
13. **Búsqueda de eventos con barra**: se edita dentro de HistoryState (no se
    añadió un InputMode nuevo); app.rs llama a history_handle_key antes del
    manejo genérico de teclas.
14. **Línea «Último evento»**: se pinta al pie del contenido de Equipos (la
    barra de estado es de views/mod.rs), como en el mockup 5, y se oculta si no
    hay evento o no cabe.
15. **Histórico sintético**: genera las tres resoluciones por separado (no
    consolida horas desde minutos ni días desde horas) para no depender del DAO
    en la medición; las magnitudes son coherentes con el perfil y está
    documentado en el módulo. La purga del test sintético borra a propósito más
    de un millón de filas con retenciones reducidas y tarda 166 ms; con la
    retención por defecto (escenario real) la purga medida es de 34 ms, dentro
    del límite de 100 ms, y así se recoge en la tabla del resumen.
16. **db_stats sin ruta**: el lector obtiene el fichero de la base de datos con
    PRAGMA database_list para medir el WAL, porque HistoryQuery::DbStats no
    lleva ruta y el lector no debe conocerla de antemano.
17. **Migración v5 con índice de purga**: además de las claves primarias se crean
    IDX_SEEN_LAST_SEEN e IDX_APP_SESSIONS_ENDED para que la purga de inventario y
    sesiones no recorra las tablas completas; el coste es mínimo y no toca las
    tablas de rollups (sin índices secundarios, como pide §3). El informe de fase
    no los prohibía y se anota como decisión.
18. **Reintentos de lote**: el primer reintento ocurre en el siguiente
    AppEvent::Rollup (un minuto después), no en cada tick; es lo que pide §4.1
    (reintento en el minuto siguiente) y evita machacar la BD si el fallo es
    persistente. Si se acumulan más de 10 se descarta el más antiguo, se cuenta
    en rollup_drops y se avisa una sola vez.
## Estructura de archivos creada/modificada

Creados (nuevos):

- src/history/mod.rs — tipos comunes (sujeto, dimensión, claves, rollups,
  consultas, respuestas, presencia, inventario, retención y sesiones).
- src/history/localtime.rs — día local ⇄ UTC con libc::localtime_r/mktime.
- src/history/rollup.rs — MinuteRollup: acumuladores del minuto y topes.
- src/history/build.rs — aplicación de topes y ~otros.
- src/history/retention.rs — cortes de la purga por resolución.
- src/history/changes.rs — eventos nuevos (presencia, servicios, identidad).
- src/history/reader.rs — hilo lector de solo lectura y canal de consultas.
- src/history/queries.rs — las diez consultas del histórico y su despacho.
- src/history/synthetic.rs — histórico sintético y prueba de medición.
- src/instance.rs — bloqueo de instancia única con flock.
- src/repo/rollups.rs — DAO de TRAFFIC_ROLLUP_* y purga/compactación.
- src/repo/seen.rs — DAO de DEVICE_SEEN.
- src/repo/sessions.rs — DAO de APP_SESSIONS.
- src/tui/history_state.rs — estado de la TUI para el histórico.
- src/tui/views/history.rs — pestaña Histórico.
- src/tui/views/charts.rs — gráficas, huecos y presencia.

Modificados:

- Cargo.toml y Cargo.lock (feature hooks de rusqlite; versión 0.5.0).
- src/events.rs (AppEvent::Rollup, AppEvent::History y AppEvent::TrafficStopped).
- src/main.rs (instancia única, sesiones y lector del histórico).
- src/config.rs ([history] y su validación tolerante).
- src/error.rs (variante History).
- src/rankings.rs (MinuteRollup en el agregador, protocolo resuelto, JA4 del
  cliente y cierre del minuto; ventanas de 1 h y 24 h en el ciclo de w).
- src/traffic.rs (flujos nuevos, lote del minuto y minuto parcial al parar).
- src/repo/mod.rs (módulos y reexportes de F5).
- src/repo/migrations.rs (migración v5, auto_vacuum y tests de compatibilidad).
- src/repo/events.rs (tipos de evento nuevos y last_service_event).
- src/repo/device_services.rs (estado CERRADO de servicios).
- src/scanner/mod.rs (eventos nuevos en la reconciliación y datos del port scan).
- src/tui/app.rs (campos de histórico, teclas e integración de pestañas).
- src/tui/mod.rs (escritura del lote, consolidación, purga, latido, sesión y
  consultas del lector).
- src/tui/keys.rs (pie y ayuda del histórico).
- src/tui/traffic_state.rs (ciclo de cinco ventanas y rankings históricos).
- src/tui/views/mod.rs (despacho de la pestaña Histórico y pie).
- src/tui/views/traffic.rs, device_detail.rs, devices.rs, config_view.rs,
  help.rs (contenido de F5).
- README.md, CHANGELOG.md y docs/fase5/almenara-fase5-checklist.md.
- AGENTS.md y CLAUDE.md (reglas de F5, actualizadas al inicio de la fase).
- docs/fase5/almenara-fase5-implementacion.md (este informe).
## Decisiones técnicas tomadas durante el desarrollo

- **Concurrencia**: el hilo de la TUI sigue siendo el único escritor (ADR-35);
  el agregador solo acumula en memoria y publica lotes; el lector abre su propia
  conexión de solo lectura (ADR-60).
- **Claves del acumulador**: mapa anidado (sujeto, dimensión) → clave → contador
  para buscar por &str sin asignar memoria en cada volcado por flujo y segundo;
  FlowDims::clave devuelve Cow<str>. Esto sostiene el requisito de rendimiento
  de MinuteRollup::add (1,89 millones de llamadas/s medido).
- **Cubos enteros y día local**: segundos Unix UTC en minutos/horas y AAAAMMDD
  local en días (ADR-56); mktime con tm_isdst = -1 resuelve los días de 23, 24 y
  25 horas sin dependencias nuevas (test con Europe/Madrid para los dos cambios
  de hora).
- **Topes**: las claves especiales no cuentan para top_keys y nunca se funden en
  ~otros; el ~otros de una resolución inferior se suma al de la superior.
- **Idempotencia**: la consolidación de una hora o un día borra el cubo y lo
  reconstruye entero en una transacción; el lote del minuto usa upsert que suma.
- **Purga**: los cortes se calculan en history::retention y el DAO los aplica en
  una transacción; el primer minuto sin consolidar acota la purga de minutos y
  se busca por tramos con la clave primaria para no recorrer 48 h de minutos.
- **Instancia única**: flock exclusivo y no bloqueante sobre data.db.lock; el
  kernel lo libera al morir el proceso (sin bloqueos huérfanos).
- **Sesiones**: start/beat/close con RFC 3339 UTC; las abiertas se cierran como
  interrumpidas con ended_at = last_beat; el latido lo da el tick de la TUI y no
  depende de que haya tráfico.
- **CERRADO en DEVICE_SERVICES**: sin columna nueva, la fila se deja STALE de
  forma determinista y el estado se recuerda con el último evento de servicio;
  así no se duplica service_gone y se detecta reopened.
- **Presencia sin tabla de intervalos** (ADR-61): se calcula al vuelo desde
  eventos y sesiones, con los huecos de fuera de sesión como «sin datos».
- **Lector**: hilo std con SQLITE_OPEN_READ_ONLY + query_only, deadline atómico
  para el progress_handler de 2 s y respuesta AppEvent::History con id; la TUI
  descarta las respuestas obsoletas con sus slots.
- **Texto de la interfaz**: todos los resúmenes de la línea de tiempo se
  componen en las consultas (castellano) para que la vista solo pinte; los
  huecos, la presencia y el foco no dependen solo del color (caracteres y «▸»).
- **Medición**: además de la prueba sintética, se añadieron pruebas ignoradas
  para lote del minuto, purga real con retención por defecto, memoria y render,
  de modo que las cifras de §8 son reproducibles en esta máquina.
## Funcionalidades del checklist completadas

Las 141 funcionalidades de docs/fase5/almenara-fase5-checklist.md quedan
marcadas y verificadas. Se copia su texto exacto, agrupado por bloque del
checklist.

### Migración y modelo de datos

- Migración v5 aditiva registrada en `SCHEMA_MIGRATIONS` e idempotente
- Tablas `TRAFFIC_ROLLUP_MINUTE`, `TRAFFIC_ROLLUP_HOUR` y `TRAFFIC_ROLLUP_DAY` con clave primaria (`bucket`, `subject`, `device_id`, `dimension`, `key`) y `WITHOUT ROWID`
- Cubos como enteros: segundos Unix UTC en minutos y horas, fecha local AAAAMMDD en días
- Tabla `DEVICE_SEEN` con `UNIQUE (device_id, kind, key)` y clave ajena a `DEVICES` con borrado en cascada
- Tabla `APP_SESSIONS` con inicio, fin, latido, motivo de cierre, modo, captura, `passive_only` y versión
- `auto_vacuum = INCREMENTAL` aplicado una sola vez con `VACUUM` fuera de la transacción de la migración
- Tipos nuevos de `DEVICE_EVENTS` sin cambio de esquema: `reappeared`, `service_new`, `service_gone`, `os_changed` y `type_changed`
- Rollups de un equipo borrados por el DAO cuando se borra el equipo
- Test de compatibilidad v4 → v5 sin pérdida de datos

### Configuración

- Sección `[history]` con `enabled`, `minute_days`, `hour_days`, `day_days`, `destination_days`, `top_keys` y `max_db_mb` y los valores por defecto del §7.12
- Rangos de `[history]` validados con aviso único y valor por defecto, sin abortar
- Con `[history].enabled = false` no se acumulan ni escriben rollups ni inventario y `w` se salta 1 h y 24 h
- Plantilla de configuración por defecto con `[history]`

### Instancia única y sesiones

- Bloqueo de instancia única con `flock` sobre `data.db.lock` junto a la BD
- Sesión de Almenara abierta al arrancar con modo, captura, `passive_only` y versión
- Latido de la sesión cada minuto, haya tráfico o no
- Cierre de la sesión al salir con `q` y `end_reason = quit`
- Sesiones sin cierre cerradas al arrancar con `ended_at = last_beat` y `end_reason = interrupted`
- Huecos de tráfico (sin sesión o con sesión sin captura) y de presencia (sin sesión) según el §7.6

### Rollups por minuto

- Acumuladores del minuto en curso por sujeto, dimensión y clave, alimentados por el mismo volcado por flujo y segundo que los rankings de F4
- Sujetos `device`, `host`, `other` y `network` con la atribución del §7.1
- Dimensiones `total`, `app`, `category`, `destination`, `protocol`, `process` (solo `host`), `org` y `country`
- Claves especiales `~sin_identificar`, `~lan` y `~desconocido` para que cada dimensión sume el total del sujeto
- Tope de `top_keys` claves normales por sujeto, dimensión y cubo, con el resto sumado en `~otros` y sin fundir las claves especiales
- Conexiones del cubo contadas por flujo nuevo, con la etiqueta que tiene al cerrarse el minuto
- Tope de 20 000 entradas en los acumuladores con suma directa en `~otros` y contador `rollup_overflow`
- Lote del minuto enviado al hilo de la TUI por `AppEvent::Rollup` en el primer tick del minuto siguiente (reloj UTC)
- Escritura del lote en una transacción, con suma si el minuto ya existe
- Reintento de lotes fallidos en el minuto siguiente, hasta 10 pendientes, y descarte del más antiguo con contador `rollup_drops` y aviso único
- Minuto parcial escrito al salir con `q`, antes de cerrar la sesión

### Consolidación por hora y día

- Construcción de cada hora cerrada desde sus minutos, con topes y `~otros`
- Construcción de cada día local cerrado desde sus horas, sin la dimensión `destination`
- Días de 23 y 25 horas en los cambios de hora construidos con sus horas reales
- Horas y días pendientes construidos al arrancar y tras cada lote, en tandas de 10 por segundo, sin bloquear la TUI
- Construcción idempotente: rehacer una hora o un día da el mismo resultado

### Retención, purga y tamaño

- Purga horaria por resolución con la retención de `[history]`: minutos 48 h, horas 90 días y días 2 años
- Destinos: minutos 2 h, horas `destination_days` (30 días) y nunca en días
- Ningún minuto de una hora sin consolidar se purga
- Inventario y sesiones purgados con la retención de días; eventos con `events_retention_days` de F1
- `incremental_vacuum` tras cada purga, con 2000 páginas como mucho
- Aviso único por sesión cuando la BD supera `max_db_mb`

### Eventos nuevos

- Evento `reappeared` al volver a ONLINE un equipo OFFLINE, con `away_since` y `away_s`
- `disappeared` con `last_seen` en sus detalles
- `service_new` cuando un escaneo de puertos ve abierto un puerto nuevo, o que estaba cerrado (`reopened`), en un equipo ya escaneado
- `service_gone` cuando un escaneo de puertos ve cerrado un puerto que estaba abierto
- Sin eventos de servicios en el primer escaneo de un equipo ni con `passive_only`
- `os_changed` cuando `os_family` cambia entre dos valores no nulos, con antes, después y `os_source`
- `type_changed` cuando el `device_type` automático cambia entre dos valores conocidos; el override manual no genera evento

### Presencia

- Presencia por equipo calculada al vuelo desde `new`, `disappeared`, `reappeared` y las sesiones
- Tiempo sin sesión mostrado como «sin datos», nunca como presente ni ausente
- Equipo que se fue con Almenara cerrada marcado ausente desde el inicio de la sesión
- Fila de presencia de 24 h (celdas de 30 min) y rejilla de 7 días (7 filas de 24 horas) en el detalle de equipo

### Inventario por equipo

- `DEVICE_SEEN` alimentado cada minuto con apps, categorías, organizaciones, países y JA4 de cada equipo, antes de aplicar los topes
- Primera y última vez por clave; las claves especiales, los destinos y el propio equipo no entran
- Puertos abiertos del inventario leídos de `DEVICE_SERVICES` con su `first_seen`
- Bloque «Visto en este equipo» en el detalle con recuentos, lo nuevo de los últimos 7 días y la fecha de inicio

### Lector del histórico

- Hilo lector con conexión de solo lectura (`SQLITE_OPEN_READ_ONLY` y `query_only`), lanzado después de las migraciones
- Peticiones con identificador y respuesta por `AppEvent::History`; la TUI descarta las respuestas obsoletas
- Consulta cortada a los 2 s con `progress_handler` y error mostrado en la vista sin bloquear la TUI
- El render nunca consulta la BD: pinta el último resultado recibido

### TUI: Histórico

- Pestaña Histórico con sujeto (toda la red, este equipo o un equipo) y rango (24 h, 7 días, 30 días o 1 año)
- Selector de sujeto con `e` y búsqueda con `/`
- Rango con `w`: 24 h → 7 días → 30 días → 1 año
- Gráfica de tráfico con la resolución del §7.11 y bajada, subida y máximo del rango en la cabecera
- Huecos dibujados con `░`, nunca interpolados, y tiempo futuro en blanco
- Cursor de la gráfica con `<` y `>` que muestra en texto la fecha, la bajada y la subida del punto
- Bloque «Más tráfico»: equipos y apps en la red; apps, destinos, organizaciones y países en un equipo
- Destinos solo en rangos de hasta 30 días, con aviso en «1 año»
- Línea de tiempo de eventos y sesiones del rango, más recientes primero
- Filtro de eventos con `f` (todos, altas y presencia, identidad, servicios, Almenara) y búsqueda con `/`
- `Tab` cambia el foco entre gráfica, «Más tráfico» y «Eventos»; `Enter` sobre un equipo o un evento abre el detalle del equipo
- Mensajes «Sin datos en este rango», «Cargando…» e histórico desactivado

### TUI: Tráfico

- Ventanas de 1 h y 24 h en el ciclo de `w`: 60 s → 5 min → 1 h → 24 h → sesión
- Rankings de 1 h y 24 h en todas las agrupaciones, en volumen y con minutos cerrados
- Pie con «Minutos cerrados hasta HH:MM» y los huecos de la ventana
- «¿Quién lo usa?» en 1 h y 24 h desde el histórico

### TUI: Detalle, Equipos, Config y Ayuda

- Detalle de equipo con fila de tráfico y fila de presencia sobre el mismo eje, 24 h y 7 días alternables con `w`
- Línea «Último evento» en Equipos, también tras un arranque
- Config con `[history]`, tamaño de la BD y del WAL, inicio de los datos, última purga y cobertura de 30 días, resaltado por encima de `max_db_mb`
- Ayuda con las teclas nuevas (`e`, `w`, `<`, `>`, `f` en Histórico; `w` en Tráfico y en el detalle)
- Ayuda con el aviso de privacidad del histórico (qué se guarda, cuánto tiempo, que la presencia de un móvil es la de su dueño) y cómo desactivarlo

### Privacidad

- El histórico nunca guarda contenido ni nombres completos: el destino es el dominio registrable, la IP o el equipo de la LAN
- Sin registro de conexiones: solo agregados
- Ningún destino en los días ni en el inventario
- Dominios y claves del histórico solo en logs de nivel `debug`
- Consultas con parámetros: ninguna clave venida de la red se concatena en el SQL

### Rendimiento

- Escritura del lote del minuto ≤ 10 ms con 50 equipos (medido)
- Construcción de una hora ≤ 50 ms y de un día ≤ 100 ms (medido)
- Purga + `incremental_vacuum` ≤ 100 ms por ejecución (medido)
- Consultas del lector ≤ 200 ms hasta 30 días y ≤ 500 ms en 1 año con 2 años de histórico sintético (medido)
- BD ≤ 300 MB con la retención por defecto y el perfil de referencia del §7.14 (medido)
- Memoria añadida ≤ 16 MB con los topes del §8
- `MinuteRollup::add` ≥ 1 millón de llamadas por segundo en un núcleo (medido)
- Render sin cambios (≤ 16 ms en 80×24, ≤ 33 ms en 120×40) con Histórico abierto

### Pruebas

- Tests de acumuladores, topes, `~otros` y claves especiales en los que los totales cuadran
- Tests de consolidación de horas y días, incluidos los cambios de hora
- Tests de purga por resolución y de que no se purgan minutos sin consolidar
- Tests de sesiones, huecos, cierre interrumpido e instancia única
- Tests de eventos nuevos y de presencia
- Tests del inventario
- Tests de las consultas del lector con datos sintéticos, incluidas las respuestas obsoletas
- Prueba ignorada `medir_historial` con el perfil de referencia y sus cifras en el informe de implementación
- `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings` limpios

### Documentación y versión

- README: histórico, retención, privacidad y cómo copiar la BD con Almenara en marcha (`.backup` o `VACUUM INTO`)
- README: dejar Almenara abierta (p. ej. en tmux) para tener histórico continuo, e instancia única
- Versión 0.5.0 en `Cargo.toml` y en Ayuda
- Novedades de la 0.5.0 en `CHANGELOG.md`

### Servicios internos (API)

- `MinuteRollup::add` — suma a sujetos, dimensiones y claves
- `MinuteRollup::add_flow` — cuenta un flujo nuevo
- `MinuteRollup::flush` — cierre del minuto con topes e inventario
- `Rankings::tick` — (extendido) cierre del minuto y `AppEvent::Rollup`
- `Repo::insert_minute_batch` — lote del minuto con suma
- `Repo::upsert_seen` — inventario por equipo
- `Repo::build_hour` — consolidación de una hora
- `Repo::build_day` — consolidación de un día local
- `Repo::pending_hours` — horas sin consolidar
- `Repo::pending_days` — días sin consolidar
- `Repo::purge_history` — purga por resolución
- `Repo::incremental_vacuum` — compactación
- `Repo::open_session` — sesión de Almenara
- `Repo::beat_session` — latido por minuto
- `Repo::close_session` — cierre con `quit`
- `Repo::close_open_sessions` — cierre de sesiones interrumpidas
- `Changes::presence` — `reappeared`
- `Changes::services` — `service_new` y `service_gone`
- `Changes::identity` — `os_changed` y `type_changed`
- `HistoryReader::spawn` — hilo lector de solo lectura
- `HistoryHandle::query` — consulta con identificador
- `Queries::series` — serie de tráfico con huecos
- `Queries::top` — «Más tráfico» del rango
- `Queries::window_ranking` — ranking de 1 h y 24 h
- `Queries::who_uses` — «¿Quién lo usa?» en 1 h y 24 h
- `Queries::timeline` — eventos y sesiones
- `Queries::presence` — tramos de presencia
- `Queries::inventory` — inventario y puertos
- `Queries::coverage` — huecos del rango
- `Queries::last_event` — último evento
- `Queries::db_stats` — tamaño, inicio y cobertura
- `Instance::acquire` — bloqueo de instancia única
- `Synthetic::generate` — histórico sintético
- `config::load` — (extendido) `[history]`

## Pendientes y bloqueos

- **No hay pendientes de la Fase 5**: las 141 funcionalidades del checklist
  están implementadas, probadas y marcadas; cargo test, cargo fmt --check y
  cargo clippy --all-targets -- -D warnings están limpios.
- Las **9 casillas de F4** de la pasada con CAP_NET_RAW siguen abiertas: no son
  de esta fase (decisión del desarrollador del 2026-11-11, respuesta 1c). El
  riesgo queda anotado en el maestro, como ya estaba.
- **Entrega**: el desarrollador debe entregar este informe al analista
  funcional antes de especificar la Fase 6; hasta entonces la documentación
  maestra (checklist e informe maestros) no refleja la realidad de F5.
- **Fuera de alcance** (no son bloqueos): el modo servicio sin TUI para
  histórico continuo queda en el roadmap (ADR-59) y la exportación CSV en F7.
- No hay bloqueos técnicos conocidos: la captura real no se ha necesitado para
  F5 (las mediciones usan histórico sintético y la app funciona en degradado).
## Ejecución y pruebas (cómo arrancar, migrar y testear)

### Arranque y migración

- Arranque normal: cargo run. La primera vez que se abre una BD de F4 se aplica
  la migración v5 aditiva (tablas del histórico, inventario y sesiones, más
  auto_vacuum = INCREMENTAL con un único VACUUM) sin perder ninguna fila.
- Arranque con captura real: scripts/ejecutar-con-permisos.sh (el setcap
  necesita el sudo del desarrollador; no recompilar después).
- Instancia única: data.db.lock junto a la BD; la segunda instancia muestra
  «Almenara ya está en marcha (PID n)» y sale con código 1 sin abrir la BD.
- Copia de la BD con Almenara abierta: sqlite3 data.db ".backup copia.db" o
  VACUUM INTO; con Almenara cerrada basta copiar data.db (y -wal/-shm si no se
  cerró limpiamente). Para tener histórico continuo, dejar la TUI abierta (por
  ejemplo en tmux): el modo servicio queda en el roadmap.

### Pruebas

- cargo test: 959 tests unitarios y 4 de tests/cli, 0 fallos; 9 tests ignorados
  son las mediciones y los replays/real que necesitan red o CAP_NET_RAW.
- cargo fmt --check: limpio. cargo clippy --all-targets -- -D warnings: limpio.
- Cobertura de F5: migración v4 → v5 sin pérdida de datos e idempotencia,
  acumuladores y topes con totales que cuadran, consolidación de horas y días
  (incluidos los días de 23 y 25 horas), purga por resolución sin tocar minutos
  sin consolidar, sesiones y cierre interrumpido, instancia única, eventos nuevos
  (reappeared, servicios con reopened y sin duplicados, SO y tipo), presencia con
  ida y vuelta y huecos, inventario con puertos cerrados, las diez consultas del
  lector con datos sintéticos y el descarte de respuestas obsoletas en la TUI.

### Mediciones (release, perfil de referencia §7.14)

```bash
cargo test --release --bin almenara -- --ignored --nocapture --test-threads=1
```

Las cifras obtenidas están en la tabla del resumen. Desglose de las pruebas
ignoradas que las producen:

- medir_historial: perfil de 30 equipos, 730 días, 90 días de horas y 48 h de
  minutos; generación 1,21 s, BD 75,5 MB, 1 727 733 filas; construir hora
  4,26 ms y día 4,86 ms; consultas 24 h 6,27 ms, 7 d 2,99 ms, 30 d 0,36 ms y
  1 año 4,03 ms; top de apps 6,82 ms.
- medir_minute_rollup: 1 892 142 llamadas/s.
- medir_lote_minuto: 8000 filas en 5,05 ms.
- medir_purga_historial_real: 34,41 ms con la retención por defecto (en el test
  sintético, que borra a propósito 1 044 070 filas, la cifra es 166 ms y queda
  explicada en las desviaciones).
- medir_memoria_historial: 2,48 MB de acumuladores + 8,82 MB de diez lotes
  pendientes = 11,30 MB.
- medir_render_historico: 0,083 ms de media en 80×24 y 0,222 ms en 120×40.

### Comprobaciones manuales pendientes de la pasada con CAP_NET_RAW

F5 no requiere captura real para funcionar: sin CAP_NET_RAW la app arranca en
modo degradado, el histórico deja huecos (sesiones sin captura) y todo lo demás
(eventos, presencia, inventario del escaneo pasivo, histórico sintético) se
puede verificar. La pasada con privilegios de F4 (9 casillas) sigue siendo la
única pendiente del proyecto antes de F6.
