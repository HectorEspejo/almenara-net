# Almenara - Checklist Fase 5: Histórico, rollups y eventos

## Migración y modelo de datos
- [x] Migración v5 aditiva registrada en `SCHEMA_MIGRATIONS` e idempotente
  - AC: Dada una BD ya en v5, cuando la aplicación arranca otra vez, entonces no se recrea ninguna tabla ni se repite el `VACUUM`
- [x] Tablas `TRAFFIC_ROLLUP_MINUTE`, `TRAFFIC_ROLLUP_HOUR` y `TRAFFIC_ROLLUP_DAY` con clave primaria (`bucket`, `subject`, `device_id`, `dimension`, `key`) y `WITHOUT ROWID`
- [x] Cubos como enteros: segundos Unix UTC en minutos y horas, fecha local AAAAMMDD en días
- [x] Tabla `DEVICE_SEEN` con `UNIQUE (device_id, kind, key)` y clave ajena a `DEVICES` con borrado en cascada
- [x] Tabla `APP_SESSIONS` con inicio, fin, latido, motivo de cierre, modo, captura, `passive_only` y versión
- [x] `auto_vacuum = INCREMENTAL` aplicado una sola vez con `VACUUM` fuera de la transacción de la migración
- [x] Tipos nuevos de `DEVICE_EVENTS` sin cambio de esquema: `reappeared`, `service_new`, `service_gone`, `os_changed` y `type_changed`
- [x] Rollups de un equipo borrados por el DAO cuando se borra el equipo
- [x] Test de compatibilidad v4 → v5 sin pérdida de datos
  - AC: Dada una BD de F4 con equipos, servicios, eventos, conexiones y caché de nombres, cuando se abre con F5, entonces todas las filas se conservan y las tablas nuevas quedan vacías

## Configuración
- [x] Sección `[history]` con `enabled`, `minute_days`, `hour_days`, `day_days`, `destination_days`, `top_keys` y `max_db_mb` y los valores por defecto del §7.12
- [x] Rangos de `[history]` validados con aviso único y valor por defecto, sin abortar
  - AC: Dado `hour_days = 2`, cuando arranca, entonces avisa una vez y usa 90
- [x] Con `[history].enabled = false` no se acumulan ni escriben rollups ni inventario y `w` se salta 1 h y 24 h
- [x] Plantilla de configuración por defecto con `[history]`

## Instancia única y sesiones
- [x] Bloqueo de instancia única con `flock` sobre `data.db.lock` junto a la BD
  - AC: Dada una Almenara en marcha, cuando se arranca otra con la misma BD, entonces la segunda muestra «Almenara ya está en marcha (PID n)» y sale con código 1 sin abrir la BD
- [x] Sesión de Almenara abierta al arrancar con modo, captura, `passive_only` y versión
- [x] Latido de la sesión cada minuto, haya tráfico o no
- [x] Cierre de la sesión al salir con `q` y `end_reason = quit`
- [x] Sesiones sin cierre cerradas al arrancar con `ended_at = last_beat` y `end_reason = interrupted`
  - AC: Dada una sesión con `ended_at` NULL y último latido a las 10:41, cuando Almenara arranca, entonces la sesión queda cerrada a las 10:41 como interrumpida
- [x] Huecos de tráfico (sin sesión o con sesión sin captura) y de presencia (sin sesión) según el §7.6

## Rollups por minuto
- [x] Acumuladores del minuto en curso por sujeto, dimensión y clave, alimentados por el mismo volcado por flujo y segundo que los rankings de F4
- [x] Sujetos `device`, `host`, `other` y `network` con la atribución del §7.1
  - AC: Dado un flujo entre un portátil y el NAS de la LAN, cuando se cierra el minuto, entonces los dos suman en su `total`, el flujo cuenta una vez en las demás dimensiones (para el equipo de su columna «Equipo») y una vez en el `total` de `network`
- [x] Dimensiones `total`, `app`, `category`, `destination`, `protocol`, `process` (solo `host`), `org` y `country`
- [x] Claves especiales `~sin_identificar`, `~lan` y `~desconocido` para que cada dimensión sume el total del sujeto
- [x] Tope de `top_keys` claves normales por sujeto, dimensión y cubo, con el resto sumado en `~otros` y sin fundir las claves especiales
  - AC: Dado un equipo con 30 destinos en un minuto, cuando se cierra el minuto, entonces se escriben los 20 con más bytes y `~otros`, y la suma coincide con el total del equipo
- [x] Conexiones del cubo contadas por flujo nuevo, con la etiqueta que tiene al cerrarse el minuto
- [x] Tope de 20 000 entradas en los acumuladores con suma directa en `~otros` y contador `rollup_overflow`
- [x] Lote del minuto enviado al hilo de la TUI por `AppEvent::Rollup` en el primer tick del minuto siguiente (reloj UTC)
- [x] Escritura del lote en una transacción, con suma si el minuto ya existe
- [x] Reintento de lotes fallidos en el minuto siguiente, hasta 10 pendientes, y descarte del más antiguo con contador `rollup_drops` y aviso único
- [x] Minuto parcial escrito al salir con `q`, antes de cerrar la sesión

## Consolidación por hora y día
- [x] Construcción de cada hora cerrada desde sus minutos, con topes y `~otros`
  - AC: Dados 60 minutos con 30 apps distintas para un equipo, cuando se construye la hora, entonces quedan 20 apps, `~otros` y las claves especiales, y la suma coincide con la de los minutos
- [x] Construcción de cada día local cerrado desde sus horas, sin la dimensión `destination`
- [x] Días de 23 y 25 horas en los cambios de hora construidos con sus horas reales
  - AC: Dado el domingo del cambio de hora de octubre, cuando se construye su día, entonces suma 25 horas
- [x] Horas y días pendientes construidos al arrancar y tras cada lote, en tandas de 10 por segundo, sin bloquear la TUI
- [x] Construcción idempotente: rehacer una hora o un día da el mismo resultado

## Retención, purga y tamaño
- [x] Purga horaria por resolución con la retención de `[history]`: minutos 48 h, horas 90 días y días 2 años
- [x] Destinos: minutos 2 h, horas `destination_days` (30 días) y nunca en días
  - AC: Dada una BD con destinos por hora de hace 31 días, cuando corre la purga, entonces desaparecen y siguen las apps de esas horas
- [x] Ningún minuto de una hora sin consolidar se purga
- [x] Inventario y sesiones purgados con la retención de días; eventos con `events_retention_days` de F1
- [x] `incremental_vacuum` tras cada purga, con 2000 páginas como mucho
- [x] Aviso único por sesión cuando la BD supera `max_db_mb`

## Eventos nuevos
- [x] Evento `reappeared` al volver a ONLINE un equipo OFFLINE, con `away_since` y `away_s`
- [x] `disappeared` con `last_seen` en sus detalles
- [x] `service_new` cuando un escaneo de puertos ve abierto un puerto nuevo, o que estaba cerrado (`reopened`), en un equipo ya escaneado
- [x] `service_gone` cuando un escaneo de puertos ve cerrado un puerto que estaba abierto
  - AC: Dado el NAS con 445/tcp abierto, cuando un escaneo bajo demanda lo ve cerrado, entonces se emite `service_gone` con puerto y protocolo; si el puerto solo pasa a STALE por tiempo, no hay evento
- [x] Sin eventos de servicios en el primer escaneo de un equipo ni con `passive_only`
- [x] `os_changed` cuando `os_family` cambia entre dos valores no nulos, con antes, después y `os_source`
- [x] `type_changed` cuando el `device_type` automático cambia entre dos valores conocidos; el override manual no genera evento

## Presencia
- [x] Presencia por equipo calculada al vuelo desde `new`, `disappeared`, `reappeared` y las sesiones
  - AC: Dado un móvil que se fue a las 8:00 y volvió a las 18:30 con Almenara abierta todo el día, cuando se abre su detalle, entonces la presencia de 24 h lo muestra ausente entre esas horas
- [x] Tiempo sin sesión mostrado como «sin datos», nunca como presente ni ausente
- [x] Equipo que se fue con Almenara cerrada marcado ausente desde el inicio de la sesión
- [x] Fila de presencia de 24 h (celdas de 30 min) y rejilla de 7 días (7 filas de 24 horas) en el detalle de equipo

## Inventario por equipo
- [x] `DEVICE_SEEN` alimentado cada minuto con apps, categorías, organizaciones, países y JA4 de cada equipo, antes de aplicar los topes
- [x] Primera y última vez por clave; las claves especiales, los destinos y el propio equipo no entran
- [x] Puertos abiertos del inventario leídos de `DEVICE_SERVICES` con su `first_seen`
- [x] Bloque «Visto en este equipo» en el detalle con recuentos, lo nuevo de los últimos 7 días y la fecha de inicio

## Lector del histórico
- [x] Hilo lector con conexión de solo lectura (`SQLITE_OPEN_READ_ONLY` y `query_only`), lanzado después de las migraciones
- [x] Peticiones con identificador y respuesta por `AppEvent::History`; la TUI descarta las respuestas obsoletas
- [x] Consulta cortada a los 2 s con `progress_handler` y error mostrado en la vista sin bloquear la TUI
- [x] El render nunca consulta la BD: pinta el último resultado recibido

## TUI: Histórico
- [x] Pestaña Histórico con sujeto (toda la red, este equipo o un equipo) y rango (24 h, 7 días, 30 días o 1 año)
- [x] Selector de sujeto con `e` y búsqueda con `/`
- [x] Rango con `w`: 24 h → 7 días → 30 días → 1 año
- [x] Gráfica de tráfico con la resolución del §7.11 y bajada, subida y máximo del rango en la cabecera
- [x] Huecos dibujados con `░`, nunca interpolados, y tiempo futuro en blanco
- [x] Cursor de la gráfica con `<` y `>` que muestra en texto la fecha, la bajada y la subida del punto
- [x] Bloque «Más tráfico»: equipos y apps en la red; apps, destinos, organizaciones y países en un equipo
- [x] Destinos solo en rangos de hasta 30 días, con aviso en «1 año»
- [x] Línea de tiempo de eventos y sesiones del rango, más recientes primero
- [x] Filtro de eventos con `f` (todos, altas y presencia, identidad, servicios, Almenara) y búsqueda con `/`
- [x] `Tab` cambia el foco entre gráfica, «Más tráfico» y «Eventos»; `Enter` sobre un equipo o un evento abre el detalle del equipo
- [x] Mensajes «Sin datos en este rango», «Cargando…» e histórico desactivado

## TUI: Tráfico
- [x] Ventanas de 1 h y 24 h en el ciclo de `w`: 60 s → 5 min → 1 h → 24 h → sesión
- [x] Rankings de 1 h y 24 h en todas las agrupaciones, en volumen y con minutos cerrados
  - AC: Dada la agrupación por destino en 24 h, cuando se cierra un minuto, entonces el ranking se refresca e incluye ese minuto
- [x] Pie con «Minutos cerrados hasta HH:MM» y los huecos de la ventana
- [x] «¿Quién lo usa?» en 1 h y 24 h desde el histórico

## TUI: Detalle, Equipos, Config y Ayuda
- [x] Detalle de equipo con fila de tráfico y fila de presencia sobre el mismo eje, 24 h y 7 días alternables con `w`
- [x] Línea «Último evento» en Equipos, también tras un arranque
- [x] Config con `[history]`, tamaño de la BD y del WAL, inicio de los datos, última purga y cobertura de 30 días, resaltado por encima de `max_db_mb`
- [x] Ayuda con las teclas nuevas (`e`, `w`, `<`, `>`, `f` en Histórico; `w` en Tráfico y en el detalle)
- [x] Ayuda con el aviso de privacidad del histórico (qué se guarda, cuánto tiempo, que la presencia de un móvil es la de su dueño) y cómo desactivarlo

## Privacidad
- [x] El histórico nunca guarda contenido ni nombres completos: el destino es el dominio registrable, la IP o el equipo de la LAN
- [x] Sin registro de conexiones: solo agregados
- [x] Ningún destino en los días ni en el inventario
- [x] Dominios y claves del histórico solo en logs de nivel `debug`
- [x] Consultas con parámetros: ninguna clave venida de la red se concatena en el SQL

## Rendimiento
- [x] Escritura del lote del minuto ≤ 10 ms con 50 equipos (medido)
- [x] Construcción de una hora ≤ 50 ms y de un día ≤ 100 ms (medido)
- [x] Purga + `incremental_vacuum` ≤ 100 ms por ejecución (medido)
- [x] Consultas del lector ≤ 200 ms hasta 30 días y ≤ 500 ms en 1 año con 2 años de histórico sintético (medido)
- [x] BD ≤ 300 MB con la retención por defecto y el perfil de referencia del §7.14 (medido)
- [x] Memoria añadida ≤ 16 MB con los topes del §8
- [x] `MinuteRollup::add` ≥ 1 millón de llamadas por segundo en un núcleo (medido)
- [x] Render sin cambios (≤ 16 ms en 80×24, ≤ 33 ms en 120×40) con Histórico abierto

## Pruebas
- [x] Tests de acumuladores, topes, `~otros` y claves especiales en los que los totales cuadran
- [x] Tests de consolidación de horas y días, incluidos los cambios de hora
- [x] Tests de purga por resolución y de que no se purgan minutos sin consolidar
- [x] Tests de sesiones, huecos, cierre interrumpido e instancia única
- [x] Tests de eventos nuevos y de presencia
- [x] Tests del inventario
- [x] Tests de las consultas del lector con datos sintéticos, incluidas las respuestas obsoletas
- [x] Prueba ignorada `medir_historial` con el perfil de referencia y sus cifras en el informe de implementación
- [x] `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings` limpios

## Documentación y versión
- [x] README: histórico, retención, privacidad y cómo copiar la BD con Almenara en marcha (`.backup` o `VACUUM INTO`)
- [x] README: dejar Almenara abierta (p. ej. en tmux) para tener histórico continuo, e instancia única
- [x] Versión 0.5.0 en `Cargo.toml` y en Ayuda
- [x] Novedades de la 0.5.0 en `CHANGELOG.md`

## Servicios internos (API)
- [x] `MinuteRollup::add` — suma a sujetos, dimensiones y claves
- [x] `MinuteRollup::add_flow` — cuenta un flujo nuevo
- [x] `MinuteRollup::flush` — cierre del minuto con topes e inventario
- [x] `Rankings::tick` — (extendido) cierre del minuto y `AppEvent::Rollup`
- [x] `Repo::insert_minute_batch` — lote del minuto con suma
- [x] `Repo::upsert_seen` — inventario por equipo
- [x] `Repo::build_hour` — consolidación de una hora
- [x] `Repo::build_day` — consolidación de un día local
- [x] `Repo::pending_hours` — horas sin consolidar
- [x] `Repo::pending_days` — días sin consolidar
- [x] `Repo::purge_history` — purga por resolución
- [x] `Repo::incremental_vacuum` — compactación
- [x] `Repo::open_session` — sesión de Almenara
- [x] `Repo::beat_session` — latido por minuto
- [x] `Repo::close_session` — cierre con `quit`
- [x] `Repo::close_open_sessions` — cierre de sesiones interrumpidas
- [x] `Changes::presence` — `reappeared`
- [x] `Changes::services` — `service_new` y `service_gone`
- [x] `Changes::identity` — `os_changed` y `type_changed`
- [x] `HistoryReader::spawn` — hilo lector de solo lectura
- [x] `HistoryHandle::query` — consulta con identificador
- [x] `Queries::series` — serie de tráfico con huecos
- [x] `Queries::top` — «Más tráfico» del rango
- [x] `Queries::window_ranking` — ranking de 1 h y 24 h
- [x] `Queries::who_uses` — «¿Quién lo usa?» en 1 h y 24 h
- [x] `Queries::timeline` — eventos y sesiones
- [x] `Queries::presence` — tramos de presencia
- [x] `Queries::inventory` — inventario y puertos
- [x] `Queries::coverage` — huecos del rango
- [x] `Queries::last_event` — último evento
- [x] `Queries::db_stats` — tamaño, inicio y cobertura
- [x] `Instance::acquire` — bloqueo de instancia única
- [x] `Synthetic::generate` — histórico sintético
- [x] `config::load` — (extendido) `[history]`

---

**Progreso Fase 5:** 141 / 141 funcionalidades

**Total Almenara (Fases 1-5):** 556 / 565 funcionalidades (F1–F3: 248; F4: 167 de 176, con la pasada con `CAP_NET_RAW` pendiente; F5: 141 de 141)