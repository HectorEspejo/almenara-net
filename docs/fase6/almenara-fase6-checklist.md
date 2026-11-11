# Almenara - Checklist Fase 6: Alertas (locales + escritorio)

## Sprint 6.0 — Verificación con tráfico real
- [x] Pasada con `CAP_NET_RAW` hecha: el desarrollador aplica la capacidad con `scripts/ejecutar-con-permisos.sh` y las 9 casillas abiertas de `almenara-fase4-checklist.md` quedan marcadas o anotadas con su motivo
  - AC: Dado el binario con la capacidad aplicada, cuando el agente mide sin recompilar, entonces cada una de las 9 casillas de F4 queda marcada en su checklist o anotada en el informe de implementación de F6 con lo medido
- [x] Histórico de F5 con captura real: tras 2 h capturando, los minutos tienen claves reales de app, categoría, organización y país del propio equipo
  - AC: Dadas 2 h de captura real, cuando se suman los minutos del sujeto `host`, entonces cuadran con el acumulado de sesión de F4 (±2 %)
- [x] Ventanas de 1 h y 24 h de Tráfico y pestaña Histórico con datos reales tras una hora de captura
- [x] Escritura del lote del minuto con tráfico real ≤ 10 ms, medida en el log `debug` durante la pasada
- [x] Hueco real: cerrar Almenara 10 minutos y volver a abrirla marca el hueco en Histórico y en la presencia
- [x] Inventario `DEVICE_SEEN` con datos reales en los equipos con tráfico visible, anotado en el informe de implementación

## Migración y modelo de datos
- [x] Migración v6 aditiva e idempotente con `ALERTS`, `ALERT_MUTES`, `ALERT_LEARNING`, `HOST_SEEN`, `COVERAGE_GAPS` y sus índices
  - AC: Dada una BD de F5, cuando se abre dos veces con la 0.6.0, entonces las tablas nuevas existen una sola vez y ningún dato de F1–F5 cambia
- [x] Columna `DEVICES.watched` con valor 0 por defecto
- [x] Columna `DEVICE_SERVICES.closed_at` rellenada en la migración para los puertos cuyo último evento de servicio es `service_gone`
  - AC: Dado un puerto cuyo último evento de servicio es un `service_gone` del 4 nov, cuando corre la migración, entonces `closed_at` es esa fecha y `last_seen` no cambia
- [x] Aprendizaje inicial de los equipos existentes desde el histórico de F5 (días con datos de `TRAFFIC_ROLLUP_DAY` y `APP_SESSIONS`)
  - AC: Dado un equipo con 8 días con datos en F5, cuando corre la migración, entonces queda aprendido con `learned_at` al final de su 7.º día con datos
- [x] Fila de aprendizaje del propio equipo creada en la migración con `learning_from` igual a la fecha de la v6 y sin días contados
- [x] Fila de aprendizaje de cada equipo nuevo creada con su evento `new` y `learning_from` igual a su `first_seen`
- [x] Test de compatibilidad v5 → v6 sin pérdida de datos
- [x] Sin `CHECK` en `rule`, `level`, `subject` ni `kind`: se validan en el código
- [x] Al borrar un equipo, sus alertas quedan con `device_id = NULL` y el DAO borra sus silencios y su aprendizaje

## Configuración
- [x] Sección `[alerts]` con `[alerts.traffic_high]`, `[alerts.capture_drops]` y `[alerts.rules]` y los valores por defecto del §7.14 en la plantilla
- [x] Validación tolerante de `[alerts]` con aviso único y valor por defecto, sin abortar el arranque
  - AC: Dado `factor = 0`, cuando arranca, entonces usa 3,0, avisa una vez y sigue
- [x] Reglas desconocidas en `[alerts.rules]` avisadas una vez e ignoradas; reglas que faltan con sus valores por defecto
- [x] `quiet_hours` vacío o «HH:MM-HH:MM» en hora local, también cruzando la medianoche
  - AC: Dado `quiet_hours = "23:00-08:00"`, cuando son las 02:10, entonces el horario silencioso está activo; a las 08:00, no
- [x] Con `[alerts].enabled = false` no se crean alertas, el contador se oculta y las guardadas se siguen viendo
- [x] Activar, apagar o cambiar el nivel de una regla desde la TUI reescribe `config.toml` como `[ui]` (F2); si no puede escribir, avisa una vez y vale para la sesión

## Motor de alertas
- [x] Motor puro en `src/alerts/`: recibe señales y devuelve acciones sin abrir la BD ni la TUI
  - AC: Dado un test sin BD, cuando se le pasan las señales de un equipo nuevo, entonces devuelve una acción de crear y otra de notificar
- [x] El hilo de la TUI aplica las acciones del motor (único escritor) y entrega las notificaciones al notificador
- [x] Las alertas nacen de señales en vivo: lo anterior a la v6 y las horas pendientes que se construyen al arrancar no crean alertas
- [x] Una regla apagada o silenciada no crea alertas; un sujeto que aprende no crea alertas de lo nuevo
- [x] La misma regla, sujeto, equipo y clave dentro de 24 h suma `count` y `last_at` en la misma fila, sin notificar
  - AC: Dada una alerta de «más tráfico de lo habitual» creada a las 10:00, cuando vuelve a saltar a las 11:00, entonces hay una sola fila con `count = 2`
- [x] El plazo de 24 h se cuenta desde `created_at`: una anomalía que dura varios días crea una alerta por día
- [x] Alertas de condición resueltas al desaparecer la condición y reactivadas en su fila si vuelve dentro de las 24 h
- [x] Apagar una regla resuelve sus alertas de condición activas
- [x] Estado del motor al arrancar desde `Repo::engine_snapshot`: reiniciar Almenara no repite alertas de las últimas 24 h
- [x] Línea base: con `DEVICES` vacía al arrancar, los equipos nuevos del primer ciclo de escaneo completo no crean alertas
- [x] Una alerta que no se puede escribir se reintenta en el minuto siguiente con aviso único

## Reglas
- [x] Regla «Equipo nuevo» (`device_new`) desde el evento `new`, importante con MAC fija y aviso con MAC privada
  - AC: Dado un equipo nuevo con `mac_random`, cuando llega su evento `new`, entonces la alerta es de nivel aviso y no notifica
- [x] Regla «Puerto nuevo» (`port_new`) desde `service_new`, también para los puertos reabiertos
- [x] Regla «Cambio de MAC» (`mac_changed`) con el motivo de F4
- [x] Reglas «Cambio de nombre», «Cambio de SO» y «Cambio de tipo» (`name_changed`, `os_changed`, `type_changed`); los cambios de IP no avisan
- [x] Reglas de lo nuevo (`new_app`, `new_category`, `new_country`, `new_org`, `new_ja4`) desde las entradas nuevas del inventario de un sujeto aprendido
  - AC: Dado el propio equipo aprendido, cuando un lote trae la app `steam` por primera vez, entonces se crea «App nueva: Steam» de nivel info
- [x] Las claves especiales (`~…`) y los destinos nunca son la clave de una alerta
- [x] Regla «Más tráfico de lo habitual» (`traffic_high`) para equipos, propio equipo y red, con bajada y subida por separado
- [x] Regla «Vigilado ausente o de vuelta» (`watched_presence`) solo para equipos vigilados
  - AC: Dado `nas` vigilado, cuando llega su `disappeared`, entonces se crea una alerta de condición que su `reappeared` resuelve, y se crea otra «de vuelta tras N min»
- [x] «Vigilado ausente» marca `while_closed` si el equipo se fue mientras Almenara estaba cerrada
- [x] Desmarcar un equipo vigilado resuelve su alerta de ausencia activa
- [x] Regla «Captura parada» (`capture_stopped`) con `CAP_NET_RAW` y la captura activada; en modo degradado no salta
- [x] Regla «Pérdidas de captura» (`capture_drops`) con más del 1 % durante 5 minutos seguidos y resuelta tras 5 minutos por debajo
- [x] Regla «Base de datos grande» (`db_size`) tras la purga horaria, por encima de `max_db_mb`
- [x] Título y `details` de cada regla según el §7.1

## Aprendizaje
- [x] Día con datos: día local con al menos 1 h de cobertura de tráfico y tráfico del sujeto en `TRAFFIC_ROLLUP_DAY`
- [x] Al consolidar un día local, `data_days` sube en los sujetos con datos y `learned_at` se fija al llegar a `learning_days`
- [x] Un sujeto aprendido no vuelve a aprender, aunque se purguen datos o cambie `learning_days`
- [x] Los días anteriores a `learning_from` y los días sin cobertura no cuentan
- [x] Con `learning_days = 0`, un sujeto nuevo nace aprendido

## Más tráfico de lo habitual
- [x] Evaluación al consolidar cada hora en vivo con cobertura de tráfico completa; las horas con huecos no se evalúan
- [x] Muestras: la misma hora local de los 14 días anteriores con cobertura completa, solo desde el alta del equipo
- [x] Sin al menos 5 muestras no hay alerta
- [x] Alerta si el valor es ≥ 3 veces la mediana y supera el mínimo del sentido (200 MB de bajada o 50 MB de subida por hora)
  - AC: Dadas muestras con mediana de 400 MB de bajada, cuando la hora trae 2,4 GB, entonces hay alerta con «×6 la mediana»; con 1 GB, no
- [x] Días con cambio de hora: una hora local que no existe se salta y una repetida usa la primera
- [x] Una repetición en la hora siguiente guarda en `details` el valor mayor

## Huecos dentro de la sesión
- [x] Suspensión detectada cuando `CLOCK_BOOTTIME` avanza más de 60 s por encima de `CLOCK_MONOTONIC` entre dos ticks, con su hueco `suspend` guardado ya cerrado
  - AC: Dado un portátil suspendido 8 h con Almenara abierta, cuando vuelve, entonces hay un hueco `suspend` de esas 8 h y la gráfica de Histórico lo pinta como «sin datos»
- [x] Captura parada dentro de una sesión: hueco `capture` abierto al pararse y cerrado al volver
- [x] Huecos abiertos cerrados al salir con `q` o, tras una caída, en el arranque siguiente con el `ended_at` de su sesión
- [x] Cobertura de tráfico del histórico, del aprendizaje y de «más tráfico» sin los huecos de `COVERAGE_GAPS`
- [x] Presencia «sin datos» durante una suspensión
- [x] Suspensiones y capturas paradas en la línea de tiempo de Histórico con el filtro Almenara
- [x] Un cambio del reloj de pared (NTP o cambio de hora) no crea huecos

## Puertos cerrados
- [x] Al ver cerrado un puerto, `closed_at` se fija y `last_seen` no se toca
- [x] Un puerto CERRADO visto abierto borra `closed_at`, actualiza `last_seen` y genera `service_new` con `reopened`
- [x] Estado del puerto: CERRADO con `closed_at`; si no, OBSOLETO por `last_seen` (F2) o ABIERTO
- [x] Puertos cerrados purgados a los `events_retention_days` de su `closed_at`
- [x] El detalle de equipo muestra «cerrado el …» con `closed_at`

## Inventario del propio equipo
- [x] El lote del minuto trae el inventario del propio equipo: apps, categorías, organizaciones, países y JA4 de los flujos en que es cliente
- [x] `HOST_SEEN` con primera y última vez, sin claves especiales ni destinos, purgado a los `day_days` de su `last_seen`
- [x] Config muestra el inventario (recuentos por tipo) y el aprendizaje del propio equipo

## Notificaciones
- [x] Notificador en un hilo propio con `notify-rust` 4.17 sobre D-Bus de sesión; la TUI nunca lo espera
  - AC: Dado un servidor de notificaciones que tarda 5 s en responder, cuando llega una alerta importante, entonces la TUI sigue pintando a su ritmo
- [x] Solo las alertas importantes notifican; los avisos suben el contador y la info solo se ve en la pestaña
- [x] Sin servidor de notificaciones, el notificador queda NO DISPONIBLE con aviso único en Config y reintenta como mucho cada 10 minutos
- [x] Notificación «Almenara · <regla>» con el sujeto y lo esencial, texto saneado y `&`, `<` y `>` escapados
  - AC: Dado un nombre DHCP `<b>x</b>` con una secuencia ANSI, cuando se notifica, entonces el cuerpo lleva `&lt;b&gt;x&lt;/b&gt;` y ningún código de escape
- [x] Puesta al día: en los 10 minutos tras arrancar no se notifica; al final, una alerta resumen y una sola notificación si alguna era importante
- [x] Horario silencioso: dentro de `quiet_hours` no se notifica y las alertas se guardan
- [x] Tope de 3 notificaciones por minuto; las demás salen juntas en una («y N alertas importantes más»)
- [x] Con `desktop_notifications = false` el notificador queda APAGADO
- [x] Canal del notificador acotado (32): si se llena, descarta y cuenta `notify_drops`, que Config muestra
- [x] `notified` solo se marca en las alertas que salieron en una notificación propia

## Pestaña Alertas
- [x] Pestaña Alertas (5) con la lista por última repetición: cuándo, nivel, qué y equipo, con «×N» y «· resuelta»
- [x] Nivel con texto y símbolo (`!! IMP`, `!  AVI`, `   INF`) y alertas no vistas con `●`; nada depende solo del color
- [x] Detalle en el panel inferior con el porqué, las repeticiones, si se notificó y, en un resumen, lo que agrupa
- [x] `Enter` abre el detalle y marca la alerta como vista; `espacio` la marca sin abrirla
- [x] `T` marca como vistas todas las del filtro, con confirmación si son más de 20; marcar un resumen marca lo que agrupa
- [x] Filtros: `f` nivel (todas → importantes → avisos → info), `u` solo sin ver y `/` por equipo
- [x] `e` abre el equipo de la alerta en Equipos con su detalle
- [x] `m` silencia la regla para el sujeto y el equipo de la alerta: 1 día, 7 días o siempre
- [x] Vista Reglas (`Tab`): estado, nivel, alertas de 7 días y silencios de cada regla; `espacio` activa o apaga y `n` cambia el nivel
  - AC: Dada «Organización nueva» activa, cuando se pulsa `espacio`, entonces queda apagada, `config.toml` lo guarda y la siguiente organización nueva no crea alerta
- [x] Vista Reglas: una regla que no puede saltar lo dice («necesita el histórico», «necesita captura» o «sin escaneo de puertos»)
- [x] Vista Silencios (`Tab`): regla, equipo, hasta y desde; `x` quita el silencio
- [x] Mensajes: «Sin alertas en este filtro», «Las alertas están desactivadas ([alerts] enabled = false)» y «Cargando…»
- [x] La lista se pide al lector y se refresca tras cada alerta nueva; el render no consulta la BD

## Resto de la interfaz
- [x] Barra de estado con «Alertas N» (no vistas importantes y avisos), oculta si N es 0
- [x] Aviso de una línea durante 10 s al llegar una alerta importante fuera de la pestaña Alertas
- [x] Equipos: `*` si el equipo está vigilado y `!` si tiene alertas importantes o avisos sin ver, con leyenda
- [x] `p` marca o desmarca un equipo como vigilado en Equipos y en su detalle
- [x] Detalle de equipo: bloque «Alertas» con las 5 últimas y las que faltan por ver, vigilado, aprendizaje y silencios
- [x] Config: `[alerts]`, estado del notificador con el nombre del servidor y horario silencioso
- [x] Ayuda: niveles, reglas, aprendizaje, silencios, teclas y privacidad de las notificaciones
- [x] Lista y detalle de Alertas usables en 80×24

## Retención y purga
- [x] Alertas purgadas a los `retention_days` (90) de su `last_at` en la purga horaria de F5
- [x] Silencios caducados borrados en la purga horaria; los de «siempre» nunca caducan
- [x] `COVERAGE_GAPS` borrado con su sesión (en cascada)

## Rendimiento y mediciones
- [x] `AlertEngine::handle` ≤ 1 ms por señal (medido)
- [x] Evaluación de una hora ≤ 20 ms con 50 equipos y 14 días de muestras (medido)
- [x] Aprendizaje de un día ≤ 50 ms con 50 equipos (medido)
- [x] Migración v6 con sus rellenos ≤ 2 s sobre el histórico sintético de 2 años (medido)
- [x] `Queries::alerts` ≤ 100 ms con 20 000 alertas (medido)
- [x] Memoria añadida ≤ 4 MB (medido)
- [x] Render con Alertas abierta ≤ 16 ms en 80×24 y ≤ 33 ms en 120×40 (medido)
- [x] Pruebas ignoradas `medir_alertas_*`, `medir_migracion_v6` y `medir_render_alertas` con sus cifras en el informe de implementación

## Privacidad y seguridad
- [x] Las alertas nunca guardan dominios ni contenido: regla, sujeto, clave y porqué
- [x] Texto de la red saneado al crear la alerta: sin caracteres de control ni secuencias ANSI, `title` ≤ 120 y `subject_label` ≤ 64 caracteres
- [x] Ninguna alerta de presencia salvo para los equipos vigilados; ninguno lo está por defecto
- [x] La Ayuda explica que las notificaciones se ven en pantalla y que el servidor de notificaciones puede guardarlas
- [x] Sin puertos nuevos ni accesos a red; D-Bus solo de sesión
- [x] Claves de las alertas solo en logs de nivel `debug`

## Documentación y cierre
- [x] README y Ayuda con las alertas, las notificaciones y cómo vigilar equipos
- [x] Versión 0.6.0 y novedades en `CHANGELOG.md`
- [x] Informe de implementación `almenara-fase6-implementacion.md`

## Servicios internos
- [x] `AlertEngine::new` — estado inicial del motor
- [x] `AlertEngine::handle` — señal → acciones
- [x] `AlertEngine::inserted` — id de una alerta recién creada
- [x] `AlertEngine::reload` — recarga tras cambiar reglas, silencios o aprendizaje
- [x] `Rules::catalog` — las 16 reglas
- [x] `Baseline::evaluate` — mediana, factor y mínimo
- [x] `Learning::is_data_day` — día con datos
- [x] `NotifyPolicy::decide` — notificar, resumen, tope o no
- [x] `QuietHours::parse` — horario silencioso
- [x] `AlertText::compose` — título, etiqueta y cuerpo saneados
- [x] `Health::sample` — salud de la captura y de la BD
- [x] `Suspend::detect` — suspensión del equipo
- [x] `Notifier::spawn` — hilo de notificaciones
- [x] `NotifierHandle::notify` — encolar sin bloquear
- [x] `NotifierHandle::status` — estado del notificador
- [x] `Repo::insert_alert` — crear una alerta
- [x] `Repo::insert_summary` — resumen de la puesta al día
- [x] `Repo::repeat_alert` — repetición o reactivación
- [x] `Repo::resolve_alert` — resolver una condición
- [x] `Repo::mark_seen` — marcar vistas
- [x] `Repo::unseen_counts` — no vistas por nivel
- [x] `Repo::engine_snapshot` — estado inicial del motor desde la BD
- [x] `Repo::upsert_mute` — crear o sustituir un silencio
- [x] `Repo::delete_mute` — quitar un silencio
- [x] `Repo::purge_alerts` — purga de alertas y silencios
- [x] `Repo::set_watched` — equipo vigilado
- [x] `Repo::ensure_learning` — fila de aprendizaje
- [x] `Repo::update_learning` — aprendizaje del día cerrado
- [x] `Repo::hour_baseline` — valor y muestras de una hora
- [x] `Repo::upsert_seen` — (extendido) entradas nuevas y `HOST_SEEN`
- [x] `Repo::open_gap` — abrir o guardar un hueco
- [x] `Repo::close_gap` — cerrar un hueco
- [x] `Repo::close_open_sessions` — (extendido) también los huecos abiertos
- [x] `Repo::mark_service_closed` — (cambia) `closed_at` sin tocar `last_seen`
- [x] `Repo::upsert_service` — (extendido) borra `closed_at`
- [x] `Repo::backfill_closed_at` — relleno de `closed_at`
- [x] `Repo::backfill_learning` — aprendizaje inicial
- [x] `Queries::alerts` — lista de alertas
- [x] `Queries::alert_detail` — detalle de una alerta
- [x] `Queries::mutes` — silencios
- [x] `Queries::rule_stats` — alertas y silencios por regla
- [x] `Queries::alert_summary` — alertas, silencios y aprendizaje de un sujeto
- [x] `Queries::coverage` — (extendido) sin los huecos de `COVERAGE_GAPS`
- [x] `Queries::presence` — (extendido) suspensión como «sin datos»
- [x] `Queries::timeline` — (extendido) suspensiones y capturas paradas
- [x] `Queries::inventory` — (extendido) también el propio equipo
- [x] `MinuteRollup::flush` — (extendido) inventario del propio equipo
- [x] `Changes::services` — (extendido) `closed_at` y `reopened`
- [x] `config::load` — (extendido) `[alerts]`
- [x] `config::save_rule` — guardar una regla desde la TUI
- [x] `Synthetic::generate` — (extendido) alertas, silencios, aprendizaje y huecos

---

**Progreso Fase 6:** 174 / 174 funcionalidades

**Total Almenara (Fases 1-6):** 738 / 738 funcionalidades (F1-F3: 248; F4: 175 de 175; F5: 141 de 141; F6: 174 de 174)
