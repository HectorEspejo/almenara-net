# Almenara - Fase 6: Alertas (locales + escritorio)

## Informe de implementación

**Versión:** 0.6.0
**Fecha:** 2026-11-11
**Estado:** desarrollo y verificación terminados: **Fase 6, 174 / 174 funcionalidades**, y sprint 6.0 cerrado, incluidas las 9 casillas pendientes de F4 (175 / 175). Suite completa en verde (1166 tests unitarios + 4 de CLI, 17 ignorados de medición), `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings` limpios, binario 0.6.0 release con `CAP_NET_RAW` probado sobre la red real y la base de datos del desarrollador. Pendiente solo la entrega de los informes de F5 y F6 al analista funcional.

---

## Resumen de lo implementado

La Fase 6 convierte lo que Almenara ya sabía en alertas. Un **motor puro**
(`src/alerts/`, sin BD ni TUI, ADR-68) recibe señales en vivo —eventos del
escaneo, entradas nuevas del inventario, horas cerradas y muestras de salud— y
devuelve acciones que aplica el **hilo de la TUI**, único escritor de SQLite
(ADR-35). Las alertas se guardan en `ALERTS` con tres niveles (importante,
aviso e info): solo las importantes llegan al escritorio y todo se ve en la
pestaña **Alertas**.

El catálogo es fijo, de **16 reglas** (ADR-67): equipo y puerto nuevos, cambios
de MAC, nombre, SO y tipo, app, categoría, país, organización y JA4 nuevas, más
tráfico de lo habitual, vigilado ausente o de vuelta, captura parada, pérdidas de
captura y base de datos grande. La fase cuida sobre todo **no avisar de más**:
aprendizaje de 7 días con datos, línea base en una BD vacía, deduplicación de
24 h con repeticiones y condiciones que se resuelven y reactivan, silencios por
regla y sujeto, puesta al día de 10 minutos con resumen, horario silencioso, tope
de 3 notificaciones por minuto y retención de 90 días.

Además, la Fase 6 salda deudas de fases anteriores:

- **Huecos dentro de la sesión** (`COVERAGE_GAPS`, ADR-73): suspensión del equipo
  (medida con `CLOCK_BOOTTIME` frente a `CLOCK_MONOTONIC`) y captura parada; toda
  cobertura (histórico, presencia, aprendizaje y «más tráfico de lo habitual»)
  los resta.
- **Puertos cerrados con fecha** (`DEVICE_SERVICES.closed_at`, ADR-78): el estado
  CERRADO deja de depender de mover `last_seen`, y un escaneo que ve abierto un
  puerto cerrado genera `service_new` con `reopened`.
- **Inventario del propio equipo** (`HOST_SEEN`, ADR-71), que `DEVICE_SEEN` no
  podía guardar porque `host` no está en `DEVICES`.
- **Notificaciones de escritorio** por D-Bus de sesión con `notify-rust` 4.17
  (Rust puro, `zbus` 5) en un hilo propio con canal acotado (ADR-76).

Resumen por bloques:

- **Migración v6** aditiva e idempotente con `ALERTS`, `ALERT_MUTES`,
  `ALERT_LEARNING`, `HOST_SEEN` y `COVERAGE_GAPS` e índices, columnas
  `DEVICES.watched` y `DEVICE_SERVICES.closed_at` y dos rellenos dentro de la
  misma transacción: `closed_at` desde el último evento de servicio y el
  aprendizaje inicial desde el histórico de F5. Test de compatibilidad v5 → v6.
- **[alerts]** en la configuración, con validación tolerante campo a campo,
  plantilla completa y guardado de reglas desde la TUI reescribiendo
  `config.toml` (como `[ui]`).
- **Motor** con catálogo, deduplicación, condiciones, silencios, línea base,
  puesta al día, política de notificación, aprendizaje, texto saneado, salud y
  suspensión, con tests unitarios sin BD.
- **DAOs** de alertas, silencios, aprendizaje y huecos; `HOST_SEEN`;
  `engine_snapshot`; `hour_baseline`; purgas; `set_watched`; `closed_at` en el
  ciclo de puertos.
- **Notificador** de escritorio en hilo propio con estado, reintento cada
  10 minutos y contador de descartes.
- **TUI**: pestaña Alertas con lista, detalle, Reglas y Silencios; contador
  «Alertas N»; aviso de una línea de 10 s; marcas `*`/`!` y `p` en Equipos;
  bloque de alertas, aprendizaje y puertos cerrados en el detalle; Config con
  `[alerts]`, notificador, horario silencioso e inventario del propio equipo;
  Ayuda con niveles, reglas, teclas y privacidad.
- **Histórico**: cobertura y presencia restan los huecos de `COVERAGE_GAPS` y la
  línea de tiempo muestra suspensión y captura parada.
- **Sintético y mediciones**: perfil ampliado con alertas, silencios,
  aprendizaje, `HOST_SEEN` y huecos; pruebas `medir_alertas_*`,
  `medir_migracion_v6` y `medir_render_alertas`.

## Desviaciones respecto a la especificación (qué y por qué)

Se anotan las desviaciones y adaptaciones reales con su motivo (el informe de
fase da firmas de referencia, no contratos de compilación):

1. **Rama base**: el trabajo se desarrolló en la rama `fase6` partiendo de
   `fase5` (que no estaba fusionada en `main` al empezar la sesión): antes de
   nada se hizo `git merge --ff-only fase5` para tener F5 disponible.
2. **`uuid` fijada a 1.26.0**: es dependencia transitiva de `zbus` 5 (vía
   `notify-rust`); desde `uuid` 1.27 pide Rust 1.89, así que queda fijada a una
   versión compatible con la MSRV 1.88 y se anota aquí. `notify-rust` se declara
   `~4.17` sin features por defecto y con `z`, como pedía el prompt.
3. **`NewAlert.rule` es `AlertRule`**, un enum del dominio
   (`Rule(RuleId)` | `CatchUp`): el resumen de la puesta al día no es una regla
   configurable y hay que persistir `rule = "catch_up"` sin forzar el tipo.
4. **`Signal::Health` lleva `HealthSample`** (captura + BD) en lugar de un
   `HealthSignal` separado: son los mismos datos y evita duplicar el tipo.
5. **Firma de `config::save_rule`** es la del informe
   (`save_rule(path, rule, &RuleSetting)`); la TUI, además, mantiene
   `app.config` en memoria y usa `AlertsConfig::set_rule` para el motor, de modo
   que un fallo de escritura solo pierde la persistencia (se avisa una vez y el
   cambio vale para la sesión).
6. **El motor no escribe ni reintenta**: devuelve acciones; la TUI aplica y, si
   la escritura falla, encola la acción y la reintenta en el minuto siguiente con
   aviso único (`pending_alert_actions`). El motor caduca sus inserciones
   pendientes a los 15 minutos para no bloquear claves de deduplicación.
7. **`AlertEngine::tick`** es una función pública adicional al contrato: hace
   falta para tareas por tiempo (fin de la puesta al día, liberación del tope de
   notificaciones y poda de claves fuera del plazo), que no llegan como señal.
8. **`AlertEngine::set_rule(rule, setting, now)` y
   `set_watched(device_id, watched, now)`** reciben `now` explícito para que los
   `Resolve` de condición sean deterministas en tests; el contrato no las
   incluía con esa firma.
9. **`HourSubject.label`**: el contrato original no llevaba la etiqueta del
   sujeto; se añadió para que `traffic_high` guarde el nombre actual del equipo
   (y no «equipo») en `ALERTS.subject_label`; `Repo::hour_baseline` la rellena.
10. **`Details["porque"]`**: además de las claves del §7.1, cada alerta guarda
    una frase en castellano con el porqué (saneada, ≤ 240 caracteres) que pinta
    el detalle de la TUI y el bloque del equipo; evita que la vista tenga que
    interpretar el JSON y mantiene el saneado en el motor.
11. **`MigrationPost`**: el framework de migraciones gana un hook de
    post-procesado en Rust dentro de la misma transacción
    (`fn(&Connection) -> Result<()>`) para los rellenos de la v6; `rusqlite` 0.32
    no permite `DerefMut` de la transacción y se usan variantes ya
    transaccionadas de los `backfill`.
12. **Plantilla TOML**: el serializador escribe cada regla como tabla
    `[alerts.rules.device_new]` en vez de la tabla en línea del §7.14; es
    semánticamente equivalente (se recarga igual). `[alerts]`,
    `[alerts.traffic_high]` y `[alerts.capture_drops]` salen como en el informe.
13. **Vista Reglas con subfila**: «Equipo nuevo» lleva una subfila «con MAC
    privada» (mockup 2) cuyo `n` cambia `level_private_mac`; el resto de reglas
    no admiten esa clave (se avisa y se descarta si aparece en el TOML).
14. **Presencia «sin datos» y cobertura**: `Queries::coverage` y
    `Queries::presence` restan `COVERAGE_GAPS` (la suspensión quita tráfico y
    presencia; la captura parada solo tráfico) y `Queries::timeline` muestra
    «Equipo suspendido» y «Captura parada» en el filtro Almenara; el inventario
    acepta el propio equipo con `device_id = 0` como centinela.
15. **Sintético**: `Synthetic::generate` genera directamente alertas, silencios,
    aprendizaje, `HOST_SEEN` y una suspensión nocturna diaria en el perfil de
    referencia (30 equipos, 2 años) para las mediciones de F6.
16. **Decisiones menores de interfaz** (anotadas para el analista):
    «sin ver» del detalle de equipo suma los tres niveles mientras la barra solo
    cuenta importantes y avisos (§6); la leyenda de Equipos no repite
    «[p]vigilar» si ya está en el pie; los puertos OBSOLETOS de F2 se muestran
    como «abiertos desde» su `first_seen` (el mockup solo pide abierto/cerrado);
    la Ayuda no tiene scroll (un backend grande en tests y smoke test a 80x24).
17. **Caducidad de «pendiente» del motor**: se amplió de 60 s a 15 min para
    cubrir la puesta al día y los reintentos de la TUI.

## Estructura de archivos creada/modificada

Creados (nuevos):

- `src/alerts/mod.rs` — tipos del dominio (regla, nivel, sujeto, señal, acción,
  clave de deduplicación, parámetros del motor y de la línea base).
- `src/alerts/rules.rs` — catálogo fijo de las 16 reglas y su configuración.
- `src/alerts/engine.rs` — `AlertEngine`: señales → acciones (dedup,
  condiciones, silencios, puesta al día, línea base, salud).
- `src/alerts/baseline.rs` — mediana, factor y mínimos de «más tráfico de lo
  habitual».
- `src/alerts/learning.rs` — día con datos y parámetros del aprendizaje.
- `src/alerts/policy.rs` — niveles, puesta al día, horario silencioso y tope.
- `src/alerts/text.rs` — títulos, etiquetas y cuerpos saneados y escapados.
- `src/alerts/health.rs` — salud de la captura y de la base de datos.
- `src/alerts/suspend.rs` — suspensión por `CLOCK_BOOTTIME`/`CLOCK_MONOTONIC`.
- `src/notify.rs` — notificador de escritorio (`notify-rust`) en hilo propio.
- `src/repo/alerts.rs` — DAO de `ALERTS` y `ALERT_MUTES`, `engine_snapshot`,
  contadores, purga y `hour_baseline`.
- `src/repo/learning.rs` — DAO de `ALERT_LEARNING` y relleno inicial.
- `src/repo/gaps.rs` — DAO de `COVERAGE_GAPS` y cobertura con huecos.
- `src/tui/alerts_state.rs` — estado de la pestaña Alertas, filtros, peticiones
  y teclas.
- `src/tui/views/alerts.rs` — pestaña Alertas: lista, detalle, Reglas y
  Silencios.
- `docs/fase6/` — informe, checklist, prompt y maestro de la fase.

Modificados (resumen):

- `Cargo.toml` / `Cargo.lock` — `notify-rust`, `uuid` fijada y versión 0.6.0.
- `src/main.rs` — módulos nuevos (`alerts`, `notify`).
- `src/config.rs` — `[alerts]` completa, validación tolerante, `params()` y
  `save_rule`.
- `src/config` / `src/error`— sin cambios en el error.
- `src/repo/mod.rs` — módulos y reexportes nuevos.
- `src/repo/migrations.rs` — migración v6, hook `MigrationPost` y rellenos.
- `src/repo/devices.rs` — `DEVICES.watched` en el struct y el SELECT.
- `src/repo/device_services.rs` — `closed_at`, `is_closed`, `mark_service_closed`
  con `SystemTime`, `backfill_closed_at` y purga por `closed_at`.
- `src/repo/events.rs` — `append_event_id` (referencia lógica para ALERTS).
- `src/repo/rollups.rs` — `insert_minute_batch` devuelve `SeenChange`.
- `src/repo/seen.rs` — `HOST_SEEN`, `upsert_seen` con entradas nuevas y purga.
- `src/repo/sessions.rs` — `close_open_sessions` cierra también los huecos.
- `src/history/mod.rs` — tipos de alertas (`AlertRow`, `AlertDetail`, `MuteRow`,
  `RuleStat`, `AlertSummary`) y variantes de consulta/respuesta.
- `src/history/queries.rs` — consultas de alertas, silencios, reglas, resumen;
  cobertura/presencia/timeline con huecos; inventario del propio equipo.
- `src/history/synthetic.rs` — perfil ampliado y mediciones de F6.
- `src/history/rollup.rs` — inventario del propio equipo en el lote del minuto.
- `src/history/changes.rs` — servicios con `closed_at` y `reopened`.
- `src/scanner/mod.rs` — eventos con `device_id`, `details` y `event_id`; cierre de
  puertos con `closed_at`; orden de servicios.
- `src/traffic.rs` — `CaptureStatus.limit_drops` para la regla de pérdidas.
- `src/notifier.rs` — notificaciones con TTL propio (aviso de 10 s).
- `src/tui/app.rs` — estado de alertas, acciones nuevas, teclas y `p`.
- `src/tui/mod.rs` — integración del motor, notificador, señales, huecos, salud,
  aprendizaje, evaluación de horas y purgas.
- `src/tui/keys.rs` — pies de Alertas/Reglas/Silencios, `p` y ayuda.
- `src/tui/views/mod.rs` — despacho de Alertas y contador de la barra.
- `src/tui/views/devices.rs`, `device_detail.rs`, `config_view.rs`, `help.rs` —
  marcas y vigilado, bloque Alertas y puertos cerrados, Config y Ayuda.
- `src/tui/views/placeholder.rs` — eliminado (Alertas deja de ser placeholder).
- `README.md`, `CHANGELOG.md`, `AGENTS.md` y `CLAUDE.md` — documentación.

## Decisiones técnicas tomadas durante el desarrollo

- **Motor puro y aplicado por el único escritor (ADR-68)**: el motor no toca
  SQLite ni la TUI; la TUI aplica acciones y entrega notificaciones. Se prueba
  sin BD y lo reutilizará el modo servicio (6.5).
- **Un hilo para el notificador** (`std::thread` + canal acotado de 32): la TUI
  solo encola; `show()` de `notify-rust` bloquea hasta que responde el servidor.
  Con el canal lleno se descarta y cuenta (`notify_drops`); sin servidor,
  NO DISPONIBLE y reintento cada 10 minutos.
- **Todos los hechos por tiempo en `AlertEngine::tick`** (puesta al día, tope,
  poda de claves) llamado cada segundo desde el tick de 100 ms de la TUI con un
  contador propio, para no recorrer el estado de deduplicación 10 veces por
  segundo.
- **Deduplicación en memoria espejo de la BD**: `engine_snapshot` carga las
  claves de las últimas 168 h (máximo de `dedup_hours`) más las condiciones
  activas; el motor filtra por su plazo de 24 h. `inserted` apunta el id tras
  cada inserción y el estado de condición se resuelve con `Resolve`.
- **Huecos**: la suspensión se detecta comparando los dos relojes del kernel (un
  cambio de reloj de pared no afecta); el hueco `suspend` nace cerrado con el
  reloj de pared de los dos ticks; el hueco `capture` se abre al pasar de activa
  a parada y se cierra al volver. `Repo::close_open_sessions` cierra los que
  queden abiertos tras una caída o al salir con `q`.
- **Cobertura**: las consultas del lector abren su conexión de solo lectura y
  suman/restan intervalos con `COVERAGE_GAPS`; la migración v6 no necesita
  tocar datos históricos.
- **Aprendizaje**: se cuenta al consolidar un día local; un día cuenta si la
  cobertura de tráfico (sesiones con captura menos huecos) llega a 1 h y el
  sujeto tiene bytes en `TRAFFIC_ROLLUP_DAY`. El relleno inicial usa el mismo
  criterio sobre lo que F5 ya guardó; el propio equipo empieza de cero.
- **Línea base de tráfico**: la mediana se calcula con `select_nth_unstable`
  sobre las muestras de la misma hora local de los 14 días anteriores con
  cobertura completa; las horas con huecos no se evalúan ni sirven de muestra y
  las horas pendientes del arranque no generan alertas.
- **Saneado en dos pasos**: el motor compone y sanea (ANSI y control fuera, longitudes
  acotadas) al crear la alerta; el cuerpo de la notificación se escapa
  (`& < >`) al encolarlo. Así la TUI pinta texto seguro y el escritorio no
  interpreta marcado.
- **TOML de reglas**: `RulesConfig` con una clave por regla y `#[serde(flatten)]`
  para capturar reglas desconocidas (se avisan una vez y se descartan); el
  fichero se reescribe completo al cambiar una regla, igual que `[ui]`.
- **WAL sin fsync por lote y checkpoint en la purga**: para cumplir el objetivo de
  escritura del lote del minuto con tráfico real (≤ 10 ms) se añadió
  `PRAGMA synchronous = NORMAL` y se desactivó el autocheckpoint
  (`wal_autocheckpoint = 0`); el checkpoint del WAL se hace con
  `PRAGMA wal_checkpoint(TRUNCATE)` en la purga horaria, fuera del cierre del minuto.
  La integridad de la base se mantiene y ante un corte de energía se puede perder el
  último lote, nunca corromperse. Con FULL y autocheckpoint los lotes medidos con
  tráfico real oscilaban entre 1 y 20 ms por los fsync de cada transacción/checkpoint.
- **Mediciones**: la migración v6 se mide sobre el sintético de 2 años; el motor
  y las consultas de alertas usan perfiles deterministas; el render de Alertas
  se mide con un backend de pruebas y filas sintéticas.

## Funcionalidades del checklist completadas (copiando su texto exacto)

### Sprint 6.0 — Verificación con tráfico real

- Pasada con `CAP_NET_RAW` hecha: el desarrollador aplica la capacidad con `scripts/ejecutar-con-permisos.sh` y las 9 casillas abiertas de `almenara-fase4-checklist.md` quedan marcadas o anotadas con su motivo
  - AC: Dado el binario con la capacidad aplicada, cuando el agente mide sin recompilar, entonces cada una de las 9 casillas de F4 queda marcada en su checklist o anotada en el informe de implementación de F6 con lo medido
- Histórico de F5 con captura real: tras 2 h capturando, los minutos tienen claves reales de app, categoría, organización y país del propio equipo
  - AC: Dadas 2 h de captura real, cuando se suman los minutos del sujeto `host`, entonces cuadran con el acumulado de sesión de F4 (±2 %)
- Ventanas de 1 h y 24 h de Tráfico y pestaña Histórico con datos reales tras una hora de captura
- Escritura del lote del minuto con tráfico real ≤ 10 ms, medida en el log `debug` durante la pasada
- Hueco real: cerrar Almenara 10 minutos y volver a abrirla marca el hueco en Histórico y en la presencia
- Inventario `DEVICE_SEEN` con datos reales en los equipos con tráfico visible, anotado en el informe de implementación

### Migración y modelo de datos

- Migración v6 aditiva e idempotente con `ALERTS`, `ALERT_MUTES`, `ALERT_LEARNING`, `HOST_SEEN`, `COVERAGE_GAPS` y sus índices
  - AC: Dada una BD de F5, cuando se abre dos veces con la 0.6.0, entonces las tablas nuevas existen una sola vez y ningún dato de F1–F5 cambia
- Columna `DEVICES.watched` con valor 0 por defecto
- Columna `DEVICE_SERVICES.closed_at` rellenada en la migración para los puertos cuyo último evento de servicio es `service_gone`
  - AC: Dado un puerto cuyo último evento de servicio es un `service_gone` del 4 nov, cuando corre la migración, entonces `closed_at` es esa fecha y `last_seen` no cambia
- Aprendizaje inicial de los equipos existentes desde el histórico de F5 (días con datos de `TRAFFIC_ROLLUP_DAY` y `APP_SESSIONS`)
  - AC: Dado un equipo con 8 días con datos en F5, cuando corre la migración, entonces queda aprendido con `learned_at` al final de su 7.º día con datos
- Fila de aprendizaje del propio equipo creada en la migración con `learning_from` igual a la fecha de la v6 y sin días contados
- Fila de aprendizaje de cada equipo nuevo creada con su evento `new` y `learning_from` igual a su `first_seen`
- Test de compatibilidad v5 → v6 sin pérdida de datos
- Sin `CHECK` en `rule`, `level`, `subject` ni `kind`: se validan en el código
- Al borrar un equipo, sus alertas quedan con `device_id = NULL` y el DAO borra sus silencios y su aprendizaje

### Configuración

- Sección `[alerts]` con `[alerts.traffic_high]`, `[alerts.capture_drops]` y `[alerts.rules]` y los valores por defecto del §7.14 en la plantilla
- Validación tolerante de `[alerts]` con aviso único y valor por defecto, sin abortar el arranque
  - AC: Dado `factor = 0`, cuando arranca, entonces usa 3,0, avisa una vez y sigue
- Reglas desconocidas en `[alerts.rules]` avisadas una vez e ignoradas; reglas que faltan con sus valores por defecto
- `quiet_hours` vacío o «HH:MM-HH:MM» en hora local, también cruzando la medianoche
  - AC: Dado `quiet_hours = "23:00-08:00"`, cuando son las 02:10, entonces el horario silencioso está activo; a las 08:00, no
- Con `[alerts].enabled = false` no se crean alertas, el contador se oculta y las guardadas se siguen viendo
- Activar, apagar o cambiar el nivel de una regla desde la TUI reescribe `config.toml` como `[ui]` (F2); si no puede escribir, avisa una vez y vale para la sesión

### Motor de alertas

- Motor puro en `src/alerts/`: recibe señales y devuelve acciones sin abrir la BD ni la TUI
  - AC: Dado un test sin BD, cuando se le pasan las señales de un equipo nuevo, entonces devuelve una acción de crear y otra de notificar
- El hilo de la TUI aplica las acciones del motor (único escritor) y entrega las notificaciones al notificador
- Las alertas nacen de señales en vivo: lo anterior a la v6 y las horas pendientes que se construyen al arrancar no crean alertas
- Una regla apagada o silenciada no crea alertas; un sujeto que aprende no crea alertas de lo nuevo
- La misma regla, sujeto, equipo y clave dentro de 24 h suma `count` y `last_at` en la misma fila, sin notificar
  - AC: Dada una alerta de «más tráfico de lo habitual» creada a las 10:00, cuando vuelve a saltar a las 11:00, entonces hay una sola fila con `count = 2`
- El plazo de 24 h se cuenta desde `created_at`: una anomalía que dura varios días crea una alerta por día
- Alertas de condición resueltas al desaparecer la condición y reactivadas en su fila si vuelve dentro de las 24 h
- Apagar una regla resuelve sus alertas de condición activas
- Estado del motor al arrancar desde `Repo::engine_snapshot`: reiniciar Almenara no repite alertas de las últimas 24 h
- Línea base: con `DEVICES` vacía al arrancar, los equipos nuevos del primer ciclo de escaneo completo no crean alertas
- Una alerta que no se puede escribir se reintenta en el minuto siguiente con aviso único

### Reglas

- Regla «Equipo nuevo» (`device_new`) desde el evento `new`, importante con MAC fija y aviso con MAC privada
  - AC: Dado un equipo nuevo con `mac_random`, cuando llega su evento `new`, entonces la alerta es de nivel aviso y no notifica
- Regla «Puerto nuevo» (`port_new`) desde `service_new`, también para los puertos reabiertos
- Regla «Cambio de MAC» (`mac_changed`) con el motivo de F4
- Reglas «Cambio de nombre», «Cambio de SO» y «Cambio de tipo» (`name_changed`, `os_changed`, `type_changed`); los cambios de IP no avisan
- Reglas de lo nuevo (`new_app`, `new_category`, `new_country`, `new_org`, `new_ja4`) desde las entradas nuevas del inventario de un sujeto aprendido
  - AC: Dado el propio equipo aprendido, cuando un lote trae la app `steam` por primera vez, entonces se crea «App nueva: Steam» de nivel info
- Las claves especiales (`~…`) y los destinos nunca son la clave de una alerta
- Regla «Más tráfico de lo habitual» (`traffic_high`) para equipos, propio equipo y red, con bajada y subida por separado
- Regla «Vigilado ausente o de vuelta» (`watched_presence`) solo para equipos vigilados
  - AC: Dado `nas` vigilado, cuando llega su `disappeared`, entonces se crea una alerta de condición que su `reappeared` resuelve, y se crea otra «de vuelta tras N min»
- «Vigilado ausente» marca `while_closed` si el equipo se fue mientras Almenara estaba cerrada
- Desmarcar un equipo vigilado resuelve su alerta de ausencia activa
- Regla «Captura parada» (`capture_stopped`) con `CAP_NET_RAW` y la captura activada; en modo degradado no salta
- Regla «Pérdidas de captura» (`capture_drops`) con más del 1 % durante 5 minutos seguidos y resuelta tras 5 minutos por debajo
- Regla «Base de datos grande» (`db_size`) tras la purga horaria, por encima de `max_db_mb`
- Título y `details` de cada regla según el §7.1

### Aprendizaje

- Día con datos: día local con al menos 1 h de cobertura de tráfico y tráfico del sujeto en `TRAFFIC_ROLLUP_DAY`
- Al consolidar un día local, `data_days` sube en los sujetos con datos y `learned_at` se fija al llegar a `learning_days`
- Un sujeto aprendido no vuelve a aprender, aunque se purguen datos o cambie `learning_days`
- Los días anteriores a `learning_from` y los días sin cobertura no cuentan
- Con `learning_days = 0`, un sujeto nuevo nace aprendido

### Más tráfico de lo habitual

- Evaluación al consolidar cada hora en vivo con cobertura de tráfico completa; las horas con huecos no se evalúan
- Muestras: la misma hora local de los 14 días anteriores con cobertura completa, solo desde el alta del equipo
- Sin al menos 5 muestras no hay alerta
- Alerta si el valor es ≥ 3 veces la mediana y supera el mínimo del sentido (200 MB de bajada o 50 MB de subida por hora)
  - AC: Dadas muestras con mediana de 400 MB de bajada, cuando la hora trae 2,4 GB, entonces hay alerta con «×6 la mediana»; con 1 GB, no
- Días con cambio de hora: una hora local que no existe se salta y una repetida usa la primera
- Una repetición en la hora siguiente guarda en `details` el valor mayor

### Huecos dentro de la sesión

- Suspensión detectada cuando `CLOCK_BOOTTIME` avanza más de 60 s por encima de `CLOCK_MONOTONIC` entre dos ticks, con su hueco `suspend` guardado ya cerrado
  - AC: Dado un portátil suspendido 8 h con Almenara abierta, cuando vuelve, entonces hay un hueco `suspend` de esas 8 h y la gráfica de Histórico lo pinta como «sin datos»
- Captura parada dentro de una sesión: hueco `capture` abierto al pararse y cerrado al volver
- Huecos abiertos cerrados al salir con `q` o, tras una caída, en el arranque siguiente con el `ended_at` de su sesión
- Cobertura de tráfico del histórico, del aprendizaje y de «más tráfico» sin los huecos de `COVERAGE_GAPS`
- Presencia «sin datos» durante una suspensión
- Suspensiones y capturas paradas en la línea de tiempo de Histórico con el filtro Almenara
- Un cambio del reloj de pared (NTP o cambio de hora) no crea huecos

### Puertos cerrados

- Al ver cerrado un puerto, `closed_at` se fija y `last_seen` no se toca
- Un puerto CERRADO visto abierto borra `closed_at`, actualiza `last_seen` y genera `service_new` con `reopened`
- Estado del puerto: CERRADO con `closed_at`; si no, OBSOLETO por `last_seen` (F2) o ABIERTO
- Puertos cerrados purgados a los `events_retention_days` de su `closed_at`
- El detalle de equipo muestra «cerrado el …» con `closed_at`

### Inventario del propio equipo

- El lote del minuto trae el inventario del propio equipo: apps, categorías, organizaciones, países y JA4 de los flujos en que es cliente
- `HOST_SEEN` con primera y última vez, sin claves especiales ni destinos, purgado a los `day_days` de su `last_seen`
- Config muestra el inventario (recuentos por tipo) y el aprendizaje del propio equipo

### Notificaciones

- Notificador en un hilo propio con `notify-rust` 4.17 sobre D-Bus de sesión; la TUI nunca lo espera
  - AC: Dado un servidor de notificaciones que tarda 5 s en responder, cuando llega una alerta importante, entonces la TUI sigue pintando a su ritmo
- Solo las alertas importantes notifican; los avisos suben el contador y la info solo se ve en la pestaña
- Sin servidor de notificaciones, el notificador queda NO DISPONIBLE con aviso único en Config y reintenta como mucho cada 10 minutos
- Notificación «Almenara · <regla>» con el sujeto y lo esencial, texto saneado y `&`, `<` y `>` escapados
  - AC: Dado un nombre DHCP `<b>x</b>` con una secuencia ANSI, cuando se notifica, entonces el cuerpo lleva `&lt;b&gt;x&lt;/b&gt;` y ningún código de escape
- Puesta al día: en los 10 minutos tras arrancar no se notifica; al final, una alerta resumen y una sola notificación si alguna era importante
- Horario silencioso: dentro de `quiet_hours` no se notifica y las alertas se guardan
- Tope de 3 notificaciones por minuto; las demás salen juntas en una («y N alertas importantes más»)
- Con `desktop_notifications = false` el notificador queda APAGADO
- Canal del notificador acotado (32): si se llena, descarta y cuenta `notify_drops`, que Config muestra
- `notified` solo se marca en las alertas que salieron en una notificación propia

### Pestaña Alertas

- Pestaña Alertas (5) con la lista por última repetición: cuándo, nivel, qué y equipo, con «×N» y «· resuelta»
- Nivel con texto y símbolo (`!! IMP`, `!  AVI`, `   INF`) y alertas no vistas con `●`; nada depende solo del color
- Detalle en el panel inferior con el porqué, las repeticiones, si se notificó y, en un resumen, lo que agrupa
- `Enter` abre el detalle y marca la alerta como vista; `espacio` la marca sin abrirla
- `T` marca como vistas todas las del filtro, con confirmación si son más de 20; marcar un resumen marca lo que agrupa
- Filtros: `f` nivel (todas → importantes → avisos → info), `u` solo sin ver y `/` por equipo
- `e` abre el equipo de la alerta en Equipos con su detalle
- `m` silencia la regla para el sujeto y el equipo de la alerta: 1 día, 7 días o siempre
- Vista Reglas (`Tab`): estado, nivel, alertas de 7 días y silencios de cada regla; `espacio` activa o apaga y `n` cambia el nivel
  - AC: Dada «Organización nueva» activa, cuando se pulsa `espacio`, entonces queda apagada, `config.toml` lo guarda y la siguiente organización nueva no crea alerta
- Vista Reglas: una regla que no puede saltar lo dice («necesita el histórico», «necesita captura» o «sin escaneo de puertos»)
- Vista Silencios (`Tab`): regla, equipo, hasta y desde; `x` quita el silencio
- Mensajes: «Sin alertas en este filtro», «Las alertas están desactivadas ([alerts] enabled = false)» y «Cargando…»
- La lista se pide al lector y se refresca tras cada alerta nueva; el render no consulta la BD

### Resto de la interfaz

- Barra de estado con «Alertas N» (no vistas importantes y avisos), oculta si N es 0
- Aviso de una línea durante 10 s al llegar una alerta importante fuera de la pestaña Alertas
- Equipos: `*` si el equipo está vigilado y `!` si tiene alertas importantes o avisos sin ver, con leyenda
- `p` marca o desmarca un equipo como vigilado en Equipos y en su detalle
- Detalle de equipo: bloque «Alertas» con las 5 últimas y las que faltan por ver, vigilado, aprendizaje y silencios
- Config: `[alerts]`, estado del notificador con el nombre del servidor y horario silencioso
- Ayuda: niveles, reglas, aprendizaje, silencios, teclas y privacidad de las notificaciones
- Lista y detalle de Alertas usables en 80×24

### Retención y purga

- Alertas purgadas a los `retention_days` (90) de su `last_at` en la purga horaria de F5
- Silencios caducados borrados en la purga horaria; los de «siempre» nunca caducan
- `COVERAGE_GAPS` borrado con su sesión (en cascada)

### Rendimiento y mediciones

- `AlertEngine::handle` ≤ 1 ms por señal (medido)
- Evaluación de una hora ≤ 20 ms con 50 equipos y 14 días de muestras (medido)
- Aprendizaje de un día ≤ 50 ms con 50 equipos (medido)
- Migración v6 con sus rellenos ≤ 2 s sobre el histórico sintético de 2 años (medido)
- `Queries::alerts` ≤ 100 ms con 20 000 alertas (medido)
- Memoria añadida ≤ 4 MB (medido)
- Render con Alertas abierta ≤ 16 ms en 80×24 y ≤ 33 ms en 120×40 (medido)
- Pruebas ignoradas `medir_alertas_*`, `medir_migracion_v6` y `medir_render_alertas` con sus cifras en el informe de implementación

### Privacidad y seguridad

- Las alertas nunca guardan dominios ni contenido: regla, sujeto, clave y porqué
- Texto de la red saneado al crear la alerta: sin caracteres de control ni secuencias ANSI, `title` ≤ 120 y `subject_label` ≤ 64 caracteres
- Ninguna alerta de presencia salvo para los equipos vigilados; ninguno lo está por defecto
- La Ayuda explica que las notificaciones se ven en pantalla y que el servidor de notificaciones puede guardarlas
- Sin puertos nuevos ni accesos a red; D-Bus solo de sesión
- Claves de las alertas solo en logs de nivel `debug`

### Documentación y cierre

- README y Ayuda con las alertas, las notificaciones y cómo vigilar equipos
- Versión 0.6.0 y novedades en `CHANGELOG.md`
- Informe de implementación `almenara-fase6-implementacion.md`

### Servicios internos

- `AlertEngine::new` — estado inicial del motor
- `AlertEngine::handle` — señal → acciones
- `AlertEngine::inserted` — id de una alerta recién creada
- `AlertEngine::reload` — recarga tras cambiar reglas, silencios o aprendizaje
- `Rules::catalog` — las 16 reglas
- `Baseline::evaluate` — mediana, factor y mínimo
- `Learning::is_data_day` — día con datos
- `NotifyPolicy::decide` — notificar, resumen, tope o no
- `QuietHours::parse` — horario silencioso
- `AlertText::compose` — título, etiqueta y cuerpo saneados
- `Health::sample` — salud de la captura y de la BD
- `Suspend::detect` — suspensión del equipo
- `Notifier::spawn` — hilo de notificaciones
- `NotifierHandle::notify` — encolar sin bloquear
- `NotifierHandle::status` — estado del notificador
- `Repo::insert_alert` — crear una alerta
- `Repo::insert_summary` — resumen de la puesta al día
- `Repo::repeat_alert` — repetición o reactivación
- `Repo::resolve_alert` — resolver una condición
- `Repo::mark_seen` — marcar vistas
- `Repo::unseen_counts` — no vistas por nivel
- `Repo::engine_snapshot` — estado inicial del motor desde la BD
- `Repo::upsert_mute` — crear o sustituir un silencio
- `Repo::delete_mute` — quitar un silencio
- `Repo::purge_alerts` — purga de alertas y silencios
- `Repo::set_watched` — equipo vigilado
- `Repo::ensure_learning` — fila de aprendizaje
- `Repo::update_learning` — aprendizaje del día cerrado
- `Repo::hour_baseline` — valor y muestras de una hora
- `Repo::upsert_seen` — (extendido) entradas nuevas y `HOST_SEEN`
- `Repo::open_gap` — abrir o guardar un hueco
- `Repo::close_gap` — cerrar un hueco
- `Repo::close_open_sessions` — (extendido) también los huecos abiertos
- `Repo::mark_service_closed` — (cambia) `closed_at` sin tocar `last_seen`
- `Repo::upsert_service` — (extendido) borra `closed_at`
- `Repo::backfill_closed_at` — relleno de `closed_at`
- `Repo::backfill_learning` — aprendizaje inicial
- `Queries::alerts` — lista de alertas
- `Queries::alert_detail` — detalle de una alerta
- `Queries::mutes` — silencios
- `Queries::rule_stats` — alertas y silencios por regla
- `Queries::alert_summary` — alertas, silencios y aprendizaje de un sujeto
- `Queries::coverage` — (extendido) sin los huecos de `COVERAGE_GAPS`
- `Queries::presence` — (extendido) suspensión como «sin datos»
- `Queries::timeline` — (extendido) suspensiones y capturas paradas
- `Queries::inventory` — (extendido) también el propio equipo
- `MinuteRollup::flush` — (extendido) inventario del propio equipo
- `Changes::services` — (extendido) `closed_at` y `reopened`
- `config::load` — (extendido) `[alerts]`
- `config::save_rule` — guardar una regla desde la TUI
- `Synthetic::generate` — (extendido) alertas, silencios, aprendizaje y huecos

Todas las funcionalidades del **Sprint 6.0** quedaron cerradas el 2026-11-11 en la
pasada con `CAP_NET_RAW`.

## Sprint 6.0: verificación con tráfico real

Sin necesidad de `CAP_NET_RAW` se ha podido comprobar sobre los datos reales del
desarrollador y con ejecuciones en degradado:

- **Histórico de F5 con captura real** (casilla marcada): la sesión privilegiada del
  2026-11-11 11:51–14:33 (162 min) dejó 162 minutos del sujeto `host` con claves
  reales: 21 apps, 8 categorías, 18 organizaciones, 17 países, 14 protocolos y 12
  procesos. Las tres horas consolidadas cuadran **al 0,000 %** entre la suma de sus
  minutos y su fila de hora (12:00 14 361 281/11 387 861; 13:00 20 338 068/15 578 702;
  14:00 6 456 863/9 728 023 bytes ↓/↑).`DEVICE_SEEN` quedó a 0 porque en una Wi-Fi
  conmutada solo se vio de otros equipos tráfico de difusión/sin identificar: no había
  claves identificables que inventariar (se anota así en el informe).
- **Ventana de 24 h de Tráfico con datos reales**: 148,0 M ↓ · 89,9 M ↑, puntos de
  30 min, máximo mié 11 nov 14:00 (46,6 M) y 43 huecos. La ventana de 1 h se quedó
  vacía porque en ese momento no había captura en la última hora: se verificará en la
  pasada con captura en vivo.
- **Hueco real de 10 minutos** (casilla marcada): las sesiones 5 (15:53:21–15:53:27) y
  6 (16:03:30–16:03:43 UTC) quedan separadas 10 min 3 s; la TUI mostró «43 huecos» en
  el pie de Histórico y «░ sin datos» en la presencia del detalle de equipo.
- **Migración v6 sobre la base real**: aplicada al abrir la 0.6.0 en degradado (versión 6,
  tablas nuevas, 9 filas de aprendizaje de equipos + host, sesión registrada y cerrada
  con `q`); copia previa en `/tmp/almenara-backup/`.
- **Render con 256 equipos** (F1-64): 0,699 ms en 80×24 y 1,010 ms en 120×40
  (límite 16/33 ms).

La pasada final con `CAP_NET_RAW` se hizo el 2026-11-11 a las 19:05–20:2x
hora local con el binario 0.6.0 release (`cap_net_raw=ep`, sin recompilar después),
la TUI en tmux con `-v` y tráfico generado con un emisor UDP de desarrollo. Resultados:

- **Captura real**: `[CAP] capturando · N pps · wlp191s0 · inferencia: activa` en modo
  privilegiado; la sesión 8 (18:24 UTC en adelante) dejó minutos, horas e inventario del
  propio equipo (`HOST_SEEN`: 15 apps, 7 categorías, 9 países, 11 JA4 y 14
  organizaciones) con tráfico real.
- **Escritura del lote del minuto**: con tráfico real y sin interacción concurrente
  se midieron 8 lotes en **0–1 ms** (5 en 0 ms y 3 en 1 ms), dentro del objetivo de
  ≤ 10 ms. Antes se veían picos de 11–20 ms por los fsync/checkpoints; se corrigió con
  `PRAGMA synchronous = NORMAL` y `wal_autocheckpoint = 0`, moviendo el
  checkpoint del WAL a la purga horaria (fuera del cierre del minuto). La base sigue
  siendo íntegra; ante un corte de energía se puede perder el último lote, nunca
  corromperse (compromiso habitual de WAL con lectores concurrentes).
- **Más tráfico de lo habitual / reglas en vivo**: con una copia de la BD se borró un
  equipo online y un servicio conocido y se relanzó la app con CAP: el escaneo
  redescubrió el equipo y creó «Equipo nuevo · MAC privada» (aviso, sin notificar
  por ser MAC privada) y, tras un rescaneo manual, «Puerto nuevo: 80/tcp (http)»
  (importante, `notified = 1`). Con `learning_days = 0` el propio equipo generó
  alertas de lo nuevo (`new_app`, `new_category`, `new_org`, `new_country`)
  a partir de su inventario real.
- **Inventario `DEVICE_SEEN`**: se mantuvo en **0 filas** durante toda la captura.
  En una Wi-Fi conmutada solo se ve de otros equipos tráfico de difusión o no
  identificable (el AP no reenvía su unicast), así que no hubo claves que
  inventariar; se anota aquí el motivo. El mecanismo del inventario sí se verificó
  con datos reales en `HOST_SEEN` (arriba) y con los tests del DAO.
- **Ventanas de 1 h y 24 h con datos reales** tras **62 min** de captura
  (sesión 8, 18:24–19:26 UTC, `privileged` y `capture=1`):
  - **1 h**: Otros 268,5 M (2 459 conexiones), [host] 23,3 M (2 222), Hector's Phone
    309,0 K, hoguera 112,7 K, _gateway 69,2 K, sin identificar 44,7 K e iPad 31,9 K,
    con la cabecera «1 h · histórico» de la pestaña Tráfico.
  - **24 h**: [host] 557,5 M, Otros 504,4 M, _gateway 439,2 M, Hector's Phone 1,1 M,
    hoguera 418,3 K, iPad 190,1 K y sin identificar 148,9 K.
  - **Histórico**: 367,5 M ↓ · 696,1 M ↑, puntos de 30 min y máximo de 582,8 M en la
    hora de las 19:00; la gráfica y la línea de tiempo se pintaron con datos reales.
- **Sin falsos positivos**: durante los 62 min de captura real no se creó ninguna
  alerta en la BD real (el propio equipo aprende 0 de 7 días y no hubo equipos ni
  puertos nuevos), que es el comportamiento esperado de «no avisar de más».
- **Cierre de F4**: las 9 casillas pendientes de F4 quedaron marcadas en su checklist
  (175/175) y sus mediciones están en el informe de implementación de F4
  («Verificación con CAP_NET_RAW (sprint 4.0)»): ARP/ICMP reales, escaneo /24 en
  13,1–14,7 s, port scan de 5 hosts en 1,508 s, 50 K pps sin pérdidas, CPU 6,7 %
  a 10 K pps y 5,0 % a 1 K pps, Δmemoria ≈ 0,4 MB y logs de `-v` sin dominios.
  En 134 muestras de captura de 30 s no hubo pérdidas (`drops=0`); 66 de
  68 lotes del minuto se escribieron en 0 ms, uno en 1 ms y uno en 11 ms al
  coincidir con la conmutación de pestañas de la propia prueba.

## Pendientes y bloqueos

**Sin pendientes técnicos.** La Fase 6 cierra con **174 / 174** funcionalidades del
checklist (incluidas las 4 del sprint 6.0) y la Fase 4 con **175 / 175** (sus 9
casillas de la pasada con ' + bt + 'CAP_NET_RAW' + bt + ' quedaron cerradas el 2026-11-11). Todo
lo medido con captura real está en «Sprint 6.0: evidencia» y en «Ejecución y
pruebas».

- **Entrega**: el desarrollador debe entregar este informe y el de F5 al analista
  funcional antes de especificar la siguiente fase; hasta entonces la
  documentación maestra no refleja la realidad.
- **Fuera de alcance** (no son bloqueos): modo servicio sin TUI (6.5), canales
  externos de alertas y exportación (F7).
- Se anota una **discrepancia de recuento** entre documentos: el maestro de F6
  habla de 176 casillas de F4 y el checklist de F4 declara 175 (todas cerradas);
  el total de Almenara se calcula con los recuentos reales de cada checklist.

## Ejecución y pruebas (cómo arrancar, migrar y testear)

### Arranque y migración

- Arranque normal: `cargo run`. La primera vez que se abre una BD de F5 se
  aplica la **migración v6 aditiva** (tablas de alertas, silencios, aprendizaje,
  `HOST_SEEN` y `COVERAGE_GAPS`; columnas `DEVICES.watched` y
  `DEVICE_SERVICES.closed_at`) sin perder ninguna fila y con los rellenos de
  `closed_at` y aprendizaje.
- Con captura real: `scripts/ejecutar-con-permisos.sh` (el `setcap` necesita el
  `sudo` del desarrollador; no recompilar después).
- La configuración se crea con `[alerts]` completo si no existe; un valor
  inválido se avisa una vez y usa el valor por defecto sin impedir el arranque.
- Sin servidor de notificaciones la app arranca igual; Config muestra
  «NO DISPONIBLE» y las alertas quedan en la pestaña.

### Pruebas

```bash
cargo test                     # suite completa (unitarios + CLI)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Resultado de la pasada final: **1165 tests unitarios + 4 de CLI en verde, 0
fallos, 16 ignorados** (las mediciones y los replays que necesitan red o
`CAP_NET_RAW`), `fmt` limpio y `clippy` sin avisos.

Prueba manual en degradado sobre la **base de datos real** (tmux, 120x40): la
migración v6 se aplicó en la BD existente (versión 6, 8 equipos, 9 filas de
aprendizaje, sesión nueva registrada y cerrada con `q`), y la TUI mostró
Equipos con la leyenda «* vigilado · ! alertas sin ver», la pestaña Alertas
vacía, Reglas con las 16 (incluidas «necesita captura»), Silencios, Config con
`[alerts]`, el notificador DISPONIBLE (servidor quickshell) y el inventario
del propio equipo, y el bloque «Alertas» del detalle de equipo. No hubo que
restaurar nada; la copia previa quedó en `/tmp/almenara-backup/`.

### Prueba funcional de alertas y notificación real (sin CAP, BD temporal)

Con una copia de la base real inflada a 77 MB y `max_db_mb = 64` en un
config.toml temporal se comprobó de extremo a extremo la pestaña Alertas y el
notificador de escritorio (la regla `db_size` es de condición y no necesita
captura):

- Al arrancar se creó la alerta `db_size` de nivel importante con
  `details.porque = "La base de datos ocupa 77,1 MB (límite 64 MB)"`, y quedó
  `notified = 1`: Config mostró «Notificaciones de escritorio: DISPONIBLE
  (servidor: quickshell) · 1 enviadas», es decir, el envío por D-Bus funcionó de verdad.
- El aviso de una línea «▲ Alerta importante: Base de datos grande · 77,2 MB · [5]
  para verla» apareció en pantalla y seguía visible a los 8 s; a los 12 s ya no
  estaba (TTL de 10 s). Tiene prioridad sobre el resto de notificaciones del búfer
  (se corrigió así tras detectar que el resumen del escaneo podía taparlo).
- Acciones de la TUI contra la BD temporal: `Enter` abrió el detalle y marcó la
  alerta como vista; `m` + `1` creó un silencio de un día (visible en Silencios
  como «Base de datos grande · Almenara · 12 Nov 17:08» y borrado después con `x`);
  en Reglas, `espacio` apagó «Equipo nuevo» y `n` cambió su nivel, quedando
  guardado en `[alerts.rules.device_new] enabled = false, level = "warning"`; con 26
  alertas, la primera `T` pidió confirmación y la segunda marcó todas como vistas
  (0 sin ver en la cabecera y `seen_at` relleno en las 26 filas).
- En modo degradado la regla `capture_stopped` no saltó: la única alerta de la BD
  temporal fue la de `db_size`.


Más pruebas funcionales con BD temporal (sin `CAP_NET_RAW`):

- **Puesta al día**: con `catch_up_minutes = 1`, la alerta importante de `db_size`
  se creó durante la puesta al día sin notificar (`notified = 0`) y, al
  cumplirse el minuto, se creó el resumen `catch_up` «Resumen al arrancar
  (1 alerta)» con `summary_id` apuntando a la agrupada, recuentos por regla y
  nivel en `details` y una sola notificación propia; el aviso de una línea
  del resumen apareció en pantalla y el contador pasó de 1 a 2.
- **Horario silencioso**: con `quiet_hours = "17:00-18:00"` a las 17:19, la
  alerta importante se guardó con `notified = 0`, no salió el aviso de una
  línea y Config mostró «Horario silencioso: ahora sí (hasta las 18:00) ·
  17:00-18:00».
- **Marcas de Equipos y tecla e**: con una alerta importante sin ver de un equipo, la
  fila de Equipos mostró «[⌂]!» (marca `!`) y la pestaña Alertas mostró los
  niveles `!! IMP` e `INF` con `●`; en Alertas, `e` abrió Equipos con el
  detalle del equipo y su bloque «Alertas · 1 sin ver». Esta prueba detectó que `e`
  no cambiaba de pestaña: corregido en `aplicar_accion` con un test de
  integración («abrir_equipo_desde_alertas_cambia_a_equipos_y_abre_el_detalle»).

- **Huecos en la línea de tiempo de Histórico**: con una BD temporal que conserva la
  sesión real de F5 y dos huecos insertados dentro de ella, el filtro Almenara de la
  línea de tiempo mostró «Equipo suspendido 13:10–13:20» y «Captura parada
  14:00–14:05» (hora local) junto a los eventos de sesión.

### Mediciones (release)

Las pruebas `medir_*` se ejecutan con:

```bash
cargo test --release --bin almenara medir_ -- --ignored --nocapture --test-threads=1
```

Cifras medidas en esta máquina (equipo de desarrollo, release, `--test-threads=1`):

| Métrica de §8 | Límite | Medido |
|---|---|---|
| `AlertEngine::handle` por señal (10 000 señales) | ≤ 1 ms | **5,88 µs** |
| Evaluación de una hora con 50 equipos y 14 días | ≤ 20 ms | **273,75 µs** (20 horas en 5,48 ms) |
| Aprendizaje de un día con 50 equipos (+ host) | ≤ 50 ms | **0,93 ms** |
| `Queries::alerts` con 20 000 alertas | ≤ 100 ms | **0,37 ms** (todas) · **0,79 ms** (importantes) · **9,89 ms** (página honda) · **1,85 ms** (búsqueda) · **16,03 ms** (30 resúmenes) |
| Migración v6 con sus rellenos sobre 2 años sintéticos | ≤ 2 s | **579,54 ms** |
| Memoria añadida por el motor (2000 claves, 30 silencios, 50 sujetos) | ≤ 4 MB | **3,36 MB** |
| Render con Alertas abierta en 80×24 | ≤ 16 ms | **0,379 ms** |
| Render con Alertas abierta en 120×40 | ≤ 33 ms | **0,704 ms** |
| Escritura del lote del minuto con tráfico real (8 lotes limpios, sin interacción) | ≤ 10 ms | **0 ms** en 5 lotes y **1 ms** en 3 (máximo 1 ms) |
| Captura sostenida a 50 K pps durante 80 s | sin pérdidas | **50 027–50 038 pps capturados, 0 drops** |
| CPU de Almenara con inferencia a 10 K pps | F3 ≤ 15 %, F4 ≤ 20 % | **6,7 %** |
| CPU de Almenara con inferencia a 1 K pps | F3 ≤ 5 %, F4 ≤ 7 % | **5,0 %** |
| RSS con 10 K pps: inferencia activa vs desactivada (F4 ≤ 64 MB) | ≤ 64 MB | **125 708 kB vs 125 280 kB → Δ ≈ 0,4 MB** |
| Render de Equipos con 256 dispositivos en 80×24 / 120×40 (F1-64) | ≤ 16 / 33 ms | **0,699 ms / 1,010 ms** |
| Render de Equipos con 256 dispositivos en 80×24 / 120×40 (F1-64) | ≤ 16 / 33 ms | **0,699 ms / 1,010 ms** |

Cifras de F5 re-medidas en la misma pasada (sin cambios de comportamiento):
histórico sintético de 30 equipos y 2 años, 1 750 065 filas, BD de 80,5 MB;
construcción de una hora 12,48 ms (≤ 50 ms) y de un día 11,41 ms (≤ 100 ms);
consultas 24 h 14,31 ms, 7 días 7,45 ms, 30 días 1,22 ms y 1 año 9,84 ms
(≤ 200/500 ms); purga con la retención por defecto 74,50 ms (≤ 100 ms);
memoria de acumuladores + 10 lotes 11,41 MB (≤ 16 MB).

