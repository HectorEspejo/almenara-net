# Almenara - Fase 6: Alertas (locales + escritorio)

## Especificación Funcional

**Versión:** 1.0
**Fecha:** 2026-11-11
**Cliente:** Uso personal (desarrollador)

---

## 1. Visión General

La Fase 6 convierte lo que Almenara ya sabe en **alertas**. F1–F5 registran los equipos que aparecen, los puertos que se abren, los cambios de identidad, lo que se ve por primera vez en cada equipo, el tráfico por hora y el estado de la captura. F6 los evalúa con un **catálogo fijo de 16 reglas** y crea alertas con tres niveles: solo las **importantes** llegan al escritorio como notificación; los **avisos** suben un contador en la barra y la **info** se queda en la pestaña **Alertas** (vacía desde F1).

La fase cuida sobre todo no avisar de más. Lo nuevo de un equipo no avisa hasta que Almenara lo ha observado **7 días con datos**; la primera exploración de una base de datos vacía no avisa de equipos nuevos; la misma alerta no se repite en **24 horas**; cada regla se puede apagar o **silenciar** para un equipo; al arrancar, lo que llega en los primeros **10 minutos** se junta en un **resumen**, y hay **horario silencioso** y un tope de 3 notificaciones por minuto.

Antes de las alertas, el **sprint 6.0** cierra la pasada pendiente con `CAP_NET_RAW`: el desarrollador aplica la capacidad, el agente mide sin recompilar, cierra las 9 casillas abiertas de F4 y prueba el histórico de F5 con tráfico real.

**Visibilidad honesta.** En una red conmutada o Wi-Fi, Almenara ve casi solo el tráfico de su propio equipo y el de difusión (F3). Las reglas de tráfico (lo nuevo de un equipo y «más tráfico de lo habitual») sirven sobre todo para el **propio equipo** y la **red entera**; para los demás equipos funcionan bien las del escaneo: equipo nuevo, puertos e identidad. Por eso F6 da inventario también al propio equipo (`HOST_SEEN`), que F5 no tenía. Y como Almenara es una TUI, solo avisa mientras está abierta: el **modo servicio** es la sub-fase 6.5, que reutilizará el motor de esta fase.

**Objetivos principales:**
1. Avisar de lo que cambia en la red con 16 reglas sobre las señales de F1–F5: equipos y puertos nuevos, cambios de identidad, lo nuevo en un equipo, tráfico inusual, equipos vigilados y salud de Almenara.
2. No avisar de más: aprendizaje, línea base, deduplicación, silencios, puesta al día, horario silencioso y tope de notificaciones.
3. Tres niveles claros: lo importante al escritorio; el resto, en la pestaña Alertas y en la barra.
4. Huecos honestos: la suspensión del equipo y la captura parada también son huecos para el histórico, el aprendizaje y la regla de tráfico.
5. Saldar la deuda de F5 con `DEVICE_SERVICES.closed_at` y dar inventario al propio equipo.
6. Construir sobre datos medidos: el sprint 6.0 cierra la pasada con `CAP_NET_RAW` de F4 y prueba F5 con tráfico real.

**Contexto:** evolución de F1–F5. F5 está implementada (141/141, versión 0.5.0) y medida con histórico sintético; F4 sigue en 167/176 a falta de la pasada con `CAP_NET_RAW`. Decisiones de la sesión del 2026-11-11: opción recomendada en las 12 preguntas («todo a»). Migración v6 aditiva: toda BD de F5 sigue funcionando sin pérdida de datos.

---

## 2. Arquitectura Técnica

### Stack tecnológico (novedades respecto a F5)

| Capa | Tecnología | Motivo |
|------|-----------|--------|
| Notificaciones | `notify-rust` 4.17 (`default-features = false`, `features = ["z"]`: `zbus` 5, Rust puro) en un hilo propio | Estándar de escritorio de Linux (`org.freedesktop.Notifications` por D-Bus de sesión) sin libdbus; 4.17 es la última versión compatible con la MSRV 1.88 (desde la 4.18 pide Rust 1.89) |
| Motor de alertas | Rust puro, sin dependencias | Se prueba sin BD ni TUI y lo reutilizará el modo servicio (6.5) |
| Mediana | `select_nth_unstable` de la biblioteca estándar | Sin crates de estadística |
| Suspensión | `clock_gettime` con `CLOCK_BOOTTIME` y `CLOCK_MONOTONIC` de `libc` (ya en el stack) | Detecta la suspensión sin depender del reloj de pared |
| Configuración | `toml` + `serde` (ya en el stack), con la reescritura del fichero que ya usa `[ui]` (F2) | Activar reglas y cambiar niveles desde la TUI |

**Una dependencia nueva:** `notify-rust` (con `zbus` 5 y sus dependencias). Se declara como `notify-rust = { version = "~4.17", default-features = false, features = ["z"] }`. Si al resolver el `Cargo.lock` alguna dependencia transitiva pide un Rust mayor que 1.88, el agente la fija a una versión compatible y lo anota como desviación; no sube la MSRV sin hablarlo con el desarrollador.

**Rutas de F1–F5.** Las rutas citadas son las de sus informes e informes de implementación. Si el código real difiere, manda el código y la correspondencia se anota en el informe de implementación.

### Estructura de carpetas (novedades)

```
almenara/
├── docs/fase6/                     # informe, prompt, checklist e implementación
├── CHANGELOG.md                    # novedades de la 0.6.0
└── src/                            # crate solo binario: las pruebas internas van en src/ (#[cfg(test)])
    ├── alerts/                     # NUEVO módulo raíz (motor puro, sin BD ni TUI)
    │   ├── mod.rs                  # tipos: regla, nivel, sujeto, señal, acción, clave de deduplicación
    │   ├── rules.rs                # catálogo de las 16 reglas (§7.1)
    │   ├── engine.rs               # AlertEngine: señales → acciones
    │   ├── baseline.rs             # «más tráfico de lo habitual»: mediana y umbrales (§7.4)
    │   ├── learning.rs             # días con datos (§7.3)
    │   ├── policy.rs               # niveles, puesta al día, horario silencioso y tope (§7.2)
    │   ├── text.rs                 # títulos y notificaciones saneados (§7.13)
    │   ├── health.rs               # salud de la captura y de la BD (§7.8)
    │   └── suspend.rs              # suspensión por CLOCK_BOOTTIME (§7.10)
    ├── notify.rs                   # NUEVO: hilo de notificaciones (notify-rust)
    ├── config.rs                   # (extendido) [alerts] y guardado de reglas
    ├── history/rollup.rs           # (extendido) inventario del propio equipo
    ├── history/queries.rs          # (extendido) consultas de alertas; huecos de COVERAGE_GAPS
    ├── history/synthetic.rs        # (extendido) alertas, silencios, aprendizaje y huecos para medir
    ├── repo/
    │   ├── alerts.rs               # NUEVO DAO de ALERTS y ALERT_MUTES
    │   ├── learning.rs             # NUEVO DAO de ALERT_LEARNING
    │   ├── gaps.rs                 # NUEVO DAO de COVERAGE_GAPS
    │   ├── seen.rs                 # (extendido) HOST_SEEN y entradas nuevas
    │   ├── device_services.rs      # (extendido) closed_at
    │   └── migrations.rs           # migración v6 y rellenos
    ├── tui/alerts_state.rs         # NUEVO: estado de la pestaña Alertas
    └── tui/views/
        ├── alerts.rs               # NUEVO: pestaña Alertas (lista, Reglas y Silencios)
        ├── devices.rs              # (extendido) marcas * y !, tecla p
        ├── device_detail.rs        # (extendido) bloque Alertas, vigilado y aprendizaje
        ├── config_view.rs          # (extendido) [alerts] y notificador
        ├── mod.rs                  # (extendido) contador y aviso de una línea en la barra
        └── help.rs                 # (extendido) alertas y privacidad de las notificaciones
```

### Hilos y flujo de datos

- **Escaneo** (F1/F2): sin cambios. Los eventos de su ciclo (altas, ausencias, vueltas, puertos e identidad) los inserta el hilo de la TUI, que pasa cada evento nuevo al motor.
- **Agregador** (F3–F5): el lote del minuto trae también el inventario del propio equipo; sus estadísticas por segundo (F3) alimentan la salud de la captura.
- **Hilo de la TUI** (único escritor, ADR-35): aplica el lote y pasa al motor lo nuevo que devuelve `Repo::upsert_seen`; tras construir una hora, pasa sus valores y muestras (`Repo::hour_baseline`); tras construir un día, actualiza el aprendizaje; cada minuto, una muestra de salud; cada segundo, un tick y la detección de suspensión. Aplica las acciones del motor (crear, repetir, resolver, resumir) y entrega las notificaciones al notificador.
- **Motor de alertas** (F6): código puro que vive en el hilo de la TUI. Recibe señales y devuelve acciones; no abre la BD ni pinta nada (ADR-68).
- **Lector del histórico** (F5): gana las consultas de la pestaña Alertas y resta los huecos de `COVERAGE_GAPS` en toda cobertura.
- **Notificador** (F6): hilo propio con un canal acotado. Llama a `notify-rust`, que habla con el servidor de notificaciones por D-Bus de sesión. Nunca toca la BD y la TUI nunca lo espera.

### Diagrama de arquitectura

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│             TUI (ratatui) · hilo de la TUI · único escritor SQLite (ADR-35)              │
│ ┌────────────┐ ┌───────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────────────┐ │
│ │ Equipos    │ │ Alertas (5)   │ │ Detalle      │ │ Config       │ │ Barra de estado   │ │
│ │ * vigilado │ │ lista, reglas │ │ alertas y    │ │ [alerts] y   │ │ «Alertas 3» y     │ │
│ │ ! sin ver  │ │ y silencios   │ │ aprendizaje  │ │ notificador  │ │ aviso de 1 línea  │ │
│ └────────────┘ └───────────────┘ └──────────────┘ └──────────────┘ └───────────────────┘ │
│ ┌────────────────────────────────────────┐  ┌──────────────────────────────────────────┐ │
│ │ Motor de alertas (alerts::engine)      │─►│ Repo (escritor): ALERTS, silencios,      │ │
│ │ señales → acciones; puro (para la 6.5) │  │ aprendizaje, huecos, HOST_SEEN           │ │
│ └────────────────────────────────────────┘  └──────────────────────────────────────────┘ │
└───────────────────────────────────────────────┬──────────────────┬──────────┬────────────┘
       ▲                  ▲                     │ consulta    ▲    │          │ Notice
       │ Devices          │ Rollup + salud      │  resultado  │    │          │
       │                  │                     ▼             │    │          ▼
┌──────┴───────┐   ┌──────┴─────────────┐   ┌─────────────────┴──┐ │ ┌─────────────────────┐
│ Escaneo      │   │ Agregador (F3–F5)  │   │ Lector (F5/F6)     │ │ │ Notificador (F6)    │
│ (F1/F2):     │   │ lote, inventario   │   │ alertas, silencios,│ │ │ hilo propio;        │
│ eventos      │   │ y estadísticas     │   │ aprendizaje        │ │ │ notify-rust 4.17    │
└──────────────┘   └────────────────────┘   └──────────┬─────────┘ │ └──────────────┬──────┘
                                                       │           │                │
                                                       │ lee       │ escribe        │ D-Bus
                                                       ▼           ▼                ▼
┌────────────────────────────────────────────────────────────────────────┐ ┌───────────────┐
│ SQLite (WAL): ALERTS · ALERT_MUTES · ALERT_LEARNING · HOST_SEEN ·      │ │ Servidor de   │
│ COVERAGE_GAPS · DEVICES (+ watched) · DEVICE_SERVICES (+ closed_at) ·  │ │ notificaciones│
│ F5: TRAFFIC_ROLLUP_* · DEVICE_SEEN · APP_SESSIONS · DEVICE_EVENTS      │ │ (mako, GNOME…)│
└────────────────────────────────────────────────────────────────────────┘ └───────────────┘
```

---

## 3. Modelo de Datos

### Migración v6 (aditiva, no rompe F1–F5)

```sql
-- v6 — Fase 6: alertas

CREATE TABLE ALERTS (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  rule           TEXT NOT NULL,              -- id de la regla (§7.1) o 'catch_up'
  level          TEXT NOT NULL,              -- 'important' | 'warning' | 'info'
  subject        TEXT NOT NULL,              -- 'device' | 'host' | 'network' | 'almenara'
  device_id      INTEGER NULL REFERENCES DEVICES(id) ON DELETE SET NULL,
  key            TEXT NOT NULL DEFAULT '',   -- clave de la regla: app, país, '22/tcp', 'down'…
  title          TEXT NOT NULL,              -- texto corto ya saneado (§7.13)
  subject_label  TEXT NOT NULL,              -- nombre del sujeto al crear la alerta
  details        TEXT NOT NULL DEFAULT '{}', -- JSON: el porqué (§7.1)
  event_id       INTEGER NULL,               -- DEVICE_EVENTS.id de origen (referencia lógica)
  summary_id     INTEGER NULL,               -- ALERTS.id del resumen que la agrupa (lógica)
  created_at     TIMESTAMP NOT NULL,         -- RFC 3339 UTC (ADR-34)
  last_at        TIMESTAMP NOT NULL,         -- última repetición
  count          INTEGER NOT NULL DEFAULT 1, -- veces dentro del plazo de deduplicación
  seen_at        TIMESTAMP NULL,             -- NULL = no vista
  resolved_at    TIMESTAMP NULL,             -- solo alertas de condición
  notified       BOOLEAN NOT NULL DEFAULT 0  -- se envió notificación de escritorio
);
CREATE INDEX IDX_ALERTS_LAST_AT ON ALERTS(last_at);              -- lista y purga
CREATE INDEX IDX_ALERTS_DEVICE ON ALERTS(device_id, last_at);    -- detalle de equipo
CREATE INDEX IDX_ALERTS_UNSEEN ON ALERTS(level) WHERE seen_at IS NULL;  -- contador

CREATE TABLE ALERT_MUTES (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  rule        TEXT NOT NULL,
  subject     TEXT NOT NULL,
  device_id   INTEGER NOT NULL DEFAULT 0,      -- DEVICES.id si subject = 'device'; 0 en otro caso
  until       TIMESTAMP NULL,                  -- NULL = siempre
  created_at  TIMESTAMP NOT NULL,
  UNIQUE (rule, subject, device_id)
);

CREATE TABLE ALERT_LEARNING (
  subject        TEXT NOT NULL,                -- 'device' | 'host'
  device_id      INTEGER NOT NULL DEFAULT 0,   -- 0 = propio equipo
  learning_from  TIMESTAMP NOT NULL,           -- desde cuándo cuentan los días
  data_days      INTEGER NOT NULL DEFAULT 0,
  learned_at     TIMESTAMP NULL,               -- NULL mientras aprende
  updated_day    INTEGER NOT NULL DEFAULT 0,   -- último día local contado (AAAAMMDD, ADR-56)
  PRIMARY KEY (subject, device_id)
) WITHOUT ROWID;

CREATE TABLE HOST_SEEN (
  kind        TEXT NOT NULL,                   -- 'app' | 'category' | 'org' | 'country' | 'ja4'
  key         TEXT NOT NULL,
  first_seen  TIMESTAMP NOT NULL,
  last_seen   TIMESTAMP NOT NULL,
  PRIMARY KEY (kind, key)
) WITHOUT ROWID;
CREATE INDEX IDX_HOST_SEEN_LAST_SEEN ON HOST_SEEN(last_seen);  -- purga

CREATE TABLE COVERAGE_GAPS (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id  INTEGER NOT NULL REFERENCES APP_SESSIONS(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,                   -- 'suspend' | 'capture'
  started_at  TIMESTAMP NOT NULL,
  ended_at    TIMESTAMP NULL                   -- NULL mientras dura (solo 'capture')
);
CREATE INDEX IDX_GAPS_SESSION ON COVERAGE_GAPS(session_id);
CREATE INDEX IDX_GAPS_STARTED ON COVERAGE_GAPS(started_at);

ALTER TABLE DEVICES ADD COLUMN watched BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE DEVICE_SERVICES ADD COLUMN closed_at TIMESTAMP NULL;

-- Rellenos, una sola vez y en la misma transacción: closed_at (§7.12) y aprendizaje (§7.3)
```

- Sin `CHECK` en enumeraciones (regla transversal): `rule`, `level`, `subject` y `kind` se validan en el código.
- `ALERTS.event_id` y `summary_id` son referencias lógicas, sin clave ajena: los eventos se purgan a su ritmo (90 días) y la alerta guarda en `details` lo que necesita mostrar.
- `ALERT_MUTES` y `ALERT_LEARNING` usan `device_id = 0` para los sujetos que no son equipos, como los rollups (ADR-55): sin clave ajena; el DAO borra sus filas cuando se borra el equipo.
- `DEVICES.watched` es una preferencia de la persona, como `alias` o las notas.
- `DEVICE_SERVICES.closed_at` sustituye al apaño de F5: el estado CERRADO ya no depende de `last_seen` (§7.12).

### Diagrama E-R (parte nueva)

```
┌──────────────────────────────────┐            ┌────────────────────────────────────┐
│ DEVICES (F1, ampl. F2–F6)        │            │ ALERTS (F6)                        │
├──────────────────────────────────┤ 1     0..N ├────────────────────────────────────┤
│ id (PK) · mac · ip · …           ├───────────►│ id (PK)                            │
│ watched (F6)                     │ SET NULL   │ rule · level · subject             │
└───────┬───────────────────┬──────┘            │ device_id (FK NULL)                │
        │ 1                 │ 1                 │ key · title · subject_label        │
        │                   │                   │ details (JSON)                     │
        │ FK (F2)           │ lógica            │ event_id · summary_id (lógicas)    │
        │                   │                   │ created_at · last_at · count       │
        │ 0..N              │ 0..N              │ seen_at · resolved_at              │
        │                   │                   │ notified                           │
        ▼                   ▼                   └────────────────────────────────────┘
┌───────────────────────┐ ┌────────────────────────────┐ ┌───────────────────────────┐
│ DEVICE_SERVICES (F2)  │ │ ALERT_MUTES (F6)           │ │ ALERT_LEARNING (F6)       │
├───────────────────────┤ ├────────────────────────────┤ ├───────────────────────────┤
│ port · protocol · …   │ │ id (PK) · rule             │ │ subject · device_id (PK)  │
│ first_seen · last_seen│ │ subject · device_id        │ │   (0 = propio equipo)     │
│ closed_at (F6)        │ │   (0 = no es un equipo)    │ │ learning_from             │
└───────────────────────┘ │ until (NULL = siempre)     │ │ data_days · learned_at    │
                          │ created_at                 │ │ updated_day               │
                          │ UNIQUE(rule, subject,      │ │ WITHOUT ROWID             │
                          │   device_id)               │ └───────────────────────────┘
                          └────────────────────────────┘

┌────────────────────────┐          ┌────────────────────────────┐ ┌─────────────────┐
│ APP_SESSIONS (F5)      │          │ COVERAGE_GAPS (F6)         │ │ HOST_SEEN (F6)  │
├────────────────────────┤ 1  0..N  ├────────────────────────────┤ ├─────────────────┤
│ id (PK) · started_at   ├─────────►│ id (PK)                    │ │ kind · key (PK) │
│ ended_at · capture …   │ CASCADE  │ session_id (FK)            │ │ first_seen      │
└────────────────────────┘          │ kind ('suspend'|'capture') │ │ last_seen       │
                                    │ started_at · ended_at      │ │ WITHOUT ROWID   │
                                    └────────────────────────────┘ └─────────────────┘
ALERT_MUTES y ALERT_LEARNING apuntan a DEVICES.id sin clave ajena (device_id = 0 para los
sujetos que no son equipos, como en los rollups, ADR-55); el DAO las borra con el equipo.
ALERTS.event_id (DEVICE_EVENTS) y summary_id (ALERTS) son referencias lógicas: se purgan
a su ritmo y la alerta guarda en details lo que necesita. HOST_SEEN no se relaciona: es el
inventario del propio equipo, que no está en DEVICES.
```

### Definición de tablas

**ALERTS** — cada alerta creada por una regla.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK | Identificador |
| `rule` | TEXT | Id de la regla (§7.1) o `catch_up` para el resumen de la puesta al día |
| `level` | TEXT | `important`, `warning` o `info` (en la TUI: importante, aviso, info) |
| `subject` | TEXT | `device`, `host` (propio equipo), `network` (red entera) o `almenara` (salud y resumen) |
| `device_id` | INTEGER FK NULL | `DEVICES.id` si `subject = 'device'`; queda NULL si se borra el equipo |
| `key` | TEXT | Clave de la regla (app, categoría, país, organización, JA4, `22/tcp`, `down`/`up`, `gone`/`back`…); vacía si no aplica |
| `title` | TEXT | Texto corto ya compuesto y saneado («Puerto nuevo: 22/tcp (ssh)») |
| `subject_label` | TEXT | Nombre del sujeto al crearla (alias, nombre, IP o MAC) |
| `details` | TEXT (JSON) | El porqué de la alerta (§7.1) |
| `event_id` | INTEGER NULL | Evento de origen (referencia lógica) |
| `summary_id` | INTEGER NULL | Resumen de la puesta al día que la agrupa (referencia lógica) |
| `created_at` | TIMESTAMP | Creación |
| `last_at` | TIMESTAMP | Última repetición; ordena la lista |
| `count` | INTEGER | Veces que ha saltado dentro del plazo de deduplicación |
| `seen_at` | TIMESTAMP NULL | Cuándo se vio; NULL = no vista |
| `resolved_at` | TIMESTAMP NULL | Cuándo desapareció la condición (solo alertas de condición) |
| `notified` | BOOLEAN | Se envió notificación de escritorio |

**ALERT_MUTES** — silencios de una regla para un sujeto.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK | Identificador |
| `rule` | TEXT | Regla silenciada |
| `subject` | TEXT | Sujeto (`device`, `host`, `network` o `almenara`) |
| `device_id` | INTEGER | `DEVICES.id` si `subject = 'device'`; 0 en otro caso |
| `until` | TIMESTAMP NULL | Fin del silencio; NULL = siempre |
| `created_at` | TIMESTAMP | Creación |

**ALERT_LEARNING** — aprendizaje de lo nuevo por sujeto.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `subject` | TEXT PK | `device` o `host` |
| `device_id` | INTEGER PK | `DEVICES.id`; 0 para el propio equipo |
| `learning_from` | TIMESTAMP | Desde cuándo cuentan los días: alta del equipo; para el propio equipo, la migración v6 |
| `data_days` | INTEGER | Días con datos contados (§7.3) |
| `learned_at` | TIMESTAMP NULL | Fin del día en que llegó a `learning_days`; NULL mientras aprende |
| `updated_day` | INTEGER | Último día local contado (AAAAMMDD) |

**HOST_SEEN** — inventario del propio equipo (el que `DEVICE_SEEN` no puede guardar, porque `host` no está en `DEVICES`).

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `kind` | TEXT PK | `app`, `category`, `org`, `country` o `ja4` |
| `key` | TEXT PK | Clave (como en `DEVICE_SEEN`) |
| `first_seen` | TIMESTAMP | Primer minuto en que se vio |
| `last_seen` | TIMESTAMP | Último minuto en que se vio |

**COVERAGE_GAPS** — huecos dentro de una sesión de Almenara.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK | Identificador |
| `session_id` | INTEGER FK | `APP_SESSIONS.id`, borrado en cascada |
| `kind` | TEXT | `suspend` (equipo suspendido: sin tráfico ni escaneo) o `capture` (captura parada: sin tráfico) |
| `started_at` | TIMESTAMP | Inicio |
| `ended_at` | TIMESTAMP NULL | Fin; NULL mientras dura |

**Columnas nuevas.** `DEVICES.watched` (BOOLEAN, 0 por defecto): equipo vigilado (§7.7). `DEVICE_SERVICES.closed_at` (TIMESTAMP NULL): cuándo un escaneo vio cerrado el puerto (§7.12).

### Relaciones

- `DEVICES` 1 — N `ALERTS` (clave ajena con `ON DELETE SET NULL`: la alerta sobrevive con `subject_label`).
- `DEVICES` 1 — N `ALERT_MUTES` y 1 — 0..1 `ALERT_LEARNING`: relaciones lógicas, sin clave ajena (`device_id = 0` para los sujetos que no son equipos); el DAO borra sus filas con el equipo.
- `APP_SESSIONS` 1 — N `COVERAGE_GAPS` (clave ajena con borrado en cascada: los huecos viven lo que su sesión, 2 años).
- `DEVICE_EVENTS` 1 — 0..N `ALERTS` por `event_id` y `ALERTS` 1 — N `ALERTS` por `summary_id`: referencias lógicas.
- `HOST_SEEN` no tiene relaciones: es el inventario del propio equipo.
- `DEVICE_SERVICES` (F2) gana `closed_at`; `DEVICE_SEEN`, los rollups y `DEVICE_EVENTS` (F5) no cambian de esquema.

### Diagrama de estados — alerta (`ALERTS`)

```
┌──────────────────────────────┐ repite  ┌───────────────────────────┐
│ NUEVA (no vista)             ├────────►│ count + 1 y last_at en la │
│ seen_at NULL; cuenta en la   │         │ misma fila; sin notificar │
│ barra (importante o aviso)   │         │ (dentro de 24 h)          │
└───────────────┬──────────────┘         └───────────────────────────┘
                │ Enter, espacio o T
                ▼
┌──────────────────────────────┐
│ VISTA                        │
│ seen_at = momento en que     │
│ se vio                       │
└───────────────┬──────────────┘
                │ vence la retención (90 días)
                ▼
┌──────────────────────────────┐
│ PURGADA                      │
└──────────────────────────────┘

Alertas de condición (captura parada, pérdidas, base de datos grande, vigilado ausente),
a la vez que lo anterior: ACTIVA (resolved_at NULL) → RESUELTA (resolved_at) cuando la
condición desaparece o se apaga la regla. Si vuelve dentro de las 24 h, se reactiva la
misma fila (resolved_at NULL, count + 1), sin notificar otra vez.

Transiciones inválidas:
 · VISTA → NUEVA (no hay «marcar como no vista»)
 · RESUELTA en una alerta que no es de condición
 · borrarla a mano (solo la purga) o crear otra fila con la misma clave dentro de 24 h
```

### Diagrama de estados — silencio (`ALERT_MUTES`)

```
┌──────────────────────────────┐   x   ┌──────────────────┐
│ ACTIVO                       ├──────►│ QUITADO          │
│ until futura o NULL          │       │ fila borrada     │
│ (siempre)                    │       └──────────────────┘
└───────────────┬──────────────┘
                │ pasa until
                ▼
┌──────────────────────────────┐
│ CADUCADO                     │
│ se ignora al evaluar         │
└───────────────┬──────────────┘
                │ purga horaria
                ▼
┌──────────────────────────────┐
│ BORRADO                      │
└──────────────────────────────┘

Transiciones inválidas:
 · CADUCADO → ACTIVO (se crea un silencio nuevo)
 · caducar un silencio «siempre» (until NULL)
 · dos filas para la misma regla, sujeto y equipo (el silencio nuevo sustituye al
   anterior)
```

### Diagrama de estados — aprendizaje de un sujeto (`ALERT_LEARNING`)

```
┌──────────────────────────────┐
│ APRENDIENDO                  │
│ data_days < learning_days;   │
│ lo nuevo se apunta sin avisar│
└───────────────┬──────────────┘
                │ se cierra un día local
                ▼
┌──────────────────────────────┐  no   ┌───────────────────┐
│ ¿fue un día con datos del    ├──────►│ no cuenta         │
│ sujeto?                      │       └───────────────────┘
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ data_days + 1                │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  no   ┌───────────────────┐
│ ¿data_days ≥                 ├──────►│ sigue APRENDIENDO │
│ learning_days?               │       └───────────────────┘
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ APRENDIDO                    │
│ learned_at = fin del día;    │
│ lo nuevo avisa               │
└──────────────────────────────┘

Día con datos: día local con ≥ 1 h de cobertura de tráfico y tráfico del sujeto en
TRAFFIC_ROLLUP_DAY (§7.3).

Transiciones inválidas:
 · APRENDIDO → APRENDIENDO (ni al purgar datos ni al cambiar learning_days)
 · contar días anteriores a learning_from o días sin cobertura
 · aprender el sujeto network (solo lo usa «más tráfico de lo habitual»)
```

### Diagrama de estados — entrada del inventario del propio equipo (`HOST_SEEN`)

```
┌──────────────────────────────┐ aprendido ┌──────────────────────┐
│ NUEVA                        ├──────────►│ señal de lo nuevo    │
│ first_seen = last_seen =     │           │ (new_app, new_org…)  │
│ minuto del lote              │           └──────────────────────┘
└───────────────┬──────────────┘
                │ se vuelve a ver
                ▼
┌──────────────────────────────┐
│ VIGENTE                      │
│ last_seen = último minuto    │
│ en que se vio                │
└───────────────┬──────────────┘
                │ sin verse en day_days
                ▼
┌──────────────────────────────┐
│ PURGADA                      │
└──────────────────────────────┘

El mismo ciclo que DEVICE_SEEN (F5), para el propio equipo.

Transiciones inválidas:
 · first_seen posterior a last_seen, o last_seen hacia atrás
 · claves especiales (~…) o destinos en el inventario
 · señal de lo nuevo mientras el propio equipo aprende
```

### Diagrama de estados — puerto de un equipo (`DEVICE_SERVICES`, F2 + F5 + F6)

```
┌──────────────────────────────┐
│ SIN ESCANEAR                 │
│ equipo sin primer escaneo    │
│ de puertos                   │
└───────────────┬──────────────┘
                │ primer escaneo (sin eventos)
                ▼
┌──────────────────────────────┐ tiempo  ┌──────────────────────┐
│ ABIERTO                      ├────────►│ OBSOLETO (STALE, F2) │
│ last_seen = último escaneo   │         │ last_seen > umbral;  │
│ que lo vio abierto           │         │ sin evento           │
└───────────────┬──────────────┘         └──────────────────────┘
                │ un escaneo lo ve cerrado
                ▼
┌──────────────────────────────┐
│ CERRADO                      │
│ closed_at = ahora (F6);      │
│ service_gone                 │
└───────────────┬──────────────┘
                │ un escaneo lo ve abierto
                ▼
┌──────────────────────────────┐
│ ABIERTO                      │
│ closed_at = NULL;            │
│ service_new (reopened)       │
└──────────────────────────────┘

Un puerto OBSOLETO que un escaneo ve cerrado pasa a CERRADO (service_gone); si lo ve
abierto, vuelve a ABIERTO sin evento, porque no llegó a cerrarse.

Transiciones inválidas:
 · mover last_seen al cerrar (lo hacía F5; desde la v6 last_seen no se toca)
 · CERRADO → OBSOLETO, o service_gone sin escaneo de puertos
 · eventos de servicios en el primer escaneo o con passive_only
```

### Diagrama de estados — hueco dentro de una sesión (`COVERAGE_GAPS`)

```
┌──────────────────────────────┐ salida  ┌─────────────────────────┐
│ ABIERTO                      ├────────►│ CERRADO al salir:       │
│ kind = capture;              │         │ ended_at = cierre de la │
│ ended_at NULL                │         │ sesión                  │
└───────────────┬──────────────┘         └─────────────────────────┘
                │ vuelve la captura
                ▼
┌──────────────────────────────┐
│ CERRADO                      │
│ ended_at = vuelta            │
└───────────────┬──────────────┘
                │ se purga su sesión
                ▼
┌──────────────────────────────┐
│ BORRADO (cascada)            │
└──────────────────────────────┘

Una suspensión se detecta al volver (§7.10): su hueco nace ya CERRADO (kind = suspend).
El hueco abierto de una sesión interrumpida se cierra en el arranque siguiente con el
ended_at de su sesión.

Transiciones inválidas:
 · reabrir un hueco CERRADO
 · dos huecos abiertos del mismo tipo en la misma sesión
 · un hueco que empieza antes de su sesión o acaba después de ella
```

### Diagrama de estados — notificaciones de una sesión

```
┌──────────────────────────────┐
│ PUESTA AL DÍA                │
│ 10 min tras arrancar;        │
│ las alertas no notifican     │
└───────────────┬──────────────┘
                │ pasan los 10 min
                ▼
┌──────────────────────────────┐   sí    ┌─────────────────────────┐
│ ¿hubo alertas?               ├────────►│ alerta resumen y 1      │
└───────────────┬──────────────┘         │ notificación si hay     │
                │ no                     │ importantes             │
                │                        └─────────────────────────┘
                ▼
┌──────────────────────────────┐ horario ┌─────────────────────────┐
│ NORMAL                       ├────────►│ SILENCIOSO              │
│ importante → notificación    │         │ dentro de quiet_hours:  │
│ (≤ 3 por minuto)             │         │ se guardan sin notificar│
└──────────────────────────────┘         └─────────────────────────┘

La rama «sí» de «¿hubo alertas?» sigue en NORMAL; SILENCIOSO vuelve a NORMAL al acabar
el horario.

Transiciones inválidas:
 · notificar durante la PUESTA AL DÍA (solo el resumen, al final)
 · más de un resumen por sesión
 · notificar dentro de quiet_hours
```

### Diagrama de estados — notificador

```
┌──────────────────────────────┐ config  ┌──────────────────────┐
│ DISPONIBLE                   ├────────►│ APAGADO              │
│ envía por D-Bus de sesión    │         │ desktop_notifications│
└───────────────┬──────────────┘         │ = false              │
                │                        └──────────────────────┘
                │ error de D-Bus o sin servidor
                ▼
┌──────────────────────────────┐
│ NO DISPONIBLE                │
│ aviso único en Config; las   │
│ alertas siguen en la TUI     │
└───────────────┬──────────────┘
                │ 10 min y llega otra
                ▼
┌──────────────────────────────┐
│ REINTENTO                    │
│ envía la siguiente           │
└──────────────────────────────┘

REINTENTO pasa a DISPONIBLE si el envío funciona y vuelve a NO DISPONIBLE si falla.

Transiciones inválidas:
 · reintentar en cada alerta (como mucho una vez cada 10 minutos)
 · bloquear el hilo de la TUI esperando a D-Bus
 · salir de APAGADO sin cambiar la configuración y reiniciar
```

---

## 4. Flujos de Trabajo

### 4.1 De la señal a la alerta

```
┌──────────────────────────────┐
│ señal: evento, lo nuevo,     │
│ hora cerrada o salud         │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   no    ┌───────────────────────┐
│ ¿[alerts] y la regla         ├────────►│ descartar             │
│ activos?                     │         └───────────────────────┘
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐   sí    ┌───────────────────────┐
│ ¿línea base o sujeto         ├────────►│ sin alerta (el        │
│ aprendiendo?                 │         │ inventario ya lo      │
└───────────────┬──────────────┘         │ apuntó)               │
                │ no                     └───────────────────────┘
                ▼
┌──────────────────────────────┐   sí    ┌───────────────────────┐
│ ¿silenciada (regla,          ├────────►│ descartar             │
│ sujeto, equipo)?             │         └───────────────────────┘
└───────────────┬──────────────┘
                │ no
                ▼
┌──────────────────────────────┐   sí    ┌───────────────────────┐
│ ¿misma clave en 24 h?        ├────────►│ repetición: count + 1,│
└───────────────┬──────────────┘         │ last_at; sin notificar│
                │ no                     └───────────────────────┘
                ▼
┌──────────────────────────────┐  error  ┌───────────────────────┐
│ Repo::insert_alert           ├────────►│ reintento en el minuto│
└───────────────┬──────────────┘         │ siguiente; aviso único│
                │                        └───────────────────────┘
                ▼
┌──────────────────────────────┐   no    ┌───────────────────────┐
│ ¿nivel importante?           ├────────►│ pestaña; los avisos   │
└───────────────┬──────────────┘         │ suben el contador     │
                │ sí                     └───────────────────────┘
                ▼
┌──────────────────────────────┐   sí    ┌───────────────────────┐
│ ¿puesta al día, horario      ├────────►│ al resumen o sin      │
│ silencioso o tope?           │         │ notificación          │
└───────────────┬──────────────┘         └───────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐  falla  ┌───────────────────────┐
│ Notifier (hilo): D-Bus       ├────────►│ NO DISPONIBLE: la     │
└──────────────────────────────┘         │ alerta sigue en la TUI│
                                         └───────────────────────┘
```

1. Una señal llega al motor: un evento recién insertado (F1/F2/F5), las entradas nuevas del inventario de un lote, una hora cerrada o una muestra de salud.
2. El motor busca la regla (§7.1). Si `[alerts]` está apagado o la regla también, no hace nada.
3. Durante la línea base (§7.9) no hay alertas de equipo nuevo; mientras un sujeto aprende (§7.3) no hay alertas de lo nuevo: el inventario ya lo apuntó y no se pierde nada.
4. Si hay un silencio vigente para la regla, el sujeto y el equipo (§7.6), se descarta.
5. Si la misma clave (regla, sujeto, equipo y clave) saltó en las últimas 24 h, es una repetición: suma `count` y `last_at` en la misma fila, sin notificar (§7.5). Las alertas de condición se reactivan o siguen activas.
6. Si no, el hilo de la TUI crea la alerta (`Repo::insert_alert`). Si la escritura falla, la acción espera al minuto siguiente y se avisa una vez.
7. Una alerta de nivel info solo aparece en la pestaña; un aviso sube además el contador de la barra; una importante pasa por la política de notificación (§7.2): puesta al día, horario silencioso y tope por minuto.
8. El notificador la envía por D-Bus en su hilo. Si no hay servidor, queda NO DISPONIBLE y la alerta sigue en la TUI.

### 4.2 Más tráfico de lo habitual

```
┌──────────────────────────────┐
│ hora cerrada y               │
│ consolidada (build_hour)     │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   no    ┌──────────────────────┐
│ ¿cobertura de tráfico        ├────────►│ no se evalúa (hueco) │
│ completa en la hora?         │         └──────────────────────┘
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ por sujeto (equipos, propio  │
│ equipo y red) y sentido      │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   < 5   ┌──────────────────────┐
│ muestras: esa hora local en  ├────────►│ sin base: no avisa   │
│ los 14 días anteriores con   │         └──────────────────────┘
│ cobertura completa           │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ mediana de las muestras      │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   no    ┌──────────────────────┐
│ ¿valor ≥ 3 × mediana y       ├────────►│ nada                 │
│ ≥ mínimo del sentido?        │         └──────────────────────┘
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ señal traffic_high (clave    │
│ down o up) → §4.1            │
└──────────────────────────────┘
```

Al consolidar una hora (F5, §4.2), `Repo::hour_baseline` lee el total de la hora y las muestras de los 14 días anteriores para cada sujeto con tráfico: equipos, propio equipo y red. El motor aplica `Baseline::evaluate` por sentido y crea las señales (§7.4). Las horas con huecos no se evalúan ni sirven de muestra. Las horas pendientes que se construyen al arrancar tampoco se evalúan: las alertas nacen en vivo (§7.9).

### 4.3 Aprendizaje

```
┌──────────────────────────────┐
│ día local consolidado        │
│ (build_day)                  │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ para cada sujeto que         │
│ aprende (equipos, propio)    │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   no    ┌──────────────────────────┐
│ ¿≥ 1 h de cobertura de       ├────────►│ el día no cuenta         │
│ tráfico y tráfico del        │         └──────────────────────────┘
│ sujeto ese día?              │
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ data_days + 1;               │
│ updated_day = día            │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   sí    ┌──────────────────────────┐
│ ¿data_days ≥                 ├────────►│ learned_at = fin del día;│
│ learning_days?               │         │ lo nuevo empieza a avisar│
└───────────────┬──────────────┘         └──────────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐
│ sigue aprendiendo            │
└──────────────────────────────┘
```

Al consolidar un día local (F5), `Repo::update_learning` cuenta el día para cada sujeto que aprende si fue un día con datos, y fija `learned_at` al llegar a `learning_days`. El motor recarga el aprendizaje con lo que devuelve.

### 4.4 Arranque y puesta al día

```
┌──────────────────────────────┐
│ arranque (F5: instancia,     │
│ migraciones y sesiones)      │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  falla  ┌────────────────────────┐
│ v6 una sola vez: tablas,     ├────────►│ modal de BD de F1:     │
│ columnas, closed_at y        │         │ reintentar o salir     │
│ aprendizaje inicial          │         └────────────────────────┘
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ cerrar los huecos abiertos   │
│ de la sesión interrumpida    │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ Repo::engine_snapshot →      │
│ AlertEngine::new             │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   sí    ┌────────────────────────┐
│ ¿DEVICES vacía?              ├────────►│ línea base: la primera │
└───────────────┬──────────────┘         │ exploración no avisa de│
                │ no                     │ equipos nuevos         │
                │                        └────────────────────────┘
                ▼
┌──────────────────────────────┐
│ PUESTA AL DÍA (10 min):      │
│ alertas sin notificar        │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   sí    ┌────────────────────────┐
│ ¿hubo alertas?               ├────────►│ alerta resumen y 1     │
└───────────────┬──────────────┘         │ notificación si hay    │
                │ no                     │ importantes            │
                │                        └────────────────────────┘
                ▼
┌──────────────────────────────┐
│ funcionamiento normal        │
└──────────────────────────────┘

Las ramas «sí» siguen al paso siguiente.
```

1. Tras el arranque de F5 (instancia, migraciones, sesiones), la migración v6 crea tablas y columnas y rellena `closed_at` y el aprendizaje inicial, una sola vez.
2. `Repo::close_open_sessions` cierra también los huecos que quedaron abiertos en una sesión interrumpida.
3. `Repo::engine_snapshot` da al motor los silencios vigentes, el aprendizaje, las claves de las últimas 24 h y las condiciones activas.
4. Si `DEVICES` está vacía, empieza la línea base hasta el final del primer ciclo de escaneo completo.
5. Durante la puesta al día (10 minutos) las alertas se crean pero no notifican. Al final, si hubo alguna, una alerta resumen las agrupa y, si alguna era importante, sale una sola notificación.

### 4.5 Huecos dentro de la sesión

```
┌──────────────────────────────┐
│ tick de la TUI (1 s)         │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  sí   ┌─────────────────────────┐
│ ¿CLOCK_BOOTTIME avanzó       ├──────►│ hueco suspend ya        │
│ > 60 s más que               │       │ cerrado: [tick anterior,│
│ CLOCK_MONOTONIC?             │       │ ahora]                  │
└───────────────┬──────────────┘       └─────────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐  sí   ┌─────────────────────────┐
│ ¿la captura pasó de activa   ├──────►│ abrir hueco capture;    │
│ a parada o con error?        │       │ señal capture_stopped   │
└───────────────┬──────────────┘       └─────────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐  sí   ┌─────────────────────────┐
│ ¿volvió a capturar?          ├──────►│ cerrar el hueco;        │
└───────────────┬──────────────┘       │ resolver la alerta      │
                │ no                   └─────────────────────────┘
                ▼
┌──────────────────────────────┐
│ seguir                       │
└──────────────────────────────┘

Las ramas «sí» también siguen al paso siguiente.
```

En cada tick (1 s), `Suspend::detect` compara cuánto han avanzado `CLOCK_BOOTTIME` (cuenta la suspensión) y `CLOCK_MONOTONIC` (no la cuenta). Si la diferencia crece más de 60 s, el equipo estuvo suspendido y se guarda un hueco `suspend` ya cerrado. Cuando la captura pasa de activa a parada o con error sin que la persona haya salido, se abre un hueco `capture` (y la regla de captura parada recibe su señal); se cierra cuando vuelve a capturar.

### 4.6 Secuencia — equipo nuevo con notificación

```
 Escaneo          TUI/Repo              Motor            SQLite        Notificador        D-Bus
    │                 │                   │                 │               │               │
    │ Devices (ciclo) │                   │                 │               │               │
    ├────────────────►│                   │                 │               │               │
    │                 │ evento new        │                 │               │               │
    │                 ├───────────────────┼────────────────►│               │               │
    │                 │ Signal::Event     │                 │               │               │
    │                 ├──────────────────►│                 │               │               │
    │                 │                   │ device_new;     │               │               │
    │                 │                   │ MAC fija        │               │               │
    │                 │ Insert + Notify   │                 │               │               │
    │                 │◄──────────────────┤                 │               │               │
    │                 │ insert_alert      │                 │               │               │
    │                 ├───────────────────┼────────────────►│               │               │
    │                 │ inserted(id)      │                 │               │               │
    │                 ├──────────────────►│                 │               │               │
    │                 │ Notice            │                 │               │               │
    │                 ├───────────────────┼─────────────────┼──────────────►│               │
    │                 │                   │                 │               │ Notify        │
    │                 │                   │                 │               ├──────────────►│
    │                 │ barra: Alertas 1  │                 │               │               │
    │                 │                   │                 │               │ no espera     │
    │                 │                   │                 │               │               │
```

### 4.7 Secuencia — app nueva en el propio equipo

```
Agregador         TUI/Repo             SQLite             Motor          Lector
    │                 │                   │                 │               │
    │ flush(10:59)    │                   │                 │               │
    │ Rollup + vistos │                   │                 │               │
    ├────────────────►│                   │                 │               │
    │                 │ upsert_seen       │                 │               │
    │                 ├──────────────────►│                 │               │
    │                 │ nuevas: steam     │                 │               │
    │                 │◄──────────────────┤                 │               │
    │                 │ Signal::Seen      │                 │               │
    │                 ├───────────────────┼────────────────►│               │
    │                 │                   │                 │ aprendido     │
    │                 │                   │                 │ nivel info    │
    │                 │ Insert            │                 │               │
    │                 │◄──────────────────┼─────────────────┤               │
    │                 │ insert_alert      │                 │               │
    │                 ├──────────────────►│                 │               │
    │                 │ alerts #12        │                 │               │
    │                 ├───────────────────┼─────────────────┼──────────────►│
    │                 │                   │ SELECT ALERTS   │               │
    │                 │                   │◄────────────────┼───────────────┤
    │                 │ History #12       │                 │               │
    │                 │◄──────────────────┼─────────────────┼───────────────┤
    │                 │ pinta Alertas     │                 │               │
    │                 │                   │                 │               │
```

### 4.8 Secuencia — más tráfico de lo habitual al cerrar la hora

```
TUI/Repo           SQLite             Motor            Lector
    │                 │                 │                 │
    │ 22:00:00        │                 │                 │
    │ build_hour 21 h │                 │                 │
    ├────────────────►│                 │                 │
    │ hour_baseline   │                 │                 │
    ├────────────────►│                 │                 │
    │ 21 h + 14 días  │                 │                 │
    │◄────────────────┤                 │                 │
    │ HourClosed      │                 │                 │
    ├─────────────────┼────────────────►│                 │
    │                 │                 │ host ↓ 2.4 GB   │
    │                 │                 │ mediana 400 MB  │
    │                 │                 │ ×6 ≥ ×3: aviso  │
    │ Insert          │                 │                 │
    │◄────────────────┼─────────────────┤                 │
    │ insert_alert    │                 │                 │
    ├────────────────►│                 │                 │
    │ Alertas +1      │                 │                 │
    │ alerts #20      │                 │                 │
    ├─────────────────┼─────────────────┼────────────────►│
    │ History #20     │                 │                 │
    │◄────────────────┼─────────────────┼─────────────────┤
    │                 │                 │                 │
```

La alerta de las 22:00 es un aviso: sube el contador, no notifica. Si vuelve a saltar a las 23:00, la misma fila suma `count = 2` (§7.5).

---
## 5. API Endpoints (servicios internos)

No hay API HTTP. La fase añade los siguientes servicios internos. Las firmas son de referencia: si la arquitectura real pide otra forma, se adapta conservando lo que hacen y se anota como desviación (regla transversal de F5).

### `alerts` (motor, puro: sin BD ni TUI)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `AlertEngine::new` | `fn(cfg: &AlertsConfig, snap: EngineSnapshot) -> AlertEngine` | Estado inicial: silencios, aprendizaje, claves de 24 h, condiciones activas, línea base y puesta al día |
| `AlertEngine::handle` | `fn(&mut self, signal: Signal, now: SystemTime) -> Vec<AlertAction>` | Evalúa una señal y devuelve acciones: crear, repetir, resolver, resumir o notificar (§4.1) |
| `AlertEngine::inserted` | `fn(&mut self, key: &DedupKey, id: i64)` | Apunta el id de una alerta recién creada (deduplicación y condiciones) |
| `AlertEngine::reload` | `fn(&mut self, cfg: &AlertsConfig, snap: EngineSnapshot)` | Recarga tras cambiar una regla, un silencio o el aprendizaje |
| `Rules::catalog` | `fn() -> &'static [RuleDef]` | Las 16 reglas: id, nombre, señal, nivel por defecto, si aprende y si es de condición (§7.1) |
| `Baseline::evaluate` | `fn(value: u64, samples: &[u64], min_bytes: u64, p: &TrafficHighParams) -> Option<HighInfo>` | Mediana, factor y mínimo de un sentido (§7.4) |
| `Learning::is_data_day` | `fn(coverage_s: u32, subject_bytes: u64) -> bool` | Día con datos: ≥ 1 h de cobertura de tráfico y tráfico del sujeto (§7.3) |
| `NotifyPolicy::decide` | `fn(&mut self, level: Level, now: SystemTime) -> NotifyDecision` | Notificar, agrupar en el resumen, agrupar por el tope o no notificar (§7.2) |
| `QuietHours::parse` | `fn(s: &str) -> Result<Option<QuietHours>>` | «HH:MM-HH:MM» en hora local, también cruzando la medianoche; vacío = sin horario |
| `AlertText::compose` | `fn(rule: RuleId, subject: &SubjectInfo, key: &str, details: &serde_json::Value) -> AlertTexts` | Título, etiqueta y cuerpo de notificación saneados (§7.13) |
| `Health::sample` | `fn(stats: &CaptureStats, db: &DbSize, now: SystemTime) -> HealthSample` | Estado de la captura, pérdidas del minuto y tamaño de la BD (§7.8) |
| `Suspend::detect` | `fn(&mut self) -> Option<Suspension>` | Suspensión del equipo por `CLOCK_BOOTTIME` frente a `CLOCK_MONOTONIC` (§7.10) |

### `notify` (hilo de notificaciones)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Notifier::spawn` | `fn(cfg: &NotifyConfig) -> NotifierHandle` | Hilo con canal acotado (32); pide el nombre del servidor al arrancar |
| `NotifierHandle::notify` | `fn(&self, n: Notice)` | Encola sin bloquear; con el canal lleno, descarta y lo cuenta (`notify_drops`) |
| `NotifierHandle::status` | `fn(&self) -> NotifierStatus` | Disponible (con el nombre del servidor), no disponible (con el próximo intento) o apagado |

### Repo (hilo de la TUI, único escritor)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Repo::insert_alert` | `fn(a: &NewAlert) -> Result<i64>` | Crea una alerta |
| `Repo::insert_summary` | `fn(a: &NewAlert, grouped: &[i64]) -> Result<i64>` | Crea el resumen de la puesta al día y apunta `summary_id` en las agrupadas, en una transacción |
| `Repo::repeat_alert` | `fn(id: i64, at: SystemTime, details: &str, reactivate: bool) -> Result<()>` | `count + 1`, `last_at` y detalles; con `reactivate`, `resolved_at = NULL` |
| `Repo::resolve_alert` | `fn(id: i64, at: SystemTime) -> Result<()>` | `resolved_at` de una alerta de condición |
| `Repo::mark_seen` | `fn(sel: SeenSel, at: SystemTime) -> Result<usize>` | Una alerta (y lo que agrupa si es un resumen) o todas las del filtro |
| `Repo::unseen_counts` | `fn() -> Result<AlertCounts>` | No vistas por nivel (contador de la barra al arrancar) |
| `Repo::engine_snapshot` | `fn(now: SystemTime, dedup: Duration) -> Result<EngineSnapshot>` | Silencios vigentes, aprendizaje, claves de las últimas 24 h y condiciones activas |
| `Repo::upsert_mute` | `fn(m: &NewMute) -> Result<i64>` | Crea o sustituye el silencio de una regla, sujeto y equipo |
| `Repo::delete_mute` | `fn(id: i64) -> Result<()>` | Quita un silencio |
| `Repo::purge_alerts` | `fn(now: SystemTime, retention_days: u32) -> Result<usize>` | Alertas vencidas y silencios caducados (§7.15) |
| `Repo::set_watched` | `fn(device_id: i64, watched: bool) -> Result<()>` | Marca o desmarca un equipo vigilado (`p`) |
| `Repo::ensure_learning` | `fn(subject: Subject, device_id: i64, from: SystemTime) -> Result<()>` | Fila de aprendizaje de un equipo nuevo (o del propio equipo) si no existe |
| `Repo::update_learning` | `fn(day: LocalDay, p: &LearningParams) -> Result<Vec<LearningChange>>` | Cuenta el día cerrado y fija `learned_at` (§7.3) |
| `Repo::hour_baseline` | `fn(hour: i64, p: &TrafficHighParams) -> Result<HourBaseline>` | Valor de la hora y muestras de 14 días por sujeto y sentido (§7.4) |
| `Repo::upsert_seen` | `fn(items: &[SeenItem], at: SystemTime) -> Result<Vec<SeenItem>>` | (extendido) devuelve las entradas nuevas; las del propio equipo van a `HOST_SEEN` (§7.11) |
| `Repo::open_gap` | `fn(session_id: i64, kind: GapKind, from: SystemTime, to: Option<SystemTime>) -> Result<i64>` | Abre un hueco de captura o guarda una suspensión ya cerrada |
| `Repo::close_gap` | `fn(id: i64, at: SystemTime) -> Result<()>` | Cierra un hueco de captura |
| `Repo::close_open_sessions` | `fn() -> Result<usize>` | (extendido) cierra también los huecos abiertos con el `ended_at` de su sesión |
| `Repo::mark_service_closed` | `fn(device_id: i64, port: u16, proto: Proto, at: SystemTime) -> Result<()>` | (cambia) `closed_at = at`; `last_seen` no se toca (§7.12) |
| `Repo::upsert_service` | `fn(&ServiceUpsert) -> Result<i64>` | (extendido, F2) un puerto visto abierto borra `closed_at` |
| `Repo::backfill_closed_at` | `fn() -> Result<usize>` | Relleno de `closed_at` desde el último evento de servicio (migración v6) |
| `Repo::backfill_learning` | `fn(now: SystemTime, p: &LearningParams) -> Result<usize>` | Aprendizaje inicial desde el histórico de F5 (migración v6) |

### `history::queries` (lector, extendido)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Queries::alerts` | `fn(&Connection, f: &AlertFilter, page: Page) -> Result<Vec<AlertRow>>` | Lista de la pestaña Alertas por `last_at`, con filtro de nivel, no vistas y equipo |
| `Queries::alert_detail` | `fn(&Connection, id: i64) -> Result<AlertDetail>` | El porqué, las repeticiones y, en un resumen, lo que agrupa |
| `Queries::mutes` | `fn(&Connection, now: i64) -> Result<Vec<MuteRow>>` | Vista Silencios |
| `Queries::rule_stats` | `fn(&Connection, since: i64) -> Result<Vec<RuleStat>>` | Alertas de 7 días y silencios por regla (vista Reglas) |
| `Queries::alert_summary` | `fn(&Connection, subject: SubjectSel) -> Result<AlertSummary>` | Últimas 5 alertas, no vistas, silencios y aprendizaje de un equipo o del propio equipo |
| `Queries::coverage` | `fn(&Connection, range: Range) -> Result<Vec<Gap>>` | (extendido) resta los huecos de `COVERAGE_GAPS` (§7.10) |
| `Queries::presence` | `fn(&Connection, device_id: i64, range: Range) -> Result<Vec<PresenceSpan>>` | (extendido) una suspensión es «sin datos» |
| `Queries::timeline` | `fn(&Connection, f: &EventFilter, range: Range, page: Page) -> Result<Vec<TimelineItem>>` | (extendido) suspensiones y capturas paradas en el filtro Almenara |
| `Queries::inventory` | `fn(&Connection, subject: SubjectSel) -> Result<Inventory>` | (extendido) también el propio equipo (`HOST_SEEN`) |

### Otros

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `MinuteRollup::flush` | `fn(&mut self, minute: i64) -> RollupBatch` | (extendido) el inventario del lote incluye el propio equipo |
| `Changes::services` | `fn(device: &DeviceRow, scan: &PortScan, known: &[ServiceRow]) -> Vec<NewEvent>` | (extendido) decide CERRADO y `reopened` con `closed_at` (§7.12) |
| `config::load` | `fn(path: Option<&Path>) -> Result<Config>` | (extendido) `[alerts]` con validación (§7.14) |
| `config::save_rule` | `fn(path: &Path, rule: RuleId, s: &RuleSetting) -> Result<()>` | Guarda si una regla está activa y su nivel desde la TUI (como `[ui]`, F2) |
| `Synthetic::generate` | `fn(conn: &Connection, profile: &SyntheticProfile) -> Result<SyntheticStats>` | (extendido) alertas, silencios, aprendizaje, `HOST_SEEN` y huecos para medir (§7.16) |

---

## 6. Interfaz de Usuario

### Mapa de navegación (novedades de F6)

```
Equipos ──► marcas * (vigilado) y ! (alertas sin ver) · p vigilar      (F6)
   └─ Enter ──► Detalle + bloque «Alertas», vigilado y aprendizaje     (F6)

Alertas (5) ──► [Tab] Alertas → Reglas → Silencios                     (F6)
   ├─ Alertas ──► Enter detalle (la marca vista) · espacio vista
   │             T todas vistas · f nivel · u sin ver · / equipo
   │             m silenciar (1 día · 7 días · siempre) · e ir al equipo
   ├─ Reglas ───► espacio activar/apagar · n nivel (se guarda en config.toml)
   └─ Silencios ► x quitar

Barra ──► «Alertas N» y aviso de una línea (10 s) con cada importante  (F6)
Histórico ──► Eventos, filtro Almenara: suspensiones y capturas paradas (F6)
Config ──► + [alerts], notificador, horario silencioso, propio equipo  (F6)
Ayuda  ──► + alertas, niveles, teclas y privacidad de las notificaciones (F6)
```

### Mockup 1 — Alertas: lista y detalle (80×24)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ [Alertas] · Reglas · Silencios         3 sin ver · filtro: todas · 90 días │
├────────────────────────────────────────────────────────────────────────────┤
│    Cuándo      Nivel   Qué                                Equipo           │
│ ▸  hoy 10:44   !! IMP  Equipo nuevo · MAC fija            192.168.1.201    │
│  ● hoy 10:31   !  AVI  Más tráfico de lo habitual ↑ ×2    [host]           │
│  ● hoy 08:53   !  AVI  Vigilado de vuelta tras 41 min     nas              │
│    hoy 08:12   !  AVI  Vigilado ausente · resuelta        nas              │
│    hoy 08:05   !! IMP  Resumen al arrancar (4 alertas)    Almenara         │
│    hoy 08:03      INF  App nueva: Steam                   [host]           │
│    ayer 22:17     INF  País nuevo: Irlanda (IE)           [host]           │
│    ayer 19:02     INF  Cambio de tipo: iot → tv           tv-sala          │
│    ayer 03:10  !  AVI  Más tráfico de lo habitual ↑       nas              │
│  ● lun 12:30   !! IMP  Puerto nuevo: 22/tcp (ssh)         nas              │
├── Detalle ─────────────────────────────────────────────────────────────────┤
│ Equipo nuevo · 192.168.1.201 · Xiaomi · MAC fija aa:4f:3c:…                │
│ Primera vez en la red: hoy 10:44 (escaneo ARP) · sin nombre DHCP ni mDNS   │
│ Notificada en el escritorio · sin repeticiones · vista ahora               │
│ [m] silenciar la regla en este equipo · [e] ir al equipo                   │
└─[Enter]ver [espacio]vista [f]nivel [u]sin ver [m]silenciar [Tab]reglas─────┘
```

### Mockup 2 — Alertas: vista Reglas (80×24)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Alertas · [Reglas] · Silencios          lo nuevo aprende 7 días con datos  │
├────────────────────────────────────────────────────────────────────────────┤
│   Regla                          Activa  Nivel       7 días  Silencios     │
│ ▸ Equipo nuevo                   sí      importante       1          0     │
│     con MAC privada                      aviso            0                │
│   Puerto nuevo                   sí      importante       1          0     │
│   Cambio de MAC                  sí      aviso            0          0     │
│   Cambio de nombre               sí      info             2          0     │
│   Cambio de SO                   sí      info             0          0     │
│   Cambio de tipo                 sí      info             1          0     │
│   App nueva                      sí      info             3          0     │
│   Categoría nueva                sí      info             0          0     │
│   País nuevo                     sí      info             1          0     │
│   Organización nueva             no      info             —          0     │
│   Huella TLS nueva (JA4)         sí      info             4          1     │
│   Más tráfico de lo habitual     sí      aviso            2          1     │
│   Vigilado ausente o de vuelta   sí      aviso            2          0     │
│   Captura parada                 sí      importante       0          0     │
│   Pérdidas de captura            sí      aviso            0          0     │
│   Base de datos grande           sí      aviso            0          0     │
│ Umbrales y horario silencioso: config.toml [alerts] (los muestra Config)   │
└─[espacio]activar/apagar [n]nivel [j/k]mover [Tab]silencios [?]ayuda────────┘
```

### Mockup 3 — Silenciar desde una alerta y vista Silencios

```
│    ayer 19:02     INF  Cambio de tipo: iot → tv           tv-sala          │
│ ▸  ayer 03:10  !  AVI  Más tráfico de lo habitual ↑       nas              │
│                                                                            │
│ Silenciar «Más tráfico de lo habitual» en nas:                             │
│   [1] 1 día     [2] 7 días     [3] siempre          [Esc] cancelar         │
└─[1-3]elegir [Esc]cancelar──────────────────────────────────────────────────┘
```

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Alertas · Reglas · [Silencios]                                  2 silencios│
├────────────────────────────────────────────────────────────────────────────┤
│   Regla                          Equipo         Hasta           Desde      │
│ ▸ Huella TLS nueva (JA4)         [host]         siempre         10 nov     │
│   Más tráfico de lo habitual     nas            17 nov 03:12    ayer 03:12 │
│                                                                            │
│ Un silencio evita que la regla cree alertas para ese equipo; las que ya    │
│ existen no cambian. Los silencios caducados se borran solos.               │
└─[x]quitar [j/k]mover [Tab]alertas [?]ayuda─────────────────────────────────┘
```

### Mockup 4 — Detalle de un equipo vigilado (≥ 100 columnas)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ───────────────────────────┐
│ Equipos (9)          │ Detalle: nas (192.168.1.10) · Synology · vigilado            ▲ más arriba │
│ ──────────────────── │ ────────────────────────────────────────────────────────────────────────  │
│  [⌂]   router  14.5M │ Alertas · 2 sin ver                                    [p] vigilado: sí   │
│ ▶[▣]*! nas      6.0M │  ● hoy 08:53    AVI  Vigilado de vuelta tras 41 min                       │
│  [▯]   iPhone   165K │    hoy 08:12    AVI  Vigilado ausente · resuelta a las 08:53              │
│  [▶]   chromec  902K │    ayer 03:10   AVI  Más tráfico de lo habitual ↑                         │
│  [▣]   laptop   1.7M │  ● lun 12:30    IMP  Puerto nuevo: 22/tcp (ssh)                           │
│  [●]   tv-sala    4K │    3 nov 18:40  INF  Cambio de nombre: diskstation → nas                  │
│  [P]   hp-laser    0 │ Lo nuevo de este equipo: aprendido el 9 nov (7 días con datos)            │
│  [?]   192.168…    0 │ Silencios: más tráfico de lo habitual hasta el 17 nov                     │
│  ○     iPad        0 │                                                                           │
│                      │ Puertos                                                                   │
│                      │  22/tcp    ssh      abierto desde lun 12:30                               │
│                      │  445/tcp   smb      abierto desde 3 oct                                   │
│                      │  5000/tcp  http     abierto desde 3 oct                                   │
│                      │  139/tcp   netbios  cerrado el 4 nov; abierto por última vez el 4 nov     │
│                      │                                                                           │
│                      │ Visto en este equipo (desde 12 oct)                                       │
│                      │  Apps (6) · nuevas en 7 días: ninguna                                     │
│                      │  Organizaciones (4): Synology, Google, Amazon, Cloudflare                 │
│                      │  Países (3): TW US ES · Clientes TLS (JA4): 2                             │
└─[hjkl]mover [Tab]panel [w]24 h/7 días [p]vigilar [Esc]cerrar [v]conexión [?]ayuda────────────────┘
```

### Mockup 5 — Equipos, Config y notificaciones de escritorio

```
│ ▶[▣]*! 192.168.1.10    nas               Synology      nas         online  │
│  [?] ! 192.168.1.201   192.168.1.201     Xiaomi        ─           online  │
│  ○     192.168.1.66    iPad              Apple         ─           offline │
│                                                                            │
│ * vigilado · ! alertas sin ver                                             │
│ ▲ Alerta importante: Equipo nuevo · 192.168.1.201 · [5] para verla         │
│ Alertas 4 · 12 equipos · 11 online · 1 offline   modo: privilegiado        │
└─[p]vigilar [f]filtrar [/]buscar [g]agrupar [Enter]detalle [?]ayuda─────────┘
```

```
│ [alerts]                                                                   │
│   enabled = true          retention_days = 90   learning_days = 7          │
│   catch_up_minutes = 10   dedup_hours = 24      quiet_hours = "23:00-08:00"│
│   desktop_notifications = true     max_notifications_per_minute = 3        │
│   traffic_high: ×3 la mediana · 14 días · mínimo 5 · ↓ 200 MB · ↑ 50 MB/h  │
│   capture_drops: > 1 % durante 5 min · reglas: 15 de 16 activas            │
│                                                                            │
│ Notificaciones de escritorio: disponibles (servidor: mako)                 │
│ Horario silencioso: ahora no (empieza a las 23:00)                         │
│ Propio equipo: aprendiendo (4 de 7 días con datos) · inventario: 41 apps,  │
│   12 categorías, 230 organizaciones, 19 países, 27 huellas JA4             │
└────────────────────────────────────────────────────────────────────────────┘
```

```
┌──────────────────────────────────────────┐    ┌──────────────────────────────────────────┐
│ Almenara · Equipo nuevo                  │    │ Almenara · Resumen al arrancar           │
│ 192.168.1.201 (Xiaomi) · MAC fija        │    │ 4 alertas: 1 equipo nuevo (importante),  │
│ Ábrela en Almenara: Alertas (5)          │    │ 3 de otros niveles                       │
└──────────────────────────────────────────┘    └──────────────────────────────────────────┘
```

### Notas de UX

- **Vistas.** `Tab` pasa de Alertas a Reglas y a Silencios, y vuelve. Cada arranque empieza en Alertas con el filtro «todas». `e` abre el equipo de la alerta seleccionada en Equipos, con su detalle; en las alertas que no son de un equipo no hace nada.
- **Lista.** Ordenada por la última repetición (`last_at`), más recientes primero. Columnas: cuándo («hoy 10:44», «ayer 22:17», día de la semana dentro de 7 días y fecha después), nivel, qué y equipo. Una alerta repetida muestra «×N»; una de condición resuelta, «· resuelta». El equipo es su nombre actual; si se borró, el guardado. Los sujetos que no son equipos se ven como `[host]`, «Toda la red» y «Almenara».
- **Niveles.** `!! IMP` (importante), `!  AVI` (aviso) y `   INF` (info), con color además del texto. Una alerta no vista lleva `●` y va en negrita; la seleccionada, `▸`. Nada depende solo del color.
- **Detalle.** Panel inferior de la propia lista (no modal). Dice el porqué en una o dos líneas (primera vez que se vio y desde cuándo aprendía; mediana, valor y factor; motivo del cambio de MAC; cuánto estuvo ausente), las repeticiones (primera y última vez), si se notificó y, en un resumen, las alertas que agrupa. `Enter` lo abre y marca la alerta como vista; `Esc` lo cierra.
- **Marcar vistas.** `espacio` marca la seleccionada sin abrirla; `T` marca todas las del filtro actual (pide confirmar con `T` otra vez si son más de 20). Marcar un resumen marca lo que agrupa. No hay «marcar como no vista».
- **Filtros.** `f` cicla el nivel: todas → importantes → avisos → info. `u` alterna «solo sin ver» y «todas». `/` filtra por nombre de equipo. Los filtros no se guardan.
- **Silenciar.** `m` abre una línea de elección: `1` un día, `2` siete días, `3` siempre, `Esc` cancela. El silencio es para la regla, el sujeto y el equipo de la alerta seleccionada; las alertas que ya existen no cambian. Un silencio nuevo sustituye al anterior de la misma regla y equipo.
- **Reglas.** Lista fija de las 16 reglas con su estado, su nivel, las alertas de los últimos 7 días y los silencios vigentes. `espacio` activa o apaga y `n` cicla el nivel (importante → aviso → info); en «con MAC privada», `n` cambia el nivel de las MAC privadas. Se guarda en `config.toml` al momento (§7.14). Una regla que no puede saltar lo dice en su fila: «necesita el histórico» (`[history].enabled = false`), «necesita captura» (modo degradado) o «sin escaneo de puertos» (`passive_only`).
- **Silencios.** Regla, equipo, hasta («siempre» o fecha) y desde. `x` quita el silencio seleccionado.
- **Barra.** «Alertas N» con las no vistas importantes y avisos (las info no cuentan); no aparece si N es 0. Al llegar una importante fuera de la pestaña Alertas, la línea de mensajes muestra 10 s «▲ Alerta importante: <título> · [5] para verla».
- **Equipos.** Tras el icono, `*` si el equipo está vigilado y `!` si tiene alertas importantes o avisos sin ver; la leyenda va bajo la lista. `p` marca o desmarca el equipo seleccionado como vigilado, también desde su detalle.
- **Detalle de equipo.** Bloque «Alertas» con las 5 últimas y cuántas faltan por ver, «vigilado: sí/no» con `[p]`, el estado del aprendizaje («aprendiendo: 4 de 7 días con datos» o «aprendido el 9 nov») y sus silencios. La lista de puertos dice «cerrado el …» con `closed_at`.
- **Config.** `[alerts]` con sus valores, el estado del notificador (disponible con el nombre del servidor, no disponible con el próximo intento o apagado), el horario silencioso (activo o no y hasta cuándo), las notificaciones descartadas si las hay y el aprendizaje y el inventario del propio equipo.
- **Mensajes.** «Sin alertas en este filtro». «Las alertas están desactivadas ([alerts] enabled = false)»: la lista guardada sigue visible. Mientras llega una consulta: «Cargando…».
- **Histórico.** El filtro Almenara de la línea de tiempo muestra también «Equipo suspendido HH:MM–HH:MM» y «Captura parada HH:MM–HH:MM»; las gráficas los pintan como «sin datos» (`░`).
- **Accesibilidad.** Lista y detalle en 80×24 en la misma pantalla. Todo estado tiene texto propio (nivel, no vista, resuelta, vigilado, silenciada) además del color.

---

## 7. Lógica de Negocio

### 7.1 Catálogo de reglas

| Regla (`rule`) | Nombre en la TUI | Señal | `key` | Nivel por defecto | Aprende | Condición |
|----------------|------------------|-------|-------|-------------------|---------|-----------|
| `device_new` | Equipo nuevo | Evento `new` (F1; también por captura, F4) | — | importante; aviso con MAC privada | no (línea base, §7.9) | no |
| `port_new` | Puerto nuevo | `service_new` (F5), también `reopened` | `22/tcp` | importante | no | no |
| `mac_changed` | Cambio de MAC | `mac_changed` (F1, F4 v2) | MAC nueva | aviso | no | no |
| `name_changed` | Cambio de nombre | `hostname_changed` (F1) | nombre nuevo | info | no | no |
| `os_changed` | Cambio de SO | `os_changed` (F5) | SO nuevo | info | no | no |
| `type_changed` | Cambio de tipo | `type_changed` (F5) | tipo nuevo | info | no | no |
| `new_app` | App nueva | Entrada nueva del inventario (`app`) | clave de app | info | sí | no |
| `new_category` | Categoría nueva | Inventario (`category`) | categoría | info | sí | no |
| `new_country` | País nuevo | Inventario (`country`) | código ISO | info | sí | no |
| `new_org` | Organización nueva | Inventario (`org`) | organización | info | sí | no |
| `new_ja4` | Huella TLS nueva (JA4) | Inventario (`ja4`) | huella JA4 | info | sí | no |
| `traffic_high` | Más tráfico de lo habitual | Hora cerrada (§7.4) | `down` o `up` | aviso | no (5 muestras) | no |
| `watched_presence` | Vigilado ausente o de vuelta | `disappeared` y `reappeared` de un equipo vigilado (§7.7) | `gone` o `back` | aviso | no | `gone` sí |
| `capture_stopped` | Captura parada | Estado de la captura (§7.8) | `capture` | importante | no | sí |
| `capture_drops` | Pérdidas de captura | Pérdidas por minuto (§7.8) | `drops` | aviso | no | sí |
| `db_size` | Base de datos grande | Tamaño tras la purga horaria (§7.8) | `db` | aviso | no | sí |

`catch_up` (resumen de la puesta al día, §7.9) no es una regla configurable: su nivel es el mayor de lo que agrupa.

**Sujeto.** `device` en las reglas de eventos, de vigilados y de lo nuevo de un equipo; `host` en lo nuevo y en el tráfico del propio equipo; `network` en el tráfico de la red entera; `almenara` en la salud y en el resumen.

**El porqué (`details`).**

| Regla | `details` |
|-------|-----------|
| `device_new` | `mac`, `mac_random`, `vendor`, `ip`, `source` (escaneo o captura), `hostname` |
| `port_new` | `port`, `protocol`, `service`, `reopened` |
| `mac_changed` | `before`, `after`, `reason` (F4) |
| `name_changed`, `os_changed`, `type_changed` | `before`, `after` (y `os_source` en SO) |
| `new_*` | `kind`, `key`, `label` (nombre del catálogo o del país), `first_seen`, `learned_at` del sujeto |
| `traffic_high` | `direction`, `hour` (inicio de la hora local), `value`, `median`, `factor`, `samples` |
| `watched_presence` | `state` (`gone`/`back`), `last_seen`, `away_s`, `while_closed` |
| `capture_stopped` | `interface`, `reason` |
| `capture_drops` | `percent`, `minutes`, `kernel_drops`, `limit_drops` |
| `db_size` | `db_bytes`, `wal_bytes`, `max_db_mb` |
| `catch_up` | recuentos por regla y por nivel |

**Reglas generales.**
- Las alertas nacen de señales **en vivo**: los eventos, el inventario y las horas anteriores a la v6 no crean alertas, y tampoco las horas pendientes que se construyen al arrancar.
- Las claves especiales del histórico (`~sin_identificar`, `~lan`, `~desconocido`, `~otros`) y los destinos nunca son la clave de una alerta: el inventario no los guarda (F5, §7.9).
- Los cambios de IP (`ip_changed`) no avisan: el DHCP los hace a menudo. Siguen en la línea de tiempo.
- `port_new` solo salta con escaneos reales (F2) y nunca en el primer escaneo de un equipo (F5): sus puertos iniciales se ven en el detalle del equipo nuevo.
- Con `[history].enabled = false` no hay inventario ni rollups: lo nuevo y `traffic_high` no saltan. Sin `CAP_NET_RAW` (modo degradado) tampoco, ni la salud de la captura. Con `passive_only` no hay escaneo de puertos: `port_new` no salta. La vista Reglas lo dice.

### 7.2 Niveles y notificación

| Nivel | Pestaña Alertas | Contador de la barra | Notificación de escritorio |
|-------|-----------------|----------------------|----------------------------|
| Importante (`important`) | sí | sí | sí, según la política |
| Aviso (`warning`) | sí | sí | no |
| Info (`info`) | sí | no | no |

- `device_new` con MAC privada (`mac_random` en el evento, F4) usa `level_private_mac` (aviso por defecto): una rotación de MAC sin huella DHCP no despierta a nadie.
- Cada regla tiene su nivel en `[alerts.rules]` y se cambia desde la vista Reglas.

```python
def decidir(politica, nivel, ahora):
    """Devuelve 'notificar', 'resumen', 'tope' o 'no'."""
    if nivel != 'important' or not politica.notificaciones_activas:
        return 'no'
    if ahora < politica.fin_puesta_al_dia:            # 10 min tras arrancar (§7.9)
        return 'resumen'
    if politica.horario and politica.horario.contiene(hora_local(ahora)):
        return 'no'                                   # horario silencioso: se guarda sin notificar
    politica.enviadas = [t for t in politica.enviadas if ahora - t < 60]
    if len(politica.enviadas) >= politica.max_por_minuto:   # 3 por defecto
        politica.retenidas += 1                        # una sola notificación «y N más» al cumplirse el minuto
        return 'tope'
    politica.enviadas.append(ahora)
    return 'notificar'
```

- Las retenidas por el tope salen juntas en una notificación («Almenara · N alertas importantes más») al cumplirse el minuto, salvo que para entonces haya empezado el horario silencioso.
- `notified` se marca solo cuando la alerta salió de verdad en una notificación propia.

### 7.3 Aprendizaje

**Día con datos** de un sujeto: día local con al menos 1 h de cobertura de tráfico (sesiones con captura menos los huecos, §7.10) y tráfico del sujeto en `TRAFFIC_ROLLUP_DAY` (fila `total` con bytes > 0). Que Almenara esté abierta y capturando no basta: si el equipo no estaba, ese día no enseña nada sobre él.

```python
def update_learning(db, dia, p):                         # al consolidar el día local
    cobertura = cobertura_trafico_s(db, dia)             # sin sesiones sin captura ni huecos
    cambios = []
    for f in db.learning(sin_aprender=True):             # equipos y propio equipo
        if dia <= f.updated_day or fin_del_dia(dia) <= f.learning_from:
            continue
        if cobertura >= 3600 and db.total_dia(dia, f.subject, f.device_id) > 0:
            f.data_days += 1
        f.updated_day = dia
        if f.data_days >= p.learning_days:
            f.learned_at = fin_del_dia(dia)
            cambios.append(f)
        db.guardar(f)
    return cambios
```

- **Quién aprende.** Cada equipo (fila creada con su evento `new`, `learning_from` = su `first_seen`) y el propio equipo (fila creada en la migración v6, `learning_from` = fecha de la migración). La red entera no aprende: solo la usa `traffic_high`.
- **Relleno en la migración v6.** Para cada equipo existente se cuentan sus días con datos en el histórico de F5 (`TRAFFIC_ROLLUP_DAY` y `APP_SESSIONS`) desde su `first_seen`; si llega a 7, queda aprendido con `learned_at` al final de su 7.º día con datos. Lo que F5 ya ha guardado cuenta.
- **El propio equipo empieza de cero.** F5 no guardó su inventario (`host` no está en `DEVICES`) y los rollups no sirven para reconstruirlo, porque los topes esconden claves en `~otros`: `HOST_SEEN` empieza vacío con la v6 y el propio equipo aprende sus 7 días desde ese momento (ADR-71).
- **Sin vuelta atrás.** Un sujeto aprendido no vuelve a aprender, aunque se purguen datos o cambie `learning_days`. Con `learning_days = 0`, todo sujeto nuevo nace aprendido.
- Mientras un sujeto aprende, lo nuevo se apunta en el inventario sin alerta: al terminar, solo avisa lo que de verdad no se había visto.

### 7.4 Más tráfico de lo habitual

```python
def evaluar_hora(base, p):
    """base: {(sujeto, device_id): (bajada, subida, muestras)}; muestras = [(bajada, subida), …]"""
    señales = []
    for (sujeto, dev), (bajada, subida, muestras) in base.items():
        if len(muestras) < p.min_days:                   # 5 por defecto: sin base no se avisa
            continue
        for sentido, valor, minimo, i in (('down', bajada, p.min_mb_down, 0),
                                          ('up', subida, p.min_mb_up, 1)):
            mediana = statistics.median(m[i] for m in muestras)
            if valor >= p.factor * mediana and valor >= minimo * 1_000_000:
                señales.append((sujeto, dev, sentido, valor, mediana, len(muestras)))
    return señales
```

- **Cuándo.** Al consolidar cada hora en vivo, si la hora tiene cobertura de tráfico completa (huecos de menos de 1 minuto no cuentan, por la granularidad del latido).
- **Muestras.** Para cada uno de los 14 días anteriores (`baseline_days`), la misma hora local; cuenta si esa hora tuvo cobertura de tráfico completa. El valor es el total de la hora del sujeto en `TRAFFIC_ROLLUP_HOUR` (0 si no hay fila: estaba cubierta y no hubo tráfico). En un equipo solo cuentan los días desde su `first_seen`.
- **Hora local.** El día con cambio de hora puede no tener esa hora (se salta) o tenerla dos veces (se usa la primera), con `mktime` como en F5.
- **Sujetos.** Equipos con filas en la hora, el propio equipo (`host`) y la red entera (`network`). Bajada y subida por separado: una subida rara es la señal de que algo saca datos.
- **Mínimos.** 200 MB de bajada y 50 MB de subida por hora (MB de 1000 × 1000 bytes, como F3). Con mediana 0 manda el mínimo.
- **Repeticiones.** La clave es el sentido: si la hora siguiente vuelve a superar el umbral, la misma alerta suma `count` (§7.5) y guarda en `details` el valor mayor.

### 7.5 Deduplicación, repeticiones y alertas de condición

```python
def admitir(motor, señal, ahora, plazo=24 * 3600):
    clave = (señal.regla, señal.sujeto, señal.device_id, señal.clave)
    previa = motor.recientes.get(clave)                  # última alerta con esa clave
    if señal.de_condicion:
        if previa and previa.activa:
            return []                                     # sigue activa: nada nuevo
        if previa and ahora - previa.created_at < plazo:
            return [Repeat(previa.id, ahora, reactivar=True)]
    elif previa and ahora - previa.created_at < plazo:
        return [Repeat(previa.id, ahora, reactivar=False)]
    return [Insert(señal)]
```

- El plazo (`dedup_hours`, 24 h) se cuenta desde `created_at`: una anomalía que dura varios días crea una alerta por día, no una por hora.
- Una repetición nunca notifica ni cambia si la alerta estaba vista.
- **Condición.** `capture_stopped`, `capture_drops`, `db_size` y `watched_presence` con `gone` están ACTIVAS mientras dura la condición y se resuelven (`resolved_at`) cuando desaparece. Apagar su regla las resuelve («resuelta al apagar la regla»).
- `Repo::engine_snapshot` carga al arrancar las claves de las últimas 24 h y las condiciones activas: reiniciar Almenara no repite alertas.

### 7.6 Silencios

- Un silencio es para una regla, un sujeto y un equipo: `(rule, subject, device_id)`. Duración: 1 día, 7 días o siempre (`until = NULL`).
- Silenciada, la regla no crea alertas para ese sujeto; las alertas que ya existen no cambian y una condición activa se sigue resolviendo.
- Un silencio caducado se ignora al evaluar y se borra en la purga horaria. Uno nuevo para la misma regla y equipo sustituye al anterior (`Repo::upsert_mute`).
- Tras crear o quitar un silencio, el hilo de la TUI recarga el motor (`AlertEngine::reload`).

### 7.7 Equipos vigilados

- `p` marca o desmarca un equipo como vigilado (`DEVICES.watched`). Por defecto ninguno: la presencia de un móvil es la de una persona (respuesta 5a). Pensado para el router, un NAS o un servidor.
- `disappeared` de un equipo vigilado crea una alerta de condición (`watched_presence`, clave `gone`): «Vigilado ausente». Si su `last_seen` es anterior al arranque de la sesión, `details.while_closed = true` y el detalle dice «se fue mientras Almenara estaba cerrada».
- `reappeared` resuelve esa alerta y crea otra con clave `back`: «Vigilado de vuelta tras 41 min» (`away_s` del evento, F5).
- Desmarcar un equipo resuelve su alerta `gone` activa.

### 7.8 Salud de Almenara

- **`capture_stopped`.** Con `[capture].enabled = true` y `CAP_NET_RAW`, la captura no está activa (no arranca, se para o da error) sin que la persona haya salido. Se resuelve cuando vuelve a capturar. En modo degradado no salta: ahí la captura nunca empezó y la barra ya lo dice (F1).
- **`capture_drops`.** Cada minuto cerrado: pérdidas = drops del anillo + `limit_drops` (F3); si pasan de `percent` (1 %) de lo capturado más lo perdido durante `minutes` (5) minutos seguidos, salta; se resuelve tras 5 minutos seguidos por debajo.
- **`db_size`.** Tras la purga horaria (F5), si la BD y su WAL pasan de `max_db_mb` (F5), salta; se resuelve al bajar. El aviso de F5 en la barra se mantiene.
- `Health::sample` se toma cada minuto con lo que el hilo de la TUI ya tiene (estadísticas de captura de F3 y tamaño de la BD de F5).

### 7.9 Puesta al día y línea base

- **Puesta al día.** Durante los `catch_up_minutes` (10) tras arrancar, las alertas se crean pero no notifican: al arrancar llegan de golpe los cambios del tiempo cerrado (equipos que se fueron o volvieron, puertos del primer ciclo). Al terminar, si hubo alguna, se crea una alerta resumen (`catch_up`, sujeto `almenara`, nivel el mayor de lo agrupado, «Resumen al arrancar (N alertas)») con `summary_id` en las agrupadas, y una sola notificación si alguna era importante (salvo horario silencioso). Con `catch_up_minutes = 0` no hay puesta al día.
- **Línea base.** Si al arrancar `DEVICES` está vacía (base de datos nueva), los equipos nuevos del primer ciclo de escaneo completo no crean alertas: son la red de partida. Lo demás funciona igual.
- **En vivo.** El motor solo recibe señales de lo que pasa en la sesión (§7.1).

### 7.10 Huecos dentro de la sesión

```python
def huecos(sesiones, huecos_sesion, desde, hasta, ahora, de_trafico=True):
    """F5 §7.6 + F6: la suspensión quita cobertura de tráfico y de presencia;
    la captura parada, solo de tráfico."""
    validas = [s for s in sesiones if s.capture or not de_trafico]
    cubierto = unir([(max(s.started_at, desde), min(s.ended_at or ahora, hasta))
                     for s in validas])
    quitar = [h for h in huecos_sesion
              if h.kind == 'suspend' or (de_trafico and h.kind == 'capture')]
    cubierto = restar(cubierto, [(h.started_at, h.ended_at or ahora) for h in quitar])
    return complemento(cubierto, desde, hasta)
```

- **Suspensión.** `Suspend::detect` guarda en cada tick `CLOCK_BOOTTIME` y `CLOCK_MONOTONIC`; si entre dos ticks el primero avanza más de 60 s por encima del segundo, el equipo estuvo suspendido. El hueco `suspend` se guarda ya cerrado con el reloj de pared del tick anterior y del actual. Un cambio del reloj de pared (NTP, cambio de hora) no afecta a esos dos relojes: no crea huecos.
- **Captura parada.** Un hueco `capture` se abre cuando la captura pasa de activa a parada o con error sin que la persona haya salido, y se cierra cuando vuelve. Al salir con `q`, un hueco abierto se cierra con el cierre de la sesión; tras una caída, `Repo::close_open_sessions` lo cierra con el `ended_at` de su sesión.
- **Quién lo usa.** `Queries::coverage`, las gráficas y las ventanas de F5 (puntos «sin datos»), la presencia (solo la suspensión), el aprendizaje (§7.3) y `traffic_high` (§7.4).
- Durante una suspensión no hay latido: la sesión sigue abierta y su `last_beat` se pone al día al volver.

### 7.11 Inventario del propio equipo

- `MinuteRollup::flush` apunta también, para el sujeto `host`, las apps, categorías, organizaciones y países del minuto (antes de los topes) y las huellas JA4 de los flujos en que el propio equipo es el cliente, como hace con los equipos (F5).
- `Repo::upsert_seen` escribe esas entradas en `HOST_SEEN` y devuelve, junto con las de `DEVICE_SEEN`, las que son nuevas: son la señal de las reglas de lo nuevo.
- Sin claves especiales ni destinos, como `DEVICE_SEEN`. Se purga a los `day_days` (2 años) de su `last_seen`.
- Config muestra los recuentos por tipo y el aprendizaje del propio equipo.

### 7.12 Puertos cerrados (`closed_at`)

- Un escaneo que ve cerrado un puerto abierto u obsoleto: `Repo::mark_service_closed` pone `closed_at` y genera `service_gone`; `last_seen` no se toca y sigue siendo la última vez que se vio abierto.
- Un escaneo que ve abierto un puerto CERRADO: `Repo::upsert_service` borra `closed_at`, actualiza `last_seen` y `Changes::services` genera `service_new` con `reopened = true`.
- **Estado** (F2 + F6): CERRADO si `closed_at` no es NULL; si no, OBSOLETO si `last_seen` pasa del umbral de F2; si no, ABIERTO.
- Los puertos cerrados se purgan como los obsoletos de F2, a los `events_retention_days` de su `closed_at`.
- **Relleno en la v6:**

```sql
WITH ultimo AS (
  SELECT device_id,
         json_extract(details, '$.port')     AS port,
         json_extract(details, '$.protocol') AS protocol,
         event_type, created_at,
         ROW_NUMBER() OVER (PARTITION BY device_id, json_extract(details, '$.port'),
                                         json_extract(details, '$.protocol')
                            ORDER BY created_at DESC, id DESC) AS n
    FROM DEVICE_EVENTS
   WHERE event_type IN ('service_new', 'service_gone'))
UPDATE DEVICE_SERVICES
   SET closed_at = (SELECT u.created_at FROM ultimo u
                     WHERE u.n = 1 AND u.event_type = 'service_gone'
                       AND u.device_id = DEVICE_SERVICES.device_id
                       AND u.port = DEVICE_SERVICES.port
                       AND u.protocol = DEVICE_SERVICES.protocol);
```

- Los `last_seen` que F5 ya movió no se pueden recuperar: en esos puertos, «abierto por última vez» queda como estaba.

### 7.13 Texto de las alertas y de las notificaciones

```python
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]')
CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')

def sanear(texto, maximo):
    t = CONTROL.sub('', ANSI.sub('', texto))             # primero las secuencias, luego el resto
    return t if len(t) <= maximo else t[:maximo - 1] + '…'

def cuerpo_notificacion(alerta):
    cuerpo = sanear(f"{alerta.subject_label} · {alerta.resumen}", 200)
    return cuerpo.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
```

- Todo texto que viene de la red (nombres DHCP, mDNS, NetBIOS o UPnP, fabricantes, organizaciones) se sanea al crear la alerta: `title` hasta 120 caracteres y `subject_label` hasta 64.
- En la notificación, el título es «Almenara · <nombre de la regla>» y el cuerpo, el sujeto y lo esencial (≤ 200 caracteres), con `&`, `<` y `>` escapados: muchos servidores interpretan marcado en el cuerpo.
- `app_name` «Almenara», icono `network-wired`, urgencia normal y la duración que decida el servidor. Sin acciones ni botones.

### 7.14 Configuración y validación

```toml
[alerts]
enabled                      = true   # motor de alertas (apagado: las guardadas se siguen viendo)
retention_days               = 90     # alertas
learning_days                = 7      # días con datos antes de avisar de lo nuevo
catch_up_minutes             = 10     # puesta al día al arrancar (0 = sin ella)
dedup_hours                  = 24     # la misma alerta no se repite en este plazo
desktop_notifications        = true   # notificaciones de escritorio (solo importantes)
quiet_hours                  = ""     # p. ej. "23:00-08:00" en hora local; vacío = sin horario
max_notifications_per_minute = 3

[alerts.traffic_high]
factor        = 3.0   # veces la mediana
baseline_days = 14
min_days      = 5
min_mb_down   = 200   # MB por hora
min_mb_up     = 50

[alerts.capture_drops]
percent = 1.0         # % perdido en un minuto
minutes = 5           # minutos seguidos

[alerts.rules]
device_new       = { enabled = true, level = "important", level_private_mac = "warning" }
port_new         = { enabled = true, level = "important" }
mac_changed      = { enabled = true, level = "warning" }
name_changed     = { enabled = true, level = "info" }
os_changed       = { enabled = true, level = "info" }
type_changed     = { enabled = true, level = "info" }
new_app          = { enabled = true, level = "info" }
new_category     = { enabled = true, level = "info" }
new_country      = { enabled = true, level = "info" }
new_org          = { enabled = true, level = "info" }
new_ja4          = { enabled = true, level = "info" }
traffic_high     = { enabled = true, level = "warning" }
watched_presence = { enabled = true, level = "warning" }
capture_stopped  = { enabled = true, level = "important" }
capture_drops    = { enabled = true, level = "warning" }
db_size          = { enabled = true, level = "warning" }
```

- Rangos válidos: `retention_days` 7–730; `learning_days` 0–30; `catch_up_minutes` 0–60; `dedup_hours` 1–168; `max_notifications_per_minute` 1–20; `factor` 1,5–20; `baseline_days` 7 a `hour_days` de F5; `min_days` 3 a `baseline_days`; `min_mb_down` y `min_mb_up` ≥ 1; `percent` 0,1–50; `minutes` 1–60; `level` y `level_private_mac` en `important`, `warning` o `info`.
- `quiet_hours` es vacío o «HH:MM-HH:MM» con inicio distinto del fin; puede cruzar la medianoche.
- Un valor inválido se avisa una vez y usa el valor por defecto; una regla desconocida se avisa una vez y se ignora; una regla que falta usa sus valores por defecto. La configuración nunca aborta el arranque (regla de F4).
- Desde la vista Reglas, `config::save_rule` reescribe el fichero completo con el valor nuevo, como `[ui]` en F2 (una escritura por pulsación). Si no puede escribir, avisa una vez y el cambio vale para la sesión.
- La plantilla de configuración por defecto incluye `[alerts]` completo.

### 7.15 Retención y purga

| Dato | Retención | Cuándo |
|------|-----------|--------|
| `ALERTS` | `retention_days` (90) desde `last_at` | Purga horaria de F5 |
| `ALERT_MUTES` | Hasta `until`; «siempre» no caduca | Purga horaria |
| `ALERT_LEARNING` | Lo que viva el equipo (el DAO la borra con él) | — |
| `HOST_SEEN` | `day_days` (2 años) desde `last_seen` | Purga horaria |
| `COVERAGE_GAPS` | Lo que viva su sesión (2 años, en cascada) | Purga de sesiones de F5 |

- No hay borrado manual de alertas (respuesta 11a): solo la purga.
- Al purgar un resumen, las alertas que agrupaba se quedan; su `summary_id` deja de resolverse y el detalle no lo muestra.

### 7.16 Mediciones

- `Synthetic::generate` (F5) añade al perfil de referencia 20 000 alertas en 90 días (90 % info), 20 silencios, el aprendizaje de los 30 equipos y del propio equipo, 300 entradas de `HOST_SEEN` y una suspensión nocturna diaria.
- Pruebas ignoradas nuevas: `medir_alertas_motor`, `medir_alertas_hora`, `medir_alertas_aprendizaje`, `medir_alertas_consulta`, `medir_migracion_v6` y `medir_render_alertas`. Se lanzan como las de F5 (`cargo test --release --bin almenara medir_ -- --ignored --nocapture --test-threads=1`) y sus cifras van al informe de implementación.

### 7.17 Casos especiales

- **Un equipo se borra.** Sus alertas se quedan con `device_id = NULL` y `subject_label`; el DAO borra sus silencios y su aprendizaje.
- **Fusión de identidad** (`mac_changed` v2, F4): el equipo conserva su `device_id`, su inventario y su aprendizaje; la alerta es «Cambio de MAC» con su motivo.
- **Regla apagada con una condición activa:** la alerta se resuelve con «resuelta al apagar la regla».
- **`[alerts].enabled = false`:** no se crean alertas, el contador se oculta y la pestaña muestra las guardadas; el aprendizaje y los huecos se siguen actualizando para que al encenderlo todo funcione.
- **Notificador sin servidor** (Almenara por SSH, sesión sin escritorio): NO DISPONIBLE, aviso único en Config y reintento cada 10 minutos con la siguiente notificación; las alertas siguen en la TUI.
- **Dos alertas iguales en el mismo lote:** la deduplicación las une antes de escribir.
- **Reloj de pared hacia atrás:** `created_at` puede quedar por delante de `last_at`; la deduplicación usa la diferencia absoluta y la lista ordena por `last_at`.

---
## 8. Requisitos No Funcionales

### Seguridad

- El texto que viene de la red se sanea al crear la alerta (caracteres de control y secuencias ANSI fuera, longitud acotada) y se escapa en el cuerpo de la notificación (`&`, `<`, `>`): un nombre DHCP o mDNS hostil no puede pintar en la terminal ni inyectar marcado o enlaces en el escritorio (ADR-77).
- Todas las consultas usan parámetros; las claves de las alertas (apps, organizaciones, nombres) vienen de la red y nunca se concatenan en el SQL (regla de F5).
- D-Bus solo de sesión, nunca de sistema; el notificador solo envía notificaciones, no escucha nada.
- `[alerts]` se valida campo a campo; un fichero malicioso no puede bloquear el arranque ni pedir valores absurdos.
- Sin puertos nuevos ni accesos a red. Los silencios y las reglas solo los cambia quien usa la TUI.

### Protección de datos (RGPD)

- Uso personal y doméstico (exención doméstica del art. 2.2.c del RGPD); aun así, la fase aplica minimización. Si en la casa viven más personas, conviene que sepan que Almenara registra el uso de la red y que puede avisar de él.
- Las alertas guardan regla, sujeto, clave (app, categoría, país, organización, JA4, puerto) y su porqué. Nunca dominios ni contenido: salen del inventario, que no guarda destinos (F5).
- **Presencia de personas:** solo hay alertas de presencia para los equipos que la persona marca como vigilados, y ninguno lo está por defecto (respuesta 5a).
- **Notificaciones:** se ven en pantalla y el servidor de notificaciones puede guardarlas en su historial. Por defecto solo notifican las importantes (equipo nuevo con MAC fija, puerto nuevo y captura parada), sin apps ni organizaciones. La Ayuda lo explica.
- Retención de 90 días para las alertas (respuesta 11a); todo es local. Para borrarlas antes, bajar `retention_days`.
- Logs: claves de las alertas solo a nivel `debug` (regla de F4).

### Backups y recuperación

- Sin cambios: las alertas, los silencios y el aprendizaje viven en `data.db` y se copian con ella (README de F5).
- Perder la BD es perder las alertas y el aprendizaje: se vuelve a aprender en 7 días con datos. Con la BD vacía, la línea base evita una avalancha de «equipo nuevo».
- Una alerta que no se puede escribir se reintenta en el minuto siguiente; el motor no pierde la acción mientras la TUI siga abierta.

### Rendimiento

- `AlertEngine::handle` ≤ 1 ms por señal (eventos, inventario, salud, tick).
- Evaluación de una hora (`Repo::hour_baseline` + motor) ≤ 20 ms con 50 equipos y 14 días de muestras; se suma a la consolidación de la hora de F5 (≤ 50 ms).
- Aprendizaje de un día (`Repo::update_learning`) ≤ 50 ms con 50 equipos.
- Migración v6 con sus rellenos ≤ 2 s sobre el histórico sintético de 2 años.
- `Queries::alerts` ≤ 100 ms con 20 000 alertas.
- Memoria añadida ≤ 4 MB (claves de 24 h, silencios, aprendizaje y canal del notificador).
- Notificar nunca bloquea la TUI: el canal es acotado y el envío ocurre en el hilo del notificador.
- Render sin cambios: ≤ 16 ms en 80×24 y ≤ 33 ms en 120×40, también con Alertas abierta (el render no consulta la BD).

### Accesibilidad

- Sin cambios de nivel (WCAG 2.1 AA en lo aplicable a TUI). Nivel, no vista, resuelta, vigilado y silenciada con texto o carácter propio además del color; lista y detalle en 80×24; las notificaciones son solo texto.

---

## 9. Integraciones

- **Notificaciones de escritorio:** especificación freedesktop `org.freedesktop.Notifications` (método `Notify`) por D-Bus de sesión, con `notify-rust` 4.17 sobre `zbus` 5 (Rust puro, sin libdbus). Campos: `app_name` «Almenara», `summary` «Almenara · <regla>», `body` saneado y escapado, icono `network-wired`, urgencia normal y duración por defecto del servidor. `get_server_information` da el nombre del servidor para Config. Funciona con cualquier servidor que implemente la especificación (mako, dunst, GNOME Shell, KDE Plasma). Almenara corre con la capacidad aplicada por `setcap`, no como root, así que alcanza el bus de sesión de la persona.
- **SQLite** (empaquetado por `rusqlite`): índice parcial (`WHERE seen_at IS NULL`), funciones de ventana y `json_extract` en el relleno de `closed_at`.
- **Sistema:** `clock_gettime` con `CLOCK_BOOTTIME` y `CLOCK_MONOTONIC` (libc) para la suspensión.
- **Formatos:** ninguno nuevo. Los canales externos de alertas (correo, ntfy, Telegram) y su exportación quedan para F7.

---

## 10. Decisiones Técnicas (ADR-lite)

La numeración de ADR es única en todo el proyecto: F5 llegó a la ADR-66 y F6 empieza en la ADR-67.

**ADR-67 · Catálogo fijo de reglas configurado en `config.toml` (vs. editor de reglas, vs. tabla `ALERT_RULES`) (respuesta 3a)**
Las 16 reglas cubren lo que dan las señales de F1–F5; un editor de reglas combinables pide un lenguaje, su validación y su interfaz, y casi nadie lo usaría en una red de casa. Los ajustes van en `config.toml`, versionable y tolerante (F4); la TUI solo activa, apaga y cambia el nivel, reescribiendo el fichero como ya hace `[ui]` (F2). La tabla `ALERT_RULES` prevista en el maestro no se crea.

**ADR-68 · Motor de alertas puro aplicado por el único escritor (vs. motor dentro de la TUI, vs. hilo con escritura propia) (respuesta 12a)**
El motor recibe señales y devuelve acciones; el hilo de la TUI las escribe y las entrega al notificador. Así se prueba sin BD ni TUI, ADR-35 sigue intacta y el modo servicio de la 6.5 podrá usarlo tal cual. Un hilo con conexión de escritura propia rompería el escritor único.

**ADR-69 · Tres niveles; solo «importante» notifica; MAC privada baja un nivel (respuesta 9a)**
Notificar todo acostumbra a ignorar las notificaciones. Lo importante por defecto (equipo nuevo con MAC fija, puerto nuevo, captura parada) es poco y merece interrumpir; los avisos se ven en la barra y la info, en la pestaña. Una MAC privada sin huella DHCP suele ser un móvil que rota su dirección (F4), no un intruso.

**ADR-70 · Aprendizaje por días con datos y por sujeto, sin vuelta atrás (vs. días de calendario, vs. sin aprendizaje) (respuesta 6a)**
Con Almenara cerrada no se aprende nada; contar días de calendario daría por aprendido un equipo que apenas se ha observado. El día cuenta si hubo cobertura de tráfico y tráfico del sujeto. Una vez aprendido, no se vuelve atrás: purgar datos o cambiar el umbral no debe reabrir una avalancha.

**ADR-71 · Inventario del propio equipo en `HOST_SEEN`, vacío al empezar (completa ADR-62)**
En una red conmutada, el propio equipo es el único sujeto que Almenara ve entero; sin inventario, lo nuevo no funcionaría donde más sirve. Meterlo en `DEVICES` lo haría aparecer en Equipos y rompería la atribución de F3; en `DEVICE_SEEN` con `device_id` nulo, `UNIQUE` no deduplicaría. No se rellena desde los rollups, porque los topes esconden claves en `~otros` y darían falsos «nuevos»: aprende 7 días desde la v6.

**ADR-72 · «Más tráfico de lo habitual» con la mediana de la misma hora local en 14 días con datos (vs. media y desviación típica, vs. límites fijos) (respuesta 4a)**
La mediana resiste los picos (una descarga grande no sube la base); la misma hora local respeta el ciclo diario. El mínimo de volumen evita avisos por bytes sueltos y la exigencia de 5 muestras evita juzgar sin base. Bajada y subida por separado, porque una subida rara es la señal de que algo saca datos.

**ADR-73 · Huecos dentro de la sesión en `COVERAGE_GAPS` (completa ADR-59)**
Un portátil se suspende cada noche con Almenara abierta: F5 contaba esas horas como «sin tráfico» y F6 aprendería bases con ceros que no lo son. Partir la sesión llenaría la línea de tiempo de arranques falsos; una tabla de huecos por sesión es aditiva y la usan todas las coberturas. `CLOCK_BOOTTIME` frente a `CLOCK_MONOTONIC` mide la suspensión sin que le afecte un cambio del reloj de pared.

**ADR-74 · Deduplicación de 24 h con repeticiones y condiciones en la misma fila (respuesta 8a)**
Una anomalía que dura horas no debe crear una alerta por hora. La misma clave dentro de 24 h suma `count` y `last_at` sin notificar; las condiciones se resuelven y se reactivan en su fila. Contar desde `created_at` deja una alerta por día si la anomalía persiste.

**ADR-75 · Puesta al día de 10 minutos, línea base y tope de notificaciones (respuesta 7a)**
Al arrancar llegan de golpe los cambios del tiempo cerrado y, en una base nueva, toda la red parece nueva. Agrupar la puesta al día en un resumen, no avisar de la red de partida y limitar a 3 notificaciones por minuto evita tapar la pantalla sin perder ninguna alerta.

**ADR-76 · Notificaciones por D-Bus con `notify-rust` 4.17 en un hilo propio (vs. `notify-send`, vs. subir la MSRV, vs. sin notificaciones) (respuesta 10a)**
`notify-rust` sobre `zbus` es Rust puro y no depende de libdbus ni de un comando instalado. La 4.17 es la última compatible con la MSRV 1.88; subirla a 1.89 se decidirá aparte. `show()` bloquea hasta que responde el servidor, así que va en su hilo con un canal acotado.

**ADR-77 · Texto de la red saneado en las alertas y escapado en las notificaciones**
Los nombres DHCP, mDNS y UPnP los pone cualquiera en la red. Quitar caracteres de control y secuencias ANSI protege la terminal; escapar `&`, `<` y `>` protege los servidores que interpretan marcado en el cuerpo. Vinculante para los canales externos de F7.

**ADR-78 · `DEVICE_SERVICES.closed_at` (respuesta 2a; salda la deuda de F5)**
F5 movía `last_seen` para que F2 viera cerrado un puerto. Una columna aditiva guarda el cierre y devuelve a `last_seen` su significado; se rellena desde el último evento de servicio. Los `last_seen` ya movidos no se recuperan.

**ADR-79 · Presencia solo de equipos vigilados (`DEVICES.watched`) (respuesta 5a)**
La presencia de un móvil es la de su dueño. Avisar de cualquier equipo que entra o sale convierte Almenara en un control de personas; marcar a mano el router, el NAS o un servidor da el aviso útil («se ha caído») sin vigilar a nadie por defecto.

**ADR-80 · Retención de 90 días y sin borrado manual (respuesta 11a)**
Lo mismo que los eventos de los que salen la mayoría de alertas. Un borrado manual añadiría confirmaciones y estados para poca ganancia; para guardar menos basta con bajar `retention_days`.

**ADR-81 · Sprint 6.0 de verificación con tráfico real (respuesta 1a)**
F3 ya demostró que la prueba real encuentra fallos que los tests no ven. Las alertas se apoyan en el tráfico, el inventario y la salud de la captura: medir antes con `CAP_NET_RAW` cierra las 9 casillas de F4 y prueba F5 con tráfico real. El desarrollador aplica la capacidad; el agente mide sin recompilar.

---

## 11. Plan de Desarrollo

**Supuestos:** 1 desarrollador, ~15 h/semana, F1–F5 estables como base. El sprint 6.0 necesita que el desarrollador ejecute `scripts/ejecutar-con-permisos.sh` al empezar; después, para probar F6 con captura real, tendrá que volver a aplicar la capacidad tras cada compilación.

### Sprint 6.0 — Verificación con tráfico real (≈ 6 h)
- Pasada con `CAP_NET_RAW`: las 9 casillas abiertas de F4, sin recompilar
- Histórico de F5 con captura real: minutos, ventanas, Histórico, huecos e inventario

### Sprint 6.1 — Modelo, configuración, huecos y puertos (≈ 16 h)
- Migración v6, rellenos (`closed_at`, aprendizaje) y test de compatibilidad v5 → v6
- `[alerts]` con validación y guardado de reglas
- Huecos de suspensión y de captura; coberturas, presencia y línea de tiempo de F5 con ellos
- `closed_at` en el ciclo de los puertos
- Inventario del propio equipo (`HOST_SEEN`)

### Sprint 6.2 — Motor y reglas (≈ 22 h)
- Motor puro: catálogo, deduplicación, condiciones, silencios, línea base y puesta al día
- Reglas de eventos, de lo nuevo, de vigilados y de salud
- Aprendizaje y «más tráfico de lo habitual»

### Sprint 6.3 — Notificaciones (≈ 10 h)
- Notificador con `notify-rust` 4.17 en su hilo, estado y reintento
- Política: niveles, puesta al día, horario silencioso y tope por minuto
- Texto saneado y escapado

### Sprint 6.4 — Interfaz y cierre (≈ 26 h)
- Pestaña Alertas: lista, detalle, filtros, silenciar, Reglas y Silencios
- Barra, Equipos (`*`, `!`, `p`), detalle de equipo, Config y Ayuda
- Mediciones `medir_*` de F6 con las cifras en el informe de implementación
- README, Ayuda, `CHANGELOG.md` y versión 0.6.0; informe de implementación

**Estimación total F6:** **~80 h → 5–6 semanas**.

---

## 12. Conexiones con Otras Fases

**Cambios sobre fases anteriores:**
- F4: el sprint 6.0 cierra sus 9 casillas pendientes (pasada con `CAP_NET_RAW`); se marcan en su propio checklist.
- F2 y F5: el estado CERRADO de un puerto pasa a `DEVICE_SERVICES.closed_at` (ADR-78); `Repo::mark_service_closed` deja de mover `last_seen` y `Changes::services` decide `reopened` con la columna.
- F5: toda cobertura (gráficas, ventanas, presencia) resta los huecos de `COVERAGE_GAPS` (ADR-73) y la línea de tiempo los muestra; el inventario gana el propio equipo (`HOST_SEEN`, ADR-71) y `Repo::upsert_seen` devuelve las entradas nuevas.
- F1: `DEVICES` gana `watched`; la pestaña Alertas deja de ser un hueco; la barra gana el contador.
- Maestro: la tabla `ALERT_RULES` prevista no se crea (ADR-67).

**Datos que usa:** `DEVICES`, `DEVICE_EVENTS` (`new`, `disappeared`, `mac_changed`, `hostname_changed`) y `events_retention_days` (F1); `DEVICE_SERVICES` y escaneo de puertos bajo demanda (F2); estadísticas de captura y `limit_drops` (F3); `mac_random` y motivo de `mac_changed` (F4); `reappeared`, `service_new`, `os_changed`, `type_changed`, `DEVICE_SEEN`, `TRAFFIC_ROLLUP_HOUR` y `_DAY`, `APP_SESSIONS`, `max_db_mb` y el lector (F5); la reescritura de `config.toml` de `[ui]` (F2).

**Fases siguientes:**
- **6.5 (Modo servicio):** Almenara sin TUI como servicio de usuario (`systemd --user`) con escaneo, captura, histórico y el motor de alertas de F6, para tener alertas con la TUI cerrada. Preguntas pendientes: cómo se conecta la TUI al servicio, la capacidad del servicio (`AmbientCapabilities`), las notificaciones desde el servicio y la instancia única.
- **F7 (Integraciones y exportación):** canales externos de alertas (correo, ntfy, Telegram) con el texto saneado de ADR-77; exportación CSV de alertas, rollups y eventos; fuentes externas (SNMP, puerto espejo) que dan visibilidad de otros equipos y hacen útiles para ellos las reglas de tráfico.
