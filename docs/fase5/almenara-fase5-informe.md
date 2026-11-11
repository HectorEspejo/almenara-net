# Almenara - Fase 5: Histórico, rollups y eventos

## Especificación Funcional

**Versión:** 1.0
**Fecha:** 2026-11-11
**Cliente:** Uso personal (desarrollador)

---

## 1. Visión General

La Fase 5 guarda lo que hasta ahora solo vivía en memoria. El agregador de F3 y F4 suma el tráfico por equipo, app, destino, protocolo, proceso, organización y país; F5 cierra esas sumas cada minuto y las escribe en **rollups** por minuto, hora y día, con una retención distinta para cada resolución. Con ellos llegan la pestaña **Histórico** (vacía desde F1), las ventanas de **1 h y 24 h** en Tráfico y la historia de cada equipo en su detalle.

La fase también completa los **eventos**: registra la vuelta a estar en línea, los puertos que se abren o se cierran, y los cambios de sistema operativo o de tipo. Con ellos se calcula la **presencia** de cada equipo (cuándo estuvo conectado). Además, guarda un **inventario por equipo** de lo que se le ha visto (apps, categorías, organizaciones, países, JA4) con la primera y la última vez, que es la base del «nuevo» de las alertas de F6.

**Visibilidad honesta.** Almenara es una TUI: solo hay histórico mientras está abierta. F5 registra cada arranque y cada cierre (sesiones con latido) y marca los huecos en gráficas, rankings y presencia; nunca los rellena. Para tener histórico continuo, se deja abierta (por ejemplo, en tmux); el modo servicio queda en el roadmap.

**Objetivos principales:**
1. Guardar el tráfico por minuto, hora y día en todas las dimensiones de F4, con topes por periodo y totales que cuadran.
2. Ofrecer la pestaña Histórico (gráfica, más tráfico y línea de tiempo) y las ventanas de 1 h y 24 h en Tráfico.
3. Completar los eventos (vuelta a línea, puertos, sistema operativo y tipo) y mostrar la presencia de cada equipo.
4. Guardar un inventario por equipo con primera y última vez, como base de las alertas de F6.
5. Mantener la privacidad: sin contenido, sin registro de conexiones y con los destinos solo por horas y durante 30 días.
6. Controlar el tamaño de la base de datos con retención por resolución, purga, compactación y aviso.

**Contexto:** evolución de F1–F4. F4 está implementada (167/176) sin la pasada con `CAP_NET_RAW`: el 2026-11-11 el desarrollador decidió seguir sin ella (respuesta 1c), así que F5 se especifica sobre una F4 sin medir y no incluye esa pasada; el riesgo queda alto en el maestro. Las mediciones de F5 usan un histórico sintético y no dependen de la captura. Resto de decisiones de la sesión del 2026-11-11: opción recomendada en las preguntas 2 a 12 y en los supuestos técnicos. Migración v5 aditiva: toda BD de F4 sigue funcionando sin pérdida de datos.

---

## 2. Arquitectura Técnica

### Stack tecnológico (novedades respecto a F4)

| Capa | Tecnología | Motivo |
|------|-----------|--------|
| Rollups | `rusqlite` (ya en el stack), tablas `WITHOUT ROWID` con upsert `ON CONFLICT DO UPDATE` | Cubos compactos y escritura que suma si el minuto ya existe |
| Lectura del histórico | Segunda conexión de `rusqlite` de solo lectura (`SQLITE_OPEN_READ_ONLY`, `query_only`) en un hilo propio | Consultas largas sin bloquear la TUI; WAL permite leer mientras se escribe |
| Compactación | `PRAGMA auto_vacuum = INCREMENTAL` + `incremental_vacuum` | Devolver espacio tras purgar sin `VACUUM` completo |
| Hora local | `libc::localtime_r` (ya en el stack) | Días por fecha local sin añadir crates de fechas |
| Instancia única | `flock` de `libc`/`nix` (ya en el stack) | Evitar dos escritores que dupliquen rollups y eventos |
| Gráficas | Widgets de ratatui (barras con bloques y sparklines) | Sin dependencias nuevas |

**Sin dependencias nuevas.** Todo lo de F5 sale de crates que ya están en el proyecto. Si alguna función de SQLite no está en la versión empaquetada por `rusqlite`, el agente lo anota como desviación y usa una alternativa equivalente.

**Rutas de F1–F4.** Las rutas citadas son las de sus informes y del informe de implementación de F4. Si el código real difiere, manda el código y la correspondencia se anota en el informe de implementación.

### Estructura de carpetas (novedades)

```
almenara/
├── docs/fase5/                     # informe, prompt, checklist e implementación
├── CHANGELOG.md                    # novedades de la 0.5.0
├── tests/
│   └── historial_sintetico.rs      # NUEVO: prueba ignorada que mide tamaño y tiempos
└── src/
    ├── history/                    # NUEVO módulo raíz
    │   ├── mod.rs                  # tipos comunes: sujeto, dimensión, clave, cubo
    │   ├── rollup.rs               # MinuteRollup: acumuladores del minuto y topes (agregador)
    │   ├── build.rs                # consolidación de horas y días, pendientes
    │   ├── retention.rs            # purga por resolución y compactación
    │   ├── changes.rs              # eventos nuevos: presencia, servicios, identidad
    │   ├── reader.rs               # HistoryReader: hilo lector y canal de consultas
    │   ├── queries.rs              # consultas: series, top, ventanas, eventos, presencia…
    │   ├── localtime.rs            # día local ⇄ UTC con localtime_r
    │   └── synthetic.rs            # histórico sintético (solo pruebas y mediciones)
    ├── instance.rs                 # NUEVO: bloqueo de instancia única
    ├── rankings.rs                 # (extendido) alimenta MinuteRollup y cierra el minuto
    ├── config.rs                   # (extendido) [history]
    ├── repo/
    │   ├── rollups.rs              # NUEVO DAO de TRAFFIC_ROLLUP_*
    │   ├── seen.rs                 # NUEVO DAO de DEVICE_SEEN
    │   ├── sessions.rs             # NUEVO DAO de APP_SESSIONS
    │   ├── events.rs               # (extendido) tipos nuevos de evento
    │   └── migrations.rs           # migración v5
    └── tui/views/
        ├── history.rs              # NUEVO: pestaña Histórico
        ├── charts.rs               # NUEVO: barras, sparklines, presencia y huecos
        ├── traffic.rs              # (extendido) ventanas 1 h y 24 h
        ├── device_detail.rs        # (extendido) histórico, presencia e inventario
        ├── devices.rs              # (extendido) «Último evento»
        ├── config_view.rs          # (extendido) [history] y tamaño de la BD
        └── help.rs                 # (extendido) teclas y privacidad del histórico
```

### Hilos y flujo de datos

- **Agregador** (F3/F4): `Rankings::record` alimenta también `MinuteRollup` con el mismo volcado por flujo y segundo. Al cambiar el minuto (reloj UTC), `MinuteRollup::flush` aplica los topes y envía el lote por `AppEvent::Rollup`. No toca la BD.
- **Hilo de la TUI** (único escritor, ADR-35): escribe el lote del minuto y el inventario, da el latido de la sesión, consolida horas y días, purga y compacta. Reconcilia los eventos del escaneo (F1/F2) y añade los nuevos tipos.
- **Lector del histórico** (F5): hilo con su propia conexión de solo lectura. Recibe `HistoryQuery` con un identificador y responde con `AppEvent::History`. El render nunca consulta la BD: pinta el último resultado recibido.
- **Escaneo** (F1/F2): sin cambios; su informe de ciclo trae el resultado de los escaneos de puertos bajo demanda, que alimenta `service_new` y `service_gone`.

### Diagrama de arquitectura

```
┌────────────────────────────────────────────────────────────────────────────┐
│      TUI (ratatui) · hilo de la TUI · único escritor SQLite (ADR-35)       │
│ ┌───────────┐ ┌───────────┐ ┌──────────────┐ ┌─────────────┐ ┌───────────┐ │
│ │ Equipos   │ │ Tráfico   │ │ Histórico    │ │ Detalle     │ │ Config    │ │
│ │ último    │ │ w: 1 h y  │ │ gráfica, top,│ │ 24 h/7 días,│ │ [history],│ │
│ │ evento    │ │ 24 h      │ │ eventos      │ │ presencia   │ │ tamaño BD │ │
│ └───────────┘ └───────────┘ └──────────────┘ └─────────────┘ └───────────┘ │
│ Repo (escritor): lotes por minuto, horas, días, purga, sesiones            │
└───────────────────────────────────────────────┬─────────┬──────────────────┘
          ▲                   ▲                 │         │ consulta      ▲
          │ Devices           │ Rollup (1/min)  │         │     resultado │
          │                   │ Traffic (1 s)   │         ▼               │
┌─────────┴────────┐    ┌─────┴──────────────┐  │   ┌─────────────────────┴──┐
│ Escaneo (F1/F2)  │    │ Agregador (F3–F5)  │  │   │ Lector del histórico   │
│ ciclo + puertos  │    │ Rankings +         │  │   │ (F5): conexión de      │
│ bajo demanda     │    │ MinuteRollup       │  │   │ solo lectura           │
└──────────────────┘    └────────────────────┘  │   └───────────┬────────────┘
                                  ▲ CaptureBatch│               │
                                  │             │               │
                        ┌─────────┴──────────┐  │               │
                        │ Captura + inspector│  │ escribe       │ lee
                        │ (F3/F4)            │  │               │
                        └────────────────────┘  │               │
                                                │               │
                                                ▼               ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ SQLite (WAL): TRAFFIC_ROLLUP_MINUTE/HOUR/DAY · DEVICE_SEEN · APP_SESSIONS  │
│ DEVICE_EVENTS (+ tipos de F5) · DEVICES · DEVICE_SERVICES · CONNECTIONS    │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Modelo de Datos

### Migración v5 (aditiva, no rompe F1–F4)

```sql
-- v5 — Fase 5: histórico, rollups y eventos

CREATE TABLE TRAFFIC_ROLLUP_MINUTE (
  bucket       INTEGER NOT NULL,            -- inicio del minuto: segundos Unix UTC
  subject      TEXT    NOT NULL,            -- 'device' | 'host' | 'other' | 'network'
  device_id    INTEGER NOT NULL DEFAULT 0,  -- DEVICES.id si subject = 'device'; 0 en otro caso
  dimension    TEXT    NOT NULL,            -- 'total' | 'app' | 'category' | 'destination'
                                            -- | 'protocol' | 'process' | 'org' | 'country'
  key          TEXT    NOT NULL,            -- '' en 'total'; claves especiales con '~' (§7.1)
  bytes_down   INTEGER NOT NULL DEFAULT 0,
  bytes_up     INTEGER NOT NULL DEFAULT 0,
  connections  INTEGER NOT NULL DEFAULT 0,  -- flujos nuevos en el cubo
  PRIMARY KEY (bucket, subject, device_id, dimension, key)
) WITHOUT ROWID;

CREATE TABLE TRAFFIC_ROLLUP_HOUR (           -- misma estructura; bucket = inicio de la hora UTC
  bucket INTEGER NOT NULL, subject TEXT NOT NULL, device_id INTEGER NOT NULL DEFAULT 0,
  dimension TEXT NOT NULL, key TEXT NOT NULL, bytes_down INTEGER NOT NULL DEFAULT 0,
  bytes_up INTEGER NOT NULL DEFAULT 0, connections INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, subject, device_id, dimension, key)
) WITHOUT ROWID;

CREATE TABLE TRAFFIC_ROLLUP_DAY (            -- misma estructura; bucket = día local AAAAMMDD
  bucket INTEGER NOT NULL, subject TEXT NOT NULL, device_id INTEGER NOT NULL DEFAULT 0,
  dimension TEXT NOT NULL, key TEXT NOT NULL, bytes_down INTEGER NOT NULL DEFAULT 0,
  bytes_up INTEGER NOT NULL DEFAULT 0, connections INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, subject, device_id, dimension, key)
) WITHOUT ROWID;

CREATE TABLE DEVICE_SEEN (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id   INTEGER NOT NULL REFERENCES DEVICES(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,                -- 'app' | 'category' | 'org' | 'country' | 'ja4'
  key         TEXT NOT NULL,
  first_seen  TIMESTAMP NOT NULL,           -- RFC 3339 UTC (ADR-34)
  last_seen   TIMESTAMP NOT NULL,
  UNIQUE (device_id, kind, key)
);

CREATE TABLE APP_SESSIONS (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at    TIMESTAMP NOT NULL,
  ended_at      TIMESTAMP NULL,             -- NULL mientras está abierta
  last_beat     TIMESTAMP NOT NULL,         -- latido cada minuto
  end_reason    TEXT NULL,                  -- 'quit' | 'interrupted'
  mode          TEXT NOT NULL,              -- 'privileged' | 'degraded' (F1)
  capture       BOOLEAN NOT NULL,           -- había captura al arrancar (F3)
  passive_only  BOOLEAN NOT NULL,
  version       TEXT NOT NULL               -- versión de Almenara
);

-- Una sola vez, fuera de la transacción de la migración (si PRAGMA auto_vacuum ≠ 2):
PRAGMA auto_vacuum = INCREMENTAL;
VACUUM;
```

- `DEVICE_EVENTS` no cambia de esquema: `event_type` es TEXT sin `CHECK` y gana `reappeared`, `service_new`, `service_gone`, `os_changed` y `type_changed`. Los detalles JSON de `disappeared` ganan `last_seen`.
- Las tablas de rollups no tienen índices secundarios: la clave primaria empieza por `bucket`, que es lo que usan la purga, la consolidación y los rangos. Si las mediciones del §8 no se cumplen, el agente puede añadir un índice por sujeto y anotar el tamaño que cuesta.
- Sin `CHECK` en enumeraciones (regla transversal): `subject`, `dimension`, `kind`, `end_reason` y `mode` se validan en el código.

### Diagrama E-R (parte nueva)

```
┌────────────────────────────────┐          ┌────────────────────────────────┐
│ DEVICES (F1, ampl. F2 y F4)    │          │ TRAFFIC_ROLLUP_MINUTE (F5)     │
├────────────────────────────────┤ 1   0..N │ TRAFFIC_ROLLUP_HOUR (F5)       │
│ id (PK) · mac · ip · …         ├─────────►│ TRAFFIC_ROLLUP_DAY (F5)        │
│ is_online · first/last_seen    │  sin FK  ├────────────────────────────────┤
└─────┬─────────────────┬────────┘          │ bucket (PK, INTEGER)           │
      │ 1               │ 1                 │ subject (PK)                   │
      │                 │                   │ device_id (PK; 0 = no equipo)  │
      │ 0..N            │ 0..N              │ dimension (PK)                 │
      ▼                 ▼                   │ key (PK)                       │
┌──────────────────┐ ┌────────────────────┐ │ bytes_down · bytes_up          │
│ DEVICE_SEEN (F5) │ │ DEVICE_EVENTS (F1) │ │ connections                    │
├──────────────────┤ ├────────────────────┤ │ WITHOUT ROWID                  │
│ id (PK)          │ │ event_type + F5:   │ └────────────────────────────────┘
│ device_id (FK)   │ │ reappeared         │
│ kind · key       │ │ service_new        │ ┌────────────────────────────────┐
│ first_seen       │ │ service_gone       │ │ APP_SESSIONS (F5)              │
│ last_seen        │ │ os_changed         │ ├────────────────────────────────┤
│ UNIQUE(device_id,│ │ type_changed       │ │ id (PK) · started_at           │
│   kind, key)     │ │ (sin cambio de     │ │ ended_at · last_beat           │
└──────────────────┘ │  esquema)          │ │ end_reason · mode              │
                     └────────────────────┘ │ capture · passive_only         │
                                            │ version                        │
DEVICE_SERVICES (F2) sin cambios: da los    │ Sin claves ajenas: sesiones    │
puertos del inventario y el origen de       │ de Almenara (huecos)           │
service_new y service_gone.                 └────────────────────────────────┘
```

### Definición de tablas

**TRAFFIC_ROLLUP_MINUTE / TRAFFIC_ROLLUP_HOUR / TRAFFIC_ROLLUP_DAY** — tráfico agregado por cubo, sujeto, dimensión y clave.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `bucket` | INTEGER | Inicio del minuto o de la hora en segundos Unix UTC; en días, la fecha local como AAAAMMDD (ADR-56) |
| `subject` | TEXT | `device`, `host` (el propio equipo), `other` (sin equipo local atribuible) o `network` (la red entera, solo `total`) |
| `device_id` | INTEGER | `DEVICES.id` cuando `subject = 'device'`; 0 en otro caso. Sin clave ajena (ADR-55) |
| `dimension` | TEXT | `total`, `app`, `category`, `destination`, `protocol`, `process`, `org` o `country` |
| `key` | TEXT | Clave de la dimensión (§7.1); vacía en `total` |
| `bytes_down` | INTEGER | Bytes de bajada en el cubo |
| `bytes_up` | INTEGER | Bytes de subida en el cubo |
| `connections` | INTEGER | Flujos cuyo primer paquete cae en el cubo |

**DEVICE_SEEN** — inventario por equipo: qué se le ha visto y cuándo.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK | Identificador |
| `device_id` | INTEGER FK | `DEVICES.id`, borrado en cascada |
| `kind` | TEXT | `app`, `category`, `org`, `country` o `ja4` |
| `key` | TEXT | Clave de app o categoría del catálogo, organización de DB-IP, código ISO de país o huella JA4 |
| `first_seen` | TIMESTAMP | Primer minuto en que se vio |
| `last_seen` | TIMESTAMP | Último minuto en que se vio |

**APP_SESSIONS** — cada ejecución de Almenara.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK | Identificador |
| `started_at` | TIMESTAMP | Arranque |
| `ended_at` | TIMESTAMP NULL | Cierre; NULL mientras está abierta |
| `last_beat` | TIMESTAMP | Último latido (cada minuto) |
| `end_reason` | TEXT NULL | `quit` (salida con `q`) o `interrupted` (cerrada en el arranque siguiente) |
| `mode` | TEXT | `privileged` o `degraded` (F1) |
| `capture` | BOOLEAN | Había captura al arrancar (F3) |
| `passive_only` | BOOLEAN | Modo pasivo |
| `version` | TEXT | Versión de Almenara |

### Relaciones

- `DEVICES` 1 — N `DEVICE_SEEN` (clave ajena con borrado en cascada).
- `DEVICES` 1 — N `TRAFFIC_ROLLUP_*` cuando `subject = 'device'`: relación lógica, sin clave ajena, porque `device_id = 0` representa a los sujetos que no son equipos. Si F1–F4 borran equipos, el DAO borra también sus rollups.
- `DEVICES` 1 — N `DEVICE_EVENTS` (F1) y `DEVICE_SERVICES` (F2), sin cambios de esquema. `DEVICE_SERVICES` da los puertos del inventario y el origen de `service_new` y `service_gone`.
- `APP_SESSIONS` no tiene relaciones: delimita los periodos con datos.
- `TRAFFIC_SNAPSHOT` (F3) sigue igual y sigue siendo la semilla de las sparklines de 60 s.

### Diagrama de estados — sesión de Almenara (`APP_SESSIONS`)

```
┌──────────────────────────────┐   q   ┌──────────────────────┐
│ ABIERTA                      ├──────►│ CERRADA              │
│ started_at; last_beat        │       │ ended_at = ahora,    │
│ cada minuto                  │       │ end_reason = quit    │
└───────────────┬──────────────┘       └──────────────────────┘
                │ caída o apagado sin q
                ▼
┌──────────────────────────────┐
│ SIN CERRAR                   │
│ ended_at NULL y Almenara     │
│ ya no corre                  │
└───────────────┬──────────────┘
                │ siguiente arranque
                ▼
┌──────────────────────────────┐
│ INTERRUMPIDA                 │
│ ended_at = last_beat,        │
│ end_reason = interrupted     │
└──────────────────────────────┘

Transiciones inválidas:
 · reabrir una sesión CERRADA o INTERRUMPIDA
 · dos sesiones ABIERTAS a la vez (lo impide la instancia única)
 · ended_at anterior a started_at, o posterior a last_beat en una INTERRUMPIDA
```

### Diagrama de estados — cubo del histórico

```
┌──────────────────────────────┐  caída  ┌─────────────────────────┐
│ EN MEMORIA                   ├────────►│ PERDIDO                 │
│ acumuladores del minuto      │         │ (como mucho 1 minuto)   │
│ en curso (agregador)         │         └─────────────────────────┘
└───────────────┬──────────────┘
                │ cambia el minuto
                ▼
┌──────────────────────────────┐  fallo  ┌─────────────────────────┐
│ MINUTO ESCRITO               ├────────►│ EN REINTENTO            │
│ TRAFFIC_ROLLUP_MINUTE        │         │ en memoria, ≤ 10 lotes; │
└───────────────┬──────────────┘         │ después rollup_drops    │
                │ cierra la hora         └─────────────────────────┘
                ▼
┌──────────────────────────────┐
│ HORA CONSOLIDADA             │
│ TRAFFIC_ROLLUP_HOUR          │
└───────────────┬──────────────┘
                │ cierra el día local
                ▼
┌──────────────────────────────┐
│ DÍA CONSOLIDADO              │
│ TRAFFIC_ROLLUP_DAY           │
│ (sin destinos)               │
└───────────────┬──────────────┘
                │ vence la retención
                ▼
┌──────────────────────────────┐
│ PURGADO                      │
└──────────────────────────────┘

Cada resolución se purga por su cuenta (§7.4): minutos a las 48 h (destinos a las
2 h), horas a los 90 días (destinos a los 30) y días a los 2 años.

Transiciones inválidas:
 · consolidar una hora o un día que no ha terminado
 · purgar minutos de una hora sin consolidar
 · escribir dos veces el mismo minuto sin sumar (el upsert suma)
```

### Diagrama de estados — presencia de un equipo (`DEVICES`, F1 + F5)

```
┌──────────────────────────────┐ cierre  ┌──────────────────────┐
│ ONLINE                       ├────────►│ SIN DATOS            │
│ evento new (una vez por      │         │ Almenara cerrada: ni │
│ MAC)                         │         │ presente ni ausente  │
└───────────────┬──────────────┘         └──────────────────────┘
                │ no visto N ciclos (F1)
                ▼
┌──────────────────────────────┐
│ OFFLINE                      │
│ evento disappeared           │
│ (+ last_seen, F5)            │
└───────────────┬──────────────┘
                │ reaparece
                ▼
┌──────────────────────────────┐
│ ONLINE                       │
│ evento reappeared (F5)       │
│ (away_since, away_s)         │
└──────────────────────────────┘

Cualquier estado pasa a SIN DATOS mientras Almenara está cerrada; al volver,
manda lo que digan los eventos de la sesión nueva (§7.8).

Transiciones inválidas:
 · reappeared sin un disappeared previo
 · new más de una vez por MAC (F1)
 · presente o ausente dentro de un hueco
```

### Diagrama de estados — servicio de un equipo (`DEVICE_SERVICES`, F2 + F5)

```
┌──────────────────────────────┐
│ SIN ESCANEAR                 │
│ equipo sin primer escaneo    │
│ de puertos                   │
└───────────────┬──────────────┘
                │ primer escaneo (sin eventos)
                ▼
┌──────────────────────────────┐ escaneo  ┌─────────────────────────┐
│ ABIERTO (ACTIVE, F2)         ├─────────►│ service_new si el puerto│
│ puerto visto abierto         │          │ aparece en un equipo ya │
└───────────────┬──────────────┘          │ escaneado               │
                │                         └─────────────────────────┘
                │ un escaneo lo ve cerrado
                ▼
┌──────────────────────────────┐
│ CERRADO (STALE, F2)          │
│ evento service_gone          │
└───────────────┬──────────────┘
                │ un escaneo lo ve abierto
                ▼
┌──────────────────────────────┐
│ ABIERTO                      │
│ evento service_new           │
│ (reopened = true)            │
└──────────────────────────────┘

Transiciones inválidas:
 · service_new o service_gone sin escaneo de puertos (p. ej. STALE por tiempo)
 · eventos de servicios en el primer escaneo del equipo o con passive_only
```

### Diagrama de estados — entrada del inventario (`DEVICE_SEEN`)

```
┌──────────────────────────────┐
│ NUEVA                        │
│ first_seen = last_seen =     │
│ minuto del lote              │
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
│ (o borrada con el equipo)    │
└──────────────────────────────┘

Transiciones inválidas:
 · first_seen posterior a last_seen, o last_seen hacia atrás
 · claves especiales (~…) o destinos en el inventario
```

---

## 4. Flujos de Trabajo

### 4.1 Cierre del minuto y escritura del lote

```
┌──────────────────────────────┐
│ bytes de un flujo con        │
│ etiqueta (Rankings::record,  │
│ por flujo y segundo)         │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  lleno  ┌─────────────────────────┐
│ MinuteRollup::add: sujeto,   ├────────►│ > 20 000 entradas: suma │
│ dimensiones y claves (§7.1)  │         │ directa en ~otros y     │
└───────────────┬──────────────┘         │ rollup_overflow         │
                │                        └─────────────────────────┘
                ▼
┌──────────────────────────────┐   no    ┌─────────────────────────┐
│ ¿cambia el minuto (reloj     ├────────►│ seguir acumulando       │
│ UTC)?                        │         └─────────────────────────┘
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ MinuteRollup::flush: topes,  │
│ ~otros e inventario          │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ AppEvent::Rollup → hilo de   │
│ la TUI                       │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  error  ┌─────────────────────────┐
│ Repo::insert_minute_batch    ├────────►│ reintento en el minuto  │
│ (transacción: minutos +      │         │ siguiente (≤ 10 lotes); │
│ inventario)                  │         │ después descarte,       │
└───────────────┬──────────────┘         │ rollup_drops y aviso    │
                │                        └─────────────────────────┘
                ▼
┌──────────────────────────────┐   sí    ┌─────────────────────────┐
│ ¿cerró una hora?             ├────────►│ consolidación y purga   │
└───────────────┬──────────────┘         │ (§4.2)                  │
                │ no                     └─────────────────────────┘
                ▼
┌──────────────────────────────┐
│ refrescar ventanas 1 h y     │
│ 24 h y vistas abiertas       │
│ (lector)                     │
└──────────────────────────────┘

Tras la consolidación también se refrescan las vistas.
```

1. Cada volcado por flujo y segundo de `Rankings::record` suma también en `MinuteRollup`, para cada sujeto y dimensión del flujo (§7.1). Un flujo nuevo suma además una conexión.
2. Si los acumuladores superan 20 000 entradas, lo que no cabe va directo a `~otros` de su sujeto y dimensión y se cuenta en `rollup_overflow`.
3. En el primer tick de un minuto nuevo (reloj UTC), `MinuteRollup::flush` cierra el anterior: aplica los topes (§7.2), anota el inventario antes de los topes y envía el lote por `AppEvent::Rollup`.
4. El hilo de la TUI escribe el lote en una transacción (`Repo::insert_minute_batch`), con suma si el minuto ya existe, y el inventario (`Repo::upsert_seen`).
5. Si la escritura falla, el lote espera en memoria y se reintenta en el minuto siguiente. Con más de 10 lotes pendientes se descarta el más antiguo, se cuenta en `rollup_drops` y se avisa una vez.
6. Si el lote cierra una hora, sigue la consolidación (§4.2). Después se refrescan las ventanas de 1 h y 24 h y las vistas del histórico abiertas.

### 4.2 Consolidación, purga y compactación

```
┌──────────────────────────────┐
│ hora cerrada, o pendiente    │
│ al arrancar                  │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐ sin datos ┌──────────────────────────┐
│ Repo::build_hour: suma de    ├──────────►│ nada que construir:      │
│ minutos, topes y ~otros      │           │ la hora es un hueco      │
└───────────────┬──────────────┘           └──────────────────────────┘
                ▼
┌──────────────────────────────┐    sí     ┌──────────────────────────┐
│ ¿cerró un día local?         ├──────────►│ Repo::build_day con sus  │
└───────────────┬──────────────┘           │ horas reales (23 a 25),  │
                │ no                       │ sin destinos             │
                │                          └──────────────────────────┘
                ▼
┌──────────────────────────────┐ sin hora  ┌──────────────────────────┐
│ Repo::purge_history por      ├──────────►│ los minutos de una hora  │
│ resolución (§7.4)            │           │ sin consolidar no se     │
└───────────────┬──────────────┘           │ purgan                   │
                │                          └──────────────────────────┘
                ▼
┌──────────────────────────────┐
│ Repo::incremental_vacuum     │
│ (≤ 2000 páginas)             │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐    sí     ┌──────────────────────────┐
│ ¿BD > max_db_mb?             ├──────────►│ aviso (una vez por       │
└───────────────┬──────────────┘           │ sesión) y Config         │
                │ no                       │ resaltada                │
                │                          └──────────────────────────┘
                ▼
┌──────────────────────────────┐
│ fin; al arrancar, la         │
│ siguiente pendiente          │
└──────────────────────────────┘

La rama «sí» de «¿cerró un día local?» sigue después con la purga.
```

1. Al cerrarse una hora, `Repo::build_hour` suma sus minutos y vuelve a aplicar los topes. Una hora sin minutos es un hueco: no se escribe nada.
2. Al cerrarse un día local, `Repo::build_day` suma sus horas reales (23, 24 o 25 según el cambio de hora), sin la dimensión destino.
3. `Repo::purge_history` borra por resolución (§7.4). Nunca borra minutos de una hora sin consolidar.
4. `Repo::incremental_vacuum` devuelve como mucho 2000 páginas por ejecución.
5. Si la BD supera `max_db_mb`, se avisa una vez por sesión y Config lo resalta.

### 4.3 Arranque

```
┌──────────────────────────────┐
│ arranque de Almenara         │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  ocupado  ┌─────────────────────────┐
│ Instance::acquire            ├──────────►│ «Almenara ya está en    │
│ (data.db.lock)               │           │ marcha (PID n)» y       │
└───────────────┬──────────────┘           │ salida sin tocar la BD  │
                │                          └─────────────────────────┘
                ▼
┌──────────────────────────────┐   falla   ┌─────────────────────────┐
│ migraciones; v5: tablas,     ├──────────►│ modal de BD de F1:      │
│ auto_vacuum y VACUUM (una    │           │ reintentar o salir      │
│ sola vez)                    │           └─────────────────────────┘
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ Repo::close_open_sessions    │
│ (ended_at = last_beat)       │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ Repo::open_session: modo,    │
│ captura, passive_only,       │
│ versión                      │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ lanzar lector, escaneo y     │
│ captura; abrir la TUI        │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ horas y días pendientes en   │
│ tandas de 10 por segundo     │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ funcionamiento normal:       │
│ lote por minuto (§4.1)       │
└──────────────────────────────┘
```

1. `Instance::acquire` toma el bloqueo `data.db.lock`. Si otra Almenara lo tiene, se muestra «Almenara ya está en marcha (PID n)» y se sale sin tocar la BD.
2. Las migraciones crean las tablas de v5 y, una sola vez, activan `auto_vacuum` incremental con un `VACUUM` fuera de la transacción.
3. `Repo::close_open_sessions` cierra las sesiones sin cierre con `ended_at = last_beat` y `end_reason = interrupted`.
4. `Repo::open_session` abre la sesión nueva con el modo, la captura, `passive_only` y la versión.
5. Se lanzan el lector, el escaneo y la captura, y se abre la TUI.
6. Las horas y los días pendientes (`Repo::pending_hours`, `Repo::pending_days`) se construyen en tandas de 10 por segundo, antes de cualquier purga.

### 4.4 Eventos nuevos en la reconciliación

```
┌──────────────────────────────┐
│ informe del ciclo de         │
│ escaneo (AppEvent::Devices)  │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ reconciliación de F1–F4      │
│ (altas, cambios, offline)    │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  sí   ┌──────────────────────────┐
│ ¿equipo OFFLINE que          ├──────►│ reappeared (away_since,  │
│ reaparece?                   │       │ away_s)                  │
└───────────────┬──────────────┘       └──────────────────────────┘
                │ sigue
                ▼
┌──────────────────────────────┐  sí   ┌──────────────────────────┐
│ ¿escaneo de puertos del      ├──────►│ Changes::services contra │
│ equipo en este ciclo?        │       │ DEVICE_SERVICES; nada en │
└───────────────┬──────────────┘       │ el primer escaneo        │
                │ sigue                └──────────────────────────┘
                ▼
┌──────────────────────────────┐  sí   ┌──────────────────────────┐
│ ¿os_family o device_type     ├──────►│ os_changed o type_changed│
│ automático cambian entre     │       │ (antes, después, fuente) │
│ valores conocidos?           │       └──────────────────────────┘
└───────────────┬──────────────┘
                │ sigue
                ▼
┌──────────────────────────────┐
│ insertar eventos y           │
│ actualizar «Último evento»   │
└──────────────────────────────┘

Las ramas «sí» también siguen al paso siguiente.
```

La reconciliación de F1–F4 sigue igual. Después, `Changes::presence`, `Changes::services` y `Changes::identity` añaden los eventos nuevos (§7.7). Los eventos se insertan en `DEVICE_EVENTS` y el más reciente pasa a la línea «Último evento» de Equipos.

### 4.5 Consulta del histórico

```
┌──────────────────────────────┐
│ la vista necesita datos:     │
│ rango, sujeto, filtro o      │
│ minuto nuevo                 │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ HistoryQuery con id →        │
│ canal del lector             │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  error  ┌────────────────────────┐
│ consulta en la conexión de   ├────────►│ resultado de error o   │
│ solo lectura (WAL)           │         │ más de 2 s: mensaje en │
└───────────────┬──────────────┘         │ la vista, sin bloquear │
                │                        └────────────────────────┘
                ▼
┌──────────────────────────────┐
│ AppEvent::History (id,       │
│ resultado)                   │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   no    ┌────────────────────────┐
│ ¿id = última petición de     ├────────►│ descartar (obsoleto)   │
│ esa vista?                   │         └────────────────────────┘
└───────────────┬──────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ guardar en el estado; el     │
│ render pinta sin tocar la    │
│ BD                           │
└──────────────────────────────┘
```

Cada vista que necesita datos pide una consulta con un identificador nuevo. El lector la ejecuta en su conexión de solo lectura y responde con `AppEvent::History`. La TUI guarda solo el resultado de la última petición de cada vista y descarta las obsoletas. Una consulta que falla o pasa de 2 s devuelve un error que la vista muestra sin bloquear.

### 4.6 Secuencia — cierre del minuto y ventana de 24 h

```
Agregador           TUI/Repo             SQLite            Lector
    │                   │                   │                 │
    │ 11:00:00          │                   │                 │
    │ flush(10:59)      │                   │                 │
    │ AppEvent::Rollup  │                   │                 │
    ├──────────────────►│                   │                 │
    │                   │ BEGIN · minutos   │                 │
    │                   ├──────────────────►│                 │
    │                   │ DEVICE_SEEN       │                 │
    │                   ├──────────────────►│                 │
    │                   │ COMMIT            │                 │
    │                   ├──────────────────►│                 │
    │                   │ ¿cerró la hora?   │                 │
    │                   │ build_hour(10 h)  │                 │
    │                   ├──────────────────►│                 │
    │                   │ purga + vacuum    │                 │
    │                   ├──────────────────►│                 │
    │                   │ ranking 24 h #7   │                 │
    │                   ├───────────────────┼────────────────►│
    │                   │                   │ SELECT HOUR+MIN │
    │                   │                   │◄────────────────┤
    │                   │ History #7        │                 │
    │                   │◄──────────────────┼─────────────────┤
    │                   │ pinta Tráfico     │                 │
    │                   │                   │                 │
```

### 4.7 Secuencia — cambio de rango en Histórico

```
Persona            TUI               Lector            SQLite
  │                 │                   │                 │
  │ w (7 días)      │                   │                 │
  ├────────────────►│                   │                 │
  │                 │ series #41        │                 │
  │                 ├──────────────────►│                 │
  │                 │ top #42           │                 │
  │                 ├──────────────────►│                 │
  │                 │ timeline #43      │                 │
  │                 ├──────────────────►│                 │
  │                 │                   │ SELECT … HOUR   │
  │                 │                   ├────────────────►│
  │                 │ History #41       │                 │
  │                 │◄──────────────────┤                 │
  │ w (30 días)     │                   │                 │
  ├────────────────►│                   │                 │
  │                 │ series #44        │                 │
  │                 ├──────────────────►│                 │
  │                 │ History #42       │                 │
  │                 │◄──────────────────┤                 │
  │                 │ obsoleto: fuera   │                 │
  │                 │                   │ SELECT … DAY    │
  │                 │                   ├────────────────►│
  │                 │ History #44       │                 │
  │                 │◄──────────────────┤                 │
  │                 │ pinta 30 días     │                 │
  │                 │                   │                 │
```

### 4.8 Secuencia — salida con `q`

```
Persona         TUI/Repo            Agregador          SQLite
  │                 │                   │                 │
  │ q               │                   │                 │
  ├────────────────►│                   │                 │
  │                 │ Stop              │                 │
  │                 ├──────────────────►│                 │
  │                 │                   │ flush(minuto    │
  │                 │                   │ parcial)        │
  │                 │ AppEvent::Rollup  │                 │
  │                 │◄──────────────────┤                 │
  │                 │ minuto parcial    │                 │
  │                 ├───────────────────┼────────────────►│
  │                 │ close_session     │                 │
  │                 ├───────────────────┼────────────────►│
  │                 │ join ≤ 2 s (F3)   │                 │
  │                 │                   │                 │
```

Al salir, el agregador cierra el minuto en curso (parcial) antes de pararse, la TUI lo escribe y cierra la sesión con `quit`. Si el proceso muere sin salir, se pierde como mucho ese minuto y la sesión se cierra en el arranque siguiente.

---

## 5. API Endpoints (servicios internos)

No hay API HTTP. La fase añade los siguientes servicios internos.

### `history::rollup` (agregador)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `MinuteRollup::add` | `fn(&mut self, subjects: &[Subject], dims: &FlowDims, bytes: u64, dir: Dir)` | Suma bytes a cada sujeto, dimensión y clave del flujo (§7.1) |
| `MinuteRollup::add_flow` | `fn(&mut self, subjects: &[Subject], dims: &FlowDims)` | Cuenta un flujo nuevo en `connections` |
| `MinuteRollup::flush` | `fn(&mut self, minute: i64, top_keys: usize) -> RollupBatch` | Cierra el minuto: topes, `~otros` e inventario (§7.2) |
| `Rankings::tick` | `fn(&mut self, now: Instant, wall: SystemTime)` | (extendido) cierra el minuto y emite `AppEvent::Rollup` |

### Repo (hilo de la TUI, único escritor)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Repo::insert_minute_batch` | `fn(&RollupBatch) -> Result<usize>` | Minutos con suma si ya existen e inventario, en una transacción |
| `Repo::upsert_seen` | `fn(items: &[SeenItem], at: SystemTime) -> Result<usize>` | Primera y última vez en `DEVICE_SEEN` |
| `Repo::build_hour` | `fn(hour: i64, top_keys: usize) -> Result<usize>` | Consolida una hora desde sus minutos (§7.3) |
| `Repo::build_day` | `fn(day: LocalDay, top_keys: usize) -> Result<usize>` | Consolida un día local desde sus horas, sin destinos |
| `Repo::pending_hours` | `fn(before: i64) -> Result<Vec<i64>>` | Horas con minutos y sin consolidar |
| `Repo::pending_days` | `fn(today: LocalDay) -> Result<Vec<LocalDay>>` | Días locales con horas y sin consolidar |
| `Repo::purge_history` | `fn(now: SystemTime, ret: &Retention) -> Result<PurgeStats>` | Purga por resolución (§7.4) |
| `Repo::incremental_vacuum` | `fn(max_pages: u32) -> Result<u32>` | Devuelve páginas libres al sistema |
| `Repo::open_session` | `fn(info: &SessionInfo) -> Result<i64>` | Abre la sesión de Almenara |
| `Repo::beat_session` | `fn(id: i64, at: SystemTime) -> Result<()>` | Latido por minuto, haya tráfico o no |
| `Repo::close_session` | `fn(id: i64, at: SystemTime) -> Result<()>` | Cierre con `end_reason = quit` |
| `Repo::close_open_sessions` | `fn() -> Result<usize>` | Cierra como `interrupted` las sesiones sin cierre |

### `history::changes` (eventos)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Changes::presence` | `fn(before: &DeviceRow, seen: bool, now: SystemTime) -> Option<NewEvent>` | `reappeared` al volver a ONLINE |
| `Changes::services` | `fn(device: &DeviceRow, scan: &PortScan, known: &[ServiceRow]) -> Vec<NewEvent>` | `service_new` y `service_gone` (§7.7) |
| `Changes::identity` | `fn(before: &DeviceRow, after: &DeviceRow) -> Vec<NewEvent>` | `os_changed` y `type_changed` |

### `history::reader` y `history::queries` (lector)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `HistoryReader::spawn` | `fn(db_path: &Path, events: Sender<AppEvent>) -> HistoryHandle` | Hilo con conexión de solo lectura |
| `HistoryHandle::query` | `fn(&self, id: u64, q: HistoryQuery)` | Encola una consulta; la respuesta llega por `AppEvent::History` |
| `Queries::series` | `fn(&Connection, subject: SubjectSel, range: Range) -> Result<Series>` | Serie de tráfico con huecos (§7.11) |
| `Queries::top` | `fn(&Connection, subject: SubjectSel, dim: Dimension, range: Range, n: usize) -> Result<Vec<TopRow>>` | «Más tráfico» del rango |
| `Queries::window_ranking` | `fn(&Connection, dim: Dimension, w: HistWindow, now: i64) -> Result<RankingResult>` | Ranking de 1 h y 24 h para Tráfico (§7.5) |
| `Queries::who_uses` | `fn(&Connection, dim: Dimension, key: &str, w: HistWindow, now: i64) -> Result<Vec<DeviceShare>>` | «¿Quién lo usa?» en 1 h y 24 h |
| `Queries::timeline` | `fn(&Connection, f: &EventFilter, range: Range, page: Page) -> Result<Vec<TimelineItem>>` | Eventos y sesiones del rango |
| `Queries::presence` | `fn(&Connection, device_id: i64, range: Range) -> Result<Vec<PresenceSpan>>` | Tramos presente, ausente y sin datos (§7.8) |
| `Queries::inventory` | `fn(&Connection, device_id: i64) -> Result<Inventory>` | `DEVICE_SEEN` + puertos de `DEVICE_SERVICES` (§7.9) |
| `Queries::coverage` | `fn(&Connection, range: Range) -> Result<Vec<Gap>>` | Huecos del rango (§7.6) |
| `Queries::last_event` | `fn(&Connection) -> Result<Option<TimelineItem>>` | «Último evento» de Equipos al arrancar |
| `Queries::db_stats` | `fn(&Connection) -> Result<DbStats>` | Tamaño de la BD y del WAL, inicio de los datos y cobertura de 30 días |

### Otros

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Instance::acquire` | `fn(db_path: &Path) -> Result<InstanceLock, AlreadyRunning>` | Bloqueo de instancia única (§7.13) |
| `Synthetic::generate` | `fn(conn: &Connection, profile: &SyntheticProfile) -> Result<SyntheticStats>` | Histórico sintético para pruebas y mediciones (§7.14) |
| `config::load` | `fn(path: Option<&Path>) -> Result<Config>` | (extendido) `[history]` |

---

## 6. Interfaz de Usuario

### Mapa de navegación (novedades de F5)

```
Equipos ──► + línea «Último evento»                                  (F5)
   └─ Enter ──► Detalle (F3/F4) + histórico 24 h ⇄ 7 días (w),       (F5)
                presencia e inventario

Tráfico ──[w]──► 60 s → 5 min → 1 h → 24 h → sesión                  (F5)
   └─ Enter en 1 h/24 h ──► «¿Quién lo usa?» desde el histórico      (F5)

Histórico (4) ──► sujeto (e) · rango (w) · foco (Tab)                (F5)
   ├─ e ──► selector: toda la red · este equipo · equipos (con /)
   ├─ w ──► 24 h → 7 días → 30 días → 1 año
   ├─ gráfica ──► cursor < > con fecha y valores en texto
   ├─ Más tráfico ──► Enter en un equipo ──► Detalle de equipo
   └─ Eventos ──► f filtro · / búsqueda · Enter ──► Detalle de equipo

Config ──► + [history], tamaño de la BD y cobertura                  (F5)
Ayuda  ──► + teclas del histórico y privacidad                       (F5)
```

### Mockup 1 — Histórico de la red, 7 días (80×24)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Histórico · Toda la red · 7 días              [e] equipo · [w] 7 días      │
├────────────────────────────────────────────────────────────────────────────┤
│ ↓ 48.2 GB · ↑ 3.1 GB · puntos de 3 h · máximo: dom 21:00 (2.5 GB)          │
│  2.5 G│                               █                                    │
│       │               ▁       ▄      ▃█                                    │
│       │      ▃▇      ▅█      ▇█    ▁▂██      ▃▆      ▄█                    │
│       │▁ ▁▄▅▆██▁ ▁▄▆▇██░░░▅▇███▁▁▂▆████▁ ▁▃▅▆██▁ ▁▄▆▆██░░░▆                │
│     0 └┬───────┬───────┬───────┬───────┬───────┬───────┬───────            │
│        jue 5   vie 6   sáb 7   dom 8   lun 9   mar 10  mié 11              │
│ ░ sin datos · [<>] dom 8 nov 21:00: ↓ 2.4 GB · ↑ 96 MB                     │
├── Más tráfico · 7 días ──────────────────┬── Eventos ──────────────────────┤
│ Equipos                                  │ mié 10:12 iPhone-Marta vuelve   │
│  chromecast-sala   21.4 GB   42 %        │ mié 08:01 Almenara arrancada    │
│  laptop-juan       12.0 GB   23 %        │ mar 23:40 Almenara cerrada      │
│ Apps                                     │ mar 19:02 tv-sala: iot → tv     │
│  YouTube           18.9 GB   37 %        │ lun 12:30 nas: cierra 445/tcp   │
│  Netflix            9.6 GB   19 %        │ lun 09:15 192.168.1.201: nuevo  │
├──────────────────────────────────────────┴─────────────────────────────────┤
│ Datos desde 12 oct · cobertura en 7 días: 89 % · BD 212 MB                 │
└─[e]equipo [w]rango [Tab]panel [<>]cursor [f]filtrar [/]buscar [?]ayuda─────┘
```

### Mockup 2 — Histórico de un equipo, 30 días, eventos filtrados (80×24)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Histórico · [●] tv-sala · 30 días            [e] equipo · [w] 30 días      │
├────────────────────────────────────────────────────────────────────────────┤
│ ↓ 61.0 GB · ↑ 1.2 GB · por día · máximo: sáb 31 oct (4.8 GB)               │
│  4.8 G│                                    ██                              │
│       │        ▂▂▄▄            ▃▃          ██▁▁▂▂          ▂▂              │
│       │▂▂▄▄  ▆▆██████▂▂▄▄▂▂▆▆████▆▆  ▄▄▂▂▆▆██████▂▂▄▄▂▂▄▄████▆▆▂▂          │
│       │████████████████████████████░░████████████████████████████▄▄        │
│     0 └┬─────────────┬─────────────┬─────────────┬─────────────┬───        │
│        13 oct        20 oct        27 oct        3 nov         10 nov      │
│ ░ sin datos · foco: Eventos ([Tab])                                        │
├── Más tráfico · 30 días ───────────────┬── Eventos · filtro: identidad ────┤
│ Apps                                   │ 10 nov 19:02 tipo: iot → tv       │
│  Netflix          31.0 GB   50 %       │ 10 nov 19:02 SO: linux → android  │
│  YouTube          18.2 GB   29 %       │ 28 oct 08:30 IP: .44 → .45        │
│ Destinos                               │ 21 oct 22:10 nombre: tv → tv-sala │
│  nflxvideo.net    30.1 GB              │                                   │
│  googlevideo.com  17.9 GB              │                                   │
│ Países: US 72 % · NL 21 % · ES 4 %     │                                   │
├────────────────────────────────────────┴───────────────────────────────────┤
│ Datos desde 12 oct · cobertura en 30 días: 91 %                            │
└─[f]filtro [/]buscar [Enter]detalle [Tab]panel [w]rango [?]ayuda────────────┘
```

### Mockup 3 — Tráfico por destino, ventana de 24 h (80×24)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Ranking por destino · ventana 24 h          [g] destino · [w] 24 h         │
├────────────────────────────────────────────────────────────────────────────┤
│ #  Destino             Organización · país  ↓ bajada  ↑ subida  Equipos    │
│ 1  googlevideo.com     Google LLC · US      14.2 GB   210 MB    3          │
│ 2  nflxvideo.net       Netflix · NL         9.6 GB    95 MB     1          │
│ 3  steamcontent.com    Valve · ES           6.1 GB    40 MB     1          │
│ 4  nas-synology (LAN)  red local            3.3 GB    1.1 GB    2          │
│ 5  icloud.com          Apple Inc. · US      880 MB    2.4 GB    3          │
│ 6  whatsapp.net        Meta · IE            410 MB    380 MB    4          │
│ 7  142.250.200.14      Google LLC · ES      300 MB    12 MB     1          │
│ 8  otros (34)          —                    3.6 GB    360 MB    7          │
│                                                                            │
│ Total 24 h: ↓ 38.4 GB · ↑ 4.6 GB · sin identificar: 4 %                    │
│ Minutos cerrados hasta 10:41 · huecos: 8 h 21 min sin datos                │
└─[g]agrupar [w]ventana [Enter]¿quién? [s]ordenar [/]buscar [?]ayuda─────────┘
```

### Mockup 4 — Detalle de equipo con histórico, presencia e inventario (≥ 100 columnas)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ───────────────────────────┐
│ Equipos (9)          │ Detalle: iPhone-Marta (192.168.1.57)                      ▲ más arriba    │
│ ──────────────────── │ ────────────────────────────────────────────────────────────────────────  │
│  [⌂] router    14.5M │ Histórico · 24 h        ↓ 2.1 GB · ↑ 340 MB         [w] 24 h ⇄ 7 días     │
│  [▣] nas        6.0M │  ▁▁▁▁▁▁▁▁▁▁▂▃▄▄▅▆▆█▇▇▆▅▄▃▂▂░░░░░░░░░░░░░░░░▁▁▁▁▃▂  tráfico                │
│ ▶[▯] iPhone     165K │  ··········████████████████░░░░░░░░░░░░░░░░····██  presencia              │
│  [▶] chromecast 902K │  11:00       17:00       23:00       05:00                                │
│  [▣] laptop     1.7M │                                                                           │
│  [●] tv-sala      4K │ Presencia · 7 días                                                        │
│  [P] hp-laser      0 │          0     6     12    18                                             │
│  [?] 192.168…      0 │   jue 5  ███████·········████████                                         │
│  ○   iPad          0 │   vie 6  ████████········████████                                         │
│                      │   sáb 7  ░░░░░░░░░███████████████                                         │
│                      │   dom 8  ████████████████████████                                         │
│                      │   lun 9  ███████·········███████·                                         │
│                      │   mar 10 ████████········████████                                         │
│                      │   mié 11 ░░░░░░░░··█                                                      │
│                      │ █ presente · · ausente · ░ sin datos (Almenara cerrada)                   │
│                      │                                                                           │
│                      │ Visto en este equipo (desde 12 oct)                                       │
│                      │  Apps (23) · nuevas en 7 días: Temu (ayer)                                │
│                      │  Organizaciones (14): Meta, Apple, Google, Akamai, Amazon…                │
│                      │  Países (6): US IE NL ES DE SG · Clientes TLS (JA4): 3                    │
│                      │  Puertos abiertos: 62078/tcp (desde 3 oct)                                │
└─[hjkl]mover [Tab]panel [w]24 h/7 días [Esc]cerrar [v]conexión [?]ayuda───────────────────────────┘
```

### Mockup 5 — Equipos y Config (fragmentos)

```
│ ○    192.168.1.66    iPad              Apple         ─           offline   │
│                                                                            │
│ Último evento: hace 2 min · iPhone-Marta vuelve a estar en línea           │
│ 12 equipos · 11 online · 1 offline   modo: privilegiado                    │
└─[f]filtrar [/]buscar [g]agrupar [Enter]detalle [?]ayuda────────────────────┘
```

```
│ [history]                                                                  │
│   enabled          = true                                                  │
│   minute_days      = 2      (destinos: 2 h)                                │
│   hour_days        = 90     destination_days = 30                          │
│   day_days         = 730    top_keys         = 20                          │
│   max_db_mb        = 1024                                                  │
│                                                                            │
│ Base de datos: 212 MB (+ WAL 4 MB) · datos desde el 12 oct 2026            │
│ Última purga: hace 12 min (4 320 filas) · cobertura en 30 días: 91 %       │
└────────────────────────────────────────────────────────────────────────────┘
```

### Notas de UX

- **Histórico.** `e` abre el selector de sujeto (toda la red, este equipo y los equipos por nombre, con búsqueda `/`); `w` cicla el rango 24 h → 7 días → 30 días → 1 año; `Tab` pasa el foco entre gráfica, «Más tráfico» y «Eventos». El sujeto y el rango no se guardan: cada arranque empieza en «Toda la red · 24 h».
- **Gráfica.** Las barras son el tráfico total (bajada + subida) de cada punto; la cabecera da la bajada y la subida del rango y el máximo. Con el foco en la gráfica, `<` y `>` mueven un cursor que muestra en texto la fecha del punto, la bajada y la subida (accesible sin leer la forma de las barras).
- **Huecos.** Un punto sin datos se dibuja con `░` y la leyenda dice «sin datos». Nunca se interpola. El tiempo que aún no ha pasado se deja en blanco.
- **Más tráfico.** En «Toda la red»: equipos y apps con su volumen y su porcentaje del total del rango (un flujo LAN↔LAN cuenta para los dos equipos, así que los porcentajes de equipos pueden sumar más de 100 %). En un equipo: apps, destinos, organizaciones y países. Los destinos solo aparecen en rangos de hasta 30 días; en «1 año» se avisa «Destinos: solo los últimos 30 días».
- **Eventos.** Más recientes primero, con las sesiones de Almenara intercaladas («Almenara arrancada», «cerrada», «interrumpida»). `f` cicla el filtro: todos → altas y presencia → identidad → servicios → Almenara. `/` busca por nombre de equipo. `Enter` sobre un evento o sobre un equipo de «Más tráfico» abre su detalle.
- **Tráfico.** `w` cicla 60 s → 5 min → 1 h → 24 h → sesión. En 1 h y 24 h las cifras son volúmenes (MB, GB), no velocidades; el pie dice «Minutos cerrados hasta HH:MM» y los huecos de la ventana. La columna Conexiones cuenta las conexiones abiertas en la ventana. Con el histórico desactivado, `w` se salta 1 h y 24 h.
- **Detalle de equipo.** Bloque «Histórico» con una fila de tráfico y otra de presencia sobre el mismo eje (`w` alterna 24 h y 7 días; puntos de 30 min y de 3 h), la presencia de 7 días en una rejilla de 7 filas × 24 horas y el bloque «Visto en este equipo» con recuentos y lo nuevo de los últimos 7 días. El panel se desplaza con j/k (F4).
- **Presencia.** `█` presente, `·` ausente, `░` sin datos. Una celda es presente si el equipo estuvo presente en algún momento de ella.
- **Equipos.** Línea «Último evento: hace N min · <equipo> <qué pasó>» encima de la barra de estado; se oculta si no cabe.
- **Config.** Muestra `[history]`, el tamaño de la BD y del WAL, la fecha de inicio de los datos, la última purga y la cobertura de los últimos 30 días; en rojo y con texto («por encima del límite») si la BD supera `max_db_mb`.
- **Mensajes.** Sin datos en el rango: «Sin datos en este rango». Histórico desactivado: «El histórico está desactivado ([history] enabled = false)»; la línea de tiempo de eventos sigue disponible. Mientras llega una consulta: «Cargando…».
- **Accesibilidad.** Nada depende solo del color: huecos, presencia y ausencia tienen carácter propio y leyenda; los valores exactos se leen con el cursor.

---

## 7. Lógica de Negocio

### 7.1 Sujetos, dimensiones y claves

**Sujetos.** `device` (un equipo de la LAN, con su `device_id`), `host` (el propio equipo, la fila `[host]` de ADR-32), `other` (tráfico sin equipo local atribuible: `[?]`, `[broadcast]`) y `network` (la red entera, solo en `total`).

**Atribución** (la misma que ya usan F3 y F4):
- **Dimensión `total`**: cada equipo local (o `host`) que participa en el flujo suma sus bytes desde su punto de vista (bajada = lo que recibe, subida = lo que envía), como el ranking por equipo de F3. Un flujo LAN↔LAN cuenta para los dos. El sujeto `network` suma cada flujo una sola vez, con bajada y subida según el rol (F4).
- **Resto de dimensiones**: cada flujo cuenta una sola vez, para el sujeto de su columna «Equipo» de F4 (lado cliente o lado LAN; `host` en los del propio equipo), con bajada y subida según el rol. Así, el top de la red no cuenta dos veces el tráfico LAN↔LAN.
- **`process`**: solo para `host` (F4).

**Claves.**

| Dimensión | Clave | Claves especiales |
|-----------|-------|-------------------|
| `total` | `''` | — |
| `app` | Clave del catálogo (`youtube`) | `~sin_identificar` |
| `category` | Clave de categoría (`streaming`, `lan`) | `~sin_identificar` |
| `destination` | Dominio registrable, IP remota o `lan:<device_id>` (F4 §7.10) | — |
| `protocol` | `app_protocol` de F4, o `tcp`/`udp`/`icmp`/`other` | — |
| `process` | Nombre del proceso, sin pid | `~desconocido` |
| `org` | Organización de DB-IP (`Google LLC`) | `~lan`, `~desconocido` |
| `country` | Código ISO 3166-1 (`US`) | `~lan`, `~desconocido` |

Todas las dimensiones salvo `total` admiten además `~otros` (lo que pasa del tope). Con las claves especiales, la suma de las claves de una dimensión es el total del sujeto en esa dimensión. La TUI las muestra como «Sin identificar», «Red local», «Desconocido» y «otros (N)».

### 7.2 Acumuladores del minuto y topes

```python
ESPECIALES = {'~sin_identificar', '~lan', '~desconocido'}
INVENTARIO = {'app', 'category', 'org', 'country'}

def flush(acc, minuto, top_keys, ja4_vistos):
    """acc: {(sujeto, device_id, dimensión, clave): [bajada, subida, conexiones]}"""
    grupos = defaultdict(list)
    for (suj, dev, dim, clave), c in acc.items():
        grupos[(suj, dev, dim)].append((clave, c))
    filas, vistos = [], set(ja4_vistos)          # ja4_vistos: {(device_id, 'ja4', huella)}
    for (suj, dev, dim), items in grupos.items():
        normales = sorted([i for i in items if not i[0].startswith('~')],
                          key=lambda i: i[1][0] + i[1][1], reverse=True)
        if suj == 'device' and dim in INVENTARIO:
            vistos |= {(dev, dim, clave) for clave, _ in normales}   # antes del tope
        if dim == 'total':
            filas += [(minuto, suj, dev, dim, clave, *c) for clave, c in items]
            continue
        especiales = [i for i in items if i[0] in ESPECIALES]
        resto = [c for clave, c in items if clave == '~otros'] + [c for _, c in normales[top_keys:]]
        filas += [(minuto, suj, dev, dim, clave, *c) for clave, c in especiales + normales[:top_keys]]
        if resto:
            filas.append((minuto, suj, dev, dim, '~otros', *map(sum, zip(*resto))))
    acc.clear()
    return RollupBatch(minuto, filas, vistos)
```

- El tope (`top_keys`, 20 por defecto) se aplica por sujeto, dimensión y cubo. Las claves especiales no cuentan para el tope y nunca se funden en `~otros`.
- `connections` cuenta los flujos cuyo primer paquete cae en el minuto, con la etiqueta que tienen al cerrarse el minuto (las etiquetas suben de fuerza en los primeros paquetes, F4).
- Con `[history].enabled = false`, el agregador no acumula y no hay lotes.

### 7.3 Consolidación de horas y días

```python
def build_hour(db, hora, top_keys):
    filas = db.query("""
        SELECT subject, device_id, dimension, key,
               SUM(bytes_down), SUM(bytes_up), SUM(connections)
          FROM TRAFFIC_ROLLUP_MINUTE
         WHERE bucket >= :h AND bucket < :h + 3600
         GROUP BY subject, device_id, dimension, key""", h=hora)
    with db.transaction():                                   # idempotente
        db.execute("DELETE FROM TRAFFIC_ROLLUP_HOUR WHERE bucket = :h", h=hora)
        db.insert_many("TRAFFIC_ROLLUP_HOUR", aplicar_topes(hora, filas, top_keys))

def build_day(db, dia, top_keys):                            # dia = fecha local
    desde, hasta = limites_utc(dia)                          # 23, 24 o 25 horas
    filas = db.query("""
        SELECT subject, device_id, dimension, key,
               SUM(bytes_down), SUM(bytes_up), SUM(connections)
          FROM TRAFFIC_ROLLUP_HOUR
         WHERE bucket >= :desde AND bucket < :hasta AND dimension <> 'destination'
         GROUP BY subject, device_id, dimension, key""", desde=desde, hasta=hasta)
    with db.transaction():
        db.execute("DELETE FROM TRAFFIC_ROLLUP_DAY WHERE bucket = :d", d=aaaammdd(dia))
        db.insert_many("TRAFFIC_ROLLUP_DAY", aplicar_topes(aaaammdd(dia), filas, top_keys))
```

- `aplicar_topes` sigue el criterio del §7.2: claves especiales siempre, las `top_keys` normales con más bytes y el resto, sumado al `~otros` que ya hubiera, en `~otros`.
- **Pendientes.** Una hora está pendiente si tiene minutos y no tiene filas en `TRAFFIC_ROLLUP_HOUR` (anterior a la hora en curso); un día, si tiene horas y no tiene filas en `TRAFFIC_ROLLUP_DAY` (anterior al día local en curso). Se construyen al arrancar y tras cada lote, en tandas de 10 por segundo.
- **Día local.** Una hora pertenece al día local que contiene su inicio. `limites_utc` calcula la medianoche local con `localtime_r`. En zonas con desfase de media hora, la medianoche cae a mitad de una hora UTC y esa hora cuenta entera para el día que contiene su inicio.
- Un minuto repetido por un salto atrás del reloj suma en su cubo (upsert); un salto adelante deja un hueco.

### 7.4 Retención y purga

| Resolución | Retención por defecto | Destinos | Clave de configuración |
|------------|-----------------------|----------|------------------------|
| Minuto | 48 h | 2 h (fijo) | `minute_days = 2` |
| Hora | 90 días | 30 días | `hour_days = 90`, `destination_days = 30` |
| Día | 2 años | nunca | `day_days = 730` |
| Inventario (`DEVICE_SEEN`) | 2 años desde `last_seen` | nunca | `day_days` |
| Sesiones (`APP_SESSIONS`) | 2 años | — | `day_days` |
| Eventos (`DEVICE_EVENTS`) | 90 días (F1) | — | `events_retention_days` de F1 |

```sql
-- Cada hora, después de consolidar. :sin_consolidar = inicio de la primera hora pendiente.
DELETE FROM TRAFFIC_ROLLUP_MINUTE
 WHERE bucket < :ahora - :minute_days * 86400 AND bucket < :sin_consolidar;
DELETE FROM TRAFFIC_ROLLUP_MINUTE
 WHERE dimension = 'destination' AND bucket < :ahora - 7200 AND bucket < :sin_consolidar;
DELETE FROM TRAFFIC_ROLLUP_HOUR WHERE bucket < :ahora - :hour_days * 86400;
DELETE FROM TRAFFIC_ROLLUP_HOUR
 WHERE dimension = 'destination' AND bucket < :ahora - :destination_days * 86400;
DELETE FROM TRAFFIC_ROLLUP_DAY WHERE bucket < :dia_limite;          -- AAAAMMDD local
DELETE FROM DEVICE_SEEN WHERE last_seen < :limite_dias;
DELETE FROM APP_SESSIONS WHERE ended_at < :limite_dias;
PRAGMA incremental_vacuum(2000);
```

- `destination_days = 0` no guarda destinos por hora (solo los minutos de 2 h, que hacen falta para la ventana de 1 h y para construir la hora).
- La purga anota cuándo corrió y cuántas filas borró (`PurgeStats`) para Config.

### 7.5 Ventanas de 1 h y 24 h

```python
def window_ranking(db, dim, ventana, ahora_min):      # ahora_min = inicio del minuto en curso
    if ventana == '1h':
        tramos = [('TRAFFIC_ROLLUP_MINUTE', ahora_min - 3600, ahora_min)]
    else:                                              # '24h'
        hora = ahora_min - ahora_min % 3600
        tramos = [('TRAFFIC_ROLLUP_HOUR', hora - 23 * 3600, hora),
                  ('TRAFFIC_ROLLUP_MINUTE', hora, ahora_min)]
    dimension = 'total' if dim == 'device' else dim    # equipo = total por sujeto
    claves = defaultdict(lambda: [0, 0, 0, set()])     # bajada, subida, conexiones, sujetos
    for tabla, desde, hasta in tramos:
        for suj, dev, clave, d, u, c in db.query(f"""
                SELECT subject, device_id, key, bytes_down, bytes_up, connections
                  FROM {tabla}
                 WHERE bucket >= ? AND bucket < ? AND dimension = ?
                   AND subject <> 'network'""", desde, hasta, dimension):
            k = (suj, dev) if dim == 'device' else clave
            claves[k][0] += d; claves[k][1] += u; claves[k][2] += c
            claves[k][3].add((suj, dev))
    filas = sorted(claves.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:50]
    return filas, sin_identificar(db, tramos)          # % con app = '~sin_identificar'
```

- Solo minutos cerrados: la ventana llega hasta el último minuto escrito y se refresca tras cada lote.
- La ventana de 24 h abarca desde el inicio de la hora de reloj de hace 23 h (entre 23 y 24 h).
- «Equipos» cuenta sujetos distintos en la ventana; «Conexiones», las abiertas en la ventana.
- «¿Quién lo usa?» en 1 h y 24 h (`Queries::who_uses`) suma la clave pedida por sujeto con los mismos tramos.

### 7.6 Sesiones y huecos

```python
def huecos(sesiones, desde, hasta, ahora, de_trafico=True):
    """De tráfico: sin sesión o con sesión sin captura. De presencia: solo sin sesión."""
    validas = [s for s in sesiones if s.capture or not de_trafico]
    cubierto = unir([(max(s.started_at, desde), min(s.ended_at or ahora, hasta))
                     for s in validas])
    return complemento(cubierto, desde, hasta)
```

- El latido (`Repo::beat_session`) se da cada minuto desde el temporizador de la TUI, haya tráfico o no.
- Una sesión sin cierre se cierra en el arranque siguiente con `ended_at = last_beat` (pérdida máxima: un minuto).
- Un punto de una gráfica es hueco si más de la mitad de su tiempo no tiene cobertura de tráfico.
- **Cobertura** de un rango = tiempo con cobertura de tráfico / tiempo transcurrido del rango.

### 7.7 Eventos nuevos

| Evento | Cuándo | Detalles (JSON) |
|--------|--------|-----------------|
| `reappeared` | Un equipo OFFLINE vuelve a verse (transición OFFLINE → ONLINE de F1) | `away_since` (`last_seen` anterior), `away_s` |
| `service_new` | Un escaneo de puertos ve abierto un puerto que no estaba en `DEVICE_SERVICES`, o que estaba CERRADO | `port`, `protocol`, `service`, `reopened` |
| `service_gone` | Un escaneo de puertos ve cerrado un puerto que estaba abierto | `port`, `protocol`, `service` |
| `os_changed` | `os_family` cambia entre dos valores no nulos | `before`, `after`, `os_source` |
| `type_changed` | El `device_type` automático cambia entre dos valores conocidos (no `unknown`) | `before`, `after` |
| `disappeared` (F1, ampliado) | Sin cambios de regla | gana `last_seen` |

- Los eventos de servicios solo salen de escaneos de puertos reales (F2: bajo demanda, al descubrir el equipo, al cambiar de IP o MAC o con `r`). Un puerto que pasa a STALE por tiempo no genera evento.
- Sin eventos de servicios en el primer escaneo de un equipo (es su línea base) ni con `passive_only` (no hay escaneo).
- El override manual de tipo (`t`, F2) no genera `type_changed`: es una acción de la persona.
- Retención: la de los eventos de F1 (`events_retention_days`, 90 días).

### 7.8 Presencia

```python
def presencia(eventos, sesiones, desde, hasta, ahora):
    """Tramos (inicio, fin, estado): 'presente', 'ausente' o 'sin_datos'."""
    tramos = []
    for s in sesiones:                                  # con o sin captura: basta el escaneo
        ini, fin = max(s.started_at, desde), min(s.ended_at or ahora, hasta)
        if ini >= fin:
            continue
        estado, t = estado_previo(eventos, s.started_at), ini   # None si el equipo no existía
        for ev in [e for e in eventos if ini <= e.at < fin]:    # new, disappeared, reappeared
            if ev.type == 'disappeared':
                nuevo, cambio = 'ausente', max(ev.details.get('last_seen', ev.at), s.started_at)
            else:
                nuevo, cambio = 'presente', ev.at
            if estado and cambio > t:
                tramos.append((t, cambio, estado))
            estado, t = nuevo, max(t, cambio)
        if estado:
            tramos.append((t, fin, estado))
    return rellenar(tramos, desde, hasta, 'sin_datos')
```

- Un equipo que se fue mientras Almenara estaba cerrada recibe `disappeared` unos minutos después del arranque, con un `last_seen` anterior a la sesión: se marca ausente desde el inicio de la sesión.
- Fuera de las sesiones no se dice nada: «sin datos».
- La presencia se calcula al vuelo desde los eventos; no hay tabla de intervalos. Su alcance es la retención de los eventos (90 días).

### 7.9 Inventario por equipo

- Cada lote trae, para los sujetos `device`, las apps, categorías, organizaciones y países vistos en el minuto (antes de los topes) y las huellas JA4 de los flujos en los que el equipo es cliente.
- `Repo::upsert_seen` inserta lo nuevo con `first_seen = last_seen = minuto` y actualiza `last_seen` de lo conocido.
- No entran las claves especiales, los destinos (privacidad) ni el propio equipo (`host` no está en `DEVICES`).
- Como el resto de dimensiones, el inventario sigue la atribución de F4: es lo que el equipo usa como cliente o lado LAN. Lo que sirve se ve en sus puertos abiertos, que salen de `DEVICE_SERVICES` con su `first_seen`.
- El detalle muestra recuentos por tipo, lo nuevo de los últimos 7 días (por `first_seen`) y la fecha de inicio del inventario (primer `first_seen` del equipo).

### 7.10 Lector del histórico

- Hilo propio con una conexión abierta con `SQLITE_OPEN_READ_ONLY` y `PRAGMA query_only = ON`; se lanza después de las migraciones, con la conexión de escritura ya abierta (así existen los ficheros `-wal` y `-shm` que necesita una conexión de solo lectura en WAL).
- `HistoryQuery`: `Series`, `Top`, `WindowRanking`, `WhoUses`, `Timeline`, `Presence`, `Inventory`, `Coverage`, `LastEvent` y `DbStats`, cada una con un identificador creciente.
- Un `progress_handler` corta la consulta que pasa de 2 s y devuelve un error; la vista lo muestra y sigue funcionando.
- La TUI guarda por vista el identificador de la última petición y descarta las respuestas con otro identificador.
- El lector nunca escribe. Las estadísticas de purga (última ejecución y filas borradas) las aporta el hilo de la TUI.

### 7.11 Gráficas y rangos

| Rango | Fuente | Punto | Puntos |
|-------|--------|-------|--------|
| 24 h | Minutos | 30 min | 48 |
| 7 días | Horas (más los minutos de la hora en curso) | 3 h | 56 |
| 30 días | Días (más las horas del día en curso) | 1 día | 30 |
| 1 año | Días | 1 semana (lunes a domingo) | 52–53 |

- Las barras son bajada + subida de cada punto; la cabecera da la bajada y la subida del rango y el punto máximo. Unidades: B, KB, MB, GB (base 1000, como F3).
- «Más tráfico» suma la dimensión pedida en el rango: para «Toda la red», sujetos `device`, `host` y `other`; para un equipo, solo ese sujeto.
- El sujeto «Toda la red» usa `network` en la gráfica y la suma de los sujetos en los tops.

### 7.12 Configuración y validación

```toml
[history]
enabled          = true   # guardar histórico (rollups e inventario)
minute_days      = 2      # minutos: 48 h (los destinos, 2 h fijas)
hour_days        = 90     # horas
day_days         = 730    # días, inventario y sesiones (2 años)
destination_days = 30     # destinos por hora (0 = no guardarlos)
top_keys         = 20     # claves por sujeto, dimensión y cubo; el resto, «otros»
max_db_mb        = 1024   # aviso si la BD lo supera
```

- Rangos válidos: `minute_days` 1–7; `hour_days` 7–365; `day_days` 30–3650; `destination_days` 0–`hour_days`; `top_keys` 5–100; `max_db_mb` ≥ 64.
- Un valor inválido se avisa una vez y usa el valor por defecto; la configuración nunca aborta el arranque (regla transversal de F4).
- La plantilla de configuración por defecto incluye `[history]`.

### 7.13 Instancia única

- `Instance::acquire` abre `<db_path>.lock` (`~/.local/share/almenara/data.db.lock`) y pide `flock(LOCK_EX | LOCK_NB)`; si lo consigue, escribe su PID.
- Si otra instancia lo tiene, la segunda muestra «Almenara ya está en marcha (PID n). Usa esa sesión (p. ej. `tmux attach`).» y sale con código 1 sin abrir la BD.
- El kernel libera el bloqueo si el proceso muere: no hay bloqueos huérfanos que limpiar.

### 7.14 Histórico sintético (pruebas y mediciones)

- `Synthetic::generate` escribe directamente minutos (48 h), horas (90 días), días (2 años), inventario, eventos y sesiones con un perfil determinista (semilla fija).
- Perfil de referencia: 30 equipos (15 activos por minuto de media), ciclo diario de uso, apps y destinos del catálogo de F4, un 10 % del tiempo sin sesión y los topes por defecto.
- La prueba ignorada `medir_historial` (`cargo test --release -- --ignored medir_historial`) genera el perfil en una BD temporal y anota tamaño, filas por tabla, tiempo de construcción de una hora y de un día, purga y consultas de 24 h, 7 días, 30 días y 1 año. Sus cifras van al informe de implementación.
- Así, las mediciones de F5 no dependen de `CAP_NET_RAW` (respuesta 1c).

---

## 8. Requisitos No Funcionales

### Seguridad

- El lector abre la BD en solo lectura (`SQLITE_OPEN_READ_ONLY` y `query_only`): un fallo del lector no puede escribir.
- Todas las consultas usan parámetros: las claves (dominios, organizaciones, procesos) vienen de la red y nunca se concatenan en el SQL.
- `[history]` se valida campo a campo; un fichero malicioso no puede bloquear el arranque ni pedir retenciones absurdas.
- Instancia única: dos procesos no escriben a la vez en la misma BD.
- Sin puertos nuevos ni accesos a red.

### Protección de datos (RGPD)

- Uso personal y doméstico (exención doméstica del art. 2.2.c del RGPD); aun así, la fase aplica minimización. Si en la casa viven más personas, conviene que sepan que Almenara registra el uso de la red.
- Se guardan agregados: bytes y conexiones por equipo y dimensión. Nunca contenido, nunca nombres completos (el destino es el dominio registrable, la IP o el equipo de la LAN) y sin registro de conexiones.
- **Destinos por equipo** (historial de navegación a nivel de dominio): por minuto 2 h y por hora 30 días; nunca en días ni en el inventario.
- **Presencia** (la de un móvil es la de su dueño): se deriva de los eventos y dura lo que ellos, 90 días.
- Apps, categorías, organizaciones y países por equipo: hasta 2 años, por día.
- Desactivable con `[history].enabled = false`; retenciones configurables; aviso en Ayuda de qué se guarda y cuánto tiempo.
- Todo es local: nada sale del equipo. Para borrar el histórico basta con cerrar Almenara y borrar la BD, o bajar las retenciones.
- Logs: dominios y claves del histórico solo a nivel `debug` (regla de F4).

### Backups y recuperación

- Sin copias automáticas (respuesta 12a). El README explica cómo copiar la BD con Almenara en marcha (`sqlite3 data.db ".backup copia.db"` o `VACUUM INTO`, seguros con WAL) o con Almenara cerrada (copiar `data.db`).
- Perder la BD es perder el histórico; el resto de datos se reconstruye con el escaneo y la captura.
- Un lote que no se puede escribir se reintenta hasta 10 minutos antes de descartarse con aviso.

### Rendimiento

- Escritura del lote del minuto ≤ 10 ms con 50 equipos.
- Construcción de una hora ≤ 50 ms y de un día ≤ 100 ms; las pendientes, en tandas de 10 por segundo.
- Purga + `incremental_vacuum` ≤ 100 ms por ejecución.
- Consultas del lector ≤ 200 ms hasta 30 días y ≤ 500 ms en 1 año, con 2 años de histórico sintético.
- BD ≤ 300 MB con la retención por defecto y el perfil de referencia (30 equipos); aviso a partir de `max_db_mb`.
- Memoria añadida ≤ 16 MB (acumuladores ≤ 20 000 entradas, 10 lotes pendientes como mucho, resultados del lector).
- `MinuteRollup::add` ≥ 1 millón de llamadas por segundo en un núcleo (se llama por flujo y segundo, no por paquete).
- Render sin cambios: ≤ 16 ms en 80×24 y ≤ 33 ms en 120×40, también con Histórico abierto (el render no consulta la BD).

### Accesibilidad

- Sin cambios de nivel (WCAG 2.1 AA en lo aplicable a TUI). Huecos, presencia y ausencia con carácter propio y leyenda; valores exactos de la gráfica en texto con el cursor; nada depende solo del color; Histórico usable en 80×24.

---

## 9. Integraciones

- Sin integraciones externas nuevas.
- **SQLite** (empaquetado por `rusqlite`): tablas `WITHOUT ROWID`, upsert `ON CONFLICT DO UPDATE`, `auto_vacuum = INCREMENTAL` e `incremental_vacuum`, conexiones de solo lectura en WAL y `progress_handler`.
- **Sistema:** `flock` y `localtime_r` de libc para la instancia única y la hora local.
- **Formatos:** ninguno nuevo. La exportación del histórico (CSV) queda para F7.

---

## 10. Decisiones Técnicas (ADR-lite)

La numeración de ADR es única en todo el proyecto: F4 llegó a la ADR-52 y F5 empieza en la ADR-53.

**ADR-53 · Rollups desde los contadores completos del agregador, escritos por lotes en el hilo de la TUI (vs. calcularlos desde `CONNECTIONS`, vs. un segundo escritor)**
`CONNECTIONS` es caliente y se purga: no sirve para reconstruir el pasado. El agregador ya tiene los contadores por flujo y segundo de F4; cerrarlos cada minuto cuesta poco y no depende del top 50 que se publica. Un segundo escritor rompería ADR-35; un lote por minuto en el hilo de la TUI es barato.

**ADR-54 · Tres resoluciones con retención propia y tope de claves con `~otros` (vs. sin tope, vs. solo horas)**
Minutos para las ventanas cortas, horas para semanas, días para años. Sin tope, un equipo que habla con cientos de destinos multiplica las filas; con 20 claves y `~otros`, los totales siguen siendo exactos y el tamaño queda acotado. Solo horas impediría la ventana de 1 h.

**ADR-55 · Una tabla por resolución con sujeto, dimensión y clave (vs. una tabla por dimensión)**
Tres tablas iguales, en vez de veinticuatro, simplifican la consolidación, la purga y las consultas. El sujeto `network` evita contar dos veces el tráfico LAN↔LAN en la gráfica de la red. `device_id = 0` para los sujetos que no son equipos obliga a renunciar a la clave ajena; el DAO borra los rollups de un equipo borrado.

**ADR-56 · Cubos como enteros; horas en UTC y días por fecha local (excepción a ADR-34)**
Las tablas de rollups son las más grandes del proyecto: un entero ocupa de 4 a 6 bytes frente a los 20 de un TEXT RFC 3339 y ordena igual. Las horas UTC no sufren el cambio de hora; los días van por fecha local porque «ayer» es un día natural (regla transversal: días naturales en hora local, nunca mezclados con UTC). El resto de fechas sigue en TEXT RFC 3339 (ADR-34).

**ADR-57 · Destinos con retención corta y nunca en días (respuesta 5a; completa ADR-48)**
Los destinos por equipo son historial de navegación. Por hora durante 30 días bastan para investigar un equipo raro; por minuto solo viven 2 h, lo justo para la ventana de 1 h y para construir la hora. A largo plazo quedan app, categoría, organización y país, que también sirven para las alertas de F6.

**ADR-58 · Sin registro de conexiones (respuesta 6a)**
Un registro por conexión cerrada daría detalle forense, pero es historial de navegación con horas exactas y crece deprisa. Los agregados responden a «quién consume» y «con quién habla este equipo»; lo reciente sigue en Conexiones.

**ADR-59 · Sesiones con latido y huecos marcados; sin modo servicio en F5 (respuesta 2a)**
Almenara es una TUI: cuando está cerrada no hay datos. Registrar arranques, cierres y un latido por minuto permite distinguir «sin tráfico» de «sin datos» y no inventar nada. El modo servicio (sin TUI) cambia la arquitectura del escritor único y queda en el roadmap.

**ADR-60 · Lector del histórico con conexión de solo lectura (amplía ADR-35)**
Las consultas de semanas o años pueden tardar cientos de milisegundos; en el hilo de la TUI congelarían la pantalla. WAL permite lectores concurrentes; ADR-35 ya preveía conexiones de solo lectura. Sigue habiendo un único escritor.

**ADR-61 · Eventos nuevos sin cambio de esquema y presencia derivada (vs. tabla de intervalos)**
`event_type` es TEXT sin `CHECK`, así que los tipos nuevos no necesitan migración. Una tabla de intervalos de presencia duplicaría la información de los eventos y habría que mantenerla coherente; calcular la presencia al vuelo es barato con 90 días de eventos.

**ADR-62 · Inventario por equipo en `DEVICE_SEEN`; puertos desde `DEVICE_SERVICES` (respuesta 11a)**
F6 necesita saber qué es «nuevo» para un equipo sin leer años de rollups. Una fila por equipo, tipo y clave con primera y última vez es pequeña y directa. Los puertos ya tienen `first_seen` en `DEVICE_SERVICES` (F2): no se duplican. Sin dominios, por privacidad.

**ADR-63 · Ventanas de 1 h y 24 h desde el histórico, con minutos cerrados (vs. en memoria)**
Unas ventanas en memoria se perderían al reiniciar y gastarían memoria por clave. Leyendo los rollups sobreviven al reinicio y cuestan una consulta por minuto. A cambio, llegan hasta el último minuto cerrado.

**ADR-64 · Purga horaria con `incremental_vacuum`; sin copias automáticas (respuesta 12a)**
Un `VACUUM` completo bloquea la BD y tarda con cientos de MB; el incremental devuelve el espacio en trozos pequeños. Las copias automáticas duplicarían el espacio en disco; la copia manual queda documentada.

**ADR-65 · Instancia única por base de datos**
Dos Almenaras sobre la misma BD contarían dos veces el tráfico y duplicarían eventos. Un `flock` sobre un fichero junto a la BD lo impide sin servidores ni ficheros huérfanos (el kernel libera el bloqueo).

**ADR-66 · Histórico sintético para medir sin captura (respuesta 1c)**
La pasada con `CAP_NET_RAW` sigue pendiente. Para que el rendimiento de F5 no quede también sin medir, un generador determinista llena una BD con 2 años de histórico y una prueba ignorada mide tamaño y tiempos.

---

## 11. Plan de Desarrollo

**Supuestos:** 1 desarrollador, ~15 h/semana, F1–F4 estables como base. Sin sprint de verificación: la pasada con `CAP_NET_RAW` de F4 queda fuera por decisión del desarrollador (respuesta 1c).

### Sprint 5.1 — Modelo, configuración, instancia y sesiones (≈ 10 h)
- Migración v5, `auto_vacuum` incremental y test de compatibilidad v4 → v5
- `[history]` con validación
- Instancia única
- Sesiones: abrir, latido, cerrar y cerrar las interrumpidas

### Sprint 5.2 — Rollups por minuto (≈ 14 h)
- `MinuteRollup` en el agregador: sujetos, dimensiones, claves especiales y topes
- Lote por `AppEvent::Rollup`, escritura con suma, reintentos y minuto parcial al salir
- Inventario (`DEVICE_SEEN`)

### Sprint 5.3 — Consolidación y retención (≈ 12 h)
- Horas y días (día local, cambios de hora) y pendientes al arrancar
- Purga por resolución, `incremental_vacuum` y aviso de tamaño

### Sprint 5.4 — Eventos y presencia (≈ 10 h)
- `reappeared`, `service_new`, `service_gone`, `os_changed`, `type_changed` y `last_seen` en `disappeared`
- Cálculo de presencia y huecos

### Sprint 5.5 — Lector del histórico (≈ 12 h)
- Hilo lector, canal de consultas, identificadores y corte a los 2 s
- Consultas: series, top, ventanas, «¿Quién lo usa?», eventos, presencia, inventario, cobertura y estadísticas

### Sprint 5.6 — Pestaña Histórico (≈ 16 h)
- Selector de sujeto, rangos, gráfica con huecos y cursor
- «Más tráfico» y línea de tiempo con filtro y búsqueda

### Sprint 5.7 — Tráfico, detalle, Equipos, Config y Ayuda (≈ 12 h)
- Ventanas de 1 h y 24 h y «¿Quién lo usa?» desde el histórico
- Detalle: histórico 24 h ⇄ 7 días, presencia e inventario
- «Último evento», Config y Ayuda

### Sprint 5.8 — Cierre (≈ 8 h)
- Histórico sintético y prueba `medir_historial` con las cifras en el informe de implementación
- README, Ayuda, `CHANGELOG.md` y versión 0.5.0
- Informe de implementación

**Estimación total F5:** **~94 h → 6–7 semanas**.

---

## 12. Conexiones con Otras Fases

**Cambios sobre fases anteriores:**
- ADR-24 (F3) se completa con ADR-63: las ventanas de 1 h y 24 h llegan desde el histórico.
- ADR-21 (F3) sigue: `TRAFFIC_SNAPSHOT` es la semilla de las sparklines de 60 s; el histórico va en los rollups.
- ADR-48 (F4) se completa con ADR-57: dominios en el histórico solo por horas y 30 días.
- ADR-35 (F1) se amplía con ADR-60 (lector de solo lectura) y ADR-34 tiene una excepción para los cubos (ADR-56).
- El diagrama de estados de `DEVICES` (F1) gana el evento `reappeared`; `disappeared` gana `last_seen` en sus detalles.
- El ciclo de vida de `DEVICE_SERVICES` (F2) genera `service_new` y `service_gone` solo con escaneos reales.
- Una segunda instancia de Almenara deja de arrancar (ADR-65).
- La pasada con `CAP_NET_RAW` de F4 (9 casillas) sigue abierta y no forma parte de F5.

**Datos que usa:** `DEVICES`, `DEVICE_EVENTS` y `events_retention_days` (F1); `DEVICE_SERVICES`, escaneo de puertos bajo demanda, `os_family` y `device_type` (F2); ventanas, atribución por equipo, fila `[host]` y captura (F3); `Rankings`, etiquetas, base IP, JA4, `AppEvent::Traffic` y el patrón de consulta de «¿Quién lo usa?» (F4).

**Fases siguientes:**
- **F6 (Alertas):** «nuevo» por equipo desde `DEVICE_SEEN` (app, país, organización, JA4) y `DEVICE_SERVICES` (puerto); eventos nuevos como señales; rollups por hora y día para «más tráfico de lo habitual»; sesiones para no alertar por huecos; `mac_random` para bajar la severidad de las MAC privadas.
- **F7 (Integraciones y exportación):** exportación CSV de rollups y eventos; posible modo servicio (sin TUI) para histórico continuo; fuentes externas (SNMP, puerto espejo) que alimentan el mismo agregador y, por tanto, el mismo histórico.
