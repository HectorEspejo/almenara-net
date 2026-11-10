# Almenara - Fase 1: Fundación y descubrimiento básico

## Especificación Funcional

**Versión:** 1.1
**Fecha:** 2026-11-10
**Cliente:** Uso personal (desarrollador)

**Changelog:**
- 2026-11-10 — v1.1: especificación alineada con la Fase 1 implementada tras procesar su informe de implementación (crate OUI real, MSRV 1.88, rutas reales de la documentación, semántica definitiva de teclas, merge ICMP sin MAC, heurística de `mac_changed`, fechas RFC 3339, APIs adicionales de `Repo`, arranque no bloqueante). v1.0: especificación inicial.

**Nota de trazabilidad:** por la regla de textos estables, el checklist conserva la redacción original de F1-05, F1-08, F1-10, F1-27, F1-36 y F1-51; su interpretación vigente es la de esta v1.1 (primer escaneo en segundo plano, `ranges = []` derivado de la interfaz, merge ICMP solo como liveness, `mac_changed` por heurística y Enter como notificación no bloqueante). Quedan pendientes de verificación manual F1-24, F1-25 y F1-64 (ejecución real con `CAP_NET_RAW` y medición de rendimiento), tal como se registra en el checklist y en el maestro.

---

## 1. Visión General

Almenara es una aplicación de terminal (TUI) para Linux que monitoriza de forma permanente la red local a la que está conectado el equipo. En esta primera fase se construye el esqueleto del proyecto: shell de la TUI, capa de configuración, persistencia SQLite y **descubrimiento básico de dispositivos** (ARP, ICMP, reverse DNS, OUI). El tráfico, las conexiones, el histórico enriquecido y las alertas se incorporan en fases posteriores, pero sus pestañas aparecen ya como placeholders.

**Objetivos principales:**
1. Sentar la arquitectura (async runtime, layout de TUI, persistencia) que soporte las fases 2–7.
2. Descubrir y listar los equipos conectados a la red local con información básica fiable (IP, MAC, fabricante, hostname).
3. Persistir el inventario y la historia de cambios (apariciones, desapariciones, cambios de IP/MAC) en SQLite.
4. Ofrecer una **vista principal de lista detallada** con navegación, búsqueda, ordenación y filtros.
5. Funcionar en **modo degradado** sin privilegios elevados, avisando al usuario de las limitaciones.
6. Fijar las convenciones (nomenclatura, logging, config, CLI) que se reutilizarán en el resto del proyecto.

**Contexto del cliente:** proyecto personal, uso doméstico/laboratorio, un desarrollador único, Linux.

---

## 2. Arquitectura Técnica

### Stack tecnológico

| Capa | Tecnología | Motivo |
|------|-----------|--------|
| Lenguaje | Rust (edition 2021, MSRV 1.88) | Seguridad memoria, binario único, TUI idiomática |
| Runtime async | `tokio` | Timers, sockets, canales multi-productor |
| TUI | `ratatui` + `crossterm` | Estándar actual en Rust, mantenido, 256 colores |
| CLI | `clap` (derive) | Flags `-c`, `-v`, `-vv`, `--no-color`, `--version` |
| Config | `serde` + `toml` | Config declarativa legible |
| Persistencia | `rusqlite` (bundled) | SQLite embebido, sin dependencias del sistema |
| Red raw | `pnet` | ARP + ICMP raw sockets |
| OUI | `ouidb` (crate real: `macaddr-ouidb`) | Base de fabricantes embebida (40 000+ prefijos IEEE/Wireshark) |
| Logs | `tracing` + `tracing-subscriber` + `tracing-appender` | Logs estructurados con rotación por tamaño (10 MiB por fichero y 3 rotados, escritor propio) |

### Estructura de carpetas

```
almenara/
├── Cargo.toml
├── Cargo.lock
├── .gitignore
├── README.md
├── CLAUDE.md
├── docs/
│   └── fase1/
│       ├── almenara-maestro.md
│       ├── almenara-fase1-informe.md
│       ├── almenara-fase1-prompt.md
│       ├── almenara-fase1-checklist.md
│       └── almenara-fase1-implementacion.md   (lo crea el agente)
├── src/
    ├── main.rs                 # arranque, parseo CLI, init servicios
    ├── config.rs               # carga TOML, defaults
    ├── error.rs                # Error central (thiserror)
    ├── capabilities.rs         # detección CAP_NET_RAW / modo degradado
    ├── logging.rs              # tracing setup
    ├── events.rs               # Event enum + bus tokio::sync::broadcast
    ├── tui/
    │   ├── mod.rs              # bucle principal, dispatcher
    │   ├── app.rs              # estado de la app
    │   ├── keys.rs             # keybindings
    │   ├── theme.rs            # paleta 256, NO_COLOR
    │   └── views/
    │       ├── devices.rs      # vista principal (lista)
    │       ├── config_view.rs  # pestaña Config (solo lectura)
    │       ├── help.rs         # pestaña Ayuda
    │       └── placeholder.rs  # pestañas futuras
    ├── scanner/
    │   ├── mod.rs
    │   ├── interfaces.rs       # detección de interfaces
    │   ├── arp.rs              # ARP scan
    │   ├── icmp.rs             # ping sweep
    │   ├── proc_arp.rs         # lectura /proc/net/arp
    │   └── dns.rs              # reverse DNS
    ├── oui.rs                  # lookup fabricante
    ├── repo/
    │   ├── mod.rs              # fachada Repo
    │   ├── migrations.rs       # migraciones versionadas
    │   ├── interfaces.rs       # DAO interfaces
    │   ├── devices.rs          # DAO devices
    │   └── events.rs           # DAO device_events
    └── notifier.rs             # buffer de notificaciones
└── tests/
    └── cli.rs                  # pruebas de integración de la CLI
```

### Diagrama de arquitectura

```
┌──────────────────────────────────────────────────────────┐
│                        TUI (ratatui)                     │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────────────┐ │
│  │ Tab Equipos │ │ Tab Config   │ │ Tab Ayuda          │ │
│  └──────┬──────┘ └──────┬───────┘ └────────────────────┘ │
│         │                │                               │
│         └────────┬───────┘                               │
│                  ▼                                       │
│         ┌──────────────────┐                             │
│         │   App State      │                             │
│         │  (devices, sel,  │                             │
│         │   filtro, etc.)  │                             │
│         └────────┬─────────┘                             │
└──────────────────┼───────────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
┌─────────────────┐  ┌──────────────────┐
│  Event Bus      │  │  Config + CLI    │
│  (tokio bcast)  │  │  (TOML + clap)   │
└────────┬────────┘  └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│                   Services Layer                    │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │
│  │ Scanner      │ │ Repo (SQLite)│ │ Notifier   │  │
│  │ (ARP+ICMP+   │ │ (rusqlite)   │ │ (buffer    │  │
│  │  proc+DNS)   │ │              │ │  circular) │  │
│  └──────┬───────┘ └──────┬───────┘ └────────────┘  │
└─────────┼────────────────┼─────────────────────────┘
          │                │
          ▼                ▼
    ┌──────────┐    ┌──────────────┐
    │ pnet +   │    │  SQLite      │
    │ /proc    │    │  data.db     │
    └──────────┘    └──────────────┘
```

---

## 3. Modelo de Datos

### Diagrama E-R

```
┌────────────────────┐
│    INTERFACES      │
├────────────────────┤
│ id (PK)            │◄──────┐
│ name (UNIQUE)      │       │
│ mac                │       │
│ ipv4               │       │
│ netmask            │       │
│ gateway            │       │
│ is_up              │       │
│ last_seen          │       │
└────────────────────┘       │
                             │ 1
                             │
                             │ N
                    ┌────────┴───────────┐
                    │      DEVICES       │
                    ├────────────────────┤
                    │ id (PK)            │◄──────┐
                    │ mac (UNIQUE)       │       │
                    │ ip                 │       │
                    │ hostname (NULL)    │       │
                    │ vendor (NULL)      │       │
                    │ interface_id (FK)  │       │
                    │ device_type        │       │
                    │ is_online          │       │
                    │ first_seen         │       │
                    │ last_seen          │       │
                    │ alias (NULL)       │       │
                    │ notes (NULL)       │       │
                    └────────┬───────────┘       │
                             │ 1                 │
                             │                   │
                             │ N                 │
                    ┌────────▼───────────┐       │
                    │   DEVICE_EVENTS    │       │
                    ├────────────────────┤       │
                    │ id (PK)            │       │
                    │ device_id (FK)     │───────┘
                    │ event_type         │
                    │ details (JSON)     │
                    │ created_at         │
                    └────────────────────┘
```

### Definición de tablas

**INTERFACES** — interfaces de red detectadas en el equipo.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK AUTOINCREMENT | Identificador |
| `name` | TEXT NOT NULL UNIQUE | Nombre (`eth0`, `wlan0`, …) |
| `mac` | TEXT | MAC de la interfaz |
| `ipv4` | TEXT | IPv4 asignada |
| `netmask` | TEXT | Máscara |
| `gateway` | TEXT | Gateway por defecto si lo hay |
| `is_up` | BOOLEAN NOT NULL DEFAULT 1 | Estado del enlace |
| `last_seen` | TIMESTAMP NOT NULL | Última detección |

**DEVICES** — dispositivos descubiertos en la red.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK AUTOINCREMENT | Identificador |
| `mac` | TEXT NOT NULL UNIQUE | MAC normalizada `aa:bb:cc:dd:ee:ff` (minúsculas) |
| `ip` | TEXT NOT NULL | Última IPv4 vista |
| `hostname` | TEXT NULL | Reverse DNS / cache |
| `vendor` | TEXT NULL | Fabricante según OUI |
| `interface_id` | INTEGER NOT NULL FK INTERFACES(id) | Interfaz por la que se ve |
| `device_type` | TEXT NOT NULL DEFAULT 'unknown' | `gateway`/`unknown` en F1 (ampliable) |
| `is_online` | BOOLEAN NOT NULL DEFAULT 1 | Estado actual |
| `first_seen` | TIMESTAMP NOT NULL | Primera detección |
| `last_seen` | TIMESTAMP NOT NULL | Última detección |
| `alias` | TEXT NULL | Nombre manual del usuario |
| `notes` | TEXT NULL | Notas libres |

**DEVICE_EVENTS** — histórico de cambios relevantes.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK AUTOINCREMENT | Identificador |
| `device_id` | INTEGER NOT NULL FK DEVICES(id) | Dispositivo afectado |
| `event_type` | TEXT NOT NULL | `new` / `disappeared` / `ip_changed` / `mac_changed` / `hostname_changed` |
| `details` | TEXT NOT NULL | JSON con `before`/`after` |
| `created_at` | TIMESTAMP NOT NULL | Momento del evento |

**Índices:** `DEVICES(mac)` (implícito por UNIQUE), `DEVICES(is_online)`, `DEVICE_EVENTS(created_at)`, `DEVICE_EVENTS(device_id, created_at)`.

**Fechas:** todas las columnas de fecha (`last_seen`, `first_seen`, `created_at`) se almacenan como TEXT con RFC 3339 en UTC (ej. `2026-11-10T10:47:54Z`).

### Diagrama de estados — DEVICES

```
         (descubierto por 1ª vez)
                    │
                    ▼
       ┌───────────────────────┐
       │        ONLINE         │
       │  (is_online = 1)      │
       │  evento: new (1 sola  │
       │  vez por MAC)         │
       └───────────┬───────────┘
                   │
      no responde N ciclos
     (N configurable, def. 3)
                   │
                   ▼
       ┌───────────────────────┐
       │       OFFLINE         │
       │  (is_online = 0)      │
       │  evento: disappeared  │
       └───────────┬───────────┘
                   │
                reaparece
                   │
                   ▼
       ┌───────────────────────┐
       │        ONLINE         │
       │  (is_online = 1)      │
       │  SIN evento 'new'     │
       └───────────────────────┘

Transiciones inválidas (no permitidas por diseño):
  · OFFLINE → first_seen reset       (un dispositivo no se "re-descubre")
  · 'new' emitido más de una vez     (el evento new es único por MAC)
  · Cambio de MAC sin evento         (si se detecta, emite mac_changed; heurística en §7)
```

---

## 4. Flujos de Trabajo

### Flujo de arranque

```
┌──────────┐
│  start   │
└────┬─────┘
     ▼
┌──────────────────┐   error   ┌───────────────────────┐
│ cargar config    ├──────────►│ usar defaults + warn  │
│ (TOML + CLI)     │           └──────────┬────────────┘
└────┬─────────────┘                      │
     │ ok                                 │
     ▼                                    ▼
┌──────────────────┐
│ init logging     │
└────┬─────────────┘
     ▼
┌──────────────────┐   error   ┌───────────────────────┐
│ abrir SQLite     ├──────────►│ MODAL bloqueante      │
│ + migraciones    │           │ "BD inaccesible"      │
└────┬─────────────┘           │ [Reintentar] [Salir]  │
     │ ok                      └───────────────────────┘
     ▼
┌──────────────────┐
│ detect caps      │──► sin CAP_NET_RAW → modo degradado
└────┬─────────────┘       (aviso visible en barra estado)
     ▼
┌──────────────────┐
│ detect ifaces    │
│ + persistir      │
└────┬─────────────┘
     ▼
┌──────────────────┐
│ primer scan      │──► en segundo plano (no bloquea el arranque)
│ (ARP+ICMP+proc)  │    al terminar refresca la lista
└────┬─────────────┘
     ▼
┌──────────────────┐
│ cargar devices   │
│ desde BD         │
└────┬─────────────┘
     ▼
┌──────────────────┐
│ bucle TUI        │◄──────────────┐
└────┬─────────────┘               │
     │                             │
     └─── timer scan ──────────────┘
```

**Notas de implementación:** si el fichero de configuración no existe, se escribe una plantilla con los valores por defecto (best-effort) y se continúa. El primer escaneo no bloquea la apertura de la TUI: se lanza en segundo plano y, al terminar, se refresca la lista; los equipos ya persistidos se muestran desde SQLite al abrir.

### Flujo de escaneo periódico

```
┌───────────────┐
│ timer tick    │ (cada scan_interval, def. 60s)
└───────┬───────┘
        ▼
┌────────────────────────┐
│ read /proc/net/arp     │──── resultado vacío → sigue
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ ARP scan (si caps)     │──── sin caps → skip + warn (1 vez)
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ ICMP sweep (si caps)   │──── sin caps → skip
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ merge resultados por   │
│ MAC (ipv4 puede variar)│
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ reverse DNS por IP     │ (timeout corto, concurrencia limitada)
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ lookup OUI por MAC     │
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ para cada equipo:      │
│ · get_device(mac)      │
│ · si no existe → new   │──► evento 'new'
│ · si existe y cambia   │──► evento 'ip_changed' / 'mac_changed'
│   IP/hostname          │    / 'hostname_changed'
│ · upsert_device        │
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ para equipos online    │
│ no vistos N ciclos →   │──► evento 'disappeared'
│ marcar OFFLINE         │
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ prune_events(retention)│
└───────┬────────────────┘
        ▼
┌────────────────────────┐
│ emit AppEvent::Devices │
│ (actualiza TUI)        │
└────────────────────────┘
```

### Diagrama de secuencia — ciclo de escaneo (scanner → BD → TUI)

```
 Timer/scan task        Scanner (spawn_blocking)        TUI thread + Repo          SQLite
      │                            │                          │                     │
      │ tick del timer o tecla r   │                          │                     │
      ├───────────────────────────►│                          │                     │
      │                            │ /proc/net/arp (pasivo)   │                     │
      │                            │ ARP + ICMP (pnet, si CAP)│                     │
      │                            │ reverse DNS + OUI        │                     │
      │◄───────────────────────────┤ Vec<Host>                │                     │
      │ AppEvent::Devices          │                          │                     │
      ├──────────────────────────────────────────────────────►│                     │
      │                            │                          │ reconcile:          │
      │                            │                          │ · upsert/interfaz   │
      │                            │                          │ · altas y cambios   │
      │                            │                          │ · offline N ciclos  │
      │                            │                          │ · eventos JSON      │
      │                            │                          ├────────────────────►│
      │                            │                          │◄────────────────────┤
      │                            │                          │ · prune_events      │
      │                            │                          │ refresca AppState   │
      │                            │                          │ (redibuja la TUI)   │
```

En modo degradado se omiten el ARP scan y el ICMP sweep: el ciclo sigue con `/proc/net/arp` y el resto del pipeline es idéntico.

### Flujo de búsqueda/orden/filtro (UI)

```
keystroke → AppState::apply → recalcula vista → render
  /  → abre buffer de búsqueda (input incremental por substring en ip, mac, hostname, vendor, alias)
  s  → cicla orden ascendente/descendente sobre columna activa
  f  → menú de filtro: [all | online | offline | new | alert]
  r  → dispara scan manual (no espera al timer)
  ?  → pestaña Ayuda
```

---

## 5. API Endpoints

No hay API HTTP. La aplicación expone los siguientes **servicios internos** (análogos a endpoints):

### Scanner

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `detect_interfaces` | `fn() -> Result<Vec<Interface>>` | Enumerar interfaces vía `pnet`; gateway desde `/proc/net/route` |
| `arp_scan` | `fn(range: Ipv4Net, iface: &str) -> Result<Vec<Host>>` | Barrido ARP en el rango |
| `icmp_sweep` | `fn(range: Ipv4Net, iface: &str, timeout: Duration) -> Result<Vec<Ipv4Addr>>` | Ping sweep concurrente |
| `read_proc_arp` | `fn() -> Vec<ArpEntry>` | Lectura pasiva de la tabla ARP |
| `resolve_hostname` | `async fn(ip: Ipv4Addr, timeout) -> Option<String>` | Reverse DNS con timeout |

### OUI

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `lookup` | `fn(mac: MacAddr) -> Option<Vendor>` | Fabricante por OUI (base embebida) |

### Repo

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `init` | `fn(path: &Path) -> Result<Repo>` | Abre BD y aplica migraciones |
| `upsert_interface` | `fn(&Interface) -> Result<i64>` | Insert o update |
| `upsert_device` | `fn(&DeviceUpsert) -> Result<(i64, ChangeSet)>` | Devuelve qué cambió |
| `list_devices` | `fn() -> Result<Vec<Device>>` | Lista completa para TUI |
| `get_device_by_mac` | `fn(mac) -> Result<Option<Device>>` | Búsqueda puntual |
| `append_event` | `fn(device_id, event_type, details) -> Result<()>` | Registro |
| `prune_events` | `fn(older_than: Duration) -> Result<usize>` | Retención |
| `set_device_online` | `fn(mac, online) -> Result<()>` | Marcar un equipo online/offline tras N ciclos |
| `update_device_mac` | `fn(id, mac) -> Result<()>` | Cambio de identidad (heurística `mac_changed`) |
| `set_alias` / `set_notes` | `fn(id, texto: Option<&str>) -> Result<()>` | Edición manual desde la TUI |
| `list_interfaces` | `fn() -> Result<Vec<Interface>>` | Pestaña Config / diagnóstico |
| `list_events` | `fn(limit) -> Result<Vec<DeviceEvent>>` | Reservado para la pestaña Histórico (F5); cubierto por tests en F1 |
| `schema_version`, `count_devices`, `path` | `fn(...)` | Diagnóstico y pruebas |

### Capabilities / Config / Notifier

| Operación | Firma |
|-----------|-------|
| `capabilities::detect` | `fn() -> Capabilities { raw_sockets: bool }` |
| `config::load` | `fn(path: Option<&Path>) -> Result<Config>` |
| `notifier::push` | `fn(level: Level, msg: String)` |

---

## 6. Interfaz de Usuario

### Mapa de navegación

```
                   ┌──────────────┐
                   │   Arranque   │
                   └──────┬───────┘
                          ▼
                   ┌──────────────┐
                   │   Equipos    │◄─────── default
                   └──┬──┬──┬──┬──┘
       /  búsqueda ───┘  │  │  └─── r rescan manual
       f  filtro  ───────┘  └─────── s ordenar
       Enter  ───────────────────► notificación "detalle no disponible (F3)"
       Tab / 1-7 ────────────────► otra pestaña
                                     │
             ┌───────────────────────┼───────────────────────┐
             ▼                       ▼                       ▼
       ┌───────────┐           ┌───────────┐           ┌───────────┐
       │  Config   │           │   Ayuda   │           │ Tráfico / │
       │ (lectura) │           │ (keybinds)│           │Conex./Hist│
       └───────────┘           └───────────┘           │/Alertas   │
                                                       │placeholder│
                                                       └───────────┘
```

### Mockup 1 — Equipos (vista principal, estado normal)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Icono  IP              Hostname         Fabricante    Tráfico    Estado │
├────────────────────────────────────────────────────────────────────────┤
│ [⌂]  192.168.1.1     router.lan        TP-Link       ─           online │
│ [?]  192.168.1.42    laptop-juan       Apple         ─           online │
│ [?]  192.168.1.57    iPhone-Marta      Apple         ─           online │
│ [?]  192.168.1.103   chromecast-sala   Google        ─           online │
│ [?]  192.168.1.88    tv-sala           Samsung       ─           online │
│ [?]  192.168.1.10    nas-synology      Synology      ─           online │
│ [?]  192.168.1.201   ?                 ?             ─           online │
│ ○    192.168.1.66    iPad              Apple         ─           offline│
│                                                                        │
│ 12 equipos · 11 online · 1 offline   modo: privilegiado                 │
└─[j/k]mover [h/l]pestaña [Enter]det. [s]orden [f]filtro [/]buscar [?]──┘
```

### Mockup 2 — Equipos con búsqueda activa

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Buscar: apple█                                                         │
├────────────────────────────────────────────────────────────────────────┤
│ [?]  192.168.1.42    laptop-juan       Apple         ─           online │
│ [?]  192.168.1.57    iPhone-Marta      Apple         ─           online │
│ ○    192.168.1.66    iPad              Apple         ─           offline│
│                                                                        │
│ 3 resultados de 12 · [Esc]cerrar búsqueda                              │
└─[j/k]mover [h/l]pestaña [Enter]det. [s]orden [f]filtro [/]buscar [?]──┘
```

### Mockup 3 — Config (solo lectura F1)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Configuración activa (solo lectura en F1)                              │
├────────────────────────────────────────────────────────────────────────┤
│ Ruta: ~/.config/almenara/config.toml                                   │
│                                                                        │
│ [scan]                                                                 │
│   interfaces = "auto"                                                  │
│   ranges     = []                # vacío = derivar de la interfaz      │
│   interval_s = 60                                                      │
│   icmp_timeout_ms = 500                                                │
│   offline_after_cycles = 3                                             │
│                                                                        │
│ [storage]                                                              │
│   db_path = "~/.local/share/almenara/data.db"                          │
│   events_retention_days = 90                                           │
│                                                                        │
│ [ui]                                                                   │
│   theme = "default"                                                    │
│   no_color = false                                                     │
└─[Esc]volver [1-7]pestañas [?]ayuda─────────────────────────────────────┘
```

### Mockup 4 — Ayuda

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Almenara v0.1.0 — Fase 1                                              │
├────────────────────────────────────────────────────────────────────────┤
│ Navegación                                                             │
│   j/k, ↑/↓          mover selección                                    │
│   h/l, ←/→          cambiar pestaña                                    │
│   Tab / Shift-Tab   cambiar pestaña                                    │
│   1-7               atajo a pestaña                                    │
│   a / n             editar alias / notas                               │
│   Enter             notificación de detalle no disponible (F3)         │
│   /                 buscar                                             │
│   s                 ordenar por columna                                │
│   f                 filtrar (all/online/offline/new/alert)             │
│   r                 rescan manual                                      │
│   ?                 esta ayuda                                         │
│   q                 salir                                              │
│                                                                        │
│ Estado: privilegiado (CAP_NET_RAW detectado)                           │
└─[Esc]volver [?]ayuda────────────────────────────────────────────────────┘
```

### Notas de UX/diseño

- Paleta 256 colores con 4 roles: `normal`, `accent` (cabeceras), `warning` (alertas), `dim` (offline).
- Respeto a `NO_COLOR=1` (monocromo con símbolos y pesos).
- Tamaño mínimo razonable: **80×24**. Por debajo, mensaje de "terminal demasiado pequeño".
- Iconos en F1: `[⌂]` gateway, `[?]` cualquier otro (device_type='unknown'), `○` offline.
- Barra de notificaciones: última notificación abajo a la derecha durante 3 s, buffer circular de 50 en memoria (no persistido en F1).
- Keybindings finales (v1.1): `j/k` y ↑/↓ mueven la selección; `h/l` y ←/→ cambian de pestaña (además de `Tab`/`Shift-Tab` y `1-7`); `a` y `n` editan alias y notas con entrada inline (Enter guarda, Esc cancela). El pie de la TUI se dibuja en dos líneas para que quepan todos los atajos a 80 columnas.
- `Enter` sobre un equipo muestra una notificación no bloqueante de "detalle no disponible hasta F3"; el informe no definía pantalla de detalle para F1.
- La barra de estado muestra equipos/online/offline, filtro, búsqueda, orden y modo (privilegiado/degradado), con el modo degradado resaltado; se omite el contador de conexiones del mockup porque Conexiones es placeholder en F1.
- Si el fichero de configuración no existe, se escribe una plantilla con los valores por defecto (best-effort) y se continúa.

---

## 7. Lógica de Negocio

### Merge de resultados ARP + ICMP + `/proc/net/arp`

La misma MAC puede aparecer con IP duplicada por caché desactualizada; el merge debe ser determinista. El ping sweep ICMP devuelve solo direcciones IP (no MAC), por lo que se usa como fuente de *liveness* y el merge por MAC se hace entre ARP y `/proc/net/arp`.

```python
def merge_hosts(arp, proc_arp, icmp_ips):
    by_mac = {}
    for h in arp + proc_arp:
        mac = h.mac_normalized()            # minúsculas, ':' como separador
        if mac not in by_mac:
            by_mac[mac] = h
        else:
            # preferimos la IP que confirma ARP (más fiable que /proc)
            if h.source == 'arp':
                by_mac[mac].ip = h.ip
            by_mac[mac].seen_sources.add(h.source)
    # ICMP solo confirma que la IP responde; no identifica MAC
    for ip in icmp_ips:
        if ip in {h.ip for h in by_mac.values()}:
            mark_alive(ip)
    return list(by_mac.values())
```

### Detección de cambios

```python
def diff(prev: Device | None, curr: Host) -> ChangeSet:
    if prev is None:
        return ChangeSet(new=True)
    cs = ChangeSet()
    if prev.ip != curr.ip:            cs.ip_changed = (prev.ip, curr.ip)
    if prev.hostname != curr.hostname: cs.hostname_changed = (prev.hostname, curr.hostname)
    # mac_changed no se detecta aquí: la identidad es la MAC (ver heurística)
    return cs
```

`ip_changed` y `hostname_changed` emiten eventos; `mac_changed` solo puede emitirse mediante la heurística siguiente. El propio upsert persiste la nueva IP/hostname.

**Heurística de `mac_changed`.** Con identidad por MAC (`UNIQUE`) y merge por MAC, un cambio de MAC no es alcanzable en un upsert normal. Si aparece una MAC desconocida con la IP de un equipo online cuya MAC anterior ha desaparecido de la foto actual del escaneo, se actualiza la identidad de ese equipo y se emite `mac_changed` con `before`/`after`. Limitación conocida: una reasignación real de IP entre dos equipos podría interpretarse como cambio de MAC; se revisará en F2 con fingerprint de dispositivo.

### Marcado offline

Un equipo `is_online = 1` que **no aparece en el resultado del merge** durante `offline_after_cycles` ciclos consecutivos (contador en memoria; default 3 ⇒ ~3 min con `interval_s=60`) pasa a `OFFLINE` y emite `disappeared`. Al volver a aparecer, `ONLINE` sin evento `new`.

### Cálculo de hostname

- Primero consulta reverse DNS con timeout `icmp_timeout_ms`.
- Si no resuelve, se conserva el último hostname conocido (no se pisa con `NULL`).

### OUI

- Base embebida `macaddr-ouidb` 0.3.1 (el crate `ouidb` no existe en crates.io; la dependencia se declara como `ouidb` con `package = "macaddr-ouidb"` en Cargo.toml).
- Normalización de MAC a `aa:bb:cc:dd:ee:ff` antes del lookup.
- MAC locales/administrativas (`02:...` con bit U/L) no tienen vendor y se muestran como `?`.

### Validación

- Rango(s) deben ser IPv4 CIDR válidos; máximo 1024 IPs por rango en F1.
- `ranges = []` (valor por defecto) significa derivar la red de cada interfaz activa desde su IP y máscara; el rango automático se acota a 1024 direcciones (equivalente a /22 alrededor de la IP local) para evitar escaneos enormes.
- `interval_s` ≥ 10.
- `icmp_timeout_ms` entre 100 y 5000.
- Una configuración inválida no aborta: se avisa por notificación y log y se usan los valores por defecto, sin reescribir el fichero del usuario.

---

## 8. Requisitos No Funcionales

### Seguridad

- Ejecutable corre sin privilegios; activa raw sockets solo si `CAP_NET_RAW` disponible.
- Sin superficie de red propia (no abre puertos).
- Validación estricta de la config (rangos CIDR, rutas).
- Sin ejecución de comandos externos por defecto.

### Protección de datos (RGPD)

- Solo se persisten **datos técnicos de red** (IP, MAC, hostname, fabricante).
- No se persisten payloads ni contenido de tráfico en F1.
- Base legal en uso personal doméstico: interés legítimo / red propia del usuario.
- Almacenamiento local, sin envío a terceros.
- Retención de eventos configurable (90 días por defecto) y purga automática.
- Aviso en la pestaña Ayuda de la responsabilidad legal si se monitorizan redes ajenas.

### Backups y recuperación

- F1 no incluye backup automático. La BD es un único fichero (`data.db`); copia manual posible.
- Si el fichero está corrupto al arrancar: modal bloqueante con opciones `[Reintentar]` / `[Salir]`. La recuperación automática queda fuera de F1.

### Rendimiento

- Hasta **256 dispositivos** por BD en F1 sin degradación perceptible.
- Escaneo `/24` completo en ≤ 15 s con timeout `500 ms` y concurrencia 64.
- Ciclo de render objetivo ≤ 16 ms en 80×24.
- Uso de CPU ≤ 5 % en reposo, ≤ 30 % durante escaneo.
- *Verificación pendiente:* el entorno de desarrollo de F1 no dispone de `CAP_NET_RAW`, por lo que el escaneo activo completo y estos objetivos de rendimiento no se han medido de extremo a extremo; queda recomendada una prueba manual con `sudo`/`setcap` y una prueba de carga con 256 equipos.

### Accesibilidad

- Nivel objetivo WCAG 2.1 AA en lo aplicable a TUI:
  - Contraste de colores ≥ 4.5:1.
  - Información nunca solo por color (símbolos + texto).
  - Respeto a `NO_COLOR=1`.
  - Tamaño mínimo 80×24 con mensaje claro por debajo.

---

## 9. Integraciones

No aplica en F1. Se reserva la sección para fases posteriores.

---

## 10. Decisiones Técnicas (ADR-lite)

**ADR-01 · `ratatui` + `crossterm` (vs. `tui-rs`, `cursive`, `termion`)**
`tui-rs` está archivado; `ratatui` es su sucesor mantenido. `crossterm` es multiplataforma y compatible con truecolor/256. `cursive` es más orientado a widgets y menos flexible para layouts propios. Se elige `ratatui`+`crossterm`.

**ADR-02 · `rusqlite` con `bundled` (vs. `sqlx`, `sled`)**
`rusqlite` es síncrono y sencillo; el uso desde un thread dedicado no penaliza la TUI. `sqlx` añade complejidad async innecesaria en F1. `sled` no es SQL y complica futuras consultas de rollups. Se elige `rusqlite` + `bundled`.

**ADR-03 · `pnet` + `/proc/net/arp` (vs. `pcap`, `nmap`, comandos `ip`/`arp`)**
`pnet` permite ARP/ICMP raw sin dependencias del sistema. `pcap` es la opción para F3 (captura de paquetes), no para F1. Delegar en `nmap`/`ip` introduce dependencia externa y dificulta el binario único. Se elige `pnet` + lectura directa de `/proc`.

**ADR-04 · `tokio` como runtime (vs. `async-std`, threads)**
`tokio` ofrece timers, canales y compatibilidad con el ecosistema (pcap, sockets) sin coste extra. `async-std` está en mantenimiento reducido. Se elige `tokio`.

**ADR-05 · Vista de lista (opción B) en F1, no grid**
La lista escala mejor a decenas de equipos, permite ordenación y filtrado, y encaja con la adición posterior de sparklines. El grid (opción A) queda como vista alternativa opcional en fase posterior. Se elige lista como vista principal de F1.

**ADR-06 · Base OUI embebida en el binario**
Evita descarga en primer arranque y dependencia de red. El crate `ouidb` no existe en crates.io, así que se usa `macaddr-ouidb` 0.3.1 (40 000+ prefijos IEEE/Wireshark), renombrado `ouidb` en `Cargo.toml` para conservar el nombre acordado. Actualizaciones se hacen publicando nueva versión. Se elige embebida.

**ADR-07 · Modo degradado en lugar de abortar sin CAP_NET_RAW**
Arrancar en modo degradado permite usar la TUI y aprovechar `/proc/net/arp` si está poblada. Abortar por falta de capabilities penaliza al usuario en entornos donde no puede elevarlas. Se elige modo degradado con aviso visible.

**ADR-08 · Fechas como TEXT RFC 3339 en UTC (vs. TIMESTAMP numérico o feature de fecha de `rusqlite`)**
Guardar RFC 3339 en UTC permite ordenar lexicográficamente, es legible en SQLite y evita depender de la feature `chrono` de `rusqlite`. Se elige TEXT RFC 3339 UTC.

**ADR-09 · Un único escritor SQLite y reconciliación en la TUI (vs. compartir `Connection` entre tareas)**
`rusqlite::Connection` no es `Sync`; compartirla exigiría mutex o pool. Se opta por una única conexión de escritura en el hilo de la TUI: el escaneo publica el informe en bruto por `AppEvent::Devices` y la TUI reconcilia (altas, cambios, offline, eventos) antes de refrescar. WAL activo para futuras conexiones de solo lectura.

**ADR-10 · Primer escaneo en segundo plano (vs. bloquear el arranque hasta completarlo)**
Un escaneo /24 con timeout de 500 ms puede tardar hasta ~15 s. La TUI se abre de inmediato con los equipos ya persistidos y se refresca al terminar el primer ciclo; el flujo funcional (lista poblada tras el primer escaneo) se mantiene.

---

## 11. Plan de Desarrollo

**Supuestos:** 1 desarrollador, ~15 h/semana, sin rediseño de esquema entre sub-sprints.

### Sprint 1.1 — Esqueleto (≈ 8 h)
- `Cargo.toml`, estructura de carpetas, `main.rs` con `clap`
- `error.rs`, `logging.rs`
- `config.rs` con `serde`/`toml` y defaults
- Shell mínimo de TUI con `ratatui` (una pestaña, texto estático)
- README mínimo

### Sprint 1.2 — Persistencia (≈ 10 h)
- `repo/mod.rs` con `rusqlite` bundled
- `migrations.rs` con la migración inicial (INTERFACES, DEVICES, DEVICE_EVENTS)
- DAOs `interfaces`, `devices`, `events`
- Tests unitarios de los DAOs

### Sprint 1.3 — Descubrimiento (≈ 14 h)
- `capabilities.rs`
- `scanner/interfaces.rs`, `scanner/proc_arp.rs`, `scanner/arp.rs`, `scanner/icmp.rs`, `scanner/dns.rs`
- `oui.rs`
- Orquestación: merge + diff + emisión de eventos
- Primer `scan` lanzado en segundo plano al arrancar

### Sprint 1.4 — TUI principal (≈ 14 h)
- Vista Equipos con la lista detallada
- Navegación j/k (mover), h/l (pestañas), flechas, Tab/Shift-Tab, 1-7
- Búsqueda `/`, orden `s`, filtro `f`, rescan `r`, ayuda `?`
- Barra de estado con resumen y modo (privilegiado/degradado)
- Notificaciones no bloqueantes
- Pestaña Config (lectura) y Ayuda
- Placeholders pestañas futuras

### Sprint 1.5 — Cierre de fase (≈ 8 h)
- Timer de escaneo periódico con `tokio`
- Logging a fichero con rotación
- Ajuste de paleta 256 + `NO_COLOR`
- Modal bloqueante de error de BD
- Manual de arranque en README (Linux, capabilities, cómo dar `CAP_NET_RAW`)
- Tests de integración de la CLI (`tests/cli.rs`)
- Informe de implementación

**Estimación total F1:** **~54 h → 3–4 semanas**.

**Estado real (2026-11-10):** Fase 1 completada; 135 tests en verde, `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings` limpios. El desarrollo se organizó por ámbitos de escritura disjuntos con contratos de módulo; se añadieron `tests/cli.rs` (4 pruebas de integración de la CLI) y se fijó el MSRV en Rust 1.88.

---

## 12. Conexiones con Otras Fases

- **F2 (Descubrimiento avanzado)** ampliará `DEVICES` (`device_type` pasa a tener más valores; no se rompe esquema) y añadirá métodos de descubrimiento (mDNS, SSDP, DHCP leases, fingerprint de SO, port scan ligero).
- **F3 (Tráfico en vivo)** añadirá nuevas tablas (`CONNECTIONS`, `TRAFFIC_BUCKETS`) y usará `interface_id` ya presente. Los eventos actuales (`new`, `disappeared`, `ip_changed`, `mac_changed`, `hostname_changed`) son la base del ticker de F5.
- **F5 (Histórico)** añadirá rollups (`TRAFFIC_ROLLUP_MINUTE/HOUR/DAY`) y consumirá `DEVICE_EVENTS`.
- **F6 (Alertas)** usará `DEVICE_EVENTS` + reglas. La columna `device_type` y `alias` ya existen para personalización.
- **F7 (Integraciones)** añadirá tablas de fuentes externas (SNMP, replay).