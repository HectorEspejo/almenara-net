# Almenara - Fase 2: Descubrimiento avanzado

## Especificación Funcional

**Versión:** 1.0
**Fecha:** 2026-11-10
**Cliente:** Uso personal (desarrollador)

---

## 1. Visión General

La Fase 2 completa el inventario de dispositivos iniciado en F1. Si F1 responde "¿qué IPs y MACs hay en mi red?", F2 responde "¿**qué** son esos dispositivos y **qué servicios** ofrecen?". Se añaden métodos de descubrimiento pasivos (mDNS, SSDP, leases DHCP, NetBIOS) y activos (M-SEARCH SSDP, mDNS browse, fingerprint de SO, port scan ligero con banner grabbing), una taxonomía ampliada de tipo de dispositivo con override manual, y una vista agrupada por categoría en la TUI.

**Objetivos principales:**
1. Identificar dispositivos por nombre, servicios y tipo (no solo IP/MAC).
2. Añadir hostname por mDNS/NetBIOS/DHCP cuando reverse DNS no resuelve.
3. Clasificar `device_type` en 12 categorías con override manual.
4. Detectar servicios expuestos por dispositivo (TOP-20 por defecto) con banner grabbing opcional.
5. Estimar `os_family` por heurística (TTL + opciones TCP) con umbral de confianza.
6. Ofrecer modo **`passive_only`** que deshabilita todo el tráfico activo (redes de terceros).
7. Añadir vista agrupada por categoría en la TUI, con preferencia persistida.

**Contexto:** evolución directa de F1 (implementada y verificada el 2026-11-10). Migración de esquema **aditiva**; toda BD de F1 debe seguir funcionando sin pérdida de datos.

---

## 2. Arquitectura Técnica

### Stack tecnológico (novedades respecto a F1)

| Capa | Tecnología | Motivo |
|------|-----------|--------|
| mDNS | `hickory-proto` | Parsing DNS/mDNS maduro, soporta multicast |
| SSDP | `ssdp` + `reqwest` (solo XML) | Parsing UPnP + descarga de LOCATION con timeout |
| DHCP leases | Parsers propios por formato | Formatos estables y bien documentados, sin crate fiable |
| NetBIOS | `nbtscan`-like propio (UDP 137) | Implementación simple del protocolo NBNS |
| Port scan | `tokio::net::TcpStream::connect_timeout` | Suficiente para CONNECT scan; sin privilegios |
| Banner grabbing | `tokio::io::AsyncReadExt::read` con timeout 1 s | Lectura inicial, sin paquetes raw |
| Fingerprint SO | `pnet` (parseo de TTL y TCP options) | Ya en stack de F1 |
| Fingerprint UI | `ratatui::widgets::Table` agrupada | Misma librería, extendida con cabeceras de sección |

Todas las nuevas dependencias son puras-Rust o con bindings ya empaquetados. Sin nuevas dependencias del sistema.

### Estructura de carpetas (novedades)

```
src/
├── discovery/                 # NUEVO módulo raíz
│   ├── mod.rs                 # orquestación del ciclo de descubrimiento avanzado
│   ├── mdns/
│   │   ├── mod.rs
│   │   ├── listener.rs        # escucha pasiva 224.0.0.251:5353
│   │   ├── query.rs           # browse activo (_services._dns-sd._udp.local)
│   │   └── parser.rs          # parser de respuestas y extracción de servicios/hostname
│   ├── ssdp/
│   │   ├── mod.rs
│   │   ├── listener.rs        # escucha pasiva 239.255.255.250:1900
│   │   ├── query.rs           # M-SEARCH activo
│   │   └── parser.rs          # NOTIFY / M-SEARCH response + fetch del XML
│   ├── dhcp/
│   │   ├── mod.rs
│   │   ├── dnsmasq.rs
│   │   ├── dhclient.rs
│   │   └── networkmanager.rs
│   ├── netbios.rs             # NBNS query (UDP 137)
│   ├── fingerprint.rs         # TTL + TCP options → os_family
│   ├── portscan.rs            # TCP CONNECT TOP-20
│   └── banner.rs              # lectura inicial por puerto
├── classify.rs                # NUEVO: device_type y servicio por puerto
├── scanner/
│   ├── mod.rs                 # (extendido) ciclo incorpora discovery
│   └── (resto igual que F1)
├── repo/
│   ├── device_services.rs     # NUEVO DAO
│   ├── discovery_sources.rs   # NUEVO DAO
│   ├── migrations.rs          # migración v2
│   └── (resto extendido)
└── tui/
    ├── views/
    │   ├── devices.rs         # (extendido) modo plano / agrupado
    │   └── (resto igual)
    └── theme.rs               # iconos por device_type
```

### Diagrama de arquitectura

```
┌──────────────────────────────────────────────────────────────┐
│                       TUI (ratatui)                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Equipos      │  │ Equipos      │  │ Config / Ayuda   │   │
│  │ (plana)      │◄─┤ (agrupada)   │  │ (sin cambios F1) │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────┘   │
└─────────┼─────────────────┼──────────────────────────────────┘
          │                 │
          ▼                 ▼
    ┌───────────────────────────┐
    │      App State            │◄── toggle `g` (flat/grouped)
    └─────────────┬─────────────┘
                  │
                  ▼
    ┌───────────────────────────┐
    │      Event Bus            │
    └─────────────┬─────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────┐
│                  Discovery Orchestrator                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Fase pasiva (siempre):                                 │  │
│  │  · mDNS listener  · SSDP listener · DHCP leases       │  │
│  │  · NetBIOS NBNS query · /proc/net/arp (heredado F1)   │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │ Fase activa (si !passive_only && CAP_NET_RAW):        │  │
│  │  · mDNS browse · M-SEARCH SSDP · Port scan TOP-20     │  │
│  │  · Banner grabbing · Fingerprint SO                   │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
    ┌───────────────────────────┐
    │  Classifier (device_type) │
    │  · OUI + puertos + mDNS   │
    │  · + SSDP + hostname      │
    └─────────────┬─────────────┘
                  │
                  ▼
    ┌───────────────────────────┐
    │  Repo (SQLite, escritor   │
    │  único en hilo TUI)       │
    │  DEVICES + SERVICES +     │
    │  DISCOVERY_SOURCES        │
    └───────────────────────────┘
```

---

## 3. Modelo de Datos

### Migración v2 (aditiva — no rompe F1)

```sql
-- v2 — Fase 2: descubrimiento avanzado

ALTER TABLE DEVICES ADD COLUMN os_family TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN device_type_manual TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN last_fingerprint TIMESTAMP NULL;

CREATE TABLE DEVICE_SERVICES (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id    INTEGER NOT NULL REFERENCES DEVICES(id) ON DELETE CASCADE,
  port         INTEGER NOT NULL,
  protocol     TEXT NOT NULL DEFAULT 'tcp',    -- 'tcp' | 'udp'
  service      TEXT NULL,                       -- 'http', 'ssh', 'upnp', ...
  banner       TEXT NULL,
  first_seen   TIMESTAMP NOT NULL,
  last_seen    TIMESTAMP NOT NULL,
  UNIQUE (device_id, port, protocol)
);

CREATE TABLE DISCOVERY_SOURCES (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id    INTEGER NOT NULL REFERENCES DEVICES(id) ON DELETE CASCADE,
  source       TEXT NOT NULL,                   -- 'arp'|'icmp'|'mdns'|'ssdp'|'dhcp'|'netbios'|'portscan'
  last_seen    TIMESTAMP NOT NULL,
  UNIQUE (device_id, source)
);

CREATE INDEX IDX_SERVICES_DEVICE ON DEVICE_SERVICES(device_id);
CREATE INDEX IDX_SOURCES_DEVICE  ON DISCOVERY_SOURCES(device_id);
```

### Diagrama E-R extendido

```
       ┌────────────────────┐
       │    INTERFACES      │  (F1)
       └─────────┬──────────┘
                 │ 1
                 │ N
       ┌─────────▼──────────┐
       │      DEVICES       │  (F1 + ampliación F2)
       ├────────────────────┤
       │ id (PK)            │
       │ mac (UNIQUE)       │
       │ ip                 │
       │ hostname           │
       │ vendor             │
       │ interface_id (FK)  │
       │ device_type        │  ◄─── + valores (F2)
       │ is_online          │
       │ first_seen         │
       │ last_seen          │
       │ alias              │
       │ notes              │
       │ os_family          │  ◄─── NUEVO F2
       │ device_type_manual │  ◄─── NUEVO F2
       │ last_fingerprint   │  ◄─── NUEVO F2
       └───┬────────────┬───┘
           │ 1          │ 1
           │            │
           │ N          │ N
  ┌────────▼────────┐  ┌▼───────────────────┐
  │ DEVICE_EVENTS   │  │ DEVICE_SERVICES    │  ◄─── NUEVO F2
  │ (F1)            │  ├────────────────────┤
  └─────────────────┘  │ id (PK)            │
                       │ device_id (FK)     │
                       │ port               │
                       │ protocol           │
                       │ service            │
                       │ banner             │
                       │ first_seen         │
                       │ last_seen          │
                       │ UNIQUE(device_id,  │
                       │  port, protocol)   │
                       └────────────────────┘

                       ┌────────────────────┐
                       │ DISCOVERY_SOURCES  │  ◄─── NUEVO F2
                       ├────────────────────┤
                       │ id (PK)            │
                       │ device_id (FK)     │
                       │ source             │
                       │ last_seen          │
                       │ UNIQUE(device_id,  │
                       │  source)           │
                       └────────────────────┘
```

### Ciclo de vida — DEVICE_SERVICES

```
   (puerto detectado en un scan)
             │
             ▼
   ┌───────────────────┐
   │      ACTIVE       │  first_seen = now
   │  last_seen = now  │
   └─────────┬─────────┘
             │
       N ciclos sin ver el puerto
       (N = offline_after_cycles, def. 3)
             │
             ▼
   ┌───────────────────┐
   │      STALE        │  last_seen > offline_after_cycles × interval_s
   │  (no se borra)    │
   └─────────┬─────────┘
             │
      reaparición ──────► vuelve a ACTIVE, actualiza last_seen y banner

   Purga: al hacer prune_events, se eliminan servicios STALE con
   last_seen anterior a events_retention_days (90 días por defecto).

   Transiciones inválidas:
     · DEVICE_SERVICES con device_id inexistente  (FK)
     · Mismo (device_id, port, protocol) repetido  (UNIQUE)
```

`DEVICES` mantiene el ciclo online↔offline de F1. `DISCOVERY_SOURCES` no tiene ciclo de vida propio (se purga con el dispositivo).

---

## 4. Flujos de Trabajo

### Ciclo de descubrimiento extendido

```
┌──────────────────┐
│ timer tick       │ (cada interval_s, def. 60 s)
└────────┬─────────┘
         ▼
┌───────────────────────┐
│ F1: /proc/arp + ARP   │ (heredado; activo solo con CAP_NET_RAW)
│ + ICMP + DNS + OUI    │
└────────┬──────────────┘
         ▼
┌───────────────────────┐
│ F2 PASIVO (siempre):  │
│  · mDNS listener      │  ── suscripción viva, lee buffer desde último ciclo
│  · SSDP listener      │
│  · DHCP leases        │
│  · NetBIOS NBNS       │
└────────┬──────────────┘
         ▼
      ┌──────────────────────┐
      │ passive_only = true? │──Sí──┐
      └──────────┬───────────┘      │
                 │ No               │
                 ▼                  │
      ┌──────────────────────┐      │
      │ CAP_NET_RAW?         │──No──┤
      └──────────┬───────────┘      │
                 │ Sí               │
                 ▼                  │
   ┌────────────────────────┐      │
   │ F2 ACTIVO:             │      │
   │  · mDNS browse         │      │
   │  · M-SEARCH SSDP       │      │
   │  · Port scan SOLO si   │      │
   │    equipo nuevo o IP/  │      │
   │    MAC cambió          │      │
   │  · Banner grabbing     │      │
   │  · Fingerprint SO      │      │
   └────────┬───────────────┘      │
            │                      │
            ▼                      ▼
   ┌────────────────────────────────────┐
   │ Merge por MAC de todas las fuentes │
   │ (F1 + F2), priorizando ARP para IP │
   └────────┬───────────────────────────┘
            ▼
   ┌────────────────────────────────────┐
   │ Clasificador:                      │
   │  device_type_manual ??             │
   │  classify(OUI, ports, mdns, ssdp,  │
   │           hostname)                │
   └────────┬───────────────────────────┘
            ▼
   ┌────────────────────────────────────┐
   │ Persistencia:                      │
   │  · upsert_devices (F1 + nuevos)    │
   │  · upsert_services                 │
   │  · upsert_sources                  │
   │  · mark_stale_services             │
   │  · prune_events + prune_services   │
   └────────┬───────────────────────────┘
            ▼
   ┌────────────────────────────────────┐
   │ AppEvent::Devices → TUI refresh    │
   └────────────────────────────────────┘
```

### Secuencia — port scan + banner grabbing

```
TUI        Orchestrator     PortScan       Network        Banner      Repo
 │              │               │              │              │         │
 │  r (manual)  │               │              │              │         │
 ├─────────────►│               │              │              │         │
 │              │ scan(host,ports)             │              │         │
 │              ├──────────────►│              │              │         │
 │              │               │ connect(22)  │              │         │
 │              │               ├─────────────►│              │         │
 │              │               │   SYN        │              │         │
 │              │               │◄─────────────┤ SYN-ACK      │         │
 │              │               │   (open)     │              │         │
 │              │               │              │              │         │
 │              │               │ grab(22)     │              │         │
 │              │               ├─────────────────────────────►│         │
 │              │               │              │  read(1s)    │         │
 │              │               │              │◄─────────────┤ banner  │
 │              │               │◄─────────────────────────────┤         │
 │              │               │              │              │         │
 │              │ (para cada puerto en paralelo, límite 64)   │         │
 │              │◄──────────────┤              │              │         │
 │              │  Vec<Service> │              │              │         │
 │              │                                              │         │
 │              │ upsert_services + DISCOVERY_SOURCES          │         │
 │              ├──────────────────────────────────────────────────────►│
 │              │                                              │         │
 │ AppEvent::Devices                                           │         │
 │◄─────────────┤                                              │         │
 │  render      │                                              │         │
```

### Toggle plano / agrupado (UI)

```
g  → alterna ui.list_view entre "flat" y "grouped"
     → persiste en ~/.config/almenara/config.toml  [ui].list_view
     → re-render con cabeceras de sección por device_type cuando grouped
```

---

## 5. API Endpoints (servicios internos)

### `discovery::mdns`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `MdnsListener::start` | `fn(iface: &str) -> Result<MdnsListener>` | Suscribe al grupo 224.0.0.251:5353 |
| `MdnsListener::drain` | `fn(&mut self) -> Vec<MdnsRecord>` | Vacía el buffer desde el último ciclo |
| `MdnsQuery::discover_services` | `async fn(timeout) -> Result<Vec<MdnsRecord>>` | Browse `_services._dns-sd._udp.local` |
| `mdns::parser::parse` | `fn(&[u8]) -> Result<Vec<MdnsRecord>>` | Parser de respuestas |

### `discovery::ssdp`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `SsdpListener::start` | `fn() -> Result<SsdpListener>` | Suscribe a 239.255.255.250:1900 |
| `SsdpListener::drain` | `fn(&mut self) -> Vec<SsdpRecord>` | Notificaciones desde el último ciclo |
| `SsdpQuery::m_search` | `async fn(st: &str, timeout) -> Result<Vec<SsdpRecord>>` | M-SEARCH activo |
| `ssdp::parser::fetch_description` | `async fn(location: Url, timeout) -> Result<UpnpDescription>` | Descarga y parsea el XML |
| `ssdp::parser::parse` | `fn(&[u8]) -> Result<SsdpRecord>` | Parser de NOTIFY / M-SEARCH response |

### `discovery::dhcp` y `discovery::netbios`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `DhcpLeases::read_all` | `fn(paths: &[PathBuf]) -> Result<Vec<Lease>>` | Lee todos los ficheros configurados |
| `dhcp::dnsmasq::parse` | `fn(&str) -> Result<Vec<Lease>>` | Parser específico |
| `dhcp::dhclient::parse` | `fn(&str) -> Result<Vec<Lease>>` | Parser específico |
| `dhcp::networkmanager::parse` | `fn(&str) -> Result<Vec<Lease>>` | Parser específico |
| `Netbios::query_name` | `async fn(ip: Ipv4Addr, timeout) -> Result<NetbiosInfo>` | NBNS query UDP 137 |

### `discovery::fingerprint`, `portscan`, `banner`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Fingerprint::detect` | `fn(&TcpFingerprint) -> Option<OsFamily>` | Devuelve None si confianza baja |
| `PortScan::scan` | `async fn(ip: Ipv4Addr, ports: &[u16], timeout, conc) -> Result<Vec<OpenPort>>` | TCP CONNECT scan |
| `BannerGrab::grab` | `async fn(ip: Ipv4Addr, port: u16, timeout) -> Option<String>` | Lectura inicial (máx. 512 B) |

### `classify`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `classify::device_type` | `fn(&DeviceCtx) -> DeviceType` | OUI + puertos + mDNS + SSDP + hostname |
| `classify::service` | `fn(port: u16, banner: Option<&str>) -> Option<Service>` | Identificación de servicio |

### Repo (nuevas operaciones)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `upsert_service` | `fn(&ServiceUpsert) -> Result<i64>` | Insert/update por (device_id, port, proto) |
| `list_services` | `fn(device_id) -> Result<Vec<Service>>` | Servicios activos de un equipo |
| `mark_stale_services` | `fn(device_id, older_than) -> Result<usize>` | Marca STALE |
| `prune_services` | `fn(older_than) -> Result<usize>` | Purga definitiva |
| `upsert_source` | `fn(device_id, source) -> Result<()>` | Marca de fuente |
| `list_sources` | `fn(device_id) -> Result<Vec<Source>>` | Fuentes que han visto el equipo |
| `set_os_family` | `fn(device_id, Option<OsFamily>) -> Result<()>` | Fingerprint |
| `set_device_type_manual` | `fn(device_id, Option<DeviceType>) -> Result<()>` | Override |

---

## 6. Interfaz de Usuario

### Mapa de navegación (sin cambios estructurales)

```
Equipos ──[g]──► flat ⇄ grouped        (preferencia persistida)
   │
   ├─ a  editar alias (F1)
   ├─ n  editar notas (F1)
   ├─ r  rescan manual (F1)
   ├─ /  búsqueda (F1)
   ├─ s  orden (F1)
   ├─ f  filtro (F1)
   ├─ Enter  notificación "detalle en F3"  (F1)
   └─ ?  Ayuda                              (F1)
```

### Mockup 1 — Modo plano (comportamiento F1, iconos extendidos)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Icono  IP              Hostname            Fabricante     Estado       │
├────────────────────────────────────────────────────────────────────────┤
│ [⌂]  192.168.1.1     router.lan           TP-Link        online       │
│ [▣]  192.168.1.42    laptop-juan.local    Apple          online       │
│ [▯]  192.168.1.57    iPhone-Marta         Apple          online       │
│ [▶]  192.168.1.103   chromecast-sala      Google         online       │
│ [▶]  192.168.1.88    tv-sala              Samsung        online       │
│ [▣]  192.168.1.10    nas-synology         Synology       online       │
│ [P]  192.168.1.20    hp-laserjet.local    HP             online       │
│ [?]  192.168.1.201   ?                    ?              online       │
│ ○    192.168.1.66    iPad                 Apple          offline      │
│                                                                        │
│ 9 equipos · 8 online · 1 offline · modo: privilegiado · [g]agrupar     │
└─[hjkl]mover [g]vista [a]alias [n]notas [s]orden [f]filtrar [/]buscar──┘
```

### Mockup 2 — Modo agrupado

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│                                                              [g]plana │
├────────────────────────────────────────────────────────────────────────┤
│ ── Infraestructura ─────────────────────────────────────────────────── │
│  [⌂] 192.168.1.1    router.lan          TP-Link         online         │
│  [▣] 192.168.1.10   nas-synology        Synology        online         │
│ ── Puestos y servidores ────────────────────────────────────────────── │
│  [▣] 192.168.1.42   laptop-juan.local   Apple           online         │
│ ── Móviles y tablets ───────────────────────────────────────────────── │
│  [▯] 192.168.1.57   iPhone-Marta        Apple           online         │
│  ○   192.168.1.66   iPad                Apple           offline        │
│ ── TV y streaming ──────────────────────────────────────────────────── │
│  [▶] 192.168.1.103  chromecast-sala     Google          online         │
│  [▶] 192.168.1.88   tv-sala             Samsung         online         │
│ ── Impresoras ──────────────────────────────────────────────────────── │
│  [P] 192.168.1.20   hp-laserjet.local   HP              online         │
│ ── Desconocidos ────────────────────────────────────────────────────── │
│  [?] 192.168.1.201  ?                   ?               online         │
│                                                                        │
│ 9 equipos · 8 online · 1 offline · modo: privilegiado · [g]plana       │
└─[hjkl]mover [g]vista [a]alias [n]notas [s]orden [f]filtrar [/]buscar──┘
```

### Mockup 3 — Modo degradado / passive_only

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Icono  IP              Hostname            Fabricante     Estado       │
├────────────────────────────────────────────────────────────────────────┤
│ [⌂]  192.168.1.1     router.lan           TP-Link        online       │
│ [▣]  192.168.1.42    laptop-juan.local    Apple          online       │
│ [▯]  192.168.1.57    iPhone-Marta         Apple          online       │
│ [?]  192.168.1.201   ?                    ?              online       │
│                                                                        │
│ 4 equipos · 4 online · 0 offline · modo: PASIVO (sin CAP_NET_RAW)      │
│ Fuentes activas: mDNS · SSDP · DHCP · /proc · NetBIOS                  │
└─[hjkl]mover [g]vista [a]alias [n]notas [s]orden [f]filtrar [/]buscar──┘
```

### Mockup 4 — Ayuda (fragmento actualizado)

```
│ Vista                                                                  │
│   g                 alternar lista plana / agrupada por categoría      │
│                                                                        │
│ Iconos por tipo                                                        │
│   [⌂] gateway   [▣] pc/server   [▯] móvil/tablet   [●] iot             │
│   [P] impresora [C] cámara      [▶] tv/streaming   [?] desconocido    │
│   ○   offline                                                          │
│                                                                        │
│ Modo                                                                   │
│   privilegiado   CAP_NET_RAW disponible; todos los métodos activos     │
│   pasivo         [scan] passive_only = true; sin tráfico activo       │
│   degradado      sin CAP_NET_RAW; solo fuentes pasivas                 │
└────────────────────────────────────────────────────────────────────────┘
```

### Notas de UX

- Preferencia `[ui].list_view = "flat" | "grouped"` persistida; por defecto `"flat"`.
- `g` cambia la vista y guarda la preferencia (una escritura por pulsación; el fichero se reescribe completo, es pequeño).
- La barra de estado indica explícitamente el modo (`privilegiado` / `pasivo` / `degradado`) y, cuando es pasivo/degradado, la lista de fuentes activas.
- Iconos por `device_type`:
  `gateway` → `[⌂]`, `pc`/`server`/`nas` → `[▣]`, `mobile`/`tablet` → `[▯]`,
  `tv`/`streaming` → `[▶]`, `printer` → `[P]`, `camera` → `[C]`, `iot` → `[●]`,
  `unknown` → `[?]`, cualquier `offline` → `○`.
- No se añaden columnas nuevas a la lista en F2 (en 80 columnas no caben); el `os_family` se muestra en la pestaña Config y se verá en el detalle de F3. `device_type` se ve por el icono.

---

## 7. Lógica de Negocio

### Clasificación de `device_type`

Prioridad descendente (el primero que casa, gana):

```python
def classify(ctx) -> DeviceType:
    if ctx.is_gateway:              return GATEWAY
    if ctx.has_service('ipp') or ctx.vendor in PRINTER_OUIS: return PRINTER
    if ctx.has_service('rtsp') or ctx.has_service('onvif'):  return CAMERA
    if ctx.upnp_type in {'MediaRenderer'} or ctx.mdns in {'_googlecast._tcp','_airplay._tcp'}:
        return STREAMING if ctx.is_tv else TV
    if ctx.vendor in NAS_VENDORS or ctx.has_service('smb') and ctx.has_service('nfs'):
        return NAS
    if ctx.hostname matches /ip(hone|ad)|android.*mobile/:  return MOBILE
    if ctx.hostname matches /ipad|tablet/:                   return TABLET
    if ctx.has_service('ssh') or ctx.has_service('http') and ctx.os_family in {LINUX, WINDOWS}:
        return SERVER if ctx.has_service('22') and ctx.has_service('80') else PC
    if ctx.vendor in IOT_OUIS:      return IOT
    return UNKNOWN
```

El override manual (`device_type_manual`) **siempre** gana sobre la clasificación automática.

### Fingerprint de SO

```python
def detect(tcp_fp) -> Option[OsFamily]:
    ttl = tcp_fp.observed_ttl
    win = tcp_fp.window
    opts = tcp_fp.options           # conjunto de opciones TCP presentes
    score = {'linux': 0, 'windows': 0, 'macos': 0, 'ios': 0, 'android': 0, 'iot': 0}
    if ttl <= 64:   score['linux'] += 2; score['macos'] += 1; score['ios'] += 1
    if ttl <= 128:  score['windows'] += 2; score['android'] += 1
    if win in {64240, 65535}: score['windows'] += 1
    if win == 5840: score['linux'] += 1
    if 'timestamp' in opts:   score['linux'] += 1
    if 'sack_ok' in opts:     score['windows'] += 1; score['linux'] += 1
    # ...
    best = max(score, key=score.get)
    return best if score[best] >= CONFIDENCE_THRESHOLD else None
```

`CONFIDENCE_THRESHOLD = 4`. Si no se supera, `os_family = NULL` (se muestra `unknown`).

### Port scan bajo demanda

- Se ejecuta cuando: (a) el equipo se descubre por primera vez; (b) el equipo cambia de IP o MAC; (c) el usuario pulsa `r`.
- Nunca en cada ciclo periódico (evita saturar la red).
- Concurrencia 64, timeout 500 ms, máximo 1024 IPs por ciclo.
- Los resultados se persisten en `DEVICE_SERVICES` vía upsert por `(device_id, port, protocol)`.

### Banner grabbing

- Solo para puertos de la lista `[scan].top_ports` que hayan resultado **abiertos**.
- Lectura máxima 512 bytes, timeout 1 s.
- Se sanea el banner (se recortan bytes no imprimibles, se trunca a 128 chars) antes de persistir.

### Precedencia de hostname

Orden de preferencia al fusionar fuentes:

```
1. alias manual del usuario         (DEVICES.alias)
2. mDNS .local                       (si no es IP)
3. NetBIOS                           (si no vacío y no es *SMBSERVER*)
4. DHCP lease                        (si lease activo)
5. reverse DNS                       (heredado F1)
6. último hostname conocido          (no se pisa con NULL)
```

### `passive_only`

- Si `[scan].passive_only = true`: no se emiten ARP scan, ICMP sweep, mDNS browse activo, M-SEARCH SSDP, port scan ni banner grabbing.
- Se mantienen: `/proc/net/arp`, mDNS listener pasivo, SSDP listener pasivo, DHCP leases, NetBIOS, reverse DNS.
- La barra de estado muestra `PASIVO`.
- Aplica con independencia de si hay `CAP_NET_RAW`.

### Validación de configuración (F2)

- `top_ports`: lista de u16 únicos, entre 1 y 65535, máx. 64 puertos.
- `dhcp_lease_paths`: rutas existentes o se descartan con aviso.
- `passive_only`: booleano.
- `[ui].list_view`: `"flat" | "grouped"`.

---

## 8. Requisitos No Funcionales (novedades)

### Seguridad

- Port scan limitado a equipos ya descubiertos por fuentes L2 (no se escanea la red a ciegas).
- Banner grabbing con timeout corto y lectura máxima; no se envían payloads activos.
- El modo `passive_only` garantiza cero tráfico activo (auditable en logs).

### Protección de datos (RGPD)

- Nuevos datos persistidos: servicios expuestos, banners (potencialmente sensibles), os_family, tipo manual. Base legal y minimización: solo se guarda el banner saneado y truncado; el banner completo no se conserva.
- Retención de `DEVICE_SERVICES` ligada a `events_retention_days` (90 días por defecto) para servicios STALE.

### Rendimiento

- Ciclo F2 completo con `/24` y 10 equipos nuevos: ≤ 20 s con CAP_NET_RAW y ≤ 5 s en modo pasivo.
- Port scan de TOP-20 sobre 10 hosts: ≤ 3 s.
- Ciclo de render objetivo ≤ 16 ms (sin cambios respecto a F1).
- Uso de CPU en reposo ≤ 8 % (mDNS + SSDP listeners pasivos están activos, coste bajo).

### Accesibilidad

- Sin cambios respecto a F1; los iconos nuevos siguen el mismo esquema (ASCII, no emoji, contraste ≥ 4.5:1).

---

## 9. Integraciones

- **UPnP**: descarga del XML de descripción con timeout 2 s y tamaño máximo 256 KB. Solo `http://` y `https://`; no se siguen redirecciones fuera del propio dispositivo.
- **mDNS**: parser limitado a registros A, AAAA, PTR, SRV, TXT y HINFO.
- **NetBIOS**: protocolo NBNS estándar (RFC 1001/1002), sin extensiones.

---

## 10. Decisiones Técnicas (ADR-lite)

**ADR-08 · `hickory-proto` para mDNS (vs. `mdns`, `trust-dns`, parser propio)**
`mdns` está poco mantenido; `hickory-proto` es el fork activo de `trust-dns` y cubre mDNS/DNS-SD completo. Parser propio es viable pero reinventa un protocolo con muchos casos. Se elige `hickory-proto`.

**ADR-09 · `ssdp` + `reqwest` para SSDP/UPnP**
`ssdp` ofrece parsing del mensaje; `reqwest` se usa solo para descargar el XML de descripción (no se necesita un cliente HTTP completo, pero evita escribir uno). Alternativa descartada: `rumqttc`-style de implementar HTTP a mano — innecesario.

**ADR-10 · Parsers DHCP propios (vs. `dhcp4r`, `dhcproto`)**
Los crates existentes implementan el protocolo DHCP, no los formatos de *lease file*, que son texto y muy estables. Un parser de 100 líneas por formato es más mantenible que adaptar un crate pensado para otra cosa.

**ADR-11 · NetBIOS NBNS propio (vs. `nbtscan` como dependencia)**
`nbtscan` es un binario C, no un crate. La implementación del NBNS query es ~150 líneas y evita dependencia externa. Se elige propio.

**ADR-12 · Port scan TCP CONNECT (vs. SYN scan)**
SYN scan requiere `CAP_NET_RAW` y es más ruidoso para IDS. TCP CONNECT funciona sin privilegios, es detectable igual pero más "legítimo", y encaja con `passive_only` (que no aplica igual a SYN). Se elige CONNECT.

**ADR-13 · Port scan solo bajo demanda (vs. cada ciclo)**
Escanear 20 puertos × 254 IPs cada 60 s es agresivo para redes domésticas y para IDS básicos. Se lanza al descubrir el equipo o al pedirlo con `r`; el resto de ciclos no escanea puertos. Trade-off: puertos abiertos tarde pueden tardar en detectarse hasta el siguiente `r`.

**ADR-14 · Fingerprint con umbral de confianza (vs. reportar siempre)**
Reportar `os_family` siempre, aunque sea con baja confianza, genera falsos positivos. Se exige umbral; si no se supera, `NULL`. Coste: algunos equipos se quedan en `unknown` para siempre. Aceptable porque el override manual está disponible.

**ADR-15 · `DEVICE_SERVICES` como tabla (vs. JSON en `DEVICES`)**
Tabla permite consultas por puerto/servicio, marcar STALE, purgar por dispositivo con FK, y alimentará la pestaña Conexiones de F3. El JSON en `DEVICES` sería más simple pero peor para F3+.

**ADR-16 · Clasificación de `device_type` con override manual**
`device_type_manual` nullable en `DEVICES`. Si no es NULL, gana sobre `device_type`. Se implementa así (en vez de "el automático solo actualiza si manual es NULL") porque el manual persiste aunque el automático cambie de idea.

**ADR-17 · Modo `passive_only` como flag de config**
No es un modo degradado; es una decisión consciente del usuario. Se documenta en Ayuda y se refleja en la barra de estado. Se puede activar con o sin `CAP_NET_RAW`.

---

## 11. Plan de Desarrollo

**Supuestos:** 1 desarrollador, ~15 h/semana, F1 estable como base.

### Sprint 2.1 — Migración + DAOs (≈ 10 h)
- Migración v2 aditiva
- DAO `device_services`
- DAO `discovery_sources`
- DAO `devices` extendido
- Tests de migración v1→v2

### Sprint 2.2 — Descubrimiento pasivo (≈ 16 h)
- mDNS listener pasivo + parser
- SSDP listener pasivo + parser
- DHCP leases (3 formatos)
- NetBIOS NBNS
- Orquestación en el ciclo
- Fuentes → `DISCOVERY_SOURCES`

### Sprint 2.3 — Descubrimiento activo (≈ 18 h)
- mDNS browse activo
- SSDP M-SEARCH + fetch XML
- Port scan + banner grabbing
- Fingerprint de SO
- Modo `passive_only`
- Configuración `[scan].top_ports`, `[scan].passive_only`

### Sprint 2.4 — Clasificación + TUI agrupada (≈ 14 h)
- Clasificador `device_type`
- Iconos nuevos en el tema
- Vista agrupada + toggle `g` + preferencia persistida
- Barra de estado con modo y fuentes
- Ayuda actualizada

### Sprint 2.5 — Cierre (≈ 8 h)
- Tests unitarios de parsers y clasificador
- Tests de integración con `passive_only=true`
- README actualizado
- Informe de implementación

**Estimación total F2:** **~66 h → 4–5 semanas**.

---

## 12. Conexiones con Otras Fases

- **F3 (Tráfico en vivo)** usará `DEVICE_SERVICES` para saber qué puertos están abiertos por dispositivo y correlacionar con conexiones activas. No hace falta cambiar el esquema.
- **F4 (Protocolos/apps)** usará la información de servicios y banners como base para la inferencia de aplicación.
- **F6 (Alertas)** podrá usar `DEVICE_SERVICES` (nuevo servicio abierto en equipo conocido) y `DISCOVERY_SOURCES` (fuente nueva) como señales.
- **F7 (Integraciones)** puede añadir SNMP como fuente adicional en `DISCOVERY_SOURCES` con un nuevo valor `source = "snmp"`.
