# Almenara - Fase 3: Tráfico en vivo (pasivo + local)

## Especificación Funcional

**Versión:** 1.0
**Fecha:** 2026-11-10
**Cliente:** Uso personal (desarrollador)

---

## 1. Visión General

La Fase 3 convierte a Almenara en un monitor de tráfico en vivo. Captura paquetes con AF_PACKET + TPACKET_V3 sobre las interfaces activas, agrega bytes y paquetes por dispositivo, mantiene sparklines en memoria (60s y 5min), descubre conexiones activas vía `/proc/net/{tcp,udp}{,6}` y conntrack, y activa las pestañas **Tráfico** y **Conexiones** de la TUI. El detalle de cada equipo pasa a ser un panel master-detail con sparkline, top-5 puertos, servicios de F2 y conexiones.

**Modo pasivo por defecto** y **visibilidad honesta**: en red conmutada Almenara ve el 100% del tráfico del propio host y de broadcast/multicast, y solo una parte del unicast de terceros. La barra de estado declara la visibilidad real (`propia + broadcast`) y el estado de captura (`capturando · N pps · filtro: …`). No se finge cobertura completa.

**Objetivos principales:**
1. Capturar paquetes sin dependencias del sistema (AF_PACKET + TPACKET_V3, sin libpcap).
2. Agregar tráfico por dispositivo (bytes/paquetes ↑↓, pico en ventana) en memoria.
3. Mantener sparklines 60s (1 punto/s) y 5min (1 punto/5s) por dispositivo.
4. Detectar conexiones activas con estado, bytes y proceso local cuando aplique.
5. Activar pestañas Tráfico (ranking top-10) y Conexiones (tabla plana ordenable) y el panel detalle de equipo.
6. Persistir un snapshot mínimo (último valor por dispositivo cada 5s) para no arrancar con TUI vacía.

**Contexto:** evolución directa de F1+F2. Migración v3 aditiva; toda BD de F1/F2 sigue funcionando sin pérdida de datos. `passive_only` se respeta: no se emite tráfico, pero escuchar no genera tráfico.

---

## 2. Arquitectura Técnica

### Stack tecnológico (novedades respecto a F2)

| Capa | Tecnología | Motivo |
|------|-----------|--------|
| Captura | **AF_PACKET + TPACKET_V3** (Rust + `nix` + `libc`) | Sin `libpcap`, binario único, control total del ring |
| Filtro | **BPF clásico** (attach al socket vía `setsockopt SO_ATTACH_FILTER`) | Estándar tcpdump, potente, sin deps |
| Parser | Propio (Ethernet, IPv4, IPv6, TCP, UDP, ICMP) | ~600 líneas, cero deps, casos acotados |
| DNS / SNI | Propio (extracción de QNAME y TLS ClientHello SNI) | Sin crate TLS; parseo de bytes suficiente |
| Conexiones | `/proc/net/{tcp,udp}{,6}` + `/proc/net/nf_conntrack` best-effort | Fuente del kernel, sin deps |
| Procesos locales | `/proc/[pid]/fd/*` → inode | Atribución de conexiones del host a PID |
| Ring buffer | 64 MB fijo (TPACKET_V3 block 1 MB, frame 4 KB) | Configurable en F7 |
| Replay (F7) | `pcap` como feature no default | Preparado, no activado en F3 |

### Estructura de carpetas (novedades)

```
src/
├── capture/                    # NUEVO módulo raíz
│   ├── mod.rs                  # Capture::start/stop/drain, ciclo de vida del ring
│   ├── afpacket.rs             # socket AF_PACKET + TPACKET_V3 + SO_ATTACH_FILTER
│   ├── bpf.rs                  # compilación de filtro BPF clásico
│   ├── parser.rs               # Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP
│   ├── dns.rs                  # extracción de QNAME (puerto 53)
│   ├── sni.rs                  # extracción de SNI TLS ClientHello (puerto 443)
│   ├── aggregate.rs            # agregación por dispositivo y global
│   ├── windows.rs              # ring buffers 60s / 5min
│   ├── conntrack.rs            # /proc/net/{tcp,udp}{,6} + nf_conntrack
│   └── process.rs              # /proc/[pid]/fd → inode → pid + comm
├── repo/
│   ├── traffic_snapshot.rs     # NUEVO DAO
│   ├── connections.rs          # NUEVO DAO
│   └── migrations.rs           # migración v3
└── tui/views/
    ├── traffic.rs              # NUEVO: ranking top-10
    ├── connections.rs          # NUEVO: tabla plana ordenable
    └── device_detail.rs        # NUEVO: panel master-detail
```

### Diagrama de arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                       TUI (ratatui)                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
│  │ Equipos  │ │ Tráfico  │ │Conexiones│ │ Detalle equipo   ││
│  │(F1+F2)   │ │ (F3)     │ │ (F3)     │ │ (F3, master-     ││
│  │          │ │          │ │          │ │  detail)         ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────────┘│
└───────┼────────────┼────────────┼──────────────┼────────────┘
        │            │            │              │
        └────────────┴─────┬──────┴──────────────┘
                           ▼
                   ┌────────────────┐
                   │   App State    │
                   └───────┬────────┘
                           │
                           ▼
                   ┌────────────────┐
                   │   Event Bus    │
                   └───────┬────────┘
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
     ┌──────────────┐ ┌───────────┐ ┌──────────────┐
     │  Capture     │ │Conntrack  │ │  Scanner F2  │
     │  (AF_PACKET) │ │  /proc    │ │  (heredado)  │
     └──────┬───────┘ └─────┬─────┘ └──────┬───────┘
            │               │              │
            ▼               ▼              ▼
     ┌──────────────┐ ┌───────────┐ ┌──────────────┐
     │  Parser +    │ │  Process  │ │   Repo       │
     │  DNS + SNI   │ │ attribution│ │  (SQLite)    │
     └──────┬───────┘ └─────┬─────┘ └──────┬───────┘
            │               │              │
            ▼               ▼              ▼
     ┌──────────────┐ ┌───────────┐ ┌──────────────┐
     │ Aggregator + │ │Connection │ │ TRAFFIC_SNAP │
     │  Windows     │ │  cache    │ │  + CONNECTIONS│
     │  (memoria)   │ │ (memoria) │ │  (5s)        │
     └──────────────┘ └───────────┘ └──────────────┘
```

---

## 3. Modelo de Datos

### Migración v3 (aditiva, no rompe F1/F2)

```sql
-- v3 — Fase 3: tráfico en vivo

CREATE TABLE TRAFFIC_SNAPSHOT (
  device_id    INTEGER PRIMARY KEY REFERENCES DEVICES(id) ON DELETE CASCADE,
  bytes_in     INTEGER NOT NULL DEFAULT 0,
  bytes_out    INTEGER NOT NULL DEFAULT 0,
  packets_in   INTEGER NOT NULL DEFAULT 0,
  packets_out  INTEGER NOT NULL DEFAULT 0,
  peak_bps     INTEGER NOT NULL DEFAULT 0,
  window_s     INTEGER NOT NULL DEFAULT 60,
  updated_at   TIMESTAMP NOT NULL
);

CREATE TABLE CONNECTIONS (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id    INTEGER NULL REFERENCES DEVICES(id) ON DELETE SET NULL,
  protocol     TEXT NOT NULL,         -- 'tcp' | 'udp' | 'icmp' | 'other'
  src_ip       TEXT NOT NULL,
  src_port     INTEGER NULL,
  dst_ip       TEXT NOT NULL,
  dst_port     INTEGER NULL,
  state        TEXT NULL,             -- 'ESTABLISHED' | 'TIME_WAIT' | ...
  bytes_in     INTEGER NOT NULL DEFAULT 0,
  bytes_out    INTEGER NOT NULL DEFAULT 0,
  first_seen   TIMESTAMP NOT NULL,
  last_seen    TIMESTAMP NOT NULL
);

CREATE INDEX IDX_CONN_DEVICE     ON CONNECTIONS(device_id);
CREATE INDEX IDX_CONN_LAST_SEEN  ON CONNECTIONS(last_seen);
CREATE INDEX IDX_CONN_STATE      ON CONNECTIONS(state);
```

`CONNECTIONS` es una tabla **caliente**: las filas se purgan al cerrarse la conexión (timeout). No es histórico; el histórico es F5.

### Diagrama E-R extendido (solo parte nueva)

```
          ┌──────────────────┐
          │     DEVICES      │  (F1+F2)
          └──┬───────────┬───┘
             │ 1         │ 1
             │           │
             │ 0..1      │ 0..N
    ┌────────▼───────┐  ┌▼────────────────┐
    │TRAFFIC_SNAPSHOT│  │  CONNECTIONS    │  ◄─── NUEVO F3
    ├────────────────┤  ├─────────────────┤
    │ device_id (PK, │  │ id (PK)         │
    │  FK)           │  │ device_id (FK,  │
    │ bytes_in       │  │  NULL = host o  │
    │ bytes_out      │  │  desconocido)   │
    │ packets_in     │  │ protocol        │
    │ packets_out    │  │ src_ip/port     │
    │ peak_bps       │  │ dst_ip/port     │
    │ window_s       │  │ state           │
    │ updated_at     │  │ bytes_in/out    │
    └────────────────┘  │ first_seen      │
                        │ last_seen       │
                        └─────────────────┘

  Notas:
   · TRAFFIC_SNAPSHOT: 1 fila por dispositivo, se sobrescribe cada 5 s.
   · CONNECTIONS: caliente; purga por timeout (TCP 300 s, UDP 60 s, ICMP 30 s).
   · device_id NULL en CONNECTIONS = el equipo no está en DEVICES (host propio
     con IP fuera de rango, conexión de broadcast, o equipo aún no descubierto).
```

### Diagrama de estados — CONNECTIONS

```
   (primera trama con 5-tuple nueva)
              │
              ▼
       ┌──────────────┐
       │   ACTIVE     │  first_seen = last_seen = now
       │              │  bytes_in/out = 0
       └──────┬───────┘
              │ tráfico nuevo
              ├────────────► ACTIVE (last_seen actualizado, bytes += n)
              │
              │ timeout sin tráfico:
              │  · TCP: 300 s
              │  · UDP: 60 s
              │  · ICMP: 30 s
              ▼
       ┌──────────────┐
       │   EXPIRED    │  ← purga definitiva (DELETE)
       └──────────────┘

   Transiciones inválidas:
    · EXPIRED sin purga (todo expired se borra)
    · device_id FK apunta a DEVICES inexistente  (ON DELETE SET NULL)
```

---

## 4. Flujos de Trabajo

### Arranque de captura

```
┌─────────────────────┐
│ arranque            │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ detect caps         │── sin CAP_NET_RAW ──► captura deshabilitada
│ (CAP_NET_RAW)       │     (aviso en barra + Ayuda)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ leer config         │
│ [capture].enabled   │
│ .filter .inspect_.. │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ compilar BPF        │── error ──► notificación + captura sin filtro
│ (BPF clásico)       │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ abrir socket        │
│ AF_PACKET + TPACKET │
│ ring 64 MB          │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ SO_ATTACH_FILTER    │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ hilo captura + poll │   (en paralelo con la TUI)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ notificación única  │
│ "capturando en      │
│  <iface>"           │
└─────────────────────┘
```

### Ciclo de captura (hilo dedicado)

```
┌───────────────────────┐
│ poll(socket, 100 ms)  │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ drain blocks TPACKET  │   (hasta 64 bloques × 1 MB)
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ por cada frame:       │
│ · parser::parse       │── error ──► contador `parse_errors`, sigue
│ · extraer metadatos   │
│ · si payload permitido│
│   → dns::extract /    │
│     sni::extract      │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ aggregate.update:     │
│ · 5-tuple → conexión  │
│ · bytes/packets por   │
│   dispositivo (in/out)│
│ · ventanas 60s/5min   │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ cada 5 s:             │
│ · upsert_snapshot     │
│ · prune_expired       │
│ · purga por timeout   │
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│ emit AppEvent::Traffic│
│ (cada 1 s, con delta) │
└───────────────────────┘
```

### Detección de conexiones (dos fuentes en paralelo)

```
A) Captura de paquetes:
   ┌────────────────────────────────────────┐
   │ 5-tuple (proto, src_ip, src_port,      │
   │  dst_ip, dst_port)                     │
   │ + flags TCP                           │
   │ + bytes acumulados                     │
   └────────────────────┬───────────────────┘
                        │
B) /proc/net/{tcp,udp}{,6} + conntrack:
   ┌────────────────────────────────────────┐
   │ · sockets del propio host              │
   │ · estado del kernel                     │
   │ · inode → /proc/[pid]/fd → pid + comm │
   └────────────────────┬───────────────────┘
                        ▼
                ┌───────────────────┐
                │  Merge por        │
                │  5-tuple          │
                └─────────┬─────────┘
                          ▼
                ┌───────────────────┐
                │ CONNECTIONS       │
                │ (memoria + SQLite)│
                └───────────────────┘

Atribución de device_id:
  · si src_ip o dst_ip ∈ DEVICES.ip → ese device
  · si es IP propia del host → device_id NULL + tag "[host]"
  · si es broadcast/multicast → device_id NULL + tag "[broadcast]"
  · si no hay match → device_id NULL (equipo no inventariado)
```

### Secuencia — paquete individual

```
Kernel   hilo-capture   parser       dns/sni     aggregate    SQLite
   │          │            │             │            │            │
   │  frame   │            │             │            │            │
   ├─────────►│            │             │            │            │
   │          │ parse      │             │            │            │
   │          ├───────────►│             │            │            │
   │          │  Metadata  │             │            │            │
   │          │◄───────────┤             │            │            │
   │          │            │             │            │            │
   │          │ si payload permitido:    │            │            │
   │          ├────────────┼────────────►│            │            │
   │          │            │             │            │            │
   │          │◄───────────┼─────────────┤ qname/sni  │            │
   │          │            │             │            │            │
   │          │ update (5-tuple + bytes) │            │            │
   │          ├────────────┼─────────────┼───────────►│            │
   │          │            │             │            │            │
   │          │ (5 s: snapshot + prune)  │            │            │
   │          ├────────────┼─────────────┼────────────┼───────────►│
```

---

## 5. API Endpoints (servicios internos)

### `capture`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Capture::start` | `fn(cfg: &CaptureConfig, ifaces: Vec<Interface>) -> Result<Capture>` | Abre socket, aplica BPF, lanza hilo |
| `Capture::stop` | `fn(self) -> Result<()>` | Cierra socket, para hilo |
| `Capture::drain` | `fn(&self) -> Vec<PacketMeta>` | Paquetes capturados desde la última llamada |
| `Capture::stats` | `fn(&self) -> CaptureStats` | pps, total, drops, parse_errors |

### `capture::bpf`, `capture::parser`, `capture::dns`, `capture::sni`

| Operación | Firma |
|-----------|-------|
| `Bpf::compile` | `fn(expr: &str) -> Result<BpfProgram>` |
| `Parser::parse` | `fn(&[u8]) -> Result<PacketMeta>` |
| `Dns::extract` | `fn(&[u8]) -> Option<DnsInfo>` |
| `Sni::extract` | `fn(&[u8]) -> Option<String>` |

### `capture::aggregate`, `capture::windows`

| Operación | Firma |
|-----------|-------|
| `Aggregator::update` | `fn(&mut self, meta: &PacketMeta)` |
| `Aggregator::snapshot` | `fn(&self) -> AggregatorSnapshot` |
| `Windows::push` | `fn(&mut self, ts: Instant, bytes: u64)` |
| `Windows::series_60s` | `fn(&self) -> [u64; 60]` |
| `Windows::series_5min` | `fn(&self) -> [u64; 60]` |

### `capture::conntrack`, `capture::process`

| Operación | Firma |
|-----------|-------|
| `Conntrack::read` | `fn() -> Result<Vec<ConntrackEntry>>` |
| `ProcNet::read_tcp` | `fn() -> Result<Vec<ProcNetEntry>>` |
| `ProcNet::read_udp` | `fn() -> Result<Vec<ProcNetEntry>>` |
| `Process::attribute` | `fn(inode: u64) -> Option<(u32, String)>` |

### Repo (nuevas operaciones)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `upsert_snapshot` | `fn(&Snapshot) -> Result<()>` | Upsert por device_id |
| `list_snapshots` | `fn() -> Result<Vec<Snapshot>>` | Para arrancar con datos |
| `upsert_connection` | `fn(&ConnectionUpsert) -> Result<i64>` | Insert/update por 5-tuple |
| `list_connections` | `fn(filter: Option<&str>) -> Result<Vec<Connection>>` | Vista Conexiones |
| `prune_expired_connections` | `fn(now: Instant) -> Result<usize>` | Purga por timeout |
| `get_connection` | `fn(id: i64) -> Result<Option<Connection>>` | Para tecla `v` |

---

## 6. Interfaz de Usuario

### Mapa de navegación (novedades en negrita)

```
Equipos ──[g]──► flat ⇄ grouped          (F2)
   │
   ├─ Enter  ──► **Detalle de equipo (F3, master-detail)**
   ├─ a  alias · n  notas · t  tipo manual · r  rescan · / · s · f · ?
   │
Tráfico (F3) ──► ranking top-10
   │
   └─ Enter  ──► **Detalle de equipo (drill-down)**
   │
Conexiones (F3) ──► tabla plana ordenable
   │
   └─ **v**  ──► cabeceras IP/TCP de conexión seleccionada (ya en memoria)
   │
Histórico (placeholder F5) · Alertas (placeholder F6) · Config · Ayuda
```

### Mockup 1 — Pestaña Tráfico (ranking top-10)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Ranking en vivo (ventana 60s)                                          │
├────────────────────────────────────────────────────────────────────────┤
│ #  Dispositivo         Tipo  ↓ in      ↑ out      Total      sparkline │
│ 1  [⌂] router.lan      gw    12.4 M/s  2.1 M/s   14.5 M/s   ▂▃▅▇▆▅▃▂  │
│ 2  [▣] nas-synology    nas   4.8 M/s   1.2 M/s   6.0 M/s    ▃▅▆▇▆▅▄▃  │
│ 3  [▣] laptop-juan     pc    1.4 M/s   320 K/s   1.7 M/s    ▁▂▂▁▂▃▂▁  │
│ 4  [▶] chromecast      tv    890 K/s   12 K/s    902 K/s    ▂▃▂▁▁▁▂▃  │
│ 5  [▯] iPhone-Marta    mob   120 K/s   45 K/s    165 K/s    ▁▁▂▁▁▁▁▂  │
│ 6  [●] tv-sala         tv    3 K/s     1 K/s     4 K/s      ▁▁▁▁▁▁▁▁  │
│ 7  [P] hp-laserjet     print 0         0         0          ────────  │
│ 8  [C] cam-garaje      cam   850 K/s   2 K/s     852 K/s    ▂▂▃▄▃▂▁▁  │
│ 9  [?] 192.168.1.201   ?     0         0         0          ────────  │
│ 10 ○  iPad             mob   0         0         0          ────────  │
│                                                                        │
│ Total observado: ↓ 20.3 M/s · ↑ 3.7 M/s · 47 conexiones                │
│ Capturando · 2.4 K pps · filtro: (ninguno) · visibilidad: propia+bcast │
└─[hjkl]mover [Enter]detalle [s]ordenar [f]filtrar [?]ayuda──────────────┘
```

### Mockup 2 — Pestaña Conexiones (tabla plana)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Conexiones activas (47) · filtro: todas                                │
├────────────────────────────────────────────────────────────────────────┤
│ Proto  Origen              Destino             Estado    ↑      ↓  Edad│
│ tcp    [▣]192.168.1.42:54… 140.82.x.x:443     ESTABL    12 K   200K 2m │
│ tcp    [▣]192.168.1.42:54… 1.1.1.1:443        ESTABL    8 K    120K 5m │
│ udp    [▯]192.168.1.57:53  8.8.8.8:53         —         —      —  1m  │
│ udp    [host]192.168.1.10… 224.0.0.251:5353   —         —      —  3s  │
│ tcp    [host]192.168.1.10… 192.168.1.42:22    ESTABL    240 K  40K 1m │
│ tcp    [⌂]192.168.1.1:80   192.168.1.57:49…   TIME_WAIT —      —  30s │
│ udp    [broadcast]:67      255.255.255.255:68 —         —      —  45s │
│                                                                        │
│ [host] = proceso local · [broadcast] = multidifusión                   │
└─[hjkl]mover [v]cabeceras [s]ordenar [f]filtrar [x]purgar [?]ayuda─────┘
```

### Mockup 3 — Detalle de equipo (master-detail, ≥100 columnas)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Equipos (9)          │ Detalle: laptop-juan (192.168.1.42)             │
│ ───────────────────  │──────────────────────────────────────────────── │
│ ▶[⌂] router     14.5M│ [▣]  Apple · pc · macOS · online (visto 2s)    │
│  [▣] nas        6.0M │ MAC: 3c:22:fb:xx:yy:zz · eth0                   │
│  [▣] laptop     1.7M │                                                  │
│  [▶] chromecast 902K │ Tráfico                                           │
│  [▯] iPhone     165K │ 60s:  ▂▃▅▇▆▅▃▂▂▃▅▆▇▆▅▄▃▂▂▁▂▃▅▆▇▆▅▄▃▂▂▁▂▃▅▆    │
│  [●] tv-sala    4K   │   ↓ 1.4 M/s   ↑ 320 K/s   pico 1.9 M/s         │
│  [P] hp-laser   0    │ 5min: ▁▂▂▁▂▃▂▁▂▁▂▂▁▂▁▂▂▁▂▂▁▂▂▁▂▁▂▁▁▂▁▂▁▂▁▂    │
│  [C] cam-garaje 852K │                                                  │
│  [?] 192.168.1… 0    │ Top puertos (5)      Conexiones activas (5)       │
│  ○  iPad        0    │  443/tcp  1.5M/s     → 140.82.x.x:443  EST 1m   │
│                      │  22/tcp   280K/s     → 1.1.1.1:443     EST 5m   │
│                      │  53/udp   2K/s       → 8.8.8.8:53      udp 1m   │
│                      │  80/tcp   3K/s       → 93.184.x.x:80   EST 30s  │
│                      │  1883/tcp 0          → 192.168.1.10:22 EST 1m   │
│                      │                                                  │
│                      │ Servicios (F2): 22/ssh · 443/https · 5900/rfb   │
└─[hjkl]mover [Tab]panel [Esc]cerrar [v]cabeceras [?]ayuda───────────────┘
```

### Mockup 4 — Modo degradado / sin CAP_NET_RAW (captura deshabilitada)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ┐
│ Tráfico                                                                │
├────────────────────────────────────────────────────────────────────────┤
│ Captura deshabilitada: requiere CAP_NET_RAW.                           │
│ Consulta la pestaña Ayuda para habilitar la captura (setcap).          │
│                                                                        │
│ Snapshot del último ciclo capturado (hace 12 min):                     │
│  router 14.5M · nas 6.0M · laptop 1.7M · chromecast 902K · …          │
│                                                                        │
│ Modo: degradado (sin CAP_NET_RAW) · ver Ayuda                          │
└────────────────────────────────────────────────────────────────────────┘
```

### Notas de UX

- Barra de estado ampliada (3 líneas en ≥100 columnas, 2 en <100):
  `equipos · online · offline · modo · modo captura`
  `capturando · N pps · filtro: …`
  `visibilidad: propia + broadcast`
- `[host]` y `[broadcast]` como etiquetas de color distinto (dim) en la tabla de conexiones.
- Sparklines usan bloques Unicode `▁▂▃▄▅▆▇█` (compatibles con NO_COLOR). Sin color: los caracteres ya diferencian la magnitud.
- En `NO_COLOR=1`, el estado de captura se indica con prefijo textual `[CAP]` / `[CAP:off]`.
- Detalle master-detail: `Tab` alterna foco entre panel izquierdo (lista) y derecho (detalle). `Esc` cierra el panel derecho y vuelve a lista ancha.
- `v` sobre conexión abre un panel inferior (no modal) con las cabeceras IP/TCP ya en memoria. `Esc` lo cierra.

---

## 7. Lógica de Negocio

### Agregación por dispositivo

```python
def on_packet(meta: PacketMeta, devices_by_ip: Map[ip, Device]):
    src_dev = devices_by_ip.get(meta.src_ip)
    dst_dev = devices_by_ip.get(meta.dst_ip)

    # Un paquete puede "pertenecer" a dos dispositivos (src y dst)
    if src_dev:
        agg[src_dev.id].bytes_out   += meta.len
        agg[src_dev.id].packets_out += 1
        agg[src_dev.id].window.push(now, meta.len)
    if dst_dev:
        agg[dst_dev.id].bytes_in    += meta.len
        agg[dst_dev.id].packets_in  += 1
        agg[dst_dev.id].window.push(now, meta.len)

    # Broadcast/multicast se cuentan como tráfico global, no por dispositivo
    if meta.is_broadcast:
        global.broadcast_bytes += meta.len
```

### `peak_bps` en ventana 60s

```
peak_bps = max( bytes de cada segundo en los últimos 60 s )
```

Se calcula on-demand al construir el snapshot; no se recalcula en cada paquete.

### Ventanas deslizantes

- `series_60s`: 60 puntos, 1 por segundo (bucketización por `floor(now.second)`).
- `series_5min`: 60 puntos, 1 cada 5 s (bucketización por `floor(now.minute) × 12 + floor(now.second/5)`).
- Cada `Windows` es un `VecDeque<u64>` de longitud fija (60). Al pushear un paquete se suma al bucket actual; cada tick de 1 s (o 5 s) se avanza el deque.

### Timeouts de conexión

| Protocolo | Sin tráfico | Estado a `EXPIRED` |
|-----------|-------------|--------------------|
| TCP ESTABLISHED | 300 s | Purga |
| TCP TIME_WAIT / CLOSE_WAIT | 60 s | Purga |
| UDP | 60 s | Purga |
| ICMP | 30 s | Purga |

La purga se lanza cada ciclo de snapshot (5 s).

### Atribución de `device_id` a conexión

```
orden de preferencia:
1. src_ip o dst_ip ∈ DEVICES.ip         → ese device
2. src_ip == propia IP y dst_ip ∉ DEVICES → device_id = NULL, tag = "[host]"
3. dst_ip == propia IP y src_ip ∉ DEVICES → device_id = NULL, tag = "[host]"
4. broadcast (dst ∈ 224.0.0.0/4, 255.255.255.255, ff00::/8)
                                          → device_id = NULL, tag = "[broadcast]"
5. resto                                  → device_id = NULL, tag = "[?]"
```

### Extracción DNS y SNI

```python
def dns_extract(payload: bytes) -> Option<DnsInfo>:
    # Solo si payload[0..2] (puerto 53 UDP) y cabecera DNS válida
    if len(payload) < 12: return None
    flags = u16(payload[2:4])
    if flags & 0x8000: return None           # respuesta, no consulta
    qname = parse_qname(payload[12:])        # compresión punteros
    return DnsInfo(qname=qname) if qname else None

def sni_extract(payload: bytes) -> Option[str]:
    # Solo puerto 443, ClientHello TLS
    if payload[0] != 0x16: return None       # handshake
    if payload[5] != 0x01: return None       # ClientHello
    # ... parsear extension server_name
    return server_name
```

Ambos solo se ejecutan si `[capture].inspect_payload = true` o `[capture].dns_attribution = true` / `sni_attribution = true`.

### Payload y privacidad

- Por defecto `inspect_payload = false`: el payload se **descarta inmediatamente** tras extraer metadatos. Ni siquiera se copia a memoria.
- Con `inspect_payload = true` (o con `dns_attribution`/`sni_attribution` activados): se extrae solo lo necesario (QNAME o SNI), se descarta el resto. **Nunca se persiste el payload.**
- La tecla `v` muestra cabeceras IP/TCP de una conexión seleccionada. Esas cabeceras están en `PacketMeta`, no en el payload.

### `max_pps` y aviso

- Si `max_pps > 0` y la captura supera ese umbral en la última ventana de 1 s, se descartan paquetes hasta que baje, y se emite una notificación **una vez por minuto** (`"captura limitada a N pps"`).
- Estado visible en la barra: `2.4 K pps (límite 5 K)` cuando `max_pps > 0`.

### Filtro BPF

- Se compila con `libc::bpf_program` desde expresión clásica (`tcp and port 80`, `not port 22`, etc.).
- Si la compilación falla, se avisa en notificación + log y se abre socket **sin filtro**. `[capture].enabled` no se cambia.

---

## 8. Requisitos No Funcionales (novedades)

### Seguridad y privacidad

- Payload descartado inmediatamente por defecto. Nunca se persiste.
- Metadatos sí: IPs, puertos, protocolo, longitud, flags TCP, timestamp. Base legal doméstica.
- Aviso en Ayuda: monitorizar redes ajenas puede ser ilegal en función de la jurisdicción.
- `passive_only` se respeta: no se emite tráfico activo. Captura pasiva sí (escuchar no emite).

### Rendimiento

- Captura hasta **50 K pps** sin pérdida en hardware doméstico (ring 64 MB, un hilo dedicado).
- CPU objetivo: **≤ 15 % con 10 K pps**, ≤ 5 % con 1 K pps.
- Ciclo de render objetivo ≤ 16 ms en 80×24 y ≤ 33 ms en 120×40.
- Snapshot cada 5 s: coste SQLite despreciable (~9 filas).
- Purga de conexiones cada 5 s: coste proporcional al número de conexiones (típicamente <100).

### Accesibilidad

- Sparklines Unicode `▁▂▃▄▅▆▇█` legibles en NO_COLOR.
- Estado de captura redundante: color + prefijo textual `[CAP]`.
- Sin cambios respecto a F1/F2.

---

## 9. Integraciones

- **`/proc/net/{tcp,udp}{,6}`**: fuente del kernel; formato estable documentado.
- **`/proc/net/nf_conntrack`**: si existe y el usuario tiene permisos de lectura (root o `nf_conntrack` accesible). Best-effort: si no, se omite.
- **`/proc/[pid]/fd/*`**: requiere permisos de lectura sobre `/proc/[pid]/fd`. Como usuario normal se ven los propios; para ver procesos de otros usuarios se necesita root (no obligatorio, se degrada).
- **`pcap` (feature no default)**: preparado para F7, no activado en F3.

---

## 10. Decisiones Técnicas (ADR-lite)

**ADR-18 · AF_PACKET + TPACKET_V3 (vs. pcap, eBPF, AF_PACKET sin ring)**
`libpcap` rompe el binario único del `CLAUDE.md`. `eBPF` exige `CAP_BPF`+`CAP_NET_ADMIN` y complica el modelo de pruebas sin red. `AF_PACKET` sin ring obliga a `recvfrom` por paquete (ineficiente). TPACKET_V3 da buffer en anillo con bloques de 1 MB y batches. Se elige AF_PACKET + TPACKET_V3.

**ADR-19 · BPF clásico (vs. filtros propios)**
BPF es el estándar; el kernel lo evalúa en el socket, no en userspace. Los filtros propios en TOML requieren recompilar a BPF de todas formas (o evaluar en userspace, más lento). Se elige BPF clásico con preset TOML.

**ADR-20 · Payload opt-in (vs. por defecto on)**
Capturar payload es sensible legalmente y costoso en CPU/memoria. Por defecto off; la extracción de DNS/SNI es un caso acotado que activa `inspect_payload` implícitamente. Se elige opt-in.

**ADR-21 · Snapshot persistente cada 5s (vs. no persistir en F3)**
Sin snapshot, la TUI arranca vacía hasta el primer ciclo de captura. Con snapshot, se muestra el último valor conocido con timestamp. Coste: ~9 filas cada 5s. Se elige snapshot.

**ADR-22 · Conexiones como tabla caliente (vs. solo en memoria)**
Persistir `CONNECTIONS` permite la tecla `v` (consultar metadatos), filtros SQL y supervivencia al reinicio a corto plazo. La purga por timeout mantiene la tabla pequeña. Se elige persistir.

**ADR-23 · Dos fuentes de conexiones (`/proc` + captura) (vs. una sola)**
`/proc/net/*` da el estado del kernel y permite atribución a proceso local. La captura da tráfico de terceros y bytes reales. Cada una ve cosas que la otra no ve. Se elige merge por 5-tuple.

**ADR-24 · Ventanas 60s + 5min en memoria (vs. todas las ventanas en F3)**
1h y 24h requieren persistencia continua y agregación; eso es F5. F3 se limita a las ventanas que caben en memoria con coste despreciable. Se elige 60s + 5min.

**ADR-25 · Aviso de captura al arrancar (vs. silencioso)**
Capturar sin avisar es mala práctica y potencialmente ilegal. Aviso único al arrancar + estado siempre visible en barra. Se elige avisar.

**ADR-26 · `passive_only` respeta captura pasiva**
`passive_only` prohíbe tráfico activo (ARP/ICMP/M-SEARCH/port scan/banner/fingerprint). Escuchar no genera tráfico. La captura pasiva funciona con `passive_only = true`. Se documenta explícitamente para evitar sorpresas.

---

## 11. Plan de Desarrollo

**Supuestos:** 1 desarrollador, ~15 h/semana, F1+F2 estables como base.

### Sprint 3.1 — Captura base (≈ 16 h)
- `capture/afpacket.rs` (socket + ring TPACKET_V3)
- `capture/bpf.rs` (compilación y attach)
- `capture/parser.rs` (Ethernet/IPv4/IPv6/TCP/UDP/ICMP)
- Tests del parser con fixtures binarios

### Sprint 3.2 — Extracción y agregación (≈ 14 h)
- `capture/dns.rs`, `capture/sni.rs`
- `capture/aggregate.rs`, `capture/windows.rs`
- `passive_only` respetado
- Tests de extracción y agregación

### Sprint 3.3 — Conexiones (≈ 12 h)
- `capture/conntrack.rs`, `capture/process.rs`
- Merge por 5-tuple
- Atribución `device_id` + tags `[host]` / `[broadcast]`
- Purga por timeout

### Sprint 3.4 — Persistencia + snapshot (≈ 8 h)
- Migración v3
- DAOs `traffic_snapshot`, `connections`
- Snapshot cada 5s
- Tests de migración v2→v3

### Sprint 3.5 — TUI (≈ 18 h)
- Pestaña Tráfico (ranking top-10)
- Pestaña Conexiones (tabla plana ordenable)
- Detalle master-detail
- `v` cabeceras
- Barra de estado ampliada
- Aviso de captura al arrancar

### Sprint 3.6 — Cierre (≈ 8 h)
- Tests de integración (pcap-file replay como fixture)
- README actualizado (capabilities, `setcap`, filtros BPF)
- Informe de implementación

**Estimación total F3:** **~76 h → 5–6 semanas**.

---

## 12. Conexiones con Otras Fases

- **F4 (Protocolos, apps y top talkers)** ampliará la inferencia de aplicación (no solo DNS/SNI básico) usando `CONNECTIONS` y servicios de F2. También añadirá top talkers por destino y por app.
- **F5 (Histórico, rollups y eventos)** consumirá `TRAFFIC_SNAPSHOT` como semilla y creará los rollups (`TRAFFIC_ROLLUP_MINUTE/HOUR/DAY`) a partir de la agregación en vivo de F3. La ventana 1h y 24h de las sparklines llegará en F5.
- **F6 (Alertas)** usará `CONNECTIONS` (nueva conexión a IP/puerto sospechoso) y `TRAFFIC_SNAPSHOT` (pico de consumo) como señales.
- **F7 (Integraciones)** habilitará la feature `pcap` para replay de ficheros y añadirá SNMP/port mirror como fuentes externas de tráfico.
