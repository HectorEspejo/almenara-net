# Almenara - Checklist Fase 3: Tráfico en vivo (pasivo + local)

## Captura (backend y BPF)
- [x] Socket AF_PACKET + TPACKET_V3 (ring 64 MB, block 1 MB, frame 4 KB)
- [x] Filtro BPF clásico compilado y aplicado con `SO_ATTACH_FILTER`
- [x] Si `[capture].filter = ""` → socket sin filtro
- [x] Si la compilación BPF falla → notificación + log + socket sin filtro (no se aborta)
- [x] Cierre limpio del socket y del hilo de captura en `Drop`
- [x] `Capture::stats()` expone pps, total, drops, parse_errors
  - AC: dado un filtro `not port 22`, cuando se captura, entonces no aparecen paquetes del puerto 22 en la agregación

## Parser
- [x] Parser Ethernet (EtherType IPv4/IPv6)
- [x] Parser IPv4 (src, dst, protocolo, longitud)
- [x] Parser IPv6 (src, dst, next-header, longitud)
- [x] Parser TCP (puertos, flags, seq/ack si aplica)
- [x] Parser UDP (puertos, longitud)
- [x] Parser ICMP/ICMPv6 (tipo, código)
- [x] Paquete mal formado → `parse_errors += 1` y se descarta
  - AC: dado un frame truncado, cuando se parsea, entonces no se emite `PacketMeta` y `parse_errors` incrementa

## Metadatos y payload
- [x] Por cada paquete: src_ip, dst_ip, src_port, dst_port, protocol, len, tcp_flags, timestamp
- [x] `inspect_payload = false` (default) → payload descartado inmediatamente (no se copia a memoria)
- [x] `inspect_payload = true` → se extraen DNS QNAME / SNI y el resto se descarta
- [x] `dns_attribution = true` → se extrae QNAME en puerto 53 UDP
- [x] `sni_attribution = true` → se extrae SNI en puerto 443 TCP ClientHello
- [x] Payload **nunca** se persiste en SQLite

## Agregación y ventanas
- [x] Agregación por dispositivo: bytes_in, bytes_out, packets_in, packets_out
- [x] `peak_bps` en ventana 60 s por dispositivo
- [x] Agregación global (total ↑↓, broadcast_bytes)
  - AC: dado un paquete de A→B, cuando se agrega, entonces A.bytes_out += n y B.bytes_in += n
- [x] Ventana 60 s (60 puntos, 1/s) por dispositivo
- [x] Ventana 5 min (60 puntos, 1/5 s) por dispositivo
- [x] Ring buffers en memoria, longitud fija, avanzan por tick
- [x] Sparklines arrancan a cero hasta el primer paquete

## Conexiones
- [x] Lectura `/proc/net/tcp` y `/proc/net/tcp6`
- [x] Lectura `/proc/net/udp` y `/proc/net/udp6`
- [x] Lectura `/proc/net/nf_conntrack` best-effort (si existe y es legible)
- [x] Atribución de socket local a PID + comm vía `/proc/[pid]/fd/*` (degradación silenciosa sin permisos)
- [x] Detección de conexiones por captura de paquetes (5-tuple)
- [x] Merge por 5-tuple de ambas fuentes
- [x] Estado TCP (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.)
- [x] Purga por timeout (TCP 300 s, TIME_WAIT/CLOSE_WAIT 60 s, UDP 60 s, ICMP 30 s) cada 5 s
- [x] Atribución de `device_id`: match por IP → ese device; host → NULL + `[host]`; broadcast → NULL + `[broadcast]`; no match → NULL
  - AC: dado un paquete desde la IP del propio host hacia 1.1.1.1, cuando se crea la conexión, entonces device_id = NULL y tag = "[host]"

## Persistencia
- [x] Migración v3: tabla `TRAFFIC_SNAPSHOT` con PK device_id, bytes_in/out, packets_in/out, peak_bps, window_s, updated_at
- [x] Migración v3: tabla `CONNECTIONS` con FK device_id ON DELETE SET NULL
- [x] Índices `IDX_CONN_DEVICE`, `IDX_CONN_LAST_SEEN`, `IDX_CONN_STATE`
- [x] DAO `TRAFFIC_SNAPSHOT`: `upsert_snapshot`, `list_snapshots`
- [x] DAO `CONNECTIONS`: `upsert_connection`, `list_connections`, `prune_expired_connections`, `get_connection`
- [x] Snapshot persistido cada 5 s
  - AC: dado un dispositivo con tráfico, cuando pasan 5 s, entonces existe una fila en `TRAFFIC_SNAPSHOT` con `updated_at` actual
- [x] Migración v3 probada sobre BD de F2 sin pérdida de datos

## Interfaz
- [x] Pestaña Tráfico activa (deja de ser placeholder)
- [x] Pestaña Conexiones activa (deja de ser placeholder)
- [x] Pestaña Tráfico muestra ranking top-10 por consumo en ventana 60 s
- [x] Ranking con columnas: dispositivo, tipo, ↓ in, ↑ out, total, sparkline 60 s
- [x] Drill-down: `Enter` sobre un equipo del ranking abre el detalle
- [x] Pestaña Conexiones muestra tabla plana ordenable (proto, origen, destino, estado, ↑, ↓, edad)
- [x] Pestaña Conexiones filtrable por dispositivo, protocolo y estado
- [x] Etiquetas `[host]` y `[broadcast]` en origen/destino cuando `device_id = NULL`
- [x] Panel detalle de equipo (master-detail): mitad derecha en ≥100 columnas, pantalla completa por debajo
- [x] Detalle muestra sparkline 60 s + 5 min del equipo, ↓ in, ↑ out, pico
- [x] Detalle muestra top-5 puertos del equipo
- [x] Detalle muestra servicios de F2 (`DEVICE_SERVICES`) del equipo
- [x] Detalle muestra conexiones activas del equipo
- [x] `Tab` alterna foco entre panel izquierdo y detalle; `Esc` cierra el detalle
- [x] Tecla `v` sobre conexión abre panel inferior no modal con cabeceras IP/TCP
- [x] Panel `v` se cierra con `Esc`
- [x] Barra de estado con modo de captura (`capturando · N pps · filtro: …`) y visibilidad (`propia + broadcast`)
- [x] Barra de estado en `NO_COLOR=1` usa prefijo textual `[CAP]` / `[CAP:off]`
- [x] Notificación única al arrancar `"capturando en <iface>"` si captura activa
- [x] Sin `CAP_NET_RAW`: captura deshabilitada con aviso claro en Tráfico/Ayuda/barra
- [x] Placeholders Histórico (F5) y Alertas (F6) actualizados en el texto

## Configuración
- [x] `[capture].enabled = true` por defecto
- [x] `[capture].filter = ""` (BPF clásica, vacío = sin filtro)
- [x] `[capture].inspect_payload = false` por defecto
- [x] `[capture].max_pps = 0` (0 = sin límite) con aviso una vez por minuto si se alcanza
- [x] `[capture].dns_attribution = true` por defecto
- [x] `[capture].sni_attribution = true` por defecto
- [x] Validación: `max_pps` ≥ 0; `filter` se compila (si falla → notificación + sin filtro); `interfaces` coincide con F2

## Servicios internos
- [x] `Capture::start()`
- [x] `Capture::stop()`
- [x] `Capture::drain()`
- [x] `Capture::stats()`
- [x] `Bpf::compile()`
- [x] `Parser::parse()`
- [x] `Dns::extract()`
- [x] `Sni::extract()`
- [x] `Aggregator::update()`
- [x] `Aggregator::snapshot()`
- [x] `Windows::push()`
- [x] `Windows::series_60s()`
- [x] `Windows::series_5min()`
- [x] `Conntrack::read()`
- [x] `ProcNet::read_tcp()`
- [x] `ProcNet::read_udp()`
- [x] `Process::attribute()`
- [x] `Repo::upsert_snapshot()`
- [x] `Repo::list_snapshots()`
- [x] `Repo::upsert_connection()`
- [x] `Repo::list_connections()`
- [x] `Repo::prune_expired_connections()`
- [x] `Repo::get_connection()`

## Tests y calidad
- [x] Tests unitarios del parser (fixtures Ethernet/IPv4/IPv6/TCP/UDP/ICMP, incluyendo truncados)
- [x] Tests unitarios de extracción DNS y SNI (fixtures binarios)
- [x] Tests de agregación (in/out, peak_bps, ventanas 60s/5min)
- [x] Tests de la migración v3 (idempotente y compatible con BD F2)
- [x] Tests de DAOs `TRAFFIC_SNAPSHOT` y `CONNECTIONS` (con `tempfile`)
- [x] Tests de purga por timeout (TCP/UDP/ICMP)
- [x] Tests de integración con replay de fichero pcap capturado como fixture (feature `pcap` no default, test condicional)
- [x] Tests de UI con `TestBackend`: ranking Tráfico, tabla Conexiones, panel detalle, panel `v`
- [x] `cargo test` en verde, `cargo fmt --check` limpio, `cargo clippy --all-targets -- -D warnings` limpio

---

**Progreso Fase 3:** 76 / 76 funcionalidades (el fichero contiene 102 casillas; ver informe de implementación)

**Total Almenara (Fases 1-3):** 222 / 222 funcionalidades (76 de Fase 3)
