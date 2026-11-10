# Almenara — Fase 3: informe de implementación

**Fecha:** 2026-11-10 · **Versión del binario:** 0.1.0 · **Estado:** Fase 3 implementada y verificada (pendiente de entrega al analista funcional)
**Revisión:** 2026-11-10 — corrección del anillo TPACKET_V3 tras la primera prueba manual con CAP_NET_RAW (ver Pendientes).

## Resumen de lo implementado

Se ha implementado la Fase 3 completa de Almenara (tráfico en vivo, pasivo + local) como evolución aditiva de las fases 1 y 2, sin romper el esquema ni el comportamiento existentes:

- **Migración v3 aditiva** de SQLite: tablas TRAFFIC_SNAPSHOT (una fila por dispositivo, PK device_id con FK ON DELETE CASCADE) y CONNECTIONS (FK device_id NULL con ON DELETE SET NULL), con los índices IDX_CONN_DEVICE, IDX_CONN_LAST_SEEN e IDX_CONN_STATE. Compatibilidad verificada con una base de datos de Fase 2 (los datos de F1/F2 se conservan y la migración es idempotente).
- **Captura sin libpcap**: socket AF_PACKET + anillo TPACKET_V3 (64 MB: 64 bloques de 1 MB, frames de 4 KB, bloque retirado cada 100 ms) con un hilo dedicado por interfaz, drenaje por lotes y parada limpia (Drop con munmap y join del hilo). Filtro BPF clásico compilado a instrucciones reales y adjunto con SO_ATTACH_FILTER; filtro vacío = socket sin filtro y error de compilación = aviso + log + captura sin filtro.
- **Compilador y evaluador BPF clásico propio** (1884 líneas con tests): gramática tcpdump acotada (tcp/udp/icmp/icmp6/ip/ip6/arp, port, portrange, host, net, src/dst, and/or/not y paréntesis), generación de saltos sin desbordar jt/jf, attach al socket e intérprete completo para tests y replay. Cubre el AC not port 22.
- **Parser propio** Ethernet (VLAN 802.1Q), IPv4 (IHL/opciones/fragmento inicial), IPv6 (extensión 0/43/44/60), TCP (puertos, seq/ack, flags de 9 bits), UDP e ICMP/ICMPv6, con copia acotada de cabeceras (IP hasta 40 B, transporte hasta 20 B) para el panel de la tecla v y con descarte inmediato del payload: inspect_payload=false no copia nada y con true solo se extraen QNAME/SNI. Paquete mal formado = parse_errors++ y descarte; protocolos no soportados y fragmentos no iniciales se ignoran sin contarlos como error.
- **Extracción DNS y SNI**: QNAME de consultas DNS (puerto 53, compresión de punteros con guarda anti-bucle) y SNI de ClientHello TLS (puerto 443), activas por defecto.
- **Agregación en memoria**: bytes y paquetes in/out por dispositivo, agregado global (total y broadcast_bytes), pico (peak_bps) en la ventana de 60 s, ring buffers fijos de 60 puntos (1 punto/s) y 5 min (1 punto/5 s), ritmos del último segundo, top-5 de puertos por equipo y series de 60 s/5 min por dispositivo.
- **Conexiones activas con dos fuentes**: lectura de /proc/net/tcp{,6} y /proc/net/udp{,6}, lectura best-effort de /proc/net/nf_conntrack y detección por captura de paquetes (5-tuple canónica), con merge por 5-tuple, estado TCP del kernel, atribución de socket local a PID + comm vía /proc/[pid]/fd/* (degradación silenciosa) y purga por timeout cada 5 s (TCP 300 s, TIME_WAIT/CLOSE_WAIT 60 s, UDP 60 s, ICMP 30 s). Atribución de device_id: match por IP; host propio = NULL + [host]; broadcast/multicast = NULL + [broadcast]; resto = NULL + [?].
- **Persistencia**: DAOs TRAFFIC_SNAPSHOT (upsert_snapshot, list_snapshots) y CONNECTIONS (upsert_connection por id o 5-tuple conservando first_seen, list_connections con filtro, prune_expired_connections y get_connection), snapshot por dispositivo y conexiones activas persistidos cada 5 s desde el hilo de la TUI (única conexión de escritura, regla de F1/F2) y semilla inicial de la TUI leída de TRAFFIC_SNAPSHOT al arrancar.
- **TUI**: pestaña Tráfico activa con ranking top-10 (dispositivo, tipo, ↓ in, ↑ out, total, sparkline 60 s y resumen global); el ranking solo lista equipos con actividad y añade una fila **[host]** con el tráfico del propio host (no pertenece al inventario), de modo que en una red conmutada la pestaña no aparece vacía, pestaña Conexiones activa con tabla plana ordenable/filtrable (proto, origen, destino, estado, ↑, ↓, edad, etiquetas [host]/[broadcast]/[?] en dim), panel detalle de equipo master-detail (mitad derecha en >=100 columnas, pantalla completa por debajo, Tab alterna foco y Esc cierra) con identidad, sparklines 60 s + 5 min, ritmos, pico, top-5 puertos, servicios de F2 y conexiones activas; panel inferior no modal con cabeceras IP/TCP de la conexión seleccionada (v, Esc cierra); drill-down desde el ranking con Enter; barra de estado ampliada (3 líneas en >=100 columnas, 2 por debajo) con modo, estado de captura (capturando · N pps · filtro: …), totales globales, visibilidad propia + broadcast y fuentes; prefijo textual [CAP]/[CAP:off] con NO_COLOR; avisos de captura al arrancar, sin CAP_NET_RAW y de max_pps (una vez por minuto).
- **Configuración [capture]**: enabled=true, filter="", inspect_payload=false, max_pps=0, dns_attribution=true y sni_attribution=true, con validación (max_pps >= 0; el filtro se compila en el arranque de la captura y si falla se avisa y se captura sin filtro; las interfaces siguen el criterio de F2 [scan].interfaces).
- **Verificación**: 530 tests unitarios/de integración + 4 tests de CLI en verde (534, 2 tests ignorados que requieren CAP_NET_RAW), 531 + 4 con la feature pcap, cargo fmt --check limpio y cargo clippy --all-targets -- -D warnings limpio. Migración v3 probada sobre BD de F2 sin pérdida, smoke test real en pty (arranque en modo degradado, BD migrada a v3, sin panics) y replay de un fichero pcap fixture condicionado a la feature pcap.

## Desviaciones respecto a la especificación (qué y por qué)

1. **Módulo raíz src/traffic.rs no listado en la estructura del informe.** El informe describe capture/mod.rs como ciclo de vida del ring; se mantiene esa fachada (Capture::start/stop/drain/stats) y se añade src/traffic.rs como tarea de orquestación (drenaje, agregación, lectura de /proc cada 5 s, caché de conexiones, merge, purga y emisión de AppEvent::Traffic cada 1 s). Motivo: separar la capa de socket/ring de la lógica de negocio y no bloquear el hilo de la TUI; encaja con el diagrama de arquitectura (Event Bus -> Capture/Conntrack -> Repo) y con la regla de una única conexión de escritura en el hilo de la TUI.

2. **prune_expired_connections recibe SystemTime en lugar de Instant.** La firma del informe usa Instant, pero las fechas persistidas son TEXT RFC 3339 UTC: la purga compara last_seen con un instante de pared. Se documenta en el rustdoc y en los tests. Misma razón por la que el snapshot usa updated_at en RFC 3339.

3. **Semántica del snapshot**: TRAFFIC_SNAPSHOT guarda bytes/paquetes de la ventana de 60 s y peak_bps de esa ventana (window_s=60), no acumulados de sesión. Motivo: la semilla al reabrir no crece sin límite y es coherente con window_s; las sparklines empiezan a cero y solo se rellenan con datos nuevos, como pide el informe.

4. **Un socket/anillo y un hilo por interfaz** en vez de un único anillo compartido. AF_PACKET se enlaza a un ifindex, así que para varias interfaces hacen falta varios sockets; el hilo de tráfico los drena juntos. El tamaño de anillo por interfaz sigue siendo 64 MB.

5. **Feature pcap sin dependencia externa.** La regla de CLAUDE.md dice que libpcap/pcap solo se usará como feature no default para replay en F7 y nunca en F3: se declara la feature pcap (sin dependencias) y el test de replay lee el fichero pcap con un lector mínimo propio bajo esa feature. El replay con libpcap real queda para F7.

6. **Nombres de API tipo Bpf::compile, Dns::extract y Sni::extract.** Se implementan como funciones de módulo (bpf::compile, BpfProgram::compile, dns::extract, sni::extract), siguiendo la convención del CLAUDE.md "Módulo::función_snake_case" para servicios internos de una TUI. El resto de servicios del checklist existen con el nombre pedido.

7. **Bytes_in/bytes_out relativos al extremo canónico de la 5-tuple.** El informe no fija el punto de vista; se canonicaliza el extremo menor (IP, puerto) como origen y bytes_out es origen->destino y bytes_in el retorno. Así ida y vuelta comparten una sola fila y la tabla es estable. Para /proc se mantiene la coherencia (origen canónico) y en la práctica el host suele quedar como origen.

8. **Estado TCP de conexiones vistas solo por captura = NULL (—).** No se inventa ESTABLISHED a partir de flags: el estado fiable viene de /proc/net o conntrack; con solo captura se muestra "—" hasta que el kernel lo aporte. Evita etiquetas engañosas en la tabla.

9. **top_ports acumulativo** (no hay ventana definida en el informe), acotado a 256 entradas por dispositivo (se descartan las de menos bytes) y ordenado por bytes. En el detalle se muestran los cinco primeros.

10. **CONNECTIONS sin restricción UNIQUE de 5-tuple.** El informe no define índice único y solo enumera los tres índices IDX_CONN_*; el upsert busca por 5-tuple y actualiza (conservando first_seen) y, como solo escribe el hilo de la TUI, no se generan duplicados.

11. **max_pps con contador de descartes separado.** CaptureStats mantiene los cuatro campos del checklist (pps, total, drops, parse_errors); los descartes por límite se cuentan aparte (Capture::limit_drops) para no disparar el aviso genérico de drops del anillo. El límite es global (mutex) y el aviso se emite como mucho una vez por minuto.

12. **Barra de estado a menos de 100 columnas**: segunda línea con captura + visibilidad; la lista de Fuentes se muestra en la tercera línea solo a partir de 100 columnas (en F2 ocupaba una línea fija). Motivo: el informe pide 2 líneas por debajo de 100 columnas y 3 a partir de 100; no caben los tres bloques con la lista completa.

13. **ParseError con marca ignorable**: ARP/LLDP, EtherTypes no soportados, IP que no es IPv4/IPv6 y fragmentos no iniciales se descartan en silencio (no incrementan parse_errors); solo las tramas mal formadas/truncadas cuentan como error, que es lo que exige el AC del checklist.

14. **Límites del parser documentados**: un solo tag VLAN 802.1Q (Q-in-Q no soportado), sin jumbogramas IPv6 (ip_total_len satura a u16::MAX), IPv6 con cadena de extensiones 0/43/44/60 (no ESP/AH u otras) y Protocol::Other no copia transport_raw por privacidad. No afecta al tráfico doméstico cubierto por F3.

15. **Interfaces de captura**: se aplica [scan].interfaces (auto o nombres) filtrando interfaces up con IPv4; los nombres inexistentes se ignoran. Si no queda ninguna interfaz activa la captura se deshabilita con aviso claro (no es error fatal), igual que sin CAP_NET_RAW.

16. **Atribución de device_id cuando una IP es a la vez host e inventario**: gana la regla 1 del informe (match por IP -> device); el tag [host] solo aparece cuando el extremo no está inventariado. Documentado en las pruebas de tráfico.

17. **Aviso "capturando en <iface>"**: con varias interfaces se listan separadas por coma (capturando en eth0, wlan0); la notificación se emite una sola vez al arrancar solo si la captura está activa.
18. **Fila [host] en el ranking de Tráfico y filtrado de equipos sin actividad.** El informe describe el ranking por dispositivo; en red conmutada el tráfico propio (que no es un equipo de DEVICES) y la difusión no se atribuyen a ningún equipo y la pestaña quedaba en ceros. Se añade la fila [host] con el agregado propio (device_id centinela -1, no se persiste en SQLite) y se ocultan las filas de equipos sin actividad, manteniendo las columnas del mockup. Es una mejora de visibilidad honesta dentro del propio informe, que declara "propia + broadcast" como visibilidad real.

## Estructura de archivos creada/modificada

Nuevos:

    src/capture/mod.rs              fachada de captura: tipos compartidos, Capture::start/stop/drain/stats, hilo por interfaz, límite max_pps
    src/capture/afpacket.rs         AF_PACKET + TPACKET_V3 + SO_ATTACH_FILTER + poll de bloques + Drop
    src/capture/bpf.rs              compilador y evaluador BPF clásico (attach + intérprete)
    src/capture/parser.rs           parser Ethernet/IPv4/IPv6/TCP/UDP/ICMP + copia de cabeceras
    src/capture/dns.rs              extracción de QNAME (puerto 53)
    src/capture/sni.rs              extracción de SNI TLS (puerto 443)
    src/capture/windows.rs          ring buffers 60 s / 5 min de longitud fija
    src/capture/aggregate.rs        Aggregator por dispositivo y global (in/out, peak_bps, top_ports, series)
    src/capture/conntrack.rs        /proc/net/{tcp,udp}{,6} + nf_conntrack best-effort
    src/capture/process.rs          /proc/[pid]/fd -> PID + comm
    src/traffic.rs                  tarea de monitorización: drenaje, agregación, caché de conexiones, merge, purga y eventos
    src/repo/traffic_snapshot.rs    DAO TRAFFIC_SNAPSHOT
    src/repo/connections.rs         DAO CONNECTIONS (protocolo, upsert por 5-tuple, filtros, purga)
    src/tui/traffic_state.rs        estado de tráfico/conexiones/detalle/cabeceras y acciones de la TUI
    src/tui/views/traffic.rs        pestaña Tráfico (ranking top-10)
    src/tui/views/connections.rs    pestaña Conexiones (tabla plana + panel de cabeceras)
    src/tui/views/device_detail.rs  panel detalle de equipo (master-detail)
    tests/fixtures/fase3-replay.pcap  fixture de replay condicional a la feature pcap

Modificados:

    Cargo.toml / Cargo.lock         dependencia nix 0.31 (stack) y feature no default pcap
    src/config.rs                   sección [capture] + validación + plantilla + tests
    src/error.rs                    variante Error::Capture
    src/events.rs                   AppEvent::Traffic, AppEvent::CaptureNotice, TrafficCommand y canal
    src/main.rs                     arranque del monitor de tráfico, semilla de snapshot, purga inicial y cierre ordenado
    src/repo/migrations.rs          migración v3 (ya existe con idempotencia y tests actualizados a v3)
    src/repo/mod.rs                 reexports y métodos Repo de Fase 3
    src/tui/mod.rs                  consumo de eventos de tráfico, persistencia cada 5 s, detalle y cierre ordenado
    src/tui/app.rs                  estado de tráfico/detalle/cabeceras, teclas de Tráfico/Conexiones, Enter -> detalle
    src/tui/traffic_state.rs        (nuevo) estado y lógica de presentación de Fase 3
    src/tui/keys.rs                 pies por pestaña, ayuda ampliada y footer de detalle
    src/tui/views/mod.rs            dispatch de pestañas, barra de estado de 2/3 líneas y pies
    src/tui/views/devices.rs        master-detail en Equipos y reparto 50/50 o pantalla completa
    src/tui/views/help.rs           ayuda de Fase 3 (captura, filtros, privacidad, detalle, cabeceras)
    src/tui/views/placeholder.rs    Histórico (F5) y Alertas (F6)
    src/tui/views/config_view.rs    nota del detalle de F3
    README.md                       Fase 3: requisitos, setcap, configuración [capture], uso, privacidad y limitaciones
    CLAUDE.md / AGENTS.md           stack, documentación y reglas de trabajo de Fase 3
    docs/fase3/almenara-fase3-checklist.md  76/76 funcionalidades (102 casillas) marcadas

## Decisiones técnicas tomadas durante el desarrollo

- **TPACKET_V3 con libc**: se usan tpacket_req3, tpacket_block_desc, tpacket3_hdr y tpacket_stats_v3 de libc 0.2; un bloque se recicla a TP_STATUS_KERNEL al terminar de recorrerlo y los drops se leen con PACKET_STATISTICS como delta. Sin libpcap, tal y como exige el informe y la regla de CLAUDE.md.
- **Hilos de captura independientes** con canal sync_channel acotado y lotes de 256 paquetes: si el consumidor no drena, se descartan lotes y se contabilizan en drops (nunca se bloquea el kernel ring). El hilo de tráfico drena cada 100 ms.
- **Límite max_pps global con mutex** (ventana de 1 s) solo cuando max_pps > 0; así varias interfaces comparten el límite y el camino sin límite no paga el coste del lock.
- **Clave de conexión canónica (5-tuple ordenada)** para que ida y vuelta compartan fila; el sentido de los bytes se deduce comparando el emisor con el extremo canónico.
- **Caché de conexiones acotada a 2048 entradas** con purga por timeout y desalojo de las más inactivas: evita crecer sin control con tráfico de terceros.
- **Persistencia solo en el hilo de la TUI**: la tarea de tráfico nunca escribe SQLite; emite TrafficUpdate y la TUI hace upsert de snapshots/conexiones y purga cada 5 s. Respeta la regla de una única conexión de escritura.
- **Semilla desde TRAFFIC_SNAPSHOT** con series a cero: los valores persistidos se muestran como último snapshot conocido y las sparklines se rellenan solo con captura nueva.
- **Estados de la captura visibles en la barra**: activo/desactivado con motivo (configuración, sin CAP_NET_RAW, sin interfaces, error de apertura) y prefijo textual con NO_COLOR.
- **Numeración de columnas adaptativa** en Tráfico y Conexiones para que ambas tablas quepan en 80 columnas (probado con el backend de tests).
- **Tags [host]/[broadcast]/[?] resueltos en la capa de tráfico** (no en la TUI) usando IP locales, rangos de difusión/multidifusión y el mapa de inventario; la TUI solo pinta en dim.
- **Notificaciones no bloqueantes**: los avisos de captura (sin CAP_NET_RAW, BPF inválido, max_pps, drops) viajan por el bus de eventos y no bloquean el arranque.
- **Cierre ordenado**: al salir se envía ScanCommand::Stop, TrafficCommand::Stop y se espera (con timeout de 2 s) a la tarea de tráfico, que para la captura y hace join de los hilos; Capture también cierra en Drop.
- **tp_frame_nr en TPACKET_V3**: packet_set_ring valida que tp_frame_nr sea exactamente block_nr * (block_size / frame_size) también en V3. Se calcula explícitamente (16 384 para el anillo por defecto de 64 MB) y se comprueba que quepa en u32; dejarlo a 0 provoca EINVAL al crear el anillo. Detectado en la primera prueba manual con CAP_NET_RAW y corregido, con test unitario del cálculo y test real de captura en loopback (ignorado por defecto, ejecutado en un namespace de usuario con CAP_NET_RAW para verificar el camino completo).
- **tp_mac relativo a la cabecera TPACKET3**: el kernel escribe la trama en h.raw + tp_mac, donde tp_mac es un desplazamiento desde el inicio de la cabecera del paquete, no desde el inicio del bloque. Se corrigió el lector del anillo y el helper de bloques sintéticos; el test real de captura en loopback ahora parsea además el datagrama UDP generado y comprueba que se trata como UDP (con el offset anterior el parser recibía basura y no se agregaba nada, aunque el contador de pps sí subía).

## Funcionalidades del checklist completadas (copiando su texto exacto)

- [x] Socket AF_PACKET + TPACKET_V3 (ring 64 MB, block 1 MB, frame 4 KB)
- [x] Filtro BPF clásico compilado y aplicado con `SO_ATTACH_FILTER`
- [x] Si `[capture].filter = ""` → socket sin filtro
- [x] Si la compilación BPF falla → notificación + log + socket sin filtro (no se aborta)
- [x] Cierre limpio del socket y del hilo de captura en `Drop`
- [x] `Capture::stats()` expone pps, total, drops, parse_errors
- [x] Parser Ethernet (EtherType IPv4/IPv6)
- [x] Parser IPv4 (src, dst, protocolo, longitud)
- [x] Parser IPv6 (src, dst, next-header, longitud)
- [x] Parser TCP (puertos, flags, seq/ack si aplica)
- [x] Parser UDP (puertos, longitud)
- [x] Parser ICMP/ICMPv6 (tipo, código)
- [x] Paquete mal formado → `parse_errors += 1` y se descarta
- [x] Por cada paquete: src_ip, dst_ip, src_port, dst_port, protocol, len, tcp_flags, timestamp
- [x] `inspect_payload = false` (default) → payload descartado inmediatamente (no se copia a memoria)
- [x] `inspect_payload = true` → se extraen DNS QNAME / SNI y el resto se descarta
- [x] `dns_attribution = true` → se extrae QNAME en puerto 53 UDP
- [x] `sni_attribution = true` → se extrae SNI en puerto 443 TCP ClientHello
- [x] Payload **nunca** se persiste en SQLite
- [x] Agregación por dispositivo: bytes_in, bytes_out, packets_in, packets_out
- [x] `peak_bps` en ventana 60 s por dispositivo
- [x] Agregación global (total ↑↓, broadcast_bytes)
- [x] Ventana 60 s (60 puntos, 1/s) por dispositivo
- [x] Ventana 5 min (60 puntos, 1/5 s) por dispositivo
- [x] Ring buffers en memoria, longitud fija, avanzan por tick
- [x] Sparklines arrancan a cero hasta el primer paquete
- [x] Lectura `/proc/net/tcp` y `/proc/net/tcp6`
- [x] Lectura `/proc/net/udp` y `/proc/net/udp6`
- [x] Lectura `/proc/net/nf_conntrack` best-effort (si existe y es legible)
- [x] Atribución de socket local a PID + comm vía `/proc/[pid]/fd/*` (degradación silenciosa sin permisos)
- [x] Detección de conexiones por captura de paquetes (5-tuple)
- [x] Merge por 5-tuple de ambas fuentes
- [x] Estado TCP (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.)
- [x] Purga por timeout (TCP 300 s, TIME_WAIT/CLOSE_WAIT 60 s, UDP 60 s, ICMP 30 s) cada 5 s
- [x] Atribución de `device_id`: match por IP → ese device; host → NULL + `[host]`; broadcast → NULL + `[broadcast]`; no match → NULL
- [x] Migración v3: tabla `TRAFFIC_SNAPSHOT` con PK device_id, bytes_in/out, packets_in/out, peak_bps, window_s, updated_at
- [x] Migración v3: tabla `CONNECTIONS` con FK device_id ON DELETE SET NULL
- [x] Índices `IDX_CONN_DEVICE`, `IDX_CONN_LAST_SEEN`, `IDX_CONN_STATE`
- [x] DAO `TRAFFIC_SNAPSHOT`: `upsert_snapshot`, `list_snapshots`
- [x] DAO `CONNECTIONS`: `upsert_connection`, `list_connections`, `prune_expired_connections`, `get_connection`
- [x] Snapshot persistido cada 5 s
- [x] Migración v3 probada sobre BD de F2 sin pérdida de datos
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
- [x] `[capture].enabled = true` por defecto
- [x] `[capture].filter = ""` (BPF clásica, vacío = sin filtro)
- [x] `[capture].inspect_payload = false` por defecto
- [x] `[capture].max_pps = 0` (0 = sin límite) con aviso una vez por minuto si se alcanza
- [x] `[capture].dns_attribution = true` por defecto
- [x] `[capture].sni_attribution = true` por defecto
- [x] Validación: `max_pps` ≥ 0; `filter` se compila (si falla → notificación + sin filtro); `interfaces` coincide con F2
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
- [x] Tests unitarios del parser (fixtures Ethernet/IPv4/IPv6/TCP/UDP/ICMP, incluyendo truncados)
- [x] Tests unitarios de extracción DNS y SNI (fixtures binarios)
- [x] Tests de agregación (in/out, peak_bps, ventanas 60s/5min)
- [x] Tests de la migración v3 (idempotente y compatible con BD F2)
- [x] Tests de DAOs `TRAFFIC_SNAPSHOT` y `CONNECTIONS` (con `tempfile`)
- [x] Tests de purga por timeout (TCP/UDP/ICMP)
- [x] Tests de integración con replay de fichero pcap capturado como fixture (feature `pcap` no default, test condicional)
- [x] Tests de UI con `TestBackend`: ranking Tráfico, tabla Conexiones, panel detalle, panel `v`
- [x] `cargo test` en verde, `cargo fmt --check` limpio, `cargo clippy --all-targets -- -D warnings` limpio

## Pendientes y bloqueos

No hay bloqueos: la Fase 3 está implementada y la suite automatizada está en verde.

Pendiente de verificación manual (no bloqueante, requiere privilegios y red real):

- Captura real con CAP_NET_RAW en una o varias interfaces: comprobar pps en la barra, el aviso único "capturando en <iface>", el filtro BPF aplicado en el socket y el panel de cabeceras (v) con tráfico real. Los tests cubren el parser, el filtro y la agregación con fixtures y replay pcap, pero no abren un socket real.
- Aviso de max_pps una vez por minuto: la lógica está implementada y revisada, pero no tiene test automático porque exige captura real superando el umbral.
- Verificación en una red doméstica con varios equipos: visibilidad propia + broadcast, atribución [host]/[broadcast] y purga de conexiones a lo largo de varios minutos.

Fuera del alcance de F3 (fases posteriores): ventanas 1 h/24 h y rollups persistentes (F5), alertas (F6), replay real con libpcap y fuentes externas (F7), e inferencia de aplicación/top talkers (F4).

Correcciones aplicadas tras las primeras pruebas manuales con CAP_NET_RAW real:

1. La apertura del anillo fallaba con "no se pudo crear el anillo TPACKET_V3: Invalid argument (os error 22)" porque se enviaba tp_frame_nr = 0. El kernel exige tp_frame_nr = block_nr * (block_size / frame_size) también en TPACKET_V3; se calcula explícitamente y se valida que quepa en u32.
2. Aunque el anillo ya se abría y se contaban pps, la agregación seguía a cero porque el lector usaba tp_mac como offset absoluto del bloque en vez de relativo al inicio de la cabecera TPACKET3: el parser recibía bytes que no eran una trama Ethernet y descartaba todo en silencio (los ARP y EtherTypes desconocidos no cuentan como parse_errors). Corregido el lector y reforzado el test real de captura en loopback para parsear y verificar el datagrama generado.

Además, para que la pestaña Tráfico sea útil en red conmutada, el ranking incluye la fila [host] y oculta equipos sin actividad. Toda la suite queda en 530 + 4 tests (531 + 4 con la feature pcap) en verde. Tras recompilar hay que volver a aplicar la capability: el script scripts/ejecutar-con-permisos.sh la reaplica en cada arranque. Queda pendiente la verificación visual final en wlp191s0 con el binario recompilado (Tráfico con fila [host], conexiones con bytes y difusión).

La actualización de la documentación maestra (checklist maestro e informe maestro) corresponde al analista funcional una vez entregado este informe; hasta entonces esa documentación no refleja la realidad de F3.

## Ejecución y pruebas (cómo arrancar, migrar y testear)

Compilar y arrancar:

    cargo build
    cargo run
    cargo run -- -c /ruta/a/config.toml
    cargo run -- -vv
    cargo run -- --no-color

Permisos para capturar (descubrimiento activo y captura de paquetes):

    sudo setcap cap_net_raw+ep target/debug/almenara
    getcap target/debug/almenara
    ./target/debug/almenara
    sudo setcap -r target/debug/almenara

Sin CAP_NET_RAW la aplicación arranca en modo degradado: captura deshabilitada, aviso en barra/pestaña Tráfico/Ayuda y conexiones desde /proc/net/*, sin panics (smoke test realizado en pty con una configuración temporal: la BD se creó en la versión 3 de esquema con las tablas TRAFFIC_SNAPSHOT y CONNECTIONS y la app siguió funcionando hasta el timeout).

Migración: se aplica automáticamente al abrir la base de datos (Repo::init -> migrations::apply_all). v3 es aditiva e idempotente; los tests migran una BD de Fase 2 con datos y verifican que se conservan, y reaplican la migración sin duplicar registros. No hay paso manual: al arrancar la nueva versión, la BD de F1/F2 pasa a v3.

Configuración relevante (nueva sección [capture], con defaults del informe):

    [capture]
    enabled = true
    filter = ""              # BPF clásico, por ejemplo "not port 22" o "tcp and port 443"
    inspect_payload = false  # payload descartado al instante (nunca se persiste)
    max_pps = 0              # 0 = sin límite; aviso una vez por minuto al alcanzarlo
    dns_attribution = true
    sni_attribution = true

Pruebas automatizadas:

    cargo test                                  # 530 unitarios/integración + 4 CLI, 2 ignorados (captura real)
    cargo test --features pcap                  # idem + 1 test de replay pcap con fixture
    cargo fmt --check                           # limpio
    cargo clippy --all-targets -- -D warnings   # limpio

Desglose de los tests nuevos por módulo: capture::afpacket 20, capture::bpf 22, capture::parser 35, capture::dns 13, capture::sni 10, capture::windows 11, capture::aggregate 15, capture::conntrack 11, capture::process 7, capture::mod 10, traffic 11, traffic_state 6, repo (migración + DAOs) 34, TUI (estado, ranking, conexiones, detalle, barras y ayuda) 23, más el replay pcap condicional (1). Los 2 tests ignorados son la captura real en loopback y una comprobación que requiere CAP_NET_RAW; se omiten solos sin privilegios.

Replay pcap: el fixture tests/fixtures/fase3-replay.pcap contiene cinco tramas (TCP SYN, SYN-ACK, TCP con payload, DNS example.com y UDP IPv6 multicast) y el test condicional a la feature pcap verifica parser, filtro BPF (tcp and port 443) y agregación por dispositivo sin abrir sockets.
