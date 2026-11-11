# Changelog de Almenara

Todas las versiones relevantes del proyecto. El formato sigue
[Versionado Semántico](https://semver.org/lang/es/).

## [0.6.0] - 2026-11-11

**Fase 6 — Alertas (locales + escritorio).** Almenara deja de solo observar y
avisa de lo que cambia: un motor puro con 16 reglas, tres niveles, aprendizaje
de 7 días con datos, deduplicación de 24 h, silencios y notificaciones de
escritorio por D-Bus. Llegan la pestaña **Alertas** (lista con detalle, Reglas y
Silencios), el contador «Alertas N» en la barra, las marcas `*`/`!` en Equipos,
el bloque de alertas y el aprendizaje en el detalle, `[alerts]` en Config y los
huecos de suspensión y captura parada en todo el histórico.

### Añadido

- **Pestaña Alertas** con lista por última repetición, nivel (importante / aviso
  / info), marca de no vista, «×N» de repeticiones y «· resuelta»; detalle con el
  porqué, las repeticiones, si se notificó y lo que agrupa un resumen. Filtros
  de nivel, solo sin ver y por equipo.
- **Catálogo fijo de 16 reglas**: equipo nuevo, puerto nuevo, cambio de MAC, de
  nombre, de SO y de tipo; app, categoría, país, organización y huella JA4
  nuevas; más tráfico de lo habitual; vigilado ausente o de vuelta; captura
  parada; pérdidas de captura y base de datos grande. Las reglas se activan,
  apagan y cambian de nivel desde la TUI, guardando en `config.toml`.
- **Aprendizaje de 7 días con datos** por sujeto (equipos y propio equipo), con
  relleno inicial desde el histórico de F5, línea base en una BD vacía y sin
  vuelta atrás.
- **Deduplicación de 24 h** con repeticiones y alertas de condición que se
  resuelven y reactivan; apagar una regla resuelve sus condiciones.
- **Silencios** por regla, sujeto y equipo (1 día, 7 días o siempre) con vista
  propia y purga de los caducados.
- **Notificaciones de escritorio** por D-Bus de sesión (`notify-rust` 4.17,
  Rust puro) en un hilo propio: solo las importantes, puesta al día de 10
  minutos con resumen, horario silencioso, tope de 3 por minuto y estado del
  notificador en Config.
- **Equipos vigilados** (`DEVICES.watched`): `p` los marca en Equipos y en el
  detalle; solo ellos avisan de presencia, con `while_closed` si se fueron con
  Almenara cerrada.
- **Inventario del propio equipo** (`HOST_SEEN`) con apps, categorías,
  organizaciones, países y JA4, y su aprendizaje en Config.
- **Huecos dentro de la sesión** (`COVERAGE_GAPS`): suspensión del equipo por
  `CLOCK_BOOTTIME` frente a `CLOCK_MONOTONIC` y captura parada; toda cobertura
  los resta y la línea de tiempo de Histórico los muestra.
- **Puertos cerrados con fecha** (`DEVICE_SERVICES.closed_at`) y detección de
  `reopened`; el detalle dice «cerrado el …» y `last_seen` vuelve a ser la
  última vez que se vio abierto.
- **Migración v6 aditiva**: ALERTS, ALERT_MUTES, ALERT_LEARNING, HOST_SEEN y
  COVERAGE_GAPS, columnas `DEVICES.watched` y `DEVICE_SERVICES.closed_at`, con
  rellenos de cierre y aprendizaje y test de compatibilidad v5 → v6.
- **Mediciones**: `medir_alertas_motor`, `medir_alertas_hora`,
  `medir_alertas_aprendizaje`, `medir_alertas_consulta`, `medir_migracion_v6` y
  `medir_render_alertas`, con el sintético ampliado con alertas, silencios,
  aprendizaje, `HOST_SEEN` y huecos.

### Cambiado

- Un puerto CERRADO se representa con `DEVICE_SERVICES.closed_at`;
  `Repo::mark_service_closed` ya no mueve `last_seen` (hasta la v6 lo hacía).
- `Repo::close_open_sessions` cierra también los huecos abiertos de una sesión
  interrumpida.
- Configuración nueva `[alerts]`, `[alerts.traffic_high]`,
  `[alerts.capture_drops]` y `[alerts.rules]`, con validación tolerante.
- Dependencia nueva `notify-rust` 4.17 (sin features por defecto, con `z`);
  `uuid` queda fijada a una versión compatible con la MSRV 1.88.

### Corregido

- El cierre de un puerto ya no falsea `last_seen` y el estado CERRADO es
  determinista con un escaneo posterior.
- La cobertura del histórico, la presencia y el aprendizaje descuentan la
  suspensión del equipo y la captura parada, que antes contaban como horas sin
  tráfico.

## [0.5.0] - 2026-11-11

**Fase 5 — Histórico, rollups y eventos.** Almenara deja de olvidar: cierra cada
minuto sus contadores de F4 y los guarda como rollups por minuto (48 h), hora
(90 días) y día local (2 años), con retención, purga y compactación. Con ellos
llegan la pestaña Histórico, las ventanas de 1 h y 24 h de Tráfico y el
histórico de cada equipo; se completan los eventos (vuelta a estar en línea,
servicios, SO y tipo) y la presencia, y se guarda el inventario por equipo.

### Añadido

- **Histórico agregado sin registro de conexiones** (ADR-58): rollups por
  minuto, hora y día con sujetos device, host, other y network; dimensiones
  total, app, categoría, destino, protocolo, proceso, organización y país;
  claves especiales (~sin_identificar, ~lan y ~desconocido) y tope de top_keys
  claves por cubo con el resto en ~otros (los totales cuadran).
- **Retención por resolución**: minutos 48 h y destinos 2 h; horas 90 días y
  destinos 30 días; días, inventario y sesiones 2 años. Purga horaria con
  incremental_vacuum y aviso si la BD supera max_db_mb.
- **Migración v5 aditiva**: TRAFFIC_ROLLUP_MINUTE/HOUR/DAY (WITHOUT ROWID),
  DEVICE_SEEN y APP_SESSIONS, auto_vacuum = INCREMENTAL (un único VACUUM) y
  test de compatibilidad F4 → F5 sin pérdida de datos.
- **Sesiones con latido**: cada ejecución abre una sesión (modo, captura,
  pasivo y versión), late cada minuto y se cierra con q o como interrumpida en
  el arranque siguiente. Los huecos de cobertura se marcan, nunca se
  interpolan.
- **Instancia única** por base de datos con flock sobre data.db.lock.
- **Eventos nuevos**: reappeared (con away_since/away_s), disappeared con
  last_seen, service_new (incluido reopened), service_gone, os_changed y
  type_changed; sin eventos de servicios en el primer escaneo ni con
  passive_only, y un puerto STALE por tiempo no emite evento.
- **Presencia por equipo** calculada al vuelo desde los eventos y las sesiones.
- **Inventario por equipo** (DEVICE_SEEN): apps, categorías, organizaciones,
  países y JA4 con primera y última vez, y puertos abiertos desde
  DEVICE_SERVICES.
- **Lector del histórico** en su propio hilo con conexión de solo lectura y
  progress_handler de 2 s; la TUI descarta las respuestas obsoletas.
- **TUI**: pestaña Histórico (sujeto con e, rango con w, foco con Tab, gráfica
  con huecos ░ y cursor < >, «Más tráfico» y línea de tiempo de eventos con f
  y /); ventanas de **1 h y 24 h** en Tráfico con volúmenes, minutos cerrados y
  huecos; detalle con histórico 24 h ⇄ 7 días, presencia y «Visto en este
  equipo»; línea «Último evento» en Equipos; [history], tamaño de la BD y
  cobertura en Config; Ayuda con las teclas y la privacidad.
- **Histórico sintético** determinista y prueba ignorada de medición
  (cargo test --release -- --ignored medir_historial), sin depender de
  CAP_NET_RAW.
- **Configuración** [history] con validación tolerante (aviso único y valor por
  defecto).
- README con el histórico, la retención, la privacidad, la copia de la BD
  (sqlite3 data.db ".backup copia.db" o VACUUM INTO), el consejo de dejar
  Almenara abierta (por ejemplo en tmux) para histórico continuo y la instancia
  única.

### Cambiado

- La versión sube a 0.5.0; la pestaña Histórico deja de ser un placeholder.
- cargo test incluye los rollups, la consolidación, la purga, la presencia, el
  inventario y las consultas del lector.

### Limitaciones conocidas

- Solo hay histórico mientras Almenara está abierta (la TUI es la que escribe);
  el modo servicio queda para el roadmap (ADR-59).
- El histórico guarda agregados: no hay detalle por conexión (ADR-58) y los
  destinos solo viven 2 h por minuto y 30 días por hora (ADR-57).
- Las 9 casillas de F4 pendientes de la pasada con CAP_NET_RAW siguen abiertas
  (decisión del desarrollador); las mediciones de F5 usan histórico sintético.

## [0.4.0] - 2026-11-11

**Fase 4 — Protocolos, apps y top talkers.** Almenara pone nombre al tráfico:
identifica el protocolo de aplicación, el nombre del servidor, la app y su
categoría, qué extremo es el cliente y cuál el servidor, y ofrece rankings por
destino, app, categoría, protocolo y proceso además del ranking por equipo.

### Añadido

- **Motor de inferencia** en el hilo de captura: reensamblado acotado del inicio
  de cada flujo TCP (4 KB cliente → servidor y 64 B servidor → cliente, con
  segmentos desordenados y duplicados), ~30 firmas de protocolo de aplicación
  (TLS, QUIC, HTTP, DNS, SSH, RDP, VNC, SMB, FTP, SMTP, IMAP, POP3, MQTT, CoAP,
  RTSP, SIP, STUN, WireGuard, OpenVPN, IPsec, BitTorrent, SNMP, NTP, SSDP,
  NetBIOS, DHCP, mDNS, LLMNR…) y rol cliente/servidor (SYN, sockets en LISTEN,
  puertos de servicio y primer datagrama UDP).
- **TLS**: parser propio del ClientHello con SNI normalizado, ALPN, versiones,
  cifrados, extensiones y algoritmos de firma; **JA4 de cliente** según la
  especificación pública de FoxIO (vectores oficiales en los tests).
- **QUIC**: descifrado del paquete Initial de QUIC v1 y v2 (claves derivadas del
  DCID, protección de cabecera y AEAD AES-128-GCM) con recomposición de las
  tramas CRYPTO, SNI y JA4 con prefijo `q`.
- **HTTP/1.x en claro**: `Host` y `User-Agent` de las peticiones.
- **Caché IP → nombre** (con caducidad de 1 h a 24 h, refresco por uso, tope de
  10 000 entradas y preferencia por el nombre consultado por el mismo equipo)
  alimentada por respuestas DNS (A/AAAA/CNAME), SNI y `Host`, persistida en la
  nueva tabla `NAME_CACHE`.
- **Catálogo propio de 162 apps en 12 categorías** (+ categoría especial
  `lan`) embebido en el binario, ampliable con `apps.toml`; reglas por
  dominio (gana el sufijo más largo), ASN y puerto, y apps de red local para los
  servicios detectados por la fase 2.
- **Destinos sin red**: dominio registrable con la Public Suffix List embebida y
  organización/país con las bases DB-IP Lite embebidas (IPv4 e IPv6).
- **Rankings** por equipo, destino, app, categoría, protocolo y proceso local en
  ventanas de 60 s, 5 min y sesión, con bytes ↓/↑ según el rol, equipos
  distintos, conexiones activas, porcentaje de tráfico sin identificar y panel
  «¿Quién lo usa?».
- **Identificación de equipos**: huella DHCP (opciones 55 y 60), nombre DHCP
  (opción 12), modelo anunciado por mDNS/UPnP, pistas del User-Agent de HTTP en
  claro, puntuación combinada de SO con umbral 4 y `os_source`, MAC privadas y
  `mac_changed` v2 (rotación de MAC privada y toma de IP con `reason`).
- **La captura como fuente L2** que crea equipos: ARP, DHCP y tramas IPv4 de la
  subred local, con filtros, deduplicación y tope de 4096 por ciclo.
- **Migración v4 aditiva**: columnas nuevas en `CONNECTIONS` (rol, protocolo de
  aplicación, nombre del servidor, app, categoría, fuentes y JA4) y en
  `DEVICES` (modelo, campos DHCP, User-Agent y fuente del SO), tabla
  `NAME_CACHE` y fuente `capture` en `DISCOVERY_SOURCES`. Test de
  compatibilidad v3 → v4 sin pérdida de datos.
- **Configuración**: sección `[inference]` (`enabled` activo por defecto,
  `apps_file`) y `[ui].traffic_group` persistida.
- **TUI**: en Tráfico `g` cicla la agrupación, `w` la ventana y `Enter`
  abre «¿Quién lo usa?» (o Conexiones filtradas en proceso); en Conexiones
  columnas Prot./Equipo/Destino/App, `i` alterna nombres ⇄ IPs y `v` amplía el
  panel con rol, fuentes, JA4 y proceso; el detalle de equipo muestra identidad,
  top 5 de apps y destinos y clientes TLS; Config muestra inferencia, catálogo y
  fecha de las bases IP; Ayuda añade privacidad y atribución a DB-IP.
- Script de desarrollo `scripts/actualizar-bases-ip.sh` y `data/FUENTES.md`
  con origen, fecha y licencia de cada dato embebido.

### Cambiado

- La inferencia está **activa por defecto** (ADR-37): leer cabeceras DNS/TLS/
  HTTP/QUIC y los primeros bytes de cada conexión se controla con
  `[inference].enabled`; el payload nunca se persiste.
- `[scan].passive_only` pasa a significar «no consultar a nadie»: además de
  desactivar el descubrimiento activo, ya no hace consultas NetBIOS ni DNS
  inverso. El DNS inverso de IPs de Internet no se hace nunca.
- Las claves de la fase 3 `[capture].inspect_payload`, `dns_attribution` y
  `sni_attribution` se aceptan pero se ignoran con un aviso único.
- La captura de ARP, DHCP y tramas puede crear equipos (`DISCOVERY_SOURCES`
  con `capture`), ampliando la regla de «solo L2 crea equipos».

### Corregido

- El primer paquete de cada clave de un ranking ya no se pierde al crear la
  entrada.
- El rol cliente/servidor se usa para orientar la bajada y la subida de los
  rankings y para atribuir el User-Agent y el SNI al equipo correcto.
- Nombres de dominio, SNI, `Host` y User-Agent solo aparecen en logs de nivel
  `debug`.

## [0.3.0] — Fase 3

Tráfico en vivo con AF_PACKET + TPACKET_V3, agregación por dispositivo,
conexiones activas con proceso local, snapshot persistente y pestañas
Tráfico/Conexiones con detalle de equipo.

## [0.2.0] — Fase 2

Descubrimiento avanzado: mDNS, SSDP/UPnP, leases DHCP, NetBIOS, port scan,
banner grabbing, fingerprint de SO y clasificación automática de equipos.

## [0.1.0] — Fase 1

Descubrimiento ARP/ICMP, reverse DNS, fabricante por OUI, inventario SQLite,
histórico de eventos y TUI con detalle de equipo.
