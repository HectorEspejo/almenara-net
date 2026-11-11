# Almenara — Informe de implementación de la Fase 4

**Fecha:** 2026-11-11 · **Versión del binario:** 0.4.0 · **Estado:** implementación completa y verificada;
solo queda la pasada manual con `CAP_NET_RAW` del sprint 4.0 (bloqueada por el entorno)
**Ámbito:** F4 «Protocolos, apps y top talkers» (`docs/fase4/almenara-fase4-checklist.md`, 166/175)
**Documento vivo:** actualizado de forma incremental; esta es la versión de cierre de la fase.

---

## Resumen de lo implementado

La Fase 4 pone nombre al tráfico de F3. Todo el código está escrito, el workspace compila y la suite
completa está en verde (`cargo test`: **812 tests unitarios + 4 de integración, 0 fallos,
2 ignorados**; `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings` limpios).

- **Motor de inferencia** (`src/inference/`) ejecutado **dentro del hilo de captura**:
  `Parser::parse_frame` localiza el payload sin copiarlo fuera de la trama; reensamblado acotado del
  inicio de flujo TCP (4 KB cliente → servidor, 64 B servidor → cliente, 8 paquetes y 3 s,
  tolerante a desorden y duplicados, tope de 1024 reensamblados por interfaz con
  `reassembly_drops`); ~30 firmas de protocolo; ClientHello TLS completo; Host y User-Agent de
  HTTP/1.x; respuestas DNS A/AAAA/CNAME; QUIC Initial v1/v2 descifrado (claves del DCID,
  protección de cabecera y AEAD, recomposición de tramas CRYPTO) con SNI y JA4 `q…`; JA4 de
  cliente `t…` con los vectores oficiales de FoxIO como tests.
- **Rol cliente/servidor** (SYN sin ACK, sockets en LISTEN de `/proc`, puertos de servicio frente a
  efímeros y primer datagrama UDP); `client_is_src = NULL` si no se puede deducir.
- **Resolución de etiquetas** (`LabelResolver`): caché IP → nombre (1 h–24 h, refresco por uso,
  tope 10 000, preferencia por el equipo que consultó), catálogo embebido de 162 apps y 13
  categorías con `apps.toml` propio, dominio registrable con PSL, organización y país con DB-IP
  Lite y precedencia dominio > servicio de F2 > ASN > puerto que **solo sube de fuerza**.
- **Rankings** por equipo, destino, app, categoría, protocolo y proceso local; ventanas de 60 s,
  5 min y sesión; bytes ↓/↑ orientados por rol; equipos distintos; conexiones activas; tope de 2048
  claves por dimensión con desalojo; % de tráfico sin identificar; panel «¿Quién lo usa?».
- **Identificación de equipos**: huella DHCP (55/60), nombre DHCP (12), modelo mDNS/UPnP, pistas de
  SO y tipo por User-Agent, puntuación combinada con umbral 4 y `os_source`, MAC privadas y
  `mac_changed` v2 (rotación y toma de IP con `reason`).
- **Captura como fuente L2** (`DISCOVERY_SOURCES.source = 'capture'`): ARP, DHCP y tramas IPv4 de
  la subred local crean equipos, con filtros, deduplicación por MAC+IP y tope de 4096 por ciclo.
- **Migración v4 aditiva**: 8 columnas en CONNECTIONS, 6 en DEVICES, tabla NAME_CACHE con sus
  índices e IDX_CONN_APP; DAOs y test de compatibilidad v3 → v4 sin pérdida de datos.
- **Configuración**: `[inference]` (`enabled` por defecto, `apps_file`) y `[ui].traffic_group`;
  claves obsoletas de F3 avisadas una sola vez y descartadas.
- **TUI**: Tráfico con `g`/`w`/`Enter` («¿Quién lo usa?»), Conexiones con Prot./Equipo/Destino/
  App, `i` nombres ⇄ IPs y panel `v` ampliado, detalle con identidad y top apps/destinos, Config
  con inferencia/catálogo/bases IP, Ayuda con privacidad y atribución a DB-IP.
- **Privacidad**: el payload nunca se persiste ni sale del hilo de captura; los dominios solo viven
  en `CONNECTIONS` y `NAME_CACHE` y solo aparecen en logs de nivel `debug`.

### Verificación realizada (medidas)

- `cargo test`: **812 + 4 tests, 0 fallos, 2 ignorados**.
- `cargo fmt --check`: limpio. `cargo clippy --all-targets -- -D warnings`: limpio.
- **Arranque real** del binario recompilado en modo degradado (sin `CAP_NET_RAW`): la BD migra a
  **v4**, carga `NAME_CACHE`, crea la plantilla de configuración con `[inference]` y
  `[ui].traffic_group`, y la TUI arranca sin pánicos.
- **Carga de datos embebidos**: catálogo + apertura de las dos MMDB = **46 ms** (límite §8: 200 ms).
- **Tamaño de los datos embebidos**: **18 206 592 bytes (~17,4 MiB)** (límite §8: 25 MB).

## Desviaciones respecto a la especificación (qué y por qué)

1. **Sprint 4.0 (verificación pendiente de F1–F3): incompleto y bloqueado.** El entorno de
   desarrollo no tiene contraseña de `sudo`, así que no se puede aplicar `CAP_NET_RAW` al binario.
   La pasada manual con capacidad sobre la red real (F1-24, F1-25, F1-64, mediciones §8 de F2/F3 y
   prueba visual en `wlp191s0`) queda pendiente de que el desarrollador ejecute
   `scripts/ejecutar-con-permisos.sh`. No se simulan ni se inventan medidas.
2. **`who_uses` no redondea**; la TUI redondea a un decimal.
3. **Pico de 60 s**: no es campo aparte de `RankRow`; es `max(series_60s)` y la serie solo se
   rellena en la dimensión App (el resto la deja a cero para no engordar el evento).
4. **`Rankings::top_for_device`** es una API añadida (no figuraba en §5) para el top 5 de apps y
   destinos del detalle de equipo (mockup 4).
5. **Desalojo de rankings**: si al superar 2048 claves todas siguen activas se desaloja también la
   más antigua, para que el tope sea un límite real de memoria.
6. **Nombres de app >40 caracteres** en apps embebidas: el límite del §7.16 se aplica solo a
   `apps.toml` del usuario; los dos nombres largos del catálogo mantienen el texto exacto de §7.9.
7. **Apps `lan`** (10): sin reglas de dominio/ASN/puerto; se resuelven solo por servicio de F2 para
   no etiquetar tráfico WAN al 445 como red local.
8. **`IpDb::build_date()`** devuelve la fecha completa del `build_epoch` de la MMDB (2026-11-01);
   `FUENTES.md` anota la versión 2026-11.
9. **`capture/dns.rs` y `capture/sni.rs` eliminados** (movidos a `inference/dns.rs` e
   `inference/tls.rs`, §12); `PacketMeta` ya no copia QNAME ni SNI.
10. **Top 50 por dimensión y ventana ordenado por total**; la TUI reordena con `s` las filas
    recibidas (publicar los 4 órdenes de las 18 combinaciones no cabía en el presupuesto del evento).
11. **`Ranking de proceso`** solo cuenta tráfico del propio equipo, como pide §7.11.

## Estructura de archivos creada/modificada

Nuevos:

- `src/inference/`: `mod.rs`, `inspector.rs`, `resolver.rs`, `reassembly.rs`, `protocols.rs`,
  `tls.rs`, `http.rs`, `dns.rs`, `ja4.rs`, `quic.rs`, `names.rs`, `catalog.rs`, `domain.rs`,
  `ipdb.rs`, `role.rs`.
- `src/identify/`: `mod.rs`, `dhcp.rs`, `models.rs`, `useragent.rs`, `mac.rs`, `observed.rs`.
- `src/rankings.rs`; `src/repo/names.rs`.
- `data/catalogo.toml`, `data/dbip-asn-lite.mmdb`, `data/dbip-country-lite.mmdb`,
  `data/FUENTES.md`; `scripts/actualizar-bases-ip.sh`.
- `tests/fixtures/fase4-replay.pcap` y tests de replay mixto en `src/inference/inspector.rs`.
- `CHANGELOG.md`; este informe.

Modificados: `Cargo.toml`/`Cargo.lock`, `README.md`, `src/main.rs`, `src/config.rs`,
`src/capture/{mod,parser,aggregate}.rs` (y borrados `capture/dns.rs` y `capture/sni.rs`),
`src/traffic.rs`, `src/events.rs`, `src/scanner/mod.rs`, `src/discovery/mod.rs`,
`src/repo/{migrations,connections,devices,discovery_sources,mod}.rs`, `src/tui/**`.

## Decisiones técnicas tomadas durante el desarrollo

1. **El payload no cambia de hilo.** `Parser::parse_frame` devuelve el rango del payload dentro de
   la trama; `FlowInspector::inspect` lo consume y lo descarta en el hilo de captura. Al agregador
   solo viajan `PacketMeta` y `Evidence` en lotes (`CaptureBatch`).
2. **Etiqueta débil perezosa**: nombre en caché/ASN/servicio/puerto se resuelve una vez por flujo; el
   volcado a rankings es por flujo y segundo (no por paquete).
3. **Evidencias con rol y extremos completados** al final de `inspect` para que cualquier extractor
   (TLS, HTTP, DNS, UDP, QUIC) lleve cliente/servidor correctos.
4. **Descubrimiento de QUIC solo en dirección cliente → servidor** (el Initial del servidor no se
   descifra con las claves del DCID del cliente) y gate por `quic_done` para recomponer el
   ClientHello en varios Initial.
5. **Rankings en memoria** con las ventanas de F3 (`capture::windows::Windows`); publicación del
   top 50 de las 18 combinaciones dimensión×ventana en `AppEvent::Traffic`.
6. **«¿Quién lo usa?»** con `TrafficCommand::WhoUses` + `oneshot` (timeout de 200 ms en la TUI).
7. **DB-IP Lite embebida** (17,4 MiB, CC BY 4.0) con `maxminddb`; PSL con `psl`; sin red en
   ejecución. Actualización solo con el script de desarrollo.
8. **Configuración tolerante**: claves obsoletas de F3 detectadas, avisadas una sola vez y
   descartadas; valores inválidos → valor por defecto con aviso, nunca abortar.
9. **Migración v4 idempotente** con comprobación previa (`already_applied`) y test real v3 → v4.
10. **Privacidad en logs**: los dominios/nombres solo se registran con `tracing::debug!`; nunca en
    `info/warn/error`.

## Funcionalidades del checklist completadas

(copiadas literalmente del checklist marcado: **166 de 175**)

### Migración y modelo de datos

- gración v4 aditiva registrada en `SCHEMA_MIGRATIONS` e idempotente
- lumnas de rol y etiquetas en `CONNECTIONS` (`client_is_src`, `app_protocol`, `server_name`, `name_source`, `app`, `category`, `app_source`, `ja4`)
- lumnas de identidad en `DEVICES` (`model`, `dhcp_fingerprint`, `dhcp_vendor`, `dhcp_hostname`, `user_agent`, `os_source`)
- bla `NAME_CACHE` con `UNIQUE (ip, name)` e índices `IDX_NAME_CACHE_IP` e `IDX_NAME_CACHE_EXPIRES`
- dice `IDX_CONN_APP` sobre `CONNECTIONS(app)`
- lor `capture` admitido en `DISCOVERY_SOURCES.source`
- st de compatibilidad v3 → v4 sin pérdida de datos

### Configuración

- cción `[inference]` con `enabled = true` por defecto y `apps_file` opcional
- aves `inspect_payload`, `dns_attribution` y `sni_attribution` ignoradas con un aviso único
- eferencia `[ui].traffic_group` guardada al cambiar la agrupación con `g` en Tráfico
- antilla de configuración por defecto con `[inference]` y `[ui].traffic_group`
- lores inválidos de `[inference]` y `[ui].traffic_group` avisan y usan el valor por defecto sin abortar

### Rol cliente/servidor

- l deducido del SYN sin ACK en TCP
- l deducido de los sockets en escucha de `/proc`, de los puertos de servicio y del primer datagrama UDP cuando no se vio el inicio
- lient_is_src` queda en NULL cuando el rol no se puede deducir

### Reensamblado y firmas de protocolo

- ensamblado del inicio de cada flujo TCP: 4 KB cliente → servidor y 64 B servidor → cliente
- ffers de reensamblado liberados al completar el mensaje, a los 4 KB, a los 8 paquetes o a los 3 s
- pe de 1024 reensamblados simultáneos por interfaz con contador `reassembly_drops`
- entificación del protocolo de aplicación por firma y puerto con los valores de la tabla del §7.3
- ntador `inference_errors` para entradas mal formadas sin detener la captura

### TLS, HTTP y JA4

- rser del ClientHello TLS con SNI normalizado, ALPN, versiones, cifrados, extensiones y algoritmos de firma
- tracción de `Host` y `User-Agent` de peticiones HTTP/1.x en claro
- ella JA4 de cliente TLS (`t…`) según la especificación pública

### QUIC

- tección de paquetes Initial de QUIC v1 y v2
- rivación de claves Initial, retirada de la protección de cabecera y descifrado AEAD
- composición del ClientHello a partir de tramas CRYPTO repartidas en varios Initial
- I y JA4 (`q…`) de conexiones QUIC
- itial de versión desconocida o que no se puede descifrar descartado sin error visible y con contador

### DNS y caché de nombres

- spuestas DNS A, AAAA y CNAME convertidas en IP → nombre consultado con `hickory-proto`
- ducidad de la caché entre 1 h y 24 h con refresco por uso
- pe de 10 000 entradas con desalojo por `last_seen` más antiguo
- I y `Host` también alimentan la caché de nombres
- eferencia por el nombre consultado por el mismo equipo cuando una IP tiene varios nombres
- rsistencia de la caché en `NAME_CACHE` cada 5 s y carga de las entradas vigentes al arrancar
- rga de entradas caducadas de `NAME_CACHE` en el ciclo de 5 s

### Catálogo de apps y categorías

- tálogo embebido `data/catalogo.toml` con las 12 categorías y la categoría especial `lan`
- das las apps de la lista mínima del §7.9 (162) presentes en el catálogo
- glas por sufijo de dominio con prioridad del sufijo más largo
- glas por ASN y por puerto
- mentario de origen en cada app del catálogo embebido
- tegoría `tracking` (publicidad, rastreo y telemetría) con lista propia
- chero `apps.toml` del usuario que añade apps o sustituye las embebidas

### Destinos: dominio registrable y base IP

- minio registrable con la Public Suffix List embebida
- ses DB-IP Lite de ASN y país embebidas para IPv4 e IPv6
- ganización y país sin acceso a red y omitidos para IPs privadas, de enlace local, de loopback y multicast
- ript `scripts/actualizar-bases-ip.sh` que sustituye las MMDB y actualiza `data/FUENTES.md`
- ribución a DB-IP en Ayuda, README y `data/FUENTES.md`

### Resolución de etiquetas

- mbre del servidor por precedencia SNI > Host > caché de nombres
- p por precedencia dominio > servicio de F2 > ASN > puerto, con `app_source`
- etiqueta de un flujo solo cambia a una evidencia más fuerte
- n `[inference].enabled = false` solo hay etiquetas por servicio de F2, ASN, puerto y proceso
- l, etiquetas y JA4 persistidos en `CONNECTIONS` en el ciclo de 5 s

### Identificación de equipos

- ella DHCP (opciones 55 y 60) y nombre (opción 12) de los paquetes DHCP capturados
- glas propias de huella DHCP para Windows, Apple, Android, Linux e IoT, cada una con origen y prueba
- delo desde los TXT de mDNS (`model`, `am`, `md`, `ty`, `rpMd`) y desde la descripción UPnP
- stas de SO y de tipo desde el User-Agent de HTTP en claro
- s_family` combina huella TCP de F2, DHCP, modelo y User-Agent con umbral 4 y registra `os_source`
- glas de `device_type` por modelo y User-Agent antes que las de hostname
- mbre DHCP capturado y nombre de Google Cast (`fn`) en la precedencia de hostname
- mpos de identidad persistidos en `DEVICES`

### MAC privadas y mac_changed v2

- C privada detectada por el bit U/L y mostrada como «MAC privada» en la columna Fabricante
- ento `new` con `mac_random` en sus detalles
- ac_changed` por rotación de MAC privada con la misma huella y el mismo nombre DHCP
- n fusión de identidad cuando hay varios candidatos de rotación
- urística de toma de IP de F1 sin aplicar si las huellas DHCP se contradicen, y con `reason = ip_takeover` cuando se aplica

### Captura como fuente de equipos

- uipos observados en ARP, DHCP y tramas IPv4 con MAC e IP de una subred local
- ltros de equipos observados: MAC propia o de grupo, IP 0.0.0.0, broadcast o propia, IP fuera de subred y MAC del gateway con otra IP
- ffer `ObservedHosts` con deduplicación por MAC + IP y tope de 4096
- ta de equipos con fuente `capture` y evento `new`
- s observaciones de la captura cuentan como «visto» en el marcado offline

### Modo pasivo

- assive_only` desactiva las consultas NetBIOS
- assive_only` desactiva el DNS inverso
- nca se hace DNS inverso de IPs de Internet, en ningún modo
- rra de estado y Ayuda con las fuentes del modo pasivo actualizadas (sin NetBIOS, con captura)

### Rankings

- nkings por destino, app, categoría, protocolo y proceso local además del de equipo
- ave de destino: dominio registrable, IP remota o equipo de la LAN
- ntanas de 60 s y 5 min y acumulado de sesión por clave
- jada y subida según el rol cliente/servidor
- uipos distintos y conexiones activas por clave
- pe de 2048 claves por dimensión con desalojo de las inactivas
- rcentaje de tráfico sin identificar por ventana
- nking de procesos solo con tráfico del propio equipo
- blicación del top 50 por dimensión y ventana en `AppEvent::Traffic` y consulta `TrafficCommand::WhoUses`

### TUI: Tráfico

- cla `g` en Tráfico: equipo → destino → app → categoría → protocolo → proceso
- cla `w` en Tráfico: ventana 60 s → 5 min → sesión
- lumnas de cada agrupación según las notas de UX del §6
- nel «¿Quién lo usa?» con `Enter` sobre destino, app, categoría o protocolo
- nter` sobre un proceso abre Conexiones filtrada por ese proceso
- e con «Sin identificar: N %» y la línea de visibilidad de F3
- dicador «inferencia: activa / desactivada» en la barra de estado
- nsaje claro cuando no hay datos en la ventana

### TUI: Conexiones

- lumnas Prot., Equipo, Destino, App, ↑, ↓ y Edad a 80 columnas; Estado desde 100 columnas
- stino con el nombre del servidor si existe y la IP con organización y país si no
- las sin rol en orden canónico con `?` delante del destino
- cla `i` para alternar nombres e IPs
- nel `v` con rol, fuentes del nombre y de la app, JA4 y proceso local
- squeda `/` también por nombre del servidor, app y proceso

### TUI: Detalle, Config y Ayuda

- talle de equipo con modelo, SO y su fuente, huella DHCP abreviada y MAC privada
- p 5 apps y top 5 destinos del equipo en el detalle (ventana de 5 min)
- ientes TLS distintos (JA4) en el detalle
- splazamiento del panel de detalle cuando no cabe
- nfig muestra `[inference]`, estadísticas del catálogo y fecha de las bases IP
- uda con las teclas nuevas (`g` y `w` en Tráfico, `i` y `v` en Conexiones, `Enter` en rankings)
- uda con el aviso de privacidad de la inferencia y cómo desactivarla
- uda con el modo pasivo redefinido y la atribución de DB-IP y de la Public Suffix List

### Privacidad

- ngún payload se persiste; solo etiquetas derivadas
- ffers de reensamblado y payload QUIC descifrado liberados en el hilo de captura tras extraer la etiqueta
- er-Agent y campos DHCP saneados y truncados antes de persistir

### Rendimiento y robustez

- rsers sin pánicos ante entradas truncadas o aleatorias
- rga del catálogo y de las bases IP ≤ 200 ms al arrancar
- nario con ≤ 25 MB más por los datos embebidos

### Pruebas

- sts unitarios de firmas, TLS, HTTP, DNS, JA4 y QUIC con fixtures
- sts del catálogo (precedencia, sufijo más largo, `apps.toml`) y del dominio registrable
- sts de identificación (DHCP, modelo, User-Agent, MAC privada, `mac_changed` v2)
- sts de rankings y del porcentaje sin identificar
- plays pcap de tráfico mixto (TLS partido, QUIC, DNS, DHCP, ARP) con etiquetas esperadas
- argo fmt --check` y `cargo clippy --all-targets -- -D warnings` limpios

### Documentación y versión

- ADME actualizado: inferencia, privacidad, bases IP y cómo actualizarlas
- ata/FUENTES.md` con origen, fecha y licencia de cada dato embebido
- rsión 0.4.0 en `Cargo.toml` y en Ayuda
- vedades de la 0.4.0 en `CHANGELOG.md`

### Servicios internos (API)

- lowInspector::new` — estado de inspección por interfaz
- lowInspector::inspect` — firmas, reensamblado y extractores
- abelResolver::resolve` — nombre, app, categoría y fuentes
- abelResolver::observe_name` — alimenta la caché de nombres
- treamStart::push` — inicio de flujo TCP
- ryptoStream::push` — tramas CRYPTO de QUIC
- rotocols::identify` — firma o puerto
- ls::parse_client_hello` — ClientHello TLS
- ttp::parse_request` — Host y User-Agent
- ns::extract_query` — QNAME de una consulta
- ns::extract_answers` — IP → nombre consultado
- uic::initial_version` — Initial de QUIC v1 o v2
- uic::decrypt_initial` — claves, protección de cabecera y AEAD
- a4::compute` — huella t… o q…
- ameCache::observe` — inserta o refresca una entrada
- ameCache::lookup` — mejor nombre vigente para una IP
- atalog::load` — catálogo embebido + apps.toml
- atalog::match_name` — sufijo de dominio más largo
- atalog::match_asn` — regla por ASN
- atalog::match_port` — regla por puerto
- atalog::lan_app` — app de red local para un servicio de F2
- omain::registrable` — eTLD+1
- pDb::embedded` — abre las MMDB embebidas
- pDb::lookup` — ASN, organización y país
- ole::infer` — client_is_src
- hcp::parse` — paquete DHCP capturado
- odels::from_mdns_txt` — modelo por TXT de mDNS
- odels::from_upnp` — modelo por descripción UPnP
- serAgent::hints` — pistas de SO y tipo
- dentify::os_family` — puntuación combinada de SO
- ac::is_private` — bit U/L
- ac::rotation_match` — regla de rotación
- bservedHosts::push` — equipo observado desde la captura
- bservedHosts::drain` — vaciado desde el ciclo de escaneo
- ankings::record` — suma a cada dimensión
- ankings::tick` — ventanas y desalojo
- ankings::top` — filas de un ranking
- ankings::who_uses` — panel «¿Quién lo usa?»
- ankings::unidentified_share` — % sin identificar
- epo::upsert_connection` — (extendido) rol, etiquetas y JA4
- epo::upsert_names` — caché de nombres
- epo::list_names` — arranque en caliente
- epo::prune_names` — purga de caducadas
- epo::set_device_identity` — campos de identidad del equipo
- onfig::load` — (extendido) [inference], [ui].traffic_group y claves obsoletas

## Pendientes y bloqueos

**Bloqueo (sprint 4.0):** sin `sudo` no se puede aplicar `CAP_NET_RAW` en este entorno. Quedan sin
marcar (9 casillas):

1. Pasada manual de F1-24 y F1-25 con `CAP_NET_RAW` anotada en el informe de implementación.
2. Medición de rendimiento de F1-64 anotada en el informe de implementación.
3. Mediciones del §8 de F2 (ciclo completo y port scan) anotadas en el informe de implementación.
4. Mediciones del §8 de F3 (pps, CPU y render) anotadas en el informe de implementación.
5. Prueba visual de F3 en `wlp191s0` con el binario recompilado anotada en el informe.
6. Captura sostenida de 50 K pps sin pérdidas con la inferencia activa (medido).
7. CPU ≤ 20 % a 10 K pps y ≤ 7 % a 1 K pps con la inferencia activa (medido).
8. Memoria añadida por la fase ≤ 64 MB con los topes del §8 (medido).
9. Dominios, SNI, `Host` y User-Agent solo en logs de nivel `debug` (AC: 5 min de navegación con
   `-v` y comprobar que el log no contiene dominios).

Para cerrarlas: ejecutar `scripts/ejecutar-con-permisos.sh`, pasar un ciclo completo y la prueba
visual en `wlp191s0`, medir pps/CPU/memoria con la inferencia activa y revisar el log con `-v`.
Los ítems 8 y 9 de rendimiento/privacy se pueden completar en esa misma pasada.

## Ejecución y pruebas

```bash
cargo run                              # arranca la TUI (sin CAP_NET_RAW usa modo degradado)
scripts/ejecutar-con-permisos.sh       # arranca con CAP_NET_RAW (setcap + usuario actual)
cargo test                             # suite completa (812 + 4)
cargo test --features pcap             # replay condicional preparado para F7
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

- La **migración v4 es aditiva e idempotente**: una BD de F3 se abre sin pérdida de datos y las
  columnas nuevas quedan en NULL. Verificado en el test de compatibilidad v3 → v4 y en un arranque
  real (BD con `version_esquema = 4`, `NAME_CACHE` con sus índices y columnas nuevas en
  CONNECTIONS/DEVICES).
- **Datos embebidos**: `data/catalogo.toml`, `data/dbip-*.mmdb` y la PSL del crate `psl`.
  Actualización de las bases IP con `scripts/actualizar-bases-ip.sh` (solo desarrollo).
- **Privacidad**: nombres de dominio y User-Agent solo en logs `debug` (`-vv`); el payload no se
  persiste. `[inference].enabled = false` desactiva toda lectura por encima de las cabeceras.
- **Fixture de replay mixto**: `tests/fixtures/fase4-replay.pcap` (TLS partido y desordenado,
  Initial de QUIC del RFC 9001, respuesta DNS, DHCP DISCOVER/ACK y ARP) con etiquetas esperadas.
