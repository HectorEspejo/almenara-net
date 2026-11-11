# Almenara

Monitor de red en TUI para Linux: descubre los equipos conectados a la red local, qué servicios
ofrecen, **qué tráfico generan en vivo**, **quién está detrás de cada conexión** y **qué ha pasado
los últimos dos años**. **Fase 5: histórico, rollups y eventos** — cierra cada minuto los
contadores de la Fase 4 y los guarda como agregados por minuto (48 h), hora (90 días) y día local
(2 años), con retención, purga y compactación; añade la pestaña **Histórico**, las ventanas de
**1 h y 24 h** de Tráfico y el histórico del detalle de equipo, completa los eventos (vuelta a
estar en línea, servicios, SO y tipo), calcula la **presencia** y guarda el **inventario por
equipo**. Todo sobre la base de las fases 1 a 4 (descubrimiento ARP/ICMP/DNS/OUI, mDNS, SSDP,
DHCP, NetBIOS, port scan, fingerprint, clasificación, captura AF_PACKET + TPACKET_V3, tráfico en
vivo, protocolos, apps y top talkers).

## Estado del proyecto

**Fases 1 a 5 implementadas** (pendiente de entrega del informe de implementación de la Fase 5 al
analista funcional; las 9 casillas de F4 de la pasada con `CAP_NET_RAW` siguen pendientes por
decisión del desarrollador). Documentación:

- Fase 1: [informe de fase](docs/fase1/almenara-fase1-informe.md),
  [checklist](docs/fase1/almenara-fase1-checklist.md) e
  [informe de implementación](docs/fase1/almenara-fase1-implementacion.md).
- Fase 2: [informe de fase](docs/fase2/almenara-fase2-informe.md),
  [checklist](docs/fase2/almenara-fase2-checklist.md) e
  [informe de implementación](docs/fase2/almenara-fase2-implementacion.md).
- Fase 3: [informe de fase](docs/fase3/almenara-fase3-informe.md),
  [checklist](docs/fase3/almenara-fase3-checklist.md) e
  [informe de implementación](docs/fase3/almenara-fase3-implementacion.md).
- Fase 4: [informe de fase](docs/fase4/almenara-fase4-informe.md),
  [checklist](docs/fase4/almenara-fase4-checklist.md) e
  [informe de implementación](docs/fase4/almenara-fase4-implementacion.md).
- Fase 5: [informe de fase](docs/fase5/almenara-fase5-informe.md),
  [checklist](docs/fase5/almenara-fase5-checklist.md) e
  [informe de implementación](docs/fase5/almenara-fase5-implementacion.md).

## Novedades de la Fase 5

- **Histórico agregado sin registro de conexiones**: rollups por minuto (48 h), hora (90 días) y
  día local (2 años) con sujetos device/host/other/network y dimensiones total, app, categoría,
  destino, protocolo, proceso, organización y país. Las claves especiales y el tope de 20 claves
  con `~otros` mantienen los totales exactos sin que la base crezca sin control.
- **Retención por resolución y tamaño acotado**: destinos solo 2 h por minuto y 30 días por hora
  (nunca en días ni en el inventario), purga horaria con `incremental_vacuum` y aviso si la BD
  supera `max_db_mb`.
- **Pestaña Histórico**: sujeto con `e`, rango con `w` (24 h → 7 días → 30 días → 1 año), gráfica
  con huecos `░` y cursor `<` `>`, «Más tráfico» y línea de tiempo de eventos con filtro `f` y
  búsqueda `/`; foco con `Tab`.
- **Tráfico de 1 h y 24 h** desde el histórico (volúmenes, minutos cerrados y huecos) y
  «¿Quién lo usa?» en esas ventanas; **detalle de equipo** con histórico 24 h ⇄ 7 días, presencia
  de 24 h y 7 días e inventario («Visto en este equipo»).
- **Eventos nuevos**: vuelta a estar en línea, servicios que se abren o cierran, cambios de SO y de
  tipo, y `disappeared` con la última vez visto. La **presencia** se calcula al vuelo desde los
  eventos y las sesiones: cuando Almenara está cerrada se muestra «sin datos», nunca presente o
  ausente inventados.
- **Sesiones con latido** (para distinguir «sin tráfico» de «sin datos») e **instancia única** por
  base de datos: una segunda Almenara no arranca y avisa con el PID de la que está en marcha.
- **Privacidad**: solo agregados, sin contenido y sin nombres completos; los destinos son el
  dominio registrable, la IP o el equipo de la LAN; el histórico se desactiva con
  `[history].enabled = false`.
- **Medición sin captura**: histórico sintético determinista y prueba ignorada `medir_historial`.

## Novedades de la Fase 4

- **Etiqueta cada conexión**: protocolo de aplicación (TLS, QUIC, HTTP, DNS, SSH…), nombre del
  servidor (SNI de TLS/QUIC, `Host` de HTTP o caché IP → nombre alimentada por las respuestas
  DNS), app y categoría del catálogo, fuente de cada dato y JA4 del cliente.
- **Rol cliente/servidor** deducido del SYN, de los sockets en escucha y de los puertos; las
  etiquetas solo cambian a una evidencia más fuerte.
- **Catálogo propio de 162 apps en 12 categorías** embebido, ampliable con `apps.toml`, con
  reglas por dominio (sufijo más largo), ASN y puerto, y apps de red local para los servicios de
  la fase 2.
- **Destinos sin red**: dominio registrable (Public Suffix List embebida) y organización y país
  con las bases DB-IP Lite embebidas (IPv4 e IPv6).
- **Top talkers**: rankings por equipo, destino, app, categoría, protocolo y proceso local en
  ventanas de 60 s, 5 min y sesión, con % de tráfico sin identificar y panel «¿Quién lo usa?».
- **Identificación de equipos** con huella DHCP, modelo mDNS/UPnP, User-Agent de HTTP en claro,
  MAC privadas y `mac_changed` v2; la **captura (ARP, DHCP, tramas) crea equipos** como fuente L2.
- **Privacidad**: el payload nunca sale del hilo de captura ni se persiste; los dominios solo
  viven en tablas calientes y fuera de los logs por encima de `debug`.
- `passive_only` ahora significa **no consultar a nadie**: sin NetBIOS ni DNS inverso, y nunca se
  hace DNS inverso de IPs de Internet.

## Novedades de la Fase 3

- **Captura sin libpcap**: socket AF_PACKET con anillo TPACKET_V3 (64 MB: 64 bloques de 1 MB,
  frames de 4 KB) y un hilo dedicado por interfaz. Filtro **BPF clásico** adjunto al socket con
  `SO_ATTACH_FILTER` desde `[capture].filter` (vacío = sin filtro). Si el filtro no compila se
  avisa y se captura sin él.
- **Parser propio**: Ethernet (con VLAN), IPv4, IPv6 (incluidas extensiones básicas), TCP (flags),
  UDP e ICMP/ICMPv6. El **payload nunca se persiste**; con `inspect_payload = false` se descarta
  al instante y solo se copian las cabeceras para el panel de la tecla `v`.
- **Atribución DNS y SNI** (opcional, activa por defecto): QNAME de consultas DNS del puerto 53 y
  SNI de ClientHello TLS del puerto 443.
- **Agregación y sparklines en memoria**: bytes y paquetes ↑/↓ por dispositivo, pico en la
  ventana de 60 s, ring buffers de 60 puntos (1 s) y 5 min (1 punto cada 5 s).
- **Conexiones activas**: merge por 5-tuple de `/proc/net/{tcp,udp}{,6}`, `/proc/net/nf_conntrack`
  (best-effort) y la captura de paquetes, con estado TCP y atribución del socket local a PID/comm
  vía `/proc/[pid]/fd` (degradación silenciosa sin permisos). Purga por timeout cada 5 s.
- **Persistencia**: migración v3 aditiva con `TRAFFIC_SNAPSHOT` (una fila por dispositivo, cada
  5 s) y `CONNECTIONS` (tabla caliente). `TRAFFIC_SNAPSHOT` se usa como semilla al reabrir.
- **TUI**: pestaña Tráfico (ranking top-10 con sparkline), pestaña Conexiones (tabla plana
  ordenable/filtrable con etiquetas `[host]`/`[broadcast]`), panel **detalle de equipo**
  master-detail y panel inferior de cabeceras IP/TCP con `v`. Barra de estado ampliada con el
  estado de captura y la visibilidad honesta (`propia + broadcast`).

## Requisitos

- Linux con kernel 3.2 o superior (TPACKET_V3).
- Rust 1.88 o superior con `cargo`.
- Conexión a red en el primer `cargo build` para descargar y compilar las dependencias.
- Datos embebidos en el binario (catálogo, Public Suffix List y ~18 MB de bases DB-IP Lite): la
  aplicación **no descarga nada en ejecución**.
- Terminal de al menos 80x24.
- Para capturar paquetes: `CAP_NET_RAW` (ver más abajo). El resto de la aplicación funciona sin
  privilegios.

## Compilación y arranque

```bash
cargo build
cargo run
cargo run -- -c /ruta/a/config.toml   # configuración alternativa
cargo run -- -v                       # más detalle en los logs
cargo run -- -vv                      # detalle máximo en los logs
cargo run -- --no-color               # sin color (equivale a NO_COLOR=1)
cargo run -- --version
cargo run -- --help
```

El binario queda en `target/debug/almenara` y también puede ejecutarse directamente.

## Permisos y modo degradado

El descubrimiento activo (ARP, ICMP, port scan, banner grabbing, fingerprint) y la **captura de
tráfico** requieren `CAP_NET_RAW`:

```bash
cargo build
sudo setcap cap_net_raw+ep target/debug/almenara
getcap target/debug/almenara            # verificación
./target/debug/almenara
sudo setcap -r target/debug/almenara    # quitarla
```

También puedes usar el script de arranque, que compila, aplica `CAP_NET_RAW` **solo al binario**
y ejecuta Almenara con tu usuario (la configuración, la base de datos y los logs siguen en tu
`HOME`; no se lanza la TUI como root):

```bash
./scripts/ejecutar-con-permisos.sh                      # compila debug y arranca
./scripts/ejecutar-con-permisos.sh --release            # binario release
./scripts/ejecutar-con-permisos.sh -- -vv --no-color    # argumentos para Almenara
./scripts/ejecutar-con-permisos.sh --comprobar          # enseña qué haría, sin aplicar nada
./scripts/ejecutar-con-permisos.sh --retirar-al-salir   # quita la capability al terminar
```

El script reaplica la capability en cada arranque porque `setcap` se pierde al recompilar el
binario. Requiere el paquete `libcap2-bin` (`setcap`/`getcap`) y `sudo`.

Si recompilas, la capability puede perderse: vuelve a aplicarla. Sin ella la aplicación arranca en
**modo degradado**: la captura de paquetes se deshabilita con un aviso claro en la barra (prefijo
`[CAP:off]`), la pestaña Tráfico muestra el último snapshot y las conexiones se leen igualmente
de `/proc/net/*`. En modo degradado el descubrimiento se limita a las fuentes pasivas. La
aplicación nunca eleva privilegios por sí misma.

## Rutas

- Configuración: `~/.config/almenara/config.toml`
- Base de datos: `~/.local/share/almenara/data.db`
- Logs: `~/.local/state/almenara/log/` (rotación por tamaño)

## Configuración

Si el fichero de configuración no existe, se crea una plantilla con los valores por defecto al
arrancar (y se usan esos valores aunque la creación no sea posible). Ejemplo actualizado a Fase 4:

```toml
[scan]
interfaces = "auto"              # "auto" o nombres de interfaz
ranges = ["192.168.1.0/24"]      # rangos IPv4 CIDR a escanear (máx. 1024 IPs por rango)
interval_s = 60                  # intervalo entre escaneos (mínimo 10)
icmp_timeout_ms = 500            # timeout ICMP y reverse DNS (100-5000)
offline_after_cycles = 3         # ciclos sin ver un equipo antes de marcarlo offline
passive_only = false             # true = solo escuchar: sin escaneo, NetBIOS ni DNS inverso
top_ports = [22, 23, 53, 80, 139, 443, 445, 515, 631, 1883, 3389, 5000, 5353, 5555, 8008, 8080, 8443, 9100, 32400]
dhcp_lease_paths = []            # rutas manuales adicionales de ficheros de leases DHCP

[capture]
enabled = true                   # activa la captura de paquetes al arrancar
filter = ""                      # BPF clásico (por ejemplo "not port 22"); vacío = sin filtro
max_pps = 0                      # 0 = sin límite; aviso una vez por minuto al alcanzarlo

[inference]
enabled = true                   # inferencia activa (lee DNS/TLS/HTTP/QUIC; no guarda contenido)
apps_file = "~/.config/almenara/apps.toml"  # reglas propias de apps (opcional)

[storage]
db_path = "~/.local/share/almenara/data.db"
events_retention_days = 90       # retención de DEVICE_EVENTS y de servicios STALE

[history]                        # histórico (Fase 5)
enabled = true                   # false = no guardar rollups ni inventario (w salta 1 h y 24 h)
minute_days = 2                  # minutos: 48 h (los destinos por minuto, 2 h fijas)
hour_days = 90                   # horas
day_days = 730                   # días, inventario y sesiones (2 años)
destination_days = 30            # destinos por hora (0 = no guardarlos)
top_keys = 20                    # claves por sujeto, dimensión y cubo; el resto, «otros»
max_db_mb = 1024                 # aviso cuando la base de datos lo supera

[ui]
theme = "default"
no_color = false
list_view = "flat"               # "flat" (plana) o "grouped" (agrupada por categoría)
traffic_group = "device"         # device | destination | app | category | protocol | process
```

- `capture.filter`: expresión de **BPF clásico** (estilo tcpdump): `tcp`, `udp`, `icmp`,
  `ip`, `ip6`, `arp`, `port N`, `portrange A-B`, `host IP`, `net CIDR`, con `and`/`or`/`not`
  y paréntesis. Se evalúa en el kernel; no hay filtros propios en userspace.
- `capture.max_pps`: 0 = sin límite. Al alcanzarlo se descartan paquetes y se avisa una vez por
  minuto; la barra muestra `límite N pps`.
- `[inference].enabled = false` desactiva todo lo que lee por encima de las cabeceras de
  transporte: solo quedan etiquetas por servicio de la fase 2, ASN, puerto y proceso.
- `inference.apps_file`: fichero TOML con apps propias. Una app con la misma clave que una
  embebida **la sustituye entera**; una clave nueva se añade; una entrada inválida se avisa y se
  ignora sin afectar al resto (máximo 500 apps propias). Si el fichero no existe se ignora.
- Las claves de la fase 3 `inspect_payload`, `dns_attribution` y `sni_attribution` ya no se
  usan: si aparecen en el fichero se avisa una sola vez y se sigue el valor de
  `[inference].enabled`.
- Los valores inválidos se avisan y se sustituyen por los valores por defecto (la aplicación nunca
  deja de arrancar por un error de configuración).

## Histórico y copias de seguridad

Almenara solo tiene histórico **mientras está abierta**: la TUI es la única que escribe. Cada
arranque abre una sesión con su latido por minuto y cada cierre se registra, de modo que las
gráficas y la presencia distinguen «sin tráfico» de «sin datos» (los huecos se dibujan con ░ y
nunca se interpolan). Para tener histórico continuo, deja Almenara abierta, por ejemplo en tmux:

```bash
tmux new -s almenara
./target/release/almenara        # o scripts/ejecutar-con-permisos.sh
# Ctrl-b d para salir del tmux sin cerrar Almenara
tmux attach -t almenara
```

Solo puede haber **una Almenara por base de datos**: la segunda muestra «Almenara ya está en marcha
(PID n)» y sale con código 1 sin abrir la BD. El bloqueo es un flock sobre data.db.lock y el
kernel lo libera si el proceso muere, así que no quedan bloqueos huérfanos.

La BD se puede copiar sin parar Almenara (WAL permite lectores concurrentes):

```bash
sqlite3 ~/.local/share/almenara/data.db ".backup copia.db"
# o, para compactar la copia:
sqlite3 ~/.local/share/almenara/data.db "VACUUM INTO 'copia.db'"
```

Con Almenara cerrada basta con copiar data.db (y, si no se cerró limpiamente, también
data.db-wal y data.db-shm). Perder la BD es perder el histórico; el inventario de equipos se
reconstruye con el escaneo y la captura. Para borrar el histórico, cierra Almenara y borra la BD, o
baja las retenciones de [history].

## Modo pasivo

Con `[scan].passive_only = true` la aplicación **solo escucha: no consulta a nadie**, con
independencia de si tiene `CAP_NET_RAW`:

- **Desactiva**: ARP scan, barrido ICMP, browse mDNS activo, M-SEARCH SSDP, port scan, banner
  grabbing, fingerprint de SO, **consultas NetBIOS** y **DNS inverso**.
- **Mantiene**: lectura de `/proc/net/arp`, escucha pasiva mDNS y SSDP, leases DHCP, **captura
  pasiva de paquetes** (escuchar no emite tráfico) y la captura como fuente L2 que crea equipos.
- **Nunca**, ni en modo normal ni en pasivo, se hace DNS inverso de IPs de Internet.
- Precedencia de hostname en pasivo: alias > mDNS > DHCP (lease o capturado) > último conocido.

La barra de estado indica el modo en todo momento (`privilegiado`, `pasivo` o `degradado`) y, en
terminales de 100 columnas o más, añade las líneas de captura y visibilidad
(`visibilidad: propia + broadcast`) y el estado de la inferencia (`inferencia: activa` /
`inferencia: desactivada`).

## Uso de la TUI

Pestañas: **Equipos · Tráfico · Conexiones · Histórico · Alertas · Config · Ayuda**. En Fase 5
están operativas Equipos (plana o agrupada, con detalle master-detail y línea «Último evento»),
Tráfico (rankings por dimensión y «¿Quién lo usa?»), Conexiones (tabla con protocolo, equipo,
destino, app y panel de detalle), Histórico, Config y Ayuda. Solo Alertas (F6) sigue mostrando su
placeholder.

En la pestaña Tráfico, `g` cicla la agrupación (equipo → destino → app → categoría → protocolo →
proceso) y se guarda en `[ui].traffic_group`; `w` cicla la ventana (60 s → 5 min → 1 h → 24 h →
sesión, sin persistir). Las ventanas de 1 h y 24 h se leen del histórico con volúmenes (no
velocidades), números de conexiones, minutos cerrados y los huecos de cobertura; con
`[history].enabled = false` se saltan. `Enter` abre el panel **«¿Quién lo usa?»** sobre destino, app, categoría o protocolo;
sobre un equipo abre su detalle y sobre un proceso abre Conexiones filtrada por ese proceso. El pie
muestra siempre el total y el porcentaje de tráfico sin identificar. La agrupación por equipo
mantiene la fila **[host]** con el tráfico del propio equipo, que no pertenece al inventario.

En Conexiones, el destino es el lado servidor (con su nombre o, si no hay, la IP con organización y
país) y el equipo es el lado cliente o el de la LAN; sin rol conocido la fila sale en orden canónico
con `?` delante del destino. `i` alterna nombres ⇄ IPs y `v` abre el panel con las cabeceras y la
identidad inferida (rol, fuentes, JA4 y proceso local).

En Histórico, `e` abre el selector de sujeto (toda la red, este equipo o un equipo con `/`), `w`
cicla el rango (24 h → 7 días → 30 días → 1 año) y `Tab` mueve el foco entre la gráfica, «Más
tráfico» y los eventos. La gráfica dibuja bajada + subida por punto y los huecos con `░` (nunca
interpolados); con el foco en la gráfica, `<` y `>` mueven un cursor que muestra en texto la
fecha, la bajada y la subida del punto. «Más tráfico» muestra equipos y apps en toda la red, y
apps, destinos, organizaciones y países en un equipo (los destinos solo hasta 30 días). En Eventos,
`f` cicla el filtro (todos, altas y presencia, identidad, servicios, Almenara) y `/` busca por
equipo; `Enter` sobre un equipo o un evento abre su detalle.

En el detalle de equipo, `w` alterna el histórico entre 24 h y 7 días: una fila de tráfico y otra de
presencia sobre el mismo eje, la rejilla de presencia de 7 días × 24 horas y el bloque «Visto en
este equipo» con recuentos, lo nuevo de los últimos 7 días y los puertos abiertos.

| Tecla | Acción |
|-------|--------|
| `h` `j` `k` `l` / flechas | mover la selección (j/k) o cambiar de pestaña (h/l) |
| `Tab` / `Shift-Tab` | cambiar de pestaña; en el detalle, alternar el foco lista/detalle |
| `1`-`7` | ir directamente a una pestaña |
| `g` | Equipos: lista plana / agrupada. Tráfico: agrupar por equipo/destino/app/categoría/protocolo/proceso (se persiste) |
| `w` | Tráfico: ventana 60 s → 5 min → 1 h → 24 h → sesión. Histórico: 24 h → 7 días → 30 días → 1 año. Detalle: histórico 24 h ⇄ 7 días |
| `e` | Histórico: selector de sujeto (toda la red, este equipo o un equipo con `/`) |
| `<` `>` | Histórico: cursor de la gráfica (fecha, bajada y subida del punto) |
| `f` `Tab` | Histórico: filtro de eventos / foco entre gráfica, «Más tráfico» y Eventos |
| `Enter` | Equipos/Tráfico: detalle del equipo. Tráfico: «¿Quién lo usa?» en destino/app/categoría/protocolo; Conexiones filtradas en proceso |
| `i` | Conexiones: alternar nombres ⇄ IPs |
| `v` | Conexiones: panel con cabeceras, rol, fuentes, JA4 y proceso |
| `t` | fijar o quitar el tipo de dispositivo manual (manda sobre el automático) |
| `s` / `f` | ordenar / filtrar (Equipos y Conexiones; en Tráfico `s` ordena el ranking) |
| `r` | rescan manual |
| `/` | buscar (en Conexiones también por servidor, app y proceso; Esc cierra la búsqueda) |
| `?` / `q` | ayuda / salir |
| `Esc` | cerrar panel, detalle o búsqueda; volver a Equipos |
| `a` / `n` | editar alias / notas del equipo |

Iconos por tipo de dispositivo: `[⌂]` gateway, `[▣]` PC/servidor/NAS, `[▯]` móvil/tablet,
`[▶]` TV/streaming, `[P]` impresora, `[C]` cámara, `[●]` IoT, `[?]` desconocido; `○` indica
equipo offline. En Conexiones, `[host]` marca el tráfico del propio host, `[broadcast]` la
multidifusión y `[?]` los extremos no inventariados (siempre en color atenuado).

## Tests y calidad

Ejecuta `cargo test`, `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings`. La
suite incluye tests unitarios de firmas, TLS, HTTP, DNS, JA4 (vectores oficiales de FoxIO), QUIC
(apéndice A de RFC 9001 y RFC 9369), catálogo, dominio registrable, bases IP, caché de nombres,
rankings, identificación de equipos y migración v3 → v4, además de replays de tráfico mixto con
etiquetas esperadas (TLS partido, QUIC, DNS, DHCP y ARP). La Fase 5 añade tests de la migración
v4 → v5 sin pérdida de datos, acumuladores y topes de los rollups (con los totales cuadrando),
consolidación de horas y días (incluidos los días de 23 y 25 horas de los cambios de hora), purga
por resolución, sesiones y huecos, instancia única, eventos nuevos y presencia, inventario y
consultas del lector con datos sintéticos. El replay condicional de la feature no default `pcap` se
mantiene para la fase 7:

```bash
cargo test --features pcap
```

Las mediciones de la Fase 5 usan un histórico sintético determinista (30 equipos, 2 años de días,
90 días de horas y 48 h de minutos) y no dependen de `CAP_NET_RAW`:

```bash
cargo test --release -- --ignored medir_historial
cargo test --release -- --ignored medir_minute_rollup
```

## Datos y privacidad

Se persisten datos técnicos de red: IP, MAC, hostname, fabricante, tipo de dispositivo, familia de
SO estimada y su fuente, modelo anunciado, huella y nombre DHCP, User-Agent truncado, puertos
abiertos y banners saneados, además de los metadatos de tráfico (agregados por dispositivo y
conexiones con 5-tuple, estado y bytes) y las **etiquetas derivadas** de la Fase 4 (protocolo de
aplicación, nombre del servidor, app, categoría, fuentes y JA4).

**El payload de los paquetes nunca se persiste** y no se envía información a terceros: todo el
almacenamiento es local. La inferencia lee cabeceras DNS/TLS/HTTP/QUIC y los primeros bytes de cada
flujo, pero los reensamblados y el payload descifrado se liberan en el hilo de captura en cuanto se
extrae la etiqueta; se puede desactivar con `[inference].enabled = false`.

Los nombres de dominio por equipo son, en la práctica, historial de navegación: solo viven en
tablas calientes (`CONNECTIONS`, purgada por timeout, y `NAME_CACHE`, con caducidad de 1 h a 24 h)
y en memoria (los rankings se pierden al cerrar). Los dominios, el SNI, el `Host` y el User-Agent
solo aparecen en logs de nivel `debug` (no con `-v`). Los eventos y servicios que dejan de verse
se purgan según `events_retention_days`; las conexiones se purgan por timeout (TCP 300 s,
TIME_WAIT/CLOSE_WAIT 60 s, UDP 60 s, ICMP 30 s).

**Histórico (Fase 5).** Se guardan solo agregados: bytes y conexiones por equipo y dimensión, sin
contenido ni nombres completos y **sin registro de conexiones**. El destino es el dominio
registrable, la IP o el equipo de la LAN; los destinos por equipo son el dato más sensible y por eso
solo viven 2 h por minuto y 30 días por hora, nunca en los días ni en el inventario. La presencia de
un móvil es la de su dueño y dura lo que los eventos (90 días). Todo es local: nada sale del equipo;
para borrar el histórico basta con cerrar Almenara y borrar la BD o bajar las retenciones, y se
desactiva entero con `[history].enabled = false`. La Ayuda de la TUI recuerda qué se guarda y
cuánto tiempo.

## Limitaciones (fases 3, 4 y 5)

- **Visibilidad parcial en red conmutada**: se ve el 100 % del tráfico propio y de
  broadcast/multicast, pero del unicast entre terceros solo lo que llegue a la interfaz (sin
  port mirror ni modo promiscuo forzado). La barra lo declara como `propia + broadcast`.
- Solo hay histórico mientras Almenara está abierta: la TUI es la única que escribe (el modo
  servicio queda para el roadmap). Los huecos se marcan y nunca se interpolan.
- El histórico guarda agregados, no conexiones: responde a «quién consume» y «con quién habla este
  equipo», no a un registro forense conexión a conexión. Los destinos solo viven 2 h por minuto y
  30 días por hora.
- Las ventanas de 1 h y 24 h llegan hasta el último minuto cerrado, no hasta el instante actual.
- La atribución de proceso local a conexión depende de los permisos de `/proc/[pid]/fd`; para
  procesos de otros usuarios se degrada a NULL.
- `/proc/net/nf_conntrack` puede requerir root; su lectura es best-effort.
- Los sparklines arrancan a cero y el último snapshot se usa como semilla; los números de la
  semilla no se mezclan con las series nuevas.
- Alertas sigue siendo un placeholder (fase 6).
- **Visibilidad del nombre en Fase 4**: DoH/DoT y ECH ocultan una parte del tráfico; sin SNI/Host
  se etiqueta por caché DNS, ASN y puerto. En red conmutada el tráfico de terceros que no llega a
  la interfaz no se etiqueta; el porcentaje de tráfico sin identificar se muestra siempre en el pie
  de Tráfico.
- **QUIC** solo se descifra para leer el ClientHello de los paquetes Initial (claves públicas
  derivadas del DCID); el resto del flujo es opaco, como debe ser. Un Initial de versión
  desconocida o corrupto se descarta con un contador.
- El catálogo es propio y finito (162 apps): una app desconocida aparece como «Sin identificar» o
  con el nombre del servidor. Se puede ampliar con `apps.toml`.
- La organización y el país proceden de DB-IP Lite: son aproximados (país del registro) y las IPs
 privadas/de enlace local no tienen información.
- JA4 se calcula y se muestra, pero no hay base de firmas ni alertas por JA4 (fase 6).

## Datos embebidos y atribuciones

| Dato | Origen | Licencia |
|------|--------|----------|
| IP → ASN y organización | DB-IP Lite (IP to ASN Lite, 2026-11) | CC BY 4.0 — «IP Geolocation by DB-IP» ([db-ip.com](https://db-ip.com)) |
| IP → país | DB-IP Lite (IP to Country Lite, 2026-11) | CC BY 4.0 — «IP Geolocation by DB-IP» ([db-ip.com](https://db-ip.com)) |
| Dominio registrable | Public Suffix List vía el crate `psl` (Mozilla) | MPL 2.0 |
| Catálogo de apps | Curación propia del proyecto (`data/catalogo.toml`) | MIT |
| Firmas de protocolo, TLS, QUIC, DHCP y JA4 | Especificaciones públicas (RFC 9000/9001/9369, RFC 8446, RFC 1035, RFC 2131/2132, RFC 6762/6763) y JA4 de FoxIO | JA4 de cliente: BSD-3 |
| OUI (fabricante de MAC) | `macaddr-ouidb` | Datos públicos IEEE |
| Ordenación de OUI y bases IP | `scripts/actualizar-bases-ip.sh` (solo desarrollo) | — |

Las bases DB-IP y la Public Suffix List van **embebidas en el binario**: la aplicación no descarga
nada en tiempo de ejecución. Origen, fecha y licencia detallados en
[`data/FUENTES.md`](data/FUENTES.md).

## Aviso legal

Almenara está pensado para su uso en redes propias o en redes en las que tengas autorización
expresa. Monitorizar redes ajenas puede ser ilegal en función de la jurisdicción.
