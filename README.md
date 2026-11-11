# Almenara

Monitor de red en TUI para Linux: descubre los equipos conectados a la red local, qué servicios
ofrecen, **qué tráfico generan en vivo** y **quién está detrás de cada conexión**. **Fase 4:
protocolos, apps y top talkers** — un motor de inferencia identifica el protocolo de aplicación, el
nombre del servidor (SNI de TLS y QUIC, `Host` de HTTP, respuestas DNS), la app y categoría del
catálogo, la huella JA4 del cliente y el rol cliente/servidor, y añade rankings por destino, app,
categoría, protocolo y proceso con el panel «¿Quién lo usa?» — sobre la base de las fases 1 a 3
(descubrimiento ARP/ICMP/DNS/OUI, mDNS, SSDP, DHCP, NetBIOS, port scan, fingerprint,
clasificación, captura AF_PACKET + TPACKET_V3 y tráfico en vivo).

## Estado del proyecto

**Fases 1 a 4 implementadas** (Fase 4 pendiente de entrega del informe de implementación al
analista funcional). Documentación:

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

Pestañas: **Equipos · Tráfico · Conexiones · Histórico · Alertas · Config · Ayuda**. En Fase 4
están operativas Equipos (plana o agrupada, con detalle master-detail), Tráfico (rankings por
dimensión y «¿Quién lo usa?»), Conexiones (tabla con protocolo, equipo, destino, app y panel de
detalle), Config y Ayuda. Histórico (F5) y Alertas (F6) siguen mostrando su placeholder.

En la pestaña Tráfico, `g` cicla la agrupación (equipo → destino → app → categoría → protocolo →
proceso) y se guarda en `[ui].traffic_group`; `w` cicla la ventana (60 s → 5 min → sesión, sin
persistir). `Enter` abre el panel **«¿Quién lo usa?»** sobre destino, app, categoría o protocolo;
sobre un equipo abre su detalle y sobre un proceso abre Conexiones filtrada por ese proceso. El pie
muestra siempre el total y el porcentaje de tráfico sin identificar. La agrupación por equipo
mantiene la fila **[host]** con el tráfico del propio equipo, que no pertenece al inventario.

En Conexiones, el destino es el lado servidor (con su nombre o, si no hay, la IP con organización y
país) y el equipo es el lado cliente o el de la LAN; sin rol conocido la fila sale en orden canónico
con `?` delante del destino. `i` alterna nombres ⇄ IPs y `v` abre el panel con las cabeceras y la
identidad inferida (rol, fuentes, JA4 y proceso local).

| Tecla | Acción |
|-------|--------|
| `h` `j` `k` `l` / flechas | mover la selección (j/k) o cambiar de pestaña (h/l) |
| `Tab` / `Shift-Tab` | cambiar de pestaña; en el detalle, alternar el foco lista/detalle |
| `1`-`7` | ir directamente a una pestaña |
| `g` | Equipos: lista plana / agrupada. Tráfico: agrupar por equipo/destino/app/categoría/protocolo/proceso (se persiste) |
| `w` | Tráfico: ventana 60 s → 5 min → sesión |
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
etiquetas esperadas (TLS partido, QUIC, DNS, DHCP y ARP). El replay condicional de la feature no
default `pcap` se mantiene para la fase 7:

```bash
cargo test --features pcap
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

## Limitaciones (fases 3 y 4)

- **Visibilidad parcial en red conmutada**: se ve el 100 % del tráfico propio y de
  broadcast/multicast, pero del unicast entre terceros solo lo que llegue a la interfaz (sin
  port mirror ni modo promiscuo forzado). La barra lo declara como `propia + broadcast`.
- Las ventanas son solo de 60 s y 5 min en memoria; 1 h y 24 h llegarán en la fase 5 con
  persistencia real (rollups).
- La atribución de proceso local a conexión depende de los permisos de `/proc/[pid]/fd`; para
  procesos de otros usuarios se degrada a NULL.
- `/proc/net/nf_conntrack` puede requerir root; su lectura es best-effort.
- Los sparklines arrancan a cero y el último snapshot se usa como semilla; los números de la
  semilla no se mezclan con las series nuevas.
- Histórico y Alertas siguen siendo placeholders (fases 5 y 6).
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
