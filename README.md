# Almenara

Monitor de red en TUI para Linux: descubre los equipos conectados a la red local, qué servicios
ofrecen y **qué tráfico generan en vivo**. **Fase 3: tráfico en vivo (pasivo + local)** — captura
de paquetes con AF_PACKET + TPACKET_V3 (sin libpcap), agregación por dispositivo, conexiones
activas con proceso local, snapshot persistente y pestañas Tráfico/Conexiones con detalle de
equipo — sobre la base de las fases 1 y 2 (descubrimiento ARP/ICMP/DNS/OUI, mDNS, SSDP, DHCP,
NetBIOS, port scan, fingerprint y clasificación).

## Estado del proyecto

**Fase 1 implementada**, **Fase 2 implementada** y **Fase 3 implementada** (pendiente de entrega
del informe de implementación al analista funcional). Documentación:

- Fase 1: [informe de fase](docs/fase1/almenara-fase1-informe.md),
  [checklist](docs/fase1/almenara-fase1-checklist.md) e
  [informe de implementación](docs/fase1/almenara-fase1-implementacion.md).
- Fase 2: [informe de fase](docs/fase2/almenara-fase2-informe.md),
  [checklist](docs/fase2/almenara-fase2-checklist.md) e
  [informe de implementación](docs/fase2/almenara-fase2-implementacion.md).
- Fase 3: [informe de fase](docs/fase3/almenara-fase3-informe.md),
  [checklist](docs/fase3/almenara-fase3-checklist.md) e
  [informe de implementación](docs/fase3/almenara-fase3-implementacion.md).

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
arrancar (y se usan esos valores aunque la creación no sea posible). Ejemplo actualizado a Fase 3:

```toml
[scan]
interfaces = "auto"              # "auto" o nombres de interfaz
ranges = ["192.168.1.0/24"]      # rangos IPv4 CIDR a escanear (máx. 1024 IPs por rango)
interval_s = 60                  # intervalo entre escaneos (mínimo 10)
icmp_timeout_ms = 500            # timeout ICMP y reverse DNS (100-5000)
offline_after_cycles = 3         # ciclos sin ver un equipo antes de marcarlo offline
passive_only = false             # true desactiva todo el tráfico activo (captura pasiva permitida)
top_ports = [22, 23, 53, 80, 139, 443, 445, 515, 631, 1883, 3389, 5000, 5353, 5555, 8008, 8080, 8443, 9100, 32400]
dhcp_lease_paths = []            # rutas manuales adicionales de ficheros de leases DHCP

[capture]
enabled = true                   # activa la captura de paquetes al arrancar
filter = ""                      # BPF clásico (por ejemplo "not port 22"); vacío = sin filtro
inspect_payload = false          # false: payload descartado al instante (por defecto)
max_pps = 0                      # 0 = sin límite; aviso una vez por minuto al alcanzarlo
dns_attribution = true           # extrae QNAME de DNS (puerto 53)
sni_attribution = true           # extrae SNI de TLS ClientHello (puerto 443)

[storage]
db_path = "~/.local/share/almenara/data.db"
events_retention_days = 90       # retención de DEVICE_EVENTS y de servicios STALE

[ui]
theme = "default"
no_color = false
list_view = "flat"               # "flat" (plana) o "grouped" (agrupada por categoría)
```

- `capture.filter`: expresión de **BPF clásico** (estilo tcpdump): `tcp`, `udp`, `icmp`,
  `ip`, `ip6`, `arp`, `port N`, `portrange A-B`, `host IP`, `net CIDR`, con `and`/`or`/`not`
  y paréntesis. Se evalúa en el kernel; no hay filtros propios en userspace.
- `capture.inspect_payload = true` activa la inspección acotada de payload (solo QNAME/SNI); el
  payload nunca se guarda en SQLite.
- `capture.max_pps`: 0 = sin límite. Al alcanzarlo se descartan paquetes y se avisa una vez por
  minuto; la barra muestra `límite N pps`.
- Los valores inválidos se avisan y se sustituyen por los valores por defecto (la aplicación nunca
  deja de arrancar por un error de configuración).

## Modo pasivo

Con `[scan].passive_only = true` la aplicación no emite tráfico activo, con independencia de si
tiene `CAP_NET_RAW`:

- **Desactiva**: ARP scan, barrido ICMP, browse mDNS activo, M-SEARCH SSDP, port scan, banner
  grabbing y fingerprint de SO.
- **Mantiene**: lectura de `/proc/net/arp`, escucha pasiva mDNS y SSDP, leases DHCP, NetBIOS,
  reverse DNS y **captura pasiva de paquetes** (escuchar no emite tráfico).

La barra de estado indica el modo en todo momento (`privilegiado`, `pasivo` o `degradado`) y, en
terminales de 100 columnas o más, añade las líneas de captura y visibilidad
(`visibilidad: propia + broadcast`).

## Uso de la TUI

Pestañas: **Equipos · Tráfico · Conexiones · Histórico · Alertas · Config · Ayuda**. En Fase 3
están operativas Equipos (plana o agrupada, con detalle master-detail), Tráfico (ranking top-10),
Conexiones (tabla plana ordenable/filtrable con cabeceras), Config y Ayuda. Histórico (F5) y
Alertas (F6) siguen mostrando su placeholder.

En la pestaña Tráfico solo se listan equipos con actividad y se añade una fila **[host]** con el
tráfico del propio equipo, que no pertenece al inventario: en una red conmutada lo normal es ver
sobre todo tráfico propio y de difusión (mDNS/SSDP/broadcast), no el unicast entre terceros.

| Tecla | Acción |
|-------|--------|
| `h` `j` `k` `l` / flechas | mover la selección (j/k) o cambiar de pestaña (h/l) |
| `Tab` / `Shift-Tab` | cambiar de pestaña; en el detalle, alternar el foco lista/detalle |
| `1`-`7` | ir directamente a una pestaña |
| `g` | alternar lista plana / agrupada por categoría (se persiste) |
| `t` | fijar o quitar el tipo de dispositivo manual (manda sobre el automático) |
| `Enter` | detalle del equipo (Equipos) o drill-down desde el ranking (Tráfico) |
| `v` | cabeceras IP/TCP de la conexión seleccionada (pestaña Conexiones) |
| `s` / `f` | ordenar / filtrar (Equipos: columnas y filtro; Conexiones: columna y filtro) |
| `r` | rescan manual |
| `/` | buscar (Esc cierra la búsqueda) |
| `?` / `q` | ayuda / salir |
| `Esc` | cerrar cabeceras, detalle o búsqueda; volver a Equipos |
| `a` / `n` | editar alias / notas del equipo |

Iconos por tipo de dispositivo: `[⌂]` gateway, `[▣]` PC/servidor/NAS, `[▯]` móvil/tablet,
`[▶]` TV/streaming, `[P]` impresora, `[C]` cámara, `[●]` IoT, `[?]` desconocido; `○` indica
equipo offline. En Conexiones, `[host]` marca el tráfico del propio host, `[broadcast]` la
multidifusión y `[?]` los extremos no inventariados (siempre en color atenuado).

## Tests y calidad

Ejecuta `cargo test`, `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings`. Los tests
con replay de fichero pcap son condicionales a la feature no default `pcap` (preparada para F7):

```bash
cargo test --features pcap
```

## Datos y privacidad

Se persisten datos técnicos de red: IP, MAC, hostname, fabricante, tipo de dispositivo, familia de
SO estimada, puertos abiertos y banners saneados, además de los metadatos de tráfico de la Fase 3
(agregados por dispositivo y conexiones con 5-tuple, estado y bytes). **El payload de los paquetes
nunca se persiste** y no se envía información a terceros: todo el almacenamiento es local. Los
eventos y servicios que dejan de verse se purgan según `events_retention_days`; las conexiones se
purgan por timeout (TCP 300 s, TIME_WAIT/CLOSE_WAIT 60 s, UDP 60 s, ICMP 30 s).

## Limitaciones de la Fase 3

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

## Aviso legal

Almenara está pensado para su uso en redes propias o en redes en las que tengas autorización
expresa. Monitorizar redes ajenas puede ser ilegal en función de la jurisdicción.
