# Almenara

Monitor de red en TUI para Linux: descubre los equipos conectados a la red local, qué servicios ofrecen y
los muestra en una lista persistente. **Fase 2: descubrimiento avanzado** (mDNS, SSDP, leases DHCP,
NetBIOS, port scan activo, fingerprint de SO y clasificación de dispositivos), sobre la base de la Fase 1
(TUI, configuración, SQLite y descubrimiento ARP/ICMP/DNS/OUI).

## Estado del proyecto

**Fase 1 implementada** (135 tests) y **Fase 2 implementada** (313 tests: 309 unitarios/de integración + 4 de CLI), pendiente de entrega del informe al analista funcional. Documentación:

- Fase 1: [informe de fase](docs/fase1/almenara-fase1-informe.md),
  [checklist](docs/fase1/almenara-fase1-checklist.md) e
  [informe de implementación](docs/fase1/almenara-fase1-implementacion.md).
- Fase 2: [informe de fase](docs/fase2/almenara-fase2-informe.md),
  [checklist](docs/fase2/almenara-fase2-checklist.md) e
  [informe de implementación](docs/fase2/almenara-fase2-implementacion.md).

## Novedades de la Fase 2

- **Descubrimiento pasivo** (siempre activo): escucha mDNS (registros A/AAAA/PTR/SRV/TXT/HINFO), escucha
  SSDP/UPnP, lectura de leases DHCP (dnsmasq, dhclient, NetworkManager, systemd-networkd y rutas manuales)
  y consulta NetBIOS NBNS (hostname y grupo de trabajo).
- **Descubrimiento activo** (solo si no está activo el modo pasivo y hay `CAP_NET_RAW`): browse mDNS,
  M-SEARCH SSDP, port scan TCP CONNECT sobre los puertos configurados (TOP-20 por defecto), banner grabbing
  y fingerprint de SO (TTL y opciones TCP con umbral de confianza).
- **Clasificación automática**: `device_type` con 12 categorías y una prioridad fija
  (gateway > impresora > cámara > TV/streaming > NAS > móvil/tablet > servidor/PC > IoT > desconocido),
  override manual persistente y servicio identificado por puerto y banner.
- **TUI**: vista plana o agrupada por categoría con `g` (preferencia persistida), iconos por tipo de
  dispositivo y barra de estado con el modo de descubrimiento y las fuentes activas.
- **Persistencia**: servicios expuestos por equipo (`DEVICE_SERVICES`), fuentes que han visto cada equipo
  (`DISCOVERY_SOURCES`), `os_family` y último fingerprint de SO.

## Requisitos

- Linux.
- Rust 1.88 o superior con `cargo`.
- Conexión a red en el primer `cargo build` para descargar y compilar las dependencias.
- Terminal de al menos 80x24.

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

El descubrimiento activo de Fase 1 (ARP e ICMP con raw sockets) y la sonda de TTL del fingerprint de SO
requieren `CAP_NET_RAW`. Para dársela al binario:

```bash
cargo build
sudo setcap cap_net_raw+ep target/debug/almenara
getcap target/debug/almenara            # verificación
./target/debug/almenara
sudo setcap -r target/debug/almenara    # quitarla
```

Si recompilas, la capability puede perderse: vuelve a aplicarla. Sin ella, la aplicación arranca en **modo
degradado**: muestra un aviso visible en la barra de estado y limita el descubrimiento a las fuentes pasivas
(`/proc/net/arp`, escucha mDNS/SSDP, leases DHCP, NetBIOS y reverse DNS); el descubrimiento activo de Fase 2
queda desactivado. La aplicación nunca eleva privilegios por sí misma.

## Rutas

- Configuración: `~/.config/almenara/config.toml`
- Base de datos: `~/.local/share/almenara/data.db`
- Logs: `~/.local/state/almenara/log/` (rotación por tamaño)

## Configuración

Si el fichero de configuración no existe, se crea una plantilla con los valores por defecto al arrancar
(y se usan esos valores aunque la creación no sea posible). Ejemplo actualizado a Fase 2:

```toml
[scan]
interfaces = "auto"              # "auto" o nombres de interfaz
ranges = ["192.168.1.0/24"]      # rangos IPv4 CIDR a escanear (máx. 1024 IPs por rango)
interval_s = 60                  # intervalo entre escaneos (mínimo 10)
icmp_timeout_ms = 500            # timeout ICMP y reverse DNS (100-5000)
offline_after_cycles = 3         # ciclos sin ver un equipo antes de marcarlo offline
passive_only = false             # true desactiva todo el tráfico activo (modo pasivo)
top_ports = [22, 23, 53, 80, 139, 443, 445, 515, 631, 1883, 3389, 5000, 5353, 5555, 8008, 8080, 8443, 9100, 32400]
dhcp_lease_paths = []            # rutas manuales adicionales de ficheros de leases DHCP

[storage]
db_path = "~/.local/share/almenara/data.db"
events_retention_days = 90       # retención de DEVICE_EVENTS y de servicios STALE

[ui]
theme = "default"
no_color = false
list_view = "flat"               # "flat" (plana) o "grouped" (agrupada por categoría)
```

- `scan.top_ports`: puertos del port scan TCP CONNECT; máx. 64 puertos únicos entre 1 y 65535. La lista por
  defecto tiene 19 puertos (la del checklist repetía 1883 y se deduplica).
- `scan.dhcp_lease_paths`: rutas adicionales de leases; las que no existen se descartan con un aviso.
- `ui.list_view`: vista de la lista de equipos; `g` la alterna y guarda la preferencia.

Los valores inválidos se avisan y se sustituyen por los valores por defecto (la aplicación nunca deja de
arrancar por un error de configuración).

## Modo pasivo

Con `[scan].passive_only = true` la aplicación no emite tráfico activo, con independencia de si tiene
`CAP_NET_RAW`:

- **Desactiva**: ARP scan, barrido ICMP, browse mDNS activo, M-SEARCH SSDP, port scan, banner grabbing y
  fingerprint de SO.
- **Mantiene**: lectura de `/proc/net/arp`, escucha pasiva mDNS y SSDP, leases DHCP, NetBIOS y reverse DNS.

La barra de estado indica el modo en todo momento:

- `privilegiado`: hay `CAP_NET_RAW` y todos los métodos activos están disponibles.
- `pasivo`: `[scan].passive_only = true`; solo fuentes pasivas y aviso visible.
- `degradado`: sin `CAP_NET_RAW`; solo fuentes pasivas y aviso visible.

En los modos pasivo y degradado la barra muestra además la lista de fuentes de descubrimiento activas.

## Uso de la TUI

Pestañas: **Equipos · Tráfico · Conexiones · Histórico · Alertas · Config · Ayuda**. En Fase 2 están
operativas Equipos (plana o agrupada), Config y Ayuda; Tráfico, Conexiones, Histórico y Alertas siguen
mostrando su placeholder ("no disponible en F1"), sin cambios respecto a la Fase 1.

| Tecla | Acción |
|-------|--------|
| `h` `j` `k` `l` / flechas | mover la selección (j/k) o cambiar de pestaña (h/l) |
| `Tab` / `Shift-Tab` | cambiar de pestaña |
| `1`-`7` | ir directamente a una pestaña |
| `g` | alternar lista plana / agrupada por categoría (se persiste) |
| `t` | fijar o quitar el tipo de dispositivo manual (manda sobre el automático) |
| `Enter` | detalle del equipo (no disponible hasta F3) |
| `/` | buscar (Esc cierra la búsqueda) |
| `s` | ordenar (alterna ascendente/descendente) |
| `f` | filtrar (`all`, `online`, `offline`, `new`, `alert`) |
| `r` | rescan manual |
| `?` / `q` | ayuda / salir |
| `Esc` | volver / cerrar búsqueda |
| `a` / `n` | editar alias / notas del equipo |

Iconos por tipo de dispositivo: `[⌂]` gateway, `[▣]` PC/servidor/NAS, `[▯]` móvil/tablet,
`[▶]` TV/streaming, `[P]` impresora, `[C]` cámara, `[●]` IoT, `[?]` desconocido; `○` indica
equipo offline. `os_family` se muestra en la pestaña Config.

## Tests y calidad

Ejecuta `cargo test`, `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings`.

## Datos y privacidad

Se persisten datos técnicos de red: IP, MAC, hostname, fabricante, tipo de dispositivo y familia de SO
estimada, además de los puertos abiertos detectados y los banners saneados (máximo 128 caracteres, sin
bytes no imprimibles). No se guardan payloads ni contenido de tráfico, todo el almacenamiento es local y
no se envía información a terceros. Los eventos y los servicios que dejan de verse se purgan
automáticamente según `events_retention_days` (90 días por defecto).

## Limitaciones de la Fase 2

- Tráfico, Conexiones, Histórico y Alertas son placeholders; no hay captura de paquetes ni notificaciones de escritorio (fases posteriores).
- El detalle de equipo no está disponible hasta la Fase 3.
- El port scan se ejecuta solo al descubrir un equipo, cuando cambia de IP/MAC o al pulsar `r`: un puerto que se abre después puede tardar en detectarse.
- El fingerprint de SO es heurístico: si no alcanza el umbral de confianza, `os_family` queda vacío y se puede fijar el tipo a mano.
- No hay backup automático: la base de datos es un único fichero (`data.db`) que puede copiarse a mano.
- Sin `CAP_NET_RAW` el descubrimiento depende de las fuentes pasivas; la base OUI embebida puede no reconocer fabricantes recientes.

## Aviso legal

Almenara está pensado para su uso en redes propias o en redes en las que tengas autorización expresa. No
debes monitorizar redes ajenas: hacerlo puede vulnerar la normativa de protección de datos y las leyes
aplicables. El usuario es el único responsable del uso que haga de la herramienta.
