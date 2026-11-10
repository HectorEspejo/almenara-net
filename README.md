# Almenara

Monitor de red en TUI para Linux: descubre los equipos conectados a la red local y los muestra en una lista
detallada persistente. **Fase 1: fundación y descubrimiento básico** (TUI, configuración, SQLite y descubrimiento ARP/ICMP/DNS/OUI).

## Estado del proyecto

**Fase 1 en desarrollo.** Documentación: [informe de fase](docs/fase1/almenara-fase1-informe.md),
[checklist](docs/fase1/almenara-fase1-checklist.md) e [informe de implementación](docs/fase1/almenara-fase1-implementacion.md).

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

El descubrimiento activo (ARP e ICMP con raw sockets) requiere `CAP_NET_RAW`. Para dársela al binario:

```bash
cargo build
sudo setcap cap_net_raw+ep target/debug/almenara
getcap target/debug/almenara            # verificación
./target/debug/almenara
sudo setcap -r target/debug/almenara    # quitarla
```

Si recompilas, la capability puede perderse: vuelve a aplicarla. Sin ella, la aplicación arranca en **modo
degradado**: muestra un aviso visible en la barra de estado y limita el descubrimiento a la lectura pasiva de
`/proc/net/arp` (que puede estar vacía si no hay tráfico ARP reciente). La aplicación nunca eleva
privilegios por sí misma.

## Rutas

- Configuración: `~/.config/almenara/config.toml`
- Base de datos: `~/.local/share/almenara/data.db`
- Logs: `~/.local/state/almenara/log/` (rotación por tamaño)

## Configuración

Si el fichero de configuración no existe, se crea una plantilla con los valores por defecto al arrancar
(y se usan esos valores aunque la creación no sea posible). Ejemplo:

```toml
[scan]
interfaces = "auto"              # "auto" o nombres de interfaz
ranges = ["192.168.1.0/24"]      # rangos IPv4 CIDR a escanear (máx. 1024 IPs por rango)
interval_s = 60                  # intervalo entre escaneos (mínimo 10)
icmp_timeout_ms = 500            # timeout ICMP y reverse DNS (100-5000)
offline_after_cycles = 3         # ciclos sin ver un equipo antes de marcarlo offline

[storage]
db_path = "~/.local/share/almenara/data.db"
events_retention_days = 90       # retención de DEVICE_EVENTS

[ui]
theme = "default"
no_color = false
```

Los valores inválidos (CIDR mal formado, rangos demasiado grandes, intervalos o timeouts fuera de rango) se
rechazan como error de configuración al arrancar.

## Uso de la TUI

Pestañas: **Equipos · Tráfico · Conexiones · Histórico · Alertas · Config · Ayuda**. En Fase 1 solo están
operativas Equipos, Config (solo lectura) y Ayuda; el resto muestra un placeholder "no disponible en F1".

| Tecla | Acción |
|-------|--------|
| `h` `j` `k` `l` / flechas | mover la selección |
| `Tab` / `Shift-Tab` | cambiar de pestaña |
| `1`-`7` | ir directamente a una pestaña |
| `Enter` | detalle del equipo (no disponible hasta F3) |
| `/` | buscar (Esc cierra la búsqueda) |
| `s` | ordenar (alterna ascendente/descendente) |
| `f` | filtrar (`all`, `online`, `offline`, `new`, `alert`) |
| `r` | rescan manual |
| `?` / `q` | ayuda / salir |
| `Esc` | volver / cerrar búsqueda |
| `a` / `n` | editar alias / notas del equipo |

## Tests y calidad

Ejecuta `cargo test`, `cargo fmt --check` y `cargo clippy -- -D warnings`.

## Datos y privacidad

Solo se persisten datos técnicos de red (IP, MAC, hostname y fabricante). No se guardan payloads ni contenido
de tráfico, todo el almacenamiento es local y no se envía información a terceros. Los eventos se purgan
automáticamente según `events_retention_days` (90 días por defecto).

## Limitaciones de Fase 1

- Tráfico, Conexiones, Histórico y Alertas son placeholders; no hay captura de paquetes ni notificaciones de escritorio (fases posteriores).
- El detalle de equipo no está disponible hasta la Fase 3.
- No hay backup automático: la base de datos es un único fichero (`data.db`) que puede copiarse a mano.
- Sin `CAP_NET_RAW`, el descubrimiento depende de `/proc/net/arp`; la base OUI embebida puede no reconocer fabricantes recientes.

## Aviso legal

Almenara está pensado para su uso en redes propias o en redes en las que tengas autorización expresa. No
debes monitorizar redes ajenas: hacerlo puede vulnerar la normativa de protección de datos y las leyes
aplicables. El usuario es el único responsable del uso que haga de la herramienta.
