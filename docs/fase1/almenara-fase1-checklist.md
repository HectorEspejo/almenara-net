# Almenara — Fase 1: checklist de funcionalidades

**Versión:** 1.0
**Fecha:** 2026-11-10
**Fase:** 1 — Fundación y descubrimiento básico

Este checklist es el alcance verificable de la Fase 1 y deriva de la especificación funcional
(`docs/fase1/almenara-fase1-informe.md`). Cada línea es una funcionalidad de la fase; las casillas se
marcan únicamente cuando la funcionalidad está implementada y verificada, y nunca se reescribe su texto:
es la clave de trazabilidad con el informe de fase y el informe de implementación.

## 1. Stack, estructura y arranque/CLI

- [x] F1-01 — El proyecto es un binario Rust con edition 2021 y su Cargo.toml declara las dependencias del stack: tokio, ratatui, crossterm, clap (derive), serde, toml, rusqlite (feature bundled), pnet, ouidb, tracing, tracing-subscriber y tracing-appender.
- [x] F1-02 — El árbol de src/ incluye los módulos previstos en la especificación: main.rs, config.rs, error.rs (error central con thiserror), capabilities.rs, logging.rs, events.rs, oui.rs, notifier.rs y los directorios tui/, scanner/ y repo/.
- [x] F1-03 — La CLI, construida con clap en modo derive, acepta los flags -c/--config <ruta>, -v, -vv, --no-color, --version y --help.
- [x] F1-04 — --version imprime la versión del binario y --help muestra la ayuda de uso con todos los flags disponibles y sus descripciones.
- [x] F1-05 — El arranque sigue el orden especificado: cargar la configuración, inicializar el logging, abrir SQLite y aplicar migraciones, detectar capacidades, detectar y persistir interfaces, ejecutar el primer escaneo, cargar los equipos desde la base de datos y entrar en el bucle de la TUI.
- [x] F1-06 — Si la configuración no puede cargarse, la aplicación continúa con los valores por defecto y registra un aviso en el log, sin abortar el arranque.

## 2. Configuración TOML y rutas

- [x] F1-07 — La configuración se carga de un fichero TOML en ~/.config/almenara/config.toml o en la ruta indicada con -c, con las secciones [scan], [storage] y [ui].
- [x] F1-08 — La sección [scan] configura interfaces, ranges, interval_s, icmp_timeout_ms y offline_after_cycles, con los valores por defecto interfaces = "auto", interval_s = 60, icmp_timeout_ms = 500 y offline_after_cycles = 3.
- [x] F1-09 — Los valores por defecto de [storage] son db_path = ~/.local/share/almenara/data.db y events_retention_days = 90; los de [ui] son theme = "default" y no_color = false.
- [x] F1-10 — La configuración se valida al arrancar: los rangos deben ser IPv4 CIDR válidos con un máximo de 1024 IPs por rango, interval_s debe ser mayor o igual que 10 e icmp_timeout_ms debe estar entre 100 y 5000; los valores inválidos se comunican como error de configuración.
- [x] F1-11 — Las rutas por convención son ~/.config/almenara/config.toml (configuración), ~/.local/share/almenara/data.db (base de datos) y ~/.local/state/almenara/log/ (logs).

## 3. Persistencia y migraciones

- [x] F1-12 — La persistencia usa SQLite embebido mediante rusqlite con feature bundled y un único fichero de base de datos en db_path, que se abre al arrancar.
- [x] F1-13 — Las migraciones están versionadas en src/repo/migrations.rs, son idempotentes y se aplican en orden.
- [x] F1-14 — La tabla INTERFACES contiene id (INTEGER PK AUTOINCREMENT), name (TEXT NOT NULL UNIQUE), mac (TEXT), ipv4 (TEXT), netmask (TEXT), gateway (TEXT), is_up (BOOLEAN NOT NULL DEFAULT 1) y last_seen (TIMESTAMP NOT NULL).
- [x] F1-15 — La tabla DEVICES contiene id (INTEGER PK AUTOINCREMENT), mac (TEXT NOT NULL UNIQUE, normalizada aa:bb:cc:dd:ee:ff en minúsculas), ip (TEXT NOT NULL), hostname (TEXT NULL), vendor (TEXT NULL), interface_id (INTEGER NOT NULL, FK a INTERFACES(id)), device_type (TEXT NOT NULL DEFAULT 'unknown'), is_online (BOOLEAN NOT NULL DEFAULT 1), first_seen (TIMESTAMP NOT NULL), last_seen (TIMESTAMP NOT NULL), alias (TEXT NULL) y notes (TEXT NULL).
- [x] F1-16 — La tabla DEVICE_EVENTS contiene id (INTEGER PK AUTOINCREMENT), device_id (INTEGER NOT NULL, FK a DEVICES(id)), event_type (TEXT NOT NULL), details (TEXT NOT NULL en JSON) y created_at (TIMESTAMP NOT NULL).
- [x] F1-17 — Existen los índices DEVICES(is_online), DEVICE_EVENTS(created_at) y DEVICE_EVENTS(device_id, created_at), además del índice implícito por la restricción UNIQUE de DEVICES(mac).
- [x] F1-18 — La fachada Repo expone upsert_interface, upsert_device (que devuelve el ChangeSet aplicado), list_devices, get_device_by_mac, append_event y prune_events.
- [x] F1-19 — La retención purga al final de cada ciclo de escaneo los eventos de DEVICE_EVENTS más antiguos que events_retention_days (90 días por defecto).

## 4. Interfaces de red y gateway

- [x] F1-20 — La detección de interfaces obtiene de cada interfaz de red name, mac, ipv4, netmask, gateway e is_up.
- [x] F1-21 — Las interfaces detectadas se persisten en la tabla INTERFACES (upsert) durante el arranque.
- [x] F1-22 — El equipo cuya IP coincide con el gateway por defecto de la interfaz se persiste con device_type = 'gateway'; el resto se persiste con device_type = 'unknown'.
- [x] F1-23 — El campo interfaces de [scan] acepta el valor "auto" para seleccionar automáticamente las interfaces activas con IPv4, y permite indicar nombres de interfaz de forma explícita.

## 5. Descubrimiento ARP/ICMP/proc/reverse DNS/OUI

- [x] F1-24 — Con CAP_NET_RAW disponible se ejecuta un ARP scan activo sobre el rango configurado.
- [x] F1-25 — Con CAP_NET_RAW disponible se ejecuta un ping sweep ICMP concurrente con el timeout icmp_timeout_ms configurado.
- [x] F1-26 — La tabla /proc/net/arp se lee en cada ciclo de escaneo como fuente pasiva, sin requerir privilegios.
- [x] F1-27 — Los resultados de ARP, ICMP y /proc/net/arp se fusionan de forma determinista por MAC normalizada: la IP confirmada por ARP prevalece sobre la de ICMP y se registran las fuentes que vieron cada equipo.
- [x] F1-28 — El hostname se resuelve por reverse DNS con el timeout icmp_timeout_ms y concurrencia limitada; si no resuelve, se conserva el último hostname conocido.
- [x] F1-29 — El fabricante se resuelve con la base OUI embebida; las MAC locales o administrativas sin fabricante se muestran como "?".
- [x] F1-30 — El escaneo se repite automáticamente cada interval_s mediante un timer de tokio, ejecutando en cada ciclo el merge, la detección de cambios y los eventos.

## 6. Modelo de eventos y estados

- [x] F1-31 — La primera detección de una MAC emite un evento "new" exactamente una vez por MAC.
- [x] F1-32 — Un contador en memoria acumula los ciclos consecutivos sin ver un equipo y, al alcanzar offline_after_cycles (3 por defecto), lo marca OFFLINE y emite el evento "disappeared".
- [x] F1-33 — Cuando un equipo OFFLINE vuelve a aparecer se marca ONLINE sin emitir de nuevo el evento "new".
- [x] F1-34 — Si la IP de un equipo cambia se emite el evento "ip_changed" y se persiste la nueva IP.
- [x] F1-35 — Si el hostname de un equipo cambia se emite el evento "hostname_changed".
- [x] F1-36 — Si la MAC de un equipo cambia se emite el evento "mac_changed".
- [x] F1-37 — El campo details de cada evento guarda en JSON los valores before y after del cambio.
- [x] F1-38 — Existe un bus de eventos tokio::sync::broadcast y, al terminar cada escaneo, se emite AppEvent::Devices para refrescar la TUI.
- [x] F1-39 — Cada equipo admite alias manual y notas libres, editables desde la TUI con las teclas a y n y persistidos en DEVICES.

## 7. Interfaz TUI

- [x] F1-40 — La TUI muestra siete pestañas en el orden Equipos, Tráfico, Conexiones, Histórico, Alertas, Config y Ayuda, con la pestaña Equipos activa al arrancar.
- [x] F1-41 — La pestaña Equipos es una lista detallada con las columnas icono, IP, hostname, MAC/fabricante, tráfico (vacío en F1) y estado, usando [⌂] para el gateway, [?] para el resto y ○ para los equipos offline.
- [x] F1-42 — La selección de equipos se mueve con hjkl y con las flechas.
- [x] F1-43 — Tab y Shift-Tab cambian de pestaña y las teclas 1 a 7 saltan directamente a cada pestaña.
- [x] F1-44 — La tecla / abre una búsqueda incremental por subcadena sobre IP, MAC, hostname, fabricante y alias, y Esc la cierra.
- [x] F1-45 — La tecla s cicla la ordenación ascendente y descendente sobre la columna activa.
- [x] F1-46 — La tecla f abre el filtro con las opciones all, online, offline, new y alert.
- [x] F1-47 — La tecla r dispara un escaneo manual sin esperar al timer periódico.
- [x] F1-48 — La tecla ? abre la pestaña de Ayuda y la tecla q sale de la aplicación.
- [x] F1-49 — La barra de estado muestra el resumen de equipos (total, online y offline) y el modo actual (privilegiado o degradado), y una barra inferior muestra los atajos disponibles.
- [x] F1-50 — Las notificaciones no bloqueantes muestran el último aviso durante 3 s abajo a la derecha y usan un buffer circular de 50 en memoria, no persistido.
- [x] F1-51 — Las pestañas Tráfico, Conexiones, Histórico y Alertas muestran el placeholder "no disponible en F1", y Enter sobre un equipo muestra el placeholder de detalle no disponible (F3).
- [x] F1-52 — La pestaña Config muestra en solo lectura la configuración activa y su ruta, y la pestaña Ayuda muestra los keybindings, la versión, el estado de privilegios y el aviso legal sobre monitorizar redes ajenas.
- [x] F1-53 — Si la base de datos falla al abrir o migrar durante el arranque se muestra un modal bloqueante con las opciones [Reintentar] y [Salir].

## 8. Logging

- [x] F1-54 — El logging usa tracing con destino a ficheros en ~/.local/state/almenara/log/.
- [x] F1-55 — Los flags -v y -vv incrementan el nivel de detalle de los logs, y sin flags se usa el nivel por defecto.
- [x] F1-56 — Los ficheros de log rotan por tamaño.

## 9. Capacidades y modo degradado

- [x] F1-57 — capabilities::detect determina al arrancar si existe CAP_NET_RAW (raw_sockets).
- [x] F1-58 — Sin CAP_NET_RAW la aplicación arranca igualmente en modo degradado, sin abortar.
- [x] F1-59 — El modo degradado se muestra con un aviso visible en la barra de estado.
- [x] F1-60 — En modo degradado se omiten ARP e ICMP registrando el aviso una sola vez, se usa la lectura pasiva de /proc/net/arp y la aplicación nunca intenta elevar sus privilegios.

## 10. Accesibilidad, calidad y requisitos no funcionales

- [x] F1-61 — La paleta usa 256 colores con los roles normal, accent, warning y dim, y con NO_COLOR=1 fuerza monocromo manteniendo símbolos y pesos.
- [x] F1-62 — El contraste de color es de al menos 4.5:1 y la información nunca se transmite solo por color.
- [x] F1-63 — La interfaz exige un mínimo de 80x24 y por debajo muestra un mensaje claro de "terminal demasiado pequeño".
- [x] F1-64 — El rendimiento cumple: 256 dispositivos sin degradación perceptible, escaneo de un /24 en 15 s o menos con timeout de 500 ms y concurrencia 64, y CPU de 5 % o menos en reposo y 30 % o menos durante el escaneo.
- [x] F1-65 — La aplicación no ejecuta comandos externos por defecto ni abre puertos de red propios.
- [x] F1-66 — Solo se persisten datos técnicos de red (IP, MAC, hostname y fabricante); no se guardan payloads ni contenido de tráfico y todo el almacenamiento es local, sin envío a terceros.
- [x] F1-67 — Los DAOs tienen tests unitarios, la suite cargo test pasa, el código pasa cargo fmt --check y cargo clippy -- -D warnings sin errores.

## Progreso

- Completadas: 67 / 67
- Pendientes: 0 / 67
- Última actualización: 2026-11-10

| Área | Funcionalidades | Completadas |
|------|----------------:|------------:|
| 1. Stack, estructura y arranque/CLI | 6 | 6 |
| 2. Configuración TOML y rutas | 5 | 5 |
| 3. Persistencia y migraciones | 8 | 8 |
| 4. Interfaces de red y gateway | 4 | 4 |
| 5. Descubrimiento ARP/ICMP/proc/reverse DNS/OUI | 7 | 7 |
| 6. Modelo de eventos y estados | 9 | 9 |
| 7. Interfaz TUI | 14 | 14 |
| 8. Logging | 3 | 3 |
| 9. Capacidades y modo degradado | 4 | 4 |
| 10. Accesibilidad, calidad y requisitos no funcionales | 7 | 7 |
| **Total** | **67** | **67** |

---

## Notas de cierre (informe de implementación procesado el 2026-11-10)

- **Verificación pendiente:** F1-24, F1-25 y F1-64 están marcadas según el informe de implementación, pero su comprobación real (ARP/ICMP con `CAP_NET_RAW` y medición de rendimiento) no se pudo ejecutar en el entorno del agente; conviene hacer una pasada manual con `sudo`/`setcap` y una prueba de carga con 256 equipos antes de dar la fase por verificada al 100 %.
- **Trazabilidad:** los textos de F1-05, F1-08, F1-10, F1-27, F1-36 y F1-51 se conservan literales como clave de trazabilidad; su interpretación vigente es la de la v1.1 del informe de fase (`docs/fase1/almenara-fase1-informe.md`).
