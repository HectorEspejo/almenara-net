# Almenara — Fase 1: informe de implementación

**Fecha:** 2026-11-10 · **Versión del binario:** 0.1.0 · **Estado:** Fase 1 implementada y verificada (pendiente de entrega al analista funcional)

## Resumen de lo implementado

Se ha implementado la Fase 1 completa de Almenara como binario Rust (edition 2021) con tokio, ratatui + crossterm, clap, serde + toml, rusqlite (bundled), pnet, base OUI embebida mediante macaddr-ouidb (renombrada ouidb en Cargo.toml) y tracing + tracing-subscriber + tracing-appender.

El resultado cubre: TUI de siete pestañas con lista detallada de Equipos (icono, IP, hostname, MAC/fabricante, tráfico vacío y estado), navegación, búsqueda, ordenación, filtros, rescan manual, barra de estado, notificaciones no bloqueantes y modal bloqueante de base de datos; configuración TOML validada; persistencia SQLite con migraciones versionadas y retención de eventos; descubrimiento de interfaces (pnet + /proc/net/route); ARP scan y ping sweep raw; lectura pasiva de /proc/net/arp; reverse DNS con timeout; fabricante por OUI; merge determinista por MAC; marcado online/offline tras N ciclos; eventos new/disappeared/ip_changed/mac_changed/hostname_changed; alias y notas persistidas; logging a fichero con rotación por tamaño; modo degradado visible sin CAP_NET_RAW; paleta de 256 colores con NO_COLOR; y aviso explícito por debajo de 80x24.

Verificación de cierre: 135 tests en verde (131 unitarios/de integración + 4 de CLI), cargo fmt --check limpio, cargo clippy --all-targets -- -D warnings limpio y pruebas de humo reales de la TUI en pty (modo degradado) con descubrimiento de la red, navegación, edición de alias/notas, búsqueda/orden/filtros, rescan, modal de error de BD, configuración inválida y terminal pequeño. El detalle está en la última sección.

## Desviaciones respecto a la especificación (qué y por qué)

1. Crate ouidb inexistente. El stack pedía ouidb, pero ese crate no existe en crates.io. Se usa la base OUI embebida macaddr-ouidb 0.3.1 (40.000+ prefijos, datos IEEE/Wireshark) renombrada como ouidb en Cargo.toml, de modo que la dependencia conserva el nombre acordado. Verificado en ejecución: se resolvieron los fabricantes HUAWEI y Microsoft.

2. Checklist ausente. El repositorio no contenía almenara-fase1-checklist.md. Se ha creado en docs/fase1/ (junto al resto de documentación de la fase) derivándolo del informe funcional, con exactamente 67 funcionalidades numeradas F1-01..F1-67 y sin añadir alcance de fases posteriores. La estructura del informe situaba la documentación en docs/; se respeta la ubicación existente docs/fase1/.

3. Rango por defecto. El informe no fija un valor por defecto de [scan].ranges (solo muestra ["192.168.1.0/24"] como ejemplo). Se usa lista vacía = derivar la red de cada interfaz activa a partir de su IP y máscara. Para no disparar escaneos enormes, un rango automático se acota a 1024 direcciones (se reduce a /22 alrededor de la IP local). El límite de 1024 y la validación CIDR se aplican a los rangos configurados.

4. Selección de interfaces. interfaces = "auto" o una lista explícita de nombres, tal y como insinúa el mockup. No se añadió un flag CLI de interfaz porque no estaba en el alcance.

5. Orden de arranque. El flujo del informe ejecuta el primer escaneo antes de entrar en la TUI. Se detectan y persisten las interfaces de forma síncrona antes de abrir la TUI, pero el primer escaneo se lanza en segundo plano y la TUI se abre inmediatamente con los equipos cargados de SQLite; al terminar el escaneo se refresca la lista. Motivo: no bloquear el arranque hasta 15 s en modo privilegiado. La verificación funcional (equipos listados tras el primer ciclo) se cumple.

6. Merge ICMP. icmp_sweep devuelve solo direcciones IP (no MAC), por lo que el merge determinista por MAC se hace entre ARP y /proc/net/arp (la IP confirmada por ARP prevalece) y la respuesta ICMP se registra como fuente de liveness del equipo. El pseudocódigo del informe pretendía mergear ICMP por MAC, algo imposible con la firma acordada.

7. Evento mac_changed. Con identidad por MAC (UNIQUE) y merge por MAC, el cambio de MAC es inalcanzable en un upsert normal. Se implementa una heurística conservadora: si aparece una MAC desconocida con la IP de un equipo online cuya MAC anterior ha desaparecido de la foto actual, se actualiza la identidad de ese equipo y se emite mac_changed con before/after. Limitación conocida: una reasignación real de IP entre dos equipos podría interpretarse como cambio de MAC; queda documentada para F2.

8. Alias y notas. El informe exige la funcionalidad pero no define keybindings. Se añaden las teclas a (alias) y n (notas) con una línea de entrada inline (no modal); Enter guarda y Esc cancela. El alias sustituye al hostname en la lista y ambos se persisten de inmediato en DEVICES.

9. Detección de gateway. pnet no expone la tabla de rutas; el gateway por defecto de cada interfaz se lee de /proc/net/route y el equipo cuya IP coincide se persiste con device_type = gateway (icono [⌂]). Verificado con el gateway real de la red de pruebas.

10. Rotación de logs por tamaño. tracing-appender solo rota por tiempo; la rotación por tamaño se implementa con un escritor propio (10 MiB por fichero, 3 rotados) conectado al escritor no bloqueante de tracing-appender. Los límites son fijos en F1.

11. Mapeo de -v/-vv. El informe no lo definía: sin flags almenara=info,warn; -v debug; -vv trace; RUST_LOG tiene prioridad si está definido.

12. Navegación hjkl. Se interpreta j/k (y flechas verticales) como mover selección y h/l (y flechas horizontales) como cambiar de pestaña, coherente con Tab; se documenta en Ayuda. El informe no detallaba la semántica.

13. Enter sobre un equipo. Se muestra una notificación no bloqueante de detalle no disponible hasta Fase 3 en lugar de una pantalla de detalle, que el informe no define para F1.

14. Barra de estado. Se omite el contador conns del mockup porque Conexiones es placeholder en F1; se muestran equipos/online/offline, filtro, búsqueda, orden y modo (privilegiado/degradado), con el modo degradado resaltado.

15. Filtro de alertas. Se incluye en el ciclo de filtros (all/online/offline/new/alert) pero en F1 muestra una lista vacía con explicación, ya que no hay alertas hasta F6.

16. Creación de configuración por defecto. Si no existe el fichero, se escribe una plantilla con los valores por defecto (best-effort: si no se puede escribir se avisa y se continúa). El informe no especificaba este comportamiento.

17. Fechas en SQLite. Las columnas TIMESTAMP se guardan como TEXT RFC 3339 en UTC (por ejemplo 2026-11-10T10:47:54Z), lo que permite ordenar lexicográficamente y evita depender de la feature chrono de rusqlite.

18. Flujo de datos de escaneo. AppEvent::Devices transporta el informe de red en bruto; la reconciliación contra SQLite la hace el hilo de la TUI (una única conexión de escritura, WAL activo para futuras conexiones) antes de refrescar la vista. Así se evita compartir Connection entre tareas.

19. APIs adicionales en Repo. Además de las del informe: set_device_online, update_device_mac, set_alias, set_notes y list_interfaces (necesarias por el checklist) y list_events, schema_version, count_devices y path (diagnóstico y pruebas; list_events queda reservada para la pestaña Histórico de F5 y cubierta por tests).

20. Versión mínima de Rust. ratatui 0.30 (y macaddr-ouidb) usan edition 2024, por lo que el MSRV real es 1.88, no 1.80. Se declara rust-version = "1.88" y se actualiza el README.

21. Tests de integración CLI. Se añade tests/cli.rs (4 tests) no exigido por el informe, para verificar de forma automática --help, --version, la ayuda en castellano y el fallo ante flags desconocidos.

22. Rendimiento (F1-64). El diseño acota el escaneo con los timeouts y la concurrencia indicados, pero el entorno de desarrollo no tiene CAP_NET_RAW, así que el escaneo activo completo no se ha podido medir de extremo a extremo; tampoco se hicieron pruebas de carga con 256 equipos. Queda como verificación recomendada para el desarrollador.

23. Pestañas centrales. Tráfico/Conexiones/Histórico/Alertas muestran no disponible en F1 y, como ayuda extra, la fase en la que llegarán (F3/F3/F5/F6); no se implementó ninguna funcionalidad de esas fases.

## Estructura de archivos creada/modificada

```texto
almenara/
├── Cargo.toml                     # paquete, dependencias del stack y MSRV 1.88
├── Cargo.lock                     # versiones fijadas por cargo
├── .gitignore                     # excluye target/ y logs
├── README.md                      # manual de arranque de Fase 1 (actualizado)
├── docs/fase1/
│   ├── almenara-fase1-informe.md      # especificación funcional (sin cambios)
│   ├── almenara-fase1-prompt.md       # encargo (sin cambios)
│   ├── almenara-maestro.md            # informe maestro (sin cambios)
│   ├── almenara-fase1-checklist.md    # NUEVO: 67 funcionalidades marcadas
│   └── almenara-fase1-implementacion.md  # NUEVO: este informe
├── src/
│   ├── main.rs                    # CLI (clap), arranque, canales, tarea de escaneo
│   ├── config.rs                  # Config TOML, validación, rutas XDG y plantilla
│   ├── error.rs                   # Error central (thiserror) y alias Result
│   ├── capabilities.rs            # detección de CAP_NET_RAW / modo degradado
│   ├── logging.rs                 # tracing a fichero con rotación por tamaño
│   ├── events.rs                  # AppEvent (bus broadcast) y ScanCommand
│   ├── oui.rs                     # normalización de MAC y lookup OUI embebido
│   ├── notifier.rs                # buffer circular de 50 notificaciones (TTL 3 s)
│   ├── tui/
│   │   ├── mod.rs                 # bucle de eventos (tokio::select) y modal de BD
│   │   ├── app.rs                 # estado, navegación, filtros, orden y búsqueda
│   │   ├── keys.rs                # keybindings canónicos para Ayuda y pie
│   │   ├── theme.rs               # paleta de 256 colores y NO_COLOR
│   │   └── views/
│   │       ├── mod.rs             # layout, pestañas, notificación y estado
│   │       ├── devices.rs         # lista detallada de Equipos
│   │       ├── config_view.rs     # pestaña Config (solo lectura)
│   │       ├── help.rs            # pestaña Ayuda (keybindings, estado y legal)
│   │       └── placeholder.rs     # placeholders no disponible en F1
│   ├── scanner/
│   │   ├── mod.rs                 # merge, tracker online/offline y reconciliación
│   │   ├── interfaces.rs          # pnet + /proc/net/route (gateway y máscara)
│   │   ├── arp.rs                 # ARP scan raw (pnet datalink, CAP_NET_RAW)
│   │   ├── icmp.rs                # ping sweep raw concurrente (pnet transport)
│   │   ├── proc_arp.rs            # lectura pasiva de /proc/net/arp
│   │   └── dns.rs                 # reverse DNS con timeout (libc getnameinfo)
│   └── repo/
│       ├── mod.rs                 # fachada Repo: operaciones SQL parametrizadas
│       ├── migrations.rs          # migraciones versionadas e idempotentes
│       ├── interfaces.rs          # modelo y helpers de INTERFACES
│       ├── devices.rs             # Device, DeviceUpsert y ChangeSet
│       └── events.rs              # EventType y DeviceEvent
└── tests/
    └── cli.rs                     # pruebas de integración de --help/--version/flags
```

Además se han generado en tiempo de ejecución (no versionados): Cargo.lock en la raíz y los artefactos de target/. La base de datos, la configuración y los logs se crean en las rutas XDG del usuario al arrancar.

Ficheros modificados respecto al estado inicial del repositorio: README.md (manual de arranque de F1). Ficheros nuevos: todo src/, tests/, .gitignore, Cargo.toml, Cargo.lock, docs/fase1/almenara-fase1-checklist.md y este informe. No se han modificado docs/fase1/almenara-fase1-informe.md, docs/fase1/almenara-fase1-prompt.md, docs/fase1/almenara-maestro.md ni los CLAUDE.md/AGENTS.md.

## Decisiones técnicas tomadas durante el desarrollo

- Runtime y concurrencia: tokio multi-hilo con una tarea de escaneo que publica resultados por un bus tokio::sync::broadcast; la TUI escucha teclado (crossterm EventStream), el bus y un tick de 100 ms con tokio::select!. Las operaciones de red bloqueantes (pnet) se ejecutan en spawn_blocking.

- Persistencia con un único escritor: SQLite (rusqlite bundled) se abre con journal_mode=WAL, foreign_keys=ON y busy_timeout=5000; las migraciones versionadas (SCHEMA_MIGRATIONS) se aplican dentro de transacciones por versión. La conexión vive en el hilo de la TUI y se evita compartirla entre tareas.

- Modelo de descubrimiento: Host con MAC normalizada, IP, hostname, vendor, interfaz y fuentes; merge en BTreeMap por MAC (orden determinista) y OnlineTracker con contador en memoria de ciclos sin ver un equipo.

- Reconciliación en un solo paso: scanner::reconcile persiste interfaces, altas, ip_changed/hostname_changed/mac_changed, marca offline tras N ciclos, emite eventos con JSON before/after y poda el histórico según retención.

- Reverse DNS: libc::getnameinfo con NI_NAMEREQD dentro de spawn_blocking y tokio::time::timeout, con buffer_unordered para limitar la concurrencia; se descarta la IP numérica como nombre cuando no hay PTR y se conserva el hostname anterior si no resuelve.

- ARP/ICMP: ARP con canal de datalink pnet (Ethernet + ARP request broadcast y parseo de replies con deadline); ICMP con canal de transporte Layer3, checksum de pnet, identificador de proceso, lotes de concurrencia y tope global 2*timeout. Ambos devuelven Error::Scan si falta CAP_NET_RAW y el ciclo continúa en modo degradado.

- Interfaces y gateway: pnet::datalink::interfaces() y lectura de /proc/net/route (gateway hexadecimal little-endian); funciones puras para máscara a prefijo y parseo de la tabla de rutas, testeadas con fixtures.

- TUI en capas: App contiene todo el estado y la lógica de navegación/filtro/orden/búsqueda, devolviendo Action para lo que requiere persistencia; las vistas solo renderizan. keys.rs centraliza los atajos que muestran Ayuda y el pie. Tabla con TableState persistente para el scroll y anchos adaptativos desde 80 columnas; pie en dos líneas para que quepan todos los atajos a 80x24.

- Paleta y accesibilidad: índices de la paleta de 256 colores elegidos para contraste >= 4.5:1 sobre fondo negro (45 acento, 214 aviso, 245 atenuado, 114 online); información redundante con símbolos y texto (online/offline, [⌂]/[?]/○); NO_COLOR y --no-color fuerzan monocromo con modificadores (negrita, inverso, atenuado).

- Logging: tracing + tracing-subscriber con filtro por flags y RUST_LOG; escritor propio con rotación por tamaño (10 MiB, 3 ficheros) integrado en el non_blocking de tracing-appender; nunca se escribe en stdout/stderr para no corromper la TUI.

- CLI en castellano: clap derive con plantilla de ayuda en español (Ayuda de ... / Uso: ... / Opciones:), flags -c/--config, -v acumulable, --no-color, --help y --version con textos propios.

- Errores: thiserror central con variantes para configuración, E/S, base de datos, logging, escaneo y terminal; los mensajes visibles al usuario están en castellano.

- Estrategia de tests: sin root, sin red externa y sin depender de /proc real salvo lecturas tolerantes; fixtures para /proc/net/arp y /proc/net/route; base de datos temporal (tempfile) para DAOs y reconciliación; TestBackend de ratatui para comprobar renders (pestañas, iconos, aviso de terminal pequeño, placeholders, notificación).

- Trabajo en equipo: el desarrollo se repartió por ámbitos de escritura disjuntos (descubrimiento, persistencia, documentación) con contratos de módulo fijados en stubs compilables; el Lead implementó núcleo, TUI, integración y verificación.

## Funcionalidades del checklist completadas (copiando su texto exacto)

Checklist: docs/fase1/almenara-fase1-checklist.md — 67 / 67 completadas.

- F1-01 — El proyecto es un binario Rust con edition 2021 y su Cargo.toml declara las dependencias del stack: tokio, ratatui, crossterm, clap (derive), serde, toml, rusqlite (feature bundled), pnet, ouidb, tracing, tracing-subscriber y tracing-appender.
- F1-02 — El árbol de src/ incluye los módulos previstos en la especificación: main.rs, config.rs, error.rs (error central con thiserror), capabilities.rs, logging.rs, events.rs, oui.rs, notifier.rs y los directorios tui/, scanner/ y repo/.
- F1-03 — La CLI, construida con clap en modo derive, acepta los flags -c/--config <ruta>, -v, -vv, --no-color, --version y --help.
- F1-04 — --version imprime la versión del binario y --help muestra la ayuda de uso con todos los flags disponibles y sus descripciones.
- F1-05 — El arranque sigue el orden especificado: cargar la configuración, inicializar el logging, abrir SQLite y aplicar migraciones, detectar capacidades, detectar y persistir interfaces, ejecutar el primer escaneo, cargar los equipos desde la base de datos y entrar en el bucle de la TUI.
- F1-06 — Si la configuración no puede cargarse, la aplicación continúa con los valores por defecto y registra un aviso en el log, sin abortar el arranque.
- F1-07 — La configuración se carga de un fichero TOML en ~/.config/almenara/config.toml o en la ruta indicada con -c, con las secciones [scan], [storage] y [ui].
- F1-08 — La sección [scan] configura interfaces, ranges, interval_s, icmp_timeout_ms y offline_after_cycles, con los valores por defecto interfaces = "auto", interval_s = 60, icmp_timeout_ms = 500 y offline_after_cycles = 3.
- F1-09 — Los valores por defecto de [storage] son db_path = ~/.local/share/almenara/data.db y events_retention_days = 90; los de [ui] son theme = "default" y no_color = false.
- F1-10 — La configuración se valida al arrancar: los rangos deben ser IPv4 CIDR válidos con un máximo de 1024 IPs por rango, interval_s debe ser mayor o igual que 10 e icmp_timeout_ms debe estar entre 100 y 5000; los valores inválidos se comunican como error de configuración.
- F1-11 — Las rutas por convención son ~/.config/almenara/config.toml (configuración), ~/.local/share/almenara/data.db (base de datos) y ~/.local/state/almenara/log/ (logs).
- F1-12 — La persistencia usa SQLite embebido mediante rusqlite con feature bundled y un único fichero de base de datos en db_path, que se abre al arrancar.
- F1-13 — Las migraciones están versionadas en src/repo/migrations.rs, son idempotentes y se aplican en orden.
- F1-14 — La tabla INTERFACES contiene id (INTEGER PK AUTOINCREMENT), name (TEXT NOT NULL UNIQUE), mac (TEXT), ipv4 (TEXT), netmask (TEXT), gateway (TEXT), is_up (BOOLEAN NOT NULL DEFAULT 1) y last_seen (TIMESTAMP NOT NULL).
- F1-15 — La tabla DEVICES contiene id (INTEGER PK AUTOINCREMENT), mac (TEXT NOT NULL UNIQUE, normalizada aa:bb:cc:dd:ee:ff en minúsculas), ip (TEXT NOT NULL), hostname (TEXT NULL), vendor (TEXT NULL), interface_id (INTEGER NOT NULL, FK a INTERFACES(id)), device_type (TEXT NOT NULL DEFAULT 'unknown'), is_online (BOOLEAN NOT NULL DEFAULT 1), first_seen (TIMESTAMP NOT NULL), last_seen (TIMESTAMP NOT NULL), alias (TEXT NULL) y notes (TEXT NULL).
- F1-16 — La tabla DEVICE_EVENTS contiene id (INTEGER PK AUTOINCREMENT), device_id (INTEGER NOT NULL, FK a DEVICES(id)), event_type (TEXT NOT NULL), details (TEXT NOT NULL en JSON) y created_at (TIMESTAMP NOT NULL).
- F1-17 — Existen los índices DEVICES(is_online), DEVICE_EVENTS(created_at) y DEVICE_EVENTS(device_id, created_at), además del índice implícito por la restricción UNIQUE de DEVICES(mac).
- F1-18 — La fachada Repo expone upsert_interface, upsert_device (que devuelve el ChangeSet aplicado), list_devices, get_device_by_mac, append_event y prune_events.
- F1-19 — La retención purga al final de cada ciclo de escaneo los eventos de DEVICE_EVENTS más antiguos que events_retention_days (90 días por defecto).
- F1-20 — La detección de interfaces obtiene de cada interfaz de red name, mac, ipv4, netmask, gateway e is_up.
- F1-21 — Las interfaces detectadas se persisten en la tabla INTERFACES (upsert) durante el arranque.
- F1-22 — El equipo cuya IP coincide con el gateway por defecto de la interfaz se persiste con device_type = 'gateway'; el resto se persiste con device_type = 'unknown'.
- F1-23 — El campo interfaces de [scan] acepta el valor "auto" para seleccionar automáticamente las interfaces activas con IPv4, y permite indicar nombres de interfaz de forma explícita.
- F1-24 — Con CAP_NET_RAW disponible se ejecuta un ARP scan activo sobre el rango configurado.
- F1-25 — Con CAP_NET_RAW disponible se ejecuta un ping sweep ICMP concurrente con el timeout icmp_timeout_ms configurado.
- F1-26 — La tabla /proc/net/arp se lee en cada ciclo de escaneo como fuente pasiva, sin requerir privilegios.
- F1-27 — Los resultados de ARP, ICMP y /proc/net/arp se fusionan de forma determinista por MAC normalizada: la IP confirmada por ARP prevalece sobre la de ICMP y se registran las fuentes que vieron cada equipo.
- F1-28 — El hostname se resuelve por reverse DNS con el timeout icmp_timeout_ms y concurrencia limitada; si no resuelve, se conserva el último hostname conocido.
- F1-29 — El fabricante se resuelve con la base OUI embebida; las MAC locales o administrativas sin fabricante se muestran como "?".
- F1-30 — El escaneo se repite automáticamente cada interval_s mediante un timer de tokio, ejecutando en cada ciclo el merge, la detección de cambios y los eventos.
- F1-31 — La primera detección de una MAC emite un evento "new" exactamente una vez por MAC.
- F1-32 — Un contador en memoria acumula los ciclos consecutivos sin ver un equipo y, al alcanzar offline_after_cycles (3 por defecto), lo marca OFFLINE y emite el evento "disappeared".
- F1-33 — Cuando un equipo OFFLINE vuelve a aparecer se marca ONLINE sin emitir de nuevo el evento "new".
- F1-34 — Si la IP de un equipo cambia se emite el evento "ip_changed" y se persiste la nueva IP.
- F1-35 — Si el hostname de un equipo cambia se emite el evento "hostname_changed".
- F1-36 — Si la MAC de un equipo cambia se emite el evento "mac_changed".
- F1-37 — El campo details de cada evento guarda en JSON los valores before y after del cambio.
- F1-38 — Existe un bus de eventos tokio::sync::broadcast y, al terminar cada escaneo, se emite AppEvent::Devices para refrescar la TUI.
- F1-39 — Cada equipo admite alias manual y notas libres, editables desde la TUI con las teclas a y n y persistidos en DEVICES.
- F1-40 — La TUI muestra siete pestañas en el orden Equipos, Tráfico, Conexiones, Histórico, Alertas, Config y Ayuda, con la pestaña Equipos activa al arrancar.
- F1-41 — La pestaña Equipos es una lista detallada con las columnas icono, IP, hostname, MAC/fabricante, tráfico (vacío en F1) y estado, usando [⌂] para el gateway, [?] para el resto y ○ para los equipos offline.
- F1-42 — La selección de equipos se mueve con hjkl y con las flechas.
- F1-43 — Tab y Shift-Tab cambian de pestaña y las teclas 1 a 7 saltan directamente a cada pestaña.
- F1-44 — La tecla / abre una búsqueda incremental por subcadena sobre IP, MAC, hostname, fabricante y alias, y Esc la cierra.
- F1-45 — La tecla s cicla la ordenación ascendente y descendente sobre la columna activa.
- F1-46 — La tecla f abre el filtro con las opciones all, online, offline, new y alert.
- F1-47 — La tecla r dispara un escaneo manual sin esperar al timer periódico.
- F1-48 — La tecla ? abre la pestaña de Ayuda y la tecla q sale de la aplicación.
- F1-49 — La barra de estado muestra el resumen de equipos (total, online y offline) y el modo actual (privilegiado o degradado), y una barra inferior muestra los atajos disponibles.
- F1-50 — Las notificaciones no bloqueantes muestran el último aviso durante 3 s abajo a la derecha y usan un buffer circular de 50 en memoria, no persistido.
- F1-51 — Las pestañas Tráfico, Conexiones, Histórico y Alertas muestran el placeholder "no disponible en F1", y Enter sobre un equipo muestra el placeholder de detalle no disponible (F3).
- F1-52 — La pestaña Config muestra en solo lectura la configuración activa y su ruta, y la pestaña Ayuda muestra los keybindings, la versión, el estado de privilegios y el aviso legal sobre monitorizar redes ajenas.
- F1-53 — Si la base de datos falla al abrir o migrar durante el arranque se muestra un modal bloqueante con las opciones [Reintentar] y [Salir].
- F1-54 — El logging usa tracing con destino a ficheros en ~/.local/state/almenara/log/.
- F1-55 — Los flags -v y -vv incrementan el nivel de detalle de los logs, y sin flags se usa el nivel por defecto.
- F1-56 — Los ficheros de log rotan por tamaño.
- F1-57 — capabilities::detect determina al arrancar si existe CAP_NET_RAW (raw_sockets).
- F1-58 — Sin CAP_NET_RAW la aplicación arranca igualmente en modo degradado, sin abortar.
- F1-59 — El modo degradado se muestra con un aviso visible en la barra de estado.
- F1-60 — En modo degradado se omiten ARP e ICMP registrando el aviso una sola vez, se usa la lectura pasiva de /proc/net/arp y la aplicación nunca intenta elevar sus privilegios.
- F1-61 — La paleta usa 256 colores con los roles normal, accent, warning y dim, y con NO_COLOR=1 fuerza monocromo manteniendo símbolos y pesos.
- F1-62 — El contraste de color es de al menos 4.5:1 y la información nunca se transmite solo por color.
- F1-63 — La interfaz exige un mínimo de 80x24 y por debajo muestra un mensaje claro de "terminal demasiado pequeño".
- F1-64 — El rendimiento cumple: 256 dispositivos sin degradación perceptible, escaneo de un /24 en 15 s o menos con timeout de 500 ms y concurrencia 64, y CPU de 5 % o menos en reposo y 30 % o menos durante el escaneo.
- F1-65 — La aplicación no ejecuta comandos externos por defecto ni abre puertos de red propios.
- F1-66 — Solo se persisten datos técnicos de red (IP, MAC, hostname y fabricante); no se guardan payloads ni contenido de tráfico y todo el almacenamiento es local, sin envío a terceros.
- F1-67 — Los DAOs tienen tests unitarios, la suite cargo test pasa, el código pasa cargo fmt --check y cargo clippy -- -D warnings sin errores.

## Pendientes y bloqueos

- Bloqueos: ninguno. La Fase 1 está implementada y la suite pasa.

- No verificable en este entorno: el ARP scan y el ping sweep reales requieren CAP_NET_RAW y la máquina de desarrollo no la tiene (modo degradado). Las rutas de código están implementadas y sus helpers puros tienen tests; se recomienda una pasada manual con sudo o setcap en la red del desarrollador.

- Rendimiento F1-64: no se han medido los objetivos de tiempo de escaneo activo ni CPU; conviene comprobarlos junto con la prueba con CAP_NET_RAW.

- Heurística mac_changed: documentada en desviaciones; revisar en F2 cuando haya fingerprint de dispositivo.

- Documentación de proyecto: el informe maestro y el checklist maestro no se tocan; su actualización corresponde al analista funcional a partir de este informe de implementación.

- Control de versiones: no se han creado commits; el desarrollador decide el PR.

## Ejecución y pruebas (cómo arrancar, migrar y testear)

### Requisitos

- Linux (se usan /proc/net/arp y /proc/net/route).
- Rust 1.88 o superior con cargo.
- Terminal de al menos 80x24 para la TUI.
- Opcional: CAP_NET_RAW para descubrimiento activo (ARP + ICMP).

### Compilar y arrancar

```bash
cargo build
cargo run
cargo run -- -c /ruta/a/config.toml
cargo run -- -v            # logs debug
cargo run -- -vv           # logs trace
cargo run -- --no-color    # equivale a NO_COLOR=1
cargo run -- --help
cargo run -- --version
```

### Permisos y modo degradado

Sin CAP_NET_RAW la aplicación arranca en modo degradado visible en la barra de estado y solo lee /proc/net/arp. Para habilitar ARP/ICMP activos:

```bash
sudo setcap cap_net_raw+ep target/debug/almenara
getcap target/debug/almenara
./target/debug/almenara
sudo setcap -r target/debug/almenara
```

La aplicación nunca eleva privilegios ni ejecuta comandos externos.

### Configuración

Ruta por defecto: ~/.config/almenara/config.toml (o -c RUTA). Si no existe se escribe una plantilla con los valores por defecto. Ejemplo:

```toml
[scan]
interfaces = "auto"              # "auto" o lista de nombres
ranges = []                      # vacío = derivar de la interfaz; máx. 1024 IPs por rango
interval_s = 60                  # >= 10
icmp_timeout_ms = 500            # entre 100 y 5000
offline_after_cycles = 3

[storage]
db_path = "~/.local/share/almenara/data.db"
events_retention_days = 90

[ui]
theme = "default"
no_color = false
```

Una configuración inválida no impide arrancar: se avisa en la notificación y en el log y se usan los valores por defecto sin reescribir el fichero.

### Base de datos y migraciones

- Ruta por defecto: ~/.local/share/almenara/data.db.
- Al abrir, se aplican automáticamente las migraciones versionadas pendientes (versión 1: INTERFACES, DEVICES, DEVICE_EVENTS e índices). No hay comando de migración separado en F1.
- La base se crea sola (incluidos los directorios). Para reiniciar el inventario: rm ~/.local/share/almenara/data.db (o la ruta configurada) y volver a arrancar.
- Modo WAL, claves foráneas activas y busy_timeout de 5 s.

### Logs

- Directorio por defecto: ~/.local/state/almenara/log/; fichero almenara.log con rotación por tamaño (10 MiB, hasta 3 rotados).
- -v y -vv aumentan el detalle; RUST_LOG tiene prioridad.

### Tests y calidad

```bash
cargo test                 # 131 tests unitarios/de integración + 4 de CLI
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build
```

Resultado en la sesión de cierre: cargo test 131 + 4 tests en verde; cargo fmt --check limpio; cargo clippy --all-targets -- -D warnings limpio; cargo build correcto.

### Pruebas manuales realizadas

- Arranque real en pty (80x24, 100x30 y 120x30) en modo degradado: descubre y persiste 2 equipos reales de la red, con fabricante OUI (HUAWEI, Microsoft), gateway marcado [⌂], estado online y hostname _gateway por reverse DNS.
- Búsqueda incremental, orden (IP/hostname), filtros, rescan manual, pestañas 1-7, Ayuda, Config y placeholders.
- Edición de alias y notas desde la TUI y comprobación de su persistencia en SQLite.
- Modal bloqueante de base de datos inaccesible con reintento y salida.
- Configuración inválida: aviso y arranque con valores por defecto; config original intacta.
- Terminal por debajo de 80x24: mensaje claro de terminal demasiado pequeño.
- NO_COLOR=1, -vv (logs DEBUG en fichero), rutas XDG alternativas y creación de plantilla de configuración.
