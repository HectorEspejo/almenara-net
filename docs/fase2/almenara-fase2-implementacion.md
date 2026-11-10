# Almenara — Fase 2: informe de implementación

**Fecha:** 2026-11-10 · **Versión del binario:** 0.1.0 · **Estado:** Fase 2 implementada y verificada (pendiente de entrega al analista funcional)

## Resumen de lo implementado

Se ha implementado la Fase 2 completa de Almenara (descubrimiento avanzado) como evolución aditiva de la Fase 1, sin romper el esquema ni el comportamiento existentes:

- **Migración v2 aditiva** de SQLite: tres columnas nuevas en DEVICES (os_family, device_type_manual, last_fingerprint), tablas DEVICE_SERVICES y DISCOVERY_SOURCES con FK ON DELETE CASCADE, índices IDX_SERVICES_DEVICE e IDX_SOURCES_DEVICE y compatibilidad verificada con una base de datos de Fase 1 (los datos antiguos se conservan).
- **DAOs nuevos**: DEVICE_SERVICES (upsert_service, list_services, mark_stale_services, prune_services) y DISCOVERY_SOURCES (upsert_source, list_sources), más DEVICES extendido (set_os_family, set_device_type_manual) y operaciones auxiliares para asociar fuentes pasivas (get_device_by_ip, set_hostname, set_last_fingerprint).
- **Descubrimiento pasivo**: escucha mDNS en 224.0.0.251:5353 con parser DNS-SD (A, AAAA, PTR, SRV, TXT, HINFO) y extracción de hostname .local y servicios; escucha SSDP en 239.255.255.250:1900 con parser HTTPU de NOTIFY/M-SEARCH/respuestas; lectura de leases DHCP de dnsmasq, dhclient, NetworkManager y systemd-networkd más rutas manuales; consulta NetBIOS NBNS (UDP 137) con timeout de 500 ms y fallo silencioso.
- **Descubrimiento activo** (solo con CAP_NET_RAW y passive_only = false): browse mDNS de _services._dns-sd._udp.local, M-SEARCH SSDP con ST=ssdp:all, descarga del XML de descripción UPnP con timeout de 2 s / máximo 256 KB / solo http(s) / sin redirecciones, port scan TCP CONNECT sobre los puertos configurados (TOP-20 por defecto, concurrencia 64, timeout 500 ms, máximo 1024 IPs por ciclo), banner grabbing (máx. 512 B, timeout 1 s, saneado y truncado a 128 caracteres) y fingerprint heurístico de SO (TTL inicial estimado + opciones TCP + banner, umbral de confianza 4).
- **Clasificación**: taxonomía device_type de 12 valores con prioridad gateway > printer > camera > tv/streaming > nas > mobile/tablet > server/pc > iot > unknown, override manual persistido en device_type_manual que siempre manda, y clasificación de servicio por puerto y banner (http, https, ssh, smb, upnp, printer, rtsp, mqtt, rdp, dns, mdns, plex, adb, telnet, ftp, nfs).
- **Precedencia de hostname**: alias (visual) > mDNS > NetBIOS > DHCP > reverse DNS > último conocido, aplicada en el merge y con conservación del valor anterior cuando no hay dato nuevo.
- **Modo pasivo**: [scan].passive_only = true deshabilita ARP scan, ICMP sweep, mDNS browse, M-SEARCH, port scan, banner grabbing y fingerprint, manteniendo listeners pasivos, /proc/net/arp, DHCP, NetBIOS y reverse DNS. Es independiente de las capacidades y se refleja en la barra de estado.
- **TUI**: toggle g entre vista plana (por defecto) y agrupada por categoría con cabeceras de sección y preferencia persistida en [ui].list_view; iconos ASCII por tipo ([⌂] gateway, [▣] pc/server/nas, [▯] mobile/tablet, [▶] tv/streaming, [P] printer, [C] camera, [●] iot, [?] unknown, ○ offline); barra de estado de dos líneas con modo (privilegiado/pasivo/degradado) y fuentes activas; pestaña Config con fingerprint de SO por dispositivo; pestaña Ayuda con g, t, leyenda de iconos y descripción de los tres modos; override manual de device_type desde la TUI con la tecla t.
- **Configuración TOML**: nuevas claves [scan].passive_only (false), [scan].top_ports (19 puertos únicos), [scan].dhcp_lease_paths ([]) y [ui].list_view ("flat"), con validación (puertos únicos 1-65535, máximo 64; list_view flat/grouped; rutas de leases inexistentes descartadas con aviso) y guardado de la configuración al alternar la vista.

Verificación de cierre: **309 tests unitarios/de integración + 4 tests de CLI en verde (313, más un test manual de red ignorado por defecto)**, cargo fmt --check limpio, cargo clippy --all-targets -- -D warnings limpio y pruebas de humo reales en pty (modo pasivo y degradado): migración v2 sobre base nueva, descubrimiento pasivo de 2 equipos reales, alternancia plano/agrupado con persistencia entre ejecuciones, override manual persistido en SQLite, pestaña Config con fingerprint y pestaña Ayuda. El detalle está en la última sección.

## Desviaciones respecto a la especificación (qué y por qué)

1. **Crate ssdp sustituido por parser propio.** El stack pedía el crate ssdp, pero ssdp 0.7.0 no compila en Rust estable (usa #![feature(ip)] y hyper 0.10). Se implementa el parser SSDP/HTTPU en src/discovery/ssdp/parser.rs (NOTIFY, M-SEARCH, respuestas 200, cabeceras case-insensitive, XML de UPnP a mano). reqwest 0.13 se usa solo para descargar el XML y hickory-proto 0.26 para mDNS, tal y como pedía el stack. Es la desviación más relevante y está cubierta por 20 tests.

2. **Lista por defecto de top_ports deduplicada.** El checklist repite el puerto 1883 (MQTT) en la lista de 20; como la validación exige puertos únicos, la lista por defecto tiene 19 puertos únicos (22, 23, 53, 80, 139, 443, 445, 515, 631, 1883, 3389, 5000, 5353, 5555, 8008, 8080, 8443, 9100, 32400). Se documenta aquí porque el texto del checklist se mantiene literal.

3. **Idempotencia de la migración v2 con ALTER TABLE.** SQLite no admite ADD COLUMN IF NOT EXISTS. Para que la migración sea realmente idempotente (y no solo "aplicada una vez" vía SCHEMA_MIGRATIONS), el struct Migration gana una comprobación opcional already_applied: la v2 comprueba si DEVICES ya tiene os_family y, si es así, registra la versión sin reejecutar el SQL. Hay un test que borra el registro de v2 y reaplica para demostrarlo.

4. **last_fingerprint como TEXT/JSON.** La especificación tipa la columna como TIMESTAMP, pero su contenido es el JSON del fingerprint observado (TTL, opciones TCP, puntuación, familia). Se implementa como TEXT (afinidad dinámica de SQLite), igual que las fechas de F1, para no falsear el tipo de dato.

5. **STALE sin columna de estado.** DEVICE_SERVICES no define columna is_stale. mark_stale_services(device_id, corte) materializa el estado derivado devolviendo cuántos servicios tienen last_seen anterior al corte, y prune_services los elimina por retención (events_retention_days). El ciclo de vida ACTIVE/STALE queda documentado en el DAO y se expone como contador stale_services en la reconciliación.

6. **NetBIOS: workgroup desde el Node Status (UDP 137), no desde 138/139.** Los puertos 138 (datagram) y 139 (session) son puertos de servicio NetBIOS, no endpoints de consulta: no existe una petición estándar de "dame el workgroup" por ellos. El workgroup se extrae de la respuesta NBSTAT (nombre con sufijo 0x00 y flag de grupo), que es la vía correcta. Se expone Netbios::query_workgroup como API y se documenta la desviación.

7. **Opciones TCP: ventana no observable con CONNECT scan.** El fingerprint usa TTL observado por ICMP raw (CAP_NET_RAW), opciones TCP negociadas leídas de TCP_INFO tras el CONNECT (timestamps, SACK, window scale y MSS) y pistas del banner. El tamaño de ventana del SYN-ACK no es observable desde espacio de usuario sin captura raw de SYN-ACK, por lo que TcpFingerprint.window queda habitualmente a None; el heurístico funciona con TTL + opciones + MSS + banner.

8. **macOS/iOS no alcanzan el umbral con la puntuación especificada.** Con las reglas de §7 (TTL + ventana + timestamps/SACK + MSS + banner) macOS se queda en 3 puntos como máximo y iOS en 2, por debajo del umbral 4; por tanto os_family = NULL para esos equipos. Es consecuencia directa de la especificación, no un fallo; se documenta y hay tests que lo fijan. Si el analista quiere que macOS/iOS sean detectables, hay que añadir señales a la especificación.

9. **Fase activa condicionada a CAP_NET_RAW.** El diagrama de flujo de §4 condiciona toda la fase activa (mDNS browse, M-SEARCH, port scan, banner, fingerprint) a CAP_NET_RAW, aunque el port scan TCP CONNECT y el banner grabbing no necesiten privilegios técnicamente. Se implementa así para que "degradado" signifique realmente solo fuentes pasivas, tal y como muestra el mockup 3. PortScan::scan y BannerGrab::grab siguen siendo utilizables sin privilegios si una fase futura lo decide.

10. **Asignación tv/streaming del pseudocódigo de §7 invertida.** El pseudocódigo dice "return STREAMING if ctx.is_tv else TV"; se interpreta como errata y se implementa Tv si is_tv y Streaming si no. El icono y el grupo son los mismos en ambos casos, por lo que no cambia el alcance funcional.

11. **Tecla t para el override manual.** El checklist exige device_type_manual con override manual, pero no define cómo editarlo desde la TUI. Se añade t (cicla automático → tipos → automático) con notificación y persistencia; sin ella el override solo sería alcanzable por SQL. Es un añadido mínimo, necesario para cumplir el requisito, y se documenta en Ayuda.

12. **Operaciones extra en Repo.** get_device_by_ip, set_hostname y set_last_fingerprint no aparecen en la tabla de operaciones de §5, pero son necesarias para asociar anuncios pasivos (mDNS/SSDP/DHCP) a equipos ya persistidos y para persistir el fingerprint. Se documentan como API adicional.

13. **Fuentes pasivas solo enriquecen equipos ya conocidos.** mDNS, SSDP y DHCP no crean dispositivos nuevos por sí solos (no hay MAC fiable en mDNS/SSDP y un lease puede estar caducado): actualizan hostname, servicios y DISCOVERY_SOURCES de equipos ya descubiertos por L2 (ARP o /proc/net/arp), que es lo que exige el AC del checklist y la restricción de seguridad "port scan limitado a equipos ya descubiertos por fuentes L2". Para equipos no presentes en la foto actual (offline) solo se rellena el hostname si está vacío, porque no se guarda la procedencia del hostname actual; mDNS se procesa antes que DHCP para respetar la precedencia.

14. **Listeners sin parámetro de interfaz.** La firma de §5 es MdnsListener::start(iface: &str) / SsdpListener::start(); se implementan start() sin parámetro (como el esqueleto acordado), uniéndose al grupo multicast por la interfaz por defecto del sistema (INADDR_ANY). Escuchar en varias interfaces a la vez queda fuera del alcance de F2.

15. **AAAA se parsea pero solo aporta hostname.** La asociación de F2 es por IPv4 (DEVICES.ip); los registros AAAA se parsean y se usan para hostname, pero no generan asociaciones IPv6.

16. **Nuevo fichero dhcp/systemd.rs.** La estructura de carpetas de §2 solo listaba networkmanager.rs, pero la funcionalidad exige leer systemd-networkd; se añade un parser propio en dhcp/systemd.rs (mismo formato CLAVE=valor) en lugar de mezclarlo con NetworkManager.

17. **Rutas por defecto de leases y tolerancia.** read_all lee las rutas del sistema (dnsmasq, dhclient, /var/lib/NetworkManager/*.lease, /run/systemd/netif/leases/*) más las rutas manuales; las inexistentes o sin permisos se omiten (solo se registra en log), y las rutas extra se prueban contra los cuatro parsers para tolerar ficheros con nombres arbitrarios. Es un comportamiento necesario para no romper el ciclo en sistemas donde no existe cada gestor.

18. **Re-escaneo inicial tras reiniciar.** El estado en memoria del escaneo activo se inicializa con los equipos ya persistidos al arrancar, de modo que un reinicio no dispara port scan/fingerprint de todo el inventario: solo se reescanea lo nuevo, lo que cambia de IP/MAC o lo pedido con r. Es la interpretación de "solo al descubrir equipo nuevo, cambio de IP/MAC o r" en presencia de una BD persistente.

19. **Flag interno netbios_enabled.** ScanOptions incluye un flag no configurable por el usuario para desactivar las consultas NetBIOS en el test de integración con passive_only (sin red real). No cambia el comportamiento por defecto.

20. **Test de integración del ciclo dentro del crate.** El paquete es un binario sin target library, así que los tests de integración de tests/ no pueden importar los módulos internos. El test de ciclo con passive_only = true (sin listeners, sin NetBIOS y con reverse DNS desactivado por timeout 0) se implementa como test #[tokio::test] dentro de src/scanner/mod.rs; verifica que no se intenta ARP/ICMP ni se seleccionan equipos para port scan.

21. **Barra de estado de dos líneas y ayuda sin scroll.** El mockup 3 muestra modo y fuentes en dos líneas, así que la barra de estado pasa de 1 a 2 líneas (resumen+modo / fuentes activas); el resto de keybindings y pestañas de F1 se mantiene. La pestaña Ayuda crece (g, t, leyenda, modos) y, como en F1, no tiene scroll: en terminales de 24 líneas la leyenda queda por debajo del pliegue; en terminales altos (probado a 110x60) se ve completa. No se añade scroll porque no está en el checklist.

22. **API pública sin consumidor de TUI.** Algunas operaciones exigidas por el checklist aún no las consume la interfaz (Repo::list_services, Repo::list_sources, Fingerprint::detect, DhcpLeases::default_paths, Netbios::query_workgroup, Device::is_gateway): quedan cubiertas por tests y marcadas con allow(dead_code) justificado, para que clippy -- -D warnings siga limpio y se integren en F3/F5.

23. **Listas de vendors del clasificador.** Las listas de OUI/fabricante de impresoras, NAS e IoT son heurísticas documentadas en classify.rs (comparación por subcadena del vendor OUI), no exhaustivas; el override manual y la clasificación por servicios son la vía para corregir falsos negativos.

24. **Documentación de proyecto intacta.** No se tocan docs/fase1/almenara-maestro.md, docs/fase2/almenara-fase2-informe.md ni docs/fase2/almenara-maestro-secciones-fase2.md: su actualización corresponde al analista funcional a partir de este informe. Sí se actualizan README.md y CLAUDE.md/AGENTS.md (reglas de trabajo del repositorio), que no son documentación funcional.

25. **Discrepancia entre las 73 funcionalidades declaradas y las 79 casillas del checklist.** El checklist de Fase 2 declara 73 funcionalidades en su contador, pero contiene 79 casillas verificables (5+3+3+5+3+4+5+3+6+8+22+5+7). Se han implementado y marcado las 79 y se han actualizado los contadores a 79/79; el analista debe reconciliar la numeración con el maestro (que usa 73) al procesar este informe. No se ha borrado ni renumerado ninguna casilla para no romper la trazabilidad.

## Estructura de archivos creada/modificada

    almenara/
    ├── Cargo.toml                    # + hickory-proto 0.26 (mdns) y reqwest 0.13 (rustls)
    ├── Cargo.lock
    ├── README.md                     # manual actualizado a Fase 2 (novedades, config, modo pasivo, privacidad)
    ├── CLAUDE.md / AGENTS.md         # stack, reglas y keybindings de Fase 2
    ├── docs/fase2/
    │   ├── almenara-fase2-checklist.md          # 73/73 marcadas
    │   ├── almenara-fase2-informe.md            # sin cambios (especificación)
    │   ├── almenara-fase2-implementacion.md     # NUEVO: este informe
    │   └── (prompt y secciones del maestro)     # sin cambios
    ├── src/
    │   ├── main.rs                   # DiscoveryState/ScanState, trigger manual, avisos de modo
    │   ├── config.rs                 # passive_only, top_ports, dhcp_lease_paths, list_view, save()
    │   ├── events.rs                 # sin cambios (ScanCommand::Rescan sigue siendo el manual)
    │   ├── classify.rs               # NUEVO: DeviceType, OsFamily, ServiceKind, DeviceGroup, device_type(), service()
    │   ├── discovery/                # NUEVO módulo raíz
    │   │   ├── mod.rs                # DiscoveryState, PassiveData, consultas activas, scan_host_active
    │   │   ├── mdns/{mod,parser,listener,query}.rs
    │   │   ├── ssdp/{mod,parser,listener,query}.rs
    │   │   ├── dhcp/{mod,dnsmasq,dhclient,networkmanager,systemd}.rs
    │   │   ├── netbios.rs
    │   │   ├── fingerprint.rs
    │   │   ├── portscan.rs
    │   │   └── banner.rs
    │   ├── repo/
    │   │   ├── migrations.rs         # migración v2 + already_applied
    │   │   ├── mod.rs                # DEVICES extendido, servicios, fuentes, fingerprint, hostname
    │   │   ├── devices.rs            # + os_family, device_type_manual, last_fingerprint, effective_device_type()
    │   │   ├── device_services.rs    # NUEVO DAO
    │   │   └── discovery_sources.rs  # NUEVO DAO
    │   ├── scanner/
    │   │   └── mod.rs                # Host/ScanReport/ScanOptions extendidos, ScanState, fases F2 y reconciliación
    │   └── tui/
    │       ├── mod.rs                # acciones nuevas (vista, tipo manual), stale_services, selección por id
    │       ├── app.rs                # list_view, g, t, modos, fuentes, visible_indices agrupado
    │       ├── keys.rs               # g y t en ayuda y pie
    │       ├── theme.rs              # iconos por device_type
    │       └── views/
    │           ├── mod.rs            # barra de estado de 2 líneas
    │           ├── devices.rs        # vista plana/agrupada
    │           ├── config_view.rs    # fingerprint de SO
    │           └── help.rs           # g, t, leyenda de iconos y modos
    └── (sin cambios: src/error.rs, capabilities.rs, logging.rs, notifier.rs, oui.rs, scanner/{arp,icmp,dns,interfaces,proc_arp}.rs, repo/{events,interfaces}.rs, tests/cli.rs)

## Decisiones técnicas tomadas durante el desarrollo

- **Dependencias y build**: hickory-proto 0.26 (feature mdns) para DNS-SD y reqwest 0.13 con rustls y sin redirecciones para el XML UPnP; el crate ssdp se descarta por no compilar en stable (ver desviación 1). MSRV 1.88 se mantiene.
- **Listeners pasivos de larga vida**: socket UDP creado con libc (SO_REUSEADDR + SO_REUSEPORT), unión al grupo multicast, hilo lector con timeout de 500 ms, buzón acotado que descarta lo más antiguo y parada limpia en Drop; DiscoveryState los arranca una sola vez y drain() los vacía en cada ciclo.
- **Parser mDNS con hickory-proto**: Message::from_vec, agrupación por host/instancia (A/AAAA + PTR + SRV + TXT + HINFO) en MdnsRecord; se ignoran CNAME/NSEC/OPT; los servicios se normalizan a minúsculas.
- **SSDP/HTTPU propio**: primera línea (NOTIFY/M-SEARCH/HTTP 200), cabeceras case-insensitive, CRLF o LF, validación anti-inyección del ST, bit QU para el browse activo y descarga XML con timeout del llamador, Policy::none(), solo http(s), content-length y chunks limitados a 256 KB.
- **DHCP puro y tolerante**: un parser por formato (dnsmasq epoch; dhclient bloques lease{...} con fecha local convertida a UTC; NetworkManager y systemd CLAVE=valor), MAC normalizada con crate::oui, expiry RFC 3339 UTC, omisión de ficheros inaccesibles.
- **NetBIOS propio**: NBSTAT (comodín CK+AA×15), parseo de Node Status con/sin pregunta ecoada y nombres comprimidos; hostname = sufijo 0x00 único, workgroup = sufijo 0x00 con flag de grupo; UDP 137 con timeout 500 ms y fallo silencioso.
- **Fingerprint**: estimate_initial_ttl (64/128/255 más cercano por arriba), puntuación exacta de §7 con umbral 4, empates por orden del enum, detect() y detect_with_score(); sonda de TTL ICMP raw con libc (checksum, Echo Reply e id, TTL de cabecera IP, SO_RCVTIMEO) y lectura de TCP_INFO (byte de opciones, window scale y MSS) del socket conectado; last_fingerprint se serializa con serde_json.
- **Port scan y banner**: TcpStream::connect con timeout por puerto, buffer_unordered(64), resultados ordenados; BannerGrab lee como máximo 512 B con timeout global de 1 s sin enviar payloads, sanea a ASCII imprimible (resto '.') y trunca a 128 caracteres.
- **Clasificador**: función pura sobre DeviceCtx con la prioridad de §7 y listas de vendors documentadas; device_type_manual siempre gana mediante Device::effective_device_type(); DeviceGroup define las secciones de la vista agrupada.
- **Merge y reconciliación**: Host incorpora nombres por fuente (reverse DNS/mDNS/NetBIOS/DHCP), servicios, upnp_types y discovery_sources; hostname_precedence() es una función pura; la fase pasiva se aplica antes que la activa y los servicios se fusionan por (puerto, protocolo) prefiriendo banner/servicio del port scan; reconcile sigue siendo el único punto de escritura SQLite (una conexión en el hilo de la TUI).
- **Disparo del escaneo activo**: ScanState en memoria (inicializado desde DEVICES al arrancar) decide equipos nuevos/cambio de IP/cambio de MAC/manual; límite de 1024 IPs por ciclo; el comando Rescan adelanta el ciclo y marca manual.
- **Modo pasivo como flag de primera clase**: ScanOptions::active_allowed() es el único predicado; el ciclo no ejecuta ARP/ICMP/activos si passive_only, y el TUI/main muestran modo pasivo con prioridad sobre degradado.
- **Migraciones**: cada versión se aplica en una transacción y se registra en SCHEMA_MIGRATIONS; la v2 añade already_applied para ALTER TABLE; test de compatibilidad F1→F2 con datos y test de reaplicación tras borrar el registro.
- **TUI**: el estado sigue devolviendo Action para la persistencia (SetListView, SetDeviceTypeManual) que ejecuta el bucle de la TUI; la vista agrupada reordena visible_indices por DeviceGroup::ALL y la tabla incluye filas de cabecera no seleccionables, con mapeo índice visible→fila real; tras cambiar el tipo manual se conserva la selección por id.
- **Configuración**: validación completa de las claves nuevas, descarte de rutas de leases inexistentes con aviso y Config::save() para persistir list_view (una escritura por pulsación).
- **Estrategia de tests**: fixtures de bytes para mDNS (serializados con hickory), texto para SSDP/XML/DHCP, paquetes NBSTAT de ida y vuelta, casos de umbral de fingerprint, temporales para SQLite y TestBackend para la TUI; ningún test usa red real y los tests de socket toleran fallos de bind.
- **Trabajo en equipo**: el desarrollo se repartió por ámbitos de escritura disjuntos (mDNS/SSDP; DHCP/NetBIOS/fingerprint; port scan/banner/clasificador; TUI) con contratos de API fijados en esqueletos compilables; el Lead implementó persistencia, configuración, integración del ciclo, TUI de acciones, documentación y verificación, y revisó/ajustó el diff completo.

- **Correcciones aplicadas durante la verificación posterior a la primera entrega**: (a) el hostname de reverse DNS se guardaba en Host.hostname pero no en reverse_dns_name, por lo que la precedencia de F2 lo descartaba en equipos nuevos (quedaba enmascarado por el hostname ya persistido); ahora se conserva en ambos campos y hay tests de la precedencia en el merge pasivo. (b) El ping sweep incluía la propia IP de la interfaz y abortaba todo el barrido si el envío a esa dirección fallaba (EINVAL); se excluye la IP local de los objetivos y los fallos de envío individuales ya no abortan el sweep (solo se devuelve error si no se pudo enviar ningún eco). (c) Los avisos no fatales del ciclo se escriben también en el log de fichero (antes solo aparecían como notificación en la TUI), lo que facilita el diagnóstico sin la interfaz abierta. (d) **El ping sweep se reimplementa con un socket raw de libc** (socket + poll/recvfrom): el canal de transporte de pnet 0.35 devolvía EINVAL en el envío en este entorno (verificado con un programa mínimo), por lo que el barrido ICMP no funcionaba ni con CAP_NET_RAW. La nueva implementación se verificó en una red aislada (respondedores_icmp = 1) y con tests puros de construcción/parseo. (e) **Respaldo de descubrimiento ARP para Wi-Fi**: si el barrido ARP raw devuelve menos de 2 hosts (algunas interfaces Wi-Fi descartan las tramas inyectadas con AF_PACKET), se calienta la tabla ARP del núcleo enviando datagramas UDP a los objetivos y se relee /proc/net/arp, con aviso en el log. (f) Se añadieron logs de diagnóstico del barrido ARP y del ping sweep (objetivos/encontrados/respondedores) y del fallback de calentado. (g) **Unión multicast por interfaz explícita en mDNS y SSDP**: unir el grupo con INADDR_ANY no selecciona la interfaz correcta en este equipo (verificado con un socket de prueba: 0 paquetes con INADDR_ANY frente a 4 con la IP de wlp191s0), por lo que los listeners pasivos no recibían nada de la red. Ahora DiscoveryState recibe las IP de las interfaces y los listeners se unen al grupo en cada una. (h) **Browse mDNS activo en dos etapas y desde el puerto 5353**: las consultas con puerto de origen efímero son ignoradas por los respondedores mDNS (RFC 6762 exige origen 5353); además, enumerar solo _services._dns-sd._udp.local devuelve tipos de servicio sin IP. El browse ahora abre un socket en 5353 con SO_REUSEADDR/SO_REUSEPORT, se une al grupo en la interfaz, enumera los tipos y consulta cada tipo para resolver instancias (SRV/TXT/A), fijando IP_MULTICAST_IF. Verificado en la red real: 9 registros, 4 con IP y hostname (192.168.1.17 = hoguera, servicios SSH/SFTP/RFB/SMB). (i) **La clasificación usa también los servicios persistidos y no regresa a unknown**: el port scan solo se ejecuta al descubrir un equipo o con r, así que en ciclos posteriores la clasificación se quedaba sin servicios y sobrescribía device_type con unknown; ahora se combinan los servicios del ciclo con los de DEVICE_SERVICES y, si el resultado es unknown, se conserva el tipo anterior. (j) **Heurística de fabricantes móviles** (Honor, Xiaomi, OnePlus...) para clasificar como mobile cuando no hay hostname revelador, corregible con el override manual.

## Funcionalidades del checklist completadas (copiando su texto exacto)

Checklist: docs/fase2/almenara-fase2-checklist.md — 79 / 79 casillas completadas (el fichero declara 73 funcionalidades; ver desviación 25).

- Escucha pasiva mDNS en 224.0.0.251:5353
- Parseo de respuestas mDNS (A, AAAA, PTR, SRV, TXT, HINFO)
- Extracción de servicios por dispositivo (`_http._tcp`, `_ipp._tcp`, `_airplay._tcp`, `_googlecast._tcp`, `_raop._tcp`, `_device-info._tcp`)
- Extracción de hostname `.local` desde mDNS
- Asociación mDNS → DEVICES por IP (y MAC cuando esté disponible)
- Escucha pasiva SSDP en 239.255.255.250:1900
- Parseo de NOTIFY y respuestas M-SEARCH (ST, USN, LOCATION)
- Fetch del XML de descripción (LOCATION) con timeout 2 s, máx. 256 KB, solo http/https, sin redirecciones externas
- Consulta mDNS activa de `_services._dns-sd._udp.local` (si no `passive_only` y CAP_NET_RAW)
- M-SEARCH activo SSDP (`ST=ssdp:all`) (si no `passive_only` y CAP_NET_RAW)
- `[scan].passive_only = true` deshabilita mDNS browse, M-SEARCH, port scan, banner grabbing, ARP scan e ICMP sweep
- Lectura de leases dnsmasq (`/var/lib/misc/dnsmasq.leases`)
- Lectura de leases dhclient (`/var/lib/dhcp/dhclient.leases`)
- Lectura de leases NetworkManager y systemd-networkd
- Rutas manuales de leases desde `[scan].dhcp_lease_paths`
- Merge de leases por MAC → hostname e IP preferente
- Consulta NetBIOS name query (UDP 137) para hostname
- Consulta NetBIOS datagram/session (UDP 138/139) para workgroup cuando aplica
- Timeout 500 ms, fallo silencioso (sin error visible si no responde)
- Cálculo de TTL inicial desde TTL observado + saltos estimados (heurística)
- Parseo de opciones TCP (ventana, MSS, timestamps) de SYN-ACK o banner
- Clasificación heurística a `os_family` con umbral de confianza ≥ 4 (si no, NULL)
- Persistir `os_family` y `last_fingerprint` en DEVICES
- Port scan TCP CONNECT sobre `[scan].top_ports` (TOP-20 por defecto)
- Concurrencia 64, timeout 500 ms, límite 1024 IPs por ciclo
- Re-escaneo de puertos solo al descubrir equipo nuevo, cambio de IP/MAC o pulsación de `r` (nunca cada ciclo periódico)
- Banner grabbing por puerto abierto (lectura máx. 512 B, timeout 1 s, saneado y truncado a 128 chars)
- Clasificación de servicio por puerto y banner (http, ssh, smb, upnp, printer, rtsp, mqtt, rdp, …)
- Ampliación de `device_type` a 12 valores: gateway, pc, server, nas, mobile, tablet, tv, streaming, iot, printer, camera, unknown
- Clasificación automática por prioridad: gateway > printer > camera > tv/streaming > nas > mobile/tablet > server/pc > iot > unknown
- Columna `device_type_manual TEXT NULL` con override manual que manda sobre el automático
- Vista agrupada por categoría activable con `g`
- Preferencia `[ui].list_view` persistida en config (`"flat"` | `"grouped"`), `"flat"` por defecto
- Iconos ASCII por tipo: `[⌂]` gateway, `[▣]` pc/server/nas, `[▯]` mobile/tablet, `[▶]` tv/streaming, `[P]` printer, `[C]` camera, `[●]` iot, `[?]` unknown, `○` offline
- Sin columnas nuevas en la lista plana (80 columnas); `os_family` se ve en Config y se verá en el detalle de F3
- Barra de estado con modo (`privilegiado` / `pasivo` / `degradado`) y fuentes activas
- Pestaña Ayuda actualizada con `g` y leyenda de iconos
- Migración v2: nuevas columnas en DEVICES (`os_family`, `device_type_manual`, `last_fingerprint`)
- Tabla `DEVICE_SERVICES` con id, device_id (FK ON DELETE CASCADE), port, protocol, service, banner, first_seen, last_seen, UNIQUE(device_id, port, protocol)
- Tabla `DISCOVERY_SOURCES` con id, device_id (FK ON DELETE CASCADE), source, last_seen, UNIQUE(device_id, source)
- Índices `IDX_SERVICES_DEVICE` y `IDX_SOURCES_DEVICE`
- DAO `DEVICE_SERVICES`: `upsert_service`, `list_services`, `mark_stale_services`, `prune_services`
- DAO `DISCOVERY_SOURCES`: `upsert_source`, `list_sources`
- DAO `DEVICES` extendido: `set_os_family`, `set_device_type_manual`
- Migración probada sobre BD de F1 sin pérdida de datos
- `MdnsListener::start()`
- `MdnsListener::drain()`
- `MdnsQuery::discover_services()`
- `SsdpListener::start()`
- `SsdpListener::drain()`
- `SsdpQuery::m_search()`
- `ssdp::parser::fetch_description()`
- `DhcpLeases::read_all()`
- `Netbios::query_name()`
- `Fingerprint::detect()`
- `PortScan::scan()`
- `BannerGrab::grab()`
- `classify::device_type()`
- `classify::service()`
- `Repo::upsert_service()`
- `Repo::list_services()`
- `Repo::mark_stale_services()`
- `Repo::prune_services()`
- `Repo::upsert_source()`
- `Repo::list_sources()`
- `Repo::set_os_family()`
- `Repo::set_device_type_manual()`
- `[scan].passive_only = false` por defecto
- `[scan].top_ports = [22,23,53,80,139,443,445,515,631,1883,3389,5000,5353,5555,8008,8080,8443,9100,1883,32400]`
- `[scan].dhcp_lease_paths = []` (rutas manuales)
- `[ui].list_view = "flat"` por defecto
- Validación: `top_ports` u16 únicos entre 1 y 65535, máx. 64; `list_view` ∈ {flat, grouped}; rutas de leases inexistentes se descartan con aviso
- Tests unitarios de parsers: mDNS, SSDP, DHCP (dnsmasq / dhclient / NetworkManager), NetBIOS, opciones TCP
- Tests del clasificador `device_type` (casos de prioridad y override manual)
- Tests del fingerprint `os_family` (umbral de confianza)
- Tests de la migración v2 (idempotente y compatible con BD F1)
- Tests de integración del ciclo con `passive_only = true` (sin red real)
- Tests de UI con `TestBackend`: modo plano, modo agrupado, toggle `g`, barra con modo `pasivo`
- `cargo test` en verde, `cargo fmt --check` limpio, `cargo clippy --all-targets -- -D warnings` limpio

## Pendientes y bloqueos

- **Bloqueos: ninguno.** La Fase 2 está implementada y la suite pasa.

- **No verificable en este entorno (CAP_NET_RAW) contra una red real**: el entorno de desarrollo no tiene CAP_NET_RAW (sudo pide contraseña), así que el descubrimiento activo no se ha podido probar contra la red real del desarrollador. Sí se ha verificado la cadena activa completa en una **red aislada en un network namespace** con un par veth y un respondedor ARP sintético: el ARP scan raw descubre el equipo (log: objetivos=253, encontrados=1), el ping sweep reimplementado con libc responde (respondedores=1), el port scan encuentra el puerto 8080, se clasifica el servicio como http, el fingerprint obtiene TTL 64 + timestamps + SACK + MSS y clasifica os_family = linux, y el clasificador asigna device_type = pc (todo persistido en DEVICE_SERVICES y DISCOVERY_SOURCES). Queda pendiente la pasada manual con sudo setcap cap_net_raw+ep target/debug/almenara en la red real.

- **Listeners pasivos y browse mDNS**: tras corregir la unión multicast por interfaz y el browse en dos etapas desde el puerto 5353, la red real devuelve servicios y hostnames (p. ej. 192.168.1.17 = hoguera con SSH/SFTP/RFB/SMB). Quedan equipos sin información porque no responden a mDNS, NetBIOS ni reverse DNS y usan MAC aleatorizada (sin fabricante OUI): para ellos no hay fuente en F2 salvo los leases DHCP del router, que no son legibles desde este equipo (ver siguiente punto).

- **Leases DHCP**: los ficheros de NetworkManager (/var/lib/NetworkManager/*.lease) son 0600 root y, además, en un portátil solo contienen el lease de este equipo, no la lista de clientes del router. Para identificar al resto de equipos por DHCP hay que ejecutar Almenara en el servidor DHCP (router/AP) o apuntar [scan].dhcp_lease_paths a una copia legible de su fichero de leases (p. ej. dnsmasq.leases). Es la vía para poner nombre a móviles con MAC aleatorizada que no anuncian mDNS.

- **Rendimiento de F2 (§8)**: no se han medido los objetivos (ciclo ≤ 20 s privilegiado / ≤ 5 s pasivo, port scan de TOP-20 sobre 10 hosts ≤ 3 s, CPU ≤ 8 % en reposo). En la prueba de humo en modo pasivo con 2 equipos el ciclo tardó ~0,5 s. Medirlo junto con la prueba con CAP_NET_RAW.

- **macOS/iOS con fingerprint**: con la puntuación de la especificación no alcanzan el umbral y quedan en os_family = NULL (desviación 8). Si el analista quiere detectarlos, hay que ampliar las señales de la especificación.

- **NetBIOS 138/139 y ventana TCP**: desviaciones 6 y 7; no hay trabajo pendiente salvo que el analista quiera otra aproximación (captura raw de SYN-ACK, que sería una funcionalidad nueva).

- **Pestaña Ayuda sin scroll**: en 80x24 la leyenda de iconos y los modos quedan por debajo del pliegue; se ve completa en terminales altos. Añadir scroll no estaba en el checklist y no se ha hecho.

- **Heurística mac_changed heredada de F1**: sigue siendo conservadora (misma IP con MAC nueva y MAC anterior desaparecida); no se ha cambiado en F2.

- **Documentación de proyecto**: docs/fase1/almenara-maestro.md, docs/fase2/almenara-fase2-informe.md y las secciones del maestro de F2 no se tocan; el desarrollador debe entregar este informe al analista funcional para que actualice el maestro y el estado del proyecto.

- **Control de versiones**: no se han creado commits; el desarrollador decide el PR.

## Ejecución y pruebas (cómo arrancar, migrar y testear)

### Requisitos

- Linux (se usan /proc/net/arp, /proc/net/route y sockets multicast).
- Rust 1.88 o superior con cargo.
- Terminal de al menos 80x24.
- Opcional: CAP_NET_RAW para descubrimiento activo (ARP/ICMP de F1, mDNS browse, M-SEARCH, port scan, banner y fingerprint de F2).

### Compilar y arrancar

    cargo build
    cargo run
    cargo run -- -c /ruta/a/config.toml
    cargo run -- -v            # logs debug
    cargo run -- -vv           # logs trace
    cargo run -- --no-color
    cargo run -- --help
    cargo run -- --version

### Permisos y modos

    sudo setcap cap_net_raw+ep target/debug/almenara
    ./target/debug/almenara
    sudo setcap -r target/debug/almenara

- Sin CAP_NET_RAW: modo degradado (solo fuentes pasivas); se avisa en la barra de estado.
- Con [scan].passive_only = true: modo pasivo, con o sin CAP_NET_RAW; no se emite tráfico activo.
- Con CAP_NET_RAW y passive_only = false: modo privilegiado (todas las fuentes).
- La aplicación nunca eleva privilegios por sí misma.

### Configuración (ejemplo F2)

    [scan]
    interfaces = "auto"
    ranges = []
    interval_s = 60
    icmp_timeout_ms = 500
    offline_after_cycles = 3
    passive_only = false
    top_ports = [22, 23, 53, 80, 139, 443, 445, 515, 631, 1883, 3389, 5000, 5353, 5555, 8008, 8080, 8443, 9100, 32400]
    dhcp_lease_paths = []

    [storage]
    db_path = "~/.local/share/almenara/data.db"
    events_retention_days = 90

    [ui]
    theme = "default"
    no_color = false
    list_view = "flat"

### Base de datos y migraciones

- Ruta por defecto: ~/.local/share/almenara/data.db.
- Al abrir, se aplican las migraciones pendientes: v1 (F1) y v2 (F2: columnas nuevas en DEVICES, DEVICE_SERVICES, DISCOVERY_SOURCES e índices). No hay comando de migración separado.
- La migración v2 es aditiva: una base de F1 conserva sus datos y gana las columnas/tablas nuevas (probado en tests).
- Para empezar de cero: borrar el fichero de base de datos y volver a arrancar.

### Logs

- ~/.local/state/almenara/log/almenara.log con rotación por tamaño (10 MiB × 3).
- -v/-vv aumentan el detalle; RUST_LOG tiene prioridad.

### Tests y calidad

    cargo test
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo build

Resultado en la sesión de cierre: cargo test 309 tests unitarios/de integración + 4 tests de CLI en verde (313, más 1 test manual de red ignorado); cargo fmt --check limpio; cargo clippy --all-targets -- -D warnings limpio; cargo build correcto.

### Pruebas manuales realizadas (pty/tmux, sin CAP_NET_RAW)

- Arranque con configuración de prueba y base de datos nueva: migración a v2 correcta (SCHEMA_MIGRATIONS = 2, tablas DEVICE_SERVICES/DISCOVERY_SOURCES/columnas nuevas presentes) y descubrimiento pasivo de 2 equipos reales (gateway HUAWEI y equipo Microsoft) desde /proc/net/arp, con ciclo pasivo de ~0,5 s.
- Modo pasivo: barra de estado con "modo: pasivo" y fuentes "/proc · mDNS · SSDP · DHCP · NetBIOS · DNS inverso"; sin ARP/ICMP ni port scan.
- Modo degradado (passive_only = false, sin CAP_NET_RAW): barra con "modo: degradado (sin CAP_NET_RAW)" y las mismas fuentes pasivas; sin avisos de fallo activo.
- Vista plana y agrupada: g alterna, la agrupada muestra cabeceras "Infraestructura"/"Desconocidos" solo de grupos no vacíos; la preferencia [ui].list_view se guarda y persiste entre ejecuciones (verificado reiniciando el binario).
- Override manual: t sobre el gateway cambia el icono a [P], persiste device_type_manual = 'printer' en SQLite y el device_type automático sigue siendo 'gateway'.
- Pestaña Config: sección "Fingerprint de SO por dispositivo" (IP → ? sin CAP_NET_RAW) y TOML completo con las claves nuevas.
- Pestaña Ayuda: g, t, leyenda de iconos y descripción de privilegiado/pasivo/degradado (visible completa en terminal de 110x60; en 80x24 la leyenda queda por debajo del pliegue, igual que en F1).
- Verificación de la cadena activa en una red aislada (network namespace con veth y respondedor ARP sintético, ejecutando como root del namespace para tener CAP_NET_RAW): el log muestra "barrido ARP completado objetivos=253 encontrados=1" y "ping sweep completado objetivos=253 respondedores=1"; ARP scan descubre 10.99.0.2, port scan detecta 8080/tcp, se clasifica http, fingerprint linux y device_type pc; todo persistido correctamente (sources arp, icmp y portscan).
- Verificación del listener mDNS pasivo con un anuncio sintético enviado a 224.0.0.251:5353: el equipo recibe el hostname y se registra DISCOVERY_SOURCES.source = 'mdns'.
- Diagnóstico de multicast: un socket Python unido al grupo con INADDR_ANY recibió 0 paquetes mDNS en 8 s, y unido a la IP de wlp191s0 recibió 4 (orígenes 192.168.1.16, .38 y .49). De ahí la corrección de unión por interfaz.
- Browse mDNS real (test manual ignorado) desde el puerto 5353: 9 registros, 4 con IP; 192.168.1.17 resuelto como hoguera con servicios _ssh/_sftp-ssh/_rfb/_smb.
- Salida limpia con q y logs sin errores ni panics.

### Verificación del alcance

- Checklist: docs/fase2/almenara-fase2-checklist.md marcado 73/73 (contadores actualizados).
- Este informe es un documento vivo: debe actualizarse si se añaden cambios antes de la entrega al analista funcional.
