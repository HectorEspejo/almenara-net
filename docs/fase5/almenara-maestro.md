# Almenara - Informe Maestro

**Última actualización:** 2026-11-11

## 1. Visión Global

Almenara es una aplicación de terminal para Linux que monitoriza de forma permanente la red local a la que está conectado el equipo: descubre los dispositivos presentes, muestra una vista principal en forma de lista detallada con iconos ASCII por tipo de equipo, y permite profundizar en el tráfico, las conexiones, el histórico y las alertas de cada uno. El objetivo es doble: **detectar intrusos / equipos desconocidos** y **diagnosticar consumo de ancho de banda y problemas de red**, todo desde la propia terminal.

La aplicación está diseñada para uso personal doméstico/laboratorio, corre en una única máquina Linux con privilegios elevados disponibles (raw sockets y captura de paquetes) y funciona también en modo degradado sin ellos. La interfaz es una TUI con pestañas navegables: la vista principal de la pestaña Equipos es una lista detallada (con toggle a vista agrupada por categoría desde F2), cada equipo tiene un panel detalle con su tráfico en vivo y sus conexiones activas (F3), y las pestañas Tráfico y Conexiones ofrecen vista agregada de toda la red.

El proyecto se desarrolla en siete fases incrementales. Fase 1 (fundación + descubrimiento básico) y Fase 2 (descubrimiento avanzado: mDNS, SSDP, DHCP, NetBIOS, fingerprint, port scan, taxonomía) están implementadas y verificadas. Fase 3 (tráfico en vivo con AF_PACKET + TPACKET_V3, agregación por dispositivo, conexiones activas, pestañas Tráfico y Conexiones) está implementada y verificada. Fase 4 (protocolos, apps y top talkers: etiquetado de conexiones por SNI de TLS y QUIC, DNS y HTTP; catálogo de apps; organización y país de los destinos; rankings por destino, app, categoría, protocolo y proceso; identificación de equipos por huella DHCP, modelo y User-Agent) está implementada (versión 0.4.0) a falta de la pasada con `CAP_NET_RAW`: verificación manual y mediciones en la red real. Fase 5 (histórico: rollups por minuto, hora y día; pestaña Histórico; ventanas de 1 h y 24 h; eventos nuevos, presencia e inventario por equipo) está especificada. Las fases 6 y 7 añadirán alertas e integraciones.

**Cliente:** uso personal del desarrollador.
**Entorno objetivo:** Linux, sin instalador (ejecución vía `cargo run` en fases iniciales).

## 2. Mapa de Módulos

```
                    ┌──────────────────────┐
                    │   M6 Config/Permisos │
                    │   (transversal)      │
                    └──────────┬───────────┘
                               │
┌──────────────┐    ┌──────────▼───────────┐    ┌──────────────┐
│ M1 Discovery │    │  M4 TUI (ratatui)    │    │ M3 Storage   │
│ (F1,F2,F4)   │───►│  (F1,F2,F3,F4,F5,F6) │◄───│ (SQLite +    │
│              │    │                      │    │  rollups)    │
└──────┬───────┘    └──────────▲───────────┘    └──────────────┘
       │                       │                       ▲
       │              ┌────────┴────────┐              │
       │              │  M2 Traffic     │              │
       └─────────────►│  (F3, F4, F5)   │──────────────┘
                      └────────┬────────┘
                               │
                      ┌────────▼────────┐    ┌──────────────┐
                      │  M5 Alerts      │    │ M7 Integr.   │
                      │  (F6)           │    │ (F7)         │
                      └─────────────────┘    └──────────────┘
```

**Dependencias principales:**
- M4 depende de M3 (persistencia) y M1 (datos a mostrar), y desde F3 consume M2 (tráfico).
- M2 (tráfico) alimenta M3 y M4; M5 (alertas) consumirá eventos y tráfico de M3/M2.
- M6 es transversal a todas.
- M7 (integraciones) se apoyará en M2 y M1.
- F4 amplía M2 (inferencia de aplicación y rankings) y M1 (identificación de equipos y captura como fuente L2), con su interfaz en M4.
- F5 añade a M2 los acumuladores por minuto, a M3 los rollups, el inventario y las sesiones (con un lector de solo lectura) y a M4 la pestaña Histórico.

## 3. Tabla Resumen de Fases

| Fase | Módulo | Funcionalidades | Sprints | Semanas | Estado |
|------|--------|-----------------|---------|---------|--------|
| 1 | Fundación + descubrimiento básico | 67 | 5 | 3–4 | Implementación reportada (2026-11-10) |
| 2 | Descubrimiento avanzado | 79 | 5 | 4–5 | Implementación reportada (2026-11-10) |
| 3 | Tráfico en vivo (pasivo + local) | 102 | 6 | 5–6 | Implementación reportada (2026-11-10) |
| 4 | Protocolos, apps y top talkers | 176 | 8 | 6–7 | Implementación reportada (2026-11-11) |
| 5 | Histórico, rollups y eventos | 141 | 8 | 6–7 | Especificada (2026-11-11) |
| 6 | Alertas (locales + escritorio) | ~9 | 1–2 | 1–2 | Pendiente de especificar |
| 7 | Integraciones y exportación | ~9 | 2 | 2 | Pendiente de especificar |
| **Total** | | **~583** | | **~27–33** | |

**Notas de recalibración:**
- F2 se especificó inicialmente con ~14 funcionalidades y se fijó en 79 al detallarla (checklist real con 79 casillas; discrepancia 73→79 resuelta al procesar el informe de implementación).
- F3 se especificó inicialmente con ~18 funcionalidades y se fijó en 102 al detallarla (discrepancia 76→102 resuelta al procesar el informe de implementación).
- F4 se especificó inicialmente con ~12 funcionalidades y se fijó en 175 al detallarla (incluye el sprint 4.0 de verificación pendiente de F1–F3 y la mejora de identificación de equipos); pasa a 176 al procesar el informe de implementación (servicio `Rankings::top_for_device`, añadido en la implementación).
- F5 se estimó con ~10 funcionalidades y se fija en 141 al detallarla (incluye eventos, presencia, inventario y la medición con histórico sintético).
- Los totales de F6–F7 son estimaciones previas a su especificación y se recalibrarán al detallarlas.
- Total acumulado implementado: **415** funcionalidades (67 + 79 + 102 + 167); las 9 que faltan de F4 son la pasada con `CAP_NET_RAW`.
- Total especificado hasta F5: **565** funcionalidades (248 + 176 + 141).

## 4. Modelo de Datos Global

```
  ┌────────────────────┐
  │    INTERFACES      │  (F1)
  ├────────────────────┤
  │ id (PK)            │◄──────┐
  │ name (UNIQUE)      │       │
  │ mac                │       │
  │ ipv4               │       │
  │ netmask            │       │
  │ gateway            │       │
  │ is_up              │       │
  │ last_seen          │       │
  └────────────────────┘       │
                               │ 1
                               │ N
  ┌────────────────────────────┴───┐
  │           DEVICES              │  (F1, ampliada F2 y F4)
  ├────────────────────────────────┤
  │ id (PK)                        │◄──────┬──────┬──────┬──────┐
  │ mac (UNIQUE)                   │       │      │      │      │
  │ ip                             │       │      │      │      │
  │ hostname                       │       │      │      │      │
  │ vendor                         │       │      │      │      │
  │ interface_id (FK)              │       │      │      │      │
  │ device_type                    │       │      │      │      │
  │ is_online                      │       │      │      │      │
  │ first_seen                     │       │      │      │      │
  │ last_seen                      │       │      │      │      │
  │ alias                          │       │      │      │      │
  │ notes                          │       │      │      │      │
  │ os_family             ◄── F2   │       │      │      │      │
  │ device_type_manual    ◄── F2   │       │      │      │      │
  │ last_fingerprint      ◄── F2   │       │      │      │      │
  │ model                 ◄── F4   │       │      │      │      │
  │ dhcp_fingerprint      ◄── F4   │       │      │      │      │
  │ dhcp_vendor           ◄── F4   │       │      │      │      │
  │ dhcp_hostname         ◄── F4   │       │      │      │      │
  │ user_agent            ◄── F4   │       │      │      │      │
  │ os_source             ◄── F4   │       │      │      │      │
  └────────────┬───────────────────┘       │      │      │      │
               │ 1                          │      │      │      │
               │                            │      │      │      │
               │ N                          │ 0..1 │ 0..N │ 0..N │ 0..N
  ┌────────────▼─────────────┐   ┌──────────▼──┐ ┌─▼──────▼─────▼──────┐
  │      DEVICE_EVENTS       │   │TRAFFIC_SNAP │ │   CONNECTIONS       │
  │      (F1, tipos F5)      │   │ SHOT (F3)   │ │   (F3, ampl. F4)    │
  ├──────────────────────────┤   ├─────────────┤ ├─────────────────────┤
  │ id (PK)                  │   │ device_id   │ │ id (PK)             │
  │ device_id (FK)           │   │  (PK, FK)   │ │ device_id (FK NULL, │
  │ event_type               │   │ bytes_in    │ │   ON DELETE SET     │
  │ details (JSON)           │   │ bytes_out   │ │   NULL)             │
  │ created_at               │   │ packets_in  │ │ protocol            │
  └──────────────────────────┘   │ packets_out │ │ src_ip/src_port     │
                                 │ peak_bps    │ │ dst_ip/dst_port     │
                                 │ window_s    │ │ state               │
                                 │ updated_at  │ │ bytes_in/out        │
                                 └─────────────┘ │ first_seen          │
                                                 │ last_seen           │
                                                 │ client_is_src  ◄ F4 │
                                                 │ app_protocol   ◄ F4 │
                                                 │ server_name    ◄ F4 │
                                                 │ name_source    ◄ F4 │
                                                 │ app            ◄ F4 │
                                                 │ category       ◄ F4 │
                                                 │ app_source     ◄ F4 │
                                                 │ ja4            ◄ F4 │
                                                 └─────────────────────┘

  ┌────────────────────┐        ┌────────────────────┐
  │  DEVICE_SERVICES   │        │ DISCOVERY_SOURCES  │
  │       (F2)         │        │       (F2)         │
  ├────────────────────┤        ├────────────────────┤
  │ id (PK)            │        │ id (PK)            │
  │ device_id (FK)     │        │ device_id (FK)     │
  │ port               │        │ source             │
  │ protocol           │        │ last_seen          │
  │ service            │        │ UNIQUE(device_id,  │
  │ banner             │        │   source)          │
  │ first_seen         │        └────────────────────┘
  │ last_seen          │
  │ UNIQUE(device_id,  │        Ambas tablas con FK
  │   port, protocol)  │        ON DELETE CASCADE.
  └────────────────────┘

  ┌────────────────────┐
  │    NAME_CACHE      │  (F4) — sin claves ajenas: caché
  │       (F4)         │  caliente IP → nombre (DNS, SNI,
  ├────────────────────┤  Host); caduca en ≤ 24 h.
  │ id (PK)            │
  │ ip                 │
  │ name               │
  │ source             │
  │ first_seen         │
  │ last_seen          │
  │ expires_at         │
  │ UNIQUE(ip, name)   │
  └────────────────────┘

  ┌──────────────────────────────┐   ┌────────────────────┐
  │ TRAFFIC_ROLLUP_MINUTE (F5)   │   │ DEVICE_SEEN (F5)   │
  │ TRAFFIC_ROLLUP_HOUR (F5)     │   ├────────────────────┤
  │ TRAFFIC_ROLLUP_DAY (F5)      │   │ id (PK)            │
  ├──────────────────────────────┤   │ device_id (FK)     │
  │ bucket (PK, INTEGER)         │   │ kind · key         │
  │ subject (PK)                 │   │ first_seen         │
  │ device_id (PK; 0 = no equipo)│   │ last_seen          │
  │ dimension (PK) · key (PK)    │   │ UNIQUE(device_id,  │
  │ bytes_down · bytes_up        │   │   kind, key)       │
  │ connections · WITHOUT ROWID  │   └────────────────────┘
  └──────────────────────────────┘
                                     ┌────────────────────┐
                                     │ APP_SESSIONS (F5)  │
                                     ├────────────────────┤
                                     │ id (PK)            │
                                     │ started_at         │
                                     │ ended_at           │
                                     │ last_beat          │
                                     │ end_reason · mode  │
                                     │ capture            │
                                     │ passive_only       │
                                     │ version            │
                                     └────────────────────┘

  Tablas previstas en fases posteriores (no creadas):

  · ALERTS                 (F6) — alertas emitidas
  · ALERT_RULES            (F6) — reglas configurables
  · EXTERNAL_SOURCES       (F7) — integraciones (SNMP, pcap replay)

  Notas de F3:
   · CONNECTIONS no tiene UNIQUE; upsert por 5-tuple canónica (extremo
     menor = origen). Ida y vuelta comparten fila.
   · CONNECTIONS es tabla caliente: purga por timeout cada 5 s.
   · TRAFFIC_SNAPSHOT guarda ventana 60 s + peak_bps (no acumulado).
   · device_id NULL en CONNECTIONS = [host] / [broadcast] / [?].

  Notas de F4:
   · CONNECTIONS gana el rol (client_is_src) y las etiquetas; la 5-tuple
     canónica (ADR-30) no cambia.
   · NAME_CACHE es caliente: caducidad entre 1 h y 24 h y purga cada 5 s.
   · DEVICES gana campos de identidad (modelo, DHCP, User-Agent, os_source).
   · DISCOVERY_SOURCES.source admite 'capture' (ARP, DHCP y tramas).

  Notas de F5:
   · TRAFFIC_ROLLUP_*.device_id → DEVICES.id cuando subject = 'device'
     (relación lógica, sin FK); DEVICE_SEEN.device_id → DEVICES.id (FK,
     borrado en cascada); APP_SESSIONS no tiene claves ajenas.
   · Cubos enteros (ADR-56): minuto y hora en segundos UTC; día local
     AAAAMMDD. Retención: minutos 48 h, horas 90 días, días 2 años;
     destinos 2 h por minuto y 30 días por hora, nunca en días.
   · DEVICE_EVENTS gana reappeared, service_new, service_gone,
     os_changed y type_changed sin cambio de esquema.
```

## 5. Glosario de Dominio

| Término de negocio | Entidad/Tabla | Fase | Notas |
|--------------------|---------------|------|-------|
| Interfaz de red | `INTERFACES` | F1 | NIC del equipo monitor |
| Dispositivo / equipo | `DEVICES` | F1 | Equipo visto en la red |
| Evento de dispositivo | `DEVICE_EVENTS` | F1 | Cambio relevante (new, disappeared, ip_changed…) |
| Servicio detectado | `DEVICE_SERVICES` | F2 | Puerto/protocolo/banner por dispositivo |
| Fuente de descubrimiento | `DISCOVERY_SOURCES` | F2 | Quién ha visto al dispositivo |
| Tipo manual | `DEVICES.device_type_manual` | F2 | Override del usuario (`t`) |
| Fingerprint SO | `DEVICES.os_family` | F2 | Estimación heurística, nullable |
| Snapshot de tráfico | `TRAFFIC_SNAPSHOT` | F3 | Último valor por dispositivo cada 5 s (ventana 60 s) |
| Conexión activa | `CONNECTIONS` | F3 | Tabla caliente; purga por timeout |
| Tag `[host]` | `CONNECTIONS.device_id = NULL` | F3 | Conexión del propio host |
| Tag `[broadcast]` | `CONNECTIONS.device_id = NULL` | F3 | Multidifusión (224/4, 255.255.255.255, ff00::/8) |
| Tag `[?]` | `CONNECTIONS.device_id = NULL` | F3 | Sin match en inventario |
| 5-tuple canónica | `CONNECTIONS` | F3 | Extremo menor (IP, puerto) como origen |
| Pico de tráfico | `TRAFFIC_SNAPSHOT.peak_bps` | F3 | Máximo en ventana 60 s |
| Ventana 60 s | (memoria) | F3 | Sparkline 1 punto/s |
| Ventana 5 min | (memoria) | F3 | Sparkline 1 punto/5 s |
| Fila `[host]` | (memoria, device_id −1) | F3 | Tráfico propio en ranking Tráfico |
| `limit_drops` | `Capture::limit_drops` | F3 | Descartes por `max_pps` (separado de drops del anillo) |
| ParseError ignorable | (parser) | F3 | ARP/LLDP/etc. no cuentan como error |
| Rol cliente/servidor | `CONNECTIONS.client_is_src` | F4 | NULL si no se puede deducir (no se inventa) |
| Protocolo de aplicación | `CONNECTIONS.app_protocol` | F4 | Por firma o puerto (§7.3 del informe de F4) |
| Nombre del servidor | `CONNECTIONS.server_name` | F4 | SNI, Host o caché de nombres |
| Fuente del nombre | `CONNECTIONS.name_source` | F4 | `sni` / `http` / `cache` |
| App | `CONNECTIONS.app` | F4 | Clave del catálogo; NULL = sin identificar |
| Categoría | `CONNECTIONS.category` | F4 | 12 categorías + `lan` |
| Fuente de la app | `CONNECTIONS.app_source` | F4 | `domain` / `lan_service` / `asn` / `port` |
| Huella JA4 | `CONNECTIONS.ja4` | F4 | Cliente TLS/QUIC; sin base de firmas en F4 |
| Sin identificar | `CONNECTIONS.app = NULL` | F4 | % visible siempre en Tráfico |
| Caché de nombres | `NAME_CACHE` | F4 | Tabla caliente IP → nombre |
| Catálogo de apps | `data/catalogo.toml` + `apps.toml` | F4 | Ficheros, no tablas |
| Dominio registrable | (memoria, PSL) | F4 | Clave de destino en los rankings |
| Organización y país | (DB-IP Lite embebida) | F4 | Sin red; atribución CC BY 4.0 |
| Ventana de sesión | (memoria) | F4 | Acumulado desde el arranque |
| Modelo | `DEVICES.model` | F4 | TXT de mDNS o descripción UPnP |
| Huella DHCP | `DEVICES.dhcp_fingerprint` | F4 | Opción 55 en su orden |
| Clase de proveedor DHCP | `DEVICES.dhcp_vendor` | F4 | Opción 60 |
| Nombre DHCP | `DEVICES.dhcp_hostname` | F4 | Opción 12 capturada |
| User-Agent | `DEVICES.user_agent` | F4 | HTTP en claro, truncado a 256 |
| Fuente del SO | `DEVICES.os_source` | F4 | `tcp` / `dhcp` / `model` / `ua` |
| MAC privada | (derivado del bit U/L de `DEVICES.mac`) | F4 | Se muestra «MAC privada» |
| Fuente `capture` | `DISCOVERY_SOURCES.source` | F4 | ARP, DHCP y tramas capturadas |
| Agrupación del ranking | `[ui].traffic_group` | F4 | Configuración, no tabla |
| Rollup | `TRAFFIC_ROLLUP_*` | F5 | Tráfico agregado por minuto (48 h), hora (90 días) y día (2 años) |
| Cubo | `TRAFFIC_ROLLUP_*.bucket` | F5 | Minuto u hora en segundos UTC; día local AAAAMMDD |
| Sujeto del histórico | `TRAFFIC_ROLLUP_*.subject` | F5 | `device`, `host`, `other` o `network` |
| Dimensión del histórico | `TRAFFIC_ROLLUP_*.dimension` | F5 | total, app, category, destination, protocol, process, org, country |
| Otros | `TRAFFIC_ROLLUP_*.key` = `~otros` | F5 | Claves por encima del tope (`top_keys`) |
| Sesión de Almenara | `APP_SESSIONS` | F5 | Arranque, cierre y latido |
| Hueco | (derivado de `APP_SESSIONS`) | F5 | Sin sesión o sin captura: «sin datos» |
| Vuelve a estar en línea | `DEVICE_EVENTS.event_type` = `reappeared` | F5 | Transición OFFLINE → ONLINE |
| Puerto abierto o cerrado | `DEVICE_EVENTS.event_type` = `service_new` / `service_gone` | F5 | Solo con escaneo de puertos |
| Cambio de SO o de tipo | `DEVICE_EVENTS.event_type` = `os_changed` / `type_changed` | F5 | Entre valores conocidos |
| Presencia | (derivado de `DEVICE_EVENTS` y `APP_SESSIONS`) | F5 | Presente, ausente o sin datos |
| Inventario («visto por primera vez») | `DEVICE_SEEN` | F5 | Apps, categorías, organizaciones, países y JA4 |
| Ventana de 1 h o 24 h | (consulta de `TRAFFIC_ROLLUP_*`) | F5 | Minutos cerrados |
| Retención del histórico | `[history]` | F5 | Configuración, no tabla |
| Alerta | `ALERTS` | F6 | Instancia disparada por una regla |
| Regla de alerta | `ALERT_RULES` | F6 | Condición configurable |

## 6. Estado del Proyecto

- **Fase 1:** **67 / 67** — **Implementación reportada** (2026-11-10).
  - Verificación: 135 tests en verde (131 + 4 CLI), `fmt`/`clippy` limpios, TUI verificada en pty en modo degradado con descubrimiento real.
  - Verificación pendiente no bloqueante: F1-24, F1-25 y F1-64 (ejecución real y rendimiento con `CAP_NET_RAW`); sigue pendiente: el sprint 4.0 de F4 quedó bloqueado (sin `sudo` en el entorno del agente).
- **Fase 2:** **79 / 79** — **Implementación reportada** (2026-11-10).
  - Verificación: 313 tests + 4 CLI en verde (más 1 manual de red ignorado por defecto), `fmt`/`clippy` limpios; migración v2 aditiva probada contra BD F1; cadena activa verificada en red aislada (ARP + ICMP + port scan + banner + fingerprint Linux + clasificación `pc`); red doméstica con descubrimiento pasivo (gateway HUAWEI, equipo Microsoft, mDNS con SSH/SFTP/RFB/SMB).
  - Verificación pendiente no bloqueante: ciclo activo completo contra la red real del desarrollador con `setcap`; rendimiento §8 no medido end-to-end. Sigue pendiente (sprint 4.0 de F4, bloqueado por `sudo`).
- **Fase 3:** **102 / 102** — **Implementación reportada** (2026-11-10).
  - Verificación: **534 tests + 4 CLI en verde** (531 + 4 con feature `pcap`; 2 ignorados que requieren `CAP_NET_RAW`), `fmt`/`clippy` limpios; migración v3 aditiva probada contra BD F2 sin pérdida; smoke test en pty con BD migrada; replay pcap con fixture (5 tramas); test real de captura en loopback (ignorado por defecto).
  - Correcciones aplicadas tras primera prueba con `CAP_NET_RAW`: `tp_frame_nr` (bug EINVAL) y `tp_mac` (bug de offset) en TPACKET_V3.
  - Verificación pendiente no bloqueante: visual final en `wlp191s0` con binario recompilado; aviso `max_pps` sin test automático (requiere captura real superando umbral); comportamiento en red doméstica con varios equipos durante varios minutos. Sigue pendiente (sprint 4.0 de F4, bloqueado por `sudo`).
- **Fase 4:** **167 / 176** — **Implementación reportada** (2026-11-11), versión 0.4.0.
  - Verificación: 812 tests unitarios + 4 de integración en verde (2 ignorados), `fmt`/`clippy` limpios; migración v4 probada contra BD de F3 y en un arranque real en modo degradado; carga del catálogo y las MMDB en 46 ms (límite 200 ms); datos embebidos 17,4 MiB (límite 25 MB); replay pcap mixto con etiquetas esperadas; vectores oficiales de JA4 y de RFC 9001 en los tests.
  - Desviaciones (recogidas en el informe v1.1): top 50 publicado por total y reordenado en la TUI; serie de 60 s solo para apps; tope de rankings real (desaloja también claves con tráfico); `Rankings::top_for_device` añadido; apps `lan` solo por servicio de F2; porcentajes de «¿Quién lo usa?» con un decimal; fecha completa de las bases IP; dos nombres del catálogo embebido de más de 40 caracteres.
  - Pendiente (9 casillas): las 5 del sprint 4.0, 50 K pps, CPU y memoria con la inferencia activa, y logs sin dominios con `-v`. Bloqueadas porque el entorno del agente no tiene `sudo` para `setcap`; las desbloquea el desarrollador (prompt de reanudación). El 2026-11-11 el desarrollador decidió seguir con F5 sin ellas (respuesta 1c): siguen abiertas.
  - Trazabilidad: la lista de completadas del informe llegó con los dos primeros caracteres de cada línea cortados; se casó por el resto del texto sin ambigüedad (166 de 166).
- **Fase 5:** **0 / 141** — **Especificada** (2026-11-11). Sin informe de implementación: progreso sin confirmar. Se especificó sobre una F4 abierta (decisión del desarrollador del 2026-11-11, respuesta 1c); F5 mide su rendimiento con histórico sintético.
- **Fases 6–7:** pendientes de especificar.
- **Progreso total:** **415 / 565** funcionalidades (F1–F3: 248; F4: 167 de 176; F5 especificada: 141, sin confirmar).
- **Deuda documental:** los informes de F2 y F3 siguen en v1.0 y no recogen sus desviaciones (están en este maestro); se subirán a v1.1 al recibir sus `-implementacion.md`. El informe de F1 está en v1.2 (renumeración de ADR) y el de F4 en v1.1 (alineado con su implementación).
- **Fechas de informes de implementación procesados:**
  - Fase 1: **2026-11-10** ✅
  - Fase 2: **2026-11-10** ✅
  - Fase 3: **2026-11-10** ✅
  - Fase 4: **2026-11-11** ✅ (quedan 9 casillas de la pasada con `CAP_NET_RAW`)
  - Fase 5: — (pendiente)

**Regla:** el progreso solo se actualiza a partir de informes de implementación reales; no se infiere de la especificación.

## 7. Roadmap

| Fase | Nombre | Depende de | Estado |
|------|--------|------------|--------|
| 1 | Fundación + descubrimiento básico | — | Implementación reportada |
| 2 | Descubrimiento avanzado | F1 | Implementación reportada |
| 3 | Tráfico en vivo (pasivo + local) | F1, F2 | Implementación reportada |
| 4 | Protocolos, apps y top talkers | F3 | Implementación reportada (9 pendientes) |
| 5 | Histórico, rollups y eventos | F3, F4 | Especificada |
| 6 | Alertas (locales + escritorio) | F5 | Pendiente de especificar |
| 7 | Integraciones y exportación | F3, F1 | Pendiente de especificar |

**Dependencias que condicionan el orden:**
- F3 no se puede hacer sin F1 (persistencia y modelo de datos) y F2 (servicios por dispositivo).
- F4, F5 y F6 son secuenciales entre sí; cada una asume la anterior.
- F7 (SNMP, ARP spoof opt-in, replay libpcap) puede solaparse con F4–F6 si se quiere, pero no bloquea.

**Sub-fase opcional (3.5):** modos intrusivos/integración con router (ARP spoof opt-in, SNMP, port mirror) si se prioriza el tráfico de terceros antes de F7. F4 se diseñó independiente de la fuente de paquetes: la 3.5 o F7 solo añaden tráfico al mismo motor.

**Modo servicio (sin TUI):** pendiente de decidir si va en F7 o en una sub-fase propia (respuesta 2a de F5). Daría histórico continuo sin tener Almenara abierta, pero cambia la arquitectura del escritor único.

**Siguiente paso previsto:** implementación de F5 y entrega de `almenara-fase5-implementacion.md`. La pasada con `CAP_NET_RAW` de F4 sigue abierta por decisión del desarrollador (respuesta 1c del 2026-11-11; riesgo alto); su prompt de reanudación sigue valiendo. Después, F6 — Alertas. Preguntas de exploración pendientes de F6: qué reglas (equipo nuevo, puerto nuevo, app, país, organización o JA4 nuevos por equipo desde `DEVICE_SEEN`, tráfico por encima de lo habitual desde los rollups), periodo de aprendizaje inicial, severidad (`mac_random` baja la de las MAC privadas), notificaciones de escritorio, silencios, retención de las alertas y cómo no alertar por huecos.

## 8. Decisiones Transversales y Riesgos Abiertos

### Decisiones transversales

- **Lenguaje y stack:** Rust (edition 2021, **MSRV 1.88**), tokio, ratatui + crossterm, clap, serde + toml, rusqlite (bundled), pnet (datalink), **libc + nix 0.31** (raw sockets, AF_PACKET, TPACKET_V3), macaddr-ouidb (renombrada `ouidb`), hickory-proto (mDNS), reqwest (rustls, solo XML UPnP), tracing. **Parser SSDP propio** (el crate `ssdp` no compila en stable). **BPF clásico con compilador e intérprete propios**. **Captura con AF_PACKET + TPACKET_V3 sin libpcap**. **F4:** `hickory-proto` también para respuestas DNS; RustCrypto (`aes-gcm`, `aes`, `hkdf`, `sha2`) para QUIC Initial y JA4; `psl`; `maxminddb` con DB-IP Lite embebida.
- **Nomenclatura:** tablas `MAYUSCULAS_SNAKE_CASE`, campos `minusculas_snake_case`. Sin endpoints HTTP (TUI); "servicios internos" como interfaz análoga (`Módulo::función_snake_case`).
- **Migraciones aditivas** con test de compatibilidad con la BD de la fase previa (obligatorio a partir de F2). Toda nueva fase que añada columnas debe incluir test que abra la BD de la fase anterior y verifique que los datos se conservan. Idempotencia con `SCHEMA_MIGRATIONS` y `already_applied` para ALTER TABLE (confirmada en v4 con test real v3 → v4).
- **SQLite como único escritor:** la conexión vive en el hilo de la TUI, `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. La reconciliación de eventos la hace el hilo de la TUI. Aplicable a F3+ (nuevas tablas de tráfico) sin reabrir la conexión. Desde F5, el histórico se lee por un hilo con conexión de solo lectura (ADR-60); sigue habiendo un único escritor.
- **Timestamps en SQLite como TEXT RFC 3339 UTC** — ordenables lexicográficamente, compatibles con `rusqlite` sin `chrono`. `last_fingerprint` es TEXT (JSON), no TIMESTAMP. Excepción (F5, ADR-56): los cubos de los rollups son enteros (segundos UTC; día local AAAAMMDD).
- **Logs con rotación por tamaño** implementada con escritor propio (10 MiB × 3), sobre `tracing-appender::non_blocking`. Sin cambios desde F1.
- **Documentación en `docs/fase[N]/`** a partir de F2.
- **Modo degradado obligatorio:** toda la app debe poder arrancar sin `CAP_NET_RAW` con aviso visible. La captura (F3), el ARP scan activo (F1) y el resto de métodos activos (F2) quedan limitados o desactivados.
- **`passive_only = true` = no consultar a nadie** (ADR-17 F2, ADR-26 F3, ADR-52 F4): prohíbe ARP scan, ICMP sweep, mDNS browse, M-SEARCH, port scan, banner grabbing, fingerprint y, desde F4, las consultas NetBIOS y el DNS inverso. **Permite captura pasiva e inferencia** (escuchar no emite tráfico; las uniones multicast del sistema no cuentan). El DNS inverso de IPs de Internet no se hace nunca, en ningún modo. Aplicable a F4–F7.
- **Pestañas centrales indican la fase de llegada** cuando son placeholder. Convención de UX.
- **Keybindings canónicos:**
  - `hjkl` (j/k selección, h/l pestañas), `Tab`/`Shift-Tab`, `1-7`
  - `/` búsqueda, `s` ordenar, `f` filtrar, `r` rescan
  - `a` alias, `n` notas, `t` override manual de `device_type` (F2)
  - `g` toggle plano/agrupado (F2)
  - `Enter` detalle master-detail (F3)
  - `v` cabeceras IP/TCP de conexión (F3), `Esc` cierra
  - `g` en Tráfico: agrupación equipo/destino/app/categoría/protocolo/proceso (F4); `w` ventana 60 s/5 min/sesión (F4)
  - `Enter` en un ranking que no es de equipos: «¿Quién lo usa?» (F4); `i` en Conexiones: nombres ⇄ IPs (F4)
  - `?` ayuda, `q` salir
- **Config por defecto escrita al primer arranque** (best-effort, si falla avisa y continúa). **Configuración tolerante** (F4): una clave obsoleta se avisa una sola vez y se descarta sin reescribir el fichero; un valor inválido usa el valor por defecto con aviso; la configuración nunca aborta el arranque.
- **`ssdp` y `ouidb` como contratos semánticos, no como crates.** Parser SSDP propio y `macaddr-ouidb` renombrada. Regla general desde F4: todo crate nombrado en una especificación es un contrato semántico; si no existe, no compila con el MSRV o no hace lo descrito, se usa un equivalente en Rust puro y se anota como desviación.
- **Ping sweep / ICMP raw con `libc`** (no `pnet transport`, bug `EINVAL` en `pnet 0.35`). Vinculante para raw ICMP en F4+.
- **Unión multicast per-interfaz obligatoria** (mDNS, SSDP y futuros). `INADDR_ANY` no es fiable en equipos multi-interfaz.
- **mDNS browse activo en 2 etapas desde puerto 5353** (RFC 6762). Cualquier consulta mDNS activa futura debe respetar esta norma.
- **Clasificador con memoria:** `device_type` combina servicios del ciclo + persistidos y **no regresa a `unknown`** si el resultado automático es `unknown`. `device_type_manual` siempre gana. F4 añade reglas por modelo (mDNS/UPnP) y User-Agent antes de las de hostname.
- **Fingerprint de SO:** umbral de confianza ≥ 4; si no se supera, `os_family = NULL`. macOS/iOS quedaban en NULL con la puntuación de F2; F4 suma señales de DHCP, modelo y User-Agent con el mismo umbral y registra `os_source` (ADR-50).
- **Fuentes pasivas (mDNS/SSDP/DHCP) solo enriquecen equipos ya conocidos por L2**; no crean dispositivos por sí solas. **La captura sí es evidencia L2** (ARP, DHCP y tramas con MAC + IP local): crea equipos con la fuente `capture` (ADR-49, F4).
- **Checklist oficial usa las casillas reales como fuente de verdad.** Al procesar un informe de implementación, el analista funcional reconcilia contadores si hay discrepancia (F2: 73→79, F3: 76→102).
- **Captura sin libpcap** (ADR-18, ADR-29). `pcap` como feature no default para replay en F7 (lector mínimo propio).
- **Filtros BPF clásicos** adjuntos al socket (ADR-19). Compilador propio (`bpf::compile`); no se implementan filtros propios en userspace.
- **Payload: descarte inmediato y nunca persistido** (ADR-20, regla dura). La inspección para etiquetar (DNS, TLS, HTTP, QUIC y primeros bytes) es activa por defecto desde F4 (ADR-37, modifica ADR-20) y se apaga con `[inference].enabled = false`; solo se guardan etiquetas derivadas. Desde la implementación de F4, el payload tampoco sale del hilo de captura: `Parser::parse_frame` devuelve su rango dentro de la trama, `FlowInspector::inspect` lo consume ahí y al agregador solo viajan `PacketMeta` y evidencias en lotes (`CaptureBatch`). Vinculante para toda fuente o inspección futura (3.5, F7).
- **Snapshot persistente cada 5 s** (ADR-21) con coste despreciable. Desde F5 sigue como semilla de las sparklines de 60 s; el histórico va en los rollups.
- **`CONNECTIONS` como tabla caliente** (ADR-22): purga por timeout; no es histórico.
- **Dos fuentes de conexiones (`/proc` + captura)** (ADR-23). La TUI debe indicar `[host]` cuando la conexión es del propio host.
- **Ventanas 60s + 5min en F3** (ADR-24); F5 añade 1 h y 24 h desde el histórico, con minutos cerrados (ADR-63).
- **Aviso único de captura al arrancar** (ADR-25).
- **TPACKET_V3 con `libc`/`nix` sin libpcap** (ADR-18). El replay con libpcap real queda reservado a F7.
- **`tp_frame_nr` y `tp_mac` como contrato de TPACKET_V3** (ADR-28): `tp_frame_nr = block_nr × (block_size/frame_size)` siempre calculado; `tp_mac` relativo a la cabecera `tpacket3_hdr`, no al bloque. Cualquier cambio del anillo debe pasar el test real en loopback.
- **Un socket/hilo por interfaz** (ADR-27). Vinculante para futuras fuentes (SNMP, port mirror en F7).
- **5-tuple canónica** (ADR-30). `bytes_out` = origen→destino; `bytes_in` = retorno. Aplicable a cualquier tabla de conexiones futura (F5 no guarda conexiones, ADR-58). El rol cliente/servidor va aparte en `client_is_src` (ADR-45, F4).
- **Estado TCP NULL** cuando no hay `/proc`/conntrack (ADR-31). No inventar ESTABLISHED a partir de flags TCP.
- **`max_pps` con `limit_drops` separado** (ADR-33). F4+ que añada límites debe seguir este patrón.
- **Fila `[host]` en rankings** (ADR-32). Cualquier ranking de tráfico en fases posteriores mantiene `[host]` + filtro de inactivos.
- **`top_ports` acumulativo** (256 entradas máx. por dispositivo, ordenadas por bytes). Top-5 en detalle.
- **Caché de conexiones en memoria** acotada a 2048 con purga por timeout + desalojo de inactivas.
- **Parser `ParseError { ignorable }`**: ARP/LLDP, EtherTypes no soportados, IP no IPv4/v6, fragmentos no iniciales → ignorable. Solo tramas mal formadas/truncadas cuentan como `parse_errors`.
- **Cierre ordenado:** `ScanCommand::Stop` + `TrafficCommand::Stop` + join con timeout 2 s.
- **Reaplicar capability tras recompilar** (`scripts/ejecutar-con-permisos.sh`). `setcap` necesita `sudo`, que el agente no tiene: toda verificación con `CAP_NET_RAW` la desbloquea el desarrollador y el agente mide sin recompilar después (F4).
- **Numeración global de ADR:** única en todo el proyecto; las ADR añadidas a posteriori a un informe toman el siguiente número libre (F1 v1.2: ADR-34 a 36). F4 usa ADR-37 a 52.
- **Etiquetas que solo suben de fuerza** (F4): puerto (1) < ASN (2) < servicio LAN (3) < caché de nombres (4) < SNI/Host (5). La fuente de cada etiqueta se guarda (`app_source`, `name_source`) y el % sin identificar se muestra siempre. Las apps `lan` solo se asignan por servicio de F2 en flujos LAN↔LAN (sin reglas de dominio, ASN ni puerto).
- **Datos embebidos versionados** (F4): catálogo, PSL y DB-IP Lite viven en el binario; la app nunca descarga datos; se actualizan con un script de desarrollo y una versión nueva, con origen y licencia en `data/FUENTES.md`. Atribución a DB-IP obligatoria (CC BY 4.0).
- **Dominios = historial de navegación** (ADR-48): solo en tablas calientes (`CONNECTIONS`, `NAME_CACHE` ≤ 24 h) y en memoria; nunca en logs por encima de `debug`. En el histórico (F5, ADR-57), los destinos solo viven 2 h por minuto y 30 días por hora; nunca en días ni en el inventario.
- **Motor de inferencia independiente de la fuente de paquetes** (F4): la visibilidad de terceros (3.5/F7) no cambia la inferencia.
- **`mac_changed` v2** (ADR-51): rotación de MAC privada con la misma identidad DHCP y un único candidato; la toma de IP de F1 no aplica si las huellas DHCP se contradicen; el evento lleva `reason`.
- **Rankings en memoria** (ADR-46): ventanas de F3 + acumulado de sesión, tope real de 2048 claves por dimensión (si todas tienen tráfico se desaloja igualmente la más antigua); desde F5, sus contadores alimentan los rollups por minuto (ADR-53). La fila `[host]` (ADR-32) se mantiene.
- **Presupuesto de `AppEvent::Traffic`** (F4): cada segundo viaja el top 50 por total de las 18 combinaciones dimensión × ventana, con serie de 60 s solo para apps; los demás órdenes se aplican en la TUI sobre esas filas.
- **Histórico por agregados** (F5, ADR-53 a 55 y 58): rollups por minuto (48 h), hora (90 días) y día (2 años) desde los contadores completos del agregador; sujetos `device`, `host`, `other` y `network`; 20 claves por sujeto, dimensión y cubo más `~otros`; claves especiales con `~`; sin registro de conexiones.
- **Horas en UTC y días por fecha local** (F5, ADR-56): «ayer» es un día natural; los días de 23 y 25 horas se construyen con sus horas reales.
- **Sesiones de Almenara con latido** (F5, ADR-59): sin sesión o sin captura es «sin datos» y nunca se interpola. Aplicable a toda vista o alerta que use el histórico (F6).
- **Instancia única por BD** (F5, ADR-65): bloqueo `data.db.lock` con `flock`; una segunda Almenara no arranca.
- **Eventos sin cambio de esquema** (F5, ADR-61): `event_type` sin `CHECK`; tipos nuevos `reappeared`, `service_new`, `service_gone`, `os_changed` y `type_changed`; la presencia se deriva de los eventos.
- **Inventario por equipo** (F5, ADR-62): `DEVICE_SEEN` con primera y última vez (apps, categorías, organizaciones, países, JA4) y puertos desde `DEVICE_SERVICES`; base del «nuevo» de F6; sin dominios.
- **Purga con `incremental_vacuum` y sin copias automáticas** (F5, ADR-64); la copia manual está en el README.
- **Medición con histórico sintético** (F5, ADR-66): tamaño y tiempos se miden sin captura.
- **Consultas puntuales de la TUI al agregador** (F4): `TrafficCommand` con respuesta por `oneshot` y 200 ms de espera máxima en la TUI (p. ej. «¿Quién lo usa?»). Patrón para futuras consultas al hilo de tráfico.

### Riesgos abiertos

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| Cambio de stack de pcap en F7 (pcap-replay real con libpcap) | Medio | ADR específico al iniciar F7; la feature `pcap` actual (lector propio) ya cubre fixtures de test |
| Escalado de la TUI a >100 equipos con lista | Medio | Paginación/virtualización si es necesario |
| ARP spoof puede romper la red del usuario | Alto | Opt-in con advertencia + documentación clara; nunca por defecto |
| Base OUI embebida se queda obsoleta | Bajo | Actualización de versión del crate en releases periódicas |
| Modo degradado con `/proc/net/arp` vacía | Bajo | Documentar limitación; recomendar `sudo` o `setcap` |
| `mac_changed` puede confundirse con reasignación IP | Bajo | F4 (ADR-51): v2 con huella DHCP; sin huella sigue la heurística de F1 |
| Rendimiento no verificado end-to-end (F1-64, F2 §8, F3 §8 y F4 §8 con la inferencia activa) | **Alto** | Cuatro fases sin medir: el sprint 4.0 quedó bloqueado por falta de `sudo` en el entorno del agente, y F3 ya demostró que la prueba real encuentra fallos que los tests no ven (TPACKET_V3). El 2026-11-11 el desarrollador decidió seguir con F5 sin la pasada (respuesta 1c). Cuando se quiera cerrar: el desarrollador aplica la capacidad y el agente mide sin recompilar (prompt de reanudación de F4); F5 mide su parte con histórico sintético |
| XML SSDP malicioso (LOCATION a IP externa) | Medio | Solo http/https, máx. 256 KB, sin redirecciones, timeout 2 s |
| Fingerprint heurístico con falsos positivos | Bajo | Umbral de confianza 4; override manual `t` |
| macOS/iOS quedan en `os_family = NULL` | Bajo | F4 añade modelo (mDNS/UPnP), DHCP y User-Agent (ADR-50) |
| `pnet 0.35` raw socket bug (EINVAL) | Medio | Migrado a `libc` en F2; ADR de F3–F4 debe considerar `libc` como primera opción |
| Multicast con `INADDR_ANY` falla en multi-interfaz | Medio | Migrado a unión per-interfaz en F2. Vinculante para futuros listeners |
| Leases DHCP no legibles desde cliente (0600 root, solo cliente) | Bajo | Documentar; F7 puede integrar SNMP al router |
| Ayuda sin scroll en 80×24 | Bajo | Aceptado; ampliación futura si molesta |
| Helpers públicos sin consumidor (dead_code justificado) | Bajo | Se consumirán en F4/F5 |
| **Privacidad: payload capturado por error** | **Alto** | Descarte inmediato en el hilo de captura; payload nunca persiste; desde F4 solo etiquetas derivadas (`[inference].enabled` para apagarlo); aviso en Ayuda |
| `TPACKET_V3` no disponible en kernels antiguos | Bajo | Requisito documentado en README (Linux ≥ 3.2) |
| Captura satura el hilo de TUI | Medio | Hilo dedicado + `max_pps` configurable + aviso de drops |
| `/proc/net/nf_conntrack` no legible sin root | Bajo | Best-effort silencioso; no bloquea |
| `/proc/[pid]/fd` sin permisos para procesos ajenos | Bajo | Degradación silenciosa; PID queda NULL |
| Filtro BPF complejo ralentiza captura | Bajo | BPF evalúa en kernel; coste usuarios despreciable |
| `device_id = NULL` en CONNECTIONS por no match | Medio | Etiqueta `[?]`; el usuario ve qué no se ha atribuido |
| Sparkline arranca a cero al reabrir | Bajo | `TRAFFIC_SNAPSHOT` como semilla; F5 especificada: ventanas de 1 h y 24 h y gráficas desde el histórico |
| `max_pps` alcanzado sin darse cuenta | Bajo | Aviso una vez por minuto + estado en barra |
| Bug del anillo TPACKET_V3 (`tp_frame_nr`, `tp_mac`) | Alto (captura silenciosa a cero) | Detectado en prueba real; corregido y con test en loopback. Regla: cualquier cambio del anillo debe pasar el test real |
| Bug del parser en protocolos no cubiertos | Medio | Límites documentados; ParseError ignorable; fixtures |
| Anillo por interfaz consume 64 MB × N | Bajo | Aceptable en Linux doméstico; configurable en F7 |
| Caché de conexiones crece con tráfico de terceros | Bajo | Límite 2048 + desalojo de inactivas |
| `CONNECTIONS` sin UNIQUE podría duplicar | Bajo | Solo escribe el hilo de la TUI; upsert por 5-tuple |
| Verificación visual final F3 en `wlp191s0` pendiente | Bajo | Sprint 4.0 de F4 (bloqueado por `sudo`; prompt de reanudación) |
| Ventanas 1h/24h fuera de F3 | Bajo | F5 especificada: 1 h y 24 h desde el histórico (ADR-63) |
| Inferencia de app limitada (DNS/SNI) | Bajo | F4 implementada: SNI de TLS y QUIC, Host, respuestas DNS, catálogo y ASN |
| ECH y DoH ocultan nombres | Medio | % sin identificar siempre visible; ASN y país como respaldo; no se intenta romper el cifrado |
| QUIC cambia (versiones nuevas, ClientHello más grande) | Medio | Solo v1 y v2; versión desconocida → sin SNI y sin error; vectores de RFC 9001 en las pruebas |
| Catálogo desactualizado o con reglas erróneas | Medio | `apps.toml` para corregir; origen por regla; pruebas de precedencia |
| Bases IP desactualizadas; tamaño del binario y del repositorio | Bajo | Script de actualización por versión; presupuesto de 25 MB |
| **Parsers expuestos a tráfico hostil** | **Alto** | Sin pánicos, límites estrictos, pruebas con entradas truncadas y aleatorias |
| **Privacidad: dominios como historial de navegación** | **Alto** | Tablas calientes con caducidad; nada por encima de `debug` en logs; aviso en Ayuda; desactivable |
| CPU de la inferencia con muchos pps | Medio | Inspección solo al inicio de cada flujo; topes; medición pendiente de la pasada con `CAP_NET_RAW` |
| Fusión errónea de identidades (`mac_changed` v2) | Medio | Exige MAC privada, huella y nombre DHCP iguales y un único candidato; `reason` para auditar |
| Equipos falsos por ARP falsificado | Bajo | Salen como `new`: es lo que se quiere detectar; F6 lo aprovechará |
| Rotación de MAC sin DHCP visible sigue dando `new` | Bajo | Marca «MAC privada» y `mac_random` en el evento para que F6 baje la severidad |
| Ranking reordenado sobre el top 50 por total: una clave que destaca en ↑ o en equipos sin estar en ese top no aparece | Bajo | Aceptado por el presupuesto del evento; revisar con uso real |
| El tope de rankings desaloja claves con tráfico si hay más de 2048 activas | Bajo | Solo con mucho tráfico de terceros (3.5/F7); protege la memoria |
| Informes de F2 y F3 en v1.0 (deuda documental) | Bajo | Se suben a v1.1 al recibir sus `-implementacion.md`; mientras, manda este maestro |
| F5 especificada sobre una F4 sin la pasada con `CAP_NET_RAW` (decisión del desarrollador del 2026-11-11) | Medio | Registrado; el prompt de reanudación de F4 sigue valiendo; F5 no depende de esas medidas |
| Huecos en el histórico mientras Almenara está cerrada | Medio | Sesiones con latido y huecos marcados; dejarla abierta (tmux); modo servicio en el roadmap |
| Crecimiento de la base de datos | Medio | Retención por resolución, topes, `incremental_vacuum`, aviso con `max_db_mb` y medición con histórico sintético (≤ 300 MB con el perfil de referencia) |
| **Privacidad: historial y presencia de las personas de la casa** | **Alto** | Destinos solo 2 h por minuto y 30 días por hora; sin registro de conexiones; presencia 90 días; aviso en Ayuda; desactivable con `[history].enabled = false` |
| Escrituras del histórico en el hilo de la TUI (tirones) | Medio | Lote ≤ 10 ms; hora ≤ 50 ms; día ≤ 100 ms; pendientes en tandas de 10 por segundo |
| Consultas de un año lentas sin índice secundario | Bajo | Lector en otro hilo con corte a los 2 s; medición sintética; índice por sujeto si hace falta, anotando su tamaño |
| Precisión limitada por los topes (`~otros`) | Bajo | 20 claves por sujeto, dimensión y cubo; los totales son exactos |
| Cambios de hora, de zona horaria o saltos del reloj | Bajo | Horas en UTC; días con sus horas reales; un minuto repetido suma |