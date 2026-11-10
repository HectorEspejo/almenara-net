# Almenara - Checklist Fase 2: Descubrimiento avanzado

## Descubrimiento pasivo (mDNS)
- [x] Escucha pasiva mDNS en 224.0.0.251:5353
- [x] Parseo de respuestas mDNS (A, AAAA, PTR, SRV, TXT, HINFO)
- [x] Extracción de servicios por dispositivo (`_http._tcp`, `_ipp._tcp`, `_airplay._tcp`, `_googlecast._tcp`, `_raop._tcp`, `_device-info._tcp`)
- [x] Extracción de hostname `.local` desde mDNS
- [x] Asociación mDNS → DEVICES por IP (y MAC cuando esté disponible)
  - AC: dado un anuncio mDNS con IP ya en DEVICES, cuando se procesa, entonces se actualiza hostname y `DISCOVERY_SOURCES.source = 'mdns'`

## Descubrimiento pasivo (SSDP)
- [x] Escucha pasiva SSDP en 239.255.255.250:1900
- [x] Parseo de NOTIFY y respuestas M-SEARCH (ST, USN, LOCATION)
- [x] Fetch del XML de descripción (LOCATION) con timeout 2 s, máx. 256 KB, solo http/https, sin redirecciones externas
  - AC: dado un LOCATION inaccesible, cuando falla el fetch, entonces se registra aviso en log y no se aborta el ciclo

## Descubrimiento activo (mDNS / SSDP)
- [x] Consulta mDNS activa de `_services._dns-sd._udp.local` (si no `passive_only` y CAP_NET_RAW)
- [x] M-SEARCH activo SSDP (`ST=ssdp:all`) (si no `passive_only` y CAP_NET_RAW)
- [x] `[scan].passive_only = true` deshabilita mDNS browse, M-SEARCH, port scan, banner grabbing, ARP scan e ICMP sweep
  - AC: dado `passive_only = true`, cuando corre un ciclo, entonces no se emite tráfico activo (verificable en captura) y solo se usan fuentes pasivas

## DHCP leases
- [x] Lectura de leases dnsmasq (`/var/lib/misc/dnsmasq.leases`)
- [x] Lectura de leases dhclient (`/var/lib/dhcp/dhclient.leases`)
- [x] Lectura de leases NetworkManager y systemd-networkd
- [x] Rutas manuales de leases desde `[scan].dhcp_lease_paths`
- [x] Merge de leases por MAC → hostname e IP preferente
  - AC: dado un lease activo con hostname, cuando el equipo no tiene hostname por reverse DNS, entonces se usa el del lease

## NetBIOS
- [x] Consulta NetBIOS name query (UDP 137) para hostname
- [x] Consulta NetBIOS datagram/session (UDP 138/139) para workgroup cuando aplica
- [x] Timeout 500 ms, fallo silencioso (sin error visible si no responde)

## Fingerprint de SO
- [x] Cálculo de TTL inicial desde TTL observado + saltos estimados (heurística)
- [x] Parseo de opciones TCP (ventana, MSS, timestamps) de SYN-ACK o banner
- [x] Clasificación heurística a `os_family` con umbral de confianza ≥ 4 (si no, NULL)
  - AC: dado un equipo con TTL y opciones TCP ambiguas, cuando el score máximo no alcanza el umbral, entonces `os_family = NULL`
- [x] Persistir `os_family` y `last_fingerprint` en DEVICES

## Port scan y banner grabbing
- [x] Port scan TCP CONNECT sobre `[scan].top_ports` (TOP-20 por defecto)
- [x] Concurrencia 64, timeout 500 ms, límite 1024 IPs por ciclo
- [x] Re-escaneo de puertos solo al descubrir equipo nuevo, cambio de IP/MAC o pulsación de `r` (nunca cada ciclo periódico)
- [x] Banner grabbing por puerto abierto (lectura máx. 512 B, timeout 1 s, saneado y truncado a 128 chars)
- [x] Clasificación de servicio por puerto y banner (http, ssh, smb, upnp, printer, rtsp, mqtt, rdp, …)

## Taxonomía device_type
- [x] Ampliación de `device_type` a 12 valores: gateway, pc, server, nas, mobile, tablet, tv, streaming, iot, printer, camera, unknown
- [x] Clasificación automática por prioridad: gateway > printer > camera > tv/streaming > nas > mobile/tablet > server/pc > iot > unknown
- [x] Columna `device_type_manual TEXT NULL` con override manual que manda sobre el automático
  - AC: dado un equipo con `device_type_manual = 'pc'`, cuando el clasificador automático dice `nas`, entonces prevalece `pc`

## Interfaz de Usuario
- [x] Vista agrupada por categoría activable con `g`
  - AC: dado modo plano, cuando se pulsa `g`, entonces la lista se agrupa por `device_type` con cabeceras de sección
- [x] Preferencia `[ui].list_view` persistida en config (`"flat"` | `"grouped"`), `"flat"` por defecto
- [x] Iconos ASCII por tipo: `[⌂]` gateway, `[▣]` pc/server/nas, `[▯]` mobile/tablet, `[▶]` tv/streaming, `[P]` printer, `[C]` camera, `[●]` iot, `[?]` unknown, `○` offline
- [x] Sin columnas nuevas en la lista plana (80 columnas); `os_family` se ve en Config y se verá en el detalle de F3
- [x] Barra de estado con modo (`privilegiado` / `pasivo` / `degradado`) y fuentes activas
- [x] Pestaña Ayuda actualizada con `g` y leyenda de iconos

## Persistencia (migración v2, aditiva)
- [x] Migración v2: nuevas columnas en DEVICES (`os_family`, `device_type_manual`, `last_fingerprint`)
- [x] Tabla `DEVICE_SERVICES` con id, device_id (FK ON DELETE CASCADE), port, protocol, service, banner, first_seen, last_seen, UNIQUE(device_id, port, protocol)
- [x] Tabla `DISCOVERY_SOURCES` con id, device_id (FK ON DELETE CASCADE), source, last_seen, UNIQUE(device_id, source)
- [x] Índices `IDX_SERVICES_DEVICE` y `IDX_SOURCES_DEVICE`
- [x] DAO `DEVICE_SERVICES`: `upsert_service`, `list_services`, `mark_stale_services`, `prune_services`
- [x] DAO `DISCOVERY_SOURCES`: `upsert_source`, `list_sources`
- [x] DAO `DEVICES` extendido: `set_os_family`, `set_device_type_manual`
- [x] Migración probada sobre BD de F1 sin pérdida de datos
  - AC: dado un `data.db` de F1, cuando se abre con F2, entonces las tablas antiguas conservan sus datos y las nuevas existen

## Servicios internos (operaciones expuestas al TUI)
- [x] `MdnsListener::start()`
- [x] `MdnsListener::drain()`
- [x] `MdnsQuery::discover_services()`
- [x] `SsdpListener::start()`
- [x] `SsdpListener::drain()`
- [x] `SsdpQuery::m_search()`
- [x] `ssdp::parser::fetch_description()`
- [x] `DhcpLeases::read_all()`
- [x] `Netbios::query_name()`
- [x] `Fingerprint::detect()`
- [x] `PortScan::scan()`
- [x] `BannerGrab::grab()`
- [x] `classify::device_type()`
- [x] `classify::service()`
- [x] `Repo::upsert_service()`
- [x] `Repo::list_services()`
- [x] `Repo::mark_stale_services()`
- [x] `Repo::prune_services()`
- [x] `Repo::upsert_source()`
- [x] `Repo::list_sources()`
- [x] `Repo::set_os_family()`
- [x] `Repo::set_device_type_manual()`

## Configuración
- [x] `[scan].passive_only = false` por defecto
- [x] `[scan].top_ports = [22,23,53,80,139,443,445,515,631,1883,3389,5000,5353,5555,8008,8080,8443,9100,1883,32400]`
- [x] `[scan].dhcp_lease_paths = []` (rutas manuales)
- [x] `[ui].list_view = "flat"` por defecto
- [x] Validación: `top_ports` u16 únicos entre 1 y 65535, máx. 64; `list_view` ∈ {flat, grouped}; rutas de leases inexistentes se descartan con aviso

## Tests y calidad
- [x] Tests unitarios de parsers: mDNS, SSDP, DHCP (dnsmasq / dhclient / NetworkManager), NetBIOS, opciones TCP
- [x] Tests del clasificador `device_type` (casos de prioridad y override manual)
- [x] Tests del fingerprint `os_family` (umbral de confianza)
- [x] Tests de la migración v2 (idempotente y compatible con BD F1)
- [x] Tests de integración del ciclo con `passive_only = true` (sin red real)
- [x] Tests de UI con `TestBackend`: modo plano, modo agrupado, toggle `g`, barra con modo `pasivo`
- [x] `cargo test` en verde, `cargo fmt --check` limpio, `cargo clippy --all-targets -- -D warnings` limpio

---

**Progreso Fase 2:** 79 / 79 funcionalidades (el fichero declara 73; contiene 79 casillas; ver informe de implementación)

**Total Almenara (Fases 1-2):** 146 / 146 funcionalidades (79 de Fase 2)
