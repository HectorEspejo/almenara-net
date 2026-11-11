# Changelog de Almenara

Todas las versiones relevantes del proyecto. El formato sigue
[Versionado Semántico](https://semver.org/lang/es/).

## [0.4.0] - 2026-11-11

**Fase 4 — Protocolos, apps y top talkers.** Almenara pone nombre al tráfico:
identifica el protocolo de aplicación, el nombre del servidor, la app y su
categoría, qué extremo es el cliente y cuál el servidor, y ofrece rankings por
destino, app, categoría, protocolo y proceso además del ranking por equipo.

### Añadido

- **Motor de inferencia** en el hilo de captura: reensamblado acotado del inicio
  de cada flujo TCP (4 KB cliente → servidor y 64 B servidor → cliente, con
  segmentos desordenados y duplicados), ~30 firmas de protocolo de aplicación
  (TLS, QUIC, HTTP, DNS, SSH, RDP, VNC, SMB, FTP, SMTP, IMAP, POP3, MQTT, CoAP,
  RTSP, SIP, STUN, WireGuard, OpenVPN, IPsec, BitTorrent, SNMP, NTP, SSDP,
  NetBIOS, DHCP, mDNS, LLMNR…) y rol cliente/servidor (SYN, sockets en LISTEN,
  puertos de servicio y primer datagrama UDP).
- **TLS**: parser propio del ClientHello con SNI normalizado, ALPN, versiones,
  cifrados, extensiones y algoritmos de firma; **JA4 de cliente** según la
  especificación pública de FoxIO (vectores oficiales en los tests).
- **QUIC**: descifrado del paquete Initial de QUIC v1 y v2 (claves derivadas del
  DCID, protección de cabecera y AEAD AES-128-GCM) con recomposición de las
  tramas CRYPTO, SNI y JA4 con prefijo `q`.
- **HTTP/1.x en claro**: `Host` y `User-Agent` de las peticiones.
- **Caché IP → nombre** (con caducidad de 1 h a 24 h, refresco por uso, tope de
  10 000 entradas y preferencia por el nombre consultado por el mismo equipo)
  alimentada por respuestas DNS (A/AAAA/CNAME), SNI y `Host`, persistida en la
  nueva tabla `NAME_CACHE`.
- **Catálogo propio de 162 apps en 12 categorías** (+ categoría especial
  `lan`) embebido en el binario, ampliable con `apps.toml`; reglas por
  dominio (gana el sufijo más largo), ASN y puerto, y apps de red local para los
  servicios detectados por la fase 2.
- **Destinos sin red**: dominio registrable con la Public Suffix List embebida y
  organización/país con las bases DB-IP Lite embebidas (IPv4 e IPv6).
- **Rankings** por equipo, destino, app, categoría, protocolo y proceso local en
  ventanas de 60 s, 5 min y sesión, con bytes ↓/↑ según el rol, equipos
  distintos, conexiones activas, porcentaje de tráfico sin identificar y panel
  «¿Quién lo usa?».
- **Identificación de equipos**: huella DHCP (opciones 55 y 60), nombre DHCP
  (opción 12), modelo anunciado por mDNS/UPnP, pistas del User-Agent de HTTP en
  claro, puntuación combinada de SO con umbral 4 y `os_source`, MAC privadas y
  `mac_changed` v2 (rotación de MAC privada y toma de IP con `reason`).
- **La captura como fuente L2** que crea equipos: ARP, DHCP y tramas IPv4 de la
  subred local, con filtros, deduplicación y tope de 4096 por ciclo.
- **Migración v4 aditiva**: columnas nuevas en `CONNECTIONS` (rol, protocolo de
  aplicación, nombre del servidor, app, categoría, fuentes y JA4) y en
  `DEVICES` (modelo, campos DHCP, User-Agent y fuente del SO), tabla
  `NAME_CACHE` y fuente `capture` en `DISCOVERY_SOURCES`. Test de
  compatibilidad v3 → v4 sin pérdida de datos.
- **Configuración**: sección `[inference]` (`enabled` activo por defecto,
  `apps_file`) y `[ui].traffic_group` persistida.
- **TUI**: en Tráfico `g` cicla la agrupación, `w` la ventana y `Enter`
  abre «¿Quién lo usa?» (o Conexiones filtradas en proceso); en Conexiones
  columnas Prot./Equipo/Destino/App, `i` alterna nombres ⇄ IPs y `v` amplía el
  panel con rol, fuentes, JA4 y proceso; el detalle de equipo muestra identidad,
  top 5 de apps y destinos y clientes TLS; Config muestra inferencia, catálogo y
  fecha de las bases IP; Ayuda añade privacidad y atribución a DB-IP.
- Script de desarrollo `scripts/actualizar-bases-ip.sh` y `data/FUENTES.md`
  con origen, fecha y licencia de cada dato embebido.

### Cambiado

- La inferencia está **activa por defecto** (ADR-37): leer cabeceras DNS/TLS/
  HTTP/QUIC y los primeros bytes de cada conexión se controla con
  `[inference].enabled`; el payload nunca se persiste.
- `[scan].passive_only` pasa a significar «no consultar a nadie»: además de
  desactivar el descubrimiento activo, ya no hace consultas NetBIOS ni DNS
  inverso. El DNS inverso de IPs de Internet no se hace nunca.
- Las claves de la fase 3 `[capture].inspect_payload`, `dns_attribution` y
  `sni_attribution` se aceptan pero se ignoran con un aviso único.
- La captura de ARP, DHCP y tramas puede crear equipos (`DISCOVERY_SOURCES`
  con `capture`), ampliando la regla de «solo L2 crea equipos».

### Corregido

- El primer paquete de cada clave de un ranking ya no se pierde al crear la
  entrada.
- El rol cliente/servidor se usa para orientar la bajada y la subida de los
  rankings y para atribuir el User-Agent y el SNI al equipo correcto.
- Nombres de dominio, SNI, `Host` y User-Agent solo aparecen en logs de nivel
  `debug`.

## [0.3.0] — Fase 3

Tráfico en vivo con AF_PACKET + TPACKET_V3, agregación por dispositivo,
conexiones activas con proceso local, snapshot persistente y pestañas
Tráfico/Conexiones con detalle de equipo.

## [0.2.0] — Fase 2

Descubrimiento avanzado: mDNS, SSDP/UPnP, leases DHCP, NetBIOS, port scan,
banner grabbing, fingerprint de SO y clasificación automática de equipos.

## [0.1.0] — Fase 1

Descubrimiento ARP/ICMP, reverse DNS, fabricante por OUI, inventario SQLite,
histórico de eventos y TUI con detalle de equipo.
