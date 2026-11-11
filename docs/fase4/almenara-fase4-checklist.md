# Almenara - Checklist Fase 4: Protocolos, apps y top talkers

## Verificación pendiente de F1–F3 (sprint 4.0)
- [x] Pasada manual de F1-24 y F1-25 con `CAP_NET_RAW` anotada en el informe de implementación
  - AC: Dado el binario con la capacidad aplicada, cuando se ejecuta un ciclo completo en la red real, entonces el informe anota fecha, resultado y desviaciones de F1-24 y F1-25
- [x] Medición de rendimiento de F1-64 anotada en el informe de implementación
- [x] Mediciones del §8 de F2 (ciclo completo y port scan) anotadas en el informe de implementación
- [x] Mediciones del §8 de F3 (pps, CPU y render) anotadas en el informe de implementación
- [x] Prueba visual de F3 en `wlp191s0` con el binario recompilado anotada en el informe de implementación

## Migración y modelo de datos
- [x] Migración v4 aditiva registrada en `SCHEMA_MIGRATIONS` e idempotente
  - AC: Dada una BD ya en v4, cuando la aplicación arranca otra vez, entonces ningún `ALTER TABLE` se reaplica ni falla
- [x] Columnas de rol y etiquetas en `CONNECTIONS` (`client_is_src`, `app_protocol`, `server_name`, `name_source`, `app`, `category`, `app_source`, `ja4`)
- [x] Columnas de identidad en `DEVICES` (`model`, `dhcp_fingerprint`, `dhcp_vendor`, `dhcp_hostname`, `user_agent`, `os_source`)
- [x] Tabla `NAME_CACHE` con `UNIQUE (ip, name)` e índices `IDX_NAME_CACHE_IP` e `IDX_NAME_CACHE_EXPIRES`
- [x] Índice `IDX_CONN_APP` sobre `CONNECTIONS(app)`
- [x] Valor `capture` admitido en `DISCOVERY_SOURCES.source`
- [x] Test de compatibilidad v3 → v4 sin pérdida de datos
  - AC: Dada una BD de F3 con equipos, servicios, snapshots y conexiones, cuando se abre con F4, entonces todas las filas se conservan y las columnas nuevas quedan en NULL

## Configuración
- [x] Sección `[inference]` con `enabled = true` por defecto y `apps_file` opcional
- [x] Claves `inspect_payload`, `dns_attribution` y `sni_attribution` ignoradas con un aviso único
  - AC: Dado un `config.toml` de F3 con esas claves, cuando arranca F4, entonces se avisa una sola vez y la inferencia sigue el valor de `[inference].enabled`
- [x] Preferencia `[ui].traffic_group` guardada al cambiar la agrupación con `g` en Tráfico
- [x] Plantilla de configuración por defecto con `[inference]` y `[ui].traffic_group`
- [x] Valores inválidos de `[inference]` y `[ui].traffic_group` avisan y usan el valor por defecto sin abortar

## Rol cliente/servidor
- [x] Rol deducido del SYN sin ACK en TCP
- [x] Rol deducido de los sockets en escucha de `/proc`, de los puertos de servicio y del primer datagrama UDP cuando no se vio el inicio
  - AC: Dada una conexión TCP ya establecida al arrancar, cuando el host tiene el puerto local en LISTEN, entonces el host figura como servidor
- [x] `client_is_src` queda en NULL cuando el rol no se puede deducir

## Reensamblado y firmas de protocolo
- [x] Reensamblado del inicio de cada flujo TCP: 4 KB cliente → servidor y 64 B servidor → cliente
  - AC: Dado un ClientHello partido en dos segmentos que llegan desordenados, cuando llegan ambos, entonces se extrae el SNI
- [x] Buffers de reensamblado liberados al completar el mensaje, a los 4 KB, a los 8 paquetes o a los 3 s
- [x] Tope de 1024 reensamblados simultáneos por interfaz con contador `reassembly_drops`
- [x] Identificación del protocolo de aplicación por firma y puerto con los valores de la tabla del §7.3
  - AC: Dado el fixture de cada fila de la tabla, cuando se procesa, entonces `app_protocol` coincide; un SSH en el puerto 443 sale como `ssh`
- [x] Contador `inference_errors` para entradas mal formadas sin detener la captura

## TLS, HTTP y JA4
- [x] Parser del ClientHello TLS con SNI normalizado, ALPN, versiones, cifrados, extensiones y algoritmos de firma
- [x] Extracción de `Host` y `User-Agent` de peticiones HTTP/1.x en claro
- [x] Huella JA4 de cliente TLS (`t…`) según la especificación pública
  - AC: Dados los vectores de prueba oficiales de JA4, cuando se calcula la huella, entonces coincide carácter a carácter

## QUIC
- [x] Detección de paquetes Initial de QUIC v1 y v2
- [x] Derivación de claves Initial, retirada de la protección de cabecera y descifrado AEAD
  - AC: Dado el Initial de cliente del apéndice A de RFC 9001, cuando se descifra, entonces el payload y el ClientHello coinciden con los del RFC
- [x] Recomposición del ClientHello a partir de tramas CRYPTO repartidas en varios Initial
- [x] SNI y JA4 (`q…`) de conexiones QUIC
- [x] Initial de versión desconocida o que no se puede descifrar descartado sin error visible y con contador

## DNS y caché de nombres
- [x] Respuestas DNS A, AAAA y CNAME convertidas en IP → nombre consultado con `hickory-proto`
  - AC: Dada una respuesta con cadena CNAME, cuando se procesa, entonces la IP final queda asociada al nombre que se consultó
- [x] Caducidad de la caché entre 1 h y 24 h con refresco por uso
- [x] Tope de 10 000 entradas con desalojo por `last_seen` más antiguo
- [x] SNI y `Host` también alimentan la caché de nombres
- [x] Preferencia por el nombre consultado por el mismo equipo cuando una IP tiene varios nombres
- [x] Persistencia de la caché en `NAME_CACHE` cada 5 s y carga de las entradas vigentes al arrancar
- [x] Purga de entradas caducadas de `NAME_CACHE` en el ciclo de 5 s

## Catálogo de apps y categorías
- [x] Catálogo embebido `data/catalogo.toml` con las 12 categorías y la categoría especial `lan`
- [x] Todas las apps de la lista mínima del §7.9 (162) presentes en el catálogo
- [x] Reglas por sufijo de dominio con prioridad del sufijo más largo
  - AC: Dado `music.youtube.com`, cuando se busca en el catálogo, entonces devuelve YouTube Music y no YouTube
- [x] Reglas por ASN y por puerto
- [x] Comentario de origen en cada app del catálogo embebido
- [x] Categoría `tracking` (publicidad, rastreo y telemetría) con lista propia
- [x] Fichero `apps.toml` del usuario que añade apps o sustituye las embebidas
  - AC: Dado un `apps.toml` con una app de clave existente y otra inválida, cuando arranca, entonces la primera sustituye a la embebida y la segunda se avisa y se ignora sin afectar al resto

## Destinos: dominio registrable y base IP
- [x] Dominio registrable con la Public Suffix List embebida
  - AC: Dado `rr3---sn-x.googlevideo.com`, cuando se calcula la clave de destino, entonces es `googlevideo.com`
- [x] Bases DB-IP Lite de ASN y país embebidas para IPv4 e IPv6
- [x] Organización y país sin acceso a red y omitidos para IPs privadas, de enlace local, de loopback y multicast
- [x] Script `scripts/actualizar-bases-ip.sh` que sustituye las MMDB y actualiza `data/FUENTES.md`
- [x] Atribución a DB-IP en Ayuda, README y `data/FUENTES.md`

## Resolución de etiquetas
- [x] Nombre del servidor por precedencia SNI > Host > caché de nombres
- [x] App por precedencia dominio > servicio de F2 > ASN > puerto, con `app_source`
  - AC: Dado un flujo QUIC sin SNI legible hacia una IP con nombre en caché `rr3---sn-x.googlevideo.com`, cuando se resuelve, entonces `app = youtube`, `app_source = domain` y `name_source = cache`
- [x] La etiqueta de un flujo solo cambia a una evidencia más fuerte
  - AC: Dado un flujo etiquetado por SNI, cuando llega después una evidencia de puerto, entonces la etiqueta no cambia
- [x] Con `[inference].enabled = false` solo hay etiquetas por servicio de F2, ASN, puerto y proceso
- [x] Rol, etiquetas y JA4 persistidos en `CONNECTIONS` en el ciclo de 5 s

## Identificación de equipos
- [x] Huella DHCP (opciones 55 y 60) y nombre (opción 12) de los paquetes DHCP capturados
- [x] Reglas propias de huella DHCP para Windows, Apple, Android, Linux e IoT, cada una con origen y prueba
- [x] Modelo desde los TXT de mDNS (`model`, `am`, `md`, `ty`, `rpMd`) y desde la descripción UPnP
- [x] Pistas de SO y de tipo desde el User-Agent de HTTP en claro
- [x] `os_family` combina huella TCP de F2, DHCP, modelo y User-Agent con umbral 4 y registra `os_source`
  - AC: Dado un Mac que anuncia `model=MacBookPro…` por mDNS, cuando se clasifica, entonces `os_family = macos` y `os_source = model`
- [x] Reglas de `device_type` por modelo y User-Agent antes que las de hostname
- [x] Nombre DHCP capturado y nombre de Google Cast (`fn`) en la precedencia de hostname
- [x] Campos de identidad persistidos en `DEVICES`

## MAC privadas y mac_changed v2
- [x] MAC privada detectada por el bit U/L y mostrada como «MAC privada» en la columna Fabricante
- [x] Evento `new` con `mac_random` en sus detalles
- [x] `mac_changed` por rotación de MAC privada con la misma huella y el mismo nombre DHCP
  - AC: Dado un móvil con MAC privada no visto en el ciclo, cuando aparece otra MAC privada con su misma huella y nombre DHCP, entonces se emite `mac_changed` con `reason = rotation` y se conserva el equipo
- [x] Sin fusión de identidad cuando hay varios candidatos de rotación
- [x] Heurística de toma de IP de F1 sin aplicar si las huellas DHCP se contradicen, y con `reason = ip_takeover` cuando se aplica

## Captura como fuente de equipos
- [x] Equipos observados en ARP, DHCP y tramas IPv4 con MAC e IP de una subred local
- [x] Filtros de equipos observados: MAC propia o de grupo, IP 0.0.0.0, broadcast o propia, IP fuera de subred y MAC del gateway con otra IP
- [x] Buffer `ObservedHosts` con deduplicación por MAC + IP y tope de 4096
- [x] Alta de equipos con fuente `capture` y evento `new`
  - AC: Dado un ARP de un equipo que el escaneo no ha visto, cuando termina el ciclo, entonces aparece en Equipos con la fuente `capture` y un evento `new`
- [x] Las observaciones de la captura cuentan como «visto» en el marcado offline

## Modo pasivo
- [x] `passive_only` desactiva las consultas NetBIOS
- [x] `passive_only` desactiva el DNS inverso
  - AC: Dado `passive_only = true`, cuando pasan 10 ciclos, entonces el log no registra ninguna consulta NetBIOS ni DNS inversa
- [x] Nunca se hace DNS inverso de IPs de Internet, en ningún modo
- [x] Barra de estado y Ayuda con las fuentes del modo pasivo actualizadas (sin NetBIOS, con captura)

## Rankings
- [x] Rankings por destino, app, categoría, protocolo y proceso local además del de equipo
- [x] Clave de destino: dominio registrable, IP remota o equipo de la LAN
- [x] Ventanas de 60 s y 5 min y acumulado de sesión por clave
- [x] Bajada y subida según el rol cliente/servidor
- [x] Equipos distintos y conexiones activas por clave
- [x] Tope de 2048 claves por dimensión con desalojo de las inactivas
- [x] Porcentaje de tráfico sin identificar por ventana
- [x] Ranking de procesos solo con tráfico del propio equipo
- [x] Publicación del top 50 por dimensión y ventana en `AppEvent::Traffic` y consulta `TrafficCommand::WhoUses`

## TUI: Tráfico
- [x] Tecla `g` en Tráfico: equipo → destino → app → categoría → protocolo → proceso
- [x] Tecla `w` en Tráfico: ventana 60 s → 5 min → sesión
- [x] Columnas de cada agrupación según las notas de UX del §6
- [x] Panel «¿Quién lo usa?» con `Enter` sobre destino, app, categoría o protocolo
  - AC: Dado el ranking por app, cuando se pulsa Enter sobre YouTube, entonces se listan los equipos que la usan con sus bytes, Enter sobre uno abre su detalle y Esc cierra el panel
- [x] `Enter` sobre un proceso abre Conexiones filtrada por ese proceso
- [x] Pie con «Sin identificar: N %» y la línea de visibilidad de F3
- [x] Indicador «inferencia: activa / desactivada» en la barra de estado
- [x] Mensaje claro cuando no hay datos en la ventana

## TUI: Conexiones
- [x] Columnas Prot., Equipo, Destino, App, ↑, ↓ y Edad a 80 columnas; Estado desde 100 columnas
- [x] Destino con el nombre del servidor si existe y la IP con organización y país si no
- [x] Filas sin rol en orden canónico con `?` delante del destino
- [x] Tecla `i` para alternar nombres e IPs
- [x] Panel `v` con rol, fuentes del nombre y de la app, JA4 y proceso local
- [x] Búsqueda `/` también por nombre del servidor, app y proceso

## TUI: Detalle, Config y Ayuda
- [x] Detalle de equipo con modelo, SO y su fuente, huella DHCP abreviada y MAC privada
- [x] Top 5 apps y top 5 destinos del equipo en el detalle (ventana de 5 min)
- [x] Clientes TLS distintos (JA4) en el detalle
- [x] Desplazamiento del panel de detalle cuando no cabe
- [x] Config muestra `[inference]`, estadísticas del catálogo y fecha de las bases IP
- [x] Ayuda con las teclas nuevas (`g` y `w` en Tráfico, `i` y `v` en Conexiones, `Enter` en rankings)
- [x] Ayuda con el aviso de privacidad de la inferencia y cómo desactivarla
- [x] Ayuda con el modo pasivo redefinido y la atribución de DB-IP y de la Public Suffix List

## Privacidad
- [x] Ningún payload se persiste; solo etiquetas derivadas
- [x] Buffers de reensamblado y payload QUIC descifrado liberados en el hilo de captura tras extraer la etiqueta
- [x] Dominios, SNI, `Host` y User-Agent solo en logs de nivel `debug`
  - AC: Dado `-v`, cuando se navega durante 5 min, entonces el fichero de log no contiene ningún nombre de dominio
- [x] User-Agent y campos DHCP saneados y truncados antes de persistir

## Rendimiento y robustez
- [x] Captura sostenida de 50 K pps sin pérdidas con la inferencia activa (medido)
- [x] CPU ≤ 20 % a 10 K pps y ≤ 7 % a 1 K pps con la inferencia activa (medido)
- [x] Parsers sin pánicos ante entradas truncadas o aleatorias
- [x] Memoria añadida por la fase ≤ 64 MB con los topes del §8 (medido)
- [x] Carga del catálogo y de las bases IP ≤ 200 ms al arrancar
- [x] Binario con ≤ 25 MB más por los datos embebidos

## Pruebas
- [x] Tests unitarios de firmas, TLS, HTTP, DNS, JA4 y QUIC con fixtures
- [x] Tests del catálogo (precedencia, sufijo más largo, `apps.toml`) y del dominio registrable
- [x] Tests de identificación (DHCP, modelo, User-Agent, MAC privada, `mac_changed` v2)
- [x] Tests de rankings y del porcentaje sin identificar
- [x] Replays pcap de tráfico mixto (TLS partido, QUIC, DNS, DHCP, ARP) con etiquetas esperadas
- [x] `cargo fmt --check` y `cargo clippy --all-targets -- -D warnings` limpios

## Documentación y versión
- [x] README actualizado: inferencia, privacidad, bases IP y cómo actualizarlas
- [x] `data/FUENTES.md` con origen, fecha y licencia de cada dato embebido
- [x] Versión 0.4.0 en `Cargo.toml` y en Ayuda
- [x] Novedades de la 0.4.0 en `CHANGELOG.md`

## Servicios internos (API)
- [x] `FlowInspector::new` — estado de inspección por interfaz
- [x] `FlowInspector::inspect` — firmas, reensamblado y extractores
- [x] `LabelResolver::resolve` — nombre, app, categoría y fuentes
- [x] `LabelResolver::observe_name` — alimenta la caché de nombres
- [x] `StreamStart::push` — inicio de flujo TCP
- [x] `CryptoStream::push` — tramas CRYPTO de QUIC
- [x] `Protocols::identify` — firma o puerto
- [x] `Tls::parse_client_hello` — ClientHello TLS
- [x] `Http::parse_request` — Host y User-Agent
- [x] `Dns::extract_query` — QNAME de una consulta
- [x] `Dns::extract_answers` — IP → nombre consultado
- [x] `Quic::initial_version` — Initial de QUIC v1 o v2
- [x] `Quic::decrypt_initial` — claves, protección de cabecera y AEAD
- [x] `Ja4::compute` — huella t… o q…
- [x] `NameCache::observe` — inserta o refresca una entrada
- [x] `NameCache::lookup` — mejor nombre vigente para una IP
- [x] `Catalog::load` — catálogo embebido + apps.toml
- [x] `Catalog::match_name` — sufijo de dominio más largo
- [x] `Catalog::match_asn` — regla por ASN
- [x] `Catalog::match_port` — regla por puerto
- [x] `Catalog::lan_app` — app de red local para un servicio de F2
- [x] `Domain::registrable` — eTLD+1
- [x] `IpDb::embedded` — abre las MMDB embebidas
- [x] `IpDb::lookup` — ASN, organización y país
- [x] `Role::infer` — client_is_src
- [x] `Dhcp::parse` — paquete DHCP capturado
- [x] `Models::from_mdns_txt` — modelo por TXT de mDNS
- [x] `Models::from_upnp` — modelo por descripción UPnP
- [x] `UserAgent::hints` — pistas de SO y tipo
- [x] `Identify::os_family` — puntuación combinada de SO
- [x] `Mac::is_private` — bit U/L
- [x] `Mac::rotation_match` — regla de rotación
- [x] `ObservedHosts::push` — equipo observado desde la captura
- [x] `ObservedHosts::drain` — vaciado desde el ciclo de escaneo
- [x] `Rankings::record` — suma a cada dimensión
- [x] `Rankings::tick` — ventanas y desalojo
- [x] `Rankings::top` — filas de un ranking
- [x] `Rankings::who_uses` — panel «¿Quién lo usa?»
- [x] `Rankings::unidentified_share` — % sin identificar
- [x] `Repo::upsert_connection` — (extendido) rol, etiquetas y JA4
- [x] `Repo::upsert_names` — caché de nombres
- [x] `Repo::list_names` — arranque en caliente
- [x] `Repo::prune_names` — purga de caducadas
- [x] `Repo::set_device_identity` — campos de identidad del equipo
- [x] `config::load` — (extendido) [inference], [ui].traffic_group y claves obsoletas

---

**Progreso Fase 4:** 175 / 175 funcionalidades

**Total Almenara (Fases 1-4):** 423 / 423 funcionalidades (F1–F3 implementadas y verificadas: 248)