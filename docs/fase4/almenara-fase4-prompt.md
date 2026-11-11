# Prompt Almenara - Fase 4: Protocolos, apps y top talkers

Continúa desarrollando **Almenara**, monitor TUI de la red local para Linux con descubrimiento (F1–F2) y captura en vivo (F3) ya implementados; la Fase 4 pone nombre al tráfico. Stack: **Rust 2021 (MSRV 1.88), tokio, ratatui + crossterm, rusqlite bundled, captura AF_PACKET + TPACKET_V3 propia, `hickory-proto`; nuevos: RustCrypto (`aes-gcm`, `aes`, `hkdf`, `sha2`), `psl` y `maxminddb` con DB-IP Lite de ASN y país embebidas (CC BY 4.0)**. Tablas (migración v4 aditiva): (1) **CONNECTIONS** + `client_is_src`, `app_protocol`, `server_name`, `name_source`, `app`, `category`, `app_source`, `ja4`; (2) **DEVICES** + `model`, `dhcp_fingerprint`, `dhcp_vendor`, `dhcp_hostname`, `user_agent`, `os_source`; (3) **NAME_CACHE** nueva con `ip`, `name`, `source`, `first_seen`, `last_seen`, `expires_at`; (4) **DISCOVERY_SOURCES** admite `capture`. Funcionalidades: sprint 4.0 de verificación pendiente con `CAP_NET_RAW`, rol cliente/servidor, reensamblado del inicio de flujo (4 KB), firmas de ~30 protocolos, SNI de TLS y de QUIC (descifrando el Initial), Host y User-Agent HTTP, JA4, caché IP→nombre desde respuestas DNS, SNI y Host, catálogo embebido de 162 apps en 12 categorías más `apps.toml`, dominio registrable, organización y país sin red, etiquetas que solo suben de fuerza, rankings por destino, app, categoría, protocolo y proceso (ventanas 60 s, 5 min y sesión, % sin identificar), identificación de equipos (huella DHCP, modelo mDNS/UPnP, User-Agent, MAC privada, `mac_changed` v2), captura (ARP, DHCP, tramas) como fuente L2 que crea equipos, `passive_only` sin NetBIOS ni DNS inverso, nunca PTR de IPs de Internet, inferencia activa por defecto (`[inference].enabled`) sin persistir payload ni registrar dominios por encima de `debug`. Interfaz: en Tráfico, `g` agrupa, `w` cambia la ventana y `Enter` abre «¿Quién lo usa?»; Conexiones con Prot./Equipo/Destino/App e `i` para nombres ⇄ IPs; detalle con identidad y top apps y destinos; Ayuda con privacidad y atribución a DB-IP.

---

## Instrucciones para el agente

1. Lee primero `CLAUDE.md` en la raíz del repositorio: contiene las reglas
   permanentes de trabajo (idioma, commits, effort, cierre de fase).
2. Sigue el checklist `almenara-fase4-checklist.md` como definición
   del alcance. No añadas funcionalidades fuera de él sin indicarlo.
   Empieza por el sprint 4.0 (verificación pendiente de F1–F3); la
   especificación completa está en `almenara-fase4-informe.md`.
3. Al finalizar el desarrollo o al pausar la sesión, marca el checklist y
   genera/actualiza el archivo **`almenara-fase4-implementacion.md`**
   (informe de implementación) con exactamente esta estructura:
   - Resumen de lo implementado
   - Desviaciones respecto a la especificación (qué y por qué)
   - Estructura de archivos creada/modificada
   - Decisiones técnicas tomadas durante el desarrollo
   - Funcionalidades del checklist completadas (copiando su texto exacto)
   - Pendientes y bloqueos
   - Ejecución y pruebas (cómo arrancar, migrar y testear)
4. Actualiza el informe de implementación en cada sesión, no lo
   regeneres desde cero.
5. Cuando el informe esté listo, avisa al desarrollador de que debe
   entregárselo al analista funcional: hasta entonces la documentación de
   proyecto (checklist maestro, informe maestro) no refleja la realidad.
6. Al cerrar la fase, añade la documentación de usuario de lo nuevo
   (README y Ayuda), sube la versión a 0.4.0 y redacta sus novedades en
   `CHANGELOG.md`.
