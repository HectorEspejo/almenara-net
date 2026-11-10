# Prompt Almenara - Fase 1: Fundación y descubrimiento básico

Desarrolla la **Fase 1** de **Almenara**, un monitor de red en TUI para Linux que descubre los equipos de la red local y los muestra en una lista detallada persistente. Stack: **Rust** (edition 2021) con **tokio**, **ratatui + crossterm**, **clap**, **serde + toml**, **rusqlite (bundled)**, **pnet**, **ouidb**, **tracing** + **tracing-subscriber** + **tracing-appender**. Tablas: (1) **INTERFACES** con id, name (unique), mac, ipv4, netmask, gateway, is_up, last_seen; (2) **DEVICES** con id, mac (unique), ip, hostname (null), vendor (null), interface_id (FK), device_type (default 'unknown'), is_online, first_seen, last_seen, alias (null), notes (null); (3) **DEVICE_EVENTS** con id, device_id (FK), event_type, details (JSON), created_at. Funcionalidades: detección de interfaces vía pnet, ARP scan y ping sweep ICMP sobre rango configurable, lectura pasiva de `/proc/net/arp`, reverse DNS con timeout, lookup de fabricante por OUI con base embebida, merge determinista de resultados por MAC, marcado online/offline tras N ciclos sin respuesta, emisión de eventos `new`/`disappeared`/`ip_changed`/`mac_changed`/`hostname_changed`, alias y notas por dispositivo, persistencia SQLite con migraciones versionadas y retención de eventos configurable, modo degradado con aviso visible si falta `CAP_NET_RAW`. Interfaz: TUI con pestañas **Equipos · Tráfico · Conexiones · Histórico · Alertas · Config · Ayuda** (las cuatro centrales son placeholders "no disponible en F1"); vista principal de lista detallada con columnas icono, IP, hostname, MAC/fabricante, tráfico (vacío en F1) y estado; iconos `[⌂]` gateway, `[?]` resto, `○` offline; navegación `hjkl`+flechas, `Tab`/`Shift-Tab`, `1-7`, búsqueda `/`, ordenar `s`, filtrar `f`, rescan `r`, ayuda `?`, salir `q`; barra de estado con resumen y modo; notificaciones no bloqueantes (buffer de 50); modal bloqueante solo si la BD falla al arrancar. Config TOML en `~/.config/almenara/config.toml`, BD en `~/.local/share/almenara/data.db`, logs en `~/.local/state/almenara/log/` con rotación por tamaño y flags `-v/-vv`. Paleta 256 colores con respeto a `NO_COLOR=1`; tamaño mínimo 80×24 con mensaje claro por debajo.

---

## Instrucciones para el agente

1. Lee primero `CLAUDE.md` en la raíz del repositorio: contiene las reglas permanentes de trabajo (idioma, commits, effort, cierre de fase).
2. Sigue el checklist `almenara-fase1-checklist.md` como definición del alcance. No añadas funcionalidades fuera de él sin indicarlo.
3. Al finalizar el desarrollo o al pausar la sesión, marca el checklist y genera/actualiza el archivo **`almenara-fase1-implementacion.md`** (informe de implementación) con exactamente esta estructura:
   - Resumen de lo implementado
   - Desviaciones respecto a la especificación (qué y por qué)
   - Estructura de archivos creada/modificada
   - Decisiones técnicas tomadas durante el desarrollo
   - Funcionalidades del checklist completadas (copiando su texto exacto)
   - Pendientes y bloqueos
   - Ejecución y pruebas (cómo arrancar, migrar y testear)
4. Actualiza el informe de implementación en cada sesión, no lo regeneres desde cero.
5. Cuando el informe esté listo, avisa al desarrollador de que debe entregárselo al analista funcional: hasta entonces la documentación de proyecto (checklist maestro, informe maestro) no refleja la realidad.