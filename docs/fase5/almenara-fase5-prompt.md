# Prompt Almenara - Fase 5: Histórico, rollups y eventos

Continúa desarrollando **Almenara**, monitor TUI de la red local para Linux con descubrimiento (F1–F2), captura (F3) y etiquetado de apps y destinos (F4) ya implementados; la Fase 5 guarda el histórico. Stack: **Rust 2021 (MSRV 1.88), tokio, ratatui + crossterm, rusqlite bundled en WAL, libc/nix; sin dependencias nuevas**. Tablas (migración v5 aditiva, `auto_vacuum = INCREMENTAL`): (1) **TRAFFIC_ROLLUP_MINUTE**, **TRAFFIC_ROLLUP_HOUR** y **TRAFFIC_ROLLUP_DAY**, `WITHOUT ROWID`, con `bucket` (entero: segundos UTC; en días, fecha local AAAAMMDD), `subject`, `device_id`, `dimension`, `key`, `bytes_down`, `bytes_up`, `connections`; (2) **DEVICE_SEEN** con `device_id`, `kind`, `key`, `first_seen`, `last_seen`; (3) **APP_SESSIONS** con `started_at`, `ended_at`, `last_beat`, `end_reason`, `mode`, `capture`, `passive_only`, `version`; (4) **DEVICE_EVENTS** gana `reappeared`, `service_new`, `service_gone`, `os_changed` y `type_changed`. Funcionalidades: acumuladores por minuto en el agregador (sujetos equipo, host, otros y red; dimensiones total, app, categoría, destino, protocolo, proceso, organización y país; 20 claves + `~otros`), lote por minuto escrito por el hilo de la TUI (único escritor), horas y días consolidados, retención 48 h / 90 días / 2 años, destinos solo 2 h por minuto y 30 días por hora, sin registro de conexiones, purga con `incremental_vacuum`, sesiones con latido que marcan huecos, instancia única, eventos nuevos, presencia, inventario por equipo, lector con conexión de solo lectura e histórico sintético para medir. Interfaz: pestaña Histórico (sujeto con `e`, rango con `w`, gráfica con huecos y cursor `<` `>`, más tráfico, eventos con filtro), ventanas de 1 h y 24 h en Tráfico, detalle con tráfico y presencia de 24 h y 7 días e inventario, «Último evento» en Equipos y `[history]` en Config.

---

## Instrucciones para el agente

1. Lee primero `CLAUDE.md` en la raíz del repositorio: contiene las reglas
   permanentes de trabajo (idioma, commits, effort, cierre de fase). Está
   actualizado con las reglas de F4 y F5.
2. Sigue el checklist `almenara-fase5-checklist.md` como definición
   del alcance. No añadas funcionalidades fuera de él sin indicarlo.
   La especificación completa está en `almenara-fase5-informe.md`. Las 9
   casillas abiertas de F4 (pasada con `CAP_NET_RAW`) no son de esta fase:
   el desarrollador decidió dejarlas pendientes.
3. Al finalizar el desarrollo o al pausar la sesión, marca el checklist y
   genera/actualiza el archivo **`almenara-fase5-implementacion.md`**
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
   (README y Ayuda), sube la versión a 0.5.0 y redacta sus novedades en
   `CHANGELOG.md`.
