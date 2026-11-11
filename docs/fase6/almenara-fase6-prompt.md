# Prompt Almenara - Fase 6: Alertas (locales + escritorio)

Continúa desarrollando **Almenara**, monitor TUI de la red local para Linux con descubrimiento (F1–F2), captura (F3), apps y destinos (F4) e histórico (F5) ya implementados; la Fase 6 añade las alertas. Empieza por el sprint 6.0: con la capacidad que aplica el desarrollador, cierra sin recompilar las 9 casillas abiertas de F4 y prueba F5 con tráfico real. Stack: **Rust 2021 (MSRV 1.88), tokio, ratatui + crossterm, rusqlite bundled en WAL, libc/nix y, nuevo, `notify-rust` 4.17 (zbus 5, Rust puro)**. Tablas (migración v6 aditiva): (1) **ALERTS** con `rule`, `level`, `subject`, `device_id`, `key`, `title`, `subject_label`, `details`, `created_at`, `last_at`, `count`, `seen_at`, `resolved_at`, `notified`; (2) **ALERT_MUTES** con `rule`, `subject`, `device_id`, `until`; (3) **ALERT_LEARNING** con `subject`, `device_id`, `learning_from`, `data_days`, `learned_at`; (4) **HOST_SEEN**, inventario del propio equipo; (5) **COVERAGE_GAPS** con `session_id`, `kind` (suspend o capture), `started_at`, `ended_at`; columnas `DEVICES.watched` y `DEVICE_SERVICES.closed_at`, rellenada desde el último evento de servicio. Funcionalidades: motor puro de señales a acciones aplicado por el hilo de la TUI (único escritor); catálogo fijo de 16 reglas (equipo y puerto nuevos, cambios de MAC, nombre, SO y tipo, app, categoría, país, organización y JA4 nuevos, más tráfico de lo habitual por mediana de 14 días, vigilados, captura parada, pérdidas y base de datos grande); tres niveles (solo importante notifica; MAC privada baja uno); aprendizaje de 7 días con datos; línea base; deduplicación de 24 h; silencios; puesta al día de 10 minutos con resumen; horario silencioso; tope de 3 notificaciones por minuto; huecos por suspensión y captura parada en toda cobertura; retención de 90 días. Interfaz: pestaña Alertas (lista con detalle, Reglas y Silencios), «Alertas N» en la barra, `*` y `!` en Equipos con `p` para vigilar, bloque Alertas en el detalle y `[alerts]` en Config.

---

## Instrucciones para el agente

1. Lee primero `CLAUDE.md` en la raíz del repositorio: contiene las reglas
   permanentes de trabajo (idioma, commits, effort, cierre de fase). Está
   actualizado con las reglas de F6.
2. Sigue el checklist `almenara-fase6-checklist.md` como definición
   del alcance. No añadas funcionalidades fuera de él sin indicarlo.
   La especificación completa está en `almenara-fase6-informe.md`.
3. Empieza por el sprint 6.0. Pide al desarrollador que ejecute
   `scripts/ejecutar-con-permisos.sh` (tú no tienes `sudo`), mide sin
   recompilar y marca las 9 casillas abiertas en
   `docs/fase4/almenara-fase4-checklist.md`, o anota por qué no pasan.
   Después, para probar F6 con captura real, pídele que vuelva a aplicar la
   capacidad tras compilar.
4. Declara `notify-rust` 4.17 sin sus funciones por defecto y con `z`. Si
   una dependencia transitiva pide un Rust mayor que 1.88, fíjala a una
   versión compatible y anótalo como desviación; no subas la MSRV sin
   hablarlo con el desarrollador.
5. Al finalizar el desarrollo o al pausar la sesión, marca el checklist y
   genera/actualiza el archivo **`almenara-fase6-implementacion.md`**
   (informe de implementación) con exactamente esta estructura:
   - Resumen de lo implementado
   - Desviaciones respecto a la especificación (qué y por qué)
   - Estructura de archivos creada/modificada
   - Decisiones técnicas tomadas durante el desarrollo
   - Funcionalidades del checklist completadas (copiando su texto exacto)
   - Pendientes y bloqueos
   - Ejecución y pruebas (cómo arrancar, migrar y testear)
6. Actualiza el informe de implementación en cada sesión, no lo
   regeneres desde cero.
7. Cuando el informe esté listo, avisa al desarrollador de que debe
   entregárselo al analista funcional: hasta entonces la documentación de
   proyecto (checklist maestro, informe maestro) no refleja la realidad.
8. Al cerrar la fase, añade la documentación de usuario de lo nuevo
   (README y Ayuda), sube la versión a 0.6.0 y redacta sus novedades en
   `CHANGELOG.md`.
