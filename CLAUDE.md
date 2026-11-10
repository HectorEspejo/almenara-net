# CLAUDE.md — Almenara

## Contexto

Almenara es un monitor de red en TUI para Linux que descubre los equipos de la red local y muestra su tráfico, conexiones e histórico. Cliente: uso personal del desarrollador.
Stack: Rust (edition 2021), tokio, ratatui + crossterm, clap, serde + toml, rusqlite (bundled), pnet, ouidb, tracing.

## Documentación del proyecto

La documentación funcional vive en `docs/`:

- `almenara-maestro.md` — visión global, mapa de fases y estado del proyecto
- `almenara-fase1-informe.md` — especificación funcional completa de la fase
- `almenara-fase1-checklist.md` — alcance verificable de la fase
- `almenara-fase1-implementacion.md` — informe de implementación (lo escribes tú)

El informe de fase manda sobre tu criterio: si algo te parece incorrecto o incompleto, no lo cambies por tu cuenta — impleméntalo como está o párate y coméntalo con el desarrollador.

## Reglas de trabajo

- Escribe siempre en castellano: respuestas, comentarios de código, mensajes de commit, documentación y textos de interfaz. Solo se mantienen en inglés los términos técnicos estándar (API, CRUD, endpoint, commit...).
- No añadas funcionalidades que no estén en el checklist de la fase. Si detectas algo necesario que falta, propónlo antes de implementarlo y déjalo anotado como desviación.
- Nomenclatura: tablas SQL en `MAYUSCULAS_SNAKE_CASE`, campos en `minusculas_snake_case`. Como Almenara es TUI (sin API HTTP), los "servicios internos" siguen el patrón `Módulo::función_snake_case`.
- Gestor de dependencias: `cargo`. Comando de arranque: `cargo run`. Tests: `cargo test`. Formato: `cargo fmt`. Lints: `cargo clippy -- -D warnings`.
- SQLite con migraciones versionadas en `src/repo/migrations.rs`. Cada migración es idempotente y se aplica en orden.
- Config del usuario: `~/.config/almenara/config.toml`. BD: `~/.local/share/almenara/data.db`. Logs: `~/.local/state/almenara/log/`.
- Modo degradado obligatorio: la app debe arrancar sin `CAP_NET_RAW` mostrando aviso visible en la barra de estado. Nunca asumas privilegios.
- Paleta 256 colores con respeto a `NO_COLOR=1`. Contraste mínimo 4.5:1.
- Todo output al usuario en castellano, incluidos los textos de la TUI.

## Al terminar una fase (o al pausar la sesión)

1. Busca el archivo markdown que tenga `checklist` en el nombre correspondiente a esa fase y marca `[x]` todo lo que se haya realizado. Actualiza los contadores de progreso del final del archivo. No reescribas el texto de las funcionalidades: es la clave de trazabilidad con el resto de documentos.
2. Genera o actualiza `almenara-fase1-implementacion.md` con exactamente esta estructura:
   - Resumen de lo implementado
   - Desviaciones respecto a la especificación (qué y por qué)
   - Estructura de archivos creada/modificada
   - Decisiones técnicas tomadas durante el desarrollo
   - Funcionalidades del checklist completadas (copiando su texto exacto)
   - Pendientes y bloqueos
   - Ejecución y pruebas (cómo arrancar, migrar y testear)

   Es un documento vivo: actualízalo de forma incremental en cada sesión, nunca lo regeneres desde cero. Sé honesto en las desviaciones y en los pendientes; ese informe es lo único que el analista funcional verá de lo que realmente pasó, y con él se actualiza la especificación.
3. Recuérdale al desarrollador que debe entregar el informe de implementación al analista funcional antes de especificar la siguiente fase.
4. Invita al desarrollador a hacer PR. Si te dice que lo hagas, usa el comando `gh`.

## Commits

- NUNCA firmes ni te atribuyas los commits: la autoría es del usuario.
- Sin `Co-Authored-By`, sin líneas de "Generated with", sin menciones a Claude en el mensaje.
- Mensajes en castellano, en imperativo y concisos.