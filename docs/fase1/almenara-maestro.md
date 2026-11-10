# Almenara - Informe Maestro

**Última actualización:** 2026-11-10

## 1. Visión Global

Almenara es una aplicación de terminal para Linux que monitoriza de forma permanente la red local a la que está conectado el equipo: descubre los dispositivos presentes, muestra una vista principal en forma de lista detallada con iconos ASCII por tipo de equipo, y permite profundizar en el tráfico, las conexiones, el histórico y las alertas de cada uno. El objetivo es doble: **detectar intrusos / equipos desconocidos** y **diagnosticar consumo de ancho de banda y problemas de red**, todo desde la propia terminal.

La aplicación está diseñada para uso personal doméstico/laboratorio, corre en una única máquina Linux con privilegios elevados disponibles (raw sockets y captura de paquetes) y funciona también en modo degradado sin ellos. La interfaz es una TUI con pestañas navegables: la vista principal de la pestaña Equipos es una lista detallada, y cada equipo tiene un detalle con su tráfico en vivo, sus conexiones activas y su histórico.

El proyecto se desarrolla en siete fases incrementales. La Fase 1 (esta entrega) es la fundación: shell de la TUI, configuración, persistencia SQLite y descubrimiento básico vía ARP + ICMP + reverse DNS + OUI. Las fases siguientes añaden descubrimiento avanzado, captura y agregación de tráfico, granularidad por protocolo/aplicación, histórico, alertas e integraciones.

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
│              │───►│                      │◄───│ (SQLite +    │
│ (F1, F2)     │    │  (F1, F3, F5, F6)    │    │  rollups)    │
└──────┬───────┘    └──────────▲───────────┘    └──────────────┘
       │                       │                       ▲
       │              ┌────────┴────────┐              │
       │              │  M2 Traffic     │              │
       └─────────────►│  (F3, F4)       │──────────────┘
                      └────────┬────────┘
                               │
                      ┌────────▼────────┐    ┌──────────────┐
                      │  M5 Alerts      │    │ M7 Integr.   │
                      │  (F6)           │    │ (F7)         │
                      └─────────────────┘    └──────────────┘
```

**Dependencias principales:**
- M4 depende de M3 (persistencia) y M1 (datos a mostrar).
- M2 (tráfico) alimenta M3 y M4; M5 (alertas) consume eventos de M3.
- M6 es transversal a todas.
- M7 (integraciones) se apoya en M2 y M1.

## 3. Tabla Resumen de Fases

| Fase | Módulo | Funcionalidades | Sprints | Semanas | Estado |
|------|--------|-----------------|---------|---------|--------|
| 1 | Fundación + descubrimiento básico | 67 | 5 | 3–4 | Especificada |
| 2 | Descubrimiento avanzado | ~14 | 2 | 2 | Pendiente de especificar |
| 3 | Tráfico en vivo (modo pasivo + local) | ~18 | 3–4 | 3–4 | Pendiente de especificar |
| 4 | Protocolos, apps y top talkers | ~12 | 2 | 2–3 | Pendiente de especificar |
| 5 | Histórico, rollups y eventos | ~10 | 2 | 2 | Pendiente de especificar |
| 6 | Alertas (locales + notificación escritorio) | ~9 | 1–2 | 1–2 | Pendiente de especificar |
| 7 | Integraciones y exportación | ~9 | 2 | 2 | Pendiente de especificar |
| **Total** | | **~139** | | **~14–18** | |

Nota: los recuentos de F2-F7 son estimaciones previas a su especificación; se recalibrarán al detallarlas.

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
                          ┌─────────┴──────────┐
                          │      DEVICES       │  (F1, ampliada F2)
                          ├────────────────────┤
                          │ id (PK)            │◄──────┐
                          │ mac (UNIQUE)       │       │
                          │ ip                 │       │
                          │ hostname           │       │
                          │ vendor             │       │
                          │ interface_id (FK)  │       │
                          │ device_type        │       │
                          │ is_online          │       │
                          │ first_seen         │       │
                          │ last_seen          │       │
                          │ alias              │       │
                          │ notes              │       │
                          └─────────┬──────────┘       │
                                    │ 1                │
                                    │                  │
                                    │ N                │
                          ┌─────────▼──────────┐       │
                          │   DEVICE_EVENTS    │  (F1) │
                          ├────────────────────┤       │
                          │ id (PK)            │       │
                          │ device_id (FK)     │───────┘
                          │ event_type         │
                          │ details            │
                          │ created_at         │
                          └────────────────────┘

  Tablas previstas en fases posteriores (no creadas en F1):

  · CONNECTIONS        (F3) — conexiones activas por dispositivo
  · TRAFFIC_BUCKETS    (F3) — contadores por IP/intervalo
  · TRAFFIC_ROLLUP_*   (F5) — agregados por minuto/hora/día
  · ALERTS             (F6) — alertas emitidas
  · ALERT_RULES        (F6) — reglas configurables
  · EXTERNAL_SOURCES   (F7) — integraciones (SNMP, replay)
```

## 5. Glosario de Dominio

| Término de negocio | Entidad/Tabla | Fase | Notas |
|--------------------|---------------|------|-------|
| Interfaz de red | `INTERFACES` | F1 | NIC del equipo monitor |
| Dispositivo / equipo | `DEVICES` | F1 | Equipo visto en la red |
| Evento de dispositivo | `DEVICE_EVENTS` | F1 | Cambio relevante (new, disappeared, ip_changed…) |
| Conexión | `CONNECTIONS` | F3 | Par (origen, destino) activo |
| Bucket de tráfico | `TRAFFIC_BUCKETS` | F3 | Contador agregado por intervalo |
| Rollup | `TRAFFIC_ROLLUP_*` | F5 | Agregado histórico por minuto/hora/día |
| Alerta | `ALERTS` | F6 | Instancia disparada por una regla |
| Regla de alerta | `ALERT_RULES` | F6 | Condición configurable |

## 6. Estado del Proyecto

- **Fase 1:** 0 / 67 funcionalidades — **especificada, sin informe de implementación procesado (sin confirmar)**.
- **Fases 2–7:** pendientes de especificar.
- **Progreso total:** 0 / 67 funcionalidades (solo F1 cuenta hasta que se implemente).
- **Fechas de informes de implementación procesados:**
  - Fase 1: —

**Regla:** el progreso solo se actualiza a partir de informes de implementación reales; no se infiere de la especificación.

## 7. Roadmap

| Fase | Nombre | Depende de |
|------|--------|------------|
| 1 | Fundación + descubrimiento básico | — |
| 2 | Descubrimiento avanzado | F1 |
| 3 | Tráfico en vivo (pasivo + local) | F1, F2 (idealmente) |
| 4 | Protocolos, apps y top talkers | F3 |
| 5 | Histórico y rollups | F3, F4 |
| 6 | Alertas (locales + escritorio) | F5 |
| 7 | Integraciones y exportación | F3 (captura), F1 |

**Dependencias que condicionan el orden:**
- F3 no se puede hacer sin F1 (persistencia y modelo de datos).
- F4, F5 y F6 son secuenciales entre sí; cada una asume la anterior.
- F7 (SNMP, ARP spoof opt-in, replay) puede solaparse con F4–F6 si se quiere, pero no bloquea.

**Sub-fase opcional (3.5):** modos intrusivos/integración con router (ARP spoof opt-in, SNMP, port mirror) si se prioriza el tráfico de terceros antes de F7.

## 8. Decisiones Transversales y Riesgos Abiertos

### Decisiones transversales
- **Lenguaje y stack:** Rust + tokio + ratatui + crossterm + rusqlite + pnet + ouidb. Aplicable a todas las fases.
- **Nomenclatura:** tablas `MAYUSCULAS_SNAKE_CASE`, campos `minusculas_snake_case`. Sin endpoints HTTP (TUI); "servicios internos" como interfaz análoga.
- **Modo degradado:** toda la app debe poder arrancar sin `CAP_NET_RAW` con aviso visible; la captura de paquetes (F3) y el ARP scan activo (F1) quedan limitados o desactivados.
- **Legalidad:** el software avisará cuando se active un modo intrusivo (ARP spoof) y exigirá confirmación explícita. Recomendación de uso solo en redes propias.
- **Visibilidad de tráfico de terceros:** en redes conmutadas solo es plenamente observable vía mirror/SNMP o ARP spoof. Modo pasivo por defecto en F3.
- **Distribución:** binario único, sin instalador. `cargo run` en fases iniciales.

### Riesgos abiertos
| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| Cambio de stack de pcap (pnet → libpcap) en F3 | Medio | ADR específico al iniciar F3 |
| Escalado de la TUI a >100 equipos con lista | Medio | Paginación/virtualización de la lista en F3 si es necesario |
| ARP spoof puede romper la red del usuario | Alto | Opt-in con advertencia + documentación clara; nunca por defecto |
| Base OUI embebida se queda obsoleta | Bajo | Actualización de versión del crate en releases periódicas |
| Modo degradado con `/proc/net/arp` vacía | Bajo | Documentar limitación; recomendar `sudo` o `setcap` |