## D) `almenara-maestro.md` — actualización (solo secciones modificadas)

**Cabecera:** `**Última actualización:** 2026-11-10`

**§2 Mapa de Módulos** — se añade módulo raíz `Capture`:

```
                    ┌──────────────────────┐
                    │   M6 Config/Permisos │
                    │   (transversal)      │
                    └──────────┬───────────┘
                               │
┌──────────────┐    ┌──────────▼───────────┐    ┌──────────────┐
│ M1 Discovery │    │  M4 TUI (ratatui)    │    │ M3 Storage   │
│ (F1 + F2)    │───►│  (F1, F2, F3, F5, F6)│◄───│ (SQLite +    │
│              │    │                      │    │  rollups)    │
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

**§3 Tabla Resumen de Fases** — filas F1-F3 actualizadas:

| Fase | Módulo | Funcionalidades | Sprints | Semanas | Estado |
|------|--------|-----------------|---------|---------|--------|
| 1 | Fundación + descubrimiento básico | 67 | 5 | 3–4 | **Implementación reportada** (2026-11-10) |
| 2 | Descubrimiento avanzado | 79 | 5 | 4–5 | **Implementación reportada** (2026-11-10) |
| 3 | Tráfico en vivo (pasivo + local) | **76** | 6 | 5–6 | **Especificada** |
| 4 | Protocolos, apps y top talkers | ~12 | 2 | 2–3 | Pendiente de especificar |
| 5 | Histórico, rollups y eventos | ~10 | 2 | 2 | Pendiente de especificar |
| 6 | Alertas (locales + escritorio) | ~9 | 1–2 | 1–2 | Pendiente de especificar |
| 7 | Integraciones y exportación | ~9 | 2 | 2 | Pendiente de especificar |
| **Total** | | **~262** | | **~22–28** | |

> **Recalibración F3:** la estimación inicial (~18) era baja; la especificación detallada la fija en **76**. Total acumulado: 67+79+76 = **222** funcionalidades especificadas hasta F3.

**§4 E-R global** — se añaden `TRAFFIC_SNAPSHOT` y `CONNECTIONS`, marcadas F3:

```
       ┌────────────────────┐
       │      DEVICES       │  (F1, ampliada F2)
       └──┬───────────┬───┬─┘
          │ 1         │ 1 │ 1
          │           │   │
          │ 0..1      │0..N│ 0..N
   ┌──────▼───────┐ ┌─▼───▼──────────┐ ┌───────────────┐
   │TRAFFIC_      │ │   CONNECTIONS  │ │DEVICE_SERVICES│
   │SNAPSHOT (F3) │ │     (F3)       │ │   (F2)        │
   └──────────────┘ └────────────────┘ └───────────────┘

  Notas:
   · TRAFFIC_SNAPSHOT: 1 fila por device, snapshot del último valor (5 s).
   · CONNECTIONS: caliente; purga por timeout. device_id NULL = host/bcast/?
   · F5 creará TRAFFIC_ROLLUP_MINUTE/HOUR/DAY (histórico).
   · F6 creará ALERTS y ALERT_RULES.
   · F7 creará EXTERNAL_SOURCES (SNMP, pcap replay).
```

**§5 Glosario** — se añaden:

| Término de negocio | Entidad/Tabla | Fase | Notas |
|--------------------|---------------|------|-------|
| Snapshot de tráfico | `TRAFFIC_SNAPSHOT` | F3 | Último valor por dispositivo cada 5 s |
| Conexión activa | `CONNECTIONS` | F3 | Tabla caliente; purga por timeout |
| Tag `[host]` | `CONNECTIONS.device_id = NULL` | F3 | Conexión del propio host |
| Tag `[broadcast]` | `CONNECTIONS.device_id = NULL` | F3 | Multidifusión |
| Pico de tráfico | `TRAFFIC_SNAPSHOT.peak_bps` | F3 | Máximo en ventana 60 s |
| Ventana 60 s | (memoria) | F3 | Sparkline 1 punto/s |
| Ventana 5 min | (memoria) | F3 | Sparkline 1 punto/5 s |
| Rollup | `TRAFFIC_ROLLUP_*` | F5 | Agregado histórico persistente |

**§6 Estado del Proyecto:**

- **Fase 1:** 67 / 67 — **Implementación reportada** (2026-11-10). Verificación pendiente: F1-64 rendimiento end-to-end con `CAP_NET_RAW`.
- **Fase 2:** 79 / 79 — **Implementación reportada** (2026-11-10). Verificación pendiente: ciclo activo completo contra red real con `setcap`; rendimiento §8 no medido end-to-end.
- **Fase 3:** 0 / 76 — **especificada, sin informe de implementación procesado (sin confirmar)**.
- **Fases 4–7:** pendientes de especificar.
- **Progreso total:** **146 / 222** funcionalidades especificadas (67+79 implementadas; 76 especificadas sin confirmar).
- **Fechas de informes de implementación procesados:**
  - Fase 1: **2026-11-10** ✅
  - Fase 2: **2026-11-10** ✅
  - Fase 3: —

**§7 Roadmap** — F3 pasa a estado "especificada". Sin cambios estructurales.

**§8 Decisiones Transversales** — se añade:

- **Captura sin `libpcap`:** AF_PACKET + TPACKET_V3 con `libc`/`nix`. Vinculante para F3+; `pcap` solo como feature no default para replay en F7 (ADR-18).
- **Filtros BPF clásicos** adjuntos al socket (ADR-19). Cualquier filtro nuevo se expresa en BPF; no se implementan filtros propios en TOML.
- **Payload opt-in y descarte inmediato** (ADR-20). Regla dura: ningún payload se persiste nunca.
- **Snapshot persistente cada 5 s** (ADR-21) con coste despreciable. F5 lo sustituirá por rollups históricos reales.
- **`CONNECTIONS` como tabla caliente** (ADR-22): purge por timeout; no es histórico. F5 añadirá rollups de conexiones si hace falta.
- **Dos fuentes de conexiones (`/proc` + captura)** (ADR-23). Vinculante: la TUI debe indicar `[host]` cuando la conexión es del propio host.
- **Ventanas 60s + 5min en F3**; 1h + 24h llegan en F5 (ADR-24).
- **Aviso único de captura al arrancar** (ADR-25). F3+ debe mantener este aviso.
- **`passive_only` respeta captura pasiva** (ADR-26). Documentado en Ayuda; regla explícita para F4–F7: "escuchar no genera tráfico, capturar sí está permitido con `passive_only = true`".

**§8 Riesgos** — se añade:

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| Privacidad: payload capturado por error | **Alto** | `inspect_payload = false` por defecto; descarte inmediato; payload nunca persiste; aviso en Ayuda |
| `TPACKET_V3` no disponible en kernels antiguos | Bajo | Requisito documentado en README (Linux ≥ 3.2) |
| Captura satura el hilo de TUI | Medio | Hilo dedicado + `max_pps` configurable + aviso de drops |
| `/proc/net/nf_conntrack` no legible sin root | Bajo | Best-effort silencioso; no bloquea |
| `/proc/[pid]/fd` sin permisos para procesos ajenos | Bajo | Degradación silenciosa; PID queda NULL |
| Filtro BPF complejo ralentiza captura | Bajo | BPF evalúa en kernel; coste usuarios despreciable |
| `device_id = NULL` en CONNECTIONS por no match | Medio | Etiqueta `[?]`; el usuario ve qué no se ha atribuido |
| Sparkline arranca a cero al reabrir | Bajo | `TRAFFIC_SNAPSHOT` como semilla; F5 dará histórico real |
| `max_pps` alcanzado sin darse cuenta | Bajo | Aviso una vez por minuto + estado en barra |

---

