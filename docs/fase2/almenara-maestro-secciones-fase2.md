# Almenara - Maestro: secciones modificadas por Fase 2

> Nota: este fichero contiene solo las secciones que cambian en `almenara-maestro.md`. El resto del maestro se conserva literal en el archivo vivo.

**Cabecera:** `**Última actualización:** 2026-11-10`

## §2 Mapa de Módulos — se añade módulo raíz `Discovery`

```
┌──────────────┐    ┌──────────────────────┐    ┌──────────────┐
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

## §3 Tabla Resumen de Fases — filas F1 y F2 actualizadas

| Fase | Módulo | Funcionalidades | Sprints | Semanas | Estado |
|------|--------|-----------------|---------|---------|--------|
| 1 | Fundación + descubrimiento básico | 67 | 5 | 3–4 | **Implementación reportada** (2026-11-10) |
| 2 | Descubrimiento avanzado | **73** | **5** | **4–5** | **Especificada** |
| 3 | Tráfico en vivo (pasivo + local) | ~18 | 3–4 | 3–4 | Pendiente de especificar |
| 4 | Protocolos, apps y top talkers | ~12 | 2 | 2–3 | Pendiente de especificar |
| 5 | Histórico, rollups y eventos | ~10 | 2 | 2 | Pendiente de especificar |
| 6 | Alertas (locales + escritorio) | ~9 | 1–2 | 1–2 | Pendiente de especificar |
| 7 | Integraciones y exportación | ~9 | 2 | 2 | Pendiente de especificar |
| **Total** | | **~198** | | **~18–24** | |

> **Recalibración:** la estimación inicial de F2 (~14 funcionalidades) era baja; la especificación detallada la fija en 73. Los totales de F3–F7 se mantienen como orden de magnitud; se recalibrarán al especificarlas.

## §4 E-R global — se añaden las dos tablas nuevas y las tres columnas nuevas en `DEVICES`

Nuevas tablas: `DEVICE_SERVICES`, `DISCOVERY_SOURCES`.
Nuevas columnas en `DEVICES`: `os_family`, `device_type_manual`, `last_fingerprint`. Marcadas con `F2`.

## §5 Glosario — se añaden

| Término de negocio | Entidad/Tabla | Fase | Notas |
|--------------------|---------------|------|-------|
| Servicio detectado | `DEVICE_SERVICES` | F2 | Puerto/protocolo/banner por dispositivo |
| Fuente de descubrimiento | `DISCOVERY_SOURCES` | F2 | Quién ha visto al dispositivo |
| Tipo manual | `DEVICES.device_type_manual` | F2 | Override del usuario |
| Fingerprint SO | `DEVICES.os_family` | F2 | Estimación heurística, nullable |

## §6 Estado del Proyecto — actualización

- **Fase 1:** 67 / 67 — **Implementación reportada** (2026-11-10). Verificación pendiente: F1-64 rendimiento end-to-end con `CAP_NET_RAW`.
- **Fase 2:** 0 / 73 — **especificada, sin informe de implementación procesado (sin confirmar)**.
- **Fases 3–7:** pendientes de especificar.
- **Progreso total:** 67 / 140 (solo F1 cuenta hasta que F2 se implemente).
- **Fechas de informes de implementación procesados:**
  - Fase 1: **2026-11-10** ✅
  - Fase 2: —

## §7 Roadmap — sin cambios estructurales; F2 pasa a estado "especificada".

## §8 Decisiones Transversales — se añade

- **`hickory-proto` + `ssdp` + `reqwest`** para descubrimiento DNS-SD/UPnP (ADR-08, ADR-09). Vinculante para F3+ si aparece necesidad de mDNS/SSDP adicional.
- **Port scan TCP CONNECT bajo demanda** (ADR-12, ADR-13). F3+ puede añadir SYN scan opt-in solo si se justifica.
- **`passive_only` como modo ciudadano de primera clase** (ADR-17). F3+ (captura de tráfico) debe respetar `passive_only` y no abrir sockets activos.
- **Migraciones aditivas y verificación v(N-1) → v(N)** como norma a partir de F2. Toda nueva fase que añada columnas debe incluir test de compatibilidad con la BD de la fase anterior.

## §8 Riesgos — se añade

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| Port scan detectado por IDS doméstico | Bajo | Solo bajo demanda, TOP-20 fijo, timeout 500 ms |
| XML SSDP malicioso (LOCATION apunta a IP externa) | Medio | Solo http/https, máx. 256 KB, sin redirecciones externas, timeout 2 s |
| Fingerprint heurístico con falsos positivos | Bajo | Umbral de confianza; override manual disponible |
| Parser DHCP de formatos no estándar (Kea, ISC dhcpd) | Bajo | Fuera de alcance F2; añadible en F7 si surge necesidad real |
| `hickory-proto` cambia de API entre versiones menores | Bajo | Pin a versión menor en `Cargo.toml` |
