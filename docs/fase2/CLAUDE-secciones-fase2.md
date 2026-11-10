# CLAUDE.md - secciones modificadas por Fase 2

> Nota: este fichero contiene solo las secciones que cambian en `CLAUDE.md`. El resto del archivo vivo se conserva literal.

## Contexto / Stack

```markdown
Stack: Rust (edition 2021, MSRV 1.88), tokio, ratatui + crossterm, clap, serde + toml,
rusqlite (bundled), pnet, macaddr-ouidb (renombrada ouidb en Cargo.toml), tracing,
hickory-proto, ssdp, reqwest.
```

## Documentación del proyecto — añadir

```markdown
- `almenara-fase2-informe.md` — especificación funcional de Fase 2 (v1.0)
- `almenara-fase2-checklist.md` — alcance verificable de Fase 2 (F2-01..F2-73)
- `almenara-fase2-implementacion.md` — informe de implementación de Fase 2 (lo escribes tú)
```

## Reglas de trabajo — añadir

```markdown
- Migraciones **aditivas**: nunca borrar ni renombrar columnas de una fase anterior sin
  ADR y sin test de compatibilidad con la BD de la fase previa. Cada nueva fase que añada
  columnas debe incluir un test que abra una BD de la fase anterior y verifique que los
  datos se conservan.
- `[scan].passive_only = true` deshabilita todo el tráfico activo (ARP scan, ICMP sweep,
  mDNS browse, M-SEARCH, port scan, banner grabbing). Es obligatorio respetarlo en todas
  las fases: ningún módulo puede emitir tráfico activo si `passive_only` está activo.
- Port scan y banner grabbing **nunca** se ejecutan en cada ciclo periódico: solo al
  descubrir un equipo nuevo, cambio de IP/MAC, o `r` manual del usuario.
- `DEVICE_SERVICES` y `DISCOVERY_SOURCES` son las fuentes de verdad para servicios y
  procedencia de descubrimientos. No se duplica esa información en columnas de `DEVICES`.
- La clasificación de `device_type` es automática con `device_type_manual` como override
  del usuario (si no es NULL, gana siempre).
- Fingerprint de SO: si la confianza no supera el umbral (≥ 4), `os_family = NULL`. No se
  reportan estimaciones con baja confianza.
```

## Ayuda y keybindings — añadir

```markdown
- `g` alterna vista plana / agrupada por categoría. Preferencia persistida en
  `[ui].list_view` (`"flat"` por defecto).
```
