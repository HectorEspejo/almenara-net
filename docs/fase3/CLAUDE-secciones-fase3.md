## E) `CLAUDE.md` — actualización (solo secciones modificadas)

**Stack (bloque "Contexto"):**

```markdown
Stack: Rust (edition 2021, MSRV 1.88), tokio, ratatui + crossterm, clap, serde + toml,
rusqlite (bundled), pnet (datalink), libc + nix (raw sockets, AF_PACKET, TPACKET_V3),
macaddr-ouidb (renombrada ouidb), hickory-proto (mdns), reqwest (rustls, solo XML UPnP),
tracing. Parser SSDP propio. Captura de tráfico con AF_PACKET + TPACKET_V3 (sin libpcap).
```

**Documentación del proyecto** — añadir:

```markdown
- `docs/fase3/almenara-fase3-informe.md` — especificación funcional de Fase 3 (v1.0)
- `docs/fase3/almenara-fase3-checklist.md` — alcance verificable de Fase 3 (76 casillas)
- `docs/fase3/almenara-fase3-implementacion.md` — informe de implementación de Fase 3
```

**Reglas de trabajo** — añadir (además de las ya existentes):

```markdown
- Captura de tráfico con AF_PACKET + TPACKET_V3 (sin libpcap). `libpcap`/`pcap` solo como
  feature no default para replay de ficheros en F7; nunca en F3.
- Filtros de captura con BPF clásico adjunta al socket (`SO_ATTACH_FILTER`). No se implementan
  filtros propios en userspace.
- Payload **nunca** se persiste. Con `[capture].inspect_payload = false` (default) el payload
  se descarta inmediatamente (no se copia a memoria). Con `true` se extraen solo QNAME/SNI y el
  resto se descarta.
- `CONNECTIONS` es tabla caliente; se purga por timeout (TCP 300 s, TIME_WAIT/CLOSE_WAIT 60 s,
  UDP 60 s, ICMP 30 s) cada 5 s. No es histórico; el histórico es F5.
- `TRAFFIC_SNAPSHOT` se sobrescribe cada 5 s; 1 fila por dispositivo. No es histórico.
- Atribución de `device_id` en CONNECTIONS: match por IP → ese device; host → NULL +
  `[host]`; broadcast → NULL + `[broadcast]`; sin match → NULL + `[?]`. La TUI muestra estas
  etiquetas en dim.
- `passive_only = true` **permite captura pasiva** (escuchar no emite tráfico). Prohíbe todo
  tráfico activo (ARP, ICMP, M-SEARCH, port scan, banner, fingerprint). Documentado en Ayuda
  y en la regla `active_allowed()` del scanner.
- Aviso de captura al arrancar (una sola vez) si `[capture].enabled = true` y hay
  `CAP_NET_RAW`. Estado siempre visible en la barra (`capturando · N pps · filtro: …`).
- Sparklines arrancan a cero hasta el primer paquete; `TRAFFIC_SNAPSHOT` se usa como semilla
  inicial al reabrir. Ventanas 1 h / 24 h son de F5 (requieren persistencia).
- Ventanas en memoria: 60 s (1 punto/s) y 5 min (1 punto/5 s). Añadir ventanas nuevas requiere
  fase (F5) con persistencia real.
- Tests con replay de fichero pcap son condicionales a la feature `pcap`; no obligatorios en F3.
```

**Ayuda y keybindings** — añadir:

```markdown
- `Enter` sobre equipo → panel detalle master-detail (mitad derecha ≥100 cols, pantalla
  completa por debajo).
- `Tab` en detalle → alternar foco entre lista y detalle; `Esc` cierra el detalle.
- `v` sobre conexión → panel inferior con cabeceras IP/TCP ya en memoria (no modal).
```

---

