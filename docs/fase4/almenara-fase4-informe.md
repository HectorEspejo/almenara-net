# Almenara - Fase 4: Protocolos, apps y top talkers

## Especificación Funcional

**Versión:** 1.0
**Fecha:** 2026-11-10
**Cliente:** Uso personal (desarrollador)

---

## 1. Visión General

La Fase 4 pone nombre al tráfico que F3 ya cuenta. Para cada conexión, Almenara deduce el **protocolo de aplicación** (TLS, QUIC, DNS, SSH…), el **nombre del servidor** (SNI de TLS y de QUIC, `Host` de HTTP o la caché de nombres que alimentan las respuestas DNS), la **app** y su **categoría** a partir de un catálogo propio embebido, y qué extremo es el **cliente** y cuál el **servidor**. Con esas etiquetas, la pestaña Tráfico ofrece rankings (top talkers) por destino, app, categoría, protocolo y proceso local, además del ranking por equipo de F3, y responde a la pregunta «¿quién lo usa?».

La fase también mejora la **identificación de equipos** con señales que la captura ya ve (huella DHCP, modelo anunciado por mDNS o UPnP, User-Agent HTTP), marca las **MAC privadas** de los móviles, sustituye la heurística de `mac_changed` por una versión con huella DHCP y usa la **captura como fuente L2** capaz de dar de alta equipos. Además, `passive_only` pasa a significar «no consultar a nadie».

**Visibilidad honesta.** Por WiFi o en red conmutada, Almenara ve bien el tráfico propio y el broadcast/multicast; DoH y ECH ocultan nombres en parte del tráfico. El motor de inferencia no depende de la fuente de los paquetes (la visibilidad de terceros llegará con la sub-fase 3.5 o con F7) y la TUI muestra siempre el porcentaje de tráfico **sin identificar**.

**Objetivos principales:**
1. Etiquetar cada conexión con protocolo de aplicación, nombre del servidor, app, categoría y la fuente de cada dato.
2. Ofrecer rankings por destino, app, categoría, protocolo y proceso local, con ventanas de 60 s, 5 min y sesión.
3. Enriquecer los destinos de Internet con dominio registrable, organización (ASN) y país sin consultas de red.
4. Mejorar la identificación de equipos (huella DHCP, modelo, User-Agent, MAC privadas, `mac_changed` v2) y usar la captura como fuente L2.
5. Mantener la privacidad: etiqueta derivada sí, payload nunca; dominios solo en tablas calientes y fuera de los logs.
6. Hacer que el modo pasivo sea pasivo de verdad (sin NetBIOS ni DNS inverso) y no hacer nunca DNS inverso de IPs de Internet.

**Contexto:** evolución de F1–F3 (implementadas y verificadas, 248/248). Migración v4 aditiva: toda BD de F3 sigue funcionando sin pérdida de datos. Decisiones de la sesión de descubrimiento del 2026-11-10: opción recomendada en las 12 preguntas. El sprint 4.0 cierra la verificación pendiente de F1–F3 con `CAP_NET_RAW` antes de tocar código nuevo.

---

## 2. Arquitectura Técnica

### Stack tecnológico (novedades respecto a F3)

| Capa | Tecnología | Motivo |
|------|-----------|--------|
| Respuestas DNS | `hickory-proto` (en el stack desde F2) | Parseo de A/AAAA/CNAME con TTL |
| TLS ClientHello | Parser propio | SNI, ALPN, versiones, cifrados, extensiones y algoritmos de firma (para JA4) |
| QUIC Initial | Parser propio + `aes-gcm`, `aes`, `hkdf`, `sha2` (RustCrypto) | Derivar las claves Initial (RFC 9001 y RFC 9369), quitar la protección de cabecera y descifrar; Rust puro |
| JA4 | Implementación propia de la especificación pública + `sha2` | Huella del cliente TLS/QUIC (JA4 de cliente, licencia BSD-3) |
| Firmas de protocolo | Propias (primeros bytes + puerto) | ~30 protocolos sin dependencias (§7.3) |
| Dominio registrable | `psl` (Public Suffix List compilada en el crate) | eTLD+1 sin descargas |
| Organización y país | DB-IP Lite (IP to ASN Lite + IP to Country Lite, formato MMDB, CC BY 4.0) embebida + `maxminddb` | Búsqueda local, sin red |
| Catálogo de apps | `data/catalogo.toml` embebido (`include_str!`) + `apps.toml` del usuario (`serde` + `toml`, ya en el stack) | Reglas legibles y ampliables |
| DHCP (paquetes) | Parser propio de opciones BOOTP/DHCP | Huella (opciones 55 y 60) y nombre (opción 12) |

**Crates como contratos semánticos.** Los nombres de crate de esta tabla describen la función que se necesita, igual que `ssdp` y `ouidb` en F1–F2. Si uno no existe, no compila con MSRV 1.88 o no ofrece lo descrito, el agente usa un equivalente en Rust puro y lo anota como desviación. No se añaden dependencias del sistema.

**Rutas de F1–F3.** Las rutas citadas son las de sus informes. Si el código real difiere, manda el código y la correspondencia se anota en el informe de implementación.

### Estructura de carpetas (novedades)

```
almenara/
├── data/                           # NUEVO: datos embebidos (versionados)
│   ├── catalogo.toml               # catálogo de apps y categorías (§7.9)
│   ├── dbip-asn-lite.mmdb          # DB-IP Lite: IP → ASN y organización
│   ├── dbip-country-lite.mmdb      # DB-IP Lite: IP → país
│   └── FUENTES.md                  # origen, fecha y licencia de cada dato
├── scripts/
│   └── actualizar-bases-ip.sh      # NUEVO: sustituye las MMDB (solo desarrollo)
├── docs/fase4/                     # informe, prompt, checklist e implementación
├── CHANGELOG.md                    # novedades por versión (se crea si no existe)
└── src/
    ├── inference/                  # NUEVO módulo raíz
    │   ├── mod.rs                  # FlowInspector (hilo de captura) y LabelResolver (agregador)
    │   ├── reassembly.rs           # inicio de flujo TCP (4 KB c→s, 64 B s→c) y CRYPTO de QUIC
    │   ├── protocols.rs            # firmas por primeros bytes + puerto (§7.3)
    │   ├── tls.rs                  # ClientHello (sustituye a capture/sni.rs)
    │   ├── quic.rs                 # Initial: claves, protección de cabecera, AEAD, CRYPTO
    │   ├── ja4.rs                  # huella JA4 (t… y q…)
    │   ├── http.rs                 # Host y User-Agent de HTTP/1.x
    │   ├── dns.rs                  # consultas y respuestas DNS (sustituye a capture/dns.rs)
    │   ├── names.rs                # NameCache: IP → nombre con caducidad
    │   ├── catalog.rs              # catálogo embebido + apps.toml
    │   ├── domain.rs               # dominio registrable (PSL)
    │   ├── ipdb.rs                 # organización (ASN) y país (MMDB embebidas)
    │   └── role.rs                 # rol cliente/servidor (§7.1)
    ├── identify/                   # NUEVO: identificación de equipos
    │   ├── mod.rs                  # señales → os_family, device_type, model
    │   ├── dhcp.rs                 # paquetes DHCP capturados: huella y nombre
    │   ├── models.rs               # modelo por TXT de mDNS y descripción UPnP
    │   ├── useragent.rs            # User-Agent → pistas de SO y tipo
    │   ├── mac.rs                  # MAC privada y mac_changed v2
    │   └── observed.rs             # equipos observados (ARP, DHCP, tramas)
    ├── rankings.rs                 # NUEVO: rankings por dimensión y ventana
    ├── config.rs                   # (extendido) [inference], [ui].traffic_group
    ├── capture/                    # (F3) parser extendido con ARP; dns.rs y sni.rs pasan a inference/
    ├── repo/
    │   ├── names.rs                # NUEVO DAO NAME_CACHE
    │   ├── connections.rs          # (extendido) rol, etiquetas, JA4
    │   ├── devices.rs              # (extendido) identidad
    │   └── migrations.rs           # migración v4
    └── tui/views/
        ├── traffic.rs              # (extendido) agrupación g, ventana w
        ├── who_uses.rs             # NUEVO: panel «¿Quién lo usa?»
        ├── connections.rs          # (extendido) Prot./Equipo/Destino/App, tecla i
        ├── device_detail.rs        # (extendido) identidad, top apps y destinos
        ├── config_view.rs          # (extendido) inferencia, catálogo, bases IP
        └── help.rs                 # (extendido) teclas, privacidad, atribución
```

### Hilos y flujo de datos

- **Hilo de captura** (uno por interfaz, ADR-27): parser de F3 + `FlowInspector` (firmas, reensamblado, TLS, QUIC, HTTP, DNS, DHCP y ARP). Mantiene el estado de inspección de sus flujos y emite evidencias. No guarda nombres ni rankings.
- **Agregador** (el de F3): recibe las evidencias, mantiene la caché de nombres, resuelve etiquetas con `LabelResolver`, suma los rankings y publica cada segundo `AppEvent::Traffic` con las filas y el % sin identificar. Atiende `TrafficCommand::WhoUses`.
- **Ciclo de escaneo** (F1/F2): vacía `ObservedHosts` y fusiona los equipos observados como una fuente L2 más.
- **Hilo de la TUI:** único escritor SQLite (ADR-35 de F1): persiste rol, etiquetas, caché de nombres e identidad de equipos en el ciclo de 5 s de F3.

### Diagrama de arquitectura

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              TUI (ratatui)                               │
│ ┌───────────┐ ┌─────────────────┐ ┌───────────────┐ ┌─────────────────┐  │
│ │ Equipos   │ │ Tráfico         │ │ Conexiones    │ │ Detalle         │  │
│ │ MAC       │ │ g: agrupación   │ │ App/Dominio   │ │ identidad,      │  │
│ │ privada   │ │ w: ventana      │ │ rol c/s       │ │ top apps        │  │
│ └─────┬─────┘ └────────┬────────┘ └───────┬───────┘ └────────┬────────┘  │
└───────┼────────────────┼──────────────────┼──────────────────┼───────────┘
        └────────────────┴────────────┬─────┴──────────────────┘
                                      ▼
                          ┌──────────────────────┐
                          │ App State + Bus      │
                          └───────────┬──────────┘
                                      │
          ┌───────────────────────────┼─────────────────────────┐
          ▼                           ▼                         ▼
 ┌─────────────────┐       ┌─────────────────────┐   ┌─────────────────────┐
 │ Captura (F3)    │       │ Agregador (F3 + F4) │   │ Escaneo (F1/F2)     │
 │ un hilo por     │       │ LabelResolver,      │   │ + equipos           │
 │ interfaz        │       │ caché de nombres,   │   │ observados (F4)     │
 └────────┬────────┘       │ Rankings            │   └──────────▲──────────┘
          ▼                └─────▲───────────────┘              │
┌───────────────────┐            │                              │
│ FlowInspector (F4)├────────────┘                              │
│ firmas,           │  FlowEvidence,                            │
│ reensamblado,     │  NameObservation                          │
│ TLS/QUIC/HTTP/DNS │                                           │
│ JA4, DHCP, ARP    ├───────────────────────────────────────────┘
└───────────────────┘  ObservedHost + identidad DHCP

┌──────────────────────────────────────────────────────────────────────────┐
│ Datos embebidos (solo lectura, los usan agregador e identificación):     │
│ catálogo de apps · Public Suffix List · DB-IP Lite (ASN y país)          │
└──────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────┐
│ Repo (SQLite, escritor único en el hilo de la TUI): CONNECTIONS          │
│ (+ rol, etiquetas, JA4), NAME_CACHE, DEVICES (+ identidad),              │
│ DISCOVERY_SOURCES (+ capture)                                            │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Modelo de Datos

### Migración v4 (aditiva, no rompe F1–F3)

```sql
-- v4 — Fase 4: protocolos, apps y top talkers

ALTER TABLE CONNECTIONS ADD COLUMN client_is_src BOOLEAN NULL;
ALTER TABLE CONNECTIONS ADD COLUMN app_protocol  TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN server_name   TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN name_source   TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN app           TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN category      TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN app_source    TEXT NULL;
ALTER TABLE CONNECTIONS ADD COLUMN ja4           TEXT NULL;

ALTER TABLE DEVICES ADD COLUMN model            TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN dhcp_fingerprint TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN dhcp_vendor      TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN dhcp_hostname    TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN user_agent       TEXT NULL;
ALTER TABLE DEVICES ADD COLUMN os_source        TEXT NULL;

CREATE TABLE NAME_CACHE (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ip          TEXT NOT NULL,
  name        TEXT NOT NULL,
  source      TEXT NOT NULL,          -- 'dns' | 'sni' | 'http'
  first_seen  TIMESTAMP NOT NULL,
  last_seen   TIMESTAMP NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  UNIQUE (ip, name)
);

CREATE INDEX IDX_NAME_CACHE_IP      ON NAME_CACHE(ip);
CREATE INDEX IDX_NAME_CACHE_EXPIRES ON NAME_CACHE(expires_at);
CREATE INDEX IDX_CONN_APP           ON CONNECTIONS(app);
```

- Idempotente con `SCHEMA_MIGRATIONS` y `already_applied` para cada `ALTER TABLE` (convención de F2).
- Enumeraciones validadas en código, sin `CHECK` en SQLite.
- Fechas en TEXT RFC 3339 UTC (ADR-34 de F1).
- `DISCOVERY_SOURCES.source` admite el valor nuevo `capture` sin cambio de esquema.

### Diagrama E-R (parte nueva y ampliada)

```
  ┌──────────────────────────────────┐
  │ DEVICES (F1, ampliada F2 y F4)   │
  ├──────────────────────────────────┤
  │ id (PK) · mac (UNIQUE) · ip      │
  │ hostname · vendor · device_type  │
  │ os_family · … (F1–F2)            │
  │ model                    ◄ F4    │
  │ dhcp_fingerprint         ◄ F4    │
  │ dhcp_vendor              ◄ F4    │
  │ dhcp_hostname            ◄ F4    │
  │ user_agent               ◄ F4    │
  │ os_source                ◄ F4    │
  └──────┬─────────────────┬─────────┘
         │ 1               │ 1
         │                 │
         │ 0..N            │ N
  ┌──────▼──────────────┐ ┌▼─────────────────────────┐
  │ CONNECTIONS         │ │ DISCOVERY_SOURCES (F2)   │
  │ (F3, ampliada F4)   │ ├──────────────────────────┤
  ├─────────────────────┤ │ source: + 'capture'      │
  │ id (PK)             │ │   (F4, sin cambio de     │
  │ device_id (FK NULL) │ │   esquema)               │
  │ protocol, 5-tupla   │ └──────────────────────────┘
  │ state, bytes_in/out │
  │ first/last_seen     │
  │ client_is_src  ◄ F4 │
  │ app_protocol   ◄ F4 │
  │ server_name    ◄ F4 │
  │ name_source    ◄ F4 │
  │ app            ◄ F4 │
  │ category       ◄ F4 │
  │ app_source     ◄ F4 │
  │ ja4            ◄ F4 │
  └─────────────────────┘

  ┌──────────────────────┐
  │ NAME_CACHE (F4)      │   Sin claves ajenas: caché caliente
  ├──────────────────────┤   IP → nombre. Se cruza por valor con
  │ id (PK)              │   la IP del lado servidor de
  │ ip                   │   CONNECTIONS (rol, §7.1).
  │ name                 │
  │ source               │
  │ first_seen           │
  │ last_seen            │
  │ expires_at           │
  │ UNIQUE(ip, name)     │
  └──────────────────────┘
```

### Definición de tablas

**CONNECTIONS** — columnas nuevas (F4).

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `client_is_src` | BOOLEAN NULL | 1 si el extremo `src` canónico es el cliente, 0 si es el servidor, NULL si no se sabe (§7.1) |
| `app_protocol` | TEXT NULL | Protocolo de aplicación (§7.3): `tls`, `quic`, `http`, `dns`… |
| `server_name` | TEXT NULL | Nombre del servidor en minúsculas y sin punto final (máx. 255) |
| `name_source` | TEXT NULL | `sni` / `http` / `cache` |
| `app` | TEXT NULL | Clave de app del catálogo; NULL = sin identificar |
| `category` | TEXT NULL | Clave de categoría del catálogo (§7.9) |
| `app_source` | TEXT NULL | `domain` / `lan_service` / `asn` / `port` |
| `ja4` | TEXT NULL | Huella JA4 del cliente (TLS o QUIC) |

**DEVICES** — columnas nuevas (F4).

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `model` | TEXT NULL | Modelo anunciado por mDNS (TXT) o UPnP, máx. 64 caracteres |
| `dhcp_fingerprint` | TEXT NULL | Opción 55 en decimal separada por comas, en su orden |
| `dhcp_vendor` | TEXT NULL | Opción 60 saneada, máx. 64 |
| `dhcp_hostname` | TEXT NULL | Opción 12 saneada, máx. 64 |
| `user_agent` | TEXT NULL | Último User-Agent de HTTP en claro, saneado y truncado a 256 |
| `os_source` | TEXT NULL | Señal que fijó `os_family`: `tcp` / `dhcp` / `model` / `ua` |

**NAME_CACHE** — tabla nueva y caliente (F4): caché IP → nombre.

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | INTEGER PK AUTOINCREMENT | Identificador |
| `ip` | TEXT NOT NULL | IPv4 o IPv6 del servidor |
| `name` | TEXT NOT NULL | Nombre consultado (DNS) u observado (SNI, Host) |
| `source` | TEXT NOT NULL | `dns` / `sni` / `http` |
| `first_seen` | TIMESTAMP NOT NULL | Primera observación |
| `last_seen` | TIMESTAMP NOT NULL | Última observación o uso para etiquetar |
| `expires_at` | TIMESTAMP NOT NULL | Caducidad (§7.7): entre 1 h y 24 h |

### Relaciones

- `CONNECTIONS.device_id → DEVICES.id` (F3, `ON DELETE SET NULL`): sin cambios. Las columnas nuevas son atributos de la conexión.
- `NAME_CACHE` no tiene claves ajenas: se cruza por valor con la IP del lado servidor de `CONNECTIONS` y, en memoria, con la IP del equipo que hizo la consulta DNS.
- `DEVICES` gana atributos de identidad. `DEVICE_EVENTS` no cambia de esquema: los detalles JSON de `new` y `mac_changed` ganan campos (§7.13).
- `DISCOVERY_SOURCES` gana el valor `capture` (§7.14).

### Diagrama de estados — etiqueta de una conexión

La etiqueta no tiene columna de estado: se deduce de `app_source` y `name_source`. Su ciclo de vida es el de la conexión de F3.

```
┌──────────────────────────────┐ cierra  ┌──────────────────────┐
│ SIN ETIQUETA                 ├────────►│ «Sin identificar»    │
│ fuerza 0 (flujo nuevo)       │         │ (app NULL) hasta que │
└───────────────┬──────────────┘         │ expire la conexión   │
                │                        └──────────────────────┘
                │ evidencia de puerto, ASN o servicio
                ▼
┌──────────────────────────────┐
│ PROVISIONAL                  │
│ port (1), asn (2) o          │
│ lan_service (3)              │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ POR NOMBRE                   │
│ domain: caché (4) o          │
│ SNI/Host (5)                 │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ EXPIRADA                     │
│ purga de CONNECTIONS (F3)    │
└──────────────────────────────┘

Se puede saltar de SIN ETIQUETA a POR NOMBRE directamente (SNI en el
primer segmento). Cualquier estado pasa a EXPIRADA por el timeout de F3.

Transiciones inválidas:
 · bajar de fuerza (p. ej. de SNI a puerto)
 · cambiar de app con la misma fuerza (gana la primera)
 · etiquetar por nombre con [inference].enabled = false
```

### Diagrama de estados — entrada de NAME_CACHE

```
┌──────────────────────────────┐ uso/obs.  ┌──────────────────────────┐
│ VIGENTE                      ├──────────►│ refresca last_seen;      │
│ expires_at > ahora           │           │ expires_at ≥ ahora + 1 h │
└───────────────┬──────────────┘           │ (máx. 24 h)              │
                │                          └──────────────────────────┘
                │ expires_at ≤ ahora o desalojo por tope
                ▼
┌──────────────────────────────┐
│ CADUCADA                     │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ purga (DELETE) en el ciclo   │
│ de 5 s                       │
└──────────────────────────────┘

La entrada nace VIGENTE con una respuesta DNS, un SNI o un Host.

Transiciones inválidas:
 · usar una entrada CADUCADA para etiquetar
 · expires_at a más de 24 h de la última observación
```

### Diagrama de estados — reensamblado del inicio de flujo (memoria)

```
┌──────────────────────────────┐
│ ABIERTO                      │
│ primer segmento con datos    │
│ cliente → servidor           │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  no   ┌────────────────────────────┐
│ ¿mensaje completo?           ├──────►│ AGOTADO (4 KB u 8          │
└───────────────┬──────────────┘       │ paquetes) o CADUCADO       │
                │ sí: COMPLETO         │ (3 s): extraer lo que haya │
                │                      └────────────────────────────┘
                ▼
┌──────────────────────────────┐
│ extraer (firma, SNI, Host,   │
│ JA4) y LIBERAR el buffer     │
└──────────────────────────────┘

AGOTADO y CADUCADO también terminan en LIBERADO.

Transiciones inválidas:
 · reabrir un flujo ya LIBERADO
 · copiar el buffer fuera del hilo de captura o guardarlo
```

`DEVICES` mantiene el ciclo online/offline de F1. Los cambios de identidad (`mac_changed` v2) se describen como flujo en §4.4.

---

## 4. Flujos de Trabajo

### 4.1 Inspección por paquete (hilo de captura)

```
┌──────────────────────────────┐
│ trama capturada (F3)         │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐     sí      ┌──────────────────────────────┐
│ ¿ARP?                        ├────────────►│ ObservedHost (MAC e IP       │
└───────────────┬──────────────┘             │ del emisor), §7.14           │
                │ no                         └──────────────────────────────┘
                ▼
┌──────────────────────────────┐    error    ┌──────────────────────────────┐
│ parser IP de F3              ├────────────►│ parse_errors (F3); la        │
└───────────────┬──────────────┘             │ trama no sigue               │
                │                            └──────────────────────────────┘
                ▼
┌──────────────────────────────┐     sí      ┌──────────────────────────────┐
│ ¿DHCP (UDP 67/68) con        ├────────────►│ Dhcp::parse → identidad      │
│ inferencia activa?           │             │ DHCP y ObservedHost          │
└───────────────┬──────────────┘             └──────────────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐     no      ┌──────────────────────────────┐
│ ¿inferencia activa?          ├────────────►│ etiqueta débil: puerto,      │
└───────────────┬──────────────┘             │ ASN, servicio de F2,         │
                │ sí                         │ proceso                      │
                │                            └──────────────────────────────┘
                ▼
┌──────────────────────────────┐     no      ┌──────────────────────────────┐
│ ¿flujo aún en                ├────────────►│ solo contar bytes con la     │
│ inspección?                  │             │ etiqueta ya resuelta         │
└───────────────┬──────────────┘             └──────────────────────────────┘
                │ sí
                ▼
┌──────────────────────────────┐    tope     ┌──────────────────────────────┐
│ reensamblado TCP o           ├────────────►│ descarte del buffer +        │
│ CRYPTO de QUIC               │             │ contador; etiqueta débil     │
└───────────────┬──────────────┘             └──────────────────────────────┘
                ▼
┌──────────────────────────────┐ mal formado ┌──────────────────────────────┐
│ firma de protocolo +         ├────────────►│ inference_errors;            │
│ extractor (TLS, QUIC,        │             │ etiqueta por puerto          │
│ HTTP, DNS)                   │             └──────────────────────────────┘
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ FlowEvidence y               │
│ NameObservation →            │
│ agregador (§7.8)             │
└──────────────────────────────┘
```

1. Si la trama es ARP, se apuntan la MAC y la IP del emisor como equipo observado (§7.14).
2. Las tramas IP pasan por el parser de F3; los errores se cuentan como en F3.
3. Los paquetes DHCP alimentan la identidad del equipo y, si traen IP confirmada, también los equipos observados.
4. Con la inferencia desactivada, solo hay etiqueta débil (puerto, ASN, servicio de F2, proceso).
5. Los flujos ya resueltos solo suman bytes. Los que siguen en inspección pasan por el reensamblado (TCP) o la recomposición CRYPTO (QUIC), la firma de protocolo y el extractor.
6. Las evidencias van al agregador; ningún byte de payload sale del hilo de captura.

### 4.2 Resolución de la etiqueta (agregador)

```
┌──────────────────────────────┐
│ FlowEvidence de un flujo     │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ lado servidor según el rol   │
│ (§7.1); sin rol: el extremo  │
│ remoto                       │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  ninguno  ┌──────────────────────────────┐
│ nombre: SNI > Host > caché   ├──────────►│ server_name = NULL; sigue    │
└───────────────┬──────────────┘           │ por ASN, servicio o puerto   │
                │                          └──────────────────────────────┘
                ▼
┌──────────────────────────────┐   casa    ┌──────────────────────────────┐
│ ¿el nombre casa en el        ├──────────►│ app_source = domain          │
│ catálogo?                    │           │ (fuerza 5 con SNI/Host,      │
└───────────────┬──────────────┘           │ 4 con caché)                 │
                │ no                       └──────────────────────────────┘
                ▼
┌──────────────────────────────┐   casa    ┌──────────────────────────────┐
│ ¿servicio de F2 en un        ├──────────►│ app_source = lan_service     │
│ flujo dentro de la LAN?      │           │ (fuerza 3)                   │
└───────────────┬──────────────┘           └──────────────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐   casa    ┌──────────────────────────────┐
│ ¿ASN del servidor en el      ├──────────►│ app_source = asn             │
│ catálogo?                    │           │ (fuerza 2)                   │
└───────────────┬──────────────┘           └──────────────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐   casa    ┌──────────────────────────────┐
│ ¿puerto o protocolo en el    ├──────────►│ app_source = port            │
│ catálogo?                    │           │ (fuerza 1)                   │
└───────────────┬──────────────┘           └──────────────────────────────┘
                │ no
                ▼
┌──────────────────────────────┐
│ sin identificar: app y       │
│ category NULL (fuerza 0)     │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐    no     ┌──────────────────────────────┐
│ ¿fuerza nueva > fuerza       ├──────────►│ se conserva la etiqueta      │
│ actual del flujo?            │           │ anterior                     │
└───────────────┬──────────────┘           └──────────────────────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ FlowLabel → Rankings y       │
│ CONNECTIONS (ciclo de 5 s)   │
└──────────────────────────────┘

Todas las ramas «casa» continúan en «¿fuerza nueva > fuerza actual?».
```

### 4.3 QUIC Initial

```
┌──────────────────────────────┐
│ datagrama UDP de un flujo    │
│ en inspección                │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   no    ┌───────────────────────────────┐
│ ¿cabecera larga Initial,     ├────────►│ no es Initial: si el flujo    │
│ versión 1 o 2?               │         │ ya es QUIC, solo contar       │
└───────────────┬──────────────┘         └───────────────────────────────┘
                │ sí
                ▼
┌──────────────────────────────┐
│ claves Initial desde el      │
│ DCID (RFC 9001 / 9369)       │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  falla  ┌───────────────────────────────┐
│ quitar protección de         ├────────►│ descartar el paquete, sin     │
│ cabecera + descifrar AEAD    │         │ error visible (contador)      │
└───────────────┬──────────────┘         └───────────────────────────────┘
                ▼
┌──────────────────────────────┐
│ tramas CRYPTO →              │
│ CryptoStream por offset      │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   no    ┌───────────────────────────────┐
│ ¿ClientHello completo?       ├────────►│ esperar (≤ 4 Initial o 3 s);  │
└───────────────┬──────────────┘         │ si caduca: caché, ASN o       │
                │ sí                     │ puerto                        │
                │                        └───────────────────────────────┘
                ▼
┌──────────────────────────────┐
│ Tls::parse_client_hello →    │
│ SNI + JA4 (q…) → evidencia   │
└──────────────────────────────┘
```

### 4.4 Identidad de equipos y `mac_changed` v2

```
┌──────────────────────────────┐
│ candidato del ciclo (MAC e   │
│ IP) + identidad DHCP si hay  │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐  sí   ┌───────────────────────────────┐
│ ¿MAC ya conocida?            ├──────►│ actualizar (F1/F2) y          │
└───────────────┬──────────────┘       │ señales de identidad (§7.12)  │
                │ no                   └───────────────────────────────┘
                ▼
┌──────────────────────────────┐  sí   ┌───────────────────────────────┐
│ ¿MAC privada con huella y    ├──────►│ mac_changed, reason =         │
│ nombre DHCP que casan con    │       │ rotation: se conserva el      │
│ UN solo equipo de MAC        │       │ equipo y cambia su MAC        │
│ privada no visto en el ciclo?│       └───────────────────────────────┘
└───────────────┬──────────────┘
                │ no (o varios candidatos)
                ▼
┌──────────────────────────────┐  sí   ┌───────────────────────────────┐
│ ¿toma la IP de un equipo     ├──────►│ ¿huellas DHCP de ambos        │
│ online cuya MAC desapareció  │       │ contradictorias? no →         │
│ (regla de F1)?               │       │ mac_changed, reason =         │
└───────────────┬──────────────┘       │ ip_takeover; sí → abajo       │
                │ no                   └───────────────────────────────┘
                ▼
┌──────────────────────────────┐
│ equipo nuevo: evento new     │
│ con mac_random               │
└──────────────────────────────┘
```

### 4.5 Equipos observados en la captura

```
┌──────────────────────────────┐
│ ARP, DHCP o trama IPv4       │
│ (hilo de captura)            │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐ descarta  ┌──────────────────────┐
│ filtros: MAC propia o de     ├──────────►│ ignorar              │
│ grupo, IP 0.0.0.0, IP propia │           └──────────────────────┘
│ o fuera de las subredes      │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐   lleno   ┌──────────────────────┐
│ ObservedHosts::push (dedup   ├──────────►│ descarte + contador  │
│ por MAC+IP, tope 4096)       │           └──────────────────────┘
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ ciclo de escaneo:            │
│ ObservedHosts::drain         │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ fusión como fuente L2        │
│ `capture` + reconciliación   │
│ de F1 (new, visto,           │
│ identidad)                   │
└──────────────────────────────┘
```

### 4.6 Rankings (cada segundo)

```
┌──────────────────────────────┐
│ bytes de un flujo con        │
│ etiqueta (Rankings::record)  │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ claves: equipo, destino,     │
│ app, categoría, protocolo y  │
│ proceso (solo [host])        │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐
│ ↓/↑ según el rol; ventanas   │
│ 60 s, 5 min y sesión;        │
│ equipos distintos            │
└───────────────┬──────────────┘
                ▼
┌──────────────────────────────┐ > 2048  ┌────────────────────────────┐
│ Rankings::tick (cada 1 s)    ├────────►│ desalojar claves sin bytes │
└───────────────┬──────────────┘         │ en 5 min (las más viejas)  │
                │                        └────────────────────────────┘
                ▼
┌──────────────────────────────┐
│ AppEvent::Traffic: top 50    │
│ por dimensión y ventana +    │
│ % sin identificar            │
└──────────────────────────────┘
```

### 4.7 Secuencia — ClientHello TLS partido en dos segmentos

```
Kernel         Captura        Inspector         Agregador         TUI/Repo         SQLite
  │               │               │                 │                 │               │
  │ SYN           │               │                 │                 │               │
  ├──────────────►│               │                 │                 │               │
  │               │ rol: cliente  │                 │                 │               │
  │ segmento 1    │               │                 │                 │               │
  ├──────────────►│               │                 │                 │               │
  │               │ push(seq)     │                 │                 │               │
  │               ├──────────────►│                 │                 │               │
  │               │               │ incompleto      │                 │               │
  │ segmento 2    │               │                 │                 │               │
  ├──────────────►│               │                 │                 │               │
  │               │ push(seq)     │                 │                 │               │
  │               ├──────────────►│                 │                 │               │
  │               │               │ ClientHello →   │                 │               │
  │               │               │ SNI, ALPN, JA4  │                 │               │
  │               │               │ libera buffer   │                 │               │
  │               │ evidencia     │                 │                 │               │
  │               │◄──────────────┤                 │                 │               │
  │               │ FlowEvidence  │                 │                 │               │
  │               ├───────────────┼────────────────►│                 │               │
  │               │               │                 │ catálogo + PSL  │               │
  │               │               │                 │ + base IP       │               │
  │               │               │                 │ rankings        │               │
  │               │               │                 │ Traffic (1 s)   │               │
  │               │               │                 ├────────────────►│               │
  │               │               │                 │                 │ cada 5 s      │
  │               │               │                 │                 │ upsert_conn.  │
  │               │               │                 │                 ├──────────────►│
  │               │               │                 │                 │ upsert_names  │
  │               │               │                 │                 ├──────────────►│
  │               │               │                 │                 │               │
```

### 4.8 Secuencia — respuesta DNS seguida de una conexión QUIC

```
Kernel         Captura        Inspector         Agregador         TUI/Repo
  │               │               │                 │                 │
  │ resp. DNS     │               │                 │                 │
  ├──────────────►│               │                 │                 │
  │               │ answers()     │                 │                 │
  │               ├──────────────►│                 │                 │
  │               │               │ NameObserv.     │                 │
  │               │               ├────────────────►│                 │
  │               │               │                 │ caché IP→nombre │
  │ Initial 1     │               │                 │                 │
  ├──────────────►│               │                 │                 │
  │               │ Initial 1     │                 │                 │
  │               ├──────────────►│                 │                 │
  │               │               │ claves (DCID)   │                 │
  │               │               │ descifra AEAD   │                 │
  │               │               │ CRYPTO parcial  │                 │
  │ Initial 2     │               │                 │                 │
  ├──────────────►│               │                 │                 │
  │               │ Initial 2     │                 │                 │
  │               ├──────────────►│                 │                 │
  │               │               │ ClientHello →   │                 │
  │               │               │ SNI + JA4 (q)   │                 │
  │               │ evidencia     │                 │                 │
  │               │◄──────────────┤                 │                 │
  │               │ FlowEvidence  │                 │                 │
  │               ├───────────────┼────────────────►│                 │
  │               │               │                 │ SNI (fuerza 5)  │
  │               │               │                 │ gana a caché    │
  │               │               │                 │ Traffic (1 s)   │
  │               │               │                 ├────────────────►│
  │               │               │                 │                 │
```

Si el Initial no se puede descifrar (versión desconocida, paquete truncado), la conexión se etiqueta con la caché de nombres (fuerza 4) gracias a la respuesta DNS anterior.

### 4.9 Secuencia — «¿Quién lo usa?»

```
Persona              TUI                Agregador
  │                   │                     │
  │ Enter (app)       │                     │
  ├──────────────────►│                     │
  │                   │ WhoUses(dim,k,w)    │
  │                   ├────────────────────►│
  │                   │                     │ Rankings::who_uses
  │                   │ Vec<DeviceShare>    │
  │                   │◄────────────────────┤
  │                   │ panel abierto       │
  │ Enter (equipo)    │                     │
  ├──────────────────►│                     │
  │                   │ Detalle (F3)        │
  │ Esc               │                     │
  ├──────────────────►│                     │
  │                   │ cierra panel        │
  │                   │                     │
```

---

## 5. API Endpoints (servicios internos)

No hay API HTTP. La fase añade los siguientes servicios internos.

### `inference` (motor)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `FlowInspector::new` | `fn(cfg: &InferenceConfig) -> FlowInspector` | Estado de inspección por interfaz (hilo de captura) |
| `FlowInspector::inspect` | `fn(&mut self, meta: &PacketMeta, payload: &[u8], now: Instant) -> Vec<Evidence>` | Firmas, reensamblado y extractores; devuelve evidencias |
| `LabelResolver::resolve` | `fn(&mut self, flow: &FlowKey, ev: &FlowEvidence) -> FlowLabel` | Nombre, app, categoría y fuentes (§7.8) |
| `LabelResolver::observe_name` | `fn(&mut self, obs: NameObservation)` | Alimenta la caché de nombres |

### `inference::reassembly`, `protocols`, `tls`, `http`, `dns`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `StreamStart::push` | `fn(&mut self, seq: u32, data: &[u8]) -> PushResult` | Inserta un segmento en el inicio del flujo (§7.2) |
| `CryptoStream::push` | `fn(&mut self, offset: u64, data: &[u8]) -> PushResult` | Inserta una trama CRYPTO de QUIC |
| `Protocols::identify` | `fn(l4: L4, ports: (u16, u16), c2s: &[u8], s2c: &[u8]) -> Option<(AppProtocol, Certainty)>` | Firma o puerto (§7.3) |
| `Tls::parse_client_hello` | `fn(&[u8]) -> Result<ClientHello>` | SNI, ALPN, versiones, cifrados, extensiones y algoritmos de firma |
| `Http::parse_request` | `fn(&[u8]) -> Option<HttpRequestInfo>` | `Host` y `User-Agent` |
| `Dns::extract_query` | `fn(&[u8]) -> Option<DnsQuery>` | QNAME de una consulta (heredado de F3) |
| `Dns::extract_answers` | `fn(&[u8]) -> Vec<NameObservation>` | IP → nombre consultado (A/AAAA/CNAME) |

### `inference::quic`, `inference::ja4`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Quic::initial_version` | `fn(&[u8]) -> Option<QuicVersion>` | Detecta un Initial de QUIC v1 o v2 |
| `Quic::decrypt_initial` | `fn(packet: &[u8], v: QuicVersion) -> Result<Vec<u8>>` | Claves, protección de cabecera y AEAD (§7.5) |
| `Ja4::compute` | `fn(hello: &ClientHello, t: Ja4Transport) -> String` | Huella `t…` (TCP) o `q…` (QUIC) |

### `inference::names`, `catalog`, `domain`, `ipdb`, `role`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `NameCache::observe` | `fn(&mut self, obs: NameObservation, now: SystemTime)` | Inserta o refresca una entrada |
| `NameCache::lookup` | `fn(&mut self, ip: IpAddr, requester: Option<IpAddr>, now: SystemTime) -> Option<NameEntry>` | Mejor nombre vigente para la IP (§7.7) |
| `Catalog::load` | `fn(embedded: &str, user_file: Option<&Path>) -> (Catalog, Vec<CatalogWarning>)` | Catálogo embebido + `apps.toml` |
| `Catalog::match_name` | `fn(&self, name: &str) -> Option<&App>` | Gana el sufijo más largo |
| `Catalog::match_asn` | `fn(&self, asn: u32) -> Option<&App>` | Regla por ASN |
| `Catalog::match_port` | `fn(&self, l4: L4, port: u16) -> Option<&App>` | Regla por puerto |
| `Catalog::lan_app` | `fn(&self, service: &str) -> Option<&App>` | App de red local para un servicio de F2 |
| `Domain::registrable` | `fn(name: &str) -> Option<String>` | eTLD+1 con la Public Suffix List |
| `IpDb::embedded` | `fn() -> Result<IpDb>` | Abre las MMDB embebidas |
| `IpDb::lookup` | `fn(&self, ip: IpAddr) -> Option<IpInfo>` | ASN, organización y país (§7.10) |
| `Role::infer` | `fn(flow: &FlowState, meta: &PacketMeta, listening: &ListenSet) -> Option<bool>` | `client_is_src` (§7.1) |

### `identify`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Dhcp::parse` | `fn(&[u8]) -> Option<DhcpInfo>` | Tipo de mensaje, MAC, IP y opciones 12, 50, 55, 60 y 61 |
| `Models::from_mdns_txt` | `fn(service: &str, txt: &[(String, String)]) -> Option<ModelHint>` | Claves `model`, `am`, `md`, `ty`, `rpMd` |
| `Models::from_upnp` | `fn(desc: &UpnpDescription) -> Option<ModelHint>` | Fabricante + modelo de la descripción UPnP |
| `UserAgent::hints` | `fn(ua: &str) -> UaHints` | Pistas de SO y tipo |
| `Identify::os_family` | `fn(signals: &OsSignals) -> (Option<OsFamily>, Option<OsSource>)` | Puntuación combinada con umbral 4 (§7.12) |
| `Mac::is_private` | `fn(mac: MacAddr) -> bool` | Bit U/L activo y unicast |
| `Mac::rotation_match` | `fn(new: &DhcpIdentity, known: &[DeviceIdentity]) -> Option<i64>` | Regla de rotación (§7.13) |
| `ObservedHosts::push` | `fn(&self, host: ObservedHost)` | Desde los hilos de captura |
| `ObservedHosts::drain` | `fn(&self) -> Vec<ObservedHost>` | Desde el ciclo de escaneo |

### `rankings`

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Rankings::record` | `fn(&mut self, label: &FlowLabel, ctx: &FlowCtx, bytes: u64, dir: Dir, now: Instant)` | Suma a cada dimensión |
| `Rankings::tick` | `fn(&mut self, now: Instant)` | Avanza ventanas y desaloja claves |
| `Rankings::top` | `fn(&self, dim: Dimension, w: Window, sort: SortKey, n: usize) -> Vec<RankRow>` | Filas de un ranking |
| `Rankings::who_uses` | `fn(&self, dim: Dimension, key: &str, w: Window) -> Vec<DeviceShare>` | Panel «¿Quién lo usa?» |
| `Rankings::unidentified_share` | `fn(&self, w: Window) -> f32` | % de bytes sin identificar |

### Repo (nuevas o extendidas)

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `Repo::upsert_connection` | `fn(&ConnectionUpsert) -> Result<i64>` | (extendido) persiste también rol, etiquetas y JA4 |
| `Repo::upsert_names` | `fn(&[NameEntry]) -> Result<usize>` | Entradas nuevas o refrescadas de la caché |
| `Repo::list_names` | `fn(now: SystemTime) -> Result<Vec<NameEntry>>` | Entradas vigentes para el arranque en caliente |
| `Repo::prune_names` | `fn(now: SystemTime) -> Result<usize>` | Purga de entradas caducadas |
| `Repo::set_device_identity` | `fn(device_id: i64, upd: &IdentityUpdate) -> Result<()>` | Modelo, campos DHCP, User-Agent, `os_family` y `os_source` |

### Config

| Operación | Firma | Descripción |
|-----------|-------|-------------|
| `config::load` | `fn(path: Option<&Path>) -> Result<Config>` | (extendido) `[inference]`, `[ui].traffic_group` y aviso de claves obsoletas |

---

## 6. Interfaz de Usuario

### Mapa de navegación (novedades de F4)

```
Equipos ──[g]──► plana ⇄ agrupada                                    (F2)
   ├─ Fabricante «MAC privada» para MAC con el bit U/L                (F4)
   └─ Enter ──► Detalle (F3) + identidad, top apps y destinos         (F4)

Tráfico ──[g]──► equipo → destino → app → categoría → protocolo → proceso (F4)
   ├─ w ──► ventana 60 s → 5 min → sesión                             (F4)
   ├─ Enter en equipo ──► Detalle de equipo                           (F3)
   ├─ Enter en proceso ──► Conexiones filtrada por ese proceso        (F4)
   └─ Enter en destino/app/categoría/protocolo ──► «¿Quién lo usa?»   (F4)
         └─ Enter en un equipo ──► Detalle de equipo · Esc cierra

Conexiones ──► Prot. · Equipo · Destino · App · ↑ · ↓ · Edad          (F4)
   ├─ i ──► nombres ⇄ IPs                                             (F4)
   └─ v ──► cabeceras (F3) + rol, fuentes, JA4 y proceso              (F4)

Histórico (placeholder F5) · Alertas (placeholder F6)
Config ──► + [inference], catálogo y bases IP                         (F4)
Ayuda  ──► + teclas, privacidad, modo pasivo y atribución             (F4)
```

### Mockup 1 — Tráfico agrupado por app (80×24)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Ranking por app · ventana 60 s                 [g] app · [w] 60 s          │
├────────────────────────────────────────────────────────────────────────────┤
│ #  App               Categoría   ↓ bajada  ↑ subida  Equipos  60 s         │
│ 1  YouTube           Vídeo       9.1 M/s   120 K/s   2        ▃▅▇▆▅▆▇▅     │
│ 2  Netflix           Vídeo       4.2 M/s   40 K/s    1        ▅▅▆▅▅▆▅▅     │
│ 3  Steam             Juegos      2.0 M/s   15 K/s    1        ▁▂▇█▇▂▁▁     │
│ 4  Compartición SMB  Red local   1.1 M/s   90 K/s    1        ▂▃▂▁▁▂▃▂     │
│ 5  Spotify           Música      320 K/s   8 K/s     1        ▂▂▂▂▂▂▂▂     │
│ 6  iCloud            Nube        40 K/s    210 K/s   2        ▁▁▁▂▅▂▁▁     │
│ 7  WhatsApp          Mensajería  45 K/s    30 K/s    3        ▁▁▂▁▃▁▁▂     │
│ 8  Google Analytics  Rastreo     12 K/s    6 K/s     4        ▁▁▁▁▁▁▁▁     │
│ 9  DNS               Infraestr.  4 K/s     2 K/s     6        ▁▁▁▁▁▁▁▁     │
│ 10 Sin identificar   —           610 K/s   70 K/s    5        ▂▂▃▂▂▂▂▂     │
│                                                                            │
│ Total: ↓ 17.4 M/s · ↑ 0.6 M/s · sin identificar: 3 %                       │
│ Capturando · 2.4 K pps · inferencia: activa · visibilidad: propia+bcast    │
└─[g]agrupar [w]ventana [Enter]¿quién? [s]ordenar [/]buscar [?]ayuda─────────┘
```

### Mockup 2 — Tráfico agrupado por destino con «¿Quién lo usa?»

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Ranking por destino · ventana 5 min         [g] destino · [w] 5 min        │
├────────────────────────────────────────────────────────────────────────────┤
│ #  Destino             Organización · país  ↓ bajada  ↑ subida  Equipos    │
│ 1  googlevideo.com     Google LLC · US      8.7 M/s   110 K/s   2          │
│ 2  nflxvideo.net       Netflix · NL         4.1 M/s   38 K/s    1          │
│ 3  steamcontent.com    Valve · ES           1.9 M/s   14 K/s    1          │
│ 4  nas-synology (LAN)  red local            1.1 M/s   90 K/s    1          │
│ 5  142.250.200.14      Google LLC · ES      620 K/s   9 K/s     1          │
│ 6  icloud.com          Apple Inc. · US      38 K/s    205 K/s   2          │
├── ¿Quién lo usa? googlevideo.com · 5 min ──────────────────────────────────┤
│  [▶] chromecast-sala      6.9 M/s   79 %                                   │
│  [▣] laptop-juan          1.8 M/s   21 %                                   │
├────────────────────────────────────────────────────────────────────────────┤
│ Total: ↓ 16.4 M/s · ↑ 0.5 M/s · sin identificar: 4 %                       │
└─[Enter]detalle [Esc]cerrar panel [g]agrupar [w]ventana [?]ayuda────────────┘
```

### Mockup 3 — Conexiones con app y nombre del servidor

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ─────┐
│ Conexiones activas (47) · vista: nombres · filtro: todas                   │
├────────────────────────────────────────────────────────────────────────────┤
│ Prot  Equipo           Destino               App          ↑     ↓    Edad  │
│ quic  [▣]laptop-juan   rr3---sn-x.googlevid… YouTube      40K   9.1M 5m    │
│ tls   [▣]laptop-juan   github.com            GitHub       12K   200K 2m    │
│ tls   [▯]iPhone-Marta  graph.instagram.com   Instagram    8K    120K 1m    │
│ dns   [▯]iPhone-Marta  1.1.1.1 (Cloudflare)  DNS          1K    2K   1m    │
│ tls   [●]tv-sala       doubleclick.net       Google Ads   3K    1K   4m    │
│ smb   [▣]laptop-juan   nas-synology (LAN)    Compart. SMB 90K   1.1M 1m    │
│ tls   [host]firefox    claude.ai             Claude       30K   400K 9m    │
│ udp   [?]192.168.1.201 52.x.x.x (Amazon, IE) Sin identif. 1K    1K   30s   │
│                                                                            │
│ Destino = lado servidor · [i] nombres/IPs · [v] detalle de la conexión     │
└─[i]IPs [v]detalle [s]ordenar [f]filtrar [/]buscar [x]purgar [?]ayuda───────┘
```

### Mockup 4 — Detalle de equipo (≥ 100 columnas)

```
┌ Equipos ┬ Tráfico ┬ Conexiones ┬ Histórico ┬ Alertas ┬ Config ┬ Ayuda ───────────────────────────┐
│ Equipos (9)          │ Detalle: iPhone-Marta (192.168.1.57)                                      │
│ ──────────────────── │ ────────────────────────────────────────────────────────────────────────  │
│  [⌂] router    14.5M │ [▯]  Apple · móvil · iOS (fuente: modelo) · online (visto 3 s)            │
│  [▣] nas        6.0M │ MAC: 5a:1c:…:9e (MAC privada) · wlan0 · modelo: iPhone15,3                │
│ ▶[▯] iPhone     165K │ DHCP: huella 1,121,3,6,15,108,114,119,252 · nombre «iPhone-de-Marta»      │
│  [▶] chromecast 902K │                                                                           │
│  [▣] laptop     1.7M │ Tráfico                                                                   │
│  [●] tv-sala      4K │ 60 s:  ▁▁▂▁▁▁▁▂▃▅▃▂▁▁▁▂▁▁▁▂▃▂▁▁   ↓ 120 K/s   ↑ 45 K/s   pico 410 K/s     │
│  [P] hp-laser      0 │                                                                           │
│  [?] 192.168…      0 │ Top apps (5 min)                 Top destinos (5 min)                     │
│  ○   iPad          0 │  Instagram      2.1 MB   48 %     cdninstagram.com      1.9 MB            │
│                      │  WhatsApp       0.9 MB   20 %     whatsapp.net          0.9 MB            │
│                      │  iCloud         0.6 MB   14 %     icloud.com            0.6 MB            │
│                      │  Google Ads     0.2 MB    5 %     doubleclick.net       0.2 MB            │
│                      │  Sin identif.   0.6 MB   13 %     17.253.x.x (Apple)    0.3 MB            │
│                      │                                                                           │
│                      │ Clientes TLS (JA4): t13d…h2_…_… (2 distintos)                             │
│                      │ Conexiones activas (12) · Servicios (F2): —                               │
└─[hjkl]mover [Tab]panel [Esc]cerrar [v]conexión [?]ayuda──────────────────────────────────────────┘
```

### Mockup 5 — Ayuda (fragmento actualizado)

```
│ Tráfico                                                                    │
│   g            agrupar: equipo/destino/app/categoría/protocolo/proceso     │
│   w            ventana: 60 s → 5 min → sesión                              │
│   Enter        ¿quién lo usa? (en destino, app, categoría o protocolo)     │
│ Conexiones                                                                 │
│   i            nombres ↔ IPs                                               │
│   v            detalle: cabeceras, rol, fuentes, JA4 y proceso             │
│                                                                            │
│ Inferencia y privacidad                                                    │
│   Almenara lee cabeceras DNS/TLS/HTTP/QUIC y los primeros bytes de cada    │
│   conexión para ponerle nombre. No guarda el contenido. Los dominios son,  │
│   en la práctica, historial de navegación: se borran al cerrarse la        │
│   conexión o al caducar (24 h como máximo). Para desactivarlo:             │
│   [inference] enabled = false                                              │
│                                                                            │
│ Modo                                                                       │
│   pasivo       solo escucha: sin escaneos, sin NetBIOS, sin DNS inverso    │
│                                                                            │
│ Datos: IP Geolocation by DB-IP (db-ip.com), CC BY 4.0 · Public Suffix      │
│ List (Mozilla, MPL 2.0) · Almenara v0.4.0 — Fase 4                         │
└────────────────────────────────────────────────────────────────────────────┘
```

### Notas de UX

- `g` en Tráfico cicla la agrupación y la guarda en `[ui].traffic_group`, igual que `g` en Equipos (F2). `w` cicla la ventana y no se guarda: cada arranque empieza en 60 s.
- Columnas por agrupación:
  - equipo: las de F3, sin cambios;
  - destino: Destino · Organización · país · ↓ · ↑ · Equipos;
  - app: App · Categoría (nombre corto) · ↓ · ↑ · Equipos · sparkline de 60 s;
  - categoría: Categoría · ↓ · ↑ · Apps · Equipos;
  - protocolo: Protocolo · ↓ · ↑ · Conexiones;
  - proceso: Proceso (pid) · ↓ · ↑ · Conexiones (solo tráfico del propio equipo).
- `Enter` en destino, app, categoría o protocolo abre el panel «¿Quién lo usa?» bajo el ranking; `Enter` sobre un equipo del panel abre su detalle (F3) y `Esc` cierra el panel. En proceso, `Enter` abre Conexiones filtrada por ese proceso. En equipo, como en F3.
- El pie del ranking muestra siempre «Sin identificar: N %». Con la inferencia apagada, la barra de estado dice «inferencia: desactivada».
- Sin datos en la ventana: mensaje claro («Sin tráfico en esta ventana» o, sin captura, el de F3).
- Conexiones: `Prot.` muestra `app_protocol` (o `tcp`/`udp` si no se sabe). Equipo es el lado cliente o el de la LAN; Destino, el lado servidor. Sin rol, la fila sale en orden canónico con `?` delante del destino. `i` alterna nombres ⇄ IPs. La columna Estado aparece a partir de 100 columnas.
- `v` añade al panel de F3: rol y su fuente, `server_name` y `name_source`, app, categoría y `app_source`, JA4 y proceso local.
- Detalle de equipo: identidad (modelo, SO y su fuente, huella DHCP abreviada, MAC privada), top 5 apps y top 5 destinos (ventana de 5 min) y clientes TLS (JA4 distintos). Si no cabe, el panel derecho se desplaza con j/k cuando tiene el foco.
- Equipos: la columna Fabricante muestra «MAC privada» en lugar de `?` para MAC con el bit U/L.
- Config: muestra `[inference]`, número de apps (embebidas, propias y avisos del catálogo) y fecha de las bases IP.
- Accesibilidad: la categoría siempre va en texto; los vacíos se muestran con `—`; nada depende solo del color.

---

## 7. Lógica de Negocio

### 7.1 Rol cliente/servidor

La 5-tupla canónica de F3 (ADR-30) ordena los extremos por valor, no por quién inició. F4 guarda el rol aparte en `client_is_src` y no lo inventa: si no se puede deducir, queda en NULL.

```python
def client_is_src(flow, meta, listening, services):
    # 1) TCP: quien envía SYN sin ACK es el cliente (regla más fuerte; no cambia después)
    if meta.proto == 'tcp' and meta.syn and not meta.ack:
        return meta.src == flow.src
    # 2) Socket local en LISTEN (/proc/net/tcp*, ya leído en F3): el host es el servidor
    local = flow.local_endpoint()
    if local and (local.port, flow.proto) in listening:
        return flow.src != local
    # 3) Puerto de servicio en un extremo (< 1024, tabla §7.3 o servicio de F2)
    #    y puerto efímero (>= 32768) en el otro
    if is_service_port(flow.src_port, flow, services) and is_ephemeral(flow.dst_port):
        return False
    if is_service_port(flow.dst_port, flow, services) and is_ephemeral(flow.src_port):
        return True
    # 4) UDP: quien envía el primer datagrama del flujo observado
    if meta.proto == 'udp' and flow.is_new:
        return meta.src == flow.src
    return None
```

Dirección para los rankings: ↓ = servidor → cliente; ↑ = cliente → servidor. Sin rol, ↓ = hacia el extremo de la LAN; entre dos equipos de la LAN sin rol, se usa el orden canónico.

### 7.2 Reensamblado del inicio de flujo

- TCP, cliente → servidor: hasta **4 KB** desde el primer byte de datos (número de secuencia relativo al SYN si se vio; si no, al primer segmento). Admite segmentos desordenados dentro de esa ventana y descarta duplicados.
- TCP, servidor → cliente: los primeros **64 B** (protocolos que saludan primero: SSH, FTP, SMTP, IMAP, POP3, VNC).
- Se cierra al completar el mensaje (registro TLS o petición HTTP completos), al llegar a 4 KB, a los **8 paquetes** con datos o a los **3 s**.
- Tope de **1024** reensamblados simultáneos por interfaz; por encima, el flujo nuevo se etiqueta sin inspección y suma un contador (`reassembly_drops`).
- QUIC: las tramas CRYPTO se recomponen por offset hasta 4 KB, con un máximo de 4 paquetes Initial o 3 s.
- Ningún buffer sale del hilo de captura ni se guarda: tras extraer la etiqueta, se libera.

Motivo: con el intercambio de claves post-cuántico que ya usan Chrome y Firefox, el ClientHello no cabe en un segmento y el SNI puede ir en el segundo.

### 7.3 Protocolos de aplicación (firmas)

Primero manda la firma de los primeros bytes; si no hay firma, el puerto da un protocolo provisional. Valores de `app_protocol`:

| Valor | Transporte y puerto típico | Firma |
|-------|----------------------------|-------|
| `dns` | UDP/TCP 53 | Cabecera DNS válida (opcode 0, QDCOUNT ≥ 1) |
| `mdns` | UDP 5353 | Cabecera DNS en 5353 |
| `llmnr` | UDP 5355 | Cabecera DNS en 5355 |
| `netbios` | UDP 137/138, TCP 139 | NBNS, NBDS o sesión NetBIOS |
| `dhcp` | UDP 67/68 | Cookie mágica `63 82 53 63` |
| `dhcpv6` | UDP 546/547 | Tipo de mensaje 1–13 |
| `ntp` | UDP 123 | 48 bytes, versión 3–4, modo válido |
| `ssdp` | UDP 1900 | `M-SEARCH * HTTP/1.1`, `NOTIFY * HTTP/1.1` o `HTTP/1.1 200` |
| `tls` | TCP | Registro `16 03 0x` (handshake) |
| `quic` | UDP | Cabecera larga con bit fijo y versión 1 o 2; los paquetes cortos heredan la marca del flujo |
| `http` | TCP | Método (`GET `, `POST `, `HEAD `, `PUT `, `DELETE `, `OPTIONS `, `PATCH `) o `HTTP/1.` |
| `http2` | TCP | Preámbulo `PRI * HTTP/2.0` (h2c en claro) |
| `ssh` | TCP | `SSH-2.0-` o `SSH-1.99-` en cualquiera de los sentidos |
| `rdp` | TCP 3389 | TPKT `03 00` + X.224 Connection Request |
| `vnc` | TCP 5900–5909 | `RFB 003.` del servidor |
| `smb` | TCP 445/139 | `FF 53 4D 42` o `FE 53 4D 42` tras la cabecera NetBIOS |
| `ftp` | TCP 21 | Saludo `220` del servidor + `USER` o `AUTH` |
| `smtp` | TCP 25/587 | Saludo `220` + `EHLO` o `HELO` |
| `imap` | TCP 143 | `* OK` del servidor |
| `pop3` | TCP 110 | `+OK` del servidor |
| `mqtt` | TCP 1883 | CONNECT (`0x10`) con `MQTT` o `MQIsdp` |
| `coap` | UDP 5683 | Versión 1, tipo y código válidos |
| `rtsp` | TCP 554 | `OPTIONS rtsp://`, `DESCRIBE rtsp://` o `RTSP/1.0` |
| `sip` | UDP/TCP 5060 | `INVITE sip:`, `REGISTER sip:` o `SIP/2.0` |
| `stun` | UDP | Cookie mágica `21 12 A4 42` en los bytes 4–7 |
| `wireguard` | UDP | Tipo 1–4 con 3 bytes reservados a cero y tamaño 148, 92, 64 o ≥ 32 |
| `openvpn` | UDP/TCP 1194 | Opcode `P_CONTROL_HARD_RESET_CLIENT_V2` o `_V3` |
| `ipsec` | UDP 500/4500 | Cabecera IKEv2 (versión `0x20`) |
| `bittorrent` | TCP/UDP | `\x13BitTorrent protocol` o DHT `d1:ad2:id20:` |
| `snmp` | UDP 161/162 | BER `SEQUENCE` + versión 0, 1 o 3 |

Sin firma ni puerto conocido, `app_protocol` toma el valor de transporte (`tcp`, `udp`, `icmp`). La firma siempre gana al puerto (un `ssh` en el puerto 443 es `ssh`).

### 7.4 TLS: SNI y JA4

- Se parsea el ClientHello completo (tras el reensamblado): SNI, ALPN, `supported_versions`, cifrados, extensiones y `signature_algorithms`.
- El SNI se normaliza (minúsculas, sin punto final, máx. 255) y alimenta `server_name` y la caché de nombres (`source = 'sni'`).
- JA4 de cliente según la especificación pública de FoxIO; los vectores de prueba oficiales mandan en los casos límite (ALPN no alfanumérico, listas vacías):

```python
def ja4(hello, transport):                    # transport: 't' (TCP) o 'q' (QUIC)
    versions = [v for v in hello.supported_versions if not grease(v)]
    ver = VERSION_CODE[max(versions) if versions else hello.legacy_version]   # '13', '12'…
    sni = 'd' if hello.sni else 'i'
    ciphers = [c for c in hello.ciphers if not grease(c)]
    exts = [e for e in hello.extensions if not grease(e)]
    alpn = (hello.alpn[0][0] + hello.alpn[0][-1]) if hello.alpn else '00'
    a = f"{transport}{ver}{sni}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}"
    b = sha256(",".join(sorted(f"{c:04x}" for c in ciphers)))[:12]
    rest = sorted(f"{e:04x}" for e in exts if e not in (0x0000, 0x0010))   # sin SNI ni ALPN
    sigs = [f"{s:04x}" for s in hello.signature_algorithms]                # en su orden
    c = sha256(",".join(rest) + ("_" + ",".join(sigs) if sigs else ""))[:12]
    return f"{a}_{b}_{c}"
```

- JA3 no se calcula. JA4 se guarda en `CONNECTIONS.ja4` y se muestra en `v` y en el detalle; no hay base de firmas en F4.

### 7.5 QUIC Initial

- Solo se tratan paquetes de cabecera larga de tipo Initial de QUIC v1 (RFC 9000/9001) y v2 (RFC 9369, con otro valor de tipo y otra sal).
- Claves: se derivan del Destination Connection ID del primer Initial del cliente, como describe RFC 9001 §5.2 (v1) y RFC 9369 §3.3 (v2):

```python
def initial_keys(dcid, version):
    salt   = SALT_V1 if version == 1 else SALT_V2          # constantes de los RFC
    prefix = b"quic" if version == 1 else b"quicv2"
    initial = hkdf_extract(sha256, salt, dcid)
    client  = hkdf_expand_label(initial, b"client in", 32)
    key = hkdf_expand_label(client, prefix + b" key", 16)
    iv  = hkdf_expand_label(client, prefix + b" iv", 12)
    hp  = hkdf_expand_label(client, prefix + b" hp", 16)
    return key, iv, hp

def hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return hkdf_expand(sha256, secret, info, length)
```

- Protección de cabecera: muestra de 16 bytes a partir de `pn_offset + 4`, máscara AES-ECB con `hp`, se desenmascaran los 4 bits bajos del primer byte y el número de paquete. Payload: AES-128-GCM con nonce `iv XOR pn` y la cabecera como AAD.
- Se leen las tramas CRYPTO (y se ignoran PADDING, PING y ACK); el ClientHello se recompone por offset (§7.2) y pasa por `Tls::parse_client_hello`. JA4 con prefijo `q`.
- Prueba obligatoria: el paquete Initial de cliente del apéndice A de RFC 9001 se descifra y produce el ClientHello esperado.
- Fallos (versión desconocida, descifrado fallido, paquete truncado): se descarta el paquete sin error visible y se suma un contador.

### 7.6 HTTP en claro

- Solo HTTP/1.x: línea de petición + cabeceras hasta `\r\n\r\n` dentro de los 4 KB reensamblados.
- `Host` (sin puerto, normalizado) → `server_name` (`name_source = 'http'`) y caché de nombres.
- `User-Agent` → identificación del equipo cliente (§7.12), saneado (solo imprimibles) y truncado a 256.

### 7.7 Caché de nombres

```python
def on_dns_response(msg, client_ip, now):
    if not msg.is_response or msg.rcode != 0 or msg.truncated:
        return
    qname = normalize(msg.questions[0].name)          # el nombre que pidió el equipo
    for rr in msg.answers:
        if rr.type in ('A', 'AAAA'):                   # aunque llegue tras una cadena CNAME
            ttl = clamp(rr.ttl, 3600, 86400)           # entre 1 h y 24 h
            cache.observe(ip=rr.address, name=qname, source='dns',
                          requester=client_ip, expires=now + ttl)
```

- SNI y `Host` también se apuntan (`source = 'sni'` y `'http'`) con caducidad de 1 h.
- Cada uso para etiquetar un flujo nuevo refresca `last_seen` y lleva `expires_at` a `max(expires_at, ahora + 1 h)`, sin pasar de 24 h desde la última observación.
- Varias entradas por IP (CDN): gana la consultada por el mismo equipo cliente (dato en memoria) y, si no, la más reciente.
- Tope de **10 000** entradas; al llenarse se desaloja la de `last_seen` más antiguo.
- Persistencia: entradas nuevas o refrescadas cada 5 s (`Repo::upsert_names`); al arrancar se cargan las vigentes (`Repo::list_names`) sin el dato del equipo que preguntó; purga cada 5 s (`Repo::prune_names`).

### 7.8 Resolución de la etiqueta

```python
FUERZA = {('domain', 'sni'): 5, ('domain', 'http'): 5, ('domain', 'cache'): 4,
          'lan_service': 3, 'asn': 2, 'port': 1}

def resolve(flow, ev, names, catalog, ipdb, f2_services):
    srv_ip, srv_port = flow.server_endpoint()        # según el rol; sin rol, extremo remoto
    if ev.sni:                 name, name_src = ev.sni, 'sni'
    elif ev.http_host:         name, name_src = ev.http_host, 'http'
    elif e := names.lookup(srv_ip, requester=flow.client_ip()):
                               name, name_src = e.name, 'cache'
    else:                      name, name_src = None, None

    if name and (app := catalog.match_name(name)):
        src, fuerza = 'domain', FUERZA[('domain', name_src)]
    elif flow.is_lan_to_lan() and (s := f2_services.get(srv_ip, srv_port)) \
            and (app := catalog.lan_app(s)):
        src, fuerza = 'lan_service', FUERZA['lan_service']
    elif (info := ipdb.lookup(srv_ip)) and (app := catalog.match_asn(info.asn)):
        src, fuerza = 'asn', FUERZA['asn']
    elif app := catalog.match_port(flow.l4, srv_port):
        src, fuerza = 'port', FUERZA['port']
    else:
        app, src, fuerza = None, None, 0

    label = Label(ev.app_protocol, name, name_src, app, src, ev.ja4)
    return label if fuerza > flow.label_strength else flow.label   # solo sube
```

- El nombre se guarda aunque no case en el catálogo (sirve para el ranking por destino).
- Con `[inference].enabled = false` no hay `ev.sni`, `ev.http_host` ni respuestas DNS: solo quedan servicio de F2, ASN, puerto y proceso.
- El cambio de etiqueta de un flujo se persiste en el siguiente ciclo de 5 s.

### 7.9 Catálogo de apps y categorías

**Formato** (`data/catalogo.toml`, embebido; `apps.toml` del usuario con la misma estructura):

```toml
[[category]]
key = "streaming"
name = "Vídeo y streaming"
short = "Vídeo"

[[app]]
key = "youtube"
name = "YouTube"
category = "streaming"
domains = ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be"]
asn = []                 # opcional
ports = []               # opcional, p. ej. ["udp/27015-27050"]
# origen: <de dónde sale la regla>   ← obligatorio en cada app embebida
```

**Reglas:**
- Un dominio casa consigo mismo y con sus subdominios; gana el **sufijo más largo** (`music.youtube.com` → YouTube Music antes que `youtube.com` → YouTube).
- Los dominios compartidos por varios servicios de un proveedor (`googleapis.com`, `gstatic.com`, `akamaized.net`…) van a una app genérica del proveedor o de CDN, nunca a una app concreta.
- Las reglas por ASN solo se usan para ASN exclusivos de un servicio (p. ej. Netflix) o para apps genéricas de proveedor (Infraestructura).
- `apps.toml`: una app con la misma clave que una embebida la **sustituye entera**; una clave nueva se añade. Una entrada inválida se avisa y se ignora sin descartar el resto. Máximo 500 apps propias.

**Categorías** (12 + dos especiales):

| Clave | Nombre | Corto |
|-------|--------|-------|
| `streaming` | Vídeo y streaming | Vídeo |
| `music` | Música y audio | Música |
| `social` | Redes sociales | Social |
| `messaging` | Mensajería | Mensajería |
| `calls` | Videollamadas | Llamadas |
| `games` | Juegos | Juegos |
| `system` | Sistema y actualizaciones | Sistema |
| `cloud` | Nube y copias | Nube |
| `work` | Trabajo y desarrollo | Trabajo |
| `web` | Navegación, compras y banca | Web |
| `tracking` | Publicidad, rastreo y telemetría | Rastreo |
| `infrastructure` | Infraestructura | Infraestr. |
| `lan` | Red local (especial: servicios de F2) | Red local |
| — | Sin identificar (app y categoría NULL) | — |

**Lista mínima de apps (162):**

- **Vídeo y streaming (14):** YouTube, Netflix, Prime Video, Disney+, Max, Twitch, Movistar Plus+, RTVE Play, Atresplayer, Mitele, DAZN, Filmin, SkyShowtime, Apple TV+.
- **Música y audio (8):** Spotify, Apple Music, Amazon Music, YouTube Music, Deezer, Tidal, SoundCloud, iVoox.
- **Redes sociales (10):** Facebook, Instagram, TikTok, X, LinkedIn, Reddit, Pinterest, Snapchat, Bluesky, Threads.
- **Mensajería (7):** WhatsApp, Telegram, Signal, Messenger, Discord, Google Messages, Viber.
- **Videollamadas (6):** Zoom, Microsoft Teams, Google Meet, FaceTime, Webex, Jitsi Meet.
- **Juegos (11):** Steam, Epic Games, PlayStation Network, Xbox Network, Nintendo, Battle.net, Riot Games, EA, Ubisoft Connect, Roblox, Minecraft.
- **Sistema y actualizaciones (12):** Windows Update, Microsoft Store, Actualizaciones de Apple, App Store, Google Play, Servicios de Google Play, Arch Linux, Debian y Ubuntu, Fedora, Flathub, Snap Store, Actualizaciones de Firefox.
- **Nube y copias (10):** iCloud, Google Drive y Fotos, OneDrive, Dropbox, MEGA, Proton Drive, Backblaze B2, Synology, Cloudflare R2, Hetzner Storage Box.
- **Trabajo y desarrollo (17):** Microsoft 365, Google Workspace, Proton Mail, Notion, Slack, GitHub, GitLab, Codeberg, Atlassian, Figma, Claude, ChatGPT, Gemini, DeepSeek, OpenRouter, Docker Hub, Registros de paquetes (crates.io, PyPI, npm).
- **Navegación, compras y banca (21):** Google (búsqueda), Bing, DuckDuckGo, Wikipedia, Amazon, AliExpress, Temu, Wallapop, Vinted, PayPal, BBVA, Santander, CaixaBank, ING, Sabadell, Revolut, Glovo, Just Eat, Uber Eats, Booking, Idealista.
- **Publicidad, rastreo y telemetría (18):** Google Ads, Google Analytics, Meta (píxel y anuncios), Amazon Ads, Microsoft Ads y Clarity, Criteo, Taboola, TikTok (analítica), Hotjar, Atribución móvil (Adjust, AppsFlyer, Branch), Firebase y Crashlytics, Sentry, Telemetría de Windows, Telemetría de Apple, Telemetría de Samsung TV, Telemetría de LG TV, Telemetría de Xiaomi, Telemetría de Amazon (Alexa y Fire TV).
- **Infraestructura (18):** DNS, DNS cifrado (DoH/DoT), NTP, Comprobación de conectividad, Certificados (OCSP/CRL), Notificaciones de Apple (APNs), Notificaciones de Google (FCM), CDN Cloudflare, CDN Akamai, CDN Fastly, Amazon Web Services, Google Cloud, Microsoft Azure, Hetzner, Servicios de Google, Servicios de Meta, Servicios de Microsoft, Servicios de Apple.
- **Red local (10):** Compartición de archivos (SMB/NFS), Impresión (IPP/LPD), AirPlay, Google Cast, Escritorio remoto (RDP/VNC), SSH, Domótica (MQTT/CoAP/Home Assistant), Cámaras (RTSP/ONVIF), UPnP/DLNA, Servidor multimedia (Plex/Jellyfin).

La lista de rastreo y telemetría es corta y propia: no se copian listas públicas de bloqueo (licencias GPL o CC BY-NC-SA). Los dominios de telemetría de televisores y del resto de apps los cura el agente, cada regla con su comentario de origen y con pruebas de precedencia.

### 7.10 Destinos: dominio registrable, organización y país

- **Clave de destino** en los rankings: el dominio registrable del `server_name` si existe (`psl`; `rr3---sn-x.googlevideo.com` → `googlevideo.com`); si no, la IP remota; si el servidor es un equipo de la LAN, el propio equipo (`lan:<device_id>`, mostrado con su nombre).
- **Organización y país:** `IpDb::lookup` sobre las MMDB embebidas (IPv4 e IPv6). No se consulta para IPs privadas, de enlace local, loopback, multicast ni la propia.
- Se muestra «Organización · país» junto a las IPs sin nombre y en el ranking por destino.
- **Sin red:** la app nunca descarga bases. `scripts/actualizar-bases-ip.sh` (solo desarrollo) sustituye las MMDB y actualiza `data/FUENTES.md` con fecha y licencia; la base se renueva con cada versión, como la OUI.
- **Atribución obligatoria** (CC BY 4.0): «IP Geolocation by DB-IP» con enlace a db-ip.com en Ayuda, README y `data/FUENTES.md`.
- **Nunca DNS inverso de IPs de Internet** (ADR-52).

### 7.11 Rankings

- **Dimensiones:** `device` (F3, incluida la fila `[host]` de ADR-32), `destination`, `app`, `category`, `protocol` y `process` (solo tráfico del propio equipo, con la atribución de proceso de F3).
- **Métricas por clave:** bytes ↓ y ↑ por ventana (60 s con 1 punto/s, 5 min con 1 punto/5 s, reutilizando las ventanas de F3) y acumulado de sesión; pico de 60 s; equipos distintos en la ventana; conexiones activas.
- **Orden por defecto:** total de bytes en la ventana; `s` cicla ↓, ↑, total y equipos.
- **% sin identificar:** bytes con app NULL / bytes totales de la ventana.
- **Topes:** 2048 claves por dimensión; al superarlo se desalojan las claves sin bytes en 5 min, primero las más antiguas (su acumulado de sesión se pierde). Al cerrar la app no se guarda nada: el histórico es F5.
- **Publicación:** cada segundo, top 50 por dimensión y ventana dentro de `AppEvent::Traffic`; «¿Quién lo usa?» se pide con `TrafficCommand::WhoUses` y se calcula al momento.

### 7.12 Identificación de equipos

**Señales nuevas:**

| Señal | De dónde sale | Aporta |
|-------|---------------|--------|
| Huella DHCP | Paquetes DHCP capturados: opción 55 (orden de la lista), opción 60, opción 12 | `dhcp_fingerprint`, `dhcp_vendor`, `dhcp_hostname`, pista de SO |
| Modelo | TXT de mDNS (`model`, `am`, `md`, `ty`, `rpMd`) y descripción UPnP de F2 | `model`, pista de SO y de tipo |
| User-Agent | Peticiones HTTP en claro del equipo | `user_agent`, pista de SO y de tipo |

**Puntuación de `os_family`:** se suman los puntos de cada señal a la de F2 (TTL y opciones TCP) con el mismo umbral 4; empates → NULL. `os_source` guarda la señal que más aportó al ganador.

```python
REGLAS = [
    # (señal, condición, sistema, puntos)
    ('dhcp',  vendor_startswith('MSFT 5.0'),       'windows', 4),
    ('dhcp',  vendor_startswith('android-dhcp-'),  'android', 4),
    ('dhcp',  vendor_contains('dhcpcd') & 'Linux', 'linux',   3),
    ('dhcp',  vendor_startswith('udhcp'),          'iot',     4),
    ('dhcp',  prl_matches(APPLE_PRL),              'macos',   2),   # y 'ios' 2: desempata el modelo
    ('model', model_prefix('MacBook', 'iMac', 'Macmini', 'MacPro', 'Mac1'), 'macos', 5),
    ('model', model_prefix('iPhone', 'iPad'),      'ios',     5),
    ('ua',    ua_contains('Windows NT'),           'windows', 4),
    ('ua',    ua_contains('iPhone OS', 'CPU OS'),  'ios',     4),
    ('ua',    ua_contains('Android'),              'android', 4),
    ('ua',    ua_contains('Macintosh'),            'macos',   3),   # un iPad en modo escritorio también lo envía
    ('ua',    ua_linux_sin_android(),              'linux',   3),
]
```

Las reglas de huella DHCP (patrones de la opción 55 incluidos) son propias, pocas y documentadas: cada una con su origen y una prueba con un paquete real o sintético descrito en el test.

**Tipo de equipo:** reglas por modelo antes que las de hostname de F2: `Mac…` → `pc`; `iPhone…` → `mobile`; `iPad…` → `tablet`; `AppleTV…` → `streaming`; `AudioAccessory…` → `iot`; `md=Chromecast` → `streaming`; impresoras (`ty`) → `printer`; User-Agent de TV (`Tizen`, `Web0S`, `SMART-TV`) → `tv`. Se mantienen el clasificador con memoria y el override manual de F2.

**Hostname:** el nombre DHCP capturado entra al nivel de «DHCP lease» de la precedencia de F2, y el nombre amigable de Google Cast (`fn`) al nivel de mDNS.

### 7.13 MAC privadas y `mac_changed` v2

- **MAC privada:** bit U/L activo (`primer octeto & 0x02`) y unicast (`& 0x01 == 0`). La columna Fabricante muestra «MAC privada» y el evento `new` lleva `"mac_random": true` en sus detalles.
- **Regla A — rotación:** si aparece una MAC privada desconocida con huella y nombre DHCP, y hay **un único** equipo con MAC privada, no visto en el ciclo y con la misma huella y el mismo nombre DHCP, se cambia la MAC de ese equipo y se emite `mac_changed` con `"reason": "rotation"`. Con varios candidatos, equipo nuevo.
- **Regla B — toma de IP (heurística de F1):** se mantiene, pero no se aplica si los dos equipos tienen huella DHCP y es distinta; en ese caso, equipo nuevo. El evento lleva `"reason": "ip_takeover"`.
- Sin evidencia DHCP, una rotación de MAC sigue apareciendo como `new` con `mac_random`, para que F6 pueda bajar su severidad.

```python
def rotation_match(new, known):
    if not (is_private(new.mac) and new.dhcp_fingerprint and new.dhcp_hostname):
        return None
    cands = [d for d in known
             if is_private(d.mac) and not d.seen_this_cycle
             and d.dhcp_fingerprint == new.dhcp_fingerprint
             and d.dhcp_hostname == new.dhcp_hostname]
    return cands[0].id if len(cands) == 1 else None
```

### 7.14 Equipos observados en la captura

- **Fuentes:** ARP (petición, respuesta o gratuito: MAC e IP del emisor), DHCP (MAC del cliente con `ciaddr` o con el `yiaddr` de un ACK visible) y tramas IPv4 con MAC de origen e IP de origen de una subred local.
- **Se descartan:** MAC propias, de grupo o broadcast; IP 0.0.0.0, broadcast o propia; IP fuera de las subredes de las interfaces; la MAC del gateway con una IP que no es la del gateway.
- **Buffer:** `ObservedHosts`, con deduplicación por MAC + IP y tope de 4096 por ciclo (por encima, descarte con contador).
- **Fusión:** el ciclo de escaneo vacía el buffer y lo trata como una fuente L2 más (`DISCOVERY_SOURCES.source = 'capture'`): puede crear equipos (evento `new`), cuenta como «visto» para el marcado offline y aporta identidad DHCP.
- Funciona con `passive_only` (solo escucha) y no sin `CAP_NET_RAW` (no hay captura). Con `[inference].enabled = false`, el ARP y las tramas siguen valiendo; el DHCP no se lee.

### 7.15 Modo pasivo redefinido

| Mecanismo | Normal | `passive_only` |
|-----------|--------|----------------|
| ARP scan, ICMP sweep, mDNS browse, M-SEARCH, port scan, banner, fingerprint activo | Sí (con `CAP_NET_RAW`) | No |
| Consultas NetBIOS (NBNS) | Sí | **No (F4)** |
| DNS inverso de IPs de la LAN | Sí | **No (F4)** |
| DNS inverso de IPs de Internet | **Nunca (F4)** | **Nunca** |
| `/proc/net/arp`, leases DHCP, escucha mDNS/SSDP, captura e inferencia | Sí | Sí |

- Pasivo significa no consultar a nadie. Las uniones multicast que hace el sistema para escuchar mDNS y SSDP no cuentan como consulta.
- Precedencia de hostname en pasivo: alias > mDNS > DHCP (lease o capturado) > último conocido.
- La barra de estado y la Ayuda listan las fuentes del modo pasivo sin NetBIOS y con la captura.

### 7.16 Configuración y validación

```toml
[inference]
enabled   = true                               # leer DNS/TLS/HTTP/QUIC para etiquetar (el contenido no se guarda)
apps_file = "~/.config/almenara/apps.toml"     # reglas propias (opcional)

[ui]
traffic_group = "device"   # device | destination | app | category | protocol | process
```

- `enabled`: booleano; `true` por defecto.
- `apps_file`: si no existe, aviso informativo y se ignora; si no se puede leer o parsear, aviso y se ignora el fichero entero; entradas inválidas, aviso y se ignora solo esa entrada.
- Entradas de `apps.toml`: `key` con `^[a-z0-9_]{1,32}$`; `name` no vacío y de 40 caracteres como máximo; `category` existente o definida en el mismo fichero; dominios en minúsculas sin esquema ni comodines; `asn` u32; `ports` como `tcp/443` o `udp/27015-27050`.
- `traffic_group` inválido → `device` con aviso.
- Claves de F3 `[capture].inspect_payload`, `dns_attribution` y `sni_attribution`: se ignoran con un aviso único («la inferencia se controla con `[inference].enabled`»), sin reescribir el fichero del usuario.
- La plantilla de configuración por defecto incluye `[inference]` y `[ui].traffic_group`.

---

## 8. Requisitos No Funcionales

### Seguridad

- Parsers expuestos a tráfico hostil: comprobación de límites en cada lectura, sin `unwrap` sobre datos de red ni pánicos; pruebas con entradas truncadas y aleatorias para firmas, TLS, QUIC, HTTP, DNS y DHCP.
- Longitudes máximas: SNI y `Host` 255, User-Agent 256, campos DHCP 64, CRYPTO y reensamblado 4 KB, Initial de QUIC 1500 B.
- El descifrado QUIC solo usa claves públicas derivables del propio paquete: no hay secretos que proteger ni claves que guardar.
- Sin puertos nuevos ni accesos a red de la aplicación (las bases IP se actualizan con un script de desarrollo).
- `apps.toml` se valida entrada a entrada; un fichero malicioso no puede ejecutar nada ni bloquear el arranque.

### Protección de datos (RGPD)

- Se persisten solo **etiquetas derivadas**: `server_name`, app, categoría, protocolo, JA4, User-Agent truncado, campos DHCP y modelo. El payload no se persiste nunca (regla dura de F3).
- Reensamblados y payload QUIC descifrado se descartan en el hilo de captura justo después de extraer la etiqueta.
- Los dominios por equipo son, en la práctica, historial de navegación: solo viven en tablas calientes (`CONNECTIONS`, purga por timeout de F3; `NAME_CACHE`, caducidad ≤ 24 h) y en memoria (rankings, que se pierden al cerrar). El histórico lo decidirá F5.
- **Logs:** nombres de dominio, SNI, `Host` y User-Agent solo a nivel `debug` (no con `-v`); nunca en `info`, `warn` ni `error`, que registran recuentos y no contenido.
- `[inference].enabled = false` desactiva todo lo que lee por encima de las cabeceras de transporte (salvo ARP, que es L2).
- Uso personal y doméstico; aviso en Ayuda de qué se lee y cómo desactivarlo, además del aviso de F1 sobre redes ajenas.
- Atribución de DB-IP (CC BY 4.0) en Ayuda, README y `data/FUENTES.md`.

### Backups y recuperación

- Sin cambios: `NAME_CACHE` es caliente y se puede perder sin consecuencias; los datos embebidos viven en el repositorio (`data/`).

### Rendimiento

- Captura sostenida de **50 K pps** sin pérdidas con la inferencia activa (objetivo de F3 mantenido).
- CPU **≤ 20 % a 10 K pps** y **≤ 7 % a 1 K pps** con la inferencia activa.
- Inspección solo en los primeros paquetes de cada flujo; el resto solo suma bytes.
- Memoria añadida por la fase **≤ 64 MB** (reensamblados ≤ 1024 × 4 KB por interfaz, caché de nombres ≤ 10 000 entradas, rankings ≤ 2048 claves por dimensión).
- Carga del catálogo y apertura de las MMDB al arrancar **≤ 200 ms**; búsqueda en base IP y PSL en microsegundos.
- Render sin cambios: ≤ 16 ms en 80×24 y ≤ 33 ms en 120×40.
- Binario: **≤ 25 MB** más por los datos embebidos.

### Accesibilidad

- Sin cambios de nivel (WCAG 2.1 AA en lo aplicable a TUI). Categorías y estados siempre en texto; nada depende solo del color; las columnas nuevas caben en 80 columnas.

---

## 9. Integraciones

- **DB-IP Lite** (IP to ASN Lite e IP to Country Lite): publicación mensual en CSV y MMDB, licencia CC BY 4.0 con atribución obligatoria. Se embeben las MMDB y se registran fecha y origen en `data/FUENTES.md`.
- **Public Suffix List** (Mozilla, MPL 2.0) a través del crate `psl`; se actualiza con la versión del crate.
- **JA4:** especificación pública de FoxIO. JA4 de cliente TLS tiene licencia BSD-3 y FoxIO declara no buscar patentes sobre él; el resto de JA4+ (JA4S, JA4H, JA4T…) va bajo la FoxIO License 1.1 y no se implementa.
- **Protocolos:** QUIC (RFC 9000, 9001 y 9369), TLS 1.3 ClientHello (RFC 8446), DNS (RFC 1035), DHCP (RFC 2131 y 2132), mDNS/DNS-SD (RFC 6762 y 6763).
- **Vectores de prueba:** apéndice A de RFC 9001 (Initial de cliente) y vectores oficiales de JA4.

---

## 10. Decisiones Técnicas (ADR-lite)

La numeración de ADR es única en todo el proyecto: F3 llegó a la ADR-33, la v1.2 de F1 renumeró sus ADR-08 a 10 como ADR-34 a 36, y F4 empieza en la ADR-37.

**ADR-37 · Inferencia activa por defecto con etiqueta derivada (modifica ADR-20)**
Sin leer cabeceras DNS/TLS/HTTP/QUIC y los primeros bytes de cada flujo, F4 solo tendría puertos y organización. Se mantiene la regla dura de ADR-20: el payload nunca se persiste. `[inference].enabled = false` lo apaga. Descartados: seguir en opt-in (F4 vacía por defecto) y guardar payload para reanálisis (riesgo legal).

**ADR-38 · Reensamblado acotado del inicio de flujo (vs. solo el primer segmento, vs. reensamblado completo)**
Con el intercambio de claves post-cuántico de Chrome y Firefox, el ClientHello ocupa más de un segmento y el SNI puede ir en el segundo. Reensamblar todo el flujo es caro y no aporta nada a la etiqueta. Se reensamblan 4 KB cliente → servidor y 64 B servidor → cliente, con topes de paquetes, tiempo y flujos.

**ADR-39 · SNI de QUIC descifrando el Initial con RustCrypto (vs. ignorar QUIC, vs. `ring` u OpenSSL)**
Gran parte de Google, YouTube y Meta va por QUIC; sin el Initial solo quedaría la caché DNS. Las claves Initial se derivan del DCID (RFC 9001 y 9369), así que cualquier observador puede leer el ClientHello. RustCrypto es Rust puro y mantiene el binario único; `ring` añade C y ensamblador, y OpenSSL una dependencia del sistema.

**ADR-40 · JA4 de cliente sin base de firmas (vs. JA3, vs. JA4+ completo)**
JA3 dejó de ser estable cuando Chrome empezó a barajar el orden de las extensiones; JA4 las ordena. JA4 de cliente es BSD-3; el resto de JA4+ va bajo una licencia que no permite monetizar, así que no se implementa. Se calcula y se muestra; la base de firmas y su uso en alertas quedan para F6.

**ADR-41 · Caché IP → nombre con respuestas DNS, SNI y Host (vs. solo consultas, vs. PTR)**
F3 solo leía consultas, que no dicen qué IP corresponde a qué nombre; las respuestas sí, y `hickory-proto` ya está en el stack. El PTR de IPs remotas genera tráfico, revela los destinos al resolvedor y suele devolver nombres genéricos del proveedor.

**ADR-42 · Catálogo propio embebido + `apps.toml` (vs. nDPI, vs. listas públicas de rastreadores)**
nDPI es C (LGPL) y rompería el binario único; sus listas no se pueden copiar sin heredar la licencia. Las listas públicas de rastreadores tienen licencias variadas (GPL, CC BY-NC-SA). Un catálogo propio de unas 160 apps, con origen por regla y ampliable por el usuario, basta para una red doméstica.

**ADR-43 · DB-IP Lite en MMDB con `maxminddb` (vs. iptoasn, vs. MaxMind GeoLite2, vs. formato propio)**
DB-IP Lite se publica cada mes en CSV y MMDB con CC BY 4.0 (exige atribución). iptoasn es de dominio público, pero su país es el del registro del sistema autónomo, no el de la IP. GeoLite2 exige cuenta y tiene licencia propia. MMDB + `maxminddb` (Rust puro) evita escribir formato y buscador propios. Coste: varios MB más en el binario y en el repositorio en cada actualización.

**ADR-44 · Destinos agrupados por dominio registrable con `psl` (vs. FQDN, vs. ASN)**
El FQDN fragmenta (cada servidor de vídeo es un nombre distinto) y el ASN mezcla servicios del mismo proveedor. La Public Suffix List compilada en `psl` da el dominio registrable sin descargas; se actualiza con el crate.

**ADR-45 · Rol cliente/servidor en columna aparte (vs. reordenar la 5-tupla)**
ADR-30 ordena la 5-tupla por valor para que ida y vuelta compartan fila; cambiarlo rompería las conexiones existentes. Se añade `client_is_src`, deducido del SYN, de los sockets en escucha o de los puertos, y NULL si no se sabe (como ADR-31 no inventa estados TCP).

**ADR-46 · Rankings en memoria con las ventanas de F3 + acumulado de sesión (vs. persistirlos, vs. 1 h y 24 h ya)**
Persistir rankings es hacer rollups, que es F5. Las ventanas de 1 h y 24 h necesitan persistencia continua. El acumulado desde el arranque cubre «qué ha pasado hoy» mientras tanto.

**ADR-47 · Sin pestaña nueva: `g` agrupa en Tráfico (vs. pestaña «Apps»)**
Una octava pestaña rompe los atajos `1-7` y aprieta la barra a 80 columnas. `g` ya significa «agrupar» en Equipos (F2), así que en Tráfico cicla la dimensión y se persiste igual.

**ADR-48 · Dominios solo en tablas calientes y fuera de los logs (vs. solo memoria, vs. ocultar los dominios de terceros)**
Los dominios por equipo son historial de navegación. Se guardan solo en `CONNECTIONS` (purga por timeout) y `NAME_CACHE` (≤ 24 h) y nunca en logs por encima de `debug`; el histórico lo decide F5. Solo memoria perdería el arranque en caliente; ocultarlos impediría diagnosticar un equipo IoT que habla con quien no debe.

**ADR-49 · La captura es fuente L2 y crea equipos (amplía la regla de F2)**
F2 decidió que solo la evidencia L2 crea equipos. Un ARP, un DHCP o una trama con MAC e IP de la subred local son evidencia L2 directa, y por WiFi el ARP y el DHCP son broadcast: se ven aunque el escaneo no pueda. Mejora la detección de intrusos que hablan poco. mDNS, SSDP y leases siguen sin crear equipos.

**ADR-50 · Identificación con huella DHCP, modelo y User-Agent con reglas propias (vs. Fingerbank)**
Fingerbank es un servicio externo con clave de API: rompería el funcionamiento sin red. Unas reglas propias, pocas y documentadas, cubren Windows, Apple, Android, Linux e IoT, que es lo que hay en una casa. Se integran con la puntuación de F2 (umbral 4) y se registra `os_source`.

**ADR-51 · `mac_changed` v2 y MAC privadas**
Los móviles usan MAC privadas que pueden rotar. Solo se fusiona identidad si la MAC nueva es privada y coinciden huella y nombre DHCP con un único equipo de MAC privada no visto en el ciclo; la toma de IP de F1 deja de aplicarse si las huellas DHCP se contradicen. El evento lleva `reason`. Sin evidencia DHCP, la rotación sigue saliendo como `new` con `mac_random`.

**ADR-52 · `passive_only` = no consultar a nadie (corrige ADR-17 de F2 y ADR-26 de F3)**
F2 prometía cero tráfico activo pero permitía NetBIOS y DNS inverso, que envían paquetes. Desde F4 ambos se desactivan en modo pasivo, y el DNS inverso de IPs de Internet no se hace en ningún modo: genera mucho tráfico y la base de organización cubre el hueco. Las uniones multicast del sistema para escuchar no cuentan como consulta.

---

## 11. Plan de Desarrollo

**Supuestos:** 1 desarrollador, ~15 h/semana, F1–F3 estables como base.

### Sprint 4.0 — Verificación pendiente de F1–F3 (≈ 4 h)
- Pasada manual con `CAP_NET_RAW` (`scripts/ejecutar-con-permisos.sh`): F1-24, F1-25 y F1-64
- Mediciones del §8 de F2 y de F3
- Prueba visual de F3 en `wlp191s0` con el binario recompilado
- Resultados en el informe de implementación de F4

### Sprint 4.1 — Modelo, configuración y rol (≈ 10 h)
- Migración v4 y test de compatibilidad v3 → v4
- DAOs `names`, `connections` y `devices` extendidos
- `[inference]`, `[ui].traffic_group` y aviso de claves obsoletas
- Rol cliente/servidor (§7.1)

### Sprint 4.2 — Extracción (≈ 18 h)
- Reensamblado del inicio de flujo
- Firmas de protocolo (§7.3)
- ClientHello TLS, SNI y JA4; HTTP en claro
- Respuestas DNS (mover `capture/dns.rs` y `capture/sni.rs` a `inference/`)
- Pruebas con fixtures y entradas aleatorias

### Sprint 4.3 — QUIC (≈ 12 h)
- Initial v1 y v2: claves, protección de cabecera, AEAD
- Recomposición CRYPTO, SNI y JA4 `q`
- Test con los vectores del apéndice A de RFC 9001

### Sprint 4.4 — Etiquetas (≈ 16 h)
- Catálogo embebido (162 apps) + `apps.toml`
- Dominio registrable (`psl`) y bases DB-IP Lite (`maxminddb`, script, `FUENTES.md`)
- Caché de nombres con persistencia
- Resolución de etiquetas (§7.8) y persistencia en `CONNECTIONS`

### Sprint 4.5 — Equipos y modo pasivo (≈ 14 h)
- DHCP capturado, modelo (mDNS/UPnP), User-Agent y puntuación de `os_family`
- MAC privadas y `mac_changed` v2
- Equipos observados en la captura (fuente `capture`)
- `passive_only` sin NetBIOS ni DNS inverso; nunca PTR de IPs de Internet

### Sprint 4.6 — Rankings y TUI (≈ 18 h)
- `Rankings` y `TrafficCommand::WhoUses`
- Tráfico: `g`, `w`, columnas, «¿Quién lo usa?», % sin identificar
- Conexiones: columnas nuevas, `i` y panel `v`
- Detalle, Equipos («MAC privada»), Config y Ayuda

### Sprint 4.7 — Cierre (≈ 8 h)
- Replays pcap de tráfico mixto con etiquetas esperadas
- Medición de rendimiento con la inferencia activa
- README, Ayuda, `CHANGELOG.md` y versión 0.4.0
- Informe de implementación

**Estimación total F4:** **~100 h → 6–7 semanas**.

---

## 12. Conexiones con Otras Fases

**Cambios sobre fases anteriores:**
- ADR-20 (F3) queda modificada por ADR-37: inspección activa por defecto; el payload sigue sin persistirse.
- ADR-17 (F2) y ADR-26 (F3) quedan corregidas por ADR-52: `passive_only` desactiva también NetBIOS y DNS inverso.
- La regla de F2 «solo la evidencia L2 crea equipos» se amplía con la captura (ADR-49).
- La heurística `mac_changed` de F1 pasa a ser la regla B de `mac_changed` v2 (ADR-51).
- `capture/dns.rs` y `capture/sni.rs` (F3) pasan a `inference/`; las claves `inspect_payload`, `dns_attribution` y `sni_attribution` dejan de usarse.
- La v1.2 del informe de F1 renumera sus ADR-08 a 10 como ADR-34 a 36.

**Fases siguientes:**
- **F5 (Histórico y rollups):** rollups por dimensión (equipo, app, categoría, destino) a partir de los rankings; decide qué se guarda de los dominios a largo plazo; ventanas de 1 h y 24 h; consume `DEVICE_EVENTS` (incluido `mac_changed` con `reason`).
- **F6 (Alertas):** JA4 nuevo en un equipo, app o categoría nueva, destino o país inusual, tráfico de rastreo, equipo nuevo por la captura (con `mac_random` para bajar la severidad).
- **F7 (Integraciones)** y la sub-fase 3.5: más visibilidad (SNMP, puerto espejo, ARP spoof opt-in) que alimenta el mismo motor sin cambiarlo; replay pcap.
