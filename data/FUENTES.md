# Fuentes de los datos embebidos en Almenara

Almenara embebe en el binario todos los datos que necesita para etiquetar el
tráfico: el catálogo de apps, la Public Suffix List, las bases de IP y la base
OUI. La aplicación **no descarga nada en tiempo de ejecución**; las
actualizaciones son manuales, de desarrollo, y se versionan con cada release
(ADR-43). Este documento registra el origen, la fecha y la licencia de cada uno.

## Bases DB-IP Lite (ASN y país)

<!-- bases-ip:inicio -->
| Fichero | Versión (mes) | Tamaño | SHA-256 |
|---|---|---|---|
| data/dbip-asn-lite.mmdb | 2026-11 | 9648279 B | 81565a450281c949fc83745f5ec9cfea70b035163b1152b055645884765d153d |
| data/dbip-country-lite.mmdb | 2026-11 | 8515063 B | 145ce5dfb812d8de28547e6289bb5c5f8b3df2f1dea21d324d5b575e0431311f |

Descargadas el 2026-11-10 desde las publicaciones mensuales de DB-IP:

- https://download.db-ip.com/free/dbip-asn-lite-2026-11.mmdb.gz
- https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz

**Atribución obligatoria (CC BY 4.0): «IP Geolocation by DB-IP»**
(<https://db-ip.com>).

- Origen: DB-IP, IP to ASN Lite e IP to Country Lite.
- Licencia: Creative Commons Attribution 4.0 International (CC BY 4.0),
  <https://creativecommons.org/licenses/by/4.0/>.
- Formato: MaxMind DB (MMDB), IPv4 e IPv6; se leen con el crate maxminddb.
- Se actualizan con scripts/actualizar-bases-ip.sh, que sustituye los ficheros
  y regenera este bloque con la versión, el tamaño y el SHA-256 nuevos.
<!-- bases-ip:fin -->

## Public Suffix List (Mozilla)

- Uso: dominio registrable de los destinos (src/inference/domain.rs), por
  ejemplo rr3---sn-x.googlevideo.com → googlevideo.com.
- Origen: Public Suffix List de Mozilla, <https://publicsuffix.org/list/>,
  embebida a través del crate psl 2.1.250 (psl-types 2.0.11).
- Licencia: Mozilla Public License 2.0 (MPL 2.0),
  <https://mozilla.org/MPL/2.0/>.
- Actualización: se renueva al subir la versión del crate psl con cada release
  de Almenara; no hay descarga en ejecución.

## Catálogo de apps y categorías

- Fichero: data/catalogo.toml (embebido con include_str!).
- Origen: catálogo propio de Almenara, curado a mano para esta fase (2026-11):
  13 categorías y las 162 apps de la lista mínima del §7.9. Los dominios
  compartidos por proveedores y CDN se asignan a apps genéricas de
  Infraestructura. No se copian listas públicas de bloqueo ni de rastreo
  (GPL o CC BY-NC-SA): la lista de rastreo y telemetría es propia y cada app
  lleva su comentario de origen en el propio fichero.
- Licencia: la del proyecto Almenara (MIT).
- Actualización: editar data/catalogo.toml; los usuarios pueden ampliarlo con
  su apps.toml ([inference].apps_file).

## Huella JA4

- Uso: huella del cliente TLS/QUIC (src/inference/ja4.rs).
- Origen: especificación pública de FoxIO,
  <https://github.com/FoxIO-LLC/ja4>.
- Licencia: JA4 de cliente bajo licencia BSD-3-Clause; FoxIO declara no buscar
  patentes sobre ella. No se embeben datos de firmas y no se implementa el
  resto de la familia JA4+ (FoxIO License 1.1).
- Actualización: no aplica (solo código).

## Base OUI (fabricantes de MAC)

- Uso: fabricante de los equipos por los tres primeros octetos de su MAC
  (funcionalidad de Fase 1–2).
- Origen: registros públicos del IEEE (MA-L, MA-M y MA-S/IAB),
  <https://standards-oui.ieee.org/>, embebidos por el crate macaddr-ouidb
  0.3.1.
- Licencia: datos de registro público del IEEE; el crate se distribuye con
  licencia Apache-2.0.
- Actualización: se renueva al subir la versión del crate con cada release de
  Almenara.

## Librerías que leen los datos

| Dato | Librería | Versión | Licencia |
|---|---|---|---|
| MMDB de DB-IP | maxminddb | 0.26.0 | ISC |
| Public Suffix List | psl / psl-types | 2.1.250 / 2.0.11 | MIT/Apache-2.0 |
| Catálogo TOML | toml | 0.8.23 | MIT/Apache-2.0 |
| OUI | macaddr-ouidb | 0.3.1 | Apache-2.0 |

## Cómo se actualizan

1. **Bases de IP:** scripts/actualizar-bases-ip.sh (solo desarrollo). Descarga
   las MMDB del mes indicado (por defecto, el actual), las valida, sustituye
   data/dbip-*.mmdb y regenera el bloque de este documento.
2. **Catálogo:** editar data/catalogo.toml (tests del catálogo en
   src/inference/catalog.rs).
3. **PSL y OUI:** actualizar la versión del crate correspondiente en Cargo.toml.
4. Tras cualquier actualización: cargo test, revisar git diff data/ y versionar
   los ficheros nuevos en la release.
