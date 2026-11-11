#!/usr/bin/env bash
# actualizar-bases-ip.sh — actualiza las bases DB-IP Lite embebidas en Almenara.
#
# SOLO DESARROLLO: la aplicación nunca descarga datos en ejecución (ADR-43).
# Este script sustituye data/dbip-asn-lite.mmdb y data/dbip-country-lite.mmdb
# por las publicaciones del mes indicado (por defecto, el mes actual en UTC) y
# regenera el bloque de data/FUENTES.md con la versión, el tamaño y el SHA-256.
#
# Uso: scripts/actualizar-bases-ip.sh [AAAA-MM]
#   Sin argumento usa el mes actual. DB-IP publica las bases a primeros de mes.
# Requisitos: curl o wget, gzip y sha256sum.
set -euo pipefail

BASE_URL="https://download.db-ip.com/free"
DIRECTORIO_SCRIPT=$(cd -- "$(dirname -- "$0")" && pwd)
DIRECTORIO_REPO=$(cd -- "$DIRECTORIO_SCRIPT/.." && pwd)
DIRECTORIO_DATOS="$DIRECTORIO_REPO/data"
FUENTES="$DIRECTORIO_DATOS/FUENTES.md"
BASE_ASN="dbip-asn-lite"
BASE_PAIS="dbip-country-lite"
TAMANO_MINIMO=$((1024 * 1024))

mensaje_info() { echo "· $*"; }
mensaje_error() { echo "error: $*" >&2; }

if [ "$#" -ge 1 ]; then
    case "$1" in
        -h|--ayuda|--help)
            sed -n '2,11p' "$0"
            exit 0
            ;;
    esac
fi

MES_ACTUAL=$(date -u +%Y-%m)
if [ "$#" -ge 1 ] && [ -n "$1" ]; then
    MES="$1"
else
    MES="$MES_ACTUAL"
fi

case "$MES" in
    [0-9][0-9][0-9][0-9]-0[1-9]|[0-9][0-9][0-9][0-9]-1[0-2]) ;;
    *)
        mensaje_error "mes inválido «$MES»: se espera AAAA-MM (por ejemplo $MES_ACTUAL)"
        exit 2
        ;;
esac
if [[ "$MES" > "$MES_ACTUAL" ]]; then
    mensaje_error "el mes «$MES» es futuro; la publicación más reciente posible es $MES_ACTUAL"
    exit 2
fi

if [ ! -d "$DIRECTORIO_DATOS" ]; then
    mensaje_error "no existe el directorio $DIRECTORIO_DATOS; ejecuta el script desde el repositorio de Almenara"
    exit 1
fi
if [ ! -f "$FUENTES" ]; then
    mensaje_error "no existe $FUENTES; no se puede anotar la actualización"
    exit 1
fi
for herramienta in gzip sha256sum tail grep; do
    if ! command -v "$herramienta" >/dev/null 2>&1; then
        mensaje_error "falta la herramienta «$herramienta»"
        exit 1
    fi
done
if command -v curl >/dev/null 2>&1; then
    DESCARGADOR="curl"
elif command -v wget >/dev/null 2>&1; then
    DESCARGADOR="wget"
else
    mensaje_error "se necesita curl o wget para descargar las bases de DB-IP"
    exit 1
fi
if ! grep -q "<!-- bases-ip:inicio -->" "$FUENTES" || ! grep -q "<!-- bases-ip:fin -->" "$FUENTES"; then
    mensaje_error "en $FUENTES faltan los marcadores <!-- bases-ip:inicio --> y <!-- bases-ip:fin -->"
    exit 1
fi

TRABAJO=$(mktemp -d)
limpiar() { rm -rf -- "$TRABAJO"; }
trap limpiar EXIT

descargar() {
    url="$1"
    destino="$2"
    mensaje_info "descargando $url"
    if [ "$DESCARGADOR" = "curl" ]; then
        curl -fsSL --retry 3 --connect-timeout 20 --max-time 300 -o "$destino" "$url"
    else
        wget -q --tries=3 --timeout=20 -O "$destino" "$url"
    fi
}

preparar_base() {
    nombre="$1"
    comprimido="$TRABAJO/$nombre.mmdb.gz"
    expandido="$TRABAJO/$nombre.mmdb"
    if ! descargar "$BASE_URL/$nombre-$MES.mmdb.gz" "$comprimido"; then
        mensaje_error "no se pudo descargar $BASE_URL/$nombre-$MES.mmdb.gz"
        mensaje_error "comprueba la conexión y que DB-IP haya publicado el mes $MES (salen a primeros de mes)"
        return 1
    fi
    if ! gzip -t "$comprimido" 2>/dev/null; then
        mensaje_error "el fichero descargado no es un gzip válido: $comprimido"
        return 1
    fi
    if ! gzip -dc "$comprimido" > "$expandido"; then
        mensaje_error "no se pudo descomprimir $comprimido"
        return 1
    fi
    tamano=$(wc -c < "$expandido")
    if [ "$tamano" -lt "$TAMANO_MINIMO" ]; then
        mensaje_error "la base $nombre parece truncada ($tamano bytes; mínimo $TAMANO_MINIMO)"
        return 1
    fi
    # Una MMDB de MaxMind DB termina con la marca de metadatos; si no está, el
    # fichero no es la base esperada.
    if ! tail -c 2048 "$expandido" | grep -aq "MaxMind.com"; then
        mensaje_error "la base $nombre no parece una MMDB de MaxMind DB"
        return 1
    fi
    mensaje_info "base $nombre descargada y validada ($tamano bytes)"
    return 0
}

mensaje_info "actualizando las bases DB-IP al mes $MES"
if ! preparar_base "$BASE_ASN"; then
    exit 1
fi
if ! preparar_base "$BASE_PAIS"; then
    exit 1
fi

instalar_base() {
    nombre="$1"
    cp -- "$TRABAJO/$nombre.mmdb" "$DIRECTORIO_DATOS/$nombre.mmdb.nuevo"
    mv -- "$DIRECTORIO_DATOS/$nombre.mmdb.nuevo" "$DIRECTORIO_DATOS/$nombre.mmdb"
    mensaje_info "sustituida data/$nombre.mmdb"
}

instalar_base "$BASE_ASN"
instalar_base "$BASE_PAIS"

FECHA=$(date -u +%Y-%m-%d)
TAMANO_ASN=$(wc -c < "$DIRECTORIO_DATOS/$BASE_ASN.mmdb")
TAMANO_PAIS=$(wc -c < "$DIRECTORIO_DATOS/$BASE_PAIS.mmdb")
SHA_ASN=$(sha256sum "$DIRECTORIO_DATOS/$BASE_ASN.mmdb" | cut -d' ' -f1)
SHA_PAIS=$(sha256sum "$DIRECTORIO_DATOS/$BASE_PAIS.mmdb" | cut -d' ' -f1)

BLOQUE="$TRABAJO/bloque-fuentes.md"
cat > "$BLOQUE" <<BLOQUE_FIN
| Fichero | Versión (mes) | Tamaño | SHA-256 |
|---|---|---|---|
| data/$BASE_ASN.mmdb | $MES | $TAMANO_ASN B | $SHA_ASN |
| data/$BASE_PAIS.mmdb | $MES | $TAMANO_PAIS B | $SHA_PAIS |

Descargadas el $FECHA desde las publicaciones mensuales de DB-IP:

- $BASE_URL/$BASE_ASN-$MES.mmdb.gz
- $BASE_URL/$BASE_PAIS-$MES.mmdb.gz

**Atribución obligatoria (CC BY 4.0): «IP Geolocation by DB-IP»**
(<https://db-ip.com>).

- Origen: DB-IP, IP to ASN Lite e IP to Country Lite.
- Licencia: Creative Commons Attribution 4.0 International (CC BY 4.0),
  <https://creativecommons.org/licenses/by/4.0/>.
- Formato: MaxMind DB (MMDB), IPv4 e IPv6; se leen con el crate maxminddb.
- Actualizadas el $FECHA con scripts/actualizar-bases-ip.sh, que sustituye los
  ficheros y regenera este bloque con la versión, el tamaño y el SHA-256.

BLOQUE_FIN

awk -v inicio="<!-- bases-ip:inicio -->" -v fin="<!-- bases-ip:fin -->" -v bloque="$BLOQUE" '
    $0 == inicio {
        print
        while ((getline linea < bloque) > 0) {
            print linea
        }
        close(bloque)
        dentro = 1
        next
    }
    $0 == fin {
        print
        dentro = 0
        next
    }
    dentro != 1 { print }
' "$FUENTES" > "$FUENTES.nuevo"

if ! grep -q "$SHA_ASN" "$FUENTES.nuevo"; then
    mensaje_error "no se pudo escribir el bloque de las bases en $FUENTES"
    exit 1
fi
mv -- "$FUENTES.nuevo" "$FUENTES"
mensaje_info "actualizado data/FUENTES.md (versión $MES, $FECHA)"

echo
mensaje_info "hecho. Revisa data/FUENTES.md, ejecuta cargo test y versiona data/ con la release."
