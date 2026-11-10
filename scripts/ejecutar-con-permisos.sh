#!/usr/bin/env bash
# Almenara — arranque con permisos elevados (CAP_NET_RAW).
#
# Aplica la capability CAP_NET_RAW solo al binario de Almenara mediante setcap y
# después lo ejecuta con el usuario actual (sin lanzar la TUI como root): la
# configuración, la base de datos y los logs siguen en el HOME del usuario.
#
# La capability se pierde al recompilar el binario; este script la vuelve a
# aplicar en cada arranque. Requiere el paquete libcap2-bin (setcap/getcap) y
# sudo disponible para el usuario.
#
# Uso:
#   scripts/ejecutar-con-permisos.sh [opciones] [-- argumentos de almenara]
#
# Opciones:
#   -r, --release           compila y ejecuta el binario release (cargo build --release)
#   -c, --comprobar         no aplica setcap ni ejecuta Almenara; muestra lo que haría
#   -R, --retirar-al-salir  quita CAP_NET_RAW del binario al terminar la aplicación
#   -h, --help              muestra esta ayuda
#
# Ejemplos:
#   scripts/ejecutar-con-permisos.sh
#   scripts/ejecutar-con-permisos.sh --release
#   scripts/ejecutar-con-permisos.sh -- -vv --no-color
#   scripts/ejecutar-con-permisos.sh --retirar-al-salir
#
# Nota: ejecutar la TUI con sudo NO es necesario y además dejaría la configuración,
# la base de datos y los logs en el HOME de root. Con setcap basta.

set -euo pipefail

PERFIL="debug"
COMPROBAR=0
RETIRAR=0

mostrar_ayuda() {
    cat <<'AYUDA'
Almenara — arranque con permisos elevados (CAP_NET_RAW)

Aplica la capability CAP_NET_RAW solo al binario de Almenara mediante setcap y
después lo ejecuta con el usuario actual (sin lanzar la TUI como root): la
configuración, la base de datos y los logs siguen en el HOME del usuario.

La capability se pierde al recompilar el binario; este script la vuelve a
aplicar en cada arranque. Requiere el paquete libcap2-bin (setcap/getcap) y
sudo disponible para el usuario.

Uso:
  scripts/ejecutar-con-permisos.sh [opciones] [-- argumentos de almenara]

Opciones:
  -r, --release           compila y ejecuta el binario release (cargo build --release)
  -c, --comprobar         no aplica setcap ni ejecuta Almenara; muestra lo que haría
  -R, --retirar-al-salir  quita CAP_NET_RAW del binario al terminar la aplicación
  -h, --help              muestra esta ayuda

Ejemplos:
  scripts/ejecutar-con-permisos.sh
  scripts/ejecutar-con-permisos.sh --release
  scripts/ejecutar-con-permisos.sh -- -vv --no-color
  scripts/ejecutar-con-permisos.sh --retirar-al-salir

Nota: ejecutar la TUI con sudo NO es necesario y además dejaría la configuración,
la base de datos y los logs en el HOME de root. Con setcap basta.
AYUDA
}

while [ $# -gt 0 ]; do
    case "$1" in
        -r|--release)
            PERFIL="release"
            shift
            ;;
        -c|--comprobar)
            COMPROBAR=1
            shift
            ;;
        -R|--retirar-al-salir)
            RETIRAR=1
            shift
            ;;
        -h|--help)
            mostrar_ayuda
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Opción desconocida: $1" >&2
            echo "Usa --help para ver las opciones disponibles." >&2
            exit 2
            ;;
    esac
done

if [ "$(uname -s)" != "Linux" ]; then
    echo "Error: Almenara solo funciona en Linux (se necesita AF_PACKET/TPACKET_V3)." >&2
    exit 1
fi

# Raíz del repositorio, con independencia del directorio desde el que se llame.
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$RAIZ"

if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: no se encontró cargo en PATH. Instala Rust 1.88 o superior." >&2
    exit 1
fi

echo "Compilando Almenara ($PERFIL)…"
if [ "$PERFIL" = "release" ]; then
    cargo build --release
else
    cargo build
fi

BIN="$RAIZ/target/$PERFIL/almenara"
if [ ! -x "$BIN" ]; then
    echo "Error: no se generó el binario $BIN" >&2
    exit 1
fi

# ¿El binario ya tiene CAP_NET_RAW?
TIENE_CAPABILITY=0
if command -v getcap >/dev/null 2>&1; then
    if getcap "$BIN" 2>/dev/null | grep -q 'cap_net_raw'; then
        TIENE_CAPABILITY=1
    fi
else
    echo "Aviso: getcap no está instalado (paquete libcap2-bin); se comprobará con setcap." >&2
fi

if [ "$TIENE_CAPABILITY" -eq 0 ]; then
    if ! command -v setcap >/dev/null 2>&1; then
        echo "Error: falta setcap (paquete libcap2-bin) para dar CAP_NET_RAW al binario." >&2
        echo "En Debian/Ubuntu: sudo apt install libcap2-bin" >&2
        echo "Alternativa manual: cargo build && sudo setcap cap_net_raw+ep target/$PERFIL/almenara" >&2
        exit 1
    fi
    if [ "$COMPROBAR" -eq 1 ]; then
        echo "[comprobar] Se ejecutaría: sudo setcap cap_net_raw+ep \"$BIN\""
    else
        echo "Aplicando CAP_NET_RAW solo al binario de Almenara (se pedirá la contraseña de sudo)…"
        if ! sudo setcap cap_net_raw+ep "$BIN"; then
            echo "Error: no se pudo aplicar CAP_NET_RAW con setcap." >&2
            echo "Comprueba que tu usuario puede usar sudo y que el sistema de ficheros" >&2
            echo "soporta atributos extendidos (xattrs). Alternativa: ejecutar con sudo," >&2
            echo "asumiendo que configuración, base de datos y logs quedarán en el HOME de root." >&2
            exit 1
        fi
        if command -v getcap >/dev/null 2>&1; then
            echo "Capability aplicada: $(getcap "$BIN")"
        fi
    fi
else
    echo "CAP_NET_RAW ya presente en el binario: $(getcap "$BIN" 2>/dev/null)"
fi

if [ "$COMPROBAR" -eq 1 ]; then
    echo "[comprobar] Se ejecutaría: $BIN $*"
    echo "[comprobar] No se aplica setcap ni se lanza Almenara (modo comprobación)."
    exit 0
fi

echo "Arrancando Almenara (usuario $(id -un), binario $PERFIL)…"

# Se ejecuta con el usuario actual: la config/BD/logs quedan en su HOME.
if [ "$RETIRAR" -eq 1 ]; then
    ESTADO=0
    "$BIN" "$@" || ESTADO=$?
    echo "Retirando CAP_NET_RAW del binario…"
    sudo setcap -r "$BIN" || echo "Aviso: no se pudo retirar CAP_NET_RAW (puedes hacerlo con: sudo setcap -r $BIN)" >&2
    exit "$ESTADO"
else
    exec "$BIN" "$@"
fi
