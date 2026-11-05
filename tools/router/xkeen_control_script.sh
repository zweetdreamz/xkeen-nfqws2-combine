#!/bin/sh
set -eu

# By default installs only the local web application file. --install-init
# installs the supervisor separately; neither mode starts or stops services
# or changes routing, XKeen or nfqws2.
# The file is a launcher: the panel is tools/router/kdn/web/app.py in the
# project directory (XKEEN_PROJECT_DIR).

require_target() {
  POLICY="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/kdn/common/xkeen.py"
  [ -f "$POLICY" ] || { echo 'Missing XKeen version guard; refusing install.' >&2; exit 2; }
  python3 -I "$POLICY" --require || exit 2
}

case "${1:-}" in
  '') [ "$#" -eq 0 ] || exit 2 ;;
  --install-init)
    [ "$#" -eq 1 ] || exit 2
    SOURCE="${XKEEN_PROJECT_DIR:-/opt/root/keenetic-discord-nfqws2}/tools/router/xkeen-web-init.sh"
    INIT_DIR="${XKEEN_INIT_DIR:-/opt/etc/init.d}"
    [ -f "$SOURCE" ] || { echo "Не найден $SOURCE" >&2; exit 1; }
    require_target
    mkdir -p "$INIT_DIR"
    DEST="$INIT_DIR/S99xkeen-web"
    TEMP=$(mktemp "$INIT_DIR/.xkeen-web.XXXXXX")
    trap 'rm -f "$TEMP"' 0 HUP INT TERM
    cp "$SOURCE" "$TEMP"
    chmod 755 "$TEMP"
    if [ -e "$DEST" ]; then
      # mktemp avoids overwriting a backup when installing twice in one second.
      BACKUP=$(mktemp "$DEST.pre-supervisor-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
      cp -p "$DEST" "$BACKUP"
    fi
    mv -f "$TEMP" "$DEST"
    echo 'Порядок миграции: остановите панель СТАРЫМ init (S99xkeen-web stop), затем установите init, затем S99xkeen-web start.'
    echo "Установлен $DEST. Ничего не запускалось и не останавливалось."
    exit 0 ;;
  *) echo 'Usage: xkeen_control_script.sh [--install-init]' >&2; exit 2 ;;
esac

APP_DIR="${XKEEN_WEB_DIR:-/opt/xkeen-web}"
require_target
mkdir -p "$APP_DIR"

cat > "$APP_DIR/app.py" <<'PYEOF'
import os
import runpy
project = os.environ.get("XKEEN_PROJECT_DIR", "/opt/root/keenetic-discord-nfqws2")
runpy.run_path(os.path.join(project, "tools", "router", "kdn", "web", "app.py"), run_name="__main__")
PYEOF

chmod 700 "$APP_DIR/app.py"

cat <<EOF
Установлен файл:
  $APP_DIR/app.py

Запуск в foreground:
  /opt/bin/python3 $APP_DIR/app.py

Панель:
  http://192.168.2.1:8088

Установщик не менял XKeen, routing, nfqws2 или автозапуск.
EOF
