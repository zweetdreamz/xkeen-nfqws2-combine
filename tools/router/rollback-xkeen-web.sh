#!/bin/sh
set -eu

BACKUP_ROOT="/opt/etc/xkeen-web-backups"
POINTER="$BACKUP_ROOT/latest.path"
PROJECT_DIR="/opt/root/keenetic-discord-nfqws2"
WEB_INIT="/opt/etc/init.d/S99xkeen-web"

[ -s "$POINTER" ] || {
  echo "ERROR: panel backup pointer not found: $POINTER" >&2
  exit 1
}

backup_dir="$(sed -n '1p' "$POINTER")"
case "$backup_dir" in
  "$BACKUP_ROOT"/*) ;;
  *)
    echo "ERROR: unsafe panel backup path: $backup_dir" >&2
    exit 1
    ;;
esac

for required in app.py S99xkeen-web apply-discord-nfqws2.sh; do
  [ -f "$backup_dir/$required" ] || {
    echo "ERROR: incomplete panel backup: $backup_dir/$required" >&2
    exit 1
  }
done

restore_file() {
  restore_source="$1"
  restore_target="$2"
  restore_tmp="${restore_target}.panel-rollback.$$"
  cp -p "$restore_source" "$restore_tmp"
  mv -f "$restore_tmp" "$restore_target"
}

echo "Stopping current panel..."
[ ! -x "$WEB_INIT" ] || "$WEB_INIT" stop || true

restore_file "$backup_dir/app.py" "/opt/xkeen-web/app.py"
restore_file "$backup_dir/S99xkeen-web" "$WEB_INIT"
restore_file \
  "$backup_dir/apply-discord-nfqws2.sh" \
  "$PROJECT_DIR/apply-discord-nfqws2.sh"

for optional in \
  README.md \
  docs/MODES-AND-FLAGS.md \
  docs/OPERATIONS.md \
  docs/guide.html \
  docs/STRATEGY.md \
  set-service-route.sh \
  scripts/diagnose-discord-voice.sh \
  tools/router/xkeen_control_script.sh \
  tools/router/README.md \
  tools/router/zapret_autotune_job.py \
  tools/router/quic_probe.py \
  tools/router/xkeen_diagnostics.py \
  tools/router/browser-diagnostics.js \
  tools/router/install-diagnostics-update.sh \
  tools/windows/README.md \
  tools/windows/reset-discord-cache.ps1 \
  tools/windows/zapret_tuner.py \
  tools/windows/router-candidate-runner.sh \
  tools/windows/tune-youtube.bat \
  tools/windows/tune-discord-tcp.bat \
  tools/windows/tune-discord-voice.bat \
  tests/test_zapret_tuner.py \
  tests/test_panel_import.py \
  tests/test_router_autotune.py \
  tests/test_quic_probe.py \
  tests/test_router_diagnostics.py \
  tests/test-browser-diagnostics.cjs \
  tests/test-routing-modes.sh \
  tests/test-router-autotune.sh
do
  if [ -f "$backup_dir/files/$optional" ]; then
    mkdir -p "$(dirname "$PROJECT_DIR/$optional")"
    restore_file "$backup_dir/files/$optional" "$PROJECT_DIR/$optional"
  elif grep -Fqx "$optional" "$backup_dir/absent.list" 2>/dev/null; then
    rm -f "$PROJECT_DIR/$optional"
  fi
done

chmod 755 "$WEB_INIT"
echo "Starting restored panel..."
"$WEB_INIT" start
"$WEB_INIT" status

echo "Panel software restored from: $backup_dir"
echo "Service routing was not changed by this panel rollback."

# Restore the launcher itself last. Atomic rename keeps this running shell on
# the already-open inode while the next invocation receives the old version.
if [ -f "$backup_dir/rollback-xkeen-web.sh" ]; then
  restore_file \
    "$backup_dir/rollback-xkeen-web.sh" \
    "$PROJECT_DIR/tools/router/rollback-xkeen-web.sh"
fi
