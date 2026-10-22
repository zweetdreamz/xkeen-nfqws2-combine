#!/bin/sh
# Install a verified staged panel update. Only the web-panel service restarts.
set -eu

stage="${1:-}"
project=/opt/root/keenetic-discord-nfqws2
backup_root=/opt/etc/xkeen-web-backups
web_init=/opt/etc/init.d/S99xkeen-web
case "$stage" in
  /opt/tmp/codex-diagnostics-[0-9]*) ;;
  *) echo "ERROR: expected /opt/tmp/codex-diagnostics-DATE staging directory" >&2; exit 2 ;;
esac
case "$stage" in *..*|*'//'*) exit 2 ;; esac
[ -d "$stage" ] && [ ! -L "$stage" ]
[ -f "$stage/generated/app.py" ]
for job in tuner route diagnostics; do
  /opt/bin/curl --max-time 8 -fsS "http://192.168.2.1:8088/api/$job/status" |
    /opt/bin/jq -e '.active == false' >/dev/null || {
      echo "ERROR: $job job is active or its status cannot be checked" >&2
      exit 1
    }
done

files='README.md
docs/OPERATIONS.md
docs/MODES-AND-FLAGS.md
docs/guide.html
tools/router/README.md
tools/router/xkeen_control_script.sh
tools/router/xkeen_diagnostics.py
tools/router/browser-diagnostics.js
tools/router/rollback-xkeen-web.sh
tools/router/install-diagnostics-update.sh
tools/windows/README.md
tools/windows/reset-discord-cache.ps1
tests/test_panel_import.py
tests/test_router_diagnostics.py'
files="$files
tests/test-browser-diagnostics.cjs"
files="$files
tools/router/zapret_autotune_job.py
tools/router/quic_probe.py
tools/windows/zapret_tuner.py
tools/windows/router-candidate-runner.sh
scripts/diagnose-discord-voice.sh
tests/test_router_autotune.py
tests/test_quic_probe.py
tests/test_zapret_tuner.py
tests/test-router-autotune.sh"

for file in $files; do
  [ -f "$stage/$file" ] && [ ! -L "$stage/$file" ] || exit 2
done
/opt/bin/python3 -m py_compile "$stage/generated/app.py" "$stage/tools/router/xkeen_diagnostics.py"
before_xray="$(pidof xray || true)"
before_nfqws="$(pidof nfqws2 || true)"
before_config="$(sha256sum /opt/etc/nfqws2/nfqws2.conf /opt/etc/xray/configs/*.json)"
backup="$backup_root/$(date +%Y%m%d-%H%M%S)-diagnostics"
[ ! -e "$backup" ]
umask 077
mkdir -p "$backup/files"
cp -p /opt/xkeen-web/app.py "$backup/app.py"
cp -p "$web_init" "$backup/S99xkeen-web"
cp -p "$project/apply-discord-nfqws2.sh" "$backup/apply-discord-nfqws2.sh"
cp -p "$project/tools/router/rollback-xkeen-web.sh" "$backup/rollback-xkeen-web.sh"
: > "$backup/absent.list"
for file in $files; do
  if [ -f "$project/$file" ]; then
    mkdir -p "$backup/files/$(dirname "$file")"
    cp -p "$project/$file" "$backup/files/$file"
  else
    echo "$file" >> "$backup/absent.list"
  fi
done
echo "$backup" > "$backup_root/.latest.path.$$"
mv "$backup_root/.latest.path.$$" "$backup_root/latest.path"

install_file() {
  source_file="$1"
  target_file="$2"
  mode="$3"
  temporary="${target_file}.diagnostics-update.$$"
  cp -p "$source_file" "$temporary"
  chmod "$mode" "$temporary"
  mv -f "$temporary" "$target_file"
}

restore_on_failure() {
  result=$?
  trap - 0 HUP INT TERM
  if [ "$result" -ne 0 ]; then
    echo "ERROR: panel update failed; restoring panel backup: $backup" >&2
    /bin/sh "$stage/tools/router/rollback-xkeen-web.sh" || true
  fi
  exit "$result"
}
trap restore_on_failure 0
trap 'exit 130' HUP INT TERM

for file in $files; do
  mode=644
  case "$file" in *.sh|*.py) mode=755 ;; esac
  install_file "$stage/$file" "$project/$file" "$mode"
done
install_file "$stage/generated/app.py" /opt/xkeen-web/app.py 700
"$web_init" restart
attempt=0
until /opt/bin/curl --max-time 4 -fsS http://192.168.2.1:8088/api/diagnostics/status >/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 10 ] || exit 1
  sleep 1
done
"$web_init" status
[ "$(pidof xray || true)" = "$before_xray" ]
[ "$(pidof nfqws2 || true)" = "$before_nfqws" ]
[ "$(sha256sum /opt/etc/nfqws2/nfqws2.conf /opt/etc/xray/configs/*.json)" = "$before_config" ]
echo "Panel installed. Xray/nfqws2 PIDs and configuration checksums unchanged."
echo "Backup: $backup"
