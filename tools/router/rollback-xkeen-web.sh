#!/bin/sh
set -eu

# Restores what tools/dev/deploy.sh saved before its last deploy (the backup
# named in latest.path): the panel app.py and every project file the deploy
# replaced; files it added are removed. The project directory is the one
# recorded in the backup (deploy.sh --project-dir), the default for a backup
# without it. Only the panel restarts. Service routing is not changed.
#
# KDN_DEPLOY_ROOT prefixes every absolute router path. Like KD_TEST_ROOT it is
# meant for the repository's isolated tests and is rejected unless
# KDN_ALLOW_DEPLOY_ROOT=1.

ROOT=""
if [ -n "${KDN_DEPLOY_ROOT:-}" ]; then
  [ "${KDN_ALLOW_DEPLOY_ROOT:-0}" = "1" ] || {
    echo "ERROR: KDN_DEPLOY_ROOT is reserved for isolated repository tests." >&2
    exit 2
  }
  ROOT="${KDN_DEPLOY_ROOT%/}"
fi

BACKUP_ROOT="$ROOT/opt/etc/xkeen-web-backups"
POINTER="$BACKUP_ROOT/latest.path"
PROJECT_DIR="$ROOT/opt/root/keenetic-discord-nfqws2"
WEB_INIT="$ROOT/opt/etc/init.d/S99xkeen-web"
APP_PY="$ROOT/opt/xkeen-web/app.py"

[ -s "$POINTER" ] || {
  echo "ERROR: panel backup pointer not found: $POINTER" >&2
  exit 1
}

backup_dir="$(sed -n '1p' "$POINTER")"
case "$backup_dir" in
  *..*)
    echo "ERROR: unsafe panel backup path: $backup_dir" >&2
    exit 1
    ;;
  "$BACKUP_ROOT"/*) ;;
  *)
    echo "ERROR: unsafe panel backup path: $backup_dir" >&2
    exit 1
    ;;
esac

for required in app.py NEW_FILES; do
  [ -f "$backup_dir/$required" ] || {
    echo "ERROR: incomplete panel backup: $backup_dir/$required" >&2
    exit 1
  }
done

if [ -f "$backup_dir/PROJECT_DIR" ]; then
  recorded_dir="$(sed -n '1p' "$backup_dir/PROJECT_DIR")"
  case "$recorded_dir" in
    /*) ;;
    *)
      echo "ERROR: unsafe project directory in $backup_dir/PROJECT_DIR: $recorded_dir" >&2
      exit 1
      ;;
  esac
  case "$recorded_dir" in
    *[!A-Za-z0-9._/-]*|*..*|*//*)
      echo "ERROR: unsafe project directory in $backup_dir/PROJECT_DIR: $recorded_dir" >&2
      exit 1
      ;;
  esac
  PROJECT_DIR="$ROOT$recorded_dir"
fi

restore_file() {
  restore_source="$1"
  restore_target="$2"
  restore_tmp="${restore_target}.panel-rollback.$$"
  mkdir -p "$(dirname "$restore_target")"
  cp -p "$restore_source" "$restore_tmp"
  mv -f "$restore_tmp" "$restore_target"
}

echo "Stopping current panel..."
[ ! -x "$WEB_INIT" ] || "$WEB_INIT" stop || true

restore_file "$backup_dir/app.py" "$APP_PY"
chmod 700 "$APP_PY"

# Every file is put back by an atomic rename, so restoring this launcher among
# them is safe: the running shell keeps the already-open inode.
if [ -d "$backup_dir/project" ]; then
  (cd "$backup_dir/project" && find . -type f) | sed 's|^\./||' | while IFS= read -r file; do
    restore_file "$backup_dir/project/$file" "$PROJECT_DIR/$file"
  done
fi

while IFS= read -r file; do
  rm -f "$PROJECT_DIR/$file"
done < "$backup_dir/NEW_FILES"
if [ -f "$backup_dir/NEW_DIRS" ]; then
  # The panel writes __pycache__ into the directories it imports from, which
  # would fail the rmdir.
  while IFS= read -r dir; do
    rm -rf "$PROJECT_DIR/$dir/__pycache__" || true
    rmdir "$PROJECT_DIR/$dir" 2>/dev/null || true
  done < "$backup_dir/NEW_DIRS"
fi

echo "Starting restored panel..."
"$WEB_INIT" start
"$WEB_INIT" status

echo "Panel software restored from: $backup_dir"
echo "Service routing was not changed by this panel rollback."
