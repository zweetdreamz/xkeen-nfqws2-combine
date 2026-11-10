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

PATH="$ROOT/opt/bin:$ROOT/opt/sbin:$PATH"
export PATH

# Bootstrap from this script: never depend on the installed project while it
# may be replaced. Keep this kernel-lock protocol identical in rollback and
# deploy. The inode stays in place; process exit/reboot releases stale locks.
if [ "${KDN_SOFTWARE_LOCKED:-}" != 1 ]; then
  mkdir -p "$ROOT/opt/tmp"
  exec python3 - "$0" "$ROOT/opt/tmp/kdn-software.lock" "$@" <<'PYLOCK'
import fcntl
import os
import signal
import stat
import subprocess
import sys

fd = None
child = None
interrupted = None

def forward(signum, _frame):
    global interrupted
    if interrupted is not None:
        return  # allow the child's cleanup to finish after the first signal
    interrupted = signum
    if child is not None and child.poll() is None:
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

try:
    fd = os.open(sys.argv[2], os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise OSError("unsafe software lock")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, forward)
    if interrupted is not None:
        raise SystemExit(130)
    child = subprocess.Popen(["sh", sys.argv[1], *sys.argv[3:]],
                             env={**os.environ, "KDN_SOFTWARE_LOCKED": "1"},
                             start_new_session=True, close_fds=True)
    if interrupted is not None:
        os.killpg(child.pid, interrupted)
    code = child.wait()
    raise SystemExit(code if code >= 0 else 128 - code)
except BlockingIOError:
    print("software delivery busy (deploy/rollback already in progress)", file=sys.stderr)
    raise SystemExit(3)
except OSError as exc:
    print("software delivery lock failed: " + str(exc), file=sys.stderr)
    raise SystemExit(2)
finally:
    if child is not None and child.poll() is None:
        child.wait()  # the lock covers error/signal rollback as well
    if fd is not None:
        os.close(fd)
PYLOCK
fi
unset KDN_SOFTWARE_LOCKED

BACKUP_ROOT="$ROOT/opt/etc/xkeen-web-backups"
POINTER="$BACKUP_ROOT/latest.path"
PROJECT_DIR="$ROOT/opt/root/keenetic-discord-nfqws2"
WEB_INIT="$ROOT/opt/etc/init.d/S99xkeen-web"
APP_PY="$ROOT/opt/xkeen-web/app.py"

# A successful init exit alone is not evidence that importing processes exited.
# Exact argv matching avoids unrelated Python processes and fixture instances.
panel_stopped() {
  python3 -I - "$APP_PY" "$WEB_INIT" <<'PYSTOP'
import errno
import os
from pathlib import Path
import sys

app, init = (os.fsencode(value) for value in sys.argv[1:])
try:
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            args = (entry / 'cmdline').read_bytes().split(b'\0')
        except OSError as exc:
            # A process can exit after enumeration or after cmdline is opened.
            # Ignore only kernel evidence of disappearance; unreadable live
            # processes and other I/O failures leave absence unconfirmed.
            if exc.errno in (errno.ENOENT, errno.ESRCH):
                continue
            raise
        if app in args or (init in args and b'supervise' in args):
            raise RuntimeError('panel or supervisor is still running')
except (OSError, RuntimeError) as exc:
    print('cannot confirm panel stopped: ' + str(exc), file=sys.stderr)
    raise SystemExit(1)
PYSTOP
}

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
if [ ! -x "$WEB_INIT" ] || ! "$WEB_INIT" stop || ! panel_stopped; then
  echo "ERROR: panel stop failed or init unavailable; no software files changed." >&2
  exit 1
fi

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
