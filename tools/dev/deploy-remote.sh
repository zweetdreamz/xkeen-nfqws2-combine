#!/bin/sh
set -eu

# Router side of tools/dev/deploy.sh: checks an uploaded package, installs it
# with a backup and restores the backup when the panel does not come back.
#
#   sh deploy-remote.sh --stage DIR [--project-dir DIR] [--dry-run]
#
# DIR (/opt/tmp/kdn-deploy-<stamp>) holds upload.tar.gz. Steps: panel busy
# check, archive check, syntax check, invariants (xray and nfqws2 PIDs, config
# checksums), backup to /opt/etc/xkeen-web-backups/<stamp>-deploy, panel stop,
# check for job processes, install, panel start and readiness wait, invariants
# again. The panel is down while the files are copied: a job it started
# meanwhile would import a mix of old and new modules. A job process that is
# still alive after the stop ends the deploy with exit 3, the panel started
# again and the backup dropped. Any other failure after the backup restores it
# (the panel restarts), and latest.path names the previous backup again.
# --dry-run stops after the invariants and lists the files to install.
#
# Exit codes: 0 ok, 1 failed and the backup was restored, 2 invalid package or
# precondition (nothing changed), 3 panel busy (nothing changed).
#
# KDN_DEPLOY_ROOT prefixes every absolute router path built here. Like
# KD_TEST_ROOT it exists for the repository's isolated tests and is rejected
# unless KDN_ALLOW_DEPLOY_ROOT=1; KDN_READY_PAUSE (seconds between panel
# readiness attempts, default 2) is honoured only then. KDN_PANEL overrides
# the panel address.
#
# Progress is also written to <stage>/deploy.log, so the outcome (done or rolled
# back) can be read after a dropped ssh session.

# Messages go to the log in the stage directory first and to the terminal on a
# best-effort basis: a dropped ssh session must not change the outcome.
LOG=""

log_line() {
  [ -z "$LOG" ] || printf '%s deploy: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null || true
}

say() {
  log_line "$*"
  printf 'deploy: %s\n' "$*" || true
}

err() {
  log_line "$*"
  printf 'deploy: %s\n' "$*" >&2 || true
}

die() {
  die_code="$1"
  shift
  err "$*"
  exit "$die_code"
}

usage() {
  sed -n '4,30p' "$0" | sed 's/^# \{0,1\}//'
}

# A write to a closed ssh pipe must fail with EPIPE instead of killing the
# script before the rollback runs.
trap '' PIPE

ROOT=""
READY_PAUSE=2
if [ -n "${KDN_DEPLOY_ROOT:-}" ]; then
  [ "${KDN_ALLOW_DEPLOY_ROOT:-0}" = "1" ] || die 2 "KDN_DEPLOY_ROOT is reserved for isolated repository tests"
  ROOT="${KDN_DEPLOY_ROOT%/}"
  READY_PAUSE="${KDN_READY_PAUSE:-2}"
  case "$READY_PAUSE" in
    ''|*[!0-9]*) die 2 "KDN_READY_PAUSE must be a number of seconds: $READY_PAUSE" ;;
  esac
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

PANEL="${KDN_PANEL:-192.168.2.1:8088}"
PROJECT_DIR=/opt/root/keenetic-discord-nfqws2
stage=""
dry_run=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --stage)
      [ "$#" -ge 2 ] || die 2 "--stage needs a value"
      stage="$2"
      shift 2
      ;;
    --project-dir)
      [ "$#" -ge 2 ] || die 2 "--project-dir needs a value"
      PROJECT_DIR="$2"
      shift 2
      ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die 2 "unknown argument: $1" ;;
  esac
done

[ -n "$stage" ] || die 2 "--stage is required"
case "$PROJECT_DIR" in
  /*) ;;
  *) die 2 "--project-dir must be an absolute path: $PROJECT_DIR" ;;
esac
case "$PROJECT_DIR" in
  *[!A-Za-z0-9._/-]*|*..*|*//*) die 2 "unsafe --project-dir: $PROJECT_DIR" ;;
esac
stage="${stage%/}"
[ "${stage%/*}" = "$ROOT/opt/tmp" ] || die 2 "--stage must be a directory in $ROOT/opt/tmp: $stage"
case "${stage##*/}" in
  kdn-deploy-?*) ;;
  *) die 2 "--stage must be named kdn-deploy-<stamp>: $stage" ;;
esac
[ -d "$stage" ] && [ ! -L "$stage" ] || die 2 "stage is not a directory: $stage"
for tool in curl jq python3 sha256sum pidof find sort; do
  command -v "$tool" >/dev/null 2>&1 || die 2 "required tool not found: $tool"
done
python3 -I -c 'import py_compile, runpy, tarfile' 2>/dev/null || die 2 "python3 lacks the tarfile, py_compile or runpy module"
python3 -I -c 'import ctypes; assert hasattr(ctypes.CDLL(None), "prctl")' 2>/dev/null || die 2 "python3 lacks ctypes/Linux prctl required for owned VPN probes"

LOG="$stage/deploy.log"
PROJECT="$ROOT$PROJECT_DIR"
APP_PY="$ROOT/opt/xkeen-web/app.py"
WEB_INIT="$ROOT/opt/etc/init.d/S99xkeen-web"
BACKUP_ROOT="$ROOT/opt/etc/xkeen-web-backups"
ARCHIVE="$stage/upload.tar.gz"
TREE="$stage/tree"
FILES="$stage/files.list"

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

state=""
backup=""
prev_latest=""
cur_tmp=""
deploy_umask="$(umask)"

check_idle() {
  for endpoint in /api/route/status /api/tuner/status /api/diagnostics/status /api/automation; do
    # An unreachable panel does not block: the deploy is what repairs it.
    busy_body="$stage/busy-check.json"
    status="$(curl --max-time 8 -sS -o "$busy_body" -w '%{http_code}' "http://$PANEL$endpoint" 2>/dev/null)" || continue
    if [ "$status" = 403 ]; then
      die 2 "panel refused the busy check (HTTP 403): KDN_PANEL must be the panel's own bind address"
    fi
    [ "$status" = 200 ] || continue
    body="$(cat "$busy_body")"
    if printf '%s' "$body" | jq -e '.active == true' >/dev/null 2>&1; then
      die 3 "busy ($endpoint)"
    fi
  done
}

check_archive() {
  [ -f "$ARCHIVE" ] && [ ! -L "$ARCHIVE" ] || die 2 "no upload archive: $ARCHIVE"
  rm -rf "$TREE"
  mkdir "$TREE"
  # Python reads the member names as stored: the tar of busybox hides a leading
  # / or ../ in its listing, so the check cannot rest on tar -t.
  python3 -I - "$ARCHIVE" "$TREE" "$FILES" <<'PY' || exit 2
import os
import re
import shutil
import sys
import tarfile

archive, tree, files_list = sys.argv[1:4]
SAFE = re.compile(r"[A-Za-z0-9._/@+=-]+")
PANEL = "generated/app.py"
LAUNCHER = "deploy-remote.sh"


def refuse(message):
    print("deploy: " + message, file=sys.stderr)
    sys.exit(2)


try:
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if not members:
            refuse("empty archive: " + archive)
        names = []
        for member in members:
            name = member.name
            if (
                not SAFE.fullmatch(name)
                or name.startswith(("/", "./"))
                or ".." in name
                or "//" in name
                or "/./" in name
                or name.endswith("/")
            ):
                refuse("unsafe archive entry: " + name)
            if not member.isreg():
                refuse("archive holds an entry that is not a regular file: " + name)
            names.append(name)
        if len(set(names)) != len(names):
            refuse("duplicate archive entry in " + archive)
        if PANEL not in names:
            refuse("archive lacks " + PANEL)
        for member in members:
            target = os.path.join(tree, member.name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tar.extractfile(member) as source, open(target, "wb") as out:
                shutil.copyfileobj(source, out)
except SystemExit:
    raise
except Exception as exc:  # corrupt or truncated archive
    refuse("unreadable archive %s: %s" % (archive, exc))

with open(files_list, "w", encoding="utf-8") as out:
    for name in names:
        if name not in (PANEL, LAUNCHER):
            out.write(name + "\n")
PY
}

check_syntax() {
  bad=0
  set -- "$TREE/generated/app.py"
  while IFS= read -r entry; do
    case "$entry" in
      *.py) set -- "$@" "$TREE/$entry" ;;
      *.sh)
        sh -n "$TREE/$entry" || {
          err "shell syntax error in $entry"
          bad=1
        }
        ;;
    esac
  done < "$FILES"
  python3 -m py_compile "$@" || {
    err "python syntax error (see above)"
    bad=1
  }
  [ "$bad" -eq 0 ] || die 2 "syntax check failed"
}

check_environment() {
  [ -d "$PROJECT" ] || die 2 "project directory not found: $PROJECT"
  [ -f "$APP_PY" ] || die 2 "panel not installed: $APP_PY"
  [ -x "$WEB_INIT" ] || die 2 "panel init script not found: $WEB_INIT"
}

snapshot() {
  printf 'xray pid=%s\n' "$(pidof xray || true)"
  printf 'nfqws2 pid=%s\n' "$(pidof nfqws2 || true)"
  for config in "$ROOT/opt/etc/nfqws2/nfqws2.conf" "$ROOT"/opt/etc/xray/configs/*.json; do
    if [ -f "$config" ]; then
      sha256sum "$config"
    else
      printf 'absent %s\n' "$config"
    fi
  done
}

list_files() {
  say "files to install: $(wc -l < "$FILES" | tr -d ' ')"
  while IFS= read -r file; do
    if [ ! -f "$PROJECT/$file" ]; then
      mark=new
    elif cmp -s "$TREE/$file" "$PROJECT/$file"; then
      mark=same
    else
      mark=changed
    fi
    printf '  %-7s %s\n' "$mark" "$file"
  done < "$FILES"
  printf '  %-7s %s\n' "panel" "$APP_PY"
}

make_backup() {
  backup_stamp="$(date +%Y%m%d-%H%M%S)"
  backup="$BACKUP_ROOT/$backup_stamp-deploy"
  backup_n=1
  while [ -e "$backup" ]; do
    backup_n=$((backup_n + 1))
    backup="$BACKUP_ROOT/$backup_stamp-deploy-$backup_n"
  done
  state=backup
  umask 077
  mkdir -p "$backup/project"
  : > "$backup/NEW_FILES"
  : > "$backup/NEW_DIRS"
  # rollback-xkeen-web.sh restores into the directory this deploy used.
  printf '%s\n' "$PROJECT_DIR" > "$backup/PROJECT_DIR"
  cp -p "$APP_PY" "$backup/app.py"
  while IFS= read -r file; do
    target="$PROJECT/$file"
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
      err "not a regular file: $target"
      return 1
    fi
    if [ -f "$target" ]; then
      mkdir -p "$backup/project/$(dirname "$file")"
      cp -p "$target" "$backup/project/$file"
    else
      printf '%s\n' "$file" >> "$backup/NEW_FILES"
      new_dir="$(dirname "$file")"
      while [ "$new_dir" != "." ] && [ ! -d "$PROJECT/$new_dir" ]; do
        printf '%s\n' "$new_dir" >> "$backup/NEW_DIRS"
        new_dir="$(dirname "$new_dir")"
      done
    fi
  done < "$FILES"
  prev_latest=""
  [ ! -s "$BACKUP_ROOT/latest.path" ] || prev_latest="$(sed -n '1p' "$BACKUP_ROOT/latest.path")"
  printf '%s\n' "$backup" > "$BACKUP_ROOT/.latest.path.$$"
  mv -f "$BACKUP_ROOT/.latest.path.$$" "$BACKUP_ROOT/latest.path"
  umask "$deploy_umask"
  state=armed
}

install_file() {
  cur_tmp="$2.deploy.$$"
  cp "$1" "$cur_tmp"
  chmod "$3" "$cur_tmp"
  mv -f "$cur_tmp" "$2"
  cur_tmp=""
}

install_all() {
  while IFS= read -r file; do
    mode=644
    case "$file" in
      *.sh|*.py) mode=755 ;;
    esac
    mkdir -p "$(dirname "$PROJECT/$file")"
    install_file "$TREE/$file" "$PROJECT/$file" "$mode"
  done < "$FILES"
  # Persist the logical router path in the launcher, without the fixture root.
  # setdefault preserves the documented environment override after reboot.
  if [ "$PROJECT_DIR" = /opt/root/keenetic-discord-nfqws2 ]; then
    install_file "$TREE/generated/app.py" "$APP_PY" 700
    return
  fi
  python3 -I - "$TREE/generated/app.py" "$stage/app-installed.py" "$PROJECT_DIR" <<'PYSHIM'
import pathlib
import sys
source, target, project = sys.argv[1:]
pathlib.Path(target).write_text("import os\nos.environ.setdefault('XKEEN_PROJECT_DIR', " + repr(project) + ")\n" + pathlib.Path(source).read_text())
PYSHIM
  install_file "$stage/app-installed.py" "$APP_PY" 700
}

panel_ready() {
  curl --max-time 8 -fsS -o /dev/null "http://$PANEL/" 2>/dev/null || return 1
  curl --max-time 8 -fsS "http://$PANEL/api/vpn-nodes" 2>/dev/null | jq -e '.ok == true' >/dev/null 2>&1
}

wait_for_panel() {
  attempt=0
  until panel_ready; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 15 ] || die 1 "panel did not become ready"
    sleep "$READY_PAUSE"
  done
}

# Runs an init script action ($1) with default signal dispositions: the panel
# daemon it spawns must not inherit the ignored SIGPIPE of this script. It also
# runs in /, not in the stage directory that prune_stages removes later.
panel_init() {
  ( trap - PIPE; cd /; exec "$WEB_INIT" "$1" )
}

restart_panel() {
  panel_init restart
}

# stop or start ($1) for the install. The daemon must not inherit the output of
# this script: over ssh that would keep the connection open until the panel
# exits.
panel_step() {
  panel_step_log="$stage/panel-$1.log"
  if panel_init "$1" > "$panel_step_log" 2>&1 < /dev/null; then
    sed 's/^/  /' "$panel_step_log" || true
  else
    sed 's/^/  /' "$panel_step_log" >&2 || true
    return 1
  fi
}

# Prints the pid file of a job process (route worker, tuner, diagnostics) that
# is alive, like the panel reads them; returns 1 when there is none.
find_live_job() {
  for job_pidfile in "$ROOT/opt/tmp/xkeen-route-switch/worker.pid" \
    "$ROOT/opt/tmp/xkeen-zapret-tuner/panel-launch.pid" \
    "$ROOT/opt/tmp/xkeen-diagnostics/panel-launch.pid"; do
    job_pid=""
    [ ! -f "$job_pidfile" ] || read -r job_pid < "$job_pidfile" || true
    case "$job_pid" in
      ''|*[!0-9]*) continue ;;
    esac
    # The panel does not take PID 1 and below for a job either.
    [ "$job_pid" -gt 1 ] 2>/dev/null || continue
    if kill -0 "$job_pid" 2>/dev/null; then
      printf '%s\n' "$job_pidfile"
      return 0
    fi
  done
  return 1
}

restore_file() {
  restore_tmp="$2.rollback.$$"
  mkdir -p "$(dirname "$2")" && cp -p "$1" "$restore_tmp" && mv -f "$restore_tmp" "$2"
}

# A deploy that was restored must not leave latest.path naming its backup: the
# rollback launcher would then restore the state it already has and lose the
# previous good backup.
restore_latest_pointer() {
  if [ -n "$prev_latest" ]; then
    ( umask 077; printf '%s\n' "$prev_latest" > "$BACKUP_ROOT/.latest.path.$$" ) &&
      mv -f "$BACKUP_ROOT/.latest.path.$$" "$BACKUP_ROOT/latest.path"
  else
    rm -f "$BACKUP_ROOT/latest.path"
  fi
}

rollback() {
  # Every step runs even when an earlier one fails.
  set +e
  umask "$deploy_umask"
  rb_failed=0
  if ! panel_step stop || ! panel_stopped; then
    err "ROLLBACK INCOMPLETE: panel stop unconfirmed; files unchanged, backup retained at $backup"
    return 1
  fi
  if [ -n "$cur_tmp" ]; then
    rm -f "$cur_tmp" || rb_failed=1
  fi
  if [ -d "$backup/project" ]; then
    (cd "$backup/project" && find . -type f) | sed 's|^\./||' > "$stage/restore.list" || rb_failed=1
    while IFS= read -r file; do
      restore_file "$backup/project/$file" "$PROJECT/$file" || {
        err "cannot restore $PROJECT/$file"
        rb_failed=1
      }
    done < "$stage/restore.list"
  fi
  while IFS= read -r file; do
    rm -f "$PROJECT/$file" || rb_failed=1
  done < "$backup/NEW_FILES"
  # NEW_DIRS lists the deepest directories first. The panel writes __pycache__
  # into every directory it imports from, which would fail the rmdir.
  while IFS= read -r dir; do
    rm -rf "$PROJECT/$dir/__pycache__" || rb_failed=1
    rmdir "$PROJECT/$dir" 2>/dev/null || true
  done < "$backup/NEW_DIRS"
  if restore_file "$backup/app.py" "$APP_PY" && chmod 700 "$APP_PY"; then
    :
  else
    err "cannot restore $APP_PY"
    rb_failed=1
  fi
  restart_panel >/dev/null 2>&1 || rb_failed=1
  if [ "$rb_failed" -eq 0 ]; then
    restore_latest_pointer || err "cannot restore $BACKUP_ROOT/latest.path; it still names $backup"
    say "restored the previous files and restarted the panel"
  else
    err "ROLLBACK INCOMPLETE: restore by hand from $backup"
  fi
}

finish() {
  finish_rc=$?
  set +e
  trap - 0
  # A no-op handler keeps the rollback from being cut short by a second signal;
  # unlike an ignored signal it is reset to the default in exec'd children.
  trap : HUP INT TERM
  case "$state" in
    backup)
      if [ "$finish_rc" -ne 0 ]; then
        rm -rf "$backup"
        err "backup failed; nothing was changed"
        exit 1
      fi
      ;;
    armed)
      if [ "$finish_rc" -ne 0 ]; then
        err "failed (exit $finish_rc); restoring $backup"
        rollback
        exit 1
      fi
      ;;
  esac
  exit "$finish_rc"
}

prune_stages() {
  prune_count=0
  ls -d "$ROOT"/opt/tmp/kdn-deploy-* 2>/dev/null | LC_ALL=C sort -r | while IFS= read -r old; do
    prune_count=$((prune_count + 1))
    [ "$prune_count" -gt 2 ] || continue
    [ "$old" != "$stage" ] || continue
    [ -d "$old" ] || continue
    rm -rf "$old"
  done
}

trap finish 0
trap 'exit 130' HUP INT TERM

check_archive
VERSION_POLICY="$TREE/tools/router/kdn/common/xkeen.py"
[ -f "$VERSION_POLICY" ] && [ ! -L "$VERSION_POLICY" ] || die 2 "missing shared XKeen version policy"
python3 -I "$VERSION_POLICY" --require >/dev/null || die 2 "unsupported XKeen target; XKeen2.1+ is required"
check_idle
check_syntax
check_environment
before="$(snapshot)" || die 2 "cannot read the invariants"
say "invariants"
printf '%s\n' "$before" | sed 's/^/  /' || true
list_files || true
if [ "$dry_run" -eq 1 ]; then
  say "dry run: nothing was installed"
  exit 0
fi

make_backup
say "backup $backup"
say "stopping the panel"
if ! panel_step stop || ! panel_stopped; then
  # Stop was not confirmed: restoring even identical files could race a live
  # panel. Only discard this unused backup and restore its previous pointer.
  state=""
  restore_latest_pointer && rm -rf "$backup"
  die 1 "panel stop failed; no software files changed"
fi
if busy_pidfile="$(find_live_job)"; then
  # Nothing was copied: start the panel again and leave as if the deploy had
  # not begun, without its backup.
  say "starting the panel again"
  panel_step start || die 1 "panel start failed"
  state=""
  if restore_latest_pointer; then
    rm -rf "$backup"
  else
    err "cannot restore $BACKUP_ROOT/latest.path; it still names $backup"
  fi
  die 3 "busy ($busy_pidfile); delete the file if that pid is not a running panel job"
fi
install_all
say "starting the panel"
panel_step start || die 1 "panel start failed"
wait_for_panel
after="$(snapshot)"
if [ "$after" != "$before" ]; then
  err "invariants changed:"
  printf '%s\n' "$after" | sed 's/^/  /' >&2 || true
  exit 1
fi

state=finished
prune_stages || true
say "ok backup=$backup"
