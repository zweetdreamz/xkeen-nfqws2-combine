#!/bin/sh
# Entware init. Only the panel is supervised; job workers have their own sessions.
set -u
PATH="/opt/bin:/opt/sbin:$PATH"
export PATH
ROOT=
STEP=2
MAX=60
LIMIT=1048576
PORT=8088
if [ "${KDN_ALLOW_INIT_ROOT:-}" = 1 ]; then
    ROOT=${KDN_INIT_ROOT:-}
    STEP=${KDN_INIT_DELAY_STEP:-2}
    MAX=${KDN_INIT_DELAY_MAX:-60}
    LIMIT=${KDN_INIT_ERR_LIMIT:-1048576}
    PORT=${KDN_INIT_PORT:-8088}
    PATH="$ROOT/opt/bin:$PATH"
fi
for number in "$STEP" "$MAX" "$LIMIT" "$PORT"; do
    case "$number" in ''|*[!0-9]*) echo 'invalid init parameter' >&2; exit 2 ;; esac
done
[ "$STEP" -gt 0 ] && [ "$MAX" -ge "$STEP" ] && [ "$LIMIT" -gt 0 ] && [ "$PORT" -le 65535 ] || exit 2
APP="$ROOT/opt/xkeen-web/app.py"
PIDFILE="$ROOT/opt/var/run/xkeen-web.pid"
CHILD="$ROOT/opt/var/run/xkeen-web.child.pid"
ERR="$ROOT/opt/var/log/xkeen-web.err"
SELF="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")"

read_pid() {
    [ -f "$1" ] || return 1
    read -r candidate < "$1" || return 1
    case "$candidate" in ''|*[!0-9]*) return 1 ;; esac
    [ "$candidate" -gt 1 ] || return 1
    printf '%s\n' "$candidate"
}
has_arg() {
    [ -r "/proc/$1/cmdline" ] || return 1
    tr '\000' '\n' < "/proc/$1/cmdline" | grep -F -x -q -- "$2"
}
has_env() {
    [ -r "/proc/$1/environ" ] || return 1
    tr '\000' '\n' < "/proc/$1/environ" 2>/dev/null | grep -F -x -q -- "$2"
}
supervisor() {
    has_arg "$1" "$SELF" && has_arg "$1" supervise || return 1
    # The same source init can supervise several independent test roots.
    # Exact argv alone does not make a process part of this instance.
    if has_env "$1" KDN_ALLOW_INIT_ROOT=1; then
        if [ -n "$ROOT" ]; then
            has_env "$1" "KDN_INIT_ROOT=$ROOT"
        else
            ! tr '\000' '\n' < "/proc/$1/environ" 2>/dev/null | grep -q '^KDN_INIT_ROOT=.'
        fi
    else
        [ -z "$ROOT" ]
    fi
}
panel() { has_arg "$1" "$APP"; }
find_panels() {
    for entry in /proc/[0-9]*; do
        found=${entry##*/}
        if panel "$found"; then printf '%s\n' "$found"; fi
    done
}
terminate() {
    # Revalidate identity on every iteration: never signal a reused PID.
    target=$1
    kind=$2
    remaining=$3
    "$kind" "$target" || return 0
    kill -TERM "$target" 2>/dev/null || :
    while "$kind" "$target" && [ "$remaining" -gt 0 ]; do
        sleep 1
        remaining=$((remaining - 1))
    done
    if "$kind" "$target"; then kill -KILL "$target" 2>/dev/null || :; fi
}
port_busy() {
    hex=$(printf '%04X' "$PORT")
    awk -v port="$hex" '$4 == "0A" {split($2,a,":"); if (a[2] == port) busy=1} END {exit !busy}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
process_token() {
    # Start time plus boot id distinguishes a live lock owner from PID reuse
    # and from a lock left on persistent /opt by a previous boot.
    boot=unknown
    read -r boot < /proc/sys/kernel/random/boot_id 2>/dev/null || :
    started=$(awk '{sub(/^.*\) /, ""); if ($1 == "Z" || $1 == "X") exit 1; print $20}' "/proc/$1/stat" 2>/dev/null) || return 1
    printf '%s:%s\n' "$boot" "$started"
}
tracked_supervisor() {
    supervisor "$1" && return 0
    # A just-forked child may not have exec'd the supervisor yet. A boot/start
    # token fences that PID without trusting an unrelated, reused pidfile.
    [ "$(read_pid "$PIDFILE" || :)" = "$1" ] || return 1
    token=$(cat "$PIDFILE.token" 2>/dev/null) || return 1
    [ -n "$token" ] && [ "$token" = "$(process_token "$1")" ] && kill -0 "$1" 2>/dev/null
}
start_lock_live() {
    owner=$(read_pid "$PIDFILE.start-lock/owner") || return 1
    [ "$owner" != "$$" ] || return 1
    kill -0 "$owner" 2>/dev/null || return 1
    token=$(cat "$PIDFILE.start-lock/token" 2>/dev/null) || return 1
    [ "$token" = "$(process_token "$owner")" ]
}
control_serialized() {
    mkdir -p "${PIDFILE%/*}" "${ERR%/*}" || return 1
    # Upgrade only the known old directory-lock format. Never remove a live
    # owner's lock or recursively delete an unexpected object.
    if [ -d "$PIDFILE.start-lock" ]; then
        if start_lock_live; then echo 'xkeen-web start already in progress' >&2; return 1; fi
        rm -f "$PIDFILE.start-lock/owner" "$PIDFILE.start-lock/token" 2>/dev/null || :
        rmdir "$PIDFILE.start-lock" 2>/dev/null || { [ ! -d "$PIDFILE.start-lock" ] || return 1; }
    fi
    # A kernel lock cannot remain held after exit/reboot, and cannot suffer
    # the stale-directory ABA race between simultaneous start invocations.
    python3 - "$SELF" "$PIDFILE.start-lock" "$1" <<'PY'
import os
import stat
import subprocess
import sys
try:
    import fcntl
except ImportError:
    print("xkeen-web init requires Python3 fcntl", file=sys.stderr)
    raise SystemExit(1)
fd = None
try:
    fd = os.open(sys.argv[2], os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise OSError("unsafe start lock")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    environment = {**os.environ, "KDN_INIT_LOCKED": "1"}
    # close_fds keeps the lock out of the supervisor and application.
    raise SystemExit(subprocess.run(["sh", sys.argv[1], "control-locked", sys.argv[3]], env=environment, close_fds=True).returncode)
except BlockingIOError:
    print("xkeen-web start already in progress", file=sys.stderr)
    raise SystemExit(1)
except OSError as exc:
    print("xkeen-web start failed: " + str(exc), file=sys.stderr)
    raise SystemExit(1)
finally:
    if fd is not None:
        os.close(fd)
PY
}
start() {
    current=$(read_pid "$PIDFILE") || current=
    if [ -n "$current" ] && tracked_supervisor "$current"; then
        echo 'xkeen-web already running'
        return 0
    fi
    legacy=$(find_panels | head -n 1)
    if [ -n "$legacy" ]; then
        echo "xkeen-web already running (unsupervised, PID $legacy); use restart to supervise it"
        return 0
    fi
    if port_busy; then echo "port $PORT is busy" >&2; return 1; fi
    if [ -f "$ERR" ] && [ "$(wc -c < "$ERR")" -gt "$LIMIT" ]; then
        chmod 600 "$ERR" || return 1
        mv -f "$ERR" "$ERR.1" || return 1
    fi
    # The supervisor writes its own PID before launching the child.
    nohup sh "$SELF" supervise </dev/null >/dev/null 2>&1 &
    launched=$!
    printf '%s\n' "$launched" > "$PIDFILE"
    process_token "$launched" > "$PIDFILE.token" || :
    echo 'xkeen-web started (supervised)'
}
stop() {
    current=$(read_pid "$PIDFILE") || current=
    if [ -n "$current" ] && tracked_supervisor "$current"; then terminate "$current" tracked_supervisor 15; fi
    # Also reap an orphan left by older init versions, recognised by exact argv.
    for entry in /proc/[0-9]*; do
        orphan=${entry##*/}
        if supervisor "$orphan"; then terminate "$orphan" supervisor 15; fi
    done
    child=$(read_pid "$CHILD") || child=
    if [ -n "$child" ]; then terminate "$child" panel 10; fi
    for legacy in $(find_panels); do terminate "$legacy" panel 10; done
    rm -f "$PIDFILE" "$PIDFILE.token" "$CHILD"
    echo 'xkeen-web stopped'
}
status() {
    current=$(read_pid "$PIDFILE") || current=
    if [ -n "$current" ] && tracked_supervisor "$current"; then
        echo "xkeen-web running (supervised), pid=$current, panel=$(read_pid "$CHILD" || :)"
        return 0
    fi
    legacy=$(find_panels | head -n 1)
    if [ -n "$legacy" ]; then echo "xkeen-web running (unsupervised), pid=$legacy"; return 0; fi
    echo 'xkeen-web stopped'
    return 1
}
bounded_errors() {
    # Keep the FIFO/pipe open between reads: the application must
    # never receive SIGPIPE at a rotation boundary. No additional Python daemon.
    exec 3<&0
    reader=
    trap 'if [ -n "$reader" ]; then kill "$reader" 2>/dev/null || :; wait "$reader" 2>/dev/null || :; fi; exit 0' TERM INT
    while :; do
        [ ! -L "$ERR" ] && [ ! -L "$ERR.1" ] || exit 1
        [ ! -e "$ERR" ] || [ -f "$ERR" ] || exit 1
        [ ! -e "$ERR.1" ] || [ -f "$ERR.1" ] || exit 1
        : >> "$ERR" || exit 1
        chmod 600 "$ERR" || exit 1
        size=$(wc -c < "$ERR")
        if [ "$size" -ge "$LIMIT" ]; then
            mv -f "$ERR" "$ERR.1" || exit 1
            continue
        fi
        remaining=$((LIMIT - size))
        chunk=$remaining
        [ "$chunk" -le 4096 ] || chunk=4096
        # One read, not a full-block read: publish a short live message at
        # once instead of waiting until LIMIT bytes or EOF arrive.
        dd bs="$chunk" count=1 <&3 >> "$ERR" 2>/dev/null &
        reader=$!
        wait "$reader" || exit 1
        reader=
        after=$(wc -c < "$ERR")
        [ "$after" -gt "$size" ] || exit 0
    done
}
finish_error_writer() {
    tries=20
    while kill -0 "$logger" 2>/dev/null && [ "$tries" -gt 0 ]; do
        sleep 0.05
        tries=$((tries - 1))
    done
    if has_arg "$logger" "$SELF" && has_arg "$logger" log-errors; then
        kill -TERM "$logger" 2>/dev/null || :
    fi
    wait "$logger" 2>/dev/null || :
    logger=
}
cleanup_supervisor() {
    if [ -n "$logger" ]; then finish_error_writer; fi
    rm -f "$log_fifo"
    rmdir "$log_dir" 2>/dev/null || :
    # An old generation cannot erase a replacement's tracking files.
    if [ "$(read_pid "$PIDFILE" || :)" = "$$" ]; then
        rm -f "$PIDFILE" "$PIDFILE.token" "$CHILD"
    elif [ -z "$(read_pid "$PIDFILE" || :)" ] && [ -n "$child" ] &&
         [ "$(read_pid "$CHILD" || :)" = "$child" ]; then
        # The legacy init removes the supervisor pid immediately after TERM.
        # Its own child's marker still needs cleaning, never a replacement's.
        rm -f "$CHILD"
    fi
}
supervise() {
    umask 077
    stopping=0
    child=
    sleeper=
    logger=
    log_dir=$(mktemp -d "${PIDFILE%/*}/xkeen-web-err.XXXXXX") || exit 1
    log_fifo="$log_dir/pipe"
    mkfifo "$log_fifo" || { rmdir "$log_dir"; exit 1; }
    trap 'stopping=1; if [ -n "$child" ] && panel "$child"; then kill -TERM "$child" 2>/dev/null || :; fi; if [ -n "$sleeper" ]; then kill "$sleeper" 2>/dev/null || :; fi' TERM INT
    trap cleanup_supervisor 0
    printf '%s\n' "$$" > "$PIDFILE" || exit 1
    process_token "$$" > "$PIDFILE.token" || :
    delay=$STEP
    while [ "$stopping" = 0 ]; do
        began=$(date +%s)
        sh "$SELF" log-errors < "$log_fifo" &
        logger=$!
        python3 "$APP" </dev/null > "$log_fifo" 2>&1 &
        child=$!
        printf '%s\n' "$child" > "$CHILD"
        wait "$child"
        result=$?
        if [ "$stopping" = 1 ]; then
            terminate "$child" panel 10
            wait "$child" 2>/dev/null || :
            break
        fi
        finish_error_writer
        child=
        rm -f "$CHILD"
        lived=$(( $(date +%s) - began ))
        if [ "$lived" -ge 60 ]; then delay=$STEP; fi
        printf '%s panel exited rc=%s runtime=%ss; retry in %ss\n' "$(date -u +%FT%TZ)" "$result" "$lived" "$delay" | sh "$SELF" log-errors
        sleep "$delay" &
        sleeper=$!
        wait "$sleeper" || :
        sleeper=
        if [ "$lived" -lt 60 ]; then
            delay=$((delay * 2))
            if [ "$delay" -gt "$MAX" ]; then delay=$MAX; fi
        fi
    done
}
case "${1:-}" in
    start|stop|restart) control_serialized "$1" ;;
    control-locked)
        [ "${KDN_INIT_LOCKED:-}" = 1 ] || exit 2
        unset KDN_INIT_LOCKED
        case "${2:-}" in start) start ;; stop) stop ;; restart) stop; start ;; *) exit 2 ;; esac
        ;;
    status) status ;;
    supervise) supervise ;;
    log-errors) bounded_errors ;;
    *) echo "Usage: $0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
