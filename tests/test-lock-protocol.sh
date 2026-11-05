#!/bin/sh
set -eu

# The project lock (a mkdir directory with a pid file in it) is taken by the
# engine, the tuner runner and kdn.common.lock, and during an upgrade copies of
# different ages meet on the same directory. This test runs the lock functions
# of apply-discord-nfqws2.sh and tools/windows/router-candidate-runner.sh on
# their own (extracted with awk, the rest of those scripts is not executed)
# and Python through PYTHONPATH, all on one lock in a temporary root:
#   a. Python holds the lock: the engine and the runner say "busy";
#   b. the engine or the runner holds it: Python gets LockBusy with its pid;
#   c. a lock without a pid whose holder writes it a second later is not
#      stale (the mkdir/pid race), for the engine, the runner and Python;
#   d. a lock that stays without a pid is stale after KD_LOCK_PID_WAIT;
#   e. a lock of a dead pid is taken over by all three; the takeover mutex of
#      Python (a file beside the lock directory) does not bother the shells;
#   f. the pid.tmp-N file that a killed Python contender leaves behind does
#      not block the shells, that of a live one does.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ENGINE="$SCRIPT_DIR/tests/fixtures/engine/legacy-apply-phase6.sh.txt"
RUNNER="$SCRIPT_DIR/tools/windows/router-candidate-runner.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-lock-protocol.XXXXXX")"
HELPERS=""

cleanup() {
  for helper in $HELPERS; do
    kill "$helper" 2>/dev/null || true
    wait "$helper" 2>/dev/null || true
  done
  rm -rf "$FIXTURE"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' HUP TERM

# The shell the functions run in: the one this test runs under ("busybox sh" in
# the busybox run), so that ash itself is exercised.
LOCK_SHELL="${TEST_SHELL:-sh}"
LOCK_LOGICAL=/opt/tmp/keenetic-discord-nfqws2.lock
LOCK_DIR="$FIXTURE$LOCK_LOGICAL"
export LOCK_TEST_ROOT="$FIXTURE"
PYTHONPATH="$SCRIPT_DIR/tools/router"
export PYTHONPATH

# Fractional sleeps only for polling the helpers; the functions under test
# sleep whole seconds.
if sleep 0.1 2>/dev/null; then tick=0.1; else tick=1; fi

fail_case() {
  echo "ERROR: $*" >&2
  exit 1
}

extract() {
  awk -v name="$2" '
    $0 == name "() {" { copying = 1 }
    copying { print }
    copying && /^}$/ { exit }
  ' "$1"
}

{
  cat <<'EOF'
set -eu
root_path() { printf '%s%s\n' "$LOCK_TEST_ROOT" "$1"; }
PROJECT=keenetic-discord-nfqws2
LOCK_DIR="$(root_path /opt/tmp/keenetic-discord-nfqws2.lock)"
LOCK_HELD=0
recover_stale_tuner_runs() { :; }
EOF
  extract "$ENGINE" release_lock
  extract "$ENGINE" acquire_lock
} > "$FIXTURE/engine-lock.sh"
{
  cat <<'EOF'
set -u
root_path() { printf '%s%s\n' "$LOCK_TEST_ROOT" "$1"; }
LOCK_DIR="$(root_path /opt/tmp/keenetic-discord-nfqws2.lock)"
LOCK_OWNED=0
EOF
  extract "$RUNNER" release_project_lock
  extract "$RUNNER" acquire_project_lock
} > "$FIXTURE/runner-lock.sh"
for required in engine-lock:release_lock engine-lock:acquire_lock \
  runner-lock:release_project_lock runner-lock:acquire_project_lock; do
  grep -q "^${required#*:}() {\$" "$FIXTURE/${required%%:*}.sh" || fail_case "${required#*:}() is missing"
done

# lock_run LIBRARY FUNCTION: calls FUNCTION in a fresh shell with the
# assignments of LOCK_RUN_ENV (set on a line of its own) in its environment;
# sets rc and out (stdout and stderr together).
LOCK_RUN_ENV=""
lock_run() {
  rc=0
  # shellcheck disable=SC2086 # LOCK_SHELL may be "busybox sh", LOCK_RUN_ENV is a word list
  out="$(env $LOCK_RUN_ENV $LOCK_SHELL -c '. "$1"; "$2"' sh "$FIXTURE/$1.sh" "$2" 2>&1)" || rc=$?
  LOCK_RUN_ENV=""
}

PY_HOLD='
import os, sys, time
from kdn.common import lock
lock.ProjectLock(sys.argv[1]).acquire()
print("held", os.getpid(), flush=True)
time.sleep(60)
'
PY_TRY='
import sys
from kdn.common import lock
try:
    lock.ProjectLock(sys.argv[1], pid_wait=float(sys.argv[2])).acquire()
except lock.LockBusy as error:
    print("busy", error.pid)
else:
    with open(sys.argv[1] + "/pid", encoding="ascii") as stream:
        print("acquired", stream.read().strip())
'

reset_lock() {
  rm -rf "$LOCK_DIR"
  mkdir -p "$FIXTURE/opt/tmp"
}

forget_helper() {
  kept=""
  for known in $HELPERS; do
    [ "$known" = "$1" ] || kept="$kept $known"
  done
  HELPERS="$kept"
}

# start_helper NAME COMMAND...: runs a command in the background and waits
# until it printed "held <pid>" (its own pid, the one in the pid file); that
# pid is left in helper_pid.
start_helper() {
  helper_name="$1"
  shift
  rm -f "$FIXTURE/$helper_name.out"
  : > "$FIXTURE/$helper_name.out"
  "$@" > "$FIXTURE/$helper_name.out" 2>&1 &
  helper_job=$!
  HELPERS="$HELPERS $helper_job"
  helper_tries=0
  while [ ! -s "$FIXTURE/$helper_name.out" ]; do
    helper_tries=$((helper_tries + 1))
    [ "$helper_tries" -lt 200 ] || fail_case "$helper_name did not start: $(cat "$FIXTURE/$helper_name.out")"
    sleep "$tick"
  done
  helper_pid="$(sed -n 's/^held \([0-9][0-9]*\)$/\1/p' "$FIXTURE/$helper_name.out")"
  [ -n "$helper_pid" ] || fail_case "$helper_name did not take the lock: $(cat "$FIXTURE/$helper_name.out")"
  [ "$helper_pid" = "$helper_job" ] || HELPERS="$HELPERS $helper_pid"
}

stop_helper() {
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
  forget_helper "$1"
}

# A shell that takes the lock with LIBRARY/FUNCTION and keeps it (the pid
# printed is the one in the pid file).
start_shell_holder() {
  # shellcheck disable=SC2086 # LOCK_SHELL may be "busybox sh"
  start_helper "$1" $LOCK_SHELL -c '. "$1"; "$2" || exit 1; echo "held $$"; exec sleep 60' sh "$FIXTURE/$2.sh" "$3"
}

start_sleeper() {
  sleep 60 &
  sleeper_pid=$!
  HELPERS="$HELPERS $sleeper_pid"
}

dead_pid() {
  sh -c 'exit 0' &
  dead=$!
  wait "$dead" || true
}

expect_rc() {
  [ "$rc" -eq "$2" ] || fail_case "$1: rc=$rc, expected $2: $out"
}

expect_in_output() {
  case "$out" in
    *"$2"*) ;;
    *) fail_case "$1: output lacks \"$2\": $out" ;;
  esac
}

expect_not_in_output() {
  case "$out" in
    *"$2"*) fail_case "$1: output has \"$2\": $out" ;;
  esac
}

expect_pid_file() {
  [ "$(cat "$LOCK_DIR/pid" 2>/dev/null)" = "$2" ] || fail_case "$1: pid file is \"$(cat "$LOCK_DIR/pid" 2>/dev/null)\", expected $2"
}

py_try() {
  rc=0
  out="$(python3 -c "$PY_TRY" "$LOCK_DIR" "$1" 2>&1)" || rc=$?
}

# (a) Python holds the lock.
reset_lock
start_helper py-holder python3 -c "$PY_HOLD" "$LOCK_DIR"
holder_pid="$helper_pid"
expect_pid_file "(a) python holder" "$holder_pid"
lock_run engine-lock acquire_lock
expect_rc "(a) engine" 1
expect_in_output "(a) engine" "is active (PID $holder_pid)"
expect_not_in_output "(a) engine" "Removing stale lock"
lock_run runner-lock acquire_project_lock
expect_rc "(a) runner" 1
expect_pid_file "(a) after the shells" "$holder_pid"
stop_helper "$holder_pid"

# (b) The engine, then the runner hold the lock; Python and the other shell see it.
for holder in engine-lock:acquire_lock runner-lock:acquire_project_lock; do
  library="${holder%%:*}"
  lock_function="${holder#*:}"
  reset_lock
  start_shell_holder "$library-holder" "$library" "$lock_function"
  holder_pid="$helper_pid"
  expect_pid_file "(b) $library holder" "$holder_pid"
  py_try 0.2
  expect_rc "(b) python after $library" 0
  [ "$out" = "busy $holder_pid" ] || fail_case "(b) python after $library: \"$out\", expected \"busy $holder_pid\""
  lock_run engine-lock acquire_lock
  expect_rc "(b) engine after $library" 1
  expect_in_output "(b) engine after $library" "is active (PID $holder_pid)"
  lock_run runner-lock acquire_project_lock
  expect_rc "(b) runner after $library" 1
  expect_pid_file "(b) after $library" "$holder_pid"
  stop_helper "$holder_pid"
done

# (c) A lock without a pid; its holder writes the pid a second later. Nobody
# may take it as stale.
start_sleeper
live_pid="$sleeper_pid"
for contender in engine-lock:acquire_lock runner-lock:acquire_project_lock python:; do
  library="${contender%%:*}"
  lock_function="${contender#*:}"
  reset_lock
  mkdir "$LOCK_DIR"
  (sleep 1; echo "$live_pid" > "$LOCK_DIR/pid") &
  writer_pid=$!
  HELPERS="$HELPERS $writer_pid"
  if [ "$library" = python ]; then
    py_try 3
    expect_rc "(c) python" 0
    [ "$out" = "busy $live_pid" ] || fail_case "(c) python: \"$out\", expected \"busy $live_pid\""
  else
    lock_run "$library" "$lock_function"
    expect_rc "(c) $library" 1
    expect_not_in_output "(c) $library" "Removing stale lock"
    case "$library" in
      engine-lock) expect_in_output "(c) $library" "is active (PID $live_pid)" ;;
    esac
  fi
  wait "$writer_pid"
  expect_pid_file "(c) $library: the holder's pid is still there" "$live_pid"
done

# (c') A lock without a pid whose directory then disappears (the holder gave
# up between mkdir and the pid): the contender makes a new try, no stale lock.
for contender in engine-lock:acquire_lock runner-lock:acquire_project_lock; do
  library="${contender%%:*}"
  lock_function="${contender#*:}"
  reset_lock
  mkdir "$LOCK_DIR"
  (sleep 1; rmdir "$LOCK_DIR") &
  writer_pid=$!
  HELPERS="$HELPERS $writer_pid"
  lock_run "$library" "$lock_function"
  expect_rc "(c') $library" 0
  expect_not_in_output "(c') $library" "Removing stale lock"
  wait "$writer_pid"
  [ -s "$LOCK_DIR/pid" ] || fail_case "(c') $library: the lock has no pid"
done

# (d) A lock that stays without a pid is stale after KD_LOCK_PID_WAIT seconds.
for contender in engine-lock:acquire_lock runner-lock:acquire_project_lock; do
  library="${contender%%:*}"
  lock_function="${contender#*:}"
  reset_lock
  mkdir "$LOCK_DIR"
  LOCK_RUN_ENV="KD_LOCK_PID_WAIT=1"
  lock_run "$library" "$lock_function"
  expect_rc "(d) $library" 0
  case "$library" in
    engine-lock) expect_in_output "(d) $library" "Removing stale lock: $LOCK_DIR" ;;
  esac
  [ -s "$LOCK_DIR/pid" ] || fail_case "(d) $library: the lock has no pid"
done
reset_lock
mkdir "$LOCK_DIR"
py_try 1
expect_rc "(d) python" 0
case "$out" in
  "acquired "[0-9]*) ;;
  *) fail_case "(d) python: $out" ;;
esac

# (d') A pid file that holds garbage counts as no pid.
reset_lock
mkdir "$LOCK_DIR"
echo garbage > "$LOCK_DIR/pid"
LOCK_RUN_ENV="KD_LOCK_PID_WAIT=0"
lock_run engine-lock acquire_lock
expect_rc "(d') engine" 0
expect_in_output "(d') engine" "Removing stale lock"

# (d'') A stale lock directory with another file in it is refused, as before.
reset_lock
mkdir "$LOCK_DIR"
echo x > "$LOCK_DIR/other"
LOCK_RUN_ENV="KD_LOCK_PID_WAIT=0"
lock_run engine-lock acquire_lock
expect_rc "(d'') engine" 1
expect_in_output "(d'') engine" "stale lock directory is not empty"

# (e) The holder is dead: a stale lock for all three, with no waiting.
dead_pid
dead_holder="$dead"
for contender in engine-lock:acquire_lock runner-lock:acquire_project_lock python:; do
  library="${contender%%:*}"
  lock_function="${contender#*:}"
  reset_lock
  mkdir "$LOCK_DIR"
  echo "$dead_holder" > "$LOCK_DIR/pid"
  started="$(date +%s)"
  if [ "$library" = python ]; then
    py_try 2
    expect_rc "(e) python" 0
    case "$out" in
      "acquired "[0-9]*) ;;
      *) fail_case "(e) python: $out" ;;
    esac
  else
    lock_run "$library" "$lock_function"
    expect_rc "(e) $library" 0
    case "$library" in
      engine-lock) expect_in_output "(e) $library" "Removing stale lock" ;;
    esac
  fi
  [ "$(cat "$LOCK_DIR/pid")" != "$dead_holder" ] || fail_case "(e) $library: the dead pid is still in the lock"
  [ $(($(date +%s) - started)) -le 1 ] || fail_case "(e) $library: a dead pid was waited for"
done

# (e') Python's takeover mutex is a file beside the lock directory (never in it);
# the shells do not look at it and take over as before.
[ -f "$LOCK_DIR.takeover" ] || fail_case "(e') python left no takeover mutex file beside the lock"
[ "$(ls -A "$LOCK_DIR")" = pid ] || fail_case "(e') the lock directory holds more than the pid: $(ls -A "$LOCK_DIR")"
for contender in engine-lock:acquire_lock runner-lock:acquire_project_lock; do
  library="${contender%%:*}"
  lock_function="${contender#*:}"
  reset_lock
  mkdir "$LOCK_DIR"
  echo "$dead_holder" > "$LOCK_DIR/pid"
  lock_run "$library" "$lock_function"
  expect_rc "(e') $library with the mutex file around" 0
  [ "$(ls -A "$LOCK_DIR")" = pid ] || fail_case "(e') $library: $(ls -A "$LOCK_DIR")"
done

# (f) kdn.common.lock leaves pid.tmp-N for the moment of its own step. The
# file of a killed contender must not wedge the shells ("not empty"); that of
# a live contender keeps the directory.
for contender in engine-lock:acquire_lock runner-lock:acquire_project_lock; do
  library="${contender%%:*}"
  lock_function="${contender#*:}"
  reset_lock
  mkdir "$LOCK_DIR"
  echo "$dead_holder" > "$LOCK_DIR/pid.tmp-$dead_holder"
  LOCK_RUN_ENV="KD_LOCK_PID_WAIT=0"
  lock_run "$library" "$lock_function"
  expect_rc "(f) $library after a dead contender" 0
  [ "$(ls -A "$LOCK_DIR")" = pid ] || fail_case "(f) $library: leftover of a dead contender stays: $(ls -A "$LOCK_DIR")"

  reset_lock
  mkdir "$LOCK_DIR"
  echo "$live_pid" > "$LOCK_DIR/pid.tmp-$live_pid"
  LOCK_RUN_ENV="KD_LOCK_PID_WAIT=0"
  lock_run "$library" "$lock_function"
  expect_rc "(f) $library with a live contender" 1
  [ -e "$LOCK_DIR/pid.tmp-$live_pid" ] || fail_case "(f) $library removed the file of a live contender"
  case "$library" in
    engine-lock) expect_in_output "(f) $library" "stale lock directory is not empty" ;;
  esac
done

# The runner started by the job (KD_TUNER_LOCK_HELD) accepts the job's lock
# and still refuses a lock of somebody else.
reset_lock
start_helper py-holder python3 -c "$PY_HOLD" "$LOCK_DIR"
holder_pid="$helper_pid"
LOCK_RUN_ENV="KD_TUNER_LOCK_HELD=$holder_pid"
lock_run runner-lock acquire_project_lock
expect_rc "job lock accepted by the runner" 0
LOCK_RUN_ENV="KD_TUNER_LOCK_HELD=$((holder_pid + 1))"
lock_run runner-lock acquire_project_lock
expect_rc "foreign lock refused by the runner" 1
expect_pid_file "job lock kept" "$holder_pid"
stop_helper "$holder_pid"

echo lock-protocol-tests-ok
