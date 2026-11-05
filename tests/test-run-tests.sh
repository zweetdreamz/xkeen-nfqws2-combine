#!/bin/sh
set -eu

# tests/docker/run-tests.sh with a stub "docker" on PATH: `--shell all` splits
# the shell suites of each shell over several containers that together run
# every tests/test-*.sh once, overlapping runs keep their own exit codes and
# logs, the log directories are pruned, and a terminated run stops its
# containers by name.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/tests/docker/run-tests.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-run-tests.XXXXXX")"
trap 'rm -rf "$FIXTURE"' 0 HUP INT TERM
MOCK_BIN="$FIXTURE/bin"
mkdir -p "$MOCK_BIN"

# STUB_JOBS: "<container>=<exit code>[@<file to wait for>]", <container> is
# the name without "kdn-tests-<pid>-" (dash-1, py-node). STUB_LAYOUT_LOG, if
# set, gets "<container> <shell> <only> <suite selection>" per container.
cat > "$MOCK_BIN/docker" <<'MOCK'
#!/bin/sh
case "$1" in
  run) ;;
  kill)
    echo "$2" >> "$STUB_KILL_LOG"
    exit 0
    ;;
  *) exit 0 ;;
esac
name=""
shell=""
only=""
selection=all
prefetch=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --entrypoint) prefetch=1 ;;
    --name) name="${2#kdn-tests-*-}" ;;
    --shell) shell="$2" ;;
    --only) only="$2" ;;
    --suites|--skip-suites) selection="$1=$2" ;;
  esac
  shift
done
[ "$prefetch" -eq 0 ] || exit 0
[ -z "${STUB_LAYOUT_LOG:-}" ] || echo "$name $shell $only $selection" >> "$STUB_LAYOUT_LOG"
spec=""
for entry in ${STUB_JOBS:-}; do
  case "$entry" in
    "$name="*) spec="${entry#*=}" ;;
  esac
done
code="${spec%%@*}"
wait_file=""
case "$spec" in
  *@*) wait_file="${spec#*@}" ;;
esac
echo "stub ${STUB_TAG:-?} $name $shell $only $selection"
if [ -n "$wait_file" ]; then
  tries=0
  while [ ! -e "$wait_file" ]; do
    tries=$((tries + 1))
    [ "$tries" -le 30 ] || exit 99
    sleep 1
  done
fi
exit "${code:-0}"
MOCK
chmod +x "$MOCK_BIN/docker"

fail() {
  echo "FAIL: $*" >&2
  for out in "$FIXTURE"/*.out; do
    [ ! -f "$out" ] || { echo "--- $(basename "$out")" >&2; cat "$out" >&2; }
  done
  exit 1
}

# Overlap: run A has a failing py+node container, a failing busybox
# container and a dash container that waits for run B to finish. With shared
# .rc files, B would overwrite A's exit codes and A would report all ok.
LOGS="$FIXTURE/logs"
KILL_LOG="$FIXTURE/kill.log"
LAYOUT="$FIXTURE/layout.log"
: > "$KILL_LOG"
(
  a_rc=0
  PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$LOGS" STUB_KILL_LOG="$KILL_LOG" STUB_TAG=A \
    STUB_JOBS="dash-1=0@$FIXTURE/b.done busybox-2=1 py-node-1=1" \
    sh "$TARGET" --shell all > "$FIXTURE/a.out" 2>&1 || a_rc=$?
  echo "$a_rc" > "$FIXTURE/a.rc"
) &
a_pid=$!
tries=0
while ! grep -Fq '[dash-1] stub A' "$FIXTURE/a.out" 2>/dev/null ||
  ! grep -Fq '[py+node-1] stub A' "$FIXTURE/a.out" 2>/dev/null; do
  tries=$((tries + 1))
  [ "$tries" -le 30 ] || fail "run A did not start its containers"
  sleep 1
done
b_rc=0
PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$LOGS" STUB_KILL_LOG="$KILL_LOG" STUB_TAG=B STUB_LAYOUT_LOG="$LAYOUT" \
  sh "$TARGET" --shell all > "$FIXTURE/b.out" 2>&1 || b_rc=$?
: > "$FIXTURE/b.done"
wait "$a_pid"

[ "$(cat "$FIXTURE/a.rc")" = 1 ] || fail "run A must exit 1"
[ "$b_rc" = 0 ] || fail "run B must exit 0"
[ "$(tail -n 1 "$FIXTURE/a.out")" = 'run-tests: dash=ok busybox=FAILED py+node=FAILED' ] || fail "run A summary"
grep -Fqx 'run-tests: dash-1=ok dash-2=ok dash-3=ok dash-4=ok dash-5=ok dash-6=ok busybox-1=ok busybox-2=FAILED busybox-3=ok busybox-4=ok busybox-5=ok busybox-6=ok py+node-1=FAILED py+node-2=ok' \
  "$FIXTURE/a.out" || fail "run A per-container result"
[ "$(tail -n 1 "$FIXTURE/b.out")" = 'run-tests: dash=ok busybox=ok py+node=ok' ] || fail "run B summary"
grep -Fq '[py+node-1] stub A py-node-1 dash pytest all' "$FIXTURE/a.out" || fail "run A prefixed output"
grep -Fq '[busybox-6] stub B busybox-6 busybox shell --skip-suites=' "$FIXTURE/b.out" || fail "run B prefixed output"

# The layout: at most 14 containers; per shell, containers with --suites and
# one with --skip-suites of exactly those, so that every tests/test-*.sh runs
# once per shell; pytest + node once.
[ "$(wc -l < "$LAYOUT" | tr -d ' ')" -le 14 ] || fail "more than 14 containers"
[ "$(grep -c ' pytest all$' "$LAYOUT")" = 1 ] || fail "pytest must run once"
[ "$(grep -c ' node all$' "$LAYOUT")" = 1 ] || fail "node must run once"
for layout_shell in dash busybox; do
  named="$(awk -v shell="$layout_shell" '$2 == shell && sub(/^--suites=/, "", $4) { print $4 }' "$LAYOUT" |
    tr ',' '\n' | sort)"
  skipped="$(awk -v shell="$layout_shell" '$2 == shell && sub(/^--skip-suites=/, "", $4) { print $4 }' "$LAYOUT" |
    tr ',' '\n' | sort)"
  [ "$(awk -v shell="$layout_shell" '$2 == shell && $3 == "shell"' "$LAYOUT" | wc -l | tr -d ' ')" -ge 2 ] ||
    fail "$layout_shell: the shell suites must be split"
  [ "$(awk -v shell="$layout_shell" '$2 == shell && $4 ~ /^--skip-suites=/' "$LAYOUT" | wc -l | tr -d ' ')" = 1 ] ||
    fail "$layout_shell: one container must take the remaining suites"
  [ -n "$named" ] && [ "$named" = "$skipped" ] || fail "$layout_shell: the remaining suites must skip exactly the named ones"
  [ -z "$(printf '%s\n' "$named" | uniq -d)" ] || fail "$layout_shell: a suite is named twice"
  for named_suite in $named; do
    [ -f "$SCRIPT_DIR/tests/$named_suite" ] || fail "$layout_shell: no such suite $named_suite"
  done
done
run_a="$(sed -n 's|^run-tests: full logs in \(.*\)/<name>\.log$|\1|p' "$FIXTURE/a.out")"
run_b="$(sed -n 's|^run-tests: full logs in \(.*\)/<name>\.log$|\1|p' "$FIXTURE/b.out")"
[ -n "$run_a" ] && [ -n "$run_b" ] && [ "$run_a" != "$run_b" ] || fail "runs must log into different directories"
grep -Fq 'stub A' "$run_a/py+node-1.log" && ! grep -Fq 'stub B' "$run_a/py+node-1.log" || fail "run A log"
grep -Fq 'stub B' "$run_b/py+node-1.log" && ! grep -Fq 'stub A' "$run_b/py+node-1.log" || fail "run B log"
[ "$(cat "$run_a/py+node-1.rc")" = 1 ] && [ "$(cat "$run_b/py+node-1.rc")" = 0 ] || fail "per-run exit codes"

# A node-only failure must fail the combined py+node summary too.
ui_rc=0
PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$FIXTURE/logs-ui" STUB_KILL_LOG="$KILL_LOG" STUB_TAG=UI \
  STUB_JOBS="py-node-2=1" sh "$TARGET" --shell all > "$FIXTURE/ui.out" 2>&1 || ui_rc=$?
[ "$ui_rc" = 1 ] || fail "node failure must propagate"
[ "$(tail -n 1 "$FIXTURE/ui.out")" = 'run-tests: dash=ok busybox=ok py+node=FAILED' ] || fail "node-only failure summary"
[ -d "$LOGS/latest" ] || fail "latest must point to a run directory"
[ ! -s "$KILL_LOG" ] || fail "no container may be killed in a normal run"

# Old run directories are pruned to the newest ten (the run itself included).
PRUNE="$FIXTURE/prune"
mkdir -p "$PRUNE"
n=0
while [ "$n" -lt 12 ]; do
  mkdir "$PRUNE/run-20200101T0000$(printf '%02d' "$n")Z-1"
  n=$((n + 1))
done
PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$PRUNE" STUB_KILL_LOG="$KILL_LOG" STUB_TAG=C \
  sh "$TARGET" --shell all --only shell > "$FIXTURE/c.out" 2>&1 || fail "run C must exit 0"
[ "$(tail -n 1 "$FIXTURE/c.out")" = 'run-tests: dash=ok busybox=ok' ] || fail "run C summary (--only shell: no py+node)"
! grep -Fq '[py+node-' "$FIXTURE/c.out" || fail "run C must not start py+node"
[ "$(find "$PRUNE" -maxdepth 1 -name 'run-*' | wc -l | tr -d ' ')" = 10 ] || fail "ten run directories must remain"
[ ! -d "$PRUNE/run-20200101T000000Z-1" ] && [ ! -d "$PRUNE/run-20200101T000002Z-1" ] || fail "oldest runs must go"
[ -d "$PRUNE/run-20200101T000003Z-1" ] || fail "newer runs must stay"

# --suites with --shell all: one container per shell, both with the list.
LAYOUT_E="$FIXTURE/layout-e.log"
PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$FIXTURE/logs-e" STUB_KILL_LOG="$KILL_LOG" STUB_TAG=E STUB_LAYOUT_LOG="$LAYOUT_E" \
  sh "$TARGET" --shell all --only shell --suites test-jsonc.sh > "$FIXTURE/e.out" 2>&1 || fail "run E must exit 0"
[ "$(tail -n 1 "$FIXTURE/e.out")" = 'run-tests: dash=ok busybox=ok' ] || fail "run E summary"
[ "$(grep -c '' "$LAYOUT_E")" = 2 ] &&
  grep -Fqx 'dash dash shell --suites=test-jsonc.sh' "$LAYOUT_E" &&
  grep -Fqx 'busybox busybox shell --suites=test-jsonc.sh' "$LAYOUT_E" || fail "run E layout"
e_rc=0
PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$FIXTURE/logs-e" STUB_KILL_LOG="$KILL_LOG" \
  sh "$TARGET" --shell all --suites test-jsonc.sh > "$FIXTURE/e2.out" 2>&1 || e_rc=$?
[ "$e_rc" = 2 ] || fail "--suites without --only shell must exit 2"

# Serial compatibility checks need both shells, but Python and browser suites
# are independent of the selected POSIX shell and must run only once.
LAYOUT_SERIAL="$FIXTURE/layout-serial.log"
PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$FIXTURE/logs-serial" STUB_KILL_LOG="$KILL_LOG" STUB_LAYOUT_LOG="$LAYOUT_SERIAL" \
  sh "$TARGET" --shell all --serial > "$FIXTURE/serial.out" 2>&1 || fail "serial run must exit 0"
[ "$(wc -l < "$LAYOUT_SERIAL" | tr -d ' ')" = 3 ] || fail "serial run must use three containers"
grep -Fqx 'dash dash shell all' "$LAYOUT_SERIAL" &&
  grep -Fqx 'busybox busybox shell all' "$LAYOUT_SERIAL" &&
  grep -Fqx 'py-node dash pytest,node all' "$LAYOUT_SERIAL" || fail "serial run must check Python and Node once"
serial_rc=0
PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$FIXTURE/logs-serial" STUB_KILL_LOG="$KILL_LOG" STUB_JOBS="py-node=1" \
  sh "$TARGET" --shell all --serial > "$FIXTURE/serial-failed.out" 2>&1 || serial_rc=$?
[ "$serial_rc" = 1 ] || fail "serial Python/Node failure must propagate"
[ "$(tail -n 1 "$FIXTURE/serial-failed.out")" = 'run-tests: dash=ok busybox=ok py+node=FAILED' ] || fail "serial failure summary"

# SIGTERM: the containers are stopped by name and the exit code is 130.
HOLD="$FIXTURE/hold"
(
  d_rc=0
  PATH="$MOCK_BIN:$PATH" KDN_TEST_LOG_DIR="$FIXTURE/logs-term" STUB_KILL_LOG="$KILL_LOG" STUB_TAG=D \
    STUB_JOBS="dash-1=0@$HOLD dash-2=0@$HOLD dash-3=0@$HOLD dash-4=0@$HOLD dash-5=0@$HOLD dash-6=0@$HOLD busybox-1=0@$HOLD busybox-2=0@$HOLD busybox-3=0@$HOLD busybox-4=0@$HOLD busybox-5=0@$HOLD busybox-6=0@$HOLD py-node-1=0@$HOLD py-node-2=0@$HOLD" \
    sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$FIXTURE/d.pid" sh "$TARGET" --shell all > "$FIXTURE/d.out" 2>&1 || d_rc=$?
  echo "$d_rc" > "$FIXTURE/d.rc"
) &
d_wait=$!
tries=0
while [ "$(grep -c '^\[[a-z+0-9-]*\] stub D ' "$FIXTURE/d.out" 2>/dev/null)" != 14 ]; do
  tries=$((tries + 1))
  [ "$tries" -le 30 ] || fail "run D did not start its containers"
  sleep 1
done
d_pid="$(cat "$FIXTURE/d.pid")"
kill -TERM "$d_pid"
: > "$HOLD"
wait "$d_wait"
[ "$(cat "$FIXTURE/d.rc")" = 130 ] || fail "terminated run must exit 130"
for name in blobs dash-1 dash-2 dash-3 dash-4 dash-5 dash-6 busybox-1 busybox-2 busybox-3 busybox-4 busybox-5 busybox-6 py-node-1 py-node-2; do
  grep -Fqx "kdn-tests-$d_pid-$name" "$KILL_LOG" || fail "container $name must be killed on SIGTERM"
done

echo "run-tests-tests-ok"
