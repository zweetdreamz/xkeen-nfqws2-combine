#!/bin/sh
set -eu

# Unit test for install_temporary_firewall() of router-candidate-runner.sh:
# the nfqws2-keenetic 1.3.2 firewall_iptables returns 1 when a rule fails, and
# Keenetic can fail one while it rebuilds its firewall. The runner retries like
# the package's netfilter hook (5 x 1 s) and only then gives up. The function
# is extracted from the runner and run on its own; the init, the firewall and
# the pauses are stubs, and no candidate search runs.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/tools/windows/router-candidate-runner.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-runner-firewall.XXXXXX")"
trap 'rm -rf "$FIXTURE"' 0 HUP INT TERM

awk '
  /^install_temporary_firewall\(\) \{$/ { copying=1 }
  copying { print }
  copying && /^}$/ { exit }
' "$TARGET" > "$FIXTURE/install_temporary_firewall.sh"
[ -s "$FIXTURE/install_temporary_firewall.sh" ] || {
  echo "ERROR: install_temporary_firewall() is missing in $TARGET" >&2
  exit 1
}
# shellcheck source=/dev/null
. "$FIXTURE/install_temporary_firewall.sh"

# The function exits the runner on the last failure, so every case runs in a
# subshell; the stubs keep their state in files. The marker after the call
# shows whether the caller went on: exit 1 must end the runner, return 1
# would let it continue with no firewall.
calls_file="$FIXTURE/calls"
events_file="$FIXTURE/events"
sleeps_file="$FIXTURE/sleeps"
reached_file="$FIXTURE/reached"
firewall_failures=0

firewall_iptables() {
  firewall_calls=$(($(cat "$calls_file") + 1))
  echo "$firewall_calls" > "$calls_file"
  [ "$firewall_calls" -gt "$firewall_failures" ]
}

emit() {
  printf '%s\n' "$1" >> "$events_file"
}

sleep() {
  printf '%s\n' "$1" >> "$sleeps_file"
}

fail_case() {
  echo "ERROR: $*" >&2
  exit 1
}

# run_case FAILURES: the stub fails FAILURES times, then succeeds.
run_case() {
  firewall_failures="$1"
  echo 0 > "$calls_file"
  : > "$events_file"
  : > "$sleeps_file"
  : > "$reached_file"
  case_rc=0
  (install_temporary_firewall; echo reached >> "$reached_file") || case_rc=$?
  case_calls="$(cat "$calls_file")"
  case_pauses="$(wc -l < "$sleeps_file" | tr -d ' ')"
}

KD_FIREWALL_RETRY_DELAY=0
export KD_FIREWALL_RETRY_DELAY

run_case 0
[ "$case_rc" -eq 0 ] || fail_case "no failures: rc=$case_rc"
[ -s "$reached_file" ] || fail_case "no failures: the caller did not continue"
[ "$case_calls" -eq 1 ] || fail_case "no failures: $case_calls calls, expected 1"
[ "$case_pauses" -eq 0 ] || fail_case "no failures: $case_pauses pauses, expected 0"
[ ! -s "$events_file" ] || fail_case "no failures: unexpected events: $(cat "$events_file")"

run_case 2
[ "$case_rc" -eq 0 ] || fail_case "2 failures: rc=$case_rc, expected 0"
[ -s "$reached_file" ] || fail_case "2 failures: the caller did not continue"
[ "$case_calls" -eq 3 ] || fail_case "2 failures: $case_calls calls, expected 3"
[ "$case_pauses" -eq 2 ] || fail_case "2 failures: $case_pauses pauses, expected 2"
if grep -Fq 'FATAL' "$events_file"; then
  fail_case "2 failures: FATAL emitted: $(cat "$events_file")"
fi

# The fifth attempt still counts.
run_case 4
[ "$case_rc" -eq 0 ] || fail_case "4 failures: rc=$case_rc, expected 0"
[ -s "$reached_file" ] || fail_case "4 failures: the caller did not continue"
[ "$case_calls" -eq 5 ] || fail_case "4 failures: $case_calls calls, expected 5"
[ ! -s "$events_file" ] || fail_case "4 failures: unexpected events: $(cat "$events_file")"

# Five attempts at most, no pause after the last one.
for failures in 5 9; do
  run_case "$failures"
  [ "$case_rc" -eq 1 ] || fail_case "$failures failures: rc=$case_rc, expected 1"
  [ ! -s "$reached_file" ] || fail_case "$failures failures: the caller went on after the last failure"
  [ "$case_calls" -eq 5 ] || fail_case "$failures failures: $case_calls calls, expected 5"
  [ "$case_pauses" -eq 4 ] || fail_case "$failures failures: $case_pauses pauses, expected 4"
  [ "$(cat "$events_file")" = "FATAL|cannot-install-temporary-firewall" ] ||
    fail_case "$failures failures: events: $(cat "$events_file")"
done

# The pause between attempts is KD_FIREWALL_RETRY_DELAY, one second by default.
run_case 2
[ "$(sort -u "$sleeps_file")" = "0" ] || fail_case "the pause ignored KD_FIREWALL_RETRY_DELAY=0"
unset KD_FIREWALL_RETRY_DELAY
run_case 2
[ "$(sort -u "$sleeps_file")" = "1" ] || fail_case "the default pause is not 1 second: $(cat "$sleeps_file")"

echo "runner-firewall-tests-ok"
