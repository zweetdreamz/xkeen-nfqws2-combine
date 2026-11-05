#!/bin/sh
set -eu

# Unit test for restore_service() of router-candidate-runner.sh: nfqws2-keenetic
# 1.3.2 "start" waits 5 s for the pidfile and, when it is late, returns 1
# before firewall_iptables, so the daemon can run with no NFQUEUE rules. The
# runner must not report RESTORED|running until the rules are present. The
# function is extracted from the runner and run on its own; the init, the
# firewall and the waits are stubs, and no candidate search runs.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/tools/windows/router-candidate-runner.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-runner-restore.XXXXXX")"
trap 'rm -rf "$FIXTURE"' 0 HUP INT TERM

awk '
  /^restore_service\(\) \{$/ { copying=1 }
  copying { print }
  copying && /^}$/ { exit }
' "$TARGET" > "$FIXTURE/restore_service.sh"
[ -s "$FIXTURE/restore_service.sh" ] || {
  echo "ERROR: restore_service() is missing in $TARGET" >&2
  exit 1
}
# shellcheck source=/dev/null
. "$FIXTURE/restore_service.sh"

# The stubs keep their state in files: every case runs in a subshell, like the
# runner's trap, and the checks read the files afterwards.
events_file="$FIXTURE/events"
calls_file="$FIXTURE/calls"
rules_file="$FIXTURE/rules"
reinstall_works=1
service_runs=1

# The init: "start" returns 1, as the 1.3.2 init does with a late pidfile.
NFQWS_INIT="$FIXTURE/S51nfqws2"
cat > "$NFQWS_INIT" <<EOF
#!/bin/sh
echo "init \$1" >> "$calls_file"
exit 1
EOF
chmod 755 "$NFQWS_INIT"
# shellcheck disable=SC2034 # read by the extracted restore_service
NFQWS_PIDFILE="$FIXTURE/nfqws2.pid"

emit() {
  printf '%s\n' "$1" >> "$events_file"
}

stop_candidate() {
  echo stop_candidate >> "$calls_file"
}

firewall_stop() {
  echo firewall_stop >> "$calls_file"
}

cleanup_tmp() {
  echo cleanup_tmp >> "$calls_file"
}

release_project_lock() {
  echo release_project_lock >> "$calls_file"
}

wait_service_running() {
  [ "$service_runs" -eq 1 ]
}

# The rules exist when the file says so; firewall_iptables creates them.
firewall_present() {
  [ -s "$rules_file" ]
}

firewall_iptables() {
  echo firewall_iptables >> "$calls_file"
  [ "$reinstall_works" -eq 0 ] || echo rules > "$rules_file"
}

firewall_ip6tables() {
  echo firewall_ip6tables >> "$calls_file"
}

fail_case() {
  echo "ERROR: $*" >&2
  exit 1
}

# run_case RULES_PRESENT REINSTALL_WORKS SERVICE_RUNS WAS_RUNNING
run_case() {
  : > "$events_file"
  : > "$calls_file"
  : > "$rules_file"
  [ "$1" -eq 0 ] || echo rules > "$rules_file"
  reinstall_works="$2"
  service_runs="$3"
  # shellcheck disable=SC2034 # read by the extracted restore_service
  WAS_RUNNING="$4" RESTORED=0 RUNTIME_PREPARED=1
  # The runner has no "set -e": its traps run restore_service in that mode.
  (set +e; restore_service) || fail_case "restore_service returned $?"
  case_events="$(cat "$events_file")"
  case_calls="$(tr '\n' ' ' < "$calls_file")"
}

# The rules are there: nothing is installed again.
run_case 1 1 1 1
[ "$case_events" = "RESTORED|running" ] || fail_case "rules present: events: $case_events"
case "$case_calls" in
  *firewall_iptables*) fail_case "rules present: the rules were installed again: $case_calls" ;;
esac
case "$case_calls" in
  "stop_candidate firewall_stop init start cleanup_tmp release_project_lock ") ;;
  *) fail_case "rules present: calls: $case_calls" ;;
esac

# The init returned before the rules: the runner installs them and reports
# the restore only after they are present.
run_case 0 1 1 1
[ "$case_events" = "RESTORED|running" ] || fail_case "rules missing, reinstalled: events: $case_events"
case "$case_calls" in
  "stop_candidate firewall_stop init start firewall_iptables firewall_ip6tables cleanup_tmp release_project_lock ") ;;
  *) fail_case "rules missing, reinstalled: calls: $case_calls" ;;
esac

# The rules cannot be installed: an error, never RESTORED|running.
run_case 0 0 1 1
[ "$case_events" = "RESTORE_ERROR|nfqws2-firewall-missing" ] || fail_case "rules missing, not reinstalled: events: $case_events"
case "$case_calls" in
  *"firewall_iptables firewall_ip6tables cleanup_tmp release_project_lock ") ;;
  *) fail_case "rules missing, not reinstalled: calls: $case_calls" ;;
esac

# The daemon never appears: the start error, and no rules without a daemon.
run_case 0 1 0 1
[ "$case_events" = "RESTORE_ERROR|nfqws2-start-failed" ] || fail_case "no daemon: events: $case_events"
case "$case_calls" in
  *firewall_iptables*) fail_case "no daemon: rules were installed without a daemon: $case_calls" ;;
esac

# The service was stopped before the run: it stays stopped, nothing to check.
run_case 0 1 0 0
[ "$case_events" = "RESTORED|stopped" ] || fail_case "was stopped: events: $case_events"
case "$case_calls" in
  *"init start"*|*firewall_iptables*) fail_case "was stopped: the service was started: $case_calls" ;;
esac

echo "runner-restore-tests-ok"
