#!/bin/sh
set -eu

# Self-test of the fixture init (tests/engine-nfqws2-fixture.sh): like the
# nfqws2-keenetic 1.3.2 init, start returns 1 and installs no firewall rules
# when the daemon does not write its pidfile in time. The engine tests rely on
# that to fail an apply; this test keeps the fixture from drifting.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-nfqws-fixture.XXXXXX")"
ROOT="$FIXTURE/root"
INIT="$ROOT/opt/etc/init.d/S51nfqws2"
# shellcheck source=tests/engine-nfqws2-fixture.sh
. "$SCRIPT_DIR/tests/engine-nfqws2-fixture.sh"

cleanup() {
  if [ -f "$ROOT/opt/var/run/nfqws2.pid" ]; then
    kill "$(sed -n '1p' "$ROOT/opt/var/run/nfqws2.pid")" 2>/dev/null || true
  fi
  rm -rf "$FIXTURE"
}
trap cleanup 0 HUP INT TERM

mkdir -p "$ROOT/opt/etc/init.d" "$ROOT/opt/etc/nfqws2" "$ROOT/opt/usr/bin" "$ROOT/opt/var/run"
engine_write_stock_nfqws2_conf "$ROOT/opt/etc/nfqws2/nfqws2.conf" fixture-wan 0
engine_write_nfqws2_init "$INIT"

run_init() {
  KD_TEST_ROOT="$ROOT" KD_FIXTURE_PIDFILE_WAIT=1 sh "$INIT" "$@"
}

# A daemon that never writes its pidfile.
printf '#!/bin/sh\nexit 0\n' > "$ROOT/opt/usr/bin/nfqws2"
chmod +x "$ROOT/opt/usr/bin/nfqws2"
start_rc=0
run_init start > "$FIXTURE/start.log" 2>&1 || start_rc=$?
[ "$start_rc" -eq 1 ] || {
  cat "$FIXTURE/start.log" >&2
  echo "ERROR: start without a pidfile exited $start_rc, expected 1" >&2
  exit 1
}
grep -Fq 'NFQWS2 daemon did not start, firewall rules not installed' "$FIXTURE/start.log" || {
  cat "$FIXTURE/start.log" >&2
  echo "ERROR: start without a pidfile did not say why" >&2
  exit 1
}
if grep -Fq 'Started NFQWS2 service' "$FIXTURE/start.log"; then
  echo "ERROR: start without a pidfile reported a started service" >&2
  exit 1
fi
if [ -e "$ROOT/iptables-mangle.rules" ] || [ -e "$ROOT/ip6tables-mangle.rules" ]; then
  echo "ERROR: start without a pidfile installed firewall rules" >&2
  exit 1
fi
run_init status | grep -Fqx 'Service NFQWS2 is stopped'

# Negative control: a daemon with a pidfile starts and gets its rules.
engine_write_fake_nfqws2 "$ROOT/opt/usr/bin/nfqws2"
run_init start > "$FIXTURE/start.log" 2>&1 || {
  cat "$FIXTURE/start.log" >&2
  echo "ERROR: start with a pidfile failed" >&2
  exit 1
}
grep -Fq 'Started NFQWS2 service' "$FIXTURE/start.log"
grep -Fq -- '-j NFQUEUE --queue-num 300' "$ROOT/iptables-mangle.rules"
run_init status | grep -Fqx 'Service NFQWS2 is running'

echo "nfqws-fixture-tests-ok"
