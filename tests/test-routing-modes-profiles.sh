#!/bin/sh
set -eu

# Routing-mode integration test, part 3 of 4 (fixture and helpers:
# tests/routing-modes-lib.sh): imported tuner profiles (XKeen untouched,
# rollback, invalid candidates, Voice and Discord TCP imports), the broken
# states --check-config finds, custom profile ports, identical applies, applies
# that fail and roll back (checks, dry-run, restart verification, init start
# failure, the Xray test gate) and the nfqws2 runtime detection.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=tests/routing-modes-lib.sh
. "$SCRIPT_DIR/tests/routing-modes-lib.sh"

# Start state, as part 2 ends: integrated, Discord zapret, YouTube vless,
# Telegram unmanaged, a restrictive XKeen port list, the upgraded nfqws2
# package files.
routing_modes_install
routing_modes_upgraded_package
printf '%s\n' '# restricted fixture' 443 > "$ROOT/opt/etc/xkeen/port_proxying.lst"
apply_mode zapret vless

# Focused tuner-profile operations must never stop or restart XKeen.
apply_mode zapret zapret
: > "$ROOT/xkeen-init.log"
: > "$ROOT/nfqws-init.log"
write_youtube_stage

run_tool --apply-import-profile "$profile_stage" --yes-router >/dev/null
[ ! -s "$ROOT/xkeen-init.log" ]
grep -Fqx 'nfqws-init:restart' "$ROOT/nfqws-init.log"
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=7' "$nfqws_file"
[ -f "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json" ]
[ "$(jq -r '.report.search_seed' "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json")" = "123456" ]
[ -s "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr" ]
[ "$(find "$ROOT/opt/etc/nfqws2/profile-versions/youtube" -type f -name '*-applied-*.json' | wc -l | tr -d '[:space:]')" = "1" ]

: > "$ROOT/xkeen-init.log"
: > "$ROOT/nfqws-init.log"
run_tool --clear-imported-profile youtube --yes-router >/dev/null
[ ! -s "$ROOT/xkeen-init.log" ]
grep -Fqx 'nfqws-init:restart' "$ROOT/nfqws-init.log"
[ ! -e "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json" ]
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=11' "$nfqws_file"
[ "$(find "$ROOT/opt/etc/nfqws2/profile-versions/youtube" -type f | wc -l | tr -d '[:space:]')" = "2" ]

# A package upgrade after the import snapshot: its Lua scripts stay.
printf '%s\n' 'NFQWS2_COMPAT_VER_REQUIRED=7' > "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
: > "$ROOT/xkeen-init.log"
: > "$ROOT/nfqws-init.log"
run_tool --rollback-import --yes-router >/dev/null
grep -Fqx 'NFQWS2_COMPAT_VER_REQUIRED=7' "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
[ ! -s "$ROOT/xkeen-init.log" ]
grep -Fq 'nfqws-init:stop' "$ROOT/nfqws-init.log"
grep -Fq 'nfqws-init:start' "$ROOT/nfqws-init.log"
[ -f "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json" ]
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=7' "$nfqws_file"
[ "$(find "$ROOT/opt/etc/nfqws2/profile-versions/youtube" -type f | wc -l | tr -d '[:space:]')" = "1" ]

bad_stage="$ROOT/opt/tmp/youtube-profile-bad.json"
jq '.candidate_id = "000000000000"' "$profile_stage" > "$bad_stage"
before_bad_import="$(sha256sum "$nfqws_file" | awk '{print $1}')"
: > "$ROOT/xkeen-init.log"
if run_tool --apply-import-profile "$bad_stage" --yes-router >/dev/null 2>&1; then
  echo "ERROR: invalid imported candidate unexpectedly passed." >&2
  exit 1
fi
[ ! -s "$ROOT/xkeen-init.log" ]
[ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$before_bad_import" ]

# An imported Voice profile replaces only the Discord UDP profile: QUIC
# (UDP 443) must stay in the NFQUEUE ports for the YouTube/base QUIC profiles.
write_voice_stage
run_tool --apply-import-profile "$voice_stage" --yes-router >/dev/null
[ -f "$ROOT/opt/etc/nfqws2/imported-profiles/discord-voice.json" ]
grep -Fqx 'UDP_PORTS=443,19294:19344,50000:50100' "$nfqws_file"
grep -Fq 'NFQWS_ARGS_UDP="--filter-udp=19294-19344,50000-50100' "$nfqws_file"
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=7' "$nfqws_file"
run_tool --clear-imported-profile discord-voice --yes-router >/dev/null
[ ! -e "$ROOT/opt/etc/nfqws2/imported-profiles/discord-voice.json" ]
grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:50100' "$nfqws_file"
assert_config_checks
# The blocks below start from the built-in profiles.
run_tool --clear-imported-profile youtube --yes-router >/dev/null
assert_mode zapret zapret zapret

# --- D2/A2/B4/E4/E12: a Discord TCP import changes only the Discord TCP
# profile; the package QUIC profile keeps its user.list hostlist.
digest_before="$(profile_digest)"
make_stage discord-tcp "$ROOT/opt/tmp/dtcp-profile.json" \
  --filter-tcp=443 --filter-l7=tls --hostlist=/opt/etc/nfqws2/lists/user.list \
  --payload=tls_client_hello --lua-desync=fake:blob=tls_clienthello:repeats=6 \
  --lua-desync=multisplit:pos=1,midsld
run_tool --apply-import-profile "$ROOT/opt/tmp/dtcp-profile.json" --yes-router >/dev/null
assert_profiles_same_except "$digest_before" "$(profile_digest)" discord-tcp
grep -Fqx 'NFQWS_EXTRA_ARGS="$MODE_LIST"' "$nfqws_file"
# Only TCP 443 has a profile now (no queued port without a profile).
grep -Fqx 'TCP_PORTS=443' "$nfqws_file"
assert_config_checks
run_tool --check-config | grep -Fqx 'CHECK|ok|unhandled-ports|every queued port has a profile'
run_tool --clear-imported-profile discord-tcp --yes-router >/dev/null
[ "$(profile_digest)" = "$digest_before" ]
grep -Fqx 'TCP_PORTS=80,443,2053,2083,2087,2096,8443' "$nfqws_file"

# --- --check-config finds the broken states it exists for. Each case edits
# the live config and puts it back.
cp "$nfqws_file" "$FIXTURE/conf.saved"
cp "$ROOT/opt/etc/nfqws2/lists/user.list" "$FIXTURE/user.list.saved"
expect_check() {
  expect_rc="$1"
  expect_line="$2"
  check_rc=0
  check_text="$(run_tool --check-config)" || check_rc=$?
  [ "$check_rc" = "$expect_rc" ] || {
    printf '%s\n' "$check_text" >&2
    echo "ERROR: --check-config exit $check_rc, expected $expect_rc" >&2
    exit 1
  }
  printf '%s\n' "$check_text" | grep -Eq "$expect_line" || {
    printf '%s\n' "$check_text" >&2
    echo "ERROR: --check-config lacks: $expect_line" >&2
    exit 1
  }
  cp "$FIXTURE/conf.saved" "$nfqws_file"
  cp "$FIXTURE/user.list.saved" "$ROOT/opt/etc/nfqws2/lists/user.list"
}
# The 3.1.0 incident: the YouTube QUIC profile on UDP 443, 443 not queued.
sed -i 's/^UDP_PORTS=.*/UDP_PORTS=19294:19344,50000:50100/' "$nfqws_file"
expect_check 1 '^CHECK\|error\|port-coverage\|.* UDP 443 outside UDP_PORTS'
# A1: the empty user.list of the earlier releases.
: > "$ROOT/opt/etc/nfqws2/lists/user.list"
expect_check 1 '^CHECK\|error\|empty-hostlist\|/opt/etc/nfqws2/lists/user.list has no entries'
# D2: NFQWS_EXTRA_ARGS="" leaves the package QUIC profile without a list.
sed -i 's/^NFQWS_EXTRA_ARGS=.*/NFQWS_EXTRA_ARGS=""/' "$nfqws_file"
expect_check 1 '^CHECK\|error\|listless-profile\|#[0-9]+ udp=443 l7=quic'
# The legacy UDP fake of 3.1.x without blob=.
sed -i 's/^NFQWS_EXTRA_ARGS=.*/&\nNFQWS_ARGS_UDP="--filter-udp=3478 --filter-l7=stun,discord --lua-desync=fake:repeats=6:strategy=1"/' "$nfqws_file"
expect_check 1 '^CHECK\|error\|legacy-blob\|.*fake:repeats=6:strategy=1'
# A user's own listless custom profile is reported, not refused; its ports
# are taken into the queue by the next apply (A3).
sed -i 's/^NFQWS_ARGS_CUSTOM=""$/NFQWS_ARGS_CUSTOM="--filter-udp=1400 --lua-desync=fake:blob=quic_initial"/' "$nfqws_file"
expect_check 0 '^CHECK\|warn\|listless-profile\|#1 udp=1400 \(user profile\)'
mv "$nfqws_file" "$FIXTURE/conf.moved"
expect_check 2 '^CHECK\|error\|read\|'
[ -f "$nfqws_file" ]

# --- A3: the ports of the user's own custom profiles stay queued.
sed -i 's/^NFQWS_ARGS_CUSTOM=""$/NFQWS_ARGS_CUSTOM="--filter-udp=1400 --filter-l7=mtproto --hostlist=\/opt\/etc\/nfqws2\/lists\/user.list --lua-desync=fake:blob=quic_initial --new --filter-tcp=1984 --hostlist=\/opt\/etc\/nfqws2\/lists\/user.list --lua-desync=multisplit"/' "$nfqws_file"
run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret >/dev/null
assert_config_checks
grep -Fqx 'TCP_PORTS=80,443,2053,2083,2087,2096,8443,1984' "$nfqws_file"
grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:50100,1400' "$nfqws_file"
run_tool --print-nfqws-profiles | grep -q '^PROFILE|2|user|--filter-tcp=1984'
cp "$FIXTURE/conf.saved" "$nfqws_file"
apply_mode zapret zapret

# --- A8/C1: identical applies give identical files (restrictive port list).
printf '%s\n' '# restricted fixture' 443 > "$ROOT/opt/etc/xkeen/port_proxying.lst"
apply_mode zapret zapret
cp "$nfqws_file" "$FIXTURE/idem.conf"
cp "$ROOT/opt/etc/xkeen/port_proxying.lst" "$FIXTURE/idem.ports"
cp "$routing_file" "$FIXTURE/idem.routing"
apply_mode zapret zapret
cmp "$nfqws_file" "$FIXTURE/idem.conf"
cmp "$ROOT/opt/etc/xkeen/port_proxying.lst" "$FIXTURE/idem.ports"
cmp "$routing_file" "$FIXTURE/idem.routing"
run_tool --apply-import-profile "$voice_stage" --yes-router >/dev/null
run_tool --clear-imported-profile discord-voice --yes-router >/dev/null
cmp "$nfqws_file" "$FIXTURE/idem.conf"
printf '%s\n' '# unrestricted fixture' > "$ROOT/opt/etc/xkeen/port_proxying.lst"

# --- The apply fails and rolls back when the checks, the dry-run or the
# restart verification fail; --rollback-latest still undoes the last
# successful apply afterwards (C4).
apply_mode zapret zapret
latest_before="$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")"
conf_before="$(sha256sum "$nfqws_file" | awk '{print $1}')"
expect_failed_apply() {
  # Voice off changes UDP_PORTS, so stale firewall rules show.
  if run_tool --apply --yes-router --core xray --discord-tcp-route zapret --discord-voice-route vless \
       --youtube-route vless > "$FIXTURE/failed.log" 2>&1; then
    echo "ERROR: apply passed although $1" >&2
    exit 1
  fi
  grep -Fq "$2" "$FIXTURE/failed.log" || {
    cat "$FIXTURE/failed.log" >&2
    echo "ERROR: missing: $2" >&2
    exit 1
  }
  grep -Fq 'Starting automatic rollback' "$FIXTURE/failed.log"
  [ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$conf_before" ]
  [ "$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")" = "$latest_before" ]
  [ "${3:-}" = edited ] || assert_mode zapret zapret zapret
}
# A stock QUIC profile edited onto a port the engine does not queue.
sed -i 's/^NFQWS_ARGS_QUIC="--filter-udp=443 /NFQWS_ARGS_QUIC="--filter-udp=443,4433 /' "$nfqws_file"
conf_before="$(sha256sum "$nfqws_file" | awk '{print $1}')"
expect_failed_apply "a profile port is not queued" 'filters UDP 4433 outside UDP_PORTS' edited
# The saved on-disk config was intentionally invalid. Strict restore refuses
# to start it rather than claiming a healthy service; repair the fixture before
# the following independent restart-fault cases.
grep -Fqx 'RESULT|partial' "$FIXTURE/failed.log"
cp "$FIXTURE/conf.saved" "$nfqws_file"
KD_TEST_ROOT="$ROOT" "$ROOT/opt/etc/init.d/S51nfqws2" restart >/dev/null
conf_before="$(sha256sum "$nfqws_file" | awk '{print $1}')"
# (The fixture binary's knob; a real KD_TEST_NFQWS2_BIN accepts the config.)
if [ -z "${KD_TEST_NFQWS2_BIN:-}" ]; then
  touch "$ROOT/nfqws2.fail-dry-run"
  expect_failed_apply "nfqws2 --dry-run failed" 'nfqws2 --dry-run rejects the generated arguments'
  rm -f "$ROOT/nfqws2.fail-dry-run"
fi
# nfqws2-ui "stale PID": the init leaves the old daemon running.
touch "$ROOT/nfqws-init.keep-old"
expect_failed_apply "the old nfqws2 still runs" 'still runs as the old process'
rm -f "$ROOT/nfqws-init.keep-old"
# The firewall still queues the ports of the previous config (A6).
touch "$ROOT/nfqws-init.stale-rules"
expect_failed_apply "the NFQUEUE rules are stale" 'udp NFQUEUE rule for fixture-wan queues'
rm -f "$ROOT/nfqws-init.stale-rules"
# A daemon that runs without the profiles of the config.
touch "$ROOT/nfqws-init.wrong-args"
expect_failed_apply "nfqws2 runs other arguments" 'was not started with the arguments of the current nfqws2.conf'
rm -f "$ROOT/nfqws-init.wrong-args"

# --- nfqws2 1.3.2 start failure: the init's restart returns 1 when the daemon
# or its pidfile fails. The engine names that exit code itself, the apply
# rolls back and the service runs again afterwards.
cp "$nfqws_file" "$FIXTURE/start-fail.conf"
echo 1 > "$ROOT/nfqws-start-fail"
start_fail_rc=0
run_service_tool discord-voice direct --yes-router --core xray > "$FIXTURE/start-fail.log" 2>&1 || start_fail_rc=$?
if [ "$start_fail_rc" -eq 0 ]; then
  cat "$FIXTURE/start-fail.log" >&2
  echo "ERROR: a route change passed although the nfqws2 init could not start" >&2
  exit 1
fi
grep -Fq 'ERROR: nfqws2 init restart failed (exit 1)' "$FIXTURE/start-fail.log" || {
  cat "$FIXTURE/start-fail.log" >&2
  echo "ERROR: missing: the engine's message about the failed init restart" >&2
  exit 1
}
grep -Fq 'Starting automatic rollback' "$FIXTURE/start-fail.log"
cmp -s "$nfqws_file" "$FIXTURE/start-fail.conf"
[ "$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")" = "$latest_before" ]
assert_mode zapret zapret zapret
# The fixture failed exactly once; the rollback restarted the service.
[ "$(cat "$ROOT/nfqws-start-fail")" = 0 ]
KD_TEST_ROOT="$ROOT" "$ROOT/opt/etc/init.d/S51nfqws2" status | grep -Fqx 'Service NFQWS2 is running'
run_tool --status | grep -Fqx 'nfqws_runtime=running'
# Negative control: with the counter spent, the same route change succeeds
# and the engine reports nothing about a failed restart.
run_service_tool discord-voice direct --yes-router --core xray > "$FIXTURE/start-ok.log" 2>&1
if grep -Fq 'init restart failed' "$FIXTURE/start-ok.log"; then
  cat "$FIXTURE/start-ok.log" >&2
  echo "ERROR: the engine reported a failed init restart although the init started" >&2
  exit 1
fi
assert_mode zapret direct zapret
rm -f "$ROOT/nfqws-start-fail"
run_service_tool discord-voice zapret --yes-router --core xray >/dev/null
assert_mode zapret zapret zapret

# --- xray test gate: "xkeen -xtest" always exits 0 (the XKeen main loop has
# no exit), so the engine runs "xray run -test" itself and a failing test
# stops the apply before XKeen restarts.
expect_xray_gate() {
  # expect_xray_gate LOG: the apply failed on the Xray configuration test.
  grep -Fq 'ERROR: Xray configuration test failed:' "$1" || {
    cat "$1" >&2
    echo "ERROR: missing: the engine's message about the failed Xray test" >&2
    exit 1
  }
  grep -Fq 'Failed to start: fixture-forced' "$1" || {
    cat "$1" >&2
    echo "ERROR: missing: the output of the failed Xray test" >&2
    exit 1
  }
  if grep -Fq 'Restarting XKeen...' "$1"; then
    cat "$1" >&2
    echo "ERROR: XKeen restarted although the Xray configuration test failed" >&2
    exit 1
  fi
}
cp "$routing_file" "$FIXTURE/xray-gate.routing"
cp "$nfqws_file" "$FIXTURE/xray-gate.conf"
# The current configuration fails: the preflight refuses.
touch "$ROOT/xray-test-fail"
xray_gate_rc=0
run_service_tool youtube vpn --yes-router --core xray > "$FIXTURE/xray-gate.log" 2>&1 || xray_gate_rc=$?
if [ "$xray_gate_rc" -eq 0 ]; then
  cat "$FIXTURE/xray-gate.log" >&2
  echo "ERROR: a route change passed although the Xray configuration test fails" >&2
  exit 1
fi
expect_xray_gate "$FIXTURE/xray-gate.log"
grep -Fq "current Xray configuration fails 'xray -test'" "$FIXTURE/xray-gate.log" || {
  cat "$FIXTURE/xray-gate.log" >&2
  echo "ERROR: the preflight did not refuse the failing Xray configuration" >&2
  exit 1
}
cmp -s "$routing_file" "$FIXTURE/xray-gate.routing"
cmp -s "$nfqws_file" "$FIXTURE/xray-gate.conf"
# Negative control: the same change succeeds once the test passes.
rm -f "$ROOT/xray-test-fail"
run_service_tool youtube vpn --yes-router --core xray >/dev/null
assert_mode zapret zapret vless
run_service_tool youtube zapret --yes-router --core xray >/dev/null
assert_mode zapret zapret zapret
# The configuration the engine has written fails: the apply rolls back before
# the restart. The text in the marker file is in the Telegram rules only.
cp "$routing_file" "$FIXTURE/xray-gate.routing"
cp "$nfqws_file" "$FIXTURE/xray-gate.conf"
xray_gate_latest="$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")"
echo kdn-telegram > "$ROOT/xray-test-fail"
xray_gate_rc=0
run_service_tool telegram direct --yes-router --core xray > "$FIXTURE/xray-gate.log" 2>&1 || xray_gate_rc=$?
if [ "$xray_gate_rc" -eq 0 ]; then
  cat "$FIXTURE/xray-gate.log" >&2
  echo "ERROR: a route change passed although the patched Xray configuration fails its test" >&2
  exit 1
fi
expect_xray_gate "$FIXTURE/xray-gate.log"
grep -Fq 'Starting automatic rollback' "$FIXTURE/xray-gate.log"
if grep -Fq "current Xray configuration fails" "$FIXTURE/xray-gate.log"; then
  cat "$FIXTURE/xray-gate.log" >&2
  echo "ERROR: the preflight failed; the test was meant to fail after the patch" >&2
  exit 1
fi
cmp -s "$routing_file" "$FIXTURE/xray-gate.routing"
cmp -s "$nfqws_file" "$FIXTURE/xray-gate.conf"
[ ! -e "$telegram_outbound_file" ]
[ "$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")" = "$xray_gate_latest" ]
assert_mode zapret zapret zapret
rm -f "$ROOT/xray-test-fail"
run_service_tool telegram direct --yes-router --core xray >/dev/null
assert_mode zapret zapret zapret direct
run_service_tool telegram unmanaged --yes-router --core xray >/dev/null
assert_mode zapret zapret zapret
# The binary is looked up on PATH, then in /opt/sbin of the router; without it
# the preflight fails with a message of its own.
mv "$MOCK_BIN/xray" "$FIXTURE/xray.saved"
no_xray_rc=0
run_tool --preflight --core xray > "$FIXTURE/no-xray.log" 2>&1 || no_xray_rc=$?
if [ "$no_xray_rc" -eq 0 ] || ! grep -Fq 'xray binary not found' "$FIXTURE/no-xray.log"; then
  cat "$FIXTURE/no-xray.log" >&2
  echo "ERROR: the preflight passed or kept quiet without an xray binary (exit $no_xray_rc)" >&2
  exit 1
fi
mkdir -p "$ROOT/opt/sbin"
cp "$FIXTURE/xray.saved" "$ROOT/opt/sbin/xray"
run_tool --preflight --core xray >/dev/null
rm -f "$ROOT/opt/sbin/xray"
rmdir "$ROOT/opt/sbin"
mv "$FIXTURE/xray.saved" "$MOCK_BIN/xray"
run_tool --preflight --core xray >/dev/null

# A process with a recycled PID or a test instance is not the service.
apply_mode zapret zapret
kill "$(cat "$ROOT/opt/var/run/nfqws2.pid")" 2>/dev/null || true
python3 -c 'import time; time.sleep(600)' nfqws2 --qnum=301 </dev/null >/dev/null 2>&1 &
test_instance=$!
printf '%s\n' "$test_instance" > "$ROOT/opt/var/run/nfqws2.pid"
run_tool --status | grep -Fqx 'nfqws_runtime=stopped'
kill "$test_instance"
rm -f "$ROOT/opt/var/run/nfqws2.pid"
apply_mode zapret zapret
run_tool --status | grep -Fqx 'nfqws_runtime=running'
cmp -s "$nfqws_file" "$FIXTURE/conf.saved" || cp "$nfqws_file" "$FIXTURE/conf.saved"

# --- An autotune runner that died left its candidate nfqws2 and state file:
# the next operation under the project lock cleans up.
sh -c 'exit 0' &
dead_runner=$!
wait "$dead_runner" || true
python3 -c 'import time; time.sleep(600)' nfqws2 --qnum=301 </dev/null >/dev/null 2>&1 &
orphan_candidate=$!
mkdir -p "$ROOT/opt/tmp/zapret-tuner.$dead_runner"
printf 'runner_pid=%s\ncandidate_pid=%s\nwas_running=1\nprepared=1\n' "$dead_runner" "$orphan_candidate" \
  > "$ROOT/opt/tmp/zapret-tuner.$dead_runner/runtime.state"
apply_mode zapret zapret
[ ! -e "$ROOT/opt/tmp/zapret-tuner.$dead_runner" ]
if process_alive "$orphan_candidate"; then
  echo "ERROR: the orphaned autotune candidate still runs" >&2
  exit 1
fi
run_tool --status | grep -Fqx 'nfqws_runtime=running'

assert_no_xkeen_xtest
echo "routing-modes-profiles-tests-ok"
