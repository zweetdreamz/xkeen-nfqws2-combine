#!/bin/sh
set -eu

# Router-native autotuner integration test. Every router path is redirected to
# a disposable fixture; HTTP, firewall, nfqws2 and PID discovery are mocked.
# The test never invokes XKeen or changes the host network.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/tools/router/zapret_autotune_job.py"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-autotune.XXXXXX")"
ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"
SOURCE_DIR="$FIXTURE/sources"

safe_cleanup() {
  case "$FIXTURE" in
    "${TMPDIR:-/tmp}/keenetic-autotune."*)
      rm -rf "$FIXTURE"
      ;;
  esac
}
trap safe_cleanup 0 HUP INT TERM

mkdir -p \
  "$ROOT/opt/etc/init.d" \
  "$ROOT/opt/etc/nfqws2/blobs" \
  "$ROOT/opt/etc/nfqws2/lists" \
  "$ROOT/opt/etc/nfqws2/lua" \
  "$ROOT/opt/etc/xray/configs" \
  "$ROOT/opt/tmp" \
  "$ROOT/opt/usr/bin" \
  "$ROOT/opt/var/run" \
  "$MOCK_BIN" \
  "$SOURCE_DIR"

cat > "$ROOT/opt/etc/nfqws2/nfqws2.conf" <<'EOF'
# Managed by keenetic-discord-nfqws2.
# Active routes: Discord=zapret, YouTube=zapret.
NFQWS_ARGS_CUSTOM=""
EOF

: > "$ROOT/opt/etc/nfqws2/blobs/tls_clienthello.bin"
: > "$ROOT/opt/etc/nfqws2/blobs/quic_initial.bin"
: > "$ROOT/opt/etc/nfqws2/blobs/discord_udp.bin"
: > "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
: > "$ROOT/opt/etc/nfqws2/lua/zapret-antidpi.lua"

cat > "$ROOT/opt/etc/xray/configs/05_routing.json" <<'EOF'
{"routing":{"rules":[{"outboundTag":"discord-direct"}]}}
EOF

cat > "$ROOT/opt/etc/init.d/S51nfqws2" <<'EOF'
#!/bin/sh
NFQUEUE_NUM=300
TCP_PORTS=443
UDP_PORTS=443
NFQWS_BASE_ARGS="--qnum=300"
NFQWS_ARGS="--filter-tcp=443 --hostlist=/fixture/discord-tcp-preserved.list"
NFQWS_ARGS_QUIC="--filter-udp=443 --hostlist=/fixture/quic-preserved.list"
NFQWS_ARGS_UDP="--filter-udp=50000-50100 --filter-l7=stun,discord"
NFQWS_ARGS_CUSTOM="--filter-tcp=443 --hostlist=/opt/etc/nfqws2/lists/youtube.list --lua-desync=fake:repeats=33 --new --filter-tcp=80 --hostlist=/fixture/custom-preserved.list"
[ -z "${KD_FIXTURE_BASE_ARGS:-}" ] || NFQWS_BASE_ARGS="$KD_FIXTURE_BASE_ARGS"

_startup_args() {
  echo "$NFQWS_BASE_ARGS $NFQWS_ARGS_CUSTOM --new $NFQWS_ARGS_UDP --new $NFQWS_ARGS_QUIC --new $NFQWS_ARGS"
}

# KD_TUNER_PIDFILE_RACE=1 behaves like nfqws2-keenetic 1.3.1: "start"
# returns before the daemon has written its pidfile.
is_running() {
  if [ "${KD_TUNER_PIDFILE_RACE:-0}" = "1" ]; then
    [ -f "$KD_TUNER_TEST_ROOT/opt/var/run/nfqws2.pid" ]
    return
  fi
  return 0
}

firewall_stop() {
  printf 'firewall-stop\n' >> "$KD_TUNER_TEST_ROOT/firewall.log"
  rm -f "$KD_TUNER_TEST_ROOT/ipt.state"
}

firewall_iptables() {
  printf 'firewall-start\n' >> "$KD_TUNER_TEST_ROOT/firewall.log"
  : > "$KD_TUNER_TEST_ROOT/ipt.state"
}

case "${1:-}" in
  start|stop|restart)
    printf 'nfqws-%s\n' "$1" >> "$KD_TUNER_TEST_ROOT/nfqws-service.log"
    case "$1" in
      start)
        : > "$KD_TUNER_TEST_ROOT/ipt.state"
        if [ "${KD_TUNER_PIDFILE_RACE:-0}" = "1" ]; then
          (sleep 2; echo 4242 > "$KD_TUNER_TEST_ROOT/opt/var/run/nfqws2.pid") &
        else
          echo 4242 > "$KD_TUNER_TEST_ROOT/opt/var/run/nfqws2.pid"
        fi
        ;;
      stop) rm -f "$KD_TUNER_TEST_ROOT/ipt.state" "$KD_TUNER_TEST_ROOT/opt/var/run/nfqws2.pid" ;;
    esac
    exit 0
    ;;
  firewall_stop)
    firewall_stop
    exit 0
    ;;
esac
EOF

cat > "$ROOT/opt/usr/bin/nfqws2" <<'EOF'
#!/bin/sh
printf 'candidate:%s\n' "$*" >> "$KD_TUNER_TEST_ROOT/nfqws-candidates.log"
echo "$$" >> "$KD_TUNER_TEST_ROOT/candidate-pids"
# Keenetic rebuilding iptables while the first candidate runs.
if [ "${KD_TUNER_FLUSH_IPT:-0}" = "1" ] && [ ! -f "$KD_TUNER_TEST_ROOT/ipt.flushed" ]; then
  : > "$KD_TUNER_TEST_ROOT/ipt.flushed"
  rm -f "$KD_TUNER_TEST_ROOT/ipt.state"
fi
if [ "${KD_TUNER_SLOW_CANDIDATE_STOP:-0}" = "1" ]; then
  trap 'sleep 1; exit 0' HUP INT TERM
else
  trap 'exit 0' HUP INT TERM
fi
while :; do
  sleep 5
done
EOF

# Without the official or a temporary firewall (no ipt.state) nothing is
# desynced: raw requests then fail as KD_TUNER_RAW says (block: TLS reset
# after connect; ipblock: no TCP connection; pass: as with a bypass).
# KD_CURL_FORCE=rc:time_connect:time_appconnect fails every GET that way.
cat > "$MOCK_BIN/curl" <<'EOF'
#!/bin/sh
# KD_TUNER_SLOW_CURL=1 hangs while a candidate runs (temporary firewall up).
if [ "${KD_TUNER_SLOW_CURL:-0}" = "1" ] && [ -f "$KD_TUNER_TEST_ROOT/ipt.state" ] &&
   grep -q nfqws-stop "$KD_TUNER_TEST_ROOT/nfqws-service.log" 2>/dev/null; then
  sleep "${KD_TUNER_SLOW_CURL_SECONDS:-60}"
fi
output=""
previous=""
post=0
range=0
for argument in "$@"; do
  case "$argument" in
    --data-binary) post=1 ;;
    --http1.1|--proxy|--noproxy|--connect-timeout|--max-time|--max-filesize) ;;
    --*) echo 'unsupported fixture curl option' >&2; exit 2 ;;
  esac
  [ "$previous" != -o ] || output="$argument"
  [ "$previous $argument" != "-r 0-65535" ] || range=1
  [ "$argument" != -I ] || { echo 'HEAD is not a volume check' >&2; exit 2; }
  previous="$argument"
done
printf '%s %s %s\n' "$post" "$range" "$argument" >> "$KD_TUNER_TEST_ROOT/curl.log"
raw=0
[ -f "$KD_TUNER_TEST_ROOT/ipt.state" ] || raw=1
mode="${KD_CURL_FORCE:-}"
if [ -z "$mode" ] && [ "$raw" = 1 ]; then
  case "${KD_TUNER_RAW:-block}" in
    block) mode="35:0.01:0" ;;
    ipblock) mode="7:0:0" ;;
  esac
fi
if [ "$post" = 1 ]; then
  if [ "${KD_CURL_POST_FREEZE:-0}" = 1 ]; then
    printf '000|0.020'
    exit 28
  fi
  printf '200|0.020'
  exit 0
fi
if [ -n "$mode" ]; then
  rc="${mode%%:*}"
  rest="${mode#*:}"
  printf '000|1.0|0|%s|%s' "${rest%%:*}" "${rest#*:}"
  echo "fixture curl error $rc" >&2
  exit "$rc"
fi
if [ -n "$output" ]; then
  if [ "${KD_TUNER_BADBODY:-0}" = 1 ]; then
    printf 'blocked page' > "$output"
  else
  case "$argument" in
    *oembed*) printf '{"title":"fixture"}' > "$output" ;;
    */gateway) printf '{"url":"wss://gateway.discord.gg"}' > "$output" ;;
    *) printf '\377\330\377' > "$output"; dd if=/dev/zero bs=512 count=1 >> "$output" 2>/dev/null ;;
  esac
  fi
fi
printf '200|0.01|560|0.005|0.010'
EOF

cat > "$MOCK_BIN/pidof" <<'EOF'
#!/bin/sh
case "${1:-}" in
  xray) echo 7777 ;;
  *) exit 1 ;;
esac
EOF

cat > "$MOCK_BIN/iptables-save" <<'EOF'
#!/bin/sh
echo '# fixture'
EOF

# The nfqws_post/nfqws_pre jumps exist while ipt.state exists.
cat > "$MOCK_BIN/iptables" <<'EOF'
#!/bin/sh
for argument in "$@"; do
  case "$argument" in
    -C) [ -f "$KD_TUNER_TEST_ROOT/ipt.state" ]; exit ;;
    -S)
      [ ! -f "$KD_TUNER_TEST_ROOT/ipt.state" ] ||
        echo '-A nfqws_post -o eth3 -p tcp -m multiport --dports 443 -j NFQUEUE --queue-num 300 --queue-bypass'
      exit 0
      ;;
  esac
done
exit 0
EOF

# QUIC probe stand-in: labels listed in KD_QUIC_FAIL get no reply
# (default: only the raw probe, i.e. QUIC is blocked without a bypass).
project_tools="$ROOT/opt/root/keenetic-discord-nfqws2/tools/router"
mkdir -p "$project_tools"
cat > "$project_tools/quic_probe.py" <<'EOF'
import os, sys
host, label = sys.argv[1], sys.argv[sys.argv.index("--label") + 1]
ip = sys.argv[sys.argv.index("--ip") + 1] if "--ip" in sys.argv else "142.250.74.14"
status = "no-reply" if label in os.environ.get("KD_QUIC_FAIL", "raw").split(",") else "ok"
with open(os.path.join(os.environ["KD_TUNER_TEST_ROOT"], "quic.log"), "a", encoding="utf-8") as log:
    log.write(f"{label} {host} {ip}\n")
print(f"EVENT|QUIC|{label}|{host}|{ip}|{status}|{12 if status == 'ok' else '-'}")
sys.exit(0 if status == "ok" else 1)
EOF
# The official nfqws2 runs with its firewall rules.
: > "$ROOT/ipt.state"

chmod +x \
  "$ROOT/opt/etc/init.d/S51nfqws2" \
  "$ROOT/opt/usr/bin/nfqws2" \
  "$MOCK_BIN/curl" \
  "$MOCK_BIN/pidof" \
  "$MOCK_BIN/iptables" \
  "$MOCK_BIN/iptables-save"

# An empty Flowseal-shaped source is enough to generate the built-in,
# known-good candidate without downloading anything.
: > "$SOURCE_DIR/general (ALT11).bat"

# A live process; a zombie (exited, not yet reaped because its parent was
# killed and the container's init does not reap) does not count.
process_running() {
  kill -0 "$1" 2>/dev/null || return 1
  ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
}

config_hash_before="$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')"

run_job() {
  PATH="$MOCK_BIN:$PATH" \
  KD_TUNER_TEST_ROOT="$ROOT" \
    python3 "$TARGET" \
      --service youtube \
      --job-id "$1" \
      --mix-level safe \
      --max-candidates 1 \
      --http-timeout 4 \
      --source-dir "$SOURCE_DIR"
}

run_job 1111111111111111

state="$ROOT/opt/tmp/xkeen-zapret-tuner/state.json"
report="$ROOT/opt/tmp/xkeen-zapret-tuner/result-report.json"
[ -s "$state" ]
if [ ! -s "$report" ]; then
  cat "$state"
  cat "$ROOT/opt/tmp/xkeen-zapret-tuner/events.log"
  exit 1
fi
python3 - "$state" "$report" <<'PY'
import json
import sys

state = json.load(open(sys.argv[1], encoding="utf-8"))
report = json.load(open(sys.argv[2], encoding="utf-8"))
assert state.get("status") == "found", state
assert state.get("nfqws_restored") == "running", state
assert state["xkeen_pids_before"] == {"xray": [7777]}, state
assert state["xkeen_pids_after"] == {"xray": [7777]}, state
assert report["service"] == "youtube", report
assert report["found"]["service"] == "youtube", report
assert state["baseline_result"]["verdict"] == "pass", state
assert state["last_suite_result"]["phase"] == "confirm", state
assert state["last_suite_result"]["verdict"] == "pass", state
# active baseline, raw (no bypass) baseline, candidate and confirm rounds
assert len(report["verification"]["probes"]) == 16, report
assert state["raw_baseline_result"]["verdict"] == "fail", state
assert state["raw_baseline"] == "fail" and state["network_discriminates"] is True, state
assert {p["status"] for p in report["verification"]["probes"] if p["phase"] == "raw"} == {"tls-error"}, report
verification = report["verification"]
assert verification["raw_baseline"] == "fail" and verification["network_discriminates"] is True, verification
# QUIC answers with the active profile only: the found candidate kept it.
assert (verification["quic_gate"], verification["quic_gate_reason"]) == ("on", "active-reply"), verification
assert verification["quic_results"] == ["EVENT|QUIC_RESULT|1|pass|2|2"], verification
assert verification["quic_verified"] is True, verification
assert state["youtube_quic"]["origin"] == "native", state
# Small pages get the 64 KB upload check (web and transport roles).
assert len(verification["volume_checks"]) == 6, verification
args = report["found"]["args"]
assert args[args.index("--new") + 1:] == [
    "--filter-udp=443", "--filter-l7=quic", "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
    "--payload=quic_initial", "--lua-desync=fake:blob=youtube_quic:repeats=11"], args
PY
# The web and transport checks read 64 KB with a range request (no HEAD).
grep -Fqx '0 1 https://www.youtube.com/' "$ROOT/curl.log"
grep -Fqx '0 1 https://redirector.googlevideo.com/' "$ROOT/curl.log"
grep -Fq '1 0 https://redirector.googlevideo.com/?t=' "$ROOT/curl.log"
grep -Fq '0 0 https://www.youtube.com/oembed' "$ROOT/curl.log"
grep -Fqx 'candidate-1 www.youtube.com 142.250.74.14' "$ROOT/quic.log"
grep -Fqx 'candidate-1 redirector.googlevideo.com 142.250.74.14' "$ROOT/quic.log"
[ -f "$ROOT/ipt.state" ]
if ls -d "$ROOT"/opt/tmp/zapret-tuner.* >/dev/null 2>&1; then
  echo 'ERROR: the runner left its temporary directory' >&2
  exit 1
fi

grep -Fq 'nfqws-stop' "$ROOT/nfqws-service.log"
grep -Fq 'nfqws-start' "$ROOT/nfqws-service.log"
grep -Fq 'firewall-start' "$ROOT/firewall.log"
grep -Fq 'firewall-stop' "$ROOT/firewall.log"
grep -Fq /fixture/discord-tcp-preserved.list "$ROOT/nfqws-candidates.log"
grep -Fq /fixture/quic-preserved.list "$ROOT/nfqws-candidates.log"
grep -Fq /fixture/custom-preserved.list "$ROOT/nfqws-candidates.log"
if grep -Fq -- '--lua-desync=fake:repeats=33' "$ROOT/nfqws-candidates.log"; then
  echo 'ERROR: old YouTube profile was not replaced' >&2
  exit 1
fi
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]
[ ! -e "$ROOT/opt/tmp/keenetic-discord-nfqws2.lock" ]

# Cancellation must terminate the candidate and run the same EXIT restoration.
rm -rf "$ROOT/opt/tmp/xkeen-zapret-tuner"
mkdir "$ROOT/opt/tmp/xkeen-zapret-tuner"
: > "$ROOT/nfqws-service.log"
: > "$ROOT/candidate-pids"
: > "$ROOT/firewall.log"

PATH="$MOCK_BIN:$PATH" \
KD_TUNER_TEST_ROOT="$ROOT" \
KD_TUNER_SLOW_CURL=1 KD_TUNER_SLOW_CURL_SECONDS=8 \
  python3 "$TARGET" \
    --service youtube \
    --job-id 2222222222222222 \
    --mix-level safe \
    --max-candidates 1 \
    --http-timeout 4 \
    --source-dir "$SOURCE_DIR" &
job_pid=$!

waited=0
while [ ! -s "$ROOT/candidate-pids" ]; do
  sleep 1
  waited=$((waited + 1))
  if [ "$waited" -ge 15 ]; then
    echo "ERROR: autotuner did not start its fixture candidate" >&2
    kill -TERM "$job_pid" 2>/dev/null || true
    wait "$job_pid" 2>/dev/null || true
    exit 1
  fi
done

kill -TERM "$job_pid"
set +e
wait "$job_pid"
job_rc=$?
set -e
[ "$job_rc" -eq 130 ]

python3 - "$state" <<'PY'
import json
import sys

state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state.get("status") == "cancelled", state
assert state.get("nfqws_restored") == "running", state
assert state["xkeen_pids_before"] == state["xkeen_pids_after"] == {"xray": [7777]}, state
PY

grep -Fq 'nfqws-start' "$ROOT/nfqws-service.log"
grep -Fq 'firewall-stop' "$ROOT/firewall.log"
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]
[ ! -e "$ROOT/opt/tmp/keenetic-discord-nfqws2.lock" ]

# Stop in the panel signals the whole process group: the runner gets SIGTERM
# directly and once more from the job. The second one must not interrupt the
# restore (the candidate takes a second to stop, so it lands inside it).
rm -rf "$ROOT/opt/tmp/xkeen-zapret-tuner"
mkdir "$ROOT/opt/tmp/xkeen-zapret-tuner"
: > "$ROOT/nfqws-service.log"
: > "$ROOT/candidate-pids"
PATH="$MOCK_BIN:$PATH" \
KD_TUNER_TEST_ROOT="$ROOT" \
KD_TUNER_SLOW_CURL=1 KD_TUNER_SLOW_CURL_SECONDS=8 \
KD_TUNER_SLOW_CANDIDATE_STOP=1 \
  setsid python3 "$TARGET" \
    --service youtube \
    --job-id 4444444444444444 \
    --mix-level safe \
    --max-candidates 1 \
    --http-timeout 4 \
    --source-dir "$SOURCE_DIR" &
job_pid=$!
waited=0
while [ ! -s "$ROOT/candidate-pids" ]; do
  sleep 1
  waited=$((waited + 1))
  if [ "$waited" -ge 15 ]; then
    echo "ERROR: autotuner did not start its fixture candidate" >&2
    python3 -c 'import os, signal, sys; os.killpg(int(sys.argv[1]), signal.SIGTERM)' "$job_pid" 2>/dev/null || true
    exit 1
  fi
done
python3 -c 'import os, signal, sys; os.killpg(int(sys.argv[1]), signal.SIGTERM)' "$job_pid"
set +e
wait "$job_pid"
set -e
python3 - "$state" <<'PY'
import json
import sys

state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state.get("status") == "cancelled", state
assert state.get("nfqws_restored") == "running", state
PY
grep -Fq 'nfqws-start' "$ROOT/nfqws-service.log"
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]

# The runner's trap waits for the current command (here a curl that hangs);
# after the stop timeout the job SIGKILLs it. The job must then kill the
# orphaned candidate nfqws2 (it would keep queue 300) and start the service.
rm -rf "$ROOT/opt/tmp/xkeen-zapret-tuner"
mkdir "$ROOT/opt/tmp/xkeen-zapret-tuner"
: > "$ROOT/nfqws-service.log"
: > "$ROOT/candidate-pids"
PATH="$MOCK_BIN:$PATH" \
KD_TUNER_TEST_ROOT="$ROOT" \
KD_TUNER_SLOW_CURL=1 KD_TUNER_SLOW_CURL_SECONDS=60 \
KD_TUNER_RUNNER_STOP_TIMEOUT=3 \
  python3 "$TARGET" \
    --service youtube \
    --job-id 4444444444444446 \
    --mix-level safe \
    --max-candidates 1 \
    --http-timeout 4 \
    --source-dir "$SOURCE_DIR" &
job_pid=$!
waited=0
while [ ! -s "$ROOT/candidate-pids" ]; do
  sleep 1
  waited=$((waited + 1))
  if [ "$waited" -ge 15 ]; then
    echo "ERROR: autotuner did not start its fixture candidate" >&2
    kill -TERM "$job_pid" 2>/dev/null || true
    exit 1
  fi
done
sleep 2
kill -TERM "$job_pid"
set +e
wait "$job_pid"
set -e
python3 - "$state" "$ROOT/candidate-pids" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
candidate = int(open(sys.argv[2], encoding="ascii").read().split()[0])
assert state.get("status") == "cancelled", state
assert state.get("nfqws_restored") == "running" and state.get("restored_by") == "job", state
assert state.get("orphan_candidate_killed") == candidate, state
PY
assert_candidate_gone() {
  while read -r candidate_pid; do
    if process_running "$candidate_pid"; then
      echo "ERROR: orphaned candidate nfqws2 $candidate_pid survived" >&2
      exit 1
    fi
  done < "$ROOT/candidate-pids"
}
assert_candidate_gone
grep -Fqx 'nfqws-start' "$ROOT/nfqws-service.log"
if ls -d "$ROOT"/opt/tmp/zapret-tuner.* >/dev/null 2>&1; then
  echo 'ERROR: the killed runner left its temporary directory' >&2
  exit 1
fi
[ ! -e "$ROOT/opt/tmp/keenetic-discord-nfqws2.lock" ]
# Let the orphaned curl stand-in finish its sleep in the background.
pkill -f "$MOCK_BIN/curl" 2>/dev/null || true

rm -f "$report"
KD_TUNER_BADBODY=1 run_job 3333333333333333
python3 - "$state" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["status"] == "none", state
assert state["last_suite_result"]["verdict"] == "fail", state
assert state["nfqws_restored"] == "running", state
PY
python3 - "$report" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["found"] is None, report
assert any(p["status"] == "invalid-metadata" for p in report["verification"]["probes"]), report
PY
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]

# Voice must keep the entire Discord TCP/QUIC and YouTube profile set.
voice_dir="$ROOT/opt/root/keenetic-discord-nfqws2/scripts"
mkdir -p "$voice_dir"
cat > "$voice_dir/diagnose-discord-voice.sh" <<'EOF'
#!/bin/sh
echo 'EVENT|VOICE_OBSERVATION|15|12|1'
echo 'EVENT|VOICE_ENDPOINT|162.159.130.234|50007|15|12'
echo yes > "$TUNER_VERDICT_FILE"
EOF
# Not executable on purpose: project scripts are stored as 0644 and run via sh.
: > "$ROOT/nfqws-candidates.log"
python3 - "$SCRIPT_DIR/tools/windows" "$ROOT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import zapret_tuner as tuner
source = tuner.SourceFile("general (ALT11).bat", "", "a" * 40, "https://example.invalid/general.bat")
tuner.save_source_cache(Path(sys.argv[2]) / "opt/etc/xkeen-web/flowseal-sources.json", [source], "b" * 40)
PY
PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" python3 "$TARGET" \
  --service discord-voice --client-ip 192.168.2.50 \
  --job-id 4444444444444444 --max-candidates 1
grep -Fq /fixture/discord-tcp-preserved.list "$ROOT/nfqws-candidates.log"
grep -Fq /fixture/quic-preserved.list "$ROOT/nfqws-candidates.log"
grep -Fq -- '--lua-desync=fake:repeats=33' "$ROOT/nfqws-candidates.log"
# The fixture's NFQWS_BASE_ARGS registers no discord_udp blob (as under
# --udp-strategy legacy): every candidate gets it, or no fake is ever sent.
grep -Fq -- "--blob=discord_udp:@$ROOT/opt/etc/nfqws2/blobs/discord_udp.bin" "$ROOT/nfqws-candidates.log"
python3 - "$state" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["status"] == "found", state
assert state["nfqws_restored"] == "running", state
assert state["voice_observation"]["incoming_packets"] == 12, state
assert state["verification"]["voice_audio_automatic"] is False, state
assert state["source_origin"] == "downloaded-cache", state
assert state["commit"] == "b" * 40, state
assert state["voice_endpoint_learned"] is True, state
PY
endpoint_file="$ROOT/opt/etc/xkeen-web/discord-voice-endpoint.json"
python3 - "$endpoint_file" <<'PY'
import json, sys
endpoint = json.load(open(sys.argv[1], encoding="utf-8"))
assert (endpoint["ip"], endpoint["port"]) == ("162.159.130.234", 50007), endpoint
PY
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]

# Automatic Voice check against the learned server. The probe is replaced by
# a script that answers for the labels listed in VOICE_PROBE_REPLIES.
probe_dir="$ROOT/opt/root/keenetic-discord-nfqws2/tools/router"
mkdir -p "$probe_dir"
cat > "$probe_dir/discord_voice_probe.py" <<'EOF'
import os, sys
host, port, label = sys.argv[1], sys.argv[2], sys.argv[sys.argv.index("--label") + 1]
with open(os.environ["VOICE_PROBE_LOG"], "a", encoding="utf-8") as log:
    log.write(f"{label} {host}:{port}\n")
replies = 3 if label in os.environ.get("VOICE_PROBE_REPLIES", "").split(",") else 0
print(f"EVENT|VOICE_PROBE|{label}|3|{replies}|{replies}")
sys.exit(0 if replies else 1)
EOF
probe_log="$FIXTURE/voice-probe.log"

run_voice_auto() {
  : > "$probe_log"
  PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" VOICE_PROBE_LOG="$probe_log" \
    VOICE_PROBE_REPLIES="$1" TUNER_VERDICT_TIMEOUT=2 python3 "$TARGET" \
    --service discord-voice --client-ip 192.168.2.50 --voice-auto \
    --job-id "$2" --max-candidates 2 --search-seed 7
}

# Only candidate 2 gets an answer: candidate 1 fails without asking anyone,
# candidate 2 passes and the user confirms the sound.
run_voice_auto candidate-2 5555555555555555
grep -Fqx 'active 162.159.130.234:50007' "$probe_log"
grep -Fqx 'raw 162.159.130.234:50007' "$probe_log"
grep -Fqx 'candidate-1 162.159.130.234:50007' "$probe_log"
grep -Fqx 'candidate-2 162.159.130.234:50007' "$probe_log"
python3 - "$state" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["status"] == "found", state
assert state["voice_auto_mode"] == "auto", state
assert state["last_voice_auto"] == {"candidate": 2, "result": "pass"}, state
assert state["voice_calibration"]["raw"]["valid"] == 0, state
assert not state.get("voice_unconfirmed"), state
assert state["nfqws_restored"] == "running", state
PY

# The server also answers without nfqws2: the probe proves nothing, so every
# candidate falls back to the manual check (the mock answers "yes").
run_voice_auto raw,active,candidate-1,candidate-2 6666666666666666
if grep -q '^candidate-' "$probe_log"; then
  echo "ERROR: candidates were probed although the raw probe was answered" >&2
  exit 1
fi
python3 - "$state" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["status"] == "found", state
assert (state["voice_auto_mode"], state["voice_auto_reason"]) == ("manual", "raw-reply"), state
PY

# A passing profile with nobody at the panel is kept, marked unconfirmed, and
# does not overwrite the learned server.
cat > "$voice_dir/diagnose-discord-voice.sh" <<'EOF'
#!/bin/sh
echo 'EVENT|VOICE_ENDPOINT|162.159.135.1|50020|9|9'
EOF
run_voice_auto candidate-1 7777777777777777
python3 - "$state" "$endpoint_file" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
endpoint = json.load(open(sys.argv[2], encoding="utf-8"))
assert state["status"] == "found", state
assert state["voice_unconfirmed"] is True, state
assert "voice_endpoint_learned" not in state, state
assert endpoint["ip"] == "162.159.130.234", endpoint
PY

# Without a learned server the automatic mode refuses to start.
rm -f "$endpoint_file"
run_voice_auto candidate-1 8888888888888888 || true
python3 - "$state" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["status"] == "error", state
assert "no learned Discord voice server" in state["error"], state
PY
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]

# Windows tuner path: there is no TUNER_VERDICT_FILE and each Voice verdict
# arrives on the runner's stdin (over SSH). The answer to candidate 1 is "no",
# to candidate 2 "yes". The verdict used to be read from the candidate list.
cat > "$voice_dir/diagnose-discord-voice.sh" <<'EOF'
#!/bin/sh
echo 'EVENT|VOICE_OBSERVATION|15|12|1'
EOF
windows_runner="$FIXTURE/windows-runner.sh"
python3 - "$SCRIPT_DIR/tools/windows" "$windows_runner" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import zapret_tuner as tuner
template = (Path(sys.argv[1]) / "router-candidate-runner.sh").read_text(encoding="utf-8")
source = tuner.SourceFile("general.bat", "", "a" * 40, "https://example.invalid/general.bat")
first = tuner.known_candidate("discord-voice", [source])
second = tuner.make_candidate(
    service="discord-voice",
    source=source,
    family="second",
    args=tuple(arg.replace("repeats=6", "repeats=11") for arg in first.args),
    notes=(),
    rank=1,
)
Path(sys.argv[2]).write_text(
    tuner.render_runner(
        template,
        service="discord-voice",
        candidates=[first, second],
        client_ip="192.168.2.50",
        voice_duration=10,
        http_timeout=6,
    ),
    encoding="utf-8",
)
PY
windows_output="$(
  printf 'no\nyes\n' |
    PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" sh "$windows_runner"
)"
printf '%s\n' "$windows_output" | grep -Fq 'EVENT|CANDIDATE|2|'
printf '%s\n' "$windows_output" | grep -Fq 'EVENT|FOUND|2|'
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]
# Discord Voice by the client's own traffic: the user stays in a channel and
# the diagnostic reports the state per window. Baseline idle, candidate 1
# only attempts, candidate 2 connects; then the user confirms the sound.
: > "$FIXTURE/traffic-calls"
cat > "$voice_dir/diagnose-discord-voice.sh" <<'EOF'
echo call >> "$KD_TRAFFIC_CALLS"
case "$(wc -l < "$KD_TRAFFIC_CALLS" | tr -d ' ')" in
  1) echo "EVENT|VOICE_TRAFFIC|idle" ;;
  2) echo "EVENT|VOICE_TRAFFIC|attempts" ;;
  *) echo "EVENT|VOICE_FLOW|63611|104.29.136.187|19300|12|11|10|1"; echo "EVENT|VOICE_TRAFFIC|connected" ;;
esac
EOF
traffic_runner="$FIXTURE/traffic-runner.sh"
python3 - "$SCRIPT_DIR/tools/windows" "$traffic_runner" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import zapret_tuner as tuner
template = (Path(sys.argv[1]) / "router-candidate-runner.sh").read_text(encoding="utf-8")
source = tuner.SourceFile("general.bat", "", "a" * 40, "https://example.invalid/general.bat")
first = tuner.known_candidate("discord-voice", [source])
second = tuner.make_candidate(
    service="discord-voice", source=source, family="second",
    args=tuple(arg.replace("repeats=6", "repeats=11") for arg in first.args), notes=(), rank=1,
)
Path(sys.argv[2]).write_text(
    tuner.render_runner(
        template, service="discord-voice", candidates=[first, second],
        client_ip="192.168.2.50", voice_duration=10, http_timeout=6, voice_traffic=True,
    ),
    encoding="utf-8",
)
PY
traffic_output="$(
  printf 'yes\n' |
    PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" KD_TRAFFIC_CALLS="$FIXTURE/traffic-calls" sh "$traffic_runner"
)"
for expected in \
  'EVENT|VOICE_TRAFFIC_RESULT|0|idle' \
  'EVENT|VOICE_TRAFFIC_RESULT|1|attempts' \
  'EVENT|VOICE_TRAFFIC_RESULT|2|connected' \
  'EVENT|VOICE_VERDICT|2'
do
  printf '%s\n' "$traffic_output" | grep -Fqx "$expected"
done
# Candidate 1 never asked for a verdict: no reconnect per candidate.
if printf '%s\n' "$traffic_output" | grep -Fqx 'EVENT|VOICE_VERDICT|1'; then
  echo "ERROR: the traffic check asked for a verdict on a failing candidate" >&2
  exit 1
fi
printf '%s\n' "$traffic_output" | grep -Fq 'EVENT|FOUND|2|'
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]

# ---------------------------------------------------------------------------
# Runner lifecycle and probes, run directly as the Windows tuner does.

# render_runner SERVICE COUNT OUTPUT: the runner with the first COUNT
# generated candidates (Safe mix of an empty ALT11 source).
render_runner() {
  python3 - "$SCRIPT_DIR/tools/windows" "$1" "$2" "$3" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import zapret_tuner as tuner
service, count, output = sys.argv[2], int(sys.argv[3]), sys.argv[4]
template = (Path(sys.argv[1]) / "router-candidate-runner.sh").read_text(encoding="utf-8")
source = tuner.SourceFile("general (ALT11).bat", "", "a" * 40, "https://example.invalid/general.bat")
candidates = tuner.build_candidates(service, [source], "safe")[:count]
Path(output).write_text(
    tuner.render_runner(
        template, service=service, candidates=candidates,
        client_ip="192.168.2.50", voice_duration=10, http_timeout=4,
    ),
    encoding="utf-8",
)
PY
}

reset_runtime_logs() {
  : > "$ROOT/nfqws-service.log"
  : > "$ROOT/nfqws-candidates.log"
  : > "$ROOT/candidate-pids"
  : > "$ROOT/curl.log"
  : > "$ROOT/quic.log"
  rm -f "$ROOT/ipt.flushed" "$ROOT/opt/var/run/nfqws2.pid"
  : > "$ROOT/ipt.state"
}

assert_restored_cleanly() {
  grep -Fqx 'nfqws-start' "$ROOT/nfqws-service.log" || {
    echo "ERROR: nfqws2 was not started again ($1)" >&2
    cat "$ROOT/nfqws-service.log" >&2
    exit 1
  }
  while read -r candidate_pid; do
    if process_running "$candidate_pid"; then
      echo "ERROR: candidate nfqws2 $candidate_pid is still running ($1)" >&2
      kill "$candidate_pid" 2>/dev/null || true
      exit 1
    fi
  done < "$ROOT/candidate-pids"
  if ls -d "$ROOT"/opt/tmp/zapret-tuner.* >/dev/null 2>&1; then
    echo "ERROR: temporary runner files were left behind ($1)" >&2
    exit 1
  fi
  [ ! -e "$ROOT/opt/tmp/keenetic-discord-nfqws2.lock" ] || {
    echo "ERROR: the runner kept the project lock ($1)" >&2
    exit 1
  }
}

run_runner() {
  PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" sh "$@" </dev/null
}

youtube_runner="$FIXTURE/youtube-runner.sh"
render_runner youtube 3 "$youtube_runner"

# B1: the reader of the runner's output goes away (Ctrl-C in the Windows
# tuner, SSH drop, killed job). busybox ash and dash skip the EXIT trap on
# SIGPIPE; the runner must still restore nfqws2 and stop its candidate.
pipe_shells="sh"
if command -v busybox >/dev/null 2>&1; then
  pipe_shells="sh busybox"
fi
for pipe_shell in $pipe_shells; do
  reset_runtime_logs
  if [ "$pipe_shell" = busybox ]; then
    set -- busybox sh
  else
    set -- sh
  fi
  PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" "$@" "$youtube_runner" </dev/null 2>/dev/null |
    while IFS= read -r line; do
      case "$line" in
        'EVENT|CANDIDATE|1|'*) break ;;
      esac
    done
  waited=0
  while ! grep -Fqx 'nfqws-start' "$ROOT/nfqws-service.log" && [ "$waited" -lt 20 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  sleep 1
  grep -Fqx 'nfqws-stop' "$ROOT/nfqws-service.log"
  [ -s "$ROOT/candidate-pids" ] || {
    echo "ERROR: the SIGPIPE check never started a candidate ($pipe_shell)" >&2
    exit 1
  }
  assert_restored_cleanly "SIGPIPE under $pipe_shell"
done

# nfqws2-keenetic 1.3.1 writes its pidfile after "start" returns: the
# restore waits for it instead of reporting a false RESTORE_ERROR.
reset_runtime_logs
echo 4242 > "$ROOT/opt/var/run/nfqws2.pid"
render_runner youtube 1 "$FIXTURE/race-runner.sh"
race_output="$(KD_TUNER_PIDFILE_RACE=1 run_runner "$FIXTURE/race-runner.sh")"
printf '%s\n' "$race_output" | grep -Fqx 'EVENT|RESTORED|running'
if printf '%s\n' "$race_output" | grep -Fq 'EVENT|RESTORE_ERROR|'; then
  echo "ERROR: restore did not wait for the pidfile" >&2
  exit 1
fi
assert_restored_cleanly "pidfile race"

# B6: another project operation holds the lock (live PID): the runner stops
# before touching nfqws2. A stale lock (dead PID) is taken over and released.
reset_runtime_logs
lock_dir="$ROOT/opt/tmp/keenetic-discord-nfqws2.lock"
mkdir "$lock_dir"
echo "$$" > "$lock_dir/pid"
set +e
busy_output="$(run_runner "$youtube_runner")"
busy_rc=$?
set -e
[ "$busy_rc" -eq 1 ]
printf '%s\n' "$busy_output" | grep -Fqx 'EVENT|FATAL|project-busy'
[ ! -s "$ROOT/nfqws-service.log" ]
[ ! -s "$ROOT/nfqws-candidates.log" ]
[ "$(cat "$lock_dir/pid")" = "$$" ]
# A job may hand its lock over only when it really holds it.
set +e
KD_TUNER_LOCK_HELD=1 run_runner "$youtube_runner" | grep -Fqx 'EVENT|FATAL|project-busy'
handover_rc=$?
set -e
[ "$handover_rc" -eq 0 ]
[ ! -s "$ROOT/nfqws-service.log" ]
sh -c 'exit 0' &
dead_pid=$!
wait "$dead_pid"
echo "$dead_pid" > "$lock_dir/pid"
render_runner youtube 1 "$FIXTURE/one-runner.sh"
run_runner "$FIXTURE/one-runner.sh" 2>/dev/null | grep -Fq 'EVENT|FOUND|1|'
assert_restored_cleanly "stale lock"

# Keenetic rebuilt iptables while candidate 1 ran: its result does not count,
# and the jumps are re-asserted before candidate 2.
reset_runtime_logs
render_runner youtube 2 "$FIXTURE/two-runner.sh"
flush_output="$(KD_TUNER_FLUSH_IPT=1 run_runner "$FIXTURE/two-runner.sh")"
for expected in \
  'EVENT|FIREWALL_LOST|1' \
  'EVENT|FIREWALL_REASSERT|2|missing' \
  'EVENT|FIREWALL_REASSERT|2|restored'
do
  printf '%s\n' "$flush_output" | grep -Fqx "$expected"
done
printf '%s\n' "$flush_output" | grep -Fq 'EVENT|FOUND|2|'
assert_restored_cleanly "firewall re-assert"

# B3: a candidate that breaks QUIC fails even though every HTTP check passes.
reset_runtime_logs
quic_output="$(KD_QUIC_FAIL=raw,candidate-1 run_runner "$FIXTURE/two-runner.sh")"
printf '%s\n' "$quic_output" | grep -Fqx 'EVENT|QUIC_GATE|on|active-reply'
printf '%s\n' "$quic_output" | grep -Fqx 'EVENT|QUIC_RESULT|1|fail|0|2'
printf '%s\n' "$quic_output" | grep -Fqx 'EVENT|QUIC_RESULT|2|pass|2|2'
printf '%s\n' "$quic_output" | grep -Fq 'EVENT|FOUND|2|'
# QUIC answers neither with nor without the profile: nothing to protect.
reset_runtime_logs
quic_output="$(KD_QUIC_FAIL=raw,active,candidate-1 run_runner "$FIXTURE/one-runner.sh")"
printf '%s\n' "$quic_output" | grep -Fqx 'EVENT|QUIC_GATE|off|no-reply'
printf '%s\n' "$quic_output" | grep -Fqx 'EVENT|QUIC_RESULT|1|skipped|0|0'
printf '%s\n' "$quic_output" | grep -Fq 'EVENT|FOUND|1|'
# QUIC answers without a bypass: every candidate must keep it.
reset_runtime_logs
quic_output="$(KD_QUIC_FAIL=none run_runner "$FIXTURE/one-runner.sh")"
printf '%s\n' "$quic_output" | grep -Fqx 'EVENT|QUIC_GATE|on|raw-reply'

# Raw no-bypass baseline: everything opens without nfqws2 (no discrimination),
# or no address accepts raw TCP (candidates are still tried).
reset_runtime_logs
raw_output="$(KD_TUNER_RAW=pass run_runner "$FIXTURE/one-runner.sh")"
printf '%s\n' "$raw_output" | grep -Fqx 'EVENT|RAW_BASELINE|pass|4|4'
printf '%s\n' "$raw_output" | grep -Fq 'EVENT|FOUND|1|'
reset_runtime_logs
raw_output="$(KD_TUNER_RAW=ipblock run_runner "$FIXTURE/one-runner.sh")"
printf '%s\n' "$raw_output" | grep -Fqx 'EVENT|RAW_BASELINE|tcp-unreachable|0|4'
printf '%s\n' "$raw_output" | grep -Fq 'EVENT|FOUND|1|'
[ -s "$ROOT/nfqws-candidates.log" ]
printf '%s\n' "$raw_output" | grep -Fq 'EVENT|PROBE_DETAIL|0|raw|1|web|000|1.0|0|7|connect-error|'
assert_restored_cleanly "raw tcp-unreachable"
rm -f "$report"
KD_TUNER_RAW=ipblock run_job 9999999999999999
python3 - "$state" "$report" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
report = json.load(open(sys.argv[2], encoding="utf-8"))
assert state["status"] == "found", state
assert state["raw_baseline"] == "tcp-unreachable", state
assert report["verification"]["raw_baseline"] == "tcp-unreachable", report
assert "перебор стратегий продолжается" in open(sys.argv[1].replace("state.json", "events.log"), encoding="utf-8").read()
PY
KD_TUNER_RAW=pass run_job 9999999999999998
python3 - "$state" "$report" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
report = json.load(open(sys.argv[2], encoding="utf-8"))
assert state["status"] == "found", state
assert state["network_discriminates"] is False, state
assert report["verification"]["network_discriminates"] is False, report
PY

# curl exit codes are classified in PROBE_DETAIL; 126/127 mean curl itself is
# broken and stop the run before nfqws2 is touched.
render_runner youtube 0 "$FIXTURE/empty-runner.sh"
for case_line in \
  '6:0:0 dns-error' '7:0:0 connect-error' '28:0:0 timeout' '28:0.01:0 stall' \
  '28:0.01:0.02 freeze' '35:0.01:0 tls-error' '52:0.01:0.02 empty-reply' \
  '56:0.01:0.02 reset' '99:0.01:0.02 network-error'
do
  reset_runtime_logs
  forced="${case_line% *}"
  expected="${case_line#* }"
  forced_output="$(KD_CURL_FORCE="$forced" run_runner "$FIXTURE/empty-runner.sh")"
  printf '%s\n' "$forced_output" |
    grep -Fq "EVENT|PROBE_DETAIL|0|baseline|1|web|000|1.0|0|${forced%%:*}|$expected|https://www.youtube.com/" || {
      echo "ERROR: curl $forced was not classified as $expected" >&2
      printf '%s\n' "$forced_output" >&2
      exit 1
    }
done
printf '%s\n' "$forced_output" | grep -Fqx 'EVENT|RAW_BASELINE|fail|0|4'
reset_runtime_logs
forced_output="$(KD_CURL_FORCE=6:0:0 run_runner "$FIXTURE/empty-runner.sh")"
printf '%s\n' "$forced_output" | grep -Fqx 'EVENT|RAW_BASELINE|dns-error|0|4'
reset_runtime_logs
set +e
forced_output="$(KD_CURL_FORCE=127:0:0 run_runner "$FIXTURE/empty-runner.sh")"
forced_rc=$?
set -e
[ "$forced_rc" -eq 1 ]
printf '%s\n' "$forced_output" | grep -Fqx 'EVENT|FATAL|curl-broken:127'
[ ! -s "$ROOT/nfqws-service.log" ]
# A small page that answers but freezes on a 64 KB upload is a freeze.
reset_runtime_logs
forced_output="$(KD_CURL_POST_FREEZE=1 run_runner "$FIXTURE/empty-runner.sh")"
printf '%s\n' "$forced_output" | grep -Fq 'EVENT|PROBE_VOLUME|0|baseline|1|web|000|28|0.020|freeze|https://www.youtube.com/'
printf '%s\n' "$forced_output" | grep -Fq 'EVENT|PROBE_DETAIL|0|baseline|1|web|200|0.01|560|0|freeze|https://www.youtube.com/'
printf '%s\n' "$forced_output" | grep -Fqx 'EVENT|SUITE_RESULT|0|baseline|1|fail|2|4'

# B7: under --udp-strategy legacy the engine deletes discord_udp.bin and
# registers no blob; the runner uses the project's copy. A registered blob is
# not added twice; without any copy the run stops.
cat > "$voice_dir/diagnose-discord-voice.sh" <<'EOF'
#!/bin/sh
echo "EVENT|VOICE_OBSERVATION|1|1|1"
EOF
voice_runner="$FIXTURE/voice-blob-runner.sh"
render_runner discord-voice 1 "$voice_runner"
mv "$ROOT/opt/etc/nfqws2/blobs/discord_udp.bin" "$FIXTURE/discord_udp.bin.saved"
mkdir -p "$ROOT/opt/root/keenetic-discord-nfqws2/config/blobs"
printf 'blob' > "$ROOT/opt/root/keenetic-discord-nfqws2/config/blobs/ACTIVE_DISCORD_UDP.bin"
reset_runtime_logs
printf 'yes\n' | PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" sh "$voice_runner" > "$FIXTURE/voice-blob.out"
grep -Fq -- "--blob=discord_udp:@$ROOT/opt/tmp/zapret-tuner." "$ROOT/nfqws-candidates.log"
grep -Fq 'EVENT|VOICE_BLOB|added|' "$FIXTURE/voice-blob.out"
assert_restored_cleanly "voice legacy blob"
reset_runtime_logs
printf 'yes\n' | PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" \
  KD_FIXTURE_BASE_ARGS="--qnum=300 --blob=discord_udp:@/opt/etc/nfqws2/blobs/discord_udp.bin" \
  sh "$voice_runner" > "$FIXTURE/voice-blob.out"
[ "$(grep -o -- '--blob=discord_udp:' "$ROOT/nfqws-candidates.log" | wc -l | tr -d ' ')" -eq 1 ]
rm -f "$ROOT/opt/root/keenetic-discord-nfqws2/config/blobs/ACTIVE_DISCORD_UDP.bin"
reset_runtime_logs
set +e
blob_output="$(run_runner "$voice_runner")"
blob_rc=$?
set -e
[ "$blob_rc" -eq 1 ]
printf '%s\n' "$blob_output" | grep -Fqx 'EVENT|FATAL|discord-udp-blob-missing'
[ ! -s "$ROOT/nfqws-candidates.log" ]
mv "$FIXTURE/discord_udp.bin.saved" "$ROOT/opt/etc/nfqws2/blobs/discord_udp.bin"

# B9: with "range=wide" the job generates Voice candidates for 50000-65535
# (before candidate_id), so an import keeps the configured range.
printf '# Discord UDP: strategy=flowseal, range=wide.\n' >> "$ROOT/opt/etc/nfqws2/nfqws2.conf"
reset_runtime_logs
cat > "$voice_dir/diagnose-discord-voice.sh" <<'EOF'
#!/bin/sh
echo yes > "$TUNER_VERDICT_FILE"
EOF
PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" python3 "$TARGET" \
  --service discord-voice --client-ip 192.168.2.50 \
  --job-id 4444444444444445 --max-candidates 1 --search-seed 1
grep -Fq -- '--filter-udp=443,3478-3481,5349,19294-19344,50000-65535' "$ROOT/nfqws-candidates.log"
python3 - "$state" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["status"] == "found", state
assert state["udp_range"] == "wide" and state["udp_range_runner"] == "wide", state
assert any("50000-65535" in arg for arg in state["found"]["args"]), state
PY
sed -i '/^# Discord UDP:/d' "$ROOT/opt/etc/nfqws2/nfqws2.conf"
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]

# Telegram is blocked by IP and is not tuned: the job refuses the service
# even when the recorded route still says zapret (older engines), and a
# runner rendered for it stops before touching nfqws2.
sed -i 's/^# Active routes: .*/# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=zapret./' \
  "$ROOT/opt/etc/nfqws2/nfqws2.conf"
config_hash_before="$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')"
: > "$ROOT/nfqws-candidates.log"
set +e
PATH="$MOCK_BIN:$PATH" \
KD_TUNER_TEST_ROOT="$ROOT" \
  python3 "$TARGET" \
    --service telegram \
    --job-id 5555555555555555 \
    --source-dir "$SOURCE_DIR" 2>"$FIXTURE/telegram-stderr"
telegram_rc=$?
set -e
[ "$telegram_rc" -eq 2 ] || {
  echo "ERROR: the job accepted --service telegram (exit $telegram_rc)" >&2
  exit 1
}
grep -Fq 'invalid choice' "$FIXTURE/telegram-stderr"
telegram_runner="$FIXTURE/telegram-runner.sh"
python3 - "$SCRIPT_DIR/tools/windows" "$telegram_runner" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import zapret_tuner as tuner
template = (Path(sys.argv[1]) / "router-candidate-runner.sh").read_text(encoding="utf-8")
Path(sys.argv[2]).write_text(
    tuner.render_runner(
        template, service="telegram", candidates=[],
        client_ip="127.0.0.1", voice_duration=10, http_timeout=6,
    ),
    encoding="utf-8",
)
PY
set +e
telegram_output="$(PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" sh "$telegram_runner" </dev/null)"
telegram_rc=$?
set -e
[ "$telegram_rc" -eq 2 ]
printf '%s\n' "$telegram_output" | grep -Fqx 'EVENT|FATAL|unsupported-service'
[ ! -s "$ROOT/nfqws-candidates.log" ]
[ "$(sha256sum "$ROOT/opt/etc/nfqws2/nfqws2.conf" | awk '{print $1}')" = "$config_hash_before" ]

echo "router-autotune-tests-ok"
