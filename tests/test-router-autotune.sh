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

_startup_args() {
  echo "$NFQWS_BASE_ARGS $NFQWS_ARGS_CUSTOM --new $NFQWS_ARGS_UDP --new $NFQWS_ARGS_QUIC --new $NFQWS_ARGS"
}

is_running() {
  return 0
}

firewall_stop() {
  printf 'firewall-stop\n' >> "$KD_TUNER_TEST_ROOT/firewall.log"
}

firewall_iptables() {
  printf 'firewall-start\n' >> "$KD_TUNER_TEST_ROOT/firewall.log"
}

case "${1:-}" in
  start|stop|restart)
    printf 'nfqws-%s\n' "$1" >> "$KD_TUNER_TEST_ROOT/nfqws-service.log"
    exit 0
    ;;
esac
EOF

cat > "$ROOT/opt/usr/bin/nfqws2" <<'EOF'
#!/bin/sh
printf 'candidate:%s\n' "$*" >> "$KD_TUNER_TEST_ROOT/nfqws-candidates.log"
if [ "${KD_TUNER_SLOW_CANDIDATE_STOP:-0}" = "1" ]; then
  trap 'sleep 1; exit 0' HUP INT TERM
else
  trap 'exit 0' HUP INT TERM
fi
while :; do
  sleep 5
done
EOF

cat > "$MOCK_BIN/curl" <<'EOF'
#!/bin/sh
if [ "${KD_TUNER_SLOW_CURL:-0}" = "1" ] && grep -q nfqws-stop "$KD_TUNER_TEST_ROOT/nfqws-service.log" 2>/dev/null; then
  sleep 60
fi
output=""
previous=""
for argument in "$@"; do
  case "$argument" in
    --http1.1|--proxy|--noproxy|--connect-timeout|--max-time|--max-filesize) ;;
    --*) echo 'unsupported fixture curl option' >&2; exit 2 ;;
  esac
  [ "$previous" != -o ] || output="$argument"
  previous="$argument"
done
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
printf '200|0.01|560'
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

chmod +x \
  "$ROOT/opt/etc/init.d/S51nfqws2" \
  "$ROOT/opt/usr/bin/nfqws2" \
  "$MOCK_BIN/curl" \
  "$MOCK_BIN/pidof" \
  "$MOCK_BIN/iptables-save"

# An empty Flowseal-shaped source is enough to generate the built-in,
# known-good candidate without downloading anything.
: > "$SOURCE_DIR/general (ALT11).bat"

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
assert len(report["verification"]["probes"]) == 12, report
PY

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
: > "$ROOT/firewall.log"

PATH="$MOCK_BIN:$PATH" \
KD_TUNER_TEST_ROOT="$ROOT" \
KD_TUNER_SLOW_CURL=1 \
  python3 "$TARGET" \
    --service youtube \
    --job-id 2222222222222222 \
    --mix-level safe \
    --max-candidates 1 \
    --http-timeout 4 \
    --source-dir "$SOURCE_DIR" &
job_pid=$!

waited=0
while ! grep -Fq 'nfqws-stop' "$ROOT/nfqws-service.log" 2>/dev/null; do
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
PATH="$MOCK_BIN:$PATH" \
KD_TUNER_TEST_ROOT="$ROOT" \
KD_TUNER_SLOW_CURL=1 \
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
while ! grep -Fq 'nfqws-stop' "$ROOT/nfqws-service.log" 2>/dev/null; do
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
echo "router-autotune-tests-ok"
