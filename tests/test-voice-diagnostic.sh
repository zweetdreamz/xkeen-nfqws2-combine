#!/bin/sh
set -eu

# diagnose-discord-voice.sh with tcpdump/ip/iptables-save mocked: checks the
# packet counters and the learned voice endpoint (EVENT|VOICE_ENDPOINT).

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/scripts/diagnose-discord-voice.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-voice-diag.XXXXXX")"
trap 'rm -rf "$FIXTURE"' 0 HUP INT TERM
ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"
mkdir -p "$ROOT/opt/etc/nfqws2" "$ROOT/opt/tmp" "$MOCK_BIN"
printf '%s\n' 'ISP_INTERFACE="eth3"' > "$ROOT/opt/etc/nfqws2/nfqws2.conf"

cat > "$MOCK_BIN/tcpdump" <<'MOCK'
#!/bin/sh
case "$*" in
  *"-ni br0"*)
    if [ -n "${KD_LAN_CAPTURE:-}" ]; then
      cat "$KD_LAN_CAPTURE"
      exit 0
    fi
    cat <<'LINES'
1.0 IP 192.168.2.60.51000 > 162.159.130.234.50007: UDP, length 74
1.1 IP 162.159.130.234.50007 > 192.168.2.60.51000: UDP, length 74
1.2 IP 192.168.2.60.51000 > 162.159.130.234.50007: UDP, length 120
1.3 IP 192.168.2.60.51000 > 162.159.130.234.50007: UDP, length 120
1.4 IP 192.168.2.60.52000 > 35.214.1.2.50010: UDP, length 120
1.5 IP 192.168.2.60.52000 > 35.214.1.2.50010: UDP, length 120
1.6 IP 192.168.2.60.52000 > 35.214.1.2.50010: UDP, length 120
1.7 IP 192.168.2.60.52000 > 35.214.1.2.50010: UDP, length 120
1.8 IP 192.168.2.60.53000 > 192.168.2.1.53: UDP, length 40
1.9 IP 192.168.2.60.54000 > 8.8.8.8.443: UDP, length 1200
LINES
    ;;
esac
MOCK
cat > "$MOCK_BIN/ip" <<'MOCK'
#!/bin/sh
echo "192.168.2.60 dev br0 src 192.168.2.1"
MOCK
printf '#!/bin/sh\nexit 0\n' > "$MOCK_BIN/iptables-save"
chmod +x "$MOCK_BIN/tcpdump" "$MOCK_BIN/ip" "$MOCK_BIN/iptables-save"

output="$(PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" sh "$TARGET" 192.168.2.60 5)"
# 35.214.1.2 sends more but never answered; the answering server is chosen.
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_ENDPOINT|162.159.130.234|50007|3|1'
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_OBSERVATION|9|1|0'
# One discovery and a single answer: the client tries, nothing lasts.
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_TRAFFIC|attempts'
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_FLOW|51000|162.159.130.234|50007|3|1|0|1'

# Shaped like a real session (Cloudflare voice server, port 19300): a new
# flow starts with the 74-byte discovery and the server keeps answering
# about once a second -> connected.
awk 'BEGIN {
  print "10.0 IP 192.168.2.60.63611 > 104.29.136.187.19300: UDP, length 74"
  print "10.1 IP 104.29.136.187.19300 > 192.168.2.60.63611: UDP, length 74"
  for (t = 11; t <= 21; t++) {
    printf "%d.0 IP 192.168.2.60.63611 > 104.29.136.187.19300: UDP, length 60\n", t
    printf "%d.1 IP 104.29.136.187.19300 > 192.168.2.60.63611: UDP, length 52\n", t
  }
}' > "$FIXTURE/connected.txt"
output="$(PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" KD_LAN_CAPTURE="$FIXTURE/connected.txt" sh "$TARGET" 192.168.2.60 5)"
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_TRAFFIC|connected'

# The same lasting flow without a discovery in this window existed before
# the check, so it says nothing about the strategy under test.
grep -v 'length 74' "$FIXTURE/connected.txt" > "$FIXTURE/established.txt"
output="$(PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" KD_LAN_CAPTURE="$FIXTURE/established.txt" sh "$TARGET" 192.168.2.60 5)"
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_TRAFFIC|established'

# A repeated attempt with a short answer burst stays "attempts", and no voice
# traffic at all is "idle".
head -n 8 "$FIXTURE/connected.txt" > "$FIXTURE/short.txt"
output="$(PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" KD_LAN_CAPTURE="$FIXTURE/short.txt" sh "$TARGET" 192.168.2.60 5)"
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_TRAFFIC|attempts'
printf '%s\n' '1.0 IP 192.168.2.60.53000 > 192.168.2.1.53: UDP, length 40' > "$FIXTURE/idle.txt"
output="$(PATH="$MOCK_BIN:$PATH" KD_TUNER_TEST_ROOT="$ROOT" KD_LAN_CAPTURE="$FIXTURE/idle.txt" sh "$TARGET" 192.168.2.60 5)"
printf '%s\n' "$output" | grep -Fqx 'EVENT|VOICE_TRAFFIC|idle'
[ -z "$(find "$ROOT/opt/tmp" -mindepth 1)" ]
echo "voice-diagnostic-tests-ok"
