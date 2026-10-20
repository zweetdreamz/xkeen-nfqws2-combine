#!/bin/sh
set -eu

# Read-only Discord Desktop voice trace for a Keenetic router.
# It captures packet headers only, uses temporary files, and removes them.

CLIENT_IP="${1:-}"
DURATION="${2:-30}"
# KD_TUNER_TEST_ROOT redirects router paths in tests (same as the tuner runner).
ROOT_PREFIX="${KD_TUNER_TEST_ROOT:-}"
NFQWS_CONF="$ROOT_PREFIX/opt/etc/nfqws2/nfqws2.conf"
TMP_DIR="$ROOT_PREFIX/opt/tmp/discord-voice-debug.$$"
LAN_PID=""
WAN_PID=""

usage() {
  echo "Usage: sh diagnose-discord-voice.sh CLIENT_IPV4 [SECONDS]"
  echo "Example: sh diagnose-discord-voice.sh 192.168.2.147 30"
}

cleanup() {
  [ -z "$LAN_PID" ] || kill "$LAN_PID" 2>/dev/null || true
  [ -z "$WAN_PID" ] || kill "$WAN_PID" 2>/dev/null || true
  if [ -d "$TMP_DIR" ]; then
    rm -f "$TMP_DIR/lan.txt" "$TMP_DIR/wan.txt" \
      "$TMP_DIR/nfqueue-before.txt" "$TMP_DIR/nfqueue-after.txt" \
      "$TMP_DIR/remote-ips.txt"
    rmdir "$TMP_DIR" 2>/dev/null || true
  fi
}
trap cleanup 0 HUP INT TERM

case "$CLIENT_IP" in
  ""|*[!0-9.]*)
    usage >&2
    exit 2
    ;;
esac

case "$DURATION" in
  ""|*[!0-9]*)
    usage >&2
    exit 2
    ;;
esac
[ "$DURATION" -ge 5 ] && [ "$DURATION" -le 60 ] || {
  echo "ERROR: duration must be between 5 and 60 seconds." >&2
  exit 2
}

for required in tcpdump ip awk grep sort sleep kill iptables-save; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $required" >&2
    exit 1
  }
done

[ -r "$NFQWS_CONF" ] || {
  echo "ERROR: nfqws2 config not found: $NFQWS_CONF" >&2
  exit 1
}

LAN_INTERFACE="$(
  ip route get "$CLIENT_IP" 2>/dev/null |
    awk '{
      for (i=1; i<=NF; i++) {
        if ($i == "dev") {
          print $(i+1)
          exit
        }
      }
    }'
)"
[ -n "$LAN_INTERFACE" ] || LAN_INTERFACE="br0"

WAN_INTERFACES="$(
  awk -F= '
    $1 == "ISP_INTERFACE" {
      value=$0
      sub(/^[^=]*=/, "", value)
      gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", value)
      last=value
    }
    END { print last }
  ' "$NFQWS_CONF"
)"
set -- $WAN_INTERFACES
WAN_INTERFACE="${1:-}"
[ -n "$WAN_INTERFACE" ] || {
  echo "ERROR: ISP_INTERFACE is empty in $NFQWS_CONF" >&2
  exit 1
}

mkdir "$TMP_DIR"
iptables-save -c -t mangle 2>/dev/null |
  grep -E 'nfqws_(post|pre).*udp.*NFQUEUE' \
  > "$TMP_DIR/nfqueue-before.txt" || true

echo "Discord Voice diagnostic"
echo "client=$CLIENT_IP lan=$LAN_INTERFACE wan=$WAN_INTERFACE duration=${DURATION}s"
echo
echo "Disconnect and reconnect Discord Desktop voice now."

tcpdump -ni "$LAN_INTERFACE" -nn -tt -l -s 160 \
  "udp and host $CLIENT_IP" > "$TMP_DIR/lan.txt" 2>&1 &
LAN_PID=$!

tcpdump -ni "$WAN_INTERFACE" -nn -tt -l -s 160 \
  "udp and (port 443 or portrange 3478-3481 or port 5349 or portrange 19294-19344 or portrange 50000-65535)" \
  > "$TMP_DIR/wan.txt" 2>&1 &
WAN_PID=$!

sleep "$DURATION"
kill "$LAN_PID" "$WAN_PID" 2>/dev/null || true
wait "$LAN_PID" 2>/dev/null || true
wait "$WAN_PID" 2>/dev/null || true
LAN_PID=""
WAN_PID=""

iptables-save -c -t mangle 2>/dev/null |
  grep -E 'nfqws_(post|pre).*udp.*NFQUEUE' \
  > "$TMP_DIR/nfqueue-after.txt" || true

echo
echo "== Discord DNS and media discovery =="
grep -Ei 'discord|discord\.media' "$TMP_DIR/lan.txt" || echo "No Discord DNS names observed."

echo
echo "== Client UDP endpoints =="
awk -v client="$CLIENT_IP" '
  $2 == "IP" && index($3, client ".") == 1 && $4 == ">" {
    endpoint=$5
    sub(/:$/, "", endpoint)
    if (endpoint !~ /^10\./ &&
        endpoint !~ /^192\.168\./ &&
        endpoint !~ /^172\.(1[6-9]|2[0-9]|3[01])\./ &&
        endpoint !~ /^22[4-9]\./ &&
        endpoint !~ /^23[0-9]\./) {
      print $3 " -> " endpoint
    }
  }
' "$TMP_DIR/lan.txt" | sort -u

awk -v client="$CLIENT_IP" '
  $2 == "IP" && index($3, client ".") == 1 && $4 == ">" {
    endpoint=$5
    sub(/:$/, "", endpoint)
    sub(/\.[0-9]+$/, "", endpoint)
    if (endpoint !~ /^10\./ &&
        endpoint !~ /^192\.168\./ &&
        endpoint !~ /^172\.(1[6-9]|2[0-9]|3[01])\./ &&
        endpoint !~ /^22[4-9]\./ &&
        endpoint !~ /^23[0-9]\./) {
      print endpoint
    }
  }
' "$TMP_DIR/lan.txt" | sort -u > "$TMP_DIR/remote-ips.txt"

echo
echo "== Replies delivered to the client =="
awk -v client="$CLIENT_IP" '
  $2 == "IP" && index($5, client ".") == 1 {
    source=$3
    destination=$5
    sub(/:$/, "", destination)
    if (source !~ /^10\./ &&
        source !~ /^192\.168\./ &&
        source !~ /^172\.(1[6-9]|2[0-9]|3[01])\./) {
      print source " -> " destination
    }
  }
' "$TMP_DIR/lan.txt" | sort -u

echo
echo "== Relevant packets on direct WAN =="
wan_matches=0
while IFS= read -r remote_ip; do
  [ -n "$remote_ip" ] || continue
  if grep -F "$remote_ip." "$TMP_DIR/wan.txt"; then
    wan_matches=1
  fi
done < "$TMP_DIR/remote-ips.txt"
[ "$wan_matches" -eq 1 ] || echo "No matching WAN packets observed."

echo
echo "== UDP conntrack for client =="
if [ -r /proc/net/nf_conntrack ]; then
  conntrack_matches=0
  while IFS= read -r remote_ip; do
    [ -n "$remote_ip" ] || continue
    if grep "src=$CLIENT_IP " /proc/net/nf_conntrack |
       grep ' udp ' |
       grep -F "dst=$remote_ip "; then
      conntrack_matches=1
    fi
  done < "$TMP_DIR/remote-ips.txt"
  [ "$conntrack_matches" -eq 1 ] || echo "No current UDP conntrack entries for detected endpoints."
else
  echo "/proc/net/nf_conntrack is unavailable."
fi

echo
echo "== NFQUEUE UDP counters before =="
cat "$TMP_DIR/nfqueue-before.txt"
echo
echo "== NFQUEUE UDP counters after =="
cat "$TMP_DIR/nfqueue-after.txt"

echo
echo "Interpretation:"
echo "- A discord.media endpoint on LAN confirms the Desktop voice target and port."
echo "- The same endpoint on WAN confirms direct routing instead of the VPN."
echo "- Replies on LAN confirm return traffic reaches the Desktop client."
echo "- NFQUEUE counters should grow on a fresh reconnect; reconnect again if the flow already existed."

# The busiest public voice endpoint that also answered, on the ports every
# autotune Voice candidate processes (19294-19344, 50000-50100). The
# autotuner remembers it after a confirmed session to probe it later.
awk -v client="$CLIENT_IP" '
  function public(ip) {
    return ip !~ /^(10|127)\./ && ip !~ /^192\.168\./ &&
      ip !~ /^172\.(1[6-9]|2[0-9]|3[01])\./ && ip !~ /^(22[4-9]|23[0-9]|24[0-9]|25[0-5])\./ &&
      ip !~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./ && ip !~ /^(0|169\.254)\./
  }
  function voice_port(port) {
    return (port >= 19294 && port <= 19344) || (port >= 50000 && port <= 50100)
  }
  function split_endpoint(value,    parts, count, port, ip, i) {
    sub(/:$/, "", value)
    count = split(value, parts, ".")
    if (count != 5) return ""
    port = parts[5] + 0
    ip = parts[1] "." parts[2] "." parts[3] "." parts[4]
    if (!public(ip) || !voice_port(port)) return ""
    return ip "|" port
  }
  $2 == "IP" && index($3, client ".") == 1 && $4 == ">" {
    key = split_endpoint($5)
    if (key != "") out[key]++
  }
  $2 == "IP" && index($5, client ".") == 1 {
    key = split_endpoint($3)
    if (key != "") back[key]++
  }
  END {
    best = ""
    for (key in out) {
      if (!(key in back)) continue
      if (best == "" || out[key] > out[best]) best = key
    }
    if (best != "") print "EVENT|VOICE_ENDPOINT|" best "|" out[best] "|" back[best]
  }
' "$TMP_DIR/lan.txt"

voice_out="$(awk -v c="$CLIENT_IP." '$2 == "IP" && index($3,c)==1 {n++} END {print n+0}' "$TMP_DIR/lan.txt")"
voice_in="$(awk -v c="$CLIENT_IP." '$2 == "IP" && index($5,c)==1 {n++} END {print n+0}' "$TMP_DIR/lan.txt")"
printf 'EVENT|VOICE_OBSERVATION|%s|%s|%s\n' "$voice_out" "$voice_in" "$wan_matches"
