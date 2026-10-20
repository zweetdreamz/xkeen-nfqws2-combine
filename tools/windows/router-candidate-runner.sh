#!/bin/sh
set -u

# This script is rendered and streamed by zapret_tuner.py. It only changes the
# running nfqws2 process and temporary firewall rules. The active configuration
# file is never edited. The original service is restored by the EXIT trap.

SERVICE="@@SERVICE@@"
CLIENT_IP="@@CLIENT_IP@@"
VOICE_DURATION="@@VOICE_DURATION@@"
HTTP_TIMEOUT="@@HTTP_TIMEOUT@@"
MIN_HTTP_SUCCESS="@@MIN_HTTP_SUCCESS@@"
# Discord Voice auto check: "IPv4:port" of a voice server learned from a
# confirmed session, or empty for manual checks only.
VOICE_TARGET="@@VOICE_TARGET@@"
TEST_ROOT="${KD_TUNER_TEST_ROOT:-}"

root_path() {
  printf '%s%s\n' "$TEST_ROOT" "$1"
}

NFQWS_INIT="$(root_path /opt/etc/init.d/S51nfqws2)"
NFQWS_CONF="$(root_path /opt/etc/nfqws2/nfqws2.conf)"
NFQWS_BIN="$(root_path /opt/usr/bin/nfqws2)"
VOICE_DIAGNOSTIC="$(root_path /opt/root/keenetic-discord-nfqws2/scripts/diagnose-discord-voice.sh)"
VOICE_PROBE="$(root_path /opt/root/keenetic-discord-nfqws2/tools/router/discord_voice_probe.py)"
VOICE_MODE="manual"
NFQWS_PIDFILE="$(root_path /opt/var/run/nfqws2.pid)"
TMP_ROOT="$(root_path /opt/tmp/zapret-tuner.$$)"
CANDIDATE_FILE="$TMP_ROOT/candidates.txt"
CANDIDATE_LOG="$TMP_ROOT/candidate.log"
PROBE_BODY="$TMP_ROOT/probe-body"
PROBE_ERROR="$TMP_ROOT/probe-error"
VERDICT_FILE="${TUNER_VERDICT_FILE:-}"
VERDICT_TIMEOUT="${TUNER_VERDICT_TIMEOUT:-300}"
CANDIDATE_PID=""
WAS_RUNNING=0
RESTORED=0
RUNTIME_PREPARED=0
TUNER_TCP_PORTS=""
TUNER_UDP_PORTS=""

emit() {
  printf 'EVENT|%s\n' "$1"
}

stop_candidate() {
  if [ -n "$CANDIDATE_PID" ]; then
    kill -15 "$CANDIDATE_PID" >/dev/null 2>&1 || true
    wait "$CANDIDATE_PID" 2>/dev/null || true
    CANDIDATE_PID=""
  fi
}

restore_service() {
  [ "$RESTORED" -eq 0 ] || return 0
  RESTORED=1
  if [ "$RUNTIME_PREPARED" -eq 0 ]; then
    rm -f "$CANDIDATE_FILE" "$CANDIDATE_LOG" "$PROBE_BODY" "$PROBE_ERROR"
    rmdir "$TMP_ROOT" 2>/dev/null || true
    return 0
  fi
  stop_candidate
  firewall_stop >/dev/null 2>&1 || true
  rm -f "$NFQWS_PIDFILE"
  if [ "$WAS_RUNNING" -eq 1 ]; then
    if "$NFQWS_INIT" start >/dev/null 2>&1 && is_running; then
      emit "RESTORED|running"
    else
      emit "RESTORE_ERROR|nfqws2-start-failed"
    fi
  else
    emit "RESTORED|stopped"
  fi
  rm -f "$CANDIDATE_FILE" "$CANDIDATE_LOG" "$PROBE_BODY" "$PROBE_ERROR"
  rmdir "$TMP_ROOT" 2>/dev/null || true
}

trap restore_service 0
trap 'restore_service; exit 130' HUP INT TERM

case "$SERVICE" in
  youtube)
    TUNER_TCP_PORTS="443"
    ;;
  discord-tcp)
    TUNER_TCP_PORTS="80,443,2053,2083,2087,2096,8443"
    ;;
  discord-voice)
    TUNER_UDP_PORTS="443,3478:3481,5349,19294:19344,50000:50100"
    ;;
  *)
    emit "FATAL|unsupported-service"
    exit 2
    ;;
esac

for required in sh awk grep base64 curl iptables-save jq od; do
  command -v "$required" >/dev/null 2>&1 || {
    emit "FATAL|missing-command:$required"
    exit 1
  }
done

[ -x "$NFQWS_INIT" ] || {
  emit "FATAL|missing-init:$NFQWS_INIT"
  exit 1
}
[ -x "$NFQWS_BIN" ] || {
  emit "FATAL|missing-binary:$NFQWS_BIN"
  exit 1
}
[ -r "$NFQWS_CONF" ] || {
  emit "FATAL|missing-config:$NFQWS_CONF"
  exit 1
}

if [ "$SERVICE" = "discord-tcp" ] || [ "$SERVICE" = "discord-voice" ]; then
  if grep -R -q -i 'zkeenip\.dat:discord' \
       "$(root_path /opt/etc/xray/configs)" 2>/dev/null; then
    emit "FATAL|broad-discord-ip-selector-is-active"
    exit 1
  fi
  if ! grep -R -q '"outboundTag"[[:space:]]*:[[:space:]]*"discord-direct"' \
       "$(root_path /opt/etc/xray/configs)" 2>/dev/null; then
    emit "FATAL|discord-direct-route-is-not-active"
    exit 1
  fi
fi

set -- noop
# shellcheck source=/dev/null # the router's nfqws2 init script
. "$NFQWS_INIT" >/dev/null 2>&1
command -v _startup_args >/dev/null 2>&1 || {
  emit "FATAL|init-does-not-expose-startup-args"
  exit 1
}
# Keep the package's complete effective profile set and both protocol hooks.
# Narrowing these ports during a Voice test used to disconnect Discord TCP.
merge_ports() {
  printf '%s,%s\n' "$1" "$2" | awk -F, '{for(i=1;i<=NF;i++) if($i!=""&&!seen[$i]++){out=out (out?",":"") $i}} END {print out}'
}
TCP_PORTS="$(merge_ports "${TCP_PORTS:-}" "$TUNER_TCP_PORTS")"
UDP_PORTS="$(merge_ports "${UDP_PORTS:-}" "$TUNER_UDP_PORTS")"

if is_running; then
  WAS_RUNNING=1
fi

mkdir "$TMP_ROOT"
cat > "$CANDIDATE_FILE" <<'CANDIDATES'
@@CANDIDATE_DATA@@
CANDIDATES

start_candidate() {
  encoded_args="$1"
  candidate_args="$(printf '%s' "$encoded_args" | base64 -d)"
  rm -f "$CANDIDATE_LOG"

  # candidate_args is generated from an allowlisted token model. Shell control
  # characters from downloaded BAT files never reach this command.
  runtime_args="$(candidate_runtime_args)" || return 1
  $NFQWS_BIN $runtime_args >"$CANDIDATE_LOG" 2>&1 &
  CANDIDATE_PID=$!
  sleep 1

  if ! kill -0 "$CANDIDATE_PID" >/dev/null 2>&1; then
    emit "START_FAILED|$(tail -n 1 "$CANDIDATE_LOG" | tr '|' '/')"
    CANDIDATE_PID=""
    return 1
  fi
  return 0
}

candidate_runtime_args() (
  # Subshell prevents one candidate from becoming the base for the next.
  # The NFQWS_ARGS* variables are read by the sourced _startup_args.
  # shellcheck disable=SC2034
  case "$SERVICE" in
    discord-voice) NFQWS_ARGS_UDP="$candidate_args" ;;
    discord-tcp) NFQWS_ARGS="$candidate_args" ;;
    youtube)
      preserved_custom="$(printf '%s\n' "${NFQWS_ARGS_CUSTOM:-}" | awk '
        function flush() {
          if (part != "" && !youtube) {out=out (out!=""?" --new ":"") part}
          part=""; youtube=0
        }
        {for(i=1;i<=NF;i++) {
          if($i=="--new") flush()
          else {part=part (part!=""?" ":"") $i; if($i=="--hostlist=/opt/etc/nfqws2/lists/youtube.list") youtube=1}
        }}
        END {flush(); print out}' )"
      NFQWS_ARGS_CUSTOM="$candidate_args"
      [ -z "$preserved_custom" ] || NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM --new $preserved_custom"
      ;;
  esac
  _startup_args
)

http_probe() {
  probe_url="$1"
  probe_role="$2"
  case "$probe_role" in
    web|transport) set -- -I ;;
    *) set -- --max-filesize 262144 ;;
  esac
  probe_metrics="$(
    curl -4 "$@" --http1.1 --proxy '' --noproxy '*' \
      --connect-timeout "$HTTP_TIMEOUT" \
      --max-time "$HTTP_TIMEOUT" \
      -sS -o "$PROBE_BODY" -w '%{http_code}|%{time_total}|%{size_download}' \
      "$probe_url" 2>"$PROBE_ERROR"
  )"
  probe_rc=$?
  probe_code="${probe_metrics%%|*}"
  probe_status=network-error
  if [ "$probe_rc" -eq 0 ]; then
    case "$probe_code" in
      2??|3??) probe_status=ok ;;
      *) probe_status=http-error ;;
    esac
    case "$probe_role" in
      transport) [ "$probe_code" = 000 ] || probe_status=ok ;;
      metadata)
        if [ "$probe_code" != 200 ] || ! jq -e 'type == "object" and (.title | type == "string" and length > 0)' "$PROBE_BODY" >/dev/null 2>&1; then
          probe_status=invalid-metadata
        fi ;;
      gateway)
        if [ "$probe_code" != 200 ] || ! jq -e '.url == "wss://gateway.discord.gg"' "$PROBE_BODY" >/dev/null 2>&1; then
          probe_status=invalid-gateway
        fi ;;
      image)
        image_signature="$(od -b "$PROBE_BODY" 2>/dev/null | awk 'NR==1 {print $2 $3 $4; exit}')"
        if [ "$probe_code" != 200 ] || [ "$(wc -c < "$PROBE_BODY")" -lt 256 ]; then
          probe_status=invalid-image
        fi
        case "$image_signature" in 377330377|211120116) ;; *) probe_status=invalid-image ;; esac ;;
    esac
  fi
  emit "PROBE|$candidate_number|$probe_code|$probe_url"
  emit "PROBE_DETAIL|$candidate_number|$probe_phase|$probe_round|$probe_role|$probe_metrics|$probe_rc|$probe_status|$probe_url"
  if [ "$probe_status" != ok ]; then
    emit "PROBE_ERROR|$candidate_number|$(head -c 300 "$PROBE_ERROR" | tr '\n|' ' /')"
  fi
  [ "$probe_status" = ok ]
}

test_http_candidate() {
  candidate_number="$1"
  probe_phase="${2:-candidate}"
  probe_round="${3:-1}"
  successes=0
  total=0
  required_failed=0

  if [ "$SERVICE" = "youtube" ]; then
    targets="web|https://www.youtube.com/
metadata|https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=jNQXAC9IVRw&format=json
image|https://i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg
transport|https://redirector.googlevideo.com/"
  else
    targets="web|https://discord.com/app
gateway|https://discord.com/api/v10/gateway
image|https://cdn.discordapp.com/embed/avatars/0.png"
  fi

  old_ifs="$IFS"
  IFS='
'
  for target in $targets; do
    target_role="${target%%|*}"
    target_url="${target#*|}"
    total=$((total + 1))
    if http_probe "$target_url" "$target_role"; then
      successes=$((successes + 1))
    else
      [ "$target_role" = transport ] || required_failed=1
    fi
  done
  IFS="$old_ifs"

  emit "HTTP_RESULT|$candidate_number|$successes|$total"
  if [ "$successes" -ge "$MIN_HTTP_SUCCESS" ] && [ "$required_failed" -eq 0 ]; then
    emit "SUITE_RESULT|$candidate_number|$probe_phase|$probe_round|pass|$successes|$total"
    return 0
  fi
  emit "SUITE_RESULT|$candidate_number|$probe_phase|$probe_round|fail|$successes|$total"
  return 1
}

# Sends Discord IP Discovery requests to VOICE_TARGET from the router and
# prints EVENT|VOICE_PROBE|label|sent|received|valid. Succeeds on a valid reply.
voice_probe() {
  voice_probe_label="$1"
  python3 "$VOICE_PROBE" "${VOICE_TARGET%:*}" "${VOICE_TARGET##*:}" \
    --label "$voice_probe_label" 2>/dev/null
}

wait_voice_verdict() {
  if [ -n "$VERDICT_FILE" ]; then
    verdict_waited=0
    while [ ! -f "$VERDICT_FILE" ] && [ "$verdict_waited" -lt "$VERDICT_TIMEOUT" ]; do
      sleep 1
      verdict_waited=$((verdict_waited + 1))
    done
    if [ -f "$VERDICT_FILE" ]; then
      verdict="$(sed -n '1p' "$VERDICT_FILE")"
      rm -f "$VERDICT_FILE"
    else
      verdict="timeout"
    fi
  elif IFS= read -r verdict; then
    :
  else
    verdict="timeout"
  fi
}

test_voice_candidate() {
  candidate_number="$1"
  if [ "$VOICE_MODE" = "auto" ]; then
    if ! voice_probe "candidate-$candidate_number"; then
      emit "VOICE_AUTO|$candidate_number|fail"
      return 1
    fi
    # The server answered only with this strategy: ask for a final sound
    # check of this one profile.
    emit "VOICE_AUTO|$candidate_number|pass"
  fi

  emit "VOICE_READY|$candidate_number|$VOICE_DURATION"
  if [ -x "$VOICE_DIAGNOSTIC" ]; then
    sh "$VOICE_DIAGNOSTIC" "$CLIENT_IP" "$VOICE_DURATION" || true
  else
    emit "VOICE_DIAGNOSTIC_MISSING|$VOICE_DIAGNOSTIC"
    sleep "$VOICE_DURATION"
  fi

  emit "VOICE_VERDICT|$candidate_number"
  wait_voice_verdict
  case "$verdict" in
    y|Y|yes|YES|да|ДА) return 0 ;;
    timeout)
      if [ "$VOICE_MODE" = "auto" ]; then
        # Nobody answered: keep the automatically passing profile, unconfirmed.
        emit "VOICE_UNCONFIRMED|$candidate_number"
        return 0
      fi
      ;;
  esac
  return 1
}

emit "SESSION|$SERVICE|runtime-only"

if [ "$SERVICE" != discord-voice ]; then
  emit "BASELINE|started"
  test_http_candidate 0 baseline 1 || true
fi

if [ "$SERVICE" = discord-voice ] && [ -n "$VOICE_TARGET" ]; then
  # Calibration 1: the strategy that is active right now.
  voice_probe active || true
fi

RUNTIME_PREPARED=1
if [ "$WAS_RUNNING" -eq 1 ]; then
  "$NFQWS_INIT" stop >/dev/null 2>&1 || {
    emit "FATAL|cannot-stop-active-nfqws2"
    exit 1
  }
else
  firewall_stop >/dev/null 2>&1 || true
fi
if [ "$SERVICE" = discord-voice ] && [ -n "$VOICE_TARGET" ]; then
  # Calibration 2: nfqws2 and its firewall rules are gone, so this request is
  # not desynced. A reply here means the probe cannot tell strategies apart.
  if voice_probe raw; then
    emit "VOICE_AUTO_MODE|manual|raw-reply"
  else
    VOICE_MODE="auto"
    emit "VOICE_AUTO_MODE|auto|raw-no-reply"
  fi
fi

firewall_iptables >/dev/null 2>&1 || {
  emit "FATAL|cannot-install-temporary-firewall"
  exit 1
}

found=0
# Candidates are read on fd 3: stdin stays connected to the Windows tuner,
# which sends each Discord Voice verdict over SSH.
while IFS='|' read -r candidate_number candidate_id encoded_args <&3; do
  [ -n "$candidate_number" ] || continue
  emit "CANDIDATE|$candidate_number|$candidate_id"

  if ! start_candidate "$encoded_args"; then
    stop_candidate
    continue
  fi

  if [ "$SERVICE" = "discord-voice" ]; then
    if test_voice_candidate "$candidate_number"; then
      found=1
    fi
  elif test_http_candidate "$candidate_number" candidate 1; then
    sleep 1
    if test_http_candidate "$candidate_number" confirm 2; then
      found=1
    fi
  fi

  stop_candidate

  if [ "$found" -eq 1 ]; then
    emit "FOUND|$candidate_number|$candidate_id"
    break
  fi
  sleep 1
done 3< "$CANDIDATE_FILE"

if [ "$found" -eq 0 ]; then
  emit "NONE"
fi

exit 0
