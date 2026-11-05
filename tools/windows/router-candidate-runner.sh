#!/bin/sh
set -u

# This script is rendered and streamed by zapret_tuner.py. It only changes the
# running nfqws2 process and temporary firewall rules. The active configuration
# file is never edited. The original service is restored by the EXIT, signal
# and SIGPIPE traps (the reader of stdout going away is the usual way an SSH
# or panel session ends).

SERVICE="@@SERVICE@@"
CLIENT_IP="@@CLIENT_IP@@"
VOICE_DURATION="@@VOICE_DURATION@@"
HTTP_TIMEOUT="@@HTTP_TIMEOUT@@"
MIN_HTTP_SUCCESS="@@MIN_HTTP_SUCCESS@@"
# Discord Voice auto check: "IPv4:port" of a voice server learned from a
# confirmed session, or empty for manual checks only.
VOICE_TARGET="@@VOICE_TARGET@@"
# Discord Voice traffic check: "1" judges each candidate by the client's own
# voice traffic (the user stays in a voice channel; Discord reconnects by
# itself while voice fails), "0" otherwise.
VOICE_TRAFFIC="@@VOICE_TRAFFIC@@"
TEST_ROOT="${KD_TUNER_TEST_ROOT:-}"

root_path() {
  printf '%s%s\n' "$TEST_ROOT" "$1"
}

NFQWS_INIT="$(root_path /opt/etc/init.d/S51nfqws2)"
NFQWS_CONF="$(root_path /opt/etc/nfqws2/nfqws2.conf)"
NFQWS_BIN="$(root_path /opt/usr/bin/nfqws2)"
PROJECT_ROOT="$(root_path /opt/root/keenetic-discord-nfqws2)"
VOICE_DIAGNOSTIC="$PROJECT_ROOT/scripts/diagnose-discord-voice.sh"
VOICE_PROBE="$PROJECT_ROOT/tools/router/discord_voice_probe.py"
QUIC_PROBE="$PROJECT_ROOT/tools/router/quic_probe.py"
WS_PROBE="$PROJECT_ROOT/tools/router/discord_ws_probe.py"
PROJECT_DISCORD_UDP_BLOB="$PROJECT_ROOT/config/blobs/ACTIVE_DISCORD_UDP.bin"
INSTALLED_DISCORD_UDP_BLOB="$(root_path /opt/etc/nfqws2/blobs/discord_udp.bin)"
LOCK_DIR="$(root_path /opt/tmp/keenetic-discord-nfqws2.lock)"
VOICE_MODE="manual"
NFQWS_PIDFILE="$(root_path /opt/var/run/nfqws2.pid)"
# The job and the engine find a run that was killed by this directory name
# and its runtime.state (candidate PID, whether nfqws2 was running).
TMP_ROOT="$(root_path /opt/tmp/zapret-tuner.$$)"
CANDIDATE_FILE="$TMP_ROOT/candidates.txt"
CANDIDATE_LOG="$TMP_ROOT/candidate.log"
PROBE_BODY="$TMP_ROOT/probe-body"
PROBE_ERROR="$TMP_ROOT/probe-error"
RUNTIME_STATE="$TMP_ROOT/runtime.state"
VOLUME_FILE="$TMP_ROOT/volume.bin"
QUIC_TARGETS="$TMP_ROOT/quic-targets"
RUNNER_DISCORD_UDP_BLOB="$TMP_ROOT/discord_udp.bin"
VERDICT_FILE="${TUNER_VERDICT_FILE:-}"
VERDICT_TIMEOUT="${TUNER_VERDICT_TIMEOUT:-300}"
# nfqws2-keenetic 1.3.2 waits up to 5 s for the pidfile inside "start" and
# returns 1 without it, skipping the firewall rules; this wait lets a late
# daemon appear, and the rules are checked after it.
RESTORE_WAIT="${KD_TUNER_RESTORE_WAIT:-15}"
# Pages smaller than this are checked for a volume freeze with an upload.
VOLUME_SMALL=24576
QUIC_HOSTS="www.youtube.com redirector.googlevideo.com"
QUIC_GATE=off
CANDIDATE_PID=""
WAS_RUNNING=0
RESTORED=0
RUNTIME_PREPARED=0
LOCK_OWNED=0
TUNER_TCP_PORTS=""
TUNER_UDP_PORTS=""
DISCORD_UDP_BLOB_ARG=""

emit() {
  printf 'EVENT|%s\n' "$1"
}

write_runtime_state() {
  [ -d "$TMP_ROOT" ] || return 0
  printf 'runner_pid=%s\ncandidate_pid=%s\nwas_running=%s\nprepared=%s\n' \
    "$$" "$CANDIDATE_PID" "$WAS_RUNNING" "$RUNTIME_PREPARED" > "$RUNTIME_STATE.tmp" &&
    mv -f "$RUNTIME_STATE.tmp" "$RUNTIME_STATE"
}

stop_candidate() {
  if [ -n "$CANDIDATE_PID" ]; then
    kill -15 "$CANDIDATE_PID" >/dev/null 2>&1 || true
    wait "$CANDIDATE_PID" 2>/dev/null || true
    CANDIDATE_PID=""
    write_runtime_state
  fi
}

release_project_lock() {
  if [ "$LOCK_OWNED" -eq 1 ]; then
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    LOCK_OWNED=0
  fi
}

# The same mkdir lock as apply-discord-nfqws2.sh and zapret_autotune_job.py.
# The router job already holds it and passes its PID in KD_TUNER_LOCK_HELD.
# A lock without a valid pid may be one that is being taken this very moment
# (mkdir and the pid write are two steps): it is waited out for
# KD_LOCK_PID_WAIT seconds (default 2) before it counts as stale.
acquire_project_lock() {
  if [ -n "${KD_TUNER_LOCK_HELD:-}" ]; then
    held_pid="$(sed -n '1p' "$LOCK_DIR/pid" 2>/dev/null)"
    [ "$held_pid" = "$KD_TUNER_LOCK_HELD" ] && kill -0 "$held_pid" 2>/dev/null
    return
  fi
  mkdir -p "$(root_path /opt/tmp)"
  lock_wait="${KD_LOCK_PID_WAIT:-2}"
  case "$lock_wait" in
    ''|*[!0-9]*) lock_wait=2 ;;
  esac
  lock_waited=0
  lock_attempts=0
  while :; do
    if mkdir "$LOCK_DIR" 2>/dev/null; then
      printf '%s\n' "$$" > "$LOCK_DIR/pid"
      LOCK_OWNED=1
      return 0
    fi

    lock_pid="$(sed -n '1p' "$LOCK_DIR/pid" 2>/dev/null)"
    case "$lock_pid" in
      ''|*[!0-9]*)
        if [ -d "$LOCK_DIR" ]; then
          [ "$lock_waited" -lt "$lock_wait" ] || break
          lock_waited=$((lock_waited + 1))
          sleep 1
        else
          lock_attempts=$((lock_attempts + 1))
          [ "$lock_attempts" -lt 20 ] || return 1
        fi
        ;;
      *)
        if kill -0 "$lock_pid" 2>/dev/null; then return 1; fi
        break
        ;;
    esac
  done

  rm -f "$LOCK_DIR/pid"
  # The pid.tmp-N that kdn/common/lock.py leaves for the moment of its own step belongs to
  # a dead process here; one of a live process keeps the directory (it is not stale).
  for lock_leftover in "$LOCK_DIR"/pid.tmp-*; do
    [ -e "$lock_leftover" ] || continue
    lock_writer="${lock_leftover##*-}"
    case "$lock_writer" in
      ''|*[!0-9]*) continue ;;
    esac
    kill -0 "$lock_writer" 2>/dev/null || rm -f "$lock_leftover"
  done
  rmdir "$LOCK_DIR" 2>/dev/null || return 1
  mkdir "$LOCK_DIR" 2>/dev/null || return 1
  printf '%s\n' "$$" > "$LOCK_DIR/pid"
  LOCK_OWNED=1
}

cleanup_tmp() {
  rm -f "$CANDIDATE_FILE" "$CANDIDATE_LOG" "$PROBE_BODY" "$PROBE_ERROR" \
    "$RUNTIME_STATE" "$RUNTIME_STATE.tmp" "$VOLUME_FILE" "$QUIC_TARGETS" \
    "$QUIC_TARGETS.tmp" "$RUNNER_DISCORD_UDP_BLOB" "$TMP_ROOT/voice-traffic.txt"
  rmdir "$TMP_ROOT" 2>/dev/null || true
}

wait_service_running() {
  restore_waited=0
  while ! is_running >/dev/null 2>&1; do
    [ "$restore_waited" -lt "$RESTORE_WAIT" ] || return 1
    sleep 1
    restore_waited=$((restore_waited + 1))
  done
  return 0
}

restore_service() {
  [ "$RESTORED" -eq 0 ] || return 0
  RESTORED=1
  # Stop sends SIGTERM to the process group and the job terminates the runner
  # too. A second signal here would re-enter the trap, which returns at once
  # and exits before nfqws2 is started again; ignore signals until restored.
  # With PIPE ignored, emits to a vanished reader fail with EPIPE instead of
  # killing the shell before nfqws2 is started.
  trap '' HUP INT TERM PIPE
  if [ "$RUNTIME_PREPARED" -eq 1 ]; then
    stop_candidate
    firewall_stop >/dev/null 2>&1 || true
    rm -f "$NFQWS_PIDFILE"
    if [ "$WAS_RUNNING" -eq 1 ]; then
      # The 1.3.2 "start" waits 5 s for the pidfile and, when it is late,
      # returns 1 before firewall_iptables: the daemon then runs with no
      # NFQUEUE rules. Wait for the daemon, then check the rules and install
      # them again when they are missing.
      "$NFQWS_INIT" start >/dev/null 2>&1 || true
      if ! wait_service_running; then
        emit "RESTORE_ERROR|nfqws2-start-failed"
      else
        firewall_present || { firewall_iptables; firewall_ip6tables; } >/dev/null 2>&1
        if firewall_present; then
          emit "RESTORED|running"
        else
          emit "RESTORE_ERROR|nfqws2-firewall-missing"
        fi
      fi
    else
      emit "RESTORED|stopped"
    fi
  fi
  cleanup_tmp
  release_project_lock
}

PYTHONPATH="$PROJECT_ROOT/tools/router" python3 -m kdn.common.xkeen --require >/dev/null || {
  emit "FATAL|unsupported-xkeen"
  exit 2
}

trap restore_service 0
trap 'restore_service; exit 130' HUP INT TERM
trap 'restore_service; exit 141' PIPE

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

for required in sh awk grep base64 curl iptables iptables-save jq od; do
  command -v "$required" >/dev/null 2>&1 || {
    emit "FATAL|missing-command:$required"
    exit 1
  }
done

acquire_project_lock || {
  emit "FATAL|project-busy"
  exit 1
}

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
IPT_POST="${IPT_GROUP_POST:-nfqws_post}"
IPT_PRE="${IPT_GROUP_PRE:-nfqws_pre}"
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
write_runtime_state
cat > "$CANDIDATE_FILE" <<'CANDIDATES'
@@CANDIDATE_DATA@@
CANDIDATES

if [ "$SERVICE" = discord-voice ]; then
  # The configured Voice range ("# Discord UDP: ..., range=wide|narrow.").
  udp_range="$(sed -n 's/^# Discord UDP: strategy=[a-z]*, range=\([a-z]*\)\.$/\1/p' "$NFQWS_CONF" | sed -n '1p')"
  emit "UDP_RANGE|${udp_range:-unknown}"
  # Every candidate uses fake:blob=discord_udp. Under --udp-strategy legacy
  # the engine registers no such blob and deletes discord_udp.bin, and an
  # unregistered blob only fails at packet time (no fake is ever sent).
  case "${NFQWS_BASE_ARGS:-}" in
    *--blob=discord_udp:*) ;;
    *)
      if [ -f "$INSTALLED_DISCORD_UDP_BLOB" ]; then
        DISCORD_UDP_BLOB_ARG="--blob=discord_udp:@$INSTALLED_DISCORD_UDP_BLOB"
      elif [ -f "$PROJECT_DISCORD_UDP_BLOB" ] && cp "$PROJECT_DISCORD_UDP_BLOB" "$RUNNER_DISCORD_UDP_BLOB"; then
        DISCORD_UDP_BLOB_ARG="--blob=discord_udp:@$RUNNER_DISCORD_UDP_BLOB"
      else
        emit "FATAL|discord-udp-blob-missing"
        exit 1
      fi
      emit "VOICE_BLOB|added|${DISCORD_UDP_BLOB_ARG#--blob=discord_udp:@}"
      ;;
  esac
fi

validate_candidate_args() {
  # Same token/function bounds as tuner/panel/FORMAT1. Data only: never eval.
  printf '%s\n' "$1" | awk '
    BEGIN {ok=1; count=0}
    {for(i=1;i<=NF;i++) {
      t=$i; count++
      if(t=="--new") continue
      if(length(t)>600 || t !~ /^--[a-z0-9-]+=[A-Za-z0-9_@\/.,:+<>=!-]+$/) {ok=0; continue}
      n=t; sub(/^--/,"",n); sub(/=.*/,"",n)
      if(n !~ /^(filter-tcp|filter-udp|filter-l7|hostlist|out-range|payload|lua-desync)$/) ok=0
      if(n=="lua-desync") {
        v=t; sub(/^--lua-desync=/,"",v); size=split(v,p,":")
        if(p[1] !~ /^(fake|multisplit|multidisorder|multidisorder_legacy|fakedsplit|hostfakesplit)$/) ok=0
        for(j=2;j<=size;j++) if(p[j] ~ /^ip_id=/ && p[j] !~ /^ip_id=(zero|seq|rnd)$/) ok=0
      }
    }}
    END {exit !(ok && count>=1 && count<=40)}'
}

start_candidate() {
  encoded_args="$1"
  candidate_args="$(printf '%s' "$encoded_args" | base64 -d)"
  validate_candidate_args "$candidate_args" || {
    emit "START_FAILED|unsafe-candidate-args"
    return 1
  }
  rm -f "$CANDIDATE_LOG"

  # candidate_args is generated from an allowlisted token model. Shell control
  # characters from downloaded BAT files never reach this command.
  runtime_args="$(candidate_runtime_args)" || return 1
  # shellcheck disable=SC2086 # the argument list is split on purpose
  $NFQWS_BIN $runtime_args >"$CANDIDATE_LOG" 2>&1 &
  CANDIDATE_PID=$!
  # Recorded before anything else can fail: a job that has to SIGKILL this
  # runner kills the candidate by this PID.
  write_runtime_state
  sleep 1

  if ! kill -0 "$CANDIDATE_PID" >/dev/null 2>&1; then
    emit "START_FAILED|$(tail -n 1 "$CANDIDATE_LOG" | tr '|' '/')"
    CANDIDATE_PID=""
    write_runtime_state
    return 1
  fi
  return 0
}

# Prints NFQWS_ARGS_CUSTOM without the profiles (parts between --new) that
# contain one of the tokens given as arguments: those of the tested service.
custom_without() {
  printf '%s\n' "${NFQWS_ARGS_CUSTOM:-}" | awk -v markers="$*" '
    BEGIN { count = split(markers, list, " "); for (i = 1; i <= count; i++) mark[list[i]] = 1 }
    function flush() {
      if (part != "" && !hit) {out=out (out!=""?" --new ":"") part}
      part=""; hit=0
    }
    {for(i=1;i<=NF;i++) {
      if($i=="--new") flush()
      else {part=part (part!=""?" ":"") $i; if($i in mark) hit=1}
    }}
    END {flush(); print out}'
}

candidate_runtime_args() (
  # Subshell prevents one candidate from becoming the base for the next.
  # The NFQWS_ARGS* variables are read by the sourced _startup_args.
  # shellcheck disable=SC2034
  case "$SERVICE" in
    discord-voice)
      NFQWS_ARGS_UDP="$candidate_args"
      [ -z "$DISCORD_UDP_BLOB_ARG" ] || NFQWS_BASE_ARGS="${NFQWS_BASE_ARGS:-} $DISCORD_UDP_BLOB_ARG"
      ;;
    discord-tcp) NFQWS_ARGS="$candidate_args" ;;
    youtube)
      preserved_custom="$(custom_without --hostlist=/opt/etc/nfqws2/lists/youtube.list)"
      NFQWS_ARGS_CUSTOM="$candidate_args"
      [ -z "$preserved_custom" ] || NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM --new $preserved_custom"
      ;;
  esac
  _startup_args
)

# Keenetic rebuilds its iptables (interface, policy or firewall changes) and
# drops the nfqws_post/nfqws_pre jumps; nothing restores them while the
# official pidfile is gone. Without them a candidate is never applied.
firewall_present() {
  iptables -w -t mangle -C POSTROUTING -j "$IPT_POST" >/dev/null 2>&1 &&
    iptables -w -t mangle -C PREROUTING -j "$IPT_PRE" >/dev/null 2>&1 &&
    iptables -w -t mangle -S "$IPT_POST" 2>/dev/null | grep -q -- '-j NFQUEUE'
}

# The 1.3.2 firewall_iptables returns 1 when any rule fails, and Keenetic can
# fail one while it rebuilds its firewall. Retry as the package's netfilter
# hook does (5 x 1 s) before giving up.
install_temporary_firewall() {
  firewall_attempt=1
  while ! firewall_iptables >/dev/null 2>&1; do
    if [ "$firewall_attempt" -ge 5 ]; then
      emit "FATAL|cannot-install-temporary-firewall"
      exit 1
    fi
    firewall_attempt=$((firewall_attempt + 1))
    sleep "${KD_FIREWALL_RETRY_DELAY:-1}"
  done
}

ensure_firewall() {
  firewall_present && return 0
  emit "FIREWALL_REASSERT|$1|missing"
  install_temporary_firewall
  if firewall_present; then
    emit "FIREWALL_REASSERT|$1|restored"
    return 0
  fi
  return 1
}

is_positive() {
  awk -v value="${1:-0}" 'BEGIN { exit !(value + 0 > 0) }'
}

with_cache_buster() {
  case "$1" in
    *\?*) printf '%s&t=%s\n' "$1" "$2" ;;
    *) printf '%s?t=%s\n' "$1" "$2" ;;
  esac
}

# A small page proves nothing about a volume freeze (TLS stalls after
# 16-20 KB): upload 64 KB in a new connection. Freeze = timeout after TLS.
volume_probe() {
  volume_url="$(with_cache_buster "$probe_url" "$$$candidate_number$probe_round")"
  volume_raw="$(
    curl -4 --http1.1 --proxy '' --noproxy '*' \
      --connect-timeout "$HTTP_TIMEOUT" --max-time "$HTTP_TIMEOUT" \
      -sS -o /dev/null -H 'Expect:' -H 'Content-Type: application/octet-stream' \
      --data-binary "@$VOLUME_FILE" -w '%{http_code}|%{time_appconnect}' \
      "$volume_url" 2>/dev/null
  )"
  volume_rc=$?
  volume_code="${volume_raw%%|*}"
  volume_appconnect="${volume_raw#*|}"
  [ "$volume_appconnect" != "$volume_raw" ] || volume_appconnect=0
  volume_result=ok
  if [ "$volume_rc" -eq 28 ] && is_positive "$volume_appconnect"; then
    volume_result=freeze
  elif [ "$volume_rc" -ne 0 ]; then
    volume_result=error
  fi
  emit "PROBE_VOLUME|$candidate_number|$probe_phase|$probe_round|$probe_role|${volume_code:-000}|$volume_rc|$volume_appconnect|$volume_result|$probe_url"
  [ "$volume_result" != freeze ]
}

http_probe() {
  probe_url="$1"
  probe_role="$2"
  case "$probe_role" in
    # Read up to 64 KB of the page: a HEAD request never meets a volume freeze.
    web|transport) set -- -r 0-65535 --max-filesize 4194304 ;;
    *) set -- --max-filesize 262144 ;;
  esac
  probe_raw="$(
    curl -4 "$@" --http1.1 --proxy '' --noproxy '*' \
      --connect-timeout "$HTTP_TIMEOUT" \
      --max-time "$HTTP_TIMEOUT" \
      -sS -o "$PROBE_BODY" \
      -w '%{http_code}|%{time_total}|%{size_download}|%{time_connect}|%{time_appconnect}' \
      "$probe_url" 2>"$PROBE_ERROR"
  )"
  probe_rc=$?
  case "$probe_rc" in
    126|127)
      emit "FATAL|curl-broken:$probe_rc"
      exit 1
      ;;
  esac
  probe_code="${probe_raw%%|*}"
  probe_rest="${probe_raw#*|}"
  probe_time="${probe_rest%%|*}"
  probe_rest="${probe_rest#*|}"
  probe_size="${probe_rest%%|*}"
  probe_rest="${probe_rest#*|}"
  probe_connect="${probe_rest%%|*}"
  probe_appconnect="${probe_rest#*|}"
  [ -n "$probe_code" ] || probe_code=000
  probe_metrics="$probe_code|${probe_time:-0}|${probe_size:-0}"
  probe_connected=0
  ! is_positive "$probe_connect" || probe_connected=1
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
  else
    # curl exit codes: 6 DNS, 7 connect, 28 timeout (before connect),
    # stall (TLS never completed) or freeze (data stopped after TLS),
    # 35 TLS alert/reset, 52 empty reply, 56 reset while receiving.
    case "$probe_rc" in
      6) probe_status=dns-error ;;
      7) probe_status=connect-error ;;
      28)
        if [ "$probe_connected" -eq 0 ]; then
          probe_status=timeout
        elif is_positive "$probe_appconnect"; then
          probe_status=freeze
        else
          probe_status=stall
        fi ;;
      35) probe_status=tls-error ;;
      52) probe_status=empty-reply ;;
      56) probe_status=reset ;;
      *) probe_status=network-error ;;
    esac
  fi
  emit "PROBE|$candidate_number|$probe_code|$probe_url"
  if [ "$probe_status" = ok ]; then
    case "$probe_role" in
      web|transport)
        if [ "${probe_size%%.*}" -lt "$VOLUME_SMALL" ] 2>/dev/null && ! volume_probe; then
          probe_status=freeze
        fi ;;
    esac
  fi
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
  suite_connected=0
  suite_dns_failed=0

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
      required_failed=1
    fi
    [ "$probe_connected" -eq 0 ] || suite_connected=$((suite_connected + 1))
    [ "$probe_rc" -ne 6 ] || suite_dns_failed=$((suite_dns_failed + 1))
  done
  IFS="$old_ifs"

  if [ "$SERVICE" = discord-tcp ]; then
    [ -f "$WS_PROBE" ] && command -v python3 >/dev/null 2>&1 || {
      emit "FATAL|discord-ws-probe-unavailable"
      exit 1
    }
    total=$((total + 1))
    ws_line="$(python3 "$WS_PROBE" --timeout "$HTTP_TIMEOUT" --label "$probe_phase-$candidate_number" </dev/null 2>/dev/null)"
    ws_rc=$?
    case "$ws_line" in
      EVENT\|WS\|ok\|*)
        [ "$ws_rc" -eq 0 ] || { emit "FATAL|discord-ws-probe-invalid"; exit 1; }
        successes=$((successes + 1))
        suite_connected=$((suite_connected + 1)) ;;
      EVENT\|WS\|fail\|*)
        [ "$ws_rc" -eq 1 ] || { emit "FATAL|discord-ws-probe-invalid"; exit 1; }
        required_failed=1 ;;
      *)
        emit "FATAL|discord-ws-probe-unavailable"
        exit 1 ;;
    esac
    emit "WS_RESULT|$candidate_number|$probe_phase|$probe_round|${ws_line#EVENT|WS|}"
  fi

  emit "HTTP_RESULT|$candidate_number|$successes|$total"
  if [ "$successes" -ge "$MIN_HTTP_SUCCESS" ] && [ "$required_failed" -eq 0 ]; then
    emit "SUITE_RESULT|$candidate_number|$probe_phase|$probe_round|pass|$successes|$total"
    return 0
  fi
  emit "SUITE_RESULT|$candidate_number|$probe_phase|$probe_round|fail|$successes|$total"
  return 1
}

# Runs quic_probe.py and passes its EVENT|QUIC line through. Sets
# quic_status and quic_seen_ip; succeeds when the host answered.
quic_probe_host() {
  quic_label="$1"
  quic_host="$2"
  quic_ip="$3"
  if [ -n "$quic_ip" ]; then
    set -- --ip "$quic_ip"
  else
    set --
  fi
  quic_line="$(python3 "$QUIC_PROBE" "$quic_host" "$@" --tries 3 --label "$quic_label" </dev/null 2>/dev/null | tail -n 1)"
  case "$quic_line" in
    EVENT\|QUIC\|*) ;;
    *) quic_line="EVENT|QUIC|$quic_label|$quic_host|${quic_ip:--}|build-error|-" ;;
  esac
  printf '%s\n' "$quic_line"
  quic_status="$(printf '%s\n' "$quic_line" | cut -d'|' -f6)"
  quic_seen_ip="$(printf '%s\n' "$quic_line" | cut -d'|' -f5)"
  [ "$quic_status" = ok ]
}

# Baseline QUIC probes: "active" with the running profile, then "raw" with no
# bypass at all. A host whose QUIC answered in either one must keep
# answering with every candidate. QUIC_TARGETS lines: host ip active raw.
quic_baseline() {
  quic_phase="$1"
  : > "$QUIC_TARGETS.tmp"
  if [ "$quic_phase" = active ]; then
    for quic_target_host in $QUIC_HOSTS; do
      quic_answer=0
      ! quic_probe_host active "$quic_target_host" "" || quic_answer=1
      printf '%s %s %s 0\n' "$quic_target_host" "${quic_seen_ip:--}" "$quic_answer" >> "$QUIC_TARGETS.tmp"
    done
  else
    while read -r quic_target_host quic_target_ip quic_active _; do
      [ "$quic_target_ip" != - ] || quic_target_ip=""
      quic_answer=0
      ! quic_probe_host raw "$quic_target_host" "$quic_target_ip" || quic_answer=1
      [ -n "$quic_target_ip" ] || quic_target_ip="${quic_seen_ip:--}"
      printf '%s %s %s %s\n' "$quic_target_host" "$quic_target_ip" "$quic_active" "$quic_answer" >> "$QUIC_TARGETS.tmp"
    done < "$QUIC_TARGETS"
  fi
  mv -f "$QUIC_TARGETS.tmp" "$QUIC_TARGETS"
}

quic_gate() {
  if [ ! -f "$QUIC_PROBE" ] || ! command -v python3 >/dev/null 2>&1; then
    emit "QUIC_GATE|off|probe-unavailable"
    return 0
  fi
  if grep -q ' 1$' "$QUIC_TARGETS"; then
    QUIC_GATE=on
    emit "QUIC_GATE|on|raw-reply"
  elif grep -q ' 1 0$' "$QUIC_TARGETS"; then
    QUIC_GATE=on
    emit "QUIC_GATE|on|active-reply"
  else
    emit "QUIC_GATE|off|no-reply"
  fi
}

test_quic_candidate() {
  candidate_number="$1"
  if [ "$QUIC_GATE" != on ]; then
    emit "QUIC_RESULT|$candidate_number|skipped|0|0"
    return 0
  fi
  quic_ok=0
  quic_total=0
  while read -r quic_target_host quic_target_ip quic_active quic_raw; do
    [ "$quic_active" = 1 ] || [ "$quic_raw" = 1 ] || continue
    [ "$quic_target_ip" != - ] || quic_target_ip=""
    quic_total=$((quic_total + 1))
    ! quic_probe_host "candidate-$candidate_number" "$quic_target_host" "$quic_target_ip" ||
      quic_ok=$((quic_ok + 1))
  done < "$QUIC_TARGETS"
  if [ "$quic_ok" -eq "$quic_total" ]; then
    emit "QUIC_RESULT|$candidate_number|pass|$quic_ok|$quic_total"
    return 0
  fi
  emit "QUIC_RESULT|$candidate_number|fail|$quic_ok|$quic_total"
  return 1
}

# Sends Discord IP Discovery requests to VOICE_TARGET from the router and
# prints EVENT|VOICE_PROBE|label|sent|received|valid. Succeeds on a valid reply.
voice_probe() {
  voice_probe_label="$1"
  python3 "$VOICE_PROBE" "${VOICE_TARGET%:*}" "${VOICE_TARGET##*:}" \
    --label "$voice_probe_label" </dev/null 2>/dev/null
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

# Watches the client's voice traffic for VOICE_DURATION seconds with the
# current nfqws2 process and prints the diagnostic's verdict on its last line:
# connected | established | attempts | idle | unavailable.
voice_traffic_window() {
  voice_traffic_output="$TMP_ROOT/voice-traffic.txt"
  if [ -f "$VOICE_DIAGNOSTIC" ]; then
    sh "$VOICE_DIAGNOSTIC" "$CLIENT_IP" "$VOICE_DURATION" > "$voice_traffic_output" 2>&1 || true
  else
    emit "VOICE_DIAGNOSTIC_MISSING|$VOICE_DIAGNOSTIC" > "$voice_traffic_output"
  fi
  cat "$voice_traffic_output"
  voice_traffic_state="$(sed -n 's/^EVENT|VOICE_TRAFFIC|//p' "$voice_traffic_output" | tail -n 1)"
  rm -f "$voice_traffic_output"
  [ -n "$voice_traffic_state" ] || voice_traffic_state=unavailable
}

test_voice_candidate() {
  candidate_number="$1"
  if [ "$VOICE_TRAFFIC" = 1 ]; then
    # No reconnect needed: Discord keeps reconnecting while voice fails, and
    # every attempt goes through this candidate.
    emit "VOICE_WATCH|$candidate_number|$VOICE_DURATION"
    voice_traffic_window
    emit "VOICE_TRAFFIC_RESULT|$candidate_number|$voice_traffic_state"
    [ "$voice_traffic_state" = connected ] || return 1
    emit "VOICE_VERDICT|$candidate_number"
    wait_voice_verdict
    case "$verdict" in
      y|Y|yes|YES|да|ДА) return 0 ;;
      timeout)
        emit "VOICE_UNCONFIRMED|$candidate_number"
        return 0
        ;;
    esac
    return 1
  fi
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
  if [ -f "$VOICE_DIAGNOSTIC" ]; then
    sh "$VOICE_DIAGNOSTIC" "$CLIENT_IP" "$VOICE_DURATION" </dev/null || true
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
  # 64 KB of random data for the upload volume check.
  head -c 65536 /dev/urandom > "$VOLUME_FILE" 2>/dev/null ||
    dd if=/dev/urandom of="$VOLUME_FILE" bs=1024 count=64 2>/dev/null || true
  baseline_pass=0
  test_http_candidate 0 baseline 1 && baseline_pass=1
  if [ "$SERVICE" = youtube ]; then
    if [ -f "$QUIC_PROBE" ] && command -v python3 >/dev/null 2>&1; then
      quic_baseline active
      quic_active_count="$(awk '$3 == 1 {n++} END {print n+0}' "$QUIC_TARGETS")"
      emit "QUIC_BASELINE|active|$quic_active_count|2"
    else
      : > "$QUIC_TARGETS"
      emit "QUIC_BASELINE|unavailable|0|2"
    fi
  fi
  if [ "${KD_TUNER_BASELINE_ONLY:-0}" = 1 ]; then
    # Check the live profile twice, without stopping nfqws2 or touching firewall.
    confirm_pass=0
    test_http_candidate 0 confirm 2 && confirm_pass=1
    if [ "$baseline_pass" -eq 1 ] && [ "$confirm_pass" -eq 1 ]; then
      emit "BASELINE_ONLY|pass"
    elif [ "$baseline_pass" -eq 0 ] && [ "$confirm_pass" -eq 0 ]; then
      emit "BASELINE_ONLY|fail"
    else
      emit "BASELINE_ONLY|unstable"
    fi
    exit 0
  fi
fi

if [ "$SERVICE" = discord-voice ] && [ -n "$VOICE_TARGET" ]; then
  # Calibration 1: the strategy that is active right now.
  voice_probe active || true
fi
if [ "$SERVICE" = discord-voice ] && [ "$VOICE_TRAFFIC" = 1 ]; then
  # Baseline: the client's voice traffic with the active strategy. "idle"
  # means Discord is not in a voice channel; "connected"/"established" means
  # voice already works and new candidates will see no new attempts.
  emit "VOICE_WATCH|0|$VOICE_DURATION"
  voice_traffic_window
  emit "VOICE_TRAFFIC_RESULT|0|$voice_traffic_state"
fi

RUNTIME_PREPARED=1
write_runtime_state
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

if [ "$SERVICE" != discord-voice ]; then
  # Raw baseline: nfqws2 and its rules are gone, nothing is desynced.
  if test_http_candidate 0 raw 1; then
    # Everything opens without a bypass: the network does not discriminate,
    # so any candidate would pass.
    emit "RAW_BASELINE|pass|$successes|$total"
  elif [ "$suite_connected" -eq 0 ] && [ "$suite_dns_failed" -eq "$total" ]; then
    emit "RAW_BASELINE|dns-error|$successes|$total"
    emit "NONE"
    exit 0
  elif [ "$suite_connected" -eq 0 ]; then
    # No raw TCP connection succeeded. This is inconclusive: try candidates.
    emit "RAW_BASELINE|tcp-unreachable|$successes|$total"
  else
    emit "RAW_BASELINE|fail|$successes|$total"
  fi
fi
if [ "$SERVICE" = youtube ]; then
  [ ! -s "$QUIC_TARGETS" ] || quic_baseline raw
  quic_gate
fi

install_temporary_firewall

found=0
# Candidates are read on fd 3: stdin stays connected to the Windows tuner,
# which sends each Discord Voice verdict over SSH.
while IFS='|' read -r candidate_number candidate_id encoded_args <&3; do
  [ -n "$candidate_number" ] || continue
  emit "CANDIDATE|$candidate_number|$candidate_id"

  ensure_firewall "$candidate_number" || {
    emit "FATAL|temporary-firewall-lost"
    exit 1
  }

  if ! start_candidate "$encoded_args"; then
    stop_candidate
    continue
  fi

  passed=0
  if [ "$SERVICE" = "discord-voice" ]; then
    if test_voice_candidate "$candidate_number"; then
      passed=1
    fi
  elif test_http_candidate "$candidate_number" candidate 1; then
    if [ "$SERVICE" != youtube ] || test_quic_candidate "$candidate_number"; then
      sleep 1
      if test_http_candidate "$candidate_number" confirm 2; then
        passed=1
      fi
    fi
  fi

  # The result only counts if the candidate was in the path the whole time.
  if ! firewall_present; then
    emit "FIREWALL_LOST|$candidate_number"
    passed=0
  fi

  stop_candidate

  if [ "$passed" -eq 1 ]; then
    found=1
    emit "FOUND|$candidate_number|$candidate_id"
    break
  fi
  sleep 1
done 3< "$CANDIDATE_FILE"

if [ "$found" -eq 0 ]; then
  emit "NONE"
fi

exit 0
