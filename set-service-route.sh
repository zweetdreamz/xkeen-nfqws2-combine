#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ENGINE="$SCRIPT_DIR/apply-discord-nfqws2.sh"

usage() {
  cat <<'EOF'
Usage:
  sh set-service-route.sh discord-tcp   direct|zapret|vpn --yes-router [apply options]
  sh set-service-route.sh discord-voice direct|zapret|vpn --yes-router [apply options]
  sh set-service-route.sh discord       direct|zapret|vpn --yes-router [apply options]
  sh set-service-route.sh youtube       direct|zapret|vpn --yes-router [apply options]

discord-tcp covers Discord domains (TCP/TLS and QUIC), discord-voice covers
Discord Voice/STUN UDP ports, and discord switches both at once.

The routes of the other services and the Discord UDP settings (--wide-udp,
--udp-strategy) are read from the current managed state and preserved; pass
--narrow-udp, --wide-udp or --udp-strategy to change them. "vpn" is a
user-facing alias for the engine route "vless".

Examples:
  sh set-service-route.sh discord-voice zapret --core auto --wan-interface eth3 --yes-router
  sh set-service-route.sh youtube direct --core auto --wan-interface eth3 --yes-router
EOF
}

[ "$#" -ge 2 ] || {
  usage >&2
  exit 2
}

service="$1"
requested_mode="$2"
shift 2

case "$service" in
  discord|discord-tcp|discord-voice|youtube) ;;
  *)
    echo "ERROR: service must be discord-tcp, discord-voice, discord or youtube." >&2
    usage >&2
    exit 2
    ;;
esac

case "$requested_mode" in
  direct|zapret) route_mode="$requested_mode" ;;
  vpn|vless) route_mode="vless" ;;
  *)
    echo "ERROR: mode must be direct, zapret or vpn." >&2
    usage >&2
    exit 2
    ;;
esac

status_output="$(sh "$ENGINE" --status)"

status_value() {
  printf '%s\n' "$status_output" |
    awk -F= -v key="$1" '$1 == key { print $2; exit }'
}

require_route() {
  case "$2" in
    direct|zapret|vless) ;;
    *)
      echo "ERROR: cannot determine current $1 route; no changes made." >&2
      exit 1
      ;;
  esac
}

current_discord_tcp="$(status_value discord_tcp_route)"
current_discord_voice="$(status_value discord_voice_route)"
current_youtube="$(status_value youtube_route)"

require_route "Discord TCP" "$current_discord_tcp"
require_route "Discord Voice" "$current_discord_voice"
require_route "YouTube" "$current_youtube"

next_discord_tcp="$current_discord_tcp"
next_discord_voice="$current_discord_voice"
next_youtube="$current_youtube"
case "$service" in
  discord)
    next_discord_tcp="$route_mode"
    next_discord_voice="$route_mode"
    ;;
  discord-tcp) next_discord_tcp="$route_mode" ;;
  discord-voice) next_discord_voice="$route_mode" ;;
  youtube) next_youtube="$route_mode" ;;
esac

# Keep the current Discord UDP settings unless the caller overrides them:
# the engine applies options in order, so "$@" (after these) wins.
case "$(status_value udp_range)" in
  wide) set -- --wide-udp "$@" ;;
  narrow) set -- --narrow-udp "$@" ;;
esac
current_udp_strategy="$(status_value udp_strategy)"
case "$current_udp_strategy" in
  flowseal|legacy) set -- --udp-strategy "$current_udp_strategy" "$@" ;;
esac

echo "Service routes: Discord TCP=$next_discord_tcp, Discord Voice=$next_discord_voice, YouTube=$next_youtube"
exec sh "$ENGINE" \
  --apply \
  --discord-tcp-route "$next_discord_tcp" \
  --discord-voice-route "$next_discord_voice" \
  --youtube-route "$next_youtube" \
  "$@"
