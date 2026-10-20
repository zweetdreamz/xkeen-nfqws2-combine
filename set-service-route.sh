#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ENGINE="$SCRIPT_DIR/apply-discord-nfqws2.sh"

usage() {
  cat <<'EOF'
Usage:
  sh set-service-route.sh discord direct|zapret|vpn --yes-router [apply options]
  sh set-service-route.sh youtube direct|zapret|vpn --yes-router [apply options]

The route of the other service is read from the current managed state and
preserved. "vpn" is a user-facing alias for the engine route "vless".

Examples:
  sh set-service-route.sh discord zapret --core auto --wan-interface eth3 --yes-router
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
  discord|youtube) ;;
  *)
    echo "ERROR: service must be discord or youtube." >&2
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
current_discord="$(
  printf '%s\n' "$status_output" |
    awk -F= '$1 == "discord_route" { print $2; exit }'
)"
current_youtube="$(
  printf '%s\n' "$status_output" |
    awk -F= '$1 == "youtube_route" { print $2; exit }'
)"

case "$current_discord" in
  direct|zapret|vless) ;;
  *)
    echo "ERROR: cannot determine current Discord route; no changes made." >&2
    exit 1
    ;;
esac
case "$current_youtube" in
  direct|zapret|vless) ;;
  *)
    echo "ERROR: cannot determine current YouTube route; no changes made." >&2
    exit 1
    ;;
esac

if [ "$service" = "discord" ]; then
  next_discord="$route_mode"
  next_youtube="$current_youtube"
else
  next_discord="$current_discord"
  next_youtube="$route_mode"
fi

echo "Service routes: Discord=$next_discord, YouTube=$next_youtube"
exec sh "$ENGINE" \
  --apply \
  --discord-route "$next_discord" \
  --youtube-route "$next_youtube" \
  "$@"
