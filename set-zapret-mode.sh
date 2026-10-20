#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ENGINE="$SCRIPT_DIR/apply-discord-nfqws2.sh"

usage() {
  cat <<'EOF'
Usage:
  sh set-zapret-mode.sh discord --yes-router
  sh set-zapret-mode.sh youtube --yes-router
  sh set-zapret-mode.sh both --yes-router
  sh set-zapret-mode.sh vless --yes-router

Presets (Discord means both Discord TCP and Discord Voice):
  discord  Discord through zapret, YouTube through VLESS
  youtube  Discord through VLESS, YouTube through zapret
  both     Discord and YouTube through zapret
  vless    Discord and YouTube through VLESS

Use set-service-route.sh to route Discord TCP and Discord Voice separately.

Additional apply options are passed to apply-discord-nfqws2.sh. The current
Discord UDP settings (--wide-udp, --udp-strategy) are kept unless overridden.
Every switch creates latest-preapply and uses automatic rollback on failure.
EOF
}

[ "$#" -gt 0 ] || {
  usage >&2
  exit 2
}

preset="$1"
shift
case "$preset" in
  discord|discord-zapret)
    discord_route="zapret"
    youtube_route="vless"
    ;;
  youtube|youtube-zapret)
    discord_route="vless"
    youtube_route="zapret"
    ;;
  both|all-zapret)
    discord_route="zapret"
    youtube_route="zapret"
    ;;
  vless|all-vless)
    discord_route="vless"
    youtube_route="vless"
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    echo "ERROR: unknown routing preset: $preset" >&2
    usage >&2
    exit 2
    ;;
esac

# Keep the current Discord UDP settings (if a managed state exists) unless the
# caller overrides them: the engine applies options in order, so "$@" wins.
status_output="$(sh "$ENGINE" --status 2>/dev/null || true)"
current_udp_range="$(printf '%s\n' "$status_output" | awk -F= '$1 == "udp_range" { print $2; exit }')"
current_udp_strategy="$(printf '%s\n' "$status_output" | awk -F= '$1 == "udp_strategy" { print $2; exit }')"
case "$current_udp_range" in
  wide) set -- --wide-udp "$@" ;;
  narrow) set -- --narrow-udp "$@" ;;
esac
case "$current_udp_strategy" in
  flowseal|legacy) set -- --udp-strategy "$current_udp_strategy" "$@" ;;
esac

exec sh "$ENGINE" \
  --apply \
  --discord-route "$discord_route" \
  --youtube-route "$youtube_route" \
  "$@"
