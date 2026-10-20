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

Presets:
  discord  Discord through zapret, YouTube through VLESS
  youtube  Discord through VLESS, YouTube through zapret
  both     Discord and YouTube through zapret
  vless    Discord and YouTube through VLESS

Additional apply options are passed to apply-discord-nfqws2.sh.
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

exec sh "$ENGINE" \
  --apply \
  --discord-route "$discord_route" \
  --youtube-route "$youtube_route" \
  "$@"
