#!/bin/sh
set -eu

# Routing-mode integration test, part 1 of 4 (fixture and helpers:
# tests/routing-modes-lib.sh): the standalone install and the wrappers on a
# standalone deployment, every Discord TCP/Voice and YouTube route
# combination, repeated applies, the service wrappers, --rollback-latest and
# --rollback-snapshot, a package upgrade between snapshot and rollback, and the
# Voice UDP range and strategy across route switches.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=tests/routing-modes-lib.sh
. "$SCRIPT_DIR/tests/routing-modes-lib.sh"

# Install standalone first: the baseline then covers nfqws2 only. The first
# integrated apply must add an XKeen baseline so that --rollback can still
# return Xray to its original files (checked at the end of
# test-routing-modes-snapshots.sh, which repeats these steps).
original_routing_hash="$(sha256sum "$routing_file" | awk '{print $1}')"
KDN_ENGINE=python run_tool_once --snapshot-baseline --standalone-zapret --yes-router >/dev/null
run_tool --apply --yes-router --standalone-zapret --youtube-route direct >/dev/null
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$original_routing_hash" ]
assert_config_checks

# A5: the wrappers (and so the panel, which passes --core auto) keep a
# standalone deployment standalone although XKeen is installed.
: > "$ROOT/xkeen-init.log"
run_service_tool youtube zapret --yes-router --core auto >/dev/null
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$original_routing_hash" ]
[ ! -s "$ROOT/xkeen-init.log" ]
grep -Fqx '# Deployment mode: standalone-zapret.' "$nfqws_file"
grep -Fqx '# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=unmanaged.' "$nfqws_file"
if run_service_tool youtube vpn --yes-router --core auto >/dev/null 2>&1; then
  echo "ERROR: a standalone deployment accepted a vpn route" >&2
  exit 1
fi
KDN_ENGINE=legacy PATH="$MOCK_BIN:$PATH" KD_TEST_ROOT="$ROOT" KD_ALLOW_TEST_ROOT=1 \
  sh "$SCRIPT_DIR/set-zapret-mode.sh" both --yes-router --core auto >/dev/null
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$original_routing_hash" ]
[ ! -s "$ROOT/xkeen-init.log" ]
if KDN_ENGINE=legacy PATH="$MOCK_BIN:$PATH" KD_TEST_ROOT="$ROOT" KD_ALLOW_TEST_ROOT=1 \
     sh "$SCRIPT_DIR/set-zapret-mode.sh" discord --yes-router >/dev/null 2>&1; then
  echo "ERROR: a standalone deployment accepted a VLESS preset" >&2
  exit 1
fi
run_tool --apply --yes-router --standalone-zapret --youtube-route direct >/dev/null

apply_mode zapret vless
discord_hash="$(sha256sum "$routing_file" | awk '{print $1}')"

for tcp_mode in direct zapret vless; do
  for voice_mode in direct zapret vless; do
    for youtube_mode in direct zapret vless; do
      apply_split_mode "$tcp_mode" "$voice_mode" "$youtube_mode"
    done
  done
done

apply_mode zapret zapret
both_hash="$(sha256sum "$routing_file" | awk '{print $1}')"
apply_mode zapret zapret
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$both_hash" ]

run_service_tool youtube direct --yes-router --core xray >/dev/null
assert_mode zapret zapret direct
run_service_tool discord-voice vpn --yes-router --core xray >/dev/null
assert_mode zapret vless direct
run_service_tool discord-tcp direct --yes-router --core xray >/dev/null
assert_mode direct vless direct
run_service_tool discord vpn --yes-router --core xray >/dev/null
assert_mode vless vless direct
run_service_tool discord-voice zapret --yes-router --core xray >/dev/null
assert_mode vless zapret direct

apply_mode zapret vless
apply_mode vless zapret
run_tool --rollback-latest --yes-router >/dev/null
assert_mode zapret zapret vless
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$discord_hash" ]

apply_mode vless zapret
selected_snapshot="$(sed -n '1p' "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")"
apply_mode direct direct
run_tool --rollback-snapshot "$selected_snapshot" --yes-router >/dev/null
assert_mode zapret zapret vless

# opkg cannot downgrade, so a package upgraded after the snapshot must only
# produce a warning. It used to fail the restore, and the automatic rollback
# then restored the rescue snapshot, silently undoing the requested rollback.
# The upgrade also replaces package files: Lua scripts must match the new
# binary (NFQWS2_COMPAT_VER), so the restore keeps them and the new init and
# netfilter scripts, and brings back only nfqws2 configuration and lists.
apply_mode zapret vless
apply_mode vless zapret
printf '%s\n' '2.0-upgraded' > "$ROOT/opkg-version"
mkdir -p "$ROOT/opt/etc/nfqws2/lua"
printf '%s\n' 'NFQWS2_COMPAT_VER_REQUIRED=6' > "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
printf '%s\n' 'package default' > "$ROOT/opt/etc/nfqws2/nfqws2.conf-opkg"
printf '%s\n' '# upgraded init' >> "$ROOT/opt/etc/init.d/S51nfqws2"
init_hash="$(sha256sum "$ROOT/opt/etc/init.d/S51nfqws2" | awk '{print $1}')"
rollback_output="$(run_tool --rollback-latest --yes-router 2>&1)"
printf '%s\n' "$rollback_output" |
  grep -Fq 'WARNING: nfqws2-keenetic version is 2.0-upgraded; snapshot has 1.0-test.'
printf '%s\n' "$rollback_output" |
  grep -Fq 'Restoring nfqws2 configuration, lists and blobs only; package files are kept.'
if printf '%s\n' "$rollback_output" | grep -Fq 'automatic rollback'; then
  echo "ERROR: package drift triggered an automatic rollback" >&2
  exit 1
fi
assert_mode zapret zapret vless
grep -Fqx 'NFQWS2_COMPAT_VER_REQUIRED=6' "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
[ -f "$ROOT/opt/etc/nfqws2/nfqws2.conf-opkg" ]
[ "$(sha256sum "$ROOT/opt/etc/init.d/S51nfqws2" | awk '{print $1}')" = "$init_hash" ]
# Without drift the snapshot is restored as a whole, as before.
rm -f "$ROOT/opkg-version"
apply_mode vless zapret
run_tool --rollback-latest --yes-router >/dev/null
assert_mode zapret zapret vless
grep -Fqx 'NFQWS2_COMPAT_VER_REQUIRED=6' "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"

# The wrappers change routes only: wide Voice ports and the legacy UDP
# strategy must survive a switch of any service, and --narrow-udp resets the
# range explicitly.
run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route vless \
  --wide-udp --udp-strategy legacy >/dev/null
run_service_tool youtube direct --yes-router --core xray >/dev/null
grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:65535' "$nfqws_file"
grep -Fq -- '--lua-desync=circular:fails=2:time=300:retrans=3:nld=2' "$nfqws_file"
jq -e 'any(.routing.rules[]?; .port == "3478-3481,5349,19294-19344,50000-65535")' "$routing_file" >/dev/null
udp_status="$(run_tool --status)"
printf '%s\n' "$udp_status" | grep -Fqx 'udp_strategy=legacy'
printf '%s\n' "$udp_status" | grep -Fqx 'udp_range=wide'
# Voice off and on again: the settings are kept while Voice is not zapret.
run_service_tool discord-voice direct --yes-router --core xray >/dev/null
run_service_tool discord-voice zapret --yes-router --core xray >/dev/null
grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:65535' "$nfqws_file"
grep -Fq -- '--lua-desync=circular:fails=2:time=300:retrans=3:nld=2' "$nfqws_file"
run_service_tool youtube vpn --yes-router --core xray --narrow-udp --udp-strategy flowseal >/dev/null
grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:50100' "$nfqws_file"
grep -Fq -- '--lua-desync=fake:blob=discord_udp:repeats=6' "$nfqws_file"
assert_mode zapret zapret vless

assert_no_xkeen_xtest
echo "routing-modes-routes-tests-ok"
