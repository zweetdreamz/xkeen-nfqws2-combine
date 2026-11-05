#!/bin/sh
set -eu

# Routing-mode integration test, part 2 of 4 (fixture and helpers:
# tests/routing-modes-lib.sh): the Telegram routes - opt-in, legacy rule tags,
# the removed Zapret route, Telegram and --ipset imports refused, the upgrade
# from the Zapret route, the WS relay across switches, rollbacks and stale
# pidfiles, a standalone apply with Telegram=ws, profile operations with the
# relay running, the v2fly dat check - and two legacy config headers.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=tests/routing-modes-lib.sh
. "$SCRIPT_DIR/tests/routing-modes-lib.sh"

# Start state, as part 1 ends: integrated, Discord zapret, YouTube vless,
# Telegram unmanaged, the upgraded nfqws2 package files.
routing_modes_install
routing_modes_upgraded_package

# Telegram: opt-in, kept across other services' switches, and removable.
# A restrictive port list exercises the XKeen 5222 handling.
printf '%s\n' '# restricted fixture' 443 > "$ROOT/opt/etc/xkeen/port_proxying.lst"
# Rules with the old shared ruleTag "kdn-telegram" (Xray refuses duplicate
# tags) are recognised by the prefix and replaced by uniquely tagged ones.
jq '.routing.rules = [
      {"type":"field","ruleTag":"kdn-telegram","outboundTag":"direct","domain":["ext:geosite_v2fly.dat:telegram"]},
      {"type":"field","ruleTag":"kdn-telegram","outboundTag":"direct","ip":["ext:geoip_v2fly.dat:telegram"]}
    ] + .routing.rules' "$routing_file" > "$routing_file.tmp"
mv "$routing_file.tmp" "$routing_file"
# Telegram has no Zapret route.
if run_service_tool telegram zapret --yes-router --core xray >/dev/null 2>&1 ||
   run_tool --apply --yes-router --core xray --telegram-route zapret >/dev/null 2>&1; then
  echo "ERROR: the removed Telegram Zapret route was accepted" >&2
  exit 1
fi
run_service_tool telegram direct --yes-router --core xray >/dev/null
assert_mode zapret zapret vless direct

# Imported profiles: Telegram has none, and --ipset is refused everywhere.
make_telegram_stage() {
  printf '%s\n' "$@" > "$ROOT/opt/tmp/telegram-args"
  telegram_id="$(
    { printf '%s\n' "$1" "fixture BAT.bat" "fixture"; tail -n +2 "$ROOT/opt/tmp/telegram-args"; } |
      awk 'NR == 1 { text=$0; next } { text=text "\n" $0 } END { printf "%s", text }' |
      sha256sum | cut -c1-12
  )"
  jq -n --arg id "$telegram_id" --arg service "$1" --rawfile args "$ROOT/opt/tmp/telegram-args" '{
    format: 1, service: $service, candidate_id: $id,
    source_name: "fixture BAT.bat", source_sha: "s", source_url: "https://example.invalid/t",
    family: "fixture", args: ($args | split("\n") | map(select(length > 0)) | .[1:]),
    notes: [], rank: 5, report: {}
  }' > "$ROOT/opt/tmp/telegram-profile.json"
}
before_bad="$(sha256sum "$nfqws_file" | awk '{print $1}')"
make_telegram_stage telegram \
  --filter-tcp=443 --filter-l7=tls --hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list \
  --out-range=-d10 --payload=tls_client_hello --lua-desync=fake:blob=telegram_tls:repeats=3
if run_tool --apply-import-profile "$ROOT/opt/tmp/telegram-profile.json" --yes-router >/dev/null 2>&1; then
  echo "ERROR: a Telegram profile was imported" >&2
  exit 1
fi
make_telegram_stage discord-tcp --filter-tcp=443 --ipset=/opt/etc/nfqws2/lists/kdn-telegram-ip.list \
  --filter-l7=tls --hostlist=/opt/etc/nfqws2/lists/user.list --payload=tls_client_hello
if run_tool --apply-import-profile "$ROOT/opt/tmp/telegram-profile.json" --yes-router >/dev/null 2>&1; then
  echo "ERROR: --ipset was accepted in an imported profile" >&2
  exit 1
fi
if run_tool --clear-imported-profile telegram --yes-router >/dev/null 2>&1; then
  echo "ERROR: --clear-imported-profile accepted telegram" >&2
  exit 1
fi
[ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$before_bad" ]

# A router upgraded from the Telegram Zapret route: the recorded zapret
# becomes direct on the next apply, and its leftovers are removed.
sed -i 's/Telegram=direct\./Telegram=zapret./' "$nfqws_file"
printf '149.154.160.0/20\n' > "$ROOT/opt/etc/nfqws2/lists/kdn-telegram-ip.list"
mkdir -p "$ROOT/opt/etc/nfqws2/imported-profiles"
printf '{}\n' > "$ROOT/opt/etc/nfqws2/imported-profiles/telegram.json"
run_tool --status | grep -Fqx 'telegram_route=zapret'
run_service_tool youtube direct --yes-router --core xray >/dev/null
assert_mode zapret zapret direct direct
[ ! -e "$ROOT/opt/etc/nfqws2/imported-profiles/telegram.json" ]
run_service_tool discord-tcp vpn --yes-router --core xray >/dev/null
assert_mode vless zapret direct direct
run_service_tool telegram ws --yes-router --core xray >/dev/null
assert_mode vless zapret direct ws
relay_pid="$(cat "$ROOT/opt/var/run/kdn-telegram-ws.pid")"
# Rollback: the relay is not in snapshots and follows the restored route.
run_tool --rollback-latest --yes-router >/dev/null
assert_mode vless zapret direct direct
if process_alive "$relay_pid"; then
  echo "ERROR: the WS relay still runs after rolling back to Telegram=direct" >&2
  exit 1
fi
run_service_tool telegram ws --yes-router --core xray >/dev/null
assert_mode vless zapret direct ws
# The hostlist of an earlier version is removed on the next apply.
printf 'tg.example.org\n' > "$ROOT/opt/etc/nfqws2/lists/kdn-telegram-cf.list"
run_service_tool telegram ws --yes-router --core xray >/dev/null
assert_mode vless zapret direct ws
[ "$(relay_count)" = 1 ]

# E2/C5: a stale relay pidfile (power loss: the PID now belongs to another
# process) must neither block the start nor get that process killed.
ws_init="$ROOT/opt/etc/init.d/S99kdn-telegram-ws"
kill -9 "$(cat "$ROOT/opt/var/run/kdn-telegram-ws.pid")"
sleep 300 &
victim_pid=$!
printf '%s\n' "$victim_pid" > "$ROOT/opt/var/run/kdn-telegram-ws.pid"
if "$ws_init" status >/dev/null 2>&1; then
  echo "ERROR: a stale relay pidfile is reported as running" >&2
  exit 1
fi
"$ws_init" start >/dev/null
process_alive "$victim_pid"
python3 -c 'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 3).close()' \
  "$KD_TEST_TELEGRAM_WS_PORT"
[ "$(cat "$ROOT/opt/var/run/kdn-telegram-ws.pid")" != "$victim_pid" ]
printf '%s\n' "$victim_pid" > "$ROOT/opt/var/run/kdn-telegram-ws.pid"
"$ws_init" restart >/dev/null
process_alive "$victim_pid"
"$ws_init" status >/dev/null
[ "$(relay_count)" = 1 ]
# A relay without a pidfile is found by its command line and replaced.
rm -f "$ROOT/opt/var/run/kdn-telegram-ws.pid"
"$ws_init" start >/dev/null
[ "$(relay_count)" = 1 ]
run_service_tool telegram ws --yes-router --core xray >/dev/null
process_alive "$victim_pid"
kill "$victim_pid"
assert_mode vless zapret direct ws
[ "$(relay_count)" = 1 ]

# E5: a standalone apply keeps the recorded Telegram route (and its Xray
# rules and relay); the next integrated apply still has Telegram=ws.
telegram_rules_before="$(jq -c '[.routing.rules[] | select((.ruleTag // "") | startswith("kdn-telegram"))]' "$routing_file")"
run_tool --apply --yes-router --standalone-zapret >/dev/null
grep -Fqx '# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=ws.' "$nfqws_file"
grep -Fq -- '--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list' "$nfqws_file"
[ "$(jq -c '[.routing.rules[] | select((.ruleTag // "") | startswith("kdn-telegram"))]' "$routing_file")" = "$telegram_rules_before" ]
run_tool --status | grep -Fqx 'telegram_route=ws'
[ "$(relay_count)" = 1 ]
assert_config_checks
run_service_tool youtube direct --yes-router --integrated --core xray >/dev/null
assert_mode zapret zapret direct ws

# E15/E12: profile operations with Telegram=ws keep the Telegram profile,
# the relay and the other services' profiles as they are.
run_service_tool youtube zapret --yes-router --core xray >/dev/null
assert_mode zapret zapret zapret ws
ws_digest_before="$(profile_digest)"
make_stage youtube "$ROOT/opt/tmp/ws-youtube.json" \
  --filter-tcp=443 --filter-l7=tls --hostlist=/opt/etc/nfqws2/lists/youtube.list \
  --out-range=-d10 --payload=tls_client_hello --lua-desync=fake:blob=tls_clienthello:repeats=4 \
  --new --filter-udp=443 --filter-l7=quic --hostlist=/opt/etc/nfqws2/lists/youtube.list \
  --payload=quic_initial --lua-desync=fake:blob=youtube_quic:repeats=5
run_tool --apply-import-profile "$ROOT/opt/tmp/ws-youtube.json" --yes-router >/dev/null
assert_profiles_same_except "$ws_digest_before" "$(profile_digest)" youtube-
assert_telegram ws
assert_config_checks
[ "$(relay_count)" = 1 ]
run_tool --rollback-import --yes-router >/dev/null
[ "$(profile_digest)" = "$ws_digest_before" ]
assert_mode zapret zapret zapret ws
[ "$(relay_count)" = 1 ]
run_service_tool youtube direct --yes-router --core xray >/dev/null
run_service_tool discord-tcp vpn --yes-router --core xray >/dev/null
assert_mode vless zapret direct ws
run_service_tool telegram direct --yes-router --core xray >/dev/null
assert_mode vless zapret direct direct
run_service_tool telegram vpn --yes-router --core xray >/dev/null
assert_mode vless zapret direct vless
# Applies without --telegram-route keep the recorded route.
apply_split_mode zapret zapret vless vless
run_service_tool telegram unmanaged --yes-router --core xray >/dev/null
assert_mode zapret zapret vless
grep -qx '# BEGIN keenetic-discord-nfqws2' "$ROOT/opt/etc/xkeen/port_proxying.lst"
if run_service_tool youtube unmanaged --yes-router --core xray >/dev/null 2>&1; then
  echo "ERROR: only Telegram may be unmanaged" >&2
  exit 1
fi

# A config written before the "# Discord UDP:" line with Voice off must not
# be read as the legacy strategy (the wrappers would pass it on).
apply_split_mode zapret direct vless
sed -i '/^# Discord UDP: /d' "$nfqws_file"
run_tool --status | grep -Fqx 'udp_strategy=unknown'
run_service_tool discord-voice zapret --yes-router --core xray >/dev/null
grep -Fq -- '--lua-desync=fake:blob=discord_udp:repeats=6' "$nfqws_file"
assert_mode zapret zapret vless

# Managed Telegram needs the v2fly dat files when XKeen's dat dir exists.
mkdir -p "$ROOT/opt/etc/xray/dat"
printf 'x' > "$ROOT/opt/etc/xray/dat/geosite_v2fly.dat"
if run_service_tool telegram direct --yes-router --core xray >/dev/null 2>&1; then
  echo "ERROR: Telegram applied without geoip_v2fly.dat" >&2
  exit 1
fi
assert_mode zapret zapret vless
rm -rf "$ROOT/opt/etc/xray/dat"

# A config written before the TCP/Voice split still reports both routes.
sed -i 's/^# Active routes: .*/# Active routes: Discord=zapret, YouTube=vless./' "$nfqws_file"
legacy_status="$(run_tool --status)"
printf '%s\n' "$legacy_status" | grep -Fqx 'discord_tcp_route=zapret'
printf '%s\n' "$legacy_status" | grep -Fqx 'discord_voice_route=zapret'
apply_mode zapret vless

assert_no_xkeen_xtest
echo "routing-modes-telegram-tests-ok"
