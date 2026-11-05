#!/bin/sh
set -eu

# Routing-mode integration test, part 4 of 4 (fixture and helpers:
# tests/routing-modes-lib.sh): the import rollback after a route switch,
# imported Voice profiles and the UDP range, two proxy outbounds, block rules
# with attribute subsets, snapshot pruning, the full baseline rollback and
# XKeen with proxy_router=on, TProxy and IPv6.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=tests/routing-modes-lib.sh
. "$SCRIPT_DIR/tests/routing-modes-lib.sh"

# Start state, as part 3 ends: integrated, every route zapret, Telegram
# unmanaged, the upgraded nfqws2 package files, the tuner descriptors of the
# import checks. The baseline rollback at the end returns to the files before
# the first apply.
original_routing_hash="$(sha256sum "$routing_file" | awk '{print $1}')"
original_nfqws_hash="$(sha256sum "$nfqws_file" | awk '{print $1}')"
routing_modes_install
routing_modes_upgraded_package
write_youtube_stage
write_voice_stage
apply_mode zapret zapret

# --- C2/A4/B5/D4: a route switch after an import ends the import rollback.
run_tool --apply-import-profile "$voice_stage" --yes-router >/dev/null
import_pointer="$ROOT/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr"
saved_import_pointer="$(cat "$import_pointer")"
run_service_tool youtube direct --yes-router --core xray >/dev/null
[ ! -e "$import_pointer" ]
switched_conf="$(sha256sum "$nfqws_file" | awk '{print $1}')"
if run_tool --rollback-import --yes-router >/dev/null 2>&1; then
  echo "ERROR: --rollback-import restored nfqws2 data from before a route switch" >&2
  exit 1
fi
[ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$switched_conf" ]
# Even with the pointer back (an older release left it), the routes guard
# refuses and changes nothing.
printf '%s\n' "$saved_import_pointer" > "$import_pointer"
if run_tool --rollback-import --yes-router > "$FIXTURE/guard.log" 2>&1; then
  echo "ERROR: --rollback-import ignored the changed routes" >&2
  exit 1
fi
grep -Fq 'the routes changed after the latest profile operation' "$FIXTURE/guard.log"
[ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$switched_conf" ]
grep -Fqx '# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=direct, Telegram=unmanaged.' "$nfqws_file"
assert_config_checks
rm -f "$import_pointer"
run_service_tool youtube zapret --yes-router --core xray >/dev/null
run_tool --clear-imported-profile discord-voice --yes-router >/dev/null
assert_mode zapret zapret zapret

# --- A10/A7/B9: imported Voice profiles and the UDP range.
make_stage discord-voice "$ROOT/opt/tmp/wide-voice.json" \
  --filter-udp=19294-19344,50000-65535 --filter-l7=stun,discord --out-range='<n2' \
  --payload=stun,discord_ip_discovery --lua-desync=fake:blob=discord_udp:repeats=6
run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret --wide-udp >/dev/null
run_tool --apply-import-profile "$ROOT/opt/tmp/wide-voice.json" --yes-router >/dev/null
# Voice off: the unused wide profile does not block a narrow apply.
run_tool --apply --yes-router --core xray --discord-tcp-route zapret --discord-voice-route vless \
  --youtube-route zapret --narrow-udp >/dev/null
[ -f "$ROOT/opt/etc/nfqws2/imported-profiles/discord-voice.json" ]
grep -Fq 'DiscordVoice=vless' "$nfqws_file"
# Voice on with the narrow range: refused, naming the profile and the remedy.
if run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret \
     --narrow-udp > "$FIXTURE/voice.log" 2>&1; then
  echo "ERROR: a wide Voice profile was used with the narrow range" >&2
  exit 1
fi
grep -Fq -- '--clear-imported-profile discord-voice' "$FIXTURE/voice.log"
run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret --wide-udp >/dev/null
run_tool --status | grep -Fqx "discord_voice_profile=imported:$(jq -r .candidate_id "$ROOT/opt/tmp/wide-voice.json")"
run_tool --apply-import-profile "$voice_stage" --yes-router >/dev/null
# A narrow profile in wide mode: reported in the header, status and checks.
grep -Fqx "# Discord Voice profile: imported $voice_id, udp=19294-19344,50000-50100." "$nfqws_file"
run_tool --status | grep -Fqx "discord_voice_profile=imported:$voice_id"
run_tool --status | grep -Fqx 'discord_voice_udp=19294-19344,50000-50100'
run_tool --check-config | grep -q '^CHECK|warn|voice-range|range=wide is recorded'
run_tool --clear-imported-profile discord-voice --yes-router >/dev/null
run_tool --status | grep -Fqx 'discord_voice_profile=builtin'
apply_mode zapret zapret

# --- C3: with two proxy outbounds the recorded tag keeps later applies working.
jq '.outbounds += [{"tag":"vless-backup","protocol":"vless"}]' \
  "$ROOT/opt/etc/xray/configs/04_outbounds.json" > "$FIXTURE/outbounds.json"
cp "$FIXTURE/outbounds.json" "$ROOT/opt/etc/xray/configs/04_outbounds.json"
jq '.routing.rules += [{"type":"field","inboundTag":["redirect","tproxy"],"outboundTag":"vless-backup","domain":["domain:example.net"]}]' \
  "$routing_file" > "$FIXTURE/routing.json"
cp "$FIXTURE/routing.json" "$routing_file"
run_service_tool discord vpn --yes-router --core auto >/dev/null
grep -Fqx '# Proxy outbound: vless-reality.' "$nfqws_file"
run_tool --status | grep -Fqx 'proxy_outbound=vless-reality'
run_service_tool youtube direct --yes-router --core auto >/dev/null
run_service_tool youtube direct --yes-router --core auto >/dev/null
run_service_tool telegram vpn --yes-router --core auto >/dev/null
run_service_tool youtube vpn --yes-router --core auto >/dev/null
jq -e '[.routing.rules[] | select(.outboundTag == "vless-backup")] | length == 1' "$routing_file" >/dev/null
jq -e 'any(.routing.rules[]; .outboundTag == "vless-reality" and any(.domain[]?; . == "ext:geosite_v2fly.dat:discord"))' "$routing_file" >/dev/null
jq -e '[.routing.rules[] | select((.ruleTag // "") | startswith("kdn-telegram")) | .outboundTag] | unique == ["vless-reality"]' "$routing_file" >/dev/null
run_service_tool telegram unmanaged --yes-router --core auto >/dev/null
jq '.routing.rules |= map(select(.outboundTag != "vless-backup"))' "$routing_file" > "$FIXTURE/routing.json"
cp "$FIXTURE/routing.json" "$routing_file"
jq '.outbounds |= map(select(.tag != "vless-backup"))' \
  "$ROOT/opt/etc/xray/configs/04_outbounds.json" > "$FIXTURE/outbounds.json"
cp "$FIXTURE/outbounds.json" "$ROOT/opt/etc/xray/configs/04_outbounds.json"
apply_mode zapret zapret

# --- A9: an attribute subset in a block rule stays a block rule, in front.
ads_rule='{"type":"field","inboundTag":["redirect","tproxy"],"outboundTag":"block","domain":["ext:geosite_v2fly.dat:youtube@ads"]}'
jq --argjson rule "$ads_rule" '.routing.rules += [$rule]' "$routing_file" > "$FIXTURE/routing.json"
cp "$FIXTURE/routing.json" "$routing_file"
run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret >/dev/null
jq -e --argjson rule "$ads_rule" '.routing.rules[0] == $rule' "$routing_file" >/dev/null
jq -e 'all(.routing.rules[]; all(.domain[]?; . != "ext:geosite_v2fly.dat:youtube@ads") or .outboundTag == "block")' \
  "$routing_file" >/dev/null
xray_config_test
jq '.routing.rules |= .[1:]' "$routing_file" > "$FIXTURE/routing.json"
cp "$FIXTURE/routing.json" "$routing_file"
apply_mode zapret zapret

# --- B10/C7: snapshots are pruned, but never the ones a pointer or the panel
# history names.
mkdir -p "$ROOT/opt/etc/xkeen-web/history"
history_snapshot="$(sed -n '1p' "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")"
printf '{"job_id":"0123456789abcdef","snapshot":"%s"}\n' "$history_snapshot" \
  > "$ROOT/opt/etc/xkeen-web/history/0123456789abcdef.json"
KD_SNAPSHOT_KEEP=2
KD_IMPORT_SNAPSHOT_KEEP=1
export KD_SNAPSHOT_KEEP KD_IMPORT_SNAPSHOT_KEEP
for _ in 1 2 3 4; do
  run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret >/dev/null
  run_tool --apply-import-profile "$voice_stage" --yes-router >/dev/null
  run_tool --clear-imported-profile discord-voice --yes-router >/dev/null
done
unset KD_SNAPSHOT_KEEP KD_IMPORT_SNAPSHOT_KEEP
[ -d "$history_snapshot" ]
for kept_pointer in baseline.ptr baseline-xkeen.ptr latest-preapply.ptr latest-nfqws-import.ptr; do
  [ -d "$(sed -n '1p' "$ROOT/opt/etc/keenetic-discord-nfqws2/$kept_pointer")" ]
done
# This fixture's full apply remains the frozen legacy oracle (old count policy).
# Native full age/minimum1 is covered by real store tests. Focused operations
# below are native: their fresh snapshots must survive regardless of keep=1.
[ "$(find "$ROOT/opt/etc/keenetic-discord-nfqws2/snapshots" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" -le 6 ]
[ "$(find "$ROOT/opt/etc/keenetic-discord-nfqws2/nfqws-import-snapshots" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" -ge 2 ]
# Import snapshots hold the nfqws2 data, not the package files.
[ ! -e "$(sed -n '1p' "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr")/nfqws2/lua" ]
rm -rf "$ROOT/opt/etc/xkeen-web"
assert_mode zapret zapret zapret

# Full baseline rollback after standalone + integrated applies.
run_tool --show-snapshots | grep -Fq 'XKeen baseline: '
run_tool --rollback --yes-router >/dev/null
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$original_routing_hash" ]
[ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$original_nfqws_hash" ]
[ ! -e "$discord_outbound_file" ]
[ ! -e "$youtube_outbound_file" ]
[ ! -e "$telegram_outbound_file" ]

# --- E14/E1: XKeen with proxy_router=on, TProxy mode and a routed IPv6 WAN.
sed -i 's/^proxy_router="off"/proxy_router="on"/; s/^ipv6_support="off"/ipv6_support="on"/' \
  "$ROOT/opt/etc/init.d/S05xkeen"
sed -i "s/^mode_proxy='Hybrid'/mode_proxy='TProxy'/; s/^proxy_router='off'/proxy_router='on'/" \
  "$ROOT/opt/etc/ndm/netfilter.d/proxy.sh"
cat > "$ROOT/opt/etc/xray/configs/03_inbounds.json" <<'EOF'
{
  "inbounds": [
    {"tag":"redirect","sniffing":{"enabled":true,"destOverride":["http","tls"]}},
    {"tag":"tproxy","settings":{"network":"tcp,udp"},"sniffing":{"enabled":true,"destOverride":["quic"]}}
  ]
}
EOF
sed -i 's#^  "-6 route get "\*).*#  "-6 route get "*) echo "2001:4860:4860::8888 from :: dev fixture-wan src 2001:db8::1 metric 1024"; exit 0 ;;#' \
  "$MOCK_BIN/ip"
# Everything on vless but Telegram=ws: the Telegram direct outbound and the
# relay still need the direct mark 255 (E1).
run_tool --apply --yes-router --core xray --discord-route vless --youtube-route vless --telegram-route ws >/dev/null
grep -Fqx 'IPV6_ENABLED=1' "$nfqws_file"
[ -s "$ROOT/ip6tables-mangle.rules" ]
jq -e '.outbounds[] | select(.tag == "telegram-direct") | .streamSettings.sockopt.mark == 255' \
  "$telegram_outbound_file" >/dev/null
if grep -Fq '"--mark"' "$SCRIPT_DIR/tools/router/telegram_ws_relay.py"; then
  grep -Fqx 'MARK="255"' "$ROOT/opt/etc/init.d/S99kdn-telegram-ws"
  tr '\0' ' ' < "/proc/$(cat "$ROOT/opt/var/run/kdn-telegram-ws.pid")/cmdline" | grep -Fq -- '--mark 255'
else
  grep -Fqx 'MARK=""' "$ROOT/opt/etc/init.d/S99kdn-telegram-ws"
fi
[ "$(relay_count)" = 1 ]
assert_config_checks
run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret >/dev/null
jq -e '.outbounds[0].streamSettings.sockopt.mark == 255' \
  "$discord_outbound_file" >/dev/null
jq -e '.outbounds[0].streamSettings.sockopt.mark == 255' \
  "$youtube_outbound_file" >/dev/null
# In TProxy mode TCP arrives on the tproxy inbound: it must sniff TLS/HTTP.
jq -e '.inbounds[] | select(.tag == "tproxy") | .sniffing.destOverride | (index("tls") != null and index("http") != null and index("quic") != null)' \
  "$ROOT/opt/etc/xray/configs/03_inbounds.json" >/dev/null
assert_config_checks
xray_config_test
run_tool --status | grep -Fqx 'telegram_route=ws'
run_tool --apply --yes-router --core xray --telegram-route unmanaged >/dev/null
[ "$(relay_count)" = 0 ]

assert_no_xkeen_xtest
echo "routing-modes-snapshots-tests-ok"
