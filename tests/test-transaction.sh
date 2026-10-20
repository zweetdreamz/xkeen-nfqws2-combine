#!/bin/sh
set -eu

# No router or network commands are used here. Every absolute router path is
# redirected into a disposable fixture and external commands are mocked.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"
DISCORD_UDP_BLOB="$SCRIPT_DIR/config/blobs/ACTIVE_DISCORD_UDP.bin"
YOUTUBE_LIST="$SCRIPT_DIR/config/youtube-user.list"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-discord-test.XXXXXX")"
trap 'rm -rf "$FIXTURE"' 0 HUP INT TERM

expected_blob_hash="2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf"
actual_blob_hash="$(sha256sum "$DISCORD_UDP_BLOB" | awk '{ print $1 }')"
[ "$actual_blob_hash" = "$expected_blob_hash" ]
grep -Fq "$expected_blob_hash" "$TARGET"
grep -Fq -- '--blob=discord_udp:@/opt/etc/nfqws2/blobs/discord_udp.bin' "$TARGET"
grep -Fq -- '--lua-desync=fake:blob=discord_udp:repeats=6' "$TARGET"
if sh "$TARGET" --print-plan --udp-strategy invalid >/dev/null 2>&1; then
  echo "ERROR: invalid UDP strategy unexpectedly passed." >&2
  exit 1
fi

awk '
  /^discord_domains\(\)/ { in_function=1; next }
  in_function && /^  cat <<'\''EOF'\''$/ { in_data=1; next }
  in_data && /^EOF$/ { exit }
  in_data { print }
' "$TARGET" > "$FIXTURE/embedded-domains.list"
diff -u "$SCRIPT_DIR/config/discord-user.list" "$FIXTURE/embedded-domains.list"
grep -Fq 'ascii_downcase | contains("discord")' "$TARGET"
grep -Fq 'chmod 700 "$STATE_ROOT" "$SNAPSHOT_ROOT"' "$TARGET"
grep -Fq 'run_nfqws_init restart' "$TARGET"
grep -Fq '"ext:geosite_v2fly.dat:discord"' "$TARGET"
if grep -Fq '"ext:zkeenip.dat:discord"' "$TARGET"; then
  echo "ERROR: broad Discord IP category must not be routed directly." >&2
  exit 1
fi
grep -Fq '.ip |= map(select(is_discord_ext_selector | not))' "$TARGET"
grep -Fq 'managed_discord_rule or managed_youtube_rule' "$TARGET"
grep -Fq '"ext:zkeen.dat:youtube"' "$TARGET"
grep -Fq '"ext:geosite_v2fly.dat:youtube"' "$TARGET"
grep -Fq -- '--out-range=-d10' "$TARGET"
grep -Fq '936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c' "$TARGET"
grep -Fq -- '--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000' "$TARGET"
grep -Fq -- '--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up' "$TARGET"
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=11' "$TARGET"
grep -Fq 'if [ -n "$NFQWS_ARGS_CUSTOM" ]; then' "$TARGET"
if grep -Fq '"domain": (($domains[0]' "$TARGET"; then
  echo "ERROR: hardcoded hostlist domains must not be copied into Xray routing." >&2
  exit 1
fi

awk '
  /^youtube_domains\(\)/ { in_function=1; next }
  in_function && /^  cat <<'\''EOF'\''$/ { in_data=1; next }
  in_data && /^EOF$/ { exit }
  in_data { print }
' "$TARGET" > "$FIXTURE/embedded-youtube-domains.list"
diff -u "$YOUTUBE_LIST" "$FIXTURE/embedded-youtube-domains.list"

# Telegram lists embedded in the engine match config/, and the Mihomo rules
# built from them use IP-CIDR6 for IPv6 and never resolve domains for IPs.
sed -n '/^telegram_domains() {$/,/^}$/p; /^telegram_networks() {$/,/^}$/p; /^telegram_mihomo_rules() {$/,/^}$/p' \
  "$TARGET" > "$FIXTURE/telegram-functions.sh"
(
  . "$FIXTURE/telegram-functions.sh"
  telegram_domains | diff -u "$SCRIPT_DIR/config/telegram-user.list" -
  telegram_networks | diff -u "$SCRIPT_DIR/config/telegram-ip.list" -
  telegram_mihomo_rules > "$FIXTURE/telegram-mihomo.rules"
)
grep -Fqx 'DOMAIN-SUFFIX,t.me,DIRECT' "$FIXTURE/telegram-mihomo.rules"
grep -Fqx 'IP-CIDR,149.154.160.0/20,DIRECT,no-resolve' "$FIXTURE/telegram-mihomo.rules"
grep -Fqx 'IP-CIDR6,2001:67c:4e8::/48,DIRECT,no-resolve' "$FIXTURE/telegram-mihomo.rules"
[ "$(wc -l < "$FIXTURE/telegram-mihomo.rules" | tr -d ' ')" = "33" ]
if grep -Fq 'zkeenip.dat:telegram' "$TARGET"; then
  echo "ERROR: zkeenip.dat:telegram includes 194.221.0.0/16 and must not be used." >&2
  exit 1
fi
if sh "$TARGET" --print-plan --telegram-route bogus >/dev/null 2>&1; then
  echo "ERROR: invalid Telegram route unexpectedly passed." >&2
  exit 1
fi
if grep -Fq 'test("discord"' "$TARGET"; then
  echo "ERROR: router jq has no ONIGURUMA support; regex test() must not be used." >&2
  exit 1
fi

ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"
mkdir -p \
  "$ROOT/opt/etc/init.d" \
  "$ROOT/opt/etc/ndm/netfilter.d" \
  "$ROOT/opt/etc/xkeen" \
  "$ROOT/opt/etc/xray/configs" \
  "$ROOT/opt/etc/opkg" \
  "$ROOT/opt/tmp" \
  "$MOCK_BIN"

cat > "$ROOT/opt/etc/init.d/S05xkeen" <<'EOF'
#!/bin/sh
name_client="xray"
name_policy="xkeen"
table_id="111"
table_mark="0x111"
proxy_dns="off"
proxy_router="off"
dscp_exclude="62"
dscp_proxy="63"
ipv6_support="on"
start_auto="on"
exit 0
EOF
chmod +x "$ROOT/opt/etc/init.d/S05xkeen"

cat > "$ROOT/opt/etc/ndm/netfilter.d/proxy.sh" <<'EOF'
mode_proxy='Hybrid'
port_redirect='61219'
port_tproxy='61219'
port_donor=''
port_exclude=''
policy_mark='0xffffaaa'
dscp_exclude='62'
dscp_proxy='63'
file_dns='false'
proxy_dns='off'
proxy_router='off'
iptables_supported='true'
ip6tables_supported='true'
EOF

cat > "$ROOT/opt/etc/xkeen/port_proxying.lst" <<'EOF'
# unrestricted fixture
EOF
cat > "$ROOT/opt/etc/xkeen/port_exclude.lst" <<'EOF'
# no exclusions
EOF
cat > "$ROOT/opt/etc/xray/configs/03_inbounds.json" <<'EOF'
{"inbounds":[{"tag":"redirect"},{"tag":"tproxy"}]}
EOF
cat > "$ROOT/opt/etc/xray/configs/05_routing.json" <<'EOF'
{"routing":{"rules":[{"type":"field","outboundTag":"vless-reality","domain":["ext:zkeen.dat:youtube","ext:geosite_v2fly.dat:youtube"]}]}}
EOF
cat > "$ROOT/opt/etc/xray/configs/04_outbounds.json" <<'EOF'
{"outbounds":[{"tag":"vless-reality","protocol":"vless"}]}
EOF

cat > "$MOCK_BIN/xkeen" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -v) echo "XKeen fixture" ;;
  -status) echo "stopped" ;;
  -cp|-cpe|-tp) echo "fixture" ;;
esac
exit 0
EOF

cat > "$MOCK_BIN/opkg" <<'EOF'
#!/bin/sh
case "${1:-}" in
  status) exit 0 ;;
  update) exit 0 ;;
  install) exit 42 ;;
  remove) exit 0 ;;
esac
exit 0
EOF

cat > "$MOCK_BIN/jq" <<'EOF'
#!/bin/sh
# Preflight-only mock. The forced opkg failure happens before JSON mutation.
case "$*" in
  *'contains("youtube")'*) echo "vless-reality" ;;
esac
exit 0
EOF

cat > "$MOCK_BIN/pidof" <<'EOF'
#!/bin/sh
exit 1
EOF

cat > "$MOCK_BIN/ip" <<'EOF'
#!/bin/sh
case "$*" in
  "-6 route get "*) echo "unreachable 2001:4860:4860::8888 dev lo error -128"; exit 0 ;;
  "-6 route show default") exit 0 ;;
  "link show dev fixture-wan") exit 0 ;;
  "route get "*) echo "1.1.1.1 dev fixture-wan src 192.0.2.1"; exit 0 ;;
  "route show default") echo "default dev fixture-wan"; exit 0 ;;
esac
exit 1
EOF

chmod +x \
  "$MOCK_BIN/xkeen" \
  "$MOCK_BIN/opkg" \
  "$MOCK_BIN/jq" \
  "$MOCK_BIN/pidof" \
  "$MOCK_BIN/ip"

run_tool() {
  PATH="$MOCK_BIN:$PATH" \
  KD_TEST_ROOT="$ROOT" \
  KD_ALLOW_TEST_ROOT=1 \
    sh "$TARGET" "$@"
}

run_rollback_launcher() {
  PATH="$MOCK_BIN:$PATH" \
  KD_TEST_ROOT="$ROOT" \
  KD_ALLOW_TEST_ROOT=1 \
    sh "$SCRIPT_DIR/rollback-to-baseline.sh"
}

original_routing="$(sha256sum "$ROOT/opt/etc/xray/configs/05_routing.json" | awk '{print $1}')"

run_tool --snapshot-baseline --core xray --yes-router >/dev/null
baseline_pointer="$ROOT/opt/etc/keenetic-discord-nfqws2/baseline.ptr"
[ -s "$baseline_pointer" ]
baseline_before="$(sed -n '1p' "$baseline_pointer")"

printf '%s\n' '{"routing":"broken after baseline"}' > "$ROOT/opt/etc/xray/configs/05_routing.json"
rm -f "$ROOT/opt/etc/xray/configs/03_inbounds.json"
run_rollback_launcher >/dev/null

restored_routing="$(sha256sum "$ROOT/opt/etc/xray/configs/05_routing.json" | awk '{print $1}')"
[ "$restored_routing" = "$original_routing" ]
[ -f "$ROOT/opt/etc/xray/configs/03_inbounds.json" ]

if run_tool --preflight --core xray --direct-mark 0x123 >/dev/null 2>&1; then
  echo "ERROR: non-decimal direct mark unexpectedly passed." >&2
  exit 1
fi
run_tool --preflight --core xray --direct-mark 123456 >/dev/null

preflight_output="$(run_tool --preflight --core xray 2>&1)"
printf '%s\n' "$preflight_output" | grep -q 'nfqws2 WAN interface(s): fixture-wan'
printf '%s\n' "$preflight_output" | grep -q 'nfqws2 IPv6: disabled'

mkdir -p "$ROOT/opt/etc/nfqws2"
cat > "$ROOT/opt/etc/nfqws2/nfqws2.conf" <<'EOF'
ISP_INTERFACE="obsolete-wan"
ISP_INTERFACE="fixture-wan"
EOF
run_tool --preflight --core xray >/dev/null
rm -rf "$ROOT/opt/etc/nfqws2"

before_failed_apply="$(sha256sum "$ROOT/opt/etc/xray/configs/05_routing.json" | awk '{print $1}')"
if run_tool --apply --core xray --yes-router >/dev/null 2>&1; then
  echo "ERROR: forced apply failure unexpectedly succeeded." >&2
  exit 1
fi
after_failed_apply="$(sha256sum "$ROOT/opt/etc/xray/configs/05_routing.json" | awk '{print $1}')"
[ "$before_failed_apply" = "$after_failed_apply" ]
[ ! -e "$ROOT/opt/etc/opkg/nfqws2-keenetic.conf" ]
[ "$(sed -n '1p' "$baseline_pointer")" = "$baseline_before" ]

echo "transaction-tests-ok"
