#!/bin/sh
set -eu

# Integration test for all nine direct/zapret/vless combinations. It must run on
# Linux/Entware with real jq. All router paths are redirected to a disposable
# fixture; service, package, route and firewall commands are mocked.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"
SERVICE_TARGET="$SCRIPT_DIR/set-service-route.sh"
BLOB_SOURCE="${NFQWS_TEST_BLOB_SOURCE:-/opt/etc/nfqws2/blobs}"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-routing-modes.XXXXXX")"
ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"

safe_cleanup() {
  pidfile="$ROOT/opt/var/run/nfqws2.pid"
  if [ -f "$pidfile" ]; then
    fixture_pid="$(sed -n '1p' "$pidfile")"
    case "$fixture_pid" in
      ''|*[!0-9]*) ;;
      *) kill "$fixture_pid" 2>/dev/null || true ;;
    esac
  fi
  case "$FIXTURE" in
    "${TMPDIR:-/tmp}/keenetic-routing-modes."*)
      rm -rf "$FIXTURE"
      ;;
  esac
}
trap safe_cleanup 0 HUP INT TERM

command -v jq >/dev/null
command -v sha256sum >/dev/null
[ -f "$BLOB_SOURCE/tls_clienthello.bin" ]
[ -f "$BLOB_SOURCE/quic_initial.bin" ]

mkdir -p \
  "$ROOT/opt/etc/init.d" \
  "$ROOT/opt/etc/ndm/netfilter.d" \
  "$ROOT/opt/etc/xkeen" \
  "$ROOT/opt/etc/xray/configs" \
  "$ROOT/opt/etc/nfqws2/lists" \
  "$ROOT/opt/etc/nfqws2/blobs" \
  "$ROOT/opt/etc/opkg" \
  "$ROOT/opt/tmp" \
  "$ROOT/opt/var/run" \
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
ipv6_support="off"
start_auto="on"
printf 'xkeen-init:%s\n' "$*" >> "$KD_TEST_ROOT/xkeen-init.log"
exit 0
EOF

cat > "$ROOT/opt/etc/init.d/S51nfqws2" <<'EOF'
#!/bin/sh
pidfile="$KD_TEST_ROOT/opt/var/run/nfqws2.pid"
stop_fixture() {
  if [ -f "$pidfile" ]; then
    pid="$(sed -n '1p' "$pidfile")"
    case "$pid" in
      ''|*[!0-9]*) ;;
      *) kill "$pid" 2>/dev/null || true ;;
    esac
    rm -f "$pidfile"
  fi
}
printf 'nfqws-init:%s\n' "$*" >> "$KD_TEST_ROOT/nfqws-init.log"
case "${1:-}" in
  stop) stop_fixture ;;
  start)
    sleep 300 &
    printf '%s\n' "$!" > "$pidfile"
    ;;
  restart)
    stop_fixture
    sleep 300 &
    printf '%s\n' "$!" > "$pidfile"
    ;;
esac
exit 0
EOF

chmod +x \
  "$ROOT/opt/etc/init.d/S05xkeen" \
  "$ROOT/opt/etc/init.d/S51nfqws2"

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
{
  "inbounds": [
    {"tag":"redirect","sniffing":{"enabled":true,"destOverride":["http","tls"]}},
    {"tag":"tproxy","sniffing":{"enabled":true,"destOverride":["quic"]}}
  ]
}
EOF
cat > "$ROOT/opt/etc/xray/configs/04_outbounds.json" <<'EOF'
{
  "outbounds": [
    {"tag":"vless-reality","protocol":"vless"},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]
}
EOF
cat > "$ROOT/opt/etc/xray/configs/05_routing.json" <<'EOF'
{
  "routing": {
    "rules": [
      {
        "type":"field",
        "inboundTag":["redirect","tproxy"],
        "outboundTag":"vless-reality",
        "domain":[
          "ext:zkeen.dat:domains",
          "ext:geosite_v2fly.dat:discord",
          "ext:zkeenip.dat:discord",
          "ext:zkeen.dat:youtube",
          "ext:geosite_v2fly.dat:youtube"
        ]
      },
      {
        "type":"field",
        "inboundTag":["redirect","tproxy"],
        "outboundTag":"vless-reality",
        "ip":[
          "ext:zkeenip.dat:discord",
          "ext:zkeenip.dat:youtube",
          "ext:zkeenip.dat:google"
        ]
      },
      {
        "type":"field",
        "inboundTag":["redirect","tproxy"],
        "outboundTag":"direct",
        "domain":["example.org"]
      }
    ]
  }
}
EOF

cat > "$ROOT/opt/etc/nfqws2/nfqws2.conf" <<'EOF'
NFQWS_BASE_ARGS="--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua"
NFQWS_ARGS="--filter-tcp=80,443 --filter-l7=http,tls"
NFQWS_ARGS_QUIC="--filter-udp=443 --filter-l7=quic"
NFQWS_ARGS_UDP="--filter-udp=443"
MODE_LIST="--hostlist=/opt/etc/nfqws2/lists/user.list"
MODE_ALL="--hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list"
MODE_AUTO="$MODE_LIST $MODE_ALL"
NFQWS_EXTRA_ARGS="$MODE_AUTO"
NFQWS_ARGS_IPSET=""
NFQWS_ARGS_CUSTOM=""
TCP_PORTS=80,443
UDP_PORTS=443
POLICY_NAME=""
POLICY_EXCLUDE=0
IPV6_ENABLED=0
ISP_INTERFACE="fixture-wan"
EOF

cp "$BLOB_SOURCE/tls_clienthello.bin" \
  "$ROOT/opt/etc/nfqws2/blobs/tls_clienthello.bin"
cp "$BLOB_SOURCE/quic_initial.bin" \
  "$ROOT/opt/etc/nfqws2/blobs/quic_initial.bin"

cat > "$MOCK_BIN/xkeen" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -v) echo "XKeen fixture" ;;
  -status) echo "running" ;;
  -cp|-cpe|-tp) echo "fixture" ;;
  -xtest)
    for f in "$KD_TEST_ROOT"/opt/etc/xray/configs/*.json; do
      jq -e . "$f" >/dev/null
    done
    ;;
esac
exit 0
EOF

cat > "$MOCK_BIN/opkg" <<'EOF'
#!/bin/sh
case "${1:-}" in
  status)
    printf 'Package: %s\nVersion: 1.0-test\nStatus: install user installed\n' "${2:-fixture}"
    ;;
  list-installed)
    echo "nfqws2-keenetic - 1.0-test"
    echo "ca-certificates - 1.0-test"
    echo "wget-ssl - 1.0-test"
    ;;
  update|install|remove) ;;
esac
exit 0
EOF

cat > "$MOCK_BIN/pidof" <<'EOF'
#!/bin/sh
case "${1:-}" in
  xray|nfqws2) exit 0 ;;
  *) exit 1 ;;
esac
EOF

cat > "$MOCK_BIN/ip" <<'EOF'
#!/bin/sh
case "$*" in
  "link show dev fixture-wan") exit 0 ;;
  "route get "*) echo "1.1.1.1 dev fixture-wan src 192.0.2.1"; exit 0 ;;
  "route show default") echo "default dev fixture-wan"; exit 0 ;;
  "-6 route get "*) echo "unreachable 2001:4860:4860::8888 dev lo error -128"; exit 0 ;;
  "-6 route show default") exit 0 ;;
esac
exit 1
EOF

cat > "$MOCK_BIN/iptables-save" <<'EOF'
#!/bin/sh
cat <<'RULES'
-A POSTROUTING -j nfqws_post
-A nfqws_post -o fixture-wan -j NFQUEUE --queue-num 300
RULES
EOF

chmod +x \
  "$MOCK_BIN/xkeen" \
  "$MOCK_BIN/opkg" \
  "$MOCK_BIN/pidof" \
  "$MOCK_BIN/ip" \
  "$MOCK_BIN/iptables-save"

run_tool() {
  PATH="$MOCK_BIN:$PATH" \
  KD_TEST_ROOT="$ROOT" \
  KD_ALLOW_TEST_ROOT=1 \
    sh "$TARGET" "$@"
}

run_service_tool() {
  PATH="$MOCK_BIN:$PATH" \
  KD_TEST_ROOT="$ROOT" \
  KD_ALLOW_TEST_ROOT=1 \
    sh "$SERVICE_TARGET" "$@"
}

routing_file="$ROOT/opt/etc/xray/configs/05_routing.json"
nfqws_file="$ROOT/opt/etc/nfqws2/nfqws2.conf"

assert_mode() {
  expected_tcp="$1"
  expected_voice="$2"
  expected_youtube="$3"

  # Discord TCP/QUIC: the domain rule goes to discord-direct unless vless.
  jq -e --arg mode "$expected_tcp" '
    if $mode != "vless"
    then any(.routing.rules[]?;
      .outboundTag == "discord-direct"
      and any(.domain[]?; contains("discord"))
    )
    else
      (any(.routing.rules[]?;
        .outboundTag == "discord-direct" and has("domain")
      ) | not)
      and any(.routing.rules[]?;
        .outboundTag == "vless-reality"
        and any(.domain[]?; contains("discord"))
      )
    end
  ' "$routing_file" >/dev/null

  # Discord Voice: the UDP port rule exists only outside vless.
  jq -e --arg mode "$expected_voice" '
    any(.routing.rules[]?;
      .outboundTag == "discord-direct"
      and .network == "udp"
      and .port == "3478-3481,5349,19294-19344,50000-50100"
    ) == ($mode != "vless")
  ' "$routing_file" >/dev/null

  jq -e '
    any(.routing.rules[]?;
      any(.domain[]?;
        . == "ext:geosite_v2fly.dat:discord"
      )
    )
    and (
      any(.routing.rules[]?;
        any((.domain // [])[]?, (.ip // [])[]?;
          type == "string"
          and startswith("ext:")
          and (ascii_downcase | contains("zkeenip.dat:discord"))
        )
      ) | not
    )
    and (
      any(.routing.rules[]?;
        any(.ip[]?;
          type == "string"
          and startswith("ext:")
          and (ascii_downcase | contains("discord"))
        )
      ) | not
    )
  ' "$routing_file" >/dev/null

  jq -e --arg mode "$expected_youtube" '
    if $mode != "vless"
    then any(.routing.rules[]?; .outboundTag == "youtube-direct")
    else
      (any(.routing.rules[]?; .outboundTag == "youtube-direct") | not)
      and any(.routing.rules[]?;
        .outboundTag == "vless-reality"
        and any(.domain[]?; contains("youtube"))
      )
    end
  ' "$routing_file" >/dev/null

  if [ "$expected_tcp" = "vless" ] && [ "$expected_voice" = "vless" ]; then
    [ ! -e "$ROOT/opt/etc/xray/configs/04_discord_nfqws2_outbound.json" ]
  else
    [ -f "$ROOT/opt/etc/xray/configs/04_discord_nfqws2_outbound.json" ]
  fi

  if [ "$expected_tcp" = "zapret" ]; then
    [ -s "$ROOT/opt/etc/nfqws2/lists/user.list" ]
    [ "$(ls -l "$ROOT/opt/etc/nfqws2/lists/user.list" | awk '{print $1}')" = "-rw-r--r--" ]
    grep -Fqx 'TCP_PORTS=80,443,2053,2083,2087,2096,8443' "$nfqws_file"
  else
    [ ! -s "$ROOT/opt/etc/nfqws2/lists/user.list" ]
    grep -Fqx 'TCP_PORTS=443' "$nfqws_file"
  fi

  if [ "$expected_voice" = "zapret" ]; then
    grep -Fq -- '--filter-l7=stun,discord' "$nfqws_file"
    grep -Fq -- '--blob=discord_udp:@/opt/etc/nfqws2/blobs/discord_udp.bin' "$nfqws_file"
    grep -Fq -- '--lua-desync=fake:blob=discord_udp:repeats=6' "$nfqws_file"
    grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:50100' "$nfqws_file"
  else
    grep -Fq 'NFQWS_ARGS_UDP=""' "$nfqws_file"
    grep -Fqx 'UDP_PORTS=443' "$nfqws_file"
  fi

  if [ "$expected_youtube" = "zapret" ]; then
    [ -f "$ROOT/opt/etc/xray/configs/04_youtube_nfqws2_outbound.json" ]
    [ "$(ls -l "$ROOT/opt/etc/nfqws2/lists/youtube.list" | awk '{print $1}')" = "-rw-r--r--" ]
    grep -Fq -- '--hostlist=/opt/etc/nfqws2/lists/youtube.list' "$nfqws_file"
    grep -Fq -- '--out-range=-d10' "$nfqws_file"
    grep -Fq -- '--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000' "$nfqws_file"
    grep -Fq -- '--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up' "$nfqws_file"
    grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=11' "$nfqws_file"
    grep -Fq 'if [ -n "$NFQWS_ARGS_CUSTOM" ]; then' "$nfqws_file"
    jq -e '
      any(.routing.rules[]?;
        .outboundTag == "vless-reality"
        and any(.domain[]?; contains("youtube"))
      ) | not
    ' "$routing_file" >/dev/null
  elif [ "$expected_youtube" = "direct" ]; then
    [ -f "$ROOT/opt/etc/xray/configs/04_youtube_nfqws2_outbound.json" ]
    if grep -Fq -- '--hostlist=/opt/etc/nfqws2/lists/youtube.list' "$nfqws_file"; then
      echo "ERROR: direct-only YouTube profile remains in nfqws2.conf" >&2
      exit 1
    fi
  else
    [ ! -e "$ROOT/opt/etc/xray/configs/04_youtube_nfqws2_outbound.json" ]
    if grep -Fq -- '--hostlist=/opt/etc/nfqws2/lists/youtube.list' "$nfqws_file"; then
      echo "ERROR: inactive YouTube profile remains in nfqws2.conf" >&2
      exit 1
    fi
  fi

  jq -e '
    any(.routing.rules[]?;
      .outboundTag == "vless-reality"
      and any(.ip[]?; . == "ext:zkeenip.dat:youtube")
    )
    and (
      any(.routing.rules[]?;
        .outboundTag == "youtube-direct"
        and any(.ip[]?; . == "ext:zkeenip.dat:youtube")
      ) | not
    )
  ' "$routing_file" >/dev/null

  sh -n "$nfqws_file"
  grep -Fqx "# Active routes: DiscordTCP=$expected_tcp, DiscordVoice=$expected_voice, YouTube=$expected_youtube." "$nfqws_file"

  if [ "$expected_tcp" = "$expected_voice" ]; then
    expected_discord="$expected_tcp"
  else
    expected_discord="mixed"
  fi
  status_output="$(run_tool --status)"
  printf '%s\n' "$status_output" |
    grep -Fqx "discord_route=$expected_discord"
  printf '%s\n' "$status_output" |
    grep -Fqx "discord_tcp_route=$expected_tcp"
  printf '%s\n' "$status_output" |
    grep -Fqx "discord_voice_route=$expected_voice"
  printf '%s\n' "$status_output" |
    grep -Fqx "youtube_route=$expected_youtube"
}

# apply_mode DISCORD YOUTUBE uses the legacy --discord-route shorthand.
apply_mode() {
  discord_mode="$1"
  youtube_mode="$2"
  run_tool \
    --apply \
    --yes-router \
    --core xray \
    --discord-route "$discord_mode" \
    --youtube-route "$youtube_mode" >/dev/null
  assert_mode "$discord_mode" "$discord_mode" "$youtube_mode"
}

apply_split_mode() {
  tcp_mode="$1"
  voice_mode="$2"
  youtube_mode="$3"
  run_tool \
    --apply \
    --yes-router \
    --core xray \
    --discord-tcp-route "$tcp_mode" \
    --discord-voice-route "$voice_mode" \
    --youtube-route "$youtube_mode" >/dev/null
  assert_mode "$tcp_mode" "$voice_mode" "$youtube_mode"
}

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

# A config written before the TCP/Voice split still reports both routes.
sed -i 's/^# Active routes: .*/# Active routes: Discord=zapret, YouTube=vless./' "$nfqws_file"
legacy_status="$(run_tool --status)"
printf '%s\n' "$legacy_status" | grep -Fqx 'discord_tcp_route=zapret'
printf '%s\n' "$legacy_status" | grep -Fqx 'discord_voice_route=zapret'
apply_mode zapret vless

# Focused tuner-profile operations must never stop or restart XKeen.
apply_mode zapret zapret
: > "$ROOT/xkeen-init.log"
: > "$ROOT/nfqws-init.log"
profile_args="$FIXTURE/youtube-args.txt"
cat > "$profile_args" <<'EOF'
--filter-tcp=443
--filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--out-range=-d10
--payload=tls_client_hello
--lua-desync=fake:blob=tls_clienthello:repeats=3
--new
--filter-udp=443
--filter-l7=quic
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--payload=quic_initial
--lua-desync=fake:blob=youtube_quic:repeats=7
EOF
profile_serialized="$FIXTURE/youtube-serialized.txt"
{
  printf '%s\n' youtube 'fixture BAT.bat' 'fixture fake profile'
  cat "$profile_args"
} | awk 'NR == 1 { text=$0; next } { text=text "\n" $0 } END { printf "%s", text }' > "$profile_serialized"
profile_id="$(sha256sum "$profile_serialized" | awk '{print substr($1,1,12)}')"
profile_stage="$ROOT/opt/tmp/youtube-profile.json"
jq -n \
  --arg id "$profile_id" \
  --rawfile args "$profile_args" '
  {
    format: 1,
    service: "youtube",
    candidate_id: $id,
    source_name: "fixture BAT.bat",
    source_sha: "fixture-sha",
    source_url: "https://example.invalid/fixture",
    family: "fixture fake profile",
    args: ($args | split("\n") | map(select(length > 0))),
    notes: ["fixture"],
    rank: 10,
    report: {
      repository: "fixture",
      ref: "main",
      commit: "abc",
      created_utc: "2026-07-23T00:00:00Z",
      search_seed: 123456
    }
  }' > "$profile_stage"

run_tool --apply-import-profile "$profile_stage" --yes-router >/dev/null
[ ! -s "$ROOT/xkeen-init.log" ]
grep -Fqx 'nfqws-init:restart' "$ROOT/nfqws-init.log"
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=7' "$nfqws_file"
[ -f "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json" ]
[ "$(jq -r '.report.search_seed' "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json")" = "123456" ]
[ -s "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr" ]
[ "$(find "$ROOT/opt/etc/nfqws2/profile-versions/youtube" -type f -name '*-applied-*.json' | wc -l | tr -d '[:space:]')" = "1" ]

: > "$ROOT/xkeen-init.log"
: > "$ROOT/nfqws-init.log"
run_tool --clear-imported-profile youtube --yes-router >/dev/null
[ ! -s "$ROOT/xkeen-init.log" ]
grep -Fqx 'nfqws-init:restart' "$ROOT/nfqws-init.log"
[ ! -e "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json" ]
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=11' "$nfqws_file"
[ "$(find "$ROOT/opt/etc/nfqws2/profile-versions/youtube" -type f | wc -l | tr -d '[:space:]')" = "2" ]

: > "$ROOT/xkeen-init.log"
: > "$ROOT/nfqws-init.log"
run_tool --rollback-import --yes-router >/dev/null
[ ! -s "$ROOT/xkeen-init.log" ]
grep -Fq 'nfqws-init:stop' "$ROOT/nfqws-init.log"
grep -Fq 'nfqws-init:start' "$ROOT/nfqws-init.log"
[ -f "$ROOT/opt/etc/nfqws2/imported-profiles/youtube.json" ]
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=7' "$nfqws_file"
[ "$(find "$ROOT/opt/etc/nfqws2/profile-versions/youtube" -type f | wc -l | tr -d '[:space:]')" = "1" ]

bad_stage="$ROOT/opt/tmp/youtube-profile-bad.json"
jq '.candidate_id = "000000000000"' "$profile_stage" > "$bad_stage"
before_bad_import="$(sha256sum "$nfqws_file" | awk '{print $1}')"
: > "$ROOT/xkeen-init.log"
if run_tool --apply-import-profile "$bad_stage" --yes-router >/dev/null 2>&1; then
  echo "ERROR: invalid imported candidate unexpectedly passed." >&2
  exit 1
fi
[ ! -s "$ROOT/xkeen-init.log" ]
[ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$before_bad_import" ]

echo "routing-mode-tests-ok"
