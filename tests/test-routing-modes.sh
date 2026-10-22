#!/bin/sh
set -eu

# Integration test for the direct/zapret/vless route combinations. It must run on
# Linux/Entware with real jq. All router paths are redirected to a disposable
# fixture; service, package, route and firewall commands are mocked.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"
SERVICE_TARGET="$SCRIPT_DIR/set-service-route.sh"
BLOB_SOURCE="${NFQWS_TEST_BLOB_SOURCE:-/opt/etc/nfqws2/blobs}"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-routing-modes.XXXXXX")"
ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"
# shellcheck source=tests/engine-nfqws2-fixture.sh
. "$SCRIPT_DIR/tests/engine-nfqws2-fixture.sh"

safe_cleanup() {
  ws_pidfile="$ROOT/opt/var/run/kdn-telegram-ws.pid"
  if [ -f "$ws_pidfile" ]; then
    kill "$(sed -n '1p' "$ws_pidfile")" 2>/dev/null || true
  fi
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
  "$ROOT/opt/bin" \
  "$MOCK_BIN"
# The Telegram WS relay runs on the real Python, on a free port.
ln -s "$(command -v python3)" "$ROOT/opt/bin/python3"
KD_TEST_TELEGRAM_WS_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
export KD_TEST_TELEGRAM_WS_PORT

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

# E13 (optional): KD_TEST_NFQWS2_BIN=<real nfqws2 build> and
# KD_TEST_NFQWS2_LUA_SRC=<its lua directory> make every apply and import run
# the real "nfqws2 --dry-run" on the composed arguments. The real binary
# checks the lists as the unprivileged nfqws2 user, so the fixture becomes
# world-readable.
if [ -n "${KD_TEST_NFQWS2_BIN:-}" ]; then
  [ -x "$KD_TEST_NFQWS2_BIN" ]
  [ -f "${KD_TEST_NFQWS2_LUA_SRC:?KD_TEST_NFQWS2_LUA_SRC is required with KD_TEST_NFQWS2_BIN}/zapret-lib.lua" ]
  cp -R "$KD_TEST_NFQWS2_LUA_SRC" "$FIXTURE/real-lua"
  chmod 755 "$FIXTURE"
  chmod -R a+rX "$FIXTURE"
  KD_TEST_NFQWS2_LUA="$FIXTURE/real-lua"
  export KD_TEST_NFQWS2_BIN KD_TEST_NFQWS2_LUA
  echo "Real nfqws2 dry-run: $KD_TEST_NFQWS2_BIN"
fi
engine_write_nfqws2_init "$ROOT/opt/etc/init.d/S51nfqws2"
engine_write_fake_nfqws2 "$ROOT/opt/usr/bin/nfqws2"

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
        "outboundTag":"block",
        "domain":[
          "ext:geosite_v2fly.dat:youtube",
          "ext:geosite_v2fly.dat:discord"
        ]
      },
      {
        "type":"field",
        "inboundTag":["redirect","tproxy"],
        "outboundTag":"block",
        "domain":["ext:geosite_v2fly.dat:youtube"],
        "ip":["ext:geoip.dat:private"]
      },
      {
        "type":"field",
        "inboundTag":["redirect","tproxy"],
        "outboundTag":"direct",
        "domain":["example.org"]
      },
      {
        "type":"field",
        "inboundTag":["redirect","tproxy"],
        "outboundTag":"direct",
        "domain":["domain:web.telegram.org"]
      }
    ]
  }
}
EOF

engine_write_stock_nfqws2_conf "$ROOT/opt/etc/nfqws2/nfqws2.conf" fixture-wan 0

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
    # A test can simulate "opkg upgrade" by writing a version to this file.
    version="$(cat "$KD_TEST_ROOT/opkg-version" 2>/dev/null || echo 1.0-test)"
    printf 'Package: %s\nVersion: %s\nStatus: install user installed\n' "${2:-fixture}" "$version"
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

engine_write_iptables_mocks "$MOCK_BIN"

chmod +x \
  "$MOCK_BIN/xkeen" \
  "$MOCK_BIN/opkg" \
  "$MOCK_BIN/pidof" \
  "$MOCK_BIN/ip"

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

# A killed process can stay a zombie in containers without a reaper.
process_alive() {
  kill -0 "$1" 2>/dev/null || return 1
  ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
}

routing_file="$ROOT/opt/etc/xray/configs/05_routing.json"
nfqws_file="$ROOT/opt/etc/nfqws2/nfqws2.conf"

# Relays of this fixture (its port), zombies excluded.
relay_count() {
  relay_total=0
  for relay_cmdline in $(grep -Fl -- "$SCRIPT_DIR/tools/router/telegram_ws_relay.py" /proc/[0-9]*/cmdline 2>/dev/null); do
    relay_proc_pid="${relay_cmdline#/proc/}"
    relay_proc_pid="${relay_proc_pid%/cmdline}"
    process_alive "$relay_proc_pid" || continue
    tr '\0' ' ' 2>/dev/null < "$relay_cmdline" |
      grep -Fq -- "--listen 127.0.0.1:$KD_TEST_TELEGRAM_WS_PORT" &&
      relay_total=$((relay_total + 1))
  done
  echo "$relay_total"
}

# make_stage SERVICE FILE ARG...: a tuner descriptor for --apply-import-profile.
make_stage() {
  stage_service="$1"
  stage_file="$2"
  shift 2
  printf '%s\n' "$@" > "$FIXTURE/stage-args.txt"
  stage_id="$(
    { printf '%s\n' "$stage_service" 'fixture BAT.bat' 'fixture profile'; cat "$FIXTURE/stage-args.txt"; } |
      awk 'NR == 1 { text=$0; next } { text=text "\n" $0 } END { printf "%s", text }' |
      sha256sum | cut -c1-12
  )"
  jq -n --arg id "$stage_id" --arg service "$stage_service" --rawfile args "$FIXTURE/stage-args.txt" '{
    format: 1, service: $service, candidate_id: $id,
    source_name: "fixture BAT.bat", source_sha: "s", source_url: "https://example.invalid/f",
    family: "fixture profile", args: ($args | split("\n") | map(select(length > 0))),
    notes: [], rank: 1, report: {}
  }' > "$stage_file"
}

# The composed profiles without the global options, one per line and keyed
# by service: discord-tcp/discord-udp (user.list), youtube-*, telegram-tcp,
# voice-udp (E12).
profile_digest() {
  run_tool --print-nfqws-profiles | awk -F'|' '{
    n = split($4, words, " ")
    text = ""
    for (i = 1; i <= n; i++)
      if (words[i] !~ /^--(user|qnum|fastpath-workaround|lua-init|blob|debug|bind-fix4|bind-fix6)(=|$)/)
        text = text " " words[i]
    if (text ~ /--filter-l7=stun,discord/) key = "voice"
    else if (text ~ /kdn-telegram\.list/) key = "telegram"
    else if (text ~ /youtube\.list/) key = "youtube"
    else if (text ~ /user\.list/) key = "discord"
    else key = "other"
    print key (text ~ /--filter-udp=/ ? "-udp" : "-tcp") "|" text
  }' | sort
}

# assert_profiles_same_except BEFORE AFTER PREFIX: only the profiles whose
# key starts with PREFIX may differ.
assert_profiles_same_except() {
  printf '%s\n' "$1" | grep -v "^$3" > "$FIXTURE/digest-before" || true
  printf '%s\n' "$2" | grep -v "^$3" > "$FIXTURE/digest-after" || true
  cmp -s "$FIXTURE/digest-before" "$FIXTURE/digest-after" || {
    echo "ERROR: an operation on $3 changed other services' nfqws2 profiles:" >&2
    diff "$FIXTURE/digest-before" "$FIXTURE/digest-after" >&2 || true
    exit 1
  }
}

# The generated config must pass both the engine's own --check-config and the
# independent tests/engine-check-profiles.sh. Warnings are allowed only for
# queued ports without a profile (UDP 443 when no QUIC profile is active).
assert_config_checks() {
  check_output="$(run_tool --check-config)" || {
    printf '%s\n' "$check_output" >&2
    echo "ERROR: --check-config failed" >&2
    exit 1
  }
  if printf '%s\n' "$check_output" | grep -v '^CHECK|ok|' | grep -v '^CHECK|warn|unhandled-ports|' | grep -q .; then
    printf '%s\n' "$check_output" >&2
    echo "ERROR: unexpected --check-config findings" >&2
    exit 1
  fi
  independent_check="$(sh "$SCRIPT_DIR/tests/engine-check-profiles.sh" "$ROOT")" || {
    printf '%s\n' "$independent_check" >&2
    exit 1
  }
}

assert_mode() {
  expected_tcp="$1"
  expected_voice="$2"
  expected_youtube="$3"
  expected_telegram="${4:-unmanaged}"

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
    expected_tcp_ports="80,443,2053,2083,2087,2096,8443"
    if grep -Fqx 'NFQWS_ARGS_QUIC=""' "$nfqws_file"; then
      echo "ERROR: the Discord QUIC profile is disabled with Discord TCP=zapret" >&2
      exit 1
    fi
  else
    # nfqws2 reads an empty hostlist as "no host filter": the package TCP
    # profile that reads user.list must get an inert entry, and the package
    # QUIC profile is dropped (A1/B2).
    [ "$(cat "$ROOT/opt/etc/nfqws2/lists/user.list")" = "kdn-disabled.invalid" ]
    grep -Fqx 'NFQWS_ARGS_QUIC=""' "$nfqws_file"
    expected_tcp_ports="443"
  fi
  grep -Fq "NFQWS_ARGS=\"--filter-tcp=$expected_tcp_ports " "$nfqws_file"
  grep -Fqx "TCP_PORTS=$expected_tcp_ports" "$nfqws_file"

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

  # The two "block" fixture rules match only managed Discord/YouTube domains.
  # Stripping those selectors must drop the rules, never leave a rule with a
  # wider match (no domain at all, or only the unrelated IP condition).
  jq -e '
    (any(.routing.rules[]?; .outboundTag == "block") | not)
    and any(.routing.rules[]?;
      .outboundTag == "direct" and .domain == ["example.org"]
    )
  ' "$routing_file" >/dev/null

  assert_telegram "$expected_telegram"

  # Xray refuses to start when two rules share a ruleTag.
  jq -e '[.routing.rules[]? | .ruleTag? // empty] | length == (unique | length)' \
    "$routing_file" >/dev/null
  xray_config_test

  sh -n "$nfqws_file"
  assert_config_checks
  grep -Fqx "# Active routes: DiscordTCP=$expected_tcp, DiscordVoice=$expected_voice, YouTube=$expected_youtube, Telegram=$expected_telegram." "$nfqws_file"

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
  printf '%s\n' "$status_output" |
    grep -Fqx "telegram_route=$expected_telegram"
}

telegram_outbound_file="$ROOT/opt/etc/xray/configs/04_telegram_nfqws2_outbound.json"

# Optional check with a real Xray binary: KD_TEST_XRAY_BIN=/path/to/xray and
# KD_TEST_XRAY_ASSETS=dir with geosite_v2fly.dat, geoip_v2fly.dat, zkeen.dat
# and zkeenip.dat. The fixture inbounds/outbounds are placeholders, so valid
# ones replace them in a copy; the generated routing and outbounds are tested.
xray_config_test() {
  [ -n "${KD_TEST_XRAY_BIN:-}" ] || return 0
  xray_test_dir="$FIXTURE/xray-test"
  rm -rf "$xray_test_dir"
  cp -a "$ROOT/opt/etc/xray/configs" "$xray_test_dir"
  cat > "$xray_test_dir/03_inbounds.json" <<'EOF'
{"inbounds":[
 {"tag":"redirect","port":61219,"protocol":"dokodemo-door","settings":{"network":"tcp","followRedirect":true},"sniffing":{"enabled":true,"routeOnly":true,"destOverride":["http","tls"]}},
 {"tag":"tproxy","port":61219,"protocol":"dokodemo-door","settings":{"network":"udp","followRedirect":true},"streamSettings":{"sockopt":{"tproxy":"tproxy"}},"sniffing":{"enabled":true,"routeOnly":true,"destOverride":["quic"]}}
]}
EOF
  cat > "$xray_test_dir/04_outbounds.json" <<'EOF'
{"outbounds":[
 {"tag":"vless-reality","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"6f1c7e0a-6b1a-4c35-9a52-7a3f2b8e9c10","encryption":"none"}]}]}},
 {"tag":"direct","protocol":"freedom"},
 {"tag":"block","protocol":"blackhole"}
]}
EOF
  XRAY_LOCATION_ASSET="$KD_TEST_XRAY_ASSETS" \
    "$KD_TEST_XRAY_BIN" run -test -confdir "$xray_test_dir" > "$FIXTURE/xray-test.log" 2>&1 || {
    echo "ERROR: real Xray rejects the generated configuration:" >&2
    cat "$FIXTURE/xray-test.log" >&2
    exit 1
  }
}

assert_telegram() {
  # The list is always installed; it is inert without the profile.
  [ "$(ls -l "$ROOT/opt/etc/nfqws2/lists/kdn-telegram.list" | awk '{print $1}')" = "-rw-r--r--" ]
  cmp -s "$ROOT/opt/etc/nfqws2/lists/kdn-telegram.list" "$SCRIPT_DIR/config/telegram-user.list"

  # The user's own Telegram rule (fixture) is never touched.
  jq -e '
    any(.routing.rules[]?;
      .outboundTag == "direct" and .domain == ["domain:web.telegram.org"])
  ' "$routing_file" >/dev/null

  case "$1" in
    unmanaged)
      jq -e 'any(.routing.rules[]?; ((.ruleTag? // "") | tostring | startswith("kdn-telegram"))) | not' "$routing_file" >/dev/null
      [ ! -e "$telegram_outbound_file" ]
      ;;
    vless)
      jq -e '
        ([.routing.rules[]? | select(((.ruleTag? // "") | tostring | startswith("kdn-telegram"))) | .outboundTag]
          == ["vless-reality", "vless-reality"])
      ' "$routing_file" >/dev/null
      [ ! -e "$telegram_outbound_file" ]
      ;;
    ws)
      jq -e '
        [.routing.rules[]? | select(((.ruleTag? // "") | tostring | startswith("kdn-telegram")))] as $rules
        | ($rules | map(.ruleTag)) == ["kdn-telegram-domain", "kdn-telegram-sniffed", "kdn-telegram-ip", "kdn-telegram-udp"]
        and ($rules | map(.outboundTag)) == ["telegram-direct", "telegram-direct", "telegram-ws", "telegram-direct"]
        and $rules[1].protocol == ["http", "tls", "quic"] and $rules[2].network == "tcp"
      ' "$routing_file" >/dev/null
      jq -e --arg redirect "127.0.0.1:$KD_TEST_TELEGRAM_WS_PORT" '
        any(.outbounds[]; .tag == "telegram-ws" and .settings.redirect == $redirect)
        and any(.outbounds[]; .tag == "telegram-direct")
      ' "$telegram_outbound_file" >/dev/null
      [ -x "$ROOT/opt/etc/init.d/S99kdn-telegram-ws" ]
      grep -Fq -- '--cf-domains-file "$CF_DOMAINS" --cf-ips-file "$CF_IPS"' "$ROOT/opt/etc/init.d/S99kdn-telegram-ws"
      kill -0 "$(cat "$ROOT/opt/var/run/kdn-telegram-ws.pid")"
      python3 -c 'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 3).close()' \
        "$KD_TEST_TELEGRAM_WS_PORT"
      ;;
    direct)
      jq -e '
        [.routing.rules[]? | select(((.ruleTag? // "") | tostring | startswith("kdn-telegram")))] as $rules
        | ($rules | map(.outboundTag)) == ["telegram-direct", "telegram-direct"]
        and ($rules[0].domain == ["ext:geosite_v2fly.dat:telegram"])
        and ($rules[1].ip == ["ext:geoip_v2fly.dat:telegram"])
      ' "$routing_file" >/dev/null
      jq -e '.outbounds[0].tag == "telegram-direct"' "$telegram_outbound_file" >/dev/null
      ;;
  esac

  if [ "$1" != ws ] && [ -e "$ROOT/opt/etc/init.d/S99kdn-telegram-ws" ]; then
    echo "ERROR: Telegram WS relay left behind with Telegram=$1" >&2
    exit 1
  fi
  if [ "$1" = "ws" ]; then
    # The TLS profile stays for the Telegram domains; the relay's Cloudflare
    # domains are not in it.
    grep -Fq -- '--hostlist=/opt/etc/nfqws2/lists/kdn-telegram.list' "$nfqws_file"
    if grep -Fq -- '--ipset=/opt/etc/nfqws2/lists/kdn-telegram-ip.list' "$nfqws_file"; then
      echo "ERROR: MTProto profile active although MTProto goes through the WS relay" >&2
      exit 1
    fi
    # Telegram registers its own TLS blob and uses only that name.
    grep -Fq -- '--blob=telegram_tls:@/opt/etc/nfqws2/blobs/tls_clienthello.bin' "$nfqws_file"
  elif grep -Fq -- 'telegram' "$nfqws_file"; then
    echo "ERROR: Telegram profile present with Telegram=$1" >&2
    exit 1
  fi

  # The MTProto ipset belonged to the removed Telegram Zapret route.
  [ ! -e "$ROOT/opt/etc/nfqws2/lists/kdn-telegram-ip.list" ]
  [ ! -e "$ROOT/opt/etc/nfqws2/lists/kdn-telegram-cf.list" ]

  # A restrictive port_proxying.lst gets 5222 for managed Telegram only.
  if grep -qx '# BEGIN keenetic-discord-nfqws2' "$ROOT/opt/etc/xkeen/port_proxying.lst"; then
    managed_ports="$(sed -n '/^# BEGIN keenetic-discord-nfqws2$/,/^# END keenetic-discord-nfqws2$/p' \
      "$ROOT/opt/etc/xkeen/port_proxying.lst")"
    if [ "$1" = "unmanaged" ]; then
      if printf '%s\n' "$managed_ports" | grep -qx 5222; then
        echo "ERROR: unmanaged Telegram added port 5222" >&2
        exit 1
      fi
    else
      printf '%s\n' "$managed_ports" | grep -qx 5222
    fi
    # Telegram call UDP ports reach Xray only for Telegram=vless (E9).
    if [ "$1" = vless ]; then
      printf '%s\n' "$managed_ports" | grep -qx '590:600'
      printf '%s\n' "$managed_ports" | grep -qx 1400
    elif printf '%s\n' "$managed_ports" | grep -Eqx '590:600|1400'; then
      echo "ERROR: Telegram call ports proxied with Telegram=$1" >&2
      exit 1
    fi
  fi
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

# apply_split_mode TCP VOICE YOUTUBE [TELEGRAM]: TELEGRAM is the route the
# engine is expected to keep (the option is not passed).
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
  assert_mode "$tcp_mode" "$voice_mode" "$youtube_mode" "${4:-unmanaged}"
}

# Install standalone first: the baseline then covers nfqws2 only. The first
# integrated apply must add an XKeen baseline so that --rollback can still
# return Xray to its original files (checked at the end of this test).
original_routing_hash="$(sha256sum "$routing_file" | awk '{print $1}')"
original_nfqws_hash="$(sha256sum "$nfqws_file" | awk '{print $1}')"
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
PATH="$MOCK_BIN:$PATH" KD_TEST_ROOT="$ROOT" KD_ALLOW_TEST_ROOT=1 \
  sh "$SCRIPT_DIR/set-zapret-mode.sh" both --yes-router --core auto >/dev/null
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$original_routing_hash" ]
[ ! -s "$ROOT/xkeen-init.log" ]
if PATH="$MOCK_BIN:$PATH" KD_TEST_ROOT="$ROOT" KD_ALLOW_TEST_ROOT=1 \
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

# A package upgrade after the import snapshot: its Lua scripts stay.
printf '%s\n' 'NFQWS2_COMPAT_VER_REQUIRED=7' > "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
: > "$ROOT/xkeen-init.log"
: > "$ROOT/nfqws-init.log"
run_tool --rollback-import --yes-router >/dev/null
grep -Fqx 'NFQWS2_COMPAT_VER_REQUIRED=7' "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
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

# An imported Voice profile replaces only the Discord UDP profile: QUIC
# (UDP 443) must stay in the NFQUEUE ports for the YouTube/base QUIC profiles.
voice_args="$FIXTURE/voice-args.txt"
cat > "$voice_args" <<'EOF'
--filter-udp=19294-19344,50000-50100
--filter-l7=stun,discord
--out-range=<n2
--payload=stun,discord_ip_discovery
--lua-desync=fake:blob=discord_udp:repeats=6
EOF
voice_serialized="$FIXTURE/voice-serialized.txt"
{
  printf '%s\n' discord-voice 'fixture BAT.bat' 'fixture voice profile'
  cat "$voice_args"
} | awk 'NR == 1 { text=$0; next } { text=text "\n" $0 } END { printf "%s", text }' > "$voice_serialized"
voice_id="$(sha256sum "$voice_serialized" | awk '{print substr($1,1,12)}')"
voice_stage="$ROOT/opt/tmp/voice-profile.json"
jq '.service = "discord-voice" | .family = "fixture voice profile" | .candidate_id = $id
    | .args = ($args | split("\n") | map(select(length > 0)))' \
  --arg id "$voice_id" --rawfile args "$voice_args" "$profile_stage" > "$voice_stage"
run_tool --apply-import-profile "$voice_stage" --yes-router >/dev/null
[ -f "$ROOT/opt/etc/nfqws2/imported-profiles/discord-voice.json" ]
grep -Fqx 'UDP_PORTS=443,19294:19344,50000:50100' "$nfqws_file"
grep -Fq 'NFQWS_ARGS_UDP="--filter-udp=19294-19344,50000-50100' "$nfqws_file"
grep -Fq -- '--lua-desync=fake:blob=youtube_quic:repeats=7' "$nfqws_file"
run_tool --clear-imported-profile discord-voice --yes-router >/dev/null
[ ! -e "$ROOT/opt/etc/nfqws2/imported-profiles/discord-voice.json" ]
grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:50100' "$nfqws_file"
assert_config_checks
# The blocks below start from the built-in profiles.
run_tool --clear-imported-profile youtube --yes-router >/dev/null
assert_mode zapret zapret zapret

# --- D2/A2/B4/E4/E12: a Discord TCP import changes only the Discord TCP
# profile; the package QUIC profile keeps its user.list hostlist.
digest_before="$(profile_digest)"
make_stage discord-tcp "$ROOT/opt/tmp/dtcp-profile.json" \
  --filter-tcp=443 --filter-l7=tls --hostlist=/opt/etc/nfqws2/lists/user.list \
  --payload=tls_client_hello --lua-desync=fake:blob=tls_clienthello:repeats=6 \
  --lua-desync=multisplit:pos=1,midsld
run_tool --apply-import-profile "$ROOT/opt/tmp/dtcp-profile.json" --yes-router >/dev/null
assert_profiles_same_except "$digest_before" "$(profile_digest)" discord-tcp
grep -Fqx 'NFQWS_EXTRA_ARGS="$MODE_LIST"' "$nfqws_file"
# Only TCP 443 has a profile now (no queued port without a profile).
grep -Fqx 'TCP_PORTS=443' "$nfqws_file"
assert_config_checks
run_tool --check-config | grep -Fqx 'CHECK|ok|unhandled-ports|every queued port has a profile'
run_tool --clear-imported-profile discord-tcp --yes-router >/dev/null
[ "$(profile_digest)" = "$digest_before" ]
grep -Fqx 'TCP_PORTS=80,443,2053,2083,2087,2096,8443' "$nfqws_file"

# --- --check-config finds the broken states it exists for. Each case edits
# the live config and puts it back.
cp "$nfqws_file" "$FIXTURE/conf.saved"
cp "$ROOT/opt/etc/nfqws2/lists/user.list" "$FIXTURE/user.list.saved"
expect_check() {
  expect_rc="$1"
  expect_line="$2"
  check_rc=0
  check_text="$(run_tool --check-config)" || check_rc=$?
  [ "$check_rc" = "$expect_rc" ] || {
    printf '%s\n' "$check_text" >&2
    echo "ERROR: --check-config exit $check_rc, expected $expect_rc" >&2
    exit 1
  }
  printf '%s\n' "$check_text" | grep -Eq "$expect_line" || {
    printf '%s\n' "$check_text" >&2
    echo "ERROR: --check-config lacks: $expect_line" >&2
    exit 1
  }
  cp "$FIXTURE/conf.saved" "$nfqws_file"
  cp "$FIXTURE/user.list.saved" "$ROOT/opt/etc/nfqws2/lists/user.list"
}
# The 3.1.0 incident: the YouTube QUIC profile on UDP 443, 443 not queued.
sed -i 's/^UDP_PORTS=.*/UDP_PORTS=19294:19344,50000:50100/' "$nfqws_file"
expect_check 1 '^CHECK\|error\|port-coverage\|.* UDP 443 outside UDP_PORTS'
# A1: the empty user.list of the earlier releases.
: > "$ROOT/opt/etc/nfqws2/lists/user.list"
expect_check 1 '^CHECK\|error\|empty-hostlist\|/opt/etc/nfqws2/lists/user.list has no entries'
# D2: NFQWS_EXTRA_ARGS="" leaves the package QUIC profile without a list.
sed -i 's/^NFQWS_EXTRA_ARGS=.*/NFQWS_EXTRA_ARGS=""/' "$nfqws_file"
expect_check 1 '^CHECK\|error\|listless-profile\|#[0-9]+ udp=443 l7=quic'
# The legacy UDP fake of 3.1.x without blob=.
sed -i 's/^NFQWS_EXTRA_ARGS=.*/&\nNFQWS_ARGS_UDP="--filter-udp=3478 --filter-l7=stun,discord --lua-desync=fake:repeats=6:strategy=1"/' "$nfqws_file"
expect_check 1 '^CHECK\|error\|legacy-blob\|.*fake:repeats=6:strategy=1'
# A user's own listless custom profile is reported, not refused; its ports
# are taken into the queue by the next apply (A3).
sed -i 's/^NFQWS_ARGS_CUSTOM=""$/NFQWS_ARGS_CUSTOM="--filter-udp=1400 --lua-desync=fake:blob=quic_initial"/' "$nfqws_file"
expect_check 0 '^CHECK\|warn\|listless-profile\|#1 udp=1400 \(user profile\)'
mv "$nfqws_file" "$FIXTURE/conf.moved"
expect_check 2 '^CHECK\|error\|read\|'
[ -f "$nfqws_file" ]

# --- A3: the ports of the user's own custom profiles stay queued.
sed -i 's/^NFQWS_ARGS_CUSTOM=""$/NFQWS_ARGS_CUSTOM="--filter-udp=1400 --filter-l7=mtproto --hostlist=\/opt\/etc\/nfqws2\/lists\/user.list --lua-desync=fake:blob=quic_initial --new --filter-tcp=1984 --hostlist=\/opt\/etc\/nfqws2\/lists\/user.list --lua-desync=multisplit"/' "$nfqws_file"
run_tool --apply --yes-router --core xray --discord-route zapret --youtube-route zapret >/dev/null
assert_config_checks
grep -Fqx 'TCP_PORTS=80,443,2053,2083,2087,2096,8443,1984' "$nfqws_file"
grep -Fqx 'UDP_PORTS=443,3478:3481,5349,19294:19344,50000:50100,1400' "$nfqws_file"
run_tool --print-nfqws-profiles | grep -q '^PROFILE|2|user|--filter-tcp=1984'
cp "$FIXTURE/conf.saved" "$nfqws_file"
apply_mode zapret zapret

# --- A8/C1: identical applies give identical files (restrictive port list).
printf '%s\n' '# restricted fixture' 443 > "$ROOT/opt/etc/xkeen/port_proxying.lst"
apply_mode zapret zapret
cp "$nfqws_file" "$FIXTURE/idem.conf"
cp "$ROOT/opt/etc/xkeen/port_proxying.lst" "$FIXTURE/idem.ports"
cp "$routing_file" "$FIXTURE/idem.routing"
apply_mode zapret zapret
cmp "$nfqws_file" "$FIXTURE/idem.conf"
cmp "$ROOT/opt/etc/xkeen/port_proxying.lst" "$FIXTURE/idem.ports"
cmp "$routing_file" "$FIXTURE/idem.routing"
run_tool --apply-import-profile "$voice_stage" --yes-router >/dev/null
run_tool --clear-imported-profile discord-voice --yes-router >/dev/null
cmp "$nfqws_file" "$FIXTURE/idem.conf"
printf '%s\n' '# unrestricted fixture' > "$ROOT/opt/etc/xkeen/port_proxying.lst"

# --- The apply fails and rolls back when the checks, the dry-run or the
# restart verification fail; --rollback-latest still undoes the last
# successful apply afterwards (C4).
apply_mode zapret zapret
latest_before="$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")"
conf_before="$(sha256sum "$nfqws_file" | awk '{print $1}')"
expect_failed_apply() {
  # Voice off changes UDP_PORTS, so stale firewall rules show.
  if run_tool --apply --yes-router --core xray --discord-tcp-route zapret --discord-voice-route vless \
       --youtube-route vless > "$FIXTURE/failed.log" 2>&1; then
    echo "ERROR: apply passed although $1" >&2
    exit 1
  fi
  grep -Fq "$2" "$FIXTURE/failed.log" || {
    cat "$FIXTURE/failed.log" >&2
    echo "ERROR: missing: $2" >&2
    exit 1
  }
  grep -Fq 'Starting automatic rollback' "$FIXTURE/failed.log"
  [ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$conf_before" ]
  [ "$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")" = "$latest_before" ]
  [ "${3:-}" = edited ] || assert_mode zapret zapret zapret
}
# A stock QUIC profile edited onto a port the engine does not queue.
sed -i 's/^NFQWS_ARGS_QUIC="--filter-udp=443 /NFQWS_ARGS_QUIC="--filter-udp=443,4433 /' "$nfqws_file"
conf_before="$(sha256sum "$nfqws_file" | awk '{print $1}')"
expect_failed_apply "a profile port is not queued" 'filters UDP 4433 outside UDP_PORTS' edited
cp "$FIXTURE/conf.saved" "$nfqws_file"
conf_before="$(sha256sum "$nfqws_file" | awk '{print $1}')"
# (The fixture binary's knob; a real KD_TEST_NFQWS2_BIN accepts the config.)
if [ -z "${KD_TEST_NFQWS2_BIN:-}" ]; then
  touch "$ROOT/nfqws2.fail-dry-run"
  expect_failed_apply "nfqws2 --dry-run failed" 'nfqws2 --dry-run rejects the generated arguments'
  rm -f "$ROOT/nfqws2.fail-dry-run"
fi
# nfqws2-ui "stale PID": the init leaves the old daemon running.
touch "$ROOT/nfqws-init.keep-old"
expect_failed_apply "the old nfqws2 still runs" 'still runs as the old process'
rm -f "$ROOT/nfqws-init.keep-old"
# The firewall still queues the ports of the previous config (A6).
touch "$ROOT/nfqws-init.stale-rules"
expect_failed_apply "the NFQUEUE rules are stale" 'udp NFQUEUE rule for fixture-wan queues'
rm -f "$ROOT/nfqws-init.stale-rules"
# A daemon that runs without the profiles of the config.
touch "$ROOT/nfqws-init.wrong-args"
expect_failed_apply "nfqws2 runs other arguments" 'was not started with the arguments of the current nfqws2.conf'
rm -f "$ROOT/nfqws-init.wrong-args"
# A process with a recycled PID or a test instance is not the service.
apply_mode zapret zapret
kill "$(cat "$ROOT/opt/var/run/nfqws2.pid")" 2>/dev/null || true
python3 -c 'import time; time.sleep(600)' nfqws2 --qnum=301 </dev/null >/dev/null 2>&1 &
test_instance=$!
printf '%s\n' "$test_instance" > "$ROOT/opt/var/run/nfqws2.pid"
run_tool --status | grep -Fqx 'nfqws_runtime=stopped'
kill "$test_instance"
rm -f "$ROOT/opt/var/run/nfqws2.pid"
apply_mode zapret zapret
run_tool --status | grep -Fqx 'nfqws_runtime=running'
cmp -s "$nfqws_file" "$FIXTURE/conf.saved" || cp "$nfqws_file" "$FIXTURE/conf.saved"

# --- An autotune runner that died left its candidate nfqws2 and state file:
# the next operation under the project lock cleans up.
sh -c 'exit 0' &
dead_runner=$!
wait "$dead_runner" || true
python3 -c 'import time; time.sleep(600)' nfqws2 --qnum=301 </dev/null >/dev/null 2>&1 &
orphan_candidate=$!
mkdir -p "$ROOT/opt/tmp/zapret-tuner.$dead_runner"
printf 'runner_pid=%s\ncandidate_pid=%s\nwas_running=1\nprepared=1\n' "$dead_runner" "$orphan_candidate" \
  > "$ROOT/opt/tmp/zapret-tuner.$dead_runner/runtime.state"
apply_mode zapret zapret
[ ! -e "$ROOT/opt/tmp/zapret-tuner.$dead_runner" ]
if process_alive "$orphan_candidate"; then
  echo "ERROR: the orphaned autotune candidate still runs" >&2
  exit 1
fi
run_tool --status | grep -Fqx 'nfqws_runtime=running'

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
# baseline, XKeen baseline, history, latest + the newest 2.
[ "$(find "$ROOT/opt/etc/keenetic-discord-nfqws2/snapshots" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" -le 6 ]
[ "$(find "$ROOT/opt/etc/keenetic-discord-nfqws2/nfqws-import-snapshots" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" -le 2 ]
# Import snapshots hold the nfqws2 data, not the package files.
[ ! -e "$(sed -n '1p' "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-nfqws-import.ptr")/nfqws2/lua" ]
rm -rf "$ROOT/opt/etc/xkeen-web"
assert_mode zapret zapret zapret

# Full baseline rollback after standalone + integrated applies.
run_tool --show-snapshots | grep -Fq 'XKeen baseline: '
run_tool --rollback --yes-router >/dev/null
[ "$(sha256sum "$routing_file" | awk '{print $1}')" = "$original_routing_hash" ]
[ "$(sha256sum "$nfqws_file" | awk '{print $1}')" = "$original_nfqws_hash" ]
[ ! -e "$ROOT/opt/etc/xray/configs/04_discord_nfqws2_outbound.json" ]
[ ! -e "$ROOT/opt/etc/xray/configs/04_youtube_nfqws2_outbound.json" ]
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
  "$ROOT/opt/etc/xray/configs/04_discord_nfqws2_outbound.json" >/dev/null
jq -e '.outbounds[0].streamSettings.sockopt.mark == 255' \
  "$ROOT/opt/etc/xray/configs/04_youtube_nfqws2_outbound.json" >/dev/null
# In TProxy mode TCP arrives on the tproxy inbound: it must sniff TLS/HTTP.
jq -e '.inbounds[] | select(.tag == "tproxy") | .sniffing.destOverride | (index("tls") != null and index("http") != null and index("quic") != null)' \
  "$ROOT/opt/etc/xray/configs/03_inbounds.json" >/dev/null
assert_config_checks
xray_config_test
run_tool --status | grep -Fqx 'telegram_route=ws'
run_tool --apply --yes-router --core xray --telegram-route unmanaged >/dev/null
[ "$(relay_count)" = 0 ]

echo "routing-mode-tests-ok"
