# shellcheck shell=sh
# Shared fixture and helpers of the routing-mode integration tests, the
# tests/test-routing-modes-*.sh parts (sourced, not run; the caller sets
# SCRIPT_DIR to the project root and runs under "set -eu"). The tests must run
# on Linux/Entware with real jq. Sourcing creates a disposable fixture, removed
# on exit, to which all router paths are redirected; service, package, route
# and firewall commands are mocked. Every part starts from this fresh fixture
# and brings it to the state its scenarios need itself.

TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"
SERVICE_TARGET="$SCRIPT_DIR/set-service-route.sh"
BLOB_SOURCE="${NFQWS_TEST_BLOB_SOURCE:-/opt/etc/nfqws2/blobs}"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-routing-modes.XXXXXX")"
ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"
# shellcheck source=tests/engine-root-fixture.sh
. "$SCRIPT_DIR/tests/engine-root-fixture.sh"

safe_cleanup() {
  if [ -f "$ROOT/xkeen-service.pid" ]; then
    fixture_xray_pid="$(cat "$ROOT/xkeen-service.pid")"
    case "$fixture_xray_pid" in ''|*[!0-9]*) ;; *) kill "$fixture_xray_pid" 2>/dev/null || true ;; esac
  fi
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
# shellcheck source=tests/engine-compare-lib.sh
. "$SCRIPT_DIR/tests/engine-compare-lib.sh"
engine_compare_init "$FIXTURE/compare"
engine_compare_rc=0
trap 'engine_compare_rc=$?; engine_compare_finish || engine_compare_rc=1; safe_cleanup; exit "$engine_compare_rc"' 0
trap 'exit 130' HUP INT TERM

command -v jq >/dev/null
command -v sha256sum >/dev/null
[ -f "$BLOB_SOURCE/tls_clienthello.bin" ]
[ -f "$BLOB_SOURCE/quic_initial.bin" ]

engine_build_root "$ROOT" "$MOCK_BIN" "$BLOB_SOURCE"
# Native2.1 restore verifies a daemon's actual cmdline, not pidof's return code.
# Only integration fixtures spawn this inert stand-in; read-only golden roots do not.
KD_TEST_XRAY_DAEMON=1
export KD_TEST_XRAY_DAEMON
PATH="$MOCK_BIN:$PATH" KD_TEST_ROOT="$ROOT" "$ROOT/opt/etc/init.d/S05xkeen" start on
rm -f "$ROOT/xkeen-init.log"
# The Telegram WS relay of this fixture listens on a free port.
KD_TEST_TELEGRAM_WS_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
export KD_TEST_TELEGRAM_WS_PORT

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

run_tool_once() {
  # Historical shell mutations remain an explicit oracle, not live fallback.
  fixture_engine="${KDN_ENGINE:-python}"
  case " $* " in *' --apply '*) [ -n "${KDN_ENGINE:-}" ] || fixture_engine=legacy ;; esac
  KDN_ENGINE="$fixture_engine" \
  PATH="$MOCK_BIN:$PATH" \
  KD_TEST_ROOT="$ROOT" \
  KD_ALLOW_TEST_ROOT=1 \
    sh "$TARGET" "$@"
}

run_tool() { engine_dual_run run_tool_once "$@"; }

run_service_tool() {
  KDN_ENGINE="${KDN_ENGINE:-legacy}" \
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
# Native owns append-only tail files; the explicit frozen shell oracle retains
# its own historical filenames. Assertions inspect whichever engine is applied.
outbound_suffix=""
[ "${KDN_ENGINE:-legacy}" != python ] || outbound_suffix="_tail"
discord_outbound_file="$ROOT/opt/etc/xray/configs/04_discord_nfqws2_outbound${outbound_suffix}.json"
youtube_outbound_file="$ROOT/opt/etc/xray/configs/04_youtube_nfqws2_outbound${outbound_suffix}.json"

# Relays of this fixture (its port), zombies excluded.
relay_count() {
  relay_total=0
  for relay_proc in /proc/[0-9]*; do
    relay_comm=""
    read -r relay_comm 2>/dev/null < "$relay_proc/comm" || continue
    case "$relay_comm" in python*) ;; *) continue ;; esac
    process_alive "${relay_proc#/proc/}" || continue
    tr '\0' ' ' 2>/dev/null < "$relay_proc/cmdline" |
      grep -Fq -- "telegram_ws_relay.py --listen 127.0.0.1:$KD_TEST_TELEGRAM_WS_PORT" &&
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
    [ ! -e "$discord_outbound_file" ]
  else
    [ -f "$discord_outbound_file" ]
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
    [ -f "$youtube_outbound_file" ]
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
    [ -f "$youtube_outbound_file" ]
    if grep -Fq -- '--hostlist=/opt/etc/nfqws2/lists/youtube.list' "$nfqws_file"; then
      echo "ERROR: direct-only YouTube profile remains in nfqws2.conf" >&2
      exit 1
    fi
  else
    [ ! -e "$youtube_outbound_file" ]
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

telegram_outbound_file="$ROOT/opt/etc/xray/configs/04_telegram_nfqws2_outbound${outbound_suffix}.json"

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
  elif grep -Eq -- '--(hostlist|ipset)=/opt/etc/nfqws2/lists/kdn-telegram' "$nfqws_file"; then
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

# The single test the parts come from began with a standalone install (the
# baseline then covers nfqws2 only), and its first integrated apply added the
# XKeen baseline. Every part but test-routing-modes-routes.sh, which checks
# these steps, starts the same way.
routing_modes_install() {
  # Fresh supported snapshot, not the old oracle's unversioned standalone STATE.
  KDN_ENGINE=python run_tool_once --snapshot-baseline --standalone-zapret --yes-router >/dev/null
  run_tool --apply --yes-router --standalone-zapret --youtube-route direct >/dev/null
  apply_mode zapret vless
}

# The nfqws2 package files test-routing-modes-routes.sh leaves behind with
# its package upgrade: the later parts run with them, as the single test did.
# Profile operations and their snapshots must keep lua/ untouched.
routing_modes_upgraded_package() {
  mkdir -p "$ROOT/opt/etc/nfqws2/lua"
  printf '%s\n' 'NFQWS2_COMPAT_VER_REQUIRED=6' > "$ROOT/opt/etc/nfqws2/lua/zapret-lib.lua"
  printf '%s\n' 'package default' > "$ROOT/opt/etc/nfqws2/nfqws2.conf-opkg"
  printf '%s\n' '# upgraded init' >> "$ROOT/opt/etc/init.d/S51nfqws2"
}

# write_youtube_stage: $profile_stage, a YouTube tuner descriptor (TCP + QUIC,
# QUIC fake repeats=7, search seed 123456).
write_youtube_stage() {
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
}

# write_voice_stage (after write_youtube_stage): $voice_stage, a Discord Voice
# tuner descriptor for the narrow range (candidate $voice_id).
write_voice_stage() {
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
}

# Every part ends with this: the engine never relied on "xkeen -xtest", which
# cannot fail.
assert_no_xkeen_xtest() {
  [ ! -e "$ROOT/xkeen-xtest.called" ] || {
    cat "$ROOT/xkeen-xtest.called" >&2
    echo "ERROR: the engine called xkeen -xtest" >&2
    exit 1
  }
}
