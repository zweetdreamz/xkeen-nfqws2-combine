#!/bin/sh
set -eu

# Full apply + rollback fixture for a fresh Entware installation without
# XKeen, Xray or Mihomo. All router paths and service/network commands are
# redirected to a disposable local root.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-standalone.XXXXXX")"
ROOT="$FIXTURE/root"
MOCK_BIN="$FIXTURE/bin"
PACKAGE_STATE="$ROOT/packages"

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
    "${TMPDIR:-/tmp}/keenetic-standalone."*) rm -rf "$FIXTURE" ;;
  esac
}
trap safe_cleanup 0 HUP INT TERM

mkdir -p \
  "$ROOT/opt/etc/init.d" \
  "$ROOT/opt/etc/opkg" \
  "$ROOT/opt/etc/ndm/netfilter.d" \
  "$ROOT/opt/etc/ndm/schedule.d" \
  "$ROOT/opt/tmp" \
  "$ROOT/opt/var/run" \
  "$PACKAGE_STATE" \
  "$MOCK_BIN"

touch "$PACKAGE_STATE/ca-certificates" "$PACKAGE_STATE/wget-ssl"

cat > "$FIXTURE/S51nfqws2.template" <<'EOF'
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
EOF
chmod +x "$FIXTURE/S51nfqws2.template"

cat > "$FIXTURE/nfqws2.conf.template" <<'EOF'
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
ISP_INTERFACE=""
EOF

cat > "$MOCK_BIN/opkg" <<'EOF'
#!/bin/sh
state="$KD_TEST_ROOT/packages"
case "${1:-}" in
  status)
    package="${2:-}"
    [ -f "$state/$package" ] || exit 0
    printf 'Package: %s\nVersion: 1.0-fixture\nStatus: install user installed\n' "$package"
    ;;
  list-installed)
    for installed in "$state"/*; do
      [ -f "$installed" ] || continue
      printf '%s - 1.0-fixture\n' "${installed##*/}"
    done
    ;;
  print-architecture)
    echo 'arch all 1'
    ;;
  update) ;;
  install)
    shift
    for package in "$@"; do
      touch "$state/$package"
      if [ "$package" = "nfqws2-keenetic" ]; then
        mkdir -p \
          "$KD_TEST_ROOT/opt/etc/nfqws2/blobs" \
          "$KD_TEST_ROOT/opt/etc/nfqws2/lists" \
          "$KD_TEST_ROOT/opt/etc/nfqws2/lua"
        cp "$KD_STANDALONE_FIXTURE/S51nfqws2.template" \
          "$KD_TEST_ROOT/opt/etc/init.d/S51nfqws2"
        chmod +x "$KD_TEST_ROOT/opt/etc/init.d/S51nfqws2"
        cp "$KD_STANDALONE_FIXTURE/nfqws2.conf.template" \
          "$KD_TEST_ROOT/opt/etc/nfqws2/nfqws2.conf"
      fi
    done
    ;;
  remove)
    shift
    for package in "$@"; do
      rm -f "$state/$package"
    done
    ;;
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

chmod +x "$MOCK_BIN/opkg" "$MOCK_BIN/ip" "$MOCK_BIN/iptables-save"

run_tool() {
  PATH="$MOCK_BIN:$PATH" \
  KD_TEST_ROOT="$ROOT" \
  KD_ALLOW_TEST_ROOT=1 \
  KD_STANDALONE_FIXTURE="$FIXTURE" \
    sh "$TARGET" "$@"
}

plan="$(run_tool --print-plan --standalone-zapret)"
printf '%s\n' "$plan" | grep -Fq 'Discord TCP=zapret, Discord Voice=zapret, YouTube=zapret'
printf '%s\n' "$plan" | grep -Fq 'только nfqws2'

if run_tool \
  --preflight \
  --standalone-zapret \
  --youtube-route vless >/dev/null 2>&1; then
  echo "ERROR: standalone mode accepted a VLESS route" >&2
  exit 1
fi

run_tool \
  --apply \
  --standalone-zapret \
  --discord-route zapret \
  --youtube-route direct \
  --wan-interface fixture-wan \
  --yes-router >/dev/null

nfqws_conf="$ROOT/opt/etc/nfqws2/nfqws2.conf"
grep -Fq '# Deployment mode: standalone-zapret.' "$nfqws_conf"
grep -Fq '# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=direct.' "$nfqws_conf"
grep -Fq 'ISP_INTERFACE="fixture-wan"' "$nfqws_conf"
grep -Fq 'NFQWS_ARGS_UDP="--filter-udp=443,3478-3481' "$nfqws_conf"
[ -f "$PACKAGE_STATE/nfqws2-keenetic" ]
[ -f "$PACKAGE_STATE/jq" ]
[ ! -e "$ROOT/opt/etc/init.d/S05xkeen" ]
[ ! -e "$ROOT/opt/etc/xkeen" ]
[ ! -e "$ROOT/opt/etc/xray" ]
[ ! -e "$ROOT/opt/etc/mihomo" ]

latest_pointer="$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr"
snapshot="$(sed -n '1p' "$latest_pointer")"
grep -Fq "$(printf 'SCOPE\tstandalone')" "$snapshot/STATE.tsv"
if grep -Eq '/xkeen|/xray|/mihomo|S05xkeen|proxy.sh' "$snapshot/MANIFEST"; then
  echo "ERROR: standalone snapshot captured an XKeen-managed path" >&2
  exit 1
fi

status="$(run_tool --status)"
printf '%s\n' "$status" | grep -Fq 'deployment_mode=standalone-zapret'
printf '%s\n' "$status" | grep -Fq 'detected_core=standalone'
printf '%s\n' "$status" | grep -Fq 'xkeen_runtime=unmanaged'

# Simulate XKeen being installed later. A scoped rollback must preserve it.
mkdir -p "$ROOT/opt/etc/xkeen" "$ROOT/opt/etc/xray/configs"
printf '%s\n' 'installed-later' > "$ROOT/opt/etc/xkeen/sentinel"
printf '%s\n' '{"installed":"later"}' > "$ROOT/opt/etc/xray/configs/sentinel.json"
cat > "$ROOT/opt/etc/init.d/S05xkeen" <<'EOF'
#!/bin/sh
echo "ERROR: standalone rollback invoked XKeen" >&2
exit 97
EOF
chmod +x "$ROOT/opt/etc/init.d/S05xkeen"

run_tool --rollback-latest --yes-router >/dev/null

grep -Fq 'installed-later' "$ROOT/opt/etc/xkeen/sentinel"
grep -Fq '"installed":"later"' "$ROOT/opt/etc/xray/configs/sentinel.json"
[ -f "$ROOT/opt/etc/init.d/S05xkeen" ]
[ ! -e "$ROOT/opt/etc/nfqws2" ]
[ ! -e "$ROOT/opt/etc/init.d/S51nfqws2" ]
[ ! -f "$PACKAGE_STATE/nfqws2-keenetic" ]
[ ! -f "$PACKAGE_STATE/jq" ]

echo "standalone-zapret-tests-ok"
