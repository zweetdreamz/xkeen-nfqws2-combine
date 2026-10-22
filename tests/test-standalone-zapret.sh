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
  "$ROOT/opt/var/opkg-lists" \
  "$PACKAGE_STATE" \
  "$MOCK_BIN"

touch "$PACKAGE_STATE/ca-certificates" "$PACKAGE_STATE/wget-ssl"
printf 'Package: jq\n' > "$ROOT/opt/var/opkg-lists/entware"

# shellcheck source=tests/engine-nfqws2-fixture.sh
. "$SCRIPT_DIR/tests/engine-nfqws2-fixture.sh"
engine_write_nfqws2_init "$FIXTURE/S51nfqws2.template"
engine_write_stock_nfqws2_conf "$FIXTURE/nfqws2.conf.template" "" 0
engine_write_fake_nfqws2 "$FIXTURE/nfqws2.template"

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
  update)
    # One dead feed: opkg reports it and exits 1; the other list is there.
    echo "Downloading https://bin.entware.net/mipselsf-k3.4/Packages.gz"
    echo "Updated list of available packages in /opt/var/opkg-lists/entware"
    echo " * Failed to download the package list from https://dead.example.invalid/Packages.gz"
    exit 1
    ;;
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
        mkdir -p "$KD_TEST_ROOT/opt/usr/bin"
        cp "$KD_STANDALONE_FIXTURE/nfqws2.template" "$KD_TEST_ROOT/opt/usr/bin/nfqws2"
        cp "$KD_STANDALONE_FIXTURE/nfqws2.conf.template" \
          "$KD_TEST_ROOT/opt/etc/nfqws2/nfqws2.conf"
        # The package ships this blob (Telegram Zapret registers it).
        cp "$KD_STANDALONE_FIXTURE/tls_clienthello.bin" \
          "$KD_TEST_ROOT/opt/etc/nfqws2/blobs/tls_clienthello.bin"
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

cp "${NFQWS_TEST_BLOB_SOURCE:-/opt/etc/nfqws2/blobs}/tls_clienthello.bin" \
  "$FIXTURE/tls_clienthello.bin"

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

chmod +x "$MOCK_BIN/opkg" "$MOCK_BIN/ip"

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
if run_tool \
  --preflight \
  --standalone-zapret \
  --telegram-route vless >/dev/null 2>&1; then
  echo "ERROR: standalone mode accepted a VLESS Telegram route" >&2
  exit 1
fi
if run_tool \
  --preflight \
  --standalone-zapret \
  --telegram-route ws >/dev/null 2>&1; then
  echo "ERROR: standalone mode accepted the Telegram WS route" >&2
  exit 1
fi

if run_tool \
  --preflight \
  --standalone-zapret \
  --telegram-route zapret >/dev/null 2>&1; then
  echo "ERROR: the removed Telegram Zapret route was accepted" >&2
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
grep -Fq '# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=direct, Telegram=unmanaged.' "$nfqws_conf"
if grep -Fq -- 'kdn-telegram' "$nfqws_conf"; then
  echo "ERROR: Telegram profile in a standalone config" >&2
  exit 1
fi
grep -Fqx 'TCP_PORTS=80,443,2053,2083,2087,2096,8443' "$nfqws_conf"
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
printf '%s\n' "$status" | grep -Fqx 'telegram_route=unmanaged'

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
