# shellcheck shell=sh
# Shared router-like root of the engine tests (sourced, not run). The caller
# sets SCRIPT_DIR to the project root, as in tests/routing-modes-lib.sh.
#
# engine_build_root ROOT MOCK_BIN [BLOB_SOURCE]
#     Builds the tree of a router with XKeen (Xray) and nfqws2-keenetic 1.3.2
#     in the directory ROOT (the KD_TEST_ROOT of the script) and the mocks of
#     the router commands in MOCK_BIN (put it first on PATH): the init script
#     S05xkeen and the netfilter hook proxy.sh of XKeen, its port lists, three
#     Xray configs, the stock nfqws2.conf, the init script S51nfqws2 with the
#     fake nfqws2 binary, the blobs, python3 for the Telegram relay, and the
#     mocks xkeen, opkg, pidof, ip, xray, iptables-save and ip6tables-save.
#     The blobs tls_clienthello.bin and quic_initial.bin are copied from
#     BLOB_SOURCE when it holds them; otherwise a placeholder file takes their
#     place (the read-only modes do not look at the content).

# shellcheck source=tests/engine-nfqws2-fixture.sh
. "$SCRIPT_DIR/tests/engine-nfqws2-fixture.sh"
# shellcheck source=tests/engine-xray-fixture.sh
. "$SCRIPT_DIR/tests/engine-xray-fixture.sh"
# shellcheck source=tests/engine-mocks-fixture.sh
. "$SCRIPT_DIR/tests/engine-mocks-fixture.sh"

engine_build_root() {
  engine_root="$1"
  engine_mock_bin="$2"
  engine_blob_source="${3:-}"

  mkdir -p \
    "$engine_root/opt/etc/init.d" \
    "$engine_root/opt/etc/ndm/netfilter.d" \
    "$engine_root/opt/etc/xkeen" \
    "$engine_root/opt/etc/xray/configs" \
    "$engine_root/opt/etc/nfqws2/lists" \
    "$engine_root/opt/etc/nfqws2/blobs" \
    "$engine_root/opt/etc/opkg" \
    "$engine_root/opt/tmp" \
    "$engine_root/opt/var/run" \
    "$engine_root/opt/bin" \
    "$engine_mock_bin"
  # The Telegram WS relay runs on the real Python.
  ln -s "$(command -v python3)" "$engine_root/opt/bin/python3"
  # Inert single-process daemon with actual Xray-shaped /proc argv. os.execv
  # avoids non-POSIX exec -a and needs no compiler in the offline test image.
  mkdir -p "$engine_root/opt/tmp/xray-fixture"
  printf 'import time; time.sleep(3600)\n' > "$engine_root/opt/tmp/xray-fixture/run"

  cat > "$engine_root/opt/etc/init.d/S05xkeen" <<'EOF'
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
fixture_xray_stop() {
  fixture_pid="$(cat "$KD_TEST_ROOT/xkeen-service.pid" 2>/dev/null || true)"
  case "$fixture_pid" in ''|*[!0-9]*) ;; *)
    if tr '\0' ' ' < "/proc/$fixture_pid/cmdline" 2>/dev/null | grep -Fq -- "$KD_TEST_ROOT/opt/etc/xray/configs"; then
      kill "$fixture_pid" 2>/dev/null || true
    fi
    ;;
  esac
  rm -f "$KD_TEST_ROOT/xkeen-service.pid"
}
printf 'xkeen-init:%s\n' "$*" >> "$KD_TEST_ROOT/xkeen-init.log"
case "$1" in
  start|restart)
    if [ "${KD_TEST_XRAY_DAEMON:-0}" = 1 ]; then
      fixture_xray_stop
      python3 -c 'import os, sys; os.chdir(sys.argv[1]); os.execve(sys.executable, ["xray", "run", "-confdir", sys.argv[2]], dict(os.environ, PYTHONHOME=sys.base_prefix))' \
        "$KD_TEST_ROOT/opt/tmp/xray-fixture" "$KD_TEST_ROOT/opt/etc/xray/configs" </dev/null >/dev/null 2>&1 &
      echo "$!" > "$KD_TEST_ROOT/xkeen-service.pid"
    fi
    printf '1\n' > "$KD_TEST_ROOT/xkeen-service.running"
    ;;
  stop)
    fixture_xray_stop
    printf '0\n' > "$KD_TEST_ROOT/xkeen-service.running"
    ;;
esac
exit 0
EOF

  engine_write_nfqws2_init "$engine_root/opt/etc/init.d/S51nfqws2"
  engine_write_fake_nfqws2 "$engine_root/opt/usr/bin/nfqws2"

  chmod +x "$engine_root/opt/etc/init.d/S05xkeen"

  cat > "$engine_root/opt/etc/ndm/netfilter.d/proxy.sh" <<'EOF'
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

  cat > "$engine_root/opt/etc/xkeen/port_proxying.lst" <<'EOF'
# unrestricted fixture
EOF
  cat > "$engine_root/opt/etc/xkeen/port_exclude.lst" <<'EOF'
# no exclusions
EOF

  cat > "$engine_root/opt/etc/xray/configs/03_inbounds.json" <<'EOF'
{
  "inbounds": [
    {"tag":"redirect","sniffing":{"enabled":true,"destOverride":["http","tls"]}},
    {"tag":"tproxy","sniffing":{"enabled":true,"destOverride":["quic"]}}
  ]
}
EOF
  cat > "$engine_root/opt/etc/xray/configs/04_outbounds.json" <<'EOF'
{
  "outbounds": [
    {"tag":"vless-reality","protocol":"vless"},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]
}
EOF
  cat > "$engine_root/opt/etc/xray/configs/05_routing.json" <<'EOF'
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

  engine_write_stock_nfqws2_conf "$engine_root/opt/etc/nfqws2/nfqws2.conf" fixture-wan 0

  for engine_blob in tls_clienthello.bin quic_initial.bin; do
    if [ -n "$engine_blob_source" ] && [ -f "$engine_blob_source/$engine_blob" ]; then
      cp "$engine_blob_source/$engine_blob" "$engine_root/opt/etc/nfqws2/blobs/$engine_blob"
    else
      printf 'placeholder %s\n' "$engine_blob" > "$engine_root/opt/etc/nfqws2/blobs/$engine_blob"
    fi
  done

  engine_write_router_mocks "$engine_mock_bin"
  engine_write_xray_mock "$engine_mock_bin"
  engine_write_iptables_mocks "$engine_mock_bin"
}
