# shellcheck shell=sh
# Shared router mocks for the engine tests (sourced, not run).
#
# engine_write_router_mocks DIR
#     Writes the executable stand-ins xkeen, opkg, pidof and ip into DIR (a
#     directory that is put first on PATH). xkeen answers like XKeen 2.x
#     ("-v", "-status", "-cp", "-cpe", "-tp"), opkg reports the packages of the
#     fixture (the version of a status query comes from
#     $KD_TEST_ROOT/opkg-version), pidof finds xray and nfqws2, ip knows the
#     route through the interface "fixture-wan". A call of "xkeen -xtest" is
#     recorded in $KD_TEST_ROOT/xkeen-xtest.called.

engine_write_router_mocks() {
  # Like XKeen 2.x, whose main loop has no exit: -xtest cannot fail. The engine
  # tests with xray itself; a call of -xtest is recorded and refused at the end.
  cat > "$1/xkeen" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -v) echo "XKeen 2.1" ;;
  -status)
    if [ "$(cat "$KD_TEST_ROOT/xkeen-service.running" 2>/dev/null || echo 1)" = 1 ]; then
      echo "running"
    else
      echo "stopped"
    fi
    ;;
  -cp|-cpe|-tp) echo "fixture" ;;
  -xtest) echo "xkeen -xtest" >> "$KD_TEST_ROOT/xkeen-xtest.called" ;;
esac
exit 0
EOF

  cat > "$1/opkg" <<'EOF'
#!/bin/sh
case "${1:-}" in
  status)
    # A test can simulate "opkg upgrade" by writing a version to this file.
    version="$(cat "$KD_TEST_ROOT/opkg-version" 2>/dev/null || echo 1.0-test)"
    if [ "${2:-}" = xkeen ]; then
      version="$(cat "$KD_TEST_ROOT/xkeen-version" 2>/dev/null || echo 2.1)"
    fi
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

  cat > "$1/pidof" <<'EOF'
#!/bin/sh
case "${1:-}" in
  xray)
    [ "$(cat "$KD_TEST_ROOT/xkeen-service.running" 2>/dev/null || echo 1)" = 1 ] || exit 1
    if [ -f "$KD_TEST_ROOT/xkeen-service.pid" ]; then
      fixture_pid="$(cat "$KD_TEST_ROOT/xkeen-service.pid")"
      kill -0 "$fixture_pid" 2>/dev/null || exit 1
      echo "$fixture_pid"
    fi
    ;;
  nfqws2) exit 0 ;;
  *) exit 1 ;;
esac
EOF

  cat > "$1/ip" <<'EOF'
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

  chmod +x \
    "$1/xkeen" \
    "$1/opkg" \
    "$1/pidof" \
    "$1/ip"
}
