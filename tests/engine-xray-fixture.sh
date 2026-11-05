# shellcheck shell=sh
# Shared Xray fixture for the engine tests (sourced, not run).
#
# engine_write_xray_mock DIR
#     Writes DIR/xray, a stand-in for /opt/sbin/xray. "xray run -test
#     -confdir D [-format json]" checks every D/*.json with "jq -e ." and
#     prints "Configuration OK"; real Xray exits non-zero on a broken
#     configuration, unlike "xkeen -xtest", which always exits 0. Any other
#     arguments exit 0.
#     Knob: the file $KD_TEST_ROOT/xray-test-fail. An empty file makes every
#     test print "Failed to start: fixture-forced" and exit 23 (the code of
#     real Xray). A file with text fails only the tests whose D holds that
#     fixed string, so that a test can pass the preflight and fail the check
#     once the engine has patched the files.

engine_write_xray_mock() {
  cat > "$1/xray" <<'EOF'
#!/bin/sh
[ "${1:-}" = run ] || exit 0
shift
xray_test=0
xray_confdir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -test) xray_test=1 ;;
    -confdir) xray_confdir="${2:-}"; [ "$#" -lt 2 ] || shift ;;
  esac
  shift
done
[ "$xray_test" = 1 ] || exit 0
fail_marker="${KD_TEST_ROOT:-}/xray-test-fail"
if [ -e "$fail_marker" ]; then
  fail_needle="$(sed -n '1p' "$fail_marker")"
  if [ -z "$fail_needle" ] || cat "$xray_confdir"/*.json 2>/dev/null | grep -Fq -- "$fail_needle"; then
    echo "Failed to start: fixture-forced"
    exit 23
  fi
fi
for xray_file in "$xray_confdir"/*.json; do
  [ -e "$xray_file" ] || continue
  jq -e . "$xray_file" >/dev/null 2>&1 || {
    echo "Failed to start: invalid JSON in $xray_file"
    exit 23
  }
done
echo "Configuration OK"
EOF
  chmod +x "$1/xray"
}
