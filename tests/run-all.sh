#!/bin/sh
set -eu

# Runs every test suite of the project from one place.
#
#   sh tests/run-all.sh             shell, Python and JavaScript tests
#   sh tests/run-all.sh --coverage  the same, with a Python coverage report
#
# Shell tests run under the POSIX shell given in TEST_SHELL (default: sh;
# "busybox sh" is closest to the router's Entware shell). With
# TEST_BUSYBOX_APPLETS=1 the shell tests also use busybox awk, sed, grep and
# the other core utilities, as on the router (jq and python3 stay native).
# The test-routing-modes-*.sh parts need the stock nfqws2 blobs: on a router
# they find them in /opt; elsewhere set NFQWS_TEST_BLOB_SOURCE or let this
# script fetch them with tests/fetch-nfqws2-blobs.sh (needs network access).

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TEST_SHELL="${TEST_SHELL:-sh}"
PYTHON="${PYTHON:-python3}"
coverage=0

for arg in "$@"; do
  case "$arg" in
    --coverage) coverage=1 ;;
    -h|--help)
      sed -n '4,15p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$SCRIPT_DIR"
failed=""

run_suite() {
  name="$1"
  shift
  printf '==> %s\n' "$name"
  if "$@"; then
    printf '    ok\n'
  else
    printf '    FAILED\n'
    failed="$failed $name"
  fi
}

if [ -z "${NFQWS_TEST_BLOB_SOURCE:-}" ] && [ ! -f /opt/etc/nfqws2/blobs/tls_clienthello.bin ]; then
  NFQWS_TEST_BLOB_SOURCE="$SCRIPT_DIR/tests/.generated/nfqws2-blobs"
  run_suite fetch-nfqws2-blobs sh tests/fetch-nfqws2-blobs.sh "$NFQWS_TEST_BLOB_SOURCE"
fi
export NFQWS_TEST_BLOB_SOURCE

shell_path="$PATH"
if [ "${TEST_BUSYBOX_APPLETS:-0}" = "1" ]; then
  applet_dir="$SCRIPT_DIR/tests/.generated/busybox-applets"
  rm -rf "$applet_dir"
  mkdir -p "$applet_dir"
  busybox_bin="$(command -v busybox)"
  for applet in awk sed grep cut tr sort head tail wc find xargs cp mv rm mkdir \
    chmod ls cat date stat sha256sum mktemp basename dirname tee od base64 ln \
    readlink touch sleep kill; do
    if busybox --list | grep -qx "$applet"; then
      ln -s "$busybox_bin" "$applet_dir/$applet"
    fi
  done
  shell_path="$applet_dir:$PATH"
fi

for test_script in tests/test-*.sh; do
  # TEST_SHELL is split on purpose so that "busybox sh" works.
  # shellcheck disable=SC2086
  run_suite "$(basename "$test_script")" env PATH="$shell_path" $TEST_SHELL "$test_script"
done

if [ "$coverage" -eq 1 ]; then
  run_suite pytest "$PYTHON" -m coverage run -m pytest -q tests
  "$PYTHON" -m coverage report || true
else
  run_suite pytest "$PYTHON" -m pytest -q tests
fi

run_suite test-browser-diagnostics.cjs node tests/test-browser-diagnostics.cjs
# Skipped (exit 0) when Playwright is not installed; CI requires it.
run_suite test-panel-ui.cjs node tests/test-panel-ui.cjs

if [ -n "$failed" ]; then
  echo "Failed suites:$failed" >&2
  exit 1
fi
echo "All test suites passed."
