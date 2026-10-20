#!/bin/sh
set -eu

# Runs every test suite of the project from one place.
#
#   sh tests/run-all.sh             shell, Python and JavaScript tests
#   sh tests/run-all.sh --coverage  the same, with a Python coverage report
#
# Shell tests run under the POSIX shell given in TEST_SHELL (default: sh;
# "busybox sh" is closest to the router's Entware shell).
# test-routing-modes.sh needs the stock nfqws2 blobs: on a router it finds
# them in /opt; elsewhere set NFQWS_TEST_BLOB_SOURCE or let this script fetch
# them with tests/fetch-nfqws2-blobs.sh (needs network access).

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TEST_SHELL="${TEST_SHELL:-sh}"
PYTHON="${PYTHON:-python3}"
coverage=0

for arg in "$@"; do
  case "$arg" in
    --coverage) coverage=1 ;;
    -h|--help)
      sed -n '4,12p' "$0" | sed 's/^# \{0,1\}//'
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

for test_script in tests/test-*.sh; do
  # TEST_SHELL is split on purpose so that "busybox sh" works.
  # shellcheck disable=SC2086
  run_suite "$(basename "$test_script")" $TEST_SHELL "$test_script"
done

if [ "$coverage" -eq 1 ]; then
  # coverage.py only measures source directories that exist at start-up;
  # tests/panel_loader.py writes the extracted panel app there.
  mkdir -p tests/.generated
  run_suite pytest "$PYTHON" -m coverage run -m pytest -q tests
  "$PYTHON" -m coverage report || true
else
  run_suite pytest "$PYTHON" -m pytest -q tests
fi

run_suite test-browser-diagnostics.cjs node tests/test-browser-diagnostics.cjs

if [ -n "$failed" ]; then
  echo "Failed suites:$failed" >&2
  exit 1
fi
echo "All test suites passed."
