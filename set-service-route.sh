#!/bin/sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ "${KDN_ENGINE:-}" = legacy ] && [ "${KD_ALLOW_TEST_ROOT:-0}" = 1 ]; then
  case "${KD_TEST_ROOT:-}" in /|//|'') echo 'ERROR: unsafe legacy oracle root.' >&2; exit 2 ;; esac
  oracle="$SCRIPT_DIR/tests/fixtures/engine/legacy-set-service-phase6.sh.txt"
  [ -f "$oracle" ] || { echo 'ERROR: isolated route oracle is missing.' >&2; exit 1; }
  # shellcheck source=/dev/null
  . "$oracle"
  exit $?
fi
PYTHONPATH="$SCRIPT_DIR/tools/router${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH
exec python3 "$SCRIPT_DIR/tools/router/route_switch.py" service "$@"
