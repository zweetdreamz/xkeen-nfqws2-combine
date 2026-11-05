#!/bin/sh
set -eu
unset KDN_ENGINE
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/engine-golden-routes.XXXXXX")"
# shellcheck source=tests/engine-golden-lib.sh
. "$SCRIPT_DIR/tests/engine-golden-lib.sh"
for scenario in fresh applied-default routes-matrix-1 routes-matrix-2 routes-matrix-3 telegram-vless telegram-recorded-zapret argv-corpus; do
  golden_prepare "$scenario"
  golden_modes "$scenario"
  if [ "$scenario" = argv-corpus ]; then
    # Each vector is a JSON argv array, not text evaluated by a shell.
    python3 "$SCRIPT_DIR/tests/engine-golden-argv.py" "$SCRIPT_DIR" "$ROOT" "$MOCK_BIN" "$ENGINE_COMPARE_LOG"
  fi
done
golden_finish
