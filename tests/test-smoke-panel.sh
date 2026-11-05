#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PYTHONPATH="$ROOT/tests${PYTHONPATH:+:$PYTHONPATH}" python3 -m unittest test_smoke_panel
echo smoke-panel-tests-ok
