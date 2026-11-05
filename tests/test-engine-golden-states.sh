#!/bin/sh
set -eu
unset KDN_ENGINE
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/engine-golden-states.XXXXXX")"
# shellcheck source=tests/engine-golden-lib.sh
. "$SCRIPT_DIR/tests/engine-golden-lib.sh"
for scenario in $(engine_scenario_names); do
  case "$scenario" in
    xray-*|no-*|unknown-core|snapshots-*|nfqws-runtime-*|synthetic21|odd-values)
      golden_prepare "$scenario"
      golden_modes "$scenario"
      ;;
  esac
done
golden_finish
