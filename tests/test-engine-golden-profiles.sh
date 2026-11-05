#!/bin/sh
set -eu
unset KDN_ENGINE
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/engine-golden-profiles.XXXXXX")"
# shellcheck source=tests/engine-golden-lib.sh
. "$SCRIPT_DIR/tests/engine-golden-lib.sh"
for flavor in system busybox; do
  golden_applets "$flavor"
  for scenario in imported-voice-narrow imported-voice-wide standalone check-udp443-not-queued check-empty-user-list check-extra-args-empty check-legacy-fake check-two-empty-lists check-custom-profile-1984; do
    golden_prepare "$scenario"
    golden_modes "$scenario"
  done
done
golden_finish
