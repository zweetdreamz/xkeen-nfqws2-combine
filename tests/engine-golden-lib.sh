# shellcheck shell=sh
# Golden roots use the same scenario functions as Python tests, never copies
# of pointer-bearing trees. Only the temporary work-directory PID is normalised.
# shellcheck source=tests/engine-root-fixture.sh
. "$SCRIPT_DIR/tests/engine-root-fixture.sh"
# shellcheck source=tests/engine-scenarios-lib.sh
. "$SCRIPT_DIR/tests/engine-scenarios-lib.sh"
# shellcheck source=tests/engine-compare-lib.sh
. "$SCRIPT_DIR/tests/engine-compare-lib.sh"
GOLDEN_BASE_PATH="$PATH"
GOLDEN_COUNT=0
GOLDEN_SCENARIOS=0
GOLDEN_JSON_SKIPPED=0
engine_compare_init "$FIXTURE/compare"

golden_cleanup() {
  for golden_pidfile in "$FIXTURE"/*/root/opt/var/run/nfqws2.pid "$FIXTURE"/*/root/opt/var/run/kdn-telegram-ws.pid; do
    [ -f "$golden_pidfile" ] || continue
    golden_pid="$(sed -n '1p' "$golden_pidfile")"
    case "$golden_pid" in ''|*[!0-9]*) continue ;; esac
    [ "$golden_pid" -gt 1 ] || continue
    if tr '\000' ' ' 2>/dev/null < "/proc/$golden_pid/cmdline" | grep -Fq "$FIXTURE/"; then
      kill "$golden_pid" 2>/dev/null || true
    fi
  done
  rm -rf "$FIXTURE"
}

golden_exit() {
  golden_rc=$?
  trap - 0
  engine_compare_finish || golden_rc=1
  golden_cleanup
  exit "$golden_rc"
}
trap golden_exit 0
trap 'exit 130' HUP INT TERM

golden_digest() {
  find "$ROOT" -type f ! -path "$ROOT/opt/tmp/keenetic-discord-nfqws2.*" \
    -exec sha256sum {} + | LC_ALL=C sort | sha256sum
}

golden_applets() {
  golden_flavor="$1"
  golden_farm="$FIXTURE/applets-$golden_flavor"
  mkdir -p "$golden_farm"
  for golden_applet in sh awk sed grep tr; do
    if [ "$golden_flavor" = busybox ]; then
      golden_target="$(PATH="$GOLDEN_BASE_PATH" command -v busybox)"
    else
      golden_target="$(PATH=/usr/bin:/bin command -v "$golden_applet")"
    fi
    [ -e "$golden_farm/$golden_applet" ] || ln -s "$golden_target" "$golden_farm/$golden_applet"
  done
  PATH="$golden_farm:$GOLDEN_BASE_PATH"
  export PATH
}

golden_prepare() {
  GOLDEN_SCENARIOS=$((GOLDEN_SCENARIOS + 1))
  ROOT="$FIXTURE/$GOLDEN_SCENARIOS/root"
  MOCK_BIN="$FIXTURE/$GOLDEN_SCENARIOS/bin"
  if [ "$1" = odd-values ]; then
    # B6/R9: native follows the router. The dedicated Python test also pins
    # the distinct dash echo output; this is not a whitespace normalisation.
    golden_applets busybox
    printf 'golden-reference: odd-values uses router BusyBox (B6/R9)\n'
  fi
  engine_build_root "$ROOT" "$MOCK_BIN" "${NFQWS_TEST_BLOB_SOURCE:-/opt/etc/nfqws2/blobs}"
  engine_scenario "$1" "$ROOT" "$MOCK_BIN"
  # All operational roots are synthetic; historical 2.0 captures remain exact.
  python3 "$SCRIPT_DIR/tests/engine-golden-record.py" stabilise "$ROOT"
  GOLDEN_INITIAL="$(golden_digest)"
}

golden_run() {
  # P10 offline plans ignore effective router defaults. Pin the old oracle's
  # implicit Telegram argument to the explicit offline default, not file data.
  case " ${KDN_ENGINE:-} $* " in
    *'legacy --print-plan '*)
      case " $* " in *' --telegram-route '*) ;; *) set -- "$@" --telegram-route unmanaged ;; esac ;;
  esac
  PATH="$MOCK_BIN:$PATH" KD_TEST_ROOT="$ROOT" KD_ALLOW_TEST_ROOT=1 \
    sh "$SCRIPT_DIR/apply-discord-nfqws2.sh" "$@"
}

golden_compare() {
  golden_label="$1"; shift
  golden_before="$(golden_digest)"
  golden_rc=0
  # Reviewed P10 policy delta, not a replacement of historical golden bytes:
  # unsupported installations no longer have an operational legacy equivalent.
  case "$golden_label:$1" in
    no-xkeen-binary/*:--status|no-xkeen-binary/*:--check-config|no-xkeen-binary/*:--print-nfqws-profiles|no-xkeen-binary/*:--preflight)
      KDN_ENGINE=python golden_run "$@" > "$FIXTURE/last.out" 2> "$FIXTURE/last.err" || golden_rc=$?
      if [ "$golden_rc" != 2 ] || ! grep -q 'XKeen 2.1+' "$FIXTURE/last.err"; then
        printf 'ENGINE MISMATCH: unsupported target not refused: %s\n' "$golden_label" >> "$ENGINE_COMPARE_LOG"
      fi
      golden_after="$(golden_digest)"
      [ "$golden_before" = "$golden_after" ] || printf 'ENGINE MISMATCH: unsupported target changed\n' >> "$ENGINE_COMPARE_LOG"
      GOLDEN_COUNT=$((GOLDEN_COUNT + 1))
      return 0 ;;
  esac
  if [ "${KDN_GOLDEN_RECORD:-0}" = 1 ] || [ "${KDN_GOLDEN_MODE:-live}" = recorded ]; then
    golden_engine=python
    golden_action=check
    if [ "${KDN_GOLDEN_RECORD:-0}" = 1 ]; then
      golden_engine=legacy
      golden_action=record
    fi
    KDN_ENGINE="$golden_engine" golden_run "$@" > "$FIXTURE/last.out" 2> "$FIXTURE/last.err" || golden_rc=$?
    printf '%s\n' "$golden_rc" > "$FIXTURE/last.rc"
    for golden_kind in out err rc; do
      python3 "$SCRIPT_DIR/tests/engine-golden-record.py" "$golden_action" "$ROOT" \
        "$FIXTURE/last.$golden_kind" \
        "${KDN_GOLDEN_DIR:-$SCRIPT_DIR/tests/fixtures/engine/golden}/$golden_label.$golden_kind" \
        >> "$ENGINE_COMPARE_LOG" 2>&1 || return 1
    done
  else
    ENGINE_COMPARE_NORMALIZE=1 ENGINE_COMPARE_CONTEXT="$golden_label" engine_compare_pair golden_run "$@" \
      > "$FIXTURE/last.out" 2> "$FIXTURE/last.err" || golden_rc=$?
  fi
  golden_after="$(golden_digest)"
  if [ "$golden_before" != "$golden_after" ]; then
    printf 'ENGINE MISMATCH: read-only tree changed: %s\n' "$golden_label" >> "$ENGINE_COMPARE_LOG"
  fi
  GOLDEN_COUNT=$((GOLDEN_COUNT + 1))
}

golden_json_check() {
  golden_before="$(golden_digest)"
  golden_json_rc=0
  KDN_ENGINE=python golden_run --status --json > "$FIXTURE/status.json" 2> "$FIXTURE/json.err" || golden_json_rc=$?
  case "$1" in no-xkeen-binary/*)
    if [ "$golden_json_rc" != 2 ] || ! jq -e '.schema == 1 and .error_code == "unsupported_xkeen" and .supported == false and .fields == {}' "$FIXTURE/status.json" >/dev/null; then
      printf 'ENGINE MISMATCH: unsupported JSON %s\n' "$1" >> "$ENGINE_COMPARE_LOG"
    fi
    [ "$golden_before" = "$(golden_digest)" ] || printf 'ENGINE MISMATCH: unsupported JSON changed tree\n' >> "$ENGINE_COMPARE_LOG"
    GOLDEN_COUNT=$((GOLDEN_COUNT + 1))
    return 0 ;;
  esac
  golden_text_rc=0
  if [ "${KDN_GOLDEN_MODE:-live}" = recorded ] && [ "${KDN_GOLDEN_RECORD:-0}" != 1 ]; then
    golden_oracle="${KDN_GOLDEN_DIR:-$SCRIPT_DIR/tests/fixtures/engine/golden}/${1%/status-json}/status"
    golden_text_rc="$(gzip -cd "$golden_oracle.rc.gz")"
    jq -rj '.text' "$FIXTURE/status.json" > "$FIXTURE/status.txt"
    cp "$FIXTURE/json.err" "$FIXTURE/text.err"
    for golden_kind in out err; do
      golden_source="$FIXTURE/status.txt"
      [ "$golden_kind" != err ] || golden_source="$FIXTURE/json.err"
      python3 "$SCRIPT_DIR/tests/engine-golden-record.py" check "$ROOT" "$golden_source" "$golden_oracle.$golden_kind" \
        >> "$ENGINE_COMPARE_LOG" 2>&1 || return 1
    done
  else
    KDN_ENGINE=legacy golden_run --status > "$FIXTURE/status.txt" 2> "$FIXTURE/text.err" || golden_text_rc=$?
  fi
  if [ "$golden_json_rc" != "$golden_text_rc" ] || ! jq -e '.schema == 1 and (.fields | type == "object")' "$FIXTURE/status.json" >/dev/null; then
    printf 'ENGINE MISMATCH: JSON schema/rc %s\n' "$1" >> "$ENGINE_COMPARE_LOG"
  else
    jq -rj '.text' "$FIXTURE/status.json" > "$FIXTURE/json-text.txt"
    engine_compare_files "$1 JSON text" "$FIXTURE/json-text.txt" "$FIXTURE/status.txt"
    jq -r '.fields | to_entries[] | "\(.key)=\(.value)"' "$FIXTURE/status.json" > "$FIXTURE/json-fields.txt"
    sed '/^State directory:/,$d' "$FIXTURE/status.txt" > "$FIXTURE/text-fields.txt"
    engine_compare_files "$1 JSON fields" "$FIXTURE/json-fields.txt" "$FIXTURE/text-fields.txt"
    engine_compare_files "$1 JSON stderr" "$FIXTURE/json.err" "$FIXTURE/text.err"
  fi
  if [ "$golden_before" != "$(golden_digest)" ]; then
    printf 'ENGINE MISMATCH: JSON changed tree %s\n' "$1" >> "$ENGINE_COMPARE_LOG"
  fi
  GOLDEN_COUNT=$((GOLDEN_COUNT + 1))
}

golden_modes() {
  golden_compare "$1/status" --status
  golden_json_check "$1/status-json"
  golden_compare "$1/check" --check-config
  golden_compare "$1/profiles" --print-nfqws-profiles
  golden_compare "$1/snapshots" --show-snapshots
  golden_compare "$1/preflight-xray" --preflight --core xray
  golden_compare "$1/preflight-auto" --preflight
  golden_compare "$1/plan" --print-plan
  golden_compare "$1/standalone-plan" --print-plan --standalone-zapret
  golden_compare "$1/complex-plan" --print-plan --wide-udp --youtube-route vless --telegram-route ws --wan-interface eth9
  # Ten REAL pairs per scenario even while JSON is intentionally skipped.
  golden_compare "$1/rollback-alias" --show-rollback
  if [ "$GOLDEN_INITIAL" != "$golden_after" ]; then
    printf 'ENGINE MISMATCH: scenario tree changed: %s\n' "$1" >> "$ENGINE_COMPARE_LOG"
  fi
}

golden_finish() {
  printf 'golden-comparisons: %s (scenarios=%s, json-skipped=%s)\n' "$GOLDEN_COUNT" "$GOLDEN_SCENARIOS" "$GOLDEN_JSON_SKIPPED"
  [ "$GOLDEN_SCENARIOS" -gt 0 ] && [ "$GOLDEN_COUNT" -ge "$((10 * GOLDEN_SCENARIOS))" ] || return 1
  engine_compare_finish
}

if [ "${TEST_BUSYBOX_APPLETS:-0}" = 1 ]; then
  golden_applets busybox
fi
