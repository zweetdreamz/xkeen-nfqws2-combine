#!/bin/sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' 0 HUP INT TERM
# shellcheck source=tests/engine-compare-lib.sh
. "$SCRIPT_DIR/tests/engine-compare-lib.sh"
engine_compare_init "$fixture/compare"
same() { printf 'same\n'; }
different() { printf '%s\n' "$KDN_ENGINE"; }
different_err() { printf '%s\n' "$KDN_ENGINE" >&2; }
different_rc() { if [ "$KDN_ENGINE" = python ]; then return 7; else return 8; fi; }
different_order() {
  if [ "$KDN_ENGINE" = python ]; then printf 'out\n'; printf 'err\n' >&2;
  else printf 'err\n' >&2; printf 'out\n'; fi
}
counted() { printf 'call\n' >> "$fixture/count"; printf 'one\n'; }
unset KDN_ENGINE
engine_dual_run same --status >/dev/null
engine_compare_finish
for context in direct substitution pipeline; do
  : > "$ENGINE_COMPARE_LOG"
  case "$context" in
    direct) engine_dual_run different --status >/dev/null ;;
    substitution) value="$(engine_dual_run different --status)"; [ "$value" = python ] ;;
    pipeline) engine_dual_run different --status | cat >/dev/null ;;
  esac
  if engine_compare_finish >/dev/null 2>&1; then echo "comparison lost in $context" >&2; exit 1; fi
done
for callback in different_err different_rc different_order; do
  : > "$ENGINE_COMPARE_LOG"
  result=0
  engine_dual_run "$callback" --status >/dev/null 2>&1 || result=$?
  if [ "$callback" = different_rc ]; then [ "$result" = 7 ]; fi
  if engine_compare_finish >/dev/null 2>&1; then echo "missed $callback" >&2; exit 1; fi
done
# A real child suite must fail at exit even if its caller consumed the result.
for context in substitution pipeline; do
  result=0
  sh -c '
    set -eu
    . "$1/tests/engine-compare-lib.sh"
    engine_compare_init "$2/child-$3"
    trap '\''rc=$?; engine_compare_finish || rc=1; exit "$rc"'\'' 0
    mismatch() { printf "%s\n" "$KDN_ENGINE"; }
    unset KDN_ENGINE
    if [ "$3" = substitution ]; then value="$(engine_dual_run mismatch --status)"; [ "$value" = python ];
    else engine_dual_run mismatch --status | cat >/dev/null; fi
  ' sh "$SCRIPT_DIR" "$fixture" "$context" >/dev/null 2>&1 || result=$?
  [ "$result" = 1 ]
done
: > "$ENGINE_COMPARE_LOG"
mkdir -p "$fixture/mock-bin"
cat > "$fixture/mock-bin/python3" <<'STUB'
#!/bin/sh
printf 'wrong\n'
STUB
chmod +x "$fixture/mock-bin/python3"
via_python() { if [ "$KDN_ENGINE" = python ]; then python3; else printf 'same\n'; fi; }
PATH="$fixture/mock-bin:$PATH" engine_dual_run via_python --status >/dev/null
if engine_compare_finish >/dev/null 2>&1; then echo 'fake python mismatch missed' >&2; exit 1; fi
: > "$ENGINE_COMPARE_LOG"
cat > "$fixture/mock-bin/python3" <<'STUB'
#!/bin/sh
printf 'same\n'
STUB
PATH="$fixture/mock-bin:$PATH" engine_dual_run via_python --status >/dev/null
engine_compare_finish
KDN_ENGINE=legacy engine_dual_run counted --status >/dev/null
KDN_ENGINE='' engine_dual_run counted --status >/dev/null
engine_dual_run counted --apply --yes-router >/dev/null
engine_dual_run counted --apply >/dev/null
[ "$(wc -l < "$fixture/count" | tr -d ' ')" = 4 ]
engine_compare_finish
echo engine-compare-tests-ok
