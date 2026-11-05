# shellcheck shell=sh
# A mismatch is a durable file, not an exit hidden in a command substitution.
engine_compare_init() {
  ENGINE_COMPARE_DIR="$1"
  ENGINE_COMPARE_LOG="$1/mismatches.log"
  export ENGINE_COMPARE_DIR ENGINE_COMPARE_LOG
  mkdir -p "$ENGINE_COMPARE_DIR"
  : > "$ENGINE_COMPARE_LOG"
}

engine_compare_finish() {
  if [ -s "$ENGINE_COMPARE_LOG" ]; then
    cat "$ENGINE_COMPARE_LOG" >&2
    return 1
  fi
}

engine_compare_files() {
  if ! cmp -s "$2" "$3"; then
    { printf 'ENGINE MISMATCH: %s %s\n' "${ENGINE_COMPARE_CONTEXT:-}" "$1"; diff -u "$2" "$3" || true; } >> "$ENGINE_COMPARE_LOG"
  fi
  return 0
}

engine_compare_pair() (
  original="$1"; shift
  pair="$(mktemp -d "$ENGINE_COMPARE_DIR/pair.XXXXXX")"
  trap 'rm -rf "$pair"' 0
  py_rc=0; old_rc=0
  KDN_ENGINE=python "$original" "$@" > "$pair/py.out" 2> "$pair/py.err" || py_rc=$?
  KDN_ENGINE=legacy "$original" "$@" > "$pair/old.out" 2> "$pair/old.err" || old_rc=$?
  printf '%s\n' "$py_rc" > "$pair/py.rc"
  printf '%s\n' "$old_rc" > "$pair/old.rc"
  for kind in out err rc; do
    if [ "${ENGINE_COMPARE_NORMALIZE:-0}" = 1 ]; then
      for side in py old; do
        sed -E 's/keenetic-discord-nfqws2\.[0-9]+/keenetic-discord-nfqws2.PID/g' "$pair/$side.$kind" > "$pair/$side.$kind.compare"
      done
    else
      cp "$pair/py.$kind" "$pair/py.$kind.compare"
      cp "$pair/old.$kind" "$pair/old.$kind.compare"
    fi
    engine_compare_files "$* [$kind]" "$pair/py.$kind.compare" "$pair/old.$kind.compare"
  done
  if [ -s "$pair/py.err" ] || [ -s "$pair/old.err" ]; then
    merged_py=0; merged_old=0
    KDN_ENGINE=python "$original" "$@" > "$pair/py.merged" 2>&1 || merged_py=$?
    KDN_ENGINE=legacy "$original" "$@" > "$pair/old.merged" 2>&1 || merged_old=$?
    if [ "${ENGINE_COMPARE_NORMALIZE:-0}" = 1 ]; then
      for side in py old; do
        sed -E 's/keenetic-discord-nfqws2\.[0-9]+/keenetic-discord-nfqws2.PID/g' "$pair/$side.merged" > "$pair/$side.merged.compare"
      done
    else
      cp "$pair/py.merged" "$pair/py.merged.compare"
      cp "$pair/old.merged" "$pair/old.merged.compare"
    fi
    engine_compare_files "$* [merged]" "$pair/py.merged.compare" "$pair/old.merged.compare"
    if [ "$merged_py" != "$py_rc" ] || [ "$merged_old" != "$old_rc" ]; then
      printf 'ENGINE MISMATCH: unstable merged exit status: %s\n' "$*" >> "$ENGINE_COMPARE_LOG"
    fi
  fi
  cat "$pair/py.out"
  cat "$pair/py.err" >&2
  exit "$py_rc"
)

engine_dual_run() {
  if [ "${KDN_ENGINE+x}" = x ]; then "$@"; return $?; fi
  engine_compare_read=0
  for engine_compare_arg in "$@"; do
    case "$engine_compare_arg" in
      --yes-router) "$@"; return $? ;;
      --status|--check-config|--print-nfqws-profiles|--show-snapshots|--show-rollback|--preflight|--print-plan) engine_compare_read=1 ;;
    esac
  done
  if [ "$engine_compare_read" = 0 ]; then "$@"; return $?; fi
  engine_compare_pair "$@"
}
