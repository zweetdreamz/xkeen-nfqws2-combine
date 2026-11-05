#!/bin/sh
set -eu

# Read-only and phase5 profile/snapshot modes go to "python3 -P -m kdn.engine";
# fullapply stays shell-owned but requires the filesystem safety bridge.
# Python is replaced by a stub python3 that records what it is given (arguments
# and environment) and exits with $STUB_EXIT, so only the dispatcher is tested.
# The script runs under the shell this test runs under (dash, or "busybox sh").
#   a. kdn_scan_mode and the whole script reproduce every row of
#      tests/fixtures/engine/mode-table.tsv;
#   b. arguments, the exit code and the streams of Python pass through as they are;
#   c. KDN_ENGINE and the engine-legacy file choose the path (KDN_ENGINE wins);
#   d. no python3 or no kdn.engine package: the shell engine and one stderr line;
#   e. what the dispatcher adds to the environment is recorded, and removed again
#      on the way back to the shell engine (checked through the real kdn.engine);
#   f. migrated mutation argv forwards exactly; fullapply never bypasses the bridge.

unset KDN_ENGINE KDN_ENGINE_SCRIPT KDN_ENGINE_SCRIPT_DIR KDN_ENGINE_ADDED_PYTHONPATH KDN_ENGINE_ADDED_ENV
unset PYTHONPATH PYTHONUTF8 PYTHONIOENCODING PYTHONCOERCECLOCALE

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"
TABLE="$SCRIPT_DIR/tests/fixtures/engine/mode-table.tsv"
TAB="$(printf '\t')"
STATE_LOGICAL=/opt/etc/keenetic-discord-nfqws2
WARN_PYTHON="WARNING: python3 not found; using the shell engine."
WARN_PACKAGE="WARNING: kdn.engine is not installed; using the shell engine."

WORK="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-engine-dispatch.XXXXXX")"
trap 'rm -rf "$WORK"' 0
trap 'exit 130' INT
trap 'exit 143' HUP TERM

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# The shell the script under test runs in, as an absolute path ("busybox sh" in the busybox run).
# shellcheck disable=SC2086
set -- ${TEST_SHELL:-sh}
shell_name="$1"
shift
shell_bin="$(command -v "$shell_name")" || fail "no shell: $shell_name"
ENGINE_SHELL="$shell_bin $*"
REAL_PYTHON="$(command -v python3 || true)"

ROOT="$WORK/root"
STUB_DIR="$WORK/stub"
CWD="$WORK/cwd"
STUB_LOG="$WORK/stub.log"
OUT="$WORK/stdout"
ERR="$WORK/stderr"
mkdir -p "$ROOT" "$STUB_DIR" "$CWD"
# Files a bare "*" would be globbed into.
: > "$CWD/glob-one"
: > "$CWD/glob-two"
cd "$CWD"
[ -f "$TABLE" ] || fail "the mode table is missing"

cat > "$STUB_DIR/python3" <<'EOF'
#!/bin/sh
# Test double of python3: records what the dispatcher passes, exits with $STUB_EXIT.
echo call >> "$STUB_LOG"
for arg in "$@"; do printf 'arg<%s>\n' "$arg"; done > "$STUB_LOG.argv"
{
  for name in KDN_ENGINE PYTHONPATH PYTHONUTF8 PYTHONIOENCODING PYTHONCOERCECLOCALE KDN_ENGINE_SCRIPT \
    KDN_ENGINE_SCRIPT_DIR KDN_ENGINE_ADDED_PYTHONPATH KDN_ENGINE_ADDED_ENV KDN_ENGINE_ADDED_ONLY PATH; do
    if eval "[ -n \"\${$name+set}\" ]"; then
      eval "value=\${$name}"
      printf '%s=<%s>\n' "$name" "$value"
    else
      printf '%s unset\n' "$name"
    fi
  done
} > "$STUB_LOG.env"
echo "stub stdout"
echo "stub stderr" >&2
exit "${STUB_EXIT:-77}"
EOF
chmod +x "$STUB_DIR/python3"
export STUB_LOG

# The tools the shell engine needs for the modes run with a PATH that has no python3.
FARM="$WORK/farm"
mkdir -p "$FARM"
for tool in dirname cat; do
  ln -s "$(command -v "$tool")" "$FARM/$tool"
done

reset_env() {
  unset KDN_ENGINE KDN_ENGINE_SCRIPT KDN_ENGINE_SCRIPT_DIR KDN_ENGINE_ADDED_PYTHONPATH KDN_ENGINE_ADDED_ENV
  unset KDN_ENGINE_ADDED_ONLY
  unset PYTHONPATH PYTHONUTF8 PYTHONIOENCODING PYTHONCOERCECLOCALE STUB_EXIT
  rm -f "$STUB_LOG" "$STUB_LOG.argv" "$STUB_LOG.env"
  : > "$STUB_LOG"
}

# run_script PATH SCRIPT ARGS...: the script in the test root; stdout, stderr and rc are kept.
run_script() {
  run_path="$1"
  run_target="$2"
  shift 2
  rc=0
  # $ENGINE_SHELL is "<path> [sh]" on purpose.
  # shellcheck disable=SC2086
  PATH="$run_path" KD_TEST_ROOT="$ROOT" KD_ALLOW_TEST_ROOT=1 \
    $ENGINE_SHELL "$run_target" "$@" > "$OUT" 2> "$ERR" < /dev/null || rc=$?
}

# The script with the stub python3 first on the PATH.
run_dispatcher() {
  run_script "$STUB_DIR:$PATH" "$TARGET" "$@"
}

stub_calls() {
  wc -l < "$STUB_LOG" | tr -d ' '
}

assert_eq() {
  [ "$2" = "$3" ] || fail "$1: expected <$2>, got <$3>"
}

# assert_file NAME FILE EXPECTED: the file holds exactly EXPECTED.
assert_file() {
  printf '%s' "$3" > "$WORK/expected"
  cmp -s "$WORK/expected" "$2" || fail "$1: expected <$3>, got <$(cat "$2")>"
}

# assert_python_args NAME ARGS...: the stub was called once, with -P -m kdn.engine and ARGS.
assert_python_args() {
  case_name="$1"
  shift
  assert_eq "$case_name: the stub was called once" 1 "$(stub_calls)"
  printf 'arg<%s>\n' -P -m kdn.engine "$@" > "$WORK/expected.argv"
  cmp -s "$WORK/expected.argv" "$STUB_LOG.argv" ||
    fail "$case_name: arguments differ: expected <$(cat "$WORK/expected.argv")>, got <$(cat "$STUB_LOG.argv")>"
}

assert_not_called() {
  assert_eq "$1: the stub must not be called" 0 "$(stub_calls)"
}

stub_env() {
  sed -n "s/^$1=<\\(.*\\)>\$/\\1/p" "$STUB_LOG.env"
}

assert_env() {
  assert_eq "$1: $2" "$3" "$(stub_env "$2")"
}

assert_env_unset() {
  grep -qx "$2 unset" "$STUB_LOG.env" || fail "$1: $2 must not be set"
}

pass() {
  printf '    ok %s\n' "$1"
}

# ---------------------------------------------------------------- a. the mode table
{
  awk '
    $0 == "kdn_scan_mode() {" { copying = 1 }
    copying { print }
    copying && /^}$/ { exit }
  ' "$TARGET"
  echo 'kdn_scan_mode "$@"'
} > "$WORK/scan.sh"
grep -q '^kdn_scan_mode() {$' "$WORK/scan.sh" || fail "kdn_scan_mode is not in the script"

rows=0
while IFS="$TAB" read -r expected words || [ -n "$expected" ]; do
  [ -n "$expected" ] || continue
  rows=$((rows + 1))
  reset_env
  set -f
  set --
  for word in $words; do
    if [ "$word" = '@empty@' ]; then
      word=''
    fi
    set -- "$@" "$word"
  done
  set +f
  # $ENGINE_SHELL is "<path> [sh]" on purpose.
  # shellcheck disable=SC2086
  got="$($ENGINE_SHELL "$WORK/scan.sh" "$@" < /dev/null)"
  assert_eq "kdn_scan_mode <$words>" "$expected" "$got"
  run_dispatcher "$@"
  case "$expected" in
    apply|status|check-config|print-nfqws-profiles|show-snapshots|preflight|print-plan|snapshot-baseline|rollback-baseline|rollback-latest|rollback-import|apply-import-profile|clear-imported-profile|rollback-snapshot)
      assert_python_args "row <$words>" "$@"
      ;;
    *)
      assert_not_called "row <$words>"
      ;;
  esac
done < "$TABLE"
[ "$rows" -ge 60 ] || fail "the mode table has $rows rows, expected at least 60"
pass "test_scan_matches_the_mode_table ($rows rows)"

# ---------------------------------------------------------------- b. arguments, exit code, streams
reset_env
newline_value="line one
line two"
check_arguments() {
  reset_env
  run_dispatcher "$@"
  assert_python_args "arguments <$*>" "$@"
}
check_arguments --wan-interface "" --status
check_arguments --wan-interface "eth0 ppp0 *" --status
check_arguments --wan-interface --status --preflight
check_arguments --core -x --check-config
check_arguments --proxy-outbound ' padded  value ' --print-plan
check_arguments --wan-interface "$newline_value" --status
check_arguments --telegram-route 'a\b $HOME `id` "q" '"'"'s'"'"'' --show-snapshots
check_arguments --direct-mark '*' --print-nfqws-profiles
check_arguments --status --json
pass "test_arguments_arrive_unchanged"

reset_env
run_dispatcher --status
assert_eq "default exit code" 77 "$rc"
assert_file "stub stdout reaches the caller untouched" "$OUT" "stub stdout
"
assert_file "stub stderr reaches the caller untouched" "$ERR" "stub stderr
"
for code in 0 3 255; do
  reset_env
  STUB_EXIT=$code
  export STUB_EXIT
  run_dispatcher --preflight
  assert_eq "exit code $code" "$code" "$rc"
done
pass "test_exit_code_of_python_is_the_exit_code_of_the_script"

# ---------------------------------------------------------------- c. KDN_ENGINE and the flag file
# The flag file lives in the state directory the shell engine itself reports.
reset_env
KDN_ENGINE=legacy
export KDN_ENGINE
run_dispatcher --show-snapshots
unset KDN_ENGINE
assert_eq "legacy --show-snapshots" 0 "$rc"
state_dir="$(sed -n 's/^State directory: //p' "$OUT")"
assert_eq "the state directory" "$ROOT$STATE_LOGICAL" "$state_dir"
assert_not_called "KDN_ENGINE=legacy"
grep -Fqx 'STATE_ROOT="$(root_path /opt/etc/keenetic-discord-nfqws2)"' "$TARGET" || fail "STATE_ROOT moved"
FLAG="$state_dir/engine-legacy"
legacy_stdout="$(cat "$OUT")"

reset_env
KDN_ENGINE=legacy
export KDN_ENGINE
run_dispatcher --status
assert_not_called "test_kdn_engine_legacy_forces_the_shell"
assert_eq "the legacy run prints no dispatcher line" 0 "$(grep -c 'WARNING' "$ERR" || true)"
pass "test_kdn_engine_legacy_forces_the_shell"

mkdir -p "$state_dir"
: > "$FLAG"
reset_env
KDN_ENGINE=python
export KDN_ENGINE
run_dispatcher --status
assert_python_args "KDN_ENGINE=python wins over the flag file" --status
pass "test_kdn_engine_python_wins_over_the_flag_file"

reset_env
run_dispatcher --show-snapshots
assert_not_called "the flag file with KDN_ENGINE unset"
assert_eq "the flag file leaves the stdout of the shell engine" "$legacy_stdout" "$(cat "$OUT")"
assert_file "the flag file prints nothing on stderr" "$ERR" ""
pass "test_flag_file_forces_the_shell_when_the_variable_is_unset"

reset_env
KDN_ENGINE=''
export KDN_ENGINE
run_dispatcher --status
assert_not_called "an empty KDN_ENGINE with the flag file"
rm -f "$FLAG"
reset_env
KDN_ENGINE=''
export KDN_ENGINE
run_dispatcher --status
assert_python_args "an empty KDN_ENGINE without the flag file" --status
pass "test_empty_kdn_engine_counts_as_unset"

for value in foo Python PYTHON ' python' 'python ' 1 legacy2; do
  for arguments in "--status" "--apply --yes-router" "--help" "--bogus" "--print-plan --core xray"; do
    reset_env
    KDN_ENGINE=$value
    export KDN_ENGINE
    # shellcheck disable=SC2086
    run_dispatcher $arguments
    assert_eq "KDN_ENGINE=<$value> $arguments: exit code" 2 "$rc"
    assert_file "KDN_ENGINE=<$value> $arguments: stdout" "$OUT" ""
    assert_file "KDN_ENGINE=<$value> $arguments: stderr" "$ERR" "ERROR: KDN_ENGINE must be python or legacy.
"
    assert_not_called "KDN_ENGINE=<$value> $arguments"
  done
done
pass "test_unknown_kdn_engine_value_is_refused"

# ---------------------------------------------------------------- d. no python3, no package
# The shell engine with a PATH that has no python3; the control run uses KDN_ENGINE=legacy.
reset_env
KDN_ENGINE=legacy
export KDN_ENGINE
run_script "$FARM" "$TARGET" --show-snapshots
control_rc=$rc
control_stdout="$(cat "$OUT")"
assert_file "the control run prints nothing on stderr" "$ERR" ""

for choice in unset python; do
  reset_env
  if [ "$choice" = python ]; then
    KDN_ENGINE=python
    export KDN_ENGINE
  fi
  run_script "$FARM" "$TARGET" --show-snapshots
  assert_eq "no python3 ($choice): exit code" "$control_rc" "$rc"
  assert_eq "no python3 ($choice): stdout is the shell engine's" "$control_stdout" "$(cat "$OUT")"
  assert_file "no python3 ($choice): one stderr line" "$ERR" "$WARN_PYTHON
"
done
pass "test_missing_python_falls_back_with_one_stderr_line"

# A copy of the script without the package next to it.
NOPKG="$WORK/nopkg"
mkdir -p "$NOPKG"
cp "$TARGET" "$NOPKG/apply-discord-nfqws2.sh"
mkdir -p "$NOPKG/tests/fixtures/engine"
cp "$SCRIPT_DIR/tests/fixtures/engine/legacy-apply-phase6.sh.txt" "$NOPKG/tests/fixtures/engine/legacy-apply-phase6.sh.txt"
for choice in unset python; do
  reset_env
  if [ "$choice" = python ]; then
    KDN_ENGINE=python
    export KDN_ENGINE
  fi
  run_script "$STUB_DIR:$PATH" "$NOPKG/apply-discord-nfqws2.sh" --show-snapshots
  assert_not_called "no package ($choice)"
  assert_eq "no package ($choice): exit code" "$control_rc" "$rc"
  assert_eq "no package ($choice): stdout is the shell engine's" "$control_stdout" "$(cat "$OUT")"
  assert_file "no package ($choice): one stderr line" "$ERR" "$WARN_PACKAGE
"
done
# Both missing: the python3 line only.
reset_env
run_script "$FARM" "$NOPKG/apply-discord-nfqws2.sh" --show-snapshots
assert_file "no python3 and no package" "$ERR" "$WARN_PYTHON
"
pass "test_missing_package_falls_back_with_one_stderr_line"

# ---------------------------------------------------------------- e. what the dispatcher adds
reset_env
run_dispatcher --status
assert_env "defaults" PYTHONPATH "$SCRIPT_DIR/tools/router"
assert_env "defaults" KDN_ENGINE_ADDED_PYTHONPATH "$SCRIPT_DIR/tools/router"
assert_env "defaults" PYTHONUTF8 1
assert_env "defaults" PYTHONIOENCODING "utf-8:surrogateescape"
assert_env "defaults" PYTHONCOERCECLOCALE 0
assert_env "defaults" KDN_ENGINE_ADDED_ENV "PYTHONUTF8 PYTHONIOENCODING PYTHONCOERCECLOCALE"
assert_env "defaults" KDN_ENGINE_SCRIPT "$TARGET"
assert_env "defaults" KDN_ENGINE_SCRIPT_DIR "$SCRIPT_DIR"
assert_env_unset "defaults" KDN_ENGINE

# What the caller set is kept and not listed; PYTHONPATH of the caller stays behind the project's.
reset_env
PYTHONPATH=/user/lib
PYTHONUTF8=0
export PYTHONPATH PYTHONUTF8
run_dispatcher --status
assert_env "caller values" PYTHONPATH "$SCRIPT_DIR/tools/router:/user/lib"
assert_env "caller values" KDN_ENGINE_ADDED_PYTHONPATH "$SCRIPT_DIR/tools/router"
assert_env "caller values" PYTHONUTF8 0
assert_env "caller values" KDN_ENGINE_ADDED_ENV "PYTHONIOENCODING PYTHONCOERCECLOCALE"
reset_env
PYTHONUTF8=1
PYTHONIOENCODING=latin-1
PYTHONCOERCECLOCALE=warn
export PYTHONUTF8 PYTHONIOENCODING PYTHONCOERCECLOCALE
run_dispatcher --status
assert_env "all set by the caller" PYTHONIOENCODING latin-1
assert_env "all set by the caller" PYTHONCOERCECLOCALE warn
assert_env "all set by the caller" KDN_ENGINE_ADDED_ENV ""
assert_env_unset "all set by the caller" KDN_ENGINE_ADDED_ONLY

# A copy under another name, in another directory: the dispatcher follows the script, not the project.
COPY="$WORK/copy"
mkdir -p "$COPY/tools/router/kdn/engine"
: > "$COPY/tools/router/kdn/engine/__main__.py"
cp "$TARGET" "$COPY/other-name.sh"
reset_env
run_script "$STUB_DIR:$PATH" "$COPY/other-name.sh" --status
assert_eq "the copy" 77 "$rc"
assert_env "the copy" KDN_ENGINE_SCRIPT "$COPY/other-name.sh"
assert_env "the copy" KDN_ENGINE_SCRIPT_DIR "$COPY"
assert_env "the copy" PYTHONPATH "$COPY/tools/router"
pass "test_dispatcher_records_what_it_added"

# Outside the test root the script sets the engine PATH before the dispatcher runs. The copy has the first
# directory of that PATH retargeted, so that the stub can be found there.
ENGINE_BIN="$WORK/engine-bin"
mkdir -p "$ENGINE_BIN" "$WORK/pathcopy"
cp "$STUB_DIR/python3" "$ENGINE_BIN/python3"
sed "s|PATH=\"/opt/bin:/opt/sbin:|PATH=\"$ENGINE_BIN:/opt/sbin:|" "$TARGET" > "$WORK/pathcopy/apply-discord-nfqws2.sh"
[ "$(grep -c "^  PATH=\"$ENGINE_BIN:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/sbin:/bin:/usr/sbin:/usr/bin\"\$" \
  "$WORK/pathcopy/apply-discord-nfqws2.sh")" = 1 ] || fail "the PATH line was not retargeted"
mkdir -p "$WORK/pathcopy/tools/router/kdn/engine"
: > "$WORK/pathcopy/tools/router/kdn/engine/__main__.py"
reset_env
rc=0
# $ENGINE_SHELL is "<path> [sh]" on purpose.
# shellcheck disable=SC2086
env -u KD_TEST_ROOT -u KD_ALLOW_TEST_ROOT PATH="$STUB_DIR:$PATH" $ENGINE_SHELL "$WORK/pathcopy/apply-discord-nfqws2.sh" \
  --status > "$OUT" 2> "$ERR" < /dev/null || rc=$?
assert_eq "outside the test root: exit code" 77 "$rc"
assert_env "outside the test root" PATH "$ENGINE_BIN:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/sbin:/bin:/usr/sbin:/usr/bin"
# Inside the test root the PATH of the caller goes through as it is.
reset_env
run_dispatcher --status
assert_env "inside the test root" PATH "$STUB_DIR:$PATH"
pass "test_path_is_the_engine_path_outside_the_test_root"

# ---------------------------------------------------------------- the guard of the test root comes first
reset_env
KDN_ENGINE=bogus
export KDN_ENGINE
rc=0
# $ENGINE_SHELL is "<path> [sh]" on purpose.
# shellcheck disable=SC2086
env -u KD_ALLOW_TEST_ROOT PATH="$STUB_DIR:$PATH" KD_TEST_ROOT="$ROOT" $ENGINE_SHELL "$TARGET" --status \
  > "$OUT" 2> "$ERR" < /dev/null || rc=$?
assert_eq "the guard: exit code" 2 "$rc"
assert_file "the guard: stderr" "$ERR" "ERROR: KD_TEST_ROOT is reserved for isolated repository tests.
"
assert_not_called "the guard"
pass "test_test_root_guard_still_comes_first"

# ---------------------------------------------------------------- f. the mutating modes
for arguments in "--help" "-h"; do
  # The same output whatever the dispatcher could have chosen.
  reset_env
  KDN_ENGINE=legacy
  export KDN_ENGINE
  # shellcheck disable=SC2086
  run_script "$FARM:$PATH" "$TARGET" $arguments
  control_rc=$rc
  control_out="$(cat "$OUT")"
  control_err="$(cat "$ERR")"
  for variant in default python nopython; do
    reset_env
    path="$STUB_DIR:$PATH"
    if [ "$variant" = python ]; then
      KDN_ENGINE=python
      export KDN_ENGINE
    elif [ "$variant" = nopython ]; then
      path="$FARM:$PATH"
    fi
    # shellcheck disable=SC2086
    run_script "$path" "$TARGET" $arguments
    assert_not_called "mutating <$arguments> ($variant)"
    assert_eq "<$arguments> ($variant): exit code" "$control_rc" "$rc"
    assert_eq "<$arguments> ($variant): stdout" "$control_out" "$(cat "$OUT")"
    assert_eq "<$arguments> ($variant): stderr" "$control_err" "$(cat "$ERR")"
  done
done
[ -n "$control_err$control_out" ] || fail "the legacy run printed nothing"
pass "test_help_keeps_the_legacy_readonly_dispatch_path"

for arguments in "--apply" "--rollback-latest" "--snapshot-baseline" "--rollback-import" \
  "--apply-import-profile x" "--clear-imported-profile youtube" "--rollback-snapshot x"; do
  for variant in default python; do
    reset_env
    if [ "$variant" = python ]; then KDN_ENGINE=python; export KDN_ENGINE; fi
    # shellcheck disable=SC2086
    run_dispatcher $arguments --yes-router
    # shellcheck disable=SC2086
    assert_python_args "native mutation <$arguments> ($variant)" $arguments --yes-router
    assert_eq "native mutation exits with Python" 77 "$rc"
  done
done
pass "test_native_mutations_forward_original_argv_once"

reset_env
run_dispatcher --apply --yes-router
assert_eq "fullapply uses native exit code" 77 "$rc"
assert_eq "fullapply calls native entry once" 1 "$(stub_calls)"
grep -Fq 'arg<kdn.engine>' "$STUB_LOG.argv" || fail "fullapply did not enter native dispatcher"
if grep -Fq 'snapshot_bridge.py>' "$STUB_LOG.argv"; then fail "fullapply unexpectedly called legacy bridge"; fi
pass "test_fullapply_enters_native_transaction_once"

# No production oracle or live legacy writes, even with explicit confirmation.
reset_env
rc=0
# shellcheck disable=SC2086
env -u KD_TEST_ROOT -u KD_ALLOW_TEST_ROOT KDN_ENGINE=legacy $ENGINE_SHELL "$TARGET" --apply --yes-router > "$OUT" 2> "$ERR" || rc=$?
assert_eq "live legacy mutation is refused" 1 "$rc"
assert_not_called "live legacy mutation cannot reach Python or a test oracle"
grep -Fq 'legacy engine is test-only' "$ERR" || fail "missing live legacy refusal"

# ---------------------------------------------------------------- e. the way back through the real kdn.engine
# The dispatcher's environment goes to the real kdn.engine, which for a mode it does not run hands over to the
# shell engine: here a script that dumps the environment it gets.
if [ -z "$REAL_PYTHON" ] || [ ! -f "$SCRIPT_DIR/tools/router/kdn/engine/__main__.py" ]; then
  pass "test_legacy_hand_over_environment (skipped: no python3 or no kdn.engine)"
else
  CHAIN="$WORK/chain"
  mkdir -p "$CHAIN"
  cat > "$CHAIN/python3" <<EOF
#!/bin/sh
KDN_ENGINE_SCRIPT="$CHAIN/dump.sh"
export KDN_ENGINE_SCRIPT
exec "$REAL_PYTHON" -P -m kdn.engine --yes-router --help
EOF
  cat > "$CHAIN/dump.sh" <<'EOF'
#!/bin/sh
env > "$CHAIN_DUMP"
printf '%s\n' "$@" > "$CHAIN_DUMP.argv"
EOF
  chmod +x "$CHAIN/python3"
  CHAIN_DUMP="$WORK/chain.env"
  export CHAIN_DUMP

  # run_chain: LANG=C without LC_ALL/LC_CTYPE is where CPython would put LC_CTYPE=C.UTF-8 into the environment.
  run_chain() {
    rm -f "$CHAIN_DUMP" "$CHAIN_DUMP.argv"
    rc=0
    # $ENGINE_SHELL is "<path> [sh]" on purpose.
    # shellcheck disable=SC2086
    env -u LC_ALL -u LC_CTYPE LANG=C PATH="$CHAIN:$PATH" KD_TEST_ROOT="$ROOT" KD_ALLOW_TEST_ROOT=1 \
      $ENGINE_SHELL "$TARGET" --status > "$OUT" 2> "$ERR" < /dev/null || rc=$?
  }

  # The control: without PYTHONCOERCECLOCALE=0 this CPython coerces the locale (it does not everywhere).
  coerces="$(env -u LC_ALL -u LC_CTYPE -u PYTHONCOERCECLOCALE LANG=C "$REAL_PYTHON" -c \
    'import os; print(os.environ.get("LC_CTYPE", ""))')"

  reset_env
  run_chain
  [ -f "$CHAIN_DUMP" ] || fail "the shell engine was not reached: rc=$rc stderr=<$(cat "$ERR")>"
  assert_file "the hand-over arguments" "$CHAIN_DUMP.argv" "--yes-router
--help
"
  grep -qx 'KDN_ENGINE=legacy' "$CHAIN_DUMP" || fail "the hand-over must set KDN_ENGINE=legacy"
  for name in PYTHONPATH PYTHONUTF8 PYTHONIOENCODING PYTHONCOERCECLOCALE KDN_ENGINE_SCRIPT KDN_ENGINE_SCRIPT_DIR \
    KDN_ENGINE_ADDED_PYTHONPATH KDN_ENGINE_ADDED_ENV LC_CTYPE; do
    if grep -q "^$name=" "$CHAIN_DUMP"; then
      if [ "$name" = LC_CTYPE ] && [ -z "$coerces" ]; then
        continue
      fi
      fail "the hand-over leaks $name: $(grep "^$name=" "$CHAIN_DUMP")"
    fi
  done
  if [ -n "$coerces" ]; then
    assert_eq "the control coerces the locale" "C.UTF-8" "$coerces"
  fi

  # What the caller set survives the round trip.
  reset_env
  PYTHONPATH=/user/lib
  PYTHONUTF8=0
  export PYTHONPATH PYTHONUTF8
  run_chain
  [ -f "$CHAIN_DUMP" ] || fail "the shell engine was not reached with caller values"
  grep -qx 'PYTHONPATH=/user/lib' "$CHAIN_DUMP" || fail "the caller's PYTHONPATH was lost: $(grep '^PYTHONPATH' "$CHAIN_DUMP" || true)"
  grep -qx 'PYTHONUTF8=0' "$CHAIN_DUMP" || fail "the caller's PYTHONUTF8 was lost"
  pass "test_legacy_hand_over_environment (control coerces the locale: ${coerces:-no})"
fi

echo "All engine dispatcher tests passed."
