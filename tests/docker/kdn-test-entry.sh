#!/bin/bash
# shellcheck shell=bash
# Container entry point of kdn-tests:local. Copies the read-only project
# (/src) to a writable /work, makes sure the pinned nfqws2 blobs are in the
# cache volume, then re-runs itself as the unprivileged "tester" user with
# CAP_NET_ADMIN as an ambient capability (SO_MARK tests) to run the suites.
#
#   kdn-test-entry [--shell dash|busybox] [--python 3.13|3.12]
#                  [--only all|pytest|shell|node|lint|pytest,node] [--no-coverage]
#                  [--suites LIST | --skip-suites LIST]
#                  [--raw-copy] [--debug] [-- EXTRA_PYTEST_ARGS...]
#
# --suites / --skip-suites (with --only shell): run only the listed
# tests/test-*.sh, or all but them; LIST holds file names separated by commas
# (test-deploy.sh,test-jsonc.sh), and every name must exist.
set -euo pipefail

shell=dash
python=3.13
only=all
coverage=1
debug=0
raw_copy=0
suites=""
skip_suites=""
phase=setup
pytest_args=()

die() { echo "kdn-test-entry: $*" >&2; exit 2; }

orig_args=("$@")
while [ "$#" -gt 0 ]; do
  case "$1" in
    --shell) shell="${2:?--shell needs a value}"; shift 2 ;;
    --python) python="${2:?--python needs a value}"; shift 2 ;;
    --only) only="${2:?--only needs a value}"; shift 2 ;;
    --no-coverage) coverage=0; shift ;;
    --suites) suites="${2:?--suites needs a value}"; shift 2 ;;
    --skip-suites) skip_suites="${2:?--skip-suites needs a value}"; shift 2 ;;
    --debug) debug=1; shift ;;
    --raw-copy) raw_copy=1; shift ;;
    --phase-run) phase=run; shift ;;
    --) shift; pytest_args=("$@"); break ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$shell" in
  dash) test_shell="dash"; busybox_applets=0 ;;
  busybox) test_shell="busybox sh"; busybox_applets=1 ;;
  *) die "--shell must be dash or busybox" ;;
esac
[ -x "/opt/py/$python/bin/python3" ] || die "--python must be one of: $(ls /opt/py | tr '\n' ' ')"
case "$only" in all|pytest|shell|node|lint|pytest,node) ;; *) die "--only must be all, pytest, shell, node, lint or pytest,node" ;; esac
if [ "${#pytest_args[@]}" -gt 0 ] && [ "$only" != pytest ]; then
  die "extra pytest arguments need --only pytest (tests/run-all.sh takes none)"
fi
if [ -n "$suites$skip_suites" ] && [ "$only" != shell ]; then
  die "--suites and --skip-suites need --only shell"
fi
[ -z "$suites" ] || [ -z "$skip_suites" ] || die "--suites and --skip-suites exclude each other"

BLOBS=/var/cache/kdn/nfqws2-blobs
export NFQWS_TEST_RUNTIME="$BLOBS/runtime"
export KD_TEST_NFQWS2_BIN="$NFQWS_TEST_RUNTIME/nfqws2"
export KD_TEST_NFQWS2_LUA_SRC="$NFQWS_TEST_RUNTIME"
export PATH="/opt/py/$python/bin:$PATH"
export TEST_SHELL="$test_shell" TEST_BUSYBOX_APPLETS="$busybox_applets"
export REQUIRE_PANEL_UI_TESTS=1 NFQWS_TEST_BLOB_SOURCE="$BLOBS"

as_tester() {
  setpriv --reuid=tester --regid=tester --init-groups \
    --inh-caps=+net_admin,+net_raw --ambient-caps=+net_admin,+net_raw -- \
    env HOME=/home/tester USER=tester LOGNAME=tester "$@"
}

# ---------------------------------------------------------------- phase: run
failed=""
run_suite() {
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  if "$@"; then
    printf '    ok\n'
  else
    printf '    FAILED\n'
    failed="$failed $name"
  fi
}

# True when tests/test-*.sh named $1 is in the comma-separated list $2.
listed() {
  case ",$2," in *",$1,"*) return 0 ;; esac
  return 1
}

# Mirrors the shell part of tests/run-all.sh (busybox applets + test-*.sh),
# narrowed by --suites / --skip-suites.
run_shell_suites() {
  local shell_path="$PATH" test_script name
  for name in ${suites//,/ } ${skip_suites//,/ }; do
    [[ "$name" == test-*.sh && -f "tests/$name" ]] || die "no such suite: tests/$name"
  done
  if [ "$TEST_BUSYBOX_APPLETS" = 1 ]; then
    local applet_dir=/work/tests/.generated/busybox-applets applet
    rm -rf "$applet_dir"
    mkdir -p "$applet_dir"
    for applet in awk sed grep cut tr sort head tail wc find xargs cp mv rm mkdir \
      chmod ls cat date stat sha256sum mktemp basename dirname tee od base64 ln \
      readlink touch sleep kill; do
      if busybox --list | grep -qx "$applet"; then
        ln -s "$(command -v busybox)" "$applet_dir/$applet"
      fi
    done
    shell_path="$applet_dir:$PATH"
  fi
  for test_script in tests/test-*.sh; do
    name="$(basename "$test_script")"
    if [ -n "$suites" ] && ! listed "$name" "$suites"; then continue; fi
    if listed "$name" "$skip_suites"; then continue; fi
    # shellcheck disable=SC2086
    run_suite "$name" env PATH="$shell_path" $TEST_SHELL "$test_script"
  done
}

run_pytest() {
  mkdir -p tests/.generated
  local workers="${KDN_PYTEST_WORKERS:-4}"
  case "$workers" in 0|1|2|3|4|5|6|7|8) ;; *) die "KDN_PYTEST_WORKERS must be 0..8" ;; esac
  # File-level isolation keeps every module's ordered tests together. A crashed
  # worker fails the gate, rather than silently restarting/retrying its tests.
  local parallel=(-n "$workers" --dist loadfile --max-worker-restart=0)
  # pyproject.toml supplies testpaths when no selectors are given. Passing
  # "tests" here as well would run the whole suite even with an explicit file.
  if [ "$coverage" = 1 ]; then
    run_suite pytest python3 -m pytest -q "${parallel[@]}" \
      --cov=tools --cov-branch --cov-config=pyproject.toml --cov-report= ${pytest_args[@]+"${pytest_args[@]}"}
    python3 -m coverage report || true
    if [ -n "${KDN_COVERAGE_ARTIFACT:-}" ]; then
      python3 -m coverage json -o "$KDN_COVERAGE_ARTIFACT"
    fi
    if [ "${KDN_ENFORCE_COVERAGE:-0}" = 1 ]; then
      run_suite coverage-thresholds python3 tools/dev/coverage_summary.py
    fi
  else
    run_suite pytest python3 -m pytest -q "${parallel[@]}" ${pytest_args[@]+"${pytest_args[@]}"}
  fi
}

run_node() {
  run_suite test-browser-diagnostics.cjs node tests/test-browser-diagnostics.cjs
  run_suite test-panel-ui.cjs node tests/test-panel-ui.cjs
}

# The CI lint job, verbatim.
run_lint() {
  # Captured third-party baseline files are restore data, not maintained code.
  run_suite shellcheck sh -c "find . -name '*.sh' -not -path './.git/*' -not -path './tests/fixtures/engine/baseline-20260723-sanitized/*' -print0 | xargs -0 shellcheck -S warning"
  run_suite ruff ruff check --select F,B,E9 tools tests
}

if [ "$phase" = run ]; then
  cd /work
  case "$only" in
    all)
      run_shell_suites
      run_pytest
      run_node
      ;;
    shell) run_shell_suites ;;
    pytest) run_pytest ;;
    node) run_node ;;
    pytest,node) run_pytest; run_node ;;
    lint) run_lint ;;
  esac
  if [ -n "$failed" ]; then
    echo "Failed suites:$failed" >&2
    exit 1
  fi
  echo "All selected suites passed."
  exit 0
fi

# -------------------------------------------------------------- phase: setup
[ "$(id -u)" = 0 ] || die "the setup phase runs as root"
[ -d /src/tests ] || die "mount the project read-only at /src"

# 1. Writable copy as a fresh checkout on Linux would have it: git drops the
#    .gitignore-d files and applies .gitattributes line endings (the working
#    tree may come from a Windows checkout). --raw-copy keeps the bytes as-is.
find /work -mindepth 1 -maxdepth 1 -exec rm -rf {} +
stage=$(mktemp -d)
tar -C /src --exclude=./.git --exclude=./.cache --exclude=./.claude --exclude=./.pwd \
  --exclude=node_modules -cf - . | tar -C "$stage" --no-same-owner -xf -
if [ "$raw_copy" = 1 ]; then
  tar -C "$stage" -cf - . | tar -C /work -xf -
else
  git -C "$stage" -c init.defaultBranch=main init -q
  git -C "$stage" -c core.autocrlf=false -c core.safecrlf=false add -A 2>/dev/null
  git -C "$stage" -c core.autocrlf=false checkout-index -a -f --prefix=/work/
fi
rm -rf "$stage"

# 2. Pinned nfqws2 blobs (SHA-256 checked; downloads only what is missing).
if [ "$only" = all ] || [ "$only" = shell ] || [ "$only" = pytest ] || [ "$only" = pytest,node ]; then
  sh /work/tests/fetch-nfqws2-blobs.sh "$BLOBS" ||
    die "cannot get the nfqws2 blobs (the first run needs network access)"
  sh /work/tests/fetch-nfqws2-runtime.sh "$NFQWS_TEST_RUNTIME" ||
    die "cannot get the pinned nfqws2 Lua runtime (the first run needs network access)"
  chmod -R a+rX "$BLOBS"
fi
chown -R tester:tester /work

echo "== kdn-tests: shell=$test_shell busybox_applets=$busybox_applets python=$python only=$only${suites:+ suites=$suites}${skip_suites:+ skip-suites=$skip_suites} coverage=$coverage copy=$([ "$raw_copy" = 1 ] && echo raw || echo checkout) files=$(find /work -type f | wc -l)"
printf '== %s\n' \
  "$(python3 -VV | head -1)" \
  "pytest $(python3 -c 'import pytest; print(pytest.__version__)'), coverage $(python3 -c 'import coverage; print(coverage.__version__)'), $(ruff --version)" \
  "node $(node --version), playwright $(node -p 'require("playwright/package.json").version')" \
  "$(busybox | head -1 | cut -d' ' -f1-2), dash $(dpkg-query -W -f='${Version}' dash), $(jq --version), shellcheck $(shellcheck --version | sed -n 's/^version: //p')" \
  "tester CapAmb=$(as_tester awk '/^CapAmb/ { print $2 }' /proc/self/status)"

cd /work
if [ "$debug" = 1 ]; then
  echo "== debug shell in /work as tester (exit to stop the container)"
  exec setpriv --reuid=tester --regid=tester --init-groups \
    --inh-caps=+net_admin,+net_raw --ambient-caps=+net_admin,+net_raw -- \
    env HOME=/home/tester USER=tester LOGNAME=tester bash -l
fi

# 3. The suites, as tester; every output line gets the elapsed time.
stamp() {
  python3 -u -c '
import sys, time
start = time.monotonic()
for line in sys.stdin:
    sys.stdout.write("[%7.1fs] %s" % (time.monotonic() - start, line))
'
}

started=$(date +%s)
set +e
as_tester "$0" --phase-run "${orig_args[@]}" 2>&1 | stamp
status=${PIPESTATUS[0]}
set -e
echo "== kdn-tests: exit $status after $(( $(date +%s) - started ))s (shell=$test_shell python=$python only=$only)"
exit "$status"
