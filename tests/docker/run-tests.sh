#!/bin/sh
set -eu

# Runs the project's test suites in the kdn-tests:local Docker image.
#
#   sh tests/docker/run-tests.sh [options] [-- EXTRA_PYTEST_ARGS...]
#
#   --shell dash|busybox|all  POSIX shell for tests/test-*.sh (default dash;
#                             busybox also sets TEST_BUSYBOX_APPLETS=1); all =
#                             both, with --only all|shell at once in parallel
#                             containers: the shell suites of each shell split
#                             over six balanced containers, plus independent pytest
#                             and node containers (once each)
#   --serial                  with --shell all: a full run per shell, one
#                             container after the other, then pytest and node
#                             once each
#   --python 3.13|3.12        Python for pytest and the scripts (default 3.13)
#   --only all|pytest|shell|node|lint
#                             all = shell, pytest with coverage, node (default);
#                             lint = the CI lint job (shellcheck + ruff);
#                             pytest, node and lint run once whatever --shell
#   --no-coverage             run pytest without coverage
#   KDN_ENGINE=legacy         force one legacy pass instead of dual comparisons
#   --suites LIST, --skip-suites LIST
#                             with --only shell: only these tests/test-*.sh, or
#                             all but them (file names, comma-separated); with
#                             --shell all one container per shell
#   --raw-copy                test the working-tree bytes as they are (default:
#                             a checkout-like copy via git: .gitignore applied,
#                             line endings per .gitattributes)
#   --offline                 no network in the container (blobs must be cached)
#   --build                   (re)build the image first
#   --debug                   interactive shell in the prepared /work copy
#   -- ARGS                   extra pytest arguments (needs --only pytest)
#
# The project is mounted read-only at /src and copied to /work inside the
# container; downloaded nfqws2 blobs stay in the docker volume kdn-nfqws2-blobs.
# Parallel containers prefix every line with their name ([dash-1] ..
# [busybox-6], [py+node-1], [py+node-2]). Each run keeps its logs in its own directory
# .cache/test-logs/run-<UTC time>-<pid>/<name>.log (latest/ points to the
# newest, the last 10 runs are kept; KDN_TEST_LOG_DIR changes the base
# directory). The result is printed per container, then per shell as the last
# line: "run-tests: dash=ok busybox=ok py+node=ok".

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT="$(CDPATH= cd -- "$HERE/../.." && pwd)"
PROJECT_MOUNT="$PROJECT"
# Git Bash paths must be converted once, not rewritten again inside -v's
# source:target:mode string. POSIX hosts keep the original source path.
if command -v cygpath >/dev/null 2>&1; then
  PROJECT_MOUNT="$(cygpath -m "$PROJECT")"
fi
IMAGE="${KDN_TEST_IMAGE:-kdn-tests:local}"
BLOB_VOLUME="${KDN_TEST_BLOB_VOLUME:-kdn-nfqws2-blobs}"
LOG_DIR="${KDN_TEST_LOG_DIR:-$PROJECT/.cache/test-logs}"
BLOB_DIR=/var/cache/kdn/nfqws2-blobs
KEEP_RUNS=10

shells=dash
build=0
offline=0
debug=0
serial=0
only=all
custom_suites=0

# Host options are consumed here; the rest is forwarded to the entry point
# (processed arguments rotate to the end of "$@").
n=$#
while [ "$n" -gt 0 ]; do
  arg="$1"
  shift
  n=$((n - 1))
  case "$arg" in
    -h|--help) sed -n '4,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --build) build=1 ;;
    --offline) offline=1 ;;
    --serial) serial=1 ;;
    --shell)
      [ "$n" -gt 0 ] || { echo "--shell needs a value" >&2; exit 2; }
      shells="$1"
      shift
      n=$((n - 1))
      ;;
    --only)
      [ "$n" -gt 0 ] || { echo "--only needs a value" >&2; exit 2; }
      only="$1"
      shift
      n=$((n - 1))
      ;;
    --suites|--skip-suites)
      [ "$n" -gt 0 ] || { echo "$arg needs a value" >&2; exit 2; }
      custom_suites=1
      set -- "$@" "$arg" "$1"
      shift
      n=$((n - 1))
      ;;
    --debug) debug=1; set -- "$@" "$arg" ;;
    --)
      set -- "$@" "$arg"
      while [ "$n" -gt 0 ]; do
        set -- "$@" "$1"
        shift
        n=$((n - 1))
      done
      ;;
    *) set -- "$@" "$arg" ;;
  esac
done

case "$shells" in
  all) shells="dash busybox" ;;
  dash|busybox) ;;
  *) echo "--shell must be dash, busybox or all" >&2; exit 2 ;;
esac
# These suites do not depend on the POSIX shell.
case "$only" in
  lint|pytest|node) shells="${shells%% *}" ;;
esac
if [ "$custom_suites" -eq 1 ] && [ "$only" != shell ]; then
  echo "--suites and --skip-suites need --only shell" >&2
  exit 2
fi

if [ "$build" -eq 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" "$HERE"
fi

network=""
[ "$offline" -eq 1 ] && network="--network=none"
tty=""
[ "$debug" -eq 1 ] && tty="-it"

# Docker container names allow no "+" or ",".
container_name() {
  printf 'kdn-tests-%s-%s' "$$" "$(printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '-')"
}

# One test container: $1 is its name, $2 the POSIX shell, $3 the --only value;
# the rest goes to the entry point.
run_container() {
  name="$(container_name "$1")"
  container_shell="$2"
  container_only="$3"
  shift 3
  # $network and $tty are empty or a single word.
  # shellcheck disable=SC2086
  MSYS_NO_PATHCONV=1 docker run --rm --init $tty $network \
    --name "$name" \
    --cap-add NET_ADMIN \
    --shm-size 512m \
    --hostname kdn-tests \
    -e KDN_ENGINE \
    -e KDN_PYTEST_WORKERS \
    -e KDN_ENFORCE_COVERAGE \
    -v "$PROJECT_MOUNT:/src:ro" \
    -v "$BLOB_VOLUME:$BLOB_DIR" \
    "$IMAGE" --shell "$container_shell" --only "$container_only" "$@"
}

# Runs one container in a pipeline: the full output goes to its own log, every
# line to the terminal with a [name] prefix (read, not awk: mawk holds its
# input back until a block is full); the exit code goes to <name>.rc.
# Both files live in $run_dir, which belongs to this run alone.
run_prefixed() {
  prefixed_name="$1"
  shift
  {
    prefixed_rc=0
    run_container "$prefixed_name" "$@" || prefixed_rc=$?
    echo "$prefixed_rc" > "$run_dir/$prefixed_name.rc"
  } 2>&1 |
    tee "$run_dir/$prefixed_name.log" |
    while IFS= read -r prefixed_line || [ -n "$prefixed_line" ]; do
      printf '[%s] %s\n' "$prefixed_name" "$prefixed_line"
    done
}

# The shell suites of a parallel run: one container per group and shell, the
# groups balanced by run time (about 45 s each). The last group, "rest", runs
# every tests/test-*.sh the others do not name, so a new suite is never left
# out.
SHELL_GROUPS="test-routing-modes-telegram.sh,test-standalone-zapret.sh,test-run-tests.sh,test-panel-init.sh
  test-engine-golden-profiles.sh,test-engine-dispatch.sh,test-engine-compare.sh,test-nfqws-fixture.sh
  test-engine-golden-states.sh,test-lock-protocol.sh
  test-routing-modes-routes.sh,test-engine-stage-lines.sh,test-transaction.sh
  test-routing-modes-profiles.sh,test-routing-modes-snapshots.sh
  rest"
named_suites=""
for group in $SHELL_GROUPS; do
  [ "$group" = rest ] || named_suites="$named_suites${named_suites:+,}$group"
done

# --shell all, not --serial: one container per "<name>:<shell>:<only>:<group>"
# job (no group: every shell suite, or those of --suites / --skip-suites).
jobs=""
if [ "$serial" -eq 0 ] && [ "$debug" -eq 0 ] && [ "$shells" = "dash busybox" ]; then
  case "$only" in
    all|shell)
      for shell in $shells; do
        if [ "$custom_suites" -eq 1 ]; then
          jobs="$jobs $shell:$shell:shell:"
          continue
        fi
        group_number=0
        for group in $SHELL_GROUPS; do
          group_number=$((group_number + 1))
          jobs="$jobs $shell-$group_number:$shell:shell:$group"
        done
      done
      [ "$only" = shell ] || jobs="$jobs py+node-1:dash:pytest: py+node-2:dash:node:"
      ;;
  esac
fi

# Kills the containers of this run by name (the blob pre-fetch included).
stop_containers() {
  docker kill "$(container_name blobs)" >/dev/null 2>&1 || true
  for job in $jobs; do
    docker kill "$(container_name "${job%%:*}")" >/dev/null 2>&1 || true
  done
}

summary=""
status=0
if [ -n "$jobs" ]; then
  # Runs overlap (parallel agents, a second terminal): exit codes and logs
  # must not be shared, so every run gets a directory of its own.
  run_dir="$LOG_DIR/run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mkdir -p "$run_dir"
  # Native Windows Git Bash may expose a symlink as a regular placeholder.
  # Never overwrite an existing non-link; keep an explicit path pointer instead.
  if [ ! -e "$LOG_DIR/latest" ] || [ -L "$LOG_DIR/latest" ]; then
    ln -sfn "$run_dir" "$LOG_DIR/latest" 2>/dev/null || printf '%s\n' "$run_dir" > "$LOG_DIR/latest.path"
  else
    printf '%s\n' "$run_dir" > "$LOG_DIR/latest.path"
  fi
  ls -1d "$LOG_DIR"/run-* | sort -r | tail -n +"$((KEEP_RUNS + 1))" | while read -r old_run; do
    rm -rf "$old_run"
  done
  # Ctrl-C reaches only the foreground shell: stop the containers by name.
  trap 'stop_containers; exit 130' HUP INT TERM
  # The containers share the blob volume: fill it once here, otherwise two
  # would download the same files at the same time on a cold volume.
  # $network is empty or a single word.
  # shellcheck disable=SC2086
  MSYS_NO_PATHCONV=1 docker run --rm --init $network --entrypoint sh \
    --name "$(container_name blobs)" \
    -v "$PROJECT_MOUNT:/src:ro" \
    -v "$BLOB_VOLUME:$BLOB_DIR" \
    "$IMAGE" -c "sh /src/tests/fetch-nfqws2-blobs.sh $BLOB_DIR && sh /src/tests/fetch-nfqws2-runtime.sh $BLOB_DIR/runtime && chmod -R a+rX $BLOB_DIR" ||
    {
      echo "run-tests: cannot get the nfqws2 blobs (the first run needs network access)" >&2
      exit 1
    }
  for job in $jobs; do
    job_name="${job%%:*}"
    job_rest="${job#*:}"
    job_shell="${job_rest%%:*}"
    job_rest="${job_rest#*:}"
    job_only="${job_rest%%:*}"
    job_group="${job_rest#*:}"
    case "$job_group" in
      '') run_prefixed "$job_name" "$job_shell" "$job_only" "$@" & ;;
      rest) run_prefixed "$job_name" "$job_shell" "$job_only" --skip-suites "$named_suites" "$@" & ;;
      *) run_prefixed "$job_name" "$job_shell" "$job_only" --suites "$job_group" "$@" & ;;
    esac
  done
  wait
  trap - HUP INT TERM
  # A shell fails when any of its containers (<shell>-<n>) fails.
  per_container=""
  failed_shells=""
  shell_names=""
  for job in $jobs; do
    job_name="${job%%:*}"
    job_shell_name="${job_name%-[0-9]*}"
    case " $shell_names " in *" $job_shell_name "*) ;; *) shell_names="$shell_names $job_shell_name" ;; esac
    if [ "$(cat "$run_dir/$job_name.rc" 2>/dev/null)" = 0 ]; then
      per_container="$per_container $job_name=ok"
    else
      per_container="$per_container $job_name=FAILED"
      failed_shells="$failed_shells $job_shell_name"
      status=1
    fi
  done
  for job_shell_name in $shell_names; do
    case " $failed_shells " in
      *" $job_shell_name "*) summary="$summary $job_shell_name=FAILED" ;;
      *) summary="$summary $job_shell_name=ok" ;;
    esac
  done
  echo "run-tests: full logs in $run_dir/<name>.log"
  [ "$per_container" = "$summary" ] || echo "run-tests:$per_container"
else
  serial_all=0
  if [ "$serial" -eq 1 ] && [ "$debug" -eq 0 ] && [ "$shells" = "dash busybox" ] && [ "$only" = all ]; then
    serial_all=1
  fi
  for shell in $shells; do
    run_only="$only"
    [ "$serial_all" -eq 0 ] || run_only=shell
    if run_container "$shell" "$shell" "$run_only" "$@"; then
      summary="$summary $shell=ok"
    else
      summary="$summary $shell=FAILED"
      status=1
    fi
  done
  if [ "$serial_all" -eq 1 ]; then
    if run_container py+node dash pytest,node "$@"; then
      summary="$summary py+node=ok"
    else
      summary="$summary py+node=FAILED"
      status=1
    fi
  fi
fi
echo "run-tests:$summary"
exit "$status"
