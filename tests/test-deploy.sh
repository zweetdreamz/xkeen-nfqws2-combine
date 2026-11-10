#!/bin/sh
set -eu

# Tests for tools/dev/deploy.sh, tools/dev/deploy-remote.sh and
# tools/router/rollback-xkeen-web.sh. The router is a fixture directory
# (KDN_DEPLOY_ROOT) with mock curl, pidof and S99xkeen-web, and "ssh" is
# a script that runs the remote command locally, so nothing here contacts a
# real router. Under TEST_BUSYBOX_APPLETS=1 the remote side uses busybox sh and
# tar, as the router does.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TOOL_SHELL="${TEST_SHELL:-sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-deploy.XXXXXX")"
trap 'rm -rf "$WORK"' 0 HUP INT TERM

# Keeps the BSD tar of macOS from adding ._* copies of extended attributes.
COPYFILE_DISABLE=1
export COPYFILE_DISABLE

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

for tool in deploy.sh deploy-remote.sh deploy-manifest.txt; do
  [ -f "$SCRIPT_DIR/tools/dev/$tool" ] || fail "tools/dev/$tool: not found"
done
[ -f "$SCRIPT_DIR/tools/router/rollback-xkeen-web.sh" ] || fail "tools/router/rollback-xkeen-web.sh: not found"

# ---------------------------------------------------------------- mocks
MOCKS="$WORK/mocks"
mkdir -p "$MOCKS"

# GET http://host/<path> answers with $MOCK_DIR/panel/<path with / as _>
# ("root" for /); a missing file is a refused connection.
cat > "$MOCKS/curl" <<'EOF'
#!/bin/sh
out=""
url=""
write_code=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w) write_code=1; shift ;;
    http://*) url="$1" ;;
  esac
  shift
done
path="${url#http://*/}"
echo "GET /$path" >> "$MOCK_DIR/curl.log"
name="$(printf '%s' "$path" | tr / _)"
[ -n "$name" ] || name=root
[ -f "$MOCK_DIR/panel/$name" ] || exit 7
if [ -n "$out" ]; then
  cat "$MOCK_DIR/panel/$name" > "$out"
else
  cat "$MOCK_DIR/panel/$name"
fi
if [ "$write_code" = 1 ]; then
  if [ -f "$MOCK_DIR/panel-status/$name" ]; then cat "$MOCK_DIR/panel-status/$name"; else printf 200; fi
fi
EOF

cat > "$MOCKS/pidof" <<'EOF'
#!/bin/sh
[ -s "$MOCK_DIR/pids/$1" ] || exit 1
cat "$MOCK_DIR/pids/$1"
EOF

# Every call is logged in init.log. A start or a restart brings the panel up:
# start-fails-once: the next one fails.
# restart-changes-xray: it replaces the xray PID.
# probe-signals: it starts one child per signal (HUP INT TERM PIPE) that sends
# itself that signal; a child that survives (the signal was inherited as
# ignored) is logged in signals.survived. signals.probed counts the children.
# panel-after-restart/: files that appear in panel/ (a dead panel that the
# deploy brings back).
# init.cwd: the working directory of every start and restart (the panel
# inherits it).
# pycache-dirs: on a start (not on a restart) the panel "imports its modules":
# __pycache__/x.pyc appears in every listed directory that exists.
# stop-watch: paths whose checksum (or "absent") is appended to stop.state on
# a stop and to start.state on a start.
# stop-fails-once: the next stop fails.
cat > "$MOCKS/S99xkeen-web" <<'EOF'
#!/bin/sh
echo "$1" >> "$MOCK_DIR/init.log"
if [ -f "$MOCK_DIR/stop-watch" ] && { [ "$1" = stop ] || [ "$1" = start ]; }; then
  while IFS= read -r watched; do
    if [ -f "$watched" ]; then
      sha256sum "$watched"
    else
      echo "absent $watched"
    fi
  done < "$MOCK_DIR/stop-watch" >> "$MOCK_DIR/$1.state"
fi
if [ "$1" = stop ] && [ -f "$MOCK_DIR/stop-fails-once" ]; then
  rm "$MOCK_DIR/stop-fails-once"
  echo "mock: stop failed"
  exit 1
fi
if [ "$1" = start ] || [ "$1" = restart ]; then
  pwd >> "$MOCK_DIR/init.cwd"
  if [ -f "$MOCK_DIR/probe-signals" ]; then
    for signal in HUP INT TERM PIPE; do
      echo "$signal" >> "$MOCK_DIR/signals.probed"
      sh -c 'kill -"$1" $$; echo "$1" >> "$2"' sh "$signal" "$MOCK_DIR/signals.survived"
    done
  fi
  if [ -f "$MOCK_DIR/start-fails-once" ]; then
    rm "$MOCK_DIR/start-fails-once"
    echo "mock: start failed"
    exit 1
  fi
  if [ "$1" = start ] && [ -f "$MOCK_DIR/pycache-dirs" ]; then
    while IFS= read -r module_dir; do
      [ ! -d "$module_dir" ] || { mkdir -p "$module_dir/__pycache__" && echo pyc > "$module_dir/__pycache__/x.pyc"; }
    done < "$MOCK_DIR/pycache-dirs"
  fi
  [ ! -f "$MOCK_DIR/restart-changes-xray" ] || echo 9999 > "$MOCK_DIR/pids/xray"
  if [ -d "$MOCK_DIR/panel-after-restart" ]; then
    mkdir -p "$MOCK_DIR/panel"
    cp "$MOCK_DIR/panel-after-restart"/* "$MOCK_DIR/panel/"
  fi
fi
exit 0
EOF

cat > "$WORK/fake-ssh.sh" <<'EOF'
#!/bin/sh
echo "$1" >> "$MOCK_DIR/ssh.log"
PATH="$REMOTE_PATH"
export PATH
exec sh -c "$1"
EOF

REMOTE_PATH="$PATH"
if [ "${TEST_BUSYBOX_APPLETS:-0}" = "1" ] && command -v busybox >/dev/null 2>&1; then
  mkdir -p "$WORK/shim"
  for applet in sh tar; do
    printf '#!/bin/sh\nexec busybox %s "$@"\n' "$applet" > "$WORK/shim/$applet"
    chmod 755 "$WORK/shim/$applet"
  done
  REMOTE_PATH="$WORK/shim:$PATH"
fi
export REMOTE_PATH

# ---------------------------------------------------------------- fixtures
PROJECT_REL=opt/root/keenetic-discord-nfqws2
NEW_PANEL='# panel version NEW
print("panel")'
OLD_PANEL='# panel version OLD'

make_project() {
  p="$1"
  mkdir -p "$p/tools/dev" "$p/scripts" "$p/config/blobs" "$p/tools/router" "$p/tools/windows" "$p/extras/new"
  cp "$SCRIPT_DIR/tools/dev/deploy.sh" "$SCRIPT_DIR/tools/dev/deploy-remote.sh" "$p/tools/dev/"
  mkdir -p "$p/tools/router/kdn/common"
  cp "$SCRIPT_DIR/tools/router/kdn/common/xkeen.py" "$p/tools/router/kdn/common/xkeen.py"
  cat > "$p/tools/dev/deploy-manifest.txt" <<'EOF'
# fixture manifest
scripts/*.sh
config/*.json
config/blobs/*.bin
tools/router/*.py
tools/router/*.sh
tools/router/kdn/common/xkeen.py
tools/windows/*.ps1
extras/new/tool.py
EOF
  cat > "$p/.gitattributes" <<'EOF'
* text=auto
*.sh text eol=lf
*.py text eol=lf
*.json text eol=lf
*.ps1 text eol=crlf
*.bin -text
EOF
  printf '#!/bin/sh\necho diagnose NEW\n' > "$p/scripts/diagnose.sh"
  printf '#!/bin/sh\necho fresh\n' > "$p/scripts/fresh.sh"
  printf 'print("helper NEW")\n' > "$p/tools/router/helper.py"
  printf '{"sample": "NEW"}\n' > "$p/config/sample.json"
  # A binary file with CRLF bytes inside: .gitattributes says -text.
  printf 'a\r\nb\r\n\000\001\n' > "$p/config/blobs/sample.bin"
  printf 'Write-Host "reset"\r\n' > "$p/tools/windows/reset.ps1"
  printf 'print("extras")\n' > "$p/extras/new/tool.py"
  printf 'unrelated project file\n' > "$p/README.md"
  cat > "$p/tools/router/xkeen_control_script.sh" <<'EOF'
#!/bin/sh
set -eu
APP_DIR="${XKEEN_WEB_DIR:-/opt/xkeen-web}"
mkdir -p "$APP_DIR"
cat > "$APP_DIR/app.py" <<'PYEOF'
# panel version NEW
print("panel")
PYEOF
echo "installed"
EOF
}

make_router() {
  r="$1"
  m="$2"
  proj="$r/$PROJECT_REL"
  mkdir -p "$r/opt/bin" "$r/opt/etc/init.d" "$r/opt/etc/nfqws2" "$r/opt/etc/xray/configs" \
    "$r/opt/etc/xkeen-web-backups" "$r/opt/tmp" "$r/opt/xkeen-web" \
    "$proj/scripts" "$proj/tools/router" "$proj/tools/windows" "$proj/config/blobs" \
    "$m/panel" "$m/pids"
  : > "$r/opt/tmp/kdn-software.lock"
  cp "$MOCKS/curl" "$MOCKS/pidof" "$r/opt/bin/"
  printf '#!/bin/sh\n[ "$1" = -v ] || exit 97\ncat "$MOCK_DIR/xkeen-version" 2>/dev/null || echo "XKeen 2.1.1 Stable"\n' > "$r/opt/bin/xkeen"
  chmod 755 "$r/opt/bin/xkeen"
  cp "$MOCKS/S99xkeen-web" "$r/opt/etc/init.d/"
  chmod 755 "$r/opt/bin/curl" "$r/opt/bin/pidof" "$r/opt/etc/init.d/S99xkeen-web"
  printf 'nfqws2 config\n' > "$r/opt/etc/nfqws2/nfqws2.conf"
  printf '{"routing": 1}\n' > "$r/opt/etc/xray/configs/05_routing.json"
  printf '{"outbounds": 1}\n' > "$r/opt/etc/xray/configs/10_outbounds.json"
  printf '%s\n' "$OLD_PANEL" > "$r/opt/xkeen-web/app.py"
  chmod 700 "$r/opt/xkeen-web/app.py"
  # Previous versions of some of the files (modes differ on purpose); fresh.sh
  # and extras/ do not exist yet.
  printf '#!/bin/sh\necho diagnose OLD\n' > "$proj/scripts/diagnose.sh"
  printf 'print("helper OLD")\n' > "$proj/tools/router/helper.py"
  printf '#!/bin/sh\necho old installer\n' > "$proj/tools/router/xkeen_control_script.sh"
  printf '{"sample": "OLD"}\n' > "$proj/config/sample.json"
  printf 'old blob\n' > "$proj/config/blobs/sample.bin"
  printf 'Write-Host "reset"\r\n' > "$proj/tools/windows/reset.ps1"
  printf 'unrelated router file\n' > "$proj/README.md"
  chmod 644 "$proj/scripts/diagnose.sh" "$proj/tools/router/xkeen_control_script.sh" "$proj/config/sample.json"
  chmod 600 "$proj/tools/router/helper.py" "$proj/README.md"
  printf '1234\n' > "$m/pids/xray"
  printf '5678\n' > "$m/pids/nfqws2"
  printf '<html>panel</html>\n' > "$m/panel/root"
  for endpoint in api_route_status api_tuner_status api_diagnostics_status api_automation; do
    printf '{"active": false}\n' > "$m/panel/$endpoint"
  done
  printf '{"ok": true}\n' > "$m/panel/api_vpn-nodes"
}

# A fresh project and router per case; CASE is the case directory.
new_case() {
  CASE="$WORK/$1"
  mkdir -p "$CASE"
  make_project "$CASE/project"
  make_router "$CASE/router" "$CASE/mock"
  SKIP='^\./opt/tmp(/|$)'
}

# ---------------------------------------------------------------- runners
# RC and $CASE/out.txt (stdout and stderr) are the result of a run.
run_deploy() {
  RC=0
  (
    cd "$CASE/project"
    MOCK_DIR="$CASE/mock"
    KDN_DEPLOY_ROOT="$CASE/router"
    KDN_ALLOW_DEPLOY_ROOT=1
    KDN_READY_PAUSE=0
    export MOCK_DIR KDN_DEPLOY_ROOT KDN_ALLOW_DEPLOY_ROOT KDN_READY_PAUSE
    # TOOL_SHELL is split on purpose ("busybox sh").
    # shellcheck disable=SC2086
    $TOOL_SHELL tools/dev/deploy.sh --ssh "sh $WORK/fake-ssh.sh" "$@"
  ) > "$CASE/out.txt" 2>&1 || RC=$?
}

# deploy-remote.sh on an existing stage directory.
run_remote() {
  RC=0
  (
    cd "$CASE/project"
    PATH="$REMOTE_PATH"
    MOCK_DIR="$CASE/mock"
    KDN_DEPLOY_ROOT="$CASE/router"
    KDN_ALLOW_DEPLOY_ROOT=1
    KDN_READY_PAUSE=0
    export PATH MOCK_DIR KDN_DEPLOY_ROOT KDN_ALLOW_DEPLOY_ROOT KDN_READY_PAUSE
    # shellcheck disable=SC2086
    $TOOL_SHELL tools/dev/deploy-remote.sh "$@"
  ) > "$CASE/out.txt" 2>&1 || RC=$?
}

run_rollback_launcher() {
  RC=0
  (
    cd "$CASE/project"
    MOCK_DIR="$CASE/mock"
    KDN_DEPLOY_ROOT="$CASE/router"
    KDN_ALLOW_DEPLOY_ROOT=1
    export MOCK_DIR KDN_DEPLOY_ROOT KDN_ALLOW_DEPLOY_ROOT
    # shellcheck disable=SC2086
    $TOOL_SHELL "$SCRIPT_DIR/tools/router/rollback-xkeen-web.sh"
  ) > "$CASE/out.txt" 2>&1 || RC=$?
}

# ---------------------------------------------------------------- assertions
show_output() {
  sed 's/^/    | /' "$CASE/out.txt" >&2
}

expect_rc() {
  [ "$RC" -eq "$1" ] || {
    show_output
    fail "$2: exit code $RC, expected $1"
  }
}

expect_out() {
  grep -Fq -- "$1" "$CASE/out.txt" || {
    show_output
    fail "$2: output lacks: $1"
  }
}

expect_out_re() {
  grep -Eq -- "$1" "$CASE/out.txt" || {
    show_output
    fail "$2: output does not match: $1"
  }
}

expect_content() {
  printf '%s\n' "$2" | cmp -s - "$1" || fail "$3: unexpected content of $1"
}

expect_same() {
  cmp -s "$1" "$2" || fail "$3: $1 differs from $2"
}

mode_of() {
  ls -ld "$1" | cut -c1-10
}

expect_mode() {
  [ "$(mode_of "$1")" = "$2" ] || fail "$3: $1 has mode $(mode_of "$1"), expected $2"
}

expect_count() {
  actual="$(wc -l < "$1" | tr -d ' ')"
  [ "$actual" = "$2" ] || fail "$3: $1 has $actual lines, expected $2"
}

# Every file and directory under DIR with mode and checksum, minus the paths
# that match the ERE in $SKIP.
tree_state() {
  (
    cd "$1"
    find . | LC_ALL=C sort | grep -Ev "$SKIP" | while IFS= read -r entry; do
      if [ -d "$entry" ]; then
        printf 'd %s\n' "$entry"
      else
        printf 'f %s %s %s\n' "$entry" "$(mode_of "$entry")" "$(sha256sum "$entry" | cut -d' ' -f1)"
      fi
    done
  )
}

remember_router() {
  tree_state "$CASE/router" > "$CASE/before.state"
}

expect_router_unchanged() {
  tree_state "$CASE/router" > "$CASE/after.state"
  cmp -s "$CASE/before.state" "$CASE/after.state" || {
    diff -u "$CASE/before.state" "$CASE/after.state" >&2 || true
    fail "$1: the router tree changed"
  }
}

# ---------------------------------------------------------------- (a) success
new_case a
for stamp in 20200101T000000Z 20200102T000000Z 20200103T000000Z; do
  mkdir -p "$CASE/router/opt/tmp/kdn-deploy-$stamp"
done
mkdir -p "$CASE/router/opt/tmp/unrelated"
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
remember_router
run_deploy
expect_rc 0 "(a) deploy"
expect_out "deploy: ok backup=" "(a)"
expect_out "xray pid=1234" "(a)"
backup="$(sed -n 's/^deploy: ok backup=//p' "$CASE/out.txt")"
[ -d "$backup/project" ] || fail "(a) backup directory not found: $backup"

router_project="$CASE/router/$PROJECT_REL"
for file in scripts/diagnose.sh scripts/fresh.sh tools/router/helper.py tools/router/xkeen_control_script.sh \
  config/sample.json config/blobs/sample.bin tools/windows/reset.ps1 extras/new/tool.py; do
  expect_same "$CASE/project/$file" "$router_project/$file" "(a) $file"
done
for file in scripts/diagnose.sh scripts/fresh.sh tools/router/helper.py tools/router/xkeen_control_script.sh extras/new/tool.py; do
  expect_mode "$router_project/$file" -rwxr-xr-x "(a) $file"
done
for file in config/sample.json config/blobs/sample.bin tools/windows/reset.ps1; do
  expect_mode "$router_project/$file" -rw-r--r-- "(a) $file"
done
expect_content "$CASE/router/opt/xkeen-web/app.py" "$NEW_PANEL" "(a) panel app.py"
expect_mode "$CASE/router/opt/xkeen-web/app.py" -rwx------ "(a) panel app.py"
expect_content "$router_project/README.md" "unrelated router file" "(a) untouched file"
[ -z "$(find "$CASE/router" -name '*.deploy.*' -o -name '*.rollback.*')" ] || fail "(a) temporary files left behind"

# The package is a plain ustar archive without ._* entries: macOS extended
# attributes would end up in PAX headers that the tar of busybox may not read.
package="$(ls "$CASE"/project/.cache/deploy/*/upload.tar.gz)"
python3 -I - "$package" <<'PY' || fail "(a) the package is not a plain ustar archive"
import gzip
import sys

data = gzip.open(sys.argv[1]).read()
offset = 0
while offset + 512 <= len(data) and data[offset:offset + 512] != b"\0" * 512:
    header = data[offset:offset + 512]
    name = header[:100].rstrip(b"\0")
    size = int(header[124:136].rstrip(b"\0 ") or b"0", 8)
    # ustar magic and version; x/g/L/K headers are PAX and GNU extensions.
    if header[257:265] != b"ustar\x0000" or header[156:157] in (b"x", b"g", b"L", b"K") or name.startswith(b"._"):
        sys.exit(1)
    offset += 512 + (size + 511) // 512 * 512
PY

# The backup holds the previous versions, the panel and the list of new files.
expect_content "$backup/project/scripts/diagnose.sh" "$(printf '#!/bin/sh\necho diagnose OLD')" "(a) backup"
expect_content "$backup/project/config/sample.json" '{"sample": "OLD"}' "(a) backup"
expect_content "$backup/project/tools/router/helper.py" 'print("helper OLD")' "(a) backup"
expect_mode "$backup/project/tools/router/helper.py" -rw------- "(a) backup keeps the mode"
expect_content "$backup/app.py" "$OLD_PANEL" "(a) backup app.py"
expect_content "$backup/NEW_FILES" "extras/new/tool.py
scripts/fresh.sh
tools/router/kdn/common/xkeen.py" "(a) NEW_FILES"
[ ! -e "$backup/project/scripts/fresh.sh" ] || fail "(a) a new file was backed up"
expect_content "$CASE/router/opt/etc/xkeen-web-backups/latest.path" "$backup" "(a) latest.path"
expect_content "$CASE/mock/init.log" "stop
start" "(a) the panel stops, then starts once"
# The stage directory is pruned later: the panel must not keep it as its cwd.
expect_content "$CASE/mock/init.cwd" "/" "(a) the panel starts from /"
expect_content "$backup/PROJECT_DIR" "/$PROJECT_REL" "(a) the backup records the project directory"

# Only the two newest staging directories remain.
ls "$CASE/router/opt/tmp" > "$CASE/tmp.list"
expect_count "$CASE/tmp.list" 4 "(a) staging cleanup (two stages, unrelated dir, permanent lock)"
grep -Fxq unrelated "$CASE/tmp.list" || fail "(a) cleanup removed an unrelated directory"
grep -Fxq kdn-deploy-20200103T000000Z "$CASE/tmp.list" || fail "(a) cleanup removed the second newest stage"

# The rollback launcher puts everything back (g1).
run_rollback_launcher
expect_rc 0 "(g1) rollback launcher"
expect_out "Panel software restored from: $backup" "(g1)"
expect_router_unchanged "(g1) after the rollback launcher"
expect_content "$CASE/mock/init.log" "stop
start
stop
start
status" "(g1) panel calls"

# (g1b) the panel wrote __pycache__ into the directories the deploy created: the
# launcher removes them with it. An existing directory keeps its __pycache__.
new_case g1b
SKIP="^\./opt/(tmp|etc/xkeen-web-backups)(/|\$)|^\./$PROJECT_REL/tools/router/__pycache__(/|\$)"
router_project="$CASE/router/$PROJECT_REL"
printf '%s\n' "$router_project/extras/new" "$router_project/extras" "$router_project/tools/router" \
  > "$CASE/mock/pycache-dirs"
remember_router
run_deploy
expect_rc 0 "(g1b) deploy"
expect_content "$router_project/extras/new/__pycache__/x.pyc" pyc "(g1b) the panel wrote __pycache__"
run_rollback_launcher
expect_rc 0 "(g1b) rollback launcher"
[ ! -e "$router_project/extras" ] || fail "(g1b) the new directory (with its __pycache__) is still there"
expect_router_unchanged "(g1b) the launcher removed the new directories"
expect_content "$router_project/tools/router/__pycache__/x.pyc" pyc "(g1b) an existing directory keeps its __pycache__"

# (a2) a dead panel does not block the deploy, the start brings it back.
new_case a2
rm -f "$CASE/mock/panel"/*
mkdir -p "$CASE/mock/panel-after-restart"
printf '<html>panel</html>\n' > "$CASE/mock/panel-after-restart/root"
printf '{"ok": true}\n' > "$CASE/mock/panel-after-restart/api_vpn-nodes"
run_deploy
expect_rc 0 "(a2) deploy with a dead panel"
expect_out "deploy: ok backup=" "(a2)"

# ---------------------------------------------------------------- (b) busy
for pair in route_status:/api/route/status tuner_status:/api/tuner/status \
  diagnostics_status:/api/diagnostics/status automation:/api/automation; do
  new_case "b-${pair%%:*}"
  printf '{"active": true}\n' > "$CASE/mock/panel/api_${pair%%:*}"
  remember_router
  run_deploy
  expect_rc 3 "(b) ${pair#*:}"
  expect_out "deploy: busy (${pair#*:})" "(b)"
  expect_router_unchanged "(b) ${pair#*:}"
  [ ! -e "$CASE/mock/init.log" ] || fail "(b) the panel was restarted"
done

# ---------------------------------------------------------------- (c) the panel does not come up
new_case busy403
mkdir -p "$CASE/mock/panel-status"
printf 403 > "$CASE/mock/panel-status/api_route_status"
remember_router
run_deploy
expect_rc 2 'busy check 403'
expect_out "panel refused the busy check (HTTP 403): KDN_PANEL" 'busy check 403'
expect_router_unchanged 'busy check 403'
[ ! -e "$CASE/mock/init.log" ] || fail '403 restarted the panel'

new_case busy500
mkdir -p "$CASE/mock/panel-status"
printf 500 > "$CASE/mock/panel-status/api_route_status"
printf '{"active":true}' > "$CASE/mock/panel/api_route_status"
run_deploy
expect_rc 0 'busy check ignores 500'

new_case c
printf '{"ok": false}\n' > "$CASE/mock/panel/api_vpn-nodes"
: > "$CASE/mock/probe-signals"
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
remember_router
run_deploy
expect_rc 1 "(c) deploy"
expect_out "panel did not become ready" "(c)"
expect_router_unchanged "(c) the previous files, the panel and the new-file directories are restored"
expect_content "$CASE/mock/init.log" "stop
start
stop
restart" "(c) deploy stop and start, rollback stop then restart"
grep -Fx "GET /api/vpn-nodes" "$CASE/mock/curl.log" > "$CASE/probes.log"
expect_count "$CASE/probes.log" 15 "(c) readiness attempts"
# The panel started by the deploy and by the rollback gets default signal
# dispositions, not the ignored ones of the script.
expect_count "$CASE/mock/signals.probed" 8 "(c) signal probes (a start and a restart, 4 signals)"
[ ! -s "$CASE/mock/signals.survived" ] || fail "(c) the panel started with ignored signals: $(tr '\n' ' ' < "$CASE/mock/signals.survived")"
expect_content "$CASE/mock/init.cwd" "/
/" "(c) the start and the restart run from /"
backup="$(ls -d "$CASE/router/opt/etc/xkeen-web-backups"/*-deploy)"
[ -f "$backup/NEW_FILES" ] || fail "(c) the backup of the failed deploy is gone"
# There was no backup before this deploy: the pointer must not name the failed one.
[ ! -e "$CASE/router/opt/etc/xkeen-web-backups/latest.path" ] || fail "(c) latest.path still names the failed deploy"

# (c7) After a restored deploy, latest.path names the previous good backup: the
# rollback launcher then undoes that deploy, not the failed one (T6).
new_case c7
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
remember_router
run_deploy
expect_rc 0 "(c7) first deploy"
first_backup="$(sed -n 's/^deploy: ok backup=//p' "$CASE/out.txt")"
printf '{"ok": false}\n' > "$CASE/mock/panel/api_vpn-nodes"
run_deploy
expect_rc 1 "(c7) second deploy"
expect_out "panel did not become ready" "(c7)"
expect_content "$CASE/router/opt/etc/xkeen-web-backups/latest.path" "$first_backup" "(c7) latest.path after the restored deploy"
[ "$(ls -d "$CASE/router/opt/etc/xkeen-web-backups"/*-deploy* | wc -l | tr -d ' ')" = 2 ] || fail "(c7) the failed deploy's backup is gone"
run_rollback_launcher
expect_rc 0 "(c7) rollback launcher"
expect_out "Panel software restored from: $first_backup" "(c7)"
expect_router_unchanged "(c7) the launcher undid the first deploy"

# (c2) xray restarted by a deploy is an error as well.
new_case c2
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
: > "$CASE/mock/restart-changes-xray"
remember_router
run_deploy
expect_rc 1 "(c2) deploy"
expect_out "invariants changed" "(c2)"
expect_router_unchanged "(c2) restored after an invariant change"

# (c3) a failing start is rolled back as well.
new_case c3
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
: > "$CASE/mock/start-fails-once"
remember_router
run_deploy
expect_rc 1 "(c3) deploy"
expect_out "panel start failed" "(c3)"
expect_router_unchanged "(c3) restored after a failed start"
expect_content "$CASE/mock/init.log" "stop
start
stop
restart" "(c3) deploy stop and start, rollback stop then restart"

# (c4) a project file that is a directory: refused before anything changes.
new_case c4
rm "$CASE/router/$PROJECT_REL/scripts/diagnose.sh"
mkdir "$CASE/router/$PROJECT_REL/scripts/diagnose.sh"
remember_router
run_deploy
expect_rc 1 "(c4) deploy"
expect_out "not a regular file" "(c4)"
expect_out "nothing was changed" "(c4)"
expect_router_unchanged "(c4) no backup, no changes"
[ ! -e "$CASE/mock/init.log" ] || fail "(c4) the panel was restarted"

# (c5) The ssh session is gone (stdout and stderr are a pipe whose reader has
# already exited) while the panel does not come up: the rollback still runs.
new_case c5
printf '{"ok": false}\n' > "$CASE/mock/panel/api_vpn-nodes"
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
run_deploy --dry-run
expect_rc 0 "(c5) upload and dry run"
stage="$(ls -d "$CASE/router"/opt/tmp/kdn-deploy-*)"
remember_router
(
  cd "$CASE/project"
  PATH="$REMOTE_PATH"
  MOCK_DIR="$CASE/mock"
  KDN_DEPLOY_ROOT="$CASE/router"
  KDN_ALLOW_DEPLOY_ROOT=1
  KDN_READY_PAUSE=0
  export PATH MOCK_DIR KDN_DEPLOY_ROOT KDN_ALLOW_DEPLOY_ROOT KDN_READY_PAUSE
  rc=0
  # shellcheck disable=SC2086
  $TOOL_SHELL tools/dev/deploy-remote.sh --stage "$stage" || rc=$?
  echo "$rc" > "$CASE/rc.txt"
) 2>&1 | true
expect_content "$CASE/rc.txt" 1 "(c5) exit code with a broken pipe"
expect_router_unchanged "(c5) restored although nothing could be printed"
grep -Fx "GET /api/vpn-nodes" "$CASE/mock/curl.log" > "$CASE/probes.log"
expect_count "$CASE/probes.log" 15 "(c5) readiness attempts"
expect_content "$CASE/mock/init.log" "stop
start
stop
restart" "(c5) deploy stop and start, rollback stop then restart"
grep -Fq "panel did not become ready" "$stage/deploy.log" || fail "(c5) the outcome is not in $stage/deploy.log"
grep -Fq "restored the previous files" "$stage/deploy.log" || fail "(c5) the rollback is not in $stage/deploy.log"

# (c6) TERM during the readiness wait rolls back as well.
new_case c6
printf '{"ok": false}\n' > "$CASE/mock/panel/api_vpn-nodes"
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
run_deploy --dry-run
expect_rc 0 "(c6) upload and dry run"
stage="$(ls -d "$CASE/router"/opt/tmp/kdn-deploy-*)"
remember_router
(
  cd "$CASE/project"
  PATH="$REMOTE_PATH"
  MOCK_DIR="$CASE/mock"
  KDN_DEPLOY_ROOT="$CASE/router"
  KDN_ALLOW_DEPLOY_ROOT=1
  KDN_READY_PAUSE=1
  export PATH MOCK_DIR KDN_DEPLOY_ROOT KDN_ALLOW_DEPLOY_ROOT KDN_READY_PAUSE
  # shellcheck disable=SC2086
  exec $TOOL_SHELL tools/dev/deploy-remote.sh --stage "$stage"
) > "$CASE/out.txt" 2>&1 &
deploy_pid=$!
waited=0
until grep -Fxq "GET /api/vpn-nodes" "$CASE/mock/curl.log" 2>/dev/null; do
  waited=$((waited + 1))
  [ "$waited" -lt 30 ] || fail "(c6) the deploy never reached the readiness wait"
  sleep 1
done
kill -TERM "$deploy_pid"
RC=0
wait "$deploy_pid" || RC=$?
expect_rc 1 "(c6) TERM during the readiness wait"
expect_router_unchanged "(c6) restored after TERM"
grep -Fq "restored the previous files" "$stage/deploy.log" || fail "(c6) the rollback is not in $stage/deploy.log"

# ---------------------------------------------------------------- (k) the panel is down while the files are copied
# A worker that the panel starts in the middle of the copy would import a mix
# of old and new modules: the panel stops before the first file changes and
# starts after the last one.
watch_state() {
  while IFS= read -r watched; do
    if [ -f "$watched" ]; then
      sha256sum "$watched"
    else
      echo "absent $watched"
    fi
  done < "$CASE/mock/stop-watch"
}

new_case k
router_project="$CASE/router/$PROJECT_REL"
{
  for file in scripts/diagnose.sh scripts/fresh.sh tools/router/helper.py tools/router/xkeen_control_script.sh \
    config/sample.json config/blobs/sample.bin tools/windows/reset.ps1 extras/new/tool.py; do
    echo "$router_project/$file"
  done
  echo "$CASE/router/opt/xkeen-web/app.py"
} > "$CASE/mock/stop-watch"
watch_state > "$CASE/watch.before"
run_deploy
expect_rc 0 "(k) deploy"
watch_state > "$CASE/watch.after"
if cmp -s "$CASE/watch.before" "$CASE/watch.after"; then fail "(k) the deploy installed nothing"; fi
expect_same "$CASE/mock/stop.state" "$CASE/watch.before" "(k) a file changed before the panel stopped"
expect_same "$CASE/mock/start.state" "$CASE/watch.after" "(k) the panel started before the last file was installed"
expect_content "$CASE/mock/init.log" "stop
start" "(k) stop, then start, no restart"

# (k2) a failing stop leaves nothing installed and the panel is brought back.
new_case k2
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
: > "$CASE/mock/stop-fails-once"
remember_router
run_deploy
expect_rc 1 "(k2) deploy"
expect_out "panel stop failed" "(k2)"
expect_router_unchanged "(k2) restored after a failed stop"
expect_content "$CASE/mock/init.log" "stop" "(k2) failed stop refuses without a restore/restart"

# ---------------------------------------------------------------- (l) a job outlives the stopped panel
# A job process that is alive after the stop (its pid file names it) stops the
# deploy: the panel starts again and nothing stays behind, not even the backup.
for pidfile in xkeen-route-switch/worker.pid xkeen-zapret-tuner/panel-launch.pid xkeen-diagnostics/panel-launch.pid; do
  new_case "l-${pidfile%%/*}"
  SKIP='^\./opt/tmp/kdn-deploy-'
  mkdir -p "$CASE/router/opt/tmp/${pidfile%/*}" "$CASE/router/opt/etc/xkeen-web-backups/20200101-000000-deploy"
  printf '%s\n' "$CASE/router/opt/etc/xkeen-web-backups/20200101-000000-deploy" \
    > "$CASE/router/opt/etc/xkeen-web-backups/latest.path"
  chmod 600 "$CASE/router/opt/etc/xkeen-web-backups/latest.path"
  sleep 30 &
  job=$!
  printf '%s\n' "$job" > "$CASE/router/opt/tmp/$pidfile"
  remember_router
  run_deploy
  kill "$job" 2>/dev/null || true
  wait "$job" 2>/dev/null || true
  expect_rc 3 "(l) $pidfile"
  expect_out "deploy: busy ($CASE/router/opt/tmp/$pidfile); delete the file if that pid is not a running panel job" \
    "(l) $pidfile"
  expect_content "$CASE/mock/init.log" "stop
start" "(l) $pidfile: the panel stops and starts again"
  expect_router_unchanged "(l) $pidfile: no file, backup or pointer changed"
done

# (l2) what is not a live job does not block: a finished process, text, PID 0
# (kill -0 0 would address the process group of the deploy).
new_case l2
mkdir -p "$CASE/router/opt/tmp/xkeen-route-switch" "$CASE/router/opt/tmp/xkeen-zapret-tuner" \
  "$CASE/router/opt/tmp/xkeen-diagnostics"
sleep 0 &
finished=$!
wait "$finished" || true
printf '%s\n' "$finished" > "$CASE/router/opt/tmp/xkeen-route-switch/worker.pid"
echo "not a pid" > "$CASE/router/opt/tmp/xkeen-zapret-tuner/panel-launch.pid"
echo 0 > "$CASE/router/opt/tmp/xkeen-diagnostics/panel-launch.pid"
run_deploy
expect_rc 0 "(l2) deploy with stale pid files"
expect_content "$CASE/mock/init.log" "stop
start" "(l2) stop and start"

# ---------------------------------------------------------------- (m) __pycache__ in new directories
# The panel writes __pycache__ into the directories it imports from; the
# rollback removes the directories the deploy created, so it removes
# __pycache__ first. An existing directory keeps whatever it holds.
new_case m
SKIP="^\./opt/(tmp|etc/xkeen-web-backups)(/|\$)|^\./$PROJECT_REL/tools/router/__pycache__(/|\$)"
router_project="$CASE/router/$PROJECT_REL"
printf '%s\n' "$router_project/extras/new" "$router_project/extras" "$router_project/tools/router" \
  > "$CASE/mock/pycache-dirs"
printf '{"ok": false}\n' > "$CASE/mock/panel/api_vpn-nodes"
remember_router
run_deploy
expect_rc 1 "(m) deploy"
expect_out "panel did not become ready" "(m)"
expect_content "$CASE/mock/init.log" "stop
start
stop
restart" "(m) deploy stop and start, rollback stop then restart"
[ ! -e "$router_project/extras" ] || fail "(m) the new directory (with its __pycache__) is still there"
expect_router_unchanged "(m) the new directories are gone, the rest is as before"
expect_content "$router_project/tools/router/__pycache__/x.pyc" pyc "(m) an existing directory keeps its __pycache__"

# ---------------------------------------------------------------- (d) invalid archives
make_archive() {
  python3 -I - "$@" <<'PY'
import io
import sys
import tarfile

out, name, kind, link = sys.argv[1:5]
kinds = {
    "file": tarfile.REGTYPE,
    "symlink": tarfile.SYMTYPE,
    "hardlink": tarfile.LNKTYPE,
    "dir": tarfile.DIRTYPE,
}
with tarfile.open(out, "w:gz") as tar:
    def add(entry, data=b"", kind=tarfile.REGTYPE, link="", mode=0o644):
        info = tarfile.TarInfo(entry)
        info.type = kind
        info.mode = mode
        info.linkname = link
        info.size = len(data) if kind == tarfile.REGTYPE else 0
        tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)

    add("generated/app.py", b"print('x')\n")
    add("scripts/diagnose.sh", b"#!/bin/sh\necho x\n", mode=0o755)
    add(name, b"evil\n", kinds[kind], link)
PY
}

try_archive() {
  new_case "d-$1"
  stage="$CASE/router/opt/tmp/kdn-deploy-20260101T000000Z"
  mkdir -p "$stage"
  make_archive "$stage/upload.tar.gz" "$2" "$3" "${4:-}"
  remember_router
  run_remote --stage "$stage"
  expect_rc 2 "(d) $1"
  expect_out_re "$5" "(d) $1"
  expect_router_unchanged "(d) $1"
  [ -z "$(ls -A "$stage/tree" 2>/dev/null)" ] || fail "(d) $1: the archive was unpacked"
  [ ! -e "$CASE/router/opt/tmp/evil" ] && [ ! -e "$CASE/router/opt/evil" ] || fail "(d) $1: a file escaped"
  [ ! -e "$CASE/mock/init.log" ] || fail "(d) $1: the panel was restarted"
}

try_archive parent ../evil file "" "unsafe archive entry: \.\./evil"
try_archive absolute "$WORK/abs-evil" file "" "unsafe archive entry: $WORK/abs-evil"
[ ! -e "$WORK/abs-evil" ] || fail "(d) an absolute path was written"
try_archive double-slash dir//evil file "" "unsafe archive entry: dir//evil"
try_archive whitespace "bad name" file "" "unsafe archive entry: bad name"
try_archive symlink link symlink /etc/passwd "not a regular file"
try_archive hardlink hard hardlink scripts/diagnose.sh "not a regular file"
try_archive directory dirent/ dir "" "unsafe archive entry: dirent/|not a regular file"

# (d2) the syntax check covers shell and Python files.
new_case d2-shell
printf '#!/bin/sh\nif true; then\n' > "$CASE/project/scripts/diagnose.sh"
remember_router
run_deploy
expect_rc 2 "(d2) shell syntax"
expect_out "shell syntax error in scripts/diagnose.sh" "(d2)"
expect_router_unchanged "(d2) shell syntax"
new_case d2-python
printf 'print(\n' > "$CASE/project/tools/router/helper.py"
remember_router
run_deploy
expect_rc 2 "(d2) python syntax"
expect_out "python syntax error" "(d2)"
expect_router_unchanged "(d2) python syntax"

# (d3) the panel shim needs runpy: a python3 without it stops the deploy before anything changes.
mkdir -p "$WORK/no-runpy"
REAL_PYTHON3="$(command -v python3)"
export REAL_PYTHON3
cat > "$WORK/no-runpy/python3" <<'EOF'
#!/bin/sh
# python3 of an Entware install without the runpy package: "import runpy" fails.
[ "$1" = "-I" ] && [ "$2" = "-c" ] || exec "$REAL_PYTHON3" "$@"
exec "$REAL_PYTHON3" -I -c "import sys; sys.modules['runpy'] = None; $3"
EOF
chmod 755 "$WORK/no-runpy/python3"
new_case d3
stage="$CASE/router/opt/tmp/kdn-deploy-20260101T000000Z"
mkdir -p "$stage"
remember_router
saved_remote_path="$REMOTE_PATH"
REMOTE_PATH="$WORK/no-runpy:$REMOTE_PATH"
run_remote --stage "$stage"
REMOTE_PATH="$saved_remote_path"
expect_rc 2 "(d3) python3 without runpy"
expect_out "python3 lacks the tarfile, py_compile or runpy module" "(d3)"
expect_router_unchanged "(d3) python3 without runpy"
[ ! -e "$CASE/mock/init.log" ] || fail "(d3) the panel was restarted"

# (d4) the owned VPN probe must not be shipped without its parent-death guard.
mkdir -p "$WORK/no-ctypes"
cat > "$WORK/no-ctypes/python3" <<'EOF'
#!/bin/sh
[ "$1" = "-I" ] && [ "$2" = "-c" ] || exec "$REAL_PYTHON3" "$@"
exec "$REAL_PYTHON3" -I -c "import sys; sys.modules['ctypes'] = None; $3"
EOF
chmod 755 "$WORK/no-ctypes/python3"
new_case d4
stage="$CASE/router/opt/tmp/kdn-deploy-20260101T000000Z"
mkdir -p "$stage"
remember_router
saved_remote_path="$REMOTE_PATH"
REMOTE_PATH="$WORK/no-ctypes:$REMOTE_PATH"
run_remote --stage "$stage"
REMOTE_PATH="$saved_remote_path"
expect_rc 2 "(d4) python3 without ctypes"
expect_out "python3 lacks ctypes/Linux prctl" "(d4)"
expect_router_unchanged "(d4) python3 without ctypes"
[ ! -e "$CASE/mock/init.log" ] || fail "(d4) the panel was restarted"

# ---------------------------------------------------------------- (e) dry run
new_case e
remember_router
run_deploy --dry-run
expect_rc 0 "(e) dry run"
expect_out "files to install: 9" "(e)"
expect_out_re '^ +new +extras/new/tool\.py$' "(e)"
expect_out_re '^ +new +scripts/fresh\.sh$' "(e)"
expect_out_re '^ +changed +scripts/diagnose\.sh$' "(e)"
expect_out_re '^ +same +tools/windows/reset\.ps1$' "(e)"
expect_out "xray pid=1234" "(e)"
expect_out "nfqws2 pid=5678" "(e)"
expect_out "dry run: nothing was installed" "(e)"
if grep -Fq "deploy: ok" "$CASE/out.txt"; then fail "(e) a dry run reported a deploy"; fi
expect_router_unchanged "(e) dry run"
[ ! -e "$CASE/mock/init.log" ] || fail "(e) the panel was restarted"

# ---------------------------------------------------------------- (f) CRLF while packing
new_case f1
printf '#!/bin/sh\r\necho diagnose NEW\r\n' > "$CASE/project/scripts/diagnose.sh"
remember_router
run_deploy
expect_rc 2 "(f) CRLF in a shell script"
expect_out "scripts/diagnose.sh" "(f)"
expect_out "CRLF" "(f)"
expect_router_unchanged "(f) CRLF in a shell script"
[ ! -e "$CASE/mock/ssh.log" ] || fail "(f) the router was contacted"
[ -z "$(ls -A "$CASE/project/.cache/deploy")" ] || fail "(f) a refused package was left behind"

# Without an eol=crlf rule the same Windows file is refused; -text keeps blobs out of the check.
new_case f2
printf '*.bin -text\n' > "$CASE/project/.gitattributes"
run_deploy
expect_rc 2 "(f) CRLF in a PowerShell file without a rule"
expect_out "tools/windows/reset.ps1" "(f)"
[ ! -e "$CASE/mock/ssh.log" ] || fail "(f) the router was contacted"

# Without any .gitattributes every CRLF file is refused.
new_case f3
rm "$CASE/project/.gitattributes"
run_deploy
expect_rc 2 "(f) CRLF without .gitattributes"
expect_out "CRLF" "(f)"

# ---------------------------------------------------------------- (g) rollback launcher
# (g1) ran after (a). (g2): a backup path with .. is refused even when it
# resolves into the backup directory.
new_case g2
run_deploy
expect_rc 0 "(g2) deploy"
backup="$(sed -n 's/^deploy: ok backup=//p' "$CASE/out.txt")"
printf '%s\n' "$CASE/router/opt/etc/xkeen-web-backups/../xkeen-web-backups/${backup##*/}" \
  > "$CASE/router/opt/etc/xkeen-web-backups/latest.path"
remember_router
run_rollback_launcher
expect_rc 1 "(g2) a path with .."
expect_out "unsafe panel backup path" "(g2)"
expect_router_unchanged "(g2) a path with .."
printf '/opt/etc/passwd\n' > "$CASE/router/opt/etc/xkeen-web-backups/latest.path"
run_rollback_launcher
expect_rc 1 "(g2) a path outside the backups"
expect_out "unsafe panel backup path" "(g2)"
rm "$CASE/router/opt/etc/xkeen-web-backups/latest.path"
run_rollback_launcher
expect_rc 1 "(g2) no pointer"
expect_out "panel backup pointer not found" "(g2)"

# (g3) a backup made before PROJECT_DIR was recorded restores into the default
# directory; a recorded value that is not a safe absolute path is refused.
new_case g3
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
remember_router
run_deploy
expect_rc 0 "(g3) deploy"
backup="$(sed -n 's/^deploy: ok backup=//p' "$CASE/out.txt")"
rm "$backup/PROJECT_DIR"
run_rollback_launcher
expect_rc 0 "(g3) a backup without PROJECT_DIR"
expect_router_unchanged "(g3) the default project directory"
for unsafe in 'relative/dir' '/opt/root/../etc' '/opt//root' '/opt/root/a b' ''; do
  printf '%s\n' "$unsafe" > "$backup/PROJECT_DIR"
  run_rollback_launcher
  expect_rc 1 "(g3) recorded project dir '$unsafe'"
  expect_out "unsafe project directory" "(g3) '$unsafe'"
done

# (j) deploy.sh --project-dir: the rollback launcher restores that directory,
# not the default one (M3).
new_case j
mkdir -p "$CASE/router/opt/root"
cp -R "$CASE/router/$PROJECT_REL" "$CASE/router/opt/root/alt-project"
SKIP='^\./opt/(tmp|etc/xkeen-web-backups)(/|$)'
remember_router
run_deploy --project-dir /opt/root/alt-project
expect_rc 0 "(j) deploy into a custom project directory"
backup="$(sed -n 's/^deploy: ok backup=//p' "$CASE/out.txt")"
expect_content "$backup/PROJECT_DIR" "/opt/root/alt-project" "(j) the backup records the project directory"
expect_same "$CASE/project/scripts/fresh.sh" "$CASE/router/opt/root/alt-project/scripts/fresh.sh" "(j) installed into the custom directory"
[ ! -e "$CASE/router/$PROJECT_REL/scripts/fresh.sh" ] || fail "(j) the deploy touched the default directory"
run_rollback_launcher
expect_rc 0 "(j) rollback launcher"
expect_router_unchanged "(j) the custom project directory is restored"

# ---------------------------------------------------------------- (h) the real tree
# Copy of what the real manifest covers: every manifest line must match, no
# CRLF may slip in, all Python and shell files must parse, every file of the
# panel module tools/router/kdn must ship, and the generated/app.py of the
# package must be the shim of the installer.
new_case h
rm -rf "$CASE/project"
mkdir -p "$CASE/project"
(
  cd "$SCRIPT_DIR"
  tar -cf - --exclude=__pycache__ .gitattributes LICENSE THIRD_PARTY_NOTICES.md ./*.sh scripts config tools
) | (cd "$CASE/project" && tar -xf -)
remember_router
run_deploy --dry-run
expect_rc 0 "(h) real tree dry run"
expect_out "files to install:" "(h)"
expect_out_re ' tools/router/vpn_node_manager\.py$' "(h)"
expect_out_re ' apply-discord-nfqws2\.sh$' "(h)"
expect_out_re ' tools/windows/reset-discord-cache\.ps1$' "(h)"
expect_router_unchanged "(h) real tree dry run"
python3 -I - "$SCRIPT_DIR/tools/router/xkeen_control_script.sh" > "$CASE/expected-app.py" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
sys.stdout.write(text.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF\n", 1)[0] + "\n")
PY
stage="$(ls -d "$CASE/router"/opt/tmp/kdn-deploy-*)"
expect_same "$CASE/expected-app.py" "$stage/tree/generated/app.py" "(h) panel shim"
grep -Fq 'tools", "router", "kdn", "web", "app.py"' "$CASE/expected-app.py" || fail "(h) the shim does not run the panel module"
[ "$(wc -l < "$CASE/expected-app.py" | tr -d ' ')" -le 8 ] || fail "(h) the shim is not a shim"
# A module file the manifest misses would not be on the router: the panel
# would not start.
(cd "$SCRIPT_DIR" && find tools/router/kdn -type f | grep -v __pycache__ | LC_ALL=C sort) > "$CASE/kdn.list"
expect_out_re ' tools/router/kdn/web/app\.py$' "(h)"
expect_out_re ' tools/router/kdn/web/assets/index\.html$' "(h)"
while IFS= read -r file; do
  expect_out_re " $(printf '%s' "$file" | sed 's/\./\\./g')\$" "(h) $file"
  expect_same "$SCRIPT_DIR/$file" "$stage/tree/$file" "(h) $file"
done < "$CASE/kdn.list"

# ---------------------------------------------------------------- (i) guards
new_case i
(cd "$CASE/project" && KDN_DEPLOY_ROOT="$CASE/router" $TOOL_SHELL tools/dev/deploy.sh) > "$CASE/out.txt" 2>&1 && RC=0 || RC=$?
expect_rc 2 "(i) deploy.sh without KDN_ALLOW_DEPLOY_ROOT"
expect_out "KDN_DEPLOY_ROOT is reserved" "(i)"
(cd "$CASE/project" && KDN_DEPLOY_ROOT="$CASE/router" $TOOL_SHELL tools/dev/deploy-remote.sh --stage /x) > "$CASE/out.txt" 2>&1 && RC=0 || RC=$?
expect_rc 2 "(i) deploy-remote.sh without KDN_ALLOW_DEPLOY_ROOT"
expect_out "KDN_DEPLOY_ROOT is reserved" "(i)"
(cd "$CASE/project" && KDN_DEPLOY_ROOT="$CASE/router" $TOOL_SHELL "$SCRIPT_DIR/tools/router/rollback-xkeen-web.sh") > "$CASE/out.txt" 2>&1 && RC=0 || RC=$?
expect_rc 2 "(i) rollback launcher without KDN_ALLOW_DEPLOY_ROOT"
expect_out "KDN_DEPLOY_ROOT is reserved" "(i)"
(cd "$CASE/project" && $TOOL_SHELL tools/dev/deploy.sh --nonsense) > "$CASE/out.txt" 2>&1 && RC=0 || RC=$?
expect_rc 2 "(i) unknown option"
(cd "$CASE/project" && $TOOL_SHELL tools/dev/deploy.sh --help) > "$CASE/out.txt" 2>&1 && RC=0 || RC=$?
expect_rc 0 "(i) --help"
expect_out "--dry-run" "(i)"

# A mistaken or overbroad manifest cannot authorize shipping private files.
private_n=0
for private in .pwd .env .env.router tools/router/.pwd tools/router/private.key \
  tools/router/private.pem config/raw-captures/router.json captures/raw/config.json \
  config/raw_captures/router.txt config/trace.pcap config/trace.pcapng config/session.har \
  .cache/router.json backups/plaintext.json dat/router.dat tools/windows/reports/result.json \
  config/router.tar.gz config/router.tgz config/router.zip config/router.7z config/router.ipk; do
  private_n=$((private_n + 1))
  new_case "private_path_$private_n"
  mkdir -p "$CASE/project/$(dirname "$private")"
  printf '%s\n' 'synthetic private sentinel' > "$CASE/project/$private"
  printf '%s\n' "$private" >> "$CASE/project/tools/dev/deploy-manifest.txt"
  remember_router
  run_deploy --dry-run
  expect_rc 2 "private path"
  expect_out 'private/local-only path' "private path"
  expect_router_unchanged "private path"
  [ ! -e "$CASE/mock/ssh.log" ] || fail "private manifest contacted router"
  if grep -Fq 'synthetic private sentinel' "$CASE/out.txt"; then fail "private bytes leaked"; fi
  [ -z "$(ls -A "$CASE/project/.cache/deploy")" ] || fail "private package retained"
  [ -f "$CASE/project/$private" ] || fail "private source was removed"
done

# Unsupported targets must be rejected before upload or live changes.
new_case unsupported_target
printf '%s\n' 'XKeen 2.0' > "$CASE/mock/xkeen-version"
remember_router
run_deploy --dry-run
expect_rc 2 "unsupported target"
expect_out "nothing uploaded" "unsupported target"
expect_router_unchanged "unsupported target"
[ -z "$(find "$CASE/router/opt/tmp" -name 'kdn-deploy-*' -print)" ] || fail "unsupported target uploaded a stage"

echo "deploy-tests-ok"
