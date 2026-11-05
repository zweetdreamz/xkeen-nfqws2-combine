#!/bin/sh
set -eu
unset KDN_ENGINE
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=tests/routing-modes-lib.sh
. "$SCRIPT_DIR/tests/routing-modes-lib.sh"
run_tool --apply --core xray --yes-router > "$FIXTURE/apply.log"
grep '^STAGE|' "$FIXTURE/apply.log" > "$FIXTURE/stages"
printf '%s\n' 'STAGE|preflight' 'STAGE|snapshot' 'STAGE|config' 'STAGE|xray' 'STAGE|nfqws' 'STAGE|verify' > "$FIXTURE/expected"
cmp "$FIXTURE/stages" "$FIXTURE/expected"
[ "$(tail -n 1 "$FIXTURE/apply.log")" = 'RESULT|ok' ]
[ ! -e "$ROOT/opt/tmp/keenetic-discord-nfqws2.lock" ]
make_stage discord-voice "$ROOT/opt/tmp/stage-voice.json" \
  --filter-udp=19294-19344,50000-50100 --filter-l7=stun,discord '--out-range=<n2' \
  --payload=stun,discord_ip_discovery --lua-desync=fake:blob=discord_udp:repeats=6
for action in import rollback-import import clear; do
  case "$action" in
    import) run_tool --apply-import-profile "$ROOT/opt/tmp/stage-voice.json" --yes-router > "$FIXTURE/action.log" ;;
    clear) run_tool --clear-imported-profile discord-voice --yes-router > "$FIXTURE/action.log" ;;
    rollback-import) run_tool --rollback-import --yes-router > "$FIXTURE/action.log" ;;
  esac
  if [ "$action" = rollback-import ]; then
    printf '%s\n' 'STAGE|preflight' 'STAGE|snapshot' 'STAGE|restore' > "$FIXTURE/expected"
  else
    printf '%s\n' 'STAGE|preflight' 'STAGE|snapshot' 'STAGE|nfqws' 'STAGE|verify' > "$FIXTURE/expected"
  fi
  grep '^STAGE|' "$FIXTURE/action.log" > "$FIXTURE/stages"
  cmp "$FIXTURE/stages" "$FIXTURE/expected"
  [ "$(tail -n 1 "$FIXTURE/action.log")" = 'RESULT|ok' ]
done
run_tool --apply --core xray --yes-router >/dev/null
selected="$(cat "$ROOT/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr")"
run_tool --rollback-snapshot "$selected" --yes-router > "$FIXTURE/restore.log"
grep '^STAGE|' "$FIXTURE/restore.log" > "$FIXTURE/stages"
printf '%s\n' 'STAGE|preflight' 'STAGE|snapshot' 'STAGE|restore' 'STAGE|verify' > "$FIXTURE/expected"
cmp "$FIXTURE/stages" "$FIXTURE/expected"
[ "$(tail -n 1 "$FIXTURE/restore.log")" = 'RESULT|ok' ]
printf '%s\n' youtube-direct > "$ROOT/xray-test-fail"
result=0
run_tool --apply --core xray --youtube-route zapret --yes-router > "$FIXTURE/fail.log" 2> "$FIXTURE/fail.err" || result=$?
[ "$result" != 0 ]
[ "$(tail -n 1 "$FIXTURE/fail.log")" = 'RESULT|rolled-back' ]
rm "$ROOT/xray-test-fail"
result=0
run_tool --apply > "$FIXTURE/guard.log" 2>/dev/null || result=$?
[ "$result" != 0 ]
[ "$(tail -n 1 "$FIXTURE/guard.log")" = 'RESULT|failed' ]
for mode in --status --preflight --print-plan; do
  run_tool "$mode" > "$FIXTURE/read.log"
  if grep -Eq '^(STAGE|RESULT)\|' "$FIXTURE/read.log"; then exit 1; fi
done
echo engine-stage-lines-tests-ok
