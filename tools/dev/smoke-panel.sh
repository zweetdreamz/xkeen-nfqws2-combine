#!/bin/sh
# Read-only HTTP smoke. Never sends POST or router commands.
set -eu
LC_ALL=C
export LC_ALL
HOST=
PORT=8088
ROUNDS=3
PARALLEL=24
LIMIT=2048
CONSENT=
DRY=0
die() { echo "$*" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --host|--port|--rounds|--parallel|--limit)
            [ "$#" -ge 2 ] || die "$1 needs a value"
            case "$1" in
                --host) HOST=$2 ;; --port) PORT=$2 ;; --rounds) ROUNDS=$2 ;;
                --parallel) PARALLEL=$2 ;; --limit) LIMIT=$2 ;;
            esac
            shift 2 ;;
        --yes-router) CONSENT=yes; shift ;;
        --local) CONSENT=local; shift ;;
        --dry-run) DRY=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$HOST" ] || die '--host is required'
case "$HOST" in *[!A-Za-z0-9._:-]*|*:*:*) die 'invalid host (use an IPv4 address or hostname)' ;; esac
for number in "$PORT" "$ROUNDS" "$PARALLEL" "$LIMIT"; do
    case "$number" in ''|*[!0-9]*) die 'numeric arguments must be positive integers' ;; esac
    [ "$number" -gt 0 ] 2>/dev/null || die 'numeric arguments must be positive integers'
done
if [ "$PORT" -gt 65535 ] || [ "$ROUNDS" -gt 1000 ] || [ "$PARALLEL" -gt 64 ]; then
    die 'argument exceeds safety limit'
fi
if [ "$CONSENT" = local ]; then
    case "$HOST" in 127.0.0.1|localhost) : ;; *) die '--local only permits 127.0.0.1 or localhost' ;; esac
elif [ "$CONSENT" != yes ] && [ "$DRY" != 1 ]; then
    die 'refusing to touch the router without --yes-router'
fi
if [ "$DRY" = 1 ]; then
    printf 'GET http://%s:%s/api/route/status (%s rounds, pause 1.5s)\n' "$HOST" "$PORT" "$ROUNDS"
    printf '%s parallel GET /api/route/status and /; GET /api/tuner/status; GET /api/diagnostics/status\n' "$PARALLEL"
    exit 0
fi
command -v curl >/dev/null 2>&1 || die 'curl is required'
command -v jq >/dev/null 2>&1 || die 'jq is required for JSON validation'
WORK=$(mktemp -d "${TMPDIR:-/tmp}/kdn-smoke.XXXXXX")
trap 'rm -rf "$WORK"' 0
trap 'exit 2' HUP INT TERM
probe() {
    index=$1
    endpoint=$2
    curl_rc=0
    metrics=$(curl --noproxy '*' --max-time 10 -sS -o "$WORK/body-$index" \
        -w '%{http_code} %{time_total}' "http://$HOST:$PORT$endpoint" 2>"$WORK/error-$index") || curl_rc=$?
    code=${metrics%% *}
    elapsed=${metrics#* }
    [ "$elapsed" != "$metrics" ] || elapsed=10
    size=0
    [ ! -f "$WORK/body-$index" ] || size=$(wc -c < "$WORK/body-$index")
    failed=0
    reached=1
    if [ "$curl_rc" -ne 0 ] || [ "$code" != 200 ]; then
        failed=1
        echo "$endpoint: HTTP $code curl=$curl_rc" >&2
    fi
    [ "$code" != 000 ] && [ -n "$code" ] || reached=0
    if [ "$endpoint" != / ] && [ "$curl_rc" -eq 0 ]; then
        if ! jq -e 'type == "object" and has("ok")' "$WORK/body-$index" >/dev/null 2>&1; then
            failed=1
            echo "$endpoint: invalid JSON or missing ok" >&2
        fi
    fi
    if [ "$endpoint" = /api/route/status ] && [ "$size" -gt "$LIMIT" ]; then
        failed=1
        echo "$endpoint: $size bytes exceeds limit $LIMIT" >&2
    fi
    printf '%s %s %s %s\n' "$elapsed" "$size" "$failed" "$reached" > "$WORK/result-$index"
}
i=1
while [ "$i" -le "$ROUNDS" ]; do
    probe "$i" /api/route/status
    if [ "$i" -lt "$ROUNDS" ]; then sleep 1.5; fi
    i=$((i + 1))
done
j=1
pids=
while [ "$j" -le "$PARALLEL" ]; do
    if [ "$((j % 2))" -eq 0 ]; then endpoint=/; else endpoint=/api/route/status; fi
    probe "$i" "$endpoint" &
    pids="$pids $!"
    i=$((i + 1))
    j=$((j + 1))
done
for pid in $pids; do wait "$pid"; done
probe "$i" /api/tuner/status
i=$((i + 1))
probe "$i" /api/diagnostics/status
cat "$WORK"/result-* | sort -n | awk '
{ n++; delays[n]=$1; if ($1>max) max=$1; if ($2>size) size=$2; reached+=$4; if ($3 || $1>10) failures++ }
END {
    print "requests max_bytes p50_seconds max_seconds failures"
    printf "%d %d %.6f %.6f %d\n", n, size, delays[int((n+1)/2)], max, failures
    if (!reached) exit 2
    if (failures) exit 1
}'
