#!/bin/sh
set -eu

# Unit test for tools/dev/checkpoint.sh (save, list, restore). It runs on a
# small synthetic copy of the project in a temporary directory, so the real
# tree and its .cache are never touched.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/tools/dev/checkpoint.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/keenetic-checkpoint.XXXXXX")"
trap 'rm -rf "$FIXTURE"' 0 HUP INT TERM

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[ -f "$TARGET" ] || fail "tools/dev/checkpoint.sh: not found"

PROJECT="$FIXTURE/project"
mkdir -p "$PROJECT/tools/dev" "$PROJECT/docs" "$PROJECT/backups" \
  "$PROJECT/tests/.generated" "$PROJECT/tools/router/__pycache__" \
  "$PROJECT/.cache/old" "$PROJECT/.idea" "$PROJECT/node_modules/pkg" \
  "$PROJECT/tests/node_modules/pkg"
cp "$TARGET" "$PROJECT/tools/dev/checkpoint.sh"
cp "$SCRIPT_DIR/README.md" "$PROJECT/README.md"
echo "kept" > "$PROJECT/docs/note.md"
echo "kept" > "$PROJECT/backups/README.md"
echo "skipped" > "$PROJECT/backups/baseline.tar.gz.dpapi"
echo "skipped" > "$PROJECT/.pwd"
echo "skipped" > "$PROJECT/tests/.generated/blob.bin"
echo "skipped" > "$PROJECT/tools/router/__pycache__/x.pyc"
echo "skipped" > "$PROJECT/.cache/old/dump.txt"
echo "skipped" > "$PROJECT/.idea/workspace.xml"
echo "skipped" > "$PROJECT/node_modules/pkg/index.js"
echo "skipped" > "$PROJECT/tests/node_modules/pkg/index.js"
echo "skipped" > "$PROJECT/.DS_Store"
echo "skipped" > "$PROJECT/docs/.DS_Store"
echo "skipped" > "$PROJECT/tools/router/.DS_Store"
echo "kept" > "$PROJECT/docs/.DS_Store.md"
mkdir -p "$PROJECT/raw-captures" "$PROJECT/docs/raw_captures" "$PROJECT/captures/raw" \
  "$PROJECT/dat" "$PROJECT/.git" "$PROJECT/tools/windows/reports"
for private in .env .env.router docs/.pwd docs/router.key docs/router.pem docs/trace.pcap \
  docs/trace.pcapng docs/session.har docs/token.dpapi raw-captures/router.json \
  docs/raw_captures/router.txt captures/raw/config.json dat/router.dat \
  backups/plaintext.json .git/config tools/windows/reports/router.json \
  docs/router.tar.gz docs/router.tgz docs/router.zip docs/router.7z docs/router.ipk; do
  printf '%s\n' 'synthetic private sentinel' > "$PROJECT/$private"
done

checkpoint() {
  (cd "$PROJECT" && sh tools/dev/checkpoint.sh "$@")
}

# save prints .cache/checkpoints/<UTC stamp>-<label>.tar.gz and creates it.
archive="$(checkpoint save t1)" || fail "save t1 failed"
case "$archive" in
  .cache/checkpoints/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z-t1.tar.gz) ;;
  *) fail "unexpected archive path: $archive" ;;
esac
[ -s "$PROJECT/$archive" ] || fail "archive was not created: $archive"

# Sources are archived, local-only files and caches are not.
listing="$(tar -tzf "$PROJECT/$archive")"
for kept in README.md docs/note.md docs/.DS_Store.md tools/dev/checkpoint.sh; do
  printf '%s\n' "$listing" | grep -q "^\./$kept\$" || fail "$kept is missing from the archive"
done
if printf '%s\n' "$listing" | grep -Eq '(^|/)(\.pwd|\.cache|\.idea|node_modules|__pycache__|\.generated|\.DS_Store)(/|$)|\.dpapi$'; then
  fail "archive contains excluded paths:
$(printf '%s\n' "$listing" | grep -E '(^|/)(\.pwd|\.cache|\.idea|node_modules|__pycache__|\.generated|\.DS_Store)(/|$)|\.dpapi$')"
fi
for private in .env .env.router docs/.pwd docs/router.key docs/router.pem docs/trace.pcap \
  docs/trace.pcapng docs/session.har docs/token.dpapi raw-captures/router.json \
  docs/raw_captures/router.txt captures/raw/config.json dat/router.dat backups/README.md \
  backups/plaintext.json .git/config tools/windows/reports/router.json \
  docs/router.tar.gz docs/router.tgz docs/router.zip docs/router.7z docs/router.ipk; do
  if printf '%s\n' "$listing" | grep -Fxq "./$private"; then
    fail "private path included: $private"
  fi
  [ -f "$PROJECT/$private" ] || fail "checkpoint removed source data: $private"
done

# list shows the archive.
[ "$(checkpoint list)" = "$archive" ] || fail "list does not show $archive"

# The tool finds the project root and itself from any directory.
(cd "$PROJECT/docs" && sh ../tools/dev/checkpoint.sh --help) | grep -q "checkpoint.sh restore" ||
  fail "--help does not work from a subdirectory"
[ "$(cd "$PROJECT/docs" && sh ../tools/dev/checkpoint.sh list)" = "$archive" ] ||
  fail "list does not work from a subdirectory"

# restore unpacks next to the tree and never overwrites it.
echo "edited after the checkpoint" >> "$PROJECT/README.md"
checkpoint restore "$archive" "$FIXTURE/out" > /dev/null || fail "restore failed"
cmp "$SCRIPT_DIR/README.md" "$FIXTURE/out/README.md" || fail "restored README.md differs from the original"
if cmp -s "$SCRIPT_DIR/README.md" "$PROJECT/README.md"; then
  fail "restore overwrote the working tree README.md"
fi
[ ! -e "$FIXTURE/out/.pwd" ] || fail "restored tree contains .pwd"

# Without DIR it restores into .cache/restore-<stamp>/.
checkpoint restore "$archive" > /dev/null || fail "restore without DIR failed"
set -- "$PROJECT"/.cache/restore-*/README.md
[ -f "$1" ] || fail "restore without DIR did not create .cache/restore-<stamp>/"

# A non-empty DIR (the project root included) is refused and left untouched.
if checkpoint restore "$archive" "$PROJECT" > /dev/null 2>&1; then
  fail "restore into the project root was not refused"
fi
if checkpoint restore "$archive" "$FIXTURE/out" > /dev/null 2>&1; then
  fail "restore into a non-empty directory was not refused"
fi
if cmp -s "$SCRIPT_DIR/README.md" "$PROJECT/README.md"; then
  fail "refused restore changed the working tree"
fi

# Bad input is rejected.
if checkpoint save "bad label/../x" > /dev/null 2>&1; then
  fail "save accepted an unsafe label"
fi
if checkpoint save > /dev/null 2>&1; then
  fail "save without a label was accepted"
fi
if checkpoint restore "$PROJECT/.cache/checkpoints/missing.tar.gz" "$FIXTURE/other" > /dev/null 2>&1; then
  fail "restore of a missing archive was not refused"
fi
if checkpoint nonsense > /dev/null 2>&1; then
  fail "unknown command was accepted"
fi

echo "checkpoint-tests-ok"
