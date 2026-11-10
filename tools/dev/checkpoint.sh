#!/bin/sh
set -eu

# Git-independent source checkpoints of the working tree.
#
#   sh tools/dev/checkpoint.sh save <label>
#   sh tools/dev/checkpoint.sh list
#   sh tools/dev/checkpoint.sh restore <archive> [DIR]
#
# save     packs the tree into .cache/checkpoints/<UTC stamp>-<label>.tar.gz
#          and prints that path. Left out: .cache/, tests/.generated/,
#          local backups/dat, private-router, credentials, raw network captures, __pycache__/, .idea/, node_modules/ and
#          .DS_Store files.
# list     prints the saved archives, oldest first.
# restore  unpacks an archive into DIR (default .cache/restore-<stamp>/), which
#          must be missing or empty: the working tree is never overwritten.
#          Compare with diff -r and copy files back by hand.
#
# Relative paths are taken from the project root.

SCRIPT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")"
ROOT="$(CDPATH= cd -- "$(dirname -- "$SCRIPT")/../.." && pwd)"
CHECKPOINT_DIR=".cache/checkpoints"

# Keeps the BSD tar of macOS from adding ._* copies of extended attributes.
COPYFILE_DISABLE=1
export COPYFILE_DISABLE

usage() {
  sed -n '4,19p' "$SCRIPT" | sed 's/^# \{0,1\}//'
}

die() {
  echo "checkpoint: $*" >&2
  exit 1
}

usage_error() {
  echo "checkpoint: $*" >&2
  exit 2
}

timestamp() {
  date -u +%Y%m%dT%H%M%SZ
}

cmd_save() {
  [ "$#" -eq 1 ] || usage_error "save takes exactly one label"
  label="$1"
  case "$label" in
    ''|*[!A-Za-z0-9._-]*) usage_error "label may only contain letters, digits, '.', '_' and '-'" ;;
  esac
  archive="$CHECKPOINT_DIR/$(timestamp)-$label.tar.gz"
  [ ! -e "$archive" ] || die "$archive already exists"
  mkdir -p "$CHECKPOINT_DIR"
  if ! tar -czf "$archive.tmp" \
    --exclude=.cache \
    --exclude=tests/.generated \
    --exclude='./backups' \
    --exclude='./dat' \
    --exclude=private-router \
    --exclude='./tools/windows/reports' \
    --exclude=.git \
    --exclude=.pwd \
    --exclude=.env \
    --exclude='.env.*' \
    --exclude='*.dpapi' \
    --exclude='*.pem' \
    --exclude='*.key' \
    --exclude='*.pcap' \
    --exclude='*.pcapng' \
    --exclude='*.har' \
    --exclude='*.tar.gz' \
    --exclude='*.tgz' \
    --exclude='*.zip' \
    --exclude='*.7z' \
    --exclude='*.ipk' \
    --exclude=raw-captures \
    --exclude=raw_captures \
    --exclude='*/captures/raw' \
    --exclude=__pycache__ \
    --exclude=.idea \
    --exclude=node_modules \
    --exclude=.DS_Store \
    .; then
    rm -f "$archive.tmp"
    die "tar failed"
  fi
  mv "$archive.tmp" "$archive"
  echo "$archive"
}

cmd_list() {
  for archive in "$CHECKPOINT_DIR"/*.tar.gz; do
    [ -f "$archive" ] || continue
    echo "$archive"
  done
}

cmd_restore() {
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage_error "restore takes an archive and an optional directory"
  archive="$1"
  [ -f "$archive" ] || die "$archive: no such archive"
  dir="${2:-.cache/restore-$(timestamp)}"
  if [ -e "$dir" ] && { [ ! -d "$dir" ] || [ -n "$(ls -A -- "$dir")" ]; }; then
    die "$dir exists and is not an empty directory"
  fi
  mkdir -p "$dir"
  tar -xzf "$archive" -C "$dir" || die "cannot unpack $archive into $dir"
  echo "$dir"
}

cd "$ROOT"
command="${1:-}"
[ "$#" -eq 0 ] || shift
case "$command" in
  save) cmd_save "$@" ;;
  list) [ "$#" -eq 0 ] || usage_error "list takes no arguments"; cmd_list ;;
  restore) cmd_restore "$@" ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
