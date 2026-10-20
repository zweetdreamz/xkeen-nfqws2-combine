#!/bin/sh
set -eu

# Downloads the two stock nfqws2 blobs that test-routing-modes.sh needs when
# it runs outside a router (CI, a developer machine). The files come from a
# pinned zapret2 commit and must match the SHA-256 values that
# apply-discord-nfqws2.sh enforces, so a changed upstream file fails here
# instead of silently weakening the test.
#
# Usage: sh tests/fetch-nfqws2-blobs.sh DEST_DIR
# Then:  NFQWS_TEST_BLOB_SOURCE=DEST_DIR sh tests/test-routing-modes.sh

ZAPRET2_COMMIT="5786448c9378cc8aa00bfadd27cc36e49d53039c"
BASE_URL="https://raw.githubusercontent.com/bol-van/zapret2/$ZAPRET2_COMMIT/files/fake"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TARGET="$SCRIPT_DIR/apply-discord-nfqws2.sh"

[ "$#" -eq 1 ] || {
  echo "Usage: $0 DEST_DIR" >&2
  exit 2
}
dest="$1"
mkdir -p "$dest"

pinned_hash() {
  sed -n "s/^$1=\"\\([0-9a-f]\\{64\\}\\)\"$/\\1/p" "$TARGET"
}

fetch_blob() {
  upstream_name="$1"
  local_name="$2"
  expected="$3"
  [ -n "$expected" ] || {
    echo "ERROR: no pinned hash for $local_name in $TARGET" >&2
    return 1
  }
  if [ -f "$dest/$local_name" ] &&
    [ "$(sha256sum "$dest/$local_name" | awk '{ print $1 }')" = "$expected" ]; then
    return 0
  fi
  curl -fsSL --retry 3 -o "$dest/$local_name.tmp" "$BASE_URL/$upstream_name"
  actual="$(sha256sum "$dest/$local_name.tmp" | awk '{ print $1 }')"
  [ "$actual" = "$expected" ] || {
    rm -f "$dest/$local_name.tmp"
    echo "ERROR: $upstream_name checksum mismatch" >&2
    echo "       Expected: $expected" >&2
    echo "       Actual:   $actual" >&2
    return 1
  }
  mv "$dest/$local_name.tmp" "$dest/$local_name"
}

fetch_blob tls_clienthello_www_google_com.bin tls_clienthello.bin \
  "$(pinned_hash YOUTUBE_TLS_BLOB_SHA256)"
fetch_blob quic_initial_www_google_com.bin quic_initial.bin \
  "$(pinned_hash YOUTUBE_QUIC_BLOB_SHA256)"
echo "nfqws2 test blobs ready in $dest"
