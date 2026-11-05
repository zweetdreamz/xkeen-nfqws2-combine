#!/bin/sh
# Pinned real Linux runtime for network-none --intercept=0 tests, not a service.
set -eu
[ "$#" -eq 1 ] || { echo 'Usage: fetch-nfqws2-runtime.sh DEST_DIR' >&2; exit 2; }
dest="$1"
mkdir -p "$dest"
archive_hash=eb412aebc82cdef1f09b6aa9df45c8ff60fb88683b6663e6c4a9275d87ea2db4
binary_hash=25049b2bff954c02051e1102a06d34f2f0f946b069d350c9065a86ecd88267c1
lib_hash=6bf528fef1f0fc3c65e189216fc8a06bb873f6e25d1c29d2bfa4695a09b73440
antidpi_hash=6d1fa9168e5de1682fef91fd174f68b58c50f6739ef00f42ca7db2b940b6246d
auto_hash=23a9b99a776d868d92f4cc0ee5110f5c1f12fe746620d9c0337022dbc2f52df0
verify() { [ -f "$1" ] && [ "$(sha256sum "$1" | cut -d ' ' -f 1)" = "$2" ]; }
if verify "$dest/nfqws2" "$binary_hash" && verify "$dest/zapret-lib.lua" "$lib_hash" &&
   verify "$dest/zapret-antidpi.lua" "$antidpi_hash" && verify "$dest/zapret-auto.lua" "$auto_hash"; then
  exit 0
fi
work=$(mktemp -d "$dest/.runtime.XXXXXX")
cleanup() { rm -f "$work/release.tar.gz" "$work/nfqws2" "$work/zapret-lib.lua" "$work/zapret-antidpi.lua" "$work/zapret-auto.lua"; rmdir "$work"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
curl -fsSL --connect-timeout 10 --max-time 120 --retry 2 \
  'https://github.com/bol-van/zapret2/releases/download/v1.0.6/zapret2-v1.0.6.tar.gz' -o "$work/release.tar.gz"
verify "$work/release.tar.gz" "$archive_hash" || { echo 'Pinned runtime archive hash mismatch' >&2; exit 1; }
tar -xOf "$work/release.tar.gz" zapret2-v1.0.6/binaries/linux-x86_64/nfqws2 > "$work/nfqws2"
for name in lib antidpi auto; do
  tar -xOf "$work/release.tar.gz" "zapret2-v1.0.6/lua/zapret-$name.lua" > "$work/zapret-$name.lua"
done
if ! { verify "$work/nfqws2" "$binary_hash" && verify "$work/zapret-lib.lua" "$lib_hash" &&
       verify "$work/zapret-antidpi.lua" "$antidpi_hash" && verify "$work/zapret-auto.lua" "$auto_hash"; }; then
  echo 'Pinned runtime member hash mismatch' >&2; exit 1;
fi
chmod 755 "$work/nfqws2"
chmod 644 "$work/zapret-lib.lua" "$work/zapret-antidpi.lua" "$work/zapret-auto.lua"
for name in nfqws2 zapret-lib.lua zapret-antidpi.lua zapret-auto.lua; do
  mv -f "$work/$name" "$dest/$name"
done
