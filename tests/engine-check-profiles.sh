#!/bin/sh
# Independent invariant check of a generated nfqws2.conf for the engine tests
# (it shares no code with apply-discord-nfqws2.sh --check-config).
#
#   sh tests/engine-check-profiles.sh ROOT
#
# Composes the arguments with the _startup_args of ROOT/opt/etc/init.d/S51nfqws2
# and prints "ok", or one "FAIL: ..." line per violation (exit 1):
#   - every --filter-tcp/--filter-udp port of every profile is in TCP_PORTS/UDP_PORTS;
#   - every --hostlist/--ipset file has at least one entry;
#   - every profile with --lua-desync has a --hostlist/--ipset, except the
#     Discord Voice profile (--filter-l7=stun,discord);
#   - every --lua-desync=fake names a blob.
set -eu
root="$1"
init="$root/opt/etc/init.d/S51nfqws2"
conf="$root/opt/etc/nfqws2/nfqws2.conf"
work="$(mktemp -d "${TMPDIR:-/tmp}/engine-check.XXXXXX")"
trap 'rm -rf "$work"' 0 HUP INT TERM
sed -n '/^_startup_args() {$/,/^}$/p' "$init" > "$work/startup.sh"
[ -s "$work/startup.sh" ]
# shellcheck disable=SC2016 # expanded by the inner shell
env -i PATH="$PATH" sh -c '
  . "$1" >/dev/null 2>&1
  . "$2"
  echo "PORTS $TCP_PORTS $UDP_PORTS"
  _startup_args
' check "$conf" "$work/startup.sh" > "$work/args"

awk -v root="$root" '
  function expand(spec, set, proto,    n, i, item, b, m, port) {
    n = split(spec, item, ",")
    for (i = 1; i <= n; i++) {
      gsub(/:/, "-", item[i])
      m = split(item[i], b, "-")
      if (m == 1) b[2] = b[1]
      for (port = b[1] + 0; port <= b[2] + 0; port++) set[proto, port] = 1
    }
  }
  function fail(text) { print "FAIL: " text; bad = 1 }
  NR == 1 && $1 == "PORTS" { expand($2, queued, "tcp"); expand($3, queued, "udp"); p = 1; next }
  {
    for (i = 1; i <= NF; i++) {
      t = $i
      if (substr(t, 1, 1) != "-") continue
      if (t == "--new") { p++; continue }
      used[p] = 1
      if (t ~ /^--filter-tcp=/) want[p] = want[p] " tcp:" substr(t, 14)
      else if (t ~ /^--filter-udp=/) want[p] = want[p] " udp:" substr(t, 14)
      else if (t ~ /^--filter-l7=/) l7[p] = substr(t, 13)
      else if (t ~ /^--(hostlist|ipset)=/) { host[p] = 1; sub(/^--[a-z]+=/, "", t); files[t] = 1 }
      else if (t ~ /^--lua-desync=/) {
        lua[p] = 1
        if ((t == "--lua-desync=fake" || t ~ /^--lua-desync=fake:/) && t !~ /:blob=/) fail("profile " p " fake without blob: " t)
      }
    }
  }
  END {
    for (q = 1; q <= p; q++) {
      if (!used[q]) continue
      n = split(want[q], specs, " ")
      for (k = 1; k <= n; k++) {
        split(specs[k], pair, ":")
        delete need
        expand(pair[2], need, pair[1])
        for (key in need) {
          split(key, kp, SUBSEP)
          if (!((kp[1], kp[2]) in queued)) { fail("profile " q " " kp[1] " port " kp[2] " is not queued"); break }
        }
      }
      if (lua[q] && !host[q] && l7[q] != "stun,discord") fail("profile " q " desyncs without a host filter")
    }
    for (f in files) {
      path = root f
      entries = 0
      while ((status = (getline line < path)) > 0) {
        sub(/^[ \t]+/, "", line)
        if (line != "" && line !~ /^[#;\/]/) entries++
      }
      close(path)
      if (entries == 0) fail("list " f " is empty or missing")
    }
    if (!bad) print "ok"
    exit bad
  }
' "$work/args"
