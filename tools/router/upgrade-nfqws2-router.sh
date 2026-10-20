#!/bin/sh
# Verified 1.2.4 -> 1.3.1 update for this Keenetic/Entware installation.
# Does not call XKeen or alter Xray configuration.
set -eu

STAGE=/opt/tmp/codex-nfqws2-1.3.1
ROOT=/opt/etc/nfqws2-update-backups
INIT=/opt/etc/init.d/S51nfqws2
TAR=/opt/bin/tar
VERSION=1.3.1
SHA=28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054

check_idle() {
  for job in tuner route diagnostics; do
    /opt/bin/curl --max-time 8 -fsS "http://192.168.2.1:8088/api/$job/status" |
      jq -e '.active == false' >/dev/null || { echo "ERROR: active $job job" >&2; exit 1; }
  done
}

safe_backup() {
  case "$1" in "$ROOT"/20[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9]*) ;; *) exit 2 ;; esac
  case "$1" in *..*|*'//'*) exit 2 ;; esac
  [ -d "$1" ] && [ ! -L "$1" ]
  [ -f "$1/old.ipk" ] && [ -f "$1/protected.tar.gz" ]
  (cd "$1" && sha256sum -c backup.sha256)
}

restore_old() {
  safe_backup "$backup"
  "$INIT" stop >/dev/null 2>&1 || true
  opkg --force-downgrade --force-reinstall install "$backup/old.ipk"
  "$INIT" stop >/dev/null 2>&1 || true
  "$TAR" -xzf "$backup/protected.tar.gz" -C /
  "$INIT" start
  "$INIT" status
  opkg status nfqws2-keenetic | grep -F 'Version: 1.2.4'
  (cd / && sha256sum -c "$backup/protected.sha256")
  echo "Rollback complete: $backup"
}

case "${1:-}" in
  --prepare)
    check_idle
    opkg status nfqws2-keenetic | grep -qx 'Version: 1.2.4'
    [ "$(sha256sum "$STAGE/new.ipk" | awk '{print $1}')" = "$SHA" ]
    grep -qx CONFIG_VERSION=1 /opt/etc/nfqws2/nfqws2.conf
    [ -x "$STAGE/root/opt/tmp/nfqws2_binary/nfqws2-mipsel" ]
    "$STAGE/root/opt/tmp/nfqws2_binary/nfqws2-mipsel" --version
    (
      set -- noop
      . "$INIT"
      args="$(_startup_args | sed "s#/opt/etc/nfqws2/lua/#$STAGE/root/opt/etc/nfqws2/lua/#g")"
      "$STAGE/root/opt/tmp/nfqws2_binary/nfqws2-mipsel" --dry-run --fastpath-workaround=auto $args
    )
    umask 077
    backup="$ROOT/$(date +%Y%m%d-%H%M%S)-1.2.4"
    [ ! -e "$backup" ]
    mkdir -p "$backup/package/control"
    cp -p "$0" "$backup/upgrade-script.sh"
    for name in control conffiles preinst postinst prerm postrm; do
      cp -p "/opt/lib/opkg/info/nfqws2-keenetic.$name" "$backup/package/control/$name"
    done
    (cd "$backup/package/control" && "$TAR" -czf ../control.tar.gz .)
    "$TAR" -czf "$backup/package/data.tar.gz" -C / \
      opt/etc/nfqws2 opt/etc/init.d/S51nfqws2 opt/etc/ndm/netfilter.d/100-nfqws2.sh opt/usr/bin/nfqws2
    echo 2.0 > "$backup/package/debian-binary"
    (cd "$backup/package" && "$TAR" -czf "$backup/old.ipk" control.tar.gz data.tar.gz debian-binary)
    : > "$backup/protected.paths"
    for path in opt/etc/nfqws2/nfqws2.conf opt/etc/nfqws2/lists opt/etc/nfqws2/blobs \
                opt/etc/nfqws2/imported-profiles opt/etc/nfqws2/profile-versions; do
      [ ! -e "/$path" ] || echo "$path" >> "$backup/protected.paths"
    done
    "$TAR" -czf "$backup/protected.tar.gz" -C / -T "$backup/protected.paths"
    (cd /; while IFS= read -r path; do find "$path" -type f; done < "$backup/protected.paths" |
      sort | xargs sha256sum) > "$backup/protected.sha256"
    sha256sum /opt/etc/xray/configs/*.json > "$backup/xray.sha256"
    cp -p "$STAGE/new.ipk" "$backup/new.ipk"
    (cd "$backup" && sha256sum old.ipk new.ipk protected.tar.gz > backup.sha256)
    opkg status nfqws2-keenetic > "$backup/status-before.txt"
    printf '#!/bin/sh\nset -eu\nexec /bin/sh "%s/upgrade-script.sh" --rollback "%s"\n' "$backup" "$backup" > "$backup/rollback.sh"
    chmod 700 "$backup/rollback.sh"
    echo "$backup" > "$ROOT/.latest.path"
    mv "$ROOT/.latest.path" "$ROOT/latest.path"
    opkg --noaction --force-downgrade --force-reinstall install "$backup/old.ipk"
    opkg --noaction install "$backup/new.ipk"
    echo "PREPARED: $backup"
    ;;
  --apply)
    backup="${2:-}"
    safe_backup "$backup"
    check_idle
    (cd / && sha256sum -c "$backup/protected.sha256")
    sha256sum -c "$backup/xray.sha256"
    xray_before="$(pidof xray)"
    updating=1
    recover() {
      result=$?
      trap - 0 HUP INT TERM
      if [ "$result" -ne 0 ] && [ "$updating" = 1 ]; then
        echo 'ERROR: update failed, restoring previous package' >&2
        restore_old || echo "CRITICAL: run $backup/rollback.sh manually" >&2
      fi
      exit "$result"
    }
    trap recover 0
    trap 'exit 130' HUP INT TERM
    opkg install "$backup/new.ipk" </dev/null
    # Package Lua/binary/init may change; retain our exact strategies and lists.
    "$INIT" stop >/dev/null 2>&1 || true
    "$TAR" -xzf "$backup/protected.tar.gz" -C /
    "$INIT" start
    "$INIT" status
    opkg status nfqws2-keenetic | grep -qx "Version: $VERSION"
    /opt/usr/bin/nfqws2 --version
    (cd / && sha256sum -c "$backup/protected.sha256")
    sha256sum -c "$backup/xray.sha256"
    [ "$(pidof xray)" = "$xray_before" ]
    grep -q '^_startup_args()' "$INIT"
    iptables-save -t mangle | grep -q NFQUEUE
    updating=0
    echo "UPDATED: nfqws2-keenetic $VERSION; Xray unchanged"
    echo "ROLLBACK: sh $backup/rollback.sh"
    ;;
  --rollback)
    backup="${2:-}"
    check_idle
    restore_old
    ;;
  *) echo 'Usage: --prepare | --apply BACKUP | --rollback BACKUP' >&2; exit 2 ;;
esac
