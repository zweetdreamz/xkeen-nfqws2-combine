#!/bin/sh
set -eu

# Ships the project to the router: packs the files of tools/dev/deploy-manifest.txt
# (the panel module tools/router/kdn included) and the panel shim, uploads the
# package over ssh and runs deploy-remote.sh there (busy check, backup, atomic
# install, panel stop and start, invariants, rollback).
#
#   sh tools/dev/deploy.sh [--dry-run] [--ssh CMD] [--project-dir DIR]
#
#   --dry-run          upload and check only: prints the files to install and the
#                      current xray/nfqws2 PIDs and config checksums
#   --ssh CMD          ssh command line (default: ssh -p 22 root@192.168.2.1)
#   --project-dir DIR  project directory on the router
#                      (default: /opt/root/keenetic-discord-nfqws2)
#
# The package stays in .cache/deploy/<UTC stamp>/upload.tar.gz. A text file with
# CRLF line endings is refused unless .gitattributes marks it eol=crlf (this
# tree may come from a Windows checkout). Exit codes of deploy-remote.sh pass
# through: 0 ok, 1 failed and restored from the backup, 2 invalid package,
# 3 panel busy. Besides, 2 means a refusal while packing and 4 a failed upload.
#
# KDN_DEPLOY_ROOT (with KDN_ALLOW_DEPLOY_ROOT=1) prefixes the upload directory;
# it exists for the repository's isolated tests.

SCRIPT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")"
ROOT="$(CDPATH= cd -- "$(dirname -- "$SCRIPT")/../.." && pwd)"
MANIFEST="tools/dev/deploy-manifest.txt"
REMOTE_SCRIPT="tools/dev/deploy-remote.sh"
INSTALLER="tools/router/xkeen_control_script.sh"
ATTRIBUTES=".gitattributes"
CR="$(printf '\r')"

# Keeps the BSD tar of macOS from adding ._* copies of extended attributes.
COPYFILE_DISABLE=1
export COPYFILE_DISABLE
# The archive is plain ustar (no PAX headers for xattrs, no GNU extensions) and
# the files are copied without their attributes, so the busybox tar of the
# router reads it.
TAR_FORMAT=ustar

usage() {
  sed -n '4,24p' "$SCRIPT" | sed 's/^# \{0,1\}//'
}

die() {
  echo "deploy: $*" >&2
  exit 2
}

ssh_command="ssh -p 22 root@192.168.2.1"
project_dir="/opt/root/keenetic-discord-nfqws2"
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --ssh)
      [ "$#" -ge 2 ] || die "--ssh needs a value"
      ssh_command="$2"
      shift 2
      ;;
    --project-dir)
      [ "$#" -ge 2 ] || die "--project-dir needs a value"
      project_dir="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

case "$project_dir" in
  /*) ;;
  *) die "--project-dir must be an absolute path: $project_dir" ;;
esac
case "$project_dir" in
  *[!A-Za-z0-9._/-]*|*..*|*//*) die "unsafe --project-dir: $project_dir" ;;
esac

remote_root=""
if [ -n "${KDN_DEPLOY_ROOT:-}" ]; then
  [ "${KDN_ALLOW_DEPLOY_ROOT:-0}" = "1" ] || die "KDN_DEPLOY_ROOT is reserved for isolated repository tests"
  remote_root="${KDN_DEPLOY_ROOT%/}"
fi

# Prints the manifest paths that exist; a line that matches nothing is an error.
manifest_files() {
  while IFS= read -r entry || [ -n "$entry" ]; do
    entry="${entry%"$CR"}"
    case "$entry" in
      ''|'#'*) continue ;;
      /*|*..*|*//*|*[!A-Za-z0-9._/*+@=-]*) die "bad manifest entry: $entry" ;;
    esac
    matched=0
    for path in $entry; do
      [ -e "$path" ] || [ -L "$path" ] || continue
      [ ! -L "$path" ] || die "symlink in the manifest: $path"
      [ -f "$path" ] || continue
      case "$path" in
        generated/*|deploy-remote.sh) die "reserved name in the manifest: $path" ;;
      esac
      # The manifest is an allowlist, never permission to publish local secrets.
      # Refuse before copying, uploading or contacting a router; no file bytes
      # are inspected or included in the error.
      case "/$path/" in
        */.pwd/*|*/.env/*|*/.env.*/*|*/.git/*|*/.cache/*|*/backups/*|*/dat/*|\
        */raw-captures/*|*/raw_captures/*|*/captures/raw/*|*/tools/windows/reports/*|\
        *.dpapi/|*.pem/|*.key/|*.pcap/|*.pcapng/|*.har/|*.tar.gz/|*.tgz/|*.zip/|*.7z/|*.ipk/)
          die "private/local-only path in manifest: $path" ;;
      esac
      printf '%s\n' "$path"
      matched=1
    done
    [ "$matched" -eq 1 ] || die "manifest entry matches no file: $entry"
  done < "$MANIFEST"
}

# Prints "binary", "crlf" or "text": what .gitattributes says about the file.
line_ending_class() {
  class=text
  [ -f "$ATTRIBUTES" ] || { echo "$class"; return 0; }
  base="${1##*/}"
  while read -r pattern attrs; do
    case "$pattern" in
      ''|'#'*) continue ;;
      */*) subject="$1"; pattern="${pattern#/}" ;;
      *) subject="$base" ;;
    esac
    # The pattern is a glob on purpose.
    # shellcheck disable=SC2254
    case "$subject" in
      $pattern) ;;
      *) continue ;;
    esac
    for attr in $attrs; do
      case "$attr" in
        -text|binary) class=binary ;;
        eol=crlf) class=crlf ;;
        text|text=*|eol=lf) class=text ;;
      esac
    done
  done < "$ATTRIBUTES"
  echo "$class"
}

check_line_endings() {
  case "$(line_ending_class "$1")" in
    binary|crlf) return 0 ;;
  esac
  if grep -q "$CR\$" "$1"; then
    die "$1 has CRLF line endings, but $ATTRIBUTES does not mark it eol=crlf"
  fi
}

# The panel shim: the heredoc of the installer between <<'PYEOF' and PYEOF. The
# installer is its only copy; the package carries it as generated/app.py.
panel_shim() {
  awk -v opener="<<'PYEOF'" '
    state == 0 {
      if (length($0) >= length(opener) && substr($0, length($0) - length(opener) + 1) == opener) state = 1
      next
    }
    $0 == "PYEOF" { exit }
    { print }
  ' "$INSTALLER"
}

cd "$ROOT"
[ -f "$MANIFEST" ] || die "manifest not found: $MANIFEST"
[ -f "$INSTALLER" ] || die "panel installer not found: $INSTALLER"
[ -f "$REMOTE_SCRIPT" ] || die "$REMOTE_SCRIPT not found"
VERSION_POLICY="tools/router/kdn/common/xkeen.py"
[ -f "$VERSION_POLICY" ] || die "version policy not found: $VERSION_POLICY"
# Bootstrap the same self-contained read-only guard before any remote upload.
# No installed copy of this project's Python package is required yet.
case "$remote_root" in *[!A-Za-z0-9._/-]*) die "unsafe deploy root" ;; esac

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
package_id="$stamp"
package_n=1
mkdir -p .cache/deploy
while ! mkdir ".cache/deploy/$package_id" 2>/dev/null; do
  package_n=$((package_n + 1))
  package_id="$stamp-$package_n"
done
work=".cache/deploy/$package_id"
keep_work=0
trap '[ "$keep_work" -eq 1 ] || rm -rf "$work"' 0
trap 'exit 130' HUP INT TERM

pack="$work/pack"
mkdir -p "$pack/generated"
manifest_files > "$work/files.raw"
LC_ALL=C sort -u "$work/files.raw" > "$work/files.list"
file_count="$(wc -l < "$work/files.list" | tr -d ' ')"
while IFS= read -r file; do
  check_line_endings "$file"
  mkdir -p "$pack/$(dirname "$file")"
  cp "$file" "$pack/$file"
done < "$work/files.list"
panel_shim > "$pack/generated/app.py"
[ -s "$pack/generated/app.py" ] || die "no panel shim (<<'PYEOF' ... PYEOF) in $INSTALLER"
cp "$REMOTE_SCRIPT" "$pack/deploy-remote.sh"
(cd "$pack" && find . -type f | sed 's|^\./||' | LC_ALL=C sort > ../upload.list)
(cd "$pack" && tar --format="$TAR_FORMAT" -czf ../upload.tar.gz -T ../upload.list)
tar -tzf "$work/upload.tar.gz" | LC_ALL=C sort > "$work/upload.listing"
cmp -s "$work/upload.list" "$work/upload.listing" || die "the package does not list what was packed: $work/upload.tar.gz"
rm -rf "$pack"
keep_work=1
echo "deploy: packed $file_count project files and the panel shim into $work/upload.tar.gz"

remote_tmp="$remote_root/opt/tmp"
remote_stage="$remote_tmp/kdn-deploy-$package_id"
remote_flags=""
[ "$dry_run" -eq 0 ] || remote_flags=" --dry-run"
# Validate local packaging before contacting the target; then refuse unsupported
# installations before creating any remote stage or uploading project files.
# shellcheck disable=SC2086
$ssh_command "PATH='$remote_root/opt/bin:$remote_root/opt/sbin':\$PATH python3 -I - --require" \
  < "$VERSION_POLICY" >/dev/null || die "unsupported XKeen target; XKeen2.1+ is required (nothing uploaded)"
echo "deploy: uploading to $remote_stage"
# The ssh command line is split into words on purpose.
# shellcheck disable=SC2086
$ssh_command "mkdir -p '$remote_tmp' && mkdir '$remote_stage' && cat > '$remote_stage/upload.tar.gz'" \
  < "$work/upload.tar.gz" || {
    echo "deploy: upload failed" >&2
    exit 4
  }
remote_rc=0
# shellcheck disable=SC2086
$ssh_command "cd '$remote_stage' && tar -x -z -o -f upload.tar.gz deploy-remote.sh && sh deploy-remote.sh --stage '$remote_stage' --project-dir '$project_dir'$remote_flags" \
  < /dev/null || remote_rc=$?
if [ "$remote_rc" -ne 0 ]; then
  echo "deploy: the router side exited with $remote_rc" >&2
fi
exit "$remote_rc"
