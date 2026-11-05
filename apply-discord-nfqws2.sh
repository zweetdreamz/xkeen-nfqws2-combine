#!/bin/sh
set -eu

# Native XKeen2.1+/Xray launcher. Legacy code exists only as non-deployed test data.
PROJECT="keenetic-discord-nfqws2"
SCRIPT_VERSION="3.2.0"
export PROJECT SCRIPT_VERSION
TEST_ROOT="${KD_TEST_ROOT:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -n "$TEST_ROOT" ] && [ "${KD_ALLOW_TEST_ROOT:-0}" != 1 ]; then
  echo "ERROR: KD_TEST_ROOT is reserved for isolated repository tests." >&2
  exit 2
fi
if [ -z "$TEST_ROOT" ]; then
  PATH="/opt/bin:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/sbin:/bin:/usr/sbin:/usr/bin"
  export PATH
fi
root_path() {
  printf '%s%s\n' "$TEST_ROOT" "$1"
}
STATE_ROOT="$(root_path /opt/etc/keenetic-discord-nfqws2)"

kdn_scan_mode() {
  kdn_scan_result=help
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --print-plan) kdn_scan_result=print-plan ;;
      --preflight) kdn_scan_result=preflight ;;
      --status) kdn_scan_result=status ;;
      --check-config) kdn_scan_result=check-config ;;
      --print-nfqws-profiles) kdn_scan_result=print-nfqws-profiles ;;
      --show-snapshots|--show-rollback) kdn_scan_result=show-snapshots ;;
      --snapshot-baseline) kdn_scan_result=snapshot-baseline ;;
      --rollback-import) kdn_scan_result=rollback-import ;;
      --prune-import-snapshots) kdn_scan_result=prune-import-snapshots ;;
      --setup-route-checker) kdn_scan_result=setup-route-checker ;;
      --rollback|--rollback-baseline) kdn_scan_result=rollback-baseline ;;
      --rollback-latest) kdn_scan_result=rollback-latest ;;
      --apply) kdn_scan_result=apply ;;
      --apply-import-profile|--clear-imported-profile|--rollback-snapshot)
        kdn_scan_option="$1"; shift
        [ "$#" -gt 0 ] || { kdn_scan_result='?'; break; }
        kdn_scan_result="${kdn_scan_option#--}"
        ;;
      --udp-strategy|--discord-route|--discord-tcp-route|--discord-voice-route|--youtube-route|--telegram-route|--proxy-outbound|--core|--direct-mark|--wan-interface|--focused-operation-context|--recover-import-source)
        shift
        [ "$#" -gt 0 ] || { kdn_scan_result='?'; break; }
        ;;
      --yes-router) [ "$kdn_scan_result" != help ] || kdn_scan_result=apply ;;
      --wide-udp|--narrow-udp|--standalone-zapret|--without-xkeen|--no-xkeen|--integrated|--json) ;;
      -h|--help) kdn_scan_result=help ;;
      *) kdn_scan_result='?'; break ;;
    esac
    shift
  done
  printf '%s\n' "$kdn_scan_result"
}

kdn_dispatch_engine() {
  kdn_choice="${KDN_ENGINE:-}"
  case "$kdn_choice" in ''|python|legacy) ;; *) echo "ERROR: KDN_ENGINE must be python or legacy." >&2; exit 2 ;; esac
  kdn_mode="$(kdn_scan_mode "$@")"
  # --help and malformed arguments use the small shell help/parser fallback below.
  case "$kdn_mode" in help|'?') return 0 ;; esac
  if [ "$kdn_choice" = legacy ] || { [ -z "$kdn_choice" ] && [ -e "$STATE_ROOT/engine-legacy" ]; }; then
    case "$TEST_ROOT" in
      /|//|'') echo "ERROR: legacy engine is test-only; use KDN_ENGINE=python or repair the installed package." >&2; exit 1 ;;
      /*) return 0 ;;
      *) echo "ERROR: legacy oracle requires an absolute disposable test root." >&2; exit 2 ;;
    esac
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    if [ -n "$TEST_ROOT" ]; then echo "WARNING: python3 not found; using the shell engine." >&2; return 0; fi
    echo "ERROR: python3 is required; no live shell fallback." >&2; exit 1
  fi
  if [ ! -f "$SCRIPT_DIR/tools/router/kdn/engine/__main__.py" ]; then
    if [ -n "$TEST_ROOT" ]; then echo "WARNING: kdn.engine is not installed; using the shell engine." >&2; return 0; fi
    echo "ERROR: install the complete kdn.engine package; no live shell fallback." >&2; exit 1
  fi
  kdn_added=""
  if [ -z "${PYTHONUTF8+set}" ]; then PYTHONUTF8=1; export PYTHONUTF8; kdn_added="PYTHONUTF8"; fi
  if [ -z "${PYTHONIOENCODING+set}" ]; then
    PYTHONIOENCODING="utf-8:surrogateescape"; export PYTHONIOENCODING
    kdn_added="${kdn_added:+$kdn_added }PYTHONIOENCODING"
  fi
  if [ -z "${PYTHONCOERCECLOCALE+set}" ]; then
    PYTHONCOERCECLOCALE=0; export PYTHONCOERCECLOCALE
    kdn_added="${kdn_added:+$kdn_added }PYTHONCOERCECLOCALE"
  fi
  KDN_ENGINE_ADDED_ENV="$kdn_added"
  KDN_ENGINE_ADDED_PYTHONPATH="$SCRIPT_DIR/tools/router"
  PYTHONPATH="$KDN_ENGINE_ADDED_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
  KDN_ENGINE_SCRIPT="$SCRIPT_DIR/${0##*/}"
  KDN_ENGINE_SCRIPT_DIR="$SCRIPT_DIR"
  export KDN_ENGINE_ADDED_ENV KDN_ENGINE_ADDED_PYTHONPATH PYTHONPATH KDN_ENGINE_SCRIPT KDN_ENGINE_SCRIPT_DIR
  exec python3 -P -m kdn.engine "$@"
}

kdn_dispatch_engine "$@"
# Historical fixture executable: never shipped by deploy-manifest.txt. Source it
# with the launcher's $0/argv so all canonical project paths retain their meaning.
if [ -n "$TEST_ROOT" ]; then
  case "$TEST_ROOT" in /|//) echo "ERROR: unsafe oracle test root." >&2; exit 2 ;; esac
  oracle="$SCRIPT_DIR/tests/fixtures/engine/legacy-apply-phase6.sh.txt"
  [ -f "$oracle" ] || { echo "ERROR: isolated legacy oracle is missing." >&2; exit 1; }
  export KDN_ENGINE=legacy
  # shellcheck source=/dev/null
  . "$oracle"
  exit $?
fi
case "$(kdn_scan_mode "$@")" in
  help)
    echo 'Usage: sh apply-discord-nfqws2.sh --apply|--status|--preflight|--check-config|--snapshot-baseline|--rollback|--rollback-latest [options]'
    echo 'Native target: XKeen2.1+ (2.x), Xray only; 2.0/unknown/major3 refused before operational work.'
    echo 'Offline: help, print-plan, snapshot metadata listing. Mutations require --yes-router.'
    echo 'Routes: --discord-tcp-route/--discord-voice-route/--youtube-route direct|zapret|vless; --telegram-route direct|vless|ws|unmanaged.'
    echo 'Other options: --wide-udp/--narrow-udp, --udp-strategy flowseal|legacy, --proxy-outbound TAG, --direct-mark N, --wan-interface IFACES.'
    echo 'Diagnostic access: --setup-route-checker --yes-router (explicit loopback API/SOCKS setup, same VPN node).'
    ;;
  *) echo 'ERROR: unsupported/incomplete arguments; use --help.' >&2; exit 2 ;;
esac
