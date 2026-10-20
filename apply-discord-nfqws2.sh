#!/bin/sh
set -eu

# Transactional XKeen + nfqws2 setup for independently routed services.
# --standalone-zapret installs and manages nfqws2 without requiring XKeen.
# This file is meant to be copied to a Keenetic router and run in Entware shell.
#
# KD_TEST_ROOT is intentionally supported only for the repository's isolated tests.
# It never points at the host root and is rejected unless KD_ALLOW_TEST_ROOT=1.

PROJECT="keenetic-discord-nfqws2"
SCRIPT_VERSION="3.0.0"
TEST_ROOT="${KD_TEST_ROOT:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ -n "$TEST_ROOT" ] && [ "${KD_ALLOW_TEST_ROOT:-0}" != "1" ]; then
  echo "ERROR: KD_TEST_ROOT is reserved for isolated repository tests." >&2
  exit 2
fi

if [ -z "$TEST_ROOT" ]; then
  # Some XKeen installations expose /opt/usr/bin/busybox wget before the
  # Entware wget-ssl symlink. opkg invokes "wget" through PATH, so HTTPS feeds
  # would fail even though wget-ssl is installed.
  PATH="/opt/bin:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/sbin:/bin:/usr/sbin:/usr/bin"
  export PATH
fi

root_path() {
  printf '%s%s\n' "$TEST_ROOT" "$1"
}

STATE_ROOT="$(root_path /opt/etc/keenetic-discord-nfqws2)"
SNAPSHOT_ROOT="$STATE_ROOT/snapshots"
BASELINE_POINTER="$STATE_ROOT/baseline.ptr"
# Integrated (XKeen) baseline, recorded only when the first baseline was taken
# by a standalone install and therefore covers nfqws2 paths only.
XKEEN_BASELINE_POINTER="$STATE_ROOT/baseline-xkeen.ptr"
LATEST_POINTER="$STATE_ROOT/latest-preapply.ptr"
LOCK_DIR="$(root_path /opt/tmp/keenetic-discord-nfqws2.lock)"

XKEEN_INIT="$(root_path /opt/etc/init.d/S05xkeen)"
XKEEN_HOOK="$(root_path /opt/etc/ndm/netfilter.d/proxy.sh)"
NFQWS_INIT="$(root_path /opt/etc/init.d/S51nfqws2)"
NFQWS_CONF="$(root_path /opt/etc/nfqws2/nfqws2.conf)"
NFQWS_LIST="$(root_path /opt/etc/nfqws2/lists/user.list)"
NFQWS_YOUTUBE_LIST="$(root_path /opt/etc/nfqws2/lists/youtube.list)"
NFQWS_TELEGRAM_LIST="$(root_path /opt/etc/nfqws2/lists/telegram.list)"
NFQWS_TELEGRAM_IPSET="$(root_path /opt/etc/nfqws2/lists/telegram-ip.list)"
NFQWS_DISCORD_UDP_BLOB="$(root_path /opt/etc/nfqws2/blobs/discord_udp.bin)"
NFQWS_YOUTUBE_TLS_BLOB="$(root_path /opt/etc/nfqws2/blobs/tls_clienthello.bin)"
NFQWS_YOUTUBE_QUIC_BLOB="$(root_path /opt/etc/nfqws2/blobs/quic_initial.bin)"
NFQWS_PIDFILE="$(root_path /opt/var/run/nfqws2.pid)"
IMPORTED_PROFILE_DIR="$(root_path /opt/etc/nfqws2/imported-profiles)"
PROFILE_VERSION_ROOT="$(root_path /opt/etc/nfqws2/profile-versions)"
IMPORT_SNAPSHOT_ROOT="$STATE_ROOT/nfqws-import-snapshots"
LATEST_IMPORT_POINTER="$STATE_ROOT/latest-nfqws-import.ptr"
XKEEN_DIR="$(root_path /opt/etc/xkeen)"
XKEEN_PORT_PROXYING="$XKEEN_DIR/port_proxying.lst"
XKEEN_PORT_EXCLUDE="$XKEEN_DIR/port_exclude.lst"
XRAY_CONFIG_DIR="$(root_path /opt/etc/xray/configs)"
MIHOMO_CONFIG="$(root_path /opt/etc/mihomo/config.yaml)"
OPKG_FEED="$(root_path /opt/etc/opkg/nfqws2-keenetic.conf)"
SOURCE_DISCORD_UDP_BLOB="$SCRIPT_DIR/config/blobs/ACTIVE_DISCORD_UDP.bin"
DISCORD_UDP_BLOB_SHA256="2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf"
YOUTUBE_TLS_BLOB_SHA256="936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c"
YOUTUBE_QUIC_BLOB_SHA256="f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a"

TCP_PORTS_VALUE="80,443,2053,2083,2087,2096,8443"
UDP_PORTS_FLOWSEAL="443,3478:3481,5349,19294:19344,50000:50100"
UDP_FILTER_FLOWSEAL="443,3478-3481,5349,19294-19344,50000-50100"
UDP_PORTS_WIDE="443,3478:3481,5349,19294:19344,50000:65535"
UDP_FILTER_WIDE="443,3478-3481,5349,19294-19344,50000-65535"
VOICE_HIGH="50100"
XKEEN_REQUIRED_PORTS="80,443,2053,2083,2087,2096,8443,3478:3481,5349,19294:19344,50000:50100"
UNBOUND_POLICY_NAME="__keenetic_discord_nfqws2_unbound__"

MODE="help"
CORE_REQUESTED="auto"
STANDALONE_ZAPRET=0
DIRECT_MARK_REQUESTED=""
DIRECT_MARK_EFFECTIVE=""
WAN_INTERFACE_REQUESTED=""
WAN_INTERFACE_EFFECTIVE=""
IPV6_WAN_INTERFACE=""
NFQWS_IPV6_EFFECTIVE=0
CONFIRMED=0
WIDE_UDP=0
UDP_STRATEGY="flowseal"
DISCORD_TCP_ROUTE_MODE="zapret"
DISCORD_VOICE_ROUTE_MODE="zapret"
YOUTUBE_ROUTE_MODE="vless"
# Telegram is opt-in: "unmanaged" leaves its traffic to the user's own rules.
# Empty means "keep the route recorded in nfqws2.conf" (resolved below).
TELEGRAM_ROUTE_MODE=""
DISCORD_TCP_ROUTE_EXPLICIT=0
DISCORD_VOICE_ROUTE_EXPLICIT=0
YOUTUBE_ROUTE_EXPLICIT=0
PROXY_OUTBOUND_REQUESTED=""
PROXY_OUTBOUND_EFFECTIVE=""
LOCK_HELD=0
TRANSACTION_ACTIVE=0
NFQWS_TRANSACTION_ACTIVE=0
AUTO_ROLLBACK_IN_PROGRESS=0
NFQWS_IMPORT_BACKUP=""
IMPORT_PROFILE_REQUESTED=""
CLEAR_IMPORTED_PROFILE=""
ROLLBACK_SNAPSHOT_REQUESTED=""
PREAPPLY_SNAPSHOT=""
CREATED_SNAPSHOT=""
DETECTED_CORE=""
WORK_TMP_DIR="$(root_path /opt/tmp/${PROJECT}.$$)"

usage() {
  cat <<'EOF'
Usage:
  sh apply-discord-nfqws2.sh --print-plan [routing options]
  sh apply-discord-nfqws2.sh --preflight [--core auto|xray|mihomo]
  sh apply-discord-nfqws2.sh --status
  sh apply-discord-nfqws2.sh --show-snapshots
  sh apply-discord-nfqws2.sh --snapshot-baseline --yes-router
  sh apply-discord-nfqws2.sh --apply --yes-router [routing options]
  sh apply-discord-nfqws2.sh --apply --standalone-zapret --yes-router
  sh apply-discord-nfqws2.sh --apply-import-profile FILE --yes-router
  sh apply-discord-nfqws2.sh --clear-imported-profile SERVICE --yes-router
  sh apply-discord-nfqws2.sh --rollback-import --yes-router
  sh apply-discord-nfqws2.sh --rollback --yes-router
  sh apply-discord-nfqws2.sh --rollback-latest --yes-router
  sh apply-discord-nfqws2.sh --rollback-snapshot SNAPSHOT --yes-router

Short form for apply (kept for compatibility):
  sh apply-discord-nfqws2.sh --yes-router

--rollback restores the immutable baseline captured before the first apply.
--rollback-latest restores the state captured immediately before the last apply.
--rollback-snapshot restores one verified snapshot below the managed snapshot
                    directory and first creates a rescue snapshot.
An apply failure automatically restores its pre-apply snapshot.

UDP strategies:
  flowseal  ACTIVE_DISCORD_UDP.bin fake for Discord Voice/STUN (default)
  legacy    previous generic/quic circular profile

Routing options:
  --standalone-zapret       Install/manage nfqws2 without XKeen/Xray/Mihomo.
                            Defaults both services to zapret; vless is rejected.
                            Aliases: --without-xkeen, --no-xkeen.
  --discord-tcp-route direct|zapret|vless
                             Discord domains: TCP/TLS and QUIC.
  --discord-voice-route direct|zapret|vless
                             Discord Voice/STUN UDP ports.
  --discord-route direct|zapret|vless
                             Shorthand that sets both Discord routes.
  --youtube-route direct|zapret|vless
  --telegram-route direct|zapret|vless|unmanaged
                             Telegram domains and DC networks. Without the
                             option the recorded route is kept (initially
                             unmanaged: the project does not touch Telegram).
  --proxy-outbound TAG       Xray proxy outbound used for vless modes;
                             normally detected from existing YouTube rules
  --core auto|xray|mihomo
  --direct-mark N
  --wan-interface IFACE
  --wide-udp                 Discord Voice ports 50000-65535 instead of 50000-50100
  --narrow-udp               back to 50000-50100 (the default)
  --udp-strategy flowseal|legacy

Imported tuner profiles:
  --apply-import-profile FILE
      Validate and install one sanitized tuner descriptor from /opt/tmp.
      The matching service must already use route=zapret.
      Only nfqws2 is restarted; XKeen/Xray is not changed or restarted.
  --clear-imported-profile youtube|discord-tcp|discord-voice
      Restore the built-in profile for this protocol family.
  --rollback-import
      Restore nfqws2 to the state before the latest profile import/clear.

The compatibility default is Discord TCP and Voice through zapret and YouTube
through vless.
With --standalone-zapret the default is zapret for both services.
Use set-zapret-mode.sh for the four explicit service combinations.

Run mutating modes only in Entware shell on the Keenetic router.
EOF
}

discord_domains() {
  cat <<'EOF'
dis.gd
discord-attachments-uploads-prd.storage.googleapis.com
discord.app
discord.co
discord.com
discord.design
discord.dev
discord.gift
discord.gifts
discord.gg
discord.media
discord.new
discord.status
discord.store
discord.tools
discord-activities.com
discordactivities.com
discordapp.com
discordapp.net
discordcdn.com
discordmerch.com
discordpartygames.com
discordsays.com
discordsez.com
discordstatus.com
cdn.discordapp.com
media.discordapp.net
gateway.discord.gg
updates.discord.com
stable.dl2.discordapp.net
EOF
}

youtube_domains() {
  cat <<'EOF'
yt3.ggpht.com
yt4.ggpht.com
yt3.googleusercontent.com
yt4.googleusercontent.com
googlevideo.com
jnn-pa.googleapis.com
wide-youtube.l.google.com
youtube-nocookie.com
youtube-ui.l.google.com
youtube.com
youtubeembeddedplayer.googleapis.com
youtubekids.com
youtube.googleapis.com
youtubei.googleapis.com
youtu.be
yt-video-upload.l.google.com
ytimg.com
ytimg.l.google.com
ytstatic.l.google.com
EOF
}

# Telegram domains from ext:geosite_v2fly.dat:telegram (config/telegram-user.list).
telegram_domains() {
  cat <<'EOF'
cdn-telegram.org
comments.app
contest.com
fragment.com
graph.org
quiz.directory
t.me
tdesktop.com
telega.one
telegra.ph
telegram-cdn.org
telegram.dog
telegram.me
telegram.org
telegram.space
telesco.pe
tg.dev
ton.org
toncenter.com
tx.me
usercontent.dev
EOF
}

# Telegram networks from ext:geoip_v2fly.dat:telegram (config/telegram-ip.list).
telegram_networks() {
  cat <<'EOF'
91.105.192.0/23
91.108.4.0/22
91.108.8.0/21
91.108.16.0/21
91.108.56.0/22
95.161.64.0/20
149.154.160.0/20
185.76.151.0/24
2001:67c:4e8::/48
2001:b28:f23c::/47
2001:b28:f23f::/48
2a0a:f280::/32
EOF
}

# Telegram route recorded in nfqws2.conf, or "unmanaged".
recorded_telegram_route() {
  if [ -f "$NFQWS_CONF" ]; then
    awk '
      $1 == "#" && $2 == "Active" && $3 == "routes:" {
        for (field = 4; field <= NF; field++) {
          pair = $field
          sub(/[,.]$/, "", pair)
          split(pair, kv, "=")
          if (kv[1] == "Telegram") value = kv[2]
        }
      }
      END {
        if (value ~ /^(direct|zapret|vless|unmanaged)$/) print value
        else print "unmanaged"
      }
    ' "$NFQWS_CONF"
  else
    echo unmanaged
  fi
}

routes_summary() {
  printf 'Discord TCP=%s, Discord Voice=%s, YouTube=%s, Telegram=%s' \
    "$DISCORD_TCP_ROUTE_MODE" "$DISCORD_VOICE_ROUTE_MODE" "$YOUTUBE_ROUTE_MODE" \
    "$TELEGRAM_ROUTE_MODE"
}

# True when at least one managed route equals $1.
any_route_is() {
  [ "$DISCORD_TCP_ROUTE_MODE" = "$1" ] ||
    [ "$DISCORD_VOICE_ROUTE_MODE" = "$1" ] ||
    [ "$YOUTUBE_ROUTE_MODE" = "$1" ] ||
    [ "$TELEGRAM_ROUTE_MODE" = "$1" ]
}

# XKeen must proxy these ports for the managed services to reach Xray.
set_xkeen_required_ports() {
  XKEEN_REQUIRED_PORTS="80,443,2053,2083,2087,2096,8443,3478:3481,5349,19294:19344,50000:$VOICE_HIGH"
  if [ "$TELEGRAM_ROUTE_MODE" != "unmanaged" ]; then
    XKEEN_REQUIRED_PORTS="$XKEEN_REQUIRED_PORTS,5222"
  fi
}

print_plan() {
  if [ "$WIDE_UDP" -eq 1 ]; then
    plan_udp="$UDP_PORTS_WIDE"
  else
    plan_udp="$UDP_PORTS_FLOWSEAL"
  fi

  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    cat <<EOF
План standalone-установки Zapret:
0. Целевые режимы nfqws2: $(routes_summary).
1. Не искать, не читать, не настраивать и не перезапускать XKeen/Xray/Mihomo.
2. Создать scoped snapshot только для nfqws2, его Entware-пакетов и hooks.
3. Установить отсутствующие зависимости и nfqws2-keenetic.
4. Настроить hostlist и отдельные TCP/QUIC/Discord Voice профили,
   Discord UDP=$plan_udp, UDP strategy=$UDP_STRATEGY,
   WAN=${WAN_INTERFACE_REQUESTED:-auto}.
5. Определить IPv4/IPv6 WAN по системным маршрутам, перезапустить и проверить
   только nfqws2. При ошибке автоматически восстановить scoped snapshot.

Применение:
  sh apply-discord-nfqws2.sh --apply --standalone-zapret --yes-router

Откат одной командой:
  sh apply-discord-nfqws2.sh --rollback-latest --yes-router
EOF
    return 0
  fi

  cat <<EOF
План изменений на роутере:
0. Целевые маршруты: $(routes_summary).
1. До любых изменений создать полный снимок состояния.
2. Сохранить неизменяемый baseline при первом запуске и отдельный latest-preapply.
3. Учесть XKeen core=$CORE_REQUESTED и безопасно прочитать:
   - -status, -cp, -cpe, -tp;
   - name_client, proxy_dns, proxy_router, ipv6_support, DSCP и автозапуск
     из /opt/etc/init.d/S05xkeen;
   - фактические Hybrid/TProxy/Redirect, policy mark и donor-порты из
     /opt/etc/ndm/netfilter.d/proxy.sh.
4. Сохранить /opt/etc/xkeen, Xray/Mihomo, nfqws2, hooks, cron, opkg feed,
   состояние пакетов, служб и runtime IPv6.
5. Для Xray:
   - добавить нужные outbound discord-direct/youtube-direct;
   - согласовать их sockopt.mark с proxy_router/существующим Freedom
     (явно: ${DIRECT_MARK_REQUESTED:-auto});
   - поставить управляемые Discord/YouTube rules первыми;
   - оставить YouTube IP-категории на исходном proxy outbound;
   - включить необходимый sniffing для redirect/tproxy;
   - закрыть world-writable права JSON до 0600;
   - проверить конфигурацию через xkeen -xtest.
   Для Mihomo:
   - поставить выбранные Discord/YouTube DIRECT rules первыми;
   - проверить конфигурацию через xkeen -mtest.
6. Если XKeen уже ограничен port_proxying.lst, добавить только нужные порты,
   не удаляя существующие. Конфликт с port_exclude.lst остановит preflight.
7. Установить отсутствующие зависимости и nfqws2-keenetic без обновления
   уже установленных пакетов.
8. Настроить независимые nfqws2 hostlist/profile для активных сервисов,
   Discord UDP=$plan_udp, UDP strategy=$UDP_STRATEGY,
   WAN=${WAN_INTERFACE_REQUESTED:-auto}. IPv6 включить для
   nfqws2 только при ipv6_support=on и реально доступном IPv6 WAN-маршруте.
9. Проверить конфиги и службы. При любой ошибке автоматически откатить apply.

Откат исходного состояния одной командой:
  sh apply-discord-nfqws2.sh --rollback --yes-router
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --print-plan) MODE="print-plan" ;;
    --preflight) MODE="preflight" ;;
    --status) MODE="status" ;;
    --show-snapshots|--show-rollback) MODE="show-snapshots" ;;
    --snapshot-baseline) MODE="snapshot-baseline" ;;
    --apply) MODE="apply" ;;
    --apply-import-profile)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --apply-import-profile requires a staging JSON file." >&2
        exit 2
      }
      MODE="apply-import-profile"
      IMPORT_PROFILE_REQUESTED="$1"
      ;;
    --clear-imported-profile)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --clear-imported-profile requires a service." >&2
        exit 2
      }
      MODE="clear-imported-profile"
      CLEAR_IMPORTED_PROFILE="$1"
      ;;
    --rollback-import) MODE="rollback-import" ;;
    --rollback|--rollback-baseline) MODE="rollback-baseline" ;;
    --rollback-latest) MODE="rollback-latest" ;;
    --rollback-snapshot)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --rollback-snapshot requires a snapshot path." >&2
        exit 2
      }
      MODE="rollback-snapshot"
      ROLLBACK_SNAPSHOT_REQUESTED="$1"
      ;;
    --yes-router)
      CONFIRMED=1
      [ "$MODE" = "help" ] && MODE="apply"
      ;;
    --wide-udp) WIDE_UDP=1 ;;
    --narrow-udp) WIDE_UDP=0 ;;
    --standalone-zapret|--without-xkeen|--no-xkeen)
      STANDALONE_ZAPRET=1
      ;;
    --udp-strategy)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --udp-strategy requires flowseal or legacy." >&2
        exit 2
      }
      UDP_STRATEGY="$1"
      ;;
    --discord-route)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --discord-route requires direct, zapret or vless." >&2
        exit 2
      }
      DISCORD_TCP_ROUTE_MODE="$1"
      DISCORD_VOICE_ROUTE_MODE="$1"
      DISCORD_TCP_ROUTE_EXPLICIT=1
      DISCORD_VOICE_ROUTE_EXPLICIT=1
      ;;
    --discord-tcp-route)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --discord-tcp-route requires direct, zapret or vless." >&2
        exit 2
      }
      DISCORD_TCP_ROUTE_MODE="$1"
      DISCORD_TCP_ROUTE_EXPLICIT=1
      ;;
    --discord-voice-route)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --discord-voice-route requires direct, zapret or vless." >&2
        exit 2
      }
      DISCORD_VOICE_ROUTE_MODE="$1"
      DISCORD_VOICE_ROUTE_EXPLICIT=1
      ;;
    --youtube-route)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --youtube-route requires direct, zapret or vless." >&2
        exit 2
      }
      YOUTUBE_ROUTE_MODE="$1"
      YOUTUBE_ROUTE_EXPLICIT=1
      ;;
    --telegram-route)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --telegram-route requires direct, zapret, vless or unmanaged." >&2
        exit 2
      }
      TELEGRAM_ROUTE_MODE="$1"
      ;;
    --proxy-outbound)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --proxy-outbound requires an Xray outbound tag." >&2
        exit 2
      }
      PROXY_OUTBOUND_REQUESTED="$1"
      ;;
    --core)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --core requires auto, xray, or mihomo." >&2
        exit 2
      }
      CORE_REQUESTED="$1"
      ;;
    --direct-mark)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --direct-mark requires a decimal Keenetic policy mark." >&2
        exit 2
      }
      DIRECT_MARK_REQUESTED="$1"
      ;;
    --wan-interface)
      shift
      [ "$#" -gt 0 ] || {
        echo "ERROR: --wan-interface requires one interface or a quoted list." >&2
        exit 2
      }
      WAN_INTERFACE_REQUESTED="$1"
      ;;
    -h|--help) MODE="help" ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

[ -n "$TELEGRAM_ROUTE_MODE" ] || TELEGRAM_ROUTE_MODE="$(recorded_telegram_route)"
case "$TELEGRAM_ROUTE_MODE" in
  direct|zapret|vless|unmanaged) ;;
  *)
    echo "ERROR: unsupported Telegram route: $TELEGRAM_ROUTE_MODE" >&2
    exit 2
    ;;
esac

if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
  [ "$DISCORD_TCP_ROUTE_EXPLICIT" -eq 1 ] || DISCORD_TCP_ROUTE_MODE="zapret"
  [ "$DISCORD_VOICE_ROUTE_EXPLICIT" -eq 1 ] || DISCORD_VOICE_ROUTE_MODE="zapret"
  [ "$YOUTUBE_ROUTE_EXPLICIT" -eq 1 ] || YOUTUBE_ROUTE_MODE="zapret"
  if [ "$CORE_REQUESTED" != "auto" ]; then
    echo "ERROR: --core cannot be combined with --standalone-zapret." >&2
    exit 2
  fi
  if [ -n "$DIRECT_MARK_REQUESTED" ] || [ -n "$PROXY_OUTBOUND_REQUESTED" ]; then
    echo "ERROR: --direct-mark/--proxy-outbound require XKeen and cannot be used in standalone mode." >&2
    exit 2
  fi
  if any_route_is vless; then
    echo "ERROR: vless routing is unavailable with --standalone-zapret; use zapret or direct." >&2
    exit 2
  fi
  if ! any_route_is zapret; then
    echo "ERROR: standalone mode needs at least one service with route=zapret." >&2
    exit 2
  fi
fi

case "$CORE_REQUESTED" in
  auto|xray|mihomo) ;;
  *)
    echo "ERROR: unsupported core: $CORE_REQUESTED" >&2
    exit 2
    ;;
esac

case "$UDP_STRATEGY" in
  flowseal|legacy) ;;
  *)
    echo "ERROR: unsupported UDP strategy: $UDP_STRATEGY" >&2
    exit 2
    ;;
esac

case "$DISCORD_TCP_ROUTE_MODE" in
  direct|zapret|vless) ;;
  *)
    echo "ERROR: unsupported Discord TCP route: $DISCORD_TCP_ROUTE_MODE" >&2
    exit 2
    ;;
esac

case "$DISCORD_VOICE_ROUTE_MODE" in
  direct|zapret|vless) ;;
  *)
    echo "ERROR: unsupported Discord Voice route: $DISCORD_VOICE_ROUTE_MODE" >&2
    exit 2
    ;;
esac

case "$YOUTUBE_ROUTE_MODE" in
  direct|zapret|vless) ;;
  *)
    echo "ERROR: unsupported YouTube route: $YOUTUBE_ROUTE_MODE" >&2
    exit 2
    ;;
esac

case "$PROXY_OUTBOUND_REQUESTED" in
  ""|*[!A-Za-z0-9_.:-]*)
    if [ -n "$PROXY_OUTBOUND_REQUESTED" ]; then
      echo "ERROR: invalid Xray proxy outbound tag: $PROXY_OUTBOUND_REQUESTED" >&2
      exit 2
    fi
    ;;
esac

if [ "$WIDE_UDP" -eq 1 ]; then
  VOICE_HIGH="65535"
fi
set_xkeen_required_ports

if [ "$MODE" = "help" ]; then
  usage
  exit 0
fi

if [ "$MODE" = "print-plan" ]; then
  print_plan
  exit 0
fi

have() {
  command -v "$1" >/dev/null 2>&1
}

verify_discord_udp_blob_source() {
  [ "$UDP_STRATEGY" = "flowseal" ] || return 0
  [ -f "$SOURCE_DISCORD_UDP_BLOB" ] || {
    echo "ERROR: Flowseal Discord UDP blob is missing: $SOURCE_DISCORD_UDP_BLOB" >&2
    return 1
  }
  have sha256sum || {
    echo "ERROR: sha256sum is required to verify the Flowseal Discord UDP blob." >&2
    return 1
  }
  blob_hash="$(sha256sum "$SOURCE_DISCORD_UDP_BLOB" | awk '{ print $1 }')"
  [ "$blob_hash" = "$DISCORD_UDP_BLOB_SHA256" ] || {
    echo "ERROR: Flowseal Discord UDP blob checksum mismatch." >&2
    echo "       Expected: $DISCORD_UDP_BLOB_SHA256" >&2
    echo "       Actual:   $blob_hash" >&2
    return 1
  }
}

verify_youtube_blobs() {
  [ "$YOUTUBE_ROUTE_MODE" = "zapret" ] || return 0
  have sha256sum || {
    echo "ERROR: sha256sum is required to verify the YouTube TLS/QUIC blobs." >&2
    return 1
  }
  [ -f "$NFQWS_YOUTUBE_TLS_BLOB" ] || {
    echo "ERROR: required nfqws2 YouTube TLS blob is missing: $NFQWS_YOUTUBE_TLS_BLOB" >&2
    return 1
  }
  [ -f "$NFQWS_YOUTUBE_QUIC_BLOB" ] || {
    echo "ERROR: required nfqws2 YouTube QUIC blob is missing: $NFQWS_YOUTUBE_QUIC_BLOB" >&2
    return 1
  }
  youtube_tls_blob_actual="$(sha256sum "$NFQWS_YOUTUBE_TLS_BLOB" | awk '{ print $1 }')"
  [ "$youtube_tls_blob_actual" = "$YOUTUBE_TLS_BLOB_SHA256" ] || {
    echo "ERROR: YouTube TLS blob checksum mismatch: $NFQWS_YOUTUBE_TLS_BLOB" >&2
    echo "       Expected: $YOUTUBE_TLS_BLOB_SHA256" >&2
    echo "       Actual:   $youtube_tls_blob_actual" >&2
    return 1
  }
  youtube_blob_actual="$(sha256sum "$NFQWS_YOUTUBE_QUIC_BLOB" | awk '{ print $1 }')"
  [ "$youtube_blob_actual" = "$YOUTUBE_QUIC_BLOB_SHA256" ] || {
    echo "ERROR: YouTube QUIC blob checksum mismatch: $NFQWS_YOUTUBE_QUIC_BLOB" >&2
    echo "       Expected: $YOUTUBE_QUIC_BLOB_SHA256" >&2
    echo "       Actual:   $youtube_blob_actual" >&2
    return 1
  }
}

run_nfqws_init() {
  nfqws_action="$1"
  (
    cd /
    "$NFQWS_INIT" "$nfqws_action"
  )
}

is_router() {
  if [ -n "$TEST_ROOT" ]; then
    return 0
  fi
  [ -x /bin/ndmc ] && [ -d /opt/etc ]
}

require_router_readonly() {
  if ! is_router; then
    echo "ERROR: this does not look like a Keenetic Entware environment." >&2
    return 1
  fi
}

require_confirmation() {
  if [ "$CONFIRMED" -ne 1 ]; then
    echo "ERROR: this mode changes router state; re-run with --yes-router." >&2
    return 1
  fi
  require_router_readonly
  if [ -z "$TEST_ROOT" ] && [ "$(id -u 2>/dev/null || echo 1)" != "0" ]; then
    echo "ERROR: root privileges are required." >&2
    return 1
  fi
}

make_tmp() {
  mkdir -p "$WORK_TMP_DIR"
  made_tmp="$(mktemp "$WORK_TMP_DIR/file.XXXXXX")"
  printf '%s\n' "$made_tmp"
}

cleanup_tmp() {
  case "$WORK_TMP_DIR" in
    "$(root_path /opt/tmp)/${PROJECT}."*)
      [ ! -d "$WORK_TMP_DIR" ] || rm -rf "$WORK_TMP_DIR"
      ;;
  esac
  cleanup_dirs="$STATE_ROOT
$(dirname "$OPKG_FEED")
$(dirname "$NFQWS_CONF")
$(dirname "$NFQWS_LIST")"
  if [ "$STANDALONE_ZAPRET" -eq 0 ]; then
    cleanup_dirs="$cleanup_dirs
$XKEEN_DIR
$XRAY_CONFIG_DIR
$(dirname "$MIHOMO_CONFIG")"
  fi
  printf '%s\n' "$cleanup_dirs" | while IFS= read -r cleanup_dir
  do
    [ -n "$cleanup_dir" ] || continue
    [ -d "$cleanup_dir" ] || continue
    for cleanup_sibling in "$cleanup_dir"/.kdtxn-"$$"-*; do
      [ ! -e "$cleanup_sibling" ] || rm -f "$cleanup_sibling"
    done
  done
}

imported_profile_path() {
  imported_service="$1"
  case "$imported_service" in
    youtube|discord-tcp|discord-voice)
      printf '%s/%s.json\n' "$IMPORTED_PROFILE_DIR" "$imported_service"
      ;;
    *) return 1 ;;
  esac
}

archive_imported_profile_version() {
  version_source="$1"
  version_reason="$2"
  validate_imported_profile "$version_source"
  version_service="$(jq -r '.service' "$version_source")"
  version_candidate="$(jq -r '.candidate_id' "$version_source")"
  case "$version_reason" in
    applied|replaced|cleared) ;;
    *)
      echo "ERROR: unsupported profile version reason: $version_reason" >&2
      return 1
      ;;
  esac
  version_stamp="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || date +%Y%m%dT%H%M%S)"
  version_dir="$PROFILE_VERSION_ROOT/$version_service"
  version_target="$version_dir/${version_stamp}-${version_candidate}-${version_reason}-$$.json"
  mkdir -p "$version_dir"
  chmod 700 "$PROFILE_VERSION_ROOT" "$version_dir"
  version_counter=0
  while [ -e "$version_target" ]; do
    version_counter=$((version_counter + 1))
    version_target="$version_dir/${version_stamp}-${version_candidate}-${version_reason}-$$-$version_counter.json"
  done
  atomic_replace_file "$version_target" "$version_source" 600
  echo "Profile version saved: $version_target"
}

safe_import_stage_path() {
  import_stage="$1"
  case "$import_stage" in
    "$(root_path /opt/tmp)/"*) ;;
    *) return 1 ;;
  esac
  case "$import_stage" in
    *"/../"*|*"/.."|*"//"*) return 1 ;;
  esac
  [ -f "$import_stage" ] && [ ! -L "$import_stage" ]
}

voice_ports_allowed() {
  voice_ports="$1"
  voice_limit="$2"
  awk -v ports="$voice_ports" -v high="$voice_limit" '
    function allowed(left, right) {
      return (left == 443 && right == 443) ||
             (left >= 3478 && right <= 3481) ||
             (left == 5349 && right == 5349) ||
             (left >= 19294 && right <= 19344) ||
             (left >= 50000 && right <= high)
    }
    BEGIN {
      count=split(ports, parts, ",")
      if (count < 1) exit 1
      for (i=1; i<=count; i++) {
        range_count=split(parts[i], range, "-")
        if (range_count == 1) range[2]=range[1]
        if (range_count > 2 || range[1] !~ /^[0-9]+$/ ||
            range[2] !~ /^[0-9]+$/ || range[1] > range[2] ||
            !allowed(range[1] + 0, range[2] + 0)) exit 1
        delete range
      }
    }
  '
}

validate_imported_profile() {
  profile_file="$1"
  [ -f "$profile_file" ] && [ ! -L "$profile_file" ] || {
    echo "ERROR: imported profile is not a regular file: $profile_file" >&2
    return 1
  }
  have jq && have sha256sum || {
    echo "ERROR: jq and sha256sum are required for profile import." >&2
    return 1
  }

  jq -e '
    type == "object"
    and .format == 1
    and (.service == "youtube" or .service == "discord-tcp" or
         .service == "discord-voice")
    and (.candidate_id | type == "string" and length == 12)
    and (.source_name | type == "string" and length > 0 and length <= 160 and
         index("\n") == null and index("\r") == null)
    and (.source_sha | type == "string" and length <= 128 and
         index("\n") == null and index("\r") == null)
    and (.source_url | type == "string" and length <= 500 and
         index("\n") == null and index("\r") == null)
    and (.family | type == "string" and length > 0 and length <= 240 and
         index("\n") == null and index("\r") == null)
    and (.rank | type == "number" and floor == . and . >= 0 and . <= 100000)
    and (.args | type == "array" and length > 0 and length <= 40 and
         all(.[]; type == "string" and length > 0 and length <= 600 and
             index("\n") == null and index("\r") == null))
    and (.notes | type == "array" and length <= 20 and
         all(.[]; type == "string" and length <= 500 and
             index("\n") == null and index("\r") == null))
    and ((keys - ["args", "candidate_id", "family", "format", "notes",
                  "rank", "report", "service", "source_name", "source_sha",
                  "source_url"]) | length == 0)
    and ((.report // {}) | type == "object")
    and (((.report // {}) | keys - ["commit", "created_utc", "ref", "repository", "search_seed"]) | length == 0)
    and ((.report.repository // "") | type == "string" and length <= 200 and
         index("\n") == null and index("\r") == null)
    and ((.report.ref // "") | type == "string" and length <= 200 and
         index("\n") == null and index("\r") == null)
    and ((.report.commit // "") | type == "string" and length <= 128 and
         index("\n") == null and index("\r") == null)
    and ((.report.created_utc // "") | type == "string" and length <= 80 and
         index("\n") == null and index("\r") == null)
    and ((.report.search_seed // null) as $seed |
         $seed == null or
         ($seed | type == "number" and floor == . and . >= 0 and . <= 4294967295))
  ' "$profile_file" >/dev/null || {
    echo "ERROR: imported profile has an invalid schema." >&2
    return 1
  }

  profile_tokens="$(make_tmp)"
  jq -r '.args[]' "$profile_file" > "$profile_tokens"
  profile_service="$(jq -r '.service' "$profile_file")"
  profile_new_count=0
  while IFS= read -r profile_token; do
    if [ "$profile_token" = "--new" ]; then
      profile_new_count=$((profile_new_count + 1))
      continue
    fi
    printf '%s\n' "$profile_token" |
      grep -Eq '^--[a-z0-9-]+=[A-Za-z0-9_@/.,:+<>=!-]+$' || {
        echo "ERROR: unsafe nfqws2 token in imported profile: $profile_token" >&2
        return 1
      }
    profile_option="${profile_token%%=*}"
    profile_option="${profile_option#--}"
    case "$profile_option" in
      filter-tcp|filter-udp|filter-l7|hostlist|out-range|payload|lua-desync) ;;
      *)
        echo "ERROR: unsupported imported nfqws2 option: --$profile_option" >&2
        return 1
        ;;
    esac
    case "$profile_token" in
      --lua-desync=*)
        profile_lua="${profile_token#--lua-desync=}"
        profile_lua="${profile_lua%%:*}"
        case "$profile_lua" in
          fake|multisplit|multidisorder|fakedsplit|hostfakesplit) ;;
          *)
            echo "ERROR: unsupported imported Lua desync: $profile_lua" >&2
            return 1
            ;;
        esac
        ;;
    esac
  done < "$profile_tokens"

  case "$profile_service" in
    youtube)
      [ "$profile_new_count" -eq 1 ] &&
        grep -Fqx -- '--filter-tcp=443' "$profile_tokens" &&
        grep -Fqx -- '--filter-udp=443' "$profile_tokens" &&
        grep -Fqx -- '--filter-l7=tls' "$profile_tokens" &&
        grep -Fqx -- '--filter-l7=quic' "$profile_tokens" &&
        grep -Fqx -- '--hostlist=/opt/etc/nfqws2/lists/youtube.list' "$profile_tokens" &&
        grep -Fqx -- '--payload=tls_client_hello' "$profile_tokens" &&
        grep -Fqx -- '--payload=quic_initial' "$profile_tokens" || {
          echo "ERROR: YouTube profile is missing its bounded TCP/QUIC selectors." >&2
          return 1
        }
      if grep -E '^--filter-(tcp|udp)=' "$profile_tokens" |
           grep -Ev '^--filter-tcp=443$|^--filter-udp=443$' >/dev/null ||
         grep -E '^--filter-l7=' "$profile_tokens" |
           grep -Ev '^--filter-l7=tls$|^--filter-l7=quic$' >/dev/null ||
         grep -E '^--hostlist=' "$profile_tokens" |
           grep -Fvx -- '--hostlist=/opt/etc/nfqws2/lists/youtube.list' >/dev/null ||
         grep -E '^--payload=' "$profile_tokens" |
           grep -Ev '^--payload=tls_client_hello$|^--payload=quic_initial$' >/dev/null ||
         grep -Eq 'user\.list|discord_udp|discord_ip_discovery' "$profile_tokens"; then
        echo "ERROR: YouTube profile crosses into a Discord profile." >&2
        return 1
      fi
      ;;
    discord-tcp)
      [ "$profile_new_count" -eq 0 ] &&
        grep -Fqx -- '--filter-tcp=443' "$profile_tokens" &&
        grep -Fqx -- '--filter-l7=tls' "$profile_tokens" &&
        grep -Fqx -- '--hostlist=/opt/etc/nfqws2/lists/user.list' "$profile_tokens" &&
        grep -Fqx -- '--payload=tls_client_hello' "$profile_tokens" || {
          echo "ERROR: Discord TCP profile is missing its bounded TLS selectors." >&2
          return 1
        }
      if grep -E '^--filter-tcp=' "$profile_tokens" |
           grep -Fvx -- '--filter-tcp=443' >/dev/null ||
         grep -E '^--filter-l7=' "$profile_tokens" |
           grep -Fvx -- '--filter-l7=tls' >/dev/null ||
         grep -E '^--hostlist=' "$profile_tokens" |
           grep -Fvx -- '--hostlist=/opt/etc/nfqws2/lists/user.list' >/dev/null ||
         grep -E '^--payload=' "$profile_tokens" |
           grep -Fvx -- '--payload=tls_client_hello' >/dev/null ||
         grep -Eq '^--filter-udp=|youtube\.list|quic_initial|discord_udp' "$profile_tokens"; then
        echo "ERROR: Discord TCP profile crosses into another protocol family." >&2
        return 1
      fi
      ;;
    discord-voice)
      [ "$profile_new_count" -eq 0 ] &&
        grep -Fqx -- '--filter-l7=stun,discord' "$profile_tokens" &&
        grep -Fqx -- '--payload=stun,discord_ip_discovery' "$profile_tokens" &&
        grep -Eq '^--lua-desync=fake:blob=discord_udp:' "$profile_tokens" || {
          echo "ERROR: Discord Voice profile is missing its bounded UDP selectors." >&2
          return 1
        }
      if grep -Eq '^--filter-tcp=|^--hostlist=|youtube|quic_initial|tls_client' "$profile_tokens"; then
        echo "ERROR: Discord Voice profile crosses into another protocol family." >&2
        return 1
      fi
      profile_voice_lua_count="$(grep -c '^--lua-desync=' "$profile_tokens" || true)"
      [ "$profile_voice_lua_count" -eq 1 ] &&
        grep -Eq '^--lua-desync=fake:blob=discord_udp:repeats=([1-9]|[1-9][0-9])$' "$profile_tokens" || {
          echo "ERROR: Discord Voice permits one bounded discord_udp fake only." >&2
          return 1
        }
      profile_voice_filters="$(sed -n 's/^--filter-udp=//p' "$profile_tokens")"
      [ "$(printf '%s\n' "$profile_voice_filters" | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ] || {
        echo "ERROR: Discord Voice profile must contain one UDP filter." >&2
        return 1
      }
      voice_ports_allowed "$profile_voice_filters" "$VOICE_HIGH" || {
        echo "ERROR: Discord Voice UDP ports exceed the currently configured safe ranges." >&2
        return 1
      }
      ;;
  esac

  profile_serialized="$(make_tmp)"
  profile_serialized_value="$(
    jq -r '[.service, .source_name, .family] + .args | join("\n")' "$profile_file"
  )"
  printf '%s' "$profile_serialized_value" > "$profile_serialized"
  profile_expected_id="$(sha256sum "$profile_serialized" | awk '{ print substr($1, 1, 12) }')"
  profile_actual_id="$(jq -r '.candidate_id' "$profile_file")"
  [ "$profile_expected_id" = "$profile_actual_id" ] || {
    echo "ERROR: imported profile candidate_id does not match its contents." >&2
    return 1
  }
}

release_lock() {
  if [ "$LOCK_HELD" -eq 1 ]; then
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    LOCK_HELD=0
  fi
}

acquire_lock() {
  mkdir -p "$(root_path /opt/tmp)"
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "$LOCK_DIR/pid"
    LOCK_HELD=1
    return 0
  fi

  lock_pid=""
  [ ! -f "$LOCK_DIR/pid" ] || lock_pid="$(sed -n '1p' "$LOCK_DIR/pid")"
  case "$lock_pid" in
    ''|*[!0-9]*) lock_alive=0 ;;
    *)
      if kill -0 "$lock_pid" 2>/dev/null; then
        lock_alive=1
      else
        lock_alive=0
      fi
      ;;
  esac

  if [ "$lock_alive" -eq 1 ]; then
    echo "ERROR: another $PROJECT process is active (PID $lock_pid)." >&2
    return 1
  fi

  echo "Removing stale lock: $LOCK_DIR" >&2
  rm -f "$LOCK_DIR/pid"
  rmdir "$LOCK_DIR" 2>/dev/null || {
    echo "ERROR: stale lock directory is not empty: $LOCK_DIR" >&2
    return 1
  }
  mkdir "$LOCK_DIR"
  printf '%s\n' "$$" > "$LOCK_DIR/pid"
  LOCK_HELD=1
}

atomic_pointer() {
  pointer_target="$1"
  pointer_value="$2"
  pointer_tmp="$(dirname "$pointer_target")/.kdtxn-$$-pointer"
  printf '%s\n' "$pointer_value" > "$pointer_tmp"
  chmod 600 "$pointer_tmp"
  mv "$pointer_tmp" "$pointer_target"
}

safe_snapshot_path() {
  candidate_snapshot="$1"
  case "$candidate_snapshot" in
    "$SNAPSHOT_ROOT"/*)
      case "$candidate_snapshot" in
        *"/../"*|*"/.."|*"//"*) return 1 ;;
      esac
      snapshot_leaf="${candidate_snapshot#"$SNAPSHOT_ROOT"/}"
      case "$snapshot_leaf" in
        ""|*/*) return 1 ;;
      esac
      ;;
    *) return 1 ;;
  esac
  [ -d "$candidate_snapshot" ] && [ ! -L "$candidate_snapshot" ]
}

read_pointer() {
  pointer_file="$1"
  [ -f "$pointer_file" ] || return 1
  pointer_snapshot="$(sed -n '1p' "$pointer_file")"
  safe_snapshot_path "$pointer_snapshot" || {
    echo "ERROR: invalid snapshot pointer: $pointer_file" >&2
    return 1
  }
  printf '%s\n' "$pointer_snapshot"
}

current_snapshot_scope() {
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    printf '%s\n' standalone
  else
    printf '%s\n' integrated
  fi
}

snapshot_scope() {
  scope_snapshot="$1"
  scope_value="$(state_value "$scope_snapshot/STATE.tsv" SCOPE 2>/dev/null || true)"
  case "$scope_value" in
    standalone|integrated) printf '%s\n' "$scope_value" ;;
    "") printf '%s\n' integrated ;;
    *)
      echo "ERROR: unsupported snapshot scope: $scope_value" >&2
      return 1
      ;;
  esac
}

managed_paths() {
  managed_scope="${1:-$(current_snapshot_scope)}"
  case "$managed_scope" in
    integrated)
      cat <<'EOF'
/opt/etc/xkeen
/opt/etc/xray/configs
/opt/etc/mihomo
/opt/etc/init.d/S05xkeen
/opt/etc/ndm/netfilter.d/proxy.sh
/opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh
EOF
      ;;
    standalone) ;;
    *)
      echo "ERROR: unsupported managed-path scope: $managed_scope" >&2
      return 1
      ;;
  esac
  cat <<'EOF'
/opt/etc/nfqws2
/opt/etc/init.d/S51nfqws2
/opt/etc/opkg/nfqws2-keenetic.conf
/opt/var/opkg-lists
/opt/etc/ndm/netfilter.d/100-nfqws2.sh
/opt/var/spool/cron/crontabs/root
EOF
}

is_managed_path() {
  checked_path="$1"
  checked_scope="${2:-$(current_snapshot_scope)}"
  managed_paths "$checked_scope" | grep -Fqx "$checked_path"
}

path_exists() {
  [ -e "$1" ] || [ -L "$1" ]
}

package_version() {
  package_name="$1"
  opkg status "$package_name" 2>/dev/null | awk '
    /^Status:.* installed/ { installed=1 }
    /^Version:/ { version=$2 }
    END { if (installed) print version }
  '
}

process_running() {
  process_name="$1"
  if have pidof && pidof "$process_name" >/dev/null 2>&1; then
    return 0
  fi
  if have pgrep && pgrep -x "$process_name" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

nfqws_running() {
  if [ -f "$NFQWS_PIDFILE" ]; then
    nfqws_pid="$(sed -n '1p' "$NFQWS_PIDFILE")"
    case "$nfqws_pid" in
      ''|*[!0-9]*) ;;
      *) kill -0 "$nfqws_pid" 2>/dev/null && return 0 ;;
    esac
  fi
  # A fixture root must never inherit the host/router nfqws2 PID through
  # pidof/pgrep. Fixture services are represented only by their redirected
  # pidfile above.
  [ -z "$TEST_ROOT" ] || return 1
  process_running nfqws2
}

init_value() {
  wanted_key="$1"
  [ -f "$XKEEN_INIT" ] || return 0
  awk -F= -v wanted="$wanted_key" '
    $1 == wanted {
      value=$0
      sub(/^[^=]*=/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
        value=substr(value, 2, length(value)-2)
      }
      print value
      exit
    }
  ' "$XKEEN_INIT"
}

runtime_value() {
  wanted_key="$1"
  [ -f "$XKEEN_HOOK" ] || return 0
  awk -F= -v wanted="$wanted_key" '
    $1 == wanted {
      value=$0
      sub(/^[^=]*=/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
        value=substr(value, 2, length(value)-2)
      }
      print value
      exit
    }
  ' "$XKEEN_HOOK"
}

xkeen_effective_value() {
  effective_key="$1"
  effective_value="$(runtime_value "$effective_key")"
  if [ -n "$effective_value" ]; then
    printf '%s\n' "$effective_value"
  else
    init_value "$effective_key"
  fi
}

detect_core() {
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    DETECTED_CORE="standalone"
    return 0
  fi
  if [ "$CORE_REQUESTED" != "auto" ]; then
    DETECTED_CORE="$CORE_REQUESTED"
  else
    DETECTED_CORE="$(init_value name_client)"
  fi
  case "$DETECTED_CORE" in
    xray|mihomo) ;;
    *)
      echo "ERROR: XKeen core is '$DETECTED_CORE'; expected xray or mihomo." >&2
      return 1
      ;;
  esac
}

active_ports() {
  ports_file="$1"
  [ -f "$ports_file" ] || return 0
  sed 's/\r$//' "$ports_file" |
    sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
    grep -v '^#' |
    grep -v '^$' |
    sed 's/-/:/g' |
    grep -E '^[0-9]+(:[0-9]+)?$' |
    tr '\n' ',' |
    sed 's/,$//' || true
}

ports_overlap() {
  overlap_left="$1"
  overlap_right="$2"
  awk -v left="$overlap_left" -v right="$overlap_right" '
    function bounds(spec, out, n) {
      gsub(/-/, ":", spec)
      n=split(spec, out, ":")
      if (n == 1) out[2]=out[1]
      return (out[1] ~ /^[0-9]+$/ && out[2] ~ /^[0-9]+$/)
    }
    BEGIN {
      nl=split(left, l, ",")
      nr=split(right, r, ",")
      for (i=1; i<=nl; i++) {
        delete lb
        if (!bounds(l[i], lb)) continue
        for (j=1; j<=nr; j++) {
          delete rb
          if (!bounds(r[j], rb)) continue
          if (lb[1] <= rb[2] && rb[1] <= lb[2]) exit 0
        }
      }
      exit 1
    }
  '
}

nfqws_value() {
  nfqws_key="$1"
  [ -f "$NFQWS_CONF" ] || return 0
  awk -F= -v wanted="$nfqws_key" '
    $1 == wanted {
      value=$0
      sub(/^[^=]*=/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
        value=substr(value, 2, length(value)-2)
      }
      found=value
    }
    END { if (found != "") print found }
  ' "$NFQWS_CONF"
}

validate_wan_interfaces() {
  interfaces_to_check="$1"
  [ -n "$interfaces_to_check" ] || return 1
  for interface_name in $interfaces_to_check; do
    case "$interface_name" in
      *[!A-Za-z0-9_.:-]*)
        echo "ERROR: invalid WAN interface name: $interface_name" >&2
        return 1
        ;;
    esac
    if [ "$interface_name" = "lo" ]; then
      echo "ERROR: loopback cannot be used as an nfqws2 WAN interface." >&2
      return 1
    fi
    ip link show dev "$interface_name" >/dev/null 2>&1 || {
      echo "ERROR: WAN interface does not exist: $interface_name" >&2
      return 1
    }
  done
}

interface_list_contains() {
  interface_list="$1"
  interface_wanted="$2"
  for interface_item in $interface_list; do
    [ "$interface_item" != "$interface_wanted" ] || return 0
  done
  return 1
}

route_interface() {
  route_mark="$1"
  route_output=""
  if [ -n "$route_mark" ] && [ "$route_mark" != "255" ]; then
    route_output="$(ip route get 1.1.1.1 mark "$route_mark" 2>/dev/null || true)"
  fi
  if [ -z "$route_output" ]; then
    route_output="$(ip route get 1.1.1.1 2>/dev/null || true)"
  fi
  if [ -z "$route_output" ]; then
    route_output="$(ip route show default 2>/dev/null | sed -n '1p')"
  fi
  case " $route_output " in
    *" unreachable "*|*" blackhole "*|*" prohibit "*|*" error "*|*" dev lo "*)
      return 0
      ;;
  esac
  printf '%s\n' "$route_output" |
    awk '{
      for (i=1; i<=NF; i++) {
        if ($i == "dev" && (i+1) <= NF) {
          print $(i+1)
          exit
        }
      }
    }'
}

route_interface_v6() {
  route_mark_v6="$1"
  route_output_v6=""
  if [ -n "$route_mark_v6" ] && [ "$route_mark_v6" != "255" ]; then
    route_output_v6="$(ip -6 route get 2001:4860:4860::8888 mark "$route_mark_v6" 2>/dev/null || true)"
  fi
  if [ -z "$route_output_v6" ]; then
    route_output_v6="$(ip -6 route get 2001:4860:4860::8888 2>/dev/null || true)"
  fi
  if [ -z "$route_output_v6" ]; then
    route_output_v6="$(ip -6 route show default 2>/dev/null | sed -n '1p')"
  fi
  case " $route_output_v6 " in
    *" unreachable "*|*" blackhole "*|*" prohibit "*|*" error "*|*" dev lo "*)
      return 0
      ;;
  esac
  printf '%s\n' "$route_output_v6" |
    awk '{
      for (i=1; i<=NF; i++) {
        if ($i == "dev" && (i+1) <= NF) {
          print $(i+1)
          exit
        }
      }
    }'
}

resolve_wan_interfaces() {
  WAN_INTERFACE_EFFECTIVE=""
  IPV6_WAN_INTERFACE=""
  NFQWS_IPV6_EFFECTIVE=0
  existing_interfaces=""
  route_lookup_mark="$DIRECT_MARK_EFFECTIVE"
  if [ "$STANDALONE_ZAPRET" -eq 0 ] &&
     [ "$DETECTED_CORE" = "mihomo" ]; then
    mihomo_routing_mark="$(
      yq -o=json '.' "$MIHOMO_CONFIG" 2>/dev/null |
        jq -r '.["routing-mark"] // empty' 2>/dev/null || true
    )"
    case "$mihomo_routing_mark" in
      ''|*[!0-9]*) ;;
      *) route_lookup_mark="$mihomo_routing_mark" ;;
    esac
  fi

  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    IPV6_WAN_INTERFACE="$(route_interface_v6 "")"
    if [ -n "$IPV6_WAN_INTERFACE" ]; then
      NFQWS_IPV6_EFFECTIVE=1
    fi
  elif [ "$(init_value ipv6_support)" = "on" ]; then
    IPV6_WAN_INTERFACE="$(route_interface_v6 "$route_lookup_mark")"
    if [ -n "$IPV6_WAN_INTERFACE" ]; then
      NFQWS_IPV6_EFFECTIVE=1
    else
      echo "WARNING: XKeen IPv6 support is on, but no usable IPv6 WAN route exists." >&2
      echo "         nfqws2 IPv6 processing will remain disabled." >&2
    fi
  fi

  if [ -n "$WAN_INTERFACE_REQUESTED" ]; then
    WAN_INTERFACE_EFFECTIVE="$WAN_INTERFACE_REQUESTED"
  else
    existing_interfaces="$(nfqws_value ISP_INTERFACE)"
    if [ -n "$existing_interfaces" ]; then
      WAN_INTERFACE_EFFECTIVE="$existing_interfaces"
    else
      WAN_INTERFACE_EFFECTIVE="$(route_interface "$route_lookup_mark")"
      if [ "$NFQWS_IPV6_EFFECTIVE" -eq 1 ]; then
        inferred_v6_iface="$IPV6_WAN_INTERFACE"
        if [ -n "$inferred_v6_iface" ]; then
          case " $WAN_INTERFACE_EFFECTIVE " in
            *" $inferred_v6_iface "*) ;;
            *) WAN_INTERFACE_EFFECTIVE="$WAN_INTERFACE_EFFECTIVE $inferred_v6_iface" ;;
          esac
        fi
      fi
    fi
  fi

  [ -n "$WAN_INTERFACE_EFFECTIVE" ] || {
    echo "ERROR: cannot determine WAN interface for nfqws2." >&2
    echo "       Pass it explicitly with --wan-interface IFACE." >&2
    return 1
  }
  validate_wan_interfaces "$WAN_INTERFACE_EFFECTIVE" || return 1

  if [ -n "$existing_interfaces" ] && [ -z "$WAN_INTERFACE_REQUESTED" ]; then
    expected_v4_iface="$(route_interface "$route_lookup_mark")"
    if [ -n "$expected_v4_iface" ] &&
       ! interface_list_contains "$WAN_INTERFACE_EFFECTIVE" "$expected_v4_iface"; then
      echo "ERROR: existing nfqws2 ISP_INTERFACE misses routed IPv4 WAN: $expected_v4_iface" >&2
      echo "       Pass the intended list with --wan-interface \"IFACE1 IFACE2\"." >&2
      return 1
    fi
    if [ "$NFQWS_IPV6_EFFECTIVE" -eq 1 ]; then
      expected_v6_iface="$IPV6_WAN_INTERFACE"
      if [ -n "$expected_v6_iface" ] &&
         ! interface_list_contains "$WAN_INTERFACE_EFFECTIVE" "$expected_v6_iface"; then
        echo "ERROR: existing nfqws2 ISP_INTERFACE misses routed IPv6 WAN: $expected_v6_iface" >&2
        echo "       Pass the intended list with --wan-interface \"IFACE1 IFACE2\"." >&2
        return 1
      fi
    fi
  fi
}

preflight() {
  preflight_errors=0
  require_router_readonly || preflight_errors=$((preflight_errors + 1))

  for required_command in opkg awk sed grep tr sort mktemp cp mv rm find ls dirname ip; do
    if ! have "$required_command"; then
      echo "ERROR: required command not found: $required_command" >&2
      preflight_errors=$((preflight_errors + 1))
    fi
  done

  if [ "$STANDALONE_ZAPRET" -eq 0 ] && ! have xkeen; then
    echo "ERROR: xkeen command not found." >&2
    preflight_errors=$((preflight_errors + 1))
  fi
  if [ "$STANDALONE_ZAPRET" -eq 0 ] && ! have jq; then
    echo "ERROR: jq is required to patch and validate routing safely." >&2
    preflight_errors=$((preflight_errors + 1))
  fi
  if [ "$DISCORD_VOICE_ROUTE_MODE" = "zapret" ] &&
     ! verify_discord_udp_blob_source; then
    preflight_errors=$((preflight_errors + 1))
  fi
  if [ -z "$TEST_ROOT" ] && package_present wget-ssl; then
    if ! have wget || ! wget --version 2>&1 | grep -q '+https'; then
      echo "ERROR: wget-ssl is installed but an HTTPS-capable wget is not first in PATH." >&2
      echo "       Expected /opt/bin/wget before /opt/usr/bin/busybox wget." >&2
      preflight_errors=$((preflight_errors + 1))
    fi
  fi
  if [ "$STANDALONE_ZAPRET" -eq 0 ] && [ ! -f "$XKEEN_INIT" ]; then
    echo "ERROR: XKeen init file not found: $XKEEN_INIT" >&2
    preflight_errors=$((preflight_errors + 1))
  fi

  if [ "$preflight_errors" -eq 0 ]; then
    detect_core || preflight_errors=$((preflight_errors + 1))
  fi

  if [ "$preflight_errors" -eq 0 ]; then
    case "$DETECTED_CORE" in
      xray)
        if [ ! -d "$XRAY_CONFIG_DIR" ]; then
          echo "ERROR: Xray config directory not found: $XRAY_CONFIG_DIR" >&2
          preflight_errors=$((preflight_errors + 1))
        elif { any_route_is direct || any_route_is zapret; } &&
             ! resolve_xray_direct_mark; then
          preflight_errors=$((preflight_errors + 1))
        elif { [ "$DISCORD_TCP_ROUTE_MODE" = "vless" ] ||
               [ "$YOUTUBE_ROUTE_MODE" = "vless" ] ||
               [ "$TELEGRAM_ROUTE_MODE" = "vless" ]; } &&
             ! resolve_xray_proxy_outbound; then
          preflight_errors=$((preflight_errors + 1))
        elif ! xkeen -xtest >/dev/null 2>&1; then
          echo "ERROR: current Xray configuration fails 'xkeen -xtest'." >&2
          preflight_errors=$((preflight_errors + 1))
        fi
        ;;
      mihomo)
        if [ -n "$DIRECT_MARK_REQUESTED" ]; then
          echo "ERROR: --direct-mark is Xray-only; Mihomo uses routing-mark in its own config." >&2
          preflight_errors=$((preflight_errors + 1))
        fi
        if ! have yq; then
          echo "ERROR: yq is required for Mihomo YAML." >&2
          preflight_errors=$((preflight_errors + 1))
        fi
        if [ ! -f "$MIHOMO_CONFIG" ]; then
          echo "ERROR: Mihomo config not found: $MIHOMO_CONFIG" >&2
          preflight_errors=$((preflight_errors + 1))
        elif ! xkeen -mtest >/dev/null 2>&1; then
          echo "ERROR: current Mihomo configuration fails 'xkeen -mtest'." >&2
          preflight_errors=$((preflight_errors + 1))
        fi
        ;;
      standalone) ;;
    esac
  fi

  if [ "$preflight_errors" -eq 0 ] && ! resolve_wan_interfaces; then
    preflight_errors=$((preflight_errors + 1))
  fi

  if [ -z "$TEST_ROOT" ] &&
     /bin/ndmc -c show ip policy 2>/dev/null |
       grep -Fqi "description = $UNBOUND_POLICY_NAME:"; then
    echo "ERROR: reserved unbound policy name already exists: $UNBOUND_POLICY_NAME" >&2
    echo "       Rename that Keenetic policy before applying this profile." >&2
    preflight_errors=$((preflight_errors + 1))
  fi

  if [ "$STANDALONE_ZAPRET" -eq 0 ]; then
    proxying_ports="$(active_ports "$XKEEN_PORT_PROXYING")"
    excluded_ports="$(active_ports "$XKEEN_PORT_EXCLUDE")"
    if [ -z "$proxying_ports" ] && [ -n "$excluded_ports" ] &&
       ports_overlap "$excluded_ports" "$XKEEN_REQUIRED_PORTS"; then
      echo "ERROR: XKeen port_exclude.lst overlaps required Discord ports." >&2
      echo "       Resolve exclusions manually; the script will not silently weaken them." >&2
      preflight_errors=$((preflight_errors + 1))
    fi
  fi

  if [ "$preflight_errors" -ne 0 ]; then
    echo "Preflight failed with $preflight_errors error(s)." >&2
    return 1
  fi

  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    echo "Preflight OK. Deployment: standalone nfqws2 (XKeen unmanaged)"
  else
    echo "Preflight OK. XKeen core: $DETECTED_CORE"
  fi
  echo "Routes: $(routes_summary)"
  if [ "$DETECTED_CORE" = "xray" ]; then
    echo "Xray discord-direct mark: ${DIRECT_MARK_EFFECTIVE:-none}"
    echo "Xray proxy outbound: ${PROXY_OUTBOUND_EFFECTIVE:-not needed}"
  fi
  echo "nfqws2 WAN interface(s): $WAN_INTERFACE_EFFECTIVE"
  echo "nfqws2 IPv6: $([ "$NFQWS_IPV6_EFFECTIVE" -eq 1 ] && echo enabled || echo disabled)"
  if [ "$STANDALONE_ZAPRET" -eq 0 ]; then
    echo "XKeen settings: mode=$(xkeen_effective_value mode_proxy), policy_mark=$(xkeen_effective_value policy_mark), proxy_dns=$(init_value proxy_dns), proxy_router=$(init_value proxy_router), ipv6_support=$(init_value ipv6_support), dscp_exclude=$(xkeen_effective_value dscp_exclude), dscp_proxy=$(xkeen_effective_value dscp_proxy)"
  fi
}

restore_preflight() {
  restore_preflight_errors=0
  require_router_readonly || restore_preflight_errors=$((restore_preflight_errors + 1))
  for restore_command in opkg awk sed grep cp mv rm find ls dirname; do
    if ! have "$restore_command"; then
      echo "ERROR: required restore command not found: $restore_command" >&2
      restore_preflight_errors=$((restore_preflight_errors + 1))
    fi
  done
  if [ "$restore_preflight_errors" -ne 0 ]; then
    echo "Restore preflight failed with $restore_preflight_errors error(s)." >&2
    return 1
  fi
}

write_snapshot_settings() {
  settings_file="$1"
  : > "$settings_file"
  for settings_key in \
    name_client name_policy name_profile table_id table_mark custom_mark \
    dscp_exclude dscp_proxy \
    ipv4_proxy ipv4_exclude ipv6_proxy ipv6_exclude proxy_dns proxy_router \
    start_attempts start_auto start_delay init_delay \
    check_fd arm64_fd other_fd delay_fd ipv6_support extended_msg backup aghfix
  do
    printf '%s\t%s\n' "$settings_key" "$(init_value "$settings_key")" >> "$settings_file"
  done
}

write_xkeen_runtime_settings() {
  runtime_settings_file="$1"
  : > "$runtime_settings_file"
  for runtime_settings_key in \
    name_client name_profile mode_proxy network_redirect network_tproxy networks \
    port_redirect port_tproxy port_donor port_exclude policy_mark custom_mark \
    dscp_exclude dscp_proxy table_mark table_id file_dns proxy_dns proxy_router \
    iptables_supported ip6tables_supported ipv4_proxy ipv6_proxy
  do
    printf '%s\t%s\n' \
      "$runtime_settings_key" \
      "$(runtime_value "$runtime_settings_key")" >> "$runtime_settings_file"
  done
}

write_package_state() {
  packages_file="$1"
  : > "$packages_file"
  for package_name in ca-certificates jq wget-ssl wget-nossl nfqws2-keenetic; do
    package_ver="$(package_version "$package_name" || true)"
    if [ -n "$package_ver" ]; then
      printf '%s\tPRESENT\t%s\n' "$package_name" "$package_ver" >> "$packages_file"
    else
      printf '%s\tABSENT\t-\n' "$package_name" >> "$packages_file"
    fi
  done
}

write_full_package_inventory() {
  inventory_file="$1"
  if have opkg; then
    opkg list-installed 2>/dev/null | sort > "$inventory_file" || true
  else
    : > "$inventory_file"
  fi
}

write_runtime_state() {
  runtime_file="$1"
  {
    if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
      printf 'XKEEN_RUNNING\tUNMANAGED\n'
    elif process_running xray || process_running mihomo; then
      printf 'XKEEN_RUNNING\t1\n'
    else
      printf 'XKEEN_RUNNING\t0\n'
    fi
    if nfqws_running; then
      printf 'NFQWS_RUNNING\t1\n'
    else
      printf 'NFQWS_RUNNING\t0\n'
    fi
  } > "$runtime_file"
}

write_ipv6_runtime() {
  ipv6_file="$1"
  if [ -n "$TEST_ROOT" ]; then
    : > "$ipv6_file"
    return
  fi
  if have sysctl; then
    sysctl -a 2>/dev/null |
      grep '^net\.ipv6\.conf\..*\.disable_ipv6[[:space:]]*=' > "$ipv6_file" || true
  else
    : > "$ipv6_file"
  fi
}

write_readonly_audit() {
  audit_file="$1"
  {
    echo "script_version=$SCRIPT_VERSION"
    echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
    echo "uname=$(uname -a 2>/dev/null || true)"
    echo
    echo "== opkg architecture =="
    opkg print-architecture 2>&1 || true
    if [ -z "$TEST_ROOT" ]; then
      echo
      echo "== Keenetic version =="
      /bin/ndmc -c show version 2>&1 || true
    fi
    if [ "$STANDALONE_ZAPRET" -eq 0 ]; then
      echo
      echo "== xkeen -v =="
      xkeen -v 2>&1 || true
      echo
      echo "== xkeen -status =="
      xkeen -status 2>&1 || true
      echo
      echo "== xkeen -cp =="
      xkeen -cp 2>&1 || true
      echo
      echo "== xkeen -cpe =="
      xkeen -cpe 2>&1 || true
      echo
      echo "== xkeen -tp =="
      xkeen -tp 2>&1 || true
      echo
      echo "== XKeen effective runtime hook =="
      for audit_key in \
        mode_proxy port_redirect port_tproxy port_donor port_exclude \
        policy_mark custom_mark dscp_exclude dscp_proxy file_dns \
        proxy_dns proxy_router iptables_supported ip6tables_supported
      do
        printf '%s=%s\n' "$audit_key" "$(runtime_value "$audit_key")"
      done
    else
      echo
      echo "XKeen scope: unmanaged (standalone nfqws2 deployment)"
    fi
    if [ -z "$TEST_ROOT" ]; then
      echo
      echo "== policy routing rules =="
      ip -4 rule show 2>&1 || true
      ip -6 rule show 2>&1 || true
    fi
  } > "$audit_file"
}

create_snapshot() {
  snapshot_purpose="$1"
  umask 077
  mkdir -p "$SNAPSHOT_ROOT"
  chmod 700 "$STATE_ROOT" "$SNAPSHOT_ROOT"

  snapshot_stamp="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown)"
  snapshot_dir="$SNAPSHOT_ROOT/${snapshot_stamp}-$$"
  snapshot_counter=0
  while [ -e "$snapshot_dir" ]; do
    snapshot_counter=$((snapshot_counter + 1))
    snapshot_dir="$SNAPSHOT_ROOT/${snapshot_stamp}-$$-$snapshot_counter"
  done
  mkdir "$snapshot_dir"
  mkdir "$snapshot_dir/files"

  {
    printf 'FORMAT\t1\n'
    printf 'SCOPE\t%s\n' "$(current_snapshot_scope)"
    printf 'PURPOSE\t%s\n' "$snapshot_purpose"
    printf 'SCRIPT_VERSION\t%s\n' "$SCRIPT_VERSION"
    printf 'CREATED_UTC\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
  } > "$snapshot_dir/STATE.tsv"

  : > "$snapshot_dir/MANIFEST"
  managed_paths "$(current_snapshot_scope)" | while IFS= read -r logical_path; do
    actual_path="$(root_path "$logical_path")"
    snapshot_copy="$snapshot_dir/files$logical_path"
    if path_exists "$actual_path"; then
      mkdir -p "$(dirname "$snapshot_copy")"
      cp -a "$actual_path" "$snapshot_copy" || {
        echo "ERROR: cannot snapshot managed path: $actual_path" >&2
        exit 1
      }
      printf '%s|PRESENT\n' "$logical_path"
    else
      printf '%s|ABSENT\n' "$logical_path"
    fi
  done > "$snapshot_dir/MANIFEST"

  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    : > "$snapshot_dir/XKEEN_SETTINGS.tsv"
    : > "$snapshot_dir/XKEEN_RUNTIME_SETTINGS.tsv"
  else
    write_snapshot_settings "$snapshot_dir/XKEEN_SETTINGS.tsv"
    write_xkeen_runtime_settings "$snapshot_dir/XKEEN_RUNTIME_SETTINGS.tsv"
  fi
  write_package_state "$snapshot_dir/PACKAGES.tsv"
  write_full_package_inventory "$snapshot_dir/OPKG_INSTALLED.txt"
  write_runtime_state "$snapshot_dir/RUNTIME.tsv"
  write_ipv6_runtime "$snapshot_dir/IPV6_RUNTIME.txt"
  write_readonly_audit "$snapshot_dir/READONLY_AUDIT.txt"

  if have sha256sum; then
    (
      cd "$snapshot_dir/files"
      find . -type f -exec sha256sum '{}' ';' | sort > "$snapshot_dir/CHECKSUMS.sha256"
    )
  else
    echo "WARNING: sha256sum is unavailable; snapshot has no content checksums." >&2
  fi

  CREATED_SNAPSHOT="$snapshot_dir"
  echo "Snapshot created: $snapshot_dir"
}

verify_snapshot() {
  verify_dir="$1"
  safe_snapshot_path "$verify_dir" || {
    echo "ERROR: unsafe or missing snapshot: $verify_dir" >&2
    return 1
  }
  [ -f "$verify_dir/MANIFEST" ] || {
    echo "ERROR: snapshot manifest is missing: $verify_dir" >&2
    return 1
  }

  verify_scope="$(snapshot_scope "$verify_dir")" || return 1
  for expected_path in $(managed_paths "$verify_scope"); do
    grep -Fq "${expected_path}|" "$verify_dir/MANIFEST" || {
      echo "ERROR: snapshot manifest is incomplete: $expected_path" >&2
      return 1
    }
  done

  while IFS='|' read -r verify_path verify_status; do
    is_managed_path "$verify_path" "$verify_scope" || {
      echo "ERROR: snapshot contains unmanaged path: $verify_path" >&2
      return 1
    }
    case "$verify_status" in
      PRESENT)
        path_exists "$verify_dir/files$verify_path" || {
          echo "ERROR: snapshot content is missing: $verify_path" >&2
          return 1
        }
        ;;
      ABSENT) ;;
      *)
        echo "ERROR: invalid manifest state for $verify_path" >&2
        return 1
        ;;
    esac
  done < "$verify_dir/MANIFEST"

  if [ -f "$verify_dir/CHECKSUMS.sha256" ]; then
    if [ -s "$verify_dir/CHECKSUMS.sha256" ]; then
      have sha256sum || {
        echo "ERROR: sha256sum is required to verify this snapshot." >&2
        return 1
      }
      (
        cd "$verify_dir/files"
        sha256sum -c "$verify_dir/CHECKSUMS.sha256" >/dev/null
      ) || {
        echo "ERROR: snapshot checksum verification failed." >&2
        return 1
      }
    elif find "$verify_dir/files" -type f | grep -q .; then
      echo "ERROR: snapshot checksums are empty but snapshot files exist." >&2
      return 1
    fi
  fi
}

state_value() {
  state_file="$1"
  state_key="$2"
  awk -F '\t' -v wanted="$state_key" '$1 == wanted { print $2; exit }' "$state_file"
}

stop_services_for_restore() {
  restore_stop_scope="${1:-integrated}"
  [ ! -x "$NFQWS_INIT" ] || run_nfqws_init stop >/dev/null 2>&1 || true
  if [ "$restore_stop_scope" = "integrated" ]; then
    [ ! -x "$XKEEN_INIT" ] || "$XKEEN_INIT" stop >/dev/null 2>&1 || true
  fi
}

restore_packages() {
  restore_packages_file="$1"
  restore_package_errors=0
  have opkg || {
    echo "ERROR: opkg unavailable; cannot restore package state." >&2
    return 1
  }

  while IFS="$(printf '\t')" read -r restore_pkg restore_presence restore_version; do
    current_version="$(package_version "$restore_pkg" || true)"
    if [ "$restore_presence" = "ABSENT" ] && [ -n "$current_version" ]; then
      echo "Removing package added by this project: $restore_pkg"
      opkg remove "$restore_pkg" >/dev/null 2>&1 || restore_package_errors=1
    fi
  done < "$restore_packages_file"

  while IFS="$(printf '\t')" read -r restore_pkg restore_presence restore_version; do
    current_version="$(package_version "$restore_pkg" || true)"
    if [ "$restore_presence" = "PRESENT" ] && [ -z "$current_version" ]; then
      echo "Reinstalling baseline package: $restore_pkg"
      opkg install "$restore_pkg" >/dev/null 2>&1 || restore_package_errors=1
      current_version="$(package_version "$restore_pkg" || true)"
    fi
    # opkg cannot install an older version from the feed, so an upgrade made
    # after the snapshot is reported but is not a restore failure: failing
    # here would make the automatic rollback undo the requested restore.
    if [ "$restore_presence" = "PRESENT" ] && [ -n "$current_version" ] &&
       [ "$current_version" != "$restore_version" ]; then
      echo "WARNING: $restore_pkg version is $current_version; snapshot has $restore_version." >&2
      echo "         opkg cannot downgrade it; the package stays at $current_version." >&2
    fi
  done < "$restore_packages_file"

  return "$restore_package_errors"
}

# nfqws2 data that profiles and routes change. Everything else under
# /opt/etc/nfqws2 (lua/, nfqws2.conf-opkg...) belongs to the package.
NFQWS_DATA_ITEMS="nfqws2.conf lists blobs imported-profiles profile-versions"

# restore_nfqws_data SOURCE_DIR TARGET_DIR: replace only the data items, so
# the installed package's Lua scripts stay matched to its binary.
restore_nfqws_data() {
  for nfqws_item in $NFQWS_DATA_ITEMS; do
    if path_exists "$2/$nfqws_item"; then
      rm -rf "${2:?}/$nfqws_item" || return 1
    fi
    if path_exists "$1/$nfqws_item"; then
      cp -a "$1/$nfqws_item" "$2/$nfqws_item" || return 1
    fi
  done
}

# Prints the nfqws2-keenetic version a snapshot recorded when the installed
# package differs from it (opkg upgraded after the snapshot), else nothing.
nfqws_package_drift() {
  drift_snapshot_version="$(
    awk -F '\t' '$1 == "nfqws2-keenetic" && $2 == "PRESENT" { print $3 }' "$1/PACKAGES.tsv"
  )"
  drift_current_version="$(package_version nfqws2-keenetic || true)"
  if [ -n "$drift_snapshot_version" ] && [ -n "$drift_current_version" ] &&
     [ "$drift_snapshot_version" != "$drift_current_version" ]; then
    printf '%s\n' "$drift_snapshot_version"
  fi
}

restore_files() {
  restore_dir="$1"
  restore_scope="$(snapshot_scope "$restore_dir")" || return 1
  restore_file_errors=0
  # The Lua scripts must match the nfqws2 binary (NFQWS2_COMPAT_VER), and the
  # binary is not part of a snapshot. After a package upgrade only the data is
  # restored; the package's own files stay at the installed version.
  restore_nfqws_drift="$(nfqws_package_drift "$restore_dir")"
  if [ -n "$restore_nfqws_drift" ]; then
    echo "nfqws2-keenetic $(package_version nfqws2-keenetic) is installed; snapshot has $restore_nfqws_drift."
    echo "Restoring nfqws2 configuration, lists and blobs only; package files are kept."
  fi
  managed_paths "$restore_scope" | while IFS= read -r restore_logical; do
    restore_record="$(grep -F "${restore_logical}|" "$restore_dir/MANIFEST" | sed -n '1p')"
    if [ -z "$restore_record" ]; then
      echo "ERROR: manifest has no record for $restore_logical" >&2
      exit 1
    fi
    restore_presence="${restore_record#*|}"
    restore_actual="$(root_path "$restore_logical")"
    restore_source="$restore_dir/files$restore_logical"

    if [ -n "$restore_nfqws_drift" ]; then
      case "$restore_logical" in
        /opt/etc/init.d/S51nfqws2|/opt/etc/ndm/netfilter.d/100-nfqws2.sh)
          continue
          ;;
        /opt/etc/nfqws2)
          if [ "$restore_presence" = "PRESENT" ] && [ -d "$restore_actual" ]; then
            restore_nfqws_data "$restore_source" "$restore_actual" || {
              echo "ERROR: cannot restore nfqws2 data: $restore_actual" >&2
              exit 1
            }
            continue
          fi
          ;;
      esac
    fi

    if path_exists "$restore_actual"; then
      rm -rf "$restore_actual" || {
        echo "ERROR: cannot remove managed path during restore: $restore_actual" >&2
        exit 1
      }
    fi
    if [ "$restore_presence" = "PRESENT" ]; then
      mkdir -p "$(dirname "$restore_actual")" || exit 1
      cp -a "$restore_source" "$restore_actual" || {
        echo "ERROR: cannot restore managed path: $restore_actual" >&2
        exit 1
      }
    fi
  done || restore_file_errors=1
  return "$restore_file_errors"
}

restore_ipv6_runtime() {
  ipv6_state_file="$1"
  [ -z "$TEST_ROOT" ] || return 0
  [ -s "$ipv6_state_file" ] || return 0
  have sysctl || {
    echo "ERROR: sysctl is unavailable; IPv6 runtime cannot be restored." >&2
    return 1
  }
  ipv6_restore_errors=0

  while IFS='=' read -r ipv6_key ipv6_value; do
    ipv6_key="$(printf '%s' "$ipv6_key" | tr -d '[:space:]')"
    ipv6_value="$(printf '%s' "$ipv6_value" | tr -d '[:space:]')"
    case "$ipv6_key:$ipv6_value" in
      net.ipv6.conf.*.disable_ipv6:0|net.ipv6.conf.*.disable_ipv6:1)
        if sysctl -n "$ipv6_key" >/dev/null 2>&1; then
          sysctl -w "$ipv6_key=$ipv6_value" >/dev/null 2>&1 ||
            ipv6_restore_errors=1
        fi
        ;;
    esac
  done < "$ipv6_state_file"
  return "$ipv6_restore_errors"
}

restore_services() {
  runtime_file="$1"
  restore_service_scope="$2"
  baseline_xkeen_running="$(state_value "$runtime_file" XKEEN_RUNNING)"
  baseline_nfqws_running="$(state_value "$runtime_file" NFQWS_RUNNING)"

  if [ "$restore_service_scope" = "integrated" ]; then
    if [ "$baseline_xkeen_running" = "1" ]; then
      if [ -x "$XKEEN_INIT" ]; then
        "$XKEEN_INIT" start on >/dev/null 2>&1 ||
          "$XKEEN_INIT" start >/dev/null 2>&1 || return 1
      else
        echo "ERROR: cannot restore running XKeen service; init script is absent." >&2
        return 1
      fi
      restored_core="$(init_value name_client)"
      case "$restored_core" in
        xray|mihomo)
          process_running "$restored_core" || {
            echo "ERROR: restored XKeen core is not running: $restored_core" >&2
            return 1
          }
          ;;
        *)
          echo "ERROR: restored XKeen core is unknown: $restored_core" >&2
          return 1
          ;;
      esac
    else
      [ ! -x "$XKEEN_INIT" ] || "$XKEEN_INIT" stop >/dev/null 2>&1 || true
      if process_running xray || process_running mihomo; then
        echo "ERROR: XKeen core is still running after restoring stopped state." >&2
        return 1
      fi
    fi
  fi

  if [ "$baseline_nfqws_running" = "1" ]; then
    if [ -x "$NFQWS_INIT" ]; then
      run_nfqws_init start >/dev/null 2>&1 || return 1
    else
      echo "ERROR: cannot restore running nfqws2 service; init script is absent." >&2
      return 1
    fi
    nfqws_running || {
      echo "ERROR: nfqws2 is not running after state restore." >&2
      return 1
    }
  else
    [ ! -x "$NFQWS_INIT" ] || run_nfqws_init stop >/dev/null 2>&1 || true
    if nfqws_running; then
      echo "ERROR: nfqws2 is still running after restoring stopped state." >&2
      return 1
    fi
  fi
}

restore_snapshot_internal() {
  restore_snapshot_dir="$1"
  restore_result=0
  verify_snapshot "$restore_snapshot_dir" || return 1
  restore_snapshot_scope="$(snapshot_scope "$restore_snapshot_dir")" || return 1

  echo "Stopping managed services for restore..."
  stop_services_for_restore "$restore_snapshot_scope"
  restore_packages "$restore_snapshot_dir/PACKAGES.tsv" || restore_result=1
  restore_files "$restore_snapshot_dir" || restore_result=1
  restore_services \
    "$restore_snapshot_dir/RUNTIME.tsv" \
    "$restore_snapshot_scope" || restore_result=1
  restore_ipv6_runtime "$restore_snapshot_dir/IPV6_RUNTIME.txt" || restore_result=1

  if [ "$restore_result" -eq 0 ]; then
    echo "Restore complete: $restore_snapshot_dir"
  else
    echo "ERROR: restore completed only partially; inspect messages above." >&2
  fi
  return "$restore_result"
}

safe_import_snapshot_path() {
  import_snapshot="$1"
  case "$import_snapshot" in
    "$IMPORT_SNAPSHOT_ROOT"/*)
      case "$import_snapshot" in
        *"/../"*|*"/.."|*"//"*) return 1 ;;
      esac
      import_snapshot_leaf="${import_snapshot#"$IMPORT_SNAPSHOT_ROOT"/}"
      case "$import_snapshot_leaf" in
        ""|*/*) return 1 ;;
      esac
      ;;
    *) return 1 ;;
  esac
  [ -d "$import_snapshot" ] && [ ! -L "$import_snapshot" ]
}

read_import_pointer() {
  [ -f "$LATEST_IMPORT_POINTER" ] || return 1
  import_pointer_value="$(sed -n '1p' "$LATEST_IMPORT_POINTER")"
  safe_import_snapshot_path "$import_pointer_value" || {
    echo "ERROR: invalid nfqws2 import rollback pointer." >&2
    return 1
  }
  printf '%s\n' "$import_pointer_value"
}

create_nfqws_import_snapshot() {
  import_purpose="$1"
  umask 077
  mkdir -p "$STATE_ROOT" "$IMPORT_SNAPSHOT_ROOT"
  chmod 700 "$STATE_ROOT" "$IMPORT_SNAPSHOT_ROOT"
  import_stamp="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown)"
  import_dir="$IMPORT_SNAPSHOT_ROOT/${import_stamp}-$$"
  import_counter=0
  while [ -e "$import_dir" ]; do
    import_counter=$((import_counter + 1))
    import_dir="$IMPORT_SNAPSHOT_ROOT/${import_stamp}-$$-$import_counter"
  done
  mkdir "$import_dir"

  if nfqws_running; then
    import_nfqws_running=1
  else
    import_nfqws_running=0
  fi
  if path_exists "$(dirname "$NFQWS_CONF")"; then
    import_nfqws_present=1
    cp -a "$(dirname "$NFQWS_CONF")" "$import_dir/nfqws2"
  else
    import_nfqws_present=0
  fi
  {
    printf 'FORMAT\t1\n'
    printf 'PURPOSE\t%s\n' "$import_purpose"
    printf 'SCRIPT_VERSION\t%s\n' "$SCRIPT_VERSION"
    printf 'NFQWS_PRESENT\t%s\n' "$import_nfqws_present"
    printf 'NFQWS_RUNNING\t%s\n' "$import_nfqws_running"
  } > "$import_dir/STATE.tsv"
  if [ "$import_nfqws_present" -eq 1 ]; then
    (
      cd "$import_dir/nfqws2"
      find . -type f -exec sha256sum '{}' ';' | sort > "$import_dir/CHECKSUMS.sha256"
    )
  else
    : > "$import_dir/CHECKSUMS.sha256"
  fi
  NFQWS_IMPORT_BACKUP="$import_dir"
  echo "nfqws2 import snapshot created: $import_dir"
}

verify_nfqws_import_snapshot() {
  verify_import_dir="$1"
  safe_import_snapshot_path "$verify_import_dir" || {
    echo "ERROR: unsafe or missing nfqws2 import snapshot: $verify_import_dir" >&2
    return 1
  }
  [ -f "$verify_import_dir/STATE.tsv" ] &&
    [ -f "$verify_import_dir/CHECKSUMS.sha256" ] || {
      echo "ERROR: nfqws2 import snapshot is incomplete." >&2
      return 1
    }
  verify_import_format="$(state_value "$verify_import_dir/STATE.tsv" FORMAT)"
  verify_import_present="$(state_value "$verify_import_dir/STATE.tsv" NFQWS_PRESENT)"
  verify_import_running="$(state_value "$verify_import_dir/STATE.tsv" NFQWS_RUNNING)"
  [ "$verify_import_format" = "1" ] || return 1
  case "$verify_import_present:$verify_import_running" in
    0:0|0:1|1:0|1:1) ;;
    *) return 1 ;;
  esac
  if [ "$verify_import_present" = "1" ]; then
    [ -d "$verify_import_dir/nfqws2" ] && [ ! -L "$verify_import_dir/nfqws2" ] || return 1
    (
      cd "$verify_import_dir/nfqws2"
      sha256sum -c "$verify_import_dir/CHECKSUMS.sha256" >/dev/null
    ) || {
      echo "ERROR: nfqws2 import snapshot checksum verification failed." >&2
      return 1
    }
  else
    [ ! -e "$verify_import_dir/nfqws2" ] || return 1
  fi
}

restore_nfqws_import_snapshot() {
  restore_import_dir="$1"
  verify_nfqws_import_snapshot "$restore_import_dir" || return 1
  restore_import_present="$(state_value "$restore_import_dir/STATE.tsv" NFQWS_PRESENT)"
  restore_import_running="$(state_value "$restore_import_dir/STATE.tsv" NFQWS_RUNNING)"
  restore_nfqws_dir="$(dirname "$NFQWS_CONF")"

  echo "Restoring nfqws2 files only; XKeen is left untouched..."
  [ ! -x "$NFQWS_INIT" ] || run_nfqws_init stop >/dev/null 2>&1 || true
  case "$restore_nfqws_dir" in
    "$(root_path /opt/etc/nfqws2)") ;;
    *)
      echo "ERROR: refusing unsafe nfqws2 restore target: $restore_nfqws_dir" >&2
      return 1
      ;;
  esac
  # Profile operations change only nfqws2 data. Package files (lua/) are
  # kept: the package may have been upgraded since this snapshot.
  if [ "$restore_import_present" = "1" ] && [ -d "$restore_nfqws_dir" ]; then
    restore_nfqws_data "$restore_import_dir/nfqws2" "$restore_nfqws_dir" || {
      echo "ERROR: cannot restore nfqws2 data: $restore_nfqws_dir" >&2
      return 1
    }
  else
    [ ! -e "$restore_nfqws_dir" ] || rm -rf "$restore_nfqws_dir"
    if [ "$restore_import_present" = "1" ]; then
      mkdir -p "$(dirname "$restore_nfqws_dir")"
      cp -a "$restore_import_dir/nfqws2" "$restore_nfqws_dir"
    fi
  fi

  if [ "$restore_import_running" = "1" ]; then
    [ -x "$NFQWS_INIT" ] || {
      echo "ERROR: nfqws2 init script is missing after restore." >&2
      return 1
    }
    run_nfqws_init start >/dev/null
    nfqws_running || {
      echo "ERROR: nfqws2 did not start after focused restore." >&2
      return 1
    }
  elif nfqws_running; then
    echo "ERROR: nfqws2 is running although the saved state was stopped." >&2
    return 1
  fi
  echo "Focused nfqws2 restore complete: $restore_import_dir"
}

on_exit() {
  exit_code=$?
  trap - 0 HUP INT TERM
  cleanup_tmp

  if [ "$NFQWS_TRANSACTION_ACTIVE" -eq 1 ] &&
     [ "$AUTO_ROLLBACK_IN_PROGRESS" -eq 0 ] &&
     [ -n "$NFQWS_IMPORT_BACKUP" ]; then
    AUTO_ROLLBACK_IN_PROGRESS=1
    echo "ERROR: nfqws2 profile operation failed (exit $exit_code). Rolling back nfqws2 only..." >&2
    set +e
    restore_nfqws_import_snapshot "$NFQWS_IMPORT_BACKUP"
    auto_import_restore_code=$?
    set -e
    if [ "$auto_import_restore_code" -ne 0 ]; then
      echo "CRITICAL: focused nfqws2 rollback was only partial." >&2
      echo "Manual recovery snapshot: $NFQWS_IMPORT_BACKUP" >&2
    fi
  fi

  if [ "$TRANSACTION_ACTIVE" -eq 1 ] &&
     [ "$AUTO_ROLLBACK_IN_PROGRESS" -eq 0 ] &&
     [ -n "$PREAPPLY_SNAPSHOT" ]; then
    AUTO_ROLLBACK_IN_PROGRESS=1
    echo "ERROR: apply failed (exit $exit_code). Starting automatic rollback..." >&2
    set +e
    restore_snapshot_internal "$PREAPPLY_SNAPSHOT"
    auto_restore_code=$?
    set -e
    if [ "$auto_restore_code" -ne 0 ]; then
      echo "CRITICAL: automatic rollback was only partial." >&2
      echo "Manual recovery snapshot: $PREAPPLY_SNAPSHOT" >&2
    fi
  fi

  release_lock
  exit "$exit_code"
}

trap 'exit 130' HUP INT TERM
trap on_exit 0

show_snapshots() {
  require_router_readonly
  echo "State directory: $STATE_ROOT"
  if baseline_snapshot="$(read_pointer "$BASELINE_POINTER" 2>/dev/null)"; then
    echo "Baseline: $baseline_snapshot"
  else
    echo "Baseline: not created"
  fi
  if xkeen_baseline_snapshot="$(read_pointer "$XKEEN_BASELINE_POINTER" 2>/dev/null)"; then
    echo "XKeen baseline: $xkeen_baseline_snapshot"
  fi
  if latest_snapshot="$(read_pointer "$LATEST_POINTER" 2>/dev/null)"; then
    echo "Latest pre-apply: $latest_snapshot"
  else
    echo "Latest pre-apply: not created"
  fi
}

# Reads one service route from the "# Active routes:" line of nfqws2.conf.
# Services: discord-tcp, discord-voice, youtube. The legacy line
# "Discord=X, YouTube=Y." (before the TCP/Voice split) applies X to both
# Discord routes.
recorded_nfqws_route() {
  recorded_service="$1"
  [ -f "$NFQWS_CONF" ] || return 1
  awk -v service="$recorded_service" '
    $1 == "#" && $2 == "Active" && $3 == "routes:" {
      value = ""
      for (field = 4; field <= NF; field++) {
        pair = $field
        sub(/[,.]$/, "", pair)
        split(pair, kv, "=")
        if ((kv[1] == "DiscordTCP" && service == "discord-tcp") ||
            (kv[1] == "DiscordVoice" && service == "discord-voice") ||
            (kv[1] == "Discord" && (service == "discord-tcp" || service == "discord-voice")) ||
            (kv[1] == "YouTube" && service == "youtube")) {
          value = kv[2]
        }
      }
    }
    END {
      if (value == "direct" || value == "zapret" || value == "vless") {
        print value
      } else {
        exit 1
      }
    }
  ' "$NFQWS_CONF"
}

recorded_deployment_mode() {
  [ -f "$NFQWS_CONF" ] || return 1
  recorded_mode="$(
    sed -n 's/^# Deployment mode: \([a-z-]*\)\.$/\1/p' "$NFQWS_CONF" |
      sed -n '1p'
  )"
  case "$recorded_mode" in
    standalone-zapret|xkeen-integrated)
      printf '%s\n' "$recorded_mode"
      ;;
    *) return 1 ;;
  esac
}

load_current_nfqws_context() {
  if [ "$(recorded_deployment_mode 2>/dev/null || true)" = "standalone-zapret" ]; then
    STANDALONE_ZAPRET=1
    DETECTED_CORE="standalone"
  fi
  DISCORD_TCP_ROUTE_MODE="$(recorded_nfqws_route discord-tcp 2>/dev/null || true)"
  DISCORD_VOICE_ROUTE_MODE="$(recorded_nfqws_route discord-voice 2>/dev/null || true)"
  YOUTUBE_ROUTE_MODE="$(recorded_nfqws_route youtube 2>/dev/null || true)"
  for current_route in \
    "$DISCORD_TCP_ROUTE_MODE" "$DISCORD_VOICE_ROUTE_MODE" "$YOUTUBE_ROUTE_MODE"
  do
    case "$current_route" in
      direct|zapret|vless) ;;
      *)
        echo "ERROR: current managed Discord/YouTube routes cannot be determined." >&2
        echo "       Apply a normal route mode once before importing a profile." >&2
        return 1
        ;;
    esac
  done

  TELEGRAM_ROUTE_MODE="$(recorded_telegram_route)"
  recorded_udp_settings
  UDP_STRATEGY="$RECORDED_UDP_STRATEGY"
  if [ "$RECORDED_UDP_RANGE" = "wide" ]; then
    WIDE_UDP=1
    VOICE_HIGH=65535
  else
    WIDE_UDP=0
    VOICE_HIGH=50100
  fi
  set_xkeen_required_ports
}

# Sets RECORDED_UDP_STRATEGY (flowseal|legacy) and RECORDED_UDP_RANGE
# (narrow|wide) from the "# Discord UDP:" line of nfqws2.conf. Configs written
# before that line existed are inferred from UDP_PORTS and the blob argument,
# which is only reliable while Discord Voice uses zapret.
recorded_udp_settings() {
  RECORDED_UDP_STRATEGY=""
  RECORDED_UDP_RANGE=""
  if [ -f "$NFQWS_CONF" ]; then
    recorded_udp_line="$(
      sed -n 's/^# Discord UDP: strategy=\([a-z]*\), range=\([a-z]*\)\.$/\1 \2/p' "$NFQWS_CONF" |
        sed -n '1p'
    )"
    case "$recorded_udp_line" in
      "flowseal narrow"|"flowseal wide"|"legacy narrow"|"legacy wide")
        RECORDED_UDP_STRATEGY="${recorded_udp_line% *}"
        RECORDED_UDP_RANGE="${recorded_udp_line#* }"
        return 0
        ;;
    esac
  fi
  case "$(nfqws_value UDP_PORTS 2>/dev/null || true)" in
    *50000:65535*|*50000-65535*) RECORDED_UDP_RANGE=wide ;;
    *) RECORDED_UDP_RANGE=narrow ;;
  esac
  if grep -Fq -- '--blob=discord_udp:' "$NFQWS_CONF" 2>/dev/null; then
    RECORDED_UDP_STRATEGY=flowseal
  else
    RECORDED_UDP_STRATEGY=legacy
  fi
}

active_imported_profile() {
  active_profile_service="$1"
  active_profile_file="$(imported_profile_path "$active_profile_service")" || return 1
  [ -e "$active_profile_file" ] || return 1
  validate_imported_profile "$active_profile_file" || {
    echo "ERROR: stored imported profile is invalid: $active_profile_file" >&2
    return 2
  }
  printf '%s\n' "$active_profile_file"
}

status_report() {
  require_router_readonly
  if [ "$(recorded_deployment_mode 2>/dev/null || true)" = "standalone-zapret" ]; then
    STANDALONE_ZAPRET=1
  fi
  detect_core || true
  reported_discord_tcp_route="unknown"
  reported_discord_voice_route="unknown"
  reported_youtube_route="unknown"
  recorded_discord_tcp_route="$(recorded_nfqws_route discord-tcp 2>/dev/null || true)"
  recorded_discord_voice_route="$(recorded_nfqws_route discord-voice 2>/dev/null || true)"
  recorded_youtube_route="$(recorded_nfqws_route youtube 2>/dev/null || true)"
  if [ "$DETECTED_CORE" = "xray" ] && have jq; then
    if reported_routing="$(find_xray_routing_file 2>/dev/null)"; then
      if strict_json_stream "$reported_routing" |
           jq -e 'any(.routing.rules[]?;
             .outboundTag == "discord-direct"
             and ((.domain // []) | length) > 0)' >/dev/null 2>&1; then
        case "$recorded_discord_tcp_route" in
          zapret|direct) reported_discord_tcp_route="$recorded_discord_tcp_route" ;;
          *) reported_discord_tcp_route="direct" ;;
        esac
      else
        reported_discord_tcp_route="vless"
      fi
      if strict_json_stream "$reported_routing" |
           jq -e 'any(.routing.rules[]?;
             .outboundTag == "discord-direct"
             and .network == "udp"
             and ((.domain // []) | length) == 0)' >/dev/null 2>&1; then
        case "$recorded_discord_voice_route" in
          zapret|direct) reported_discord_voice_route="$recorded_discord_voice_route" ;;
          *) reported_discord_voice_route="direct" ;;
        esac
      else
        reported_discord_voice_route="vless"
      fi
      if strict_json_stream "$reported_routing" |
           jq -e 'any(.routing.rules[]?;
             .outboundTag == "youtube-direct")' >/dev/null 2>&1; then
        case "$recorded_youtube_route" in
          zapret|direct) reported_youtube_route="$recorded_youtube_route" ;;
          *) reported_youtube_route="direct" ;;
        esac
      else
        reported_youtube_route="vless"
      fi
    fi
  else
    case "$recorded_discord_tcp_route" in
      direct|zapret|vless) reported_discord_tcp_route="$recorded_discord_tcp_route" ;;
    esac
    case "$recorded_discord_voice_route" in
      direct|zapret|vless) reported_discord_voice_route="$recorded_discord_voice_route" ;;
    esac
    case "$recorded_youtube_route" in
      direct|zapret|vless) reported_youtube_route="$recorded_youtube_route" ;;
    esac
  fi
  echo "project=$PROJECT"
  echo "script_version=$SCRIPT_VERSION"
  echo "deployment_mode=$(recorded_deployment_mode 2>/dev/null || current_snapshot_scope)"
  echo "detected_core=${DETECTED_CORE:-unknown}"
  # discord_route is kept for older readers: it is "mixed" when TCP and
  # Voice use different routes.
  if [ "$reported_discord_tcp_route" = "$reported_discord_voice_route" ]; then
    echo "discord_route=$reported_discord_tcp_route"
  else
    echo "discord_route=mixed"
  fi
  echo "discord_tcp_route=$reported_discord_tcp_route"
  echo "discord_voice_route=$reported_discord_voice_route"
  reported_telegram_route="$(recorded_telegram_route)"
  if [ "$DETECTED_CORE" = "xray" ] && have jq &&
     telegram_routing="$(find_xray_routing_file 2>/dev/null)"; then
    telegram_outbound="$(
      strict_json_stream "$telegram_routing" |
        jq -r '[.routing.rules[]? | select(.ruleTag? == "kdn-telegram") | .outboundTag]
               | if length > 0 then .[0] else "" end' 2>/dev/null || true
    )"
    case "$telegram_outbound" in
      "") reported_telegram_route="unmanaged" ;;
      telegram-direct)
        case "$reported_telegram_route" in
          direct|zapret) ;;
          *) reported_telegram_route="direct" ;;
        esac
        ;;
      *) reported_telegram_route="vless" ;;
    esac
  fi
  echo "telegram_route=$reported_telegram_route"
  if [ -f "$NFQWS_CONF" ]; then
    recorded_udp_settings
    echo "udp_strategy=$RECORDED_UDP_STRATEGY"
    echo "udp_range=$RECORDED_UDP_RANGE"
  else
    echo "udp_strategy=unknown"
    echo "udp_range=unknown"
  fi
  echo "youtube_route=$reported_youtube_route"
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    echo "proxy_dns=unmanaged"
    echo "proxy_router=unmanaged"
    echo "ipv6_support=route-detected"
    echo "mode_proxy=unmanaged"
    echo "policy_mark=unmanaged"
    echo "dscp_exclude=unmanaged"
    echo "dscp_proxy=unmanaged"
    echo "start_auto=unmanaged"
    echo "table_mark=unmanaged"
    echo "custom_mark=unmanaged"
    echo "xkeen_port_proxying=unmanaged"
    echo "xkeen_port_exclude=unmanaged"
  else
    echo "proxy_dns=$(init_value proxy_dns)"
    echo "proxy_router=$(init_value proxy_router)"
    echo "ipv6_support=$(init_value ipv6_support)"
    echo "mode_proxy=$(xkeen_effective_value mode_proxy)"
    echo "policy_mark=$(xkeen_effective_value policy_mark)"
    echo "dscp_exclude=$(xkeen_effective_value dscp_exclude)"
    echo "dscp_proxy=$(xkeen_effective_value dscp_proxy)"
    echo "start_auto=$(init_value start_auto)"
    echo "table_mark=$(init_value table_mark)"
    echo "custom_mark=$(init_value custom_mark)"
    echo "xkeen_port_proxying=$(active_ports "$XKEEN_PORT_PROXYING")"
    echo "xkeen_port_exclude=$(active_ports "$XKEEN_PORT_EXCLUDE")"
  fi
  echo "nfqws_package=$(package_version nfqws2-keenetic || true)"
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    echo "xkeen_runtime=unmanaged"
  elif process_running xray || process_running mihomo; then
    echo "xkeen_runtime=running"
  else
    echo "xkeen_runtime=stopped"
  fi
  if nfqws_running; then
    echo "nfqws_runtime=running"
  else
    echo "nfqws_runtime=stopped"
  fi
  show_snapshots
  if [ "$STANDALONE_ZAPRET" -eq 0 ] && have xkeen; then
    echo
    xkeen -status 2>/dev/null || true
    xkeen -cp 2>/dev/null || true
    xkeen -cpe 2>/dev/null || true
    xkeen -tp 2>/dev/null || true
  fi
}

strict_json_copy() {
  json_input="$1"
  json_output="$2"
  strict_json_stream "$json_input" > "$json_output"
  jq -e . "$json_output" >/dev/null
}

# Prints a JSONC file as plain JSON: removes // and /* */ comments while
# leaving comment-like text inside strings untouched.
strict_json_stream() {
  stream_json_input="$1"
  awk '
    BEGIN { block = 0 }
    {
      line = $0
      out = ""
      in_string = 0
      escaped = 0
      i = 1
      n = length(line)
      while (i <= n) {
        c = substr(line, i, 1)
        pair = substr(line, i, 2)
        if (block) {
          if (pair == "*/") { block = 0; i += 2 } else { i++ }
          continue
        }
        if (in_string) {
          out = out c
          if (escaped) {
            escaped = 0
          } else if (c == "\\") {
            escaped = 1
          } else if (c == "\"") {
            in_string = 0
          }
          i++
          continue
        }
        if (pair == "//") break
        if (pair == "/*") { block = 1; i += 2; continue }
        if (c == "\"") in_string = 1
        out = out c
        i++
      }
      if (out !~ /^[[:space:]]*$/ || line ~ /^[[:space:]]*$/) print out
    }
  ' "$stream_json_input"
}

file_mode() {
  mode_target="$1"
  mode_string="$(
    LC_ALL=C ls -ld "$mode_target" 2>/dev/null |
      awk 'NR == 1 { print substr($1, 2, 9); exit }'
  )"
  [ "${#mode_string}" -eq 9 ] || return 1
  awk -v perms="$mode_string" '
    function has(pos, chars) {
      return index(chars, substr(perms, pos, 1)) > 0
    }
    BEGIN {
      special = (has(3, "sS") ? 4 : 0) +
                (has(6, "sS") ? 2 : 0) +
                (has(9, "tT") ? 1 : 0)
      user = (has(1, "r") ? 4 : 0) +
             (has(2, "w") ? 2 : 0) +
             (has(3, "xs") ? 1 : 0)
      group = (has(4, "r") ? 4 : 0) +
              (has(5, "w") ? 2 : 0) +
              (has(6, "xs") ? 1 : 0)
      other = (has(7, "r") ? 4 : 0) +
              (has(8, "w") ? 2 : 0) +
              (has(9, "xt") ? 1 : 0)
      printf "%d%d%d%d\n", special, user, group, other
    }
  '
}

replace_preserving_mode() {
  replace_target="$1"
  replace_source="$2"
  replace_mode="$(file_mode "$replace_target" 2>/dev/null || echo 0600)"
  atomic_replace_file "$replace_target" "$replace_source" "$replace_mode"
}

atomic_replace_file() {
  atomic_target="$1"
  atomic_source="$2"
  atomic_mode="$3"
  atomic_dir="$(dirname "$atomic_target")"
  mkdir -p "$atomic_dir"
  atomic_stage="$(mktemp "$atomic_dir/.kdtxn-$$-XXXXXX")"
  cp "$atomic_source" "$atomic_stage"
  chmod "$atomic_mode" "$atomic_stage"
  mv "$atomic_stage" "$atomic_target"
}

find_xray_routing_file() {
  active_routing=""
  for routing_candidate in "$XRAY_CONFIG_DIR"/*.json; do
    [ -f "$routing_candidate" ] || continue
    routing_probe="$(make_tmp)"
    if strict_json_copy "$routing_candidate" "$routing_probe" 2>/dev/null &&
       jq -e '.routing | type == "object"' "$routing_probe" >/dev/null 2>&1; then
      # Xray reads confdir files in filename order. Keep the last routing
      # object because a later top-level object overrides an earlier one.
      active_routing="$routing_candidate"
    fi
  done
  [ -n "$active_routing" ] || return 1
  printf '%s\n' "$active_routing"
}

xray_outbound_tag_exists() {
  searched_tag="$1"
  for searched_file in "$XRAY_CONFIG_DIR"/*.json; do
    [ -f "$searched_file" ] || continue
    strict_json_stream "$searched_file" 2>/dev/null |
      jq -e --arg tag "$searched_tag" \
        'any(.outbounds[]?; .tag == $tag)' >/dev/null 2>&1 &&
      return 0
  done
  return 1
}

discover_xray_proxy_outbound() {
  discovery_routing="$(find_xray_routing_file)" || return 1
  discovered_from_youtube="$(
    strict_json_stream "$discovery_routing" |
      jq -r '
      [
        .routing.rules[]?
        | select(.outboundTag? != null)
        | select(
            .outboundTag != "discord-direct"
            and .outboundTag != "youtube-direct"
            and .outboundTag != "direct"
            and .outboundTag != "block"
          )
        | select(any(.domain[]?;
            type == "string" and (ascii_downcase | contains("youtube"))
          ))
        | .outboundTag
      ]
      | if length > 0 then .[0] else empty end
    '
  )"
  if [ -n "$discovered_from_youtube" ]; then
    printf '%s\n' "$discovered_from_youtube"
    return 0
  fi

  discovered_candidates="$(
    for discovery_file in "$XRAY_CONFIG_DIR"/*.json; do
      [ -f "$discovery_file" ] || continue
      strict_json_stream "$discovery_file" 2>/dev/null |
        jq -r '
          .outbounds[]?
          | select(
              .protocol != "freedom"
              and .protocol != "blackhole"
              and .protocol != "dns"
              and .protocol != "loopback"
            )
          | .tag // empty
        ' 2>/dev/null || true
    done | sort -u
  )"
  discovered_count="$(
    printf '%s\n' "$discovered_candidates" |
      awk 'NF { count++ } END { print count + 0 }'
  )"
  [ "$discovered_count" -eq 1 ] || return 1
  printf '%s\n' "$discovered_candidates" | awk 'NF { print; exit }'
}

resolve_xray_proxy_outbound() {
  PROXY_OUTBOUND_EFFECTIVE="$PROXY_OUTBOUND_REQUESTED"
  if [ -z "$PROXY_OUTBOUND_EFFECTIVE" ]; then
    PROXY_OUTBOUND_EFFECTIVE="$(discover_xray_proxy_outbound 2>/dev/null || true)"
  fi
  [ -n "$PROXY_OUTBOUND_EFFECTIVE" ] || {
    echo "ERROR: cannot detect the Xray proxy outbound for vless routing." >&2
    echo "       Pass it explicitly with --proxy-outbound TAG." >&2
    return 1
  }
  xray_outbound_tag_exists "$PROXY_OUTBOUND_EFFECTIVE" || {
    echo "ERROR: Xray outbound tag not found: $PROXY_OUTBOUND_EFFECTIVE" >&2
    return 1
  }
}

valid_decimal_mark() {
  candidate_mark="$1"
  case "$candidate_mark" in
    ''|*[!0-9]*) return 1 ;;
  esac
  awk -v mark="$candidate_mark" 'BEGIN { exit !(mark >= 1 && mark <= 4294967295) }'
}

find_existing_xray_freedom_mark() {
  existing_freedom_mark=""
  for mark_file in "$XRAY_CONFIG_DIR"/*.json; do
    [ -f "$mark_file" ] || continue
    candidate_freedom_mark="$(
      strict_json_stream "$mark_file" 2>/dev/null |
        jq -r '
          [
            .outbounds[]?
            | select(.protocol == "freedom")
            | (.streamSettings.sockopt.mark // empty)
          ]
          | if length > 0 then .[-1] else empty end
        ' 2>/dev/null || true
    )"
    [ -z "$candidate_freedom_mark" ] ||
      existing_freedom_mark="$candidate_freedom_mark"
  done
  printf '%s\n' "$existing_freedom_mark"
}

resolve_xray_direct_mark() {
  DIRECT_MARK_EFFECTIVE=""
  if [ -n "$DIRECT_MARK_REQUESTED" ]; then
    valid_decimal_mark "$DIRECT_MARK_REQUESTED" || {
      echo "ERROR: --direct-mark must be a decimal integer from 1 to 4294967295." >&2
      return 1
    }
    DIRECT_MARK_EFFECTIVE="$DIRECT_MARK_REQUESTED"
    return 0
  fi

  inherited_mark="$(find_existing_xray_freedom_mark)"
  if [ -n "$inherited_mark" ]; then
    valid_decimal_mark "$inherited_mark" || {
      echo "ERROR: existing Xray Freedom mark is not a valid decimal number: $inherited_mark" >&2
      return 1
    }
    DIRECT_MARK_EFFECTIVE="$inherited_mark"
    return 0
  fi

  if [ "$(init_value proxy_router)" = "on" ]; then
    DIRECT_MARK_EFFECTIVE="255"
  fi
}

patch_xray_inbounds() {
  found_redirect=0
  found_tproxy=0
  for inbound_file in "$XRAY_CONFIG_DIR"/*.json; do
    [ -f "$inbound_file" ] || continue
    inbound_strict="$(make_tmp)"
    if ! strict_json_copy "$inbound_file" "$inbound_strict" 2>/dev/null; then
      continue
    fi

    has_redirect=0
    has_tproxy=0
    jq -e 'any(.inbounds[]?; .tag == "redirect")' "$inbound_strict" >/dev/null 2>&1 &&
      has_redirect=1
    jq -e 'any(.inbounds[]?; .tag == "tproxy")' "$inbound_strict" >/dev/null 2>&1 &&
      has_tproxy=1
    [ "$has_redirect" -eq 1 ] || [ "$has_tproxy" -eq 1 ] || continue

    inbound_patched="$(make_tmp)"
    jq '
      if (.inbounds | type) == "array" then
        .inbounds |= map(
          if .tag == "redirect" then
            .sniffing = ((.sniffing // {}) + {
              "enabled": true,
              "routeOnly": true,
              "destOverride": (((.sniffing.destOverride // []) + ["http", "tls"]) | unique)
            })
          elif .tag == "tproxy" then
            .sniffing = ((.sniffing // {}) + {
              "enabled": true,
              "routeOnly": true,
              "destOverride": (((.sniffing.destOverride // []) + ["quic"]) | unique)
            })
          else .
          end
        )
      else .
      end
    ' "$inbound_strict" > "$inbound_patched"
    replace_preserving_mode "$inbound_file" "$inbound_patched"
    [ "$has_redirect" -eq 0 ] || found_redirect=1
    [ "$has_tproxy" -eq 0 ] || found_tproxy=1
  done

  [ "$found_redirect" -eq 1 ] || {
    echo "ERROR: Xray inbound tag 'redirect' not found." >&2
    return 1
  }
  [ "$found_tproxy" -eq 1 ] || {
    echo "ERROR: Xray inbound tag 'tproxy' not found." >&2
    return 1
  }
}

harden_xray_config_permissions() {
  for hardened_config in "$XRAY_CONFIG_DIR"/*.json; do
    [ -f "$hardened_config" ] || continue
    chmod 0600 "$hardened_config"
  done
}

write_xray_direct_outbound() {
  direct_outbound_file="$1"
  direct_outbound_tag="$2"
  direct_outbound_tmp="$(make_tmp)"
  if [ -n "$DIRECT_MARK_EFFECTIVE" ]; then
    cat > "$direct_outbound_tmp" <<EOF
{
  "outbounds": [
    {
      "tag": "$direct_outbound_tag",
      "protocol": "freedom",
      "settings": {},
      "streamSettings": {
        "sockopt": {
          "mark": $DIRECT_MARK_EFFECTIVE
        }
      }
    }
  ]
}
EOF
  else
    cat > "$direct_outbound_tmp" <<EOF
{
  "outbounds": [
    {
      "tag": "$direct_outbound_tag",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
  fi
  atomic_replace_file "$direct_outbound_file" "$direct_outbound_tmp" 600
}

patch_xray() {
  routing_file="$(find_xray_routing_file)" || {
    echo "ERROR: Xray routing object was not found in $XRAY_CONFIG_DIR." >&2
    return 1
  }
  echo "Patching Xray routing: $routing_file"

  routing_strict="$(make_tmp)"
  strict_json_copy "$routing_file" "$routing_strict" || {
    echo "ERROR: Xray routing file is not valid JSON/JSONC: $routing_file" >&2
    return 1
  }
  routing_patched="$(make_tmp)"
  jq \
    --arg discord_tcp_mode "$DISCORD_TCP_ROUTE_MODE" \
    --arg discord_voice_mode "$DISCORD_VOICE_ROUTE_MODE" \
    --arg youtube_mode "$YOUTUBE_ROUTE_MODE" \
    --arg telegram_mode "$TELEGRAM_ROUTE_MODE" \
    --arg proxy_outbound "$PROXY_OUTBOUND_EFFECTIVE" \
    --arg voice_ports "3478-3481,5349,19294-19344,50000-$VOICE_HIGH" '
    def is_discord_selector:
      type == "string" and (ascii_downcase | contains("discord"));
    def is_discord_ext_selector:
      is_discord_selector and startswith("ext:");
    def is_zkeenip_discord_selector:
      is_discord_ext_selector
      and (ascii_downcase | contains("zkeenip.dat:discord"));
    def is_youtube_ext_selector:
      type == "string"
      and startswith("ext:")
      and (ascii_downcase | contains("youtube"));
    def only_discord_ext($values):
      ($values | type) == "array"
      and ($values | length) > 0
      and all($values[]; is_discord_ext_selector);
    def only_youtube_ext($values):
      ($values | type) == "array"
      and ($values | length) > 0
      and all($values[]; is_youtube_ext_selector);
    def managed_discord_voice:
      .type == "field"
      and .network == "udp"
      and (
        .port == "3478-3481,5349,19294-19344,50000-50100"
        or .port == "3478-3481,5349,19294-19344,50000-65535"
      )
      and ((.domain // []) | length) == 0
      and ((.ip // []) | length) == 0;
    def managed_discord_rule:
      .outboundTag == "discord-direct"
      or only_discord_ext(.domain // [])
      or only_discord_ext(.ip // [])
      or managed_discord_voice;
    def managed_youtube_rule:
      .outboundTag == "youtube-direct"
      or (
        only_youtube_ext(.domain // [])
        and ((.ip // []) | length) == 0
      );

    .routing = (.routing // {})
    | (.routing.rules // []) as $original_rules
    | ([
        $original_rules[]
        | (.domain // [])[]
        | select(
            is_discord_ext_selector
            and (is_zkeenip_discord_selector | not)
          )
      ] + ["ext:geosite_v2fly.dat:discord"] | unique) as $discord_domains
    | ([
        $original_rules[]
        | (.domain // [])[]
        | select(is_youtube_ext_selector)
      ] + [
        "ext:zkeen.dat:youtube",
        "ext:geosite_v2fly.dat:youtube"
      ] | unique) as $youtube_domains
    | ($original_rules | map(
        select(.ruleTag? != "kdn-telegram")
        | select((managed_discord_rule or managed_youtube_rule) | not)
        | ((.domain | type) == "array" and (.domain | length) > 0) as $had_domain
        | ((.ip | type) == "array" and (.ip | length) > 0) as $had_ip
        | if (.domain | type) == "array" then
            .domain |= map(
              select((is_discord_ext_selector or is_youtube_ext_selector) | not)
            )
            | if (.domain | length) == 0 then del(.domain) else . end
          else .
          end
        | if (.ip | type) == "array" then
            .ip |= map(select(is_discord_ext_selector | not))
            | if (.ip | length) == 0 then del(.ip) else . end
          else .
          end
        # A matcher list emptied by the cleanup means the rule only selected
        # managed Discord/YouTube traffic. Keeping it without that condition
        # would widen it (to all traffic, or to its remaining conditions), so
        # drop it; the managed rules placed first now handle that traffic.
        | select(
            ($had_domain | not) or has("domain")
          )
        | select(
            ($had_ip | not) or has("ip")
          )
      )) as $remaining_rules
    | ([
        {
          "type": "field",
          "inboundTag": ["redirect", "tproxy"],
          "outboundTag": (if $discord_tcp_mode != "vless" then "discord-direct"
                          else $proxy_outbound end),
          "domain": $discord_domains
        }
      ] + (if $discord_voice_mode != "vless" then
        [
          {
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "outboundTag": "discord-direct",
            "network": "udp",
            "port": $voice_ports
          }
        ]
      else
        []
      end)) as $discord_rules
    | (if $youtube_mode != "vless" then "youtube-direct"
       else $proxy_outbound
       end) as $youtube_outbound
    # Telegram rules carry ruleTag "kdn-telegram": only they are replaced or
    # removed, other Telegram rules of the user stay (ours come first).
    | (if $telegram_mode == "unmanaged" then []
       else
         (if $telegram_mode == "vless" then $proxy_outbound
          else "telegram-direct" end) as $telegram_outbound
         | [
             {
               "type": "field",
               "ruleTag": "kdn-telegram",
               "inboundTag": ["redirect", "tproxy"],
               "outboundTag": $telegram_outbound,
               "domain": ["ext:geosite_v2fly.dat:telegram"]
             },
             {
               "type": "field",
               "ruleTag": "kdn-telegram",
               "inboundTag": ["redirect", "tproxy"],
               "outboundTag": $telegram_outbound,
               "ip": ["ext:geoip_v2fly.dat:telegram"]
             }
           ]
       end) as $telegram_rules
    | .routing.rules = (
        $discord_rules
        + [
          {
            "type": "field",
            "inboundTag": ["redirect", "tproxy"],
            "outboundTag": $youtube_outbound,
            "domain": $youtube_domains
          }
        ]
        + $telegram_rules
        + $remaining_rules
      )
  ' "$routing_strict" > "$routing_patched"
  replace_preserving_mode "$routing_file" "$routing_patched"

  discord_outbound_file="$XRAY_CONFIG_DIR/04_discord_nfqws2_outbound.json"
  if [ "$DISCORD_TCP_ROUTE_MODE" != "vless" ] ||
     [ "$DISCORD_VOICE_ROUTE_MODE" != "vless" ]; then
    write_xray_direct_outbound "$discord_outbound_file" "discord-direct"
  else
    rm -f "$discord_outbound_file"
  fi

  youtube_outbound_file="$XRAY_CONFIG_DIR/04_youtube_nfqws2_outbound.json"
  if [ "$YOUTUBE_ROUTE_MODE" != "vless" ]; then
    write_xray_direct_outbound "$youtube_outbound_file" "youtube-direct"
  else
    rm -f "$youtube_outbound_file"
  fi

  telegram_outbound_file="$XRAY_CONFIG_DIR/04_telegram_nfqws2_outbound.json"
  case "$TELEGRAM_ROUTE_MODE" in
    direct|zapret) write_xray_direct_outbound "$telegram_outbound_file" "telegram-direct" ;;
    *) rm -f "$telegram_outbound_file" ;;
  esac

  patch_xray_inbounds
  harden_xray_config_permissions
  xkeen -xtest
}

make_mihomo_rules_json() {
  mihomo_rules_file="$1"
  {
    if [ "$DISCORD_TCP_ROUTE_MODE" != "vless" ]; then
      discord_domains | awk '{ print "DOMAIN-SUFFIX," $0 ",DIRECT" }'
    fi
    if [ "$DISCORD_VOICE_ROUTE_MODE" != "vless" ]; then
      echo "AND,((NETWORK,UDP),(DST-PORT,3478-3481)),DIRECT"
      echo "AND,((NETWORK,UDP),(DST-PORT,5349)),DIRECT"
      echo "AND,((NETWORK,UDP),(DST-PORT,19294-19344)),DIRECT"
      echo "AND,((NETWORK,UDP),(DST-PORT,50000-$VOICE_HIGH)),DIRECT"
    fi
    if [ "$YOUTUBE_ROUTE_MODE" != "vless" ]; then
      youtube_domains | awk '{ print "DOMAIN-SUFFIX," $0 ",DIRECT" }'
    fi
    case "$TELEGRAM_ROUTE_MODE" in
      direct|zapret) telegram_mihomo_rules ;;
    esac
  } | jq -Rsc 'split("\n") | map(select(length > 0))' > "$mihomo_rules_file"
}

make_mihomo_removal_rules_json() {
  mihomo_removal_file="$1"
  {
    discord_domains | awk '{ print "DOMAIN-SUFFIX," $0 ",DIRECT" }'
    echo "AND,((NETWORK,UDP),(DST-PORT,3478-3481)),DIRECT"
    echo "AND,((NETWORK,UDP),(DST-PORT,5349)),DIRECT"
    echo "AND,((NETWORK,UDP),(DST-PORT,19294-19344)),DIRECT"
    echo "AND,((NETWORK,UDP),(DST-PORT,50000-50100)),DIRECT"
    echo "AND,((NETWORK,UDP),(DST-PORT,50000-65535)),DIRECT"
    youtube_domains | awk '{ print "DOMAIN-SUFFIX," $0 ",DIRECT" }'
    telegram_mihomo_rules
  } | jq -Rsc 'split("\n") | map(select(length > 0))' > "$mihomo_removal_file"
}

telegram_mihomo_rules() {
  telegram_domains | awk '{ print "DOMAIN-SUFFIX," $0 ",DIRECT" }'
  telegram_networks | awk '{
    if (index($0, ":")) print "IP-CIDR6," $0 ",DIRECT,no-resolve"
    else print "IP-CIDR," $0 ",DIRECT,no-resolve"
  }'
}

patch_mihomo() {
  echo "Patching Mihomo rules: $MIHOMO_CONFIG"
  mihomo_json="$(make_tmp)"
  yq -o=json '.' "$MIHOMO_CONFIG" > "$mihomo_json"
  jq -e . "$mihomo_json" >/dev/null

  mihomo_new_rules="$(make_tmp)"
  make_mihomo_rules_json "$mihomo_new_rules"
  mihomo_removal_rules="$(make_tmp)"
  make_mihomo_removal_rules_json "$mihomo_removal_rules"
  mihomo_patched_json="$(make_tmp)"
  jq --slurpfile project_rules "$mihomo_new_rules" \
    --slurpfile removal_rules "$mihomo_removal_rules" '
    .rules = (
      $project_rules[0]
      + [
          (.rules // [])[] as $rule
          | select(($removal_rules[0] | index($rule)) == null)
          | $rule
        ]
    )
  ' "$mihomo_json" > "$mihomo_patched_json"

  mihomo_patched_yaml="$(make_tmp)"
  yq -P '.' "$mihomo_patched_json" > "$mihomo_patched_yaml"
  replace_preserving_mode "$MIHOMO_CONFIG" "$mihomo_patched_yaml"
  xkeen -mtest
}

patch_xkeen_ports_if_restricted() {
  current_proxying="$(active_ports "$XKEEN_PORT_PROXYING")"
  [ -n "$current_proxying" ] || {
    echo "XKeen port_proxying.lst is not restrictive; leaving it unchanged."
    return 0
  }

  port_tmp="$(make_tmp)"
  sed '/^# BEGIN keenetic-discord-nfqws2$/,/^# END keenetic-discord-nfqws2$/d' \
    "$XKEEN_PORT_PROXYING" > "$port_tmp"
  cat >> "$port_tmp" <<EOF

# BEGIN keenetic-discord-nfqws2
80
443
2053
2083
2087
2096
8443
3478:3481
5349
19294:19344
50000:$VOICE_HIGH
EOF
  if [ "$TELEGRAM_ROUTE_MODE" != "unmanaged" ]; then
    echo "5222" >> "$port_tmp"
  fi
  echo "# END keenetic-discord-nfqws2" >> "$port_tmp"
  replace_preserving_mode "$XKEEN_PORT_PROXYING" "$port_tmp"
}

package_present() {
  [ -n "$(package_version "$1" || true)" ]
}

install_missing_packages() {
  echo "Checking Entware packages..."
  if ! package_present ca-certificates ||
     ! package_present wget-ssl ||
     { [ "$STANDALONE_ZAPRET" -eq 1 ] && ! package_present jq; }; then
    opkg update
  fi
  package_present ca-certificates || opkg install ca-certificates
  package_present wget-ssl || opkg install wget-ssl
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    package_present jq || opkg install jq
  fi
  if package_present wget-nossl; then
    opkg remove wget-nossl
  fi

  mkdir -p "$(dirname "$OPKG_FEED")"
  feed_tmp="$(make_tmp)"
  printf '%s\n' 'src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all' > "$feed_tmp"
  atomic_replace_file "$OPKG_FEED" "$feed_tmp" 600

  if ! package_present nfqws2-keenetic; then
    opkg update
    opkg install nfqws2-keenetic
    # The package post-install script starts its broad default profile.
    # Keep that transient window as short as possible until our narrowed
    # transactional configuration is ready.
    [ ! -x "$NFQWS_INIT" ] || run_nfqws_init stop >/dev/null 2>&1 || true
  fi
}

# NFQWS_BASE_ARGS line that registers the Discord Voice fake blob.
# shellcheck disable=SC2016 # $NFQWS_BASE_ARGS is expanded later by nfqws2.conf.
DISCORD_UDP_BLOB_BASE_ARGS='NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS
                 --blob=discord_udp:@/opt/etc/nfqws2/blobs/discord_udp.bin"'

# Copies the checksum-verified Flowseal Discord UDP fake into nfqws2 blobs.
install_discord_udp_blob() {
  verify_discord_udp_blob_source
  mkdir -p "$(dirname "$NFQWS_DISCORD_UDP_BLOB")"
  blob_tmp="$(make_tmp)"
  cp "$SOURCE_DISCORD_UDP_BLOB" "$blob_tmp"
  atomic_replace_file "$NFQWS_DISCORD_UDP_BLOB" "$blob_tmp" 600
}

patch_nfqws() {
  [ -f "$NFQWS_CONF" ] || {
    echo "ERROR: nfqws2 config not found after installation: $NFQWS_CONF" >&2
    return 1
  }
  mkdir -p "$(dirname "$NFQWS_LIST")"

  list_tmp="$(make_tmp)"
  if [ "$DISCORD_TCP_ROUTE_MODE" = "zapret" ]; then
    discord_domains > "$list_tmp"
  else
    : > "$list_tmp"
  fi
  if [ -e "$NFQWS_LIST" ]; then
    list_mode="$(file_mode "$NFQWS_LIST" 2>/dev/null || echo 0644)"
  else
    list_mode=0644
  fi
  atomic_replace_file "$NFQWS_LIST" "$list_tmp" "$list_mode"

  youtube_list_tmp="$(make_tmp)"
  youtube_domains > "$youtube_list_tmp"
  if [ -e "$NFQWS_YOUTUBE_LIST" ]; then
    youtube_list_mode="$(file_mode "$NFQWS_YOUTUBE_LIST" 2>/dev/null || echo 0644)"
  else
    youtube_list_mode=0644
  fi
  atomic_replace_file \
    "$NFQWS_YOUTUBE_LIST" "$youtube_list_tmp" "$youtube_list_mode"

  telegram_list_tmp="$(make_tmp)"
  telegram_domains > "$telegram_list_tmp"
  atomic_replace_file "$NFQWS_TELEGRAM_LIST" "$telegram_list_tmp" 0644
  telegram_ipset_tmp="$(make_tmp)"
  telegram_networks > "$telegram_ipset_tmp"
  atomic_replace_file "$NFQWS_TELEGRAM_IPSET" "$telegram_ipset_tmp" 0644

  discord_tcp_import=""
  discord_voice_import=""
  youtube_import=""
  if [ "$DISCORD_TCP_ROUTE_MODE" = "zapret" ]; then
    discord_tcp_import="$(active_imported_profile discord-tcp 2>/dev/null || true)"
  fi
  if [ "$DISCORD_VOICE_ROUTE_MODE" = "zapret" ]; then
    discord_voice_import="$(active_imported_profile discord-voice 2>/dev/null || true)"
  fi
  if [ "$YOUTUBE_ROUTE_MODE" = "zapret" ]; then
    youtube_import="$(active_imported_profile youtube 2>/dev/null || true)"
  fi
  for expected_import in \
    "$IMPORTED_PROFILE_DIR/discord-tcp.json" \
    "$IMPORTED_PROFILE_DIR/discord-voice.json" \
    "$IMPORTED_PROFILE_DIR/youtube.json"
  do
    if [ -e "$expected_import" ]; then
      validate_imported_profile "$expected_import"
    fi
  done

  nfqws_tmp="$(make_tmp)"
  sed '/^# BEGIN keenetic-discord-nfqws2$/,/^# END keenetic-discord-nfqws2$/d' \
    "$NFQWS_CONF" > "$nfqws_tmp"

  if [ "$DISCORD_TCP_ROUTE_MODE" = "zapret" ]; then
    selected_tcp_ports="$TCP_PORTS_VALUE"
  else
    selected_tcp_ports="443"
  fi

  base_tcp_filter="$selected_tcp_ports"
  if [ "$TELEGRAM_ROUTE_MODE" = "zapret" ]; then
    # MTProto also uses 80 and 5222; only the netfilter port list grows.
    case ",$selected_tcp_ports," in
      *,80,*) ;;
      *) selected_tcp_ports="80,$selected_tcp_ports" ;;
    esac
    selected_tcp_ports="$selected_tcp_ports,5222"
  fi

  if grep -q '^NFQWS_ARGS="--filter-tcp=' "$nfqws_tmp"; then
    sed "s/^NFQWS_ARGS=\"--filter-tcp=[^ ]*/NFQWS_ARGS=\"--filter-tcp=$base_tcp_filter/" \
      "$nfqws_tmp" > "${nfqws_tmp}.sed"
    mv "${nfqws_tmp}.sed" "$nfqws_tmp"
  else
    echo "ERROR: unsupported nfqws2 config: NFQWS_ARGS TCP filter not found." >&2
    return 1
  fi

  if [ -n "$discord_voice_import" ]; then
    imported_voice_filter="$(jq -r '.args[] | select(startswith("--filter-udp=")) | ltrimstr("--filter-udp=")' "$discord_voice_import")"
    selected_udp_filter="$imported_voice_filter"
    selected_udp_ports="$(printf '%s\n' "$imported_voice_filter" | tr '-' ':')"
  elif [ "$DISCORD_VOICE_ROUTE_MODE" = "zapret" ] &&
     [ "$WIDE_UDP" -eq 1 ]; then
    selected_udp_ports="$UDP_PORTS_WIDE"
    selected_udp_filter="$UDP_FILTER_WIDE"
  elif [ "$DISCORD_VOICE_ROUTE_MODE" = "zapret" ]; then
    selected_udp_ports="$UDP_PORTS_FLOWSEAL"
    selected_udp_filter="$UDP_FILTER_FLOWSEAL"
  else
    selected_udp_ports="443"
    selected_udp_filter="443"
  fi

  udp_base_append=""
  udp_desync=""
  case "$DISCORD_VOICE_ROUTE_MODE:${discord_voice_import:+imported}:$UDP_STRATEGY" in
    zapret:imported:*)
      install_discord_udp_blob
      udp_base_append="$DISCORD_UDP_BLOB_BASE_ARGS"
      ;;
    zapret::flowseal)
      install_discord_udp_blob
      udp_base_append="$DISCORD_UDP_BLOB_BASE_ARGS"
      udp_desync='                --lua-desync=fake:blob=discord_udp:repeats=6'
      ;;
    zapret::legacy)
      rm -f "$NFQWS_DISCORD_UDP_BLOB"
      udp_desync='                --lua-desync=circular:fails=2:time=300:retrans=3:nld=2
                --lua-desync=fake:repeats=6:strategy=1'
      if grep -q -e '--blob=quic_initial:' "$nfqws_tmp"; then
        udp_desync="$udp_desync
                --lua-desync=fake:blob=quic_initial:repeats=6:strategy=2"
      else
        echo "WARNING: nfqws2 config does not register quic_initial; using one legacy UDP strategy." >&2
      fi
      ;;
    direct:*:*|vless:*:*)
      ;;
  esac

  youtube_base_append=""
  youtube_custom_append=""
  if [ "$YOUTUBE_ROUTE_MODE" = "zapret" ]; then
    verify_youtube_blobs
    youtube_base_append='NFQWS_BASE_ARGS="$NFQWS_BASE_ARGS
                 --blob=youtube_quic:@/opt/etc/nfqws2/blobs/quic_initial.bin"'
    if [ -n "$youtube_import" ]; then
      youtube_import_args="$(jq -r '.args[]' "$youtube_import")"
      youtube_custom_append="if [ -n \"\$NFQWS_ARGS_CUSTOM\" ]; then
  NFQWS_ARGS_CUSTOM=\"\$NFQWS_ARGS_CUSTOM
--new\"
fi
NFQWS_ARGS_CUSTOM=\"\$NFQWS_ARGS_CUSTOM
$youtube_import_args\""
    else
      youtube_custom_append='if [ -n "$NFQWS_ARGS_CUSTOM" ]; then
  NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM
--new"
fi
NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM
--filter-tcp=443 --filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--out-range=-d10
--payload=tls_client_hello
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up
--new
--filter-udp=443 --filter-l7=quic
--hostlist=/opt/etc/nfqws2/lists/youtube.list
--payload=quic_initial
--lua-desync=fake:blob=youtube_quic:repeats=11"'
    fi
  fi

  telegram_custom_append=""
  if [ "$TELEGRAM_ROUTE_MODE" = "zapret" ]; then
    # Web/CDN by hostlist (TLS) and MTProto to the Telegram DC networks.
    # The MTProto strategy is a starting point; verify it in the app.
    telegram_custom_append='if [ -n "$NFQWS_ARGS_CUSTOM" ]; then
  NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM
--new"
fi
NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM
--filter-tcp=443 --filter-l7=tls
--hostlist=/opt/etc/nfqws2/lists/telegram.list
--out-range=-d10
--payload=tls_client_hello
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up
--new
--filter-tcp=80,443,5222
--ipset=/opt/etc/nfqws2/lists/telegram-ip.list
--filter-l7=mtproto
--out-range=-d10
--payload=mtproto_initial
--lua-desync=fake:blob=tls_clienthello:repeats=6
--lua-desync=multisplit:pos=1"'
  fi

  discord_tcp_profile_assignment=""
  nfqws_extra_args='$MODE_LIST'
  if [ -n "$discord_tcp_import" ]; then
    discord_tcp_import_args="$(jq -r '.args[]' "$discord_tcp_import")"
    discord_tcp_profile_assignment="NFQWS_ARGS=\"$discord_tcp_import_args\""
    nfqws_extra_args=""
  fi

  if [ -n "$discord_voice_import" ]; then
    discord_voice_import_args="$(jq -r '.args[]' "$discord_voice_import")"
    udp_profile_assignment="NFQWS_ARGS_UDP=\"$discord_voice_import_args\""
  elif [ "$DISCORD_VOICE_ROUTE_MODE" = "zapret" ]; then
    udp_profile_assignment="NFQWS_ARGS_UDP=\"--filter-udp=$selected_udp_filter
                --filter-l7=stun,discord
                --out-range=<n2
                --payload=stun,discord_ip_discovery
$udp_desync\""
  else
    udp_profile_assignment='NFQWS_ARGS_UDP=""'
  fi

  nfqws_ipv6="$NFQWS_IPV6_EFFECTIVE"
  if [ "$WIDE_UDP" -eq 1 ]; then
    udp_range_label=wide
  else
    udp_range_label=narrow
  fi
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    deployment_mode="standalone-zapret"
  else
    deployment_mode="xkeen-integrated"
  fi

  cat >> "$nfqws_tmp" <<EOF

# BEGIN keenetic-discord-nfqws2
# Generated by apply-discord-nfqws2.sh $SCRIPT_VERSION.
# Deployment mode: $deployment_mode.
# Active routes: DiscordTCP=$DISCORD_TCP_ROUTE_MODE, DiscordVoice=$DISCORD_VOICE_ROUTE_MODE, YouTube=$YOUTUBE_ROUTE_MODE, Telegram=$TELEGRAM_ROUTE_MODE.
# Discord UDP: strategy=$UDP_STRATEGY, range=$udp_range_label.
# Base TCP/QUIC use user.list; YouTube has isolated custom profiles.
$udp_base_append
$youtube_base_append
$discord_tcp_profile_assignment
$udp_profile_assignment
NFQWS_EXTRA_ARGS="$nfqws_extra_args"
NFQWS_ARGS_IPSET=""
$youtube_custom_append
$telegram_custom_append
TCP_PORTS=$selected_tcp_ports
UDP_PORTS=$selected_udp_ports
POLICY_NAME="$UNBOUND_POLICY_NAME"
POLICY_EXCLUDE=0
IPV6_ENABLED=$nfqws_ipv6
ISP_INTERFACE="$WAN_INTERFACE_EFFECTIVE"
# END keenetic-discord-nfqws2
EOF
  replace_preserving_mode "$NFQWS_CONF" "$nfqws_tmp"
}

verify_nfqws_runtime() {
  nfqws_running || {
    echo "ERROR: nfqws2 is not running." >&2
    return 1
  }

  have iptables-save || {
    echo "ERROR: iptables-save is unavailable after nfqws2 installation." >&2
    return 1
  }
  ipv4_rules="$(iptables-save -t mangle 2>/dev/null)" || {
    echo "ERROR: cannot read IPv4 mangle rules." >&2
    return 1
  }
  printf '%s\n' "$ipv4_rules" | grep -q '^-A POSTROUTING -j nfqws_post$' || {
    echo "ERROR: nfqws2 POSTROUTING hook was not created." >&2
    return 1
  }
  for verified_iface in $WAN_INTERFACE_EFFECTIVE; do
    printf '%s\n' "$ipv4_rules" |
      grep '^-A nfqws_post ' |
      grep -F -e "-o $verified_iface " |
      grep -q 'NFQUEUE' || {
        echo "ERROR: no nfqws2 IPv4 NFQUEUE rule for $verified_iface." >&2
        return 1
      }
  done

  if [ "$NFQWS_IPV6_EFFECTIVE" -eq 1 ]; then
    have ip6tables-save || {
      echo "ERROR: IPv6 is enabled but ip6tables-save is unavailable." >&2
      return 1
    }
    ipv6_rules="$(ip6tables-save -t mangle 2>/dev/null)" || {
      echo "ERROR: cannot read IPv6 mangle rules." >&2
      return 1
    }
    printf '%s\n' "$ipv6_rules" | grep -q '^-A POSTROUTING -j nfqws_post$' || {
      echo "ERROR: nfqws2 IPv6 POSTROUTING hook was not created." >&2
      return 1
    }
    for verified_iface in $IPV6_WAN_INTERFACE; do
      printf '%s\n' "$ipv6_rules" |
        grep '^-A nfqws_post ' |
        grep -F -e "-o $verified_iface " |
        grep -q 'NFQUEUE' || {
          echo "ERROR: no nfqws2 IPv6 NFQUEUE rule for $verified_iface." >&2
          return 1
        }
    done
  fi
}

restart_nfqws_only_and_verify() {
  echo "Restarting nfqws2 only; XKeen is left untouched..."
  [ -x "$NFQWS_INIT" ] || {
    echo "ERROR: nfqws2 init script is missing: $NFQWS_INIT" >&2
    return 1
  }
  run_nfqws_init restart
  verify_nfqws_runtime
}

restart_and_verify() {
  echo "Restarting XKeen..."
  "$XKEEN_INIT" restart on
  case "$DETECTED_CORE" in
    xray) process_running xray ;;
    mihomo) process_running mihomo ;;
  esac || {
    echo "ERROR: $DETECTED_CORE is not running after restart." >&2
    return 1
  }

  restart_nfqws_only_and_verify
}

apply_transaction() {
  require_confirmation
  acquire_lock
  preflight
  umask 077
  mkdir -p "$STATE_ROOT"

  if existing_baseline="$(read_pointer "$BASELINE_POINTER" 2>/dev/null)"; then
    create_snapshot pre-apply
    PREAPPLY_SNAPSHOT="$CREATED_SNAPSHOT"
    if [ "$STANDALONE_ZAPRET" -eq 0 ] &&
       [ "$(snapshot_scope "$existing_baseline" 2>/dev/null || true)" = "standalone" ] &&
       ! read_pointer "$XKEEN_BASELINE_POINTER" >/dev/null 2>&1; then
      atomic_pointer "$XKEEN_BASELINE_POINTER" "$PREAPPLY_SNAPSHOT"
      echo "XKeen baseline recorded (the first baseline covers nfqws2 only): $PREAPPLY_SNAPSHOT"
    fi
  else
    create_snapshot baseline
    PREAPPLY_SNAPSHOT="$CREATED_SNAPSHOT"
    atomic_pointer "$BASELINE_POINTER" "$PREAPPLY_SNAPSHOT"
    echo "Immutable baseline recorded: $PREAPPLY_SNAPSHOT"
  fi
  atomic_pointer "$LATEST_POINTER" "$PREAPPLY_SNAPSHOT"
  TRANSACTION_ACTIVE=1

  install_missing_packages
  if [ "$STANDALONE_ZAPRET" -eq 0 ]; then
    patch_xkeen_ports_if_restricted
    case "$DETECTED_CORE" in
      xray) patch_xray ;;
      mihomo) patch_mihomo ;;
    esac
  fi
  patch_nfqws
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    restart_nfqws_only_and_verify
  else
    restart_and_verify
  fi

  TRANSACTION_ACTIVE=0
  echo "Apply complete."
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    echo "XKeen/Xray/Mihomo were outside this transaction and were not touched."
    echo "One-command scoped rollback:"
    echo "  sh apply-discord-nfqws2.sh --rollback-latest --yes-router"
  else
    echo "One-command baseline rollback:"
    echo "  sh apply-discord-nfqws2.sh --rollback --yes-router"
  fi
}

prepare_nfqws_profile_operation() {
  require_confirmation
  acquire_lock
  load_current_nfqws_context
  preflight
  [ -f "$NFQWS_CONF" ] && [ -x "$NFQWS_INIT" ] || {
    echo "ERROR: nfqws2 must already be installed before profile import." >&2
    return 1
  }
  nfqws_running || {
    echo "ERROR: nfqws2 is currently stopped; start it before applying a profile." >&2
    return 1
  }
  umask 077
  mkdir -p "$STATE_ROOT"
}

apply_import_profile_transaction() {
  safe_import_stage_path "$IMPORT_PROFILE_REQUESTED" || {
    echo "ERROR: profile staging file must be a regular file below /opt/tmp." >&2
    return 1
  }
  import_size="$(wc -c < "$IMPORT_PROFILE_REQUESTED" | tr -d '[:space:]')"
  case "$import_size" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$import_size" -le 524288 ] || {
    echo "ERROR: imported profile exceeds 512 KiB." >&2
    return 1
  }

  prepare_nfqws_profile_operation
  validate_imported_profile "$IMPORT_PROFILE_REQUESTED"
  import_service="$(jq -r '.service' "$IMPORT_PROFILE_REQUESTED")"
  case "$import_service" in
    youtube) import_route="$YOUTUBE_ROUTE_MODE" ;;
    discord-tcp) import_route="$DISCORD_TCP_ROUTE_MODE" ;;
    discord-voice) import_route="$DISCORD_VOICE_ROUTE_MODE" ;;
  esac
  [ "$import_route" = "zapret" ] || {
    echo "ERROR: $import_service currently uses route=$import_route." >&2
    echo "       Switch that service to Zapret separately, then import the profile." >&2
    return 1
  }

  create_nfqws_import_snapshot "import-$import_service"
  atomic_pointer "$LATEST_IMPORT_POINTER" "$NFQWS_IMPORT_BACKUP"
  NFQWS_TRANSACTION_ACTIVE=1

  mkdir -p "$IMPORTED_PROFILE_DIR"
  chmod 700 "$IMPORTED_PROFILE_DIR"
  normalized_profile="$(make_tmp)"
  jq -S '{
    format, service, candidate_id, source_name, source_sha, source_url,
    family, args, notes, rank,
    report: {
      repository: (.report.repository // ""),
      ref: (.report.ref // ""),
      commit: (.report.commit // ""),
      created_utc: (.report.created_utc // ""),
      search_seed: (.report.search_seed // null)
    }
  }' "$IMPORT_PROFILE_REQUESTED" > "$normalized_profile"
  import_target="$(imported_profile_path "$import_service")"
  if [ -e "$import_target" ]; then
    validate_imported_profile "$import_target"
    archive_imported_profile_version "$import_target" replaced
  fi
  atomic_replace_file "$import_target" "$normalized_profile" 600
  validate_imported_profile "$import_target"
  archive_imported_profile_version "$import_target" applied
  patch_nfqws
  restart_nfqws_only_and_verify

  NFQWS_TRANSACTION_ACTIVE=0
  echo "Imported $import_service profile: $(jq -r '.candidate_id' "$import_target")"
  echo "XKeen was not restarted or reconfigured."
}

clear_import_profile_transaction() {
  case "$CLEAR_IMPORTED_PROFILE" in
    youtube|discord-tcp|discord-voice) ;;
    *)
      echo "ERROR: unsupported imported profile service: $CLEAR_IMPORTED_PROFILE" >&2
      return 1
      ;;
  esac
  clear_target="$(imported_profile_path "$CLEAR_IMPORTED_PROFILE")"
  [ -e "$clear_target" ] || {
    echo "No imported $CLEAR_IMPORTED_PROFILE profile is installed."
    return 0
  }

  prepare_nfqws_profile_operation
  validate_imported_profile "$clear_target"
  create_nfqws_import_snapshot "clear-$CLEAR_IMPORTED_PROFILE"
  atomic_pointer "$LATEST_IMPORT_POINTER" "$NFQWS_IMPORT_BACKUP"
  NFQWS_TRANSACTION_ACTIVE=1
  archive_imported_profile_version "$clear_target" cleared
  rm -f "$clear_target"
  patch_nfqws
  restart_nfqws_only_and_verify
  NFQWS_TRANSACTION_ACTIVE=0
  echo "Built-in $CLEAR_IMPORTED_PROFILE profile restored."
  echo "XKeen was not restarted or reconfigured."
}

rollback_import_transaction() {
  require_confirmation
  acquire_lock
  restore_preflight
  target_import_snapshot="$(read_import_pointer)" || {
    echo "ERROR: no focused nfqws2 import rollback is available." >&2
    return 1
  }
  verify_nfqws_import_snapshot "$target_import_snapshot"

  create_nfqws_import_snapshot pre-import-rollback-rescue
  rescue_import_snapshot="$NFQWS_IMPORT_BACKUP"
  NFQWS_TRANSACTION_ACTIVE=1
  restore_nfqws_import_snapshot "$target_import_snapshot"
  NFQWS_TRANSACTION_ACTIVE=0
  atomic_pointer "$LATEST_IMPORT_POINTER" "$rescue_import_snapshot"
  echo "Latest profile operation rolled back. XKeen was not touched."
}

manual_restore_target() {
  target_snapshot="$1"
  restore_label="$2"
  require_confirmation
  acquire_lock
  restore_preflight
  verify_snapshot "$target_snapshot"
  target_scope="$(snapshot_scope "$target_snapshot")" || return 1
  if [ "$target_scope" = "standalone" ]; then
    STANDALONE_ZAPRET=1
    DETECTED_CORE="standalone"
  elif [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    echo "ERROR: standalone mode refuses to restore an integrated XKeen snapshot." >&2
    return 1
  fi

  create_snapshot pre-rollback-rescue
  rescue_snapshot="$CREATED_SNAPSHOT"
  echo "Rescue snapshot of current state: $rescue_snapshot"
  PREAPPLY_SNAPSHOT="$rescue_snapshot"
  TRANSACTION_ACTIVE=1
  restore_snapshot_internal "$target_snapshot"
  TRANSACTION_ACTIVE=0
  echo "$restore_label rollback complete."
}

manual_restore() {
  restore_pointer="$1"
  restore_label="$2"
  target_snapshot="$(read_pointer "$restore_pointer")" || {
    echo "ERROR: $restore_label snapshot was not found." >&2
    return 1
  }
  manual_restore_target "$target_snapshot" "$restore_label"
}

# --rollback: return to the state before this project was installed. When the
# baseline came from a standalone install, the XKeen baseline (taken before the
# first integrated apply) is restored first, then the nfqws2-only baseline.
rollback_to_baseline() {
  xkeen_baseline="$(read_pointer "$XKEEN_BASELINE_POINTER" 2>/dev/null)" || {
    manual_restore "$BASELINE_POINTER" "Baseline"
    return
  }
  nfqws_baseline="$(read_pointer "$BASELINE_POINTER")" || {
    echo "ERROR: Baseline snapshot was not found." >&2
    return 1
  }
  if [ "$STANDALONE_ZAPRET" -eq 1 ]; then
    echo "ERROR: standalone mode refuses to restore the integrated XKeen baseline." >&2
    return 1
  fi
  require_confirmation
  acquire_lock
  restore_preflight
  verify_snapshot "$xkeen_baseline"
  verify_snapshot "$nfqws_baseline"
  [ "$(snapshot_scope "$xkeen_baseline")" = "integrated" ] || {
    echo "ERROR: XKeen baseline is not an integrated snapshot: $xkeen_baseline" >&2
    return 1
  }

  create_snapshot pre-rollback-rescue
  rescue_snapshot="$CREATED_SNAPSHOT"
  echo "Rescue snapshot of current state: $rescue_snapshot"
  PREAPPLY_SNAPSHOT="$rescue_snapshot"
  TRANSACTION_ACTIVE=1
  restore_snapshot_internal "$xkeen_baseline"
  restore_snapshot_internal "$nfqws_baseline"
  TRANSACTION_ACTIVE=0
  echo "Baseline rollback complete (XKeen baseline, then nfqws2 baseline)."
}

manual_restore_path() {
  target_snapshot="$1"
  safe_snapshot_path "$target_snapshot" || {
    echo "ERROR: unsafe or missing requested snapshot: $target_snapshot" >&2
    return 1
  }
  manual_restore_target "$target_snapshot" "Selected snapshot"
}

case "$MODE" in
  preflight)
    preflight
    ;;
  status)
    status_report
    ;;
  show-snapshots)
    show_snapshots
    ;;
  snapshot-baseline)
    require_confirmation
    acquire_lock
    preflight
    mkdir -p "$STATE_ROOT"
    if baseline_snapshot="$(read_pointer "$BASELINE_POINTER" 2>/dev/null)"; then
      echo "Baseline already exists and is immutable: $baseline_snapshot"
    else
      create_snapshot baseline
      atomic_pointer "$BASELINE_POINTER" "$CREATED_SNAPSHOT"
      echo "Baseline recorded: $CREATED_SNAPSHOT"
    fi
    ;;
  apply)
    apply_transaction
    ;;
  apply-import-profile)
    apply_import_profile_transaction
    ;;
  clear-imported-profile)
    clear_import_profile_transaction
    ;;
  rollback-import)
    rollback_import_transaction
    ;;
  rollback-baseline)
    rollback_to_baseline
    ;;
  rollback-latest)
    manual_restore "$LATEST_POINTER" "Latest pre-apply"
    ;;
  rollback-snapshot)
    manual_restore_path "$ROLLBACK_SNAPSHOT_REQUESTED"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
