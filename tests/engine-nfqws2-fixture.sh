# shellcheck shell=sh
# Shared nfqws2 fixture for the engine tests (sourced, not run).
#
# engine_write_stock_nfqws2_conf FILE IFACE IPV6
#     The stock /opt/etc/nfqws2/nfqws2.conf of nfqws2-keenetic 1.3.2, with the
#     given ISP_INTERFACE and IPV6_ENABLED.
# engine_write_nfqws2_init FILE
#     A fixture /opt/etc/init.d/S51nfqws2 that behaves like the 1.3.2 init: it
#     composes the arguments with the package _startup_args, starts the
#     fixture binary, waits for its pidfile, writes the iptables rules the
#     real init would create and refuses to start twice. Like the 1.3.2 init,
#     start returns 1 and installs no rules when the daemon fails or its
#     pidfile does not appear.
# engine_write_fake_nfqws2 FILE
#     A fixture /opt/usr/bin/nfqws2.
# engine_write_iptables_mocks MOCK_BIN
#     iptables-save/ip6tables-save that print the rules of the fixture init.
#
# nfqws2-keenetic (https://github.com/nfqws/nfqws2-keenetic) is MIT licensed,
# Copyright (c) 2026 nfqws. The stock config and _startup_args below are
# copied from its v1.3.2 tag.

engine_write_stock_nfqws2_conf() {
  cat > "$1" <<'EOF'
# Provider network interface, e.g. eth3
# You can specify multiple interfaces separated by space, e.g. ISP_INTERFACE="eth3 nwg1"
ISP_INTERFACE="eth3"

# All arguments here: https://github.com/bol-van/zapret2/blob/master/docs/manual.md

# Startup arguments
NFQWS_BASE_ARGS="--fastpath-workaround=auto
                 --lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua
                 --lua-init=@/opt/etc/nfqws2/lua/zapret-antidpi.lua
                 --lua-init=@/opt/etc/nfqws2/lua/zapret-auto.lua
                 --blob=quic_initial:@/opt/etc/nfqws2/blobs/quic_initial.bin
                 --blob=tls_clienthello:@/opt/etc/nfqws2/blobs/tls_clienthello.bin"

# HTTP(S) strategy
NFQWS_ARGS="--filter-tcp=443,80,1984,5222 --filter-l7=http,tls,mtproto
            # HTTPS
            --payload=tls_client_hello,mtproto_initial
            --lua-desync=circular:fails=2:time=300:retrans=3:nld=2
            # Strategy 1
            --lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000:strategy=1
            --lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up:strategy=1
            # Strategy 2
            --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com:repeats=2:strategy=2
            --lua-desync=multisplit:pos=1,midsld:strategy=2
            # Strategy 3
            --lua-desync=hostfakesplit:host=ozon.ru:midhost=host-2:seqovl=sniext+3:seqovl_pattern=tls_clienthello:badsum:tcp_md5:tcp_ts_up:strategy=3
            --lua-desync=hostfakesplit:tcp_md5:tcp_ts_up:strategy=3
            # HTTP
            --payload=http_req
            --lua-desync=http_methodeol:badsum"

# QUIC strategy
NFQWS_ARGS_QUIC="--filter-udp=443 --filter-l7=quic
                 --payload=quic_initial
                 --lua-desync=fake:blob=quic_initial:repeats=11"

# UDP strategy (doesn't use lists from NFQWS_EXTRA_ARGS)
NFQWS_ARGS_UDP="--filter-udp=590-600,1400,3478-3481,5349,19294-19344,49152-65535
                --filter-l7=wireguard,stun,discord,mtproto,unknown
                --out-range=<n2
                --payload=wireguard_initiation,wireguard_response,wireguard_cookie,stun,discord_ip_discovery,mtproto_initial,unknown
                --lua-desync=circular:fails=2:time=300:retrans=3:nld=2
                # Strategy 1
                --lua-desync=fake:blob=0x00000000:repeats=6:strategy=1
                # Strategy 2
                --lua-desync=fake:blob=quic_initial:repeats=6:strategy=2"

# Working modes, don't change
MODE_LIST="--hostlist=/opt/etc/nfqws2/lists/user.list"
MODE_ALL="--hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list"
MODE_AUTO="$MODE_LIST --hostlist-auto=/opt/etc/nfqws2/lists/auto.list --hostlist-auto-debug=/opt/var/log/nfqws2.log $MODE_ALL"

# $MODE_AUTO - automatically detects blocked resources and adds them to the auto.list
# $MODE_LIST - applies rules only to domains in the user.list
# $MODE_ALL  - applies rules to all traffic except domains from exclude.list
NFQWS_EXTRA_ARGS="$MODE_AUTO"

# IP-lists
NFQWS_ARGS_IPSET="--ipset=/opt/etc/nfqws2/lists/ipset.list --ipset-exclude=/opt/etc/nfqws2/lists/ipset_exclude.list"

# Custom arguments, e.g. NFQWS_ARGS_CUSTOM="--filter-tcp=80 --dpi-desync=fakedsplit --new --filter-tcp=443 --dpi-desync=fake"
NFQWS_ARGS_CUSTOM=""

# IPv6 support
IPV6_ENABLED=1

# TCP ports for iptables rules
TCP_PORTS=80,443,1984,2053,2083,2087,2096,5222,8443

# UDP ports for iptables rules
UDP_PORTS=443,590:600,1400,3478:3481,5349,19294:19344,49152:65535

# Keenetic policy name
POLICY_NAME="nfqws"
# Policy mode (0 - include, 1 - exclude)
POLICY_EXCLUDE=0

# Syslog logging level (0 - silent, 1 - debug)
LOG_LEVEL=0
LOG_DEBUG_PATH="@/opt/var/log/nfqws2-debug.log"

NFQUEUE_NUM=300
USER=nobody
CONFIG_VERSION=1
EOF
  sed -i "s/^ISP_INTERFACE=\"eth3\"\$/ISP_INTERFACE=\"$2\"/; s/^IPV6_ENABLED=1\$/IPV6_ENABLED=$3/" "$1"
}

engine_write_nfqws2_init() {
  cat > "$1" <<'EOF'
#!/bin/sh
# Fixture /opt/etc/init.d/S51nfqws2 modeled on nfqws2-keenetic 1.3.2
# (MIT License, Copyright (c) 2026 nfqws); _startup_args is unchanged.
# Knob files in $KD_TEST_ROOT:
#   nfqws-init.keep-old     restart does nothing (the old daemon keeps running)
#   nfqws-init.stale-rules  start keeps the firewall rules of the previous start
#   nfqws-init.fail-start   start fails
#   nfqws-init.wrong-args   start runs the daemon without the config's profiles
#   nfqws-start-fail        a counter N > 0: the next N starts fail at once,
#                           without a daemon or rules
# KD_FIXTURE_PIDFILE_WAIT: seconds start waits for the pidfile (default 5).
NFQWS_BIN="$KD_TEST_ROOT/opt/usr/bin/nfqws2"
CONFFILE="$KD_TEST_ROOT/opt/etc/nfqws2/nfqws2.conf"
PIDFILE="$KD_TEST_ROOT/opt/var/run/nfqws2.pid"
RULES4="$KD_TEST_ROOT/iptables-mangle.rules"
RULES6="$KD_TEST_ROOT/ip6tables-mangle.rules"
printf 'nfqws-init:%s\n' "$*" >> "$KD_TEST_ROOT/nfqws-init.log"
[ ! -f "$CONFFILE" ] || . "$CONFFILE"

is_running() {
  [ -f "$PIDFILE" ] || return 1
  PID_SAVED=$(cat "$PIDFILE" 2>/dev/null)
  case "$PID_SAVED" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$PID_SAVED" 2>/dev/null
}

_startup_args() {
  local fastpath_workaround=
  case "$NFQWS_BASE_ARGS" in
    *--fastpath-workaround=*) ;;
    *) fastpath_workaround="--fastpath-workaround=auto" ;;
  esac

  local args="--user=$USER --qnum=$NFQUEUE_NUM $fastpath_workaround $NFQWS_BASE_ARGS"

  # Fix bind multiple interfaces
  local iface_count=$(echo $ISP_INTERFACE | wc -w)
  if [ "$iface_count" -gt "1" ]; then
    args="$args --bind-fix4"
    if [ -n "$IPV6_ENABLED" ] && [ "$IPV6_ENABLED" -ne "0" ]; then
      args="$args --bind-fix6"
    fi
  fi

  # Logging
  if [ "$LOG_LEVEL" -eq "1" ]; then
    if [ -n "$LOG_DEBUG_PATH" ]; then
      args="--debug=$LOG_DEBUG_PATH $args"
    else
      args="--debug=syslog $args"
    fi
  fi

  # Custom args
  if [ -n "$NFQWS_ARGS_CUSTOM" ]; then
    args="$args $NFQWS_ARGS_CUSTOM --new"
  fi

  # UDP
  if [ -n "$NFQWS_ARGS_UDP" ]; then
    args="$args $NFQWS_ARGS_UDP --new"
  fi

  # QUIC
  if [ -n "$NFQWS_ARGS_QUIC" ]; then
    if [ -n "$NFQWS_ARGS_IPSET" ]; then
      args="$args $NFQWS_ARGS_QUIC $NFQWS_ARGS_IPSET --ipset-ip=0.0.0.0 --new"
    fi
    args="$args $NFQWS_ARGS_QUIC $NFQWS_EXTRA_ARGS --new"
  fi

  # HTTP(S)
  if [ -n "$NFQWS_ARGS_IPSET" ]; then
    args="$args $NFQWS_ARGS $NFQWS_ARGS_IPSET --ipset-ip=0.0.0.0 --new"
  fi
  args="$args $NFQWS_ARGS $NFQWS_EXTRA_ARGS"

  echo "$args"
}

# The NFQUEUE rules of the real _firewall_start, without the policy rules.
write_rules() {
  queue="-j NFQUEUE --queue-num $NFQUEUE_NUM --queue-bypass"
  check="-m mark ! --mark 0x40000000/0x40000000"
  echo '*mangle'
  echo '-A PREROUTING -j nfqws_pre'
  echo '-A POSTROUTING -j nfqws_post'
  for IFACE in $ISP_INTERFACE; do
    echo "-A nfqws_post -o $IFACE $check -p udp -m multiport --dports $UDP_PORTS -m connbytes --connbytes 1:15 --connbytes-dir original --connbytes-mode packets $queue"
    echo "-A nfqws_post -o $IFACE $check -p tcp -m multiport --dports $TCP_PORTS -m connbytes --connbytes 1:15 --connbytes-dir original --connbytes-mode packets $queue"
    echo "-A nfqws_post -o $IFACE $check -p tcp -m multiport --dports $TCP_PORTS -m tcp --tcp-flags FIN FIN $queue"
    echo "-A nfqws_pre -i $IFACE -m mark --mark 0x40000000/0x40000000 -j RETURN"
    echo "-A nfqws_pre -i $IFACE $check -p udp -m multiport --sports $UDP_PORTS -m connbytes --connbytes 1:15 --connbytes-dir reply --connbytes-mode packets $queue"
    echo "-A nfqws_pre -i $IFACE $check -p tcp -m multiport --sports $TCP_PORTS -m connbytes --connbytes 1:15 --connbytes-dir reply --connbytes-mode packets $queue"
  done
  echo 'COMMIT'
}

start() {
  if [ -f "$KD_TEST_ROOT/nfqws-init.fail-start" ]; then
    echo 'fixture: start fails' >&2
    return 1
  fi
  start_fail_left=$(cat "$KD_TEST_ROOT/nfqws-start-fail" 2>/dev/null || true)
  case "$start_fail_left" in ''|*[!0-9]*) start_fail_left=0 ;; esac
  if [ "$start_fail_left" -gt 0 ]; then
    echo $((start_fail_left - 1)) > "$KD_TEST_ROOT/nfqws-start-fail"
    echo 'fixture: start fails (nfqws-start-fail)' >&2
    return 1
  fi
  if is_running; then
    echo 'Service NFQWS2 is already running' >&2
    return 1
  fi
  if [ -f "$KD_TEST_ROOT/nfqws-init.wrong-args" ]; then
    "$NFQWS_BIN" --daemon --pidfile="$PIDFILE" --qnum="$NFQUEUE_NUM" --filter-tcp=1 || return 1
  else
    # shellcheck disable=SC2046
    "$NFQWS_BIN" --daemon --pidfile="$PIDFILE" $(_startup_args) || return 1
  fi
  # The parent can exit before the child writes its pidfile.
  pidfile_wait="${KD_FIXTURE_PIDFILE_WAIT:-5}"
  while ! is_running && [ "$pidfile_wait" -gt 0 ]; do
    sleep 1
    pidfile_wait=$((pidfile_wait - 1))
  done
  if ! is_running; then
    echo 'NFQWS2 daemon did not start, firewall rules not installed' >&2
    return 1
  fi
  if [ ! -f "$KD_TEST_ROOT/nfqws-init.stale-rules" ] || [ ! -f "$RULES4" ]; then
    write_rules > "$RULES4"
    if [ -n "$IPV6_ENABLED" ] && [ "$IPV6_ENABLED" -ne 0 ]; then
      write_rules > "$RULES6"
    else
      rm -f "$RULES6"
    fi
  fi
  echo 'Started NFQWS2 service'
}

stop() {
  [ -f "$KD_TEST_ROOT/nfqws-init.stale-rules" ] || rm -f "$RULES4" "$RULES6"
  if ! is_running; then
    echo 'Service NFQWS2 is not running' >&2
    return 1
  fi
  kill -15 "$(cat "$PIDFILE")" && rm -f "$PIDFILE"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart)
    [ ! -f "$KD_TEST_ROOT/nfqws-init.keep-old" ] || exit 0
    stop
    start
    ;;
  status) if is_running; then echo 'Service NFQWS2 is running'; else echo 'Service NFQWS2 is stopped'; fi ;;
  firewall_stop) rm -f "$RULES4" "$RULES6" ;;
  *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
EOF
  chmod +x "$1"
}

engine_write_fake_nfqws2() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<'EOF'
#!/bin/sh
# Fixture nfqws2. --dry-run accepts everything (the engine tests set
# KD_TEST_NFQWS2_BIN to check with a real build); --daemon starts a
# placeholder process whose command line carries every argument, as the
# /proc/PID/cmdline of the real daemon does.
pidfile=""
for arg in "$@"; do
  case "$arg" in
    --dry-run)
      if [ -f "$KD_TEST_ROOT/nfqws2.fail-dry-run" ]; then
        echo 'fixture: nfqws2 rejects the arguments' >&2
        exit 1
      fi
      exit 0
      ;;
    --pidfile=*) pidfile="${arg#--pidfile=}" ;;
  esac
done
python3 -c 'import time; time.sleep(3600)' "$0" "$@" </dev/null >/dev/null 2>&1 &
[ -z "$pidfile" ] || printf '%s\n' "$!" > "$pidfile"
EOF
  chmod +x "$1"
}

engine_write_iptables_mocks() {
  cat > "$1/iptables-save" <<'EOF'
#!/bin/sh
cat "$KD_TEST_ROOT/iptables-mangle.rules" 2>/dev/null || true
EOF
  cat > "$1/ip6tables-save" <<'EOF'
#!/bin/sh
cat "$KD_TEST_ROOT/ip6tables-mangle.rules" 2>/dev/null || true
EOF
  chmod +x "$1/iptables-save" "$1/ip6tables-save"
}
