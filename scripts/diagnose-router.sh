#!/bin/sh
set -eu

section() {
  printf '\n== %s ==\n' "$1"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

section "System"
uname -a 2>/dev/null || true
uname -m 2>/dev/null || true

section "Entware"
if have opkg; then
  opkg print-architecture 2>/dev/null || true
  opkg list-installed 2>/dev/null | grep -E '^(nfqws|iptables|ip6tables|ipset|busybox|ca-certificates|wget|kmod)' || true
else
  echo "opkg: not found"
fi

section "Keenetic"
if [ -x /bin/ndmc ]; then
  /bin/ndmc -c show ip policy 2>/dev/null | grep -i -A 1 'description = nfqws:' || true
  if /bin/ndmc -c show version 2>/dev/null | grep -qw hwnat; then
    echo "hardware_acceleration_capable=yes (current state not inferred)"
  fi
else
  echo "/bin/ndmc: not found"
fi

section "Interfaces"
if have route; then
  route 2>/dev/null | awk '$1=="default"{print "default_iface=" $NF}' || true
fi
if have ip; then
  ip -6 route 2>/dev/null | awk '/^default/ { print "default_ipv6=" $0 }' || true
  ipv6_probe="$(ip -6 route get 2001:4860:4860::8888 2>/dev/null || true)"
  case " $ipv6_probe " in
    *" unreachable "*|*" blackhole "*|*" prohibit "*|*" error "*|*" dev lo "*)
      echo "usable_ipv6_wan=no"
      ;;
    *" dev "*) echo "usable_ipv6_wan=yes $ipv6_probe" ;;
    *) echo "usable_ipv6_wan=no" ;;
  esac
fi
if have ip; then
  ip route 2>/dev/null | awk '/^default/ { for (i=1; i<=NF; i++) if ($i=="dev") print "default_iface=" $(i+1) }' || true
fi

section "Kernel modules"
if have lsmod; then
  for mod in nfnetlink_queue xt_NFQUEUE xt_multiport xt_connbytes xt_CONNMARK xt_connmark nf_conntrack; do
    if lsmod | awk '{print $1}' | grep -qx "$mod"; then
      echo "$mod=yes"
    else
      echo "$mod=no"
    fi
  done
else
  echo "lsmod: not found"
fi

section "Firewall tools"
iptables -V 2>/dev/null || echo "iptables: not found"
ip6tables -V 2>/dev/null || echo "ip6tables: not found"

section "nfqws2 files"
if [ -f /opt/etc/nfqws2/nfqws2.conf ]; then
  grep -E '^(ISP_INTERFACE|NFQWS_EXTRA_ARGS|NFQWS_ARGS_IPSET|TCP_PORTS|UDP_PORTS|POLICY_NAME|POLICY_EXCLUDE|IPV6_ENABLED)=' /opt/etc/nfqws2/nfqws2.conf || true
else
  echo "/opt/etc/nfqws2/nfqws2.conf: not found"
fi

if [ -x /opt/etc/init.d/S51nfqws2 ]; then
  /opt/etc/init.d/S51nfqws2 status 2>/dev/null || true
else
  echo "/opt/etc/init.d/S51nfqws2: not found"
fi

section "nfqws2 firewall rules"
if have iptables-save; then
  iptables-save -t mangle 2>/dev/null | grep -E 'nfqws|NFQUEUE' || true
else
  echo "iptables-save: not found"
fi
if have ip6tables-save; then
  ip6tables-save -t mangle 2>/dev/null | grep -E 'nfqws|NFQUEUE' || true
else
  echo "ip6tables-save: not found"
fi

section "nfqws2 PID and recent log"
if [ -f /opt/var/run/nfqws2.pid ]; then
  nfqws_pid="$(sed -n '1p' /opt/var/run/nfqws2.pid)"
  echo "pid=$nfqws_pid"
  kill -0 "$nfqws_pid" 2>/dev/null && echo "pid_alive=yes" || echo "pid_alive=no"
else
  echo "pidfile: not found"
fi
if [ -f /opt/var/log/nfqws2.log ]; then
  tail -n 40 /opt/var/log/nfqws2.log 2>/dev/null || true
fi
