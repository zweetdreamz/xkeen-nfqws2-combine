#!/bin/sh
set -eu

# Read-only diagnostics. Do not add bare xkeen -dns/-pr/-ipv6/-dscp calls:
# without an explicit on/off argument those commands may open an interactive
# toggle and change S05xkeen.

XKEEN_INIT="/opt/etc/init.d/S05xkeen"
XKEEN_HOOK="/opt/etc/ndm/netfilter.d/proxy.sh"
NFQWS_CONF="/opt/etc/nfqws2/nfqws2.conf"
STATE_ROOT="/opt/etc/keenetic-discord-nfqws2"

section() {
  printf '\n== %s ==\n' "$1"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

init_value() {
  wanted_key="$1"
  [ -f "$XKEEN_INIT" ] || return 0
  awk -F= -v wanted="$wanted_key" '
    $1 == wanted {
      value=$0
      sub(/^[^=]*=/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/^["\047]|["\047]$/, "", value)
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
      gsub(/^["\047]|["\047]$/, "", value)
      print value
      exit
    }
  ' "$XKEEN_HOOK"
}

active_ports() {
  [ -f "$1" ] || return 0
  sed 's/\r$//' "$1" |
    sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
    grep -v '^#' |
    grep -v '^$' |
    tr '\n' ',' |
    sed 's/,$//' || true
}

pointer_value() {
  if [ -f "$1" ]; then
    sed -n '1p' "$1"
  else
    echo "not created"
  fi
}

section "System"
uname -a 2>/dev/null || true
uname -m 2>/dev/null || true
[ -x /bin/ndmc ] && echo "keenetic_ndmc=yes" || echo "keenetic_ndmc=no"

section "Entware packages"
if have opkg; then
  opkg print-architecture 2>/dev/null || true
  opkg list-installed 2>/dev/null |
    grep -E '^(xkeen|xray|mihomo|nfqws|iptables|ipset|jq|yq|curl|ca-certificates|wget)' || true
else
  echo "opkg: not found"
fi

section "XKeen persisted settings (read from S05xkeen)"
if [ -f "$XKEEN_INIT" ]; then
  for key in \
    name_client name_policy name_profile table_id table_mark custom_mark \
    proxy_dns proxy_router dscp_exclude dscp_proxy \
    ipv4_proxy ipv4_exclude ipv6_proxy ipv6_exclude ipv6_support \
    start_auto start_attempts start_delay init_delay backup aghfix
  do
    printf '%s=%s\n' "$key" "$(init_value "$key")"
  done
else
  echo "$XKEEN_INIT: not found"
fi

section "XKeen effective runtime (read from generated hook)"
if [ -f "$XKEEN_HOOK" ]; then
  for key in \
    mode_proxy network_redirect network_tproxy port_redirect port_tproxy \
    port_donor port_exclude policy_mark custom_mark dscp_exclude dscp_proxy \
    file_dns proxy_dns proxy_router iptables_supported ip6tables_supported
  do
    printf '%s=%s\n' "$key" "$(runtime_value "$key")"
  done
else
  echo "$XKEEN_HOOK: not found"
fi

section "XKeen safe read-only commands"
if have xkeen; then
  for safe_arg in -v -status -cp -cpe -tp; do
    echo "-- xkeen $safe_arg"
    xkeen "$safe_arg" 2>/dev/null || true
  done
else
  echo "xkeen: not found"
fi

section "XKeen external lists"
for list_file in \
  /opt/etc/xkeen/port_proxying.lst \
  /opt/etc/xkeen/port_exclude.lst \
  /opt/etc/xkeen/ip_exclude.lst
do
  if [ -f "$list_file" ]; then
    echo "$list_file=$(active_ports "$list_file")"
  else
    echo "$list_file: not found"
  fi
done

section "Core configuration"
core="$(init_value name_client)"
echo "detected_core=${core:-unknown}"
case "$core" in
  xray)
    for config_file in /opt/etc/xray/configs/*.json; do
      [ -f "$config_file" ] || continue
      config_mode="$(LC_ALL=C ls -ld "$config_file" 2>/dev/null | awk 'NR == 1 { print $1 }')"
      if [ "$(printf '%s' "$config_mode" | cut -c9)" = "w" ]; then
        echo "WARNING: world-writable Xray config: $config_mode $config_file"
      fi
    done
    if have xkeen; then
      xkeen -xtest 2>/dev/null || echo "xray_config_test=failed"
    fi
    grep -R -n -E '"outboundTag"[[:space:]]*:[[:space:]]*"discord-direct"|"tag"[[:space:]]*:[[:space:]]*"discord-direct"' \
      /opt/etc/xray/configs 2>/dev/null || echo "discord_direct_rules=not found"
    discord_ip_selector_found=0
    if have jq; then
      for config_file in /opt/etc/xray/configs/*.json; do
        [ -f "$config_file" ] || continue
        if jq -e '
          any(.routing.rules[]?;
            any(.ip[]?;
              type == "string"
              and startswith("ext:")
              and (ascii_downcase | contains("discord"))
            )
          )
        ' "$config_file" >/dev/null 2>&1; then
          echo "WARNING: broad Discord IP selector in $config_file"
          discord_ip_selector_found=1
        fi
      done
    elif grep -R -q -i 'zkeenip\.dat:discord' /opt/etc/xray/configs 2>/dev/null; then
      echo "WARNING: broad Discord IP selector in Xray configs"
      discord_ip_selector_found=1
    fi
    if [ "$discord_ip_selector_found" -eq 0 ]; then
      echo "discord_ip_scope=domain-only"
    else
      echo "discord_ip_scope=broad-selector-present"
    fi
    grep -R -n -E '"tag"[[:space:]]*:[[:space:]]*"(redirect|tproxy)"|"sniffing"|"routeOnly"' \
      /opt/etc/xray/configs 2>/dev/null || true
    ;;
  mihomo)
    if have xkeen; then
      xkeen -mtest 2>/dev/null || echo "mihomo_config_test=failed"
    fi
    grep -n -E 'DOMAIN-SUFFIX,discord|DST-PORT.*(3478|19294|50000)' \
      /opt/etc/mihomo/config.yaml 2>/dev/null || echo "discord_direct_rules=not found"
    ;;
  *) echo "core_config_test=skipped" ;;
esac

section "Keenetic policies"
if [ -x /bin/ndmc ]; then
  /bin/ndmc -c show ip policy 2>/dev/null |
    grep -i -A 1 -E 'description = (xkeen|nfqws):' || true
else
  echo "/bin/ndmc: not found"
fi

section "nfqws2"
if [ -f "$NFQWS_CONF" ]; then
  grep -E '^(ISP_INTERFACE|NFQWS_EXTRA_ARGS|NFQWS_ARGS_IPSET|TCP_PORTS|UDP_PORTS|POLICY_NAME|POLICY_EXCLUDE|IPV6_ENABLED)=' \
    "$NFQWS_CONF" || true
  grep -n -A 14 '^# BEGIN keenetic-discord-nfqws2$' "$NFQWS_CONF" || true
else
  echo "$NFQWS_CONF: not found"
fi

if [ -x /opt/etc/init.d/S51nfqws2 ]; then
  /opt/etc/init.d/S51nfqws2 status 2>/dev/null || true
else
  echo "/opt/etc/init.d/S51nfqws2: not found"
fi

section "IPv6 runtime"
if have sysctl; then
  sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null || true
  sysctl net.ipv6.conf.default.disable_ipv6 2>/dev/null || true
fi
if have ip; then
  ip -6 route show default 2>/dev/null || true
  ip -6 route get 2001:4860:4860::8888 2>/dev/null || true
fi

section "Policy routing rules"
if have ip; then
  ip -4 rule show 2>/dev/null || true
  ip -6 rule show 2>/dev/null || true
fi

section "Tagged firewall rules"
if have iptables-save; then
  iptables-save -t mangle 2>/dev/null | grep -E 'xkeen_rule|nfqws|NFQUEUE' || true
else
  echo "iptables-save: not found"
fi
if have ip6tables-save; then
  ip6tables-save -t mangle 2>/dev/null | grep -E 'xkeen_rule|nfqws|NFQUEUE' || true
fi

section "Project snapshots"
echo "baseline=$(pointer_value "$STATE_ROOT/baseline.ptr")"
echo "latest_preapply=$(pointer_value "$STATE_ROOT/latest-preapply.ptr")"
if [ -d "$STATE_ROOT/snapshots" ]; then
  find "$STATE_ROOT/snapshots" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort || true
fi

section "Recent logs"
for log_file in /opt/var/log/nfqws2.log /opt/var/log/xkeen.log; do
  if [ -f "$log_file" ]; then
    echo "-- $log_file"
    tail -n 30 "$log_file" 2>/dev/null || true
  fi
done
