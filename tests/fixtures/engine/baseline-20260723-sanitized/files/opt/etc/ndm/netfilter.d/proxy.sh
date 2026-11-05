#!/bin/sh
# XKeen: Auto-generated file. DO NOT EDIT!
[ -f /tmp/xkeen_ready ] || exit 0
name_client='xray'
name_profile='xkeen'
mode_proxy='Hybrid'
network_redirect='tcp'
network_tproxy='udp'
networks='tcp udp'
name_chain='xkeen'
port_redirect='61219'
port_tproxy='61219'
port_donor='80,443,596:599,1400,5222,50000:50030'
port_exclude=''
policy_mark='0xffffaaa'
comment_tag='xkeen_rule'
comment='-m comment --comment xkeen_rule'
custom_mark=''
dscp_exclude='62'
dscp_proxy='63'
user_policies=''
table_redirect='nat'
table_tproxy='mangle'
table_mark='0x111'
table_id='111'
status_file='/opt/lib/opkg/status'
file_dns='false'
file_cpu='/opt/sbin/.xkeen/01_info/03_info_router.sh'
file_ca='/opt/etc/ssl/certs/ca-certificates.crt'
proxy_dns='on'
proxy_router='off'
directory_configs_app='/opt/etc/xray'
directory_xray_config='/opt/etc/xray/configs'
directory_xray_asset='/opt/etc/xray/dat'
iptables_supported='true'
ip6tables_supported='true'
arm64_fd='40000'
other_fd='10000'
aghfix='off'
ipv6_proxy='::1'
ipv4_proxy='127.0.0.1'
val_exclude_ip6='2001:2:7847:1251:feee:ed78:4712:5180/128 ::1/128 0000::/8 0100::/64 0200::/7 2001:0002::/48 2001:0010::/28 2001:0db8::/32 2002::/16 3ffe::/16 fc00::/7 fd00::/8 fe80::/10 fec0::/10 ff00::/8 ::ffff:0:0/96 64:ff9b::/96 64:ff9b:1::/48 100::/64 2001::/23'
val_exclude_ip4='192.0.2.1/32 255.255.255.255/32 0.0.0.0/8 192.0.2.1/8 192.0.2.1/10 192.0.2.1/8 192.0.2.1/16 192.0.2.1/12 192.0.2.1/24 192.0.2.1/24 192.0.2.1/16 192.0.2.1/15 192.0.2.1/24 192.0.2.1/24 192.0.2.1/4 192.0.2.1/4'
name_ipset_deny_mac='xkeen_deny_mac'
url_server='localhost:79'
url_hotspot='rci/show/ip/hotspot'
restart_script() {
    exec /bin/sh "$0" "$@"
}
if pidof "$name_client" >/dev/null; then
    _xkeen_sync_deny_mac_ipset() {
        command -v ipset >/dev/null 2>&1 || return 0
        ipset create "$name_ipset_deny_mac" hash:mac -exist 2>/dev/null || return 0
        _tmp="${name_ipset_deny_mac}_tmp"
        ipset create "$_tmp" hash:mac -exist 2>/dev/null
        ipset flush "$_tmp" >/dev/null 2>&1
        _hjson=$(curl --connect-timeout 2 -m 5 -kfsS "${url_server}/${url_hotspot}" 2>/dev/null)
        if [ -n "$_hjson" ]; then
            printf '%s' "$_hjson" | jq -r '
                ((.host // . // []) |
                 (if type == "array" then .[] else . end)) |
                select((.access // "") == "deny" and (.mac // "") != "") |
                .mac
            ' 2>/dev/null | tr '[:lower:]' '[:upper:]' | while IFS= read -r _m; do
                [ -n "$_m" ] && ipset add "$_tmp" "$_m" -exist 2>/dev/null
            done
        fi
        ipset swap "$_tmp" "$name_ipset_deny_mac" 2>/dev/null
        ipset destroy "$_tmp" 2>/dev/null
    }
    _xkeen_sync_deny_mac_ipset
    _xkeen_v4_nat_rules=""
    _xkeen_v4_mangle_rules=""
    _xkeen_v6_nat_rules=""
    _xkeen_v6_mangle_rules=""
    ipt() {
        [ "$family" = "iptables" ] && [ "$iptables_supported" != "true" ] && return 0
        [ "$family" = "ip6tables" ] && [ "$ip6tables_supported" != "true" ] && return 0
        case "$1" in
            -A|-I|-D)
                _line=$*
                case "${family}_${table}" in
                    iptables_nat)     _xkeen_v4_nat_rules="${_xkeen_v4_nat_rules}${_line}
" ;;
                    iptables_mangle)  _xkeen_v4_mangle_rules="${_xkeen_v4_mangle_rules}${_line}
" ;;
                    ip6tables_nat)    _xkeen_v6_nat_rules="${_xkeen_v6_nat_rules}${_line}
" ;;
                    ip6tables_mangle) _xkeen_v6_mangle_rules="${_xkeen_v6_mangle_rules}${_line}
" ;;
                esac
                return 0
                ;;
            *)
                if [ "$family" = "iptables" ]; then
                    iptables -w -t "$table" "$@"
                else
                    ip6tables -w -t "$table" "$@"
                fi
                return $?
                ;;
        esac
    }
    _xkeen_apply_table() {
        _family="$1"
        _table="$2"
        _rules_var="$3"
        eval "_rules=\${$_rules_var}"
        [ -z "$_rules" ] && return 0
        save_cmd=""
        [ "$_family" = "iptables" ] && [ "$iptables_supported" = "true" ] && save_cmd="iptables-save"
        [ "$_family" = "ip6tables" ] && [ "$ip6tables_supported" = "true" ] && save_cmd="ip6tables-save"
        [ -z "$save_cmd" ] && { _deletes=""; return; }
        _deletes=$($save_cmd -t "$_table" 2>/dev/null | awk \
            -v tag="$comment_tag" \
            -v c1="$name_chain" \
            -v c2="${name_chain}_out" '
            index($0, tag) &&
            $1 == "-A" &&
            $2 != c1 &&
            $2 != c2 {
                sub(/^-A /, "-D ")
                print
            }
        ')
        {
            printf '*%s\n' "$_table"
            printf ':%s -\n' "$name_chain"
            [ "$proxy_router" = "on" ] && printf ':%s_out -\n' "$name_chain"
            [ -n "$_deletes" ] && printf '%s\n' "$_deletes"
            printf '%s' "$_rules"
            printf 'COMMIT\n'
        } | if [ "$_family" = "iptables" ]; then
            iptables-restore --noflush 2>/dev/null
        else
            ip6tables-restore --noflush 2>/dev/null
        fi
    }
    _xkeen_apply() {
        [ "$iptables_supported" = "true" ] && _xkeen_apply_table iptables nat _xkeen_v4_nat_rules || true
        [ "$iptables_supported" = "true" ] && _xkeen_apply_table iptables mangle _xkeen_v4_mangle_rules || true
        [ "$ip6tables_supported" = "true" ] && _xkeen_apply_table ip6tables nat _xkeen_v6_nat_rules || true
        [ "$ip6tables_supported" = "true" ] && _xkeen_apply_table ip6tables mangle _xkeen_v6_mangle_rules || true
    }
    add_exclude_rules() {
        chain="$1"
        for exclude in $exclude_list; do
            if [ "$file_dns" = "true" ] && [ "$proxy_dns" = "on" ] && [ "$chain" != "${name_chain}_out" ]; then
                case "$exclude" in
                    192.0.2.1/8|192.0.2.1/12|192.0.2.1/16|fd00::/8|fe80::/10)
                    if [ "$table" = "mangle" ] && [ "$mode_proxy" = "Hybrid" ]; then
                        ipt -A "$chain" -d "$exclude" -p tcp --dport 53 $comment -j RETURN >/dev/null 2>&1
                        ipt -A "$chain" -d "$exclude" -p udp ! --dport 53 $comment -j RETURN >/dev/null 2>&1
                    elif [ "$table" = "nat" ] && [ "$mode_proxy" = "Hybrid" ]; then
                        ipt -A "$chain" -d "$exclude" -p tcp ! --dport 53 $comment -j RETURN >/dev/null 2>&1
                        ipt -A "$chain" -d "$exclude" -p udp --dport 53 $comment -j RETURN >/dev/null 2>&1
                    elif [ "$table" = "mangle" ] && [ "$mode_proxy" = "TProxy" ]; then
                        ipt -A "$chain" -d "$exclude" -p tcp ! --dport 53 $comment -j RETURN >/dev/null 2>&1
                        ipt -A "$chain" -d "$exclude" -p udp ! --dport 53 $comment -j RETURN >/dev/null 2>&1
                    fi
                    ;;
                esac
            else
                ipt -A "$chain" -d "$exclude" $comment -j RETURN >/dev/null 2>&1
            fi
        done
    }
    add_ipset_exclude() {
        base_set="$1"
        set_type="${2:-hash:net}"
        if [ "$family" = "ip6tables" ]; then
            set_name="${base_set}6"
            ipset_family="inet6"
        else
            set_name="$base_set"
            ipset_family="inet"
        fi
        ipset create "$set_name" "$set_type" family "$ipset_family" -exist || return
        ipt -I "$chain" 1 -m set --match-set "$set_name" dst $comment -j RETURN >/dev/null 2>&1
    }
    add_geo_exclude() {
        if [ "$family" = "ip6tables" ]; then
            geo_set="geo_exclude6"
            override_set="geo_override6"
            ipset_family="inet6"
        else
            geo_set="geo_exclude"
            override_set="geo_override"
            ipset_family="inet"
        fi
        ipset create "$geo_set" hash:net family "$ipset_family" -exist
        ipset create "$override_set" hash:net family "$ipset_family" -exist
        ipt -I "$chain" 1 -m set --match-set "$geo_set" dst -m set ! --match-set "$override_set" dst $comment -j RETURN >/dev/null 2>&1
    }
    add_ipt_rule() {
        family="$1"
        table="$2"
        chain="$3"
        shift 3
        [ "$family" = "iptables" ] && [ "$iptables_supported" = "false" ] && return
        [ "$family" = "ip6tables" ] && [ "$ip6tables_supported" = "false" ] && return
        add_exclude_rules "$chain"
        if [ "$table" = "$table_tproxy" ]; then
            if [ "$mode_proxy" = "Hybrid" ]; then
                set -- -p udp -m conntrack --ctstate ESTABLISHED,RELATED $comment -j CONNMARK --restore-mark
            else
                set -- -m conntrack --ctstate ESTABLISHED,RELATED $comment -j CONNMARK --restore-mark
            fi
            ipt -I "$chain" 1 "$@" >/dev/null 2>&1
        fi
        case "$mode_proxy" in
            Hybrid)
                if [ "$table" = "$table_redirect" ]; then
                    ipt -I "$chain" 1 -m conntrack --ctstate DNAT $comment -j RETURN >/dev/null 2>&1
                    add_ipset_exclude ext_exclude hash:ip
                    add_ipset_exclude user_exclude hash:net
                    add_geo_exclude
                    ipt -A "$chain" -p tcp $comment -j REDIRECT --to-port "$port_redirect" >/dev/null 2>&1
                else
                    ipt -I "$chain" 1 -m conntrack --ctstate DNAT $comment -j RETURN >/dev/null 2>&1
                    add_ipset_exclude ext_exclude hash:ip
                    add_ipset_exclude user_exclude hash:net
                    add_geo_exclude
                    ipt -A "$chain" -p udp -m socket --transparent $comment -j MARK --set-mark "$table_mark" >/dev/null 2>&1
                    ipt -A "$chain" -p udp -m mark ! --mark 0 $comment -j CONNMARK --save-mark >/dev/null 2>&1
                    ipt -A "$chain" -p udp $comment -j TPROXY --on-ip "$proxy_ip" --on-port "$port_tproxy" --tproxy-mark "$table_mark" >/dev/null 2>&1
                fi
                ;;
            TProxy)
                ipt -I "$chain" 1 -m conntrack --ctstate DNAT $comment -j RETURN >/dev/null 2>&1
                for net in $network_tproxy; do
                    add_ipset_exclude ext_exclude hash:ip
                    add_ipset_exclude user_exclude hash:net
                    add_geo_exclude
                    ipt -A "$chain" -p "$net" -m socket --transparent $comment -j MARK --set-mark "$table_mark" >/dev/null 2>&1
                    ipt -A "$chain" -p "$net" -m mark ! --mark 0 $comment -j CONNMARK --save-mark >/dev/null 2>&1
                    ipt -A "$chain" -p "$net" $comment -j TPROXY --on-ip "$proxy_ip" --on-port "$port_tproxy" --tproxy-mark "$table_mark" >/dev/null 2>&1
                done
                ;;
            Redirect)
                ipt -I "$chain" 1 -m conntrack --ctstate DNAT $comment -j RETURN >/dev/null 2>&1
                add_ipset_exclude ext_exclude hash:ip
                add_ipset_exclude user_exclude hash:net
                add_geo_exclude
                for net in $network_redirect; do
                    ipt -A "$chain" -p "$net" $comment -j REDIRECT --to-port "$port_redirect" >/dev/null 2>&1
                done
                ;;
            *) exit 0 ;;
        esac
        if [ -n "$dscp_exclude" ]; then
            for dscp in $dscp_exclude; do
                ipt -I "$chain" -m dscp --dscp "$dscp" $comment -j RETURN >/dev/null 2>&1
            done
        fi
    }
    configure_route() {
        ip_version="$1"
        if [ -n "$policy_mark" ]; then
            policy_table=$(ip rule show | awk -v policy="$policy_mark" '$0 ~ policy && /lookup/ && !/blackhole/ {print $(NF); exit}')
        fi
        source_table="${policy_table:-main}"
        check_default() {
            if [ "$ip_version" = "6" ] && ! ip -6 route show default 2>/dev/null | grep -q .; then
                return 0
            fi
            if [ "$source_table" = "main" ]; then
                ip -"$ip_version" route show default 2>/dev/null | grep -q '^default'
            else
                ip -"$ip_version" route show table all 2>/dev/null | grep -E "^[[:space:]]*default .* table $policy_table([[:space:]]|$)" | grep -vq 'unreachable' >/dev/null
            fi
        }
        attempts=0
        max_attempts=4
        until check_default; do
            attempts=$((attempts + 1))
            if [ "$attempts" -ge "$max_attempts" ]; then
                [ "$ip_version" = "4" ] && touch "/tmp/noinet"
                return 1
            fi
            sleep 1
        done
        [ "$ip_version" = "4" ] && rm -f "/tmp/noinet"
        ip -"$ip_version" rule del fwmark "$table_mark" lookup "$table_id" >/dev/null 2>&1 || true
        ip -"$ip_version" route flush table "$table_id" >/dev/null 2>&1 || true
        ip -"$ip_version" route add local default dev lo table "$table_id" >/dev/null 2>&1 || true
        ip -"$ip_version" rule add fwmark "$table_mark" lookup "$table_id" >/dev/null 2>&1 || true
        ip -"$ip_version" route show table "$source_table" 2>/dev/null | while read -r route_line; do
            case "$route_line" in
                default*|unreachable*|blackhole*) continue ;;
                *) ip -"$ip_version" route add table "$table_id" $route_line >/dev/null 2>&1 || true ;;
            esac
        done
        return 0
    }
    add_multiport_rules() {
        family="$1"
        table="$2"
        net="$3"
        mark="$4"
        ports="$5"
        target="$6"
        [ -z "$ports" ] && return
        num_ports=$(echo "$ports" | tr ',' '\n' | wc -l)
        i=1
        while [ "$i" -le "$num_ports" ]; do
            end=$((i + 6))
            chunk=$(echo "$ports" | tr ',' '\n' | sed -n "${i},${end}p" | tr '\n' ',' | sed 's/,$//')
            [ -z "$chunk" ] && break
            if [ -n "$mark" ]; then
                set -- -m connmark --mark "$mark" -m conntrack ! --ctstate INVALID -p "$net" -m multiport --dports "$chunk" $comment -j "$target"
            else
                set -- -m conntrack ! --ctstate INVALID -p "$net" -m multiport --dports "$chunk" $comment -j "$target"
            fi
            ipt -A PREROUTING "$@" >/dev/null 2>&1
            i=$((i + 7))
        done
    }
    add_prerouting() {
        family="$1"
        table="$2"
        ipt -I PREROUTING 1 -m set --match-set "$name_ipset_deny_mac" src $comment -j RETURN >/dev/null 2>&1
        for net in $networks; do
            if [ "$mode_proxy" = "Hybrid" ]; then
                [ "$table" = "nat"    ] && [ "$net" != "tcp" ] && continue
                [ "$table" = "mangle" ] && [ "$net" != "udp" ] && continue
            fi
            if [ "$mode_proxy" = "TProxy" ]; then
                proto_match=""
            else
                proto_match="-p $net"
            fi
            for dscp in $dscp_proxy; do
                set -- -m conntrack ! --ctstate INVALID $proto_match -m dscp --dscp "$dscp" $comment -j "$name_chain"
                ipt -A PREROUTING "$@" >/dev/null 2>&1
            done
            if [ "$proxy_router" = "on" ]; then
                set -- -i lo -m mark --mark "$table_mark" $proto_match $comment -j "$name_chain"
                ipt -A PREROUTING "$@" >/dev/null 2>&1
            fi
            while IFS='|' read -r pname pmark pmode pports; do
                [ -z "$pmark" ] && continue
                pmark=$(echo "$pmark" | tr -d ' \r\n')
                pmode=$(echo "$pmode" | tr -d ' \r\n')
                pports=$(echo "$pports" | tr -d ' \r\n')
                if [ "$pmode" = "all" ]; then
                    set -- -m connmark --mark 0x"$pmark" -m conntrack ! --ctstate INVALID $comment -j "$name_chain"
                    ipt -A PREROUTING "$@" >/dev/null 2>&1
                elif [ "$pmode" = "include" ]; then
                    add_multiport_rules "$family" "$table" "$net" "0x$pmark" "$pports" "$name_chain"
                elif [ "$pmode" = "exclude" ]; then
                    add_multiport_rules "$family" "$table" "$net" "0x$pmark" "$pports" "RETURN"
                    set -- -m connmark --mark 0x"$pmark" -m conntrack ! --ctstate INVALID -p "$net" $comment -j "$name_chain"
                    ipt -A PREROUTING "$@" >/dev/null 2>&1
                fi
            done <<USER_POLICIES_EOF
$user_policies
USER_POLICIES_EOF
            if [ -n "$policy_mark" ]; then
                if [ -n "$port_donor" ]; then
                    add_multiport_rules "$family" "$table" "$net" "$policy_mark" "$port_donor" "$name_chain"
                elif [ -n "$port_exclude" ]; then
                    add_multiport_rules "$family" "$table" "$net" "$policy_mark" "$port_exclude" "RETURN"
                    set -- -m connmark --mark "$policy_mark" -m conntrack ! --ctstate INVALID -p "$net" $comment -j "$name_chain"
                    ipt -A PREROUTING "$@" >/dev/null 2>&1
                else
                    set -- -m connmark --mark "$policy_mark" -m conntrack ! --ctstate INVALID $comment -j "$name_chain"
                    ipt -A PREROUTING "$@" >/dev/null 2>&1
                fi
            else
                if [ -n "$port_donor" ]; then
                    add_multiport_rules "$family" "$table" "$net" "" "$port_donor" "$name_chain"
                elif [ -n "$port_exclude" ]; then
                    add_multiport_rules "$family" "$table" "$net" "" "$port_exclude" "RETURN"
                    set -- -m conntrack ! --ctstate INVALID -p "$net" $comment -j "$name_chain"
                    ipt -A PREROUTING "$@" >/dev/null 2>&1
                else
                    set -- -m conntrack ! --ctstate INVALID $comment -j "$name_chain"
                    ipt -A PREROUTING "$@" >/dev/null 2>&1
                fi
            fi
        done
    }
    add_output() {
        family="$1"
        table="$2"
        [ "$proxy_router" != "on" ] && return
        out_chain="${name_chain}_out"
        orig_chain="$chain"
        chain="$out_chain"
        ipt -A "$out_chain" -o lo $comment -j RETURN >/dev/null 2>&1
        ipt -A "$out_chain" -m mark --mark 255 $comment -j RETURN >/dev/null 2>&1
        add_exclude_rules "$out_chain"
        add_ipset_exclude ext_exclude hash:ip
        add_ipset_exclude user_exclude hash:net
        add_geo_exclude
        chain="$orig_chain"
        for net in $networks; do
            if [ "$mode_proxy" = "Hybrid" ]; then
                [ "$table" = "nat"    ] && [ "$net" != "tcp" ] && continue
                [ "$table" = "mangle" ] && [ "$net" != "udp" ] && continue
            fi
            if [ "$mode_proxy" = "TProxy" ]; then
                proto_match=""
            else
                proto_match="-p $net"
            fi
            set -- -m conntrack ! --ctstate INVALID $proto_match $comment -j "$out_chain"
            ipt -A OUTPUT "$@" >/dev/null 2>&1
            if [ "$table" = "$table_redirect" ]; then
                set -- -p "$net" $comment -j REDIRECT --to-port "$port_redirect"
                ipt -A "$out_chain" "$@" >/dev/null 2>&1
            elif [ "$table" = "$table_tproxy" ]; then
                set -- -p "$net" $comment -j MARK --set-mark "$table_mark"
                ipt -A "$out_chain" "$@" >/dev/null 2>&1
            fi
        done
    }
    dns_redir() {
        family="$1"
        table="nat"
        [ "$aghfix" != "on" ] && return
        [ "$file_dns" = "true" ] && [ "$proxy_dns" = "on" ] && return
        all_marks=""
        [ -n "$policy_mark" ] && all_marks="$policy_mark"
        [ -n "$custom_mark" ] && all_marks="$custom_mark $all_marks"
        if [ -n "$user_policies" ]; then
            user_marks=$(echo "$user_policies" | awk -F'|' '{if ($2 != "") print "0x"$2}')
            all_marks="$all_marks $user_marks"
        fi
        for mark in $all_marks; do
            mark=$(echo "$mark" | tr -d ' \r\n')
            [ -z "$mark" ] && continue
            for proto in udp tcp; do
                set -- -p "$proto" -m mark --mark "$mark" -m pkttype --pkt-type unicast -m "$proto" --dport 53 $comment -j REDIRECT --to-ports 53
                ipt -I _NDM_HOTSPOT_DNSREDIR "$@" >/dev/null 2>&1
            done
        done
    }
    if [ -n "$port_donor" ] || [ -n "$port_exclude" ]; then
        [ "$file_dns" = "true" ] && [ "$proxy_dns" = "on" ] && [ -n "$port_donor" ] && port_donor="53,$port_donor"
    fi
    for family in iptables ip6tables; do
        [ "$family" = "ip6tables" ] && [ "$ip6tables_supported" != "true" ] && continue
        [ "$family" = "iptables" ] && [ "$iptables_supported" != "true" ] && continue
        if [ "$family" = "ip6tables" ]; then
            exclude_list="$val_exclude_ip6"
            proxy_ip="$ipv6_proxy"
            configure_route 6
        else
            exclude_list="$val_exclude_ip4"
            proxy_ip="$ipv4_proxy"
            configure_route 4
        fi
        if [ -n "$port_redirect" ] && [ -n "$port_tproxy" ]; then
            for table in "$table_tproxy" "$table_redirect"; do
                add_ipt_rule "$family" "$table" "$name_chain"
                add_prerouting "$family" "$table"
                add_output "$family" "$table"
            done
        elif [ -z "$port_redirect" ] && [ -n "$port_tproxy" ]; then
            table="$table_tproxy"
            add_ipt_rule "$family" "$table" "$name_chain"
            add_prerouting "$family" "$table"
            add_output "$family" "$table"
        elif [ -n "$port_redirect" ] && [ -z "$port_tproxy" ]; then
            table="$table_redirect"
            add_ipt_rule "$family" "$table" "$name_chain"
            add_prerouting "$family" "$table"
            add_output "$family" "$table"
        fi
        dns_redir "$family"
    done
    _xkeen_apply
else
    [ -f "/tmp/xkeen_starting.lock" ] && exit 0
    touch "/tmp/xkeen_starting.lock"
    . "$file_cpu"
    info_cpu
    fd_limit="$other_fd"
    [ "$architecture" = "arm64-v8a" ] && fd_limit="$arm64_fd"
    ulimit -SHn "$fd_limit"
    export SSL_CERT_FILE="$file_ca"
    case "$name_client" in
        xray)
            export XRAY_LOCATION_CONFDIR="$directory_xray_config"
            export XRAY_LOCATION_ASSET="$directory_xray_asset"
            "$name_client" run >/dev/null 2>&1 &
        ;;
        mihomo)
            export CLASH_HOME_DIR="$directory_configs_app"
            "$name_client" >/dev/null 2>&1 &
        ;;
    esac
    _probe=0
    while [ "$_probe" -lt 60 ]; do
        pidof "$name_client" >/dev/null 2>&1 && break
        _probe=$((_probe + 1))
        usleep 100000
    done
    unset _probe
    rm -f "/tmp/xkeen_starting.lock"
    if pidof "$name_client" >/dev/null; then
        restart_script "$@"
    else
        exit 1
    fi
fi
