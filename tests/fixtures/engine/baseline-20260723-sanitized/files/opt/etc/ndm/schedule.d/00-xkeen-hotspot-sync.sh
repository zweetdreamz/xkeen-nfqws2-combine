#!/bin/sh
# XKeen: re-sync deny MAC ipset on schedule start/stop. Auto-generated. DO NOT EDIT!
[ "$1" = "start" ] || [ "$1" = "stop" ] || exit 0
[ -x /opt/etc/ndm/netfilter.d/proxy.sh ] && /opt/etc/ndm/netfilter.d/proxy.sh
