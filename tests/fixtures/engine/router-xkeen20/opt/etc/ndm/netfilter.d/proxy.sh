#!/bin/sh
# shellcheck disable=SC2034
# Skeleton of the XKeen netfilter hook: the assignments the engine modes read.
mode_proxy='Hybrid'
policy_mark='0xffffaaa'
custom_mark=''
dscp_exclude='62'
dscp_proxy='63'
table_mark='0x111'
proxy_dns='on'
proxy_router='off'
