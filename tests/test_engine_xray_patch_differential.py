"""Semantic differential against frozen legacy jq for all108 route combinations.

Role-based tags, optional type and preservation of unrelated Voice-like rules
are intentional differences and have separate regression vectors.
"""
from itertools import product
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import engine_shell
from kdn.engine import xray_patch


@unittest.skipUnless(shutil.which('jq'), 'legacy differential requires jq (provided by Docker)')
class XrayPatchDifferentialTests(unittest.TestCase):
    def test_all_routes_match_frozen_legacy_routing_and_outbound_objects(self):
        source = {'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'outboundTag': 'block', 'domain': ['ext:geosite_v2fly.dat:youtube@ads']},
            {'type': 'field', 'outboundTag': 'vpn', 'domain': ['ext:geosite_v2fly.dat:discord', 'example.org']},
            {'type': 'field', 'outboundTag': 'vpn', 'ip': ['ext:zkeenip.dat:discord', '203.0.113.0/24']},
            {'type': 'field', 'outboundTag': 'vpn', 'ip': ['ext:zkeenip.dat:youtube']},
            {'type': 'field', 'outboundTag': 'block', 'domain': ['ext:geosite_v2fly.dat:youtube'], 'ip': ['192.0.2.1']},
            {'type': 'field', 'outboundTag': 'vpn', 'inboundTag': ['redirect', 'tproxy'],
             'network': 'udp', 'port': '3478-3481,5349,19294-19344,50000-50100'},
            {'type': 'field', 'ruleTag': 'kdn-telegram-old', 'outboundTag': 'old', 'domain': ['old.example.invalid']},
        ]}}
        helpers = '''
make_tmp() { mktemp "$XRAY_CONFIG_DIR/tmp.XXXXXX"; }
find_xray_routing_file() { printf '%s/05_routing.json\\n' "$XRAY_CONFIG_DIR"; }
strict_json_copy() { cp "$1" "$2"; }
replace_preserving_mode() { cp "$2" "$1"; }
atomic_replace_file() { cp "$2" "$1"; }
xray_blackhole_tags_json() { printf '%s\\n' '["block"]'; }
patch_xray_inbounds() { :; }
harden_xray_config_permissions() { :; }
xray_test_config() { :; }
'''
        body = ('set -eu\n' + helpers + engine_shell.extract_function('write_xray_direct_outbound')
                + '\n' + engine_shell.extract_function('patch_xray') + '\npatch_xray\n')
        with tempfile.TemporaryDirectory(prefix='kdn-xray-diff-') as temporary:
            root = Path(temporary)
            for tcp, voice, youtube, telegram in product(*([('direct', 'zapret', 'vless')] * 3),
                                                        ('direct', 'vless', 'ws', 'unmanaged')):
                routes = dict(discord_tcp=tcp, discord_voice=voice, youtube=youtube, telegram=telegram)
                with self.subTest(routes=routes):
                    routing = root / '05_routing.json'
                    routing.write_text(json.dumps(source))
                    env = dict(os.environ, XRAY_CONFIG_DIR=str(root), DISCORD_TCP_ROUTE_MODE=tcp,
                        DISCORD_VOICE_ROUTE_MODE=voice, YOUTUBE_ROUTE_MODE=youtube, TELEGRAM_ROUTE_MODE=telegram,
                        PROXY_OUTBOUND_EFFECTIVE='vpn', VOICE_HIGH='50100', TELEGRAM_WS_PORT='18443', DIRECT_MARK_EFFECTIVE='')
                    done = engine_shell.run_sh(body, env=env, timeout=20)
                    self.assertEqual(done.returncode, 0, done.stderr)
                    expected = json.loads(routing.read_text())
                    actual = xray_patch.patch_routing(source, inbound_tags=['redirect', 'tproxy'], routes=routes,
                                                      proxy_outbound='vpn', block_tags=['block'])
                    self.assertEqual(actual, expected)
                    for service, needed in (('discord', tcp != 'vless' or voice != 'vless'),
                                            ('youtube', youtube != 'vless'), ('telegram', telegram in ('direct', 'ws'))):
                        path = root / ('04_' + service + '_nfqws2_outbound.json')
                        self.assertEqual(path.exists(), needed)
                        if not needed:
                            continue
                        expected_outbound = xray_patch.direct_outbound(service + '-direct')
                        if service == 'telegram' and telegram == 'ws':
                            expected_outbound['outbounds'].append({'tag': 'telegram-ws', 'protocol': 'freedom',
                                                                  'settings': {'redirect': '127.0.0.1:18443'}})
                        self.assertEqual(json.loads(path.read_text()), expected_outbound)
