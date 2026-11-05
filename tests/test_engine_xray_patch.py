"""Pure phase6 transforms: no router writes or service operations."""
from copy import deepcopy
from itertools import product
import unittest

from kdn.engine.xray_patch import direct_outbound, patch_inbounds, patch_routing


class XrayPatchTests(unittest.TestCase):
    def test_roles_and_network_precedence_and_no_mutation(self):
        source = {'inbounds': [
            {'tag': 'custom', 'settings': {'followRedirect': True, 'allowedNetwork': 'tcp,udp', 'network': 'udp'},
             'streamSettings': {'sockopt': {'tproxy': 'tproxy'}},
             'sniffing': {'metadataOnly': False, 'destOverride': ['fakedns']}},
            {'tag': 'redirect', 'protocol': 'socks'}]}
        before = deepcopy(source)
        result = patch_inbounds(source)
        self.assertEqual(source, before)
        self.assertEqual(result['inbounds'][0]['sniffing']['destOverride'], ['fakedns', 'http', 'quic', 'tls'])
        self.assertFalse(result['inbounds'][0]['sniffing']['metadataOnly'])
        self.assertEqual(result['inbounds'][1], source['inbounds'][1])
        self.assertEqual(patch_inbounds(result), result)

    def test_bad_roles(self):
        for row in ({'tag': 'tproxy'}, {'settings': {'followRedirect': True}},
                    {'tag': 'x', 'settings': {'followRedirect': True, 'allowedNetwork': 'bad'}}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                patch_inbounds({'inbounds': [row]})
        with self.assertRaises(ValueError):
            patch_inbounds({'inbounds': [{'tag': 'a', 'settings': {'followRedirect': True}}, {'tag': 'a'}]})

    def test_marks(self):
        for mark in (0, 2147483647, None):
            self.assertEqual(direct_outbound('d', mark)['outbounds'][0]['protocol'], 'freedom')
        for mark in (-1, 2147483648, True, '255', 1.5):
            with self.subTest(mark=mark), self.assertRaises(ValueError):
                direct_outbound('d', mark)

    def test_route_matrix_and_idempotence(self):
        original = {'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'outboundTag': 'block', 'domain': ['ext:geosite_v2fly.dat:youtube@ads']},
            {'outboundTag': 'vpn', 'inboundTag': ['custom-tproxy'], 'network': 'udp',
             'port': '3478-3481,5349,19294-19344,50000-50100'},
            {'outboundTag': 'vpn', 'domain': ['ext:geosite_v2fly.dat:discord', 'domain:example.org']},
            {'outboundTag': 'vpn', 'ip': ['160.79.96.0/20']}]}}
        before = deepcopy(original)
        for tcp, voice, youtube, telegram in product(*([('direct', 'zapret', 'vless')] * 3),
                                                    ('direct', 'vless', 'ws', 'unmanaged')):
            routes = dict(discord_tcp=tcp, discord_voice=voice, youtube=youtube, telegram=telegram)
            kwargs = dict(inbound_tags=['custom-tproxy'], routes=routes, proxy_outbound='vpn', block_tags=['block'])
            with self.subTest(routes=routes):
                result = patch_routing(original, **kwargs)
                self.assertEqual(result, patch_routing(result, **kwargs))
                rows = result['routing']['rules']
                self.assertEqual(rows[0], original['routing']['rules'][0])
                self.assertEqual(rows[-1], original['routing']['rules'][-1])
                self.assertEqual(rows[-2]['domain'], ['domain:example.org'])
                self.assertEqual(rows[1]['inboundTag'], ['custom-tproxy'])
                self.assertEqual(sum(r.get('network') == 'udp' and 'port' in r for r in rows), 1)
        self.assertEqual(original, before)
        kwargs['voice_high'] = 52000
        result = patch_routing(original, **kwargs)
        self.assertEqual(result, patch_routing(result, **kwargs))

    def test_empty_selector_never_widens_rule(self):
        kwargs = dict(inbound_tags=['t'], routes=dict(discord_tcp='direct', discord_voice='direct',
                      youtube='direct', telegram='unmanaged'), proxy_outbound='vpn')
        source = {'routing': {'rules': [{'outboundTag': 'vpn', 'domain': ['ext:geosite_v2fly.dat:youtube'],
                                       'ip': ['1.1.1.1']}]}}
        self.assertEqual(len(patch_routing(source, **kwargs)['routing']['rules']), 3)
        for change in ({'voice_high': True}, {'inbound_tags': []}, {'routes': {}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                patch_routing(source, **dict(kwargs, **change))

    def test_voice_lookalike_on_an_unrelated_inbound_is_preserved(self):
        row = {'outboundTag': 'vpn', 'inboundTag': ['private-socks'], 'network': 'udp',
               'port': '3478-3481,5349,19294-19344,50000-50100'}
        kwargs = dict(inbound_tags=['custom-tproxy'], routes=dict(discord_tcp='direct', discord_voice='direct',
                      youtube='direct', telegram='unmanaged'), proxy_outbound='vpn')
        source = {'routing': {'rules': [row]}}
        result = patch_routing(source, **kwargs)
        self.assertEqual(result['routing']['rules'][-1], row)
        self.assertEqual(source['routing']['rules'], [row])
