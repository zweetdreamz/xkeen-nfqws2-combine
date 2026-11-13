import base64
from pathlib import Path
import sys
import unittest
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools/router'))
from kdn import vpn_wireguard as wg, vpn_fields


class WireGuardTests(unittest.TestCase):
    def link(self, host='example.org:51820', **query):
        self.secret = base64.b64encode(bytes(range(32))).decode()
        self.public = base64.b64encode(bytes(range(1,33))).decode()
        params = {'publickey':self.public,'address':'10.77.0.2/32','dns':'1.1.1.1,9.9.9.9',
                  'mtu':'1280','keepalive':'25', **query}
        return 'wireguard://'+quote(self.secret,safe='')+'@'+host+'?'+ '&'.join(
            quote(k,safe='')+'='+quote(v,safe='') for k,v in params.items())

    def test_link(self):
        s = wg.parse(self.link(presharedkey=base64.b64encode(b'x'*32).decode()), 'test')['settings']
        self.assertEqual(s['secretKey'], self.secret)
        self.assertEqual(s['peers'][0]['publicKey'], self.public)
        self.assertEqual(s['remoteDNS'], ['1.1.1.1','9.9.9.9'])
        self.assertEqual(s['mtu'],1280)
        self.assertEqual(s['peers'][0]['keepAlive'],25)
        self.assertTrue(s['noKernelTun'])

    def test_ipv6_and_partial_edit(self):
        node = wg.parse(self.link(host='[2001:db8::1]:1234'), 'test')
        changed = vpn_fields.patch_outbound(node, {'port':51820})
        self.assertEqual(changed['settings']['peers'][0]['endpoint'],'[2001:db8::1]:51820')
        self.assertEqual(changed['settings']['secretKey'],node['settings']['secretKey'])
        self.assertEqual(node['settings']['peers'][0]['endpoint'],'[2001:db8::1]:1234')

    def test_invalid_inputs(self):
        for changes in ({'publickey':'bad'}, {'mtu':'0'}, {'dns':'not-an-ip'},
                        {'reserved':'256,0,0'}, {'keepalive':'-1'}, {'unknown':'1'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                wg.parse(self.link(**changes), 'test')

    def test_duplicate_parameters(self):
        with self.assertRaises(ValueError): wg.parse(self.link()+'&mtu=1420', 'test')

    def test_json_forces_userspace(self):
        s = wg.parse(self.link(), 'test')['settings']
        s['noKernelTun'] = False
        wg.validate(s)
        self.assertTrue(s['noKernelTun'])
