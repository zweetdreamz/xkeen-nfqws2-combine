"""Regression coverage for imported profile and live firewall semantic guards."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from engine_firewall import firewall_rules
from panel_fixtures import VALID_ARGS
from kdn.engine import checks, compose, config, nfqws_marks, nfqws_service, nfqws_validate, profile_descriptor


def descriptor(service='youtube'):
    value = dict(format=1, service=service, source_name='synthetic.bat', source_sha='',
                 source_url='', family='regression', rank=1, notes=[], args=list(VALID_ARGS[service]))
    value['candidate_id'] = profile_descriptor.candidate_id(value)
    return value


class ProfileSemanticGuards(unittest.TestCase):
    def test_each_youtube_profile_has_its_own_service_bounds(self):
        value = descriptor()
        args = value['args']
        split = args.index('--new')
        mutations = [
            ['--new', *[token for token in args if token != '--new']],
            [*[token for token in args if token != '--new'], '--new'],
            [*args[:split], '--new', '--new', *args[split + 1:]],
            [*args[:split - 1], '--new', args[split - 1], *args[split + 1:]],
        ]
        for name in ('--filter-tcp=443', '--filter-l7=tls', '--hostlist=/opt/etc/nfqws2/lists/youtube.list',
                     '--payload=tls_client_hello'):
            moved = list(args)
            moved.remove(name)
            moved.append(name)
            mutations.append(moved)
        for changed in mutations:
            candidate = dict(value, args=changed)
            candidate['candidate_id'] = profile_descriptor.candidate_id(candidate)
            with self.subTest(args=changed), self.assertRaises(ValueError):
                profile_descriptor.validate_descriptor(candidate)

    def test_every_service_requires_nonempty_desync_and_rejects_global_options(self):
        for service in profile_descriptor.SERVICES:
            value = descriptor(service)
            for args in ([token for token in value['args'] if not token.startswith('--lua-desync=')],
                         [*value['args'], '--fwmark=1']):
                candidate = dict(value, args=args)
                candidate['candidate_id'] = profile_descriptor.candidate_id(candidate)
                with self.subTest(service=service, args=args), self.assertRaises(ValueError):
                    profile_descriptor.validate_descriptor(candidate)

    def test_lua_call_order_and_existing_identity_are_preserved(self):
        value = descriptor('discord-tcp')
        value['args'].extend(['--lua-desync=fake:blob=fake_default_tls', '--lua-desync=hostfakesplit:host=example.org'])
        value['candidate_id'] = profile_descriptor.candidate_id(value)
        self.assertEqual(profile_descriptor.validate_descriptor(value), value)

    def test_managed_catchall_noop_is_rejected_but_stock_globals_are_allowed(self):
        globals_only = ['--qnum=300', '--lua-init=@/synthetic/zapret-lib.lua', '--blob=synthetic:0x00']
        active = ['--filter-tcp=443', '--filter-l7=tls', '--lua-desync=multisplit:pos=1', '--hostlist-domains=example.org']
        for prefix in ([], globals_only):
            composition = compose.Composition([*prefix, '--new', *active], {'TCP_PORTS': '443'}, 'test')
            lines, status = checks._composition_lines(composition, '')
            self.assertEqual(status, 1, lines)
            self.assertTrue(any('|shadowed-profile|' in line for line in lines), lines)
        for tokens in (globals_only, [*globals_only, '--filter-tcp=1', '--new', *active]):
            lines, status = checks._composition_lines(compose.Composition(tokens, {'TCP_PORTS': '1,443'}, 'test'), '')
            self.assertEqual(status, 0, lines)

    def test_real_validate_config_rejects_leading_new_before_runtime(self):
        runtime = Path(os.environ['NFQWS_TEST_RUNTIME'])
        with tempfile.TemporaryDirectory() as folder:
            paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': folder, 'KD_ALLOW_TEST_ROOT': '1'})
            base = Path(paths.nfqws_conf).parent
            (base / 'lists').mkdir(parents=True)
            (base / 'lists/youtube.list').write_text('example.org\n')
            args = list(VALID_ARGS['youtube'])
            args.remove('--new')
            args.insert(0, '--new')
            args = [token.replace('blob=quic_google', 'blob=fake_default_quic') for token in args]
            Path(paths.nfqws_conf).write_text('NFQWS_BASE_ARGS="--lua-init=@' + str(runtime / 'zapret-lib.lua')
                + ' --lua-init=@' + str(runtime / 'zapret-antidpi.lua') + '"\nNFQWS_ARGS="' + ' '.join(args)
                + '"\nTCP_PORTS=443\nUDP_PORTS=443\n')
            original = Path(paths.nfqws_conf).read_bytes()
            ctx = SimpleNamespace(paths=paths, environ=dict(os.environ))
            with self.assertRaisesRegex(nfqws_validate.ValidationError, 'invariants'):
                nfqws_validate.validate_config(ctx, paths.nfqws_conf)
            self.assertEqual(Path(paths.nfqws_conf).read_bytes(), original)




class FirewallSemanticGuards(unittest.TestCase):
    def verify(self, text):
        return nfqws_service.verify_rules(text, 'eth3', '443', '50000:50100', '300')

    def test_fin_rst_and_synack_do_not_replace_tcp_data(self):
        rows = firewall_rules().splitlines()
        for chain in ('nfqws_post', 'nfqws_pre'):
            text = '\n'.join(row for row in rows if not (row.startswith('-A ' + chain)
                            and '-p tcp ' in row and '--connbytes ' in row))
            with self.subTest(chain=chain), self.assertRaises(nfqws_service.ServiceError):
                self.verify(text)

    def test_replies_need_each_protocol_ports_queue_and_direction(self):
        original = firewall_rules()
        cases = [
            '\n'.join(row for row in original.splitlines() if not row.startswith('-A nfqws_pre ')),
            original.replace('--sports 443', '--sports 80'),
            original.replace('--sports 50000:50100', '--sports 50000:50010'),
            original.replace('--connbytes-dir reply', '--connbytes-dir original'),
            original.replace('--connbytes-dir original', '--connbytes-dir reply'),
            original.replace('--connbytes-mode packets', '--connbytes-mode bytes'),
            original.replace('--connbytes 1:15', '--connbytes 2:15'),
            original.replace('-i eth3', '-i eth4'),
            original.replace('--queue-num 300', '--queue-num 301'),
            original.replace(' --queue-num 300', ''),
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(nfqws_service.ServiceError):
                self.verify(text)

    def test_negated_selectors_cannot_prove_full_coverage(self):
        for before in ('-o eth3', '-i eth3', '-p tcp', '--dports 443', '--sports 443', '--connbytes 1:15'):
            text = firewall_rules().replace(before, '! ' + before)
            with self.subTest(selector=before), self.assertRaises(nfqws_service.ServiceError):
                self.verify(text)

    def test_real_shape_equal_options_and_split_ranges_are_accepted(self):
        self.verify(firewall_rules())
        text = firewall_rules().replace('--connbytes-dir ', '--connbytes-dir=').replace('--queue-num ', '--queue-num=')
        self.verify(text)
        self.verify(text.replace('FIN FIN', 'fin fin').replace('RST RST', 'rst rst'))
        rows = firewall_rules().splitlines()
        split = []
        for row in rows:
            if '-p udp ' in row:
                split.extend(row.replace('50000:50100', ports) for ports in ('50000:50050', '50051:50100'))
            else:
                split.append(row)
        self.verify('\n'.join(split))

    def test_opposite_direction_port_or_interface_restrictions_are_not_full_coverage(self):
        for before, after in (('-o eth3', '-o eth3 -i br0'), ('-i eth3', '-i eth3 -o br0'),
                              ('--dports 443', '--dports 443 --sports 1234'),
                              ('--sports 443', '--sports 443 --dports 1234')):
            with self.subTest(after=after), self.assertRaises(nfqws_service.ServiceError):
                self.verify(firewall_rules().replace(before, after))

    def test_only_proven_processed_mark_exception_can_count_as_payload_coverage(self):
        stock = firewall_rules()
        for mark in ('--mark 0x40000000/0x40000000', '! --mark 0x1/0x1', '! --mark 0/0',
                     '--mark 0x1/0x1', '! --mark malformed'):
            changed = stock.replace('! --mark 0x40000000/0x40000000', mark)
            with self.subTest(mark=mark), self.assertRaises(nfqws_service.ServiceError):
                self.verify(changed)
        self.verify(stock)
        self.verify(stock.replace(' -m mark ! --mark 0x40000000/0x40000000', ''))
        self.verify(stock.replace('! --mark 0x40000000/0x40000000', '--mark 0/0'))

    def test_custom_processed_exception_matches_actual_config_and_keeps_allowed_direct_mark(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = config.EnginePaths.from_environ({'KD_TEST_ROOT': folder, 'KD_ALLOW_TEST_ROOT': '1'})
            conf = Path(paths.nfqws_conf)
            conf.parent.mkdir(parents=True)
            conf.write_text('MARK_PROCESSED="1/3"\nNFQWS_ARGS="--filter-tcp=443"\n')
            _skip, processed = nfqws_marks.effective(paths, os.environ)
            nfqws_marks.validate(paths, '255', os.environ)
            custom = firewall_rules().replace('! --mark 0x40000000/0x40000000', '! --mark 0x1/0x3')
            nfqws_service.verify_rules(custom, 'eth3', '443', '50000:50100', '300', processed_mark=processed)
            # Numeric spelling and bits outside the mask do not alter the
            # normalized equality predicate required by this package contract.
            nfqws_service.verify_rules(custom.replace('0x1/0x3', '5/3'), 'eth3', '443', '50000:50100',
                                       '300', processed_mark=processed)
            for incorrect in (firewall_rules(), custom.replace('0x1/0x3', '0x1/0x1')):
                with self.subTest(rules=incorrect), self.assertRaises(nfqws_service.ServiceError):
                    nfqws_service.verify_rules(incorrect, 'eth3', '443', '50000:50100',
                                               '300', processed_mark=processed)
