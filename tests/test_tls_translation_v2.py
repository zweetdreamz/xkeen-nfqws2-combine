"""V2 translation and consumer parity; immutable legacy oracle stays independent."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import shlex
import subprocess
import tempfile
import unittest

from test_flowseal_phase9_corpus import TUNER, FIXTURE
from panel_fixtures import PanelUnitCase, make_candidate, make_report


class TranslationV2Tests(unittest.TestCase):
    def profile(self, *options):
        source = TUNER.SourceFile('general.bat', '', 'a' * 40, 'https://example.invalid')
        return TUNER.Profile(source, 1, (('dpi-desync', 'fake,multisplit'), *options))

    def test_order_duplicates_and_individual_modifiers(self):
        profile = self.profile(
            ('dpi-desync-fake-tls', '!'),
            ('dpi-desync-fake-tls-mod', 'rnd'),
            ('dpi-desync-fake-tls', '!'),
            ('dpi-desync-fake-tls-mod', 'dupsid'),
            ('dpi-desync-repeats', '6'),
        )
        result = TUNER.translate_tls_v2(profile, 'youtube')
        self.assertEqual(result.reasons, ())
        fakes = [a for a in result.candidate.args if a.startswith('--lua-desync=fake:')]
        self.assertEqual(fakes, [
            '--lua-desync=fake:blob=fake_default_tls:repeats=6:tls_mod=rnd',
            '--lua-desync=fake:blob=fake_default_tls:repeats=6:tls_mod=dupsid',
        ])

    def test_ip_id_only_on_emitting_functions(self):
        result = TUNER.translate_tls_v2(self.profile(('ip-id', 'zero')), 'discord-tcp')
        functions = [a for a in result.candidate.args if a.startswith('--lua-desync=')]
        self.assertEqual(len(functions), 2)
        self.assertTrue(all(a.endswith(':ip_id=zero') for a in functions))
        self.assertFalse(any('pktmod' in a for a in result.candidate.args))

    def test_explicit_rejections(self):
        for option, reason in [
            (('dpi-desync-hostfakesplit-mod', 'host=example.com,altorder=1'), 'unsupported-altorder'),
            (('dpi-desync-fake-tls', 'unknown_google.bin'), 'unsupported-fake-asset'),
            (('dpi-desync-fake-tls', '0x123'), 'unsupported-fake-asset'),
            (('ip-id', 'random'), 'unsupported-ip-id'),
            (('dpi-desync-fake-tls-mod', 'unknown'), 'invalid-tls-mod'),
            (('dpi-desync-fake-tls-mod', 'none,rnd'), 'unsupported-mixed-none-mod'),
            (('dpi-desync-hostfakesplit-mod', 'unknown=1'), 'unsupported-hostfakesplit-mod'),
            (('dpi-desync-repeats', '0'), 'invalid-repeats'),
            (('dpi-desync-fooling', 'unknown'), 'unsupported-fooling'),
            (('dpi-desync-split-pos', '1;id'), 'invalid-split-position'),
            (('dpi-desync-fake-tls', 'a' * 513), 'source-budget-exceeded'),
        ]:
            with self.subTest(option=option):
                result = TUNER.translate_tls_v2(self.profile(option), 'youtube')
                self.assertIsNone(result.candidate)
                self.assertEqual(result.reasons, (reason,))

    def test_mod_inheritance_and_rejected_hex_mod(self):
        profile = self.profile(('dpi-desync-fake-tls-mod', 'rnd'),
                               ('dpi-desync-fake-tls', '!'), ('dpi-desync-fake-tls', '!'))
        candidate = TUNER.translate_tls_v2(profile, 'youtube').candidate
        fakes = [a for a in candidate.args if a.startswith('--lua-desync=fake:')]
        self.assertEqual(len(fakes), 2)
        self.assertEqual(fakes[0], fakes[1])
        self.assertIn(':tls_mod=rnd', fakes[0])
        result = TUNER.translate_tls_v2(self.profile(('dpi-desync-fake-tls', '0x0000'),
                                                    ('dpi-desync-fake-tls-mod', 'rnd')), 'youtube')
        self.assertEqual(result.reasons, ('unsupported-hex-tls-mod',))
        self.assertIsNone(result.candidate)

    def test_unchanged_arguments_keep_identity(self):
        profile = self.profile(('dpi-desync-fake-tls', '!'), ('dpi-desync-split-pos', 'midsld'))
        old = TUNER.translate_tls_profile(profile, 'youtube')
        new = TUNER.translate_tls_v2(profile, 'youtube').candidate
        self.assertEqual(old.args, new.args)
        self.assertEqual(old.candidate_id, new.candidate_id)

    def test_implicit_default_randomization_is_not_explicit_bang(self):
        implicit = TUNER.translate_tls_v2(self.profile(), 'youtube').candidate
        explicit = TUNER.translate_tls_v2(self.profile(('dpi-desync-fake-tls', '!')), 'youtube').candidate
        self.assertIn('--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,rndsni,dupsid', implicit.args)
        self.assertIn('--lua-desync=fake:blob=fake_default_tls', explicit.args)
        self.assertNotEqual(implicit.candidate_id, explicit.candidate_id)

    def test_badseq_advances_by_blob_size_not_repeats(self):
        profile = self.profile(('dpi-desync-fake-tls', '0x00000000'),
                               ('dpi-desync-fake-tls', '!'),
                               ('dpi-desync-fake-tls-mod', 'rnd,dupsid,sni=www.google.com'),
                               ('dpi-desync-fooling', 'badseq'), ('dpi-desync-repeats', '11'))
        result = TUNER.translate_tls_v2(profile, 'youtube')
        self.assertEqual(result.reasons, ())
        fakes = [a for a in result.candidate.args if a.startswith('--lua-desync=fake:')]
        self.assertIn('tcp_seq=-10000', fakes[0].split(':'))
        self.assertIn('tcp_seq=-9996', fakes[1].split(':'))
        self.assertTrue(all('repeats=11' in a.split(':') for a in fakes))

    def test_badseq_rejects_unknown_previous_modified_length(self):
        result = TUNER.translate_tls_v2(self.profile(
            ('dpi-desync-fake-tls', '!'), ('dpi-desync-fake-tls-mod', 'padencap'),
            ('dpi-desync-fake-tls', '!'), ('dpi-desync-fooling', 'badseq')), 'youtube')
        self.assertIsNone(result.candidate)
        self.assertEqual(result.reasons, ('unsupported-multi-fake-sequence-length',))

    def test_adversarial_options_are_bounded_results_not_exceptions(self):
        rng = random.Random(90203)
        fields = ('dpi-desync-fake-tls', 'dpi-desync-fake-tls-mod', 'dpi-desync-repeats',
                  'dpi-desync-split-pos', 'dpi-desync-fooling', 'dpi-desync-badseq-increment')
        values = ['²', '١', ',', 'rnd,', 'none', '!', '0x00', '0x123', 'a' * 513,
                  'sni=' + 'a' * 498, 'sni=example.com', '0', '999999999999999999999',
                  'foo;id', '@evil.lua', '1,midsld', '\n', 'badseq', 'rnd,dupsid']
        for index in range(200):
            options = tuple((rng.choice(fields), rng.choice(values)) for _ in range(rng.randint(1, 5)))
            with self.subTest(index=index, options=options):
                result = TUNER.translate_tls_v2(self.profile(*options), 'discord-tcp')
                if result.candidate is None:
                    self.assertTrue(result.reasons)
                else:
                    TUNER.validate_args(result.candidate.args)
                    self.assertFalse(result.reasons)

    def test_frozen_corpus_change_set_and_final_quic_ids(self):
        import sys
        sys.path.insert(0, str(FIXTURE.parents[3] / 'tools/dev'))
        self.addCleanup(sys.path.pop, 0)
        spec = importlib.util.spec_from_file_location('phase9_changes', FIXTURE.parents[3] / 'tools/dev/report_flowseal_translation.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.changes(FIXTURE)
        self.assertEqual(report['counts'], dict(changed=27, rejected=13, unchanged=23))
        self.assertEqual(report['reasons'], {
            'unsupported-altorder': 4, 'unsupported-fake-asset': 5, 'unsupported-pattern-asset': 4})
        expected = {
            'youtube/off': (16, 17, 1), 'youtube/safe': (40, 40, 7),
            'youtube/extended': (75, 81, 14), 'discord-tcp/off': (23, 17, 11),
            'discord-tcp/safe': (57, 40, 29), 'discord-tcp/extended': (83, 69, 42),
        }
        for name, (old, new, unchanged) in expected.items():
            with self.subTest(search=name):
                entry = report['search'][name]
                self.assertEqual((entry['old'], entry['new'], entry['unchanged']), (old, new, unchanged))
                self.assertEqual(len(entry['added']), new - unchanged)
                self.assertEqual(len(entry['removed']), old - unchanged)
        for row in report['rows']:
            with self.subTest(source=row['source'], profile=row['profile'], service=row['service']):
                if row['status'] == 'unchanged':
                    self.assertEqual(row['old_id'], row['new_id'])
                    self.assertEqual(row['old_final_id'], row['new_final_id'])
                elif row['status'] == 'changed':
                    self.assertNotEqual(row['old_id'], row['new_id'])
                    self.assertNotEqual(row['old_final_id'], row['new_final_id'])
                else:
                    self.assertIsNone(row['new_id'])
                    self.assertTrue(row['reasons'])

    def test_legacy_disorder_split_components_and_position_variants(self):
        profile = self.profile(('dpi-desync', 'fake,multidisorder'),
                               ('dpi-desync-split-pos', '1,midsld'), ('dpi-desync-fake-tls', '!'))
        candidate = TUNER.translate_tls_v2(profile, 'discord-tcp').candidate
        base, fake, split = TUNER.split_components(candidate)
        self.assertTrue(base)
        self.assertTrue(fake.startswith('--lua-desync=fake:'))
        self.assertEqual(split, '--lua-desync=multidisorder_legacy:pos=1,midsld')
        mutated = TUNER.mutate_tls_recipe(candidate.args, position='midsld')
        self.assertIn('--lua-desync=multidisorder_legacy:pos=midsld', mutated)
        self.assertEqual([a for a in mutated if a != '--lua-desync=multidisorder_legacy:pos=midsld'],
                         [a for a in candidate.args if a != split])
        sources = [profile.source]
        sweeps = TUNER.parameter_sweep_candidates('discord-tcp', [candidate], sources, 'extended', base=candidate)
        self.assertTrue(any('--lua-desync=multidisorder_legacy:pos=midsld' in c.args for c in sweeps))
        mixes = TUNER.mixed_candidates('discord-tcp', [candidate], sources, 'safe')
        self.assertTrue(any(split in c.args for c in mixes))
        self.assertTrue(all(c.args.count(split) == 1 for c in mixes if split in c.args))

    def test_production_build_uses_v2_and_reports_rejections(self):
        from unittest import mock

        valid = self.profile(('dpi-desync-fake-tls', '!'), ('dpi-desync-fake-tls', '!'), ('ip-id', 'zero'))
        invalid = self.profile(('dpi-desync-hostfakesplit-mod', 'altorder=1'))
        rejected = []
        with mock.patch.object(TUNER, 'parse_profiles', return_value=[valid, invalid]), \
                mock.patch.object(TUNER, 'profile_roles', return_value=['discord-tcp']):
            candidates = TUNER.build_candidates('discord-tcp', [valid.source], 'off',
                                               include_builtin=False, translation_rejections=rejected)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].args, TUNER.translate_tls_v2(valid, 'discord-tcp').candidate.args)
        self.assertEqual(rejected[0]['reasons'], ['unsupported-altorder'])
        self.assertEqual(TUNER.split_components(candidates[0])[1:], (None, None))
        mutated = TUNER.mutate_tls_recipe(candidates[0].args, repeats='3')
        self.assertEqual(sum(a.startswith('--lua-desync=fake:') for a in mutated), 2)
        self.assertTrue(all('ip_id=zero' in a.split(':')[1:] for a in mutated if a.startswith('--lua-desync=')))


class TranslationV2PolicyTests(PanelUnitCase):
    def runner_accepts(self, args):
        template = (FIXTURE.parents[3] / 'tools/windows/router-candidate-runner.sh').read_text()
        function = template.split('validate_candidate_args() {', 1)[1].split('\nstart_candidate()', 1)[0]
        script = 'validate_candidate_args() {' + function + '\nvalidate_candidate_args ' + shlex.quote(' '.join(args))
        return subprocess.run(['sh', '-c', script], capture_output=True, timeout=3, check=False).returncode == 0

    def test_all_accepted_corpus_profiles_pass_every_validator(self):
        from kdn.engine import profile_descriptor

        for source in json.loads(FIXTURE.read_bytes())['files']:
            origin = TUNER.SourceFile(source['name'], '', source['sha'], source['url'])
            for item in source['profiles']:
                profile = TUNER.Profile(origin, item['number'], tuple(tuple(pair) for pair in item['options']))
                for service in sorted(set(item['roles']) & {'youtube', 'discord-tcp'}):
                    result = TUNER.translate_tls_v2(profile, service)
                    if result.candidate is None:
                        continue
                    args = list(result.candidate.args)
                    if service == 'youtube':
                        args += ['--new', *TUNER.NATIVE_QUIC]
                    with self.subTest(source=origin.name, profile=profile.number, service=service):
                        TUNER.validate_args(args)
                        candidate = make_candidate(service, args=args)
                        descriptor = self.ns['validate_candidate'](candidate, make_report(service, candidate))
                        self.assertEqual(profile_descriptor.validate_descriptor(descriptor), descriptor)
                        self.assertTrue(self.runner_accepts(args))

    def test_stored_multidisorder_and_legacy_name_both_pass_every_validator(self):
        from kdn.engine import profile_descriptor

        for name in ('multidisorder', 'multidisorder_legacy'):
            with self.subTest(name=name):
                args = [a for a in make_candidate()['args'] if not a.startswith('--lua-desync=')]
                args.append('--lua-desync=' + name + ':pos=1,midsld')
                TUNER.validate_args(args)
                candidate = make_candidate(args=args)
                descriptor = self.ns['validate_candidate'](candidate, make_report(candidate=candidate))
                self.assertEqual(profile_descriptor.validate_descriptor(descriptor), descriptor)
                self.assertTrue(self.runner_accepts(args))

    def test_negative_policy_parity(self):
        from kdn.engine import profile_descriptor

        for token in ('--lua-init=@/tmp/evil.lua', '--lua-desync=pktmod:ip_id=zero',
                      '--lua-desync=fake:blob=fake_default_tls:ip_id=bad',
                      '--lua-desync=fake:blob=x;id', '--qnum=42'):
            with self.subTest(token=token):
                candidate = make_candidate(args=[*make_candidate()['args'], token])
                with self.assertRaises(ValueError):
                    TUNER.validate_args(candidate['args'])
                with self.assertRaises(ValueError):
                    self.ns['validate_candidate'](candidate, make_report(candidate=candidate))
                descriptor = {key: value for key, value in candidate.items()}
                descriptor['format'] = 1
                with self.assertRaises(ValueError):
                    profile_descriptor.validate_descriptor(descriptor)
                self.assertFalse(self.runner_accepts(candidate['args']))


class TranslationV2PacketTests(unittest.TestCase):
    def corpus_candidate(self, name):
        row = next(row for row in json.loads(FIXTURE.read_bytes())['files'] if row['name'] == name)
        item = next(item for item in row['profiles'] if 'youtube' in item['roles'])
        source = TUNER.SourceFile(row['name'], '', row['sha'], row['url'])
        profile = TUNER.Profile(source, item['number'], tuple(tuple(pair) for pair in item['options']))
        result = TUNER.translate_tls_v2(profile, 'youtube')
        self.assertEqual(result.reasons, ())
        return result.candidate

    def emitted(self, recipe, case='single'):
        runtime = Path(os.environ['NFQWS_TEST_RUNTIME'])
        harness = (FIXTURE.parent / 'packet-flowseal-v2.lua').read_text()
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / 'emission.lua'
            script.write_text('RECIPE=' + json.dumps(recipe.split('=', 1)[1])
                              + '\nCASE=' + json.dumps(case) + '\n' + harness)
            done = subprocess.run([str(runtime / 'nfqws2'), '--intercept=0',
                                   '--lua-init=@' + str(runtime / 'zapret-lib.lua'),
                                   '--lua-init=@' + str(runtime / 'zapret-antidpi.lua'),
                                   '--lua-init=@' + str(script)],
                                  capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('FLOWSEAL_EMISSION_OK', done.stdout)
        return [tuple(map(int, line.partition('=')[2].split(',')))
                for line in done.stdout.splitlines() if line.startswith('PACKET=')]

    def test_alt_split_repeats_only_fake_bursts(self):
        candidate = self.corpus_candidate('general (ALT).bat')
        recipe = next(a for a in candidate.args if a.startswith('--lua-desync=fakedsplit:'))
        packets = self.emitted(recipe)
        self.assertEqual(len(packets), 26)  # four fake bursts * 6 + two real pieces
        self.assertEqual(packets.count((100, 2)), 13)
        self.assertEqual(packets.count((102, 678)), 13)

    def test_alt_default_split_position_is_two(self):
        candidate = self.corpus_candidate('general (ALT).bat')
        recipe = next(a for a in candidate.args if a.startswith('--lua-desync=fakedsplit:'))
        self.assertEqual(sorted(set(self.emitted(recipe))), [(100, 2), (102, 678)])

    def test_alt9_repeats_only_fake_host_bursts(self):
        candidate = self.corpus_candidate('general (ALT9).bat')
        recipe = next(a for a in candidate.args if a.startswith('--lua-desync=hostfakesplit:'))
        packets = self.emitted(recipe)
        self.assertEqual(len(packets), 11)  # two fake bursts * 4 + three real pieces
        self.assertEqual(packets, [(100, 125)] + [(225, 17)] * 9 + [(242, 538)])

    def test_auto_multidisorder_preserves_order_of_two_replay_pieces(self):
        candidate = self.corpus_candidate('general (FAKE TLS AUTO).bat')
        recipe = next(a for a in candidate.args if a.startswith('--lua-desync=multidisorder'))
        expected = [(233, 867), (101, 132), (100, 1), (1100, 1000)]
        self.assertEqual(self.emitted(recipe, 'reasm'), expected)
        # Independent contrast: current nfqws2 operates on the whole reassembly.
        modern = recipe.replace('multidisorder_legacy:', 'multidisorder:')
        self.assertNotEqual(self.emitted(modern, 'reasm'), expected)

    def test_all_supported_corpus_calls_initialize_in_pinned_runtime(self):
        from kdn.engine import nfqws_validate

        runtime = Path(os.environ.get('NFQWS_TEST_RUNTIME', '/var/cache/kdn/nfqws2-blobs/runtime'))
        if not (runtime / 'nfqws2').is_file():
            self.skipTest('pinned runtime required; run offline Docker suite')
        tokens = ['--lua-init=@' + str(runtime / 'zapret-lib.lua'),
                  '--lua-init=@' + str(runtime / 'zapret-antidpi.lua'),
                  '--blob=tls_clienthello:@' + str(runtime.parent / 'tls_clienthello.bin')]
        count = 0
        for row in json.loads(FIXTURE.read_bytes())['files']:
            source = TUNER.SourceFile(row['name'], '', row['sha'], row['url'])
            for item in row['profiles']:
                for service in set(item['roles']) & {'youtube', 'discord-tcp'}:
                    p = TUNER.Profile(source, item['number'], tuple(tuple(pair) for pair in item['options']))
                    result = TUNER.translate_tls_v2(p, service)
                    if result.candidate:
                        if count:
                            tokens.append('--new')
                        # Local initialization needs no router-only hostlist file.
                        tokens.extend(a for a in result.candidate.args if not a.startswith('--hostlist='))
                        count += 1
        self.assertEqual(count, 50)
        result = nfqws_validate.validate_tokens(tokens, runtime / 'nfqws2', os.environ,
                                               expected_binary_sha256=nfqws_validate.PINNED_X86_SHA256)
        self.assertIn('--intercept=0', result.argv)

    def test_pinned_lua_packet_emission(self):
        from kdn.engine import nfqws_validate

        runtime = Path(os.environ.get('NFQWS_TEST_RUNTIME', '/var/cache/kdn/nfqws2-blobs/runtime'))
        if not (runtime / 'nfqws2').is_file():
            self.skipTest('pinned runtime required; run offline Docker suite')
        self.assertEqual(hashlib.sha256((runtime / 'nfqws2').read_bytes()).hexdigest(),
                         nfqws_validate.PINNED_X86_SHA256)
        for name in ('zapret-lib.lua', 'zapret-antidpi.lua'):
            self.assertEqual(hashlib.sha256((runtime / name).read_bytes()).hexdigest(),
                             nfqws_validate.PINNED_LUA_SHA256[name])
        done = subprocess.run([
            str(runtime / 'nfqws2'), '--intercept=0',
            '--lua-init=@' + str(runtime / 'zapret-lib.lua'),
            '--lua-init=@' + str(runtime / 'zapret-antidpi.lua'),
            '--lua-init=@' + str(FIXTURE.parent / 'packet-emission-v2.lua'),
        ], capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('PACKET_EMISSION_V2_OK', done.stdout)
        hexline = next(line for line in done.stdout.splitlines() if line.startswith('DEFAULTHEX='))
        blob = bytes.fromhex(hexline.partition('=')[2])
        self.assertEqual(len(blob), 680)
        self.assertEqual(hashlib.sha256(blob).hexdigest(),
                         '11d33b3d926b1702a56a0757672e39ba6ec1ba113a7f8063b743d4c900bbc666')
