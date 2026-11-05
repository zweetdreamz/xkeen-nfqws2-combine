"""Persisted descriptor validation: canonical panel parity, bounded legacy schema."""
import copy
import json
import os
from pathlib import Path
import shlex
import tempfile

import engine_shell
from panel_fixtures import PanelUnitCase, make_candidate, make_report
from kdn.engine import profile_descriptor

PROFILE_ORACLE = (Path(__file__).parent / 'fixtures/engine/profile-validator-before-phase5.sh.txt').read_text(encoding='utf-8')


class DescriptorTests(PanelUnitCase):
    def descriptor(self, service='discord-tcp', **changes):
        candidate = make_candidate(service, **changes)
        return self.ns['validate_candidate'](candidate, make_report(service, candidate))

    def test_canonical_panel_output_is_unchanged(self):
        for service in ('youtube', 'discord-tcp', 'discord-voice'):
            with self.subTest(service=service):
                value = self.descriptor(service)
                self.assertEqual(profile_descriptor.validate_descriptor(value), value)
                self.assertEqual(profile_descriptor.candidate_id(value), value['candidate_id'])

    def test_return_is_detached_and_input_not_changed(self):
        value = self.descriptor()
        original = copy.deepcopy(value)
        result = profile_descriptor.validate_descriptor(value)
        result['args'].append('--new')
        result['notes'].append('new')
        result['report']['commit'] = 'changed'
        self.assertEqual(value, original)

    def test_schema_rejects_unknown_fields_types_and_limits(self):
        for change in ({'format': 2}, {'format': True}, {'unknown': 1}, {'rank': True},
                       {'rank': float('inf')}, {'rank': float('nan')}, {'notes': 'scalar'},
                       {'args': [1]},
                       {'rank': 100001}, {'notes': ['x'] * 21}, {'source_name': ''},
                       {'source_sha': 'x\n'}, {'report': {'unknown': ''}},
                       {'report': {'search_seed': True}}, {'report': {'search_seed': -1}},
                       {'args': []}, {'candidate_id': '0' * 12}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                profile_descriptor.validate_descriptor(dict(self.descriptor(), **change))
        for value in (None, [], '', 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                profile_descriptor.validate_descriptor(value)

    def test_report_optional_defaults_and_integer_json_numbers(self):
        value = self.descriptor()
        value.pop('report')
        value['rank'] = 3.0
        result = profile_descriptor.validate_descriptor(value)
        self.assertNotIn('report', result)
        value['report'] = {'search_seed': 42.0, 'commit': None}
        self.assertEqual(profile_descriptor.validate_descriptor(value), value)

    def test_payload_boundary_matches_legacy_not_panel_gap(self):
        for service in ('youtube', 'discord-tcp'):
            value = self.descriptor(service)
            value['args'].append('--payload=unexpected')
            value['candidate_id'] = profile_descriptor.candidate_id(value)
            with self.subTest(service=service), self.assertRaises(ValueError):
                profile_descriptor.validate_descriptor(value)

    def test_voice_range_is_explicit_not_read_from_router(self):
        value = self.descriptor('discord-voice')
        value['args'][0] = '--filter-udp=50000-65535'
        value['candidate_id'] = profile_descriptor.candidate_id(value)
        self.assertEqual(profile_descriptor.validate_descriptor(value), value)
        with self.assertRaises(ValueError):
            profile_descriptor.validate_descriptor(value, voice_high=50100)
        for high in (None, True, 65535.0, '65535', 0, 65536):
            with self.subTest(high=high), self.assertRaises(ValueError):
                profile_descriptor.validate_descriptor(value, voice_high=high)

    def test_hash_inputs_order_and_utf8_are_existing_contract(self):
        value = self.descriptor()
        previous = value['candidate_id']
        value['source_name'] = 'пример.bat'
        value['candidate_id'] = profile_descriptor.candidate_id(value)
        self.assertNotEqual(value['candidate_id'], previous)
        self.assertEqual(profile_descriptor.validate_descriptor(value), value)
        value['args'] = list(reversed(value['args']))
        with self.assertRaises(ValueError):
            profile_descriptor.validate_descriptor(value)

    def test_rejects_unsafe_options_strategies_and_service_crossing(self):
        for token in ('--queue-num=1', '--lua-desync=unknown', '--hostlist=/tmp/other',
                      '--filter-udp=443', '--payload=quic_initial', '--new', '--out-range=x;id'):
            value = self.descriptor()
            value['args'].append(token)
            value['candidate_id'] = profile_descriptor.candidate_id(value)
            with self.subTest(token=token), self.assertRaises(ValueError):
                profile_descriptor.validate_descriptor(value)

    def test_legacy_acceptance_matches_persisted_schema_vectors(self):
        vectors = [self.descriptor(service) for service in ('youtube', 'discord-tcp', 'discord-voice')]
        for change in ({'format': True}, {'rank': 2.5}, {'unknown': ''}, {'report': []},
                       {'report': None}, {'report': False}, {'report': {'search_seed': False}},
                       {'report': {'commit': False}}, {'report': {'search_seed': 42.0}},
                       {'report': {'search_seed': None}},
                       {'report': {'search_seed': True}}, {'rank': 3.0}, {'report': {'commit': None}},
                       {'notes': ['x'] * 21}, {'candidate_id': '0' * 12}):
            vectors.append(dict(self.descriptor(), **change))
        for service in ('youtube', 'discord-tcp'):
            value = self.descriptor(service)
            value['args'].append('--payload=unexpected')
            value['candidate_id'] = profile_descriptor.candidate_id(value)
            vectors.append(value)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'descriptor.json'
            for number, value in enumerate(vectors):
                with self.subTest(number=number, value=value):
                    path.write_text(json.dumps(value), encoding='utf-8')
                    done = engine_shell.run_function(
                        'validate_imported_profile', str(path),
                        defs=('have() { command -v "$1" >/dev/null 2>&1; }',
                              'make_tmp() { mktemp; }', 'voice_ports_allowed', PROFILE_ORACLE),
                        variables={'VOICE_RANGE_CHECK': 0, 'VOICE_HIGH': 50100},
                        env=dict(os.environ, TMPDIR=temporary),
                        shell=shlex.split(os.environ.get('TEST_SHELL', 'sh')),
                    )
                    try:
                        profile_descriptor.validate_descriptor(value)
                    except ValueError:
                        accepted = False
                    else:
                        accepted = True
                    self.assertEqual(accepted, done.returncode == 0, done.stderr)

    def test_all_required_fields_must_be_present(self):
        for field in profile_descriptor.FIELDS - {'report'}:
            value = self.descriptor()
            value.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                profile_descriptor.validate_descriptor(value)

    def test_nul_is_explicit_transport_safety_deviation(self):
        value = self.descriptor()
        value['notes'] = ['ambiguous\0text']
        with self.assertRaises(ValueError):
            profile_descriptor.validate_descriptor(value)

    def test_unpaired_surrogates_in_metadata_fail_before_publication(self):
        for change in ({'notes': ['bad\ud800']}, {'source_url': '\ud800'}, {'report': {'repository': '\ud800'}}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'UTF-8'):
                profile_descriptor.validate_descriptor(dict(self.descriptor(), **change))

    def test_voice_extra_payload_exposes_legacy_panel_gap(self):
        value = self.descriptor('discord-voice')
        value['args'].append('--payload=unexpected')
        value['candidate_id'] = profile_descriptor.candidate_id(value)
        with self.assertRaises(ValueError):
            profile_descriptor.validate_descriptor(value)
        with self.assertRaises(ValueError):
            self.ns['validate_candidate'](value, {})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'descriptor.json'
            path.write_text(json.dumps(value), encoding='utf-8')
            done = engine_shell.run_function(
                'validate_imported_profile', str(path),
                defs=('have() { command -v "$1" >/dev/null 2>&1; }',
                      'make_tmp() { mktemp; }', 'voice_ports_allowed', PROFILE_ORACLE),
                variables={'VOICE_RANGE_CHECK': 0, 'VOICE_HIGH': 50100},
                env=dict(os.environ, TMPDIR=temporary),
                shell=shlex.split(os.environ.get('TEST_SHELL', 'sh')),
            )
            self.assertEqual(done.returncode, 0, done.stderr)

    def test_panel_report_rejects_profile_boundary_and_missing_desync_vectors(self):
        for service in ('youtube', 'discord-tcp', 'discord-voice'):
            value = self.descriptor(service)
            variants = [[token for token in value['args'] if not token.startswith('--lua-desync=')]]
            if service == 'youtube':
                merged = [token for token in value['args'] if token != '--new']
                variants.extend([['--new', *merged], [*merged, '--new'],
                                 [*value['args'][:4], '--new', *value['args'][4:5], *value['args'][6:]]])
            for args in variants:
                candidate = dict(value, args=args)
                candidate['candidate_id'] = profile_descriptor.candidate_id(candidate)
                with self.subTest(service=service, args=args), self.assertRaises(ValueError):
                    self.ns['validate_report'](make_report(service, candidate))
