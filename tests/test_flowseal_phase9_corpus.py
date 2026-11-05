"""Immutable input/baseline characterization for P9.1; no network or BAT execution.

P9.2 must explicitly classify changed outputs/IDs against this old baseline,
not silently regenerate the fixture when translation changes.
"""
import dataclasses
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/flowseal/phase9-176f56dc3f11.json'
FIXTURE_SHA256 = '5486ab65efd2f97893821bf8380054b81f0c0da124d3cf88242bba9233b3e9a1'
COMMIT = '176f56dc3f11ce5915c26abcdde903f93d835b64'
SPEC = importlib.util.spec_from_file_location('phase9_capture', ROOT / 'tools/dev/capture_flowseal_corpus.py')
CAPTURE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CAPTURE
SPEC.loader.exec_module(CAPTURE)
TUNER = CAPTURE.TUNER


class Phase9CorpusTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(FIXTURE.read_bytes())

    def test_pinned_identity_and_complete_counts(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes().replace(b'\r\n', b'\n')).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(self.data['commit'], COMMIT)
        self.assertEqual(self.data['repository'], TUNER.DEFAULT_REPOSITORY)
        self.assertEqual(len(self.data['files']), 22)
        self.assertEqual(sum(len(row['profiles']) for row in self.data['files']), 195)
        self.assertEqual(sum(len(p['baseline']) for row in self.data['files'] for p in row['profiles']), 85)
        for row in self.data['files']:
            with self.subTest(source=row['name']):
                self.assertTrue(TUNER.SOURCE_NAME_RE.fullmatch(row['name']))
                self.assertRegex(row['sha'], r'^[a-f0-9]{40}$')
                self.assertRegex(row['raw_sha256'], r'^[a-f0-9]{64}$')
                self.assertIn('/' + COMMIT + '/', row['url'])

    def test_current_translation_matches_frozen_baseline_for_every_profile(self):
        for row in self.data['files']:
            source = TUNER.SourceFile(row['name'], '', row['sha'], row['url'])
            for value in row['profiles']:
                profile = TUNER.Profile(source, value['number'], tuple(tuple(pair) for pair in value['options']))
                with self.subTest(source=row['name'], profile=profile.number):
                    self.assertEqual(sorted(TUNER.profile_roles(profile)), value['roles'])
                    translated = []
                    for service in value['roles']:
                        candidate = (TUNER.translate_tls_profile(profile, service) if service in ('youtube', 'discord-tcp')
                                     else TUNER.translate_voice_profile(profile) if service == 'discord-voice' else None)
                        if candidate is not None:
                            translated.append(json.loads(json.dumps(dataclasses.asdict(candidate))))
                    self.assertEqual(translated, value['baseline'])

    def test_targeted_loss_vectors_are_present_in_real_corpus(self):
        counts = dict(tls=0, ip_id_zero=0, altorder=0, multi_tls=0)
        for row in self.data['files']:
            for value in row['profiles']:
                if not set(value['roles']) & {'youtube', 'discord-tcp'}:
                    continue
                counts['tls'] += 1
                options = value['options']
                counts['ip_id_zero'] += ['ip-id', 'zero'] in options
                counts['altorder'] += any(name == 'dpi-desync-hostfakesplit-mod' and 'altorder=' in (text or '')
                                         for name, text in options)
                counts['multi_tls'] += sum(name == 'dpi-desync-fake-tls' for name, _text in options) > 1
        self.assertEqual(counts, dict(tls=63, ip_id_zero=20, altorder=4, multi_tls=11))

    def test_capture_checks_git_blob_before_parsing_and_uses_immutable_urls(self):
        raw = b'--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=fake\r\n'
        sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        listing = [{'name': 'general.bat', 'type': 'file', 'sha': sha, 'download_url': 'https://untrusted.invalid'}]
        with mock.patch.object(CAPTURE, 'read', side_effect=[json.dumps(listing).encode(), raw]) as read:
            cache, fixture = CAPTURE.capture(COMMIT)
            self.assertEqual(len(cache['sources']), 1)
            self.assertEqual(fixture['files'][0]['sha'], sha)
            self.assertTrue(read.call_args.args[0].startswith('https://raw.githubusercontent.com/Flowseal/'))
            self.assertIn(COMMIT, read.call_args.args[0])
        listing[0]['sha'] = '0' * 40
        with mock.patch.object(CAPTURE, 'read', side_effect=[json.dumps(listing).encode(), raw]):
            with self.assertRaisesRegex(ValueError, 'Git blob mismatch'):
                CAPTURE.capture(COMMIT)
        with self.assertRaisesRegex(ValueError, 'immutable commit'):
            CAPTURE.capture('main')
