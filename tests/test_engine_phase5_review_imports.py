"""Regressions for final review: never guess routes or accept ambiguous queues."""
from pathlib import Path
import unittest
from unittest import mock

import test_engine_import_ops as import_fixtures
import test_engine_nfqws_service_extra as service_fixtures

from kdn.engine import import_ops, nfqws_service


class ImportRouteReviewTests(unittest.TestCase):
    setUp = import_fixtures.ImportOperationsTests.setUp
    context = import_fixtures.ImportOperationsTests.context
    seams = import_fixtures.ImportOperationsTests.seams

    def test_missing_or_invalid_route_is_refused_before_precheck_snapshot_or_service(self):
        variants = (
            self.initial.replace(b'# Active routes:', b'# Removed routes:'),
            self.initial.replace(b'DiscordTCP=zapret', b'DiscordTCP=unknown'),
            self.initial.replace(b'DiscordVoice=zapret', b'DiscordVoice='),
            self.initial.replace(b'YouTube=zapret', b'YouTube=invalid'),
        )
        for raw in variants:
            with self.subTest(raw=raw):
                target = Path(self.paths.nfqws_conf)
                target.write_bytes(raw)
                with self.seams(), mock.patch.object(import_ops, '_capture') as capture:
                    self.assertEqual(import_ops.run(self.context()), 1, self.err.getvalue())
                    self.validate.assert_not_called()
                    capture.assert_not_called()
                    self.restart.assert_not_called()
                    import_ops.nfqws_service.action.assert_not_called()
                self.assertEqual(target.read_bytes(), raw)
                self.assertFalse((target.parent / 'imported-profiles/discord-tcp.json').exists())
                self.assertFalse((Path(self.paths.state_root) / 'nfqws-import-snapshots').exists())
                self.assertFalse(Path(self.paths.lock_dir).exists())

    def test_clear_does_not_guess_routes_or_remove_stored_profile(self):
        with self.seams():
            self.assertEqual(import_ops.run(self.context()), 0, self.err.getvalue())
        profile = Path(self.paths.nfqws_conf).parent / 'imported-profiles/discord-tcp.json'
        original_profile = profile.read_bytes()
        pointer = Path(self.paths.state_root) / 'latest-nfqws-import.ptr'
        original_pointer = pointer.read_bytes()
        config = Path(self.paths.nfqws_conf)
        config.write_bytes(config.read_bytes().replace(b'DiscordVoice=zapret', b'DiscordVoice=invalid'))
        original_config = config.read_bytes()
        with self.seams(), mock.patch.object(import_ops, '_capture') as capture:
            self.assertEqual(import_ops.run(self.context(['--clear-imported-profile', 'discord-tcp', '--yes-router'])), 1)
            self.validate.assert_not_called()
            capture.assert_not_called()
            self.restart.assert_not_called()
        self.assertEqual(config.read_bytes(), original_config)
        self.assertEqual(profile.read_bytes(), original_profile)
        self.assertEqual(pointer.read_bytes(), original_pointer)

    def test_legacy_combined_discord_route_header_remains_supported(self):
        target = Path(self.paths.nfqws_conf)
        raw = b'\n'.join(line for line in self.initial.split(b'\n') if not line.startswith(b'# Active routes:'))
        raw += b'\n# Active routes: Discord=zapret, YouTube=vless, Telegram=vless.\n'
        target.write_bytes(raw)
        self.assertEqual(import_ops._context(self.context())[1], ('zapret', 'zapret', 'vless', 'vless'))


class ServiceQueueReviewTests(unittest.TestCase):
    setUp = service_fixtures.ServiceVerifyExtraTests.setUp

    def test_duplicate_wrong_and_missing_daemon_queue_refused_before_firewall(self):
        for queues in ([], ['300', '301'], ['300', '300'], ['301']):
            actual = ['nfqws2', *('--qnum=' + value for value in queues), *self.tokens]
            self.cmdline.write_bytes(('\0'.join(actual) + '\0').encode())
            with self.subTest(queues=queues), self.assertRaises(nfqws_service.ServiceError):
                nfqws_service.verify(self.ctx, 76, attempts=1, delay=0)
        self.run.assert_not_called()

    def test_one_actual_queue_must_match_configured_queue_not_only_firewall(self):
        self.values['NFQUEUE_NUM'] = '301'
        self.run.return_value = service_fixtures.completed(output=service_fixtures.rules(queue='301'))
        with self.assertRaises(nfqws_service.ServiceError):
            nfqws_service.verify(self.ctx, 76, attempts=1, delay=0)
        self.run.assert_not_called()

    def test_split_or_abbreviated_override_cannot_hide_behind_one_canonical_queue(self):
        for shadow in ('--qnum', '--qnu=301'):
            self.tokens.append(shadow)
            actual = ['nfqws2', '--qnum=300', *self.tokens, '301']
            self.cmdline.write_bytes(('\0'.join(actual) + '\0').encode())
            with self.subTest(shadow=shadow), self.assertRaises(nfqws_service.ServiceError):
                nfqws_service.verify(self.ctx, 76, attempts=1, delay=0)
            self.tokens.pop()
        self.run.assert_not_called()

    def test_single_matching_default_and_explicit_queue_keep_success(self):
        self.assertEqual(nfqws_service.verify(self.ctx, 76, attempts=1, delay=0), 77)
        self.values['NFQUEUE_NUM'] = ''  # package default is300
        self.assertEqual(nfqws_service.verify(self.ctx, 76, attempts=1, delay=0), 77)
