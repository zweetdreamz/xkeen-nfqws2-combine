"""Advisory caches cannot authorise actions or hide unsupported targets."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from kdn.common import xkeen
from kdn.web.infra import readcache


class LiveVersionCacheGateTests(unittest.TestCase):
    def test_http_scope_avoids_duplicate_probe_but_never_skips_write_or_next_request_guard(self):
        import panel_harness
        namespace = panel_harness.load_panel('phase8-status-read-scope')
        engine = namespace.module('kdn.web.infra.engine')
        with mock.patch.object(engine, 'require_supported_target', return_value='2.1') as guard, \
                mock.patch.object(engine.proc, 'run_command', return_value={'ok': True, 'code': 0, 'output': ''}):
            with engine.status_read_scope():
                engine.read_status_fields()
                self.assertEqual(guard.call_count, 1)
                engine.run_xkeen_action(['synthetic'], xray_expected=False)
                self.assertEqual(guard.call_count, 2, 'write must still check actual version')
            engine.read_status_fields()
            self.assertEqual(guard.call_count, 3, 'scope must not leak to the next read')
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                with engine.status_read_scope():
                    raise RuntimeError('injected')
            engine.read_status_fields()
            self.assertEqual(guard.call_count, 5)

    def test_cached_status_still_runs_real_version_probe_after_downgrade(self):
        import panel_harness
        from target_fixture import version_executable
        namespace = panel_harness.load_panel('phase8-cache-real-version')
        routes = namespace.module('kdn.web.api.read_routes')
        routes.readcache.invalidate()
        self.addCleanup(routes.readcache.invalidate)
        version_executable(routes.cfg.XKEEN, 'XKeen 2.1.1')
        engine = namespace.root / 'fixture-engine.sh'
        engine.write_text('# synthetic engine; builder is mocked')
        app = routes.router.Router(routes.READ_ROUTES)
        request = routes.router.Request('GET', '/api/status')
        with mock.patch.object(routes.cfg, 'ENGINE', engine), \
                mock.patch.object(routes.engine, 'read_status_fields', return_value={'ok': True}) as build:
            self.assertEqual(app.dispatch(request).status, 200)
            version_executable(routes.cfg.XKEEN, 'XKeen 2.0')
            with mock.patch.object(routes.readcache, '_stamp', side_effect=AssertionError('metadata before version gate')):
                response = app.dispatch(request)
        self.assertEqual(response.status, 409)
        self.assertIn(b'unsupported_xkeen', response.body)
        self.assertEqual(build.call_count, 1)


class ReadCacheTests(unittest.TestCase):
    def setUp(self):
        readcache.invalidate()
        self.addCleanup(readcache.invalidate)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'config.json'
        self.path.write_text('{}')

    def test_hit_is_copied_and_ttl_file_change_or_post_boundary_invalidates(self):
        load = mock.Mock(return_value={'ok': True, 'nested': {'value': 1}})
        with mock.patch.object(readcache.time, 'monotonic', return_value=0) as clock:
            readcache.read('status', [self.path], load)['nested']['value'] = 99
            self.assertEqual(readcache.read('status', [self.path], load)['nested']['value'], 1)
            self.assertEqual(load.call_count, 1)
            clock.return_value = 3
            readcache.read('status', [self.path], load)
            self.assertEqual(load.call_count, 2)
            self.path.write_text('{"changed":true}')
            readcache.read('status', [self.path], load)
            self.assertEqual(load.call_count, 3)
            readcache.invalidate()
            readcache.read('status', [self.path], load)
            self.assertEqual(load.call_count, 4)

    def test_unsupported_hit_is_rechecked_and_never_served(self):
        load = mock.Mock(return_value={'ok': True})
        readcache.read('status', [self.path], load)
        guard = mock.Mock(side_effect=xkeen.UnsupportedXKeen())
        with self.assertRaises(xkeen.UnsupportedXKeen):
            readcache.read('status', [self.path], load, validate_hit=guard)
        guard.assert_called_once()
        readcache.read('status', [self.path], load)
        self.assertEqual(load.call_count, 2)

    def test_errors_oversized_payloads_and_bad_fingerprints_are_not_cached(self):
        for result in ({'ok': False}, {'ok': True, 'status': 'error'},
                       {'ok': True, 'data': 'x' * (readcache.MAX_ENTRY_BYTES + 1)}):
            with self.subTest(result_type=tuple(result)):
                readcache.invalidate()
                load = mock.Mock(return_value=result)
                readcache.read('sources', [self.path], load)
                readcache.read('sources', [self.path], load)
                self.assertEqual(load.call_count, 2)
        load = mock.Mock(return_value={'ok': True})
        with mock.patch.object(readcache, '_stamp', return_value=None):
            readcache.read('status', [self.path], load)
            readcache.read('status', [self.path], load)
        self.assertEqual(load.call_count, 2)

    def test_concurrent_requests_share_one_load(self):
        def slow():
            time.sleep(0.05)
            return {'ok': True}
        load = mock.Mock(side_effect=slow)
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: readcache.read('status', [self.path], load), range(5)))
        self.assertTrue(all(row['ok'] for row in results))
        self.assertEqual(load.call_count, 1)

    def test_mutation_during_load_prevents_caching_old_result(self):
        started, finish = threading.Event(), threading.Event()
        def slow():
            started.set()
            self.assertTrue(finish.wait(2))
            return {'ok': True, 'old': True}
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(readcache.read, 'status', [self.path], slow)
            self.assertTrue(started.wait(2))
            readcache.invalidate()
            finish.set()
            self.assertTrue(future.result()['old'])
        fresh = readcache.read('status', [self.path], lambda: {'ok': True, 'old': False})
        self.assertFalse(fresh['old'])

    def test_link_and_directory_budget_disable_caching(self):
        link = self.path.parent / 'link'
        link.symlink_to(self.path)
        self.assertIsNone(readcache._stamp([link]))
        self.assertIsNone(readcache._stamp([self.path.parent]))
        link.unlink()
        with mock.patch.object(readcache, 'MAX_STAMPS', 1):
            self.assertIsNone(readcache._stamp([self.path.parent]))
