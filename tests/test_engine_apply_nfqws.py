"""Prospective nfqws apply validates real pinned Lua from an isolated shadow root."""
from itertools import product
import io
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from kdn.engine import apply_nfqws, cli, config, console, options


class ApplyNfqwsRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = Path(os.environ.get('NFQWS_TEST_RUNTIME', '/var/cache/kdn/nfqws2-blobs/runtime'))
        if not (self.runtime / 'nfqws2').is_file():
            self.skipTest('pinned runtime required; use the Docker test image')
        self.env = dict(os.environ, KD_TEST_ROOT=str(self.root), KD_ALLOW_TEST_ROOT='1',
                        KD_TEST_NFQWS2_BIN=str(self.runtime / 'nfqws2'), KD_TEST_NFQWS2_LUA_SRC=str(self.runtime))
        from target_fixture import supported_environment
        supported_environment(self.env)
        self.paths = config.EnginePaths.from_environ(self.env)
        project = Path(__file__).resolve().parents[1]
        source = project / 'tests/fixtures/engine/nfqws-neutral'
        shutil.copytree(source, Path(self.paths.nfqws_conf).parent)
        base = Path(self.paths.nfqws_conf).parent
        (base / 'blobs').mkdir(exist_ok=True)
        for name in ('tls_clienthello.bin', 'quic_initial.bin'):
            (base / 'blobs' / name).write_bytes((self.runtime.parent / name).read_bytes())
        init = Path(self.paths.nfqws_init)
        init.parent.mkdir(parents=True)
        init.write_text('#!/bin/sh\n# fallback composer used by this fixture\n')
        Path(self.paths.work_tmp_root).mkdir(parents=True)
        self.ctx = cli.Context([], self.env, console.Console(io.StringIO(), io.StringIO()), paths=self.paths)

    def test_all_service_route_combinations_initialize_real_pinned_lua_without_writes(self):
        before = Path(self.paths.nfqws_conf).read_bytes()
        for tcp, voice, youtube in product(('direct', 'zapret', 'vless'), repeat=3):
            with self.subTest(tcp=tcp, voice=voice, youtube=youtube):
                parsed = options.parse_args(['--apply', '--yes-router'])
                self.ctx.options, self.ctx.resolved = parsed, options.resolve(parsed, '')
                prepared = apply_nfqws.prepare(self.ctx, routes=(tcp, voice, youtube, 'unmanaged'),
                                               wan='eth3', ipv6=False, proxy_outbound='vpn')
                apply_nfqws.validate_staged(self.ctx, prepared)
                self.assertEqual(Path(self.paths.nfqws_conf).read_bytes(), before)
                self.assertEqual(list(Path(self.paths.work_tmp_root).glob('kdn-nfqws-check-*')), [])
