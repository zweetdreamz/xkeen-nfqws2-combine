"""Custom profiles retain firewall coverage after managed config rendering."""
import os
from pathlib import Path
import shlex
import shutil
import tempfile
from types import SimpleNamespace
import unittest

from kdn.engine import apply_nfqws, compose, config, nfqws_render


BASE = (b'NFQWS_BASE_ARGS=""\n'
        b'NFQWS_ARGS="--filter-tcp=443 --filter-l7=tls"\n'
        b'NFQWS_ARGS_QUIC=""\nTCP_PORTS=443\nUDP_PORTS=443\n')


class CustomPortTests(unittest.TestCase):
    def composed(self, directory, payload):
        env = dict(os.environ, KD_TEST_ROOT=str(directory), KD_ALLOW_TEST_ROOT='1')
        paths = config.EnginePaths.from_environ(env)
        path = Path(paths.nfqws_conf)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return compose.compose(path, paths, env, 5)

    def test_literal_and_appended_profiles_keep_tcp_udp_firewall_coverage(self):
        variants = (
            b'NFQWS_ARGS_CUSTOM="--filter-tcp=8080 --filter-udp=62000-62003"\n',
            b"NFQWS_ARGS_CUSTOM='--filter-tcp=8080 --filter-udp=62000-62003'\n",
            b'NFQWS_ARGS_CUSTOM="--filter-tcp=8080 --filter-udp=62000-62003"\n'
            b'NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM --new --filter-tcp=8444 --filter-udp=63000"\n',
            b"NFQWS_ARGS_CUSTOM='--filter-tcp=8080 --filter-udp=62000-62003'\n"
            b'NFQWS_ARGS_CUSTOM="${NFQWS_ARGS_CUSTOM} --new --filter-tcp=8444 --filter-udp=63000"\n',
        )
        for index, custom in enumerate(variants):
            with self.subTest(variant=index), tempfile.TemporaryDirectory() as folder:
                output = nfqws_render.render(nfqws_render.RenderInput(BASE + custom, ('direct',) * 4))
                observed = self.composed(folder, output.config)
                self.assertEqual(observed.meta['TCP_PORTS'], '443,8080,8444' if index >= 2 else '443,8080')
                self.assertEqual(observed.meta['UDP_PORTS'], '443,62000:62003,63000' if index >= 2 else '443,62000:62003')
                self.assertIn('--filter-tcp=8080', observed.tokens)
                self.assertIn('--filter-udp=62000-62003', observed.tokens)
                self.assertEqual(nfqws_render.render(nfqws_render.RenderInput(output.config, ('direct',) * 4)).config,
                                 output.config)

    def test_dynamic_custom_forms_require_resolution_without_execution(self):
        forms = (
            b'NFQWS_ARGS_CUSTOM="$EXTRA_PROFILE"\n',
            b'NFQWS_ARGS_CUSTOM="$(printf -- --filter-tcp=8080)"\n',
            b'if true; then\nNFQWS_ARGS_CUSTOM="--filter-tcp=8080"\nfi\n',
            b'NFQWS_ARGS_CUSTOM="--filter-tcp=8080"; NFQWS_ARGS_CUSTOM="--filter-tcp=8444"\n',
        )
        for custom in forms:
            with self.subTest(custom=custom), self.assertRaisesRegex(ValueError, 'custom.*resolv'):
                nfqws_render.render(nfqws_render.RenderInput(BASE + custom, ('direct',) * 4))

    def test_composition_resolves_dynamic_user_ports_without_changing_default_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            env = dict(os.environ, KD_TEST_ROOT=folder, KD_ALLOW_TEST_ROOT='1')
            paths = config.EnginePaths.from_environ(env)
            path = Path(paths.nfqws_conf)
            path.parent.mkdir(parents=True)
            custom = (b'EXTRA_PROFILE="--filter-tcp=8080 --filter-udp=62000-62003"\n'
                      b'NFQWS_ARGS_CUSTOM="$EXTRA_PROFILE"\n'
                      b'NFQWS_ARGS_CUSTOM="$NFQWS_ARGS_CUSTOM --new --filter-tcp=8444"\n')
            path.write_bytes(BASE + custom)
            plain = compose.compose(path, paths, env, 5)
            self.assertEqual(set(plain.meta), {'TCP_PORTS', 'UDP_PORTS', 'NFQUEUE_NUM', 'USER_PROFILES'})
            resolved = compose.compose(path, paths, env, 5, custom_ports=True)
            self.assertEqual(resolved.meta['CUSTOM_FILTER_TCP'], '8080,8444')
            self.assertEqual(resolved.meta['CUSTOM_FILTER_UDP'], '62000-62003')
            routes = ('direct', 'direct', 'zapret', 'ws')
            output = nfqws_render.render(nfqws_render.RenderInput(BASE + custom, routes,
                custom_ports=(resolved.meta['CUSTOM_FILTER_TCP'], resolved.meta['CUSTOM_FILTER_UDP'])))
            after = self.composed(folder, output.config)
            self.assertEqual(after.meta['TCP_PORTS'], '443,8080,8444')
            self.assertEqual(after.meta['UDP_PORTS'], '443,62000:62003')
            # Generated custom profiles are excluded from the next resolution.
            again = compose.compose(path, paths, env, 5, custom_ports=True)
            self.assertEqual(again.meta['CUSTOM_FILTER_TCP'], '8080,8444')
            self.assertEqual(again.meta['CUSTOM_FILTER_UDP'], '62000-62003')
            self.assertEqual(nfqws_render.render(nfqws_render.RenderInput(output.config, routes,
                custom_ports=(again.meta['CUSTOM_FILTER_TCP'], again.meta['CUSTOM_FILTER_UDP']))).config, output.config)

    def test_resolved_composition_keeps_source_count_timeout_and_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            env = dict(os.environ, KD_TEST_ROOT=folder, KD_ALLOW_TEST_ROOT='1')
            paths = config.EnginePaths.from_environ(env)
            path, count = Path(folder) / 'config', Path(folder) / 'source-count'
            path.write_bytes(BASE + ('printf x >> ' + shlex.quote(str(count)) + '\n').encode())
            compose.compose(path, paths, env, 5)
            self.assertEqual(count.read_bytes(), b'xx')
            count.unlink()
            compose.compose(path, paths, env, 5, custom_ports=True)
            self.assertEqual(count.read_bytes(), b'xx')
            path.write_text('sleep 1\n')
            with self.assertRaises(compose.ComposeError):
                compose.compose(path, paths, env, .05, custom_ports=True)
            self.assertEqual(list(Path(paths.work_tmp_root).iterdir()), [])

    def test_prepare_uses_effective_dynamic_ports_without_publishing(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = str(Path(folder).resolve())
            env = dict(os.environ, KD_TEST_ROOT=folder, KD_ALLOW_TEST_ROOT='1')
            paths = config.EnginePaths.from_environ(env)
            fixture = Path(__file__).parent / 'fixtures/engine/nfqws-neutral'
            shutil.copytree(fixture, Path(paths.nfqws_conf).parent)
            path = Path(paths.nfqws_conf)
            original = BASE + (b'EXTRA_PROFILE="--filter-tcp=8080 --filter-udp=62000-62003"\n'
                               b'NFQWS_ARGS_CUSTOM="$EXTRA_PROFILE"\n')
            path.write_bytes(original)
            ctx = SimpleNamespace(paths=paths, environ=env,
                                  resolved=SimpleNamespace(udp_strategy='flowseal', wide_udp=False))
            prepared = apply_nfqws.prepare(ctx, routes=('direct',) * 4, wan='eth0', ipv6=False, proxy_outbound='')
            self.assertEqual(path.read_bytes(), original)
            after = self.composed(folder, prepared.rendered.config)
            self.assertEqual(after.meta['TCP_PORTS'], '443,8080')
            self.assertEqual(after.meta['UDP_PORTS'], '443,62000:62003')
