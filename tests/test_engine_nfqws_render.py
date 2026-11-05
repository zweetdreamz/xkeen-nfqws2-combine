"""Pure renderer differential against actual patch_nfqws, with I/O helpers stubbed."""
import itertools
import json
import os
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import engine_shell
from panel_fixtures import make_candidate

from kdn.common import fsutil
from kdn.engine import config, nfqws_render, nfqws_write


BASE = (b'# user\xff\nNFQWS_BASE_ARGS="--blob=quic_initial:0x0000"\n'
        b'NFQWS_ARGS="--filter-tcp=80,443 --lua-desync=fake:blob=tls_clienthello"\n'
        b'NFQWS_ARGS_QUIC="--filter-udp=443 --payload=quic_initial"\n'
        b'NFQWS_ARGS_CUSTOM="--filter-tcp=440-445,8080 --filter-udp=60000-60003"\n\n')


def descriptor(service):
    return dict(make_candidate(service), format=1)


class NfqwsRenderTests(unittest.TestCase):
    def legacy(self, request):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / 'nfqws2.conf'
            target.write_bytes(request.config)
            imports = directory / 'imports'
            imports.mkdir()
            for service, value in request.imported_profiles.items():
                (imports / (service + '.json')).write_text(json.dumps(value), encoding='utf-8')
            variables = {name: getattr(config, name) for name in ('TCP_PORTS_VALUE', 'UDP_PORTS_WIDE',
                         'UDP_FILTER_WIDE', 'UDP_PORTS_FLOWSEAL', 'UDP_FILTER_FLOWSEAL', 'UNBOUND_POLICY_NAME', 'SCRIPT_VERSION')}
            variables.update(NFQWS_CONF=str(target), NFQWS_LIST=str(directory / 'user.list'),
                NFQWS_YOUTUBE_LIST=str(directory / 'youtube.list'), NFQWS_TELEGRAM_LIST=str(directory / 'telegram.list'),
                NFQWS_TELEGRAM_IPSET=str(directory / 'unused-ipset'), NFQWS_TELEGRAM_CF_LIST=str(directory / 'unused-cf'),
                NFQWS_DISCORD_UDP_BLOB=str(directory / 'unused-blob'), IMPORTED_PROFILE_DIR=str(imports),
                DISCORD_TCP_ROUTE_MODE=request.routes[0], DISCORD_VOICE_ROUTE_MODE=request.routes[1],
                YOUTUBE_ROUTE_MODE=request.routes[2], TELEGRAM_ROUTE_MODE=request.routes[3],
                TELEGRAM_HEADER_ROUTE=request.telegram_header_route, PROXY_OUTBOUND_EFFECTIVE=request.proxy_outbound,
                WIDE_UDP=int(request.wide_udp), UDP_STRATEGY=request.udp_strategy,
                STANDALONE_ZAPRET=int(request.standalone), NFQWS_IPV6_EFFECTIVE=int(request.ipv6_enabled),
                WAN_INTERFACE_EFFECTIVE=request.wan_interfaces,
                NFQWS_DISABLED_HOST=config.NFQWS_DISABLED_HOST,
                DISCORD_UDP_BLOB_BASE_ARGS=engine_shell.extract_assignment('DISCORD_UDP_BLOB_BASE_ARGS'),
                NFQWS_PORT_AWK=engine_shell.extract_assignment('NFQWS_PORT_AWK'))
            defs = ('make_tmp() { mktemp; }', 'file_mode() { echo 0644; }',
                'atomic_replace_file() { cp "$2" "$1"; }', 'replace_preserving_mode() { cp "$2" "$1"; }',
                'install_discord_udp_blob() { :; }', 'verify_youtube_blobs() { :; }', 'verify_telegram_blob() { :; }',
                'validate_imported_profile() { :; }', 'validate_generated_nfqws_config() { :; }',
                'active_imported_profile() { p="$IMPORTED_PROFILE_DIR/$1.json"; [ -f "$p" ] && printf "%s\\n" "$p"; }',
                'discord_domains', 'youtube_domains', 'telegram_domains', 'recorded_proxy_outbound',
                'strip_trailing_blank_lines', 'user_custom_filter_ports', 'ports_union')
            done = engine_shell.run_function('patch_nfqws', defs=defs, variables=variables,
                env=dict(os.environ, TMPDIR=temporary, LC_ALL='C'),
                awk='busybox' if os.environ.get('TEST_BUSYBOX_APPLETS') == '1' else 'system',
                shell=shlex.split(os.environ.get('TEST_SHELL', 'sh')))
            self.assertEqual(done.returncode, 0, done.stderr)
            return target.read_bytes(), done.stderr

    def assertParity(self, request):
        actual = nfqws_render.render(request)
        expected, stderr = self.legacy(request)
        self.assertEqual(actual.config, expected)
        for warning in actual.warnings:
            self.assertIn(warning, stderr)
        again = nfqws_render.RenderInput(actual.config, request.routes,
            udp_strategy=request.udp_strategy, wide_udp=request.wide_udp, standalone=request.standalone,
            wan_interfaces=request.wan_interfaces, ipv6_enabled=request.ipv6_enabled,
            proxy_outbound=request.proxy_outbound, imported_profiles=request.imported_profiles,
            telegram_header_route=request.telegram_header_route)
        self.assertEqual(nfqws_render.render(again).config, actual.config)

    def test_all_route_combinations_builtin(self):
        for routes in itertools.product(('direct', 'zapret', 'vless'), repeat=3):
            for telegram in ('direct', 'vless', 'ws', 'unmanaged'):
                with self.subTest(routes=routes, telegram=telegram):
                    self.assertParity(nfqws_render.RenderInput(BASE, (*routes, telegram), wan_interfaces='eth0 eth1'))

    def test_imported_subsets_and_active_inactive_voice_ranges(self):
        services = ('discord-tcp', 'discord-voice', 'youtube')
        for bits in itertools.product((False, True), repeat=3):
            imports = {name: descriptor(name) for name, enabled in zip(services, bits, strict=True) if enabled}
            with self.subTest(bits=bits):
                self.assertParity(nfqws_render.RenderInput(BASE, ('zapret',) * 3 + ('ws',), imported_profiles=imports))
                self.assertParity(nfqws_render.RenderInput(BASE, ('vless',) * 3 + ('direct',), imported_profiles=imports))

    def test_flags_proxy_fallback_and_legacy_strategy(self):
        for wide, standalone, ipv6 in itertools.product((False, True), repeat=3):
            with self.subTest(wide=wide, standalone=standalone, ipv6=ipv6):
                self.assertParity(nfqws_render.RenderInput(BASE + b'# Proxy outbound: saved-node.\n',
                    ('zapret',) * 3 + ('ws',), udp_strategy='legacy', wide_udp=wide,
                    standalone=standalone, ipv6_enabled=ipv6, telegram_header_route='unmanaged'))
        self.assertParity(nfqws_render.RenderInput(BASE.replace(b'--blob=quic_initial:', b'--blob=another:'),
            ('direct', 'zapret', 'direct', 'direct'), udp_strategy='legacy', proxy_outbound='selected'))

    def test_unmanaged_bytes_repeated_blocks_unclosed_and_blank_normalisation(self):
        for source in (BASE.rstrip(b'\n'), BASE + b' \t\n\n',
                       BASE + nfqws_render.BEGIN + b'\nold\n' + nfqws_render.END + b'\n\n',
                       BASE + nfqws_render.BEGIN + b'\nold',
                       BASE + nfqws_render.BEGIN + b'\r\nnot-a-marker\n',
                       BASE + b' \t\nnonblank\r\n',
                       BASE + b'NFQWS_ARGS_CUSTOM="--filter-udp=50000-65535"\n'):
            with self.subTest(source=source):
                self.assertParity(nfqws_render.RenderInput(source, ('direct', 'zapret', 'zapret', 'ws')))

    def test_cr_only_blank_policy_matches_router_busybox_not_mawk(self):
        request = nfqws_render.RenderInput(BASE.rstrip(b'\n') + b'\n\r\n', ('direct',) * 4)
        result = nfqws_render.render(request)
        legacy, _ = self.legacy(request)
        if os.environ.get('TEST_BUSYBOX_APPLETS') == '1':
            self.assertEqual(result.config, legacy)
        else:
            self.assertEqual(legacy.replace(b'\r\n\n# BEGIN', b'\n# BEGIN'), result.config)

    def test_imported_wide_voice_only_constrains_active_profile(self):
        value = descriptor('discord-voice')
        value['args'][0] = '--filter-udp=50000-65535'
        from kdn.engine import profile_descriptor
        value['candidate_id'] = profile_descriptor.candidate_id(value)
        imports = {'discord-voice': value}
        with self.assertRaises(ValueError):
            nfqws_render.RenderInput(BASE, ('direct', 'zapret', 'direct', 'direct'), imported_profiles=imports)
        self.assertParity(nfqws_render.RenderInput(BASE, ('direct', 'zapret', 'direct', 'direct'),
            imported_profiles=imports, wide_udp=True))
        self.assertParity(nfqws_render.RenderInput(BASE, ('direct',) * 4, imported_profiles=imports))

    def test_unsupported_base_and_import_mapping_fail_without_io(self):
        with self.assertRaises(ValueError):
            nfqws_render.render(nfqws_render.RenderInput(b'no-base\n', ('direct',) * 4))
        with self.assertRaises(ValueError):
            nfqws_render.RenderInput(BASE, ('direct',) * 4, imported_profiles={'youtube': descriptor('discord-tcp')})
        with mock.patch('builtins.open', side_effect=AssertionError('pure render opened file')):
            self.assertTrue(nfqws_render.render(nfqws_render.RenderInput(BASE, ('direct',) * 4)).block)
        for text in ('bad"text', '$(command)', '`command`', 'x;command'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                nfqws_render.render(nfqws_render.RenderInput(BASE, ('direct',) * 4, wan_interfaces=text))


class NfqwsWriterTests(unittest.TestCase):
    def test_publication_requires_confirmation_canonical_paths_and_router(self):
        output = nfqws_render.RenderOutput(b'new')
        ctx = SimpleNamespace(options=SimpleNamespace(confirmed=False), environ={},
                              paths=config.EnginePaths.from_environ({}))
        with self.assertRaises(ValueError):
            nfqws_write.publish_config(output, ctx)
        ctx.options.confirmed = True
        ctx.paths = ctx.paths.replace(nfqws_list='/tmp/forged')
        with self.assertRaises(ValueError):
            nfqws_write.publish_config(output, ctx)
        ctx.paths = config.EnginePaths.from_environ({})
        with mock.patch.object(nfqws_write.os, 'geteuid', return_value=1000):
            with self.assertRaises(ValueError):
                nfqws_write.publish_config(output, ctx)
        with mock.patch.object(nfqws_write.os, 'geteuid', return_value=0):
            with mock.patch.object(nfqws_write.system, 'is_router', return_value=False):
                with self.assertRaises(ValueError):
                    nfqws_write.publish_config(output, ctx)

    def test_publication_test_root_and_mocked_live_checks_never_write_real_opt(self):
        output = nfqws_render.RenderOutput(b'new')
        with tempfile.TemporaryDirectory() as temporary:
            environ = {'KD_TEST_ROOT': temporary, 'KD_ALLOW_TEST_ROOT': '1'}
            from target_fixture import supported_environment
            supported_environment(environ)
            ctx = SimpleNamespace(options=SimpleNamespace(confirmed=True), environ=environ,
                                  paths=config.EnginePaths.from_environ(environ))
            target = Path(ctx.paths.nfqws_conf)
            target.parent.mkdir(parents=True)
            target.write_bytes(b'old')
            nfqws_write.publish_config(output, ctx)
            self.assertEqual(target.read_bytes(), b'new')
        ctx = SimpleNamespace(options=SimpleNamespace(confirmed=True), environ={},
                              paths=config.EnginePaths.from_environ({}))
        with mock.patch.object(nfqws_write.os, 'geteuid', return_value=0):
            with mock.patch.object(nfqws_write.system, 'is_router', return_value=True):
                with mock.patch.object(nfqws_write, '_publish_checked') as publish, \
                        mock.patch.object(nfqws_write.system, 'run', return_value=type('Version', (), {
                            'returncode': 0, 'timed_out': False, 'stdout': 'XKeen 2.1'})()), \
                    mock.patch.object(nfqws_write.transaction.xkeen, 'require', return_value='2.1'), \
                        mock.patch.object(nfqws_write.transaction.confvalues, 'init_value', return_value='xray'):
                    nfqws_write.publish_config(output, ctx)
                    self.assertEqual(publish.call_args.args[1], Path('/opt/etc/nfqws2/nfqws2.conf'))

    def test_atomic_bytes_and_writer_keep_mode_and_opaque_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            environ = {'KD_TEST_ROOT': temporary, 'KD_ALLOW_TEST_ROOT': '1'}
            paths = config.EnginePaths.from_environ(environ)
            target = Path(paths.nfqws_conf)
            target.parent.mkdir(parents=True)
            target.write_bytes(BASE)
            target.chmod(0o640)
            output = nfqws_render.render(nfqws_render.RenderInput(BASE, ('direct',) * 4))
            nfqws_write.write_config(output, paths, environ)
            self.assertEqual(target.read_bytes(), output.config)
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_failed_write_fsync_replace_preserve_original_and_cleanup(self):
        for operation in ('fsync', 'replace', 'chmod'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / 'config'
                target.write_bytes(b'original')
                with mock.patch.object(fsutil.os, operation, side_effect=OSError('injected')):
                    with self.assertRaises(OSError):
                        fsutil.atomic_bytes(target, b'new\xff')
                self.assertEqual(target.read_bytes(), b'original')
                self.assertEqual(list(Path(temporary).iterdir()), [target])

    def test_disk_full_write_and_fdopen_failure_preserve_original(self):
        original_fdopen = fsutil.os.fdopen

        def disk_full(descriptor, mode):
            stream = original_fdopen(descriptor, mode)
            wrapped = mock.MagicMock(wraps=stream)
            wrapped.__enter__.return_value = wrapped
            wrapped.__exit__.side_effect = stream.__exit__
            wrapped.write.side_effect = OSError(28, 'No space left on device')
            return wrapped

        for failure in (disk_full, OSError('fdopen failure')):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / 'config'
                target.write_bytes(b'original')
                with mock.patch.object(fsutil.os, 'fdopen', side_effect=failure):
                    with self.assertRaises(OSError):
                        fsutil.atomic_bytes(target, b'new')
                self.assertEqual(target.read_bytes(), b'original')
                self.assertEqual(list(Path(temporary).iterdir()), [target])

    def test_live_path_wrong_target_and_symlinks_are_rejected(self):
        output = nfqws_render.RenderOutput(b'new')
        with self.assertRaises(ValueError):
            nfqws_write.write_config(output, config.EnginePaths.from_environ({}), {})
        with tempfile.TemporaryDirectory() as temporary:
            environ = {'KD_TEST_ROOT': temporary, 'KD_ALLOW_TEST_ROOT': '1'}
            paths = config.EnginePaths.from_environ(environ)
            with self.assertRaises(ValueError):
                nfqws_write.write_config(output, paths.replace(nfqws_conf='/tmp/other'), environ)
            target = Path(paths.nfqws_conf)
            target.parent.mkdir(parents=True)
            target.symlink_to(Path(temporary) / 'outside')
            with self.assertRaises(ValueError):
                nfqws_write.write_config(output, paths, environ)
