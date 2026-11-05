"""Pure phase-5 foundations, not a renderer, writer or snapshot restorer."""
import unittest
from unittest import mock

import engine_shell

from kdn.engine import nfqws_render, snapshot_format


class RenderModelsTests(unittest.TestCase):
    def test_layout_preserves_bytes_and_all_sed_range_boundaries(self):
        begin = b'# BEGIN keenetic-discord-nfqws2'
        end = b'# END keenetic-discord-nfqws2'
        source = b'user\xff\r\n\n' + begin + b'\na\n' + end + b'\nmid\n' + begin + b'\nb'
        layout = nfqws_render.BlockLayout(source)
        self.assertEqual(layout.source, source)
        self.assertEqual(len(layout.spans), 2)
        self.assertTrue(layout.unclosed)
        self.assertEqual(layout.unmanaged(), b'user\xff\r\n\nmid\n')
        self.assertEqual(source[slice(*layout.spans[0])], begin + b'\na\n' + end + b'\n')

    def test_crlf_and_non_lf_separators_do_not_create_markers(self):
        source = b'# BEGIN keenetic-discord-nfqws2\r\nhello\x0b# END keenetic-discord-nfqws2\n'
        layout = nfqws_render.BlockLayout(source)
        self.assertEqual(layout.spans, ())
        self.assertEqual(layout.unmanaged(), source)
        self.assertFalse(layout.unclosed)

    def test_nested_begin_closes_at_first_end_like_sed(self):
        begin = b'# BEGIN keenetic-discord-nfqws2\n'
        end = b'# END keenetic-discord-nfqws2\n'
        layout = nfqws_render.BlockLayout(end + begin + begin + end + b'user')
        self.assertEqual(len(layout.spans), 1)
        self.assertEqual(layout.unmanaged(), end + b'user')

    def test_request_and_output_are_data_only(self):
        request = nfqws_render.RenderInput(b'user\n', ('zapret', 'vless', 'direct', 'ws'), wide_udp=True)
        self.assertEqual(request.routes, ('zapret', 'vless', 'direct', 'ws'))
        self.assertTrue(request.wide_udp)
        self.assertEqual(request.config, b'user\n')
        warnings = ['note']
        output = nfqws_render.RenderOutput(b'block', warnings)
        warnings.append('later')
        self.assertEqual(output.warnings, ('note',))
        self.assertEqual(output.block, b'block')
        for bad in (b'x', ('zapret',) * 3, ('vpn', 'zapret', 'vless', 'unmanaged')):
            with self.subTest(routes=bad), self.assertRaises((TypeError, ValueError)):
                nfqws_render.RenderInput(b'', bad)

    def test_flag_and_text_types_are_checked_without_io(self):
        routes = ['direct', 'zapret', 'vless', 'unmanaged']
        with mock.patch('builtins.open', side_effect=AssertionError('unexpected file IO')):
            request = nfqws_render.RenderInput(b'', routes)
            routes[0] = 'vless'
            self.assertEqual(request.routes[0], 'direct')
            for options in ({'wide_udp': 1}, {'ipv6_enabled': 'on'}, {'standalone': None},
                            {'udp_strategy': 'unknown'}, {'wan_interfaces': 'wan0\nwan1'},
                            {'proxy_outbound': '\0'}):
                with self.subTest(options=options), self.assertRaises((TypeError, ValueError)):
                    nfqws_render.RenderInput(b'', request.routes, **options)
            for block, warnings in (('text', ()), (b'', 'text'), (b'', [1])):
                with self.subTest(block=block, warnings=warnings), self.assertRaises(TypeError):
                    nfqws_render.RenderOutput(block, warnings)

    def test_boundary_scanner_matches_actual_sed_on_vectors(self):
        begin, end = nfqws_render.BEGIN, nfqws_render.END
        vectors = [b'', b'user', begin, end, begin + b'\n' + end, b'\xff\r\n' + begin + b'\nmanaged\n' + end + b'\n\n',
                   begin + b'\r\nmanaged\n' + end + b'\r\n', begin + b'\n' + begin + b'\n' + end + b'\nuser',
                   begin + b'\n' + end + b'\nmid\n' + begin + b'\ntruncated']
        command = "sed '/^# BEGIN keenetic-discord-nfqws2$/,/^# END keenetic-discord-nfqws2$/d'"
        for source in vectors:
            with self.subTest(source=source):
                done = engine_shell.run_sh(command, stdin=source.decode('utf-8', 'surrogateescape'))
                self.assertEqual(done.returncode, 0)
                self.assertEqual(nfqws_render.BlockLayout(source).unmanaged(), done.stdout.encode('utf-8', 'surrogateescape'))


class SnapshotModelsTests(unittest.TestCase):
    def test_old_minimal_and_full_metadata_roundtrip(self):
        for data in (b'FORMAT\t1\nSCOPE\tintegrated\n',
                     b'FORMAT\t1\nPURPOSE\tbaseline\nSCRIPT_VERSION\t3.2.0\nCREATED_UTC\t2026-10-31T00:00:00Z\n',
                     b'FORMAT\t1\nFUTURE\tvalue\xff\textra\nFUTURE\tsecond'):
            with self.subTest(data=data):
                metadata = snapshot_format.parse_state(data)
                self.assertEqual(metadata.to_bytes(), data)
                self.assertEqual(metadata.value('FORMAT'), '1')
                self.assertEqual(metadata.scope, 'integrated')
        metadata = snapshot_format.parse_state(b'FORMAT\t1\nFUTURE\tvalue\xff\textra\nFUTURE\tsecond')
        self.assertEqual(metadata.value('FUTURE'), 'value\udcff')
        self.assertEqual(metadata.value('missing', 'fallback'), 'fallback')

    def test_focused_metadata_and_canonical_creation(self):
        metadata = snapshot_format.make_state((('FORMAT', '1'), ('NFQWS_PRESENT', '1'),
            ('NFQWS_RUNNING', '0'), ('ROUTES_HEADER', '# Active routes: YouTube=zapret.')))
        self.assertEqual(metadata.kind, 'nfqws-import')
        self.assertIsNone(metadata.scope)
        self.assertEqual(metadata.value('NFQWS_RUNNING'), '0')
        self.assertEqual(snapshot_format.parse_state(metadata.to_bytes()).to_bytes(), metadata.to_bytes())
        self.assertTrue(metadata.to_bytes().endswith(b'\n'))

    def test_basic_format_and_encoder_do_not_accept_ambiguous_fields(self):
        for raw in (b'', b'FORMAT\t2\n', b'FORMAT\t1\r\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                snapshot_format.parse_state(raw)
        for fields in ((('FORMAT', '1'), ('BAD\tKEY', 'x')), (('FORMAT', '1'), ('X', 'a\nb')),
                       (('FORMAT', '1'), ('FORMAT', '1'))):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                snapshot_format.make_state(fields)

    def test_inventory_preserves_order_but_does_not_authorize_restore_paths(self):
        entry = snapshot_format.InventoryEntry('/opt/etc/example', 'PRESENT')
        self.assertEqual(entry.to_bytes(), b'/opt/etc/example|PRESENT\n')
        self.assertEqual(entry.logical_path, '/opt/etc/example')
        self.assertEqual(entry.presence, 'PRESENT')
        self.assertEqual(snapshot_format.InventoryEntry('../untrusted', 'ABSENT').logical_path, '../untrusted')
        for path, status in (('/x', 'unknown'), ('/x|PRESENT', 'ABSENT'), ('/x\n/y', 'PRESENT')):
            with self.subTest(path=path, status=status), self.assertRaises(ValueError):
                snapshot_format.InventoryEntry(path, status)

    def test_state_values_match_legacy_awk_and_real_minimal_fixture(self):
        from pathlib import Path
        data = (Path(engine_shell.ROOT) / 'tests/fixtures/engine/router-xkeen20/opt/etc/'
                'keenetic-discord-nfqws2/snapshots/20260723-115259-17170/STATE.tsv').read_bytes()
        self.assertEqual(snapshot_format.parse_state(data).to_bytes(), data)
        raw = b'FORMAT\t1\nPURPOSE\tfirst\textra\nPURPOSE\tsecond\nUNKNOWN\t\xff\r\n'
        metadata = snapshot_format.parse_state(raw)
        for key in ('FORMAT', 'PURPOSE', 'UNKNOWN', 'MISSING'):
            with self.subTest(key=key):
                done = engine_shell.run_sh("awk -F '\\t' -v wanted='" + key + "' '$1 == wanted { print $2; exit }'",
                                           stdin=raw.decode('utf-8', 'surrogateescape'))
                self.assertEqual(done.returncode, 0)
                self.assertEqual(metadata.value(key), done.stdout.rstrip('\n'))
