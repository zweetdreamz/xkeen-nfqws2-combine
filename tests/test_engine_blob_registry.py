"""Pure registry checks; these do not execute Lua or check file contents."""
import unittest
from unittest import mock

from kdn.engine import nfqws_validate as blobs


class BlobRegistryTests(unittest.TestCase):
    def test_default_registry_and_explicit_global_declarations(self):
        result = blobs.inspect_blobs([
            '--lua-desync=fake:blob=tls_clienthello', '--new=udp',
            '--blob=tls_clienthello:@/opt/blobs/tls.bin',
            '--lua-desync=fake:blob=fake_default_tls',
        ])
        self.assertEqual(result.issues, ())
        self.assertEqual([(use.profile, use.kind) for use in result.uses], [(1, 'global'), (2, 'global')])
        self.assertEqual(result.declarations[0].source, '@/opt/blobs/tls.bin')
        self.assertEqual(result.declarations[0].kind, 'file')

    def test_names_elsewhere_do_not_satisfy_a_reference(self):
        result = blobs.inspect_blobs([
            '--hostlist=/tmp/missing', '--lua-desync=fake:blob=missing', '--new',
            '--lua-desync=pass:note=missing',
        ])
        self.assertEqual([(issue.code, issue.profile, issue.reference) for issue in result.issues],
                         [('unknown-blob', 1, 'missing')])

    def test_inline_and_file_sources_and_reserved_duplicate_names(self):
        result = blobs.inspect_blobs([
            '--blob=x:0x0011', '--blob=offset:+16@/tmp/a:b', '--blob=raw:relative.bin',
            '--blob=x:0x22', '--blob=fake_default_tls:0x33', '--new', '--blob=x:@/tmp/x',
            '--lua-desync=fake:blob=0xaabb',
        ])
        self.assertEqual([item.kind for item in result.declarations], ['inline', 'file', 'file', 'inline', 'inline', 'file'])
        self.assertEqual([issue.code for issue in result.issues], ['duplicate-blob'] * 3)
        self.assertEqual(result.uses[0].kind, 'inline')

    def test_bad_declarations_and_inline_references_are_not_registered(self):
        result = blobs.inspect_blobs([
            '--blob=x', '--blob=bad-name:@/tmp/x', '--blob=y:0x0g', '--blob=z:',
            '--blob=offset:+no@/tmp/x', '--lua-desync=fake:blob=0x1',
        ])
        self.assertEqual([issue.code for issue in result.issues], ['invalid-declaration'] * 5 + ['invalid-inline'])
        self.assertEqual(result.declarations, ())

    def test_dynamic_clone_output_is_local_ordered_and_not_a_use(self):
        result = blobs.inspect_blobs([
            '--lua-desync=fake:blob=copy',
            '--lua-desync=tls_client_hello_clone:blob=copy:fallback=fake_default_tls',
            '--lua-desync=fake:blob=copy', '--new', '--lua-desync=fake:blob=copy',
        ])
        self.assertEqual([use.kind for use in result.uses], ['unknown', 'global', 'dynamic', 'unknown'])
        self.assertEqual([issue.profile for issue in result.issues], [1, 2])

    def test_patterns_are_function_specific_and_optional_is_preserved(self):
        result = blobs.inspect_blobs([
            '--lua-desync=detect_payload_str:pattern=literal',
            '--lua-desync=hostfakesplit:seqovl_pattern=ignored_by_pinned_lua',
            '--lua-desync=multisplit:seqovl_pattern=missing:optional',
            '--lua-desync=fakedsplit:pattern=0x11:seqovl_pattern=fake_default_tls',
            '--lua-desync=udplen:pattern=0x22',
        ])
        self.assertEqual([use.argument for use in result.uses], ['seqovl_pattern', 'pattern', 'seqovl_pattern', 'pattern'])
        self.assertTrue(result.uses[0].optional)
        self.assertEqual([issue.code for issue in result.issues], ['unknown-blob'])

    def test_escaped_colon_and_prefix_references(self):
        result = blobs.inspect_blobs([
            '--blob=known:0x11',
            '--lua-desync=pass:note=literal\\:blob=not_a_blob:size=#known:val=%missing',
        ])
        self.assertEqual([use.reference for use in result.uses], ['known', 'missing'])
        self.assertEqual([issue.reference for issue in result.issues], ['missing'])

    def test_explicit_builtin_registry_no_io_and_inputs_not_mutated(self):
        tokens = ['--lua-desync=fake:blob=fake_default_tls']
        with mock.patch('builtins.open', side_effect=AssertionError('unexpected I/O')):
            result = blobs.inspect_blobs(tokens, builtin_names=())
        self.assertEqual(result.uses[0].kind, 'unknown')
        self.assertEqual(tokens, ['--lua-desync=fake:blob=fake_default_tls'])
        for bad in ('--blob=x:0x11', [None]):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                blobs.inspect_blobs(bad)

    def test_duplicate_lua_arguments_fail_closed(self):
        result = blobs.inspect_blobs(['--lua-desync=fake:blob=missing:blob=fake_default_tls'])
        self.assertIn('duplicate-argument', [issue.code for issue in result.issues])

    def test_builtin_generators_materialized_once_and_duplicates_rejected(self):
        result = blobs.inspect_blobs(['--lua-desync=fake:blob=custom'],
                                     builtin_names=(name for name in ('custom',)))
        self.assertEqual(result.uses[0].kind, 'global')
        for names in ('custom', ('custom', 'custom'), ('bad-name',), (None,)):
            with self.subTest(names=names), self.assertRaises(ValueError):
                blobs.inspect_blobs([], builtin_names=names)

