"""Pure policy, not permission to traverse or restore filesystem paths."""
import unittest

from kdn.engine import snapshot_policy as policy


class SnapshotPolicyTests(unittest.TestCase):
    def test_scopes_and_children(self):
        self.assertEqual(policy.path_policy('/opt/etc/nfqws2/lists/user.list'), 'managed')
        self.assertEqual(policy.path_policy('/opt/etc/xkeen/xkeen.json'), 'managed')
        self.assertEqual(policy.path_policy('/opt/etc/xkeen/xkeen.json', 'standalone'), 'unmanaged')
        self.assertEqual(policy.path_policy('/opt/etc/xkeen-other'), 'unmanaged')
        self.assertEqual(policy.path_policy('/opt/etc/init.d/S05xkeen/child'), 'unmanaged')
        with self.assertRaises(ValueError):
            policy.path_policy('/opt/etc/nfqws2', 'other')

    def test_vpn_exclusion_wins_in_old_and_new_inventories(self):
        for suffix in ('', '/child'):
            self.assertEqual(policy.path_policy('/opt/etc/xray/configs/04_outbounds.json' + suffix), 'excluded')
        self.assertEqual(policy.path_policy('/opt/etc/xray/configs/05_routing.json'), 'managed')
        self.assertEqual(policy.path_policy('/opt/etc/xray/configs/04_outbounds.json.bak'), 'managed')

    def test_noncanonical_paths_fail_closed(self):
        for path in ('', '/', 'opt/etc/nfqws2', '/opt//etc/nfqws2',
                     '/opt/etc/../etc/nfqws2', '/opt/etc/./nfqws2',
                     '/opt/etc/nfqws2/', '/opt/etc/nfqws2\n', '/opt/etc\\nfqws2'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                policy.path_policy(path)

    def test_versions_require_exact_known_release(self):
        for release in ('2.1', '2.1.1', '2.2', '2.1.9', '2.1.1β'):
            self.assertTrue(policy.versions_compatible(release, release))
        for saved, current in (('2.0', '2.1'), ('2.0.1', '2.0.2'),
                               ('2.0', '2.0.0'), ('', ''), (None, '2.1'),
                               ('3.0', '3.0'), ('XKeen 2.1', '2.1'),
                               ('2.1\n', '2.1'), ('2.01', '2.01'), ('2.0', '2.0'), ('2.0.1', '2.0.1')):
            with self.subTest(saved=saved, current=current):
                self.assertFalse(policy.versions_compatible(saved, current))

    def test_version_policy_is_data_only(self):
        self.assertEqual(policy.xkeen_restore_policy('2.1', '2.1'), 'full-compatible')
        with self.assertRaises(ValueError):
            policy.xkeen_restore_policy(None, '2.1')

    def test_21_plus_labelled_version_and_old_baseline_policy(self):
        for output, expected in (('XKeen 2.1', '2.1'), ('Версия XKeen 2.1.1β', '2.1.1β'),
                                 ('XKeen 2.2', '2.2'), ('XKeen 2.0', ''),
                                 ('XKeen 2.1 / XKeen 2.2', ''), ('XKeen 3.0', ''), ('unknown', '')):
            with self.subTest(output=output):
                self.assertEqual(policy.version_from_text(output), expected)
        with self.assertRaises(ValueError):
            policy.xkeen_restore_policy('2.0', '2.1')

    def test_actual_cli_separate_beta_build_is_not_a_stable_snapshot_version(self):
        self.assertEqual(policy.version_from_text('XKeen 2.1.1 Beta (время сборки: 2026)'), '2.1.1-beta')
        self.assertEqual(policy.version_from_text('XKeen 2.1.1 Stable'), '2.1.1')
        self.assertFalse(policy.versions_compatible('2.1.1-beta', '2.1.1'))
