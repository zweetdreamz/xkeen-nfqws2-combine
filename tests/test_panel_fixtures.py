"""Tests of tests/panel_fixtures.py: the tree digest the "nothing was written" tests compare."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import panel_fixtures


class TreeDigestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "sub" / "deep").mkdir(parents=True)
        (self.root / "empty").mkdir()
        (self.root / "a.txt").write_text("alpha\n", encoding="utf-8")
        (self.root / "sub" / "b.txt").write_text("beta\n", encoding="utf-8")
        (self.root / "sub" / "deep" / "c.bin").write_bytes(b"\x00\x01\x02")

    def keep_mtime(self, path, action):
        """Run ``action`` and give ``path`` back the mtime it had: only the content or the size differs."""
        before = path.stat().st_mtime_ns
        action()
        os.utime(path, ns=(before, before))

    def test_tree_digest_describes_every_file_and_directory(self):
        digest = panel_fixtures.tree_digest(self.root)
        self.assertEqual(
            sorted(digest), ["a.txt", "empty", "sub", "sub/b.txt", "sub/deep", "sub/deep/c.bin"]
        )
        size, mtime_ns, sha = digest["a.txt"]
        self.assertEqual(size, 6)
        self.assertEqual(mtime_ns, (self.root / "a.txt").stat().st_mtime_ns)
        self.assertEqual(sha, hashlib.sha256(b"alpha\n").hexdigest())
        self.assertEqual(digest["sub/deep/c.bin"][2], hashlib.sha256(b"\x00\x01\x02").hexdigest())
        for directory in ("empty", "sub", "sub/deep"):
            with self.subTest(directory=directory):
                self.assertEqual(
                    digest[directory], (0, (self.root / directory).stat().st_mtime_ns, "")
                )

    def test_tree_digest_changes_on_content_size_and_mtime(self):
        target = self.root / "a.txt"
        before = panel_fixtures.tree_digest(self.root)

        self.keep_mtime(target, lambda: target.write_text("omega\n", encoding="utf-8"))
        same_size = panel_fixtures.tree_digest(self.root)
        self.assertEqual(same_size["a.txt"][:2], before["a.txt"][:2])
        self.assertNotEqual(same_size, before)

        self.keep_mtime(target, lambda: target.write_text("alpha\n", encoding="utf-8"))
        self.assertEqual(panel_fixtures.tree_digest(self.root), before)

        self.keep_mtime(target, lambda: target.write_text("alpha, longer\n", encoding="utf-8"))
        longer = panel_fixtures.tree_digest(self.root)
        self.assertNotEqual(longer["a.txt"][0], before["a.txt"][0])
        self.assertNotEqual(longer, before)

        self.keep_mtime(target, lambda: target.write_text("alpha\n", encoding="utf-8"))
        self.assertEqual(panel_fixtures.tree_digest(self.root), before)

        # The same bytes written again a moment later: only the modification time tells it apart.
        stamp = before["a.txt"][1] + 1_000_000_000
        os.utime(target, ns=(stamp, stamp))
        touched = panel_fixtures.tree_digest(self.root)
        self.assertEqual(touched["a.txt"][0], before["a.txt"][0])
        self.assertEqual(touched["a.txt"][2], before["a.txt"][2])
        self.assertNotEqual(touched["a.txt"][1], before["a.txt"][1])
        self.assertNotEqual(touched, before)

    def test_tree_digest_sees_added_removed_and_replaced_entries(self):
        # An old mtime to start from: adding a file must move it, however coarse the clock of the file system is.
        long_ago = 1_000_000_000_000_000_000
        os.utime(self.root / "empty", ns=(long_ago, long_ago))
        before = panel_fixtures.tree_digest(self.root)
        self.assertEqual(before["empty"][1], long_ago)
        added = self.root / "empty" / "new.txt"
        added.write_text("x", encoding="utf-8")
        with_file = panel_fixtures.tree_digest(self.root)
        self.assertEqual(set(with_file) - set(before), {"empty/new.txt"})
        self.assertNotEqual(with_file["empty"], before["empty"])
        added.unlink()
        self.assertEqual(set(panel_fixtures.tree_digest(self.root)), set(before))
        (self.root / "sub" / "deep" / "c.bin").unlink()
        self.assertNotIn("sub/deep/c.bin", panel_fixtures.tree_digest(self.root))

    def test_tree_digest_does_not_follow_links(self):
        elsewhere = tempfile.TemporaryDirectory()
        self.addCleanup(elsewhere.cleanup)
        outside = Path(elsewhere.name)
        (outside / "kept.txt").write_text("outside\n", encoding="utf-8")
        (self.root / "link-dir").symlink_to(outside, target_is_directory=True)
        (self.root / "link-file").symlink_to(outside / "kept.txt")
        digest = panel_fixtures.tree_digest(self.root)
        self.assertIn("link-dir", digest)
        self.assertIn("link-file", digest)
        self.assertNotIn("link-dir/kept.txt", digest)
        (self.root / "link-file").unlink()
        (self.root / "link-file").symlink_to(self.root / "a.txt")
        self.assertNotEqual(panel_fixtures.tree_digest(self.root)["link-file"], digest["link-file"])

    def test_tree_digest_of_an_untouched_tree_is_equal(self):
        first = panel_fixtures.tree_digest(self.root)
        # Reading the tree (files, directory listings) leaves the digest as it was.
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                path.read_bytes()
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["a.txt", "empty", "sub"])
        self.assertEqual(panel_fixtures.tree_digest(self.root), first)
        self.assertEqual(panel_fixtures.tree_digest(str(self.root)), first)

    def test_tree_digest_of_an_empty_directory_is_empty(self):
        empty = self.root / "empty"
        self.assertEqual(panel_fixtures.tree_digest(empty), {})


if __name__ == "__main__":
    unittest.main()
