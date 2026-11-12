"""Offline documentation and packaging checks; never execute router examples."""
from pathlib import Path
import re
import fnmatch
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DOC_TREE = (
    'README.md', 'usage/operations.md', 'usage/route-checker.md', 'configuration/cli.md',
    'configuration/zapret.md', 'configuration/vpn.md', 'configuration/telegram.md', 'configuration/dns.md',
    'reference/architecture.md', 'reference/safety.md', 'development.md',
)
DOC_ASSETS = (
    'images/control.png', 'images/notifications.png',
    'images/schedule.png', 'images/vpn-nodes.png', 'images/vpn-monitor.png',
)
CURRENT_DOCS = ('README.md', 'tools/router/README.md', 'tools/windows/README.md',
                'tools/dat-reader/README.md') + tuple('docs/' + name for name in DOC_TREE)


def links(path):
    source = re.sub(r'```.*?```', '', path.read_text(encoding='utf-8'), flags=re.S)
    return [target.split(' "', 1)[0]
            for _, target in re.findall(r'\[([^]]+)\]\(([^)]+)\)', source)]


class DocumentationTests(unittest.TestCase):
    def test_docs_tree_contains_current_documents_only(self):
        actual = {p.relative_to(ROOT / 'docs').as_posix()
                  for p in (ROOT / 'docs').rglob('*') if p.is_file()}
        self.assertEqual(actual, set(DOC_TREE) | set(DOC_ASSETS))

    def test_current_local_links_resolve(self):
        for relative in CURRENT_DOCS:
            source = ROOT / relative
            for link in links(source):
                with self.subTest(source=relative, link=link):
                    value = urlsplit(link.strip('<>'))
                    if value.scheme or value.netloc or not value.path:
                        continue
                    target = (source.parent / unquote(value.path)).resolve()
                    self.assertTrue(target.is_relative_to(ROOT), 'local link escapes project')
                    self.assertTrue(target.exists(), 'broken local documentation link')
                    if value.fragment and target.suffix == '.md':
                        headings = re.findall(r'^#{1,6}\s+(.+)$', target.read_text(encoding='utf-8'), re.M)
                        anchors = {re.sub(r'[^\w -]', '', heading.lower()).replace(' ', '-')
                                   for heading in headings}
                        self.assertIn(unquote(value.fragment), anchors, 'broken heading link')

    def test_index_lists_every_current_topic(self):
        index = (ROOT / 'docs/README.md').read_text(encoding='utf-8')
        for relative in DOC_TREE[1:]:
            self.assertIn('](' + relative + ')', index)

    def test_restore_eligibility_is_explicit(self):
        for relative in ('README.md', 'docs/reference/safety.md', 'docs/usage/operations.md'):
            source = ' '.join((ROOT / relative).read_text(encoding='utf-8').lower().split())
            with self.subTest(document=relative):
                self.assertIn('2.0', source)
                self.assertIn('не восстанавливаются', source)
                self.assertIn('stable/beta', source)
        readme = (ROOT / 'README.md').read_text(encoding='utf-8').lower()
        self.assertRegex(readme, r'xkeen\s*2\.1\+')

    def test_script_version_is_not_a_fictional_release(self):
        config = (ROOT / 'tools/router/kdn/engine/config.py').read_text(encoding='utf-8')
        version = re.search(r'^SCRIPT_VERSION = "([^"]+)"', config, re.M).group(1)
        self.assertIn('SCRIPT_VERSION=' + version, (ROOT / 'README.md').read_text(encoding='utf-8'))

    def test_legacy_shell_tools_are_not_deployed_and_launchers_remain(self):
        patterns = [row.strip() for row in (ROOT / 'tools/dev/deploy-manifest.txt').read_text().splitlines()
                    if row.strip() and not row.startswith('#')]
        for name in ('diagnose-router.sh', 'diagnose-xkeen-router.sh', 'upgrade-nfqws2-router.sh'):
            with self.subTest(script=name):
                self.assertFalse((ROOT / 'scripts' / name).exists())
                self.assertFalse((ROOT / 'tools/router' / name).exists())
                archived = 'manual-delete/legacy-shell/' + name
                self.assertFalse(any(fnmatch.fnmatchcase(archived, pattern) for pattern in patterns))
        for name in ('apply-discord-nfqws2.sh', 'set-service-route.sh', 'set-zapret-mode.sh',
                     'rollback-last-change.sh', 'rollback-to-baseline.sh',
                     'scripts/diagnose-discord-voice.sh', 'tools/windows/router-candidate-runner.sh'):
            self.assertTrue((ROOT / name).is_file(), 'required shell adapter removed')
