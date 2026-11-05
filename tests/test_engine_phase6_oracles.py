"""Legacy source is immutable non-deployed test data, never the live implementation."""
import glob
import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PINS = {
    'legacy-apply-phase6.sh.txt': 'db53d7244fd9d4ee9cd14473eabcc61871f5acc906686ca7644deecb40b540e0',
    'legacy-set-service-phase6.sh.txt': 'aae5f42a43c3965295373ac67c152d823903eeb4b97cf5f60dfbf20d260570b1',
    'legacy-set-mode-phase6.sh.txt': 'de791449d5abbdc7978ffb2140cf7b95f3a3c40543b9a508f46383af28d2f14e',
}


class Phase6OracleTests(unittest.TestCase):
    def test_source_pins_and_no_oracle_in_deploy_manifest(self):
        deployed = set()
        for line in (ROOT / 'tools/dev/deploy-manifest.txt').read_text().splitlines():
            if line and not line.startswith('#'):
                deployed.update(Path(path).resolve() for path in glob.glob(str(ROOT / line)))
        for name, digest in PINS.items():
            path = ROOT / 'tests/fixtures/engine' / name
            with self.subTest(oracle=name):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                self.assertNotIn(path.resolve(), deployed)

    def test_root_scripts_are_launchers_not_old_mutation_implementations(self):
        for name in ('apply-discord-nfqws2.sh', 'set-service-route.sh', 'set-zapret-mode.sh'):
            text = (ROOT / name).read_text()
            with self.subTest(script=name):
                self.assertLess(len(text.splitlines()), 200)
                self.assertNotIn('patch_xray() {', text)
                self.assertNotIn('patch_mihomo() {', text)
                self.assertNotIn('apply_transaction() {', text)
