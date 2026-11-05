"""Operation admission does file-only preflight and creates detached job specifications."""
import json
import re
import subprocess
from types import SimpleNamespace
from unittest import mock

import panel_harness
from tools.router.vpn_node_manager import display_name


class OperationTests(panel_harness.PanelTestCase):
    modules = ("kdn.web.domain.operations",)

    def setUp(self):
        self.root = self.fresh_root()
        self.ops = self.ns.module("operations")
        self.jobs = self.ns.module("jobfiles")
        self.cfg = self.ns.module("config")
        self.profile = {"service": "youtube", "candidate_id": "A"}
        self.manager = SimpleNamespace(load=lambda: {"nodes": {"current": {}}}, _mutation_allowed=lambda: None)
        self.module = SimpleNamespace(NODE_NAME=re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,31}"), MAX_NODES=16,
                                      normalize_outbound=mock.Mock(), display_name=display_name)
        self.patch(vpn_manager=lambda: self.manager, VPN_MODULE=self.module,
                   validate_report=lambda body: self.profile, profile_version_path=lambda *args: (None, self.profile),
                   run_command=mock.Mock(side_effect=AssertionError("command in admission")))

    def operations(self):
        return [(lambda: self.ops.start_xkeen_job("start"), "XKEEN_ACTION"),
                (lambda: self.ops.start_apply_job(self.profile), "PROFILE_APPLY"),
                (self.ops.start_tuner_apply_job, "TUNER_APPLY"),
                (lambda: self.ops.start_version_apply_job("youtube", "v1"), "VERSION_APPLY"),
                (lambda: self.ops.start_import_clear_job("youtube"), "PROFILE_CLEAR"),
                (self.ops.start_import_rollback_job, "IMPORT_ROLLBACK"),
                (lambda: self.ops.start_vpn_add_job("node1", "vless://fixture"), "VPN_STORE"),
                (lambda: self.ops.start_vpn_check_job("current"), "VPN_STORE")]

    def test_unicode_add_uses_ascii_worker_subject_and_private_payload(self):
        with mock.patch.object(self.ops, '_launch', return_value={'ok': True}) as launch:
            self.ops.start_vpn_add_job('Европа', 'vless://fixture')
        self.assertEqual(launch.call_args.args[:4], ('vpn-add', 'new-node', 'vpn', 'add'))
        self.assertEqual(launch.call_args.args[4], {'name': 'Европа', 'source': 'vless://fixture'})

    def test_every_operation_own_refusals_before_payload_or_spawn(self):
        for callback, preset in self.operations():
            for family in ("route", "tuner", "diagnostic"):
                with self.subTest(preset=preset, family=family), self.patched(**{family + "_active": lambda: True}), \
                        mock.patch.object(subprocess, "Popen") as popen:
                    with self.assertRaises(RuntimeError) as exc:
                        callback()
                    self.assertEqual(str(exc.exception), getattr(getattr(self.ops.refusals, preset), family))
                    popen.assert_not_called()
                    self.assertFalse(self.jobs.route_payload_path().exists())

    def test_state_worker_args_payload_and_no_history(self):
        self.cfg.PROJECT_DIR.mkdir(parents=True, exist_ok=True)
        self.cfg.TUNER_STATE.parent.mkdir(parents=True, exist_ok=True)
        self.cfg.TUNER_STATE.write_text('{"status":"found","result_available":true}')
        self.cfg.TUNER_RESULT.write_text('{}')
        for callback, _preset in self.operations():
            with mock.patch.object(subprocess, "Popen", return_value=mock.Mock(pid=4321)) as popen:
                state = callback()
            self.assertEqual((state["status"], state["active"], state["progress"]), ("queued", True, 0))
            self.assertEqual(popen.call_args.args[0][2:4], ["--route-job", state["job_id"]])
            self.assertEqual(popen.call_args.args[0][4], state["operation"])
            self.assertNotIn("vless://fixture", popen.call_args.args[0])
            self.assertFalse(self.cfg.ROUTE_HISTORY_DIR.exists())
            if self.jobs.route_payload_path().exists():
                self.assertEqual(self.jobs.route_payload_path().stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(self.jobs.route_payload_path().read_text())["job_id"], state["job_id"])

    def test_validation_and_vpn_preflight_never_probe(self):
        for callback in (lambda: self.ops.start_xkeen_job("invalid"), lambda: self.ops.start_import_clear_job("invalid"),
                         lambda: self.ops.start_vpn_add_job("current", "fixture"),
                         lambda: self.ops.start_vpn_add_job("bad;id", "fixture"),
                         lambda: self.ops.start_vpn_check_job("missing")):
            with self.assertRaises(ValueError):
                callback()
        with mock.patch.object(self.module, "normalize_outbound", side_effect=ValueError("bad source")):
            with self.assertRaisesRegex(ValueError, "некорректная ссылка"):
                self.ops.start_vpn_add_job("node1", "fixture")
        with mock.patch.object(self.manager, "load", return_value={"nodes": {str(n): {} for n in range(16)}}):
            with self.assertRaisesRegex(ValueError, "предел 16"):
                self.ops.start_vpn_add_job("node1", "fixture")
