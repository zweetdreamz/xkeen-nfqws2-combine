"""Local-only tests for the global VPN node panel."""

from pathlib import Path
import json
import tempfile
import sys
import unittest

import panel_harness


class OutboundSelectionTests(panel_harness.PanelTestCase):
    ns_name = "outbound_selection_test"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.panel = cls.ns

    def setUp(self):
        (panel_harness.ROOT / "tests" / ".generated").mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=panel_harness.ROOT / "tests" / ".generated")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_start_job_keeps_all_service_routes_unchanged(self):
        captured = []

        class FakeManager:
            def load(self):
                return {"nodes": {"vless_2": {}}}

            def status(self):
                return {"active": "current", "drift": False, "warning": "", "recovery_needed": False, "nodes": []}

        with self.patched(
            run_command=lambda *_args, **_kwargs: {"ok": True, "output": "detected_core=xray\n"},
            vpn_manager=FakeManager,
            current_routes_fast=lambda: {"discord-tcp": "zapret", "discord-voice": "zapret",
                                         "youtube": "vless", "telegram": "unmanaged"},
            launch_route_worker=lambda state, args: captured.append((state, args)) or state,
        ):
            state = self.panel["start_vpn_node_job"]("vless_2")
            self.assertEqual(state["operation"], "vpn-node")
            self.assertEqual(state["requested_routes"]["discord-tcp"], "zapret")
            self.assertEqual(state["requested_routes"]["youtube"], "vless")
            self.assertEqual(state["outbound_tag"], "vless_2")
            self.assertEqual(captured[0][1], ["vpn-node", "vless_2", "-"])
            with self.assertRaises(ValueError):
                self.panel["start_vpn_node_job"]("missing")
            with self.assertRaises(ValueError):
                self.panel["start_vpn_node_job"]("bad;command")

    def test_panel_has_one_global_node_tab_and_independent_checker(self):
        page = (panel_harness.ROOT / "tools/router/kdn/web/assets/index.html").read_text(encoding="utf-8")
        self.assertIn('data-tab="vpn-nodes"', page)
        self.assertIn('textContent="Проверить"', page)
        self.assertIn('textContent="Сделать активной"', page)
        self.assertNotIn('data-outbound-service="discord-tcp"', page)

    def test_route_worker_calls_global_manager_not_service_switch(self):
        captured = []
        manager = self.root / "vpn_node_manager.py"
        state = self.root / "route" / "state.json"
        state.parent.mkdir()
        state.write_text(json.dumps({"job_id": "0123456789abcdef", "operation": "vpn-node", "status": "queued"}))
        with self.patched(
            VPN_MANAGER_SCRIPT=manager,
            ROUTE_STATE=state,
            update_history=lambda *_args, **_kwargs: True,
            current_routes_fast=lambda: {"youtube": "zapret"},
            run_route_command=lambda command, *_args: captured.append(command) or
                              {"ok": True, "code": 0, "output": "Global VPN node active"},
        ):
            self.assertEqual(self.panel["run_route_job"]("0123456789abcdef", "vpn-node", "vless_2", "-"), 0)
        self.assertEqual(captured, [[sys.executable, str(manager), "activate", "vless_2"]])
        self.assertEqual(json.loads(state.read_text())["status"], "completed")


if __name__ == "__main__":
    unittest.main()
