"""Local-only tests for the global VPN node registry and switch transaction."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.router.vpn_node_manager import VpnNodeManager, normalize_outbound
from panel_harness import ROOT


UUID = "6f1c7e0a-6b1a-4c35-9a52-7a3f2b8e9c10"


def outbound(address="vpn.example"):
    return {"tag": "vless-reality", "protocol": "vless",
            "settings": {"address": address, "port": 443, "id": UUID, "encryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"serverName": "example.com", "fingerprint": "chrome",
                                                   "publicKey": "key", "shortId": "", "spiderX": "/"}}}


class VpnNodeTests(unittest.TestCase):
    def test_public_connection_metadata_excludes_credentials(self):
        value = outbound()
        value['settings']['flow'] = 'xtls-rprx-vision'
        node = {'outbound': value, 'name': 'node'}
        public = self.manager._public_node('n1', node, 'n1')
        self.assertEqual(public['endpoint'], 'vpn.example:443')
        self.assertEqual(public['sni'], 'example.com')
        self.assertEqual(public['fingerprint'], 'chrome')
        self.assertEqual(public['flow'], 'xtls-rprx-vision')
        self.assertNotIn(UUID, json.dumps(public))
        self.assertNotIn('publicKey', json.dumps(public))
        self.assertNotIn('outbound', public)
        for field in ('serverName', 'fingerprint'):
            value['streamSettings']['realitySettings'][field] = '<img src=x onerror=alert(1)>'
        value['settings']['flow'] = 'private-secret'
        public = self.manager._public_node('n1', node, 'n1')
        self.assertIsNone(public['sni'])
        self.assertIsNone(public['fingerprint'])
        self.assertIsNone(public['flow'])

    def test_tls_metadata_and_missing_optional_fields(self):
        value = outbound('2001:db8::1')
        value['streamSettings'] = {'network': 'ws', 'security': 'tls',
                                   'tlsSettings': {'serverName': 'front.example', 'fingerprint': 'firefox'}}
        node = {'outbound': value}
        public = self.manager._public_node('n1', node, '')
        self.assertEqual(public['endpoint'], '[2001:db8::1]:443')
        self.assertEqual(public['sni'], 'front.example')
        self.assertEqual(public['fingerprint'], 'firefox')
        self.assertIsNone(public['flow'])
        value['streamSettings'] = {}
        public = self.manager._public_node('n1', node, '')
        self.assertIsNone(public['sni'])
        self.assertIsNone(public['fingerprint'])

    def setUp(self):
        (ROOT / "tests" / ".generated").mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "tests" / ".generated")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.xray_dir = self.root / "xray"
        self.xray_dir.mkdir()
        self.outbounds = self.xray_dir / "04_outbounds.json"
        self.outbounds.write_text(json.dumps({"outbounds": [outbound(),
            {"tag": "direct", "protocol": "freedom"}]}), encoding="utf-8")
        (self.xray_dir / "05_routing.json").write_text(json.dumps({"routing": {"rules": [
            {"outboundTag": "vless-reality", "domain": ["domain:example.net"]},
            {"outboundTag": "direct", "domain": ["domain:local.test"]},
        ]}}), encoding="utf-8")
        self.manager_args = {"xray_dir": self.xray_dir, "state_file": self.root / "vpn-nodes.json",
                             "backup_dir": self.root / "backups", "lock_dir": self.root / "project.lock"}
        self.manager = VpnNodeManager(**self.manager_args)
        # These are transaction/lifecycle sequencing tests, not /proc or version
        # parsing tests. Dedicated integration vectors exercise both real guards.
        for method in ('_owns_xray_pid', '_require_supported_xkeen'):
            patcher = mock.patch.object(VpnNodeManager, method, return_value=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_vless_link_and_json_are_accepted(self):
        link = (f"vless://{UUID}@node.example:443?type=tcp&security=reality"
                "&sni=example.com&fp=chrome&pbk=public&sid=abcd#node")
        converted = normalize_outbound(link)
        self.assertEqual(converted["tag"], "vless-reality")
        self.assertEqual(converted["settings"]["address"], "node.example")
        self.assertEqual(converted["streamSettings"]["realitySettings"]["shortId"], "abcd")
        self.assertEqual(normalize_outbound(json.dumps(outbound("other.example")))["settings"]["address"],
                         "other.example")
        with self.assertRaises(ValueError):
            normalize_outbound("not a link or JSON")

    def test_trojan_and_hysteria2_links(self):
        trojan = normalize_outbound("trojan://secret@node.example:443?security=tls&sni=front.example&type=tcp")
        self.assertEqual(trojan["protocol"], "trojan")
        self.assertEqual(trojan["settings"]["password"], "secret")
        hysteria = normalize_outbound("hy2://authpass@hy.example:443/?sni=front.example")
        self.assertEqual(hysteria["protocol"], "hysteria")
        self.assertEqual(hysteria["settings"]["version"], 2)
        self.assertEqual(hysteria["streamSettings"]["hysteriaSettings"]["auth"], "authpass")
        with self.assertRaisesRegex(ValueError, "insecure"):
            normalize_outbound("hysteria2://auth@hy.example/?insecure=1")
        with self.assertRaisesRegex(ValueError, "неподдерживаемые параметры"):
            normalize_outbound("hy2://auth@hy.example/?up=100")

    def test_hysteria2_json_must_use_xray_protocol_and_transport(self):
        hy = {"tag": "hy2", "protocol": "hysteria",
              "settings": {"version": 2, "address": "hy.example", "port": 443},
              "streamSettings": {"network": "hysteria", "security": "tls",
                                 "tlsSettings": {"serverName": "hy.example", "alpn": ["h3"]},
                                 "hysteriaSettings": {"version": 2, "auth": "secret"}}}
        self.assertEqual(normalize_outbound(hy)["tag"], "vless-reality")
        hy["streamSettings"]["hysteriaSettings"]["version"] = 1
        with self.assertRaises(ValueError):
            normalize_outbound(hy)

    def test_add_checks_immediately_without_changing_live_config(self):
        before = self.outbounds.read_bytes()
        with mock.patch.object(self.manager, "probe", return_value={"ok": True, "checked_utc": "now"}) as probe:
            result = self.manager.add("vless_2", json.dumps(outbound("other.example")))
        probe.assert_called_once()
        self.assertTrue(result["node"]["health"]["ok"])
        self.assertEqual(before, self.outbounds.read_bytes())
        public = self.manager.status()
        self.assertEqual(public["active"], "current")
        self.assertEqual(len(public["nodes"]), 2)
        self.assertNotIn(UUID, json.dumps(public))
        with self.assertRaises(ValueError):
            self.manager.remove("current")

    def test_activation_replaces_one_stable_tag_for_every_existing_rule(self):
        with mock.patch.object(self.manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            self.manager.add("vless_2", json.dumps(outbound("other.example")))
            pid_reads = iter(("100\n", "100\n", "200\n"))  # precondition, before restart, after restart

            def fake_run(command, **_kwargs):
                return mock.Mock(returncode=0, stdout=next(pid_reads) if command == ["pidof", "xray"] else "")

            with mock.patch("tools.router.vpn_node_manager.subprocess.run",
                            side_effect=fake_run) as commands:
                result = self.manager.activate("vless_2")
        self.assertTrue(result["ok"])
        self.assertEqual(self.manager.status()["active"], "vless_2")
        self.assertEqual(json.loads(self.outbounds.read_text())["outbounds"][0]["settings"]["address"],
                         "other.example")
        rules = json.loads((self.xray_dir / "05_routing.json").read_text())["routing"]["rules"]
        self.assertEqual([rule["outboundTag"] for rule in rules], ["vless-reality", "direct"])
        self.assertTrue(any(call.args[0] == [self.manager.xkeen_init, "restart", "on"] for call in commands.call_args_list))

    def activate_with_xray_test(self, run_xray_test):
        """Activate vless_2 with run_xray_test(command, kwargs) answering `xray run -test`.

        Returns the recorded commands and the bytes of 04_outbounds.json before the attempt.
        """
        with mock.patch.object(self.manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            self.manager.add("vless_2", json.dumps(outbound("other.example")))
            before = self.outbounds.read_bytes()
            calls = []
            pid_reads = iter(("100\n", "100\n", "200\n"))  # precondition, before rollback restart, after it

            def fake_run(command, **kwargs):
                calls.append(command)
                if command[:3] == [self.manager.xray, "run", "-test"]:
                    return run_xray_test(command, kwargs)
                return mock.Mock(returncode=0, stdout=next(pid_reads) if command == ["pidof", "xray"] else "")

            with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "xray -test") as caught:
                    self.manager.activate("vless_2")
        return calls, before, caught.exception

    def test_failed_xray_test_restores_previous_outbound(self):
        seen = []

        def failing_test(command, kwargs):
            seen.append((command, kwargs))
            return mock.Mock(returncode=1, stdout="a" * 600 + "Failed to start: broken")

        calls, before, error = self.activate_with_xray_test(failing_test)
        self.assertEqual(self.outbounds.read_bytes(), before)
        self.assertEqual(self.manager.status()["active"], "current")
        self.assertNotIn([self.manager.xkeen_init, "restart", "on"], calls)  # stage failure: live state untouched
        self.assertFalse(self.manager.transaction_file.exists())
        self.assertEqual(
            [self.manager.xray, "run", "-test", "-confdir", seen[0][0][4], "-format", "json"], seen[0][0])
        self.assertNotEqual(seen[0][0][4], str(self.xray_dir))
        self.assertTrue(Path(seen[0][0][4]).name.startswith('xkeen-vpn-stage-'))
        self.assertEqual(seen[0][1]["timeout"], 60)
        self.assertEqual(seen[0][1]["env"]["XRAY_LOCATION_ASSET"], str(self.manager.dat_dir))
        self.assertNotIn('Failed to start: broken', str(error))
        self.assertLessEqual(len(str(error)), 500)

    def test_xray_test_timeout_is_a_failure(self):
        def hanging_test(command, kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        calls, before, _error = self.activate_with_xray_test(hanging_test)
        self.assertEqual(self.outbounds.read_bytes(), before)
        self.assertEqual(self.manager.status()["active"], "current")
        self.assertNotIn([self.manager.xkeen_init, "restart", "on"], calls)  # stage timeout: no live restart
        self.assertFalse(self.manager.transaction_file.exists())

    def test_xkeen_xtest_is_not_used(self):
        with mock.patch.object(self.manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            self.manager.add("vless_2", json.dumps(outbound("other.example")))
            pid_reads = iter(("100\n", "100\n", "200\n"))
            calls = []

            def fake_run(command, **_kwargs):
                calls.append(command)
                return mock.Mock(returncode=0, stdout=next(pid_reads) if command == ["pidof", "xray"] else "")

            with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run):
                self.manager.activate("vless_2")
        # xkeen -xtest exits 0 whatever the configuration is: it proves nothing.
        self.assertFalse([command for command in calls if "-xtest" in command])
        tests = [command for command in calls if command[:3] == [self.manager.xray, "run", "-test"]]
        self.assertEqual(len(tests), 1)
        self.assertLess(calls.index(tests[0]), calls.index([self.manager.xkeen_init, "restart", "on"]))

    def xkeen_run(self, manager, *after_restart):
        """Stand-in for subprocess.run: `pidof xray` says 100 until `xkeen -restart` runs.

        after_restart[n] lists what `pidof xray` answers after the n-th restart (the last item repeats).
        Returns the recorded (command, kwargs) pairs and the stand-in.
        """
        calls = []
        state = {"restarts": 0, "reads": 0}

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            if command == [manager.xkeen_init, "restart", "on"]:
                state["restarts"] += 1
                state["reads"] = 0
            if command != ["pidof", "xray"]:
                return mock.Mock(returncode=0, stdout="")
            if not state["restarts"]:
                return mock.Mock(returncode=0, stdout="100\n")
            answers = after_restart[state["restarts"] - 1]
            pid = answers[min(state["reads"], len(answers) - 1)]
            state["reads"] += 1
            return mock.Mock(returncode=0, stdout=f"{pid}\n")

        return calls, fake_run

    def restart_kwargs(self, calls, manager=None):
        return [kwargs for command, kwargs in calls if command == [(manager or self.manager).xkeen_init, "restart", "on"]]

    def test_restart_runs_xkeen_in_foreground(self):
        # Without a TTY "xkeen -restart" detaches (start-stop-daemon -b) and returns 0 at once.
        with mock.patch.object(self.manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            self.manager.add("vless_2", json.dumps(outbound("other.example")))
            calls, fake_run = self.xkeen_run(self.manager, ("200",))
            with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run):
                self.manager.activate("vless_2")
        restarts = self.restart_kwargs(calls)
        self.assertEqual(len(restarts), 1)
        self.assertEqual(restarts[0]["env"]["XKEEN_FOREGROUND"], "1")
        self.assertEqual(restarts[0]["timeout"], 150)

    def test_activation_waits_for_new_xray_pid(self):
        self.assertEqual(VpnNodeManager().restart_timeout, 90)
        with mock.patch.object(self.manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            self.manager.add("vless_2", json.dumps(outbound("other.example")))
            _calls, fake_run = self.xkeen_run(self.manager, ("100", "100", "200"))
            with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run), \
                    mock.patch("tools.router.vpn_node_manager.time.sleep") as sleep:
                result = self.manager.activate("vless_2")
        self.assertTrue(result["ok"])
        self.assertEqual(self.manager.status()["active"], "vless_2")
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(sleep.call_args_list, [mock.call(self.manager.poll_interval)] * 2)

    def test_activation_rolls_back_when_xray_pid_never_changes(self):
        manager = VpnNodeManager(**self.manager_args, restart_timeout=3, poll_interval=1)
        with mock.patch.object(manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            manager.add("vless_2", json.dumps(outbound("other.example")))
            before = self.outbounds.read_bytes()
            calls, fake_run = self.xkeen_run(manager, ("100",), ("100",))
            with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run), \
                    mock.patch("tools.router.vpn_node_manager.time.sleep") as sleep:
                with self.assertRaisesRegex(RuntimeError, "откат Xray тоже не удался"):
                    manager.activate("vless_2")
        self.assertEqual(self.outbounds.read_bytes(), before)
        self.assertEqual(manager.status()["active"], "current")
        # The rollback restart failed too: the transaction stays for recover_pending.
        self.assertTrue(manager.transaction_file.exists())
        restarts = self.restart_kwargs(calls, manager)
        self.assertEqual(len(restarts), 2)  # the switch and its rollback
        self.assertEqual([kwargs["env"]["XKEEN_FOREGROUND"] for kwargs in restarts], ["1", "1"])
        self.assertEqual(sleep.call_args_list, [mock.call(1)] * 6)  # restart_timeout / poll_interval per restart

    def test_failed_switch_is_rolled_back_when_the_old_config_restarts(self):
        manager = VpnNodeManager(**self.manager_args, restart_timeout=3, poll_interval=1)
        with mock.patch.object(manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            manager.add("vless_2", json.dumps(outbound("other.example")))
            before = self.outbounds.read_bytes()
            calls, fake_run = self.xkeen_run(manager, ("100",), ("300",))
            with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run), \
                    mock.patch("tools.router.vpn_node_manager.time.sleep"):
                with self.assertRaisesRegex(RuntimeError, "Xray не перезапустился за 3 с") as caught:
                    manager.activate("vless_2")
        self.assertNotIn("откат", str(caught.exception))
        self.assertEqual(self.outbounds.read_bytes(), before)
        self.assertFalse(manager.transaction_file.exists())
        self.assertEqual(manager.status()["active"], "current")
        restarts = self.restart_kwargs(calls, manager)
        self.assertEqual([kwargs["env"]["XKEEN_FOREGROUND"] for kwargs in restarts], ["1", "1"])

    def test_xkeen_restart_failure_is_reported(self):
        failure = "xkeen -restart завершился с ошибкой: "
        for name, outcome, message in (
                ("exit code", mock.Mock(returncode=3), failure + "код 3"),
                ("timeout", subprocess.TimeoutExpired(["xkeen"], 150), failure + "таймаут 150 с")):
            with self.subTest(name):
                with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=[outcome]) as run:
                    with self.assertRaises(RuntimeError) as caught:
                        self.manager._restart_xkeen(frozenset({"100"}))
                self.assertEqual(str(caught.exception), message)
                run.assert_called_once()

    def test_recovery_restarts_xkeen_in_foreground_and_waits_for_xray(self):
        self.pending_transaction()
        calls, fake_run = self.xkeen_run(self.manager, ("100", "200"))
        with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run), \
                mock.patch("tools.router.vpn_node_manager.time.sleep") as sleep:
            result = self.manager.recover_pending()
        self.assertEqual(result, {"ok": True, "needed": True, "restarted": True})
        self.assertEqual(json.loads(self.outbounds.read_text())["outbounds"][0]["settings"]["address"], "old.example")
        self.assertFalse(self.manager.transaction_file.exists())
        self.assertEqual([kwargs["env"]["XKEEN_FOREGROUND"] for kwargs in self.restart_kwargs(calls)], ["1"])
        self.assertEqual(sleep.call_count, 1)

    def test_recovery_fails_when_xray_does_not_come_back(self):
        manager = VpnNodeManager(**self.manager_args, restart_timeout=2, poll_interval=1)
        self.pending_transaction()
        _calls, fake_run = self.xkeen_run(manager, ("100",))
        with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run), \
                mock.patch("tools.router.vpn_node_manager.time.sleep"):
            with self.assertRaisesRegex(RuntimeError, "XKeen не запустился: Xray не перезапустился за 2 с"):
                manager.recover_pending()
        self.assertTrue(manager.transaction_file.exists())

    def pending_transaction(self):
        """Leave an interrupted switch behind: new.example on disk, old.example in the snapshot."""
        self.manager.backup_dir.mkdir(mode=0o700)
        snapshot = self.manager.backup_dir / "20260101T000000Z-0123abcd"
        snapshot.mkdir(mode=0o700)
        (snapshot / "04_outbounds.json").write_text(json.dumps({"outbounds": [outbound("old.example")]}),
                                                    encoding="utf-8")
        self.outbounds.write_text(json.dumps({"outbounds": [outbound("new.example")]}), encoding="utf-8")
        self.manager.transaction_file.write_text(json.dumps({"version": 1, "snapshot": str(snapshot)}),
                                                 encoding="utf-8")
        return snapshot

    def test_recovery_checks_the_restored_config_with_xray(self):
        self.pending_transaction()
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            return mock.Mock(returncode=1 if command[:3] == [self.manager.xray, "run", "-test"] else 0, stdout="")

        with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "xray -test"):
                self.manager.recover_pending()
        self.assertFalse([command for command in calls if "-xtest" in command])
        self.assertNotIn([self.manager.xkeen_init, "restart", "on"], calls)

    def test_trojan_then_hysteria2_use_same_global_tag(self):
        trojan = normalize_outbound("trojan://secret@trojan.example:443?sni=front.example")
        hysteria = normalize_outbound("hy2://secret@hy.example:443/?sni=front.example")
        with mock.patch.object(self.manager, "probe", return_value={"ok": True, "checked_utc": "now"}):
            self.manager.add("trojan_1", json.dumps(trojan))
            self.manager.add("hy2_1", json.dumps(hysteria))
            pid_reads = iter(("100\n", "100\n", "200\n", "200\n", "200\n", "300\n"))

            def fake_run(command, **_kwargs):
                return mock.Mock(returncode=0, stdout=next(pid_reads) if command == ["pidof", "xray"] else "")

            with mock.patch("tools.router.vpn_node_manager.subprocess.run", side_effect=fake_run):
                self.manager.activate("trojan_1")
                self.assertEqual(json.loads(self.outbounds.read_text())["outbounds"][0]["protocol"], "trojan")
                self.manager.activate("hy2_1")
        active = json.loads(self.outbounds.read_text())["outbounds"][0]
        self.assertEqual((active["tag"], active["protocol"]), ("vless-reality", "hysteria"))
        self.assertEqual(self.manager.status()["active"], "hy2_1")

    def test_other_vless_route_target_blocks_global_claim(self):
        (self.xray_dir / "04_other.json").write_text(json.dumps({"outbounds": [
            {"tag": "private-node", "protocol": "vless"}]}), encoding="utf-8")
        (self.xray_dir / "05_routing.json").write_text(json.dumps({"routing": {"rules": [
            {"outboundTag": "private-node", "domain": ["domain:other.example"]}]}}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "другие proxy outbound"):
            self.manager._verify_global_targets()


if __name__ == "__main__":
    unittest.main()
