"""Tests of the engine adapter kdn.web.infra.engine: the engine CLI the panel runs, built in one place.

The commands and timeouts are the ones the panel used before the adapter, byte for byte. The engine and the
service switch are called with their absolute paths, read from the configuration at call time.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import panel_harness


OK = {"ok": True, "code": 0, "output": "engine output"}


class PanelEngineTests(panel_harness.PanelTestCase):
    ns_name = "panel_engine_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.calls = []

    def record(self, command, /, *, timeout):
        # The panel passes the command positionally and the timeout by keyword, nothing else.
        self.calls.append((command, timeout))
        if command[-2:] == ['--status', '--json']:
            return {**OK, 'output': json.dumps({'schema': 1, 'text': OK['output']}, indent=2)}
        return dict(OK)

    def test_engine_commands_use_absolute_paths(self):
        engine, switch = self.ns["ENGINE"], self.ns["SERVICE_SWITCH"]
        self.assertTrue(engine.is_absolute())
        self.assertTrue(switch.is_absolute())
        self.assertEqual(self.ns["engine_command"]("--status"), ["/bin/sh", str(engine), "--status"])
        self.assertEqual(self.ns["engine_command"](), ["/bin/sh", str(engine)])
        self.assertEqual(
            self.ns["service_switch_command"]("youtube", "vpn"),
            ["/bin/sh", str(switch), "youtube", "vpn", "--core", "auto", "--yes-router"],
        )
        snapshot = self.root / "snapshots" / "20261028-0123"
        self.assertEqual(
            self.ns["rollback_snapshot_command"](snapshot),
            ["/bin/sh", str(engine), "--rollback-snapshot", str(snapshot), "--yes-router"],
        )
        # The paths are read at call time, from the configuration.
        with self.patched(ENGINE=Path("/x/engine.sh"), SERVICE_SWITCH=Path("/x/switch.sh")):
            self.assertEqual(self.ns["engine_command"]("--a", "b"), ["/bin/sh", "/x/engine.sh", "--a", "b"])
            self.assertEqual(
                self.ns["service_switch_command"]("discord", "direct"),
                ["/bin/sh", "/x/switch.sh", "discord", "direct", "--core", "auto", "--yes-router"],
            )

    def test_read_status_uses_40s(self):
        self.patch(run_command=self.record)
        self.assertEqual(self.ns["read_status"](), OK)
        self.assertEqual(self.calls, [(["/bin/sh", str(self.ns["ENGINE"]), "--status", "--json"], 40)])

    def test_read_status_keeps_the_text_output_with_warnings(self):
        text = 'project=fixture\nxkeen_runtime=running\n'
        output = 'ERROR: core diagnostic\n' + json.dumps({'schema': 1, 'text': text, 'warnings': ['ERROR: core diagnostic']}, indent=2)
        calls = []

        def run(command, *, timeout):
            calls.append((command, timeout))
            return {'ok': True, 'code': 0, 'output': output}

        self.patch(run_command=run)
        self.assertEqual(self.ns['read_status'](), {'ok': True, 'code': 0, 'output': 'ERROR: core diagnostic\n' + text.strip()})
        self.assertEqual(calls, [(["/bin/sh", str(self.ns['ENGINE']), '--status', '--json'], 40)])

    def test_parse_result(self):
        for value in ('ok', 'failed', 'rolled-back', 'partial'):
            with self.subTest(value=value):
                self.assertEqual(self.ns['parse_result']('before\nRESULT|' + value + '\n'), value)
                self.assertEqual(self.ns['parse_result']('RESULT|ok\r\nRESULT|' + value + '\r\n'), value)
        for text in ('', 'RESULT|unknown', 'RESULT|ok\nmore work\n', 'RESULT|ok|extra', 'prefix RESULT|ok', 'RESULT|ok '):
            with self.subTest(text=text):
                self.assertIsNone(self.ns['parse_result'](text))

    def test_read_status_falls_back_to_text_for_invalid_or_old_documents(self):
        invalid = [None, 'unknown argument: --json', '{\n broken', json.dumps({'schema': 2, 'text': 'future'}, indent=2),
                   json.dumps({'schema': True, 'text': 'wrong schema type'}, indent=2),
                   json.dumps({'schema': 1, 'text': None}, indent=2), json.dumps({'schema': 1, 'text': '\ud800'}, indent=2), '{}', '{\n}\nextra',
                   '{\nwarning that is not JSON\n' + json.dumps({'schema': 1, 'text': 'must not skip the first brace'}, indent=2)]
        for output in invalid:
            calls = []

            def run(command, *, timeout, calls=calls, output=output):
                calls.append((command, timeout))
                return {'ok': False, 'code': 2, 'output': output} if command[-1] == '--json' else dict(OK)

            with self.subTest(output=output):
                self.patch(run_command=run)
                self.assertEqual(self.ns['read_status'](), OK)
                self.assertEqual(calls, [(["/bin/sh", str(self.ns['ENGINE']), '--status', '--json'], 40),
                                         (["/bin/sh", str(self.ns['ENGINE']), '--status'], 40)])

    def test_read_status_does_not_retry_after_a_timeout(self):
        for output in ('timeout', 'timeout\n' + json.dumps({'schema': 1, 'text': 'partial'}, indent=2)):
            calls = []
            payload = {'ok': False, 'code': 124, 'output': output}

            def run(command, *, timeout, calls=calls, payload=payload):
                calls.append((command, timeout))
                return dict(payload)

            with self.subTest(output=output):
                self.patch(run_command=run)
                self.assertEqual(self.ns['read_status'](), payload)
                self.assertEqual(len(calls), 1)
                calls.clear()
                self.assertIsNone(self.ns['read_status_report']())
                self.assertEqual(len(calls), 1)

    def test_read_status_report_returns_document_and_preserves_failure_metadata(self):
        report = {'schema': 1, 'text': ' xkeen_runtime=stopped\n', 'fields': {'xkeen_runtime': 'stopped'},
                  'lock': {'exists': True, 'pid': 42, 'alive': True}, 'warnings': ['WARNING: example'],
                  'xkeen': {'generation': '2.1'}, 'xray': {'rules': {'total': 3}}}
        calls = []

        def run(command, *, timeout):
            calls.append((command, timeout))
            return {'ok': False, 'code': 1, 'output': 'WARNING: example\n' + json.dumps(report, indent=2)}

        self.patch(run_command=run)
        self.assertEqual(self.ns['read_status_report'](), report)
        self.assertEqual(len(calls), 1)
        calls.clear()
        self.assertEqual(self.ns['read_status'](), {'ok': False, 'code': 1, 'output': 'WARNING: example\n xkeen_runtime=stopped'})
        self.assertEqual(len(calls), 1)

    def test_json_opaque_bytes_keep_old_text_decoder_semantics(self):
        raw_text = 'xkeen_runtime=running\n\udced\udca0\udc80\udcff tail\n'
        report = {'schema': 1, 'text': raw_text}
        self.patch(run_command=lambda *_args, **_kwargs: {'ok': True, 'code': 0, 'output': json.dumps(report, indent=2)})
        expected = raw_text.encode('utf-8', 'surrogateescape').decode('utf-8', 'replace').strip()
        payload = self.ns['read_status']()
        self.assertEqual(payload['output'], expected)
        payload['output'].encode('utf-8')  # safe for the existing HTTP JSON writer
        self.assertEqual(self.ns['read_status_report'](), report)

    def test_report_is_none_after_legacy_fallback(self):
        calls = []

        def run(command, *, timeout):
            calls.append(command)
            return {'ok': True, 'code': 0, 'output': 'legacy text'}

        self.patch(run_command=run)
        self.assertIsNone(self.ns['read_status_report']())
        self.assertEqual([command[2:] for command in calls], [['--status', '--json'], ['--status']])

    def test_route_stage_prefers_last_structured_marker(self):
        switch = [('preflight', 'Проверка конфигурации', 10), ('snapshot', 'Создание snapshot', 25),
                  ('config', 'Запись конфигурации', 45), ('xray', 'Перезапуск XKeen/Xray', 65),
                  ('nfqws', 'Перезапуск nfqws2', 82), ('verify', 'Проверка служб', 94)]
        for expected in switch:
            with self.subTest(expected=expected):
                output = 'STAGE|preflight\nSTAGE|' + expected[0] + '\nSnapshot created: late human text\n'
                self.assertEqual(self.ns['route_stage'](output, 'switch'), expected)
        for operation, stage, label, percent in [('rollback', 'snapshot', 'Rescue snapshot', 30),
                                                 ('rollback', 'restore', 'Восстановление файлов', 58),
                                                 ('rollback', 'verify', 'Проверка восстановленного состояния', 92),
                                                 ('vpn-node', 'snapshot', 'Снимок текущей VPN-ноды', 40),
                                                 ('vpn-node', 'xray', 'Перезапуск XKeen/Xray', 75),
                                                 ('vpn-node', 'verify', 'Проверка выбранной ноды', 94),
                                                 ('vpn-recover', 'verify', 'Прежняя VPN-нода восстановлена', 94)]:
            with self.subTest(operation=operation, stage=stage):
                self.assertEqual(self.ns['route_stage']('STAGE|' + stage + '\r\n', operation), (stage, label, percent))

    def test_route_stage_keeps_the_human_text_fallback(self):
        for output, operation, expected in [('Restarting XKeen...', 'switch', ('xray', 'Перезапуск XKeen/Xray', 65)),
                                             ('Restore complete: /snapshot', 'rollback', ('verify', 'Проверка восстановленного состояния', 92)),
                                             ('Global VPN node active', 'vpn-node', ('verify', 'Проверка выбранной ноды', 94)),
                                             ('Previous global VPN node restored', 'vpn-recover', ('verify', 'Прежняя VPN-нода восстановлена', 94))]:
            with self.subTest(output=output):
                self.assertEqual(self.ns['route_stage'](output, operation), expected)
        # A future unknown final ID falls back to text, not a stale earlier stage.
        self.assertEqual(self.ns['route_stage']('STAGE|preflight\nSTAGE|future\nRestarting XKeen...', 'switch'),
                         ('xray', 'Перезапуск XKeen/Xray', 65))

    def test_read_status_fields_merges_parsed_keys_with_the_command_result(self):
        output = "youtube_route=zapret\ndetected_core=xray\nunlisted_key=1\nnot a status line"
        reads = []

        def read_status():
            reads.append(1)
            return {"ok": True, "code": 0, "output": output}

        self.patch(read_status=read_status)
        self.assertEqual(
            self.ns["read_status_fields"](),
            {"ok": True, "code": 0, "output": output, "youtube_route": "zapret", "detected_core": "xray"},
        )
        # --status takes up to 40 s: one read per call.
        self.assertEqual(len(reads), 1)

    def test_read_status_fields_keeps_a_failed_command_as_is(self):
        for failed in ({"ok": False, "code": 124, "output": ""}, {"ok": False, "code": 1}):
            with self.subTest(failed=failed):
                self.patch(read_status=lambda failed=failed: dict(failed))
                self.assertEqual(self.ns["read_status_fields"](), failed)

    def test_read_status_fields_runs_the_engine_status_once_through_the_adapter(self):
        self.patch(run_command=self.record)
        self.assertEqual(self.ns["read_status_fields"](), OK)
        self.assertEqual(self.calls, [(["/bin/sh", str(self.ns["ENGINE"]), "--status", "--json"], 40)])

    def test_process_running_runs_pidof_with_5s_timeout(self):
        self.patch(run_command=self.record)
        self.assertIs(self.ns["process_running"]("xray"), True)
        self.assertIs(self.ns["process_running"]("nfqws2"), True)
        self.assertEqual(self.calls, [(["pidof", "xray"], 5), (["pidof", "nfqws2"], 5)])

    def test_process_running_is_false_on_failure(self):
        self.patch(run_command=lambda command, /, *, timeout: {"ok": False, "code": 1, "output": ""})
        self.assertIs(self.ns["process_running"]("xray"), False)

    def test_xkeen_command_builds_the_three_actions(self):
        xkeen = str(self.ns["XKEEN_INIT"])
        for action in ("start", "stop", "restart"):
            with self.subTest(action=action):
                expected = [xkeen, action] + ([] if action == "stop" else ["on"])
                self.assertEqual(self.ns["xkeen_command"](action), expected)
        with self.patched(XKEEN_INIT="/x/S05xkeen"):
            self.assertEqual(self.ns["xkeen_command"]("start"), ["/x/S05xkeen", "start", "on"])

    def test_xkeen_command_rejects_other_actions(self):
        for action in ("status", "-start", "START", "start ", "", None, ["start"]):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "неподдерживаемое действие XKeen"):
                self.ns["xkeen_command"](action)

    def test_run_xkeen_action_asks_process_running_for_xray(self):
        asked = []

        def process_running(name):
            asked.append(name)
            return True

        self.patch(process_running=process_running)
        with self.patched(run_command=lambda command, /, *, timeout, env=None: dict(OK)):
            self.assertEqual(self.ns["run_xkeen_action"](["xkeen", "-start"], xray_expected=True), OK)
        self.assertEqual(asked, ["xray"])

    def test_run_xkeen_action_runs_the_command_in_the_foreground_and_judges_xray(self):
        calls = []

        def run_command(command, /, *, timeout, env=None):
            calls.append((command, timeout, env))
            return {"ok": True, "code": 0, "output": "done"}

        command = ["xkeen", "-restart"]
        expected_call = [(command, 150, None)]
        cases = (
            (True, True, {"ok": True, "code": 0, "output": "done"}),
            (False, False, {"ok": True, "code": 0, "output": "done"}),
            (True, False, {"ok": False, "code": 0, "output": "done\nXray не запущен после команды XKeen"}),
            (False, True, {"ok": False, "code": 0, "output": "done\nXray всё ещё запущен после остановки XKeen"}),
        )
        for xray_expected, running, expected in cases:
            with self.subTest(xray_expected=xray_expected, running=running):
                calls.clear()
                with self.patched(run_command=run_command, process_running=lambda name, running=running: running):
                    self.assertEqual(self.ns["run_xkeen_action"](command, xray_expected=xray_expected), expected)
                self.assertEqual(calls, expected_call)

    def test_run_xkeen_action_skips_the_xray_check_when_the_command_failed(self):
        failed = {"ok": False, "code": 124, "output": "timeout"}
        self.patch(process_running=lambda name: self.fail("xray must not be asked after a failed command"))
        with self.patched(run_command=lambda command, /, *, timeout, env=None: dict(failed)):
            self.assertEqual(self.ns["run_xkeen_action"](["xkeen", "-stop"], xray_expected=False), failed)

    def test_import_operations_use_300s(self):
        self.patch(run_command=self.record)
        engine = str(self.ns["ENGINE"])
        self.assertEqual(self.ns["clear_imported_profile"]("youtube"), OK)
        self.assertEqual(self.ns["rollback_import"](), OK)
        self.assertEqual(self.calls, [
            (["/bin/sh", engine, "--clear-imported-profile", "youtube", "--yes-router"], 300),
            (["/bin/sh", engine, "--rollback-import", "--yes-router"], 300),
        ])

    def test_routes_and_voice_high_from_config(self):
        unknown = {"discord-tcp": "unknown", "discord-voice": "unknown", "youtube": "unknown", "telegram": "unknown"}
        unreadable = self.root / "directory.conf"
        unreadable.mkdir()
        for config in (self.root / "missing.conf", unreadable):
            with self.subTest(config=config.name), self.patched(NFQWS_CONFIG=config):
                routes = self.ns["current_routes_fast"]()
                self.assertEqual(routes, unknown)
                routes["youtube"] = "zapret"
                self.assertEqual(self.ns["current_routes_fast"](), unknown)
                self.assertEqual(self.ns["recorded_voice_high"](), (50100, "narrow"))
        config = self.root / "nfqws2.conf"
        with self.patched(NFQWS_CONFIG=config):
            # Bytes that are not UTF-8 do not stop the headers from being read.
            config.write_bytes(
                b"# Active routes: DiscordTCP=zapret, DiscordVoice=direct, YouTube=vless, Telegram=ws.\n"
                b"# Discord UDP: strategy=flowseal, range=wide.\n"
                b"NFQWS_OPT=\"\xff\xfe\"\n"
            )
            self.assertEqual(
                self.ns["current_routes_fast"](),
                {"discord-tcp": "zapret", "discord-voice": "direct", "youtube": "vless", "telegram": "ws"},
            )
            self.assertEqual(self.ns["recorded_voice_high"](), (65535, "wide"))
            config.write_text("# Active routes: DiscordTCP=bogus.\nUDP_PORTS=443,50000-50100\n", encoding="utf-8")
            self.assertEqual(self.ns["current_routes_fast"](), unknown)
            self.assertEqual(self.ns["recorded_voice_high"](), (50100, "narrow"))
            config.write_text("UDP_PORTS=\"443,50000:65535\"\n", encoding="utf-8")
            self.assertEqual(self.ns["recorded_voice_high"](), (65535, "wide"))

    def test_apply_profile_stages_under_staging_dir(self):
        profile = {"service": "youtube", "name": "Проверка", "args": ["--filter-tcp=443"]}
        expected = (json.dumps(profile, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        engine = str(self.ns["ENGINE"])
        seen = []

        def run_command(command, /, *, timeout):
            stage = Path(command[3])
            seen.append((stage, stage.read_bytes(), stat.S_IMODE(os.stat(stage).st_mode)))
            self.calls.append((command, timeout))
            return dict(OK)

        self.patch(IMPORT_STAGING_DIR=self.root, run_command=run_command)
        self.assertEqual(self.ns["apply_profile"](profile), OK)
        ((stage, content, mode),) = seen
        self.assertEqual(self.calls, [(["/bin/sh", engine, "--apply-import-profile", str(stage), "--yes-router"], 300)])
        self.assertEqual(stage.parent, self.root)
        self.assertTrue(stage.name.startswith("xkeen-profile-") and stage.name.endswith(".json"), stage.name)
        self.assertEqual(content, expected)
        self.assertEqual(mode, 0o600)
        self.assertFalse(stage.exists())
        self.assertEqual(list(self.root.iterdir()), [])

        # A failing engine call leaves no staged file behind either.
        def failing(command, /, *, timeout):
            seen.append(Path(command[3]))
            raise OSError("engine failed")

        self.patch(run_command=failing)
        with self.assertRaisesRegex(OSError, "engine failed"):
            self.ns["apply_profile"](profile)
        self.assertFalse(seen[-1].exists())
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
