"""Tests of the parsing and file helpers of the panel: status text, route stages, voice ports, JSON files, PIDs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from panel_fixtures import PanelUnitCase


class ParsingHelpersTests(PanelUnitCase):
    def test_parse_status_keeps_only_allowlisted_keys(self):
        text = (
            "discord_route=zapret\n"
            "youtube_route=vless\n"
            "telegram_route=unmanaged\n"
            "xkeen_runtime=running\n"
            "nfqws_runtime=stopped\n"
            "script_version=6.4=beta\n"
            "unknown_key=value\n"
            "no separator here\n"
            "=empty-key\n"
        )
        self.assertEqual(
            self.ns["parse_status"](text),
            {
                "discord_route": "zapret",
                "youtube_route": "vless",
                "telegram_route": "unmanaged",
                "xkeen_runtime": "running",
                "nfqws_runtime": "stopped",
                "script_version": "6.4=beta",
            },
        )
        self.assertEqual(self.ns["parse_status"](""), {})

    def test_parse_status_last_duplicate_wins(self):
        self.assertEqual(
            self.ns["parse_status"]("discord_route=direct\ndiscord_route=zapret"),
            {"discord_route": "zapret"},
        )

    def test_private_client(self):
        cases = {
            "192.168.2.10": True,
            "10.0.0.1": True,
            "172.16.5.4": True,
            "127.0.0.1": True,
            "::1": True,
            "fd00::1": True,
            "8.8.8.8": False,
            "2001:4860:4860::8888": False,
            "not-an-ip": False,
            "": False,
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertIs(self.ns["private_client"](address), expected)

    def test_bounded_text(self):
        bounded = self.ns["bounded_text"]
        self.assertEqual(bounded("abc", "f", 3), "abc")
        self.assertEqual(bounded("", "f", 3), "")
        with self.assertRaisesRegex(ValueError, "некорректное поле f"):
            bounded("abcd", "f", 3)
        for value in (None, 5, b"abc", ["a"]):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "некорректное поле f"):
                    bounded(value, "f", 10)
        for value in ("a\nb", "a\rb"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "некорректное поле f"):
                    bounded(value, "f", 10)
        with self.assertRaisesRegex(ValueError, "пустое поле f"):
            bounded("", "f", 10, allow_empty=False)

    def test_voice_ports_allowed(self):
        allowed = self.ns["voice_ports_allowed"]
        for value in (
            "443",
            "3478",
            "3478-3481",
            "3479-3480",
            "5349",
            "19294-19344",
            "19300",
            "50000-65535",
            "60000",
            "443,3478-3481,50000-65535",
        ):
            with self.subTest(value=value):
                self.assertTrue(allowed(value))
        for value in (
            "",
            "80",
            "443-444",
            "3477-3481",
            "3478-3482",
            "5350",
            "19293-19344",
            "49999-65535",
            "50000-65536",
            "3481-3478",
            "abc",
            "1-2-3",
            "443,80",
            "443,",
            " 443",
        ):
            with self.subTest(value=value):
                self.assertFalse(allowed(value))
        # The narrow range ends at 50100, as the engine's VOICE_HIGH.
        self.assertTrue(allowed("19294-19344,50000-50100", 50100))
        self.assertFalse(allowed("50000-50101", 50100))
        self.assertFalse(allowed("60000", 50100))

    def test_route_stage_empty_output_is_preflight(self):
        for operation in ("switch", "rollback"):
            with self.subTest(operation=operation):
                self.assertEqual(
                    self.ns["route_stage"]("", operation),
                    ("preflight", "Проверка конфигурации", 10),
                )

    def test_route_stage_switch_sequence(self):
        stage = self.ns["route_stage"]
        output = "Snapshot created: /x\n"
        self.assertEqual(stage(output, "switch")[0], "snapshot")
        output += "Patching Mihomo config\n"
        self.assertEqual(stage(output, "switch"), ("config", "Запись конфигурации", 45))
        output += "Restarting XKeen...\n"
        self.assertEqual(stage(output, "switch"), ("xray", "Перезапуск XKeen/Xray", 65))
        output += "Restarting nfqws2 only\n"
        self.assertEqual(stage(output, "switch"), ("nfqws", "Перезапуск nfqws2", 82))

    def test_route_stage_rollback_sequence(self):
        stage = self.ns["route_stage"]
        output = "Rescue snapshot of current state: /x\n"
        self.assertEqual(stage(output, "rollback"), ("snapshot", "Rescue snapshot", 30))
        output += "Restoring /opt/etc/xray\n"
        self.assertEqual(stage(output, "rollback"), ("restore", "Восстановление файлов", 58))
        output += "Restore complete: /x\n"
        self.assertEqual(
            stage(output, "rollback"),
            ("verify", "Проверка восстановленного состояния", 92),
        )

    def test_route_stage_ignores_markers_of_other_operation(self):
        stage = self.ns["route_stage"]
        self.assertEqual(
            stage("Restarting XKeen...\nStarted NFQWS2 service", "rollback")[0],
            "preflight",
        )
        self.assertEqual(stage("Restoring\nRestore complete: /x", "switch")[0], "preflight")
        # "Snapshot created:" is shared by both operations.
        self.assertEqual(stage("Snapshot created: /x", "rollback"), ("snapshot", "Создание snapshot", 25))

    def test_validate_route(self):
        validate = self.ns["validate_route"]
        for service in ("discord-tcp", "discord-voice", "discord", "youtube"):
            for mode in ("direct", "zapret", "vpn"):
                self.assertEqual(validate(service, mode), (service, mode))
        for mode in ("direct", "vpn", "ws", "unmanaged"):
            self.assertEqual(validate("telegram", mode), ("telegram", mode))
        # Telegram is blocked by IP; the Zapret mode was removed.
        with self.assertRaisesRegex(ValueError, "Zapret для Telegram удалён"):
            validate("telegram", "zapret")
        with self.assertRaisesRegex(ValueError, "неподдерживаемый сервис"):
            validate("discord-video", "direct")
        with self.assertRaisesRegex(ValueError, "неподдерживаемый маршрут"):
            validate("youtube", "vless")
        for service in ("discord-tcp", "discord-voice", "discord", "youtube"):
            with self.subTest(service=service):
                with self.assertRaisesRegex(ValueError, "неподдерживаемый маршрут"):
                    validate(service, "unmanaged")

    def test_history_path(self):
        self.patch(ROUTE_HISTORY_DIR=self.root / "history")
        job_id = "0123456789abcdef"
        self.assertEqual(self.ns["history_path"](job_id), self.root / "history" / f"{job_id}.json")
        for bad in (
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdef0",
            "../../etc/passwd",
            "0123456789abcdeg",
            "",
            None,
            123,
        ):
            with self.subTest(job_id=bad):
                with self.assertRaisesRegex(ValueError, "некорректный ID операции"):
                    self.ns["history_path"](bad)

    def test_utc_now_format(self):
        self.assertRegex(self.ns["utc_now"](), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class FileHelperTests(PanelUnitCase):
    def test_safe_json_file(self):
        safe = self.ns["safe_json_file"]
        good = self.root / "good.json"
        good.write_text('{"a": 1}', encoding="utf-8")
        self.assertEqual(safe(good), {"a": 1})

        link = self.root / "link.json"
        link.symlink_to(good)
        with self.assertRaisesRegex(ValueError, "необычный тип файла"):
            safe(link)
        with self.assertRaisesRegex(ValueError, "необычный тип файла"):
            safe(self.root)

        empty = self.root / "empty.json"
        empty.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "некорректный размер файла"):
            safe(empty)
        with self.assertRaisesRegex(ValueError, "некорректный размер файла"):
            safe(good, maximum=3)
        self.assertEqual(safe(good, maximum=good.stat().st_size), {"a": 1})

        listing = self.root / "list.json"
        listing.write_text("[1, 2]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ожидается JSON-объект"):
            safe(listing)

        broken = self.root / "broken.json"
        broken.write_text("{nope", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            safe(broken)
        with self.assertRaises(FileNotFoundError):
            safe(self.root / "missing.json")

    def test_atomic_text_creates_and_replaces(self):
        target = self.root / "nested" / "dir" / "state.json"
        self.ns["atomic_text"](target, "first\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "first\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.ns["atomic_text"](target, "second\n", mode=0o644)
        self.assertEqual(target.read_text(encoding="utf-8"), "second\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)
        self.assertEqual(sorted(path.name for path in target.parent.iterdir()), ["state.json"])

    def test_atomic_text_replaces_symlink_instead_of_following_it(self):
        outside = self.root / "outside.txt"
        outside.write_text("keep\n", encoding="utf-8")
        target = self.root / "target.txt"
        target.symlink_to(outside)
        self.ns["atomic_text"](target, "new\n")
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")

    def test_current_routes_fast(self):
        config = self.root / "nfqws2.conf"
        self.patch(NFQWS_CONFIG=config)
        unknown = {
            "discord-tcp": "unknown",
            "discord-voice": "unknown",
            "youtube": "unknown",
            "telegram": "unknown",
        }
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("# nothing here\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("# Active routes: Discord=vpn, YouTube=zapret.\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text(
            "NFQWS_ARGS=x\n# Active routes: Discord=zapret, YouTube=vless.\nother\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.ns["current_routes_fast"](),
            {"discord-tcp": "zapret", "discord-voice": "zapret", "youtube": "vless", "telegram": "unmanaged"},
        )
        config.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless.\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.ns["current_routes_fast"](),
            {"discord-tcp": "direct", "discord-voice": "zapret", "youtube": "vless", "telegram": "unmanaged"},
        )
        config.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=zapret.\n",
            encoding="utf-8",
        )
        # Zapret is no longer selectable for Telegram, but an old header still reads.
        self.assertEqual(self.ns["current_routes_fast"]()["telegram"], "zapret")
        # Only Telegram may be unmanaged.
        config.write_text(
            "# Active routes: DiscordTCP=unmanaged, DiscordVoice=zapret, YouTube=vless, Telegram=direct.\n",
            encoding="utf-8",
        )
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text(
            "# Active routes: DiscordTCP=direct, DiscordVoice=zapret, YouTube=vless, Telegram=proxy.\n",
            encoding="utf-8",
        )
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("# Active routes: DiscordTCP=direct, YouTube=vless.\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)
        config.write_text("  # Active routes: Discord=direct, YouTube=direct.\n", encoding="utf-8")
        self.assertEqual(self.ns["current_routes_fast"](), unknown)

    def test_route_pid_parsing(self):
        pid_file = self.root / "worker.pid"
        self.patch(ROUTE_PID=pid_file)
        self.assertIsNone(self.ns["route_pid"]())
        for raw, expected in (("123\n", 123), ("  456  ", 456), ("1", None), ("0", None), ("-5", None), ("abc", None), ("", None)):
            with self.subTest(raw=raw):
                pid_file.write_text(raw, encoding="ascii")
                self.assertEqual(self.ns["route_pid"](), expected)

    def test_process_alive(self):
        self.assertTrue(self.ns["process_alive"](os.getpid()))
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        self.assertFalse(self.ns["process_alive"](child.pid))

    def test_route_process_alive_requires_route_job_cmdline(self):
        self.patch(ENTRY=self.root / "app.py")
        self.assertFalse(self.ns["route_process_alive"](os.getpid()))
        self.assertFalse(self.ns["tuner_process_alive"](os.getpid()))
        self.assertFalse(self.ns["diagnostic_process_alive"](os.getpid()))


if __name__ == "__main__":
    unittest.main()
