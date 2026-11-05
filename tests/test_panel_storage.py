"""Tests of the data the panel keeps on disk: malformed stored files and the profile store."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from panel_fixtures import DIAGNOSTICS_MODULE, PanelUnitCase, make_report


class MalformedStoredDataTests(PanelUnitCase):
    """Valid-JSON but wrongly shaped files must not crash the panel."""

    def test_imported_profile_that_is_not_an_object(self):
        imported = self.root / "imported"
        imported.mkdir()
        (imported / "youtube.json").write_text("[]", encoding="utf-8")
        (imported / "discord-tcp.json").write_text('{"format": 1, "report": []}', encoding="utf-8")
        self.patch(IMPORTED_PROFILE_DIR=imported)
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        self.assertFalse(items["youtube"]["installed"])
        self.assertIn("error", items["youtube"])
        self.assertFalse(items["discord-tcp"]["installed"])
        self.assertIn("error", items["discord-tcp"])

    def test_report_metadata_must_be_an_object(self):
        report = make_report("youtube")
        report["found"]["candidate_id"] = report["found"]["candidate_id"]
        with self.assertRaisesRegex(ValueError, "report"):
            self.ns["validate_candidate"](report["found"], [])

    def test_route_history_with_non_string_dates(self):
        history = self.root / "history"
        history.mkdir()
        for job_id, created in (("aaaaaaaaaaaaaaaa", 5), ("bbbbbbbbbbbbbbbb", "2026-01-01T00:00:00Z"), ("cccccccccccccccc", None)):
            (history / f"{job_id}.json").write_text(
                json.dumps({"job_id": job_id, "created_utc": created}), encoding="utf-8"
            )
        self.patch(ROUTE_HISTORY_DIR=history, SNAPSHOT_DIR=self.root / "snapshots")
        items = self.ns["route_history"]()
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["job_id"], "bbbbbbbbbbbbbbbb")

    def test_config_health_with_wrongly_shaped_routing(self):
        self.patch(
            NFQWS_CONFIG=self.root / "nfqws2.conf",
            XRAY_CONFIG_DIR=self.root,
            DISCORD_LIST=self.root / "user.list",
            DIAGNOSTICS=DIAGNOSTICS_MODULE,
        )
        for routing in ({"routing": []}, {"routing": {"rules": "x"}}):
            with self.subTest(routing=routing):
                (self.root / "05_routing.json").write_text(json.dumps(routing), encoding="utf-8")
                with self.patched(run_command=lambda *_a, **_k: {"ok": True, "code": 0, "output": "1"}):
                    health = self.ns["config_health"]()
                self.assertFalse(health["all_ok"])

    def test_flowseal_update_with_wrongly_shaped_commit(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"sha": "a" * 40, "commit": []}
        ).encode("utf-8")
        module = mock.Mock()
        module.read_source_cache.return_value = ([], "a" * 40)
        self.patch(
            FLOWSEAL_SOURCE_CACHE=self.root / "flowseal-sources.json",
            FLOWSEAL_UPDATE_STATE=self.root / "flowseal-update.json",
            flowseal_source_module=lambda: module,
        )
        with mock.patch.object(self.ns["urllib"].request, "urlopen", return_value=response):
            payload = self.ns["check_flowseal_update"]()
        self.assertEqual(payload["status"], "up_to_date")
        self.assertEqual(payload["latest_date"], "")


class ProfileStoreTests(PanelUnitCase):
    def setUp(self):
        super().setUp()
        self.imported = self.root / "imported"
        self.versions = self.root / "versions"
        self.patch(IMPORTED_PROFILE_DIR=self.imported, PROFILE_VERSION_DIR=self.versions)

    def install(self, service, data, name=None):
        self.imported.mkdir(exist_ok=True)
        path = self.imported / f"{name or service}.json"
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def add_version(self, service, profile, stamp="20260815T020304Z", reason="applied", candidate_id=None, suffix=""):
        directory = self.versions / service
        directory.mkdir(parents=True, exist_ok=True)
        version_id = f"{stamp}-{candidate_id or profile['candidate_id']}-{reason}-123{suffix}"
        (directory / f"{version_id}.json").write_text(json.dumps(profile), encoding="utf-8")
        return version_id

    def test_imported_profiles_empty(self):
        self.assertEqual(
            self.ns["imported_profiles"](),
            [
                {"service": "youtube", "installed": False},
                {"service": "discord-tcp", "installed": False},
                {"service": "discord-voice", "installed": False},
            ],
        )

    def test_imported_profiles_installed_and_errors(self):
        tcp = self.profile("discord-tcp")
        self.install("discord-tcp", tcp)
        self.install("youtube", tcp)
        voice = self.profile("discord-voice")
        voice["format"] = 2
        self.install("discord-voice", voice)
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        installed = items["discord-tcp"]
        self.assertTrue(installed["installed"])
        self.assertEqual(installed["candidate_id"], tcp["candidate_id"])
        self.assertEqual(installed["family"], "fixture-family")
        self.assertEqual(installed["source_name"], "general (ALT).bat")
        self.assertEqual(installed["commit"], "abc1234")
        self.assertEqual(installed["created_utc"], "2026-08-15T00:00:00Z")
        self.assertRegex(installed["installed_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertNotIn("error", installed)
        for service in ("youtube", "discord-voice"):
            self.assertFalse(items[service]["installed"])
            self.assertEqual(items[service]["error"], "Некорректный профиль: неверный сервис")

    def test_imported_profiles_unusual_files(self):
        tcp = self.profile("discord-tcp")
        real = self.install("real", tcp)
        self.imported.joinpath("discord-tcp.json").symlink_to(real)
        self.install("youtube", "{broken")
        self.imported.joinpath("discord-voice.json").mkdir()
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        self.assertIn("необычный тип файла", items["discord-tcp"]["error"])
        self.assertIn("необычный тип файла", items["discord-voice"]["error"])
        self.assertTrue(items["youtube"]["error"].startswith("Некорректный профиль:"))
        self.assertFalse(any(item["installed"] for item in items.values()))

    def test_imported_profiles_too_large(self):
        self.patch(MAX_REPORT_BYTES=10)
        self.install("youtube", self.profile("youtube"))
        items = {item["service"]: item for item in self.ns["imported_profiles"]()}
        self.assertEqual(items["youtube"]["error"], "Некорректный профиль: файл слишком велик")

    def test_profile_versions_without_directory(self):
        self.assertEqual(self.ns["profile_versions"](), [])

    def test_profile_versions_sorting_and_active(self):
        tcp = self.profile("discord-tcp")
        youtube = self.profile("youtube")
        self.install("discord-tcp", tcp)
        old = self.add_version("discord-tcp", tcp, stamp="20260101T000000Z", reason="replaced")
        new = self.add_version("youtube", youtube, stamp="20260901T120000Z", reason="cleared", suffix="-2")
        versions = self.ns["profile_versions"]()
        self.assertEqual([item["id"] for item in versions], [new, old])
        self.assertEqual(versions[0]["service"], "youtube")
        self.assertEqual(versions[0]["reason"], "cleared")
        self.assertEqual(versions[0]["created_utc"], "2026-09-01T12:00:00Z")
        self.assertFalse(versions[0]["active"])
        self.assertEqual(versions[1]["reason"], "replaced")
        self.assertTrue(versions[1]["active"])
        self.assertEqual(versions[1]["commit"], "abc1234")

    def test_profile_versions_skip_invalid_entries(self):
        tcp = self.profile("discord-tcp")
        directory = self.versions / "discord-tcp"
        directory.mkdir(parents=True)
        (directory / "not-a-version.json").write_text(json.dumps(tcp), encoding="utf-8")
        (directory / f"20260815T020304Z-{tcp['candidate_id']}-deleted-1.json").write_text(json.dumps(tcp), encoding="utf-8")
        self.add_version("discord-tcp", tcp, candidate_id="0" * 12)
        self.add_version("youtube", tcp)
        (directory / f"20260815T020304Z-{'a' * 12}-applied-9.json").write_text("{broken", encoding="utf-8")
        (directory / f"20260815T020304Z-{'b' * 12}-applied-9.json").write_text("[]", encoding="utf-8")
        tampered = dict(tcp, family="tampered")
        self.add_version("discord-tcp", tampered, stamp="20260816T000000Z")
        self.assertEqual(self.ns["profile_versions"](), [])

    def test_profile_version_path_validation(self):
        tcp = self.profile("discord-tcp")
        version_id = self.add_version("discord-tcp", tcp)
        path, profile = self.ns["profile_version_path"]("discord-tcp", version_id)
        self.assertEqual(path, self.versions / "discord-tcp" / f"{version_id}.json")
        self.assertEqual(profile["candidate_id"], tcp["candidate_id"])
        with self.assertRaisesRegex(ValueError, "неподдерживаемый сервис"):
            self.ns["profile_version_path"]("discord", version_id)
        for bad in ("../x", version_id + ".json", "20260815T020304Z-abc-applied-1", ""):
            with self.subTest(version_id=bad):
                with self.assertRaisesRegex(ValueError, "некорректный ID версии"):
                    self.ns["profile_version_path"]("discord-tcp", bad)
        with self.assertRaises(FileNotFoundError):
            self.ns["profile_version_path"]("youtube", version_id)
        link_id = f"20260815T020304Z-{tcp['candidate_id']}-applied-777"
        (self.versions / "discord-tcp" / f"{link_id}.json").symlink_to(path)
        with self.assertRaisesRegex(ValueError, "необычный файл версии"):
            self.ns["profile_version_path"]("discord-tcp", link_id)
        wrong_id = self.add_version("youtube", tcp)
        with self.assertRaisesRegex(ValueError, "сервис версии не совпадает"):
            self.ns["profile_version_path"]("youtube", wrong_id)


if __name__ == "__main__":
    unittest.main()
