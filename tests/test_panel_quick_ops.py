"""Quick metadata operations share admission with job starts, never the project lock."""
import contextlib
from types import SimpleNamespace
from unittest import mock

import panel_harness


class QuickTests(panel_harness.PanelTestCase):
    def setUp(self):
        self.fresh_root()
        self.jobfiles = self.ns.module("jobfiles")
        self.history = self.ns.module("history")
        self.profiles = self.ns.module("profiles")
        self.vpn = self.ns.module("vpn")

    def operations(self):
        return [(lambda: self.history.delete_history_record("a" * 16), "нельзя удалять историю во время выполняющегося задания"),
                (lambda: self.profiles.delete_profile_version("youtube", "v1"), "нельзя удалять версии во время выполняющегося задания"),
                (lambda: self.vpn.remove_node("node1"), "переключение маршрута уже выполняется"),
                (self.vpn.sync_current, "переключение маршрута уже выполняется")]

    def test_refusal_texts_for_all_families_and_starting(self):
        for family in ("route", "tuner", "diagnostic"):
            for operation, text in self.operations():
                if text.startswith("переключение"):
                    text = {"route": text, "tuner": "маршруты нельзя менять во время подбора",
                            "diagnostic": "маршруты нельзя менять во время диагностики"}[family]
                with self.subTest(family=family, operation=operation), self.patched(**{family + "_active": lambda: True}):
                    with self.assertRaisesRegex(RuntimeError, text):
                        operation()
        with self.jobfiles.JOB_START_LOCK:
            for operation, _text in self.operations():
                with self.assertRaisesRegex(RuntimeError, "другое задание уже запускается"):
                    operation()

    def test_idle_operations_preserve_results_without_asking_project_lock(self):
        expected = {"ok": True, "test": "manager"}
        manager = SimpleNamespace(remove=lambda node: expected, sync_current=lambda: expected)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.jobfiles.COORDINATOR, "_project_lock",
                                                  side_effect=AssertionError("project lock asked")))
            stack.enter_context(mock.patch.object(self.vpn, "vpn_manager", return_value=manager))
            for operation in (lambda: self.vpn.remove_node("node1"), self.vpn.sync_current):
                self.assertEqual(operation(), expected)
            path = self.history.history_path("a" * 16)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"job_id":"' + "a" * 16 + '"}')
            with mock.patch.object(self.history, "archive_record") as archive:
                self.assertEqual(self.history.delete_history_record("a" * 16), {"ok": True, "snapshot_preserved": True})
                archive.assert_called_once_with(path, "history")
            with mock.patch.object(self.profiles, "profile_version_path", return_value=(path, {"candidate_id": "A"})), \
                    mock.patch.object(self.profiles, "imported_profiles", return_value=[]), \
                    mock.patch.object(self.history, "archive_record") as archive:
                self.assertEqual(self.profiles.delete_profile_version("youtube", "v1"), {"ok": True, "archived": True})
                archive.assert_called_once_with(path, "versions", "youtube")
