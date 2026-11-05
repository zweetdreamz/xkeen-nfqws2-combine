"""Tests of kdn.web.infra.jobfiles (families, stores and the coordinator of the panel's jobs) and refusals.

The modules are taken on their own (``modules``), without the panel entry. Every path lies under the test root;
the processes of the integration tests are short sleeper scripts that the families recognise through the
configuration (ENTRY, AUTOTUNER, DIAGNOSTICS), nothing touches /opt.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import unittest
from unittest import mock

import panel_harness


# The refusal texts of phase 2, written out from the code that was replaced, as (route, tuner, diagnostic).
OLD_MESSAGES = {
    "ROUTE_CHANGE": (
        "переключение маршрута уже выполняется",
        "маршруты нельзя менять во время подбора",
        "маршруты нельзя менять во время диагностики",
    ),
    "TUNER_START": (
        "сначала завершите переключение маршрута",
        "подбор уже выполняется",
        "сначала завершите диагностику",
    ),
    "DIAGNOSTIC_START": (
        "сначала завершите переключение маршрута",
        "сначала завершите автоподбор",
        "диагностика уже выполняется",
    ),
    "TUNER_APPLY": (
        "сначала завершите переключение маршрута",
        "сначала завершите подбор",
        "сначала завершите диагностику",
    ),
    "XKEEN_ACTION": (
        "XKeen нельзя менять во время переключения маршрута",
        "XKeen нельзя менять во время подбора",
        "XKeen нельзя менять во время диагностики",
    ),
    "PROFILE_APPLY": (
        "профиль нельзя применять во время переключения маршрута",
        "профиль нельзя применять во время подбора",
        "профиль нельзя применять во время диагностики",
    ),
    "VERSION_APPLY": (
        "версию нельзя применять во время переключения маршрута",
        "версию нельзя применять во время подбора",
        "версию нельзя применять во время диагностики",
    ),
    "PROFILE_CLEAR": (
        "профиль нельзя удалять во время переключения маршрута",
        "профиль нельзя удалять во время подбора",
        "профиль нельзя удалять во время диагностики",
    ),
    "IMPORT_ROLLBACK": (
        "откат нельзя выполнять во время переключения маршрута",
        "откат нельзя выполнять во время подбора",
        "откат нельзя выполнять во время диагностики",
    ),
    "HISTORY_DELETE": ("нельзя удалять историю во время выполняющегося задания",) * 3,
    "VERSION_DELETE": ("нельзя удалять версии во время выполняющегося задания",) * 3,
    "VPN_STORE": (
        "переключение маршрута уже выполняется",
        "маршруты нельзя менять во время подбора",
        "маршруты нельзя менять во время диагностики",
    ),
}
# The operations that do not ask the project lock: xkeen start/stop never took it, a stale lock must not stop a
# restart of XKeen; the others do not touch the router (the diagnostics tool checks the lock itself).
NO_PROJECT_LOCK = frozenset({"XKEEN_ACTION", "DIAGNOSTIC_START", "HISTORY_DELETE", "VERSION_DELETE", "VPN_STORE"})
FAMILIES = ("route", "tuner", "diagnostic")
SLEEPER = "import time\ntime.sleep(120)\n"
WAIT = 10


def kill_group(pid):
    with contextlib.suppress(OSError):
        os.killpg(pid, signal.SIGKILL)


class JobfilesTestCase(panel_harness.PanelTestCase):
    modules = ("kdn.web.infra.jobfiles", "kdn.web.domain.refusals")

    def setUp(self):
        self.root = self.fresh_root()
        self.cfg = self.ns.module("kdn.web.infra.config")
        self.store = {name: self.ns[f"{name.upper()}_STORE"] for name in FAMILIES}
        self.family = {name: self.ns[name.upper()] for name in FAMILIES}

    def live_process(self):
        process = subprocess.Popen(["sleep", "60"])
        self.addCleanup(self.reap, process)
        return process

    @staticmethod
    def reap(process):
        process.kill()
        process.wait()

    @staticmethod
    def dead_pid():
        finished = subprocess.Popen(["true"])
        finished.wait()
        return finished.pid

    def make_project_lock(self, pid):
        directory = self.cfg.PROJECT_LOCK_DIR
        directory.mkdir(parents=True, mode=0o700)
        (directory / "pid").write_text(f"{pid}\n", encoding="ascii")

    def job_command(self, command, pid=4242):
        return mock.patch.object(
            self.ns.module("kdn.common.proc"), "job_command", lambda number: command if number == pid else None
        )


class FamilyTests(JobfilesTestCase):
    def test_families_follow_the_configuration_paths(self):
        elsewhere = self.root / "elsewhere"
        entry, autotuner, diagnostics = (elsewhere / name for name in ("app.py", "autotune.py", "diagnostics.py"))
        self.patch(
            ROUTE_JOB_DIR=elsewhere / "route", ROUTE_STATE=elsewhere / "route" / "own-state.json",
            ROUTE_PID=elsewhere / "route" / "own.pid", ROUTE_LOG=elsewhere / "route" / "own.log",
            ROUTE_APPLY_LOG=elsewhere / "route" / "own-apply.log",
            TUNER_JOB_DIR=elsewhere / "tuner", TUNER_STATE=elsewhere / "tuner" / "own-state.json",
            TUNER_PID=elsewhere / "tuner" / "own.pid",
            DIAGNOSTIC_JOB_DIR=elsewhere / "diagnostics", DIAGNOSTIC_STATE=elsewhere / "diagnostics" / "own-state.json",
            DIAGNOSTIC_PID=elsewhere / "diagnostics" / "own.pid", DIAGNOSTIC_LOG=elsewhere / "diagnostics" / "own.log",
            ENTRY=entry, AUTOTUNER=autotuner, DIAGNOSTICS=diagnostics,
        )
        route, tuner, diagnostic = (self.family[name] for name in FAMILIES)
        route_dir, tuner_dir, diagnostic_dir = elsewhere / "route", elsewhere / "tuner", elsewhere / "diagnostics"
        with self.subTest(family="route"):
            self.assertEqual(route.name, "route")
            self.assertEqual(route.directory(), route_dir)
            self.assertEqual(route.state(), route_dir / "own-state.json")
            self.assertEqual(route.pid(), route_dir / "own.pid")
            self.assertEqual(route.log(), route_dir / "own.log")
            self.assertCountEqual(route.files(), [
                route_dir / "own-state.json", route_dir / "own.pid", route_dir / "own.log",
                route_dir / "own-apply.log", route_dir / "payload.json",
            ])
            self.assertEqual(route.marker(), (b"--route-job", os.fsencode(str(entry))))
            self.assertEqual(self.ns["route_payload_path"](), route_dir / "payload.json")
        with self.subTest(family="tuner"):
            self.assertEqual(tuner.name, "tuner")
            self.assertEqual(tuner.directory(), tuner_dir)
            self.assertEqual(tuner.state(), tuner_dir / "own-state.json")
            self.assertEqual(tuner.pid(), tuner_dir / "own.pid")
            self.assertEqual(tuner.log(), tuner_dir / "process.log")
            self.assertCountEqual(tuner.files(), [tuner_dir / name for name in (
                "state.json", "events.log", "result-report.json", "runner.sh", "verdict.txt", "panel-launch.pid",
                "process.log",
            )])
            self.assertEqual(tuner.marker(), (os.fsencode(str(autotuner)),))
        with self.subTest(family="diagnostic"):
            self.assertEqual(diagnostic.name, "diagnostic")
            self.assertEqual(diagnostic.directory(), diagnostic_dir)
            self.assertEqual(diagnostic.state(), diagnostic_dir / "own-state.json")
            self.assertEqual(diagnostic.pid(), diagnostic_dir / "own.pid")
            self.assertEqual(diagnostic.log(), diagnostic_dir / "own.log")
            self.assertCountEqual(
                diagnostic.files(), [diagnostic_dir / "own-state.json", diagnostic_dir / "own.pid",
                                     diagnostic_dir / "own.log"],
            )
            self.assertEqual(diagnostic.marker(), (os.fsencode(str(diagnostics)),))
            self.assertEqual(diagnostic.place, "каталоге диагностики")

    def test_the_default_paths_are_the_ones_of_the_router(self):
        cfg = self.cfg
        self.assertEqual(self.ns["PAYLOAD_NAME"], "payload.json")
        self.assertEqual(self.ns["route_payload_path"](), cfg.ROUTE_JOB_DIR / "payload.json")
        self.assertEqual(cfg.ROUTE_JOB_DIR.name, "xkeen-route-switch")
        self.assertEqual(self.family["route"].pid(), cfg.ROUTE_JOB_DIR / "worker.pid")
        self.assertEqual(self.family["tuner"].pid(), cfg.TUNER_JOB_DIR / "panel-launch.pid")
        self.assertEqual(self.family["diagnostic"].pid(), cfg.DIAGNOSTIC_JOB_DIR / "panel-launch.pid")
        for name in FAMILIES:
            with self.subTest(family=name):
                self.assertIs(self.store[name].family, self.family[name])

    def test_tool_owned_flags(self):
        self.assertEqual(
            {name: self.family[name].tool_owned for name in FAMILIES},
            {"route": False, "tuner": True, "diagnostic": True},
        )

    def test_a_dead_job_the_panel_did_not_start_is_settled_only_for_the_route(self):
        # tool_owned in action: a tool run by hand over SSH leaves a state with no job.id, which the panel keeps.
        for name in FAMILIES:
            with self.subTest(family=name, started_by="a tool run by hand"):
                self.fresh_root()
                family = self.family[name]
                family.directory().mkdir(parents=True)
                family.state().write_text(json.dumps({"job_id": "j1", "status": "running"}), encoding="utf-8")
                settled = self.store[name].settle("j1", status="error")
                self.assertIs(settled, name == "route")
                self.assertEqual(
                    json.loads(family.state().read_text(encoding="utf-8"))["status"],
                    "error" if name == "route" else "running",
                )
            with self.subTest(family=name, started_by="the panel"):
                self.fresh_root()
                spec = self.ns["JobSpec"](
                    family=name, kind="x", job_id="j2", argv=["true"], initial={"job_id": "j2", "status": "queued"},
                )
                self.store[name].prepare(spec)
                self.assertIs(self.store[name].settle("j2", status="error"), True)
                self.assertEqual(json.loads(self.family[name].state().read_text(encoding="utf-8"))["status"], "error")


class ClearTests(JobfilesTestCase):
    def listing(self, directory):
        return sorted(path.name for path in directory.iterdir())

    def test_route_family_clears_the_payload(self):
        directory = self.cfg.ROUTE_JOB_DIR
        directory.mkdir(parents=True)
        for name in ("state.json", "worker.pid", "process.log", "apply.log", "payload.json", "job.id", "cancel.request",
                     "keep.txt"):
            (directory / name).write_text("x", encoding="utf-8")
        self.store["route"].clear()
        self.assertEqual(self.listing(directory), ["keep.txt"])
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_prepare_over_a_previous_route_job_leaves_only_the_new_one(self):
        directory = self.cfg.ROUTE_JOB_DIR
        directory.mkdir(parents=True)
        (directory / "payload.json").write_text('{"secret": 1}', encoding="utf-8")
        (directory / "apply.log").write_text("old", encoding="utf-8")
        spec = self.ns["JobSpec"](
            family="route", kind="switch", job_id="j9", argv=["true"], initial={"job_id": "j9", "status": "queued"},
        )
        self.store["route"].prepare(spec)
        self.assertEqual(self.listing(directory), ["job.id", "state.json"])
        self.assertEqual(json.loads((directory / "state.json").read_text(encoding="utf-8"))["job_id"], "j9")

    def test_tuner_family_clears_its_seven_files_the_job_id_and_the_cancel_marker(self):
        directory = self.cfg.TUNER_JOB_DIR
        directory.mkdir(parents=True)
        names = ("state.json", "events.log", "result-report.json", "runner.sh", "verdict.txt", "panel-launch.pid",
                 "process.log", "job.id", "cancel.request")
        for name in (*names, "other.txt"):
            (directory / name).write_text("x", encoding="utf-8")
        self.store["tuner"].clear()
        self.assertEqual(self.listing(directory), ["other.txt"])
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_diagnostic_family_clears_payload_bins_only_when_regular(self):
        directory = self.cfg.DIAGNOSTIC_JOB_DIR
        directory.mkdir(parents=True)
        outside = self.root / "outside.bin"
        outside.write_text("keep", encoding="utf-8")
        for name in ("state.json", "panel-launch.pid", "process.log", "job.id", "cancel.request", "payload-1.bin",
                     "payload-22.bin", "payload-x.bin", "payload-3.bin.bak", "xpayload-4.bin"):
            (directory / name).write_text("x", encoding="utf-8")
        (directory / "payload-5.bin").symlink_to(outside)
        (directory / "payload-6.bin").mkdir()
        self.store["diagnostic"].clear()
        self.assertEqual(
            self.listing(directory),
            ["payload-3.bin.bak", "payload-5.bin", "payload-6.bin", "payload-x.bin", "xpayload-4.bin"],
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep")
        self.assertTrue((directory / "payload-6.bin").is_dir())

    def test_an_unusual_object_in_the_job_directory_is_refused_with_the_place(self):
        places = {"route": "каталоге задания", "tuner": "каталоге задания", "diagnostic": "каталоге диагностики"}
        for name in FAMILIES:
            with self.subTest(family=name):
                self.fresh_root()
                family = self.family[name]
                family.directory().mkdir(parents=True)
                family.state().mkdir()
                with self.assertRaises(RuntimeError) as raised:
                    self.store[name].clear()
                self.assertEqual(str(raised.exception), f"необычный объект в {places[name]}: {family.state()}")

    def test_clear_job_files_keeps_its_contract(self):
        clear_job_files = self.ns["clear_job_files"]
        directory = self.root / "jobs"
        target = self.root / "target.txt"
        target.write_text("keep", encoding="utf-8")
        directory.mkdir()
        directory.chmod(0o755)
        regular, link, unusual = directory / "a.log", directory / "b.log", directory / "c.log"
        regular.write_text("x", encoding="utf-8")
        link.symlink_to(target)
        clear_job_files(directory, [regular, link, directory / "missing.log"])
        self.assertEqual(self.listing(directory), [])
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        unusual.mkdir()
        with self.assertRaisesRegex(RuntimeError, f"необычный объект в каталоге задания: {unusual}"):
            clear_job_files(directory, [unusual])
        with self.assertRaisesRegex(RuntimeError, f"необычный объект в тестовом каталоге: {unusual}"):
            clear_job_files(directory, [unusual], place="тестовом каталоге")
        clear_job_files(self.root / "new", [])
        self.assertEqual(stat.S_IMODE((self.root / "new").stat().st_mode), 0o700)


class LegacyHelperTests(JobfilesTestCase):
    PIDS = {"route": "ROUTE_PID", "tuner": "TUNER_PID", "diagnostic": "DIAGNOSTIC_PID"}

    def commands(self):
        entry, autotuner, diagnostics = (os.fsencode(str(getattr(self.cfg, name))) for name in (
            "ENTRY", "AUTOTUNER", "DIAGNOSTICS"))
        return {
            "route": ([b"python3", entry, b"--route-job", b"j1"], [
                [b"python3", entry],
                [b"python3", b"--route-job", b"j1"],
                [b"python3", entry + b".old", b"--route-job"],
                [b"python3", b"x" + entry, b"--route-job"],
            ]),
            "tuner": ([b"python3", autotuner, b"--service", b"youtube"], [
                [b"python3", b"--service"], [b"python3", autotuner + b".old"],
            ]),
            "diagnostic": ([b"python3", diagnostics, b"--kind", b"health"], [
                [b"python3", b"--kind"], [b"python3", diagnostics + b".old"],
            ]),
        }

    def test_legacy_helpers_delegate_to_the_stores(self):
        for name, (alive, strangers) in self.commands().items():
            pid_path = getattr(self.cfg, self.PIDS[name])
            pid_of, alive_of, active_of = (self.ns[f"{name}_{what}"] for what in ("pid", "process_alive", "active"))
            with self.subTest(family=name, case="no pid file"):
                self.assertIsNone(pid_of())
                self.assertIs(active_of(), False)
            pid_path.parent.mkdir(parents=True, exist_ok=True)
            with self.subTest(family=name, case="garbage pid file"):
                pid_path.write_text("not a pid\n", encoding="utf-8")
                self.assertIsNone(pid_of())
                self.assertIs(active_of(), False)
            pid_path.write_text("4242\n", encoding="utf-8")
            with self.subTest(family=name, case="the family's own process"), self.job_command(alive):
                self.assertEqual(pid_of(), 4242)
                self.assertIs(alive_of(4242), True)
                self.assertIs(active_of(), True)
            for stranger in strangers:
                with self.subTest(family=name, case="another process", command=stranger), self.job_command(stranger):
                    self.assertEqual(pid_of(), 4242)
                    self.assertIs(alive_of(4242), False)
                    self.assertIs(active_of(), False)
            with self.subTest(family=name, case="no such process"), self.job_command(None):
                self.assertIs(alive_of(4242), False)
                self.assertIs(active_of(), False)
            with self.subTest(family=name, case="the store answers"):
                store = self.store[name]
                with mock.patch.object(store, "pid", return_value=7), \
                        mock.patch.object(store, "alive", side_effect=lambda pid: pid == 7):
                    self.assertEqual(pid_of(), 7)
                    self.assertIs(alive_of(7), True)
                    self.assertIs(alive_of(8), False)
                    self.assertIs(active_of(), True)

    def test_the_active_helpers_look_up_the_pid_helpers_on_every_call(self):
        # The tests of the panel patch tuner_pid and tuner_process_alive (not the store) and expect tuner_active
        # and the cancel to follow.
        for name in FAMILIES:
            with self.subTest(family=name):
                self.assertIs(self.ns[f"{name}_active"](), False)
                with self.patched(**{f"{name}_pid": lambda: 7, f"{name}_process_alive": lambda pid: pid == 7}):
                    self.assertIs(self.ns[f"{name}_active"](), True)
                with self.patched(**{f"{name}_pid": lambda: 7, f"{name}_process_alive": lambda _pid: False}):
                    self.assertIs(self.ns[f"{name}_active"](), False)
                with self.patched(**{f"{name}_pid": lambda: None, f"{name}_process_alive": lambda _pid: True}):
                    self.assertIs(self.ns[f"{name}_active"](), False)

    def test_route_marker_matches_only_the_entry_of_this_generation(self):
        # A worker started with the entry of another installation is not this panel's worker.
        entry = os.fsencode(str(self.cfg.ENTRY))
        other = os.fsencode(str(self.root / "other" / "app.py"))
        self.assertNotEqual(entry, other)
        cases = (
            ([b"python3", entry, b"--route-job", b"j", b"switch"], True),
            ([b"python3", other, b"--route-job", b"j", b"switch"], False),
            ([b"python3", entry, b"j", b"switch"], False),
        )
        for command, expected in cases:
            with self.subTest(command=command), self.job_command(command, pid=11):
                self.assertIs(self.ns["route_process_alive"](11), expected)
                self.assertIs(self.store["route"].alive(11), expected)


class CoordinatorTests(JobfilesTestCase):
    def setUp(self):
        super().setUp()
        self.coordinator = self.ns["COORDINATOR"]
        self.busy = self.ns["Busy"]
        self.lock = self.ns["JOB_START_LOCK"]
        self.assertFalse(self.lock.locked())

    def test_coordinator_probes_follow_patched_helpers(self):
        refusals = self.ns["ROUTE_CHANGE"]
        for family in FAMILIES:
            with self.subTest(family=family), self.patched(**{f"{family}_active": lambda: True}):
                with self.assertRaises(self.busy) as raised:
                    self.coordinator.ensure_idle(refusals)
                self.assertEqual(str(raised.exception), getattr(refusals, family))
                self.assertEqual(self.coordinator.active(), family)
        with self.subTest(family=None):
            self.coordinator.ensure_idle(refusals)
            self.assertIsNone(self.coordinator.active())

    def test_the_start_lock_of_the_coordinator_is_job_start_lock(self):
        refusals = self.ns["ROUTE_CHANGE"]
        with self.coordinator.exclusive(refusals, family="route"):
            self.assertTrue(self.lock.locked())
            self.assertTrue(self.coordinator.start_in_progress())
            self.assertEqual(self.coordinator.starting(), "route")
            with self.assertRaises(RuntimeError) as raised, self.coordinator.exclusive(refusals):
                pass
            self.assertEqual(str(raised.exception), self.ns["STARTING"])
        self.assertFalse(self.lock.locked())
        self.assertFalse(self.coordinator.start_in_progress())
        self.lock.acquire()
        self.addCleanup(self.lock.release)
        self.assertTrue(self.coordinator.start_in_progress())
        with self.assertRaises(self.busy) as raised, self.coordinator.exclusive(refusals):
            pass
        self.assertEqual(str(raised.exception), "другое задание уже запускается; повторите через несколько секунд")

    def test_job_start_guard_is_non_blocking_and_shares_the_lock(self):
        guard = lambda: self.coordinator.exclusive(self.ns["ROUTE_CHANGE"])
        with guard():
            self.assertTrue(self.lock.locked())
            with self.assertRaises(self.busy) as raised, self.coordinator.exclusive(self.ns["ROUTE_CHANGE"]):
                pass
            self.assertEqual(str(raised.exception), self.ns["STARTING"])
        self.assertFalse(self.lock.locked())
        with self.assertRaisesRegex(ZeroDivisionError, "division"), guard():
            self.assertTrue(self.lock.locked())
            1 / 0  # noqa: B018
        self.assertFalse(self.lock.locked(), "the guard releases the lock when its body fails")

    def test_the_coordinator_asks_the_project_lock_of_the_configuration(self):
        refusals = self.ns["ROUTE_CHANGE"]
        elsewhere = self.root / "elsewhere.lock"
        elsewhere.mkdir(mode=0o700)
        process = self.live_process()
        (elsewhere / "pid").write_text(f"{process.pid}\n", encoding="ascii")
        self.coordinator.ensure_idle(refusals)
        self.patch(PROJECT_LOCK_DIR=elsewhere)
        with self.assertRaises(self.busy) as raised:
            self.coordinator.ensure_idle(refusals)
        self.assertEqual(str(raised.exception), f"проект занят другой операцией (PID {process.pid}); повторите позже")

    def test_project_lock_of_another_process_refuses_a_router_operation_but_not_xkeen_or_a_quick_one(self):
        process = self.live_process()
        self.make_project_lock(process.pid)
        for name in OLD_MESSAGES:
            preset = self.ns[name]
            with self.subTest(preset=name, lock="held by a live process"):
                if name in NO_PROJECT_LOCK:
                    self.coordinator.ensure_idle(preset)
                    with self.coordinator.exclusive(preset):
                        pass
                else:
                    with self.assertRaises(self.busy) as raised:
                        self.coordinator.ensure_idle(preset)
                    self.assertEqual(
                        str(raised.exception), f"проект занят другой операцией (PID {process.pid}); повторите позже",
                    )
                    with self.assertRaises(self.busy), self.coordinator.exclusive(preset):
                        pass
                    self.assertFalse(self.lock.locked())

    def test_a_stale_project_lock_refuses_nothing(self):
        self.make_project_lock(self.dead_pid())
        for name in OLD_MESSAGES:
            with self.subTest(preset=name):
                self.coordinator.ensure_idle(self.ns[name])

    def test_a_running_family_refuses_with_its_own_text_before_the_project_lock(self):
        process = self.live_process()
        self.make_project_lock(process.pid)
        with self.patched(tuner_active=lambda: True):
            for name, (_route, tuner, _diagnostic) in OLD_MESSAGES.items():
                with self.subTest(preset=name), self.assertRaises(self.busy) as raised:
                    self.coordinator.ensure_idle(self.ns[name])
                self.assertEqual(str(raised.exception), tuner)


class RefusalTests(JobfilesTestCase):
    def test_refusal_presets_keep_the_wording(self):
        starting = self.ns["STARTING"]
        project_busy = self.ns["PROJECT_BUSY"]
        for name, (route, tuner, diagnostic) in OLD_MESSAGES.items():
            with self.subTest(preset=name):
                preset = self.ns[name]
                self.assertIsInstance(preset, self.ns["Refusals"])
                # Byte for byte, not only equal as text.
                self.assertEqual(preset.route.encode("utf-8"), route.encode("utf-8"))
                self.assertEqual(preset.tuner.encode("utf-8"), tuner.encode("utf-8"))
                self.assertEqual(preset.diagnostic.encode("utf-8"), diagnostic.encode("utf-8"))
                self.assertEqual(preset.starting, starting)
                self.assertEqual(preset.project, None if name in NO_PROJECT_LOCK else project_busy)

    def test_the_table_lists_every_preset_of_the_module(self):
        refusals = self.ns.module("kdn.web.domain.refusals")
        presets = {name for name, value in vars(refusals).items() if isinstance(value, self.ns["Refusals"])}
        self.assertLessEqual(set(OLD_MESSAGES), presets)
        self.assertEqual(len(OLD_MESSAGES), 12)

    def test_vpn_store_is_route_change_without_the_project_lock(self):
        route_change, vpn_store = self.ns["ROUTE_CHANGE"], self.ns["VPN_STORE"]
        self.assertIsNot(vpn_store, route_change)
        self.assertEqual((vpn_store.route, vpn_store.tuner, vpn_store.diagnostic, vpn_store.starting),
                         (route_change.route, route_change.tuner, route_change.diagnostic, route_change.starting))
        self.assertIsNone(vpn_store.project)
        self.assertIsNotNone(route_change.project)

    def test_the_project_lock_text_is_the_new_refusal_of_the_coordinator(self):
        self.assertEqual(self.ns["PROJECT_BUSY"], "проект занят другой операцией (PID {pid}); повторите позже")
        for name in OLD_MESSAGES:
            preset = self.ns[name]
            if preset.project is not None:
                self.assertEqual(preset.project.format(pid=7), "проект занят другой операцией (PID 7); повторите позже")


class RunningJobTests(JobfilesTestCase):
    """A real process of each family is seen through the helpers and the coordinator, with no patches on them."""

    def test_a_running_job_of_each_family_is_seen_by_the_helpers_and_the_coordinator(self):
        script = self.root / "worker.py"
        script.write_text(SLEEPER, encoding="utf-8")
        self.patch(ENTRY=script, AUTOTUNER=script, DIAGNOSTICS=script)
        coordinator, busy = self.ns["COORDINATOR"], self.ns["Busy"]
        refusals = self.ns["ROUTE_CHANGE"]
        arguments = {"route": ["--route-job", "j1", "switch"], "tuner": ["--job-id", "j1"], "diagnostic": ["--job-id", "j1"]}
        for name in FAMILIES:
            with self.subTest(family=name):
                store = self.store[name]
                ended = threading.Event()
                spec = self.ns["JobSpec"](
                    family=name, kind="x", job_id="j1", argv=[sys.executable, str(script), *arguments[name]],
                    initial={"job_id": "j1", "status": "queued"},
                )
                store.prepare(spec)
                pid = store.spawn(spec, on_exit=ended.set)
                self.addCleanup(kill_group, pid)
                self.assertIs(self.ns[f"{name}_active"](), True)
                self.assertEqual(self.ns[f"{name}_pid"](), pid)
                self.assertEqual(coordinator.active(), name)
                with self.assertRaises(busy) as raised:
                    coordinator.ensure_idle(refusals)
                self.assertEqual(str(raised.exception), getattr(refusals, name))
                for other in FAMILIES:
                    if other != name:
                        self.assertIs(self.ns[f"{other}_active"](), False)
                kill_group(pid)
                self.assertTrue(ended.wait(WAIT), "the reaper reported the end of the process")
                self.assertIs(self.ns[f"{name}_active"](), False)
                coordinator.ensure_idle(refusals)
                store.clear()

    def test_a_worker_of_another_entry_is_not_this_panels_route_job(self):
        script = self.root / "worker.py"
        script.write_text(SLEEPER, encoding="utf-8")
        self.patch(ENTRY=self.root / "app.py")
        store = self.store["route"]
        spec = self.ns["JobSpec"](
            family="route", kind="x", job_id="j1", argv=[sys.executable, str(script), "--route-job", "j1"],
            initial={"job_id": "j1", "status": "queued"},
        )
        store.prepare(spec)
        pid = store.spawn(spec)
        self.addCleanup(kill_group, pid)
        self.assertEqual(self.ns["route_pid"](), pid)
        self.assertIs(self.ns["route_active"](), False)
        self.assertIsNone(self.ns["COORDINATOR"].active())


if __name__ == "__main__":
    unittest.main()
