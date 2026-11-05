"""Route read views, byte budgets, owned payloads and process-exit reconciliation."""
import json
import os
import signal
import subprocess
import sys
import threading
import time
from unittest import mock

import panel_harness


class RouteViewTests(panel_harness.PanelTestCase):
    def setUp(self):
        self.root = self.fresh_root()
        self.route = self.ns.module("route_jobs")
        self.jobs = self.ns.module("jobfiles")
        self.cfg = self.ns.module("config")
        self.patch(current_routes_fast=lambda: {}, route_active=lambda: False)
        self.job_id = "a" * 16

    def state(self, **values):
        state = {"job_id": self.job_id, "operation": "switch", "status": "running", "output": "", **values}
        self.jobs.ROUTE_STORE.write_state(state) if self.cfg.ROUTE_JOB_DIR.exists() else self.prepare(state)
        return state

    def prepare(self, state):
        self.jobs.ROUTE_STORE.prepare(self.route.jobspec.JobSpec("route", state.get("operation", "switch"), state["job_id"], [], initial=state))

    def digest(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}

    def until(self, predicate):
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("process/reaper did not finish")

    def test_dead_view_is_read_only_and_reconcile_writes_once(self):
        self.state()
        self.route.history.write_history({"job_id": self.job_id, "status": "running"})
        self.route.stage_payload(self.job_id, {"secret": "fixture"})
        before = self.digest()
        view = self.route.route_status()
        self.assertEqual(view["status"], "failed")
        self.assertEqual(before, self.digest())
        with mock.patch.object(self.route.history, "update_history", wraps=self.route.history.update_history) as update:
            self.assertTrue(self.route.reconcile_route_job())
            self.assertFalse(self.route.reconcile_route_job())
            self.assertEqual(update.call_count, 1)
        self.assertFalse(self.jobs.route_payload_path().exists())
        self.assertEqual(self.jobs.ROUTE_STORE.read_state()["status"], "failed")

    def test_snapshot_and_operation_specific_dead_text(self):
        self.state()
        with mock.patch.object(self.route.engine, "parse_snapshot_from_output", return_value="snapshot-A"):
            self.assertEqual(self.route.route_view()["snapshot"], "snapshot-A")
        for operation in (*self.route.SWITCH_OPERATIONS, "xkeen", "vpn-add"):
            with self.subTest(operation=operation):
                text = self.route.dead_route_changes({"operation": operation}, "")["error"]
                self.assertEqual(text, "процесс переключения завершился неожиданно" if operation in self.route.SWITCH_OPERATIONS
                                 else "процесс операции завершился неожиданно")

    def test_starting_view_wins_even_after_queued_was_written(self):
        for family in ("route", "tuner"):
            with self.subTest(family=family), self.jobs.COORDINATOR.exclusive(self.route.refusals.ROUTE_CHANGE, family=family):
                self.state(status="queued")
                view = self.route.route_status()
                self.assertEqual(view["status"], "starting" if family == "route" else "queued")
                self.assertEqual(self.jobs.ROUTE_STORE.read_state()["status"], "queued")

    def test_status_byte_budget_and_result_keeps_full_output(self):
        for text in ("я" * 200000, "\x1b[31m" * 10000, "漢" * 10000, "😀" * 10000):
            with self.subTest(text=text[:8]):
                self.state(status="completed", output=text, error=text[:10000], result={"health": {"ok": True}})
                result = self.route.route_result(self.job_id)
                self.assertEqual(result["output"], text)
                self.assertEqual(result["health"], {"ok": True})
                view = self.route.route_status()
                self.assertLessEqual(len(json.dumps(view, ensure_ascii=False).encode()), 2048)
                self.assertLessEqual(set(view), set(self.route.ROUTE_STATUS_FIELDS))
                self.assertEqual(view["job_id"], self.job_id)
                self.assertNotIn("log_tail", view)
        with self.assertRaisesRegex(LookupError, "состояние задания изменилось"):
            self.route.route_result("b" * 16)

    def test_finish_bounds_escaped_state_and_history_can_be_disabled(self):
        for text in ("\x1b" * 100000, "😀" * 100000, "я" * 100000):
            with self.subTest(text=text[:8]):
                self.state(status="queued")
                self.assertTrue(self.route.begin_route_job(self.job_id))
                with mock.patch.object(self.route.history, "update_history") as history:
                    self.assertEqual(self.route.finish_route_job(self.job_id, {"ok": True, "code": 0, "output": text,
                                                                              "health": {"ok": True}}, history=False), 0)
                    history.assert_not_called()
                state = self.jobs.ROUTE_STORE.read_state()
                self.assertEqual(state["status"], "completed")
                self.assertEqual(state["result"]["health"], {"ok": True})
                self.assertLessEqual(self.cfg.ROUTE_STATE.stat().st_size, self.route.STATE_BYTE_LIMIT)
                self.assertTrue(state["output"].endswith(text[-20:]))

    def test_payload_taken_once_and_other_job_kept(self):
        self.state()
        self.route.stage_payload(self.job_id, {"credentials": "fixture"})
        self.assertEqual(self.jobs.route_payload_path().stat().st_mode & 0o777, 0o600)
        with self.assertRaises(LookupError):
            self.route.take_payload("b" * 16)
        self.assertFalse(self.route.discard_payload("b" * 16))
        self.assertEqual(self.route.take_payload(self.job_id), {"credentials": "fixture"})
        with self.assertRaises(LookupError):
            self.route.take_payload(self.job_id)

    def test_spawn_and_failure_cleanup(self):
        state = {"job_id": self.job_id, "operation": "switch", "status": "queued"}
        with mock.patch.object(subprocess, "Popen", return_value=mock.Mock(pid=1234)) as popen:
            result = self.route.launch_route_worker(state, ["switch", "youtube", "direct"], history=False, payload={"A": 1})
        self.assertEqual(result["pid"], 1234)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.args[0], [sys.executable, str(self.cfg.ENTRY), "--route-job", self.job_id,
                                                 "switch", "youtube", "direct"])
        with mock.patch.object(subprocess, "Popen", side_effect=OSError("spawn failed")):
            with self.assertRaisesRegex(OSError, "spawn failed"):
                self.route.launch_route_worker(state, ["switch", "youtube", "direct"], history=False, payload={"A": 2})
        self.assertFalse(self.jobs.route_payload_path().exists())
        self.assertEqual(self.jobs.ROUTE_STORE.read_state()["status"], "failed")
        self.assertFalse(self.cfg.ROUTE_HISTORY_DIR.exists())

    def test_reaper_start_failure_and_staging_failure_do_not_leave_payload(self):
        state = {"job_id": self.job_id, "operation": "xkeen", "status": "queued"}
        with mock.patch.object(self.jobs.ROUTE_STORE, "spawn", side_effect=RuntimeError("no threads")):
            with self.assertRaisesRegex(RuntimeError, "no threads"):
                self.route.launch_route_worker(state, ["xkeen", "start", "-"], history=False, payload={"secret": "fixture"})
        self.assertFalse(self.jobs.route_payload_path().exists())
        self.assertEqual(self.jobs.ROUTE_STORE.read_state()["status"], "failed")
        with mock.patch.object(self.route, "stage_payload", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.route.launch_route_worker(state, ["xkeen", "start", "-"], history=False, payload={"secret": "fixture"})
        self.assertFalse(self.jobs.route_payload_path().exists())
        self.assertEqual(self.jobs.ROUTE_STORE.read_state()["status"], "failed")

    def test_real_killed_worker_reaper_discards_payload_and_marks_failure(self):
        self.cfg.PROJECT_DIR.mkdir(parents=True, exist_ok=True)
        entry = self.root / "entry.py"
        entry.write_text("import time\ntime.sleep(60)\n")
        self.patch(ENTRY=entry)
        state = {"job_id": self.job_id, "operation": "xkeen", "status": "queued"}
        launched = self.route.launch_route_worker(state, ["xkeen", "start", "-"], history=False, payload={"secret": "fixture"})
        pid = launched["pid"]
        self.addCleanup(lambda: self.jobs.ROUTE_STORE.active() and os.killpg(pid, signal.SIGKILL))
        os.kill(pid, signal.SIGKILL)
        self.until(lambda: self.jobs.ROUTE_STORE.read_state()["status"] == "failed")
        self.until(lambda: not self.jobs.route_payload_path().exists())

    def test_stale_reconcile_leaves_new_job_and_payload_intact(self):
        old = self.state()
        entered, resume = threading.Event(), threading.Event()
        errors = []
        original = self.jobs.ROUTE_STORE.settle

        def settling(*args, **kwargs):
            entered.set()
            resume.wait(3)
            return original(*args, **kwargs)

        def run():
            try:
                self.route.mark_dead_route_job(old, "")
            except Exception as exc:
                errors.append(exc)

        with mock.patch.object(self.jobs.ROUTE_STORE, "settle", side_effect=settling):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            self.assertTrue(entered.wait(2))
            # Simulate the competing prepare through the actual store, not a
            # patched update that would hide a stale-id overwrite.
            newer = {"job_id": "b" * 16, "operation": "switch", "status": "queued"}
            self.prepare(newer)
            path = self.jobs.route_payload_path()
            path.write_text(json.dumps({"job_id": "b" * 16, "data": {"new": True}}))
            resume.set()
            worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(self.jobs.ROUTE_STORE.read_state(), newer)
        self.assertTrue(path.exists())

    def test_settle_rechecks_terminal_status_under_the_store_lock(self):
        self.state(status="completed")
        before = self.digest()
        self.assertFalse(self.jobs.ROUTE_STORE.settle(self.job_id, expected_statuses={"running"}, status="failed"))
        self.assertEqual(before, self.digest())

    def test_immediate_exit_is_reconciled_even_while_start_lock_is_held(self):
        self.cfg.PROJECT_DIR.mkdir(parents=True, exist_ok=True)
        entry = self.root / "fast-entry.py"
        entry.write_text("pass\n")
        self.patch(ENTRY=entry)
        with self.jobs.COORDINATOR.exclusive(self.route.refusals.ROUTE_CHANGE, family="route"):
            self.route.launch_route_worker({"job_id": self.job_id, "operation": "xkeen", "status": "queued"},
                                           ["xkeen", "start", "-"], history=False, payload={"secret": "fixture"})
            self.until(lambda: self.jobs.ROUTE_STORE.read_state()["status"] == "failed")
            self.until(lambda: not self.jobs.route_payload_path().exists())

    def test_cancel_and_prepare_are_serialized_before_signal(self):
        self.state()
        store = self.jobs.ROUTE_STORE
        entered, release, preparing = threading.Event(), threading.Event(), threading.Event()
        errors = []

        def alive(pid):
            entered.set()
            release.wait(3)
            return True

        def cancel():
            try:
                store.request_cancel("not active")
            except Exception as exc:
                errors.append(exc)

        def prepare():
            preparing.set()
            self.prepare({"job_id": "b" * 16, "operation": "xkeen", "status": "queued"})

        def signal_old(pid, sig):
            self.assertEqual((pid, sig, store.job_id()), (4321, signal.SIGTERM, self.job_id))

        with mock.patch.object(store, "pid", return_value=4321), mock.patch.object(store, "alive", side_effect=alive), \
                mock.patch.object(os, "killpg", side_effect=signal_old) as killpg:
            cancelling = threading.Thread(target=cancel, daemon=True)
            next_job = threading.Thread(target=prepare, daemon=True)
            cancelling.start()
            try:
                self.assertTrue(entered.wait(2))
                next_job.start()
                self.assertTrue(preparing.wait(2))
                next_job.join(0.1)
                self.assertTrue(next_job.is_alive())
            finally:
                release.set()
                cancelling.join(4)
                if next_job.ident is not None:
                    next_job.join(4)
            killpg.assert_called_once_with(4321, signal.SIGTERM)
        self.assertEqual(errors, [])
        self.assertEqual(store.job_id(), "b" * 16)
        self.assertFalse((self.cfg.ROUTE_JOB_DIR / "cancel.request").exists())

    def test_cancel_revalidates_identity_after_marker_fsync(self):
        self.state()
        store = self.jobs.ROUTE_STORE
        before = self.cfg.ROUTE_STATE.read_bytes()
        with mock.patch.object(store, "pid", return_value=4321), \
                mock.patch.object(store, "alive", side_effect=[True, False]), mock.patch.object(os, "killpg") as killpg:
            with self.assertRaisesRegex(RuntimeError, "not active"):
                store.request_cancel("not active")
            killpg.assert_not_called()
        self.assertFalse((self.cfg.ROUTE_JOB_DIR / "cancel.request").exists())
        self.assertEqual(self.cfg.ROUTE_STATE.read_bytes(), before)
