"""Shared real-process fixtures for tool-owned job views (never router commands)."""
import json
import os
import signal
import sys
import time

import panel_harness


class OwnedJobCase(panel_harness.PanelTestCase):
    family_name = ""

    def setUp(self):
        self.root = self.fresh_root()
        self.jobs = self.ns.module("jobfiles")
        self.cfg = self.ns.module("config")
        self.specs = self.ns.module("kdn.jobs.jobspec")
        self.mod = self.ns.module("tuner_jobs" if self.family_name == "tuner" else "diagnostic_jobs")
        self.store = getattr(self.jobs, self.family_name.upper() + "_STORE")
        self.family = self.store.family
        self.job_id = "a" * 16
        self.cfg.PROJECT_DIR.mkdir(parents=True, exist_ok=True)
        self.patch(read_status_fields=lambda: {"ok": True, "output": "", "youtube_route": "zapret", "discord_voice_route": "zapret"})

    def spec(self, status="running", argv=None):
        return self.specs.JobSpec(self.family_name, "test", self.job_id, argv or [], cwd=self.cfg.PROJECT_DIR,
            initial={"job_id": self.job_id, "status": status, **({"kind": "health"} if self.family_name == "diagnostic" else {"service": "youtube"})})

    def read_view(self):
        return getattr(self.mod, self.family_name + "_status")()

    def reconcile(self):
        return getattr(self.mod, "reconcile_" + self.family_name + "_job")()

    def cancel(self):
        return getattr(self.mod, "cancel_" + self.family_name + "_job")()

    def start(self, **options):
        if self.family_name == "diagnostic":
            return self.mod.start_diagnostic_job("health")
        settings = self.mod.validate_tuner_request({"service": "youtube", "search_seed": 5})
        return self.mod.start_tuner_job(settings, **options)

    def digest(self):
        return {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}

    def until(self, predicate):
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("reaper did not finish")

    def spawn_real(self, source="import time; time.sleep(60)", callback=None):
        args = [sys.executable, "-c", source, *[os.fsdecode(marker) for marker in self.family.marker()]]
        spec = self.spec(argv=args)
        self.store.prepare(spec)
        pid = self.store.spawn(spec, on_exit=callback)
        self.addCleanup(lambda: self.store.active() and os.killpg(pid, signal.SIGKILL))
        return pid

    def check_owned_view_and_reconcile(self):
        self.store.prepare(self.spec())
        before = self.digest()
        self.assertEqual(self.read_view()["status"], "error")
        self.assertEqual(before, self.digest())
        self.assertTrue(self.reconcile())
        self.assertEqual(self.store.read_state()["status"], "error")
        self.assertFalse(self.reconcile())

    def check_cancel_marker_and_terminal_state(self, terminal):
        self.spawn_real()
        before = self.family.state().read_bytes()
        self.cancel()
        self.assertEqual(self.family.state().read_bytes(), before)
        marker = json.loads((self.family.directory() / "cancel.request").read_text())
        self.assertEqual(marker["job_id"], self.job_id)
        self.assertEqual(self.read_view()["status"], "cancelling")
        self.store.update_state(self.job_id, status=terminal)
        self.assertEqual(self.read_view()["status"], terminal)

    def check_manual_tool_is_never_settled(self):
        self.family.directory().mkdir(parents=True, exist_ok=True)
        self.store.write_state(self.spec().initial)
        before = self.digest()
        self.assertEqual(self.read_view()["status"], "error")
        self.assertFalse(self.reconcile())
        self.assertEqual(before, self.digest())

    def check_starting_and_legacy_marker(self, refusals):
        with self.jobs.COORDINATOR.exclusive(refusals, family=self.family_name):
            self.store.prepare(self.spec(status="queued"))
            self.assertEqual(self.read_view()["status"], "starting")
        (self.family.directory() / "job.id").unlink()
        (self.family.directory() / "cancel.request").write_text(json.dumps({"job_id": "old", "pid": 9876}))
        self.assertNotEqual(self.read_view()["status"], "cancelling")

    def check_early_exit_is_reconciled_while_starting(self):
        script = self.root / "early-tool.py"
        script.write_text("pass\n")
        if self.family_name == "tuner":
            self.patch(AUTOTUNER=script)
            refusals = self.mod.refusals.TUNER_START
            launch = lambda: self.mod.launch_tuner_job(self.mod.validate_tuner_request({"service": "youtube"}))
        else:
            self.patch(DIAGNOSTICS=script)
            refusals = self.mod.refusals.DIAGNOSTIC_START
            launch = lambda: self.mod.launch_diagnostic_job("health")
        with self.jobs.COORDINATOR.exclusive(refusals, family=self.family_name):
            launch()
            self.until(lambda: self.store.read_state()["status"] == "error")
