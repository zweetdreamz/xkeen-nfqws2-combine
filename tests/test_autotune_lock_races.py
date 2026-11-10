"""Real tuner/CLI interleavings without router services or network calls."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

from kdn.common.lock import ProjectLock


ROUTER_DIR = Path(__file__).resolve().parents[1] / "tools/router"
CHILD = r'''
import os, sys
import zapret_autotune_job as job
from kdn.common import lock
job.TEST_ROOT = sys.argv[1]
mode = sys.argv[2]
real_alive = lock.proc.process_alive
real_read = lock.proc.read_job_pid
paused = False

def pause():
    global paused
    if not paused:
        paused = True
        print("observed", flush=True)
        assert sys.stdin.readline().strip() == "continue"

def alive(pid):
    if mode == "stale" and pid == 99999999:
        pause()
        return False
    return real_alive(pid)

def reader(path):
    value = real_read(path)
    if mode == "empty" and value is None:
        pause()
    return value

job.process_alive = alive
lock.proc.process_alive = alive
job.read_pid = reader
lock.proc.read_job_pid = reader
try:
    handle = job.acquire_project_lock()
except RuntimeError:
    print("busy", flush=True)
else:
    print("acquired", flush=True)
    job.release_project_lock(handle)
'''


class TunerLockRaceTests(unittest.TestCase):
    def test_tuner_cannot_replace_cli_owner_after_stale_observation(self):
        self.interleaving("stale")

    def test_tuner_waits_for_cli_pid_publication(self):
        self.interleaving("empty")

    def interleaving(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "opt/tmp/keenetic-discord-nfqws2.lock"
            path.mkdir(parents=True)
            if mode == "stale":
                (path / "pid").write_text("99999999\n", encoding="ascii")
            child = subprocess.Popen(
                [sys.executable, "-c", CHILD, directory, mode], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={**os.environ, "PYTHONPATH": str(ROUTER_DIR)},
            )
            owner = ProjectLock(path)
            try:
                ready, _, _ = select.select([child.stdout], [], [], 5)
                self.assertTrue(ready, "tuner did not reach the acquisition interleaving")
                self.assertEqual(child.stdout.readline().strip(), "observed")
                if mode == "empty":
                    # The CLI has mkdir'd and is now publishing in its original directory.
                    self.assertTrue(owner._publish_pid())
                else:
                    owner.acquire()
                output, error = child.communicate("continue\n", timeout=5)
                self.assertEqual(child.returncode, 0, error)
                self.assertEqual(output.strip(), "busy", error)
                self.assertTrue(owner.held)
                self.assertEqual((path / "pid").read_text().strip(), str(os.getpid()))
            finally:
                owner.release()
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)


PUBLISHER = r'''
import sys
from kdn.common import lock
original_link = lock.os.link

def paused_link(source, target):
    print("before-link", flush=True)
    assert sys.stdin.readline().strip() == "publish"
    return original_link(source, target)

lock.os.link = paused_link
handle = lock.ProjectLock(sys.argv[1])
handle.acquire()
print("owner-held", flush=True)
assert sys.stdin.readline().strip() == "finish"
handle.release()
'''
PUBLICATION_TAKER = r'''
import inspect, sys
import zapret_autotune_job as job
from kdn.common import lock
job.TEST_ROOT = sys.argv[1]
original_read = lock.proc.read_job_pid

def paused_read(path):
    value = original_read(path)
    caller = inspect.currentframe().f_back
    if value is None and caller.f_code.co_name == "_pid" and caller.f_back.f_code.co_name == "_remove_directory":
        print("observed-empty", flush=True)
        assert sys.stdin.readline().strip() == "continue"
    return value

lock.proc.read_job_pid = paused_read
try:
    handle = job.acquire_project_lock()
except RuntimeError:
    print("busy", flush=True)
else:
    print("acquired", flush=True)
    assert sys.stdin.readline().strip() == "finish"
    job.release_project_lock(handle)
'''


class PublicationRaceTests(unittest.TestCase):
    def test_original_publisher_keeps_ownership_when_tuner_checks_empty_pid(self):
        # A late link+unlink(tmp) must not let stale cleanup delete a live PID.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "opt/tmp/keenetic-discord-nfqws2.lock"
            children = []

            def start(source, argument):
                child = subprocess.Popen(
                    [sys.executable, "-c", source, str(argument)], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env={**os.environ, "PYTHONPATH": str(ROUTER_DIR)},
                )
                children.append(child)
                return child

            def line(child):
                self.assertTrue(select.select([child.stdout], [], [], 8)[0], "child stalled")
                return child.stdout.readline().strip()

            def send(child, value):
                child.stdin.write(value + "\n")
                child.stdin.flush()

            try:
                owner = start(PUBLISHER, path)
                self.assertEqual(line(owner), "before-link")
                tuner = start(PUBLICATION_TAKER, directory)
                outcome = line(tuner)
                if outcome == "observed-empty":
                    # Without publication synchronization, the taker reaches its
                    # invalid-pid decision while the original writer is alive.
                    send(owner, "publish")
                    self.assertEqual(line(owner), "owner-held")
                    send(tuner, "continue")
                    outcome = line(tuner)
                else:
                    # A synchronized publisher keeps the takeover mutex until
                    # its PID is published, so the bounded taker refuses first.
                    send(owner, "publish")
                    self.assertEqual(line(owner), "owner-held")
                self.assertEqual(outcome, "busy")
                self.assertIsNone(owner.poll())
                self.assertEqual((path / "pid").read_text().strip(), str(owner.pid))
                send(owner, "finish")
                for child in children:
                    _, error = child.communicate(timeout=5)
                    self.assertEqual(child.returncode, 0, error)
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=5)
