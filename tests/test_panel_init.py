"""Linux-only init integration tests: temporary /opt, real processes, no router."""
import os
import concurrent.futures
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[1]
INIT = REPO / "tools/router/xkeen-web-init.sh"
INSTALL = REPO / "tools/router/xkeen_control_script.sh"


@unittest.skipUnless(sys.platform == "linux", "requires Linux /proc")
class InitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kdn-init-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("opt/xkeen-web", "opt/bin", "opt/var/run", "opt/var/log"):
            (self.root / directory).mkdir(parents=True)
        self.app = self.root / "opt/xkeen-web/app.py"
        self.app.write_text("import time\nwhile True: time.sleep(0.1)\n")
        (self.root / "opt/bin/python3").symlink_to(sys.executable)
        if os.environ.get('TEST_BUSYBOX_APPLETS') == '1':
            busybox = shutil.which('busybox')
            self.assertIsNotNone(busybox)
            available = subprocess.check_output([busybox, '--list'], text=True).splitlines()
            for applet in ('sh', 'dd', 'wc', 'mv', 'chmod', 'mkfifo', 'mktemp', 'sleep',
                           'rm', 'rmdir', 'cat', 'tr', 'grep', 'awk', 'date', 'nohup', 'head'):
                if applet in available:
                    (self.root / 'opt/bin' / applet).symlink_to(busybox)
        self.pidfile = self.root / "opt/var/run/xkeen-web.pid"
        self.childfile = self.root / "opt/var/run/xkeen-web.child.pid"
        self.err = self.root / "opt/var/log/xkeen-web.err"
        self.env = {**os.environ, "KDN_ALLOW_INIT_ROOT": "1", "KDN_INIT_ROOT": str(self.root),
                    "KDN_INIT_DELAY_STEP": "1", "KDN_INIT_DELAY_MAX": "2", "KDN_INIT_PORT": "0",
                    "KDN_INIT_ERR_LIMIT": "64"}
        self.shell = os.environ.get("TEST_SHELL", "sh").split()
        self.init = INIT
        self.addCleanup(lambda: self.run_init("stop"))

    def run_init(self, command, check=False):
        return subprocess.run([*self.shell, str(self.init), command], env=self.env, capture_output=True,
                              text=True, timeout=35, check=check)

    def until(self, predicate, timeout=7):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        self.fail("condition timed out")

    def child(self):
        """A published PID is ready only after this supervisor's child execs APP."""
        pid = int(self.childfile.read_text())
        process = Path('/proc') / str(pid)
        args = (process / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        fields = (process / 'stat').read_bytes().rsplit(b') ', 1)[1].split()
        if (args[1:] != [str(self.app).encode()] or fields[0] in (b'Z', b'X')
                or int(fields[1]) != int(self.pidfile.read_text())
                or int(self.childfile.read_text()) != pid):
            return None
        return pid

    def supervisors(self):
        # Keep the full raw scan: persistent duplicate supervisors must fail,
        # not disappear through a PPID filter intended for transient children.
        found = []
        for entry in Path('/proc').glob('[0-9]*/cmdline'):
            try:
                args = entry.read_bytes().split(b'\0')
                if str(self.init).encode() in args and b'supervise' in args:
                    found.append(int(entry.parent.name))
            except OSError:
                pass
        return sorted(found)

    def settled_supervisor(self):
        supervisor = int(self.pidfile.read_text())
        if self.child() and self.supervisors() == [supervisor]:
            return supervisor
        return None

    def start(self):
        self.run_init("start", check=True)
        return self.until(self.child)

    def test_start_restart_crashed_child_stop_and_detach(self):
        started = time.monotonic()
        first = self.start()  # capture_output must not wait for daemon descriptors
        self.assertLess(time.monotonic() - started, 5)
        supervisor = self.pidfile.read_text()
        self.assertIn("supervised", self.run_init("status", check=True).stdout)
        self.assertIn("already running", self.run_init("start", check=True).stdout)
        self.assertEqual(self.pidfile.read_text(), supervisor)
        os.kill(first, signal.SIGKILL)
        self.until(lambda: (current := self.child()) and current != first)
        self.run_init("stop", check=True)
        self.assertFalse(self.pidfile.exists())
        self.assertFalse(self.childfile.exists())
        self.assertEqual(self.run_init("status").returncode, 1)
        self.run_init("stop", check=True)

    def test_crash_loop_backoff_and_stop_during_pause(self):
        # This test observes four messages; the dedicated rotation test uses
        # a small cap. Four messages intentionally no longer fit in 64 bytes.
        self.env['KDN_INIT_ERR_LIMIT'] = '4096'
        self.app.write_text("raise SystemExit(1)\n")
        self.run_init("start", check=True)
        self.until(lambda: self.err.read_text().count("retry in") >= 4, timeout=10)
        log = self.err.read_text()
        self.assertIn("retry in 1s", log)
        self.assertGreaterEqual(log.count("retry in 2s"), 3)
        self.run_init("status", check=True)
        began = time.monotonic()
        self.run_init("stop", check=True)
        self.assertLess(time.monotonic() - began, 2.5)

    def test_error_log_is_bounded_while_child_is_still_running(self):
        self.env['KDN_INIT_ERR_LIMIT'] = '256'
        self.app.write_text('import time\nprint("x" * 4096 + "END", flush=True)\nwhile True: time.sleep(.1)\n')
        child = self.start()
        self.until(lambda: self.err.exists() and 'END' in self.err.read_text())
        self.assertLessEqual(self.err.stat().st_size, 256)
        archive = Path(str(self.err) + '.1')
        self.assertTrue(archive.exists())
        self.assertLessEqual(archive.stat().st_size, 256)
        os.kill(child, 0)

    def test_stop_holds_the_same_lock_as_start(self):
        self.init = self.root / 'review-init.sh'
        source = INIT.read_text()
        anchor = 'stop() {\n    current=$(read_pid "$PIDFILE") || current=\n'
        self.assertEqual(source.count(anchor), 1)
        entered, release = self.root / 'entered', self.root / 'release'
        hook = ('    touch "$KDN_REVIEW_ENTERED"\n'
                '    while [ ! -e "$KDN_REVIEW_RELEASE" ]; do sleep 0.05; done\n')
        self.init.write_text(source.replace(anchor, anchor + hook, 1))
        self.env.update(KDN_REVIEW_ENTERED=str(entered), KDN_REVIEW_RELEASE=str(release))
        process = subprocess.Popen([*self.shell, str(self.init), 'stop'], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.until(entered.exists)
            result = self.run_init('start')
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        finally:
            release.touch()
            process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0)
        self.start()
        supervisor = self.until(self.settled_supervisor)
        self.assertEqual(self.supervisors(), [supervisor])

    def test_child_pidfile_does_not_prove_app_exec(self):
        # A deterministic fork-before-exec seam in a disposable copy only.
        self.init = self.root / 'preexec-init.sh'
        source = INIT.read_text()
        anchor = '        python3 "$APP" </dev/null > "$log_fifo" 2>&1 &\n'
        self.assertEqual(source.count(anchor), 1)
        entered, gate = self.root / 'preexec-entered', self.root / 'preexec-gate'
        os.mkfifo(gate)
        release_fd = os.open(gate, os.O_RDWR | os.O_NONBLOCK)
        hook = ('        ( : > "$KDN_REVIEW_PREEXEC"; '
                'read -r released < "$KDN_REVIEW_GATE"; '
                'exec python3 "$APP" ) </dev/null > "$log_fifo" 2>&1 &\n')
        self.init.write_text(source.replace(anchor, hook, 1))
        self.env.update(KDN_REVIEW_PREEXEC=str(entered), KDN_REVIEW_GATE=str(gate))
        try:
            self.run_init('start', check=True)
            self.until(entered.exists)
            child = self.until(lambda: int(self.childfile.read_text()))
            supervisor = int(self.pidfile.read_text())
            args = Path(f'/proc/{child}/cmdline').read_bytes().split(b'\0')
            fields = Path(f'/proc/{child}/stat').read_bytes().rsplit(b') ', 1)[1].split()
            parent = int(fields[1])
            print(f'PREEXEC child={child} ppid={parent} supervisor={supervisor} argv={args!r}', flush=True)
            self.assertEqual(parent, supervisor)
            self.assertIn(str(self.init).encode(), args)
            self.assertIn(b'supervise', args)
            self.assertNotIn(str(self.app).encode(), args)
            self.assertIsNone(self.child(), 'published PID is still a forked shell, not the app')
        finally:
            os.write(release_fd, b'released\n')
            os.close(release_fd)
        self.assertEqual(self.until(self.settled_supervisor), supervisor)
        self.assertEqual(self.child(), child)
        self.assertEqual(self.supervisors(), [supervisor])
        self.run_init('stop', check=True)
        self.assertFalse(self.childfile.exists())

    def test_concurrent_restarts_leave_one_supervisor_and_stop_reaps_it(self):
        self.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.run_init('restart'), range(4)))
        self.assertTrue(any(result.returncode == 0 for result in results))
        self.assertTrue(all(result.returncode in (0, 1) for result in results))
        supervisor = self.until(self.settled_supervisor)
        self.assertEqual(self.supervisors(), [supervisor])
        self.run_init('stop', check=True)
        self.until(lambda: not self.supervisors())
        self.assertFalse(self.childfile.exists())

    def test_error_log_stays_bounded_across_crashes(self):
        counter = self.root / 'crashes'
        self.env.update(KDN_INIT_ERR_LIMIT='256', KDN_INIT_DELAY_MAX='1')
        self.app.write_text('from pathlib import Path\n'
                            f'p=Path({str(counter)!r})\n'
                            'p.write_text(str(int(p.read_text())+1) if p.exists() else "1")\n'
                            'print("x"*1024, flush=True)\nraise SystemExit(1)\n')
        self.run_init('start', check=True)
        self.until(lambda: int(counter.read_text()) >= 3)
        self.run_init('stop', check=True)
        for path in (self.err, Path(str(self.err) + '.1')):
            self.assertTrue(path.exists())
            self.assertLessEqual(path.stat().st_size, 256)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_stop_does_not_signal_supervisor_of_another_root(self):
        other = InitTests('test_start_restart_crashed_child_stop_and_detach')
        other.setUp()
        self.addCleanup(other.doCleanups)
        self.start()
        other_child = other.start()
        other_supervisor = int(other.pidfile.read_text())
        self.run_init('stop', check=True)
        os.kill(other_supervisor, 0)
        os.kill(other_child, 0)
        self.assertIn('supervised', other.run_init('status', check=True).stdout)

    def test_stale_and_reused_pid_are_not_signalled_and_error_log_rotates(self):
        self.pidfile.write_text(str(os.getpid()) + "\n")
        self.assertEqual(self.run_init("status").returncode, 1)
        self.run_init("stop", check=True)  # must not signal this test process
        self.err.write_text("x" * 100)
        self.start()
        self.assertEqual(Path(str(self.err) + ".1").read_text(), "x" * 100)

    def test_stale_start_lock_does_not_block_boot_and_starts_are_serialized(self):
        lock = Path(str(self.pidfile) + ".start-lock")
        lock.mkdir()
        (lock / "owner").write_text(str(os.getpid()) + "\n")
        (lock / "token").write_text("previous-boot-token\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.run_init("start"), range(4)))
        self.assertTrue(any(result.returncode == 0 for result in results))
        self.until(lambda: self.child())
        self.assertIn("supervised", self.run_init("status", check=True).stdout)
        self.assertTrue(lock.is_file())  # persistent inode, kernel releases its lock automatically
        matching = []
        for path in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                if str(self.app).encode() in path.read_bytes().split(b"\0"):
                    matching.append(path)
            except OSError:
                pass
        self.assertEqual(len(matching), 1)

    def test_legacy_panel_migration_and_missing_pid_scan(self):
        legacy = subprocess.Popen([sys.executable, str(self.app)])
        self.addCleanup(lambda: legacy.poll() is None and legacy.kill())
        self.pidfile.write_text(str(legacy.pid) + "\n")
        self.assertIn("unsupervised", self.run_init("status", check=True).stdout)
        self.assertIn("unsupervised", self.run_init("start", check=True).stdout)
        self.run_init("restart", check=True)
        self.until(lambda: legacy.poll() is not None)
        self.until(lambda: self.child())
        self.assertIn("supervised", self.run_init("status", check=True).stdout)
        self.run_init("stop", check=True)
        legacy2 = subprocess.Popen([sys.executable, str(self.app)])
        self.addCleanup(lambda: legacy2.poll() is None and legacy2.kill())
        self.run_init("stop", check=True)
        self.until(lambda: legacy2.poll() is not None)

    def test_busy_port_refuses_start(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            self.env["KDN_INIT_PORT"] = str(listener.getsockname()[1])
            result = self.run_init("start")
        self.assertEqual(result.returncode, 1)
        self.assertIn("busy", result.stderr)
        self.assertFalse(self.pidfile.exists())

    def test_independent_worker_survives_panel_and_supervisor(self):
        workerfile = self.root / "worker.pid"
        self.app.write_text(
            "import subprocess, sys, time\nfrom pathlib import Path\n"
            f"p = Path({str(workerfile)!r})\n"
            "if not p.exists():\n"
            " c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'], start_new_session=True)\n"
            " p.write_text(str(c.pid))\nwhile True: time.sleep(0.1)\n")
        child = self.start()
        worker = self.until(lambda: int(workerfile.read_text()))
        self.addCleanup(lambda: os.kill(worker, signal.SIGKILL))
        os.kill(child, signal.SIGKILL)
        self.until(lambda: (current := self.child()) and current != child)
        self.run_init("stop", check=True)
        os.kill(worker, 0)

    def test_old_init_stop_can_stop_supervised_panel(self):
        self.start()
        # Exact stop behaviour of router-init.txt when its PIDFILE exists.
        subprocess.run(["sh", "-c", 'kill "$(cat "$1")"; rm -f "$1"', "sh", str(self.pidfile)], check=True)
        self.until(lambda: not self.childfile.exists())
        self.assertEqual(self.run_init("status").returncode, 1)

    def test_installed_init_migration_both_orders_and_backup_rollback(self):
        initdir = self.root / "opt/etc/init.d"
        initdir.mkdir(parents=True)
        self.init = initdir / "S99xkeen-web"
        # Captured router init's relevant semantics; only absolute fixture paths differ.
        old = (f'#!/bin/sh\nPIDFILE="{self.pidfile}"\nAPP="{self.app}"\n'
               'case "$1" in\n'
               ' start) nohup python3 "$APP" </dev/null >/dev/null 2>&1 & echo $! > "$PIDFILE" ;;\n'
               ' stop) if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE")" 2>/dev/null; '
               'rm -f "$PIDFILE"; else pkill -f "$APP" 2>/dev/null; fi ;;\n'
               ' status) [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null ;;\n'
               'esac\n')
        from target_fixture import installer_environment
        install_env = installer_environment({**self.env, "XKEEN_PROJECT_DIR": str(REPO), "XKEEN_INIT_DIR": str(initdir)}, self.root)
        for stop_first in (True, False):
            with self.subTest(stop_first=stop_first):
                self.init.write_text(old)
                self.init.chmod(0o755)
                self.run_init("start", check=True)
                legacy = int(self.pidfile.read_text())
                self.until(lambda pid=legacy: Path(f"/proc/{pid}/cmdline").read_bytes().find(str(self.app).encode()) >= 0)
                if stop_first:
                    self.run_init("stop", check=True)
                    self.until(lambda pid=legacy: not Path(f"/proc/{pid}/cmdline").exists()
                               or not Path(f"/proc/{pid}/cmdline").read_bytes())
                subprocess.run([*self.shell, str(INSTALL), "--install-init"], env=install_env,
                               capture_output=True, check=True, timeout=5)
                self.run_init("start" if stop_first else "restart", check=True)
                self.until(lambda: self.child())
                self.assertIn("supervised", self.run_init("status", check=True).stdout)
                supervisor = int(self.pidfile.read_text())
                backups = list(initdir.glob("*.pre-supervisor-*"))
                self.assertTrue(any(p.read_text() == old for p in backups))
                self.init.write_text(old)
                self.run_init("status", check=True)  # old init recognises supervisor PID
                self.run_init("stop", check=True)
                self.until(lambda: not self.childfile.exists())
                self.until(lambda pid=supervisor: not Path(f"/proc/{pid}/cmdline").exists()
                           or not Path(f"/proc/{pid}/cmdline").read_bytes())


@unittest.skipUnless(sys.platform == "linux", "shell installer")
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kdn-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.initdir = self.root / "init"
        self.web = self.root / "web"
        self.env = {**os.environ, "XKEEN_PROJECT_DIR": str(REPO), "XKEEN_INIT_DIR": str(self.initdir),
                    "XKEEN_WEB_DIR": str(self.web)}
        from target_fixture import installer_environment
        self.env = installer_environment(self.env, self.root)

    def install(self, *args):
        return subprocess.run([*os.environ.get("TEST_SHELL", "sh").split(), str(INSTALL), *args],
                              env=self.env, capture_output=True, text=True, timeout=5)

    def test_default_only_writes_unchanged_launcher(self):
        self.assertEqual(self.install().returncode, 0)
        self.assertFalse(self.initdir.exists())
        expected = ('import os\nimport runpy\nproject = os.environ.get("XKEEN_PROJECT_DIR", '
                    '"/opt/root/keenetic-discord-nfqws2")\nrunpy.run_path(os.path.join(project, '
                    '"tools", "router", "kdn", "web", "app.py"), run_name="__main__")\n')
        self.assertEqual((self.web / "app.py").read_text(), expected)

    def test_unsupported_target_refuses_before_app_init_or_backup_writes(self):
        from target_fixture import version_executable
        for version in ('XKeen 2.0', 'unknown', 'XKeen 3.0'):
            version_executable(self.root / '.installer-bin/xkeen', version)
            for args in ((), ('--install-init',)):
                with self.subTest(version=version, args=args):
                    result = self.install(*args)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('XKeen 2.1+', result.stdout)
                    self.assertFalse(self.web.exists())
                    self.assertFalse(self.initdir.exists())

    def test_install_and_unique_backup_preserve_old_file(self):
        self.initdir.mkdir()
        dest = self.initdir / "S99xkeen-web"
        dest.write_text("old init\n")
        self.assertEqual(self.install("--install-init").returncode, 0)
        self.assertEqual(dest.read_bytes(), INIT.read_bytes())
        self.assertEqual(dest.stat().st_mode & 0o777, 0o755)
        backups = list(self.initdir.glob("*.pre-supervisor-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "old init\n")
        self.assertEqual(self.install("--install-init").returncode, 0)
        self.assertEqual(len(list(self.initdir.glob("*.pre-supervisor-*"))), 2)
        self.assertFalse(self.web.exists())

    def test_install_fresh_missing_source_and_unknown_argument(self):
        self.assertEqual(self.install("--wrong").returncode, 2)
        self.assertFalse(self.initdir.exists())
        self.env["XKEEN_PROJECT_DIR"] = str(self.root / "missing")
        self.assertEqual(self.install("--install-init").returncode, 1)
        self.assertFalse(self.initdir.exists())
        self.assertFalse(self.web.exists())
        self.env["XKEEN_PROJECT_DIR"] = str(REPO)
        self.assertEqual(self.install("--install-init").returncode, 0)
        self.assertFalse(list(self.initdir.glob("*.pre-supervisor-*")))


if __name__ == "__main__":
    unittest.main()
