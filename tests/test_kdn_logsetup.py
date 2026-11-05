"""Unit tests of kdn.common.logsetup: the panel log with rotation and the redirection of print and tracebacks into it.

The module is imported directly. Every log lives in a TemporaryDirectory; no test touches /opt. The logger "kdn.panel"
and sys.stdout/sys.stderr are process-wide state: every test removes its handlers and restores the streams in a cleanup.
The last classes run a child process that holds an appending descriptor of the log, as the old init leaves it
(`nohup python3 app.py >> xkeen-web.log 2>&1 &`), and pin what a rotation does to such a descriptor.
"""

from __future__ import annotations

import contextlib
import errno
import io
import logging
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from kdn.common import logsetup


ROUTER_DIR = Path(logsetup.__file__).resolve().parents[2]
CHILD_ENV = {**os.environ, "PYTHONPATH": str(ROUTER_DIR)}
RECORD = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} (?P<level>[A-Z]+) (?P<text>.*)$")
MULTIBYTE_TEXT = "Ошибка проверки конфигурации маршрута, попытка %02d из тридцати: повторите запрос позже"
THREAD_TRACEBACK_TEXT = "сбой в потоке обработчика"


class LoggingLoop(BaseException):
    """Not an Exception: the handlers swallow those, and the loop would never end."""


class FullDisk:
    """A log stream whose every write fails; more than 20 attempts mean the failure report went back into the log."""

    def __init__(self):
        self.attempts = 0

    def seek(self, *args):
        return 0

    def tell(self):
        return 0

    def write(self, text):
        self.attempts += 1
        if self.attempts > 20:
            raise LoggingLoop("the logging failure came back into the logger")
        raise OSError(errno.ENOSPC, "disk full")

    def flush(self):
        pass

    def close(self):
        pass


class LogTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dir = Path(temporary.name)
        self.path = self.dir / "panel.log"
        self.addCleanup(self.reset_panel_logger)

    def reset_panel_logger(self):
        logsetup.restore_std_streams()
        logger = logging.getLogger("kdn.panel")
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

    def configure(self, **overrides):
        options = {"max_bytes": 1_000_000, "backups": 2, **overrides}
        return logsetup.configure_logging(self.path, **options)

    def rotated(self, number):
        return self.path.with_name(f"{self.path.name}.{number}")

    def records(self, path=None):
        """(level, text) of every line of a log file; a line that is not a record fails the test."""
        found = []
        for line in (path or self.path).read_text(encoding="utf-8").splitlines():
            match = RECORD.match(line)
            self.assertIsNotNone(match, f"not a log record: {line!r}")
            found.append((match["level"], match["text"]))
        return found

    def mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def log_until(self, logger, reached):
        """Log panel records until `reached()` holds; a rotation is never more than a few records away."""
        for _ in range(200):
            if reached():
                return
            logger.info("запись панели для ротации")
        self.fail("the rotation did not happen")


class ConfigureTests(LogTestCase):
    def test_message_format_has_time_level_and_text(self):
        self.assertEqual(logsetup.LOG_FORMAT, "%(asctime)s %(levelname)s %(message)s")
        logger = self.configure()
        logger.warning("значение %s из %d", "раз", 5)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} WARNING значение раз из 5$")

    def test_panel_logger_is_the_configured_logger(self):
        logger = self.configure()
        self.assertIs(logsetup.panel_logger(), logger)
        self.assertEqual(logger.name, "kdn.panel")
        self.assertEqual(logger.level, logging.INFO)

    def test_does_not_propagate_to_the_root_logger(self):
        root = logging.getLogger()
        seen = []
        capture = logging.Handler()
        capture.emit = seen.append
        root.addHandler(capture)
        self.addCleanup(root.removeHandler, capture)
        logger = self.configure()
        logger.error("не для корня")
        self.assertFalse(logger.propagate)
        self.assertEqual(seen, [])
        self.assertEqual(self.records(), [("ERROR", "не для корня")])

    def test_the_root_logger_is_left_alone(self):
        root = logging.getLogger()
        before = (list(root.handlers), root.level)
        self.configure(console=True)
        self.assertEqual((list(root.handlers), root.level), before)

    def test_percent_formatting_is_lazy(self):
        class Counted:
            calls = 0

            def __str__(self):
                self.calls += 1
                return "значение"

        value = Counted()
        logger = self.configure()
        logger.debug("отладка %s", value)
        self.assertEqual(value.calls, 0)
        logger.info("сообщение %s", value)
        self.assertGreaterEqual(value.calls, 1)
        self.assertEqual(self.records(), [("INFO", "сообщение значение")])

    def test_unconfigured_logger_is_silent(self):
        logger = logging.getLogger("kdn.panel")
        self.reset_panel_logger()  # pytest hangs its own capture handlers on a logger that does not propagate
        logger.propagate = True
        logger.setLevel(logging.NOTSET)
        self.assertIs(logsetup.panel_logger(), logger)
        root = logging.getLogger()
        seen = []
        capture = logging.Handler()
        capture.emit = seen.append
        root.addHandler(capture)
        self.addCleanup(root.removeHandler, capture)
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            logger.info("тихо")
            logger.error("и ошибка тоже")
        self.assertEqual((stderr.getvalue(), stdout.getvalue(), seen), ("", "", []))
        self.assertFalse(logger.propagate)

    def test_configure_twice_does_not_duplicate_handlers(self):
        first_path = self.dir / "first.log"
        first = logsetup.configure_logging(first_path, max_bytes=1000, backups=1)
        first_handler = first.handlers[0]
        second = self.configure()
        self.assertIs(second, first)
        self.assertEqual(len(second.handlers), 1)
        self.assertIsNot(second.handlers[0], first_handler)
        self.assertIsNone(first_handler.stream)
        second.info("один раз")
        self.assertEqual(self.records(), [("INFO", "один раз")])
        self.assertEqual(first_path.read_text(encoding="utf-8"), "")
        self.configure(console=True)
        self.configure(console=True)
        self.assertEqual(len(logsetup.panel_logger().handlers), 2)

    def test_console_flag_adds_a_stream_handler(self):
        for console in (False, True):
            with self.subTest(console=console):
                stderr = io.StringIO()
                with mock.patch.object(sys, "stderr", stderr):
                    logger = self.configure(console=console)
                    logger.info("видно в консоли")
                self.assertEqual("видно в консоли" in stderr.getvalue(), console)
                self.assertIn(("INFO", "видно в консоли"), self.records())

    def test_log_directory_is_created(self):
        self.path = self.dir / "var" / "log" / "panel.log"
        self.configure().info("в новом каталоге")
        self.assertEqual(self.records(), [("INFO", "в новом каталоге")])


class FallbackTests(LogTestCase):
    def broken_paths(self):
        blocker = self.dir / "blocker"
        blocker.write_text("не каталог", encoding="utf-8")
        return {"under a regular file": blocker / "panel.log", "a directory": self.dir}

    def test_unwritable_path_falls_back_to_the_stream_with_a_warning(self):
        for name, path in self.broken_paths().items():
            with self.subTest(name):
                stream = io.StringIO()
                logger = logsetup.configure_logging(path, max_bytes=200, backups=1, stream=stream)
                logger.info("после предупреждения")
                lines = stream.getvalue().splitlines()
                self.assertEqual(len(lines), 2, lines)
                self.assertRegex(lines[0], r" WARNING .*" + re.escape(str(path)))
                self.assertRegex(lines[1], r" INFO после предупреждения$")
                # The guarded subclass is required so an error from the
                # fallback stream cannot recurse through redirected stderr.
                self.assertEqual([type(handler) for handler in logger.handlers], [logsetup._GuardedStreamHandler])

    def test_the_default_fallback_stream_is_stderr(self):
        stderr = io.StringIO()
        with mock.patch.object(sys, "stderr", stderr):
            logger = logsetup.configure_logging(self.broken_paths()["under a regular file"], max_bytes=200, backups=1)
            logger.error("в stderr")
        self.assertEqual(len(stderr.getvalue().splitlines()), 2)
        self.assertIn("ERROR в stderr", stderr.getvalue())

    def test_console_does_not_double_the_fallback_stream(self):
        stderr = io.StringIO()
        with mock.patch.object(sys, "stderr", stderr):
            logger = logsetup.configure_logging(
                self.broken_paths()["under a regular file"], max_bytes=200, backups=1, console=True
            )
            logger.info("один раз")
        self.assertEqual(stderr.getvalue().count("один раз"), 1)
        self.assertEqual(len(logger.handlers), 1)


class RotationTests(LogTestCase):
    def test_rotation_keeps_the_configured_number_of_files(self):
        logger = self.configure(max_bytes=200, backups=2)
        for number in range(50):
            logger.info("record %02d", number)
        names = sorted(path.name for path in self.dir.iterdir())
        self.assertEqual(names, ["panel.log", "panel.log.1", "panel.log.2"])
        kept = []
        for path in (self.rotated(2), self.rotated(1), self.path):
            kept += [int(match[1]) for match in re.finditer(r"record (\d\d)", path.read_text(encoding="utf-8"))]
        # The oldest records are gone, the rest is consecutive and ends with the newest.
        self.assertEqual(kept, list(range(kept[0], 50)))
        self.assertGreater(kept[0], 0)

    def test_files_stay_within_the_limit_counted_in_bytes(self):
        logger = self.configure(max_bytes=350, backups=3)
        for number in range(30):
            logger.info(MULTIBYTE_TEXT, number)
        sizes = {path.name: path.stat().st_size for path in self.dir.iterdir()}
        self.assertEqual(sorted(sizes), ["panel.log", "panel.log.1", "panel.log.2", "panel.log.3"])
        self.assertLessEqual(max(sizes.values()), 350, sizes)

    def test_a_file_is_rotated_before_it_would_reach_the_limit(self):
        self.configure(max_bytes=1000).info("record %02d", 0)
        record_size = self.path.stat().st_size
        for limit, per_file in ((2 * record_size, 1), (2 * record_size + 1, 2)):
            with self.subTest(limit=limit):
                self.path = self.dir / f"limit-{limit}.log"
                logger = self.configure(max_bytes=limit, backups=10)
                for number in range(6):
                    logger.info("record %02d", number)
                self.assertEqual(len(self.records()), per_file)
                self.assertLessEqual(self.path.stat().st_size, limit)

    def test_one_record_bigger_than_the_limit_does_not_rotate_an_empty_file(self):
        logger = self.configure(max_bytes=100, backups=2)
        logger.info("пустой файл не ротируется, запись остаётся целой: " + "я" * 200)
        logger.info("следующая запись")
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), ["panel.log", "panel.log.1"])
        self.assertEqual([text[:20] for _, text in self.records(self.rotated(1))], ["пустой файл не ротир"])
        self.assertEqual(self.records(), [("INFO", "следующая запись")])

    def test_a_late_record_after_the_handler_was_closed_reopens_the_file(self):
        logger = self.configure()
        logger.info("до закрытия")
        logger.handlers[0].close()
        noise = io.StringIO()
        with contextlib.redirect_stderr(noise):
            logger.info("после закрытия")
        self.assertEqual(noise.getvalue(), "")
        self.assertEqual([text for _, text in self.records()], ["до закрытия", "после закрытия"])

    def test_no_rotation_without_backups(self):
        logger = self.configure(max_bytes=200, backups=0)
        for number in range(50):
            logger.info("record %02d", number)
        self.assertEqual([path.name for path in self.dir.iterdir()], ["panel.log"])

    def test_no_rotation_without_a_limit(self):
        logger = self.configure(max_bytes=0, backups=2)
        for number in range(200):
            logger.info("record %03d", number)
        self.assertEqual([path.name for path in self.dir.iterdir()], ["panel.log"])

    def test_rotation_never_widens_the_file_mode(self):
        previous = os.umask(0)
        self.addCleanup(os.umask, previous)
        logger = self.configure(max_bytes=200, backups=2)
        for number in range(30):
            logger.info("record %02d", number)
        files = sorted(self.dir.iterdir())
        self.assertEqual(len(files), 3)
        self.assertEqual({path.name: self.mode(path) for path in files}, {path.name: 0o600 for path in files})

    def test_concurrent_writers_do_not_tear_lines_or_overshoot_the_limit(self):
        logger = self.configure(max_bytes=2000, backups=3)
        noise = io.StringIO()

        def write(worker):
            for number in range(100):
                logger.info("поток %d запись %03d", worker, number)

        threads = [threading.Thread(target=write, args=(worker,)) for worker in range(8)]
        with contextlib.redirect_stderr(noise):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(noise.getvalue(), "")
        files = sorted(self.dir.iterdir())
        self.assertGreater(len(files), 1)
        for path in files:
            with self.subTest(path.name):
                self.assertLessEqual(path.stat().st_size, 2000)
                for _level, text in self.records(path):
                    self.assertRegex(text, r"^поток \d запись \d{3}$")


class EncodingTests(LogTestCase):
    def test_russian_text_is_written_as_utf8(self):
        logger = self.configure(max_bytes=300, backups=2)
        for number in range(12):
            logger.warning(MULTIBYTE_TEXT, number)
        logger.info("Панель запущена: «проверка» — готово")
        files = sorted(self.dir.iterdir())
        self.assertGreater(len(files), 1)
        for path in files:
            path.read_bytes().decode("utf-8")
        self.assertEqual(self.records()[-1], ("INFO", "Панель запущена: «проверка» — готово"))

    def test_undecodable_text_survives_in_the_record(self):
        broken = b"bad \xff byte".decode("utf-8", "surrogateescape")
        logger = self.configure()
        noise = io.StringIO()
        with contextlib.redirect_stderr(noise):
            logger.info("вывод команды: %s", broken)
            logger.info("следующая запись")
        self.assertEqual(noise.getvalue(), "")
        self.assertEqual(
            self.records(),
            [("INFO", "вывод команды: bad \\udcff byte"), ("INFO", "следующая запись")],
        )


class FileModeTests(LogTestCase):
    def test_a_special_file_is_neither_rotated_nor_chmodded(self):
        fifo = self.dir / "panel.fifo"
        os.mkfifo(fifo, 0o644)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        noise = io.StringIO()
        with contextlib.redirect_stderr(noise):
            logger = logsetup.configure_logging(fifo, max_bytes=60, backups=1)
            for number in range(5):
                logger.info("record %02d", number)
        self.assertEqual(noise.getvalue(), "")
        self.assertEqual(self.mode(fifo), 0o644)
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), ["panel.fifo"])
        self.assertEqual(os.read(reader, 4096).decode().count("record"), 5)

    def test_file_mode_is_600(self):
        # Under umask 0 an ordinary open would give 666.
        previous = os.umask(0)
        self.addCleanup(os.umask, previous)
        self.configure().info("первая запись")
        self.assertEqual(self.mode(self.path), 0o600)

    def test_existing_file_is_narrowed_and_appended_to(self):
        self.path.write_text("прежняя строка\n", encoding="utf-8")
        self.path.chmod(0o644)
        self.configure().info("новая запись")
        self.assertEqual(self.mode(self.path), 0o600)
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], "прежняя строка")
        self.assertEqual(len(lines), 2)


class RedirectTests(LogTestCase):
    def setUp(self):
        super().setUp()
        self.out, self.err = io.StringIO(), io.StringIO()
        for name, stream in (("stdout", self.out), ("stderr", self.err)):
            patcher = mock.patch.object(sys, name, stream)
            patcher.start()
            self.addCleanup(patcher.stop)

    def redirect(self, **overrides):
        logger = self.configure(**overrides)
        logsetup.redirect_std_streams(logger)
        return logger

    def test_redirected_print_is_info(self):
        self.redirect()
        print("Привет", "мир")
        sys.stdout.write("раз\nдва\nтри")
        self.assertEqual(self.records(), [("INFO", "Привет мир"), ("INFO", "раз"), ("INFO", "два")])
        sys.stdout.write(" и четыре\n")
        self.assertEqual(self.records()[-1], ("INFO", "три и четыре"))
        self.assertEqual((self.out.getvalue(), self.err.getvalue()), ("", ""))

    def test_redirected_stderr_is_error(self):
        self.redirect()
        sys.stderr.write("плохо\n")
        print("совсем плохо", file=sys.stderr)
        self.assertEqual(self.records(), [("ERROR", "плохо"), ("ERROR", "совсем плохо")])
        self.assertEqual((self.out.getvalue(), self.err.getvalue()), ("", ""))

    def test_a_percent_sign_in_printed_text_is_not_a_format(self):
        self.redirect()
        print("загрузка 100% %s %d")
        self.assertEqual(self.records(), [("INFO", "загрузка 100% %s %d")])

    def test_blank_lines_are_dropped_and_indentation_is_kept(self):
        self.redirect()
        sys.stderr.write("\n  \r\n  File \"x.py\", line 1\r\n\n")
        self.assertEqual(self.records(), [("ERROR", "  File \"x.py\", line 1")])
        self.assertNotIn(b"\r", self.path.read_bytes())

    def test_a_partial_line_is_bounded(self):
        self.redirect()
        sys.stdout.write("я" * (64 * 1024 - 1))
        self.assertEqual(self.path.read_text(encoding="utf-8"), "")
        sys.stdout.write("я")
        records = self.records()
        self.assertEqual([(level, len(text)) for level, text in records], [("INFO", 64 * 1024)])
        sys.stdout.write("\n")
        self.assertEqual(len(self.records()), 1)

    def test_redirect_flushes_the_original_streams_first(self):
        class Tracked(io.StringIO):
            flushes = 0

            def flush(self):
                Tracked.flushes += 1
                super().flush()

        for name in ("stdout", "stderr"):
            patcher = mock.patch.object(sys, name, Tracked())
            patcher.start()
            self.addCleanup(patcher.stop)
        self.redirect()
        self.assertEqual(Tracked.flushes, 2)

    def test_flush_writes_out_a_pending_partial_line(self):
        self.redirect()
        sys.stdout.write("без перевода строки")
        self.assertEqual(self.path.read_text(encoding="utf-8"), "")
        sys.stdout.flush()
        self.assertEqual(self.records(), [("INFO", "без перевода строки")])
        sys.stdout.flush()
        self.assertEqual(len(self.records()), 1)

    def test_redirected_stderr_lands_in_the_file(self):
        self.redirect()

        def fail():
            raise ValueError(THREAD_TRACEBACK_TEXT)

        thread = threading.Thread(target=fail, name="handler-1")
        # pytest installs its own hook; the default one is the code that prints to sys.stderr.
        with mock.patch.object(threading, "excepthook", threading.__excepthook__):
            thread.start()
            thread.join()
        records = self.records()
        self.assertEqual({level for level, _ in records}, {"ERROR"})
        texts = [text for _, text in records]
        self.assertIn("Exception in thread handler-1:", texts)
        self.assertIn("Traceback (most recent call last):", texts)
        self.assertIn(f"ValueError: {THREAD_TRACEBACK_TEXT}", texts)
        self.assertEqual(self.err.getvalue(), "")

    def test_lines_of_different_threads_do_not_glue_together(self):
        self.redirect()
        started, done = threading.Event(), threading.Event()

        def slow():
            sys.stdout.write("начало ")
            started.set()
            done.wait(10)
            sys.stdout.write("конец\n")

        def quick():
            started.wait(10)
            sys.stdout.write("чужая строка\n")
            done.set()

        threads = [threading.Thread(target=slow), threading.Thread(target=quick)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(self.records(), [("INFO", "чужая строка"), ("INFO", "начало конец")])

    def test_redirect_is_idempotent_and_restorable(self):
        logger = self.configure()
        logsetup.redirect_std_streams(logger)
        writers = (sys.stdout, sys.stderr)
        self.assertIsNot(writers[0], self.out)
        self.assertIsNot(writers[1], self.err)
        logsetup.redirect_std_streams(logger)
        self.assertEqual((sys.stdout, sys.stderr), writers)
        print("один раз")
        sys.stdout.write("хвост без перевода строки")
        self.assertEqual(self.records(), [("INFO", "один раз")])
        logsetup.restore_std_streams()
        self.assertEqual(self.records()[-1], ("INFO", "хвост без перевода строки"))
        self.assertEqual((sys.stdout, sys.stderr), (self.out, self.err))
        logsetup.restore_std_streams()
        self.assertEqual((sys.stdout, sys.stderr), (self.out, self.err))
        print("после восстановления")
        self.assertEqual(self.out.getvalue(), "после восстановления\n")
        self.assertEqual(len(self.records()), 2)

    def test_restore_leaves_foreign_streams_alone(self):
        self.redirect()
        foreign = io.StringIO()
        with mock.patch.object(sys, "stdout", foreign):
            logsetup.restore_std_streams()
            self.assertIs(sys.stdout, foreign)

    def test_redirect_again_with_another_logger_retargets_the_writers(self):
        self.redirect()
        other = logging.getLogger("kdn.test-logsetup-other")
        other.setLevel(logging.INFO)
        seen = []
        capture = logging.Handler()
        capture.emit = lambda record: seen.append((record.levelname, record.getMessage()))
        other.addHandler(capture)
        other.propagate = False
        self.addCleanup(other.removeHandler, capture)
        writers = (sys.stdout, sys.stderr)
        logsetup.redirect_std_streams(other)
        self.assertEqual((sys.stdout, sys.stderr), writers)
        print("в другой журнал")
        sys.stderr.write("и ошибка\n")
        self.assertEqual(seen, [("INFO", "в другой журнал"), ("ERROR", "и ошибка")])
        self.assertEqual(self.path.read_text(encoding="utf-8"), "")

    def test_redirected_streams_look_like_text_streams(self):
        self.redirect()
        for stream in (sys.stdout, sys.stderr):
            with self.subTest(stream=stream):
                self.assertFalse(stream.isatty())
                self.assertTrue(stream.writable())
                self.assertEqual(stream.encoding, "utf-8")
                self.assertEqual(stream.write("текст\n"), len("текст\n"))
                with self.assertRaises(io.UnsupportedOperation):
                    stream.fileno()
                with self.assertRaises(TypeError):
                    stream.write(b"bytes")

    def test_console_handler_keeps_writing_to_the_real_stderr(self):
        self.redirect(console=True)
        print("видно и в файле, и в консоли", file=sys.stderr)
        self.assertEqual(self.records(), [("ERROR", "видно и в файле, и в консоли")])
        self.assertEqual(self.err.getvalue().count("видно и в файле, и в консоли"), 1)
        # A second configuration after the redirect must not aim the console at the writer: a record of the logger
        # would come back as an ERROR line of the stderr writer.
        logger = logsetup.configure_logging(self.path, max_bytes=1000, backups=1, console=True)
        logger.info("прямая запись")
        direct = [text for _, text in self.records() if "прямая запись" in text]
        self.assertEqual(direct, ["прямая запись"])
        self.assertEqual(self.err.getvalue().count("прямая запись"), 1)

    def test_the_fallback_stream_set_up_after_the_redirect_is_the_real_stderr(self):
        broken = self.dir / "blocker"
        broken.write_text("не каталог", encoding="utf-8")
        logger = logsetup.configure_logging(self.path, max_bytes=1000, backups=1)
        logsetup.redirect_std_streams(logger)
        logger = logsetup.configure_logging(broken / "panel.log", max_bytes=1000, backups=1)
        logger.info("после перенаправления")
        lines = self.err.getvalue().splitlines()
        self.assertEqual(len(lines), 2, lines)
        self.assertRegex(lines[0], r" WARNING ")
        self.assertRegex(lines[1], r" INFO после перенаправления$")

    def test_a_failing_log_write_does_not_recurse_through_the_redirected_stderr(self):
        logger = self.redirect()
        full_disk = FullDisk()
        logger.handlers[0].stream = full_disk
        print("лог не пишется", file=sys.stderr)
        report = self.err.getvalue()
        self.assertIn("--- Logging error ---", report)
        self.assertIn("disk full", report)
        self.assertEqual(full_disk.attempts, 1)

    def test_a_failing_handler_does_not_loop_on_a_direct_logger_call(self):
        logger = self.redirect()
        full_disk = FullDisk()
        logger.handlers[0].stream = full_disk
        logger.info("прямая запись")
        report = self.err.getvalue()
        self.assertEqual(full_disk.attempts, 1)
        self.assertIn("--- Logging error ---", report)
        self.assertIn("disk full", report)
        self.assertLess(len(report.splitlines()), 40)

    def test_a_failing_fallback_stream_does_not_loop_on_a_direct_logger_call(self):
        logger = self.redirect()
        broken = self.dir / "blocker"
        broken.write_text("не каталог", encoding="utf-8")
        full_disk = FullDisk()
        logger = logsetup.configure_logging(broken / "panel.log", max_bytes=1000, backups=1, stream=full_disk)
        self.assertEqual(full_disk.attempts, 1)  # the warning
        logger.info("прямая запись")
        self.assertEqual(full_disk.attempts, 2)
        self.assertLess(len(self.err.getvalue().splitlines()), 80)

    def test_a_logging_failure_is_swallowed_when_there_was_no_stderr(self):
        patcher = mock.patch.object(sys, "stderr", None)
        patcher.start()
        self.addCleanup(patcher.stop)
        logger = self.redirect()
        logger.handlers[0].stream = FullDisk()
        print("лог не пишется")
        self.assertEqual(self.out.getvalue(), "")

    def test_a_handler_aimed_at_the_replaced_stderr_does_not_loop(self):
        logger = self.redirect()
        logger.addHandler(logging.StreamHandler(sys.stderr))
        sys.stderr.write("раз\nдва\nтри")
        sys.stderr.write("\n")
        self.assertEqual([text for _, text in self.records()], ["раз", "два", "три"])


class InheritedDescriptorTests(LogTestCase):
    """What the rotation does to a descriptor opened on the log with O_APPEND before it was configured.

    The intended behaviour: the handler renames the file and reopens the path, so a holder of the old descriptor
    follows the renamed file (panel.log.1) and, once the backups drop it, a deleted one; it never writes into the new
    panel.log. The panel itself stops being such a holder by redirecting print and tracebacks into the logger; what a
    foreign holder writes is not captured, but the size counts every byte in the file.
    """

    def open_like_the_old_init(self):
        holder = open(self.path, "ab", buffering=0)  # noqa: SIM115
        self.addCleanup(holder.close)
        return holder

    def open_reader(self):
        descriptor = os.open(self.path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_the_first_record_rotates_a_file_the_old_init_already_filled(self):
        holder = self.open_like_the_old_init()
        for number in range(20):
            holder.write(b"old init line %02d\n" % number)
        self.path.chmod(0o644)
        logger = self.configure(max_bytes=300, backups=1)
        logger.info("первая запись панели")
        self.assertEqual(self.records(), [("INFO", "первая запись панели")])
        old = self.rotated(1).read_text(encoding="utf-8").splitlines()
        self.assertEqual(old, [f"old init line {number:02d}" for number in range(20)])
        self.assertEqual(os.fstat(holder.fileno()).st_ino, self.rotated(1).stat().st_ino)
        self.assertEqual((self.mode(self.path), self.mode(self.rotated(1))), (0o600, 0o600))

    def test_a_holder_of_the_old_descriptor_follows_the_renamed_file(self):
        holder = self.open_like_the_old_init()
        reader = self.open_reader()
        logger = self.configure(max_bytes=300, backups=1)
        holder.write(b"from the old descriptor before the rotation\n")
        self.log_until(logger, self.rotated(1).exists)
        holder.write(b"from the old descriptor after the rotation\n")
        self.assertIn("after the rotation", self.rotated(1).read_text(encoding="utf-8"))
        self.assertNotIn("old descriptor", self.path.read_text(encoding="utf-8"))
        # Once the backups drop the renamed file the holder writes into a deleted one.
        self.log_until(logger, lambda: not os.fstat(holder.fileno()).st_nlink)
        holder.write(b"from the old descriptor into the deleted file\n")
        for path in (self.path, self.rotated(1)):
            self.assertNotIn("old descriptor", path.read_text(encoding="utf-8"))
        self.assertIn(b"into the deleted file", os.pread(reader, 4096, 0))
        # The panel's own records are unaffected and the live file is still private.
        logger.info("панель продолжает писать")
        self.assertEqual(self.records()[-1], ("INFO", "панель продолжает писать"))
        self.assertEqual(self.mode(self.path), 0o600)

    def test_bytes_appended_by_a_holder_count_towards_the_limit(self):
        holder = self.open_like_the_old_init()
        logger = self.configure(max_bytes=300, backups=1)
        logger.info("запись панели")
        self.assertFalse(self.rotated(1).exists())
        holder.write(b"x" * 280 + b"\n")
        logger.info("следующая запись панели")
        self.assertEqual(self.records(), [("INFO", "следующая запись панели")])
        self.assertIn("x" * 280, self.rotated(1).read_text(encoding="utf-8"))

    def test_a_live_child_holding_the_descriptor_follows_the_inode(self):
        holder = self.open_like_the_old_init()
        reader = self.open_reader()
        logger = self.configure(max_bytes=300, backups=1)
        child = self.start_holder_child(holder)
        self.say(child, "child before the rotation")
        self.assertIn("child before the rotation", self.path.read_text(encoding="utf-8"))
        self.log_until(logger, self.rotated(1).exists)
        self.say(child, "child after the rotation")
        self.assertIn("child after the rotation", self.rotated(1).read_text(encoding="utf-8"))
        self.assertNotIn("child", self.path.read_text(encoding="utf-8"))
        self.log_until(logger, lambda: not os.fstat(holder.fileno()).st_nlink)
        self.say(child, "child into the deleted file")
        for path in (self.path, self.rotated(1)):
            self.assertNotIn("child", path.read_text(encoding="utf-8"))
        self.assertIn(b"child into the deleted file", os.pread(reader, 4096, 0))
        logger.info("панель продолжает писать")
        self.assertEqual(self.records()[-1], ("INFO", "панель продолжает писать"))

    def start_holder_child(self, holder):
        source = (
            "import os, sys\n"
            "while True:\n"
            "    line = sys.stdin.readline()\n"
            "    if not line:\n"
            "        break\n"
            "    os.write(1, line.encode())\n"
            "    os.write(2, b'ok\\n')\n"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", source],
            stdin=subprocess.PIPE,
            stdout=holder,
            stderr=subprocess.PIPE,
            env=CHILD_ENV,
        )
        self.addCleanup(self.stop_child, child)
        return child

    def say(self, child, text):
        child.stdin.write(f"{text}\n".encode())
        child.stdin.flush()
        self.assertEqual(child.stderr.readline(), b"ok\n")

    @staticmethod
    def stop_child(child):
        child.stdin.close()
        child.stderr.close()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()

    def test_a_redirected_process_never_writes_to_its_inherited_descriptors(self):
        source = (
            "import sys, threading\n"
            "from kdn.common import logsetup\n"
            "logger = logsetup.configure_logging(sys.argv[1], max_bytes=2000, backups=1)\n"
            "logsetup.redirect_std_streams(logger)\n"
            "for number in range(200):\n"
            "    print('строка', number)\n"
            "def boom():\n"
            f"    raise ValueError({THREAD_TRACEBACK_TEXT!r})\n"
            "thread = threading.Thread(target=boom, name='handler-1')\n"
            "thread.start()\n"
            "thread.join()\n"
            "sys.stderr.write('последние слова\\n')\n"
        )
        holder = self.open_like_the_old_init()
        holder.write(b"banner from the old init\n")
        reader = self.open_reader()
        result = subprocess.run(
            [sys.executable, "-c", source, str(self.path)],
            stdout=holder,
            stderr=holder,
            env=CHILD_ENV,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        # The file the init opened was the live log at first, then it was rotated out and deleted. What reached it
        # is the banner and records of the logger; a print or a traceback written to fd 1 or 2 would show as a line
        # without the time and level.
        self.assertEqual(os.fstat(reader).st_nlink, 0)
        first_file = os.pread(reader, 65536, 0).decode("utf-8").splitlines()
        self.assertEqual(first_file[0], "banner from the old init")
        for line in first_file[1:]:
            self.assertRegex(line, RECORD)
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), ["panel.log", "panel.log.1"])
        kept = self.records(self.rotated(1)) + self.records()
        texts = [text for _, text in kept]
        self.assertEqual(texts[-1], "последние слова")
        self.assertIn("строка 199", texts)
        self.assertIn(f"ValueError: {THREAD_TRACEBACK_TEXT}", texts)
        self.assertEqual({level for level, text in kept if text.startswith("строка")}, {"INFO"})
        self.assertEqual(kept[-1][0], "ERROR")
        self.assertEqual((self.mode(self.path), self.mode(self.rotated(1))), (0o600, 0o600))


if __name__ == "__main__":
    unittest.main()
