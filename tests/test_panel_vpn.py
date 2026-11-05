"""Tests of the VPN node facade of the panel (kdn.web.domain.vpn) and of the Handler routes that call it.

Every operation on the node store runs the same sequence: coordinator.exclusive (including its idle check),
then the manager call under VPN_STORE_LOCK. The facade owns that sequence; Handler only validates the body and maps
the exceptions to 400/409/500. The sequence is pinned on a recording journal, the Handler routes on a real server on
127.0.0.1 with a stub manager, so nothing here touches the router, /opt or the network beyond the loopback.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import threading
import unittest
from unittest import mock

import panel_harness


# facade function -> (arguments, manager method it runs)
STORE_OPERATIONS = {
    "remove_node": (("vless_2",), "remove"),
    "sync_current": ((), "sync_current"),
}
JOB_STARTING = "другое задание уже запускается; повторите через несколько секунд"
ROUTE_RUNNING = "переключение маршрута уже выполняется"
JSON_TYPE = "application/json; charset=utf-8"


class RecordingLock:
    """The store lock with a journal: every take and release goes to ``events`` and on to a real RLock."""

    def __init__(self, events):
        self.events = events
        self.lock = threading.RLock()

    def acquire(self, blocking=True, timeout=-1):
        taken = self.lock.acquire(blocking, timeout)
        if taken:
            self.events.append("store lock taken")
        return taken

    def release(self):
        self.events.append("store lock released")
        self.lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc):
        self.release()


class FakeManager:
    """Stands in for VpnNodeManager: records each call and answers with a payload, or raises ``error``."""

    def __init__(self, events=None, probe=None, error=None):
        self.events = [] if events is None else events
        self.probe = probe
        self.error = error
        self.calls = []
        self.probed = []

    def __getattr__(self, operation):
        if operation not in {"status", "add", "check", "remove", "sync_current"}:
            raise AttributeError(operation)

        def run(*args):
            self.calls.append((operation, args))
            self.events.append(f"manager.{operation}({', '.join(map(repr, args))})")
            if self.probe is not None:
                self.probed.append(self.probe())
            if self.error is not None:
                raise self.error
            return {"ok": True, "operation": operation, "args": list(args)}

        return run


def another_thread_can_take(lock, timeout=10):
    """Whether a second thread can take ``lock`` right now (an RLock lets its owner in, so not the test thread)."""
    answer, failure = [], []

    def probe():
        try:
            taken = lock.acquire(blocking=False)
            if taken:
                lock.release()
            answer.append(taken)
        except Exception as exc:  # reported by the caller, with the lock named
            failure.append(exc)

    thread = threading.Thread(target=probe, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise AssertionError(f"the probe thread did not finish within {timeout} s: {lock!r} may be blocked")
    if failure:
        raise AssertionError(f"the probe thread failed on {lock!r}: {failure[0]!r}") from failure[0]
    return answer[0]


class AnotherThreadCanTakeTests(unittest.TestCase):
    """The probe helper fails with a message when its thread hangs or breaks, not with an IndexError."""

    def test_a_probe_thread_that_hangs_is_reported(self):
        release = threading.Event()
        self.addCleanup(release.set)

        class HungLock:
            def acquire(self, blocking=True):
                release.wait(10)
                return False

        with self.assertRaisesRegex(AssertionError, "did not finish within 0.2 s"):
            another_thread_can_take(HungLock(), timeout=0.2)

    def test_a_probe_thread_that_breaks_is_reported(self):
        class BrokenLock:
            def acquire(self, blocking=True):
                raise OSError("lock is gone")

        with self.assertRaisesRegex(AssertionError, "probe thread failed .*lock is gone"):
            another_thread_can_take(BrokenLock())

    def test_it_answers_for_a_free_and_a_held_lock(self):
        lock = threading.Lock()
        self.assertTrue(another_thread_can_take(lock))
        with lock:
            self.assertFalse(another_thread_can_take(lock))
        self.assertTrue(another_thread_can_take(lock))


class VpnFacadeTests(panel_harness.PanelTestCase):
    ns_name = "panel_vpn_facade_test"

    def setUp(self):
        self.vpn = self.ns.module("vpn")
        self.jobfiles = self.ns.module("jobfiles")

    def test_edit_refuses_busy_before_manager_access(self):
        with self.patched(route_active=lambda: True), mock.patch.object(self.vpn, 'vpn_manager') as manager:
            with self.assertRaises(RuntimeError):
                self.vpn.update_node('reserve', {'name': 'Европа'})
            manager.assert_not_called()

    @contextlib.contextmanager
    def journal(self, error=None, record_guard=True, record_check=True):
        """Patch the facade's collaborators with recording stand-ins; yields (events, manager).

        ``record_guard`` / ``record_check`` False keep the real job-start guard / availability check.
        """
        events = []
        lock = RecordingLock(events)
        coordinator = self.jobfiles.COORDINATOR
        real_guard = coordinator.exclusive

        @contextlib.contextmanager
        def guard(*args, **kwargs):
            with real_guard(*args, **kwargs):
                events.append("guard entered")
                try:
                    yield
                finally:
                    events.append("guard left")

        def probe():
            return {
                "store lock free for others": another_thread_can_take(lock),
                "job start lock held": self.jobfiles.JOB_START_LOCK.locked(),
            }

        manager = FakeManager(events, probe, error)
        patches = {"VPN_STORE_LOCK": lock, "vpn_manager": lambda: manager}
        with contextlib.ExitStack() as stack:
            if record_guard:
                stack.enter_context(mock.patch.object(coordinator, "exclusive", guard))
            if record_check:
                stack.enter_context(mock.patch.object(coordinator, "ensure_idle",
                                                      lambda *args, **kwargs: events.append("availability checked")))
            stack.enter_context(self.patched(**patches))
            yield events, manager

    def hold_job_start_lock(self):
        self.assertTrue(self.jobfiles.JOB_START_LOCK.acquire(blocking=False))
        self.addCleanup(self.jobfiles.JOB_START_LOCK.release)

    def test_store_operations_run_guard_then_check_then_locked_call(self):
        for name, (args, method) in STORE_OPERATIONS.items():
            with self.subTest(operation=name), self.journal() as (events, manager):
                result = getattr(self.vpn, name)(*args)
                call = f"manager.{method}({', '.join(map(repr, args))})"
                self.assertEqual(
                    events,
                    ["availability checked", "guard entered", "store lock taken", call, "store lock released", "guard left"],
                )
                self.assertEqual(result, {"ok": True, "operation": method, "args": list(args)})
                # Inside the call the store lock is held against other threads and a job start is excluded.
                self.assertEqual(manager.probed, [{"store lock free for others": False, "job start lock held": True}])
                self.assertFalse(self.jobfiles.JOB_START_LOCK.locked())
                self.assertTrue(another_thread_can_take(self.vpn.VPN_STORE_LOCK))

    def test_store_operation_refused_while_a_job_starts(self):
        self.hold_job_start_lock()
        for name, (args, _method) in STORE_OPERATIONS.items():
            with self.subTest(operation=name), self.journal(record_guard=False) as (events, manager):
                with self.assertRaises(RuntimeError) as caught:
                    getattr(self.vpn, name)(*args)
                self.assertEqual(str(caught.exception), JOB_STARTING)
                self.assertIn("уже запускается", str(caught.exception))
                self.assertEqual(events, [])
                self.assertEqual(manager.calls, [])

    def test_store_operation_refused_while_another_job_runs(self):
        cases = (
            ("tuner_active", "маршруты нельзя менять во время подбора"),
            ("diagnostic_active", "маршруты нельзя менять во время диагностики"),
            ("route_active", ROUTE_RUNNING),
        )
        for name, (args, _method) in STORE_OPERATIONS.items():
            for active, message in cases:
                with self.subTest(operation=name, active=active):
                    with self.journal(record_check=False) as (events, manager), self.patched(**{active: lambda: True}):
                        with self.assertRaises(RuntimeError) as caught:
                            getattr(self.vpn, name)(*args)
                        self.assertEqual(str(caught.exception), message)
                        self.assertEqual(events, [])  # refusal happens before exclusive yields
                        self.assertEqual(manager.calls, [])
                        self.assertFalse(self.jobfiles.JOB_START_LOCK.locked())

    def test_manager_error_reaches_the_caller_and_frees_both_locks(self):
        for name, (args, _method) in STORE_OPERATIONS.items():
            error = ValueError("VPN-нода не найдена")
            with self.subTest(operation=name), self.journal(error=error) as (events, manager):
                with self.assertRaises(ValueError) as caught:
                    getattr(self.vpn, name)(*args)
                self.assertIs(caught.exception, error)
                self.assertEqual(events[-2:], ["store lock released", "guard left"])
                self.assertFalse(self.jobfiles.JOB_START_LOCK.locked())
                self.assertTrue(another_thread_can_take(self.vpn.VPN_STORE_LOCK))

    def test_nodes_status_holds_the_store_lock(self):
        with self.journal() as (events, manager):
            status = self.vpn.nodes_status()
            self.assertEqual(events, ["store lock taken", "manager.status()", "store lock released"])
            self.assertEqual(status, {"ok": True, "operation": "status", "args": []})
            self.assertEqual(manager.probed[0]["store lock free for others"], False)
            self.assertTrue(another_thread_can_take(self.vpn.VPN_STORE_LOCK))

    def test_nodes_status_is_served_while_a_job_starts_or_runs(self):
        self.hold_job_start_lock()
        with self.journal(record_guard=False, record_check=False) as (events, manager), self.patched(
            route_active=lambda: True
        ):
            self.assertEqual(self.vpn.nodes_status()["operation"], "status")
            self.assertEqual(events, ["store lock taken", "manager.status()", "store lock released"])

    def test_nodes_status_error_reaches_the_caller_and_frees_the_lock(self):
        error = OSError("реестр нод недоступен")
        with self.journal(error=error):
            with self.assertRaises(OSError) as caught:
                self.vpn.nodes_status()
            self.assertIs(caught.exception, error)
            self.assertTrue(another_thread_can_take(self.vpn.VPN_STORE_LOCK))


class VpnHandlerTests(panel_harness.PanelTestCase):
    """The /api/vpn-nodes routes that go through the facade: bodies, arguments and the 200/400/409/500 mapping."""

    ns_name = "panel_vpn_handler_test"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        def forbidden(*_args, **_kwargs):
            raise AssertionError("router command must not run in this test")

        handler = cls.ns["Handler"]
        quiet = mock.patch.object(handler, "log_message", lambda *_args: None)
        quiet.start()
        cls.addClassCleanup(quiet.stop)
        cls.server = cls.ns["ThreadingHTTPServer"](("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        cls.patch_class(BIND_HOST="127.0.0.1", PORT=cls.port, run_command=forbidden)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.vpn = self.ns.module("vpn")
        self.jobfiles = self.ns.module("jobfiles")
        self.manager = FakeManager(probe=self.probe)
        self.patch(vpn_manager=lambda: self.manager)

    def probe(self):
        return {
            "store lock free for others": another_thread_can_take(self.vpn.VPN_STORE_LOCK),
            "job start lock held": self.jobfiles.JOB_START_LOCK.locked(),
        }

    def request(self, method, path, payload=None):
        headers = {}
        body = None
        if method == "POST":
            headers = {"X-XKeen-Control": "1", "Content-Type": "application/json"}
            body = json.dumps({} if payload is None else payload).encode()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read()
        finally:
            connection.close()
        self.assertEqual(response.getheader("Content-Type"), JSON_TYPE)
        return response.status, json.loads(data)

    def store_routes(self):
        """(path, body, manager call) of the four POST routes that run a store operation."""
        return (
            ("/api/vpn-nodes/delete/vless_2", None, ("remove", ("vless_2",))),
            ("/api/vpn-nodes/sync-current", None, ("sync_current", ())),
        )

    def test_store_routes_pass_the_request_to_the_manager(self):
        for path, body, call in self.store_routes():
            with self.subTest(path=path):
                self.manager.calls.clear()
                self.manager.probed.clear()
                status, answer = self.request("POST", path, body)
                self.assertEqual(status, 200)
                self.assertEqual(answer, {"ok": True, "operation": call[0], "args": list(call[1])})
                self.assertEqual(self.manager.calls, [call])
                # The route reaches the manager through the facade: a job start is excluded, the store is locked.
                self.assertEqual(self.manager.probed, [{"store lock free for others": False, "job start lock held": True}])

    def test_store_routes_answer_409_while_a_job_starts(self):
        self.assertTrue(self.jobfiles.JOB_START_LOCK.acquire(blocking=False))
        self.addCleanup(self.jobfiles.JOB_START_LOCK.release)
        for path, body, _call in self.store_routes():
            with self.subTest(path=path):
                self.assertEqual(self.request("POST", path, body), (409, {"ok": False, "error": JOB_STARTING}))
        self.assertEqual(self.manager.calls, [])

    def test_store_routes_answer_409_while_a_route_job_runs(self):
        self.patch(route_active=lambda: True)
        for path, body, _call in self.store_routes():
            with self.subTest(path=path):
                self.assertEqual(self.request("POST", path, body), (409, {"ok": False, "error": ROUTE_RUNNING}))
        self.assertEqual(self.manager.calls, [])

    def test_manager_errors_map_to_400_and_409(self):
        cases = (
            (ValueError("VPN-нода не найдена"), 400),
            (OSError("реестр нод недоступен"), 400),
            (TypeError("неверный тип"), 400),
            (json.JSONDecodeError("битый реестр", "{", 0), 400),
            (RuntimeError("менеджер занят"), 409),
        )
        for error, status in cases:
            self.manager.error = error
            for path, body, _call in self.store_routes():
                with self.subTest(error=type(error).__name__, path=path):
                    self.assertEqual(self.request("POST", path, body), (status, {"ok": False, "error": str(error)}))

    def test_add_with_a_bad_body_is_refused_before_the_manager(self):
        bodies = ([1], {"name": "vless_2"}, {"name": "vless_2", "source": 5}, {"name": "n", "source": "x" * 32769})
        for body in bodies:
            with self.subTest(body=str(body)[:40]):
                status, answer = self.request("POST", "/api/vpn-nodes/add", body)
                self.assertEqual((status, answer["ok"]), (400, False))
                self.assertEqual(answer["error"], "ожидаются имя и ссылка/JSON outbound до 32 КиБ")
        self.assertEqual(self.manager.calls, [])

    def test_listing_answers_the_manager_status(self):
        status, answer = self.request("GET", "/api/vpn-nodes")
        self.assertEqual((status, answer), (200, {"ok": True, "operation": "status", "args": []}))
        self.assertEqual(self.manager.probed, [{"store lock free for others": False, "job start lock held": False}])

    def test_listing_is_served_while_a_job_starts_or_runs(self):
        self.assertTrue(self.jobfiles.JOB_START_LOCK.acquire(blocking=False))
        self.addCleanup(self.jobfiles.JOB_START_LOCK.release)
        self.patch(route_active=lambda: True)
        self.assertEqual(self.request("GET", "/api/vpn-nodes")[0], 200)

    def test_listing_errors_answer_500(self):
        errors = (
            OSError("реестр нод недоступен"),
            RuntimeError("менеджер занят"),
            ValueError("битый реестр"),
            TypeError("неверный тип"),
            json.JSONDecodeError("битый реестр", "{", 0),
        )
        for error in errors:
            self.manager.error = error
            with self.subTest(error=type(error).__name__):
                self.assertEqual(self.request("GET", "/api/vpn-nodes"), (500, {"ok": False, "error": str(error)}))


if __name__ == "__main__":
    unittest.main()
