"""Real loopback HTTP tests of transport, security order and bounded admission.

No router commands: routes are small in-memory callbacks. Blocking callbacks
use events; all sockets, executor tasks and servers have bounded lifetimes.
"""
import concurrent.futures
import contextlib
from http import client
from http.server import ThreadingHTTPServer
import json
import socket
import threading
import time
from unittest import mock

import panel_harness


class ServerCase(panel_harness.PanelTestCase):
    modules = ("kdn.web.api.server",)

    def setUp(self):
        self.api = self.ns.module("kdn.web.api.server")
        self.routes = self.ns.module("kdn.web.api.router")
        self.cfg = self.ns.module("kdn.web.infra.config")
        self.logger = mock.Mock()
        patcher = mock.patch.object(self.api.logsetup, "panel_logger", return_value=self.logger)
        patcher.start()
        self.addCleanup(patcher.stop)

    def route(self, method="GET", path="/", handler=None, **options):
        return self.routes.Route(method, path, handler or (lambda r: self.routes.json_response(200, {"ok": True})),
                                 **options)

    @contextlib.contextmanager
    def serving(self, *routes, held=None, handler=None, **limits):
        handler = handler or self.api.handler_for(self.routes.Router(routes), held)
        server = (self.api.PanelServer(("127.0.0.1", 0), handler, **limits) if limits
                  else ThreadingHTTPServer(("127.0.0.1", 0), handler))
        with mock.patch.object(self.cfg, "BIND_HOST", "127.0.0.1"), \
                mock.patch.object(self.cfg, "PORT", server.server_port):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            thread.start()
            try:
                yield server
            finally:
                server.shutdown()
                server.server_close()
                thread.join(3)
                self.assertFalse(thread.is_alive())

    def request(self, server, method="GET", path="/", body=None, headers=None):
        conn = client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def post(self, server, **options):
        headers = {"X-XKeen-Control": "1", "Content-Type": "application/json", **options.pop("headers", {})}
        return self.request(server, "POST", headers=headers, body=options.pop("body", b"{}"), **options)

    def raw(self, server, content):
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=3) as conn:
            conn.sendall(content)
            conn.shutdown(socket.SHUT_WR)
            chunks = []
            while part := conn.recv(65536):
                chunks.append(part)
            return b"".join(chunks)

    def until(self, predicate):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("condition timed out")


class TransportTests(ServerCase):
    def test_get_host_and_post_security_order(self):
        with self.serving(self.route(), self.route("POST")) as server:
            self.assertEqual(self.request(server)[0], 200)
            self.assertEqual(self.request(server, headers={"Host": "evil"})[0], 403)
            with mock.patch.object(self.api.security, "private_client", return_value=False):
                status, _, body = self.post(server, headers={"Host": "evil", "X-XKeen-Control": "0"})
                self.assertEqual((status, json.loads(body)["error"]), (403, "client is outside LAN"))
            cases = [({"Host": "evil", "X-XKeen-Control": "0"}, "control header missing"),
                     ({"Host": "evil"}, "unexpected Host header"),
                     ({"Origin": "https://evil"}, "cross-origin request denied")]
            for headers, error in cases:
                with self.subTest(error=error):
                    status, _, body = self.post(server, headers=headers, body=b"not json")
                    self.assertEqual((status, json.loads(body)["error"]), (403, error))

    def test_duplicate_host_first_wins(self):
        with self.serving(self.route()) as server:
            for first, second, status in [("evil", "127.0.0.1", 403), ("127.0.0.1", "evil", 200)]:
                with self.subTest(first=first):
                    result = self.raw(server, f"GET / HTTP/1.0\r\nHost: {first}\r\nhOsT: {second}\r\n\r\n".encode())
                    self.assertIn(f" {status} ".encode(), result.split(b"\r\n")[0])

    def test_json_errors_content_type_and_size_boundary(self):
        with self.serving(self.route("POST")) as server:
            prefix = b"POST / HTTP/1.0\r\nHost: 127.0.0.1\r\nX-XKeen-Control: 1\r\n"
            cases = [(b"Content-Type: text/plain\r\n", b"", "ожидается Content-Type: application/json"),
                     (b"Content-Type: application/json\r\n", b"", "некорректный Content-Length"),
                     (b"Content-Type: application/json\r\nContent-Length: -1\r\n", b"", "некорректный Content-Length"),
                     (b"Content-Type: application/json\r\nContent-Length: 524289\r\n", b"", "JSON превышает 512 КиБ"),
                     (b"Content-Type: application/json\r\nContent-Length: 1\r\n", b"{", "некорректный JSON:"),
                     (b"Content-Type: application/json\r\nContent-Length: 1\r\n", b"\xff", "некорректный JSON:")]
            for headers, body, error in cases:
                with self.subTest(headers=headers, body=body):
                    reply = self.raw(server, prefix + headers + b"\r\n" + body)
                    self.assertIn(b" 400 ", reply.split(b"\r\n")[0])
                    self.assertTrue(json.loads(reply.split(b"\r\n\r\n", 1)[1])["error"].startswith(error))
            self.assertEqual(self.post(server, headers={"Content-Type": "Application/JSON; charset=UTF-8"})[0], 200)
            boundary = b'"' + b"x" * (self.cfg.MAX_REPORT_BYTES - 2) + b'"'
            self.assertEqual(self.post(server, body=boundary)[0], 200)
            # Python builds differ in the decoder depth limit. Exercise the
            # handler's RecursionError path deterministically, not by risking
            # the interpreter's C stack with an enormous nested document.
            with mock.patch.object(self.api.json, "loads", side_effect=RecursionError):
                status, _, body = self.post(server)
            self.assertEqual((status, json.loads(body)["error"]),
                             (400, "некорректный JSON: слишком глубокая вложенность"))

    def test_routes_and_automation_hold(self):
        with self.serving(self.route(), self.route("POST", "/free", automation_blocks=False),
                          held=lambda name: "busy schedule") as server:
            self.assertEqual(self.request(server)[0], 200)
            self.assertEqual(json.loads(self.request(server, path="/missing")[2])["error"], "unknown endpoint")
            self.assertEqual(self.post(server, path="/missing")[0], 409)
            self.assertEqual(self.post(server, path="/free")[0], 200)
        with self.serving() as server:
            self.assertEqual(json.loads(self.post(server, path="/missing")[2])["error"], "unknown action")

    def test_errors_response_headers_and_logging(self):
        def failing(request):
            raise LookupError("broken")

        routes = [self.route(path="/fail", handler=failing, errors=()),
                  self.route(path="/mapped", handler=failing, errors=((LookupError, 418),)),
                  self.route(path="/text", handler=lambda r: self.routes.text_response(200, "hello", "text/plain")),
                  self.route(path="/download", handler=lambda r: self.routes.Response(
                      200, b"report", "text/plain", {"Content-Disposition": 'attachment; filename="report.txt"'})),
                  self.route(path="/api/route/status")]
        with self.serving(*routes) as server:
            for path, code in [("/fail", 500), ("/mapped", 418), ("/text", 200), ("/download", 200)]:
                with self.subTest(path=path):
                    status, headers, body = self.request(server, path=path)
                    self.assertEqual(status, code)
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                    self.assertEqual(headers["X-Frame-Options"], "DENY")
                    self.assertEqual(int(headers["Content-Length"]), len(body))
                    if path == "/fail":
                        self.assertEqual(json.loads(body)["error"], "внутренняя ошибка панели: LookupError: broken")
                    if path == "/download":
                        self.assertIn("attachment", headers["Content-Disposition"])
            self.logger.reset_mock()
            self.request(server, path="/api/route/status?job_id=1")
            self.logger.info.assert_not_called()
            self.request(server, path="/api/status")
            self.assertIn("GET /api/status", str(self.logger.info.call_args))
            self.logger.reset_mock()
            self.request(server, path="/api/route/status", headers={"Host": "evil"})
            self.logger.info.assert_called()

    def test_no_second_response_after_started_response(self):
        api = self.api

        class Partial(api.PanelHandler):
            def handle_get(self):
                self.send_response(200)
                self.end_headers()
                raise RuntimeError("after headers")

        with self.serving(handler=Partial) as server:
            result = self.raw(server, b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            self.assertEqual(result.count(b"HTTP/1.0"), 1)
            self.assertNotIn(b"500", result)

    def test_socket_timeout_and_work_slot_wrap_only_dispatch(self):
        self.assertEqual(self.api.PanelHandler.timeout, 30)
        entered = []
        api = self.api
        route = self.route("POST", handler=lambda r: (entered.append("dispatch") or self.routes.json_response(200, {})))

        class Observed(api.PanelHandler):
            router = self.routes.Router((route,))

            def read_json_body(self):
                entered.append("body")
                return super().read_json_body()

            @contextlib.contextmanager
            def work_slot(self, match):
                entered.append("enter")
                yield
                entered.append("exit")

        with self.serving(handler=Observed) as server:
            self.assertEqual(self.post(server)[0], 200)
        self.assertEqual(entered, ["body", "enter", "dispatch", "exit"])


class AdmissionTests(ServerCase):
    LIMITS = {"max_threads": 2, "max_connections": 64, "first_line_timeout": 1}

    def test_active_handler_limit_and_queued_request(self):
        running = peak = 0
        lock = threading.Lock()
        entered, release = threading.Event(), threading.Event()

        def slow(request):
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
                if running == 3:
                    entered.set()
            release.wait(3)
            with lock:
                running -= 1
            return self.routes.json_response(200, {})

        with self.serving(self.route(handler=slow), **{**self.LIMITS, "max_threads": 3}) as server:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(self.request, server) for _ in range(8)]
                self.assertTrue(entered.wait(2))
                self.assertFalse(any(f.done() for f in futures))
                release.set()
                self.assertTrue(all(f.result(timeout=4)[0] == 200 for f in futures))
            self.assertEqual(peak, 3)

    def test_idle_connections_and_slow_body_do_not_take_work_slots(self):
        with self.serving(self.route(), self.route("POST"), **{**self.LIMITS, "max_threads": 1}) as server:
            with contextlib.ExitStack() as stack:
                for _ in range(20):
                    stack.enter_context(socket.create_connection(("127.0.0.1", server.server_port), timeout=3))
                slow = stack.enter_context(socket.create_connection(("127.0.0.1", server.server_port), timeout=3))
                slow.sendall(b"POST / HTTP/1.0\r\nHost: 127.0.0.1\r\nX-XKeen-Control: 1\r\n"
                             b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{")
                self.assertEqual(self.request(server)[0], 200)
                slow.sendall(b"}")
                self.assertIn(b" 200 ", slow.recv(4096))

    def test_idle_timeout_is_quiet_and_failed_thread_start_returns_connection_budget(self):
        with self.serving(self.route(), **{**self.LIMITS, "first_line_timeout": 0.1}) as server:
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=3) as idle:
                self.assertEqual(idle.recv(1), b"")
            self.until(lambda: server.connections == 0)
            self.logger.info.assert_not_called()
            left, right = socket.socketpair()
            try:
                with mock.patch.object(self.api.threading.Thread, "start", side_effect=RuntimeError("no threads")):
                    with self.assertRaisesRegex(RuntimeError, "no threads"):
                        server.process_request(left, ("127.0.0.1", 0))
                self.assertEqual(server.connections, 0)
            finally:
                left.close()
                right.close()

    def test_first_line_timeout_and_connection_cap(self):
        limits = {**self.LIMITS, "max_connections": 4, "first_line_timeout": 0.5}
        with self.serving(self.route(), **limits) as server:
            with contextlib.ExitStack() as stack:
                sockets = [stack.enter_context(socket.create_connection(("127.0.0.1", server.server_port), timeout=3))
                           for _ in range(4)]
                self.until(lambda: server.connections == 4)
                with socket.create_connection(("127.0.0.1", server.server_port), timeout=3) as extra:
                    self.assertEqual(extra.recv(1), b"")
                for conn in sockets:
                    self.assertEqual(conn.recv(1), b"")
            self.until(lambda: server.connections == 0)
            self.assertEqual(self.request(server)[0], 200)

    def test_heavy_waiter_holds_no_general_slot_and_error_returns_slots(self):
        entered, release = threading.Event(), threading.Event()
        waiting = threading.Event()
        running = peak = 0
        lock = threading.Lock()

        class HeavyPool:
            def __init__(self):
                self.semaphore = threading.BoundedSemaphore(1)
                self.calls = 0

            def __enter__(self):
                with lock:
                    self.calls += 1
                    if self.calls == 2:
                        waiting.set()
                self.semaphore.acquire()

            def __exit__(self, *args):
                self.semaphore.release()

        def slow(request):
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            entered.set()
            release.wait(3)
            with lock:
                running -= 1
            return self.routes.json_response(200, {})

        def fail(request):
            raise RuntimeError("failure")

        with mock.patch.object(self.api, "HEAVY_SLOTS", HeavyPool()), \
                self.serving(self.route(path="/heavy", handler=slow, heavy=True), self.route(),
                             self.route(path="/fail", handler=fail, heavy=True, errors=()), **self.LIMITS) as server:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.request, server, path="/heavy")
                self.assertTrue(entered.wait(2))
                second = pool.submit(self.request, server, path="/heavy")
                self.assertTrue(waiting.wait(2))
                began = time.monotonic()
                self.assertEqual(self.request(server)[0], 200)
                self.assertLess(time.monotonic() - began, 1)
                release.set()
                self.assertEqual(first.result(timeout=4)[0], 200)
                self.assertEqual(second.result(timeout=4)[0], 200)
                self.assertEqual(peak, 1)
            self.assertEqual(self.request(server, path="/fail")[0], 500)
            self.assertEqual(self.request(server, path="/heavy")[0], 200)

    def test_shutdown_returns_with_busy_slots_and_idle_connections(self):
        entered, release = threading.Event(), threading.Event()

        def slow(request):
            entered.set()
            release.wait(3)
            return self.routes.json_response(200, {})

        with self.serving(self.route(handler=slow), **{**self.LIMITS, "max_threads": 1}) as server:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool, \
                    socket.create_connection(("127.0.0.1", server.server_port), timeout=3):
                first = pool.submit(self.request, server)
                self.assertTrue(entered.wait(2))
                second = pool.submit(self.request, server)
                self.until(lambda: server.connections >= 3)
                began = time.monotonic()
                server.shutdown()
                server.server_close()
                self.assertLess(time.monotonic() - began, 1)
                release.set()
                self.assertEqual(first.result(timeout=4)[0], 200)
                self.assertEqual(second.result(timeout=4)[0], 200)
