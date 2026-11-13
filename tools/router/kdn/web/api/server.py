"""HTTP transport and bounded admission; no job, domain or router-engine work.

The connection cap protects threads waiting for input or admission. Work slots
are taken only around dispatch, after security and body parsing. A heavy
request waits for the shared heavy pool before taking a general work slot.
The entry wires this transport through api.table; domain work stays outside HTTP.
"""
import contextlib
import http.client
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

from kdn.common import errors
from kdn.common import logsetup
from kdn.web.api import router
from kdn.web.api import security
from kdn.web.infra import config as cfg


QUIET_POLLS = frozenset({"/api/metrics", "/api/status/fast", "/api/route/status", "/api/tuner/status", "/api/diagnostics/status", "/api/automation"})
HEAVY_SLOTS = threading.BoundedSemaphore(cfg.HEAVY_GET_SLOTS)


class _HeaderReader:
    """Budget bytes BEFORE HTTPMessage allocates them, including a total deadline.

    peek/read consume exactly one line; already-buffered body bytes stay in the
    original stream. Recheck the deadline even for a peer dripping one byte at a time.
    """

    def __init__(self, stream, connection):
        self.stream, self.connection = stream, connection
        self.remaining = cfg.HTTP_HEADER_BYTES
        self.lines = 0
        self.deadline = time.monotonic() + cfg.HTTP_HEADER_TIMEOUT

    def readline(self, size=-1):
        line = bytearray()
        maximum = min(size if size >= 0 else self.remaining + 1, self.remaining + 1)
        while len(line) < maximum:
            remaining_time = self.deadline - time.monotonic()
            if remaining_time <= 0:
                raise TimeoutError('HTTP header deadline exceeded')
            self.connection.settimeout(remaining_time)
            available = self.stream.peek(1)
            if not available:
                break
            take = min(len(available), maximum - len(line))
            end = available.find(b'\n', 0, take)
            if end >= 0:
                take = end + 1
            line.extend(self.stream.read(take))
            if end >= 0:
                break
        self.remaining -= len(line)
        if self.remaining < 0:
            raise http.client.LineTooLong('HTTP header block')
        if line not in (b'', b'\n', b'\r\n'):
            self.lines += 1
            if self.lines > cfg.HTTP_HEADER_LINES:
                raise http.client.HTTPException('too many header lines')
        return bytes(line)


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "XKeenControl/6.4"
    timeout = 30
    router = router.Router(())
    held = staticmethod(lambda name: None)
    response_started = False

    def send_response(self, code, message=None):
        self.response_started = True
        super().send_response(code, message)

    def log_message(self, format_string, *args):
        logsetup.panel_logger().info("%s %s", self.client_address[0], format_string % args)

    def log_request(self, code="-", size="-"):
        path, _query = router.split_target(getattr(self, "path", ""))
        if self.command == "GET" and path in QUIET_POLLS and str(code).isdigit() and int(code) < 400:
            return
        super().log_request(code, size)

    def send_answer(self, answer):
        self.send_response(answer.status)
        self.send_header("Content-Type", answer.content_type)
        self.send_header("Content-Length", str(len(answer.body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for name, value in answer.headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(answer.body)

    def guarded(self, callback):
        self.response_started = False
        try:
            callback()
        except Exception as exc:
            self.log_message("unhandled %s: %s", type(exc).__name__, exc)
            if not self.response_started:
                self.send_answer(router.error_response(
                    500, f"внутренняя ошибка панели: {type(exc).__name__}: {exc}"[:500]))

    def make_request(self):
        # HTTPMessage preserves duplicates. Lowercase + setdefault retains the
        # FIRST value even when duplicate spellings have different letter case.
        headers = {}
        for name, value in self.headers.raw_items():
            headers.setdefault(name.lower(), value)
        path, query = router.split_target(self.path)
        return router.Request(self.command, path, query=query, headers=headers, client=self.client_address[0])

    def read_json_body(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise errors.BadRequest("ожидается Content-Type: application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isascii() or not raw_length.isdigit():
            raise errors.BadRequest("некорректный Content-Length")
        # Avoid Python's integer conversion digit limit while keeping the size
        # error for an arbitrarily large, otherwise valid decimal header.
        normalized = raw_length.lstrip("0") or "0"
        if len(normalized) > len(str(cfg.MAX_REPORT_BYTES)) or int(normalized) > cfg.MAX_REPORT_BYTES:
            raise errors.BadRequest("JSON превышает 512 КиБ")
        raw = self.rfile.read(int(normalized))
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise errors.BadRequest(f"некорректный JSON: {exc}") from exc
        except RecursionError as exc:
            raise errors.BadRequest("некорректный JSON: слишком глубокая вложенность") from exc

    def do_GET(self):
        self.guarded(self.handle_get)

    def do_POST(self):
        self.guarded(self.handle_post)

    def handle_get(self):
        self.handle_panel_request()

    def handle_post(self):
        self.handle_panel_request()

    def handle_panel_request(self):
        request = self.make_request()
        refused = security.check_request(request, bind_host=cfg.BIND_HOST, port=cfg.PORT)
        if refused is not None:
            self.send_answer(refused)
            return
        if request.method == "POST":
            try:
                request = replace(request, body=self.read_json_body())
            except errors.BadRequest as exc:
                self.send_answer(router.error_response(400, str(exc)))
                return
        match = self.router.match(request.method, request.path)
        if request.method == "POST" and (match is None or match.route.automation_blocks):
            held = self.held("automation")
            if held:
                self.send_answer(router.error_response(409, held))
                return
        with self.work_slot(match):
            answer = self.router.dispatch(request, match)
        # Slow output clients also do not retain a work slot.
        self.send_answer(answer)

    @contextlib.contextmanager
    def work_slot(self, match):
        with contextlib.ExitStack() as stack:
            if match is not None and match.route.heavy:
                stack.enter_context(HEAVY_SLOTS)
            slots = getattr(self.server, "slots", None)
            if slots is not None:
                stack.enter_context(slots)
            yield

    def handle_one_request(self):
        """stdlib request cycle, with a separate, quiet request-line timeout."""
        reading_line = True
        try:
            self.connection.settimeout(getattr(self.server, "first_line_timeout", cfg.HTTP_FIRST_LINE_TIMEOUT))
            self.raw_requestline = self.rfile.readline(65537)
            reading_line = False
            self.connection.settimeout(self.timeout)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            original = self.rfile
            try:
                self.rfile = _HeaderReader(original, self.connection)
                parsed = self.parse_request()
            finally:
                self.rfile = original
                self.connection.settimeout(self.timeout)
            if not parsed:
                return
            method_name = "do_" + self.command
            if not hasattr(self, method_name):
                self.send_error(501, f"Unsupported method ({self.command!r})")
                return
            getattr(self, method_name)()
            self.wfile.flush()
        except TimeoutError as exc:
            if not reading_line:
                self.log_error("Request timed out: %r", exc)
            self.close_connection = True


def handler_for(route_table, held=None):
    """An isolated handler class bound to a table and an optional plain hold callback."""
    attributes = {"router": route_table}
    if held is not None:
        attributes["held"] = staticmethod(held)
    return type("Handler", (PanelHandler,), attributes)


class PanelServer(ThreadingHTTPServer):
    request_queue_size = 64
    daemon_threads = True

    def __init__(self, address, handler, *, max_threads, max_connections, first_line_timeout):
        if max_threads < 1 or max_connections < 1 or first_line_timeout <= 0:
            raise ValueError("HTTP limits must be positive")
        self.slots = threading.BoundedSemaphore(max_threads)
        self.max_connections = max_connections
        self.first_line_timeout = first_line_timeout
        self._connections_lock = threading.Lock()
        self._connections = 0
        super().__init__(address, handler)

    @property
    def connections(self):
        with self._connections_lock:
            return self._connections

    def process_request(self, request, client_address):
        with self._connections_lock:
            full = self._connections >= self.max_connections
            if not full:
                self._connections += 1
        if full:
            logsetup.panel_logger().info("%s connection limit reached", client_address[0])
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._connections_lock:
                self._connections -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._connections_lock:
                self._connections -= 1
