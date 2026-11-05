"""Early header budgets: real loopback HTTP, never a router command."""
import json
import socket
import threading
import time
from unittest import TestCase, mock

from kdn.web.api import router, server
from kdn.web.infra import config


class HeaderLimitTests(TestCase):
    def setUp(self):
        self.calls = []
        calls = self.calls

        class Handler(server.PanelHandler):
            def log_message(self, *_args):
                pass

            def handle_get(self):
                calls.append('GET')
                self.send_answer(router.json_response(200, {'ok': True}))

            def handle_post(self):
                value = self.read_json_body()
                calls.append(value)
                self.send_answer(router.json_response(200, {'ok': True}))

        self.httpd = server.PanelServer(('127.0.0.1', 0), Handler,
            max_threads=1, max_connections=2, first_line_timeout=1)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
            kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def request(self, raw):
        with socket.create_connection(self.httpd.server_address, timeout=2) as connection:
            try:
                connection.sendall(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
            chunks = []
            while True:
                try:
                    chunk = connection.recv(65536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return b''.join(chunks)

    def test_large_header_is_rejected_before_domain_and_slots_are_reusable(self):
        response = self.request(b'GET / HTTP/1.0\r\nHost: local\r\nX-Pad: ' + b'x' * 40000 + b'\r\n\r\n')
        self.assertIn(b' 431 ', response.split(b'\r\n', 1)[0])
        self.assertEqual(self.calls, [])
        self.assertIn(b' 200 ', self.request(b'GET / HTTP/1.0\r\nHost: local\r\n\r\n').split(b'\r\n', 1)[0])

    def test_aggregate_size_not_only_individual_line_is_bounded(self):
        headers = b''.join(b'X-Pad: ' + b'x' * 1000 + b'\r\n' for _ in range(40))
        response = self.request(b'GET / HTTP/1.0\r\nHost: local\r\n' + headers + b'\r\n')
        self.assertIn(b' 431 ', response.split(b'\r\n', 1)[0])
        self.assertEqual(self.calls, [])

    def test_header_budget_does_not_consume_or_limit_json_body(self):
        value = {'text': 'x' * 65536}
        body = json.dumps(value).encode()
        head = (f'POST / HTTP/1.0\r\nHost: local\r\nContent-Type: application/json\r\n'
                f'Content-Length: {len(body)}\r\n\r\n').encode()
        self.assertIn(b' 200 ', self.request(head + body).split(b'\r\n', 1)[0])
        self.assertEqual(self.calls, [value])

    def test_exact_byte_budget_and_header_line_count(self):
        prefix = b'Host: local\r\nX-Pad: '
        block = prefix + b'x' * (128 - len(prefix) - 4) + b'\r\n\r\n'
        with mock.patch.object(config, 'HTTP_HEADER_BYTES', 128):
            self.assertEqual(len(block), 128)
            self.assertIn(b' 200 ', self.request(b'GET / HTTP/1.0\r\n' + block).split(b'\r\n', 1)[0])
            self.assertIn(b' 431 ', self.request(b'GET / HTTP/1.0\r\n' + b'X: \r\n' + block).split(b'\r\n', 1)[0])
        with mock.patch.object(config, 'HTTP_HEADER_LINES', 2):
            self.assertIn(b' 200 ', self.request(b'GET / HTTP/1.0\r\nHost: local\r\nX: 1\r\n\r\n').split(b'\r\n', 1)[0])
            self.assertIn(b' 431 ', self.request(b'GET / HTTP/1.0\r\nHost: local\r\nX: 1\r\nX: 2\r\n\r\n').split(b'\r\n', 1)[0])
        self.assertEqual(self.calls, ['GET', 'GET'])

    def test_slow_partial_header_has_a_total_deadline(self):
        with mock.patch.object(config, 'HTTP_HEADER_TIMEOUT', .3, create=True):
            began = time.monotonic()
            with socket.create_connection(self.httpd.server_address, timeout=1) as connection:
                connection.sendall(b'GET / HTTP/1.0\r\nHost: ')
                for _ in range(10):
                    try:
                        connection.sendall(b'x')
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    time.sleep(.05)
                try:
                    self.assertEqual(connection.recv(1024), b'')
                except ConnectionResetError:
                    pass
            self.assertLess(time.monotonic() - began, 1.5)
            self.assertEqual(self.calls, [])
