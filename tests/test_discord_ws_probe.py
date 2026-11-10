from __future__ import annotations

import base64
import hashlib
import importlib.util
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
import unittest
from unittest import mock

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("discord_ws_probe_test", ROOT / "tools/router/discord_ws_probe.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class WebSocketResponseTests(unittest.TestCase):
    def test_valid_upgrade_requires_matching_accept(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        accept = base64.b64encode(hashlib.sha1((key + PROBE.GUID).encode()).digest()).decode()
        header = ("HTTP/1.1 101 Switching Protocols\r\n"
                  "Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
                  f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode()
        self.assertTrue(PROBE.response_ok(header, key))
        self.assertFalse(PROBE.response_ok(header, "different-key"))
        self.assertFalse(PROBE.response_ok(header.replace(b"101", b"403", 1), key))


class GatewayStream:
    """An offline TLS peer; its accept value follows the actual client request."""

    def __init__(self, suffix=b"", padding=0):
        self.suffix = suffix
        self.padding = padding
        self.response = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        pass

    def sendall(self, request):
        key = request.split(b"Sec-WebSocket-Key: ", 1)[1].split(b"\r\n", 1)[0]
        accept = base64.b64encode(hashlib.sha1(key + PROBE.GUID.encode()).digest())
        self.response = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept
                         + b"\r\nX-Padding: " + b"a" * self.padding + b"\r\n\r\n" + self.suffix)

    def recv(self, maximum):
        part, self.response = self.response[:maximum], self.response[maximum:]
        return part


@pytest.mark.parametrize("suffix", [b"", b'\x81\x29{"op":10,"d":{"heartbeat_interval":41250}}'])
def test_probe_accepts_upgrade_with_coalesced_gateway_hello(suffix):
    stream = GatewayStream(suffix)
    with mock.patch.object(PROBE.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("192.0.2.1", 443))]), \
         mock.patch.object(PROBE.socket, "create_connection", return_value=stream), \
         mock.patch.object(PROBE.ssl, "create_default_context") as context:
        context.return_value.wrap_socket.return_value = stream
        assert PROBE.probe(6) == ("ok", "upgrade")


@pytest.mark.parametrize("padding", [8192, 10000])
def test_probe_rejects_upgrade_headers_over_budget(padding):
    stream = GatewayStream(padding=padding)
    with mock.patch.object(PROBE.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("192.0.2.1", 443))]), \
         mock.patch.object(PROBE.socket, "create_connection", return_value=stream), \
         mock.patch.object(PROBE.ssl, "create_default_context") as context:
        context.return_value.wrap_socket.return_value = stream
        assert PROBE.probe(6) == ("fail", "bad-upgrade")


@pytest.mark.parametrize("timeout", [4, 6, 20, 21, 30])
def test_manual_tuner_timeout_is_accepted_by_ws_helper(timeout, capsys):
    with mock.patch("sys.argv", ["discord_ws_probe.py", "--timeout", str(timeout)]), \
         mock.patch.object(PROBE, "probe", return_value=("ok", "upgrade")) as probe:
        assert PROBE.main() == 0
    probe.assert_called_once_with(float(timeout))
    assert capsys.readouterr().out.startswith("EVENT|WS|ok|")


@pytest.mark.parametrize("timeout", ["1", "31", "nan", "inf"])
def test_ws_helper_rejects_invalid_timeout_before_network(timeout):
    with mock.patch("sys.argv", ["discord_ws_probe.py", "--timeout", timeout]), \
         mock.patch.object(PROBE, "probe") as probe, pytest.raises(SystemExit) as error:
        PROBE.main()
    assert error.value.code == 2
    probe.assert_not_called()


@pytest.mark.parametrize("timeout", [21, 30])
def test_candidate_runner_does_not_treat_manual_timeout_as_fatal(timeout):
    tuner = runpy.run_path(str(ROOT / "tools/windows/zapret_tuner.py"))
    args = tuner["parser"]().parse_args(["discord-tcp", "--http-timeout", str(timeout)])
    tuner["validate_cli"](args)
    rendered = tuner["render_runner"](
        (ROOT / "tools/windows/router-candidate-runner.sh").read_text(),
        service=args.service, candidates=[], client_ip="127.0.0.1", voice_duration=25,
        http_timeout=args.http_timeout,
    )
    suite = "test_http_candidate() {" + rendered.split("test_http_candidate() {", 1)[1].split("\n}", 1)[0] + "\n}"
    # Execute the actual runner's suite and helper parser; only the network probe
    # is replaced, since neither a router nor Discord is involved in this test.
    offline_helper = ("import runpy,sys; scope=runpy.run_path(sys.argv.pop(1)); "
                      "scope['main'].__globals__['probe']=lambda timeout:('ok','upgrade'); "
                      "sys.exit(scope['main']())")
    script = "\n".join([
        "SERVICE=discord-tcp", "MIN_HTTP_SUCCESS=3",
        next(line for line in rendered.splitlines() if line.startswith("HTTP_TIMEOUT=")),
        "WS_PROBE=" + shlex.quote(str(ROOT / "tools/router/discord_ws_probe.py")),
        "emit() { printf '%s\\n' \"$1\"; }",
        "http_probe() { probe_connected=1; probe_rc=0; return 0; }",
        "python3() { " + shlex.quote(sys.executable) + " -c " + shlex.quote(offline_helper) + ' "$@"; }',
        suite, "test_http_candidate 1 verification 1",
    ])
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WS_RESULT|1|verification|1|ok|" in result.stdout
    assert "SUITE_RESULT|1|verification|1|pass|4|4" in result.stdout
    assert "FATAL" not in result.stdout


if __name__ == "__main__":
    unittest.main()
