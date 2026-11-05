"""Real native CLI transaction on a disposable router, not just mocked Python calls.

Only loopback RCI in Docker, inert daemon stand-ins and pinned nfqws Lua init.
No real router, proxy traffic, packet interception or host firewall changes.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

import engine_fixture


class NativeApplyCliTests(unittest.TestCase):
    def test_full_cli_success_and_failed_restart_restore_files_and_runtime(self):
        runtime = Path(os.environ.get('NFQWS_TEST_RUNTIME', '/var/cache/kdn/nfqws2-blobs/runtime'))
        if not (runtime / 'nfqws2').is_file():
            self.skipTest('run in the Docker image with pinned nfqws runtime')
        class Rci(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                authorized = self.path == '/rci/show/ip/policy' and self.headers.get('X-Ndma-Tkn') == 'fixture-rci'
                self.send_response(200 if authorized else 403)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'[]')
        server = HTTPServer(('127.0.0.1', 79), Rci)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = engine_fixture.make_root(Path(temporary.name) / 'fixture')
        env = dict(fixture.env, KDN_ENGINE='python', KD_TEST_XRAY_DAEMON='1',
                   KD_TEST_NFQWS2_BIN=str(runtime / 'nfqws2'), KD_TEST_NFQWS2_LUA_SRC=str(runtime))
        fixture.set_init('pbr_strict', 'off')
        fixture.write('/opt/etc/xkeen/xkeen.json', '{"xkeen":{"rci_token":"fixture-rci"}}')
        fixture.write('/opt/etc/xray/configs/03_inbounds.json', json.dumps({'inbounds': [{
            'tag': 'not-a-fixed-name', 'protocol': 'dokodemo-door',
            'settings': {'followRedirect': True, 'allowedNetwork': 'tcp,udp'},
            'streamSettings': {'sockopt': {'tproxy': 'tproxy'}}}]}))
        init = fixture.path('/opt/etc/init.d/S05xkeen')
        data = init.read_text().replace('printf \'xkeen-init:',
            'if [ "${1:-}" = restart ] && [ -f "$KD_TEST_ROOT/native-restart-fail" ]; then exit 23; fi\nprintf \'xkeen-init:')
        init.write_text(data)
        init.chmod(0o700)
        # All required dependencies are present; wget-nossl is absent. No package mutation is needed.
        opkg = fixture.mock_bin / 'opkg'
        opkg.write_text('''#!/bin/sh
case "$1" in
  status)
    case "$2" in wget-nossl) exit 0 ;; esac
    printf 'Package: %s\\nVersion: 2.1\\nStatus: install user installed\\n' "$2"
    ;;
  list-installed) echo 'nfqws2-keenetic - 2.1' ;;
  *) echo unexpected-package-mutation >&2; exit 1 ;;
esac
''')
        opkg.chmod(0o700)
        def stop(logical):
            path = fixture.path(logical)
            if path.exists():
                subprocess.run([str(path), 'stop'], env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20, check=False)
        self.addCleanup(stop, '/opt/etc/init.d/S05xkeen')
        self.addCleanup(stop, '/opt/etc/init.d/S51nfqws2')
        subprocess.run([str(init), 'start', 'on'], env=env, check=True, timeout=10)
        engine = engine_fixture.PROJECT / 'apply-discord-nfqws2.sh'
        args = ['sh', str(engine), '--apply', '--discord-route', 'direct', '--youtube-route', 'vless',
                '--wan-interface', 'fixture-wan', '--yes-router']
        first = subprocess.run(args, env=env, capture_output=True, text=True, timeout=90)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertTrue(first.stdout.rstrip().endswith('RESULT|ok'))
        config = fixture.path('/opt/etc/nfqws2/nfqws2.conf')
        routing = fixture.path('/opt/etc/xray/configs/05_routing.json')
        pointer = fixture.path('/opt/etc/keenetic-discord-nfqws2/latest-preapply.ptr')
        before = config.read_bytes(), routing.read_bytes(), pointer.read_bytes()
        fixture.write('/native-restart-fail', '1')
        args[args.index('vless')] = 'direct'
        failed = subprocess.run(args, env=env, capture_output=True, text=True, timeout=90)
        self.assertNotEqual(failed.returncode, 0)
        self.assertTrue(failed.stdout.rstrip().endswith('RESULT|rolled-back'), failed.stdout + failed.stderr)
        self.assertEqual((config.read_bytes(), routing.read_bytes(), pointer.read_bytes()), before)
        self.assertFalse(fixture.path('/opt/tmp/keenetic-discord-nfqws2.lock').exists())
