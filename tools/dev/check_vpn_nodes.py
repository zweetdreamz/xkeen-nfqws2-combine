#!/usr/bin/env python3
"""Pinned local-only P7 acceptance. Run inside Docker --network none.

python tools/dev/check_vpn_nodes.py /runtime/xray
No router configs, services, DAT files, downloaded scripts or external endpoints.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock
from urllib.parse import urlencode

from tools.router import vpn_node_manager as nodes


PIN = 'cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1'
UUID = '6f1c7e0a-6b1a-4c35-9a52-7a3f2b8e9c10'
PUBLIC = 'L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q'  # test-only fixed key


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main(binary):
    binary = str(Path(binary).resolve())
    assert hashlib.sha256(Path(binary).read_bytes()).hexdigest() == PIN, 'unreviewed Xray binary'
    version = subprocess.check_output([binary, 'version'], text=True, timeout=10)
    assert version.startswith('Xray 26.10.31'), 'unexpected Xray version'
    manager = nodes.VpnNodeManager(xray=binary, curl=shutil.which('curl'))
    count = 0
    with tempfile.TemporaryDirectory(prefix='kdn-vpn-accept-') as folder:
        root = Path(folder)
        # Explicit synthetic XKeen version boundary for this offline data-path
        # test, not a claim about a router's installed version.
        target = root / 'xkeen'
        target.write_text('#!/bin/sh\n[ "$1" = -v ] || exit 97\necho "XKeen 2.1.1 Stable"\n')
        target.chmod(0o700)
        manager.xkeen = str(target)
        for protocol in ('vless', 'trojan'):
            for network in ('tcp', 'raw', 'ws', 'grpc', 'xhttp', 'splithttp'):
                for security in ('tls', 'reality'):
                    if network == 'ws' and security == 'reality':
                        continue
                    query = dict(type=network, security=security, sni='example.com')
                    if security == 'reality':
                        query.update(password=PUBLIC, sid='abcd', fp='chrome')
                    else:
                        query.update(pcs='ab' * 32, vcn='example.com')
                    if network == 'ws':
                        query.update(host='example.com', path='/ws')
                    elif network == 'grpc':
                        query.update(serviceName='service', authority='example.com', mode='multi')
                    elif network in {'xhttp', 'splithttp'}:
                        query.update(host='example.com', path='/xhttp', mode='packet-up', extra='{"noSSEHeader":true}')
                    auth = UUID if protocol == 'vless' else 'test-password'
                    uri = f'{protocol}://{auth}@127.0.0.1:443?' + urlencode(query)
                    config = manager._probe_config(nodes.normalize_outbound(uri), free_port())
                    path = root / 'matrix.json'
                    nodes.atomic_json(path, config)
                    done = subprocess.run([binary, 'run', '-test', '-c', str(path)],
                                          capture_output=True, timeout=10, check=False)
                    assert done.returncode == 0, (protocol, network, security, done.stdout + done.stderr)
                    count += 1
        mask = {'udp': [{'type': 'udphop', 'settings': {'mode': 'intervalremote',
                'remotePorts': '10000-20000', 'interval': '30'}}], 'quicParams': {'congestion': 'bbr'}}
        for extra in ({}, {'finalmask': json.dumps(mask)}, {'pinSHA256': 'ab' * 32}):
            uri = 'hy2://test-password@127.0.0.1:443?' + urlencode({'sni': 'example.com', **extra})
            nodes.atomic_json(root / 'matrix.json', manager._probe_config(nodes.normalize_outbound(uri), free_port()))
            done = subprocess.run([binary, 'run', '-test', '-c', str(root / 'matrix.json')],
                                  capture_output=True, timeout=10, check=False)
            assert done.returncode == 0, done.stdout + done.stderr
            count += 1
        print('XRAY26_VPN_MATRIX_OK', count, flush=True)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
        calls = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                self.send_response(204 if self.path.endswith('/generate_204') else 200)
                self.end_headers()
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = free_port()
        config = {'log': {'loglevel': 'debug'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
            'protocol': 'vless', 'settings': {'clients': [{'id': UUID}], 'decryption': 'none'}}],
            # Pinned Xray26 blocks private targets by default. This allowance
            # belongs only to the disposable local test server, never router config.
            'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}]}
        nodes.atomic_json(root / 'server.json', config)
        server_log = (root / 'server.log').open('wb')
        process = subprocess.Popen([binary, 'run', '-c', str(root / 'server.json')],
                                   stdout=server_log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                with socket.socket() as connection:
                    if connection.connect_ex(('127.0.0.1', port)) == 0:
                        break
                time.sleep(0.05)
            else:
                raise AssertionError('local VLESS test server did not start')
            target = f'https://127.0.0.1:{server.server_port}'
            outbound = nodes.normalize_outbound(f'vless://{UUID}@127.0.0.1:{port}?type=tcp&security=none')
            original_run = subprocess.run
            def probe_run(argv, **kwargs):
                if argv[0] == manager.curl:
                    kwargs['stderr'] = subprocess.PIPE
                result = original_run(argv, **kwargs)
                if argv[0] == manager.curl and result.returncode:
                    print('LOCAL_TEST_CURL_ERROR', result.returncode, result.stderr, flush=True)
                return result
            with mock.patch.object(nodes, 'PROBE_URLS', (target + '/generate_204', target + '/trace')), \
                    mock.patch.dict(os.environ, {'CURL_CA_BUNDLE': str(cert), 'NO_PROXY': '*'}), \
                    mock.patch.object(nodes.subprocess, 'run', side_effect=probe_run):
                health = manager.probe(outbound)
                assert health['ok'], health
                assert calls == ['/generate_204', '/trace'], calls
                outbound['settings']['port'] = free_port()  # target still reachable directly
                health = manager.probe(outbound)
                assert not health['ok'], 'probe bypassed selected outbound through NO_PROXY'
                assert len(calls) == 2, 'failed node reached HTTPS target directly'
            print('LOCAL_VLESS_SOCKS_HTTPS_PROBE_OK (no external network)', flush=True)
        finally:
            process.terminate()
            process.wait(timeout=5)
            server_log.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    main(sys.argv[1])
