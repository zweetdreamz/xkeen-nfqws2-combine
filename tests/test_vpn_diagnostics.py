"""Detailed VPN probe failures expose controlled diagnostics, never raw secrets."""
import subprocess
import time
import unittest
from unittest import mock

from kdn import vpn_diagnostics
from tools.router import vpn_node_manager as nodes
from test_vpn_node_manager import outbound, UUID


class DiagnosticsTests(unittest.TestCase):
    def check(self, *, curl_code=97, http='000', xray_text='', config_code=0, timeout=False, oversized=False):
        manager = nodes.VpnNodeManager()
        selected = outbound()
        selected['streamSettings'] = {'network': 'ws', 'security': 'tls',
            'tlsSettings': {'serverName': 'vpn.example'},
            'wsSettings': {'path': '/?token=SECRET_TOKEN'}}
        process = mock.Mock(pid=99999999)
        process.poll.return_value = None

        def run(argv, **kwargs):
            if argv[0] == manager.curl:
                if oversized:
                    time.sleep(0.25)
                if timeout:
                    raise subprocess.TimeoutExpired(argv, 10, stderr='SECRET_PASSWORD')
                return mock.Mock(returncode=curl_code, stdout=http+'|0.125000',
                                 stderr='curl: wss://SECRET_PASSWORD@vpn.example/?token=SECRET_TOKEN')
            if config_code:
                kwargs['stderr'].write(('failed to parse SECRET_PASSWORD '+UUID).encode())
            return mock.Mock(returncode=config_code)

        def launch(*_args, **kwargs):
            if oversized:
                kwargs['stderr'].write(b'X' * (129 * 1024))
            kwargs['stderr'].write(xray_text.encode())
            kwargs['stderr'].flush()
            return process

        with mock.patch.object(manager, '_require_supported_xkeen'), \
                mock.patch.object(nodes.subprocess, 'run', side_effect=run) as calls, \
                mock.patch.object(nodes.subprocess, 'Popen', side_effect=launch) as popen, \
                mock.patch.object(nodes.socket, 'socket') as sock:
            sock.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 1234)
            sock.return_value.__enter__.return_value.connect_ex.return_value = 0
            health = manager.probe(selected)
        for secret in ('SECRET_PASSWORD', 'SECRET_TOKEN', UUID):
            self.assertNotIn(secret, health['log'])
        self.assertLessEqual(len(health['log'].encode('utf-8')), 8192)
        self.assertGreaterEqual(health['total_ms'], 0)
        return health, calls, popen, process

    def test_ws_failure_has_stage_curl_http_and_safe_upgrade_reason(self):
        health, _calls, _popen, process = self.check(xray_text=(
            'dial wss://SECRET_PASSWORD@vpn.example/?token=SECRET_TOKEN '+UUID+
            ' > websocket: bad handshake > HTTP/1.1 403 Forbidden\n'))
        self.assertFalse(health['ok'])
        self.assertEqual(health['curl_code'], 97)
        for part in ('vless / ws / tls', '[config]', '[startup]', '[https]', 'curl=97',
                     'HTTP 000', 'WS: сервер отклонил WebSocket Upgrade', '403', '[result] FAIL'):
            self.assertIn(part, health['log'])
        process.terminate.assert_called_once()

    def test_http_rejection_is_distinct_from_connection_failure(self):
        health, _calls, _popen, _process = self.check(curl_code=0, http='403')
        self.assertEqual(health['http_code'], 403)
        self.assertIn('HTTP 403 вместо 204', health['detail'])
        self.assertIn('curl=0', health['log'])
        self.assertNotIn('сервер отклонил WebSocket', health['log'])

    def test_bad_config_does_not_start_daemon_or_curl(self):
        health, calls, popen, _process = self.check(config_code=1)
        self.assertFalse(health['ok'])
        self.assertIn('exit=1', health['log'])
        self.assertIn('ошибка разбора конфигурации', health['log'])
        self.assertEqual(calls.call_count, 1)
        popen.assert_not_called()

    def test_timeout_keeps_stage_and_cleans_up(self):
        health, _calls, _popen, process = self.check(timeout=True)
        self.assertIn('curl не завершился за 10 с', health['log'])
        self.assertIn('таймаут', health['detail'])
        process.terminate.assert_called_once()

    def test_tls_and_dns_classification_never_echoes_original_text(self):
        issues = vpn_diagnostics.xray_issues('certificate is valid for SECRET_TOKEN, not SECRET_PASSWORD; no such host')
        self.assertEqual(issues, ['TLS: имя сертификата не совпадает с SNI', 'DNS: имя сервера не разрешилось'])
        self.assertEqual(vpn_diagnostics.xray_issues('unrecognized SECRET_TOKEN'), [])
        self.assertIsInstance(vpn_diagnostics.curl_reason(999), str)

    def test_log_size_guard_stops_only_its_probe(self):
        health, _calls, _popen, process = self.check(oversized=True)
        self.assertFalse(health['ok'])
        self.assertIn('128 KiB', health['detail'])
        process.kill.assert_called_once()

    def test_public_history_preserves_bounded_diagnostics(self):
        manager = nodes.VpnNodeManager()
        value = manager._public_node('n1', {'outbound': outbound(),
                'health': {'ok': False, 'curl_code': 97, 'log': 'Ж' * 9000}}, '')
        self.assertEqual(value['health']['curl_code'], 97)
        self.assertLessEqual(len(value['health']['log'].encode('utf-8')), 8192)
