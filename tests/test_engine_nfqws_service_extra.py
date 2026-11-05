"""Additional adapter safety coverage without calling any real router service."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import nfqws_service as service


def rules(interface='eth3', queue='300'):
    from engine_firewall import firewall_rules
    return firewall_rules(interface=interface, queue=queue)


def completed(code=0, output='', timeout=False, limited=False):
    return SimpleNamespace(returncode=code, output=output, timed_out=timeout, output_limited=limited)


class ServiceActionExtraTests(unittest.TestCase):
    def test_stop_rc1_only_accepted_when_definitely_stopped_and_not_truncated(self):
        ctx = SimpleNamespace(paths=SimpleNamespace(nfqws_init='/fixture/init'), environ={})
        with mock.patch.object(service.os.path, 'isfile', return_value=True), \
                mock.patch.object(service.os, 'access', return_value=True), \
                mock.patch.object(service, 'pid', return_value=None), \
                mock.patch.object(service.nfqws_process, 'run', return_value=completed(1)) as run:
            self.assertIsNone(service.action(ctx, 'stop'))
            self.assertEqual(run.call_args.args[0], ['/fixture/init', 'stop'])
            self.assertEqual(run.call_args.kwargs['cwd'], '/')
            for result in (completed(1, timeout=True), completed(1, limited=True)):
                run.return_value = result
                with self.subTest(result=result), self.assertRaises(service.ServiceError):
                    service.action(ctx, 'stop')
            run.return_value = completed(1)
            with mock.patch.object(service, 'pid', return_value=42), self.assertRaises(service.ServiceError):
                service.action(ctx, 'stop')
            run.return_value = completed(0)
            with mock.patch.object(service, 'pid', return_value=42), self.assertRaises(service.ServiceError):
                service.action(ctx, 'stop')

    def test_missing_init_stop_only_and_restore_state_start_order(self):
        ctx = SimpleNamespace(paths=SimpleNamespace(nfqws_init='/missing/init'), environ={})
        with mock.patch.object(service, 'pid', return_value=None):
            self.assertIsNone(service.action(ctx, 'stop'))
            with self.assertRaises(service.ServiceError):
                service.action(ctx, 'start')
        calls = []
        with mock.patch.object(service, 'action', side_effect=lambda _ctx, verb: calls.append(verb)), \
                mock.patch.object(service, 'verify', return_value=77):
            self.assertEqual(service.restore_state(ctx, '1'), 77)
        self.assertEqual(calls, ['stop', 'start'])
        with mock.patch.object(service, 'action'), mock.patch.object(service, 'pid', return_value=77), \
                self.assertRaises(service.ServiceError):
            service.restore_state(ctx, '0')

    def test_successful_start_and_restart_verify_previous_pid(self):
        ctx = SimpleNamespace(paths=SimpleNamespace(nfqws_init='/fixture/init'), environ={})
        with mock.patch.object(service.os.path, 'isfile', return_value=True), \
                mock.patch.object(service.os, 'access', return_value=True), \
                mock.patch.object(service.nfqws_process, 'run', return_value=completed()):
            self.assertIsNone(service.action(ctx, 'start'))
        with mock.patch.object(service, 'pid', return_value=76), mock.patch.object(service, 'action') as action, \
                mock.patch.object(service, 'verify', return_value=77) as verify:
            self.assertEqual(service.restart(ctx), 77)
            action.assert_called_once_with(ctx, 'restart')
            verify.assert_called_once_with(ctx, 76)

    def test_pid_reuses_existing_probe_and_queue_guard(self):
        ctx = SimpleNamespace(paths=SimpleNamespace(test_root='/fixture'), environ={'PATH': '/fixture/bin'})
        with mock.patch.object(service.system, 'nfqws_service_pid', return_value=77) as lookup, \
                mock.patch.object(service.confvalues, 'nfqws_value', return_value='300') as value:
            self.assertEqual(service.pid(ctx), 77)
            args = lookup.call_args.args
            self.assertEqual(args[:3], (ctx.paths, ctx.environ, '/fixture'))
            self.assertEqual(args[3]('NFQUEUE_NUM'), '300')
            value.assert_called_once_with(ctx.paths, 'NFQUEUE_NUM')


class ServiceVerifyExtraTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc = Path(self.tmp.name)
        (self.proc / '77').mkdir()
        self.cmdline = self.proc / '77/cmdline'
        self.tokens = ['--filter-tcp=443', '--lua-desync=fake:blob=fake_default_tls']
        self.cmdline.write_bytes(('nfqws2\0--qnum=300\0' + '\0'.join(self.tokens) + '\0').encode())
        self.ctx = SimpleNamespace(paths=SimpleNamespace(nfqws_conf='/fixture/conf', nfqws_init='/fixture/init', test_root='/fixture'), environ={})
        self.values = {'TCP_PORTS': '443', 'UDP_PORTS': '50000:50100', 'ISP_INTERFACE': 'eth3',
                       'IPV6_ENABLED': '0', 'IPV6_INTERFACE': '', 'NFQUEUE_NUM': '300'}
        self.stack = __import__('contextlib').ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(service.system, 'PROC_ROOT', str(self.proc)))
        self.pid = self.stack.enter_context(mock.patch.object(service, 'pid', return_value=77))
        self.stack.enter_context(mock.patch.object(service.time, 'sleep'))
        self.stack.enter_context(mock.patch.object(service.compose, 'compose', return_value=SimpleNamespace(tokens=self.tokens)))
        self.stack.enter_context(mock.patch.object(service.confvalues, 'nfqws_value',
                                                  side_effect=lambda _paths, key: self.values.get(key, '')))
        self.run = self.stack.enter_context(mock.patch.object(service.nfqws_process, 'run', return_value=completed(output=rules())))

    def test_live_ordered_args_and_ipv6_interfaces_checked(self):
        self.assertEqual(service.verify(self.ctx, 76, attempts=1, delay=0), 77)
        self.assertEqual(self.run.call_args.args[0], ['iptables-save', '-t', 'mangle'])
        self.values.update({'IPV6_ENABLED': '1', 'IPV6_INTERFACE': 'ppp0'})
        self.run.side_effect = [completed(output=rules()), completed(output=rules('ppp0'))]
        self.assertEqual(service.verify(self.ctx, 76, attempts=1, delay=0), 77)
        self.assertEqual(self.run.call_args_list[-1].args[0], ['ip6tables-save', '-t', 'mangle'])

    def test_missing_or_reordered_profile_args_fail_before_firewall(self):
        for wanted in (self.tokens[:1], list(reversed(self.tokens)), ['--filter-tcp=80', *self.tokens]):
            self.cmdline.write_bytes(('nfqws2\0' + '\0'.join(wanted) + '\0').encode())
            with self.subTest(wanted=wanted), self.assertRaises(service.ServiceError):
                service.verify(self.ctx, 76, attempts=1, delay=0)
        self.run.assert_not_called()

    def test_excess_cmdline_and_missing_process_are_not_success(self):
        self.cmdline.write_bytes(b'x' * (1024 * 1024 + 1))
        with self.assertRaises(service.ServiceError):
            service.verify(self.ctx, 76, attempts=1, delay=0)
        self.cmdline.unlink()
        with self.assertRaises(service.ServiceError):
            service.verify(self.ctx, 76, attempts=1, delay=0)

    def test_wrong_queue_and_failed_rules_are_not_success(self):
        self.run.return_value = completed(output=rules(queue='999'))
        with self.assertRaises(service.ServiceError):
            service.verify(self.ctx, 76, attempts=1, delay=0)
        for result in (completed(1), completed(timeout=True), completed(limited=True)):
            self.run.return_value = result
            with self.subTest(result=result), self.assertRaises(service.ServiceError):
                service.verify(self.ctx, 76, attempts=1, delay=0)

    def test_no_wan_or_ipv6_missing_hook_fails(self):
        self.values['ISP_INTERFACE'] = ''
        with self.assertRaises(service.ServiceError):
            service.verify(self.ctx, 76, attempts=1, delay=0)
        self.values.update({'ISP_INTERFACE': 'eth3', 'IPV6_ENABLED': '1'})
        self.run.side_effect = [completed(output=rules()), completed(output='')]
        with self.assertRaises(service.ServiceError):
            service.verify(self.ctx, 76, attempts=1, delay=0)

    def test_pid_change_during_verification_refuses_stale_firewall(self):
        self.pid.side_effect = [77, None]
        with self.assertRaises(service.ServiceError):
            service.verify(self.ctx, 76, attempts=1, delay=0)
        self.run.assert_not_called()

    def test_daemon_disappearing_during_firewall_read_is_not_accepted(self):
        self.pid.side_effect = [77, 77, None]
        with self.assertRaises(service.ServiceError):
            service.verify(self.ctx, 76, attempts=1, delay=0)
        self.run.assert_called_once()

    def test_bad_ports_and_absent_hook_are_rejected(self):
        for text in ('0', '65536', '443-80', 'not-a-port'):
            with self.subTest(text=text), self.assertRaises(service.ServiceError):
                service._ports(text)
        with self.assertRaises(service.ServiceError):
            service.verify_rules(rules().replace('-A POSTROUTING -j nfqws_post', ''), 'eth3', '443', '50000:50100')
        with self.assertRaises(service.ServiceError):
            service.verify_rules(rules().replace('--dports 443', ''), 'eth3', '443', '50000:50100')

    def test_live_verifier_uses_effective_custom_processed_exception(self):
        custom = rules().replace('! --mark 0x40000000/0x40000000', '! --mark 0x1/0x3')
        with mock.patch.object(service.nfqws_marks, 'effective', return_value=(0x40000000, '1/3')) as effective:
            self.run.return_value = completed(output=custom)
            self.assertEqual(service.verify(self.ctx, 76, attempts=1, delay=0), 77)
            effective.assert_called_once_with(self.ctx.paths, self.ctx.environ)
            self.run.return_value = completed(output=rules())
            with self.assertRaises(service.ServiceError):
                service.verify(self.ctx, 76, attempts=1, delay=0)
            self.values.update({'IPV6_ENABLED': '1', 'IPV6_INTERFACE': 'eth4'})
            self.run.side_effect = [completed(output=custom), completed(output=rules('eth4'))]
            with self.assertRaises(service.ServiceError):
                service.verify(self.ctx, 76, attempts=1, delay=0)
