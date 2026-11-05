"""Service adapter never treats a failed init or stale daemon as success."""
from types import SimpleNamespace
import unittest
from unittest import mock

from kdn.engine import nfqws_service as service


class ServiceTests(unittest.TestCase):
    def test_rule_ports_are_compared_as_sets_per_interface(self):
        from engine_firewall import firewall_rules
        rules = firewall_rules(tcp='443,80')
        service.verify_rules(rules, 'eth3', '80,443', '50000-50100')
        for interface, tcp, udp in (('eth4', '80,443', '50000-50100'),
                                     ('eth3', '443', '50000-50100'),
                                     ('eth3', '80,443', '50000-65535')):
            with self.subTest(interface=interface, tcp=tcp, udp=udp), self.assertRaises(service.ServiceError):
                service.verify_rules(rules, interface, tcp, udp)
        with self.assertRaises(service.ServiceError):
            service.verify_rules(rules.replace('-A PREROUTING -j nfqws_pre', ''), 'eth3', '80,443', '50000-50100')

    def test_failed_init_aborts_before_runtime_verify(self):
        context = SimpleNamespace(paths=SimpleNamespace(nfqws_init='/fixture/init'), environ={})
        with mock.patch.object(service, 'pid', return_value=12), \
                mock.patch.object(service.os.path, 'isfile', return_value=True), \
                mock.patch.object(service.os, 'access', return_value=True), \
                mock.patch.object(service.nfqws_process, 'run', return_value=SimpleNamespace(
                    returncode=1, timed_out=False, output_limited=False)) as run, \
                mock.patch.object(service, 'verify') as verify:
            with self.assertRaises(service.ServiceError):
                service.restart(context)
            verify.assert_not_called()
            self.assertEqual(run.call_args.args[0], ['/fixture/init', 'restart'])
            self.assertEqual(run.call_args.kwargs['cwd'], '/')

    def test_stale_pid_is_not_accepted(self):
        with mock.patch.object(service, 'pid', return_value=12), mock.patch.object(service.time, 'sleep'):
            with self.assertRaises(service.ServiceError):
                service.verify(None, 12, attempts=2)

    def test_stopped_state_and_invalid_actions(self):
        with mock.patch.object(service, 'action') as action, mock.patch.object(service, 'pid', return_value=None):
            self.assertIsNone(service.restore_state(None, '0'))
            action.assert_called_once_with(None, 'stop')
        with self.assertRaises(service.ServiceError):
            service.restore_state(None, 'unknown')
        with self.assertRaises(ValueError):
            service.action(None, 'delete')
