"""The mock server of the browser UI tests answers with the fields the page reads (tests/panel_contract.py).

tests/panel_mock_server.py must not drift from what the panel's Handler returns (tests/test_panel_endpoints.py
checks the Handler against the same contract), or the UI tests pass on answers the router never gives.
"""

from __future__ import annotations

import ast
import http.client
import json
from pathlib import Path
import re
import threading
import unittest
from unittest import mock

from panel_contract import BOOLEAN_FIELDS, FRONTEND_CONDITIONAL, FRONTEND_CONTRACT, all_fields, missing_fields
import panel_mock_server


# (function, local payload/alias, contract key). Keep this curated list small;
# state-dependent aliases describe nested objects rather than inventing fields
# on the enclosing API answer.
PAGE_READERS = (
    ('renderDnsMode','d','GET /api/dns'),
    ('renderNotifications','d','GET /api/notifications'),
    ('renderNotifications','item','GET /api/notifications#choices[]'),
    ("renderTuner", "d", "GET /api/tuner/status"),
    ("voiceSummary", "d", "GET /api/tuner/status"),
    ("renderDiagnostic", "d", "GET /api/diagnostics/status"),
    ("renderAutomation", "d", "GET /api/automation"),
    ("renderAutomation", "c", "GET /api/automation#config"),
    ("renderAutomation", "s", "GET /api/automation#state"),
    ("renderAutomation", "scenario", "GET /api/automation#config.services[]"),
    ("refreshHistory", "item", "GET /api/history#items[]"),
    ("refreshVersions", "v", "GET /api/profile-versions#versions[]"),
    ("refreshVpnNodes", "d", "GET /api/vpn-nodes"),
    ("refreshVpnNodes", "node", "GET /api/vpn-nodes#nodes[]"),
    ("renderUpdate", "d", "GET /api/updates"),
    ("refreshTunerSources", "d", "GET /api/tuner/sources"),
    ("renderPostChecks", "config", "GET /api/checks/config"),
    ("watchRouteJob", "result", "GET /api/route/result"),
    ("operation", "start", "POST /api/xkeen/<action>"),
    ("xkeenAction", "d", "GET /api/route/result"),
    ("applyImport", "d", "GET /api/route/result"),
    ("clearImport", "d", "GET /api/route/result"),
    ("rollbackImport", "d", "GET /api/route/result"),
    ("applyVersion", "d", "GET /api/route/result"),
    ("applyTunerResult", "d", "GET /api/route/result"),
    ("diagnoseVpnNode", "d", "GET /api/route/result"),
    ("checkVpnNode", "d", "POST /api/vpn-nodes/ping/<id>"),
    ("postChecksAfter", "d", "GET /api/route/result"),
)
JS_METHODS = frozenset({"length", "map", "forEach", "slice", "join", "filter", "some", "includes"})


def function_body(source, name):
    """Brace-balanced function body, ignoring quoted strings and comments."""
    found = re.search(r"\bfunction\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
    if not found:
        raise AssertionError(f"function {name} missing")
    start = found.end()
    depth, quote, escaped, comment = 1, "", False, ""
    i = start
    while i < len(source):
        char, pair = source[i], source[i:i + 2]
        if comment:
            if comment == "//" and char == "\n":
                comment = ""
            elif comment == "/*" and pair == "*/":
                comment = ""
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "\"'`":
            quote = char
        elif pair in ("//", "/*"):
            comment = pair
            i += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:i]
        i += 1
    raise AssertionError(f"unbalanced function {name}")


def page_fields(source, function, parameter):
    return set(re.findall(r"\b" + re.escape(parameter) + r"\.([A-Za-z_]\w*)", function_body(source, function))) - JS_METHODS


class PageReaderTests(unittest.TestCase):
    def test_every_field_the_page_reads_is_in_the_contract(self):
        source = (Path(__file__).resolve().parents[1] / "tools/router/kdn/web/assets/index.html").read_text(encoding="utf-8")
        self.assertLessEqual(len(PAGE_READERS), 28)  # plus Home DNS status reader
        for function, parameter, key in PAGE_READERS:
            with self.subTest(function=function, parameter=parameter):
                fields = page_fields(source, function, parameter)
                self.assertTrue(fields)
                self.assertEqual(fields - all_fields(key), set(), (key, fields - all_fields(key)))

    def test_removed_conditional_field_is_detected(self):
        source = (Path(__file__).resolve().parents[1] / "tools/router/kdn/web/assets/index.html").read_text(encoding="utf-8")
        key = "GET /api/tuner/status"
        reduced = {k: v for k, v in FRONTEND_CONDITIONAL[key].items() if k != "current_candidate"}
        with mock.patch.dict(FRONTEND_CONDITIONAL, {key: reduced}):
            self.assertIn("current_candidate", page_fields(source, "renderTuner", "d") - all_fields(key))

# The table of the task as it was given (a minimum): the module may split it (conditional fields) and extend it.
GIVEN_TABLE = {
    "*": {"ok"},
    "GET /api/status": {"discord_tcp_route", "discord_voice_route", "youtube_route", "telegram_route", "xkeen_runtime"},
    "GET /api/route/status": {"job_id", "active", "status", "stage", "stage_label", "progress", "operation", "service",
                              "output", "error"},
    "GET /api/history": {"items"},
    "GET /api/history#items[]": {"operation", "created_utc", "status", "before_routes", "service", "snapshot",
                                 "rollback_available", "job_id"},
    "GET /api/vpn-nodes": {"active", "nodes", "drift", "warning", "canonical_tag", "recovery_needed"},
    "GET /api/vpn-nodes#nodes[]": {"id", "name", "active", "protocol", "endpoint", "network", "security", "health"},
    "GET /api/tuner/status": {"status", "active", "error", "service", "candidate_count", "log_tail"},
    "GET /api/diagnostics/status": {"active", "status", "progress", "summary", "error", "results", "kind", "job_id"},
    "GET /api/checks/config": {"checks"},
    "GET /api/checks/config#checks[]": {"ok", "status", "name", "detail"},
    "POST /api/route/<svc>/<mode>": {"job_id"},
    "POST /api/vpn-nodes/activate/<n>": {"job_id"},
    "POST /api/vpn-nodes/recover": {"job_id"},
    "POST /api/history/rollback/<id>": {"job_id"},
}

# Contract key -> a request the mock answers (templates get a concrete path).
SERVED = {
    'GET /api/inspection/status': '/api/inspection/status',
    'GET /api/vpn-monitor': '/api/vpn-monitor',
    'POST /api/inspection/check/<kind>': '/api/inspection/check/vpn',
    'POST /api/inspection/setup': '/api/inspection/setup',
    'POST /api/vpn-monitor/save': '/api/vpn-monitor/save',
    'POST /api/vpn-monitor/approve': '/api/vpn-monitor/approve',
    'GET /api/notifications': '/api/notifications',
    'GET /api/dns': '/api/dns',
    'POST /api/dns/<mode>': '/api/dns/doh',
    'POST /api/notifications/save': '/api/notifications/save',
    'POST /api/notifications/test': '/api/notifications/test',
    'POST /api/notifications/topic': '/api/notifications/topic',
    "GET /api/status": "/api/status",
    "GET /api/route/status": "/api/route/status",
    "GET /api/route/result": "/api/route/result",
    "GET /api/history": "/api/history",
    "GET /api/tuner/status": "/api/tuner/status",
    "GET /api/diagnostics/status": "/api/diagnostics/status",
    "GET /api/checks/config": "/api/checks/config",
    "GET /api/imported": "/api/imported",
    "GET /api/profile-versions": "/api/profile-versions",
    "GET /api/updates": "/api/updates",
    "GET /api/tuner/sources": "/api/tuner/sources",
    "GET /api/tuner/voice-endpoint": "/api/tuner/voice-endpoint",
    "GET /api/vpn-nodes": "/api/vpn-nodes",
    "GET /api/automation": "/api/automation",
    "GET /api/diagnostics/targets": "/api/diagnostics/targets",
    "POST /api/route/<svc>/<mode>": "/api/route/youtube/vpn",
    "POST /api/vpn-nodes/activate/<n>": "/api/vpn-nodes/activate/vless_2",
    "POST /api/vpn-nodes/recover": "/api/vpn-nodes/recover",
    "POST /api/history/rollback/<id>": "/api/history/rollback/0123456789abcdef",
    # The default answer of every other POST is {"ok": true, "output": "mock"}.
    "POST /api/tuner/apply": "/api/tuner/apply",
    "POST /api/xkeen/<action>": "/api/xkeen/restart",
    "POST /api/vpn-nodes/check/<id>": "/api/vpn-nodes/check/current",
    "POST /api/vpn-nodes/add": "/api/vpn-nodes/add",
    'POST /api/vpn-nodes/ping/<id>': '/api/vpn-nodes/ping/current',
    'POST /api/vpn-nodes/ping': '/api/vpn-nodes/ping',
    "POST /api/import/apply": "/api/import/apply",
    "POST /api/import/clear/<service>": "/api/import/clear/youtube",
    "POST /api/import/rollback": "/api/import/rollback",
    "POST /api/profiles/apply/<service>/<version_id>": "/api/profiles/apply/youtube/v1",
}
# Read by the page, not served: no UI test shows these parts of the page (GET answers: 404).
NOT_SERVED = {
    "POST /api/updates/check": None,
    "POST /api/diagnostics/start/health": None,
}


# The module the guard is tried on: a test class with a helper that checks a key, to which a case adds methods.
GUARD_SOURCE = """
import unittest
import unittest as ut
from unittest import skip


class Base(panel_harness.PanelTestCase):
    def assertContract(self, key, payload):
        self.assertEqual(key, key)

    def check_helper(self):
        self.assertContract("HELPER", {})

"""

ENDPOINT_TESTS = Path(__file__).with_name("test_panel_endpoints.py")
# The checks of test_panel_endpoints.py that hold an answer of the real Handler against a contract key; the key is
# their first argument (assertPage is for the HTML page, which has no JSON fields to compare).
CONTRACT_CHECKS = ("assertContract", "assertElements", "assertPage")
# unittest runs the methods whose names start with this, of the classes that derive from TestCase.
TEST_PREFIX = "test"
NOT_RUN_DECORATORS = ("skip", "skipIf", "skipUnless", "expectedFailure")


def is_skipped(node):
    return any(
        ast.unparse(decorator.func if isinstance(decorator, ast.Call) else decorator).split(".")[-1]
        in NOT_RUN_DECORATORS
        for decorator in node.decorator_list
    )


def case_classes(tree):
    """Classes of the module that unittest runs: derived from a TestCase, directly or through a class of the module."""
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef) and not is_skipped(node)}
    found = set()
    while True:
        more = {
            name
            for name, node in classes.items()
            if name not in found
            and any(ast.unparse(base).endswith("TestCase") or ast.unparse(base) in found for base in node.bases)
        }
        if not more:
            return [classes[name] for name in classes if name in found]
        found |= more


def runnable_methods(tree):
    """The methods unittest would run: test* of those classes, the last definition of a name, not skipped."""
    methods = []
    for node in case_classes(tree):
        defined = {item.name: item for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
        methods.extend(
            method for name, method in defined.items() if name.startswith(TEST_PREFIX) and not is_skipped(method)
        )
    return methods


def contract_keys_checked_by(source, filename="<source>"):
    """(keys given as literals, lines of the checks whose key is not a literal) in the test methods of the source."""
    literal, computed = set(), []
    for method in runnable_methods(ast.parse(source, filename=filename)):
        for node in ast.walk(method):
            function = node.func if isinstance(node, ast.Call) else None
            if not (isinstance(function, ast.Attribute) and function.attr in CONTRACT_CHECKS):
                continue
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                literal.add(first.value)
            else:
                computed.append(node.lineno)
    return literal, computed


def contract_keys_checked_by_endpoint_tests():
    return contract_keys_checked_by(ENDPOINT_TESTS.read_text(encoding="utf-8"), str(ENDPOINT_TESTS))


def top_level_keys():
    return {key for key in FRONTEND_CONTRACT if key not in {"*", "GET /"} and "#" not in key}


class ContractTableTests(unittest.TestCase):
    def test_the_given_table_is_kept(self):
        for key, fields in GIVEN_TABLE.items():
            with self.subTest(key=key):
                self.assertLessEqual(fields, all_fields(key))

    def test_every_contract_key_reaches_the_real_handler(self):
        # Every key is held against an answer of the real Handler (test_panel_endpoints.py serves it on a socket).
        # A key passed as a variable cannot be seen here, and a key that is not in the contract is checked against
        # nothing: both are refused, so the guard cannot be fooled by a loop or a typo.
        checked, computed = contract_keys_checked_by_endpoint_tests()
        self.assertEqual(computed, [], "contract checks of test_panel_endpoints.py with a key that is not a literal")
        self.assertEqual(sorted(set(FRONTEND_CONTRACT) - {"*"} - checked), [])
        self.assertEqual(sorted(checked - set(FRONTEND_CONTRACT)), [])

    def test_the_guard_counts_only_the_test_methods_unittest_runs(self):
        def method(name, *decorators, call="self.assertContract('KEY', {})"):
            lines = [f"    {decorator}\n" for decorator in decorators]
            return "".join(lines) + f"    def {name}(self):\n        {call}\n\n"

        def keys(body):
            literal, computed = contract_keys_checked_by(GUARD_SOURCE + body)
            return literal - {"HELPER"}, computed

        runs = {
            "a test method": method("test_one"),
            "a name without the underscore": method("testOne"),
            "a name that only starts with test": method("tests_one"),
            "an element check": method("test_one", call="self.assertElements('KEY', [])"),
            "a page check": method("test_one", call="self.assertPage('KEY', 1, 2)"),
            "another decorator": method("test_one", "@mock.patch('x')"),
            "a nested function": method("test_one", call="(lambda: self.assertContract('KEY', {}))()"),
            "a subclass of a test class": "class Child(Base):\n" + method("test_one"),
            "the last definition of a name": method("test_one", call="self.assertContract('OLD', {})")
            + method("test_one"),
        }
        for case, body in runs.items():
            with self.subTest(runs=case):
                self.assertEqual(keys(body), ({"KEY"}, []))
        silent = {
            "a method renamed to a non-test name": method("_disabled_one"),
            "a method renamed to a helper name": method("check_one"),
            "a skipped method": method("test_one", "@unittest.skip('x')"),
            "a skip through an alias": method("test_one", "@ut.skipIf(True, 'x')"),
            "a skip by a bare name": method("test_one", "@skip('x')"),
            "an expected failure": method("test_one", "@unittest.expectedFailure"),
            "a skipped class": "@unittest.skip('x')\nclass Child(Base):\n" + method("test_one"),
            "a class that is not a test case": "class Plain:\n" + method("test_one"),
            "a module function": "def test_one(case):\n    case.assertContract('KEY', {})\n",
            "a definition shadowed by a later one": method("test_one") + method("test_one", call="pass"),
        }
        for case, body in silent.items():
            with self.subTest(silent=case):
                self.assertEqual(keys(body), (set(), []))
        _, computed = keys(method("test_one", call="self.assertContract(key, {})"))
        self.assertEqual(len(computed), 1)

    def test_conditional_and_boolean_fields_belong_to_known_keys(self):
        for key, fields in FRONTEND_CONDITIONAL.items():
            with self.subTest(key=key):
                self.assertIn(key, FRONTEND_CONTRACT)
                self.assertEqual(set(fields) & FRONTEND_CONTRACT[key], set())
        for key, fields in BOOLEAN_FIELDS.items():
            with self.subTest(key=key):
                self.assertLessEqual(fields, FRONTEND_CONTRACT[key])

    def test_missing_fields_reports_what_an_answer_lacks(self):
        self.assertEqual(missing_fields("GET /api/route/status", {"ok": True, "status": "idle", "active": 0, "output": ""}),
                         ["active (bool)"])
        self.assertEqual(missing_fields("GET /api/route/status", {"ok": True, "status": "idle", "active": False}), ["output"])
        self.assertEqual(missing_fields("*", {"ok": False}), ["error|output"])
        self.assertEqual(missing_fields("*", {"ok": False, "output": "x"}), [])
        self.assertEqual(missing_fields("GET /api/vpn-nodes#nodes[].health", {"ok": False, "detail": "x"}), ["checked_utc"])
        with self.assertRaises(KeyError):
            missing_fields("GET /api/status", {}, also=("job_id",))


class MockServerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = panel_mock_server.ThreadingHTTPServer(("127.0.0.1", 0), panel_mock_server.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, key, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            method = key.split(" ", 1)[0]
            body = b"{}" if method == "POST" else None
            connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, response.read(), response.getheader("Content-Type")
        finally:
            connection.close()

    def test_every_contract_key_is_served_or_listed_as_not_served(self):
        self.assertEqual(top_level_keys(), set(SERVED) | set(NOT_SERVED))
        self.assertEqual(set(SERVED) & set(NOT_SERVED), set())

    def test_served_answers_carry_the_contract_fields(self):
        for key, path in SERVED.items():
            with self.subTest(key=key):
                status, data, content_type = self.request(key, path)
                self.assertIn(status, (200, 202))
                self.assertEqual(content_type, "application/json")
                payload = json.loads(data)
                self.assertEqual(missing_fields(key, payload), [], payload)

    def test_job_starts_are_answered_with_a_queued_job(self):
        for key in ("POST /api/route/<svc>/<mode>", "POST /api/vpn-nodes/activate/<n>", "POST /api/vpn-nodes/recover",
                    "POST /api/history/rollback/<id>"):
            with self.subTest(key=key):
                status, data, _ = self.request(key, SERVED[key])
                self.assertEqual(status, 202)
                payload = json.loads(data)
                self.assertEqual(missing_fields("GET /api/route/status", payload, also=(
                    "job_id", "stage", "stage_label", "progress", "operation", "service")), [], payload)
                self.assertIs(payload["active"], True)

    def test_unserved_get_paths_are_not_found(self):
        for key, path in NOT_SERVED.items():
            if path is None:
                continue
            with self.subTest(key=key):
                status, data, _ = self.request(key, path)
                self.assertEqual(status, 404)
                self.assertIs(json.loads(data)["ok"], False)

    def test_root_is_the_page(self):
        status, data, content_type = self.request("GET /", "/")
        self.assertEqual((status, content_type), (200, "text/html; charset=utf-8"))
        self.assertTrue(data.startswith(b"<!doctype html>"))


if __name__ == "__main__":
    unittest.main()
