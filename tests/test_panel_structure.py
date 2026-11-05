"""Structure rules of the kdn package, checked on the source with ast (phase 2, "Правила кода kdn").

Panel code reaches other kdn modules only through module attributes at call time, and the tests import a
fresh generation of the package per class: these rules keep both working. One test per rule.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re
import sys
from typing import NamedTuple
import unittest

import panel_harness


ROOT = panel_harness.ROOT
PACKAGE_DIR = panel_harness.PACKAGE_DIR
WEB_DIR = PACKAGE_DIR / "web"
TESTS_DIR = ROOT / "tests"
ENTRY_MODULE = panel_harness.ENTRY_MODULE
# L0 … L6 of the phase-2 architecture; a module imports only modules of its own or a lower layer.
# Modules that do not exist yet are skipped; package __init__ modules import no kdn module at all.
LAYERS = {
    'kdn.common.xkeen': 0,
    'kdn.common.xray_process': 0,
    'kdn.common.retention': 0,
    'kdn.vpn_links': 1,  # pure URI/data translation
    'kdn.vpn_probe_child': 0,  # stdlib-only isolated Linux exec helper
    **dict.fromkeys(('kdn.inspection.wire', 'kdn.inspection.resources', 'kdn.inspection.layout',
                    'kdn.inspection.policy', 'kdn.inspection.transport'), 0),
    'kdn.inspection.rpc': 1,
    'kdn.inspection.native': 1,
    'kdn.inspection.probe': 1,
    'kdn.inspection.request': 1,
    'kdn.inspection.receipt': 1,
    'kdn.inspection.context': 15,
    'kdn.inspection.worker': 15,
    **dict.fromkeys(
        ("kdn.common.paths", "kdn.common.fsutil", "kdn.common.jsonc", "kdn.common.proc", "kdn.common.timeutil",
         "kdn.common.lock", "kdn.common.errors", "kdn.common.logsetup"),
        0,
    ),
    "kdn.state.nfqws": 1,
    **dict.fromkeys(("kdn.jobs.jobspec", "kdn.jobs.jobstore", "kdn.jobs.coordinator"), 1),
    "kdn.web.infra.config": 2,
    "kdn.web.infra.readcache": 2,
    **dict.fromkeys(("kdn.web.infra.jobfiles", "kdn.web.infra.toolmods", "kdn.web.infra.statestore"), 3),
    "kdn.web.infra.engine": 4,
    "kdn.web.infra.inspection": 4,
    "kdn.web.domain.inspection": 5,
    "kdn.web.domain.vpn_monitor": 5,
    "kdn.web.domain.notifications": 5,
    "kdn.web.api.inspection_routes": 6,
    **dict.fromkeys(
        tuple(
            f"kdn.web.domain.{name}"
            for name in ("validation", "history", "profiles", "flowseal", "health", "route_jobs", "tuner_jobs",
                         "diagnostic_jobs", "vpn", "automation", "refusals", "operations", "job_ops")
        ),
        5,
    ),
    **dict.fromkeys(
        tuple(
            f"kdn.web.api.{name}"
            for name in ("router", "security", "server", "read_routes", "job_routes", "record_routes",
                         "operation_routes", "table")
        ),
        6,
    ),
    ENTRY_MODULE: 6,
    # kdn.engine (phase 4): L10-L16.
    **dict.fromkeys(
        ("kdn.engine.console", "kdn.engine.legacy", "kdn.engine.config", "kdn.engine.lifecycle",
         "kdn.engine.findings", "kdn.engine.snapshot_format",
         "kdn.engine.snapshot_policy", "kdn.engine.profile_descriptor"),
        10,
    ),
    **dict.fromkeys(("kdn.engine.confvalues", "kdn.engine.system", "kdn.engine.xrayconf",
                    "kdn.engine.nfqws_process", "kdn.engine.transaction"), 11),
    **dict.fromkeys(("kdn.engine.options", "kdn.engine.snapshots", "kdn.engine.compose",
                    "kdn.engine.nfqws_render", "kdn.engine.nfqws_write", "kdn.engine.snapshot_store",
                    "kdn.engine.xray_patch", "kdn.engine.dns_mode"), 12),
    **dict.fromkeys(
        ("kdn.engine.checks", "kdn.engine.profiles", "kdn.engine.plan", "kdn.engine.preflight_xray",
         "kdn.engine.preflight_wan", "kdn.engine.statusblocks", "kdn.engine.nfqws_validate", "kdn.engine.record_retention"),
        13,
    ),
    **dict.fromkeys(("kdn.engine.status", "kdn.engine.preflight", "kdn.engine.nfqws_service",
                    "kdn.engine.import_ops", "kdn.engine.rollback_ops", "kdn.engine.relay_restore",
                    "kdn.engine.apply_files", "kdn.engine.apply_dependencies", "kdn.engine.apply_nfqws",
                    "kdn.engine.xkeen_service"), 14),
    "kdn.engine.apply_ops": 15,
    "kdn.engine.inspection_setup": 15,
    "kdn.engine.route_switch": 15,
    "kdn.engine.snapshot_bridge": 15,
    "kdn.engine.import_worker": 12,
    "kdn.engine.nfqws_marks": 13,
    "kdn.engine.cli": 15,
    "kdn.engine.__main__": 16,
}
KDN_STRING = re.compile(r"(tools\.router\.)?kdn(\.|$)")
# Names a panel test holds the facade of its generation under (PanelTestCase.ns, an alias of it, a local copy).
FACADES = frozenset({"self.ns", "cls.ns", "self.panel", "cls.panel", "namespace", "ns"})
# Methods that would write the facade; indexed writes (ns["X"] = ..., += ..., del ns["X"]) are found by their context.
FACADE_WRITE_METHODS = frozenset({"update", "clear", "setdefault", "pop", "popitem"})
# The first parameter of patch and patch.multiple, and of patch.dict: the target a test gives by keyword.
PATCH_TARGET_KEYWORDS = frozenset({"target", "in_dict"})
# What the entry module holds besides its imports (until the HTTP layer leaves it, phase 3).
ENTRY_DEFINITIONS = ("_package_path", "main")
ENTRY_STATEMENTS = (
    "sys.path[:] = _package_path(sys.path, __file__)",
    "cfg.ENTRY = Path(__file__).absolute()",
    "if __name__ == '__main__':\n    raise SystemExit(main())",
)


class ImportRef(NamedTuple):
    lineno: int
    module: str
    name: str | None
    level: int
    in_function: bool
    dynamic: bool


class _Imports(ast.NodeVisitor):
    def __init__(self):
        self.found = []
        self.depth = 0

    def visit_FunctionDef(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_Import(self, node):
        for alias in node.names:
            self.found.append(ImportRef(node.lineno, alias.name, None, 0, self.depth > 0, False))

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.found.append(ImportRef(node.lineno, node.module or "", alias.name, node.level, self.depth > 0, False))

    def visit_Call(self, node):
        function = node.func
        name = function.id if isinstance(function, ast.Name) else getattr(function, "attr", None)
        if (
            name in ("import_module", "__import__")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            self.found.append(ImportRef(node.lineno, node.args[0].value, None, 0, self.depth > 0, True))
        self.generic_visit(node)


class _RootPathRefs(ast.NodeVisitor):
    """References to root_path (calls and bare reads), with the function depth they are made at."""

    def __init__(self):
        self.found = []
        self.depth = 0

    def visit_FunctionDef(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_Name(self, node):
        if node.id == "root_path":
            self.found.append((node.lineno, self.depth > 0))

    def visit_Attribute(self, node):
        if node.attr == "root_path":
            self.found.append((node.lineno, self.depth > 0))
        self.generic_visit(node)


def python_files(directory):
    return sorted(path for path in directory.rglob("*.py") if "__pycache__" not in path.parts)


def module_name(path):
    parts = path.relative_to(PACKAGE_DIR.parent).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def kdn_modules():
    return {module_name(path): path for path in python_files(PACKAGE_DIR)}


def imports(path):
    visitor = _Imports()
    visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
    return visitor.found


def is_kdn(name):
    return name == "kdn" or name.startswith("kdn.")


def is_tools_kdn(name):
    return name == "tools.router.kdn" or name.startswith("tools.router.kdn.")


def target(ref, modules):
    """kdn module an absolute import loads: the module itself, or the module a name is taken from."""
    if ref.level or not is_kdn(ref.module):
        return None
    if ref.name is None:
        return ref.module
    candidate = f"{ref.module}.{ref.name}"
    return candidate if candidate in modules else ref.module


def where(path, ref):
    return f"{path.relative_to(ROOT)}:{ref.lineno}"


def import_graph(modules):
    graph = {}
    for name, path in modules.items():
        graph[name] = sorted({
            found for found in (target(ref, modules) for ref in imports(path)) if found in modules and found != name
        })
    return graph


def find_cycles(graph):
    cycles, state, stack = [], {}, []

    def visit(node):
        state[node] = "open"
        stack.append(node)
        for following in graph[node]:
            if state.get(following) == "open":
                cycles.append(stack[stack.index(following):] + [following])
            elif following not in state:
                visit(following)
        stack.pop()
        state[node] = "done"

    for node in graph:
        if node not in state:
            visit(node)
    return cycles


def is_patch(function):
    if isinstance(function, ast.Name):
        return function.id == "patch"
    if isinstance(function, ast.Attribute):
        return function.attr == "patch" or (function.attr in ("dict", "multiple") and is_patch(function.value))
    return False


def is_patch_dict(function):
    return isinstance(function, ast.Attribute) and function.attr == "dict" and is_patch(function.value)


def patch_target(call):
    """First argument of a patch call: the positional one, or the keyword it is given by."""
    if call.args:
        return call.args[0]
    return next((keyword.value for keyword in call.keywords if keyword.arg in PATCH_TARGET_KEYWORDS), None)


def leading_text(node):
    """The text a string expression starts with (literal, f-string, "a" + x, "a%s" % x, "a{}".format(x)), or None."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return leading_text(node.values[0]) if node.values else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return leading_text(node.left)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return leading_text(node.func.value)
    return None


def string_patches(tree):
    """(line, target) of every patch call that names a kdn module by a string."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and is_patch(node.func):
            text = leading_text(patch_target(node))
            if text is not None and KDN_STRING.match(text):
                found.append((node.lineno, text))
    return found


def facade_writes(tree):
    """(line, what) of every write to a panel facade that goes around PanelTestCase.patch/patched/patch_class."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if is_patch_dict(node.func):
                target = patch_target(node)
                if target is not None and ast.unparse(target) in FACADES:
                    found.append((node.lineno, f"patch.dict({ast.unparse(target)}, ...)"))
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in FACADE_WRITE_METHODS
                and ast.unparse(node.func.value) in FACADES
            ):
                found.append((node.lineno, f"{ast.unparse(node.func)}(...)"))
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and ast.unparse(node.value) in FACADES
        ):
            found.append((node.lineno, f"{'del ' if isinstance(node.ctx, ast.Del) else ''}{ast.unparse(node)} write"))
    return found


class KdnStructureTests(unittest.TestCase):
    def setUp(self):
        self.modules = kdn_modules()
        self.assertIn(ENTRY_MODULE, self.modules)

    def test_kdn_imports_modules_not_names(self):
        problems = []
        for path in self.modules.values():
            for ref in imports(path):
                if ref.dynamic:
                    continue
                if ref.level:
                    problems.append(f"{where(path, ref)}: relative import of {ref.name} (use from kdn.x import module)")
                elif ref.name is not None and is_kdn(ref.module) and target(ref, self.modules) == ref.module:
                    problems.append(f"{where(path, ref)}: from {ref.module} import {ref.name} is not a module import")
        self.assertEqual(problems, [])

    def test_kdn_imports_are_module_level(self):
        problems = [
            f"{where(path, ref)}: {ref.module or '.'} imported inside a function"
            for path in self.modules.values()
            for ref in imports(path)
            if ref.in_function and (ref.level or is_kdn(ref.module))
            and not (path == PACKAGE_DIR / 'engine' / 'status.py' and ref.module == 'kdn.common' and ref.name == 'lock'
                     and ref.lineno in {node.lineno for fn in ast.walk(ast.parse(path.read_text(encoding='utf-8'))) if isinstance(fn, ast.FunctionDef)
                                        and fn.name == '_json_lock' for node in fn.body if isinstance(node, ast.ImportFrom)})
            and not (path == WEB_DIR / "infra" / "engine.py" and ref.module == "kdn.engine"
                     and ref.name in ("import_worker", "snapshot_store"))
            and not (path == PACKAGE_DIR / 'engine' / 'cli.py' and ref.module == 'kdn.engine'
                     and ref.name in ('apply_ops', 'import_ops', 'rollback_ops', 'inspection_setup')
                     and ref.lineno in {node.lineno for fn in ast.walk(ast.parse(path.read_text(encoding='utf-8')))
                                        if isinstance(fn, ast.FunctionDef) and fn.name == '_run_mutation'
                                        for node in ast.walk(fn) if isinstance(node, ast.ImportFrom)})
        ]
        self.assertEqual(problems, [])

    def test_no_module_or_package_shadows_the_stdlib(self):
        problems = []
        for path in [PACKAGE_DIR, *sorted(PACKAGE_DIR.rglob("*"))]:
            if "__pycache__" in path.parts:
                continue
            name = path.name if path.is_dir() else path.stem if path.suffix == ".py" else None
            if name and not name.startswith("__") and name in sys.stdlib_module_names:
                problems.append(f"{path.relative_to(ROOT)}: {name} is a stdlib module name")
        self.assertEqual(problems, [])

    def test_web_package_holds_only_the_entry_module(self):
        problems = []
        for entry in sorted(WEB_DIR.iterdir()):
            if entry.name.startswith("."):
                continue
            if entry.is_dir():
                allowed = entry.name in ("assets", "__pycache__") or (entry / "__init__.py").is_file()
            else:
                allowed = entry.name in ("app.py", "__init__.py")
            if not allowed:
                problems.append(str(entry.relative_to(ROOT)))
        self.assertEqual(problems, [])

    def test_entry_module_is_thin(self):
        path = self.modules[ENTRY_MODULE]
        body = ast.parse(path.read_text(encoding="utf-8"), filename=str(path)).body
        definitions = [stmt.name for stmt in body if isinstance(stmt, (ast.FunctionDef, ast.ClassDef))]
        statements = [
            ast.unparse(stmt)
            for stmt in body
            if not isinstance(stmt, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
        ]
        self.assertEqual(definitions, list(ENTRY_DEFINITIONS))
        self.assertEqual(statements, list(ENTRY_STATEMENTS))

    def test_jobs_are_spawned_only_by_the_store(self):
        allowed = {("kdn.jobs.jobstore", "spawn"), ("kdn.web.domain.route_jobs", "run_route_command")}
        problems = []
        for name, path in self.modules.items():
            if not (name.startswith("kdn.web.") or name.startswith("kdn.jobs.")):
                continue
            for function in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(function, ast.FunctionDef):
                    for node in ast.walk(function):
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Popen":
                            if (name, function.name) not in allowed:
                                problems.append((name, function.name, node.lineno))
        self.assertEqual(problems, [])

    def test_busy_checks_live_only_in_the_coordinator(self):
        problems = []
        phrases = ("сначала завершите", "во время подбора", "во время диагностики", "во время переключения", "уже выполняется", "уже запускается")
        for name, path in self.modules.items():
            if name.startswith("kdn.engine."):
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                symbol = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None
                if symbol in {"job_start_guard", "ensure_route_job_available", "JOB_START_LOCK"} and name != "kdn.web.infra.jobfiles":
                    problems.append((name, node.lineno, symbol))
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and name not in {"kdn.jobs.coordinator", "kdn.web.domain.refusals"}:
                    if any(phrase in node.value for phrase in phrases):
                        problems.append((name, node.lineno, node.value))
        self.assertEqual(problems, [])

    def test_http_layer_runs_no_router_mutation(self):
        prohibited = {"apply_profile", "clear_imported_profile", "rollback_import", "run_xkeen_action", "add", "check"}
        problems = []
        for path in (WEB_DIR / "api").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in prohibited:
                    if path.name == "router.py" and ast.unparse(node.func) == "seen.add":
                        # Router's duplicate-pattern set is not a VPN manager.
                        continue
                    problems.append((path.name, node.lineno, node.func.attr))
        self.assertEqual(problems, [])

    def test_status_is_never_read_under_the_start_lock(self):
        problems = []
        for path in (WEB_DIR / "domain").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.With) and any(".exclusive(" in ast.unparse(item.context_expr) for item in node.items):
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "read_status_fields":
                            problems.append((path.name, child.lineno))
        self.assertEqual(problems, [])

    def test_route_handlers_have_the_request_signature(self):
        handlers = []
        for path in (WEB_DIR / "api").glob("*.py"):
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(node, ast.FunctionDef) and node.name.startswith(("get_", "post_")):
                    handlers.append(node.name)
                    self.assertEqual([argument.arg for argument in node.args.args], ["request"], node.name)
        self.assertTrue(handlers)

    def test_api_modules_are_in_the_layer_table(self):
        for path in (WEB_DIR / "api").glob("*.py"):
            if path.name != "__init__.py":
                self.assertEqual(LAYERS.get(module_name(path)), 6, path.name)

    def test_nothing_imports_the_entry_module(self):
        problems = [
            f"{where(path, ref)}: imports {ENTRY_MODULE}"
            for path in self.modules.values()
            for ref in imports(path)
            if target(ref, self.modules) == ENTRY_MODULE
        ]
        self.assertEqual(problems, [])

    def test_layers_import_downwards(self):
        problems = []
        for name, path in self.modules.items():
            package = path.name == "__init__.py"
            if not package and name not in LAYERS:
                problems.append(f"{path.relative_to(ROOT)}: {name} has no layer in LAYERS")
                continue
            for ref in imports(path):
                found = target(ref, self.modules)
                if found is None or found == name:
                    continue
                if package:
                    problems.append(f"{where(path, ref)}: package {name} imports {found}")
                # The single panel engine adapter reads bounded focused identity/source metadata.
                # Domain/API modules still cannot reach engine internals or restore files.
                elif name == "kdn.web.infra.engine" and found in ("kdn.engine.import_worker", "kdn.engine.snapshot_store"):
                    continue
                elif found in LAYERS and LAYERS[found] > LAYERS[name]:
                    problems.append(
                        f"{where(path, ref)}: {name} (L{LAYERS[name]}) imports {found} (L{LAYERS[found]})"
                    )
        self.assertEqual(problems, [])

    def test_kdn_import_graph_is_acyclic(self):
        cycles = find_cycles(import_graph(self.modules))
        self.assertEqual([" -> ".join(cycle) for cycle in cycles], [])

    def test_one_import_identity(self):
        problems = []
        for path in python_files(TESTS_DIR) + python_files(PACKAGE_DIR):
            for ref in imports(path):
                if is_tools_kdn(ref.module) or (ref.module == "tools.router" and ref.name == "kdn"):
                    problems.append(f"{where(path, ref)}: imports {ref.module} (import kdn.* instead)")
        self.assertEqual(problems, [])
        ns = panel_harness.load_panel()
        self.assertEqual([name for name in sys.modules if is_tools_kdn(name)], [])
        for name, module in ns.modules.items():
            with self.subTest(module=name):
                self.assertTrue(Path(module.__spec__.origin).is_relative_to(PACKAGE_DIR), module.__spec__.origin)

    def test_root_path_only_in_config(self):
        config = WEB_DIR / "infra" / "config.py"
        problems, at_import = [], 0
        for path in python_files(WEB_DIR):
            visitor = _RootPathRefs()
            visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
            for lineno, in_function in visitor.found:
                if path == config and not in_function:
                    at_import += 1
                else:
                    problems.append(f"{path.relative_to(ROOT)}:{lineno}: root_path outside the import of config.py")
        self.assertEqual(problems, [])
        self.assertGreater(at_import, 0, "infra/config.py takes no path from root_path")

    def test_tests_do_not_patch_kdn_by_string(self):
        problems = []
        for path in python_files(TESTS_DIR):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            problems.extend(
                f"{path.relative_to(ROOT)}:{lineno}: patch({target!r}) "
                "(use mock.patch.object on the module or PanelTestCase.patch)"
                for lineno, target in string_patches(tree)
            )
        self.assertEqual(problems, [])

    def test_panel_tests_write_names_only_through_the_helper(self):
        problems = []
        for path in sorted(TESTS_DIR.glob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            problems.extend(
                f"{path.relative_to(ROOT)}:{lineno}: {what} (use PanelTestCase.patch/patched/patch_class)"
                for lineno, what in facade_writes(tree)
            )
        self.assertEqual(problems, [])

    def test_the_scans_of_the_tests_see_planted_violations(self):
        string_cases = {
            "positional": 'mock.patch("kdn.common.proc.run_command")',
            "keyword": 'mock.patch(target="kdn.common.proc.run_command", new=None)',
            "bare patch": 'patch("kdn.web.infra.config.PORT", 1)',
            "multiple": 'mock.patch.multiple("kdn.web.infra.config", PORT=1)',
            "dict by keyword": 'mock.patch.dict(in_dict="kdn.web.infra.config.TABLE", values={})',
            "tools prefix": 'mock.patch("tools.router.kdn.common.proc.run_command")',
            "f-string": 'mock.patch(f"kdn.common.{module}.run_command")',
            "concatenation": 'mock.patch("kdn.common." + module)',
            "format": 'mock.patch("kdn.common.{}".format(module))',
            "decorator": '@mock.patch("kdn.common.proc.run_command")\ndef test(self, run):\n    pass',
        }
        for case, source in string_cases.items():
            with self.subTest(case=case):
                self.assertEqual(len(string_patches(ast.parse(source))), 1)
        for source in (
            'mock.patch.object(proc, "run_command")',
            'mock.patch("os.getcwd")',
            'mock.patch(target="subprocess.run")',
            'mock.patch.dict(os.environ, {"A": "1"})',
            'mock.patch(f"{owner}.run_command")',
        ):
            with self.subTest(clean=source):
                self.assertEqual(string_patches(ast.parse(source)), [])
        write_cases = {
            "patch.dict self.ns": 'mock.patch.dict(self.ns, {"A": 1})',
            "patch.dict cls.panel": 'patch.dict(cls.panel, {"A": 1}, clear=False)',
            "patch.dict by keyword": 'mock.patch.dict(values={"A": 1}, in_dict=namespace)',
            "patch.dict ns": 'mock.patch.dict(ns, {"A": 1})',
            "assignment": 'self.ns["A"] = 1',
            "assignment to panel": 'cls.panel["A"] = 1',
            "augmented": 'self.panel["A"] += 1',
            "annotated": 'ns["A"]: int = 1',
            "deletion": 'del namespace["A"]',
            "unpacking": 'self.ns["A"], other = 1, 2',
            "loop target": 'for self.ns["A"] in range(2):\n    pass',
            "update": 'self.ns.update(A=1)',
            "clear": 'ns.clear()',
            "pop": 'self.panel.pop("A")',
        }
        for case, source in write_cases.items():
            with self.subTest(case=case):
                self.assertEqual(len(facade_writes(ast.parse(source))), 1)
        for source in (
            'self.patch(A=1)',
            'with self.patched(A=1) as ns:\n    pass',
            'mock.patch.dict(os.environ, {"A": "1"})',
            'mock.patch.dict(self.environment, {"A": 1})',
            'value = self.ns["A"]',
            'self.ns.module("app").A',
            'cache["A"] = 1',
            'self.results.update(A=1)',
        ):
            with self.subTest(clean=source):
                self.assertEqual(facade_writes(ast.parse(source)), [])


if __name__ == "__main__":
    unittest.main()
