"""Structure rules of kdn.engine, checked on the source with ast (phase 4, "Правила кода kdn.engine").

The layers and the one-import-identity rules of the whole kdn package are checked by test_panel_structure.py;
this file adds what only the engine needs: no link to the panel, the standard library only, the router root joined
to a logical path in config.py alone, no slow import on the way of a mode (rule 9, "Бюджет импорта"), and the one
place of the signal handlers and of SystemExit. The scans are checked on planted violations.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ROUTER_DIR = ROOT / "tools" / "router"
PACKAGE_DIR = ROUTER_DIR / "kdn"
ENGINE_DIR = PACKAGE_DIR / "engine"
WEB_DIR = PACKAGE_DIR / "web"
ENGINE_CONFIG = ENGINE_DIR / "config.py"
SCRIPT = ROOT / "apply-discord-nfqws2.sh"

# Rule 9: modules that make Python start slowly on the router. No module of kdn.engine imports one of them at
# module level, and the interpreter that imports a mode does not load one either (-X importtime). Tasks that add
# modes extend the set; compose imports tempfile and shutil inside its function, which the rule allows.
FORBIDDEN_MODULES = frozenset(
    {"dataclasses", "inspect", "typing", "tempfile", "shutil", "argparse", "logging", "enum"}
)
# Names that hold the router root: joined to a logical path outside config.py they bypass its string concatenation.
ROOT_NAMES = frozenset({"root", "test_root", "testroot", "TEST_ROOT"})
# The files that may end the process or change signal dispositions.
EXIT_FILES = frozenset({"__main__.py", "lifecycle.py"})


class _Imports(ast.NodeVisitor):
    """(line, module, name, level, in_function) of every import statement."""

    def __init__(self):
        self.found = []
        self.depth = 0

    def _function(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_FunctionDef = visit_AsyncFunctionDef = visit_Lambda = _function

    def visit_Import(self, node):
        for alias in node.names:
            self.found.append((node.lineno, alias.name, None, 0, self.depth > 0))

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.found.append((node.lineno, node.module or "", alias.name, node.level, self.depth > 0))


def parse(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imports_of(source):
    visitor = _Imports()
    visitor.visit(ast.parse(source) if isinstance(source, str) else source)
    return visitor.found


def dotted_names(found):
    """The modules an import statement may load: the module, and module.name for a from-import."""
    _, module, name, _, _ = found
    return [module] if name is None else [module, f"{module}.{name}" if module else name]


def is_under(name, package):
    return name == package or name.startswith(package + ".")


def links_to(source, package):
    """Lines of the imports in the source that reach the package."""
    return [found[0] for found in imports_of(source) if any(is_under(name, package) for name in dotted_names(found))]


def engine_files():
    return sorted(path for path in ENGINE_DIR.rglob("*.py") if "__pycache__" not in path.parts)


def web_files():
    return sorted(path for path in WEB_DIR.rglob("*.py") if "__pycache__" not in path.parts)


def top_level(module):
    return module.split(".")[0]


def foreign_imports(source):
    """(line, module) of the imports that are neither the standard library nor kdn, and of every relative import."""
    allowed = sys.stdlib_module_names | {"kdn"}
    return [
        (found[0], "." * found[3] + found[1])
        for found in imports_of(source)
        if found[3] or top_level(found[1]) not in allowed
    ]


def slow_module_imports(source):
    """(line, module) of the module-level imports of a FORBIDDEN_MODULES member."""
    return [
        (found[0], found[1])
        for found in imports_of(source)
        if not found[4] and not found[3] and top_level(found[1]) in FORBIDDEN_MODULES
    ]


def _is_root_name(node):
    return (isinstance(node, ast.Name) and node.id in ROOT_NAMES) or (
        isinstance(node, ast.Attribute) and node.attr in ROOT_NAMES
    )


def root_concatenations(tree):
    """Lines where a router root is joined: root + x, f"{root}...", "..." % root, os.path.join(root, ...)."""
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            if _is_root_name(node.left) or _is_root_name(node.right):
                lines.append(node.lineno)
        elif isinstance(node, ast.JoinedStr):
            if any(isinstance(part, ast.FormattedValue) and _is_root_name(part.value) for part in node.values):
                lines.append(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join":
            if any(_is_root_name(argument) for argument in node.args):
                lines.append(node.lineno)
    return sorted(set(lines))


def root_path_references(tree):
    return sorted(
        node.lineno
        for node in ast.walk(tree)
        if (isinstance(node, ast.Name) and node.id == "root_path")
        or (isinstance(node, ast.Attribute) and node.attr == "root_path")
    )


def process_control(tree):
    """(line, what) of the exits and signal calls of a module: SystemExit, sys.exit, os._exit, signal.signal."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "SystemExit":
            found.append((node.lineno, "SystemExit"))
        elif isinstance(node, ast.Attribute):
            owner = node.value.id if isinstance(node.value, ast.Name) else None
            if (owner, node.attr) in {("sys", "exit"), ("os", "_exit"), ("signal", "signal"), ("_signal", "signal")}:
                found.append((node.lineno, f"{owner}.{node.attr}"))
    return sorted(found)


def focused_bridge_lines(path, tree):
    """Only the adapter's two exact lazy read-only edges; mixed imports remain forbidden."""
    if path != WEB_DIR / 'infra' / 'engine.py':
        return set()
    grouped = {}
    for row in imports_of(tree):
        grouped.setdefault(row[0], []).append(row)
    return {line for line, rows in grouped.items() if all(
        module == 'kdn.engine' and name in ('import_worker', 'snapshot_store') and level == 0 and in_function
        for _line, module, name, level, in_function in rows)}


def package_files_exist():
    return ENGINE_DIR.is_dir()


class EngineStructureTests(unittest.TestCase):
    def test_the_engine_package_exists(self):
        self.assertTrue(package_files_exist())
        names = {path.name for path in engine_files()}
        for name in ("__init__.py", "__main__.py", "cli.py", "console.py", "legacy.py", "lifecycle.py", "findings.py"):
            self.assertIn(name, names)

    def test_engine_and_web_do_not_import_each_other(self):
        problems = []
        for path in engine_files():
            problems.extend(
                f"{path.relative_to(ROOT)}:{line}: the engine imports the panel"
                for line in links_to(parse(path), "kdn.web")
            )
        for path in web_files():
            tree = parse(path)
            allowed = focused_bridge_lines(path, tree)
            problems.extend(
                f"{path.relative_to(ROOT)}:{line}: the panel imports the engine"
                for line in links_to(tree, "kdn.engine") if line not in allowed
            )
        self.assertEqual(problems, [])

    def test_engine_modules_use_only_the_stdlib_and_kdn(self):
        problems = [
            f"{path.relative_to(ROOT)}:{line}: imports {module}"
            for path in engine_files()
            for line, module in foreign_imports(parse(path))
        ]
        self.assertEqual(problems, [])

    def test_engine_modules_do_not_import_the_slow_modules_at_module_level(self):
        problems = [
            f"{path.relative_to(ROOT)}:{line}: imports {module} at module level (rule 9)"
            for path in engine_files()
            for line, module in slow_module_imports(parse(path))
        ]
        self.assertEqual(problems, [])

    def test_path_concatenation_only_in_engine_config(self):
        problems = []
        for path in engine_files():
            tree = parse(path)
            problems.extend(
                f"{path.relative_to(ROOT)}:{line}: root_path is not used" for line in root_path_references(tree)
            )
            if path != ENGINE_CONFIG:
                problems.extend(
                    f"{path.relative_to(ROOT)}:{line}: the router root is joined outside config.py"
                    for line in root_concatenations(tree)
                )
        self.assertEqual(problems, [])
        if ENGINE_CONFIG.exists():
            self.assertTrue(root_concatenations(parse(ENGINE_CONFIG)), "config.py joins no root to a logical path")

    def test_engine_modules_have_a_layer(self):
        import test_panel_structure

        problems = []
        for path in engine_files():
            if path.name == "__init__.py":
                continue
            name = "kdn.engine." + path.relative_to(ENGINE_DIR).with_suffix("").as_posix().replace("/", ".")
            layer = test_panel_structure.LAYERS.get(name)
            if layer is None:
                problems.append(f"{name} has no layer in LAYERS")
            elif not 10 <= layer <= 16:
                problems.append(f"{name} is on layer {layer}; the engine owns layers 10-16")
        self.assertEqual(problems, [])

    def test_only_the_entry_point_and_lifecycle_end_the_process_or_set_handlers(self):
        problems = [
            f"{path.relative_to(ROOT)}:{line}: {what}"
            for path in engine_files()
            if path.name not in EXIT_FILES
            for line, what in process_control(parse(path))
        ]
        self.assertEqual(problems, [])

    def test_only_the_entry_point_installs_the_handlers(self):
        problems = [
            f"{path.relative_to(ROOT)}:{node.lineno}: install_signal_handlers is called outside __main__"
            for path in engine_files()
            if path.name != "__main__.py"
            for node in ast.walk(parse(path))
            if isinstance(node, ast.Call)
            and getattr(node.func, "attr", getattr(node.func, "id", None)) == "install_signal_handlers"
        ]
        self.assertEqual(problems, [])

    def test_every_mode_module_defines_run(self):
        for name in ("status", "checks", "profiles", "snapshots", "preflight", "plan"):
            with self.subTest(module=name):
                body = parse(ENGINE_DIR / f"{name}.py").body
                self.assertIn("run", [node.name for node in body if isinstance(node, ast.FunctionDef)])


class ScanSelfTests(unittest.TestCase):
    def test_the_scans_see_planted_violations(self):
        self.assertEqual(links_to("from kdn.web.infra import config", "kdn.web"), [1])
        self.assertEqual(links_to("import kdn.web.app", "kdn.web"), [1])
        self.assertEqual(links_to("from kdn import engine", "kdn.engine"), [1])
        self.assertEqual(links_to("from kdn.engine import cli", "kdn.engine"), [1])
        self.assertEqual(links_to("def f():\n    import kdn.engine.cli", "kdn.engine"), [2])
        self.assertEqual(foreign_imports("import requests"), [(1, "requests")])
        self.assertEqual(foreign_imports("from yaml import safe_load"), [(1, "yaml")])
        self.assertEqual(foreign_imports("from . import cli"), [(1, ".")])
        self.assertEqual(slow_module_imports("import dataclasses"), [(1, "dataclasses")])
        self.assertEqual(slow_module_imports("from typing import Any"), [(1, "typing")])
        self.assertEqual(slow_module_imports("import logging.handlers"), [(1, "logging.handlers")])
        self.assertEqual(slow_module_imports("from enum import Enum"), [(1, "enum")])
        for source, line in (
            ('x = root + "/opt/etc"', 1),
            ('x = "/opt/etc" + self.root', 1),
            ('x = f"{test_root}/opt/etc"', 1),
            ('x = "%s/opt" % TEST_ROOT', 1),
            ('x = os.path.join(test_root, "opt")', 1),
            ('\n\nx = paths.test_root + "/opt"', 3),
        ):
            with self.subTest(source=source):
                self.assertEqual(root_concatenations(ast.parse(source)), [line])
        self.assertEqual(root_path_references(ast.parse("x = paths.root_path")), [1])
        self.assertEqual(root_path_references(ast.parse("paths.root_path('/opt')")), [1])
        self.assertEqual(root_path_references(ast.parse("x = root_path('/opt')")), [1])
        for source, what in (
            ("raise SystemExit(1)", "SystemExit"),
            ("sys.exit(1)", "sys.exit"),
            ("os._exit(1)", "os._exit"),
            ("signal.signal(2, h)", "signal.signal"),
            ("_signal.signal(2, h)", "_signal.signal"),
        ):
            with self.subTest(source=source):
                self.assertEqual([item[1] for item in process_control(ast.parse(source))], [what])

    def test_only_two_exact_lazy_adapter_bridges_are_allowed(self):
        adapter = WEB_DIR / 'infra' / 'engine.py'
        for name in ('import_worker', 'snapshot_store'):
            source = 'def read():\n    from kdn.engine import ' + name
            self.assertEqual(focused_bridge_lines(adapter, ast.parse(source)), {2})
            self.assertEqual(focused_bridge_lines(WEB_DIR / 'domain' / 'automation.py', ast.parse(source)), set())
        for source in ('from kdn.engine import snapshot_store',
                       'def read():\n    from kdn.engine import snapshot_store, cli',
                       'def read():\n    from kdn.engine import import_ops',
                       'def read():\n    import kdn.engine.snapshot_store',
                       'def read():\n    from kdn.engine.snapshot_store import restore_files'):
            self.assertTrue(links_to(source, 'kdn.engine'))
            self.assertEqual(focused_bridge_lines(adapter, ast.parse(source)), set())

    def test_the_scans_pass_clean_code(self):
        self.assertEqual(links_to("from kdn.web.infra import engine", "kdn.engine"), [])
        self.assertEqual(links_to("from kdn.common import proc", "kdn.web"), [])
        clean = "from __future__ import annotations\nimport os\nfrom kdn.common import proc"
        self.assertEqual(foreign_imports(clean), [])
        self.assertEqual(slow_module_imports("def f():\n    import tempfile\n    import shutil"), [])
        self.assertEqual(slow_module_imports("import json\nimport re\nimport subprocess"), [])
        for source in (
            "x = a + b",
            'x = f"{name}/opt"',
            'x = root_dir + "/opt"',
            'x = os.path.join(directory, "opt")',
            "x = paths.test_root(environ)",
        ):
            with self.subTest(source=source):
                self.assertEqual(root_concatenations(ast.parse(source)), [])
        self.assertEqual(process_control(ast.parse("code = main()\nprint(exit_code)")), [])


def importtime_modules(args, env_extra=None, cwd=None):
    """Top-level names of the modules a fresh interpreter loads running ``python -X importtime -P args``."""
    env = {name: value for name, value in os.environ.items() if not name.startswith(("KDN_ENGINE", "PYTHON"))}
    env["PYTHONPATH"] = str(ROUTER_DIR)
    env.update(env_extra or {})
    result = subprocess.run(
        [sys.executable, "-X", "importtime", "-P", *args],
        env=env,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=120,
    )
    names = set()
    for line in result.stderr.decode("utf-8", errors="replace").splitlines():
        if line.startswith("import time:") and "|" in line:
            names.add(line.rsplit("|", 1)[1].strip())
    names.discard("imported package")
    return result, names


class ImportBudgetTests(unittest.TestCase):
    """Rule 9 (R7): a router needs seconds to import dataclasses, typing, tempfile and the like."""

    @classmethod
    def setUpClass(cls):
        _, cls.baseline = importtime_modules(["-c", "pass"])

    def offenders(self, names):
        # R11: re, json, subprocess and pathlib load enum themselves, so it is banned as a direct import only.
        return sorted({top_level(name) for name in names - self.baseline} & (FORBIDDEN_MODULES - {"enum"}))

    def test_the_interpreter_starts_clean(self):
        self.assertEqual(sorted({top_level(name) for name in self.baseline} & FORBIDDEN_MODULES), [])

    def test_mode_imports_stay_within_budget(self):
        result, names = importtime_modules(["-c", "import kdn.engine.cli"])
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace")[-2000:])
        for module in ("kdn.engine.cli", "kdn.engine.console", "kdn.engine.legacy", "kdn.engine.status"):
            self.assertIn(module, names)
        self.assertEqual(self.offenders(names), [], "importing kdn.engine.cli loads slow modules")

        with tempfile.TemporaryDirectory() as tmp:
            result, names = importtime_modules(
                ["-m", "kdn.engine", "--print-plan"],
                env_extra={"KD_TEST_ROOT": tmp, "KD_ALLOW_TEST_ROOT": "1", "KDN_ENGINE_SCRIPT_DIR": str(ROOT)},
            )
        # The run ends in the shell engine (exec); only the interpreter that was running matters here.
        for module in ("kdn.engine.cli", "kdn.engine.lifecycle", "kdn.engine.plan"):
            self.assertIn(module, names)
        self.assertEqual(self.offenders(names), [], "python -m kdn.engine --print-plan loads slow modules")

    def test_the_budget_check_sees_a_slow_import(self):
        _, names = importtime_modules(["-c", "import kdn.engine.cli, dataclasses, tempfile"])
        self.assertLessEqual({"dataclasses", "tempfile"}, set(self.offenders(names)))


if __name__ == "__main__":
    unittest.main()
