"""Tests of tests/panel_harness.py: panel generations, the name facade and the patch helpers."""

from __future__ import annotations

import datetime
import gc
import importlib.util
import inspect
import operator
import os
from pathlib import Path, PurePath
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import panel_harness


def run_case(case):
    """Run one TestCase through unittest (class fixtures and cleanups included) and return the result."""
    result = unittest.TestResult()
    unittest.TestSuite([case]).run(result)
    return result


def synthetic_modules(root, sources):
    """Modules executed from files under root, keyed by the given dotted names, not put in sys.modules."""
    root.mkdir()
    modules = {}
    for name, text in sources.items():
        path = root / (name.replace(".", "_") + ".py")
        path.write_text(text, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


REFUSAL = "patch panel names with PanelTestCase.patch/patched/patch_class"
BINDINGS = """
import contextlib
import json
from os import path as path_alias

__all__ = ["plain"]
__version__ = "1"
type Alias = int


async def coroutine():
    local_in_function = 1
    return local_in_function


class Klass:
    in_class = 1


@contextlib.contextmanager
def pair():
    yield 1, 2


plain = 1
annotated: int = 2
bare: int
head, (second_item, *rest) = 1, (2, 3, 4)
for loop_target, (loop_a, loop_b) in [(1, (2, 3))]:
    in_for = 1
else:
    in_for_else = 1
while False:
    in_while = 1
else:
    in_while_else = 1
with pair() as (first, second), pair() as third:
    in_with = 1
match {"k": 1, "z": 2}:
    case {"k": 1, **mapping_rest}:
        in_case = 1
    case [first_item, *other_items]:
        in_other_case = 1
    case str() as text:
        in_text_case = 1
if (walrus := 1) > 0:
    listed = [(inner := 5) for _ in range(1)]
    for nested_target in (1,):
        with pair() as nested_pair:
            in_nested = 1
try:
    in_try = 1
except OSError as error:
    in_except = 1
else:
    in_try_else = 1
finally:
    in_finally = 1
"""
# What BINDINGS leaves out: imports, dunders, annotation-only names, and every name of a narrower scope.
BOUND = {
    "Alias", "coroutine", "Klass", "pair", "plain", "annotated", "head", "second_item", "rest", "loop_target",
    "loop_a", "loop_b", "in_for", "in_for_else", "in_while", "in_while_else", "first", "second", "third", "in_with",
    "mapping_rest", "first_item", "other_items", "text", "in_case", "in_other_case", "in_text_case", "walrus",
    "listed", "inner", "nested_target", "nested_pair", "in_nested", "in_try", "in_except", "in_try_else", "in_finally",
}


class PanelHarnessTests(panel_harness.PanelTestCase):
    ns_name = "panel_harness_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_every_name_has_exactly_one_owner(self):
        names = [name for name in self.ns if name not in panel_harness.STDLIB_NAMES]
        self.assertIn("run_command", names)
        self.assertIn("Handler", names)
        for name in names:
            with self.subTest(name=name):
                module, attribute = self.ns.owner(name)
                value = self.ns[name]
                self.assertIs(vars(module)[attribute], value)
                if name in panel_harness.ALIASES:
                    continue
                if inspect.isfunction(value) or inspect.isclass(value):
                    # Where Python itself says the object was defined, not where the harness looked it up.
                    self.assertEqual(value.__module__, module.__name__)
                if not name.startswith("_"):
                    holders = [full for full, found in self.ns.modules.items() if name in vars(found)]
                    self.assertEqual(holders, [module.__name__])
        owners = {}
        for module_name, module in self.ns.modules.items():
            for name in panel_harness.top_level_names(module):
                if not name.startswith("_"):
                    owners.setdefault(name, []).append(module_name)
        self.assertEqual({name: found for name, found in owners.items() if len(found) > 1}, {})

    def test_top_level_names_cover_every_binding_statement(self):
        module = synthetic_modules(self.root / "bindings", {"fake.bindings": BINDINGS})["fake.bindings"]
        self.assertEqual(set(panel_harness.top_level_names(module)), BOUND)
        # A name bound inside a compound statement is owned like any other: a second owner fails the load.
        clash = synthetic_modules(self.root / "clash", {
            "fake.one.config": "with open(__file__) as handle:\n    pass\n",
            "fake.two.config": "for handle in ():\n    pass\n",
        })
        with self.assertRaisesRegex(RuntimeError, r"handle in fake\.one\.config, fake\.two\.config"):
            panel_harness.PanelNamespace(clash)

    def test_duplicate_public_name_fails_the_load(self):
        clash = synthetic_modules(self.root / "clash", {
            "fake.one.config": "LIMIT = 1\n",
            "fake.two.config": "if True:\n    LIMIT = 2\n",
        })
        with self.assertRaisesRegex(RuntimeError, r"LIMIT in fake\.one\.config, fake\.two\.config"):
            panel_harness.PanelNamespace(clash)
        modules = synthetic_modules(self.root / "split", {
            "fake.one.config": "_helper = 1\nLIMIT = 1\n__all__ = ['LIMIT']\n",
            "fake.two.config": "_helper = 2\ntry:\n    SIZE = 2\nexcept OSError:\n    SIZE = 0\n",
        })
        # The source is read through __spec__.origin: a patched __file__ does not move an owner.
        modules["fake.one.config"].__file__ = str(self.root / "missing.py")
        ns = panel_harness.PanelNamespace(modules)
        self.assertIs(ns.owner("LIMIT")[0], modules["fake.one.config"])
        self.assertIs(ns.owner("SIZE")[0], modules["fake.two.config"])
        self.assertNotIn("__all__", ns)
        with self.assertRaisesRegex(KeyError, "ambiguous panel name '_helper'"):
            ns["_helper"]
        with self.assertRaisesRegex(KeyError, "ambiguous panel module 'config'"):
            ns.module("config")
        self.assertIs(ns.module("two.config"), modules["fake.two.config"])
        with self.assertRaisesRegex(KeyError, "unknown panel module 'three'"):
            ns.module("three")

    def test_patched_sets_and_restores_owner_attributes(self):
        wide_conf = self.root / "nfqws2.conf"
        wide_conf.write_text("# Discord UDP: strategy=flowseal, range=wide.\n", encoding="utf-8")
        module, attribute = self.ns.owner("NFQWS_CONFIG")
        before = getattr(module, attribute)
        with self.patched(NFQWS_CONFIG=wide_conf):
            self.assertIs(getattr(module, attribute), wide_conf)
            self.assertEqual(self.ns["recorded_voice_high"](), (65535, "wide"))
        self.assertIs(getattr(module, attribute), before)

    def test_patch_with_unknown_name_changes_nothing(self):
        before = self.ns["NFQWS_CONFIG"]
        with self.assertRaisesRegex(KeyError, "unknown panel name 'NO_SUCH'"):
            with self.patched(NFQWS_CONFIG=self.root / "nfqws2.conf", NO_SUCH=1):
                pass
        self.assertIs(self.ns["NFQWS_CONFIG"], before)
        with self.assertRaises(TypeError):
            self.patch(NFQWS_CONFIG=self.root / "nfqws2.conf", subprocess=object())
        self.assertIs(self.ns["NFQWS_CONFIG"], before)

    def test_facade_is_read_only(self):
        # The writes go through operator and an alias: test_panel_structure refuses the direct forms in tests.
        facade = self.ns
        run_command = self.ns["run_command"]
        port = self.ns["PORT"]
        module, attribute = self.ns.owner("run_command")
        writes = {
            "item assignment": lambda: operator.setitem(facade, "PORT", 1),
            "item deletion": lambda: operator.delitem(facade, "run_command"),
            "stdlib item assignment": lambda: operator.setitem(facade, "subprocess", subprocess),
            "update": lambda: operator.methodcaller("update", {"PORT": 1}, BIND_HOST="10.0.0.1")(facade),
            "copy": facade.copy,
            "clear": lambda: operator.methodcaller("clear")(facade),
            "patch.dict": lambda: mock.patch.dict(facade, {"PORT": 1}).start(),
        }
        for how, write in writes.items():
            with self.subTest(how=how):
                with self.assertRaises(TypeError) as raised:
                    write()
                self.assertEqual(str(raised.exception), REFUSAL)
        self.assertIs(self.ns["run_command"], run_command)
        self.assertIs(getattr(module, attribute), run_command)
        self.assertEqual(run_command.__module__, module.__name__)
        self.assertEqual(self.ns["PORT"], port)
        self.assertIs(self.ns["subprocess"], subprocess)

    def test_stdlib_names_are_shared_and_cannot_be_replaced(self):
        self.assertIs(self.ns["subprocess"], subprocess)
        self.assertIs(self.ns["sys"], sys)
        with self.assertRaisesRegex(TypeError, "shared stdlib object"):
            self.patch(subprocess=object())
        with self.assertRaisesRegex(TypeError, "shared stdlib object"):
            self.patch(subprocess=subprocess)
        with self.assertRaisesRegex(TypeError, "shared stdlib object"):
            self.ns.owner("subprocess")
        self.assertIs(self.ns["subprocess"], subprocess)

    def test_generations_are_isolated(self):
        a, b = panel_harness.load_panel(), panel_harness.load_panel()
        self.assertIsNot(a.module("app"), b.module("app"))
        self.assertIsNot(a.module("app"), self.ns.module("app"))
        self.assertIsNot(a["JOB_START_LOCK"], b["JOB_START_LOCK"])
        port = b["PORT"]
        with mock.patch.object(*a.owner("PORT"), 1):
            self.assertEqual(a["PORT"], 1)
            self.assertEqual(b["PORT"], port)
            self.assertEqual(self.ns["PORT"], port)
        self.assertEqual(a["PORT"], port)

    def test_modules_generation_imports_only_the_named_closure(self):
        ns = panel_harness.load_modules("kdn.web.domain.history")
        self.assertIn("kdn.web.domain.history", ns.modules)
        self.assertIn("kdn.web.infra.config", ns.modules)
        self.assertNotIn("kdn.web.app", ns.modules)
        self.assertNotIn("kdn.web.app", sys.modules)
        self.assertTrue(all(name == "kdn" or name.startswith("kdn.") for name in ns.modules))
        # Nothing of the previous generation is left: every module of the new one is a new object.
        for name, module in ns.modules.items():
            if name in self.ns.modules:
                with self.subTest(module=name):
                    self.assertIsNot(module, self.ns.modules[name])
                    self.assertIs(sys.modules[name], module)
        self.assertEqual(ns.module("history").__name__, "kdn.web.domain.history")
        self.assertIs(ns["route_history"], ns.module("history").route_history)
        with self.assertRaisesRegex(KeyError, "unknown panel module 'app'"):
            ns.module("app")

    def test_modules_class_attribute_switches_the_mode_on(self):
        seen = {}

        class Probe(panel_harness.PanelTestCase):
            modules = ("kdn.web.domain.history",)

            def test_probe(self):
                seen["modules"] = set(self.ns.modules)
                seen["root"] = self.ns.root

        self.assertEqual(panel_harness.PanelTestCase.modules, ())
        result = run_case(Probe("test_probe"))
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertIn("kdn.web.domain.history", seen["modules"])
        self.assertNotIn("kdn.web.app", seen["modules"])
        self.assertTrue(seen["root"].name.startswith("kdn-panel-"))

        class Whole(panel_harness.PanelTestCase):
            def test_probe(self):
                seen["whole"] = set(self.ns.modules)

        result = run_case(Whole("test_probe"))
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertIn("kdn.web.app", seen["whole"])

    def test_modules_given_a_string_is_refused(self):
        class Probe(panel_harness.PanelTestCase):
            modules = "kdn.web.domain.history"

            def test_probe(self):
                self.fail("the generation must not load")

        result = run_case(Probe("test_probe"))
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(result.failures, [])
        self.assertEqual(len(result.errors), 1)
        message = result.errors[0][1]
        self.assertIn("TypeError", message)
        self.assertIn("tuple of module names", message)
        self.assertIn("kdn.web.domain.history", message)
        self.assertNotIn("ModuleNotFoundError", message)

    def test_modules_generation_needs_a_module_and_cleans_up_after_a_failure(self):
        with self.assertRaisesRegex(ValueError, "at least one module"):
            panel_harness.load_modules()
        roots = []
        make_directory = tempfile.mkdtemp

        def remember(*args, **kwargs):
            roots.append(Path(make_directory(*args, **kwargs)))
            return str(roots[-1])

        with mock.patch.object(tempfile, "mkdtemp", remember):
            with self.assertRaises(ModuleNotFoundError):
                panel_harness.load_modules("kdn.web.domain.no_such_module")
        self.assertEqual(len(roots), 1)
        self.assertFalse(roots[0].exists())

    def test_modules_generation_has_its_own_test_root(self):
        ns = panel_harness.load_modules("kdn.web.infra.config")
        cfg = ns.module("infra.config")
        self.assertTrue(ns.root.is_dir())
        self.assertTrue(ns.root.name.startswith("kdn-panel-"))
        self.assertNotEqual(ns.root, self.ns.root)
        self.assertEqual(cfg.LOG_FILE, ns.root / "opt" / "var" / "log" / "xkeen-web.log")
        # ENTRY is the running file; XKEEN may be a binary found on PATH.
        checked, problems = [], []
        for name in sorted(panel_harness.top_level_names(cfg)):
            value = vars(cfg).get(name)
            if name == "ENTRY" or (name == "XKEEN" and value == shutil.which("xkeen")):
                continue
            if isinstance(value, PurePath):
                checked.append(name)
                if not PurePath(value).is_relative_to(ns.root):
                    problems.append(f"{name} = {value}")
        self.assertEqual(problems, [])
        for name in ("LOG_FILE", "NFQWS_CONFIG", "PROJECT_DIR", "ROUTE_JOB_DIR"):
            self.assertIn(name, checked)
        root = ns.root
        del ns, cfg
        gc.collect()
        self.assertFalse(root.exists())

    def test_modules_generation_imports_under_the_environment_of_load_panel(self):
        saved = {"XKEEN_PROJECT_DIR": "/srv/project", "KD_ALLOW_TEST_ROOT": "0"}
        with mock.patch.dict(os.environ, saved):
            os.environ.pop("KD_TEST_ROOT", None)
            ns = panel_harness.load_modules("kdn.web.infra.config")
            self.assertEqual({name: os.environ.get(name) for name in saved}, saved)
            self.assertNotIn("KD_TEST_ROOT", os.environ)
        self.assertEqual(ns["PROJECT_DIR"], ns.root / "opt" / "root" / "keenetic-discord-nfqws2")

    def test_modules_generations_are_isolated(self):
        a = panel_harness.load_modules("kdn.web.infra.config")
        b = panel_harness.load_modules("kdn.web.infra.config")
        self.assertNotEqual(a.root, b.root)
        self.assertIsNot(a.module("infra.config"), b.module("infra.config"))
        port = b["PORT"]
        with mock.patch.object(*a.owner("PORT"), 1):
            self.assertEqual(a["PORT"], 1)
            self.assertEqual(b["PORT"], port)
            self.assertEqual(self.ns["PORT"], port)
        self.assertEqual(a["PORT"], port)
        # The generation of the class is not the module set of a later load.
        self.assertIsNot(self.ns.module("infra.config"), a.module("infra.config"))
        self.assertIn("kdn.web.app", self.ns.modules)

    def test_patch_helper_restores_after_cleanup(self):
        seen = {}

        class Probe(panel_harness.PanelTestCase):
            def test_probe(self):
                seen["before"] = self.ns["PORT"]
                self.patch(PORT=1)
                seen["during"] = getattr(*self.ns.owner("PORT"))

        result = run_case(Probe("test_probe"))
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(seen["during"], 1)
        self.assertNotEqual(seen["before"], 1)
        self.assertEqual(Probe.ns["PORT"], seen["before"])

    def test_patch_class_restores_after_class_cleanups(self):
        seen = {}

        class Probe(panel_harness.PanelTestCase):
            @classmethod
            def setUpClass(cls):
                super().setUpClass()
                seen["before"] = cls.ns["BIND_HOST"]
                cls.patch_class(BIND_HOST="10.0.0.1")

            def test_probe(self):
                seen["during"] = self.ns["BIND_HOST"]

        result = run_case(Probe("test_probe"))
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(seen["during"], "10.0.0.1")
        self.assertEqual(Probe.ns["BIND_HOST"], seen["before"])

    def test_patched_yields_the_namespace_and_checks_every_name_first(self):
        port = self.ns["PORT"]
        with self.patched(PORT=2) as ns:
            self.assertIs(ns, self.ns)
            self.assertEqual(getattr(*ns.owner("PORT")), 2)
        self.assertEqual(self.ns["PORT"], port)
        with self.assertRaises(KeyError):
            self.patch(PORT=3, NO_SUCH=1)
        self.assertEqual(self.ns["PORT"], port)

    def test_datetime_alias_targets_the_automation_module(self):
        class Clock:
            pass

        with self.patched(datetime=Clock) as ns:
            self.assertIs(ns.owner("automation_loop")[0].datetime, Clock)
            self.assertIs(ns["datetime"], Clock)
        self.assertIs(self.ns.owner("automation_loop")[0].datetime, datetime.datetime)

    def test_module_lookup_by_full_or_short_name(self):
        app = self.ns.module("kdn.web.app")
        self.assertIs(self.ns.module("app"), app)
        self.assertIs(self.ns.module("web.app"), app)
        self.assertEqual(app.__spec__.origin, str(panel_harness.APP))
        self.assertTrue(all(name == "kdn" or name.startswith("kdn.") for name in self.ns.modules))

    def test_every_path_constant_lies_under_the_test_root(self):
        # ENTRY is the running file, PROC_ROOT the kernel's process table, ROUTER_PATH the PATH of the child
        # processes and DEFAULT_PROJECT_DIR the logical path root_path() moves; XKEEN may be a binary on PATH.
        exempt = {"ENTRY", "PROC_ROOT", "ROUTER_PATH", "DEFAULT_PROJECT_DIR"}
        root = self.ns.root
        self.assertTrue(root.is_dir())
        checked, problems = [], []
        for module_name, module in self.ns.modules.items():
            for name in sorted(panel_harness.top_level_names(module)):
                value = vars(module).get(name)
                if name in exempt or (name == "XKEEN" and value == shutil.which("xkeen")):
                    continue
                if isinstance(value, PurePath) or (isinstance(value, str) and "/opt/" in value):
                    checked.append(f"{module_name}.{name}")
                    if not PurePath(value).is_relative_to(root):
                        problems.append(f"{module_name}.{name} = {value}")
        self.assertEqual(problems, [])
        self.assertIn("kdn.web.infra.config.NFQWS_CONFIG", checked)
        self.assertIn("kdn.web.infra.config.PROJECT_DIR", checked)
        self.assertIn("kdn.web.infra.config.IMPORT_STAGING_DIR", checked)

    def test_generation_imports_under_its_own_test_root(self):
        saved = {"XKEEN_PROJECT_DIR": "/srv/project", "KD_ALLOW_TEST_ROOT": "0"}
        with mock.patch.dict(os.environ, saved):
            os.environ.pop("KD_TEST_ROOT", None)
            ns = panel_harness.load_panel()
            self.assertEqual({name: os.environ.get(name) for name in saved}, saved)
            self.assertNotIn("KD_TEST_ROOT", os.environ)
        root = ns.root
        self.assertTrue(root.is_dir())
        self.assertTrue(root.name.startswith("kdn-panel-"))
        self.assertNotEqual(root, self.ns.root)
        self.assertEqual(ns["PROJECT_DIR"], root / "opt" / "root" / "keenetic-discord-nfqws2")
        del ns
        gc.collect()
        self.assertFalse(root.exists())

    def test_fresh_root_empties_the_test_root(self):
        root = self.ns.root
        (root / "opt" / "etc").mkdir(parents=True)
        (root / "opt" / "etc" / "nfqws2.conf").write_text("x\n", encoding="utf-8")
        (root / "file").write_text("x\n", encoding="utf-8")
        (root / "link").symlink_to(self.root, target_is_directory=True)
        (self.root / "kept").write_text("x\n", encoding="utf-8")
        self.assertEqual(self.fresh_root(), root)
        self.assertTrue(root.is_dir())
        self.assertEqual([p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()], ['opt/sbin/xkeen'])
        self.assertTrue((self.root / "kept").is_file())


if __name__ == "__main__":
    unittest.main()
