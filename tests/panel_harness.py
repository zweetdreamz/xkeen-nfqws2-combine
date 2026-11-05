"""Test harness of the web panel: generations of the kdn modules and one read-only facade over their names.

``load_panel()`` imports a fresh generation of the panel: it drops ``kdn`` and ``kdn.*`` from ``sys.modules``
and imports ``kdn.web.app`` again. Every test class so gets its own locks, module caches, ``AUTOMATION_CANCEL``
and ``Handler``, as a fresh exec of the monolith gave. ``__name__`` is the module name, not ``"__main__"``, so
no server starts, and the real import keeps coverage on the real files. Each generation is imported with its own
test root (``KD_TEST_ROOT``, ``ns.root``): every router path of ``kdn.web.infra.config`` lies under it, so a path
a test forgets to patch never reaches /opt.

``load_modules(*names)`` makes the same kind of generation from the named modules and what they import, without
``kdn.web.app``; a test class lists the modules in ``PanelTestCase.modules`` and tests them in isolation.

``PanelNamespace`` maps a panel name to the attribute of the module that defines it at top level, its owner.
Panel modules reach each other through module attributes at call time (``proc.run_command(...)``), so a patch
of the owner's attribute is seen by every caller, as a patch of the monolith's globals was. The facade only
reads (``ns["X"]``); every write raises TypeError, and tests patch through ``PanelTestCase.patch/patched/
patch_class``, which patch the owner's attribute with ``mock.patch.object``.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator, Mapping
import contextlib
import functools
from http.server import ThreadingHTTPServer
import importlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from types import MappingProxyType, ModuleType
from typing import Any
import unittest
from unittest import mock
import urllib.request
import weakref


ROOT = Path(__file__).resolve().parents[1]
ROUTER_DIR = (ROOT / "tools" / "router").resolve()
PACKAGE_DIR = ROUTER_DIR / "kdn"
APP = PACKAGE_DIR / "web" / "app.py"
ENTRY_MODULE = "kdn.web.app"
# The environment a generation is imported with: KD_TEST_ROOT is set to its own root, XKEEN_PROJECT_DIR is dropped
# so that the project directory lies under that root too.
TEST_ROOT_ENV = "KD_TEST_ROOT"
ALLOW_TEST_ROOT_ENV = "KD_ALLOW_TEST_ROOT"
PROJECT_DIR_ENV = "XKEEN_PROJECT_DIR"

# Shared stdlib objects the tests reach through the facade (ns["subprocess"].Popen, ...). They are not panel
# names: the helpers refuse to replace them, patch their attributes with mock.patch.object instead.
STDLIB_NAMES = MappingProxyType({
    "subprocess": subprocess,
    "threading": threading,
    "time": time,
    "secrets": secrets,
    "urllib": urllib,
    "sys": sys,
    "os": os,
    "json": json,
    "ThreadingHTTPServer": ThreadingHTTPServer,
})
# Imported names the tests patch: name -> (anchor, attribute), the attribute of the module that owns the
# anchor. The anchor moves with the code that uses the name, so the alias follows a move without edits.
ALIASES = MappingProxyType({
    "datetime": ("automation_loop", "datetime"),
})


def top_level_names(module: ModuleType) -> frozenset[str]:
    """Names the module's source defines at top level, also inside top-level compound statements.

    Counted: def, class, ``type``, assignment targets (also of for, with, match and ``:=``). Not counted: imports,
    which only borrow a name, and dunder names. The source is read through ``__spec__.origin``, not ``__file__``.
    """
    origin = getattr(getattr(module, "__spec__", None), "origin", None)
    if not origin or not origin.endswith(".py") or not os.path.isfile(origin):
        return frozenset()
    status = os.stat(origin)
    return _source_names(origin, status.st_mtime_ns, status.st_size)


@functools.cache
def _source_names(origin: str, _mtime_ns: int, _size: int) -> frozenset[str]:
    names: set[str] = set()
    _collect(ast.parse(Path(origin).read_text(encoding="utf-8"), filename=origin).body, names)
    return frozenset(name for name in names if not (name.startswith("__") and name.endswith("__")))


def _collect(statements: Iterable[ast.stmt], names: set[str]) -> None:
    for node in statements:
        _walrus(node, names)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.TypeAlias):
            _bound(node.name, names)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                _bound(target, names)
        elif isinstance(node, ast.AugAssign) or (isinstance(node, ast.AnnAssign) and node.value is not None):
            _bound(node.target, names)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _bound(node.target, names)
            _collect(node.body, names)
            _collect(node.orelse, names)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    _bound(item.optional_vars, names)
            _collect(node.body, names)
        elif isinstance(node, (ast.If, ast.While)):
            _collect(node.body, names)
            _collect(node.orelse, names)
        elif isinstance(node, (ast.Try, ast.TryStar)):
            _collect(node.body, names)
            for handler in node.handlers:
                _collect(handler.body, names)
            _collect(node.orelse, names)
            _collect(node.finalbody, names)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                _pattern(case.pattern, names)
                _collect(case.body, names)


def _bound(target: ast.expr, names: set[str]) -> None:
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _bound(element, names)
    elif isinstance(target, ast.Starred):
        _bound(target.value, names)


def _pattern(pattern: ast.pattern, names: set[str]) -> None:
    for node in ast.walk(pattern):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)


def _walrus(statement: ast.stmt, names: set[str]) -> None:
    """Names a ``:=`` binds in the statement's own expressions (a lambda has a scope of its own)."""
    pending = [
        child
        for child in ast.iter_child_nodes(statement)
        if not isinstance(child, (ast.stmt, ast.excepthandler, ast.match_case))
    ]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.NamedExpr):
            _bound(node.target, names)
        if not isinstance(node, ast.Lambda):
            pending.extend(ast.iter_child_nodes(node))


READ_ONLY = "patch panel names with PanelTestCase.patch/patched/patch_class"


class PanelNamespace(Mapping):
    """Panel names of one generation, each read on the module that defines it. The facade is read-only.

    A public name defined in two modules fails the load; a private one is ambiguous and only reachable
    through ``module(...)``. Writing a name is refused with TypeError, ``mock.patch.dict(ns, ...)`` included:
    ``PanelTestCase.patch/patched/patch_class`` patch the attribute of the owner instead.
    """

    def __init__(self, modules: Mapping[str, ModuleType], root: Path | None = None) -> None:
        # The test root load_panel imported the generation with; None for other module sets.
        self.root = root
        self._modules = dict(sorted(modules.items()))
        defined: dict[str, list[str]] = {}
        for module_name, module in self._modules.items():
            for name in sorted(top_level_names(module)):
                defined.setdefault(name, []).append(module_name)
        clashes = {name: owners for name, owners in defined.items() if len(owners) > 1}
        public = sorted(name for name in clashes if not name.startswith("_"))
        if public:
            raise RuntimeError(
                "panel names defined in several modules: "
                + "; ".join(f"{name} in {', '.join(clashes[name])}" for name in public)
            )
        self._ambiguous = clashes
        self._owners = {
            name: self._modules[owners[0]]
            for name, owners in defined.items()
            if len(owners) == 1 and name in vars(self._modules[owners[0]])
        }

    def __repr__(self) -> str:
        return f"<PanelNamespace of {', '.join(self._modules)}>"

    @property
    def modules(self) -> Mapping[str, ModuleType]:
        """Modules of this generation by full name."""
        return MappingProxyType(self._modules)

    def module(self, name: str) -> ModuleType:
        """Module of this generation by full name or by an unambiguous dotted suffix ("app", "infra.config")."""
        if name in self._modules:
            return self._modules[name]
        matches = [full for full in self._modules if full.endswith("." + name)]
        if len(matches) == 1:
            return self._modules[matches[0]]
        if matches:
            raise KeyError(f"ambiguous panel module {name!r}: {', '.join(matches)}")
        raise KeyError(f"unknown panel module {name!r}")

    def owner(self, name: str) -> tuple[ModuleType, str]:
        """(module, attribute) that holds the panel name: what PanelTestCase.patch patches."""
        target = self._target(name)
        if target is not None:
            return target
        if name in STDLIB_NAMES:
            raise TypeError(self._shared(name))
        raise self._missing(name)

    def __getitem__(self, name: str) -> Any:
        target = self._target(name)
        if target is not None:
            return getattr(*target)
        if name in STDLIB_NAMES:
            return STDLIB_NAMES[name]
        raise self._missing(name)

    def __iter__(self) -> Iterator[str]:
        names = dict.fromkeys(self._owners)
        names.update(dict.fromkeys(name for name in ALIASES if self._target(name) is not None))
        names.update(dict.fromkeys(STDLIB_NAMES))
        return iter(names)

    def __len__(self) -> int:
        return sum(1 for _name in self)

    def __setitem__(self, name: str, value: Any) -> None:
        raise TypeError(READ_ONLY)

    def __delitem__(self, name: str) -> None:
        raise TypeError(READ_ONLY)

    def update(self, *_args: Any, **_values: Any) -> None:
        raise TypeError(READ_ONLY)

    def copy(self) -> dict[str, Any]:
        raise TypeError(READ_ONLY)

    def clear(self) -> None:
        raise TypeError(READ_ONLY)

    def _target(self, name: str) -> tuple[ModuleType, str] | None:
        module = self._owners.get(name)
        if module is not None:
            return module, name
        alias = ALIASES.get(name)
        if alias is not None:
            anchor = self._owners.get(alias[0])
            if anchor is not None and hasattr(anchor, alias[1]):
                return anchor, alias[1]
        return None

    def _missing(self, name: str) -> KeyError:
        if name in self._ambiguous:
            owners = ", ".join(self._ambiguous[name])
            return KeyError(f"ambiguous panel name {name!r}: defined in {owners}; use ns.module(...)")
        return KeyError(f"unknown panel name {name!r}")

    @staticmethod
    def _shared(name: str) -> str:
        return (
            f"{name!r} is the shared stdlib object, not a panel name: "
            f"patch its attributes with mock.patch.object(ns[{name!r}], ...)"
        )


def _generation() -> dict[str, ModuleType]:
    return {name: module for name, module in list(sys.modules.items()) if name == "kdn" or name.startswith("kdn.")}


@contextlib.contextmanager
def _test_root_environment(root: str) -> Iterator[None]:
    names = (TEST_ROOT_ENV, ALLOW_TEST_ROOT_ENV, PROJECT_DIR_ENV)
    saved = {name: os.environ.get(name) for name in names}
    os.environ[TEST_ROOT_ENV] = root
    os.environ[ALLOW_TEST_ROOT_ENV] = "1"
    os.environ.pop(PROJECT_DIR_ENV, None)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _fresh_generation(names: Iterable[str]) -> PanelNamespace:
    """Drop the loaded ``kdn*`` modules, import ``names`` under a fresh test root and wrap what got loaded."""
    for module_name in _generation():
        del sys.modules[module_name]
    router_dir = str(ROUTER_DIR)
    if sys.path[:1] != [router_dir]:
        sys.path[:] = [router_dir, *(entry for entry in sys.path if entry != router_dir)]
    importlib.invalidate_caches()
    root = tempfile.mkdtemp(prefix="kdn-panel-")
    from target_fixture import version_executable
    version_executable(Path(root) / 'opt/sbin/xkeen')
    try:
        with _test_root_environment(root):
            for module_name in names:
                importlib.import_module(module_name)
        ns = PanelNamespace(_generation(), Path(root))
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    weakref.finalize(ns, shutil.rmtree, root, True)
    return ns


def load_panel(name: str = "panel_test") -> PanelNamespace:
    """Import a fresh generation of the panel under a fresh test root and return the facade over its modules.

    The root is a new temporary directory, ``ns.root``; it is removed with the facade. ``name`` is ignored; the
    test classes still pass their ``ns_name``.
    """
    return _fresh_generation((ENTRY_MODULE,))


def load_modules(*names: str) -> PanelNamespace:
    """Like ``load_panel`` for the named modules and their imports only: ``kdn.web.app`` is not loaded."""
    if not names:
        raise ValueError("load_modules needs at least one module name")
    return _fresh_generation(names)


def _patchers(ns: PanelNamespace, values: Mapping[str, Any]) -> list[Any]:
    owners = [(ns.owner(name), value) for name, value in values.items()]
    return [mock.patch.object(module, attribute, value) for (module, attribute), value in owners]


class PanelTestCase(unittest.TestCase):
    """Base class of panel tests: a fresh generation per class, patches on the modules that own the names."""

    ns_name = "panel_test"
    # Modules a class tests on their own: the generation then holds only these and their imports, not the panel.
    modules: tuple[str, ...] = ()
    ns: PanelNamespace

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if isinstance(cls.modules, str):
            raise TypeError(f"{cls.__name__}.modules must be a tuple of module names, not the string {cls.modules!r}")
        cls.ns = load_modules(*cls.modules) if cls.modules else load_panel(cls.ns_name)
        # Generic HTTP/job unit tests assume a supported installation and often
        # replace all subprocess.Popen calls to inspect worker launch ownership.
        # Version integration negatives use load_panel directly, not this base.
        engine = cls.ns._modules.get('kdn.web.infra.engine')
        if engine is not None:
            patcher = mock.patch.object(engine, 'require_supported_target', return_value='2.1.1')
            patcher.start()
            cls.addClassCleanup(patcher.stop)

    def patch(self, **values: Any) -> None:
        """Patch panel names until the end of the test."""
        for patcher in _patchers(self.ns, values):
            patcher.start()
            self.addCleanup(patcher.stop)

    @contextlib.contextmanager
    def patched(self, **values: Any) -> Iterator[PanelNamespace]:
        """Patch panel names for the with block; yields the namespace."""
        with contextlib.ExitStack() as stack:
            for patcher in _patchers(self.ns, values):
                stack.enter_context(patcher)
            yield self.ns

    def fresh_root(self) -> Path:
        """Empty the test root of this generation (where the panel's router paths lie) and return it."""
        root = self.ns.root
        for entry in root.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        from target_fixture import version_executable
        version_executable(root / 'opt/sbin/xkeen')
        return root

    @classmethod
    def patch_class(cls, **values: Any) -> None:
        """Patch panel names until the class cleanups, after tearDownClass."""
        for patcher in _patchers(cls.ns, values):
            patcher.start()
            cls.addClassCleanup(patcher.stop)
