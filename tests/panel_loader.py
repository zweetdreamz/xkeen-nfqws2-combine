"""Shared loader for the web panel embedded in xkeen_control_script.sh.

The installer writes the panel as a heredoc between ``<<'PYEOF'`` and
``PYEOF``. Tests extract that source, write it to ``tests/.generated/``
and compile it with that real filename so coverage.py can attribute lines
(``coverage run --include='tests/.generated/*'``). Every call execs into a
fresh namespace; ``__name__`` is not ``"__main__"``, so no server starts.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "router" / "xkeen_control_script.sh"
GENERATED_DIR = Path(__file__).resolve().parent / ".generated"
GENERATED_APP = GENERATED_DIR / "panel_app.py"


def panel_source():
    installer = INSTALLER.read_text(encoding="utf-8")
    return installer.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF\n", 1)[0]


def write_generated_app():
    source = panel_source() + "\n"
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    try:
        current = GENERATED_APP.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = None
    if current != source:
        GENERATED_APP.write_text(source, encoding="utf-8")
    return source


def load_panel_namespace(name="panel_import_test"):
    source = write_generated_app()
    namespace = {"__name__": name}
    exec(compile(source, str(GENERATED_APP), "exec"), namespace)
    return namespace
