"""Router-like root of the engine tests: the Python face of tests/engine-root-fixture.sh.

``make_root`` builds, with the same shell function that tests/routing-modes-lib.sh uses for the shell suites, a
tree of a router with XKeen (Xray) and nfqws2-keenetic, plus the mocks of the router commands; ``Fixture`` is the
handle on it. The module does not import ``kdn``.

Paths inside the root are written the way the script writes them: the root, then the logical path
(``/opt/etc/...``), joined as strings.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re

import engine_shell


PROJECT = engine_shell.ROOT
DEFAULT_BLOB_SOURCE = "/opt/etc/nfqws2/blobs"
XKEEN_INIT = "/opt/etc/init.d/S05xkeen"
NFQWS_CONF = "/opt/etc/nfqws2/nfqws2.conf"
STATE_ROOT = "/opt/etc/keenetic-discord-nfqws2"

_BUILD_SCRIPT = """\
set -eu
SCRIPT_DIR="$KDN_FIXTURE_SCRIPT_DIR"
. "$SCRIPT_DIR/tests/engine-root-fixture.sh"
engine_build_root "$KDN_FIXTURE_ROOT" "$KDN_FIXTURE_MOCK_BIN" "$KDN_FIXTURE_BLOB_SOURCE"
"""
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _encode(text):
    return text.encode("utf-8", errors="surrogateescape")


def _decode(data):
    return data.decode("utf-8", errors="surrogateescape")


@dataclass(frozen=True)
class Fixture:
    """A built root (``root``) and the directory with the router command mocks (``mock_bin``)."""

    root: Path
    mock_bin: Path

    @property
    def env(self):
        """A new environment dictionary: the shell engine on this root, with the mocks first on ``PATH``."""
        env = dict(os.environ)
        env["KD_TEST_ROOT"] = str(self.root)
        env["KD_ALLOW_TEST_ROOT"] = "1"
        env["PATH"] = f"{self.mock_bin}{os.pathsep}{os.environ.get('PATH', os.defpath)}"
        env["KDN_ENGINE_SCRIPT_DIR"] = str(PROJECT)
        return env

    def path(self, logical):
        """The path of the logical path ``/opt/...`` inside the root (string concatenation, as ``root_path``)."""
        if not logical.startswith("/"):
            raise ValueError(f"a logical path starts with '/': {logical!r}")
        return Path(f"{self.root}{logical}")

    def write(self, logical, text):
        """Writes ``text`` (UTF-8, surrogateescape, no newline translation) and creates the directories."""
        return self.write_bytes(logical, _encode(text))

    def write_bytes(self, logical, data):
        path = self.path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def set_init(self, key, value):
        """Sets ``key="value"`` in the init script of XKeen; a missing key goes after the last assignment."""
        if not _KEY.match(key):
            raise ValueError(f"bad key {key!r}")
        if '"' in value or "\n" in value:
            raise ValueError(f"the value {value!r} cannot sit in a double-quoted line")
        path = self.path(XKEEN_INIT)
        lines = _decode(path.read_bytes()).split("\n")
        line = f'{key}="{value}"'
        for index, current in enumerate(lines):
            if current.startswith(f"{key}="):
                lines[index] = line
                break
        else:
            last = max(index for index, current in enumerate(lines) if _ASSIGNMENT.match(current))
            lines.insert(last + 1, line)
        path.write_bytes(_encode("\n".join(lines)))

    def set_conf(self, text):
        """Replaces the whole nfqws2.conf."""
        return self.write(NFQWS_CONF, text)

    def write_pointer(self, name, snapshot_name, directory="snapshots"):
        """Writes the pointer ``name`` (``baseline.ptr``; the suffix may be left out) to ``directory/snapshot_name``.

        The pointer holds the absolute path inside the root, as ``atomic_pointer`` writes it, mode 600. The snapshot
        itself is not created.
        """
        if not name.endswith(".ptr"):
            name += ".ptr"
        target = f"{self.root}{STATE_ROOT}/{directory}/{snapshot_name}"
        path = self.write(f"{STATE_ROOT}/{name}", f"{target}\n")
        path.chmod(0o600)
        return path


def make_root(tmp, blob_source=None):
    """Builds a root and a mock directory in ``tmp`` (``tmp/root``, ``tmp/bin``) and returns the ``Fixture``.

    ``blob_source`` (default: ``$NFQWS_TEST_BLOB_SOURCE``, else the Entware directory) supplies the nfqws2 blobs;
    a blob it lacks is replaced by a placeholder file.
    """
    tmp = Path(tmp)
    root = tmp / "root"
    mock_bin = tmp / "bin"
    if blob_source is None:
        blob_source = os.environ.get("NFQWS_TEST_BLOB_SOURCE", DEFAULT_BLOB_SOURCE)
    env = dict(os.environ)
    env["KDN_FIXTURE_SCRIPT_DIR"] = str(PROJECT)
    env["KDN_FIXTURE_ROOT"] = str(root)
    env["KDN_FIXTURE_MOCK_BIN"] = str(mock_bin)
    env["KDN_FIXTURE_BLOB_SOURCE"] = str(blob_source)
    result = engine_shell.run_sh(_BUILD_SCRIPT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"engine_build_root failed with {result.returncode}: {result.stderr}")
    return Fixture(root=root, mock_bin=mock_bin)
