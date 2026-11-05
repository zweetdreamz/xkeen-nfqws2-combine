"""Paths, constants and timeouts of the engine: the values of the head of apply-discord-nfqws2.sh.

The constants are copies of the script's assignments (tests/test_engine_config.py compares them with the script).
The paths follow ``root_path`` of the script: the test root, empty on a router, is joined to the logical path by
plain string concatenation, so a root with a trailing slash or a double slash gives the paths the script prints.
That is why ``kdn.common.paths.root_path`` is not used: it returns a Path and normalises both.
"""

import os
import re

from kdn.common import paths as common_paths
from kdn.engine import legacy


PROJECT = "keenetic-discord-nfqws2"
SCRIPT_VERSION = "3.2.0"

TCP_PORTS_VALUE = "80,443,2053,2083,2087,2096,8443"
UDP_PORTS_FLOWSEAL = "443,3478:3481,5349,19294:19344,50000:50100"
UDP_FILTER_FLOWSEAL = "443,3478-3481,5349,19294-19344,50000-50100"
UDP_PORTS_WIDE = "443,3478:3481,5349,19294:19344,50000:65535"
UDP_FILTER_WIDE = "443,3478-3481,5349,19294-19344,50000-65535"
# XKEEN_REQUIRED_PORTS of the script before --wide-udp and Telegram change it.
XKEEN_REQUIRED_PORTS_NARROW = "80,443,2053,2083,2087,2096,8443,3478:3481,5349,19294:19344,50000:50100"
TELEGRAM_CALL_PORTS = "590:600,1400"
UNBOUND_POLICY_NAME = "__keenetic_discord_nfqws2_unbound__"
NFQWS_DISABLED_HOST = "kdn-disabled.invalid"
DISCORD_UDP_BLOB_SHA256 = "2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf"
YOUTUBE_TLS_BLOB_SHA256 = "936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c"
YOUTUBE_QUIC_BLOB_SHA256 = "f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a"
TELEGRAM_WS_PORT = 18443
# Under a test root the script takes the port of the Telegram relay from this variable.
TELEGRAM_WS_PORT_ENV = "KD_TEST_TELEGRAM_WS_PORT"

# Seconds an external command may run. The values are several times the slowest known run on the router (a MIPS
# Keenetic): xkeen -status takes about 2 s, the whole --status 8 to 10 s and --preflight 15 to 18 s. A hung command
# then ends in a warning or an error instead of holding a mode for ever; xray -test checks a whole config directory
# and gets the most. KDN_ENGINE_TIMEOUT_SCALE multiplies every value for a slower router.
TIMEOUTS = {
    "xkeen_status": 20,
    "xkeen_version": 10,
    "opkg": 20,
    "process": 5,
    "ip": 10,
    "wget": 5,
    "ndmc": 20,
    "xray_test": 90,
    "python_check": 10,
    "compose": 20,
}
SCALE_ENV = "KDN_ENGINE_TIMEOUT_SCALE"
# Ceiling of a scaled timeout, one day: communicate() raises OverflowError ("timeout is too large") from about 2.1e6 s.
MAX_TIMEOUT = 86400
_DECIMAL = re.compile(r"[0-9]+(?:\.[0-9]+)?")

_FIELDS = (
    "state_root",
    "snapshot_root",
    "baseline_pointer",
    "xkeen_baseline_pointer",
    "latest_pointer",
    "lock_dir",
    "xkeen_init",
    "xkeen_hook",
    "nfqws_init",
    "nfqws_conf",
    "nfqws_list",
    "nfqws_pidfile",
    "nfqws_bin",
    "xkeen_dir",
    "xkeen_port_proxying",
    "xkeen_port_exclude",
    "xkeen_json",
    "xray_config_dir",
    "xray_dat_dir",
    "xray_default_bin",
    "mihomo_config",
    "telegram_ws_python",
    "telegram_ws_relay",
    "source_discord_udp_blob",
    "work_tmp_root",
    "script_dir",
    "script",
    "test_root",
)  # fmt: skip


class EnginePaths:
    """The router paths of a run, as strings: the fields have the names of the script's variables in lower case.

    Read-only, compares and hashes by value. ``xkeen_json``, ``xray_default_bin``, ``work_tmp_root`` and ``script``
    have no variable of their own in the script: the config file of XKeen, the Xray binary ``xray_test_config``
    falls back to, the directory of ``WORK_TMP_DIR``, and the script itself.
    """

    __slots__ = _FIELDS

    def __init__(self, **values):
        unknown = sorted(set(values) - set(_FIELDS))
        missing = [name for name in _FIELDS if name not in values]
        if unknown or missing:
            raise TypeError(f"EnginePaths: unknown fields {unknown}, missing fields {missing}")
        for name in _FIELDS:
            object.__setattr__(self, name, values[name])

    def __setattr__(self, name, value):
        raise AttributeError(f"EnginePaths is read-only: {name}")

    def __delattr__(self, name):
        raise AttributeError(f"EnginePaths is read-only: {name}")

    def _values(self):
        return tuple(getattr(self, name) for name in _FIELDS)

    def __eq__(self, other):
        if not isinstance(other, EnginePaths):
            return NotImplemented
        return self._values() == other._values()

    def __hash__(self):
        return hash(self._values())

    def __repr__(self):
        pairs = ", ".join(f"{name}={getattr(self, name)!r}" for name in _FIELDS)
        return f"EnginePaths({pairs})"

    def replace(self, **changes):
        """A copy with the named fields changed."""
        values = {name: getattr(self, name) for name in _FIELDS}
        values.update(changes)
        return EnginePaths(**values)

    @classmethod
    def from_environ(cls, environ=None):
        """The paths for the environment; RuntimeError when KD_TEST_ROOT is set without KD_ALLOW_TEST_ROOT=1."""
        environ = os.environ if environ is None else environ
        root = common_paths.test_root(environ)
        # The directory of the project: from the dispatcher, else where this package lives.
        script_dir = environ.get(legacy.SCRIPT_DIR_ENV) or os.path.dirname(legacy.script_path({}))
        state_root = root + "/opt/etc/keenetic-discord-nfqws2"
        xkeen_dir = root + "/opt/etc/xkeen"
        return cls(
            state_root=state_root,
            snapshot_root=state_root + "/snapshots",
            baseline_pointer=state_root + "/baseline.ptr",
            xkeen_baseline_pointer=state_root + "/baseline-xkeen.ptr",
            latest_pointer=state_root + "/latest-preapply.ptr",
            lock_dir=root + "/opt/tmp/keenetic-discord-nfqws2.lock",
            xkeen_init=root + "/opt/etc/init.d/S05xkeen",
            xkeen_hook=root + "/opt/etc/ndm/netfilter.d/proxy.sh",
            nfqws_init=root + "/opt/etc/init.d/S51nfqws2",
            nfqws_conf=root + "/opt/etc/nfqws2/nfqws2.conf",
            nfqws_list=root + "/opt/etc/nfqws2/lists/user.list",
            nfqws_pidfile=root + "/opt/var/run/nfqws2.pid",
            nfqws_bin=root + "/opt/usr/bin/nfqws2",
            xkeen_dir=xkeen_dir,
            xkeen_port_proxying=xkeen_dir + "/port_proxying.lst",
            xkeen_port_exclude=xkeen_dir + "/port_exclude.lst",
            xkeen_json=xkeen_dir + "/xkeen.json",
            xray_config_dir=root + "/opt/etc/xray/configs",
            xray_dat_dir=root + "/opt/etc/xray/dat",
            xray_default_bin=root + "/opt/sbin/xray",
            mihomo_config=root + "/opt/etc/mihomo/config.yaml",
            telegram_ws_python=root + "/opt/bin/python3",
            telegram_ws_relay=script_dir + "/tools/router/telegram_ws_relay.py",
            source_discord_udp_blob=script_dir + "/config/blobs/ACTIVE_DISCORD_UDP.bin",
            work_tmp_root=root + "/opt/tmp",
            script_dir=script_dir,
            script=legacy.script_path(environ),
            test_root=root,
        )


def list_path(path, test_root):
    """Remap only absolute /opt/ list paths, preserving shell string semantics."""
    real = os.fspath(path)
    return test_root + real if test_root and real.startswith("/opt/") else real


def telegram_ws_port(paths, environ=None):
    """The port of the Telegram relay as the script has it: 18443, or the test override under a test root."""
    environ = os.environ if environ is None else environ
    override = environ.get(TELEGRAM_WS_PORT_ENV, "")
    if paths.test_root and override:
        return override
    return str(TELEGRAM_WS_PORT)


def _scale(environ):
    """The factor of KDN_ENGINE_TIMEOUT_SCALE: a decimal number of at least 1, else 1."""
    text = environ.get(SCALE_ENV, "")
    if not _DECIMAL.fullmatch(text):
        return 1
    scale = float(text)
    return scale if scale >= 1 else 1


def timeout(name, environ=None):
    """Seconds the external command ``name`` may run (a key of TIMEOUTS), times the scale, at most MAX_TIMEOUT."""
    seconds = TIMEOUTS[name]
    environ = os.environ if environ is None else environ
    return min(seconds * _scale(environ), MAX_TIMEOUT)
