"""Fixtures of the panel tests: autotune reports and candidates, the base class of the unit tests, shared paths."""

import hashlib
import os
from pathlib import Path
import stat
import tempfile

import panel_harness


REPO = Path(__file__).resolve().parents[1]
DIAGNOSTICS_MODULE = REPO / "tools" / "router" / "xkeen_diagnostics.py"

VALID_ARGS = {
    "youtube": [
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
        "--payload=tls_client_hello",
        "--lua-desync=multisplit:pos=1",
        "--new",
        "--filter-udp=443",
        "--filter-l7=quic",
        "--hostlist=/opt/etc/nfqws2/lists/youtube.list",
        "--payload=quic_initial",
        "--lua-desync=fake:blob=quic_google:repeats=6",
    ],
    "discord-tcp": [
        "--filter-tcp=443",
        "--filter-l7=tls",
        "--hostlist=/opt/etc/nfqws2/lists/user.list",
        "--payload=tls_client_hello",
        "--lua-desync=multisplit:pos=1",
    ],
    "discord-voice": [
        "--filter-udp=50000-50100",
        "--filter-l7=stun,discord",
        "--payload=stun,discord_ip_discovery",
        "--lua-desync=fake:blob=discord_udp:repeats=6",
    ],
}


def expected_candidate_id(service, source_name, family, args):
    serialized = "\n".join((service, source_name, family, *args))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]


_DEFAULT = object()


def make_candidate(service="discord-tcp", args=_DEFAULT, **overrides):
    candidate = {
        "service": service,
        "source_name": "general (ALT).bat",
        "source_sha": "a" * 40,
        "source_url": "https://example.invalid/general.bat",
        "family": "fixture-family",
        "rank": 3,
        "notes": ["fixture note"],
        "args": (
            list(VALID_ARGS.get(service, VALID_ARGS["discord-tcp"]))
            if args is _DEFAULT
            else (list(args) if isinstance(args, list) else args)
        ),
    }
    candidate.update(overrides)
    if "candidate_id" not in overrides:
        try:
            candidate["candidate_id"] = expected_candidate_id(
                candidate["service"],
                candidate["source_name"],
                candidate["family"],
                candidate["args"],
            )
        except TypeError:
            candidate["candidate_id"] = "0" * 12
    return candidate


def make_report(service="discord-tcp", candidate=None, **overrides):
    report = {
        "report_format": 1,
        "created_utc": "2026-08-15T00:00:00Z",
        "repository": "fixture/repository",
        "ref": "main",
        "commit": "abc1234",
        "search_seed": 42,
        "service": service,
        "found": candidate if candidate is not None else make_candidate(service),
    }
    report.update(overrides)
    return report


def tree_digest(root) -> dict[str, tuple[int, int, str]]:
    """Every path under ``root`` -> (size, st_mtime_ns, sha256): a tree equal before and after was not written.

    Directories have size 0 and an empty hash, and their mtime changes with each entry added or removed. A link
    is not followed: its hash is that of the target it names.
    """
    base = Path(root)
    digest = {}
    for directory, directories, files in os.walk(base):
        for name in directories + files:
            path = Path(directory, name)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                entry = (info.st_size, info.st_mtime_ns, hashlib.sha256(os.readlink(path).encode()).hexdigest())
            elif stat.S_ISREG(info.st_mode):
                entry = (info.st_size, info.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                entry = (0, info.st_mtime_ns, "")
            digest[path.relative_to(base).as_posix()] = entry
    return digest


class PanelUnitCase(panel_harness.PanelTestCase):
    ns_name = "panel_units_test"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def profile(self, service="discord-tcp"):
        return self.ns["validate_report"](make_report(service))
