"""Router paths with the single test-root rule of apply-discord-nfqws2.sh."""

import os
from pathlib import Path


TEST_ROOT_ENV = "KD_TEST_ROOT"
ALLOW_TEST_ROOT_ENV = "KD_ALLOW_TEST_ROOT"
PROJECT_DIR_ENV = "XKEEN_PROJECT_DIR"
DEFAULT_PROJECT_DIR = "/opt/root/keenetic-discord-nfqws2"


def test_root(environ=None):
    """Prefix for isolated repository tests; empty on a router. Same rule as the engine."""
    environ = os.environ if environ is None else environ
    root = environ.get(TEST_ROOT_ENV, "")
    if root and environ.get(ALLOW_TEST_ROOT_ENV, "0") != "1":
        raise RuntimeError("KD_TEST_ROOT is reserved for isolated repository tests.")
    return root


def root_path(logical, *, environ=None):
    """Path of an absolute router path (/opt/...) moved under the test root."""
    if not logical.startswith("/"):
        raise ValueError(f"logical path must be absolute: {logical}")
    return Path(test_root(environ) + logical)


def project_dir(environ=None):
    """Directory of the installed project: XKEEN_PROJECT_DIR as is, else the default under the test root."""
    environ = os.environ if environ is None else environ
    configured = environ.get(PROJECT_DIR_ENV)
    if configured is not None:
        return Path(configured)
    return root_path(DEFAULT_PROJECT_DIR, environ=environ)
