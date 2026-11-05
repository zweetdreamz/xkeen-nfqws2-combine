"""Synthetic version-only XKeen executable; never an operational router capture."""
from pathlib import Path
import os
import shlex
import shutil


def version_executable(path, version='XKeen 2.1.1 Stable'):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!/bin/sh\ncase "$1" in\n-v) printf "%s\\n" '
                    + shlex.quote(version) + ' ;;\n*) exit 97 ;;\nesac\n', encoding='utf-8')
    path.chmod(0o700)
    return path


def supported_environment(env):
    """Declare the supported precondition of disposable algorithm-unit roots.

    Never overrides an explicit xkeen executable/version. No production bypass:
    the real gate still executes this version-only stub through the real PATH.
    """
    root = env.get('KD_TEST_ROOT', '')
    if not root or Path(root).resolve() == Path('/'):
        return env
    search = env.get('PATH', os.defpath)
    if shutil.which('xkeen', path=search) is None:
        binary = version_executable(Path(root) / '.target-version-bin/xkeen', 'XKeen 2.1')
        env['PATH'] = str(binary.parent) + os.pathsep + search
    return env


def installer_environment(env, root):
    """Explicit supported installer target, without any production bypass flag."""
    binary = version_executable(Path(root) / '.installer-bin/xkeen', 'XKeen 2.1')
    return {**env, 'PATH': str(binary.parent) + os.pathsep + env.get('PATH', os.defpath)}
