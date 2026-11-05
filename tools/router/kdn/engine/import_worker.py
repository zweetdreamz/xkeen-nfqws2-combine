"""Bounded identity of focused engine workers, including the pre-lock version gate."""
import os
import re
from pathlib import Path

from kdn.engine import options


_PROC_ROOT = Path('/proc')
_MAX_PROCESSES = 8192
_MAX_COMMAND = 65536
_MAX_ENVIRON = 1024 * 1024


def _read(path, limit):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('process identity exceeds bound')
    return raw


def _identity(path):
    fields = _read(path / 'stat', 8192).rsplit(b') ', 1)[1].split()
    return fields[0], fields[19]  # state and starttime, immune to spaces in comm


def active(launcher, *, exclude_pid=None):
    """True own live mutation, False proven absent, None incomplete/unknown scan.

    Never return, log or persist argv/environment. Only matching native module
    candidates need environment reads; unrelated interpreters are not workers.
    """
    launcher = Path(launcher).absolute()
    expected = {'KDN_ENGINE_SCRIPT': str(launcher), 'KDN_ENGINE_SCRIPT_DIR': str(launcher.parent),
                'KDN_ENGINE_ADDED_PYTHONPATH': str(launcher.parent / 'tools/router')}
    unknown = False
    try:
        with os.scandir(_PROC_ROOT) as entries:
            count = 0
            for entry in entries:
                if not entry.name.isdigit() or int(entry.name) == exclude_pid:
                    continue
                count += 1
                if count > _MAX_PROCESSES:
                    return None
                path = _PROC_ROOT / entry.name
                try:
                    before = _identity(path)
                    if before[0] in (b'Z', b'X'):
                        continue
                    argv = [os.fsdecode(item) for item in _read(path / 'cmdline', _MAX_COMMAND).rstrip(b'\0').split(b'\0')]
                    offset = 2 if len(argv) > 1 and argv[1] == '-P' else 1
                    native = (re.fullmatch(r'python(?:[0-9]+(?:\.[0-9]+)?)?', Path(argv[0]).name) is not None
                              and argv[offset:offset + 2] == ['-m', 'kdn.engine'])
                    legacy = len(argv) >= 2 and Path(argv[0]).name in ('sh', 'dash', 'ash', 'bash') and argv[1] == str(launcher)
                    if not (native or legacy):
                        continue
                    parsed = options.parse_args(argv[offset + 2:] if native else argv[2:])
                    if parsed.mode not in ('apply-import-profile', 'clear-imported-profile', 'rollback-import'):
                        continue
                    if native:
                        raw = _read(path / 'environ', _MAX_ENVIRON)
                        values = {}
                        for item in raw.split(b'\0'):
                            key, _, value = item.partition(b'=')
                            name = os.fsdecode(key)
                            if name in expected or name == 'PYTHONPATH':
                                if name in values:
                                    raise ValueError('ambiguous launcher identity')
                                values[name] = os.fsdecode(value)
                        if any(values.get(key) != value for key, value in expected.items()):
                            # Missing proof is unknown; an explicit different project is foreign.
                            if not all(key in values for key in expected):
                                unknown = True
                            continue
                        if values.get('PYTHONPATH', '').split(os.pathsep)[0] != expected['KDN_ENGINE_ADDED_PYTHONPATH']:
                            unknown = True
                            continue
                    after = _identity(path)
                    if before != after:
                        unknown = True
                        continue
                    return True
                except FileNotFoundError:
                    continue  # vanished process
                except options.ArgError:
                    continue
                except (OSError, ValueError, IndexError):
                    unknown = True
    except OSError:
        return None
    return None if unknown else False
