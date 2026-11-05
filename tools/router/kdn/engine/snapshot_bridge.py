"""Narrow safety bridge called by the shell engine under its existing lock.

This is not a second transaction owner and never acquires the project lock.
Read-only verify/strict operations do not need a mutation lock. The wrapper
returns errors, never silently falls back to unsafe legacy filesystem restore.
"""
import os
from pathlib import Path
import sys

from kdn.common import xkeen
from kdn.engine import config, nfqws_service, nfqws_validate, profile_descriptor, rollback_ops, snapshot_format, snapshot_store, system


class BridgeContext:
    __slots__ = ('paths', 'environ')

    def __init__(self, paths, environ):
        self.paths, self.environ = paths, environ


def _paths(environ):
    paths = config.EnginePaths.from_environ(environ)
    if not system.is_router(paths, paths.test_root):
        raise ValueError('not a guarded router/test-root environment')
    snapshot_store._mutation_guard(paths, allow_live=True)
    if not paths.test_root and os.geteuid() != 0:
        raise ValueError('root privileges required')
    return paths


def _held(paths, environ):
    expected = environ.get('KDN_SNAPSHOT_BRIDGE_PID', '')
    if not expected.isascii() or not expected.isdecimal() or int(expected) <= 0:
        raise ValueError('shell project-lock owner missing')
    owner = snapshot_store._read(Path(paths.lock_dir) / 'pid', 64).decode('ascii').strip()
    if owner != expected:
        raise ValueError('shell project-lock owner mismatch')
    os.kill(int(owner), 0)
    ancestor = os.getpid()
    for _ in range(8):
        if ancestor == int(owner):
            return
        with (Path(system.PROC_ROOT) / str(ancestor) / 'stat').open('rb') as stream:
            raw = stream.read(4096)
        fields = raw.rsplit(b')', 1)[1].split()
        ancestor = int(fields[1])
        if ancestor <= 0:
            break
    raise ValueError('shell lock owner is not a process ancestor')


def _snapshot(paths, value):
    path = snapshot_store._no_links(value)
    if path.parent != snapshot_store._store(paths, False):
        raise ValueError('snapshot is outside the full snapshot store')
    return path


def _strict(paths, environ, path):
    nfqws_validate.validate_config(BridgeContext(paths, environ), path)


def _capture_data(paths, snapshot, scope):
    """One process for all roots; metadata/audit remain owned by shell caller."""
    content = snapshot_store._no_links(snapshot / 'files')
    if not content.is_dir() or any(content.iterdir()):
        raise ValueError('capture-data requires a new empty snapshot data directory')
    metadata = snapshot_format.parse_state(snapshot_store._read(snapshot / 'STATE.tsv', 65536))
    if metadata.kind != 'full' or metadata.scope != scope:
        raise ValueError('capture-data scope does not match shell metadata')
    entries = snapshot_store.capture_plan(paths, scope)
    for logical, source, present in entries:
        if present:
            snapshot_store._copy(source, content / logical.lstrip('/'), logical, scope)
    manifest = snapshot_store.POLICY_RECORD + b''.join(
        snapshot_format.InventoryEntry(logical, 'PRESENT' if present else 'ABSENT').to_bytes()
        for logical, _source, present in entries)
    snapshot_store._atomic_bytes(snapshot / 'MANIFEST', manifest)


def run(argv, environ=None):
    """Command allowlist only. All failure details intentionally omit file bytes."""
    environ = dict(os.environ if environ is None else environ)
    try:
        paths = _paths(environ)
        if not argv:
            raise ValueError('bridge operation missing')
        action, *arguments = argv
        if action not in ('verify', 'verify-full', 'xkeen-version', 'validate-profile'):
            xkeen.require(environ=environ)
        if action == 'available' and not arguments:
            return 0
        if action == 'verify' and len(arguments) == 1:
            snapshot_store.verify(_snapshot(paths, arguments[0]))
        elif action == 'xkeen-version' and not arguments:
            print(rollback_ops.xkeen_version(BridgeContext(paths, environ)))
        elif action == 'package-state' and not arguments:
            _held(paths, environ)
            context = BridgeContext(paths, environ)
            rows = []
            for name in rollback_ops.PACKAGES:
                version = rollback_ops.package_version(context, name)
                rows.append(name + '\t' + ('PRESENT\t' + version if version else 'ABSENT\t-') + '\n')
            # Never expose a partially successful inventory as an ABSENT record.
            print(''.join(rows), end='')
        elif action == 'verify-full' and len(arguments) == 1:
            saved = snapshot_store.verify(_snapshot(paths, arguments[0]))
            rollback_ops.validate_auxiliary(saved)
        elif action == 'capture-data' and len(arguments) == 2:
            _held(paths, environ)
            _capture_data(paths, _snapshot(paths, arguments[0]), arguments[1])
        elif action == 'capture-entry' and len(arguments) == 3:
            _held(paths, environ)
            logical, destination, scope = arguments
            if logical not in snapshot_store.managed_roots(scope):
                raise ValueError('unowned capture root')
            target = snapshot_store._no_links(destination)
            suffix = Path('files') / logical.lstrip('/')
            if len(target.parts) < len(suffix.parts) + 1:
                raise ValueError('invalid capture target')
            snapshot = target.parents[len(suffix.parts) - 1]
            _snapshot(paths, str(snapshot))
            if target != snapshot / suffix:
                raise ValueError('capture target mapping mismatch')
            source = snapshot_store._actual(paths, logical)
            if source.is_dir():
                snapshot_store._walk(source)
            snapshot_store._copy(source, target, logical, scope)
        elif action == 'restore' and len(arguments) == 3:
            _held(paths, environ)
            current_nfqws = arguments[2]
            if Path(paths.nfqws_bin).exists() or Path(paths.nfqws_bin).is_symlink():
                current_nfqws = rollback_ops.package_version(BridgeContext(paths, environ), 'nfqws2-keenetic')
                if not current_nfqws:
                    raise ValueError('installed nfqws binary has unknown package version')
            result = snapshot_store.restore_files(paths, _snapshot(paths, arguments[0]),
                                                   current_xkeen_version=xkeen.require(environ=environ),
                                                  current_nfqws_version=current_nfqws, allow_live=True)
            for warning in result.warnings:
                if not warning.startswith('nfqws2 package drift;'):
                    print('WARNING: ' + warning)
        elif action == 'strict' and len(arguments) == 1:
            _strict(paths, environ, arguments[0])
        elif action == 'validate-profile' and len(arguments) == 2:
            import json
            if not arguments[1].isascii() or not arguments[1].isdecimal() or len(arguments[1]) > 5:
                raise ValueError('invalid profile range')
            value = json.loads(snapshot_store._read(arguments[0], 524288))
            profile_descriptor.validate_descriptor(value, voice_high=int(arguments[1]))
        elif action == 'verify-runtime' and len(arguments) == 1:
            previous = arguments[0]
            if previous and (not previous.isascii() or not previous.isdecimal() or len(previous) > 12):
                raise ValueError('invalid previous service PID')
            nfqws_service.verify(BridgeContext(paths, environ), int(previous) if previous else None)
        else:
            raise ValueError('unknown bridge operation or arguments')
        return 0
    except Exception as error:
        print('ERROR: snapshot safety bridge refused operation (' + type(error).__name__ + ').', file=sys.stderr)
        return 1
