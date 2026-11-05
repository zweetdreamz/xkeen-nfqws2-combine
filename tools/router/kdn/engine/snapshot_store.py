"""Bounded FORMAT1 snapshot data store. Service/package transactions are callers' work.

No file from a snapshot authorises its own destination. Manifest roots must be
the fixed ownership table, links/devices are rejected, outbound exclusions apply
also when deleting old files. Live mutations require an explicit guarded opt-in.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from kdn.common import fsutil, retention
from kdn.engine import config, snapshot_format, snapshot_policy


MAX_METADATA = 4 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 16384
MAX_DEPTH = 128
DATA_ITEMS = ('nfqws2.conf', 'lists', 'blobs', 'imported-profiles', 'profile-versions')
AUXILIARY = ('XKEEN_SETTINGS.tsv', 'XKEEN_RUNTIME_SETTINGS.tsv', 'PACKAGES.tsv',
             'OPKG_INSTALLED.txt', 'RUNTIME.tsv', 'IPV6_RUNTIME.txt', 'READONLY_AUDIT.txt')
BEGIN = b'# BEGIN keenetic-discord-nfqws2'
END = b'# END keenetic-discord-nfqws2'
POLICY_RECORD = b'KDN_SNAPSHOT_POLICY|2\n'


class VerifiedSnapshot:
    __slots__ = ('path', 'metadata', 'entries', 'files', 'auxiliary')

    def __init__(self, path, metadata, entries, files, auxiliary):
        self.path, self.metadata, self.entries = path, metadata, tuple(entries)
        self.files, self.auxiliary = tuple(files), auxiliary


class RestoreResult:
    __slots__ = ('warnings',)

    def __init__(self, warnings=()):
        self.warnings = tuple(warnings)


def expired(snapshot, *, focused=False, now=None):
    """Age selection only; callers must still verify checksums before deletion."""
    metadata = snapshot_format.parse_state(_read(Path(snapshot) / 'STATE.tsv', 65536))
    if (metadata.kind == 'nfqws-import') != bool(focused):
        raise ValueError('snapshot kind mismatch')
    rows = [row for row in metadata.rows if row[0] == b'CREATED_UTC']
    if len(rows) > 1:
        raise ValueError('ambiguous snapshot creation date')
    if len(rows) != 1:
        return False
    return retention.older_than_limit(metadata.value('CREATED_UTC'), now=now)


def _no_links(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('snapshot path traverses parents')
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('symlink in snapshot path')
    return path


def _read(path, maximum=MAX_METADATA):
    path = _no_links(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ValueError('snapshot file type/size is unsafe')
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum or len(data) != info.st_size:
        raise ValueError('snapshot file changed while reading')
    return data


def _relative(value):
    if (not value or value.startswith('/') or any(char in value for char in '\\|\t\r\n\0')
            or any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('unsafe snapshot relative path')
    return value


def managed_roots(scope='integrated'):
    if scope not in ('integrated', 'standalone'):
        raise ValueError('unsupported snapshot scope')
    integrated = snapshot_policy.INTEGRATED_TREES + snapshot_policy.INTEGRATED_FILES
    return ((integrated if scope == 'integrated' else ())
            + snapshot_policy.COMMON_TREES + snapshot_policy.COMMON_FILES)


def parse_manifest(raw, scope='integrated'):
    if not isinstance(raw, bytes) or len(raw) > MAX_METADATA:
        raise ValueError('invalid snapshot manifest size')
    expected, entries, seen = set(managed_roots(scope)), [], set()
    policy_seen = False
    for line in raw.splitlines():
        if line == POLICY_RECORD.rstrip(b'\n'):
            if policy_seen:
                raise ValueError('duplicate snapshot policy record')
            policy_seen = True
            continue
        parts = line.split(b'|')
        if len(parts) != 2:
            raise ValueError('invalid snapshot manifest row')
        logical = parts[0].decode('utf-8', 'surrogateescape')
        presence = parts[1].decode('ascii')
        if logical not in expected or logical in seen or presence not in ('PRESENT', 'ABSENT'):
            raise ValueError('unmanaged, duplicate or invalid manifest record')
        seen.add(logical)
        entries.append(snapshot_format.InventoryEntry(logical, presence))
    if seen != expected:
        raise ValueError('incomplete snapshot manifest')
    return tuple(entries)


def parse_checksums(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_METADATA:
        raise ValueError('invalid checksum manifest size')
    result = {}
    for line in raw.splitlines():
        match = re.fullmatch(rb'([a-fA-F0-9]{64}) [ *](.+)', line)
        if match is None:
            raise ValueError('invalid checksum record')
        name = match.group(2).decode('utf-8', 'surrogateescape')
        if name.startswith('./'):
            name = name[2:]
        name = _relative(name)
        if name in result or len(result) >= MAX_ENTRIES:
            raise ValueError('duplicate or excessive checksum records')
        result[name] = match.group(1).lower()
    return result


def _children(directory, limit=MAX_ENTRIES):
    """Bound directory enumeration before materialising/sorting its entries."""
    names, total = [], 0
    with os.scandir(directory) as entries:
        for entry in entries:
            total += len(entry.name.encode('utf-8', 'surrogateescape'))
            if len(names) >= limit or total > MAX_METADATA:
                raise ValueError('snapshot directory exceeds entry limit')
            names.append(entry.name)
    # Keep bare names, not thousands of cached absolute-path strings.
    return (Path(directory) / name for name in sorted(names))


def _walk(directory):
    """Fixed lexical traversal, never follows links. Returns dirs/files and byte budget."""
    directory = _no_links(directory)
    if not directory.is_dir():
        raise ValueError('snapshot content directory is missing')
    pending, result, total, name_bytes = [''], [], 0, 0
    while pending:
        parent = directory / pending.pop()
        for path in _children(parent, MAX_ENTRIES - len(result)):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                raise ValueError('snapshot contains symlink or special file')
            relative = _relative(path.relative_to(directory).as_posix())
            name_bytes += len(relative.encode('utf-8', 'surrogateescape'))
            if name_bytes > MAX_METADATA or len(Path(relative).parts) > MAX_DEPTH:
                raise ValueError('snapshot path metadata exceeds limits')
            result.append((relative, info))
            if stat.S_ISDIR(info.st_mode):
                pending.append(relative)
            else:
                total += info.st_size
                if info.st_size > MAX_FILE:
                    raise ValueError('snapshot file exceeds limit')
            if len(result) > MAX_ENTRIES or total > MAX_BYTES:
                raise ValueError('snapshot content exceeds limits')
    return result


def capture_plan(paths, scope='integrated', *, focused=False):
    """Check aggregate copied data across all roots BEFORE the first copy.

    Returns logical/source/presence triples. Namespace must remain owned by the
    cooperating transaction; this is not isolation from another root writer.
    """
    managed_roots(scope)
    logical_roots = (tuple('/opt/etc/nfqws2/' + name for name in DATA_ITEMS)
                     if focused else managed_roots(scope))
    entries, names, total, name_bytes = [], set(), 0, 0
    for logical in logical_roots:
        source = _actual(paths, logical)
        present = source.exists()
        entries.append((logical, source, present))
        if not present:
            continue
        info = source.lstat()
        if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
            raise ValueError('snapshot capture rejects links/devices')
        content = [('', info)] + (_walk(source) if source.is_dir() else [])
        for relative, item in content:
            full = logical + ('/' + relative if relative else '')
            if snapshot_policy.path_policy(full, scope) == 'excluded':
                continue
            name = (full[len('/opt/etc/nfqws2/'):] if focused else full.lstrip('/'))
            node = Path(name)
            if len(node.parts) > MAX_DEPTH:
                raise ValueError('aggregate snapshot depth exceeds limit')
            for part in (node, *node.parents):
                if part == Path('.'):
                    continue
                item_name = part.as_posix()
                if item_name not in names:
                    name_bytes += len(item_name.encode('utf-8', 'surrogateescape'))
                    names.add(item_name)
            if stat.S_ISREG(item.st_mode):
                if item.st_size > MAX_FILE:
                    raise ValueError('snapshot file exceeds limit')
                total += item.st_size
            if total > MAX_BYTES or len(names) > MAX_ENTRIES or name_bytes > MAX_METADATA:
                raise ValueError('aggregate snapshot capture exceeds limits')
    return entries


def verify(path, *, focused=False):
    """Read-only verification. Does not authorise restore of arbitrary paths."""
    path = _no_links(path)
    if not path.is_dir():
        raise ValueError('snapshot does not exist')
    metadata = snapshot_format.parse_state(_read(path / 'STATE.tsv', 65536))
    seen = set()
    for row in metadata.rows:
        if row[0] in seen:
            raise ValueError('duplicate snapshot metadata')
        seen.add(row[0])
    if (metadata.kind == 'nfqws-import') != bool(focused):
        raise ValueError('snapshot kind mismatch')
    if focused:
        present = metadata.value('NFQWS_PRESENT')
        if present not in ('0', '1') or metadata.value('NFQWS_RUNNING') not in ('0', '1'):
            raise ValueError('invalid focused runtime metadata')
        entries = ()
        data_dir = path / 'nfqws2'
        content = _walk(data_dir) if present == '1' else []
        if present == '0' and data_dir.exists():
            raise ValueError('absent focused snapshot contains data')
        if any(relative.split('/')[0] not in DATA_ITEMS for relative, _info in content):
            raise ValueError('focused snapshot contains package or unrelated files')
    else:
        entries = parse_manifest(_read(path / 'MANIFEST'), metadata.scope)
        data_dir = path / 'files'
        content = _walk(data_dir)
        for entry in entries:
            item = data_dir / entry.logical_path.lstrip('/')
            if item.exists() != (entry.presence == 'PRESENT'):
                raise ValueError('snapshot presence does not match manifest')
            if item.exists():
                tree = entry.logical_path in snapshot_policy.COMMON_TREES + snapshot_policy.INTEGRATED_TREES
                if item.is_dir() != tree:
                    raise ValueError('snapshot manifest root has incorrect type')
        for relative, info in content:
            logical = '/' + relative
            # Intermediate /opt/etc directories are containers, not restore roots.
            if not any(logical == entry.logical_path or logical.startswith(entry.logical_path + '/')
                       or (stat.S_ISDIR(info.st_mode) and entry.logical_path.startswith(logical + '/'))
                       for entry in entries):
                raise ValueError('snapshot file outside manifest roots')
    checksums = parse_checksums(_read(path / 'CHECKSUMS.sha256'))
    files = {relative for relative, info in content if stat.S_ISREG(info.st_mode)}
    if set(checksums) != files:
        raise ValueError('snapshot checksum coverage is incomplete')
    for relative in files:
        if hashlib.sha256(_read(data_dir / relative, MAX_FILE)).hexdigest().encode() != checksums[relative]:
            raise ValueError('snapshot checksum mismatch')
    auxiliary = {}
    for name in AUXILIARY:
        candidate = path / name
        if candidate.exists() or candidate.is_symlink():
            auxiliary[name] = _read(candidate)
    allowed_top = {'STATE.tsv', 'CHECKSUMS.sha256', 'nfqws2' if focused else 'files'}
    if not focused:
        allowed_top.add('MANIFEST')
    allowed_top.update(AUXILIARY)
    if any(item.name not in allowed_top for item in path.iterdir()):
        raise ValueError('unexpected snapshot top-level entry')
    verified = VerifiedSnapshot(path, metadata, entries, sorted(files), auxiliary)
    if focused and metadata.value('FOCUSED_OPERATION'):
        focused_read(verified)
    return verified


def _mutation_guard(paths, allow_live):
    if not paths.test_root and not allow_live:
        raise RuntimeError('live snapshot mutation requires guarded explicit opt-in')
    if paths.test_root:
        physical = _no_links(paths.test_root)
        if (not Path(paths.test_root).is_absolute() or not physical.is_dir()
                or physical == Path(physical.anchor)):
            raise ValueError('unsafe disposable root')
    expected = _no_links(config.list_path('/opt/etc/keenetic-discord-nfqws2', paths.test_root))
    fields = ((paths.state_root, expected), (paths.snapshot_root, expected / 'snapshots'),
              (paths.baseline_pointer, expected / 'baseline.ptr'),
              (paths.xkeen_baseline_pointer, expected / 'baseline-xkeen.ptr'),
              (paths.latest_pointer, expected / 'latest-preapply.ptr'))
    if any(_no_links(actual) != wanted for actual, wanted in fields):
        raise ValueError('snapshot store escaped configured root')


def _actual(paths, logical):
    return _no_links(config.list_path(logical, paths.test_root))


def _atomic_bytes(path, data, mode=0o600):
    import tempfile

    path = _no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _copy(source, destination, logical, scope):
    if snapshot_policy.path_policy(logical, scope) == 'excluded':
        return
    info = source.lstat()
    if stat.S_ISDIR(info.st_mode):
        destination.mkdir(parents=True, exist_ok=True)
        os.chmod(destination, stat.S_IMODE(info.st_mode))
        for child in _children(source, MAX_ENTRIES):
            _copy(child, destination / child.name, logical + '/' + child.name, scope)
    elif stat.S_ISREG(info.st_mode):
        _atomic_bytes(destination, _read(source, MAX_FILE), stat.S_IMODE(info.st_mode))
    else:
        raise ValueError('snapshot capture rejects links/devices')


def _store(paths, focused):
    return _no_links(Path(paths.state_root) / 'nfqws-import-snapshots' if focused else paths.snapshot_root)


def create(paths, *, purpose, scope='integrated', xkeen_version='', metadata=(), auxiliary=None,
           focused=False, allow_live=False):
    """Capture data only. Caller supplies pre-read package/runtime metadata under lock."""
    _mutation_guard(paths, allow_live)
    managed_roots(scope)
    planned = capture_plan(paths, scope, focused=focused)
    store = _store(paths, focused)
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(Path(paths.state_root), 0o700)
    os.chmod(store, 0o700)
    stamp = time.strftime('%Y%m%d-%H%M%S') + '-' + str(os.getpid())
    counter = 0
    while True:
        identity = stamp + ('-' + str(counter) if counter else '')
        final, stage = store / identity, store / ('.building-' + identity)
        if not final.exists():
            try:
                stage.mkdir(mode=0o700)
                break
            except FileExistsError:
                pass
        counter += 1
    try:
        fields = [('FORMAT', '1'), ('PURPOSE', purpose), ('SCRIPT_VERSION', config.SCRIPT_VERSION),
                  ('CREATED_UTC', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))]
        if focused:
            fields.append(('XKEEN_VERSION', xkeen_version))
            source = _actual(paths, '/opt/etc/nfqws2')
            fields.append(('NFQWS_PRESENT', '1' if source.exists() else '0'))
            data_dir = stage / 'nfqws2'
            if source.exists():
                data_dir.mkdir()
                for logical, item, present in planned:
                    if present:
                        _copy(item, data_dir / item.name, logical, scope)
        else:
            fields.extend((('SCOPE', scope), ('XKEEN_VERSION', xkeen_version)))
            data_dir = stage / 'files'
            data_dir.mkdir()
            entries = []
            for logical, source, present in planned:
                entries.append(snapshot_format.InventoryEntry(logical, 'PRESENT' if present else 'ABSENT'))
                if present:
                    _copy(source, data_dir / logical.lstrip('/'), logical, scope)
            _atomic_bytes(stage / 'MANIFEST', POLICY_RECORD + b''.join(entry.to_bytes() for entry in entries))
        fields.extend(metadata)
        _atomic_bytes(stage / 'STATE.tsv', snapshot_format.make_state(fields).to_bytes())
        auxiliary = {} if auxiliary is None else auxiliary
        if set(auxiliary) - set(AUXILIARY):
            raise ValueError('unknown snapshot auxiliary file')
        for name, data in auxiliary.items():
            if not isinstance(data, bytes) or len(data) > MAX_METADATA:
                raise ValueError('invalid snapshot auxiliary bytes')
            _atomic_bytes(stage / name, data)
        content = _walk(data_dir) if data_dir.exists() else []
        rows = []
        for relative, info in sorted(content):
            if stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256(_read(data_dir / relative, MAX_FILE)).hexdigest()
                rows.append((digest + '  ./' + relative + '\n').encode('utf-8', 'surrogateescape'))
        _atomic_bytes(stage / 'CHECKSUMS.sha256', b''.join(rows))
        verify(stage, focused=focused)
        if focused:
            # Snapshot data/modes and all directory entries precede the durable cue.
            for relative, _info in reversed(content):
                fsutil.fsync_path(data_dir / relative)
            if data_dir.exists():
                fsutil.fsync_path(data_dir)
            for name in ('STATE.tsv', 'CHECKSUMS.sha256', *auxiliary):
                fsutil.fsync_path(stage / name)
            fsutil.fsync_path(stage)
        os.rename(stage, final)
        if focused:
            fsutil.fsync_path(store)
            fsutil.fsync_path(store.parent)
            fsutil.fsync_path(store.parent.parent)
        return final
    except BaseException:
        # Stage is our own unpublished directory; cleanup never follows links.
        _remove_tree(stage)
        raise


def _remove_tree(path):
    if not path.exists():
        return
    info = path.lstat()
    if stat.S_ISDIR(info.st_mode):
        for child in path.iterdir():
            _remove_tree(child)
        path.rmdir()
    else:
        path.unlink()


def publish_pointer(paths, pointer, snapshot, *, baseline=False, focused=False, allow_live=False):
    _mutation_guard(paths, allow_live)
    snapshot, pointer = _no_links(snapshot), _no_links(pointer)
    if snapshot.parent != _store(paths, focused):
        raise ValueError('pointer target outside snapshot store')
    allowed = {Path(paths.baseline_pointer), Path(paths.xkeen_baseline_pointer), Path(paths.latest_pointer),
               Path(paths.state_root) / 'latest-nfqws-import.ptr'}
    if pointer not in {_no_links(item) for item in allowed}:
        raise ValueError('unowned snapshot pointer')
    verify(snapshot, focused=focused)
    if baseline and pointer.exists():
        return False
    fsutil.atomic_text(pointer, str(snapshot) + '\n')
    if focused:
        fsutil.fsync_path(pointer)
        fsutil.fsync_path(pointer.parent)
    return True


def rollover_xkeen_baseline(paths, snapshot, version, *, allow_live=False):
    """Version pointer changes; original baseline.ptr and previous snapshots stay intact."""
    if not snapshot_policy.versions_compatible(version, version):
        raise ValueError('unknown XKeen baseline version')
    verified = verify(snapshot)
    if verified.metadata.scope != 'integrated' or verified.metadata.value('XKEEN_VERSION') != version:
        raise ValueError('baseline version mismatch')
    return publish_pointer(paths, paths.xkeen_baseline_pointer, snapshot, allow_live=allow_live)


def _blocks(data):
    result, block, inside = [], [], False
    for line in data.splitlines(keepends=True):
        marker = line[:-1] if line.endswith(b'\n') else line
        if not inside and marker == BEGIN:
            inside, block = True, [line]
        elif inside:
            block.append(line)
            if marker == END:
                result.append(b''.join(block))
                inside = False
    if inside:
        raise ValueError('unterminated managed port block')
    return b''.join(result)


def _merge_ports(current, saved):
    replacement = _blocks(saved)
    _blocks(current)  # fail closed for an incomplete current marker range
    output, inside = [], False
    for line in current.splitlines(keepends=True):
        marker = line[:-1] if line.endswith(b'\n') else line
        if not inside and marker == BEGIN:
            inside = True
        elif inside and marker == END:
            inside = False
        elif not inside:
            output.append(line)
    retained = b''.join(output)
    if replacement and retained and not retained.endswith(b'\n'):
        retained += b'\n'
    return retained + replacement


def _protected(logical, drift):
    if snapshot_policy.path_policy(logical) == 'excluded':
        return True
    if drift:
        if logical in ('/opt/etc/init.d/S51nfqws2', '/opt/etc/ndm/netfilter.d/100-nfqws2.sh'):
            return True
        prefix = '/opt/etc/nfqws2/'
        if logical.startswith(prefix):
            return logical[len(prefix):].split('/')[0] not in DATA_ITEMS
    return False


def _sync(source, target, logical, drift):
    if _protected(logical, drift):
        return
    if source.exists() and source.is_dir():
        if target.exists() and not target.is_dir():
            target.unlink()
        target.mkdir(parents=True, exist_ok=True)
        os.chmod(target, stat.S_IMODE(source.stat().st_mode))
        source_names = {child.name for child in source.iterdir()}
        target_names = {child.name for child in target.iterdir()}
        for name in sorted(source_names | target_names):
            _sync(source / name, target / name, logical + '/' + name, drift)
        os.chmod(target, stat.S_IMODE(source.stat().st_mode))
    elif source.exists():
        if target.exists() and target.is_dir():
            for child in sorted(target.iterdir()):
                _sync(source / '__absent__' / child.name, child, logical + '/' + child.name, drift)
            if any(target.iterdir()):
                raise ValueError('restore would replace protected directory content')
            target.rmdir()
        _atomic_bytes(target, _read(source, MAX_FILE), stat.S_IMODE(source.stat().st_mode))
    elif target.exists():
        if target.is_dir():
            for child in sorted(target.iterdir()):
                _sync(source / child.name, child, logical + '/' + child.name, drift)
            if not any(target.iterdir()):
                target.rmdir()
        else:
            target.unlink()


def restore_files(paths, snapshot, *, current_xkeen_version='', current_nfqws_version='',
                  focused=False, allow_live=False):
    """Data-only restore after complete source/target preflight, under caller's lock.

    Caller must capture rescue state and stop/verify/restart services. Failures
    can be partial and require rescue rollback; this function never claims an
    atomic whole-system transaction.
    """
    _mutation_guard(paths, allow_live)
    verified = verify(snapshot, focused=focused)
    snapshot_policy.xkeen_restore_policy(verified.metadata.value('XKEEN_VERSION'), current_xkeen_version)
    recorded_nfqws = ''
    for row in verified.auxiliary.get('PACKAGES.tsv', b'').splitlines():
        fields = row.split(b'\t')
        if len(fields) == 3 and fields[:2] == [b'nfqws2-keenetic', b'PRESENT']:
            recorded_nfqws = fields[2].decode('utf-8', 'surrogateescape')
    drift = bool(recorded_nfqws and current_nfqws_version and recorded_nfqws != current_nfqws_version)
    if focused:
        source = verified.path / 'nfqws2'
        pairs = [(source / name, _actual(paths, '/opt/etc/nfqws2/' + name), '/opt/etc/nfqws2/' + name)
                 for name in DATA_ITEMS]
    else:
        pairs = [(verified.path / 'files' / entry.logical_path.lstrip('/'), _actual(paths, entry.logical_path), entry.logical_path)
                 for entry in verified.entries]
    # Scan all mutable targets before any write/removal; do not follow links.
    for _source, target, _logical in pairs:
        if target.exists():
            if target.is_dir():
                _walk(target)
            elif not target.is_file():
                raise ValueError('restore target is not regular')
    for source, target, logical in pairs:
        _sync(source, target, logical, drift)
    warnings = []
    if drift:
        warnings.append('nfqws2 package drift; installed package files kept, data restored only')
    return RestoreResult(warnings)


FOCUSED_MAX_RECEIPT = 16384
FOCUSED_CONTEXT_KEYS = ('schema', 'operation_id', 'project', 'service', 'candidate_id',
                'before_hash', 'before_pointer', 'before_descriptor')


def focused_encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


def focused_file_state(data, mode):
    return ['file', mode, hashlib.sha256(data).hexdigest()]


def focused_node(path):
    path = _no_links(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISDIR(info.st_mode):
        return ['dir', mode]
    if stat.S_ISREG(info.st_mode):
        return focused_file_state(_read(path, MAX_FILE), mode)
    raise ValueError('unsafe focused node')


def focused_inventory(base):
    result = {}
    total = 0
    for name in DATA_ITEMS:
        root = base / name
        result[name] = focused_node(root)
        if result[name] and result[name][0] == 'dir':
            for relative, info in _walk(root):
                result[name + '/' + relative] = focused_node(root / relative)
                total += info.st_size if stat.S_ISREG(info.st_mode) else 0
                if len(result) > MAX_ENTRIES or total > MAX_BYTES:
                    raise ValueError('focused inventory exceeds bound')
    return result


def focused_context(value):
    if (not isinstance(value, dict) or value.get('schema') != 2
            or not re.fullmatch(r'[0-9a-f]{32}', str(value.get('operation_id', '')))
            or value.get('service') not in ('youtube', 'discord-tcp', 'discord-voice')
            or not re.fullmatch(r'[0-9a-f]{12}', str(value.get('candidate_id', '')))
            or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('before_hash', '')))
            or not isinstance(value.get('before_pointer'), str)
            or not isinstance(value.get('project'), str) or not value['project'].startswith('/')
            or 'before_descriptor' not in value):
        raise ValueError('untrusted focused operation context; legacy hash-only recovery is unsupported')
    focused_validate_node(value['before_descriptor'])
    return {key: value[key] for key in FOCUSED_CONTEXT_KEYS}


def focused_validate_node(value):
    if value is None:
        return
    if (not isinstance(value, list) or len(value) not in (2, 3) or type(value[1]) is not int
            or not 0 <= value[1] <= 0o7777):
        raise ValueError('invalid focused node fingerprint')
    if value[0] == 'dir' and len(value) == 2:
        return
    if value[0] == 'file' and len(value) == 3 and re.fullmatch(r'[0-9a-f]{64}', str(value[2])):
        return
    raise ValueError('invalid focused node fingerprint')


def focused_check_before(operation, before):
    target = 'imported-profiles/' + operation['service'] + '.json'
    config = before.get('nfqws2.conf')
    if (not config or config[0] != 'file' or config[2] != operation['before_hash']
            or before.get(target) != operation['before_descriptor']):
        raise ValueError('focused source differs from pre-apply state')


def focused_read(saved):
    raw = saved.metadata.value('FOCUSED_OPERATION')
    if not raw or len(raw) > FOCUSED_MAX_RECEIPT:
        raise ValueError('missing or oversized focused operation receipt')
    value = json.loads(raw, object_pairs_hook=_focused_pairs)
    if not isinstance(value, dict) or set(value) != {'schema', 'context', 'changes'} or value['schema'] != 1:
        raise ValueError('invalid focused operation receipt')
    operation = focused_context(value['context'])
    changes = value['changes']
    if not isinstance(changes, dict) or len(changes) > 16:
        raise ValueError('invalid focused changes')
    for relative, expected in changes.items():
        _relative(relative)
        service = operation['service']
        fixed = {'nfqws2.conf', 'imported-profiles', 'imported-profiles/' + service + '.json',
                 'profile-versions', 'profile-versions/' + service}
        archive = re.fullmatch(r'profile-versions/' + re.escape(service)
                              + r'/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}-(?:applied|replaced)-[0-9]+(?:-[0-9]+)?\.json', relative)
        if relative not in fixed and archive is None:
            raise ValueError('focused change outside planned import paths')
        focused_validate_node(expected)
    if saved.metadata.value('NFQWS_RUNNING') != '1' or saved.metadata.value('PURPOSE') != 'import-' + operation['service']:
        raise ValueError('focused receipt does not describe an import snapshot')
    before = focused_inventory(saved.path / 'nfqws2')
    focused_check_before(operation, before)
    return value, before


def focused_source(path, operation, store, *, fingerprint=None):
    path = _no_links(path)
    store = _no_links(store)
    if path.parent != store or not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9]+(?:-[0-9]+)?', path.name):
        raise ValueError('focused recovery source outside canonical store')
    saved = verify(path, focused=True)
    receipt, before = focused_read(saved)
    if receipt['context'] != focused_context(operation):
        raise ValueError('focused recovery source belongs to another operation')
    digest = hashlib.sha256(saved.metadata.raw + focused_encode(before).encode()).hexdigest()
    if fingerprint is not None and digest != fingerprint:
        raise ValueError('focused recovery source fingerprint changed')
    return saved, receipt, before, digest


def focused_admit_current(base, before, receipt):
    current = focused_inventory(base)
    changes = receipt['changes']
    for relative in before.keys() | current.keys() | changes.keys():
        actual = current.get(relative)
        if actual != before.get(relative) and (relative not in changes or actual != changes[relative]):
            raise ValueError('focused state has foreign drift; recovery refused')


def focused_confirm(base, saved):
    if focused_inventory(base) != focused_inventory(saved.path / 'nfqws2'):
        raise ValueError('restored focused data does not match original snapshot')


def focused_pending(paths):
    """Unclear state protects all focused snapshots/profile versions from GC."""
    path = Path(config.list_path('/opt/etc/xkeen-web/automation-state.json', paths.test_root))
    try:
        value = json.loads(_read(path, fsutil.MAX_JSON_BYTES), object_pairs_hook=_focused_pairs)
    except FileNotFoundError:
        return False
    except (OSError, ValueError, RecursionError):
        return True
    return not isinstance(value, dict) or value.get('transaction') is not None or 'state_error' in value


def _focused_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('ambiguous focused metadata')
        value[key] = item
    return value
