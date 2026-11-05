"""Bounded E4 file plans and guarded publication; no service lifecycle.

The orchestrator supplies a verified full rescue and arms its transaction before
calling publish. Multi-file publication is not power-loss atomic: the durable
full snapshot remains the recovery source. All cooperating writers hold the
project lock; hostile root namespace swaps are outside this boundary.
"""
from collections import namedtuple
import json
import os
from pathlib import Path
import stat

from kdn.common import fsutil, jsonc, lock
from kdn.engine import config, confvalues, nfqws_process, rollback_ops, snapshot_store, system, transaction, xray_patch


MAX_FILES = 128
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
LEGACY_OUTBOUNDS = ('04_discord_nfqws2_outbound.json', '04_youtube_nfqws2_outbound.json',
                    '04_telegram_nfqws2_outbound.json')
# Xray Config.Override appends new outbounds only when the filename contains tail.
OWNED_OUTBOUNDS = tuple(name.replace('.json', '_tail.json') for name in LEGACY_OUTBOUNDS)
EXTRA_FILES = ('/opt/etc/xkeen/port_proxying.lst', '/opt/etc/opkg/nfqws2-keenetic.conf')
OBSERVED_FILES = (*EXTRA_FILES, '/opt/etc/xkeen/port_exclude.lst', '/opt/etc/init.d/S05xkeen')


Change = namedtuple('Change', 'logical before mode after')
# Entire Xray corpus including protected VPN file: never publish stale plans.
Plan = namedtuple('Plan', 'changes corpus observations', defaults=((),))


def _path(ctx, logical):
    if logical in EXTRA_FILES:
        return snapshot_store._no_links(config.list_path(logical, ctx.paths.test_root))
    prefix = '/opt/etc/xray/configs/'
    name = logical.removeprefix(prefix)
    if (not logical.startswith(prefix) or '/' in name or '\\' in name or name.startswith('.')
            or not name.endswith('.json') or name == '04_outbounds.json'
            or any(ord(c) < 32 for c in name)):
        raise ValueError('unowned apply file target')
    return snapshot_store._no_links(Path(ctx.paths.xray_config_dir) / name)


def _state(path):
    path = snapshot_store._no_links(path)
    try:
        mode = stat.S_IMODE(path.lstat().st_mode)
    except FileNotFoundError:
        return None, 0o600
    return snapshot_store._read(path, MAX_FILE), mode


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('ambiguous duplicate Xray key')
        result[key] = value
    return result


def _decode(raw):
    try:
        value = json.loads(jsonc.strip_json_comments(raw.decode('utf-8-sig')), object_pairs_hook=_pairs,
                           parse_constant=lambda _v: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid Xray JSONC') from error
    if not isinstance(value, dict):
        raise ValueError('Xray config must be an object')
    return value


def _encode(document):
    return (json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')


def _corpus(ctx):
    directory = snapshot_store._no_links(ctx.paths.xray_config_dir)
    files, total = [], 0
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries, 1):
            if count > MAX_FILES:
                raise ValueError('Xray directory exceeds entry budget')
            if entry.name.startswith('.') or not entry.name.endswith('.json'):
                continue
            data, mode = _state(Path(entry.path))
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError('Xray corpus exceeds byte budget')
            files.append((entry.name, data, mode))
    return tuple(sorted(files))


def _owned_outbound(document, tag, service):
    """Prove the exact native/legacy generated shape before replacing or deleting."""
    if set(document) != {'outbounds'} or not isinstance(document['outbounds'], list):
        return False
    rows = document['outbounds']
    expected = [tag] + (['telegram-ws'] if len(rows) == 2 and service == 'telegram' else [])
    if [row.get('tag') for row in rows] != expected:
        return False
    for row in rows:
        if (set(row) - {'tag', 'protocol', 'settings', 'streamSettings'}
                or row.get('protocol') != 'freedom'):
            return False
        if row['tag'] == 'telegram-ws':
            settings = row.get('settings')
            if not isinstance(settings, dict) or set(settings) != {'redirect'}:
                return False
            host, separator, port = str(settings['redirect']).rpartition(':')
            if (host != '127.0.0.1' or separator != ':' or not port.isascii() or not port.isdecimal()
                    or len(port) > 5 or not 1 <= int(port) <= 65535):
                return False
        elif row.get('settings', {}) != {}:
            return False
        if 'streamSettings' in row:
            stream = row['streamSettings']
            if not isinstance(stream, dict) or set(stream) != {'sockopt'}:
                return False
            sockopt = stream['sockopt']
            if (not isinstance(sockopt, dict) or set(sockopt) != {'mark'}
                    or type(sockopt['mark']) is not int or not 0 <= sockopt['mark'] <= 2147483647):
                return False
    return True


def _outbound_default(documents):
    """Xray26.10.31 serial.mergeConfigs + Config.Override, without IO.

    The first file supplies its array directly. Later files update the first
    matching tag in place, append tail rows immediately, and prepend other new
    rows as a batch only after finishing that file.
    """
    rows = []
    for index, (name, document) in enumerate(sorted(documents.items())):
        incoming = document.get('outbounds', [])
        if index == 0:
            rows = list(incoming)
            continue
        prepend = []
        for outbound in incoming:
            tag = outbound.get('tag') or ''
            position = next((i for i, previous in enumerate(rows)
                             if (previous.get('tag') or '') == tag), None)
            if position is not None:
                rows[position] = outbound
            elif 'tail' in name.lower():
                rows.append(outbound)
            else:
                prepend.append(outbound)
        rows = prepend + rows
    return rows[0] if rows else None


def prepare_xray(ctx, *, routes, proxy_outbound, mark=None, voice_high=50100, relay_port=18443):
    """Read and transform everything before any effective write. Does not create a rescue."""
    transaction.guard(ctx, readonly=True)
    init_logical = '/opt/etc/init.d/S05xkeen'
    init_raw, init_mode = _state(config.list_path(init_logical, ctx.paths.test_root))
    base = confvalues.assigned_value((init_raw or b'').decode('utf-8', 'surrogateescape'),
                                    'dscp_force_proxy_tag') or 'force-proxy'
    excluded_tags = (base, base + '-redirect', base + '-tproxy')
    corpus = _corpus(ctx)
    documents = {name: _decode(data) for name, data, _mode in corpus}
    routing = [name for name, doc in documents.items() if isinstance(doc.get('routing'), dict)]
    if not routing:
        raise ValueError('Xray routing object was not found')
    tags, all_tags, blocks, proxies, output = [], [], [], [], {}
    xray_patch.direct_outbound('direct', mark)
    for name, doc in documents.items():
        roles = xray_patch.inbound_roles(doc, excluded_tags=excluded_tags)
        all_tags.extend(row.get('tag') for row in doc.get('inbounds', []) if isinstance(row, dict))
        tags.extend(tag for tag, _networks in roles)
        if roles:
            output[name] = xray_patch.patch_inbounds(doc, excluded_tags=excluded_tags)
        outbounds = doc.get('outbounds', [])
        if not isinstance(outbounds, list) or any(not isinstance(row, dict) for row in outbounds):
            raise ValueError('invalid outbound list')
        for row in outbounds:
            if row.get('protocol') == 'blackhole':
                blocks.append(row.get('tag'))
            elif row.get('protocol') not in ('freedom', 'blackhole', 'dns', 'loopback', None):
                proxies.append(row.get('tag'))
    if (proxy_outbound or 'vless' in routes.values()) and proxy_outbound not in proxies:
        raise ValueError('selected proxy outbound does not exist')
    if not tags or len(tags) != len(set(tags)):
        raise ValueError('missing or duplicate transparent inbound tags')
    if any(all_tags.count(tag) != 1 for tag in tags):
        raise ValueError('transparent tag conflicts with another inbound')
    active = routing[-1]
    if active == '04_outbounds.json' or '04_outbounds.json' in output:
        raise ValueError('protected VPN file contains mutable Xray sections')
    output[active] = xray_patch.patch_routing(output.get(active, documents[active]), inbound_tags=tags,
        routes=routes, proxy_outbound=proxy_outbound, voice_high=voice_high, block_tags=blocks)
    reserved = (*OWNED_OUTBOUNDS, *LEGACY_OUTBOUNDS)
    for name, doc in documents.items():
        if name not in reserved and any(row.get('tag') in (
                'discord-direct', 'youtube-direct', 'telegram-direct', 'telegram-ws')
                for row in doc.get('outbounds', [])):
            raise ValueError('managed outbound tag exists outside reserved files')
    for name, old_name, service, tag in zip(OWNED_OUTBOUNDS, LEGACY_OUTBOUNDS, ('discord', 'youtube', 'telegram'),
                                 ('discord-direct', 'youtube-direct', 'telegram-direct'), strict=True):
        # Never replace unexpected user content under a reserved filename.
        previous, old = documents.get(name), documents.get(old_name)
        for existing in (previous, old):
            if existing is not None and not _owned_outbound(existing, tag, service):
                raise ValueError('reserved direct outbound file is not project-owned')
        if previous is not None and old is not None and previous != old:
            raise ValueError('reserved direct outbound migration collision')
        if old is not None:
            output[old_name] = None
        needed = (routes['discord_tcp'] != 'vless' or routes['discord_voice'] != 'vless') if service == 'discord' else (
            routes['youtube'] != 'vless' if service == 'youtube' else routes['telegram'] in ('direct', 'ws'))
        output[name] = xray_patch.direct_outbound(tag, mark) if needed else None
        if service == 'telegram' and routes['telegram'] == 'ws':
            if type(relay_port) is not int or not 1 <= relay_port <= 65535:
                raise ValueError('invalid relay port')
            relay = xray_patch.direct_outbound('telegram-ws', mark)['outbounds'][0]
            relay['settings'] = {'redirect': f'127.0.0.1:{relay_port}'}
            output[name]['outbounds'].append(relay)
    unmanaged = {name: doc for name, doc in documents.items() if name not in reserved}
    prospective = {name: doc for name, doc in (documents | output).items() if doc is not None}
    if _outbound_default(unmanaged) != _outbound_default(prospective):
        raise ValueError('managed outbounds would change the unmanaged Xray default')
    before = {name: (data, mode) for name, data, mode in corpus}
    changes = []
    for name, doc in sorted(output.items()):
        raw, mode = before.get(name, (None, 0o600))
        after = _encode(doc) if doc is not None else None
        if raw != after:
            changes.append(Change('/opt/etc/xray/configs/' + name, raw, mode, after))
    planned = {Path(item.logical).name for item in changes}
    # Legacy hardened Xray configs to0600. Keep that intent, but never even
    # chmod the VPN manager's excluded04_outbounds.json.
    for name, raw, mode in corpus:
        if name != '04_outbounds.json' and name not in planned and mode != 0o600:
            changes.append(Change('/opt/etc/xray/configs/' + name, raw, mode, raw))
    return Plan(tuple(changes), corpus, ((init_logical, init_raw, init_mode),))


def extend(ctx, plan, updates):
    """Attach bounded owned port/feed bytes to an already prepared Xray plan."""
    additions = []
    existing = {item.logical for item in plan.changes}
    for logical, data in updates.items():
        if logical not in EXTRA_FILES or logical in existing or not isinstance(data, bytes) or len(data) > MAX_FILE:
            raise ValueError('invalid extra apply change')
        raw, mode = _state(_path(ctx, logical))
        if raw != data:
            additions.append(Change(logical, raw, mode, data))
    return Plan(plan.changes + tuple(additions), plan.corpus, plan.observations)


def observe(ctx, plan, logical):
    """Track non-written dependency inputs as well (notably port exclusions)."""
    if logical not in OBSERVED_FILES:
        raise ValueError('unowned apply observation')
    data, mode = _state(config.list_path(logical, ctx.paths.test_root))
    if any(row[0] == logical for row in plan.observations):
        raise ValueError('duplicate apply observation')
    return Plan(plan.changes, plan.corpus, plan.observations + ((logical, data, mode),))


def validate_staged(ctx, plan):
    """Actual xray -test over complete prospective corpus, never live configuration."""
    import tempfile

    transaction.guard(ctx, readonly=True)
    _validate_plan(ctx, plan)
    binary = system.find_xray(ctx.paths, ctx.environ)
    if binary is None:
        raise ValueError('Xray binary not found')
    root = snapshot_store._no_links(ctx.paths.work_tmp_root)
    if not root.is_dir():
        raise ValueError('temporary work directory is missing')
    with tempfile.TemporaryDirectory(prefix='kdn-xray-check-', dir=root) as folder:
        files = {name: data for name, data, _mode in plan.corpus}
        for change in plan.changes:
            if change.logical.startswith('/opt/etc/xray/configs/'):
                files[Path(change.logical).name] = change.after
        for name, data in files.items():
            if data is not None:
                fsutil.atomic_bytes(Path(folder) / name, data, 0o600)
        done = nfqws_process.run([str(binary), 'run', '-test', '-confdir', folder, '-format', 'json'],
            dict(ctx.environ, XRAY_LOCATION_ASSET=ctx.paths.xray_dat_dir),
            timeout=config.timeout('xray_test', ctx.environ), output_limit=1024 * 1024, cwd='/')
        if done.returncode or done.timed_out or done.output_limited:
            raise RuntimeError('prospective Xray configuration test failed')


def _check_shape(ctx, plan):
    # Migration can delete an old filename and create its tail replacement in
    # the same plan. Count those bounded new names in addition to the corpus.
    if not isinstance(plan, Plan) or len(plan.changes) > MAX_FILES + len(OWNED_OUTBOUNDS) + len(EXTRA_FILES):
        raise ValueError('invalid apply plan')
    total, seen = 0, set()
    for change in plan.changes:
        if not isinstance(change, Change) or change.logical in seen:
            raise ValueError('duplicate or invalid apply target')
        seen.add(change.logical)
        _path(ctx, change.logical)
        if type(change.mode) is not int or not 0 <= change.mode <= 0o777:
            raise ValueError('unsafe apply mode')
        for data in (change.before, change.after):
            if data is not None:
                if not isinstance(data, bytes) or len(data) > MAX_FILE:
                    raise ValueError('unsafe apply payload')
                total += len(data)
    if total > MAX_TOTAL * 2:
        raise ValueError('apply payload exceeds budget')


def _validate_plan(ctx, plan):
    _check_shape(ctx, plan)
    if _corpus(ctx) != plan.corpus:
        raise ValueError('Xray files changed since preparation')
    for item in plan.changes:
        if _state(_path(ctx, item.logical)) != (item.before, item.mode):
            raise ValueError('apply target changed since preparation')
    if len(plan.observations) > 3:
        raise ValueError('too many apply observations')
    for logical, data, mode in plan.observations:
        if logical not in OBSERVED_FILES:
            raise ValueError('unowned apply observation')
        if _state(config.list_path(logical, ctx.paths.test_root)) != (data, mode):
            raise ValueError('apply dependency changed since preparation')


def require_owner(ctx):
    transaction.guard(ctx)
    state = lock.inspect_lock(snapshot_store._no_links(ctx.paths.lock_dir))
    if state.pid != os.getpid() or not state.alive:
        raise ValueError('apply publication requires own project lock')


def publish(tx, plan, rescue):
    """Publish only under an armed transaction and verified matching full rescue.

    Caller owns rollback (files plus runtime/packages). No pointer is committed
    here. Native full rollback can use the full snapshot after process death.
    """
    ctx = tx.ctx
    require_owner(ctx)
    if not tx.changed or not callable(tx.rollback):
        raise ValueError('apply publication requires armed rescue')
    _validate_plan(ctx, plan)
    saved = snapshot_store.verify(rescue)
    if saved.path.parent != Path(ctx.paths.snapshot_root) or saved.metadata.scope != 'integrated':
        raise ValueError('rescue is outside integrated snapshot store')
    rollback_ops.validate_auxiliary(saved)  # Durable rescue must support full native recovery.
    for item in plan.changes:
        source = saved.path / 'files' / item.logical.lstrip('/')
        before, mode = _state(source)
        if before != item.before or (before is not None and mode != item.mode):
            raise ValueError('rescue does not match apply input')
    validate_staged(ctx, plan)
    _validate_plan(ctx, plan)  # Recheck after external validation and before first write.
    tx.stage('xray')  # Existing panel STAGE contract, not an unrecognised new label.
    for item in plan.changes:
        target = _path(ctx, item.logical)
        if item.after is None:
            target.unlink(missing_ok=True)
        else:
            harden = item.logical.startswith('/opt/etc/xray/configs/') or item.logical == EXTRA_FILES[1]
            fsutil.atomic_bytes(target, item.after, 0o600 if harden or item.before is None else item.mode)


def restore_files(ctx, plan, rescue):
    """Data-only rescue for this exact plan; full runtime restore is caller-owned."""
    require_owner(ctx)
    _check_shape(ctx, plan)
    saved = snapshot_store.verify(rescue)
    if saved.path.parent != Path(ctx.paths.snapshot_root) or saved.metadata.scope != 'integrated':
        raise ValueError('invalid apply rescue')
    # Verify all saved bytes before touching any effective target.
    originals = []
    for item in plan.changes:
        target = _path(ctx, item.logical)
        data, mode = _state(saved.path / 'files' / item.logical.lstrip('/'))
        if data != item.before or (data is not None and mode != item.mode):
            raise ValueError('rescue does not match apply plan')
        originals.append((target, data, mode))
    for target, data, mode in originals:
        if data is None:
            target.unlink(missing_ok=True)
        else:
            fsutil.atomic_bytes(target, data, mode)
