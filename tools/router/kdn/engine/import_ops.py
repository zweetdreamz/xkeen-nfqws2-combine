"""Focused profile operations. No route changes, XKeen calls or package installs."""
import json
import os
from pathlib import Path
import re
import time

from kdn.common import fsutil, retention, xkeen
from kdn.engine import import_worker, confvalues, nfqws_render, nfqws_service, nfqws_validate, nfqws_write
from kdn.engine import profile_descriptor, record_retention, rollback_ops, snapshot_store, snapshot_policy, transaction


def _read(path, maximum=524288):
    return snapshot_store._read(path, maximum)


def _profile(path, high=65535):
    value = json.loads(_read(path))
    try:
        return profile_descriptor.validate_descriptor(value, voice_high=high)
    except ValueError:
        if high != 65535 and isinstance(value, dict) and value.get('service') == 'discord-voice':
            profile_descriptor.validate_descriptor(value, voice_high=65535)
            raise ValueError('imported Discord Voice UDP ports exceed the current range; use --wide-udp or --clear-imported-profile discord-voice') from None
        raise


def _encoded(profile):
    value = dict(profile)
    report = value.get('report') or {}
    value['report'] = {name: report.get(name) or '' for name in profile_descriptor.REPORT_FIELDS}
    seed = report.get('search_seed')
    value['report']['search_seed'] = int(seed) if seed is not None and seed is not False else None
    value['rank'] = int(value['rank'])
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def _header(data):
    prefixes = (b'# Deployment mode:', b'# Active routes:', b'# Discord UDP:', b'# Proxy outbound:')
    return ' | '.join(line.decode('utf-8') for line in data.split(b'\n') if line.startswith(prefixes))


def _context(ctx, replacing_service=None):
    raw = _read(ctx.paths.nfqws_conf, 4 * 1024 * 1024)
    text = raw.decode('utf-8', 'surrogateescape')
    routes = tuple(confvalues.recorded_route(text, name) for name in
                   ('discord-tcp', 'discord-voice', 'youtube'))
    if any(route not in ('direct', 'zapret', 'vless') for route in routes):
        raise ValueError('current managed Discord/YouTube routes cannot be determined; apply a normal route mode once before importing a profile')
    telegram = confvalues.recorded_telegram_route(text)
    if telegram == 'zapret':
        telegram = 'direct'
    strategy, voice_range = confvalues.recorded_udp_settings(text, confvalues.nfqws_value(ctx.paths, 'UDP_PORTS'))
    strategy = strategy or 'flowseal'
    wide = voice_range == 'wide'
    base = Path(ctx.paths.nfqws_conf).parent
    imports = {}
    for service in profile_descriptor.SERVICES:
        file = base / 'imported-profiles' / (service + '.json')
        if file.exists() or file.is_symlink():
            high = 50100 if service == 'discord-voice' and service != replacing_service and routes[1] == 'zapret' and not wide else 65535
            imports[service] = _profile(file, high)
    return raw, routes + (telegram,), strategy, wide, imports


def _render(ctx, state, imports):
    raw, routes, strategy, wide, _old = state
    text = raw.decode('utf-8', 'surrogateescape')
    return nfqws_render.render(nfqws_render.RenderInput(
        raw, routes, udp_strategy=strategy, wide_udp=wide,
        standalone=confvalues.recorded_deployment_mode(text) == 'standalone-zapret',
        wan_interfaces=confvalues.nfqws_value(ctx.paths, 'ISP_INTERFACE'),
        ipv6_enabled=confvalues.nfqws_value(ctx.paths, 'IPV6_ENABLED') not in ('', '0'),
        proxy_outbound=confvalues.recorded_proxy_outbound(text) or '', imported_profiles=imports))


def _archive_plan(ctx, profile, reason):
    directory = Path(ctx.paths.nfqws_conf).parent / 'profile-versions' / profile['service']
    snapshot_store._no_links(directory)
    stem = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + profile['candidate_id'] + '-' + reason + '-' + str(os.getpid())
    target, counter = directory / (stem + '.json'), 0
    while target.exists():
        counter += 1
        target = directory / (stem + '-' + str(counter) + '.json')
    return target, _encoded(profile)


def _archive(ctx, planned):
    target, data = planned
    directory = target.parent
    snapshot_store._no_links(target)
    if target.exists():
        raise ValueError('planned profile archive already exists')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory.parent, 0o700)
    os.chmod(directory, 0o700)
    fsutil.atomic_bytes(target, data, 0o600)
    ctx.console.out('Profile version saved: ' + str(target))


def _pointer(ctx):
    return Path(ctx.paths.state_root) / 'latest-nfqws-import.ptr'


def _prune(ctx, current):
    """Only snapshots older than30d, never the last or a referenced point."""
    transaction.guard(ctx)
    if snapshot_store.focused_pending(ctx.paths):
        return
    directory = snapshot_store._no_links(Path(ctx.paths.state_root) / 'nfqws-import-snapshots')
    keep = retention.keep_count(ctx.environ.get('KD_IMPORT_SNAPSHOT_KEEP', '1'))
    protected = {Path(current).name}
    pointer = _pointer(ctx)
    if pointer.exists() or pointer.is_symlink():
        target = Path(_read(pointer, 4096).decode('utf-8').strip())
        target = snapshot_store._no_links(target)
        if target.parent != directory or not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9]+(?:-[0-9]+)?', target.name):
            raise ValueError('unsafe focused retention pointer')
        protected.add(target.name)
    candidates = []
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries, 1):
            if count > 16384:
                raise ValueError('focused snapshot inventory exceeds retention budget')
            if re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9]+(?:-[0-9]+)?', entry.name) and entry.is_dir(follow_symlinks=False):
                candidates.append(Path(entry.path))
    candidates.sort(key=lambda item: item.name, reverse=True)
    if len(candidates) <= 1:
        return
    protected.update(item.name for item in candidates[:keep])
    record_retention.expire_history(ctx.paths)
    removed = record_retention.expire_versions(ctx.paths)
    if removed:
        ctx.console.out('Old profile versions removed: ' + str(removed))
    protected.update(rollback_ops._history_protected(ctx, focused=True))
    doomed = [item for item in candidates if item.name not in protected and snapshot_store.expired(item, focused=True)]
    if not doomed:
        return
    snapshot_store.verify(next(item for item in candidates if item.name in protected), focused=True)
    for item in doomed:
        snapshot_store.verify(item, focused=True)
    for item in doomed:
        snapshot_store._no_links(item)
        snapshot_store._remove_tree(item)


def _prune_after_success(ctx, snapshot):
    try:
        _prune(ctx, snapshot)
    except (OSError, ValueError, RecursionError):
        ctx.console.err('WARNING: focused snapshot retention skipped; working state remains applied.')


def _capture(tx, purpose, receipt=None):
    ctx = tx.ctx
    extra = (('FOCUSED_OPERATION', snapshot_store.focused_encode(receipt)),) if receipt is not None else ()
    snapshot = snapshot_store.create(ctx.paths, purpose=purpose, focused=True,
        xkeen_version=xkeen.require(environ=ctx.environ),
        metadata=(('NFQWS_RUNNING', '1' if nfqws_service.pid(ctx) is not None else '0'),
                  ('ROUTES_HEADER', _header(_read(ctx.paths.nfqws_conf)))) + extra, allow_live=True)
    ctx.console.out('nfqws2 import snapshot created: ' + str(snapshot))
    return snapshot


def _restore(ctx, snapshot):
    saved = snapshot_store.verify(snapshot, focused=True)
    version = xkeen.require(environ=ctx.environ)
    snapshot_policy.xkeen_restore_policy(saved.metadata.value('XKEEN_VERSION'), version)
    nfqws_service.action(ctx, 'stop')
    snapshot_store.restore_files(ctx.paths, snapshot, focused=True, current_xkeen_version=version, allow_live=True)
    if saved.metadata.value('NFQWS_PRESENT') == '1':
        nfqws_validate.validate_config(ctx, ctx.paths.nfqws_conf)
    nfqws_service.restore_state(ctx, saved.metadata.value('NFQWS_RUNNING'))
    snapshot_store.focused_confirm(Path(ctx.paths.nfqws_conf).parent, saved)


def _operation_context(ctx):
    raw = ctx.options.focused_context
    if not raw:
        return None
    if len(raw) > snapshot_store.FOCUSED_MAX_RECEIPT:
        raise ValueError('focused context exceeds bound')
    value = json.loads(raw)
    snapshot_store.focused_context(value)
    if value['project'] != ctx.environ.get('KDN_ENGINE_SCRIPT'):
        raise ValueError('focused context does not match launcher project')
    return value


def _previous_pointer(pointer, previous):
    if previous is None:
        pointer.unlink(missing_ok=True)
    else:
        fsutil.atomic_bytes(pointer, previous)
        fsutil.fsync_path(pointer)
    fsutil.fsync_path(pointer.parent)


def _install(tx, state, service, profile):
    ctx = tx.ctx
    imports = dict(state[4])
    old = imports.pop(service, None)
    if profile is not None:
        imports[service] = profile
    rendered = _render(ctx, state, imports)
    # Validate a private candidate before capturing/publishing anything effective.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='kdn-profile-') as temporary:
        candidate = Path(temporary) / 'nfqws2.conf'
        fsutil.atomic_bytes(candidate, rendered.config)
        nfqws_validate.validate_config(ctx, candidate)
    base = Path(ctx.paths.nfqws_conf).parent
    target = base / 'imported-profiles' / (service + '.json')
    archives = []
    if old is not None:
        archives.append(_archive_plan(ctx, old, 'replaced' if profile is not None else 'cleared'))
    if profile is not None:
        archives.append(_archive_plan(ctx, profile, 'applied'))
    pointer = _pointer(ctx)
    previous = _read(pointer, 4096) if pointer.exists() else None
    operation = _operation_context(ctx)
    receipt = None
    if operation is not None:
        if (operation['service'] != service or profile is None or operation['candidate_id'] != profile['candidate_id']
                or operation['before_pointer'] != (previous.decode('utf-8').strip() if previous else '')):
            raise ValueError('focused operation does not match import or previous pointer')
        before = snapshot_store.focused_inventory(base)
        snapshot_store.focused_check_before(operation, before)
        changes = {'nfqws2.conf': snapshot_store.focused_file_state(rendered.config, before['nfqws2.conf'][1]),
                   target.relative_to(base).as_posix(): snapshot_store.focused_file_state(_encoded(profile), 0o600),
                   'imported-profiles': ['dir', 0o700]}
        for archive, data in archives:
            changes[archive.relative_to(base).as_posix()] = snapshot_store.focused_file_state(data, 0o600)
            changes[archive.parent.relative_to(base).as_posix()] = ['dir', 0o700]
            changes['profile-versions'] = ['dir', 0o700]
        receipt = {'schema': 1, 'context': snapshot_store.focused_context(operation), 'changes': changes}
    tx.stage('snapshot')
    rescue = _capture(tx, ('import-' if profile is not None else 'clear-') + service, receipt)

    def rollback():
        _restore(ctx, rescue)
        _previous_pointer(pointer, previous)

    tx.arm(rollback)
    snapshot_store.publish_pointer(ctx.paths, pointer, rescue, focused=True, allow_live=True)
    tx.stage('nfqws')
    target = Path(ctx.paths.nfqws_conf).parent / 'imported-profiles' / (service + '.json')
    snapshot_store._no_links(target)
    if old is not None:
        _archive(ctx, archives.pop(0))
    if profile is None:
        target.unlink(missing_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target.parent, 0o700)
        fsutil.atomic_bytes(target, _encoded(profile))
        _archive(ctx, archives.pop(0))
    nfqws_write.publish_config(rendered, ctx)
    tx.stage('verify')
    nfqws_validate.validate_config(ctx, ctx.paths.nfqws_conf)
    nfqws_service.restart(ctx)
    tx.changed = False
    _prune_after_success(ctx, rescue)
    ctx.console.out(('Imported ' + service + ' profile: ' + profile['candidate_id']) if profile is not None
                    else 'Built-in ' + service + ' profile restored.')
    ctx.console.out('XKeen was not restarted or reconfigured.')


def operation(tx):
    ctx = tx.ctx
    operation_context = _operation_context(ctx)
    if ctx.options.mode == 'prune-import-snapshots':
        pointer = _pointer(ctx)
        if pointer.exists():
            current = Path(_read(pointer, 4096).decode('utf-8').strip())
            _prune(ctx, current)
        return
    if ctx.options.mode == 'rollback-import':
        pointer = _pointer(ctx)
        previous_pointer = _read(pointer, 4096)
        target = Path(previous_pointer.decode('utf-8').strip())
        if target.parent != Path(ctx.paths.state_root) / 'nfqws-import-snapshots':
            raise ValueError('invalid nfqws2 import rollback pointer')
        recovery = ctx.options.recover_import_source
        if operation_context is not None and not recovery:
            raise ValueError('automated rollback requires a pinned source')
        if recovery:
            if import_worker.active(operation_context['project'], exclude_pid=os.getpid()) is not False:
                raise ValueError('another focused worker may still be active')
            if str(target) != recovery:
                raise ValueError('focused pointer changed after source was pinned')
            saved, receipt, before, _digest = snapshot_store.focused_source(
                recovery, operation_context, target.parent, fingerprint=operation_context.get('source_fingerprint'))
            if not operation_context.get('source_fingerprint'):
                raise ValueError('automated rollback requires pinned source fingerprint')
            snapshot_store.focused_admit_current(Path(ctx.paths.nfqws_conf).parent, before, receipt)
        else:
            saved = snapshot_store.verify(target, focused=True)
        snapshot_policy.xkeen_restore_policy(saved.metadata.value('XKEEN_VERSION'), xkeen.require(environ=ctx.environ))
        header = saved.metadata.value('ROUTES_HEADER')
        if not any(row[0] == b'ROUTES_HEADER' for row in saved.metadata.rows):
            legacy_config = target / 'nfqws2/nfqws2.conf'
            header = _header(_read(legacy_config)) if legacy_config.exists() else ''
        if header != _header(_read(ctx.paths.nfqws_conf)):
            raise ValueError('the routes changed after the latest profile operation; its nfqws2 snapshot no longer matches Xray')
        tx.stage('snapshot')
        rescue = _capture(tx, 'pre-import-rollback-rescue')
        def rollback():
            _restore(ctx, rescue)
            _previous_pointer(pointer, previous_pointer)

        tx.arm(rollback)
        tx.stage('restore')
        _restore(ctx, target)
        snapshot_store.publish_pointer(ctx.paths, pointer, target if recovery else rescue, focused=True, allow_live=True)
        tx.changed = False
        _prune_after_success(ctx, rescue)
        if recovery:
            ctx.console.out('FOCUSED_RECOVERED|' + operation_context['operation_id'] + '|' + operation_context['source_fingerprint'])
        ctx.console.out('Latest profile operation rolled back. XKeen was not touched.')
        return
    service = ctx.options.clear_profile
    candidate = None
    if ctx.options.mode == 'apply-import-profile':
        raw_path = ctx.options.import_profile
        staging = snapshot_store._no_links(raw_path)
        boundary = Path(ctx.paths.work_tmp_root)
        if not staging.is_relative_to(boundary) or staging == boundary or re.search(r'(^|/)\.\.(/|$)|//', raw_path):
            raise ValueError('profile staging file must be a regular file below /opt/tmp')
        candidate = _profile(staging)
        service = candidate['service']
    if service not in profile_descriptor.SERVICES:
        raise ValueError('unsupported imported profile service')
    target = Path(ctx.paths.nfqws_conf).parent / 'imported-profiles' / (service + '.json')
    if candidate is None and not target.exists() and not target.is_symlink():
        ctx.console.out('No imported ' + service + ' profile is installed.')
        return
    if nfqws_service.pid(ctx) is None:
        raise ValueError('nfqws2 is currently stopped; start it before applying a profile.')
    state = _context(ctx, service)
    if candidate is not None and state[1][('discord-tcp', 'discord-voice', 'youtube').index(service)] != 'zapret':
        raise ValueError(service + ' currently does not use route=zapret')
    _install(tx, state, service, candidate)


def run(ctx):
    return transaction.execute(ctx, operation)
