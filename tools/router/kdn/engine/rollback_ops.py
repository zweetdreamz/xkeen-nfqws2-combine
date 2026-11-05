"""Native baseline/manual restore transactions; data store never controls services."""
from pathlib import Path
import json
import os
import re

from kdn.common import retention, xkeen
from kdn.engine import config, confvalues, nfqws_process, nfqws_service, nfqws_validate
from kdn.engine import preflight_xray, record_retention, relay_restore, snapshot_policy, snapshot_store, transaction, xkeen_service


PACKAGES = ('ca-certificates', 'jq', 'wget-ssl', 'wget-nossl', 'nfqws2-keenetic')
MODES = ('snapshot-baseline', 'rollback-baseline', 'rollback-latest', 'rollback-snapshot')
_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}')
_IPV6 = re.compile(r'net\.ipv6\.conf\.[A-Za-z0-9_.:-]+\.disable_ipv6')
INIT_SETTINGS = ('name_client', 'name_policy', 'name_profile', 'table_id', 'table_mark', 'custom_mark',
    'dscp_exclude', 'dscp_proxy', 'ipv4_proxy', 'ipv4_exclude', 'ipv6_proxy', 'ipv6_exclude',
    'proxy_dns', 'proxy_router', 'start_attempts', 'start_auto', 'start_delay', 'init_delay',
    'check_fd', 'arm64_fd', 'other_fd', 'delay_fd', 'ipv6_support', 'extended_msg', 'backup', 'aghfix')
RUNTIME_SETTINGS = ('name_client', 'name_profile', 'mode_proxy', 'network_redirect', 'network_tproxy',
    'networks', 'port_redirect', 'port_tproxy', 'port_donor', 'port_exclude', 'policy_mark', 'custom_mark',
    'dscp_exclude', 'dscp_proxy', 'table_mark', 'table_id', 'file_dns', 'proxy_dns', 'proxy_router',
    'iptables_supported', 'ip6tables_supported', 'ipv4_proxy', 'ipv6_proxy')
_SNAPSHOT_LEAF = re.compile(r'[0-9]{8}-[0-9]{6}-[0-9]+(?:-[0-9]+)?')
_HISTORY_REFERENCE = re.compile(r'keenetic-discord-nfqws2/snapshots/('
    + _SNAPSHOT_LEAF.pattern + r')(?=$|[^0-9A-Za-z-])')
_IMPORT_HISTORY_REFERENCE = re.compile(r'keenetic-discord-nfqws2/nfqws-import-snapshots/('
    + _SNAPSHOT_LEAF.pattern + r')(?=$|[^0-9A-Za-z-])')
MAX_RETENTION_ENTRIES = 16384
MAX_HISTORY_RECORDS = 4096
MAX_HISTORY_BYTES = 64 * 1024 * 1024


def _history_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('ambiguous snapshot history record')
        value[key] = item
    return value


def _history_protected(ctx, *, focused=False):
    """Read all bounded history references; unreadable history cancels pruning.

    Never consult a paginated UI view: even its oldest existing JSON record
    protects its snapshot. References can only protect names, never authorise
    deletion or filesystem targets. No record is modified by this reader.
    """
    folders = [snapshot_store._no_links(config_path(ctx, logical)) for logical in (
        '/opt/etc/xkeen-web/history', '/opt/etc/xkeen-web/record-trash/history')]
    protected, total, count = set(), 0, 0
    reference = _IMPORT_HISTORY_REFERENCE if focused else _HISTORY_REFERENCE
    for folder in folders:
        if not folder.exists():
            continue
        with os.scandir(folder) as entries:
            for entry in entries:
                count += 1
                if count > MAX_HISTORY_RECORDS:
                    raise ValueError('snapshot history exceeds retention read budget')
                if not entry.name.endswith('.json'):
                    continue
                raw = snapshot_store._read(entry.path, 524288)
                total += len(raw)
                if total > MAX_HISTORY_BYTES:
                    raise ValueError('snapshot history exceeds retention byte budget')
                pending = [json.loads(raw, object_pairs_hook=_history_object)]
                visited = 0
                while pending:
                    value = pending.pop()
                    visited += 1
                    if visited > 65536:
                        raise ValueError('snapshot history structure exceeds retention budget')
                    if isinstance(value, str):
                        protected.update(match[1] for match in reference.finditer(value))
                    elif isinstance(value, dict):
                        pending.extend(value.values())
                    elif isinstance(value, list):
                        pending.extend(value)
    return protected


def _prune_snapshots(ctx, current, targets=()):
    """Age30d, retain at least one + pointers/run/history refs.

    Unknown names/links are never deletion candidates. Verify every doomed full
    snapshot before the first deletion; a corrupt corpus stops cleanup safely.
    Caller holds the transaction lock and already committed working state.
    """
    transaction.guard(ctx)
    folder = snapshot_store._no_links(ctx.paths.snapshot_root)
    if not folder.exists():
        return
    keep = retention.keep_count(ctx.environ.get('KD_SNAPSHOT_KEEP', '1'), maximum=MAX_RETENTION_ENTRIES)
    protected = set()
    for target in (current, *targets):
        path = target.path if isinstance(target, snapshot_store.VerifiedSnapshot) else Path(target)
        path = snapshot_store._no_links(path)
        if path.parent != folder:
            raise ValueError('retention protected target is outside snapshot store')
        protected.add(path.name)
    for pointer in (ctx.paths.baseline_pointer, ctx.paths.xkeen_baseline_pointer, ctx.paths.latest_pointer):
        pointer = Path(pointer)
        if pointer.exists() or pointer.is_symlink():
            value = snapshot_store._read(pointer, 4096).decode('utf-8').strip()
            target = snapshot_store._no_links(value)
            if not value or target.parent != folder or not _SNAPSHOT_LEAF.fullmatch(target.name):
                raise ValueError('unsafe snapshot retention pointer')
            protected.add(target.name)
    candidates = []
    with os.scandir(folder) as entries:
        for count, entry in enumerate(entries, 1):
            if count > MAX_RETENTION_ENTRIES:
                raise ValueError('snapshot inventory exceeds retention budget')
            if _SNAPSHOT_LEAF.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                candidates.append(Path(entry.path))
    candidates.sort(key=lambda path: path.name, reverse=True)
    if len(candidates) <= 1:
        return
    protected.update(path.name for path in candidates[:keep])
    moved, removed = record_retention.expire_history(ctx.paths, protected)
    if moved or removed:
        ctx.console.out(f'Old history archived: {moved}; expired trash removed: {removed}')
    protected.update(_history_protected(ctx))
    doomed = [path for path in candidates if path.name not in protected and snapshot_store.expired(path)]
    if not doomed:
        return
    # Verify a surviving restore point as well as every deletion candidate.
    survivor = next(path for path in candidates if path.name in protected)
    snapshot_store.verify(survivor)
    for path in doomed:
        snapshot_store.verify(path)
    for path in doomed:
        snapshot_store._no_links(path)
        snapshot_store._remove_tree(path)
    if doomed:
        ctx.console.out('Old snapshots removed: ' + str(len(doomed)))


def _prune_after_success(ctx, current, targets=()):
    try:
        _prune_snapshots(ctx, current, targets)
    except (OSError, ValueError, RecursionError):
        ctx.console.err('WARNING: snapshot retention skipped; working state remains restored.')


def _run(ctx, argv, timeout=90, required=True):
    done = nfqws_process.run(argv, ctx.environ, timeout=timeout, output_limit=1024 * 1024, cwd='/')
    if required and (done.returncode or done.timed_out or done.output_limited):
        raise RuntimeError('restore command failed: ' + Path(argv[0]).name)
    return done


def package_version(ctx, name):
    """Strict bounded status query: a failed query is never mistaken for ABSENT."""
    if name not in (*PACKAGES, 'xkeen'):
        raise ValueError('unowned package query')
    done = _run(ctx, ['opkg', 'status', name], timeout=20)
    fields = {}
    for line in done.output.splitlines():
        if line.startswith(('Package:', 'Status:', 'Version:')):
            key, value = line.split(':', 1)
            if key in fields:
                raise ValueError('ambiguous installed package state')
            fields[key] = value.strip()
    if fields.get('Package', name) != name:
        raise ValueError('installed package query returned another package')
    if 'installed' not in fields.get('Status', '').split():
        if done.output.strip() and 'Status' not in fields:
            raise ValueError('unrecognised installed package state')
        return ''
    version = fields.get('Version', '')
    if not _VERSION.fullmatch(version):
        raise ValueError('invalid installed package version')
    return version


def xkeen_version(ctx):
    # Package database failures remain fatal, but its cached version is not
    # authoritative after a script-only XKeen upgrade/downgrade. Always label
    # snapshots with the actually running installation's own version output.
    version = xkeen.require(environ=ctx.environ)
    package_version(ctx, 'xkeen')
    return version


def _table(raw, columns):
    result = {}
    for row in raw.splitlines():
        fields = row.decode('utf-8').split('\t')
        if len(fields) != columns or fields[0] in result or not fields[0]:
            raise ValueError('invalid restore metadata table')
        result[fields[0]] = fields[1:]
    return result


def validate_auxiliary(saved):
    packages = _table(saved.auxiliary.get('PACKAGES.tsv', b''), 3)
    if set(packages) != set(PACKAGES):
        raise ValueError('snapshot package inventory is incomplete or unowned')
    for presence, version in packages.values():
        if presence not in ('PRESENT', 'ABSENT') or (presence == 'PRESENT' and not _VERSION.fullmatch(version)):
            raise ValueError('invalid snapshot package version/state')
        if presence == 'ABSENT' and version not in ('', '-'):
            raise ValueError('absent package has a version')
    runtime = _table(saved.auxiliary.get('RUNTIME.tsv', b''), 2)
    if (set(runtime) != {'XKEEN_RUNNING', 'NFQWS_RUNNING'}
            or runtime['NFQWS_RUNNING'] not in (['0'], ['1'])
            or runtime['XKEEN_RUNNING'] not in ((['0'], ['1'], ['UNMANAGED'])
                if saved.metadata.scope == 'standalone' else (['0'], ['1']))):
        raise ValueError('invalid snapshot runtime state')
    ipv6, seen = [], set()
    for row in saved.auxiliary.get('IPV6_RUNTIME.txt', b'').decode('ascii').splitlines():
        key, equal, value = row.partition('=')
        key, value = key.strip(), value.strip()
        if not equal or not _IPV6.fullmatch(key) or value not in ('0', '1') or key in seen:
            raise ValueError('invalid saved IPv6 runtime setting')
        seen.add(key)
        ipv6.append((key, value))
    return packages, {key: value[0] for key, value in runtime.items()}, ipv6


def capture(ctx, purpose, scope=None):
    transaction.guard(ctx)
    scope = scope or ('standalone' if ctx.resolved.standalone else 'integrated')
    rows = []
    for name in PACKAGES:
        version = package_version(ctx, name)
        if version and not _VERSION.fullmatch(version):
            raise ValueError('invalid installed package version')
        rows.append(name + '\t' + ('PRESENT\t' + version if version else 'ABSENT\t-') + '\n')
    running = xkeen_service.pid(ctx) is not None if scope == 'integrated' else False
    runtime = ('XKEEN_RUNNING\t' + (str(int(running)) if scope == 'integrated' else 'UNMANAGED')
               + '\nNFQWS_RUNNING\t' + str(int(nfqws_service.pid(ctx) is not None)) + '\n')
    ipv6 = b''
    if not ctx.paths.test_root:
        done = _run(ctx, ['sysctl', '-a'], timeout=10, required=False)
        if not done.returncode and not done.output_limited:
            ipv6 = ('\n'.join(line for line in done.output.splitlines()
                     if re.fullmatch(r'net\.ipv6\.conf\.[A-Za-z0-9_.:-]+\.disable_ipv6\s*=\s*[01]', line)) + '\n').encode()
            if ipv6 == b'\n':
                ipv6 = b''
    settings, runtime_settings = b'', b''
    if scope == 'integrated':
        for path, keys, destination in ((ctx.paths.xkeen_init, INIT_SETTINGS, 'init'),
                                       (ctx.paths.xkeen_hook, RUNTIME_SETTINGS, 'runtime')):
            text = snapshot_store._read(path, 1024 * 1024).decode('utf-8', 'surrogateescape') if Path(path).exists() else ''
            data = ''.join(key + '\t' + confvalues.assigned_value(text, key) + '\n' for key in keys).encode('utf-8', 'surrogateescape')
            if destination == 'init':
                settings = data
            else:
                runtime_settings = data
    inventory = _run(ctx, ['opkg', 'list-installed'], timeout=20, required=False)
    inventory_bytes = b'' if inventory.returncode or inventory.timed_out or inventory.output_limited else ('\n'.join(sorted(inventory.output.splitlines())) + '\n').encode('utf-8')
    snapshot = snapshot_store.create(ctx.paths, purpose=purpose, scope=scope,
        xkeen_version=xkeen_version(ctx),
        auxiliary={'PACKAGES.tsv': ''.join(rows).encode(), 'RUNTIME.tsv': runtime.encode(),
                   'IPV6_RUNTIME.txt': ipv6, 'XKEEN_SETTINGS.tsv': settings, 'XKEEN_RUNTIME_SETTINGS.tsv': runtime_settings,
                   'OPKG_INSTALLED.txt': inventory_bytes, 'READONLY_AUDIT.txt': b'Native guarded snapshot\n'}, allow_live=True)
    ctx.console.out('Snapshot created: ' + str(snapshot))
    return snapshot


def _xkeen_state(ctx, running):
    if running not in ('0', '1'):
        raise ValueError('invalid saved XKeen runtime state')
    if running == '0':
        if Path(ctx.paths.xkeen_init).exists():
            xkeen_service.action(ctx, 'stop')
        if xkeen_service.pid(ctx) is not None:
            raise RuntimeError('XKeen core is still running after stop')
        return
    if not Path(ctx.paths.xkeen_init).is_file():
        raise RuntimeError('XKeen init script is absent')
    version = xkeen_version(ctx)
    if not snapshot_policy.versions_compatible(version, version):
        raise ValueError('XKeen2.1+ is required for runtime restoration')
    xkeen_service.action(ctx, 'start')


def _relay_route(ctx, saved=None):
    path = Path(ctx.paths.nfqws_conf) if saved is None else saved.path / 'files/opt/etc/nfqws2/nfqws2.conf'
    return confvalues.recorded_telegram_route(confvalues.read_text(path))


def _relay_preflight(ctx, targets):
    if not any(saved.metadata.scope == 'integrated' for saved in targets):
        return
    relay_restore.preflight(ctx, [_relay_route(ctx), *(_relay_route(ctx, saved) for saved in targets)])


def config_path(ctx, logical):
    # config.list_path is the canonical logical-root remapper.
    return config.list_path(logical, ctx.paths.test_root)


def _packages(ctx, packages):
    for wanted in ('ABSENT', 'PRESENT'):
        for name in PACKAGES:
            presence, version = packages[name]
            current = package_version(ctx, name)
            if presence != wanted:
                continue
            if presence == 'ABSENT' and current:
                ctx.console.out('Removing package added by this project: ' + name)
                _run(ctx, ['opkg', 'remove', name])
                if package_version(ctx, name):
                    raise RuntimeError('added package was not removed')
            elif presence == 'PRESENT' and not current:
                ctx.console.out('Reinstalling baseline package: ' + name)
                _run(ctx, ['opkg', 'install', name])
                if name == 'nfqws2-keenetic':
                    nfqws_service.action(ctx, 'stop')
                if not package_version(ctx, name):
                    raise RuntimeError('baseline package was not installed')
            elif presence == 'PRESENT' and current != version:
                ctx.console.err('WARNING: ' + name + ' version is ' + current + '; snapshot has ' + version + '.')
                ctx.console.err('         opkg cannot downgrade it; the package stays at ' + current + '.')


def restore(ctx, saved, *, reconcile_relay=True):
    transaction.guard(ctx)
    saved = snapshot_store.verify(saved.path if isinstance(saved, snapshot_store.VerifiedSnapshot) else saved)
    if saved.metadata.scope == 'integrated':
        nfqws_process.service_capture_ready()
    snapshot_policy.xkeen_restore_policy(saved.metadata.value('XKEEN_VERSION'), xkeen_version(ctx))
    packages, runtime, ipv6 = validate_auxiliary(saved)
    if saved.metadata.scope == 'integrated' and runtime['XKEEN_RUNNING'] == '1':
        init = saved.path / 'files/opt/etc/init.d/S05xkeen'
        if init.exists():
            client = confvalues.assigned_value(snapshot_store._read(init, 1024 * 1024).decode('utf-8', 'surrogateescape'), 'name_client')
            if client and client != 'xray':
                raise ValueError('historical non-Xray runtime cannot be activated; snapshot remains readable')
    _relay_preflight(ctx, [saved])
    nfqws_service.action(ctx, 'stop')
    if saved.metadata.scope == 'integrated':
        _xkeen_state(ctx, '0')
    _packages(ctx, packages)
    outcome = snapshot_store.restore_files(ctx.paths, saved.path,
        current_xkeen_version=xkeen_version(ctx),
        current_nfqws_version=package_version(ctx, 'nfqws2-keenetic'), allow_live=True)
    for warning in outcome.warnings:
        ctx.console.err('WARNING: ' + warning)
        if warning.startswith('nfqws2 package drift;'):
            ctx.console.out('Restoring nfqws2 configuration, lists and blobs only; package files are kept.')
    if runtime['NFQWS_RUNNING'] == '1':
        nfqws_validate.validate_config(ctx, ctx.paths.nfqws_conf)
    if saved.metadata.scope == 'integrated':
        if runtime['XKEEN_RUNNING'] == '1' and confvalues.init_value(ctx.paths, 'name_client') == 'xray':
            if preflight_xray.xray_test_config(ctx.paths, ctx.environ) is not None:
                raise RuntimeError('restored Xray configuration test failed')
        _xkeen_state(ctx, runtime['XKEEN_RUNNING'])
    nfqws_service.restore_state(ctx, runtime['NFQWS_RUNNING'])
    if not ctx.paths.test_root:
        for key, value in ipv6:
            if not _run(ctx, ['sysctl', '-n', key], timeout=10, required=False).returncode:
                _run(ctx, ['sysctl', '-w', key + '=' + value], timeout=10)
    if reconcile_relay and saved.metadata.scope == 'integrated':
        relay_restore.reconcile(ctx, _relay_route(ctx))


def _pointer(ctx, path):
    pointer = snapshot_store._read(path, 4096).decode('utf-8').strip()
    target = snapshot_store._no_links(pointer)
    if target.parent != Path(ctx.paths.snapshot_root):
        raise ValueError('snapshot pointer target is outside managed store')
    return snapshot_store.verify(target)


def resolve_targets(ctx):
    mode = ctx.options.mode
    if mode == 'rollback-snapshot':
        target = snapshot_store._no_links(ctx.options.rollback_snapshot)
        if target.parent != Path(ctx.paths.snapshot_root):
            raise ValueError('requested snapshot is outside managed store')
        targets = [snapshot_store.verify(target)]
    elif mode == 'rollback-latest':
        targets = [_pointer(ctx, ctx.paths.latest_pointer)]
    else:
        targets = [_pointer(ctx, ctx.paths.baseline_pointer)]
        if Path(ctx.paths.xkeen_baseline_pointer).exists():
            xkeen = _pointer(ctx, ctx.paths.xkeen_baseline_pointer)
            if xkeen.metadata.scope != 'integrated':
                raise ValueError('XKeen baseline is not integrated')
            targets.insert(0, xkeen)
    if ctx.resolved.standalone and any(saved.metadata.scope == 'integrated' for saved in targets):
        raise ValueError('standalone mode refuses an integrated snapshot')
    for saved in targets:
        snapshot_policy.xkeen_restore_policy(saved.metadata.value('XKEEN_VERSION'), xkeen_version(ctx))
        validate_auxiliary(saved)
    _relay_preflight(ctx, targets)
    return targets


def operation(tx):
    ctx = tx.ctx
    if ctx.options.mode not in MODES:
        raise ValueError('unsupported native snapshot operation')
    if ctx.options.mode == 'snapshot-baseline':
        if Path(ctx.paths.baseline_pointer).exists():
            existing = _pointer(ctx, ctx.paths.baseline_pointer)
            ctx.console.out('Baseline already exists and is immutable: ' + str(existing.path))
            if not ctx.resolved.standalone:
                version = xkeen_version(ctx)
                version_baseline = (_pointer(ctx, ctx.paths.xkeen_baseline_pointer)
                    if Path(ctx.paths.xkeen_baseline_pointer).exists() else existing)
                if Path(ctx.paths.xkeen_baseline_pointer).exists() and version_baseline.metadata.scope != 'integrated':
                    raise ValueError('XKeen baseline is not integrated')
                if (snapshot_policy.versions_compatible(version, version)
                        and (version_baseline.metadata.scope != 'integrated'
                             or not snapshot_policy.versions_compatible(version_baseline.metadata.value('XKEEN_VERSION'), version))):
                    tx.stage('snapshot')
                    replacement = capture(ctx, 'xkeen-version-baseline', 'integrated')
                    snapshot_store.rollover_xkeen_baseline(ctx.paths, replacement, version, allow_live=True)
                    ctx.console.out('XKeen version-specific baseline recorded: ' + str(replacement))
            return
        tx.stage('snapshot')
        saved = capture(ctx, 'baseline')
        snapshot_store.publish_pointer(ctx.paths, ctx.paths.baseline_pointer, saved, baseline=True, allow_live=True)
        ctx.console.out('Baseline recorded: ' + str(saved))
        return
    targets = resolve_targets(ctx)
    scope = 'integrated' if any(saved.metadata.scope == 'integrated' for saved in targets) else 'standalone'
    if scope == 'integrated':
        nfqws_process.service_capture_ready()
    tx.stage('snapshot')
    rescue = capture(ctx, 'pre-rollback-rescue', scope)
    ctx.console.out('Rescue snapshot of current state: ' + str(rescue))
    relay_state = relay_restore.capture(ctx) if scope == 'integrated' else None

    def undo():
        if relay_state is not None:
            relay_restore.restore_init(ctx, relay_state)
        # Relay runtime may intentionally have been stopped/absent while its
        # recorded route is ws. Do not start a transient replacement during
        # rescue: exact in-memory init/runtime restoration follows below.
        restore(ctx, rescue, reconcile_relay=False)
        if relay_state is not None:
            relay_restore.restore_saved(ctx, relay_state)

    tx.arm(undo)
    tx.stage('restore')
    for target in targets:
        restore(ctx, target)
    tx.stage('verify')
    (Path(ctx.paths.state_root) / 'latest-nfqws-import.ptr').unlink(missing_ok=True)
    tx.changed = False
    _prune_after_success(ctx, rescue, targets)
    label = {'rollback-baseline': 'Baseline', 'rollback-latest': 'Latest pre-apply',
             'rollback-snapshot': 'Selected snapshot'}[ctx.options.mode]
    ctx.console.out(label + ' rollback complete.')


def run(ctx):
    return transaction.execute(ctx, operation)
