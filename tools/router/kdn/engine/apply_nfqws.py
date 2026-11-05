"""E4 nfqws data preparation, shadow-root validation and guarded publication."""
from collections import namedtuple
import hashlib
from pathlib import Path

from kdn.common import fsutil
from kdn.engine import apply_files, config, import_ops, nfqws_render, nfqws_validate, snapshot_store


Prepared = namedtuple('Prepared', 'rendered changes')
BASE = '/opt/etc/nfqws2/'
OWNED = ('nfqws2.conf', 'lists/user.list', 'lists/youtube.list', 'lists/kdn-telegram.list',
         'lists/kdn-telegram-ip.list', 'lists/kdn-telegram-cf.list', 'imported-profiles/telegram.json',
         'blobs/discord_udp.bin')


def _target(ctx, logical):
    if not logical.startswith(BASE) or logical[len(BASE):] not in OWNED:
        raise ValueError('unowned nfqws apply target')
    return snapshot_store._no_links(config.list_path(logical, ctx.paths.test_root))


def _hostlist(ctx, name):
    data = snapshot_store._read(Path(ctx.paths.script_dir) / 'config' / (name + '-user.list'), 65536)
    lines = data.decode('ascii').splitlines()
    if not lines or any(not line or any(char not in 'abcdefghijklmnopqrstuvwxyz0123456789-._' for char in line)
                        for line in lines):
        raise ValueError('invalid repository hostlist')
    return ('\n'.join(lines) + '\n').encode('ascii')


def _verified(path, expected):
    data = snapshot_store._read(path, 4 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('required nfqws blob checksum mismatch')
    return data


def prepare(ctx, *, routes, wan, ipv6, proxy_outbound):
    raw = snapshot_store._read(ctx.paths.nfqws_conf, 1024 * 1024)
    imports = {}
    for service in ('discord-tcp', 'discord-voice', 'youtube'):
        path = Path(ctx.paths.nfqws_conf).parent / 'imported-profiles' / (service + '.json')
        if path.exists() or path.is_symlink():
            high = int(ctx.resolved.voice_high) if service == 'discord-voice' and routes[1] == 'zapret' else 65535
            imports[service] = import_ops._profile(path, high)
    rendered = nfqws_render.render(nfqws_render.RenderInput(raw, routes,
        udp_strategy=ctx.resolved.udp_strategy, wide_udp=ctx.resolved.wide_udp,
        wan_interfaces=wan, ipv6_enabled=ipv6, proxy_outbound=proxy_outbound, imported_profiles=imports))
    directory = Path(ctx.paths.nfqws_conf).parent
    data = {'nfqws2.conf': rendered.config,
            'lists/user.list': _hostlist(ctx, 'discord') if routes[0] == 'zapret' else (config.NFQWS_DISABLED_HOST + '\n').encode(),
            'lists/youtube.list': _hostlist(ctx, 'youtube'), 'lists/kdn-telegram.list': _hostlist(ctx, 'telegram'),
            'lists/kdn-telegram-ip.list': None, 'lists/kdn-telegram-cf.list': None,
            'imported-profiles/telegram.json': None}
    if 'discord_udp' in rendered.required_blobs:
        data['blobs/discord_udp.bin'] = _verified(ctx.paths.source_discord_udp_blob, config.DISCORD_UDP_BLOB_SHA256)
    elif routes[1] == 'zapret' and ctx.resolved.udp_strategy == 'legacy':
        data['blobs/discord_udp.bin'] = None
    if routes[2] == 'zapret':
        _verified(directory / 'blobs/quic_initial.bin', config.YOUTUBE_QUIC_BLOB_SHA256)
        _verified(directory / 'blobs/tls_clienthello.bin', config.YOUTUBE_TLS_BLOB_SHA256)
    if routes[3] == 'ws':
        _verified(directory / 'blobs/tls_clienthello.bin', config.YOUTUBE_TLS_BLOB_SHA256)
    changes = []
    for name, value in data.items():
        logical = BASE + name
        before, mode = apply_files._state(_target(ctx, logical))
        if before != value:
            changes.append(apply_files.Change(logical, before, mode, value))
    return Prepared(rendered, tuple(changes))


def validate_staged(ctx, prepared):
    """Validate all prospective lists/blobs/config using a private disposable root.

    The original daemon binary still uses the approved pin; only its read paths
    are remapped. No production test-root/environment override is trusted.
    """
    import tempfile

    base = Path(ctx.paths.nfqws_conf).parent
    inventory = snapshot_store._walk(base)  # Aggregate/entry/type budget before first copy.
    if sum(info.st_size for _name, info in inventory) > 32 * 1024 * 1024 or len(inventory) > 1024:
        raise ValueError('nfqws staging corpus exceeds budget')
    with tempfile.TemporaryDirectory(prefix='kdn-nfqws-check-', dir=ctx.paths.work_tmp_root) as folder:
        shadow = Path(folder)
        destination = shadow / 'opt/etc/nfqws2'
        snapshot_store._copy(base, destination, '/opt/etc/nfqws2', 'integrated')
        init = shadow / 'opt/etc/init.d/S51nfqws2'
        fsutil.atomic_bytes(init, snapshot_store._read(ctx.paths.nfqws_init, 1024 * 1024), 0o700)
        for item in prepared.changes:
            _target(ctx, item.logical)
            target = shadow / item.logical.lstrip('/')
            if item.after is None:
                target.unlink(missing_ok=True)
            else:
                fsutil.atomic_bytes(target, item.after, 0o600)
        env = {key: value for key, value in ctx.environ.items() if not key.startswith('KD_TEST_')}
        env.update(KD_TEST_ROOT=str(shadow), KD_ALLOW_TEST_ROOT='1', KD_TEST_NFQWS2_BIN=ctx.paths.nfqws_bin)
        if ctx.paths.test_root:
            for key in ('KD_TEST_NFQWS2_BIN', 'KD_TEST_NFQWS2_LUA_SRC', 'KD_TEST_NFQWS2_LUA'):
                if ctx.environ.get(key):
                    env[key] = ctx.environ[key]
        paths = config.EnginePaths.from_environ(env)
        class Candidate:
            pass
        candidate = Candidate()
        candidate.paths, candidate.environ = paths, env
        nfqws_validate.validate_config(candidate, paths.nfqws_conf)


def publish(tx, prepared):
    apply_files.require_owner(tx.ctx)
    if not tx.changed or not callable(tx.rollback):
        raise ValueError('nfqws apply requires armed rescue')
    if (not isinstance(prepared, Prepared) or len(prepared.changes) > len(OWNED)
            or len({item.logical for item in prepared.changes}) != len(prepared.changes)):
        raise ValueError('invalid nfqws data plan')
    # Check every source before first publication; changes may only come from prepare.
    for item in prepared.changes:
        path = _target(tx.ctx, item.logical)
        if apply_files._state(path) != (item.before, item.mode):
            raise ValueError('nfqws data changed since preparation')
        if (type(item.mode) is not int or not 0 <= item.mode <= 0o777
                or any(data is not None and (not isinstance(data, bytes) or len(data) > 1024 * 1024)
                       for data in (item.before, item.after))):
            raise ValueError('unsafe nfqws data plan payload')
    validate_staged(tx.ctx, prepared)
    for item in prepared.changes:
        if apply_files._state(_target(tx.ctx, item.logical)) != (item.before, item.mode):
            raise ValueError('nfqws data changed during validation')
    for item in prepared.changes:
        target = _target(tx.ctx, item.logical)
        if item.after is None:
            target.unlink(missing_ok=True)
        else:
            mode = item.mode if item.before is not None else (0o644 if '/lists/' in item.logical else 0o600)
            fsutil.atomic_bytes(target, item.after, mode)
