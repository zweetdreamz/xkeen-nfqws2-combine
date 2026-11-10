"""E4 dependency primitives, composed by the future full-apply orchestrator.

No CLI activation here. Port rendering is pure, package mutations require an
armed transaction + own lock; relay reuses the phase5 guarded implementation.
"""
from kdn.engine import apply_files, config, confvalues, nfqws_process, nfqws_service
from kdn.engine import relay_restore, rollback_ops, snapshot_store


FEED_PATH = '/opt/etc/opkg/nfqws2-keenetic.conf'
FEED = b'src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all\n'
INSTALL = ('ca-certificates', 'wget-ssl', 'nfqws2-keenetic')
REMOVE = ('wget-nossl',)
PACKAGE_TIMEOUT = 120


def render_ports(current, excluded=b'', *, voice_high=50100, telegram='unmanaged'):
    """Preserve user lines; modify only our complete LF-delimited port block.

    Unrestricted (no active ports) stays untouched. Incomplete/nested markers are
    refused rather than allowing sed to consume unrelated user configuration.
    """
    if not isinstance(current, bytes) or not isinstance(excluded, bytes):
        raise ValueError('port lists must be bytes')
    if type(voice_high) is not int or not 50000 <= voice_high <= 65535:
        raise ValueError('invalid voice port range')
    if telegram not in ('direct', 'vless', 'ws', 'unmanaged'):
        raise ValueError('invalid Telegram mode')
    if not confvalues.active_ports(current.decode('utf-8', 'surrogateescape')):
        return current, ()
    retained, inside = [], False
    for line in current.splitlines(keepends=True):
        marker = line.removesuffix(b'\n')
        if marker == snapshot_store.BEGIN:
            if inside:
                raise ValueError('nested managed port block')
            # This LF separator was inserted with the managed block. Everything
            # else outside its markers (including user CRLF/blank lines) is opaque.
            if retained and retained[-1] == b'\n':
                retained.pop()
            inside = True
        elif marker == snapshot_store.END:
            if not inside:
                raise ValueError('orphan managed port block end')
            inside = False
        elif not inside:
            retained.append(line)
    if inside:
        raise ValueError('unterminated managed port block')
    prefix = b''.join(retained)
    if prefix and not prefix.endswith(b'\n'):
        prefix += b'\n'
    ports = ['80', '443', '2053', '2083', '2087', '2096', '8443', '3478:3481',
             '5349', '19294:19344', f'50000:{voice_high}']
    warnings = []
    if telegram != 'unmanaged':
        ports.append('5222')
    if telegram == 'vless':
        exclusions = confvalues.active_ports(excluded.decode('utf-8', 'surrogateescape'))
        for port in config.TELEGRAM_CALL_PORTS.split(','):
            if confvalues.ports_overlap(exclusions, port):
                warnings.append('port_exclude.lst excludes Telegram call port ' + port + '; calls bypass VPN')
            else:
                ports.append(port)
    block = snapshot_store.BEGIN + b'\n' + ('\n'.join(ports) + '\n').encode() + snapshot_store.END + b'\n'
    return prefix + b'\n' + block, tuple(warnings)


def prepare_files(ctx, plan, *, voice_high=50100, telegram='unmanaged'):
    """Read both port lists before publication; excluded ports are never edited."""
    plan = apply_files.observe(ctx, plan, '/opt/etc/xkeen/port_proxying.lst')
    plan = apply_files.observe(ctx, plan, '/opt/etc/xkeen/port_exclude.lst')
    current = plan.observations[-2][1]
    excluded = plan.observations[-1][1]
    rendered, warnings = render_ports(current or b'', excluded or b'', voice_high=voice_high, telegram=telegram)
    updates = {FEED_PATH: FEED}
    if current is not None and rendered != current:
        updates['/opt/etc/xkeen/port_proxying.lst'] = rendered
    return apply_files.extend(ctx, plan, updates), warnings


def package_plan(ctx):
    """Query every owned package before returning any action; errors fail closed."""
    versions = {name: rollback_ops.package_version(ctx, name) for name in (*INSTALL, *REMOVE)}
    return tuple(('install', name) for name in INSTALL if not versions[name]) + tuple(
        ('remove', name) for name in REMOVE if versions[name])


def _armed(tx):
    apply_files.require_owner(tx.ctx)
    if not tx.changed or not callable(tx.rollback):
        raise ValueError('dependency mutation requires armed rescue')


def _run(ctx, argv, timeout):
    return nfqws_process.run(argv, ctx.environ, timeout=timeout, output_limit=1024 * 1024, cwd='/')


def update_feeds(tx):
    """Bounded update. One failed feed may use existing lists, as in legacy."""
    _armed(tx)
    done = _run(tx.ctx, ['opkg', 'update'], PACKAGE_TIMEOUT)
    if not (done.returncode or done.timed_out or done.output_limited):
        return
    if done.output_limited:
        raise RuntimeError('opkg update output exceeded budget')
    folder = snapshot_store._no_links(config.list_path('/opt/var/opkg-lists', tx.ctx.paths.test_root))
    usable = False
    if folder.is_dir():
        # Bound entry count before accepting a fallback; never read arbitrary lists.
        import os
        with os.scandir(folder) as entries:
            for count, item in enumerate(entries, 1):
                if count > 1024:
                    raise ValueError('opkg list inventory exceeds budget')
                if item.is_file(follow_symlinks=False) and item.stat(follow_symlinks=False).st_size > 0:
                    usable = True
    if done.output.count('Failed to download') <= 1 and usable:
        tx.ctx.console.err('WARNING: opkg update failed; using existing package lists.')
        return
    raise RuntimeError('opkg update failed')


def install_packages(tx, actions):
    """Fixed package allowlist, validated as a whole before the first command.

    Feed publication is caller-owned and must precede this operation. Each
    command is checked by querying actual installed state; package postinst may
    start nfqws, so stop is attempted even if its install exits unsuccessfully.
    """
    _armed(tx)
    actions = tuple(actions)
    allowed = {('install', name) for name in INSTALL} | {('remove', name) for name in REMOVE}
    if len(actions) > len(allowed) or any(not isinstance(row, tuple) or row not in allowed for row in actions):
        raise ValueError('unowned package action')
    if len(set(actions)) != len(actions):
        raise ValueError('duplicate package action')
    if any(verb == 'install' for verb, _name in actions):
        feed = snapshot_store._read(config.list_path(FEED_PATH, tx.ctx.paths.test_root), 4096)
        if feed != FEED:
            raise ValueError('owned nfqws feed was not published')
        update_feeds(tx)
    # Dependencies are installed before removing the old wget provider.
    actions = sorted(actions, key=lambda row: row[0] == 'remove')
    for verb, name in actions:
        if name == 'nfqws2-keenetic':
            try:
                done = _run(tx.ctx, ['opkg', verb, name], PACKAGE_TIMEOUT)
            finally:
                nfqws_service.action(tx.ctx, 'stop')
        else:
            done = _run(tx.ctx, ['opkg', verb, name], PACKAGE_TIMEOUT)
        if done.returncode or done.timed_out or done.output_limited:
            raise RuntimeError('opkg ' + verb + ' failed for owned package')
        installed = rollback_ops.package_version(tx.ctx, name)
        if bool(installed) != (verb == 'install'):
            raise RuntimeError('package state did not match requested action')


def prepare_relay(ctx, route):
    if route not in ('direct', 'vless', 'ws', 'unmanaged'):
        raise ValueError('invalid relay route')
    relay_restore.preflight(ctx, (route,))
    return relay_restore.capture(ctx)


def activate_relay(tx, route):
    _armed(tx)
    if route not in ('direct', 'vless', 'ws', 'unmanaged'):
        raise ValueError('invalid relay route')
    relay_restore.reconcile(tx.ctx, route)
