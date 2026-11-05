"""Native integrated apply: one project lock, durable rescue, commit after verification."""
from pathlib import Path

from kdn.common import fsutil
from kdn.engine import apply_dependencies, apply_files, apply_nfqws, config, findings
from kdn.engine import nfqws_service, nfqws_validate, preflight_wan, preflight_xray, relay_restore
from kdn.engine import rollback_ops, snapshot_policy, snapshot_store, system, transaction, xkeen_service


def _routes(ctx):
    request = ctx.resolved
    return dict(discord_tcp=request.discord_tcp_route, discord_voice=request.discord_voice_route,
                youtube=request.youtube_route, telegram=request.telegram_route)


def prepare(ctx, *, capture_relay=True):
    """Read-only preflight and prospective Xray validation; no effective writes."""
    version = xkeen_service.preflight(ctx)
    for name in ('opkg', 'ip', 'sh', 'jq'):  # jq belongs to the XKeen2.1 runtime, not our Xray patcher.
        if not system.have(name, ctx.environ):
            raise ValueError('required native apply command missing: ' + name)
    routes = _routes(ctx)
    request = preflight_xray.XrayRequest({}, ctx.resolved.direct_mark_requested,
        ctx.resolved.proxy_outbound_requested, ctx.resolved.telegram_route, ctx.paths.test_root)
    try:
        mark = preflight_xray.resolve_direct_mark(ctx.paths, request, ctx.environ)
    except preflight_xray.XrayCheckError as error:
        raise ValueError(str(error).removeprefix('ERROR: ').rstrip()) from error
    if mark:
        significant = mark.lstrip('0') or '0'
        if len(significant) > 10 or not 1 <= int(significant) <= 2147483647:
            raise ValueError('Xray direct mark must fit a positive int32')
    proxy = ''
    if 'vless' in routes.values() or request.proxy_outbound_requested:
        proxy = preflight_xray.resolve_proxy_outbound(ctx.paths, request)
    else:
        # Preserve an unambiguous existing VPN tag without requiring VPN installation.
        try:
            proxy = preflight_xray.resolve_proxy_outbound(ctx.paths, request)
        except preflight_xray.XrayCheckError:
            pass
    preflight_xray.telegram_dat_present(ctx.paths, request)
    if capture_relay:
        relay = apply_dependencies.prepare_relay(ctx, routes['telegram'])
    else:
        relay_restore.preflight(ctx, (routes['telegram'],))
        relay = None
    state = findings.State(detected_core='xray', direct_mark=mark)
    wan_request = preflight_wan.WanRequest(ctx.resolved.wan_interface_requested, False, mark, 'xray',
                                          ctx.resolved.xkeen_required_ports, ctx.paths.test_root)
    preflight_wan.check(ctx.paths, ctx.environ, wan_request, state)
    for item in state.findings:
        ctx.console.err(item.text, end='')
    if state.errors:
        raise ValueError('native apply WAN/policy/port preflight failed')
    plan = apply_files.prepare_xray(ctx, routes=routes, proxy_outbound=proxy,
        mark=int(mark) if mark else None, voice_high=int(ctx.resolved.voice_high),
        relay_port=int(config.telegram_ws_port(ctx.paths, ctx.environ)))
    plan, warnings = apply_dependencies.prepare_files(ctx, plan, voice_high=int(ctx.resolved.voice_high),
                                                       telegram=routes['telegram'])
    for warning in warnings:
        ctx.console.err('WARNING: ' + warning)
    xkeen_service.preflight(ctx, plan=plan)
    apply_files.validate_staged(ctx, plan)
    actions = apply_dependencies.package_plan(ctx)
    return plan, state, proxy, actions, relay, version


def _baseline(ctx, rescue, version):
    baseline = Path(ctx.paths.baseline_pointer)
    if not baseline.exists():
        snapshot_store.publish_pointer(ctx.paths, baseline, rescue, baseline=True, allow_live=True)
        ctx.console.out('Immutable baseline recorded: ' + str(rescue))
        return
    original = rollback_ops._pointer(ctx, baseline)
    selected = (rollback_ops._pointer(ctx, ctx.paths.xkeen_baseline_pointer)
                if Path(ctx.paths.xkeen_baseline_pointer).exists() else original)
    if (selected.metadata.scope != 'integrated' or not snapshot_policy.versions_compatible(
            selected.metadata.value('XKEEN_VERSION'), version)):
        snapshot_store.rollover_xkeen_baseline(ctx.paths, rescue, version, allow_live=True)


def operation(tx):
    ctx = tx.ctx
    plan, state, proxy, packages, relay, version = prepare(ctx)
    tx.stage('snapshot')
    rescue = rollback_ops.capture(ctx, 'pre-apply', 'integrated')
    _baseline(ctx, rescue, version)
    latest = snapshot_store._no_links(ctx.paths.latest_pointer)
    previous_latest = snapshot_store._read(latest, 4096) if latest.exists() else None
    imported_pointer = snapshot_store._no_links(Path(ctx.paths.state_root) / 'latest-nfqws-import.ptr')
    previous_import = snapshot_store._read(imported_pointer, 4096) if imported_pointer.exists() else None

    def undo():
        try:
            relay_restore.restore_init(ctx, relay)
            rollback_ops.restore(ctx, rescue, reconcile_relay=False)
            relay_restore.restore_saved(ctx, relay)
        finally:
            for pointer, old in ((latest, previous_latest), (imported_pointer, previous_import)):
                if old is None:
                    pointer.unlink(missing_ok=True)
                else:
                    fsutil.atomic_bytes(pointer, old)

    tx.arm(undo)
    # Publish the durable recovery cue before the first config/package mutation.
    snapshot_store.publish_pointer(ctx.paths, latest, rescue, allow_live=True)
    tx.stage('config')
    apply_files.publish(tx, plan, rescue)
    apply_dependencies.install_packages(tx, packages)
    tx.stage('nfqws')
    routes = tuple(_routes(ctx).values())
    prepared = apply_nfqws.prepare(ctx, routes=routes, wan=state.wan, ipv6=state.ipv6 == '1', proxy_outbound=proxy)
    apply_nfqws.publish(tx, prepared)
    tx.stage('verify')
    nfqws_validate.validate_config(ctx, ctx.paths.nfqws_conf)
    apply_dependencies.activate_relay(tx, routes[3])
    xkeen_service.action(ctx, 'restart')
    nfqws_service.restart(ctx)
    if xkeen_service.pid(ctx) is None:
        raise RuntimeError('Xray daemon disappeared after nfqws restart')
    # Commit: no later best-effort cleanup may trigger rollback of working state.
    imported_pointer.unlink(missing_ok=True)
    tx.changed = False
    rollback_ops._prune_after_success(ctx, rescue)
    ctx.console.out('Apply complete.')
    ctx.console.out('One-command baseline rollback:')
    ctx.console.out('  sh apply-discord-nfqws2.sh --rollback --yes-router')


def run(ctx):
    return transaction.execute(ctx, operation)


def preflight_run(ctx):
    """Same prospective apply checks, no lock/snapshot/packages/services/config writes."""
    try:
        transaction.guard(ctx, readonly=True)
        prepare(ctx, capture_relay=False)
        ctx.console.out('Preflight OK. Native XKeen2.1+/Xray; no configuration was changed.')
        return 0
    except (OSError, ValueError, RuntimeError, preflight_xray.XrayCheckError, RecursionError) as error:
        message = str(error) if isinstance(error, (ValueError, RuntimeError)) else 'check XKeen2.1/Xray, RCI, policy marks, WAN and prospective config'
        ctx.console.err('ERROR: native preflight failed: ' + message)
        return 1
