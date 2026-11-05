"""Explicit setup transaction for diagnostic listeners; no VPN/node/nfqws changes."""
from pathlib import Path
import socket
import time

from kdn.common import fsutil
from kdn.engine import apply_files, config, nfqws_marks, preflight_xray, rollback_ops
from kdn.engine import snapshot_store, system, transaction, xkeen_service
from kdn.inspection import context, layout, native, receipt, rpc


def prepare(ctx):
    rpc.require_http2()
    binary = system.find_xray(ctx.paths, ctx.environ)
    if binary is None:
        raise ValueError('Xray binary is missing')
    native.require_version(str(binary))
    xkeen_service.preflight(ctx)
    request = preflight_xray.XrayRequest({}, ctx.resolved.direct_mark_requested, '', '', ctx.paths.test_root)
    mark = preflight_xray.resolve_direct_mark(ctx.paths, request, ctx.environ)
    nfqws_marks.validate(ctx.paths, mark or '0', ctx.environ)
    corpus = apply_files._corpus(ctx)
    documents = {name: apply_files._decode(data) for name, data, _mode in corpus}
    updates = layout.prepare(documents, int(mark) if mark else None)
    if apply_files._outbound_default(documents) != apply_files._outbound_default(documents | updates):
        raise ValueError('inspection setup would alter the effective default outbound')
    before = {name: (raw, mode) for name, raw, mode in corpus}
    changes = tuple(apply_files.Change('/opt/etc/xray/configs/' + name, *before.get(name, (None, 0o600)),
                                      apply_files._encode(doc)) for name, doc in sorted(updates.items()))
    plan = apply_files.Plan(changes, corpus)
    live = xkeen_service.pid(ctx)
    for port in (layout.api_port(documents | updates), layout.VPN_PORT, layout.DIRECT_PORT):
        if live is not None and context._listener_owned(live, port):
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            try:
                candidate.bind(('127.0.0.1', port))
            except OSError as error:
                raise ValueError('diagnostic listener port is occupied outside configured Xray') from error
    xkeen_service.preflight(ctx, plan=plan)
    apply_files.validate_staged(ctx, plan)
    return plan


def verify_access(ctx):
    live = context.Live(ctx)
    live.prove_paths(['direct', 'vpn'])


def wait_for_listeners(ctx, pid, expected_digest, *, timeout=15):
    """PID is not readiness: wait only for absent ports, never foreign owners/drift."""
    directory = ctx.paths.xray_config_dir
    expected = receipt.value(directory, pid)
    if expected['corpus_digest'] != expected_digest:
        raise ValueError('Xray files changed before listener readiness')
    documents = {name: apply_files._decode(raw) for name, raw, _mode in apply_files._corpus(ctx)}
    ports = (layout.api_port(documents), layout.VPN_PORT, layout.DIRECT_PORT)
    deadline = time.monotonic() + timeout

    def stable():
        if xkeen_service.pid(ctx) != pid or receipt.value(directory, pid) != expected:
            raise ValueError('Xray process/config changed during listener readiness')

    while True:
        stable()
        ready = True
        for port in ports:
            if context._listener_owned(pid, port):
                continue
            if context._listener_present(pid, port):
                # A listener can appear between the first ownership check and
                # the presence read. Recheck ownership, not mere TCP-connect.
                if context._listener_owned(pid, port):
                    continue
                raise ValueError('diagnostic listener is occupied outside configured Xray')
            ready = False
        stable()
        if ready:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('Xray diagnostic listeners did not become ready within deadline')
        time.sleep(min(.2, remaining))


def operation(tx):
    ctx = tx.ctx
    plan = prepare(ctx)
    path = Path(config.list_path('/opt/etc/xkeen-web/inspection-runtime.json', ctx.paths.test_root))
    live_pid = xkeen_service.pid(ctx)
    if not plan.changes and live_pid is not None and receipt.matches(path, ctx.paths.xray_config_dir, live_pid):
        ctx.console.out('Diagnostic access is already prepared; no restart.')
        return
    was_running = live_pid is not None
    if not was_running:
        raise ValueError('start Xray manually before preparing diagnostic access')
    tx.stage('snapshot')
    rescue = rollback_ops.capture(ctx, 'pre-inspection-setup', 'integrated')
    pointer = snapshot_store._no_links(Path(ctx.paths.latest_pointer))
    old_pointer = snapshot_store._read(pointer, 4096) if pointer.exists() else None

    def undo():
        apply_files.restore_files(ctx, plan, rescue)
        xkeen_service.action(ctx, 'restart')
        if old_pointer is None:
            pointer.unlink(missing_ok=True)
        else:
            fsutil.atomic_bytes(pointer, old_pointer)

    tx.arm(undo)
    snapshot_store.publish_pointer(ctx.paths, pointer, rescue, allow_live=True)
    apply_files.publish(tx, plan, rescue)
    tx.stage('verify')
    prepared_digest = receipt.corpus_digest(ctx.paths.xray_config_dir)
    pid = xkeen_service.action(ctx, 'restart')
    receipt.record(path, ctx.paths.xray_config_dir, pid, expected_digest=prepared_digest)
    wait_for_listeners(ctx, pid, prepared_digest)
    verify_access(ctx)
    # Runtime read-only API capability is checked by the checker, not repaired
    # from a query or monitor. The full rescue stays available after SIGKILL.
    tx.changed = False
    ctx.console.out('Loopback route/resource diagnostic access prepared; VPN selection unchanged.')


def run(ctx):
    return transaction.execute(ctx, operation)
