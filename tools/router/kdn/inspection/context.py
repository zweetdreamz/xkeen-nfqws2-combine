"""Read-only binding to the active registry source and actual Xray process."""
import hashlib
import json
import os
from pathlib import Path
import sys
import socket

from kdn.common import fsutil
from kdn.engine import apply_files, config, snapshot_store, system, xkeen_service
from kdn.inspection import layout, native, receipt, rpc, transport


def digest(outbound):
    return hashlib.sha256(json.dumps(outbound, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def manager_for(ctx):
    # Sibling executable already used by the panel; no imports from web/domain.
    import vpn_node_manager
    return vpn_node_manager.VpnNodeManager(
        xray_dir=Path(ctx.paths.xray_config_dir),
        state_file=Path(config.list_path('/opt/etc/xkeen-web/vpn-nodes.json', ctx.paths.test_root)),
        lock_dir=Path(ctx.paths.lock_dir), xray=str(system.find_xray(ctx.paths, ctx.environ) or ctx.paths.xray_default_bin),
        nfqws_conf=Path(ctx.paths.nfqws_conf), xkeen_init=ctx.paths.xkeen_init)


def active_identity(manager):
    if manager.transaction_file.exists() or manager.transaction_file.is_symlink():
        raise ValueError('VPN recovery is required; inspection is paused')
    state = manager.load()
    node = state['nodes'][state['active']]
    module = sys.modules[manager.__class__.__module__]
    expected = module.normalize_outbound(node['outbound'])
    _document, current = manager._current_file()
    if module.normalize_outbound(current) != expected:
        raise ValueError('VPN source drift; sync or restore manually')
    return {'node_id': state['active'], 'source_digest': digest(expected)}, expected


def _listener_present(pid, port, proc_root=Path('/proc')):
    """Read-only conflict probe; never bind a port while Xray is opening it."""
    for table, addresses in (('tcp', {'0100007F', '00000000'}),
                             ('tcp6', {'0' * 32, '0000000000000000FFFF00000100007F'})):
        path = proc_root / str(pid) / 'net' / table
        try:
            stream = path.open('r', encoding='ascii')
        except FileNotFoundError:
            if table == 'tcp6':
                continue
            raise
        with stream:
            for count, line in enumerate(stream):
                if count > 8192:
                    raise ValueError('socket inspection limit')
                fields = line.split()
                if len(fields) >= 10 and fields[3] == '0A':
                    address, _, number = fields[1].rpartition(':')
                    if number == f'{port:04X}' and address in addresses:
                        return True
    return False


def _listener_owned(pid, port, proc_root=Path('/proc')):
    inodes = set()
    with (proc_root / str(pid) / 'net/tcp').open('r', encoding='ascii') as stream:
        for count, line in enumerate(stream):
            if count > 8192:
                raise ValueError('socket inspection limit')
            fields = line.split()
            if len(fields) >= 10 and fields[1] == f'0100007F:{port:04X}' and fields[3] == '0A':
                inodes.add(fields[9])
    if len(inodes) != 1:
        return False
    with os.scandir(proc_root / str(pid) / 'fd') as entries:
        for count, entry in enumerate(entries):
            if count > 4096:
                raise ValueError('socket descriptor limit')
            try:
                if os.readlink(entry.path) == 'socket:[' + next(iter(inodes)) + ']':
                    return True
            except FileNotFoundError:
                continue
    return False


class Live:
    def __init__(self, ctx, *, manager=None):
        self.ctx = ctx
        self.manager = manager or manager_for(ctx)
        self.identity, self.outbound = active_identity(self.manager)
        self.corpus = apply_files._corpus(ctx)
        self.documents = {name: apply_files._decode(raw) for name, raw, _mode in self.corpus}
        for document in self.documents.values():
            if any(key.casefold() == 'routing' and key != 'routing' for key in document):
                raise ValueError('ambiguous routing spelling')
            routing = document.get('routing', {})
            if (any(key.casefold() == 'script' and value for key, value in routing.items())
                    or any(any(key.casefold() == 'webhook' and value for key, value in row.items())
                           for row in routing.get('rules', []))):
                raise ValueError('routing scripts/webhooks cannot be inspected without side effects')
        self.binary = str(system.find_xray(ctx.paths, ctx.environ) or '')
        self.pid = xkeen_service.pid(ctx)
        if not self.binary or self.pid is None:
            raise ValueError('configured Xray daemon is not running')
        native.require_version(self.binary)
        path = Path(config.list_path('/opt/etc/xkeen-web/inspection-runtime.json', ctx.paths.test_root))
        if not receipt.matches(path, ctx.paths.xray_config_dir, self.pid):
            raise ValueError('diagnostic access needs explicit re-arm after an external restart/edit')
        self.runtime_identity = {key: value for key, value in receipt.value(ctx.paths.xray_config_dir, self.pid).items()
                                 if key != 'version'}
        self.start = receipt.process_start(self.pid)
        binary_info, running_info = os.stat(self.binary), os.stat(f'/proc/{self.pid}/exe')
        if (binary_info.st_dev, binary_info.st_ino) != (running_info.st_dev, running_info.st_ino):
            raise ValueError('Xray executable changed; restart manually before inspection')
        self.client = rpc.Client(layout.api_port(self.documents))
        if not _listener_owned(self.pid, self.client.port):
            raise ValueError('diagnostic API listener does not belong to configured Xray')
        self.rule_fingerprint = hashlib.sha256(self.client.call('ListRule')).digest()

    def stable(self):
        identity, _outbound = active_identity(self.manager)
        if (identity != self.identity or apply_files._corpus(self.ctx) != self.corpus
                or xkeen_service.pid(self.ctx) != self.pid or receipt.process_start(self.pid) != self.start
                or hashlib.sha256(self.client.call('ListRule')).digest() != self.rule_fingerprint):
            raise ValueError('inspection became stale: node/config/process changed')

    def prove_paths(self, paths):
        fragment = self.documents.get(layout.FILE, {})
        direct_rows = fragment.get('outbounds', [])
        if not isinstance(direct_rows, list) or len(direct_rows) != 1:
            raise ValueError('diagnostic layout is not owned')
        mark = direct_rows[0].get('streamSettings', {}).get('sockopt', {}).get('mark')
        if {k: v for k, v in fragment.items() if k != 'api'} != layout.fragment(mark):
            raise ValueError('diagnostic layout differs from the plain owned paths')
        expected = {'outbounds': [self.outbound], 'inbounds': []}
        for mode in paths:
            tag, port = (layout.VPN_IN, layout.VPN_PORT) if mode == 'vpn' else (layout.DIRECT_IN, layout.DIRECT_PORT)
            rows = [row for row in fragment.get('inbounds', []) if row.get('tag') == tag]
            if len(rows) != 1 or rows[0] not in layout.fragment()['inbounds'] or not _listener_owned(self.pid, port):
                raise ValueError('diagnostic SOCKS listener is not prepared or not owned by Xray')
            expected['inbounds'] += rows
            if mode == 'direct':
                direct = [row for row in fragment.get('outbounds', []) if row.get('tag') == layout.DIRECT_TAG]
                if len(direct) != 1 or direct[0].get('protocol') != 'freedom' or direct[0].get('settings') != {}:
                    raise ValueError('diagnostic Direct outbound is not plain Freedom')
                expected['outbounds'] += direct
        native.prove(self.binary, expected, self.client.call('ListOutbounds'), self.client.call('ListInbounds'))
        self.stable()

    def route_path(self, mode, target_ip, source_port, port=443):
        inbound, expected = (layout.VPN_IN, layout.VPN_TAG) if mode == 'vpn' else (layout.DIRECT_IN, layout.DIRECT_TAG)
        local_port = layout.VPN_PORT if mode == 'vpn' else layout.DIRECT_PORT
        result = self.client.route(inbound=inbound, network='tcp', port=port, ip=target_ip,
                                   source='127.0.0.1', source_port=source_port,
                                   local_ip='127.0.0.1', local_port=local_port)
        if result != expected:
            raise ValueError('live diagnostic route does not select the required outbound')


def source_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def resolve(domain):
    program = ('import json,socket,sys; '
               'print(json.dumps(list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(sys.argv[1],None)))[:8]))')
    raw = transport.run([sys.executable, '-P', '-c', program, domain], timeout=4, limit=4096)
    value = json.loads(raw)
    if not isinstance(value, list) or not value or len(value) > 8:
        raise ValueError('router DNS did not provide a bounded address set')
    return value


def pending_recovery(ctx):
    if snapshot_store.focused_pending(ctx.paths):
        return True
    for logical in ('/opt/etc/xkeen-web/vpn-switch-transaction.json',
                    '/opt/etc/xkeen-web/automation-state.json'):
        path = Path(config.list_path(logical, ctx.paths.test_root))
        if logical.endswith('transaction.json') and os.path.lexists(path):
            return True
        if logical.endswith('state.json') and path.exists():
            state = fsutil.safe_json_file(path)
            if (state.get('status') == 'recovery-failed'
                    or state.get('phase') in ('applying', 'recovering', 'recovery-failed', 'recovery-needed', 'testing')):
                return True
    return False
