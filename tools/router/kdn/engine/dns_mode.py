"""Manual Home DNS profile assignment only; never edits/restarts Xray/nfqws2."""
import hashlib
import json
from pathlib import Path
import shlex

from kdn.common import fsutil, timeutil
from kdn.engine import confvalues, nfqws_process, transaction


INTERFACE = 'Home'
PROFILES = {'vless': 'DnsVlessMain', 'doh': 'DnsProfile0'}
VLESS_UPSTREAM = '192.168.2.1:15355'


def _native(ctx, command):
    result = nfqws_process.run(['/bin/ndmc', '-c', command], ctx.environ, timeout=20, output_limit=262144)
    if result.returncode or result.timed_out or result.output_limited:
        raise RuntimeError('Keenetic DNS command did not complete')
    if command != 'show running-config' and any(mark in result.output.casefold() for mark in ('error[', 'error:', 'ошибка:')):
        raise RuntimeError('Keenetic rejected DNS command')
    return result.output


def parse_dns(text):
    rows, inside, count = [], False, 0
    for line in text.splitlines():
        if line == 'dns-proxy':
            count += 1; inside = True
        elif inside and line.strip() == '!':
            inside = False
        elif inside:
            if not line[:1].isspace():
                raise ValueError('unrecognised DNS configuration layout')
            rows.append(line.strip())
    if count != 1:
        raise ValueError('one native DNS proxy configuration is required')
    tokens = [shlex.split(row) for row in rows]
    if ['filter','engine','public'] not in tokens:
        raise ValueError('native DNS profile engine is not public; no overwrite')
    assignments = [row[5] for row in tokens if row[:5] == ['filter','assign','interface','profile',INTERFACE] and len(row) == 6]
    if len(assignments) != 1 or assignments[0] not in PROFILES.values():
        raise ValueError('Home uses an unknown or ambiguous DNS profile; no overwrite')
    profiles = {name: [row[3:] for row in tokens if row[:3] == ['filter','profile',name]] for name in PROFILES.values()}
    vless = profiles[PROFILES['vless']]
    if (['dns53','upstream',VLESS_UPSTREAM] not in vless or ['intercept','enable'] not in vless
            or sum(row[:2] == ['dns53','upstream'] for row in vless) != 1
            or any(row[:1] in (['https'],['tls']) for row in vless)):
        raise ValueError('VLESS DNS profile differs from the supported topology')
    doh = profiles[PROFILES['doh']]
    urls = [row[2] for row in doh if row[:2] == ['https','upstream'] and len(row) >= 3]
    if (not urls or any(not value.startswith('https://') for value in urls)
            or ['intercept','enable'] not in doh or any(row[:1] in (['dns53'],['tls']) for row in doh)):
        raise ValueError('native DoH profile is missing or includes non-DoH upstreams')
    stable = sorted(row for row, parts in zip(rows, tokens, strict=True)
                    if parts[:5] != ['filter','assign','interface','profile',INTERFACE])
    fingerprint = hashlib.sha256(json.dumps(stable).encode()).hexdigest()
    return {'profile': assignments[0], 'mode': next(k for k,v in PROFILES.items() if v == assignments[0]),
            'fingerprint': fingerprint,
            'host_overrides': sum(row[:4] == ['filter','assign','host','profile'] for row in tokens)}


def _marker(ctx):
    return Path(ctx.paths.state_root) / 'dns-last-change.json'


def _record(ctx):
    path = _marker(ctx)
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('unsafe DNS recovery path')
    try:
        value = fsutil.safe_json_file(path, maximum=8192)
    except FileNotFoundError:
        return {}
    if (value.get('version') != 1 or value.get('before') not in PROFILES.values()
            or value.get('after') not in PROFILES.values() or value.get('phase') not in ('pending','completed','rolled-back')
            or not isinstance(value.get('fingerprint'), str)):
        raise ValueError('DNS recovery record is invalid; manual inspection required')
    return value


def dns_status(ctx):
    transaction.guard(ctx, readonly=True)
    try:
        if confvalues.init_value(ctx.paths,'proxy_router') != 'off':
            raise ValueError('proxy_router must be off to keep router DoH independent of Xray')
        observed = parse_dns(_native(ctx,'show running-config'))
        record = _record(ctx)
    except ValueError as error:
        return {'ok': True, 'supported': False, 'mode': 'unknown', 'interface': INTERFACE, 'detail': str(error),
                'pending': False, 'recovery_mode': None, 'host_overrides': 0}
    pending = record.get('phase') == 'pending'
    return {'ok': True, 'supported': True, 'mode': observed['mode'], 'interface': INTERFACE,
            'detail': '', 'pending': pending,
            'recovery_mode': next((k for k,v in PROFILES.items() if v == record.get('before')),None) if pending else None,
            'host_overrides': observed['host_overrides']}


def _store(ctx, record):
    path = _marker(ctx)
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('unsafe DNS recovery path')
    fsutil.atomic_json(path,record,maximum=8192,parent_mode=0o700)
    fsutil.fsync_path(path.parent)


def switch_dns(ctx, mode):
    if mode not in PROFILES:
        raise ValueError('DNS mode: vless or doh')
    def operation(tx):
        if confvalues.init_value(ctx.paths,'proxy_router') != 'off':
            raise ValueError('router DoH independence is not confirmed; proxy_router must be off')
        before = parse_dns(_native(ctx,'show running-config'))
        old = _record(ctx)
        pending = old.get('phase') == 'pending'
        if pending:
            if PROFILES[mode] != old['before'] or before['fingerprint'] != old['fingerprint']:
                raise ValueError('unfinished DNS operation: select the previous mode for explicit recovery')
            record = old
        else:
            if before['mode'] == mode:
                ctx.console.out('DNS mode unchanged; no commands applied.')
                return
            record = {'version':1, 'phase':'pending', 'before':before['profile'], 'after':PROFILES[mode],
                      'fingerprint':before['fingerprint'], 'created_utc':timeutil.utc_now()}
            _store(ctx,record)
        def assign(profile):
            _native(ctx,'dns-proxy filter assign interface profile '+INTERFACE+' '+profile)
            after = parse_dns(_native(ctx,'show running-config'))
            if after['profile'] != profile or after['fingerprint'] != record['fingerprint']:
                raise RuntimeError('DNS assignment or other DNS settings changed unexpectedly')
            _native(ctx,'system configuration save')
            verified = parse_dns(_native(ctx,'show running-config'))
            if verified != after:
                raise RuntimeError('DNS configuration changed during persistence')
        def undo():
            assign(record['before'])
            _store(ctx,dict(record,phase='rolled-back'))
        tx.arm(undo)
        tx.stage('dns')
        assign(PROFILES[mode])
        _store(ctx,dict(record,phase='rolled-back' if pending else 'completed'))
        tx.changed = False
        ctx.console.out('Home DNS mode: '+mode+'. Xray/nfqws2 were not restarted.')
    return transaction.execute(ctx, operation)
