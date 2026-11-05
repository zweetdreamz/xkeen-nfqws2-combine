"""Offline phase6 matrix against a pinned real Xray; no daemon or sockets started.

Run in Docker with read-only binary/DAT mounts:
python3 tools/dev/check_xray_apply.py XRAY DAT_DIR
The DAT corpus is caller-provided; never fetched or modified by this check.
"""
import hashlib
from itertools import product
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import os

from kdn.engine import xray_patch


BINARY_SHA256 = 'cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1'
ARCHIVE_SHA256 = 'e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214'
RELEASE = 'https://github.com/XTLS/Xray-core/releases/tag/v26.10.31'


def check(binary, dat_dir):
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != BINARY_SHA256:
        raise ValueError('unapproved Xray runtime hash')
    provenance = {}
    for name in ('zkeen.dat', 'geosite_v2fly.dat', 'geoip_v2fly.dat'):
        path = Path(dat_dir) / name
        provenance[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    count = 0
    with tempfile.TemporaryDirectory(prefix='kdn-xray-matrix-') as folder:
        for mode in ('hybrid', 'tproxy'):
            inbounds = [{'tag': 'custom-tproxy', 'listen': '127.0.0.1', 'port': 61220, 'protocol': 'dokodemo-door',
                'settings': {'followRedirect': True, 'allowedNetwork': 'tcp,udp' if mode == 'tproxy' else 'udp'},
                'streamSettings': {'sockopt': {'tproxy': 'tproxy'}}}]
            if mode == 'hybrid':
                inbounds.append({'tag': 'custom-redirect', 'listen': '127.0.0.1', 'port': 61219,
                    'protocol': 'dokodemo-door', 'settings': {'followRedirect': True, 'allowedNetwork': 'tcp'}})
            inputs = xray_patch.patch_inbounds({'inbounds': inbounds})
            (Path(folder) / '03_inbounds.json').write_text(json.dumps(inputs))
            (Path(folder) / '04_outbounds.json').write_text(json.dumps({'outbounds': [{
                'tag': 'vpn', 'protocol': 'vless', 'settings': {'vnext': [{
                    'address': '192.0.2.1', 'port': 443, 'users': [{'id': '00000000-0000-4000-8000-000000000001',
                    'encryption': 'none'}]}]}, 'streamSettings': {'security': 'tls',
                    'tlsSettings': {'serverName': 'vpn.example.invalid'}}}]}))
            tags = [row['tag'] for row in inputs['inbounds']]
            for tcp, voice, youtube, telegram in product(*([('direct', 'zapret', 'vless')] * 3),
                                                        ('direct', 'vless', 'ws', 'unmanaged')):
                routes = dict(discord_tcp=tcp, discord_voice=voice, youtube=youtube, telegram=telegram)
                document = xray_patch.patch_routing({'routing': {'rules': []}}, inbound_tags=tags,
                                                    routes=routes, proxy_outbound='vpn')
                (Path(folder) / '05_routing.json').write_text(json.dumps(document))
                direct = [xray_patch.direct_outbound(tag, 255)['outbounds'][0]
                          for tag in ('discord-direct', 'youtube-direct', 'telegram-direct')]
                if telegram == 'ws':
                    relay = xray_patch.direct_outbound('telegram-ws', 255)['outbounds'][0]
                    relay['settings'] = {'redirect': '127.0.0.1:18443'}
                    direct.append(relay)
                (Path(folder) / '04_managed.json').write_text(json.dumps({'outbounds': direct}))
                done = subprocess.run([binary, 'run', '-test', '-confdir', folder, '-format', 'json'],
                    env=dict(os.environ, XRAY_LOCATION_ASSET=str(dat_dir)), capture_output=True, timeout=15)
                if done.returncode:
                    # Only synthetic non-secret inputs exist in this checker.
                    raise RuntimeError(f'matrix failed: {mode} {routes}: {done.stderr.decode(errors="replace")[-4096:]}')
                count += 1
            print('validated', mode, count, flush=True)
    return {'release': RELEASE, 'binary_sha256': BINARY_SHA256, 'archive_sha256': ARCHIVE_SHA256,
            'dat_sha256': provenance, 'configurations_passed': count, 'network': 'none', 'operation': 'run -test only'}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: check_xray_apply.py XRAY DAT_DIR')
    print(json.dumps(check(sys.argv[1], sys.argv[2]), sort_keys=True))
