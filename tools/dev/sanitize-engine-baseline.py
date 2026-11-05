#!/usr/bin/env python3
"""Generate a non-deployable, anonymised restore corpus from a private capture.

Never extracts tar paths. Only regular files/directories, bounded input, explicit
source/destination, new destination required. Credentials are replaced before
any output file is written; checksum metadata is regenerated for transformed
bytes. Raw captures must remain outside versioned fixtures.
"""
import hashlib
import gzip
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'router'))
from kdn.common import jsonc  # noqa: E402


PRIVATE_KEYS = frozenset(('id', 'uuid', 'password', 'pass', 'user', 'username',
                          'login', 'secret', 'token', 'apikey', 'api_key',
                          'privatekey', 'publickey', 'shortid', 'shortids',
                          'email', 'fingerprint', 'name_profile', 'key', 'rci_token',
                          'access_token', 'authorization', 'credentials', 'private_key',
                          'public_key', 'short_id', 'short_ids', 'api-key'))
ENDPOINT_KEYS = frozenset(('address', 'server', 'servername', 'sni', 'host'))
UUID = re.compile(r'(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b')
IP = re.compile(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])')


def scrub(value, secrets, key=''):
    normal = re.sub('[^a-z0-9]', '', key.lower())
    if key.lower() in PRIVATE_KEYS or normal.endswith(('token', 'password', 'secret', 'apikey', 'privatekey')):
        if isinstance(value, str) and len(value) >= 8:
            secrets.add(value)
        if isinstance(value, list):
            return [scrub(item, secrets, key) for item in value]
        if isinstance(value, dict):
            return {name: scrub(item, secrets, 'password') for name, item in value.items()}
        if value is None:
            return None
        if isinstance(value, bool):
            return False
        if isinstance(value, (int, float)):
            return 0
        if key.lower() in ('id', 'uuid'):
            return '00000000-0000-4000-8000-000000000001'
        return 'fixture-only'
    if isinstance(value, dict):
        return {name: scrub(item, secrets, name) for name, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, secrets, key) for item in value]
    if isinstance(value, str) and key.lower() in ENDPOINT_KEYS:
        if value in ('127.0.0.1', '::1', '0.0.0.0', '::'):
            return value
        if len(value) >= 8:
            secrets.add(value)
        return 'router-fixture.invalid'
    return value


def generate(source, destination):
    if destination.exists():
        raise ValueError('destination must not exist')
    files, directories, secrets, modes = {}, [], set(), {}
    total = 0
    with tarfile.open(source) as archive:
        for item in archive.getmembers():
            logical = PurePosixPath(item.name)
            if logical.is_absolute() or '..' in logical.parts or not (item.isdir() or item.isfile()):
                raise ValueError('unsafe archive entry')
            name = str(logical)
            if name == '.':
                continue
            if name in modes:
                raise ValueError('duplicate archive entry')
            modes[name] = item.mode & 0o777
            if item.isdir():
                directories.append(name)
                continue
            total += item.size
            if total > 16 * 1024 * 1024 or item.size > 4 * 1024 * 1024:
                raise ValueError('capture too large')
            data = archive.extractfile(item).read(item.size + 1)
            if len(data) != item.size:
                raise ValueError('short capture')
            if name.endswith('.json'):
                value = json.loads(jsonc.strip_json_comments(data.decode('utf-8')))
                data = (json.dumps(scrub(value, secrets), ensure_ascii=True, indent=2) + '\n').encode()
            elif name == 'READONLY_AUDIT.txt':
                data = b'Anonymised baseline corpus; original audit intentionally omitted. Not deployable.\n'
            files[name] = data
    # Redact cross-file appearances of all endpoint/credential values identified
    # structurally, UUIDs, and IP literals except unspecified/loopback addresses.
    for name, data in files.items():
        compressed = data.startswith(b'\x1f\x8b')
        text = (gzip.decompress(data) if compressed else data).decode('utf-8')
        for secret in sorted(secrets, key=len, reverse=True):
            text = text.replace(secret, 'fixture-only')
        text = UUID.sub('00000000-0000-4000-8000-000000000001', text)
        text = IP.sub(lambda match: match[0] if match[0] in ('127.0.0.1', '0.0.0.0', '255.255.255.255')
                      else '192.0.2.1', text)
        text = re.sub(r'(?im)^(\s*(?:secret|password|token|api[-_]key)\s*:\s*).+$',
                      r'\1fixture-only', text)
        encoded = text.encode('utf-8')
        files[name] = gzip.compress(encoded, mtime=0) if compressed else encoded
    files['CHECKSUMS.sha256'] = b''.join(
        (hashlib.sha256(data).hexdigest() + '  ./' + name[len('files/'):] + '\n').encode()
        for name, data in sorted(files.items()) if name.startswith('files/'))
    if any(secret.encode() in (gzip.decompress(data) if data.startswith(b'\x1f\x8b') else data)
           for secret in secrets for data in files.values()):
        raise ValueError('credential residue')
    destination.mkdir(parents=True)
    for name in directories:
        (destination / name).mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(modes.get(name, 0o600))
    print('Sanitised regular files:', len(files), '; credentials/endpoints scrubbed:', len(secrets))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: sanitize-engine-baseline.py PRIVATE_TAR NEW_DESTINATION')
    generate(Path(sys.argv[1]), Path(sys.argv[2]))
