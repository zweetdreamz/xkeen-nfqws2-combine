"""One actual-version policy for operational XKeen2.1+ (generation2.x).

No opkg/init-option inference, config reads, filesystem writes or test-root
bypass. The parser is pure; subprocess imports are lazy for offline callers.
"""
import re


SUPPORTED = re.compile(r'2\.[1-9][0-9]*(?:\.(?:0|[1-9][0-9]*))?(?:β|-beta(?:\.[0-9]+)?)?')
MESSAGE = 'XKeen 2.1+ (2.x) is required; 2.0, unknown and unsupported major versions are not supported.'
ERROR_CODE = 'unsupported_xkeen'


class UnsupportedXKeen(ValueError):
    def __init__(self):
        super().__init__(MESSAGE)


def supported(version):
    return isinstance(version, str) and SUPPORTED.fullmatch(version) is not None


def parse_version(text):
    if not isinstance(text, str):
        return ''
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    matches = re.finditer(r'(?i)(?:XKeen\s*[:=\-]?\s*v?)'
                          r'([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:β|-beta(?:\.[0-9]+)?)?)(?![\w.])'
                          r'([ \t]+Beta\b)?', text)
    tokens = []
    for match in matches:
        token = match[1]
        if match[2] and 'β' not in token and '-beta' not in token.lower():
            token += '-beta'
        tokens.append(token)
    return tokens[0] if len(set(tokens)) == 1 and supported(tokens[0]) else ''


def probe(command='xkeen', environ=None, *, timeout=10):
    """Bounded read-only version command; an incomplete/oversized reply is invalid."""
    import os
    import selectors
    import subprocess
    import time

    if not 0 < timeout <= 30:
        raise ValueError('invalid version timeout')
    try:
        process = subprocess.Popen([str(command), '-v'], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=None if environ is None else dict(environ))
    except OSError:
        return ''
    raw = bytearray()
    deadline = time.monotonic() + timeout
    valid = True
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    valid = False
                    break
                if selector.select(min(0.1, remaining)):
                    data = os.read(process.stdout.fileno(), min(4096, 4097 - len(raw)))
                    if not data:
                        break
                    raw.extend(data)
                    if len(raw) > 4096:
                        valid = False
                        break
        if valid:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                valid = False
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        process.stdout.close()
    return parse_version(raw.decode('utf-8', 'replace')) if valid and process.returncode == 0 else ''


def require(command='xkeen', environ=None):
    version = probe(command, environ)
    if not version:
        raise UnsupportedXKeen()
    return version


def error_status():
    # Schema1 keeps the panel adapter on the JSON path, never a legacy fallback.
    return {'schema': 1, 'ok': False, 'supported': False, 'error_code': ERROR_CODE, 'error': MESSAGE,
            'required': 'XKeen 2.1+ (2.x)', 'text': 'ERROR: ' + MESSAGE + '\n',
            'fields': {}, 'snapshots': None, 'xkeen_output': None, 'warnings': []}


def _cli_main(argv):
    if argv not in ([], ['--require']):
        return 2
    try:
        print(require())
        return 0
    except UnsupportedXKeen:
        print('ERROR: ' + MESSAGE)
        return 2


if __name__ == '__main__':
    import sys
    raise SystemExit(_cli_main(sys.argv[1:]))
