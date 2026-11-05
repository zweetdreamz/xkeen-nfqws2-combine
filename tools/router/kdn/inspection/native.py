"""Compare native compiled settings to live handlers without exposing credentials."""
import base64
import json
import re

from kdn.inspection import transport


def require_version(binary):
    raw = transport.run([binary, 'version'], timeout=5, limit=8192)
    match = re.match(rb'Xray (\d+)\.(\d+)\.(\d+)\b', raw)
    version = tuple(map(int, match.groups())) if match else ()
    if not version or version[0] != 26 or version < (26, 10, 31):
        raise ValueError('inspection requires Xray26.10.31+ generation26')


def _json(raw):
    # convert pb emits a fixed loader notice before JSON, even with stdin input.
    marker = re.search(rb'(?m)^[ \t]*\{', raw)
    if marker is None:
        raise ValueError('Xray converter unavailable')
    try:
        value = json.loads(raw[marker.start():])
    except (ValueError, RecursionError) as error:
        raise ValueError('Xray converter returned invalid JSON') from error
    if not isinstance(value, dict):
        raise ValueError('invalid native message')
    return value


def compile_config(binary, document):
    return _json(transport.run([binary, 'convert', 'pb', '-debug', '-type', 'stdin:'],
                              data=json.dumps(document, allow_nan=False).encode(), timeout=8))


def decode(binary, typename, raw):
    payload = json.dumps({'type': typename, 'value': base64.b64encode(raw).decode('ascii')}).encode()
    return _json(transport.run([binary, 'convert', 'json', '-type', 'stdin:'], data=payload, timeout=8))


def prove(binary, document, outbound_raw, inbound_raw, *, inbound=True):
    expected = compile_config(binary, document)
    for plural, singular, raw, setting in (
            ('outbounds', 'outbound', outbound_raw, 'senderSettings'),
            ('inbounds', 'inbound', inbound_raw, 'receiverSettings')):
        if plural == 'inbounds' and not inbound:
            continue
        live = decode(binary, 'xray.app.proxyman.command.List' + plural.title() + 'Response', raw)
        live_rows = live.get(plural, [])
        if not isinstance(live_rows, list):
            raise ValueError('live handler proof unavailable')
        for row in expected.get(singular, []):
            found = [item for item in live_rows if item.get('tag') == row.get('tag')]
            if len(found) != 1 or any(found[0].get(key) != row.get(key)
                                      for key in ('tag', setting, 'proxySettings')):
                raise ValueError('live handler differs from selected configuration; restart/sync manually')
