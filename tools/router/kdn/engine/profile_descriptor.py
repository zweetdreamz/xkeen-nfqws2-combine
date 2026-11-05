"""Pure persisted FORMAT1 descriptor validation; no file/service/CLI operations.

Canonical panel output is accepted unchanged. Legacy's stricter payload bounds
are retained; historical panel/legacy differences are not silently widened.
This schema check is not nfqws runtime/Lua validation or blob registration.
"""
import hashlib
import re

from kdn.state import nfqws


SERVICES = ('youtube', 'discord-tcp', 'discord-voice')
FIELDS = frozenset(('format', 'service', 'candidate_id', 'source_name', 'source_sha',
                    'source_url', 'family', 'args', 'notes', 'rank', 'report'))
REPORT_FIELDS = {'repository': 200, 'ref': 200, 'commit': 128, 'created_utc': 80}
SAFE_TOKEN = re.compile(r'--[a-z0-9-]+=[A-Za-z0-9_@/.,:+<>=!-]+')
SAFE_OPTIONS = frozenset(('filter-tcp', 'filter-udp', 'filter-l7', 'hostlist',
                          'out-range', 'payload', 'lua-desync'))
SAFE_LUA = frozenset(('fake', 'multisplit', 'multidisorder', 'multidisorder_legacy', 'fakedsplit', 'hostfakesplit'))


def candidate_id(value):
    """Existing tuner/panel SHA256 first12; no reordering or new ID algorithm."""
    text = '\n'.join((value['service'], value['source_name'], value['family'], *value['args']))
    return hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]


def _text(value, maximum, required=False):
    if (not isinstance(value, str) or len(value) > maximum or (required and not value)
            or any(char in value for char in '\r\n\0')):
        raise ValueError('invalid descriptor text')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('descriptor text is not valid UTF-8') from None


def _integer(value, maximum):
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and 0 <= value <= maximum and value % 1 == 0)


def validate_descriptor(value, *, voice_high=65535):
    """Return detached descriptor after validation; supply active Voice range explicitly.

    Default65535 matches validation of an unused legacy Voice profile. This
    function never reads a router/config. Missing report stays missing; no
    metadata or IDs are invented. NUL text is rejected (ambiguous shell transport).
    """
    if not isinstance(value, dict) or set(value) - FIELDS:
        raise ValueError('invalid descriptor schema')
    if (isinstance(value.get('format'), bool) or value.get('format') != 1
            or value.get('service') not in SERVICES or not _integer(value.get('rank'), 100000)):
        raise ValueError('invalid descriptor schema')
    for name, maximum, required in (('source_name', 160, True), ('source_sha', 128, False),
                                    ('source_url', 500, False), ('family', 240, True)):
        _text(value.get(name), maximum, required)
    identity = value.get('candidate_id')
    if not isinstance(identity, str) or not re.fullmatch(r'[0-9a-f]{12}', identity):
        raise ValueError('invalid candidate_id')
    args, notes = value.get('args'), value.get('notes')
    if not isinstance(args, list) or not 1 <= len(args) <= 40:
        raise ValueError('invalid args')
    if not isinstance(notes, list) or len(notes) > 20:
        raise ValueError('invalid notes')
    for note in notes:
        _text(note, 500)
    report = value.get('report')
    if report is not None:
        if not isinstance(report, dict) or set(report) - (set(REPORT_FIELDS) | {'search_seed'}):
            raise ValueError('invalid report')
        for name, maximum in REPORT_FIELDS.items():
            item = report.get(name)
            _text('' if item is None or item is False else item, maximum)
        seed = report.get('search_seed')
        if seed is not None and seed is not False and not _integer(seed, 4294967295):
            raise ValueError('invalid search_seed')
    for token in args:
        _text(token, 600, True)
        if token == '--new':
            continue
        if not SAFE_TOKEN.fullmatch(token):
            raise ValueError('unsafe token')
        name, content = token[2:].split('=', 1)
        if name not in SAFE_OPTIONS or (name == 'lua-desync' and content.split(':', 1)[0] not in SAFE_LUA):
            raise ValueError('unsupported option or strategy')
        if name == 'lua-desync' and any(
                part.startswith('ip_id=') and part not in {'ip_id=zero', 'ip_id=seq', 'ip_id=rnd'}
                for part in content.split(':')[1:]):
            raise ValueError('unsupported IP ID policy')
    _service_bounds(value['service'], args, voice_high)
    if candidate_id(value) != identity:
        raise ValueError('candidate_id does not match content')
    result = dict(value, args=list(args), notes=list(notes))
    if isinstance(report, dict):
        result['report'] = dict(report)
    return result


def _service_bounds(service, args, voice_high):
    nfqws.validate_service_profiles(service, args, voice_high=voice_high)
