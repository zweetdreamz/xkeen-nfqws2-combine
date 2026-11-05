"""Read-only proof that Direct packets do not match nfqws processed marks."""
import os
import re

from kdn.engine import compose, config, nfqws_validate


DEFAULT_FWMARK = '0x40000000'
DEFAULT_PROCESSED = '0x40000000/0x40000000'
_NUMBER = r'(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})'
_MASK = re.compile(_NUMBER + r'(?:/' + _NUMBER + r')?')


class MarkError(ValueError):
    pass


def _number(text, *, iptables=False):
    if not re.fullmatch(_NUMBER, text):
        raise MarkError('unparseable nfqws processed mark')
    base = 16 if text.lower().startswith('0x') else (8 if iptables and text.startswith('0') else 10)
    try:
        number = int(text, base)
    except ValueError as exc:
        raise MarkError('unparseable iptables processed mark') from exc
    if number > 0xffffffff:
        raise MarkError('nfqws processed mark exceeds uint32')
    return number


def _read(path):
    if not os.path.lexists(path):
        return ''
    try:
        return nfqws_validate._read_asset(path, 1048576, decompress=False,
                                          gzip_fallback=False).decode('utf-8', 'surrogateescape')
    except nfqws_validate.ValidationError as exc:
        raise MarkError('cannot read bounded nfqws mark configuration') from exc


def _package_processed(paths):
    """Extract only a literal package default preceding config sourcing.

    v1.3.2 inlines common into S51nfqws2. Executing that script would also
    dispatch service/kernel/RCI operations; none belongs in this preflight.
    """
    text = _read(paths.nfqws_init)
    found, sourced, scopes = [], False, []
    for line in text.splitlines():
        code = line.strip()
        if not code or code.startswith('#'):
            continue
        if re.search(r'(?:^|\s)(?:source|\.)\s+["\']?\$\{?CONFFILE(?:\}|["\']|$)', code):
            sourced = True
        if re.search(r'\bMARK_PROCESSED\s*=', code):
            match = re.fullmatch(r'MARK_PROCESSED=(?:"([^"\n]*)"|\'([^\'\n]*)\'|([^\s;]+))', line)
            value = next((item for item in match.groups() if item is not None), '') if match else ''
            if not match or sourced or scopes or not _MASK.fullmatch(value):
                raise MarkError('ambiguous package MARK_PROCESSED override; expected a literal before CONFFILE')
            found.append(value)
        elif re.search(r'\bMARK_PROCESSED\b', re.sub(
                r'\$\{MARK_PROCESSED\}|\$MARK_PROCESSED\b', '', code)):
            raise MarkError('ambiguous package MARK_PROCESSED mutation')
        if re.match(r'(?:if|case|for|while|until)\b', code) or re.match(r'[A-Za-z_][A-Za-z_0-9]*\(\)\s*\{', code):
            scopes.append(code)
        if code in ('fi', 'esac', 'done', '}') and scopes:
            scopes.pop()
    if len(found) > 1 or (found and not sourced):
        raise MarkError('ambiguous package MARK_PROCESSED initialization')
    return found[0] if found else DEFAULT_PROCESSED


def processed_mask(text):
    """Normalized iptables equality predicate, retaining its actual mask."""
    if not _MASK.fullmatch(text):
        raise MarkError('unparseable MARK_PROCESSED value/mask')
    value, slash, mask = text.partition('/')
    value, mask = _number(value, iptables=True), _number(mask, iptables=True) if slash else 0xffffffff
    return value & mask, mask


def effective(paths, environ=None):
    """Resolve checked nfqws skip bits and package processed predicate read-only."""
    default = _package_processed(paths)
    # Upstream-generated .run carries policy/interface/port metadata only.
    # Custom mark/startup overrides there are not reproducible on restart.
    running = _read(paths.nfqws_conf + '.run')
    if re.search(r'\b(?:MARK_PROCESSED|NFQWS_[A-Z_]*ARGS[A-Z_]*)\s*=', running):
        raise MarkError('unsupported mark/startup override in nfqws configuration.run')
    fwmark, processed = DEFAULT_FWMARK, default
    if os.path.isfile(paths.nfqws_conf):
        try:
            composition = compose.compose(paths.nfqws_conf, paths, environ or os.environ,
                config.timeout('compose', environ), processed_mark=default)
        except compose.ComposeError as exc:
            raise MarkError('cannot compose effective nfqws processed marks') from exc
        processed = composition.meta.get('MARK_PROCESSED', '')
        masks = []
        for token in composition.tokens:
            if token == '--':
                raise MarkError('ambiguous nfqws mark option separator')
            name, equal, value = token.partition('=')
            if name != '--' and len(name) > 2 and '--fwmark'.startswith(name):
                if name != '--fwmark' or not equal:
                    raise MarkError('ambiguous or abbreviated nfqws --fwmark option')
                masks.append(value)
        if len(masks) > 1:
            raise MarkError('ambiguous duplicate nfqws --fwmark options')
        if masks:
            fwmark = masks[0]
    processed_mask(processed)
    if not re.fullmatch(r'(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})', fwmark):
        raise MarkError('unparseable nfqws --fwmark')
    skip = _number(fwmark)
    if not skip:
        raise MarkError('nfqws --fwmark must be nonzero')
    return skip, processed


def validate(paths, mark, environ=None):
    """Raise before writes on skip-bit/equality collision, including implicit zero."""
    skip, processed = effective(paths, environ)
    value, mask = processed_mask(processed)
    number = int(mark.lstrip('0') or '0')
    if number & skip:
        raise MarkError('Direct mark collides with effective nfqws --fwmark skip bits')
    if number & mask == value & mask:
        raise MarkError('Direct mark collides with package MARK_PROCESSED value/mask')
