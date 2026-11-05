"""Xray config files for the engine: the ``*.json`` of the config directory, JSONC loading and the jq primitives.

The shell reads these files with ``strict_json_stream`` (awk) and ``jq``; this module does the same in Python and
needs neither at run time. On what Xray writes the results are equal (the differential tests run both on one
corpus). They differ, on purpose (B7), on input that is not that:

* a file with several documents (``{} {}``): jq reads all of them and ``jq -e`` judges the last output, here the
  file is not a document and ``load_strict`` returns None;
* numbers that JSON does not allow but jq accepts (``007``, ``+1``, ``.5``, ``5.``, ``nan``): not a document here;
* a comment inside a token (``1/**/2``): awk joins the pieces, ``kdn.common.jsonc`` leaves a space;
* an escaped lone surrogate (``"\\ud800"``): jq refuses it, json keeps it;
* an invalid UTF-8 byte inside a string: jq turns it into U+FFFD, here it stays as a surrogate escape;
* an integer of more than 4300 digits or nesting deeper than the interpreter allows: not a document here;
* an exponent beyond the interpreter's integer-conversion limit: not a document here, rather than a later
  failure while formatting it (jq accepts/clamps these extreme literals);
* a number literal whose exponent is below the decNumber range (``1e-1234567890``) prints as written, jq prints a
  zero with a huge exponent; ``jq_length`` of a number beyond the range of a double is infinite, jq's is the
  largest double.
"""

import json
import os
from pathlib import Path

from kdn.common import jsonc


_DBL_MAX = 1.7976931348623157e308
_DBL_MAX_TEXT = "1.7976931348623157e+308"
# decNumber's largest exponent: a literal beyond it is infinite for jq and prints as the largest double.
_MAX_ADJUSTED_EXPONENT = 999999999


class JqError(Exception):
    """A jq runtime error (for example the length of a boolean)."""


class JqFloat(float):
    """A number read from a file that keeps its literal: jq 1.7 and later print a number as it was written."""

    def __new__(cls, literal):
        _mantissa, separator, exponent = literal.lower().partition("e")
        if separator:
            # _literal_text needs this integer. Validate while load_strict can
            # still reject the file, not after returning a half-usable value.
            int(exponent)
        number = super().__new__(cls, literal)
        number.literal = literal
        return number


def json_files(config_dir):
    """The paths of ``"$DIR"/*.json`` that ``[ -f ]`` accepts: no dotfiles, bytewise order, symlinks followed."""
    base = os.fspath(config_dir)
    try:
        names = os.listdir(os.fsencode(base))
    except OSError:
        return []
    found = []
    for name in sorted(names):
        if name.startswith(b".") or not name.endswith(b".json"):
            continue
        path = Path(base, os.fsdecode(name))
        if os.path.isfile(path):
            found.append(path)
    return found


def _parse_int(text):
    return JqFloat(text) if text == "-0" else int(text)


def _parse_constant(name):
    # jq reads NaN as a number that prints as null and Infinity as the largest double.
    if name == "NaN":
        return float("nan")
    return -_DBL_MAX if name == "-Infinity" else _DBL_MAX


def load_strict(path):
    """The document of a JSONC file, or None when it is unreadable, not one JSON document, null or false.

    A result of None is the only "no": 0, "" and [] are documents. Numbers with a fraction or an exponent are
    ``JqFloat`` (a float that remembers its literal).
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None
    text = raw.decode("utf-8", "surrogateescape")
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        document = json.loads(
            jsonc.strip_json_comments(text), parse_int=_parse_int, parse_float=JqFloat, parse_constant=_parse_constant
        )
    except (ValueError, RecursionError):
        return None
    return None if document is None or document is False else document


def routing_file(config_dir):
    """The last file of the directory whose ``.routing`` is an object (Xray lets a later one override), or None."""
    found = None
    for path in json_files(config_dir):
        document = load_strict(path)
        if isinstance(document, dict) and isinstance(document.get("routing"), dict):
            found = path
    return found


def jq_iter(value):
    """Iterator of ``.[]?``: the items of a list, the values of an object, nothing for anything else."""
    if isinstance(value, list):
        return iter(value)
    if isinstance(value, dict):
        return iter(value.values())
    return iter(())


def jq_length(value):
    """``length``: 0 for null, the absolute value of a number, the size of a string, list or object."""
    if value is None:
        return 0
    if isinstance(value, bool):
        raise JqError(f"boolean ({'true' if value else 'false'}) has no length")
    if isinstance(value, (int, float)):
        return abs(value)
    return len(value)


def jq_raw(value):
    """The text of ``jq -r`` for a value, without the final newline."""
    return value if isinstance(value, str) else _dump(value, "")


def _dump(value, indent):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, JqFloat):
        return _literal_text(value.literal)
    if isinstance(value, int):
        return str(int(value))
    if isinstance(value, float):
        return _double_text(value)
    inner = indent + "  "
    if isinstance(value, list):
        if not value:
            return "[]"
        return "[\n" + ",\n".join(inner + _dump(item, inner) for item in value) + "\n" + indent + "]"
    if not value:
        return "{}"
    entries = (f"{inner}{_quote(key)}: {_dump(item, inner)}" for key, item in value.items())
    return "{\n" + ",\n".join(entries) + "\n" + indent + "}"


def _quote(text):
    return json.dumps(text, ensure_ascii=False).replace("\x7f", "\\u007f")


def _literal_text(literal):
    """The scientific string of a number literal (General Decimal Arithmetic), which jq 1.7 and later print."""
    sign = "-" if literal.startswith("-") else ""
    mantissa, _, exponent_text = literal.lstrip("+-").lower().partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0") or "0"
    exponent = int(exponent_text or 0) - len(fraction)
    adjusted = exponent + len(digits) - 1
    if adjusted > _MAX_ADJUSTED_EXPONENT:
        return sign + _DBL_MAX_TEXT
    if exponent <= 0 and adjusted >= -6:
        if exponent == 0:
            return sign + digits
        if len(digits) > -exponent:
            return f"{sign}{digits[:exponent]}.{digits[exponent:]}"
        return f"{sign}0.{'0' * (-exponent - len(digits))}{digits}"
    tail = f".{digits[1:]}" if len(digits) > 1 else ""
    return f"{sign}{digits[0]}{tail}E{'+' if adjusted >= 0 else '-'}{abs(adjusted)}"


def _double_text(value):
    """A double the way jq prints a computed number: 255.0 is 255, 1e20 is 1e+20."""
    if value != value:
        return "null"
    if value in (float("inf"), float("-inf")):
        return ("-" if value < 0 else "") + _DBL_MAX_TEXT
    sign = "-" if repr(value).startswith("-") else ""
    if value == 0:
        return sign + "0"
    mantissa, _, exponent_text = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = whole + fraction
    point = len(whole) + int(exponent_text or 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    if point <= -4 or point > len(digits) + 15:
        tail = f".{digits[1:]}" if len(digits) > 1 else ""
        return f"{sign}{digits[0]}{tail}e{point - 1:+03d}"
    if point <= 0:
        return f"{sign}0.{'0' * -point}{digits}"
    if point >= len(digits):
        return sign + digits + "0" * (point - len(digits))
    return f"{sign}{digits[:point]}.{digits[point:]}"


def _field(value, name):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise JqError("cannot index this JSON value with a string")
    return value.get(name)


def _rules(document):
    return jq_iter(_field(_field(document, "routing"), "rules"))


def _domain_length(rule):
    domain = _field(rule, "domain")
    return jq_length([] if domain is None or domain is False else domain)


def _direct(document, service):
    try:
        for rule in _rules(document):
            tag = _field(rule, "outboundTag")
            if service == "youtube":
                if tag == "youtube-direct":
                    return True
            elif tag == "discord-direct":
                if service == "tcp" and _domain_length(rule) > 0:
                    return True
                if service == "udp" and _field(rule, "network") == "udp" and _domain_length(rule) == 0:
                    return True
    except JqError:
        return False
    return False


def discord_tcp_direct(document):
    return _direct(document, "tcp")


def discord_voice_direct(document):
    return _direct(document, "udp")


def youtube_direct(document):
    return _direct(document, "youtube")


def telegram_outbound(document):
    try:
        tags = [_field(rule, "outboundTag") for rule in _rules(document)
                if isinstance(rule, dict) and isinstance(rule.get("ruleTag"), str)
                and rule["ruleTag"].startswith("kdn-telegram")]
    except JqError:
        return ""
    if "telegram-ws" in tags:
        return "telegram-ws"
    return jq_raw(tags[0]).rstrip("\n") if tags else ""


def _is_proxy(outbound):
    return _field(outbound, "protocol") not in ("freedom", "blackhole", "dns", "loopback")


def _tag_exists(config_dir, tag, proxy):
    for path in json_files(config_dir):
        try:
            for outbound in jq_iter(_field(load_strict(path), "outbounds")):
                if _field(outbound, "tag") == tag and (not proxy or _is_proxy(outbound)):
                    return True
        except JqError:
            continue
    return False


def outbound_tag_exists(config_dir, tag):
    return _tag_exists(config_dir, tag, False)


def proxy_outbound_tag_exists(config_dir, tag):
    return _tag_exists(config_dir, tag, True)


def freedom_mark(config_dir):
    result = ""
    for path in json_files(config_dir):
        marks = []
        try:
            for outbound in jq_iter(_field(load_strict(path), "outbounds")):
                if _field(outbound, "protocol") == "freedom":
                    mark = _field(_field(_field(outbound, "streamSettings"), "sockopt"), "mark")
                    if mark is not None and mark is not False:
                        marks.append(mark)
        except JqError:
            continue  # jq constructs the whole array before printing it
        if marks:
            candidate = jq_raw(marks[-1]).rstrip("\n")
            if candidate:
                result = candidate
    return result


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_DIRECT_TAGS = ("discord-direct", "youtube-direct", "direct", "block")


def _youtube_proxy(document):
    tags = []
    for rule in _rules(document):
        # jq's optional .outboundTag? skips scalar rules in this query.
        if not isinstance(rule, dict):
            continue
        tag = rule.get("outboundTag")
        if tag is None or tag in _DIRECT_TAGS:
            continue
        if any(isinstance(domain, str) and "youtube" in domain.translate(_ASCII_LOWER)
               for domain in jq_iter(rule.get("domain"))):
            tags.append(tag)
    return jq_raw(tags[0]).rstrip("\n") if tags else ""


def _raw_lines(value):
    return jq_raw(value).split("\n")


def _nonempty_lines(lines):
    return [line for line in sorted(set(lines), key=os.fsencode) if line.strip(" \t\r\n\v\f")]


def discover_proxy_outbound(config_dir):
    path = routing_file(config_dir)
    if path is None:
        return None
    document = load_strict(path)
    try:
        youtube = _youtube_proxy(document)
    except JqError:
        youtube = ""
    if youtube:
        return youtube
    candidates = []
    for config_path in json_files(config_dir):
        try:
            for outbound in jq_iter(_field(load_strict(config_path), "outbounds")):
                if _is_proxy(outbound):
                    tag = _field(outbound, "tag")
                    if tag is not None and tag is not False:
                        candidates.extend(_raw_lines(tag))
        except JqError:
            pass  # streaming jq keeps values printed before an error
    candidates = _nonempty_lines(candidates)
    if len(candidates) == 1:
        return candidates[0]
    used = []
    try:
        for rule in _rules(document):
            tag = _field(rule, "outboundTag")
            if tag is not None and tag is not False:
                used.extend(_raw_lines(tag))
    except JqError:
        pass
    used = _nonempty_lines(line for line in used if line in candidates)
    return used[0] if len(used) == 1 else None


def inbounds(config_dir):
    """Approved inbound metadata only; roles follow settings/sockopt, not tag names."""
    result = []
    for path in json_files(config_dir):
        document = load_strict(path)
        if not isinstance(document, dict):
            continue
        for inbound in jq_iter(document.get('inbounds')):
            if not isinstance(inbound, dict):
                continue
            settings = inbound.get('settings')
            settings = settings if isinstance(settings, dict) else {}
            stream = inbound.get('streamSettings')
            stream = stream if isinstance(stream, dict) else {}
            sockopt = stream.get('sockopt')
            sockopt = sockopt if isinstance(sockopt, dict) else {}
            role = sockopt.get('tproxy')
            if role not in ('redirect', 'tproxy'):
                role = 'redirect' if settings.get('followRedirect') is True else 'other'
            sniffing = inbound.get('sniffing')
            sniffing = sniffing if isinstance(sniffing, dict) else {}
            safe_sniffing = {key: sniffing[key] for key in ('enabled', 'routeOnly') if isinstance(sniffing.get(key), bool)}
            if isinstance(sniffing.get('destOverride'), list):
                safe_sniffing['destOverride'] = [value for value in sniffing['destOverride'] if isinstance(value, str)]
            network = settings.get('allowedNetwork', settings.get('network'))
            result.append({'file': path.name, 'tag': inbound.get('tag') if isinstance(inbound.get('tag'), str) else None,
                           'protocol': inbound.get('protocol') if isinstance(inbound.get('protocol'), str) else None,
                           'role': role, 'allowed_network': network if isinstance(network, str) else None,
                           'sniffing': safe_sniffing})
    return result


def rules_summary(doc):
    routing = doc.get('routing') if isinstance(doc, dict) else None
    rules = routing.get('rules') if isinstance(routing, dict) else None
    rows = list(jq_iter(rules))
    return {'total': len(rows), 'with_type_field': sum(isinstance(row, dict) and row.get('type') == 'field' for row in rows),
            'with_domain': sum(isinstance(row, dict) and bool(row.get('domain')) for row in rows),
            'with_ip': sum(isinstance(row, dict) and bool(row.get('ip')) for row in rows)}
