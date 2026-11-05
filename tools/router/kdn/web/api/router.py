"""Request and Response as data, the route table and the Router: matching and dispatch without sockets.

A pattern is a path whose segments are literals or ``<name>``. A parameter takes exactly one non-empty segment
(raw, nothing is percent-decoded), a trailing slash or an empty segment is "no route", and the query string is not
part of the path: split_target cuts it off first. A literal route wins over a parameterised one.
"""

from dataclasses import dataclass, field, replace
import json
from urllib.parse import parse_qsl

from kdn.common import errors as panel_errors
from kdn.common import xkeen
from kdn.web.infra import readcache


JSON_CONTENT_TYPE = "application/json; charset=utf-8"
# (exception class, HTTP status): the first entry that fits wins; None takes the status the exception carries.
DEFAULT_ERRORS = (
    (panel_errors.PanelError, None),
    (RuntimeError, 409),
    (ValueError, 400),
    (OSError, 400),
)


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    query: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    client: str = ""
    body: object = None
    params: dict = field(default_factory=dict)

    def header(self, name):
        """Value of the header by name, in any letter case; the first one wins; None when it is absent."""
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return None


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str
    headers: dict = field(default_factory=dict)


def json_response(status, payload):
    return Response(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), JSON_CONTENT_TYPE)


def text_response(status, text, content_type):
    return Response(status, text.encode("utf-8"), content_type)


def error_response(status, message):
    return json_response(status, {"ok": False, "error": message})


def status_for(exc, errors):
    """HTTP status of the first entry of the table that fits the exception, or None when no entry does."""
    for kind, status in errors:
        if isinstance(exc, kind):
            return getattr(exc, "status", 500) if status is None else status
    return None


@dataclass(frozen=True)
class Route:
    method: str
    pattern: str
    handler: object
    errors: tuple | None = None
    automation_blocks: bool = True
    heavy: bool = False
    choices: dict = field(default_factory=dict)

    def __post_init__(self):
        names = [text for text, is_parameter in _segments(self.pattern) if is_parameter]
        unknown = sorted(set(self.choices) - set(names))
        if unknown:
            raise ValueError(f"choices for {unknown} but the pattern {self.pattern!r} has no such parameter")


@dataclass(frozen=True)
class Match:
    route: Route
    params: dict


def _segments(pattern):
    """((text, is_parameter), ...) of a pattern; a malformed pattern is a ValueError."""
    if not pattern.startswith("/"):
        raise ValueError(f"pattern {pattern!r} must start with /")
    if pattern == "/":
        return (("", False),)
    found = []
    for part in pattern[1:].split("/"):
        if part.startswith("<") and part.endswith(">") and part[1:-1].isidentifier():
            found.append((part[1:-1], True))
        elif part and "<" not in part and ">" not in part:
            found.append((part, False))
        else:
            raise ValueError(f"pattern {pattern!r}: segment {part!r} is neither a literal nor <name>")
    names = [text for text, is_parameter in found if is_parameter]
    if len(set(names)) != len(names):
        raise ValueError(f"pattern {pattern!r} repeats a parameter name")
    return tuple(found)


def split_target(target):
    """(path, query) of a request target: the query holds the first value of every key."""
    path, _, text = target.partition("?")
    query = {}
    for key, value in parse_qsl(text, keep_blank_values=True):
        query.setdefault(key, value)
    return path, query


class Router:
    """The route table: match finds a route by method and path, dispatch calls it and maps its errors to codes."""

    def __init__(self, routes):
        self.routes = tuple(routes)
        self._literal = {}
        self._parameterised = []
        seen = set()
        for route in self.routes:
            key = (route.method, route.pattern)
            if key in seen:
                raise ValueError(f"duplicate route {route.method} {route.pattern}")
            seen.add(key)
            segments = _segments(route.pattern)
            if any(is_parameter for _text, is_parameter in segments):
                self._parameterised.append((route, segments))
            else:
                self._literal[key] = route

    def match(self, method, path):
        """Match of the route for the method and the path (no query), or None."""
        route = self._literal.get((method, path))
        if route is not None:
            return Match(route, {})
        if not path.startswith("/"):
            return None
        parts = path[1:].split("/")
        for route, segments in self._parameterised:
            if route.method == method and len(segments) == len(parts):
                params = _capture(route, segments, parts)
                if params is not None:
                    return Match(route, params)
        return None

    def dispatch(self, request, match=None):
        """Answer for the request: the route's Response, 404 for an unknown route, a mapped code for its errors."""
        if match is None:
            match = self.match(request.method, request.path)
        if match is None:
            return error_response(404, "unknown endpoint" if request.method == "GET" else "unknown action")
        table = DEFAULT_ERRORS if match.route.errors is None else match.route.errors
        mutation = request.method != 'GET'
        if mutation:
            readcache.invalidate()
        try:
            return match.route.handler(replace(request, params=match.params))
        except xkeen.UnsupportedXKeen:
            return json_response(409, xkeen.error_status())
        except tuple(kind for kind, _status in table) as exc:
            return error_response(status_for(exc, table), str(exc))
        finally:
            if mutation:
                readcache.invalidate()


def _capture(route, segments, parts):
    params = {}
    for (text, is_parameter), part in zip(segments, parts, strict=True):
        if not is_parameter:
            if part != text:
                return None
        elif not part or (text in route.choices and part not in route.choices[text]):
            return None
        else:
            params[text] = part
    return params
