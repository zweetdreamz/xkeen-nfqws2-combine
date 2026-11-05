"""Typed errors of the panel: each carries the HTTP status the API layer answers with.

BadRequest, NotFound and Busy also derive from ValueError, LookupError and RuntimeError, so code that catches
the built-in kind (the mapping RuntimeError -> 409, ValueError -> 400) keeps working.
"""


class PanelError(Exception):
    """Base of the errors the panel maps to an HTTP status."""

    status = 500


class BadRequest(PanelError, ValueError):
    """The request is wrong: 400."""

    status = 400


class NotFound(PanelError, LookupError):
    """The thing asked for does not exist: 404."""

    status = 404


class Busy(PanelError, RuntimeError):
    """The router is busy with another job or lock: 409."""

    status = 409


class Upstream(PanelError):
    """An outside service failed: 502."""

    status = 502
