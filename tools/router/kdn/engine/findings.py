"""The common language of the parts of --preflight: the messages found so far and what was learned on the way.

Plain classes with __slots__ (rule 9 of the import budget: no dataclasses on the way of a mode).
"""


class Finding:
    """One message of a mode: ``stream`` is the name of the Console method that prints it ("out" or "err")."""

    __slots__ = ("stream", "text")

    def __init__(self, stream, text):
        self.stream = stream
        self.text = text

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return NotImplemented
        return (self.stream, self.text) == (other.stream, other.text)

    def __hash__(self):
        return hash((self.stream, self.text))

    def __repr__(self):
        return f"Finding({self.stream!r}, {self.text!r})"


class State:
    """What the checks of --preflight share: the error count, the findings in the order of sh, the resolved values."""

    __slots__ = ("errors", "findings", "detected_core", "direct_mark", "proxy_outbound", "wan", "ipv6")

    def __init__(
        self, errors=0, findings=None, detected_core="", direct_mark="", proxy_outbound="", wan="", ipv6=""
    ):
        self.errors = errors
        self.findings = [] if findings is None else findings
        self.detected_core = detected_core
        self.direct_mark = direct_mark
        self.proxy_outbound = proxy_outbound
        self.wan = wan
        self.ipv6 = ipv6

    def _fields(self):
        return tuple(getattr(self, name) for name in self.__slots__)

    def __eq__(self, other):
        if not isinstance(other, State):
            return NotImplemented
        return self._fields() == other._fields()

    __hash__ = None

    def __repr__(self):
        pairs = ", ".join(f"{name}={getattr(self, name)!r}" for name in self.__slots__)
        return f"State({pairs})"
