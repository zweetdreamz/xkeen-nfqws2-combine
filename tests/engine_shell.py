"""Shell extractors and runners of the engine tests: functions and assignments of apply-discord-nfqws2.sh.

``extract_function`` and ``extract_assignment`` read the text of the script the way a POSIX shell lexes it, not
with ``awk '/^}$/'``: the file holds closing braces in the first column inside heredocs and inside quoted strings
that span lines, and assignments such as ``NFQWS_ARGS_CUSTOM=`` in the first column inside those strings. The
scanner follows heredocs (``<<EOF``, ``<<'EOF'``, ``<<"EOF"``, ``<<\\EOF``, ``<<-EOF`` with tab-stripped
terminators), single and double quotes, backslash escapes, comments, ``$(...)``, ``$((...))``, ``${...}``,
backticks and ``case`` patterns inside a substitution. A line counts as top level when no quote, substitution
or heredoc is open at its start; only such lines start functions and assignments.

``run_sh`` and ``run_function`` run the extracted text under dash, busybox ash or any other shell. The module
does not import ``kdn``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import contextlib
import functools
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import Any, NamedTuple


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests/fixtures/engine/legacy-apply-phase6.sh.txt"

# Characters that end an unquoted word.
_WORD_END = frozenset(" \t\n;&|()<>")
# Characters after which a word starts (a "#" there opens a comment, a keyword there may be one).
_WORD_START_AFTER = frozenset(" \t\n;&|(){")
# After these words a command starts.
_COMMAND_KEYWORDS = frozenset({"then", "do", "else", "elif", "if", "while", "until"})
_KIND_NAMES = {
    "sq": "single quote",
    "dq": "double quote",
    "brace": "${...} expansion",
    "cmd": "$(...) substitution",
    "bt": "backtick substitution",
}
_WORD = re.compile(r"[A-Za-z0-9_]+")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_FUNCTION_START = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\(\) *\{(?=[ \t]*(?:\n|#|\Z))")
_ASSIGNMENT_START = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")
_RAW_FUNCTION = re.compile(r"(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\(\)")


class _Frame:
    """One open construct: command text ("cmd", "bt"), a quote ("sq", "dq") or a ``${...}`` expansion."""

    __slots__ = ("arithmetic", "cases", "command_start", "kind", "opened", "paren")

    def __init__(self, kind: str, *, paren: int = 0, arithmetic: bool = False) -> None:
        self.kind = kind
        self.opened = 0
        self.paren = paren
        self.arithmetic = arithmetic
        self.cases = 0
        self.command_start = True


class _Scanner:
    """Walks shell text token by token and records the offsets of the lines that start at the top level."""

    def __init__(self, text: str, pos: int = 0) -> None:
        self.text = text
        self.size = len(text)
        self.pos = pos
        self.frames = [_Frame("cmd")]
        self.pending: list[tuple[str, bool, int]] = []
        self.line_starts = [pos]

    def at_top(self) -> bool:
        return len(self.frames) == 1

    def run(self) -> None:
        while self.pos < self.size:
            self.step()
        self.finish()

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1

    def unterminated(self) -> ValueError:
        frame = self.frames[-1]
        return ValueError(f"unterminated {_KIND_NAMES[frame.kind]} opened on line {self.line_of(frame.opened)}")

    def finish(self) -> None:
        if len(self.frames) > 1:
            raise self.unterminated()
        if self.pending:
            word, _, opened = self.pending[0]
            raise ValueError(f"unterminated heredoc <<{word} opened on line {self.line_of(opened)}")

    def step(self) -> None:
        frame = self.frames[-1]
        if frame.kind == "sq":
            self._single_quote()
        elif frame.kind == "dq":
            self._double_quote()
        elif frame.kind == "brace":
            self._expansion()
        else:
            self._command(frame)

    def _push(self, frame: _Frame, width: int) -> None:
        frame.opened = self.pos
        self.frames.append(frame)
        self.pos += width

    def _pop(self, width: int) -> None:
        self.frames.pop()
        self.pos += width
        self.frames[-1].command_start = False

    def _single_quote(self) -> None:
        end = self.text.find("'", self.pos)
        if end < 0:
            raise self.unterminated()
        self._pop(end + 1 - self.pos)

    def _dollar(self) -> None:
        """Handles ``$`` in a double quote, an expansion or command text."""
        text, i = self.text, self.pos
        following = text[i + 1 : i + 2]
        if following == "(":
            if text.startswith("((", i + 1):
                self._push(_Frame("cmd", paren=1, arithmetic=True), 3)
            else:
                self._push(_Frame("cmd"), 2)
        elif following == "{":
            self._push(_Frame("brace"), 2)
        else:
            self.pos += 1

    def _double_quote(self) -> None:
        char = self.text[self.pos]
        if char == "\\":
            self.pos += 2
        elif char == '"':
            self._pop(1)
        elif char == "$":
            self._dollar()
        elif char == "`":
            self._push(_Frame("bt"), 1)
        else:
            self.pos += 1

    def _expansion(self) -> None:
        char = self.text[self.pos]
        if char == "\\":
            self.pos += 2
        elif char == "'":
            self._push(_Frame("sq"), 1)
        elif char == '"':
            self._push(_Frame("dq"), 1)
        elif char == "$":
            self._dollar()
        elif char == "`":
            self._push(_Frame("bt"), 1)
        elif char == "}":
            self._pop(1)
        else:
            self.pos += 1

    def _command(self, frame: _Frame) -> None:
        text, i = self.text, self.pos
        char = text[i]
        if char == "\n":
            self._newline(frame)
        elif char in " \t":
            self.pos = i + 1
        elif char == "\\":
            frame.command_start = False
            self.pos = i + 2
        elif char == "'":
            frame.command_start = False
            self._push(_Frame("sq"), 1)
        elif char == '"':
            frame.command_start = False
            self._push(_Frame("dq"), 1)
        elif char == "`":
            frame.command_start = False
            if frame.kind == "bt":
                self._pop(1)
            else:
                self._push(_Frame("bt"), 1)
        elif char == "$":
            frame.command_start = False
            self._dollar()
        elif char == "#" and (i == 0 or text[i - 1] in _WORD_START_AFTER):
            end = text.find("\n", i)
            self.pos = self.size if end < 0 else end
        elif char == "<" and text.startswith("<<", i):
            frame.command_start = False
            if frame.arithmetic or text.startswith("<<<", i):
                self.pos = i + (3 if text.startswith("<<<", i) else 2)
            else:
                self._heredoc_word()
        elif char in ";&|":
            frame.command_start = True
            self.pos = i + 1
        elif char == "(":
            frame.paren += 1
            frame.command_start = True
            self.pos = i + 1
        elif char == ")":
            frame.command_start = True
            if frame.paren > 0:
                frame.paren -= 1
                self.pos = i + 1
            elif len(self.frames) > 1 and frame.cases == 0:
                self._pop(1)
            else:
                self.pos = i + 1
        elif char == "{":
            frame.command_start = True
            self.pos = i + 1
        else:
            word = _WORD.match(text, i)
            if word:
                self._word(frame, word)
            else:
                frame.command_start = False
                self.pos = i + 1

    def _word(self, frame: _Frame, match: re.Match[str]) -> None:
        text, i = self.text, self.pos
        end = match.end()
        word = match.group()
        whole = (i == 0 or text[i - 1] in _WORD_START_AFTER) and (end >= self.size or text[end] in _WORD_END)
        self.pos = end
        if whole and word == "case" and frame.command_start:
            frame.cases += 1
            frame.command_start = False
        elif whole and word == "esac" and frame.command_start and frame.cases > 0:
            frame.cases -= 1
            frame.command_start = False
        else:
            frame.command_start = whole and word in _COMMAND_KEYWORDS

    def _heredoc_word(self) -> None:
        """Reads the delimiter after ``<<`` and queues the heredoc; the body is skipped at the next newline."""
        text, size = self.text, self.size
        j = self.pos + 2
        strip_tabs = text.startswith("-", j)
        if strip_tabs:
            j += 1
        while j < size and text[j] in " \t":
            j += 1
        word: list[str] = []
        while j < size and text[j] not in _WORD_END:
            char = text[j]
            if char == "'":
                end = text.find("'", j + 1)
                if end < 0:
                    raise ValueError(f"unterminated quote in a heredoc word on line {self.line_of(j)}")
                word.append(text[j + 1 : end])
                j = end + 1
            elif char == '"':
                j += 1
                while j < size and text[j] != '"':
                    if text[j] == "\\" and text[j + 1 : j + 2] in ("\\", '"', "$", "`"):
                        j += 1
                    word.append(text[j])
                    j += 1
                if j >= size:
                    raise ValueError(f"unterminated quote in a heredoc word on line {self.line_of(j)}")
                j += 1
            elif char == "\\":
                word.append(text[j + 1 : j + 2])
                j += 2
            else:
                word.append(char)
                j += 1
        if not word:
            raise ValueError(f"a heredoc without a delimiter on line {self.line_of(self.pos)}")
        self.pending.append(("".join(word), strip_tabs, self.pos))
        self.pos = j

    def _newline(self, frame: _Frame) -> None:
        text, i = self.text, self.pos + 1
        for word, strip_tabs, opened in self.pending:
            while True:
                if i >= self.size:
                    raise ValueError(f"unterminated heredoc <<{word} opened on line {self.line_of(opened)}")
                end = text.find("\n", i)
                line = text[i : self.size if end < 0 else end]
                i = self.size if end < 0 else end + 1
                if (line.lstrip("\t") if strip_tabs else line) == word:
                    break
        self.pending = []
        self.pos = i
        frame.command_start = True
        if self.at_top():
            self.line_starts.append(i)


class _Function(NamedTuple):
    name: str
    start: int
    end: int


class _Index(NamedTuple):
    text: str
    functions: tuple[_Function, ...]
    assignments: tuple[tuple[str, int], ...]


@functools.lru_cache(maxsize=32)
def _index(text: str) -> _Index:
    scanner = _Scanner(text)
    scanner.run()
    starts = scanner.line_starts
    functions: list[_Function] = []
    assignments: list[tuple[str, int]] = []
    inside_until = -1
    for number, start in enumerate(starts):
        if start < inside_until:
            continue
        found = _FUNCTION_START.match(text, start)
        if found:
            for later in range(number + 1, len(starts)):
                end = starts[later]
                if text.startswith("}", end):
                    break
            else:
                raise ValueError(f"function {found.group(1)} has no closing brace in the first column")
            line_end = text.find("\n", end)
            inside_until = len(text) if line_end < 0 else line_end
            functions.append(_Function(found.group(1), start, inside_until))
            continue
        found = _ASSIGNMENT_START.match(text, start)
        if found:
            assignments.append((found.group(1), found.end()))
    return _Index(text, tuple(functions), tuple(assignments))


def script_text() -> str:
    """The text of apply-discord-nfqws2.sh with its bytes kept (undecodable ones as surrogates)."""
    return SCRIPT.read_bytes().decode("utf-8", errors="surrogateescape")


def function_names(source: str | None = None) -> list[str]:
    """Names of the functions defined at the top level of the script, in file order."""
    return [function.name for function in _index(script_text() if source is None else source).functions]


def function_spans(source: str | None = None) -> list[tuple[str, int, int]]:
    """(name, start, end) offsets of the functions in the text; ``end`` is the end of the closing-brace line."""
    return [tuple(function) for function in _index(script_text() if source is None else source).functions]


def extract_function(name: str, source: str | None = None) -> str:
    """Text of the function from ``name() {`` to its closing ``}`` in the first column, outside heredocs and strings."""
    index = _index(script_text() if source is None else source)
    found = [function for function in index.functions if function.name == name]
    if not found:
        raise KeyError(f"no function {name!r} at the top level of the script")
    if len(found) > 1:
        raise ValueError(f"function {name!r} is defined {len(found)} times")
    return index.text[found[0].start : found[0].end]


def extract_assignment(name: str, source: str | None = None) -> str:
    """Value of the top-level ``NAME=...``, as written, without its outer quotes (one quoted part or none)."""
    index = _index(script_text() if source is None else source)
    found = [offset for assigned, offset in index.assignments if assigned == name]
    if not found:
        raise KeyError(f"no top-level assignment of {name!r} in the script")
    if len(found) > 1:
        raise ValueError(f"{name!r} is assigned {len(found)} times at the top level")
    return _read_value(index.text, found[0])


def _read_value(text: str, start: int) -> str:
    scanner = _Scanner(text, start)
    quoted: list[tuple[int, int]] = []
    plain = False
    opened = -1
    while scanner.pos < scanner.size:
        if scanner.at_top():
            char = text[scanner.pos]
            if char in _WORD_END:
                break
            if char in "'\"":
                opened = scanner.pos
            else:
                plain = True
        scanner.step()
        if opened >= 0 and scanner.at_top():
            quoted.append((opened, scanner.pos))
            opened = -1
    scanner.finish()
    end = scanner.pos
    if not quoted:
        return text[start:end]
    if plain or quoted != [(start, end)]:
        raise ValueError(f"the value {text[start:end]!r} mixes quoted and other parts")
    return text[start + 1 : end - 1]


def run_sh(
    script: str,
    *,
    env: Mapping[str, str] | None = None,
    shell: Sequence[str] = ("sh",),
    stdin: str | None = None,
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    """Runs ``<shell> -c script``; output and ``stdin`` are text, decoded and encoded as bytes (surrogateescape).

    There is no newline translation: CR and CRLF come back as they were written. ``env`` is the whole environment
    when given.
    """
    completed = subprocess.run(
        [*shell, "-c", script],
        input=None if stdin is None else stdin.encode("utf-8", errors="surrogateescape"),
        stdin=subprocess.DEVNULL if stdin is None else None,
        capture_output=True,
        env=None if env is None else dict(env),
        timeout=timeout,
        check=False,
    )
    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        completed.stdout.decode("utf-8", errors="surrogateescape"),
        completed.stderr.decode("utf-8", errors="surrogateescape"),
    )


def run_function(
    name: str,
    *args: Any,
    defs: Sequence[str] = (),
    variables: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    awk: str = "system",
    shell: Sequence[str] = ("sh",),
    stdin: str | None = None,
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    """Runs the script function ``name`` with ``args`` after the definitions in ``defs`` and the ``variables``.

    An entry of ``defs`` that is an identifier names a function of the script to define; any other entry is shell
    text put in as it is (stubs, extra assignments), and a function it defines takes the place of the script's.
    ``awk="busybox"`` puts a directory with an ``awk`` link to busybox at the front of ``PATH`` for the call.
    """
    if awk not in ("system", "busybox"):
        raise ValueError(f"awk must be 'system' or 'busybox', not {awk!r}")
    definitions: dict[str, str] = {}
    texts: list[str] = []
    for entry in defs:
        if _IDENTIFIER.match(entry):
            if entry not in definitions:
                definitions[entry] = extract_function(entry)
                texts.append(definitions[entry])
        else:
            texts.append(entry)
            definitions.update(dict.fromkeys(_RAW_FUNCTION.findall(entry), entry))
    if name not in definitions:
        texts.append(extract_function(name))
    for variable, value in (variables or {}).items():
        if not _IDENTIFIER.match(variable):
            raise ValueError(f"bad variable name {variable!r}")
        texts.append(f"{variable}={shlex.quote(str(value))}")
    texts.append(" ".join([name, *(shlex.quote(str(argument)) for argument in args)]))
    script = "\n".join(texts) + "\n"
    with contextlib.ExitStack() as stack:
        run_env = env
        if awk == "busybox":
            busybox = shutil.which("busybox")
            if busybox is None:
                raise FileNotFoundError("busybox is not installed")
            applets = stack.enter_context(tempfile.TemporaryDirectory(prefix="engine-awk-"))
            os.symlink(os.path.abspath(busybox), os.path.join(applets, "awk"))
            run_env = dict(os.environ if env is None else env)
            run_env["PATH"] = applets + os.pathsep + run_env.get("PATH", os.defpath)
        return run_sh(script, env=run_env, shell=shell, stdin=stdin, timeout=timeout)
