"""The maintainers' lists of actions, and how a command is read before they are matched.

A command is read in lower case, compatibility forms folded, without invisible characters,
without the escapes and quotes a shell removes, quoted pieces joined, and with one space between
words, so that ``v^ssadmin "delete"`` reads as ``vssadmin delete``. It is then cut into
statements, at ``;``, ``&&``, ``||``, ``&`` and line ends; a pipe stays inside its statement.

An action is a few steps, each a regular expression the maintainers own, found in order inside
one statement, however far apart: no padding between two words hides an action, and each step
is searched once from where the previous one ended, so that reading stays linear. What restores
a protection must start a statement of the cleanup command, so that ``echo`` of it is none.
"""

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

type Steps = tuple[re.Pattern[str], ...]

_WHY_LIMIT = 120
_STEPS_LIMIT = 8
_REMOVED = str.maketrans("", "", "^`\"'")  # cmd and PowerShell escapes, and quotes
_JOINED = re.compile(r"[\"']\s*\+\s*[\"']")  # "vssa"+"dmin": the pieces of one word
_LINES = re.compile(r"[\r\n]+")  # each line a statement
_BLANKS = re.compile(r"[^\S\r\n]+")
_SEPARATOR = re.compile(r"\s?(?:;|&&|\|\||&)\s?")
_PIPE = re.compile(r"\s?\|\s?")
_CONTINUED = re.compile(r"[\^`\\]\r?\n")  # cmd, PowerShell and shell line continuations
_DUPLICATED = re.compile(r"\d*[<>]&\d*-?|\|&")  # 2>&1, |&: no separator and no file
_BOTH_TO_FILE = re.compile(r"&(>>?)")  # &>f writes both outputs to f: a redirection to a file
_QUOTED = re.compile(r"\"[^\"]*(?:\"|\Z)|'[^']*(?:'|\Z)")  # an unclosed quote runs to the end
_BREAKS = re.compile(r"[;&|\r\n]")


@dataclass(frozen=True)
class ForbiddenAction:
    """An action a shared scenario never takes; one that removes a protection names what
    restores it, and is allowed in a payload whose cleanup command does."""

    steps: Steps
    why: str
    restore: Steps | None


def _unquoted_breaks(text: str) -> str:
    """``text`` with the separators and line ends inside quotes made blanks: a quoted value
    is part of its statement, whatever it holds."""
    return _QUOTED.sub(lambda quoted: _BREAKS.sub(" ", quoted[0]), text)


def as_command(text: str) -> str:
    """``text`` as a shell reads it, for matching."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = _unquoted_breaks(_CONTINUED.sub("", text))
    text = _DUPLICATED.sub(" ", _JOINED.sub("", text))
    text = _BOTH_TO_FILE.sub(r"\1", text).translate(_REMOVED)
    text = _LINES.sub(" ; ", _BLANKS.sub(" ", text))
    return _BLANKS.sub(" ", text).strip().lower()


def statements(read: str) -> list[str]:
    """The statements of a command read by ``as_command``."""
    return [part for part in _SEPARATOR.split(read) if part]


def pipeline_parts(read: str) -> list[str]:
    """The commands of each pipeline of each statement: what one program is given to run."""
    return [part for statement in statements(read) for part in _PIPE.split(statement) if part]


def _in_order(steps: Steps, statement: str, position: int = 0) -> bool:
    """Whether ``statement`` holds every step, in order, from ``position`` on."""
    for step in steps:
        found = step.search(statement, position)
        if found is None:
            return False
        position = found.end()
    return True


def takes(steps: Steps, read: str) -> bool:
    """Whether a statement of the command ``read`` holds every step, in order."""
    return any(_in_order(steps, statement) for statement in statements(read))


def runs(steps: Steps, read: str) -> bool:
    """Whether one command of a pipeline of ``read`` holds every step, in order: a command
    that writes is one program, never the ones its output is piped to."""
    return any(_in_order(steps, part) for part in pipeline_parts(read))


def starts(steps: Steps, read: str) -> bool:
    """Whether a statement of the command ``read`` starts with the first step and holds the
    others after it, in order."""
    first, rest = steps[0], steps[1:]
    for statement in statements(read):
        started = first.match(statement)
        if started is not None and _in_order(rest, statement, started.end()):
            return True
    return False


def _steps(value: object, name: str) -> Steps:
    if not isinstance(value, list) or not 1 <= len(value) <= _STEPS_LIMIT:
        raise ValueError(f"{name}: steps must be a list of 1 to {_STEPS_LIMIT} patterns")
    patterns: list[re.Pattern[str]] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name}: a pattern must be a text")
        try:
            patterns.append(re.compile(item))
        except re.error:
            raise ValueError(f"{name}: a pattern must compile") from None
    return tuple(patterns)


def _items(document: object, name: str, key: str) -> list[object]:
    if not isinstance(document, Mapping) or not isinstance(document.get(key), list):
        raise ValueError(f"{name}: the document must be a mapping holding {key}")
    unknown = sorted(str(other) for other in document if other != key)
    if unknown:
        raise ValueError(f"{name}: unknown keys {', '.join(unknown)}")
    items: list[object] = document[key]
    return items


def _distinct(all_steps: list[Steps], name: str) -> None:
    keys = [tuple(step.pattern for step in steps) for steps in all_steps]
    if len(set(keys)) != len(keys):
        raise ValueError(f"{name}: each action once")


def forbidden_from_document(document: object) -> tuple[ForbiddenAction, ...]:
    """Read the forbidden-actions data document: each action its steps, a short reason and, for
    the removal of a protection, the steps of what restores it."""
    name = "forbidden-actions"
    actions: list[ForbiddenAction] = []
    for item in _items(document, name, "actions"):
        if not isinstance(item, Mapping):
            raise ValueError(f"{name}: an action must be a mapping")
        unknown = sorted(str(key) for key in item if key not in ("steps", "why", "restore"))
        if unknown:
            raise ValueError(f"{name}: unknown keys {', '.join(unknown)}")
        why = item.get("why")
        if not isinstance(why, str) or not why or len(why) > _WHY_LIMIT:
            raise ValueError(f"{name}: why must be a short text")
        restore = _steps(item["restore"], name) if "restore" in item else None
        actions.append(ForbiddenAction(_steps(item.get("steps"), name), why, restore))
    _distinct([action.steps for action in actions], name)
    return tuple(actions)


def side_effects_from_document(document: object) -> tuple[Steps, ...]:
    """Read the side-effects data document: the steps of each command that writes, creates or
    starts something."""
    name = "side-effects"
    commands = [_steps(item, name) for item in _items(document, name, "commands")]
    _distinct(commands, name)
    return tuple(commands)
