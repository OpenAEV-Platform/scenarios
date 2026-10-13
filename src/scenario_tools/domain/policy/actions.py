"""The maintainers' lists of actions, and how a command is read before they are matched: in
lower case, compatibility forms folded, without invisible characters, without the escapes and
quotes a shell removes, and with one space between words, so that ``v^ssadmin "delete"`` reads
as ``vssadmin delete``. A pattern is a regular expression the maintainers own."""

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

_WHY_LIMIT = 120
_REMOVED = str.maketrans("", "", "^`\"'")  # cmd and PowerShell escapes, and quotes
_JOINED = re.compile(r"[\"']\s*\+\s*[\"']")  # "vssa"+"dmin": the pieces of one word
_LINES = re.compile(r"[\r\n]+")  # each line a statement
_BLANKS = re.compile(r"[^\S\r\n]+")


@dataclass(frozen=True)
class ForbiddenAction:
    """An action a shared scenario never takes; one that removes a protection names what
    restores it, and is allowed in a payload whose cleanup command does."""

    pattern: re.Pattern[str]
    why: str
    restore: re.Pattern[str] | None


def as_command(text: str) -> str:
    """``text`` as a shell reads it, for matching."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = _JOINED.sub("", text).translate(_REMOVED)
    text = _LINES.sub(" ; ", _BLANKS.sub(" ", text))
    return _BLANKS.sub(" ", text).strip().lower()


def _pattern(value: object, name: str) -> re.Pattern[str]:
    if not isinstance(value, str):
        raise ValueError(f"{name}: a pattern must be a text")
    try:
        return re.compile(value)
    except re.error:
        raise ValueError(f"{name}: a pattern must compile") from None


def _items(document: object, name: str, key: str) -> list[object]:
    if not isinstance(document, Mapping) or not isinstance(document.get(key), list):
        raise ValueError(f"{name}: the document must be a mapping holding {key}")
    unknown = sorted(str(other) for other in document if other != key)
    if unknown:
        raise ValueError(f"{name}: unknown keys {', '.join(unknown)}")
    items: list[object] = document[key]
    return items


def _distinct(patterns: list[re.Pattern[str]], name: str) -> None:
    if len({pattern.pattern for pattern in patterns}) != len(patterns):
        raise ValueError(f"{name}: each pattern once")


def forbidden_from_document(document: object) -> tuple[ForbiddenAction, ...]:
    """Read the forbidden-actions data document: each action a pattern, a short reason and,
    for the removal of a protection, the pattern of what restores it."""
    name = "forbidden-actions"
    actions: list[ForbiddenAction] = []
    for item in _items(document, name, "actions"):
        if not isinstance(item, Mapping):
            raise ValueError(f"{name}: an action must be a mapping")
        unknown = sorted(str(key) for key in item if key not in ("pattern", "why", "restore"))
        if unknown:
            raise ValueError(f"{name}: unknown keys {', '.join(unknown)}")
        why = item.get("why")
        if not isinstance(why, str) or not why or len(why) > _WHY_LIMIT:
            raise ValueError(f"{name}: why must be a short text")
        restore = _pattern(item["restore"], name) if "restore" in item else None
        actions.append(ForbiddenAction(_pattern(item.get("pattern"), name), why, restore))
    _distinct([action.pattern for action in actions], name)
    return tuple(actions)


def side_effects_from_document(document: object) -> tuple[re.Pattern[str], ...]:
    """Read the side-effects data document: the patterns of commands that write, create or
    start something."""
    name = "side-effects"
    patterns = [_pattern(item, name) for item in _items(document, name, "commands")]
    _distinct(patterns, name)
    return tuple(patterns)
