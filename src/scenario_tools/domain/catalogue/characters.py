"""Hidden characters anywhere in a scenario: every value and key, and the characters the escapes
of a value write. Any value may hold JSON text, which the platform decodes, and a text may be
encoded more than once: each value is decoded as a JSON reader would, up to three times, and
every one of these views is checked. An escape still written after the last decoding is refused
whatever it writes, so that no depth of encoding hides a character from the check."""

import re
import unicodedata
from collections.abc import Collection, Iterator
from typing import Any

from scenario_tools.domain.shared.characters import HIDDEN, JOINERS, Hidden, hidden_occurrences
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, REPORT_LIMIT, Finding, Severity

# What one decoding of a JSON string turns into a single character: a pair of backslashes, an
# escape, or a surrogate pair written as two adjacent escapes. Other escapes are left as written:
# a newline or a quote hides nothing, and reading backspace and form feed would turn every regex
# word boundary and Windows path into a control character.
_HEX = "[0-9a-fA-F]"
_ESCAPE = re.compile(
    rf"\\(?:(\\)|u(?:([dD][89abAB]{_HEX}{{2}})\\u([dD][c-fC-F]{_HEX}{{2}})|({_HEX}{{4}})))"
)
_YAML_BREAKS = frozenset((chr(0x85), chr(0x2028), chr(0x2029)))
_LEFT = re.compile(rf"\\u{_HEX}{{4}}")  # an escape a further decoding would read
_DECODINGS = 3
_TO_DO = "remove it on the platform and export the scenario again"
_CHUNK = 4096  # pieces joined at a time, so that a text of many escapes stays small to decode


def _character(match: re.Match[str]) -> str:
    """The character an escape writes: a backslash for a pair, a surrogate pair's whole."""
    if match.group(1):
        return match.group(1)
    if match.group(2):
        high, low = int(match.group(2), 16), int(match.group(3), 16)
        return chr(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
    return chr(int(match.group(4), 16))


def _decoded(text: str) -> str | None:
    """``text`` decoded once, as a JSON reader would, or None when it writes no escape. Linear
    in time and in memory: the pieces are joined as they come."""
    chunks: list[str] = []
    pieces: list[str] = []
    last = 0
    for match in _ESCAPE.finditer(text):
        pieces += (text[last : match.start()], _character(match))
        last = match.end()
        if len(pieces) >= _CHUNK:
            chunks.append("".join(pieces))
            pieces.clear()
    if not last:
        return None
    pieces.append(text[last:])
    chunks.append("".join(pieces))
    return "".join(chunks)


def _views(text: str) -> list[str]:
    """``text``, then what each decoding makes of the one before, until a decoding finds no
    escape or ``_DECODINGS`` are made."""
    views = [text]
    while len(views) <= _DECODINGS and (decoded := _decoded(views[-1])) is not None:
        views.append(decoded)
    return views


def _places(text: str, wanted: list[int]) -> dict[int, tuple[int, bool]]:
    """Where in ``text`` each ``wanted`` index of its decoded view comes from, and whether an
    escape wrote it there: one pass, however many are wanted."""
    targets = sorted(wanted, reverse=True)  # the next one last, to take it in constant time
    places: dict[int, tuple[int, bool]] = {}
    decoded = last = 0  # where the text after the last escape starts, decoded and in the source
    for match in _ESCAPE.finditer(text):
        escape = decoded + match.start() - last
        while targets and targets[-1] <= escape:
            target = targets.pop()
            places[target] = (
                (match.start(), True) if target == escape else (last + target - decoded, False)
            )
        decoded, last = escape + 1, match.end()
    places.update((target, (last + target - decoded, False)) for target in targets)
    return places


def _sources(
    views: list[str], wanted: list[tuple[int, int]]
) -> dict[tuple[int, int], tuple[int, bool]]:
    """Where in the source each wanted (view, index) comes from, and whether an escape wrote it
    on the way: one pass per decoding, however many are wanted."""
    state = {key: (key[1], False) for key in wanted}
    for level in range(len(views) - 1, 0, -1):
        moving = [key for key in state if key[0] >= level]  # each now stands in this view
        places = _places(views[level - 1], [state[key][0] for key in moving])
        for key in moving:
            source, escaped = places[state[key][0]]
            state[key] = (source, state[key][1] or escaped)
    return state


def _children(pointer: str, value: Any) -> Iterator[tuple[str, str | None, Any]]:
    """The children of a container as (pointer, key or None, child), made one at a time."""
    if isinstance(value, dict):
        return ((f"{pointer}/{_shown(key)}", key, child) for key, child in value.items())
    return ((f"{pointer}/{index}", None, child) for index, child in enumerate(value))


def _texts(document: Any) -> Iterator[tuple[str, str, str, bool]]:
    """Every text of ``document`` as (pointer, where, text, decoded): each key as it is, each
    value with what its escapes write. Walked without recursion, holding one cursor per level of
    nesting, never the siblings, so that a wide list stays small to walk."""
    cursors: list[Iterator[tuple[str, str | None, Any]]] = [iter((("", None, document),))]
    while cursors:
        entry = next(cursors[-1], None)
        if entry is None:
            cursors.pop()
            continue
        pointer, key, value = entry
        if key is not None:
            yield pointer, " in a key", key, False
        if isinstance(value, dict | list):
            cursors.append(_children(pointer, value))
        elif isinstance(value, str):
            yield pointer, "", value, True


def _shown(key: str) -> str:
    """A key as a pointer segment: bounded, since the finding shortens it anyway, and with every
    hidden, joiner or non-printable character escaped, so that no finding carries one."""
    segment = key[:MESSAGE_LIMIT].replace("~", "~0").replace("/", "~1")
    return "".join(
        repr(c)[1:-1] if c in HIDDEN or c in JOINERS or not c.isprintable() else c for c in segment
    )


def _message(what: str, count: int, first: int, to_do: str = _TO_DO) -> str:
    times = "1 time" if count == 1 else f"{count} times"
    return f"{what}, {times}, first at character {first}: {to_do}"


def _messages(
    text: str, where: str, decoded: bool, written: Collection[str], to_do: str
) -> list[str]:
    """The findings of a text: each hidden character once, whatever view shows it, with the
    larger count of any view and the earliest place in the source (for an escape, where it
    starts), and the escapes still written after the last decoding, if any: all in the order of
    their first place. A character whose label is in ``written`` is left out: the file was
    found holding it as written already."""
    views = _views(text) if decoded else [text]
    found = [{hidden.label: hidden for hidden in hidden_occurrences(view)} for view in views]
    deepest = views[-1] if len(views) > _DECODINGS else ""
    left_matches = _LEFT.finditer(deepest)
    first_left = next(left_matches, None)
    wanted = [(level, hidden.first) for level, view in enumerate(found) for hidden in view.values()]
    if first_left is not None:
        wanted.append((_DECODINGS, first_left.start()))
    sources = _sources(views, wanted)
    characters = _character_messages(found, sources, written, where, to_do)
    if first_left is not None:
        what = f"escape sequence encoded more than {_DECODINGS} levels deep"
        first = sources[(_DECODINGS, first_left.start())][0]
        count = 1 + sum(1 for _ in left_matches)
        fewer = f"encode it fewer times, or {to_do}"
        characters.append((first, what, _message(what, count, first, fewer)))
    return [message for _, _, message in sorted(characters)]


def _character_messages(
    found: list[dict[str, Hidden]],
    sources: dict[tuple[int, int], tuple[int, bool]],
    written: Collection[str],
    where: str,
    to_do: str,
) -> list[tuple[int, str, str]]:
    """Each hidden character ``found`` in a view, once, with its first place in the source, its
    label and its message; those labelled in ``written`` left out."""
    characters = []
    for label in dict.fromkeys(label for view in found for label in view if label not in written):
        seen = [(level, view[label]) for level, view in enumerate(found) if label in view]
        first, by_escape = min(sources[(level, hidden.first)] for level, hidden in seen)
        place = " as an escape" if by_escape and label not in found[0] else where
        what = f"invisible or bidirectional control character {label}{place}"
        count = max(hidden.count for _, hidden in seen)
        characters.append((first, label, _message(what, count, first, to_do)))
    return characters


def _breaks(text: str) -> tuple[Hidden, ...]:
    """The line breaks of ``text`` that YAML reads, ending a comment for instance, while a
    reviewer may not see them, each once with its count and the offset of the first."""
    found: dict[str, list[int]] = {}
    for index, character in enumerate(text):
        if character in _YAML_BREAKS:
            found.setdefault(character, [0, index])[0] += 1
    return tuple(
        Hidden(_name(character), count, first) for character, (count, first) in found.items()
    )


def _name(character: str) -> str:
    code = f"U+{ord(character):04X}"
    name = unicodedata.name(character, "")
    return f"{code} ({name})" if name else code


def text_findings(text: str, path: str, *, breaks: bool = False) -> tuple[Finding, ...]:
    """An ``IO-017`` finding for each hidden character of ``text``, a file a person writes, such
    as Markdown: checked as written, never decoded, since its escapes are text to read; with
    ``breaks``, for YAML, each line break other than ``\\n`` and ``\\r`` too, which YAML reads
    while a reviewer may not see it. Past ``REPORT_LIMIT``, the last finding counts the
    characters left."""
    lines = tuple(
        Finding(
            "IO-017",
            Severity.BLOCKING,
            path,
            "",
            _message(
                f"line break {hidden.label} other than \\n, which YAML reads while a reviewer "
                "may not see it",
                hidden.count,
                hidden.first,
                "remove it from the file",
            ),
        )
        for hidden in (_breaks(text) if breaks else ())
    )
    return lines + _hidden_text_findings(text, path)


def _hidden_text_findings(text: str, path: str) -> tuple[Finding, ...]:
    occurrences = hidden_occurrences(text)
    shown = occurrences if len(occurrences) <= REPORT_LIMIT else occurrences[: REPORT_LIMIT - 1]
    findings = tuple(
        Finding(
            "IO-017",
            Severity.BLOCKING,
            path,
            "",
            _message(
                f"invisible or bidirectional control character {hidden.label}",
                hidden.count,
                hidden.first,
                "remove it from the file",
            ),
        )
        for hidden in shown
    )
    if len(shown) == len(occurrences):
        return findings
    message = f"{len(occurrences) - len(shown)} more hidden characters in the file: remove them"
    return (*findings, Finding("IO-017", Severity.BLOCKING, path, "", message))


def hidden_character_findings(
    document: object,
    path: str,
    *,
    written: Collection[str] = frozenset(),
    to_do: str = _TO_DO,
) -> tuple[Finding, ...]:
    """An ``IO-017`` finding for each hidden character in each text of ``document``, at the
    pointer of its value or key, with its count, never the text, and ``to_do``. A character whose
    label is in ``written`` is left out, the file it was read from being reported as holding it.
    Past ``REPORT_LIMIT``, the last finding counts the texts left, a text cut short included, so
    that a flood of them stays small to report while the first ones are shown."""
    findings: list[Finding] = []
    left = 0
    for pointer, where, text, decoded in _texts(document):
        messages = _messages(text, where, decoded, written, to_do)
        if not messages:
            continue
        room = REPORT_LIMIT - 1 - len(findings)  # never below zero: no more is ever added
        findings.extend(
            Finding("IO-017", Severity.BLOCKING, path, pointer, message)
            for message in messages[:room]
        )
        if len(messages) > room:
            left += 1  # a text cut short, or not reported, is counted in the summary
    if left:
        summary = f"{left} more {'texts hold' if left > 1 else 'text holds'} hidden characters"
        findings.append(Finding("IO-017", Severity.BLOCKING, path, "", summary))
    return tuple(findings)
