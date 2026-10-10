"""Hidden characters anywhere in a scenario: every value and key, and the escapes a value writes
in JSON terms, which the platform turns into characters when it reads a JSON text. Any value
may hold JSON text, so the escapes are looked for in all of them, in the text itself, whatever
its depth, encoding or validity: nothing is decoded here, so no nesting can break the check or
hide a character from it."""

import re
from collections.abc import Iterator
from typing import Any

from scenario_tools.domain.shared.characters import HIDDEN, JOINERS, Hidden, hidden_occurrences
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, REPORT_LIMIT, Finding, Severity

# An escape, possibly after escaped backslashes ("u005c"), each of which takes one more decoding
# to reach it; and the low half of a surrogate pair in the same form.
_LINK = r"\\(?:u005[cC])*u"
_ESCAPE = re.compile(f"{_LINK}([0-9a-fA-F]{{4}})(?:{_LINK}([dD][c-fC-F][0-9a-fA-F]{{2}}))?")
_TO_DO = "remove it on the platform and export the scenario again"
_CHUNK = 4096  # pieces joined at a time, so that a text of many escapes stays small to decode


def _character(match: re.Match[str]) -> str:
    """The character an escape writes, a surrogate pair's whole."""
    code = int(match.group(1), 16)
    if match.group(2) and 0xD800 <= code <= 0xDBFF:
        code = 0x10000 + ((code - 0xD800) << 10) + (int(match.group(2), 16) - 0xDC00)
    return chr(code)


def _decoded(text: str) -> str:
    """``text`` with the escapes it writes turned into the characters a JSON reader would make
    of them, so that a hidden character, or a joiner out of place, is seen in its context.
    Empty when no escape writes a hidden character or a joiner and ``text`` holds no joiner, whose
    context an escape could change: the decoded view would show nothing more. Linear in time and
    in memory: the pieces are joined as they come."""
    chunks: list[str] = []
    pieces: list[str] = []
    candidate = False
    last = 0
    for match in _ESCAPE.finditer(text):
        character = _character(match)
        candidate = candidate or character in HIDDEN or character in JOINERS
        pieces += (text[last : match.start()], character)
        last = match.end()
        if len(pieces) >= _CHUNK:
            chunks.append("".join(pieces))
            pieces.clear()
    if not candidate and JOINERS.isdisjoint(text):
        return ""
    pieces.append(text[last:])
    chunks.append("".join(pieces))
    return "".join(chunks)


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


def _texts(document: Any) -> Iterator[tuple[str, str, str, str]]:
    """Every text of ``document`` as (pointer, where, text, decoded), walked without recursion:
    each value with the characters its escapes write, each key as it is."""
    stack: list[tuple[str, Any]] = [("", document)]
    while stack:
        pointer, value = stack.pop()
        if isinstance(value, dict):
            for key, child in reversed(value.items()):
                child_pointer = f"{pointer}/{_shown(key)}"
                yield child_pointer, " in a key", key, ""
                stack.append((child_pointer, child))
        elif isinstance(value, list):
            stack.extend(
                (f"{pointer}/{index}", child) for index, child in reversed(list(enumerate(value)))
            )
        elif isinstance(value, str):
            yield pointer, "", value, _decoded(value)


def _shown(key: str) -> str:
    """A key as a pointer segment: bounded, since the finding shortens it anyway, and with every
    hidden, joiner or non-printable character escaped, so that no finding carries one."""
    segment = key[:MESSAGE_LIMIT].replace("~", "~0").replace("/", "~1")
    return "".join(
        repr(c)[1:-1] if c in HIDDEN or c in JOINERS or not c.isprintable() else c for c in segment
    )


def _message(hidden: Hidden, where: str) -> str:
    times = "1 time" if hidden.count == 1 else f"{hidden.count} times"
    what = f"invisible or bidirectional control character {hidden.label}{where}"
    return f"{what}, {times}, first at character {hidden.first}: {_TO_DO}"


def _merged(text: str, decoded: str, where: str) -> list[tuple[Hidden, str]]:
    """The hidden characters of a text and where they show: the decoded view holds the raw
    characters too, so its count is the whole count, and its first occurrence may be an escape
    before the first raw one; a character only the decoded view holds came from an escape, or
    stands out of place only once its neighbours are decoded. An escape's place is where it
    starts in the source."""
    raw = {hidden.label: hidden for hidden in hidden_occurrences(text)}
    escaped = {hidden.label: hidden for hidden in hidden_occurrences(decoded)}
    places = _places(text, [hidden.first for hidden in escaped.values()])
    merged = []
    for label in [*raw, *(label for label in escaped if label not in raw)]:
        if label in raw:
            count, first = raw[label].count, raw[label].first
            if label in escaped:
                count = escaped[label].count
                first = min(first, places[escaped[label].first][0])
            merged.append((Hidden(label, count, first), where))
        else:
            first, by_escape = places[escaped[label].first]
            merged.append(
                (
                    Hidden(label, escaped[label].count, first),
                    " as an escape" if by_escape else where,
                )
            )
    return merged


def hidden_character_findings(document: object, path: str) -> tuple[Finding, ...]:
    """An ``IO-017`` finding for each hidden character in each text of ``document``, at the
    pointer of its value or key, with its count, never the text. Past ``REPORT_LIMIT``, the last
    finding counts the texts left, so that a flood of them stays small to report."""
    findings: list[Finding] = []
    left = 0
    for pointer, where, text, decoded in _texts(document):
        occurrences = _merged(text, decoded, where)
        if not occurrences:
            continue
        if left or len(findings) + len(occurrences) > REPORT_LIMIT - 1:
            left += 1  # a text is reported whole or counted in the summary
            continue
        findings.extend(
            Finding("IO-017", Severity.BLOCKING, path, pointer, _message(hidden, place))
            for hidden, place in occurrences
        )
    if left:
        summary = f"{left} more {'texts hold' if left > 1 else 'text holds'} hidden characters"
        findings.append(Finding("IO-017", Severity.BLOCKING, path, "", summary))
    return tuple(findings)
