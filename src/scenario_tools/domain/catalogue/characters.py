"""Hidden characters anywhere in a scenario: every value and key, and the escapes a value writes
in JSON terms, which the platform turns into characters when it reads a JSON text. Any value
may hold JSON text, so the escapes are looked for in all of them, in the text itself, whatever
its depth, encoding or validity: nothing is decoded here, so no nesting can break the check or
hide a character from it."""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from scenario_tools.domain.shared.characters import HIDDEN, JOINERS, Hidden, hidden_occurrences
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, REPORT_LIMIT, Finding, Severity

# An escape, possibly after escaped backslashes ("u005c"), each of which takes one more decoding
# to reach it; and the low half of a surrogate pair in the same form.
_LINK = r"\\(?:u005[cC])*u"
_ESCAPE = re.compile(f"{_LINK}([0-9a-fA-F]{{4}})(?:{_LINK}([dD][c-fC-F][0-9a-fA-F]{{2}}))?")
_TO_DO = "remove it on the platform and export the scenario again"


@dataclass(frozen=True)
class Decoded:
    """A text with the escapes it writes turned into the characters a JSON reader would make of
    them, and where each such character's escape starts in the source text."""

    text: str
    sources: Mapping[int, int]  # decoded index of an escaped character -> its source index


_NOTHING = Decoded("", MappingProxyType({}))


def _decoded(text: str) -> Decoded:
    """The decoded view of ``text``, so that a hidden character, or a joiner out of place, is
    seen in its context; empty when ``text`` writes no escape. Linear in the text's length."""
    pieces: list[str] = []
    sources: dict[int, int] = {}
    decoded = 0
    last = 0
    for match in _ESCAPE.finditer(text):
        pieces.append(text[last : match.start()])
        decoded += match.start() - last
        code = int(match.group(1), 16)
        if match.group(2) and 0xD800 <= code <= 0xDBFF:
            code = 0x10000 + ((code - 0xD800) << 10) + (int(match.group(2), 16) - 0xDC00)
        pieces.append(chr(code))
        sources[decoded] = match.start()
        decoded += 1
        last = match.end()
    if not sources:
        return _NOTHING
    pieces.append(text[last:])
    return Decoded("".join(pieces), MappingProxyType(sources))


def _texts(document: Any) -> Iterator[tuple[str, str, str, Decoded]]:
    """Every text of ``document`` as (pointer, where, text, decoded), walked without recursion:
    each value with the characters its escapes write, each key as it is."""
    stack: list[tuple[str, Any]] = [("", document)]
    while stack:
        pointer, value = stack.pop()
        if isinstance(value, dict):
            for key, child in reversed(value.items()):
                child_pointer = f"{pointer}/{_shown(key)}"
                yield child_pointer, " in a key", key, _NOTHING
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


def _merged(text: str, decoded: Decoded, where: str) -> list[tuple[Hidden, str]]:
    """The hidden characters of a text and where they show: the decoded view holds the raw
    characters too, so its count is the whole count, and its first occurrence may be an escape
    before the first raw one; a character only the decoded view holds came from an escape. An
    escape's place is where it starts in the source."""
    raw = {hidden.label: hidden for hidden in hidden_occurrences(text)}
    escaped = {hidden.label: hidden for hidden in hidden_occurrences(decoded.text)}
    merged = []
    for label in [*raw, *(label for label in escaped if label not in raw)]:
        if label in raw:
            count, first = raw[label].count, raw[label].first
            if label in escaped:
                count = escaped[label].count
                # An escape may come first: its place in the source is earlier than the raw one.
                first = min(first, decoded.sources.get(escaped[label].first, first))
            merged.append((Hidden(label, count, first), where))
        else:
            # Only an escape writes it, so its first occurrence is an escape's character.
            first = decoded.sources[escaped[label].first]
            merged.append((Hidden(label, escaped[label].count, first), " as an escape"))
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
