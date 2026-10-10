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

_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})(?:\\u([dD][c-fC-F][0-9a-fA-F]{2}))?")
_ESCAPED_BACKSLASH = re.compile(r"\\u005[cC]")
_TO_DO = "remove it on the platform and export the scenario again"


def _texts(document: Any) -> Iterator[tuple[str, str, str]]:
    """Every text of ``document`` as (pointer, where, text), walked without recursion: each
    value as it is and as the escapes it writes, each key as it is."""
    stack: list[tuple[str, Any]] = [("", document)]
    while stack:
        pointer, value = stack.pop()
        if isinstance(value, dict):
            for key, child in reversed(value.items()):
                child_pointer = f"{pointer}/{_shown(key)}"
                yield child_pointer, " in a key", key
                stack.append((child_pointer, child))
        elif isinstance(value, list):
            stack.extend(
                (f"{pointer}/{index}", child) for index, child in reversed(list(enumerate(value)))
            )
        elif isinstance(value, str):
            yield pointer, "", value
            yield pointer, " as an escape", _unescaped(value)


def _shown(key: str) -> str:
    """A key as a pointer segment: bounded, since the finding shortens it anyway, and with every
    hidden, joiner or non-printable character escaped, so that no finding carries one."""
    segment = key[:MESSAGE_LIMIT].replace("~", "~0").replace("/", "~1")
    return "".join(
        repr(c)[1:-1] if c in HIDDEN or c in JOINERS or not c.isprintable() else c for c in segment
    )


def _unescaped(text: str) -> str:
    """The hidden characters a text writes as escapes. An escaped backslash before an escape
    (two decodings away) is followed down to the character."""
    while (reduced := _ESCAPED_BACKSLASH.sub(lambda _: "\\", text)) != text:
        text = reduced
    found = []
    for match in _ESCAPE.finditer(text):
        code = int(match.group(1), 16)
        if match.group(2) and 0xD800 <= code <= 0xDBFF:
            code = 0x10000 + ((code - 0xD800) << 10) + (int(match.group(2), 16) - 0xDC00)
        if chr(code) in HIDDEN:
            found.append(chr(code))
    return "".join(found)


def _message(hidden: Hidden, where: str) -> str:
    times = "1 time" if hidden.count == 1 else f"{hidden.count} times"
    first = "" if where else f", first at character {hidden.first}"
    what = f"invisible or bidirectional control character {hidden.label}{where}"
    return f"{what}, {times}{first}: {_TO_DO}"


def hidden_character_findings(document: object, path: str) -> tuple[Finding, ...]:
    """An ``IO-017`` finding for each hidden character in each text of ``document``, at the
    pointer of its value or key, with its count, never the text. Past ``REPORT_LIMIT``, the last
    finding counts the texts left, so that a flood of them stays small to report."""
    findings: list[Finding] = []
    left = 0
    for pointer, where, text in _texts(document):
        occurrences = hidden_occurrences(text)
        if not occurrences:
            continue
        if left or len(findings) + len(occurrences) > REPORT_LIMIT - 1:
            left += 1  # a text is reported whole or counted in the summary
            continue
        findings.extend(
            Finding("IO-017", Severity.BLOCKING, path, pointer, _message(hidden, where))
            for hidden in occurrences
        )
    if left:
        summary = f"{left} more {'texts hold' if left > 1 else 'text holds'} hidden characters"
        findings.append(Finding("IO-017", Severity.BLOCKING, path, "", summary))
    return tuple(findings)
