"""No internal data: a shared scenario carries no user record, no team member and no variable
value, which normalisation removes, and no e-mail address whose domain is not an example name,
in any of its values. A refused address is never quoted."""

import re
import unicodedata
from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

# An e-mail address: a local part, an "@", and a domain of labels ending in a letter top-level
# name. Bounded, so that the search stays linear.
# A local part, an "@", and a domain of labels ending in a top-level name of letters or an
# "xn--" A-label, so that a version or a git URL (user@1.2.3, git@host:path) is not read as an
# address while an internationalised domain is. The whole domain is captured, up to its top-level
# name, so that a real tail is never left out. An internationalised domain in its raw (U-label)
# form is left to the human review.
_EMAIL = re.compile(
    r"[\w.+-]{1,64}@((?:[a-z0-9-]{1,63}\.){1,32}(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59}))\.?"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_DOTS = str.maketrans(dict.fromkeys((chr(0x3002), chr(0xFF61), chr(0xFF0E)), "."))  # full stops
_EMAIL_MESSAGE = (
    "this value holds an e-mail address outside the example domains: use one such as "
    "user@example.com"
)
_EMPTIED = (
    ("scenario_users", None, "the scenario holds users"),
    ("scenario_teams", "team_users", "this team holds members"),
    ("scenario_variables", "variable_value", "this variable holds a value"),
)


def _as_read(raw: str) -> str:
    """``raw`` folded as a tool reads a domain: compatibility forms, invisible characters dropped,
    and the full stops an IDNA tool accepts turned into ``.``."""
    folded = unicodedata.normalize(
        "NFKC", "".join(c for c in raw if unicodedata.category(c) != "Cf")
    )
    return folded.translate(_DOTS)


def _texts(value: object, pointer: str) -> Iterator[tuple[str, str]]:
    """Every string of ``value`` to read for an address, with the pointer to report it at: a value
    at its own pointer, a key at the pointer of the object that holds it, so the key, which may be
    an address, is never put in a finding's field."""
    if isinstance(value, str):
        yield pointer, value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            yield pointer, str(key)
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from _texts(child, f"{pointer}/{escaped}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _texts(child, f"{pointer}/{index}")


def _addresses(stored: object, allowed: Any, path: str) -> Iterator[Violation]:
    for field, raw in _texts(stored, ""):
        text = _as_read(raw)
        for match in _EMAIL.finditer(text):
            if not allowed.example_domain(match[1]):
                yield Violation(path, field, _EMAIL_MESSAGE)
                break


def _records(stored: Mapping[str, Any], path: str) -> Iterator[Violation]:
    for part, inner, message in _EMPTIED:
        items = stored.get(part)
        if not isinstance(items, list):
            continue
        if inner is None:
            if items:
                yield Violation(
                    path, f"/{part}", f"{message}: normalise the export again, which removes them"
                )
            continue
        for index, item in enumerate(items):
            value = item.get(inner) if isinstance(item, Mapping) else None
            if value:
                yield Violation(
                    path,
                    f"/{part}/{index}/{inner}",
                    f"{message}: normalise the export again, which removes them",
                )


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    path = f"{content.directory}/scenario.json"
    yield from _addresses(content.stored, data.targets, path)
    if isinstance(content.stored, Mapping):
        yield from _records(content.stored, path)


RULE = Rule(
    "POL-010",
    Severity.BLOCKING,
    "A shared scenario holds no user, team member, variable value or e-mail address of a real "
    "domain.",
    _check,
)
