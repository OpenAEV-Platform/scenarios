"""No internal data: a shared scenario carries no user record, no team member and no variable
value, which normalisation removes, and no e-mail address whose domain is not an example name,
in any of its values. A refused address is never quoted."""

import re
import unicodedata
from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.policy.payloads import strings
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

# An e-mail address: a local part, an "@", and a domain of labels ending in a letter top-level
# name. Bounded, so that the search stays linear.
# A local part, an "@", and a domain of labels ending in a top-level name of letters, so that a
# version or a git URL (user@1.2.3, git@host:path) is not read as an address. The whole domain
# is captured, up to its alphabetic top-level name, so that a real tail is never left out.
_EMAIL = re.compile(
    r"[\w.+-]{1,64}@((?:[a-z0-9-]{1,63}\.){1,32}[a-z]{2,24})(?![\w.-])", re.IGNORECASE
)
_EMAIL_MESSAGE = (
    "this value holds an e-mail address outside the example domains: use one such as "
    "user@example.com"
)
_EMPTIED = (
    ("scenario_users", None, "the scenario holds users"),
    ("scenario_teams", "team_users", "this team holds members"),
    ("scenario_variables", "variable_value", "this variable holds a value"),
)


def _addresses(stored: object, allowed: Any, path: str) -> Iterator[Violation]:
    for field, raw in strings(stored, ""):
        text = unicodedata.normalize(
            "NFKC", "".join(c for c in raw if unicodedata.category(c) != "Cf")
        )
        for match in _EMAIL.finditer(text):
            if not allowed.allows(match[1]):
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
