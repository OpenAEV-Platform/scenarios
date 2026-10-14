"""Justified exceptions. The maintainers' registry, ``policy/data/exceptions.yaml``, lets a
blocking finding of a few rules through as information, for one field of an entry's scenario as
it is, with the reason why: a legitimate new attack is never blocked without recourse, and every
exception stays in one reviewed file. An exception names the ``scenario.json`` it was granted for,
what the scenario runs, by its hash, so that a payload changed under it blocks again until the
maintainers review the change; a change to ``scenario.yaml`` alone keeps it. Only the rules a
new attack may need to breach can be excepted; the sources, the recurrence, the allowed targets
and internal data never can."""

import re
from collections.abc import Mapping
from dataclasses import dataclass

from scenario_tools.domain.shared.finding import MESSAGE_LIMIT

EXCEPTABLE = frozenset({"POL-004", "POL-005", "POL-006", "POL-009"})
REGISTRY = "policy/data/exceptions.yaml"

_KEYS = frozenset({"entry", "code", "field", "sha256", "justification"})
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REASON = (20, 200)  # the fewest and the most characters of a justification


def _is_pointer(field: object) -> bool:
    """A pointer a finding reports whole: at most as long as a finding keeps one."""
    return (
        isinstance(field, str)
        and (field == "" or field.startswith("/"))
        and len(field) <= MESSAGE_LIMIT
        and field.isprintable()
    )


def _is_reason(text: object) -> bool:
    shortest, longest = _REASON
    return (
        isinstance(text, str)
        and shortest <= len(text.strip())
        and len(text) <= longest
        and text.isprintable()
    )


@dataclass(frozen=True)
class PolicyException:
    """A breach the maintainers accept: the entry, by its external ID, the rule's code, the
    field of the finding in ``scenario.json``, the hash of the ``scenario.json`` it was granted
    for, and why. Checked when built, so that none exists the registry would refuse."""

    entry: str
    code: str
    field: str
    sha256: str
    justification: str

    def __post_init__(self) -> None:
        if not isinstance(self.entry, str) or not _UUID.fullmatch(self.entry):
            raise ValueError("an entry is the external ID of a scenario, a UUID in lower case")
        if not isinstance(self.code, str) or self.code not in EXCEPTABLE:
            raise ValueError(f"a code is one of {', '.join(sorted(EXCEPTABLE))}")
        if not _is_pointer(self.field):
            raise ValueError("a field is the JSON pointer a finding reports in scenario.json")
        if not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ValueError("a sha256 is the hash of the entry's scenario.json, in lower case")
        if not _is_reason(self.justification):
            raise ValueError("a justification says why, in one line of 20 to 200 characters")


def _exception(item: object, found: list[PolicyException]) -> PolicyException:
    if not isinstance(item, Mapping) or set(item) != _KEYS:
        raise ValueError("an exception is an entry, a code, a field, a sha256 and a justification")
    exception = PolicyException(
        item["entry"], item["code"], item["field"], item["sha256"], item["justification"]
    )
    if any(
        (other.entry, other.code, other.field) == (exception.entry, exception.code, exception.field)
        for other in found
    ):
        raise ValueError("each entry, code and field once")
    return exception


def exceptions_from_document(document: object) -> tuple[PolicyException, ...]:
    """Read the exceptions data document: each exception an entry, a code, a field, a sha256 and
    a justification, each entry, code and field once; a refusal names the exception by its
    position."""
    if not isinstance(document, Mapping) or not isinstance(document.get("exceptions"), list):
        raise ValueError("exceptions: the document must be a mapping holding exceptions")
    unknown = sorted(str(key) for key in document if key != "exceptions")
    if unknown:
        raise ValueError(f"exceptions: unknown keys {', '.join(unknown)}")
    found: list[PolicyException] = []
    for index, item in enumerate(document["exceptions"]):
        try:
            found.append(_exception(item, found))
        except ValueError as error:
            raise ValueError(f"exceptions: #{index}: {error}") from error
    return tuple(found)
