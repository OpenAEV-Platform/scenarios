"""Privileges for the reviewer: an embedded payload that asks for elevated privileges is
pointed out, never refused, so that the reviewer checks why it needs them."""

from collections.abc import Iterator

from scenario_tools.domain.policy.payloads import payloads
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

_ELEVATION = "payload_elevation_required"


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    path = f"{content.directory}/scenario.json"
    for payload in payloads(content.stored):
        if payload.fields.get(_ELEVATION) is True:
            yield Violation(
                path,
                f"{payload.pointer}/{_ELEVATION}",
                "this payload asks for elevated privileges: check why it needs them",
            )


RULE = Rule(
    "POL-007",
    Severity.INFO,
    "An embedded payload that asks for elevated privileges is pointed out to the reviewer.",
    _check,
)
