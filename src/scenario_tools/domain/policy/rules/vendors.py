"""Vendor-neutral payloads: an embedded payload's commands, with their arguments' values in
place, its name and its output parsers never name a security product, since a shared scenario
emulates an attacker's behaviour whatever product defends the endpoint. The message never names
the product."""

from collections.abc import Iterator

from scenario_tools.domain.policy.actions import as_command
from scenario_tools.domain.policy.payloads import (
    COMMAND_LIMIT,
    commands,
    effective,
    payloads,
    strings,
)
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

_MESSAGE = (
    "this text names a security product: a shared scenario stays vendor-neutral; describe the "
    "behaviour instead"
)
_DESCRIBED = ("payload_name", "payload_output_parsers")


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    path = f"{content.directory}/scenario.json"
    for payload in payloads(content.stored):
        texts = [
            (field, effective(payload, command, COMMAND_LIMIT))
            for field, command, _ in commands(payload)
        ]
        for key in _DESCRIBED:
            texts += strings(payload.fields.get(key), f"{payload.pointer}/{key}")
        for field, text in texts:
            if text is not None and data.vendors.search(as_command(text)):
                yield Violation(path, field, _MESSAGE)


RULE = Rule(
    "POL-006",
    Severity.BLOCKING,
    "No embedded payload names a security product in its commands, its name or its output parsers.",
    _check,
)
