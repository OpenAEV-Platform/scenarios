"""A cleanup for every payload with a side effect: an embedded payload that runs or drops a
file, or one of whose commands, arguments or prerequisites writes, creates or starts something,
has a cleanup command, with an executor to run it, that undoes it. Read-only commands need
none."""

from collections.abc import Iterator

from scenario_tools.domain.policy.actions import as_command, runs
from scenario_tools.domain.policy.payloads import (
    CLEANUP,
    COMMAND_LIMIT,
    EXECUTOR,
    TYPE,
    commands,
    effective,
    payloads,
    text,
)
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

# Running a file or dropping one always changes the endpoint, whatever its command says.
_CHANGING_TYPES = frozenset({"Executable", "FileDrop"})
_MESSAGE = (
    "this payload changes the endpoint (it writes, creates or starts something) but has no "
    "cleanup command with an executor: add one that undoes it"
)


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    path = f"{content.directory}/scenario.json"
    for payload in payloads(content.stored):
        if text(payload, CLEANUP).strip() and text(payload, EXECUTOR).strip():
            continue
        resolved = [
            effective(payload, command, COMMAND_LIMIT)
            for _, command, where in commands(payload)
            if where != CLEANUP
        ]
        reads = [as_command(found) for found in resolved if found is not None]  # else too long
        changes = text(payload, TYPE) in _CHANGING_TYPES or any(
            runs(steps, read) for read in reads for steps in data.side_effects
        )
        if changes:
            yield Violation(path, f"{payload.pointer}/{CLEANUP}", _MESSAGE)


RULE = Rule(
    "POL-005",
    Severity.BLOCKING,
    "Every embedded payload that writes, creates or starts something has a cleanup command with "
    "an executor.",
    _check,
)
