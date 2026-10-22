"""No forbidden action: an embedded payload never destroys data or what restores it, never
encrypts data for real, and removes a protection only when its cleanup command restores it.
Every command a payload runs is read: the command, the cleanup command, the arguments' default
values and the prerequisites. The message gives the maintainers' reason, never the command."""

from collections.abc import Iterator

from scenario_tools.domain.policy.actions import as_command, starts, takes
from scenario_tools.domain.policy.payloads import (
    CLEANUP,
    COMMAND_LIMIT,
    EXECUTOR,
    Payload,
    argument_values,
    commands,
    payloads,
    substituted,
    text,
)
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

_TOO_LONG = (
    f"this command is longer than {COMMAND_LIMIT} characters, its arguments given, too long to "
    "check: shorten it"
)


def _runs(payload: Payload) -> bool:
    """Whether the payload has a cleanup command and an executor to run it."""
    return bool(text(payload, CLEANUP).strip() and text(payload, EXECUTOR).strip())


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    path = f"{content.directory}/scenario.json"
    for payload in payloads(content.stored):
        values = argument_values(payload)  # once, however many commands it has
        cleanup = substituted(text(payload, CLEANUP), values, COMMAND_LIMIT)
        runs = _runs(payload)
        restored = None if cleanup is None else as_command(cleanup)
        for field, command, where in commands(payload):
            resolved = substituted(command, values, COMMAND_LIMIT)
            if resolved is None:
                yield Violation(path, field, _TOO_LONG)
                continue
            read = as_command(resolved)
            for action in data.forbidden:
                if not takes(action.steps, read):
                    continue
                if (
                    action.restore is not None
                    and where != CLEANUP  # a cleanup never removes a protection
                    and runs
                    and restored is not None
                    and starts(action.restore, restored)
                ):
                    continue
                yield Violation(
                    path,
                    field,
                    f"this command {action.why}, which a shared scenario never does: remove it",
                )
                break


RULE = Rule(
    "POL-004",
    Severity.BLOCKING,
    "No embedded payload takes a forbidden action: destructive or irreversible, real encryption, "
    "or the removal of a protection its cleanup command does not restore.",
    _check,
)
