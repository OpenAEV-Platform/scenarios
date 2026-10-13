"""The embedded payloads of a stored scenario and the commands they run, with their pointers:
the command, the cleanup command, each argument's default value and the value the inject gives
it, and each prerequisite's commands. A part not shaped as a payload is left to its own
check."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.structure import CONTRACT, INJECTS, PAYLOAD

COMMAND = "command_content"
CLEANUP = "payload_cleanup_command"
_ARGUMENTS = "payload_arguments"
_PREREQUISITES = "payload_prerequisites"
GET = "get_command"
CHECK = "check_command"
ARGUMENT = "argument"
TYPE = "payload_type"
EXECUTOR = "payload_cleanup_executor"
_CONTENT = "inject_content"


@dataclass(frozen=True)
class Payload:
    """An embedded payload: its pointer, its fields, and the values the inject gives to its
    arguments, with the pointer of the inject's content."""

    pointer: str
    fields: Mapping[str, Any]
    given: Mapping[str, Any]
    given_pointer: str


def payloads(stored: object) -> Iterator[Payload]:
    """Every embedded payload."""
    injects = stored.get(INJECTS) if isinstance(stored, Mapping) else None
    if not isinstance(injects, list):
        return
    for index, inject in enumerate(injects):
        if not isinstance(inject, Mapping):
            continue
        contract = inject.get(CONTRACT)
        payload = contract.get(PAYLOAD) if isinstance(contract, Mapping) else None
        if isinstance(payload, Mapping):
            given = inject.get(_CONTENT)
            yield Payload(
                f"/{INJECTS}/{index}/{CONTRACT}/{PAYLOAD}",
                payload,
                given if isinstance(given, Mapping) else {},
                f"/{INJECTS}/{index}/{_CONTENT}",
            )


def text(payload: Payload, key: str) -> str:
    """The text ``key`` of ``payload``, empty when it has none."""
    value = payload.fields.get(key)
    return value if isinstance(value, str) else ""


def _escaped(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def commands(payload: Payload) -> Iterator[tuple[str, str, str]]:
    """Every command text of ``payload``: its pointer, the text and where it is (``COMMAND``,
    ``CLEANUP``, ``GET`` or ``CHECK`` for a prerequisite, ``ARGUMENT`` for an argument's
    default value or the value the inject gives it)."""
    fields, pointer = payload.fields, payload.pointer
    for key in (COMMAND, CLEANUP):
        if isinstance(fields.get(key), str):
            yield f"{pointer}/{key}", fields[key], key
    arguments = fields.get(_ARGUMENTS)
    names: set[str] = set()
    if isinstance(arguments, list):
        for index, argument in enumerate(arguments):
            if not isinstance(argument, Mapping):
                continue
            if isinstance(argument.get("key"), str):
                names.add(argument["key"].strip())
            if isinstance(argument.get("default_value"), str):
                where = f"{pointer}/{_ARGUMENTS}/{index}/default_value"
                yield where, argument["default_value"], ARGUMENT
    for key, value in payload.given.items():
        if str(key).strip() in names and isinstance(value, str):
            yield f"{payload.given_pointer}/{_escaped(str(key))}", value, ARGUMENT
    prerequisites = fields.get(_PREREQUISITES)
    if isinstance(prerequisites, list):
        for index, prerequisite in enumerate(prerequisites):
            if isinstance(prerequisite, Mapping):
                for key in (GET, CHECK):
                    if isinstance(prerequisite.get(key), str):
                        where = f"{pointer}/{_PREREQUISITES}/{index}/{key}"
                        yield where, prerequisite[key], key
