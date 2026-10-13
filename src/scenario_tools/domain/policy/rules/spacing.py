"""Spacing of the injects that run on an endpoint: in a time-based scenario, two consecutive
injects that embed a payload, ordered by their offset, are at least 60 seconds apart; less than
120 seconds before a heavy payload (an executable, a dropped file or one with prerequisites) is
pointed out to the reviewer. An inject that runs on the platform, with no payload, is not
counted, and the scenario's kind is read from its metadata, never from the export."""

import itertools
from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.catalogue.structure import CONTRACT, INJECTS, PAYLOAD
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.shared.finding import Severity

_OFFSET = "inject_depends_duration"
_HEAVY_TYPES = frozenset({"Executable", "FileDrop"})
_MINIMUM = 60
_HEAVY_MINIMUM = 120


def _payload(inject: Mapping[str, Any]) -> Mapping[str, Any] | None:
    contract = inject.get(CONTRACT)
    payload = contract.get(PAYLOAD) if isinstance(contract, Mapping) else None
    return payload if isinstance(payload, Mapping) else None


def _heavy(payload: Mapping[str, Any]) -> bool:
    return payload.get("payload_type") in _HEAVY_TYPES or bool(payload.get("payload_prerequisites"))


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    declared = content.declared
    if not isinstance(declared, Mapping) or declared.get("type") != "time-based":
        return
    stored = content.stored
    injects = stored.get(INJECTS) if isinstance(stored, Mapping) else None
    if not isinstance(injects, list):
        return
    path = f"{content.directory}/scenario.json"
    running: list[tuple[int, int, Mapping[str, Any]]] = []
    for index, inject in enumerate(injects):
        if not isinstance(inject, Mapping):
            continue
        payload = _payload(inject)
        if payload is None:  # an inject that runs on the platform, not on an endpoint
            continue
        offset = inject.get(_OFFSET)
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            yield Violation(
                path,
                f"/{INJECTS}/{index}/{_OFFSET}",
                "this inject runs on the endpoint but its start is not a whole number of "
                "seconds: give a non-negative integer",
            )
            continue
        running.append((index, offset, payload))
    running.sort(key=lambda item: item[1])
    for (_, previous, _), (index, offset, payload) in itertools.pairwise(running):
        gap = offset - previous
        if gap < _MINIMUM:
            yield Violation(
                path,
                f"/{INJECTS}/{index}/{_OFFSET}",
                f"this inject starts {gap} seconds after the previous one that runs on the "
                f"endpoint: space them by at least {_MINIMUM} seconds",
            )
        elif gap < _HEAVY_MINIMUM and _heavy(payload):
            yield Violation(
                path,
                f"/{INJECTS}/{index}/{_OFFSET}",
                f"this inject starts {gap} seconds after the previous one that runs on the "
                f"endpoint: space them by at least {_HEAVY_MINIMUM} seconds",
                Severity.INFO,
            )


RULE = Rule(
    "POL-009",
    Severity.BLOCKING,
    "Injects that run on an endpoint are at least 60 seconds apart in a time-based scenario.",
    _check,
)
