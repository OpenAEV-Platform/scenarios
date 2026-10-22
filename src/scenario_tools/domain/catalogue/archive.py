"""What keeps a stored scenario out of an import archive, until the archive can carry it.

The archive holds the reviewed ``scenario.json`` as it is, so it never changes content to make
it importable, and it fails closed: a part a normalised scenario never has is refused, since the
importer reads other parts too (an exercise set, a workflow whose steps rebuild payloads). A
payload outside the contract of an inject or a step is refused, since no payload reference can
name it; the payloads of the injects and steps are checked against their references. A
recurrence is the policy's matter, which the archive also asks.
"""

from collections.abc import Iterator
from typing import Any

from scenario_tools.domain.catalogue.identifiers import scenario_namespace, stable_id
from scenario_tools.domain.catalogue.normalisation import NOT_SUPPORTED
from scenario_tools.domain.catalogue.structure import (
    CONTRACT,
    INFORMATION,
    PAYLOAD,
    checked_injects,
    not_an_export,
    require_object,
)
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.stored import INJECTS, WORKFLOW, injects

# The parts of a normalised scenario, which are all an archive may carry.
STORED_PARTS = frozenset(
    {
        "export_version",
        INFORMATION,
        INJECTS,
        "scenario_articles",
        "scenario_challenges",
        "scenario_channels",
        "scenario_documents",
        "scenario_organizations",
        "scenario_tags",
        "scenario_teams",
        "scenario_users",
        "scenario_variables",
    }
)
# Parts normalisation refuses unless empty, and then leaves in place; a workflow is carried once
# its steps are checked here too.
_LEFT_EMPTY = frozenset(part for part, _ in NOT_SUPPORTED) | {WORKFLOW}


def _objects(value: Any, pointer: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    """Every object inside ``value``, with its JSON pointer."""
    if isinstance(value, dict):
        yield pointer, value
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            yield from _objects(child, f"{pointer}/{escaped}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _objects(child, f"{pointer}/{index}")


def archive_findings(document: object, path: str) -> tuple[Finding, ...]:
    """The blocking findings that keep the scenario at ``path`` out of an import archive."""
    export = require_object(document, "the export")
    for part in sorted(set(export) - STORED_PARTS):
        if part in _LEFT_EMPTY and export[part] in (None, [], {}):
            continue  # normalisation leaves these parts in place when empty; others are refused
        raise not_an_export(f"{part} is not a part of a stored scenario")
    require_object(export.get(INFORMATION), INFORMATION)
    for found in checked_injects(export):
        contract = found.inject.get(CONTRACT)
        if contract is not None:
            require_object(contract, CONTRACT)
    return payloads_outside_contracts(export, path)


def payloads_outside_contracts(document: object, path: str) -> tuple[Finding, ...]:
    """The payloads of ``document``, at ``path``, that sit outside an inject's or a step's
    contract: no payload reference can name them, and the importer may read them still."""
    contracts = {f"{found.pointer}/{CONTRACT}" for found in injects(document)}
    return tuple(
        Finding(
            "PAY-004",
            Severity.BLOCKING,
            path,
            pointer,
            "the document embeds a payload outside an inject's or a step's contract: no reference "
            "can name it, and the archive cannot carry it",
        )
        for pointer, item in _objects(document)
        if item.get(PAYLOAD) not in (None, {}) and pointer not in contracts
    )


def belongs_to(document: object, external_id: str) -> bool:
    """Whether the stored scenario is the one of the entry with this external ID: its scenario
    identifier derives from it."""
    information = document.get(INFORMATION) if isinstance(document, dict) else None
    if not isinstance(information, dict):
        return False
    expected = stable_id(scenario_namespace(external_id), "scenario", external_id)
    return bool(information.get("scenario_id") == expected)
