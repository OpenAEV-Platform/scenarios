"""What keeps a stored scenario out of an import archive, until the archive can carry it.

The archive holds the reviewed ``scenario.json`` as it is, so it never changes content to make
it importable, and it fails closed: a part a normalised scenario never has is refused, since the
importer reads other parts too (an exercise set, a workflow whose steps rebuild payloads). A
payload anywhere in the document is refused, until a payload reference names the payload whose
ID the archive must set. A recurrence is the policy's matter, which the archive also asks.
"""

from collections.abc import Iterator
from typing import Any

from scenario_tools.domain.catalogue.identifiers import scenario_namespace, stable_id
from scenario_tools.domain.catalogue.normalisation import NOT_SUPPORTED
from scenario_tools.domain.catalogue.structure import (
    CONTRACT,
    INFORMATION,
    INJECTS,
    PAYLOAD,
    not_an_export,
    require_object,
)
from scenario_tools.domain.shared.finding import Finding, Severity

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
# Parts normalisation refuses unless empty, and then leaves in place.
_LEFT_EMPTY = frozenset(part for part, _ in NOT_SUPPORTED)


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
            continue  # normalisation leaves these parts in place, empty; a scalar stays as it is
        raise not_an_export(f"{part} is not a part of a stored scenario")
    require_object(export.get(INFORMATION), INFORMATION)
    injects = export.get(INJECTS)
    if not isinstance(injects, list):
        raise not_an_export(f"{INJECTS} must be a list")
    for inject in injects:
        contract = require_object(inject, INJECTS).get(CONTRACT)
        if contract is not None:
            require_object(contract, CONTRACT)
    return tuple(
        Finding(
            "PAY-004",
            Severity.BLOCKING,
            path,
            pointer,
            "the document embeds a payload here: the archive cannot carry it until payload "
            "references name their payloads",
        )
        for pointer, item in _objects(export)
        if item.get(PAYLOAD) not in (None, {})
    )


def belongs_to(document: object, external_id: str) -> bool:
    """Whether the stored scenario is the one of the entry with this external ID: its scenario
    identifier derives from it."""
    information = document.get(INFORMATION) if isinstance(document, dict) else None
    if not isinstance(information, dict):
        return False
    expected = stable_id(scenario_namespace(external_id), "scenario", external_id)
    return bool(information.get("scenario_id") == expected)
