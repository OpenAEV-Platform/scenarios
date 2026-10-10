"""Preparing an entry: the export, normalised with the rules kept as data, in stored form."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.catalogue.facts import BuiltinContracts, export_facts
from scenario_tools.domain.catalogue.identifiers import (
    InjectMatchingError,
    InvalidInjectMappingError,
)
from scenario_tools.domain.catalogue.metadata import starting_metadata
from scenario_tools.domain.catalogue.normalisation import (
    ExportStructureError,
    NormalisationRules,
    normalise,
)
from scenario_tools.domain.catalogue.structure import INFORMATION
from scenario_tools.domain.shared.canonical import stored_form, stored_size
from scenario_tools.domain.shared.finding import Finding
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

VOLATILE_FIELDS = "volatile-fields"
BUILTIN_CONTRACTS = "builtin-contracts"
# The stored form indents by depth, so a small export can give a much larger file: it is bounded
# like a JSON input.
MAX_STORED_SIZE = 20 * 1024 * 1024


@dataclass(frozen=True)
class PreparedEntry:
    """The stored form, the injects the previous version had and the export lost, and, on a
    first preparation, the starting ``scenario.yaml`` and what is left to complete in it."""

    scenario_json: bytes
    removed_injects: tuple[str, ...]
    metadata: dict[str, object] | None = None
    to_complete: tuple[Finding, ...] = ()
    # Hidden characters in the normalised form: when there is one, nothing is to be written.
    refusals: tuple[Finding, ...] = ()


def prepare_entry(
    export: Any,
    external_id: str,
    data: DataLoader,
    *,
    path: str,
    previous: object = None,
    previous_path: str | None = None,
    mapping: Mapping[str, str] | None = None,
    mapping_path: str | None = None,
    start_at: str | None = None,
) -> PreparedEntry:
    """Normalise the export read from ``path`` for the entry ``external_id``, and, on a first
    preparation, start its ``scenario.yaml``, reported at ``start_at``: both are established
    before anything is written. A refusal names its code and the file at fault, like any
    refused input: the export, the previous version or the mapping."""
    try:
        rules = NormalisationRules.from_document(data.load(VOLATILE_FIELDS))
    except (ValueError, UnsafeInputError) as error:  # the maintainers' data, not the input
        raise EnvironmentProblemError(f"policy data {error}") from error
    try:
        normalised = normalise(export, external_id, rules, previous=previous, mapping=mapping)
    except ExportStructureError as error:
        where = (previous_path or path) if error.origin == "previous" else path
        raise UnsafeInputError(error.code, str(error), where) from error
    except InvalidInjectMappingError as error:
        raise UnsafeInputError(error.code, str(error), mapping_path or path) from error
    except InjectMatchingError as error:
        raise UnsafeInputError(error.code, str(error), path) from error
    if stored_size(normalised.document) > MAX_STORED_SIZE:
        raise UnsafeInputError(
            "IO-001", f"normalised form larger than {MAX_STORED_SIZE} bytes", path
        )
    refusals = hidden_character_findings(normalised.document, path)
    if start_at is None or refusals:
        return PreparedEntry(
            stored_form(normalised.document), normalised.removed_injects, refusals=refusals
        )
    metadata, to_complete = start_metadata(
        normalised.document, external_id, data, path=start_at, source=path
    )
    return PreparedEntry(
        stored_form(normalised.document), normalised.removed_injects, metadata, to_complete
    )


def start_metadata(
    document: Mapping[str, Any], external_id: str, data: DataLoader, *, path: str, source: str
) -> tuple[dict[str, object], tuple[Finding, ...]]:
    """The starting ``scenario.yaml`` of a first preparation, for the normalised ``document``,
    and the ``SCH-007`` findings of what is left to complete in it, at ``path``. The facts of
    the injects come from the recorded built-in contracts, as for every cross-check; facts the
    export read from ``source`` cannot give are a refusal of that export."""
    try:
        builtin = BuiltinContracts.from_document(data.load(BUILTIN_CONTRACTS))
    except (ValueError, UnsafeInputError) as error:  # the maintainers' data, not the input
        raise EnvironmentProblemError(f"policy data {error}") from error
    try:
        facts, unknown = export_facts(document, builtin, path)
    except ExportStructureError as error:
        raise UnsafeInputError(error.code, str(error), source) from error
    description = document[INFORMATION].get("scenario_description")
    return starting_metadata(
        facts,
        external_id=external_id,
        description=description if isinstance(description, str) else "",
        platform_version=builtin.platform_version,
        unknown_injects=len(unknown),
        path=path,
    )
