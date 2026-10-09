"""Preparing an entry: the export, normalised with the rules kept as data, in stored form."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.identifiers import InjectMatchingError
from scenario_tools.domain.catalogue.normalisation import (
    ExportStructureError,
    NormalisationRules,
    normalise,
)
from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.errors import UnsafeInputError

VOLATILE_FIELDS = "volatile-fields"


@dataclass(frozen=True)
class PreparedEntry:
    scenario_json: bytes
    removed_injects: tuple[str, ...]


def prepare_entry(
    export: Any,
    external_id: str,
    data: DataLoader,
    *,
    path: str,
    previous: Mapping[str, Any] | None = None,
    mapping: Mapping[str, str] | None = None,
) -> PreparedEntry:
    """Normalise the export read from ``path`` for the entry ``external_id``. A refusal names its
    code and the export, like any refused input."""
    rules = NormalisationRules.from_document(data.load(VOLATILE_FIELDS))
    try:
        normalised = normalise(export, external_id, rules, previous=previous, mapping=mapping)
    except (ExportStructureError, InjectMatchingError) as error:
        raise UnsafeInputError(error.code, str(error), path) from error
    return PreparedEntry(stored_form(normalised.document), normalised.removed_injects)
