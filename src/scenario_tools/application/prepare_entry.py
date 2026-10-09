"""Preparing an entry: the export, normalised with the rules kept as data, in stored form."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.identifiers import (
    InjectMatchingError,
    InvalidInjectMappingError,
)
from scenario_tools.domain.catalogue.normalisation import (
    ExportStructureError,
    NormalisationRules,
    normalise,
)
from scenario_tools.domain.shared.canonical import stored_form, stored_size
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

VOLATILE_FIELDS = "volatile-fields"
# The stored form indents by depth, so a small export can give a much larger file: it is bounded
# like a JSON input.
MAX_STORED_SIZE = 20 * 1024 * 1024


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
    previous: object = None,
    previous_path: str | None = None,
    mapping: Mapping[str, str] | None = None,
    mapping_path: str | None = None,
) -> PreparedEntry:
    """Normalise the export read from ``path`` for the entry ``external_id``. A refusal names its
    code and the file at fault, like any refused input: the export, the previous version or the
    mapping."""
    try:
        rules = NormalisationRules.from_document(data.load(VOLATILE_FIELDS))
    except ValueError as error:  # the maintainers' data, not the contributor's input
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
    return PreparedEntry(stored_form(normalised.document), normalised.removed_injects)
