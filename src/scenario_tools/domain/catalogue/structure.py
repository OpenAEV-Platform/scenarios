"""The shape of a stored scenario, as the checks read it: its parts, and how a part that is not
shaped as expected is refused (``IO-014``)."""

from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.shared.stored import (
    INJECTS,
    Origin,
    StoredInject,
    inject_pointer,
    injects,
)

INFORMATION = "scenario_information"
CONTRACT, PAYLOAD = "inject_injector_contract", "injector_contract_payload"


def not_an_export(what: str) -> ExportStructureError:
    error = ExportStructureError(f"not an OpenAEV scenario export: {what}")
    error.what = what
    return error


def require_object(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise not_an_export(f"{where} must be an object")
    return value


def require_text(item: Mapping[str, Any], key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise not_an_export(f"{where}.{key} must be text")
    return value


def checked_injects(export: Mapping[str, Any]) -> Iterator[StoredInject]:
    """The injects of ``export``, as the walk gives them, refusing a part that is not a list and,
    when it is reached, an item that is not an object."""
    part = export.get(INJECTS)
    if not isinstance(part, list):
        raise not_an_export(f"{INJECTS} must be a list")
    for index, inject in enumerate(part):
        yield StoredInject(inject_pointer(index), require_object(inject, INJECTS), Origin.INJECT)


def contracts_with_payloads(
    stored: object,
) -> Iterator[tuple[str, Mapping[str, Any], Mapping[str, Any]]]:
    """Every inject whose contract embeds a payload: the inject's JSON pointer, the inject and its
    contract, which holds the payload under ``PAYLOAD``. A payload that is null or an empty object
    is none, as the archive reads it; any other value is one, for its check to refuse when it is
    not shaped as a payload."""
    for found in injects(stored):
        contract = found.inject.get(CONTRACT)
        if isinstance(contract, Mapping) and contract.get(PAYLOAD) not in (None, {}):
            yield found.pointer, found.inject, contract
