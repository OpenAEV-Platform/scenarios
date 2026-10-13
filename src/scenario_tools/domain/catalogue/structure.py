"""The shape of a stored scenario, as the checks read it: its parts, and how a part that is not
shaped as expected is refused (``IO-014``)."""

from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.catalogue.normalisation import ExportStructureError

INFORMATION, INJECTS = "scenario_information", "scenario_injects"
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


def contracts_with_payloads(
    stored: object,
) -> Iterator[tuple[str, Mapping[str, Any], Mapping[str, Any]]]:
    """Every inject whose contract embeds a payload: the inject's JSON pointer, the inject and its
    contract, which holds the payload under ``PAYLOAD``. A payload that is null or an empty object
    is none, as the archive reads it; any other value is one, for its check to refuse when it is
    not shaped as a payload."""
    injects = stored.get(INJECTS) if isinstance(stored, Mapping) else None
    if not isinstance(injects, list):
        return
    for index, inject in enumerate(injects):
        contract = inject.get(CONTRACT) if isinstance(inject, Mapping) else None
        if isinstance(contract, Mapping) and contract.get(PAYLOAD) not in (None, {}):
            yield f"/{INJECTS}/{index}", inject, contract
