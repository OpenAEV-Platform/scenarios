"""What changes from one export or instance to the next, and how normalisation takes it out of a
document once its identifiers are rewritten: the rules, kept as data; volatile fields removed,
inside the JSON text of contract copies too; domains named; internal data replaced; set-like lists
sorted."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.export_reading import (
    CONTENT,
    CONTRACT,
    INFORMATION,
    INJECTS,
    PAYLOAD,
    decoded_text,
    every_object,
    structure_error,
)
from scenario_tools.domain.catalogue.identifiers import NS_OPENAEV_SCENARIOS, stable_id
from scenario_tools.domain.shared.identifiers import CANONICAL_UUID
from scenario_tools.domain.shared.stored import STEP_DATA, STEPS, WORKFLOW
from scenario_tools.domain.shared.workflow import ExportKeys

PLACEHOLDER_SENDER = "simulation@example.org"
_DOMAINS = "injector_contract_domains"


@dataclass(frozen=True)
class NormalisationRules:
    """What changes from one export or instance to the next, kept as data."""

    removed: frozenset[str]
    removed_suffixes: tuple[str, ...]
    sorted_lists: frozenset[str]
    emptied_in_builtin_contracts: frozenset[str]
    export_keys: ExportKeys

    @classmethod
    def from_document(cls, document: object, export_keys: ExportKeys) -> "NormalisationRules":
        """Read the rules from the volatile-fields data document, with the closed lists of keys
        an export may hold."""

        def names(key: str) -> tuple[str, ...]:
            value = document.get(key) if isinstance(document, Mapping) else None
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item for item in value
            ):
                raise ValueError(f"volatile-fields: {key} must be a list of names")
            return tuple(value)

        return cls(
            removed=frozenset(names("removed")),
            removed_suffixes=names("removed_suffixes"),
            sorted_lists=frozenset(names("sorted")),
            emptied_in_builtin_contracts=frozenset(names("emptied_in_builtin_contracts")),
            export_keys=export_keys,
        )


def _strip_text(text: object, rules: NormalisationRules) -> object:
    """The JSON text of a contract copy, without its volatile fields and with its set-like lists
    sorted, encoded again in compact form with sorted keys: the platform does not encode all its
    contracts the same way, and two equivalent copies must give the same text."""
    if text is None:
        return None
    if not isinstance(text, str):
        raise structure_error(f"{CONTENT} must be JSON text")
    decoded = decoded_text(text)
    cleaned = sort_sets(
        strip_volatile(decoded, rules), rules
    )  # the same rules as the rest of the export
    return json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _declared_domains(contract: Mapping[str, Any]) -> bool:
    copy = contract.get("convertedContent")
    if copy is None and isinstance(contract.get(CONTENT), str):
        copy = decoded_text(contract[CONTENT])
    return isinstance(copy, dict) and bool(copy.get("domains"))


def _domain_names(contract: Mapping[str, Any]) -> set[str]:
    """The names of the domains declared in a contract's own copy."""
    copy = contract.get("convertedContent")
    if copy is None and isinstance(contract.get(CONTENT), str):
        copy = decoded_text(contract[CONTENT])
    domains = copy.get("domains") if isinstance(copy, dict) else None
    if not isinstance(domains, list) or not all(
        isinstance(domain, dict)
        and isinstance(domain.get("domain_name"), str)
        and domain["domain_name"]
        for domain in domains
    ):
        raise structure_error(f"{_DOMAINS} needs a copy of the contract that names its domains")
    return {domain["domain_name"] for domain in domains}


def name_domains(document: Any) -> None:
    """A contract's bare domain list, which carries no name, replaced by the identifiers of the
    domains its copy names: each instance generates its own domain identifiers."""
    for item in every_object(document):
        bare = item.get(_DOMAINS)
        if bare is not None and not isinstance(bare, list):
            raise structure_error(f"{_DOMAINS} must be a list")
        if not bare:  # absent, null or empty: its copy, if any, must name no domain either
            if _declared_domains(item):
                raise structure_error(f"{_DOMAINS} names no domain, but the contract's copy does")
            continue
        if not all(isinstance(domain, str) and CANONICAL_UUID.fullmatch(domain) for domain in bare):
            raise structure_error(f"{_DOMAINS} must be a list of identifiers")
        names = _domain_names(item)
        if len(names) != len(set(bare)):
            raise structure_error(f"{_DOMAINS} does not match the domains of the contract's copy")
        item[_DOMAINS] = sorted(stable_id(NS_OPENAEV_SCENARIOS, "domain", name) for name in names)


def strip_volatile(value: Any, rules: NormalisationRules) -> Any:
    """Volatile fields removed, inside the JSON text of contract copies too."""
    if isinstance(value, dict):
        return {
            key: _strip_text(child, rules) if key == CONTENT else strip_volatile(child, rules)
            for key, child in value.items()
            if key not in rules.removed and not key.endswith(rules.removed_suffixes)
        }
    if isinstance(value, list):
        return [strip_volatile(child, rules) for child in value]
    return value


def _order(value: Any) -> str:
    """The sort key of a set-like list item: its JSON text with sorted keys. Two distinct values
    never share it, unlike their canonical bytes (1 and 1.0 have the same ones)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def sort_sets(value: Any, rules: NormalisationRules) -> Any:
    if isinstance(value, dict):
        return {
            key: sorted(sort_sets(child, rules), key=_order)
            if key in rules.sorted_lists and isinstance(child, list)
            else sort_sets(child, rules)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [sort_sets(child, rules) for child in value]
    return value


def unlink_builtin_lists(document: dict[str, Any], rules: NormalisationRules) -> None:
    """Empty the lists a built-in contract's copy gains from the instance it was exported from,
    such as the techniques its collectors linked to the contract. A contract created from a
    payload keeps its own: they are the payload's content."""
    for inject in document.get(INJECTS) or []:
        contract = inject.get(CONTRACT)
        if isinstance(contract, dict) and not contract.get(PAYLOAD):
            for key in rules.emptied_in_builtin_contracts & contract.keys():
                contract[key] = []


def neutralise(document: dict[str, Any]) -> None:
    document[INFORMATION]["scenario_mail_from"] = PLACEHOLDER_SENDER
    document["scenario_users"] = []
    for team in document.get("scenario_teams") or []:
        team["team_users"] = []
    for variable in document.get("scenario_variables") or []:
        variable.pop("variable_value", None)


def _listed(holder: object, key: str) -> list[Any]:
    """The list ``holder`` holds under ``key``; none when it holds no list there."""
    found = holder.get(key) if isinstance(holder, dict) else None
    return found if isinstance(found, list) else []


def describe_payloads(document: dict[str, Any]) -> None:
    """Give each payload, of an inject or a step, without a description (absent, null or blank)
    its name as one: a payload of the catalogue has a description, and the starter pack's
    exports hold payloads without. Any other value is left for the payload checks."""
    holders = list(_listed(document, INJECTS))
    workflow = document.get(WORKFLOW)
    holders += [step.get(STEP_DATA) for step in _listed(workflow, STEPS) if isinstance(step, dict)]
    for holder in holders:
        contract = holder.get(CONTRACT) if isinstance(holder, dict) else None
        payload = contract.get(PAYLOAD) if isinstance(contract, dict) else None
        if not isinstance(payload, dict):
            continue
        text = payload.get("payload_description")
        if text is None or (isinstance(text, str) and not text.strip()):
            payload["payload_description"] = payload.get("payload_name")
