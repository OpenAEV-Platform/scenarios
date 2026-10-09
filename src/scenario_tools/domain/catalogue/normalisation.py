"""Normalisation of an exported scenario.

An export carries the identifiers, dates and internal data of the instance it comes from. Once
normalised, it holds:

- identifiers derived from the entry's external ID for every object of the scenario, and the
  identifiers of the previous version for the injects it already had;
- the platform's own identifiers for its built-in contracts and domains, which the importer
  looks up as they are, and identifiers derived from the external identifier for attack
  patterns and kill chain phases, which the importer matches that way;
- every reference rewritten accordingly, inside text too;
- no field that changes from one export or instance to the next, as listed in the rules;
- no internal data: a placeholder sender, no user, no variable value;
- set-like lists and collections in a stable order.

The same export, external ID and previous version always give the same document.
"""

import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.identifiers import (
    NS_OPENAEV_SCENARIOS,
    InjectSignature,
    match_injects,
    scenario_namespace,
    stable_id,
)
from scenario_tools.domain.shared.canonical import jcs

PLACEHOLDER_SENDER = "simulation@example.org"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_INFORMATION, _INJECTS = "scenario_information", "scenario_injects"
# Collections whose objects take identifiers derived from the entry, with their identifier key.
_OBJECTS = (
    ("scenario_teams", "team_id", "team"),
    ("scenario_variables", "variable_id", "variable"),
    ("scenario_tags", "tag_id", "tag"),
    ("scenario_documents", "document_id", "document"),
    ("scenario_channels", "channel_id", "channel"),
    ("scenario_articles", "article_id", "article"),
    ("scenario_challenges", "challenge_id", "challenge"),
    ("scenario_organizations", "organization_id", "organization"),
)
# Catalogue objects the importer matches by external identifier, so that their identifier is
# derived from it, the same in every scenario.
_CATALOGUE = (
    ("attack_pattern_id", "attack_pattern_external_id", "attack-pattern"),
    ("phase_id", "phase_external_id", "kill-chain-phase"),
)
_CONTRACT, _PAYLOAD = "inject_injector_contract", "injector_contract_payload"


class ExportStructureError(ValueError):
    """The input is not shaped like an OpenAEV scenario export."""

    code = "IO-014"


@dataclass(frozen=True)
class NormalisationRules:
    """What changes from one export or instance to the next, kept as data."""

    removed: frozenset[str]
    removed_suffixes: tuple[str, ...]
    sorted_lists: frozenset[str]

    @classmethod
    def from_document(cls, document: object) -> "NormalisationRules":
        """Read the rules from the volatile-fields data document."""

        def names(key: str) -> tuple[str, ...]:
            value = document.get(key) if isinstance(document, Mapping) else None
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"volatile-fields: {key} must be a list of names")
            return tuple(value)

        return cls(
            removed=frozenset(names("removed")),
            removed_suffixes=names("removed_suffixes"),
            sorted_lists=frozenset(names("sorted")),
        )


@dataclass(frozen=True)
class Normalised:
    """The normalised document, and the injects of the previous version it no longer has."""

    document: dict[str, Any]
    removed_injects: tuple[str, ...]


def _refuse(what: str) -> ExportStructureError:
    return ExportStructureError(f"not an OpenAEV scenario export: {what}")


def _objects(document: Mapping[str, Any], collection: str) -> list[dict[str, Any]]:
    value = document.get(collection)
    if value is None:  # absent or null: an empty collection
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise _refuse(f"{collection} must be a list of objects")
    return value


def _text(item: Mapping[str, Any], key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise _refuse(f"{where}.{key} must be text")
    return value


def _dicts(value: object) -> Iterator[dict[str, Any]]:
    """Every object inside ``value``, at any depth."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _dicts(child)


class _Identifiers:
    """The map from source identifiers to normalised ones; one source never gets two."""

    def __init__(self) -> None:
        self.targets: dict[str, str] = {}

    def add(self, source: str, target: str) -> None:
        if self.targets.setdefault(source, target) != target:
            raise _refuse(f"identifier {source!r} names two different objects")


def _payload(inject: Mapping[str, Any]) -> dict[str, Any] | None:
    contract = inject.get(_CONTRACT)
    if contract is None:
        return None
    if not isinstance(contract, dict):
        raise _refuse(f"{_CONTRACT} must be an object")
    payload = contract.get(_PAYLOAD)
    if payload in (None, {}):
        return None
    if not isinstance(payload, dict):
        raise _refuse(f"{_PAYLOAD} must be an object")
    return payload


def _signature(inject: Mapping[str, Any], contract_of: Callable[[str], str]) -> InjectSignature:
    """``contract_of`` turns a payload ID into the contract part of the signature: a contract
    created from a payload is specific to an instance, its payload is not."""
    payload = _payload(inject)
    contract = inject.get(_CONTRACT) or {}
    if payload is not None:
        key = contract_of(_text(payload, "payload_id", _PAYLOAD))
    else:
        key = contract.get("injector_contract_id") or ""
    parents = tuple(
        sorted(
            relation["dependency_relationship"]["inject_parent_id"]
            for relation in inject.get("inject_depends_on") or []
            if isinstance(relation, dict)
            and isinstance(relation.get("dependency_relationship"), dict)
            and isinstance(relation["dependency_relationship"].get("inject_parent_id"), str)
        )
    )
    return InjectSignature(
        _text(inject, "inject_id", "inject"),
        str(key),
        _text(inject, "inject_title", "inject"),
        parents,
    )


def _identifiers(
    export: Mapping[str, Any],
    external_id: str,
    previous: Mapping[str, Any] | None,
    mapping: Mapping[str, str] | None,
) -> tuple[_Identifiers, tuple[str, ...]]:
    namespace = scenario_namespace(external_id)
    identifiers = _Identifiers()
    information = export[_INFORMATION]
    identifiers.add(
        _text(information, "scenario_id", _INFORMATION),
        stable_id(namespace, "scenario", information["scenario_id"]),
    )
    for collection, key, object_type in _OBJECTS:
        for item in _objects(export, collection):
            source = _text(item, key, collection)
            identifiers.add(source, stable_id(namespace, object_type, source))
    for inject in _objects(export, _INJECTS):
        payload = _payload(inject)
        if payload is not None:
            source = _text(payload, "payload_id", _PAYLOAD)
            identifiers.add(source, stable_id(namespace, "payload", source))
            contract = _text(inject[_CONTRACT], "injector_contract_id", _CONTRACT)
            identifiers.add(contract, stable_id(namespace, "contract", contract))
    for item in _dicts(export):
        for key, external_key, object_type in _CATALOGUE:
            if isinstance(item.get(key), str) and isinstance(item.get(external_key), str):
                target = stable_id(NS_OPENAEV_SCENARIOS, object_type, item[external_key])
                identifiers.add(item[key], target)
    new = [
        _signature(inject, lambda payload: stable_id(namespace, "payload", payload))
        for inject in _objects(export, _INJECTS)
    ]
    old = [
        _signature(inject, lambda payload: payload) for inject in _objects(previous or {}, _INJECTS)
    ]
    matching = match_injects(namespace, new, old, mapping)
    for source, target in matching.ids.items():
        identifiers.add(source, target)
    return identifiers, matching.removed


def _rewrite(value: Any, targets: Mapping[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: _rewrite(child, targets) for key, child in value.items()}
    if isinstance(value, list):
        return [_rewrite(child, targets) for child in value]
    if isinstance(value, str):
        return _UUID.sub(lambda match: targets.get(match.group(), match.group()), value)
    return value


def _strip(value: Any, rules: NormalisationRules) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip(child, rules)
            for key, child in value.items()
            if key not in rules.removed and not key.endswith(rules.removed_suffixes)
        }
    if isinstance(value, list):
        return [_strip(child, rules) for child in value]
    return value


def _sort(value: Any, rules: NormalisationRules) -> Any:
    if isinstance(value, dict):
        return {
            key: sorted(_sort(child, rules), key=jcs)
            if key in rules.sorted_lists and isinstance(child, list)
            else _sort(child, rules)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_sort(child, rules) for child in value]
    return value


def _neutralise(document: dict[str, Any]) -> None:
    document[_INFORMATION]["scenario_mail_from"] = PLACEHOLDER_SENDER
    document["scenario_users"] = []
    for team in document.get("scenario_teams") or []:
        team["team_users"] = []
    for variable in document.get("scenario_variables") or []:
        variable.pop("variable_value", None)


def normalise(
    export: object,
    external_id: str,
    rules: NormalisationRules,
    *,
    previous: Mapping[str, Any] | None = None,
    mapping: Mapping[str, str] | None = None,
) -> Normalised:
    """Normalise ``export`` for the entry ``external_id``, reusing the inject identifiers of
    ``previous`` (a normalised document) and the explicit ``mapping`` of source to stable IDs."""
    if not isinstance(export, dict):
        raise _refuse("not a JSON object")
    if not isinstance(export.get(_INFORMATION), dict):
        raise _refuse(f"{_INFORMATION} must be an object")
    identifiers, removed_injects = _identifiers(export, external_id, previous, mapping)
    document = _strip(_rewrite(export, identifiers.targets), rules)  # new objects, export untouched
    _neutralise(document)
    document = _sort(document, rules)
    for collection, key, _ in (*_OBJECTS, (_INJECTS, "inject_id", "inject")):
        if collection in document and isinstance(document[collection], list):
            document[collection] = sorted(document[collection], key=lambda item: item[key])
    return Normalised(document, removed_injects)
