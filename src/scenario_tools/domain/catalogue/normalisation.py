"""Normalisation of an exported scenario.

An export carries the identifiers, dates and internal data of the instance it comes from. Once
normalised, it holds:

- identifiers derived from the entry's external ID: for the scenario itself, for its named
  objects from their name or key, which every instance exports the same way, and for its
  injects, which keep the identifiers of the previous version;
- the platform's own identifiers for its built-in contracts, which the importer looks up as
  they are, and identifiers derived from a shared key for the catalogue objects each instance
  creates: attack patterns and kill chain phases from their external identifier, domains from
  their name;
- every reference rewritten accordingly, inside text too;
- no field that changes from one export or instance to the next, as listed in the rules, inside
  the JSON text of contract copies too;
- no internal data: a placeholder sender, no user, no variable value;
- set-like lists and collections in a stable order.

The same export, external ID and previous version always give the same document, and a
normalised document normalised again with itself as the previous version is unchanged.
"""

import json
import math
import re
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.identifiers import (
    NS_OPENAEV_SCENARIOS,
    InjectSignature,
    match_injects,
    scenario_namespace,
    stable_id,
)
from scenario_tools.domain.shared.canonical import SAFE_INTEGER

PLACEHOLDER_SENDER = "simulation@example.org"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_UUID_IN_TEXT = re.compile(_UUID.pattern, re.IGNORECASE)
# A hexadecimal digit or a hyphen written as an escape in JSON text, not preceded by an escaped
# backslash: an identifier written that way would escape rewriting.
_ESCAPED_ID_CHARACTER = re.compile(r"(?<!\\)(?:\\\\)*\\u00(?:3[0-9]|4[1-6]|6[1-6]|2[dD])")
_JSON_TEXT_FIELDS = ("inject_content", "injector_contract_content")
_INFORMATION, _INJECTS = "scenario_information", "scenario_injects"
_ARTICLES = "scenario_articles"
# Parts of an export whose identifiers have no agreed rule yet: refused when not empty.
NOT_SUPPORTED = (
    ("scenario_workflow", "chained scenarios"),
    ("scenario_objectives", "objectives"),
    ("scenario_lessons_categories", "lessons"),
    ("scenario_lessons_questions", "lessons"),
)
MAX_INJECTS = 1000  # matching is quadratic in the worst case; real scenarios have under 100
# Collections whose objects take identifiers from their natural key, which every instance exports
# the same way: collection, identifier key, natural key and object type.
_OBJECTS = (
    ("scenario_teams", "team_id", "team_name", "team"),
    ("scenario_variables", "variable_id", "variable_key", "variable"),
    ("scenario_tags", "tag_id", "tag_name", "tag"),
    ("scenario_documents", "document_id", "document_target", "document"),
    ("scenario_channels", "channel_id", "channel_name", "channel"),
    ("scenario_challenges", "challenge_id", "challenge_name", "challenge"),
    ("scenario_organizations", "organization_id", "organization_name", "organization"),
)
# Catalogue objects whose identifiers each instance generates, derived from a key that every
# instance shares, the same in every scenario: attack patterns and kill chain phases, which the
# importer matches by external identifier, and domains, by name.
_CATALOGUE = (
    ("attack_pattern_id", "attack_pattern_external_id", "attack-pattern"),
    ("phase_id", "phase_external_id", "kill-chain-phase"),
    ("domain_id", "domain_name", "domain"),
)
_DOMAINS = "injector_contract_domains"
_CONTRACT, _PAYLOAD = "inject_injector_contract", "injector_contract_payload"
_CONTENT = "injector_contract_content"
_MAX_DEPTH = 64  # the nesting bound the readers apply to the export itself


class ExportStructureError(ValueError):
    """The input is not shaped like an OpenAEV scenario export. ``origin`` names the input at
    fault: ``export``, or ``previous`` for the previous version."""

    code = "IO-014"

    def __init__(self, message: str, origin: str = "export") -> None:
        super().__init__(message)
        self.origin = origin
        self.what = message


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
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item for item in value
            ):
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


_FAULTS = {
    "export": "not an OpenAEV scenario export",
    "previous": "not a previous version of this entry",
}


def _refuse(what: str, origin: str = "export") -> ExportStructureError:
    error = ExportStructureError(f"{_FAULTS[origin]}: {what}", origin)
    error.what = what
    return error


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
        if not _UUID.fullmatch(source):
            raise _refuse(f"identifier {source!r} is not a canonical UUID")
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


def _signature(inject: Mapping[str, Any], namespace: uuid.UUID) -> InjectSignature:
    """The contract part of the signature is the payload's stable ID for an inject that runs a
    payload: a contract created from a payload is specific to an instance, the payload's name is
    not."""
    payload = _payload(inject)
    contract = inject.get(_CONTRACT) or {}
    if payload is not None:
        key = stable_id(namespace, "payload", _name(payload, "payload_name", _PAYLOAD))
    else:
        key = contract.get("injector_contract_id") or ""
    relations = inject.get("inject_depends_on")
    if relations is None:
        relations = []
    if not isinstance(relations, list):
        raise _refuse("inject_depends_on must be a list")
    inject_id = _text(inject, "inject_id", "inject")
    parents = []
    for relation in relations:
        link = relation.get("dependency_relationship") if isinstance(relation, dict) else None
        if not isinstance(link, dict):
            raise _refuse("inject_depends_on must hold dependency relationships")
        if link.get("inject_children_id") != inject_id:
            raise _refuse(f"a dependency of inject {inject_id!r} names another child")
        parents.append(_text(link, "inject_parent_id", "dependency_relationship"))
    return InjectSignature(
        inject_id, str(key), _text(inject, "inject_title", "inject"), tuple(parents)
    )


def _name(item: Mapping[str, Any], key: str, where: str) -> str:
    name = _text(item, key, where)
    if not name:
        raise _refuse(f"{where}.{key} must not be empty")
    return name


def _catalogue_objects(export: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Every object of the export, and those inside the JSON text of contract copies, where the
    platform writes the domains of a contract."""
    for item in _dicts(export):
        yield item
        if isinstance(item.get(_CONTENT), str):
            yield from _dicts(_decode(item[_CONTENT]))


def _check_injects(signatures: list[InjectSignature]) -> None:
    if len(signatures) > MAX_INJECTS:
        raise _refuse(f"more than {MAX_INJECTS} injects")
    identifiers = {signature.id for signature in signatures}
    if len(identifiers) != len(signatures):
        raise _refuse("an inject identifier appears twice")
    for signature in signatures:
        if not identifiers.issuperset(signature.parents):
            raise _refuse(
                f"inject {signature.id!r} depends on an inject the scenario does not have"
            )


def _previous_signatures(
    previous: Mapping[str, Any] | None, namespace: uuid.UUID, scenario_id: str
) -> list[InjectSignature]:
    """The injects of the previous version, a normalised document of the same entry: its
    scenario ID is the entry's, and its inject identifiers are canonical UUIDs. A refusal names
    the previous version as the input at fault."""
    if previous is None:
        return []
    try:
        information = previous.get(_INFORMATION)
        if not isinstance(information, dict) or information.get("scenario_id") != scenario_id:
            raise _refuse("its scenario identifier is not this entry's")
        signatures = [_signature(inject, namespace) for inject in _objects(previous, _INJECTS)]
        _check_injects(signatures)
        for signature in signatures:
            if not _UUID.fullmatch(signature.id):
                raise _refuse(f"inject identifier {signature.id!r} is not a canonical UUID")
    except ExportStructureError as error:
        raise _refuse(error.what, "previous") from error
    return signatures


def _identifiers(
    export: Mapping[str, Any],
    external_id: str,
    previous: Mapping[str, Any] | None,
    mapping: Mapping[str, str] | None,
) -> tuple[_Identifiers, tuple[str, ...]]:
    namespace = scenario_namespace(external_id)
    identifiers = _Identifiers()
    scenario_id = stable_id(namespace, "scenario", external_id)
    identifiers.add(_text(export[_INFORMATION], "scenario_id", _INFORMATION), scenario_id)
    channels: dict[str, str] = {}
    for collection, key, name_key, object_type in _OBJECTS:
        named: set[str] = set()
        for item in _objects(export, collection):
            source, name = _text(item, key, collection), _name(item, name_key, collection)
            if name in named:
                raise _refuse(f"two objects of {collection} are named {name!r}")
            named.add(name)
            identifiers.add(source, stable_id(namespace, object_type, name))
            if object_type == "channel":
                channels[source] = name
    # An article's name is unique within its channel only.
    articles: set[str] = set()
    for item in _objects(export, _ARTICLES):
        source, name = _text(item, "article_id", _ARTICLES), _name(item, "article_name", _ARTICLES)
        channel = channels.get(_text(item, "article_channel", _ARTICLES))
        if channel is None:
            raise _refuse(f"article {name!r} has no channel of the scenario")
        article_key = json.dumps([channel, name])
        if article_key in articles:
            raise _refuse(f"two articles of channel {channel!r} are named {name!r}")
        articles.add(article_key)
        identifiers.add(source, stable_id(namespace, "article", article_key))
    payloads: dict[str, str] = {}
    for inject in _objects(export, _INJECTS):
        payload = _payload(inject)
        contract_copy = inject.get(_CONTRACT)
        if payload is None and isinstance(contract_copy, dict):
            custom = contract_copy.get("injector_contract_custom")
            if custom is not None and not isinstance(custom, bool):
                raise _refuse("injector_contract_custom must be true or false")
            if custom:
                # Its identifier belongs to one instance, and the contract exists on no other.
                raise _refuse("custom contracts without a payload are not supported yet")
            # A built-in contract keeps its identifier: registered as it is, so that it is
            # checked like any other and no other object can take it.
            built_in = _text(contract_copy, "injector_contract_id", _CONTRACT)
            identifiers.add(built_in, built_in)
        if payload is not None:
            source = _text(payload, "payload_id", _PAYLOAD)
            name = _name(payload, "payload_name", _PAYLOAD)
            if payloads.setdefault(name, source) != source:
                raise _refuse(f"two payloads are named {name!r}")
            identifiers.add(source, stable_id(namespace, "payload", name))
            contract = _text(inject[_CONTRACT], "injector_contract_id", _CONTRACT)
            identifiers.add(contract, stable_id(namespace, "contract", name))
    for item in _catalogue_objects(export):
        for key, external_key, object_type in _CATALOGUE:
            if item.get(key) is not None:  # an identifier given: its shared key is required
                if not isinstance(item[key], str):
                    raise _refuse(f"{key} must be text")
                if not isinstance(item.get(external_key), str) or not item[external_key]:
                    raise _refuse(f"{key} needs a non-empty {external_key}")
                target = stable_id(NS_OPENAEV_SCENARIOS, object_type, item[external_key])
                identifiers.add(item[key], target)
    new = [_signature(inject, namespace) for inject in _objects(export, _INJECTS)]
    _check_injects(new)
    old = _previous_signatures(previous, namespace, scenario_id)
    matching = match_injects(namespace, new, old, mapping)
    for source, target in matching.ids.items():
        identifiers.add(source, target)
    return identifiers, matching.removed


def _rewrite(value: Any, targets: Mapping[str, str]) -> Any:
    """Every rewritten identifier replaced, in values, inside text and in object keys. Two keys
    of one object that become the same are refused: one value would be lost."""
    if isinstance(value, dict):
        rewritten = {
            _rewrite(key, targets): _rewrite(child, targets) for key, child in value.items()
        }
        if len(rewritten) != len(value):
            raise _refuse("two keys of an object name the same identifier")
        return rewritten
    if isinstance(value, list):
        return [_rewrite(child, targets) for child in value]
    if isinstance(value, str):
        return _UUID_IN_TEXT.sub(
            lambda match: targets.get(match.group().lower(), match.group()), value
        )
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise _refuse(f"{_CONTENT} repeats a key")
    return dict(pairs)


def _finite(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):
        raise _refuse(f"{_CONTENT} holds a number out of range")
    return number


def _not_a_number(text: str) -> None:
    raise _refuse(f"{_CONTENT} holds {text}")


def _check_decoded(value: Any) -> None:
    """What the readers would refuse in a file: nesting deeper than they allow, an unpaired
    surrogate in a string or a key, an integer the canonical form cannot hold exactly; and a
    contract copy inside the copy, which bounds the work
    on nested text."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth == _MAX_DEPTH:
                raise _refuse(f"{_CONTENT} is nested deeper than {_MAX_DEPTH} levels")
            if isinstance(item, dict):
                if _CONTENT in item:
                    raise _refuse(f"{_CONTENT} holds another contract copy")
                stack.extend((key, depth) for key in item)
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as error:
                raise _refuse(f"{_CONTENT} holds an unpaired surrogate") from error
        elif isinstance(item, int) and abs(item) > SAFE_INTEGER:  # a boolean is 0 or 1
            raise _refuse(f"{_CONTENT} holds an integer beyond the exact range of 2^53 - 1")


def _decode(text: str) -> Any:
    """The JSON text of a contract copy, decoded within the bounds the readers apply."""
    try:
        decoded = json.loads(
            text, object_pairs_hook=_unique, parse_float=_finite, parse_constant=_not_a_number
        )
    except (ValueError, RecursionError) as error:  # too many digits, as well as invalid JSON
        raise _refuse(f"{_CONTENT} must be JSON text") from error
    _check_decoded(decoded)
    return decoded


def _strip_text(text: object, rules: NormalisationRules) -> object:
    """The JSON text of a contract copy, without its volatile fields and with its set-like lists
    sorted, encoded again in compact form with sorted keys: the platform does not encode all its
    contracts the same way, and two equivalent copies must give the same text."""
    if text is None:
        return None
    if not isinstance(text, str):
        raise _refuse(f"{_CONTENT} must be JSON text")
    decoded = _decode(text)
    cleaned = _sort(_strip(decoded, rules), rules)  # the same rules as the rest of the export
    return json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _declared_domains(contract: Mapping[str, Any]) -> bool:
    copy = contract.get("convertedContent")
    if copy is None and isinstance(contract.get(_CONTENT), str):
        copy = _decode(contract[_CONTENT])
    return isinstance(copy, dict) and bool(copy.get("domains"))


def _domain_names(contract: Mapping[str, Any]) -> set[str]:
    """The names of the domains declared in a contract's own copy."""
    copy = contract.get("convertedContent")
    if copy is None and isinstance(contract.get(_CONTENT), str):
        copy = _decode(contract[_CONTENT])
    domains = copy.get("domains") if isinstance(copy, dict) else None
    if not isinstance(domains, list) or not all(
        isinstance(domain, dict)
        and isinstance(domain.get("domain_name"), str)
        and domain["domain_name"]
        for domain in domains
    ):
        raise _refuse(f"{_DOMAINS} needs a copy of the contract that names its domains")
    return {domain["domain_name"] for domain in domains}


def _name_domains(document: Any) -> None:
    """A contract's bare domain list, which carries no name, replaced by the identifiers of the
    domains its copy names: each instance generates its own domain identifiers."""
    for item in _dicts(document):
        bare = item.get(_DOMAINS)
        if bare is not None and not isinstance(bare, list):
            raise _refuse(f"{_DOMAINS} must be a list")
        if not bare:  # absent, null or empty: its copy, if any, must name no domain either
            if _declared_domains(item):
                raise _refuse(f"{_DOMAINS} names no domain, but the contract's copy does")
            continue
        if not all(isinstance(domain, str) and _UUID.fullmatch(domain) for domain in bare):
            raise _refuse(f"{_DOMAINS} must be a list of identifiers")
        names = _domain_names(item)
        if len(names) != len(set(bare)):
            raise _refuse(f"{_DOMAINS} does not match the domains of the contract's copy")
        item[_DOMAINS] = sorted(stable_id(NS_OPENAEV_SCENARIOS, "domain", name) for name in names)


def _strip(value: Any, rules: NormalisationRules) -> Any:
    """Volatile fields removed, inside the JSON text of contract copies too."""
    if isinstance(value, dict):
        return {
            key: _strip_text(child, rules) if key == _CONTENT else _strip(child, rules)
            for key, child in value.items()
            if key not in rules.removed and not key.endswith(rules.removed_suffixes)
        }
    if isinstance(value, list):
        return [_strip(child, rules) for child in value]
    return value


def _order(value: Any) -> str:
    """The sort key of a set-like list item: its JSON text with sorted keys. Two distinct values
    never share it, unlike their canonical bytes (1 and 1.0 have the same ones)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _sort(value: Any, rules: NormalisationRules) -> Any:
    if isinstance(value, dict):
        return {
            key: sorted(_sort(child, rules), key=_order)
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
    previous: object = None,
    mapping: Mapping[str, str] | None = None,
) -> Normalised:
    """Normalise ``export`` for the entry ``external_id``, reusing the inject identifiers of
    ``previous`` (a normalised document) and the explicit ``mapping`` of source to stable IDs."""
    if not _UUID.fullmatch(external_id):
        raise ValueError(f"external_id {external_id!r} must be a canonical UUID")
    if not isinstance(export, dict):
        raise _refuse("not a JSON object")
    if not isinstance(export.get(_INFORMATION), dict):
        raise _refuse(f"{_INFORMATION} must be an object")
    for item in _dicts(export):
        for field in _JSON_TEXT_FIELDS:
            text = item.get(field)
            if isinstance(text, str) and _ESCAPED_ID_CHARACTER.search(text):
                raise _refuse(f"{field} writes an identifier character as an escape")
    for key, what in NOT_SUPPORTED:
        if export.get(key):
            raise _refuse(f"{what} are not supported yet")
    if previous is not None and not isinstance(previous, dict):
        raise _refuse("the previous version must be a JSON object", "previous")
    identifiers, removed_injects = _identifiers(export, external_id, previous, mapping)
    document = _rewrite(export, identifiers.targets)  # new objects, export untouched
    _name_domains(document)
    document = _strip(document, rules)
    _neutralise(document)
    document = _sort(document, rules)
    for collection, key, *_ in (*_OBJECTS, (_ARTICLES, "article_id"), (_INJECTS, "inject_id")):
        if collection in document and isinstance(document[collection], list):
            document[collection] = sorted(document[collection], key=lambda item: item[key])
    return Normalised(document, removed_injects)
