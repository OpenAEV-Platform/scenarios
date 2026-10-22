"""Normalisation of an exported scenario.

An export carries the identifiers, dates and internal data of the instance it comes from. Once
normalised, it holds:

- identifiers derived from the entry's external ID: for the scenario itself, for its named
  objects from their name or key, which every instance exports the same way, and for its
  injects, which keep the identifiers of the previous version; for the steps of a workflow,
  from what each step runs and the steps it waits for, and for their conditions, from their
  content and place in the step's tree;
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

import hashlib
import json
import math
import re
import uuid
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.identifiers import (
    NS_OPENAEV_SCENARIOS,
    AmbiguousInjectError,
    InjectSignature,
    match_injects,
    scenario_namespace,
    stable_id,
)
from scenario_tools.domain.policy.step_rules import step_refusals
from scenario_tools.domain.policy.workflow_rules import graph_refusals, subset_refusals
from scenario_tools.domain.shared.canonical import SAFE_INTEGER, jcs
from scenario_tools.domain.shared.payload_names import base_name
from scenario_tools.domain.shared.stored import STEP_DATA, STEPS, WORKFLOW
from scenario_tools.domain.shared.workflow import (
    CONDITION_SIBLINGS_SAME,
    CONDITIONS,
    ID_NOT_KNOWN,
    MAX_STEPS,
    STEP_DATA_UNREADABLE,
    STEPS_SAME_SIGNATURE,
    TOO_MANY_STEPS,
    Condition,
    ExportKeys,
    Refusal,
    Step,
    StepDataKeys,
    export_refusals,
    has_workflow,
    parsed_workflow,
    settled_workflow,
)

PLACEHOLDER_SENDER = "simulation@example.org"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_UUID_IN_TEXT = re.compile(_UUID.pattern, re.IGNORECASE)
# A hexadecimal digit or a hyphen written as an escape in JSON text, not preceded by an escaped
# backslash: an identifier written that way would escape rewriting.
_ESCAPED_ID_CHARACTER = re.compile(r"(?<!\\)(?:\\\\)*\\u00(?:3[0-9]|4[1-6]|6[1-6]|2[dD])")
_JSON_TEXT_FIELDS = (
    "inject_content",
    "injector_contract_content",
    "step_data",
    "step_input",
    "step_output_parser",
)
_INFORMATION, _INJECTS = "scenario_information", "scenario_injects"
_ARTICLES = "scenario_articles"
# Parts of an export whose identifiers have no agreed rule yet: refused when not empty.
NOT_SUPPORTED = (
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

    def __init__(self, message: str, origin: str = "export", pointer: str = "") -> None:
        super().__init__(message)
        self.origin = origin
        self.what = message
        self.pointer = pointer  # the JSON pointer of the node at fault; empty is the whole input


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


@dataclass(frozen=True)
class Normalised:
    """The normalised document, and the injects and steps of the previous version it no longer
    has."""

    document: dict[str, Any]
    removed_injects: tuple[str, ...]
    removed_steps: tuple[str, ...] = ()


_FAULTS = {
    "export": "not an OpenAEV scenario export",
    "previous": "not a previous version of this entry",
}


def _refuse(what: str, origin: str = "export", pointer: str = "") -> ExportStructureError:
    error = ExportStructureError(f"{_FAULTS[origin]}: {what}", origin, pointer)
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
        key = stable_id(namespace, "payload", _base(payload))
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


def _base(payload: Mapping[str, Any]) -> str:
    """The base name of ``payload``: what its stable identifiers are derived from, so that every
    version of one payload shares them."""
    base = base_name(_name(payload, "payload_name", _PAYLOAD))
    if not base.strip():
        raise _refuse(f"{_PAYLOAD}.payload_name must have a base name before its version")
    return base


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
) -> tuple[_Identifiers, tuple[str, ...], tuple[str, ...]]:
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
    payloads: dict[str, tuple[str, str]] = {}  # the source and name of each base name
    for inject in [*_objects(export, _INJECTS), *_step_injects(export)]:
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
            name, base = _name(payload, "payload_name", _PAYLOAD), _base(payload)
            first_source, first_name = payloads.setdefault(base, (source, name))
            if first_source == source and first_name != name:
                raise _refuse(f"one payload is named {first_name!r} and {name!r}")
            if first_source != source:
                if first_name == name:
                    raise _refuse(f"two payloads are named {name!r}")
                raise _refuse(
                    f"two versions of the payload {base!r} are embedded: a scenario embeds one "
                    "version of a payload"
                )
            identifiers.add(source, stable_id(namespace, "payload", base))
            contract = _text(inject[_CONTRACT], "injector_contract_id", _CONTRACT)
            identifiers.add(contract, stable_id(namespace, "contract", base))
    for item in _catalogue_objects(export):
        for key, external_key, object_type in _CATALOGUE:
            if item.get(key) is not None:  # an identifier given: its shared key is required
                if not isinstance(item[key], str):
                    raise _refuse(f"{key} must be text")
                if not isinstance(item.get(external_key), str) or not item[external_key]:
                    raise _refuse(f"{key} needs a non-empty {external_key}")
                target = stable_id(NS_OPENAEV_SCENARIOS, object_type, item[external_key])
                identifiers.add(item[key], target)
    old = _previous_signatures(previous, namespace, scenario_id)  # also checks the entry
    mapping = dict(mapping or {})
    previous_steps = _previous_steps(previous, namespace)
    removed_steps = tuple(sorted(step.id for step in previous_steps))
    if has_workflow(export):
        sources = {
            step.get("step_id")
            for step in export[WORKFLOW][STEPS]
            if isinstance(step.get("step_id"), str)  # others are refused with their pointer
        }
        step_mapping = {key: mapping.pop(key) for key in sorted(mapping) if key in sources}
        pairs, removed_steps = _step_identifiers(
            export[WORKFLOW],
            namespace,
            identifiers.targets,
            previous_steps,
            step_mapping,
        )
        for source, target in pairs:
            identifiers.add(source, target)
    new = [_signature(inject, namespace) for inject in _objects(export, _INJECTS)]
    _check_injects(new)
    matching = match_injects(namespace, new, old, mapping)
    for source, target in matching.ids.items():
        identifiers.add(source, target)
    return identifiers, matching.removed, removed_steps


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


def _keep_filter_values(export: Mapping[str, Any], document: dict[str, Any]) -> None:
    """Each filter's value as the export gives it, once the identifiers are rewritten: it is what
    the filter compares with, never an identifier of the instance, which the checks keep out of
    it; a dependency's value names the step it waits for and stays rewritten."""
    if not has_workflow(export):
        return
    given_steps, written_steps = export[WORKFLOW][STEPS], document[WORKFLOW][STEPS]
    for given, written in zip(given_steps, written_steps, strict=True):
        pairs = zip(given.get(CONDITIONS) or [], written.get(CONDITIONS) or [], strict=True)
        for before, after in pairs:  # the checks made both lists of objects, in one order
            if before.get("condition_type") != "DEPEND_ON":
                after["condition_value"] = before.get("condition_value")


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


def _check_decoded(value: Any, field: str = _CONTENT, copies: int = 0, depth: int = 0) -> None:
    """What the readers would refuse in a file: nesting deeper than they allow, an unpaired
    surrogate in a string or a key, an integer the canonical form cannot hold exactly; and a
    contract copy inside the copy, which bounds the work on nested text: ``copies`` contract
    copies are allowed, the inject of a step holding one. ``value`` sits ``depth`` levels down in
    the file where it is stored."""
    stack: list[tuple[Any, int]] = [(value, depth)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth == _MAX_DEPTH:
                raise _refuse(f"{field} is nested deeper than {_MAX_DEPTH} levels")
            if isinstance(item, dict):
                if _CONTENT in item:
                    if not copies:
                        raise _refuse(f"{field} holds another contract copy")
                    copies -= 1
                stack.extend((key, depth) for key in item)
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as error:
                raise _refuse(f"{field} holds an unpaired surrogate") from error
        elif isinstance(item, int) and abs(item) > SAFE_INTEGER:  # a boolean is 0 or 1
            raise _refuse(f"{field} holds an integer beyond the exact range of 2^53 - 1")


def _decode(text: str, field: str = _CONTENT, copies: int = 0, depth: int = 0) -> Any:
    """The JSON text of ``field``, a contract copy by default, decoded within the bounds the
    readers apply, once stored ``depth`` levels down; ``copies`` contract copies may be nested in
    it."""
    try:
        decoded = json.loads(
            text, object_pairs_hook=_unique, parse_float=_finite, parse_constant=_not_a_number
        )
    except (ValueError, RecursionError) as error:  # too many digits, as well as invalid JSON
        raise _refuse(f"{field} must be JSON text") from error
    _check_decoded(decoded, field, copies, depth)
    return decoded


# The steps of a workflow

# A step's inject is stored as an object four levels down: in the workflow, in its list of steps,
# in its step.
_STEP_DATA_DEPTH = 4


def _decoded_or_none(text: str, field: str) -> Any:
    """The JSON text of a step's field decoded within the readers' bounds, or ``None``: a step's
    inject may hold one contract copy."""
    try:
        if field == "step_data":
            return _decode(text, field, copies=1, depth=_STEP_DATA_DEPTH)
        return _decode(text, field)
    except ExportStructureError:
        return None


def canonical_step_text(value: object) -> str:
    """A step's empty input or output parser in one form, compact JSON text. Only for a step that
    passed its checks, whose input is empty JSON text or absent."""
    decoded = {} if value is None else json.loads(str(value))
    return json.dumps(decoded, separators=(",", ":"), sort_keys=True)


def _step_refusals(export: Mapping[str, Any], keys: StepDataKeys) -> Iterator[Refusal]:
    """The refusals of the steps of ``export``, whose workflow has passed ``export_refusals``."""
    tags = export.get("scenario_tags")
    tag_ids = frozenset(
        tag["tag_id"]
        for tag in (tags if isinstance(tags, list) else [])
        if isinstance(tag, Mapping) and isinstance(tag.get("tag_id"), str)
    )
    for index, step in enumerate(export[WORKFLOW][STEPS]):
        at = f"/{WORKFLOW}/{STEPS}/{index}"
        data = step.get("step_data")
        # An inject given as an object gets the checks its text form gets when decoded.
        if isinstance(data, Mapping) and not _readable(data):
            yield Refusal(STEP_DATA_UNREADABLE, f"{at}/step_data")
        else:
            yield from step_refusals(step, at, keys, tag_ids, _decoded_or_none)


def _readable(data: Mapping[str, Any]) -> bool:
    """Whether a step's inject, given as an object, is within the readers' bounds."""
    try:
        _check_decoded(data, "step_data", copies=1, depth=_STEP_DATA_DEPTH)
    except ExportStructureError:
        return False
    return True


def stored_step_data(data: Mapping[str, Any], keys: StepDataKeys) -> dict[str, Any]:
    """A step's inject as it is stored: without the keys a running instance writes."""
    return {key: value for key, value in data.items() if key not in keys.removed}


def _with_decoded_steps(export: dict[str, Any]) -> dict[str, Any]:
    """``export`` with the inject of each step as an object, in new objects for the parts that
    change; the escape guard reads the text that decoding uncovers."""
    steps = []
    for index, step in enumerate(export[WORKFLOW][STEPS]):
        data = step["step_data"]
        if isinstance(data, str):
            data = _decode(data, "step_data", copies=1, depth=_STEP_DATA_DEPTH)
        for item in _dicts(data):
            for field in _JSON_TEXT_FIELDS:
                text = item.get(field)
                if isinstance(text, str) and _ESCAPED_ID_CHARACTER.search(text):
                    raise _refuse(
                        f"{field} writes an identifier character as an escape",
                        pointer=f"/{WORKFLOW}/{STEPS}/{index}/step_data",
                    )
        steps.append({**step, "step_data": data})
    return {**export, WORKFLOW: {**export[WORKFLOW], STEPS: steps}}


def _step_injects(export: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The inject of each step, once decoded."""
    return [step["step_data"] for step in export[WORKFLOW][STEPS]] if has_workflow(export) else []


def _known(value: object, pointer: str) -> str:
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise _refuse(ID_NOT_KNOWN, pointer=pointer)
    return value


def _named_identifiers(step: Step) -> None:
    """The identifiers of a step and of its conditions that rewriting must find."""
    _known(step.identifier, f"{step.pointer}/step_id")
    for condition in step.conditions:
        _known(condition.identifier, f"{condition.pointer}/condition_id")
        if condition.parent is not None:
            _known(condition.parent, f"{condition.pointer}/condition_parent_id")


def _by_identifier(step: Step) -> dict[str, Condition]:
    """The conditions of a step by identifier; the graph checks made its copies identical."""
    return {str(condition.identifier): condition for condition in reversed(step.conditions)}


def _masked(value: Any) -> Any:
    """``value`` with every identifier quoted in its text replaced by one placeholder: what a
    signature hashes must not depend on the identifiers of the instance, nor on whether they were
    rewritten already."""
    if isinstance(value, list):
        return [_masked(child) for child in value]
    if isinstance(value, str):
        return _UUID_IN_TEXT.sub("<identifier>", value)
    return value


def _runs(inject: Mapping[str, Any], namespace: uuid.UUID) -> tuple[str, str]:
    """What a step runs, as its signature reads it: the stable identifier of its payload, from
    the payload's name, and its title, with the identifiers it quotes masked."""
    payload = _payload(inject) or {}
    return (
        stable_id(namespace, "payload", _base(payload)),
        _masked(_text(inject, "inject_title", "step_data")),
    )


def _previous_steps(
    previous: Mapping[str, Any] | None, namespace: uuid.UUID
) -> list[InjectSignature]:
    """The steps of the previous version, a stored file of the same entry, as the matcher reads
    them: stable identifier, what each runs and the steps it waits for. A refusal names the
    previous version as the input at fault."""
    if previous is None or not has_workflow(previous):
        return []
    try:
        workflow = previous[WORKFLOW]
        if not isinstance(workflow, dict):
            raise _refuse(f"{WORKFLOW} must be an object")
        steps = _objects(workflow, STEPS)
        if len(steps) > MAX_STEPS:  # the bound of an export, which the digests' depth relies on
            raise _refuse(TOO_MANY_STEPS)
        signatures = []
        seen: set[str] = set()
        for step in steps:
            identifier = _text(step, "step_id", STEPS)
            if not _UUID.fullmatch(identifier):
                raise _refuse(f"step identifier {identifier!r} is not a canonical UUID")
            if identifier in seen:
                raise _refuse(f"step identifier {identifier!r} appears twice")
            seen.add(identifier)
            inject = step.get("step_data")
            if not isinstance(inject, dict):
                raise _refuse("step_data must be an object")
            awaited = {
                _text(condition, "condition_value", CONDITIONS)
                for condition in _objects(step, CONDITIONS)
                if condition.get("condition_type") == "DEPEND_ON"
            }
            signatures.append(
                InjectSignature(identifier, *_runs(inject, namespace), tuple(sorted(awaited)))
            )
        _previous_digests(signatures)  # refuses a dependency on no step, or a loop
    except ExportStructureError as error:
        raise _refuse(error.what, "previous") from error
    return signatures


def _previous_digests(signatures: list[InjectSignature]) -> dict[str, str]:
    """The signature digest of each step of the previous version, by stable identifier: what it
    runs and the digests of the steps it waits for, as for the steps of the export."""
    by_id = {signature.id: signature for signature in signatures}
    digests: dict[str, str] = {}

    def digest(identifier: str, path: tuple[str, ...]) -> str:
        if identifier not in by_id:
            raise _refuse(f"a step waits for {identifier!r}, which is no step of it")
        if identifier in path:
            raise _refuse(f"step {identifier!r} waits for itself")
        if identifier not in digests:
            signature = by_id[identifier]
            awaited = sorted({digest(parent, (*path, identifier)) for parent in signature.parents})
            parts = [signature.contract, signature.title, awaited]
            digests[identifier] = hashlib.sha256(jcs(parts)).hexdigest()
        return digests[identifier]

    for signature in signatures:
        digest(signature.id, ())
    return digests


def _digests(steps: list[Step], data: Mapping[str, Any], namespace: uuid.UUID) -> dict[str, str]:
    """The signature digest of each step, by source identifier: the SHA-256 of the canonical
    form of the payload it runs, its title and the digests of the steps it waits for. The graph
    has no loop, so the digests of the steps waited for come first."""
    by_id = {str(step.identifier): step for step in steps}
    digests: dict[str, str] = {}

    def digest(identifier: str) -> str:
        if identifier not in digests:
            step, inject = by_id[identifier], data[identifier]
            awaited = sorted(  # a step named twice is waited for once
                {
                    digest(str(condition.value))
                    for condition in _by_identifier(step).values()
                    if condition.kind == "DEPEND_ON"
                }
            )
            signature = [*_runs(inject, namespace), awaited]
            digests[identifier] = hashlib.sha256(jcs(signature)).hexdigest()
        return digests[identifier]

    for step in steps:
        digest(str(step.identifier))
    return digests


_CONDITION_CONTENT = (
    "condition_type",
    "condition_key",
    "condition_key_types",
    "condition_mapping_type",
    "condition_value",
    "condition_name",
    "condition_description",
    "condition_is_root",
    "condition_step_from_id",
)


def _condition_identifiers(
    step: Step, step_id: str, known: Mapping[str, str], namespace: uuid.UUID
) -> dict[str, str]:
    """The stable identifier of each condition of a step: the step, the content keys of the
    condition's ancestors and its own, so that a child is known by what it is and where it sits,
    never by its place in a list. A condition's content holds the contents of the conditions under
    it, in sorted order, so that two groups that differ only below are two conditions. The
    identifiers its texts quote are masked; a filter's value is kept as it is, since it is what the
    filter compares with, and a dependency's names the step it waits for by its stable
    identifier, one of the ``known`` ones."""
    conditions = _by_identifier(step)
    under: dict[str, list[Condition]] = {}
    for condition in conditions.values():
        if condition.parent is not None:
            under.setdefault(str(condition.parent), []).append(condition)
    contents: dict[str, str] = {}

    def content(condition: Condition) -> str:
        source = str(condition.identifier)
        if source not in contents:  # the graph checks made the conditions one tree
            values = _masked([condition.fields.get(key) for key in _CONDITION_CONTENT])
            value = _CONDITION_CONTENT.index("condition_value")
            if condition.kind == "DEPEND_ON":
                values[value] = known[str(condition.value)]
            else:
                values[value] = condition.value
            below = sorted(  # a digest each, so that a deep tree's contents stay small
                hashlib.sha256(content(child).encode()).hexdigest()
                for child in under.get(source, [])
            )
            held = [values, below] if below else values  # a leaf's, as before groups were read
            contents[source] = json.dumps(held, ensure_ascii=False, sort_keys=True)
        return contents[source]

    def path(condition: Condition) -> list[str]:
        parent = conditions.get(str(condition.parent)) if condition.parent is not None else None
        return [*(path(parent) if parent is not None else []), content(condition)]

    targets: dict[str, str] = {}
    sources: dict[str, str] = {}
    for condition in step.conditions:
        source = str(condition.identifier)
        if source in targets:
            continue  # a copy
        target = stable_id(namespace, "condition", json.dumps([step_id, *path(condition)]))
        if target in sources:
            raise _refuse(CONDITION_SIBLINGS_SAME, pointer=condition.pointer)
        targets[source], sources[target] = target, source
    return targets


def _step_identifiers(
    workflow: Mapping[str, Any],
    namespace: uuid.UUID,
    known: Mapping[str, str],
    previous: list[InjectSignature],
    mapping: Mapping[str, str],
) -> tuple[list[tuple[str, str]], tuple[str, ...]]:
    """The source and stable identifier of each step, then of each condition, and the steps of
    the ``previous`` version left out. Each step keeps the identifier of the step of the previous
    version the matcher finds, or the explicit ``mapping`` names, by its source identifier;
    ``known`` holds the identifiers already derived for the rest of the scenario. A source
    identifier given to a step and to a condition is listed twice, so that registering both
    refuses it."""
    parsed = parsed_workflow(workflow)
    for step in parsed.steps:
        _named_identifiers(step)
    data = {
        str(step.identifier): inject
        for step, inject in zip(parsed.steps, _step_injects({WORKFLOW: workflow}), strict=True)
    }
    digests = _digests(list(parsed.steps), data, namespace)
    seen: set[str] = set()
    for step in parsed.steps:
        if digests[str(step.identifier)] in seen:
            raise _refuse(STEPS_SAME_SIGNATURE, pointer=step.pointer)
        seen.add(digests[str(step.identifier)])
    step_ids, removed = _matched_steps(parsed.steps, data, digests, namespace, previous, mapping)
    pairs = list(step_ids.items())
    for step in parsed.steps:
        conditions = _condition_identifiers(
            step, step_ids[str(step.identifier)], {**known, **step_ids}, namespace
        )
        pairs.extend(conditions.items())
    return pairs, removed


def _matched_steps(
    steps: Sequence[Step],
    data: Mapping[str, Any],
    digests: Mapping[str, str],
    namespace: uuid.UUID,
    previous: list[InjectSignature],
    mapping: Mapping[str, str],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """The stable identifier of each step by source identifier, the matcher reading each step by
    its digest, and the steps of the previous version left out."""
    new = [
        InjectSignature(
            digests[str(step.identifier)],
            *_runs(data[str(step.identifier)], namespace),
            tuple(
                sorted(
                    {
                        digests[str(condition.value)]
                        for condition in _by_identifier(step).values()
                        if condition.kind == "DEPEND_ON"
                    }
                )
            ),
        )
        for step in steps
    ]
    sources = {digest: source for source, digest in digests.items()}
    explicit = {digests[source]: target for source, target in mapping.items()}
    # A step whose content is unchanged keeps its identifier, whatever happened to the others.
    unchanged = {
        digest: target
        for target, digest in _previous_digests(previous).items()
        if digest in sources and digest not in explicit and target not in explicit.values()
    }
    try:
        matching = match_injects(
            namespace,
            new,
            previous,
            {**explicit, **unchanged},
            object_type="step",
            content_sources=True,
        )
    except AmbiguousInjectError as error:  # named by the export's identifier, not the digest
        raise AmbiguousInjectError(sources[error.source_id], error.candidates, "step") from error
    ids = {sources[digest]: target for digest, target in matching.ids.items()}
    return ids, matching.removed


def _stored_workflow(workflow: Mapping[str, Any], keys: StepDataKeys) -> dict[str, Any]:
    """The workflow as it is stored: every setting written, each step's inject without the keys
    a running instance writes, its empty input in one form, each condition once, and the steps
    and conditions in the order of their identifiers."""
    steps = []
    for step in workflow[STEPS]:
        conditions = {
            condition["condition_id"]: condition for condition in step.get(CONDITIONS) or []
        }
        steps.append(
            {
                **step,
                "step_data": stored_step_data(step["step_data"], keys),
                "step_input": canonical_step_text(step.get("step_input")),
                "step_output_parser": canonical_step_text(step.get("step_output_parser")),
                CONDITIONS: [conditions[key] for key in sorted(conditions)],
            }
        )
    return {**settled_workflow(workflow), STEPS: sorted(steps, key=lambda step: step["step_id"])}


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


def _unlink(document: dict[str, Any], rules: NormalisationRules) -> None:
    """Empty the lists a built-in contract's copy gains from the instance it was exported from,
    such as the techniques its collectors linked to the contract. A contract created from a
    payload keeps its own: they are the payload's content."""
    for inject in document.get(_INJECTS) or []:
        contract = inject.get(_CONTRACT)
        if isinstance(contract, dict) and not contract.get(_PAYLOAD):
            for key in rules.emptied_in_builtin_contracts & contract.keys():
                contract[key] = []


def _neutralise(document: dict[str, Any]) -> None:
    document[_INFORMATION]["scenario_mail_from"] = PLACEHOLDER_SENDER
    document["scenario_users"] = []
    for team in document.get("scenario_teams") or []:
        team["team_users"] = []
    for variable in document.get("scenario_variables") or []:
        variable.pop("variable_value", None)


def _listed(holder: object, key: str) -> list[Any]:
    """The list ``holder`` holds under ``key``; none when it holds no list there."""
    found = holder.get(key) if isinstance(holder, dict) else None
    return found if isinstance(found, list) else []


def _describe_payloads(document: dict[str, Any]) -> None:
    """Give each payload, of an inject or a step, without a description (absent, null or blank)
    its name as one: a payload of the catalogue has a description, and the starter pack's
    exports hold payloads without. Any other value is left for the payload checks."""
    holders = list(_listed(document, _INJECTS))
    workflow = document.get(WORKFLOW)
    holders += [step.get(STEP_DATA) for step in _listed(workflow, STEPS) if isinstance(step, dict)]
    for holder in holders:
        contract = holder.get(_CONTRACT) if isinstance(holder, dict) else None
        payload = contract.get(_PAYLOAD) if isinstance(contract, dict) else None
        if not isinstance(payload, dict):
            continue
        text = payload.get("payload_description")
        if text is None or (isinstance(text, str) and not text.strip()):
            payload["payload_description"] = payload.get("payload_name")


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
    refusal = next(export_refusals(export, rules.export_keys), None)
    if refusal is not None:
        raise _refuse(refusal.what, pointer=refusal.pointer)
    if has_workflow(export):
        workflow = parsed_workflow(export[WORKFLOW])
        refusal = (
            next(_step_refusals(export, rules.export_keys.step_data), None)
            or next(graph_refusals(workflow), None)
            or next(subset_refusals(workflow, rules.export_keys.condition_types), None)
        )
        if refusal is not None:
            raise _refuse(refusal.what, pointer=refusal.pointer)
        export = _with_decoded_steps(export)
    for key, what in NOT_SUPPORTED:
        if export.get(key):
            raise _refuse(f"{what} are not supported yet")
    if previous is not None and not isinstance(previous, dict):
        raise _refuse("the previous version must be a JSON object", "previous")
    identifiers, removed_injects, removed_steps = _identifiers(
        export, external_id, previous, mapping
    )
    document = _rewrite(export, identifiers.targets)  # new objects, export untouched
    _keep_filter_values(export, document)
    _name_domains(document)
    document = _strip(document, rules)
    _unlink(document, rules)
    _neutralise(document)
    _describe_payloads(document)
    document = _sort(document, rules)
    if has_workflow(document):
        document[WORKFLOW] = _stored_workflow(document[WORKFLOW], rules.export_keys.step_data)
    for collection, key, *_ in (*_OBJECTS, (_ARTICLES, "article_id"), (_INJECTS, "inject_id")):
        if collection in document and isinstance(document[collection], list):
            document[collection] = sorted(document[collection], key=lambda item: item[key])
    return Normalised(document, removed_injects, removed_steps)
