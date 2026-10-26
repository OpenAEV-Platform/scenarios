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

import json
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.catalogue.export_reading import (
    CONTENT,
    CONTRACT,
    ESCAPED_ID_CHARACTER,
    INFORMATION,
    INJECTS,
    JSON_TEXT_FIELDS,
    PAYLOAD,
    UUID_IN_TEXT,
    ExportStructureError,
    decoded_text,
    embedded_payload,
    every_object,
    name_in,
    objects_in,
    payload_base,
    structure_error,
    text_in,
)
from scenario_tools.domain.catalogue.identifiers import (
    NS_OPENAEV_SCENARIOS,
    InjectSignature,
    match_injects,
    scenario_namespace,
    stable_id,
)
from scenario_tools.domain.catalogue.volatile_fields import (
    NormalisationRules,
    describe_payloads,
    name_domains,
    neutralise,
    sort_sets,
    strip_volatile,
    unlink_builtin_lists,
)
from scenario_tools.domain.catalogue.workflow_steps import (
    previous_step_signatures,
    step_identifiers,
    step_injects,
    stored_workflow,
    with_decoded_steps,
    workflow_step_refusals,
)
from scenario_tools.domain.policy.workflow_rules import graph_refusals, subset_refusals
from scenario_tools.domain.shared.identifiers import CANONICAL_UUID
from scenario_tools.domain.shared.stored import STEPS, WORKFLOW
from scenario_tools.domain.shared.stored_workflow import parsed_workflow
from scenario_tools.domain.shared.workflow import CONDITIONS, export_refusals, has_workflow

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


@dataclass(frozen=True)
class Normalised:
    """The normalised document, and the injects and steps of the previous version it no longer
    has."""

    document: dict[str, Any]
    removed_injects: tuple[str, ...]
    removed_steps: tuple[str, ...] = ()


class _Identifiers:
    """The map from source identifiers to normalised ones; one source never gets two."""

    def __init__(self) -> None:
        self.targets: dict[str, str] = {}

    def add(self, source: str, target: str) -> None:
        if not CANONICAL_UUID.fullmatch(source):
            raise structure_error(f"identifier {source!r} is not a canonical UUID")
        if self.targets.setdefault(source, target) != target:
            raise structure_error(f"identifier {source!r} names two different objects")


def _signature(inject: Mapping[str, Any], namespace: uuid.UUID) -> InjectSignature:
    """The contract part of the signature is the payload's stable ID for an inject that runs a
    payload: a contract created from a payload is specific to an instance, the payload's name is
    not."""
    payload = embedded_payload(inject)
    contract = inject.get(CONTRACT) or {}
    if payload is not None:
        key = stable_id(namespace, "payload", payload_base(payload))
    else:
        key = contract.get("injector_contract_id") or ""
    relations = inject.get("inject_depends_on")
    if relations is None:
        relations = []
    if not isinstance(relations, list):
        raise structure_error("inject_depends_on must be a list")
    inject_id = text_in(inject, "inject_id", "inject")
    parents = []
    for relation in relations:
        link = relation.get("dependency_relationship") if isinstance(relation, dict) else None
        if not isinstance(link, dict):
            raise structure_error("inject_depends_on must hold dependency relationships")
        if link.get("inject_children_id") != inject_id:
            raise structure_error(f"a dependency of inject {inject_id!r} names another child")
        parents.append(text_in(link, "inject_parent_id", "dependency_relationship"))
    return InjectSignature(
        inject_id, str(key), text_in(inject, "inject_title", "inject"), tuple(parents)
    )


def _catalogue_objects(export: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Every object of the export, and those inside the JSON text of contract copies, where the
    platform writes the domains of a contract."""
    for item in every_object(export):
        yield item
        if isinstance(item.get(CONTENT), str):
            yield from every_object(decoded_text(item[CONTENT]))


def _check_injects(signatures: list[InjectSignature]) -> None:
    if len(signatures) > MAX_INJECTS:
        raise structure_error(f"more than {MAX_INJECTS} injects")
    identifiers = {signature.id for signature in signatures}
    if len(identifiers) != len(signatures):
        raise structure_error("an inject identifier appears twice")
    for signature in signatures:
        if not identifiers.issuperset(signature.parents):
            raise structure_error(
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
        information = previous.get(INFORMATION)
        if not isinstance(information, dict) or information.get("scenario_id") != scenario_id:
            raise structure_error("its scenario identifier is not this entry's")
        signatures = [_signature(inject, namespace) for inject in objects_in(previous, INJECTS)]
        _check_injects(signatures)
        for signature in signatures:
            if not CANONICAL_UUID.fullmatch(signature.id):
                raise structure_error(f"inject identifier {signature.id!r} is not a canonical UUID")
    except ExportStructureError as error:
        raise structure_error(error.what, "previous") from error
    return signatures


def _object_identifiers(
    export: Mapping[str, Any], namespace: uuid.UUID, identifiers: _Identifiers
) -> dict[str, str]:
    """The identifiers of the objects named in their collection, from their names, each name
    once in a collection; and the name of each channel, by its source identifier."""
    channels: dict[str, str] = {}
    for collection, key, name_key, object_type in _OBJECTS:
        named: set[str] = set()
        for item in objects_in(export, collection):
            source, name = text_in(item, key, collection), name_in(item, name_key, collection)
            if name in named:
                raise structure_error(f"two objects of {collection} are named {name!r}")
            named.add(name)
            identifiers.add(source, stable_id(namespace, object_type, name))
            if object_type == "channel":
                channels[source] = name
    return channels


def _article_identifiers(
    export: Mapping[str, Any],
    namespace: uuid.UUID,
    channels: Mapping[str, str],
    identifiers: _Identifiers,
) -> None:
    """The identifiers of the articles, from their channel and name: an article's name is
    unique within its channel only, which must be one of the scenario's."""
    articles: set[str] = set()
    for item in objects_in(export, _ARTICLES):
        source, name = (
            text_in(item, "article_id", _ARTICLES),
            name_in(item, "article_name", _ARTICLES),
        )
        channel = channels.get(text_in(item, "article_channel", _ARTICLES))
        if channel is None:
            raise structure_error(f"article {name!r} has no channel of the scenario")
        article_key = json.dumps([channel, name])
        if article_key in articles:
            raise structure_error(f"two articles of channel {channel!r} are named {name!r}")
        articles.add(article_key)
        identifiers.add(source, stable_id(namespace, "article", article_key))


def _contract_identifiers(
    export: Mapping[str, Any], namespace: uuid.UUID, identifiers: _Identifiers
) -> None:
    """The identifiers of the contracts of injects and steps: a built-in contract keeps its
    own; a payload and its contract take theirs from the payload's base name, one version of a
    payload in a scenario."""
    payloads: dict[str, tuple[str, str]] = {}  # the source and name of each base name
    for inject in [*objects_in(export, INJECTS), *step_injects(export)]:
        payload = embedded_payload(inject)
        contract_copy = inject.get(CONTRACT)
        if payload is None and isinstance(contract_copy, dict):
            custom = contract_copy.get("injector_contract_custom")
            if custom is not None and not isinstance(custom, bool):
                raise structure_error("injector_contract_custom must be true or false")
            if custom:
                # Its identifier belongs to one instance, and the contract exists on no other.
                raise structure_error("custom contracts without a payload are not supported yet")
            # A built-in contract keeps its identifier: registered as it is, so that it is
            # checked like any other and no other object can take it.
            built_in = text_in(contract_copy, "injector_contract_id", CONTRACT)
            identifiers.add(built_in, built_in)
        if payload is not None:
            source = text_in(payload, "payload_id", PAYLOAD)
            name, base = name_in(payload, "payload_name", PAYLOAD), payload_base(payload)
            first_source, first_name = payloads.setdefault(base, (source, name))
            if first_source == source and first_name != name:
                raise structure_error(f"one payload is named {first_name!r} and {name!r}")
            if first_source != source:
                if first_name == name:
                    raise structure_error(f"two payloads are named {name!r}")
                raise structure_error(
                    f"two versions of the payload {base!r} are embedded: a scenario embeds one "
                    "version of a payload"
                )
            identifiers.add(source, stable_id(namespace, "payload", base))
            contract = text_in(inject[CONTRACT], "injector_contract_id", CONTRACT)
            identifiers.add(contract, stable_id(namespace, "contract", base))


def _catalogue_identifiers(export: Mapping[str, Any], identifiers: _Identifiers) -> None:
    """The identifiers of the catalogue's objects anywhere in the export (techniques, phases,
    domains), from their shared key, which an object that gives an identifier must have."""
    for item in _catalogue_objects(export):
        for key, external_key, object_type in _CATALOGUE:
            if item.get(key) is not None:  # an identifier given: its shared key is required
                if not isinstance(item[key], str):
                    raise structure_error(f"{key} must be text")
                if not isinstance(item.get(external_key), str) or not item[external_key]:
                    raise structure_error(f"{key} needs a non-empty {external_key}")
                target = stable_id(NS_OPENAEV_SCENARIOS, object_type, item[external_key])
                identifiers.add(item[key], target)


def _identifiers(
    export: Mapping[str, Any],
    external_id: str,
    previous: Mapping[str, Any] | None,
    mapping: Mapping[str, str] | None,
) -> tuple[_Identifiers, tuple[str, ...], tuple[str, ...]]:
    namespace = scenario_namespace(external_id)
    identifiers = _Identifiers()
    scenario_id = stable_id(namespace, "scenario", external_id)
    identifiers.add(text_in(export[INFORMATION], "scenario_id", INFORMATION), scenario_id)
    channels = _object_identifiers(export, namespace, identifiers)
    _article_identifiers(export, namespace, channels, identifiers)
    _contract_identifiers(export, namespace, identifiers)
    _catalogue_identifiers(export, identifiers)
    old = _previous_signatures(previous, namespace, scenario_id)  # also checks the entry
    mapping = dict(mapping or {})
    previous_steps = previous_step_signatures(previous, namespace)
    removed_steps = tuple(sorted(step.id for step in previous_steps))
    if has_workflow(export):
        sources = {
            step.get("step_id")
            for step in export[WORKFLOW][STEPS]
            if isinstance(step.get("step_id"), str)  # others are refused with their pointer
        }
        step_mapping = {key: mapping.pop(key) for key in sorted(mapping) if key in sources}
        pairs, removed_steps = step_identifiers(
            export[WORKFLOW],
            namespace,
            identifiers.targets,
            previous_steps,
            step_mapping,
        )
        for source, target in pairs:
            identifiers.add(source, target)
    new = [_signature(inject, namespace) for inject in objects_in(export, INJECTS)]
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
            raise structure_error("two keys of an object name the same identifier")
        return rewritten
    if isinstance(value, list):
        return [_rewrite(child, targets) for child in value]
    if isinstance(value, str):
        return UUID_IN_TEXT.sub(
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
    if not CANONICAL_UUID.fullmatch(external_id):
        raise ValueError(f"external_id {external_id!r} must be a canonical UUID")
    export = _checked_export(export, rules)
    if previous is not None and not isinstance(previous, dict):
        raise structure_error("the previous version must be a JSON object", "previous")
    identifiers, removed_injects, removed_steps = _identifiers(
        export, external_id, previous, mapping
    )
    document = _rewrite(export, identifiers.targets)  # new objects, export untouched
    _keep_filter_values(export, document)
    name_domains(document)
    document = strip_volatile(document, rules)
    unlink_builtin_lists(document, rules)
    neutralise(document)
    describe_payloads(document)
    document = sort_sets(document, rules)
    if has_workflow(document):
        document[WORKFLOW] = stored_workflow(document[WORKFLOW], rules.export_keys.step_data)
    _sort_collections(document)
    return Normalised(document, removed_injects, removed_steps)


def _checked_export(export: object, rules: NormalisationRules) -> dict[str, Any]:
    """``export``, refused unless normalisation can read it, with the data of its chaining steps
    decoded."""
    if not isinstance(export, dict):
        raise structure_error("not a JSON object")
    if not isinstance(export.get(INFORMATION), dict):
        raise structure_error(f"{INFORMATION} must be an object")
    for item in every_object(export):
        for field in JSON_TEXT_FIELDS:
            text = item.get(field)
            if isinstance(text, str) and ESCAPED_ID_CHARACTER.search(text):
                raise structure_error(f"{field} writes an identifier character as an escape")
    refusal = next(export_refusals(export, rules.export_keys), None)
    if refusal is not None:
        raise structure_error(refusal.what, pointer=refusal.pointer)
    if has_workflow(export):
        workflow = parsed_workflow(export[WORKFLOW])
        refusal = (
            next(workflow_step_refusals(export, rules.export_keys.step_data), None)
            or next(graph_refusals(workflow), None)
            or next(subset_refusals(workflow, rules.export_keys.condition_types), None)
        )
        if refusal is not None:
            raise structure_error(refusal.what, pointer=refusal.pointer)
        export = with_decoded_steps(export)
    for key, what in NOT_SUPPORTED:
        if export.get(key):
            raise structure_error(f"{what} are not supported yet")
    return export


def _sort_collections(document: dict[str, Any]) -> None:
    """Each collection of ``document`` sorted by the identifier of its items, in place."""
    for collection, key, *_ in (*_OBJECTS, (_ARTICLES, "article_id"), (INJECTS, "inject_id")):
        if collection in document and isinstance(document[collection], list):
            document[collection] = sorted(document[collection], key=lambda item: item[key])
