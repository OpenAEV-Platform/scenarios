"""The steps of a workflow in an export, as normalisation reads them: their checks, the stable
identifier of each step and of each of its conditions, and the form they are stored in."""

import hashlib
import json
import uuid
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from scenario_tools.domain.catalogue.export_reading import (
    ESCAPED_ID_CHARACTER,
    JSON_TEXT_FIELDS,
    UUID_IN_TEXT,
    ExportStructureError,
    check_decoded,
    decoded_text,
    embedded_payload,
    every_object,
    objects_in,
    payload_base,
    structure_error,
    text_in,
)
from scenario_tools.domain.catalogue.identifiers import (
    AmbiguousInjectError,
    InjectSignature,
    match_injects,
    stable_id,
)
from scenario_tools.domain.policy.step_rules import step_refusals
from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.domain.shared.identifiers import CANONICAL_UUID
from scenario_tools.domain.shared.stored import STEPS, WORKFLOW
from scenario_tools.domain.shared.stored_workflow import Condition, Step, parsed_workflow
from scenario_tools.domain.shared.workflow import (
    CONDITION_SIBLINGS_SAME,
    CONDITIONS,
    ID_NOT_KNOWN,
    MAX_STEPS,
    STEP_DATA_UNREADABLE,
    STEPS_SAME_SIGNATURE,
    TOO_MANY_STEPS,
    Refusal,
    StepDataKeys,
    has_workflow,
    settled_workflow,
)

# A step's inject is stored as an object four levels down: in the workflow, in its list of steps,
# in its step.
_STEP_DATA_DEPTH = 4


def decoded_step_data(text: str) -> Any:
    """A step's inject given as JSON text, decoded within the readers' bounds; one that cannot be
    read is ``ExportStructureError``."""
    return decoded_text(text, "step_data", copies=1, depth=_STEP_DATA_DEPTH)


def _decoded_or_none(text: str, field: str) -> Any:
    """The JSON text of a step's field decoded within the readers' bounds, or ``None``: a step's
    inject may hold one contract copy."""
    try:
        if field == "step_data":
            return decoded_text(text, field, copies=1, depth=_STEP_DATA_DEPTH)
        return decoded_text(text, field)
    except ExportStructureError:
        return None


def canonical_step_text(value: object) -> str:
    """A step's empty input or output parser in one form, compact JSON text. Only for a step that
    passed its checks, whose input is empty JSON text or absent."""
    decoded = {} if value is None else json.loads(str(value))
    return json.dumps(decoded, separators=(",", ":"), sort_keys=True)


def workflow_step_refusals(export: Mapping[str, Any], keys: StepDataKeys) -> Iterator[Refusal]:
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
        check_decoded(data, "step_data", copies=1, depth=_STEP_DATA_DEPTH)
    except ExportStructureError:
        return False
    return True


def stored_step_data(data: Mapping[str, Any], keys: StepDataKeys) -> dict[str, Any]:
    """A step's inject as it is stored: without the keys a running instance writes."""
    return {key: value for key, value in data.items() if key not in keys.removed}


def with_decoded_steps(export: dict[str, Any]) -> dict[str, Any]:
    """``export`` with the inject of each step as an object, in new objects for the parts that
    change; the escape guard reads the text that decoding uncovers."""
    steps = []
    for index, step in enumerate(export[WORKFLOW][STEPS]):
        data = step["step_data"]
        if isinstance(data, str):
            data = decoded_text(data, "step_data", copies=1, depth=_STEP_DATA_DEPTH)
        for item in every_object(data):
            for field in JSON_TEXT_FIELDS:
                text = item.get(field)
                if isinstance(text, str) and ESCAPED_ID_CHARACTER.search(text):
                    raise structure_error(
                        f"{field} writes an identifier character as an escape",
                        pointer=f"/{WORKFLOW}/{STEPS}/{index}/step_data",
                    )
        steps.append({**step, "step_data": data})
    return {**export, WORKFLOW: {**export[WORKFLOW], STEPS: steps}}


def step_injects(export: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The inject of each step, once decoded."""
    return [step["step_data"] for step in export[WORKFLOW][STEPS]] if has_workflow(export) else []


def _known(value: object, pointer: str) -> str:
    if not isinstance(value, str) or not CANONICAL_UUID.fullmatch(value):
        raise structure_error(ID_NOT_KNOWN, pointer=pointer)
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
        return UUID_IN_TEXT.sub("<identifier>", value)
    return value


def _runs(inject: Mapping[str, Any], namespace: uuid.UUID) -> tuple[str, str]:
    """What a step runs, as its signature reads it: the stable identifier of its payload, from
    the payload's name, and its title, with the identifiers it quotes masked."""
    payload = embedded_payload(inject) or {}
    return (
        stable_id(namespace, "payload", payload_base(payload)),
        _masked(text_in(inject, "inject_title", "step_data")),
    )


def previous_step_signatures(
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
            raise structure_error(f"{WORKFLOW} must be an object")
        steps = objects_in(workflow, STEPS)
        if len(steps) > MAX_STEPS:  # the bound of an export, which the digests' depth relies on
            raise structure_error(TOO_MANY_STEPS)
        signatures = []
        seen: set[str] = set()
        for step in steps:
            identifier = text_in(step, "step_id", STEPS)
            if not CANONICAL_UUID.fullmatch(identifier):
                raise structure_error(f"step identifier {identifier!r} is not a canonical UUID")
            if identifier in seen:
                raise structure_error(f"step identifier {identifier!r} appears twice")
            seen.add(identifier)
            inject = step.get("step_data")
            if not isinstance(inject, dict):
                raise structure_error("step_data must be an object")
            awaited = {
                text_in(condition, "condition_value", CONDITIONS)
                for condition in objects_in(step, CONDITIONS)
                if condition.get("condition_type") == "DEPEND_ON"
            }
            signatures.append(
                InjectSignature(identifier, *_runs(inject, namespace), tuple(sorted(awaited)))
            )
        _previous_digests(signatures)  # refuses a dependency on no step, or a loop
    except ExportStructureError as error:
        raise structure_error(error.what, "previous") from error
    return signatures


def _previous_digests(signatures: list[InjectSignature]) -> dict[str, str]:
    """The signature digest of each step of the previous version, by stable identifier: what it
    runs and the digests of the steps it waits for, as for the steps of the export."""
    by_id = {signature.id: signature for signature in signatures}
    digests: dict[str, str] = {}

    def digest(identifier: str, path: tuple[str, ...]) -> str:
        if identifier not in by_id:
            raise structure_error(f"a step waits for {identifier!r}, which is no step of it")
        if identifier in path:
            raise structure_error(f"step {identifier!r} waits for itself")
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
            raise structure_error(CONDITION_SIBLINGS_SAME, pointer=condition.pointer)
        targets[source], sources[target] = target, source
    return targets


def step_identifiers(
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
        for step, inject in zip(parsed.steps, step_injects({WORKFLOW: workflow}), strict=True)
    }
    digests = _digests(list(parsed.steps), data, namespace)
    seen: set[str] = set()
    for step in parsed.steps:
        if digests[str(step.identifier)] in seen:
            raise structure_error(STEPS_SAME_SIGNATURE, pointer=step.pointer)
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


def stored_workflow(workflow: Mapping[str, Any], keys: StepDataKeys) -> dict[str, Any]:
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
