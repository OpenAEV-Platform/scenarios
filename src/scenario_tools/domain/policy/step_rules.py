"""The rules a step of a workflow keeps before it is stored.

A step runs the inject of a command payload on the platform's implant, and holds nothing of the
instance it was exported from: no run state, no input, no target, asset, team or document, no key
outside the classification of its inject. The rules read the step as the export wrote it; JSON
text inside it is decoded by the caller, within the bounds the readers apply.
"""

from collections.abc import Callable, Iterator, Mapping
from typing import Any

from scenario_tools.domain.shared.workflow import (
    KEY_RUNTIME,
    KEY_UNKNOWN,
    STEP_ACTION,
    STEP_DATA_UNREADABLE,
    STEP_FIELD,
    STEP_INJECTOR,
    STEP_INPUT,
    STEP_PAYLOAD,
    STEP_TARGETS,
    STEP_VALUE,
    Refusal,
    StepDataKeys,
    key_pointer,
)

# Decodes the JSON text of a field (the text, the field's name), or gives None when the text is
# not JSON within the readers' bounds.
Decoder = Callable[[str, str], Any]

_CONTRACT, _PAYLOAD = "inject_injector_contract", "injector_contract_payload"
_CONTENT = "inject_content"
_CONTRACT_CONTENT = "injector_contract_content"
_EMPTY_TEXTS: tuple[object, ...] = ({}, {"input": []})
_RUN_STATE: tuple[tuple[str, tuple[object, ...]], ...] = (
    ("step_output", (None,)),
    ("step_condition_executed", (None,)),
    ("step_limit_execution", (None, 0)),
)
# Keys that belong to where the scenario is installed: a value is a target, never run state.
_INSTALLATION = frozenset(
    {"inject_assets", "inject_asset_groups", "inject_teams", "inject_documents", "inject_all_teams"}
)
# Fields of a contract whose content names targets, by their declared type.
_TARGET_FIELD_TYPES = frozenset({"asset", "asset-group", "targeted-asset"})
_NO_TARGET: tuple[object, ...] = (None, "", [], {})


def _same(value: object, allowed: object) -> bool:
    """Equal and of the same type, so that ``True`` is never ``1`` nor ``0`` ``False``."""
    return type(value) is type(allowed) and value == allowed


def _held(value: object, allowed: tuple[object, ...]) -> bool:
    return any(_same(value, candidate) for candidate in allowed)


def _object(value: object, field: str, decode: Decoder) -> object:
    """``value``, decoded when it is JSON text."""
    return decode(value, field) if isinstance(value, str) else value


def _keys(data: Mapping[str, Any], at: str, keys: StepDataKeys) -> Iterator[Refusal]:
    for key in data:
        if key in keys.refused:
            yield Refusal(KEY_RUNTIME, key_pointer(at, key))
        elif key not in keys.known:
            yield Refusal(KEY_UNKNOWN, key_pointer(at, key))


def _values(data: Mapping[str, Any], at: str, keys: StepDataKeys) -> Iterator[Refusal]:
    for key, allowed in keys.must_equal.items():
        if key in data and not _held(data[key], allowed):
            yield Refusal(STEP_TARGETS if key in _INSTALLATION else STEP_VALUE, f"{at}/{key}")


def _tags(data: Mapping[str, Any], at: str, tag_ids: frozenset[str]) -> Iterator[Refusal]:
    """The tags of a step name tags of the scenario, which the import carries over."""
    tags = data.get("inject_tags")
    if tags is None:
        return
    if not isinstance(tags, list) or not all(
        isinstance(tag, str) and tag in tag_ids for tag in tags
    ):
        yield Refusal(STEP_VALUE, f"{at}/inject_tags")


def _target_fields(contract: Mapping[str, Any], decode: Decoder) -> frozenset[str] | None:
    """The keys of the contract's fields whose declared type names targets, or ``None`` when
    the contract's content cannot be read as an object."""
    raw = contract.get(_CONTRACT_CONTENT)
    if raw is None:
        return frozenset()
    content = _object(raw, _CONTRACT_CONTENT, decode)
    if not isinstance(content, Mapping):
        return None
    fields = content.get("fields")
    return frozenset(
        field["key"]
        for field in (fields if isinstance(fields, list) else [])
        if isinstance(field, Mapping)
        and isinstance(field.get("type"), str)
        and field["type"] in _TARGET_FIELD_TYPES
        and isinstance(field.get("key"), str)
    )


def _targets(
    data: Mapping[str, Any],
    at: str,
    keys: StepDataKeys,
    contract: Mapping[str, Any],
    decode: Decoder,
) -> Iterator[Refusal]:
    fields = _target_fields(contract, decode)
    if fields is None:
        yield Refusal(STEP_DATA_UNREADABLE, f"{at}/{_CONTRACT}/{_CONTRACT_CONTENT}")
        fields = frozenset()
    raw = data.get(_CONTENT)
    if raw is None:
        return
    content = _object(raw, _CONTENT, decode)
    if not isinstance(content, Mapping):
        yield Refusal(STEP_DATA_UNREADABLE, f"{at}/{_CONTENT}")
        return
    for key in sorted(keys.content_target_keys | fields):
        if content.get(key) not in _NO_TARGET:
            yield Refusal(STEP_TARGETS, key_pointer(f"{at}/{_CONTENT}", key))
    if content.get("target_selector") == "manual":  # targets typed by hand, not chosen assets
        yield Refusal(STEP_TARGETS, f"{at}/{_CONTENT}/target_selector")


def _injector(
    data: Mapping[str, Any], at: str, keys: StepDataKeys, contract: Mapping[str, Any]
) -> Iterator[Refusal]:
    """The contract states a known injector type, the inject has that type, and names one known
    injector of it or none: the platform then takes the contract's. A contract that lists its
    injectors lists known ones of that type; a stored contract no longer lists them, as
    normalisation removes the list."""
    refusal = Refusal(STEP_INJECTOR, f"{at}/inject_injector")
    kind = contract.get("injector_contract_injector_type")
    if not (
        isinstance(kind, str)
        and kind in keys.injectors.values()
        and _same(data.get("inject_type"), kind)
    ):
        yield refusal
        return
    allowed = {item for item, item_kind in keys.injectors.items() if item_kind == kind}
    if "injector_contract_injectors" in contract:
        listed = contract["injector_contract_injectors"]
        if not (
            isinstance(listed, list)
            and listed
            and all(isinstance(item, str) and item in allowed for item in listed)
        ):
            yield refusal
            return
        allowed = set(listed)
    injector = data.get("inject_injector")
    if injector is not None and (not isinstance(injector, str) or injector not in allowed):
        yield refusal


def _payload(contract: Mapping[str, Any], at: str) -> Iterator[Refusal]:
    payload = contract.get(_PAYLOAD)
    if not isinstance(payload, Mapping) or payload.get("payload_type") != "Command":
        yield Refusal(STEP_PAYLOAD, f"{at}/{_CONTRACT}/{_PAYLOAD}")


def inject_refusals(
    data: Mapping[str, Any],
    at: str,
    keys: StepDataKeys,
    tag_ids: frozenset[str],
    decode: Decoder,
) -> Iterator[Refusal]:
    """The refusals of a step's inject ``data``, found at ``at``: its keys, the values only a
    running instance gives, its tags, its targets, its payload and its injector."""
    contract = data.get(_CONTRACT)
    contract = contract if isinstance(contract, Mapping) else {}
    yield from _keys(data, at, keys)
    yield from _values(data, at, keys)
    yield from _tags(data, at, tag_ids)
    yield from _targets(data, at, keys, contract, decode)
    yield from _payload(contract, at)
    yield from _injector(data, at, keys, contract)


def step_refusals(
    step: Mapping[str, Any],
    at: str,
    keys: StepDataKeys,
    tag_ids: frozenset[str],
    decode: Decoder,
) -> Iterator[Refusal]:
    """The refusals of ``step``, found at ``at``: its action, its run state, its input and
    output parser, and the inject it runs."""
    if step.get("step_action_class") != "INJECT_EXECUTION":
        yield Refusal(STEP_ACTION, f"{at}/step_action_class")
    for key, allowed in _RUN_STATE:
        if not _held(step.get(key), allowed):
            yield Refusal(STEP_FIELD, f"{at}/{key}")
    for key in ("step_input", "step_output_parser"):
        value = step.get(key)
        decoded = {} if value is None else decode(value, key) if isinstance(value, str) else None
        if decoded not in _EMPTY_TEXTS:
            yield Refusal(STEP_INPUT, f"{at}/{key}")
    data = _object(step.get("step_data"), "step_data", decode)
    if not isinstance(data, Mapping):
        yield Refusal(STEP_DATA_UNREADABLE, f"{at}/step_data")
        return
    yield from inject_refusals(data, f"{at}/step_data", keys, tag_ids, decode)
