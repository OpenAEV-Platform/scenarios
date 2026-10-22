"""The workflow of a stored scenario as the checks first read it: whether there is one, the keys
of its nodes and its bounds.

A scenario in chaining holds its injects in the steps of a workflow instead of the injects part.
The keys of the workflow, of a step, of a condition, of a scope rule and of a scope variable are
closed lists taken from the platform's exporter and kept as data: a key outside them may carry a
behaviour no reviewer saw, so it is refused rather than dropped. Each refusal has a fixed message
and the JSON pointer of the node at fault, which names a key only when the key is a plain name.
"""

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, TypeGuard

from scenario_tools.domain.shared.stored import INJECTS, STEPS, WORKFLOW

CONDITIONS = "step_conditions"
_EXPORT_VERSION = "export_version"
_SCOPE_RULES = "workflow_scope_rules"
_SCOPE_VARIABLES = "workflow_scope_variables"
_STANDALONE = "workflow_standalone_conditions"
_TEAM_MEMBERS = "workflow_scope_rule_team_members"
_ID, _PARENT = "condition_id", "condition_parent_id"
_STEP_ID = "step_id"
DEPEND_ON = "DEPEND_ON"
_VERSION = "workflow_version"
_TIMEOUT_ON, _TIMEOUT = "workflow_timeout_enabled", "workflow_timeout_seconds"
_SAFE_MODE = "workflow_safe_mode_enabled"
_PACE_ON = "workflow_rate_limit_enabled"
_ATTEMPTS, _PERIOD = "workflow_max_attempts", "workflow_max_temporal_rate_seconds"
_PLAIN_KEY = re.compile(r"[A-Za-z0-9_]{1,64}")

MAX_STEPS = 50
MAX_CONDITIONS = 50  # distinct conditions in one step
MAX_DEPTH = 16  # levels below the root of a step's conditions
MAX_SCOPE = 50  # scope rules, scope variables, or conditions linked to no step
# A step's list may hold one condition more than once (once for each way the exporter reaches
# it); this bounds the list itself, whatever the repetitions.
MAX_ENTRIES = MAX_CONDITIONS * (MAX_DEPTH + 1)

# The bounds of the settings: the delay is always on and at most an hour; the pace, when on,
# keeps within what the platform accepts.
TIMEOUT_RANGE = (60, 3600)
ATTEMPTS_RANGE = (1, 99)
PERIOD_RANGE = (1, 5940)
# What the platform's importer applies to a setting the export does not hold.
SETTINGS_WHEN_ABSENT: Mapping[str, object] = MappingProxyType(
    {
        _PACE_ON: False,
        _ATTEMPTS: None,
        _PERIOD: None,
        _TIMEOUT_ON: True,
        _TIMEOUT: 3600,
        _SAFE_MODE: True,
    }
)

EXPORT_VERSION_UNKNOWN = "the export's version is not one these tools read"
INJECTS_AND_WORKFLOW = "a scenario holds injects or a workflow, never both"
WORKFLOW_NO_STEP = "a workflow holds at least one step"
NOT_AN_OBJECT = "this node must be an object"
NOT_A_LIST = "this node must be a list"
KEY_UNKNOWN = "this node holds a key the platform does not export here"
KEY_LEGACY = (
    "this node holds a legacy key that is no longer read: export the scenario again from a "
    "current platform"
)
KEY_RUNTIME = "this key is read by the platform when a step runs, never written by its export"
STEP_ACTION = "a step runs an inject: its action is INJECT_EXECUTION"
STEP_FIELD = "a stored step holds no run state: no output, no condition executed, no limit"
STEP_INPUT = 'a step\'s input and output parser are empty: "{}" or {"input": []} as JSON text'
STEP_DATA_UNREADABLE = "a step's inject must be a JSON object, or JSON text holding one"
STEP_VALUE = "this key of a step's inject holds a value only a running instance gives it"
STEP_TARGETS = (
    "a step names no target, asset, team or document: they are set where the scenario is "
    "installed; empty this key in the export"
)
STEP_INJECTOR = "a step runs on the platform's implant, as its contract and inject type say"
STEP_PAYLOAD = "a step's contract embeds a payload that runs a command"
TOO_MANY_STEPS = f"a workflow holds at most {MAX_STEPS} steps"
TOO_MANY_CONDITIONS = f"a step holds at most {MAX_CONDITIONS} conditions"
TOO_MANY_ENTRIES = f"this list of the workflow holds at most {MAX_SCOPE} entries"
SETTINGS_BOUNDS = (
    "this setting is outside its bounds: the delay is on and between "
    f"{TIMEOUT_RANGE[0]} and {TIMEOUT_RANGE[1]} seconds, safe mode is on, and the pace is off "
    f"with no values, or on with {ATTEMPTS_RANGE[0]} to {ATTEMPTS_RANGE[1]} attempts per "
    f"{PERIOD_RANGE[0]} to {PERIOD_RANGE[1]} seconds"
)
SCOPE_NOT_EMPTY = (
    "a scenario of the catalogue has no scope: its targets are set where it is installed; empty "
    "this list in the export"
)
STANDALONE_NOT_EMPTY = "every condition belongs to a step: this list must be empty"
TOO_DEEP = (
    f"a step's conditions are nested at most {MAX_DEPTH} levels below their root, "
    "and no condition is its own ancestor"
)
STEP_ID_TWICE = "each step of a workflow has its own identifier"
CONDITION_ID_TWICE = "the copies of a condition in a step are the same condition"
CONDITION_SHARED = "a condition belongs to one step"
CONDITION_PARENT_ELSEWHERE = "a condition's parent is a condition of the same step"
CONDITION_ROOT = (
    "a step's conditions form one tree: one root, with no parent, and every other condition "
    "under a parent of the step"
)
CONDITION_STEP_FROM = "a condition reads the output of no step: its step_from is empty"
DEPEND_ON_NULL = "a dependency names the step it waits for"
DEPEND_ON_DANGLING = "a dependency waits for a step of the scenario"
CYCLE = "a step never waits for itself, directly or through other steps"
ID_NOT_KNOWN = "this identifier must be a canonical UUID, which normalisation rewrites"
STEPS_SAME_SIGNATURE = (
    "two steps run the same payload under the same title after the same steps: give them "
    "different titles"
)
CONDITION_MAPPER = (
    "a condition never maps the output of a step into another: the data passed between steps "
    "is not reviewed"
)
CONDITION_NOT_YET = "this type of condition is not supported yet: a step waits for one step or none"
CONDITION_DEPEND_NESTED = "a dependency is the only condition of its step"
CONDITION_SIBLINGS_SAME = "two conditions under one parent are the same: keep one"


@dataclass(frozen=True)
class Refusal:
    """Why a stored scenario is refused (a fixed message) and where (a JSON pointer)."""

    what: str
    pointer: str


@dataclass(frozen=True)
class StepDataKeys:
    """How each key of a step's inject is treated: removed when stored, held to one of a few
    values (an absent key counting as the first), or kept; and the injectors a step may use."""

    removed: frozenset[str]
    must_equal: Mapping[str, tuple[object, ...]]
    kept: frozenset[str]
    refused: frozenset[str]
    injectors: Mapping[str, str]  # identifier to type
    content_target_keys: frozenset[str]

    @property
    def known(self) -> frozenset[str]:
        return self.removed | self.kept | frozenset(self.must_equal)

    @classmethod
    def from_document(cls, document: object) -> "StepDataKeys":
        if not isinstance(document, Mapping):
            raise ValueError("export-keys: step_data must be an object")

        def names(key: str) -> frozenset[str]:
            value = document.get(key)
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item for item in value
            ):
                raise ValueError(f"export-keys: step_data.{key} must be a list of names")
            return frozenset(value)

        must_equal = document.get("must_equal")
        if not isinstance(must_equal, Mapping) or not all(
            isinstance(values, list) and values for values in must_equal.values()
        ):
            raise ValueError("export-keys: step_data.must_equal must map names to value lists")
        injectors = document.get("injectors")
        if not isinstance(injectors, list) or not all(
            isinstance(item, Mapping)
            and isinstance(item.get("id"), str)
            and isinstance(item.get("type"), str)
            for item in injectors
        ):
            raise ValueError("export-keys: step_data.injectors must list an id and a type each")
        return cls(
            removed=names("removed"),
            must_equal=MappingProxyType(
                {str(key): tuple(values) for key, values in must_equal.items()}
            ),
            kept=names("kept"),
            refused=names("refused_by_name"),
            injectors=MappingProxyType({item["id"]: item["type"] for item in injectors}),
            content_target_keys=names("content_target_keys"),
        )


@dataclass(frozen=True)
class ExportKeys:
    """The closed lists of keys and versions of an export, kept as data."""

    export_versions: frozenset[int]
    workflow: frozenset[str]
    step: frozenset[str]
    condition: frozenset[str]
    condition_legacy: frozenset[str]
    condition_types: frozenset[str]  # the types of condition a step may hold
    scope_rule: frozenset[str]
    scope_variable: frozenset[str]
    step_data: StepDataKeys

    @classmethod
    def from_document(cls, document: object) -> "ExportKeys":
        """Read the closed lists from the export-keys data document."""
        if not isinstance(document, Mapping):
            raise ValueError("export-keys: the document must be an object")

        def names(section: str, key: str = "keys", *, required: bool = True) -> frozenset[str]:
            part = document.get(section)
            value = part.get(key, None if required else []) if isinstance(part, Mapping) else None
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item for item in value
            ):
                raise ValueError(f"export-keys: {section}.{key} must be a list of names")
            return frozenset(value)

        versions = document.get("export_versions")
        if not isinstance(versions, list) or not versions or not all(map(_whole, versions)):
            raise ValueError("export-keys: export_versions must be a list of whole numbers")
        return cls(
            export_versions=frozenset(versions),
            workflow=names("workflow"),
            step=names("step"),
            condition=names("condition"),
            condition_legacy=names("condition", "legacy", required=False),
            condition_types=names("condition", "supported_types"),
            scope_rule=names("scope_rule"),
            scope_variable=names("scope_variable"),
            step_data=StepDataKeys.from_document(document.get("step_data")),
        )


def _whole(value: object) -> TypeGuard[int]:
    """A whole number, not a boolean, which Python counts as one."""
    return isinstance(value, int) and not isinstance(value, bool)


def has_workflow(stored: object) -> bool:
    """Whether ``stored`` has a workflow: any value of the part but null or an empty object. The
    platform's importer also reads an empty list or a scalar as no workflow; here they count as
    one, and are refused as not being an object. For an export; a stored file, which
    normalisation wrote, is read with ``holds_workflow``."""
    if not isinstance(stored, Mapping):
        return False
    return stored.get(WORKFLOW) not in (None, {})


def _escaped(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def key_pointer(pointer: str, key: str) -> str:
    """The pointer of ``key`` inside the node at ``pointer`` when the key is a plain name, and of
    the node otherwise, so that a pointer never repeats what an export wrote."""
    return f"{pointer}/{_escaped(key)}" if _PLAIN_KEY.fullmatch(key) else pointer


def _keys(
    node: Mapping[str, Any], pointer: str, known: frozenset[str], legacy: frozenset[str]
) -> Iterator[Refusal]:
    """A refusal for each key outside ``known``."""
    for key in node:
        if key not in known or key in legacy:
            yield Refusal(KEY_LEGACY if key in legacy else KEY_UNKNOWN, key_pointer(pointer, key))


def _listed(
    node: Mapping[str, Any], key: str, pointer: str
) -> tuple[list[tuple[str, Mapping[str, Any]]], Refusal | None]:
    """The objects of the list ``node[key]``, with their pointers, and the refusal of its shape
    if any: the list is read up to the first item that is not an object. A missing list counts as
    empty."""
    value = node.get(key, [])
    if not isinstance(value, list):
        return [], Refusal(NOT_A_LIST, f"{pointer}/{key}")
    found: list[tuple[str, Mapping[str, Any]]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            return found, Refusal(NOT_AN_OBJECT, f"{pointer}/{key}/{index}")
        found.append((f"{pointer}/{key}/{index}", item))
    return found, None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _too_deep(conditions: Sequence[Mapping[str, Any]]) -> bool:
    """Whether a condition sits more than ``MAX_DEPTH`` levels below its root, or is its own
    ancestor. Every parent a condition is given counts, so that a copy of a condition under
    another parent cannot hide a level. Identifiers that are not text are left to the later
    checks."""
    edges = {
        (identifier, parent)
        for item in conditions
        if (identifier := _text(item.get(_ID))) is not None
        and (parent := _text(item.get(_PARENT))) is not None
    }
    # Each round that changes a level raises one, and no level goes past MAX_DEPTH without a
    # refusal, so the rounds end; a loop keeps raising its levels until it is refused.
    levels: dict[str, int] = {}
    grown = True
    while grown:
        grown = False
        for identifier, parent in edges:
            level = levels.get(parent, 0) + 1
            if level > MAX_DEPTH:
                return True
            if level > levels.get(identifier, 0):
                levels[identifier], grown = level, True
    return False


def _conditions(
    found: list[tuple[str, Mapping[str, Any]]], pointer: str, keys: ExportKeys
) -> Iterator[Refusal]:
    for at, condition in found:
        yield from _keys(condition, at, keys.condition, keys.condition_legacy)
    items = [condition for _, condition in found]
    if len(items) > MAX_ENTRIES or len({_text(item.get(_ID)) for item in items}) > MAX_CONDITIONS:
        yield Refusal(TOO_MANY_CONDITIONS, pointer)
    elif _too_deep(items):
        yield Refusal(TOO_DEEP, pointer)


def _within(value: object, bounds: tuple[int, int]) -> bool:
    return _whole(value) and bounds[0] <= value <= bounds[1]


def _settings(workflow: Mapping[str, Any]) -> Iterator[str]:
    """The settings of ``workflow`` outside their bounds, a setting it does not hold, or holds as
    null, taking the value the import applies."""
    settings = {
        key: default if workflow.get(key) is None else workflow[key]
        for key, default in SETTINGS_WHEN_ABSENT.items()
    }
    if settings[_TIMEOUT_ON] is not True:
        yield _TIMEOUT_ON
    if not _within(settings[_TIMEOUT], TIMEOUT_RANGE):
        yield _TIMEOUT
    if settings[_SAFE_MODE] is not True:
        yield _SAFE_MODE
    pace = settings[_PACE_ON]
    if pace is False:
        yield from (key for key in (_ATTEMPTS, _PERIOD) if settings[key] is not None)
    elif pace is True:
        if not _within(settings[_ATTEMPTS], ATTEMPTS_RANGE):
            yield _ATTEMPTS
        if not _within(settings[_PERIOD], PERIOD_RANGE):
            yield _PERIOD
    else:
        yield _PACE_ON


def _workflow(workflow: Mapping[str, Any], keys: ExportKeys) -> Iterator[Refusal]:
    pointer = f"/{WORKFLOW}"
    yield from _keys(workflow, pointer, keys.workflow, frozenset())
    for setting in _settings(workflow):
        yield Refusal(SETTINGS_BOUNDS, f"{pointer}/{setting}")
    if workflow.get(_TEAM_MEMBERS) not in (None, []):
        yield Refusal(SCOPE_NOT_EMPTY, f"{pointer}/{_TEAM_MEMBERS}")
    for part, known in ((_SCOPE_RULES, keys.scope_rule), (_SCOPE_VARIABLES, keys.scope_variable)):
        found, refusal = _listed(workflow, part, pointer)
        if refusal is not None:
            yield refusal
        if len(found) > MAX_SCOPE:
            yield Refusal(TOO_MANY_ENTRIES, f"{pointer}/{part}")
            continue
        for at, item in found:
            yield from _keys(item, at, known, frozenset())
        if found:
            yield Refusal(SCOPE_NOT_EMPTY, f"{pointer}/{part}")
    standalone, refusal = _listed(workflow, _STANDALONE, pointer)
    if refusal is not None:
        yield refusal
    if len(standalone) > MAX_SCOPE:
        yield Refusal(TOO_MANY_ENTRIES, f"{pointer}/{_STANDALONE}")
    else:
        for at, condition in standalone:
            yield from _keys(condition, at, keys.condition, keys.condition_legacy)
        if standalone:  # refused whatever it holds, so its tree is not read
            yield Refusal(STANDALONE_NOT_EMPTY, f"{pointer}/{_STANDALONE}")
    steps, refusal = _listed(workflow, STEPS, pointer)
    if refusal is not None:
        yield refusal
        return
    if not steps:
        yield Refusal(WORKFLOW_NO_STEP, f"{pointer}/{STEPS}")
    elif len(steps) > MAX_STEPS:
        yield Refusal(TOO_MANY_STEPS, f"{pointer}/{STEPS}")
        return
    for at, step in steps:
        yield from _keys(step, at, keys.step, frozenset())
        conditions, refusal = _listed(step, CONDITIONS, at)
        if refusal is not None:
            yield refusal
        else:
            yield from _conditions(conditions, f"{at}/{CONDITIONS}", keys)


def export_refusals(export: object, keys: ExportKeys) -> Iterator[Refusal]:
    """The refusals of ``export``'s version and workflow, in order: its version first, then
    injects held with a workflow, then the workflow's keys, its scope lists, the conditions
    linked to no step, and its steps with their conditions. A list beyond its bound is not read
    further."""
    if not isinstance(export, Mapping):
        return
    version = export.get(_EXPORT_VERSION)
    if not _whole(version) or version not in keys.export_versions:
        yield Refusal(EXPORT_VERSION_UNKNOWN, f"/{_EXPORT_VERSION}")
    if not has_workflow(export):
        return
    workflow = export[WORKFLOW]
    if not isinstance(workflow, Mapping):
        yield Refusal(NOT_AN_OBJECT, f"/{WORKFLOW}")
        return
    if export.get(INJECTS) not in (None, []):
        yield Refusal(INJECTS_AND_WORKFLOW, f"/{WORKFLOW}")
    yield from _workflow(workflow, keys)


def settled_workflow(workflow: Mapping[str, Any]) -> dict[str, Any]:
    """``workflow`` as it is stored, once ``export_refusals`` has found nothing to refuse: every
    setting written, with the value the import applies when the export does not hold it or holds
    it as null; the lists of scope and of conditions linked to no step written empty; and without
    the version, which changes each time an edited workflow is launched. The result is a new
    object; the values it shares with ``workflow`` are not changed."""
    settled = {key: value for key, value in workflow.items() if key != _VERSION}
    for key, value in SETTINGS_WHEN_ABSENT.items():
        if settled.get(key) is None:
            settled[key] = value
    for part in (_SCOPE_RULES, _SCOPE_VARIABLES, _STANDALONE):
        settled[part] = settled.get(part) or []
    settled.pop(_TEAM_MEMBERS, None)  # written by the exporter only when not empty
    return settled


@dataclass(frozen=True, slots=True)
class Condition:
    """A condition of a step as the export wrote it, with the pointer it is reported at.
    Identifiers that are not text read as ``None``."""

    pointer: str
    fields: Mapping[str, Any]

    @property
    def identifier(self) -> str | None:
        return _text(self.fields.get(_ID))

    @property
    def parent(self) -> object:
        return self.fields.get(_PARENT)

    @property
    def is_root(self) -> object:
        return self.fields.get("condition_is_root")

    @property
    def kind(self) -> object:
        return self.fields.get("condition_type")

    @property
    def value(self) -> object:
        return self.fields.get("condition_value")

    @property
    def step_from(self) -> object:
        return self.fields.get("condition_step_from_id")


@dataclass(frozen=True, slots=True)
class Step:
    """A step of a workflow, with the pointer it is reported at and its conditions in the
    export's order, copies included."""

    pointer: str
    identifier: str | None
    conditions: tuple[Condition, ...]


@dataclass(frozen=True, slots=True)
class Workflow:
    steps: tuple[Step, ...]


def parsed_workflow(workflow: Mapping[str, Any]) -> Workflow:
    """``workflow`` as value objects, once ``export_refusals`` has found nothing to refuse, so
    that its steps and their conditions are lists of objects."""
    pointer = f"/{WORKFLOW}/{STEPS}"
    return Workflow(
        tuple(
            Step(
                f"{pointer}/{index}",
                _text(step.get("step_id")),
                tuple(
                    Condition(f"{pointer}/{index}/{CONDITIONS}/{position}", condition)
                    for position, condition in enumerate(step.get(CONDITIONS) or [])
                ),
            )
            for index, step in enumerate(workflow.get(STEPS) or [])
        )
    )


def conditions(stored: object) -> Iterator[tuple[str, Mapping[str, Any]]]:
    """Every condition of the steps of a stored scenario, with the pointer it is reported at.
    Lenient, as the walk over injects is: a part of another shape gives nothing."""
    workflow = stored.get(WORKFLOW) if isinstance(stored, Mapping) else None
    steps = workflow.get(STEPS) if isinstance(workflow, Mapping) else None
    for index, step in enumerate(steps if isinstance(steps, list) else []):
        found = step.get(CONDITIONS) if isinstance(step, Mapping) else None
        for position, condition in enumerate(found if isinstance(found, list) else []):
            if isinstance(condition, Mapping):
                yield f"/{WORKFLOW}/{STEPS}/{index}/{CONDITIONS}/{position}", condition


def holds_workflow(stored: object) -> bool:
    """Whether a stored scenario holds a workflow, of any shape: its part is not left empty, as
    normalisation leaves it for a time-based scenario (``null``, ``{}`` or ``[]``)."""
    return isinstance(stored, Mapping) and stored.get(WORKFLOW) not in (None, {}, [])


def stored_steps(stored: object) -> Iterator[tuple[int, Mapping[str, Any]]]:
    """Every step of the workflow of a stored scenario that is an object, with its index.
    Lenient, as the walk over injects is."""
    workflow = stored.get(WORKFLOW) if isinstance(stored, Mapping) else None
    steps = workflow.get(STEPS) if isinstance(workflow, Mapping) else None
    for index, step in enumerate(steps if isinstance(steps, list) else []):
        if isinstance(step, Mapping):
            yield index, step


@dataclass(frozen=True, slots=True)
class StoredSettings:
    """The settings of a stored workflow as a reader shows them: each value as the file holds
    it, a flag true only when it is ``true``."""

    timeout_enabled: bool
    timeout_seconds: object
    safe_mode: bool
    pace_enabled: bool
    attempts: object
    period: object


def stored_settings(stored: object) -> StoredSettings:
    """The settings of the workflow of a stored scenario, read leniently: a workflow of another
    shape has every flag off and no value."""
    workflow = stored.get(WORKFLOW) if isinstance(stored, Mapping) else None
    found: Mapping[str, Any] = workflow if isinstance(workflow, Mapping) else {}
    return StoredSettings(
        timeout_enabled=found.get(_TIMEOUT_ON) is True,
        timeout_seconds=found.get(_TIMEOUT),
        safe_mode=found.get(_SAFE_MODE) is True,
        pace_enabled=found.get(_PACE_ON) is True,
        attempts=found.get(_ATTEMPTS),
        period=found.get(_PERIOD),
    )


def step_identifier(step: Mapping[str, Any]) -> str:
    """The identifier of a stored step, or an empty text when it has none that is text."""
    value = step.get(_STEP_ID)
    return value if isinstance(value, str) else ""


def step_waits(step: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """What a stored step waits for, read leniently: the identifiers its dependencies name, in
    its order, and the types of its other conditions, as text."""
    found = step.get(CONDITIONS)
    awaited: list[str] = []
    others: list[str] = []
    for condition in found if isinstance(found, list) else []:
        if not isinstance(condition, Mapping):
            continue
        kind, value = condition.get("condition_type"), condition.get("condition_value")
        if kind == DEPEND_ON and isinstance(value, str):
            awaited.append(value)
        else:
            others.append(str(kind))
    return tuple(awaited), tuple(others)
