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
from typing import Any

from scenario_tools.domain.shared.stored import INJECTS

WORKFLOW = "scenario_workflow"
STEPS = "workflow_steps"
CONDITIONS = "step_conditions"
_EXPORT_VERSION = "export_version"
_SCOPE_RULES = "workflow_scope_rules"
_SCOPE_VARIABLES = "workflow_scope_variables"
_STANDALONE = "workflow_standalone_conditions"
_ID, _PARENT = "condition_id", "condition_parent_id"
_PLAIN_KEY = re.compile(r"[A-Za-z0-9_]{1,64}")

MAX_STEPS = 50
MAX_CONDITIONS = 50  # distinct conditions in one step
MAX_DEPTH = 16  # levels below the root of a step's conditions
MAX_SCOPE = 50  # scope rules, scope variables, or conditions linked to no step
# A step's list may hold one condition more than once (once for each way the exporter reaches
# it); this bounds the list itself, whatever the repetitions.
MAX_ENTRIES = MAX_CONDITIONS * (MAX_DEPTH + 1)

EXPORT_VERSION_UNKNOWN = "the export's version is not one these tools read"
INJECTS_AND_WORKFLOW = "a scenario holds injects or a workflow, never both"
WORKFLOW_NO_STEP = "a workflow holds at least one step"
WORKFLOW_NOT_YET = "scenarios in chaining are checked but not normalised yet"
NOT_AN_OBJECT = "this node must be an object"
NOT_A_LIST = "this node must be a list"
KEY_UNKNOWN = "this node holds a key the platform does not export here"
KEY_LEGACY = (
    "this node holds a legacy key that is no longer read: export the scenario again from a "
    "current platform"
)
TOO_MANY_STEPS = f"a workflow holds at most {MAX_STEPS} steps"
TOO_MANY_CONDITIONS = f"a step holds at most {MAX_CONDITIONS} conditions"
TOO_MANY_ENTRIES = f"this list of the workflow holds at most {MAX_SCOPE} entries"
TOO_DEEP = (
    f"a step's conditions are nested at most {MAX_DEPTH} levels below their root, "
    "and no condition is its own ancestor"
)


@dataclass(frozen=True)
class Refusal:
    """Why a stored scenario is refused (a fixed message) and where (a JSON pointer)."""

    what: str
    pointer: str


@dataclass(frozen=True)
class ExportKeys:
    """The closed lists of keys and versions of an export, kept as data."""

    export_versions: frozenset[int]
    workflow: frozenset[str]
    step: frozenset[str]
    condition: frozenset[str]
    condition_legacy: frozenset[str]
    scope_rule: frozenset[str]
    scope_variable: frozenset[str]

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
            scope_rule=names("scope_rule"),
            scope_variable=names("scope_variable"),
        )


def _whole(value: object) -> bool:
    """A whole number, not a boolean, which Python counts as one."""
    return isinstance(value, int) and not isinstance(value, bool)


def has_workflow(stored: object) -> bool:
    """Whether ``stored`` has a workflow: any value of the part but null or an empty object. The
    platform's importer also reads an empty list or a scalar as no workflow; here they count as
    one, and are refused as not being an object."""
    if not isinstance(stored, Mapping):
        return False
    return stored.get(WORKFLOW) not in (None, {})


def _escaped(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _keys(
    node: Mapping[str, Any], pointer: str, known: frozenset[str], legacy: frozenset[str]
) -> Iterator[Refusal]:
    """A refusal for each key outside ``known``, at the key when it is a plain name and at the
    node otherwise, so that the pointer never repeats what the export wrote."""
    for key in node:
        if key not in known or key in legacy:
            at = f"{pointer}/{_escaped(key)}" if _PLAIN_KEY.fullmatch(key) else pointer
            yield Refusal(KEY_LEGACY if key in legacy else KEY_UNKNOWN, at)


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


def _workflow(workflow: Mapping[str, Any], keys: ExportKeys) -> Iterator[Refusal]:
    pointer = f"/{WORKFLOW}"
    yield from _keys(workflow, pointer, keys.workflow, frozenset())
    for part, known in ((_SCOPE_RULES, keys.scope_rule), (_SCOPE_VARIABLES, keys.scope_variable)):
        found, refusal = _listed(workflow, part, pointer)
        if refusal is not None:
            yield refusal
        if len(found) > MAX_SCOPE:
            yield Refusal(TOO_MANY_ENTRIES, f"{pointer}/{part}")
            continue
        for at, item in found:
            yield from _keys(item, at, known, frozenset())
    standalone, refusal = _listed(workflow, _STANDALONE, pointer)
    if refusal is not None:
        yield refusal
    if len(standalone) > MAX_SCOPE:
        yield Refusal(TOO_MANY_ENTRIES, f"{pointer}/{_STANDALONE}")
    else:
        yield from _conditions(standalone, f"{pointer}/{_STANDALONE}", keys)
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
