"""The injects of a stored scenario, read through one walk.

Every check that reads injects reads them here, each with the JSON pointer it is reported at and
the part it comes from, so that a part that holds injects is never missed by one check and read
by another: the injects part, then the inject each step of a workflow runs. The walk is lenient: a
part of another shape, or an item that is not an object, yields nothing, and a check that must
refuse such a shape refuses it itself.
"""

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

INJECTS = "scenario_injects"
WORKFLOW = "scenario_workflow"
STEPS = "workflow_steps"
STEP_DATA = "step_data"


class Origin(Enum):
    """The part an inject comes from."""

    INJECT = "inject"
    STEP = "step"


@dataclass(frozen=True, slots=True)
class StoredInject:
    """An inject of a stored scenario, with the JSON pointer it is reported at."""

    pointer: str
    inject: Mapping[str, Any]
    origin: Origin


def inject_pointer(index: int) -> str:
    """The JSON pointer of the inject at ``index`` of the injects part."""
    return f"/{INJECTS}/{index}"


def step_pointer(index: int) -> str:
    """The JSON pointer of the inject of the step at ``index`` of a workflow."""
    return f"/{WORKFLOW}/{STEPS}/{index}/{STEP_DATA}"


def injects(stored: object) -> Iterator[StoredInject]:
    """Every inject of ``stored`` that is an object, in order: those of the injects part, then
    those of the steps of its workflow."""
    if not isinstance(stored, Mapping):
        return
    part = stored.get(INJECTS)
    for index, inject in enumerate(part if isinstance(part, list) else []):
        if isinstance(inject, Mapping):
            yield StoredInject(inject_pointer(index), inject, Origin.INJECT)
    workflow = stored.get(WORKFLOW)
    steps = workflow.get(STEPS) if isinstance(workflow, Mapping) else None
    for index, step in enumerate(steps if isinstance(steps, list) else []):
        inject = step.get(STEP_DATA) if isinstance(step, Mapping) else None
        if isinstance(inject, Mapping):
            yield StoredInject(step_pointer(index), inject, Origin.STEP)


def injects_replaced(document: object, change: Callable[[object], object]) -> object:
    """A copy of ``document`` with ``change`` applied to each item of its injects part and to
    the inject of each step of its workflow, whether a step holds it decoded, as a stored
    scenario does, or as JSON text, as an export does; the rest is kept as it is. A step whose
    text is not JSON is left to the checks that refuse it."""
    if not isinstance(document, Mapping):
        return document
    copied = dict(document)
    part = document.get(INJECTS)
    if isinstance(part, list):
        copied[INJECTS] = [change(inject) for inject in part]
    workflow = document.get(WORKFLOW)
    steps = workflow.get(STEPS) if isinstance(workflow, Mapping) else None
    if isinstance(workflow, Mapping) and isinstance(steps, list):
        copied[WORKFLOW] = {**workflow, STEPS: [_step_replaced(step, change) for step in steps]}
    return copied


def steps_decoded(
    document: object, decode: Callable[[str], object]
) -> tuple[object, tuple[str, ...]]:
    """A copy of ``document`` with the inject of each step that holds it as JSON text, as an
    export does, decoded by ``decode``, and the pointers of the steps whose text ``decode``
    refuses with ``ValueError``, left as they are; the rest is kept as it is."""
    if not isinstance(document, Mapping):
        return document, ()
    workflow = document.get(WORKFLOW)
    if not isinstance(workflow, Mapping):
        return document, ()
    steps = workflow.get(STEPS)
    if not isinstance(steps, list):
        return document, ()
    unreadable: list[str] = []
    decoded: list[object] = []
    for index, step in enumerate(steps):
        data = step.get(STEP_DATA) if isinstance(step, Mapping) else None
        if isinstance(data, str):
            try:
                step = {**step, STEP_DATA: decode(data)}
            except ValueError:
                unreadable.append(step_pointer(index))
        decoded.append(step)
    return {**document, WORKFLOW: {**workflow, STEPS: decoded}}, tuple(unreadable)


def _step_replaced(step: object, change: Callable[[object], object]) -> object:
    data = step.get(STEP_DATA) if isinstance(step, Mapping) else None
    if not isinstance(step, Mapping) or data is None:
        return step
    if not isinstance(data, str):
        return {**step, STEP_DATA: change(data)}
    try:
        decoded = json.loads(data)
    except ValueError:
        return step
    return {
        **step,
        STEP_DATA: json.dumps(change(decoded), ensure_ascii=False, separators=(",", ":")),
    }
