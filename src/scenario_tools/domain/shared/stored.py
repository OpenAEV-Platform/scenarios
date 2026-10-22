"""The injects of a stored scenario, read through one walk.

Every check that reads injects reads them here, each with the JSON pointer it is reported at and
the part it comes from, so that a part that holds injects is never missed by one check and read
by another: the injects part, then the inject each step of a workflow runs. The walk is lenient: a
part of another shape, or an item that is not an object, yields nothing, and a check that must
refuse such a shape refuses it itself.
"""

from collections.abc import Iterator, Mapping
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
