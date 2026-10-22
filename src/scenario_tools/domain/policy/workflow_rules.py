"""The rules the graph of a workflow keeps before its identifiers are derived.

Each step appears once, and each condition belongs to the tree of one step: one root, every other
condition under a parent of the same step. The export repeats a condition once for each path to
it, so identical copies are one condition. A dependency names a step of the scenario, and no step
waits for itself, directly or through other steps. The rules read the source identifiers of the
export, before any is rewritten; identifiers that are not text are left to the identifier checks.
"""

from collections.abc import Iterator

from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.domain.shared.workflow import (
    CONDITION_DEPEND_NESTED,
    CONDITION_GROUP_EMPTY,
    CONDITION_ID_TWICE,
    CONDITION_LEAF_CHILD,
    CONDITION_LIST_EMPTY,
    CONDITION_MAPPER,
    CONDITION_NOT_YET,
    CONDITION_PARENT_ELSEWHERE,
    CONDITION_ROOT,
    CONDITION_SHARED,
    CONDITION_STEP_FROM,
    CONDITION_VALUE_IDENTIFIER,
    CONDITION_VALUE_SHAPE,
    CYCLE,
    DEPEND_ON_DANGLING,
    DEPEND_ON_NULL,
    STEP_ID_TWICE,
    Condition,
    Refusal,
    Step,
    Workflow,
)

_DEPEND_ON = "DEPEND_ON"
_MAPPER = "MAPPER"
_GROUPS = frozenset({"AND", "OR"})
_LISTS = frozenset({"IN", "NIN"})


def _distinct(step: Step) -> list[Condition]:
    """The conditions of ``step``, each copy of a condition after the first left out."""
    seen: set[str] = set()
    distinct = []
    for condition in step.conditions:
        identifier = condition.identifier
        if identifier is None or identifier not in seen:
            distinct.append(condition)
        if identifier is not None:
            seen.add(identifier)
    return distinct


def _step_ids(workflow: Workflow) -> Iterator[Refusal]:
    seen: set[str] = set()
    for step in workflow.steps:
        if step.identifier in seen:
            yield Refusal(STEP_ID_TWICE, f"{step.pointer}/step_id")
        if step.identifier is not None:
            seen.add(step.identifier)


def _condition_ids(workflow: Workflow) -> Iterator[Refusal]:
    claimed: set[str] = set()  # by the steps before
    for step in workflow.steps:
        first: dict[str, Condition] = {}
        for condition in step.conditions:
            identifier = condition.identifier
            if identifier is None:
                continue
            if identifier in first:
                if jcs(condition.fields) != jcs(first[identifier].fields):  # types count
                    yield Refusal(CONDITION_ID_TWICE, f"{condition.pointer}/condition_id")
            elif identifier in claimed:
                yield Refusal(CONDITION_SHARED, f"{condition.pointer}/condition_id")
            else:
                first[identifier] = condition
        claimed.update(first)


def _trees(workflow: Workflow) -> Iterator[Refusal]:
    everywhere = {condition.identifier for step in workflow.steps for condition in step.conditions}
    for step in workflow.steps:
        here = {condition.identifier for condition in step.conditions}
        roots = 0
        for condition in _distinct(step):
            parent = condition.parent
            if parent is not None and not isinstance(parent, str):
                continue  # left to the identifier checks
            if parent is not None and parent not in here:
                if parent in everywhere:
                    yield Refusal(
                        CONDITION_PARENT_ELSEWHERE, f"{condition.pointer}/condition_parent_id"
                    )
                else:
                    yield Refusal(CONDITION_ROOT, condition.pointer)  # an orphan
            elif condition.is_root is not (parent is None):
                yield Refusal(CONDITION_ROOT, condition.pointer)
            elif parent is None:
                roots += 1
                if roots > 1:
                    yield Refusal(CONDITION_ROOT, condition.pointer)


def _dependencies(workflow: Workflow) -> Iterator[Refusal]:
    steps = {step.identifier for step in workflow.steps} - {None}
    for step in workflow.steps:
        for condition in _distinct(step):
            if condition.step_from is not None:
                yield Refusal(CONDITION_STEP_FROM, f"{condition.pointer}/condition_step_from_id")
            if condition.kind != _DEPEND_ON:
                continue
            if condition.value is None:
                yield Refusal(DEPEND_ON_NULL, f"{condition.pointer}/condition_value")
            elif not isinstance(condition.value, str) or condition.value not in steps:
                yield Refusal(DEPEND_ON_DANGLING, f"{condition.pointer}/condition_value")


def _cycles(workflow: Workflow) -> Iterator[Refusal]:
    """A refusal at each step that waits for itself, directly or through other steps."""
    steps = workflow.steps
    awaited = [
        [
            index
            for index, other in enumerate(steps)
            if other.identifier is not None
            and any(
                condition.kind == _DEPEND_ON and condition.value == other.identifier
                for condition in step.conditions
            )
        ]
        for step in steps
    ]
    for start, step in enumerate(steps):
        reached: set[int] = set()
        frontier = set(awaited[start])
        for _ in steps:  # a path that comes back visits each step at most once
            reached |= frontier
            frontier = {after for index in frontier for after in awaited[index]} - reached
        if start in reached:
            yield Refusal(CYCLE, step.pointer)


def graph_refusals(workflow: Workflow) -> Iterator[Refusal]:
    """The refusals of ``workflow``'s graph, in order of kind: step identifiers, condition
    identifiers, the tree of each step, the dependencies, then the loops."""
    yield from _step_ids(workflow)
    yield from _condition_ids(workflow)
    yield from _trees(workflow)
    yield from _dependencies(workflow)
    yield from _cycles(workflow)


def _identifiers(workflow: Workflow) -> list[str]:
    """The identifiers of the steps and conditions of ``workflow``, as a filter value could quote
    them."""
    found = [step.identifier for step in workflow.steps]
    found += [condition.identifier for step in workflow.steps for condition in step.conditions]
    return sorted({name.casefold() for name in found if isinstance(name, str) and name})


def _value_refusal(condition: Condition, identifiers: list[str]) -> Refusal | None:
    """Why a filter's value is refused: neither a text nor nothing, an IN or NIN list with no
    value, or a value that quotes a step or a condition, whose identifiers are rewritten and so
    never what a filter compares."""
    value = condition.value
    if value is not None and not isinstance(value, str):
        return Refusal(CONDITION_VALUE_SHAPE, f"{condition.pointer}/condition_value")
    if condition.kind in _LISTS and (
        not isinstance(value, str) or not value.replace(",", "").strip()
    ):
        return Refusal(CONDITION_LIST_EMPTY, f"{condition.pointer}/condition_value")
    if isinstance(value, str) and any(name in value.casefold() for name in identifiers):
        return Refusal(CONDITION_VALUE_IDENTIFIER, f"{condition.pointer}/condition_value")
    return None


def subset_refusals(workflow: Workflow, supported: frozenset[str]) -> Iterator[Refusal]:
    """The conditions of ``workflow`` outside the subset: a mapper, refused for good; a type not
    ``supported``; a dependency that is not the only condition of its step, at its root; a filter
    that holds a condition, AND or OR holding none; and a filter's value that is an empty list or
    quotes a step or a condition. The graph rules have made each step's conditions one tree."""
    identifiers = _identifiers(workflow)
    for step in workflow.steps:
        conditions = _distinct(step)
        parents = {
            condition.parent for condition in conditions if isinstance(condition.parent, str)
        }
        for condition in conditions:
            if condition.kind == _MAPPER:
                yield Refusal(CONDITION_MAPPER, condition.pointer)
            elif not isinstance(condition.kind, str) or condition.kind not in supported:
                yield Refusal(CONDITION_NOT_YET, condition.pointer)
            elif condition.kind == _DEPEND_ON:
                if len(conditions) > 1:
                    yield Refusal(CONDITION_DEPEND_NESTED, condition.pointer)
            elif condition.kind in _GROUPS:
                if condition.identifier not in parents:
                    yield Refusal(CONDITION_GROUP_EMPTY, condition.pointer)
                elif condition.value is not None:
                    yield Refusal(CONDITION_VALUE_SHAPE, f"{condition.pointer}/condition_value")
            elif condition.identifier in parents:
                yield Refusal(CONDITION_LEAF_CHILD, condition.pointer)
            elif (refused := _value_refusal(condition, identifiers)) is not None:
                yield refused
