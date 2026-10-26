"""The workflow of a stored scenario, once its shape is checked, as the checks and the sheet read
it: its steps and their conditions as value objects, what each step waits for, and the tree of
its conditions."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.domain.shared.stored import STEPS, WORKFLOW
from scenario_tools.domain.shared.workflow import (
    CONDITION_ID,
    CONDITION_PARENT,
    CONDITIONS,
    DEPEND_ON,
    MAX_DEPTH,
    MAX_STEPS,
    STEP_ID,
    TOO_MANY_STEPS,
    text_or_none,
)


@dataclass(frozen=True, slots=True)
class Condition:
    """A condition of a step as the export wrote it, with the pointer it is reported at.
    Identifiers that are not text read as ``None``."""

    pointer: str
    fields: Mapping[str, Any]

    @property
    def identifier(self) -> str | None:
        return text_or_none(self.fields.get(CONDITION_ID))

    @property
    def parent(self) -> object:
        return self.fields.get(CONDITION_PARENT)

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
                text_or_none(step.get("step_id")),
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


def step_identifier(step: Mapping[str, Any]) -> str:
    """The identifier of a stored step, or an empty text when it has none that is text."""
    value = step.get(STEP_ID)
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


@dataclass(frozen=True)
class ConditionNode:
    """A condition of a stored step as a reader sees it: its type, the key it reads, the value it
    compares with, the conditions under it, and whether some of those were left out because they
    lie deeper than a sheet reads."""

    kind: object
    key: object
    value: object
    children: tuple["ConditionNode", ...]
    cut: bool = False


def step_condition_trees(step: Mapping[str, Any]) -> tuple[ConditionNode, ...]:
    """Every condition of a stored step but a plain dependency (a root that waits for a step and
    holds nothing), as trees, read leniently so that none is hidden: identical copies once, a
    copy that differs as a condition of its own, the conditions under a parent in the order of the
    file, a condition whose parent the step does not hold as a root, and a condition on a loop of
    parents as a root where the loop is first met. Below ``MAX_DEPTH`` levels a tree is cut, and
    says so."""
    found = step.get(CONDITIONS)
    nodes: list[Mapping[str, Any]] = []
    copies: set[str] = set()
    first: dict[str, int] = {}  # the first condition of each identifier, by its index
    for condition in found if isinstance(found, list) else []:
        if not isinstance(condition, Mapping):
            continue
        try:
            text = jcs(condition).decode()
        except (TypeError, ValueError):  # what no JSON reader gives, as a test may
            text = repr(condition)
        if text in copies:
            continue
        copies.add(text)
        identifier = condition.get("condition_id")
        if isinstance(identifier, str):
            first.setdefault(identifier, len(nodes))
        nodes.append(condition)
    below: dict[int, list[int]] = {}
    roots: list[int] = []
    for index, condition in enumerate(nodes):
        parent = condition.get("condition_parent_id")
        holder = first.get(parent) if isinstance(parent, str) else None
        if holder is None or holder == index:
            roots.append(index)
        else:
            below.setdefault(holder, []).append(index)
    reached: set[int] = set()

    def reach(index: int) -> None:
        pending = [index]
        while pending:
            current = pending.pop()
            if current not in reached:
                reached.add(current)
                pending += below.get(current, [])

    def tree(index: int, path: frozenset[int]) -> ConditionNode:
        reached.add(index)
        children: list[ConditionNode] = []
        cut = False
        for child in below.get(index, []):
            if child in path:
                continue  # a loop: the child is said above, where the loop begins
            if len(path) > MAX_DEPTH:
                cut = True
                reach(child)
                continue
            children.append(tree(child, path | {child}))
        condition = nodes[index]
        return ConditionNode(
            condition.get("condition_type"),
            condition.get("condition_key"),
            condition.get("condition_value"),
            tuple(children),
            cut,
        )

    def plain_dependency(index: int) -> bool:
        condition = nodes[index]
        return (
            condition.get("condition_type") == DEPEND_ON
            and isinstance(condition.get("condition_value"), str)
            and condition.get("condition_parent_id") is None  # not on itself, nor orphaned
            and not below.get(index)
        )

    trees = [tree(index, frozenset({index})) for index in roots if not plain_dependency(index)]
    reached.update(index for index in roots if plain_dependency(index))

    def parent_of(index: int) -> int | None:
        parent = nodes[index].get("condition_parent_id")
        return first.get(parent) if isinstance(parent, str) else None

    for index in range(len(nodes)):
        if index in reached:
            continue
        # No root is above it, so its parents lead to a loop: the tree starts on the loop, and
        # the condition is said once, below it.
        seen, last = {index}, index
        following = parent_of(index)
        while following is not None and following not in seen:  # each parent followed once
            seen.add(following)
            last = following
            following = parent_of(following)
        start = following if following is not None else last  # always on the loop
        trees.append(tree(start, frozenset({start})))
    return tuple(trees)


def checked_stored_workflow(stored: object) -> Workflow | None:
    """The workflow of a stored scenario as value objects, or ``None`` when it holds none;
    ``ValueError`` when its steps or their conditions are not lists of objects, or it holds more
    steps than an export may."""
    if not holds_workflow(stored):
        return None
    workflow = stored[WORKFLOW]  # type: ignore[index]  # holds_workflow read it as a mapping
    if not isinstance(workflow, Mapping):
        raise ValueError(f"{WORKFLOW} must be an object")
    steps = workflow.get(STEPS)
    if not isinstance(steps, list) or not all(isinstance(step, Mapping) for step in steps):
        raise ValueError(f"{STEPS} must be a list of objects")
    if len(steps) > MAX_STEPS:  # the graph is read only within the bounds of an export
        raise ValueError(TOO_MANY_STEPS)
    for step in steps:
        conditions = step.get(CONDITIONS)
        if conditions is not None and (
            not isinstance(conditions, list)
            or not all(isinstance(condition, Mapping) for condition in conditions)
        ):
            raise ValueError(f"{CONDITIONS} must be a list of objects")
    return parsed_workflow(workflow)
