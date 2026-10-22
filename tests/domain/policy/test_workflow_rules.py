"""The graph of a workflow, read on hand-built workflows: each step appears once, each condition
belongs to one step's tree, and the steps wait for steps of the scenario, never in a loop."""

from typing import Any

import pytest

from scenario_tools.domain.policy.workflow_rules import graph_refusals, subset_refusals
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
    Refusal,
    parsed_workflow,
)

AT = "/scenario_workflow/workflow_steps"


def _condition(
    identifier: object,
    parent: object = None,
    *,
    kind: object = "DEPEND_ON",
    value: object = "s1",
    **fields: object,
) -> dict[str, Any]:
    return {
        "condition_id": identifier,
        "condition_parent_id": parent,
        "condition_is_root": parent is None,
        "condition_type": kind,
        "condition_value": value,
        "condition_step_from_id": None,
        **fields,
    }


def _step(identifier: object, *conditions: dict[str, Any]) -> dict[str, Any]:
    return {"step_id": identifier, "step_conditions": list(conditions)}


def _refusals(*steps: dict[str, Any]) -> list[Refusal]:
    return list(graph_refusals(parsed_workflow({"workflow_steps": list(steps)})))


def _at(step: int, condition: int | None = None, key: str | None = None) -> str:
    pointer = f"{AT}/{step}"
    if condition is not None:
        pointer += f"/step_conditions/{condition}"
    return pointer if key is None else f"{pointer}/{key}"


def test_steps_that_wait_for_steps_of_the_scenario_pass() -> None:
    assert _refusals(_step("s1"), _step("s2", _condition("c1")), _step("s3")) == []


def test_a_step_identifier_given_twice_is_refused_at_its_second_step() -> None:
    assert _refusals(_step("s1"), _step("s2"), _step("s1")) == [
        Refusal(STEP_ID_TWICE, _at(2, key="step_id"))
    ]


def test_identical_copies_of_a_condition_are_one_condition() -> None:
    condition = _condition("c1")
    assert _refusals(_step("s1"), _step("s2", condition, dict(condition))) == []


def test_two_copies_of_a_condition_that_differ_are_refused() -> None:
    first, second = _condition("c1"), _condition("c1", condition_name="other")
    assert _refusals(_step("s1"), _step("s2", first, second)) == [
        Refusal(CONDITION_ID_TWICE, _at(1, 1, "condition_id"))
    ]


def test_a_condition_in_two_steps_is_refused_in_the_second() -> None:
    assert _refusals(_step("s1"), _step("s2", _condition("c1")), _step("s3", _condition("c1"))) == [
        Refusal(CONDITION_SHARED, _at(2, 0, "condition_id"))
    ]


def test_a_child_whose_parent_is_in_another_step_is_refused() -> None:
    root = _condition("c1", kind="AND", value=None)
    assert _refusals(_step("s1", root), _step("s2", _condition("c2", "c1"))) == [
        Refusal(CONDITION_PARENT_ELSEWHERE, _at(1, 0, "condition_parent_id"))
    ]


def test_a_child_whose_parent_is_nowhere_is_an_orphan() -> None:
    assert _refusals(_step("s1"), _step("s2", _condition("c2", "c9"))) == [
        Refusal(CONDITION_ROOT, _at(1, 0))
    ]


@pytest.mark.parametrize(
    ("parent", "root"),
    [(None, False), ("c1", True), (None, None), (None, 1)],
    ids=["no-parent-not-root", "parent-and-root", "flag-null", "flag-not-boolean"],
)
def test_the_root_flag_agrees_with_the_parent(parent: object, root: object) -> None:
    group = _condition("c1", kind="AND", value=None)
    condition = _condition("c2", parent, condition_is_root=root)
    assert _refusals(_step("s1"), _step("s2", group, condition)) == [
        Refusal(CONDITION_ROOT, _at(1, 1))
    ]


def test_a_step_holds_one_root_and_its_copies_count_once() -> None:
    root = _condition("c1")
    assert _refusals(_step("s1"), _step("s2", root, dict(root))) == []
    assert _refusals(_step("s1"), _step("s2", root, _condition("c2"))) == [
        Refusal(CONDITION_ROOT, _at(1, 1))
    ]


def test_a_condition_reads_no_other_step_output() -> None:
    assert _refusals(_step("s1"), _step("s2", _condition("c1", condition_step_from_id="s1"))) == [
        Refusal(CONDITION_STEP_FROM, _at(1, 0, "condition_step_from_id"))
    ]


def test_a_dependency_names_a_step() -> None:
    assert _refusals(_step("s1"), _step("s2", _condition("c1", value=None))) == [
        Refusal(DEPEND_ON_NULL, _at(1, 0, "condition_value"))
    ]


@pytest.mark.parametrize("value", ["s9", 1, ["s1"]])
def test_a_dependency_on_no_step_of_the_scenario_is_refused(value: object) -> None:
    assert _refusals(_step("s1"), _step("s2", _condition("c1", value=value))) == [
        Refusal(DEPEND_ON_DANGLING, _at(1, 0, "condition_value"))
    ]


def test_only_a_dependency_names_a_step() -> None:
    assert _refusals(_step("s1"), _step("s2", _condition("c1", kind="EQ", value="s9"))) == []
    assert _refusals(_step("s1"), _step("s2", _condition("c1", kind="EQ", value=None))) == []


def test_steps_that_wait_for_each_other_are_refused() -> None:
    assert _refusals(
        _step("s1", _condition("c1", value="s2")),
        _step("s2", _condition("c2", value="s1")),
        _step("s3", _condition("c3", value="s1")),
    ) == [Refusal(CYCLE, _at(0)), Refusal(CYCLE, _at(1))]


def test_a_step_that_waits_for_itself_is_refused() -> None:
    assert _refusals(_step("s1", _condition("c1"))) == [Refusal(CYCLE, _at(0))]


def test_a_longer_chain_is_no_loop() -> None:
    steps = [_step("s0")]
    steps += [_step(f"s{i}", _condition(f"c{i}", value=f"s{i - 1}")) for i in range(1, 50)]
    assert _refusals(*steps) == []


def test_identifiers_that_are_not_text_are_left_to_the_identifier_checks() -> None:
    assert (
        _refusals(
            _step(1),
            _step(1),
            _step("s1"),
            _step("s2", _condition(2)),
            _step("s3", _condition(2, condition_name="other")),
        )
        == []
    )


def test_the_refusals_come_in_order_of_kind() -> None:
    assert _refusals(
        _step("s1", _condition("c1", value="s1")),
        _step("s1", _condition("c2", value=None, condition_step_from_id="x")),
    ) == [
        Refusal(STEP_ID_TWICE, _at(1, key="step_id")),
        Refusal(CONDITION_STEP_FROM, _at(1, 0, "condition_step_from_id")),
        Refusal(DEPEND_ON_NULL, _at(1, 0, "condition_value")),
        Refusal(CYCLE, _at(0)),
    ]


def test_a_null_dependency_waits_for_no_step_even_one_without_a_text_identifier() -> None:
    assert _refusals(_step(1, _condition("c1", value=None))) == [
        Refusal(DEPEND_ON_NULL, _at(0, 0, "condition_value"))
    ]


@pytest.mark.parametrize("parent", [["c1"], {"id": "c1"}, 5, True])
def test_a_parent_that_is_not_text_is_left_to_the_identifier_checks(parent: object) -> None:
    group = _condition("c1", kind="AND", value=None)
    child = _condition("c2", "c1", condition_parent_id=parent)
    assert _refusals(_step("s1"), _step("s2", group, child)) == []


def test_copies_that_differ_only_in_type_are_not_identical() -> None:
    first, second = _condition("c1"), _condition("c1", condition_is_root=1)
    assert _refusals(_step("s1"), _step("s2", first, second)) == [
        Refusal(CONDITION_ID_TWICE, _at(1, 1, "condition_id"))
    ]


def test_conditions_without_a_text_identifier_are_each_checked() -> None:
    first = _condition(None, value=None)
    second = _condition(None, value=None, condition_name="other")
    assert _refusals(_step("s1"), _step("s2", first, second)) == [
        Refusal(CONDITION_ROOT, _at(1, 1)),
        Refusal(DEPEND_ON_NULL, _at(1, 0, "condition_value")),
        Refusal(DEPEND_ON_NULL, _at(1, 1, "condition_value")),
    ]


def test_every_fault_of_a_step_tree_is_reported() -> None:
    group = _condition("c1", kind="AND", value=None)
    assert _refusals(
        _step("s1"),
        _step(
            "s2",
            group,
            _condition("c2", "c8"),
            _condition("c3", "c9"),
            _condition("c4", "c1", condition_is_root=True),
            _condition("c5", "c1", condition_is_root=None),
            _condition("c6"),
            _condition("c7"),
        ),
    ) == [
        Refusal(CONDITION_ROOT, _at(1, 1)),
        Refusal(CONDITION_ROOT, _at(1, 2)),
        Refusal(CONDITION_ROOT, _at(1, 3)),
        Refusal(CONDITION_ROOT, _at(1, 4)),
        Refusal(CONDITION_ROOT, _at(1, 5)),
        Refusal(CONDITION_ROOT, _at(1, 6)),
    ]


def test_a_child_under_a_parent_of_its_own_step_passes() -> None:
    group = _condition("c1", kind="AND", value=None)
    assert _refusals(_step("s1", group), _step("s2", _condition("c1", kind="AND", value=None))) == [
        Refusal(CONDITION_SHARED, _at(1, 0, "condition_id"))
    ]
    leaf = _condition("c2", "c1", kind="EQ", value="x")
    assert _refusals(_step("s1"), _step("s2", group, leaf)) == []


def test_the_first_of_two_differing_copies_is_the_one_checked() -> None:
    first, second = _condition("c1"), _condition("c1", condition_step_from_id="s1")
    assert _refusals(_step("s1"), _step("s2", first, second)) == [
        Refusal(CONDITION_ID_TWICE, _at(1, 1, "condition_id"))
    ]


def test_a_step_with_no_list_of_conditions_waits_for_nothing() -> None:
    assert _refusals({"step_id": "s1"}, {"step_id": "s2", "step_conditions": None}) == []


def test_a_condition_skipped_by_a_rule_does_not_stop_the_rule_on_the_next_ones() -> None:
    group = _condition("c1", kind="AND", value=None)
    odd = _condition(None, "c1", kind="EQ", value="x", condition_parent_id=["c1"])
    first, second = _condition("c2", "c1", value=None), _condition("c2", "c1", condition_name="x")
    orphan = _condition("c3", "c9")
    assert _refusals(_step("s1"), _step("s2", group, odd, first, second, orphan)) == [
        Refusal(CONDITION_ID_TWICE, _at(1, 3, "condition_id")),
        Refusal(CONDITION_ROOT, _at(1, 4)),
        Refusal(DEPEND_ON_NULL, _at(1, 2, "condition_value")),
    ]


def test_a_loop_through_every_step_is_found_at_each_of_them() -> None:
    count = 50
    steps = [_step(f"s{i}", _condition(f"c{i}", value=f"s{(i + 1) % count}")) for i in range(count)]
    assert _refusals(*steps) == [Refusal(CYCLE, _at(i)) for i in range(count)]


# The subset of the conditions a step may hold


DEPENDENCY_ONLY = frozenset({"DEPEND_ON"})


def _subset(*steps: dict[str, Any], supported: frozenset[str] = DEPENDENCY_ONLY) -> list[Refusal]:
    return list(subset_refusals(parsed_workflow({"workflow_steps": list(steps)}), supported))


def test_a_step_that_waits_for_one_step_or_none_is_in_the_subset() -> None:
    assert _subset(_step("s1"), _step("s2", _condition("c1"))) == []


@pytest.mark.parametrize("kind", ["EQ", "IN", "AND", "OR", "UNKNOWN", None])
def test_a_condition_of_a_type_not_supported_yet_is_refused(kind: object) -> None:
    assert _subset(_step("s1"), _step("s2", _condition("c1", kind=kind, value="x"))) == [
        Refusal(CONDITION_NOT_YET, _at(1, 0))
    ]


def test_a_mapper_is_refused_for_good_at_any_depth() -> None:
    group = _condition("c1", kind="AND", value=None)
    mapper = _condition("c2", "c1", kind="MAPPER", value="x")
    supported = frozenset({"DEPEND_ON", "AND", "MAPPER"})
    assert _subset(_step("s1"), _step("s2", group, mapper), supported=supported) == [
        Refusal(CONDITION_MAPPER, _at(1, 1))
    ]


def test_a_dependency_is_alone_at_the_root_of_its_step() -> None:
    group = _condition("c1", kind="AND", value=None)
    nested = _condition("c2", "c1")
    supported = frozenset({"DEPEND_ON", "AND"})
    assert _subset(_step("s1"), _step("s2", group, nested), supported=supported) == [
        Refusal(CONDITION_DEPEND_NESTED, _at(1, 1))
    ]
    with_filter = _condition("c3", "c2", kind="EQ", value="x")
    supported = frozenset({"DEPEND_ON", "EQ"})
    assert _subset(
        _step("s1"), _step("s2", _condition("c2"), with_filter), supported=supported
    ) == [Refusal(CONDITION_DEPEND_NESTED, _at(1, 0))]


def test_copies_of_a_dependency_count_once() -> None:
    dependency = _condition("c1")
    assert _subset(_step("s1"), _step("s2", dependency, dict(dependency))) == []


def test_every_condition_out_of_the_subset_is_reported_in_order() -> None:
    supported = frozenset({"DEPEND_ON", "AND"})
    group = _condition("c1", kind="AND", value=None)
    assert _subset(
        _step("s1"),
        _step(
            "s2", group, _condition("c2", "c1", kind="MAPPER"), _condition("c3", "c1", kind="EQ")
        ),
        supported=supported,
    ) == [Refusal(CONDITION_MAPPER, _at(1, 1)), Refusal(CONDITION_NOT_YET, _at(1, 2))]


@pytest.mark.parametrize("kind", [[], {}, 5])
def test_a_condition_type_that_is_not_text_is_not_supported(kind: object) -> None:
    assert _subset(_step("s1"), _step("s2", _condition("c1", kind=kind))) == [
        Refusal(CONDITION_NOT_YET, _at(1, 0))
    ]


def test_a_mapper_is_refused_for_good_with_the_list_of_the_cut() -> None:
    assert _subset(_step("s1"), _step("s2", _condition("c1", kind="MAPPER"))) == [
        Refusal(CONDITION_MAPPER, _at(1, 0))
    ]


# The full format: filters and AND / OR


FULL = frozenset(
    {"DEPEND_ON", "AND", "OR", "EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "NIN"}
    | {"IS_NULL", "IS_NOT_NULL"}
)


def _full(*steps: dict[str, Any]) -> list[Refusal]:
    return _subset(*steps, supported=FULL)


def _tree() -> list[dict[str, Any]]:
    """The tree of the second probe: an AND holding an EQ and an OR of an IN and an IS_NOT_NULL,
    each condition repeated once for each path to it, as the export lists them."""
    root = _condition("c1", kind="AND", value=None)
    equal = _condition("c2", "c1", kind="EQ", value="sshd", condition_key="process")
    either = _condition("c3", "c1", kind="OR", value=None)
    listed = _condition("c4", "c3", kind="IN", value="root,admin", condition_key="user")
    known = _condition("c5", "c3", kind="IS_NOT_NULL", value=None, condition_key="pid")
    return [root, equal, either, listed, known, equal, either, listed, known, listed, known]


def test_a_tree_of_filters_under_and_and_or_is_in_the_full_format() -> None:
    assert _full(_step("s1"), _step("s2", *_tree())) == []
    assert _refusals(_step("s1"), _step("s2", *_tree())) == []


def test_a_filter_holding_a_condition_is_refused() -> None:
    equal = _condition("c1", kind="EQ", value="x")
    child = _condition("c2", "c1", kind="EQ", value="y")
    assert _full(_step("s1"), _step("s2", equal, child)) == [
        Refusal(CONDITION_LEAF_CHILD, _at(1, 0))
    ]


@pytest.mark.parametrize("kind", ["AND", "OR"])
def test_a_group_holding_no_condition_is_refused(kind: str) -> None:
    assert _full(_step("s1"), _step("s2", _condition("c1", kind=kind, value=None))) == [
        Refusal(CONDITION_GROUP_EMPTY, _at(1, 0))
    ]


@pytest.mark.parametrize("kind", ["IN", "NIN"])
@pytest.mark.parametrize("value", ["", "  ", ",", " , ,", None])
def test_an_empty_list_is_refused(kind: str, value: object) -> None:
    assert _full(_step("s1"), _step("s2", _condition("c1", kind=kind, value=value))) == [
        Refusal(CONDITION_LIST_EMPTY, _at(1, 0, "condition_value"))
    ]


@pytest.mark.parametrize("value", ["a", " a ,", ",b"])
def test_a_list_with_a_value_passes(value: str) -> None:
    assert _full(_step("s1"), _step("s2", _condition("c1", kind="IN", value=value))) == []


@pytest.mark.parametrize("value", ["", None])
def test_a_filter_other_than_a_list_may_compare_with_nothing(value: object) -> None:
    assert _full(_step("s1"), _step("s2", _condition("c1", kind="EQ", value=value))) == []


@pytest.mark.parametrize("value", ["s1", "is S1 done", "c9", "after-c9"])
def test_a_filter_value_holding_a_step_or_condition_identifier_is_refused(value: str) -> None:
    other = _step("s3", _condition("c9", kind="EQ", value="x"))
    found = _full(_step("s1"), _step("s2", _condition("c1", kind="EQ", value=value)), other)
    assert found == [Refusal(CONDITION_VALUE_IDENTIFIER, _at(1, 0, "condition_value"))]


def test_a_dependency_value_is_the_step_it_names_not_a_filter_value() -> None:
    assert _full(_step("s1"), _step("s2", _condition("c1", value="s1"))) == []


def test_a_dependency_under_a_group_is_still_refused_in_the_full_format() -> None:
    group = _condition("c1", kind="AND", value=None)
    assert _full(_step("s1"), _step("s2", group, _condition("c2", "c1"))) == [
        Refusal(CONDITION_DEPEND_NESTED, _at(1, 1))
    ]


def test_a_mapper_is_still_refused_in_the_full_format() -> None:
    group = _condition("c1", kind="OR", value=None)
    mapper = _condition("c2", "c1", kind="MAPPER", value="x")
    assert _full(_step("s1"), _step("s2", group, mapper)) == [Refusal(CONDITION_MAPPER, _at(1, 1))]


@pytest.mark.parametrize("parent", [["c1"], {"id": "c1"}, 5])
def test_a_filter_whose_parent_is_not_text_leaves_its_group_empty(parent: object) -> None:
    group = _condition("c1", kind="AND", value=None)
    child = _condition("c2", parent, kind="EQ", value="x")
    assert _full(_step("s1"), _step("s2", group, child)) == [
        Refusal(CONDITION_GROUP_EMPTY, _at(1, 0))
    ]


@pytest.mark.parametrize("kind", ["EQ", "IN"])
@pytest.mark.parametrize("value", [["x"], {"v": "x"}, 5, True])
def test_a_filter_value_that_is_not_text_is_refused(kind: str, value: object) -> None:
    assert _full(_step("s1"), _step("s2", _condition("c1", kind=kind, value=value))) == [
        Refusal(CONDITION_VALUE_SHAPE, _at(1, 0, "condition_value"))
    ]


@pytest.mark.parametrize("value", ["s1", "x", ""])
def test_a_group_with_a_value_is_refused(value: str) -> None:
    group = _condition("c1", kind="OR", value=value)
    child = _condition("c2", "c1", kind="EQ", value="y")
    assert _full(_step("s1"), _step("s2", group, child)) == [
        Refusal(CONDITION_VALUE_SHAPE, _at(1, 0, "condition_value"))
    ]


def test_an_identifier_is_found_in_a_value_whatever_its_case() -> None:
    found = _full(_step("S1"), _step("s2", _condition("c1", kind="EQ", value="after s1")))
    assert found == [Refusal(CONDITION_VALUE_IDENTIFIER, _at(1, 0, "condition_value"))]


def test_a_group_without_an_identifier_beside_a_root_holds_nothing() -> None:
    root = _condition("c1", kind="AND", value=None)
    unnamed = _condition(None, "c1", kind="OR", value=None)
    leaf = _condition("c3", "c1", kind="EQ", value="x")
    assert _full(_step("s1"), _step("s2", root, unnamed, leaf)) == [
        Refusal(CONDITION_GROUP_EMPTY, _at(1, 1))
    ]


@pytest.mark.parametrize("unnamed", ["", None, 5])
def test_an_identifier_that_is_empty_or_not_text_is_never_looked_for(unnamed: object) -> None:
    found = _full(_step(unnamed), _step("s2", _condition("c1", kind="EQ", value="any text")))
    assert found == []
