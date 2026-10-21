"""The workflow of a stored scenario as the checks first read it: whether there is one, its keys
and its bounds, each refusal with a fixed message and the pointer of the node at fault."""

import copy
from typing import Any

import pytest

from scenario_tools.domain.shared.workflow import (
    EXPORT_VERSION_UNKNOWN,
    INJECTS_AND_WORKFLOW,
    KEY_LEGACY,
    KEY_UNKNOWN,
    MAX_CONDITIONS,
    MAX_DEPTH,
    MAX_SCOPE,
    MAX_STEPS,
    NOT_A_LIST,
    NOT_AN_OBJECT,
    TOO_DEEP,
    TOO_MANY_CONDITIONS,
    TOO_MANY_ENTRIES,
    TOO_MANY_STEPS,
    WORKFLOW_NO_STEP,
    ExportKeys,
    Refusal,
    export_refusals,
    has_workflow,
)
from tests.support.workflow import KEYS, KEYS_DOCUMENT


def _condition(identifier: str, parent: str | None = None, **fields: object) -> dict[str, Any]:
    return {
        "condition_id": identifier,
        "condition_type": "DEPEND_ON" if parent is None else "EQ",
        "condition_parent_id": parent,
        "condition_is_root": parent is None,
        **fields,
    }


def _step(identifier: str, *conditions: dict[str, Any]) -> dict[str, Any]:
    return {
        "step_id": identifier,
        "step_action_class": "INJECT_EXECUTION",
        "step_data": {},
        "step_conditions": list(conditions),
    }


def _export(**changes: Any) -> dict[str, Any]:
    export: dict[str, Any] = {
        "export_version": 1,
        "scenario_information": {"scenario_name": "Probe"},
        "scenario_injects": [],
        "scenario_workflow": {
            "workflow_steps": [_step("s1"), _step("s2", _condition("c1", condition_value="s1"))],
            "workflow_scope_rules": [],
            "workflow_scope_variables": [],
            "workflow_standalone_conditions": [],
        },
    }
    export.update(changes)
    return export


STEP_CONDITIONS = "/scenario_workflow/workflow_steps/1/step_conditions"


def _first(export: object) -> Refusal | None:
    return next(export_refusals(export, KEYS), None)


def test_a_well_shaped_workflow_and_a_time_based_export_pass() -> None:
    assert _first(_export()) is None
    assert _first(_export(scenario_workflow=None, scenario_injects=[{"inject_id": "i"}])) is None


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ({"scenario_workflow": {"workflow_steps": []}}, True),
        ({"scenario_workflow": {}}, False),
        ({"scenario_workflow": None}, False),
        ({}, False),
        ({"scenario_workflow": "text"}, True),
        ({"scenario_workflow": []}, True),
        ({"scenario_workflow": 0}, True),
        ([], False),
    ],
)
def test_a_workflow_is_any_part_that_is_not_null_or_empty(stored: object, expected: bool) -> None:
    assert has_workflow(stored) is expected


@pytest.mark.parametrize("version", [2, 0, None, "1", True])
def test_an_export_version_outside_the_closed_list_is_refused(version: object) -> None:
    assert _first(_export(export_version=version)) == Refusal(
        EXPORT_VERSION_UNKNOWN, "/export_version"
    )


def test_an_export_without_a_version_is_refused() -> None:
    export = _export()
    del export["export_version"]
    assert _first(export) == Refusal(EXPORT_VERSION_UNKNOWN, "/export_version")


def test_injects_and_a_workflow_together_are_refused() -> None:
    export = _export(scenario_injects=[{"inject_id": "i"}])
    assert _first(export) == Refusal(INJECTS_AND_WORKFLOW, "/scenario_workflow")


def test_a_workflow_with_no_step_is_refused() -> None:
    export = _export()
    export["scenario_workflow"]["workflow_steps"] = []
    assert _first(export) == Refusal(WORKFLOW_NO_STEP, "/scenario_workflow/workflow_steps")


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (lambda e: e.update(scenario_workflow="text"), "/scenario_workflow"),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"].append("text"),
            "/scenario_workflow/workflow_steps/2",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"][1]["step_conditions"].append(None),
            "/scenario_workflow/workflow_steps/1/step_conditions/1",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_scope_rules"].append(1),
            "/scenario_workflow/workflow_scope_rules/0",
        ),
    ],
)
def test_a_node_that_is_not_an_object_is_refused(change: Any, pointer: str) -> None:
    export = _export()
    change(export)
    assert _first(export) == Refusal(NOT_AN_OBJECT, pointer)


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (
            lambda e: e["scenario_workflow"].update(workflow_steps="text"),
            "/scenario_workflow/workflow_steps",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"][0].update(step_conditions={}),
            "/scenario_workflow/workflow_steps/0/step_conditions",
        ),
        (
            lambda e: e["scenario_workflow"].update(workflow_standalone_conditions=None),
            "/scenario_workflow/workflow_standalone_conditions",
        ),
    ],
)
def test_a_list_of_another_shape_is_refused(change: Any, pointer: str) -> None:
    export = _export()
    change(export)
    assert _first(export) == Refusal(NOT_A_LIST, pointer)


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (
            lambda e: e["scenario_workflow"].update(workflow_owner="x"),
            "/scenario_workflow/workflow_owner",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"][0].update(step_owner="x"),
            "/scenario_workflow/workflow_steps/0/step_owner",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"][1]["step_conditions"][0].update(
                condition_case_sensitive=False
            ),
            "/scenario_workflow/workflow_steps/1/step_conditions/0/condition_case_sensitive",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_scope_rules"].append({"x": 1}),
            "/scenario_workflow/workflow_scope_rules/0/x",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_scope_variables"].append(
                {"scope_variable_key": "k", "scope_variable_label": "x"}
            ),
            "/scenario_workflow/workflow_scope_variables/0/scope_variable_label",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_standalone_conditions"].append(
                {"condition_id": "c", "condition_owner": "x"}
            ),
            "/scenario_workflow/workflow_standalone_conditions/0/condition_owner",
        ),
        (  # a key that is not a plain name is not repeated: the pointer is its node's
            lambda e: e["scenario_workflow"].update({"a/b~c\n\u202e": 1}),
            "/scenario_workflow",
        ),
        (
            lambda e: e["scenario_workflow"]["workflow_steps"][0].update({"x" * 65: 1}),
            "/scenario_workflow/workflow_steps/0",
        ),
    ],
)
def test_a_key_outside_the_closed_lists_is_refused_at_its_pointer(
    change: Any, pointer: str
) -> None:
    export = _export()
    change(export)
    assert _first(export) == Refusal(KEY_UNKNOWN, pointer)


def test_the_legacy_key_type_of_a_condition_is_refused_by_name() -> None:
    export = _export()
    condition = export["scenario_workflow"]["workflow_steps"][1]["step_conditions"][0]
    condition["condition_key_type"] = "text"
    assert _first(export) == Refusal(
        KEY_LEGACY, "/scenario_workflow/workflow_steps/1/step_conditions/0/condition_key_type"
    )


def test_every_key_of_the_closed_lists_passes() -> None:
    export = _export()
    workflow = export["scenario_workflow"]
    workflow.update(dict.fromkeys(KEYS.workflow - set(workflow), None))
    workflow["workflow_scope_rule_team_members"] = []
    step = workflow["workflow_steps"][1]
    step.update(dict.fromkeys(KEYS.step - set(step), None))
    step["step_conditions"][0].update(
        dict.fromkeys(KEYS.condition - set(step["step_conditions"][0]), None)
    )
    workflow["workflow_scope_rules"] = [dict.fromkeys(KEYS.scope_rule)]
    workflow["workflow_scope_variables"] = [dict.fromkeys(KEYS.scope_variable)]
    step["step_conditions"][0]["condition_parent_id"] = None
    assert _first(export) is None


def test_a_missing_list_counts_as_empty() -> None:
    export = _export()
    del export["scenario_workflow"]["workflow_scope_rules"]
    del export["scenario_workflow"]["workflow_steps"][0]["step_conditions"]
    assert _first(export) is None


def test_the_step_bound_is_inclusive() -> None:
    export = _export()
    steps = [_step(f"s{index}") for index in range(MAX_STEPS)]
    export["scenario_workflow"]["workflow_steps"] = steps
    assert _first(export) is None
    steps.append(_step("one too many"))
    assert _first(export) == Refusal(TOO_MANY_STEPS, "/scenario_workflow/workflow_steps")


def test_the_condition_bound_counts_each_condition_once() -> None:
    export = _export()
    conditions = [_condition("root", condition_type="AND")]
    conditions += [_condition(f"c{index}", "root") for index in range(MAX_CONDITIONS - 1)]
    step = export["scenario_workflow"]["workflow_steps"][1]
    step["step_conditions"] = conditions + copy.deepcopy(conditions[1:])  # repeated as exported
    assert _first(export) is None
    step["step_conditions"].append(_condition("one too many", "root"))
    assert _first(export) == Refusal(
        TOO_MANY_CONDITIONS, "/scenario_workflow/workflow_steps/1/step_conditions"
    )


def test_the_entries_of_a_step_are_bounded_too() -> None:
    export = _export()
    condition = _condition("c1", condition_value="s1")
    export["scenario_workflow"]["workflow_steps"][1]["step_conditions"] = [condition] * (
        MAX_CONDITIONS * (MAX_DEPTH + 1) + 1
    )
    assert _first(export) == Refusal(
        TOO_MANY_CONDITIONS, "/scenario_workflow/workflow_steps/1/step_conditions"
    )


def _chain(length: int) -> list[dict[str, Any]]:
    conditions = [_condition("c0", condition_type="AND")]
    conditions += [_condition(f"c{index}", f"c{index - 1}") for index in range(1, length)]
    return conditions


def test_the_depth_bound_is_inclusive() -> None:
    export = _export()
    step = export["scenario_workflow"]["workflow_steps"][1]
    step["step_conditions"] = _chain(MAX_DEPTH + 1)  # a root then sixteen levels below it
    assert _first(export) is None
    step["step_conditions"] = _chain(MAX_DEPTH + 2)
    assert _first(export) == Refusal(
        TOO_DEEP, "/scenario_workflow/workflow_steps/1/step_conditions"
    )


def test_parents_that_form_a_loop_are_refused_as_too_deep() -> None:
    export = _export()
    export["scenario_workflow"]["workflow_steps"][1]["step_conditions"] = [
        _condition("a", "b"),
        _condition("b", "a"),
    ]
    assert _first(export) == Refusal(
        TOO_DEEP, "/scenario_workflow/workflow_steps/1/step_conditions"
    )


def test_the_closed_lists_are_read_as_data() -> None:
    assert KEYS.export_versions == frozenset({1})
    assert "workflow_steps" in KEYS.workflow
    assert KEYS.condition_legacy == frozenset({"condition_key_type"})


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(export_versions=["1"]),
        lambda d: d.update(export_versions=[True]),
        lambda d: d.update(export_versions=[]),
        lambda d: d["workflow"].update(keys="x"),
        lambda d: d["workflow"].update(keys=[""]),
        lambda d: d.update(step=[]),
        lambda d: d.pop("condition"),
        lambda d: d["condition"].update(legacy=[1]),
    ],
)
def test_malformed_closed_lists_are_refused(change: Any) -> None:
    document = copy.deepcopy(KEYS_DOCUMENT)
    change(document)
    with pytest.raises(ValueError, match=r"^export-keys: "):
        ExportKeys.from_document(document)


def test_a_document_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ValueError, match=r"^export-keys: "):
        ExportKeys.from_document([])


@pytest.mark.parametrize("stored", [None, [], "text"])
def test_a_document_that_is_not_an_object_has_no_refusal_of_its_own(stored: object) -> None:
    assert _first(stored) is None


def test_identifiers_that_are_not_text_are_left_to_later_checks() -> None:
    export = _export()
    export["scenario_workflow"]["workflow_steps"][1]["step_conditions"] = [
        {"condition_id": ["a"], "condition_parent_id": {"b": 1}},
        {"condition_id": "c", "condition_parent_id": ["a"]},
    ]
    assert _first(export) is None


def test_the_refusals_come_in_their_documented_order() -> None:
    export = _export(export_version=2, scenario_injects=[{"inject_id": "i"}])
    workflow = export["scenario_workflow"]
    workflow["workflow_owner"] = "x"
    workflow["workflow_scope_rules"] = [{"x": 1}]
    workflow["workflow_steps"] = [_step(f"s{index}") for index in range(MAX_STEPS + 1)]
    assert list(export_refusals(export, KEYS)) == [
        Refusal(EXPORT_VERSION_UNKNOWN, "/export_version"),
        Refusal(INJECTS_AND_WORKFLOW, "/scenario_workflow"),
        Refusal(KEY_UNKNOWN, "/scenario_workflow/workflow_owner"),
        Refusal(KEY_UNKNOWN, "/scenario_workflow/workflow_scope_rules/0/x"),
        Refusal(TOO_MANY_STEPS, "/scenario_workflow/workflow_steps"),
    ]


@pytest.mark.parametrize(
    "part", ["workflow_scope_rules", "workflow_scope_variables", "workflow_standalone_conditions"]
)
def test_the_scope_lists_are_bounded_inclusively(part: str) -> None:
    export = _export()
    export["scenario_workflow"][part] = [{} for _ in range(MAX_SCOPE)]
    assert _first(export) is None
    export["scenario_workflow"][part].append({})
    assert _first(export) == Refusal(TOO_MANY_ENTRIES, f"/scenario_workflow/{part}")


@pytest.mark.parametrize("part", ["workflow_scope_rules", "workflow_scope_variables"])
def test_a_scope_list_of_another_shape_is_refused(part: str) -> None:
    export = _export()
    export["scenario_workflow"][part] = "text"
    assert _first(export) == Refusal(NOT_A_LIST, f"/scenario_workflow/{part}")


def test_conditions_linked_to_no_step_are_bounded_in_depth_too() -> None:
    export = _export()
    export["scenario_workflow"]["workflow_standalone_conditions"] = _chain(MAX_DEPTH + 2)
    assert _first(export) == Refusal(TOO_DEEP, "/scenario_workflow/workflow_standalone_conditions")


def test_the_entries_bound_of_a_step_is_inclusive() -> None:
    export = _export()
    condition = _condition("c1", condition_value="s1")
    export["scenario_workflow"]["workflow_steps"][1]["step_conditions"] = [condition] * (
        MAX_CONDITIONS * (MAX_DEPTH + 1)
    )
    assert _first(export) is None


def test_reading_goes_on_past_a_list_beyond_its_bound() -> None:
    export = _export()
    workflow = export["scenario_workflow"]
    workflow["workflow_scope_rules"] = [{} for _ in range(MAX_SCOPE + 1)]
    workflow["workflow_steps"][0]["step_owner"] = "x"
    assert list(export_refusals(export, KEYS)) == [
        Refusal(TOO_MANY_ENTRIES, "/scenario_workflow/workflow_scope_rules"),
        Refusal(KEY_UNKNOWN, "/scenario_workflow/workflow_steps/0/step_owner"),
    ]


def test_steps_of_another_shape_end_the_reading() -> None:
    export = _export()
    export["scenario_workflow"]["workflow_steps"] = "text"
    assert list(export_refusals(export, KEYS)) == [
        Refusal(NOT_A_LIST, "/scenario_workflow/workflow_steps")
    ]


def test_a_workflow_that_is_not_an_object_ends_the_reading() -> None:
    assert list(export_refusals(_export(scenario_workflow="text"), KEYS)) == [
        Refusal(NOT_AN_OBJECT, "/scenario_workflow")
    ]
