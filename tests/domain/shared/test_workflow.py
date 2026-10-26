"""The workflow of a stored scenario as the checks first read it: whether there is one, its keys
and its bounds, each refusal with a fixed message and the pointer of the node at fault."""

import copy
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.shared.stored_workflow import conditions, holds_workflow, parsed_workflow
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
    SCOPE_NOT_EMPTY,
    SETTINGS_BOUNDS,
    STANDALONE_NOT_EMPTY,
    TOO_DEEP,
    TOO_MANY_CONDITIONS,
    TOO_MANY_ENTRIES,
    TOO_MANY_STEPS,
    WORKFLOW_NO_STEP,
    ExportKeys,
    Refusal,
    export_refusals,
    has_workflow,
    settled_workflow,
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
    refused = [refusal.what for refusal in export_refusals(export, KEYS)]
    # the example fills every key, so only its values are refused: settings and scope
    assert set(refused) <= {SETTINGS_BOUNDS, SCOPE_NOT_EMPTY}


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


@pytest.mark.parametrize("before", [True, False])
def test_a_copy_of_a_condition_under_another_parent_does_not_hide_the_depth(before: bool) -> None:
    export = _export()
    chain = _chain(MAX_DEPTH + 2)
    copied = _condition(f"c{MAX_DEPTH}")  # the condition above the last one, with no parent
    conditions = [copied, *chain] if before else [*chain, copied]
    export["scenario_workflow"]["workflow_steps"][1]["step_conditions"] = conditions
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
        Refusal(SCOPE_NOT_EMPTY, "/scenario_workflow/workflow_scope_rules"),
        Refusal(TOO_MANY_STEPS, "/scenario_workflow/workflow_steps"),
    ]


@pytest.mark.parametrize(
    "part", ["workflow_scope_rules", "workflow_scope_variables", "workflow_standalone_conditions"]
)
def test_the_scope_lists_are_bounded_inclusively(part: str) -> None:
    export = _export()
    export["scenario_workflow"][part] = [{} for _ in range(MAX_SCOPE)]
    within = STANDALONE_NOT_EMPTY if part == "workflow_standalone_conditions" else SCOPE_NOT_EMPTY
    assert _first(export) == Refusal(within, f"/scenario_workflow/{part}")
    export["scenario_workflow"][part].append({})
    assert _first(export) == Refusal(TOO_MANY_ENTRIES, f"/scenario_workflow/{part}")


@pytest.mark.parametrize("part", ["workflow_scope_rules", "workflow_scope_variables"])
def test_a_scope_list_of_another_shape_is_refused(part: str) -> None:
    export = _export()
    export["scenario_workflow"][part] = "text"
    assert _first(export) == Refusal(NOT_A_LIST, f"/scenario_workflow/{part}")


def test_conditions_linked_to_no_step_are_refused_without_reading_their_tree() -> None:
    export = _export()
    export["scenario_workflow"]["workflow_standalone_conditions"] = _chain(MAX_DEPTH + 2)
    assert list(export_refusals(export, KEYS)) == [
        Refusal(STANDALONE_NOT_EMPTY, "/scenario_workflow/workflow_standalone_conditions")
    ]


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


# Settings and scope


def _with(**settings: object) -> dict[str, Any]:
    export = _export()
    export["scenario_workflow"].update(settings)
    return export


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {"workflow_timeout_enabled": True, "workflow_timeout_seconds": 60},
        {"workflow_timeout_seconds": 3600},
        {"workflow_safe_mode_enabled": True},
        {"workflow_rate_limit_enabled": False, "workflow_max_attempts": None},
        {
            "workflow_rate_limit_enabled": True,
            "workflow_max_attempts": 1,
            "workflow_max_temporal_rate_seconds": 1,
        },
        {
            "workflow_rate_limit_enabled": True,
            "workflow_max_attempts": 99,
            "workflow_max_temporal_rate_seconds": 5940,
        },
        {"workflow_scope_rule_team_members": []},
        {"workflow_timeout_seconds": None, "workflow_safe_mode_enabled": None},
        {"workflow_rate_limit_enabled": None, "workflow_timeout_enabled": None},
    ],
)
def test_settings_within_their_bounds_pass(settings: dict[str, object]) -> None:
    assert _first(_with(**settings)) is None


@pytest.mark.parametrize(
    ("settings", "key"),
    [
        ({"workflow_timeout_enabled": False}, "workflow_timeout_enabled"),
        ({"workflow_timeout_seconds": 59}, "workflow_timeout_seconds"),
        ({"workflow_timeout_seconds": 3601}, "workflow_timeout_seconds"),
        ({"workflow_timeout_seconds": True}, "workflow_timeout_seconds"),
        ({"workflow_safe_mode_enabled": False}, "workflow_safe_mode_enabled"),
        ({"workflow_rate_limit_enabled": "yes"}, "workflow_rate_limit_enabled"),
        ({"workflow_max_attempts": 3}, "workflow_max_attempts"),
        ({"workflow_max_temporal_rate_seconds": 10}, "workflow_max_temporal_rate_seconds"),
        (
            {"workflow_rate_limit_enabled": True, "workflow_max_temporal_rate_seconds": 10},
            "workflow_max_attempts",
        ),
        (
            {
                "workflow_rate_limit_enabled": True,
                "workflow_max_attempts": 100,
                "workflow_max_temporal_rate_seconds": 10,
            },
            "workflow_max_attempts",
        ),
        (
            {
                "workflow_rate_limit_enabled": True,
                "workflow_max_attempts": 1,
                "workflow_max_temporal_rate_seconds": 5941,
            },
            "workflow_max_temporal_rate_seconds",
        ),
        (
            {
                "workflow_rate_limit_enabled": True,
                "workflow_max_attempts": 1,
                "workflow_max_temporal_rate_seconds": 0,
            },
            "workflow_max_temporal_rate_seconds",
        ),
        (
            {
                "workflow_rate_limit_enabled": True,
                "workflow_max_attempts": 0,
                "workflow_max_temporal_rate_seconds": 10,
            },
            "workflow_max_attempts",
        ),
    ],
)
def test_a_setting_outside_its_bounds_is_refused_at_its_key(
    settings: dict[str, object], key: str
) -> None:
    assert _first(_with(**settings)) == Refusal(SETTINGS_BOUNDS, f"/scenario_workflow/{key}")


@pytest.mark.parametrize(
    "part",
    [
        "workflow_scope_rules",
        "workflow_scope_variables",
        "workflow_scope_rule_team_members",
        "workflow_standalone_conditions",
    ],
)
def test_a_scope_or_a_condition_linked_to_no_step_is_refused_never_removed(part: str) -> None:
    refused = STANDALONE_NOT_EMPTY if part == "workflow_standalone_conditions" else SCOPE_NOT_EMPTY
    assert _first(_with(**{part: [{}]})) == Refusal(refused, f"/scenario_workflow/{part}")


def test_settings_are_written_as_the_import_applies_them_when_missing() -> None:
    settled = settled_workflow({"workflow_version": 3, "workflow_steps": []})
    assert settled == {
        "workflow_steps": [],
        "workflow_rate_limit_enabled": False,
        "workflow_max_attempts": None,
        "workflow_max_temporal_rate_seconds": None,
        "workflow_timeout_enabled": True,
        "workflow_timeout_seconds": 3600,
        "workflow_safe_mode_enabled": True,
        "workflow_scope_rules": [],
        "workflow_scope_variables": [],
        "workflow_standalone_conditions": [],
    }


def test_null_lists_and_settings_are_written_as_when_absent() -> None:
    settled = settled_workflow(
        {
            "workflow_steps": [],
            "workflow_scope_rules": None,
            "workflow_timeout_seconds": None,
            "workflow_scope_rule_team_members": [],
            "workflow_other": 1,
        }
    )
    assert settled["workflow_scope_rules"] == []
    assert settled["workflow_timeout_seconds"] == 3600
    assert "workflow_scope_rule_team_members" not in settled
    assert settled["workflow_other"] == 1


def test_settings_given_are_kept_and_the_version_removed() -> None:
    workflow = {"workflow_version": 2, "workflow_timeout_seconds": 600}
    settled = settled_workflow(workflow)
    assert settled["workflow_timeout_seconds"] == 600
    assert "workflow_version" not in settled
    assert workflow == {"workflow_version": 2, "workflow_timeout_seconds": 600}  # untouched


@given(st.integers(min_value=-10_000, max_value=10_000))
def test_the_delay_is_bounded_at_every_value(seconds: int) -> None:
    refusal = _first(_with(workflow_timeout_seconds=seconds))
    assert (refusal is None) == (60 <= seconds <= 3600)


_NOT_WHOLE: st.SearchStrategy[object] = st.one_of(
    st.booleans(), st.floats(), st.text(), st.just([])
)


@given(_NOT_WHOLE)
def test_a_value_that_is_not_a_whole_number_is_refused_for_every_number(value: object) -> None:
    for key in ("workflow_timeout_seconds", "workflow_max_attempts"):
        settings: dict[str, object] = {
            "workflow_rate_limit_enabled": True,
            "workflow_max_attempts": 1,
        }
        settings |= {"workflow_max_temporal_rate_seconds": 1, key: value}
        assert _first(_with(**settings)) == Refusal(SETTINGS_BOUNDS, f"/scenario_workflow/{key}")


@given(st.integers(min_value=-200, max_value=6000), st.integers(min_value=-200, max_value=6000))
def test_the_pace_is_bounded_at_every_value(attempts: int, period: int) -> None:
    refusal = _first(
        _with(
            workflow_rate_limit_enabled=True,
            workflow_max_attempts=attempts,
            workflow_max_temporal_rate_seconds=period,
        )
    )
    assert (refusal is None) == (1 <= attempts <= 99 and 1 <= period <= 5940)


def test_settings_scope_and_conditions_linked_to_no_step_come_in_order() -> None:
    export = _with(
        workflow_safe_mode_enabled=False,
        workflow_scope_rule_team_members=[{}],
        workflow_scope_rules=[{}],
        workflow_standalone_conditions=[{}],
    )
    assert [refusal.pointer for refusal in export_refusals(export, KEYS)] == [
        "/scenario_workflow/workflow_safe_mode_enabled",
        "/scenario_workflow/workflow_scope_rule_team_members",
        "/scenario_workflow/workflow_scope_rules",
        "/scenario_workflow/workflow_standalone_conditions",
    ]


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(step_data=[]),
        lambda d: d["step_data"].update(removed="x"),
        lambda d: d["step_data"].update(must_equal=[]),
        lambda d: d["step_data"].update(must_equal={"inject_id": []}),
        lambda d: d["step_data"].update(injectors=[{"id": "x"}]),
        lambda d: d["step_data"].update(injectors={}),
    ],
)
def test_a_malformed_step_classification_is_refused(change: Any) -> None:
    document = copy.deepcopy(KEYS_DOCUMENT)
    change(document)
    with pytest.raises(ValueError, match=r"^export-keys: step_data"):
        ExportKeys.from_document(document)


def test_a_parsed_workflow_reads_steps_and_conditions_with_their_pointers() -> None:
    condition = {"condition_id": "c1", "condition_parent_id": None, "condition_type": "DEPEND_ON"}
    parsed = parsed_workflow(
        {"workflow_steps": [{"step_id": 7}, {"step_id": "s2", "step_conditions": [condition]}]}
    )
    first, second = parsed.steps
    assert (first.pointer, first.identifier, first.conditions) == (
        "/scenario_workflow/workflow_steps/0",
        None,
        (),
    )
    assert second.identifier == "s2"
    (only,) = second.conditions
    assert only.pointer == "/scenario_workflow/workflow_steps/1/step_conditions/0"
    assert (only.identifier, only.parent, only.kind) == ("c1", None, "DEPEND_ON")
    assert parsed_workflow({}).steps == ()


def test_the_conditions_of_a_stored_workflow_are_walked_leniently() -> None:
    condition = {"condition_id": "c1"}
    stored = {
        "scenario_workflow": {
            "workflow_steps": [
                {"step_conditions": [condition, "not an object"]},
                {"step_conditions": "not a list"},
                "not a step",
                {},
            ]
        }
    }
    assert list(conditions(stored)) == [
        ("/scenario_workflow/workflow_steps/0/step_conditions/0", condition)
    ]
    assert list(conditions({"scenario_workflow": {"workflow_steps": "x"}})) == []
    assert list(conditions({"scenario_workflow": "x"})) == []
    assert list(conditions("not a scenario")) == []


@pytest.mark.parametrize(
    ("workflow", "held"),
    [(None, False), ({}, False), ([], False), ({"workflow_steps": []}, True), ("x", True)],
)
def test_a_stored_scenario_holds_a_workflow_unless_the_part_is_left_empty(
    workflow: object, held: bool
) -> None:
    assert holds_workflow({"scenario_workflow": workflow}) is held
    assert holds_workflow({}) is False
    assert holds_workflow("not a scenario") is False
