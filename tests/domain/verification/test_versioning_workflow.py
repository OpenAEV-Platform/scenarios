"""The version a change to a scenario in chaining needs: a step added or removed, or what a step
waits for, needs a major version; the rest of a step and a workflow setting, a minor one; and a
step's inject is classed field by field as an inject is."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.verification.versioning import (
    Bump,
    changes,
    diff_findings,
    located_changes,
    required_bump,
    versioning_findings,
)

ROOT = Path(__file__).resolve().parents[3]
STORED: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json").read_text("utf-8")
)
FILTERED: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "filters.normalised.json").read_text("utf-8")
)
METADATA = {"external_id": "x", "version": "1.0.0"}
STEPS = "/scenario_workflow/workflow_steps"
JSON = "scenarios/techniques/x/scenario.json"


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = document["scenario_workflow"]["workflow_steps"]
    return steps


def _first(document: dict[str, Any]) -> dict[str, Any]:
    return next(step for step in _steps(document) if not step["step_conditions"])


def _waiting(document: dict[str, Any]) -> dict[str, Any]:
    return next(step for step in _steps(document) if step["step_conditions"])


def _bump(after: dict[str, Any], before: dict[str, Any] = STORED) -> Bump:
    return required_bump(changes(METADATA, before, METADATA, after)).bump


@pytest.mark.parametrize("stored", [STORED, FILTERED])
def test_an_entry_compared_with_itself_has_no_change(stored: dict[str, Any]) -> None:
    assert changes(METADATA, stored, METADATA, copy.deepcopy(stored)) == []


def test_a_step_added_or_removed_needs_a_major_version() -> None:
    added = copy.deepcopy(STORED)
    _steps(added).append({**copy.deepcopy(_first(added)), "step_id": "added-step"})
    removed = copy.deepcopy(STORED)
    _steps(removed).remove(_first(removed))
    assert _bump(added) == Bump.MAJOR
    assert _bump(removed) == Bump.MAJOR
    reasons = {c.reason for c in changes(METADATA, STORED, METADATA, added)}
    assert reasons == {"a step added"}


def test_what_a_step_waits_for_changed_needs_a_major_version() -> None:
    after = copy.deepcopy(STORED)
    _waiting(after)["step_conditions"][0]["condition_name"] = "Another name"
    (found,) = located_changes(METADATA, STORED, METADATA, after)
    assert (found.change.bump, found.change.reason) == (Bump.MAJOR, "a step's conditions changed")
    index = _steps(after).index(_waiting(after))
    assert found.field == f"{STEPS}/{index}/step_conditions"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("workflow_timeout_seconds", 120),
        ("workflow_rate_limit_enabled", True),
        ("workflow_max_attempts", 3),
    ],
)
def test_a_workflow_setting_changed_needs_a_minor_version(key: str, value: object) -> None:
    after = copy.deepcopy(STORED)
    after["scenario_workflow"][key] = value
    (found,) = located_changes(METADATA, STORED, METADATA, after)
    assert (found.change.bump, found.change.reason) == (Bump.MINOR, "a workflow setting changed")
    assert found.field == f"/scenario_workflow/{key}"


def test_the_rest_of_a_step_needs_a_minor_version() -> None:
    after = copy.deepcopy(STORED)
    _first(after)["step_action_class"] = "SOMETHING_ELSE"
    (found,) = located_changes(METADATA, STORED, METADATA, after)
    assert (found.change.bump, found.change.reason) == (
        Bump.MINOR,
        "a step's step_action_class changed",
    )


@pytest.mark.parametrize(
    ("change", "bump"),
    [
        (lambda data: data.update(inject_title="Another title"), Bump.PATCH),
        (lambda data: data.update(inject_description="Another"), Bump.PATCH),
        (
            lambda data: data["inject_injector_contract"]["injector_contract_payload"].update(
                command_content="ps -e"
            ),
            Bump.MINOR,
        ),
        (
            lambda data: data["inject_injector_contract"].update(injector_contract_id="other"),
            Bump.MAJOR,
        ),
    ],
)
def test_a_step_s_inject_is_classed_as_an_inject(change: Any, bump: Bump) -> None:
    after = copy.deepcopy(STORED)
    change(_first(after)["step_data"])
    assert _bump(after) == bump
    index = _steps(after).index(_first(after))
    assert all(
        located.field.startswith(f"{STEPS}/{index}/step_data")
        for located in located_changes(METADATA, STORED, METADATA, after)
    )


def test_a_step_retitled_reads_as_a_step_removed_and_one_added() -> None:
    after = copy.deepcopy(STORED)
    step = _first(after)
    step["step_id"] = "retitled-step"  # normalisation gives a retitled step a new identifier
    step["step_data"]["inject_title"] = "Another title"
    reasons = [c.reason for c in changes(METADATA, STORED, METADATA, after)]
    assert reasons[:2] == ["a step removed", "a step added"]
    assert _bump(after) == Bump.MAJOR


def test_a_workflow_of_another_shape_is_a_major_change() -> None:
    after = copy.deepcopy(STORED)
    after["scenario_workflow"] = "text"
    assert _bump(after) == Bump.MAJOR
    steps_text = copy.deepcopy(STORED)
    steps_text["scenario_workflow"]["workflow_steps"] = "text"
    assert _bump(steps_text) == Bump.MAJOR


def test_a_step_re_added_under_a_new_identifier_is_ver_003() -> None:
    after = copy.deepcopy(STORED)
    _first(after)["step_id"] = "new-identifier"
    found = versioning_findings(
        (METADATA, STORED),
        {**METADATA, "version": "2.0.0"},
        after,
        metadata_path="scenarios/techniques/x/scenario.yaml",
        scenario_path=JSON,
    )
    index = _steps(after).index(_first(after))
    assert [(f.code, f.field) for f in found] == [("VER-003", f"{STEPS}/{index}/step_id")]


@given(st.sampled_from(range(2)), st.text(max_size=5))
def test_an_untouched_step_gives_no_change(index: int, title: str) -> None:
    after = copy.deepcopy(STORED)
    touched = _steps(after)[index]
    touched["step_data"]["inject_description"] = title
    for located in located_changes(METADATA, STORED, METADATA, after):
        assert located.field.startswith(f"{STEPS}/{index}/")


def _reasons(after: dict[str, Any], before: dict[str, Any] = STORED) -> list[tuple[Bump, str]]:
    return [(c.bump, c.reason) for c in changes(METADATA, before, METADATA, after)]


def test_conditions_linked_to_no_step_or_run_state_of_conditions_need_a_major_version() -> None:
    standalone = copy.deepcopy(STORED)
    standalone["scenario_workflow"]["workflow_standalone_conditions"] = [{"condition_id": "c"}]
    executed = copy.deepcopy(STORED)
    _first(executed)["step_condition_executed"] = True
    assert _reasons(standalone) == [(Bump.MAJOR, "a workflow's conditions changed")]
    assert _reasons(executed) == [(Bump.MAJOR, "a step's conditions changed")]


@pytest.mark.parametrize("data", ["text", None, []])
def test_a_step_s_inject_of_another_shape_is_a_major_change(data: object) -> None:
    after = copy.deepcopy(STORED)
    _first(after)["step_data"] = data
    assert _reasons(after) == [(Bump.MAJOR, "a step's inject changed")]


@pytest.mark.parametrize(("before", "after"), [(None, []), ([], None), (None, "text")])
def test_steps_that_change_between_empty_forms_are_a_major_change(
    before: object, after: object
) -> None:
    old = copy.deepcopy(STORED)
    old["scenario_workflow"]["workflow_steps"] = before
    new = copy.deepcopy(STORED)
    new["scenario_workflow"]["workflow_steps"] = after
    assert _reasons(new, old) == [(Bump.MAJOR, "its workflow_steps changed")]


@pytest.mark.parametrize(
    "steps",
    [
        lambda s: [s[0], {**s[1], "step_id": s[0]["step_id"]}],  # an identifier twice
        lambda s: [s[0], "not a step"],
        lambda s: [s[0], {k: v for k, v in s[1].items() if k != "step_id"}],
    ],
)
def test_steps_that_are_not_a_list_by_identifier_are_a_major_change(steps: Any) -> None:
    after = copy.deepcopy(STORED)
    after["scenario_workflow"]["workflow_steps"] = steps(copy.deepcopy(_steps(STORED)))
    assert _reasons(after) == [(Bump.MAJOR, "its workflow_steps changed")]


@pytest.mark.parametrize(("before", "after"), [(None, {}), ({}, []), (None, [])])
def test_a_time_based_scenario_moving_between_empty_workflows_is_a_major_change(
    before: object, after: object
) -> None:
    old, new = {"scenario_workflow": before}, {"scenario_workflow": after}
    assert _reasons(new, old) == [(Bump.MAJOR, "its scenario_workflow changed")]


def test_several_changes_come_in_the_order_of_the_keys_then_of_the_steps() -> None:
    after = copy.deepcopy(STORED)
    after["scenario_workflow"]["workflow_timeout_seconds"] = 120
    after["scenario_workflow"]["workflow_max_attempts"] = 3
    _first(after)["step_action_class"] = "OTHER"
    _first(after)["step_input"] = "x"
    fields = [found.field for found in located_changes(METADATA, STORED, METADATA, after)]
    index = _steps(after).index(_first(after))
    assert fields == [
        "/scenario_workflow/workflow_max_attempts",
        f"{STEPS}/{index}/step_action_class",
        f"{STEPS}/{index}/step_input",
        "/scenario_workflow/workflow_timeout_seconds",
    ]


@pytest.mark.parametrize(
    "change",
    [
        lambda step: step["step_data"]["inject_injector_contract"].update(
            injector_contract_id="other"
        ),
        lambda step: step["step_data"].update(inject_title="Another title"),
    ],
)
def test_a_step_under_a_new_identifier_is_ver_003_only_with_the_same_contract_and_title(
    change: Any,
) -> None:
    after = copy.deepcopy(STORED)
    _first(after)["step_id"] = "new-identifier"
    change(_first(after))
    found = versioning_findings(
        (METADATA, STORED),
        {**METADATA, "version": "2.0.0"},
        after,
        metadata_path="scenarios/techniques/x/scenario.yaml",
        scenario_path=JSON,
    )
    assert [f.code for f in found] == []


@pytest.mark.parametrize("workflow", [None, "text", {"workflow_steps": "text"}])
def test_ver_003_reads_no_workflow_of_another_shape(workflow: object) -> None:
    for previous, current in (
        (STORED, {**STORED, "scenario_workflow": workflow}),
        ({**STORED, "scenario_workflow": workflow}, STORED),
    ):
        found = versioning_findings(
            (METADATA, previous),
            {**METADATA, "version": "2.0.0"},
            current,
            metadata_path="scenarios/techniques/x/scenario.yaml",
            scenario_path=JSON,
        )
        assert "VER-003" not in [f.code for f in found]


def test_a_step_without_its_inject_is_compared_by_nothing_it_runs() -> None:
    after = copy.deepcopy(STORED)
    _first(after)["step_id"] = "new-identifier"
    del _first(after)["step_data"]
    found = versioning_findings(
        (METADATA, STORED),
        {**METADATA, "version": "2.0.0"},
        after,
        metadata_path="scenarios/techniques/x/scenario.yaml",
        scenario_path=JSON,
    )
    assert "VER-003" not in [f.code for f in found]


def test_diff_lists_a_workflow_change_by_its_pointer_never_its_value() -> None:
    after = copy.deepcopy(STORED)
    _waiting(after)["step_conditions"][0]["condition_name"] = "A secret-looking name"
    found = diff_findings((METADATA, STORED), METADATA, after, entry="scenarios/techniques/x")
    listed = [f for f in found if f.code == "VER-013"]
    index = _steps(after).index(_waiting(after))
    assert [(f.path, f.field) for f in listed] == [
        ("scenarios/techniques/x/scenario.json", f"{STEPS}/{index}/step_conditions")
    ]
    assert all("secret-looking" not in f.message for f in found)
    assert _waiting(after)["step_id"] in listed[0].message


def _located(after: dict[str, Any], before: dict[str, Any] = STORED) -> list[tuple[Any, ...]]:
    return [
        (found.change.bump, found.change.reason, found.file, found.field, found.item)
        for found in located_changes(METADATA, before, METADATA, after)
    ]


def test_each_change_says_its_file_its_pointer_and_its_step() -> None:
    first_id, waiting_id = _first(STORED)["step_id"], _waiting(STORED)["step_id"]
    index = _steps(STORED).index(_first(STORED))
    after = copy.deepcopy(STORED)
    _first(after)["step_action_class"] = "OTHER"
    _first(after)["step_data"] = "text"
    after["scenario_workflow"]["workflow_standalone_conditions"] = [{"condition_id": "c"}]
    after["scenario_workflow"]["workflow_max_attempts"] = 3
    _steps(after).remove(_waiting(after))
    _steps(after).append({**copy.deepcopy(_first(STORED)), "step_id": "added-step"})
    assert _located(after) == [
        (
            Bump.MINOR,
            "a workflow setting changed",
            "scenario.json",
            "/scenario_workflow/workflow_max_attempts",
            "",
        ),
        (
            Bump.MAJOR,
            "a workflow's conditions changed",
            "scenario.json",
            "/scenario_workflow/workflow_standalone_conditions",
            "",
        ),
        (Bump.MAJOR, "a step removed", "scenario.json", STEPS, waiting_id),
        (
            Bump.MINOR,
            "a step's step_action_class changed",
            "scenario.json",
            f"{STEPS}/{index}/step_action_class",
            first_id,
        ),
        (
            Bump.MAJOR,
            "a step's inject changed",
            "scenario.json",
            f"{STEPS}/{index}/step_data",
            first_id,
        ),
        (Bump.MAJOR, "a step added", "scenario.json", f"{STEPS}/1", "added-step"),
    ]


def test_a_change_of_a_step_s_inject_names_its_step() -> None:
    index = _steps(STORED).index(_first(STORED))
    after = copy.deepcopy(STORED)
    _first(after)["step_data"]["inject_title"] = "Another"
    assert _located(after) == [
        (
            Bump.PATCH,
            "an inject's text changed",
            "scenario.json",
            f"{STEPS}/{index}/step_data/inject_title",
            _first(STORED)["step_id"],
        )
    ]


@pytest.mark.parametrize("key", ["step_input", "workflow_max_attempts"])
def test_a_key_held_by_one_side_only_is_a_change(key: str) -> None:
    before = copy.deepcopy(STORED)
    if key == "step_input":
        _first(before).pop(key, None)
        after = copy.deepcopy(before)
        _first(after)[key] = "x"
    else:
        before["scenario_workflow"].pop(key, None)
        after = copy.deepcopy(before)
        after["scenario_workflow"][key] = 3
    assert len(_located(after, before)) == 1


@pytest.mark.parametrize(
    ("before", "after", "field"),
    [
        ("text", {"workflow_steps": []}, "/scenario_workflow"),
        ({"workflow_steps": "text"}, {"workflow_steps": []}, STEPS),
    ],
)
def test_a_part_of_another_shape_says_where_it_is(
    before: object, after: object, field: str
) -> None:
    found = _located({"scenario_workflow": after}, {"scenario_workflow": before})
    assert [(f[2], f[3]) for f in found] == [("scenario.json", field)]


def test_ver_003_says_why_the_identifier_must_stay() -> None:
    after = copy.deepcopy(STORED)
    _first(after)["step_id"] = "new-identifier"
    (found,) = versioning_findings(
        (METADATA, STORED),
        {**METADATA, "version": "2.0.0"},
        after,
        metadata_path="scenarios/techniques/x/scenario.yaml",
        scenario_path=JSON,
    )
    assert found.message == (
        "this step runs the contract and has the title of a step of the previous version, under "
        "a new ID: its ID must stay; prepare the entry with `normalize --previous` or `intake`, "
        "or give a new step another title"
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            ("scenario_workflow", "workflow_max_attempts"),
            (Bump.MINOR, "a workflow setting changed"),
        ),
        (
            ("scenario_workflow", "workflow_steps", 0, "step_output"),
            (Bump.MINOR, "a step's step_output changed"),
        ),
        (
            ("scenario_workflow", "workflow_steps", 0, "step_condition_executed"),
            (Bump.MAJOR, "a step's conditions changed"),
        ),
        (
            ("scenario_workflow", "workflow_steps", 0, "step_data", "inject_city"),
            (Bump.PATCH, "an inject's text changed"),
        ),
        (
            (
                "scenario_workflow",
                "workflow_steps",
                0,
                "step_data",
                "inject_injector_contract",
                "injector_contract_external_id",
            ),
            (Bump.MAJOR, "an inject's contract changed"),
        ),
        (
            ("scenario_information", "scenario_message_footer"),
            (Bump.PATCH, "its scenario_message_footer changed"),
        ),
    ],
    ids=["workflow", "step", "step conditions", "step's inject", "step's contract", "information"],
)
def test_a_null_key_removed_or_added_is_a_change(path: tuple[Any, ...], expected: Any) -> None:
    without = copy.deepcopy(STORED)
    holder: Any = without
    for part in path[:-1]:
        holder = holder[part]
    assert holder[path[-1]] is None
    del holder[path[-1]]
    assert _reasons(without) == [expected]
    assert _reasons(STORED, without) == [expected]
