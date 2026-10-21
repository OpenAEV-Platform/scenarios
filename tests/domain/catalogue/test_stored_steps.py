"""The stored form of a scenario in chaining: identifiers derived from what each step runs and what
it waits for, dependencies rewritten to them, and nothing of the instance or of the export's
order left."""

import copy
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.safe_readers import parse_json
from scenario_tools.domain.catalogue.identifiers import scenario_namespace, stable_id
from scenario_tools.domain.catalogue.normalisation import (
    ExportStructureError,
    NormalisationRules,
    normalise,
)
from scenario_tools.domain.shared.workflow import (
    CONDITION_DEPEND_NESTED,
    CONDITION_MAPPER,
    CONDITION_NOT_YET,
    CONDITION_SIBLINGS_SAME,
    ID_NOT_KNOWN,
    STEP_DATA_UNREADABLE,
    STEPS_SAME_SIGNATURE,
)
from tests.domain.catalogue.test_normalisation import RULES

ROOT = Path(__file__).resolve().parents[3]
EXPORT: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.json").read_text(encoding="utf-8")
)
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
FIRST, SECOND = "00000000-0000-4000-8000-000000000016", "00000000-0000-4000-8000-000000000018"
AT = "/scenario_workflow/workflow_steps"


# Rules that accept filters and their groups, which the subset refuses for now: the identifiers
# of a tree of conditions are derived already.
TREES = dataclasses.replace(
    RULES,
    export_keys=dataclasses.replace(
        RULES.export_keys, condition_types=frozenset({"DEPEND_ON", "EQ", "AND"})
    ),
)


def _stored(export: dict[str, Any], rules: NormalisationRules = RULES) -> dict[str, Any]:
    return normalise(copy.deepcopy(export), ENTRY_ID, rules).document


def _refusal(export: dict[str, Any], rules: NormalisationRules = RULES) -> tuple[str, str]:
    with pytest.raises(ExportStructureError) as error:
        normalise(export, ENTRY_ID, rules)
    return error.value.what, error.value.pointer


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = document["scenario_workflow"]["workflow_steps"]
    return steps


def _by_title(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {step["step_data"]["inject_title"]: step for step in _steps(document)}


def _data(export: dict[str, Any], index: int) -> dict[str, Any]:
    """The decoded inject of a step, written back as text when changed through ``_edit``."""
    data: dict[str, Any] = json.loads(_steps(export)[index]["step_data"])
    return data


def _edit(export: dict[str, Any], index: int, change: Any) -> dict[str, Any]:
    edited = copy.deepcopy(export)
    data = _data(edited, index)
    change(data)
    _steps(edited)[index]["step_data"] = json.dumps(data)
    return edited


# The identifiers an instance generates and normalisation rewrites: the scenario's tags, the
# user, the attack pattern, phase and domain, the payload and its contract, the steps and the
# condition. Others, such as those of the payload's output parsers, stay as they are, as they do
# for the injects of a time-based scenario.
_REWRITTEN = (0x02, 0x03, 0x04, 0x06, 0x08, 0x09, 0x0A, 0x0B, 0x16, 0x17, 0x18, 0xF0)


def _renumbered(export: dict[str, Any], prefix: str) -> dict[str, Any]:
    """The export as another instance would write it, its rewritten identifiers renumbered."""
    text = json.dumps(export)
    for number in _REWRITTEN:
        text = text.replace(
            f"00000000-0000-4000-8000-{number:012x}", f"{prefix}-0000-4000-8000-{number:012x}"
        )
    return dict(json.loads(text))


def test_a_step_waits_for_the_stored_identifier_of_the_step_before() -> None:
    steps = _by_title(_stored(EXPORT))
    first, second = steps["Step 1 - list processes"], steps["Step 2 - list processes again"]
    (condition,) = second["step_conditions"]
    assert condition["condition_value"] == first["step_id"]
    assert {first["step_id"], second["step_id"], condition["condition_id"]}.isdisjoint(
        {FIRST, SECOND, "00000000-0000-4000-8000-000000000017"}
    )


def test_the_identifiers_belong_to_the_entry() -> None:
    namespace = scenario_namespace(ENTRY_ID)
    document = _stored(EXPORT)
    payload = document["scenario_workflow"]["workflow_steps"][0]["step_data"][
        "inject_injector_contract"
    ]["injector_contract_payload"]
    assert payload["payload_id"] == stable_id(namespace, "payload", "Process Discovery - ps")


def test_another_instance_gives_the_same_stored_form() -> None:
    assert _stored(_renumbered(EXPORT, "11111111")) == _stored(EXPORT)


def test_the_order_of_steps_and_of_condition_copies_does_not_show() -> None:
    reordered = copy.deepcopy(EXPORT)
    _steps(reordered).reverse()
    second = next(step for step in _steps(reordered) if step["step_id"] == SECOND)
    second["step_conditions"] = second["step_conditions"] * 2  # a copy, as the export repeats it
    assert _stored(reordered) == _stored(EXPORT)


def test_steps_and_conditions_are_sorted_by_identifier() -> None:
    steps = _steps(_stored(EXPORT))
    assert [step["step_id"] for step in steps] == sorted(step["step_id"] for step in steps)


def test_a_retitled_step_changes_its_identifier_and_those_of_the_steps_after_it() -> None:
    before = _by_title(_stored(EXPORT))
    after = _by_title(
        _stored(_edit(EXPORT, 0, lambda data: data.update(inject_title="Step 1 - renamed")))
    )
    assert after["Step 1 - renamed"]["step_id"] != before["Step 1 - list processes"]["step_id"]
    second = "Step 2 - list processes again"
    assert after[second]["step_id"] != before[second]["step_id"]


def test_a_retitled_last_step_leaves_the_first_one_alone() -> None:
    before = _by_title(_stored(EXPORT))
    after = _by_title(_stored(_edit(EXPORT, 1, lambda data: data.update(inject_title="Renamed"))))
    first = "Step 1 - list processes"
    assert after[first]["step_id"] == before[first]["step_id"]


def test_two_steps_that_run_the_same_payload_under_the_same_title_after_the_same_steps() -> None:
    export = _edit(EXPORT, 1, lambda data: data.update(inject_title="Step 1 - list processes"))
    second = next(step for step in _steps(export) if step["step_id"] == SECOND)
    second["step_conditions"] = []
    assert _refusal(export) == (STEPS_SAME_SIGNATURE, f"{AT}/1")


def test_a_stored_step_holds_its_inject_as_an_object_without_the_run_time_keys() -> None:
    (stored,) = [s for s in _steps(_stored(EXPORT)) if not s["step_conditions"]]
    data = stored["step_data"]
    assert isinstance(data, dict)
    assert {"inject_user", "inject_status", "inject_date", "inject_attack_patterns"}.isdisjoint(
        data
    )
    assert data["inject_title"] == "Step 1 - list processes"


def test_a_stored_step_writes_its_empty_input_in_one_form() -> None:
    export = copy.deepcopy(EXPORT)
    _steps(export)[0]["step_input"] = '{ "input" : [] }'
    _steps(export)[1]["step_input"] = None
    inputs = {step["step_input"] for step in _steps(_stored(export))}
    assert inputs == {'{"input":[]}', "{}"}


def test_the_workflow_writes_every_setting_and_no_version() -> None:
    export = copy.deepcopy(EXPORT)
    export["scenario_workflow"].pop("workflow_timeout_seconds", None)
    export["scenario_workflow"]["workflow_version"] = 7
    workflow = _stored(export)["scenario_workflow"]
    assert workflow["workflow_timeout_seconds"] == 3600
    assert "workflow_version" not in workflow


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (lambda step: step.update(step_id="not-an-identifier"), f"{AT}/0/step_id"),
        (
            lambda step: step["step_conditions"][0].update(condition_id="c1"),
            f"{AT}/1/step_conditions/0/condition_id",
        ),
    ],
    ids=["step", "condition"],
)
def test_an_identifier_that_is_not_one_is_refused(change: Any, pointer: str) -> None:
    export = copy.deepcopy(EXPORT)
    index = 0 if pointer.startswith(f"{AT}/0") else 1
    change(_steps(export)[index])
    if index == 0:  # the step that waits names the step by its new identifier
        _steps(export)[1]["step_conditions"][0]["condition_value"] = "not-an-identifier"
    assert _refusal(export) == (ID_NOT_KNOWN, pointer)


def test_identical_siblings_are_refused() -> None:
    export = copy.deepcopy(EXPORT)
    root = {
        **_steps(export)[1]["step_conditions"][0],
        "condition_type": "AND",
        "condition_value": None,
    }
    leaf = {
        **root,
        "condition_id": "00000000-0000-4000-8000-0000000000f1",
        "condition_parent_id": root["condition_id"],
        "condition_is_root": False,
        "condition_type": "EQ",
        "condition_value": "x",
    }
    twin = {**leaf, "condition_id": "00000000-0000-4000-8000-0000000000f2"}
    _steps(export)[1]["step_conditions"] = [root, leaf, twin]
    assert _refusal(export, TREES) == (CONDITION_SIBLINGS_SAME, f"{AT}/1/step_conditions/2")


def test_an_escaped_identifier_inside_the_text_of_a_step_is_refused() -> None:
    def escaped(data: dict[str, Any]) -> None:
        data["inject_content"] = '{"ref": "\\u0030"}'  # the text holds the six characters 0

    assert _refusal(_edit(EXPORT, 0, escaped)) == (
        "inject_content writes an identifier character as an escape",
        f"{AT}/0/step_data",
    )


def test_an_inject_given_as_an_object_may_hold_one_contract_copy_only() -> None:
    export = copy.deepcopy(EXPORT)
    data = _data(export, 0)
    data["inject_content"] = {"nested": {"injector_contract_content": "{}"}}
    _steps(export)[0]["step_data"] = data
    assert _refusal(export) == (STEP_DATA_UNREADABLE, f"{AT}/0/step_data")


def test_two_payloads_of_one_name_are_refused_across_steps() -> None:
    def other(data: dict[str, Any]) -> None:
        payload = data["inject_injector_contract"]["injector_contract_payload"]
        payload["payload_id"] = "00000000-0000-4000-8000-0000000000e1"

    what, _ = _refusal(_edit(EXPORT, 1, other))
    assert what == "two payloads are named 'Process Discovery - ps'"


def test_a_condition_that_names_a_step_in_its_value_is_known_by_the_stored_step() -> None:
    export = copy.deepcopy(EXPORT)
    condition = _steps(export)[1]["step_conditions"][0]
    condition.update(condition_type="EQ", condition_name=f"Like {FIRST}")
    assert _stored(_renumbered(export, "11111111"), TREES) == _stored(export, TREES)


TAG = "00000000-0000-4000-8000-000000000002"


def _normalised_again(
    document: dict[str, Any], rules: NormalisationRules = RULES
) -> dict[str, Any]:
    return normalise(copy.deepcopy(document), ENTRY_ID, rules, previous=document).document


def test_a_title_that_quotes_an_identifier_keeps_the_identifiers_stable() -> None:
    export = _edit(EXPORT, 0, lambda data: data.update(inject_title=f"Step 1 - see {TAG}"))
    stored = _stored(export)
    assert _stored(_renumbered(export, "11111111")) == stored
    assert _normalised_again(stored) == stored


def test_a_condition_that_quotes_another_one_keeps_the_identifiers_stable() -> None:
    export = copy.deepcopy(EXPORT)
    root = {
        **_steps(export)[1]["step_conditions"][0],
        "condition_id": "00000000-0000-4000-8000-0000000000f0",
        "condition_type": "AND",
        "condition_value": None,
    }
    leaf = {
        **root,
        "condition_id": "00000000-0000-4000-8000-000000000017",
        "condition_parent_id": root["condition_id"],
        "condition_is_root": False,
        "condition_type": "EQ",
        "condition_value": "x",
        "condition_name": f"Under {root['condition_id']}",
    }
    _steps(export)[1]["step_conditions"] = [root, leaf]
    stored = _stored(export, TREES)
    assert _stored(_renumbered(export, "11111111"), TREES) == stored
    assert _normalised_again(stored, TREES) == stored


def _nested(levels: int) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for _ in range(levels - 1):
        value = {"down": value}
    return value


def test_a_stored_step_is_never_deeper_than_the_readers_allow() -> None:
    # A step's inject sits four levels down in the stored file: the deepest it may nest is 59
    # levels below it, for the file to be read back within the readers' 64.
    deepest = _edit(EXPORT, 0, lambda data: data.update(inject_content=_nested(59)))
    stored = _stored(deepest)
    assert parse_json(json.dumps(stored).encode()) == stored
    too_deep = _edit(EXPORT, 0, lambda data: data.update(inject_content=_nested(60)))
    assert _refusal(too_deep) == (STEP_DATA_UNREADABLE, f"{AT}/0/step_data")


def test_a_condition_that_takes_the_identifier_of_a_step_is_refused() -> None:
    export = copy.deepcopy(EXPORT)
    _steps(export)[1]["step_conditions"][0]["condition_id"] = SECOND
    what, _ = _refusal(export)
    assert what == f"identifier {SECOND!r} names two different objects"


def test_a_dependency_under_a_group_is_refused_even_once_filters_are_accepted() -> None:
    export = copy.deepcopy(EXPORT)
    dependency = _steps(export)[1]["step_conditions"][0]
    root = {
        **dependency,
        "condition_id": "00000000-0000-4000-8000-0000000000f0",
        "condition_type": "AND",
        "condition_value": None,
    }
    twice = [
        {
            **dependency,
            "condition_id": f"00000000-0000-4000-8000-0000000000f{number}",
            "condition_parent_id": root["condition_id"],
            "condition_is_root": False,
            "condition_name": f"After step 1, {number}",
        }
        for number in (1, 2)
    ]
    _steps(export)[1]["step_conditions"] = [root, *twice]
    assert _refusal(export, TREES) == (CONDITION_DEPEND_NESTED, f"{AT}/1/step_conditions/1")


@pytest.mark.parametrize(
    ("kind", "what"), [("MAPPER", CONDITION_MAPPER), ("EQ", CONDITION_NOT_YET)]
)
def test_a_condition_out_of_the_subset_is_refused_by_normalisation(kind: str, what: str) -> None:
    export = copy.deepcopy(EXPORT)
    _steps(export)[1]["step_conditions"][0].update(condition_type=kind, condition_value="x")
    assert _refusal(export) == (what, f"{AT}/1/step_conditions/0")


def test_a_dependency_with_a_child_is_refused_by_normalisation() -> None:
    export = copy.deepcopy(EXPORT)
    dependency = _steps(export)[1]["step_conditions"][0]
    child = {
        **dependency,
        "condition_id": "00000000-0000-4000-8000-0000000000f1",
        "condition_parent_id": dependency["condition_id"],
        "condition_is_root": False,
    }
    _steps(export)[1]["step_conditions"].append(child)
    assert _refusal(export) == (CONDITION_DEPEND_NESTED, f"{AT}/1/step_conditions/0")


def test_a_dependency_whose_parent_is_not_an_identifier_is_refused() -> None:
    export = copy.deepcopy(EXPORT)
    _steps(export)[1]["step_conditions"][0].update(condition_parent_id=5, condition_is_root=False)
    assert _refusal(export) == (ID_NOT_KNOWN, f"{AT}/1/step_conditions/0/condition_parent_id")
