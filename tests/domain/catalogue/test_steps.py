"""The steps of a scenario in chaining, as normalisation checks them: each step runs the inject of
a command payload on the platform's implant, with nothing of the instance it was exported from."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.catalogue.normalisation import (
    ExportStructureError,
    canonical_step_text,
    normalise,
    stored_step_data,
)
from scenario_tools.domain.shared.workflow import (
    DEPEND_ON_DANGLING,
    KEY_RUNTIME,
    KEY_UNKNOWN,
    STEP_ACTION,
    STEP_DATA_UNREADABLE,
    STEP_FIELD,
    STEP_INJECTOR,
    STEP_INPUT,
    STEP_PAYLOAD,
    STEP_TARGETS,
    STEP_VALUE,
)
from tests.domain.catalogue.test_normalisation import RULES
from tests.support.workflow import KEYS

ROOT = Path(__file__).resolve().parents[3]
EXPORT: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.json").read_text(encoding="utf-8")
)
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
STEP = "/scenario_workflow/workflow_steps/1"
DATA = f"{STEP}/step_data"


PASSED = None  # normalisation gives a stored form


def _refusal(export: dict[str, Any]) -> tuple[str, str] | None:
    """What normalisation refuses in ``export`` and where, or ``PASSED``."""
    try:
        normalise(export, ENTRY_ID, RULES)
    except ExportStructureError as error:
        return error.what, error.pointer
    return PASSED


def _with_step(**fields: object) -> dict[str, Any]:
    export = copy.deepcopy(EXPORT)
    export["scenario_workflow"]["workflow_steps"][1].update(fields)
    return export


def _with_data(change: Any) -> dict[str, Any]:
    export = copy.deepcopy(EXPORT)
    step = export["scenario_workflow"]["workflow_steps"][1]
    data = json.loads(step["step_data"])
    change(data)
    step["step_data"] = json.dumps(data)
    return export


def test_well_shaped_steps_pass_every_step_check() -> None:
    assert _refusal(copy.deepcopy(EXPORT)) == PASSED


def test_a_step_data_given_as_an_object_is_read_as_its_text() -> None:
    export = copy.deepcopy(EXPORT)
    step = export["scenario_workflow"]["workflow_steps"][1]
    step["step_data"] = json.loads(step["step_data"])
    assert _refusal(export) == PASSED


@pytest.mark.parametrize("action", ["OTHER", None, 1])
def test_a_step_that_does_not_run_an_inject_is_refused(action: object) -> None:
    assert _refusal(_with_step(step_action_class=action)) == (
        STEP_ACTION,
        f"{STEP}/step_action_class",
    )


@pytest.mark.parametrize(
    ("fields", "key"),
    [
        ({"step_output": "x"}, "step_output"),
        ({"step_condition_executed": "x"}, "step_condition_executed"),
        ({"step_limit_execution": 1}, "step_limit_execution"),
        ({"step_limit_execution": False}, "step_limit_execution"),
    ],
)
def test_a_step_that_holds_run_state_is_refused(fields: dict[str, object], key: str) -> None:
    assert _refusal(_with_step(**fields)) == (STEP_FIELD, f"{STEP}/{key}")


def test_absent_run_state_passes() -> None:
    export = copy.deepcopy(EXPORT)
    step = export["scenario_workflow"]["workflow_steps"][1]
    for key in ("step_output", "step_condition_executed", "step_limit_execution"):
        step.pop(key, None)
    assert _refusal(export) == PASSED


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ('{"input": [1]}', "step_input"),
        ('{"other": 1}', "step_output_parser"),
        ("not json", "step_input"),
        ("[]", "step_output_parser"),
        ({"input": []}, "step_input"),
        (1, "step_output_parser"),
    ],
)
def test_a_step_input_or_parser_other_than_empty_is_refused(value: object, key: str) -> None:
    assert _refusal(_with_step(**{key: value})) == (STEP_INPUT, f"{STEP}/{key}")


@pytest.mark.parametrize("value", ["{}", '{ "input" : [] }', None])
def test_an_empty_step_input_passes(value: object) -> None:
    assert _refusal(_with_step(step_input=value)) == PASSED


@pytest.mark.parametrize("data", ["not json", "[]", "1", 1, None, '{"a": NaN}'])
def test_a_step_data_that_is_not_an_object_is_refused(data: object) -> None:
    assert _refusal(_with_step(step_data=data)) == (STEP_DATA_UNREADABLE, DATA)


def test_a_key_outside_the_classification_is_refused_at_its_pointer() -> None:
    export = _with_data(lambda data: data.update(inject_owner="x"))
    assert _refusal(export) == (KEY_UNKNOWN, f"{DATA}/inject_owner")


def test_the_key_a_platform_reads_when_a_step_runs_is_refused_by_name() -> None:
    export = _with_data(lambda data: data.update(_chaining_target={"type": "ASSET"}))
    assert _refusal(export) == (KEY_RUNTIME, f"{DATA}/_chaining_target")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("inject_enabled", False),
        ("inject_id", "00000000-0000-4000-8000-0000000000aa"),
        ("inject_depends_duration", 5),
        ("inject_depends_duration", False),
        ("inject_depends_on", [{"x": 1}]),
        ("inject_secret_references", ["x"]),
    ],
)
def test_a_key_held_to_a_value_is_refused_when_it_holds_another(key: str, value: object) -> None:
    export = _with_data(lambda data: data.update({key: value}))
    assert _refusal(export) == (STEP_VALUE, f"{DATA}/{key}")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("inject_assets", ["00000000-0000-4000-8000-0000000000aa"]),
        ("inject_asset_groups", ["00000000-0000-4000-8000-0000000000aa"]),
        ("inject_teams", ["00000000-0000-4000-8000-0000000000aa"]),
        ("inject_documents", [{"document_id": "x"}]),
        ("inject_all_teams", True),
    ],
)
def test_what_belongs_to_the_installation_is_refused_never_stripped(
    key: str, value: object
) -> None:
    export = _with_data(lambda data: data.update({key: value}))
    assert _refusal(export) == (STEP_TARGETS, f"{DATA}/{key}")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("targets", ["x"]),
        ("targets_assets", ["x"]),
        ("assets", ["x"]),
        ("asset_groups", ["x"]),
        ("targets", 0),
        ("assets", False),
    ],
)
def test_targets_in_the_inject_content_are_refused(key: str, value: object) -> None:
    export = _with_data(lambda data: data["inject_content"].update({key: value}))
    assert _refusal(export) == (STEP_TARGETS, f"{DATA}/inject_content/{key}")


def test_a_contract_field_typed_as_a_target_is_a_target_whatever_its_key() -> None:
    def change(data: dict[str, Any]) -> None:
        contract = data["inject_injector_contract"]
        content = json.loads(contract["injector_contract_content"])
        content["fields"].append({"key": "where", "type": "targeted-asset"})
        contract["injector_contract_content"] = json.dumps(content)
        data["inject_content"]["where"] = ["00000000-0000-4000-8000-0000000000aa"]

    assert _refusal(_with_data(change)) == (STEP_TARGETS, f"{DATA}/inject_content/where")


@pytest.mark.parametrize("selector", ["assets", None])
def test_a_target_selector_that_chooses_assets_passes(selector: object) -> None:
    export = _with_data(lambda data: data["inject_content"].update(target_selector=selector))
    assert _refusal(export) == PASSED


def test_targets_typed_by_hand_are_refused() -> None:
    export = _with_data(lambda data: data["inject_content"].update(target_selector="manual"))
    assert _refusal(export) == (STEP_TARGETS, f"{DATA}/inject_content/target_selector")


def test_targets_in_an_inject_content_given_as_text_are_refused() -> None:
    def change(data: dict[str, Any]) -> None:
        data["inject_content"] = json.dumps({"targets": ["x"]})

    assert _refusal(_with_data(change)) == (STEP_TARGETS, f"{DATA}/inject_content/targets")


@pytest.mark.parametrize("content", [5, "not json", "[]", ["x"]])
def test_an_inject_content_that_is_not_an_object_is_refused(content: object) -> None:
    export = _with_data(lambda data: data.update(inject_content=content))
    assert _refusal(export) == (STEP_DATA_UNREADABLE, f"{DATA}/inject_content")


def test_an_absent_inject_content_names_no_target() -> None:
    export = _with_data(lambda data: data.pop("inject_content"))
    assert _refusal(export) == PASSED


def test_empty_targets_and_an_absent_held_key_pass() -> None:
    def change(data: dict[str, Any]) -> None:
        data["inject_content"]["targets"] = []
        del data["inject_enabled"]

    assert _refusal(_with_data(change)) == PASSED


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data.update(inject_injector="00000000-0000-4000-8000-0000000000aa"),
        lambda data: data.update(inject_type="openaev_nmap"),
        lambda data: data["inject_injector_contract"].update(
            injector_contract_injector_type="openaev_nmap"
        ),
        lambda data: data["inject_injector_contract"].update(
            injector_contract_injectors=["00000000-0000-4000-8000-0000000000aa"]
        ),
        lambda data: data["inject_injector_contract"].pop("injector_contract_injector_type"),
        lambda data: data["inject_injector_contract"].update(injector_contract_injectors=[]),
        lambda data: data.pop("inject_type"),
    ],
)
def test_a_step_on_another_injector_is_refused(change: Any) -> None:
    assert _refusal(_with_data(change)) == (STEP_INJECTOR, f"{DATA}/inject_injector")


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data["inject_injector_contract"]["injector_contract_payload"].update(
            payload_type="Executable"
        ),
        lambda data: data["inject_injector_contract"].update(injector_contract_payload=None),
        lambda data: data.update(inject_injector_contract=None),
    ],
)
def test_a_step_that_runs_no_command_payload_is_refused(change: Any) -> None:
    pointer = f"{DATA}/inject_injector_contract/injector_contract_payload"
    assert _refusal(_with_data(change)) == (STEP_PAYLOAD, pointer)


@pytest.mark.parametrize("injector", [None, "absent"])
def test_a_step_that_leaves_its_injector_to_its_contract_passes(injector: object) -> None:
    def change(data: dict[str, Any]) -> None:
        if injector == "absent":
            del data["inject_injector"]
        else:
            data["inject_injector"] = injector

    assert _refusal(_with_data(change)) == PASSED


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        (["00000000-0000-4000-8000-000000000002"], PASSED),
        (["00000000-0000-4000-8000-0000000000aa"], (STEP_VALUE, f"{DATA}/inject_tags")),
        ("x", (STEP_VALUE, f"{DATA}/inject_tags")),
        (None, PASSED),
    ],
)
def test_the_tags_of_a_step_are_tags_of_the_scenario(
    tags: object, expected: tuple[str, str] | None
) -> None:
    assert _refusal(_with_data(lambda data: data.update(inject_tags=tags))) == expected


@pytest.mark.parametrize("key", ["inject_launched_by", "inject_scheduled_by"])
def test_keys_of_newer_platforms_are_classified(key: str) -> None:
    export = _with_data(lambda data: data.update({key: None}))
    assert _refusal(export) == PASSED


def test_the_first_step_is_checked_and_the_first_refusal_reported() -> None:
    export = copy.deepcopy(EXPORT)
    for step in export["scenario_workflow"]["workflow_steps"]:
        step["step_output"] = "x"
    assert _refusal(export) == (
        STEP_FIELD,
        "/scenario_workflow/workflow_steps/0/step_output",
    )


def test_a_step_data_holding_two_contract_copies_is_refused() -> None:
    def change(data: dict[str, Any]) -> None:
        data["inject_content"]["copy"] = {"injector_contract_content": "{}"}

    assert _refusal(_with_data(change)) == (STEP_DATA_UNREADABLE, DATA)


def test_a_stored_step_data_keeps_what_is_kept_and_drops_what_is_removed() -> None:
    data = json.loads(EXPORT["scenario_workflow"]["workflow_steps"][1]["step_data"])
    stored = stored_step_data(data, KEYS.step_data)
    assert stored == {k: v for k, v in data.items() if k not in KEYS.step_data.removed}
    assert "inject_user" in data  # untouched


def test_a_step_input_is_written_in_one_canonical_form() -> None:
    assert canonical_step_text('{ "input" : [] }') == '{"input":[]}'
    assert canonical_step_text(None) == "{}"


@pytest.mark.parametrize("field", ["step_data", "step_input", "step_output_parser"])
def test_an_identifier_written_as_an_escape_in_a_step_text_is_refused(field: str) -> None:
    export = copy.deepcopy(EXPORT)
    step = export["scenario_workflow"]["workflow_steps"][1]
    step[field] = step[field].replace("{", '{"ref": "\\u0041", ', 1)
    refusal = _refusal(export)
    assert refusal is not None
    assert refusal[0] == f"{field} writes an identifier character as an escape"


def test_the_graph_of_the_workflow_is_checked_after_its_steps() -> None:
    export = copy.deepcopy(EXPORT)
    condition = export["scenario_workflow"]["workflow_steps"][1]["step_conditions"][0]
    condition["condition_value"] = "00000000-0000-4000-8000-000000000099"
    assert _refusal(export) == (
        DEPEND_ON_DANGLING,
        f"{STEP}/step_conditions/0/condition_value",
    )
    export["scenario_workflow"]["workflow_steps"][1]["step_action_class"] = "OTHER"
    assert _refusal(export) == (STEP_ACTION, f"{STEP}/step_action_class")
