"""The rules of a step, read in full: every refusal of a step, in order."""

import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.policy.step_rules import step_refusals
from scenario_tools.domain.shared.workflow import STEP_DATA_UNREADABLE, STEP_INJECTOR, Refusal
from tests.support.workflow import KEYS

ROOT = Path(__file__).resolve().parents[3]
EXPORT = json.loads((ROOT / "tests" / "golden" / "chaining" / "two-steps.json").read_text())
STEP: dict[str, Any] = EXPORT["scenario_workflow"]["workflow_steps"][1]
AT = "/scenario_workflow/workflow_steps/1"
IMPLANT = "49229430-b5b5-431f-ba5b-f36f599b0144"


def _decode(text: str, field: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _all(step: dict[str, Any]) -> list[Refusal]:
    return list(step_refusals(step, AT, KEYS.step_data, frozenset(), _decode))


def test_a_well_shaped_step_has_no_refusal() -> None:
    assert _all(STEP) == []


def test_an_unreadable_inject_is_the_last_refusal_of_its_step() -> None:
    assert _all({**STEP, "step_data": "not json"}) == [
        Refusal(STEP_DATA_UNREADABLE, f"{AT}/step_data")
    ]


def test_an_unreadable_content_still_lets_the_payload_and_injector_be_checked() -> None:
    data = json.loads(STEP["step_data"])
    data["inject_content"] = "not json"
    assert _all({**STEP, "step_data": data}) == [
        Refusal(STEP_DATA_UNREADABLE, f"{AT}/step_data/inject_content")
    ]


def test_a_contract_that_lists_an_unknown_injector_is_refused() -> None:
    data = json.loads(STEP["step_data"])
    data["inject_injector_contract"]["injector_contract_injectors"].append("unknown-injector")
    assert _all({**STEP, "step_data": data}) == [
        Refusal(STEP_INJECTOR, f"{AT}/step_data/inject_injector")
    ]


def test_each_text_is_decoded_under_the_name_of_its_field() -> None:
    data = json.loads(STEP["step_data"])
    data["inject_content"] = json.dumps(data["inject_content"])
    fields: list[str] = []

    def decode(text: str, field: str) -> Any:
        fields.append(field)
        return _decode(text, field)

    step = {**STEP, "step_data": json.dumps(data)}
    assert list(step_refusals(step, AT, KEYS.step_data, frozenset(), decode)) == []
    assert sorted(fields) == sorted(
        [
            "step_input",
            "step_output_parser",
            "step_data",
            "inject_content",
            "injector_contract_content",
        ]
    )


def _contract(change: Any) -> dict[str, Any]:
    data = json.loads(STEP["step_data"])
    change(data["inject_injector_contract"])
    return {**STEP, "step_data": data}


CONTENT_AT = f"{AT}/step_data/inject_injector_contract/injector_contract_content"


@pytest.mark.parametrize("kind", [[], {}])
def test_a_contract_field_of_an_odd_type_names_no_target(kind: object) -> None:
    def odd(contract: dict[str, Any]) -> None:
        contract["injector_contract_content"] = json.dumps({"fields": [{"key": "x", "type": kind}]})

    assert _all(_contract(odd)) == []


@pytest.mark.parametrize("content", ["not json", "[]", 5])
def test_a_contract_content_that_cannot_be_read_is_refused(content: object) -> None:
    def unreadable(contract: dict[str, Any]) -> None:
        contract["injector_contract_content"] = content

    assert _all(_contract(unreadable)) == [Refusal(STEP_DATA_UNREADABLE, CONTENT_AT)]


def test_a_contract_with_no_content_names_no_target() -> None:
    assert _all(_contract(lambda contract: contract.pop("injector_contract_content"))) == []


@pytest.mark.parametrize("listed", [["unknown-injector"], [IMPLANT]])
def test_an_injector_type_given_nowhere_is_refused(listed: list[str]) -> None:
    data = json.loads(STEP["step_data"])
    data.pop("inject_type")
    contract = data["inject_injector_contract"]
    contract.pop("injector_contract_injector_type")
    contract["injector_contract_injectors"] = listed
    data["inject_injector"] = listed[0]
    assert _all({**STEP, "step_data": data}) == [
        Refusal(STEP_INJECTOR, f"{AT}/step_data/inject_injector")
    ]


@pytest.mark.parametrize("content", ["{}", '{"fields": "assets"}'])
def test_a_contract_content_without_a_list_of_fields_names_no_target(content: str) -> None:
    def without_fields(contract: dict[str, Any]) -> None:
        contract["injector_contract_content"] = content

    assert _all(_contract(without_fields)) == []
