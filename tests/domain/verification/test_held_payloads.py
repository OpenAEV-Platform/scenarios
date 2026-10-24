"""What installing a scenario would reuse on a platform: a payload held under the identifier the
archive gives must have the content the archive embeds."""

import copy
import json
from typing import Any

import pytest

from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.held_payloads import (
    NO_PAYLOAD,
    NOT_HASHED,
    OTHER_PAYLOAD,
    UNCOMPARABLE,
    UNREADABLE_STEP,
    HeldContract,
    identifiers,
    reuse_findings,
)

ARCHIVE = "scenario.zip"
POINTER = "/scenario_injects/{}/inject_injector_contract/injector_contract_payload"


def payload(content: str = "whoami", external_id: str = "ext-1") -> dict[str, Any]:
    return {
        "payload_type": "Command",
        "payload_name": "who",
        "command_executor": "sh",
        "command_content": content,
        "payload_external_id": external_id,
    }


def stored(*contracts: tuple[str, object]) -> dict[str, Any]:
    return {
        "scenario_injects": [
            {
                "inject_injector_contract": {
                    "injector_contract_id": contract_id,
                    "injector_contract_attack_patterns": [{"attack_pattern_external_id": "T1033"}],
                    "injector_contract_payload": item,
                }
            }
            for contract_id, item in contracts
        ]
    }


def _found(scenario: object, contracts: Any = None, payloads: Any = None) -> list[tuple[str, str]]:
    return [
        (f.field, f.message)
        for f in reuse_findings(scenario, contracts or {}, payloads or {}, ARCHIVE)
    ]


def test_the_identifiers_are_those_of_the_embedded_payloads() -> None:
    scenario = stored(("c-1", payload()), ("c-2", payload(external_id="ext-2")))
    scenario["scenario_injects"].append(
        {"inject_injector_contract": {"injector_contract_id": 3, "injector_contract_payload": {}}}
    )
    scenario["scenario_injects"].append(
        {"inject_injector_contract": {"injector_contract_id": 5, "injector_contract_payload": "x"}}
    )
    scenario["scenario_injects"].append(
        {
            "inject_injector_contract": {
                "injector_contract_id": "c-4",
                "injector_contract_payload": {"payload_external_id": 4},
            }
        }
    )

    assert identifiers(scenario) == (
        frozenset({"c-1", "c-2", "c-4"}),
        frozenset({"ext-1", "ext-2"}),
    )


def test_nothing_held_under_its_identifiers_is_nothing_to_say() -> None:
    assert _found(stored(("c-1", payload()))) == []


def test_the_same_payload_held_under_its_external_id_is_reused_as_it_is() -> None:
    held = {**payload(), "payload_id": "local", "payload_created_at": "2026-10-24T00:00:00Z"}

    assert _found(stored(("c-1", payload())), payloads={"ext-1": held}) == []


def test_another_payload_held_under_its_external_id_is_refused() -> None:
    found = reuse_findings(
        stored(("c-1", payload())), {}, {"ext-1": payload("rm -rf /tmp/x")}, ARCHIVE
    )

    assert [(f.code, f.severity, f.path, f.field, f.message) for f in found] == [
        (
            "OAV-002",
            Severity.BLOCKING,
            ARCHIVE,
            POINTER.format(0),
            OTHER_PAYLOAD.format(by="payload external ID"),
        )
    ]


def test_another_payload_held_under_its_contract_id_is_refused_before_the_external_id() -> None:
    contracts = {"c-1": HeldContract(payload("id"))}

    assert _found(stored(("c-1", payload())), contracts, {"ext-1": payload()}) == [
        (POINTER.format(0), OTHER_PAYLOAD.format(by="contract ID"))
    ]


def test_the_same_payload_held_under_its_contract_id_is_reused() -> None:
    contracts = {"c-1": HeldContract(payload())}

    assert _found(stored(("c-1", payload())), contracts, {"ext-1": payload("id")}) == []


def test_a_contract_held_without_a_payload_is_refused() -> None:
    assert _found(stored(("c-1", payload())), {"c-1": HeldContract(None)}) == [
        (POINTER.format(0), NO_PAYLOAD)
    ]


@pytest.mark.parametrize(
    ("contracts", "payloads", "by"),
    [
        ({"c-1": HeldContract({"payload_type": "Command", "unknown": 1})}, {}, "contract ID"),
        ({}, {"ext-1": {"payload_type": "Command", "unknown": 1}}, "payload external ID"),
    ],
)
def test_a_held_payload_that_cannot_be_hashed_is_refused(
    contracts: Any, payloads: Any, by: str
) -> None:
    assert _found(stored(("c-1", payload())), contracts, payloads) == [
        (POINTER.format(0), UNCOMPARABLE.format(by=by))
    ]


def test_an_embedded_payload_that_cannot_be_hashed_and_is_held_is_refused() -> None:
    unhashable = {**payload(), "unknown": 1}

    assert _found(stored(("c-1", unhashable)), payloads={"ext-1": payload()}) == [
        (POINTER.format(0), NOT_HASHED.format(by="payload external ID"))
    ]


def test_an_embedded_payload_that_cannot_be_hashed_and_is_not_held_is_nothing_to_say() -> None:
    unhashable = {**payload(), "unknown": 1}

    assert _found(stored(("c-1", unhashable)), {"c-2": HeldContract(payload())}) == []


def test_an_embedded_payload_that_is_no_object_is_refused_when_its_contract_is_held() -> None:
    assert _found(stored(("c-1", "x")), {"c-1": HeldContract(payload())}) == [
        (POINTER.format(0), NOT_HASHED.format(by="contract ID"))
    ]


def test_each_payload_is_judged_at_its_own_pointer() -> None:
    scenario = stored(("c-1", payload()), ("c-2", payload("ls", "ext-2")))

    assert _found(scenario, payloads={"ext-1": payload(), "ext-2": payload("pwd", "ext-2")}) == [
        (POINTER.format(1), OTHER_PAYLOAD.format(by="payload external ID"))
    ]


def test_the_techniques_are_the_archive_s_on_both_sides() -> None:
    scenario = stored(("c-1", payload()))
    other = copy.deepcopy(scenario)
    other["scenario_injects"][0]["inject_injector_contract"][
        "injector_contract_attack_patterns"
    ] = [{"attack_pattern_external_id": "T1059"}]

    assert _found(other, payloads={"ext-1": payload()}) == []


def test_a_payload_without_identifiers_is_nothing_to_compare() -> None:
    bare = {k: v for k, v in payload().items() if k != "payload_external_id"}
    scenario = stored(("c-1", bare))
    scenario["scenario_injects"][0]["inject_injector_contract"].pop("injector_contract_id")

    assert _found(scenario, {"c-1": HeldContract(payload("id"))}, {"ext-1": payload("id")}) == []


def test_an_embedded_payload_with_a_file_cannot_be_compared() -> None:
    with_file = {**payload(), "payload_type": "Executable", "executable_file": "doc-1"}
    with_file.pop("command_executor")
    with_file.pop("command_content")

    assert _found(stored(("c-1", with_file)), payloads={"ext-1": payload("id")}) == [
        (POINTER.format(0), NOT_HASHED.format(by="payload external ID"))
    ]


def test_each_payload_is_judged_whatever_the_payloads_before_it_give() -> None:
    unhashable = payload()
    unhashable["payload_type"] = "Unknown"
    scenario = stored(
        ("c-0", unhashable),
        ("c-1", payload(external_id="ext-1")),  # not held
        ("c-2", payload(external_id="ext-2")),  # held without a payload
        ("c-3", payload(external_id="ext-3")),  # held, cannot be hashed
        ("c-4", payload(external_id="ext-4")),  # held as it is
        ("c-5", payload(external_id="ext-5")),  # held otherwise
    )
    held_unhashable = payload(external_id="ext-3")
    held_unhashable["payload_type"] = "Unknown"
    contracts = {
        "c-0": HeldContract(payload("id")),
        "c-2": HeldContract(None),
        "c-3": HeldContract(held_unhashable),
        "c-4": HeldContract(payload(external_id="ext-4")),
        "c-5": HeldContract(payload("id", external_id="ext-5")),
    }

    assert _found(scenario, contracts) == [
        (POINTER.format(0), NOT_HASHED.format(by="contract ID")),
        (POINTER.format(2), NO_PAYLOAD),
        (POINTER.format(3), UNCOMPARABLE.format(by="contract ID")),
        (POINTER.format(5), OTHER_PAYLOAD.format(by="contract ID")),
    ]


def test_a_held_payload_with_a_file_cannot_be_compared() -> None:
    held = {
        "payload_type": "Executable",
        "payload_name": "who",
        "executable_file": "document-1",
        "payload_external_id": "ext-1",
    }

    assert _found(stored(("c-1", payload())), {"c-1": HeldContract(held)}) == [
        (POINTER.format(0), UNCOMPARABLE.format(by="contract ID"))
    ]


STEP_POINTER = (
    "/scenario_workflow/workflow_steps/{}/step_data"
    "/inject_injector_contract/injector_contract_payload"
)


def _in_steps(*data: object) -> dict[str, Any]:
    return {"scenario_workflow": {"workflow_steps": [{"step_data": item} for item in data]}}


@pytest.mark.parametrize("as_text", [False, True], ids=["object", "JSON text"])
def test_a_step_is_judged_whether_its_inject_is_an_object_or_json_text(as_text: bool) -> None:
    inject = stored(("c-1", payload()))["scenario_injects"][0]
    scenario = _in_steps(json.dumps(inject) if as_text else inject)

    assert _found(scenario, {"c-1": HeldContract(payload("id"))}) == [
        (STEP_POINTER.format(0), OTHER_PAYLOAD.format(by="contract ID"))
    ]


def test_the_identifiers_of_a_step_given_as_json_text_are_read() -> None:
    inject = stored(("c-1", payload()))["scenario_injects"][0]

    assert identifiers(_in_steps(json.dumps(inject))) == (
        frozenset({"c-1"}),
        frozenset({"ext-1"}),
    )


@pytest.mark.parametrize("text", ["{", '{"a": 1, "a": 2}'], ids=["not JSON", "a key twice"])
def test_a_step_whose_json_text_cannot_be_read_is_refused(text: str) -> None:
    inject = stored(("c-1", payload()))["scenario_injects"][0]

    assert _found(_in_steps(text, json.dumps(inject)), {"c-1": HeldContract(payload("id"))}) == [
        ("/scenario_workflow/workflow_steps/0/step_data", UNREADABLE_STEP),
        (STEP_POINTER.format(1), OTHER_PAYLOAD.format(by="contract ID")),
    ]


def test_a_step_given_as_json_text_is_left_as_it_is() -> None:
    inject = stored(("c-1", payload()))["scenario_injects"][0]
    scenario = _in_steps(json.dumps(inject))
    before = copy.deepcopy(scenario)

    _found(scenario, {"c-1": HeldContract(payload("id"))})

    assert scenario == before


def test_an_embedded_payload_that_is_no_object_and_is_not_held_is_nothing_to_say() -> None:
    assert _found(stored(("c-1", "x")), payloads={"ext-1": payload()}) == []


@pytest.mark.parametrize(
    "scenario",
    [
        {"scenario_workflow": "x"},
        {"scenario_workflow": {"workflow_steps": "x"}},
        {"scenario_workflow": {"workflow_steps": ["x", {"step_data": None}]}},
    ],
    ids=["workflow", "steps", "a step"],
)
def test_a_workflow_of_another_shape_is_nothing_to_compare(scenario: dict[str, Any]) -> None:
    assert _found(scenario, {"c-1": HeldContract(payload("id"))}) == []
