"""The payloads of the steps of a stored scenario in chaining, read through the walk over its
injects: the payload checks, the facts and the assignment of payload IDs see them as they see
the payloads of injects."""

import copy
import json
from pathlib import Path
from typing import Any

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.application.assign_payloads import assigned_entry, payload_findings
from scenario_tools.domain.catalogue.archive import payloads_outside_contracts
from scenario_tools.domain.catalogue.facts import BuiltinContracts, export_facts
from scenario_tools.domain.verification.payload_references import AgreedIds

ROOT = Path(__file__).resolve().parents[3]
STORED: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json").read_text("utf-8")
)
PATH = "scenarios/techniques/chained/scenario.json"
STEPS = "/scenario_workflow/workflow_steps"
CONTRACT = "inject_injector_contract"
PAYLOAD = "injector_contract_payload"
BUILTIN = BuiltinContracts.from_document(
    YamlDataLoader(ROOT / "policy" / "data").load("builtin-contracts")
)


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = document["scenario_workflow"]["workflow_steps"]
    return steps


def test_the_payload_of_a_step_sits_inside_a_contract() -> None:
    assert payloads_outside_contracts(STORED, PATH) == ()


def test_a_payload_elsewhere_in_a_step_is_outside_any_contract() -> None:
    stored = copy.deepcopy(STORED)
    data = _steps(stored)[0]["step_data"]
    data["inject_content"] = {"hidden": {PAYLOAD: data[CONTRACT][PAYLOAD]}}
    (finding,) = payloads_outside_contracts(stored, PATH)
    assert (finding.code, finding.field) == (
        "PAY-004",
        f"{STEPS}/0/step_data/inject_content/hidden",
    )


def test_the_facts_cover_the_steps() -> None:
    facts, unknown = export_facts(STORED, BUILTIN, PATH)
    assert unknown == ()
    assert [(item.injector_type, item.needs_executor) for item in facts.injects] == [
        ("openaev_implant", True),
        ("openaev_implant", True),
    ]
    assert all(item.platforms for item in facts.injects)


def test_the_payload_of_each_step_is_given_the_id_its_content_has() -> None:
    assigned = assigned_entry({"name": "x"}, copy.deepcopy(STORED), "entry", AgreedIds({}))
    assert assigned.refusals == ()
    assert assigned.stored is not None
    assert assigned.metadata is not None
    ids = {
        step["step_data"][CONTRACT][PAYLOAD]["payload_external_id"]
        for step in _steps(dict(assigned.stored))
    }
    (reference,) = assigned.metadata["payloads"]
    assert ids == {reference["id"]}


def _codes(findings: tuple[Any, ...]) -> list[tuple[str, str]]:
    return [(finding.code, finding.field) for finding in findings]


def _with_inject_of(step: int) -> dict[str, Any]:
    """The stored scenario with an inject that runs the payload of the step at ``step``."""
    stored = copy.deepcopy(STORED)
    stored["scenario_injects"] = [copy.deepcopy(_steps(stored)[step]["step_data"])]
    return stored


def test_a_payload_shared_by_an_inject_and_a_step_gets_one_reference() -> None:
    assigned = assigned_entry({"name": "x"}, _with_inject_of(0), "entry", AgreedIds({}))
    assert assigned.refusals == ()
    assert assigned.metadata is not None
    assert len(assigned.metadata["payloads"]) == 1


def test_two_payloads_of_one_name_in_an_inject_and_a_step_are_refused() -> None:
    stored = _with_inject_of(0)
    stored["scenario_injects"][0][CONTRACT][PAYLOAD]["payload_description"] = "Another content."
    codes = _codes(payload_findings({}, stored, "entry", AgreedIds({})))
    name = f"step_data/{CONTRACT}/{PAYLOAD}/payload_name"
    assert [field for code, field in codes if code == "PAY-007"] == [
        f"{STEPS}/0/{name}",
        f"{STEPS}/1/{name}",
    ]


def test_a_payload_of_a_step_that_cannot_be_hashed_is_refused_at_its_pointer() -> None:
    stored = copy.deepcopy(STORED)
    _steps(stored)[1]["step_data"][CONTRACT][PAYLOAD]["payload_unknown_field"] = True
    codes = _codes(payload_findings({}, stored, "entry", AgreedIds({})))
    assert any(code == "PAY-005" and field.startswith(f"{STEPS}/1/") for code, field in codes)


def test_a_step_whose_contract_is_unknown_is_reported_at_the_step() -> None:
    stored = copy.deepcopy(STORED)
    _steps(stored)[0]["step_data"][CONTRACT] = None
    _, unknown = export_facts(stored, BUILTIN, PATH)
    assert _codes(unknown) == [("SCH-005", f"{STEPS}/0/step_data")]
    assert "inject or step" in unknown[0].message


def test_the_facts_say_whether_the_scenario_has_a_workflow() -> None:
    assert export_facts(STORED, BUILTIN, PATH)[0].holds_workflow
    empty: object
    for empty in (None, {}, []):
        without = {**copy.deepcopy(STORED), "scenario_workflow": empty}
        assert not export_facts(without, BUILTIN, PATH)[0].holds_workflow


def test_a_workflow_with_no_step_is_still_a_workflow() -> None:
    stored = {**copy.deepcopy(STORED), "scenario_workflow": {"workflow_steps": []}}
    assert export_facts(stored, BUILTIN, PATH)[0].holds_workflow
