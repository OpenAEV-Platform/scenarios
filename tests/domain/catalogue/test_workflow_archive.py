"""The archive of a scenario in chaining: the workflow is a part of the stored scenario, carried
as it is once its graph and conditions are checked, and its steps' payloads are what the release
check counts."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.catalogue.archive import STORED_PARTS, archive_findings, checked_workflow
from scenario_tools.domain.catalogue.facts import BuiltinContracts, export_facts
from scenario_tools.domain.catalogue.metadata import is_tabletop
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.shared.workflow import (
    CONDITION_MAPPER,
    CONDITION_STEP_FROM,
    CYCLE,
    MAX_STEPS,
    TOO_MANY_STEPS,
)
from scenario_tools.domain.verification.payload_hash import embedded_payloads, payload_hash
from scenario_tools.domain.verification.release_output import payload_content_findings

ROOT = Path(__file__).resolve().parents[3]
STORED: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json").read_text("utf-8")
)
PATH = "scenarios/techniques/chained/scenario.json"
STEPS = "/scenario_workflow/workflow_steps"
CONTRACT, PAYLOAD = "inject_injector_contract", "injector_contract_payload"
SUPPORTED = frozenset({"DEPEND_ON"})


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = document["scenario_workflow"]["workflow_steps"]
    return steps


def test_the_workflow_is_a_part_of_a_stored_scenario() -> None:
    assert "scenario_workflow" in STORED_PARTS
    assert archive_findings(STORED, PATH) == ()


@pytest.mark.parametrize("workflow", ["text", {"workflow_steps": "text"}])
def test_a_workflow_of_another_shape_is_refused(workflow: object) -> None:
    with pytest.raises(ExportStructureError):
        archive_findings({**copy.deepcopy(STORED), "scenario_workflow": workflow}, PATH)


def test_a_workflow_whose_graph_and_conditions_are_sound_is_carried() -> None:
    checked_workflow(STORED, SUPPORTED)
    checked_workflow({**copy.deepcopy(STORED), "scenario_workflow": None}, SUPPORTED)


def test_a_condition_out_of_the_subset_keeps_the_scenario_out_of_an_archive() -> None:
    stored = copy.deepcopy(STORED)
    waiting = next(step for step in _steps(stored) if step["step_conditions"])
    waiting["step_conditions"][0]["condition_type"] = "MAPPER"
    index = _steps(stored).index(waiting)
    with pytest.raises(ExportStructureError) as error:
        checked_workflow(stored, SUPPORTED)
    assert (error.value.what, error.value.pointer) == (
        CONDITION_MAPPER,
        f"{STEPS}/{index}/step_conditions/0",
    )


def test_steps_that_wait_for_each_other_keep_the_scenario_out_of_an_archive() -> None:
    stored = copy.deepcopy(STORED)
    first, second = _steps(stored)
    waiting, awaited = (second, first) if second["step_conditions"] else (first, second)
    awaited["step_conditions"] = [
        {
            **waiting["step_conditions"][0],
            "condition_id": "00000000-0000-4000-8000-0000000000c1",
            "condition_value": waiting["step_id"],
        }
    ]
    with pytest.raises(ExportStructureError) as error:
        checked_workflow(stored, SUPPORTED)
    assert error.value.what == CYCLE


def test_a_scenario_in_chaining_is_never_tabletop_in_a_release() -> None:
    builtin = BuiltinContracts.from_document(
        YamlDataLoader(ROOT / "policy" / "data").load("builtin-contracts")
    )
    facts, _ = export_facts(STORED, builtin, PATH)
    assert not is_tabletop(facts, frozenset({"openaev_implant"}))


# What the release check counts


def _item(stored: dict[str, Any], *listed: tuple[str, str]) -> dict[str, Any]:
    return {
        "archive": {"name": "chained-1.0.0.zip"},
        "payloads": [{"id": identifier, "sha256": digest} for identifier, digest in listed],
    }


def _listed(stored: dict[str, Any]) -> tuple[str, str]:
    """The ID and hash of the payload the steps share, as the release check computes them."""
    found = next(embedded_payloads(stored))
    assert isinstance(found.payload, dict)
    return str(found.payload["payload_external_id"]), payload_hash(
        found.payload, found.attack_patterns, _files
    ).hex


def _files(_: str) -> str | None:
    return None


def test_the_payload_of_the_steps_listed_once_with_its_hash_passes() -> None:
    assert payload_content_findings(_item(STORED, _listed(STORED)), STORED, _files) == ()


def test_a_payload_of_a_step_the_manifest_does_not_list_is_refused_at_its_step() -> None:
    findings = payload_content_findings(_item(STORED), STORED, _files)
    assert [(f.code, f.field) for f in findings] == [
        ("VRF-008", f"{STEPS}/0/step_data/{CONTRACT}/{PAYLOAD}"),
        ("VRF-008", f"{STEPS}/1/step_data/{CONTRACT}/{PAYLOAD}"),
    ]


def test_a_payload_outside_the_contract_of_a_step_is_refused() -> None:
    stored = copy.deepcopy(STORED)
    data = _steps(stored)[0]["step_data"]
    data["inject_content"] = {"hidden": {PAYLOAD: data[CONTRACT][PAYLOAD]}}
    findings = payload_content_findings(_item(stored, _listed(stored)), stored, _files)
    assert [(f.code, f.field) for f in findings] == [
        ("VRF-008", f"{STEPS}/0/step_data/inject_content/hidden")
    ]


def test_a_workflow_part_of_another_shape_in_an_archive_is_refused() -> None:
    stored = {**copy.deepcopy(STORED), "scenario_workflow": "text"}
    findings = payload_content_findings(_item(stored), stored, _files)
    assert [f.code for f in findings] == ["VRF-007"]


@pytest.mark.parametrize(
    "workflow",
    [
        0,
        ["not", "a", "workflow"],
        {"workflow_steps": ["not a step"]},
        {"workflow_steps": [{"step_conditions": "not a list"}]},
        {"workflow_steps": [{"step_conditions": ["not a condition"]}]},
    ],
)
def test_a_workflow_of_another_shape_is_refused_before_its_graph(workflow: object) -> None:
    with pytest.raises(ExportStructureError):
        checked_workflow({**copy.deepcopy(STORED), "scenario_workflow": workflow}, SUPPORTED)


def test_the_graph_is_checked_before_the_subset() -> None:
    stored = copy.deepcopy(STORED)
    waiting = next(step for step in _steps(stored) if step["step_conditions"])
    condition = waiting["step_conditions"][0]
    condition.update(condition_type="MAPPER", condition_step_from_id="x")
    with pytest.raises(ExportStructureError) as error:
        checked_workflow(stored, SUPPORTED)
    assert error.value.what == CONDITION_STEP_FROM  # a graph rule, before the mapper


def test_the_archive_check_leaves_injects_beside_a_workflow_to_normalisation() -> None:
    # Normalising the stored file again refuses injects and a workflow together; the workflow
    # check reads the workflow only.
    stored = copy.deepcopy(STORED)
    stored["scenario_injects"] = [copy.deepcopy(_steps(stored)[0]["step_data"])]
    checked_workflow(stored, SUPPORTED)


def test_verify_checks_the_payloads_of_a_workflow_not_its_graph() -> None:
    # A consumer's verify proves what the manifest vouches for: the archive's hash and its
    # payloads. The workflow's graph and conditions are checked by build, not again by verify.
    stored = copy.deepcopy(STORED)
    for step in _steps(stored):
        for condition in step["step_conditions"]:
            condition["condition_type"] = "MAPPER"
    assert payload_content_findings(_item(stored, _listed(stored)), stored, _files) == ()


def test_a_workflow_beyond_its_bound_is_refused_before_its_graph_is_read() -> None:
    stored = copy.deepcopy(STORED)
    first = _steps(stored)[0]
    _steps(stored)[:] = [
        {**copy.deepcopy(first), "step_id": f"00000000-0000-4000-8000-{index:012x}"}
        for index in range(MAX_STEPS + 1)
    ]
    with pytest.raises(ExportStructureError) as error:
        checked_workflow(stored, SUPPORTED)
    assert error.value.what == TOO_MANY_STEPS
