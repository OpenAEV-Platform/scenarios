"""The policy rules on the steps of a workflow: each rule that reads an inject's payload or content
reads a step's too, at the step's pointer; the spacing rule reads the injects of a time-based
scenario only; and an exception can name a step's field."""

from typing import Any

import pytest

from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rule import EntryContent
from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.versioning import versioning_findings
from tests.domain.policy.cases import DATA, METADATA, content
from tests.domain.policy.test_exceptions import ID, SHA, data_with, identified
from tests.domain.verification.test_versioning import METADATA as VERSIONED

STEP = "/scenario_workflow/workflow_steps/1/step_data"
STEP_PAYLOAD = f"{STEP}/inject_injector_contract/injector_contract_payload"


def _in_a_step(data: dict[str, Any], kind: str = "chained") -> EntryContent:
    """A scenario whose second step runs the inject ``data``, after a first step that runs a
    harmless payload."""
    harmless = {
        "inject_injector_contract": {"injector_contract_payload": {"command_content": "whoami"}}
    }
    return content(
        declared={**METADATA, "type": kind},
        stored={
            "scenario_information": {"scenario_name": "Chained"},
            "scenario_injects": [],
            "scenario_workflow": {"workflow_steps": [{"step_data": harmless}, {"step_data": data}]},
        },
    )


def _payload(**payload: object) -> EntryContent:
    return _in_a_step({"inject_injector_contract": {"injector_contract_payload": payload}})


def _content(inject_content: object) -> EntryContent:
    return _in_a_step({"inject_content": inject_content})


# A passing and a failing example of each rule that reads an inject, both on a step, with the
# field the failing one is reported at.
STEP_CASES: dict[str, tuple[EntryContent, EntryContent, str]] = {
    "POL-003": (
        _content({"targets": "192.0.2.10"}),
        _content({"targets": "10.0.0.5"}),
        f"{STEP}/inject_content/targets",
    ),
    "POL-004": (
        _payload(command_content="vssadmin list shadows"),
        _payload(command_content="vssadmin delete shadows /all /quiet"),
        f"{STEP_PAYLOAD}/command_content",
    ),
    "POL-005": (
        _payload(
            command_content="copy a b",
            payload_cleanup_command="del b",
            payload_cleanup_executor="cmd",
        ),
        _payload(command_content="copy a b"),
        f"{STEP_PAYLOAD}/payload_cleanup_command",
    ),
    "POL-006": (
        _payload(command_content="whoami"),
        _payload(command_content="sc query CrowdStrike"),
        f"{STEP_PAYLOAD}/command_content",
    ),
    "POL-007": (
        _payload(payload_elevation_required=False),
        _payload(payload_elevation_required=True),
        f"{STEP_PAYLOAD}/payload_elevation_required",
    ),
    "POL-010": (
        _content({"message": "write to a@example.org"}),
        _content({"message": "write to a@corp.com"}),
        f"{STEP}/inject_content/message",
    ),
}


def _of(code: str, findings: tuple[Any, ...]) -> list[str]:
    return [finding.field for finding in findings if finding.code == code]


@pytest.mark.parametrize("code", sorted(STEP_CASES))
def test_a_rule_that_reads_an_inject_reads_a_step(code: str) -> None:
    passing, failing, field = STEP_CASES[code]
    assert _of(code, policy_findings(DATA, passing)) == []
    assert _of(code, policy_findings(DATA, failing)) == [field]


def _timed_steps(*offsets: int, kind: str) -> EntryContent:
    return content(
        declared={**METADATA, "type": kind},
        stored={
            "scenario_information": {"scenario_name": "Chained"},
            "scenario_injects": [],
            "scenario_workflow": {
                "workflow_steps": [
                    {
                        "step_data": {
                            "inject_depends_duration": offset,
                            "inject_injector_contract": {
                                "injector_contract_payload": {"command_content": "whoami"}
                            },
                        }
                    }
                    for offset in offsets
                ]
            },
        },
    )


def test_steps_closer_than_a_minute_are_exempt_from_the_spacing_rule() -> None:
    # A chained scenario is outside the rule: time-based metadata reaches the rule, whose filter
    # on the origin leaves the steps out (SCH-013 refuses that combination on its own).
    assert _of("POL-009", policy_findings(DATA, _timed_steps(0, 30, kind="time-based"))) == []


def test_a_step_never_pairs_with_an_inject_and_injects_are_still_spaced() -> None:
    mixed = _timed_steps(30, kind="time-based")
    mixed.stored["scenario_injects"] = [  # type: ignore[index]
        {
            "inject_depends_duration": 0,
            "inject_injector_contract": {"injector_contract_payload": {"command_content": "id"}},
        }
    ]
    assert _of("POL-009", policy_findings(DATA, mixed)) == []
    mixed.stored["scenario_injects"].append(  # type: ignore[index]
        {
            "inject_depends_duration": 30,
            "inject_injector_contract": {"injector_contract_payload": {"command_content": "id"}},
        }
    )
    assert _of("POL-009", policy_findings(DATA, mixed)) == [
        "/scenario_injects/1/inject_depends_duration"
    ]


def test_an_exception_can_name_the_field_of_a_step() -> None:
    _, failing, field = STEP_CASES["POL-006"]
    exception = {
        "entry": ID,
        "code": "POL-006",
        "field": field,
        "sha256": SHA,
        "justification": "the product is named to check that the simulation stops at the query",
    }
    findings = policy_findings(data_with(exception), identified(failing))
    assert [(f.code, f.severity, f.field) for f in findings if f.code == "POL-006"] == [
        ("POL-006", Severity.INFO, field)
    ]


def _with_step_payload(identifier: str) -> dict[str, Any]:
    payload = {"payload_external_id": identifier}
    step = {"step_data": {"inject_injector_contract": {"injector_contract_payload": payload}}}
    return {
        "scenario_information": {"scenario_name": "Chained"},
        "scenario_injects": [],
        "scenario_workflow": {"workflow_steps": [{"step_data": {}}, step]},
    }


def test_a_payload_a_step_did_not_run_before_is_pointed_out() -> None:
    previous = (VERSIONED, _with_step_payload("p1"))

    def new_payloads(identifier: str) -> list[str]:
        found = versioning_findings(
            previous,
            {**VERSIONED, "version": "1.1.0"},
            _with_step_payload(identifier),
            metadata_path="scenario.yaml",
            scenario_path="scenario.json",
        )
        return [f.field for f in found if f.code == "POL-008"]

    assert new_payloads("p1") == []
    assert new_payloads("p2") == [f"{STEP_PAYLOAD}/payload_external_id"]
