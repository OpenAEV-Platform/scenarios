"""No recurrence: a shared scenario never schedules itself on the platform that imports it."""

import pytest

from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rules.recurrence import RECURRENCE_FIELDS, RULE, violations
from scenario_tools.domain.shared.finding import Severity
from tests.domain.policy.cases import ENTRY, content, with_recurrence

JSON = f"{ENTRY}/scenario.json"


def test_the_rule_is_pol_002_and_blocks() -> None:
    assert (RULE.code, RULE.severity) == ("POL-002", Severity.BLOCKING)


def test_the_fields_are_the_ones_the_importer_reads() -> None:
    assert RECURRENCE_FIELDS == (
        "scenario_recurrence",
        "scenario_recurrence_start",
        "scenario_recurrence_end",
    )


@pytest.mark.parametrize("field", RECURRENCE_FIELDS)
@pytest.mark.parametrize("value", ["0 0 8 * * MON", "2026-10-13T08:00:00Z", "", 0, False, [], {}])
def test_a_recurrence_field_with_a_value_is_refused(field: str, value: object) -> None:
    (finding,) = policy_findings(with_recurrence(field, value))

    assert (finding.code, finding.severity, finding.path, finding.field) == (
        "POL-002",
        Severity.BLOCKING,
        JSON,
        f"/scenario_information/{field}",
    )
    assert finding.message == (
        f"{field} is set: the importer would schedule the scenario, which the catalogue never does"
    )


def test_each_field_with_a_value_is_reported() -> None:
    information = {"scenario_recurrence": "0 0 8 * * MON", "scenario_recurrence_end": "2027"}

    findings = policy_findings(content(stored={"scenario_information": information}))

    assert [f.field for f in findings] == [
        "/scenario_information/scenario_recurrence",
        "/scenario_information/scenario_recurrence_end",
    ]


@pytest.mark.parametrize("field", RECURRENCE_FIELDS)
def test_an_empty_recurrence_field_is_no_recurrence(field: str) -> None:
    assert policy_findings(with_recurrence(field, None)) == ()


@pytest.mark.parametrize(
    "scenario",
    [None, [], "scenario", {}, {"scenario_information": None}, {"scenario_information": []}],
)
def test_a_stored_scenario_not_shaped_like_one_is_left_to_its_own_check(scenario: object) -> None:
    assert policy_findings(content(stored=scenario)) == ()


def test_violations_name_the_path_they_are_given() -> None:
    document = {"scenario_information": {"scenario_recurrence": "0 0 8 * * MON"}}

    (violation,) = violations(document, "elsewhere/scenario.json")

    assert (violation.path, violation.field) == (
        "elsewhere/scenario.json",
        "/scenario_information/scenario_recurrence",
    )
