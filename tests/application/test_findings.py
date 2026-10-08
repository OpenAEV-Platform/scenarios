"""Refusals from the adapters become findings."""

from scenario_tools.application.findings import finding_from_unsafe_input
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import UnsafeInputError


def test_an_unsafe_input_becomes_a_blocking_io_finding() -> None:
    error = UnsafeInputError("IO-001", "larger than 10 bytes", "scenarios/x/scenario.json")

    assert finding_from_unsafe_input(error) == Finding(
        "IO-001", Severity.BLOCKING, "scenarios/x/scenario.json", "", "larger than 10 bytes"
    )


def test_an_unsafe_input_without_a_file_has_an_empty_path() -> None:
    assert finding_from_unsafe_input(UnsafeInputError("IO-002", "not valid JSON")).path == ""
