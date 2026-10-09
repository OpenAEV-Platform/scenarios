"""Refusals from the adapters become findings."""

from pathlib import PurePosixPath

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.adapters.safe_readers import parse_json
from scenario_tools.application.findings import finding_from_unsafe_input
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Finding, Severity
from scenario_tools.ports.errors import UnsafeInputError

ROOT = PurePosixPath("/work/scenarios")


def test_an_unsafe_input_becomes_a_blocking_io_finding() -> None:
    error = UnsafeInputError("IO-001", "larger than 10 bytes", "scenarios/x/scenario.json")

    assert finding_from_unsafe_input(error, ROOT) == Finding(
        "IO-001", Severity.BLOCKING, "scenarios/x/scenario.json", "", "larger than 10 bytes"
    )


def test_an_unsafe_input_without_a_file_has_an_empty_path() -> None:
    assert finding_from_unsafe_input(UnsafeInputError("IO-002", "not valid JSON"), ROOT).path == ""


def test_an_absolute_path_inside_the_repository_becomes_relative() -> None:
    error = UnsafeInputError("IO-001", "too large", "/work/scenarios/scenarios/x/scenario.json")

    assert finding_from_unsafe_input(error, ROOT).path == "scenarios/x/scenario.json"


@pytest.mark.parametrize(
    "path", ["/home/runner/.ssh/id_rsa", "../outside/id_rsa", "/work/scenarios/../outside/id_rsa"]
)
def test_a_path_outside_the_repository_keeps_only_its_file_name(path: str) -> None:
    finding = finding_from_unsafe_input(UnsafeInputError("IO-013", "a symbolic link", path), ROOT)

    assert finding.path == "id_rsa"


@pytest.mark.parametrize(
    ("path", "kept"),
    [("C:\\work\\id_rsa", "id_rsa"), ("a\\b.json", "b.json"), ("C:", ""), ("x/..", ""), ("/", "")],
)
def test_paths_that_cannot_be_reported_as_they_are_keep_only_their_name(
    path: str, kept: str
) -> None:
    assert finding_from_unsafe_input(UnsafeInputError("IO-002", "m", path), ROOT).path == kept


@given(st.text())
def test_no_path_can_make_the_conversion_fail(path: str) -> None:
    finding = finding_from_unsafe_input(UnsafeInputError("IO-002", "not valid JSON", path), ROOT)

    assert finding.code == "IO-002"


def test_a_value_quoted_by_a_reader_is_never_echoed_in_full() -> None:
    key = "k" * 1_000_000
    try:
        parse_json(f'{{"{key}": 1, "{key}": 2}}'.encode())
    except UnsafeInputError as error:
        finding = finding_from_unsafe_input(error, ROOT)
    else:  # pragma: no cover - the reader refuses duplicate keys
        pytest.fail("the duplicate key was accepted")

    assert finding.code == "IO-005"
    assert len(finding.message) <= MESSAGE_LIMIT
