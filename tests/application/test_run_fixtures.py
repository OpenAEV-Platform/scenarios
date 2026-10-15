"""The release fixtures run through the verifier, each compared with what expected.json says."""

import pytest

from scenario_tools.application.fixture_expectations import Expectation, ExpectedFinding
from scenario_tools.application.run_fixtures import run_fixtures
from scenario_tools.domain.shared.finding import Finding, Report, Severity

UNSAFE = Finding("VRF-007", Severity.BLOCKING, "a.zip", "", "IO-010: unsafe entry name '../x'")
MISSING = Finding(
    "VRF-006", Severity.BLOCKING, "a.zip", "", "the archive the manifest lists is missing"
)
UNSAFE_EXPECTED = Expectation(
    "unsafe", "Unsafe.", (ExpectedFinding("VRF-007", "a.zip", "", "IO-010"),)
)


def _run(
    expectations: tuple[Expectation, ...],
    outcomes: dict[str, Report],
    present: set[str] | None = None,
) -> Report:
    names = frozenset(outcomes) if present is None else frozenset(present)
    return run_fixtures(
        expectations, present=names, outcome_of=lambda expected: outcomes[expected.name]
    )


def test_fixtures_giving_what_is_expected_pass() -> None:
    accepted = Expectation("accepted", "Accepted.", ())

    report = _run(
        (accepted, UNSAFE_EXPECTED),
        {"accepted": Report("verify"), "unsafe": Report("verify", (UNSAFE,))},
    )

    assert report.command == "conformance"
    assert report.ok


@pytest.mark.parametrize(
    "outcome",
    [Report("verify"), Report("verify", (MISSING,)), Report("verify", (UNSAFE, UNSAFE))],
    ids=["accepted", "another finding", "one more finding"],
)
def test_a_fixture_giving_anything_else_fails(outcome: Report) -> None:
    report = _run((UNSAFE_EXPECTED,), {"unsafe": outcome})

    assert [(f.code, f.path) for f in report.findings] == [("CNF-001", "unsafe")]


def test_the_cause_of_an_unsafe_archive_is_compared_too() -> None:
    expected = Expectation("unsafe", "U.", (ExpectedFinding("VRF-007", "a.zip", "", "IO-009"),))

    (finding,) = _run((expected,), {"unsafe": Report("verify", (UNSAFE,))}).findings

    assert (finding.code, finding.message) == (
        "CNF-001",
        "verify gives VRF-007 a.zip (IO-010), where expected.json says VRF-007 a.zip (IO-009)",
    )


def test_a_directory_no_fixture_names_and_a_fixture_without_its_directory_fail() -> None:
    expectations = (Expectation("accepted", "A.", ()), Expectation("gone", "G.", ()))

    report = _run(expectations, {"accepted": Report("verify")}, present={"accepted", "stray"})

    assert [(f.code, f.path, f.message) for f in report.findings] == [
        ("CNF-002", "gone", "the fixture has no directory"),
        ("CNF-002", "stray", "no fixture of expected.json names this directory"),
    ]


def test_findings_that_differ_only_by_a_cause_and_none_are_compared_without_failing() -> None:
    expected = Expectation(
        "unsafe",
        "U.",
        (
            ExpectedFinding("VRF-007", "a.zip", "", "IO-010"),
            ExpectedFinding("VRF-007", "a.zip", "", None),
        ),
    )
    after = Expectation("zz-after", "Z.", ())
    no_cause = Finding("VRF-007", Severity.BLOCKING, "a.zip", "", "refused")

    report = _run(
        (expected, after),
        {
            "unsafe": Report("verify", (UNSAFE, no_cause, UNSAFE)),
            "zz-after": Report("verify", (MISSING,)),
        },
    )

    assert [(f.code, f.path) for f in report.findings] == [
        ("CNF-001", "unsafe"),
        ("CNF-001", "zz-after"),
    ]
