"""The release fixtures run through the verifier, each compared with what ``expected.json``
says verifying it must give: its findings by code, path and field, and the ``IO`` code an
archive refused as unsafe was refused with."""

from collections.abc import Callable, Sequence

from scenario_tools.application.fixture_expectations import Expectation
from scenario_tools.application.verify_release import unsafe_cause
from scenario_tools.domain.shared.finding import Finding, Report, Severity

Outcome = tuple[tuple[str, str, str, str | None], ...]


def _given(report: Report) -> Outcome:
    return tuple(sorted((f.code, f.path, f.field, unsafe_cause(f)) for f in report.findings))


def _expected(expectation: Expectation) -> Outcome:
    return tuple(sorted((f.code, f.path, f.field, f.cause) for f in expectation.findings))


def _said(outcome: Outcome) -> str:
    if not outcome:
        return "no finding"
    return ", ".join(
        f"{code} {path}{field}" + (f" ({cause})" if cause else "")
        for code, path, field, cause in outcome
    )


def run_fixtures(
    expectations: Sequence[Expectation],
    *,
    present: frozenset[str],
    outcome_of: Callable[[Expectation], Report],
) -> Report:
    """The report on the fixtures ``expectations`` describe: ``present`` names the directories
    beside ``expected.json``, and ``outcome_of`` verifies a fixture. ``CNF-001`` for a fixture
    giving other findings than expected, ``CNF-002`` for a fixture without its directory or a
    directory no fixture names."""
    by_name = {expectation.name: expectation for expectation in expectations}
    findings: list[Finding] = []
    for name in sorted(by_name.keys() | present):
        if name not in present or name not in by_name:
            message = (
                "the fixture has no directory"
                if name not in present
                else "no fixture of expected.json names this directory"
            )
            findings.append(Finding("CNF-002", Severity.BLOCKING, name, "", message))
            continue
        given, expected = _given(outcome_of(by_name[name])), _expected(by_name[name])
        if given != expected:
            message = f"verify gives {_said(given)}, where expected.json says {_said(expected)}"
            findings.append(Finding("CNF-001", Severity.BLOCKING, name, "", message))
    return Report("conformance", tuple(findings))
