"""The check-title use case reports a TTL-001 finding for a title that breaks the convention."""

from scenario_tools.application.check_title import check_title
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.title import TitleProblem


def test_a_valid_title_gives_an_ok_report() -> None:
    report = check_title("ci(tooling): check pull request titles (#6)")

    assert report.ok
    assert report.findings == ()


def test_an_invalid_title_gives_a_blocking_finding() -> None:
    report = check_title("ci(tooling): check pull request titles")

    assert report.findings == (
        Finding("TTL-001", Severity.BLOCKING, "", "", TitleProblem.MISSING_ISSUE.message),
    )
