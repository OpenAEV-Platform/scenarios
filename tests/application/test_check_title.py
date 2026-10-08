"""The check-title use case applies the shared title convention."""

from scenario_tools.application.check_title import check_title
from scenario_tools.domain.shared.title import TitleProblem


def test_a_valid_title_has_no_problem() -> None:
    assert check_title("ci(tooling): check pull request titles (#6)") is None


def test_an_invalid_title_reports_its_problem() -> None:
    assert check_title("ci(tooling): check pull request titles") is TitleProblem.MISSING_ISSUE
