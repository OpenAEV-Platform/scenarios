"""Use case: check a pull request title against the shared convention."""

from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.domain.shared.title import check_pull_request_title

COMMAND = "check-title"


def check_title(title: str) -> Report:
    """A report with a blocking ``TTL-001`` finding when ``title`` breaks the convention."""
    problem = check_pull_request_title(title)
    if problem is None:
        return Report(COMMAND)
    return Report(COMMAND, (Finding("TTL-001", Severity.BLOCKING, "", "", problem.message),))
