"""Use case: check a pull request title against the shared convention."""

from scenario_tools.domain.shared.title import TitleProblem, check_pull_request_title


def check_title(title: str) -> TitleProblem | None:
    """Return the first problem found in ``title``, or ``None`` if it follows the convention.

    The title is the only input; no port is needed.
    """
    return check_pull_request_title(title)
