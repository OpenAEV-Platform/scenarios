"""The pull request title convention shared across Filigran repositories.

``type(scope?)!?: description (#issue)``, with the same rules as the shared Filigran title
check, plus no trailing period. The description may start with a capital letter, for proper
nouns such as OpenAEV. Dependency updates, marked ``(deps)``, need no issue reference.
"""

import re
from enum import Enum

TYPES = (
    "feat",
    "fix",
    "chore",
    "docs",
    "style",
    "refactor",
    "perf",
    "test",
    "build",
    "ci",
    "revert",
)
EXPECTED_FORMAT = "type(scope?)!?: description (#issue)"
DEPENDENCY_MARKER = "(deps)"

_HEAD = rf"(?:{'|'.join(TYPES)})(?:\([a-zA-Z0-9_.\-]+\))?!?: "
_PREFIX = re.compile(_HEAD)
_DESCRIPTION = re.compile(rf"{_HEAD}.+")
_ISSUE_REFERENCE = re.compile(r"\(#[0-9]+(?:, ?#[0-9]+)*\)\Z")


class TitleProblem(Enum):
    """Why a title breaks the convention, in the order the checks run."""

    BAD_PREFIX = f"the prefix must be type(scope?)!?: with a type among {', '.join(TYPES)}"
    EMPTY_DESCRIPTION = "a description must follow ': '"
    MISSING_ISSUE = "the title must end with an issue reference, such as (#123)"
    TRAILING_PERIOD = "the description must not end with a period"

    @property
    def message(self) -> str:
        return f"{self.value}. Expected: {EXPECTED_FORMAT}"


def check_pull_request_title(title: str) -> TitleProblem | None:
    """Return the first problem found in ``title``, or ``None`` if it follows the convention."""
    if not _PREFIX.match(title):
        return TitleProblem.BAD_PREFIX
    if not _DESCRIPTION.match(title):
        return TitleProblem.EMPTY_DESCRIPTION
    if DEPENDENCY_MARKER not in title and not _ISSUE_REFERENCE.search(title):
        return TitleProblem.MISSING_ISSUE
    if _ISSUE_REFERENCE.sub("", title).rstrip().endswith("."):
        return TitleProblem.TRAILING_PERIOD
    return None
