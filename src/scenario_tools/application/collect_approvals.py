"""Collect who approved the change of each entry: the pull request merged as the last commit
that changed it, and those who approved what it merged, asked of GitHub once each."""

from collections.abc import Callable, Sequence

from scenario_tools.domain.release.manifest import Approval, Approvals
from scenario_tools.domain.release.pull_requests import (
    MergedPullRequest,
    approvers_from_reviews,
    merged_pull_request,
)
from scenario_tools.ports.errors import EnvironmentProblemError


def _usable(error: ValueError) -> EnvironmentProblemError:
    return EnvironmentProblemError(f"GitHub's answer cannot be used: {error}")


def collect_approvals(
    entries: Sequence[str],
    *,
    commit: str,
    repository: str,
    last_commit: Callable[[str], str],
    pulls_of: Callable[[str], object],
    reviews_of: Callable[[int], object],
) -> Approvals:
    """The approval of each of ``entries`` of ``repository`` at ``commit``: ``last_commit``
    gives the last commit that changed an entry, ``pulls_of`` the pull requests GitHub
    associates with a commit, and ``reviews_of`` the reviews of a pull request. An entry no
    pull request merged last is refused: a change of the catalogue goes through a reviewed
    pull request."""
    merged: dict[str, MergedPullRequest | None] = {}
    approvers: dict[int, tuple[str, ...]] = {}
    found = {}
    for entry in entries:
        changed = last_commit(entry)
        if changed not in merged:
            pulls = pulls_of(changed)
            try:
                merged[changed] = merged_pull_request(pulls, changed, repository)
            except ValueError as error:
                raise _usable(error) from error
        pull = merged[changed]
        if pull is None:
            raise EnvironmentProblemError(
                f"the last commit that changed {entry}, {changed}, was merged into the default "
                "branch by no pull request: a change of the catalogue goes through a reviewed, "
                "squash-merged pull request"
            )
        if pull.number not in approvers:
            reviews = reviews_of(pull.number)
            try:
                approvers[pull.number] = approvers_from_reviews(reviews, pull)
            except ValueError as error:
                raise _usable(error) from error
        found[entry] = Approval(pull.number, approvers[pull.number])
    return Approvals(commit, found)
