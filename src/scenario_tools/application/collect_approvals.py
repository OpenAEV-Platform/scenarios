"""Collect who approved the change of each entry: the pull request merged as the last commit
that changed it, and those who approved what it merged, asked of GitHub once each; and the
entry's origin: whether the author of the pull request merged as the first commit that changed
it is a member of the organisation, asked of GitHub once for each author."""

from collections.abc import Callable, Sequence

from scenario_tools.domain.release.manifest import COMMUNITY, FILIGRAN, Approval, Approvals
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
    first_commit: Callable[[str], str],
    pulls_of: Callable[[str], object],
    reviews_of: Callable[[int], object],
    is_member: Callable[[str], bool],
) -> Approvals:
    """The approval of each of ``entries`` of ``repository`` at ``commit``: ``last_commit``
    gives the last commit that changed an entry, ``first_commit`` the first, ``pulls_of`` the
    pull requests GitHub associates with a commit, ``reviews_of`` the reviews of a pull request,
    and ``is_member`` whether a login is a member of the organisation. An entry no pull request
    merged last, or first, is refused: a change of the catalogue goes through a reviewed pull
    request, and an origin is never guessed."""
    merged: dict[str, MergedPullRequest | None] = {}
    approvers: dict[int, tuple[str, ...]] = {}
    members: dict[str, bool] = {}

    def merged_as(changed: str) -> MergedPullRequest | None:
        if changed not in merged:
            pulls = pulls_of(changed)
            try:
                merged[changed] = merged_pull_request(pulls, changed, repository)
            except ValueError as error:
                raise _usable(error) from error
        return merged[changed]

    found = {}
    for entry in entries:
        changed = last_commit(entry)
        pull = merged_as(changed)
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
        brought = first_commit(entry)
        first = merged_as(brought)
        if first is None:
            raise EnvironmentProblemError(
                f"the first commit that changed {entry}, {brought}, was merged into the default "
                "branch by no pull request: its origin cannot be told"
            )
        if first.author not in members:
            members[first.author] = is_member(first.author)
        if members[first.author]:
            found[entry] = Approval(pull.number, approvers[pull.number], FILIGRAN, None)
        else:
            found[entry] = Approval(pull.number, approvers[pull.number], COMMUNITY, first.author)
    return Approvals(commit, found)
