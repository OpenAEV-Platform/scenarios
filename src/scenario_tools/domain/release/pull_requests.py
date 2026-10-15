"""What GitHub says of pull requests, read for a release: the pull request merged as the last
commit that changed an entry, into the default branch of the repository, and those who
approved what it merged. An approver reviewed the pull request's last commit, holds a role in
the repository, and is neither a bot nor its author. What GitHub gives out of its shape is
refused, never read in part."""

from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.release.manifest import is_github_login

# A review that decides: an approval, a request for changes, or one dismissed, which no longer
# counts. A comment, or a review not yet submitted, decides nothing.
_DECISIVE = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})
# What a pull request GitHub gives must hold, to be read.
_PULL = frozenset({"number", "merge_commit_sha", "merged_at", "head", "user", "base"})
# Those whose approval counts: the repository's owner, the organisation's members and the
# repository's collaborators. GitHub lets anyone else review, without their approval counting.
# A role is no proof of write access: what makes an approval count for a merge is the branch's
# rules, which this check stands behind, never in place of.
_ROLES = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})


@dataclass(frozen=True)
class MergedPullRequest:
    """A pull request merged: its number, its last commit, as merged, and its author's login,
    in lower case."""

    number: int
    head: str
    author: str


def _malformed(what: str, why: str) -> ValueError:
    return ValueError(f"{what}: not as GitHub gives them: {why}")


def _field(value: object, *keys: str) -> Any:
    """``value[keys[0]][keys[1]]…``, or ``None`` where one is missing or not an object."""
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def approvers_from_reviews(reviews: object, pull: MergedPullRequest) -> tuple[str, ...]:
    """The logins, in lower case and sorted, of those whose last decisive review of ``pull``'s
    last commit approves it, from its reviews as GitHub lists them, oldest first."""
    if not isinstance(reviews, list):
        raise _malformed("reviews", "a list is needed")
    approves: dict[str, bool] = {}
    for review in reviews:
        kind, login = _field(review, "user", "type"), _field(review, "user", "login")
        state, role = _field(review, "state"), _field(review, "author_association")
        if not isinstance(kind, str) or not isinstance(state, str) or not isinstance(role, str):
            raise _malformed(
                "reviews", f"one of #{pull.number} without its reviewer, its state or its role"
            )
        if not isinstance(review, dict) or "commit_id" not in review:
            raise _malformed("reviews", f"one of #{pull.number} without the commit it reviewed")
        if kind != "User":  # a bot, or an organisation, never approves
            continue
        if not isinstance(login, str) or not is_github_login(login.lower()):
            raise _malformed("reviews", f"one of #{pull.number} without its reviewer's login")
        login = login.lower()
        if role not in _ROLES or login == pull.author or state not in _DECISIVE:
            continue
        # An approval of an earlier commit approves what was not merged: it never counts. A
        # request for changes or a dismissal withdraws an approval, whatever it reviewed.
        approves[login] = state == "APPROVED" and review["commit_id"] == pull.head
    return tuple(sorted(login for login, approved in approves.items() if approved))


def merged_pull_request(pulls: object, commit: str, repository: str) -> MergedPullRequest | None:
    """The pull request merged as ``commit`` into the default branch of ``repository``, among
    the pull requests GitHub associates with it; none when no pull request was."""
    if not isinstance(pulls, list):
        raise _malformed("pull requests", "a list is needed")
    merged = []
    for pull in pulls:
        number, head = _field(pull, "number"), _field(pull, "head", "sha")
        author = _field(pull, "user", "login")
        base, name = _field(pull, "base", "ref"), _field(pull, "base", "repo", "full_name")
        default = _field(pull, "base", "repo", "default_branch")
        if not isinstance(pull, dict) or not pull.keys() >= _PULL:
            raise _malformed("pull requests", "one without its number, merge, head, author or base")
        if type(number) is not int or number < 1:
            raise _malformed("pull requests", "one without its number")
        if not all(isinstance(value, str) for value in (head, author, base, name, default)):
            raise _malformed("pull requests", f"#{number} without its head, author or base")
        into_default = name == repository and base == default
        if pull["merge_commit_sha"] == commit and pull["merged_at"] is not None and into_default:
            merged.append(MergedPullRequest(number, head, author.lower()))
    if len(merged) > 1:
        raise _malformed("pull requests", f"several were merged as {commit}")
    return merged[0] if merged else None
