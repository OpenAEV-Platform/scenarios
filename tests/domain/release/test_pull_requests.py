"""Who approved a pull request, and which pull request brought a commit, from what GitHub says."""

from typing import Any

import pytest

from scenario_tools.domain.release.pull_requests import (
    MergedPullRequest,
    approvers_from_reviews,
    merged_pull_request,
)

COMMIT = "a" * 40
HEAD = "c" * 40
REPOSITORY = "OpenAEV-Platform/scenarios"
PULL = MergedPullRequest(9, HEAD, "author")


def _review(
    login: str,
    state: str,
    *,
    kind: str = "User",
    commit: str | None = HEAD,
    association: str = "MEMBER",
) -> dict[str, Any]:
    return {
        "user": {"login": login, "type": kind},
        "state": state,
        "commit_id": commit,
        "author_association": association,
    }


def _pull(number: object = 9, **changes: Any) -> dict[str, Any]:
    pull: dict[str, Any] = {
        "number": number,
        "merge_commit_sha": COMMIT,
        "merged_at": "2026-10-02T00:00:00Z",
        "head": {"sha": HEAD},
        "user": {"login": "Author"},
        "base": {"ref": "main", "repo": {"full_name": REPOSITORY, "default_branch": "main"}},
    }
    pull.update(changes)
    return pull


def test_an_approver_is_one_whose_last_decisive_review_of_the_merged_head_approves() -> None:
    reviews = [
        _review("Alice", "APPROVED"),
        _review("bob", "APPROVED"),
        _review("bob", "CHANGES_REQUESTED"),  # then asked for changes: no longer approves
        _review("carol", "CHANGES_REQUESTED"),
        _review("carol", "APPROVED"),
        _review("carol", "COMMENTED"),  # a comment decides nothing
        _review("dave", "APPROVED"),
        _review("dave", "DISMISSED"),
        _review("erin", "COMMENTED"),
        _review("erin", "PENDING"),
        _review("frank", "DISMISSED"),
        _review("frank", "APPROVED"),  # approved again
    ]

    assert approvers_from_reviews(reviews, PULL) == ("alice", "carol", "frank")


def test_a_request_for_changes_submitted_after_an_approval_withdraws_it_whatever_it_reviewed() -> (
    None
):
    """Begun on an earlier commit and submitted after a push, it is still the last word."""
    reviews = [
        _review("alice", "APPROVED"),
        _review("alice", "CHANGES_REQUESTED", commit="b" * 40),
        _review("bob", "APPROVED"),
        _review("bob", "DISMISSED", commit="b" * 40),
    ]

    assert approvers_from_reviews(reviews, PULL) == ()


def test_an_approval_of_an_earlier_head_no_longer_counts() -> None:
    """What was approved is not what was merged: a push since leaves it out."""
    reviews = [_review("alice", "APPROVED", commit="b" * 40), _review("bob", "APPROVED")]

    assert approvers_from_reviews(reviews, PULL) == ("bob",)


@pytest.mark.parametrize("association", ["CONTRIBUTOR", "FIRST_TIMER", "NONE", "MANNEQUIN"])
def test_only_one_with_a_role_in_the_repository_approves(association: str) -> None:
    reviews = [_review("alice", "APPROVED", association=association)]

    assert approvers_from_reviews(reviews, PULL) == ()


@pytest.mark.parametrize("association", ["OWNER", "MEMBER", "COLLABORATOR"])
def test_an_owner_a_member_or_a_collaborator_approves(association: str) -> None:
    reviews = [_review("alice", "APPROVED", association=association)]

    assert approvers_from_reviews(reviews, PULL) == ("alice",)


def test_neither_a_bot_nor_the_pull_request_s_author_approves() -> None:
    reviews = [
        _review("copilot-pull-request-reviewer[bot]", "APPROVED", kind="Bot"),
        _review("robot", "APPROVED", kind="Bot"),
        _review("Author", "APPROVED"),
    ]

    assert approvers_from_reviews(reviews, PULL) == ()


@pytest.mark.parametrize(
    "reviews",
    [
        {},
        [[]],
        [{"state": "APPROVED"}],
        [{**_review("a", "APPROVED"), "user": None}],
        [{**_review("a", "APPROVED"), "user": {"login": "a"}}],
        [{**_review("a", "APPROVED"), "user": {"login": 1, "type": "User"}}],
        [_review("a b", "APPROVED")],
        [_review("a" * 40, "APPROVED")],
        [_review("a_b", "APPROVED")],
        [{**_review("a", "APPROVED"), "state": 1}],
        [{key: value for key, value in _review("a", "APPROVED").items() if key != "commit_id"}],
        [{**_review("a", "APPROVED"), "author_association": None}],
    ],
)
def test_reviews_out_of_their_shape_are_refused(reviews: Any) -> None:
    with pytest.raises(ValueError, match="reviews: "):
        approvers_from_reviews(reviews, PULL)


def test_a_commit_is_brought_by_the_pull_request_merged_as_it_into_the_default_branch() -> None:
    pulls = [
        _pull(7, merge_commit_sha="b" * 40),
        _pull(8, merged_at=None),  # closed, not merged
        _pull(9),
    ]

    assert merged_pull_request(pulls, COMMIT, REPOSITORY) == MergedPullRequest(9, HEAD, "author")


@pytest.mark.parametrize(
    "pull",
    [
        _pull(merged_at=None),
        _pull(merge_commit_sha="b" * 40),
        _pull(base={"ref": "feature", "repo": {"full_name": REPOSITORY, "default_branch": "main"}}),
        _pull(
            base={"ref": "main", "repo": {"full_name": "someone/fork", "default_branch": "main"}}
        ),
    ],
    ids=["not merged", "another commit", "another branch", "another repository"],
)
def test_a_commit_no_pull_request_merged_into_the_default_branch_has_none(pull: Any) -> None:
    assert merged_pull_request([pull], COMMIT, REPOSITORY) is None
    assert merged_pull_request([], COMMIT, REPOSITORY) is None


@pytest.mark.parametrize(
    "pulls",
    [
        {},
        [1],
        [_pull(number="9")],
        [_pull(number=0)],
        [_pull(number=True)],
        [{key: value for key, value in _pull().items() if key != "merged_at"}],
        [{key: value for key, value in _pull().items() if key != "merge_commit_sha"}],
        [_pull(head=None)],
        [_pull(head={"sha": 1})],
        [_pull(user={"login": None})],
        [_pull(user=None)],  # a deleted account
        [_pull(base={"ref": "main"})],
        [_pull(9), _pull(10)],
    ],
)
def test_pull_requests_out_of_their_shape_are_refused(pulls: Any) -> None:
    with pytest.raises(ValueError, match="pull requests: "):
        merged_pull_request(pulls, COMMIT, REPOSITORY)


def test_a_review_of_a_deleted_account_names_the_pull_request() -> None:
    reviews = [{**_review("a", "APPROVED"), "user": None}]

    with pytest.raises(ValueError, match="#9 without its reviewer"):
        approvers_from_reviews(reviews, PULL)


def test_a_bot_s_review_is_passed_over_never_the_reviews_after_it() -> None:
    reviews = [_review("robot", "APPROVED", kind="Bot"), _review("alice", "APPROVED")]

    assert approvers_from_reviews(reviews, PULL) == ("alice",)


def test_the_first_pull_request_of_a_repository_is_one() -> None:
    assert merged_pull_request([_pull(1)], COMMIT, REPOSITORY) == MergedPullRequest(
        1, HEAD, "author"
    )


@pytest.mark.parametrize(
    ("reviews", "why"),
    [
        ({}, "a list is needed"),
        ([{**_review("a", "APPROVED"), "user": None}],
         "one of #9 without its reviewer, its state or its role"),
        ([{k: v for k, v in _review("a", "APPROVED").items() if k != "commit_id"}],
         "one of #9 without the commit it reviewed"),
        ([_review("a b", "APPROVED")], "one of #9 without its reviewer's login"),
    ],
)  # fmt: skip
def test_reviews_out_of_their_shape_say_why(reviews: Any, why: str) -> None:
    with pytest.raises(ValueError, match="reviews: ") as error:
        approvers_from_reviews(reviews, PULL)

    assert str(error.value) == f"reviews: not as GitHub gives them: {why}"


@pytest.mark.parametrize(
    ("pulls", "why"),
    [
        ({}, "a list is needed"),
        ([{k: v for k, v in _pull().items() if k != "merged_at"}],
         "one without its number, merge, head, author or base"),
        ([_pull(number=0)], "one without its number"),
        ([_pull(head={"sha": 1})], "#9 without its head, author or base"),
        ([_pull(9), _pull(10)], f"several were merged as {COMMIT}"),
    ],
)  # fmt: skip
def test_pull_requests_out_of_their_shape_say_why(pulls: Any, why: str) -> None:
    with pytest.raises(ValueError, match="pull requests: ") as error:
        merged_pull_request(pulls, COMMIT, REPOSITORY)

    assert str(error.value) == f"pull requests: not as GitHub gives them: {why}"
