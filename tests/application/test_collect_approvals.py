"""The approvals of every entry, collected from the history and from GitHub."""

from typing import Any

import pytest

from scenario_tools.application.collect_approvals import collect_approvals
from scenario_tools.domain.release.manifest import Approval, Approvals
from scenario_tools.ports.errors import EnvironmentProblemError

A, B, HEAD = "a" * 40, "b" * 40, "c" * 40
F1, F2 = "d" * 40, "e" * 40  # the commits that brought the first versions
REPOSITORY = "OpenAEV-Platform/scenarios"
COMMITS = {"scenarios/x/one": A, "scenarios/x/two": A, "scenarios/x/three": B}
FIRST = {"scenarios/x/one": F1, "scenarios/x/two": F2, "scenarios/x/three": B}
MEMBERS = {"author": True, "staff": True, "jdoe": False}


def _pull(number: int, commit: str, author: str = "author") -> dict[str, Any]:
    return {
        "number": number,
        "merge_commit_sha": commit,
        "merged_at": "2026-10-01T00:00:00Z",
        "head": {"sha": HEAD},
        "user": {"login": author},
        "base": {"ref": "main", "repo": {"full_name": REPOSITORY, "default_branch": "main"}},
    }


PULLS = {
    A: [_pull(12, A)],
    B: [_pull(13, B)],
    F1: [_pull(3, F1, "JDoe")],
    F2: [_pull(4, F2, "Staff")],
}
REVIEW = {
    "user": {"login": "Alice", "type": "User"},
    "state": "APPROVED",
    "commit_id": HEAD,
    "author_association": "MEMBER",
}
REVIEWS = {12: [REVIEW], 13: []}


def _collect(pulls: dict[str, Any] = PULLS, reviews: dict[int, Any] = REVIEWS) -> Any:
    asked: list[object] = []

    def pulls_of(commit: str) -> Any:
        asked.append(commit)
        return pulls[commit]

    def reviews_of(number: int) -> Any:
        asked.append(number)
        return reviews[number]

    def is_member(login: str) -> bool:
        asked.append(login)
        return MEMBERS[login]

    found = collect_approvals(
        sorted(COMMITS),
        commit=HEAD,
        repository=REPOSITORY,
        last_commit=COMMITS.__getitem__,
        first_commit=FIRST.__getitem__,
        pulls_of=pulls_of,
        reviews_of=reviews_of,
        is_member=is_member,
    )
    return found, asked


def test_each_entry_takes_its_approvals_from_its_last_change_and_its_origin_from_its_first() -> (
    None
):
    found, asked = _collect()

    assert found == Approvals(
        HEAD,
        {
            "scenarios/x/one": Approval(12, ("alice",), "community", "jdoe"),
            "scenarios/x/three": Approval(13, (), "filigran", None),
            "scenarios/x/two": Approval(12, ("alice",), "filigran", None),
        },
    )
    # Each commit, pull request and author asked once.
    assert sorted(map(str, asked)) == sorted(
        map(str, [A, B, F1, F2, 12, 13, "author", "jdoe", "staff"])
    )


def test_an_entry_whose_first_commit_no_pull_request_merged_is_said() -> None:
    with pytest.raises(EnvironmentProblemError) as error:
        _collect(pulls={**PULLS, F1: []})

    assert str(error.value) == (
        f"the first commit that changed scenarios/x/one, {F1}, was merged into the default "
        "branch by no pull request: its origin cannot be told"
    )


def test_an_entry_whose_last_commit_no_pull_request_merged_is_said() -> None:
    with pytest.raises(EnvironmentProblemError) as error:
        _collect(pulls={A: [], B: PULLS[B]})

    assert str(error.value) == (
        f"the last commit that changed scenarios/x/one, {A}, was merged into the default "
        "branch by no pull request: a change of the catalogue goes through a reviewed, "
        "squash-merged pull request"
    )


@pytest.mark.parametrize(
    ("pulls", "reviews", "said"),
    [
        (PULLS, {12: [{"state": "APPROVED"}], 13: []}, "reviews: "),
        ({**PULLS, A: [{"number": 12}]}, REVIEWS, "pull requests: "),
    ],
)
def test_what_github_gives_out_of_its_shape_is_the_environment_s_fault(
    pulls: dict[str, Any], reviews: dict[int, Any], said: str
) -> None:
    with pytest.raises(EnvironmentProblemError, match=f"GitHub's answer cannot be used: {said}"):
        _collect(pulls, reviews)


def test_a_failure_of_a_callback_is_never_taken_for_github_s_answer() -> None:
    def broken(commit: str) -> Any:
        raise ValueError("a defect")

    with pytest.raises(ValueError, match=r"^a defect$"):
        collect_approvals(
            ["scenarios/x/one"],
            commit=HEAD,
            repository=REPOSITORY,
            last_commit=broken,
            first_commit=FIRST.__getitem__,
            pulls_of=PULLS.__getitem__,
            reviews_of=REVIEWS.__getitem__,
            is_member=MEMBERS.__getitem__,
        )
