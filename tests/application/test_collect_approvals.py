"""The approvals of every entry, collected from the history and from GitHub."""

from typing import Any

import pytest

from scenario_tools.application.collect_approvals import collect_approvals
from scenario_tools.domain.release.manifest import Approval, Approvals
from scenario_tools.ports.errors import EnvironmentProblemError

A, B, HEAD = "a" * 40, "b" * 40, "c" * 40
REPOSITORY = "OpenAEV-Platform/scenarios"
COMMITS = {"scenarios/x/one": A, "scenarios/x/two": A, "scenarios/x/three": B}


def _pull(number: int, commit: str) -> dict[str, Any]:
    return {
        "number": number,
        "merge_commit_sha": commit,
        "merged_at": "2026-10-01T00:00:00Z",
        "head": {"sha": HEAD},
        "user": {"login": "author"},
        "base": {"ref": "main", "repo": {"full_name": REPOSITORY, "default_branch": "main"}},
    }


PULLS = {A: [_pull(12, A)], B: [_pull(13, B)]}
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

    found = collect_approvals(
        sorted(COMMITS),
        commit=HEAD,
        repository=REPOSITORY,
        last_commit=COMMITS.__getitem__,
        pulls_of=pulls_of,
        reviews_of=reviews_of,
    )
    return found, asked


def test_each_entry_takes_the_pull_request_of_its_last_commit_and_its_approvers() -> None:
    found, asked = _collect()

    assert found == Approvals(
        HEAD,
        {
            "scenarios/x/one": Approval(12, ("alice",)),
            "scenarios/x/three": Approval(13, ()),
            "scenarios/x/two": Approval(12, ("alice",)),
        },
    )
    assert sorted(map(str, asked)) == sorted(map(str, [A, B, 12, 13]))  # each asked once


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
        ({A: [{"number": 12}], B: PULLS[B]}, REVIEWS, "pull requests: "),
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
            pulls_of=PULLS.__getitem__,
            reviews_of=REVIEWS.__getitem__,
        )
