"""A commit ID is a commit in full, never anything git would read otherwise."""

import pytest

from scenario_tools.domain.shared.commits import is_commit_id


@pytest.mark.parametrize("value", ["a" * 40, "0123456789abcdef" * 4])
def test_a_full_commit_id_is_one(value: str) -> None:
    assert is_commit_id(value)


@pytest.mark.parametrize(
    "value", ["A" * 40, "a" * 39, "a" * 41, "a" * 63, "HEAD", "--all", "a" * 40 + "\n", None, 1]
)
def test_anything_else_is_no_commit_id(value: object) -> None:
    assert not is_commit_id(value)
