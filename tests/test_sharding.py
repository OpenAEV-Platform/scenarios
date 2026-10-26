"""The shares of the tests, for the CI's parallel jobs: every test in exactly one share, the same
share from run to run, and shares of about the same size."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.support.sharding import parse_share, share_of

ROOT = Path(__file__).parents[1]
IDS = [f"tests/test_x.py::test_case[{n}]" for n in range(6000)]
# Shares computed once and pinned: a change of the hash would move every test.
HYGIENE_SHARE = 4
CASE_SHARE = 3


@pytest.mark.parametrize("count", [1, 2, 4, 6])
def test_every_test_is_in_exactly_one_share(count: int) -> None:
    shares = [share_of(test, count) for test in IDS]

    assert set(shares) == set(range(1, count + 1))


def test_a_test_stays_in_its_share_from_run_to_run() -> None:
    """The share is a stable hash of the test's ID, never Python's own, which changes per run."""
    assert share_of("tests/test_hygiene.py::test_no_repository_file_refers_to_the_planning", 4) == (
        HYGIENE_SHARE
    )
    assert share_of("tests/test_x.py::test_case[0]", 4) == CASE_SHARE


def test_the_shares_are_of_about_the_same_size() -> None:
    sizes = [sum(share_of(test, 4) == share for test in IDS) for share in range(1, 5)]

    assert max(sizes) - min(sizes) < len(IDS) // 4 // 10  # within a tenth of a share


@pytest.mark.parametrize(("text", "share"), [("1/1", (1, 1)), ("2/4", (2, 4)), ("4/4", (4, 4))])
def test_a_share_is_read_as_index_over_count(text: str, share: tuple[int, int]) -> None:
    assert parse_share(text) == share


@pytest.mark.parametrize("text", ["", "4", "0/4", "5/4", "1/0", "a/b", "1/4/2", " 1/4", "-1/4"])
def test_a_share_out_of_its_shape_is_refused(text: str) -> None:
    with pytest.raises(ValueError, match="SCENARIOS_TEST_SHARD"):
        parse_share(text)


def _collected(share: str | None) -> set[str]:
    env = {k: v for k, v in os.environ.items() if k != "SCENARIOS_TEST_SHARD"}
    if share is not None:
        env["SCENARIOS_TEST_SHARD"] = share
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            "tests/test_sharding.py",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return {line for line in done.stdout.splitlines() if "::" in line}


def test_the_shares_of_a_run_partition_its_tests() -> None:
    whole = _collected(None)
    shares = [_collected(f"{index}/3") for index in (1, 2, 3)]

    assert set().union(*shares) == whole
    assert sum(len(share) for share in shares) == len(whole)
