"""Settings every test shares."""

import os

import pytest
from hypothesis import settings

from tests.support.sharding import parse_share, share_of

# A property test judges what holds, never how fast: the default deadline of 200 ms fails a test
# whose property holds when the machine is busy. The tests that bound a running time are marked
# `timing` and run alone (see the Makefile).
settings.register_profile("repository", deadline=None)
# For make check-fast only, never a gate: fewer examples, a quicker loop while working.
settings.register_profile("fast", deadline=None, max_examples=10)
settings.load_profile(os.environ.get("SCENARIOS_HYPOTHESIS_PROFILE", "repository"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Under ``SCENARIOS_TEST_SHARD=index/count``, as each of the CI's test jobs runs, only the
    tests of that share: every test is in exactly one share, by a stable hash of its ID."""
    text = os.environ.get("SCENARIOS_TEST_SHARD")
    if text is None:
        return
    index, count = parse_share(text)
    kept: list[pytest.Item] = []
    left: list[pytest.Item] = []
    for item in items:
        (kept if share_of(item.nodeid, count) == index else left).append(item)
    config.hook.pytest_deselected(items=left)
    items[:] = kept
