"""The package exposes a semantic version."""

import re

import scenario_tools


def test_version_is_semantic() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", scenario_tools.__version__)
