"""The package exposes a semantic version."""

import hashlib
import re
import tomllib
from pathlib import Path

import scenario_tools


def test_version_is_semantic() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", scenario_tools.__version__)


def test_the_repository_is_under_the_apache_licence_2_0() -> None:
    root = Path(__file__).parents[1]
    notice, _, text = (root / "LICENSE").read_text(encoding="utf-8").partition("\n\n")

    assert notice == "Copyright (c) 2026 Filigran SAS"
    # The text published at https://www.apache.org/licenses/LICENSE-2.0.txt, unchanged.
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert digest == "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["license"] == "Apache-2.0"
