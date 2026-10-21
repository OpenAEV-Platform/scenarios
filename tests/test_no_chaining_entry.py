"""No scenario of the catalogue is in chaining yet.

A merge to the default branch is published on the edge channel. A scenario in chaining cannot be
merged until its import has been checked on a test instance: the platform's importer must keep
the dependencies between its steps and check a payload it already holds. The pull request that
adds the first scenario in chaining, once that check is done, removes this test.
"""

import json
from pathlib import Path

from scenario_tools.domain.shared.workflow import has_workflow

ROOT = Path(__file__).resolve().parents[1]


def test_no_stored_scenario_has_a_workflow() -> None:
    chaining = [
        str(path.relative_to(ROOT))
        for path in sorted((ROOT / "scenarios").glob("**/scenario.json"))
        if has_workflow(json.loads(path.read_text(encoding="utf-8")))
    ]
    assert chaining == [], (
        "a scenario in chaining cannot be merged until its import has been checked on a test "
        "instance; the pull request that adds the first one removes this test"
    )
