"""What every command gives on the reference corpus stays the same, byte for byte.

Each case runs one command in a workspace of its own, with the clock, the time zone and the
locale fixed, and compares its output, its error output, its exit code and the files it wrote
with the snapshot in ``tests/snapshots/expected/``. A difference is a change of behaviour: the
snapshots are regenerated only for a change meant to happen (``tests/snapshots/regenerate.py``),
never to make a refactoring pass.
"""

from pathlib import Path

import pytest

from tests.snapshots.cases import CASES, EXPECTED, Case, expected, run


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_a_command_gives_what_its_snapshot_holds(case: Case, tmp_path: Path) -> None:
    given = run(case, tmp_path)
    recorded = expected(case)

    assert sorted(given.keys() - recorded.keys()) == [], f"{case.name}: written, not recorded"
    assert sorted(recorded.keys() - given.keys()) == [], f"{case.name}: recorded, not written"
    for path, data in recorded.items():
        assert given[path] == data, f"{case.name}: {path}"


def test_every_snapshot_belongs_to_a_case() -> None:
    names = {case.name for case in CASES}
    assert {path.name for path in EXPECTED.iterdir()} <= names
