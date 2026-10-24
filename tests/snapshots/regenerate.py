"""Write the snapshots of every case, after a deliberate change of what the tools give.

A refactoring never runs this: its snapshots stay as they are, and a difference is a change of
behaviour to look at. Run from the repository root, then review every difference before
committing:

    uv run python -m tests.snapshots.regenerate [CASE ...]
"""

import shutil
import sys
import tempfile
from pathlib import Path

from tests.snapshots.cases import CASES, EXPECTED, run


def main(names: list[str]) -> None:
    unknown = sorted(set(names) - {case.name for case in CASES})
    if unknown:
        sys.exit(f"no such case: {', '.join(unknown)}")
    chosen = [case for case in CASES if not names or case.name in names]
    for case in chosen:
        with tempfile.TemporaryDirectory() as base:
            given = run(case, Path(base) / "first")
            if run(case, Path(base) / "second") != given:
                sys.exit(f"{case.name}: two runs differ, nothing written")
            written = Path(base) / "snapshot"
            for path, data in given.items():
                target = written / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            directory = EXPECTED / case.name
            shutil.rmtree(directory, ignore_errors=True)
            shutil.copytree(written, directory)
        print(f"{case.name}: {len(given)} files")


if __name__ == "__main__":
    main(sys.argv[1:])
