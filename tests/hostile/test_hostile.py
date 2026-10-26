"""Every input of the hostile corpus is refused as its case says, within its budget of time and of
memory, and never as an internal error.

Each case replays an input built to break the tools in a way they were once found open to; a
refusal that becomes an internal error, a traceback, a slower run or a larger one fails here.
"""

import json
from pathlib import Path

import pytest

from tests.hostile.corpus import CASES, INPUTS, Case, renamed_entry, run


def _document(output: str) -> dict[str, object]:
    """The JSON document a command wrote: its one line that is a JSON object."""
    found = [line for line in output.splitlines() if line.startswith("{")]
    assert len(found) == 1, output
    document = json.loads(found[0])
    assert isinstance(document, dict)
    return document


@pytest.mark.timing
@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_a_hostile_input_is_refused_within_its_budget(case: Case, tmp_path: Path) -> None:
    outcome = run(case, tmp_path / "workspace")

    assert outcome.exit_code == case.exit_code, outcome.output
    assert "Traceback" not in outcome.output
    if case.code is None:  # said as the environment's fault, and why
        assert "environment error: " in outcome.output, outcome.output
    else:
        document = _document(outcome.output)
        assert document["ok"] is False
        findings = document["findings"]
        assert isinstance(findings, list)
        assert case.code in [finding["code"] for finding in findings], outcome.output
    assert outcome.seconds <= case.seconds, f"{outcome.seconds:.2f} s"
    assert outcome.mebibytes <= case.mebibytes, f"{outcome.mebibytes:.0f} MiB"


def test_every_case_has_a_name_of_its_own() -> None:
    names = [case.name for case in CASES]
    assert len(set(names)) == len(names)


def test_the_versioned_inputs_are_those_the_cases_read() -> None:
    assert sorted(path.name for path in INPUTS.iterdir()) == ["renamed-entry.zip", "tags.yaml"]


def test_the_renamed_entry_is_what_its_builder_gives() -> None:
    # The builder documents the archive, byte for byte; the file is what the case reads.
    assert (INPUTS / "renamed-entry.zip").read_bytes() == renamed_entry()
