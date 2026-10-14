"""Diff an entry: what changed since the version the base branch holds, read like `validate`
reads it, a moved entry found by its external ID."""

import copy

from scenario_tools.application.diff_entry import diff_entry
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import UnsafeInputError
from tests.application.test_validate_entry import (
    ENTRY,
    JSON,
    METADATA,
    SCENARIO,
    YAML,
    FakePrevious,
    FakeSource,
)


def _diff(files: dict[str, object], previous: dict[str, object]) -> tuple[Finding, ...]:
    return diff_entry(ENTRY, FakeSource(files), FakePrevious(previous))  # type: ignore[arg-type]


def _codes(found: tuple[Finding, ...]) -> list[tuple[str, Severity, str, str]]:
    return [(f.code, f.severity, f.path, f.field) for f in found]


def test_an_entry_is_compared_with_its_copy_on_the_base_branch() -> None:
    changed = {**copy.deepcopy(METADATA), "description": "Another crisis exercise."}

    found = _diff({YAML: changed, JSON: SCENARIO}, {YAML: METADATA, JSON: SCENARIO})

    assert _codes(found) == [
        ("VER-014", Severity.INFO, ENTRY, ""),
        ("VER-013", Severity.INFO, YAML, "/description"),
    ]
    assert found[0].message.startswith("these changes need 1.0.1 at least, a patch version")


def test_a_moved_entry_is_compared_with_its_copy_where_it_was() -> None:
    old = "scenarios/ransomware/akira-old"
    changed = {**copy.deepcopy(METADATA), "description": "Another crisis exercise."}

    found = _diff(
        {YAML: changed, JSON: SCENARIO},
        {f"{old}/scenario.yaml": METADATA, f"{old}/scenario.json": SCENARIO},
    )

    assert [f.code for f in found] == ["VER-014", "VER-013"]


def test_an_entry_the_base_branch_does_not_hold_is_new() -> None:
    (found,) = _diff({YAML: METADATA, JSON: SCENARIO}, {})

    assert (found.code, found.message) == (
        "VER-014",
        "a new entry: the base branch holds no previous version to compare with",
    )


def test_an_entry_that_cannot_be_read_says_so_and_validate_says_why() -> None:
    refused = UnsafeInputError("IO-013", "a link", YAML)

    cases: list[dict[str, object]] = [
        {JSON: SCENARIO},
        {YAML: ["x"], JSON: SCENARIO},
        {YAML: METADATA},
    ]
    for files in cases:
        (found,) = _diff(files, {YAML: METADATA, JSON: SCENARIO})
        assert (found.code, found.severity, found.path, found.field, found.message) == (
            "VER-014",
            Severity.INFO,
            ENTRY,
            "",
            "this entry cannot be compared: its scenario.yaml or its scenario.json is missing or "
            "is not an object; validate says why",
        )

    (found,) = _diff({YAML: refused, JSON: SCENARIO}, {YAML: METADATA, JSON: SCENARIO})
    assert (found.code, found.severity, found.path) == ("IO-013", Severity.BLOCKING, YAML)


def test_a_base_copy_that_cannot_be_read_is_a_finding() -> None:
    refused = UnsafeInputError("IO-013", "a link", YAML)

    (found,) = _diff({YAML: METADATA, JSON: SCENARIO}, {YAML: refused, JSON: SCENARIO})

    assert (found.code, found.severity, found.path, found.message) == (
        "IO-013",
        Severity.BLOCKING,
        YAML,
        "the base branch's copy of this file cannot be read: a link",
    )


def test_an_entry_whose_name_no_finding_could_show_is_not_read() -> None:
    assert diff_entry("../outside", FakeSource({}), FakePrevious({})) == ()  # type: ignore[arg-type]


def test_an_entry_whose_files_cannot_be_listed_is_a_finding() -> None:
    class Unlisted(FakeSource):
        def names(self, entry: str) -> frozenset[str]:
            raise UnsafeInputError("IO-013", "a symbolic link", entry)

    (found,) = diff_entry(ENTRY, Unlisted({}), FakePrevious({}))  # type: ignore[arg-type]

    assert (found.code, found.path) == ("IO-013", ENTRY)


def test_nothing_changed_is_said() -> None:
    found = _diff({YAML: METADATA, JSON: SCENARIO}, {YAML: METADATA, JSON: SCENARIO})

    assert [(f.code, f.message) for f in found] == [
        ("VER-014", "nothing changed that needs a new version")
    ]
