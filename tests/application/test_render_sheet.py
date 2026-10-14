"""Render an entry's sheet, and check the README.md it holds."""

from scenario_tools.application.render_sheet import check_sheet, sheet_of
from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.sheet.sheet import render_sheet
from scenario_tools.ports.errors import UnsafeInputError
from tests.application.test_validate_entry import (
    ENTRY,
    JSON,
    METADATA,
    README,
    SCENARIO,
    YAML,
    FakeSource,
)


def test_the_sheet_of_an_entry_is_rendered_from_its_files() -> None:
    sheet = sheet_of(ENTRY, FakeSource({YAML: METADATA, JSON: SCENARIO}), ())

    assert (sheet.text, sheet.refusals) == (render_sheet(METADATA, SCENARIO, ()), ())


def test_an_entry_that_cannot_be_read_has_no_sheet() -> None:
    for files in ({JSON: SCENARIO}, {YAML: ["x"], JSON: SCENARIO}, {YAML: METADATA}):
        (refusal,) = sheet_of(ENTRY, FakeSource(files), ()).refusals
        assert (refusal.code, refusal.severity, refusal.path) == (
            "GEN-001",
            Severity.BLOCKING,
            YAML,
        )
        assert refusal.message.startswith("the sheet cannot be rendered")

    refused = UnsafeInputError("IO-013", "a link", JSON)
    (refusal,) = sheet_of(ENTRY, FakeSource({YAML: METADATA, JSON: refused}), ()).refusals
    assert (refusal.code, refusal.path, refusal.message) == ("IO-013", JSON, "a link")


def test_the_check_says_whether_the_readme_is_the_sheet() -> None:
    assert check_sheet(ENTRY, FakeSource({YAML: METADATA, JSON: SCENARIO}), ()) == ()

    (missing,) = check_sheet(ENTRY, FakeSource({YAML: METADATA, JSON: SCENARIO, README: None}), ())
    (stale,) = check_sheet(ENTRY, FakeSource({YAML: METADATA, JSON: SCENARIO, README: "x"}), ())

    assert (missing.code, missing.path, stale.code, stale.path) == (
        "GEN-001",
        README,
        "GEN-001",
        README,
    )
    assert missing.message.startswith("README.md is missing")
    assert stale.message.startswith("README.md is not the sheet")


def test_the_check_of_an_entry_that_cannot_be_read_says_why() -> None:
    (refusal,) = check_sheet(ENTRY, FakeSource({JSON: SCENARIO}), ())

    assert refusal.message.startswith("the sheet cannot be rendered")


def test_a_readme_the_readers_refuse_is_left_to_the_check_of_the_texts() -> None:
    refused = UnsafeInputError("IO-013", "a link", README)

    assert (
        check_sheet(ENTRY, FakeSource({YAML: METADATA, JSON: SCENARIO, README: refused}), ()) == ()
    )
