"""The semantic diff of an entry: each change where it is, the file and the pointer of what changed
in the entry as it is, and the identifier of the inject or item it concerns, with the version it
needs; first, the least version the changes need. Never a value of the entry."""

import copy
from typing import Any

import pytest

from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.entry_changes import (
    Bump,
    Change,
    LocatedChange,
    changes,
    located_changes,
)
from scenario_tools.domain.verification.versioning import diff_findings
from tests.domain.verification.test_versioning import CONTRACT, METADATA, STORED, inject

ENTRY = "scenarios/techniques/x"
YAML, JSON = f"{ENTRY}/scenario.yaml", f"{ENTRY}/scenario.json"


def stored(**parts: Any) -> dict[str, Any]:
    return {**copy.deepcopy(STORED), **parts}


def located(
    metadata: dict[str, Any] | None = None, after: dict[str, Any] | None = None
) -> list[tuple[Bump, str, str, str, str]]:
    return [
        (c.change.bump, c.change.reason, c.file, c.field, c.item)
        for c in located_changes(METADATA, STORED, metadata or METADATA, after or STORED)
    ]


# Where each change is


def test_a_metadata_change_is_its_field_of_scenario_yaml() -> None:
    assert located({**METADATA, "name": "Y", "requires": {}}) == [  # in the order of the keys
        (Bump.PATCH, "its name changed", "scenario.yaml", "/name", ""),
        (Bump.MAJOR, "its requirements changed", "scenario.yaml", "/requires", ""),
    ]


def test_a_key_is_escaped_in_its_pointer() -> None:
    assert located({**METADATA, "a/b~c": 1}) == [
        (Bump.MAJOR, "its a/b~c changed", "scenario.yaml", "/a~1b~0c", "")
    ]


def test_an_inject_added_is_where_it_is_and_one_removed_is_named() -> None:
    after = stored(scenario_injects=[inject("c"), inject("a")])

    assert located(after=after) == [
        (Bump.MAJOR, "an inject removed", "scenario.json", "/scenario_injects", "b"),
        (Bump.MINOR, "an inject added", "scenario.json", "/scenario_injects/0", "c"),
    ]


def test_several_injects_added_and_removed_are_each_a_change() -> None:
    after = stored(scenario_injects=[inject("c"), inject("d")])

    assert [(field, item) for _, _, _, field, item in located(after=after)] == [
        ("/scenario_injects", "a"),
        ("/scenario_injects", "b"),
        ("/scenario_injects/0", "c"),
        ("/scenario_injects/1", "d"),
    ]


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        (
            {"inject_title": "T"},
            [(Bump.PATCH, "an inject's text changed", "/scenario_injects/1/inject_title")],
        ),
        (
            {"inject_depends_on": ["x"]},
            [
                (
                    Bump.MAJOR,
                    "an inject's place in the chain changed",
                    "/scenario_injects/1/inject_depends_on",
                )
            ],
        ),
        (
            {"inject_content": {"targets": ["x"], "template": "t"}},
            [
                (Bump.MAJOR, "an inject's targets changed", "/scenario_injects/1/inject_content"),
                (Bump.MINOR, "an inject's content changed", "/scenario_injects/1/inject_content"),
            ],
        ),
        (
            {"inject_injector_contract": {"injector_contract_id": "other"}},
            [
                (
                    Bump.MAJOR,
                    "an inject's contract changed",
                    "/scenario_injects/1/inject_injector_contract/injector_contract_id",
                )
            ],
        ),
        (
            {
                "inject_injector_contract": {
                    "injector_contract_id": CONTRACT,
                    "injector_contract_payload": {"p": 1},
                    "x": 1,
                }
            },
            [
                (
                    Bump.MINOR,
                    "an inject's payload changed",
                    "/scenario_injects/1/inject_injector_contract/injector_contract_payload",
                ),
                (
                    Bump.MAJOR,
                    "an inject's contract changed",
                    "/scenario_injects/1/inject_injector_contract",
                ),
            ],
        ),
        (
            {"inject_injector_contract": "x"},
            [
                (
                    Bump.MAJOR,
                    "an inject's contract changed",
                    "/scenario_injects/1/inject_injector_contract",
                )
            ],
        ),
        (
            {"inject_new": 1},
            [(Bump.MAJOR, "an inject's inject_new changed", "/scenario_injects/1/inject_new")],
        ),
    ],
)
def test_an_inject_change_is_its_field_where_the_inject_now_is(
    fields: dict[str, Any], expected: list[tuple[Bump, str, str]]
) -> None:
    """The inject is found by its ID, at its place in the list as it is now."""
    after = stored(
        scenario_injects=[inject("z"), inject("b", **{"inject_depends_on": ["a"], **fields})]
    )
    before = stored(scenario_injects=[inject("b", inject_depends_on=["a"]), inject("z")])

    located_found = located_changes(METADATA, before, METADATA, after)
    found = [(c.change.bump, c.change.reason, c.field) for c in located_found]

    assert found == expected
    assert {(c.file, c.item) for c in located_found} == {("scenario.json", "b")}  # by its ID


@pytest.mark.parametrize(
    ("part", "value", "expected"),
    [
        (
            "scenario_injects",
            "x",
            [(Bump.MAJOR, "its scenario_injects changed", "/scenario_injects", "")],
        ),
        (
            "scenario_information",
            {"scenario_name": "Y", "scenario_id": "s"},
            [(Bump.PATCH, "its scenario_name changed", "/scenario_information/scenario_name", "")],
        ),
        (
            "scenario_information",
            "x",
            [(Bump.MAJOR, "its scenario_information changed", "/scenario_information", "")],
        ),
        (
            "scenario_teams",
            [{"team_id": "u", "team_name": "Red"}],
            [
                (Bump.MAJOR, "an item of scenario_teams removed", "/scenario_teams", "t"),
                (Bump.MINOR, "an item of scenario_teams added", "/scenario_teams/0", "u"),
            ],
        ),
        (
            "scenario_teams",
            [{"team_id": "v"}, {"team_id": "t", "team_name": "Red", "team_description": "d"}],
            [
                (Bump.MINOR, "an item of scenario_teams added", "/scenario_teams/0", "v"),
                (
                    Bump.PATCH,
                    "an item of scenario_teams changed its text",
                    "/scenario_teams/1",
                    "t",
                ),
            ],
        ),
        (
            "scenario_teams",
            [{"team_id": "t", "team_name": "Blue", "team_description": "d", "x": 1}],
            [(Bump.MINOR, "an item of scenario_teams changed", "/scenario_teams/0", "t")],
        ),
        (
            "scenario_teams",
            "x",
            [(Bump.MAJOR, "its scenario_teams changed", "/scenario_teams", "")],
        ),
        ("scenario_new", 1, [(Bump.MAJOR, "its scenario_new changed", "/scenario_new", "")]),
    ],
)
def test_a_part_of_scenario_json_is_where_it_changed(
    part: str, value: object, expected: list[tuple[Bump, str, str, str]]
) -> None:
    found = [
        (bump, reason, field, item)
        for bump, reason, file, field, item in located(after=stored(**{part: value}))
        if file == "scenario.json"
    ]

    assert found == expected


def test_the_changes_validate_reads_are_the_located_ones_each_kind_once() -> None:
    after = stored(scenario_injects=[inject("a", inject_title="1"), inject("b", inject_title="2")])
    after["scenario_injects"][1]["inject_depends_on"] = ["a"]

    assert [c.change for c in located_changes(METADATA, STORED, METADATA, after)] == [
        Change(Bump.PATCH, "an inject's text changed"),
        Change(Bump.PATCH, "an inject's text changed"),
    ]
    assert changes(METADATA, STORED, METADATA, after) == [
        Change(Bump.PATCH, "an inject's text changed")
    ]


def test_a_located_change_names_no_item_by_default() -> None:
    change = LocatedChange(Change(Bump.PATCH, "x"), "scenario.yaml", "/name")

    assert change.item == ""


# The diff's findings


def diff(
    metadata: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    previous: tuple[object, object] | None = (METADATA, STORED),
) -> list[tuple[str, Severity, str, str, str]]:
    return [
        (f.code, f.severity, f.path, f.field, f.message)
        for f in diff_findings(previous, metadata or METADATA, after or STORED, entry=ENTRY)
    ]


def test_the_least_version_comes_first_then_each_change() -> None:
    """First, so that a report cut at its limit always keeps it; then the changes, those
    that need the most first."""
    after = stored(scenario_injects=[inject("a"), inject("c")])
    metadata = {**METADATA, "name": "Y", "version": "1.3.0"}

    assert diff(metadata, after) == [
        (
            "VER-014",
            Severity.INFO,
            ENTRY,
            "",
            "these changes need 2.0.0 at least, a major version (an inject removed), from 1.2.3; "
            "the entry gives 1.3.0: too low",
        ),
        (
            "VER-013",
            Severity.INFO,
            JSON,
            "/scenario_injects",
            "an inject removed: needs a major version (ID b)",
        ),
        (
            "VER-013",
            Severity.INFO,
            JSON,
            "/scenario_injects/1",
            "an inject added: needs a minor version (ID c)",
        ),
        ("VER-013", Severity.INFO, YAML, "/name", "its name changed: needs a patch version"),
    ]


@pytest.mark.parametrize(
    ("version", "verdict"), [("2.0.0", "enough"), ("3.1.0", "enough"), ("1.9.9", "too low")]
)
def test_the_least_version_says_whether_the_entry_s_is_enough(version: str, verdict: str) -> None:
    after = stored(scenario_injects=[inject("a")])

    first, *_ = diff({**METADATA, "version": version}, after)

    assert first[4].endswith(f"the entry gives {version}: {verdict}")


def test_the_changes_listed_stop_at_thirty_and_the_least_version_says_how_many_more() -> None:
    after = stored(
        scenario_injects=[*STORED["scenario_injects"], *(inject(f"n{i:02}") for i in range(40))]
    )

    first, *listed = diff(after=after)

    assert len(listed) == 30
    assert first[4].endswith("the entry gives 1.2.3: too low; 10 more changes, not listed")
    assert [f[3] for f in listed] == [f"/scenario_injects/{i}" for i in range(2, 32)]


def test_the_changes_listed_are_the_ones_that_need_the_most() -> None:
    """A major change found last is listed before patch changes found first."""
    titled = [inject(f"n{i:02}", inject_title="old") for i in range(35)]
    retitled = [inject(f"n{i:02}", inject_title="new") for i in range(35)]
    before = stored(scenario_injects=titled)
    after = stored(scenario_injects=retitled, scenario_new=1)

    found = [
        (f.field, f.message)
        for f in diff_findings((METADATA, before), METADATA, after, entry=ENTRY)
    ]

    assert len(found) == 31
    assert found[1] == ("/scenario_new", "its scenario_new changed: needs a major version")
    assert found[0][1].endswith("; 6 more changes, not listed")


def test_thirty_changes_are_all_listed() -> None:
    after = stored(
        scenario_injects=[*STORED["scenario_injects"], *(inject(f"n{i:02}") for i in range(30))]
    )

    found = diff(after=after)

    assert len(found) == 1 + 30
    assert all("more changes" not in f[4] for f in found)


def test_changes_of_one_level_name_the_first_as_the_reason() -> None:
    after = stored(
        scenario_injects=[inject("a", inject_title="T"), inject("b", inject_depends_on=["a"])]
    )
    metadata = {**METADATA, "description": "D"}

    first, *_ = diff(metadata, after)

    assert first[4].startswith(
        "these changes need 1.2.4 at least, a patch version (its description changed)"
    )


def test_a_change_that_needs_no_version_is_listed_as_such() -> None:
    expected = [("VER-014", Severity.INFO, ENTRY, "", "nothing changed that needs a new version")]

    assert diff({**METADATA, "payloads": ["x"]}) == expected
    assert diff() == expected


@pytest.mark.parametrize(
    ("metadata", "after", "least", "level"),
    [
        ({**METADATA, "name": "Y"}, STORED, "1.2.4", "patch"),
        (
            METADATA,
            stored(scenario_injects=[*STORED["scenario_injects"], inject("c")]),
            "1.3.0",
            "minor",
        ),
        (METADATA, stored(scenario_new=1), "2.0.0", "major"),
    ],
)
def test_the_least_version_follows_the_level(
    metadata: dict[str, Any], after: dict[str, Any], least: str, level: str
) -> None:
    first, *_ = diff(metadata, after)

    assert first[4].startswith(f"these changes need {least} at least, a {level} version (")


def test_an_entry_the_base_branch_does_not_hold_is_new() -> None:
    assert diff(previous=None) == [
        (
            "VER-014",
            Severity.INFO,
            ENTRY,
            "",
            "a new entry: the base branch holds no previous version to compare with",
        )
    ]


@pytest.mark.parametrize(
    "previous",
    [
        (None, STORED),
        (METADATA, None),
        ({**METADATA, "version": "x"}, STORED),
        (["x"], STORED),
    ],
)
def test_a_base_copy_that_cannot_be_compared_says_so(previous: tuple[object, object]) -> None:
    assert diff(previous=previous) == [
        (
            "VER-014",
            Severity.INFO,
            ENTRY,
            "",
            "the base branch's copy of this entry cannot be compared: its scenario.yaml or its "
            "scenario.json is missing, or it has no valid version",
        )
    ]


def test_an_entry_without_a_valid_version_is_told_so() -> None:
    first, *_ = diff({**METADATA, "name": "Y", "version": "one"})

    assert first[4].endswith("from 1.2.3; the entry gives no valid version: too low")
