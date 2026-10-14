"""Versioning: an entry's version is raised as its change needs, against the entry as the base
branch holds it; its inject identifiers stay; its changelog has a section per version."""

import copy
from typing import Any

import pytest

from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.versioning import (
    Bump,
    Change,
    changelog_findings,
    changes,
    declared_bump,
    required_bump,
    versioning_findings,
)

YAML = "scenarios/techniques/x/scenario.yaml"
JSON = "scenarios/techniques/x/scenario.json"
LOG = "scenarios/techniques/x/CHANGELOG.md"
CONTRACT = "2790bd39-37d4-4e39-be7e-53f3ca783f86"
METADATA: dict[str, Any] = {
    "external_id": "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
    "version": "1.2.3",
    "status": "VERIFIED",
    "name": "X",
    "requires": {"openaev": ">=3.0.0"},
    "payloads": [],
}


def inject(identifier: str, **fields: Any) -> dict[str, Any]:
    return {
        "inject_id": identifier,
        "inject_title": f"Inject {identifier}",
        "inject_injector_contract": {"injector_contract_id": CONTRACT},
        **fields,
    }


STORED: dict[str, Any] = {
    "scenario_information": {"scenario_name": "X", "scenario_id": "s"},
    "scenario_injects": [inject("a"), inject("b", inject_depends_on=["a"])],
    "scenario_teams": [{"team_id": "t", "team_name": "Blue", "team_description": "d"}],
    "scenario_users": [],
}


def changed(part: str = "", **fields: Any) -> dict[str, Any]:
    stored = copy.deepcopy(STORED)
    if part:
        stored[part] = fields.pop("value")
    return stored


def diff(
    metadata: dict[str, Any] | None = None, stored: dict[str, Any] | None = None
) -> list[tuple[Bump, str]]:
    return [
        (c.bump, c.reason)
        for c in changes(METADATA, STORED, metadata or METADATA, stored or STORED)
    ]


def test_an_unchanged_entry_has_no_change() -> None:
    assert diff() == []


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("requires", {"openaev": ">=4.0.0"}, (Bump.MAJOR, "its requirements changed")),
        ("targets", [{"placeholder": "x"}], (Bump.MAJOR, "its targets changed")),
        ("type", "chained", (Bump.MAJOR, "its type changed")),
        ("name", "Y", (Bump.PATCH, "its name changed")),
        ("description", "d", (Bump.PATCH, "its description changed")),
        ("severity", "high", (Bump.PATCH, "its severity changed")),
        ("category", "c", (Bump.PATCH, "its category changed")),
        ("main_focus", "m", (Bump.PATCH, "its main_focus changed")),
        ("platforms", ["Linux"], (Bump.PATCH, "its platforms changed")),
        ("threat", {"ttps": ["T1"]}, (Bump.PATCH, "its threat changed")),
        ("sources", [], (Bump.PATCH, "its sources changed")),
        ("status", "REVOKED", (Bump.PATCH, "its status changed")),
        ("generated_by", "x", (Bump.PATCH, "its generated_by changed")),
        ("relevance", {"score": 1}, (Bump.PATCH, "its relevance changed")),
        ("new_field", 1, (Bump.MAJOR, "its new_field changed")),
    ],
)
def test_a_metadata_change_is_classified(
    key: str, value: object, expected: tuple[Bump, str]
) -> None:
    assert diff(metadata={**METADATA, key: value}) == [expected]


@pytest.mark.parametrize("key", ["version", "payloads", "external_id"])
def test_metadata_the_bump_does_not_compare(key: str) -> None:
    assert diff(metadata={**METADATA, key: "changed"}) == []


def test_a_removed_metadata_field_is_a_change_too() -> None:
    metadata = {key: value for key, value in METADATA.items() if key != "requires"}

    assert diff(metadata=metadata) == [(Bump.MAJOR, "its requirements changed")]


def test_injects_removed_and_added() -> None:
    stored = changed("scenario_injects", value=[inject("a"), inject("c")])

    assert diff(stored=stored) == [
        (Bump.MAJOR, "an inject removed"),
        (Bump.MINOR, "an inject added"),
    ]


CONTENT = {"target_selector": "asset-groups", "targets": [], "template": "t", "expectations": []}


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (
            {**CONTENT, "targets": ["evil.example.com"]},
            [(Bump.MAJOR, "an inject's targets changed")],
        ),
        ({**CONTENT, "target_selector": "assets"}, [(Bump.MAJOR, "an inject's targets changed")]),
        (
            {**CONTENT, "target_property_selector": "hostname"},
            [(Bump.MAJOR, "an inject's targets changed")],
        ),
        ({**CONTENT, "template": "u"}, [(Bump.MINOR, "an inject's content changed")]),
        (
            {**CONTENT, "targets": ["x"], "expectations": [1]},
            [
                (Bump.MAJOR, "an inject's targets changed"),
                (Bump.MINOR, "an inject's content changed"),
            ],
        ),
        (
            "x",
            [
                (Bump.MAJOR, "an inject's targets changed"),
                (Bump.MINOR, "an inject's content changed"),
            ],
        ),
    ],
)
def test_the_targets_an_inject_content_holds_are_its_targets(
    content: object, expected: list[tuple[Bump, str]]
) -> None:
    before = changed("scenario_injects", value=[inject("a", inject_content=CONTENT)])
    after = changed("scenario_injects", value=[inject("a", inject_content=content)])

    assert [(c.bump, c.reason) for c in changes(METADATA, before, METADATA, after)] == expected


def test_a_content_that_is_no_object_is_compared_as_a_whole() -> None:
    before = changed("scenario_injects", value=[inject("a", inject_content="x")])
    after = changed("scenario_injects", value=[inject("a", inject_content="y")])

    assert [(c.bump, c.reason) for c in changes(METADATA, before, METADATA, after)] == [
        (Bump.MINOR, "an inject's content changed")
    ]


@pytest.mark.parametrize(
    ("part", "items"),
    [
        (
            "scenario_injects",
            [
                inject("a", inject_content={"x": 2}),
                inject("a"),
                inject("b", inject_depends_on=["a"]),
            ],
        ),
        (
            "scenario_teams",
            [{"team_id": "t", "team_name": "Red"}, *STORED["scenario_teams"]],
        ),
    ],
)
def test_an_identifier_held_twice_hides_no_change(part: str, items: list[Any]) -> None:
    """Kept by the last of its items, a change in the first would pass unseen."""
    assert diff(stored=changed(part, value=items)) == [(Bump.MAJOR, f"its {part} changed")]
    assert [
        (c.bump, c.reason) for c in changes(METADATA, changed(part, value=items), METADATA, STORED)
    ] == [(Bump.MAJOR, f"its {part} changed")]


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"inject_depends_on": ["x"]}, (Bump.MAJOR, "an inject's place in the chain changed")),
        ({"inject_depends_duration": 60}, (Bump.MAJOR, "an inject's place in the chain changed")),
        ({"inject_enabled": False}, (Bump.MAJOR, "an inject's place in the chain changed")),
        ({"inject_teams": ["t"]}, (Bump.MAJOR, "an inject's targets changed")),
        ({"inject_all_teams": True}, (Bump.MAJOR, "an inject's targets changed")),
        ({"inject_content": {"x": 1}}, (Bump.MINOR, "an inject's content changed")),
        ({"inject_documents": ["d"]}, (Bump.MINOR, "an inject's content changed")),
        ({"inject_title": "T"}, (Bump.PATCH, "an inject's text changed")),
        ({"inject_description": "D"}, (Bump.PATCH, "an inject's text changed")),
        ({"inject_tags": ["x"]}, (Bump.PATCH, "an inject's text changed")),
        ({"inject_country": "FR"}, (Bump.PATCH, "an inject's text changed")),
        ({"inject_city": "Paris"}, (Bump.PATCH, "an inject's text changed")),
        ({"inject_new": 1}, (Bump.MAJOR, "an inject's inject_new changed")),
        (
            {"inject_injector_contract": {"injector_contract_id": "other"}},
            (Bump.MAJOR, "an inject's contract changed"),
        ),
        (
            {
                "inject_injector_contract": {
                    "injector_contract_id": CONTRACT,
                    "injector_contract_labels": {"en": "x"},
                }
            },
            (Bump.MAJOR, "an inject's contract changed"),
        ),
        (
            {
                "inject_injector_contract": {
                    "injector_contract_id": CONTRACT,
                    "injector_contract_payload": {"p": 1},
                }
            },
            (Bump.MINOR, "an inject's payload changed"),
        ),
    ],
)
def test_an_inject_change_is_classified(fields: dict[str, Any], expected: tuple[Bump, str]) -> None:
    stored = changed(
        "scenario_injects", value=[inject("a", **fields), inject("b", inject_depends_on=["a"])]
    )

    assert diff(stored=stored) == [expected]


def test_one_change_per_kind_and_inject() -> None:
    stored = changed(
        "scenario_injects",
        value=[
            inject("a", inject_title="T", inject_description="D"),
            inject("b", inject_depends_on=["a"]),
        ],
    )

    assert diff(stored=stored) == [(Bump.PATCH, "an inject's text changed")]


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("scenario_name", (Bump.PATCH, "its scenario_name changed")),
        ("scenario_description", (Bump.PATCH, "its scenario_description changed")),
        ("scenario_subtitle", (Bump.PATCH, "its scenario_subtitle changed")),
        ("scenario_message_header", (Bump.PATCH, "its scenario_message_header changed")),
        ("scenario_message_footer", (Bump.PATCH, "its scenario_message_footer changed")),
        ("scenario_category", (Bump.PATCH, "its scenario_category changed")),
        ("scenario_main_focus", (Bump.PATCH, "its scenario_main_focus changed")),
        ("scenario_severity", (Bump.PATCH, "its scenario_severity changed")),
        ("scenario_tags", (Bump.PATCH, "its scenario_tags changed")),
        ("scenario_lessons_enabled", (Bump.PATCH, "its scenario_lessons_enabled changed")),
        ("scenario_lessons_anonymized", (Bump.PATCH, "its scenario_lessons_anonymized changed")),
        ("scenario_dependencies", (Bump.MAJOR, "its scenario_dependencies changed")),
    ],
)
def test_an_information_change_is_classified(key: str, expected: tuple[Bump, str]) -> None:
    stored = changed("scenario_information", value={**STORED["scenario_information"], key: "x"})

    assert diff(stored=stored) == [expected]


@pytest.mark.parametrize(
    ("teams", "expected"),
    [
        ([], [(Bump.MAJOR, "an item of scenario_teams removed")]),
        (
            [STORED["scenario_teams"][0], {"team_id": "u", "team_name": "Red"}],
            [(Bump.MINOR, "an item of scenario_teams added")],
        ),
        (
            [{"team_id": "t", "team_name": "Green", "team_description": "e", "team_tags": ["x"]}],
            [(Bump.PATCH, "an item of scenario_teams changed its text")],
        ),
        (
            [{"team_id": "t", "team_name": "Blue", "team_description": "d", "team_users": ["x"]}],
            [(Bump.MINOR, "an item of scenario_teams changed")],
        ),
    ],
)
def test_a_collection_change_is_classified(
    teams: list[Any], expected: list[tuple[Bump, str]]
) -> None:
    assert diff(stored=changed("scenario_teams", value=teams)) == expected


@pytest.mark.parametrize(
    "part",
    [
        "scenario_articles",
        "scenario_channels",
        "scenario_challenges",
        "scenario_documents",
        "scenario_variables",
        "scenario_organizations",
        "scenario_tags",
    ],
)
def test_every_collection_is_matched_by_its_identifier(part: str) -> None:
    key = part.removeprefix("scenario_").removesuffix("s") + "_id"
    stored = changed(part, value=[{key: "i"}])

    assert diff(stored=stored) == [(Bump.MINOR, f"an item of {part} added")]


def test_an_unknown_part_needs_a_major_version_and_users_are_not_compared() -> None:
    stored = changed("scenario_users", value=["x"])
    stored["export_version"] = 2

    assert diff(stored=stored) == [(Bump.MAJOR, "its export_version changed")]


def test_odd_shapes_count_as_changes_never_crash() -> None:
    stored = changed("scenario_injects", value="x")
    stored["scenario_teams"] = ["x", {"team_name": "no id"}]

    assert diff(stored=stored) == [
        (Bump.MAJOR, "its scenario_injects changed"),
        (Bump.MAJOR, "its scenario_teams changed"),
    ]


def test_the_required_bump_is_the_highest_change() -> None:
    assert required_bump([]) == Change(Bump.NONE, "")
    assert required_bump(
        [
            Change(Bump.PATCH, "p"),
            Change(Bump.MAJOR, "m"),
            Change(Bump.MINOR, "n"),
            Change(Bump.MAJOR, "o"),
        ]
    ) == Change(Bump.MAJOR, "m")


@pytest.mark.parametrize(
    ("previous", "version", "expected"),
    [
        ("1.2.3", "1.2.3", Bump.NONE),
        ("1.2.3", "1.2.4", Bump.PATCH),
        ("1.2.3", "1.3.0", Bump.MINOR),
        ("1.2.3", "1.3.9", Bump.MINOR),
        ("1.2.3", "2.0.0", Bump.MAJOR),
        ("1.9.9", "10.0.0", Bump.MAJOR),
        ("1.2.3", "1.2.2", None),
        ("1.2.3", "1.1.9", None),
        ("2.0.0", "1.9.9", None),
        ("1.2.3", "x", None),
        ("x", "1.2.3", None),
    ],
)
def test_the_declared_bump(previous: str, version: str, expected: Bump | None) -> None:
    assert declared_bump(previous, version) == expected


def findings(
    metadata: dict[str, Any] | None = None,
    stored: dict[str, Any] | None = None,
    *,
    previous: bool = True,
) -> list[tuple[str, Severity, str, str, str]]:
    return [
        (f.code, f.severity, f.path, f.field, f.message)
        for f in versioning_findings(
            (METADATA, STORED) if previous else None,
            metadata or METADATA,
            stored or STORED,
            metadata_path=YAML,
            scenario_path=JSON,
        )
    ]


def test_a_version_raised_as_the_change_needs_passes() -> None:
    stored = changed(
        "scenario_injects", value=[inject("a"), inject("b", inject_depends_on=["a"]), inject("c")]
    )

    assert findings({**METADATA, "version": "1.3.0"}, stored) == []
    assert findings({**METADATA, "version": "2.0.0"}, stored) == []  # higher is allowed


@pytest.mark.parametrize(
    ("version", "least", "level", "reason"),
    [
        ("1.2.3", "2.0.0", "major", "an inject removed"),
        ("1.2.4", "2.0.0", "major", "an inject removed"),
        ("1.3.0", "2.0.0", "major", "an inject removed"),
    ],
)
def test_a_version_raised_less_than_the_change_needs_is_refused(
    version: str, least: str, level: str, reason: str
) -> None:
    stored = changed("scenario_injects", value=[inject("a")])

    assert findings({**METADATA, "version": version}, stored) == [
        (
            "VER-001",
            Severity.BLOCKING,
            YAML,
            "/version",
            f"this change needs a {level} version ({reason}): raise the version to {least} "
            "at least, and add its section on top of CHANGELOG.md",
        )
    ]


@pytest.mark.parametrize(
    ("value", "least"),
    [({"name": "Y"}, "1.2.4"), ({"requires": {}}, "2.0.0")],
)
def test_the_least_version_follows_the_level(value: dict[str, Any], least: str) -> None:
    (finding,) = findings({**METADATA, **value})

    assert finding[4].endswith(
        f"raise the version to {least} at least, and add its section on top of CHANGELOG.md"
    )


def test_a_minor_change_gives_the_next_minor_version() -> None:
    stored = changed("scenario_injects", value=[*STORED["scenario_injects"], inject("c")])

    (finding,) = findings(METADATA, stored)

    assert finding[4] == (
        "this change needs a minor version (an inject added): raise the version to 1.3.0 at least, "
        "and add its section on top of CHANGELOG.md"
    )


def test_a_lower_version_is_refused() -> None:
    assert findings({**METADATA, "version": "1.2.2"}) == [
        (
            "VER-002",
            Severity.BLOCKING,
            YAML,
            "/version",
            "the version is lower than the previous one, 1.2.3: a version never decreases",
        )
    ]


def test_a_version_number_has_at_most_nine_digits() -> None:
    """Read as a number, a longer one could exhaust the run, never a finding."""
    assert declared_bump("1.0.0", "1.0.1234567890") is None
    assert declared_bump("1.0.0", "1.0.123456789") is Bump.PATCH


def test_an_external_id_never_changes() -> None:
    assert findings({**METADATA, "external_id": "other"}) == [
        (
            "VER-005",
            Severity.BLOCKING,
            YAML,
            "/external_id",
            "the external ID of an entry never changes: a new scenario is a new entry",
        )
    ]


def test_an_inject_back_under_a_new_id_is_refused() -> None:
    stored = changed(
        "scenario_injects",
        value=[inject("c", inject_title="Inject a"), inject("b", inject_depends_on=["a"])],
    )

    assert [f for f in findings({**METADATA, "version": "2.0.0"}, stored) if f[0] == "VER-003"] == [
        (
            "VER-003",
            Severity.BLOCKING,
            JSON,
            "/scenario_injects/0/inject_id",
            "this inject has the contract and the title of an inject of the previous version, "
            "under a new ID: its ID must stay; prepare the entry with `normalize --previous` or "
            "`intake`, or give a new inject another title",
        )
    ]


def test_an_inject_back_under_a_new_id_is_found_among_the_injects_removed_only() -> None:
    """An inject kept, its title changed, leaves no title free: only those of the injects
    removed are."""
    stored = changed(
        "scenario_injects",
        value=[inject("a", inject_title="A"), inject("b", inject_depends_on=["a"]), inject("c")],
    )
    stored["scenario_injects"][2]["inject_title"] = "Inject a"

    assert [f[0] for f in findings({**METADATA, "version": "2.0.0"}, stored)] == []


@pytest.mark.parametrize("identifier", [[1], {}, None, 1])
def test_an_inject_id_that_is_no_text_is_a_change_never_a_crash(identifier: object) -> None:
    stored = changed("scenario_injects", value=[inject("a"), inject("b", inject_depends_on=["a"])])
    stored["scenario_injects"][1]["inject_id"] = identifier

    assert findings({**METADATA, "version": "2.0.0"}, stored) == []
    assert [f[0] for f in findings({**METADATA, "version": "1.3.0"}, stored)] == ["VER-001"]


def payloaded(*identifiers: str) -> dict[str, Any]:
    return changed(
        "scenario_injects",
        value=[
            inject(
                identifier,
                inject_injector_contract={
                    "injector_contract_id": CONTRACT,
                    "injector_contract_payload": {"payload_external_id": identifier},
                },
            )
            for identifier in identifiers
        ],
    )


def test_a_new_payload_is_pointed_out_to_the_reviewer() -> None:
    before, after = payloaded("p1"), payloaded("p1", "p2")

    found = [
        (f.code, f.severity, f.field, f.message)
        for f in versioning_findings(
            (METADATA, before),
            {**METADATA, "version": "1.3.0"},
            after,
            metadata_path=YAML,
            scenario_path=JSON,
        )
    ]

    assert found == [
        (
            "POL-008",
            Severity.INFO,
            "/scenario_injects/1/inject_injector_contract/injector_contract_payload/payload_external_id",
            "a payload this scenario did not run before: review what it runs",
        )
    ]


def test_every_payload_of_a_new_entry_is_new() -> None:
    assert [f[0] for f in findings(None, payloaded("p1", "p2"), previous=False)] == [
        "POL-008",
        "POL-008",
    ]


def test_a_new_entry_has_no_version_to_compare() -> None:
    assert findings({**METADATA, "version": "0.0.1"}, previous=False) == []


@pytest.mark.parametrize(
    ("previous_metadata", "previous_stored"),
    [
        ({**METADATA, "version": 1}, STORED),
        ({**METADATA, "version": "1.0.1234567890"}, STORED),
        ({key: value for key, value in METADATA.items() if key != "version"}, STORED),
        (["x"], STORED),
        (None, STORED),
        (METADATA, None),
        (METADATA, ["x"]),
    ],
)
def test_a_previous_version_that_cannot_be_compared_blocks(
    previous_metadata: Any, previous_stored: Any
) -> None:
    """A copy the base branch holds, damaged, never lets a change pass as a new entry."""
    found = versioning_findings(
        (previous_metadata, previous_stored),
        METADATA,
        STORED,
        metadata_path=YAML,
        scenario_path=JSON,
    )

    assert [(f.code, f.severity, f.path, f.field, f.message) for f in found] == [
        (
            "VER-006",
            Severity.BLOCKING,
            YAML,
            "",
            "the base branch's copy of this entry cannot be compared: its scenario.yaml or its "
            "scenario.json is missing, or it has no valid version; a maintainer fixes the base "
            "branch first",
        )
    ]


def test_an_external_id_is_checked_whatever_the_previous_version() -> None:
    previous = {**METADATA, "version": "x", "external_id": "other"}

    found = versioning_findings(
        (previous, STORED), METADATA, STORED, metadata_path=YAML, scenario_path=JSON
    )

    assert [f.code for f in found] == ["VER-005", "VER-006"]


# Changelog


def test_a_changelog_with_a_section_per_version_newest_first_passes() -> None:
    text = "# Changelog\n\n## 1.2.3 — 2026-10-14\n\n### Changed\n\n- x\n\n## 1.0.0 — 2026-10-12\n"

    assert changelog_findings(text, "1.2.3", LOG) == ()


HEADING = (
    "line {}: a level-2 heading opens a version's section, `## <version> — <YYYY-MM-DD>` with a "
    "valid date; other headings take `###`"
)


@pytest.mark.parametrize(
    "text",
    [
        "## 1.2.3 - 2026-10-14\n## 1.0.0 \u2013 2026-10-12\n",
        "## 1.2.3 — 2026-10-14  \r\n## 1.0.0 — 2026-10-12\t\r\n",
        "## 1.2.3 — 2026-10-14\n```\n## not a section\n```\n~~~\n## nor this\n~~~\n",
        "```\n## not a section\n```\n## 1.2.3 — 2026-10-14\n",
    ],
)
def test_a_heading_takes_any_dash_and_trailing_spaces_and_a_fence_holds_no_section(
    text: str,
) -> None:
    """A hyphen and an en dash look like the em dash: refusing them would only trip a
    contributor."""
    assert changelog_findings(text, "1.2.3", LOG) == ()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            None,
            "CHANGELOG.md is missing: add a `## <version> — <YYYY-MM-DD>` section for each "
            "version, newest first",
        ),
        (
            "# Changelog\n",
            "CHANGELOG.md has no section: add `## 1.2.3 — <YYYY-MM-DD>` for this version",
        ),
        ("## 1.2.2 — 2026-10-14\n", "the first section must be this version, 1.2.3, newest first"),
        ("## 1.2.3 — 2026-13-14\n", HEADING.format(1)),
        ("## v1.2.3 — 2026-10-14\n", HEADING.format(1)),
        ("## [1.2.3] — 2026-10-14\n", HEADING.format(1)),
        ("## 1.2.3 -- 2026-10-14\n", HEADING.format(1)),
        ("## 1.2.3 — 2026-10-14 x\n", HEADING.format(1)),
        ("# Changelog\n\n## Unreleased\n", HEADING.format(3)),
        ("## 1.2.1234567890 — 2026-10-14\n", HEADING.format(1)),
        ("## 1.2.3 — 2026-10-14\u2028x\n", HEADING.format(1)),
        ("## 1.2.3 — 2026-10-14\u2028\n", HEADING.format(1)),
        ("## 1.2.3 — 2026-10-14X\n", HEADING.format(1)),
        (
            "## 1.2.3 — 2026-10-14\n## 1.2.2 — 2027-01-01\n",
            "line 2: each section's date is no later than the one above",
        ),
        ("\x0c\n\u2028\n## x\n", HEADING.format(3)),
        (
            "x\r## 1.2.3 — 2026-10-14\r## 1.2.3 — 2026-10-13\r\n",
            "line 3: each section's version is lower than the one above",
        ),
        (
            "```\n## 1.2.3 — 2026-10-14\n```\n",
            "CHANGELOG.md has no section: add `## 1.2.3 — <YYYY-MM-DD>` for this version",
        ),
        (
            "x\n## 1.2.3 — 2026-10-14\n## 1.2.3 — 2026-10-13\n",
            "line 3: each section's version is lower than the one above",
        ),
        (
            "## 1.2.3 — 2026-10-14\n## 1.2.4 — 2026-10-13\n",
            "line 2: each section's version is lower than the one above",
        ),
        (
            "## 1.2.3 — 2026-10-14\n## 1.2.2 — 2026-10-15\n",
            "line 2: each section's date is no later than the one above",
        ),
    ],
)
def test_a_changelog_out_of_its_form_is_refused(text: str | None, message: str) -> None:
    (finding,) = changelog_findings(text, "1.2.3", LOG)

    assert (finding.code, finding.severity, finding.path, finding.field, finding.message) == (
        "VER-004",
        Severity.BLOCKING,
        LOG,
        "",
        message,
    )


def test_a_section_on_the_same_day_passes_and_deeper_headings_are_free() -> None:
    text = "## 1.2.3 — 2026-10-14\n### 9.9.9 notes\n## 1.2.2 — 2026-10-14\n"

    assert changelog_findings(text, "1.2.3", LOG) == ()


def test_a_contract_or_information_that_is_no_object_counts_as_changed() -> None:
    stored = changed(
        "scenario_injects",
        value=[inject("a", inject_injector_contract="x"), inject("b", inject_depends_on=["a"])],
    )
    stored["scenario_information"] = "x"

    assert diff(stored=stored) == [  # the parts in the order of their names
        (Bump.MAJOR, "its scenario_information changed"),
        (Bump.MAJOR, "an inject's contract changed"),
    ]


def test_a_payload_without_an_id_is_not_counted_as_new() -> None:
    stored = changed(
        "scenario_injects",
        value=[
            inject(
                "a", inject_injector_contract={"injector_contract_payload": {"payload_name": "p"}}
            ),
            inject("b", inject_injector_contract={"injector_contract_payload": "x"}),
        ],
    )

    assert [f[0] for f in findings(None, stored, previous=False)] == []


@pytest.mark.parametrize("injects", ["x", []])
def test_no_inject_is_compared_when_either_version_holds_none_as_a_list(injects: object) -> None:
    stored = changed("scenario_injects", value=injects)

    assert [f[0] for f in findings({**METADATA, "version": "2.0.0"}, stored)] == []


def contracted(contract: object) -> dict[str, Any]:
    return changed(
        "scenario_injects",
        value=[
            inject("a", inject_injector_contract=contract),
            inject("b", inject_depends_on=["a"]),
        ],
    )


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (
            {"injector_contract_id": CONTRACT, "injector_contract_payload": {"p": 1}},
            {"injector_contract_id": "other", "injector_contract_payload": {"p": 1}},
            [(Bump.MAJOR, "an inject's contract changed")],
        ),
        (
            {"injector_contract_id": CONTRACT, "injector_contract_payload": {"p": 1}, "x": 1},
            {"injector_contract_id": CONTRACT, "injector_contract_payload": {"p": 2}, "x": 1},
            [(Bump.MINOR, "an inject's payload changed")],
        ),
    ],
)
def test_a_contract_s_parts_are_compared_each_with_its_own(
    before: dict[str, Any], after: dict[str, Any], expected: list[tuple[Bump, str]]
) -> None:
    found = changes(METADATA, contracted(before), METADATA, contracted(after))

    assert [(c.bump, c.reason) for c in found] == expected


def test_an_unchanged_item_never_ends_the_comparison_of_the_others() -> None:
    teams = [{"team_id": "t", "team_name": "Blue"}, {"team_id": "u", "team_name": "Red"}]
    after = [teams[0], {"team_id": "u", "team_name": "Green"}]

    found = changes(
        METADATA,
        changed("scenario_teams", value=teams),
        METADATA,
        changed("scenario_teams", value=after),
    )

    assert [(c.bump, c.reason) for c in found] == [
        (Bump.PATCH, "an item of scenario_teams changed its text")
    ]


def test_a_payload_held_by_two_injects_is_pointed_out_once() -> None:
    stored = payloaded("p1")
    stored["scenario_injects"].append(copy.deepcopy(stored["scenario_injects"][0]))
    stored["scenario_injects"][1]["inject_id"] = "b"

    assert [f[0] for f in findings(None, stored, previous=False)] == ["POL-008"]


@pytest.mark.parametrize(
    ("removed", "added", "codes"),
    [
        ({"injector_contract_id": CONTRACT}, {"injector_contract_id": "other"}, []),
        ("x", {"injector_contract_id": CONTRACT}, []),
        ({"injector_contract_id": CONTRACT}, {"injector_contract_id": CONTRACT}, ["VER-003"]),
    ],
)
def test_an_inject_is_the_same_only_under_the_same_contract(
    removed: object, added: object, codes: list[str]
) -> None:
    before = changed("scenario_injects", value=[inject("a", inject_injector_contract=removed)])
    after = changed(
        "scenario_injects",
        value=[inject("c", inject_title="Inject a", inject_injector_contract=added)],
    )

    found = versioning_findings(
        (METADATA, before),
        {**METADATA, "version": "2.0.0"},
        after,
        metadata_path=YAML,
        scenario_path=JSON,
    )

    assert [f.code for f in found] == codes


@pytest.mark.parametrize("odd", [[1], {}])
@pytest.mark.parametrize("side", ["removed", "added"])
@pytest.mark.parametrize("field", ["inject_title", "contract"])
def test_a_title_or_contract_id_of_any_shape_is_compared_never_a_crash(
    odd: object, side: str, field: str
) -> None:
    removed, added = inject("a"), inject("c", inject_title="Inject a")
    target = removed if side == "removed" else added
    if field == "contract":
        target["inject_injector_contract"] = {"injector_contract_id": odd}
    else:
        target["inject_title"] = odd

    found = versioning_findings(
        (METADATA, changed("scenario_injects", value=[removed])),
        {**METADATA, "version": "2.0.0"},
        changed("scenario_injects", value=[added]),
        metadata_path=YAML,
        scenario_path=JSON,
    )

    assert [f.code for f in found] == []


def test_an_odd_title_shared_by_an_inject_removed_and_one_added_is_the_same_inject() -> None:
    removed, added = inject("a", inject_title=["x"]), inject("c", inject_title=["x"])

    found = versioning_findings(
        (METADATA, changed("scenario_injects", value=[removed])),
        {**METADATA, "version": "2.0.0"},
        changed("scenario_injects", value=[added]),
        metadata_path=YAML,
        scenario_path=JSON,
    )

    assert [f.code for f in found] == ["VER-003"]


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (
            {"inject_enabled": True},
            {"inject_enabled": 1},
            [(Bump.MAJOR, "an inject's place in the chain changed")],
        ),
        (
            {"inject_depends_duration": 0},
            {"inject_depends_duration": False},
            [(Bump.MAJOR, "an inject's place in the chain changed")],
        ),
        (
            {"inject_content": {"x": [1]}},
            {"inject_content": {"x": [True]}},
            [(Bump.MINOR, "an inject's content changed")],
        ),
        (
            {"inject_content": {"targets": [1]}},
            {"inject_content": {"targets": [1.0]}},
            [(Bump.MAJOR, "an inject's targets changed")],
        ),
        (
            {"inject_injector_contract": {"injector_contract_id": CONTRACT, "x": 1}},
            {"inject_injector_contract": {"injector_contract_id": CONTRACT, "x": True}},
            [(Bump.MAJOR, "an inject's contract changed")],
        ),
        (
            {"inject_injector_contract": {"injector_contract_payload": {"p": 0}}},
            {"inject_injector_contract": {"injector_contract_payload": {"p": 0.0}}},
            [(Bump.MINOR, "an inject's payload changed")],
        ),
        (
            {"inject_injector_contract": {"injector_contract_id": 1}},
            {"inject_injector_contract": {"injector_contract_id": True}},
            [(Bump.MAJOR, "an inject's contract changed")],
        ),
    ],
)
def test_a_value_that_changes_only_its_type_is_a_change(
    before: dict[str, Any], after: dict[str, Any], expected: list[tuple[Bump, str]]
) -> None:
    """``True == 1 == 1.0`` in Python, never for the platform that reads the scenario."""
    old = changed("scenario_injects", value=[inject("a", **before)])
    new = changed("scenario_injects", value=[inject("a", **after)])

    assert [(c.bump, c.reason) for c in changes(METADATA, old, METADATA, new)] == expected


@pytest.mark.parametrize(
    ("part", "before", "after", "expected"),
    [
        (
            "scenario_information",
            {"scenario_lessons_enabled": True},
            {"scenario_lessons_enabled": 1},
            (Bump.PATCH, "its scenario_lessons_enabled changed"),
        ),
        (
            "scenario_teams",
            [{"team_id": "t", "team_contextual": False}],
            [{"team_id": "t", "team_contextual": 0}],
            (Bump.MINOR, "an item of scenario_teams changed"),
        ),
        ("scenario_new", 1, True, (Bump.MAJOR, "its scenario_new changed")),
        ("scenario_new", [1], [1, 2], (Bump.MAJOR, "its scenario_new changed")),
        ("scenario_new", {"a": 1}, {"b": 1}, (Bump.MAJOR, "its scenario_new changed")),
    ],
)
def test_a_part_that_changes_only_a_type_is_a_change(
    part: str, before: object, after: object, expected: tuple[Bump, str]
) -> None:
    found = changes(METADATA, changed(part, value=before), METADATA, changed(part, value=after))

    assert [(c.bump, c.reason) for c in found] == [expected]


def test_a_metadata_value_that_changes_only_its_type_is_a_change() -> None:
    before, after = (
        {**METADATA, "relevance": {"score": 1}},
        {**METADATA, "relevance": {"score": 1.0}},
    )

    assert [(c.bump, c.reason) for c in changes(before, STORED, after, STORED)] == [
        (Bump.PATCH, "its relevance changed")
    ]


def test_equal_values_of_the_same_types_are_no_change() -> None:
    value = {"a": [1, {"b": True, "c": None}], "d": 1.5, "e": "x"}
    stored = changed("scenario_new", value=value)

    assert changes(METADATA, stored, METADATA, copy.deepcopy(stored)) == []
