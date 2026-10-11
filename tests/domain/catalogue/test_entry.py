"""The checks of an entry that the schema cannot express: its layout, the truncation mark, the
uniqueness of its external ID and the platform version its contracts were recorded on.

Characters are written by code point, never raw, so that this file holds none of them."""

import pytest

from scenario_tools.domain.catalogue.entry import (
    domains_from_document,
    duplicate_findings,
    layout_findings,
    truncation_findings,
    version_findings,
)
from scenario_tools.domain.shared.finding import Finding, Severity

ENTRY = "scenarios/ransomware/akira-crisis"
METADATA = f"{ENTRY}/scenario.yaml"
MARK = chr(0x2026)
DOMAINS = ("vulnerabilities", "intrusion-sets", "ransomware", "techniques")


def _one(findings: tuple[Finding, ...]) -> Finding:
    [finding] = findings
    return finding


@pytest.mark.parametrize(
    "domain", ["vulnerabilities", "intrusion-sets", "ransomware", "techniques"]
)
def test_an_entry_at_its_place_has_no_layout_finding(domain: str) -> None:
    assert (
        layout_findings(f"scenarios/{domain}/a-slug-2", ("scenario.yaml", "scenario.json"), DOMAINS)
        == ()
    )


@pytest.mark.parametrize(
    ("path", "why"),
    [
        ("scenarios/ransomware", "scenarios/<domain>/<slug>/"),
        ("scenarios/ransomware/akira/more", "scenarios/<domain>/<slug>/"),
        ("other/ransomware/akira", "scenarios/<domain>/<slug>/"),
        ("scenarios/malware/akira", "the domain malware is not one of"),
        ("scenarios/ransomware/Akira", "the slug is not kebab-case"),
        ("scenarios/ransomware/akira--crisis", "the slug is not kebab-case"),
        ("scenarios/ransomware/-akira", "the slug is not kebab-case"),
        ("scenarios/ransomware/" + "a" * 65, "the slug is not kebab-case"),
    ],
    ids=["too short", "too deep", "elsewhere", "domain", "case", "double", "leading", "long"],
)
def test_an_entry_out_of_its_place_is_reported(path: str, why: str) -> None:
    finding = _one(layout_findings(path, ("scenario.yaml", "scenario.json"), DOMAINS))

    assert (finding.code, finding.severity, finding.path, finding.field) == (
        "SCH-008",
        Severity.BLOCKING,
        path,
        "",
    )
    assert why in finding.message


def test_a_slug_of_64_characters_is_allowed() -> None:
    assert (
        layout_findings(
            "scenarios/ransomware/" + "a" * 64, ("scenario.yaml", "scenario.json"), DOMAINS
        )
        == ()
    )


@pytest.mark.parametrize("missing", ["scenario.yaml", "scenario.json"])
def test_a_missing_file_of_the_entry_is_reported_at_its_path(missing: str) -> None:
    present = tuple(name for name in ("scenario.yaml", "scenario.json") if name != missing)

    finding = _one(layout_findings(ENTRY, present, DOMAINS))

    assert (finding.code, finding.path) == ("SCH-008", f"{ENTRY}/{missing}")
    assert finding.message == f"the entry has no {missing}"


@pytest.mark.parametrize(
    "description",
    [f"A cut text{MARK}", f"A cut text{MARK}\n", f"A cut text{MARK}  \n\n"],
    ids=["mark", "then a break", "then blanks"],
)
def test_a_description_ending_with_the_truncation_mark_is_refused(description: str) -> None:
    finding = _one(truncation_findings(description, METADATA))

    assert (finding.code, finding.severity, finding.path, finding.field) == (
        "SCH-009",
        Severity.BLOCKING,
        METADATA,
        "/description",
    )
    assert finding.message == (
        f"the description ends with the truncation mark {MARK}: it was cut to fit; review its "
        "end and remove the mark"
    )


@pytest.mark.parametrize(
    "description", ["A whole text.", f"A mark{MARK} inside.", "Three dots...", ""], ids=str
)
def test_a_description_without_the_mark_at_its_end_is_fine(description: str) -> None:
    assert truncation_findings(description, METADATA) == ()


@pytest.mark.parametrize(
    ("constraint", "reported"),
    [
        (">=3.261005.0", False),
        (">=3.261005", False),
        (">=3.261006", False),
        ("==3.261005.0", False),
        (">=3.260923", True),
        ("~=3.261004.9", True),
        (">2.9", True),
        (">=3.261005.0.0", False),
    ],
    ids=str,
)
def test_a_minimum_older_than_the_recorded_version_is_information(
    constraint: str, reported: bool
) -> None:
    findings = version_findings(constraint, "3.261005.0", METADATA)

    assert bool(findings) is reported
    if reported:
        finding = _one(findings)
        assert (finding.code, finding.severity, finding.field) == (
            "SCH-011",
            Severity.INFO,
            "/requires/openaev",
        )
        assert finding.message == (
            "requires.openaev allows versions older than 3.261005.0, where the built-in "
            "contracts were recorded: they were checked on that version only; raise the "
            "minimum to it, or check the scenario on the older versions"
        )


def test_an_external_id_another_entry_has_is_refused_and_names_it() -> None:
    others = {"a": ("scenarios/ransomware/one",), "b": ("scenarios/techniques/two",)}

    finding = _one(duplicate_findings("b", METADATA, others))

    assert (finding.code, finding.severity, finding.path, finding.field) == (
        "SCH-010",
        Severity.BLOCKING,
        METADATA,
        "/external_id",
    )
    assert finding.message == "another entry has this external_id: scenarios/techniques/two"


def test_several_entries_with_the_same_external_id_are_all_named() -> None:
    others = {"b": ("scenarios/techniques/two", "scenarios/ransomware/three")}

    finding = _one(duplicate_findings("b", METADATA, others))

    assert finding.message == (
        "other entries have this external_id: scenarios/ransomware/three, scenarios/techniques/two"
    )


def test_an_external_id_no_other_entry_has_is_fine() -> None:
    assert duplicate_findings("c", METADATA, {"a": ("scenarios/ransomware/one",)}) == ()


def test_a_constraint_the_schema_refuses_gives_no_version_finding() -> None:
    assert version_findings("latest", "3.261005.0", METADATA) == ()


def test_a_version_of_any_length_is_compared_without_failing() -> None:
    huge = "9" * 5000
    assert version_findings(f">=1.{huge}", "3.261005.0", METADATA)  # older: 1 < 3
    assert version_findings(f">=3.{huge}", "3.261005.0", METADATA) == ()
    assert version_findings(">=03.0261005.00", "3.261005.0", METADATA) == ()  # leading zeros


def test_a_wrong_domain_and_a_wrong_slug_are_both_reported() -> None:
    findings = layout_findings("scenarios/Bad/My_Slug", ("scenario.yaml", "scenario.json"), DOMAINS)

    assert [finding.message.split(" ")[1] for finding in findings] == ["domain", "slug"]


def test_many_duplicates_are_named_up_to_three_and_counted() -> None:
    others = {"b": tuple(f"scenarios/techniques/e{n}" for n in range(5))}

    finding = _one(duplicate_findings("b", METADATA, others))

    assert finding.message == (
        "other entries have this external_id: scenarios/techniques/e0, scenarios/techniques/e1, "
        "scenarios/techniques/e2 and 2 more"
    )


def test_four_duplicates_are_three_named_and_one_counted() -> None:
    others = {"b": tuple(f"scenarios/techniques/e{n}" for n in range(4))}

    assert _one(duplicate_findings("b", METADATA, others)).message.endswith(" and 1 more")


def test_the_domains_are_read_from_their_data_document() -> None:
    assert domains_from_document({"domains": ["ransomware", "techniques"]}) == (
        "ransomware",
        "techniques",
    )


@pytest.mark.parametrize(
    "document",
    [
        [],
        {},
        {"domains": "ransomware"},
        {"domains": []},
        {"domains": ["Ransomware"]},
        {"domains": [1]},
    ],
    ids=["not a mapping", "missing", "not a list", "empty", "not kebab-case", "not text"],
)
def test_a_domains_document_that_cannot_be_used_is_refused(document: object) -> None:
    with pytest.raises(ValueError, match="domains"):
        domains_from_document(document)
