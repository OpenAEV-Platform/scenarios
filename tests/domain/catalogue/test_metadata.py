"""Scenario metadata and its cross-checks against the export (data model, cross-checks)."""

from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.catalogue.metadata import (
    ExportFacts,
    InjectFacts,
    Requirements,
    ScenarioMetadata,
    cross_check,
    is_tabletop,
)
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Finding, Severity

PATH = "scenarios/ransomware/akira/scenario.yaml"
COMMUNICATION = frozenset({"openaev_email", "openaev_manual"})


def _document(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 1,
        "external_id": "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
        "version": "1.0.0",
        "status": "VERIFIED",
        "name": "Akira",
        "description": "A crisis exercise.",
        "severity": "high",
        "category": "global-crisis",
        "main_focus": "incident-response",
        "type": "time-based",
        "platforms": ["Windows", "Linux"],
        "threat": {"ttps": ["T1486"]},
        "sources": [{"url": "https://example.com/", "tlp": "TLP:CLEAR"}],
        "requires": {
            "openaev": ">=3.260923",
            "edition": "CE",
            "injectors": ["openaev_implant", "openaev_email"],
            "executors": [],
        },
        "payloads": [],
    }
    document.update(changes)
    return document


def _metadata(**changes: Any) -> ScenarioMetadata:
    return replace(ScenarioMetadata.from_document(_document()), **changes)


def _inject(
    injector_type: str, needs_executor: bool = False, platforms: frozenset[str] = frozenset()
) -> InjectFacts:
    return InjectFacts(injector_type, needs_executor, platforms)


FACTS = ExportFacts(
    name="Akira",
    severity="high",
    category="global-crisis",
    main_focus="incident-response",
    injects=(
        _inject("openaev_email", platforms=frozenset({"Service"})),
        _inject("openaev_implant", needs_executor=True, platforms=frozenset({"Windows"})),
    ),
)


# Reading a document valid against the schema


def test_metadata_is_read_from_a_schema_valid_document() -> None:
    metadata = ScenarioMetadata.from_document(_document())

    assert metadata == ScenarioMetadata(
        external_id="5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
        version="1.0.0",
        status="VERIFIED",
        name="Akira",
        severity="high",
        category="global-crisis",
        main_focus="incident-response",
        type="time-based",
        platforms=frozenset({"Windows", "Linux"}),
        requires=Requirements(
            openaev=">=3.260923",
            edition="CE",
            injectors=frozenset({"openaev_implant", "openaev_email"}),
            executors=frozenset(),
        ),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"name": 3},
        {"name": None},
        {"platforms": "Windows"},
        {"platforms": ["Windows", 1]},
        {"requires": ["CE"]},
        {"requires": {"openaev": ">=1", "edition": "CE", "injectors": [], "executors": None}},
    ],
)
def test_a_document_that_does_not_follow_the_schema_is_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"scenario\.yaml"):
        ScenarioMetadata.from_document(_document(**changes))


def test_a_missing_field_is_refused() -> None:
    document = _document()
    del document["main_focus"]

    with pytest.raises(ValueError, match="main_focus"):
        ScenarioMetadata.from_document(document)


# Cross-checks


def test_metadata_that_matches_its_export_has_no_finding() -> None:
    assert cross_check(_metadata(), FACTS, PATH) == ()


@pytest.mark.parametrize(
    ("field", "pointer"),
    [
        ("name", "/name"),
        ("severity", "/severity"),
        ("category", "/category"),
        ("main_focus", "/main_focus"),
    ],
)
def test_a_name_or_facet_that_differs_from_the_export_is_reported(field: str, pointer: str) -> None:
    findings = cross_check(_metadata(**{field: "other"}), FACTS, PATH)

    assert len(findings) == 1
    assert findings[0].code == "SCH-002"
    assert findings[0].severity is Severity.BLOCKING
    assert (findings[0].path, findings[0].field) == (PATH, pointer)
    assert "'other'" in findings[0].message
    assert repr(getattr(FACTS, field)) in findings[0].message


def test_names_are_compared_exactly() -> None:
    findings = cross_check(_metadata(name="akira "), FACTS, PATH)

    assert [finding.code for finding in findings] == ["SCH-002"]


def test_each_differing_facet_is_its_own_finding() -> None:
    findings = cross_check(_metadata(severity="low", category="other"), FACTS, PATH)

    assert sorted(finding.field for finding in findings) == ["/category", "/severity"]


def _requires(injectors: set[str]) -> Requirements:
    return replace(_metadata().requires, injectors=frozenset(injectors))


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        ({"openaev_email"}, "missing: openaev_implant"),
        ({"openaev_email", "openaev_implant", "openaev_sms"}, "not used: openaev_sms"),
        ({"openaev_sms", "openaev_email"}, "missing: openaev_implant; not used: openaev_sms"),
        (set(), "missing: openaev_email, openaev_implant"),
    ],
)
def test_injectors_that_differ_from_the_injects_are_reported(
    declared: set[str], expected: str
) -> None:
    findings = cross_check(_metadata(requires=_requires(declared)), FACTS, PATH)

    assert [(finding.code, finding.field) for finding in findings] == [
        ("SCH-003", "/requires/injectors")
    ]
    assert findings[0].message.endswith(expected)


def test_a_platform_of_an_inject_that_needs_an_executor_must_be_declared() -> None:
    findings = cross_check(_metadata(platforms=frozenset({"Linux"})), FACTS, PATH)

    assert [(finding.code, finding.field) for finding in findings] == [("SCH-004", "/platforms")]
    assert findings[0].message.endswith("missing: Windows")


def test_missing_platforms_are_all_named_in_order() -> None:
    facts = replace(
        FACTS,
        injects=(
            *FACTS.injects,
            _inject("openaev_implant", needs_executor=True, platforms=frozenset({"Linux"})),
        ),
    )

    findings = cross_check(_metadata(platforms=frozenset()), facts, PATH)

    assert findings[0].message.endswith("missing: Linux, Windows")


def test_platforms_are_a_facet_the_contributor_may_widen() -> None:
    metadata = _metadata(platforms=frozenset({"Windows", "Linux", "MacOS", "Generic"}))

    assert cross_check(metadata, FACTS, PATH) == ()


def test_platforms_of_injects_without_an_executor_are_not_required() -> None:
    facts = replace(FACTS, injects=(_inject("openaev_email", platforms=frozenset({"Service"})),))
    metadata = _metadata(platforms=frozenset(), requires=_requires({"openaev_email"}))

    assert cross_check(metadata, facts, PATH) == ()


def test_an_inject_that_needs_an_executor_without_a_platform_requires_none() -> None:
    facts = replace(FACTS, injects=(_inject("openaev_implant", needs_executor=True),))
    metadata = _metadata(platforms=frozenset(), requires=_requires({"openaev_implant"}))

    assert cross_check(metadata, facts, PATH) == ()


names = st.sampled_from(["a", "b", "c"])
name_sets = st.frozensets(names)


@given(
    facet=names,
    declared_injectors=name_sets,
    used=st.lists(st.tuples(names, st.booleans(), name_sets), max_size=4),
    platforms=name_sets,
)
def test_cross_check_reports_exactly_the_rules_that_are_broken(
    facet: str,
    declared_injectors: frozenset[str],
    used: list[tuple[str, bool, frozenset[str]]],
    platforms: frozenset[str],
) -> None:
    facts = ExportFacts("a", "a", "a", "a", tuple(_inject(*inject) for inject in used))
    metadata = _metadata(
        name=facet,
        severity="a",
        category="a",
        main_focus="a",
        platforms=platforms,
        requires=_requires(set(declared_injectors)),
    )
    required = {p for kind, executor, targets in used if executor for p in targets}

    codes = {finding.code for finding in cross_check(metadata, facts, PATH)}

    assert ("SCH-002" in codes) == (facet != "a")
    assert ("SCH-003" in codes) == (declared_injectors != {kind for kind, _, _ in used})
    assert ("SCH-004" in codes) == (not required <= platforms)
    assert all(isinstance(finding, Finding) for finding in cross_check(metadata, facts, PATH))


# Tabletop, derived from the communication injector list


def test_a_scenario_whose_injects_all_communicate_is_tabletop() -> None:
    facts = replace(FACTS, injects=(_inject("openaev_email"), _inject("openaev_manual")))

    assert is_tabletop(facts, COMMUNICATION)


def test_one_injector_outside_the_list_makes_the_scenario_technical() -> None:
    facts = replace(FACTS, injects=(_inject("openaev_email"), _inject("openaev_nmap")))

    assert not is_tabletop(facts, COMMUNICATION)


def test_a_scenario_without_any_inject_is_technical() -> None:
    assert not is_tabletop(replace(FACTS, injects=()), COMMUNICATION)


def test_values_from_the_export_are_never_echoed_in_full() -> None:
    facts = replace(
        FACTS,
        name="x" * 100_000,
        injects=(
            *FACTS.injects,
            _inject("y" * 100_000, needs_executor=True, platforms=frozenset({"z" * 100_000})),
        ),
    )

    findings = cross_check(_metadata(), facts, PATH)

    assert [finding.code for finding in findings] == ["SCH-002", "SCH-003", "SCH-004"]
    assert all(len(finding.message) <= MESSAGE_LIMIT for finding in findings)
