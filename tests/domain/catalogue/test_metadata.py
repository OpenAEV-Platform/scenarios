"""Scenario metadata and its cross-checks against the export."""

from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.catalogue.metadata import (
    DESCRIPTION_LIMIT,
    FACET_LIMIT,
    NAME_LIMIT,
    ExportFacts,
    InjectFacts,
    Requirements,
    ScenarioMetadata,
    cross_check,
    is_tabletop,
    starting_metadata,
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


def test_a_communication_inject_that_needs_an_executor_makes_the_scenario_technical() -> None:
    facts = replace(
        FACTS,
        injects=(
            _inject("openaev_email"),
            _inject("openaev_email", needs_executor=True, platforms=frozenset({"Windows"})),
        ),
    )

    assert not is_tabletop(facts, COMMUNICATION)


@given(
    st.lists(
        st.tuples(
            st.sampled_from(["openaev_email", "openaev_manual", "openaev_nmap"]), st.booleans()
        ),
        max_size=4,
    )
)
def test_tabletop_means_communication_only_and_no_executor(
    injects: list[tuple[str, bool]],
) -> None:
    facts = replace(FACTS, injects=tuple(_inject(kind, executor) for kind, executor in injects))

    expected = bool(injects) and all(
        kind in COMMUNICATION and not executor for kind, executor in injects
    )
    assert is_tabletop(facts, COMMUNICATION) == expected


# The starting scenario.yaml of a first preparation

ENTRY = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
DEFAULTS = ["/version", "/status", "/requires/openaev", "/requires/edition"]


def _start(
    facts: ExportFacts = FACTS, **changes: Any
) -> tuple[dict[str, Any], tuple[Finding, ...]]:
    arguments: dict[str, Any] = {
        "external_id": ENTRY,
        "description": "A crisis exercise.",
        "platform_version": "3.261005.0",
        "unknown_injects": 0,
        "path": PATH,
    }
    arguments.update(changes)
    return starting_metadata(facts, **arguments)


def _todo(findings: tuple[Finding, ...]) -> list[str]:
    assert {(f.code, f.severity, f.path) for f in findings} <= {("SCH-007", Severity.INFO, PATH)}
    return [finding.field for finding in findings]


def _message(findings: tuple[Finding, ...], field: str) -> str:
    [finding] = [f for f in findings if f.field == field]
    return finding.message


def test_the_starting_metadata_takes_what_the_export_establishes() -> None:
    metadata, _ = _start()

    assert metadata == {
        "schema_version": 1,
        "external_id": ENTRY,
        "version": "1.0.0",
        "status": "VERIFIED",
        "name": "Akira",
        "description": "A crisis exercise.",
        "severity": "high",
        "category": "global-crisis",
        "main_focus": "incident-response",
        "type": "time-based",
        "platforms": ["Windows"],
        "threat": {},
        "sources": [],
        "requires": {
            "openaev": ">=3.261005.0",
            "edition": "CE",
            "injectors": ["openaev_email", "openaev_implant"],
            "executors": [],
        },
        "payloads": [],
    }
    assert list(metadata) == list(_document())  # the order of the data model


def test_the_starting_metadata_passes_its_own_cross_checks() -> None:
    metadata, _ = _start()
    complete = {**metadata, **{k: _document()[k] for k in ("threat", "sources")}}

    assert cross_check(ScenarioMetadata.from_document(complete), FACTS, PATH) == ()


def test_every_default_and_every_missing_field_is_listed() -> None:
    _, findings = _start()

    # An inject runs through an executor: which one is the contributor's to say.
    assert sorted(_todo(findings)) == sorted([*DEFAULTS, "/threat", "/sources",
                                              "/requires/executors"])  # fmt: skip


def test_the_messages_say_what_to_give_and_in_which_form() -> None:
    _, findings = _start()

    assert "CVE-" in _message(findings, "/threat")
    assert "TLP:CLEAR" in _message(findings, "/sources")
    assert "Windows" in _message(findings, "/requires/executors")
    assert "default" in _message(findings, "/status")
    _, why = _start(replace(FACTS, name="n" * (NAME_LIMIT + 1)))
    assert "write it in scenario.yaml" in _message(why, "/name")  # never rewritten by the tool


def test_a_scenario_with_no_executor_inject_is_generic_and_needs_no_executor() -> None:
    metadata, findings = _start(replace(FACTS, injects=(_inject("openaev_email"),)))

    assert metadata["platforms"] == ["Generic"]
    assert "/requires/executors" not in _todo(findings)


def test_platforms_are_written_in_a_stable_order() -> None:
    implant = _inject("openaev_implant", True, frozenset({"Windows", "Linux", "MacOS"}))

    metadata, _ = _start(replace(FACTS, injects=(implant,)))

    assert metadata["platforms"] == ["Linux", "MacOS", "Windows"]


def test_platforms_the_schema_does_not_know_are_left_out_and_listed() -> None:
    # A payload's platforms come from the contributor.
    implant = _inject("openaev_implant", True, frozenset({"Linux", "x" * 1000}))

    metadata, findings = _start(replace(FACTS, injects=(implant,)))

    assert metadata["platforms"] == ["Linux"]
    assert "1 platform" in _message(findings, "/platforms")
    assert "x" * 100 not in _message(findings, "/platforms")


@pytest.mark.parametrize("description", ["", "   \n"], ids=["empty", "blank"])
def test_an_empty_description_is_left_to_write(description: str) -> None:
    metadata, findings = _start(description=description)

    assert metadata["description"] == ""
    assert "/description" in _todo(findings)


def test_a_description_longer_than_the_schema_allows_is_left_to_write() -> None:
    # Copied whole, it would make a file the reader refuses; the export keeps the text.
    metadata, findings = _start(description="d" * (DESCRIPTION_LIMIT + 1))

    assert metadata["description"] == ""
    assert f"{DESCRIPTION_LIMIT + 1} characters" in _message(findings, "/description")
    kept, findings = _start(description="d" * DESCRIPTION_LIMIT)
    assert kept["description"] == "d" * DESCRIPTION_LIMIT
    assert "/description" not in _todo(findings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "n" * (NAME_LIMIT + 1)),
        ("name", ""),
        ("name", "  "),
        ("category", "c" * (FACET_LIMIT + 1)),
        ("main_focus", "m" * (FACET_LIMIT + 1)),
        ("severity", "High"),
    ],
)
def test_a_facet_the_schema_would_refuse_is_left_empty_and_listed(field: str, value: str) -> None:
    facts = replace(
        FACTS,
        name=value if field == "name" else FACTS.name,
        severity=value if field == "severity" else FACTS.severity,
        category=value if field == "category" else FACTS.category,
        main_focus=value if field == "main_focus" else FACTS.main_focus,
    )
    metadata, findings = _start(facts)

    assert metadata[field] == ""
    assert f"/{field}" in _todo(findings)
    assert value[:50] not in _message(findings, f"/{field}") or not value


def test_injectors_that_cannot_be_established_are_left_to_complete() -> None:
    _, findings = _start(unknown_injects=2)

    assert "2 injects" in _message(findings, "/requires/injectors")
