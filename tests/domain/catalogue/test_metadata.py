"""Scenario metadata and its cross-checks against the export."""

import hashlib
import unicodedata
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.catalogue.metadata import (
    DESCRIPTION_LIMIT,
    FACET_LIMIT,
    INJECTORS_LIMIT,
    NAME_LIMIT,
    STARTING_EDITION_OF_A_WORKFLOW,
    TYPE_WITHOUT_WORKFLOW,
    WORKFLOW_NEEDS_EE,
    WORKFLOW_NOT_CHAINED,
    ExportFacts,
    InjectFacts,
    Requirements,
    ScenarioMetadata,
    bound,
    clean,
    communication_injectors_from_document,
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
    has_workflow=False,
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
    facts = ExportFacts("a", "a", "a", "a", tuple(_inject(*inject) for inject in used), False)
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


def _asks_nothing(findings: tuple[Finding, ...], field: str) -> bool:
    [finding] = [f for f in findings if f.field == field]
    return finding.asks_nothing


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


@pytest.mark.parametrize(
    "description", ["", "   \n", chr(0x0B)], ids=["empty", "blank", "other white space"]
)
def test_an_empty_description_is_left_to_write(description: str) -> None:
    metadata, findings = _start(description=description)

    assert metadata["description"] == ""
    assert "/description" in _todo(findings)


def test_a_description_too_long_with_no_place_to_cut_is_left_to_write() -> None:
    # Copied whole, it would make a file the reader refuses; the export keeps the text.
    text = "d" * (DESCRIPTION_LIMIT + 1)
    metadata, findings = _start(description=text)

    assert metadata["description"] == ""
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert _message(findings, "/description") == (
        f"the export's description has {DESCRIPTION_LIMIT + 1} characters, more than "
        f"{DESCRIPTION_LIMIT} (SHA-256 {digest}), and no paragraph, sentence or word end between "
        f"1000 and {DESCRIPTION_LIMIT - 1} characters to cut at: write a shorter one; "
        "scenario.json keeps the whole text"
    )
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


def test_injects_whose_contract_is_unknown_leave_platforms_and_executors_to_check() -> None:
    # Their facts are unknown: they may run on an endpoint through an executor.
    metadata, findings = _start(replace(FACTS, injects=()), unknown_injects=2)

    assert metadata["platforms"] == ["Generic"]
    assert "2 injects" in _message(findings, "/platforms")
    assert "2 injects" in _message(findings, "/requires/executors")


def test_both_reasons_are_given_when_a_field_has_two() -> None:
    implant = _inject("openaev_implant", True, frozenset({"Linux", "x" * 10}))

    _, findings = _start(replace(FACTS, injects=(implant,)), unknown_injects=1)

    platforms = _message(findings, "/platforms")
    assert "1 platform" in platforms
    assert "1 inject" in platforms
    executors = _message(findings, "/requires/executors")
    assert "Linux" in executors
    assert "1 inject" in executors


@pytest.mark.parametrize(
    ("count", "words"),
    [(1, "1 inject uses a contract"), (2, "2 injects use a contract")],
)
def test_the_unknown_contracts_are_counted_in_plain_words(count: int, words: str) -> None:
    _, findings = _start(unknown_injects=count)

    assert words in _message(findings, "/requires/injectors")


def test_more_injector_types_than_the_schema_allows_are_left_to_complete() -> None:
    injects = tuple(_inject(f"injector_{n:02}") for n in range(INJECTORS_LIMIT + 1))

    metadata, findings = _start(replace(FACTS, injects=injects))

    assert metadata["requires"]["injectors"] == []
    assert f"{INJECTORS_LIMIT + 1} injector types" in _message(findings, "/requires/injectors")
    within, findings = _start(replace(FACTS, injects=injects[:INJECTORS_LIMIT]))
    assert len(within["requires"]["injectors"]) == INJECTORS_LIMIT


# The texts of the starting scenario.yaml, cleaned. Characters are written by code point.

NEL, LS, PS, NBSP, IDEOGRAPHIC = chr(0x85), chr(0x2028), chr(0x2029), chr(0xA0), chr(0x3000)


@pytest.mark.parametrize(
    ("text", "cleaned"),
    [
        ("a\r\nb\rc", "a\nb\nc"),
        (f"a{NEL}b{LS}c{PS}d", "a\nb\nc\nd"),
        ("a \t\nb", "a\nb"),
        (f"a{NBSP}{IDEOGRAPHIC}\nb", "a\nb"),
        ("\n\n  a\n  b\n\n", "  a\n  b"),
        ("a\n\n\nb", "a\n\n\nb"),
        (f"a{NBSP}b", f"a{NBSP}b"),
    ],
    ids=[
        "crlf and cr",
        "unicode breaks",
        "trailing tab",
        "trailing zs",
        "outer",
        "blank lines",
        "inner",
    ],
)
def test_a_text_is_cleaned_of_breaks_trailing_blanks_and_outer_blanks(
    text: str, cleaned: str
) -> None:
    assert clean(text).text == cleaned


def test_what_cleaning_changed_is_counted() -> None:
    cleaned = clean(f"\n a  \r\nb\t{LS}c  \nd \n")

    assert cleaned.text == " a\nb\nc\nd"  # the first line's indentation is kept
    assert (cleaned.breaks, cleaned.trimmed, cleaned.hard_breaks, cleaned.outer) == (2, 4, 2, True)


@pytest.mark.parametrize(
    "text",
    ["a  \n", "a  ", "a  \n\nb", "a\n  \nb", "  \na", "a  \n  \n", "a \nb"],
    ids=[
        "then a break",
        "at the end",
        "before a blank line",
        "blank line",
        "leading",
        "trailing",
        "one space",
    ],
)
def test_two_spaces_with_no_line_of_text_after_are_no_hard_break(text: str) -> None:
    assert clean(text).hard_breaks == 0


def test_every_unicode_space_ending_a_line_is_trimmed() -> None:
    spaces = [chr(code) for code in range(0x110000) if unicodedata.category(chr(code)) == "Zs"]

    assert all(clean(f"a{space}\nb").text == "a\nb" for space in spaces)


def test_a_clean_text_is_unchanged_and_counts_nothing() -> None:
    cleaned = clean("a\n  b")

    assert (cleaned.text, cleaned.breaks, cleaned.trimmed, cleaned.hard_breaks, cleaned.outer) == (
        "a\n  b",
        0,
        0,
        0,
        False,
    )


@given(
    st.one_of(
        st.text(max_size=60),
        st.text(
            alphabet=st.sampled_from(["a", " ", "\t", "\n", "\r", NEL, LS, PS, NBSP]), max_size=30
        ),
    )
)
def test_cleaning_twice_changes_nothing(text: str) -> None:
    once = clean(text).text

    assert clean(once).text == once
    assert not clean(once).changed


def test_the_description_is_cleaned_and_what_changed_is_reported_by_counts() -> None:
    metadata, findings = _start(description="Steps:  \r\n1. scan  \r\n2. report \n")

    assert metadata["description"] == "Steps:\n1. scan\n2. report"
    message = _message(findings, "/description")
    assert message == (
        "the export's description was cleaned for scenario.yaml: 2 line breaks unified, "
        "3 line ends trimmed, the blank lines around the text removed; 2 Markdown hard breaks "
        "(two spaces ending a line) are lost: check its layout"
    )
    assert "scan" not in message


def test_a_single_change_is_said_in_the_singular() -> None:
    _, findings = _start(description="a  \rb")

    assert _message(findings, "/description") == (
        "the export's description was cleaned for scenario.yaml: 1 line break unified, "
        "1 line end trimmed; 1 Markdown hard break (two spaces ending a line) is lost: "
        "check its layout"
    )
    assert not _asks_nothing(findings, "/description")


def test_a_description_with_only_blank_lines_around_says_so() -> None:
    metadata, findings = _start(description="\nA crisis exercise.\n")

    assert metadata["description"] == "A crisis exercise."
    assert _message(findings, "/description") == (
        "the export's description was cleaned for scenario.yaml: the blank lines around the "
        "text removed; nothing to do"
    )
    assert _asks_nothing(findings, "/description")
    assert [field for field in _todo(findings) if _asks_nothing(findings, field)] == [
        "/description"
    ]


def test_a_clean_description_is_not_reported() -> None:
    _, findings = _start(description="A crisis exercise.\n\nIn two phases.")

    assert "/description" not in _todo(findings)


def test_the_bound_applies_to_the_cleaned_description() -> None:
    metadata, findings = _start(description="d" * DESCRIPTION_LIMIT + " \n ")

    assert metadata["description"] == "d" * DESCRIPTION_LIMIT
    assert "cleaned" in _message(findings, "/description")
    too_long, findings = _start(description="d" * (DESCRIPTION_LIMIT + 1) + " ")
    assert too_long["description"] == ""
    assert f"{DESCRIPTION_LIMIT + 1} characters once cleaned, more" in _message(
        findings, "/description"
    )


@pytest.mark.parametrize("field", ["name", "category", "main_focus"])
@pytest.mark.parametrize(
    ("value", "what"),
    [
        ("Crisis ", "blanks around it"),
        (" Crisis", "blanks around it"),
        ("\nCrisis", "blanks around it"),
        ("Crisis\r\nexercise", "line breaks other than \\n"),
        ("Crisis  \nexercise", "blanks ending a line"),
    ],
    ids=["after", "before", "before a line", "break", "inner line end"],
)
def test_a_name_or_facet_that_would_need_cleaning_is_copied_as_it_is_and_listed(
    field: str, value: str, what: str
) -> None:
    facts = replace(
        FACTS,
        name=value if field == "name" else FACTS.name,
        category=value if field == "category" else FACTS.category,
        main_focus=value if field == "main_focus" else FACTS.main_focus,
    )

    metadata, findings = _start(facts)

    assert metadata[field] == value  # it must equal the export's
    assert _message(findings, f"/{field}") == (
        f"the export's {field} has {what}: kept as it is, since it must equal the export's; "
        "fix it on the platform when you can, export the scenario again and write it in "
        "scenario.yaml too"
    )


# A description over its bound, cut where a reader can tell, and marked.

MARK = chr(0x2026)


def _words(count: int, word: str = "word") -> str:
    return " ".join([word] * count)


def test_a_text_within_the_bound_is_kept_whole() -> None:
    text = "a" * DESCRIPTION_LIMIT

    assert bound(text) == (text, "")


def test_a_long_text_is_cut_at_its_last_paragraph_break_in_reach() -> None:
    first = "First paragraph. " * 70  # about 1,190 characters
    text = f"{first.strip()}\n\nSecond. " + "More words here. " * 100

    kept, kind = bound(text)

    assert kept == first.strip() + MARK
    assert kind == "paragraph"


def test_without_a_paragraph_break_it_is_cut_at_a_sentence_end() -> None:
    text = "One sentence ends here. " * 120  # 2,880 characters

    kept, kind = bound(text)

    assert kept.endswith(f"here.{MARK}")
    assert len(kept) <= DESCRIPTION_LIMIT
    assert len(kept) > DESCRIPTION_LIMIT - 30  # the last sentence end in reach
    assert kind == "sentence"


@pytest.mark.parametrize("end", ["!", "?"])
def test_a_sentence_may_end_with_an_exclamation_or_a_question(end: str) -> None:
    text = f"Is it a sentence{end} " * 150

    kept, kind = bound(text)

    assert kept.endswith(f"sentence{end}{MARK}")
    assert kind == "sentence"


def test_without_a_sentence_end_it_is_cut_at_a_blank() -> None:
    kept, kind = bound(_words(600))

    assert kept.endswith(f"word{MARK}")
    assert len(kept) <= DESCRIPTION_LIMIT
    assert kind == "word"


def test_a_cut_that_would_end_with_a_colon_is_skipped() -> None:
    head = "x" * 1500
    text = f"{head} items:\n\n- a\n- b " + "y" * 600

    kept, kind = bound(text)

    assert not kept.removesuffix(MARK).rstrip().endswith(":")
    assert kind == "word"


def test_a_place_to_cut_before_1000_characters_is_not_taken() -> None:
    text = "a" * 500 + "\n\n" + "b" * 2000

    assert bound(text) == ("", "")


def test_a_cut_never_exceeds_the_bound_with_its_mark() -> None:
    text = "w" * (DESCRIPTION_LIMIT - 1) + " " + "z" * 50

    kept, kind = bound(text)

    assert kept == "w" * (DESCRIPTION_LIMIT - 1) + MARK
    assert len(kept) == DESCRIPTION_LIMIT
    assert kind == "word"


def test_a_long_description_is_cut_and_marked_and_reported_without_the_text() -> None:
    text = ("Intro paragraph. " * 70).strip() + "\n\nDropped secret part." * 60

    metadata, findings = _start(description=text)

    assert metadata["description"].endswith(MARK)
    assert len(metadata["description"]) <= DESCRIPTION_LIMIT
    message = _message(findings, "/description")
    digest = hashlib.sha256(text.encode()).hexdigest()
    assert message == (
        f"the export's description has {len(text)} characters, more than {DESCRIPTION_LIMIT} "
        f"(SHA-256 {digest}): cut at a paragraph end and marked {MARK}; review the cut, close any "
        "code block or link left open, remove the mark; scenario.json keeps the whole text"
    )
    assert "Dropped" not in message


def test_a_cut_may_keep_exactly_the_floor() -> None:
    text = "a" * 1000 + " " + "b" * 1500

    assert bound(text) == ("a" * 1000 + MARK, "word")


def test_a_place_that_would_keep_the_whole_bound_is_not_taken() -> None:
    text = "w" * DESCRIPTION_LIMIT + " " + "z" * 50  # its mark would exceed the bound

    assert bound(text) == ("", "")


def test_no_blank_is_left_before_the_mark() -> None:
    text = "  ".join(["word"] * 500)  # two blanks between words

    kept, _ = bound(text)

    assert kept.endswith(f"word{MARK}")


def test_the_digest_is_of_the_export_s_description_as_it_is() -> None:
    text = ("Intro paragraph. " * 70).strip() + "  \n\nMore." * 200  # cleaning changes it

    _, findings = _start(description=text)

    assert hashlib.sha256(text.encode()).hexdigest() in _message(findings, "/description")


@pytest.mark.parametrize(
    "text",
    ["a" * 990 + " " * 20 + "b" * 1500, " " * 1500 + "x" * 600],
    ids=["blanks before the floor", "only blanks before"],
)
def test_a_cut_that_would_keep_less_than_the_floor_is_not_taken(text: str) -> None:
    assert bound(text) == ("", "")


def test_the_report_of_a_huge_description_keeps_its_whole_digest() -> None:
    text = "Some words. " * 2_000_000  # 24,000,000 characters, more than an export may hold

    _, findings = _start(description=text)

    message = _message(findings, "/description")
    assert hashlib.sha256(text.encode()).hexdigest() in message
    assert len(message) <= MESSAGE_LIMIT


def test_a_paragraph_break_at_the_last_position_in_reach_is_found() -> None:
    head = "a" * (DESCRIPTION_LIMIT - 1)  # the break starts where the last cut may be

    assert bound(head + "\n\n" + "b" * 100) == (head + MARK, "paragraph")


def test_the_communication_injectors_from_document_are_those_the_maintainers_list() -> None:
    document = {"injectors": ["openaev_email", "openaev_manual"]}

    assert communication_injectors_from_document(document) == frozenset(
        {"openaev_email", "openaev_manual"}
    )


@pytest.mark.parametrize(
    "document",
    [None, {}, {"injectors": []}, {"injectors": "openaev_email"}, {"injectors": [""]},
     {"injectors": [1]}, {"injectors": ["a", "a"]}, {"injectors": ["a"], "more": 1}],
)  # fmt: skip
def test_a_list_of_communication_injectors_from_document_out_of_its_shape_is_refused(
    document: Any,
) -> None:
    with pytest.raises(ValueError, match="tabletop-injectors"):
        communication_injectors_from_document(document)


# A scenario in chaining


CHAINED = replace(FACTS, has_workflow=True)


def _sch_013(metadata: ScenarioMetadata, facts: ExportFacts) -> list[tuple[str, str]]:
    return [(f.field, f.message) for f in cross_check(metadata, facts, PATH) if f.code == "SCH-013"]


def test_a_workflow_with_type_chained_and_edition_ee_passes() -> None:
    metadata = _metadata(type="chained", requires=replace(_metadata().requires, edition="EE"))
    assert _sch_013(metadata, CHAINED) == []


def test_type_chained_without_a_workflow_is_refused() -> None:
    assert _sch_013(_metadata(type="chained"), FACTS) == [("/type", TYPE_WITHOUT_WORKFLOW)]


def test_a_workflow_with_type_time_based_is_refused() -> None:
    metadata = _metadata(requires=replace(_metadata().requires, edition="EE"))
    assert _sch_013(metadata, CHAINED) == [("/type", WORKFLOW_NOT_CHAINED)]


def test_a_workflow_with_another_edition_is_refused() -> None:
    assert _sch_013(_metadata(type="chained"), CHAINED) == [
        ("/requires/edition", WORKFLOW_NEEDS_EE)
    ]


def test_each_case_is_its_own_finding() -> None:
    assert _sch_013(_metadata(), CHAINED) == [
        ("/type", WORKFLOW_NOT_CHAINED),
        ("/requires/edition", WORKFLOW_NEEDS_EE),
    ]


def test_a_time_based_scenario_may_need_the_enterprise_edition() -> None:
    metadata = _metadata(requires=replace(_metadata().requires, edition="EE"))
    assert _sch_013(metadata, FACTS) == []


def test_a_scenario_in_chaining_is_never_tabletop() -> None:
    facts = replace(CHAINED, injects=(_inject("openaev_email"), _inject("openaev_manual")))
    assert not is_tabletop(facts, COMMUNICATION)


def test_the_starting_metadata_of_a_workflow_is_chained_and_needs_ee() -> None:
    metadata, findings = _start(CHAINED)
    assert (metadata["type"], metadata["requires"]["edition"]) == ("chained", "EE")
    assert _message(findings, "/requires/edition") == STARTING_EDITION_OF_A_WORKFLOW
    assert _asks_nothing(findings, "/requires/edition")
    complete = {**metadata, **{k: _document()[k] for k in ("threat", "sources")}}
    assert cross_check(ScenarioMetadata.from_document(complete), CHAINED, PATH) == ()
