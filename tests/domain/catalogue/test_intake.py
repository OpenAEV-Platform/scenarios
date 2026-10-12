"""Intake: a request and an export become an entry, unless the catalogue says the request is
wrong; and a plan, the same for the same inputs, that a pull request is opened from."""

import json
from typing import Any

import pytest

from scenario_tools.domain.catalogue.intake import (
    CatalogueEntry,
    IntakeRequest,
    domain_refusals,
    intake_plan,
    intake_refusals,
    same_name,
)
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.shared.title import check_pull_request_title

ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
OTHER = "0b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
REQUEST = "request.yaml"
EXPORT = "export.zip"
DOCUMENT: dict[str, Any] = {
    "mode": "new",
    "external_id": ID,
    "domain": "ransomware",
    "slug": "akira-crisis",
    "threat": {"ttps": ["T1486"]},
    "sources": [{"url": "https://example.org", "tlp": "TLP:CLEAR"}],
    "generated_by": "run 42",
    "issue": 12,
}


def _request(**changes: Any) -> IntakeRequest:
    return IntakeRequest.from_document({**DOCUMENT, **changes})


def _codes(findings: tuple[Finding, ...]) -> list[tuple[str, str, str]]:
    assert {finding.severity for finding in findings} <= {Severity.BLOCKING}
    return [(finding.code, finding.path, finding.field) for finding in findings]


def _refusals(
    request: IntakeRequest, name: str = "Akira crisis", *entries: CatalogueEntry
) -> tuple[Finding, ...]:
    return intake_refusals(request, name, entries, request_path=REQUEST, export_path=EXPORT)


def test_a_request_is_read_with_its_entry_place() -> None:
    request = _request()

    assert (request.mode, request.external_id, request.entry) == (
        "new",
        ID,
        "scenarios/ransomware/akira-crisis",
    )
    assert (request.issue, request.rewrite, request.generated_by) == (12, False, "run 42")
    assert request.metadata() == {
        "threat": {"ttps": ["T1486"]},
        "sources": [{"url": "https://example.org", "tlp": "TLP:CLEAR"}],
        "generated_by": "run 42",
    }


def test_a_new_entry_in_an_empty_catalogue_is_accepted() -> None:
    assert _refusals(_request()) == ()


def test_a_new_entry_whose_identifier_is_taken_is_refused() -> None:
    taken = CatalogueEntry("scenarios/techniques/other", ID, "Other")

    findings = _refusals(_request(), "Akira crisis", taken)

    assert _codes(findings) == [("ITK-001", REQUEST, "/external_id")]
    assert "scenarios/techniques/other" in findings[0].message


def test_a_new_entry_whose_place_is_taken_is_refused() -> None:
    there = CatalogueEntry("scenarios/ransomware/akira-crisis", OTHER, "Other")

    assert _codes(_refusals(_request(), "Akira crisis", there)) == [("ITK-002", REQUEST, "/slug")]


def test_a_new_entry_whose_place_holds_anything_is_refused() -> None:
    findings = intake_refusals(
        _request(), "Akira crisis", (), request_path=REQUEST, export_path=EXPORT, place_taken=True
    )

    assert _codes(findings) == [("ITK-002", REQUEST, "/slug")]


def test_a_new_entry_whose_name_is_taken_is_refused() -> None:
    named = CatalogueEntry("scenarios/techniques/other", OTHER, "Akira crisis")

    findings = _refusals(_request(), "Akira crisis", named)

    assert _codes(findings) == [("ITK-003", EXPORT, "")]
    assert "scenarios/techniques/other" in findings[0].message


@pytest.mark.parametrize("mode", ["new", "update"])
def test_a_catalogue_holding_an_entry_that_cannot_be_read_refuses_the_request(mode: str) -> None:
    unreadable = CatalogueEntry("scenarios/techniques/broken", "", "", readable=False)
    entry = CatalogueEntry("scenarios/ransomware/akira-crisis", ID, "Akira crisis")

    findings = _refusals(_request(mode=mode), "Akira crisis", entry, unreadable)

    assert _codes(findings) == [("ITK-008", REQUEST, "")]
    assert "scenarios/techniques/broken" in findings[0].message


def test_an_update_of_an_unknown_entry_is_refused() -> None:
    assert _codes(_refusals(_request(mode="update"))) == [("ITK-004", REQUEST, "/external_id")]


def test_an_update_elsewhere_than_the_entry_is_refused() -> None:
    entry = CatalogueEntry("scenarios/techniques/akira", ID, "Akira crisis")

    findings = _refusals(_request(mode="update"), "Akira crisis", entry)

    assert _codes(findings) == [("ITK-005", REQUEST, "/domain")]  # the field that differs
    assert "scenarios/techniques/akira" in findings[0].message
    elsewhere = CatalogueEntry("scenarios/ransomware/akira", ID, "Akira crisis")
    assert _codes(_refusals(_request(mode="update"), "Akira crisis", elsewhere)) == [
        ("ITK-005", REQUEST, "/slug")
    ]


@pytest.mark.parametrize("first", [True, False], ids=["listed-first", "listed-last"])
def test_an_update_of_an_identifier_several_entries_have_is_refused(first: bool) -> None:
    entry = CatalogueEntry("scenarios/ransomware/akira-crisis", ID, "Akira crisis")
    other = CatalogueEntry("scenarios/techniques/akira", ID, "Akira")

    findings = _refusals(
        _request(mode="update"), "Akira crisis", *([entry, other][:: 1 if first else -1])
    )

    assert _codes(findings) == [("ITK-001", REQUEST, "/external_id")]
    assert "scenarios/ransomware/akira-crisis, scenarios/techniques/akira" in findings[0].message


def test_an_update_with_another_scenario_name_is_refused_unless_rewritten() -> None:
    entry = CatalogueEntry("scenarios/ransomware/akira-crisis", ID, "Akira crisis")

    assert _codes(_refusals(_request(mode="update"), "Black Basta", entry)) == [
        ("ITK-006", EXPORT, "")
    ]
    assert _refusals(_request(mode="update", rewrite=True), "Black Basta", entry) == ()
    assert _refusals(_request(mode="update"), "Akira crisis", entry) == ()


def _plan(**changes: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "base": "a" * 40,
        "changed": True,
        "files": {
            "scenarios/ransomware/akira-crisis/scenario.yaml": "1" * 64,
            "scenarios/ransomware/akira-crisis/scenario.json": "2" * 64,
        },
        "checklist": (),
    }
    arguments.update(changes)
    return intake_plan(_request(**arguments.pop("request", {})), **arguments)


def test_the_plan_names_the_entry_its_files_and_its_pull_request() -> None:
    plan = _plan()

    assert plan["mode"] == "new"
    assert plan["entry"] == "scenarios/ransomware/akira-crisis"
    assert plan["base"] == "a" * 40
    assert plan["changed"] is True
    assert plan["files"] == [
        {"path": "scenarios/ransomware/akira-crisis/scenario.json", "sha256": "2" * 64},
        {"path": "scenarios/ransomware/akira-crisis/scenario.yaml", "sha256": "1" * 64},
    ]
    assert plan["title"] == "feat(scenarios): add akira-crisis (#12)"
    assert plan["body"].startswith("Closes #12\n")


@pytest.mark.parametrize("mode", ["new", "update"])
def test_the_title_follows_the_convention(mode: str) -> None:
    title = _plan(request={"mode": mode})["title"]

    assert check_pull_request_title(title) is None
    assert title.startswith(f"feat(scenarios): {'add' if mode == 'new' else 'update'} ")
    longest = {"mode": mode, "slug": "a" * 64, "issue": 2**53 - 1}  # the request's bounds
    assert check_pull_request_title(_plan(request=longest)["title"]) is None


def test_the_same_inputs_give_the_same_plan() -> None:
    assert json.dumps(_plan(), sort_keys=True) == json.dumps(_plan(), sort_keys=True)


def test_the_body_lists_what_is_left_as_inert_text() -> None:
    hostile = Finding(
        "SCH-007",
        Severity.INFO,
        "scenarios/ransomware/akira-crisis/scenario.yaml",
        "/requires/executors",
        "name @team the <b>executors</b> `now`",
    )

    body = _plan(checklist=(hostile,))["body"]

    line = next(line for line in body.splitlines() if line.startswith("- [ ]"))
    assert line == (
        "- [ ] `scenarios/ransomware/akira-crisis/scenario.yaml` `/requires/executors`: "
        "`name @team the <b>executors</b> 'now'`"
    )
    assert "`" + "1" * 64 + "`" in body  # the digests


def test_an_unchanged_update_plans_nothing_to_propose() -> None:
    plan = _plan(request={"mode": "update"}, changed=False, files={})

    assert plan["changed"] is False
    assert plan["files"] == []
    assert "nothing to propose" in plan["body"]
    assert "Files:" not in plan["body"]


def test_a_request_without_generated_by_gives_no_such_field() -> None:
    document = {key: value for key, value in DOCUMENT.items() if key != "generated_by"}

    assert "generated_by" not in IntakeRequest.from_document(document).metadata()


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("Akira crisis", "akira  CRISIS"),
        ("Akira crisis", " Akira crisis "),
        (
            "Akira crisis",
            "".join(chr(0xFF21 + ord(c) - ord("A")) if c == "A" else c for c in "Akira crisis"),
        ),
    ],
    ids=["case and spaces", "outer blanks", "compatibility form"],
)
def test_names_are_the_same_whatever_their_case_spacing_or_form(first: str, second: str) -> None:
    assert same_name(first, second)
    assert not same_name(first, "Black Basta")


def test_a_new_entry_whose_name_is_taken_in_another_form_is_refused() -> None:
    named = CatalogueEntry("scenarios/techniques/other", OTHER, "AKIRA  crisis")

    assert _codes(_refusals(_request(), "Akira crisis", named)) == [("ITK-003", EXPORT, "")]


def test_an_update_differing_only_in_case_is_the_same_scenario() -> None:
    entry = CatalogueEntry("scenarios/ransomware/akira-crisis", ID, "Akira Crisis")

    assert _refusals(_request(mode="update"), "akira crisis", entry) == ()


def test_an_export_without_a_name_takes_no_entry_s_name() -> None:
    nameless = CatalogueEntry("scenarios/techniques/other", OTHER, "")

    assert _refusals(_request(), "", nameless) == ()  # normalisation says why it has none


def test_a_rename_to_another_entry_s_name_is_refused() -> None:
    entry = CatalogueEntry("scenarios/ransomware/akira-crisis", ID, "Akira crisis")
    other = CatalogueEntry("scenarios/techniques/basta", OTHER, "Black Basta")

    findings = _refusals(_request(mode="update", rewrite=True), "Black Basta", entry, other)

    assert _codes(findings) == [("ITK-003", EXPORT, "")]


def test_the_rewrite_advice_says_scenario_yaml_is_to_align() -> None:
    entry = CatalogueEntry("scenarios/ransomware/akira-crisis", ID, "Akira crisis")

    [finding] = _refusals(_request(mode="update"), "Black Basta", entry)

    assert "align scenario.yaml" in finding.message


def test_a_domain_outside_the_catalogue_is_refused() -> None:
    findings = domain_refusals(_request(domain="malware"), ("ransomware", "techniques"), REQUEST)

    assert _codes(findings) == [("SCH-001", REQUEST, "/domain")]
    assert findings[0].message == "malware is not one of ransomware, techniques"
    assert domain_refusals(_request(), ("ransomware",), REQUEST) == ()


def test_the_body_stays_inert_whatever_line_break_a_message_holds() -> None:
    message = "a\r\r# H @v" + chr(0x85) + "x" + chr(0x2028) + "y" + chr(0x0B) + chr(0x0C) + "z"
    hostile = Finding("SCH-007", Severity.INFO, "p", "/f", message)

    body = _plan(checklist=(hostile,))["body"]

    line = next(line for line in body.splitlines() if line.startswith("- [ ]"))
    assert line == "- [ ] `p` `/f`: `a # H @v x y z`"
    assert body.count("\n") == len(body.splitlines())


def test_the_plan_counts_the_blocking_findings_left() -> None:
    blocking = Finding("SCH-009", Severity.BLOCKING, "p", "/description", "cut")
    info = Finding("SCH-007", Severity.INFO, "p", "/version", "give it")

    assert _plan(checklist=(info, blocking))["blocking"] == 1
    assert _plan()["blocking"] == 0


def test_the_checklist_holds_one_item_per_field_and_nothing_with_nothing_to_do() -> None:
    noted = Finding("SCH-007", Severity.INFO, "p", "/description", "cut at a paragraph end")
    blocking = Finding("SCH-009", Severity.BLOCKING, "p", "/description", "ends with the mark")
    idle = Finding("SCH-007", Severity.INFO, "p", "/name", "blanks around it; nothing to do")

    body = _plan(checklist=(noted, blocking, idle))["body"]

    items = [line for line in body.splitlines() if line.startswith("- [ ]")]
    assert items == ["- [ ] `p` `/description`: `ends with the mark`"]


def test_every_finding_on_a_field_is_listed_once_and_counted_once() -> None:
    first = Finding("VER-012", Severity.INFO, "p/scenario.json", "", "inject a is gone")
    second = Finding("VER-012", Severity.INFO, "p/scenario.json", "", "inject b is gone")
    hidden = Finding("IO-017", Severity.BLOCKING, "p", "/name", "U+202E")
    other = Finding("SCH-001", Severity.BLOCKING, "p", "/name", "too long")

    plan = _plan(checklist=(first, second, first, hidden, other, hidden))

    items = [line for line in plan["body"].splitlines() if line.startswith("- [ ]")]
    assert items == [
        "- [ ] `p/scenario.json` ``: `inject a is gone`",
        "- [ ] `p/scenario.json` ``: `inject b is gone`",
        "- [ ] `p` `/name`: `U+202E`",
        "- [ ] `p` `/name`: `too long`",
    ]
    assert plan["blocking"] == 2


def test_only_an_informative_finding_is_dropped_for_having_nothing_to_do() -> None:
    blocking = Finding("SCH-009", Severity.BLOCKING, "p", "/description", "cut; nothing to do")

    plan = _plan(checklist=(blocking,))

    assert plan["blocking"] == 1
    assert "nothing to do" in plan["body"]


def test_the_plan_keys_come_in_a_stable_order() -> None:
    assert list(_plan()) == [
        "base",
        "blocking",
        "body",
        "changed",
        "entry",
        "files",
        "mode",
        "title",
    ]


def test_a_blocking_item_is_kept_whatever_follows_it_for_the_same_field() -> None:
    blocking = Finding("SCH-009", Severity.BLOCKING, "p", "/description", "ends with the mark")
    noted = Finding("SCH-007", Severity.INFO, "p", "/description", "cut at a paragraph end")

    body = _plan(checklist=(blocking, noted))["body"]

    items = [line for line in body.splitlines() if line.startswith("- [ ]")]
    assert items == ["- [ ] `p` `/description`: `ends with the mark`"]


def test_a_joiner_where_emoji_put_one_makes_another_name() -> None:
    man, woman = chr(0x1F468), chr(0x1F469)

    assert not same_name(man + chr(0x200D) + woman, man + woman)  # a family, or two people
    assert same_name(man + chr(0x200D) + woman, man + chr(0x200D) + woman)


def test_an_invisible_character_does_not_make_another_name() -> None:
    assert same_name("akira", "aki" + chr(0x200B) + "ra")
    assert same_name("akira", "aki" + chr(0xAD) + "ra")


@pytest.mark.parametrize("hidden", [0x3164, 0xFFA0, 0x2800, 0xFE00], ids=hex)
def test_a_character_the_checks_find_hidden_does_not_make_another_name(hidden: int) -> None:
    assert same_name("akira", "aki" + chr(hidden) + "ra")


def test_the_body_holds_no_character_the_checks_find_hidden() -> None:
    message = "a" + chr(0x3164) + "b" + chr(0x2800) + "c" + chr(0xFE00) + "d"
    hostile = Finding("SCH-007", Severity.INFO, "p", "/f", message)

    body = _plan(checklist=(hostile,))["body"]

    assert "- [ ] `p` `/f`: `abcd`" in body


def test_the_body_holds_no_invisible_or_bidirectional_control() -> None:
    message = "a" + chr(0x202E) + "b" + chr(0x2066) + "c" + chr(0x200B) + "d"
    hostile = Finding("SCH-007", Severity.INFO, "p", "/f", message)

    body = _plan(checklist=(hostile,))["body"]

    assert "- [ ] `p` `/f`: `abcd`" in body


def test_an_unchanged_update_still_lists_what_blocks_its_entry() -> None:
    blocking = Finding("SCH-009", Severity.BLOCKING, "p", "/description", "ends with the mark")

    plan = _plan(request={"mode": "update"}, changed=False, files={}, checklist=(blocking,))

    assert plan["blocking"] == 1
    assert "- [ ] `p` `/description`: `ends with the mark`" in plan["body"]
    assert "nothing to propose" in plan["body"]


def test_the_body_stays_within_what_a_pull_request_takes_whatever_its_items() -> None:
    long = "x" * 300  # the longest a path, a field or a message is
    many = tuple(
        Finding("SCH-001", Severity.BLOCKING, f"{index:03}{long}"[:300], "/" + long[1:], long)
        for index in range(100)
    )

    plan = _plan(checklist=many)

    assert len(plan["body"]) <= 65536  # what GitHub takes for a pull request's body
    items = [line for line in plan["body"].splitlines() if line.startswith("- [ ]")]
    assert 0 < len(items) < 100
    assert f"and {100 - len(items)} more: run validate on the entry" in plan["body"]
    assert plan["blocking"] == 100


def test_the_body_lists_a_bounded_number_of_items_and_counts_every_blocking_one() -> None:
    many = tuple(
        Finding("SCH-001", Severity.BLOCKING, "p", f"/field{index}", "wrong")
        for index in range(150)
    )

    plan = _plan(checklist=many)

    items = [line for line in plan["body"].splitlines() if line.startswith("- [ ]")]
    assert len(items) == 100
    assert "and 50 more: run validate on the entry to see them all" in plan["body"]
    assert plan["blocking"] == 150  # exact, whatever the body shows
