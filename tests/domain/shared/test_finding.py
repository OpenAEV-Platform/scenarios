"""Findings: what every command reports, in one stable shape."""

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.shared.finding import (
    MESSAGE_LIMIT,
    REPORT_LIMIT,
    Finding,
    Report,
    Severity,
    shorten,
)


def _finding(**changes: object) -> Finding:
    values: dict[str, object] = {
        "code": "SCH-001",
        "severity": Severity.BLOCKING,
        "path": "scenarios/techniques/easm/scenario.yaml",
        "field": "/version",
        "message": "'1.0' does not match the semantic version pattern",
    }
    values.update(changes)
    return Finding(**values)  # type: ignore[arg-type]


def test_a_well_formed_finding_is_accepted() -> None:
    finding = _finding()

    assert finding.severity.value == "blocking"


@pytest.mark.parametrize("path", ["", "a.yaml", "scenarios/x/scenario.json"])
def test_paths_relative_to_the_repository_or_empty_are_accepted(path: str) -> None:
    assert _finding(path=path).path == path


@pytest.mark.parametrize("code", ["SCH-1", "sch-001", "SCHEMA-001", "IO-0001", "IO001", "I-001"])
def test_a_malformed_code_is_refused(code: str) -> None:
    with pytest.raises(ValueError, match="code"):
        _finding(code=code)


@pytest.mark.parametrize("path", ["/etc/passwd", "../x", "a/../b", "a\\b", "C:/x"])
def test_a_path_outside_the_repository_form_is_refused(path: str) -> None:
    with pytest.raises(ValueError, match="path"):
        _finding(path=path)


@pytest.mark.parametrize("field", ["version", "#/version", "/name~2x", "/name~", "/a~/b"])
def test_a_field_that_is_not_a_json_pointer_is_refused(field: str) -> None:
    with pytest.raises(ValueError, match="field"):
        _finding(field=field)


@pytest.mark.parametrize("field", ["", "/", "//", "/name", "/a~0b", "/a~1b", "/items/0/name"])
def test_rfc_6901_pointers_are_accepted(field: str) -> None:
    assert _finding(field=field).field == field


def test_an_empty_message_is_refused() -> None:
    with pytest.raises(ValueError, match="message"):
        _finding(message="")


def test_a_report_is_ok_only_without_blocking_findings() -> None:
    info = _finding(severity=Severity.INFO)

    assert Report("validate", ()).ok
    assert Report("validate", (info,)).ok
    assert not Report("validate", (info, _finding())).ok


def test_a_report_document_follows_the_contract() -> None:
    document = Report("validate", (_finding(),)).document()

    assert document == {
        "command": "validate",
        "ok": False,
        "findings": [
            {
                "code": "SCH-001",
                "severity": "blocking",
                "path": "scenarios/techniques/easm/scenario.yaml",
                "field": "/version",
                "message": "'1.0' does not match the semantic version pattern",
            }
        ],
    }


_findings = st.lists(
    st.builds(
        Finding,
        code=st.sampled_from(["SCH-001", "IO-002", "POL-010", "VER-010"]),
        severity=st.sampled_from(list(Severity)),
        path=st.sampled_from(["", "a.yaml", "b/c.json"]),
        field=st.sampled_from(["", "/name", "/items/0"]),
        message=st.sampled_from(["x", "y"]),
    ),
    max_size=8,
)


@given(_findings, st.randoms())
def test_findings_are_reported_in_a_stable_order(findings: list[Finding], random: object) -> None:
    shuffled = list(findings)
    random.shuffle(shuffled)  # type: ignore[attr-defined]

    ordered = Report("validate", tuple(findings)).findings

    assert Report("validate", tuple(shuffled)).findings == ordered
    assert list(ordered) == sorted(
        findings, key=lambda f: (f.path, f.field, f.code, f.message, f.severity.value)
    )


def test_a_long_message_is_shortened_to_the_limit() -> None:
    assert shorten("a" * MESSAGE_LIMIT) == "a" * MESSAGE_LIMIT
    assert shorten("a" * (MESSAGE_LIMIT + 1)) == "a" * (MESSAGE_LIMIT - 1) + "…"


@pytest.mark.parametrize("length", [1, MESSAGE_LIMIT, MESSAGE_LIMIT + 1, 1_000_000])
def test_every_finding_message_is_at_most_the_limit(length: int) -> None:
    message = "m" * length

    finding = Finding("IO-005", Severity.BLOCKING, "a.json", "", message)

    assert finding.message == shorten(message)
    assert len(finding.message) <= MESSAGE_LIMIT


def test_a_long_path_and_field_are_shortened_like_the_message() -> None:
    # Both carry contributor content: a key or a directory name of any length.
    finding = _finding(path="d/" + "p" * 1_000_000, field="/" + "k" * 1_000_000)

    assert (len(finding.path), len(finding.field)) == (MESSAGE_LIMIT, MESSAGE_LIMIT)
    assert finding.path.endswith("…")
    assert finding.field.endswith("…")


@pytest.mark.parametrize("cut", [MESSAGE_LIMIT - 2, MESSAGE_LIMIT - 3])
def test_a_shortened_field_is_still_a_json_pointer(cut: int) -> None:
    # Cut right after a "~", the escape would be broken; the "~" goes with the rest.
    field = "/" + "k" * (cut - 1) + "~1" + "k" * 10

    shortened = _finding(field=field).field

    assert len(shortened) <= MESSAGE_LIMIT
    assert not shortened.removesuffix("…").endswith("~")
    Finding("SCH-001", Severity.BLOCKING, "", shortened, "m")  # still accepted as a pointer


def _many(count: int, severity: Severity = Severity.BLOCKING) -> tuple[Finding, ...]:
    return tuple(_finding(field=f"/items/{index:04}", severity=severity) for index in range(count))


def test_a_report_shows_at_most_a_hundred_findings_then_counts_the_rest() -> None:
    report = Report("archive", _many(250))

    assert len(report.findings) == REPORT_LIMIT + 1
    assert report.findings[:REPORT_LIMIT] == Report("archive", _many(REPORT_LIMIT)).findings
    last = report.findings[-1]
    assert (last.code, last.severity, last.path, last.field) == (
        "IO-016",
        Severity.BLOCKING,
        "",
        "",
    )
    assert last.message == "150 more findings not shown"
    assert not report.ok


def test_the_count_is_blocking_only_when_a_finding_it_counts_is() -> None:
    shown = _many(REPORT_LIMIT, Severity.INFO)
    hidden = (_finding(field="/zz", severity=Severity.INFO),)

    assert Report("archive", shown + hidden).findings[-1].severity is Severity.INFO
    assert Report("archive", shown + hidden).ok
    blocking = (_finding(field="/zz", severity=Severity.BLOCKING),)
    assert Report("archive", shown + blocking).findings[-1].severity is Severity.BLOCKING
    assert not Report("archive", shown + blocking).ok


def test_a_report_of_exactly_a_hundred_findings_is_shown_whole() -> None:
    assert len(Report("archive", _many(REPORT_LIMIT)).findings) == REPORT_LIMIT


def test_a_report_with_changed_findings_is_not_limited_again() -> None:
    report = Report("archive", _many(250))

    changed = report.with_findings(lambda f: dataclasses.replace(f, message="changed"))

    assert len(changed.findings) == REPORT_LIMIT + 1
    assert [f.field for f in changed.findings] == [f.field for f in report.findings]
    assert {f.message for f in changed.findings} == {"changed"}
