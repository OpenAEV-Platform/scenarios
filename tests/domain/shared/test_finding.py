"""Findings: what every command reports, in one stable shape."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Finding, Report, Severity, shorten


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
