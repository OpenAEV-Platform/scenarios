"""Building the import archive of an entry: refused while it holds what the archive cannot carry."""

from typing import Any

import pytest

from scenario_tools.application.build_archive import build_archive
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import UnsafeInputError
from tests.domain.policy.cases import DATA

PATH = "scenarios/ransomware/akira/scenario.json"
OUT = "build/akira.zip"
DOCUMENT: dict[str, Any] = {"scenario_information": {}, "scenario_injects": []}


def _unchecked(data: bytes) -> None:
    pass


def _same(document: object) -> bytes:
    return b"{}"  # the stored bytes the tests pass: normalisation would not change them


def _no_contract_findings(document: object) -> tuple[Finding, ...]:
    return ()


class FakeBuilder:
    def __init__(self, output: bytes = b"archive") -> None:
        self.output = output
        self.calls: list[tuple[bytes, bytes | None]] = []

    def build(self, scenario: bytes, attachments: bytes | None) -> bytes:
        self.calls.append((scenario, attachments))
        return self.output


def test_an_entry_is_built_from_its_stored_bytes() -> None:
    builder = FakeBuilder()
    checked: list[bytes] = []

    report, data = build_archive(
        DOCUMENT,
        b"{}",
        b"att",
        PATH,
        OUT,
        builder,
        renormalised=_same,
        contract_findings=_no_contract_findings,
        check=checked.append,
        limit=100,
        policy=DATA,
    )

    assert report.command == "archive"
    assert report.ok
    assert data == b"archive"
    assert builder.calls == [(b"{}", b"att")]
    assert checked == [b"archive"]  # the archive built passes the archive checks


def test_an_entry_the_archive_cannot_carry_is_never_built() -> None:
    builder = FakeBuilder()
    document = {"scenario_information": {"scenario_recurrence": "x"}, "scenario_injects": []}

    report, data = build_archive(
        document,
        b"{}",
        None,
        PATH,
        OUT,
        builder,
        renormalised=_same,
        contract_findings=_no_contract_findings,
        check=_unchecked,
        limit=100,
        policy=DATA,
    )

    assert [(f.code, f.severity) for f in report.findings] == [("POL-002", Severity.BLOCKING)]
    assert data is None
    assert builder.calls == []


def test_an_archive_over_the_limit_is_refused() -> None:
    with pytest.raises(UnsafeInputError) as error:
        build_archive(
            DOCUMENT,
            b"{}",
            None,
            PATH,
            OUT,
            FakeBuilder(b"x" * 101),
            renormalised=_same,
            contract_findings=_no_contract_findings,
            check=_unchecked,
            limit=100,
            policy=DATA,
        )
    assert (error.value.code, error.value.message, error.value.path) == (
        "IO-001",
        "larger than 100 bytes",
        OUT,
    )


def test_an_archive_at_the_limit_is_built() -> None:
    _, data = build_archive(
        DOCUMENT,
        b"{}",
        None,
        PATH,
        OUT,
        FakeBuilder(b"x" * 100),
        renormalised=_same,
        contract_findings=_no_contract_findings,
        check=_unchecked,
        limit=100,
        policy=DATA,
    )

    assert data == b"x" * 100


def test_a_stored_scenario_not_shaped_like_one_is_refused_on_its_file() -> None:
    with pytest.raises(UnsafeInputError) as error:
        build_archive(
            {"a": 1},
            b"{}",
            None,
            PATH,
            OUT,
            FakeBuilder(),
            renormalised=_same,
            contract_findings=_no_contract_findings,
            check=_unchecked,
            limit=100,
            policy=DATA,
        )
    assert (error.value.code, error.value.path) == ("IO-014", PATH)
    assert error.value.message == (
        "not an OpenAEV scenario export: a is not a part of a stored scenario"
    )


def test_an_archive_the_checks_refuse_is_never_returned() -> None:
    def refuse(data: bytes) -> None:
        raise UnsafeInputError("IO-009", "too many entries", OUT)

    with pytest.raises(UnsafeInputError):
        build_archive(
            DOCUMENT,
            b"{}",
            None,
            PATH,
            OUT,
            FakeBuilder(),
            renormalised=_same,
            contract_findings=_no_contract_findings,
            check=refuse,
            limit=100,
            policy=DATA,
        )


def test_a_stored_scenario_normalisation_would_change_is_refused() -> None:
    builder = FakeBuilder()

    report, data = build_archive(
        DOCUMENT,
        b"{}",
        None,
        PATH,
        OUT,
        builder,
        renormalised=lambda document: b'{"changed": true}',
        contract_findings=_no_contract_findings,
        check=_unchecked,
        limit=100,
        policy=DATA,
    )

    assert [(f.code, f.severity, f.path, f.field) for f in report.findings] == [
        ("GEN-002", Severity.BLOCKING, PATH, "")
    ]
    message = report.findings[0].message
    assert "edited by hand" in message  # the two likely causes, and what to do
    assert "external ID in scenario.yaml" in message
    assert "normalise the export again" in message
    assert data is None
    assert builder.calls == []


def test_a_contract_without_established_facts_keeps_the_entry_out() -> None:
    builder = FakeBuilder()
    unknown = Finding("SCH-005", Severity.BLOCKING, PATH, "/scenario_injects/0", "unknown")

    report, data = build_archive(
        DOCUMENT,
        b"{}",
        None,
        PATH,
        OUT,
        builder,
        renormalised=_same,
        contract_findings=lambda document: (unknown,),
        check=_unchecked,
        limit=100,
        policy=DATA,
    )

    assert report.findings == (unknown,)
    assert data is None
    assert builder.calls == []


def test_an_entry_naming_a_host_outside_the_allowed_targets_is_never_built() -> None:
    builder = FakeBuilder()
    document = {
        "scenario_information": {},
        "scenario_injects": [{"inject_content": {"targets": "10.0.0.5"}}],
    }

    report, data = build_archive(
        document,
        b"{}",
        None,
        PATH,
        OUT,
        builder,
        renormalised=_same,
        contract_findings=_no_contract_findings,
        check=_unchecked,
        limit=100,
        policy=DATA,
    )

    assert [(f.code, f.field) for f in report.findings] == [
        ("POL-003", "/scenario_injects/0/inject_content/targets")
    ]
    assert data is None
    assert builder.calls == []
