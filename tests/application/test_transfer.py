"""Export and import through the platform port: an export is checked before it is written, and
each inject the platform skips at import is a blocking finding."""

from collections.abc import Mapping
from typing import Any

import pytest

from scenario_tools.application.transfer import check_reuse, export_scenario, import_archive
from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.held_payloads import OTHER_PAYLOAD, HeldContract
from scenario_tools.ports.errors import (
    EnvironmentProblemError,
    OutcomeUnknownError,
    UnsafeInputError,
)
from scenario_tools.ports.openaev import ImportResult, SkippedInject

SCENARIO = "0a64b5ab-2016-426b-813f-9051d32e88b3"


class FakePlatform:
    def __init__(
        self,
        export: bytes = b"archive",
        skipped: tuple[SkippedInject, ...] = (),
        contracts: Mapping[str, HeldContract] | None = None,
        payloads: Mapping[str, object] | None = None,
    ):
        self.export, self.skipped = export, skipped
        self.contracts, self.payloads = contracts or {}, payloads or {}
        self.calls: list[tuple[str, object]] = []

    def held_contract(self, contract_id: str) -> HeldContract | None:
        self.calls.append(("contract", contract_id))
        return self.contracts.get(contract_id)

    def held_payloads(self, external_ids: frozenset[str]) -> Mapping[str, object]:
        self.calls.append(("payloads", external_ids))
        return {k: v for k, v in self.payloads.items() if k in external_ids}

    def export_scenario(self, scenario_id: str) -> bytes:
        self.calls.append(("export", scenario_id))
        return self.export

    def import_scenario(self, archive: bytes) -> ImportResult:
        self.calls.append(("import", archive))
        return ImportResult(self.skipped)


def test_an_export_is_checked_then_written() -> None:
    platform, events = FakePlatform(), list[tuple[str, bytes]]()

    report = export_scenario(
        platform,
        SCENARIO,
        "export.zip",
        check=lambda data: events.append(("check", data)),
        write=lambda data: events.append(("write", data)),
    )

    assert report.command == "openaev export"
    assert report.ok
    assert report.findings == ()
    assert platform.calls == [("export", SCENARIO)]
    assert events == [("check", b"archive"), ("write", b"archive")]


def test_a_refused_export_is_never_written() -> None:
    written: list[bytes] = []

    def refuse(data: bytes) -> None:
        raise UnsafeInputError("IO-007", "not a valid ZIP archive", "export.zip")

    with pytest.raises(UnsafeInputError):
        export_scenario(FakePlatform(), SCENARIO, "export.zip", check=refuse, write=written.append)
    assert written == []


def test_an_export_the_platform_adapter_refuses_is_reported_on_the_output() -> None:
    class Oversized(FakePlatform):
        def export_scenario(self, scenario_id: str) -> bytes:
            raise UnsafeInputError("IO-001", "larger than 100 bytes")

    with pytest.raises(UnsafeInputError) as error:
        export_scenario(Oversized(), SCENARIO, "build/e.zip", check=print, write=print)
    assert (error.value.code, error.value.message, error.value.path) == (
        "IO-001",
        "larger than 100 bytes",
        "build/e.zip",
    )


def test_a_complete_import_is_ok() -> None:
    platform = FakePlatform()

    report = import_archive(platform, b"archive", "build/scenario.zip", {})

    assert report.command == "openaev import"
    assert report.ok
    assert report.findings == ()
    assert platform.calls == [("import", b"archive")]


def test_an_inject_without_a_name_or_type_is_reported_all_the_same() -> None:
    platform = FakePlatform(skipped=(SkippedInject(None, None), SkippedInject("Injector", "")))

    report = import_archive(platform, b"archive", "build/scenario.zip", {})

    assert sorted(finding.message for finding in report.findings) == [
        "the platform skipped an inject without a name: its Injector is missing on the instance",
        "the platform skipped an inject without a name: its dependency is missing on the instance",
    ]


class _Failing(FakePlatform):
    def __init__(self, error: EnvironmentProblemError) -> None:
        super().__init__()
        self.error = error

    def import_scenario(self, archive: bytes) -> ImportResult:
        raise self.error


def test_a_failed_import_that_may_have_acted_says_the_scenario_may_exist() -> None:
    platform = _Failing(OutcomeUnknownError("the platform answered HTTP 500"))

    with pytest.raises(OutcomeUnknownError) as error:
        import_archive(platform, b"archive", "build/scenario.zip", {})
    assert str(error.value) == (
        "the platform answered HTTP 500; the scenario may have been created all the same: "
        "check the platform before trying again"
    )


def test_a_failed_import_that_never_reached_the_platform_says_only_what_failed() -> None:
    platform = _Failing(EnvironmentProblemError("the platform refused the token (HTTP 401)"))

    with pytest.raises(EnvironmentProblemError) as error:
        import_archive(platform, b"archive", "build/scenario.zip", {})
    assert str(error.value) == "the platform refused the token (HTTP 401)"


def test_each_skipped_inject_is_a_blocking_finding_on_the_archive() -> None:
    platform = FakePlatform(
        skipped=(
            SkippedInject("InjectorContract/Payload", "Dump credentials"),
            SkippedInject("Injector", "Scan"),
        )
    )

    report = import_archive(platform, b"archive", "build/scenario.zip", {})

    assert not report.ok
    assert [(f.code, f.severity, f.path, f.field, f.message) for f in report.findings] == [
        (
            "OAV-001",
            Severity.BLOCKING,
            "build/scenario.zip",
            "",
            "the platform skipped inject 'Dump credentials': its InjectorContract/Payload is "
            "missing on the instance",
        ),
        (
            "OAV-001",
            Severity.BLOCKING,
            "build/scenario.zip",
            "",
            "the platform skipped inject 'Scan': its Injector is missing on the instance",
        ),
    ]


def _payload(content: str) -> dict[str, Any]:
    return {
        "payload_type": "Command",
        "payload_name": "who",
        "command_executor": "sh",
        "command_content": content,
        "payload_external_id": "ext-1",
    }


SCENARIO_WITH_PAYLOAD = {
    "scenario_injects": [
        {
            "inject_injector_contract": {
                "injector_contract_id": "c-1",
                "injector_contract_payload": _payload("whoami"),
            }
        }
    ]
}


def test_an_archive_whose_payload_the_platform_holds_otherwise_is_never_imported() -> None:
    platform = FakePlatform(payloads={"ext-1": _payload("id")})

    report = import_archive(platform, b"archive", "build/scenario.zip", SCENARIO_WITH_PAYLOAD)

    assert report.command == "openaev import"
    assert [(f.code, f.message) for f in report.findings] == [
        ("OAV-002", OTHER_PAYLOAD.format(by="payload external ID"))
    ]
    assert ("import", b"archive") not in platform.calls


def test_an_archive_whose_payload_the_platform_holds_as_it_is_is_imported() -> None:
    platform = FakePlatform(contracts={"c-1": HeldContract(_payload("whoami"))})

    report = import_archive(platform, b"archive", "build/scenario.zip", SCENARIO_WITH_PAYLOAD)

    assert report.ok
    assert platform.calls == [
        ("contract", "c-1"),
        ("payloads", frozenset({"ext-1"})),
        ("import", b"archive"),
    ]


def test_the_check_only_reads_the_platform() -> None:
    platform = FakePlatform(payloads={"ext-1": _payload("id")})

    report = check_reuse(platform, SCENARIO_WITH_PAYLOAD, "build/scenario.zip")

    assert report.command == "openaev check"
    assert [f.code for f in report.findings] == ["OAV-002"]
    assert [call for call, _ in platform.calls] == ["contract", "payloads"]
