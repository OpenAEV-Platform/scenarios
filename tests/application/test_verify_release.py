"""A release verified as its consumers will: the manifest, then each archive it lists."""

import hashlib
import json
from pathlib import Path
from typing import Any

from scenario_tools.application.verify_release import verify_release
from scenario_tools.domain.verification.payload_version import PayloadVersion
from scenario_tools.ports.errors import UnsafeInputError

ONE_ID, TWO_ID = "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d", "1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
ONE, TWO = f"{ONE_ID}-1.0.0.zip", f"{TWO_ID}-2.0.0.zip"
ARCHIVES = {ONE: b"first", TWO: b"second"}


def _item(name: str) -> dict[str, Any]:
    data = ARCHIVES[name]
    external_id, version = name[:36], name[37:-4]
    return {
        "external_id": external_id,
        "version": version,
        "archive": {"name": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
        "payloads": [],
    }


MANIFEST: dict[str, Any] = {
    "items": [_item(ONE), _item(TWO)],
    "payloads": [],
    "release_approver": "alice",
}
PS_DATA = (
    Path(__file__).parents[2]
    / "tests"
    / "golden"
    / "payloads"
    / "process-discovery-ps"
    / "1.0.0.json"
).read_bytes()
PS = PayloadVersion("process-discovery-ps", "1.0.0", "", json.loads(PS_DATA))
PS_FILE = "process-discovery-ps-1.0.0.json"
PS_ENTRY = {
    "payload": PS.slug,
    "version": PS.version,
    "sha256": PS.digest(),
    "openaev_id": PS.identifier,
    "file": {"name": PS_FILE, "sha256": hashlib.sha256(PS_DATA).hexdigest(), "size": len(PS_DATA)},
}
WITH_PAYLOAD: dict[str, Any] = {**MANIFEST, "payloads": [PS_ENTRY]}
NO_PAYLOAD_FILE: dict[str, bytes] = {}


def _verify(
    document: Any = MANIFEST,
    violations: tuple[tuple[str, str], ...] = (),
    archives: dict[str, bytes | None] | None = None,
    unsafe: frozenset[str] = frozenset(),
    approved: bool = True,
    present: frozenset[str] | None = None,
    payload_files: dict[str, bytes] | None = None,
) -> Any:
    held = ARCHIVES if archives is None else archives
    carried = {} if payload_files is None else payload_files
    opened: list[str] = []

    def scenario_of(data: bytes, name: str) -> object:
        opened.append(name)
        if name in unsafe:
            raise UnsafeInputError("IO-010", "unsafe entry name '../x'", name)
        return {"scenario_information": {}, "scenario_injects": []}

    def payload_of(name: str) -> bytes | None:
        opened.append(name)
        return carried.get(name)

    report = verify_release(
        document,
        validate=lambda document: violations,
        approved=approved,
        archive_of=held.get,
        scenario_of=scenario_of,
        present=frozenset(held) | frozenset(carried) if present is None else present,
        payload_of=payload_of,
        read_payload=json.loads,
    )
    return report, opened


def test_a_release_as_its_manifest_lists_it_is_accepted() -> None:
    report, opened = _verify()

    assert report.command == "verify"
    assert report.ok
    assert opened == [ONE, TWO]


def test_a_manifest_out_of_its_schema_is_refused_without_reading_its_items() -> None:
    report, opened = _verify(
        document={"items": "x"}, violations=(("/items", "'x' is not an array"),), approved=False
    )

    assert [(f.code, f.field) for f in report.findings] == [("VRF-009", "/items")]
    assert opened == []


def test_an_approved_manifest_without_its_approver_is_refused_without_reading_its_items() -> None:
    report, opened = _verify(document={"items": [_item(ONE), _item(ONE)]})

    assert [(f.code, f.field) for f in report.findings] == [("VRF-009", "/release_approver")]
    assert opened == []


def test_an_archive_missing_is_never_opened_and_the_others_are() -> None:
    report, opened = _verify(archives={TWO: ARCHIVES[TWO]})

    assert [(f.code, f.path) for f in report.findings] == [("VRF-006", ONE)]
    assert opened == [TWO]


def test_an_archive_unsafe_to_extract_is_refused_with_why() -> None:
    report, _ = _verify(unsafe=frozenset({TWO}))

    assert [(f.code, f.path, f.message) for f in report.findings] == [
        ("VRF-007", TWO, "IO-010: unsafe entry name '../x'")
    ]


def test_an_archive_too_large_to_read_is_unsafe() -> None:
    def too_large(name: str) -> bytes | None:
        raise UnsafeInputError("IO-001", "larger than 20971520 bytes", name)

    report = verify_release(
        MANIFEST,
        validate=lambda document: (),
        approved=False,
        archive_of=too_large,
        scenario_of=lambda data, name: {},
        present=frozenset(ARCHIVES),
        payload_of=NO_PAYLOAD_FILE.get,
        read_payload=json.loads,
    )

    assert [(f.code, f.path) for f in report.findings] == [("VRF-007", ONE), ("VRF-007", TWO)]


def test_a_file_beside_the_archives_that_the_manifest_does_not_list_is_refused() -> None:
    report, _ = _verify(present=frozenset({ONE, TWO, "manifest.json", "extra.zip"}))

    message = "the manifest does not list it, and it would be published"
    assert [(f.code, f.path, f.message) for f in report.findings] == [
        ("VRF-006", "extra.zip", message),
        ("VRF-006", "manifest.json", message),  # the manifest verified is not among them
    ]


def test_a_payload_two_scenarios_list_with_two_hashes_is_refused_without_reading_archives() -> None:
    one, two = _item(ONE), _item(TWO)
    one["payloads"] = [{"id": "shared", "version": "1.0.0", "sha256": "a" * 64}]
    two["payloads"] = [{"id": "shared", "version": "1.0.0", "sha256": "b" * 64}]

    report, opened = _verify(document={"items": [one, two], "payloads": []}, approved=False)

    assert [(f.code, f.field) for f in report.findings] == [("VRF-008", "/items/1/payloads/0")]
    assert opened == []


def test_a_manifest_listing_a_scenario_twice_is_refused_without_reading_its_archives() -> None:
    report, opened = _verify(
        document={"items": [_item(ONE), _item(ONE)], "payloads": []}, approved=False
    )

    assert [(f.code, f.field) for f in report.findings] == [("VRF-009", "/items/1")]
    assert opened == []


def test_the_cause_of_an_unsafe_archive_is_the_io_code_its_message_starts_with() -> None:
    from scenario_tools.application.verify_release import unsafe_cause
    from scenario_tools.domain.shared.finding import Finding, Severity

    def finding(code: str, message: str) -> Finding:
        return Finding(code, Severity.BLOCKING, "a.zip", "", message)

    assert unsafe_cause(finding("VRF-007", "IO-010: unsafe entry name")) == "IO-010"
    assert unsafe_cause(finding("VRF-007", "refused, IO-010: unsafe entry name")) is None
    assert unsafe_cause(finding("VRF-008", "IO-010: not an unsafe archive")) is None


def test_a_release_whose_payload_files_are_as_listed_is_accepted() -> None:
    report, opened = _verify(document=WITH_PAYLOAD, payload_files={PS_FILE: PS_DATA})

    assert report.ok
    assert opened == [ONE, TWO, PS_FILE]


def test_a_payload_file_missing_is_refused_and_the_archives_are_still_read() -> None:
    report, opened = _verify(document=WITH_PAYLOAD, payload_files={})

    assert [(f.code, f.path) for f in report.findings] == [("VRF-006", PS_FILE)]
    assert opened == [ONE, TWO, PS_FILE]


def test_a_payload_file_beside_the_archives_that_the_manifest_does_not_list_is_refused() -> None:
    report, _ = _verify(payload_files={PS_FILE: PS_DATA})  # a file the manifest does not list

    assert [(f.code, f.path) for f in report.findings] == [("VRF-006", PS_FILE)]


def test_a_payload_file_unsafe_to_read_is_refused_with_why() -> None:
    def too_large(name: str) -> bytes | None:
        raise UnsafeInputError("IO-001", "larger than 262144 bytes", name)

    report = verify_release(
        WITH_PAYLOAD,
        validate=lambda document: (),
        approved=False,
        archive_of=ARCHIVES.get,
        scenario_of=lambda data, name: {"scenario_information": {}, "scenario_injects": []},
        present=frozenset(ARCHIVES) | {PS_FILE},
        payload_of=too_large,
        read_payload=json.loads,
    )

    assert [(f.code, f.path, f.message) for f in report.findings] == [
        ("VRF-007", PS_FILE, "IO-001: larger than 262144 bytes")
    ]


def test_a_payload_version_listed_twice_is_refused_without_reading_anything() -> None:
    report, opened = _verify(document={**MANIFEST, "payloads": [PS_ENTRY, PS_ENTRY]})

    assert [(f.code, f.field) for f in report.findings] == [("VRF-008", "/payloads/1")]
    assert opened == []


def test_a_reference_to_an_unlisted_version_is_refused_without_reading_anything() -> None:
    item = {**_item(ONE), "payloads": [{"id": "x", "version": "1.0.0", "sha256": "f" * 64}]}

    report, opened = _verify(document={**MANIFEST, "items": [item, _item(TWO)]})

    assert [(f.code, f.field) for f in report.findings] == [("VRF-008", "/items/0/payloads/0")]
    assert opened == []
