"""A release verified as its consumers will: the manifest, then each archive it lists."""

import hashlib
from typing import Any

from scenario_tools.application.verify_release import verify_release
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


MANIFEST: dict[str, Any] = {"items": [_item(ONE), _item(TWO)], "release_approver": "alice"}


def _verify(
    document: Any = MANIFEST,
    violations: tuple[tuple[str, str], ...] = (),
    archives: dict[str, bytes | None] | None = None,
    unsafe: frozenset[str] = frozenset(),
    approved: bool = True,
    present: frozenset[str] | None = None,
) -> Any:
    held = ARCHIVES if archives is None else archives
    opened: list[str] = []

    def scenario_of(data: bytes, name: str) -> object:
        opened.append(name)
        if name in unsafe:
            raise UnsafeInputError("IO-010", "unsafe entry name '../x'", name)
        return {"scenario_information": {}, "scenario_injects": []}

    report = verify_release(
        document,
        validate=lambda document: violations,
        approved=approved,
        archive_of=held.get,
        scenario_of=scenario_of,
        present=frozenset(held) if present is None else present,
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

    report, opened = _verify(document={"items": [one, two]}, approved=False)

    assert [(f.code, f.field) for f in report.findings] == [("VRF-008", "/items/1/payloads/0")]
    assert opened == []


def test_a_manifest_listing_a_scenario_twice_is_refused_without_reading_its_archives() -> None:
    report, opened = _verify(document={"items": [_item(ONE), _item(ONE)]}, approved=False)

    assert [(f.code, f.field) for f in report.findings] == [("VRF-009", "/items/1")]
    assert opened == []
