"""A release built from the catalogue: every entry's archive and the manifest, or why not."""

import datetime
import hashlib
import json
from collections.abc import Callable
from typing import Any

import pytest

from scenario_tools.application.build_release import (
    ArchivedEntry,
    EntryResult,
    build_release,
    entry_for_release,
)
from scenario_tools.domain.release.manifest import (
    Approval,
    BuiltEntry,
    PayloadFile,
    PreviousRelease,
    payload_entry,
    previous_release,
)
from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import EnvironmentProblemError

FIRST = "scenarios/techniques/easm"
SECOND = "scenarios/ransomware/akira"
IDS = {
    FIRST: "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d",
    SECOND: "1a2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d",
}
MOMENT = datetime.datetime(2026, 10, 30, 9, 15, 2, tzinfo=datetime.UTC)
APPROVALS = {FIRST: Approval(12, ("alice",)), SECOND: Approval(13, ("bob",))}


def _metadata(entry: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "external_id": IDS[entry],
        "version": "1.0.0",
        "status": "VERIFIED",
        "name": entry.rsplit("/", 1)[1],
        "description": "d",
        "severity": "low",
        "category": "c",
        "main_focus": "m",
        "type": "time-based",
        "platforms": ["Generic"],
        "threat": {"ttps": ["T1595"]},
        "sources": [],
        "requires": {"openaev": ">=3", "edition": "CE", "injectors": [], "executors": []},
        "payloads": [],
    }


def _built(
    findings: dict[str, tuple[Finding, ...]] | None = None,
) -> Callable[[str], EntryResult]:
    def build(entry: str) -> EntryResult:
        found = (findings or {}).get(entry, ())
        if any(finding.severity is Severity.BLOCKING for finding in found):
            return EntryResult(found, None)
        built = BuiltEntry(_metadata(entry), entry == SECOND, f"zip of {entry}".encode())
        return EntryResult(found, built)

    return build


def _build(**changes: Any) -> Any:
    arguments: dict[str, Any] = {
        "approvals": APPROVALS,
        "before_review": frozenset(),
        "previous": None,
        "channel": "edge",
        "moment": MOMENT,
        "payloads": (),
        "catalogue": (),
    }
    arguments.update(changes)
    build = arguments.pop("build", _built())
    return build_release([FIRST, SECOND], build, **arguments)


def test_a_release_holds_every_archive_and_the_manifest_in_its_canonical_form() -> None:
    report, release = _build()

    assert report.ok
    assert report.command == "build"
    assert release is not None
    names = {entry: f"{IDS[entry]}-1.0.0.zip" for entry in (FIRST, SECOND)}
    assert release.archives == {names[entry]: f"zip of {entry}".encode() for entry in names}
    document = json.loads(release.manifest)
    assert release.manifest == jcs(document)
    assert (document["channel"], document["issued_at"], document["release"]) == (
        "edge",
        "2026-10-30T09:15:02Z",
        "2026.10.30.1",
    )
    [first, second] = document["items"]  # sorted by external ID
    assert (first["external_id"], second["external_id"]) == (IDS[FIRST], IDS[SECOND])
    archive = f"zip of {FIRST}".encode()
    assert first["archive"] == {
        "name": names[FIRST],
        "sha256": hashlib.sha256(archive).hexdigest(),
        "size": len(archive),
    }
    assert (first["tabletop"], second["tabletop"]) == (False, True)
    assert first["approvals"] == {"pull_request": 12, "approvers": ["alice"]}


def test_two_builds_give_the_same_bytes() -> None:
    assert _build()[1] == _build()[1]


def test_an_entry_that_cannot_be_archived_leaves_the_release_unbuilt() -> None:
    refused = Finding("GEN-002", Severity.BLOCKING, f"{SECOND}/scenario.json", "", "not normalised")
    noted = Finding("VER-012", Severity.INFO, f"{FIRST}/scenario.json", "", "an inject is gone")

    report, release = _build(build=_built({SECOND: (refused,), FIRST: (noted,)}))

    assert release is None
    assert set(report.findings) == {noted, refused}


def test_an_informative_finding_is_said_and_the_release_built() -> None:
    noted = Finding("VER-012", Severity.INFO, f"{FIRST}/scenario.json", "", "an inject is gone")

    report, release = _build(build=_built({FIRST: (noted,)}))

    assert report.findings == (noted,)
    assert release is not None


def test_an_entry_without_an_approval_is_said_and_the_release_built() -> None:
    report, release = _build(approvals={FIRST: APPROVALS[FIRST], SECOND: Approval(9, ())})

    assert [(f.code, f.path, f.severity) for f in report.findings] == [
        ("REL-002", SECOND, Severity.INFO)
    ]
    assert release is not None
    second = json.loads(release.manifest)["items"][1]
    assert second["approvals"] == {"pull_request": 9, "approvers": []}


def test_a_pull_request_merged_before_review_needs_no_approver() -> None:
    report, release = _build(
        approvals={FIRST: APPROVALS[FIRST], SECOND: Approval(9, ())}, before_review=frozenset({9})
    )

    assert report.ok
    assert release is not None
    second = json.loads(release.manifest)["items"][1]
    assert second["approvals"] == {"pull_request": 9, "approvers": []}


def test_a_released_version_whose_archive_changed_leaves_the_release_unbuilt() -> None:
    previous = PreviousRelease(
        "edge", "2026.10.29.1", {(IDS[FIRST], "1.0.0"): "0" * 64, (IDS[SECOND], "0.9.0"): "1" * 64}
    )

    report, release = _build(previous=previous)

    assert release is None
    assert [(f.code, f.path) for f in report.findings] == [("VER-020", f"{FIRST}/scenario.yaml")]


def test_a_release_takes_its_rank_after_the_previous_one_of_the_day() -> None:
    previous = PreviousRelease("edge", "2026.10.30.3", {})

    _, release = _build(previous=previous)

    assert release is not None
    assert json.loads(release.manifest)["release"] == "2026.10.30.4"


def test_a_previous_release_of_another_channel_is_refused() -> None:
    with pytest.raises(
        EnvironmentProblemError, match="the previous release is on stable, not edge"
    ):
        _build(previous=PreviousRelease("stable", "2026.10.29.1", {}))


def test_a_previous_release_dated_after_the_commit_is_refused() -> None:
    with pytest.raises(EnvironmentProblemError, match="dated after this commit"):
        _build(previous=PreviousRelease("edge", "2026.11.01.1", {}))


def test_a_released_scenario_that_no_entry_has_leaves_the_release_unbuilt() -> None:
    gone = "9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f"
    previous = PreviousRelease("edge", "2026.10.29.1", {(gone, "1.0.0"): "0" * 64})

    report, release = _build(previous=previous)

    assert release is None
    assert [(f.code, f.message.split(",")[0]) for f in report.findings] == [
        ("REL-003", f"the previous release lists the scenario {gone}")
    ]


def test_a_version_lower_than_the_released_one_leaves_the_release_unbuilt() -> None:
    previous = PreviousRelease("edge", "2026.10.29.1", {(IDS[FIRST], "2.0.0"): "0" * 64})

    report, release = _build(previous=previous)

    assert release is None
    assert [(f.code, f.path) for f in report.findings] == [("VER-002", f"{FIRST}/scenario.yaml")]


def test_a_catalogue_without_an_entry_has_no_release() -> None:
    with pytest.raises(EnvironmentProblemError, match="no entry: nothing to release"):
        build_release(
            [],
            _built(),
            approvals={},
            before_review=frozenset(),
            previous=None,
            channel="edge",
            moment=MOMENT,
            payloads=(),
            catalogue=(),
        )


def test_an_entry_the_approvals_file_leaves_out_leaves_the_release_unbuilt() -> None:
    report, release = _build(approvals={FIRST: APPROVALS[FIRST]})

    assert release is None
    assert [(f.code, f.path) for f in report.findings] == [("REL-001", SECOND)]


def _archived(entry: str, *found: Finding, archive: bytes | None = b"zip") -> ArchivedEntry:
    return ArchivedEntry(found, archive, _metadata(entry), {"document": entry})


def test_an_entry_is_validated_then_archived_and_told_tabletop_from_its_scenario() -> None:
    noted = Finding("VER-012", Severity.INFO, f"{FIRST}/scenario.json", "", "an inject is gone")
    told: list[object] = []

    def tabletop(document: object, entry: str) -> bool:
        told.append((document, entry))
        return True

    result = entry_for_release(
        FIRST,
        validate=lambda entry: (noted,),
        archive=lambda entry: _archived(entry),
        tabletop=tabletop,
    )

    assert result.findings == (noted,)
    assert result.built == BuiltEntry(_metadata(FIRST), True, b"zip")
    assert told == [({"document": FIRST}, FIRST)]


def test_an_entry_validate_refuses_is_never_archived() -> None:
    refused = Finding("SCH-001", Severity.BLOCKING, f"{FIRST}/scenario.yaml", "/name", "no")

    def never(entry: str) -> ArchivedEntry:
        raise AssertionError("never archived")

    result = entry_for_release(
        FIRST, validate=lambda entry: (refused,), archive=never, tabletop=lambda d, e: False
    )

    assert result == EntryResult((refused,), None)


def test_an_entry_the_archive_refuses_is_left_out_with_why() -> None:
    refused = Finding("GEN-002", Severity.BLOCKING, f"{FIRST}/scenario.json", "", "not normalised")

    result = entry_for_release(
        FIRST,
        validate=lambda entry: (),
        archive=lambda entry: _archived(entry, refused, archive=None),
        tabletop=lambda d, e: False,
    )

    assert result == EntryResult((refused,), None)


def test_an_entry_without_an_archive_and_without_a_reason_is_a_defect() -> None:
    noted = Finding("VER-012", Severity.INFO, f"{FIRST}/scenario.json", "", "an inject is gone")

    with pytest.raises(ValueError, match=f"{FIRST}: no archive was built, and nothing blocks it"):
        entry_for_release(
            FIRST,
            validate=lambda entry: (),
            archive=lambda entry: _archived(entry, noted, archive=None),
            tabletop=lambda d, e: False,
        )


def test_a_released_version_whose_status_changed_leaves_the_release_unbuilt() -> None:
    _, first = _build()
    assert first is not None
    previous = previous_release(json.loads(first.manifest))

    def deprecated(entry: str) -> EntryResult:
        metadata = dict(_metadata(entry), status="DEPRECATED")
        return EntryResult((), BuiltEntry(metadata, entry == SECOND, f"zip of {entry}".encode()))

    report, release = _build(build=deprecated, previous=previous)

    assert release is None
    assert sorted((f.code, f.path) for f in report.findings) == [
        ("VER-020", f"{SECOND}/scenario.yaml"),
        ("VER-020", f"{FIRST}/scenario.yaml"),
    ]


UNUSED = PayloadFile("unused-payload", "1.0.0", "c" * 64, "unused-id", b'{"unused": true}\n')
USED = PayloadFile("ps", "1.10.0", "d" * 64, "ps-id", b'{"ps": true}\n')
EARLIER = PayloadFile("ps", "1.9.0", "e" * 64, "ps-earlier-id", b'{"ps": 1}\n')


def test_a_release_lists_every_payload_version_and_carries_its_file() -> None:
    report, release = _build(payloads=(USED, UNUSED, EARLIER))

    assert report.ok
    assert release is not None
    document = json.loads(release.manifest)
    assert document["payloads"] == [payload_entry(v) for v in (EARLIER, USED, UNUSED)]
    assert release.payload_files == {
        "ps-1.9.0.json": EARLIER.data,
        "ps-1.10.0.json": USED.data,
        "unused-payload-1.0.0.json": UNUSED.data,
    }


def test_a_release_of_an_empty_catalogue_lists_no_payload() -> None:
    _, release = _build()

    assert release is not None
    assert json.loads(release.manifest)["payloads"] == []
    assert release.payload_files == {}


def test_a_catalogue_finding_that_blocks_leaves_the_release_unbuilt() -> None:
    refused = Finding("PAY-009", Severity.BLOCKING, "payloads/ps/1.10.0.json", "", "not sorted")
    told = Finding("PAY-010", Severity.INFO, "payloads", "", "information")

    report, release = _build(payloads=(USED,), catalogue=(refused,))
    _, built = _build(payloads=(USED,), catalogue=(told,))

    assert release is None
    assert report.findings == (refused,)
    assert built is not None


def test_a_released_payload_version_whose_file_changed_leaves_the_release_unbuilt() -> None:
    changed = PayloadFile(USED.payload, USED.version, USED.sha256, USED.openaev_id, b"{}\n")
    previous = PreviousRelease(
        "edge",
        "2026.10.29.1",
        {},
        payloads={("ps", "1.10.0"): (USED.sha256, hashlib.sha256(USED.data).hexdigest())},
    )

    report, release = _build(payloads=(changed,), previous=previous)
    _, kept = _build(payloads=(USED,), previous=previous)

    assert release is None
    assert [(f.code, f.path) for f in report.findings] == [("VER-021", "payloads/ps/1.10.0.json")]
    assert kept is not None
