"""The release manifest: what each item says, and how the release is named and approved."""

import datetime
from typing import Any

import pytest

from scenario_tools.domain.release.manifest import (
    Approval,
    ArchiveFacts,
    BuiltEntry,
    PreviousRelease,
    approval_findings,
    approvals_from_document,
    archive_name,
    issued_at_text,
    manifest,
    manifest_item,
    merged_before_review_from_document,
    previous_release,
    release_name,
    withdrawn_findings,
)
from scenario_tools.domain.shared.finding import Severity

ID = "0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d"
OTHER = "f1e2d3c4-b5a6-4978-8a9b-0c1d2e3f4a5b"
ENTRY = "scenarios/techniques/easm"
SHA = "a" * 64
METADATA: dict[str, Any] = {
    "schema_version": 1,
    "external_id": ID,
    "version": "1.2.3",
    "status": "VERIFIED",
    "name": "EASM",
    "description": "Scans the exposed surface.",
    "severity": "medium",
    "category": "attack-scenario",
    "main_focus": "endpoint-protection",
    "type": "time-based",
    "platforms": ["Generic"],
    "threat": {"ttps": ["T1595"]},
    "sources": [{"url": "https://example.org"}],
    "requires": {"openaev": ">=3.261005.0", "edition": "CE", "injectors": ["x"], "executors": []},
    "payloads": [{"id": "p1", "version": "1.0.0", "sha256": SHA}],
    "targets": [],
}
ARCHIVE = ArchiveFacts(f"{ID}-1.2.3.zip", "b" * 64, 1234)
APPROVAL = Approval(122, ("alice", "bob"))
MOMENT = datetime.datetime(2026, 10, 30, 9, 15, 2, tzinfo=datetime.UTC)


def test_an_item_copies_the_catalogue_facets_and_says_what_was_built_and_approved() -> None:
    item = manifest_item(METADATA, tabletop=False, archive=ARCHIVE, approval=APPROVAL)

    assert item == {
        "external_id": ID,
        "version": "1.2.3",
        "status": "VERIFIED",
        "name": "EASM",
        "description": "Scans the exposed surface.",
        "severity": "medium",
        "category": "attack-scenario",
        "main_focus": "endpoint-protection",
        "platforms": ["Generic"],
        "threat": {"ttps": ["T1595"]},
        "type": "time-based",
        "tabletop": False,
        "requires": METADATA["requires"],
        "archive": {"name": f"{ID}-1.2.3.zip", "sha256": "b" * 64, "size": 1234},
        "payloads": [{"id": "p1", "version": "1.0.0", "sha256": SHA}],
        "approvals": {"pull_request": 122, "approvers": ["alice", "bob"]},
    }


def test_an_item_shares_nothing_with_the_metadata_it_copies() -> None:
    item = manifest_item(METADATA, tabletop=True, archive=ARCHIVE, approval=APPROVAL)

    item["threat"]["ttps"].append("T0000")
    item["requires"]["injectors"].append("y")

    assert METADATA["threat"] == {"ttps": ["T1595"]}
    assert METADATA["requires"]["injectors"] == ["x"]
    assert item["tabletop"] is True


def test_an_archive_is_named_by_the_scenario_and_its_version() -> None:
    assert archive_name(ID, "1.2.3") == f"{ID}-1.2.3.zip"


def test_the_manifest_lists_the_items_by_external_id() -> None:
    first = manifest_item(METADATA, tabletop=False, archive=ARCHIVE, approval=APPROVAL)
    second = dict(first, external_id=OTHER)

    document = manifest(
        channel="edge",
        issued_at="2026-10-30T09:15:02Z",
        release="2026.10.30.1",
        items=[second, first],
    )

    assert document == {
        "schema_version": 1,
        "repository": "OpenAEV-Platform/scenarios",
        "channel": "edge",
        "issued_at": "2026-10-30T09:15:02Z",
        "release": "2026.10.30.1",
        "items": [first, second],
    }


def test_two_items_of_one_scenario_have_no_manifest() -> None:
    item = manifest_item(METADATA, tabletop=False, archive=ARCHIVE, approval=APPROVAL)

    with pytest.raises(ValueError, match=f"two entries have the external_id {ID}"):
        manifest(channel="edge", issued_at="x", release="y", items=[item, dict(item)])


@pytest.mark.parametrize("channel", ["", "beta", "EDGE"])
def test_a_channel_is_edge_or_stable(channel: str) -> None:
    with pytest.raises(ValueError, match="channel"):
        manifest(channel=channel, issued_at="x", release="y", items=[])


def test_the_issue_time_is_the_moment_in_utc_to_the_second() -> None:
    paris = datetime.timezone(datetime.timedelta(hours=2))
    moment = datetime.datetime(2026, 10, 30, 11, 15, 2, 999_999, tzinfo=paris)

    assert issued_at_text(moment) == "2026-10-30T09:15:02Z"


def test_a_moment_without_its_offset_has_no_issue_time() -> None:
    with pytest.raises(ValueError, match="offset"):
        issued_at_text(datetime.datetime(2026, 10, 30, 9, 15, 2))


@pytest.mark.parametrize(
    ("previous", "name"),
    [
        (None, "2026.10.30.1"),
        ("2026.10.29.4", "2026.10.30.1"),
        ("2026.10.30.1", "2026.10.30.2"),
        ("2026.10.30.9", "2026.10.30.10"),
        ("2025.12.31.3", "2026.10.30.1"),
    ],
)
def test_a_release_is_named_by_its_day_and_its_rank_that_day(
    previous: str | None, name: str
) -> None:
    assert release_name(MOMENT, previous) == name


def test_the_day_of_a_release_is_its_day_in_utc() -> None:
    late = datetime.datetime(
        2026, 10, 31, 1, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=2))
    )

    assert release_name(late, "2026.10.30.1") == "2026.10.30.2"


@pytest.mark.parametrize("previous", ["2026.10.31.1", "2027.01.01.1"])
def test_a_previous_release_dated_after_the_commit_is_refused(previous: str) -> None:
    with pytest.raises(ValueError, match=f"the previous release {previous} is dated after"):
        release_name(MOMENT, previous)


@pytest.mark.parametrize("previous", ["2026.10.30", "2026.10.30.0", "2026.13.01.1", "x"])
def test_a_previous_release_name_that_is_none_is_refused(previous: str) -> None:
    with pytest.raises(ValueError, match="is not a release name"):
        release_name(MOMENT, previous)


def _approvals(**entries: Any) -> dict[str, Any]:
    return {"schema_version": 1, "entries": entries}


def test_the_approvals_file_gives_each_entry_its_pull_request_and_its_approvers() -> None:
    document = _approvals(
        **{ENTRY: {"pull_request": 122, "approvers": ["bob", "alice"]}},
        **{"scenarios/x/y": {"pull_request": 7, "approvers": []}},
    )

    assert approvals_from_document(document) == {
        ENTRY: Approval(122, ("alice", "bob")),
        "scenarios/x/y": Approval(7, ()),
    }


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"entries": {}},
        {"schema_version": 2, "entries": {}},
        {"schema_version": 1, "entries": []},
        {"schema_version": 1, "entries": {}, "more": 1},
        _approvals(**{ENTRY: {"pull_request": 0, "approvers": []}}),
        _approvals(**{ENTRY: {"pull_request": True, "approvers": []}}),
        _approvals(**{ENTRY: {"pull_request": "122", "approvers": []}}),
        _approvals(**{ENTRY: {"pull_request": 1, "approvers": ["Alice"]}}),
        _approvals(**{ENTRY: {"pull_request": 1, "approvers": ["a" * 40]}}),
        _approvals(**{ENTRY: {"pull_request": 1, "approvers": ["-a"]}}),
        _approvals(**{ENTRY: {"pull_request": 1, "approvers": ["a", "a"]}}),
        _approvals(**{ENTRY: {"pull_request": 1, "approvers": [f"u{n}" for n in range(11)]}}),
        _approvals(**{ENTRY: {"pull_request": 1}}),
        _approvals(**{ENTRY: {"pull_request": 1, "approvers": [], "more": 1}}),
        _approvals(**{"scenarios/x": {"pull_request": 1, "approvers": []}}),
        _approvals(**{"elsewhere/x/y": {"pull_request": 1, "approvers": []}}),
    ],
)
def test_an_approvals_file_out_of_its_shape_is_refused(document: Any) -> None:
    with pytest.raises(ValueError, match="approvals"):
        approvals_from_document(document)


def test_every_entry_needs_its_approvals_and_an_approver() -> None:
    approvals = {
        ENTRY: Approval(122, ("alice",)),
        "scenarios/x/unapproved": Approval(9, ()),
        "scenarios/x/early": Approval(73, ()),
    }
    entries = [ENTRY, "scenarios/x/unapproved", "scenarios/x/early", "scenarios/x/missing"]

    findings = approval_findings(entries, approvals, frozenset({73}))

    assert [(f.code, f.path, f.severity.value, f.message) for f in findings] == [
        (
            "REL-002",
            "scenarios/x/unapproved",
            "blocking",
            "pull request #9, the last to change this entry, has no approval, and is not listed "
            "as merged before reviews were required",
        ),
        (
            "REL-001",
            "scenarios/x/missing",
            "blocking",
            "the approvals file names no pull request for this entry",
        ),
    ]


def test_the_pull_requests_merged_before_review_are_listed_with_why() -> None:
    document = {"pull_requests": [{"number": 73, "reason": "merged before the rules"}]}

    assert merged_before_review_from_document(document) == frozenset({73})
    assert merged_before_review_from_document({"pull_requests": []}) == frozenset()


@pytest.mark.parametrize(
    "document",
    [
        None,
        {},
        {"pull_requests": {}},
        {"pull_requests": [73]},
        {"pull_requests": [{"number": 73}]},
        {"pull_requests": [{"number": 73, "reason": ""}]},
        {"pull_requests": [{"number": 0, "reason": "r"}]},
        {"pull_requests": [{"number": 73, "reason": "r"}, {"number": 73, "reason": "s"}]},
        {"pull_requests": [], "more": 1},
    ],
)
def test_a_list_of_pull_requests_merged_before_review_out_of_its_shape_is_refused(
    document: Any,
) -> None:
    with pytest.raises(ValueError, match="merged-before-review"):
        merged_before_review_from_document(document)


def test_the_previous_release_gives_its_channel_name_and_archives() -> None:
    first = manifest_item(METADATA, tabletop=False, archive=ARCHIVE, approval=APPROVAL)
    document = manifest(channel="edge", issued_at="x", release="2026.10.29.4", items=[first])

    released = previous_release(document)

    assert (released.channel, released.release) == ("edge", "2026.10.29.4")
    assert released.archives == {(ID, "1.2.3"): "b" * 64}


def test_a_scenario_of_the_previous_release_that_no_entry_has_is_refused() -> None:
    previous = PreviousRelease("edge", "2026.10.29.1", {(ID, "1.0.0"): SHA, (OTHER, "2.0.0"): SHA})

    (finding,) = withdrawn_findings(previous, {ID})

    assert (finding.code, finding.severity, finding.path, finding.field) == (
        "REL-003",
        Severity.BLOCKING,
        "",
        "",
    )
    assert finding.message == (
        f"the previous release lists the scenario {OTHER}, which no entry has: a released "
        "scenario is deprecated or revoked by a new version, never removed"
    )
    assert withdrawn_findings(previous, {ID, OTHER}) == ()


def test_what_an_entry_gives_a_release_is_its_metadata_its_kind_and_its_archive() -> None:
    built = BuiltEntry(METADATA, True, b"zip")

    assert (built.metadata, built.tabletop, built.archive) == (METADATA, True, b"zip")


PREFIX = "approvals: the file is not as the release workflow writes it: "
NEEDED = "schema_version 1 and an object of entries are needed"


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "it needs a schema_version and entries, and nothing else"),
        ({"schema_version": 2, "entries": {}}, NEEDED),
        ({"schema_version": 1, "entries": []}, NEEDED),
        (_approvals(x={"pull_request": 1, "approvers": []}), "'x' is not the path of an entry"),
        (_approvals(**{ENTRY: {"pull_request": 1}}),
         f"{ENTRY} needs a pull request and its approvers, and nothing else"),
        (_approvals(**{ENTRY: {"pull_request": 0, "approvers": []}}),
         f"{ENTRY} has no pull request number"),
        (_approvals(**{ENTRY: {"pull_request": 1, "approvers": [f"u{n}" for n in range(11)]}}),
         f"{ENTRY} needs a list of at most 10 approvers"),
        (_approvals(**{ENTRY: {"pull_request": 1, "approvers": ["a" * 40]}}),
         f"{ENTRY} has an approver that is no GitHub login in lower case"),
        (_approvals(**{ENTRY: {"pull_request": 1, "approvers": ["a", "a"]}}),
         f"{ENTRY} names an approver twice"),
    ],
)  # fmt: skip
def test_an_approvals_file_out_of_its_shape_says_where(document: Any, why: str) -> None:
    with pytest.raises(ValueError, match="approvals: ") as error:
        approvals_from_document(document)

    assert str(error.value) == PREFIX + why


def test_the_approvals_file_takes_its_bounds_whole() -> None:
    """The first pull request, ten approvers and a login of 39 characters are all GitHub's."""
    approvers = ["a" * 39, *(f"u{n}" for n in range(9))]
    document = _approvals(**{ENTRY: {"pull_request": 1, "approvers": approvers}})

    assert approvals_from_document(document) == {ENTRY: Approval(1, tuple(sorted(approvers)))}


def test_the_first_pull_request_may_be_merged_before_review() -> None:
    document = {"pull_requests": [{"number": 1, "reason": "the first"}]}

    assert merged_before_review_from_document(document) == frozenset({1})


def test_a_list_merged_before_review_out_of_its_shape_says_what_it_needs() -> None:
    with pytest.raises(ValueError, match="merged-before-review: ") as error:
        merged_before_review_from_document({})

    assert str(error.value) == (
        "merged-before-review: must list pull_requests, each a number with a reason, once"
    )


def test_a_channel_out_of_the_list_is_named_with_the_list() -> None:
    with pytest.raises(ValueError, match="channel") as error:
        manifest(channel="beta", issued_at="x", release="y", items=[])

    assert str(error.value) == "the channel 'beta' is not one of edge, stable"


def test_a_moment_without_its_offset_says_so() -> None:
    with pytest.raises(ValueError, match="offset") as error:
        issued_at_text(datetime.datetime(2026, 10, 30))

    assert str(error.value) == "a moment without its offset from UTC is no time of issue"
