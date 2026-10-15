"""The release manifest. Each item copies what a consumer needs to list and filter the
catalogue from the manifest alone, says which archive was built and who approved the change
that brought it; the release takes its name from the day of its commit and its rank that day.
Nothing in it depends on when, or where, it is built."""

import copy
import datetime
import itertools
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from scenario_tools.domain.shared.commits import is_commit_id
from scenario_tools.domain.shared.finding import Finding, Severity

CHANNELS = ("edge", "stable")
REPOSITORY = "OpenAEV-Platform/scenarios"
SCHEMA_VERSION = 1

# What an item copies from the entry's scenario.yaml, in the order of the data model.
_COPIED = (
    "external_id",
    "version",
    "status",
    "name",
    "description",
    "severity",
    "category",
    "main_focus",
    "platforms",
    "threat",
    "type",
)
_RELEASE = re.compile(r"([0-9]{4})\.([0-9]{2})\.([0-9]{2})\.([1-9][0-9]*)")
_LOGIN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_LOGIN_LIMIT = 39
_APPROVERS_LIMIT = 10
_ENTRY = re.compile(r"scenarios/[^/]+/[^/]+")


@dataclass(frozen=True)
class ArchiveFacts:
    """An archive built: its file name, its SHA-256 and its size in bytes."""

    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class BuiltEntry:
    """What an entry gives a release: its ``scenario.yaml`` as checked, whether it is tabletop,
    and its archive."""

    metadata: Mapping[str, Any]
    tabletop: bool
    archive: bytes


@dataclass(frozen=True)
class Approval:
    """The pull request that last changed an entry, and the logins of those who approved it,
    sorted."""

    pull_request: int
    approvers: tuple[str, ...]


@dataclass(frozen=True)
class Approvals:
    """The approval of each entry, by its path, collected at ``commit``, the commit a release of
    them is built from."""

    commit: str
    entries: Mapping[str, Approval]


@dataclass(frozen=True)
class PreviousRelease:
    """What a previous release says that this one needs: its channel, its name, the hash of
    each archive, by external ID and version, and what it said of each, but who approved it."""

    channel: str
    release: str
    archives: Mapping[tuple[str, str], str]
    items: Mapping[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)


# What may differ between two releases of one version: who approved its last change, and the
# report of its test run; the archive is compared by its hash.
_NOT_SAID = frozenset({"archive", "approvals", "test_report"})


def _said(item: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if key not in _NOT_SAID}


def archive_name(external_id: str, version: str) -> str:
    """The file name of a scenario's archive in a release."""
    return f"{external_id}-{version}.zip"


def manifest_item(
    metadata: Mapping[str, Any], *, tabletop: bool, archive: ArchiveFacts, approval: Approval
) -> dict[str, Any]:
    """The item of an entry whose ``scenario.yaml`` holds ``metadata``, as checked against its
    schema: its catalogue facets, as copies, then what was built and who approved it."""
    item = {key: copy.deepcopy(metadata[key]) for key in _COPIED}
    item["tabletop"] = tabletop
    item["requires"] = copy.deepcopy(metadata["requires"])
    item["archive"] = {"name": archive.name, "sha256": archive.sha256, "size": archive.size}
    item["payloads"] = [
        {"id": reference["id"], "version": reference["version"], "sha256": reference["sha256"]}
        for reference in metadata["payloads"]
    ]
    item["approvals"] = {
        "pull_request": approval.pull_request,
        "approvers": list(approval.approvers),
    }
    return item


def manifest(
    *, channel: str, issued_at: str, release: str, items: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """The manifest of a release on ``channel``, its items sorted by external ID, one each."""
    if channel not in CHANNELS:
        raise ValueError(f"the channel {channel!r} is not one of {', '.join(CHANNELS)}")
    listed = sorted(items, key=lambda item: str(item["external_id"]))
    for before, after in itertools.pairwise(listed):
        if before["external_id"] == after["external_id"]:
            raise ValueError(f"two entries have the external_id {after['external_id']}")
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "channel": channel,
        "issued_at": issued_at,
        "release": release,
        "items": [dict(item) for item in listed],
    }


def issued_at_text(moment: datetime.datetime) -> str:
    """``moment`` in UTC, to the second, as RFC 3339 writes it."""
    if moment.utcoffset() is None:
        raise ValueError("a moment without its offset from UTC is no time of issue")
    return moment.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def release_name(moment: datetime.datetime, previous: str | None) -> str:
    """The name of a release made at ``moment``: its day in UTC and its rank that day, one
    after ``previous``, the channel's previous release, when it is of the same day."""
    day = moment.astimezone(datetime.UTC).date()
    rank = 1
    if previous is not None:
        found = _RELEASE.fullmatch(previous)
        try:
            before = datetime.date(*(int(part) for part in found.groups()[:3])) if found else None
        except ValueError:  # a day no calendar has
            before = None
        if found is None or before is None:
            raise ValueError(f"{previous!r} is not a release name")
        if before > day:
            raise ValueError(f"the previous release {previous} is dated after this commit")
        if before == day:
            rank = int(found.group(4)) + 1
    return f"{day:%Y.%m.%d}.{rank}"


def _malformed(why: str) -> ValueError:
    return ValueError(f"approvals: the file is not as the release workflow writes it: {why}")


def is_github_login(value: object) -> bool:
    """Whether ``value`` is a GitHub login in lower case: letters, digits and inner single
    hyphens, 39 characters at most."""
    return isinstance(value, str) and len(value) <= _LOGIN_LIMIT and bool(_LOGIN.fullmatch(value))


def _approval(entry: str, value: object) -> Approval:
    if not isinstance(value, dict) or set(value) != {"pull_request", "approvers"}:
        raise _malformed(f"{entry} needs a pull request and its approvers, and nothing else")
    number, approvers = value["pull_request"], value["approvers"]
    if type(number) is not int or number < 1:
        raise _malformed(f"{entry} has no pull request number")
    if not isinstance(approvers, list) or len(approvers) > _APPROVERS_LIMIT:
        raise _malformed(f"{entry} needs a list of at most {_APPROVERS_LIMIT} approvers")
    for login in approvers:
        if not is_github_login(login):
            raise _malformed(f"{entry} has an approver that is no GitHub login in lower case")
    if len(set(approvers)) != len(approvers):
        raise _malformed(f"{entry} names an approver twice")
    return Approval(number, tuple(sorted(approvers)))


def approvals_from_document(document: object) -> Approvals:
    """The approval of each entry, by its path, and the commit they were collected at, from the
    approvals file the release workflow writes; one out of its shape is refused, never read in
    part."""
    if not isinstance(document, dict) or set(document) != {"schema_version", "commit", "entries"}:
        raise _malformed("it needs a schema_version, a commit and entries, and nothing else")
    if document["schema_version"] != 1 or not isinstance(document["entries"], dict):
        raise _malformed("schema_version 1 and an object of entries are needed")
    commit = document["commit"]
    if not isinstance(commit, str) or not is_commit_id(commit):
        raise _malformed(f"{commit!r} is not a commit ID")
    approvals = {}
    for entry, value in document["entries"].items():
        if not _ENTRY.fullmatch(entry):
            raise _malformed(f"{entry!r} is not the path of an entry")
        approvals[entry] = _approval(entry, value)
    return Approvals(commit, approvals)


def approvals_document(approvals: Approvals) -> dict[str, Any]:
    """The approvals file ``build`` reads, its entries sorted by path."""
    return {
        "schema_version": 1,
        "commit": approvals.commit,
        "entries": {
            entry: {
                "pull_request": approvals.entries[entry].pull_request,
                "approvers": list(approvals.entries[entry].approvers),
            }
            for entry in sorted(approvals.entries)
        },
    }


def merged_before_review_from_document(document: object) -> frozenset[int]:
    """The pull requests merged before reviews were required, each listed once with why, from
    the policy data the maintainers review."""
    refused = ValueError(
        "merged-before-review: must list pull_requests, each a number with a reason, once"
    )
    if not isinstance(document, dict) or set(document) != {"pull_requests"}:
        raise refused
    listed = document["pull_requests"]
    if not isinstance(listed, list):
        raise refused
    numbers: set[int] = set()
    for value in listed:
        if not isinstance(value, dict) or set(value) != {"number", "reason"}:
            raise refused
        number, reason = value["number"], value["reason"]
        if type(number) is not int or number < 1 or number in numbers:
            raise refused
        if not isinstance(reason, str) or not reason.strip():
            raise refused
        numbers.add(number)
    return frozenset(numbers)


def approval_findings(
    entries: Iterable[str], approvals: Mapping[str, Approval], before_review: frozenset[int]
) -> tuple[Finding, ...]:
    """``REL-001`` for each of ``entries`` the approvals file leaves out, and ``REL-002`` for
    each whose last pull request has no approver, unless it was merged before reviews were
    required."""
    findings = []
    for entry in entries:
        approval = approvals.get(entry)
        if approval is None:
            message = "the approvals file names no pull request for this entry"
            findings.append(Finding("REL-001", Severity.BLOCKING, entry, "", message))
        elif not approval.approvers and approval.pull_request not in before_review:
            message = (
                f"pull request #{approval.pull_request}, the last to change this entry, has no "
                "approval, and is not listed as merged before reviews were required"
            )
            findings.append(Finding("REL-002", Severity.BLOCKING, entry, "", message))
    return tuple(findings)


def withdrawn_findings(previous: PreviousRelease, present: Iterable[str]) -> tuple[Finding, ...]:
    """``REL-003`` for each scenario of the previous release that no entry has, by external ID
    among ``present``: a released scenario is withdrawn by a new version, never removed."""
    kept = set(present)
    gone = sorted({external_id for external_id, _ in previous.archives} - kept)
    return tuple(
        Finding(
            "REL-003",
            Severity.BLOCKING,
            "",
            "",
            f"the previous release lists the scenario {external_id}, which no entry has: a "
            "released scenario is deprecated or revoked by a new version, never removed",
        )
        for external_id in gone
    )


def previous_release(document: Mapping[str, Any]) -> PreviousRelease:
    """What the manifest ``document`` of a previous release, checked against its schema, says
    that the next one needs; one that lists a scenario twice is refused, never read in part."""
    archives: dict[tuple[str, str], str] = {}
    items: dict[tuple[str, str], Mapping[str, Any]] = {}
    seen: set[str] = set()
    for item in document["items"]:
        external_id = str(item["external_id"])
        if external_id in seen:
            raise ValueError(f"the previous release lists {external_id} twice")
        seen.add(external_id)
        key = (external_id, str(item["version"]))
        archives[key] = str(item["archive"]["sha256"])
        items[key] = _said(item)
    return PreviousRelease(str(document["channel"]), str(document["release"]), archives, items)


def released_item_findings(
    entry: str, item: Mapping[str, Any], previous: PreviousRelease
) -> tuple[Finding, ...]:
    """``VER-020`` when the previous release holds the version of ``item`` and said otherwise
    of it, its status or its facets: a released version never changes, its archive no more
    than what the manifest says of it."""
    key = (str(item["external_id"]), str(item["version"]))
    before = previous.items.get(key)
    if before is None:
        return ()
    now = _said(item)
    changed = sorted(
        name for name in before.keys() | now.keys() if before.get(name) != now.get(name)
    )
    if not changed:
        return ()
    message = (
        f"version {key[1]} was released saying otherwise of {', '.join(changed)}, and a released "
        "version never changes: raise the version"
    )
    return (Finding("VER-020", Severity.BLOCKING, f"{entry}/scenario.yaml", "/version", message),)
