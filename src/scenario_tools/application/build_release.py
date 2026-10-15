"""Build a release from the catalogue: every entry's archive and the manifest that lists them,
once no entry, approval or earlier release keeps one out."""

import datetime
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.release.manifest import (
    Approval,
    ArchiveFacts,
    BuiltEntry,
    PreviousRelease,
    approval_findings,
    archive_name,
    issued_at_text,
    manifest,
    manifest_item,
    release_name,
    withdrawn_findings,
)
from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.domain.verification.versioning import released_version_findings
from scenario_tools.ports.errors import EnvironmentProblemError


@dataclass(frozen=True)
class ArchivedEntry:
    """What the archive's checks found of an entry, the archive when they let it be built, and
    what they read: its ``scenario.yaml`` and its ``scenario.json``, so that the item and the
    archive come from the same bytes. The repository is held while it is read, and checked
    again before anything is written."""

    findings: tuple[Finding, ...]
    archive: bytes | None
    metadata: Mapping[str, Any]
    document: object


@dataclass(frozen=True)
class EntryResult:
    """What an entry's checks found, and what it gives the release when nothing blocks it."""

    findings: tuple[Finding, ...]
    built: BuiltEntry | None


@dataclass(frozen=True)
class Release:
    """The manifest, in its canonical form, and the archives it lists, by file name."""

    manifest: bytes
    archives: Mapping[str, bytes]


def _blocks(findings: Sequence[Finding]) -> bool:
    return any(finding.severity is Severity.BLOCKING for finding in findings)


def entry_for_release(
    entry: str,
    *,
    validate: Callable[[str], tuple[Finding, ...]],
    archive: Callable[[str], ArchivedEntry],
    tabletop: Callable[[object, str], bool],
) -> EntryResult:
    """``entry`` checked as ``validate`` checks it, then, when nothing blocks, archived by the
    archive's code, and told tabletop from its ``scenario.json``. An entry left without an
    archive always says why."""
    findings = validate(entry)
    if _blocks(findings):
        return EntryResult(findings, None)
    archived = archive(entry)
    findings += archived.findings
    if archived.archive is None:
        # A release never leaves an entry out unsaid: an archive the checks keep back for an
        # informative finding alone is a defect, never a silent gap.
        if not _blocks(archived.findings):
            raise ValueError(f"{entry}: no archive was built, and nothing blocks it")
        return EntryResult(findings, None)
    is_tabletop = tabletop(archived.document, entry)
    return EntryResult(findings, BuiltEntry(archived.metadata, is_tabletop, archived.archive))


def build_release(
    entries: Sequence[str],
    build_entry: Callable[[str], EntryResult],
    *,
    approvals: Mapping[str, Approval],
    before_review: frozenset[int],
    previous: PreviousRelease | None,
    channel: str,
    moment: datetime.datetime,
) -> tuple[Report, Release | None]:
    """The report, and the release of ``entries`` on ``channel`` when the report is ok.
    ``build_entry`` checks an entry and builds its archive; ``moment`` is the time of the
    commit the release comes from, never of the run, so that two builds give the same bytes.
    ``previous`` is the channel's previous release, if it has one."""
    if not entries:
        raise EnvironmentProblemError("the catalogue has no entry: nothing to release")
    if previous is not None and previous.channel != channel:
        raise EnvironmentProblemError(
            f"the previous release is on {previous.channel}, not {channel}: give the previous "
            "release of the same channel"
        )
    try:
        name = release_name(moment, previous.release if previous else None)
    except ValueError as error:
        raise EnvironmentProblemError(f"cannot name the release: {error}") from error
    findings = list(approval_findings(entries, approvals, before_review))
    built: dict[str, BuiltEntry] = {}
    for entry in entries:
        result = build_entry(entry)
        findings += result.findings
        if result.built is not None:
            built[entry] = result.built
    items = []
    archives = {}
    for entry, found in built.items():
        external_id, version = str(found.metadata["external_id"]), str(found.metadata["version"])
        sha256 = hashlib.sha256(found.archive).hexdigest()
        if previous is not None:
            findings += released_version_findings(
                entry, external_id, version, sha256, previous.archives
            )
        approval = approvals.get(entry)
        if approval is None:  # said above
            continue
        facts = ArchiveFacts(archive_name(external_id, version), sha256, len(found.archive))
        items.append(
            manifest_item(found.metadata, tabletop=found.tabletop, archive=facts, approval=approval)
        )
        archives[facts.name] = found.archive
    if previous is not None and len(built) == len(entries):  # an entry left out is said above
        present = {str(found.metadata["external_id"]) for found in built.values()}
        findings += withdrawn_findings(previous, present)
    report = Report("build", tuple(findings))
    if not report.ok:
        return report, None
    document = manifest(
        channel=channel, issued_at=issued_at_text(moment), release=name, items=items
    )
    return report, Release(jcs(document), archives)
