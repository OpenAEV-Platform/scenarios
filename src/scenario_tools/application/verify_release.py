"""Verify a release as its consumers will, before it is published: the manifest, then each
archive it lists, by its bytes, its safe extraction, the parts of its scenario and the payloads it
embeds, then each payload file it lists, by its bytes and its content, and nothing beside them
that the manifest does not list."""

import re
from collections.abc import Callable, Mapping, Sequence

from scenario_tools.application.assign_payloads import no_attached_files
from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.domain.verification.payload_hash import FileHash
from scenario_tools.domain.verification.release_output import (
    archive_findings,
    item_findings,
    manifest_findings,
    payload_content_findings,
    payload_file_findings,
    payload_list_findings,
    payload_reference_findings,
    shared_payload_findings,
)
from scenario_tools.ports.errors import UnsafeInputError

_CAUSE = re.compile(r"(IO-[0-9]{3}): ")


def _unsafe(name: str, error: UnsafeInputError) -> Finding:
    return Finding("VRF-007", Severity.BLOCKING, name, "", f"{error.code}: {error.message}")


def unsafe_cause(finding: Finding) -> str | None:
    """The ``IO`` code an archive refused as unsafe (``VRF-007``) was refused with, which its
    message starts with; nothing for another finding."""
    found = _CAUSE.match(finding.message) if finding.code == "VRF-007" else None
    return found.group(1) if found else None


def verify_release(
    document: object,
    *,
    validate: Callable[[object], Sequence[tuple[str, str]]],
    approved: bool,
    archive_of: Callable[[str], bytes | None],
    scenario_of: Callable[[bytes, str], object],
    present: frozenset[str],
    payload_of: Callable[[str], bytes | None],
    read_payload: Callable[[bytes], object],
    files: FileHash = no_attached_files,
) -> Report:
    """The report on the release whose manifest is ``document``: ``validate`` gives where it
    does not meet its schema, and why. ``archive_of`` gives an archive's bytes by its name, or
    nothing when it is missing; ``scenario_of`` opens an archive, refusing one unsafe to
    extract, and gives the scenario it holds; ``present`` names what stands beside the archives,
    the manifest verified left out by the caller: anything else there, a ``manifest.json``
    included, is ``VRF-006``. ``payload_of`` gives a payload file's bytes by its name, or nothing
    when it is missing, and ``read_payload`` reads them as JSON, ``ValueError`` when it cannot. A
    manifest with a finding of its own (its schema, its approver), listing a scenario twice, a
    payload version with two contents or twice, or a reference to a version it does not
    list, is reported alone: no archive or payload file is read."""
    mapping = document if isinstance(document, Mapping) else {}
    manifest = manifest_findings(validate(document), mapping, approved=approved)
    if manifest:
        return Report("verify", manifest)
    items, payloads = mapping["items"], mapping["payloads"]
    listed = (
        item_findings(items)
        or shared_payload_findings(items)
        or payload_list_findings(payloads)
        or payload_reference_findings(items, payloads)
    )
    if listed:
        return Report("verify", listed)
    findings: list[Finding] = []
    names = {str(item["archive"]["name"]) for item in items}
    names |= {str(entry["file"]["name"]) for entry in payloads}
    for extra in sorted(present - names):
        message = "the manifest does not list it, and it would be published"
        findings.append(Finding("VRF-006", Severity.BLOCKING, extra, "", message))
    for item in items:
        name = str(item["archive"]["name"])
        try:
            data = archive_of(name)
        except UnsafeInputError as error:
            findings.append(_unsafe(name, error))
            continue
        refused = archive_findings(item, data)
        findings += refused
        if refused or data is None:
            continue
        try:
            stored = scenario_of(data, name)
        except UnsafeInputError as error:
            findings.append(_unsafe(name, error))
            continue
        findings += payload_content_findings(item, stored, files)
    for entry in payloads:
        name = str(entry["file"]["name"])
        try:
            data = payload_of(name)
        except UnsafeInputError as error:
            findings.append(_unsafe(name, error))
            continue
        findings += payload_file_findings(entry, data, read_payload)
    return Report("verify", tuple(findings))
