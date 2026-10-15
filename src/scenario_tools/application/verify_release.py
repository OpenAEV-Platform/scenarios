"""Verify a release as its consumers will, before it is published: the manifest, then each
archive it lists, by its bytes, its safe extraction and the payloads it embeds, and nothing
beside them that the manifest does not list."""

from collections.abc import Callable, Mapping, Sequence

from scenario_tools.application.assign_payloads import no_attached_files
from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.domain.verification.payload_hash import FileHash
from scenario_tools.domain.verification.release_output import (
    MANIFEST,
    archive_findings,
    item_findings,
    manifest_findings,
    payload_content_findings,
)
from scenario_tools.ports.errors import UnsafeInputError


def _unsafe(name: str, error: UnsafeInputError) -> Finding:
    return Finding("VRF-007", Severity.BLOCKING, name, "", f"{error.code}: {error.message}")


def verify_release(
    document: object,
    *,
    validate: Callable[[object], Sequence[tuple[str, str]]],
    approved: bool,
    archive_of: Callable[[str], bytes | None],
    scenario_of: Callable[[bytes, str], object],
    present: frozenset[str],
    files: FileHash = no_attached_files,
) -> Report:
    """The report on the release whose manifest is ``document``: ``validate`` gives where it
    does not meet its schema, and why. ``archive_of`` gives an archive's bytes by its name, or
    nothing when it is missing; ``scenario_of`` opens an archive, refusing one unsafe to
    extract, and gives the scenario it holds; ``present`` names what stands beside the archives.
    A manifest out of its schema, or listing a scenario twice, is refused alone."""
    violations = validate(document)
    mapping = document if isinstance(document, Mapping) else {}
    findings = list(manifest_findings(violations, mapping, approved=approved))
    if violations:
        return Report("verify", tuple(findings))
    items = mapping["items"]
    listed = item_findings(items)
    if listed:
        return Report("verify", (*findings, *listed))
    names = {str(item["archive"]["name"]) for item in items}
    for extra in sorted(present - names - {MANIFEST}):
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
    return Report("verify", tuple(findings))
