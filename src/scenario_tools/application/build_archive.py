"""Build the import archive of an entry, once nothing keeps it out of one."""

from collections.abc import Callable

from scenario_tools.application.assign_payloads import payload_findings
from scenario_tools.application.findings import not_normalised
from scenario_tools.domain.catalogue.archive import archive_findings, checked_workflow
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.policy.registry import rule_findings
from scenario_tools.domain.policy.rule import EntryContent, PolicyData
from scenario_tools.domain.shared.finding import Finding, Report
from scenario_tools.domain.verification.payload_references import AgreedIds, HeldVersions
from scenario_tools.ports.archive import ArchiveBuilder
from scenario_tools.ports.errors import UnsafeInputError


def build_archive(
    document: object,
    scenario: bytes,
    attachments: bytes | None,
    path: str,
    out: str,
    builder: ArchiveBuilder,
    *,
    renormalised: Callable[[object], bytes],
    contract_findings: Callable[[object], tuple[Finding, ...]],
    check: Callable[[bytes], None],
    limit: int,
    policy: PolicyData,
    declared: object,
    agreed: AgreedIds,
    catalogue: HeldVersions,
    condition_types: frozenset[str],
) -> tuple[Report, bytes | None]:
    """The report, and the archive when the report is ok. ``scenario`` holds the stored bytes
    of ``document``, found at ``path``; the archive, meant for ``out``, is never larger than
    ``limit``, and passes ``check``, the archive checks, before it is returned.

    The entry is checked here, since its file may have been edited by hand: ``renormalised``
    gives what normalisation writes for the document, and ``contract_findings`` the contracts
    whose facts cannot be established. ``declared`` is the entry's ``scenario.yaml`` as read,
    whose references must name each payload the scenario embeds, with its hash, under the ID
    its content has, ``agreed`` holding the IDs the registry agrees, and naming a version the
    ``catalogue`` holds. A workflow is checked as
    normalisation checks it, ``condition_types`` being the types of condition a step may hold."""
    try:
        findings = archive_findings(document, path)
        checked_workflow(document, condition_types)
        entry = EntryContent(path.rpartition("/")[0], frozenset(), None, document)
        # The archive carries no recurrence and names no host outside the allowed targets.
        findings += rule_findings("POL-002", policy, entry)
        findings += rule_findings("POL-003", policy, entry)
        findings += contract_findings(document)
        findings += payload_findings(declared, document, path.rpartition("/")[0], agreed, catalogue)
    except ExportStructureError as error:
        raise UnsafeInputError(error.code, str(error), path, error.pointer) from error
    if renormalised(document) != scenario:
        findings += (not_normalised(path),)
    if findings:
        return Report("archive", findings), None
    data = builder.build(scenario, attachments)
    if len(data) > limit:
        raise UnsafeInputError("IO-001", f"larger than {limit} bytes", out)
    check(data)
    return Report("archive"), data
