"""Build the import archive of an entry, once nothing keeps it out of one."""

from collections.abc import Callable

from scenario_tools.application.findings import not_normalised
from scenario_tools.domain.catalogue.archive import archive_findings
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.shared.finding import Finding, Report
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
) -> tuple[Report, bytes | None]:
    """The report, and the archive when the report is ok. ``scenario`` holds the stored bytes
    of ``document``, found at ``path``; the archive, meant for ``out``, is never larger than
    ``limit``, and passes ``check``, the archive checks, before it is returned.

    The entry is checked here, since its file may have been edited by hand: ``renormalised``
    gives what normalisation writes for the document, and ``contract_findings`` the contracts
    whose facts cannot be established."""
    try:
        findings = archive_findings(document, path)
        findings += contract_findings(document)
    except ExportStructureError as error:
        raise UnsafeInputError(error.code, str(error), path) from error
    if renormalised(document) != scenario:
        findings += (not_normalised(path),)
    if findings:
        return Report("archive", findings), None
    data = builder.build(scenario, attachments)
    if len(data) > limit:
        raise UnsafeInputError("IO-001", f"larger than {limit} bytes", out)
    check(data)
    return Report("archive"), data
