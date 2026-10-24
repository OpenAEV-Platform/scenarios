"""Export a scenario from the platform, or import an archive into it.

An export is checked before it is written, so that a refused archive never reaches the output.
Each inject the platform skips at import is a blocking finding: a partial import never reads as
a success. Before an import, each payload the platform would reuse under an identifier the archive
gives must have the archive's content: otherwise nothing is sent.
"""

from collections.abc import Callable

from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.domain.verification.held_payloads import identifiers, reuse_findings
from scenario_tools.ports.errors import OutcomeUnknownError, UnsafeInputError
from scenario_tools.ports.openaev import OpenAEV, SkippedInject


def export_scenario(
    platform: OpenAEV,
    scenario_id: str,
    path: str,
    *,
    check: Callable[[bytes], None],
    write: Callable[[bytes], None],
) -> Report:
    """Export the scenario, check the archive, then write it to ``path``, which also names the
    archive in a refusal."""
    try:
        data = platform.export_scenario(scenario_id)
    except UnsafeInputError as error:  # refused as it arrived: reported on the output
        raise UnsafeInputError(error.code, error.message, path) from error
    check(data)
    write(data)
    return Report("openaev export")


def check_reuse(platform: OpenAEV, scenario: object, path: str) -> Report:
    """What importing the archive at ``path``, holding ``scenario``, would reuse on the platform
    with another content than the archive's: each such payload is a blocking finding. Nothing is
    written on the platform."""
    contract_ids, external_ids = identifiers(scenario)
    contracts = {
        contract_id: held
        for contract_id in sorted(contract_ids)
        if (held := platform.held_contract(contract_id)) is not None
    }
    payloads = platform.held_payloads(external_ids) if external_ids else {}
    return Report("openaev check", reuse_findings(scenario, contracts, payloads, path))


def import_archive(platform: OpenAEV, archive: bytes, path: str, scenario: object) -> Report:
    """Import an archive already checked, holding ``scenario``, once nothing it embeds would be
    replaced by another payload the platform holds under the same identifier; ``path`` is the
    archive, relative to the repository root."""
    reused = check_reuse(platform, scenario, path)
    if not reused.ok:
        return Report("openaev import", reused.findings)  # nothing is sent
    try:
        result = platform.import_scenario(archive)
    except OutcomeUnknownError as error:  # the archive may have been taken all the same
        raise OutcomeUnknownError(
            f"{error}; the scenario may have been created all the same: check the platform "
            "before trying again"
        ) from error
    return Report(
        "openaev import",
        tuple(
            Finding("OAV-001", Severity.BLOCKING, path, "", _skipped(inject))
            for inject in result.skipped
        ),
    )


def _skipped(inject: SkippedInject) -> str:
    subject = f"inject {inject.name!r}" if inject.name else "an inject without a name"
    return (
        f"the platform skipped {subject}: its {inject.type or 'dependency'} is missing on the "
        "instance"
    )
