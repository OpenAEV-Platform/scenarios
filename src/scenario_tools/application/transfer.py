"""Export a scenario from the platform, or import an archive into it.

An export is checked before it is written, so that a refused archive never reaches the output.
Each inject the platform skips at import is a blocking finding: a partial import never reads as
a success.
"""

from collections.abc import Callable

from scenario_tools.domain.shared.finding import Finding, Report, Severity
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


def import_archive(platform: OpenAEV, archive: bytes, path: str) -> Report:
    """Import an archive already checked; ``path`` is the archive, relative to the repository
    root."""
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
