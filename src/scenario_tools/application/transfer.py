"""Export a scenario from the platform, or import an archive into it.

An export is checked before it is written, so that a refused archive never reaches the output.
Each inject the platform skips at import is a blocking finding: a partial import never reads as
a success.
"""

from collections.abc import Callable

from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.ports.errors import UnsafeInputError
from scenario_tools.ports.openaev import OpenAEV


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
    result = platform.import_scenario(archive)
    return Report(
        "openaev import",
        tuple(
            Finding(
                "OAV-001",
                Severity.BLOCKING,
                path,
                "",
                f"the platform skipped inject {skipped.name!r}: its {skipped.type} is missing on "
                "the instance",
            )
            for skipped in result.skipped
        ),
    )
