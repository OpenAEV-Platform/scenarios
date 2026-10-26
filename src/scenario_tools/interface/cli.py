"""Command-line entry point: ``scenario-tools``.

Every command returns a report through ``execute``, which renders it as text or as the JSON
document of the contract and gives the exit code: 0 when the report is ok, 1 with a blocking
finding, 2 on a usage error (click), 3 when the environment cannot be used, and 4 when the tool
itself fails, so that a defect of the tool never reads as a defect of the content.
"""

from scenario_tools.interface import entries, intake, openaev, payloads, release
from scenario_tools.interface.base import (
    EXIT_BLOCKING,
    EXIT_ENVIRONMENT,
    EXIT_INTERNAL,
    EXIT_OK,
    execute,
    main,
)

__all__ = [
    "EXIT_BLOCKING",
    "EXIT_ENVIRONMENT",
    "EXIT_INTERNAL",
    "EXIT_OK",
    "entries",
    "execute",
    "intake",
    "main",
    "openaev",
    "payloads",
    "release",
]
