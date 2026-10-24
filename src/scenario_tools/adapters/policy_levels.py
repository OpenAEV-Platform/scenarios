"""Adapter: where policy data lies above an entry, as the file system says."""

import os
from pathlib import Path

from scenario_tools.ports.errors import EnvironmentProblemError


def policy_levels(out: Path) -> list[Path]:
    """OUT and those of its parents that hold policy data, from the deepest up."""
    resolved = Path(os.path.realpath(out))  # a loop of links is left as it is, not raised
    try:
        return [
            directory
            for directory in (resolved, *resolved.parents)
            if (directory / "policy" / "data").is_dir()
        ]
    except OSError as error:  # a directory that cannot be searched, for instance
        raise EnvironmentProblemError(
            f"cannot look for policy data above {out}: {error.strerror}"
        ) from error
