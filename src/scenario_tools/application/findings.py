"""Turn what the adapters refuse into findings."""

import re
from pathlib import PurePath, PurePosixPath

from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import UnsafeInputError

_NO_FILE = "<input>"
_DRIVE = re.compile(r"[A-Za-z]:")


def repository_path(raw: str, root: PurePath) -> str:
    """``raw`` as a path relative to the repository root, or empty when there is no file. A path
    outside the repository, or one that cannot be expressed with ``/`` separators, keeps only its
    file name, so that no path of the runner is ever reported."""
    if raw == _NO_FILE:
        return ""
    path = PurePosixPath(raw)
    if path.is_absolute():
        try:
            path = path.relative_to(PurePosixPath(root))
        except ValueError:
            path = PurePosixPath(path.name)
    candidate = "" if path == PurePosixPath() else path.as_posix()
    if ".." in path.parts or "\\" in candidate or _DRIVE.match(candidate):
        name = re.split(r"[\\/]", raw)[-1]
        return "" if name in ("", "..") or _DRIVE.match(name) else name
    return candidate


def finding_from_unsafe_input(error: UnsafeInputError, root: PurePath) -> Finding:
    """A refused input is a blocking ``IO-*`` finding on its file."""
    return Finding(
        error.code, Severity.BLOCKING, repository_path(error.path, root), "", error.message
    )
