"""Turn what the adapters refuse into findings."""

from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.errors import UnsafeInputError

_NO_FILE = "<input>"


def finding_from_unsafe_input(error: UnsafeInputError) -> Finding:
    """A refused input is a blocking ``IO-*`` finding on its file."""
    path = "" if error.path == _NO_FILE else error.path
    return Finding(error.code, Severity.BLOCKING, path, "", error.message)
