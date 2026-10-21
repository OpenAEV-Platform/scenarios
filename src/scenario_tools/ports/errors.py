"""Errors that adapters raise and use cases handle."""


class UnsafeInputError(Exception):
    """Input refused, with its code: ``IO-*`` for unsafe or malformed input, ``VER-*`` for a
    versioning refusal such as an invalid inject mapping."""

    def __init__(self, code: str, message: str, path: str = "<input>", field: str = "") -> None:
        super().__init__(f"{code} {path}: {message}")
        self.code = code
        self.message = message
        self.path = path
        self.field = field  # the JSON pointer of the node at fault; empty is the whole file


class EnvironmentProblemError(Exception):
    """The environment cannot be used: a missing credential, an unreachable service. This is
    never the input's fault, so it is never reported as a finding (exit code 3)."""


class OutcomeUnknownError(EnvironmentProblemError):
    """A service failed after the request may have reached it: what it did is not known."""
