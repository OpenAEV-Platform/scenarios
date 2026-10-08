"""Errors that adapters raise and use cases handle."""


class UnsafeInputError(Exception):
    """Input refused by a bounded reader, with its ``IO-*`` code."""

    def __init__(self, code: str, message: str, path: str = "<input>") -> None:
        super().__init__(f"{code} {path}: {message}")
        self.code = code
        self.message = message
        self.path = path


class EnvironmentProblemError(Exception):
    """The environment cannot be used: a missing credential, an unreachable service. This is
    never the input's fault, so it is never reported as a finding (exit code 3)."""
