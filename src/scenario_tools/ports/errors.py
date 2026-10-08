"""Errors that adapters raise and use cases handle."""


class UnsafeInputError(Exception):
    """Input refused by a bounded reader, with its ``IO-*`` code."""

    def __init__(self, code: str, message: str, path: str = "<input>") -> None:
        super().__init__(f"{code} {path}: {message}")
        self.code = code
        self.message = message
        self.path = path
