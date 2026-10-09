"""Data the rules read, kept as files that the maintainers own."""

from typing import Any, Protocol


class DataLoader(Protocol):
    def load(self, name: str) -> Any:
        """The data document called ``name``, such as ``volatile-fields``."""
        ...
