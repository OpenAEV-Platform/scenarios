"""The import archive of an entry, as the tools build it."""

from typing import Protocol


class ArchiveBuilder(Protocol):
    def build(self, scenario: bytes, attachments: bytes | None) -> bytes:
        """The archive holding the stored scenario and, when there are some, its attachments,
        both as they are."""
        ...
