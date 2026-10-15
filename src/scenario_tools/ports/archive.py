"""The import archive of an entry, as the tools build it."""

from collections.abc import Mapping, Sequence
from typing import Protocol


class ArchiveBuilder(Protocol):
    def build(self, scenario: bytes, attachments: bytes | None) -> bytes:
        """The archive holding the stored scenario and, when there are some, its attachments,
        both as they are."""
        ...


class FixtureArchives(Protocol):
    """The archives the release fixtures need beside those ``build`` writes, the same bytes on
    every build."""

    def stored(
        self, entries: Sequence[tuple[str, bytes, bytes]], *, links: frozenset[str] = frozenset()
    ) -> bytes:
        """An archive of ``entries``, each a name, its bytes and its comment, stored as given,
        whatever the name; those named in ``links`` are symbolic links to their bytes."""
        ...

    def bomb(self, name: str, comment: bytes, size: int, *, declared: int | None = None) -> bytes:
        """An archive of one entry, ``size`` zero bytes deflated into a small stream, which
        declares ``declared`` bytes, or its own size."""
        ...

    def attachments(self, files: Mapping[str, bytes], password: bytes) -> bytes:
        """An attachments archive of ``files``, by name, each encrypted with ``password``."""
        ...
