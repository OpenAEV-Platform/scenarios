"""Port: the files of the payload catalogue, ``payloads/``."""

from typing import Protocol

from scenario_tools.domain.verification.payload_catalogue import TreeEntry


class CatalogueFiles(Protocol):
    def entries(self) -> tuple[TreeEntry, ...]:
        """Every entry of the catalogue down to its version files, without following a link:
        a link is an entry of its own kind, and nothing below a payload folder's entries is
        listed."""
        ...

    def read(self, path: tuple[str, ...]) -> tuple[bytes, object]:
        """The bytes of the version file at ``path`` and the JSON document they hold, read as
        every file of the repository is (no link, no key twice, no unpaired surrogate); an
        ``UnsafeInputError`` when they cannot be read so."""
        ...
