"""Ports: the files of the repository's entries, read within the repository, and an entry
written in it."""

from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Protocol

from scenario_tools.domain.catalogue.intake import CatalogueEntry


class EntrySource(Protocol):
    """Reads files by their path relative to the repository, never following a symbolic link,
    parent directories included, and within the input limits; a refused file raises
    ``UnsafeInputError`` with its ``IO-*`` code."""

    def names(self, entry: str) -> frozenset[str]:
        """The names in the directory ``entry``, whatever their kind."""
        ...

    def read_yaml(self, path: str) -> object:
        """The YAML document at ``path``."""
        ...

    def read_json(self, path: str) -> tuple[bytes, object]:
        """The bytes of the JSON document at ``path``, and the document."""
        ...

    def read_text(self, path: str) -> str:
        """The UTF-8 text at ``path``."""
        ...

    def exists(self, path: str) -> bool:
        """Whether something is at ``path``, a link included, never followed."""
        ...

    def entries(self) -> tuple[CatalogueEntry, ...]:
        """Every entry with its directory, external ID and scenario name, in path order. An entry
        whose ``scenario.yaml`` declares a name but no usable external ID is kept, with an empty
        one, so that no other entry takes its name. One that is a link, or whose
        ``scenario.yaml`` cannot be read or is not a mapping, is kept as unreadable, as what it
        declares is unknown, as is a domain that is a link; one that declares neither is left
        out. Their own check says why, and the tool's own hidden names are no entry. A
        ``scenarios`` directory that is a link is refused (``IO-013``)."""
        ...

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        """Every entry's external ID, mapped to the directories that declare it; an entry whose
        ``scenario.yaml`` cannot be read, or declares none, is left out: its own check says
        why."""
        ...


class WrittenEntry(Protocol):
    """An entry being written."""

    def check(self) -> None:
        """Make sure what reads the entry by its path afterwards reads what was written: the
        repository's path still names the repository held, if one is, and the entry's path the
        entry written, with each file as written. Raises ``EnvironmentProblemError``
        otherwise."""
        ...


class EntryWriter(Protocol):
    """Writes an entry in the repository, never through a link, for as long as a block runs."""

    def writing(
        self,
        entry: str,
        files: Mapping[str, bytes],
        *,
        previous: Mapping[str, bytes] | None,
    ) -> AbstractContextManager[WrittenEntry]:
        """Write ``files``, by name, in the entry at ``entry``. Without ``previous``, the entry
        is new: it is made only where nothing is, with the directories above it that are
        missing. With it, each file is replaced at once, once it is known to still hold its
        ``previous`` bytes. If the block does not end, what was written is taken back, never
        what another put there; what cannot be is said (``EnvironmentProblemError``). A link
        on the entry's path is refused (``UnsafeInputError``, ``IO-013``). Nothing to write
        writes nothing, and the block is still given its check."""
        ...
