"""Port: the files of the repository's entries, read within the repository."""

from collections.abc import Mapping
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
        """Every entry with its directory, external ID and scenario name, in path order; an
        entry whose ``scenario.yaml`` cannot be read, or declares no external ID, is left out:
        its own check says why."""
        ...

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        """Every entry's external ID, mapped to the directories that declare it; an entry whose
        ``scenario.yaml`` cannot be read, or declares none, is left out: its own check says
        why."""
        ...
