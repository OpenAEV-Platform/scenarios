"""The OpenAEV platform, as the tools use it: export a scenario, import an archive."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SkippedInject:
    """An inject the platform did not create, because the instance lacks a dependency of it.
    The platform may give neither its name nor the kind of the missing dependency."""

    type: str | None
    name: str | None


@dataclass(frozen=True)
class ImportResult:
    skipped: tuple[SkippedInject, ...]


class OpenAEV(Protocol):
    def export_scenario(self, scenario_id: str) -> bytes:
        """The export archive of the scenario, taken with the fixed export options."""
        ...

    def import_scenario(self, archive: bytes) -> ImportResult:
        """Import an archive and return what the platform skipped."""
        ...
