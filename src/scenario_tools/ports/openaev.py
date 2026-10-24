"""The OpenAEV platform, as the tools use it: export a scenario, import an archive, and read
what the import would reuse."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from scenario_tools.domain.verification.held_payloads import HeldContract


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

    def held_contract(self, contract_id: str) -> HeldContract | None:
        """The contract the platform holds under ``contract_id``, with its payload, or nothing."""
        ...

    def held_payloads(self, external_ids: frozenset[str]) -> Mapping[str, object]:
        """The payloads the platform holds under each of ``external_ids``, by external ID."""
        ...
