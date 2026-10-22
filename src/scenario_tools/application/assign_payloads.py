"""The payload references of an entry: checked by ``validate``, ``archive`` and ``payloads``,
and given by ``payloads --assign`` and ``intake``. The bytes of an attached file are not read
yet, so a payload that carries one is refused until they are."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.verification.payload_catalogue import (
    Catalogue,
    CatalogueCollisionError,
    layout,
)
from scenario_tools.domain.verification.payload_references import (
    AgreedIds,
    HeldVersions,
    assign,
    declared_references,
    reference_findings,
)
from scenario_tools.domain.verification.payload_version import PayloadVersion
from scenario_tools.ports.catalogue import CatalogueFiles
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError


@dataclass(frozen=True)
class AssignedEntry:
    """An entry whose payloads carry their IDs: its ``scenario.yaml`` and its stored scenario;
    or, when they cannot be given, the refusals and nothing else."""

    metadata: dict[str, Any] | None
    stored: Mapping[str, Any] | None
    refusals: tuple[Finding, ...] = ()


def agreed_ids(data: DataLoader) -> AgreedIds:
    """The payload IDs the registry agrees, from the repository's data."""
    try:
        return AgreedIds.from_document(data.load("payload-ids"))
    except (ValueError, UnsafeInputError) as error:  # the repository's data, not the entry's
        raise EnvironmentProblemError(f"policy data cannot be used: {error}") from error


def catalogue_of(files: CatalogueFiles | None) -> Catalogue:
    """The index of the repository's payload catalogue, ``files`` (empty when it has no
    ``payloads/``). A catalogue the index cannot be built on is the repository's fault, never an
    entry's: `validate-payloads` says why."""
    if files is None:
        return Catalogue.of([])
    try:
        _, places = layout("payloads", files.entries())
        versions = []
        for place in places:
            _, document = files.read((place.slug, f"{place.version}.json"))
            if isinstance(document, Mapping):
                versions.append(PayloadVersion(place.slug, place.version, place.path, document))
        return Catalogue.of(versions)
    except (CatalogueCollisionError, UnsafeInputError, KeyError, TypeError) as error:
        raise EnvironmentProblemError(
            "the payload catalogue cannot be used: run `scenario-tools validate-payloads` "
            f"({error})"
        ) from error


def no_attached_files(document: str) -> str | None:
    """No attached file's bytes are read yet: a payload that carries one cannot be hashed."""
    return None


def payload_findings(
    declared: object, stored: object, entry: str, agreed: AgreedIds, catalogue: HeldVersions
) -> tuple[Finding, ...]:
    """What keeps the payloads of the stored scenario of ``entry`` from carrying the IDs their
    contents have, each named by a reference of its ``scenario.yaml``, ``declared``, which names
    a version of the ``catalogue``."""
    return reference_findings(
        stored,
        declared_references(declared),
        agreed=agreed,
        catalogue=catalogue,
        scenario=f"{entry}/scenario.json",
        metadata=f"{entry}/scenario.yaml",
        files=no_attached_files,
    )


def _refused(code: str, path: str, message: str) -> AssignedEntry:
    return AssignedEntry(None, None, (Finding(code, Severity.BLOCKING, path, "", message),))


def assigned_entry(
    declared: object, stored: object, entry: str, agreed: AgreedIds, catalogue: HeldVersions
) -> AssignedEntry:
    """``entry`` with each payload given the ID its content has, in its stored scenario and in
    the references of its ``scenario.yaml``, whose key keeps its place among the others."""
    if not isinstance(declared, dict):
        return _refused(
            "SCH-001",
            f"{entry}/scenario.yaml",
            "scenario.yaml must be an object holding the entry's metadata",
        )
    if not isinstance(stored, dict):
        return _refused(
            "IO-014",
            f"{entry}/scenario.json",
            "not an OpenAEV scenario export: the document must be an object",
        )
    result = assign(
        stored,
        agreed=agreed,
        catalogue=catalogue,
        files=no_attached_files,
        scenario=f"{entry}/scenario.json",
    )
    if result.refusals:
        return AssignedEntry(None, None, result.refusals)
    given = [
        {"id": reference.id, "version": reference.version, "sha256": reference.sha256}
        for reference in result.references
    ]
    return AssignedEntry({**declared, "payloads": given}, result.stored)
