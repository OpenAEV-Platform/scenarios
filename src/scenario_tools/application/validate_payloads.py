"""Use case: check the payload catalogue, ``payloads/``, file by file and as a whole."""

from collections.abc import Mapping

from scenario_tools.domain.shared.finding import Finding, Report
from scenario_tools.domain.verification.payload_catalogue import (
    catalogue_findings,
    immutability_findings,
    layout,
    schema_findings,
)
from scenario_tools.domain.verification.payload_references import AgreedIds
from scenario_tools.domain.verification.payload_version import PayloadVersion, version_findings
from scenario_tools.ports.catalogue import CatalogueFiles
from scenario_tools.ports.schema import SchemaValidator


def checked_payloads(
    files: CatalogueFiles, schema: SchemaValidator, agreed: AgreedIds, root: str
) -> tuple[tuple[Finding, ...], tuple[tuple[PayloadVersion, bytes], ...]]:
    """The findings on the catalogue ``files`` hold, at ``root`` in the repository: its layout,
    each version file against the payload schema, its stored form, its name and its ID by the IDs
    ``agreed``, then the rules across its versions; and each version the schema accepts, with the
    bytes of its file. A file the schema refuses is checked no further."""
    findings: list[Finding] = []
    layout_findings, places = layout(root, files.entries())
    findings += layout_findings
    versions: list[tuple[PayloadVersion, bytes]] = []
    for place in places:
        data, document = files.read((place.slug, f"{place.version}.json"))
        violations = schema.validate("payload", document)
        if violations or not isinstance(document, Mapping):
            findings += schema_findings(place.path, [v.pointer for v in violations])
            continue
        version = PayloadVersion(place.slug, place.version, place.path, document)
        findings += version_findings(version, data, agreed)
        versions.append((version, data))
    findings += catalogue_findings([version for version, _ in versions], agreed.own)
    return tuple(findings), tuple(versions)


def _held(files: CatalogueFiles, root: str) -> dict[tuple[str, str], bytes]:
    """The bytes of each version file the catalogue ``files`` hold, by slug and version."""
    _, places = layout(root, files.entries())
    return {
        (place.slug, place.version): files.read((place.slug, f"{place.version}.json"))[0]
        for place in places
    }


def validate_payloads(
    files: CatalogueFiles,
    schema: SchemaValidator,
    agreed: AgreedIds,
    root: str,
    base: CatalogueFiles | None = None,
) -> Report:
    """The report on the catalogue ``files`` hold, at ``root`` in the repository, as
    ``checked_payloads`` checks it; with ``base``, the catalogue of the base branch, also what
    it does to the versions the base holds (``VER-022``, ``VER-023``)."""
    findings, _ = checked_payloads(files, schema, agreed, root)
    if base is not None:
        findings += immutability_findings(_held(base, root), _held(files, root), root)
    return Report("validate-payloads", findings)
