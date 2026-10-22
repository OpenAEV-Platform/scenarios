"""Use case: check the payload catalogue, ``payloads/``, file by file and as a whole."""

from collections.abc import Mapping

from scenario_tools.domain.shared.finding import Finding, Report
from scenario_tools.domain.verification.payload_catalogue import (
    catalogue_findings,
    layout,
    schema_findings,
)
from scenario_tools.domain.verification.payload_references import AgreedIds
from scenario_tools.domain.verification.payload_version import PayloadVersion, version_findings
from scenario_tools.ports.catalogue import CatalogueFiles
from scenario_tools.ports.schema import SchemaValidator


def validate_payloads(
    files: CatalogueFiles, schema: SchemaValidator, agreed: AgreedIds, root: str
) -> Report:
    """The findings on the catalogue ``files`` hold, at ``root`` in the repository: its layout,
    each version file against the payload schema, its stored form, its name and its ID by the IDs
    ``agreed``, then the rules across its versions. A file the schema refuses is checked no
    further."""
    findings: list[Finding] = []
    layout_findings, places = layout(root, files.entries())
    findings += layout_findings
    versions: list[PayloadVersion] = []
    for place in places:
        data, document = files.read((place.slug, f"{place.version}.json"))
        violations = schema.validate("payload", document)
        if violations or not isinstance(document, Mapping):
            findings += schema_findings(place.path, [v.pointer for v in violations])
            continue
        version = PayloadVersion(place.slug, place.version, place.path, document)
        findings += version_findings(version, data, agreed)
        versions.append(version)
    findings += catalogue_findings(versions)
    return Report("validate-payloads", tuple(findings))
