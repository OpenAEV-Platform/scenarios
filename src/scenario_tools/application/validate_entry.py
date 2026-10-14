"""Validate an entry: each of its files checked as the data model says. A file the readers
refuse is a finding of the entry, not an end of the run, so that one broken file never hides the
findings of the others, nor of the other entries."""

from collections.abc import Callable, Mapping
from typing import Any, cast

from scenario_tools.application.assign_payloads import payload_findings
from scenario_tools.application.findings import not_normalised
from scenario_tools.domain.catalogue.archive import payloads_outside_contracts
from scenario_tools.domain.catalogue.characters import hidden_character_findings, text_findings
from scenario_tools.domain.catalogue.entry import (
    duplicate_findings,
    layout_findings,
    name_findings,
    truncation_findings,
    version_findings,
)
from scenario_tools.domain.catalogue.facts import BuiltinContracts, copy_findings, export_facts
from scenario_tools.domain.catalogue.intake import name_key
from scenario_tools.domain.catalogue.metadata import ExportFacts, ScenarioMetadata, cross_check
from scenario_tools.domain.catalogue.normalisation import ExportStructureError
from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rule import EntryContent, PolicyData
from scenario_tools.domain.shared.characters import hidden_occurrences
from scenario_tools.domain.shared.finding import Finding, Severity, reportable
from scenario_tools.domain.verification.payload_references import AgreedIds
from scenario_tools.ports.errors import UnsafeInputError
from scenario_tools.ports.repository import EntrySource
from scenario_tools.ports.schema import SchemaValidator

_TEXTS = ("README.md", "CHANGELOG.md")  # written by a person or a tool, checked as written


def _refused(error: UnsafeInputError | ExportStructureError, path: str) -> Finding:
    if isinstance(error, UnsafeInputError):
        return Finding(error.code, Severity.BLOCKING, error.path, "", error.message)
    return Finding(error.code, Severity.BLOCKING, path, "", str(error))


def _metadata_findings(
    document: object,
    path: str,
    entry: str,
    schema: SchemaValidator,
    builtin: BuiltinContracts,
    others: Mapping[str, tuple[str, ...]],
    written: frozenset[str],
    names: Mapping[str, tuple[str, ...]],
) -> tuple[tuple[Finding, ...], ScenarioMetadata | None]:
    """The findings of ``scenario.yaml``, and its metadata when it meets its schema: the checks
    that read a field run only then."""
    violations = schema.validate("scenario", document)
    findings = hidden_character_findings(
        document, path, written=written, to_do="remove it from the file"
    ) + tuple(
        Finding("SCH-001", Severity.BLOCKING, path, violation.pointer, violation.message)
        for violation in violations
    )
    if violations or not isinstance(document, dict):
        return findings, None
    metadata = ScenarioMetadata.from_document(document)
    elsewhere = {
        external_id: tuple(directory for directory in directories if directory != entry)
        for external_id, directories in others.items()
    }
    findings += truncation_findings(document["description"], path)
    findings += version_findings(document["requires"]["openaev"], builtin.platform_version, path)
    findings += duplicate_findings(metadata.external_id, path, elsewhere)
    key = name_key(metadata.name)  # its own directory left out, one lookup whatever the size
    named = {key: tuple(other for other in names.get(key, ()) if other != entry)}
    findings += name_findings(metadata.name, path, named)
    return findings, metadata


def _scenario_findings(
    stored: bytes,
    document: object,
    path: str,
    builtin: BuiltinContracts,
    renormalised: Callable[[], bytes] | None,
) -> tuple[tuple[Finding, ...], ExportFacts | None]:
    """The findings of the stored ``scenario.json``, and its facts when it is shaped like a
    normalised export; ``renormalised`` gives what normalisation writes for it, when the
    entry's external ID is known."""
    findings = hidden_character_findings(document, path)
    try:
        facts, unknown = export_facts(document, builtin, path)
        findings += unknown + copy_findings(document, builtin, path)
    except ExportStructureError as error:
        return (*findings, _refused(error, path)), None
    try:  # a refusal here leaves the facts established: the cross-checks still run
        if renormalised is not None and renormalised() != stored:
            findings += (not_normalised(path),)
    except (ExportStructureError, UnsafeInputError) as error:
        findings += (_refused(error, path),)
    return findings, facts


def validate_entry(
    entry: str,
    source: EntrySource,
    *,
    schema: SchemaValidator,
    builtin: BuiltinContracts,
    renormalised: Callable[[object, str, str], bytes],
    domains: tuple[str, ...],
    policy: PolicyData,
    agreed: AgreedIds,
) -> tuple[Finding, ...]:
    """The findings of the entry at ``entry``, a directory relative to the repository.
    ``renormalised`` gives what normalisation writes for a stored scenario, given the entry's
    external ID and the scenario's path; ``policy`` holds the data the policy rules read, and
    ``agreed`` the payload IDs the registry agrees."""
    if not reportable(entry):  # none of its files could be named in a finding: none is read
        return layout_findings(entry, (), domains)
    try:
        names = source.names(entry)
    except UnsafeInputError as error:
        return (_refused(error, entry),)
    findings = layout_findings(entry, names, domains)
    metadata: ScenarioMetadata | None = None
    facts: ExportFacts | None = None
    declared_checked: Mapping[str, Any] | None = None  # once it meets its schema, for the policy
    stored_document: object = None  # the stored scenario.json once read, for the policy
    if "scenario.yaml" in names:
        path = f"{entry}/scenario.yaml"
        try:
            # As written, comments included, and as read, escapes of quoted texts included; a
            # character written as it is, found in both, is reported once, for the file.
            written = source.read_text(path)
            findings += text_findings(written, path, breaks=True)
            labels = frozenset(hidden.label for hidden in hidden_occurrences(written))
            declared = source.read_yaml(path)
            found, metadata = _metadata_findings(
                declared,
                path,
                entry,
                schema,
                builtin,
                source.external_ids(),
                labels,
                source.scenario_names(),
            )
            findings += found
            if metadata is not None:  # it met its schema, so it is an object
                declared_checked = cast(Mapping[str, Any], declared)
        except UnsafeInputError as error:
            findings += (_refused(error, path),)
    if "scenario.json" in names:
        path = f"{entry}/scenario.json"
        try:
            stored, document = source.read_json(path)
            stored_document = document
            external_id = metadata.external_id if metadata is not None else None
            again = (
                (lambda: renormalised(document, external_id, path))
                if external_id is not None
                else None
            )
            found, facts = _scenario_findings(stored, document, path, builtin, again)
            findings += found + payloads_outside_contracts(document, path)
        except UnsafeInputError as error:
            findings += (_refused(error, path),)
    if metadata is not None and facts is not None:
        findings += cross_check(metadata, facts, f"{entry}/scenario.yaml")
    if declared_checked is not None and stored_document is not None:
        findings += payload_findings(declared_checked, stored_document, entry, agreed)
    for name in _TEXTS:
        if name in names:
            path = f"{entry}/{name}"
            try:
                findings += text_findings(source.read_text(path), path)
            except UnsafeInputError as error:
                findings += (_refused(error, path),)
    content = EntryContent(entry, names, declared_checked, stored_document)
    return findings + policy_findings(policy, content)
