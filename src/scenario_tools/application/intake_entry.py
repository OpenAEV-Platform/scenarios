"""Intake an export into the catalogue: everything that would refuse the request is found before
anything is written, so that a refused request leaves the repository as it was."""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.catalogue.intake import (
    NEW,
    IntakeRequest,
    domain_refusals,
    intake_plan,
    intake_refusals,
    same_name,
)
from scenario_tools.domain.catalogue.structure import INFORMATION
from scenario_tools.domain.shared.canonical import ContentHash
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.repository import EntrySource
from scenario_tools.ports.schema import SchemaValidator


@dataclass(frozen=True)
class IntakeResult:
    """What intake makes of a request: the findings that refuse it, or what to write (the stored
    ``scenario.json``, and for a new entry its ``scenario.yaml``), whether it changes anything,
    and what is left to complete."""

    request: IntakeRequest | None
    refusals: tuple[Finding, ...] = ()
    scenario_json: bytes | None = None
    metadata: dict[str, Any] | None = None
    to_complete: tuple[Finding, ...] = ()
    changed: bool = False


def _scenario_name(export: Any) -> str:
    """The export's scenario name, empty when it has none; normalisation refuses it then."""
    information = export.get(INFORMATION) if isinstance(export, Mapping) else None
    name = information.get("scenario_name") if isinstance(information, Mapping) else None
    return name if isinstance(name, str) else ""


def _refused(code: str, path: str, pointer: str, message: str) -> Finding:
    return Finding(code, Severity.BLOCKING, path, pointer, message)


def intake_entry(
    export: Any,
    request_document: object,
    *,
    request_path: str,
    export_path: str,
    source: EntrySource,
    data: DataLoader,
    schema: SchemaValidator,
    domains: tuple[str, ...],
) -> IntakeResult:
    """What intake makes of ``export`` and the request read from ``request_path``, against the
    catalogue ``source`` reads."""
    violations = schema.validate("intake-request", request_document)
    if violations or not isinstance(request_document, Mapping):
        return IntakeResult(
            None,
            tuple(
                _refused("SCH-001", request_path, violation.pointer, violation.message)
                for violation in violations
            ),
        )
    request = IntakeRequest.from_document(request_document)
    # What the request writes is checked as the export is, before anything is written.
    refusals = hidden_character_findings(request_document, request_path)
    refusals = (
        refusals
        or domain_refusals(request, domains, request_path)
        or intake_refusals(
            request,
            _scenario_name(export),
            source.entries(),
            request_path=request_path,
            export_path=export_path,
            place_taken=request.mode == NEW and source.exists(request.entry),
        )
    )
    if refusals:
        return IntakeResult(request, refusals)
    if request.mode == NEW:
        return _new(request, export, export_path, request_path, data, schema)
    return _update(request, export, export_path, data, source)


def intake_files(
    result: IntakeResult, render: Callable[[dict[str, Any]], bytes]
) -> dict[str, bytes]:
    """The files intake writes in the entry, by name, in the order they are written: its
    ``scenario.yaml`` first for a new entry, as ``render`` writes it, then its ``scenario.json``;
    none when the request is refused or changes nothing."""
    if result.refusals or not result.changed or result.scenario_json is None:
        return {}
    files = {} if result.metadata is None else {"scenario.yaml": render(result.metadata)}
    files["scenario.json"] = result.scenario_json
    return files


def plan_document(
    result: IntakeResult, files: Mapping[str, bytes], base: str, findings: Iterable[Finding]
) -> dict[str, Any]:
    """The plan of the pull request: the files written with their digests, from the commit
    ``base``, and what is left, from intake and from the checks of the entry written."""
    if result.request is None:
        raise ValueError("a refused request has no plan")
    entry = result.request.entry
    digests = {f"{entry}/{name}": ContentHash.of_bytes(data).hex for name, data in files.items()}
    return intake_plan(
        result.request,
        base=base,
        changed=result.changed,
        files=digests,
        checklist=(*result.to_complete, *findings),
    )


def _new(
    request: IntakeRequest,
    export: Any,
    export_path: str,
    request_path: str,
    data: DataLoader,
    schema: SchemaValidator,
) -> IntakeResult:
    metadata_path = f"{request.entry}/scenario.yaml"
    prepared = prepare_entry(
        export, request.external_id, data, path=export_path, start_at=metadata_path
    )
    if prepared.refusals:
        return IntakeResult(request, prepared.refusals)
    given = request.metadata()
    metadata = {**(prepared.metadata or {}), **given}  # a first preparation always starts one
    violations = schema.validate("scenario", metadata)
    if violations:
        why = "the scenario.yaml the request completes breaks its schema: nothing is written"
        return IntakeResult(
            request,
            (
                _refused("ITK-007", request_path, "", why),
                *(
                    _refused("SCH-001", metadata_path, violation.pointer, violation.message)
                    for violation in violations
                ),
            ),
        )
    left = tuple(
        finding for finding in prepared.to_complete if finding.field.strip("/") not in given
    )
    return IntakeResult(request, (), prepared.scenario_json, metadata, left, changed=True)


def _update(
    request: IntakeRequest,
    export: Any,
    export_path: str,
    data: DataLoader,
    source: EntrySource,
) -> IntakeResult:
    stored_path = f"{request.entry}/scenario.json"
    stored, previous = source.read_json(stored_path)
    prepared = prepare_entry(
        export,
        request.external_id,
        data,
        path=export_path,
        previous=previous,
        previous_path=stored_path,
    )
    if prepared.refusals:
        return IntakeResult(request, prepared.refusals)
    changed = prepared.scenario_json != stored
    metadata_path = f"{request.entry}/scenario.yaml"
    left: tuple[Finding, ...] = ()
    if changed:
        left += (
            Finding(
                "SCH-007",
                Severity.INFO,
                metadata_path,
                "/version",
                "raise the version for this change and add its section to CHANGELOG.md",
            ),
        )
    entry = next(entry for entry in source.entries() if entry.path == request.entry)
    if not same_name(entry.name, _scenario_name(export)):  # renamed, as rewrite declares
        left += (
            Finding(
                "SCH-007",
                Severity.INFO,
                metadata_path,
                "/name",
                "the scenario was renamed: align name, category and main focus with the export",
            ),
        )
    left += tuple(
        Finding(
            "VER-012",
            Severity.INFO,
            stored_path,
            "",
            f"inject {inject} of the previous version is no longer in the export",
        )
        for inject in prepared.removed_injects
    )
    return IntakeResult(request, (), prepared.scenario_json, None, left, changed)
