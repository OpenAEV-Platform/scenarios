"""Intake an export into the catalogue: everything that would refuse the request is found before
anything is written, so that a refused request leaves the repository as it was."""

import contextlib
import datetime
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from scenario_tools.application.assign_payloads import agreed_ids, assigned_entry
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.application.render_sheet import SHEET, policy_exceptions
from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.catalogue.entry import SLUG_LIMIT, is_slug
from scenario_tools.domain.catalogue.intake import (
    FACETS,
    NEW,
    IntakeRequest,
    completed_facets,
    domain_refusals,
    intake_plan,
    intake_refusals,
    same_name,
)
from scenario_tools.domain.catalogue.payload_verdict import verdicts
from scenario_tools.domain.catalogue.structure import INFORMATION
from scenario_tools.domain.shared.canonical import ContentHash, stored_form
from scenario_tools.domain.shared.finding import Finding, Severity
from scenario_tools.domain.sheet.sheet import SHEET_LIMIT, render_sheet
from scenario_tools.domain.verification.payload_catalogue import Catalogue
from scenario_tools.domain.verification.payload_references import HeldVersions, PayloadReference
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.errors import EnvironmentProblemError
from scenario_tools.ports.plan import PlanSink
from scenario_tools.ports.repository import EntrySource, EntryWriter
from scenario_tools.ports.schema import SchemaValidator


@dataclass(frozen=True)
class IntakeResult:
    """What intake makes of a request: the findings that refuse it, or what to write (the stored
    ``scenario.json``, and its ``scenario.yaml`` for a new entry, or for an update whose payload
    references change), whether it changes anything, what is left to complete, and the bytes of
    each file an update replaces, as read: none for a new entry, which replaces nothing."""

    request: IntakeRequest | None
    refusals: tuple[Finding, ...] = ()
    scenario_json: bytes | None = None
    metadata: dict[str, Any] | None = None
    to_complete: tuple[Finding, ...] = ()
    changed: bool = False
    previous: dict[str, bytes] | None = None
    changelog: bytes | None = None  # a new entry's starting CHANGELOG.md
    sheet: bytes | None = None  # a new entry's README.md
    payload_files: dict[str, bytes] = field(default_factory=dict)  # new versions, by their path


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
    today: datetime.date,
    payloads: Catalogue,
) -> IntakeResult:
    """What intake makes of ``export`` and the request read from ``request_path``, against the
    catalogue ``source`` reads and the payload catalogue ``payloads``; a new entry's changelog
    starts on ``today``."""
    # What the request writes is checked as the export is, before anything else: a hidden
    # character is said as such, whatever the schema would say of the field that holds it.
    hidden = hidden_character_findings(request_document, request_path)
    if hidden:
        return IntakeResult(None, hidden)
    violations = schema.validate("intake-request", request_document)
    if violations:
        return IntakeResult(
            None,
            tuple(
                _refused("SCH-001", request_path, violation.pointer, violation.message)
                for violation in violations
            ),
        )
    if not isinstance(request_document, Mapping):  # whatever the schema lets through
        why = "the request must be a mapping of its fields"
        return IntakeResult(None, (_refused("SCH-001", request_path, "", why),))
    if not isinstance(request_document.get("issue"), int):  # 12.0 is an integer to the schema
        why = "the issue must be a whole number, as #12 is"
        return IntakeResult(None, (_refused("SCH-001", request_path, "/issue", why),))
    for key in ("domain", "slug"):  # a place in the catalogue, whatever its schema lets through
        if not is_slug(request_document.get(key)):
            why = f"must be kebab-case of at most {SLUG_LIMIT} characters, never a path"
            return IntakeResult(None, (_refused("SCH-001", request_path, f"/{key}", why),))
    for key in ("category", "main_focus"):  # a facet as the platform shows it: one clean line
        value = request_document.get(key)
        if isinstance(value, str) and (value != value.strip() or len(value.splitlines()) > 1):
            why = "must be one line, with no blank at either end"
            return IntakeResult(None, (_refused("SCH-001", request_path, f"/{key}", why),))
    request = IntakeRequest.from_document(request_document)
    refusals: tuple[Finding, ...] = ()
    name = _scenario_name(export)
    if not name.strip():
        why = "the export's scenario has no name: name it on the platform, and export it again"
        refusals = (_refused("SCH-001", export_path, "/scenario_information/scenario_name", why),)
    refusals = (
        refusals
        or domain_refusals(request, domains, request_path)
        or intake_refusals(
            request,
            name,
            source.entries(),
            request_path=request_path,
            export_path=export_path,
            place_taken=request.mode == NEW and source.exists(request.entry),
        )
    )
    if refusals:
        return IntakeResult(request, refusals)
    if request.mode == NEW:
        return _new(request, export, export_path, request_path, data, schema, today, payloads)
    return _update(request, export, name, export_path, data, source, schema, payloads)


@dataclass(frozen=True)
class _Payloads:
    """The verdicts on the payloads of an entry: the refusals (a new payload's name taken), the
    information, the versions held once the new ones are written, and their files by path."""

    refusals: tuple[Finding, ...]
    told: tuple[Finding, ...]
    held: HeldVersions
    files: dict[str, bytes]


def _payloads(
    scenario_json: bytes, entry: str, payloads: Catalogue, data: DataLoader, schema: SchemaValidator
) -> _Payloads:
    found, new = verdicts(
        json.loads(scenario_json),
        payloads,
        agreed_ids(data),
        accepted=lambda document: not schema.validate("payload", document),
        scenario=f"{entry}/scenario.json",
    )
    refusals = tuple(f for f in found if f.severity is Severity.BLOCKING)
    held = [*payloads.held().by_id.values()]
    held += [PayloadReference(v.identifier, v.version, digest) for digest, v in new.items()]
    return _Payloads(
        refusals,
        tuple(f for f in found if f.severity is Severity.INFO),
        HeldVersions.of(held),
        {version.path: stored_form(version.document) for version in new.values()},
    )


def intake_files(
    result: IntakeResult, render: Callable[[dict[str, Any]], bytes]
) -> dict[str, bytes]:
    """The files intake writes in the entry, by name, in the order they are written: its
    ``scenario.yaml`` first when there is one to write, as ``render`` writes it, then its
    ``scenario.json``; none when the request is refused or changes nothing."""
    if result.refusals or not result.changed or result.scenario_json is None:
        return {}
    files = {} if result.metadata is None else {"scenario.yaml": render(result.metadata)}
    if result.changelog is not None:
        files["CHANGELOG.md"] = result.changelog
    if result.sheet is not None:
        files[SHEET] = result.sheet
    files["scenario.json"] = result.scenario_json
    return files


def plan_document(
    result: IntakeResult, files: Mapping[str, bytes], base: str, findings: Iterable[Finding]
) -> dict[str, Any]:
    """The plan of the pull request: the files written with their digests, from the commit
    ``base``, and what is left, from intake and from the checks of the entry written."""
    if result.request is None or result.refusals:
        raise ValueError("a refused request has no plan")
    entry = result.request.entry
    digests = {f"{entry}/{name}": ContentHash.of_bytes(data).hex for name, data in files.items()}
    digests.update(
        {path: ContentHash.of_bytes(data).hex for path, data in result.payload_files.items()}
    )
    return intake_plan(
        result.request,
        base=base,
        changed=result.changed,
        files=digests,
        checklist=(*result.to_complete, *findings),
    )


def write_intake(
    result: IntakeResult,
    *,
    entries: EntryWriter,
    plan: PlanSink,
    base: str,
    current: Callable[[], str],
    validate: Callable[[str], tuple[Finding, ...]],
    render: Callable[[dict[str, Any]], bytes],
) -> tuple[Finding, ...]:
    """Write the entry ``result`` says and its plan, from the commit ``base``, in one go: the
    plan's place is reserved first, then the entry is written and checked as ``validate``
    checks it, and the plan is published only once the checkout's commit, as ``current`` reads
    it once sure its path still names the checkout held, is still ``base``, then, last, the
    entry is known to be still where and as it was written. The entry is
    kept only with its plan: if anything stops the run before, what was written is taken back
    and the place given back. What is left to complete and the entry's findings are given. The
    caller holds the repository from the catalogue's check that made ``result`` until this
    returns."""
    if result.request is None or result.refusals:
        raise ValueError("a refused request is never written")
    entry = result.request.entry
    with plan.reserving() as reservation, contextlib.ExitStack() as stack:
        files = intake_files(result, render)
        # The new payload versions first, each in a folder of its own: the entry's check reads
        # them, and they are taken back with it if anything stops the run.
        versions = []
        for path, data in sorted(result.payload_files.items()):
            folder, name = path.rsplit("/", 1)
            versions.append(
                stack.enter_context(entries.writing(folder, {name: data}, previous=None))
            )
        written = stack.enter_context(entries.writing(entry, files, previous=result.previous))
        findings = validate(entry)
        document = plan_document(result, files, base, findings)
        if current() != base:  # the plan must describe what its base gives
            raise EnvironmentProblemError(
                "the checkout's commit changed while the run wrote: nothing is kept"
            )
        for checked in (*versions, written):  # last: what the checkout's check leaves out
            checked.check()
        reservation.publish(json.dumps(document, indent=2).encode() + b"\n")
    return (*result.to_complete, *findings)


def _new(
    request: IntakeRequest,
    export: Any,
    export_path: str,
    request_path: str,
    data: DataLoader,
    schema: SchemaValidator,
    today: datetime.date,
    payloads: Catalogue,
) -> IntakeResult:
    metadata_path = f"{request.entry}/scenario.yaml"
    export, missing = completed_facets(export, request.facets, {}, export_path)
    if missing:
        return IntakeResult(request, missing)
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
    scenario_json = prepared.scenario_json
    verdict = _payloads(scenario_json, request.entry, payloads, data, schema)
    if verdict.refusals:
        return IntakeResult(request, verdict.refusals)
    left += verdict.told
    assigned = assigned_entry(
        metadata, json.loads(scenario_json), request.entry, agreed_ids(data), verdict.held
    )
    if assigned.metadata is not None and assigned.stored is not None:
        metadata, scenario_json = assigned.metadata, stored_form(assigned.stored)
    # Otherwise the entry's check, run once it is written, says why in the plan.
    changelog = (
        f"# Changelog\n\n## {metadata['version']} \u2014 {today.isoformat()}\n\n"
        "First version in the catalogue.\n"
    ).encode()
    left += (
        Finding(
            "SCH-007",
            Severity.INFO,
            f"{request.entry}/CHANGELOG.md",
            "",
            "a starting section for this version: say what it holds before the pull request",
        ),
    )
    rendered = render_sheet(metadata, json.loads(scenario_json), policy_exceptions(data)).encode()
    # A sheet over what a README.md may hold is not written: the entry's check says so.
    sheet = rendered if len(rendered) <= SHEET_LIMIT else None
    return IntakeResult(
        request,
        (),
        scenario_json,
        metadata,
        left,
        changed=True,
        changelog=changelog,
        sheet=sheet,
        payload_files=verdict.files,
    )


def _update(
    request: IntakeRequest,
    export: Any,
    name: str,
    export_path: str,
    data: DataLoader,
    source: EntrySource,
    schema: SchemaValidator,
    payloads: Catalogue,
) -> IntakeResult:
    stored_path = f"{request.entry}/scenario.json"
    if "scenario.json" not in source.names(request.entry):
        return IntakeResult(
            request,
            (_refused("SCH-008", stored_path, "", "the entry has no scenario.json to update"),),
        )
    stored, previous = source.read_json(stored_path)
    held = previous.get("scenario_information") if isinstance(previous, dict) else None
    export, missing = completed_facets(
        export, request.facets, held if isinstance(held, dict) else {}, export_path
    )
    if missing:
        return IntakeResult(request, missing)
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
    metadata_path = f"{request.entry}/scenario.yaml"
    scenario_json = prepared.scenario_json
    metadata: dict[str, Any] | None = None
    previous_files = {"scenario.json": stored}
    # Without scenario.yaml, the entry's check says it is missing. The text first: if the file
    # changes before its document is read, the writer, which checks the text it replaces, refuses
    # to write over the newer file.
    declared: object = None
    if "scenario.yaml" in source.names(request.entry):
        written = source.read_text(metadata_path)
        declared = source.read_yaml(metadata_path)
    verdict = _payloads(scenario_json, request.entry, payloads, data, schema)
    if verdict.refusals:
        return IntakeResult(request, verdict.refusals)
    assigned = assigned_entry(
        declared, json.loads(scenario_json), request.entry, agreed_ids(data), verdict.held
    )
    if assigned.metadata is not None and assigned.stored is not None:
        scenario_json = stored_form(assigned.stored)
        # A facet the request gives is the stored scenario's now: scenario.yaml takes it too.
        information = assigned.stored.get(INFORMATION) or {}  # as normalised, then stored
        given = {name: information.get(FACETS[name]) for name in request.facets}
        wanted = {**assigned.metadata, **given}
        if wanted != declared:  # its references or its facets change: scenario.yaml too
            metadata = wanted
            previous_files["scenario.yaml"] = written.encode()
    # Otherwise the entry's check, run once it is written, says why in the plan.
    changed = scenario_json != stored or metadata is not None or bool(verdict.files)
    left: tuple[Finding, ...] = verdict.told
    if changed:
        left += (
            Finding(
                "SCH-007",
                Severity.INFO,
                metadata_path,
                "/version",
                "raise the version for this change and add its section to CHANGELOG.md",
            ),
            Finding(
                "SCH-007",
                Severity.INFO,
                f"{request.entry}/{SHEET}",
                "",
                "the sheet follows scenario.yaml: once it is complete, render it again with "
                "`scenario-tools render`",
            ),
        )
    entry = next(entry for entry in source.entries() if entry.path == request.entry)
    if not same_name(entry.name, name):  # renamed, as rewrite declares
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
            f"{kind} {identifier} of the previous version is no longer in the export",
        )
        for kind, identifiers in (
            ("inject", prepared.removed_injects),
            ("step", prepared.removed_steps),
        )
        for identifier in identifiers
    )
    return IntakeResult(
        request,
        (),
        scenario_json,
        metadata,
        left,
        changed,
        previous_files,
        payload_files=verdict.files,
    )
