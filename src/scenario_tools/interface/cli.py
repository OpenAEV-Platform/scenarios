"""Command-line entry point: ``scenario-tools``.

Every command returns a report through ``execute``, which renders it as text or as the JSON
document of the contract and gives the exit code: 0 when the report is ok, 1 with a blocking
finding, 2 on a usage error (click), 3 when the environment cannot be used, and 4 when the tool
itself fails, so that a defect of the tool never reads as a defect of the content.
"""

import contextlib
import dataclasses
import datetime
import json
import os
import re
import signal
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import NoReturn

import click

from scenario_tools import __version__
from scenario_tools.adapters.catalogue_files import CatalogueDirectory
from scenario_tools.adapters.data_files import (
    DOCUMENTS_NOT_SUPPORTED,
    DocumentsNotSupportedError,
    YamlDataLoader,
    check_export_archive,
    read_attachments,
    read_export,
    read_export_archive,
    read_mapping,
    read_stored_scenario,
    scenario_from_archive,
    write_output,
)
from scenario_tools.adapters.entry_writer import RepositoryWriter
from scenario_tools.adapters.fixture_zip import HandmadeArchives
from scenario_tools.adapters.git import (
    changed_entries,
    commit_time,
    converted,
    converting,
    head_commit,
    last_commit,
    uncommitted,
)
from scenario_tools.adapters.github_api import HttpGitHub
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.openaev_http import HttpOpenAEV, usable_token
from scenario_tools.adapters.plan import PlanFile
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import (
    YAML_LIMIT,
    parse_json,
    parse_yaml,
    read_json_file,
    read_regular_file,
    read_yaml_file,
    yaml_bytes,
)
from scenario_tools.adapters.safe_zip import ARCHIVE_LIMIT
from scenario_tools.adapters.zip_archive import ZipArchiveBuilder
from scenario_tools.application.assign_payloads import (
    agreed_ids,
    assigned_entry,
    catalogue_of,
    payload_findings,
)
from scenario_tools.application.build_archive import build_archive
from scenario_tools.application.build_fixtures import EXPECTED, fixture_files, release_fixtures
from scenario_tools.application.build_release import (
    ArchivedEntry,
    EntryResult,
    build_release,
    entry_for_release,
)
from scenario_tools.application.check_title import check_title as check_title_use_case
from scenario_tools.application.collect_approvals import collect_approvals
from scenario_tools.application.diff_entry import diff_entry
from scenario_tools.application.findings import finding_from_unsafe_input, repository_path
from scenario_tools.application.fixture_expectations import (
    Expectation,
    expectations_from_document,
)
from scenario_tools.application.intake_entry import (
    intake_check,
    intake_entry,
    intake_files,
    write_intake,
)
from scenario_tools.application.prepare_entry import prepare_entry, renormaliser
from scenario_tools.application.render_sheet import SHEET, check_sheet, policy_exceptions, sheet_of
from scenario_tools.application.run_fixtures import run_fixtures
from scenario_tools.application.transfer import export_scenario, import_archive
from scenario_tools.application.validate_entry import validate_entry
from scenario_tools.application.validate_payloads import checked_payloads, validate_payloads
from scenario_tools.application.verify_release import verify_release
from scenario_tools.domain.catalogue.archive import payloads_outside_contracts
from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.catalogue.entry import domains_from_document
from scenario_tools.domain.catalogue.facts import BuiltinContracts, copy_findings, export_facts
from scenario_tools.domain.catalogue.metadata import (
    communication_injectors_from_document,
    is_tabletop,
)
from scenario_tools.domain.policy.actions import forbidden_from_document, side_effects_from_document
from scenario_tools.domain.policy.exceptions import exceptions_from_document
from scenario_tools.domain.policy.rule import PolicyData
from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.policy.vendors import vendors_from_document
from scenario_tools.domain.release.manifest import (
    CHANNELS,
    REPOSITORY,
    PayloadFile,
    PreviousRelease,
    approvals_document,
    approvals_from_document,
    archive_name,
    merged_before_review_from_document,
    previous_release,
)
from scenario_tools.domain.shared.canonical import jcs, stored_form
from scenario_tools.domain.shared.finding import (
    COUNT_CODE,
    ERROR_LIMIT,
    MESSAGE_LIMIT,
    Finding,
    Report,
    Severity,
    shorten,
)
from scenario_tools.domain.shared.workflow import ExportKeys
from scenario_tools.domain.verification.payload_catalogue import Catalogue, TreeEntry
from scenario_tools.domain.verification.payload_references import (
    AgreedIds,
    HeldVersions,
    PayloadReference,
)
from scenario_tools.domain.verification.payload_version import VERSION_FILE_LIMIT
from scenario_tools.domain.verification.release_output import payload_reference_findings
from scenario_tools.ports.catalogue import CatalogueFiles
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

EXIT_OK, EXIT_BLOCKING, EXIT_ENVIRONMENT, EXIT_INTERNAL = 0, 1, 3, 4


def _printable(text: str) -> str:
    """Escape every non-printable character (control, line break, undecodable byte) as Python
    writes it in a string literal, so contributor content can neither break a line nor be read
    as a CI workflow command."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def _line(finding: Finding) -> str:
    where = " ".join(part for part in (finding.path, finding.field) if part)
    location = f" {where}" if where else ""
    return _printable(f"{finding.severity.name} {finding.code}{location}: {finding.message}")


def _text(report: Report) -> str:
    lines = [_line(finding) for finding in report.findings]
    if report.ok:
        return "\n".join([*lines, f"{report.command}: ok"])
    blocking = sum(finding.severity is Severity.BLOCKING for finding in report.findings)
    plural = "" if blocking == 1 else "s"
    return "\n".join([*lines, f"{report.command}: {blocking} blocking finding{plural}"])


def execute(
    command: str,
    produce: Callable[[], Report],
    output_format: str,
    root: Path | None = None,
    hidden: str = "",
) -> tuple[str, int]:
    """Run ``produce`` and return what to print and the exit code. Paths in findings are made
    relative to ``root``, the repository root, which is the working directory by default. A
    failure anywhere, while producing or while rendering, exits with 4, never with 1. Nothing
    printed shows ``hidden``, however the output writes what the findings hold."""
    try:
        return _run(command, produce, output_format, root, hidden)
    except Exception as error:  # noqa: BLE001 - the last guard: a defect never exits with 1

        def render(text: str) -> str:
            return shorten(_printable(f"{command}: internal error: {text}"))

        message = f"{type(error).__name__}: {_describe(error)}"
        return _concealed(message, render, hidden), EXIT_INTERNAL


def _describe(error: Exception) -> str:
    """The text of an error, even one whose own text cannot be built."""
    try:
        return str(error)
    except Exception:  # noqa: BLE001 - the guard itself must not fail
        return "<unprintable>"


_WITHHELD = "withheld: it would show a secret"


def _cut_in(text: str, hidden: str) -> bool:
    """Whether ``text`` was cut short in the middle of ``hidden``: it then ends with the start
    of it, before the ellipsis, as it is or as JSON writes it."""
    for ellipsis in ("…", "\\u2026"):
        if text.endswith(ellipsis):
            shown = text[: -len(ellipsis)]
            # No start longer than the text can end it: the work stays bounded by the text.
            longest = min(len(hidden), len(shown))
            return any(shown.endswith(hidden[:length]) for length in range(1, longest + 1))
    return False


def _cut_in_any_form(text: str, hidden: str) -> bool:
    """Whether ``text``, as the text or the JSON output writes it, was cut short in the middle
    of ``hidden``: an escape can write the start of the token."""
    forms = (_printable(text), json.dumps(text)[1:-1])
    return any(_cut_in(form, hidden) for form in forms)


def _concealed(
    message: str, render: Callable[[str], str], hidden: str, limit: int = MESSAGE_LIMIT
) -> str:
    """``message`` as ``render`` writes it, or withheld when that would show ``hidden``, or the
    start of it where the message is cut short to ``limit``. The token's characters are never
    escaped, so the token shows as it is or not at all."""
    output = render(message)
    if hidden and (
        hidden in output
        or _cut_in(output, hidden)
        or _cut_in_any_form(shorten(message, limit), hidden)
    ):
        return render(_WITHHELD)
    return output


def _render(report: Report, output_format: str) -> str:
    return json.dumps(report.document()) if output_format == "json" else _text(report)


def _shows(output: str, report: Report, hidden: str) -> bool:
    """Whether ``hidden`` shows in the output, or its start in a message, a path or a field cut
    short. The token's characters are never escaped, so the token shows as it is or not at all."""
    return hidden in output or any(
        _cut_in_any_form(text, hidden)
        for finding in report.findings
        for text in (finding.message, finding.path, finding.field)
    )


def _withhold(report: Report, output_format: str, hidden: str) -> str:
    """The output, with the messages, then the paths and fields, of the findings withheld while
    it would show ``hidden``: what then remains is the tool's own text, never the platform's.
    The finding that counts those a report does not show is the tool's own text, and stays."""
    output = _render(report, output_format)
    for paths_too in (False, True):
        if not hidden or not _shows(output, report, hidden):
            break

        def withheld(f: Finding, paths_too: bool = paths_too) -> Finding:
            if f.code == COUNT_CODE:
                return f
            if paths_too:
                return dataclasses.replace(f, message=_WITHHELD, path="", field="")
            return dataclasses.replace(f, message=_WITHHELD)

        report = report.with_findings(withheld)
        output = _render(report, output_format)
    return output


def _run(
    command: str,
    produce: Callable[[], Report],
    output_format: str,
    root: Path | None,
    hidden: str = "",
) -> tuple[str, int]:
    try:
        report = produce()
    except UnsafeInputError as error:
        report = Report(command, (finding_from_unsafe_input(error, root or Path.cwd()),))
    except EnvironmentProblemError as error:

        def render(text: str) -> str:
            if output_format == "json":
                error = shorten(text, ERROR_LIMIT)
                return json.dumps({"command": command, "ok": False, "findings": [], "error": error})
            return shorten(_printable(f"{command}: environment error: {text}"), ERROR_LIMIT)

        return _concealed(str(error), render, hidden, ERROR_LIMIT), EXIT_ENVIRONMENT
    code = EXIT_OK if report.ok else EXIT_BLOCKING
    return _withhold(report, output_format, hidden), code


def _emit(
    ctx: click.Context,
    command: str,
    produce: Callable[[], Report],
    root: Path | None = None,
    hidden: str = "",
) -> NoReturn:
    output, code = execute(command, produce, ctx.obj["format"], root, hidden)
    click.echo(output, err=code == EXIT_INTERNAL)  # an internal error writes nothing to stdout
    ctx.exit(code)


@click.group(name="scenario-tools")
@click.version_option(__version__, prog_name="scenario-tools")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Human-readable text, or one JSON document on stdout.",
)
@click.pass_context
def main(ctx: click.Context, output_format: str) -> None:
    """Prepare, check, release and verify OpenAEV scenarios."""
    ctx.obj = {"format": output_format}


@main.command(name="check-title")
@click.argument("title")
@click.pass_context
def check_title(ctx: click.Context, title: str) -> None:
    """Check a pull request TITLE against the shared convention."""
    _emit(ctx, "check-title", lambda: check_title_use_case(title))


@main.command(name="changed-entries")
@click.argument("checkout", type=click.Path(path_type=Path, file_okay=False))
@click.option(
    "--base", required=True, help="The full ID of the commit the checkout is compared with."
)
@click.pass_context
def changed_entries_command(ctx: click.Context, checkout: Path, base: str) -> None:
    """List the entries the pull request checked out at CHECKOUT adds or changes since its merge
    base with BASE, each followed by a NUL byte, for a workflow to read whatever their names."""
    try:
        entries = changed_entries(checkout, base)
    except EnvironmentProblemError as error:
        text = shorten(_printable(f"changed-entries: environment error: {error}"), ERROR_LIMIT)
        click.echo(text, err=True)
        ctx.exit(EXIT_ENVIRONMENT)
    click.echo("".join(f"{entry}\0" for entry in entries), nl=False)


_CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _entry_external_id(out: Path, given: str | None) -> str:
    """The external ID of the entry: from its ``scenario.yaml`` when it exists, otherwise given
    on the command line. Anything else is a usage error, raised before anything is written."""
    declared = None
    metadata = out / "scenario.yaml"
    if metadata.exists() or metadata.is_symlink():
        declared = _declared_external_id(metadata)
    if given is not None and declared is not None and given != declared:
        raise click.UsageError(f"--external-id contradicts {metadata}: {shorten(repr(declared))}")
    if given is None and declared is not None:
        if not isinstance(declared, str) or not _CANONICAL_UUID.fullmatch(declared):
            raise click.UsageError(
                f"the external_id of {metadata} is not a UUID in lower case with hyphens: "
                f"{shorten(repr(declared))}"
            )
        return declared
    if given is None or not _CANONICAL_UUID.fullmatch(given):
        raise click.UsageError(
            "give --external-id, a UUID in lower case with hyphens, for a first preparation"
        )
    return given


def _policy_levels(out: Path) -> list[Path]:
    """OUT and those of its parents that hold policy data, from the deepest up."""
    resolved = Path(os.path.realpath(out))  # a loop of links is left as it is, not raised
    try:
        return [
            directory
            for directory in (resolved, *resolved.parents)
            if (directory / "policy" / "data").is_dir()
        ]
    except OSError as error:  # a directory that cannot be searched, for instance
        raise EnvironmentProblemError(
            f"cannot look for policy data above {out}: {error.strerror}"
        ) from error


def _repository_root(levels: list[Path], out: Path) -> Path:
    """The repository that holds the entry, wherever the command runs from: the only directory
    among OUT and its parents with policy data. A second one would let an entry bring its own
    rules, so it is refused."""
    if not levels:
        raise EnvironmentProblemError(
            f"no policy/data directory in {out} or above: not a repository"
        )
    if len(levels) > 1:
        raise UnsafeInputError(
            "IO-015",
            "policy data below the repository root: an entry may not carry its own rules",
            str(levels[0] / "policy" / "data"),
        )
    return levels[0]


def _refused(error: Exception) -> Callable[[], Report]:
    def produce() -> Report:
        raise error

    return produce


@main.command(name="normalize")
@click.argument("export", type=click.Path(path_type=Path, dir_okay=False))
@click.option("--out", required=True, type=click.Path(path_type=Path, file_okay=False, exists=True))
@click.option("--external-id", help="The entry's external ID, for a first preparation.")
@click.option("--previous", type=click.Path(path_type=Path, file_okay=False, exists=True))
@click.option("--map", "mapping_file", type=click.Path(path_type=Path, dir_okay=False))
@click.pass_context
def normalize(
    ctx: click.Context,
    export: Path,
    out: Path,
    external_id: str | None,
    previous: Path | None,
    mapping_file: Path | None,
) -> None:
    """Write the normalised form of EXPORT, an archive or a JSON file, to OUT/scenario.json."""
    # Absolute paths, so that findings are reported from the repository root.
    export, out = export.absolute(), out.absolute()
    levels: list[Path] = []
    metadata = out / "scenario.yaml"
    try:
        levels = _policy_levels(out)
        root = _repository_root(levels, out)
        # Decided once, before the external ID is chosen: a scenario.yaml that appears later
        # is never read nor replaced, and the run stops before writing anything.
        first = not (metadata.exists() or metadata.is_symlink())
        entry_id = _entry_external_id(out, external_id)
    except click.UsageError:
        raise
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, "normalize", _refused(error), levels[-1] if levels else None)
    previous_file = previous.absolute() / "scenario.json" if previous else None
    mapping_file = mapping_file.absolute() if mapping_file else None

    def produce() -> Report:
        loader = YamlDataLoader(root / "policy" / "data")
        prepared = prepare_entry(
            read_export(export),
            entry_id,
            loader,
            path=repository_path(str(export), root),
            previous=read_json_file(previous_file) if previous_file else None,
            previous_path=str(previous_file) if previous_file else None,
            mapping=read_mapping(mapping_file) if mapping_file else None,
            mapping_path=str(mapping_file) if mapping_file else None,
            start_at=repository_path(str(metadata.resolve()), root) if first else None,
        )
        if prepared.refusals:
            return Report("normalize", prepared.refusals)
        if prepared.metadata is not None:  # a first preparation: never written again
            write_output(metadata, yaml_bytes(prepared.metadata), create=True)
        target = out / "scenario.json"
        write_output(target, prepared.scenario_json)
        where = repository_path(str(target.resolve()), root)
        findings = tuple(
            Finding(
                "VER-012",
                Severity.INFO,
                where,
                "",
                f"{kind} {identifier} of the previous version is no longer in the export",
            )
            for kind, identifiers in (
                ("inject", prepared.removed_injects),
                ("step", prepared.removed_steps),
            )
            for identifier in identifiers
        )
        return Report("normalize", findings + prepared.to_complete)

    _emit(ctx, "normalize", produce, root)


def _entry_archive(
    entry: Path, root: Path, loader: YamlDataLoader, catalogue: HeldVersions, out: str | None
) -> ArchivedEntry:
    """What the archive's checks find of the entry at ``entry``, of the repository at
    ``root`` whose payload catalogue holds ``catalogue``, its import archive when they let it be
    built, meant for ``out`` or, without it, named as a release names it, and what they read."""
    scenario, metadata = entry / "scenario.json", entry / "scenario.yaml"
    declared = read_yaml_file(metadata)
    external_id = declared.get("external_id") if isinstance(declared, dict) else None
    if not isinstance(external_id, str) or not _CANONICAL_UUID.fullmatch(external_id):
        message = "external_id must be a UUID in lower case with hyphens"
        where = repository_path(str(metadata), root)
        refused = Finding("SCH-001", Severity.BLOCKING, where, "/external_id", message)
        return ArchivedEntry((refused,), None, {}, None)
    try:
        builtin = BuiltinContracts.from_document(loader.load("builtin-contracts"))
        policy = _policy_data(loader)
        condition_types = ExportKeys.from_document(loader.load("export-keys")).condition_types
    except ValueError as error:
        raise EnvironmentProblemError(f"policy data cannot be used: {error}") from error
    path = repository_path(str(scenario), root)
    data, document = read_stored_scenario(scenario)
    named = out if out is not None else archive_name(external_id, str(declared.get("version")))
    report, built = build_archive(
        document,
        data,
        read_attachments(entry / "attachments.zip"),
        path,
        named,
        ZipArchiveBuilder(),
        # Normalised again with itself as the previous version, unless it is another
        # entry's: then what normalisation writes for this one differs anyway.
        renormalised=lambda stored: renormaliser(loader)(stored, external_id, path),
        contract_findings=lambda stored: (
            export_facts(stored, builtin, path)[1]
            + copy_findings(stored, builtin, path)
            + hidden_character_findings(stored, path)
        ),
        check=lambda built: check_export_archive(built, named),
        limit=ARCHIVE_LIMIT,
        policy=policy,
        declared=declared,
        agreed=agreed_ids(loader),
        catalogue=catalogue,
        condition_types=condition_types,
    )
    return ArchivedEntry(report.findings, built, declared, document)


@main.command(name="archive")
@click.argument("entry", type=click.Path(path_type=Path))
@click.option("--out", required=True, type=click.Path(path_type=Path))
@click.pass_context
def archive(ctx: click.Context, entry: Path, out: Path) -> None:
    """Write the import archive of ENTRY to OUT: its scenario.json and attachments.zip as they
    are, in the layout the platform's importer reads, once the entry passes its checks."""
    entry = Path(os.path.realpath(entry))  # its place in the repository, whatever link names it
    out = Path(os.path.normpath(out.absolute()))
    if _inside(out, entry):
        raise click.UsageError("OUT may not be inside the entry")
    if out.is_dir():
        raise click.UsageError("OUT is a directory: give the path of the archive file")
    levels: list[Path] = []
    try:
        levels = _policy_levels(entry)
        root = _repository_root(levels, entry)
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, "archive", _refused(error), levels[-1] if levels else None)

    def produce() -> Report:
        loader = YamlDataLoader(root / "policy" / "data")
        catalogue = _catalogue(RepositoryEntries(root))
        archived = _entry_archive(entry, root, loader, catalogue, str(out))
        if archived.archive is not None:
            write_output(out, archived.archive)
        return Report("archive", archived.findings)

    _emit(ctx, "archive", produce, root)


def _previous(path: Path, schema: JsonSchemaValidator) -> PreviousRelease:
    """The previous release of a channel, from its manifest at ``path``, once it meets the
    manifest's schema: what it says is compared, never trusted unread."""
    document = read_json_file(path)
    violations = schema.validate("manifest", document)
    if violations:
        raise EnvironmentProblemError(
            "the previous release's manifest does not meet its schema, at "
            + ", ".join(violation.pointer or "/" for violation in violations[:5])
        )
    try:
        return previous_release(document)
    except ValueError as error:
        raise EnvironmentProblemError(str(error)) from error


def _output(out: Path, root: Path, *, directory: bool) -> Path:
    """``out`` as a release command writes it: outside the repository at ``root``, in a
    directory that exists, where nothing is, or an empty ``directory``; a usage error
    otherwise."""
    out = Path(os.path.normpath(out.absolute()))
    if _inside(out, root):
        raise click.UsageError("--out may not be inside the repository")
    return _free_place(out, directory=directory)


def _free_place(out: Path, *, directory: bool) -> Path:
    """``out``, absolute, in a directory that exists, where nothing is, or an empty
    ``directory`` that is no link; a usage error otherwise."""
    out = Path(os.path.normpath(out.absolute()))
    if not out.parent.is_dir():
        raise click.UsageError("--out must be in a directory that exists")
    empty = directory and not out.is_symlink() and out.is_dir() and not any(out.iterdir())
    if os.path.lexists(out) and not empty:
        kind = "a new or empty directory" if directory else "a new file"
        raise click.UsageError(f"--out names a place that is taken: give {kind}")
    return out


@main.command(name="approvals")
@click.option("--repo", "repo", required=True, type=click.Path(path_type=Path, file_okay=False))
@click.option("--out", required=True, type=click.Path(path_type=Path, dir_okay=False))
@click.pass_context
def approvals_command(ctx: click.Context, repo: Path, out: Path) -> None:
    """Write to --out, a new file outside the repository, who approved the last change of every
    entry of the checkout at --repo, as build reads it: the pull request merged into the
    default branch as the last commit that changed the entry, and those who approved what it
    merged, asked of GitHub with the token in GITHUB_TOKEN."""
    root = Path(os.path.realpath(repo))
    out = _output(out, root, directory=False)

    def produce() -> Report:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            raise EnvironmentProblemError("GITHUB_TOKEN is not set: GitHub cannot be asked")
        running = os.environ.get("GITHUB_REPOSITORY") or REPOSITORY
        if running != REPOSITORY:  # a release names this repository: never another's history
            raise EnvironmentProblemError(
                f"the release is of {REPOSITORY}, not of {running}: approvals are read there only"
            )
        github = HttpGitHub(token, REPOSITORY)
        source = RepositoryEntries(root, strict=True)
        commit = head_commit(root)
        found = collect_approvals(
            source.places(),
            commit=commit,
            repository=REPOSITORY,
            last_commit=lambda entry: last_commit(root, entry, at=commit),
            pulls_of=github.pulls_of,
            reviews_of=github.reviews_of,
        )
        document = approvals_document(found)
        try:
            approvals_from_document(document)  # what build reads, or nothing
        except ValueError as error:
            raise EnvironmentProblemError(str(error)) from error
        write_output(out, jcs(document), create=True)
        return Report("approvals")

    _emit(ctx, "approvals", produce, root)


@main.command(name="build")
@click.option("--repo", "repo", required=True, type=click.Path(path_type=Path, file_okay=False))
@click.option(
    "--previous-release",
    "previous",
    required=True,
    help="The channel's previous manifest; none for its first release (./none for a file).",
)
@click.option("--channel", required=True, type=click.Choice(CHANNELS))
@click.option("--approvals", required=True, type=click.Path(path_type=Path, dir_okay=False))
@click.option("--out", required=True, type=click.Path(path_type=Path))
@click.pass_context
def build(
    ctx: click.Context, repo: Path, previous: str, channel: str, approvals: Path, out: Path
) -> None:
    """Build the release of the catalogue of the checkout at --repo on --channel: every
    entry's archive and the manifest, written to --out, a new or empty directory outside the
    repository, once every entry passes its checks and has its approvals. --previous-release is
    the channel's previous manifest, or none for its first release."""
    root = Path(os.path.realpath(repo))
    out = _output(out, root, directory=True)
    earlier = None if previous == "none" else Path(previous)
    for given, place in (("--approvals", approvals), ("--previous-release", earlier)):
        if place is not None and _inside(place, root):
            raise click.UsageError(f"{given} may not be inside the repository")

    def produce() -> Report:
        source = RepositoryEntries(root, strict=True)  # what a cut run left is never ignored
        with source.locked():  # no intake writes in the catalogue while it is read
            base = head_commit(root)
            _refuse_uncommitted(root, release=True)
            if head_commit(root) != base:
                raise EnvironmentProblemError(
                    "the checkout's commit changed while it was checked: run again"
                )
            source.check_held()  # git found the checkout by its path: still the one held
            moment = commit_time(root, base)
            # The catalogue is read once, by its own checks: their findings are the release's,
            # and the entries are checked against the versions they let through.
            rules = _rules(source, catalogue=HeldVersions.of([]))
            found, versions = _release_payloads(root, rules)
            if any(finding.severity is Severity.BLOCKING for finding in found):
                return Report("build", found)
            held = [PayloadReference(v.openaev_id, v.version, v.sha256) for v in versions]
            rules = dataclasses.replace(rules, catalogue=HeldVersions.of(held))
            try:
                granted = approvals_from_document(read_json_file(approvals))
                if granted.commit != base:
                    raise ValueError(
                        f"approvals: collected at {granted.commit}, not at the commit built, "
                        f"{base}: collect them again"
                    )
                loaded = rules.loader.load("merged-before-review")
                before = merged_before_review_from_document(loaded)
                tabletop = rules.loader.load("tabletop-injectors")
                communication = communication_injectors_from_document(tabletop)
            except ValueError as error:
                raise EnvironmentProblemError(str(error)) from error
            released = None if earlier is None else _previous(earlier, rules.schema)

            def tabletop_of(document: object, entry: str) -> bool:
                facts = export_facts(document, rules.builtin, f"{entry}/scenario.json")[0]
                return is_tabletop(facts, communication)

            def validated(entry: str) -> tuple[Finding, ...]:
                return rules.validate(entry, source)

            def archived(entry: str) -> ArchivedEntry:
                return _entry_archive(root / entry, root, rules.loader, rules.catalogue, None)

            def build_entry(entry: str) -> EntryResult:
                return entry_for_release(
                    entry, validate=validated, archive=archived, tabletop=tabletop_of
                )

            report, release = build_release(
                source.places(),
                build_entry,
                approvals=granted.entries,
                before_review=before,
                previous=released,
                channel=channel,
                moment=moment,
                payloads=versions,
                catalogue=found,
            )
            if release is None:
                return report
            built = json.loads(release.manifest)
            violations = rules.schema.validate("manifest", built)
            if violations:  # a defect of the tools: the release goes nowhere
                raise EnvironmentProblemError(
                    "the manifest built does not meet its schema, at "
                    + ", ".join(violation.pointer or "/" for violation in violations[:5])
                )
            unlisted = payload_reference_findings(built["items"], built["payloads"])
            if unlisted:  # validate and the catalogue's checks read one payloads/: a defect
                raise EnvironmentProblemError(
                    "the manifest built lists a payload reference no listed version has, at "
                    + ", ".join(finding.field for finding in unlisted[:5])
                )
            _refuse_uncommitted(root, release=True)  # nothing changed while it was built
            if head_commit(root) != base:
                raise EnvironmentProblemError(
                    "the checkout's commit changed while the release was built: run again"
                )
            source.check_held()
            out.mkdir(exist_ok=True)
            for name, data in sorted({**release.archives, **release.payload_files}.items()):
                write_output(out / name, data, create=True)
            write_output(out / "manifest.json", release.manifest, create=True)  # last
            return report

    _emit(ctx, "build", produce, root)


def _release_payloads(
    root: Path, rules: "_Rules"
) -> tuple[tuple[Finding, ...], tuple[PayloadFile, ...]]:
    """What the checks of the payload catalogue find of the repository at ``root``, as
    ``validate-payloads`` checks it, and each of its versions, with the bytes of its file; none
    while a finding blocks, or when the repository holds no ``payloads/``."""
    if not (root / "payloads").is_dir():
        return (), ()
    if not (root / "schemas" / "payload.schema.json").is_file():
        raise EnvironmentProblemError("schemas cannot be used: payload.schema.json is missing")
    found, checked = checked_payloads(
        CatalogueDirectory(root, ("payloads",)), rules.schema, rules.agreed, "payloads"
    )
    if any(finding.severity is Severity.BLOCKING for finding in found):
        return found, ()
    # Each version is hashable: one that is not is a blocking finding of its checks, above.
    versions = tuple(
        PayloadFile(version.slug, version.version, version.digest(), version.identifier, data)
        for version, data in checked
    )
    return found, versions


def _payload_document(data: bytes) -> object:
    """A payload file of a release as JSON, read as the repository reads its own files;
    ``ValueError`` with why when it cannot be."""
    try:
        return parse_json(data, limit=VERSION_FILE_LIMIT)
    except UnsafeInputError as error:
        raise ValueError(f"{error.code}: {error.message}") from error


def _verified(manifest: Path, schemas: Path, held: Path, *, approved: bool) -> Report:
    """The report of verify on the release whose manifest is ``manifest`` and whose archives
    are in ``held``, with the manifest's schema in ``schemas``."""
    if schemas.is_symlink() or not (schemas / "manifest.schema.json").is_file():
        raise EnvironmentProblemError(
            f"schemas cannot be used: {schemas} holds no manifest.schema.json"
        )
    try:
        validator = JsonSchemaValidator(schemas)
        beside = frozenset(path.name for path in held.iterdir())
        if held.resolve() == manifest.parent.resolve():  # the manifest is not one to list
            beside -= {manifest.name}
    except (OSError, ValueError) as error:
        raise EnvironmentProblemError(f"cannot read the release: {error}") from error
    document = read_json_file(manifest)

    def archive_of(name: str) -> bytes | None:
        place = held / name  # the name meets the manifest's schema: a plain file name
        return read_regular_file(place, ARCHIVE_LIMIT) if os.path.lexists(place) else None

    def payload_of(name: str) -> bytes | None:
        place = held / name  # the name meets the manifest's schema: a plain file name
        return read_regular_file(place, VERSION_FILE_LIMIT) if os.path.lexists(place) else None

    return verify_release(
        document,
        validate=lambda found: tuple(
            (violation.pointer, violation.message)
            for violation in validator.validate("manifest", found)
        ),
        approved=approved,
        archive_of=archive_of,
        scenario_of=scenario_from_archive,
        present=beside,
        payload_of=payload_of,
        read_payload=_payload_document,
    )


@main.command(name="verify")
@click.argument("manifest", type=click.Path(path_type=Path, dir_okay=False))
@click.option(
    "--schemas",
    required=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="The repository's schemas directory, which holds manifest.schema.json.",
)
@click.option("--archives", type=click.Path(path_type=Path, file_okay=False), default=None)
@click.option("--approved", is_flag=True, help="The release is approved: it names its approver.")
@click.pass_context
def verify(
    ctx: click.Context, manifest: Path, schemas: Path, archives: Path | None, approved: bool
) -> None:
    """Verify the release whose manifest is MANIFEST as its consumers will: the manifest meets
    its schema, each archive in --archives (the manifest's directory by default) is the one it
    lists, safe to extract, holds a scenario with only the parts of a stored scenario, and embeds
    the payloads it lists with their canonical hashes; and nothing stands beside them, but the
    manifest verified, that the manifest does not list. A manifest refused, or listing a payload
    ID with two versions or hashes, is refused alone: no archive is read."""
    held = archives if archives is not None else manifest.parent

    def produce() -> Report:
        return _verified(manifest, schemas, held, approved=approved)

    _emit(ctx, "verify", produce, None)


@main.group(name="conformance")
def conformance() -> None:
    """Build the release fixtures, and run the verifier on them."""


@conformance.command(name="build")
@click.option("--out", required=True, type=click.Path(path_type=Path))
@click.pass_context
def conformance_build(ctx: click.Context, out: Path) -> None:
    """Write the release fixtures to --out, a new or empty directory: a release verify
    accepts, and one for each way it refuses one, each in its directory, with expected.json
    beside them. They need no secret, and are the same bytes on every build."""
    out = _free_place(out, directory=True)

    def produce() -> Report:
        files = fixture_files(release_fixtures(ZipArchiveBuilder(), HandmadeArchives()))
        out.mkdir(exist_ok=True)
        for path, data in sorted(files.items()):
            target = out / path
            target.parent.mkdir(exist_ok=True)
            write_output(target, data, create=True)
        return Report("conformance")

    _emit(ctx, "conformance", produce, None)


@conformance.command(name="run")
@click.argument("fixtures", type=click.Path(path_type=Path, file_okay=False, exists=True))
@click.option(
    "--schemas",
    required=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="The repository's schemas directory, which holds manifest.schema.json.",
)
@click.pass_context
def conformance_run(ctx: click.Context, fixtures: Path, schemas: Path) -> None:
    """Run verify on every release fixture in FIXTURES, and compare what it gives with what
    FIXTURES/expected.json says: the findings of each, by code, path and field, and the IO code
    of an archive refused as unsafe."""

    def produce() -> Report:
        expected = fixtures / EXPECTED
        try:
            expectations = expectations_from_document(read_json_file(expected))
        except ValueError as error:
            raise UnsafeInputError("IO-014", str(error), str(expected)) from error
        try:
            present = frozenset(path.name for path in fixtures.iterdir()) - {EXPECTED}
        except OSError as error:
            raise EnvironmentProblemError(f"cannot read the fixtures: {error}") from error

        def outcome_of(expectation: Expectation) -> Report:
            case = fixtures / expectation.name  # a plain name, as expected.json requires
            try:
                if case.is_symlink() or not case.is_dir():
                    message = "a fixture is a directory, never a link or a file"
                    raise UnsafeInputError("IO-013", message, str(case))
                return _verified(
                    case / "manifest.json", schemas, case, approved=expectation.approved
                )
            except UnsafeInputError as error:
                return Report("verify", (finding_from_unsafe_input(error, fixtures),))

        return run_fixtures(expectations, present=present, outcome_of=outcome_of)

    _emit(ctx, "conformance", produce, None)


@main.command(name="payloads")
@click.argument("entry", type=click.Path(path_type=Path, file_okay=False, exists=True))
@click.option(
    "--assign",
    is_flag=True,
    help="Give each payload its ID, in scenario.json and in the references of scenario.yaml.",
)
@click.pass_context
def payloads(ctx: click.Context, entry: Path, assign: bool) -> None:
    """Check that each payload ENTRY's scenario embeds carries the ID its content has, the one
    derived from its hash or the one policy/data/payload-ids.yaml agrees for it, and that a
    reference of its scenario.yaml gives that ID with the payload's hash. With --assign, give
    each payload that ID and write the references; scenario.yaml is written again in the tools'
    layout, so a comment in it is not kept."""
    entry = Path(os.path.realpath(entry))
    metadata, scenario = entry / "scenario.yaml", entry / "scenario.json"
    levels: list[Path] = []
    try:
        levels = _policy_levels(entry)
        root = _repository_root(levels, entry)
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, "payloads", _refused(error), levels[-1] if levels else None)

    def produce() -> Report:
        agreed = agreed_ids(YamlDataLoader(root / "policy" / "data"))
        catalogue = _catalogue(RepositoryEntries(root))
        where = repository_path(str(entry), root)
        # Its bytes and its document from one read: the bytes are what --assign replaces.
        written = read_regular_file(metadata, YAML_LIMIT)
        declared = parse_yaml(written, path=str(metadata))
        data, stored = read_stored_scenario(scenario)
        # A payload outside an inject's contract is never named: nothing is given then.
        outside = payloads_outside_contracts(stored, f"{where}/scenario.json")
        if not assign or outside:
            return Report(
                "payloads", outside + payload_findings(declared, stored, where, agreed, catalogue)
            )
        result = assigned_entry(declared, stored, where, agreed, catalogue)
        if result.metadata is None or result.stored is None:
            return Report("payloads", result.refusals)
        previous = {"scenario.yaml": written, "scenario.json": data}
        files = {
            "scenario.yaml": yaml_bytes(result.metadata),
            "scenario.json": stored_form(result.stored),
        }
        # Both files go together, each replaced only if it still holds what was read, so that a
        # change to either meanwhile is refused; nothing to change writes nothing. The check after
        # the block makes sure a later run reads what was written.
        changed = files if files != previous else {}
        with RepositoryWriter(RepositoryEntries(root)).writing(
            where, changed, previous=previous
        ) as replaced:
            replaced.check()
        # The assignment gives every payload its reference: the check of what was given says so.
        return Report(
            "payloads", payload_findings(result.metadata, result.stored, where, agreed, catalogue)
        )

    _emit(ctx, "payloads", produce, root)


def _one_repository(
    ctx: click.Context, command: str, entries: tuple[Path, ...]
) -> tuple[Path, list[str]]:
    """The repository that holds every one of ``entries``, and each entry relative to it; an
    entry no repository holds is refused input, and entries of two repositories a usage error."""
    # Not resolved: a link on the way is refused when the entry is read, never followed.
    directories = [Path(os.path.normpath(entry.absolute())) for entry in entries]
    levels: list[Path] = []
    roots: dict[tuple[int, int], Path] = {}  # each repository once, however it is reached
    relatives: list[str] = []
    try:
        for directory in directories:
            levels = _levels_as_given(directory)
            root = _repository_root(levels, directory)
            roots.setdefault(_identity(root), root)
            relatives.append(directory.relative_to(root).as_posix())
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, command, _refused(error), levels[-1] if levels else None)
    if len(roots) > 1:
        raise click.UsageError("the entries belong to different repositories")
    [root] = roots.values()
    return root, relatives


@main.command(name="validate")
@click.argument("entries", nargs=-1, required=True, type=click.Path(path_type=Path))
@click.option(
    "--previous-root",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    help="The root of a checkout of the base branch: each entry is compared with its copy there.",
)
@click.pass_context
def validate(ctx: click.Context, entries: tuple[Path, ...], previous_root: Path | None) -> None:
    """Check each of ENTRIES, an entry directory, against the schemas and the rules of an entry
    of the repository that holds them; exit with 1 if anything blocks one of them.

    Of the policy rules, POL-001 (sources linked to public pages, nothing copied into an entry),
    POL-002 (no recurrence), POL-003 (only allowed hosts), POL-004 (no forbidden action),
    POL-005 (a cleanup for every payload that changes the endpoint), POL-006 (no security
    product named), POL-007 (elevated privileges, for the reviewer), POL-009 (injects spaced
    out) and POL-010 (no internal data) run, with the payload references and the CHANGELOG.md
    sections; a finding policy/data/exceptions.yaml excepts is information, and an exception
    that covers none blocks (POL-011). With --previous-root, each entry is compared with its
    previous version, the copy the base branch holds: its version must be raised as the change
    needs, its inject IDs stay, and a new payload is pointed out (POL-008); an entry the base
    branch does not hold is new.
    The sheet, README.md, must be the one render writes (GEN-001). The check of the private
    deny-list is not run yet: an entry that passes may still fail it.

    No symbolic link inside the repository is followed; the path that leads to the repository
    may go through one."""
    root, relatives = _one_repository(ctx, "validate", entries)
    if previous_root is None:  # what the pull request compares, a local run would not
        click.echo(
            "validate: without --previous-root, each entry is checked as a new one: its version "
            "is not compared with the base branch's",
            err=True,
        )

    def produce() -> Report:
        source = RepositoryEntries(root)
        rules = _rules(source)
        previous = RepositoryEntries(previous_root.absolute()) if previous_root else None
        findings: list[Finding] = []
        for entry in dict.fromkeys(relatives):  # an entry given twice is checked once
            findings += rules.validate(entry, source, previous)
        return Report("validate", tuple(findings))

    _emit(ctx, "validate", produce, root)


class _EmptyCatalogue:
    """The catalogue of a base branch that holds no ``payloads/``."""

    def entries(self) -> tuple[TreeEntry, ...]:
        return ()

    def read(self, path: tuple[str, ...]) -> tuple[bytes, object]:
        raise EnvironmentProblemError(f"an empty catalogue holds no {'/'.join(path)}")


@main.command(name="validate-payloads")
@click.argument("directory", type=click.Path(path_type=Path, file_okay=False, exists=True))
@click.option(
    "--previous-root",
    "previous_root",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    default=None,
    help="The root of a checkout of the base branch: a version its payloads/ holds must stay "
    "as it is.",
)
@click.pass_context
def validate_payloads_command(
    ctx: click.Context, directory: Path, previous_root: Path | None
) -> None:
    """Check DIRECTORY, the payload catalogue of a repository (its payloads/ or a copy): one
    folder per payload, named by its slug, one file per version, named by its version, and nothing
    else; each file against schemas/payload.schema.json, in the stored form, its name carrying
    its version, its ID the one its content has (PAY-003); and no slug, base name, ID or hash
    used twice (PAY-009). Exit with 1 if anything blocks.

    The policy data and the schemas are the repository's, above DIRECTORY. No symbolic link is
    followed, and git is not read. No policy rule runs on the version files yet."""
    # Not resolved: a link inside the repository is refused when the catalogue is read.
    directory = Path(os.path.normpath(directory.absolute()))
    levels: list[Path] = []
    try:
        levels = _levels_as_given(directory.parent)
        root = _repository_root(levels, directory.parent)
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, "validate-payloads", _refused(error), levels[-1] if levels else None)

    def produce() -> Report:
        source = RepositoryEntries(root)  # the rules, read like an entry's, never through a link
        try:
            agreed = agreed_ids(YamlDataLoader(source.directory("policy/data")))
            schemas = source.directory("schemas")
        except UnsafeInputError as error:
            raise EnvironmentProblemError(f"policy data cannot be used: {error}") from error
        if not (schemas / "payload.schema.json").is_file():
            raise EnvironmentProblemError("schemas cannot be used: payload.schema.json is missing")
        try:
            schema = JsonSchemaValidator(schemas)
        except (OSError, ValueError, UnsafeInputError) as error:
            raise EnvironmentProblemError(f"schemas cannot be used: {error}") from error
        parts = directory.relative_to(root).parts
        catalogue = CatalogueDirectory(root, parts)
        base: CatalogueFiles | None = None
        if previous_root is not None:  # its payloads/, wherever DIRECTORY is
            held = Path(os.path.normpath(previous_root.absolute()))
            folder = held / "payloads"
            if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
                raise EnvironmentProblemError("the base checkout's payloads is no directory")
            base = CatalogueDirectory(held, ("payloads",)) if folder.is_dir() else _EmptyCatalogue()
        return validate_payloads(catalogue, schema, agreed, "/".join(parts), base)

    _emit(ctx, "validate-payloads", produce, root)


@main.command(name="render")
@click.argument("entries", nargs=-1, required=True, type=click.Path(path_type=Path))
@click.option(
    "--check", is_flag=True, help="Write nothing: report a README.md that is not the sheet."
)
@click.pass_context
def render(ctx: click.Context, entries: tuple[Path, ...], check: bool) -> None:
    """Write the sheet of each of ENTRIES, an entry directory: its README.md, rendered from
    scenario.yaml and scenario.json, with the policy exceptions the maintainers granted it. With
    --check, write nothing and report GEN-001 for a README.md missing or not the sheet. The
    contributor's texts are plain text in it, never Markdown, a link or an image.

    No symbolic link inside the repository is followed, nor written through; the path that
    leads to the repository may go through one."""
    root, relatives = _one_repository(ctx, "render", entries)

    def produce() -> Report:
        source = RepositoryEntries(root)
        exceptions = policy_exceptions(YamlDataLoader(source.directory("policy/data")))
        findings: list[Finding] = []
        for entry in dict.fromkeys(relatives):  # an entry given twice is rendered once
            if check:
                findings += check_sheet(entry, source, exceptions)
                continue
            sheet = sheet_of(entry, source, exceptions)
            findings += sheet.refusals
            if sheet.text is not None:
                write_output(root / entry / SHEET, sheet.text.encode())
        return Report("render", tuple(findings))

    _emit(ctx, "render", produce, root)


@main.command(name="diff")
@click.argument("entries", nargs=-1, required=True, type=click.Path(path_type=Path))
@click.option(
    "--previous-root",
    required=True,
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    help="The root of a checkout of the base branch: each entry is compared with its copy there.",
)
@click.pass_context
def diff(ctx: click.Context, entries: tuple[Path, ...], previous_root: Path) -> None:
    """Show what changed in each of ENTRIES, an entry directory, since its copy in the checkout
    of the base branch at --previous-root, found by its external ID when it moved, as validate
    classifies them: first the least version the changes need and whether the entry's is enough
    (VER-014), then each change, where it is, the inject or item it concerns and the version it
    needs (VER-013), the 30 that need the most. Never a value of the entry. Exit with 0 whatever
    changed: validate judges the version.

    No symbolic link inside the repository is followed; the path that leads to the repository
    may go through one."""
    root, relatives = _one_repository(ctx, "diff", entries)

    def produce() -> Report:
        source = RepositoryEntries(root)
        previous = RepositoryEntries(previous_root.absolute())
        findings: list[Finding] = []
        for entry in dict.fromkeys(relatives):  # an entry given twice is shown once
            findings += diff_entry(entry, source, previous)
        return Report("diff", tuple(findings))

    _emit(ctx, "diff", produce, root)


@dataclasses.dataclass(frozen=True)
class _Rules:
    """The maintainers' rules the checks of an entry read."""

    loader: YamlDataLoader
    builtin: BuiltinContracts
    domains: tuple[str, ...]
    schema: JsonSchemaValidator
    policy: PolicyData
    agreed: AgreedIds
    catalogue: HeldVersions

    def validate(
        self, entry: str, source: RepositoryEntries, previous: RepositoryEntries | None = None
    ) -> tuple[Finding, ...]:
        return validate_entry(
            entry,
            source,
            schema=self.schema,
            builtin=self.builtin,
            renormalised=renormaliser(self.loader),
            domains=self.domains,
            policy=self.policy,
            agreed=self.agreed,
            catalogue=self.catalogue,
            previous=previous,
        )


def _payload_catalogue(source: RepositoryEntries) -> Catalogue:
    """The index of the repository's payload catalogue: empty when it has no payloads/."""
    if not (source.root / "payloads").is_dir():
        return catalogue_of(None)
    return catalogue_of(CatalogueDirectory(source.root, ("payloads",)))


def _catalogue(source: RepositoryEntries) -> HeldVersions:
    """The payload versions the repository's catalogue holds: none when it has no payloads/."""
    return _payload_catalogue(source).held()


def _policy_data(loader: YamlDataLoader) -> PolicyData:
    """The data the policy rules read: the allowed targets, the forbidden actions, the
    commands that change an endpoint, the vendors' names, and the exceptions the maintainers
    accept."""
    return PolicyData(
        AllowedTargets.from_document(loader.load("allowed-targets")),
        forbidden_from_document(loader.load("forbidden-actions")),
        side_effects_from_document(loader.load("side-effects")),
        vendors_from_document(loader.load("vendor-names")),
        exceptions_from_document(loader.load("exceptions")),
    )


def _rules(
    source: RepositoryEntries, *, intake: bool = False, catalogue: HeldVersions | None = None
) -> _Rules:
    """The rules of the repository ``source`` reads, read like the entries, never through a
    link, the intake request's schema among them for ``intake``; rules that cannot be used are
    the environment's fault, never an entry's. The payload versions held are ``catalogue`` when
    the caller read them already, the repository's otherwise."""
    try:
        loader = YamlDataLoader(source.directory("policy/data"))
        builtin = BuiltinContracts.from_document(loader.load("builtin-contracts"))
        domains = domains_from_document(loader.load("domains"))
        policy = _policy_data(loader)
    except (ValueError, UnsafeInputError, EnvironmentProblemError) as error:
        raise EnvironmentProblemError(f"policy data cannot be used: {error}") from error
    try:
        schemas = source.directory("schemas")
        schema = JsonSchemaValidator(schemas)
    except (OSError, ValueError, UnsafeInputError, EnvironmentProblemError) as error:
        raise EnvironmentProblemError(f"schemas cannot be used: {error}") from error
    for name in ("scenario", "intake-request", "payload") if intake else ("scenario",):
        if not (schemas / f"{name}.schema.json").is_file():
            raise EnvironmentProblemError(f"schemas cannot be used: {name}.schema.json is missing")
    held = _catalogue(source) if catalogue is None else catalogue
    return _Rules(loader, builtin, domains, schema, policy, agreed_ids(loader), held)


REQUEST_LIMIT = 64 * 1024  # bytes of an intake request

# What intake keeps as committed, but for the entry it writes: no plan nor input goes there.
_PLANNED = ("scenarios", "payloads", "policy", "schemas")
_PLANNED_NAMED = ", ".join(f"{path}/" for path in _PLANNED[:-1]) + f" or {_PLANNED[-1]}/"


_DIRECTORY = click.Path(path_type=Path, file_okay=False, exists=True)


@main.command(name="intake")
@click.argument("export", type=click.Path(path_type=Path, dir_okay=False))
@click.option("--request", "request", type=click.Path(path_type=Path))
@click.option("--repo", "repo", type=click.Path(path_type=Path))
@click.option("--plan", "plan", type=click.Path(path_type=Path))
@click.option(
    "--check",
    is_flag=True,
    help="Write nothing: give the verdicts on the export's payloads against --payloads.",
)
@click.option(
    "--payloads",
    "payloads",
    type=_DIRECTORY,
    help="With --check: a checkout's payloads/, or a release's version files laid out as "
    "<slug>/<version>.json.",
)
@click.option(
    "--rules",
    "rules",
    type=_DIRECTORY,
    help="With --check: a directory holding the repository's policy/data/ and schemas/.",
)
@click.option(
    "--claims",
    "claims",
    type=click.Path(path_type=Path, dir_okay=False),
    help="With --check: a YAML document holding a request's payloads list alone.",
)
@click.option(
    "--external-id",
    "external_id",
    help="With --check: the entry's external ID, which normalisation derives identifiers from.",
)
@click.option(
    "--previous",
    "previous",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="With --check, for an update: the entry's stored scenario.json.",
)
@click.pass_context
def intake(
    ctx: click.Context,
    export: Path,
    request: Path | None,
    repo: Path | None,
    plan: Path | None,
    check: bool,
    payloads: Path | None,
    rules: Path | None,
    claims: Path | None,
    external_id: str | None,
    previous: Path | None,
) -> None:
    """Turn EXPORT, a platform export (an archive, or its JSON), and the request at --request
    into an entry of the repository at --repo, written in place, and write at --plan the plan of
    the pull request that proposes it. A refused request writes nothing.

    With --check, write nothing and read no git: give the verdict on each payload EXPORT embeds
    against the catalogue at --payloads, and the findings on the claims at --claims, as intake
    gives them, with the rules at --rules. Exit with 1 if a claim or a payload is refused."""
    checking: dict[str, object] = {
        "--payloads": payloads,
        "--rules": rules,
        "--claims": claims,
        "--external-id": external_id,
        "--previous": previous,
    }
    writing = {"--request": request, "--repo": repo, "--plan": plan}
    if check:
        extra = [name for name, value in writing.items() if value is not None]
        if extra:
            raise click.UsageError(f"--check writes nothing: leave out {', '.join(extra)}")
        if payloads is None or rules is None or external_id is None:
            raise click.UsageError("--check needs --payloads, --rules and --external-id")
        if not _CANONICAL_UUID.fullmatch(external_id):
            raise click.UsageError("--external-id must be a UUID in lower case with hyphens")
        _intake_check(ctx, export, payloads, rules, claims, external_id, previous)
        return
    extra = [name for name, value in checking.items() if value is not None]
    if extra:
        raise click.UsageError(f"only with --check: {', '.join(extra)}")
    if request is None or repo is None or plan is None:
        missing = [name for name, value in writing.items() if value is None]
        raise click.UsageError(f"intake needs {', '.join(missing)}, or --check")
    try:
        root = Path(os.path.realpath(repo))  # resolved once: the run holds what it names
        plan, inputs = plan.absolute(), (export.absolute(), request.absolute())
    except OSError as error:  # a relative path, once the working directory is gone
        _emit(ctx, "intake", _failing(f"cannot resolve the paths given: {error.strerror}"))
    planned = [root / place for place in _PLANNED]  # as committed, or the run stops
    if any(place in (plan, *plan.parents) or _inside(plan, place) for place in planned):
        raise click.UsageError(
            f"--plan may not be inside {_PLANNED_NAMED} of the repository: they stay as committed"
        )
    if os.path.lexists(plan):
        raise click.UsageError(
            "--plan names a place where something is already there: remove the earlier plan "
            "first, so that it is never taken for this run's"
        )
    for given, place in zip((export, request), inputs, strict=True):
        if any(_inside(place, directory) for directory in planned):
            raise click.UsageError(
                f"{given.name} is inside {_PLANNED_NAMED} of the repository: an export or a "
                "request must never enter git"
            )

    def produce() -> Report:
        source = RepositoryEntries(root, strict=True)  # what a cut run left is never ignored
        written = False
        try:
            # From the catalogue's check to the plan, no other run may check or write in it.
            with _stops_as_interruptions(), source.locked():
                base = head_commit(root)  # read before: a request to stop meanwhile stops it
                _refuse_uncommitted(root)
                if head_commit(root) != base:
                    raise EnvironmentProblemError(
                        "the checkout's commit changed while it was checked: run again"
                    )
                source.check_held()  # git found the checkout by its path: still the one held
                rules = _rules(source, intake=True)
                result = intake_entry(
                    read_export(export),
                    read_yaml_file(request, limit=REQUEST_LIMIT),
                    request_path=repository_path(str(request), root),
                    export_path=repository_path(str(export), root),
                    source=source,
                    data=rules.loader,
                    schema=rules.schema,
                    domains=rules.domains,
                    today=datetime.date.today(),
                    payloads=_payload_catalogue(source),
                )
                if result.refusals or result.request is None:
                    return Report("intake", result.refusals)
                entry = result.request.entry
                ours = frozenset(f"{entry}/{name}" for name in intake_files(result, yaml_bytes))
                ours |= frozenset(result.payload_files)
                _refuse_converting(root, ours)  # files not written yet: attributes match them too
                source.check_held()
                with _stop_requests_held():
                    left = write_intake(
                        result,
                        entries=RepositoryWriter(source),
                        plan=PlanFile(plan),
                        base=base,
                        current=lambda: _still_base(source, ours),
                        validate=lambda entry: _validate_written(rules, root, entry),
                        render=yaml_bytes,
                    )
                    written = True  # while requests to stop still wait: never missed
                return Report("intake", left)
        except KeyboardInterrupt as error:  # never read as a refusal
            if written:
                raise EnvironmentProblemError(
                    "the run was asked to stop once its entry and its plan were written: both stand"
                ) from error
            raise EnvironmentProblemError("the run was interrupted: nothing was written") from error

    def produce_shown() -> Report:
        try:
            return produce()
        except EnvironmentProblemError as error:  # said without where the run is
            raise EnvironmentProblemError(_unplaced(str(error), root, plan, inputs)) from error

    _emit(ctx, "intake", produce_shown, root)


def _intake_check(
    ctx: click.Context,
    export: Path,
    payloads: Path,
    rules: Path,
    claims: Path | None,
    external_id: str,
    previous: Path | None,
) -> None:
    """``intake --check``: the verdicts on EXPORT's payloads, writing nothing and reading no git."""
    try:
        root = Path(os.path.realpath(rules))  # resolved once: the run holds what it names
        catalogue = payloads.absolute()  # as given: a ".." after a link is the link's parent
    except OSError as error:  # a relative path, once the working directory is gone
        _emit(ctx, "intake", _failing(f"cannot resolve the paths given: {error.strerror}"))

    def produce() -> Report:
        source = RepositoryEntries(root)  # the rules, read like an entry's, never through a link
        try:
            loader = YamlDataLoader(source.directory("policy/data"))
            schemas = source.directory("schemas")
            schema = JsonSchemaValidator(schemas)
        except (OSError, ValueError, UnsafeInputError) as error:
            raise EnvironmentProblemError(f"the rules cannot be used: {error}") from error
        for name in ("intake-request", "payload"):
            if not (schemas / f"{name}.schema.json").is_file():
                raise EnvironmentProblemError(
                    f"the rules cannot be used: {name}.schema.json is missing"
                )
        found = intake_check(
            _read_as(export, read_export),
            None if claims is None else _read_as(claims, _claims_document),
            export_path=_shown(export),  # by their names: no repository holds them
            claims_path="" if claims is None else _shown(claims),
            data=loader,
            schema=schema,
            payloads=catalogue_of(CatalogueDirectory(catalogue.parent, (catalogue.name,))),
            external_id=external_id,
            previous=None if previous is None else _read_as(previous, _previous_scenario),
            previous_path=None if previous is None else _shown(previous),
        )
        return Report("intake", found)

    _emit(ctx, "intake", produce, None)


def _read_as(path: Path, read: Callable[[Path], object]) -> object:
    """What ``read`` reads from ``path``; a refusal names the file as every finding of the check
    does, by its name."""
    try:
        return read(path)
    except UnsafeInputError as error:
        raise UnsafeInputError(error.code, error.message, _shown(path), error.field) from error


def _shown(path: Path) -> str:
    """How a finding names a file the check reads: its name, as a report path takes it."""
    return repository_path(path.name, Path("/"))


def _previous_scenario(path: Path) -> object:
    """The stored scenario at ``path``: a document of another shape is refused, never read as
    the absence of a previous version."""
    _, document = read_stored_scenario(path)
    if not isinstance(document, Mapping):
        raise UnsafeInputError(
            "IO-014",
            "not a stored scenario: the document must be an object",
            _shown(path),
        )
    return document


def _claims_document(path: Path) -> object:
    """The claims file's document; an empty one is an empty mapping, which its check refuses,
    never the absence of claims."""
    document = read_yaml_file(path, limit=REQUEST_LIMIT)
    return {} if document is None else document


def _validate_written(rules: _Rules, root: Path, entry: str) -> tuple[Finding, ...]:
    """The findings of ``entry`` once intake wrote it, read afresh: the scenarios now hold the
    entry, and the payload catalogue the new versions written with it."""
    written = RepositoryEntries(root)
    return dataclasses.replace(rules, catalogue=_catalogue(written)).validate(entry, written)


def _refuse_uncommitted(root: Path, *, release: bool = False) -> None:
    """Refuse a checkout whose bytes git converts from its commit, or whose catalogue or rules
    differ from it: the plan, or the ``release``, must describe what its commit gives.
    Conversions come first: git status would run a filter the attributes name."""
    made = "the release" if release else "the plan"
    turned = converted(root, _PLANNED)
    if turned:
        more = f" and {len(turned) - 1} more" if len(turned) > 1 else ""
        raise EnvironmentProblemError(
            f"git converts files under {_PLANNED_NAMED} between the commit and the checkout "
            f"({turned[0]}{more}, by its attributes or its line ends): {made} would not "
            "describe the commit's bytes"
        )
    changed = uncommitted(root, _PLANNED)
    if changed and release:
        more = f" and {len(changed) - 1} more" if len(changed) > 1 else ""
        raise EnvironmentProblemError(
            f"the checkout has changes that are not committed under {_PLANNED_NAMED} "
            f"({changed[0]}{more}): build from a clean checkout of the commit, so that the "
            "release describes its commit"
        )
    if changed:
        more = f" and {len(changed) - 1} more" if len(changed) > 1 else ""
        raise EnvironmentProblemError(
            f"the checkout has changes that are not committed under {_PLANNED_NAMED} "
            f"({changed[0]}{more}): commit or remove them first, so that the plan describes "
            "what its base gives; an entry an earlier intake wrote counts: commit it on its "
            "own branch, then start the next intake from the commit it should start from"
        )


def _refuse_converting(root: Path, files: frozenset[str]) -> None:
    """Refuse ``files``, the run's, when git would convert them by their attributes: what the
    plan says of their bytes would not be what a commit of them holds."""
    turned = converting(root, tuple(sorted(files)))
    if turned:
        more = f" and {len(turned) - 1} more" if len(turned) > 1 else ""
        raise EnvironmentProblemError(
            f"git converts {turned[0]}{more} by its attributes: the plan would not describe the "
            "bytes a commit of it holds; nothing is kept"
        )


def _still_base(source: RepositoryEntries, ours: frozenset[str]) -> str:
    """The checkout's commit, once its path still names the checkout held and nothing differs
    from it under the catalogue and its rules but ``ours``, the files the run wrote: the plan
    must describe what its base gives."""
    source.check_held()  # git reads the checkout by its path: never another's
    root = source.root
    _refuse_converting(root, ours)  # attributes changed while the run wrote
    others = [path for path in uncommitted(root, _PLANNED) if path not in ours]
    if others:
        more = f" and {len(others) - 1} more" if len(others) > 1 else ""
        raise EnvironmentProblemError(
            f"the checkout changed while the run wrote ({others[0]}{more}): nothing is kept"
        )
    return head_commit(root)


def _unplaced(text: str, root: Path, plan: Path, inputs: tuple[Path, ...]) -> str:
    """``text`` with the paths of the repository, of the plan's directory and of the inputs
    given relative to them, as findings are: a log never shows where the run is."""
    for given in inputs:
        text = text.replace(str(given), given.name)
    for place in (plan.parent, root):
        text = text.replace(f"{place}/", "")
    return text.replace(str(root), ".").replace(str(plan.parent), plan.parent.name)


def _failing(why: str) -> Callable[[], Report]:
    """What reports the environment error ``why``, as a command's work would."""

    def produce() -> Report:
        raise EnvironmentProblemError(why)

    return produce


# What asks a run to stop: Ctrl-C, a CI job cancelled, a terminal closed, Ctrl-\\.
_STOPS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


def _restorable(handler: object) -> Callable[[int, object], object] | int:
    """A handler as ``signal.signal`` takes it back: one installed from outside Python, which it
    cannot give, is the default."""
    return handler if handler is not None else signal.SIG_DFL  # type: ignore[return-value]


@contextlib.contextmanager
def _stops_as_interruptions() -> Iterator[None]:
    """Each request to stop interrupts the run as Ctrl-C does, so that the run says what it
    leaves, rather than end without a word."""

    def interrupted(signal_number: int, frame: object) -> None:
        raise KeyboardInterrupt

    # One the caller already ignores, as nohup does, stays ignored.
    stops = [stop for stop in _STOPS if signal.getsignal(stop) is not signal.SIG_IGN]
    before = {stop: signal.signal(stop, interrupted) for stop in stops}
    try:
        yield
    finally:
        for stop, handler in before.items():
            signal.signal(stop, _restorable(handler))


@contextlib.contextmanager
def _stop_requests_held() -> Iterator[None]:
    """While a run writes, a request to stop waits, and is then let go: a run never stops half
    way through what it writes, and once it is written, it ends as usual."""
    before = signal.pthread_sigmask(signal.SIG_BLOCK, ())  # as it is, before anything changes
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, _STOPS)
        yield
    finally:
        # Ignored for a moment, a pending request to stop is dropped, then all is as it was.
        handlers = {stop: signal.signal(stop, signal.SIG_IGN) for stop in _STOPS}
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)
        finally:
            for stop, handler in handlers.items():
                signal.signal(stop, _restorable(handler))


def _identity(root: Path) -> tuple[int, int]:
    """Which directory ``root`` is, whatever path reaches it."""
    try:
        status = root.stat()
    except OSError as error:
        raise EnvironmentProblemError(f"cannot read {root}: {error.strerror}") from error
    return status.st_dev, status.st_ino


def _levels_as_given(directory: Path) -> list[Path]:
    """DIRECTORY and those of its parents that hold policy data, from the deepest up, the path
    taken as given: a link on it is refused later, when the entry is read."""
    try:
        return [
            level
            for level in (directory, *directory.parents)
            if (level / "policy" / "data").is_dir()
        ]
    except OSError as error:  # a directory that cannot be searched, for instance
        raise EnvironmentProblemError(
            f"cannot look for policy data above {directory}: {error.strerror}"
        ) from error


def _declared_external_id(metadata: Path) -> object:
    """What ``scenario.yaml`` declares as the external ID, ``None`` when it declares none."""
    document = read_yaml_file(metadata)
    return document.get("external_id") if isinstance(document, dict) else None


def _inside(path: Path, directory: Path) -> bool:
    """Whether ``path`` is ``directory`` or lies within it, compared by file identity on the
    path the write or the read resolves to: a link to the directory or to a folder of it, or
    another case on a case-insensitive disk, still names a place inside it. A place that cannot
    be looked at is not taken to be it: what then reads or writes there fails on its own."""
    try:
        if not directory.is_dir():
            return False
    except OSError:
        return False
    resolved = Path(os.path.realpath(path))
    for candidate in (resolved, *resolved.parents):
        try:
            if candidate.samefile(directory):
                return True
        except OSError:
            continue
    return False


@main.group(name="openaev")
def openaev() -> None:
    """Export a scenario from an OpenAEV platform, or import an archive into one. The platform
    is OPENAEV_URL, and the token OPENAEV_TOKEN, both read from the environment only."""


@openaev.command(name="export")
@click.argument("scenario_id")
# Paths are checked by the command itself, never by the parser: a usage error would repeat
# a path that may hold the token, outside the guard.
@click.option("--out", required=True, type=click.Path(path_type=Path))
@click.pass_context
def openaev_export(ctx: click.Context, scenario_id: str, out: Path) -> None:
    """Write the export archive of SCENARIO_ID to OUT, once it passes the archive checks."""
    if not _CANONICAL_UUID.fullmatch(scenario_id):
        raise click.UsageError("SCENARIO_ID must be a UUID in lower case with hyphens")
    out = Path(os.path.normpath(out.absolute()))  # without "..", links left as they are

    def check(data: bytes) -> None:
        try:
            check_export_archive(data, str(out))
        except UnsafeInputError as error:
            # The platform has seen the token and chooses what the archive holds: the refusal
            # gives the check that failed, never the content, however it would be written. That
            # an export carries documents is said in the tool's own words.
            message = "the archive the platform exported fails this check"
            if isinstance(error, DocumentsNotSupportedError):
                message = DOCUMENTS_NOT_SUPPORTED
            raise UnsafeInputError(error.code, message, error.path) from error

    def produce() -> Report:
        return export_scenario(
            HttpOpenAEV.from_environment(os.environ),
            scenario_id,
            str(out),
            check=check,
            write=lambda data: write_output(out, data),
        )

    # The platform has seen the token: what it sends back never shows it.
    _emit(
        ctx,
        "openaev export",
        produce,
        hidden=usable_token(os.environ.get("OPENAEV_TOKEN")),
    )


@openaev.command(name="import")
@click.argument("archive", type=click.Path(path_type=Path))
@click.pass_context
def openaev_import(ctx: click.Context, archive: Path) -> None:
    """Import ARCHIVE, once it passes the archive checks; each inject the platform skips is a
    blocking finding."""
    archive = Path(os.path.normpath(archive.absolute()))  # without "..", links left as they are

    def produce() -> Report:
        platform = HttpOpenAEV.from_environment(os.environ)
        data = read_export_archive(archive)
        return import_archive(platform, data, repository_path(str(archive), Path.cwd()))

    _emit(
        ctx,
        "openaev import",
        produce,
        hidden=usable_token(os.environ.get("OPENAEV_TOKEN")),
    )
