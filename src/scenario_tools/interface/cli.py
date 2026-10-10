"""Command-line entry point: ``scenario-tools``.

Every command returns a report through ``execute``, which renders it as text or as the JSON
document of the contract and gives the exit code: 0 when the report is ok, 1 with a blocking
finding, 2 on a usage error (click), 3 when the environment cannot be used, and 4 when the tool
itself fails, so that a defect of the tool never reads as a defect of the content.
"""

import dataclasses
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import click

from scenario_tools import __version__
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
    write_output,
)
from scenario_tools.adapters.openaev_http import HttpOpenAEV, usable_token
from scenario_tools.adapters.safe_readers import read_json_file, read_yaml_file, yaml_bytes
from scenario_tools.adapters.safe_zip import ARCHIVE_LIMIT
from scenario_tools.adapters.zip_archive import ZipArchiveBuilder
from scenario_tools.application.build_archive import build_archive
from scenario_tools.application.check_title import check_title as check_title_use_case
from scenario_tools.application.findings import finding_from_unsafe_input, repository_path
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.application.transfer import export_scenario, import_archive
from scenario_tools.domain.catalogue.archive import belongs_to
from scenario_tools.domain.catalogue.facts import BuiltinContracts, copy_findings, export_facts
from scenario_tools.domain.shared.finding import COUNT_CODE, Finding, Report, Severity, shorten
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


def _concealed(message: str, render: Callable[[str], str], hidden: str) -> str:
    """``message`` as ``render`` writes it, or withheld when that would show ``hidden``, or the
    start of it where the message is cut short. The token's characters are never escaped, so
    the token shows as it is or not at all."""
    output = render(message)
    if hidden and (
        hidden in output or _cut_in(output, hidden) or _cut_in_any_form(shorten(message), hidden)
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
                document = {"command": command, "ok": False, "findings": [], "error": shorten(text)}
                return json.dumps(document)
            return shorten(_printable(f"{command}: environment error: {text}"))

        return _concealed(str(error), render, hidden), EXIT_ENVIRONMENT
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
            path=str(export),
            previous=read_json_file(previous_file) if previous_file else None,
            previous_path=str(previous_file) if previous_file else None,
            mapping=read_mapping(mapping_file) if mapping_file else None,
            mapping_path=str(mapping_file) if mapping_file else None,
            start_at=repository_path(str(metadata.resolve()), root) if first else None,
        )
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
                f"inject {inject} of the previous version is no longer in the export",
            )
            for inject in prepared.removed_injects
        )
        return Report("normalize", findings + prepared.to_complete)

    _emit(ctx, "normalize", produce, root)


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
    scenario, metadata = entry / "scenario.json", entry / "scenario.yaml"
    levels: list[Path] = []
    try:
        levels = _policy_levels(entry)
        root = _repository_root(levels, entry)
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, "archive", _refused(error), levels[-1] if levels else None)

    def produce() -> Report:
        loader = YamlDataLoader(root / "policy" / "data")
        external_id = _declared_external_id(metadata)
        if not isinstance(external_id, str) or not _CANONICAL_UUID.fullmatch(external_id):
            message = "external_id must be a UUID in lower case with hyphens"
            where = repository_path(str(metadata), root)
            return Report(
                "archive", (Finding("SCH-001", Severity.BLOCKING, where, "/external_id", message),)
            )
        try:
            builtin = BuiltinContracts.from_document(loader.load("builtin-contracts"))
        except ValueError as error:
            raise EnvironmentProblemError(f"policy data cannot be used: {error}") from error
        path = repository_path(str(scenario), root)
        data, document = read_stored_scenario(scenario)
        report, built = build_archive(
            document,
            data,
            read_attachments(entry / "attachments.zip"),
            path,
            str(out),
            ZipArchiveBuilder(),
            # Normalised again with itself as the previous version, unless it is another
            # entry's: then what normalisation writes for this one differs anyway.
            renormalised=lambda stored: (
                prepare_entry(
                    stored,
                    external_id,
                    loader,
                    path=path,
                    previous=stored if belongs_to(stored, external_id) else None,
                ).scenario_json
            ),
            contract_findings=lambda stored: (
                export_facts(stored, builtin, path)[1] + copy_findings(stored, builtin, path)
            ),
            check=lambda built: check_export_archive(built, str(out)),
            limit=ARCHIVE_LIMIT,
        )
        if built is not None:
            write_output(out, built)
        return report

    _emit(ctx, "archive", produce, root)


def _declared_external_id(metadata: Path) -> object:
    """What ``scenario.yaml`` declares as the external ID, ``None`` when it declares none."""
    document = read_yaml_file(metadata)
    return document.get("external_id") if isinstance(document, dict) else None


def _inside(path: Path, directory: Path) -> bool:
    """Whether ``path`` is ``directory`` or lies within it, compared by file identity on the
    path the write resolves to: a link to the directory or to a folder of it, or another case
    on a case-insensitive disk, still names a place inside it."""
    if not directory.is_dir():
        return False
    resolved = Path(os.path.realpath(path))
    return any(
        candidate.exists() and candidate.samefile(directory)
        for candidate in (resolved, *resolved.parents)
    )


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
