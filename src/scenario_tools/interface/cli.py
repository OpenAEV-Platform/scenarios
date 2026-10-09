"""Command-line entry point: ``scenario-tools``.

Every command returns a report through ``execute``, which renders it as text or as the JSON
document of the contract and gives the exit code: 0 when the report is ok, 1 with a blocking
finding, 2 on a usage error (click), 3 when the environment cannot be used, and 4 when the tool
itself fails, so that a defect of the tool never reads as a defect of the content.
"""

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import click

from scenario_tools import __version__
from scenario_tools.adapters.data_files import (
    YamlDataLoader,
    check_export_archive,
    read_export,
    read_export_archive,
    read_mapping,
    write_output,
)
from scenario_tools.adapters.openaev_http import HttpOpenAEV
from scenario_tools.adapters.safe_readers import read_json_file, read_yaml_file
from scenario_tools.application.check_title import check_title as check_title_use_case
from scenario_tools.application.findings import finding_from_unsafe_input, repository_path
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.application.transfer import export_scenario, import_archive
from scenario_tools.domain.shared.finding import Finding, Report, Severity, shorten
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
    command: str, produce: Callable[[], Report], output_format: str, root: Path | None = None
) -> tuple[str, int]:
    """Run ``produce`` and return what to print and the exit code. Paths in findings are made
    relative to ``root``, the repository root, which is the working directory by default. A
    failure anywhere, while producing or while rendering, exits with 4, never with 1."""
    try:
        return _run(command, produce, output_format, root)
    except Exception as error:  # noqa: BLE001 - the last guard: a defect never exits with 1
        line = f"{command}: internal error: {type(error).__name__}: {_describe(error)}"
        return shorten(_printable(line)), EXIT_INTERNAL


def _describe(error: Exception) -> str:
    """The text of an error, even one whose own text cannot be built."""
    try:
        return str(error)
    except Exception:  # noqa: BLE001 - the guard itself must not fail
        return "<unprintable>"


def _run(
    command: str, produce: Callable[[], Report], output_format: str, root: Path | None
) -> tuple[str, int]:
    try:
        report = produce()
    except UnsafeInputError as error:
        report = Report(command, (finding_from_unsafe_input(error, root or Path.cwd()),))
    except EnvironmentProblemError as error:
        if output_format == "json":
            message = shorten(str(error))
            document = {"command": command, "ok": False, "findings": [], "error": message}
            return json.dumps(document), EXIT_ENVIRONMENT
        return shorten(_printable(f"{command}: environment error: {error}")), EXIT_ENVIRONMENT
    code = EXIT_OK if report.ok else EXIT_BLOCKING
    if output_format == "json":
        return json.dumps(report.document()), code
    return _text(report), code


def _emit(
    ctx: click.Context, command: str, produce: Callable[[], Report], root: Path | None = None
) -> NoReturn:
    output, code = execute(command, produce, ctx.obj["format"], root)
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
        document = read_yaml_file(metadata)
        declared = document.get("external_id") if isinstance(document, dict) else None
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
    return [
        directory
        for directory in (out.resolve(), *out.resolve().parents)
        if (directory / "policy" / "data").is_dir()
    ]


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
    try:
        levels = _policy_levels(out)
        root = _repository_root(levels, out)
        entry_id = _entry_external_id(out, external_id)
    except click.UsageError:
        raise
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, "normalize", _refused(error), levels[-1] if levels else None)
    previous_file = previous.absolute() / "scenario.json" if previous else None
    mapping_file = mapping_file.absolute() if mapping_file else None

    def produce() -> Report:
        prepared = prepare_entry(
            read_export(export),
            entry_id,
            YamlDataLoader(root / "policy" / "data"),
            path=str(export),
            previous=read_json_file(previous_file) if previous_file else None,
            previous_path=str(previous_file) if previous_file else None,
            mapping=read_mapping(mapping_file) if mapping_file else None,
            mapping_path=str(mapping_file) if mapping_file else None,
        )
        target = out / "scenario.json"
        write_output(target, prepared.scenario_json)
        where = repository_path(str(target.resolve()), root)
        return Report(
            "normalize",
            tuple(
                Finding(
                    "VER-012",
                    Severity.INFO,
                    where,
                    "",
                    f"inject {inject} of the previous version is no longer in the export",
                )
                for inject in prepared.removed_injects
            ),
        )

    _emit(ctx, "normalize", produce, root)


@main.group(name="openaev")
def openaev() -> None:
    """Export a scenario from an OpenAEV platform, or import an archive into one. The platform
    is OPENAEV_URL, and the token OPENAEV_TOKEN, both read from the environment only."""


@openaev.command(name="export")
@click.argument("scenario_id")
@click.option("--out", required=True, type=click.Path(path_type=Path, dir_okay=False))
@click.pass_context
def openaev_export(ctx: click.Context, scenario_id: str, out: Path) -> None:
    """Write the export archive of SCENARIO_ID to OUT, once it passes the archive checks."""
    if not _CANONICAL_UUID.fullmatch(scenario_id):
        raise click.UsageError("SCENARIO_ID must be a UUID in lower case with hyphens")
    out = Path(os.path.normpath(out.absolute()))  # without "..", links left as they are

    def produce() -> Report:
        return export_scenario(
            HttpOpenAEV.from_environment(os.environ),
            scenario_id,
            str(out),
            check=lambda data: check_export_archive(data, str(out)),
            write=lambda data: write_output(out, data),
        )

    _emit(ctx, "openaev export", produce)


@openaev.command(name="import")
@click.argument("archive", type=click.Path(path_type=Path, dir_okay=False))
@click.pass_context
def openaev_import(ctx: click.Context, archive: Path) -> None:
    """Import ARCHIVE, once it passes the archive checks; each inject the platform skips is a
    blocking finding."""
    archive = Path(os.path.normpath(archive.absolute()))  # without "..", links left as they are

    def produce() -> Report:
        platform = HttpOpenAEV.from_environment(os.environ)
        data = read_export_archive(archive)
        return import_archive(platform, data, repository_path(str(archive), Path.cwd()))

    _emit(ctx, "openaev import", produce)
