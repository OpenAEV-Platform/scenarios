"""The commands on the catalogue's entries: preparing one from an export, checking, rendering,
comparing and archiving it, taking an export in, and the checks of a pull request's title and
entries."""

import os
from pathlib import Path

import click

from scenario_tools.adapters.data_files import (
    YamlDataLoader,
    read_export,
    read_mapping,
    write_output,
)
from scenario_tools.adapters.git import changed_entries
from scenario_tools.adapters.policy_levels import policy_levels
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import read_json_file, read_yaml_file, yaml_bytes
from scenario_tools.application.check_title import check_title as check_title_use_case
from scenario_tools.application.diff_entry import diff_entry
from scenario_tools.application.entry_external_id import entry_external_id
from scenario_tools.application.findings import repository_path
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.application.render_sheet import SHEET, check_sheet, policy_exceptions, sheet_of
from scenario_tools.application.report_output import printable
from scenario_tools.application.repository_root import repository_root
from scenario_tools.domain.shared.finding import ERROR_LIMIT, Finding, Report, Severity, shorten
from scenario_tools.interface.base import (
    EXIT_ENVIRONMENT,
    _catalogue,
    _emit,
    _entry_archive,
    _inside,
    _one_repository,
    _refused,
    _rules,
    main,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UsageProblemError


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
        text = shorten(printable(f"changed-entries: environment error: {error}"), ERROR_LIMIT)
        click.echo(text, err=True)
        ctx.exit(EXIT_ENVIRONMENT)
    click.echo("".join(f"{entry}\0" for entry in entries), nl=False)


def _entry_external_id(out: Path, given: str | None) -> str:
    """The external ID of the entry, as ``entry_external_id`` chooses it from what its
    ``scenario.yaml`` declares, if it has one, and what is given; a refusal is a usage error."""
    metadata = out / "scenario.yaml"
    declared = None
    if metadata.exists() or metadata.is_symlink():
        declared = _declared_external_id(metadata)
    try:
        return entry_external_id(metadata, declared, given)
    except UsageProblemError as error:
        raise click.UsageError(str(error)) from None


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
        levels = policy_levels(out)
        root = repository_root(levels, out)
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
        levels = policy_levels(entry)
        root = repository_root(levels, entry)
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


def _declared_external_id(metadata: Path) -> object:
    """What ``scenario.yaml`` declares as the external ID, ``None`` when it declares none."""
    document = read_yaml_file(metadata)
    return document.get("external_id") if isinstance(document, dict) else None
