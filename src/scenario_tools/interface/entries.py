"""The commands on the catalogue's entries: preparing one from an export, checking, rendering,
comparing and archiving it, taking an export in, and the checks of a pull request's title and
entries."""

import contextlib
import dataclasses
import datetime
import os
import signal
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

import click

from scenario_tools.adapters.catalogue_files import CatalogueDirectory
from scenario_tools.adapters.data_files import (
    YamlDataLoader,
    read_export,
    read_mapping,
    read_stored_scenario,
    write_output,
)
from scenario_tools.adapters.entry_writer import RepositoryWriter
from scenario_tools.adapters.git import changed_entries, converting, head_commit, uncommitted
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.plan import PlanFile
from scenario_tools.adapters.policy_levels import policy_levels
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import read_json_file, read_yaml_file, yaml_bytes
from scenario_tools.application.assign_payloads import catalogue_of
from scenario_tools.application.check_title import check_title as check_title_use_case
from scenario_tools.application.diff_entry import diff_entry
from scenario_tools.application.entry_external_id import entry_external_id
from scenario_tools.application.findings import repository_path
from scenario_tools.application.intake_check import intake_check
from scenario_tools.application.intake_entry import intake_entry
from scenario_tools.application.intake_write import intake_files, write_intake
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.application.render_sheet import SHEET, check_sheet, policy_exceptions, sheet_of
from scenario_tools.application.report_output import printable
from scenario_tools.application.repository_root import repository_root
from scenario_tools.domain.shared.finding import ERROR_LIMIT, Finding, Report, Severity, shorten
from scenario_tools.domain.shared.identifiers import CANONICAL_UUID
from scenario_tools.interface.base import (
    _PLANNED,
    _PLANNED_NAMED,
    EXIT_ENVIRONMENT,
    _catalogue,
    _emit,
    _entry_archive,
    _inside,
    _one_repository,
    _payload_catalogue,
    _refuse_uncommitted,
    _refused,
    _Rules,
    _rules,
    main,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError, UsageProblemError


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


REQUEST_LIMIT = 64 * 1024  # bytes of an intake request


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
    if check:
        payloads, rules, external_id = _check_options(
            (request, repo, plan), payloads, rules, external_id
        )
        _intake_check(ctx, export, payloads, rules, claims, external_id, previous)
        return
    request, repo, plan = _writing_options(checking, request, repo, plan)
    root, plan, inputs = _intake_places(ctx, export, request, repo, plan)

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


_WRITING = ("--request", "--repo", "--plan")  # the options of a run that writes


def _check_options(
    writing: tuple[Path | None, Path | None, Path | None],
    payloads: Path | None,
    rules: Path | None,
    external_id: str | None,
) -> tuple[Path, Path, str]:
    """The options --check needs; refuse those it may not have, or lacks."""
    extra = [name for name, value in zip(_WRITING, writing, strict=True) if value is not None]
    if extra:
        raise click.UsageError(f"--check writes nothing: leave out {', '.join(extra)}")
    if payloads is None or rules is None or external_id is None:
        raise click.UsageError("--check needs --payloads, --rules and --external-id")
    if not CANONICAL_UUID.fullmatch(external_id):
        raise click.UsageError("--external-id must be a UUID in lower case with hyphens")
    return payloads, rules, external_id


def _writing_options(
    checking: dict[str, object], request: Path | None, repo: Path | None, plan: Path | None
) -> tuple[Path, Path, Path]:
    """The options of a run that writes; refuse those of --check, and the missing ones."""
    extra = [name for name, value in checking.items() if value is not None]
    if extra:
        raise click.UsageError(f"only with --check: {', '.join(extra)}")
    if request is None or repo is None or plan is None:
        given = (request, repo, plan)
        missing = [name for name, value in zip(_WRITING, given, strict=True) if value is None]
        raise click.UsageError(f"intake needs {', '.join(missing)}, or --check")
    return request, repo, plan


def _intake_places(
    ctx: click.Context, export: Path, request: Path, repo: Path, plan: Path
) -> tuple[Path, Path, tuple[Path, Path]]:
    """The repository's root, the plan and the inputs, resolved, refused where git holds them."""
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
    return root, plan, inputs


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
        catalogue = payloads.absolute()
        if catalogue.name in ("", ".", ".."):  # no leaf to keep: the directory it names
            catalogue = Path(os.path.realpath(catalogue))
        # The parent as the system resolves it, a link or a ".." after one included; the
        # catalogue itself, and what it holds, are read without following any link.
        catalogue = Path(os.path.realpath(catalogue.parent)) / catalogue.name
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


def _declared_external_id(metadata: Path) -> object:
    """What ``scenario.yaml`` declares as the external ID, ``None`` when it declares none."""
    document = read_yaml_file(metadata)
    return document.get("external_id") if isinstance(document, dict) else None
