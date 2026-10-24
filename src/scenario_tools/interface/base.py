"""What every command of ``scenario-tools`` shares: the command group, how a report is run and
written out with its exit code, and the helpers more than one group of commands reads with."""

import dataclasses
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import click

from scenario_tools import __version__
from scenario_tools.adapters.catalogue_files import CatalogueDirectory
from scenario_tools.adapters.data_files import (
    YamlDataLoader,
    check_export_archive,
    read_attachments,
    read_stored_scenario,
)
from scenario_tools.adapters.git import (
    converted,
    uncommitted,
)
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import (
    read_yaml_file,
)
from scenario_tools.adapters.safe_zip import ARCHIVE_LIMIT
from scenario_tools.adapters.zip_archive import ZipArchiveBuilder
from scenario_tools.application.assign_payloads import (
    agreed_ids,
    catalogue_of,
)
from scenario_tools.application.build_archive import build_archive
from scenario_tools.application.build_release import (
    ArchivedEntry,
)
from scenario_tools.application.entry_external_id import CANONICAL_UUID
from scenario_tools.application.findings import finding_from_unsafe_input, repository_path
from scenario_tools.application.prepare_entry import renormaliser
from scenario_tools.application.report_output import (
    concealed,
    printable,
    withheld_output,
)
from scenario_tools.application.repository_root import repository_root
from scenario_tools.application.validate_entry import validate_entry
from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.catalogue.entry import domains_from_document
from scenario_tools.domain.catalogue.facts import BuiltinContracts, copy_findings, export_facts
from scenario_tools.domain.policy.actions import forbidden_from_document, side_effects_from_document
from scenario_tools.domain.policy.exceptions import exceptions_from_document
from scenario_tools.domain.policy.rule import PolicyData
from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.policy.vendors import vendors_from_document
from scenario_tools.domain.release.manifest import (
    archive_name,
)
from scenario_tools.domain.shared.finding import (
    ERROR_LIMIT,
    Finding,
    Report,
    Severity,
    shorten,
)
from scenario_tools.domain.shared.workflow import ExportKeys
from scenario_tools.domain.verification.payload_catalogue import Catalogue
from scenario_tools.domain.verification.payload_references import (
    AgreedIds,
    HeldVersions,
)
from scenario_tools.ports.errors import (
    EnvironmentProblemError,
    UnsafeInputError,
)

EXIT_OK, EXIT_BLOCKING, EXIT_ENVIRONMENT, EXIT_INTERNAL = 0, 1, 3, 4


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
            return shorten(printable(f"{command}: internal error: {text}"))

        message = f"{type(error).__name__}: {_describe(error)}"
        return concealed(message, render, hidden), EXIT_INTERNAL


def _describe(error: Exception) -> str:
    """The text of an error, even one whose own text cannot be built."""
    try:
        return str(error)
    except Exception:  # noqa: BLE001 - the guard itself must not fail
        return "<unprintable>"


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
            return shorten(printable(f"{command}: environment error: {text}"), ERROR_LIMIT)

        return concealed(str(error), render, hidden, ERROR_LIMIT), EXIT_ENVIRONMENT
    code = EXIT_OK if report.ok else EXIT_BLOCKING
    return withheld_output(report, output_format, hidden), code


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


def _refused(error: Exception) -> Callable[[], Report]:
    def produce() -> Report:
        raise error

    return produce


def _entry_archive(
    entry: Path, root: Path, loader: YamlDataLoader, catalogue: HeldVersions, out: str | None
) -> ArchivedEntry:
    """What the archive's checks find of the entry at ``entry``, of the repository at
    ``root`` whose payload catalogue holds ``catalogue``, its import archive when they let it be
    built, meant for ``out`` or, without it, named as a release names it, and what they read."""
    scenario, metadata = entry / "scenario.json", entry / "scenario.yaml"
    declared = read_yaml_file(metadata)
    external_id = declared.get("external_id") if isinstance(declared, dict) else None
    if not isinstance(external_id, str) or not CANONICAL_UUID.fullmatch(external_id):
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
            root = repository_root(levels, directory)
            roots.setdefault(_identity(root), root)
            relatives.append(directory.relative_to(root).as_posix())
    except Exception as error:  # noqa: BLE001 - reported as refused input, environment or defect
        _emit(ctx, command, _refused(error), levels[-1] if levels else None)
    if len(roots) > 1:
        raise click.UsageError("the entries belong to different repositories")
    [root] = roots.values()
    return root, relatives


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


# What intake keeps as committed, but for the entry it writes: no plan nor input goes there.
_PLANNED = ("scenarios", "payloads", "policy", "schemas")


_PLANNED_NAMED = ", ".join(f"{path}/" for path in _PLANNED[:-1]) + f" or {_PLANNED[-1]}/"


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
