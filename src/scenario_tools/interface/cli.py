"""Command-line entry point: ``scenario-tools``.

Every command returns a report through ``execute``, which renders it as text or as the JSON
document of the contract and gives the exit code: 0 when the report is ok, 1 with a blocking
finding, 2 on a usage error (click), 3 when the environment cannot be used, and 4 when the tool
itself fails, so that a defect of the tool never reads as a defect of the content.
"""

import contextlib
import dataclasses
import json
import os
import re
import signal
from collections.abc import Callable, Iterator
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
from scenario_tools.adapters.entry_writer import RepositoryWriter
from scenario_tools.adapters.git import (
    changed_entries,
    converted,
    converting,
    head_commit,
    uncommitted,
)
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.openaev_http import HttpOpenAEV, usable_token
from scenario_tools.adapters.plan import PlanFile
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import (
    YAML_LIMIT,
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
    payload_findings,
)
from scenario_tools.application.build_archive import build_archive
from scenario_tools.application.check_title import check_title as check_title_use_case
from scenario_tools.application.findings import finding_from_unsafe_input, repository_path
from scenario_tools.application.intake_entry import intake_entry, intake_files, write_intake
from scenario_tools.application.prepare_entry import prepare_entry, renormaliser
from scenario_tools.application.transfer import export_scenario, import_archive
from scenario_tools.application.validate_entry import validate_entry
from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.catalogue.entry import domains_from_document
from scenario_tools.domain.catalogue.facts import BuiltinContracts, copy_findings, export_facts
from scenario_tools.domain.policy.actions import forbidden_from_document, side_effects_from_document
from scenario_tools.domain.policy.rule import PolicyData
from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.policy.vendors import vendors_from_document
from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.shared.finding import (
    COUNT_CODE,
    ERROR_LIMIT,
    MESSAGE_LIMIT,
    Finding,
    Report,
    Severity,
    shorten,
)
from scenario_tools.domain.verification.payload_references import AgreedIds
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
        declared = read_yaml_file(metadata)
        external_id = declared.get("external_id") if isinstance(declared, dict) else None
        if not isinstance(external_id, str) or not _CANONICAL_UUID.fullmatch(external_id):
            message = "external_id must be a UUID in lower case with hyphens"
            where = repository_path(str(metadata), root)
            return Report(
                "archive", (Finding("SCH-001", Severity.BLOCKING, where, "/external_id", message),)
            )
        try:
            builtin = BuiltinContracts.from_document(loader.load("builtin-contracts"))
            policy = _policy_data(loader)
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
            renormalised=lambda stored: renormaliser(loader)(stored, external_id, path),
            contract_findings=lambda stored: (
                export_facts(stored, builtin, path)[1]
                + copy_findings(stored, builtin, path)
                + hidden_character_findings(stored, path)
            ),
            check=lambda built: check_export_archive(built, str(out)),
            limit=ARCHIVE_LIMIT,
            policy=policy,
            declared=declared,
            agreed=agreed_ids(loader),
        )
        if built is not None:
            write_output(out, built)
        return report

    _emit(ctx, "archive", produce, root)


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
        where = repository_path(str(entry), root)
        # Its bytes and its document from one read: the bytes are what --assign replaces.
        written = read_regular_file(metadata, YAML_LIMIT)
        declared = parse_yaml(written, path=str(metadata))
        data, stored = read_stored_scenario(scenario)
        if not assign:
            return Report("payloads", payload_findings(declared, stored, where, agreed))
        result = assigned_entry(declared, stored, where, agreed)
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
        return Report("payloads", payload_findings(result.metadata, result.stored, where, agreed))

    _emit(ctx, "payloads", produce, root)


@main.command(name="validate")
@click.argument("entries", nargs=-1, required=True, type=click.Path(path_type=Path))
@click.pass_context
def validate(ctx: click.Context, entries: tuple[Path, ...]) -> None:
    """Check each of ENTRIES, an entry directory, against the schemas and the rules of an entry
    of the repository that holds them; exit with 1 if anything blocks one of them.

    Of the policy rules, POL-001 (sources linked to public pages, nothing copied into an entry),
    POL-002 (no recurrence), POL-003 (only allowed hosts), POL-004 (no forbidden action),
    POL-005 (a cleanup for every payload that changes the endpoint), POL-006 (no security
    product named), POL-007 (elevated privileges, for the reviewer), POL-009 (injects spaced
    out) and POL-010 (no internal data) run. The other policy rules, versioning against the
    previous release, the generated README.md, the payload references, the CHANGELOG.md
    sections and the private deny-list are not run yet: an entry that passes may still fail
    them.

    No symbolic link inside the repository is followed; the path that leads to the repository
    may go through one."""
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
        _emit(ctx, "validate", _refused(error), levels[-1] if levels else None)
    if len(roots) > 1:
        raise click.UsageError("the entries belong to different repositories")
    [root] = roots.values()

    def produce() -> Report:
        source = RepositoryEntries(root)
        rules = _rules(source)
        findings: list[Finding] = []
        for entry in dict.fromkeys(relatives):  # an entry given twice is checked once
            findings += rules.validate(entry, source)
        return Report("validate", tuple(findings))

    _emit(ctx, "validate", produce, root)


@dataclasses.dataclass(frozen=True)
class _Rules:
    """The maintainers' rules the checks of an entry read."""

    loader: YamlDataLoader
    builtin: BuiltinContracts
    domains: tuple[str, ...]
    schema: JsonSchemaValidator
    policy: PolicyData
    agreed: AgreedIds

    def validate(self, entry: str, source: RepositoryEntries) -> tuple[Finding, ...]:
        return validate_entry(
            entry,
            source,
            schema=self.schema,
            builtin=self.builtin,
            renormalised=renormaliser(self.loader),
            domains=self.domains,
            policy=self.policy,
            agreed=self.agreed,
        )


def _policy_data(loader: YamlDataLoader) -> PolicyData:
    """The data the policy rules read: the allowed targets, the forbidden actions and the
    commands that change an endpoint."""
    return PolicyData(
        AllowedTargets.from_document(loader.load("allowed-targets")),
        forbidden_from_document(loader.load("forbidden-actions")),
        side_effects_from_document(loader.load("side-effects")),
        vendors_from_document(loader.load("vendor-names")),
    )


def _rules(source: RepositoryEntries, *, intake: bool = False) -> _Rules:
    """The rules of the repository ``source`` reads, read like the entries, never through a
    link, the intake request's schema among them for ``intake``; rules that cannot be used are
    the environment's fault, never an entry's."""
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
    for name in ("scenario", "intake-request") if intake else ("scenario",):
        if not (schemas / f"{name}.schema.json").is_file():
            raise EnvironmentProblemError(f"schemas cannot be used: {name}.schema.json is missing")
    return _Rules(loader, builtin, domains, schema, policy, agreed_ids(loader))


REQUEST_LIMIT = 64 * 1024  # bytes of an intake request

# What intake keeps as committed, but for the entry it writes: no plan nor input goes there.
_PLANNED = ("scenarios", "policy", "schemas")
_PLANNED_NAMED = ", ".join(f"{path}/" for path in _PLANNED[:-1]) + f" or {_PLANNED[-1]}/"


@main.command(name="intake")
@click.argument("export", type=click.Path(path_type=Path, dir_okay=False))
@click.option("--request", "request", required=True, type=click.Path(path_type=Path))
@click.option("--repo", "repo", required=True, type=click.Path(path_type=Path))
@click.option("--plan", "plan", required=True, type=click.Path(path_type=Path))
@click.pass_context
def intake(ctx: click.Context, export: Path, request: Path, repo: Path, plan: Path) -> None:
    """Turn EXPORT, a platform export (an archive, or its JSON), and the request at --request
    into an entry of the repository at --repo, written in place, and write at --plan the plan of
    the pull request that proposes it. A refused request writes nothing."""
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
                )
                if result.refusals or result.request is None:
                    return Report("intake", result.refusals)
                entry = result.request.entry
                ours = frozenset(f"{entry}/{name}" for name in intake_files(result, yaml_bytes))
                _refuse_converting(root, ours)  # files not written yet: attributes match them too
                with _stop_requests_held():
                    left = write_intake(
                        result,
                        entries=RepositoryWriter(source),
                        plan=PlanFile(plan),
                        base=base,
                        current=lambda: _still_base(source, ours),
                        # Read afresh: the catalogue now holds the entry written.
                        validate=lambda entry: rules.validate(entry, RepositoryEntries(root)),
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


def _refuse_uncommitted(root: Path) -> None:
    """Refuse a checkout whose bytes git converts from its commit, or whose catalogue or rules
    differ from it: the plan must describe what its base gives. Conversions come first: git
    status would run a filter the attributes name."""
    turned = converted(root, _PLANNED)
    if turned:
        more = f" and {len(turned) - 1} more" if len(turned) > 1 else ""
        raise EnvironmentProblemError(
            f"git converts files under {_PLANNED_NAMED} between the commit and the checkout "
            f"({turned[0]}{more}, by its attributes or its line ends): the plan would not "
            "describe the commit's "
            "bytes"
        )
    changed = uncommitted(root, _PLANNED)
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
