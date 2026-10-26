"""The intake command: an export taken into the catalogue, or checked against it, its request,
its places and its plan read as the command's options give them; a stop asked while it writes
waits until what it wrote is kept or taken back."""

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
    read_stored_scenario,
)
from scenario_tools.adapters.entry_writer import RepositoryWriter
from scenario_tools.adapters.git import converting, head_commit, uncommitted
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.plan import PlanFile
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import read_yaml_file, yaml_bytes
from scenario_tools.application.assign_payloads import catalogue_of
from scenario_tools.application.findings import repository_path
from scenario_tools.application.intake_check import intake_check
from scenario_tools.application.intake_entry import intake_entry
from scenario_tools.application.intake_write import intake_files, write_intake
from scenario_tools.domain.shared.finding import Finding, Report
from scenario_tools.domain.shared.identifiers import CANONICAL_UUID
from scenario_tools.interface.base import (
    _PLANNED,
    _PLANNED_NAMED,
    _catalogue,
    _emit,
    _inside,
    _payload_catalogue,
    _refuse_uncommitted,
    _Rules,
    _rules,
    main,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

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
