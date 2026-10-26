"""The commands on releases: collecting approvals, building a release, verifying one, and the
conformance fixtures."""

import dataclasses
import json
import os
from pathlib import Path
from typing import Any

import click

from scenario_tools.adapters.catalogue_files import CatalogueDirectory
from scenario_tools.adapters.data_files import (
    scenario_from_archive,
    write_output,
)
from scenario_tools.adapters.fixture_zip import HandmadeArchives
from scenario_tools.adapters.git import (
    commit_time,
    head_commit,
    last_commit,
)
from scenario_tools.adapters.github_api import HttpGitHub
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import (
    JSON_LIMIT,
    parse_json,
    read_json_file,
    read_regular_file,
)
from scenario_tools.adapters.safe_zip import ARCHIVE_LIMIT
from scenario_tools.adapters.zip_archive import ZipArchiveBuilder
from scenario_tools.application.build_fixtures import EXPECTED, fixture_files, release_fixtures
from scenario_tools.application.build_release import (
    ArchivedEntry,
    EntryResult,
    build_release,
    entry_for_release,
)
from scenario_tools.application.collect_approvals import collect_approvals
from scenario_tools.application.findings import finding_from_unsafe_input
from scenario_tools.application.fixture_expectations import (
    Expectation,
    expectations_from_document,
)
from scenario_tools.application.run_fixtures import run_fixtures
from scenario_tools.application.validate_payloads import checked_payloads
from scenario_tools.application.verify_release import verify_release
from scenario_tools.domain.catalogue.facts import export_facts
from scenario_tools.domain.catalogue.metadata import (
    communication_injectors_from_document,
    is_tabletop,
)
from scenario_tools.domain.release.channel import (
    POINTER_LIMIT,
    channel_pointer,
    check_moved_forward,
    pointer_document,
    pointer_from_document,
    points_at,
)
from scenario_tools.domain.release.manifest import (
    CHANNELS,
    REPOSITORY,
    PayloadFile,
    PreviousRelease,
    approvals_document,
    approvals_from_document,
    approved_manifest,
    is_github_login,
    merged_before_review_from_document,
    previous_release,
)
from scenario_tools.domain.shared.canonical import jcs
from scenario_tools.domain.shared.finding import (
    Finding,
    Report,
    Severity,
)
from scenario_tools.domain.verification.payload_references import (
    HeldVersions,
    PayloadReference,
)
from scenario_tools.domain.verification.payload_version import VERSION_FILE_LIMIT
from scenario_tools.domain.verification.release_output import payload_reference_findings
from scenario_tools.interface.base import (
    _emit,
    _entry_archive,
    _free_place,
    _inside,
    _output,
    _refuse_uncommitted,
    _Rules,
    _rules,
    main,
)
from scenario_tools.ports.errors import (
    EnvironmentProblemError,
    UnsafeInputError,
)


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


@main.command(name="approve")
@click.argument("manifest", type=click.Path(path_type=Path, dir_okay=False))
@click.option("--approver", required=True, help="The release approver's GitHub login.")
@click.option(
    "--out",
    required=True,
    type=click.Path(path_type=Path),
    help="A new or empty directory, where manifest.json is written.",
)
@click.pass_context
def approve(ctx: click.Context, manifest: Path, approver: str, out: Path) -> None:
    """Name --approver, a GitHub login in lower case, as the release approver of the manifest
    MANIFEST, written to --out in canonical JSON (JCS); a manifest already approved is refused.
    Run in the release job once the release is approved, before verify --approved, which checks
    the manifest against its schema."""
    if not is_github_login(approver):
        raise click.BadParameter("give a GitHub login in lower case", param_hint="--approver")
    out = _free_place(out, directory=True)

    def produce() -> Report:
        try:
            approved = approved_manifest(read_json_file(manifest), approver)
        except ValueError as error:
            raise EnvironmentProblemError(str(error)) from error
        out.mkdir(exist_ok=True)
        write_output(out / "manifest.json", jcs(approved), create=True)
        return Report("approve")

    _emit(ctx, "approve", produce, None)


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


@main.group(name="channel")
def channel() -> None:
    """Check a release channel's pointer, and write the one that moves it forward."""


def _manifest_read(manifest: Path) -> tuple[bytes, Any]:
    """The bytes of ``manifest`` and what they hold, read as every JSON document of a release."""
    data = read_regular_file(manifest, JSON_LIMIT)
    return data, parse_json(data, limit=JSON_LIMIT)


@channel.command(name="previous")
@click.option("--pointer", required=True, type=click.Path(path_type=Path, dir_okay=False))
@click.option("--manifest", required=True, type=click.Path(path_type=Path, dir_okay=False))
@click.option("--channel", "name", required=True, type=click.Choice(CHANNELS))
@click.pass_context
def channel_previous(ctx: click.Context, pointer: Path, manifest: Path, name: str) -> None:
    """Check that --pointer, the pointer of --channel, is well formed and names the release
    whose manifest is --manifest: its SHA-256, repository, channel and name. The release
    workflow runs it on the channel's previous release before it builds the next one."""

    def produce() -> Report:
        try:
            found = pointer_from_document(read_json_file(pointer, limit=POINTER_LIMIT))
        except ValueError as error:
            raise EnvironmentProblemError(str(error)) from error
        if found.channel != name:
            raise EnvironmentProblemError(
                f"{pointer} is the pointer of {found.channel}, not {name}"
            )
        data, document = _manifest_read(manifest)
        if not isinstance(document, dict) or not points_at(found, data, document):
            raise EnvironmentProblemError(
                f"{manifest} is not the release the channel's pointer names, {found.release}"
            )
        return Report("channel")

    _emit(ctx, "channel", produce, None)


@channel.command(name="pointer")
@click.argument("manifest", type=click.Path(path_type=Path, dir_okay=False))
@click.option(
    "--previous",
    required=True,
    help="The channel's pointer until now, or none when the channel has none yet.",
)
@click.option("--out", required=True, type=click.Path(path_type=Path))
@click.pass_context
def channel_pointer_command(ctx: click.Context, manifest: Path, previous: str, out: Path) -> None:
    """Write to --out, a new file, the pointer that moves the channel of MANIFEST, an approved
    release's manifest, to that release: refused unless it follows --previous, the channel's
    pointer until now, to a later release, or names the same release with the same manifest."""
    out = _free_place(out, directory=False)

    def produce() -> Report:
        data, document = _manifest_read(manifest)
        try:
            before = (
                None
                if previous == "none"
                else pointer_from_document(read_json_file(Path(previous), limit=POINTER_LIMIT))
            )
            if not isinstance(document, dict):
                raise ValueError("channel pointer: the manifest must be an object")
            after = channel_pointer(data, document)
            check_moved_forward(before, after)
        except ValueError as error:
            raise EnvironmentProblemError(str(error)) from error
        write_output(out, jcs(pointer_document(after)), create=True)
        return Report("channel")

    _emit(ctx, "channel", produce, None)
