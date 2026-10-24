"""The commands on payloads: the IDs of an entry's payloads, and the payload catalogue."""

import os
from pathlib import Path

import click

from scenario_tools.adapters.catalogue_files import CatalogueDirectory
from scenario_tools.adapters.data_files import (
    YamlDataLoader,
    read_stored_scenario,
)
from scenario_tools.adapters.entry_writer import RepositoryWriter
from scenario_tools.adapters.jsonschema_validator import JsonSchemaValidator
from scenario_tools.adapters.policy_levels import policy_levels
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.adapters.safe_readers import (
    YAML_LIMIT,
    parse_yaml,
    read_regular_file,
    yaml_bytes,
)
from scenario_tools.application.assign_payloads import (
    agreed_ids,
    assigned_entry,
    payload_findings,
)
from scenario_tools.application.findings import repository_path
from scenario_tools.application.repository_root import repository_root
from scenario_tools.application.validate_payloads import validate_payloads
from scenario_tools.domain.catalogue.archive import payloads_outside_contracts
from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.shared.finding import (
    Report,
)
from scenario_tools.domain.verification.payload_catalogue import TreeEntry
from scenario_tools.interface.base import (
    _catalogue,
    _emit,
    _levels_as_given,
    _refused,
    main,
)
from scenario_tools.ports.catalogue import CatalogueFiles
from scenario_tools.ports.errors import (
    EnvironmentProblemError,
    UnsafeInputError,
)


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
        levels = policy_levels(entry)
        root = repository_root(levels, entry)
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
        root = repository_root(levels, directory.parent)
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
