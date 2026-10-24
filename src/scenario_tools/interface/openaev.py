"""The commands that talk to an OpenAEV platform: export, import, and the check before an
import."""

import os
from pathlib import Path

import click

from scenario_tools.adapters.data_files import (
    DOCUMENTS_NOT_SUPPORTED,
    DocumentsNotSupportedError,
    check_export_archive,
    read_export_archive,
    scenario_from_export,
    write_output,
)
from scenario_tools.adapters.openaev_http import HttpOpenAEV, usable_token
from scenario_tools.application.findings import repository_path
from scenario_tools.application.transfer import check_reuse, export_scenario, import_archive
from scenario_tools.domain.shared.finding import (
    Report,
)
from scenario_tools.domain.shared.identifiers import CANONICAL_UUID
from scenario_tools.interface.base import (
    _emit,
    main,
)
from scenario_tools.ports.errors import (
    UnsafeInputError,
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
    if not CANONICAL_UUID.fullmatch(scenario_id):
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
    """Import ARCHIVE, once it passes the archive checks and nothing it embeds would be replaced
    by another payload the platform holds under the same identifier (OAV-002, as openaev check
    says); each inject the platform skips is a blocking finding."""
    archive = Path(os.path.normpath(archive.absolute()))  # without "..", links left as they are

    def produce() -> Report:
        platform = HttpOpenAEV.from_environment(os.environ)
        data = read_export_archive(archive)
        path = repository_path(str(archive), Path.cwd())
        return import_archive(platform, data, path, scenario_from_export(data, str(archive)))

    _emit(
        ctx,
        "openaev import",
        produce,
        hidden=usable_token(os.environ.get("OPENAEV_TOKEN")),
    )


@openaev.command(name="check")
@click.argument("archive", type=click.Path(path_type=Path))
@click.pass_context
def openaev_check(ctx: click.Context, archive: Path) -> None:
    """Say, without importing anything, what importing ARCHIVE would reuse on the platform with
    another content: each payload the platform holds under the contract ID or the payload
    external ID the archive gives, and whose canonical hash is not the archive's, is a blocking
    finding (OAV-002). The platform is only read."""
    archive = Path(os.path.normpath(archive.absolute()))

    def produce() -> Report:
        platform = HttpOpenAEV.from_environment(os.environ)
        data = read_export_archive(archive)
        path = repository_path(str(archive), Path.cwd())
        return check_reuse(platform, scenario_from_export(data, str(archive)), path)

    _emit(
        ctx,
        "openaev check",
        produce,
        hidden=usable_token(os.environ.get("OPENAEV_TOKEN")),
    )
