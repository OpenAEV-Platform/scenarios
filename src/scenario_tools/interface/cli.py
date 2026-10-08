"""Command-line entry point: ``scenario-tools``.

Every command returns a report through ``execute``, which renders it as text or as the JSON
document of the contract and gives the exit code: 0 when the report is ok, 1 with a blocking
finding, 2 on a usage error (click), 3 when the environment cannot be used.
"""

import json
from collections.abc import Callable
from pathlib import Path

import click

from scenario_tools import __version__
from scenario_tools.application.check_title import check_title as check_title_use_case
from scenario_tools.application.findings import finding_from_unsafe_input
from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

EXIT_OK, EXIT_BLOCKING, EXIT_ENVIRONMENT = 0, 1, 3


def _line(finding: Finding) -> str:
    where = " ".join(part for part in (finding.path, finding.field) if part)
    location = f" {where}" if where else ""
    return f"{finding.severity.name} {finding.code}{location}: {finding.message}"


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
    relative to ``root``, the repository root, which is the working directory by default."""
    try:
        report = produce()
    except UnsafeInputError as error:
        report = Report(command, (finding_from_unsafe_input(error, root or Path.cwd()),))
    except EnvironmentProblemError as error:
        if output_format == "json":
            document = {"command": command, "ok": False, "findings": [], "error": str(error)}
            return json.dumps(document, ensure_ascii=False), EXIT_ENVIRONMENT
        return f"{command}: environment error: {error}", EXIT_ENVIRONMENT
    code = EXIT_OK if report.ok else EXIT_BLOCKING
    if output_format == "json":
        return json.dumps(report.document(), ensure_ascii=False), code
    return _text(report), code


def _emit(ctx: click.Context, command: str, produce: Callable[[], Report]) -> None:
    output, code = execute(command, produce, ctx.obj["format"])
    click.echo(output)
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
