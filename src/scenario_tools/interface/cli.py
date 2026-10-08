"""Command-line entry point: ``scenario-tools``."""

import click

from scenario_tools import __version__
from scenario_tools.application.check_title import check_title as check_title_use_case


@click.group(name="scenario-tools")
@click.version_option(__version__, prog_name="scenario-tools")
def main() -> None:
    """Prepare, check, release and verify OpenAEV scenarios."""


@main.command(name="check-title")
@click.argument("title")
def check_title(title: str) -> None:
    """Check a pull request TITLE against the shared convention."""
    problem = check_title_use_case(title)
    if problem is not None:
        click.echo(f"Invalid pull request title: {problem.message}", err=True)
        raise click.exceptions.Exit(1)
    click.echo("Pull request title is valid.")
