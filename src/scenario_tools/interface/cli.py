"""Command-line entry point: ``scenario-tools``."""

import click

from scenario_tools import __version__


@click.group(name="scenario-tools")
@click.version_option(__version__, prog_name="scenario-tools")
def main() -> None:
    """Prepare, check, release and verify OpenAEV scenarios."""
