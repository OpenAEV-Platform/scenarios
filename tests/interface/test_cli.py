"""The command-line entry point starts and reports its version."""

from click.testing import CliRunner

import scenario_tools
from scenario_tools.interface.cli import main


def test_version_option_prints_the_package_version() -> None:
    result = CliRunner().invoke(main, ["--version"])

    assert result.exit_code == 0
    assert scenario_tools.__version__ in result.output


def test_help_names_the_tool() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "scenario-tools" in result.output
