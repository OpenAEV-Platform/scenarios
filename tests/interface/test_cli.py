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


def test_check_title_accepts_a_valid_title() -> None:
    result = CliRunner().invoke(main, ["check-title", "feat(api): add login endpoint (#42)"])

    assert result.exit_code == 0
    assert "valid" in result.output


def test_check_title_rejects_an_invalid_title_with_its_reason() -> None:
    result = CliRunner().invoke(main, ["check-title", "feat: add login endpoint"])

    assert result.exit_code == 1
    assert "issue reference" in result.output


def test_check_title_needs_a_title() -> None:
    result = CliRunner().invoke(main, ["check-title"])

    assert result.exit_code == 2
