"""The command-line entry point: version, help and the title check."""

import pytest
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


@pytest.mark.parametrize("title", ["--help", "--version", "-h"])
def test_check_title_treats_an_option_like_title_as_a_title(title: str) -> None:
    result = CliRunner().invoke(main, ["check-title", "--", title])

    assert result.exit_code == 1
    assert "Invalid pull request title" in result.output
