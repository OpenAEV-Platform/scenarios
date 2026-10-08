"""The command-line entry point: version, help, output formats, exit codes and the title check."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

import scenario_tools
from scenario_tools.domain.shared.finding import Finding, Report, Severity
from scenario_tools.interface.cli import execute, main
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError


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
    assert result.output.strip() == "check-title: ok"


def test_check_title_reports_an_invalid_title_as_a_blocking_finding() -> None:
    result = CliRunner().invoke(main, ["check-title", "feat: add login endpoint"])

    assert result.exit_code == 1
    assert (
        "BLOCKING TTL-001: the title must end with a space and an issue reference" in result.output
    )
    assert result.output.strip().endswith("check-title: 1 blocking finding")


def test_check_title_needs_a_title() -> None:
    result = CliRunner().invoke(main, ["check-title"])

    assert result.exit_code == 2


@pytest.mark.parametrize("title", ["--help", "--version", "-h"])
def test_check_title_treats_an_option_like_title_as_a_title(title: str) -> None:
    result = CliRunner().invoke(main, ["check-title", "--", title])

    assert result.exit_code == 1
    assert "TTL-001" in result.output


def test_json_output_follows_the_contract() -> None:
    valid = CliRunner().invoke(main, ["--format", "json", "check-title", "fix: a (#1)"])
    invalid = CliRunner().invoke(main, ["--format", "json", "check-title", "fix: a"])

    assert (valid.exit_code, json.loads(valid.output)) == (
        0,
        {"command": "check-title", "ok": True, "findings": []},
    )
    document = json.loads(invalid.output)
    assert invalid.exit_code == 1
    assert document["ok"] is False
    assert document["findings"] == [
        {
            "code": "TTL-001",
            "severity": "blocking",
            "path": "",
            "field": "",
            "message": document["findings"][0]["message"],
        }
    ]


def test_an_unknown_format_is_a_usage_error() -> None:
    assert (
        CliRunner().invoke(main, ["--format", "xml", "check-title", "fix: a (#1)"]).exit_code == 2
    )


# The command runner every command goes through


def _report(*findings: Finding) -> Callable[[], Report]:
    return lambda: Report("demo", findings)


def test_a_report_with_only_info_findings_exits_zero() -> None:
    info = Finding("SCH-001", Severity.INFO, "a.yaml", "/name", "a remark")

    output, code = execute("demo", _report(info), "text")

    assert code == 0
    assert output.splitlines() == ["INFO SCH-001 a.yaml /name: a remark", "demo: ok"]


def test_an_unsafe_input_becomes_an_io_finding_and_exits_one() -> None:
    def produce() -> Report:
        raise UnsafeInputError("IO-001", "larger than 10 bytes", "scenarios/x/scenario.json")

    output, code = execute("demo", produce, "json")

    assert code == 1
    assert json.loads(output)["findings"][0]["code"] == "IO-001"


def test_an_unsafe_input_read_by_absolute_path_is_reported_not_raised(tmp_path: Path) -> None:
    def produce() -> Report:
        raise UnsafeInputError("IO-001", "larger than 10 bytes", str(tmp_path / "a" / "b.json"))

    output, code = execute("demo", produce, "json", root=tmp_path)

    assert code == 1
    assert json.loads(output)["findings"][0]["path"] == "a/b.json"


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_an_environment_problem_exits_three_and_is_never_a_finding(output_format: str) -> None:
    def produce() -> Report:
        raise EnvironmentProblemError("the test tenant is unreachable")

    output, code = execute("demo", produce, output_format)

    assert code == 3
    if output_format == "json":
        assert json.loads(output) == {
            "command": "demo",
            "ok": False,
            "findings": [],
            "error": "the test tenant is unreachable",
        }
    else:
        assert output == "demo: environment error: the test tenant is unreachable"
