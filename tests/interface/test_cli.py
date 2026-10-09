"""The command-line entry point: version, help, output formats, exit codes and the title check."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from hypothesis import given
from hypothesis import strategies as st

import scenario_tools
import scenario_tools.interface.cli as cli_module
from scenario_tools.adapters.safe_readers import read_json_file
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Finding, Report, Severity
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


@pytest.mark.parametrize(
    "args",
    [
        ["--format", "json", "check-title"],
        ["--format", "json", "unknown-command"],
        ["--format", "xml", "check-title", "fix: a (#1)"],
    ],
)
def test_a_usage_error_writes_nothing_to_stdout(args: list[str]) -> None:
    result = CliRunner().invoke(main, args)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Error:" in result.stderr


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


# Paths and messages carry contributor content: the output never echoes it raw

_HOSTILE = Finding(
    "IO-002",
    Severity.BLOCKING,
    "bad\udcff.yaml\n::error::injected",
    "/caf\u00e9\u2028",
    "not valid \x1b[31m\r\n::add-mask::secret",
)


def test_json_output_is_ascii_and_keeps_every_value() -> None:
    output, code = execute("demo", _report(_HOSTILE), "json")

    assert code == 1
    assert output.isascii()
    finding = json.loads(output)["findings"][0]
    assert (finding["path"], finding["field"], finding["message"]) == (
        _HOSTILE.path,
        _HOSTILE.field,
        _HOSTILE.message,
    )


def test_text_output_escapes_non_printable_characters_and_keeps_one_line_per_finding() -> None:
    output, _ = execute("demo", _report(_HOSTILE), "text")

    assert output.splitlines() == [
        "BLOCKING IO-002 bad\\udcff.yaml\\n::error::injected /caf\u00e9\\u2028: "
        "not valid \\x1b[31m\\r\\n::add-mask::secret",
        "demo: 1 blocking finding",
    ]
    output.encode("utf-8")


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_an_environment_error_is_rendered_safely(output_format: str) -> None:
    def produce() -> Report:
        raise EnvironmentProblemError("cannot reach bad\udcff\n::error::injected")

    output, code = execute("demo", produce, output_format)

    assert code == 3
    output.encode("utf-8")
    assert len(output.splitlines()) == 1
    if output_format == "json":
        assert json.loads(output)["error"] == "cannot reach bad\udcff\n::error::injected"
    else:
        assert output == "demo: environment error: cannot reach bad\\udcff\\n::error::injected"


@given(st.text(min_size=1))
def test_any_message_is_rendered_on_one_line_and_encodes_as_utf8(message: str) -> None:
    finding = Finding("IO-002", Severity.BLOCKING, "a.yaml", "", message)

    text, _ = execute("demo", _report(finding), "text")
    document, _ = execute("demo", _report(finding), "json")

    assert len(text.splitlines()) == 2
    text.encode("utf-8")
    assert document.isascii()
    assert json.loads(document)["findings"][0]["message"] == message


# Defects of the tool and unreadable files never read as a content defect


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_an_unexpected_error_exits_four_with_one_escaped_line_on_stderr(
    monkeypatch: pytest.MonkeyPatch, output_format: str
) -> None:
    def broken(title: str) -> Report:
        raise RuntimeError("boom\n::error::injected")

    monkeypatch.setattr(cli_module, "check_title_use_case", broken)

    result = CliRunner().invoke(main, ["--format", output_format, "check-title", "fix: a (#1)"])

    assert result.exit_code == 4
    assert result.stdout == ""
    assert result.stderr.splitlines() == [
        "check-title: internal error: RuntimeError: boom\\n::error::injected"
    ]


def test_a_file_that_cannot_be_read_is_an_environment_problem(tmp_path: Path) -> None:
    output, code = execute("demo", lambda: read_json_file(tmp_path / "missing"), "text")

    assert code == 3
    assert output.startswith("demo: environment error: ")


def test_a_long_internal_error_is_shortened(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(title: str) -> Report:
        raise RuntimeError("x" * 100_000)

    monkeypatch.setattr(cli_module, "check_title_use_case", broken)

    result = CliRunner().invoke(main, ["check-title", "fix: a (#1)"])

    assert result.exit_code == 4
    assert len(result.stderr.strip()) <= MESSAGE_LIMIT


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_a_failure_while_rendering_exits_four(
    monkeypatch: pytest.MonkeyPatch, output_format: str
) -> None:
    def broken(*args: object) -> object:
        raise RuntimeError("rendering failed")

    monkeypatch.setattr(cli_module, "_text", broken)
    monkeypatch.setattr(Report, "document", broken)

    output, code = execute("demo", _report(), output_format)

    assert code == 4
    assert output == "demo: internal error: RuntimeError: rendering failed"


def test_a_failure_while_converting_a_refusal_exits_four(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused() -> Report:
        raise UnsafeInputError("IO-001", "too large", "a.json")

    def broken(*args: object) -> object:
        raise RuntimeError("conversion failed")

    monkeypatch.setattr(cli_module, "finding_from_unsafe_input", broken)

    output, code = execute("demo", refused, "json")

    assert (output, code) == ("demo: internal error: RuntimeError: conversion failed", 4)


def test_an_error_that_cannot_be_printed_still_exits_four() -> None:
    class UnprintableError(Exception):
        def __str__(self) -> str:
            raise ValueError("no text")

    def produce() -> Report:
        raise UnprintableError

    output, code = execute("demo", produce, "text")

    assert (output, code) == ("demo: internal error: UnprintableError: <unprintable>", 4)


# The normalize command

REPOSITORY = Path(__file__).parents[2]
EASM = REPOSITORY / "tests" / "golden" / "exports" / "easm-scenario.zip"
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"


def _normalize(
    monkeypatch: pytest.MonkeyPatch, out: Path, *options: str, export: Path = EASM
) -> Any:
    monkeypatch.chdir(REPOSITORY)  # the policy data is read from the repository
    return CliRunner().invoke(main, ["normalize", str(export), "--out", str(out), *options])


def test_normalize_writes_the_normalised_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _normalize(monkeypatch, tmp_path, "--external-id", ENTRY_ID)

    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() == ["normalize: ok"]
    document = json.loads((tmp_path / "scenario.json").read_text(encoding="utf-8"))
    assert document["scenario_information"]["scenario_name"] == "EASM Scenario"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["scenario.json"]


def test_normalize_twice_gives_the_same_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()

    _normalize(monkeypatch, first, "--external-id", ENTRY_ID)
    _normalize(monkeypatch, second, "--external-id", ENTRY_ID)

    assert (first / "scenario.json").read_bytes() == (second / "scenario.json").read_bytes()


def test_normalize_reads_the_external_id_of_an_existing_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "scenario.yaml").write_text(f"external_id: {ENTRY_ID}\n", encoding="utf-8")
    reference = tmp_path / "reference"
    reference.mkdir()
    _normalize(monkeypatch, reference, "--external-id", ENTRY_ID)

    result = _normalize(monkeypatch, tmp_path)

    assert result.exit_code == 0, result.output
    assert (tmp_path / "scenario.json").read_bytes() == (reference / "scenario.json").read_bytes()


@pytest.mark.parametrize(
    ("yaml_id", "option"),
    [
        (None, None),
        (ENTRY_ID, "00000000-0000-4000-8000-000000000001"),
        (None, "5B9A2C84-3A0E-4C55-9A8C-2A6F0D7E1B42"),
        (None, "not-a-uuid"),
    ],
    ids=["no external id", "contradicts scenario.yaml", "not canonical", "not a uuid"],
)
def test_normalize_without_a_usable_external_id_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, yaml_id: str | None, option: str | None
) -> None:
    if yaml_id is not None:
        (tmp_path / "scenario.yaml").write_text(f"external_id: {yaml_id}\n", encoding="utf-8")

    result = _normalize(monkeypatch, tmp_path, *(["--external-id", option] if option else []))

    assert result.exit_code == 2
    assert not (tmp_path / "scenario.json").exists()


def test_normalize_reports_the_injects_removed_since_the_previous_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    previous = tmp_path / "previous"
    previous.mkdir()
    _normalize(monkeypatch, previous, "--external-id", ENTRY_ID)
    document = json.loads((previous / "scenario.json").read_text(encoding="utf-8"))
    extra = dict(document["scenario_injects"][0], inject_id="00000000-0000-4000-8000-0000000000aa")
    document["scenario_injects"].append(extra)
    (previous / "scenario.json").write_text(json.dumps(document), encoding="utf-8")

    result = _normalize(
        monkeypatch, tmp_path, "--external-id", ENTRY_ID, "--previous", str(previous)
    )

    assert result.exit_code == 0, result.output
    assert "INFO VER-012" in result.stdout
    assert "00000000-0000-4000-8000-0000000000aa" in result.stdout


def test_normalize_applies_a_mapping_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mapping = tmp_path / "map.yaml"
    mapping.write_text("- {source_inject_id: unknown, stable_id: x}\n", encoding="utf-8")

    result = _normalize(monkeypatch, tmp_path, "--external-id", ENTRY_ID, "--map", str(mapping))

    assert result.exit_code == 1
    assert "VER-011" in result.stdout


@pytest.mark.parametrize(
    "content",
    ["not a list", "- [a, b]", "- {source_inject_id: a}"],
    ids=["not a list", "not objects", "missing stable id"],
)
def test_a_malformed_mapping_file_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str
) -> None:
    mapping = tmp_path / "map.yaml"
    mapping.write_text(content + "\n", encoding="utf-8")

    result = _normalize(monkeypatch, tmp_path, "--external-id", ENTRY_ID, "--map", str(mapping))

    assert result.exit_code == 1
    assert "VER-011" in result.stdout


def test_an_unreadable_scenario_yaml_is_refused_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "elsewhere.yaml").write_text(f"external_id: {ENTRY_ID}\n", encoding="utf-8")
    (tmp_path / "scenario.yaml").symlink_to(tmp_path / "elsewhere.yaml")

    result = _normalize(monkeypatch, tmp_path)

    assert result.exit_code == 1
    assert "IO-013" in result.stdout
    assert not (tmp_path / "scenario.json").exists()
