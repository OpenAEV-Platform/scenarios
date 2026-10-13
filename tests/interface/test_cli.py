"""The command-line entry point: version, help, output formats, exit codes and the title check."""

import json
import shutil
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from hypothesis import given
from hypothesis import strategies as st

import scenario_tools
import scenario_tools.interface.cli as cli_module
from scenario_tools.adapters.data_files import write_output
from scenario_tools.adapters.safe_readers import parse_yaml, read_json_file
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


def _entry(tmp_path: Path, name: str = "entry") -> Path:
    """An entry directory in a repository of its own, with the policy data of this one."""
    data = tmp_path / "repository" / "policy" / "data"
    if not data.exists():
        data.mkdir(parents=True)
        for policy in (
            "volatile-fields.yaml",
            "builtin-contracts.yaml",
            "allowed-targets.yaml",
            "forbidden-actions.yaml",
            "side-effects.yaml",
        ):
            shutil.copy(REPOSITORY / "policy" / "data" / policy, data)
    entry = tmp_path / "repository" / "scenarios" / name
    entry.mkdir(parents=True)
    return entry


def _normalize(
    monkeypatch: pytest.MonkeyPatch, out: Path, *options: str, export: Path = EASM
) -> Any:
    monkeypatch.chdir("/")  # the working directory plays no part
    return CliRunner().invoke(main, ["normalize", str(export), "--out", str(out), *options])


def test_normalize_refuses_an_export_carrying_documents_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    export = tmp_path / "export.zip"
    with zipfile.ZipFile(EASM) as source, zipfile.ZipFile(export, "w") as target:
        for info in source.infolist():
            target.writestr(info, source.read(info))
        document = zipfile.ZipInfo("report.pdf")
        document.comment = b"Attachment"  # as the platform writes a scenario's document
        target.writestr(document, b"%PDF-1.4")

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, export=export)

    assert result.exit_code == 1
    assert "IO-014" in result.output
    assert "documents are not supported yet" in result.output
    assert list(entry.iterdir()) == []


def test_normalize_writes_the_normalised_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)

    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines()[-1] == "normalize: ok"  # after what is left to complete
    document = json.loads((entry / "scenario.json").read_text(encoding="utf-8"))
    assert document["scenario_information"]["scenario_name"] == "EASM Scenario"
    assert sorted(path.name for path in entry.iterdir()) == ["scenario.json", "scenario.yaml"]


def test_a_first_preparation_also_writes_a_starting_scenario_yaml(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    options = ["--out", str(entry), "--external-id", ENTRY_ID]

    result = CliRunner().invoke(main, ["--format", "json", "normalize", str(EASM), *options])

    assert result.exit_code == 0, result.output  # what is left to complete is information
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    assert (metadata["external_id"], metadata["name"]) == (ENTRY_ID, "EASM Scenario")
    assert metadata["requires"]["injectors"] == ["openaev_nmap", "openaev_nuclei"]
    assert (entry / "scenario.yaml").stat().st_mode & 0o777 == 0o644
    findings = json.loads(result.stdout)["findings"]
    assert {(f["code"], f["severity"], f["path"]) for f in findings} == {
        ("SCH-007", "info", "scenarios/entry/scenario.yaml")
    }
    assert [f["field"] for f in findings] == [  # the defaults to review, what is missing
        "/description",
        "/requires/edition",
        "/requires/openaev",
        "/sources",
        "/status",
        "/threat",
        "/version",
    ]
    # The export's description ends a line with a blank: cleaned, it is written as a block.
    assert findings[0]["message"].endswith("1 line end trimmed; nothing to do")
    assert b"description: |" in (entry / "scenario.yaml").read_bytes()


def _edited_export(tmp_path: Path, change: Callable[[dict[str, Any]], None]) -> Path:
    """The reference EASM export, its scenario changed by ``change``."""
    export = tmp_path / "export.zip"
    with zipfile.ZipFile(EASM) as source, zipfile.ZipFile(export, "w") as target:
        for info in source.infolist():
            document = json.loads(source.read(info))
            change(document)
            target.writestr(info, json.dumps(document))
    return export


def test_an_export_with_a_hidden_character_is_refused_and_nothing_is_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    export = _edited_export(
        tmp_path,
        lambda d: d["scenario_injects"][0].update(inject_title=f"Scan{chr(0x2066)}"),
    )

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, export=export)

    assert result.exit_code == 1, result.output
    assert "IO-017" in result.stdout
    assert "U+2066" in result.stdout
    assert list(entry.iterdir()) == []


def test_an_export_whose_facts_cannot_be_read_is_refused_and_nothing_is_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    export = _edited_export(
        tmp_path, lambda d: d["scenario_information"].update(scenario_main_focus=None)
    )

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, export=export)

    assert result.exit_code == 1, result.output
    assert "IO-014" in result.stdout
    assert list(entry.iterdir()) == []


def test_hostile_texts_in_the_export_never_make_an_entry_the_tools_refuse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    long = {"scenario_description": "d" * 300_000, "scenario_category": "c" * 300_000}
    export = _edited_export(tmp_path, lambda d: d["scenario_information"].update(long))

    first = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, export=export)
    again = _normalize(monkeypatch, entry, export=export)

    assert (first.exit_code, again.exit_code) == (0, 0), first.output + again.output
    assert (entry / "scenario.yaml").stat().st_size < 4096


def test_an_existing_scenario_yaml_is_never_written_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # What a contributor completed stays, whatever the export now says.
    entry = _entry(tmp_path)
    completed = f"external_id: {ENTRY_ID}\nname: completed by hand\n".encode()
    (entry / "scenario.yaml").write_bytes(completed)

    result = _normalize(monkeypatch, entry)

    assert result.exit_code == 0, result.output
    assert (entry / "scenario.yaml").read_bytes() == completed
    assert "SCH-007" not in result.stdout


def test_an_entry_prepared_from_an_export_archives_as_it_is(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # An export archive, as the platform produces it, becomes an entry the tools accept.
    entry = _entry(tmp_path)
    _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)

    result = CliRunner().invoke(main, ["archive", str(entry), "--out", str(tmp_path / "e.zip")])

    assert result.exit_code == 0, result.output


def test_normalize_outside_a_repository_is_an_environment_problem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _normalize(monkeypatch, tmp_path, "--external-id", ENTRY_ID)

    assert result.exit_code == 3
    assert "policy/data" in result.stdout
    assert not (tmp_path / "scenario.json").exists()


def test_normalize_reads_the_external_id_of_an_existing_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry, reference = _entry(tmp_path), _entry(tmp_path, "reference")
    (entry / "scenario.yaml").write_text(f"external_id: {ENTRY_ID}\n", encoding="utf-8")
    _normalize(monkeypatch, reference, "--external-id", ENTRY_ID)

    result = _normalize(monkeypatch, entry)

    assert result.exit_code == 0, result.output
    assert (entry / "scenario.json").read_bytes() == (reference / "scenario.json").read_bytes()


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
    entry = _entry(tmp_path)
    if yaml_id is not None:
        (entry / "scenario.yaml").write_text(f"external_id: {yaml_id}\n", encoding="utf-8")

    result = _normalize(monkeypatch, entry, *(["--external-id", option] if option else []))

    assert result.exit_code == 2
    assert not (entry / "scenario.json").exists()


def test_a_contradicting_external_id_is_quoted_within_bounds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    (entry / "scenario.yaml").write_text(f"external_id: {'x' * 200_000}\n", encoding="utf-8")

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)

    assert result.exit_code == 2
    assert len(result.output) < 2 * MESSAGE_LIMIT + len(str(entry)) + 200


def test_normalize_reports_the_injects_removed_since_the_previous_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry, previous = _entry(tmp_path), _entry(tmp_path, "previous")
    _normalize(monkeypatch, previous, "--external-id", ENTRY_ID)
    document = json.loads((previous / "scenario.json").read_text(encoding="utf-8"))
    extra = dict(document["scenario_injects"][0], inject_id="00000000-0000-4000-8000-0000000000aa")
    document["scenario_injects"].append(extra)
    (previous / "scenario.json").write_text(json.dumps(document), encoding="utf-8")

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, "--previous", str(previous))
    options = ["--out", str(entry), "--previous", str(previous), "--external-id", ENTRY_ID]
    as_json = CliRunner().invoke(main, ["--format", "json", "normalize", str(EASM), *options])

    assert result.exit_code == 0, result.output
    assert "INFO VER-012" in result.stdout
    assert "00000000-0000-4000-8000-0000000000aa" in result.stdout
    findings = json.loads(as_json.stdout)["findings"]
    assert [(finding["code"], finding["path"]) for finding in findings] == [
        ("VER-012", "scenarios/entry/scenario.json")
    ]


def test_a_previous_version_without_its_file_is_an_environment_problem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry, previous = _entry(tmp_path), _entry(tmp_path, "previous")

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, "--previous", str(previous))

    assert result.exit_code == 3


def test_a_refused_previous_version_is_reported_on_its_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry, previous = _entry(tmp_path), _entry(tmp_path, "previous")
    (previous / "scenario.json").write_text("[]", encoding="utf-8")

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, "--previous", str(previous))

    assert result.exit_code == 1
    assert "IO-014 scenarios/previous/scenario.json" in result.stdout


def test_normalize_applies_a_mapping_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entry = _entry(tmp_path)
    mapping = tmp_path / "repository" / "map.yaml"
    mapping.write_text("- {source_inject_id: unknown, stable_id: x}\n", encoding="utf-8")

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, "--map", str(mapping))

    assert result.exit_code == 1
    assert "VER-011 map.yaml" in result.stdout


@pytest.mark.parametrize(
    "content",
    ["not a list", "- [a, b]", "- {source_inject_id: a}"],
    ids=["not a list", "not objects", "missing stable id"],
)
def test_a_malformed_mapping_file_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str
) -> None:
    entry = _entry(tmp_path)
    mapping = tmp_path / "map.yaml"
    mapping.write_text(content + "\n", encoding="utf-8")

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID, "--map", str(mapping))

    assert result.exit_code == 1
    assert "VER-011" in result.stdout


def test_a_linked_scenario_yaml_is_refused_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    (tmp_path / "elsewhere.yaml").write_text(f"external_id: {ENTRY_ID}\n", encoding="utf-8")
    (entry / "scenario.yaml").symlink_to(tmp_path / "elsewhere.yaml")

    result = _normalize(monkeypatch, entry)

    assert result.exit_code == 1
    assert "IO-013" in result.stdout
    assert not (entry / "scenario.json").exists()


def test_an_unreadable_scenario_yaml_is_an_environment_problem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    metadata = entry / "scenario.yaml"
    metadata.write_text(f"external_id: {ENTRY_ID}\n", encoding="utf-8")
    metadata.chmod(0)
    try:
        result = _normalize(monkeypatch, entry)
    finally:
        metadata.chmod(0o644)

    assert result.exit_code == 3
    assert "Traceback" not in result.output


def test_a_defect_while_reading_the_entry_exits_with_4(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    (entry / "scenario.yaml").write_text(f"external_id: {ENTRY_ID}\n", encoding="utf-8")

    def broken(path: Path) -> Any:
        raise RuntimeError("defect")

    monkeypatch.setattr(cli_module, "read_yaml_file", broken)
    result = _normalize(monkeypatch, entry)

    assert result.exit_code == 4
    assert "internal error: RuntimeError: defect" in result.stderr


@pytest.mark.parametrize("where", ["entry", "scenarios"])
def test_policy_data_below_the_repository_root_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, where: str
) -> None:
    entry = _entry(tmp_path)
    rogue = (entry if where == "entry" else entry.parent) / "policy" / "data"
    rogue.mkdir(parents=True)
    (rogue / "volatile-fields.yaml").write_text(
        "removed: []\nremoved_suffixes: []\nsorted: []\nemptied_in_builtin_contracts: []\n",
        encoding="utf-8",
    )

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)

    assert result.exit_code == 1
    assert "IO-015" in result.stdout
    assert not (entry / "scenario.json").exists()


def test_refusals_are_reported_from_the_repository_root_whatever_the_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry, previous = _entry(tmp_path), _entry(tmp_path, "previous")
    (previous / "scenario.json").write_text("[]", encoding="utf-8")
    monkeypatch.chdir(entry.parent)

    result = CliRunner().invoke(
        main,
        ["normalize", str(EASM), "--out", "entry", "--previous", "previous",
         "--external-id", ENTRY_ID],
    )  # fmt: skip

    assert result.exit_code == 1
    assert "IO-014 scenarios/previous/scenario.json" in result.stdout


def test_an_invalid_external_id_in_scenario_yaml_is_named_as_such(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    (entry / "scenario.yaml").write_text("external_id: not-a-uuid\n", encoding="utf-8")

    result = _normalize(monkeypatch, entry)

    assert result.exit_code == 2
    assert "scenario.yaml" in result.output


def test_a_stored_entry_normalised_with_itself_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)
    stored = (entry / "scenario.json").read_bytes()
    copy_of_stored = tmp_path / "stored.json"
    copy_of_stored.write_bytes(stored)

    result = _normalize(
        monkeypatch,
        entry,
        "--external-id",
        ENTRY_ID,
        "--previous",
        str(entry),
        export=copy_of_stored,
    )

    assert result.exit_code == 0, result.output
    assert (entry / "scenario.json").read_bytes() == stored


def test_a_refused_export_given_by_a_relative_path_is_reported_from_the_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    (entry / "bad.json").write_text("[]", encoding="utf-8")
    monkeypatch.chdir(entry)

    result = CliRunner().invoke(
        main, ["normalize", "bad.json", "--out", ".", "--external-id", ENTRY_ID]
    )

    assert result.exit_code == 1
    assert "IO-014 scenarios/entry/bad.json" in result.stdout


def test_a_scenario_yaml_that_appears_meanwhile_leaves_the_entry_as_it_was(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The starting file is written first: if it cannot be, scenario.json is not replaced.
    entry = _entry(tmp_path)

    def appears_first(path: Path, data: bytes, *, create: bool = False) -> None:
        if create:
            path.write_bytes(b"completed: meanwhile\n")
        write_output(path, data, create=create)

    monkeypatch.setattr(cli_module, "write_output", appears_first)

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)

    assert result.exit_code == 3
    assert (entry / "scenario.yaml").read_bytes() == b"completed: meanwhile\n"
    assert not (entry / "scenario.json").exists()


def test_a_scenario_yaml_that_appears_after_the_external_id_was_chosen_stops_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The run decided on a first preparation: a file that appears later is never trusted nor
    # replaced, and no scenario.json is written for an identifier it may contradict.
    entry = _entry(tmp_path)
    choose = cli_module._entry_external_id

    def then_appears(out: Path, given: str | None) -> str:
        chosen = choose(out, given)
        (out / "scenario.yaml").write_text("external_id: 00000000-0000-4000-8000-000000000009\n")
        return chosen

    monkeypatch.setattr(cli_module, "_entry_external_id", then_appears)

    result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)

    assert result.exit_code == 3, result.output
    assert not (entry / "scenario.json").exists()


def test_an_entry_that_cannot_be_searched_is_an_environment_problem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _entry(tmp_path)
    entry.chmod(0o600)  # no search permission: whether scenario.yaml exists cannot be known
    try:
        result = _normalize(monkeypatch, entry, "--external-id", ENTRY_ID)
    finally:
        entry.chmod(0o755)

    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output
