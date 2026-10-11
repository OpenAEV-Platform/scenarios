"""The validate command: an entry checked as the data model says, from the repository that holds
it, whatever the working directory; its exit code says whether anything blocks it."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.adapters.safe_readers import parse_yaml, yaml_bytes
from scenario_tools.interface.cli import main

REPOSITORY = Path(__file__).parents[2]
EASM = REPOSITORY / "tests" / "golden" / "exports" / "easm-scenario.zip"
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"


def _repository(tmp_path: Path, name: str = "repository") -> Path:
    """A repository of its own, with the policy data and the schemas of this one."""
    root = tmp_path / name
    shutil.copytree(REPOSITORY / "policy" / "data", root / "policy" / "data")
    shutil.copytree(REPOSITORY / "schemas", root / "schemas")
    return root


def _invoke(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> Any:
    monkeypatch.chdir("/")  # the working directory plays no part
    return CliRunner().invoke(main, ["--format", "json", *arguments])


def _complete_entry(
    monkeypatch: pytest.MonkeyPatch, root: Path, relative: str = "scenarios/techniques/easm"
) -> Path:
    """An entry prepared from the EASM export, then completed as a contributor would."""
    entry = root / relative
    entry.mkdir(parents=True)
    prepared = _invoke(
        monkeypatch, "normalize", str(EASM), "--out", str(entry), "--external-id", ENTRY_ID
    )
    assert prepared.exit_code == 0, prepared.output
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["threat"] = {"ttps": ["T1595"]}
    metadata["sources"] = [
        {"url": "https://attack.mitre.org/techniques/T1595/", "tlp": "TLP:CLEAR"}
    ]
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    return entry


def _findings(result: Any) -> list[tuple[str, str, str]]:
    return [(f["code"], f["path"], f["field"]) for f in json.loads(result.stdout)["findings"]]


def test_a_completed_entry_validates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path))

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"command": "validate", "ok": True, "findings": []}


def test_what_blocks_an_entry_is_reported_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["description"] += chr(0x2026)
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    (entry / "README.md").write_text(f"# EASM {chr(0x202E)}\n", encoding="utf-8")
    other = _complete_entry(monkeypatch, root, "scenarios/techniques/easm-copy")
    (other / "scenario.json").unlink()

    result = _invoke(monkeypatch, "validate", str(entry), str(other))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [
        ("SCH-008", "scenarios/techniques/easm-copy/scenario.json", ""),
        ("SCH-010", "scenarios/techniques/easm-copy/scenario.yaml", "/external_id"),
        ("IO-017", "scenarios/techniques/easm/README.md", ""),
        ("SCH-009", "scenarios/techniques/easm/scenario.yaml", "/description"),
        ("SCH-010", "scenarios/techniques/easm/scenario.yaml", "/external_id"),
    ]


def test_a_directory_of_the_path_that_is_a_link_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    _complete_entry(monkeypatch, root, "elsewhere/techniques/easm")
    (root / "scenarios").symlink_to(root / "elsewhere")

    result = _invoke(monkeypatch, "validate", str(root / "scenarios" / "techniques" / "easm"))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("IO-013", "scenarios", "")]


def test_entries_of_two_repositories_are_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = _complete_entry(monkeypatch, _repository(tmp_path, "one"))
    second = _complete_entry(monkeypatch, _repository(tmp_path, "two"))

    result = _invoke(monkeypatch, "validate", str(first), str(second))

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "the entries belong to different repositories" in result.stderr


def test_an_entry_outside_any_repository_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _invoke(monkeypatch, "validate", str(tmp_path))

    assert result.exit_code == 3
    assert json.loads(result.stdout)["ok"] is False


@pytest.mark.parametrize("option", ["--previous-release", "--private-denylist"])
def test_the_options_of_later_checks_are_refused_until_they_come(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, option: str
) -> None:
    result = _invoke(monkeypatch, "validate", str(tmp_path), option, "x")

    assert result.exit_code == 2


def test_validate_needs_an_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _invoke(monkeypatch, "validate").exit_code == 2


def test_unusable_recorded_contracts_are_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    (root / "policy" / "data" / "builtin-contracts.yaml").write_text("contracts: {}\n")

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3
    assert "policy data cannot be used" in json.loads(result.stdout)["error"]


def test_a_directory_that_cannot_be_searched_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unsearchable(self: Path) -> bool:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "is_dir", unsearchable)

    result = _invoke(monkeypatch, "validate", str(tmp_path))

    assert result.exit_code == 3
    assert "cannot look for policy data above" in json.loads(result.stdout)["error"]


def test_a_stored_scenario_of_another_entry_is_not_what_normalisation_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path))
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["external_id"] = "0b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("GEN-002", "scenarios/techniques/easm/scenario.json", "")]


def test_an_entry_given_twice_is_checked_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path))
    (entry / "README.md").write_text(f"# EASM {chr(0x202E)}\n", encoding="utf-8")

    result = _invoke(monkeypatch, "validate", str(entry), str(entry / "."))

    assert _findings(result) == [("IO-017", "scenarios/techniques/easm/README.md", "")]


def test_the_help_says_which_checks_run_yet(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke(monkeypatch, "validate", "--help")

    assert "not run yet" in " ".join(result.output.split())
    assert "data model" not in result.output
