"""The diff command: what changed in each entry since the base branch's copy, for the reviewer."""

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from scenario_tools.adapters.safe_readers import parse_yaml, yaml_bytes
from scenario_tools.interface.cli import main
from tests.interface.test_cli_validate import _complete_entry, _invoke, _repository

EASM = "scenarios/techniques/easm"


def _changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """An entry, its base copy kept, then its description changed."""
    entry = _complete_entry(monkeypatch, _repository(tmp_path / "pull"))
    base = tmp_path / "base"
    shutil.copytree(entry, base / EASM)
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["description"] = "Another description"
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    return entry, base


def test_the_diff_lists_each_change_and_the_least_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry, base = _changed(tmp_path, monkeypatch)

    result = _invoke(monkeypatch, "diff", "--previous-root", str(base), "--", str(entry))

    assert result.exit_code == 0, result.output  # informative: validate judges the version
    report = json.loads(result.stdout)
    assert (report["command"], report["ok"]) == ("diff", True)
    assert [(f["code"], f["path"], f["field"]) for f in report["findings"]] == [
        ("VER-014", EASM, ""),
        ("VER-013", f"{EASM}/scenario.yaml", "/description"),
    ]
    assert report["findings"][1]["message"] == "its description changed: needs a patch version"
    assert report["findings"][0]["message"].endswith("the entry gives 1.0.0: too low")


def test_the_diff_reads_as_text_for_the_reviewer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry, base = _changed(tmp_path, monkeypatch)
    monkeypatch.chdir("/")

    result = CliRunner().invoke(main, ["diff", "--previous-root", str(base), "--", str(entry)])

    assert result.exit_code == 0, result.output
    assert f"VER-013 {EASM}/scenario.yaml /description: its description changed" in result.stdout


def test_an_entry_the_base_branch_does_not_hold_is_new(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path / "pull"))
    (tmp_path / "base").mkdir()

    result = _invoke(monkeypatch, "diff", "--previous-root", str(tmp_path / "base"), str(entry))

    assert result.exit_code == 0, result.output
    [finding] = json.loads(result.stdout)["findings"]
    assert finding["message"].startswith("a new entry")


def test_the_previous_root_is_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path / "pull"))

    result = _invoke(monkeypatch, "diff", str(entry))

    assert result.exit_code == 2
    assert "--previous-root" in result.output


def test_entries_of_two_repositories_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = _complete_entry(monkeypatch, _repository(tmp_path / "one"))
    second = _complete_entry(monkeypatch, _repository(tmp_path / "two"))
    (tmp_path / "base").mkdir()

    result = _invoke(
        monkeypatch, "diff", "--previous-root", str(tmp_path / "base"), str(first), str(second)
    )

    assert result.exit_code == 2
    assert "different repositories" in result.output


def test_an_entry_outside_any_repository_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "loose").mkdir()
    (tmp_path / "base").mkdir()

    result = _invoke(
        monkeypatch, "diff", "--previous-root", str(tmp_path / "base"), str(tmp_path / "loose")
    )

    assert result.exit_code != 0
    assert json.loads(result.stdout)["command"] == "diff"
