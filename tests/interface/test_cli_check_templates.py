"""The check-templates command: each Nuclei template an entry fetches is on its repository's
default branch, as GitHub says, asked with the workflow's token."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.interface.cli import main
from tests.domain.policy.cases import COMMIT, PINNED
from tests.support.interface import patch_interface

ROOT = Path(__file__).parents[2]
TOKEN = "test-token-0123456789"  # noqa: S105 - the tests' own, never a real one
UPSTREAM = "projectdiscovery/nuclei-templates"
FORK = "90fa27fa51fcdc84cffb635016a31b79f8949406"
ENTRY = "scenarios/vulnerabilities/x"


def _repository(tmp_path: Path, *links: str) -> Path:
    root = tmp_path / "repository"
    shutil.copytree(ROOT / "policy" / "data", root / "policy" / "data")
    shutil.copytree(ROOT / "schemas", root / "schemas")
    entry = root / ENTRY
    entry.mkdir(parents=True)
    stored = {"scenario_injects": [{"inject_content": {"template_url": link}} for link in links]}
    (entry / "scenario.json").write_text(json.dumps(stored), encoding="utf-8")
    return root


def _run(
    monkeypatch: pytest.MonkeyPatch, root: Path, statuses: dict[str, str | None], **env: str
) -> tuple[Any, list[tuple[str, ...]]]:
    asked: list[tuple[str, ...]] = []

    class GitHub:
        def __init__(self, token: str, repository: str) -> None:
            asked.append(("made", token, repository))
            self._repository = repository

        def default_branch(self) -> str:
            asked.append(("branch", self._repository))
            return "main"

        def compared(self, branch: str, commit: str) -> str | None:
            asked.append(("compare", self._repository, branch, commit))
            return statuses[commit]

    patch_interface(monkeypatch, "HttpGitHub", GitHub)
    monkeypatch.chdir("/")  # the working directory plays no part
    result = CliRunner(env={"GITHUB_TOKEN": TOKEN, **env}).invoke(
        main, ["--format", "json", "check-templates", str(root / ENTRY)]
    )
    return result, asked


def test_a_template_on_the_default_branch_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, asked = _run(monkeypatch, _repository(tmp_path, PINNED), {COMMIT: "behind"})

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"command": "check-templates", "ok": True, "findings": []}
    assert asked == [
        ("made", TOKEN, UPSTREAM),
        ("branch", UPSTREAM),
        ("compare", UPSTREAM, "main", COMMIT),
    ]


def test_a_template_of_a_fork_blocks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _repository(tmp_path, PINNED.replace(COMMIT, FORK))

    result, _ = _run(monkeypatch, root, {FORK: "diverged"})

    assert result.exit_code == 1, result.output
    [finding] = json.loads(result.output)["findings"]
    assert (finding["code"], finding["path"], finding["field"]) == (
        "POL-012",
        f"{ENTRY}/scenario.json",
        "/scenario_injects/0/inject_content/template_url",
    )
    assert FORK not in finding["message"]  # the link is never quoted


def test_without_a_token_github_is_never_asked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result, asked = _run(monkeypatch, _repository(tmp_path, PINNED), {}, GITHUB_TOKEN="")

    assert result.exit_code == 3, result.output
    assert "GITHUB_TOKEN is not set" in json.loads(result.output)["error"]
    assert asked == []


def test_an_entry_without_a_readable_scenario_is_left_to_validate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path, PINNED)
    (root / ENTRY / "scenario.json").write_text("{not json", encoding="utf-8")

    result, asked = _run(monkeypatch, root, {})

    assert result.exit_code == 0, result.output
    assert asked == []


def test_an_entry_without_a_scenario_is_left_to_validate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path, PINNED)
    (root / ENTRY / "scenario.json").unlink()

    result, asked = _run(monkeypatch, root, {})

    assert result.exit_code == 0, result.output
    assert asked == []
