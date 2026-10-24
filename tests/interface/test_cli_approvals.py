"""The ``approvals`` command: who approved the last change of every entry, for ``build``."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.interface.cli import main
from tests.support.interface import patch_interface

ROOT = Path(__file__).parents[2]
EASM = "scenarios/techniques/easm"
REPOSITORY = "OpenAEV-Platform/scenarios"
TOKEN = "test-token-0123456789"  # noqa: S105 - the tests' own, never a real one


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
        ["git", "-C", str(root), *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    for path in ("policy", "schemas", EASM):
        shutil.copytree(ROOT / path, root / path)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "start")  # fmt: skip
    return root, _git(root, "rev-parse", "HEAD")


def _pull(number: int, commit: str) -> dict[str, Any]:
    return {
        "number": number,
        "merge_commit_sha": commit,
        "merged_at": "2026-10-01T00:00:00Z",
        "head": {"sha": "c" * 40},
        "user": {"login": "author"},
        "base": {"ref": "main", "repo": {"full_name": REPOSITORY, "default_branch": "main"}},
    }


APPROVAL = {
    "user": {"login": "Alice", "type": "User"},
    "state": "APPROVED",
    "commit_id": "c" * 40,
    "author_association": "MEMBER",
}


def _run(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    out: Path,
    pulls: dict[str, Any] | None = None,
    reviews: dict[int, Any] | None = None,
    **env: str,
) -> tuple[Any, list[tuple[str, str]]]:
    made: list[tuple[str, str]] = []

    class GitHub:
        def __init__(self, token: str, repository: str) -> None:
            made.append((token, repository))

        def pulls_of(self, commit: str) -> Any:
            return (pulls or {})[commit]

        def reviews_of(self, number: int) -> Any:
            return (reviews or {})[number]

    patch_interface(monkeypatch, "HttpGitHub", GitHub)
    environment = {"GITHUB_TOKEN": TOKEN, **env}
    result = CliRunner(env=environment).invoke(
        main, ["--format", "json", "approvals", "--repo", str(root), "--out", str(out)]
    )
    return result, made


def test_the_approvals_of_every_entry_are_written_for_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, commit = _repository(tmp_path)
    out = tmp_path / "approvals.json"

    result, made = _run(monkeypatch, root, out, {commit: [_pull(123, commit)]}, {123: [APPROVAL]})

    assert result.exit_code == 0, result.output
    assert json.loads(out.read_bytes()) == {
        "schema_version": 1,
        "commit": commit,
        "entries": {EASM: {"pull_request": 123, "approvers": ["alice"]}},
    }
    assert made == [(TOKEN, REPOSITORY)]
    assert TOKEN not in result.output


def test_a_run_for_another_repository_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = _repository(tmp_path)
    out = tmp_path / "approvals.json"

    result, made = _run(monkeypatch, root, out, GITHUB_REPOSITORY="someone/fork")

    assert result.exit_code == 3, result.output
    assert "not of someone/fork" in result.output
    assert (made, out.exists()) == ([], False)


def test_without_a_token_nothing_is_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, _ = _repository(tmp_path)
    out = tmp_path / "approvals.json"

    result, made = _run(monkeypatch, root, out, GITHUB_TOKEN="")

    assert result.exit_code == 3, result.output
    assert "GITHUB_TOKEN" in result.output
    assert (made, out.exists()) == ([], False)


def test_an_entry_no_pull_request_changed_last_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, commit = _repository(tmp_path)
    out = tmp_path / "approvals.json"

    result, _ = _run(monkeypatch, root, out, {commit: []})

    assert result.exit_code == 3, result.output
    assert "by no pull request" in result.output
    assert not out.exists()


@pytest.mark.parametrize("place", ["inside", "taken", "missing"])
def test_the_output_is_a_new_file_outside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, place: str
) -> None:
    root, _ = _repository(tmp_path)
    out = {
        "inside": root / "approvals.json",
        "taken": tmp_path / "taken.json",
        "missing": tmp_path / "missing" / "approvals.json",
    }[place]
    if place == "taken":
        out.write_text("{}")

    result, _ = _run(monkeypatch, root, out)

    assert result.exit_code == 2, result.output


def test_more_approvers_than_a_release_lists_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, commit = _repository(tmp_path)
    reviews = [dict(APPROVAL, user={"login": f"user{n}", "type": "User"}) for n in range(11)]
    out = tmp_path / "approvals.json"

    result, _ = _run(monkeypatch, root, out, {commit: [_pull(123, commit)]}, {123: reviews})

    assert result.exit_code == 3, result.output
    assert "at most 10 approvers" in result.output
    assert not out.exists()
