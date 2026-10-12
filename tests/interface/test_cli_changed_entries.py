"""`changed-entries`: the entries a pull request adds or changes, for the stage 1 workflow."""

import subprocess
from pathlib import Path

from click.testing import CliRunner

from scenario_tools.interface.cli import main


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
        ["git", "-C", str(root), *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(root: Path) -> str:
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "next")  # fmt: skip
    return _git(root, "rev-parse", "HEAD")


def test_the_changed_entries_are_printed_each_followed_by_a_nul_byte(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "README.md").write_text("x")
    base = _commit(tmp_path)
    for entry in ("scenarios/techniques/easm", "scenarios/ransomware/new\nline"):
        (tmp_path / entry).mkdir(parents=True)
        (tmp_path / entry / "scenario.yaml").write_text("x")
    _commit(tmp_path)

    result = CliRunner().invoke(main, ["changed-entries", str(tmp_path), "--base", base])

    assert result.exit_code == 0, result.output
    assert result.stdout == "scenarios/ransomware/new\nline\0scenarios/techniques/easm\0"


def test_no_changed_entry_prints_nothing(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "README.md").write_text("x")
    base = _commit(tmp_path)

    result = CliRunner().invoke(main, ["changed-entries", str(tmp_path), "--base", base])

    assert (result.exit_code, result.stdout) == (0, "")


def test_a_base_that_is_not_a_commit_is_the_environment_s_fault(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")

    result = CliRunner().invoke(main, ["changed-entries", str(tmp_path), "--base", "--output=x"])

    assert result.exit_code == 3
    assert result.stdout == ""
    assert "not a commit" in result.stderr
