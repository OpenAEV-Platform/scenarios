"""The commit a checkout is at, which a plan names as its base."""

import subprocess
from pathlib import Path

import pytest

from scenario_tools.adapters.git import head_commit
from scenario_tools.ports.errors import EnvironmentProblemError


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
        ["git", "-C", str(root), *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_the_commit_of_a_checkout_is_read(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "file").write_text("x")
    _git(tmp_path, "add", "file")
    _git(
        tmp_path,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.org",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "one",
    )

    assert head_commit(tmp_path) == _git(tmp_path, "rev-parse", "HEAD")


@pytest.mark.parametrize("init", [False, True], ids=["not a repository", "no commit yet"])
def test_a_checkout_without_a_commit_is_the_environment_s_fault(tmp_path: Path, init: bool) -> None:
    if init:
        _git(tmp_path, "init", "-q")

    with pytest.raises(EnvironmentProblemError, match="commit"):
        head_commit(tmp_path)


def test_a_missing_git_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)

    with pytest.raises(EnvironmentProblemError, match="not installed"):
        head_commit(tmp_path)


def test_a_git_that_does_not_answer_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def hanging(*arguments: object, **options: object) -> object:
        raise subprocess.TimeoutExpired("git", 30)

    monkeypatch.setattr("subprocess.run", hanging)

    with pytest.raises(EnvironmentProblemError, match="cannot read the commit"):
        head_commit(tmp_path)


def test_a_directory_inside_another_checkout_is_not_a_checkout(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "file").write_text("x")
    _git(tmp_path, "add", "file")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "one")  # fmt: skip
    inner = tmp_path / "inner"
    inner.mkdir()

    with pytest.raises(EnvironmentProblemError, match="not the top of a checkout"):
        head_commit(inner)


def test_the_environment_cannot_point_git_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q")
    (other / "file").write_text("x")
    _git(other, "add", "file")
    _git(other, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "one")  # fmt: skip
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    plain = tmp_path / "plain"
    plain.mkdir()

    with pytest.raises(EnvironmentProblemError):
        head_commit(plain)
