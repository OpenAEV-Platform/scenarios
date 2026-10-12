"""The commit a checkout is at, which a plan names as its base."""

import subprocess
from pathlib import Path

import pytest

from scenario_tools.adapters import git as git_module
from scenario_tools.adapters.git import converted, head_commit, uncommitted
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

    with pytest.raises(EnvironmentProblemError, match="git did not answer"):
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


def test_a_git_found_inside_the_checkout_is_never_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = tmp_path / "bin" / "git"
    planted.parent.mkdir()
    planted.write_text(f"#!/bin/sh\ntouch {tmp_path / 'ran'}\n")  # wherever it is run from
    planted.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda name: str(planted))

    with pytest.raises(EnvironmentProblemError, match="inside the repository"):
        head_commit(tmp_path)
    assert not (tmp_path / "ran").exists()


def test_what_git_prints_that_is_not_utf_8_is_read_all_the_same(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def printing(*arguments: object, **options: object) -> object:
        assert options.get("errors") == "replace"
        return subprocess.CompletedProcess("git", 0, stdout="caf\ufffd\n", stderr="")

    monkeypatch.setattr("subprocess.run", printing)

    with pytest.raises(EnvironmentProblemError, match="not the top of a checkout"):
        head_commit(tmp_path)


def test_a_top_that_cannot_be_looked_at_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def printing(*arguments: object, **options: object) -> object:
        return subprocess.CompletedProcess("git", 0, stdout=f"{tmp_path}/gone\n", stderr="")

    monkeypatch.setattr("subprocess.run", printing)

    with pytest.raises(EnvironmentProblemError, match="not the top of a checkout"):
        head_commit(tmp_path)


def _committed(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    for path in ("scenarios/a/b/scenario.json", "policy/data/x.yaml", "README.md"):
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text("x")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "one")  # fmt: skip
    return root


def test_a_clean_checkout_has_no_change(tmp_path: Path) -> None:
    root = _committed(tmp_path)

    assert uncommitted(root, ("scenarios", "policy", "schemas")) == ()


def test_changes_under_the_paths_given_are_told_untracked_ones_included(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    (root / "scenarios/a/b/scenario.json").write_text("changed")
    (root / "policy/data/new.yaml").write_text("new")
    (root / "README.md").write_text("elsewhere: not asked for")
    (root / "export.zip").write_text("elsewhere too")

    found = uncommitted(root, ("scenarios", "policy", "schemas"))

    assert found == ("policy/data/new.yaml", "scenarios/a/b/scenario.json")


def test_changes_that_cannot_be_read_are_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError, match="cannot read the changes"):
        uncommitted(tmp_path, ("scenarios",))  # no checkout here


def test_a_file_moved_is_told_by_both_its_paths(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    _git(root, "mv", "scenarios/a/b/scenario.json", "scenarios/a/b/moved.json")

    assert uncommitted(root, ("scenarios",)) == (
        "scenarios/a/b/moved.json",
        "scenarios/a/b/scenario.json",
    )


def test_ignored_and_hidden_changes_are_told_too(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    (root / ".git" / "info" / "exclude").write_text("scenarios/ignored/\n")
    (root / "scenarios" / "ignored").mkdir()
    (root / "scenarios" / "ignored" / "scenario.yaml").write_text("x")
    (root / "policy/data/x.yaml").write_text("changed, but hidden from status")
    _git(root, "update-index", "--assume-unchanged", "policy/data/x.yaml")

    found = uncommitted(root, ("scenarios", "policy"))

    assert found == ("policy/data/x.yaml", "scenarios/ignored/scenario.yaml")


def test_skipped_files_are_told(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    _git(root, "update-index", "--skip-worktree", "scenarios/a/b/scenario.json")

    assert uncommitted(root, ("scenarios",)) == ("scenarios/a/b/scenario.json",)


def test_a_monitor_the_checkout_configures_is_never_run(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {tmp_path / 'ran'}\n")
    hook.chmod(0o755)
    _git(root, "config", "core.fsmonitor", str(hook))

    uncommitted(root, ("scenarios",))

    assert not (tmp_path / "ran").exists()


def test_a_git_that_does_not_answer_says_so_without_its_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def hanging(*arguments: object, **options: object) -> object:
        raise subprocess.TimeoutExpired(["/somewhere/git", "status"], 30)

    monkeypatch.setattr("subprocess.run", hanging)

    with pytest.raises(EnvironmentProblemError) as error:
        uncommitted(tmp_path, ("scenarios",))
    assert "/somewhere" not in str(error.value)
    assert "git did not answer" in str(error.value)


def test_a_git_that_cannot_be_run_is_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unrunnable(*arguments: object, **options: object) -> object:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("subprocess.run", unrunnable)

    with pytest.raises(
        EnvironmentProblemError, match="cannot read the checkout: Permission denied"
    ):
        head_commit(tmp_path)


def test_a_submodule_told_to_be_ignored_is_told_all_the_same(tmp_path: Path) -> None:
    inner = _committed(tmp_path / "inner")
    root = _committed(tmp_path / "root")
    _git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(inner),
         "scenarios/sub")  # fmt: skip
    _git(root, "config", "-f", ".gitmodules", "submodule.scenarios/sub.ignore", "all")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "sub")  # fmt: skip
    (root / "scenarios" / "sub" / "README.md").write_text("changed inside")

    assert uncommitted(root, ("scenarios",)) == ("scenarios/sub",)


def test_files_git_converts_are_told(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    (root / ".gitattributes").write_text(
        "scenarios/** text eol=crlf\n*.md filter=x\npolicy/** -text\n"
    )

    assert converted(root, ("scenarios", "policy")) == ("scenarios/a/b/scenario.json",)
    assert converted(_committed(tmp_path / "plain"), ("scenarios", "policy")) == ()


def test_conversions_the_commit_sets_are_told_when_the_checkout_unsets_them(
    tmp_path: Path,
) -> None:
    root = _committed(tmp_path)
    (root / ".gitattributes").write_text("scenarios/** text eol=crlf\n")
    _git(root, "add", ".gitattributes")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", "two")  # fmt: skip
    (root / ".gitattributes").write_text("scenarios/** -text\n")  # not committed, nor checked

    assert converted(root, ("scenarios",)) == ("scenarios/a/b/scenario.json",)


def test_conversions_that_cannot_be_read_are_the_environment_s_fault(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentProblemError, match="cannot read the attributes"):
        converted(tmp_path, ("scenarios",))  # no checkout here


def test_no_file_under_the_paths_is_no_conversion(tmp_path: Path) -> None:
    assert converted(_committed(tmp_path), ("schemas",)) == ()


def test_conversions_staged_only_are_told(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    (root / ".gitattributes").write_text("scenarios/** text eol=crlf\n")
    _git(root, "add", ".gitattributes")  # staged, not committed
    (root / ".gitattributes").write_text("scenarios/** -text\n")

    assert converted(root, ("scenarios",)) == ("scenarios/a/b/scenario.json",)


def test_conversions_the_checkout_sets_are_told_whatever_tree_the_config_names(
    tmp_path: Path,
) -> None:
    root = _committed(tmp_path)
    _git(root, "config", "attr.tree", "HEAD")  # attributes read from a tree, not the checkout
    (root / ".gitattributes").write_text("scenarios/** text eol=crlf\n")

    assert converted(root, ("scenarios",)) == ("scenarios/a/b/scenario.json",)


def test_commit_attributes_that_cannot_be_read_say_the_git_needed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _committed(tmp_path)
    real = git_module._git

    def old_git(directory: Path, *arguments: str, given: str | None = None) -> str | None:
        if "--source" in arguments:  # what git before 2.40 cannot do
            return None
        return real(directory, *arguments, given=given)

    monkeypatch.setattr(git_module, "_git", old_git)

    with pytest.raises(EnvironmentProblemError, match=r"git 2\.40 or later"):
        converted(root, ("scenarios",))


def test_attributes_that_cannot_be_read_are_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _committed(tmp_path)
    real = git_module._git

    def failing_attributes(
        directory: Path, *arguments: str, given: str | None = None
    ) -> str | None:
        return None if arguments[0] == "check-attr" else real(directory, *arguments, given=given)

    monkeypatch.setattr(git_module, "_git", failing_attributes)

    with pytest.raises(EnvironmentProblemError, match="cannot read the attributes") as error:
        converted(root, ("scenarios",))
    assert "2.40" not in str(error.value)  # what fails is not the version
