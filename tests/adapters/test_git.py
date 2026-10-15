"""The commit a checkout is at, which a plan names as its base."""

import datetime
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.adapters import git as git_module
from scenario_tools.adapters.git import (
    changed_entries,
    commit_time,
    converted,
    converting,
    head_commit,
    last_commit,
    uncommitted,
)
from scenario_tools.ports.errors import EnvironmentProblemError


@pytest.fixture(autouse=True)
def _no_git_config_of_the_machine(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git reads no configuration of the machine nor of its user, which could ignore or convert
    the files the tests write."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


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


def test_the_time_of_a_commit_is_its_committer_s_with_its_offset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-10-30T11:15:02+02:00")
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2020-01-01T00:00:00+00:00")  # never the author's
    root = _committed(tmp_path)

    moment = commit_time(root, _git(root, "rev-parse", "HEAD"))

    paris = datetime.timezone(datetime.timedelta(hours=2))
    assert moment == datetime.datetime(2026, 10, 30, 11, 15, 2, tzinfo=paris)
    assert moment.utcoffset() == datetime.timedelta(hours=2)


@pytest.mark.parametrize("commit", ["0" * 40, "HEAD", "--all"])
def test_the_time_of_a_commit_the_checkout_does_not_hold_is_the_environment_s_fault(
    tmp_path: Path, commit: str
) -> None:
    root = _committed(tmp_path)

    with pytest.raises(EnvironmentProblemError, match="cannot read the time of the commit"):
        commit_time(root, commit)


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


def test_git_reads_no_configuration_of_the_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _committed(tmp_path)
    seen: list[dict[str, str]] = []
    run = subprocess.run

    def spied(*arguments: Any, **options: Any) -> Any:
        seen.append(options["env"])
        return run(*arguments, **options)

    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere"))
    monkeypatch.setattr(subprocess, "run", spied)

    head_commit(root)

    assert seen
    for environment in seen:  # the same results on any machine, whatever /etc/gitconfig says
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert "GIT_DIR" not in environment


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


def test_files_not_written_yet_that_attributes_would_convert_are_told(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    (root / ".gitattributes").write_text("scenarios/new/** text eol=crlf\n")

    told = converting(root, ("scenarios/new/one/scenario.json", "scenarios/other/x.json"))

    assert told == ("scenarios/new/one/scenario.json",)
    assert converting(root, ()) == ()


def test_line_ends_that_cannot_be_read_are_the_environment_s_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _committed(tmp_path)
    real = git_module._git

    def failing_ends(directory: Path, *arguments: str, given: str | None = None) -> str | None:
        return None if "--eol" in arguments else real(directory, *arguments, given=given)

    monkeypatch.setattr(git_module, "_git", failing_ends)

    with pytest.raises(EnvironmentProblemError, match="cannot read the attributes"):
        converted(root, ("scenarios",))


def test_line_ends_a_setting_changes_are_told(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    _git(root, "config", "core.autocrlf", "true")
    (root / "scenarios/a/b/scenario.json").write_bytes(b"x\r\n")
    _git(root, "add", "scenarios")  # the index holds LF, the checkout CRLF
    (root / "scenarios/a/b/scenario.json").write_bytes(b"x\r\n")

    assert converted(root, ("scenarios", "policy")) == ("scenarios/a/b/scenario.json",)


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


def _commit_all(root: Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-m", message)  # fmt: skip
    return _git(root, "rev-parse", "HEAD")


def test_the_entries_a_pull_request_adds_or_changes_are_listed_once_each(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    (root / "scenarios/gone/entry").mkdir(parents=True)
    (root / "scenarios/gone/entry/scenario.yaml").write_text("x")
    (root / "scenarios/other/kept").mkdir(parents=True)
    (root / "scenarios/other/kept/scenario.yaml").write_text("x")
    base = _commit_all(root, "base")
    (root / "scenarios/a/b/scenario.json").write_text("changed")
    (root / "scenarios/a/b/scenario.yaml").write_text("added")
    (root / "scenarios/c/d").mkdir(parents=True)
    (root / "scenarios/c/d/scenario.yaml").write_text("new")
    (root / "scenarios/c/new\nline").mkdir()
    (root / "scenarios/c/new\nline/scenario.yaml").write_text("odd")
    (root / "scenarios/gone/entry/scenario.yaml").unlink()
    (root / "scenarios/gone/entry").rmdir()  # as a checkout of the pull request has it
    (root / "scenarios/README.md").write_text("not an entry")
    (root / "scenarios/x").mkdir()
    (root / "scenarios/x/link").symlink_to(tmp_path)  # judged by validate, never followed
    _commit_all(root, "pull request")

    assert changed_entries(root, base) == (
        "scenarios/README.md",  # what is no domain is judged too
        "scenarios/a/b",
        "scenarios/c/d",
        "scenarios/c/new\nline",
        "scenarios/gone/entry",  # removed: listed, for the workflow to remove it as well
        "scenarios/x/link",
    )


def test_a_base_that_cannot_be_read_is_the_environment_s_fault(tmp_path: Path) -> None:
    root = _committed(tmp_path)

    with pytest.raises(EnvironmentProblemError, match="cannot read the changes"):
        changed_entries(root, "0" * 40)


@pytest.mark.parametrize("base", ["--output=/tmp/x", "main", "HEAD~1", "0" * 39])
def test_a_base_that_is_not_a_full_commit_id_is_never_given_to_git(
    tmp_path: Path, base: str
) -> None:
    root = _committed(tmp_path)

    with pytest.raises(EnvironmentProblemError, match="not a commit"):
        changed_entries(root, base)


def test_a_domain_the_pull_request_turns_into_a_link_is_listed_itself_never_crossed(
    tmp_path: Path,
) -> None:
    root = _committed(tmp_path)
    base = _git(root, "rev-parse", "HEAD")
    outside = tmp_path / "outside"
    (outside / "slug").mkdir(parents=True)
    (outside / "slug" / "scenario.yaml").write_text("x")
    (root / "scenarios/linked").symlink_to(outside)  # the domain itself
    (root / "scenarios/top-link").symlink_to(outside / "slug")
    _commit_all(root, "pull request")

    assert changed_entries(root, base) == ("scenarios/linked", "scenarios/top-link")


@pytest.mark.parametrize("replaced", ["scenarios/techniques", "scenarios"])
def test_a_domain_or_the_catalogue_replaced_by_a_file_is_listed_itself(
    tmp_path: Path, replaced: str
) -> None:
    root = _committed(tmp_path)
    (root / "scenarios/techniques/easm").mkdir(parents=True)
    (root / "scenarios/techniques/easm/scenario.yaml").write_text("x")
    base = _commit_all(root, "base")
    shutil.rmtree(root / replaced)
    (root / replaced).write_text("a file where a directory should be")
    _commit_all(root, "pull request")

    assert changed_entries(root, base) == (replaced,)


def test_a_changed_path_that_is_not_utf_8_fails_rather_than_being_left_out(
    tmp_path: Path,
) -> None:
    root = _committed(tmp_path)
    base = _git(root, "rev-parse", "HEAD")
    odd = Path(os.fsdecode(os.fsencode(str(root / "scenarios/techniques")) + b"/bad\xff"))
    odd.mkdir(parents=True)
    (odd / "scenario.yaml").write_bytes(b"x")
    _commit_all(root, "pull request")

    with pytest.raises(EnvironmentProblemError, match="not UTF-8"):
        changed_entries(root, base)


def test_a_directory_that_is_not_the_top_of_a_checkout_is_the_environment_s_fault(
    tmp_path: Path,
) -> None:
    root = _committed(tmp_path)
    base = _git(root, "rev-parse", "HEAD")

    with pytest.raises(EnvironmentProblemError, match="top"):
        changed_entries(root / "scenarios", base)


def test_a_file_of_the_catalogue_that_is_no_domain_and_goes_leaves_nothing_to_judge(
    tmp_path: Path,
) -> None:
    root = _committed(tmp_path)
    (root / "scenarios/README.md").write_text("x")
    base = _commit_all(root, "base")
    (root / "scenarios/README.md").unlink()
    _commit_all(root, "pull request")

    assert changed_entries(root, base) == ()


def _plant(root: Path, components: list[str]) -> None:
    """A commit whose tree holds ``scenarios/<components...>/tool.py``, built by hand as an
    attacker would: git refuses to check such a path out, not to store it."""

    def run(*arguments: str, given: str = "") -> str:
        return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
            ["git", "-C", str(root), *arguments],  # noqa: S607
            input=given,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    blob = run("hash-object", "-w", "--stdin", given="print('the pull request runs')\n")
    tree = run("mktree", given=f"100644 blob {blob}\ttool.py\n")
    for name in reversed(components):
        tree = run("mktree", "--missing", given=f"040000 tree {tree}\t{name}\n")
    tree = run("mktree", "--missing", given=f"040000 tree {tree}\tscenarios\n")
    commit = run("-c", "user.name=t", "-c", "user.email=t@example.org", "commit-tree", tree,
                 "-p", "HEAD", "-m", "pull request")  # fmt: skip
    run("update-ref", "HEAD", commit)


@pytest.mark.parametrize("components", [["..", "src"], [".", "x"], ["x", "..", "y"]])
def test_a_changed_path_leaving_the_catalogue_fails_rather_than_being_listed(
    tmp_path: Path, components: list[str]
) -> None:
    root = _committed(tmp_path)
    base = _git(root, "rev-parse", "HEAD")
    _plant(root, components)

    with pytest.raises(EnvironmentProblemError, match="never a place outside the catalogue"):
        changed_entries(root, base)


def test_the_last_commit_that_changed_a_path_is_read(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    first = _git(root, "rev-parse", "HEAD")
    (root / "README.md").write_text("changed")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-am", "two")  # fmt: skip

    assert last_commit(root, "scenarios/a/b") == first
    assert last_commit(root, "README.md") == _git(root, "rev-parse", "HEAD")


@pytest.mark.parametrize("path", ["scenarios/none", "-p", "", "../x", "/etc"])
def test_a_path_no_commit_changed_or_no_path_of_the_checkout_is_the_environment_s_fault(
    tmp_path: Path, path: str
) -> None:
    root = _committed(tmp_path)

    with pytest.raises(EnvironmentProblemError, match="cannot read the last commit"):
        last_commit(root, path)


def test_a_path_is_read_as_it_is_never_as_a_pattern(tmp_path: Path) -> None:
    root = _committed(tmp_path)  # holds scenarios/a/b

    with pytest.raises(EnvironmentProblemError, match="cannot read the last commit"):
        last_commit(root, "scenarios/a/*")


def test_the_last_of_two_commits_that_changed_a_path_is_given(tmp_path: Path) -> None:
    root = _committed(tmp_path)
    (root / "scenarios/a/b/scenario.json").write_text("y")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c",
         "commit.gpgsign=false", "commit", "-q", "-am", "two")  # fmt: skip

    assert last_commit(root, "scenarios/a/b") == _git(root, "rev-parse", "HEAD")


def test_a_shallow_clone_has_no_history_to_read(tmp_path: Path) -> None:
    """What changed a path last may be beyond its boundary, which git would give instead."""
    root = _committed(tmp_path / "full")
    shallow = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "1", f"file://{root}", str(shallow))

    with pytest.raises(EnvironmentProblemError, match="shallow"):
        last_commit(shallow, "scenarios/a/b")
