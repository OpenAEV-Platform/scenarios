"""The stage 1 workflow: the base branch judges the entries a pull request adds or changes."""

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "pr-entries.yml"
DOCUMENT: dict[Any, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
STEPS: list[dict[str, Any]] = DOCUMENT["jobs"]["entries"]["steps"]


def _checkouts() -> list[dict[str, Any]]:
    return [step["with"] for step in STEPS if step.get("uses", "").startswith("actions/checkout@")]


def test_it_runs_as_the_base_branch_has_it_whatever_the_pull_request_changes() -> None:
    on = DOCUMENT.get("on", DOCUMENT.get(True))

    assert isinstance(on, dict)
    assert list(on) == ["pull_request_target"]  # the workflow itself is never the pull request's


def test_the_base_branch_is_checked_out_and_the_pull_request_beside_it() -> None:
    base, pull = _checkouts()

    assert base["ref"] == "${{ github.event.pull_request.base.sha }}"
    assert "path" not in base  # the tools, the policy data and the schemas run from here
    assert pull["ref"] == "${{ github.event.pull_request.head.sha }}"
    assert pull["path"] == "pull"
    assert pull["fetch-depth"] == 0  # the merge base with the base branch is in it


def test_only_the_base_branch_s_tools_run() -> None:
    named = "Install the base branch's tools"
    install = [step["run"] for step in STEPS if step.get("name") == named]
    scripts = "\n".join(step.get("run", "") for step in STEPS)

    assert install == ["uv sync --frozen --no-dev"]
    for word in ("--project", "--directory", "cd ", "pushd", "working-directory"):
        assert word not in scripts  # the pull request's checkout is data, never run from
    assert all("working-directory" not in step for step in STEPS)
    for line in scripts.splitlines():
        if "uv run" in line:
            assert "uv run --frozen --no-dev scenario-tools " in line


def test_entries_are_copied_as_they_are_links_never_followed() -> None:
    scripts = "\n".join(step.get("run", "") for step in STEPS)

    assert "changed-entries pull --base" in scripts
    assert "read -r -d ''" in scripts  # names split on NUL bytes only
    assert 'rm -rf -- "$entry"' in scripts  # removed or changed: the base's copy goes first
    assert 'cp -P -R -- "pull/$entry" "$entry"' in scripts
    assert "$(dirname" not in scripts  # which drops a name's trailing line breaks


def test_the_changed_entries_are_validated_and_scanned_for_secrets() -> None:
    scripts = "\n".join(step.get("run", "") for step in STEPS)

    assert 'scenario-tools validate --previous-root "$RUNNER_TEMP/previous"' in scripts
    assert '-- "${entries[@]}"' in scripts
    assert "GITHUB_STEP_SUMMARY" in scripts
    assert '--config "$GITHUB_WORKSPACE/.gitleaks.toml"' in scripts  # never an entry's own
    assert "--ignore-gitleaks-allow" in scripts
    assert "2>&1" in scripts  # what validate says on its error output is summed up too


def test_the_entries_are_taken_before_they_are_checked_and_scanned_whatever_validate_says() -> None:
    names = [step.get("name", "") for step in STEPS]

    taken = names.index("Take the changed entries from the pull request")
    assert taken < names.index("Validate the changed entries")
    assert taken < names.index("Look for secrets in the changed entries")
    for step in STEPS[names.index("Validate the changed entries") + 1 :]:
        assert step["if"] == "${{ !cancelled() }}"


def _copy_script() -> str:
    """The step that takes the changed entries over, its listing replaced by what a test gives."""
    [step] = [
        step
        for step in STEPS
        if step.get("name") == "Take the changed entries from the pull request"
    ]
    script = str(step["run"])
    listing = next(line for line in script.splitlines() if "changed-entries" in line)
    return script.replace(listing, 'cat "$LISTING" > "$RUNNER_TEMP/changed"')


@pytest.mark.parametrize(
    "entry",
    ["scenarios/../src", "scenarios/./x", "scenarios//x", "src", "../outside", "scenarios/x/.."],
)
def test_a_listed_path_outside_the_catalogue_stops_the_job_before_anything_is_removed(
    tmp_path: Path, entry: str
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "tool.py").write_text("the base's code")
    (tmp_path / "pull" / "src").mkdir(parents=True)
    (tmp_path / "pull" / "src" / "tool.py").write_text("the pull request's code")
    (tmp_path / "listing").write_bytes(entry.encode() + b"\0")
    environment = {
        "PATH": "/usr/bin:/bin",
        "RUNNER_TEMP": str(tmp_path),
        "LISTING": str(tmp_path / "listing"),
    }

    result = subprocess.run(  # noqa: S603 - bash runs the workflow's own step
        ["/bin/bash", "-c", _copy_script()],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "refused, outside the catalogue" in result.stderr
    assert (tmp_path / "src" / "tool.py").read_text() == "the base's code"


def test_an_entry_of_the_catalogue_is_taken_over(tmp_path: Path) -> None:
    (tmp_path / "scenarios" / "techniques" / "easm").mkdir(parents=True)
    (tmp_path / "scenarios" / "techniques" / "easm" / "scenario.yaml").write_text("base")
    (tmp_path / "pull" / "scenarios" / "techniques" / "easm").mkdir(parents=True)
    (tmp_path / "pull" / "scenarios" / "techniques" / "easm" / "scenario.yaml").write_text("pull")
    (tmp_path / "listing").write_bytes(b"scenarios/techniques/easm\0")
    environment = {
        "PATH": "/usr/bin:/bin",
        "RUNNER_TEMP": str(tmp_path),
        "LISTING": str(tmp_path / "listing"),
    }

    result = subprocess.run(  # noqa: S603 - bash runs the workflow's own step
        ["/bin/bash", "-c", _copy_script()],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "scenarios" / "techniques" / "easm" / "scenario.yaml").read_text() == "pull"
    assert (tmp_path / "entries").read_bytes() == b"scenarios/techniques/easm\0"
    kept = tmp_path / "previous" / "scenarios" / "techniques" / "easm" / "scenario.yaml"
    assert kept.read_text() == "base"  # the previous version, for the version checks


def _run_copy(tmp_path: Path, listing: bytes) -> subprocess.CompletedProcess[str]:
    (tmp_path / "listing").write_bytes(listing)
    environment = {
        "PATH": "/usr/bin:/bin",
        "RUNNER_TEMP": str(tmp_path),
        "LISTING": str(tmp_path / "listing"),
    }
    return subprocess.run(  # noqa: S603 - bash runs the workflow's own step
        ["/bin/bash", "-c", _copy_script()],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_removed_entry_keeps_its_previous_version_and_is_not_validated(tmp_path: Path) -> None:
    (tmp_path / "scenarios" / "techniques" / "easm").mkdir(parents=True)
    (tmp_path / "scenarios" / "techniques" / "easm" / "scenario.yaml").write_text("base")
    (tmp_path / "pull").mkdir()

    result = _run_copy(tmp_path, b"scenarios/techniques/easm\0")

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "scenarios" / "techniques" / "easm").exists()
    assert (tmp_path / "entries").read_bytes() == b""
    kept = tmp_path / "previous" / "scenarios" / "techniques" / "easm" / "scenario.yaml"
    assert kept.read_text() == "base"  # a moved entry is found again by its external ID


def test_a_new_entry_has_no_previous_version(tmp_path: Path) -> None:
    (tmp_path / "pull" / "scenarios" / "techniques" / "easm").mkdir(parents=True)
    (tmp_path / "pull" / "scenarios" / "techniques" / "easm" / "scenario.yaml").write_text("pull")

    result = _run_copy(tmp_path, b"scenarios/techniques/easm\0")

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "previous").is_dir()
    assert not (tmp_path / "previous" / "scenarios").exists()


def test_a_link_in_the_base_is_never_kept_as_a_previous_version(tmp_path: Path) -> None:
    (tmp_path / "scenarios" / "techniques").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "scenarios" / "techniques" / "easm").symlink_to(tmp_path / "elsewhere")
    (tmp_path / "pull").mkdir()

    result = _run_copy(tmp_path, b"scenarios/techniques/easm\0")

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "previous" / "scenarios").exists()
    assert (tmp_path / "elsewhere").is_dir()


# The policy exceptions a pull request grants

EXCEPTIONS = "policy/data/exceptions.yaml"


def _exceptions_script() -> str:
    [step] = [
        step for step in STEPS if step.get("name") == "Take the pull request's policy exceptions"
    ]
    return str(step["run"])


def _run_exceptions(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    (tmp_path / "summary").write_text("")
    environment = {"PATH": "/usr/bin:/bin", "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")}
    return subprocess.run(  # noqa: S603 - bash runs the workflow's own step
        ["/bin/bash", "-c", _exceptions_script()],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _base_and_pull(tmp_path: Path, pull: str | None, *, owners: bool = True) -> None:
    """A base branch with no exception, with code owners or not, and a pull request whose
    registry holds ``pull``, or that has none."""
    (tmp_path / "policy" / "data").mkdir(parents=True)
    (tmp_path / EXCEPTIONS).write_text("exceptions: []\n")
    if owners:
        (tmp_path / ".github").mkdir()
        (tmp_path / ".github" / "CODEOWNERS").write_text("/policy/ @maintainers\n")
    (tmp_path / "pull" / "policy" / "data").mkdir(parents=True)
    if pull is not None:
        (tmp_path / "pull" / EXCEPTIONS).write_text(pull)


def test_the_exceptions_are_taken_after_the_entries_and_before_the_validation() -> None:
    names = [step.get("name", "") for step in STEPS]

    taken = names.index("Take the pull request's policy exceptions")
    assert names.index("Take the changed entries from the pull request") < taken
    assert taken < names.index("Validate the changed entries")


def test_the_exceptions_a_pull_request_grants_are_taken_and_pointed_out(tmp_path: Path) -> None:
    """Reviewed in the same diff as the entry they cover; a code owner approves them."""
    _base_and_pull(tmp_path, "exceptions: [granted]\n")

    result = _run_exceptions(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: [granted]\n"
    assert result.stdout.startswith(f"::warning file={EXCEPTIONS}::")  # in the checks list
    assert "a code owner approves each one" in (tmp_path / "summary").read_text()


def test_no_exception_is_granted_while_no_code_owner_can_approve_it(tmp_path: Path) -> None:
    _base_and_pull(tmp_path, "exceptions: [granted]\n", owners=False)

    result = _run_exceptions(tmp_path)

    assert result.returncode != 0
    assert "no code owner can approve them yet" in result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: []\n"


@pytest.mark.parametrize("owners", [True, False])
def test_unchanged_exceptions_leave_the_base_s(tmp_path: Path, owners: bool) -> None:
    _base_and_pull(tmp_path, "exceptions: []\n", owners=owners)

    result = _run_exceptions(tmp_path)

    assert (result.returncode, result.stdout) == (0, ""), result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: []\n"
    assert (tmp_path / "summary").read_text() == ""


def test_a_pull_request_without_exceptions_keeps_the_base_s(tmp_path: Path) -> None:
    _base_and_pull(tmp_path, None)

    result = _run_exceptions(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: []\n"
    assert "the base branch's are kept" in (tmp_path / "summary").read_text()


def test_exceptions_that_are_no_file_are_refused(tmp_path: Path) -> None:
    _base_and_pull(tmp_path, None)
    (tmp_path / "pull" / EXCEPTIONS).mkdir()

    result = _run_exceptions(tmp_path)

    assert result.returncode != 0
    assert "refused, not a regular file" in result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: []\n"


@pytest.mark.parametrize("linked", ["pull/policy", "pull/policy/data", f"pull/{EXCEPTIONS}"])
def test_exceptions_reached_through_a_link_are_refused(tmp_path: Path, linked: str) -> None:
    (tmp_path / "policy" / "data").mkdir(parents=True)
    (tmp_path / EXCEPTIONS).write_text("exceptions: []\n")
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "data").mkdir(parents=True)
    (elsewhere / "data" / "exceptions.yaml").write_text("exceptions: [linked]\n")
    (elsewhere / "exceptions.yaml").write_text("exceptions: [linked]\n")
    target = {
        "pull/policy": elsewhere,
        "pull/policy/data": elsewhere / "data",
        f"pull/{EXCEPTIONS}": elsewhere / "exceptions.yaml",
    }[linked]
    (tmp_path / linked).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / linked).symlink_to(target)

    result = _run_exceptions(tmp_path)

    assert result.returncode != 0
    assert f"refused, a link: {linked}" in result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: []\n"
    assert (tmp_path / "summary").read_text() == ""
