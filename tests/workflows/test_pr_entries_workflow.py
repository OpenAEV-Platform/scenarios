"""The stage 1 workflow: the base branch judges the entries a pull request adds or changes."""

import json
import shutil
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
        (tmp_path / ".github" / "CODEOWNERS").write_text("* @everyone\n/policy/ @maintainers\n")
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


@pytest.mark.parametrize("owners", [False, True])
def test_no_exception_is_granted_while_no_code_owner_can_approve_it(
    tmp_path: Path, owners: bool
) -> None:
    """No code owners at all, or none for the policy data: a file for /docs/ only, say."""
    _base_and_pull(tmp_path, "exceptions: [granted]\n", owners=owners)
    if owners:
        (tmp_path / ".github" / "CODEOWNERS").write_text("/docs/ @maintainers\n/policy/data/x @a\n")

    result = _run_exceptions(tmp_path)

    assert result.returncode != 0
    assert "no code owner can approve them yet" in result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: []\n"


@pytest.mark.parametrize(
    "line", ["/policy/data/ @maintainers", "/policy/data/exceptions.yaml @a @b", "/policy/\t@a"]
)
def test_code_owners_of_the_policy_data_let_the_exceptions_be_taken(
    tmp_path: Path, line: str
) -> None:
    _base_and_pull(tmp_path, "exceptions: [granted]\n")
    (tmp_path / ".github" / "CODEOWNERS").write_text(f"# owners\n{line}\n")

    result = _run_exceptions(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / EXCEPTIONS).read_text() == "exceptions: [granted]\n"


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


# The built-in contracts a pull request records

CONTRACTS = "policy/data/builtin-contracts.yaml"
_BASE_CONTRACTS = "platform_version: 3.261016.0\ncontracts: []\n"
_PULL_CONTRACTS = "platform_version: 3.261016.0\ncontracts: [recorded]\n"


def _contracts_script() -> str:
    [step] = [
        step for step in STEPS if step.get("name") == "Take the pull request's built-in contracts"
    ]
    return str(step["run"])


def _run_contracts(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    (tmp_path / "summary").write_text("")
    environment = {"PATH": "/usr/bin:/bin", "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")}
    return subprocess.run(  # noqa: S603 - bash runs the workflow's own step
        ["/bin/bash", "-c", _contracts_script()],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _base_and_pull_contracts(tmp_path: Path, pull: str | None, *, owners: bool = True) -> None:
    """A base branch with its own built-in contracts, with code owners or not, and a pull request
    whose contracts hold ``pull``, or that records none of its own."""
    (tmp_path / "policy" / "data").mkdir(parents=True)
    (tmp_path / CONTRACTS).write_text(_BASE_CONTRACTS)
    if owners:
        (tmp_path / ".github").mkdir()
        (tmp_path / ".github" / "CODEOWNERS").write_text("* @everyone\n/policy/ @maintainers\n")
    (tmp_path / "pull" / "policy" / "data").mkdir(parents=True)
    if pull is not None:
        (tmp_path / "pull" / CONTRACTS).write_text(pull)


def test_the_contracts_are_taken_after_the_entries_and_before_the_validation() -> None:
    names = [step.get("name", "") for step in STEPS]

    taken = names.index("Take the pull request's built-in contracts")
    assert names.index("Take the changed entries from the pull request") < taken
    assert taken < names.index("Validate the changed entries")


def test_the_contracts_a_pull_request_records_are_taken_and_pointed_out(tmp_path: Path) -> None:
    """Recorded in the same diff as the scenario that first uses them, a code owner approving."""
    _base_and_pull_contracts(tmp_path, _PULL_CONTRACTS)

    result = _run_contracts(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / CONTRACTS).read_text() == _PULL_CONTRACTS
    assert result.stdout.startswith(f"::warning file={CONTRACTS}::")  # in the checks list
    assert "a code owner approves them" in (tmp_path / "summary").read_text()


@pytest.mark.parametrize("owners", [False, True])
def test_no_contract_is_taken_while_no_code_owner_can_approve_it(
    tmp_path: Path, owners: bool
) -> None:
    """No code owners at all, or none for the policy data: a file for /docs/ only, say."""
    _base_and_pull_contracts(tmp_path, _PULL_CONTRACTS, owners=owners)
    if owners:
        (tmp_path / ".github" / "CODEOWNERS").write_text("/docs/ @maintainers\n/policy/data/x @a\n")

    result = _run_contracts(tmp_path)

    assert result.returncode != 0
    assert "no code owner can approve them yet" in result.stderr
    assert (tmp_path / CONTRACTS).read_text() == _BASE_CONTRACTS


@pytest.mark.parametrize(
    "line",
    ["/policy/data/ @maintainers", "/policy/data/builtin-contracts.yaml @a @b", "/policy/\t@a"],
)
def test_code_owners_of_the_policy_data_let_the_contracts_be_taken(
    tmp_path: Path, line: str
) -> None:
    _base_and_pull_contracts(tmp_path, _PULL_CONTRACTS)
    (tmp_path / ".github" / "CODEOWNERS").write_text(f"# owners\n{line}\n")

    result = _run_contracts(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / CONTRACTS).read_text() == _PULL_CONTRACTS


@pytest.mark.parametrize("owners", [True, False])
def test_unchanged_contracts_leave_the_base_s(tmp_path: Path, owners: bool) -> None:
    _base_and_pull_contracts(tmp_path, _BASE_CONTRACTS, owners=owners)

    result = _run_contracts(tmp_path)

    assert (result.returncode, result.stdout) == (0, ""), result.stderr
    assert (tmp_path / CONTRACTS).read_text() == _BASE_CONTRACTS
    assert (tmp_path / "summary").read_text() == ""


def test_a_pull_request_without_contracts_keeps_the_base_s(tmp_path: Path) -> None:
    _base_and_pull_contracts(tmp_path, None)

    result = _run_contracts(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / CONTRACTS).read_text() == _BASE_CONTRACTS
    assert "the base branch's are kept" in (tmp_path / "summary").read_text()


def test_contracts_that_are_no_file_are_refused(tmp_path: Path) -> None:
    _base_and_pull_contracts(tmp_path, None)
    (tmp_path / "pull" / CONTRACTS).mkdir()

    result = _run_contracts(tmp_path)

    assert result.returncode != 0
    assert "refused, not a regular file" in result.stderr
    assert (tmp_path / CONTRACTS).read_text() == _BASE_CONTRACTS


@pytest.mark.parametrize("linked", ["pull/policy", "pull/policy/data", f"pull/{CONTRACTS}"])
def test_contracts_reached_through_a_link_are_refused(tmp_path: Path, linked: str) -> None:
    (tmp_path / "policy" / "data").mkdir(parents=True)
    (tmp_path / CONTRACTS).write_text(_BASE_CONTRACTS)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "data").mkdir(parents=True)
    (elsewhere / "data" / "builtin-contracts.yaml").write_text(_PULL_CONTRACTS)
    (elsewhere / "builtin-contracts.yaml").write_text(_PULL_CONTRACTS)
    target = {
        "pull/policy": elsewhere,
        "pull/policy/data": elsewhere / "data",
        f"pull/{CONTRACTS}": elsewhere / "builtin-contracts.yaml",
    }[linked]
    (tmp_path / linked).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / linked).symlink_to(target)

    result = _run_contracts(tmp_path)

    assert result.returncode != 0
    assert f"refused, a link: {linked}" in result.stderr
    assert (tmp_path / CONTRACTS).read_text() == _BASE_CONTRACTS
    assert (tmp_path / "summary").read_text() == ""


# The pull request's commits, scanned for secrets

COMMITS = "Look for secrets in the pull request's commits"


def _commits_step() -> dict[str, Any]:
    [step] = [step for step in STEPS if step.get("name") == COMMITS]
    return step


def test_every_commit_of_the_pull_request_is_scanned_whatever_validate_says() -> None:
    """A merge keeps every commit: a secret a later commit removes stays in the history."""
    step = _commits_step()

    assert step["if"] == "${{ !cancelled() }}"
    assert step["env"] == {
        "BASE": "${{ github.event.pull_request.base.sha }}",
        "HEAD": "${{ github.event.pull_request.head.sha }}",
    }
    script = str(step["run"])
    assert '--config "$GITHUB_WORKSPACE/.gitleaks.toml"' in script  # never the pull request's
    assert "--ignore-gitleaks-allow" in script
    assert '--log-opts="--diff-merges=first-parent $BASE..$HEAD"' in script  # a merge's own
    assert "-- pull/.git" in script  # its git directory: no file of its tree is read


def test_archives_are_opened_by_every_scan() -> None:
    scans = [str(step["run"]) for step in STEPS if 'gitleaks" ' in str(step.get("run", ""))]

    assert len(scans) == 2
    assert all("--max-archive-depth 2" in scan for scan in scans)


def _git(directory: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - git on a repository of the test
        ["git", "-C", str(directory), *arguments],  # noqa: S607 - git from the PATH
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(directory: Path, name: str, text: str) -> str:
    (directory / name).write_text(text)
    _git(directory, "add", "--all")
    _git(directory, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", name)
    return _git(directory, "rev-parse", "HEAD")


def _gitleaks() -> str:
    found = shutil.which("gitleaks")
    if found is None:
        pytest.fail("gitleaks is required, as `make secrets` says")
    return found


def _run_scan(tmp_path: Path, script: str, **variables: str) -> subprocess.CompletedProcess[str]:
    """A secret scan step of the workflow, with the pinned gitleaks where the job installs it."""
    (tmp_path / "temp").mkdir(exist_ok=True)
    if not (tmp_path / "temp" / "gitleaks").exists():
        (tmp_path / "temp" / "gitleaks").symlink_to(_gitleaks())
    shutil.copy(WORKFLOW.parents[2] / ".gitleaks.toml", tmp_path / ".gitleaks.toml")
    (tmp_path / "summary").touch()
    environment = {
        "PATH": "/usr/bin:/bin",
        "RUNNER_TEMP": str(tmp_path / "temp"),
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        **variables,
    }
    return subprocess.run(  # noqa: S603 - bash runs the workflow's own step
        ["/bin/bash", "-c", script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _scan_commits(tmp_path: Path, base: str, head: str) -> subprocess.CompletedProcess[str]:
    return _run_scan(tmp_path, str(_commits_step()["run"]), BASE=base, HEAD=head)


def _pull(tmp_path: Path) -> tuple[Path, str]:
    pull = tmp_path / "pull"
    pull.mkdir()
    _git(pull, "init", "--quiet")
    _git(pull, "config", "user.email", "contributor@example.com")
    _git(pull, "config", "user.name", "Contributor")
    return pull, _commit(pull, "README.md", "a catalogue\n")


KEY = "".join(["ghp_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8"])  # never one constant


def test_a_secret_a_later_commit_removes_and_hides_is_still_found(tmp_path: Path) -> None:
    pull, base = _pull(tmp_path)
    _commit(pull, "notes.txt", f'token = "{KEY}"\n')
    found = subprocess.run(  # noqa: S603 - the pinned gitleaks, on the test's repository
        [
            _gitleaks(),
            "git",
            str(pull),
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            str(tmp_path / "report.json"),
            "--exit-code",
            "0",
        ],
        check=True,
        capture_output=True,
    )
    assert found.returncode == 0
    fingerprint = json.loads((tmp_path / "report.json").read_text())[0]["Fingerprint"]
    (pull / "notes.txt").unlink()
    (pull / ".gitleaksignore").write_text(f"{fingerprint}\n")  # the pull request's own ignore
    head = _commit(pull, "cleanup", "")

    result = _scan_commits(tmp_path, base, head)

    assert result.returncode != 0
    assert "leaks found: 1" in result.stdout + result.stderr  # the secret, not a broken scan
    assert "CONTRIBUTING.md" in (tmp_path / "summary").read_text()  # what to do, in the run


def test_commits_without_a_secret_pass_and_the_base_s_history_is_not_scanned(
    tmp_path: Path,
) -> None:
    pull, _ = _pull(tmp_path)
    base = _commit(pull, "old.txt", f'token = "{KEY}"\n')  # the base branch's, already merged
    head = _commit(pull, "scenario.txt", "a scenario\n")

    result = _scan_commits(tmp_path, base, head)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "no leaks found" in result.stdout + result.stderr


def test_a_secret_only_a_merge_commit_brings_is_found(tmp_path: Path) -> None:
    """A merge's own changes, a conflict's resolution say, are no other commit's."""
    pull, base = _pull(tmp_path)
    _git(pull, "checkout", "--quiet", "-b", "side")
    _commit(pull, "side.txt", "a side change\n")
    _git(pull, "checkout", "--quiet", "-")
    _commit(pull, "main.txt", "a main change\n")
    _git(pull, "-c", "commit.gpgsign=false", "merge", "--quiet", "--no-ff", "--no-commit", "side")
    (pull / "evil.txt").write_text(f'token = "{KEY}"\n')
    _git(pull, "add", "--all")
    _git(pull, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "merge")
    head = _git(pull, "rev-parse", "HEAD")

    result = _scan_commits(tmp_path, base, head)

    assert result.returncode != 0
    assert "leaks found: 1" in result.stdout + result.stderr


@pytest.mark.parametrize("which", ["BASE", "HEAD"])
def test_a_range_that_cannot_be_read_fails_the_scan(tmp_path: Path, which: str) -> None:
    """Never "0 commits scanned, no leaks found" for a commit the clone does not hold."""
    pull, base = _pull(tmp_path)
    head = _commit(pull, "scenario.txt", "a scenario\n")
    commits = {"BASE": base, "HEAD": head, which: "0" * 40}

    result = _scan_commits(tmp_path, commits["BASE"], commits["HEAD"])

    assert result.returncode != 0
    assert "refused, not a commit of the pull request's clone" in result.stderr


ENTRIES_SCAN = "Look for secrets in the changed entries"


def _entries_scan(tmp_path: Path, entry: str) -> subprocess.CompletedProcess[str]:
    [step] = [step for step in STEPS if step.get("name") == ENTRIES_SCAN]
    (tmp_path / "temp").mkdir(exist_ok=True)
    (tmp_path / "temp" / "entries").write_bytes(entry.encode() + b"\0")
    return _run_scan(tmp_path, str(step["run"]))


def test_an_entry_s_own_ignore_file_never_hides_a_secret(tmp_path: Path) -> None:
    entry = tmp_path / "scenarios" / "techniques" / "x"
    entry.mkdir(parents=True)
    (entry / "scenario.json").write_text(f'{{"token": "{KEY}"}}\n')
    report = tmp_path / "report.json"
    subprocess.run(  # noqa: S603 - the pinned gitleaks, on the test's entry
        [
            _gitleaks(),
            "dir",
            str(entry),
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--exit-code",
            "0",
        ],
        check=True,
        capture_output=True,
    )
    fingerprints = {finding["Fingerprint"] for finding in json.loads(report.read_text())}
    (entry / ".gitleaksignore").write_text("".join(f"{line}\n" for line in fingerprints))

    result = _entries_scan(tmp_path, "scenarios/techniques/x")

    assert result.returncode != 0
    assert "refused, an ignore file: scenarios/techniques/x/.gitleaksignore" in result.stderr
    assert "leaks found" in result.stdout + result.stderr
    assert "CONTRIBUTING.md" in (tmp_path / "summary").read_text()


def test_an_entry_without_a_secret_passes_the_scan(tmp_path: Path) -> None:
    entry = tmp_path / "scenarios" / "techniques" / "x"
    entry.mkdir(parents=True)
    (entry / "scenario.json").write_text('{"scenario_name": "x"}\n')

    result = _entries_scan(tmp_path, "scenarios/techniques/x")

    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "summary").read_text() == ""


def test_the_diff_of_the_changed_entries_is_written_for_the_reviewer() -> None:
    """Informative: it runs whatever validate says, and never fails the job."""
    names = [step.get("name", "") for step in STEPS]
    shown = names.index("Show what changes in each entry")
    step = STEPS[shown]

    assert names.index("Validate the changed entries") < shown
    assert step["if"] == "${{ !cancelled() }}"
    script = str(step["run"])
    assert 'scenario-tools diff --previous-root "$RUNNER_TEMP/previous"' in script
    assert '-- "${entries[@]}"' in script
    assert "GITHUB_STEP_SUMMARY" in script
    assert "|| true" in script


# The pull request's payload catalogue

CATALOGUE = "Take the pull request's payload catalogue"


def _run_catalogue(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    [step] = [step for step in STEPS if step.get("name") == CATALOGUE]
    return subprocess.run(  # noqa: S603 - bash runs the workflow's own step
        ["/bin/bash", "-c", str(step["run"])],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(tmp_path / "runner")},
        capture_output=True,
        text=True,
        check=False,
    )


def _catalogues(tmp_path: Path) -> None:
    """A base branch holding one version, and a pull request that adds another."""
    (tmp_path / "payloads" / "ps").mkdir(parents=True)
    (tmp_path / "payloads" / "ps" / "1.0.0.json").write_text("{}\n")
    (tmp_path / "pull" / "payloads" / "ps").mkdir(parents=True)
    (tmp_path / "pull" / "payloads" / "ps" / "1.0.0.json").write_text("{}\n")
    (tmp_path / "pull" / "payloads" / "new").mkdir()
    (tmp_path / "pull" / "payloads" / "new" / "1.0.0.json").write_text('{"new": 1}\n')


def test_the_catalogue_is_taken_and_checked_before_the_entries_are() -> None:
    names = [step.get("name", "") for step in STEPS]
    scripts = "\n".join(step.get("run", "") for step in STEPS)

    taken = names.index(CATALOGUE)
    assert names.index("Take the pull request's policy exceptions") < taken
    assert taken < names.index("Check the payload catalogue")
    assert names.index("Check the payload catalogue") < names.index("Validate the changed entries")
    assert "scenario-tools validate-payloads payloads" in scripts


def test_the_pull_request_s_catalogue_replaces_the_base_s(tmp_path: Path) -> None:
    _catalogues(tmp_path)
    (tmp_path / "payloads" / "gone").mkdir()
    (tmp_path / "payloads" / "gone" / "1.0.0.json").write_text("{}\n")

    result = _run_catalogue(tmp_path)

    assert result.returncode == 0, result.stderr
    assert sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.glob("payloads/*/*")) == [
        "payloads/new/1.0.0.json",
        "payloads/ps/1.0.0.json",
    ]


def test_a_pull_request_without_a_catalogue_leaves_an_empty_one_and_the_base_s_kept(
    tmp_path: Path,
) -> None:
    """So that the next step refuses every version the base holds and the pull request drops."""
    _catalogues(tmp_path)
    shutil.rmtree(tmp_path / "pull" / "payloads")

    result = _run_catalogue(tmp_path)

    assert result.returncode == 0, result.stderr
    assert list((tmp_path / "payloads").iterdir()) == []
    assert (tmp_path / "runner" / "base" / "payloads" / "ps" / "1.0.0.json").read_text() == "{}\n"


def test_the_base_s_catalogue_is_kept_for_the_check_against_it(tmp_path: Path) -> None:
    _catalogues(tmp_path)

    result = _run_catalogue(tmp_path)
    scripts = "\n".join(step.get("run", "") for step in STEPS)

    assert result.returncode == 0, result.stderr
    kept = sorted(p.name for p in (tmp_path / "runner" / "base" / "payloads").iterdir())
    assert kept == ["ps"]  # the base's, not the pull request's
    assert '--previous-root "$RUNNER_TEMP/base"' in scripts


@pytest.mark.parametrize("shape", ["link", "file"])
def test_a_catalogue_that_is_a_link_or_no_directory_is_refused(tmp_path: Path, shape: str) -> None:
    _catalogues(tmp_path)
    shutil.rmtree(tmp_path / "pull" / "payloads")
    if shape == "link":
        (tmp_path / "elsewhere").mkdir()
        (tmp_path / "pull" / "payloads").symlink_to(tmp_path / "elsewhere")
    else:
        (tmp_path / "pull" / "payloads").write_text("not a directory\n")

    result = _run_catalogue(tmp_path)

    assert result.returncode != 0
    assert "refused" in result.stderr
    assert (tmp_path / "payloads" / "ps" / "1.0.0.json").exists()  # the base's is kept


@pytest.mark.parametrize("shape", ["link", "file"])
def test_a_base_catalogue_that_is_no_directory_stops_the_job(tmp_path: Path, shape: str) -> None:
    _catalogues(tmp_path)
    shutil.rmtree(tmp_path / "payloads")
    if shape == "link":
        (tmp_path / "elsewhere").mkdir()
        (tmp_path / "payloads").symlink_to(tmp_path / "elsewhere")
    else:
        (tmp_path / "payloads").write_text("not a directory\n")

    result = _run_catalogue(tmp_path)

    assert result.returncode != 0
    assert "the base branch's payloads is no directory" in result.stderr
