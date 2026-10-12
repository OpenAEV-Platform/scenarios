"""The stage 1 workflow: the base branch judges the entries a pull request adds or changes."""

from pathlib import Path
from typing import Any

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

    assert 'scenario-tools validate -- "${entries[@]}"' in scripts
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
