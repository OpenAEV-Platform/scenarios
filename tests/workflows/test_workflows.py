"""Rules every workflow follows, whatever it does."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = sorted((Path(__file__).parents[2] / ".github" / "workflows").glob("*.yml"))
_PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}")


def _load(path: Path) -> dict[Any, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _triggers(document: dict[Any, Any]) -> dict[str, Any]:
    on = document.get("on", document.get(True))  # YAML 1.1 reads a bare "on" as true
    return on if isinstance(on, dict) else dict.fromkeys([on] if on else [])


def _steps(document: dict[Any, Any]) -> list[dict[str, Any]]:
    return [step for job in document["jobs"].values() for step in job.get("steps", [])]


def test_there_are_workflows_to_check() -> None:
    assert {path.name for path in WORKFLOWS} >= {"pr-entries.yml", "pr-title.yml", "tools-ci.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_workflow_reads_the_repository_only(path: Path) -> None:
    document = _load(path)

    assert document["permissions"] == {"contents": "read"}
    for job in document["jobs"].values():
        assert "permissions" not in job, "a job never widens the token"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_by_a_full_commit(path: Path) -> None:
    for step in _steps(_load(path)):
        if "uses" in step:
            assert _PINNED.fullmatch(step["uses"]), step["uses"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_expression_is_written_into_a_script(path: Path) -> None:
    for step in _steps(_load(path)):  # what the event carries reaches a script through env only
        assert "${{" not in step.get("run", ""), step.get("name")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_job_has_a_time_limit(path: Path) -> None:
    for job in _load(path)["jobs"].values():
        assert 0 < job["timeout-minutes"] <= 30


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_checkout_keeps_no_credentials(path: Path) -> None:
    for step in _steps(_load(path)):
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_a_pull_request_target_checks_out_the_pull_request_beside_the_base_only(
    path: Path,
) -> None:
    document = _load(path)
    if "pull_request_target" not in _triggers(document):
        return
    checkouts = [
        step["with"]
        for step in _steps(document)
        if step.get("uses", "").startswith("actions/checkout@")
    ]
    assert checkouts[0]["ref"] == "${{ github.event.pull_request.base.sha }}"
    assert "path" not in checkouts[0]  # the base is what runs
    for checkout in checkouts[1:]:  # the pull request's head, as data beside it, if at all
        assert checkout.get("path"), "never over the base"
    for checkout in checkouts:
        assert "head" not in str(checkout.get("repository", "")) or checkout.get("path")
    for step in _steps(document):
        assert "working-directory" not in step
