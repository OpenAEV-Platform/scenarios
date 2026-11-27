"""Each Nuclei template the entries fetch is on its repository's default branch: a commit of a
fork passes POL-012's reading of the link, never this check."""

from typing import Any

import pytest

from scenario_tools.application.check_template_commits import template_commit_findings
from scenario_tools.domain.policy.templates import TemplateSources
from scenario_tools.domain.shared.finding import Severity
from tests.domain.policy.cases import COMMIT, PINNED, TEMPLATES

PATH = "scenarios/vulnerabilities/x/scenario.json"
UPSTREAM = "projectdiscovery/nuclei-templates"
FIELD = "/scenario_injects/0/inject_content/template_url"
FORK = "90fa27fa51fcdc84cffb635016a31b79f8949406"  # an unmerged pull request's head, from a fork


def _stored(*links: object) -> dict[str, Any]:
    return {"scenario_injects": [{"inject_content": {"template_url": link}} for link in links]}


class _GitHub:
    def __init__(self, statuses: dict[str, str | None], branch: str = "main") -> None:
        self.statuses = statuses
        self.branch = branch
        self.asked: list[tuple[str, ...]] = []

    def default_branch(self, repository: str) -> str:
        self.asked.append(("branch", repository))
        return self.branch

    def compared(self, repository: str, branch: str, commit: str) -> str | None:
        self.asked.append(("compare", repository, branch, commit))
        return self.statuses[commit]


def _findings(github: _GitHub, *scenarios: tuple[str, object]) -> list[tuple[str, str, str]]:
    found = template_commit_findings(
        scenarios,
        TemplateSources.from_document(TEMPLATES),
        default_branch=github.default_branch,
        compared=github.compared,
    )
    assert all(f.severity is Severity.BLOCKING for f in found)
    return [(f.code, f.field, f.message) for f in found]


@pytest.mark.parametrize("status", ["identical", "behind"])
def test_a_commit_the_default_branch_holds_passes(status: str) -> None:
    github = _GitHub({COMMIT: status})

    assert _findings(github, (PATH, _stored(PINNED))) == []
    assert github.asked == [("branch", UPSTREAM), ("compare", UPSTREAM, "main", COMMIT)]


@pytest.mark.parametrize("status", ["ahead", "diverged"])
def test_a_commit_off_the_default_branch_blocks_without_quoting_the_link(status: str) -> None:
    link = PINNED.replace(COMMIT, FORK)

    assert _findings(_GitHub({FORK: status}), (PATH, _stored(link))) == [
        (
            "POL-012",
            FIELD,
            f"this Nuclei template link names a commit that is not on {UPSTREAM}'s default "
            f"branch, main (GitHub compares it as {status}): a commit of a fork, or of a pull "
            "request not merged, is served under the repository's link too; use a commit of "
            "main",
        )
    ]


def test_a_commit_no_repository_holds_blocks() -> None:
    [(code, field, message)] = _findings(_GitHub({COMMIT: None}), (PATH, _stored(PINNED)))

    assert (code, field) == ("POL-012", FIELD)
    assert message == (
        f"this Nuclei template link names a commit that no repository of {UPSTREAM}'s network "
        "holds; use a commit of main"
    )


def test_the_branch_named_is_the_repository_s_default_one() -> None:
    [(_, _, message)] = _findings(_GitHub({COMMIT: "diverged"}, "trunk"), (PATH, _stored(PINNED)))

    assert "default branch, trunk (" in message
    assert message.endswith("use a commit of trunk")


def test_github_is_asked_once_for_each_repository_and_commit() -> None:
    github = _GitHub({COMMIT: "behind", FORK: "diverged"})
    other = PINNED.replace(COMMIT, FORK)
    stored = _stored(PINNED, PINNED, other)

    found = _findings(github, (PATH, stored), ("scenarios/b/scenario.json", stored))

    assert [field for _, field, _ in found] == [
        "/scenario_injects/2/inject_content/template_url",
        "/scenario_injects/2/inject_content/template_url",
    ]
    assert github.asked == [
        ("branch", UPSTREAM),
        ("compare", UPSTREAM, "main", COMMIT),
        ("compare", UPSTREAM, "main", FORK),
    ]


def test_a_finding_names_the_file_and_every_step_is_read() -> None:
    stored = {
        "scenario_workflow": {
            "workflow_steps": [{"step_data": {"inject_content": {"template_url": PINNED}}}]
        }
    }

    [(_, field, _)] = _findings(_GitHub({COMMIT: "ahead"}), (PATH, stored))

    assert field.endswith("/inject_content/template_url")
    assert field != FIELD


@pytest.mark.parametrize(
    "stored",
    [
        _stored(None, "", 3, ["x"]),  # no link, or none POL-012 reads as one
        _stored(PINNED.replace(COMMIT, "main")),  # POL-012 refuses it
        _stored(PINNED.replace("projectdiscovery", "someone")),
        {"scenario_injects": [{"inject_content": "not an object"}]},
        {"scenario_injects": "not a list"},
        None,
    ],
)
def test_github_is_never_asked_of_a_link_pol_012_does_not_let_through(stored: object) -> None:
    github = _GitHub({})

    assert _findings(github, (PATH, stored)) == []
    assert github.asked == []
