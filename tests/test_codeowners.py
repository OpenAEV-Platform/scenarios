"""The repository's code owners: the maintainers' team owns everything, and by name what judges a
pull request, so that a change to it waits for their review once the branch rules require it."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
TEAM = "@OpenAEV-Platform/scenarios-maintainers"
RULES = [
    line.split()
    for line in (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
]
JUDGES = (
    "*",
    "/.github/",
    "/policy/",
    "/schemas/",
    "/conformance/",
    "/src/",
    "/tests/",
    "/pyproject.toml",
    "/uv.lock",
    "/.python-version",
    "/Makefile",
    "/.pre-commit-config.yaml",
    "/.gitleaks.toml",
    "/.gitleaks.local.toml",
)


def test_every_rule_names_the_maintainers_team_only() -> None:
    assert RULES
    assert all(owners == [TEAM] for _, *owners in RULES)


def test_what_judges_a_pull_request_is_owned_by_name() -> None:
    assert [pattern for pattern, *_ in RULES] == list(JUDGES)


def test_the_pull_request_workflow_finds_an_owner_of_the_policy_data() -> None:
    """Its step that takes a pull request's policy exceptions reads the same file the same way."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "pr-entries.yml").read_text())
    [step] = [
        step
        for step in workflow["jobs"]["entries"]["steps"]
        if step.get("name") == "Take the pull request's policy exceptions"
    ]
    [pattern] = re.findall(r"owners='([^']+)'", step["run"])
    text = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")

    assert re.search(pattern.replace("[[:space:]]", r"\s"), text, re.MULTILINE)
