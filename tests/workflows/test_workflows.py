"""Rules every workflow follows, whatever it does."""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

DIRECTORY = Path(__file__).parents[2] / ".github" / "workflows"
WORKFLOWS = sorted(DIRECTORY.iterdir())  # every file GitHub could run, whatever its name
_PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}")
_MOVES = re.compile(r"(^|[\s;&|(])(cd|pushd)\s|--project\b|--directory\b")


def _load(path: Path) -> dict[Any, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _triggers(document: dict[Any, Any]) -> dict[str, Any]:
    on = document.get("on", document.get(True))  # YAML 1.1 reads a bare "on" as true
    if isinstance(on, dict):
        return on
    return dict.fromkeys(on if isinstance(on, list) else [on] if on else [])


def _steps(document: dict[Any, Any]) -> list[dict[str, Any]]:
    return [step for job in document["jobs"].values() for step in job.get("steps", [])]


def test_there_are_workflows_to_check() -> None:
    assert {path.name for path in WORKFLOWS} >= {"pr-entries.yml", "pr-title.yml", "tools-ci.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_workflow_is_a_yml_file(path: Path) -> None:
    """GitHub runs a `.yaml` file too: one would escape every rule here, which reads `.yml`."""
    assert path.suffix == ".yml"
    assert path.is_file()
    assert not path.is_symlink()


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_job_calls_a_workflow_or_runs_in_an_image(path: Path) -> None:
    """A called workflow or an image is code no rule here reads, pinned or not."""
    for job in _load(path)["jobs"].values():
        assert not {"uses", "container", "services"} & set(job)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_an_expression_given_to_an_action_names_a_commit_only(path: Path) -> None:
    """An action's input may run what it is given, as a script does: only a ref is computed."""
    for step in _steps(_load(path)):
        for key, value in (step.get("with") or {}).items():
            assert "${{" not in str(value) or key == "ref", (step.get("name"), key)


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
        assert checkout.get("path") == "pull", "never over the base, nor within its tools"
    for checkout in checkouts:
        assert "head" not in str(checkout.get("repository", "")) or checkout.get("path")
    assert "defaults" not in document
    for job in document["jobs"].values():
        assert "defaults" not in job  # a working directory in the pull request's tree
    for step in _steps(document):
        assert "working-directory" not in step
        assert "shell" not in step
        assert not _MOVES.search(step.get("run", "")), step.get("name")  # its tools run from it


# Secrets: each workflow uses only the secrets it is allowed, and no other uses any, the token
# included. Fork pull requests get none, but a workflow on the base branch's rights would. An
# expression is read case-insensitively, as GitHub reads it, in the text and once YAML has
# decoded its escapes.
ALLOWED_SECRETS: dict[str, frozenset[str]] = {
    "tools-ci.yml": frozenset({"HYGIENE_TERMS"}),  # the private terms of the hygiene test
}
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_NAMED_SECRET = re.compile(r"\bsecrets\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_SECRETS = re.compile(r"\bsecrets\b", re.IGNORECASE)
_TOKEN = re.compile(r"\bgithub\b(?:\s*\[|\s*\.\s*token\b|(?!\s*\.))", re.IGNORECASE)
_INHERIT = re.compile(r"\bsecrets\s*:\s*inherit\b", re.IGNORECASE)


def secrets_used(text: str) -> set[str]:
    """The secrets a workflow's text names, by name, and every other way to a secret, the token
    included, by the text that reaches it: any `secrets` not followed by a name, any `github`
    that is not one of its named fields."""
    used: set[str] = {match.group(0) for match in _INHERIT.finditer(text)}
    for expression in _EXPRESSION.findall(text):
        named = _NAMED_SECRET.findall(expression)
        used |= {name.upper() for name in named}
        if len(_SECRETS.findall(expression)) > len(named):
            used.add("secrets")
        used |= {match.group(0) for match in _TOKEN.finditer(expression)}
    return used


def _strings(value: object) -> Iterator[str]:
    """Every key and value of a loaded YAML document that is text, its escapes decoded."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def workflow_secrets(text: str) -> set[str]:
    used = secrets_used(text)
    for string in _strings(yaml.safe_load(text)):
        used |= secrets_used(string)
    return used


@pytest.mark.parametrize(
    ("text", "used"),
    [
        ("env:\n  A: ${{ secrets.HYGIENE_TERMS }}\n", {"HYGIENE_TERMS"}),
        ("token: ${{ secrets.GITHUB_TOKEN }}", {"GITHUB_TOKEN"}),
        ("token: ${{ SECRETS.x }}", {"X"}),
        ("token: ${{ secrets [ 'X' ] }}", {"secrets"}),
        ("all: ${{ toJSON(secrets) }}", {"secrets"}),
        ("one: ${{ format('{0}', secrets) }} ${{ secrets.A }}", {"A", "secrets"}),
        ("token: ${{ github.token }}", {"github.token"}),
        ("token: ${{ GitHub . Token }}", {"GitHub . Token"}),
        ("token: ${{ github['token'] }}", {"github["}),
        ("all: ${{ toJSON(github) }}", {"github"}),
        ("uses: ./.github/workflows/x.yml\n    secrets: inherit", {"secrets: inherit"}),
        ("ref: ${{ github.event.pull_request.base.sha }}", set()),
        ("run: echo the secrets of a scenario, on GitHub, from https://github.com/x", set()),
        ("run: echo ${{ github.tokens_count }}", set()),
    ],
)
def test_every_way_to_a_secret_is_seen(text: str, used: set[str]) -> None:
    assert secrets_used(text) == used


def test_an_escape_yaml_decodes_hides_no_secret() -> None:
    text = 'env:\n  A: "${{ secre\\x74s.FOO }}"\n'

    assert secrets_used(text) == set()  # the text alone misses it
    assert workflow_secrets(text) == {"FOO"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_a_workflow_uses_only_the_secrets_it_is_allowed(path: Path) -> None:
    used = workflow_secrets(path.read_text(encoding="utf-8"))

    assert used <= ALLOWED_SECRETS.get(path.name, frozenset()), sorted(used)


# Triggers: those that run on the repository's own events by default; any other, which may run
# with the base branch's rights on what someone outside wrote, only where a workflow is
# declared for it and built to read that content as data.
SAFE_TRIGGERS = frozenset({"pull_request", "push", "workflow_dispatch", "schedule", "merge_group"})
ALLOWED_TRIGGERS: dict[str, frozenset[str]] = {
    "pr-entries.yml": frozenset({"pull_request_target"}),  # the entries, read as data
    "pr-title.yml": frozenset({"pull_request_target"}),  # the title, read through env
}


@pytest.mark.parametrize(
    ("text", "triggers"),
    [
        ("on: [workflow_run]\njobs: {}", {"workflow_run"}),
        ("on:\n  - pull_request_target\njobs: {}", {"pull_request_target"}),
        ("on: issue_comment\njobs: {}", {"issue_comment"}),
        ("'on':\n  push: {}\njobs: {}", {"push"}),
    ],
)
def test_every_shape_of_trigger_is_read(text: str, triggers: set[str]) -> None:
    assert set(_triggers(yaml.safe_load(text))) == triggers


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_an_other_trigger_runs_only_the_workflows_declared_for_it(path: Path) -> None:
    other = set(_triggers(_load(path))) - SAFE_TRIGGERS

    assert other <= ALLOWED_TRIGGERS.get(path.name, frozenset()), sorted(other)


def test_every_declared_workflow_exists() -> None:
    """An allowance left for a workflow since removed would let a new one by that name in."""
    names = {path.name for path in WORKFLOWS}

    assert set(ALLOWED_SECRETS) <= names
    assert set(ALLOWED_TRIGGERS) <= names
