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
# The commits an action may be given to check out, both fixed by the event.
COMMITS = frozenset(
    {"${{ github.event.pull_request.base.sha }}", "${{ github.event.pull_request.head.sha }}"}
)
# A path in the runner's temporary directory, which the runner sets and no one else: where the
# release workflow keeps what its tools write, outside the checkout.
_IN_RUNNER_TEMP = re.compile(r"\$\{\{ runner\.temp \}\}/[a-z]+(?:\.json)?")
# An artifact's name taken from a matrix value, which the workflow file itself sets, never an
# event: the one way to name the artifact of each job of a matrix.
_BY_MATRIX = re.compile(r"[a-z-]*\$\{\{ matrix\.[a-z]+ \}\}")
# A static guard, never a proof: what would run the base branch's tools from the pull request's
# tree, or run a file of it. Code-owner review of the workflows is the barrier.
_MOVES = re.compile(
    r"(^|[\s;&|(])(cd|pushd)\s"  # a move into another directory
    r"|--project\b|--directory\b"  # a tool told to run from another one
    r"|(^|[\s;&|(])(?!git\s)[\w.-]+\s+-C\s*[\"']?pull\b"  # but git, which reads it as data
    r"|(^|[;&|(]|\bthen|\bdo|\belse)\s*[\"']?(\./)?pull/"  # a file of it as a command
    r"|\b(source|bash|sh|zsh|python3?|node|perl|ruby|make)\b[^\n;&|]*[\s\"'=](\./)?pull/"
    r"|(^|[\s;&|(])\.\s+[\"']?(\./)?pull/",
    re.MULTILINE,
)


@pytest.mark.parametrize(
    ("script", "moves"),
    [
        ("cd pull", True),
        ("  pushd pull/scenarios", True),
        ("uv run --project pull scenario-tools validate", True),
        ("uv run --directory pull x", True),
        ("make -C pull check", True),
        ('make -C "pull"', True),
        ("pull/run.sh", True),
        ('if true; then "pull/run.sh"; fi', True),
        ("bash pull/run.sh", True),
        ("python3 pull/x.py", True),
        (". pull/env.sh", True),
        ("source pull/env.sh", True),
        ("git -C pull rev-parse HEAD", False),
        ('cp -P -R -- "pull/$entry" "$entry"', False),
        ('cmp -s -- "pull/$exceptions" "$exceptions"', False),
        ('if [ -e "pull/$entry" ]; then', False),
        ("uv run scenario-tools changed-entries pull --base x", False),
    ],
)
def test_a_script_that_runs_from_or_runs_the_pull_request_s_tree_is_seen(
    script: str, moves: bool
) -> None:
    assert bool(_MOVES.search(script)) is moves


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
    """An action's input may run what it is given, as a script does: only a ref is computed,
    but in a step the secret rules fix to the letter, inputs included."""
    for step in _steps(_load(path)):
        if _fixed(path, step):
            continue
        for key, value in (step.get("with") or {}).items():
            computed = "${{" in str(value)
            in_temp = key == "path" and _IN_RUNNER_TEMP.fullmatch(str(value)) is not None
            named = key == "name" and _BY_MATRIX.fullmatch(str(value)) is not None
            assert not computed or in_temp or named or (key == "ref" and value in COMMITS), (
                step.get("name"),
                key,
            )


def _fixed(path: Path, step: dict[str, Any]) -> bool:
    """Whether the secret rules of ``path`` declare ``step`` as it is, to the letter."""
    for steps in SECRET_STEPS.get(path.name, {}).values():
        allowed = steps.get(step.get("name", ""))
        if allowed is not None and step == {"name": step["name"], **allowed}:
            return True
    return False


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("${{ runner.temp }}/approvals.json", True),
        ("${{ runner.temp }}/release", True),
        ("${{ runner.temp }}/../x", False),
        ("${{ github.event.pull_request.title }}", False),
        ("${{ runner.temp }}/x ${{ github.head_ref }}", False),
    ],
)
def test_only_a_plain_path_in_the_runner_temp_may_be_computed(value: str, kept: bool) -> None:
    assert (_IN_RUNNER_TEMP.fullmatch(value) is not None) is kept


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("coverage-${{ matrix.data }}", True),
        ("${{ matrix.share }}", True),
        ("x-${{ github.head_ref }}", False),
        ("${{ matrix.data }}-${{ github.ref }}", False),
        ("${{ matrix.data || github.ref }}", False),
    ],
)
def test_only_a_matrix_value_may_name_an_artifact(value: str, kept: bool) -> None:
    assert (_BY_MATRIX.fullmatch(value) is not None) is kept


def test_a_ref_that_is_no_commit_is_refused() -> None:
    """A branch's name moves after the run is triggered: only a commit's SHA is fixed."""
    assert "${{ github.head_ref }}" not in COMMITS
    assert "${{ github.event.pull_request.head.ref }}" not in COMMITS


# A job's own permissions, by workflow and job: reads only, and only where a job needs one.
ALLOWED_JOB_PERMISSIONS: dict[str, dict[str, dict[str, str]]] = {
    "release.yml": {
        # The approvals of each entry, from the pull requests' reviews.
        "approvals": {"contents": "read", "pull-requests": "read"},
        # The one job that writes: the release, and the channel's pointer.
        "publish": {"contents": "write"},
    },
}
# The jobs whose token may write, by workflow: the release workflow's publication only.
WRITING_JOBS: dict[str, frozenset[str]] = {"release.yml": frozenset({"publish"})}
# The environment of each job that runs in one, by workflow: the release app's key is kept in
# `release`, which only the default branch can deploy to, and only the publication reads it.
ENVIRONMENTS: dict[str, dict[str, str]] = {"release.yml": {"publish": "release"}}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_workflow_reads_the_repository_only(path: Path) -> None:
    document = _load(path)

    assert document["permissions"] == {"contents": "read"}
    allowed = ALLOWED_JOB_PERMISSIONS.get(path.name, {})
    for name, job in document["jobs"].items():
        if name in allowed:
            assert job["permissions"] == allowed[name]
            if name not in WRITING_JOBS.get(path.name, frozenset()):
                assert set(job["permissions"].values()) == {"read"}
        else:
            assert "permissions" not in job, "a job never widens the token"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_only_the_jobs_declared_run_in_an_environment(path: Path) -> None:
    allowed = ENVIRONMENTS.get(path.name, {})
    for name, job in _load(path)["jobs"].items():
        assert job.get("environment") == allowed.get(name), name


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
    "release.yml": frozenset(
        {
            "github.token",  # to read the reviews, in its approvals job, and publish the release
            "RELEASE_APP_PRIVATE_KEY",  # the release app's key, for a token to move the channel
            "steps.app.outputs.token",  # that token
        }
    ),
}
# The jobs of a workflow that may use what it is allowed; the others use nothing.
SECRET_JOBS: dict[str, frozenset[str]] = {"release.yml": frozenset({"approvals", "publish"})}
# And within them, the steps that use it, each by its name and exactly what it runs: never a step
# that runs another's code but the tools.
SECRET_STEPS: dict[str, dict[str, dict[str, dict[str, Any]]]] = {
    "release.yml": {
        "approvals": {
            "Read the channel's previous release": {
                "env": {
                    "GH_TOKEN": "${{ github.token }}",
                    "CHANNEL": "${{ inputs.channel }}",
                },
                "run": (
                    "export LC_ALL=C\n"
                    'default=$(gh api "repos/${GITHUB_REPOSITORY}" --jq .default_branch)\n'
                    'head=$(gh api "repos/${GITHUB_REPOSITORY}/branches/${default}" --jq .commi'
                    "t.sha)\n"
                    'if [ "$head" != "$GITHUB_SHA" ]; then\n'
                    '  echo "A release is built from the head of the default branch, $head, not'
                    ' $GITHUB_SHA."\n'
                    "  exit 1\n"
                    "fi\n"
                    'mkdir "$RUNNER_TEMP"/previous\n'
                    'if answer=$(gh api "repos/${GITHUB_REPOSITORY}/contents/${CHANNEL}.json?re'
                    'f=channels" 2> "$RUNNER_TEMP"/previous/error.txt); then\n'
                    "  sha=$(printf '%s' \"$answer\" | jq -r .sha)\n"
                    '  if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then\n'
                    '    echo "The pointer of $CHANNEL is not as GitHub gives a file."\n'
                    "    exit 1\n"
                    "  fi\n"
                    '  printf \'%s\' "$sha" > "$RUNNER_TEMP"/previous/pointer.sha\n'
                    '  printf \'%s\' "$answer" | jq -r .content | base64 -d > "$RUNNER_TEMP"/pr'
                    "evious/pointer.json\n"
                    '  release=$(jq -r .release "$RUNNER_TEMP"/previous/pointer.json)\n'
                    '  if ! [[ "$release" =~ ^[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}\\.[1-9][0-9]{0,8}$'
                    " ]]; then\n"
                    '    echo "The pointer of $CHANNEL names no release."\n'
                    "    exit 1\n"
                    "  fi\n"
                    '  gh release download "$release" --repo "$GITHUB_REPOSITORY" --pattern man'
                    'ifest.json --dir "$RUNNER_TEMP"/previous\n'
                    'elif grep -q "Not Found (HTTP 404)" "$RUNNER_TEMP"/previous/error.txt; the'
                    "n\n"
                    '  count=$(gh api "repos/${GITHUB_REPOSITORY}/releases?per_page=1" --jq len'
                    "gth)\n"
                    '  if [ "$count" != "0" ]; then\n'
                    '    echo "The repository has a release, but $CHANNEL has no pointer: resto'
                    're it before releasing again."\n'
                    "    exit 1\n"
                    "  fi\n"
                    '  echo "The channel has no release yet." > "$RUNNER_TEMP"/previous/first-r'
                    "elease\n"
                    "else\n"
                    '  cat "$RUNNER_TEMP"/previous/error.txt\n'
                    "  exit 1\n"
                    "fi\n"
                    'rm "$RUNNER_TEMP"/previous/error.txt\n'
                ),
            },
            "Collect the approvals": {
                "env": {"GITHUB_TOKEN": "${{ github.token }}"},
                "run": (
                    'uv run --frozen --no-dev scenario-tools approvals --repo . --out "$RUNNER_'
                    'TEMP"/approvals.json'
                ),
            },
        },
        "publish": {
            "Publish the release": {
                "env": {
                    "GH_TOKEN": "${{ github.token }}",
                    "CHANNEL": "${{ inputs.channel }}",
                },
                "run": (
                    'default=$(gh api "repos/${GITHUB_REPOSITORY}" --jq .default_branch)\n'
                    'head=$(gh api "repos/${GITHUB_REPOSITORY}/branches/${default}" --jq .commi'
                    "t.sha)\n"
                    'if [ "$head" != "$GITHUB_SHA" ]; then\n'
                    '  echo "The default branch moved to $head while the release was built from'
                    ' $GITHUB_SHA: release again."\n'
                    "  exit 1\n"
                    "fi\n"
                    'release=$(jq -r .release "$RUNNER_TEMP/pointer/${CHANNEL}.json")\n'
                    'if gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${release}" > /dev/null'
                    ' 2> "$RUNNER_TEMP"/tag-error.txt; then\n'
                    '  echo "The tag $release exists: a release is never replaced."\n'
                    "  exit 1\n"
                    'elif ! grep -q "Not Found (HTTP 404)" "$RUNNER_TEMP"/tag-error.txt; then\n'
                    '  cat "$RUNNER_TEMP"/tag-error.txt\n'
                    "  exit 1\n"
                    "fi\n"
                    'gh release create "$release" "$RUNNER_TEMP"/release/* --repo "$GITHUB_REPO'
                    'SITORY" --target "$GITHUB_SHA" --title "$release" --notes "Release $releas'
                    "e of the catalogue, on $CHANNEL. Check it against its manifest before usin"
                    'g it: see docs/consumers.md."\n'
                    'tagged=$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${release}" --jq '
                    ".object.sha)\n"
                    'if [ "$tagged" != "$GITHUB_SHA" ]; then\n'
                    '  echo "The release $release is tagged on $tagged, not $GITHUB_SHA: the ch'
                    'annel does not move to it."\n'
                    "  exit 1\n"
                    "fi\n"
                    'mkdir "$RUNNER_TEMP"/published\n'
                    'gh release download "$release" --repo "$GITHUB_REPOSITORY" --dir "$RUNNER_'
                    'TEMP"/published\n'
                ),
            },
            "Take a token of the release app": {
                "id": "app",
                "uses": "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510",
                "with": {
                    "client-id": "${{ vars.RELEASE_APP_ID }}",
                    "private-key": "${{ secrets.RELEASE_APP_PRIVATE_KEY }}",
                    "permission-contents": "write",
                },
            },
            "Move the channel to the release": {
                "env": {
                    "GH_TOKEN": "${{ steps.app.outputs.token }}",
                    "CHANNEL": "${{ inputs.channel }}",
                },
                "run": (
                    'release=$(jq -r .release "$RUNNER_TEMP/pointer/${CHANNEL}.json")\n'
                    'sha=""\n'
                    'if [ -f "$RUNNER_TEMP"/previous/pointer.sha ]; then\n'
                    '  sha=$(cat "$RUNNER_TEMP"/previous/pointer.sha)\n'
                    "fi\n"
                    'gh api -X PUT "repos/${GITHUB_REPOSITORY}/contents/${CHANNEL}.json" -f bra'
                    'nch=channels -f message="Move ${CHANNEL} to ${release}" -f content="$(base'
                    '64 -w0 "$RUNNER_TEMP/pointer/${CHANNEL}.json")" ${sha:+-f sha="$sha"} > /d'
                    "ev/null\n"
                ),
            },
        },
    }
}


def _expressions(text: str) -> Iterator[str]:
    """Every ``${{ … }}`` expression of ``text``, a ``}}`` inside a quoted string ending none,
    as GitHub reads them; an expression left open runs to the end of the text."""
    start = text.find("${{")
    while start != -1:
        index, quoted = start + 3, False
        while index < len(text) and (quoted or not text.startswith("}}", index)):
            if text[index] == "'":
                quoted = not quoted  # a doubled quote inside a string toggles twice
            index += 1
        yield text[start + 3 : index]
        start = text.find("${{", index)


_NAMED_SECRET = re.compile(r"\bsecrets\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_SECRETS = re.compile(r"\bsecrets\b", re.IGNORECASE)
_TOKEN = re.compile(  # any `github` that is not one of its named fields, the token aside
    r"\bgithub\b(?:\s*\[|\s*\.\s*token\b|(?!\s*\.\s*[A-Za-z_]))", re.IGNORECASE
)
_INHERIT = re.compile(r"\bsecrets\s*:\s*inherit\b", re.IGNORECASE)
# A step's outputs, which may hold a token: any `steps`, by the output it names if it names one.
_STEPS = re.compile(
    r"\bsteps\b(?:\s*\.\s*[A-Za-z_][\w-]*\s*\.\s*outputs\s*\.\s*[A-Za-z_][\w-]*)?", re.IGNORECASE
)


def secrets_used(text: str) -> set[str]:
    """The secrets a workflow's text names, by name, and every other way to a secret, the token
    included, by the text that reaches it: any `secrets` not followed by a name, any `github`
    that is not one of its named fields, any `steps`."""
    used: set[str] = {match.group(0) for match in _INHERIT.finditer(text)}
    for expression in _expressions(text):
        named = _NAMED_SECRET.findall(expression)
        used |= {name.upper() for name in named}
        if len(_SECRETS.findall(expression)) > len(named):
            used.add("secrets")
        used |= {match.group(0) for match in _TOKEN.finditer(expression)}
        used |= {match.group(0) for match in _STEPS.finditer(expression)}
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
        ("one: ${{ format('{{x}} {0}', secrets.FOO) }}", {"FOO"}),
        ("one: ${{ format('it''s }} {0}', secrets.FOO) }}", {"FOO"}),
        ("open: ${{ secrets.FOO", {"FOO"}),
        ("token: ${{ github.token }}", {"github.token"}),
        ("token: ${{ GitHub . Token }}", {"GitHub . Token"}),
        ("token: ${{ github['token'] }}", {"github["}),
        ("all: ${{ toJSON(github) }}", {"github"}),
        ("all: ${{ toJSON(github.*) }}", {"github"}),
        ("all: ${{ toJSON(github . *) }}", {"github"}),
        ("uses: ./.github/workflows/x.yml\n    secrets: inherit", {"secrets: inherit"}),
        ("ref: ${{ github.event.pull_request.base.sha }}", set()),
        ("run: echo the secrets of a scenario, on GitHub, from https://github.com/x", set()),
        ("run: echo ${{ github.tokens_count }}", set()),
        ("token: ${{ steps.app.outputs.token }}", {"steps.app.outputs.token"}),
        ("all: ${{ toJSON(steps) }}", {"steps"}),
        ("id: ${{ vars.RELEASE_APP_ID }}", set()),
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
    if path.name in SECRET_JOBS:
        document = _load(path)
        assert "env" not in document  # never every job's
        assert "defaults" not in document
        for name, job in document["jobs"].items():
            assert "env" not in job, name  # never every step's
            assert "defaults" not in job, name
            names = [step["name"] for step in job["steps"]]
            assert len(names) == len(set(names)), name  # a name allowed is one step only
            allowed = SECRET_STEPS[path.name].get(name, {})
            for step in job["steps"]:
                if workflow_secrets(yaml.safe_dump(step)):
                    assert step == {"name": step["name"], **allowed[step["name"]]}, step["name"]


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
    assert set(ALLOWED_JOB_PERMISSIONS) <= names
    assert set(SECRET_JOBS) <= names
    assert set(WRITING_JOBS) <= names
    assert set(ENVIRONMENTS) <= names


def test_the_two_builds_of_a_release_are_the_same_job() -> None:
    """What makes them independent is that they run apart, never that they differ."""
    jobs = _load(DIRECTORY / "release.yml")["jobs"]
    one, two = (yaml.safe_dump(jobs[name]) for name in ("build-one", "build-two"))

    assert one.replace("release-one", "X").replace("first runner", "Y") == (
        two.replace("release-two", "X").replace("second runner", "Y")
    )


def test_a_release_is_built_by_hand_from_the_default_branch_and_from_the_approvals() -> None:
    """Its approvals job runs the tools with the token: what it runs is first the branch whose
    changes were reviewed, compared by the shell, where case counts."""
    document = _load(DIRECTORY / "release.yml")
    jobs = document["jobs"]
    first = jobs["approvals"]["steps"][0]

    assert set(_triggers(document)) == {"workflow_dispatch"}
    assert first["name"] == "Build from the default branch only"
    assert first["env"] == {"DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}"}
    assert (
        'if [ -z "$DEFAULT_BRANCH" ] || [ "$GITHUB_REF" != "refs/heads/$DEFAULT_BRANCH" ]'
        in (first["run"])
    )
    assert "exit 1" in first["run"]
    assert "if" not in first
    assert (jobs["build-one"]["needs"], jobs["build-two"]["needs"]) == ("approvals", "approvals")
    assert jobs["compare"]["needs"] == ["build-one", "build-two"]
    [*_, compared, verified] = [step["name"] for step in jobs["compare"]["steps"]]
    assert (compared, verified) == (
        "Compare them byte for byte",
        "Verify the release as its consumers will",
    )
    assert (
        'scenario-tools verify "$RUNNER_TEMP"/one/manifest.json'
        in (jobs["compare"]["steps"][-1]["run"])
    )


def test_a_release_is_published_after_its_builds_compared_approved_and_verified() -> None:
    """The release published is the one compared and verified, approved by who started the run,
    verified again once approved; it never replaces a release, is read back and checked against
    the next pointer, and the channel moves last."""
    jobs = _load(DIRECTORY / "release.yml")["jobs"]
    publish = jobs["publish"]
    names = [step["name"] for step in publish["steps"]]
    steps = {step["name"]: step for step in publish["steps"]}

    assert publish["needs"] == "compare"
    assert steps["Take the release built"]["with"]["name"] == "release-one"
    assert names[names.index("Approve the release") :] == [
        "Approve the release",
        "Verify the approved release as its consumers will",
        "Write the channel's next pointer",
        "Publish the release",
        "Check the published release against the next pointer",
        "Take a token of the release app",
        "Move the channel to the release",
        "Say what was published",
    ]
    assert steps["Approve the release"]["env"] == {"APPROVER": "${{ github.triggering_actor }}"}
    assert "--approved" in steps["Verify the approved release as its consumers will"]["run"]
    assert "a release is never replaced" in steps["Publish the release"]["run"]
    assert steps["Check the published release against the next pointer"]["run"] == (
        'uv run --frozen --no-dev scenario-tools channel previous --pointer "$RUNNER_TEMP/point'
        'er/${CHANNEL}.json" --manifest "$RUNNER_TEMP"/published/manifest.json --channel "$CHAN'
        'NEL"\n'
        'uv run --frozen --no-dev scenario-tools verify "$RUNNER_TEMP"/published/manifest.json '
        "--schemas schemas --approved\n"
    )


def test_every_build_is_made_against_the_channel_s_previous_release() -> None:
    jobs = _load(DIRECTORY / "release.yml")["jobs"]
    approvals = [step["name"] for step in jobs["approvals"]["steps"]]

    assert approvals.index("Read the channel's previous release") < approvals.index(
        "Check the previous release against the channel's pointer"
    )
    for name in ("build-one", "build-two"):
        build = {step["name"]: step for step in jobs[name]["steps"]}["Build the release"]
        assert '--previous-release "$previous"' in build["run"]


def test_one_release_runs_at_a_time_and_no_step_is_skipped_or_let_fail() -> None:
    document = _load(DIRECTORY / "release.yml")

    assert document["concurrency"] == {"group": "release", "cancel-in-progress": False}
    for name, job in document["jobs"].items():
        assert "if" not in job, name
        assert "continue-on-error" not in job, name
        for step in job["steps"]:
            assert "if" not in step, step["name"]
            assert "continue-on-error" not in step, step["name"]
