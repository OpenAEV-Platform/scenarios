"""Materialise a scenario entry on a ``scenario-publish/*`` branch.

The Publisher agent commits ``.scenario-publish/publish.yaml`` to a ``scenario-publish/*``
branch and opens a draft pull request. This script runs in the scenario-publish
Action to fill that pull request:

1. read and schema-check the staging file;
2. export ``scenario_id`` from the author OpenAEV platform (``scenario-tools``
   reads ``OPENAEV_URL`` / ``OPENAEV_TOKEN`` from the environment);
3. run ``scenario-tools intake`` to write the catalogue entry, then ``validate``
   it as a smoke check;
4. remove the staging file;
5. commit the result as ONE GitHub-verified commit through the REST API, so the
   repository's signed-commit rule is met and the author is the bot, not a
   person. The pull request's existing checks then judge the entry.

No token is ever printed. The export subprocess reads ``OPENAEV_TOKEN`` itself
and hides it from its own output; this script only sends ``GITHUB_TOKEN`` in an
Authorization header.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
import yaml

_API = "https://api.github.com"
_STAGING = ".scenario-publish/publish.yaml"


def _fail(message: str) -> None:
    print(f"scenario-publish: {message}", file=sys.stderr)
    raise SystemExit(1)


def _run(args: list[str], *, cwd: Path) -> None:
    """Run a command, streaming its output; fail the job if it does."""
    print(f"$ {' '.join(args)}")
    result = subprocess.run(args, cwd=cwd, check=False)
    if result.returncode != 0:
        _fail(f"'{' '.join(args[:2])}' exited {result.returncode}")


def _git(args: list[str], *, cwd: Path) -> str:
    """Run a read-only git command and return its stdout."""
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def _load_staging(root: Path) -> dict[str, Any]:
    path = root / _STAGING
    if not path.is_file():
        print(f"scenario-publish: no {_STAGING} on this branch; nothing to do.")
        raise SystemExit(0)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    schema = json.loads((root / "schemas" / "scenario-publish.schema.json").read_text("utf-8"))
    try:
        jsonschema.validate(document, schema)
    except jsonschema.ValidationError as error:
        _fail(f"{_STAGING} is not a valid publish request: {error.message}")
    return document


def _materialise(root: Path, staging: dict[str, Any], work: Path) -> str:
    """Export, intake and validate; return the entry path written in the repo."""
    scenario_id = staging["scenario_id"]
    request = staging["request"]
    entry = f"scenarios/{request['domain']}/{request['slug']}"

    request_file = work / "request.yaml"
    request_file.write_text(yaml.safe_dump(request, sort_keys=False), encoding="utf-8")
    export = work / "export.zip"

    _run(["scenario-tools", "openaev", "export", scenario_id, "--out", str(export)], cwd=root)
    _run(
        [
            "scenario-tools",
            "intake",
            str(export),
            "--request",
            str(request_file),
            "--repo",
            ".",
            "--plan",
            str(work / "plan.md"),
        ],
        cwd=root,
    )
    # A smoke check with the repository's own rules; the pull request's pr-entries
    # does the authoritative check against the base branch.
    _run(["scenario-tools", "validate", "--", entry], cwd=root)
    return entry


def _remove_staging(root: Path) -> None:
    (root / _STAGING).unlink()
    staging_dir = root / ".scenario-publish"
    if not any(staging_dir.iterdir()):
        staging_dir.rmdir()


def _changes(root: Path) -> tuple[list[str], list[str]]:
    """The paths written and the paths removed, from the staged diff against HEAD."""
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    fields = _git(["diff", "--cached", "--name-status", "-z"], cwd=root).split("\0")
    written: list[str] = []
    removed: list[str] = []
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        if status.startswith("R"):  # rename: old path removed, new path written
            removed.append(fields[i + 1])
            written.append(fields[i + 2])
            i += 3
            continue
        (removed if status == "D" else written).append(fields[i + 1])
        i += 2
    return written, removed


def _api(token: str, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{_API}{path}", data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        _fail(f"GitHub API {method} {path} -> {error.code} {error.read().decode(errors='replace')}")
        raise  # unreachable; _fail raises


def _commit(
    root: Path,
    repo: str,
    branch: str,
    token: str,
    written: list[str],
    removed: list[str],
    message: str,
) -> str:
    """Create one GitHub-verified commit from the changes, advance the branch."""
    head = _git(["rev-parse", "HEAD"], cwd=root).strip()
    base_tree = _api(token, "GET", f"/repos/{repo}/git/commits/{head}")["tree"]["sha"]

    tree: list[dict[str, Any]] = []
    for path in written:
        content = base64.b64encode((root / path).read_bytes()).decode()
        sha = _api(
            token,
            "POST",
            f"/repos/{repo}/git/blobs",
            {"content": content, "encoding": "base64"},
        )["sha"]
        tree.append({"path": path, "mode": "100644", "type": "blob", "sha": sha})
    for path in removed:
        tree.append({"path": path, "mode": "100644", "type": "blob", "sha": None})

    new_tree = _api(
        token, "POST", f"/repos/{repo}/git/trees", {"base_tree": base_tree, "tree": tree}
    )["sha"]
    commit = _api(
        token,
        "POST",
        f"/repos/{repo}/git/commits",
        {"message": message, "tree": new_tree, "parents": [head]},
    )["sha"]
    _api(token, "PATCH", f"/repos/{repo}/git/refs/heads/{branch}", {"sha": commit, "force": False})
    return commit


def main() -> None:
    root = Path.cwd()
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    branch = os.environ.get("GITHUB_REF_NAME", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not (repo and branch and token):
        _fail("GITHUB_REPOSITORY, GITHUB_REF_NAME and GITHUB_TOKEN are required")

    staging = _load_staging(root)
    # Outside the repo: intake refuses a dirty checkout, so nothing it does not write lands there.
    with tempfile.TemporaryDirectory() as tmp:
        entry = _materialise(root, staging, Path(tmp))
    _remove_staging(root)

    written, removed = _changes(root)
    if not written:
        _fail("intake wrote no entry files; see the log above")
    request = staging["request"]
    verb = "add" if request["mode"] == "new" else "update"
    message = f"feat(scenarios): {verb} {request['domain']}/{request['slug']} (#{request['issue']})"
    commit = _commit(root, repo, branch, token, written, removed, message)

    line = f"Materialised `{entry}` and committed it as `{commit[:9]}` (verified)."
    print(f"scenario-publish: {line}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(f"## Scenario publish\n\n{line}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
