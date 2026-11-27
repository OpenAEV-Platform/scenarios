"""Materialise a scenario entry on a ``scenario-publish/*`` branch.

The Publisher agent exports the scenario itself, its lab targets already
neutralised, and commits two files to the branch: ``.scenario-publish/export.zip``
(the platform export, a ``.zip`` so a scenario with documents survives) and
``.scenario-publish/request.yaml`` (the intake request). This script runs in the
scenario-publish Action, from the base branch (``pull_request_target``), to fill
the draft pull request, with **no call to the OpenAEV platform**. The pull
request's head is checked out beside the base, in ``pull/``, as data only:

1. copy the staging files out of ``pull/`` (regular files only, never a link),
   then drop ``pull/`` so the base checkout stays clean for intake;
2. neutralise any lab target left in the export, as POL-003 reads them;
3. run ``scenario-tools intake`` on the base checkout to write the catalogue
   entry, then ``validate`` it as a smoke check;
4. commit the entry and the removal of the staging files as ONE commit on top of
   the pull request's head, through the REST API with a token of the publish app,
   so the author is the app (not a person), the commit is GitHub-verified,
   and — unlike ``GITHUB_TOKEN`` — it triggers the pull request's checks. The
   existing checks then judge the entry.

No OpenAEV URL or token is needed here any more; the only secret this uses is the
publish app's GitHub token, sent in an Authorization header.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jsonschema
import yaml

from scenario_tools.domain.policy.targets import AllowedTargets

_API = "https://api.github.com"
_STAGING_DIR = ".scenario-publish"
_REQUEST = f"{_STAGING_DIR}/request.yaml"
#: The export the Publisher committed, by preference: a .zip (keeps documents),
#: or the .json intake also accepts.
_EXPORT_NAMES = ("export.zip", "export.json")
#: The example host and sender a lab target is neutralised to for publication.
_EXAMPLE_HOST = "host.example.com"
_EXAMPLE_IPV4 = "192.0.2.10"  # RFC 5737
_EXAMPLE_IPV6 = "2001:db8::10"  # RFC 3849
_EXAMPLE_SENDER = "user@example.com"
#: Where the pull request's head is checked out, as data, beside the base.
_PULL = "pull"
#: The separators of a list of targets typed by hand: kept as they are.
_TARGET_SEPARATORS = re.compile(r"([,;\s]+)")
#: A platform variable, filled at launch: never a host to rewrite.
_VARIABLE = re.compile(r"#\{|\$\{|\{\{")


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


def _staging(root: Path, work: Path) -> tuple[dict[str, Any], Path, Path, list[str]]:
    """The intake request (schema-checked) and the export the Publisher committed, copied from the
    pull request's head (``pull/``) into ``work``, with the staging paths to remove from the branch.
    Only regular files are taken: a link, which could point anywhere, is refused."""
    staging = root / _PULL / _STAGING_DIR
    if staging.is_symlink() or not staging.is_dir():
        print(f"scenario-publish: no {_STAGING_DIR}/ on this branch; nothing to do.")
        raise SystemExit(0)
    names = sorted(child.name for child in staging.iterdir())
    for name in names:
        member = staging / name
        if member.is_symlink() or not member.is_file():
            _fail(f"{_STAGING_DIR}/{name} is not a regular file")
    if "request.yaml" not in names:
        print(f"scenario-publish: no {_REQUEST} on this branch; nothing to do.")
        raise SystemExit(0)
    export_name = next((name for name in _EXPORT_NAMES if name in names), None)
    if export_name is None:
        _fail(f"{_REQUEST} is present but no {' or '.join(_EXPORT_NAMES)} beside it")
    request_path = work / "request.yaml"
    export_path = work / str(export_name)
    shutil.copyfile(staging / "request.yaml", request_path)
    shutil.copyfile(staging / str(export_name), export_path)

    request = yaml.safe_load(request_path.read_text(encoding="utf-8"))
    schema = json.loads((root / "schemas" / "intake-request.schema.json").read_text("utf-8"))
    try:
        jsonschema.validate(request, schema)
    except jsonschema.ValidationError as error:
        _fail(f"{_REQUEST} is not a valid intake request: {error.message}")
    if request["mode"] != "new":
        # An update needs its version, changelog and sheet completed after intake and validated
        # against the previous version; a maintainer does it in V1.
        _fail("only a new entry is published this way in V1; an update goes through a maintainer")
    return request, export_path, request_path, [f"{_STAGING_DIR}/{name}" for name in names]


def _allowed_targets(root: Path) -> AllowedTargets:
    """What a published entry may name, from the policy data POL-003 reads."""
    document = yaml.safe_load(
        (root / "policy" / "data" / "allowed-targets.yaml").read_text(encoding="utf-8")
    )
    return AllowedTargets.from_document(document)


def _replacement(host: str) -> str:
    """The example a real host or address becomes: a name, or a documentation address."""
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return _EXAMPLE_HOST
    return _EXAMPLE_IPV4 if address.version == 4 else _EXAMPLE_IPV6


def _neutral_url(url: str, allowed: AllowedTargets, neutralised: set[str]) -> str:
    """``url`` with its host neutralised, scheme, user, port, path, query and fragment kept."""
    parts = urlsplit(url)
    host = parts.hostname
    if not host or allowed.allows(host):
        return url
    neutralised.add(host)
    new_host = _replacement(host)
    if ":" in new_host:
        new_host = f"[{new_host}]"
    user = parts.netloc.rpartition("@")[0]
    netloc = (f"{user}@" if user else "") + new_host
    if parts.port is not None:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _neutral_target(token: str, allowed: AllowedTargets, neutralised: set[str]) -> str:
    """One target typed by hand: a URL, a host, a host and its port, or an address."""
    if not token or _VARIABLE.search(token):
        return token
    if "://" in token:
        return _neutral_url(token, allowed, neutralised)
    host, port = token, ""
    if token.startswith("["):  # [IPv6]:port
        host, _, rest = token[1:].partition("]")
        port = rest
    elif token.count(":") == 1:  # host:port; several colons are an IPv6 address
        host, _, after = token.partition(":")
        port = f":{after}"
    if allowed.allows(host):
        return token
    neutralised.add(host)
    new_host = _replacement(host)
    if ":" in new_host and port:
        new_host = f"[{new_host}]"
    return new_host + port


def _sanitise_scenario(scenario: dict[str, Any], allowed: AllowedTargets) -> bool:
    """Point every lab target at an example host or address and the sender at the example
    address, so a published entry never names a real system: the URL of an HTTP query, and the
    targets typed by hand of a scanner (Nuclei, Nmap). Returns whether anything changed."""
    changed = False
    information = scenario.get("scenario_information")
    if isinstance(information, dict):
        sender = information.get("scenario_mail_from")
        if (
            isinstance(sender, str)
            and "@" in sender
            and not allowed.example_domain(sender.rsplit("@", 1)[1])
        ):
            information["scenario_mail_from"] = _EXAMPLE_SENDER
            changed = True
    neutralised: set[str] = set()
    injects = [
        inject for inject in scenario.get("scenario_injects") or [] if isinstance(inject, dict)
    ]
    for inject in injects:
        content = inject.get("inject_content")
        if not isinstance(content, dict):
            continue
        uri = content.get("uri")
        if isinstance(uri, str) and uri:
            new = _neutral_url(uri, allowed, neutralised)
            if new != uri:
                content["uri"] = new
                changed = True
        targets = content.get("targets")
        if content.get("target_selector") == "manual" and isinstance(targets, str):
            pieces = _TARGET_SEPARATORS.split(targets)
            new = "".join(
                piece if index % 2 else _neutral_target(piece, allowed, neutralised)
                for index, piece in enumerate(pieces)
            )
            if new != targets:
                content["targets"] = new
                changed = True
    # The same real hosts may be named in the prose; replace exactly the hosts just neutralised,
    # so no text points at a real system either, without guessing at other words.
    texts: list[tuple[dict[str, Any], str]] = []
    if isinstance(information, dict):
        texts.append((information, "scenario_description"))
    texts += [(inject, key) for inject in injects for key in ("inject_title", "inject_description")]
    for holder, key in texts:
        text = holder.get(key)
        if not isinstance(text, str):
            continue
        new = text
        for host in sorted(neutralised, key=len, reverse=True):
            new = new.replace(host, _replacement(host))
        if new != text:
            holder[key] = new
            changed = True
    return changed


def _sanitise_export(export: Path, allowed: AllowedTargets) -> None:
    """Neutralise the lab targets in the export in place, before intake reads it. The Publisher
    already exports them neutralised; this is the second line, as POL-003 reads them."""
    if export.suffix == ".json":
        scenario = json.loads(export.read_text(encoding="utf-8"))
        if _sanitise_scenario(scenario, allowed):
            export.write_text(json.dumps(scenario, ensure_ascii=False), encoding="utf-8")
        return
    with zipfile.ZipFile(export) as archive:
        infos = archive.infolist()  # kept whole: writestr(info, ...) preserves the entry comment
        data = {info.filename: archive.read(info.filename) for info in infos}
    changed = False
    for info in infos:
        # The scenario entry is the member the platform commented "Scenario", whatever its name.
        if info.comment == b"Scenario":
            scenario = json.loads(data[info.filename].decode("utf-8"))
            if _sanitise_scenario(scenario, allowed):
                data[info.filename] = json.dumps(scenario, ensure_ascii=False).encode("utf-8")
                changed = True
    if changed:
        with zipfile.ZipFile(export, "w", zipfile.ZIP_DEFLATED) as archive:
            for info in infos:
                archive.writestr(info, data[info.filename])


def _materialise(
    root: Path, request: dict[str, Any], export: Path, request_path: Path, work: Path
) -> str:
    """Intake the committed export, validate the entry; return its path in the repo."""
    entry = f"scenarios/{request['domain']}/{request['slug']}"
    _run(
        [
            "scenario-tools",
            "intake",
            str(export),
            "--request",
            str(request_path),
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


def _changes(root: Path) -> list[str]:
    """The paths intake wrote in the base checkout, from the staged diff against its commit."""
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    fields = _git(["diff", "--cached", "--name-status", "-z"], cwd=root).split("\0")
    written: list[str] = []
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        if status.startswith(("R", "C")) or status == "D":
            _fail(f"intake did more than write files ({status} {fields[i + 1]})")
        written.append(fields[i + 1])
        i += 2
    return written


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
    head: str,
    token: str,
    written: list[str],
    removed: list[str],
    message: str,
) -> str:
    """Create one GitHub-verified commit on top of the pull request's ``head``: the files intake
    wrote in the base checkout, the staging files removed. Advance the branch, never forcing it, so
    a branch that moved since the event is refused rather than overwritten."""
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
    branch = os.environ.get("HEAD_REF", "")
    head = os.environ.get("HEAD_SHA", "")
    # The publish app's token: its commit triggers the pull request's checks
    # (a GITHUB_TOKEN commit does not), and it keeps the author off a real person.
    token = os.environ.get("PUBLISH_TOKEN", "")
    if not (repo and branch and head and token):
        _fail("GITHUB_REPOSITORY, HEAD_REF, HEAD_SHA and PUBLISH_TOKEN are required")
    if not branch.startswith("scenario-publish/"):
        _fail(f"refused: {branch} is not a scenario-publish/ branch")

    # Outside the repo: intake refuses a dirty checkout, so nothing it does not write lands there.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        request, export, request_path, staged = _staging(root, work)
        shutil.rmtree(root / _PULL)  # the pull request's data, copied out: the checkout is clean
        # Neutralise the lab targets before intake: the lab exercised the real host, the
        # published entry ships the example one, as the catalogue policy requires.
        _sanitise_export(export, _allowed_targets(root))
        entry = _materialise(root, request, export, request_path, work)

    written = _changes(root)
    if not written:
        _fail("intake wrote no entry files; see the log above")
    message = f"feat(scenarios): add {request['domain']}/{request['slug']} (#{request['issue']})"
    commit = _commit(root, repo, branch, head, token, written, staged, message)

    line = f"Materialised `{entry}` and committed it as `{commit[:9]}`."
    print(f"scenario-publish: {line}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(f"## Scenario publish\n\n{line}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
