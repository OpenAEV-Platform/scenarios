"""The commands the snapshot test runs, and how one is run.

Each case runs one command of the tools, in process, in a workspace of its own: a git checkout
of the reference corpus, committed at a fixed time, with the clock, the time zone and the locale
fixed. The corpus is a frozen copy, in ``corpus/``, of the catalogue's entries (one of them in
chaining), ``payloads/``, the schemas and policy data, the conformance fixtures and the
starter-pack exports: the catalogue keeps growing, and what a snapshot holds must change only
when the tools do. What a case gives is its output, its error output, its exit code, and the
files it wrote or changed, in the workspace or in ``outside/`` beside it, byte for byte.
"""

import contextlib
import datetime
import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import time_machine
from click.testing import CliRunner

from scenario_tools.interface.cli import main

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
INPUTS = HERE / "inputs"
EXPECTED = HERE / "expected"

MOMENT = datetime.datetime(2026, 10, 30, 9, 15, 2, tzinfo=datetime.UTC)
GIT_DATE = "2026-10-30T09:15:02+00:00"
ENVIRONMENT = {
    "TZ": "UTC",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "SOURCE_DATE_EPOCH": str(int(MOMENT.timestamp())),
    "GIT_AUTHOR_NAME": "snapshot",
    "GIT_AUTHOR_EMAIL": "snapshot@example.invalid",
    "GIT_COMMITTER_NAME": "snapshot",
    "GIT_COMMITTER_EMAIL": "snapshot@example.invalid",
    "GIT_AUTHOR_DATE": GIT_DATE,
    "GIT_COMMITTER_DATE": GIT_DATE,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "NO_COLOR": "1",
    "COLUMNS": "80",  # click wraps its help to the terminal's width
    "LINES": "24",
}
# What the developer's environment may hold that a command reads: left out of every case.
UNSET = ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "OPENAEV_URL", "OPENAEV_TOKEN", "XDG_CONFIG_HOME")
STARTER = sorted(path.name for path in (CORPUS / "exports").glob("*.zip"))
ENTRIES = sorted(
    path.parent.relative_to(CORPUS).as_posix()
    for path in (CORPUS / "scenarios").glob("*/*/scenario.yaml")
)
RELEASES = sorted(
    path.name for path in (CORPUS / "conformance" / "releases").iterdir() if path.is_dir()
)
LARGE = 16 * 1024  # bytes of a written file kept as it is
BASE = "@BASE@"  # replaced, when the case runs, by the full ID of the commit before the last


@dataclass(frozen=True)
class Case:
    """One command, with the arguments it is given in its workspace, and the workspace
    preparation it needs before it runs, if any."""

    name: str
    arguments: tuple[str, ...]
    prepare: Callable[[Path], None] | None = None


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
        ["git", "-C", str(root), *arguments],  # noqa: S607
        env={**os.environ, **ENVIRONMENT},
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def workspace(into: Path) -> Path:
    """A git checkout of the corpus at ``into``, committed at the fixed time, with an empty
    ``out/`` for what the commands write, which git does not track."""
    shutil.copytree(CORPUS, into, symlinks=True)
    shutil.copytree(INPUTS, into / "inputs", symlinks=True)
    (into / ".gitignore").write_text("/out/\n")
    _git(into, "init", "-q", "-b", "main")
    _git(into, "add", "-A")
    _git(into, "commit", "-q", "-m", "corpus")
    (into / "out").mkdir()
    return into


def _approvals(workspace: Path) -> None:
    """The approvals file build reads, beside the workspace, naming every entry, for the commit
    of the workspace."""
    commit = _git(workspace, "rev-parse", "HEAD")
    entries = {entry: {"pull_request": 1, "approvers": ["snapshot"]} for entry in ENTRIES}
    document = {"schema_version": 1, "commit": commit, "entries": entries}
    (workspace.parent / "outside" / "approvals.json").write_text(
        json.dumps(document, indent=2) + "\n"
    )


def _second_commit(workspace: Path) -> None:
    """A commit changing an entry's changelog, for changed-entries to compare with the first."""
    changelog = workspace / ENTRIES[0] / "CHANGELOG.md"
    changelog.write_text(changelog.read_text(encoding="utf-8") + "\n- A change.\n")
    _git(workspace, "commit", "-q", "-am", "change")


def _changed(workspace: Path) -> None:
    """The base branch beside the workspace, in ``outside/base``, and in the workspace a changed
    description in the first entry's metadata and a changed step title in the entry in chaining,
    for the version checks to compare."""
    base = workspace.parent / "outside" / "base"
    for part in ("scenarios", "payloads"):
        shutil.copytree(workspace / part, base / part, symlinks=True)
    metadata = workspace / ENTRIES[0] / "scenario.yaml"
    text = metadata.read_text(encoding="utf-8")
    metadata.write_text(text.replace("description: |-\n  ", "description: |-\n  Changed. ", 1))
    stored = workspace / ENTRIES[-1] / "scenario.json"
    text = stored.read_text(encoding="utf-8")
    stored.write_text(text.replace("Step 1 - list processes", "Step 1 - list the processes", 1))


def _formats(
    name: str, *arguments: str, prepare: Callable[[Path], None] | None = None
) -> Iterator[Case]:
    """The case in text and in JSON."""
    yield Case(f"{name}.text", arguments, prepare)
    yield Case(f"{name}.json", ("--format", "json", *arguments), prepare)


def _cases() -> Iterator[Case]:
    yield from _formats("check-title.valid", "check-title", "feat(scenarios): add a scenario (#1)")
    yield from _formats("check-title.invalid", "check-title", "Add a scenario")
    yield Case("usage.no-command", ())
    yield Case("usage.unknown-command", ("nonexistent",))
    yield Case("usage.validate-without-entry", ("validate",))
    yield from _formats("validate.catalogue", "validate", *ENTRIES)
    for entry in ENTRIES:
        slug = entry.rsplit("/", 1)[-1]
        yield from _formats(f"validate.{slug}", "validate", entry)
        yield from _formats(f"render-check.{slug}", "render", "--check", entry)
        yield from _formats(f"payloads.{slug}", "payloads", entry)
        yield from _formats(f"archive.{slug}", "archive", entry, "--out", f"out/{slug}.zip")
        yield from _formats(f"diff.{slug}", "diff", entry, "--previous-root", ".")
    for entry in ENTRIES:
        slug = entry.rsplit("/", 1)[-1]
        for command in ("diff", "validate"):
            yield from _formats(
                f"{command}.changed.{slug}", command, entry, "--previous-root", "../outside/base",
                prepare=_changed,
            )  # fmt: skip
    yield from _formats(
        "validate-payloads.changed", "validate-payloads", "payloads",
        "--previous-root", "../outside/base", prepare=_changed,
    )  # fmt: skip
    yield from _formats("render.catalogue", "render", *ENTRIES)
    yield from _formats("validate-payloads", "validate-payloads", "payloads")
    yield from _formats(
        "validate-payloads.previous-root", "validate-payloads", "payloads", "--previous-root", "."
    )
    for export in STARTER:
        stem = export.removesuffix(".zip")
        yield from _formats(
            f"normalize.{stem}", "normalize", f"exports/{export}", "--out", "out",
            "--external-id", "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
        )  # fmt: skip
        yield from _formats(
            f"intake-check.{stem}", "intake", f"exports/{export}", "--check",
            "--payloads", "payloads", "--rules", ".",
            "--external-id", "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42",
        )  # fmt: skip
    for request in sorted(path.stem for path in (INPUTS / "requests").glob("*.yaml")):
        export, _, _ = request.partition("--")
        yield from _formats(
            f"intake.{request}", "intake", f"exports/{export}.zip",
            "--request", f"inputs/requests/{request}.yaml", "--repo", ".",
            "--plan", "out/plan.md",
        )  # fmt: skip
    yield from _formats(
        "build.edge", "build", "--repo", ".", "--previous-release", "none", "--channel", "edge",
        "--approvals", "../outside/approvals.json", "--out", "../outside/release",
        prepare=_approvals,
    )  # fmt: skip
    yield from _formats(
        "changed-entries", "changed-entries", ".", "--base", BASE, prepare=_second_commit
    )
    for release in RELEASES:
        yield from _formats(
            f"verify.{release}", "verify", f"conformance/releases/{release}/manifest.json",
            "--schemas", "schemas",
        )  # fmt: skip
    yield from _formats("conformance-run", "conformance", "run", "conformance/releases",
                        "--schemas", "schemas")  # fmt: skip
    yield from _formats("conformance-build", "conformance", "build", "--out", "out/fixtures")


CASES = tuple(_cases())
assert len({case.name for case in CASES}) == len(CASES), "two cases share a name"


def _snapshot(directory: Path) -> dict[str, bytes]:
    """Every regular file and link under ``directory``, by its path relative to it, with git's
    own files left out."""
    found: dict[str, bytes] = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if "/.git/" in f"/{relative}/":
            continue
        if path.is_symlink():
            found[relative] = b"-> " + str(path.readlink()).encode()
        elif path.is_file():
            found[relative] = path.read_bytes()
    return found


def _kept(data: bytes) -> bytes:
    """What a snapshot holds of written bytes: the bytes, or, past ``LARGE`` bytes, their SHA-256
    and size, which tell them apart as strictly."""
    if len(data) > LARGE:
        return f"sha256 {hashlib.sha256(data).hexdigest()} size {len(data)}\n".encode()
    return data


def _stream(data: bytes) -> bytes:
    """What a snapshot holds of an output stream: as ``_kept``, but in hexadecimal when it holds
    a null character, as the list changed-entries writes for xargs does: no text file of the
    repository may hold one raw."""
    if b"\x00" in data and len(data) <= LARGE:
        return b"hex " + data.hex().encode() + b"\n"
    return _kept(data)


def run(case: Case, base: Path) -> dict[str, bytes]:
    """What ``case`` gives, run in a fresh workspace under ``base``: ``exit``, ``stdout``,
    ``stderr``, and ``files/<path>`` for each file it wrote or changed."""
    root = workspace(base / "workspace")
    (base / "outside").mkdir()
    home = base / "home"  # git reads its user configuration there: an empty one
    home.mkdir()
    if case.prepare is not None:
        case.prepare(root)
    arguments = [
        _git(root, "rev-parse", "HEAD~1") if argument == BASE else argument
        for argument in case.arguments
    ]
    before = _snapshot(base)
    with contextlib.chdir(root), time_machine.travel(MOMENT, tick=False):
        environment = {**ENVIRONMENT, "HOME": str(home), **dict.fromkeys(UNSET)}
        result = CliRunner().invoke(main, arguments, env=environment)
    after = _snapshot(base)
    given = {
        "exit": f"{result.exit_code}\n".encode(),
        "stdout": _stream(result.stdout_bytes),
        "stderr": _stream(result.stderr_bytes),
    }
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        given["exception"] = f"{type(result.exception).__name__}\n".encode()
    for path, data in after.items():
        if before.get(path) != data:
            given[f"files/{path}"] = _kept(data)
    for path in before.keys() - after.keys():
        given[f"files/{path}"] = b"(removed)\n"
    return given


def expected(case: Case) -> dict[str, bytes]:
    """The snapshot recorded for ``case``."""
    directory = EXPECTED / case.name
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }
