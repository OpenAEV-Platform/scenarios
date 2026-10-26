"""The hostile corpus: inputs built to break the tools in a way they were once found open to, each
with the command that reads it and how it must be refused.

A case is refused with its finding code and exit code 1, or, for what the tools read as the
environment rather than content, exit code 3 and the cause said; never exit code 4, an internal
error, and never a traceback. It runs in a process of its own, in a git checkout of the reference
corpus the snapshot test uses, within a budget of time and of memory (peak resident size).

The small inputs are versioned in ``inputs/``; the large ones, and those git refuses to check out,
are built when the case runs, the same bytes every time.
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from tests.snapshots.cases import ENTRIES, ENVIRONMENT, UNSET, workspace

HERE = Path(__file__).resolve().parent
INPUTS = HERE / "inputs"
TOOLS = Path(sys.executable).parent / "scenario-tools"
LAUNCHER = HERE / "launcher.py"
ENTRY = ENTRIES[0]
EXTERNAL_ID = "00000000-0000-4000-8000-000000000001"
JSON_LIMIT = 20 * 1024 * 1024  # what the readers accept of one JSON file
VALUE_LIMIT = 500_000  # and of the values it holds, counted by its commas and opening brackets


@dataclass(frozen=True)
class Case:
    """An input, the command that reads it, and how it must be refused."""

    name: str
    flaw: str  # what the input does, one sentence
    prepare: Callable[[Path], tuple[str, ...]]  # writes the input, gives the command's arguments
    code: str | None  # the finding code; none for an environment refusal
    exit_code: int = 1
    seconds: float = 10.0
    mebibytes: int = 128  # the tools take some 30 MiB to start


@dataclass(frozen=True)
class Outcome:
    exit_code: int
    output: str
    seconds: float
    mebibytes: float


def renamed_entry() -> bytes:
    """A ZIP whose one entry is declared ``scenario.json`` while its Info-ZIP Unicode path field
    (0x7075) names ``../../escaped.json``, the name the zip library would report."""
    declared, published = b"scenario.json", b"../../escaped.json"
    extra = struct.pack("<HHBI", 0x7075, 5 + len(published), 1, zlib.crc32(declared)) + published
    data = b"{}"
    crc = zlib.crc32(data)
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, crc, len(data), len(data),
        len(declared), len(extra),
    ) + declared + extra + data  # fmt: skip
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0x21, crc, len(data), len(data),
        len(declared), len(extra), 0, 0, 0, 0, 0,
    ) + declared + extra  # fmt: skip
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def _zip_renamed(root: Path) -> tuple[str, ...]:
    shutil.copyfile(INPUTS / "renamed-entry.zip", root / "out" / "renamed-entry.zip")
    return ("normalize", "out/renamed-entry.zip", "--out", "out", "--external-id", EXTERNAL_ID)


def _yaml_tags(root: Path) -> tuple[str, ...]:
    metadata = root / ENTRY / "scenario.yaml"
    metadata.write_bytes(metadata.read_bytes() + (INPUTS / "tags.yaml").read_bytes())
    return ("validate", ENTRY)


def _million_items(root: Path) -> tuple[str, ...]:
    release = root / "out" / "release"
    release.mkdir()
    items = ",".join(['{"external_id":"x"}'] * 1_000_000)
    (release / "manifest.json").write_text(f'{{"schema_version":1,"items":[{items}]}}')
    return ("verify", "out/release/manifest.json", "--schemas", "schemas")


def _dot_dot_tree(root: Path) -> tuple[str, ...]:
    """A commit whose tree holds ``scenarios/../src/tool.py``, built by hand as an attacker
    would: git refuses to check such a path out, not to store it."""
    base = _git(root, "rev-parse", "HEAD")
    blob = _git(root, "hash-object", "-w", "--stdin", given="print('the pull request runs')\n")
    tree = _git(root, "mktree", given=f"100644 blob {blob}\ttool.py\n")
    for name in ("src", "..", "scenarios"):
        tree = _git(root, "mktree", "--missing", given=f"040000 tree {tree}\t{name}\n")
    commit = _git(root, "commit-tree", tree, "-p", "HEAD", "-m", "pull request")
    _git(root, "update-ref", "HEAD", commit)
    return ("changed-entries", ".", "--base", base)


def _linked_file(root: Path) -> tuple[str, ...]:
    stored = root / ENTRY / "scenario.json"
    stored.unlink()
    stored.symlink_to(root / "out" / "elsewhere.json")
    (root / "out" / "elsewhere.json").write_text("{}")
    return ("validate", ENTRY)


def _near_limit(root: Path) -> tuple[str, ...]:
    """A stored scenario just under the readers' limit, of the smallest values JSON has, so that
    it holds as many of them as its size allows."""
    count = (JSON_LIMIT - 2) // 3
    (root / ENTRY / "scenario.json").write_text("[" + ",".join(["{}"] * count) + "]")
    return ("validate", ENTRY)


def _many_values(root: Path) -> tuple[str, ...]:
    """A stored scenario holding as many values as the readers accept, of the smallest kind."""
    count = (
        VALUE_LIMIT - 1
    ) // 2  # its commas, its braces and its bracket: two per value, one more
    (root / ENTRY / "scenario.json").write_text("[" + ",".join(["{}"] * count) + "]")
    return ("validate", ENTRY)


def _escaped_values(root: Path) -> tuple[str, ...]:
    """A stored scenario whose contract copy, JSON text inside a string, holds as many values as
    the file's size allows, its braces and commas written as escapes: decoded a second time, they
    are values the file's own count would not see if escapes were not counted."""
    stored = root / ENTRY / "scenario.json"
    document = json.loads(stored.read_bytes())
    contract = document["scenario_injects"][0]["inject_injector_contract"]
    contract["injector_contract_content"] = "@inner@"
    text = json.dumps(document)
    count = (JSON_LIMIT - len(text) - 16) // 18  # each value its two braces and comma, escaped
    inner = "[" + "\\u007b\\u007d\\u002c" * count + "\\u007b\\u007d]"
    stored.write_text(text.replace('"@inner@"', f'"{inner}"'))
    return ("validate", ENTRY)


def _git(root: Path, *arguments: str, given: str = "") -> str:
    return subprocess.run(  # noqa: S603 - a fixed program, arguments of the test's own
        ["git", "-C", str(root), *arguments],  # noqa: S607
        input=given,
        env={**os.environ, **ENVIRONMENT},
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


CASES = (
    Case(
        "zip-renamed-entry",
        "a ZIP entry declared under one name, renamed by an extra field (0x7075) to a path outside",
        _zip_renamed,
        "IO-010",
    ),
    Case(
        "yaml-tags",
        "YAML tags that build values JSON does not have: a Python object, bytes, a set",
        _yaml_tags,
        "IO-006",
    ),
    Case(
        "manifest-million-items",
        "a release manifest listing a million items",
        _million_items,
        "IO-001",
    ),
    Case(
        "git-tree-dot-dot",
        "a commit whose tree holds a path with a .. component: git stores it, never checks it out",
        _dot_dot_tree,
        None,
        exit_code=3,
    ),
    Case(
        "linked-file",
        "an entry's scenario.json that is a symbolic link to a file outside the entry",
        _linked_file,
        "IO-013",
    ),
    Case(
        "json-many-values",
        "a stored scenario holding as many values as the readers accept, of the smallest kind",
        _many_values,
        "IO-014",
    ),
    Case(
        "json-escaped-values",
        "JSON text inside a string, its braces and commas escaped, decoded a second time",
        _escaped_values,
        "IO-001",
    ),
    Case(
        "json-near-limit",
        "a stored scenario just under the size limit, made of as many values as its size allows",
        _near_limit,
        "IO-001",
    ),
)


def run(case: Case, into: Path) -> Outcome:
    """Run ``case`` in a workspace at ``into``, in a process of its own started from the small
    launcher, with JSON output; a run beyond three times its budget of time is stopped."""
    root = workspace(into)
    arguments = case.prepare(root)
    report = into.parent / f"{into.name}.peak"
    environment = {key: value for key, value in os.environ.items() if key not in UNSET}
    started = time.monotonic()
    command = [sys.executable, "-I", str(LAUNCHER), str(report), str(TOOLS), "--format", "json"]
    try:
        done = subprocess.run(  # noqa: S603 - the tools themselves, arguments of the case
            [*command, *arguments],
            cwd=root,
            env={**environment, **ENVIRONMENT},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=case.seconds * 3,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise AssertionError(f"{case.name}: over {case.seconds * 3} s") from error
    return Outcome(
        done.returncode,
        done.stdout.decode(errors="replace"),
        time.monotonic() - started,
        int(report.read_text(encoding="ascii")) / 1024,  # KiB on Linux
    )
