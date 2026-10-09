"""The public repository never refers to internal planning or to internal documents.

Contributors only see this repository: a reference to a document they cannot read, to a task
number or to the tools used to plan the work tells them nothing. Every sentence must stand on its
own. This file is the only one allowed to name the forbidden references.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
THIS_FILE = Path(__file__).relative_to(ROOT)

# Matched in any case, except the two names that are also common words.
_FORBIDDEN = re.compile(
    "|".join(
        (
            r"\bresearch R[0-9]",  # an item of the design research notes
            r"\bcli\.md\b",  # the internal command-line contract
            r"\bdata-model\b|\(data model\b",  # the internal data model document, cited
            r"\bRFC[ -]?0004\b",  # an RFC that is not public
            r"\b(T[0-9]{3}|A0[0-9]{2})[a-z]?\b",  # a task; ATT&CK techniques have four digits
            r"\b(FR|SC|AR)-[0-9]{3}\b",  # a requirement or success criterion
            r"\bspeckit\b",
            r"\bconstitution(\.md\b| [IVX]+\b)",  # the project rules, by file or principle
            r"(?-i:\bNotion\b)",
            r"(?-i:\bClaude\b)",
            r"co-authored-by",
        )
    ),
    re.IGNORECASE,
)


def _internal_references(text: str) -> list[str]:
    return [match.group() for match in _FORBIDDEN.finditer(text)]


@pytest.mark.parametrize(
    "text",
    [
        "Deterministic identifiers (research R2).",
        "Findings, in one stable shape (contract cli.md).",
        "Cross-checks (data model, cross-checks).",
        "See the Data-Model.",
        "Described in data-model.md.",
        "One release on one channel (RFC 0004 §4.2).",
        "As RFC-0004 says.",
        "Done in T012b.",
        "Before T013 starts.",
        "Moved to T123.",
        "See A001.",
        "Serves FR-020 and SC-005.",
        "Closes AR-001.",
        "Read the speckit first.",
        "As constitution IX requires.",
        "Read constitution.md first.",
        "Copied from a Notion page.",
        "Written with Claude.",
        "Co-authored-by: someone <a@b.c>",
        "Research R2 explains it.",
        "See CLI.md.",
        "As rfc 0004 says.",
        "Done in t012b.",
    ],
)
def test_the_check_refuses_internal_references(text: str) -> None:
    assert _internal_references(text)


@pytest.mark.parametrize(
    "text",
    [
        "Serialised in RFC 8785 canonical form, pointers per RFC 6901.",
        "Technique T1595, and the ICS technique T0866.",
        "Findings SCH-001, IO-005, VER-010, TTL-001 and a future PAR-001.",
        "TT012 is not a task number.",
        "The notion of order, the data, the model.",
        "The manifest data model is versioned.",
        "A crisis that suspends the constitution.",
        "Research notes, an R2 value, cli.py.",
    ],
)
def test_the_check_accepts_ordinary_text(text: str) -> None:
    assert _internal_references(text) == []


def _committable_files(root: Path) -> list[Path]:
    """Tracked files and new files that are not ignored: what a commit can contain."""
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],  # noqa: S607
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return sorted(Path(os.fsdecode(name)) for name in listing.split(b"\0") if name)


def _files_with_internal_references(root: Path) -> dict[str, list[str]]:
    found = {}
    for relative in _committable_files(root):
        path = root / relative
        if relative == THIS_FILE or not path.is_file():
            continue  # this file names the references; a deleted file is not read
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # binary files, such as the reference exports
        references = _internal_references(text)
        if references:
            found[relative.as_posix()] = references
    return found


def test_no_repository_file_refers_to_internal_documents() -> None:
    assert _files_with_internal_references(ROOT) == {}


def test_only_files_that_can_be_committed_are_scanned_and_only_this_one_is_exempt(
    tmp_path: Path,
) -> None:
    files: dict[Path, bytes] = {
        Path(".gitignore"): b"htmlcov/\n.venv/\n",
        THIS_FILE: b"the speckit",
        Path("other") / THIS_FILE.name: b"the speckit",
        Path("uv.lock"): b"the speckit",
        Path("htmlcov") / "index.html": b"the speckit",
        Path(".venv") / "lib.py": b"the speckit",
        Path("export.zip"): b"\xff\xfe the speckit",
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)  # noqa: S607

    assert _files_with_internal_references(tmp_path) == {
        f"other/{THIS_FILE.name}": ["speckit"],
        "uv.lock": ["speckit"],
    }
