"""The public repository never refers to internal planning or to internal documents.

Contributors only see this repository: a reference to a document they cannot read, to a task
number or to the tools used to plan the work tells them nothing. Every sentence must stand on its
own. This file is the only one allowed to name the forbidden references.
"""

import re
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
            r"\bdata[ -]model\b",  # the internal data model document
            r"\bRFC[ -]?0004\b",  # an RFC that is not public
            r"\bT0[0-9]{2}[a-z]?\b",  # a task number; ATT&CK techniques have four digits
            r"\bspeckit\b",
            r"\bconstitution\b",
            r"(?-i:\bNotion\b)",
            r"(?-i:\bClaude\b)",
            r"co-authored-by",
        )
    ),
    re.IGNORECASE,
)
_SKIPPED_DIRECTORIES = frozenset(
    {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "mutants"}
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
        "One release on one channel (RFC 0004 §4.2).",
        "As RFC-0004 says.",
        "Done in T012b.",
        "Before T013 starts.",
        "Read the speckit first.",
        "As the Constitution requires.",
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
        "TT012 is not a task number.",
        "The notion of order, the data, the model.",
        "Research notes, an R2 value, cli.py.",
    ],
)
def test_the_check_accepts_ordinary_text(text: str) -> None:
    assert _internal_references(text) == []


def _files_with_internal_references(root: Path) -> dict[str, list[str]]:
    found = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if (
            not path.is_file()
            or _SKIPPED_DIRECTORIES & set(relative.parts)
            or relative == THIS_FILE
        ):
            continue
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


def test_only_this_test_file_is_exempt(tmp_path: Path) -> None:
    files: dict[Path, bytes] = {
        THIS_FILE: b"the speckit",
        Path("other") / THIS_FILE.name: b"the speckit",
        Path("uv.lock"): b"the speckit",
        Path(".venv") / "lib.py": b"the speckit",
        Path("export.zip"): b"\xff\xfe the speckit",
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    assert _files_with_internal_references(tmp_path) == {
        f"other/{THIS_FILE.name}": ["speckit"],
        "uv.lock": ["speckit"],
    }
