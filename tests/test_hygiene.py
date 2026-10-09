"""The public repository never refers to internal planning or to internal documents.

Contributors only see this repository: a reference to a document they cannot read, to a task
number or to the tools used to plan the work tells them nothing. Every sentence must stand on its
own. This file is the only one allowed to name the forbidden references.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

_FORBIDDEN = re.compile(
    "|".join(
        (
            r"\bresearch R[0-9]",  # an item of the design research notes
            r"\bcli\.md\b",  # the internal command-line contract
            r"(?i:\bdata[ -]model\b)",  # the internal data model document
            r"\bRFC[ -]?0004\b",  # an RFC that is not public
            r"\bT0[0-9]{2}[a-z]?\b",  # a task number; ATT&CK techniques have four digits
            r"(?i:\bspeckit\b)",
            r"(?i:\bconstitution\b)",
            r"\bNotion\b",
            r"\bClaude\b",
            r"(?i:co-authored-by)",
        )
    )
)
_SKIPPED_DIRECTORIES = frozenset(
    {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "mutants"}
)
_SKIPPED_FILES = frozenset({Path(__file__).name, "uv.lock"})


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


def _repository_text_files() -> list[Path]:
    files = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if not path.is_file() or _SKIPPED_DIRECTORIES & set(relative.parts):
            continue
        if path.name in _SKIPPED_FILES:
            continue
        files.append(path)
    return files


def test_no_repository_file_refers_to_internal_documents() -> None:
    found = {}
    for path in _repository_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # binary files, such as the reference exports
        references = _internal_references(text)
        if references:
            found[str(path.relative_to(ROOT))] = references

    assert found == {}
