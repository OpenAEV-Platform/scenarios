"""The public repository never refers to internal planning or to internal documents.

Contributors only see this repository: a reference to a document they cannot read, to a task
number or to the tools used to plan the work tells them nothing. Every sentence must stand on its
own. This file names only generic patterns; the names of internal documents and tools are read
from a private list, never committed: ``SCENARIOS_HYGIENE_TERMS`` holds it (one regular
expression per line), or ``SCENARIOS_HYGIENE_TERMS_FILE`` names a file that does. Without it, the
private check is skipped and says so, unless ``SCENARIOS_HYGIENE_REQUIRED`` is ``true``, as in
the continuous integration of this repository. A finding gives the file and the line, never the
term, so that no log shows it.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

from scenario_tools.domain.shared.characters import hidden_in

ROOT = Path(__file__).parents[1]
THIS_FILE = Path(__file__).relative_to(ROOT)

# What a reference to the internal planning looks like, whatever it names.
_GENERIC = re.compile(
    "|".join(
        (
            r"\b(T[0-9]{3}|A0[0-9]{2})[a-z]?\b",  # a task; ATT&CK techniques have four digits
            r"\b(FR|SC|AR)-[0-9]{3}\b",  # a requirement or success criterion
            r"co-authored-by",
        )
    ),
    re.IGNORECASE,
)
# A generated identifier, shaped as RFC 4122 says (its version digit and its variant in place):
# its hex groups can spell a task number by chance, as the derived `8d993877-a012-5df3-…` does,
# and a reference never sits inside one. The generic patterns read each line without them; a
# reference beside one, or in any other run of hex, is still found. An identifier shaped so on
# purpose to hide `A0` and two digits is left to the review: this check stops mistakes, not a
# contributor set on hiding one.
_IDENTIFIER = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"(?![0-9a-f])"
    # Data embedded as base64, such as the fonts of an image: its letters can spell a task number
    # by chance too, and a reference written beside it is still found.
    r"|data:[a-z0-9.+-]+/[a-z0-9.+-]+;base64,[a-z0-9+/]+=*",
    re.IGNORECASE,
)


def _private() -> re.Pattern[str] | None:
    """The private terms, from the environment, or ``None`` when none is given."""
    text = os.environ.get("SCENARIOS_HYGIENE_TERMS", "")
    if not text.strip() and (path := os.environ.get("SCENARIOS_HYGIENE_TERMS_FILE")):
        text = Path(path).read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines()]
    terms = [line for line in lines if line and not line.startswith("#")]
    return re.compile("|".join(f"(?:{term})" for term in terms), re.IGNORECASE) if terms else None


def _required_private() -> re.Pattern[str]:
    """The private terms, or a skip that says why, or a failure where they must be given."""
    private = _private()
    if private is not None:
        return private
    if os.environ.get("SCENARIOS_HYGIENE_REQUIRED") == "true":
        pytest.fail("the private list of internal terms is required here, and none is given")
    pytest.skip("no private list of internal terms given: only the generic patterns were checked")


def _lines_with(
    pattern: re.Pattern[str], text: str, *, ignored: re.Pattern[str] | None = None
) -> list[int]:
    """The numbers of the lines of ``text`` that ``pattern`` finds something in, once what
    ``ignored`` matches is taken out of each line."""
    return [
        number
        for number, line in enumerate(text.splitlines(), 1)
        if pattern.search(ignored.sub(" ", line) if ignored else line)
    ]


def _generic_lines(text: str) -> list[int]:
    """The lines of ``text`` the generic patterns find a reference in, identifiers left aside."""
    return _lines_with(_GENERIC, text, ignored=_IDENTIFIER)


@pytest.mark.parametrize(
    "text",
    [
        "Done in T012b.",
        "Before T013 starts.",
        "Moved to T123.",
        "See A001.",
        "Serves FR-020 and SC-005.",
        "Closes AR-001.",
        "Co-authored-by: someone <a@b.c>",
        "Done in t012b.",
    ],
)
def test_the_generic_patterns_refuse_a_reference_to_the_planning(text: str) -> None:
    assert _generic_lines(text) == [1]


@pytest.mark.parametrize(
    "text",
    [
        "Done in A012, for 8d993877-a012-5df3-bee6-63028383c124.",
        "Branch task/T003-fix.",
        "A run 8d993877-a012 of hex, no identifier.",
        "8d993877-a012-5df3-bee6-63028383c124x and T013.",
        "8d993877-a012-5df3-bee6-63028383c124-A034",
        "A034-8d993877-a012-5df3-bee6-63028383c124",
        "FR-020 for 8d993877-a012-5df3-bee6-63028383c124.",
        "8d993877-a012-5df3-bee6-63028383c124 Co-authored-by: someone",
        "00000000-a034-0000-0000-000000000000, not shaped as a generated identifier",
    ],
)
def test_a_reference_beside_or_around_an_identifier_is_still_refused(text: str) -> None:
    assert _generic_lines(text) == [1]


@pytest.mark.parametrize(
    "text",
    [
        "Serialised in RFC 8785 canonical form, pointers per RFC 6901.",
        "Technique T1595, and the ICS technique T0866.",
        "Findings SCH-001, IO-005, VER-010, TTL-001 and a future PAR-001.",
        "TT012 is not a task number.",
    ],
)
def test_the_generic_patterns_accept_ordinary_text(text: str) -> None:
    assert _generic_lines(text) == []


@pytest.mark.parametrize(
    "text",
    [
        '"variable_id": "8d993877-a012-5df3-bee6-63028383c124",',
        "IDs 0a64b5ab-2016-426b-813f-9051d32e88b3 and 1A7A1F81-5811-41D7-8C2D-E6DDDBC9E7CA.",
        "t003a1b2-0000-4000-8000-000000000000",
    ],
)
def test_an_identifier_is_never_read_as_a_reference(text: str) -> None:
    """A derived identifier's hex groups can spell a task number by chance: not a reference."""
    assert _generic_lines(text) == []


def test_embedded_base64_data_is_never_read_as_a_reference() -> None:
    """A font embedded in an image is base64, whose letters can spell a task number by chance."""
    assert _generic_lines("src:url(data:font/woff2;base64,AAx/T012/Fr+A034=) format('woff2')") == []


@pytest.mark.parametrize(
    "text",
    [
        "src:url(data:font/woff2;base64,AAxF) for T012",
        "Done in T012: data:image/png;base64,AAxF",
        "data:font/woff2,T012 is not base64",
    ],
)
def test_a_reference_beside_embedded_data_is_still_refused(text: str) -> None:
    assert _generic_lines(text) == [1]


def test_the_private_list_is_read_from_the_environment_or_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SCENARIOS_HYGIENE_TERMS", raising=False)
    monkeypatch.delenv("SCENARIOS_HYGIENE_TERMS_FILE", raising=False)
    assert _private() is None

    monkeypatch.setenv("SCENARIOS_HYGIENE_TERMS", "# a comment\n\\bzorblax\\b\n(?-i:Quux)\n")
    private = _private()
    assert private is not None
    assert _lines_with(private, "one\nthe ZORBLAX plan\nquux\nQuux") == [2, 4]

    monkeypatch.setenv("SCENARIOS_HYGIENE_TERMS", "")
    (tmp_path / "terms").write_text("\\bfrobnitz\\b\n", encoding="utf-8")
    monkeypatch.setenv("SCENARIOS_HYGIENE_TERMS_FILE", str(tmp_path / "terms"))
    private = _private()
    assert private is not None
    assert _lines_with(private, "a frobnitz") == [1]


def test_without_the_private_list_the_check_is_skipped_unless_it_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SCENARIOS_HYGIENE_TERMS", raising=False)
    monkeypatch.delenv("SCENARIOS_HYGIENE_TERMS_FILE", raising=False)
    monkeypatch.delenv("SCENARIOS_HYGIENE_REQUIRED", raising=False)
    with pytest.raises(pytest.skip.Exception, match="only the generic patterns"):
        _required_private()

    monkeypatch.setenv("SCENARIOS_HYGIENE_REQUIRED", "true")
    with pytest.raises(pytest.fail.Exception, match="required here"):
        _required_private()


def _committable_files(root: Path) -> list[Path]:
    """Tracked files and new files that are not ignored: what a commit can contain."""
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],  # noqa: S607
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return sorted(Path(os.fsdecode(name)) for name in listing.split(b"\0") if name)


def _files_with(
    pattern: re.Pattern[str],
    root: Path,
    *,
    exempt: Path | None = THIS_FILE,
    ignored: re.Pattern[str] | None = None,
) -> dict[str, list[int]]:
    """Every committable file, but ``exempt``, with the lines ``pattern`` finds something in: a
    link by what the repository stores for it, its target; binary files left aside."""
    found = {}
    for relative in _committable_files(root):
        path = root / relative
        if relative == exempt:
            continue  # this file names the generic patterns
        if path.is_symlink():
            text = str(path.readlink())
        elif not path.is_file():
            continue  # deleted from the working tree
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue  # binary files, such as the reference exports
        lines = _lines_with(pattern, text, ignored=ignored)
        if lines:
            found[relative.as_posix()] = lines
    return found


def test_no_repository_file_refers_to_the_planning() -> None:
    assert _files_with(_GENERIC, ROOT, ignored=_IDENTIFIER) == {}


def test_no_repository_file_names_an_internal_document_or_tool() -> None:
    # Only where and on which line, never the term: the logs of this repository are public.
    assert _files_with(_required_private(), ROOT, exempt=None) == {}  # this file included


def test_this_file_is_exempt_from_the_generic_patterns_only(tmp_path: Path) -> None:
    (tmp_path / THIS_FILE).parent.mkdir(parents=True)
    (tmp_path / THIS_FILE).write_text("done in T012\nthe zorblax plan\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)  # noqa: S607
    private = re.compile(r"\bzorblax\b")

    assert _files_with(_GENERIC, tmp_path) == {}
    assert _files_with(private, tmp_path, exempt=None) == {THIS_FILE.as_posix(): [2]}


def test_only_files_that_can_be_committed_are_scanned_and_only_this_one_is_exempt(
    tmp_path: Path,
) -> None:
    files: dict[Path, bytes] = {
        Path(".gitignore"): b"htmlcov/\n.venv/\n",
        THIS_FILE: b"done in T012",
        Path("other") / THIS_FILE.name: b"line one\ndone in T012",
        Path("uv.lock"): b"done in T012",
        Path("htmlcov") / "index.html": b"done in T012",
        Path(".venv") / "lib.py": b"done in T012",
        Path("export.zip"): b"\xff\xfe done in T012",
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (tmp_path / "broken-link").symlink_to("plan/T012.md")
    (tmp_path / "link").symlink_to("uv.lock")
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)  # noqa: S607

    assert _files_with(_GENERIC, tmp_path) == {
        "broken-link": [1],
        f"other/{THIS_FILE.name}": [2],
        "uv.lock": [1],
    }


_BINARY = frozenset({".zip", ".png", ".jpg", ".pdf", ".gz"})


def _files_with_hidden_characters(root: Path) -> dict[str, tuple[str, ...]]:
    """Every committable file whose name, link target or text holds a hidden character. Text
    that is not valid UTF-8 is read anyway, its invalid bytes left aside; only binary formats
    are skipped."""
    found = {}
    for relative in _committable_files(root):
        path = root / relative
        texts = [relative.as_posix()]
        if path.is_symlink():
            texts.append(str(path.readlink()))  # what the repository stores for a link
        elif path.is_file() and path.suffix not in _BINARY:
            texts.append(path.read_bytes().decode("utf-8", errors="ignore"))
        hidden = tuple(label for text in texts for label in hidden_in(text))
        if hidden:
            found[relative.as_posix()] = hidden
    return found


def test_no_repository_file_holds_a_hidden_character() -> None:
    # The rule the tools apply to scenarios holds for the repository itself: tests write such
    # characters by code point, never raw.
    assert _files_with_hidden_characters(ROOT) == {}


def test_a_hidden_character_in_a_committable_file_is_found(tmp_path: Path) -> None:
    rlo = chr(0x202E)
    (tmp_path / "tool.py").write_text(f"command = 'ls{rlo}'\n", encoding="utf-8")
    (tmp_path / "notes.md").write_bytes(b"\xff not utf-8 " + rlo.encode())
    (tmp_path / f"evil{rlo}gpj.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "link").symlink_to(f"target{rlo}")
    (tmp_path / "export.zip").write_bytes(rlo.encode())  # binary formats are not text
    (tmp_path / "clean.py").write_text("command = 'ls'\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)  # noqa: S607

    found = _files_with_hidden_characters(tmp_path)

    assert sorted(found) == sorted(["tool.py", "notes.md", f"evil{rlo}gpj.py", "link"])
    assert all(labels == ("U+202E (RIGHT-TO-LEFT OVERRIDE)",) for labels in found.values())
