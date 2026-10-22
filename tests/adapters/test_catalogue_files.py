"""The catalogue as a directory: its entries listed in order, down to the version files, and no
link followed; a version file read with the bounded readers."""

import os
from pathlib import Path

import pytest

from scenario_tools.adapters.catalogue_files import CatalogueDirectory
from scenario_tools.domain.verification.payload_catalogue import EntryKind, TreeEntry
from scenario_tools.ports.errors import UnsafeInputError


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "payloads"
    (root / "b-payload").mkdir(parents=True)
    (root / "a-payload").mkdir()
    (root / "a-payload" / "1.0.0.json").write_text("{}\n")
    (root / "b-payload" / "2.0.0.json").write_text('{"k": 1}\n')
    (root / "b-payload" / "1.0.0.json").write_text("{}\n")
    return root


def test_the_entries_are_listed_in_order_with_their_kinds_and_sizes(tmp_path: Path) -> None:
    assert CatalogueDirectory(_tree(tmp_path)).entries() == (
        TreeEntry(("a-payload",), EntryKind.FOLDER, 0),
        TreeEntry(("a-payload", "1.0.0.json"), EntryKind.FILE, 3),
        TreeEntry(("b-payload",), EntryKind.FOLDER, 0),
        TreeEntry(("b-payload", "1.0.0.json"), EntryKind.FILE, 3),
        TreeEntry(("b-payload", "2.0.0.json"), EntryKind.FILE, 9),
    )


def test_a_link_is_listed_as_special_and_never_followed(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "linked").symlink_to(root / "a-payload")
    (root / "a-payload" / "2.0.0.json").symlink_to(root / "b-payload" / "2.0.0.json")
    entries = CatalogueDirectory(root).entries()
    assert TreeEntry(("linked",), EntryKind.SPECIAL, 0) in entries
    assert not [entry for entry in entries if entry.path[:1] == ("linked",) and len(entry.path) > 1]
    special = [entry for entry in entries if entry.path == ("a-payload", "2.0.0.json")]
    assert [entry.kind for entry in special] == [EntryKind.SPECIAL]


def test_a_special_file_is_listed_as_special(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    os.mkfifo(root / "a-payload" / "3.0.0.json")
    entries = CatalogueDirectory(root).entries()
    assert [e.kind for e in entries if e.path == ("a-payload", "3.0.0.json")] == [EntryKind.SPECIAL]


def test_nothing_below_the_entries_of_a_payload_folder_is_listed(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "a-payload" / "deeper").mkdir()
    (root / "a-payload" / "deeper" / "1.0.0.json").write_text("{}\n")
    paths = [entry.path for entry in CatalogueDirectory(root).entries()]
    assert ("a-payload", "deeper") in paths
    assert ("a-payload", "deeper", "1.0.0.json") not in paths


def test_a_catalogue_that_is_a_link_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (tmp_path / "elsewhere").symlink_to(root)
    with pytest.raises(UnsafeInputError) as refused:
        CatalogueDirectory(tmp_path / "elsewhere").entries()
    assert refused.value.code == "IO-013"


def test_a_version_file_is_read_as_bytes_and_strict_json(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    assert CatalogueDirectory(root).read(("b-payload", "2.0.0.json")) == (b'{"k": 1}\n', {"k": 1})
    (root / "a-payload" / "1.0.0.json").write_text('{"k": 1, "k": 2}\n')
    with pytest.raises(UnsafeInputError):
        CatalogueDirectory(root).read(("a-payload", "1.0.0.json"))


def test_a_byte_order_mark_is_kept_in_the_bytes_and_read_past_in_the_document(
    tmp_path: Path,
) -> None:
    root = _tree(tmp_path)
    (root / "a-payload" / "1.0.0.json").write_bytes(b"\xef\xbb\xbf{}\n")
    assert CatalogueDirectory(root).read(("a-payload", "1.0.0.json")) == (b"\xef\xbb\xbf{}\n", {})


def test_a_version_file_that_became_a_link_is_never_read_through_it(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "a-payload" / "1.0.0.json").unlink()
    (root / "a-payload" / "1.0.0.json").symlink_to(root / "b-payload" / "2.0.0.json")
    with pytest.raises(UnsafeInputError) as refused:
        CatalogueDirectory(root).read(("a-payload", "1.0.0.json"))
    assert refused.value.code == "IO-013"


def test_a_folder_replaced_by_a_link_since_it_was_listed_is_never_followed(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    directory = CatalogueDirectory(root)
    directory.entries()
    (root / "b-payload").rename(tmp_path / "moved")
    (root / "b-payload").symlink_to(tmp_path / "moved")
    with pytest.raises(UnsafeInputError) as refused:
        directory.read(("b-payload", "2.0.0.json"))
    assert refused.value.code == "IO-013"
