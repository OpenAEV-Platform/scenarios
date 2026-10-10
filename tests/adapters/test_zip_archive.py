"""The import archive: the layout the platform's importer reads, the same bytes every build."""

import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from scenario_tools.adapters.data_files import check_export_archive
from scenario_tools.adapters.zip_archive import ZipArchiveBuilder

ROOT = Path(__file__).parents[2]
SCENARIO = (ROOT / "tests" / "golden" / "normalised" / "easm-scenario.json").read_bytes()
ATTACHMENTS = b"PK\x03\x04 an encrypted archive, carried as it is"


def _entries(data: bytes) -> list[zipfile.ZipInfo]:
    return zipfile.ZipFile(io.BytesIO(data)).infolist()


def test_the_scenario_is_one_entry_the_importer_reads_by_its_comment() -> None:
    data = ZipArchiveBuilder().build(SCENARIO, None)

    [entry] = _entries(data)
    assert (entry.filename, entry.comment) == ("scenario.json", b"Scenario")
    assert zipfile.ZipFile(io.BytesIO(data)).read("scenario.json") == SCENARIO
    check_export_archive(data, "archive.zip")  # the same checks as an export


def test_the_attachments_are_carried_as_they_are_under_their_name() -> None:
    data = ZipArchiveBuilder().build(SCENARIO, ATTACHMENTS)

    names = [entry.filename for entry in _entries(data)]
    assert names == ["attachments.zip", "scenario.json"]  # sorted by path
    assert zipfile.ZipFile(io.BytesIO(data)).read("attachments.zip") == ATTACHMENTS


def test_every_entry_has_fixed_metadata() -> None:
    data = ZipArchiveBuilder().build(SCENARIO, ATTACHMENTS)

    assert zipfile.ZipFile(io.BytesIO(data)).comment == b""
    for entry in _entries(data):
        assert entry.date_time == (1980, 1, 1, 0, 0, 0)
        assert entry.external_attr >> 16 == 0o100644
        assert entry.create_system == 3
        assert entry.extra == b""


def test_an_archive_built_on_windows_is_the_same(monkeypatch: pytest.MonkeyPatch) -> None:
    on_linux = ZipArchiveBuilder().build(SCENARIO, ATTACHMENTS)
    monkeypatch.setattr("zipfile.sys.platform", "win32")

    assert ZipArchiveBuilder().build(SCENARIO, ATTACHMENTS) == on_linux


def test_two_builds_give_the_same_bytes() -> None:
    assert ZipArchiveBuilder().build(SCENARIO, ATTACHMENTS) == ZipArchiveBuilder().build(
        SCENARIO, ATTACHMENTS
    )


def test_the_bytes_do_not_depend_on_the_toolchain() -> None:
    # Pinned: a Python or zipfile release that writes other headers would change every archive.
    data = ZipArchiveBuilder().build(b'{"scenario": {}}\n', b"attachments")

    assert hashlib.sha256(data).hexdigest() == (
        "2c4938926525c915dc549c941a0a6a9ad4b1e5770b76956bb6ec8edbace43b99"
    )


def test_entries_are_stored_without_compression() -> None:
    # Deflate bytes depend on the zlib build: stored, an entry gives the same bytes everywhere.
    data = ZipArchiveBuilder().build(SCENARIO, ATTACHMENTS)

    for entry in _entries(data):
        assert entry.compress_type == zipfile.ZIP_STORED
        assert entry.compress_size == entry.file_size
