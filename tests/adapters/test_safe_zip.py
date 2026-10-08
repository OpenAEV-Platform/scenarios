"""Bounded ZIP reader: an archive is checked before any entry is read, and reading is bounded."""

import base64
import contextlib
import io
import stat
import struct
import unicodedata
import warnings
import zipfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import scenario_tools.adapters.safe_zip as safe_zip_module
from scenario_tools.adapters.safe_readers import parse_json
from scenario_tools.adapters.safe_zip import (
    DECOMPRESSED_LIMIT,
    ENTRY_LIMIT,
    archive_from_bytes,
    open_zip,
)
from scenario_tools.ports.errors import UnsafeInputError

GOLDEN = Path(__file__).parents[1] / "golden" / "exports"
# One entry, s.txt = b"secret\n", encrypted with the conventional password "infected".
ENCRYPTED = base64.b64decode(
    "UEsDBAoACQAAAAAIIVyMsuviEwAAAAcAAAAFAAAAcy50eHQAOW5QRM8ewNu3RoSE1/TFyJsXUEsHCIyy6+ITAAAABw"
    "AAAFBLAQIeAwoACQAAAAAIIVyMsuviEwAAAAcAAAAFAAAAAAAAAAEAAAC0gQAAAABzLnR4dFBLBQYAAAAAAQABADMA"
    "AABGAAAAAAA="
)


def _zip(entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # duplicate names are built on purpose
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
    return buffer.getvalue()


def _patch_uint(data: bytes, *, central: int, local: int, value: int, size: int = 4) -> bytes:
    """Patch a field of the first entry, in its central directory and local headers."""
    patched = bytearray(data)
    fmt = "<I" if size == 4 else "<H"
    struct.pack_into(fmt, patched, data.find(b"PK\x01\x02") + central, value)
    struct.pack_into(fmt, patched, data.find(b"PK\x03\x04") + local, value)
    return bytes(patched)


def _read_all(
    data: bytes, *, decompressed_limit: int = DECOMPRESSED_LIMIT, entry_limit: int = ENTRY_LIMIT
) -> None:
    archive = archive_from_bytes(
        data, decompressed_limit=decompressed_limit, entry_limit=entry_limit
    )
    for name in archive.names:
        archive.read(name)


def _refused(
    data: bytes, *, decompressed_limit: int = DECOMPRESSED_LIMIT, entry_limit: int = ENTRY_LIMIT
) -> str:
    with pytest.raises(UnsafeInputError) as error:
        _read_all(data, decompressed_limit=decompressed_limit, entry_limit=entry_limit)
    return error.value.code


# Valid archives


def test_names_and_contents_are_returned() -> None:
    archive = archive_from_bytes(_zip([("dir/", b""), ("dir/a.json", b"{}"), ("b.txt", b"x")]))

    assert archive.names == ("dir/", "dir/a.json", "b.txt")
    assert archive.read("dir/a.json") == b"{}"
    assert archive.read("dir/") == b""


def test_an_archive_file_is_opened(tmp_path: Path) -> None:
    file = tmp_path / "a.zip"
    file.write_bytes(_zip([("a.txt", b"x")]))

    assert open_zip(file).read("a.txt") == b"x"


def test_the_reference_exports_open_and_parse() -> None:
    for file in sorted(GOLDEN.glob("*.zip")):
        archive = open_zip(file)
        (name,) = archive.names
        assert isinstance(parse_json(archive.read(name)), dict)


def test_an_encrypted_entry_is_read_with_the_password() -> None:
    assert archive_from_bytes(ENCRYPTED).read("s.txt", password=b"infected") == b"secret\n"


def test_an_unknown_entry_is_a_usage_error() -> None:
    with pytest.raises(KeyError):
        archive_from_bytes(_zip([("a", b"")])).read("b")


# The archive as a whole


def test_an_archive_over_its_size_limit_is_refused(tmp_path: Path) -> None:
    file = tmp_path / "a.zip"
    file.write_bytes(_zip([("a.txt", b"x" * 100)]))

    with pytest.raises(UnsafeInputError) as error:
        open_zip(file, archive_limit=50)
    assert error.value.code == "IO-001"
    assert error.value.path == str(file)


def test_an_archive_through_a_symbolic_link_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "a.zip"
    target.write_bytes(_zip([("a.txt", b"x")]))
    link = tmp_path / "link.zip"
    link.symlink_to(target)

    with pytest.raises(UnsafeInputError) as error:
        open_zip(link)
    assert error.value.code == "IO-013"


@pytest.mark.parametrize(
    "data",
    [b"", b"not a zip", _zip([("a", b"x" * 50)])[:-10]],
    ids=["empty", "text", "truncated"],
)
def test_bytes_that_are_not_a_zip_are_refused(data: bytes) -> None:
    assert _refused(data) == "IO-007"


def test_archive_bytes_over_the_size_limit_are_refused_before_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _zip([("a.txt", b"x" * 100)])
    monkeypatch.setattr(zipfile, "ZipFile", _must_not_parse)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data, archive_limit=50)
    assert error.value.code == "IO-001"


def _must_not_parse(*args: object, **kwargs: object) -> None:
    raise AssertionError("the ZIP library must not parse this archive")


@pytest.mark.parametrize("zip64", [False, True], ids=["zip", "zip64"])
def test_entries_are_counted_before_the_zip_library_indexes_them(
    monkeypatch: pytest.MonkeyPatch, zip64: bool
) -> None:
    if zip64:
        monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1)  # forces a zip64 directory
    data = _zip([(f"e{index}", b"") for index in range(50)])
    monkeypatch.undo()
    assert (b"PK\x06\x06" in data) is zip64
    monkeypatch.setattr(zipfile, "ZipFile", _must_not_parse)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data, entry_limit=10)
    assert error.value.code == "IO-009"


def test_a_comment_does_not_hide_the_entry_count(monkeypatch: pytest.MonkeyPatch) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index in range(20):
            archive.writestr(f"e{index}", b"")
        archive.comment = b"a comment"
    monkeypatch.setattr(zipfile, "ZipFile", _must_not_parse)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(buffer.getvalue(), entry_limit=10)
    assert error.value.code == "IO-009"


def test_a_zip64_directory_size_beyond_32_bits_is_followed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1)
    data = bytearray(_zip([(f"e{index}", b"") for index in range(50)]))
    monkeypatch.undo()
    end = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, end + 12, 0xFFFFFFFF)  # as tools write once zip64 is used
    assert len(zipfile.ZipFile(io.BytesIO(bytes(data))).infolist()) == 50
    monkeypatch.setattr(zipfile, "ZipFile", _must_not_parse)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data), entry_limit=10)
    assert error.value.code == "IO-009"


def test_an_end_signature_inside_an_entry_does_not_hide_the_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("decoy", b"PK\x05\x06" + b"\x00" * 18)
        for index in range(20):
            archive.writestr(f"e{index}", b"")
    monkeypatch.setattr(zipfile, "ZipFile", _must_not_parse)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(buffer.getvalue(), entry_limit=10)
    assert error.value.code == "IO-009"


def test_entry_comments_are_skipped_when_counting(monkeypatch: pytest.MonkeyPatch) -> None:
    entries: list[tuple[str | zipfile.ZipInfo, bytes]] = []
    for index in range(20):
        info = zipfile.ZipInfo(f"e{index}")
        info.comment = b"an entry comment"
        entries.append((info, b""))
    data = _zip(entries)
    monkeypatch.setattr(zipfile, "ZipFile", _must_not_parse)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data, entry_limit=10)
    assert error.value.code == "IO-009"


def test_the_entry_count_is_checked_again_should_the_walk_miss_a_layout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(safe_zip_module, "_count_entries", lambda data, stop: 0)

    assert len(archive_from_bytes(_zip([("a", b""), ("b", b"")]), entry_limit=2).names) == 2
    assert _refused(_zip([("a", b""), ("b", b""), ("c", b"")]), entry_limit=2) == "IO-009"


def test_entries_at_the_limit_pass_and_one_more_is_refused() -> None:
    three = _zip([("a", b""), ("b", b""), ("c", b"")])

    assert len(archive_from_bytes(three, entry_limit=3).names) == 3
    assert _refused(three, entry_limit=2) == "IO-009"


def test_a_declared_decompressed_size_over_the_limit_is_refused() -> None:
    data = _zip([("a", b"x" * 60), ("b", b"y" * 60)])

    assert archive_from_bytes(data, decompressed_limit=120).names == ("a", "b")
    assert _refused(data, decompressed_limit=119) == "IO-008"


# Entry names


@pytest.mark.parametrize(
    "name",
    ["/etc/passwd", "../x", "a/../../x", "a/..", "a\\b", "..\\x", "C:/x", "c:x", "//server/x"],
)
def test_unsafe_entry_names_are_refused(name: str) -> None:
    assert _refused(_zip([(name, b"")])) == "IO-010"


def test_a_nul_character_is_refused_although_the_zip_library_truncates_the_name() -> None:
    data = _zip([("abc.txt", b"x")]).replace(b"abc.txt", b"a\x00c.txt")

    assert _refused(data) == "IO-010"


def test_an_empty_name_is_refused() -> None:
    assert _refused(_zip([(zipfile.ZipInfo(""), b"x")])) == "IO-010"


def test_dots_inside_a_name_are_not_a_parent_reference() -> None:
    assert archive_from_bytes(_zip([("notes..v2.txt", b"x")])).names == ("notes..v2.txt",)


def test_a_link_entry_is_refused() -> None:
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16

    assert _refused(_zip([(link, b"/etc/passwd")])) == "IO-011"


@pytest.mark.parametrize(
    "names",
    [
        ("a", "a"),
        ("A.txt", "a.txt"),
        (unicodedata.normalize("NFC", "é"), unicodedata.normalize("NFD", "é")),
        ("dir/ß", "dir/SS"),
    ],
    ids=["identical", "case", "unicode normalisation", "case folding"],
)
def test_duplicate_entry_names_are_refused(names: tuple[str, str]) -> None:
    assert _refused(_zip([(names[0], b"1"), (names[1], b"2")])) == "IO-012"


# Reading an entry


def test_an_entry_larger_than_declared_is_refused() -> None:
    data = _patch_uint(_zip([("f", b"A" * 1000)]), central=24, local=22, value=10)

    assert _refused(data) == "IO-007"  # the zip library stops at 10 bytes: bad CRC


def test_an_entry_smaller_than_declared_is_refused() -> None:
    data = _patch_uint(_zip([("f", b"A" * 1000)]), central=24, local=22, value=5000)

    assert _refused(data) == "IO-008"


def test_reading_stops_if_the_zip_library_returns_more_than_declared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Stream(io.BytesIO):
        consumed = 0

        def close(self) -> None:
            self.consumed = self.tell()
            super().close()

    archive = archive_from_bytes(_zip([("f", b"A" * 10)]))
    stream = Stream(b"A" * (1024 * 1024))
    monkeypatch.setattr(archive._archive, "open", lambda info, pwd=None: stream)

    with pytest.raises(UnsafeInputError) as error:
        archive.read("f")
    assert error.value.code == "IO-008"
    assert stream.consumed <= 64 * 1024  # stopped at the first chunk, not at the end


def test_an_unsupported_compression_method_is_refused() -> None:
    data = _patch_uint(_zip([("f", b"A" * 100)]), central=10, local=8, value=99, size=2)

    assert _refused(data) == "IO-007"


@pytest.mark.parametrize("password", [None, b"wrong"])
def test_an_encrypted_entry_without_the_right_password_is_refused(password: bytes | None) -> None:
    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(ENCRYPTED).read("s.txt", password=password)
    assert error.value.code == "IO-007"


def test_a_refusal_names_the_archive() -> None:
    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(b"not a zip", path="in/export.zip")
    assert error.value.path == "in/export.zip"


# Hostile input in general


@given(st.binary(max_size=400))
def test_arbitrary_bytes_are_read_or_refused(data: bytes) -> None:
    with contextlib.suppress(UnsafeInputError):
        _read_all(data)


VALID = _zip([("a.json", b'{"a": 1}' * 20), ("dir/b.txt", b"hello" * 30)])


@given(st.lists(st.tuples(st.integers(0, len(VALID) - 1), st.integers(0, 255)), max_size=6))
def test_a_corrupted_archive_is_read_or_refused(changes: list[tuple[int, int]]) -> None:
    data = bytearray(VALID)
    for position, value in changes:
        data[position] = value
    with contextlib.suppress(UnsafeInputError):
        _read_all(bytes(data))
