"""ZIP archives written by hand for the release fixtures, the same bytes on every build: the
shapes the deterministic writer never makes, read back here by the safe reader."""

import io
import zipfile
import zlib

import pytest

from scenario_tools.adapters.fixture_zip import (
    HandmadeArchives,
    HandmadeEntry,
    encrypted_zip,
    handmade_zip,
    zero_deflate,
    zipcrypto,
)
from scenario_tools.adapters.safe_zip import archive_from_bytes
from scenario_tools.ports.errors import UnsafeInputError

DATA = b'{"name": "fixture"}'


def _stored(name: str, data: bytes = DATA, comment: bytes = b"") -> HandmadeEntry:
    return HandmadeEntry(name, data, 0, zlib.crc32(data), len(data), comment=comment)


@pytest.mark.parametrize("size", [1, 2, 3, 258, 259, 260, 1000, 70_000])
def test_zero_deflate_inflates_to_that_many_zero_bytes(size: int) -> None:
    stream = zero_deflate(size)

    assert zlib.decompressobj(-15).decompress(stream) == bytes(size)


def test_zero_deflate_writes_13_bits_for_each_run_of_258_bytes() -> None:
    size = 258 * 10_000 + 1

    assert len(zero_deflate(size)) == (3 + 8 + 13 * 10_000 + 7 + 7) // 8


def test_zero_deflate_needs_a_byte_at_least() -> None:
    with pytest.raises(ValueError, match="at least one byte"):
        zero_deflate(0)


def test_a_handmade_archive_is_read_by_the_safe_reader_with_its_comments() -> None:
    data = handmade_zip([_stored("scenario.json", comment=b"Scenario"), _stored("b.txt", b"b")])

    archive = archive_from_bytes(data)

    assert archive.names == ("scenario.json", "b.txt")
    assert archive.comment("scenario.json") == b"Scenario"
    assert archive.read("scenario.json") == DATA
    assert zipfile.ZipFile(io.BytesIO(data)).testzip() is None


def test_a_handmade_archive_keeps_the_name_it_is_given() -> None:
    data = handmade_zip([_stored("../escape.json")])

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data)
    assert error.value.code == "IO-010"


def test_an_entry_deflated_by_hand_is_read() -> None:
    entry = HandmadeEntry("zeros", zero_deflate(5000), 8, zlib.crc32(bytes(5000)), 5000)

    assert archive_from_bytes(handmade_zip([entry])).read("zeros") == bytes(5000)


def test_zipcrypto_is_the_traditional_encryption_the_reader_decrypts() -> None:
    crc = zlib.crc32(DATA)
    entry = HandmadeEntry("f", zipcrypto(DATA, b"infected", crc >> 24), 0, crc, len(DATA), 1)

    assert archive_from_bytes(handmade_zip([entry])).read("f", password=b"infected") == DATA


def test_an_encrypted_archive_opens_with_its_password_only() -> None:
    data = encrypted_zip({"b.txt": b"second", "a.txt": b"first"}, b"infected")
    archive = archive_from_bytes(data)

    assert archive.names == ("a.txt", "b.txt")
    assert archive.read("a.txt", password=b"infected") == b"first"
    with pytest.raises(UnsafeInputError) as error:
        archive.read("b.txt", password=b"another")
    assert error.value.code == "IO-007"


def test_the_same_files_give_the_same_bytes() -> None:
    files = {"a.txt": b"first"}

    assert encrypted_zip(files, b"infected") == encrypted_zip(dict(files), b"infected")
    assert zero_deflate(10_000) == zero_deflate(10_000)


def test_the_fixture_archives_are_the_handmade_shapes() -> None:
    archives = HandmadeArchives()

    stored = archive_from_bytes(archives.stored([("a.json", DATA, b"Scenario")]))
    bomb = archive_from_bytes(archives.bomb("zeros", b"Scenario", 5000))
    attached = archive_from_bytes(archives.attachments({"a.txt": b"first"}, b"infected"))

    assert (stored.read("a.json"), stored.comment("a.json")) == (DATA, b"Scenario")
    assert (bomb.read("zeros"), bomb.comment("zeros")) == (bytes(5000), b"Scenario")
    assert attached.read("a.txt", password=b"infected") == b"first"


def test_an_encrypted_archive_opens_with_zipfile_too() -> None:
    """An oracle that shares no code with the tools: Python's own ZipCrypto reader."""
    data = encrypted_zip({"a.txt": b"first"}, b"infected")

    assert zipfile.ZipFile(io.BytesIO(data)).read("a.txt", pwd=b"infected") == b"first"


def test_an_entry_named_a_link_is_a_symbolic_link() -> None:
    data = HandmadeArchives().stored([("a", b"elsewhere", b"")], links=frozenset({"a"}))

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data)
    assert error.value.code == "IO-011"


def test_a_bomb_may_declare_fewer_bytes_than_it_inflates_to() -> None:
    data = HandmadeArchives().bomb("zeros", b"", 5000, declared=10)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data).read("zeros")
    assert error.value.code == "IO-008"


def test_a_bomb_over_several_mebibytes_has_the_crc_of_its_bytes() -> None:
    size = 3 * 1024 * 1024 + 1

    assert archive_from_bytes(HandmadeArchives().bomb("zeros", b"", size)).read("zeros") == bytes(
        size
    )
