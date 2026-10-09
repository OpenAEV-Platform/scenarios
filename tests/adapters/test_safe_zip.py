"""Bounded ZIP reader: an archive is checked before any entry is read, and reading is bounded."""

import base64
import contextlib
import io
import stat
import struct
import tracemalloc
import unicodedata
import warnings
import zipfile
import zlib
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
_LOCAL_HEADER_SIZE = 30
# Made with `zip -P infected`: deflate, and deflate streamed from standard input (zip64, entry
# "-"). Like the archive above, both use a data descriptor.
ENCRYPTED_DEFLATED = base64.b64decode(
    "UEsDBBQACQAIAAAIIVx2qfMqGwAAACwBAAAFAAAAZC50eHTZ2ep5tmOmUsoG0Q/KQhruN8r8hD4E5a+1oNNQSwcIdqnz"
    "KhsAAAAsAQAAUEsBAh4DFAAJAAgAAAghXHap8yobAAAALAEAAAUAAAAAAAAAAQAAALSBAAAAAGQudHh0UEsFBgAAAAAB"
    "AAEAMwAAAE4AAAAAAA=="
)
ENCRYPTED_STREAMED = base64.b64decode(
    "UEsDBC0ACQAIAHedSF2rU7CF//////////8BABQALQEAEAA1AAAAAAAAACQAAAAAAAAAb3ElrPqfvtuajSaYwjOiIC0n"
    "+UXGp41+zANPsfUFngj/3w5VUEsHCKtTsIUkAAAAAAAAADUAAAAAAAAAUEsBAh4DLQAJAAgAd51IXatTsIUkAAAANQAA"
    "AAEAAAAAAAAAAQAAAIARAAAAAC1QSwYGLAAAAAAAAAAeAy0AAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAALwAAAAAAAABv"
    "AAAAAAAAAFBLBgcAAAAAngAAAAAAAAABAAAAUEsFBgAAAAABAAEALwAAAG8AAAAAAA=="
)
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

    assert _refused(data) == "IO-008"


def test_an_entry_smaller_than_declared_is_refused() -> None:
    data = _patch_uint(_zip([("f", b"A" * 1000)]), central=24, local=22, value=5000)

    assert _refused(data) == "IO-008"


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


# Entry data, read by the tools


def _handmade(
    data: bytes,
    *,
    method: int,
    crc: int,
    size: int,
    flags: int = 0,
    name: bytes = b"f",
    local_name: bytes | None = None,
) -> bytes:
    """One-entry archive built byte by byte, so that every field can be set at will."""
    local_name = name if local_name is None else local_name
    date = 0x21  # 1980-01-01
    local = (
        struct.pack(
            "<4s5H3I2H",
            b"PK\x03\x04",
            20,
            flags,
            method,
            0,
            date,
            crc,
            len(data),
            size,
            len(local_name),
            0,
        )
        + local_name
        + data
    )
    central = (
        struct.pack(
            "<4s6H3I5H2I",
            b"PK\x01\x02",
            20,
            20,
            flags,
            method,
            0,
            date,
            crc,
            len(data),
            size,
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def _deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _crc_table() -> list[int]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    return table


CRC_TABLE = _crc_table()


def _zipcrypto(plain: bytes, password: bytes, check_byte: int) -> bytes:
    """Encrypt as `zip -P` does (APPNOTE 6.1), for archives the tests build by hand."""
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte: int) -> None:
        keys[0] = (keys[0] >> 8) ^ CRC_TABLE[(keys[0] ^ byte) & 0xFF]
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = (keys[2] >> 8) ^ CRC_TABLE[(keys[2] ^ (keys[1] >> 24)) & 0xFF]

    for byte in password:
        update(byte)
    out = bytearray()
    for byte in bytes(11) + bytes([check_byte]) + plain:
        temp = (keys[2] | 2) & 0xFFFF
        out.append(byte ^ ((temp * (temp ^ 1)) >> 8) & 0xFF)
        update(byte)
    return bytes(out)


VISIBLE = b'{"name": "safe"}'
HIDDEN = b'\n{"name": "never checked"}'


@pytest.mark.parametrize(
    ("data", "name", "expected"),
    [
        (ENCRYPTED, "s.txt", b"secret\n"),
        (ENCRYPTED_DEFLATED, "d.txt", b"aaaa bbbb " * 30),
        (ENCRYPTED_STREAMED, "-", b"streamed content, " * 2 + b"streamed content\n"),
    ],
    ids=["stored", "deflate", "streamed zip64"],
)
def test_archives_made_by_zip_with_a_password_are_read(
    data: bytes, name: str, expected: bytes
) -> None:
    assert archive_from_bytes(data).read(name, password=b"infected") == expected


def test_a_stream_going_on_beyond_its_declared_size_is_refused() -> None:
    data = _handmade(
        _deflate(VISIBLE + HIDDEN), method=8, crc=zlib.crc32(VISIBLE), size=len(VISIBLE)
    )

    assert _refused(data) == "IO-008"


def test_an_encrypted_stream_going_on_beyond_its_declared_size_is_refused() -> None:
    crc = zlib.crc32(VISIBLE)
    encrypted = _zipcrypto(_deflate(VISIBLE + HIDDEN), b"infected", crc >> 24)
    data = _handmade(encrypted, method=8, crc=crc, size=len(VISIBLE), flags=1)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data).read("f", password=b"infected")
    assert error.value.code == "IO-008"


def test_an_encrypted_entry_made_by_hand_is_read() -> None:
    crc = zlib.crc32(VISIBLE)
    encrypted = _zipcrypto(_deflate(VISIBLE), b"infected", crc >> 24)
    data = _handmade(encrypted, method=8, crc=crc, size=len(VISIBLE), flags=1)

    assert archive_from_bytes(data).read("f", password=b"infected") == VISIBLE


def test_stored_bytes_beyond_the_declared_size_are_refused() -> None:
    data = _handmade(VISIBLE + HIDDEN, method=0, crc=zlib.crc32(VISIBLE), size=len(VISIBLE))

    assert _refused(data) == "IO-008"


def test_a_deflate_bomb_is_refused_with_bounded_memory() -> None:
    compressed = _deflate(b"\0" * (50 * 1024 * 1024))
    data = _handmade(compressed, method=8, crc=zlib.crc32(b"\0" * 10), size=10)
    tracemalloc.start()
    try:
        assert _refused(data) == "IO-008"
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA], ids=["bzip2", "lzma"])
def test_compression_methods_other_than_stored_and_deflate_are_refused(method: int) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        archive.writestr("f", b"x" * 100)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(buffer.getvalue())
    assert error.value.code == "IO-007"


def test_a_bad_crc_is_refused() -> None:
    data = _handmade(_deflate(VISIBLE), method=8, crc=zlib.crc32(VISIBLE) ^ 1, size=len(VISIBLE))

    assert _refused(data) == "IO-007"


def test_a_local_header_naming_another_entry_is_refused() -> None:
    data = _handmade(VISIBLE, method=0, crc=zlib.crc32(VISIBLE), size=len(VISIBLE), local_name=b"g")

    assert _refused(data) == "IO-007"


def test_a_missing_local_header_is_refused() -> None:
    data = _handmade(VISIBLE, method=0, crc=zlib.crc32(VISIBLE), size=len(VISIBLE))
    data = b"XX" + data[2:]

    assert _refused(data) == "IO-007"


def test_entry_data_cut_short_is_refused() -> None:
    entry = _handmade(VISIBLE, method=0, crc=zlib.crc32(VISIBLE), size=len(VISIBLE))
    data = _patch_uint(entry, central=20, local=18, value=len(VISIBLE) + 1000)

    assert _refused(data) == "IO-007"


def test_data_after_the_end_of_a_deflate_stream_is_refused() -> None:
    data = _handmade(
        _deflate(VISIBLE) + b"trailing", method=8, crc=zlib.crc32(VISIBLE), size=len(VISIBLE)
    )

    assert _refused(data) == "IO-007"


def test_an_invalid_deflate_stream_is_refused() -> None:
    data = _handmade(b"\xff\xff\xff\xff", method=8, crc=0, size=4)

    assert _refused(data) == "IO-007"


def test_a_truncated_deflate_stream_is_refused() -> None:
    compressed = _deflate(VISIBLE * 20)
    data = _handmade(
        compressed[:-5], method=8, crc=zlib.crc32(VISIBLE * 20), size=len(VISIBLE) * 20
    )

    assert _refused(data) == "IO-007"


def test_an_encrypted_entry_too_short_for_its_header_is_refused() -> None:
    data = _handmade(b"short", method=0, crc=0, size=0, flags=1)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data).read("f", password=b"infected")
    assert error.value.code == "IO-007"


def test_a_wrong_password_is_reported_as_such() -> None:
    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(ENCRYPTED_DEFLATED).read("d.txt", password=b"wrong")
    assert error.value.code == "IO-007"
    assert "wrong password" in error.value.message


def test_a_password_is_ignored_for_an_entry_that_is_not_encrypted() -> None:
    data = _handmade(VISIBLE, method=0, crc=zlib.crc32(VISIBLE), size=len(VISIBLE))

    assert archive_from_bytes(data).read("f", password=b"infected") == VISIBLE


# Layout and encrypted entries: no byte outside an entry, a total budget, an early password check


def _all_encrypted(data: bytes, *, entries: int | None = None) -> bytes:
    """Set the encryption flag of every entry, or of the first ``entries`` ones, in their central
    and local headers."""
    patched = bytearray(data)
    for signature, flags_at in ((b"PK\x01\x02", 8), (b"PK\x03\x04", 6)):
        position, done = data.find(signature), 0
        while position >= 0 and (entries is None or done < entries):
            (flags,) = struct.unpack_from("<H", patched, position + flags_at)
            struct.pack_into("<H", patched, position + flags_at, flags | 1)
            position, done = data.find(signature, position + 4), done + 1
    return bytes(patched)


class _Stream(io.RawIOBase):
    """A destination that cannot seek, so that the ZIP library writes data descriptors."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, data: object) -> int:
        chunk = bytes(data)  # type: ignore[call-overload]
        self.data += chunk
        return len(chunk)


@pytest.mark.parametrize("zip64", [False, True], ids=["descriptor", "zip64 descriptor"])
def test_archives_written_as_a_stream_lie_end_to_end(zip64: bool) -> None:
    stream = _Stream()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("a.txt", "b.txt"):
            info = zipfile.ZipInfo(name)
            info.extra = struct.pack("<HHB", 0x5455, 1, 1)  # a timestamp field, not zip64
            with archive.open(info, "w", force_zip64=zip64) as entry:
                entry.write(name.encode() * 50)
    data = bytes(stream.data)
    assert all(info.flag_bits & 0x8 for info in zipfile.ZipFile(io.BytesIO(data)).infolist())

    checked = archive_from_bytes(data)
    assert checked.read("b.txt") == b"b.txt" * 50


def test_a_data_descriptor_without_its_optional_signature_is_read() -> None:
    stream = _Stream()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", b"a" * 100)
    signed = bytes(stream.data)
    descriptor = signed.find(b"PK\x07\x08")
    data = bytearray(signed[:descriptor] + signed[descriptor + 4 :])  # signature removed
    end = data.rfind(b"PK\x05\x06")
    (directory,) = struct.unpack_from("<I", data, end + 16)
    struct.pack_into("<I", data, end + 16, directory - 4)

    assert archive_from_bytes(bytes(data)).read("a.txt") == b"a" * 100


def _streamed(content: bytes = b"a" * 100) -> bytes:
    stream = _Stream()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", content)
    return bytes(stream.data)


def _move_directory(data: bytearray, by: int) -> None:
    end = data.rfind(b"PK\x05\x06")
    (directory,) = struct.unpack_from("<I", data, end + 16)
    struct.pack_into("<I", data, end + 16, directory + by)


def test_a_descriptor_flag_set_only_in_the_directory_is_refused() -> None:
    plain = _zip([("a.txt", b"a" * 100)])
    info = zipfile.ZipFile(io.BytesIO(plain)).infolist()[0]
    directory = plain.find(b"PK\x01\x02")
    descriptor = struct.pack("<3I", info.CRC, info.compress_size, info.file_size)
    data = bytearray(plain[:directory] + descriptor + plain[directory:])
    struct.pack_into("<H", data, directory + len(descriptor) + 8, info.flag_bits | 0x8)
    _move_directory(data, len(descriptor))

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


@pytest.mark.parametrize(
    ("field", "value"),
    [(6, 1), (8, 0), (14, 0), (18, 1), (22, 1)],
    ids=["encryption flag", "method", "crc", "compressed size", "size"],
)
def test_a_local_header_that_disagrees_with_the_directory_is_refused(
    field: int, value: int
) -> None:
    data = bytearray(_zip([("a.txt", b"a" * 100)]))
    size = 2 if field in (6, 8) else 4
    struct.pack_into("<H" if size == 2 else "<I", data, field, value)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


def test_a_descriptor_that_disagrees_with_the_directory_is_refused() -> None:
    data = bytearray(_streamed())
    descriptor = data.find(b"PK\x07\x08")
    data[descriptor + 4] ^= 0xFF  # its CRC

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


def test_an_unsigned_descriptor_whose_crc_looks_like_the_signature_is_laid_out_right() -> None:
    signed = _streamed()
    descriptor = signed.find(b"PK\x07\x08")
    data = bytearray(signed[:descriptor] + signed[descriptor + 4 :])
    _move_directory(data, -4)
    struct.pack_into("<4s", data, descriptor, b"PK\x07\x08")  # the CRC, in the descriptor
    struct.pack_into("<4s", data, data.find(b"PK\x01\x02") + 16, b"PK\x07\x08")  # and directory

    archive_from_bytes(bytes(data))  # laid out right; reading would fail on the real CRC


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_a_zip64_entry_without_descriptor_is_read(compression: int) -> None:
    buffer = io.BytesIO()
    with (
        zipfile.ZipFile(buffer, "w", compression) as archive,
        archive.open("a.txt", "w", force_zip64=True) as entry,
    ):
        entry.write(b"a" * 100)

    assert archive_from_bytes(buffer.getvalue()).read("a.txt") == b"a" * 100


def test_zip64_sizes_without_their_zip64_field_are_refused() -> None:
    buffer = io.BytesIO()
    with (
        zipfile.ZipFile(buffer, "w") as archive,
        archive.open("a.txt", "w", force_zip64=True) as entry,
    ):
        entry.write(b"a" * 100)
    data = bytearray(buffer.getvalue())
    extra = _LOCAL_HEADER_SIZE + len(b"a.txt")
    assert struct.unpack_from("<H", data, extra) == (0x0001,)
    struct.pack_into("<H", data, extra, 0x9999)  # the local zip64 field becomes unknown

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


def test_a_local_name_that_differs_from_the_directory_is_refused_before_reading() -> None:
    data = bytearray(_zip([("safe", b"x")]))
    struct.pack_into("<4s", data, _LOCAL_HEADER_SIZE, b"../x")  # same length, unchecked name

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


@pytest.mark.parametrize("name", ["caf\u00e9.txt", "plain.txt"], ids=["non-ascii", "ascii"])
def test_a_local_name_encoding_flag_that_differs_from_the_directory_is_refused(name: str) -> None:
    data = bytearray(_zip([(name, b"x")]))
    (flags,) = struct.unpack_from("<H", data, 6)
    struct.pack_into("<H", data, 6, flags ^ 0x800)  # the local header alone says otherwise

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


@pytest.mark.parametrize("compressed", [2**32, 2**33], ids=["4 GiB", "8 GiB"])
def test_a_zip64_size_the_local_descriptor_cannot_hold_is_refused(compressed: int) -> None:
    name, content = b"a", b"x" * 10
    crc = zlib.crc32(content)
    local = (
        struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0x8, 0, 0, 0x21, 0, 0, 0, len(name), 0)
        + name
        + content
        + struct.pack("<3I", crc, len(content), len(content))
    )
    central = (
        struct.pack(
            "<4s6H3I5H2I",
            b"PK\x01\x02",
            45,
            45,
            0x8,
            0,
            0,
            0x21,
            crc,
            0xFFFFFFFF,
            len(content),
            len(name),
            12,
            0,
            0,
            0,
            0,
            0,
        )
        + name
        + struct.pack("<HHQ", 0x0001, 8, compressed)  # zip64 field: the compressed size
    )
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(local + central + end)
    assert error.value.code == "IO-007"


def test_encrypted_entries_are_limited_in_total_not_one_by_one() -> None:
    data = _all_encrypted(_zip([("a", b"a" * 20), ("b", b"b" * 20)]))
    sizes = [info.compress_size for info in zipfile.ZipFile(io.BytesIO(data)).infolist()]

    archive_from_bytes(data, encrypted_limit=sum(sizes))
    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(data, encrypted_limit=sum(sizes) - 1)
    assert error.value.code == "IO-008"
    assert max(sizes) <= sum(sizes) - 1  # each entry alone is within the limit


def test_entries_that_are_not_encrypted_do_not_count_in_the_budget() -> None:
    data = _all_encrypted(_zip([("a", b"a" * 20), ("b", b"b" * 2000)]), entries=1)
    encrypted = zipfile.ZipFile(io.BytesIO(data)).infolist()[0].compress_size

    archive_from_bytes(data, encrypted_limit=encrypted)


def test_entries_that_overlap_are_refused_before_any_entry_is_read() -> None:
    data = bytearray(_zip([("a", b"a" * 20), ("b", b"b" * 20)]))
    second = data.find(b"PK\x01\x02", data.find(b"PK\x01\x02") + 4)
    struct.pack_into("<I", data, second + 42, 0)  # "b" now starts where "a" starts

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


def test_bytes_that_no_entry_lists_are_refused() -> None:
    hidden = _zip([("../../evil.sh", b"echo owned")])
    hidden = hidden[: hidden.find(b"PK\x01\x02")]  # its local header and data only
    listed = _zip([("ok.txt", b"fine"), ("other.txt", b"fine too")])
    second = listed.find(b"PK\x03\x04", 4)
    data = bytearray(listed[:second] + hidden + listed[second:])  # unlisted bytes between entries
    central = data.find(b"PK\x01\x02", data.find(b"PK\x01\x02") + 4)
    struct.pack_into("<I", data, central + 42, second + len(hidden))
    end = data.rfind(b"PK\x05\x06")
    (directory,) = struct.unpack_from("<I", data, end + 16)
    struct.pack_into("<I", data, end + 16, directory + len(hidden))
    assert [info.filename for info in zipfile.ZipFile(io.BytesIO(bytes(data))).infolist()] == [
        "ok.txt",
        "other.txt",
    ]

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


def test_bytes_between_the_last_entry_and_the_directory_are_refused() -> None:
    listed = _zip([("ok.txt", b"fine")])
    directory = listed.find(b"PK\x01\x02")
    data = bytearray(listed[:directory] + b"unlisted" + listed[directory:])
    end = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, end + 16, directory + len(b"unlisted"))
    assert zipfile.ZipFile(io.BytesIO(bytes(data))).namelist() == ["ok.txt"]

    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(bytes(data))
    assert error.value.code == "IO-007"


def test_data_before_the_first_entry_is_refused() -> None:
    with pytest.raises(UnsafeInputError) as error:
        archive_from_bytes(b"prefix" + _zip([("a", b"a")]))
    assert error.value.code == "IO-007"


def test_a_wrong_password_is_found_before_the_entry_is_decrypted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decrypted: list[int] = []
    original = safe_zip_module._ZipCryptoKeys.decrypt

    def spy(keys: object, data: bytes) -> bytes:
        decrypted.append(len(data))
        return original(keys, data)  # type: ignore[arg-type]

    monkeypatch.setattr(safe_zip_module._ZipCryptoKeys, "decrypt", spy)
    archive = archive_from_bytes(ENCRYPTED_DEFLATED)

    with pytest.raises(UnsafeInputError):
        archive.read("d.txt", password=b"wrong")
    assert decrypted == [12]
    decrypted.clear()
    archive.read("d.txt", password=b"infected")
    assert decrypted == [12, 27 - 12]


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
