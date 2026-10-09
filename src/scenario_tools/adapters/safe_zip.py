"""Bounded ZIP reader: an archive is checked as a whole before any entry is read.

The archive, read from a regular file or given in memory, is within its size limit. Its entries
are counted from the central directory headers before the ZIP library indexes them. Its declared
decompressed size, compression methods (stored or deflate only) and every entry name are
checked next: names as stored, before the ZIP library truncates them at a NUL character. The
entries must lie end to end, from the first byte of the archive to its central directory, so that
no byte belongs to no entry and no entry overlaps another; and the encrypted entries are limited
in total, since decrypting costs CPU time for every encrypted byte read.

Entry data is read here, not by the ZIP library, which stops at the declared size and would
accept a stream that goes on beyond it. The local header must match the central directory;
ZipCrypto entries are decrypted with the given password; deflate output is bounded to one byte
past the declared size; and the stream must end exactly at the declared size, with the declared
CRC. Every tool that reads the archive therefore sees the same content. Refusals raise
``UnsafeInputError`` with an ``IO-*`` code.
"""

import io
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
from pathlib import Path

from scenario_tools.adapters.safe_readers import read_regular_file
from scenario_tools.ports.errors import UnsafeInputError

ARCHIVE_LIMIT = 20 * 1024 * 1024
DECOMPRESSED_LIMIT = 100 * 1024 * 1024
ENCRYPTED_LIMIT = 10 * 1024 * 1024
ENTRY_LIMIT = 1000

_DRIVE = re.compile(r"[A-Za-z]:")
# What the ZIP library raises on a malformed central directory.
_ZIP_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, ValueError, OSError)
_STORED, _DEFLATED = 0, 8
_ENCRYPTED, _DATA_DESCRIPTOR, _UTF8_NAME = 0x1, 0x8, 0x800
_LOCAL = b"PK\x03\x04"
_LOCAL_SIZE = 30
_DESCRIPTOR = b"PK\x07\x08"
_ZIP64_EXTRA = 0x0001
_ZIP64_MARK = 0xFFFFFFFF
_DEFLATE_OPTIONS = 0x6
# Every other flag (patched data, strong encryption, masked headers…) changes how an entry is
# decoded in a way this reader does not implement.
_SUPPORTED_FLAGS = _ENCRYPTED | _DEFLATE_OPTIONS | _DATA_DESCRIPTOR | _UTF8_NAME
_ZIPCRYPTO_HEADER = 12


_END = b"PK\x05\x06"
_END_SIZE = 22
_ZIP64_END = b"PK\x06\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_ZIP64_TRAILER_SIZE = 56 + 20  # zip64 end record, then its locator, before the end record
_CENTRAL = b"PK\x01\x02"
_CENTRAL_SIZE = 46


def _count_entries(data: bytes, stop: int) -> int:
    """Count the central directory headers, stopping at ``stop``, where the ZIP library will
    look for them, but without building its index of every entry. Returns what was counted when
    the directory cannot be walked: the ZIP library then reports the archive as invalid."""
    end = data.rfind(_END, max(0, len(data) - _END_SIZE - 0xFFFF))
    if end < 0 or end + _END_SIZE > len(data):
        return 0
    (size,) = struct.unpack_from("<I", data, end + 12)
    directory_end = end
    trailer = end - _ZIP64_TRAILER_SIZE
    is_zip64 = data[end - 20 : end - 16] == _ZIP64_LOCATOR
    if trailer >= 0 and is_zip64 and data[trailer : trailer + 4] == _ZIP64_END:
        (size,) = struct.unpack_from("<Q", data, trailer + 40)
        directory_end = trailer
    position = directory_end - size
    count = 0
    while 0 <= position < directory_end and count < stop:
        if position + _CENTRAL_SIZE > len(data) or data[position : position + 4] != _CENTRAL:
            break
        name, extra, comment = struct.unpack_from("<HHH", data, position + 28)
        position += _CENTRAL_SIZE + name + extra + comment
        count += 1
    return count


def _crc_table() -> tuple[int, ...]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _crc_table()


class _ZipCryptoKeys:
    """The key state of traditional PKWARE encryption (APPNOTE 6.1), the `zip -P` convention."""

    def __init__(self, password: bytes) -> None:
        self._keys = [0x12345678, 0x23456789, 0x34567890]
        for byte in password:
            self._update(byte)

    def _update(self, byte: int) -> None:
        keys = self._keys
        keys[0] = (keys[0] >> 8) ^ _CRC_TABLE[(keys[0] ^ byte) & 0xFF]
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = (keys[2] >> 8) ^ _CRC_TABLE[(keys[2] ^ (keys[1] >> 24)) & 0xFF]

    def decrypt(self, data: bytes) -> bytes:
        plain = bytearray(len(data))
        for index, byte in enumerate(data):
            temp = (self._keys[2] | 2) & 0xFFFF
            plain[index] = byte ^ ((temp * (temp ^ 1)) >> 8) & 0xFF
            self._update(plain[index])
        return bytes(plain)


def _zipcrypto_decrypt(data: bytes, password: bytes, check_byte: int) -> bytes | None:
    """Decrypt an entry, or return ``None`` when the password does not match the check byte of
    its 12-byte header, found before the rest of the entry is decrypted. This is a decoding step,
    not a security control: the conventional password is public."""
    keys = _ZipCryptoKeys(password)
    if keys.decrypt(data[:_ZIPCRYPTO_HEADER])[-1] != check_byte:
        return None
    return keys.decrypt(data[_ZIPCRYPTO_HEADER:])


def _zip64_extra(extra: bytes) -> bytes | None:
    """The zip64 field of an extra block, or ``None`` when there is none."""
    position = 0
    while position + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, position)
        if tag == _ZIP64_EXTRA:
            return extra[position + 4 : position + 4 + size]
        position += 4 + size
    return None


def _dos_time(info: zipfile.ZipInfo) -> int:
    """The DOS modification time the directory holds for an entry."""
    hour, minute, second = info.date_time[3:]
    return (hour << 11) | (minute << 5) | (second // 2)


def _local_sizes(header: bytes, extra: bytes) -> tuple[int, int]:
    """The compressed and uncompressed sizes a local header declares, zip64 included. In a local
    header, the zip64 field holds both sizes (APPNOTE 4.5.3), not only the promoted ones. A zip64
    marker without a full zip64 field is returned as is, and so never matches the directory."""
    compressed, size = struct.unpack_from("<II", header, 18)
    field = _zip64_extra(extra)
    if _ZIP64_MARK in (compressed, size) and field is not None and len(field) >= 16:
        size, compressed = struct.unpack_from("<QQ", field)
    return compressed, size


def _entry_end(data: bytes, position: int, info: zipfile.ZipInfo) -> int | None:
    """Where the entry whose local header is at ``position`` ends, after its data and, when
    flagged, its data descriptor; or ``None`` when the local header or the descriptor says
    something else than the directory."""
    header = data[position : position + _LOCAL_SIZE]
    flags, method, time = struct.unpack_from("<3H", header, 6)
    (crc,) = struct.unpack_from("<I", header, 14)
    name_length, extra_length = struct.unpack_from("<HH", header, 26)
    extra_start = position + _LOCAL_SIZE + name_length
    extra = data[extra_start : extra_start + extra_length]
    if flags != info.flag_bits or method != info.compress_type:
        return None
    if flags & _ENCRYPTED and flags & _DATA_DESCRIPTOR and time != _dos_time(info):
        return None  # the time then gives the password check byte: both readers must agree
    # The ZIP library decoded the name with the encoding these agreeing flags select, so
    # encoding it back gives the bytes the directory holds.
    encoding = "utf-8" if flags & _UTF8_NAME else "cp437"
    if data[position + _LOCAL_SIZE : extra_start] != info.orig_filename.encode(encoding):
        return None
    end: int = extra_start + extra_length + info.compress_size
    if not flags & _DATA_DESCRIPTOR:
        sizes = _local_sizes(header, extra)
        agrees = crc == info.CRC and sizes == (info.compress_size, info.file_size)
        return end if agrees else None
    layout = "<QQ" if _zip64_extra(extra) is not None else "<II"
    if layout == "<II" and max(info.compress_size, info.file_size) > _ZIP64_MARK:
        return None  # a size the descriptor this local header announces cannot hold
    body = struct.pack("<I", info.CRC) + struct.pack(layout, info.compress_size, info.file_size)
    for descriptor in (_DESCRIPTOR + body, body):  # its signature is optional
        if data.startswith(descriptor, end):
            return end + len(descriptor)
    return None


def _check_layout(data: bytes, infos: list[zipfile.ZipInfo], directory: int, path: str) -> None:
    """Require the entries to lie end to end from the first byte to the central directory, each
    local header saying what the directory says: a streaming reader, which follows the local
    headers, then sees exactly the entries that were checked."""
    position = 0
    for info in sorted(infos, key=lambda entry: entry.header_offset):
        header = data[position : position + _LOCAL_SIZE]
        if info.header_offset != position or len(header) < _LOCAL_SIZE or header[:4] != _LOCAL:
            raise UnsafeInputError(
                "IO-007", f"entries overlap or leave bytes no entry lists, at {position}", path
            )
        end = _entry_end(data, position, info)
        if end is None:
            raise UnsafeInputError(
                "IO-007",
                f"local header of entry {info.filename!r} disagrees with the directory",
                path,
            )
        position = end
    if position != directory:
        raise UnsafeInputError(
            "IO-007", f"entries overlap or leave bytes no entry lists, at {position}", path
        )


def _is_unsafe_name(raw: str) -> bool:
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/") or _DRIVE.match(raw):
        return True
    return ".." in raw.split("/")


class CheckedArchive:
    """A ZIP archive whose structure passed every check; its entries are read on demand."""

    def __init__(self, data: bytes, archive: zipfile.ZipFile, path: str) -> None:
        self._data = data
        self._entries = {info.filename: info for info in archive.infolist()}
        self.path = path
        self.names = tuple(info.filename for info in archive.infolist())

    def _refuse(self, code: str, message: str) -> UnsafeInputError:
        return UnsafeInputError(code, message, self.path)

    def _stored_data(self, info: zipfile.ZipInfo) -> bytes:
        """The entry's bytes as stored. The layout check already proved that its local header
        says what the directory says and that the data lies within the archive."""
        start = info.header_offset
        name_length, extra_length = struct.unpack_from("<HH", self._data, start + 26)
        begin = start + _LOCAL_SIZE + name_length + extra_length
        return self._data[begin : begin + info.compress_size]

    def _decrypt(self, info: zipfile.ZipInfo, data: bytes, password: bytes | None) -> bytes:
        if password is None:
            raise self._refuse("IO-007", f"entry {info.filename!r} is encrypted, password required")
        if len(data) < _ZIPCRYPTO_HEADER:
            raise self._refuse("IO-007", f"entry {info.filename!r} too short for its encryption")
        # With a data descriptor, the CRC is not known when the header is written: the check
        # byte is then the high byte of the modification time.
        descriptor = info.flag_bits & _DATA_DESCRIPTOR
        check_byte = _dos_time(info) >> 8 if descriptor else info.CRC >> 24
        plain = _zipcrypto_decrypt(data, password, check_byte)
        if plain is None:
            raise self._refuse("IO-007", f"wrong password for entry {info.filename!r}")
        return plain

    def _decompress(self, info: zipfile.ZipInfo, data: bytes) -> bytes:
        """Decompress, never more than one byte past the declared size, and require the stream
        to end exactly there."""
        if info.compress_type == _STORED:
            if len(data) != info.file_size:
                raise self._refuse(
                    "IO-008", f"entry {info.filename!r} differs from its declared size"
                )
            return data
        decompressor = zlib.decompressobj(-15)
        try:
            content = decompressor.decompress(data, info.file_size + 1)
        except zlib.error as error:
            raise self._refuse("IO-007", f"entry {info.filename!r}: {error}") from error
        if len(content) > info.file_size:  # the stream goes on beyond the declared size
            raise self._refuse("IO-008", f"entry {info.filename!r} larger than declared")
        if not decompressor.eof:
            raise self._refuse("IO-007", f"entry {info.filename!r}: stream cut short")
        if decompressor.unused_data:
            raise self._refuse(
                "IO-007", f"entry {info.filename!r}: data after the end of the stream"
            )
        if len(content) != info.file_size:
            raise self._refuse("IO-008", f"entry {info.filename!r} smaller than declared")
        return content

    def read(self, name: str, *, password: bytes | None = None) -> bytes:
        """Read one entry exactly as declared, or raise ``UnsafeInputError``."""
        info = self._entries[name]
        data = self._stored_data(info)
        if info.flag_bits & _ENCRYPTED:
            data = self._decrypt(info, data, password)
        content = self._decompress(info, data)
        if zlib.crc32(content) != info.CRC:
            raise self._refuse("IO-007", f"bad CRC for entry {info.filename!r}")
        return content


def archive_from_bytes(
    data: bytes,
    *,
    path: str = "<input>",
    archive_limit: int = ARCHIVE_LIMIT,
    decompressed_limit: int = DECOMPRESSED_LIMIT,
    encrypted_limit: int = ENCRYPTED_LIMIT,
    entry_limit: int = ENTRY_LIMIT,
) -> CheckedArchive:
    """Check the structure of a ZIP archive held in memory, or raise ``UnsafeInputError``."""
    if len(data) > archive_limit:
        raise UnsafeInputError("IO-001", f"larger than {archive_limit} bytes", path)
    if _count_entries(data, entry_limit + 1) > entry_limit:
        raise UnsafeInputError("IO-009", f"more than {entry_limit} entries", path)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except _ZIP_ERRORS as error:
        raise UnsafeInputError("IO-007", f"not a valid ZIP archive: {error}", path) from error
    if len(infos) > entry_limit:  # a second defence, should the walk above miss a layout
        raise UnsafeInputError("IO-009", f"more than {entry_limit} entries", path)
    if sum(info.file_size for info in infos) > decompressed_limit:
        raise UnsafeInputError("IO-008", f"declared size over {decompressed_limit} bytes", path)
    encrypted = sum(info.compress_size for info in infos if info.flag_bits & _ENCRYPTED)
    if encrypted > encrypted_limit:
        raise UnsafeInputError("IO-008", f"encrypted entries over {encrypted_limit} bytes", path)
    seen: set[str] = set()
    for info in infos:
        if info.compress_type not in (_STORED, _DEFLATED):
            raise UnsafeInputError(
                "IO-007", f"compression method {info.compress_type} not allowed", path
            )
        if info.flag_bits & ~_SUPPORTED_FLAGS:
            raise UnsafeInputError(
                "IO-007", f"flags {info.flag_bits:#06x} not supported for {info.filename!r}", path
            )
        if _is_unsafe_name(info.orig_filename):
            raise UnsafeInputError("IO-010", f"unsafe entry name {info.orig_filename!r}", path)
        if stat.S_ISLNK(info.external_attr >> 16):
            raise UnsafeInputError("IO-011", f"link entry {info.filename!r}", path)
        key = unicodedata.normalize("NFC", info.filename).casefold()
        if key in seen:
            raise UnsafeInputError("IO-012", f"duplicate entry name {info.filename!r}", path)
        seen.add(key)
    _check_layout(data, infos, archive.start_dir, path)
    return CheckedArchive(data, archive, path)


def open_zip(
    path: Path,
    *,
    archive_limit: int = ARCHIVE_LIMIT,
    decompressed_limit: int = DECOMPRESSED_LIMIT,
    encrypted_limit: int = ENCRYPTED_LIMIT,
    entry_limit: int = ENTRY_LIMIT,
) -> CheckedArchive:
    """Read a ZIP archive file within its limits and check it, or raise ``UnsafeInputError``."""
    return archive_from_bytes(
        read_regular_file(path, archive_limit),
        path=str(path),
        archive_limit=archive_limit,
        decompressed_limit=decompressed_limit,
        encrypted_limit=encrypted_limit,
        entry_limit=entry_limit,
    )
