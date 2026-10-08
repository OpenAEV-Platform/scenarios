"""Bounded ZIP reader: an archive is checked as a whole before any entry is read.

The archive, read from a regular file or given in memory, is within its size limit. Its entries
are counted from the central directory headers before the ZIP library indexes them. Its declared
decompressed size and every entry name are checked next: names as stored, before the ZIP library
truncates them at a NUL character. Reading an entry is bounded while streaming, and its actual
size must equal its declared size, because headers can lie; the total declared size then bounds
what can really be decompressed. Refusals raise ``UnsafeInputError`` with an ``IO-*`` code.
"""

import io
import lzma
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
ENTRY_LIMIT = 1000

_CHUNK = 64 * 1024
_DRIVE = re.compile(r"[A-Za-z]:")
# What the ZIP library raises on malformed, unsupported or encrypted content.
_ZIP_ERRORS = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    NotImplementedError,
    RuntimeError,
    ValueError,
    EOFError,
    OSError,
    zlib.error,
    lzma.LZMAError,
)


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


def _is_unsafe_name(raw: str) -> bool:
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/") or _DRIVE.match(raw):
        return True
    return ".." in raw.split("/")


class CheckedArchive:
    """A ZIP archive whose structure passed every check; its entries are read on demand."""

    def __init__(self, archive: zipfile.ZipFile, path: str) -> None:
        self._archive = archive
        self._entries = {info.filename: info for info in archive.infolist()}
        self.path = path
        self.names = tuple(info.filename for info in archive.infolist())

    def read(self, name: str, *, password: bytes | None = None) -> bytes:
        """Read one entry, never more than its declared size, or raise ``UnsafeInputError``."""
        info = self._entries[name]
        chunks: list[bytes] = []
        size = 0
        try:
            with self._archive.open(info, pwd=password) as entry:
                while chunk := entry.read(_CHUNK):
                    size += len(chunk)
                    if size > info.file_size:
                        raise UnsafeInputError(
                            "IO-008", f"entry {name!r} larger than declared", self.path
                        )
                    chunks.append(chunk)
        except _ZIP_ERRORS as error:
            raise UnsafeInputError(
                "IO-007", f"cannot read entry {name!r}: {error}", self.path
            ) from error
        if size != info.file_size:
            raise UnsafeInputError("IO-008", f"entry {name!r} smaller than declared", self.path)
        return b"".join(chunks)


def archive_from_bytes(
    data: bytes,
    *,
    path: str = "<input>",
    archive_limit: int = ARCHIVE_LIMIT,
    decompressed_limit: int = DECOMPRESSED_LIMIT,
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
    seen: set[str] = set()
    for info in infos:
        if _is_unsafe_name(info.orig_filename):
            raise UnsafeInputError("IO-010", f"unsafe entry name {info.orig_filename!r}", path)
        if stat.S_ISLNK(info.external_attr >> 16):
            raise UnsafeInputError("IO-011", f"link entry {info.filename!r}", path)
        key = unicodedata.normalize("NFC", info.filename).casefold()
        if key in seen:
            raise UnsafeInputError("IO-012", f"duplicate entry name {info.filename!r}", path)
        seen.add(key)
    return CheckedArchive(archive, path)


def open_zip(
    path: Path,
    *,
    archive_limit: int = ARCHIVE_LIMIT,
    decompressed_limit: int = DECOMPRESSED_LIMIT,
    entry_limit: int = ENTRY_LIMIT,
) -> CheckedArchive:
    """Read a ZIP archive file within its limits and check it, or raise ``UnsafeInputError``."""
    return archive_from_bytes(
        read_regular_file(path, archive_limit),
        path=str(path),
        archive_limit=archive_limit,
        decompressed_limit=decompressed_limit,
        entry_limit=entry_limit,
    )
