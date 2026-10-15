"""ZIP archives written by hand, for the release fixtures: the shapes the deterministic writer
never makes (an encrypted entry, a name leaving the extraction directory, a deflate bomb), the
same bytes on every build.

Every entry is dated 1980-01-01 00:00:00 and marked as a Unix regular file, as the writer of
``build`` does. Deflate streams are written bit by bit, never by zlib, whose output depends on its
version; an encrypted entry's 12-byte header is fixed instead of random. Nothing here is a
security control: these archives exist to be refused, or to be read as ``build`` writes them.
"""

import stat
import struct
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from scenario_tools.adapters.safe_zip import ZipCryptoKeys

_DATE = (1 << 5) | 1  # 1980-01-01, the earliest a ZIP can hold, at 00:00:00
_VERSION = 20  # 2.0: deflate and traditional encryption
_MADE_BY = (3 << 8) | _VERSION  # on Unix, whatever the system that builds it
_REGULAR = (stat.S_IFREG | 0o644) << 16
_LINK = (stat.S_IFLNK | 0o777) << 16
_UTF8 = 0x800
_RUN = 258  # the longest match deflate can say


@dataclass(frozen=True)
class HandmadeEntry:
    """An entry as it is written: its bytes as stored (compressed, encrypted), its method (0
    stored, 8 deflate), the CRC-32 and size its content declares, its flags and its comment."""

    name: str
    data: bytes
    method: int
    crc: int
    size: int
    flags: int = 0
    comment: bytes = b""
    link: bool = False


def handmade_zip(entries: Sequence[HandmadeEntry]) -> bytes:
    """A ZIP archive holding ``entries`` in that order, written as they are given."""
    local = bytearray()
    central = bytearray()
    for entry in entries:
        name = entry.name.encode("utf-8")
        flags = entry.flags | (0 if name.isascii() else _UTF8)
        fields = (entry.method, 0, _DATE, entry.crc, len(entry.data), entry.size, len(name))
        offset = len(local)
        local += struct.pack("<IHH" + "HHHIIIHH", 0x04034B50, _VERSION, flags, *fields, 0)
        local += name + entry.data
        central += struct.pack(
            "<IHHH" + "HHHIIIHH" + "HHHII",
            0x02014B50,
            _MADE_BY,
            _VERSION,
            flags,
            *fields,
            0,
            len(entry.comment),
            0,
            0,
            _LINK if entry.link else _REGULAR,
            offset,
        )
        central += name + entry.comment
    count = len(entries)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count, len(central), len(local), 0)
    return bytes(local + central + end)


def zipcrypto(plain: bytes, password: bytes, check_byte: int) -> bytes:
    """``plain`` encrypted with ``password``, after the 12-byte header whose last byte is
    ``check_byte`` (the high byte of the entry's CRC-32); the other header bytes are zero."""
    return ZipCryptoKeys(password).encrypt(bytes(11) + bytes([check_byte]) + plain)


def encrypted_zip(files: Mapping[str, bytes], password: bytes) -> bytes:
    """An archive of ``files``, by name, each stored and encrypted with ``password``."""
    entries = []
    for name, plain in sorted(files.items()):
        crc = zlib.crc32(plain)
        encrypted = zipcrypto(plain, password, crc >> 24)
        entries.append(HandmadeEntry(name, encrypted, 0, crc, len(plain), flags=1))
    return handmade_zip(entries)


class _Bits:
    """A deflate bit stream: values written from their least significant bit, Huffman codes from
    their most significant one."""

    def __init__(self) -> None:
        self._value = 0
        self._count = 0
        self._out = bytearray()

    def value(self, value: int, width: int) -> None:
        self._value |= value << self._count
        self._count += width
        while self._count >= 8:
            self._out.append(self._value & 0xFF)
            self._value >>= 8
            self._count -= 8

    @staticmethod
    def reversed(code: int, width: int) -> int:
        return int(format(code, f"0{width}b")[::-1], 2)

    def code(self, code: int, width: int) -> None:
        self.value(self.reversed(code, width), width)

    def bytes(self) -> bytes:
        return bytes(self._out + (bytes([self._value]) if self._count else b""))


def zero_deflate(size: int) -> bytes:
    """A raw deflate stream of ``size`` zero bytes, in one block of fixed Huffman codes: a zero,
    then runs of 258 bytes copied from one byte back, then zeros one by one, then the end."""
    if size < 1:
        raise ValueError("a stream of zeros holds at least one byte")
    bits = _Bits()
    bits.value(1, 1)  # the last block
    bits.value(1, 2)  # of fixed Huffman codes
    bits.code(0x30, 8)  # the literal 0
    runs, rest = divmod(size - 1, _RUN)
    run = _Bits.reversed(0xC5, 8) | _Bits.reversed(0, 5) << 8  # length 258, one byte back
    for _ in range(runs):
        bits.value(run, 13)
    for _ in range(rest):
        bits.code(0x30, 8)
    bits.code(0, 7)  # the end of the block
    return bits.bytes()


def _zero_crc(size: int) -> int:
    crc, chunk = 0, bytes(1024 * 1024)
    while size > 0:
        crc = zlib.crc32(chunk[: min(size, len(chunk))], crc)
        size -= len(chunk)
    return crc


class HandmadeArchives:
    """The fixture archives, written by hand."""

    def stored(
        self, entries: Sequence[tuple[str, bytes, bytes]], *, links: frozenset[str] = frozenset()
    ) -> bytes:
        return handmade_zip(
            [
                HandmadeEntry(name, data, 0, zlib.crc32(data), len(data), 0, comment, name in links)
                for name, data, comment in entries
            ]
        )

    def bomb(self, name: str, comment: bytes, size: int, *, declared: int | None = None) -> bytes:
        stream = zero_deflate(size)
        told = size if declared is None else declared
        return handmade_zip([HandmadeEntry(name, stream, 8, _zero_crc(size), told, 0, comment)])

    def attachments(self, files: Mapping[str, bytes], password: bytes) -> bytes:
        return encrypted_zip(files, password)
