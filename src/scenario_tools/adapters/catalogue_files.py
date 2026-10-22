"""The payload catalogue as a directory of the file system, read without following a link and
without git.

Each directory is opened once, never through a link, and what it holds is listed and opened
relative to that open directory: a folder replaced by a link after it was listed is refused, never
followed, whether it is being listed or read."""

import contextlib
import errno
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from scenario_tools.adapters.safe_readers import parse_json
from scenario_tools.domain.verification.payload_catalogue import EntryKind, TreeEntry
from scenario_tools.domain.verification.payload_version import VERSION_FILE_LIMIT
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

_BOM = b"\xef\xbb\xbf"
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _kind(mode: int) -> EntryKind:
    if stat.S_ISDIR(mode):
        return EntryKind.FOLDER
    return EntryKind.FILE if stat.S_ISREG(mode) else EntryKind.SPECIAL


@contextmanager
def _directory(name: str, shown: str, parent: int | None = None) -> Iterator[int]:
    """The directory ``name`` (relative to the open directory ``parent``, if given), opened
    without following a link, for as long as the block runs."""
    try:
        descriptor = os.open(name, _DIRECTORY, dir_fd=parent)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise UnsafeInputError("IO-013", "a symbolic link or not a directory", shown) from error
        raise EnvironmentProblemError(f"cannot read {shown}: {error.strerror}") from error
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _listed(descriptor: int, shown: str) -> list[tuple[str, os.stat_result]]:
    """The names an open directory holds, each with its status, never through a link."""
    try:
        with os.scandir(descriptor) as found:
            names = sorted(entry.name for entry in found)
        return [(name, os.stat(name, dir_fd=descriptor, follow_symlinks=False)) for name in names]
    except OSError as error:  # gone while listed, for instance
        raise EnvironmentProblemError(f"cannot list {shown}: {error.strerror}") from error


def _read(parent: int, name: str, shown: str) -> bytes:
    """A regular file of an open directory, never through a link, at most the size limit."""
    try:
        descriptor = os.open(name, _FILE, dir_fd=parent)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafeInputError("IO-013", "a symbolic link", shown) from error
        if error.errno == errno.ENXIO:
            raise UnsafeInputError("IO-013", "not a regular file", shown) from error
        raise EnvironmentProblemError(f"cannot read {shown}: {error.strerror}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise UnsafeInputError("IO-013", "not a regular file", shown)
        with os.fdopen(descriptor, "rb", closefd=False) as file:
            data = file.read(VERSION_FILE_LIMIT + 1)
    except OSError as error:
        raise EnvironmentProblemError(f"cannot read {shown}: {error.strerror}") from error
    finally:
        os.close(descriptor)
    if len(data) > VERSION_FILE_LIMIT:
        raise UnsafeInputError("IO-001", f"larger than {VERSION_FILE_LIMIT} bytes", shown)
    return data


class CatalogueDirectory:
    """The catalogue at ``parts`` below the repository ``repository``: the path to the
    repository may go through a link, but no directory from the repository down is one."""

    def __init__(self, repository: Path, parts: tuple[str, ...]) -> None:
        self._repository = repository
        self._parts = parts
        self._root = repository.joinpath(*parts)

    @contextmanager
    def _catalogue(self) -> Iterator[int]:
        """The catalogue's directory, opened one directory at a time from the repository, none
        of them through a link."""
        with contextlib.ExitStack() as opened:
            current = opened.enter_context(_directory(str(self._repository), str(self._repository)))
            for depth, part in enumerate(self._parts, 1):
                shown = str(self._repository.joinpath(*self._parts[:depth]))
                current = opened.enter_context(_directory(part, shown, current))
            yield current

    def entries(self) -> tuple[TreeEntry, ...]:
        found: list[TreeEntry] = []
        with self._catalogue() as root:
            for name, status in _listed(root, str(self._root)):
                kind = _kind(status.st_mode)
                found.append(TreeEntry((name,), kind, 0))
                if kind is not EntryKind.FOLDER:
                    continue
                shown = str(self._root / name)
                with _directory(name, shown, root) as folder:
                    found += [
                        TreeEntry((name, item), _kind(held.st_mode), held.st_size)
                        for item, held in _listed(folder, shown)
                    ]
        return tuple(found)

    def read(self, path: tuple[str, ...]) -> tuple[bytes, object]:
        folder_name, file_name = path
        shown = str(self._root.joinpath(*path))
        with (
            self._catalogue() as root,
            _directory(folder_name, str(self._root / folder_name), root) as folder,
        ):
            data = _read(folder, file_name, shown)
        # A byte order mark is read past: the file is then refused as not in the stored form,
        # which its bytes are compared with, rather than as JSON it is not.
        return data, parse_json(data.removeprefix(_BOM), path=shown, limit=VERSION_FILE_LIMIT)
