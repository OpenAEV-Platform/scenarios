"""The payload catalogue as a directory of the file system, read without following a link and
without git."""

import os
import stat
from pathlib import Path

from scenario_tools.adapters.safe_readers import parse_json, read_regular_file
from scenario_tools.domain.verification.payload_catalogue import EntryKind, TreeEntry
from scenario_tools.domain.verification.payload_version import VERSION_FILE_LIMIT
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

_BOM = b"\xef\xbb\xbf"


def _kind(mode: int) -> EntryKind:
    if stat.S_ISDIR(mode):
        return EntryKind.FOLDER
    return EntryKind.FILE if stat.S_ISREG(mode) else EntryKind.SPECIAL


class CatalogueDirectory:
    """The catalogue held by the directory ``root``, itself never a link."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def _listed(self, directory: Path) -> list[os.DirEntry[str]]:
        try:
            with os.scandir(directory) as found:
                return sorted(found, key=lambda entry: entry.name)
        except OSError as error:
            raise EnvironmentProblemError(f"cannot list {directory}: {error.strerror}") from error

    def entries(self) -> tuple[TreeEntry, ...]:
        try:
            mode = os.lstat(self._root).st_mode
        except OSError as error:
            raise EnvironmentProblemError(f"cannot read {self._root}: {error.strerror}") from error
        if not stat.S_ISDIR(mode):
            raise UnsafeInputError("IO-013", "a symbolic link or not a directory", str(self._root))
        found: list[TreeEntry] = []
        for folder in self._listed(self._root):
            kind = _kind(self._status(folder).st_mode)
            found.append(TreeEntry((folder.name,), kind, 0))
            if kind is not EntryKind.FOLDER:
                continue
            for item in self._listed(Path(folder.path)):
                status = self._status(item)
                found.append(
                    TreeEntry((folder.name, item.name), _kind(status.st_mode), status.st_size)
                )
        return tuple(found)

    @staticmethod
    def _status(entry: os.DirEntry[str]) -> os.stat_result:
        try:
            return entry.stat(follow_symlinks=False)
        except OSError as error:  # gone while listed, for instance
            raise EnvironmentProblemError(f"cannot read {entry.path}: {error.strerror}") from error

    def read(self, path: tuple[str, ...]) -> tuple[bytes, object]:
        where = self._root.joinpath(*path)
        # The file is opened without following a link; the folders on the way are checked again,
        # so that one replaced by a link since it was listed is refused, not followed.
        for depth in range(len(path)):
            folder = self._root.joinpath(*path[:depth])
            try:
                mode = os.lstat(folder).st_mode
            except OSError as error:
                raise EnvironmentProblemError(f"cannot read {folder}: {error.strerror}") from error
            if not stat.S_ISDIR(mode):
                raise UnsafeInputError("IO-013", "a symbolic link or not a directory", str(folder))
        data = read_regular_file(where, VERSION_FILE_LIMIT)
        # A byte order mark is read past: the file is then refused as not in the stored form,
        # which its bytes are compared with, rather than as JSON it is not.
        return data, parse_json(data.removeprefix(_BOM), path=str(where), limit=VERSION_FILE_LIMIT)
