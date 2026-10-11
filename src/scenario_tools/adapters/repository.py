"""Adapter: the repository's entries, read by their path in the repository, never through a
symbolic link, parent directories included, and within the input limits."""

import errno
import os
import shutil
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TypeVar

from scenario_tools.adapters.data_files import read_stored_scenario, write_output
from scenario_tools.adapters.safe_readers import read_text_file, read_yaml_file
from scenario_tools.domain.catalogue.intake import CatalogueEntry
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

_T = TypeVar("_T")


_ABSENT = (errno.ENOENT, errno.ENOTDIR)


def _exists(path: Path) -> bool:
    """Whether ``path`` exists, a link included; one that cannot be looked at is the
    environment's fault, never taken as absent, so that no entry is left out unseen."""
    try:
        os.lstat(path)
    except OSError as error:
        if error.errno in _ABSENT:
            return False
        raise EnvironmentProblemError(f"cannot read {path}: {error.strerror}") from error
    return True


def _directories(path: Path) -> list[str]:
    """The names of the directories in ``path``, never through a link; none when ``path`` is
    not a directory itself. One that cannot be read is the environment's fault."""
    try:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            return []
        with os.scandir(path) as entries:
            return sorted(
                entry.name
                for entry in entries
                # A hidden one is no entry: one a write that was cut short left behind.
                if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False)
            )
    except OSError as error:
        if error.errno in _ABSENT:
            return []
        raise EnvironmentProblemError(f"cannot read {path}: {error.strerror}") from error


class RepositoryEntries:
    """The entries of the repository at ``root``."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._entries: tuple[CatalogueEntry, ...] | None = None

    def _checked(self, relative: str) -> Path:
        """``relative``, a path in the repository, once no directory of it is a link."""
        parts = relative.split("/")
        current = self._root
        for index, part in enumerate(parts[:-1]):
            current = current / part
            try:
                mode = os.lstat(current).st_mode
            except OSError as error:
                where = "/".join(parts[: index + 1])
                raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
            if stat.S_ISLNK(mode):
                where = "/".join(parts[: index + 1])
                raise UnsafeInputError(
                    "IO-013", "a directory of the path is a symbolic link, never followed", where
                )
        return current / parts[-1]

    def _read(self, relative: str, read: Callable[[Path], _T]) -> _T:
        try:
            return read(self._checked(relative))
        except UnsafeInputError as error:
            if error.path != str(self._root / relative):
                raise  # it names a directory of the path already
            raise UnsafeInputError(error.code, error.message, relative) from error

    def directory(self, relative: str) -> Path:
        """The directory at ``relative``, once neither it nor a directory above it in the
        repository is a link, such as the policy data or the schemas the checks read."""
        return self._checked(f"{relative}/-").parent

    def names(self, entry: str) -> frozenset[str]:
        directory = self.directory(entry)
        try:
            return frozenset(child.name for child in directory.iterdir())
        except OSError as error:
            raise EnvironmentProblemError(f"cannot read {entry}: {error.strerror}") from error

    def read_yaml(self, path: str) -> object:
        return self._read(path, read_yaml_file)

    def read_json(self, path: str) -> tuple[bytes, object]:
        return self._read(path, read_stored_scenario)

    def read_text(self, path: str) -> str:
        return self._read(path, read_text_file)

    def make_directory(self, relative: str) -> Path:
        """The directory at ``relative``, made with those above it that are missing, never
        through a link nor over a file."""
        parts = relative.split("/")
        current = self._root
        for index, part in enumerate(parts):
            current = current / part
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                try:
                    current.mkdir(mode=0o755)
                except OSError as error:
                    raise EnvironmentProblemError(
                        f"cannot make {'/'.join(parts[: index + 1])}: {error.strerror}"
                    ) from error
                continue
            except OSError as error:
                where = "/".join(parts[: index + 1])
                raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
            if not stat.S_ISDIR(mode):  # a link is no directory to lstat
                where = "/".join(parts[: index + 1])
                raise UnsafeInputError(
                    "IO-013", "not a directory: a link or a file, never followed", where
                )
        return current

    def write_entry(self, entry: str, files: Mapping[str, bytes], *, new: bool) -> None:
        """Write ``files``, by name, in the entry at ``entry``. A new entry's place is reserved
        at once, never over anything there, and what this write made is removed if it cannot
        end. An existing entry has the files given replaced, each at once."""
        if not new:
            directory = self.directory(entry)
            for name, data in files.items():
                write_output(directory / name, data)
            return
        parent_path, slug = entry.rsplit("/", 1)
        target = self.make_directory(parent_path) / slug
        try:
            target.mkdir(mode=0o755)  # fails if anything is there, even made a moment ago
        except FileExistsError as error:
            raise EnvironmentProblemError(f"cannot write {entry}: it already exists") from error
        except OSError as error:
            raise EnvironmentProblemError(f"cannot write {entry}: {error.strerror}") from error
        try:
            target.chmod(0o755)
            for name, data in files.items():
                write_output(target / name, data, create=True)
        except BaseException:
            shutil.rmtree(target, ignore_errors=True)
            raise

    def exists(self, path: str) -> bool:
        parts = path.split("/")
        for index in range(1, len(parts)):
            if not _exists(self._root.joinpath(*parts[:index])):
                return False  # a directory above it is missing: nothing is there
        return _exists(self._checked(path))

    def entries(self) -> tuple[CatalogueEntry, ...]:
        """Read once a run, however many entries are checked against them."""
        if self._entries is None:
            self._entries = self._read_entries()
        return self._entries

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        found: dict[str, list[str]] = {}
        for entry in self.entries():
            if entry.external_id:
                found.setdefault(entry.external_id, []).append(entry.path)
        return {external_id: tuple(found[external_id]) for external_id in sorted(found)}

    def _read_entries(self) -> tuple[CatalogueEntry, ...]:
        found: list[CatalogueEntry] = []
        base = self._root / "scenarios"
        for domain in _directories(base):
            for slug in _directories(base / domain):
                metadata = base / domain / slug / "scenario.yaml"
                if not _exists(metadata):
                    continue  # not an entry, or one its own check reports as incomplete
                try:
                    document = read_yaml_file(metadata)
                except UnsafeInputError:
                    continue  # the entry's own check says why it is refused
                fields = document if isinstance(document, dict) else {}
                external_id, name = fields.get("external_id"), fields.get("name")
                if isinstance(external_id, str) or isinstance(name, str):
                    # Its name counts even when its identifier does not: no other may take it.
                    found.append(
                        CatalogueEntry(
                            f"scenarios/{domain}/{slug}",
                            external_id if isinstance(external_id, str) else "",
                            name if isinstance(name, str) else "",
                        )
                    )
        return tuple(found)
