"""Adapter: the repository's entries, read by their path in the repository, never through a
symbolic link, parent directories included, and within the input limits; written from the
descriptor of the repository held, one directory at a time, never through a link."""

import contextlib
import errno
import fcntl
import os
import stat
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TypeVar

from scenario_tools.adapters.data_files import read_stored_scenario
from scenario_tools.adapters.places import (
    identity,
    is_hidden_name,
)
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


def _listing(path: Path) -> list[tuple[str, bool]]:
    """The directories and links in ``path``, each with whether it is a link, never followed;
    none when ``path`` is not a directory itself. One that cannot be read is the environment's
    fault."""
    try:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            return []
        with os.scandir(path) as entries:
            return sorted(
                (entry.name, entry.is_symlink())
                for entry in entries
                if entry.is_symlink() or entry.is_dir(follow_symlinks=False)
            )
    except OSError as error:
        if error.errno in _ABSENT:
            return []
        raise EnvironmentProblemError(f"cannot read {path}: {error.strerror}") from error


class RepositoryEntries:
    """The entries of the repository at ``root``. The tool's own hidden names, what a run cut
    short left, are no entry; read ``strict``, as a run that writes in it reads it, each is an
    entry that cannot be read, since what it holds is unknown."""

    def __init__(self, root: Path, *, strict: bool = False) -> None:
        self._root = root
        self._strict = strict
        self._entries: tuple[CatalogueEntry, ...] | None = None
        self._external_ids: Mapping[str, tuple[str, ...]] | None = None
        self._held: int | None = None
        self._held_identity: tuple[int, int] | None = None

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

    @property
    def root(self) -> Path:
        """Where the repository is, as given."""
        return self._root

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

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the repository for this run alone while the block runs, so that no other intake
        run checks the catalogue or writes in it meanwhile; one already holding it is the
        environment's matter. While held, entries are written from the repository held, never
        from its path again. The lock goes with the run, however it ends."""
        try:
            descriptor = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY)
        except OSError as error:
            raise EnvironmentProblemError(f"cannot read {self._root}: {error.strerror}") from error
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise EnvironmentProblemError(
                    f"cannot hold {self._root}: another run is writing in it"
                ) from error
            except OSError as error:
                raise EnvironmentProblemError(
                    f"cannot hold {self._root}: {error.strerror}"
                ) from error
            self._held, self._held_identity = descriptor, identity(descriptor, str(self._root))
            try:
                yield
            finally:
                self._held = self._held_identity = None
        finally:
            os.close(descriptor)  # which releases the lock

    def check_held(self) -> None:
        """Make sure the root's path still names the repository held, if one is, as what is read
        by that path is checked against it."""
        if self._held_identity is None:
            return
        try:
            status = self._root.stat()
            found: tuple[int, int] | None = (status.st_dev, status.st_ino)
        except OSError:
            found = None
        if found != self._held_identity:
            raise EnvironmentProblemError(
                f"{self._root} no longer names the repository this run holds: nothing more "
                "is written"
            )

    def descriptor(self) -> int:
        """A descriptor of the repository: the one held, or the one its path names."""
        try:
            if self._held is not None:
                return os.dup(self._held)
            return os.open(self._root, os.O_RDONLY | os.O_DIRECTORY)
        except OSError as error:
            raise EnvironmentProblemError(f"cannot read {self._root}: {error.strerror}") from error

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
        """Built once a run from the entries, and shared: never changed by a reader."""
        if self._external_ids is None:
            found: dict[str, list[str]] = {}
            for entry in self.entries():
                if entry.external_id:
                    found.setdefault(entry.external_id, []).append(entry.path)
            self._external_ids = MappingProxyType(
                {external_id: tuple(found[external_id]) for external_id in sorted(found)}
            )
        return self._external_ids

    def _read_entries(self) -> tuple[CatalogueEntry, ...]:
        found: list[CatalogueEntry] = []
        base = self._root / "scenarios"
        if base.is_symlink():  # what it leads to is never read as the catalogue
            raise UnsafeInputError("IO-013", "a symbolic link, never followed", "scenarios")
        for domain, linked in _listing(base):
            if is_hidden_name(domain) and not self._strict:
                continue
            if linked or is_hidden_name(domain):  # never read: unknown, so taken
                found.append(CatalogueEntry(f"scenarios/{domain}", "", "", False))
                continue
            for slug, linked in _listing(base / domain):
                path = f"scenarios/{domain}/{slug}"
                if is_hidden_name(slug) and not self._strict:
                    continue
                if linked or is_hidden_name(slug):
                    found.append(CatalogueEntry(path, "", "", False))
                    continue
                metadata = base / domain / slug / "scenario.yaml"
                if not _exists(metadata):
                    continue  # not an entry, or one its own check reports as incomplete
                try:
                    document = read_yaml_file(metadata)
                except UnsafeInputError:  # its own check says why; what it declares is unknown
                    document = None
                if not isinstance(document, dict):
                    found.append(CatalogueEntry(path, "", "", False))
                    continue
                external_id, name = document.get("external_id"), document.get("name")
                if isinstance(external_id, str) or isinstance(name, str):
                    # Its name counts even when its identifier does not: no other may take it.
                    found.append(
                        CatalogueEntry(
                            path,
                            external_id if isinstance(external_id, str) else "",
                            name if isinstance(name, str) else "",
                        )
                    )
        return tuple(found)
