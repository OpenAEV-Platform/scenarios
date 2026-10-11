"""Adapter: the repository's entries, read by their path in the repository, never through a
symbolic link, parent directories included, and within the input limits."""

import errno
import os
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TypeVar

from scenario_tools.adapters.data_files import read_stored_scenario
from scenario_tools.adapters.safe_readers import read_text_file, read_yaml_file
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
            return sorted(entry.name for entry in entries if entry.is_dir(follow_symlinks=False))
    except OSError as error:
        if error.errno in _ABSENT:
            return []
        raise EnvironmentProblemError(f"cannot read {path}: {error.strerror}") from error


class RepositoryEntries:
    """The entries of the repository at ``root``."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._external_ids: Mapping[str, tuple[str, ...]] | None = None

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

    def external_ids(self) -> Mapping[str, tuple[str, ...]]:
        """Read once a run, however many entries are checked against them."""
        if self._external_ids is None:
            self._external_ids = self._read_external_ids()
        return self._external_ids

    def _read_external_ids(self) -> Mapping[str, tuple[str, ...]]:
        found: dict[str, list[str]] = {}
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
                external_id = document.get("external_id") if isinstance(document, dict) else None
                if isinstance(external_id, str):
                    found.setdefault(external_id, []).append(f"scenarios/{domain}/{slug}")
        return {external_id: tuple(sorted(found[external_id])) for external_id in sorted(found)}
