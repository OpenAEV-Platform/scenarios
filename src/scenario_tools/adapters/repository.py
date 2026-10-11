"""Adapter: the repository's entries, read by their path in the repository, never through a
symbolic link, parent directories included, and within the input limits; written one directory
at a time through descriptors, so that nothing swapped meanwhile leads a write elsewhere."""

import contextlib
import errno
import fcntl
import os
import secrets
import shutil
import stat
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import TypeVar

from scenario_tools.adapters.data_files import read_stored_scenario, write_in
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


def _child(directory: int, name: str, where: str) -> int:
    """A descriptor of the directory ``name`` in ``directory``, never through a link nor a
    file; a missing one raises ``FileNotFoundError``."""
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        raise
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise UnsafeInputError(
                "IO-013", "not a directory: a link or a file, never followed", where
            ) from error
        raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error


@contextlib.contextmanager
def _replaced(directory: int, path: Path, files: Mapping[str, bytes]) -> Iterator[None]:
    """Replace ``files`` in ``directory``, the entry at ``path``, keeping each previous file
    aside under a hidden name until the block ends, and putting it back if it does not."""
    kept: dict[str, str] = {}
    try:
        for name, data in files.items():
            aside = f".{name}.{secrets.token_hex(8)}.previous"
            try:
                link = {"src_dir_fd": directory, "dst_dir_fd": directory}
                os.link(name, aside, **link, follow_symlinks=False)  # a link is kept as is
            except OSError as error:
                raise EnvironmentProblemError(
                    f"cannot write {path / name}: {error.strerror}"
                ) from error
            kept[name] = aside
            write_in(directory, path / name, data)
        yield
    except BaseException as failure:
        lost: list[str] = []
        for name, aside in kept.items():
            try:
                os.rename(aside, name, src_dir_fd=directory, dst_dir_fd=directory)
            except OSError:
                lost.append(f"{path / name} (the previous one is kept as {aside})")
                continue
            with contextlib.suppress(OSError):  # left by a rename over the same file
                os.unlink(aside, dir_fd=directory)
        if lost:
            raise EnvironmentProblemError(f"cannot put back {'; '.join(lost)}") from failure
        raise
    for aside in kept.values():
        with contextlib.suppress(OSError):
            os.unlink(aside, dir_fd=directory)


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

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the repository for this run alone while the block runs, so that no other run
        checks the catalogue or writes in it meanwhile; one already holding it is the
        environment's matter. The lock goes with the run, however it ends."""
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
            yield
        finally:
            os.close(descriptor)  # which releases the lock

    def _opened(self, relative: str, *, make: bool) -> int:
        """A descriptor of the directory at ``relative``, reached from the root one directory
        at a time, each opened from the one above and never through a link nor a file, so that
        nothing swapped meanwhile can lead the run elsewhere. The missing ones are made when
        ``make``. The caller closes it."""
        try:
            descriptor = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY)
        except OSError as error:
            raise EnvironmentProblemError(f"cannot read {self._root}: {error.strerror}") from error
        parts = relative.split("/")
        try:
            for index, part in enumerate(parts):
                where = "/".join(parts[: index + 1])
                try:
                    child = _child(descriptor, part, where)
                except FileNotFoundError:
                    if not make:
                        raise EnvironmentProblemError(
                            f"cannot read {where}: it is missing"
                        ) from None
                    try:
                        os.mkdir(part, 0o755, dir_fd=descriptor)
                    except FileExistsError:
                        pass  # made a moment ago: opened as any other, never through a link
                    except OSError as error:
                        raise EnvironmentProblemError(
                            f"cannot make {where}: {error.strerror}"
                        ) from error
                    child = _child(descriptor, part, where)
                os.close(descriptor)
                descriptor = child
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @contextlib.contextmanager
    def writing(self, entry: str, files: Mapping[str, bytes], *, new: bool) -> Iterator[None]:
        """Write ``files``, by name, in the entry at ``entry``, for as long as the block runs:
        if it does not end, what was written is undone. A new entry's place is reserved at
        once, never over anything there, and the entry is removed; an existing entry has the
        files given replaced, each at once, and put back as they were. Nothing to write writes
        nothing."""
        if not files:
            yield
            return
        parent_path, slug = entry.rsplit("/", 1)
        # A new entry is made in its parent; an existing one is written in as it is.
        opened = self._opened(parent_path if new else entry, make=new)
        try:
            if new:
                with self._new_entry(opened, slug, entry, files):
                    yield
            else:
                with _replaced(opened, self._root / entry, files):
                    yield
        finally:
            os.close(opened)

    @contextlib.contextmanager
    def _new_entry(
        self, parent: int, slug: str, entry: str, files: Mapping[str, bytes]
    ) -> Iterator[None]:
        try:
            os.mkdir(slug, 0o755, dir_fd=parent)  # fails if anything is there, even just made
        except FileExistsError as error:
            raise EnvironmentProblemError(f"cannot write {entry}: it already exists") from error
        except OSError as error:
            raise EnvironmentProblemError(f"cannot write {entry}: {error.strerror}") from error
        try:
            directory = _child(parent, slug, entry)
            try:
                # A directory of the repository, read by all, whatever the umask.
                os.fchmod(directory, 0o755)  # nosec B103
                for name, data in files.items():
                    write_in(directory, self._root / entry / name, data, create=True)
                yield
            finally:
                os.close(directory)
        except BaseException as failure:
            try:
                shutil.rmtree(slug, dir_fd=parent)
            except OSError as error:
                raise EnvironmentProblemError(
                    f"cannot remove {entry}, which this run left incomplete: {error.strerror}; "
                    "remove it by hand"
                ) from failure
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
