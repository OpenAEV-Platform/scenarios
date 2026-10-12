"""Adapter: an entry written in the repository, from the repository held if one is, one
directory at a time, never through a link; what a run cannot keep is taken back, never what
another put there."""

import contextlib
import errno
import os
import posixpath
import stat
from collections.abc import Iterator, Mapping
from pathlib import Path

from scenario_tools.adapters.data_files import write_in
from scenario_tools.adapters.places import (
    ABSENT,
    FOREIGN,
    create_in,
    described,
    identity,
    made_directory,
    open_directory,
    take_back,
)
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

# Opened never through a link, and without waiting: a pipe put there is never waited on.
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _same_bytes(directory: int, name: str, where: str, expected: bytes) -> bool:
    """Whether ``name`` in ``directory`` still holds ``expected``, a regular file read never
    through a link and never beyond what is expected; ``where`` names it in what is reported."""
    try:
        descriptor = os.open(name, _READ, dir_fd=directory)
    except FileNotFoundError:
        return False
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENXIO):
            raise UnsafeInputError(
                "IO-013", "a symbolic link or not a regular file", where
            ) from error
        raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise UnsafeInputError("IO-013", "not a regular file", where)
        with os.fdopen(descriptor, "rb", closefd=False) as file:
            found = file.read(len(expected) + 1)
    except OSError as error:
        raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
    finally:
        os.close(descriptor)
    return found == expected


def _as_written(directory: int, name: str, mine: tuple[int, int], data: bytes) -> bool:
    """Whether ``name`` in ``directory`` is still the file written, ``mine`` by its identity,
    holding ``data``: one gone, changed, a link, not a regular file, or that cannot be read is
    not."""
    try:
        descriptor = os.open(name, _READ, dir_fd=directory)
    except OSError:
        return False
    try:
        status = os.fstat(descriptor)
        if (status.st_dev, status.st_ino) != mine or not stat.S_ISREG(status.st_mode):
            return False
        with os.fdopen(descriptor, "rb", closefd=False) as file:
            return file.read(len(data) + 1) == data
    except OSError:
        return False
    finally:
        os.close(descriptor)


class _WrittenEntry:
    """What a run wrote, to check that what reads it by its path afterwards reads it: the
    repository held, the entry by its identity, and each file by its identity and bytes.
    Nothing written has only the repository to check."""

    def __init__(
        self,
        writer: "RepositoryWriter",
        entry: str,
        made: tuple[int, int] | None = None,
        files: Mapping[str, tuple[tuple[int, int], bytes]] | None = None,
    ) -> None:
        self._writer = writer
        self._entry = entry
        self._made = made
        self._files = dict(files or {})

    def check(self) -> None:
        self._writer.source.check_held()
        if self._made is None:
            return
        said = f"{self._entry} no longer names the entry this run wrote: nothing more is written"
        try:
            descriptor = self._writer.opened(self._entry, make=False)
        except (EnvironmentProblemError, UnsafeInputError) as error:
            raise EnvironmentProblemError(said) from error
        try:
            if identity(descriptor, self._entry) != self._made:
                raise EnvironmentProblemError(said)
            for name, (mine, data) in self._files.items():
                if not _as_written(descriptor, name, mine, data):
                    raise EnvironmentProblemError(
                        f"{self._entry}/{name} changed since this run wrote it: nothing more is "
                        "written"
                    )
        finally:
            os.close(descriptor)


class RepositoryWriter:
    """Writes the entries of the repository ``source`` reads, from the repository it holds while
    it holds one, from its path otherwise."""

    def __init__(self, source: RepositoryEntries) -> None:
        self.source = source
        self._root = source.root

    def opened(self, relative: str, *, make: bool, made: list[str] | None = None) -> int:
        """A descriptor of the directory at ``relative``, reached from the repository one
        directory at a time, each opened from the one above and never through a link nor a
        file. When ``make``, the missing ones are made, empty once opened and set to 0755, and
        told to ``made``, from the highest; if the way cannot be made whole, those made go
        again. The caller closes the descriptor."""
        made = [] if made is None else made
        descriptor = self.source.descriptor()
        parts = relative.split("/") if relative else []
        try:
            for index, part in enumerate(parts):
                where = "/".join(parts[: index + 1])
                try:
                    child = open_directory(descriptor, part, where)
                except FileNotFoundError:
                    if not make:
                        raise EnvironmentProblemError(
                            f"cannot read {where}: it is missing"
                        ) from None
                    child = self._made(descriptor, part, where, made)
                os.close(descriptor)
                descriptor = child
        except BaseException:
            os.close(descriptor)
            self._remove_made(made)
            raise
        return descriptor

    @staticmethod
    def _made(directory: int, name: str, where: str, made: list[str]) -> int:
        """The directory ``name`` made in ``directory``, unless another run made it a moment
        ago; ``made`` is told when it is this run's."""
        try:
            os.mkdir(name, 0o755, dir_fd=directory)
        except FileExistsError:
            try:
                return open_directory(directory, name, where)  # another's: opened as any other
            except FileNotFoundError as error:  # made by another, and gone again
                raise EnvironmentProblemError(
                    f"cannot make {where}: another made it and removed it meanwhile"
                ) from error
        except OSError as error:
            raise EnvironmentProblemError(f"cannot make {where}: {error.strerror}") from error
        made.append(where)
        child = made_directory(directory, name, where)
        try:
            # A directory of the repository, read by all, whatever the umask.
            os.fchmod(child, 0o755)  # nosec B103
        except OSError as error:
            os.close(child)
            raise EnvironmentProblemError(f"cannot make {where}: {error.strerror}") from error
        return child

    def _remove_made(self, made: list[str]) -> None:
        """Remove the directories this run made, the lowest first, when they are empty: one
        that is not holds what is not this run's, or what could not be taken back, and stays."""
        for where in reversed(made):
            parent, name = posixpath.split(where)
            with contextlib.suppress(EnvironmentProblemError, UnsafeInputError, OSError):
                directory = self.opened(parent, make=False)
                try:
                    os.rmdir(name, dir_fd=directory)
                finally:
                    os.close(directory)
        made.clear()

    @contextlib.contextmanager
    def writing(
        self,
        entry: str,
        files: Mapping[str, bytes],
        *,
        previous: Mapping[str, bytes] | None,
    ) -> Iterator[_WrittenEntry]:
        """Write ``files``, by name, in the entry at ``entry``, for as long as the block runs.
        Without ``previous``, the entry is new: it is made where nothing is, its files created
        in it, with the directories above it that are missing. With it, each file is replaced
        at once, once it is known to still hold its ``previous`` bytes. If the block does not
        end, what was written is taken back: a new entry's files, the entry and the directories
        made for it are removed; a replaced file is given its previous bytes back. Nothing
        another put meanwhile is ever removed, and what cannot be taken back is said. Nothing
        to write writes nothing. The block is given a check that what reads the entry by its
        path afterwards reads what was written."""
        if not files:
            yield _WrittenEntry(self, entry)
        elif previous is None:
            with self._new_entry(entry, files) as written:
                yield written
        else:
            with self._replaced(entry, files, previous) as written:
                yield written

    @contextlib.contextmanager
    def _new_entry(self, entry: str, files: Mapping[str, bytes]) -> Iterator[_WrittenEntry]:
        parent_path, slug = entry.rsplit("/", 1)
        made_above: list[str] = []
        parent = self.opened(parent_path, make=True, made=made_above)
        try:
            directory, made = self._make_entry(parent, slug, entry)
            try:
                created: dict[str, tuple[tuple[int, int], bytes]] = {}
                try:
                    for name, data in files.items():
                        created[name] = (
                            create_in(directory, self._root / entry / name, data),
                            data,
                        )
                    yield _WrittenEntry(self, entry, made, created)
                except BaseException as failure:
                    self._take_back_entry(parent, slug, entry, made, created, failure)
                    raise
            finally:
                os.close(directory)
        except BaseException:
            os.close(parent)
            self._remove_made(made_above)
            raise
        os.close(parent)

    @staticmethod
    def _make_entry(parent: int, slug: str, entry: str) -> tuple[int, tuple[int, int]]:
        """The new entry's directory, made where nothing is, opened, with its identity, set to
        0755; one that cannot be made whole is not left, when it is empty."""
        try:
            os.mkdir(slug, 0o755, dir_fd=parent)  # fails if anything is there
        except FileExistsError as error:
            raise EnvironmentProblemError(f"cannot write {entry}: it already exists") from error
        except OSError as error:
            raise EnvironmentProblemError(f"cannot write {entry}: {error.strerror}") from error
        try:
            directory = made_directory(parent, slug, entry)
        except BaseException:
            with contextlib.suppress(OSError):
                os.rmdir(slug, dir_fd=parent)  # only ever an empty one
            raise
        try:
            made = identity(directory, entry)
            try:
                # A directory of the repository, read by all, whatever the umask.
                os.fchmod(directory, 0o755)  # nosec B103
            except OSError as error:
                raise EnvironmentProblemError(f"cannot make {entry}: {error.strerror}") from error
        except BaseException:
            os.close(directory)
            with contextlib.suppress(OSError):
                os.rmdir(slug, dir_fd=parent)
            raise
        return directory, made

    @staticmethod
    def _take_back_entry(
        parent: int,
        slug: str,
        entry: str,
        made: tuple[int, int],
        created: Mapping[str, tuple[tuple[int, int], bytes]],
        failure: BaseException,
    ) -> None:
        """Remove the new entry: only the files this run created in it, then the directory, so
        that what another put in it meanwhile stays, and the entry with it."""

        def remove(aside: str) -> None:
            inside = open_directory(parent, aside, entry)
            try:
                for name, (mine, data) in created.items():
                    if _as_written(inside, name, mine, data):  # what another changed stays
                        os.unlink(name, dir_fd=inside)
            finally:
                os.close(inside)
            try:
                os.rmdir(aside, dir_fd=parent)
            except OSError as error:
                if error.errno in (errno.ENOTEMPTY, errno.EEXIST):
                    raise EnvironmentProblemError(
                        "what another put or changed in it meanwhile stays, and the entry with it"
                    ) from error
                raise

        outcome = take_back(
            parent,
            slug,
            made,
            remove,
            where=entry,
            failure=failure,
            remedy="remove by hand what this run wrote",
        )
        if outcome == FOREIGN:
            raise EnvironmentProblemError(
                f"cannot take back {entry}: another was put at its place meanwhile, and stays; "
                f"this run's was moved, and is left where it went{described(failure)}"
            ) from failure
        if outcome == ABSENT:
            raise EnvironmentProblemError(
                f"cannot take back {entry}: it was moved meanwhile, and is left where it went"
                f"{described(failure)}"
            ) from failure

    @contextlib.contextmanager
    def _replaced(
        self, entry: str, files: Mapping[str, bytes], previous: Mapping[str, bytes]
    ) -> Iterator[_WrittenEntry]:
        if not files.keys() <= previous.keys():
            raise ValueError("each file an update replaces needs the bytes it was read with")
        directory = self.opened(entry, make=False)
        try:
            folder = self._root / entry
            for name in files:
                where = f"{entry}/{name}"
                if not _same_bytes(directory, name, where, previous[name]):
                    raise EnvironmentProblemError(
                        f"cannot write {where}: it changed since it was read; nothing is written"
                    )
            written: dict[str, tuple[tuple[int, int], bytes]] = {}
            try:
                for name, data in files.items():
                    written[name] = (write_in(directory, folder / name, data), data)
                yield _WrittenEntry(self, entry, identity(directory, entry), written)
            except BaseException as failure:
                said = []
                for name, (mine, data) in written.items():
                    said += self._put_back(
                        directory,
                        folder / name,
                        f"{entry}/{name}",
                        mine,
                        data,
                        previous[name],
                        failure,
                    )
                if said:
                    raise EnvironmentProblemError("; ".join(said) + described(failure)) from failure
                raise
        finally:
            os.close(directory)

    @staticmethod
    def _put_back(
        directory: int,
        path: Path,
        where: str,
        mine: tuple[int, int],
        data: bytes,
        before: bytes,
        failure: BaseException,
    ) -> list[str]:
        """Give the file this run replaced its previous bytes back, only while it still is the
        file written with ``data``, never one another changed; what cannot be is said."""
        left: list[str] = []

        def restore(aside: str) -> None:
            create_in(directory, path, before)  # where nothing is: never over another's
            try:
                os.unlink(aside, dir_fd=directory)
            except OSError:
                left.append(aside)  # given back all the same: what is left is only a copy

        try:
            outcome = take_back(
                directory,
                path.name,
                mine,
                restore,
                ours=lambda aside: _as_written(directory, aside, mine, data),
                where=where,
                failure=None,
                remedy="restore it by hand, from git",
            )
        except EnvironmentProblemError as error:
            return [str(error)]
        if outcome == ABSENT:
            return [f"cannot take back {where}: it is gone meanwhile; restore it by hand, from git"]
        if outcome == FOREIGN:
            return [f"cannot take back {where}: it changed meanwhile, and is left as it is"]
        if left:
            copy = posixpath.join(posixpath.dirname(where), left[0])
            return [
                f"{where} is given its previous bytes back, but this run's version is left as "
                f"{copy}: remove it by hand"
            ]
        return []
