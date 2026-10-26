"""Adapter: an entry written in the repository, from the repository held if one is, one
directory at a time, never through a link; what a run cannot keep is taken back, never what
another put there."""

import contextlib
import errno
import os
import posixpath
from collections.abc import Iterator, Mapping
from pathlib import Path

from scenario_tools.adapters.guarded_writes import (
    as_written,
    holding,
    new_directory,
    readable_by_all,
    remove_made_directory,
    replace_checked,
    said_with,
    take_back_created,
)
from scenario_tools.adapters.places import (
    ABSENT,
    FOREIGN,
    Identity,
    create_in,
    described,
    identity,
    not_taken_back,
    open_directory,
    take_back,
)
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError


class _WrittenEntry:
    """What a run wrote, to check that what reads it by its path afterwards reads it: the
    repository held, the entry by its identity, and each file by its identity and bytes.
    Nothing written has only the repository to check."""

    def __init__(
        self,
        writer: "RepositoryWriter",
        entry: str,
        entry_identity: Identity | None = None,
        files: Mapping[str, tuple[Identity, bytes]] | None = None,
    ) -> None:
        self._writer = writer
        self._entry = entry
        self._entry_identity = entry_identity
        self._files = dict(files or {})

    def check(self) -> None:
        self._writer.source.check_held()
        if self._entry_identity is None:
            return
        said = f"{self._entry} no longer names the entry this run wrote: nothing more is written"
        try:
            descriptor = self._writer.opened(self._entry, make=False)
        except (EnvironmentProblemError, UnsafeInputError) as error:
            raise EnvironmentProblemError(said) from error
        try:
            if identity(descriptor, self._entry) != self._entry_identity:
                raise EnvironmentProblemError(said)
            for name, (mine, data) in self._files.items():
                if not as_written(descriptor, name, mine, data):
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

    def opened(
        self, relative: str, *, make: bool, made_dirs: list[tuple[str, Identity]] | None = None
    ) -> int:
        """A descriptor of the directory at ``relative``, reached from the repository one
        directory at a time, each opened from the one above and never through a link nor a
        file. When ``make``, the missing ones are made, empty once opened and set to 0755, and
        told to ``made_dirs``, from the highest; if the way cannot be made whole, those made go
        again. The caller closes the descriptor."""
        made_dirs = [] if made_dirs is None else made_dirs
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
                    child = self._make_or_open(descriptor, part, where, made_dirs)
                os.close(descriptor)
                descriptor = child
        except BaseException as failure:
            os.close(descriptor)
            said_with(failure, self._remove_made_directories(made_dirs))
            raise
        return descriptor

    @staticmethod
    def _make_or_open(
        directory: int, name: str, where: str, made_dirs: list[tuple[str, Identity]]
    ) -> int:
        """The directory ``name`` made in ``directory``, or opened as any other when another
        run made it a moment ago; ``made_dirs`` is told when it is this run's, with its
        identity."""
        try:
            child, mine = new_directory(directory, name, where, "make")
        except FileExistsError:
            try:
                return open_directory(directory, name, where)  # another's: opened as any other
            except FileNotFoundError as error:  # made by another, and gone again
                raise EnvironmentProblemError(
                    f"cannot make {where}: another made it and removed it meanwhile"
                ) from error
        try:
            made_dirs.append((where, mine))  # the run's: taken back with the others if need be
            readable_by_all(child)
        except OSError as error:
            os.close(child)
            raise EnvironmentProblemError(f"cannot make {where}: {error.strerror}") from error
        except BaseException:
            os.close(child)
            raise
        return child

    def _remove_made_directories(self, made_dirs: list[tuple[str, Identity]]) -> list[str]:
        """Remove the directories this run made, the lowest first, when they are empty and
        still the ones made: one that is not holds what is not this run's, or what could not be
        taken back, or is another's, and stays. What stays is given, to be said."""
        left: list[str] = []
        for where, mine in reversed(made_dirs):
            parent, name = posixpath.split(where)
            try:
                directory = self.opened(parent, make=False)
            except (EnvironmentProblemError, UnsafeInputError) as error:
                left.append(f"cannot take back {where}: {error}")
                continue
            try:
                said, holds = remove_made_directory(directory, name, mine, where)
            finally:
                os.close(directory)
            if holds and said is not None and (where, mine) != made_dirs[0]:
                left.append(f"{said}, as do the directories made above it")
                break  # each holds the one below it
            if said is not None:
                left.append(said)
        made_dirs.clear()
        return left

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
        in it, with the directories above it that are missing. With it, the entry is there: each
        file ``previous`` holds is replaced at once, once it is known to still hold those bytes,
        and each other file is created where nothing is. If the block does not end, what was
        written is taken back: a new entry's files, the entry and the directories made for it
        are removed; a replaced file is given its previous bytes back, a file created in an
        entry that was there is removed. Nothing
        another put meanwhile is ever removed, and what cannot be taken back is said. Nothing
        to write writes nothing. The block is given a check that what reads the entry by its
        path afterwards reads what was written."""
        if not files:
            with self._unchanged(entry, previous or {}) as unchanged:
                yield unchanged
        elif previous is None:
            with self._new_entry(entry, files) as written:
                yield written
        else:
            with self._replaced(entry, files, previous) as written:
                yield written

    @contextlib.contextmanager
    def _unchanged(self, entry: str, previous: Mapping[str, bytes]) -> Iterator[_WrittenEntry]:
        """Nothing written: the entry's files read are known to be still as read, and are
        checked again before the plan is published."""
        if not previous:
            yield _WrittenEntry(self, entry)
            return
        directory = self.opened(entry, make=False)
        try:
            kept: dict[str, tuple[Identity, bytes]] = {}
            for name, before in previous.items():
                kept[name] = (holding(directory, name, f"{entry}/{name}", before), before)
            yield _WrittenEntry(self, entry, identity(directory, entry), kept)
        finally:
            os.close(directory)

    @contextlib.contextmanager
    def _new_entry(self, entry: str, files: Mapping[str, bytes]) -> Iterator[_WrittenEntry]:
        parent_path, slug = entry.rsplit("/", 1)
        made_above: list[tuple[str, Identity]] = []
        parent = self.opened(parent_path, make=True, made_dirs=made_above)
        try:
            directory, entry_identity = self._make_entry(parent, slug, entry)
            try:
                created: dict[str, tuple[Identity, bytes]] = {}
                try:
                    for name, data in files.items():
                        created[name] = (
                            create_in(directory, self._root / entry / name, data),
                            data,
                        )
                    yield _WrittenEntry(self, entry, entry_identity, created)
                except BaseException as failure:
                    self._take_back_entry(parent, slug, entry, entry_identity, created, failure)
                    raise
            finally:
                os.close(directory)
        except BaseException as failure:
            os.close(parent)
            said_with(failure, self._remove_made_directories(made_above))
            raise
        os.close(parent)

    @staticmethod
    def _make_entry(parent: int, slug: str, entry: str) -> tuple[int, Identity]:
        """The new entry's directory, made where nothing is, opened, with its identity, set to
        0755; one that cannot be made whole, or that a stop ends, is not left, when it is empty and
        known to be the one made. One whose identity cannot be read is left, and said."""
        try:
            directory, entry_identity = new_directory(parent, slug, entry, "write")
        except FileExistsError as error:
            raise EnvironmentProblemError(f"cannot write {entry}: it already exists") from error
        try:
            readable_by_all(directory)
        except BaseException as failure:  # a stop too: the entry goes, as it is known
            os.close(directory)
            left, _ = remove_made_directory(parent, slug, entry_identity, entry)
            if isinstance(failure, OSError):
                more = "" if left is None else f"; {left}"
                raise EnvironmentProblemError(
                    f"cannot make {entry}: {failure.strerror}{more}"
                ) from failure
            if left is not None:
                raise EnvironmentProblemError(f"{left}{described(failure)}") from failure
            raise
        return directory, entry_identity

    @staticmethod
    def _take_back_entry(
        parent: int,
        slug: str,
        entry: str,
        entry_identity: Identity,
        created: Mapping[str, tuple[Identity, bytes]],
        failure: BaseException,
    ) -> None:
        """Remove the new entry: only the files this run created in it, then the directory, so
        that what another put in it meanwhile stays, and the entry with it."""

        def remove(aside: str) -> None:
            inside = open_directory(parent, aside, entry)
            try:
                for name, (mine, data) in created.items():
                    if as_written(inside, name, mine, data):  # what another changed stays
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
            entry_identity,
            remove,
            where=entry,
            failure=failure,
            remedy="remove by hand what this run wrote",
        )
        said = not_taken_back(outcome, entry)
        if said is not None:
            raise EnvironmentProblemError(f"{said}{described(failure)}") from failure

    @contextlib.contextmanager
    def _replaced(
        self, entry: str, files: Mapping[str, bytes], previous: Mapping[str, bytes]
    ) -> Iterator[_WrittenEntry]:
        directory = self.opened(entry, make=False)
        # Each file created is held open until the run ends, taken back or kept: no file
        # another puts at its name meanwhile can then have its identity.
        held: list[int] = []
        try:
            folder = self._root / entry
            written: dict[str, tuple[Identity, bytes]] = {}
            created: dict[str, tuple[Identity, bytes]] = {}
            try:
                for name, data in files.items():
                    where = f"{entry}/{name}"
                    if name not in previous:  # where nothing is, never over another's
                        made = create_in(directory, folder / name, data, keep=held)
                        created[name] = (made, data)
                        continue
                    mine, left = replace_checked(
                        directory, folder / name, where, previous[name], data
                    )
                    written[name] = (mine, data)
                    if left:  # what was written is known: it is taken back with the rest
                        raise EnvironmentProblemError(
                            f"{left}; the update is taken back: remove it by hand"
                        )
                yield _WrittenEntry(self, entry, identity(directory, entry), {**written, **created})
            except BaseException as failure:
                said = [
                    told
                    for name, (mine, data) in created.items()
                    for told in take_back_created(directory, f"{entry}/{name}", mine, data, failure)
                ]
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
            for descriptor in held:
                os.close(descriptor)
            os.close(directory)

    @staticmethod
    def _put_back(
        directory: int,
        path: Path,
        where: str,
        mine: Identity,
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
                ours=lambda aside: as_written(directory, aside, mine, data),
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
