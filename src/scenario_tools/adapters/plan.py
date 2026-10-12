"""Adapter: the plan's place, reserved as an empty file held open, the plan written in it and
published only while the place is still the one reserved; a place a run does not publish is
given back, never another file."""

import contextlib
import errno
import os
from collections.abc import Iterator
from contextlib import AbstractContextManager
from pathlib import Path

from scenario_tools.adapters.places import (
    identity,
    removing_file,
    take_back,
    untold,
    write_all,
)
from scenario_tools.ports.errors import EnvironmentProblemError


class Reservation:
    """An output's place, reserved by ``reserve_plan``: the output is written in the empty
    file the reservation made, through its descriptor, so never in another file, and the place
    is given back through the directory it was reserved in, never looked up again by its path."""

    def __init__(self, path: Path, directory: int, file: int, identity: tuple[int, int]) -> None:
        self._path = path
        self._directory = directory
        self._file = file
        self._identity = identity
        self._published = False

    def _ours(self, name: str) -> bool:
        """Whether ``name`` in the directory is the file the reservation made, which cannot be
        another while it is held open."""
        status = os.stat(name, dir_fd=self._directory, follow_symlinks=False)
        return (status.st_dev, status.st_ino) == self._identity

    def _still_its_directory(self) -> bool:
        """Whether the path of the place's directory still names the directory reserved in."""
        try:
            status = self._path.parent.stat()
        except OSError:
            return False
        return (status.st_dev, status.st_ino) == identity(self._directory, str(self._path.parent))

    def publish(self, data: bytes) -> None:
        """Write ``data`` in the reserved file; published only if the place still holds it."""
        try:
            write_all(self._file, data)
            os.fsync(self._file)
            # The plan is at its path only if both its directory and its name are still the
            # ones reserved: another put in their place meanwhile would not show it.
            ours = self._ours(self._path.name) and self._still_its_directory()
        except FileNotFoundError:
            ours = False
        except OSError as error:
            raise EnvironmentProblemError(f"cannot write {self._path}: {error.strerror}") from error
        if not ours:
            raise EnvironmentProblemError(
                f"cannot write {self._path}: the place reserved for it was taken meanwhile"
            )
        self._published = True

    def give_back(self, failure: BaseException | None) -> None:
        """Give the place back unless the plan was published: the reserved file is taken back,
        never another put there meanwhile; what cannot be is said, with ``failure``."""
        if self._published:
            return

        take_back(
            self._directory,
            self._path.name,
            self._identity,
            removing_file(self._directory),
            where=str(self._path),
            failure=failure,
        )


@contextlib.contextmanager
def reserve_plan(path: Path) -> Iterator[Reservation]:
    """Reserve ``path`` for the plan the block publishes: make it as an empty file, never over
    anything there nor through a link at its place, the file or its directory, so that no other
    run can take it meanwhile and a directory that cannot be written in is known before
    anything else is written. The directories above are the path the caller was given, links
    included. A place that cannot be used, a link included, is the environment's matter. Once
    published, the plan stays, however the block ends; a block that ends before gives the place
    back."""
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise _unusable(path.parent, error) from error
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        try:
            descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
        except FileExistsError as error:
            raise EnvironmentProblemError(f"cannot write {path}: it already exists") from error
        except OSError as error:
            raise _unusable(path, error) from error
        # Held open until the block ends, so that the file's identity is never reused.
        try:
            reservation = Reservation(
                path, directory, descriptor, _reserved(path, directory, descriptor)
            )
            try:
                yield reservation
            except BaseException as failure:
                reservation.give_back(failure)
                raise
            reservation.give_back(None)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


class PlanFile:
    """The plan's place at ``path``, reserved as ``reserve_plan`` reserves it."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def reserving(self) -> AbstractContextManager[Reservation]:
        return reserve_plan(self._path)


def _unusable(path: Path, error: OSError) -> EnvironmentProblemError:
    """A place for an output that cannot be used: a link or not a directory, or what else."""
    if error.errno in (errno.ELOOP, errno.ENOTDIR):
        return EnvironmentProblemError(
            f"cannot write {path}: a symbolic link or not a directory, never followed"
        )
    return EnvironmentProblemError(f"cannot write {path}: {error.strerror}")


def _reserved(path: Path, directory: int, descriptor: int) -> tuple[int, int]:
    """The identity of the empty file just made at ``path``, set to 0644 whatever the umask;
    one that cannot be is taken back. One whose identity cannot be read cannot be told from
    another's, and is never removed: it is said."""
    try:
        made = identity(descriptor, str(path))
    except EnvironmentProblemError as error:
        raise untold(str(error), str(path)) from error
    try:
        os.fchmod(descriptor, 0o644)
    except OSError as error:
        failure = EnvironmentProblemError(f"cannot write {path}: {error.strerror}")

        take_back(
            directory, path.name, made, removing_file(directory), where=str(path), failure=failure
        )
        raise failure from error
    return made
