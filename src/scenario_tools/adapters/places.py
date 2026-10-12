"""Adapter: places in a directory held open by its descriptor, never looked up again by a path.

A directory is opened never through a link nor a file. A file is created only where nothing is.
What a run made is taken back by setting aside at once what is at its place, under a hidden name
of the tool's own, then undoing it only if it is what the run made, and putting back anything
else: nothing another put there is ever removed. What cannot be done is said, with the failure
that led to it, and with where what is left is.

The words: a run *takes back* what it wrote (``take_back``), and so *gives back* the plan's place
it reserved and *puts back* the previous bytes of a file it replaced; what *another* put or
changed meanwhile is never taken back."""

import errno
import os
import posixpath
import re
import secrets
from collections.abc import Callable
from pathlib import Path

from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

_HIDDEN = re.compile(r"\.scenario-tools-[0-9a-f]{16}")


class PlaceTakenError(EnvironmentProblemError):
    """Something is already where a file was to be created or put back."""


REMOVED = "removed"
ABSENT = "absent"
FOREIGN = "foreign"


def hidden_name() -> str:
    """A name of the tool's own, hidden and short whatever it stands for."""
    return f".scenario-tools-{secrets.token_hex(8)}"


def is_hidden_name(name: str) -> bool:
    """Whether ``name`` is one ``hidden_name`` gives, which no entry or file of the repository
    ever has."""
    return _HIDDEN.fullmatch(name) is not None


def described(failure: BaseException | None) -> str:
    """The failure that led to a take-back, as a reader sees it after what is said."""
    if failure is None:
        return ""
    if isinstance(failure, KeyboardInterrupt):
        return " (after an interruption)"
    return f" (after: {str(failure) or type(failure).__name__})"


def identity(descriptor: int, where: str) -> tuple[int, int]:
    """Which file or directory ``descriptor`` is: one held open is never another's."""
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
    return status.st_dev, status.st_ino


def open_directory(directory: int, name: str, where: str) -> int:
    """A descriptor of the directory ``name`` in ``directory``, never through a link nor a file;
    a missing one raises ``FileNotFoundError``. ``where`` names it in what is reported."""
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


def made_directory(directory: int, name: str, where: str) -> int:
    """A descriptor of the directory ``name`` the run has just made in ``directory``. It is
    opened by its name, which another could take meanwhile, so it must be empty, as one just
    made is: one that is not was put at its place, and is never written in."""
    child = open_directory(directory, name, where)
    try:
        with os.scandir(child) as names:  # by its descriptor, never by its name again
            taken = next(names, None) is not None
        if taken:
            raise EnvironmentProblemError(
                f"cannot make {where}: another directory was put at its place meanwhile"
            )
    except OSError as error:
        os.close(child)
        raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
    except BaseException:
        os.close(child)
        raise
    return child


def make_directory(directory: int, name: str) -> None:
    """Make the directory ``name`` in ``directory``, only where nothing is, open to its owner
    alone whatever the umask, so that the run can open it at once: its mode is set once it is
    known to be the run's. The umask is the process's: the run is single-threaded, and writes
    while its requests to stop are held, so that none falls between setting and restoring it."""
    umask = os.umask(0o077)
    try:
        os.mkdir(name, 0o700, dir_fd=directory)
    finally:
        os.umask(umask)


def untold(reason: str, where: str) -> EnvironmentProblemError:
    """What says ``reason``, and that what the run made at ``where`` is left: nothing tells it
    from another's any more, so it is never removed."""
    return EnvironmentProblemError(
        f"{reason}; what was made at {where} cannot be told from another's: remove it by hand if "
        "it is this run's"
    )


def write_all(descriptor: int, data: bytes) -> None:
    """Write all of ``data`` to ``descriptor``, however many writes it takes."""
    view = memoryview(data)
    while view:
        view = view[os.write(descriptor, view) :]


def create_in(directory: int, path: Path, data: bytes) -> tuple[int, int]:
    """Create ``path``'s name in ``directory`` with ``data``, only where nothing is, a link
    included, with mode 0644 whatever the umask; a file that cannot be written whole is taken
    back, never another put at its name, and one whose identity cannot be read is left, and
    said. The identity of the file written is given; ``path``
    names it in what is reported."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
    except FileExistsError as error:
        raise PlaceTakenError(f"cannot write {path}: it already exists") from error
    except OSError as error:
        raise EnvironmentProblemError(f"cannot write {path}: {error.strerror}") from error
    made: tuple[int, int] | None = None
    try:
        try:
            status = os.fstat(descriptor)
            made = (status.st_dev, status.st_ino)
            write_all(descriptor, data)
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException as failure:  # an interruption too: the file goes, if it is known
        if made is None:  # nothing tells this run's file from another's: never removed
            why = failure.strerror if isinstance(failure, OSError) else "interrupted"
            raise untold(f"cannot write {path}: {why}", str(path)) from failure
        remove = removing_file(directory)
        take_back(directory, path.name, made, remove, where=str(path), failure=failure)
        if isinstance(failure, OSError):
            raise EnvironmentProblemError(f"cannot write {path}: {failure.strerror}") from failure
        raise
    return made


# What a link cannot be made for: a directory, or a file system without hard links.
_NO_LINK = (errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP, errno.EMLINK, errno.EXDEV)


def place_back(directory: int, aside: str, name: str) -> bool:
    """Put what was set aside as ``aside`` back at ``name`` in ``directory``, only where nothing
    is: a file by a new link to it, which fails if another is there; a directory, or a file
    where links cannot be made, by its name, which leaves a tiny window. Says whether ``aside``
    is gone: once a file is back, its hidden name may stay as a second name of it. Raises
    ``PlaceTakenError`` when another is there; ``aside`` then stays as it is."""
    try:
        os.link(aside, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    except FileExistsError as error:
        raise PlaceTakenError(f"{name}: another is there") from error
    except OSError as error:
        if error.errno not in _NO_LINK:
            raise
        os.rename(aside, name, src_dir_fd=directory, dst_dir_fd=directory)
        return True
    try:
        os.unlink(aside, dir_fd=directory)
    except OSError:
        return False  # back at its place all the same
    return True


def removing_file(directory: int) -> Callable[[str], None]:
    """What removes a file set aside in ``directory``, for ``take_back``."""

    def remove(aside: str) -> None:
        os.unlink(aside, dir_fd=directory)

    return remove


def take_back(
    directory: int,
    name: str,
    made: tuple[int, int],
    undo: Callable[[str], None],
    *,
    where: str,
    failure: BaseException | None,
    remedy: str = "remove it by hand",
    ours: Callable[[str], bool] | None = None,
) -> str:
    """Take back what the run made at ``name`` in ``directory``, ``made`` being its identity:
    what is there is set aside at once under a hidden name, then given to ``undo`` if it is
    what the run made, by its identity and, when ``ours`` is given, by what ``ours`` says of it,
    or put back if it is not. Says whether it was ``REMOVED``, ``ABSENT`` or ``FOREIGN``. What
    cannot be done is said, ``where`` naming the place, ``remedy`` what to do about it, and
    ``failure`` the failure that led to it, which stays as the cause."""
    after = described(failure)
    aside = hidden_name()
    try:
        os.rename(name, aside, src_dir_fd=directory, dst_dir_fd=directory)
    except FileNotFoundError:
        return ABSENT
    except OSError as error:
        raise EnvironmentProblemError(
            f"cannot take back {where}: {error.strerror}; {remedy}{after}"
        ) from failure
    left = posixpath.join(posixpath.dirname(where), aside)
    try:
        status = os.stat(aside, dir_fd=directory, follow_symlinks=False)
        mine = (status.st_dev, status.st_ino) == made and (ours is None or ours(aside))
        if mine:
            undo(aside)
            return REMOVED
    except (OSError, EnvironmentProblemError, UnsafeInputError) as error:
        reason = error.strerror if isinstance(error, OSError) else str(error)
        try:
            gone = place_back(directory, aside, name)
        except (OSError, PlaceTakenError):
            raise EnvironmentProblemError(
                f"cannot take back {where}: {reason}; it is left as {left}: {remedy}{after}"
            ) from failure
        second = "" if gone else f"; a second name of it remains as {left}: remove that name"
        raise EnvironmentProblemError(
            f"cannot take back {where}: {reason}; {remedy}{second}{after}"
        ) from failure
    try:
        gone = place_back(directory, aside, name)
    except PlaceTakenError:
        raise EnvironmentProblemError(
            f"cannot put back what was put at {where} meanwhile, as yet another is there: it is "
            f"kept as {left}{after}"
        ) from failure
    except OSError as error:
        raise EnvironmentProblemError(
            f"cannot put back what was put at {where} meanwhile: {error.strerror}; it is kept "
            f"as {left}{after}"
        ) from failure
    if not gone:
        raise EnvironmentProblemError(
            f"what was put at {where} meanwhile is put back, but a second name of it remains as "
            f"{left}: remove that name by hand{after}"
        ) from failure
    return FOREIGN
