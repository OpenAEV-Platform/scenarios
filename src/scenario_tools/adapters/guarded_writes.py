"""The file operations the entry writer is made of: a file or a directory created, compared or
replaced in an open directory, never through a link and without waiting on a pipe; what this run
made and cannot keep is taken back, never what another put there."""

import errno
import os
import posixpath
import stat
from pathlib import Path

from scenario_tools.adapters.places import (
    Identity,
    PlaceTakenError,
    create_in,
    hidden_name,
    identity,
    made_directory,
    make_directory,
    not_taken_back,
    place_back,
    removing_file,
    take_back,
    untold,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

# Opened never through a link, and without waiting: a pipe put there is never waited on.
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _compared(directory: int, name: str, expected: bytes) -> tuple[os.stat_result, bool]:
    """The status of ``name`` in ``directory``, and whether it is a regular file holding
    ``expected``: opened never through a link and without waiting, nothing read when it is not
    a regular file, never more than what is expected and one byte; ``OSError`` as the system
    raises it. What a file found that is not the one expected means is the caller's to say."""
    descriptor = os.open(name, _READ, dir_fd=directory)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            return status, False
        with os.fdopen(descriptor, "rb", closefd=False) as file:
            return status, file.read(len(expected) + 1) == expected
    finally:
        os.close(descriptor)


# What an open says when what is there is gone, a link, or not a regular file.
_NOT_THE_FILE = (errno.ENOENT, errno.ELOOP, errno.ENXIO)


def _same_bytes(directory: int, name: str, where: str, expected: bytes) -> bool:
    """Whether ``name`` in ``directory`` still holds ``expected``, a regular file read never
    through a link and never beyond what is expected; ``where`` names it in what is reported."""
    try:
        status, same = _compared(directory, name, expected)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENXIO):
            raise UnsafeInputError(
                "IO-013", "a symbolic link or not a regular file", where
            ) from error
        raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
    if not stat.S_ISREG(status.st_mode):
        raise UnsafeInputError("IO-013", "not a regular file", where)
    return same


def as_written(directory: int, name: str, mine: Identity, data: bytes) -> bool:
    """Whether ``name`` in ``directory`` is still the file written, ``mine`` by its identity,
    holding ``data``: one gone, changed, a link, not a regular file, or that cannot be read is
    not."""
    try:
        status, same = _compared(directory, name, data)
    except OSError:
        return False
    return same and (status.st_dev, status.st_ino) == mine


def take_back_created(
    directory: int, where: str, mine: Identity, data: bytes, failure: BaseException
) -> list[str]:
    """Take back the file this run created at ``where`` in an entry that was there: set aside
    at once, then removed only while it is the file written, ``mine`` holding ``data``; never
    another's put at its name meanwhile. What is not taken back is said."""
    name = posixpath.basename(where)
    try:
        outcome = take_back(
            directory,
            name,
            mine,
            removing_file(directory),
            ours=lambda aside: as_written(directory, aside, mine, data),
            where=where,
            failure=failure,
        )
    except EnvironmentProblemError as error:
        return [str(error)]
    said = not_taken_back(outcome, where)
    return [] if said is None else [said]


def holding(directory: int, name: str, where: str, expected: bytes) -> Identity:
    """The identity of ``name`` in ``directory``, once it is known to hold ``expected``, a
    regular file read never through a link and without waiting."""
    changed = f"cannot write {where}: it changed since it was read; nothing is written"
    try:
        status, same = _compared(directory, name, expected)
    except OSError as error:
        if error.errno in _NOT_THE_FILE:
            raise EnvironmentProblemError(changed) from error
        raise EnvironmentProblemError(f"cannot read {where}: {error.strerror}") from error
    if not same:
        raise EnvironmentProblemError(changed)
    return status.st_dev, status.st_ino


def new_directory(parent: int, name: str, where: str, doing: str) -> tuple[int, Identity]:
    """The directory ``name`` made in ``parent`` where nothing is, opened, with its identity;
    ``doing`` (make, write) says what fails. Anything there already raises ``FileExistsError``,
    as the system does. One another removed or replaced once made is said; one whose identity
    cannot be read, or that a stop leaves before it is known to be the run's, is left, and said.
    The caller sets its mode, then closes it."""
    try:
        make_directory(parent, name)
    except FileExistsError:
        raise
    except OSError as error:
        raise EnvironmentProblemError(f"cannot {doing} {where}: {error.strerror}") from error
    except BaseException as failure:  # a stop as it was made: what is there, if anything, is said
        if _present(parent, name):
            raise untold(f"cannot {doing} {where}: interrupted", where) from failure
        raise
    try:
        child = made_directory(parent, name, where)  # what is there is not known ours
    except FileNotFoundError as error:
        raise EnvironmentProblemError(
            f"cannot {doing} {where}: the run made it, and another removed it meanwhile"
        ) from error
    except UnsafeInputError as error:  # a link or a file put at its place
        raise EnvironmentProblemError(
            f"cannot {doing} {where}: the run made it, and another replaced it meanwhile"
        ) from error
    except EnvironmentProblemError as error:
        raise untold(str(error), where) from error
    except BaseException as failure:  # a stop too: nothing tells it from another's yet
        raise untold(f"cannot {doing} {where}: interrupted", where) from failure
    try:
        return child, identity(child, where)
    except EnvironmentProblemError as error:
        os.close(child)
        raise untold(str(error), where) from error
    except BaseException as failure:  # a stop too: it is not yet known to be the run's
        os.close(child)
        raise untold(f"cannot {doing} {where}: interrupted", where) from failure


def _present(parent: int, name: str) -> bool:
    """Whether anything may be at ``name`` in ``parent``, a link included: only a name known
    to be missing is not."""
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        return True  # it cannot be seen, so it may be there
    return True


def readable_by_all(directory: int) -> None:
    """Set the directory made to 0755, as one of the repository: read by all, whatever the
    umask. ``OSError`` as the system raises it."""
    os.fchmod(directory, 0o755)  # nosec B103


_HOLDS = "it holds what was not taken back"


def remove_made_directory(
    parent: int, name: str, mine: Identity, where: str
) -> tuple[str | None, bool]:
    """Remove the directory ``name`` in ``parent`` if it is the one the run made, ``mine`` by
    its identity, and empty: it is set aside at once, so never another's put in its place, and
    put back when it is not. What cannot be done is given, to be said, with whether it stays as
    it holds anything, which the directories above it then hold too."""
    holds = False

    def remove(aside: str) -> None:
        nonlocal holds
        try:
            os.rmdir(aside, dir_fd=parent)
        except OSError as error:
            if error.errno in (errno.ENOTEMPTY, errno.EEXIST):
                holds = True
                raise EnvironmentProblemError(_HOLDS) from error
            raise

    try:
        outcome = take_back(
            parent, name, mine, remove, where=where, failure=None, remedy="it stays"
        )
    except EnvironmentProblemError as error:
        return str(error), holds
    return not_taken_back(outcome, where), False


def said_with(failure: BaseException, left: list[str]) -> None:
    """Raise what says ``failure``, which led to the take-back, then ``left``, what could not
    be taken back; nothing when all was. The failure stays the cause, or its own cause when the
    run said it already."""
    if not left:
        return
    if isinstance(failure, (EnvironmentProblemError, UnsafeInputError)):
        first = str(failure)
    elif isinstance(failure, KeyboardInterrupt):
        first = "interrupted"
    else:  # a defect: named, as it is no longer what ends the run
        first = f"{type(failure).__name__}: {failure}"
    cause = failure.__cause__ if isinstance(failure, EnvironmentProblemError) else None
    raise EnvironmentProblemError(f"{first}; {'; '.join(left)}") from (cause or failure)


def replace_checked(
    directory: int, path: Path, where: str, before: bytes, data: bytes
) -> tuple[Identity, str]:
    """Replace ``path``'s name in ``directory`` with ``data``, only while it holds ``before``:
    the file is set aside at once and checked there, then the new one is created where nothing
    is, so that what another puts there meanwhile is never overwritten. The previous bytes are
    the caller's, and the checkout's commit holds them too. The identity of the file written is
    given, with what is left of the previous one if it cannot be removed, which the caller says
    once it knows what it wrote; ``where`` names it in what is reported."""
    aside = hidden_name()
    left = posixpath.join(posixpath.dirname(where), aside)
    changed = f"cannot write {where}: it changed since it was read; nothing is written"
    try:
        os.rename(path.name, aside, src_dir_fd=directory, dst_dir_fd=directory)
    except FileNotFoundError:
        raise EnvironmentProblemError(changed) from None
    except OSError as error:
        raise EnvironmentProblemError(f"cannot write {where}: {error.strerror}") from error

    def put_back(why: str) -> tuple[EnvironmentProblemError, bool]:
        """Put the previous version back, never over a file now there: the error that says
        ``why`` and what is left, and whether anything is."""
        try:
            gone = place_back(directory, aside, path.name)
        except PlaceTakenError:
            said = f"the file now at {where} stays, and the previous version is kept as {left}"
            return EnvironmentProblemError(f"{why}; {said}"), True
        except OSError as error:
            said = f"the previous version cannot be put back ({error.strerror}): kept as {left}"
            return EnvironmentProblemError(f"{why}; {said}"), True
        if not gone:
            said = f"it is put back, but a second name of it remains as {left}: remove that name"
            return EnvironmentProblemError(f"{why}; {said}"), True
        return EnvironmentProblemError(why), False

    try:
        same = _same_bytes(directory, aside, where, before)
    except (EnvironmentProblemError, UnsafeInputError) as error:
        said, left_any = put_back(str(error))
        if left_any:
            raise said from error
        raise
    if not same:
        raise put_back(changed)[0]
    try:
        mine = create_in(directory, path, data)
    except PlaceTakenError as error:  # another's file stays; the previous is committed
        taken = f"cannot write {where}: another put a file there meanwhile, which stays"
        try:
            os.unlink(aside, dir_fd=directory)
        except OSError as failure:
            taken += f"; its previous version is left as {left}: {failure.strerror}"
        raise EnvironmentProblemError(taken) from error
    except EnvironmentProblemError as error:
        raise put_back(str(error))[0] from error
    except BaseException as error:  # an interruption: as it was, or what is left is said
        said, left_any = put_back("interrupted")
        if left_any:
            raise said from error
        raise
    try:
        os.unlink(aside, dir_fd=directory)
    except OSError as error:
        return (
            mine,
            f"{where} is written, but its previous version is left as {left}: {error.strerror}",
        )
    return mine, ""
