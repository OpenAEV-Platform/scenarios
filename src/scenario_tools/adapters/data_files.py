"""Files around normalisation: policy data, exports, and the files a command writes.

Every read goes through the bounded readers. A command's output is written without ever
following a symbolic link, so that a link planted in an entry cannot redirect the write.
"""

import contextlib
import errno
import os
import re
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from scenario_tools.adapters.safe_readers import (
    JSON_LIMIT,
    parse_json,
    read_json_file,
    read_regular_file,
    read_yaml_file,
)
from scenario_tools.adapters.safe_zip import (
    ARCHIVE_LIMIT,
    CheckedArchive,
    archive_from_bytes,
    open_zip,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

_DATA_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


class YamlDataLoader:
    """Policy data read from ``<directory>/<name>.yaml``."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self, name: str) -> Any:
        if not _DATA_NAME.fullmatch(name):
            raise ValueError(f"data name {name!r} is not a plain name")
        return read_yaml_file(self.directory / f"{name}.yaml")


# The comments the platform's importer reads as an entry's type, whatever its name.
_SCENARIO_ENTRY = b"Scenario"
_DOCUMENT_ENTRY = b"Attachment"


DOCUMENTS_NOT_SUPPORTED = "documents are not supported yet"


class DocumentsNotSupportedError(UnsafeInputError):
    """An export that carries documents: its message is the tool's own text and a count."""


def _export_document(archive: CheckedArchive) -> Any:
    documents = [name for name in archive.names if archive.comment(name) == _DOCUMENT_ENTRY]
    if documents:
        raise DocumentsNotSupportedError(
            "IO-014",
            f"{DOCUMENTS_NOT_SUPPORTED}: the export carries {len(documents)} document"
            + ("s" if len(documents) > 1 else ""),
            archive.path,
        )
    entries = [name for name in archive.names if archive.comment(name) == _SCENARIO_ENTRY]
    if len(entries) != 1:
        raise UnsafeInputError(
            "IO-014",
            f"an export archive holds one scenario entry, not {len(entries)}",
            archive.path,
        )
    return parse_json(archive.read(entries[0]), path=archive.path)


def check_export_archive(data: bytes, path: str) -> None:
    """Refuse bytes that are not a safe export archive holding exactly one scenario entry (the
    entry whose comment is ``Scenario``, whatever its name) and no document; ``path`` names the
    archive in the refusal."""
    _export_document(archive_from_bytes(data, path=path))


def read_export_archive(path: Path) -> bytes:
    """The bytes of an export archive file that passes the same checks."""
    data = read_regular_file(path, ARCHIVE_LIMIT)
    check_export_archive(data, str(path))
    return data


# The password the importer opens attachments with, and contributors encrypt them with.
ATTACHMENTS_PASSWORD = b"infected"


def read_stored_scenario(path: Path) -> tuple[bytes, Any]:
    """The bytes of a stored ``scenario.json``, and the document they hold."""
    data = read_regular_file(path, JSON_LIMIT)
    return data, parse_json(data, path=str(path))


def read_attachments(path: Path) -> bytes | None:
    """The bytes of an entry's attachments archive, once every entry opens with the shared
    password, as the importer will open them; ``None`` when the entry has none."""
    if not path.exists() and not path.is_symlink():
        return None
    data = read_regular_file(path, ARCHIVE_LIMIT)
    archive = archive_from_bytes(data, path=str(path))
    for name in archive.names:
        archive.read(name, password=ATTACHMENTS_PASSWORD)
    return data


def read_export(path: Path) -> Any:
    """An exported scenario, from its archive or from its JSON file."""
    if path.suffix != ".zip":
        return read_json_file(path)
    return _export_document(open_zip(path))


def read_mapping(path: Path) -> dict[str, str]:
    """An explicit inject mapping: a list of ``{source_inject_id, stable_id}``, maybe empty."""
    refusal = UnsafeInputError(
        "VER-011",
        "the mapping must list each source inject once, as {source_inject_id, stable_id}",
        str(path),
    )
    document = read_yaml_file(path)
    if not isinstance(document, list):
        raise refusal
    mapping: dict[str, str] = {}
    for entry in document:
        source = entry.get("source_inject_id") if isinstance(entry, dict) else None
        stable = entry.get("stable_id") if isinstance(entry, dict) else None
        if not isinstance(source, str) or not isinstance(stable, str) or source in mapping:
            raise refusal
        mapping[source] = stable
    return mapping


def _not_followed(path: Path, error: OSError) -> Exception:
    """A link, or anything but a directory or a regular file, is refused input; any other
    failure is the environment's."""
    if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EISDIR, errno.ENXIO):
        return UnsafeInputError("IO-013", "a symbolic link or not a regular file", str(path))
    return EnvironmentProblemError(f"cannot write {path}: {error.strerror}")


class Reservation:
    """An output's place, reserved by ``reserve_output``: the output is written in the empty
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

    def publish(self, data: bytes) -> None:
        """Write ``data`` in the reserved file; published only if the place still holds it."""
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(self._file, view) :]
            os.fsync(self._file)
            ours = self._ours(self._path.name)
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
        """Remove the reservation unless it was published, never another file: what is at the
        place is set aside at once, then removed if it is the reserved file, or put back,
        over nothing, if it is not. What cannot be is said, with ``failure`` as its cause."""
        if self._published:
            return
        aside = f".{self._path.name}.{secrets.token_hex(8)}"
        try:
            try:
                os.rename(
                    self._path.name, aside, src_dir_fd=self._directory, dst_dir_fd=self._directory
                )
            except FileNotFoundError:
                return  # nothing is there to give back
            if self._ours(aside):
                os.unlink(aside, dir_fd=self._directory)
                return
            try:
                os.link(
                    aside,
                    self._path.name,
                    src_dir_fd=self._directory,
                    dst_dir_fd=self._directory,
                    follow_symlinks=False,
                )
            except FileExistsError:
                raise EnvironmentProblemError(
                    f"cannot put back the file put at {self._path} meanwhile, as yet another "
                    f"is there: it is kept as {self._path.parent / aside}"
                ) from failure
            os.unlink(aside, dir_fd=self._directory)
        except OSError as error:
            raise EnvironmentProblemError(
                f"cannot remove {self._path.parent / aside}, the place reserved for "
                f"{self._path}: {error.strerror}; remove it by hand"
            ) from failure


@contextlib.contextmanager
def reserve_output(path: Path) -> Iterator[Reservation]:
    """Reserve ``path`` for an output the block publishes: make it as an empty file, never over
    anything there nor through a link at its place, the file or its directory, so that no other
    run can take it meanwhile and a directory that cannot be written in is known before
    anything else is written. The directories above are the path the caller was given, links
    included, as ``write_output`` takes them. Once published, the output stays, however the
    block ends; a block that ends before gives the place back."""
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise _not_followed(path.parent, error) from error
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        try:
            descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
        except FileExistsError as error:
            raise EnvironmentProblemError(f"cannot write {path}: it already exists") from error
        except OSError as error:
            raise _not_followed(path, error) from error
        # Held open until the block ends, so that the file's identity is never reused.
        try:
            try:
                os.fchmod(descriptor, 0o644)
                status = os.fstat(descriptor)
            except OSError as error:  # the file is this run's own: nothing is left behind
                failure = EnvironmentProblemError(f"cannot write {path}: {error.strerror}")
                try:
                    os.unlink(path.name, dir_fd=directory)
                except OSError as left:
                    raise EnvironmentProblemError(
                        f"cannot remove {path}, the place reserved for it: {left.strerror}; "
                        "remove it by hand"
                    ) from failure
                raise failure from error
            reservation = Reservation(path, directory, descriptor, (status.st_dev, status.st_ino))
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


def write_output(path: Path, data: bytes, *, create: bool = False) -> None:
    """Write ``data`` to ``path``, replacing a regular file at once: the data go to a new
    temporary file in the same directory, which is then renamed over the target. A failure
    leaves the previous output as it was, a hard link to another file never receives the data,
    and the mode is 0644 whatever the umask. Neither the output directory nor the target may be
    a link, and the target must be a regular file if it exists. With ``create``, the target is
    only ever created: the temporary file is linked to its name, which fails if a file of that
    name appeared in the meantime, and that file is left as it is."""
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise _not_followed(path.parent, error) from error
    try:
        write_in(directory, path, data, create=create)
    finally:
        os.close(directory)


def write_in(directory: int, path: Path, data: bytes, *, create: bool = False) -> None:
    """Write ``data`` as ``write_output`` does, in the directory open as ``directory``, which is
    never looked up again by its path: ``path`` names the file in what is reported, and its name
    is the file written."""
    temporary = f".{path.name}.{secrets.token_hex(8)}"
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise UnsafeInputError("IO-013", "a symbolic link or not a regular file", str(path))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        except OSError as error:  # a file of that name is not ours to remove
            raise _not_followed(path, error) from error
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if create:
                os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.unlink(temporary, dir_fd=directory)
            else:
                os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        except FileExistsError as error:
            os.unlink(temporary, dir_fd=directory)
            raise EnvironmentProblemError(f"cannot write {path}: it already exists") from error
        except BaseException as error:  # an interruption too: no temporary file is left behind
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=directory)
            if isinstance(error, OSError):
                raise _not_followed(path, error) from error
            raise
    except OSError as error:  # the target's status could not be read
        raise EnvironmentProblemError(f"cannot write {path}: {error.strerror}") from error
