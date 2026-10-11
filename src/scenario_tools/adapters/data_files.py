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


def check_output(path: Path) -> None:
    """Refuse, before anything is written, an output ``write_output`` would refuse: a directory
    that is a link, cannot be opened or written in, a target that is a link or not a regular
    file."""
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise _not_followed(path.parent, error) from error
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise UnsafeInputError("IO-013", "a symbolic link or not a regular file", str(path))
        # A file is made and removed beside it, as the write will, to know it can be.
        probe = f".{path.name}.{secrets.token_hex(8)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            os.close(os.open(probe, flags, 0o600, dir_fd=directory))
            os.unlink(probe, dir_fd=directory)
        except OSError as error:
            raise EnvironmentProblemError(f"cannot write {path}: {error.strerror}") from error
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
    finally:
        os.close(directory)
