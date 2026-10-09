"""Files around normalisation: policy data, exports, and the files a command writes.

Every read goes through the bounded readers. A command's output is written without ever
following a symbolic link, so that a link planted in an entry cannot redirect the write.
"""

import errno
import os
import re
from pathlib import Path
from typing import Any

from scenario_tools.adapters.safe_readers import parse_json, read_json_file, read_yaml_file
from scenario_tools.adapters.safe_zip import open_zip
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


def read_export(path: Path) -> Any:
    """An exported scenario, from its archive or from its JSON file."""
    if path.suffix != ".zip":
        return read_json_file(path)
    archive = open_zip(path)
    entries = [name for name in archive.names if name.endswith(".json")]
    if len(entries) != 1:
        raise UnsafeInputError(
            "IO-014",
            f"an export archive holds one scenario JSON entry, not {len(entries)}",
            str(path),
        )
    return parse_json(archive.read(entries[0]), path=str(path))


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


def write_output(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path``, replacing a regular file, never through a link."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafeInputError("IO-013", "a symbolic link", str(path)) from error
        raise EnvironmentProblemError(f"cannot write {path}: {error.strerror}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as file:
            file.write(data)
    except OSError as error:
        raise EnvironmentProblemError(f"cannot write {path}: {error.strerror}") from error
    finally:
        os.close(descriptor)
