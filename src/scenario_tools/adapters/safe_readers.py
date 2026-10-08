"""Bounded readers for JSON and YAML: everything they read is hostile until proven otherwise.

Each reader opens regular files only, never through a link, enforces a size limit before
parsing, refuses what JSON cannot represent, refuses duplicate keys so that a reviewer and an
importer can never read different values, and limits nesting. YAML is read with a loader
derived from the safe loader that also refuses anchors, aliases and merge keys, and keeps dates
as text. Refusals raise ``UnsafeInputError`` with an ``IO-*`` code.
"""

import errno
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

import yaml

from scenario_tools.ports.errors import UnsafeInputError

JSON_LIMIT = 20 * 1024 * 1024
YAML_LIMIT = 256 * 1024
MAX_DEPTH = 64

_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_MERGE_TAG = "tag:yaml.org,2002:merge"


class _RefusedError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read a regular file, never through a link, and never more than ``limit`` bytes."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafeInputError("IO-013", "a symbolic link", str(path)) from error
        raise
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise UnsafeInputError("IO-013", "not a regular file", str(path))
    with os.fdopen(descriptor, "rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise UnsafeInputError("IO-001", f"larger than {limit} bytes", str(path))
    return data


def _check_json_value(value: Any, max_depth: int) -> None:
    """Refuse anything JSON cannot represent, and nesting deeper than ``max_depth``."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth + 1 > max_depth:
                raise _RefusedError("IO-004", f"nested deeper than {max_depth} levels")
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise _RefusedError("IO-006", f"non-string key {key!r}")
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise _RefusedError("IO-006", "non-finite number")
        elif not (item is None or isinstance(item, str | bool | int)):
            raise _RefusedError("IO-006", f"value of type {type(item).__name__}")


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _RefusedError("IO-002", "not valid UTF-8") from error


# JSON


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _RefusedError("IO-005", f"duplicate key {key!r}")
        result[key] = value
    return result


def _json_constant(name: str) -> Any:
    raise _RefusedError("IO-006", f"{name} is not JSON")


def _parse_json(data: bytes, max_depth: int) -> Any:
    text = _decode(data)
    try:
        value = json.loads(text, object_pairs_hook=_json_object, parse_constant=_json_constant)
    except RecursionError as error:
        raise _RefusedError("IO-004", f"nested deeper than {max_depth} levels") from error
    except ValueError as error:
        raise _RefusedError("IO-002", f"not valid JSON: {error}") from error
    _check_json_value(value, max_depth)
    return value


def parse_json(
    data: bytes, *, path: str = "<input>", limit: int = JSON_LIMIT, max_depth: int = MAX_DEPTH
) -> Any:
    """Parse JSON bytes within the limits, or raise ``UnsafeInputError``."""
    if len(data) > limit:
        raise UnsafeInputError("IO-001", f"larger than {limit} bytes", path)
    try:
        return _parse_json(data, max_depth)
    except _RefusedError as refusal:
        raise UnsafeInputError(refusal.code, refusal.message, path) from refusal


def read_json_file(path: Path, *, limit: int = JSON_LIMIT, max_depth: int = MAX_DEPTH) -> Any:
    """Read and parse a JSON file within the limits, or raise ``UnsafeInputError``."""
    return parse_json(_read_bounded(path, limit), path=str(path), limit=limit, max_depth=max_depth)


# YAML


class _Loader(yaml.SafeLoader):
    """The safe loader, without anchors, aliases, merge keys, duplicate keys or timestamps."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise _RefusedError("IO-003", "YAML alias")
        event = self.peek_event()  # type: ignore[no-untyped-call]  # untyped in the stubs
        if getattr(event, "anchor", None) is not None:
            raise _RefusedError("IO-003", "YAML anchor")
        return super().compose_node(parent, index)

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        if any(key.tag == _MERGE_TAG for key, _ in node.value):
            raise _RefusedError("IO-003", "YAML merge key")

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise _RefusedError("IO-006", "unhashable mapping key") from error
            if duplicate:
                raise _RefusedError("IO-005", f"duplicate key {key!r}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


# Without the timestamp resolver, a date stays text instead of becoming a non-JSON object.
_Loader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != _TIMESTAMP_TAG]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _parse_yaml(data: bytes, max_depth: int) -> Any:
    text = _decode(data)
    try:
        loader = _Loader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except RecursionError as error:
        raise _RefusedError("IO-004", f"nested deeper than {max_depth} levels") from error
    except yaml.constructor.ConstructorError as error:
        raise _RefusedError("IO-006", f"YAML value outside JSON: {error.problem}") from error
    except yaml.YAMLError as error:
        raise _RefusedError("IO-002", f"not valid YAML: {error}") from error
    _check_json_value(value, max_depth)
    return value


def parse_yaml(
    data: bytes, *, path: str = "<input>", limit: int = YAML_LIMIT, max_depth: int = MAX_DEPTH
) -> Any:
    """Parse YAML bytes within the limits, or raise ``UnsafeInputError``."""
    if len(data) > limit:
        raise UnsafeInputError("IO-001", f"larger than {limit} bytes", path)
    try:
        return _parse_yaml(data, max_depth)
    except _RefusedError as refusal:
        raise UnsafeInputError(refusal.code, refusal.message, path) from refusal


def read_yaml_file(path: Path, *, limit: int = YAML_LIMIT, max_depth: int = MAX_DEPTH) -> Any:
    """Read and parse a YAML file within the limits, or raise ``UnsafeInputError``."""
    return parse_yaml(_read_bounded(path, limit), path=str(path), limit=limit, max_depth=max_depth)
