"""Schema validation with jsonschema, format checking included (research R6).

Schemas are JSON Schema 2020-12 files named ``<name>.schema.json``, read with the bounded JSON
reader and checked when loaded. Formats are checked by the standard validators; jsonschema
silently skips a format whose validator is missing, which a test guards against. Violations are
reported with the JSON pointer of the offending value, each unexpected property at its own
pointer, in a stable order, and messages are shortened so that a long value is never echoed in
full. Patterns follow ECMA-262, as JSON Schema requires: ``$`` matches only at the very end, not
before a final newline as in Python.
"""

import functools
import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator

from scenario_tools.adapters.safe_readers import read_json_file
from scenario_tools.domain.shared.finding import shorten
from scenario_tools.ports.schema import SchemaViolation

_SUFFIX = ".schema.json"


def json_pointer(path: Iterable[str | int]) -> str:
    """The RFC 6901 pointer of a path: ``~`` becomes ``~0`` and ``/`` becomes ``~1``."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in path)


_ECMA_WILDCARD = r"[^\n\r\u2028\u2029]"


def ecma_to_python(pattern: str) -> str:
    """Translate what Python reads differently from ECMA-262, outside a character class: an
    unescaped ``$`` becomes ``\\Z``, the absolute end, since Python's ``$`` also matches before a
    final newline; the wildcard ``.`` excludes every ECMA-262 line terminator, where Python's
    excludes only ``\\n``."""
    out: list[str] = []
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            out.append(pattern[index : index + 2])
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "$":
            char = r"\Z"
        elif char == ".":
            char = _ECMA_WILDCARD
        out.append(char)
        index += 1
    return "".join(out)


@functools.lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(ecma_to_python(pattern))


def _pattern(
    validator: Any, pattern: str, instance: object, schema: Mapping[str, Any]
) -> Iterator[jsonschema.ValidationError]:
    if isinstance(instance, str) and not _regex(pattern).search(instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


def _pattern_properties(
    validator: Any, patterns: Mapping[str, Any], instance: object, schema: Mapping[str, Any]
) -> Iterator[jsonschema.ValidationError]:
    if not isinstance(instance, dict):
        return
    for pattern, subschema in patterns.items():
        for name, value in instance.items():
            if _regex(pattern).search(name):
                yield from validator.descend(value, subschema, path=name, schema_path=pattern)


def _unexpected(schema: Mapping[str, Any], instance: Mapping[str, Any]) -> list[str]:
    known, patterns = schema.get("properties", {}), schema.get("patternProperties", {})
    return [
        name
        for name in instance
        if name not in known and not any(_regex(pattern).search(name) for pattern in patterns)
    ]


def _additional_properties(
    validator: Any, additional: Any, instance: object, schema: Mapping[str, Any]
) -> Iterator[jsonschema.ValidationError]:
    if not isinstance(instance, dict):
        return
    extras = _unexpected(schema, instance)
    if isinstance(additional, dict):
        for name in extras:
            yield from validator.descend(instance[name], additional, path=name)
    elif additional is False and extras:
        yield jsonschema.ValidationError(f"unexpected properties: {', '.join(map(repr, extras))}")


# Every keyword that matches a pattern uses the ECMA-262 end anchor.
_Validator = jsonschema.validators.extend(  # type: ignore[no-untyped-call]  # untyped stubs
    Draft202012Validator,
    {
        "pattern": _pattern,
        "patternProperties": _pattern_properties,
        "additionalProperties": _additional_properties,
    },
)


def _violations(error: jsonschema.ValidationError) -> list[SchemaViolation]:
    """One violation per offending value. jsonschema reports unexpected properties on their
    parent object; each one is reported at its own pointer instead."""
    path = list(error.absolute_path)
    general = [SchemaViolation(json_pointer(path), shorten(error.message))]
    if error.validator != "additionalProperties" or not isinstance(error.instance, dict):
        return general
    schema = error.schema if isinstance(error.schema, dict) else {}
    unexpected = [
        SchemaViolation(json_pointer([*path, name]), "unexpected property")
        for name in _unexpected(schema, error.instance)
    ]
    return unexpected or general  # never drop an error, even if no property can be named


class JsonSchemaValidator:
    """Validates documents against the schemas of a directory."""

    def __init__(self, schema_dir: Path) -> None:
        self._validators: dict[str, Any] = {}
        for file in sorted(schema_dir.glob(f"*{_SUFFIX}")):
            schema = read_json_file(file)
            try:
                Draft202012Validator.check_schema(schema)
            except jsonschema.SchemaError as error:
                raise ValueError(f"invalid schema {file.name}: {error.message}") from error
            self._validators[file.name.removesuffix(_SUFFIX)] = _Validator(
                schema, format_checker=Draft202012Validator.FORMAT_CHECKER
            )

    def validate(self, schema: str, document: object) -> tuple[SchemaViolation, ...]:
        validator = self._validators[schema]
        violations = {
            violation
            for error in validator.iter_errors(document)
            for violation in _violations(error)
        }
        return tuple(
            sorted(violations, key=lambda violation: (violation.pointer, violation.message))
        )
