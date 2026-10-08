"""Schema validation with jsonschema, format checking included (research R6).

Schemas are JSON Schema 2020-12 files named ``<name>.schema.json``, read with the bounded JSON
reader and checked when loaded. Formats are checked by the standard validators; jsonschema
silently skips a format whose validator is missing, which a test guards against. Violations are
reported with the JSON pointer of the offending value, each unexpected property at its own
pointer, in a stable order, and messages are shortened so that a long value is never echoed in
full.
"""

import re
from collections.abc import Iterable
from pathlib import Path

import jsonschema
from jsonschema import Draft202012Validator

from scenario_tools.adapters.safe_readers import read_json_file
from scenario_tools.ports.schema import SchemaViolation

MESSAGE_LIMIT = 300
_SUFFIX = ".schema.json"


def json_pointer(path: Iterable[str | int]) -> str:
    """The RFC 6901 pointer of a path: ``~`` becomes ``~0`` and ``/`` becomes ``~1``."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in path)


def _shorten(message: str) -> str:
    return message if len(message) <= MESSAGE_LIMIT else message[: MESSAGE_LIMIT - 1] + "…"


def _violations(error: jsonschema.ValidationError) -> list[SchemaViolation]:
    """One violation per offending value. jsonschema reports unexpected properties on their
    parent object; each one is reported at its own pointer instead."""
    path = list(error.absolute_path)
    general = [SchemaViolation(json_pointer(path), _shorten(error.message))]
    if error.validator != "additionalProperties" or not isinstance(error.instance, dict):
        return general
    schema = error.schema if isinstance(error.schema, dict) else {}
    known, patterns = schema.get("properties", {}), schema.get("patternProperties", {})
    unexpected = [
        SchemaViolation(json_pointer([*path, name]), "unexpected property")
        for name in error.instance
        if name not in known and not any(re.search(pattern, name) for pattern in patterns)
    ]
    return unexpected or general  # never drop an error, even if no property can be named


class JsonSchemaValidator:
    """Validates documents against the schemas of a directory."""

    def __init__(self, schema_dir: Path) -> None:
        self._validators: dict[str, Draft202012Validator] = {}
        for file in sorted(schema_dir.glob(f"*{_SUFFIX}")):
            schema = read_json_file(file)
            try:
                Draft202012Validator.check_schema(schema)
            except jsonschema.SchemaError as error:
                raise ValueError(f"invalid schema {file.name}: {error.message}") from error
            self._validators[file.name.removesuffix(_SUFFIX)] = Draft202012Validator(
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
