"""An OpenAEV scenario export as normalisation reads it: the error that refuses one
(``IO-014``), its parts read by type, and the JSON text it carries decoded within the bounds the
readers apply to a file."""

import json
import math
import re
from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.shared.canonical import SAFE_INTEGER
from scenario_tools.domain.shared.identifiers import CANONICAL_UUID
from scenario_tools.domain.shared.payload_names import base_name

UUID_IN_TEXT = re.compile(CANONICAL_UUID.pattern, re.IGNORECASE)
# A hexadecimal digit or a hyphen written as an escape in JSON text, not preceded by an escaped
# backslash: an identifier written that way would escape rewriting.
ESCAPED_ID_CHARACTER = re.compile(r"(?<!\\)(?:\\\\)*\\u00(?:3[0-9]|4[1-6]|6[1-6]|2[dD])")
JSON_TEXT_FIELDS = (
    "inject_content",
    "injector_contract_content",
    "step_data",
    "step_input",
    "step_output_parser",
)
INFORMATION, INJECTS = "scenario_information", "scenario_injects"
CONTRACT, PAYLOAD = "inject_injector_contract", "injector_contract_payload"
CONTENT = "injector_contract_content"
_MAX_DEPTH = 64  # the nesting bound the readers apply to the export itself


class ExportStructureError(ValueError):
    """The input is not shaped like an OpenAEV scenario export. ``origin`` names the input at
    fault: ``export``, or ``previous`` for the previous version."""

    code = "IO-014"

    def __init__(self, message: str, origin: str = "export", pointer: str = "") -> None:
        super().__init__(message)
        self.origin = origin
        self.what = message
        self.pointer = pointer  # the JSON pointer of the node at fault; empty is the whole input


_FAULTS = {
    "export": "not an OpenAEV scenario export",
    "previous": "not a previous version of this entry",
}


def structure_error(what: str, origin: str = "export", pointer: str = "") -> ExportStructureError:
    error = ExportStructureError(f"{_FAULTS[origin]}: {what}", origin, pointer)
    error.what = what
    return error


def objects_in(document: Mapping[str, Any], collection: str) -> list[dict[str, Any]]:
    value = document.get(collection)
    if value is None:  # absent or null: an empty collection
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise structure_error(f"{collection} must be a list of objects")
    return value


def text_in(item: Mapping[str, Any], key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise structure_error(f"{where}.{key} must be text")
    return value


def every_object(value: object) -> Iterator[dict[str, Any]]:
    """Every object inside ``value``, at any depth."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from every_object(child)
    elif isinstance(value, list):
        for child in value:
            yield from every_object(child)


def embedded_payload(inject: Mapping[str, Any]) -> dict[str, Any] | None:
    contract = inject.get(CONTRACT)
    if contract is None:
        return None
    if not isinstance(contract, dict):
        raise structure_error(f"{CONTRACT} must be an object")
    payload = contract.get(PAYLOAD)
    if payload in (None, {}):
        return None
    if not isinstance(payload, dict):
        raise structure_error(f"{PAYLOAD} must be an object")
    return payload


def name_in(item: Mapping[str, Any], key: str, where: str) -> str:
    name = text_in(item, key, where)
    if not name:
        raise structure_error(f"{where}.{key} must not be empty")
    return name


def payload_base(payload: Mapping[str, Any]) -> str:
    """The base name of ``payload``: what its stable identifiers are derived from, so that every
    version of one payload shares them."""
    base = base_name(name_in(payload, "payload_name", PAYLOAD))
    if not base.strip():
        raise structure_error(f"{PAYLOAD}.payload_name must have a base name before its version")
    return base


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise structure_error(f"{CONTENT} repeats a key")
    return dict(pairs)


def _finite(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):
        raise structure_error(f"{CONTENT} holds a number out of range")
    return number


def _not_a_number(text: str) -> None:
    raise structure_error(f"{CONTENT} holds {text}")


def check_decoded(value: Any, field: str = CONTENT, copies: int = 0, depth: int = 0) -> None:
    """What the readers would refuse in a file: nesting deeper than they allow, an unpaired
    surrogate in a string or a key, an integer the canonical form cannot hold exactly; and a
    contract copy inside the copy, which bounds the work on nested text: ``copies`` contract
    copies are allowed, the inject of a step holding one. ``value`` sits ``depth`` levels down in
    the file where it is stored."""
    stack: list[tuple[Any, int]] = [(value, depth)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth == _MAX_DEPTH:
                raise structure_error(f"{field} is nested deeper than {_MAX_DEPTH} levels")
            if isinstance(item, dict):
                if CONTENT in item:
                    if not copies:
                        raise structure_error(f"{field} holds another contract copy")
                    copies -= 1
                stack.extend((key, depth) for key in item)
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as error:
                raise structure_error(f"{field} holds an unpaired surrogate") from error
        elif isinstance(item, int) and abs(item) > SAFE_INTEGER:  # a boolean is 0 or 1
            raise structure_error(f"{field} holds an integer beyond the exact range of 2^53 - 1")


def decoded_text(text: str, field: str = CONTENT, copies: int = 0, depth: int = 0) -> Any:
    """The JSON text of ``field``, a contract copy by default, decoded within the bounds the
    readers apply, once stored ``depth`` levels down; ``copies`` contract copies may be nested in
    it."""
    try:
        decoded = json.loads(
            text, object_pairs_hook=_unique, parse_float=_finite, parse_constant=_not_a_number
        )
    except (ValueError, RecursionError) as error:  # too many digits, as well as invalid JSON
        raise structure_error(f"{field} must be JSON text") from error
    check_decoded(decoded, field, copies, depth)
    return decoded
