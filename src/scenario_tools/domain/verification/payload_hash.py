"""The canonical form of a payload and its hash, which the platform recomputes to recognise an
imported payload; the shared test vectors of ``conformance/payload-hash.json`` pin it down.

The form is a JSON object of the payload's fields under the names the platform exports, each read
as its type requires. Identifiers, sources, statuses, authors, tags and dates are left out, each
by its name, so that a field the form does not know is refused rather than dropped; so is every
null or empty value at any depth, while ``false`` and ``0`` are kept. Sets are sorted, texts by
their UTF-16 code units and objects by their JCS text in the same order, and may not hold an item
twice; ordered lists keep their order. An attached file enters by the SHA-256 of its bytes, and
the techniques the payload's contract holds by their external IDs. The hash is the SHA-256 of the
form's JCS (RFC 8785).

What cannot be hashed without guessing is refused (``PAY-005``): a field the form does not know,
a field of another payload type, a value of an unexpected type, a detection remediation (the
export names its security platform by an identifier, the form by a type), a free-form AI object,
and an attached file whose bytes are not given. A refusal names the field, never its value.

The fields are described as data, read by the functions below when a payload is hashed."""

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, TypeGuard

from scenario_tools.domain.catalogue.structure import CONTRACT, PAYLOAD, contracts_with_payloads
from scenario_tools.domain.shared.canonical import SAFE_INTEGER, ContentHash, jcs

FileHash = Callable[[str], str | None]
"""The SHA-256 of an attached document's bytes, by the document's identifier, in lower-case
hexadecimal; ``None`` when the entry does not hold them. Another answer is a fault of the caller,
refused with a ``ValueError``."""

_TECHNIQUES = "payload_attack_patterns"
_HELD = "injector_contract_attack_patterns"
_EXTERNAL_ID = "attack_pattern_external_id"
_UNEXPECTED = "a value of an unexpected type"
_TWICE = "a set holds the same item twice"


class UnhashablePayloadError(ValueError):
    """A payload the canonical form cannot hash without guessing. ``field`` is the JSON pointer
    of the field at fault, in the payload, or in its contract when ``on_contract`` is set."""

    code = "PAY-005"

    def __init__(self, field: str, reason: str, *, on_contract: bool = False) -> None:
        super().__init__(f"{field or '(payload)'}: {reason}")
        self.field = field
        self.reason = reason
        self.on_contract = on_contract


@dataclass(frozen=True)
class EmbeddedPayload:
    """A payload a stored scenario embeds: the JSON pointer of its contract, the payload as given,
    and the external IDs of the techniques the contract holds, ``None`` where one has none."""

    contract: str
    payload: object
    attack_patterns: tuple[object, ...]

    @property
    def pointer(self) -> str:
        return f"{self.contract}/{PAYLOAD}"

    def locate(self, error: UnhashablePayloadError) -> str:
        """The pointer, in the stored scenario, of the field ``error`` refuses."""
        return (self.contract if error.on_contract else self.pointer) + error.field


class _Scalar(Enum):
    TEXT = auto()
    BOOL = auto()
    INT = auto()
    TEXTS = auto()  # an ordered list of texts
    TEXT_SET = auto()
    FILE = auto()  # an attached document, by the hash of its bytes


@dataclass(frozen=True)
class _Object:
    """An object of known fields; the ``left_out`` ones are dropped by name. In an argument, a
    document's value is the hash of its file."""

    fields: Mapping[str, "_Spec"]
    left_out: frozenset[str] = frozenset()
    names_a_document: bool = False


@dataclass(frozen=True)
class _Items:
    """A list of one kind: a set is sorted by the canonical text of its items, and holds none
    twice."""

    item: "_Spec"
    is_set: bool


@dataclass(frozen=True)
class _Map:
    """An object whose keys are free and whose values are all of one scalar kind, never a file."""

    item: "_Scalar"


@dataclass(frozen=True)
class _Refused:
    reason: str


_Spec = _Scalar | _Object | _Items | _Map | _Refused


def _escaped(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _empty(value: object) -> bool:
    return value is None or (isinstance(value, str | list | Mapping) and not value)


_Order = tuple[tuple[bool, int], ...]


def _units(text: str) -> _Order:
    """``text`` in the order of its UTF-16 code units, the order JCS gives to keys: it differs
    from the order of code points only in that U+E000 to U+FFFF sort after the characters outside
    the basic plane, which UTF-16 writes with lower surrogates. A lone surrogate never reaches
    here."""
    return tuple((0xE000 <= ord(character) <= 0xFFFF, ord(character)) for character in text)


def _canonical_units(item: object) -> _Order:
    return _units(jcs(item).decode())


def _distinct(keys: list[_Order], pointer: str, *, on_contract: bool = False) -> None:
    if len(set(keys)) != len(keys):
        raise UnhashablePayloadError(pointer, _TWICE, on_contract=on_contract)


def _is_text(value: object) -> TypeGuard[str]:
    # A lone surrogate is no character: no JSON text can carry it.
    return isinstance(value, str) and not any(0xD800 <= ord(unit) <= 0xDFFF for unit in value)


def _text(value: object, pointer: str) -> str:
    if not _is_text(value):
        raise UnhashablePayloadError(pointer, _UNEXPECTED)
    return value


def _bool(value: object, pointer: str) -> bool:
    if not isinstance(value, bool):
        raise UnhashablePayloadError(pointer, _UNEXPECTED)
    return value


def _int(value: object, pointer: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) > SAFE_INTEGER:
        raise UnhashablePayloadError(pointer, _UNEXPECTED)
    return value


def _texts(value: object, pointer: str) -> list[str]:
    if not isinstance(value, list):
        raise UnhashablePayloadError(pointer, _UNEXPECTED)
    for index, item in enumerate(value):
        if not item:
            raise UnhashablePayloadError(f"{pointer}/{index}", _UNEXPECTED)
        _text(item, f"{pointer}/{index}")
    return list(value)


def _text_set(value: object, pointer: str) -> list[str]:
    texts = sorted(_texts(value, pointer), key=_units)
    _distinct([_units(text) for text in texts], pointer)
    return texts


def _file(value: object, pointer: str, files: FileHash) -> str:
    digest = files(_text(value, pointer))
    if digest is None:
        raise UnhashablePayloadError(
            pointer,
            "the bytes of this attached file are not in the entry, so its hash cannot be computed",
        )
    return ContentHash(digest).hex


_SCALARS: Mapping[_Scalar, Callable[[object, str], Any]] = {
    _Scalar.TEXT: _text,
    _Scalar.BOOL: _bool,
    _Scalar.INT: _int,
    _Scalar.TEXTS: _texts,
    _Scalar.TEXT_SET: _text_set,
}


def _read(spec: _Spec, value: object, pointer: str, files: FileHash) -> Any:
    if isinstance(spec, _Refused):
        raise UnhashablePayloadError(pointer, spec.reason)
    if isinstance(spec, _Object):
        return _read_object(spec, value, pointer, files)
    if isinstance(spec, _Items):
        return _read_items(spec, value, pointer, files)
    if isinstance(spec, _Map):
        return _read_map(spec, value, pointer)
    if spec is _Scalar.FILE:
        return _file(value, pointer, files)
    return _SCALARS[spec](value, pointer)


def _read_object(spec: _Object, value: object, pointer: str, files: FileHash) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise UnhashablePayloadError(pointer, _UNEXPECTED)
    kept: dict[str, Any] = {}
    for key, item in value.items():
        if _empty(item) or key in spec.left_out:
            continue
        place = f"{pointer}/{_escaped(str(key))}"
        if key not in spec.fields:
            raise UnhashablePayloadError(
                place, "a field the canonical form of a payload does not know"
            )
        read = _read(spec.fields[key], item, place, files)
        if not _empty(read):
            kept[key] = read
    if spec.names_a_document and kept.get("type") == "document" and "default_value" in kept:
        kept["default_value"] = _file(kept["default_value"], f"{pointer}/default_value", files)
    return kept


def _read_items(spec: _Items, value: object, pointer: str, files: FileHash) -> list[Any]:
    if not isinstance(value, list):
        raise UnhashablePayloadError(pointer, _UNEXPECTED)
    read = [_read(spec.item, item, f"{pointer}/{index}", files) for index, item in enumerate(value)]
    items = [item for item in read if not _empty(item)]
    if not spec.is_set:
        return items
    # One JCS text per item, compared in UTF-16 code units as a Java implementation would.
    items.sort(key=_canonical_units)
    _distinct([_canonical_units(item) for item in items], pointer)
    return items


def _read_map(spec: _Map, value: object, pointer: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise UnhashablePayloadError(pointer, _UNEXPECTED)
    kept: dict[str, Any] = {}
    for key, item in value.items():
        place = f"{pointer}/{_escaped(str(key))}"
        _text(key, place)
        if not _empty(item):
            kept[key] = _SCALARS[spec.item](item, place)
    return kept


_TEXT, _BOOL, _INT, _FILE = _Scalar.TEXT, _Scalar.BOOL, _Scalar.INT, _Scalar.FILE
_INSTANCE = frozenset({"listened"})
_ARGUMENT = _Object(
    {"type": _TEXT, "key": _TEXT, "default_value": _TEXT, "description": _TEXT, "separator": _TEXT},
    names_a_document=True,
)
_PREREQUISITE = _Object(
    {"executor": _TEXT, "get_command": _TEXT, "check_command": _TEXT, "description": _TEXT}
)
_REGEX_GROUP = _Object(
    {"regex_group_field": _TEXT, "regex_group_index_values": _TEXT},
    _INSTANCE | {"regex_group_id", "regex_group_created_at", "regex_group_updated_at"},
)
_OUTPUT_ELEMENT = _Object(
    {
        "contract_output_element_key": _TEXT,
        "contract_output_element_name": _TEXT,
        "contract_output_element_rule": _TEXT,
        "contract_output_element_type": _TEXT,
        "contract_output_element_is_finding": _BOOL,
        "contract_output_element_regex_groups": _Items(_REGEX_GROUP, is_set=True),
    },
    _INSTANCE
    | {
        "contract_output_element_id",
        "contract_output_element_tags",
        "contract_output_element_created_at",
        "contract_output_element_updated_at",
    },
)
_OUTPUT_PARSER = _Object(
    {
        "output_parser_mode": _TEXT,
        "output_parser_type": _TEXT,
        "output_parser_contract_output_elements": _Items(_OUTPUT_ELEMENT, is_set=True),
    },
    _INSTANCE | {"output_parser_id", "output_parser_created_at", "output_parser_updated_at"},
)
_PAYLOAD_INSTANCE = _INSTANCE | {
    "payload_id",
    "payload_external_id",
    "payload_source",
    "payload_status",
    "payload_collector_type",
    "payload_author_user",
    "payload_author_team",
    "payload_author_organization",
    "payload_tags",
    "payload_created_at",
    "payload_updated_at",
}
_COMMON: Mapping[str, _Spec] = {
    "payload_type": _TEXT,
    "payload_name": _TEXT,
    "payload_description": _TEXT,
    "payload_platforms": _Scalar.TEXT_SET,
    "payload_execution_arch": _TEXT,
    "payload_elevation_required": _BOOL,
    "payload_expectations": _Scalar.TEXT_SET,
    "payload_expected_security_platforms": _Map(_Scalar.TEXT_SET),
    "payload_arguments": _Items(_ARGUMENT, is_set=False),
    "payload_prerequisites": _Items(_PREREQUISITE, is_set=False),
    "payload_cleanup_executor": _TEXT,
    "payload_cleanup_command": _TEXT,
    "payload_output_parsers": _Items(_OUTPUT_PARSER, is_set=True),
    "payload_detection_remediations": _Refused(
        "a detection remediation names its security platform by an identifier, which the "
        "canonical form cannot use"
    ),
}
_FREE_FORM = _Refused("a free-form object the canonical form does not cover yet")
_OWN: Mapping[str, Mapping[str, _Spec]] = {
    "Command": {"command_executor": _TEXT, "command_content": _TEXT},
    "Executable": {"executable_file": _FILE},
    "FileDrop": {"file_drop_file": _FILE},
    "DnsResolution": {"dns_resolution_hostname": _TEXT},
    "NetworkTraffic": {
        "network_traffic_ip_src": _TEXT,
        "network_traffic_ip_dst": _TEXT,
        "network_traffic_port_src": _INT,
        "network_traffic_port_dst": _INT,
        "network_traffic_protocol": _TEXT,
    },
    "AiAttack": {
        "ai_attack_engine": _TEXT,
        "ai_attack_category": _TEXT,
        "ai_attack_content": _TEXT,
        "ai_attack_converters": _Scalar.TEXTS,
        "ai_attack_multi_turn": _FREE_FORM,
        "ai_attack_success_detector": _FREE_FORM,
    },
}
_FOREIGN = _Refused("a field of another payload type")
# Each type reads its own fields and the common ones, and refuses a filled field of another type.
_TYPES: Mapping[str, _Object] = {
    kind: _Object(
        {**{key: _FOREIGN for fields in _OWN.values() for key in fields}, **_COMMON, **own},
        _PAYLOAD_INSTANCE,
    )
    for kind, own in _OWN.items()
}


def _techniques(attack_patterns: Sequence[object]) -> list[str]:
    techniques: list[str] = []
    # One text is no list of techniques: it is refused as a technique without an external ID.
    for technique in (None,) if isinstance(attack_patterns, str) else attack_patterns:
        if not _is_text(technique) or not technique:
            raise UnhashablePayloadError(
                f"/{_HELD}",
                "each technique of the contract needs one external ID",
                on_contract=True,
            )
        techniques.append(technique)
    techniques.sort(key=_units)
    _distinct([_units(technique) for technique in techniques], f"/{_HELD}", on_contract=True)
    return techniques


def canonical_payload(
    payload: object, attack_patterns: Sequence[object], files: FileHash
) -> dict[str, Any]:
    """The canonical form of ``payload``, whose contract holds ``attack_patterns``, by their
    external IDs; ``files`` gives the hash of an attached document's bytes."""
    if not isinstance(payload, Mapping):
        raise UnhashablePayloadError("", _UNEXPECTED)
    kind = payload.get("payload_type")
    if not isinstance(kind, str) or kind not in _TYPES:
        raise UnhashablePayloadError("/payload_type", "an unknown payload type")
    canonical = _read_object(_TYPES[kind], payload, "", files)
    techniques = _techniques(attack_patterns)
    if techniques:
        canonical[_TECHNIQUES] = techniques
    return canonical


def payload_hash(
    payload: object, attack_patterns: Sequence[object], files: FileHash
) -> ContentHash:
    """The SHA-256 of the JCS of the canonical form of ``payload``."""
    return ContentHash.of_json(canonical_payload(payload, attack_patterns, files))


def embedded_payloads(stored: object) -> Iterator[EmbeddedPayload]:
    """Every payload a stored scenario's injects embed, as given, with the techniques of its
    contract; a contract whose techniques are not a list gives one without an external ID, so that
    the payload is refused rather than hashed without them."""
    for pointer, _, contract in contracts_with_payloads(stored):
        held = contract.get(_HELD)
        if held is None:
            techniques: tuple[object, ...] = ()
        elif isinstance(held, list):
            techniques = tuple(
                item.get(_EXTERNAL_ID) if isinstance(item, Mapping) else None for item in held
            )
        else:
            techniques = (None,)
        yield EmbeddedPayload(f"{pointer}/{CONTRACT}", contract[PAYLOAD], techniques)
