"""Canonical forms of JSON values.

Two forms, for two readers:
- the stored form, for people: UTF-8, keys sorted, two-space indentation, LF line endings and
  a final newline, so that files are readable and diffs are small;
- the JCS form (RFC 8785), for machines: the unambiguous byte form that every content hash is
  computed over, and that consumers in other languages can reproduce.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

import rfc8785

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class CanonicalFormError(ValueError):
    """The value has no canonical form.

    It is not JSON, holds a non-finite number, an integer outside the range JCS can represent
    exactly (±(2**53 - 1)), a non-string key or an invalid string, or is nested too deeply.
    """


def jcs(value: Any) -> bytes:
    """Return the RFC 8785 canonical bytes of ``value``."""
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as error:
        raise CanonicalFormError(str(error)) from error
    except RecursionError as error:
        raise CanonicalFormError("value too deeply nested") from error


def stored_form(value: Any) -> bytes:
    """Return the stored form of ``value``: readable, diffable and deterministic."""
    jcs(value)  # Anything stored must also be hashable.
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        separators=(",", ": "),
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


@dataclass(frozen=True)
class ContentHash:
    """A SHA-256 digest, as 64 lowercase hexadecimal characters."""

    hex: str

    def __post_init__(self) -> None:
        if not _SHA256_HEX.fullmatch(self.hex):
            raise ValueError(f"not a SHA-256 hex digest: {self.hex!r}")

    @classmethod
    def of_bytes(cls, data: bytes) -> "ContentHash":
        return cls(hashlib.sha256(data).hexdigest())

    @classmethod
    def of_json(cls, value: Any) -> "ContentHash":
        """Hash ``value`` over its JCS bytes."""
        return cls.of_bytes(jcs(value))

    def __str__(self) -> str:
        return self.hex
