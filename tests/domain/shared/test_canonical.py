"""Canonical forms: the stored JSON form, the JCS bytes (RFC 8785) and content hashes."""

import hashlib
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.shared.canonical import (
    CanonicalFormError,
    ContentHash,
    jcs,
    stored_form,
)

# RFC 8785, section 3.2.3: input and its canonical form. Backslashes are spelled out so that
# no escape sequence in this file is interpreted before JSON parsing.
BS = "\\"
RFC_8785_STRING = BS.join(
    ["", "u20ac$", "u000F", "u000aA'", "u0042", "u0022", "u005c", "", "", '"', "/"]
)
RFC_8785_INPUT = (
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], '
    '"string": "' + RFC_8785_STRING + '", "literals": [null, true, false]}'
)
RFC_8785_OUTPUT = (
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
    '"string":"' + BS.join(["\N{EURO SIGN}$", "u000f", "nA'B", '"', "", "", "", "", '"/']) + '"}'
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=20,
)


def _reversed_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _reversed_keys(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reversed_keys(item) for item in value]
    return value


def test_jcs_matches_the_rfc_8785_example() -> None:
    assert jcs(json.loads(RFC_8785_INPUT)) == RFC_8785_OUTPUT.encode("utf-8")


def test_jcs_sorts_keys_and_drops_whitespace() -> None:
    assert jcs({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'


def test_stored_form_is_sorted_indented_utf8_with_a_final_newline() -> None:
    assert stored_form({"b": 1, "a": "é"}) == '{\n  "a": "é",\n  "b": 1\n}\n'.encode()


@pytest.mark.parametrize(("value", "expected"), [({}, b"{}\n"), ([], b"[]\n")])
def test_stored_form_of_empty_containers(value: Any, expected: bytes) -> None:
    assert stored_form(value) == expected


def test_content_hash_of_bytes_is_their_sha256() -> None:
    assert ContentHash.of_bytes(b"").hex == EMPTY_SHA256
    assert str(ContentHash.of_bytes(b"")) == EMPTY_SHA256


@pytest.mark.parametrize("text", ["", "abc", EMPTY_SHA256.upper(), EMPTY_SHA256 + "0", "g" * 64])
def test_content_hash_refuses_anything_but_64_lowercase_hex(text: str) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        ContentHash(text)


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        {"a": [float("-inf")]},
        2**53,
        -(2**53),
        {1: "a"},
        "\ud800",
        {"a": {"b"}},
        b"bytes",
    ],
)
def test_values_without_a_canonical_form_are_refused(value: Any) -> None:
    with pytest.raises(CanonicalFormError):
        jcs(value)
    with pytest.raises(CanonicalFormError):
        stored_form(value)
    with pytest.raises(CanonicalFormError):
        ContentHash.of_json(value)


def _nested(depth: int) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth):
        value = [value]
    return value


def test_a_too_deeply_nested_value_is_refused_cleanly() -> None:
    with pytest.raises(CanonicalFormError, match="nested"):
        jcs(_nested(5000))
    with pytest.raises(CanonicalFormError, match="nested"):
        stored_form(_nested(5000))


@given(json_values)
def test_stored_form_round_trips(value: Any) -> None:
    assert json.loads(stored_form(value)) == value


@given(json_values)
def test_stored_form_is_idempotent(value: Any) -> None:
    once = stored_form(value)

    assert stored_form(json.loads(once)) == once


@given(json_values)
def test_stored_form_uses_lf_and_ends_with_one_newline(value: Any) -> None:
    text = stored_form(value)

    assert b"\r" not in text
    assert text.endswith(b"\n")
    assert not text.endswith(b"\n\n")


@given(json_values)
def test_key_order_changes_neither_form(value: Any) -> None:
    assert stored_form(_reversed_keys(value)) == stored_form(value)
    assert jcs(_reversed_keys(value)) == jcs(value)


@given(json_values)
def test_the_stored_form_hashes_like_the_value(value: Any) -> None:
    assert ContentHash.of_json(json.loads(stored_form(value))) == ContentHash.of_json(value)


@given(json_values)
def test_content_hash_of_json_is_the_sha256_of_its_jcs(value: Any) -> None:
    assert ContentHash.of_json(value).hex == hashlib.sha256(jcs(value)).hexdigest()
