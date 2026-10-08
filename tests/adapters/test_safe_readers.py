"""Bounded JSON and YAML readers: everything they read is hostile until proven otherwise."""

import contextlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.adapters.safe_readers import (
    MAX_DEPTH,
    parse_json,
    parse_yaml,
    read_json_file,
    read_yaml_file,
)
from scenario_tools.ports.errors import UnsafeInputError

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


def _code(error: pytest.ExceptionInfo[UnsafeInputError]) -> str:
    return error.value.code


# JSON


def test_json_object_is_parsed() -> None:
    assert parse_json(b'{"a": [1, 2.5, "x", true, null]}') == {"a": [1, 2.5, "x", True, None]}


def test_json_file_is_read(tmp_path: Path) -> None:
    file = tmp_path / "scenario.json"
    file.write_bytes(b'{"a": 1}')

    assert read_json_file(file) == {"a": 1}


def test_json_at_the_size_limit_passes_and_one_byte_more_is_refused(tmp_path: Path) -> None:
    file = tmp_path / "big.json"
    file.write_bytes(b'"' + b"x" * 8 + b'"')

    assert read_json_file(file, limit=10) == "x" * 8
    file.write_bytes(b'"' + b"x" * 9 + b'"')
    with pytest.raises(UnsafeInputError) as error:
        read_json_file(file, limit=10)
    assert _code(error) == "IO-001"
    assert error.value.path == str(file)


def test_json_bytes_over_the_size_limit_are_refused() -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_json(b"[1, 2]", path="in-memory.json", limit=5)
    assert _code(error) == "IO-001"
    assert error.value.path == "in-memory.json"


@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xfe{}",
        b'{"a": }',
        b"\xef\xbb\xbf{}",
        b"1" * 5000,
        b"",
    ],
    ids=["invalid utf-8", "syntax", "byte order mark", "integer too long", "empty"],
)
def test_invalid_json_is_refused(data: bytes) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_json(data)
    assert _code(error) == "IO-002"


@pytest.mark.parametrize("data", [b'{"a": 1, "a": 2}', b'[{"x": {"b": 1, "b": 1}}]'])
def test_json_duplicate_keys_are_refused(data: bytes) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_json(data)
    assert _code(error) == "IO-005"


@pytest.mark.parametrize("data", [b"NaN", b"[Infinity]", b'{"a": -Infinity}', b"1e999"])
def test_json_values_outside_json_are_refused(data: bytes) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_json(data)
    assert _code(error) == "IO-006"


def test_json_nesting_at_the_limit_passes_and_one_level_more_is_refused() -> None:
    assert parse_json(b"[" * MAX_DEPTH + b"]" * MAX_DEPTH) is not None
    with pytest.raises(UnsafeInputError) as error:
        parse_json(b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1))
    assert _code(error) == "IO-004"


def test_json_nesting_bomb_is_refused_cleanly() -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_json(b"[" * 200_000 + b"]" * 200_000)
    assert _code(error) == "IO-004"


@given(json_values)
def test_any_json_value_round_trips(value: Any) -> None:
    assert parse_json(json.dumps(value).encode()) == value


@given(st.binary(max_size=200))
def test_json_reader_only_returns_or_refuses(data: bytes) -> None:
    with contextlib.suppress(UnsafeInputError):
        parse_json(data)


# YAML


def test_yaml_mapping_is_parsed_with_json_types() -> None:
    data = b"name: x\ncount: 3\nratio: 0.5\nok: true\nnone: null\nlist: [a, 1]\n"

    assert parse_yaml(data) == {
        "name": "x",
        "count": 3,
        "ratio": 0.5,
        "ok": True,
        "none": None,
        "list": ["a", 1],
    }


def test_yaml_dates_stay_text() -> None:
    assert parse_yaml(b"published: 2026-10-08\nat: 2026-10-08T10:00:00Z\n") == {
        "published": "2026-10-08",
        "at": "2026-10-08T10:00:00Z",
    }


def test_yaml_file_is_read(tmp_path: Path) -> None:
    file = tmp_path / "scenario.yaml"
    file.write_bytes(b"a: 1\n")

    assert read_yaml_file(file) == {"a": 1}


def test_yaml_bytes_over_the_size_limit_are_refused() -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(b"a: 12345\n", limit=5)
    assert _code(error) == "IO-001"


def test_yaml_over_the_size_limit_is_refused(tmp_path: Path) -> None:
    file = tmp_path / "big.yaml"
    file.write_bytes(b"a: " + b"x" * 20 + b"\n")

    with pytest.raises(UnsafeInputError) as error:
        read_yaml_file(file, limit=10)
    assert _code(error) == "IO-001"


@pytest.mark.parametrize(
    "data",
    [
        b"a: &anchor 1\n",
        b"a: &x 1\nb: *x\n",
        b"a: *undefined\n",
        b"base: {a: 1}\nderived:\n  <<: {a: 2}\n",
        b'a: &a ["x","x"]\nb: &b [*a,*a]\nc: &c [*b,*b]\n',
    ],
    ids=["anchor", "anchor and alias", "alias alone", "merge key", "alias bomb"],
)
def test_yaml_anchors_aliases_and_merge_keys_are_refused(data: bytes) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(data)
    assert _code(error) == "IO-003"


def test_a_yaml_alias_is_refused_as_an_alias() -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(b"a: *undefined\n")
    assert error.value.message == "YAML alias"


def test_yaml_duplicate_keys_are_refused() -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(b"a: 1\nb:\n  c: 1\n  c: 2\n")
    assert _code(error) == "IO-005"


@pytest.mark.parametrize(
    "data",
    [
        b"a: !!python/object/apply:os.system ['true']\n",
        b"a: !!binary aGVsbG8=\n",
        b"a: !!set {x: null}\n",
        b"a: .nan\n",
        b"a: .inf\n",
        b"1: one\n",
        b"? [a, b]\n: c\n",
    ],
    ids=["python object", "binary", "set", "nan", "infinity", "integer key", "list key"],
)
def test_yaml_values_outside_json_are_refused(data: bytes) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(data)
    assert _code(error) == "IO-006"


@pytest.mark.parametrize(
    "data",
    [b"\xff\xfea: 1", b"a: [1, 2\n", b"a: 1\n---\nb: 2\n"],
    ids=["invalid utf-8", "syntax", "two documents"],
)
def test_invalid_yaml_is_refused(data: bytes) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(data)
    assert _code(error) == "IO-002"


def test_yaml_nesting_over_the_limit_is_refused() -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1))
    assert _code(error) == "IO-004"


def test_yaml_nesting_bomb_is_refused_cleanly() -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(b"[" * 100_000 + b"]" * 100_000, limit=300_000)
    assert _code(error) == "IO-004"


@given(json_values)
def test_any_json_value_written_as_yaml_round_trips(value: Any) -> None:
    # Escaped output: unescaped, PyYAML writes characters such as U+0085 that YAML 1.1 reads
    # as line breaks, a writer limitation that says nothing about the reader.
    assert parse_yaml(yaml.safe_dump(value, allow_unicode=False).encode()) == value


@given(st.binary(max_size=200))
def test_yaml_reader_only_returns_or_refuses(data: bytes) -> None:
    with contextlib.suppress(UnsafeInputError):
        parse_yaml(data)


# Files


@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_a_symbolic_link_is_refused_without_being_followed(
    tmp_path: Path, reader: Callable[[Path], Any]
) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"token: do-not-leak\n")
    link = tmp_path / "scenario"
    link.symlink_to(secret)

    with pytest.raises(UnsafeInputError) as error:
        reader(link)
    assert _code(error) == "IO-013"
    assert "do-not-leak" not in str(error.value)


@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_a_directory_is_refused(tmp_path: Path, reader: Callable[[Path], Any]) -> None:
    with pytest.raises(UnsafeInputError) as error:
        reader(tmp_path)
    assert _code(error) == "IO-013"


@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_a_device_is_refused(reader: Callable[[Path], Any]) -> None:
    with pytest.raises(UnsafeInputError) as error:
        reader(Path("/dev/zero"))
    assert _code(error) == "IO-013"


@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_a_named_pipe_is_refused_without_blocking(
    tmp_path: Path, reader: Callable[[Path], Any]
) -> None:
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)

    with pytest.raises(UnsafeInputError) as error:
        reader(pipe)
    assert _code(error) == "IO-013"


@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_a_missing_file_is_not_an_unsafe_input(
    tmp_path: Path, reader: Callable[[Path], Any]
) -> None:
    with pytest.raises(FileNotFoundError):
        reader(tmp_path / "missing")


def test_refusal_names_its_code_and_path() -> None:
    error = UnsafeInputError("IO-001", "too large", "scenarios/x/scenario.json")

    assert str(error) == "IO-001 scenarios/x/scenario.json: too large"
