"""Bounded JSON and YAML readers: everything they read is hostile until proven otherwise."""

import contextlib
import errno
import json
import os
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.adapters.safe_readers import (
    MAX_DEPTH,
    _Loader,
    parse_json,
    parse_yaml,
    read_json_file,
    read_yaml_file,
)
from scenario_tools.ports.errors import EnvironmentProblemError, UnsafeInputError

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


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (b"t: 12:30\n", "12:30"),
        (b"c: NO\n", "NO"),
        (b"o: on\n", "on"),
        (b"y: yes\n", "yes"),
        (b"h: 0x1F\n", "0x1F"),
        (b"u: 1_000\n", "1_000"),
        (b"e: =\n", "="),
        (b"z: 01234\n", "01234"),
        (b"p: +4\n", "+4"),
        (b"d: .5\n", ".5"),
        (b"t: 1.\n", "1."),
        (b"f: 01.5\n", "01.5"),
        (b"b: True\n", "True"),
        (b"c: FALSE\n", "FALSE"),
    ],
    ids=[
        "sexagesimal",
        "NO",
        "on",
        "yes",
        "hexadecimal",
        "underscore",
        "equals",
        "leading zero",
        "plus sign",
        "no integer part",
        "no fraction",
        "leading zero float",
        "capitalised true",
        "upper-case false",
    ],
)
def test_scalars_outside_json_types_stay_text(text: bytes, expected: str) -> None:
    assert list(parse_yaml(text).values()) == [expected]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (b"v: true\n", True),
        (b"v: false\n", False),
        (b"v: !!bool false\n", False),
        (b"v: 10\n", 10),
        (b"v: -3\n", -3),
        (b"v: 1.5\n", 1.5),
        (b"v: -2e3\n", -2000.0),
        (b"v: 0\n", 0),
        (b"v: -0.25\n", -0.25),
        (b"v: 1E+3\n", 1000.0),
        (b"v: ~\n", None),
        (b"v: !!int 12\n", 12),
        (b"v: !!float 1.5\n", 1.5),
        (b"v: !!bool true\n", True),
        (b"v: !!str 12\n", "12"),
    ],
)
def test_yaml_core_schema_values_are_typed(text: bytes, expected: Any) -> None:
    assert parse_yaml(text) == {"v": expected}


def test_a_long_sexagesimal_scalar_stays_cheap_text() -> None:
    data = b"a: 1" + b":1" * 100_000 + b"\n"

    assert parse_yaml(data, limit=len(data)) == {"a": data[3:-1].decode()}


@pytest.mark.parametrize(
    "data",
    [
        b"a: !!int 1:1:1\n",
        b"a: !!int 0x1F\n",
        b"a: !!int x\n",
        b"a: !!float x\n",
        b"a: !!float 1_000.5\n",
        b"a: !!bool yes\n",
        b"a: !!bool True\n",
        b"a: !!int +4\n",
        b"a: !!int 010\n",
        b"a: !!float .5\n",
        b"a: " + b"1" * 5000 + b"\n",
    ],
    ids=[
        "explicit sexagesimal",
        "explicit hexadecimal",
        "explicit int x",
        "explicit float x",
        "explicit underscore",
        "explicit yes",
        "explicit capitalised true",
        "explicit plus sign",
        "explicit leading zero",
        "explicit no integer part",
        "integer of 5000 digits",
    ],
)
def test_explicit_tags_outside_json_types_are_refused(data: bytes) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(data)
    assert _code(error) == "IO-002"


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
    [
        b"a: !!map [1]\n",
        b"a: !!map x\n",
        b"a: !!set [1]\n",
        b"a: !!timestamp x\n",
        b"a: !!timestamp 2001-12-14\n",
        b"a: !!omap [1]\n",
        b"a: !!pairs x\n",
        b"a: !!int {? !!value x : 12}\n",
        b"a: !!str {? !!value k : hello}\n",
        b"a: !!null {? !!value k : null}\n",
    ],
    ids=[
        "map on list",
        "map on text",
        "set on list",
        "bad date",
        "date",
        "omap",
        "pairs",
        "int on map with a value key",
        "str on map with a value key",
        "null on map with a value key",
    ],
)
def test_yaml_tags_json_cannot_represent_are_refused(data: bytes) -> None:
    # Only the tags of JSON's own types are read, and only on a node of their kind.
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(data)
    assert _code(error) == "IO-006"


def test_a_value_a_wider_reader_would_build_is_still_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A second defence: should a constructor ever build a type outside JSON, the value check
    # still refuses it.
    monkeypatch.setitem(_Loader.yaml_constructors, "!x", lambda loader, node: object())

    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(b"a: !x 1\n")
    assert (_code(error), error.value.message) == ("IO-006", "value of type object")


def test_a_node_the_reader_cannot_build_is_refused_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(loader: Any, node: Any) -> Any:
        raise TypeError("cannot unpack")

    monkeypatch.setitem(_Loader.yaml_constructors, "!x", broken)

    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(b"a: !x 1\n")
    assert _code(error) == "IO-002"


_TAGS = [
    *(f"!!{name}" for name in ("str", "bool", "int", "float", "null", "seq", "map")),
    *(f"!!{name}" for name in ("timestamp", "binary", "set", "omap", "pairs", "merge", "value")),
    "!local",
    "!<tag:example.org,2026:x>",
]
_BODIES = [
    *("x", "1", "1.5", "true", "''", "[]", "[1, [2]]", "{}", "{a: 1}", "{a: [1]}"),
    "{? !!value k : 1}",
]


def test_no_tag_on_any_body_escapes_the_refusals() -> None:
    # Every combination is read or refused, never raised as another exception.
    for tag in _TAGS:
        for body in _BODIES:
            for document in (f"{tag} {body}\n", f"a: {tag} {body}\n", f"- {tag} {body}\n"):
                with contextlib.suppress(UnsafeInputError):  # anything else fails the test
                    parse_yaml(document.encode())


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


class _SameRulesDumper(yaml.SafeDumper):
    """Writes YAML with the reader's own resolution rules, so it quotes every string that the
    reader would otherwise type, such as "0E0" under the JSON number grammar."""


_SameRulesDumper.yaml_implicit_resolvers = _Loader.yaml_implicit_resolvers


@given(json_values)
def test_any_json_value_written_as_yaml_round_trips(value: Any) -> None:
    # Escaped output: unescaped, PyYAML writes characters such as U+0085 that YAML reads as line
    # breaks, a writer limitation that says nothing about the reader.
    written = yaml.dump(value, Dumper=_SameRulesDumper, allow_unicode=False)

    assert parse_yaml(written.encode()) == value


def test_a_string_that_looks_like_a_json_number_round_trips_once_quoted() -> None:
    assert parse_yaml(yaml.dump({"0E0": "1e3"}, Dumper=_SameRulesDumper).encode()) == {"0E0": "1e3"}


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
def test_a_socket_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: Callable[[Path], Any]
) -> None:
    monkeypatch.chdir(tmp_path)  # a relative name keeps the socket path short enough
    with socket.socket(socket.AF_UNIX) as server:
        server.bind("socket")
        with pytest.raises(UnsafeInputError) as error:
            reader(Path("socket"))
    assert _code(error) == "IO-013"


@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_a_missing_file_is_an_environment_problem(
    tmp_path: Path, reader: Callable[[Path], Any]
) -> None:
    with pytest.raises(EnvironmentProblemError, match="missing"):
        reader(tmp_path / "missing")


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not apply to root")
@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_an_unreadable_file_is_an_environment_problem(
    tmp_path: Path, reader: Callable[[Path], Any]
) -> None:
    path = tmp_path / "locked"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0)
    try:
        with pytest.raises(EnvironmentProblemError):
            reader(path)
    finally:
        path.chmod(0o600)


class _FailingFile:
    """An open file whose read fails, as on a network file system that drops."""

    def __init__(self, descriptor: int, mode: str, *, closefd: bool) -> None:
        self.descriptor = descriptor

    def __enter__(self) -> "_FailingFile":
        return self

    def __exit__(self, *exc: object) -> None:
        pass  # the reader closes the descriptor itself

    def read(self, size: int) -> bytes:
        raise OSError(errno.EIO, "Input/output error")


@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_a_failure_while_reading_is_an_environment_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: Callable[[Path], Any]
) -> None:
    path = tmp_path / "flaky"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(os, "fdopen", _FailingFile)

    with pytest.raises(EnvironmentProblemError, match="Input/output error"):
        reader(path)


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="needs /proc")
@pytest.mark.parametrize("reader", [read_json_file, read_yaml_file])
def test_no_descriptor_is_left_open_whether_the_file_is_read_or_refused(
    tmp_path: Path, reader: Callable[[Path], Any]
) -> None:
    regular = tmp_path / "a"
    regular.write_text("{}", encoding="utf-8")
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))

    reader(regular)
    with pytest.raises(UnsafeInputError):
        reader(tmp_path)  # a directory

    assert len(list(descriptors.iterdir())) == before


# Values the canonical form cannot hold


@pytest.mark.parametrize(
    "text",
    [
        "9007199254740992",
        "-9007199254740992",
        '{"a": [1, 18446744073709551616]}',
        '"\\ud800"',
        '{"\\udc00": 1}',
        '["ok", "\\ud83d"]',
    ],
    ids=["above 2^53-1", "below -(2^53-1)", "nested", "lone high", "in a key", "unpaired"],
)
def test_json_values_the_canonical_form_cannot_hold_are_refused(text: str) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_json(text.encode())
    assert _code(error) == "IO-006"


@pytest.mark.parametrize(
    "text", ["a: 9007199254740992", 'a: "\\ud800"', '"\\udc00": 1'], ids=["integer", "value", "key"]
)
def test_yaml_values_the_canonical_form_cannot_hold_are_refused(text: str) -> None:
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(text.encode())
    assert _code(error) == "IO-006"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('a: "\\ud83d\\ude00"', {"a": "\U0001f600"}),
        ('"\\ud83d\\ude00": 1', {"\U0001f600": 1}),
        ('a: ["x\\ud83d\\ude00y"]', {"a": ["x\U0001f600y"]}),
    ],
    ids=["value", "key", "inside a string"],
)
def test_yaml_surrogate_pairs_become_the_character_they_encode(text: str, expected: object) -> None:
    assert parse_yaml(text.encode()) == expected


def test_a_yaml_key_written_as_a_surrogate_pair_and_as_its_character_is_a_duplicate() -> None:
    text = '"\\ud83d\\ude00": 1\n"\U0001f600": 2\n'
    with pytest.raises(UnsafeInputError) as error:
        parse_yaml(text.encode())
    assert _code(error) == "IO-005"


def test_the_largest_safe_integers_and_surrogate_pairs_are_kept() -> None:
    text = '[9007199254740991, -9007199254740991, "\\ud83d\\ude00", true]'

    assert parse_json(text.encode()) == [2**53 - 1, -(2**53) + 1, "\U0001f600", True]


def test_refusal_names_its_code_and_path() -> None:
    error = UnsafeInputError("IO-001", "too large", "scenarios/x/scenario.json")

    assert str(error) == "IO-001 scenarios/x/scenario.json: too large"
