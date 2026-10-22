"""The base name of a payload: its name without the version a later version carries, so that
every version of one payload shares the identifiers derived from its name."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.shared.payload_names import FIRST_VERSION, base_name, versioned_name


@pytest.mark.parametrize(
    ("name", "base"),
    [
        ("Process Discovery - ps", "Process Discovery - ps"),
        ("Process Discovery - ps (1.1.0)", "Process Discovery - ps"),
        ("ps (10.20.30)", "ps"),
        ("ps (1.0.0) (1.1.0)", "ps (1.0.0)"),  # stripped once
        ("ps (01.1.0)", "ps (01.1.0)"),  # not a version: a leading zero
        ("ps (1.1)", "ps (1.1)"),
        ("ps(1.1.0)", "ps(1.1.0)"),  # the space belongs to the suffix
        ("ps (1.1.0) ", "ps (1.1.0) "),  # the suffix ends the name
        ("ps (1.1.0-rc.1)", "ps (1.1.0-rc.1)"),
        ("ps (1.1.0)\n", "ps (1.1.0)\n"),
        ("", ""),
    ],
)
def test_the_base_name_is_the_name_without_a_final_version(name: str, base: str) -> None:
    assert base_name(name) == base


def test_the_first_version_carries_the_base_name_and_any_other_its_own_version() -> None:
    assert FIRST_VERSION == "1.0.0"
    assert versioned_name("ps", "1.0.0") == "ps"
    assert versioned_name("ps", "1.1.0") == "ps (1.1.0)"
    assert versioned_name("ps", "0.9.0") == "ps (0.9.0)"


_VERSIONS = st.tuples(*[st.integers(0, 999)] * 3).map(lambda v: ".".join(map(str, v)))


@given(st.text(max_size=40), _VERSIONS)
def test_a_versioned_name_reads_back_to_its_base(base: str, version: str) -> None:
    assert base_name(versioned_name(base_name(base), version)) == base_name(base)
