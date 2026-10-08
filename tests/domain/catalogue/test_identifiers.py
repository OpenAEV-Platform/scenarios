"""Deterministic identifiers and inject matching across versions (research R2)."""

import uuid
from collections.abc import Sequence
from random import Random

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.catalogue.identifiers import (
    NS_OPENAEV_SCENARIOS,
    AmbiguousInjectError,
    InjectMatching,
    InjectSignature,
    InvalidInjectMappingError,
    match_injects,
    scenario_namespace,
    stable_id,
)

EXTERNAL_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
NS = scenario_namespace(EXTERNAL_ID)


def _sig(
    identifier: str, contract: str = "c", title: str = "t", parents: Sequence[str] = ()
) -> InjectSignature:
    return InjectSignature(identifier, contract, title, tuple(parents))


def _inject_id(source: str) -> str:
    return stable_id(NS, "inject", source)


# Namespaces and derived identifiers


def test_the_root_namespace_is_derived_from_the_repository_url() -> None:
    expected = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/OpenAEV-Platform/scenarios")

    assert expected == NS_OPENAEV_SCENARIOS


def test_the_scenario_namespace_derives_from_the_external_id() -> None:
    assert uuid.uuid5(NS_OPENAEV_SCENARIOS, EXTERNAL_ID) == NS


def test_the_scenario_namespace_does_not_depend_on_the_case_of_the_external_id() -> None:
    assert scenario_namespace(EXTERNAL_ID.upper()) == NS


@pytest.mark.parametrize("external_id", ["", "not-a-uuid", EXTERNAL_ID + "0"])
def test_an_external_id_that_is_not_a_uuid_is_refused(external_id: str) -> None:
    with pytest.raises(ValueError, match="external ID"):
        scenario_namespace(external_id)


def test_a_stable_id_is_the_uuid5_of_type_and_source_id() -> None:
    assert stable_id(NS, "inject", "abc") == str(uuid.uuid5(NS, "inject:abc"))


@given(st.text(min_size=1), st.text(min_size=1), st.text(min_size=1), st.text(min_size=1))
def test_stable_ids_differ_when_type_or_source_differ(
    type_a: str, source_a: str, type_b: str, source_b: str
) -> None:
    same = (type_a, source_a) == (
        type_b,
        source_b,
    ) or f"{type_a}:{source_a}" == f"{type_b}:{source_b}"
    assert (stable_id(NS, type_a, source_a) == stable_id(NS, type_b, source_b)) == same


# Matching


def test_first_version_gives_every_inject_a_derived_id() -> None:
    result = match_injects(NS, [_sig("a"), _sig("b", title="u")], [])

    assert result.ids == {"a": _inject_id("a"), "b": _inject_id("b")}
    assert result.new == ("a", "b")
    assert result.removed == ()


def test_a_re_export_from_the_same_instance_keeps_ids_even_when_titles_change() -> None:
    previous = [_sig(_inject_id("a"), title="old title")]

    result = match_injects(NS, [_sig("a", title="new title")], previous)

    assert result.ids == {"a": _inject_id("a")}
    assert result.new == ()


def test_an_export_from_another_instance_matches_by_contract_and_title() -> None:
    previous = [_sig("p1", contract="x", title="scan"), _sig("p2", contract="y", title="scan")]

    result = match_injects(
        NS,
        [_sig("s2", contract="y", title="scan"), _sig("s1", contract="x", title="scan")],
        previous,
    )

    assert result.ids == {"s1": "p1", "s2": "p2"}


def test_parents_disambiguate_injects_with_the_same_contract_and_title() -> None:
    previous = [
        _sig("root-a", contract="ra"),
        _sig("root-b", contract="rb"),
        _sig("child-a", parents=["root-a"]),
        _sig("child-b", parents=["root-b"]),
    ]
    new = [
        _sig("sb", parents=["rb2"]),
        _sig("sa", parents=["ra2"]),
        _sig("ra2", contract="ra"),
        _sig("rb2", contract="rb"),
    ]

    result = match_injects(NS, new, previous)

    assert result.ids == {"ra2": "root-a", "rb2": "root-b", "sa": "child-a", "sb": "child-b"}


def test_matching_resolves_the_dependency_tree_level_by_level() -> None:
    previous = [
        _sig("G", contract="g"),
        _sig("P1", contract="p", parents=["G"]),
        _sig("P2", contract="p"),
        _sig("C1", contract="c", parents=["P1"]),
        _sig("C2", contract="c", parents=["P2"]),
    ]
    new = [  # children sort first, so their parents are not matched yet when first examined
        _sig("a1", contract="c", parents=["b1"]),
        _sig("a2", contract="c", parents=["b2"]),
        _sig("b1", contract="p", parents=["z"]),
        _sig("b2", contract="p"),
        _sig("z", contract="g"),
    ]

    result = match_injects(NS, new, previous)

    assert result.ids == {"a1": "C1", "a2": "C2", "b1": "P1", "b2": "P2", "z": "G"}


def test_an_unresolved_ambiguity_is_refused_with_its_candidates() -> None:
    previous = [_sig("p1"), _sig("p2")]

    with pytest.raises(AmbiguousInjectError) as error:
        match_injects(NS, [_sig("s")], previous)
    assert error.value.code == "VER-010"
    assert error.value.source_id == "s"
    assert error.value.candidates == ("p1", "p2")


def test_two_new_injects_competing_for_one_candidate_are_ambiguous() -> None:
    with pytest.raises(AmbiguousInjectError) as error:
        match_injects(NS, [_sig("s1"), _sig("s2")], [_sig("p")])
    assert error.value.candidates == ("p",)


def test_the_mapping_resolves_an_ambiguity() -> None:
    result = match_injects(NS, [_sig("s")], [_sig("p1"), _sig("p2")], {"s": "p2"})

    assert result.ids == {"s": "p2"}
    assert result.removed == ("p1",)


def test_unmatched_injects_are_new_and_unmatched_previous_injects_are_removed() -> None:
    result = match_injects(NS, [_sig("s", contract="new")], [_sig("p", contract="old")])

    assert result.ids == {"s": _inject_id("s")}
    assert result.new == ("s",)
    assert result.removed == ("p",)


@pytest.mark.parametrize(
    ("mapping", "reason"),
    [
        ({"unknown": "p1"}, "unknown source inject"),
        ({"s1": "unknown"}, "not in the previous version"),
        ({"s1": "p1", "s2": "p1"}, "used twice"),
    ],
)
def test_an_invalid_mapping_is_refused(mapping: dict[str, str], reason: str) -> None:
    with pytest.raises(InvalidInjectMappingError, match=reason) as error:
        match_injects(NS, [_sig("s1"), _sig("s2", title="u")], [_sig("p1")], mapping)
    assert error.value.code == "VER-011"


def test_a_new_id_colliding_with_a_mapped_one_is_refused() -> None:
    previous = [_sig(_inject_id("a"))]

    with pytest.raises(InvalidInjectMappingError, match="already"):
        match_injects(NS, [_sig("a"), _sig("b", title="u")], previous, {"b": _inject_id("a")})


def test_duplicate_source_ids_are_refused() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        match_injects(NS, [_sig("a"), _sig("a")], [])


# Properties

_signatures = st.lists(
    st.builds(
        InjectSignature,
        st.text(alphabet="abcdef", min_size=1, max_size=3),
        st.sampled_from(["c1", "c2", "c3"]),
        st.sampled_from(["t1", "t2"]),
        st.just(()),
    ),
    max_size=8,
    unique_by=lambda signature: signature.id,
)


def _outcome(
    new: list[InjectSignature], previous: list[InjectSignature]
) -> InjectMatching | tuple[str, tuple[str, ...]]:
    try:
        return match_injects(NS, new, previous)
    except AmbiguousInjectError as error:
        return error.source_id, error.candidates


@given(_signatures, _signatures, st.randoms())
def test_the_result_does_not_depend_on_the_order_of_injects(
    new: list[InjectSignature], previous: list[InjectSignature], random: Random
) -> None:
    shuffled_new, shuffled_previous = list(new), list(previous)
    random.shuffle(shuffled_new)
    random.shuffle(shuffled_previous)

    assert _outcome(shuffled_new, shuffled_previous) == _outcome(new, previous)


@given(_signatures, _signatures)
def test_every_inject_gets_one_unique_id(
    new: list[InjectSignature], previous: list[InjectSignature]
) -> None:
    try:
        result = match_injects(NS, new, previous)
    except AmbiguousInjectError:
        return
    assert set(result.ids) == {signature.id for signature in new}
    assert len(set(result.ids.values())) == len(new)
    reused = set(result.ids.values()) & {signature.id for signature in previous}
    assert set(result.removed) == {signature.id for signature in previous} - reused
    assert set(result.new) == {
        source for source, target in result.ids.items() if target not in reused
    }


@given(_signatures)
def test_re_preparing_from_the_same_instance_is_the_identity(new: list[InjectSignature]) -> None:
    first = match_injects(NS, new, [])
    previous = [
        InjectSignature(first.ids[signature.id], signature.contract, signature.title, ())
        for signature in new
    ]

    second = match_injects(NS, new, previous)

    assert second.ids == first.ids
    assert second.new == ()
    assert second.removed == ()
